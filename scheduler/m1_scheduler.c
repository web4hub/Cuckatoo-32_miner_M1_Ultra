// m1_scheduler.c: async stratum proxy/scheduler between the miner and the grin node.
//
// The miner itself is never modified; it just connects here instead of the node (a different
// port). Async via poll() on both sockets, single process, no threads.
//
// Two modes:
//   default (pass-through): forward all stratum traffic; track height; drop the miner's stale submits
//     (submitted height < current height) so they never reach the node as "submitted too late" misses.
//   pinning (M1_SCHED_PIN=1, used with external scoring tools): additionally pin one pre_pow per block,
//     answer the miner's getjobtemplate locally with it and suppress the node's intra-height churn, so
//     the miner stays on a single stable pre_pow per block; also write that pinned pre_pow's params to
//     M1_SCHED_PIN_FILE so an external scorer sees the same pre_pow the miner is mining.
//
// build:  make   (or: xcrun clang -O2 -o bin/m1_scheduler scheduler/m1_scheduler.c)
// run:    M1_SCHED_LISTEN=3410 M1_SCHED_NODE_PORT=3416 [M1_SCHED_PIN=1 M1_SCHED_PIN_FILE=/tmp/m1_pinned.json] ./bin/m1_scheduler

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static uint64_t json_u64(const char *s, const char *key){
  char pat[64]; snprintf(pat,sizeof pat,"\"%s\":",key);
  const char *p = strstr(s,pat); if(!p) return 0; p += strlen(pat);
  while(*p==' ') p++;
  return strtoull(p,NULL,10);
}
static int line_is_job(const char *s){ return strstr(s,"\"pre_pow\"") && strstr(s,"\"job_id\""); }
static int line_is_submit(const char *s){ return strstr(s,"\"method\":\"submit\"") || strstr(s,"\"method\": \"submit\""); }
static int line_is_getjob(const char *s){ return strstr(s,"getjobtemplate") != NULL; }
// copy the balanced {...} object that follows `key` in `line` into out; 1 on success.
static int extract_obj(const char *line, const char *key, char *out, size_t cap){
  const char *p = strstr(line,key); if(!p) return 0; p = strchr(p,'{'); if(!p) return 0;
  int depth=0; size_t n=0;
  for(const char *q=p; *q; q++){ if(n+1>=cap) return 0; out[n++]=*q;
    if(*q=='{') depth++; else if(*q=='}'){ if(--depth==0){ out[n]=0; return 1; } } }
  return 0;
}
// copy the `"id":<value>` pair (up to the next comma/brace) into out; 1 on success.
static int extract_id(const char *line, char *out, size_t cap){
  const char *p = strstr(line,"\"id\":"); if(!p) return 0;
  const char *e = strpbrk(p+5, ",}"); if(!e) return 0;
  size_t n=(size_t)(e-p); if(n+1>=cap) n=cap-1; memcpy(out,p,n); out[n]=0; return 1;
}

static int connect_node(const char *host, const char *port){
  struct addrinfo h, *res=NULL, *rp; memset(&h,0,sizeof h);
  h.ai_family=AF_UNSPEC; h.ai_socktype=SOCK_STREAM;
  if(getaddrinfo(host,port,&h,&res)!=0) return -1;
  int fd=-1;
  for(rp=res; rp; rp=rp->ai_next){ fd=socket(rp->ai_family,rp->ai_socktype,rp->ai_protocol); if(fd<0) continue; if(connect(fd,rp->ai_addr,rp->ai_addrlen)==0) break; close(fd); fd=-1; }
  freeaddrinfo(res); return fd;
}
static int listen_on(int port){
  int fd=socket(AF_INET,SOCK_STREAM,0); if(fd<0) return -1;
  int one=1; setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&one,sizeof one);
  struct sockaddr_in a; memset(&a,0,sizeof a); a.sin_family=AF_INET; a.sin_addr.s_addr=htonl(INADDR_LOOPBACK); a.sin_port=htons((uint16_t)port);
  if(bind(fd,(struct sockaddr*)&a,sizeof a)!=0){ close(fd); return -1; }
  if(listen(fd,4)!=0){ close(fd); return -1; }
  return fd;
}
static int send_all(int fd, const char *b, size_t n){ while(n){ ssize_t w=send(fd,b,n,0); if(w<=0) return -1; b+=w; n-=(size_t)w; } return 0; }

typedef int (*line_cb)(const char *line, size_t len, void *ud);
struct lbuf { char buf[262144]; size_t used; };
static int feed(struct lbuf *lb, const char *data, size_t n, line_cb cb, void *ud){
  for(size_t i=0;i<n;i++){
    if(lb->used < sizeof lb->buf - 1) lb->buf[lb->used++] = data[i];
    if(data[i]=='\n'){ lb->buf[lb->used]=0; if(cb(lb->buf, lb->used, ud)!=0){ lb->used=0; return -1; } lb->used=0; }
  }
  return 0;
}

struct ctx {
  int node_fd, miner_fd;
  int pin; const char *pin_file;          // pinning mode + where to publish the pinned pre_pow for external tools
  uint64_t cur_height, cur_job_id;
  char pinned[8192]; int have_pinned;      // the {params} of the one job pinned for cur_height
  uint64_t fwd_submits, steer_drops, jobs_seen, height_changes;
};

// publish the pinned job's params to the pin_file (atomic) so an external scorer sees the same pre_pow.
static void publish_pinned(struct ctx *c){
  if(!c->pin_file || !c->have_pinned) return;
  char tmp[1100]; snprintf(tmp,sizeof tmp,"%s.tmp",c->pin_file);
  FILE *f=fopen(tmp,"w"); if(!f) return;
  fputs(c->pinned,f); fputc('\n',f); fclose(f); rename(tmp,c->pin_file);
}

// node -> miner. Pass-through by default (track height). In pin mode: capture one pre_pow per height,
// publish it, push it to the miner once, and suppress the node's intra-height churn.
static int on_node_line(const char *line, size_t len, void *ud){
  struct ctx *c = (struct ctx*)ud;
  if(line_is_job(line)){
    uint64_t h=json_u64(line,"height"), j=json_u64(line,"job_id");
    c->jobs_seen++;
    int newblock = (h && h > c->cur_height);
    if(newblock){ c->height_changes++; c->cur_height=h; c->cur_job_id=j; }
    if(c->pin){
      if(newblock){
        if(!extract_obj(line,"\"result\":",c->pinned,sizeof c->pinned)) extract_obj(line,"\"params\":",c->pinned,sizeof c->pinned);
        c->have_pinned = (c->pinned[0]=='{');
        if(c->have_pinned){
          publish_pinned(c);
          char push[8500]; int pn=snprintf(push,sizeof push,"{\"id\":\"Stratum\",\"jsonrpc\":\"2.0\",\"method\":\"job\",\"params\":%s}\n",c->pinned);
          printf("[sched] PIN height %llu (job_id %llu) -> pinned + published + pushed to miner\n",(unsigned long long)h,(unsigned long long)j); fflush(stdout);
          return send_all(c->miner_fd,push,(size_t)pn);
        }
      }
      return 0; // pin mode: suppress same-height churn (miner stays on the pinned pre_pow)
    }
    if(newblock){ printf("[sched] NEW BLOCK height %llu (job_id %llu)\n",(unsigned long long)h,(unsigned long long)j); fflush(stdout); }
  }
  return send_all(c->miner_fd,line,len);
}

// miner -> node. Drop stale submits (the height has advanced). In pin mode also answer the miner's
// getjobtemplate locally with the pinned job. Everything else (login/keepalive/fresh submits) passes through.
static int on_miner_line(const char *line, size_t len, void *ud){
  struct ctx *c = (struct ctx*)ud;
  if(line_is_submit(line)){
    uint64_t sh=json_u64(line,"height"), sj=json_u64(line,"job_id");
    if(c->cur_height && sh && sh < c->cur_height){
      c->steer_drops++;
      printf("[sched] STEER-DROP submit: height %llu < current %llu (job_id %llu) -> dropped, NOT a miss | drops=%llu\n",
        (unsigned long long)sh,(unsigned long long)c->cur_height,(unsigned long long)sj,(unsigned long long)c->steer_drops);
      fflush(stdout);
      return 0;
    }
    c->fwd_submits++;
    return send_all(c->node_fd,line,len);
  }
  if(c->pin && line_is_getjob(line)){
    if(c->have_pinned){
      char id[256]="\"id\":\"getjob\""; extract_id(line,id,sizeof id);
      char resp[8800]; int rn=snprintf(resp,sizeof resp,"{%s,\"jsonrpc\":\"2.0\",\"method\":\"getjobtemplate\",\"result\":%s}\n",id,c->pinned);
      return send_all(c->miner_fd,resp,(size_t)rn);   // local pinned answer
    }
    return send_all(c->node_fd,line,len);              // bootstrap: no pin yet -> let the node answer
  }
  return send_all(c->node_fd,line,len);
}

int main(void){
  const char *lp = getenv("M1_SCHED_LISTEN"); int listen_port = lp&&*lp?atoi(lp):3410;
  const char *nh = getenv("M1_SCHED_NODE_HOST"); if(!nh||!*nh) nh="127.0.0.1";
  const char *np = getenv("M1_SCHED_NODE_PORT"); if(!np||!*np) np="3416";
  int pin = getenv("M1_SCHED_PIN") && atoi(getenv("M1_SCHED_PIN"))!=0;
  const char *pin_file = getenv("M1_SCHED_PIN_FILE"); if(!pin_file||!*pin_file) pin_file="/tmp/m1_pinned.json";

  int lfd = listen_on(listen_port);
  if(lfd<0){ fprintf(stderr,"m1_scheduler: cannot listen on %d: %s\n",listen_port,strerror(errno)); return 1; }
  printf("[sched] listening 127.0.0.1:%d -> node %s:%s | mode=%s\n",listen_port,nh,np,pin?"PIN":"pass-through");
  if(pin) printf("[sched] pinned pre_pow -> %s\n",pin_file);
  fflush(stdout);

  for(;;){
    struct sockaddr_in ca; socklen_t cl=sizeof ca;
    int mfd = accept(lfd,(struct sockaddr*)&ca,&cl);
    if(mfd<0){ if(errno==EINTR) continue; fprintf(stderr,"[sched] accept: %s\n",strerror(errno)); break; }
    int nfd = connect_node(nh,np);
    if(nfd<0){ fprintf(stderr,"[sched] cannot reach node %s:%s; dropping miner\n",nh,np); close(mfd); continue; }
    printf("[sched] miner connected; bridged to node. proxying...\n"); fflush(stdout);

    struct ctx c; memset(&c,0,sizeof c); c.node_fd=nfd; c.miner_fd=mfd; c.pin=pin; c.pin_file=pin_file;
    struct lbuf nb, mb; nb.used=0; mb.used=0;
    char rb[65536];
    struct pollfd pfds[2]; pfds[0].fd=nfd; pfds[1].fd=mfd;
    int alive=1;
    while(alive){
      pfds[0].events=POLLIN; pfds[1].events=POLLIN; pfds[0].revents=pfds[1].revents=0;
      int pr=poll(pfds,2,-1);
      if(pr<0){ if(errno==EINTR) continue; break; }
      if(pfds[0].revents & POLLIN){ ssize_t n=recv(nfd,rb,sizeof rb,0); if(n<=0){ alive=0; } else if(feed(&nb,rb,(size_t)n,on_node_line,&c)!=0) alive=0; }
      if(alive && (pfds[1].revents & POLLIN)){ ssize_t n=recv(mfd,rb,sizeof rb,0); if(n<=0){ alive=0; } else if(feed(&mb,rb,(size_t)n,on_miner_line,&c)!=0) alive=0; }
      if(pfds[0].revents & (POLLHUP|POLLERR)) alive=0;
      if(pfds[1].revents & (POLLHUP|POLLERR)) alive=0;
    }
    printf("[sched] session ended | jobs=%llu height_changes=%llu submits=%llu steer_drops=%llu\n",
      (unsigned long long)c.jobs_seen,(unsigned long long)c.height_changes,(unsigned long long)c.fwd_submits,(unsigned long long)c.steer_drops);
    fflush(stdout);
    close(mfd); close(nfd);
  }
  close(lfd); return 0;
}
