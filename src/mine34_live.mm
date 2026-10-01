// mine34_live: live Grin Cuckatoo-32 miner = bucketed trim -> gather survivor indices -> recover + verify.
//
// Combines a reservation-staged trim pipeline (L1v+L2 seed, trim_stage+L2 rounds) with a host
// recovery oracle (union-find 2-core + 42-cycle find + Tromp verify()). The trim stores survivors
// as edge indices in fine buckets, so no recovery kernel is needed; the indices are gathered
// directly and handed to recover(). Scans keys until a cuckatoo 42-cycle passes verify(), which
// prints POW_OK.
//
// build: make   (links submit_source/ for key derivation, job assignment and submit)
// run:   ./bin/v2/mine34_live 32 160 0    # edge bits, half-rounds per graph, 0 = mine until stopped
#import <Metal/Metal.h>
#import <Foundation/Foundation.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <time.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <pthread/qos.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <poll.h>
#include "m1ultra_grin_rsi.h"            // M1RsiKeys, M1RsiProof42
#include "m1mean_sidecar_job_assigner.h" // M1MeanSidecarJobTemplate, parse/frames
extern uint32_t m1rsi_grin_keys_from_pre_pow_nonce(const uint8_t*,size_t,uint64_t,M1RsiKeys*);
extern uint64_t m1rsi_proof_difficulty(const M1RsiProof42*,uint32_t,uint64_t);
// ---- minimal persistent stratum client (connect/login once; getjob+submit on same fd) ----
static int LFD=-1;
static int strat_conn(const char*host,uint16_t port){ char ps[16]; struct addrinfo h,*res=NULL,*rp; memset(&h,0,sizeof h);
  h.ai_family=AF_UNSPEC; h.ai_socktype=SOCK_STREAM; snprintf(ps,sizeof ps,"%u",port?port:3416);
  if(getaddrinfo(host,ps,&h,&res)!=0)return -1; int fd=-1;
  for(rp=res;rp;rp=rp->ai_next){ fd=socket(rp->ai_family,rp->ai_socktype,rp->ai_protocol); if(fd<0)continue; if(connect(fd,rp->ai_addr,rp->ai_addrlen)==0)break; close(fd); fd=-1; }
  freeaddrinfo(res); if(fd>=0){ struct timeval tv={30,0}; setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof tv); setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&tv,sizeof tv); int nd=1; setsockopt(fd,IPPROTO_TCP,TCP_NODELAY,&nd,sizeof nd);} return fd; }
static int strat_send(const char*s){ size_t n=strlen(s); while(n){ ssize_t w=send(LFD,s,n,0); if(w<=0)return -1; s+=w; n-=w;} return 0; }
static ssize_t strat_line(char*b,size_t cap){ size_t u=0; while(u+1<cap){ char c=0; ssize_t r=recv(LFD,&c,1,0); if(r<=0)return r; b[u++]=c; if(c=='\n')break; } b[u]=0; return (ssize_t)u; }
static int strat_login(const char*host,uint16_t port,const char*login,const char*pass,const char*agent){
  LFD=strat_conn(host,port); if(LFD<0)return -1; char line[65536],msg[65536];
  if(login&&pass){ if(m1mean_sidecar_format_login_frame("login",login,pass,agent,msg,sizeof msg)==0||strat_send(msg)!=0||strat_line(line,sizeof line)<=0)return -2;
    if(!strstr(line,"\"result\":\"ok\"")&&!strstr(line,"\"result\": \"ok\""))return -3; }
  return 0; }
// drain all buffered lines and keep the newest job. The node pushes unsolicited job updates on the
// same socket; returning the oldest buffered job meant mining a stale block that the node then
// rejected as submitted too late. poll(0) after each line stops once the socket buffer is empty.
static int strat_getjob(M1MeanSidecarJobTemplate*job){ char line[65536],msg[65536];
  if(m1mean_sidecar_format_getjobtemplate_frame("getjob",msg,sizeof msg)==0||strat_send(msg)!=0)return -1;
  int got=0;
  while(strat_line(line,sizeof line)>0){
    if(strstr(line,"\"pre_pow\"")&&strstr(line,"\"job_id\"")){
      M1MeanSidecarJobTemplate t; if(m1mean_sidecar_parse_job_template(line,&t)==M1MEAN_SIDECAR_JOB_OK){ *job=t; got=1; } }
    if(got){ struct pollfd pf={LFD,POLLIN,0}; if(poll(&pf,1,0)<=0) break; } // newest wins; stop when drained
  }
  return got?0:-3; }
static size_t hexdec(const char*h,uint8_t*o,size_t cap){ size_t n=0; for(size_t i=0;h[i]&&h[i+1];i+=2){ int a=h[i],b=h[i+1];
  int da=(a>='0'&&a<='9')?a-'0':(a>='a'&&a<='f')?a-'a'+10:(a>='A'&&a<='F')?a-'A'+10:-1;
  int db=(b>='0'&&b<='9')?b-'0':(b>='a'&&b<='f')?b-'a'+10:(b>='A'&&b<='F')?b-'A'+10:-1;
  if(da<0||db<0||n>=cap)break; o[n++]=(uint8_t)((da<<4)|db); } return n; }
static int u64cmp(const void*a,const void*b){ uint64_t x=*(const uint64_t*)a,y=*(const uint64_t*)b; return x<y?-1:x>y?1:0; }
static int strat_submit(uint64_t height,uint64_t job_id,uint64_t nonce,const uint32_t*sol42){ char msg[4096]; uint64_t pow[42];
  for(int i=0;i<42;i++)pow[i]=sol42[i]; qsort(pow,42,sizeof(uint64_t),u64cmp);
  int p=snprintf(msg,sizeof msg,"{\"id\":\"submit\",\"jsonrpc\":\"2.0\",\"method\":\"submit\",\"params\":{\"edge_bits\":32,\"height\":%llu,\"job_id\":%llu,\"nonce\":%llu,\"pow\":[",
    (unsigned long long)height,(unsigned long long)job_id,(unsigned long long)nonce);
  for(int i=0;i<42;i++)p+=snprintf(msg+p,sizeof msg-p,"%s%llu",i?",":"",(unsigned long long)pow[i]);
  snprintf(msg+p,sizeof msg-p,"]}}\n"); return strat_send(msg); }
  // write-only: the submit response is drained by the next strat_getjob. Reading it here raced with the
  // node's job pushes (it often grabbed a "method":"job" push, not the submit ack) and stalled the loop.
static void hexenc(const uint8_t*in,size_t n,char*out,size_t cap){ static const char h[]="0123456789abcdef"; if(!out||cap==0)return; size_t j=0;
  for(size_t i=0;i<n && j+2<cap;i++){ out[j++]=h[in[i]>>4]; out[j++]=h[in[i]&15]; } out[j]=0; }
static uint64_t wall_ms(){ struct timeval tv; gettimeofday(&tv,NULL); return (uint64_t)tv.tv_sec*1000ull+(uint64_t)tv.tv_usec/1000ull; }
// ---- hot telemetry (default off): bounded local JSONL appends, no in-memory event queue. ----
typedef struct{ int on,disabled,warned; FILE*f; char path[1024]; uint64_t bytes,max_bytes; int keep_files; pthread_mutex_t mx; } TelState;
static TelState TEL={0,0,0,NULL,{0},0,0,4,PTHREAD_MUTEX_INITIALIZER};
static void tel_disable_locked(const char*why){ if(!TEL.warned){ printf("TELEMETRY_DISABLED: %s errno=%d\n",why?why:"write_fail",errno); TEL.warned=1; }
  if(TEL.f){ fclose(TEL.f); TEL.f=NULL; } TEL.disabled=1; TEL.on=0; }
static void tel_rotate_locked(void){ if(!TEL.f||TEL.max_bytes==0||TEL.bytes<TEL.max_bytes)return; fclose(TEL.f); TEL.f=NULL;
  if(TEL.keep_files<=0){ remove(TEL.path); }
  else{ char oldp[1200],newp[1200]; for(int i=TEL.keep_files-1;i>=1;i--){ snprintf(oldp,sizeof oldp,"%s.%d",TEL.path,i); snprintf(newp,sizeof newp,"%s.%d",TEL.path,i+1); rename(oldp,newp); }
    snprintf(newp,sizeof newp,"%s.1",TEL.path); rename(TEL.path,newp); }
  TEL.f=fopen(TEL.path,"a"); TEL.bytes=0; if(!TEL.f){ tel_disable_locked("rotate_reopen_fail"); return; } setvbuf(TEL.f,NULL,_IOLBF,0); }
static void tel_init(void){ const char*p=getenv("M1_TELEMETRY_PATH"); if(!p||!*p)return; strncpy(TEL.path,p,sizeof TEL.path-1); TEL.path[sizeof TEL.path-1]=0;
  double max_mb=getenv("M1_TELEMETRY_MAX_MB")?atof(getenv("M1_TELEMETRY_MAX_MB")):256.0; TEL.max_bytes=max_mb>0.0?(uint64_t)(max_mb*1024.0*1024.0):0ull;
  TEL.keep_files=getenv("M1_TELEMETRY_KEEP_FILES")?atoi(getenv("M1_TELEMETRY_KEEP_FILES")):4; if(TEL.keep_files<0)TEL.keep_files=0; if(TEL.keep_files>32)TEL.keep_files=32;
  TEL.f=fopen(TEL.path,"a"); if(!TEL.f){ tel_disable_locked("open_fail"); return; } fseek(TEL.f,0,SEEK_END); long pos=ftell(TEL.f); TEL.bytes=pos>0?(uint64_t)pos:0; setvbuf(TEL.f,NULL,_IOLBF,0); TEL.on=1;
  printf("TELEMETRY: ON path=%s rotate_mb=%.3f keep_files=%d\n",TEL.path,max_mb,TEL.keep_files); }
static void tel_close(void){ pthread_mutex_lock(&TEL.mx); if(TEL.f){ fclose(TEL.f); TEL.f=NULL; } TEL.on=0; pthread_mutex_unlock(&TEL.mx); }
static void tel_write(const char*fmt,...){ if(!TEL.on||TEL.disabled)return; pthread_mutex_lock(&TEL.mx); if(!TEL.on||TEL.disabled){ pthread_mutex_unlock(&TEL.mx); return; }
  tel_rotate_locked(); if(!TEL.f){ pthread_mutex_unlock(&TEL.mx); return; } va_list ap; va_start(ap,fmt); int n=vfprintf(TEL.f,fmt,ap); va_end(ap);
  if(n<0){ tel_disable_locked("write_fail"); pthread_mutex_unlock(&TEL.mx); return; } TEL.bytes+=(uint64_t)n; pthread_mutex_unlock(&TEL.mx); }
static void tel_job(uint64_t h,uint64_t j,uint64_t d,const char*ppid,const char*pphex,uint64_t gen,double th){
  tel_write("{\"receipt_kind\":\"mine34_hot_job.v1\",\"height\":%llu,\"job_id\":%llu,\"difficulty\":%llu,\"pre_pow_id\":\"%s\",\"pre_pow_hex\":\"%s\",\"generation\":%llu,\"threshold\":%.6f,\"timestamp_ms\":%llu}\n",
    (unsigned long long)h,(unsigned long long)j,(unsigned long long)d,ppid?ppid:"",pphex?pphex:"",(unsigned long long)gen,th,(unsigned long long)wall_ms()); }
static void tel_score(uint64_t h,uint64_t j,uint64_t d,const char*ppid,uint64_t gen,uint64_t nonce,double score,double th,const char*decision){
  tel_write("{\"receipt_kind\":\"mine34_hot_score.v1\",\"height\":%llu,\"job_id\":%llu,\"difficulty\":%llu,\"pre_pow_id\":\"%s\",\"generation\":%llu,\"nonce\":%llu,\"skip_score\":%.6f,\"threshold\":%.6f,\"decision\":\"%s\",\"timestamp_ms\":%llu}\n",
    (unsigned long long)h,(unsigned long long)j,(unsigned long long)d,ppid?ppid:"",(unsigned long long)gen,(unsigned long long)nonce,score,th,decision,(unsigned long long)wall_ms()); }
static void tel_result(uint64_t h,uint64_t j,const char*ppid,uint64_t gen,uint64_t nonce,int cycle_found,int verify_ok,int submitted,int has_score,double score){
  char score_part[80]=""; if(has_score) snprintf(score_part,sizeof score_part,",\"skip_score\":%.6f",score);
  tel_write("{\"receipt_kind\":\"mine34_hot_mine_result.v1\",\"height\":%llu,\"job_id\":%llu,\"pre_pow_id\":\"%s\",\"generation\":%llu,\"nonce\":%llu,\"cycle_found\":%s,\"verify_ok\":%s,\"submitted\":%s%s,\"timestamp_ms\":%llu}\n",
    (unsigned long long)h,(unsigned long long)j,ppid?ppid:"",(unsigned long long)gen,(unsigned long long)nonce,cycle_found?"true":"false",verify_ok?"true":"false",submitted?"true":"false",score_part,(unsigned long long)wall_ms()); }
// ---- steerer (default off): cheap pre-trim skip score computed before committing to a full solve ----
// Samples 2^20 edges via siphash from the live job keys and computes a skip score; if it exceeds
// the M1_STEER threshold the graph is predicted cycle-free and skipped, saving the full solve.
// Caveat: the threshold was calibrated on synthetic keys, and on real keys this score showed no
// usable signal in held-out tests, so leave it off unless it is revalidated.
static uint64_t STK0,STK1,STK2,STK3;
typedef struct{ double dup,branch,corridor,closure,deg2; } SteerWeights;
static const SteerWeights STEER_BASE_W={500000.0,300000.0,-1500000.0,-1000000.0,-250000.0};
static inline uint64_t st_rotl(uint64_t x,int b){return (x<<b)|(x>>(64-b));}
static inline uint64_t st_sip(uint64_t n){ uint64_t v0=STK0,v1=STK1,v2=STK2,v3=STK3^n;
#define STR v0+=v1;v2+=v3;v1=st_rotl(v1,13)^v0;v3=st_rotl(v3,16)^v2;v0=st_rotl(v0,32);v2+=v1;v0+=v3;v1=st_rotl(v1,17)^v2;v3=st_rotl(v3,21)^v0;v2=st_rotl(v2,32);
  STR STR v0^=n; v2^=0xff; STR STR STR STR
#undef STR
  return v0^v1^v2^v3; }
static double steer_skip_score_w(uint64_t k0,uint64_t k1,uint64_t k2,uint64_t k3,SteerWeights w){
  STK0=k0;STK1=k1;STK2=k2;STK3=k3;
  const uint64_t SC=1ULL<<20, ST=4096ULL, em=0xFFFFFFFFULL, nm=0xFFFFFFFFULL, bm=(1ULL<<16)-1ULL;
  uint64_t samples=0,dup=0,closure=0,deg2=0,branch=0,corridor=0;
  for(uint64_t i=0;i<SC;i++){ uint64_t edge=(i*ST)&em;
    uint64_t left=st_sip(edge*2ULL)&nm, right=st_sip(edge*2ULL+1ULL)&nm; left>>=1; right>>=1;
    uint64_t lb=left&bm, rb=right&bm; samples++;
    if(lb==rb)dup++; if(((lb+rb+(edge&bm))&bm)==0)closure++;
    if(__builtin_popcountll((left^right)&((1ULL<<20)-1ULL))<=10)deg2++;
    if(__builtin_popcountll((left+0x9e3779b97f4a7c15ULL)^right)>34)branch++;
    for(uint32_t j=1;j<=4;j++){ uint64_t ne=(edge+(uint64_t)j*ST)&em;
      uint64_t nl=st_sip(ne*2ULL)&nm, nr=st_sip(ne*2ULL+1ULL)&nm; nl>>=1; nr>>=1;
      uint64_t nlb=nl&bm, nrb=nr&bm; if(nrb==lb||nlb==rb)corridor++; } }
  double dn=samples?(double)samples:1.0, dd=dn*4.0;
  return w.dup*(dup/dn)+w.branch*(branch/dn)+w.corridor*(corridor/dd)+w.closure*(closure/dn)+w.deg2*(deg2/dn);
}
static double steer_skip_score(uint64_t k0,uint64_t k1,uint64_t k2,uint64_t k3){ return steer_skip_score_w(k0,k1,k2,k3,STEER_BASE_W); }
static int steer_state_load(const char*path,uint64_t diff,double*threshold,SteerWeights*w){
  if(!path||!*path||!threshold||!w)return 0; FILE*f=fopen(path,"r"); if(!f)return 0;
  char line[4096],tag[32]; unsigned long long bmin,bmax,labels,hits,updated; double th,dup,branch,corridor,closure,deg2,skip,basegps,steergps;
  int found=0; unsigned long long best_span=~0ULL; double best_th=*threshold; SteerWeights best_w=*w;
  while(fgets(line,sizeof line,f)){ if(line[0]=='#'||line[0]=='\n')continue; tag[0]=0;
    int n=sscanf(line,"%31s %llu %llu %lf %lf %lf %lf %lf %lf %llu %llu %lf %lf %lf %llu",
      tag,&bmin,&bmax,&th,&dup,&branch,&corridor,&closure,&deg2,&labels,&hits,&skip,&basegps,&steergps,&updated);
    if(n<9||strcmp(tag,"bucket")!=0)continue; if(diff<bmin||diff>bmax)continue;
    unsigned long long span=bmax-bmin; if(!found||span<best_span){ found=1; best_span=span; best_th=th; best_w=(SteerWeights){dup,branch,corridor,closure,deg2}; } }
  fclose(f); if(!found)return 0; *threshold=best_th; *w=best_w; return 1; }
// ---- parallel scanner: a CPU scorer thread (producer) fills a keep-queue of low-skip nonces; the
// GPU mining loop (consumer) drains it. Scoring overlaps mining, so the GPU never waits on it.
// A job change bumps S_GEN and flushes the queue so stale nonces are dropped. Switch: M1_STEER=<thresh>.
static pthread_mutex_t SMX=PTHREAD_MUTEX_INITIALIZER;
static uint8_t S_PP[8192]; static size_t S_PPLEN=0; static volatile uint64_t S_GEN=0; static volatile int S_STOP=0; static double S_THRESH=0; static SteerWeights S_W={500000.0,300000.0,-1500000.0,-1000000.0,-250000.0};
static uint64_t S_H=0,S_J=0,S_D=0; static char S_PPID[2*M1MEAN_SIDECAR_PRE_POW_ID_BYTES+1];
#define QCAP 512
static struct { uint64_t nonce, gen; double score; } S_Q[QCAP]; static int S_QH=0,S_QT=0;
static volatile unsigned long S_SCANNED=0,S_SKIPPED=0;
static void* scorer_thread(void* arg){ (void)arg; uint64_t my_gen=0, scan=0;
  while(!S_STOP){
    uint8_t pp[8192]; size_t ppl; uint64_t gen,h,j,d; char ppid[sizeof S_PPID]; SteerWeights w; double th;
    pthread_mutex_lock(&SMX); memcpy(pp,S_PP,sizeof pp); ppl=S_PPLEN; gen=S_GEN; h=S_H; j=S_J; d=S_D; memcpy(ppid,S_PPID,sizeof ppid); w=S_W; th=S_THRESH; pthread_mutex_unlock(&SMX);
    if(ppl==0){ usleep(50000); continue; }
    if(gen!=my_gen){ my_gen=gen; scan=0; }
    M1RsiKeys k; m1rsi_grin_keys_from_pre_pow_nonce(pp,ppl,scan,&k);
    double ss=steer_skip_score_w(k.k0,k.k1,k.k2,k.k3,w); __sync_fetch_and_add(&S_SCANNED,1ul);
    tel_score(h,j,d,ppid,gen,scan,ss,th,ss<=th?"would_keep":"would_skip");
    if(ss<=th){ for(;;){ if(S_STOP)break;
        pthread_mutex_lock(&SMX); int nt=(S_QT+1)%QCAP;
        if(gen!=S_GEN){ pthread_mutex_unlock(&SMX); break; }
        if(nt!=S_QH){ S_Q[S_QT].nonce=scan; S_Q[S_QT].gen=gen; S_Q[S_QT].score=ss; S_QT=nt; pthread_mutex_unlock(&SMX); break; }
        pthread_mutex_unlock(&SMX); usleep(10000); } }   // queue full -> wait for the GPU to drain
    else __sync_fetch_and_add(&S_SKIPPED,1ul);
    scan++;
  } return NULL; }
#define TPB 1024
#define PROOFSIZE 42
#define SIZEMASK (~0u >> __builtin_clz(PROOFSIZE))
typedef uint64_t u64; typedef uint32_t u32; typedef uint64_t word_t;
static double now_s(){ struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t); return t.tv_sec+t.tv_nsec*1e-9; }
// cb_note: command-buffer error reporting. The happy path costs one status compare.
static int MTL_ERRS=0;
static int cb_note(id<MTLCommandBuffer> c,const char*label){ if(!c||c.status==MTLCommandBufferStatusCompleted) return 0; MTL_ERRS++;
  const char*msg=(c.error&&c.error.localizedDescription)?c.error.localizedDescription.UTF8String:"unknown";
  printf("METAL_COMMAND_ERROR label=%s status=%ld error=%s\n",label?label:"?",(long)c.status,msg);
  tel_write("{\"receipt_kind\":\"mine34_metal_command_error.v1\",\"label\":\"%s\",\"status\":%ld,\"error\":\"%s\",\"timestamp_ms\":%llu}\n",
    label?label:"?",(long)c.status,msg,(unsigned long long)wall_ms());
  return 1; }

// ---- host SipHash (Tromp 4-key variant, matches GPU sip24) + verify() oracle ----
static inline u64 hrotl(u64 x,u64 b){return (x<<b)|(x>>(64-b));}
#define SR v0+=v1;v2+=v3;v1=hrotl(v1,13);v3=hrotl(v3,16);v1^=v0;v3^=v2;v0=hrotl(v0,32);v2+=v1;v0+=v3;v1=hrotl(v1,17);v3=hrotl(v3,21);v1^=v2;v3^=v0;v2=hrotl(v2,32);
static u64 SK0,SK1,SK2,SK3; static word_t NODEMASK_G;
static u64 sipc(u64 n){ u64 v0=SK0,v1=SK1,v2=SK2,v3=SK3; v3^=n; SR SR v0^=n; v2^=0xff; SR SR SR SR return (v0^v1)^(v2^v3); }
static word_t sipnode(word_t e,u32 uv){ return sipc(2*(u64)e+uv)&NODEMASK_G; }
static int verify(word_t edges[PROOFSIZE]){
  word_t uvs[2*PROOFSIZE],xor0,xor1,u,v; word_t prev[2*PROOFSIZE],headu[SIZEMASK+1],headv[SIZEMASK+1];
  xor0=xor1=(PROOFSIZE/2)&1; memset(headu,-1,sizeof(headu)); memset(headv,-1,sizeof(headv));
  for(u32 n=0;n<PROOFSIZE;n++){
    if(edges[n]>NODEMASK_G) return 1;
    if(n && edges[n]<=edges[n-1]) return 2;
    u=sipnode(edges[n],0); xor0^=uvs[2*n]=u; prev[2*n]=headu[(u>>1)&SIZEMASK]; headu[(u>>1)&SIZEMASK]=2*n;
    v=sipnode(edges[n],1); xor1^=uvs[2*n+1]=v; prev[2*n+1]=headv[(v>>1)&SIZEMASK]; headv[(v>>1)&SIZEMASK]=2*n+1;
  }
  for(u32 n=0;n<PROOFSIZE;n++){
    if(prev[2*n]==(word_t)-1) prev[2*n]=headu[(uvs[2*n]>>1)&SIZEMASK];
    if(prev[2*n+1]==(word_t)-1) prev[2*n+1]=headv[(uvs[2*n+1]>>1)&SIZEMASK];
  }
  if(xor0|xor1) return 3;
  u32 n=0,i=0,j; do{
    for(u32 k=j=i;(k=prev[k])!=i;){ if(uvs[k]>>1==uvs[i]>>1){ if(j!=i) return 4; j=k; } }
    if(j==i||uvs[j]==uvs[i]) return 5; i=j^1; n++;
  } while(i!=0);
  return n==PROOFSIZE?0:6;
}
// ---- recover(): Tromp cuckatoo cycle-finder (ported from cuckatoo/graph.hpp) ----
// O(ne log ne) densify + O(ne) adjacency build + depth-<=PROOFSIZE DFS, vs the old O(ne^2).
// Our miner keeps full 32-bit endpoints (no Tromp COMPRESSROUND), so we densify node-pairs
// ourselves (sort->dense rank), preserving the ^1 partner pairing (node = 2*rank + lsb).
#define G_NIL (~(u32)0)
typedef struct { u32 next, to; } glink;
static u32 *G_adj=NULL; static glink *G_lnk=NULL; static u32 *G_vis=NULL;
static u32 G_nlinks, G_MAXNODES, *G_nonce, *G_sol2, G_path[PROOFSIZE+1]; static int G_found;
static int u32cmp(const void*a,const void*b){ u32 x=*(const u32*)a,y=*(const u32*)b; return x<y?-1:(x>y); }
// LSD radix sort (4x8-bit), ascending u32 -- output is bit-identical to qsort(...,u32cmp) but O(n) not O(n log n).
// 4 passes => data ends back in a. Used for the peel densify sort (replaces qsort of the ~643k survivor endpoints).
static void radix_u32(u32* a, u32 n){
  if(n<2) return; u32* tmp=(u32*)malloc((size_t)n*4); if(!tmp){ qsort(a,n,4,u32cmp); return; }
  u32* src=a; u32* dst=tmp;
  for(int shift=0; shift<32; shift+=8){
    u32 cnt[256]; for(int k=0;k<256;k++) cnt[k]=0;
    for(u32 i=0;i<n;i++) cnt[(src[i]>>shift)&0xffu]++;
    u32 sum=0; for(int k=0;k<256;k++){ u32 c=cnt[k]; cnt[k]=sum; sum+=c; }
    for(u32 i=0;i<n;i++){ u32 b=(src[i]>>shift)&0xffu; dst[cnt[b]++]=src[i]; }
    u32* t=src; src=dst; dst=t;
  }
  free(tmp); // src==a after 4 swaps; sorted data is in a
}
static u32 g_lb(const u32*arr,u32 n,u32 key){ u32 lo=0,hi=n; while(lo<hi){u32 m=(lo+hi)>>1; if(arr[m]<key)lo=m+1; else hi=m;} return lo; }
static inline int g_vt(u32 e){return (G_vis[e>>5]>>(e&31))&1;}
static inline void g_vs(u32 e){G_vis[e>>5]|=1u<<(e&31);}
static inline void g_vr(u32 e){G_vis[e>>5]&=~(1u<<(e&31));}
static void g_cycles(u32 len,u32 u,u32 dest){
  if(G_found||g_vt(u>>1)) return;
  if((u^1)==dest){
    if(len==PROOFSIZE){ word_t cand[PROOFSIZE];
      for(int z=0;z<PROOFSIZE;z++) cand[z]=G_nonce[G_path[z]];
      for(int a=0;a<PROOFSIZE;a++)for(int b=a+1;b<PROOFSIZE;b++) if(cand[b]<cand[a]){word_t t=cand[a];cand[a]=cand[b];cand[b]=t;}
      if(verify(cand)==0){ for(int z=0;z<PROOFSIZE;z++) G_sol2[z]=(u32)cand[z]; G_found=1; } }
    return; }
  if(len==PROOFSIZE) return;
  u32 au1=G_adj[u^1]; if(au1==G_NIL) return;
  g_vs(u>>1);
  for(; au1!=G_NIL; au1=G_lnk[au1].next){ G_path[len]=au1/2; g_cycles(len+1,G_lnk[au1^1].to,dest); if(G_found) break; }
  g_vr(u>>1);
}
static void g_add_edge(u32 u,u32 v){
  v+=G_MAXNODES;
  if(G_adj[u^1]!=G_NIL && G_adj[v^1]!=G_NIL){ G_path[0]=G_nlinks/2; g_cycles(1,u,v); }
  u32 ul=G_nlinks++, vl=G_nlinks++;
  for(u32 au=G_adj[u]; au!=G_NIL; au=G_lnk[au].next) if(G_lnk[au^1].to==v) return; // drop duplicate edge
  G_lnk[ul].next=G_adj[u]; G_lnk[vl].next=G_adj[v];
  G_adj[u]=ul; G_lnk[ul].to=u; G_adj[v]=vl; G_lnk[vl].to=v;
}
static int recover(word_t nodemask,u32*nonces,u32 ne,u32*sol){
  if(ne<PROOFSIZE) return 0;
  u32 *up=malloc((size_t)ne*4),*vp=malloc((size_t)ne*4),*ul=malloc((size_t)ne*4),*vl=malloc((size_t)ne*4);
  for(u32 i=0;i<ne;i++){ word_t uf=sipc(2ULL*nonces[i])&nodemask, vf=sipc(2ULL*nonces[i]+1)&nodemask;
    up[i]=(u32)(uf>>1); ul[i]=(u32)(uf&1); vp[i]=(u32)(vf>>1); vl[i]=(u32)(vf&1); }
  u32 *su=malloc((size_t)ne*4),*sv=malloc((size_t)ne*4); memcpy(su,up,(size_t)ne*4); memcpy(sv,vp,(size_t)ne*4);
  qsort(su,ne,4,u32cmp); qsort(sv,ne,4,u32cmp);
  u32 nU=0,nV=0; for(u32 i=0;i<ne;i++) if(i==0||su[i]!=su[i-1]) su[nU++]=su[i];
  for(u32 i=0;i<ne;i++) if(i==0||sv[i]!=sv[i-1]) sv[nV++]=sv[i];
  G_MAXNODES=(2*nU>2*nV)?2*nU:2*nV; if(G_MAXNODES<2)G_MAXNODES=2;
  G_adj=malloc((size_t)2*G_MAXNODES*4); for(u32 i=0;i<2*G_MAXNODES;i++) G_adj[i]=G_NIL;
  G_lnk=malloc((size_t)2*ne*sizeof(glink)); G_vis=calloc(((size_t)G_MAXNODES+31)/32,4);
  G_nlinks=0; G_found=0; G_nonce=nonces; G_sol2=sol;
  for(u32 i=0;i<ne && !G_found;i++){ u32 un=2*g_lb(su,nU,up[i])+ul[i], vn=2*g_lb(sv,nV,vp[i])+vl[i]; g_add_edge(un,vn); }
  free(up);free(vp);free(ul);free(vl);free(su);free(sv);free(G_adj);free(G_lnk);free(G_vis);
  return G_found;
}

// ---- GPU kernels: reservation-staged trim ----
static NSString *kSrc = @
"#include <metal_stdlib>\n"
"using namespace metal;\n"
"#define TPB 1024\n"
// sip24: hand-lowered 2x32-bit form with a demanded-bits final round (measured 32.16 Gsips/s vs
// 28.35 for the plain ulong version, +13.4%, bit-exact against full dumps). Every miner call site
// consumes only (sip24 & p.nodemask) with nodemask <= 32 bits, so only the low 32 bits of
// v0^v1^v2^v3 are demanded and the final round's d0 term cancels exactly. rotl32 is a free .yx swap.
"inline uint2 add64(uint2 a,uint2 b){ uint lo=a.x+b.x; return uint2(lo,a.y+b.y+(lo<a.x?1u:0u)); }\n"
"inline uint2 rl13(uint2 a){ return uint2((a.x<<13)|(a.y>>19),(a.y<<13)|(a.x>>19)); }\n"
"inline uint2 rl16(uint2 a){ return uint2((a.x<<16)|(a.y>>16),(a.y<<16)|(a.x>>16)); }\n"
"inline uint2 rl17(uint2 a){ return uint2((a.x<<17)|(a.y>>15),(a.y<<17)|(a.x>>15)); }\n"
"inline uint2 rl21(uint2 a){ return uint2((a.x<<21)|(a.y>>11),(a.y<<21)|(a.x>>11)); }\n"
"#define WR v0=add64(v0,v1);v2=add64(v2,v3);v1=rl13(v1);v3=rl16(v3);v1^=v0;v3^=v2;v0=v0.yx;v2=add64(v2,v1);v0=add64(v0,v3);v1=rl17(v1);v3=rl21(v3);v1^=v2;v3^=v0;v2=v2.yx;\n"
"inline uint sip24wlo(uint2 k0,uint2 k1,uint2 k2,uint2 k3,uint2 n){\n"
"  uint2 v0=k0,v1=k1,v2=k2,v3=k3; v3^=n;\n"
"  WR WR\n"
"  v0^=n; v2.x^=0xffu;\n"
"  WR WR WR\n"
"  uint2 b0=add64(v0,v1),b2=add64(v2,v3); uint2 c1=rl13(v1)^b0,c3=rl16(v3)^b2; uint2 d2=add64(b2,c1);\n"
"  return ((c1.x<<17)|(c1.y>>15))^((c3.x<<21)|(c3.y>>11))^d2.x^d2.y;\n"
"}\n"
"inline uint sip24(ulong k0,ulong k1,ulong k2,ulong k3, ulong n){\n"
"  return sip24wlo(uint2((uint)k0,(uint)(k0>>32)),uint2((uint)k1,(uint)(k1>>32)),uint2((uint)k2,(uint)(k2>>32)),uint2((uint)k3,(uint)(k3>>32)),uint2((uint)n,(uint)(n>>32)));\n"
"}\n"
"struct Keys{ulong k0,k1,k2,k3;};\n"
"struct P{uint nodemask,zbits,coarse_shift,coarse_n,coarse_cap,fine_shift,fine_mask,fine_n,fine_cap,side;};\n"
"inline void stage_ep(uint vep,uint vidx,uint key,uint tid,bool live,\n"
"  device atomic_uint* ccnt,device uint* cep,device uint* cidx,uint cap,\n"
"  threadgroup atomic_uint* bcnt,threadgroup uint* gbase,uint NK){\n"
"  if(tid<NK) atomic_store_explicit(&bcnt[tid],0u,memory_order_relaxed);\n"
"  threadgroup_barrier(mem_flags::mem_threadgroup);\n"
"  uint lpos=0u; if(live) lpos=atomic_fetch_add_explicit(&bcnt[key],1u,memory_order_relaxed);\n"
"  threadgroup_barrier(mem_flags::mem_threadgroup);\n"
"  if(tid<NK){ uint c=atomic_load_explicit(&bcnt[tid],memory_order_relaxed); gbase[tid]= c?atomic_fetch_add_explicit(&ccnt[tid],c,memory_order_relaxed):0u; }\n"
"  threadgroup_barrier(mem_flags::mem_threadgroup);\n"
"  if(live){ uint dd=gbase[key]+lpos; if(dd<cap){ cidx[(ulong)key*cap+dd]=vidx; } }\n"
"  threadgroup_barrier(mem_flags::mem_threadgroup);\n"
"}\n"
// three-barrier trim stage: bcnt is pre-zeroed once by the caller (sharing the seen-build barrier)
// and re-zeroed in the reservation, removing the per-chunk zero barrier (4 barriers down to 3,
// +1.4% trim). The staging is bijective, so the residual is identical.
"inline void stage_ep3(uint vidx,uint key,uint tid,bool live,\n"
"  device atomic_uint* ccnt,device uint* cidx,uint cap,\n"
"  threadgroup atomic_uint* bcnt,threadgroup uint* gbase,uint NK){\n"
"  uint lpos=0u; if(live) lpos=atomic_fetch_add_explicit(&bcnt[key],1u,memory_order_relaxed);\n"
"  threadgroup_barrier(mem_flags::mem_threadgroup);\n"
"  if(tid<NK){ uint c=atomic_load_explicit(&bcnt[tid],memory_order_relaxed); gbase[tid]= c?atomic_fetch_add_explicit(&ccnt[tid],c,memory_order_relaxed):0u; atomic_store_explicit(&bcnt[tid],0u,memory_order_relaxed); }\n"
"  threadgroup_barrier(mem_flags::mem_threadgroup);\n"
"  if(live){ uint dd=gbase[key]+lpos; if(dd<cap){ cidx[(ulong)key*cap+dd]=vidx; } }\n"
"  threadgroup_barrier(mem_flags::mem_threadgroup);\n"
"}\n"
"kernel void L1v(constant Keys& K [[buffer(0)]], constant P& p [[buffer(1)]], device atomic_uint* ccn [[buffer(2)]], device uint* cep [[buffer(3)]], device uint* cidx [[buffer(4)]], constant uint& base [[buffer(5)]], uint tid [[thread_position_in_threadgroup]], uint tgid [[threadgroup_position_in_grid]]){\n"
"  threadgroup atomic_uint bcnt[256]; threadgroup uint gbase[256];\n"
"  ulong e=(ulong)base+tgid*TPB+tid; uint ep=sip24(K.k0,K.k1,K.k2,K.k3,2*e+p.side)&p.nodemask; uint key=(ep>>p.coarse_shift)&(p.coarse_n-1u);\n"
"  stage_ep(ep,(uint)e,key,tid,true,ccn,cep,cidx,p.coarse_cap,bcnt,gbase,p.coarse_n); }\n"
"kernel void trim_stage(constant Keys& K [[buffer(0)]], constant P& p [[buffer(1)]], device const uint* fcnt [[buffer(2)]], device const uint2* fidx [[buffer(3)]], device atomic_uint* ccn [[buffer(4)]], device uint* cep [[buffer(5)]], device uint* cidx [[buffer(6)]], uint b [[threadgroup_position_in_grid]], uint tid [[thread_position_in_threadgroup]], uint tpb [[threads_per_threadgroup]]){\n"
"  threadgroup atomic_uint seen[1<<(17-5)]; threadgroup atomic_uint bcnt[256]; threadgroup uint gbase[256];\n"
"  uint c=fcnt[b]; if(c>p.fine_cap)c=p.fine_cap; ulong base=(ulong)b*p.fine_cap;\n"
"  uint words=1u<<(p.zbits-5); for(uint i=tid;i<words;i+=tpb) atomic_store_explicit(&seen[i],0u,memory_order_relaxed);\n"
"  threadgroup_barrier(mem_flags::mem_threadgroup);\n"
"  for(uint i=tid;i<c;i+=tpb){ uint z=fidx[base+i].y; atomic_fetch_or_explicit(&seen[z>>5],1u<<(z&31),memory_order_relaxed); }\n"
"  if(tid<p.coarse_n) atomic_store_explicit(&bcnt[tid],0u,memory_order_relaxed);\n"  // mine34: pre-zero bcnt (free: shares seen-build barrier) for 3-barrier staging
"  threadgroup_barrier(mem_flags::mem_threadgroup);\n"
"  for(uint cs=0; cs<c; cs+=tpb){ uint i=cs+tid; bool live=false; uint vidx=0,key=0;\n"
"    if(i<c){ uint2 ez=fidx[base+i]; uint pz=ez.y^1u;\n"
"      if((atomic_load_explicit(&seen[pz>>5],memory_order_relaxed)>>(pz&31))&1u){ uint e=ez.x; uint other=sip24(K.k0,K.k1,K.k2,K.k3,2*(ulong)e+(p.side^1u))&p.nodemask; vidx=e; key=(other>>p.coarse_shift)&(p.coarse_n-1u); live=true; } }\n"
"    stage_ep3(vidx,key,tid,live,ccn,cidx,p.coarse_cap,bcnt,gbase,p.coarse_n);\n"
"  }\n"
"}\n"
"kernel void L2(constant P& p [[buffer(0)]], device const uint* ccn [[buffer(1)]], device const uint* cep [[buffer(2)]], device const uint* cidx [[buffer(3)]], device atomic_uint* fcn [[buffer(4)]], device uint2* fi [[buffer(5)]], constant Keys& K [[buffer(6)]], uint2 tidv [[thread_position_in_threadgroup]], uint2 tg [[threadgroup_position_in_grid]]){\n"
"  uint tid=tidv.x; threadgroup atomic_uint bcnt[256]; threadgroup uint gbase[256]; uint NK=p.fine_n;\n"
"  uint coarse=tg.y, chunk=tg.x; uint c=ccn[coarse]; if(c>p.coarse_cap)c=p.coarse_cap; uint start=chunk*TPB; bool live=(start+tid)<c; uint e=0,key=0,zres=0;\n"
"  if(live){ e=cidx[(ulong)coarse*p.coarse_cap+start+tid]; uint ep=sip24(K.k0,K.k1,K.k2,K.k3,2*(ulong)e+p.side)&p.nodemask; key=(ep>>p.fine_shift)&p.fine_mask; zres=ep&((1u<<p.zbits)-1u); }\n"
"  if(tid<NK) atomic_store_explicit(&bcnt[tid],0u,memory_order_relaxed);\n"
"  threadgroup_barrier(mem_flags::mem_threadgroup);\n"
"  uint lpos=0u; if(live) lpos=atomic_fetch_add_explicit(&bcnt[key],1u,memory_order_relaxed);\n"
"  threadgroup_barrier(mem_flags::mem_threadgroup);\n"
"  if(tid<NK){ uint cnt=atomic_load_explicit(&bcnt[tid],memory_order_relaxed); uint gfb=coarse*p.fine_n+tid; gbase[tid]= cnt?atomic_fetch_add_explicit(&fcn[gfb],cnt,memory_order_relaxed):0u; }\n"
"  threadgroup_barrier(mem_flags::mem_threadgroup);\n"
"  if(live){ uint gfb=coarse*p.fine_n+key; uint dd=gbase[key]+lpos; if(dd<p.fine_cap) fi[(ulong)gfb*p.fine_cap+dd]=uint2(e,zres); } }\n"
// ---- GPU 2-core peel on dense node-pair ids (du/dv precomputed host-side, relabel sparse to dense).
// degU/degV are compact arrays (m_u/m_v entries, a few MB), so they stay cache-resident with no TLB
// cliff and no siphash.
// buffer layout (consistent across the 3): du(0) dv(1) ne(2) alive(3) degU(4) degV(5) chg(6)
"kernel void pclr(device const uint* du [[buffer(0)]], device const uint* dv [[buffer(1)]], constant uint& ne [[buffer(2)]], device uint* degU [[buffer(4)]], device uint* degV [[buffer(5)]], uint i [[thread_position_in_grid]]){\n"
"  if(i>=ne) return; degU[du[i]]=0u; degV[dv[i]]=0u; }\n"
"kernel void pcnt(device const uint* du [[buffer(0)]], device const uint* dv [[buffer(1)]], constant uint& ne [[buffer(2)]], device const uchar* alive [[buffer(3)]], device atomic_uint* degU [[buffer(4)]], device atomic_uint* degV [[buffer(5)]], uint i [[thread_position_in_grid]]){\n"
"  if(i>=ne||!alive[i]) return; atomic_fetch_add_explicit(&degU[du[i]],1u,memory_order_relaxed); atomic_fetch_add_explicit(&degV[dv[i]],1u,memory_order_relaxed); }\n"
"kernel void pkil(device const uint* du [[buffer(0)]], device const uint* dv [[buffer(1)]], constant uint& ne [[buffer(2)]], device uchar* alive [[buffer(3)]], device const uint* degU [[buffer(4)]], device const uint* degV [[buffer(5)]], device atomic_uint* chg [[buffer(6)]], uint i [[thread_position_in_grid]]){\n"
"  if(i>=ne||!alive[i]) return; if(degU[du[i]]<2u||degV[dv[i]]<2u){ alive[i]=0; atomic_store_explicit(chg,1u,memory_order_relaxed); } }\n"
// gridk: GPU-side adaptive grid for L2 (max coarse fill -> indirect dispatch args), so trim+L2 batch in one command buffer (no host readback or per-round sync).
"kernel void gridk(device const uint* ccn [[buffer(0)]], constant uint& cn [[buffer(1)]], constant uint& tpb [[buffer(2)]], device uint* grid [[buffer(3)]], uint t [[thread_position_in_grid]]){\n"
"  if(t!=0u) return; uint mc=0u; for(uint i=0;i<cn;i++){ uint c=ccn[i]; if(c>mc)mc=c; } mc=(mc+tpb-1u)/tpb; if(mc<1u)mc=1u; grid[0]=mc; grid[1]=cn; grid[2]=1u; }\n"
// ---- d2 early-abort verdict kernels (param struct named DP to avoid clashing with the trim P).
// d2emit: cut-round survivor scan -> dense SoA {idx,uf,vf} append with full endpoint ids
// uf=sip24(2e), vf=sip24(2e+1); one global atomic counter, threadgroup-batched reservation (the
// same staging idiom as the trim). Arcs join on the full id ^ 1 (same id>>1 pair, opposite lsb),
// hence DP.xb=1; joining on full-id equality instead has zero recall on real graphs. k_d2_emit
// writes a dst-only CSR (adj_dst at arc_off[src]; per-src regions are disjoint and in order, so the
// adjacency matches a host-built CSR from {src,mid,dst} triples at a third of the bytes, with no
// host rebuild). k_d2_dfs: per-source bounded DFS, 21-deep explicit stack, vertex-simple path list,
// global found-flag early exit at cand_cap==1.
"kernel void d2emit(constant Keys& K [[buffer(0)]], constant P& p [[buffer(1)]], device const uint* fcnt [[buffer(2)]], device const uint2* fidx [[buffer(3)]], device atomic_uint* dn [[buffer(4)]], device uint* didx [[buffer(5)]], device uint* dku [[buffer(6)]], device uint* dkv [[buffer(7)]], constant uint& dcap [[buffer(8)]], uint b [[threadgroup_position_in_grid]], uint tid [[thread_position_in_threadgroup]], uint tpb [[threads_per_threadgroup]]){\n"
"  threadgroup uint gbase; uint c=fcnt[b]; if(c>p.fine_cap)c=p.fine_cap; ulong base=(ulong)b*p.fine_cap;\n"
"  for(uint cs=0; cs<c; cs+=tpb){ uint i=cs+tid; uint nlive=min(c-cs,tpb);\n"
"    if(tid==0) gbase=atomic_fetch_add_explicit(dn,nlive,memory_order_relaxed);\n"
"    threadgroup_barrier(mem_flags::mem_threadgroup);\n"
"    if(i<c){ uint dd=gbase+tid; if(dd<dcap){ uint e=fidx[base+i].x; didx[dd]=e; dku[dd]=sip24(K.k0,K.k1,K.k2,K.k3,2*(ulong)e)&p.nodemask; dkv[dd]=sip24(K.k0,K.k1,K.k2,K.k3,2*(ulong)e+1)&p.nodemask; } }\n"
"    threadgroup_barrier(mem_flags::mem_threadgroup);\n"
"  } }\n"
"struct DP{ uint n; uint xb; uint hmask; };\n"
// hash-join verdict (replaces a host radix sort + binary search): open-addressing multimaps
// keyU->edge / keyV->edge, Fibonacci hash, linear probe, empty slot = 0xFFFFFFFF, table = 2x
// emit_cap slots (load at most 50%, ~11% at cut 64). Build is one CAS insert per edge per side;
// fills, build and count are fused into one command buffer. Probe chains terminate at an empty
// slot (nothing is ever deleted). dst==mid can never match under xb=1 (a key never equals its own
// ^1); under xb=0 it always does, so an explicit skip keeps the kernel exact for that mode too.
"kernel void k_d2_hbuild(constant DP& p [[buffer(0)]], const device uint* keyU [[buffer(1)]], const device uint* keyV [[buffer(2)]], device atomic_uint* HU [[buffer(3)]], device atomic_uint* HV [[buffer(4)]], uint gid [[thread_position_in_grid]]){\n"
"  if(gid>=p.n) return;\n"
"  uint s=(keyU[gid]*0x9E3779B1u)&p.hmask;\n"
"  while(true){ uint exp=0xFFFFFFFFu; if(atomic_compare_exchange_weak_explicit(&HU[s],&exp,gid,memory_order_relaxed,memory_order_relaxed)) break; if(exp!=0xFFFFFFFFu) s=(s+1u)&p.hmask; }\n"
"  s=(keyV[gid]*0x9E3779B1u)&p.hmask;\n"
"  while(true){ uint exp=0xFFFFFFFFu; if(atomic_compare_exchange_weak_explicit(&HV[s],&exp,gid,memory_order_relaxed,memory_order_relaxed)) break; if(exp!=0xFFFFFFFFu) s=(s+1u)&p.hmask; } }\n"
// Fusing count and emit into one pass measured slower (arc 62.6 vs 58.2 ms): the warm rewalk is
// cold again at 3.7M-thread scale (chains evicted across the dispatch) and the single arcN counter
// adds atomic contention. Two cold passes plus a host scan stand.
"kernel void k_d2_count(constant DP& p [[buffer(0)]], const device uint* keyU [[buffer(1)]], const device uint* keyV [[buffer(2)]], const device uint* HU [[buffer(3)]], const device uint* HV [[buffer(4)]], device uint* arc_cnt [[buffer(5)]], uint gid [[thread_position_in_grid]]){\n"
"  if(gid>=p.n) return; uint src=gid; uint ku=keyU[src]^p.xb; uint c=0;\n"
"  uint s=(ku*0x9E3779B1u)&p.hmask;\n"
"  for(uint e=HU[s]; e!=0xFFFFFFFFu; s=(s+1u)&p.hmask, e=HU[s]){\n"
"    if(e==src||keyU[e]!=ku) continue; uint mid=e; uint kv=keyV[mid]^p.xb;\n"
"    uint t=(kv*0x9E3779B1u)&p.hmask;\n"
"    for(uint f=HV[t]; f!=0xFFFFFFFFu; t=(t+1u)&p.hmask, f=HV[t]){\n"
"      if(keyV[f]!=kv||f==src) continue; if(p.xb==0u&&f==mid) continue; c++; } }\n"
"  arc_cnt[src]=c; }\n"
"kernel void k_d2_emit(constant DP& p [[buffer(0)]], const device uint* keyU [[buffer(1)]], const device uint* keyV [[buffer(2)]], const device uint* HU [[buffer(3)]], const device uint* HV [[buffer(4)]], const device uint* arc_off [[buffer(5)]], device uint* adj_dst [[buffer(6)]], uint gid [[thread_position_in_grid]]){\n"
"  if(gid>=p.n) return; uint src=gid; uint ku=keyU[src]^p.xb; uint w=arc_off[src];\n"
"  uint s=(ku*0x9E3779B1u)&p.hmask;\n"
"  for(uint e=HU[s]; e!=0xFFFFFFFFu; s=(s+1u)&p.hmask, e=HU[s]){\n"
"    if(e==src||keyU[e]!=ku) continue; uint mid=e; uint kv=keyV[mid]^p.xb;\n"
"    uint t=(kv*0x9E3779B1u)&p.hmask;\n"
"    for(uint f=HV[t]; f!=0xFFFFFFFFu; t=(t+1u)&p.hmask, f=HV[t]){\n"
"      if(keyV[f]!=kv||f==src) continue; if(p.xb==0u&&f==mid) continue; adj_dst[w]=f; w++; } } }\n"
"kernel void k_d2_dfs(constant DP& p [[buffer(0)]], const device uint* adj_off [[buffer(1)]], const device uint* adj_dst [[buffer(2)]], device atomic_uint* found [[buffer(3)]], device atomic_uint* cand [[buffer(4)]], constant uint& cand_cap [[buffer(5)]], uint gid [[thread_position_in_grid]]){\n"
"  if(gid>=p.n) return; uint src=gid;\n"
"  uint path[22]; uint it[22];\n"
"  int d=0; path[0]=src; it[0]=adj_off[src]; uint poll=0;\n"
"  while(d>=0){\n"
"    if(((poll++)&1023u)==0u && cand_cap==1u && atomic_load_explicit(found,memory_order_relaxed)) return;\n"
"    uint i=it[d];\n"
"    if(i>=adj_off[path[d]+1]){ d--; continue; }\n"
"    it[d]=i+1u; uint nxt=adj_dst[i];\n"
"    if(nxt==src){ if(d+1==21){ atomic_fetch_add_explicit(cand,1u,memory_order_relaxed);\n"
"        if(cand_cap==1u){ atomic_store_explicit(found,1u,memory_order_relaxed); return; } }\n"
"      continue; }\n"
"    if(d+1==21) continue;\n"
"    bool onp=false; for(int k=1;k<=d;k++) if(path[k]==nxt){ onp=true; break; }\n"
"    if(onp) continue;\n"
"    d++; path[d]=nxt; it[d]=adj_off[nxt];\n"
"  } }\n";

typedef struct{uint32_t nodemask,zbits,coarse_shift,coarse_n,coarse_cap,fine_shift,fine_mask,fine_n,fine_cap,side;}P;

// d2_witness: re-walk the candidate arc CSR on the CPU keeping the mid of every step (the GPU CSR
// is dst-only, so the mids are otherwise lost). Each closed vertex-simple 21-walk lifts to
// A(W) = {s_i} u {m_i} = 42 edge ids; a lift stays a candidate until verify()==0 confirms it.
// Returns 1 + sol[42] ascending on a verified lift; 0 on budget exhaustion or no verifiable lift
// (the caller falls back to the full tail, so recall is preserved by construction).
// Mid resolution: m must satisfy kU[m]==kU[s]^1 && kV[m]==kV[d]^1;
// candidates found via a host keyU-partner hash (open addressing, built once per candidate graph).
static int d2_witness(const u32*didx,const u32*kU,const u32*kV,const u32*aoff,const u32*adj,u32 n,u32*sol){
  if(!n) return 0;
  u32 hbits=1; while((1u<<hbits)<2*n) hbits++; u32 hsz=1u<<hbits, hm=hsz-1;
  u32* H=malloc((size_t)hsz*4); if(!H) return 0; memset(H,0xFF,(size_t)hsz*4);
  for(u32 i=0;i<n;i++){ u32 t=(kU[i]*0x9E3779B1u)&hm; while(H[t]!=0xFFFFFFFFu) t=(t+1)&hm; H[t]=i; }
  u32 *path=malloc(22*4), *it=malloc(22*4), *mids=malloc(21*4); u64 steps=0; int found=0; u32 closures=0;
  for(u32 src=0; src<n && !found; src++){
    if(aoff[src]==aoff[src+1]) continue;
    int d=0; path[0]=src; it[0]=aoff[src];
    while(d>=0){
      if(++steps>50000000ull) { d=-2; break; } // budget: fall back to the full tail
      u32 i=it[d];
      if(i>=aoff[path[d]+1]){ d--; continue; }
      it[d]=i+1; u32 nxt=adj[i];
      if(nxt==src && d+1==21){ closures++;
        // resolve the 21 mids for consecutive (s,d) pairs incl. the closing (path[20] -> src)
        int ok=1;
        for(int k=0;k<21 && ok;k++){ u32 a=path[k], b=(k==20)?src:path[k+1]; u32 want_u=kU[a]^1u, want_v=kV[b]^1u;
          u32 t=(want_u*0x9E3779B1u)&hm; u32 m=0xFFFFFFFFu;
          while(H[t]!=0xFFFFFFFFu){ u32 c2=H[t]; if(kU[c2]==want_u && kV[c2]==want_v && c2!=a && c2!=b){ m=c2; break; } t=(t+1)&hm; }
          if(m==0xFFFFFFFFu){ ok=0; break; } mids[k]=m; }
        if(ok){ u32 ed[42]; for(int k=0;k<21;k++){ ed[2*k]=didx[path[k]]; ed[2*k+1]=didx[mids[k]]; }
          // ascending + distinct, then the Tromp verifier has the final word
          for(int a2=1;a2<42;a2++){ u32 v2=ed[a2]; int b2=a2-1; while(b2>=0&&ed[b2]>v2){ed[b2+1]=ed[b2];b2--;} ed[b2+1]=v2; }
          int dup=0; for(int a2=1;a2<42;a2++) if(ed[a2]==ed[a2-1]){dup=1;break;}
          if(!dup){ word_t we[PROOFSIZE]; for(int a2=0;a2<42;a2++) we[a2]=ed[a2];
            if(verify(we)==0){ for(int a2=0;a2<42;a2++) sol[a2]=ed[a2]; found=1; break; } } }
        if(closures>=256u){ d=-2; break; } // closure budget
        continue; }
      if(nxt==src) continue;
      if(d+1==21) continue;
      int onp=0; for(int k2=1;k2<=d;k2++) if(path[k2]==nxt){onp=1;break;}
      if(onp) continue;
      d++; path[d]=nxt; it[d]=aoff[nxt];
    }
    if(d==-2) break; // budget exhausted: give up extraction entirely
  }
  free(H);free(path);free(it);free(mids); return found;
}
typedef struct{uint32_t n,xb,hmask;}D2PAR; // host mirror of kernel DP (hbuild/count/emit/dfs param)

int main(int argc,char**argv){
 @autoreleasepool{
  if(!isatty(1)) setvbuf(stdout,NULL,_IOLBF,0); // headless logs: line-buffer so progress is visible and a crash cannot eat buffered output
  if(getenv("M1_QOS")){ int qrc=pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE,0); printf("QOS: USER_INTERACTIVE requested on main thread rc=%d (M1_QOS set; unset => untouched)\n",qrc); } // env-gated, default off
  u32 eb=argc>1?atoi(argv[1]):27, rounds=argc>2?atoi(argv[2]):160, maxkeys=argc>3?atoi(argv[3]):2000;
  u32 zbits=17; u64 nedges=1ULL<<eb; u32 nodemask=(eb>=32)?0xFFFFFFFFu:((1u<<eb)-1u);
  u32 buckbits=eb-zbits, coarsebits=(buckbits>7)?7:buckbits, finebits=buckbits-coarsebits;  // TLB split: coarse_n=128 / fine_n=256 at C32 (fine_n<=256 fits bcnt[256])
  u32 coarse_n=1u<<coarsebits, fine_n=1u<<finebits, nb=coarse_n*fine_n;
  u32 coarse_cap=(u32)(nedges/coarse_n)+(u32)(nedges/coarse_n/16)+(1u<<16);
  u32 fine_cap=(u32)(nedges/nb)+(u32)(nedges/nb/16)+4096; // tight slack (uint2 fine)
  // M1_FINE_CAP / M1_COARSE_CAP (optional): bound the wired arena to free headroom for co-allocation.
  // Unset means the verified default formula above, and the default path is byte-identical. The cap
  // is the clip predicate: a bucket clips iff fill > cap, so a cap must stay above the measured max
  // bucket fill (fine seed0_max=133123 over 2535 graphs; coarse mean=nedges/coarse_n) or the trim
  // silently drops edges. Warn if so.
  { const char* e=getenv("M1_FINE_CAP"); if(e){ u32 v=(u32)atoi(e); if(v){
        if(v<134000u) printf("[cap] WARNING M1_FINE_CAP=%u < safe floor ~134000 (measured max fill 133123) -> clip/false-kill risk\n",v);
        fine_cap=v; } }
    e=getenv("M1_COARSE_CAP"); if(e){ u32 v=(u32)atoi(e); if(v){
        u32 cfloor=(u32)(nedges/coarse_n)+(u32)(nedges/coarse_n/64); // mean + ~1.5% guard
        if(v<cfloor) printf("[cap] WARNING M1_COARSE_CAP=%u < safe floor %u (~mean bucket fill) -> clip/false-kill risk\n",v,cfloor);
        coarse_cap=v; } } }
  u32 coarse_shift=zbits+finebits, fine_shift=zbits, fine_mask=fine_n-1u;
  NODEMASK_G=nodemask;
  id<MTLDevice> dev=MTLCreateSystemDefaultDevice(); NSError*err=nil;
  id<MTLLibrary> lib=[dev newLibraryWithSource:kSrc options:nil error:&err];
  if(!lib){printf("COMPILE_FAIL %s\n",err.localizedDescription.UTF8String);return 2;}
  id<MTLComputePipelineState> psL1=[dev newComputePipelineStateWithFunction:[lib newFunctionWithName:@"L1v"] error:&err];
  id<MTLComputePipelineState> psTS=[dev newComputePipelineStateWithFunction:[lib newFunctionWithName:@"trim_stage"] error:&err];
  id<MTLComputePipelineState> psL2=[dev newComputePipelineStateWithFunction:[lib newFunctionWithName:@"L2"] error:&err];
  id<MTLComputePipelineState> psPC=[dev newComputePipelineStateWithFunction:[lib newFunctionWithName:@"pclr"] error:&err];
  id<MTLComputePipelineState> psPN=[dev newComputePipelineStateWithFunction:[lib newFunctionWithName:@"pcnt"] error:&err];
  id<MTLComputePipelineState> psPK=[dev newComputePipelineStateWithFunction:[lib newFunctionWithName:@"pkil"] error:&err];
  id<MTLComputePipelineState> psGR=[dev newComputePipelineStateWithFunction:[lib newFunctionWithName:@"gridk"] error:&err];
  id<MTLCommandQueue> q=[dev newCommandQueue];
  id<MTLBuffer> bK=[dev newBufferWithLength:32 options:MTLResourceStorageModeShared];
  id<MTLBuffer> fcA=[dev newBufferWithLength:(u64)nb*4 options:MTLResourceStorageModeShared];
  id<MTLBuffer> fcB=[dev newBufferWithLength:(u64)nb*4 options:MTLResourceStorageModeShared];
  id<MTLBuffer> ccn=[dev newBufferWithLength:(u64)coarse_n*4 options:MTLResourceStorageModeShared];
  id<MTLBuffer> fiA=[dev newBufferWithLength:(u64)nb*fine_cap*8 options:MTLResourceStorageModeShared]; // uint2 (idx,z), Shared for gather
  id<MTLBuffer> fiB=[dev newBufferWithLength:(u64)nb*fine_cap*8 options:MTLResourceStorageModeShared];
  id<MTLBuffer> cEP=[dev newBufferWithLength:4096 options:MTLResourceStorageModePrivate]; // dead (idx-only coarse) -> stub
  id<MTLBuffer> cIDX=[dev newBufferWithLength:(u64)coarse_n*coarse_cap*4 options:MTLResourceStorageModePrivate];
  id<MTLBuffer> bParT=[dev newBufferWithLength:sizeof(P) options:MTLResourceStorageModeShared]; // reused trim param (no per-round alloc)
  id<MTLBuffer> bParL=[dev newBufferWithLength:sizeof(P) options:MTLResourceStorageModeShared]; // reused L2 param
  id<MTLBuffer> bGrid=[dev newBufferWithLength:12 options:MTLResourceStorageModePrivate]; // indirect L2 grid (gridk writes)
  u32 TPBv=TPB; id<MTLBuffer> bCN=[dev newBufferWithBytes:&coarse_n length:4 options:MTLResourceStorageModeShared];
  id<MTLBuffer> bTPB=[dev newBufferWithBytes:&TPBv length:4 options:MTLResourceStorageModeShared];
  double memGB=((double)nb*fine_cap*8*2+(double)coarse_n*coarse_cap*4)/1e9; // fiA+fiB (uint2=8B ×2) + cIDX (u32)
  printf("cuckatoo%u FAST miner: nb=%u coarse=%u fine_n=%u rounds=%u maxkeys=%u mem~%.0fGB\n",eb,nb,coarse_n,fine_n,rounds,maxkeys,memGB);
  { // swap-ceiling guard: past recommendedMaxWorkingSetSize a measured 324x collapse lives. Warn loudly, never abort.
    unsigned long long mAl=(unsigned long long)dev.currentAllocatedSize, mRec=(unsigned long long)dev.recommendedMaxWorkingSetSize;
    printf("MEM: device allocated=%.2fGB recommendedMaxWorkingSet=%.2fGB headroom=%.2fGB\n",mAl/1e9,mRec/1e9,((double)mRec-(double)mAl)/1e9);
    if(mAl>mRec) printf("WARNING: SWAP-CEILING allocated %.2fGB > recommendedMaxWorkingSetSize %.2fGB -> eviction/compression risk (324x slowdown measured past ceiling); continuing\n",mAl/1e9,mRec/1e9); }

  // ---- d2 mode ladder (M1_D2=emit|shadow|abort; unset/"0" = off -> no alloc, no output, per-graph
  // path identical). Env is read once here. emit: at round r==M1_D2_CUT, dump survivors' full
  // endpoint ids (GPU). shadow: also run the verdict (host radix sort -> arc count/emit -> bounded
  // DFS), log it and continue. abort: run the verdict; zero candidates proves the graph cycle-free
  // (recall 1 in every gate run), so skip the remaining rounds, gather, peel and recover.
  int D2M=0; const char* d2name="off";
  { const char* e=getenv("M1_D2"); if(e&&*e&&strcmp(e,"0")!=0){ if(!strcmp(e,"emit")){D2M=1;d2name="emit";} else if(!strcmp(e,"shadow")){D2M=2;d2name="shadow";} else if(!strcmp(e,"abort")){D2M=3;d2name="abort";} else printf("M1_D2: unknown mode '%s' -> off\n",e); } }
  u32 D2CUT=getenv("M1_D2_CUT")?(u32)atoi(getenv("M1_D2_CUT")):64u;
  u32 D2CAP=getenv("M1_D2_EMIT_CAP")?(u32)atoi(getenv("M1_D2_EMIT_CAP")):(16u<<20);
  u32 D2HT=1; while(D2HT<2*D2CAP) D2HT<<=1; // hash slots: pow2 >= 2x cap -> load <=50% // records: cut-64 survivors ~3.9M, cut-48 ~6-7M -> 16M = >2x headroom; SoA 12B/rec emit + sort/arc scratch
  id<MTLComputePipelineState> psD2E=nil,psD2H=nil,psD2C=nil,psD2A=nil,psD2D=nil;
  id<MTLBuffer> d2N=nil,d2Idx=nil,d2KU=nil,d2KV=nil,d2HU=nil,d2HV=nil,d2Cnt=nil,d2Off=nil,d2Adj=nil,d2P=nil,d2Found=nil,d2Cand=nil,d2Ccap=nil,d2Dcap=nil;
  if(D2M){ // one-time allocation (never in the per-graph loop): 10 device cap*4B bufs + cap*4B host tmp = 44B/rec ~= 0.74GB at 16M
    psD2E=[dev newComputePipelineStateWithFunction:[lib newFunctionWithName:@"d2emit"] error:&err];
    psD2H=[dev newComputePipelineStateWithFunction:[lib newFunctionWithName:@"k_d2_hbuild"] error:&err];
    psD2C=[dev newComputePipelineStateWithFunction:[lib newFunctionWithName:@"k_d2_count"] error:&err];
    psD2A=[dev newComputePipelineStateWithFunction:[lib newFunctionWithName:@"k_d2_emit"] error:&err];
    psD2D=[dev newComputePipelineStateWithFunction:[lib newFunctionWithName:@"k_d2_dfs"] error:&err];
    d2N=[dev newBufferWithLength:4 options:MTLResourceStorageModeShared];
    d2Idx=[dev newBufferWithLength:(u64)D2CAP*4 options:MTLResourceStorageModeShared];
    d2KU=[dev newBufferWithLength:(u64)D2CAP*4 options:MTLResourceStorageModeShared];
    d2KV=[dev newBufferWithLength:(u64)D2CAP*4 options:MTLResourceStorageModeShared];
    d2HU=[dev newBufferWithLength:(u64)D2HT*4 options:MTLResourceStorageModeShared]; // hash multimaps keyU/keyV->edge, 2x cap slots
    d2HV=[dev newBufferWithLength:(u64)D2HT*4 options:MTLResourceStorageModeShared];
    d2Cnt=[dev newBufferWithLength:(u64)D2CAP*4 options:MTLResourceStorageModeShared];
    d2Off=[dev newBufferWithLength:((u64)D2CAP+1)*4 options:MTLResourceStorageModeShared]; // n+1 entries: k_d2_dfs reads adj_off[src+1]
    d2Adj=[dev newBufferWithLength:(u64)D2CAP*4 options:MTLResourceStorageModeShared];     // arc cap == emit cap (arcs measure about 1.00n at every depth)
    d2P=[dev newBufferWithLength:sizeof(D2PAR) options:MTLResourceStorageModeShared];
    d2Found=[dev newBufferWithLength:4 options:MTLResourceStorageModeShared];
    d2Cand=[dev newBufferWithLength:4 options:MTLResourceStorageModeShared];
    u32 one=1; d2Ccap=[dev newBufferWithBytes:&one length:4 options:MTLResourceStorageModeShared]; // cand_cap=1: DFS stops at first candidate; verdict only needs zero/nonzero
    d2Dcap=[dev newBufferWithBytes:&D2CAP length:4 options:MTLResourceStorageModeShared];
    if(!psD2E||!psD2H||!psD2C||!psD2A||!psD2D||!d2N||!d2Idx||!d2KU||!d2KV||!d2HU||!d2HV||!d2Cnt||!d2Off||!d2Adj||!d2P||!d2Found||!d2Cand||!d2Ccap||!d2Dcap){ printf("D2: pipeline/alloc FAIL -> mode forced off\n"); D2M=0; }
    else printf("D2: mode=%s cut=%u emit_cap=%u buffers=%.2fGB%s\n",d2name,D2CUT,D2CAP,((double)D2CAP*24+(double)D2HT*8)/1e9,(D2CUT>=rounds)?" (WARNING: cut>=rounds, verdict never fires)":"");
  }

  double(^doL2)(P,id<MTLBuffer>,id<MTLBuffer>) = ^double(P pr, id<MTLBuffer> dFC, id<MTLBuffer> dFI){
    *(P*)bParL.contents=pr; id<MTLBuffer> bP=bParL;
    memset(dFC.contents,0,(u64)nb*4);
    u32 maxc=0; u32* cc=(u32*)ccn.contents; for(u32 i=0;i<coarse_n;i++) if(cc[i]>maxc)maxc=cc[i]; // adaptive grid
    u32 mc=(maxc+TPB-1)/TPB; if(mc<1)mc=1;
    id<MTLCommandBuffer>c=[q commandBuffer];id<MTLComputeCommandEncoder>e=[c computeCommandEncoder];
    [e setComputePipelineState:psL2];[e setBuffer:bP offset:0 atIndex:0];[e setBuffer:ccn offset:0 atIndex:1];[e setBuffer:cEP offset:0 atIndex:2];[e setBuffer:cIDX offset:0 atIndex:3];[e setBuffer:dFC offset:0 atIndex:4];[e setBuffer:dFI offset:0 atIndex:5];[e setBuffer:bK offset:0 atIndex:6];
    [e dispatchThreadgroups:MTLSizeMake(mc,coarse_n,1) threadsPerThreadgroup:MTLSizeMake(TPB,1,1)];[e endEncoding];[c commit];[c waitUntilCompleted]; cb_note(c,"seedL2");
    return 0; };

  // live mode: persistent stratum connection + login
  const char*HOST=getenv("M1_STRATUM_HOST"); if(!HOST||!*HOST)HOST="127.0.0.1";
  uint16_t PORT=(uint16_t)(getenv("M1_STRATUM_PORT")?atoi(getenv("M1_STRATUM_PORT")):3416);
  const char*LOGIN=getenv("M1_STRATUM_LOGIN"); if(!LOGIN)LOGIN="m1miner";
  const char*PASS=getenv("M1_STRATUM_PASSWORD"); if(!PASS)PASS="x";
  // fixed-key sweep mode (M1_FIXED_PREPOW=<hex>): pin one pre_pow, mine nonce 0..maxkeys-1 deterministically,
  // no stratum jobs/submit -> identical graphs at every trim-round count, so two_core/verify can be compared
  // per-key across runs (the false-deletion tripwire). Input-path only; trim/peel/recover math untouched.
  const char* FPPHEX=getenv("M1_FIXED_PREPOW"); int FIXED=(FPPHEX&&*FPPHEX);
  if(!FIXED && strat_login(HOST,PORT,LOGIN,PASS,"mine34-live")!=0){ printf("STRATUM_LOGIN_FAIL %s:%u\n",HOST,PORT); return 5; }
  printf("LIVE: logged in to %s:%u as %s (C%u, %u rounds)\n",HOST,PORT,LOGIN,eb,rounds);
  tel_init();
  M1MeanSidecarJobTemplate job; memset(&job,0,sizeof job);
  uint8_t PP[8192]; size_t PPLEN=0; u64 CUR_H=0,CUR_J=0,CUR_DIFF=0;
  if(FIXED){ PPLEN=hexdec(FPPHEX,PP,sizeof PP); CUR_H=1; CUR_J=0;
    printf("FIXED-KEY MODE: pinned pre_pow %zu bytes, nonce 0..%u, %u trim rounds (no stratum)\n",PPLEN,maxkeys?maxkeys-1:0,rounds); }
  char CUR_PPID[2*M1MEAN_SIDECAR_PRE_POW_ID_BYTES+1]={0}; uint64_t CUR_GEN=0;
  double t0=now_s(); u32 sol[PROOFSIZE]; u32 *nonces=malloc((size_t)(nedges/4+16)*4*4);
  // steerer switch: M1_STEER=<skip_threshold> spawns a parallel CPU scorer thread (producer) that
  // pre-filters nonces; the GPU loop (consumer) drains the keep-queue. Fully overlapped. Default off.
  const char*STEER_STATE=getenv("M1_STEER_STATE");
  int STEER_ON = getenv("M1_STEER")!=NULL; pthread_t sth;
  if(STEER_ON){ S_THRESH=atof(getenv("M1_STEER")); pthread_create(&sth,NULL,scorer_thread,NULL);
    printf("STEERER: ON (parallel CPU scorer, skip if score>%.0f%s%s)\n",S_THRESH,STEER_STATE?" state=":"",STEER_STATE?STEER_STATE:""); }
  else printf("STEERER: OFF (set M1_STEER=<thresh> to enable parallel pre-filter)\n");
  u64 nonce=getenv("M1_NONCE0")?strtoull(getenv("M1_NONCE0"),NULL,10):0; u32 graphs=0, sols=0; // M1_NONCE0: fixed-mode start nonce (corpus extension without re-mining)
  // ---- arena feasibility telemetry (read-only, gated by M1_ARENA_TELEM; default off is byte-for-byte
  // the baseline behavior). Per round, read the live per-bucket survivor counts straight out of the
  // Shared fc buffer and pair them against the previous graph's seed fill, which is the true
  // cross-graph deterministic-next-nonce co-residency. worst_sum=max_b(seed0[b]+live_r[b]) is the
  // memory-fit gate; drop_g* counts edges dropped under the next graph's reduced cap (the 42-cycle
  // yield risk); gpu_us vs wall_us per round is harvestable tail idle. The bucket scan runs after
  // wall capture so it never pollutes the per-round wall/gpu numbers (it does inflate total graph
  // wall, which is not trusted). ----
  const int ATEL = getenv("M1_ARENA_TELEM")!=NULL;
  u32 RB=getenv("M1_RBATCH")?(u32)atoi(getenv("M1_RBATCH")):1u; if(RB<1u)RB=1u; // rounds per command buffer (blit clears, 2 static parity params); 1 = legacy per-round sync
  u32 L1PRE=getenv("M1_L1PRE")?1u:0u;
  u32 L1PRECUT=getenv("M1_L1PRE_CUT")?(u32)atoi(getenv("M1_L1PRE_CUT")):L1PRE; // cut-site prefire: fire the next nonce's L1 on a second queue at the cut, under the d2 verdict (hash-join+DFS). The aborted path (about 98% of graphs) never reaches peel, so the post-peel prefire never fires there and the seed L1 would be fully exposed without this. Own key buffer (bKpre): the fallback tail still reads bK every round. On a no-abort continuation: wait and discard (cross-queue race against the round-65 clobber of ccn/cEP/cIDX).
  u32 D2WIT=getenv("M1_D2_WITNESS")?(u32)atoi(getenv("M1_D2_WITNESS")):1u; // witness extraction on candidate graphs (abort mode); 0 = always run the full tail // post-peel prefire: fire the next nonce's seed L1 on the same queue after peel's last GPU batch, hidden under the compact/recover/verify CPU work. Zero extra memory (bK/ccn/cEP/cIDX are dead after the rounds). Consumed at the next graph top; a job-generation/nonce mismatch discards it and the normal L1 runs.
  id<MTLCommandBuffer> pf_cb=nil; u64 pf_nonce=0,pf_gen=0;
  id<MTLCommandQueue> qPre=(L1PRECUT)?[dev newCommandQueue]:nil; // cut-site prefire queue: concurrent with the verdict command buffers on q (same-queue would serialize ahead of them)
  id<MTLBuffer> bKpre=(L1PRECUT)?[dev newBufferWithLength:32 options:MTLResourceStorageModeShared]:nil;
  u32 *prev_seed0=NULL,*cur_seed0=NULL; int have_prev=0;
  static const u32 AGUARD[4]={0,2048,4096,8192};
  if(ATEL){ prev_seed0=(u32*)calloc(nb,4); cur_seed0=(u32*)malloc((size_t)nb*4);
    tel_write("{\"receipt_kind\":\"mine34_arena_cfg.v1\",\"nb\":%u,\"fine_cap\":%u,\"rounds\":%u}\n",nb,fine_cap,rounds); }
  // ---- L1 overlap probe (env M1_PROBE_L1OVL): at round PRCUT, fire the next nonce's real full L1 on
  // a second command queue into its own cIDX2 (result discarded), concurrent with this graph's
  // tail+peel+recover. Measures whether a bandwidth-bound seed dispatch co-occupies the light tail
  // (about 20% reachable) or just contends (dead, only about 13% idle-fill survives). The correctness
  // path is untouched: separate queue and buffers. ----
  int PROBE = getenv("M1_PROBE_L1OVL")!=NULL;
  if(RB>1u){ if(ATEL||PROBE){ printf("RBATCH: forced 1 (ATEL/PROBE need per-round sync)\n"); RB=1u; } else printf("RBATCH: %u rounds/cmdbuf (c02 batched rounds, GPU blit clears)\n",RB); }
  u32 PRCUT = getenv("M1_PROBE_RCUT")?(u32)atoi(getenv("M1_PROBE_RCUT")):40;
  id<MTLCommandQueue> q2=nil; id<MTLBuffer> cIDX2=nil,ccn2=nil,cEP2=nil,bK2=nil,bPs2=nil;
  if(PROBE){ double g2=(double)((u64)coarse_n*coarse_cap*4)/1073741824.0; q2=[dev newCommandQueue];
    cIDX2=[dev newBufferWithLength:(u64)coarse_n*coarse_cap*4 options:MTLResourceStorageModePrivate];
    ccn2=[dev newBufferWithLength:(u64)coarse_n*4 options:MTLResourceStorageModeShared];
    cEP2=[dev newBufferWithLength:4096 options:MTLResourceStorageModePrivate];
    bK2=[dev newBufferWithLength:32 options:MTLResourceStorageModeShared];
    P ps2={nodemask,zbits,coarse_shift,coarse_n,coarse_cap,fine_shift,fine_mask,fine_n,fine_cap,0};
    bPs2=[dev newBufferWithBytes:&ps2 length:sizeof(P) options:MTLResourceStorageModeShared];
    if(!q2||!cIDX2||!ccn2||!bK2||!bPs2){ printf("PROBE: alloc failed (cIDX2 ~%.1fGB) -- DISABLED\n",g2); PROBE=0; }
    else { printf("PROBE L1-overlap: ON rcut=%u cIDX2=%.1fGB\n",PRCUT,g2);
      tel_write("{\"receipt_kind\":\"mine34_probe_cfg.v1\",\"rcut\":%u,\"cidx2_gb\":%.2f}\n",PRCUT,g2); } }
  while(maxkeys==0 || graphs<maxkeys){ @autoreleasepool{ // per-graph pool: drain this graph's autoreleased command buffers (and the GPU buffers they retain) every iteration so IOAccelerator/unified memory stays flat -- fixes the forever-loop OOM (single main() pool never drained -> 941 cmdbufs/88GB in 27min)
    if(!FIXED){ // poll every graph for the freshest job (drain-to-latest above). ~1ms vs the 1.9s mine = lossless; mining a job that was up to 8 graphs (~15s) old was the staleness.
      if(strat_getjob(&job)==0){ size_t nl=hexdec(job.pre_pow_hex,PP,sizeof PP);
        if(nl && (job.job_id!=CUR_J || job.height!=CUR_H)){ PPLEN=nl; CUR_H=job.height; CUR_J=job.job_id; CUR_DIFF=job.difficulty; nonce=0; CUR_GEN++;
          hexenc(job.pre_pow_id,M1MEAN_SIDECAR_PRE_POW_ID_BYTES,CUR_PPID,sizeof CUR_PPID);
          if(STEER_ON){ double job_thresh=S_THRESH; SteerWeights job_w=S_W; int state_ok=steer_state_load(STEER_STATE,CUR_DIFF,&job_thresh,&job_w);
            pthread_mutex_lock(&SMX); memcpy(S_PP,PP,sizeof S_PP); S_PPLEN=PPLEN; S_H=CUR_H; S_J=CUR_J; S_D=CUR_DIFF; memcpy(S_PPID,CUR_PPID,sizeof S_PPID); S_THRESH=job_thresh; S_W=job_w; S_GEN=CUR_GEN; S_QH=S_QT=0; pthread_mutex_unlock(&SMX);
            if(state_ok) printf("STEER_STATE: applied diff=%llu threshold=%.3f weights=(%.0f,%.0f,%.0f,%.0f,%.0f)\n",(unsigned long long)CUR_DIFF,job_thresh,job_w.dup,job_w.branch,job_w.corridor,job_w.closure,job_w.deg2);
            else if(STEER_STATE) printf("STEER_STATE: no bucket for diff=%llu, using threshold=%.3f\n",(unsigned long long)CUR_DIFF,job_thresh); } // publish job -> scorer, flush stale queue
          tel_job(CUR_H,CUR_J,CUR_DIFF,CUR_PPID,job.pre_pow_hex,CUR_GEN,S_THRESH);
          printf("[%.1fs] NEW JOB height=%llu job_id=%llu diff=%llu | mined %u graphs, %u sols, scanned %lu skipped %lu\n",now_s()-t0,(unsigned long long)CUR_H,(unsigned long long)CUR_J,(unsigned long long)CUR_DIFF,graphs,sols,S_SCANNED,S_SKIPPED); } }
      if(PPLEN==0){ printf("waiting for job...\n"); sleep(2); continue; } }
    double qscore=0; int have_qscore=0;
    if(STEER_ON){ uint64_t nn; int got=0;  // drain a kept nonce from the parallel scorer
      pthread_mutex_lock(&SMX); if(S_QH!=S_QT && S_Q[S_QH].gen==S_GEN){ nn=S_Q[S_QH].nonce; qscore=S_Q[S_QH].score; have_qscore=1; S_QH=(S_QH+1)%QCAP; got=1; } pthread_mutex_unlock(&SMX);
      if(!got){ usleep(20000); continue; } nonce=nn; }
    u32 key=graphs;
    M1RsiKeys rk; m1rsi_grin_keys_from_pre_pow_nonce(PP,PPLEN,nonce,&rk);
    u64 kk[4]={rk.k0,rk.k1,rk.k2,rk.k3};
    int pf_hit=0;
    if(pf_cb){ [pf_cb waitUntilCompleted]; cb_note(pf_cb,"seedL1pre"); if(pf_nonce==nonce && pf_gen==CUR_GEN) pf_hit=1; pf_cb=nil; } // wait before bK overwrite: an in-flight prefired L1 reads bK
    SK0=kk[0];SK1=kk[1];SK2=kk[2];SK3=kk[3]; memcpy(bK.contents,kk,32);
    double tkey=now_s();
    // seed: L1v (virtual edges -> coarse by u) then L2 -> fiA
    P ps={nodemask,zbits,coarse_shift,coarse_n,coarse_cap,fine_shift,fine_mask,fine_n,fine_cap,0};
    id<MTLBuffer> bPs=[dev newBufferWithBytes:&ps length:sizeof(P) options:MTLResourceStorageModeShared];
    u64 CH=1ull<<28;
    double tL1_0=ATEL?now_s():0;
    if(!pf_hit){ memset(ccn.contents,0,(u64)coarse_n*4);
      id<MTLCommandBuffer>c=[q commandBuffer];id<MTLComputeCommandEncoder>e=[c computeCommandEncoder];
      [e setComputePipelineState:psL1];[e setBuffer:bK offset:0 atIndex:0];[e setBuffer:bPs offset:0 atIndex:1];[e setBuffer:ccn offset:0 atIndex:2];[e setBuffer:cEP offset:0 atIndex:3];[e setBuffer:cIDX offset:0 atIndex:4];
      for(u64 base=0;base<nedges;base+=CH){u32 b32=(u32)base;u64 n=(nedges-base<CH)?(nedges-base):CH; id<MTLBuffer> bB=[dev newBufferWithBytes:&b32 length:4 options:MTLResourceStorageModeShared];[e setBuffer:bB offset:0 atIndex:5];[e dispatchThreadgroups:MTLSizeMake((n+TPB-1)/TPB,1,1) threadsPerThreadgroup:MTLSizeMake(TPB,1,1)];}
      [e endEncoding];[c commit];[c waitUntilCompleted]; cb_note(c,"seedL1"); } // pf_hit: a prefired L1 already populated ccn/cEP/cIDX with this key
    double tSeedL1=ATEL?(now_s()-tL1_0):0, tL2_0=ATEL?now_s():0;
    doL2(ps, fcA, fiA);
    double tSeedL2=ATEL?(now_s()-tL2_0):0;
    double tSeed=now_s()-tkey; double tRoundGPU=0;
    id<MTLCommandBuffer> l1cb=nil; double l1c0=0, tpc0=0, t_post=0, l1_wall=0, l1_gpu=0; int probed=0;
    id<MTLBuffer> curFC=fcA,curFI=fiA,dstFC=fcB,dstFI=fiB;
    double d2_emit_ms=0,d2_sort_ms=0,d2_arc_ms=0,d2_dfs_ms=0,d2_saved_ms=0; u64 d2_arc_n=0; u32 d2_emit_n=0,d2_cand=0; int d2_would=0,d2_abort=0,d2_ovf=0,d2_wit=0; char d2sfx[160]; d2sfx[0]=0; // inert stack inits when D2M==0
    if(ATEL) memcpy(cur_seed0,curFC.contents,(size_t)nb*4); // graph N seed distribution (post-doL2, round 0)
    { P p0={nodemask,zbits,coarse_shift,coarse_n,coarse_cap,fine_shift,fine_mask,fine_n,fine_cap,0u}; *(P*)bParT.contents=p0; p0.side=1u; *(P*)bParL.contents=p0; } // parity-static params: side0=bParT side1=bParL, written once (RB>1 must not mutate mid-cmdbuf; same values the legacy path wrote per round)
    id<MTLCommandBuffer> rb_cb=nil; // open batched cmdbuf when RB>1
    for(u32 r=0;r<rounds;r++){ u32 cur=r&1;
      id<MTLBuffer> bT=cur?bParL:bParT, bL=cur?bParT:bParL; // trim side=cur, L2 side=cur^1
      id<MTLCommandBuffer>c;
      if(RB<=1u){ memset(ccn.contents,0,(u64)coarse_n*4); memset(dstFC.contents,0,(u64)nb*4);
        c=[q commandBuffer]; } // legacy: one command buffer per round, host clears
      else { if(!rb_cb) rb_cb=[q commandBuffer]; c=rb_cb; // clears ride as a blit inside the chunk (encoder order = round order)
        id<MTLBlitCommandEncoder> bl=[c blitCommandEncoder];
        [bl fillBuffer:ccn range:NSMakeRange(0,(u64)coarse_n*4) value:0];[bl fillBuffer:dstFC range:NSMakeRange(0,(u64)nb*4) value:0];[bl endEncoding]; }
      id<MTLComputeCommandEncoder>e=[c computeCommandEncoder];
      [e setComputePipelineState:psTS];[e setBuffer:bK offset:0 atIndex:0];[e setBuffer:bT offset:0 atIndex:1];[e setBuffer:curFC offset:0 atIndex:2];[e setBuffer:curFI offset:0 atIndex:3];[e setBuffer:ccn offset:0 atIndex:4];[e setBuffer:cEP offset:0 atIndex:5];[e setBuffer:cIDX offset:0 atIndex:6];
      [e dispatchThreadgroups:MTLSizeMake(nb,1,1) threadsPerThreadgroup:MTLSizeMake(TPB,1,1)];
      [e memoryBarrierWithScope:MTLBarrierScopeBuffers];
      [e setComputePipelineState:psGR];[e setBuffer:ccn offset:0 atIndex:0];[e setBuffer:bCN offset:0 atIndex:1];[e setBuffer:bTPB offset:0 atIndex:2];[e setBuffer:bGrid offset:0 atIndex:3];
      [e dispatchThreadgroups:MTLSizeMake(1,1,1) threadsPerThreadgroup:MTLSizeMake(1,1,1)];
      [e memoryBarrierWithScope:MTLBarrierScopeBuffers];
      [e setComputePipelineState:psL2];[e setBuffer:bL offset:0 atIndex:0];[e setBuffer:ccn offset:0 atIndex:1];[e setBuffer:cEP offset:0 atIndex:2];[e setBuffer:cIDX offset:0 atIndex:3];[e setBuffer:dstFC offset:0 atIndex:4];[e setBuffer:dstFI offset:0 atIndex:5];[e setBuffer:bK offset:0 atIndex:6];
      [e dispatchThreadgroupsWithIndirectBuffer:bGrid indirectBufferOffset:0 threadsPerThreadgroup:MTLSizeMake(TPB,1,1)];
      [e endEncoding];
      double rw0=ATEL?now_s():0;
      int flush = (RB<=1u) || (((r+1)%RB)==0u) || (r+1u==rounds) || (D2M && r==D2CUT); // chunk ends at K, at R, and at the D2 cut (verdict needs completed survivors)
      int d2_fused=0;
      if(flush && RB>1u && D2M && r==D2CUT){ // fold d2emit into the cut chunk so one wait covers rounds+emit. Note: post-round survivors live in dstFC/dstFI here (the swap happens below); emit reads those.
        *(u32*)d2N.contents=0;
        id<MTLComputeCommandEncoder>e2=[c computeCommandEncoder];
        [e2 setComputePipelineState:psD2E];[e2 setBuffer:bK offset:0 atIndex:0];[e2 setBuffer:bParT offset:0 atIndex:1];[e2 setBuffer:dstFC offset:0 atIndex:2];[e2 setBuffer:dstFI offset:0 atIndex:3];[e2 setBuffer:d2N offset:0 atIndex:4];[e2 setBuffer:d2Idx offset:0 atIndex:5];[e2 setBuffer:d2KU offset:0 atIndex:6];[e2 setBuffer:d2KV offset:0 atIndex:7];[e2 setBuffer:d2Dcap offset:0 atIndex:8];
        [e2 dispatchThreadgroups:MTLSizeMake(nb,1,1) threadsPerThreadgroup:MTLSizeMake(TPB,1,1)];[e2 endEncoding]; d2_fused=1; }
      double rgpu=0;
      if(flush){ [c commit];[c waitUntilCompleted]; cb_note(c,"round");
        rgpu=(c.GPUEndTime-c.GPUStartTime); tRoundGPU += rgpu; rb_cb=nil; }
      double rwall=ATEL?(now_s()-rw0):0;
      id<MTLBuffer> t;t=curFC;curFC=dstFC;dstFC=t;t=curFI;curFI=dstFI;dstFI=t;
      if(ATEL && have_prev){ // curFC (post-swap) = round-r survivor counts; pair against the previous graph's seed0
        const u32*lv=(const u32*)curFC.contents; u64 tot=0; u32 mx=0,ws=0; u64 drop[4]={0,0,0,0};
        for(u32 b=0;b<nb;b++){ u32 L=lv[b]; if(L>fine_cap)L=fine_cap; tot+=L; if(L>mx)mx=L;
          u32 s=prev_seed0[b]+L; if(s>ws)ws=s;
          for(int g=0;g<4;g++){ u32 cap=(fine_cap>AGUARD[g])?(fine_cap-AGUARD[g]):0; if(s>cap) drop[g]+=(s-cap); } }
        tel_write("{\"receipt_kind\":\"mine34_arena_round.v1\",\"key\":%u,\"r\":%u,\"live_total\":%llu,\"live_max\":%u,\"worst_sum\":%u,\"drop_g0\":%llu,\"drop_g2k\":%llu,\"drop_g4k\":%llu,\"drop_g8k\":%llu,\"gpu_us\":%.1f,\"wall_us\":%.1f}\n",
          key,r,(unsigned long long)tot,mx,ws,(unsigned long long)drop[0],(unsigned long long)drop[1],(unsigned long long)drop[2],(unsigned long long)drop[3],rgpu*1e6,rwall*1e6); }
      if(D2M && r==D2CUT){ // d2 at the cut (post-swap: curFC/curFI = round-r survivors). Emit always; verdict for shadow/abort.
        if(!d2_fused){ *(u32*)d2N.contents=0;
          id<MTLCommandBuffer>cd=[q commandBuffer];id<MTLComputeCommandEncoder>e=[cd computeCommandEncoder];
          [e setComputePipelineState:psD2E];[e setBuffer:bK offset:0 atIndex:0];[e setBuffer:bParT offset:0 atIndex:1];[e setBuffer:curFC offset:0 atIndex:2];[e setBuffer:curFI offset:0 atIndex:3];[e setBuffer:d2N offset:0 atIndex:4];[e setBuffer:d2Idx offset:0 atIndex:5];[e setBuffer:d2KU offset:0 atIndex:6];[e setBuffer:d2KV offset:0 atIndex:7];[e setBuffer:d2Dcap offset:0 atIndex:8];
          [e dispatchThreadgroups:MTLSizeMake(nb,1,1) threadsPerThreadgroup:MTLSizeMake(TPB,1,1)];[e endEncoding];[cd commit];[cd waitUntilCompleted]; cb_note(cd,"d2emit");
          d2_emit_ms=(cd.GPUEndTime-cd.GPUStartTime)*1e3; } // fused: emit rode in the cut chunk (emit_ms=0 in receipt)
        d2_emit_n=*(u32*)d2N.contents; u32 dn_=d2_emit_n>D2CAP?D2CAP:d2_emit_n; if(d2_emit_n>D2CAP)d2_ovf=1; // records dropped -> verdict unknowable, never abort
        int pf_cut=0;
        if(L1PRECUT && D2M==3 && !d2_ovf && !STEER_ON && !pf_cb && (maxkeys==0 || graphs+1<maxkeys)){ // cut-site prefire: the next nonce's L1 rides qPre under the verdict. Placement was settled by three measured variants: under the join is 11 ms better net, baseline is next, and under the DFS only is 52 ms worse (the 22 ms DFS window stretches to about 140 ms covering the co-running L1). About 98% of graphs abort, so the prefire is consumed at the next graph top (pf_hit); on no-abort it is waited on and discarded below. ccn is dead after the cut chunk; cEP/cIDX stale content is never read past the per-bucket counts, so the fallback tail can safely clobber it.
          M1RsiKeys nk; m1rsi_grin_keys_from_pre_pow_nonce(PP,PPLEN,nonce+1,&nk);
          u64 nkk[4]={nk.k0,nk.k1,nk.k2,nk.k3}; memcpy(bKpre.contents,nkk,32); memset(ccn.contents,0,(u64)coarse_n*4);
          id<MTLCommandBuffer>pc=[qPre commandBuffer]; id<MTLComputeCommandEncoder>pe=[pc computeCommandEncoder];
          [pe setComputePipelineState:psL1];[pe setBuffer:bKpre offset:0 atIndex:0];[pe setBuffer:bPs offset:0 atIndex:1];[pe setBuffer:ccn offset:0 atIndex:2];[pe setBuffer:cEP offset:0 atIndex:3];[pe setBuffer:cIDX offset:0 atIndex:4];
          u64 CH2=1ull<<28; for(u64 base=0;base<nedges;base+=CH2){u32 b32=(u32)base;u64 n=(nedges-base<CH2)?(nedges-base):CH2; id<MTLBuffer> bB=[dev newBufferWithBytes:&b32 length:4 options:MTLResourceStorageModeShared];[pe setBuffer:bB offset:0 atIndex:5];[pe dispatchThreadgroups:MTLSizeMake((n+TPB-1)/TPB,1,1) threadsPerThreadgroup:MTLSizeMake(TPB,1,1)];}
          [pe endEncoding];[pc commit]; pf_cb=pc; pf_nonce=nonce+1; pf_gen=CUR_GEN; pf_cut=1; }
        if(D2M>=2 && !d2_ovf){
          // Join key = id^1 (D2PAR.xb=1): same pair, opposite lsb. Joining on full-id equality (xb=0)
          // instead has zero recall on real graphs. Table sizing is settled: a per-graph 2x-emit table
          // (45% load) measured slower (arc 69.3 vs 58.2 ms uncontended); at 11% load the probe chains
          // of about 1.1 beat the TLB savings, so the cap-sized table stands.
          *(D2PAR*)d2P.contents=(D2PAR){dn_,1u,D2HT-1u}; u32 ag=(dn_+255u)/256u; if(ag<1u)ag=1u;
          if(dn_){ // one command buffer: blit-fill both hash tables to empty -> hbuild (CAS inserts) -> count (probe). No host sort.
            id<MTLCommandBuffer>cd=[q commandBuffer];
            id<MTLBlitCommandEncoder> bl=[cd blitCommandEncoder];
            [bl fillBuffer:d2HU range:NSMakeRange(0,(u64)D2HT*4) value:0xFF];[bl fillBuffer:d2HV range:NSMakeRange(0,(u64)D2HT*4) value:0xFF];[bl endEncoding];
            id<MTLComputeCommandEncoder>e=[cd computeCommandEncoder];
            [e setComputePipelineState:psD2H];[e setBuffer:d2P offset:0 atIndex:0];[e setBuffer:d2KU offset:0 atIndex:1];[e setBuffer:d2KV offset:0 atIndex:2];[e setBuffer:d2HU offset:0 atIndex:3];[e setBuffer:d2HV offset:0 atIndex:4];
            [e dispatchThreadgroups:MTLSizeMake(ag,1,1) threadsPerThreadgroup:MTLSizeMake(256,1,1)];
            [e memoryBarrierWithScope:MTLBarrierScopeBuffers];
            [e setComputePipelineState:psD2C];[e setBuffer:d2P offset:0 atIndex:0];[e setBuffer:d2KU offset:0 atIndex:1];[e setBuffer:d2KV offset:0 atIndex:2];[e setBuffer:d2HU offset:0 atIndex:3];[e setBuffer:d2HV offset:0 atIndex:4];[e setBuffer:d2Cnt offset:0 atIndex:5];
            [e dispatchThreadgroups:MTLSizeMake(ag,1,1) threadsPerThreadgroup:MTLSizeMake(256,1,1)];[e endEncoding];[cd commit];[cd waitUntilCompleted]; cb_note(cd,"d2hash"); d2_arc_ms+=(cd.GPUEndTime-cd.GPUStartTime)*1e3; }
          { double ts0=now_s(); u32* ac=(u32*)d2Cnt.contents; u32* ao=(u32*)d2Off.contents; u64 tot=0; for(u32 i=0;i<dn_;i++){ ao[i]=(u32)tot; tot+=ac[i]; } ao[dn_]=(u32)tot; d2_arc_n=tot; d2_sort_ms=(now_s()-ts0)*1e3; } // exclusive scan + total (DFS reads adj_off[n])
          if(d2_arc_n>(u64)D2CAP) d2_ovf=2; // arc explosion past cap -> verdict unknowable, never abort
          else{
            if(d2_arc_n){ id<MTLCommandBuffer>cd=[q commandBuffer];id<MTLComputeCommandEncoder>e=[cd computeCommandEncoder];
              [e setComputePipelineState:psD2A];[e setBuffer:d2P offset:0 atIndex:0];[e setBuffer:d2KU offset:0 atIndex:1];[e setBuffer:d2KV offset:0 atIndex:2];[e setBuffer:d2HU offset:0 atIndex:3];[e setBuffer:d2HV offset:0 atIndex:4];[e setBuffer:d2Off offset:0 atIndex:5];[e setBuffer:d2Adj offset:0 atIndex:6];
              [e dispatchThreadgroups:MTLSizeMake(ag,1,1) threadsPerThreadgroup:MTLSizeMake(256,1,1)];[e endEncoding];[cd commit];[cd waitUntilCompleted]; cb_note(cd,"d2arc"); d2_arc_ms+=(cd.GPUEndTime-cd.GPUStartTime)*1e3; }
            *(u32*)d2Found.contents=0; *(u32*)d2Cand.contents=0;
            if(dn_){ id<MTLCommandBuffer>cd=[q commandBuffer];id<MTLComputeCommandEncoder>e=[cd computeCommandEncoder];
              [e setComputePipelineState:psD2D];[e setBuffer:d2P offset:0 atIndex:0];[e setBuffer:d2Off offset:0 atIndex:1];[e setBuffer:d2Adj offset:0 atIndex:2];[e setBuffer:d2Found offset:0 atIndex:3];[e setBuffer:d2Cand offset:0 atIndex:4];[e setBuffer:d2Ccap offset:0 atIndex:5];
              [e dispatchThreadgroups:MTLSizeMake(ag,1,1) threadsPerThreadgroup:MTLSizeMake(256,1,1)];[e endEncoding];[cd commit];[cd waitUntilCompleted]; cb_note(cd,"d2dfs"); d2_dfs_ms=(cd.GPUEndTime-cd.GPUStartTime)*1e3; }
            d2_cand=*(u32*)d2Cand.contents; d2_would=(d2_cand==0); // zero candidates proves the graph cycle-free (cand_cap=1, so the reported value is zero/nonzero, not a full count)
          }
        }
        if(d2_would){ double avg_ms=(now_s()-tkey-tSeed)/(double)(r+1)*1e3; d2_saved_ms=avg_ms*(double)(rounds-1u-r); } // rounds-only estimate (gather/peel/recover tail excluded)
        if(D2M==3 && d2_would) d2_abort=1;
        if(D2M==3 && !d2_would && !d2_ovf && D2WIT){ double tw0=now_s(); u32 dnw=d2_emit_n>D2CAP?D2CAP:d2_emit_n;
          d2_wit=d2_witness((const u32*)d2Idx.contents,(const u32*)d2KU.contents,(const u32*)d2KV.contents,(const u32*)d2Off.contents,(const u32*)d2Adj.contents,dnw,sol);
          printf("  d2_witness: %s (%.3fs)\n",d2_wit?"VERIFIED 42-edge lift -> tail skipped":"no verifiable lift -> full tail",now_s()-tw0);
          if(d2_wit) d2_abort=1; } // verified witness: skip rounds 65+/gather/peel/recover; rec path takes sol[] directly
        if(pf_cut && !d2_abort){ [pf_cb waitUntilCompleted]; cb_note(pf_cb,"seedL1preCutDiscard"); pf_cb=nil; pf_nonce=~0ull; } // no-abort continuation: rounds 65+ clobber ccn/cEP/cIDX on q while prefire writes them on qPre -> must drain qPre first; prefired data is then stale -> discard (the post-peel prefire refires)
        tel_write("{\"receipt_kind\":\"mine34_d2.v1\",\"key\":%u,\"mode\":\"%s\",\"cut\":%u,\"emit_n\":%u,\"emit_ms\":%.3f,\"sort_ms\":%.3f,\"arc_n\":%llu,\"arc_ms\":%.3f,\"dfs_ms\":%.3f,\"candidates\":%u,\"overflow\":%d,\"would_abort\":%d,\"aborted\":%d,\"saved_est_ms\":%.1f,\"pf_cut\":%d,\"timestamp_ms\":%llu}\n",
          key,d2name,D2CUT,d2_emit_n,d2_emit_ms,d2_sort_ms,(unsigned long long)d2_arc_n,d2_arc_ms,d2_dfs_ms,d2_cand,d2_ovf,d2_would,d2_abort,d2_saved_ms,pf_cut,(unsigned long long)wall_ms());
        snprintf(d2sfx,sizeof d2sfx," | d2[%s@%u] n=%u arcs=%llu cand=%u%s%s%s",d2name,D2CUT,d2_emit_n,(unsigned long long)d2_arc_n,d2_cand,d2_ovf?" OVERFLOW":"",d2_would?" would_abort":"",d2_abort?" ABORT":"");
        if(d2_abort) break; // proven cycle-free -> skip remaining rounds; gather/peel/recover skipped below (rec=0 path)
      }
    }
    double tRound=now_s()-tkey-tSeed;
    // probe: fire the next nonce's L1 on q2 now, entering the GPU-idle window (host gather, peel-host
    // sort, recover union-find). Almost no per-round GPU syncs are issued here, so L1 runs into real
    // idle rather than arbitrating against the trim tail. t_post below measures the window with L1 live.
    tpc0=(ATEL||PROBE)?now_s():0;
    if(PROBE){ M1RsiKeys rk2; m1rsi_grin_keys_from_pre_pow_nonce(PP,PPLEN,nonce+1,&rk2);
      u64 kk2[4]={rk2.k0,rk2.k1,rk2.k2,rk2.k3}; memcpy(bK2.contents,kk2,32); memset(ccn2.contents,0,(u64)coarse_n*4);
      l1cb=[q2 commandBuffer]; id<MTLComputeCommandEncoder>e2=[l1cb computeCommandEncoder];
      [e2 setComputePipelineState:psL1];[e2 setBuffer:bK2 offset:0 atIndex:0];[e2 setBuffer:bPs2 offset:0 atIndex:1];[e2 setBuffer:ccn2 offset:0 atIndex:2];[e2 setBuffer:cEP2 offset:0 atIndex:3];[e2 setBuffer:cIDX2 offset:0 atIndex:4];
      for(u64 base=0;base<nedges;base+=CH){u32 b32=(u32)base;u64 n=(nedges-base<CH)?(nedges-base):CH; id<MTLBuffer> bB=[dev newBufferWithBytes:&b32 length:4 options:MTLResourceStorageModeShared];[e2 setBuffer:bB offset:0 atIndex:5];[e2 dispatchThreadgroups:MTLSizeMake((n+TPB-1)/TPB,1,1) threadsPerThreadgroup:MTLSizeMake(TPB,1,1)];}
      [e2 endEncoding];[l1cb commit]; l1c0=now_s(); probed=1; }
    // gather survivor indices from cur fine buckets
    u32* fc=(u32*)curFC.contents; u32* fi=(u32*)curFI.contents; u32 ne=0;  // fi is uint2 (idx,z); idx = fi[2*entry]
    if(!d2_abort) for(u32 b=0;b<nb;b++){ u32 cnt=fc[b]; if(cnt>fine_cap)cnt=fine_cap; u64 bs=(u64)b*fine_cap; for(u32 i=0;i<cnt;i++) nonces[ne++]=fi[2*(bs+i)]; } // d2 abort: ne=0 -> peel+recover skip = rec=0 path
    // ---- GPU 2-core peel: kill degree<2 node-pairs until stable (on-GPU; dstFI reused as degU/degV) ----
    u32 ne2=ne; double tPeel=0, tPeelGPU=0, tSip=0, tSort=0, tLb=0, tCompact=0; u32 peelIters=0;
    if(ne>=PROOFSIZE){
      double tp0=now_s();
      // host: endpoints -> densify node-pairs (sparse 2^31 -> dense [0,m)) so deg arrays are cache-resident
      double ts_=now_s();
      u32 *up=malloc((size_t)ne*4),*vp=malloc((size_t)ne*4),*du=malloc((size_t)ne*4),*dv=malloc((size_t)ne*4);
      for(u32 i=0;i<ne;i++){ word_t uf=sipc(2ULL*nonces[i])&nodemask, vf=sipc(2ULL*nonces[i]+1)&nodemask; up[i]=(u32)(uf>>1); vp[i]=(u32)(vf>>1); }
      tSip=now_s()-ts_; ts_=now_s();
      u32 *su=malloc((size_t)ne*4),*sv=malloc((size_t)ne*4); memcpy(su,up,(size_t)ne*4); memcpy(sv,vp,(size_t)ne*4);
      radix_u32(su,ne); radix_u32(sv,ne); // was qsort(...,u32cmp); identical sorted output, O(n)
      u32 mU=0,mV=0; for(u32 i=0;i<ne;i++) if(i==0||su[i]!=su[i-1]) su[mU++]=su[i];
      for(u32 i=0;i<ne;i++) if(i==0||sv[i]!=sv[i-1]) sv[mV++]=sv[i];
      tSort=now_s()-ts_; ts_=now_s();
      for(u32 i=0;i<ne;i++){ du[i]=g_lb(su,mU,up[i]); dv[i]=g_lb(sv,mV,vp[i]); }
      tLb=now_s()-ts_;
      id<MTLBuffer> bDu=[dev newBufferWithBytes:du length:(u64)ne*4 options:MTLResourceStorageModeShared];
      id<MTLBuffer> bDv=[dev newBufferWithBytes:dv length:(u64)ne*4 options:MTLResourceStorageModeShared];
      id<MTLBuffer> bAl=[dev newBufferWithLength:ne options:MTLResourceStorageModeShared]; memset(bAl.contents,1,ne);
      id<MTLBuffer> bNe=[dev newBufferWithBytes:&ne length:4 options:MTLResourceStorageModeShared];
      id<MTLBuffer> bChg=[dev newBufferWithLength:4 options:MTLResourceStorageModeShared];
      id<MTLBuffer> bDegU=[dev newBufferWithLength:(u64)(mU?mU:1)*4 options:MTLResourceStorageModePrivate];
      id<MTLBuffer> bDegV=[dev newBufferWithLength:(u64)(mV?mV:1)*4 options:MTLResourceStorageModePrivate];
      u32 grid=(ne+TPB-1)/TPB; int pit=0; MTLSize gd=MTLSizeMake(grid,1,1), tg=MTLSizeMake(TPB,1,1);
      const int PM=16; // peel iters per command buffer (work/iter is tiny -> syncs dominate; batch them)
      for(pit=0; pit<4096; pit+=PM){ *(u32*)bChg.contents=0;
        id<MTLCommandBuffer>c=[q commandBuffer];id<MTLComputeCommandEncoder>e=[c computeCommandEncoder];
        [e setBuffer:bDu offset:0 atIndex:0];[e setBuffer:bDv offset:0 atIndex:1];[e setBuffer:bNe offset:0 atIndex:2];[e setBuffer:bAl offset:0 atIndex:3];[e setBuffer:bDegU offset:0 atIndex:4];[e setBuffer:bDegV offset:0 atIndex:5];[e setBuffer:bChg offset:0 atIndex:6];
        for(int m=0;m<PM;m++){
          [e setComputePipelineState:psPC];[e dispatchThreadgroups:gd threadsPerThreadgroup:tg];[e memoryBarrierWithScope:MTLBarrierScopeBuffers];
          [e setComputePipelineState:psPN];[e dispatchThreadgroups:gd threadsPerThreadgroup:tg];[e memoryBarrierWithScope:MTLBarrierScopeBuffers];
          [e setComputePipelineState:psPK];[e dispatchThreadgroups:gd threadsPerThreadgroup:tg];[e memoryBarrierWithScope:MTLBarrierScopeBuffers];
        }
        [e endEncoding];[c commit];[c waitUntilCompleted]; cb_note(c,"peel");
        if(ATEL) tPeelGPU += (c.GPUEndTime-c.GPUStartTime);
        if(*(u32*)bChg.contents==0) break;
      }
      peelIters=(u32)pit; // peel iterations actually run (>= ~4096 => iteration-capped, peel returns an over-retained superset)
      if(L1PRE && !STEER_ON && (maxkeys==0 || graphs+1<maxkeys)){ // prefire next-nonce L1 into the compact+recover+verify CPU window (same queue: peel GPU batches are done)
        M1RsiKeys nk; m1rsi_grin_keys_from_pre_pow_nonce(PP,PPLEN,nonce+1,&nk);
        u64 nkk[4]={nk.k0,nk.k1,nk.k2,nk.k3}; memcpy(bK.contents,nkk,32); memset(ccn.contents,0,(u64)coarse_n*4);
        id<MTLCommandBuffer>pc=[q commandBuffer];id<MTLComputeCommandEncoder>pe=[pc computeCommandEncoder];
        [pe setComputePipelineState:psL1];[pe setBuffer:bK offset:0 atIndex:0];[pe setBuffer:bPs offset:0 atIndex:1];[pe setBuffer:ccn offset:0 atIndex:2];[pe setBuffer:cEP offset:0 atIndex:3];[pe setBuffer:cIDX offset:0 atIndex:4];
        u64 CH2=1ull<<28; for(u64 base=0;base<nedges;base+=CH2){u32 b32=(u32)base;u64 n=(nedges-base<CH2)?(nedges-base):CH2; id<MTLBuffer> bB=[dev newBufferWithBytes:&b32 length:4 options:MTLResourceStorageModeShared];[pe setBuffer:bB offset:0 atIndex:5];[pe dispatchThreadgroups:MTLSizeMake((n+TPB-1)/TPB,1,1) threadsPerThreadgroup:MTLSizeMake(TPB,1,1)];}
        [pe endEncoding];[pc commit]; pf_cb=pc; pf_nonce=nonce+1; pf_gen=CUR_GEN; } // no wait: hides under host tail; consumed (or discarded) at next graph top
      double tc_=now_s();
      unsigned char* al=(unsigned char*)bAl.contents; ne2=0; for(u32 i=0;i<ne;i++) if(al[i]) nonces[ne2++]=nonces[i];
      tCompact=now_s()-tc_;
      free(up);free(vp);free(du);free(dv);free(su);free(sv);
      tPeel=now_s()-tp0;
    }
    double tr0=now_s(); int rec=d2_wit?1:((ne2>=PROOFSIZE)?recover(nodemask,nonces,ne2,sol):0); double tRec=now_s()-tr0;
    if((ATEL||PROBE) && tpc0>0) t_post=now_s()-tpc0; // this graph's own post-cut wall (before waiting on the probe L1)
    if(PROBE && probed && l1cb){ [l1cb waitUntilCompleted]; l1_wall=now_s()-l1c0; l1_gpu=l1cb.GPUEndTime-l1cb.GPUStartTime; }
    if(key<6||(key%50)==0) printf("key %u: 2core=%u | seed %.3f round %.3f (GPU %.3f, sync %.3f) peel %.3f recover %.3f | WALL %.3fs%s\n",key,ne2,tSeed,tRound,tRoundGPU,tRound-tRoundGPU,tPeel,tRec,now_s()-tkey,d2sfx);
    if(ATEL){ u64 s0tot=0; u32 s0mx=0; for(u32 b=0;b<nb;b++){ s0tot+=cur_seed0[b]; if(cur_seed0[b]>s0mx)s0mx=cur_seed0[b]; }
      tel_write("{\"receipt_kind\":\"mine34_arena_graph.v1\",\"key\":%u,\"two_core\":%u,\"survivors\":%u,\"seed0_total\":%llu,\"seed0_max\":%u,\"seed_s\":%.4f,\"seed_l1_s\":%.4f,\"seed_l2_s\":%.4f,\"round_s\":%.4f,\"round_gpu_s\":%.4f,\"peel_s\":%.4f,\"peel_gpu_s\":%.4f,\"peel_sip_s\":%.4f,\"peel_sort_s\":%.4f,\"peel_lb_s\":%.4f,\"peel_compact_s\":%.4f,\"peel_iters\":%u,\"recover_s\":%.4f,\"t_post\":%.4f,\"probe\":%d,\"l1_wall\":%.4f,\"l1_gpu\":%.4f}\n",
        key,ne2,ne,(unsigned long long)s0tot,s0mx,tSeed,tSeedL1,tSeedL2,tRound,tRoundGPU,tPeel,tPeelGPU,tSip,tSort,tLb,tCompact,peelIters,tRec,t_post,probed,l1_wall,l1_gpu);
      memcpy(prev_seed0,cur_seed0,(size_t)nb*4); have_prev=1; }
    int verify_ok=0, submitted=0;
    if(rec){
      word_t we[PROOFSIZE]; for(int i=0;i<PROOFSIZE;i++) we[i]=sol[i];
      int ok=(verify(we)==0); verify_ok=ok; sols++;
      printf("\n[%.1fs] 42-CYCLE found! nonce=%llu height=%llu job_id=%llu Tromp verify=%s\n",
        now_s()-t0,(unsigned long long)nonce,(unsigned long long)CUR_H,(unsigned long long)CUR_J, ok?"POW_OK":"FAIL");
      if(ok && !FIXED){ printf("  SUBMITTING share -> node\n"); strat_submit(CUR_H,CUR_J,nonce,sol); submitted=1; } // submit the freshly-mined job (drained-to-latest at graph start)
    }
    tel_result(CUR_H,CUR_J,CUR_PPID,CUR_GEN,nonce,rec,verify_ok,submitted,have_qscore,qscore);
    if(!STEER_ON) nonce++;
    graphs++;
  }}
  S_STOP=1;
  if(STEER_ON) pthread_join(sth,NULL);
  tel_close();
  printf("done: mined %u graphs, %u sols | scorer scanned %lu, skipped %lu (%.0f%% skip) | %.1fs\n",
    graphs,sols,S_SCANNED,S_SKIPPED, S_SCANNED?100.0*S_SKIPPED/S_SCANNED:0.0, now_s()-t0); free(nonces);
 }
 return 0;
}
