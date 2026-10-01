// Generated file, do not hand-edit.
// Exact kernel source compiled at runtime: extracted from the kSrc NSString in
// src/mine34_live.m by tools/kernel_sync_check.py --write.
// Check sync:  make kernel-sync-check     Regenerate:  make kernel-sync-write
// Kernel documentation comments live in src/mine34_live.m next to the string.
#include <metal_stdlib>
using namespace metal;
#define TPB 1024
inline uint2 add64(uint2 a,uint2 b){ uint lo=a.x+b.x; return uint2(lo,a.y+b.y+(lo<a.x?1u:0u)); }
inline uint2 rl13(uint2 a){ return uint2((a.x<<13)|(a.y>>19),(a.y<<13)|(a.x>>19)); }
inline uint2 rl16(uint2 a){ return uint2((a.x<<16)|(a.y>>16),(a.y<<16)|(a.x>>16)); }
inline uint2 rl17(uint2 a){ return uint2((a.x<<17)|(a.y>>15),(a.y<<17)|(a.x>>15)); }
inline uint2 rl21(uint2 a){ return uint2((a.x<<21)|(a.y>>11),(a.y<<21)|(a.x>>11)); }
#define WR v0=add64(v0,v1);v2=add64(v2,v3);v1=rl13(v1);v3=rl16(v3);v1^=v0;v3^=v2;v0=v0.yx;v2=add64(v2,v1);v0=add64(v0,v3);v1=rl17(v1);v3=rl21(v3);v1^=v2;v3^=v0;v2=v2.yx;
inline uint sip24wlo(uint2 k0,uint2 k1,uint2 k2,uint2 k3,uint2 n){
  uint2 v0=k0,v1=k1,v2=k2,v3=k3; v3^=n;
  WR WR
  v0^=n; v2.x^=0xffu;
  WR WR WR
  uint2 b0=add64(v0,v1),b2=add64(v2,v3); uint2 c1=rl13(v1)^b0,c3=rl16(v3)^b2; uint2 d2=add64(b2,c1);
  return ((c1.x<<17)|(c1.y>>15))^((c3.x<<21)|(c3.y>>11))^d2.x^d2.y;
}
inline uint sip24(ulong k0,ulong k1,ulong k2,ulong k3, ulong n){
  return sip24wlo(uint2((uint)k0,(uint)(k0>>32)),uint2((uint)k1,(uint)(k1>>32)),uint2((uint)k2,(uint)(k2>>32)),uint2((uint)k3,(uint)(k3>>32)),uint2((uint)n,(uint)(n>>32)));
}
struct Keys{ulong k0,k1,k2,k3;};
struct P{uint nodemask,zbits,coarse_shift,coarse_n,coarse_cap,fine_shift,fine_mask,fine_n,fine_cap,side;};
inline void stage_ep(uint vep,uint vidx,uint key,uint tid,bool live,
  device atomic_uint* ccnt,device uint* cep,device uint* cidx,uint cap,
  threadgroup atomic_uint* bcnt,threadgroup uint* gbase,uint NK){
  if(tid<NK) atomic_store_explicit(&bcnt[tid],0u,memory_order_relaxed);
  threadgroup_barrier(mem_flags::mem_threadgroup);
  uint lpos=0u; if(live) lpos=atomic_fetch_add_explicit(&bcnt[key],1u,memory_order_relaxed);
  threadgroup_barrier(mem_flags::mem_threadgroup);
  if(tid<NK){ uint c=atomic_load_explicit(&bcnt[tid],memory_order_relaxed); gbase[tid]= c?atomic_fetch_add_explicit(&ccnt[tid],c,memory_order_relaxed):0u; }
  threadgroup_barrier(mem_flags::mem_threadgroup);
  if(live){ uint dd=gbase[key]+lpos; if(dd<cap){ cidx[(ulong)key*cap+dd]=vidx; } }
  threadgroup_barrier(mem_flags::mem_threadgroup);
}
inline void stage_ep3(uint vidx,uint key,uint tid,bool live,
  device atomic_uint* ccnt,device uint* cidx,uint cap,
  threadgroup atomic_uint* bcnt,threadgroup uint* gbase,uint NK){
  uint lpos=0u; if(live) lpos=atomic_fetch_add_explicit(&bcnt[key],1u,memory_order_relaxed);
  threadgroup_barrier(mem_flags::mem_threadgroup);
  if(tid<NK){ uint c=atomic_load_explicit(&bcnt[tid],memory_order_relaxed); gbase[tid]= c?atomic_fetch_add_explicit(&ccnt[tid],c,memory_order_relaxed):0u; atomic_store_explicit(&bcnt[tid],0u,memory_order_relaxed); }
  threadgroup_barrier(mem_flags::mem_threadgroup);
  if(live){ uint dd=gbase[key]+lpos; if(dd<cap){ cidx[(ulong)key*cap+dd]=vidx; } }
  threadgroup_barrier(mem_flags::mem_threadgroup);
}
kernel void L1v(constant Keys& K [[buffer(0)]], constant P& p [[buffer(1)]], device atomic_uint* ccn [[buffer(2)]], device uint* cep [[buffer(3)]], device uint* cidx [[buffer(4)]], constant uint& base [[buffer(5)]], uint tid [[thread_position_in_threadgroup]], uint tgid [[threadgroup_position_in_grid]]){
  threadgroup atomic_uint bcnt[256]; threadgroup uint gbase[256];
  ulong e=(ulong)base+tgid*TPB+tid; uint ep=sip24(K.k0,K.k1,K.k2,K.k3,2*e+p.side)&p.nodemask; uint key=(ep>>p.coarse_shift)&(p.coarse_n-1u);
  stage_ep(ep,(uint)e,key,tid,true,ccn,cep,cidx,p.coarse_cap,bcnt,gbase,p.coarse_n); }
kernel void trim_stage(constant Keys& K [[buffer(0)]], constant P& p [[buffer(1)]], device const uint* fcnt [[buffer(2)]], device const uint2* fidx [[buffer(3)]], device atomic_uint* ccn [[buffer(4)]], device uint* cep [[buffer(5)]], device uint* cidx [[buffer(6)]], uint b [[threadgroup_position_in_grid]], uint tid [[thread_position_in_threadgroup]], uint tpb [[threads_per_threadgroup]]){
  threadgroup atomic_uint seen[1<<(17-5)]; threadgroup atomic_uint bcnt[256]; threadgroup uint gbase[256];
  uint c=fcnt[b]; if(c>p.fine_cap)c=p.fine_cap; ulong base=(ulong)b*p.fine_cap;
  uint words=1u<<(p.zbits-5); for(uint i=tid;i<words;i+=tpb) atomic_store_explicit(&seen[i],0u,memory_order_relaxed);
  threadgroup_barrier(mem_flags::mem_threadgroup);
  for(uint i=tid;i<c;i+=tpb){ uint z=fidx[base+i].y; atomic_fetch_or_explicit(&seen[z>>5],1u<<(z&31),memory_order_relaxed); }
  if(tid<p.coarse_n) atomic_store_explicit(&bcnt[tid],0u,memory_order_relaxed);
  threadgroup_barrier(mem_flags::mem_threadgroup);
  for(uint cs=0; cs<c; cs+=tpb){ uint i=cs+tid; bool live=false; uint vidx=0,key=0;
    if(i<c){ uint2 ez=fidx[base+i]; uint pz=ez.y^1u;
      if((atomic_load_explicit(&seen[pz>>5],memory_order_relaxed)>>(pz&31))&1u){ uint e=ez.x; uint other=sip24(K.k0,K.k1,K.k2,K.k3,2*(ulong)e+(p.side^1u))&p.nodemask; vidx=e; key=(other>>p.coarse_shift)&(p.coarse_n-1u); live=true; } }
    stage_ep3(vidx,key,tid,live,ccn,cidx,p.coarse_cap,bcnt,gbase,p.coarse_n);
  }
}
kernel void L2(constant P& p [[buffer(0)]], device const uint* ccn [[buffer(1)]], device const uint* cep [[buffer(2)]], device const uint* cidx [[buffer(3)]], device atomic_uint* fcn [[buffer(4)]], device uint2* fi [[buffer(5)]], constant Keys& K [[buffer(6)]], uint2 tidv [[thread_position_in_threadgroup]], uint2 tg [[threadgroup_position_in_grid]]){
  uint tid=tidv.x; threadgroup atomic_uint bcnt[256]; threadgroup uint gbase[256]; uint NK=p.fine_n;
  uint coarse=tg.y, chunk=tg.x; uint c=ccn[coarse]; if(c>p.coarse_cap)c=p.coarse_cap; uint start=chunk*TPB; bool live=(start+tid)<c; uint e=0,key=0,zres=0;
  if(live){ e=cidx[(ulong)coarse*p.coarse_cap+start+tid]; uint ep=sip24(K.k0,K.k1,K.k2,K.k3,2*(ulong)e+p.side)&p.nodemask; key=(ep>>p.fine_shift)&p.fine_mask; zres=ep&((1u<<p.zbits)-1u); }
  if(tid<NK) atomic_store_explicit(&bcnt[tid],0u,memory_order_relaxed);
  threadgroup_barrier(mem_flags::mem_threadgroup);
  uint lpos=0u; if(live) lpos=atomic_fetch_add_explicit(&bcnt[key],1u,memory_order_relaxed);
  threadgroup_barrier(mem_flags::mem_threadgroup);
  if(tid<NK){ uint cnt=atomic_load_explicit(&bcnt[tid],memory_order_relaxed); uint gfb=coarse*p.fine_n+tid; gbase[tid]= cnt?atomic_fetch_add_explicit(&fcn[gfb],cnt,memory_order_relaxed):0u; }
  threadgroup_barrier(mem_flags::mem_threadgroup);
  if(live){ uint gfb=coarse*p.fine_n+key; uint dd=gbase[key]+lpos; if(dd<p.fine_cap) fi[(ulong)gfb*p.fine_cap+dd]=uint2(e,zres); } }
kernel void pclr(device const uint* du [[buffer(0)]], device const uint* dv [[buffer(1)]], constant uint& ne [[buffer(2)]], device uint* degU [[buffer(4)]], device uint* degV [[buffer(5)]], uint i [[thread_position_in_grid]]){
  if(i>=ne) return; degU[du[i]]=0u; degV[dv[i]]=0u; }
kernel void pcnt(device const uint* du [[buffer(0)]], device const uint* dv [[buffer(1)]], constant uint& ne [[buffer(2)]], device const uchar* alive [[buffer(3)]], device atomic_uint* degU [[buffer(4)]], device atomic_uint* degV [[buffer(5)]], uint i [[thread_position_in_grid]]){
  if(i>=ne||!alive[i]) return; atomic_fetch_add_explicit(&degU[du[i]],1u,memory_order_relaxed); atomic_fetch_add_explicit(&degV[dv[i]],1u,memory_order_relaxed); }
kernel void pkil(device const uint* du [[buffer(0)]], device const uint* dv [[buffer(1)]], constant uint& ne [[buffer(2)]], device uchar* alive [[buffer(3)]], device const uint* degU [[buffer(4)]], device const uint* degV [[buffer(5)]], device atomic_uint* chg [[buffer(6)]], uint i [[thread_position_in_grid]]){
  if(i>=ne||!alive[i]) return; if(degU[du[i]]<2u||degV[dv[i]]<2u){ alive[i]=0; atomic_store_explicit(chg,1u,memory_order_relaxed); } }
kernel void gridk(device const uint* ccn [[buffer(0)]], constant uint& cn [[buffer(1)]], constant uint& tpb [[buffer(2)]], device uint* grid [[buffer(3)]], uint t [[thread_position_in_grid]]){
  if(t!=0u) return; uint mc=0u; for(uint i=0;i<cn;i++){ uint c=ccn[i]; if(c>mc)mc=c; } mc=(mc+tpb-1u)/tpb; if(mc<1u)mc=1u; grid[0]=mc; grid[1]=cn; grid[2]=1u; }
kernel void d2emit(constant Keys& K [[buffer(0)]], constant P& p [[buffer(1)]], device const uint* fcnt [[buffer(2)]], device const uint2* fidx [[buffer(3)]], device atomic_uint* dn [[buffer(4)]], device uint* didx [[buffer(5)]], device uint* dku [[buffer(6)]], device uint* dkv [[buffer(7)]], constant uint& dcap [[buffer(8)]], uint b [[threadgroup_position_in_grid]], uint tid [[thread_position_in_threadgroup]], uint tpb [[threads_per_threadgroup]]){
  threadgroup uint gbase; uint c=fcnt[b]; if(c>p.fine_cap)c=p.fine_cap; ulong base=(ulong)b*p.fine_cap;
  for(uint cs=0; cs<c; cs+=tpb){ uint i=cs+tid; uint nlive=min(c-cs,tpb);
    if(tid==0) gbase=atomic_fetch_add_explicit(dn,nlive,memory_order_relaxed);
    threadgroup_barrier(mem_flags::mem_threadgroup);
    if(i<c){ uint dd=gbase+tid; if(dd<dcap){ uint e=fidx[base+i].x; didx[dd]=e; dku[dd]=sip24(K.k0,K.k1,K.k2,K.k3,2*(ulong)e)&p.nodemask; dkv[dd]=sip24(K.k0,K.k1,K.k2,K.k3,2*(ulong)e+1)&p.nodemask; } }
    threadgroup_barrier(mem_flags::mem_threadgroup);
  } }
struct DP{ uint n; uint xb; uint hmask; };
kernel void k_d2_hbuild(constant DP& p [[buffer(0)]], const device uint* keyU [[buffer(1)]], const device uint* keyV [[buffer(2)]], device atomic_uint* HU [[buffer(3)]], device atomic_uint* HV [[buffer(4)]], uint gid [[thread_position_in_grid]]){
  if(gid>=p.n) return;
  uint s=(keyU[gid]*0x9E3779B1u)&p.hmask;
  while(true){ uint exp=0xFFFFFFFFu; if(atomic_compare_exchange_weak_explicit(&HU[s],&exp,gid,memory_order_relaxed,memory_order_relaxed)) break; if(exp!=0xFFFFFFFFu) s=(s+1u)&p.hmask; }
  s=(keyV[gid]*0x9E3779B1u)&p.hmask;
  while(true){ uint exp=0xFFFFFFFFu; if(atomic_compare_exchange_weak_explicit(&HV[s],&exp,gid,memory_order_relaxed,memory_order_relaxed)) break; if(exp!=0xFFFFFFFFu) s=(s+1u)&p.hmask; } }
kernel void k_d2_count(constant DP& p [[buffer(0)]], const device uint* keyU [[buffer(1)]], const device uint* keyV [[buffer(2)]], const device uint* HU [[buffer(3)]], const device uint* HV [[buffer(4)]], device uint* arc_cnt [[buffer(5)]], uint gid [[thread_position_in_grid]]){
  if(gid>=p.n) return; uint src=gid; uint ku=keyU[src]^p.xb; uint c=0;
  uint s=(ku*0x9E3779B1u)&p.hmask;
  for(uint e=HU[s]; e!=0xFFFFFFFFu; s=(s+1u)&p.hmask, e=HU[s]){
    if(e==src||keyU[e]!=ku) continue; uint mid=e; uint kv=keyV[mid]^p.xb;
    uint t=(kv*0x9E3779B1u)&p.hmask;
    for(uint f=HV[t]; f!=0xFFFFFFFFu; t=(t+1u)&p.hmask, f=HV[t]){
      if(keyV[f]!=kv||f==src) continue; if(p.xb==0u&&f==mid) continue; c++; } }
  arc_cnt[src]=c; }
kernel void k_d2_emit(constant DP& p [[buffer(0)]], const device uint* keyU [[buffer(1)]], const device uint* keyV [[buffer(2)]], const device uint* HU [[buffer(3)]], const device uint* HV [[buffer(4)]], const device uint* arc_off [[buffer(5)]], device uint* adj_dst [[buffer(6)]], uint gid [[thread_position_in_grid]]){
  if(gid>=p.n) return; uint src=gid; uint ku=keyU[src]^p.xb; uint w=arc_off[src];
  uint s=(ku*0x9E3779B1u)&p.hmask;
  for(uint e=HU[s]; e!=0xFFFFFFFFu; s=(s+1u)&p.hmask, e=HU[s]){
    if(e==src||keyU[e]!=ku) continue; uint mid=e; uint kv=keyV[mid]^p.xb;
    uint t=(kv*0x9E3779B1u)&p.hmask;
    for(uint f=HV[t]; f!=0xFFFFFFFFu; t=(t+1u)&p.hmask, f=HV[t]){
      if(keyV[f]!=kv||f==src) continue; if(p.xb==0u&&f==mid) continue; adj_dst[w]=f; w++; } } }
kernel void k_d2_dfs(constant DP& p [[buffer(0)]], const device uint* adj_off [[buffer(1)]], const device uint* adj_dst [[buffer(2)]], device atomic_uint* found [[buffer(3)]], device atomic_uint* cand [[buffer(4)]], constant uint& cand_cap [[buffer(5)]], uint gid [[thread_position_in_grid]]){
  if(gid>=p.n) return; uint src=gid;
  uint path[22]; uint it[22];
  int d=0; path[0]=src; it[0]=adj_off[src]; uint poll=0;
  while(d>=0){
    if(((poll++)&1023u)==0u && cand_cap==1u && atomic_load_explicit(found,memory_order_relaxed)) return;
    uint i=it[d];
    if(i>=adj_off[path[d]+1]){ d--; continue; }
    it[d]=i+1u; uint nxt=adj_dst[i];
    if(nxt==src){ if(d+1==21){ atomic_fetch_add_explicit(cand,1u,memory_order_relaxed);
        if(cand_cap==1u){ atomic_store_explicit(found,1u,memory_order_relaxed); return; } }
      continue; }
    if(d+1==21) continue;
    bool onp=false; for(int k=1;k<=d;k++) if(path[k]==nxt){ onp=true; break; }
    if(onp) continue;
    d++; path[d]=nxt; it[d]=adj_off[nxt];
  } }
