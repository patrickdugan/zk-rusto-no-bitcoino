"""Fixed-schedule native circuit model for aligned, sealed append blocks."""
from frontier import H, EMPTY, zeros, need, digest, Reference, auth, fixture, rejects
from dataclasses import dataclass
from hashlib import sha256
from random import Random
from time import perf_counter
import json
import sys

ZERO=bytes(32)

@dataclass(frozen=True)
class State:
    d: int
    b: int
    blocks: int
    rows: int
    sealed: bool
    slots: tuple
    root: bytes
    @classmethod
    def empty(cls,d,b):
        need(type(d) is int and type(b) is int and 0<=b<=d<=32 and d>=1)
        return cls(d,b,0,0,False,(ZERO,)*(d-b+1),zeros(d)[d])
    def check(self):
        d,b,m,n=self.d,self.b,self.blocks,self.rows
        need(type(d) is int and type(b) is int and 0<=b<=d<=32 and d>=1)
        need(type(m) is int and 0<=m<=1<<(d-b) and type(n) is int)
        need(type(self.sealed) is bool and digest(self.root))
        need((m>0 and (m-1)*(1<<b)<n<=m*(1<<b)) if self.sealed else n==m*(1<<b))
        need(type(self.slots) is tuple and len(self.slots)==d-b+1)
        for k,v in enumerate(self.slots):
            need(digest(v) and (((m>>k)&1) or v==ZERO))

def root(d,b,m,slots):
    z=zeros(d); a=z[b]
    for k in range(d-b):
        a=H(slots[k],a) if (m>>k)&1 else H(a,z[b+k])
    return slots[d-b] if m==1<<(d-b) else a

def step(st,xs,active,seal):
    st.check(); need(not st.sealed and st.blocks<1<<(st.d-st.b))
    d,b,m=st.d,st.b,st.blocks; B=1<<b; h=d-b
    need(type(active) is int and 1<=active<=B and len(xs)==B and type(seal) is bool)
    need(active==B or seal)
    need(m+1<1<<h or seal)
    for i,x in enumerate(xs): need(digest(x) and ((x!=EMPTY) if i<active else x==EMPTY))
    layer=list(xs); hashes=0
    while len(layer)>1:
        layer=[H(layer[i],layer[i+1]) for i in range(0,len(layer),2)]; hashes+=len(layer)
    x=layer[0]; c=True; slots=list(st.slots)
    # Every candidate hash is computed, even when the carry is inactive.
    for k in range(h):
        bit=bool((m>>k)&1); y=H(slots[k],x); hashes+=1
        if c:
            if bit: slots[k]=ZERO; x=y
            else: slots[k]=x
        c=c and bit
    slots[h]=x if c else ZERO
    rr=root(d,b,m+1,slots); hashes+=h
    out=State(d,b,m+1,st.rows+active,seal,tuple(slots),rr)
    out.check(); need(hashes==B-1+2*h)
    return out,hashes

def transition(st,xs,active,seal,claimed):
    # Prior-root recomputation is for standalone conformance. In IVC this
    # invariant is enforced at genesis and each output; it need not be repeated.
    st.check(); need(root(st.d,st.b,st.blocks,st.slots)==st.root)
    out,_=step(st,xs,active,seal); need(out==claimed); return out

def bench(n,b,scatter,d=17):
    t=perf_counter(); leaves,reads=fixture(n,scatter); B=1<<b
    st=State.empty(d,b); ref=Reference(d); a=c=s=0
    for start in range(0,len(leaves),B):
        end=min(start+B,len(leaves)); active=end-start
        hist={i for r in reads[start:end] for i in r if i<start}
        for i in hist: auth(d,st.root,start,i,leaves[i],ref.path(i))
        a+=len(hist); xs=leaves[start:end]+[EMPTY]*(B-active)
        st,cc=step(st,xs,active,end==len(leaves)); c+=cc; s+=1
        for x in leaves[start:end]: ref.append(x)
        need(st.root==ref.root() and st.rows==end)
    need(st.sealed); auth(d,st.root,st.rows,st.rows-1,leaves[-1],ref.path(st.rows-1))
    return dict(workload='scatter' if scatter else 'chain',rows=n,genesis=4,batch=B,steps=s,
                historical_reads=a,fixed_write_hashes=c,hashes_per_step=B-1+2*(d-b),
                total_hashes=c+d*a,seconds=round(perf_counter()-t,3))

def test():
    rng=Random(31); cases=steps=0
    for d in range(1,9):
        for b in range(d+1):
            B=1<<b
            for n in sorted({1,B,min(1<<d,B+1),1<<d,rng.randrange(1,(1<<d)+1)}):
                st=State.empty(d,b); ref=Reference(d); cases+=1
                for start in range(0,n,B):
                    active=min(B,n-start); seal=start+active==n
                    xs=[sha256(rng.randbytes(32)).digest() for _ in range(active)]
                    padded=xs+[EMPTY]*(B-active)
                    out,_=step(st,padded,active,seal); transition(st,padded,active,seal,out)
                    for x in xs: ref.append(x)
                    need(out.root==ref.root()); st=out; steps+=1
                rejects(lambda:step(st,[sha256(b'new').digest()]*B,B,True))
    st=State.empty(4,2); xs=[sha256(bytes([i])).digest() for i in range(4)]
    out,_=step(st,xs,4,False); partial=xs[:2]+[EMPTY]*2
    final,_=step(out,partial,2,True)
    attacks=[lambda:step(st,partial,2,False),lambda:step(st,xs,2,True),
             lambda:step(st,[EMPTY]*4,4,True),lambda:step(st,xs,0,True),
             lambda:step(st,xs,5,True),lambda:step(st,xs,4,1),
             lambda:step(final,xs,4,True),lambda:transition(st,xs[::-1],4,False,out),
             lambda:transition(st,xs,4,True,out),lambda:transition(st,xs,4,False,final),
             lambda:transition(State(4,2,0,0,False,st.slots,ZERO),xs,4,False,out),
             lambda:State(4,2,1,3,False,out.slots,out.root).check()]
    for f in attacks: rejects(f)
    return dict(cases=cases,fixed_steps=steps,sealed_rejections=cases,targeted_rejections=len(attacks))

if __name__=='__main__':
    print(json.dumps(test()),flush=True)
    n=int(sys.argv[1]) if len(sys.argv)>1 else 100000
    for scatter in (False,True):
        for b in (4,6,8): print(json.dumps(bench(n,b,scatter)),flush=True)
