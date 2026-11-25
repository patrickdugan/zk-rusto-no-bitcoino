"""ZKL-NOVA-03: native shared-path authentication and fixed-slot model."""
from frontier import H, EMPTY, Reference, auth, digest, fixture, need, rejects
from block_frontier import State, step
from hashlib import sha256
from random import Random
from time import perf_counter
import json, sys

ZERO = bytes(32)
PAD = (-1, 0, ZERO)
LPAD = (-1, ZERO)

def caps(d,k):
    need(type(d) is int and 1<=d<=32 and type(k) is int and 1<=k<=1<<d)
    return [min(k,1<<(d-l-1)) for l in range(d)]

def plan(ref,ids):
    nodes=sorted(ids); layers=[]
    for l in range(ref.d):
        rows=[]; j=0
        while j<len(nodes):
            i=nodes[j]; p=i//2
            if i%2==0 and j+1<len(nodes) and nodes[j+1]==i+1:
                rows.append((p,3,ZERO)); j+=2
            else:
                rows.append((p,1 if i%2==0 else 2,ref.get(l,i^1))); j+=1
        layers.append(tuple(rows)); nodes=[r[0] for r in rows]
    return tuple(layers)

def verify(d,n,root,expected,leaves,layers,k=None):
    """Expected is caller-bound addresses/digests; Python reads are not R1CS."""
    need(type(d) is int and 1<=d<=32 and type(n) is int and 0<=n<=1<<d and digest(root))
    need(type(expected) is dict and all(type(i) is int and 0<=i<n and digest(x) and x!=EMPTY for i,x in expected.items()))
    fixed=k is not None
    limit=caps(d,k) if fixed else [1<<(d-l-1) for l in range(d)]
    if fixed: need(len(leaves)==k and len(expected)<=k)
    entries=tuple(sorted(expected.items())); active=len(entries)
    need(tuple(leaves[:active])==entries)
    need(tuple(leaves[active:])==(LPAD,)*(k-active) if fixed else len(leaves)==active)
    need(len(layers)==d); nodes=list(entries); hashes=real=siblings=0
    for l,rows in enumerate(layers):
        need(len(rows)==limit[l] if fixed else len(rows)<=limit[l])
        out=[]; j=0
        for row in rows:
            need(type(row) is tuple and len(row)==3)
            p,mask,s=row
            if j==len(nodes):
                need(fixed and row==PAD); H(ZERO,ZERO); hashes+=1; continue
            need(type(p) is int and type(mask) is int and digest(s))
            i,x=nodes[j]; need(p==i//2 and 0<=p<1<<(d-l-1))
            pair=i%2==0 and j+1<len(nodes) and nodes[j+1][0]==i+1
            if pair:
                need(mask==3 and s==ZERO); y=H(x,nodes[j+1][1]); j+=2
            else:
                need(mask==(1 if i%2==0 else 2)); y=H(x,s) if mask==1 else H(s,x)
                j+=1; siblings+=1
            out.append((p,y)); real+=1; hashes+=1
        need(j==len(nodes)); nodes=out
    need(nodes==[(0,root)] if active else not nodes)
    return real,hashes,siblings

def pad(leaves,layers,d,k):
    need(len(leaves)<=k)
    return tuple(leaves)+(LPAD,)*(k-len(leaves)),tuple(tuple(a)+(PAD,)*(c-len(a)) for a,c in zip(layers,caps(d,k)))

def check(ref,ids,k=None):
    expected={i:ref.get(0,i) for i in ids}; leaves=tuple(sorted(expected.items())); layers=plan(ref,ids)
    if k is not None: leaves,layers=pad(leaves,layers,ref.d,k)
    return verify(ref.d,ref.n,ref.root(),expected,leaves,layers,k)

def test():
    rng=Random(308); cases=tight=0
    for d in range(1,9):
        ref=Reference(d)
        for i in range(1<<d): ref.append(sha256(rng.randbytes(32)).digest())
        for k in range(1,(1<<d)+1):
            ids=[i*(1<<d)//k for i in range(k)]
            r,f,_=check(ref,ids,k); need(r==f==sum(caps(d,k))); tight+=1
        for _ in range(32):
            n=rng.randrange(1<<d)+1; sub=Reference(d)
            for i in range(n): sub.append(ref.get(0,i))
            k=rng.randrange(1,min(n,64)+1); ids=rng.sample(range(n),rng.randrange(k+1))
            a=check(sub,ids); b=check(sub,ids,k)
            need(a[0]==b[0] and a[2]==b[2] and b[1]==sum(caps(d,k)))
            for i in ids: auth(d,sub.root(),n,i,sub.get(0,i),sub.path(i))
            cases+=1
    ref=Reference(4)
    for i in range(11): ref.append(sha256(bytes([i])).digest())
    ids=[0,1,4,9]; expected={i:ref.get(0,i) for i in ids}; k=5
    leaves,layers=pad(tuple(sorted(expected.items())),plan(ref,ids),4,k)
    v=lambda e=expected,L=leaves,P=layers,N=11,R=ref.root():verify(4,N,R,e,L,P,k)
    def change(l,j,row):
        P=list(layers); a=list(P[l]); a[j]=row; P[l]=tuple(a); return tuple(P)
    p,m,s=layers[0][1]; attacks=[lambda:v(R=ZERO),lambda:v(N=9),lambda:v(e={**expected,10:ref.get(0,10)}),
        lambda:v(e={i:x for i,x in expected.items() if i!=4}),lambda:v(L=leaves[::-1]),
        lambda:v(L=(leaves[0],leaves[0])+leaves[2:]),lambda:v(L=((0,ZERO),)+leaves[1:]),
        lambda:v(L=leaves[:-1]+((3,ZERO),)),lambda:v(P=change(0,1,(p,m,ZERO))),
        lambda:v(P=change(0,0,(0,1,ZERO))),lambda:v(P=change(0,0,(1,3,ZERO))),
        lambda:v(P=change(0,0,(0,3,bytes([1])*32))),lambda:v(P=change(0,3,(7,1,ZERO))),
        lambda:v(P=change(0,1,PAD)),lambda:v(P=layers[:-1]),lambda:v(P=(layers[0][:-1],)+layers[1:])]
    for attack in attacks: rejects(attack)
    return dict(random_cases=cases,tight_bound_cases=tight,targeted_rejections=len(attacks))

def bench(n,B,workload,d=17):
    t=perf_counter(); leaves,reads=fixture(n,workload=='scatter'); rng=Random(20261125)
    if workload=='entropy': reads=[set() if i<4 else set(rng.sample(range(i),min(i,5))) for i in range(len(leaves))]
    k=min(5*B,1<<d); b=B.bit_length()-1; st=State.empty(d,b); ref=Reference(d)
    paths=actual=slots=sib=writes=peak=steps=0; padded_checks=0
    for start in range(0,len(leaves),B):
        end=min(start+B,len(leaves)); ids={i for r in reads[start:end] for i in r if i<start}
        a,_,s=check(ref,ids); actual+=a; sib+=s; paths+=len(ids)*d; peak=max(peak,len(ids))
        slots+=sum(caps(d,k)); steps+=1
        if steps<=2 or end==len(leaves) or steps%127==0:
            x,y,z=check(ref,ids,k); need(x==a and z==s and y==sum(caps(d,k))); padded_checks+=1
        st,c=step(st,leaves[start:end]+[EMPTY]*(B-(end-start)),end-start,end==len(leaves)); writes+=c
        for x in leaves[start:end]: ref.append(x)
        need(st.root==ref.root())
    return dict(workload=workload,rows=n,batch=B,steps=steps,K=k,peak_reads=peak,independent_actual=paths,
        multiproof_actual=actual,sibling_digests=sib,independent_padded=d*k*steps,multiproof_padded=slots,
        fixed_write_hashes=writes,padded_checks=padded_checks,seconds=round(perf_counter()-t,3))

if __name__=='__main__':
    print(json.dumps(test()),flush=True)
    n=int(sys.argv[1]) if len(sys.argv)>1 else 100000
    for workload in ('chain','scatter','entropy'):
        for B in (16,64,256): print(json.dumps(bench(n,B,workload)),flush=True)
