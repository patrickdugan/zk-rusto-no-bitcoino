"""ZKL-NOVA-04: evaluated R1CS-compatible arithmetic routing equations.
SHA-to-field is an EXTERNAL oracle. No synthesized hash circuit or Nova proof.
"""
from hashlib import sha256
from random import Random
from collections import Counter
from time import perf_counter
from itertools import permutations
import json
P=28948022309329048855892746252171976963363056481941647379679742748393362948097
PAD=(0,0,0)
def H(a,b):return int.from_bytes(sha256(b'ZKL04/node'+a.to_bytes(32,'big')+b.to_bytes(32,'big')).digest(),'big')%P
def ceil2(n):return 1<<(n-1).bit_length()
def caps(d,k):return [min(k,1<<(d-l-1)) for l in range(d)]
def nswitch(n):return n//2*(2*(n.bit_length()-1)-1) if n>1 else 0
class Reject(ValueError):pass
class CS:
    def __init__(self):self.c=Counter();self.g='';self.h=0
    def mul(self,a,b,z):
        self.c[self.g]+=1
        if (a*b-z)%P:raise Reject(self.g)
    def eq(self,a,b=0):self.mul(a-b,1,0)
    def bit(self,b):self.mul(b,b-1,0)
    def sel(self,s,a,b):
        z=(a+s*(b-a))%P;self.mul(s,b-a,z-a);return z
    def bounded(self,x,w):
        bits=[(x>>j)&1 for j in range(w)]
        for b in bits:self.bit(b)
        self.eq(x,sum(b<<j for j,b in enumerate(bits)));return bits
    def zero(self,x):
        x%=P;z=int(x==0);inv=pow(x,-1,P) if x else 0
        self.mul(x,inv,1-z);self.mul(x,z,0);return z
    def hash(self,a,b):self.h+=1;return H(a,b)

def controls(pi):
    n=len(pi)
    if n==1:return None
    if n==2:return pi[0]
    inv=[0]*n
    for i,j in enumerate(pi):inv[j]=i
    color=[-1]*n
    for i in range(n):
        if color[i]>=0:continue
        color[i]=0;stack=[i]
        while stack:
            j=stack.pop()
            for t in (j^1,inv[pi[j]^1]):
                if color[t]<0:color[t]=1-color[j];stack.append(t)
                else:assert color[t]!=color[j]
    subs=[[0]*(n//2) for _ in range(2)]
    for i,j in enumerate(pi):subs[color[i]][i//2]=j//2
    return [color[2*i] for i in range(n//2)],controls(subs[0]),controls(subs[1]),[color[inv[2*i]] for i in range(n//2)]

def route(cs,x,c):
    n=len(x)
    if n==1:return x
    def switch(a,b,s):
        cs.bit(s);z=tuple(cs.sel(s,i,j) for i,j in zip(a,b));w=tuple((i+j-k)%P for i,j,k in zip(a,b,z));return z,w
    if n==2:return list(switch(*x,c))
    f,t,u,l=c;top=[];bot=[]
    for j in range(n//2):
        a,b=switch(x[2*j],x[2*j+1],f[j]);top.append(a);bot.append(b)
    top=route(cs,top,t);bot=route(cs,bot,u);out=[]
    for j in range(n//2):out.extend(switch(top[j],bot[j],l[j]))
    return out

def permute(cs,src,pos,n,corrupt=False,packed=False):
    x=list(src)+[PAD]*(n-len(src));pi=[-1]*n
    for i,j in pos.items():pi[i]=j
    spare=iter(sorted(set(range(n))-set(pos.values())))
    for i in range(n):
        if pi[i]<0:pi[i]=next(spare)
    assert sorted(pi)==list(range(n))
    c=controls(pi)
    if corrupt:c[0][0]=2
    if not packed:return route(cs,x,c)
    # Canonical inactive record is zero. Active key is address+1.
    y=route(cs,[(a+i,v) for a,i,v in x],c);out=[]
    for key,v in y:
        a=1-cs.zero(key);out.append((a,(key-a)%P,v))
    return out

def prefix(cs,x):
    for a,b in zip(x,x[1:]):cs.mul(b[0],1-a[0],0)
def gap(cs,a,b,w,strict):
    x=b[0]*(b[1]-a[1]-strict)%P;cs.mul(b[0],b[1]-a[1]-strict,x);cs.bounded(x,w)
def canonical(cs,rows):
    for r in rows:
        for x in r:cs.eq(x)

def dedup(cs,raw,d,n,k,attack,optimized):
    cs.g='request_bounds'
    for a,i,x in raw:
        cs.bit(a);cs.mul(1-a,i,0);cs.mul(1-a,x,0);cs.bounded(i,d)
        z=a*(n-1-i)%P;cs.mul(a,n-1-i,z);cs.bounded(z,d)
    cs.g='request_sort_switch';order=sorted(range(k),key=lambda j:(-raw[j][0],raw[j][1]))
    x=permute(cs,raw,{i:j for j,i in enumerate(order)},ceil2(k),attack=='switch',optimized)
    cs.g='request_sort_checks';canonical(cs,x[k:]);x=x[:k];prefix(cs,x);heads=[]
    for j,r in enumerate(x):
        a,i,v=r;dup=0
        if j:
            prev=x[j-1];gap(cs,prev,r,d,0);z=cs.zero(i-prev[1]);dup=a*z%P;cs.mul(a,z,dup);cs.mul(dup,v-prev[2],0)
        h=(a-dup)%P;q=(h,h*i%P,h*v%P);cs.mul(h,i,q[1]);cs.mul(h,v,q[2]);heads.append(q)
    if optimized:return heads
    cs.g='request_compact_switch';order=sorted(range(k),key=lambda j:(-heads[j][0],heads[j][1]))
    y=permute(cs,heads,{i:j for j,i in enumerate(order)},ceil2(k))
    cs.g='request_compact_checks';canonical(cs,y[k:]);y=y[:k];prefix(cs,y)
    for a,b in zip(y,y[1:]):gap(cs,a,b,d,1)
    return y

class Tree:
    def __init__(self,d,n):
        self.d=d;self.n=n;self.layers=[[i+1 if i<n else 0 for i in range(1<<d)]]
        for l in range(d):
            x=self.layers[-1];self.layers.append([H(x[j],x[j+1]) for j in range(0,len(x),2)])
    def get(self,l,i):return self.layers[l][i]
    @property
    def root(self):return self.layers[-1][0]

def layer(cs,children,tree,l,c,attack,optimized):
    d=tree.d;active=[(j,r) for j,r in enumerate(children) if r[0]]
    parents=sorted(set(r[1]//2 for j,r in active));pos={p:j for j,p in enumerate(parents)}
    places={j:2*pos[r[1]//2]+r[1]%2 for j,r in active}
    cs.g='layer_switch';x=permute(cs,children,places,ceil2(2*c),packed=optimized)
    cs.g='layer_padding';canonical(cs,x[2*c:]);out=[]
    for j in range(c):
        L,R=x[2*j:2*j+2];a,b=L[0],R[0];p=parents[j] if j<len(parents) else 0
        if attack=='parent' and j==0:p+=1
        cs.g='layer_index';both=a*b%P;cs.mul(a,b,both);live=(a+b-both)%P
        cs.mul(a,L[1]-2*p,0);cs.mul(b,R[1]-2*p-1,0);cs.mul(1-live,p,0);cs.bounded(p,d-l-1)
        cs.g='layer_sibling';s=tree.get(l,2*p+1 if a else 2*p) if live and not both else 0
        if attack=='sibling' and j==0:s=(s+1)%P
        cs.mul(1-live+both,s,0);u=(L[2]+(1-a)*s)%P;v=(R[2]+(1-b)*s)%P
        cs.mul(1-a,s,u-L[2]);cs.mul(1-b,s,v-R[2])
        cs.g='layer_output';h=cs.hash(u,v);z=live*h%P;cs.mul(live,h,z);out.append((live,p,z))
    cs.g='layer_order';prefix(cs,out)
    for a,b in zip(out,out[1:]):gap(cs,a,b,d-l-1,1)
    return out

def check(tree,raw,k,attack=None,optimized=False):
    assert len(raw)==k and 1<=k<=1<<tree.d
    cs=CS();d=tree.d;n=tree.n;cs.g='public_bounds';cs.bounded(n,d+1);cs.bounded((1<<d)-n,d+1)
    x=dedup(cs,raw,d,n,k,attack,optimized)
    for l,c in enumerate(caps(d,k)):x=layer(cs,x,tree,l,c,attack if l==0 else None,optimized)
    cs.g='root';a,i,z=x[0];cs.eq(i);cs.mul(a,z-tree.root,0)
    return dict(routing_constraints=sum(cs.c.values()),hash_slots=cs.h,counts=dict(cs.c))

def independent(tree,raw):
    cs=CS();d=tree.d;n=tree.n;cs.g='public_bounds';cs.bounded(n,d+1);cs.bounded((1<<d)-n,d+1)
    for a,i,x in raw:
        cs.g='request_bounds';cs.bit(a);cs.mul(1-a,i,0);cs.mul(1-a,x,0);bits=cs.bounded(i,d)
        z=a*(n-1-i)%P;cs.mul(a,n-1-i,z);cs.bounded(z,d)
        for l,b in enumerate(bits):
            cs.g='path_select';s=tree.get(l,(i>>l)^1) if a else 0;u=cs.sel(b,x,s);v=(x+s-u)%P;x=cs.hash(u,v)
        cs.g='root';cs.mul(a,x-tree.root,0)
    return dict(routing_constraints=sum(cs.c.values()),hash_slots=cs.h,counts=dict(cs.c))

def rec(tree,i):return (1,i,tree.get(0,i))

def tests():
    rng=Random(404);nc=nr=na=0
    for n in (1,2,4,8,16,32,64):
        for pi in (permutations(range(n)) if n<=4 else (rng.sample(range(n),n) for _ in range(32))):
            cs=CS();cs.g='network';out=route(cs,[(1,i,i+100) for i in range(n)],controls(pi));assert all(out[j][1]==i for i,j in enumerate(pi));assert sum(cs.c.values())==4*nswitch(n);nc+=1
    for d in range(1,7):
        t=Tree(d,1<<d)
        for k in sorted({1,min(5,1<<d),min(12,1<<d),1<<d}):
            for _ in range(12):
                a=[rec(t,rng.randrange(t.n)) for j in range(rng.randrange(k+1))];a+=[PAD]*(k-len(a));rng.shuffle(a);r=check(t,a,k);q=check(t,a,k,optimized=True);u=independent(t,a);assert r['hash_slots']==q['hash_slots']==sum(caps(d,k)) and u['hash_slots']==d*k;nr+=1
    t=Tree(4,11);a=[rec(t,i) for i in (0,1,4,9,4)]+[PAD]*3
    attacks=[(a,'parent'),(a,'sibling'),(a,'switch'),(a[:4]+[(1,4,999)]+a[5:],None),([(1,11,0)]+a[1:],None),([(2,0,0)]+a[1:],None),(a[:-1]+[(0,2,0)],None),([(1,0,999)]+a[1:],None),([(1,P-1,0)]+a[1:],None)]
    for raw,attack in attacks:
        for opt in (False,True):
            try:check(t,raw,8,attack,opt)
            except Reject:na+=1
            else:raise AssertionError('accepted attack')
    return dict(network_cases=nc,routing_cases=nr,forgeries_rejected=na)

def run():
    print(json.dumps(tests()),flush=True);t=Tree(17,100000)
    for B in (16,64,256):
        k=5*B;rng=Random(404+B)
        for w in ('chain','scatter','entropy','empty'):
            ids=([0,1,3,11,t.n-1]*B if w=='chain' else [i for j in range(B) for i in (0,1,3,11,rng.randrange(t.n))] if w=='scatter' else [rng.randrange(t.n) for j in range(k)] if w=='entropy' else [])
            raw=[rec(t,i) for i in ids]+[PAD]*(k-len(ids));
            for mode in ("independent","benes","packed"):
                s=perf_counter();r=independent(t,raw) if mode=="independent" else check(t,raw,k,optimized=mode=="packed")
                print(json.dumps(dict(batch=B,K=k,workload=w,unique=len(set(ids)),mode=mode,**r,seconds=round(perf_counter()-s,3))),flush=True)
if __name__=='__main__':run()
