"""Native append frontier, independently checked against a sparse Merkle tree."""
from hashlib import sha256
from dataclasses import dataclass
from random import Random
from time import perf_counter
import json
import sys

EMPTY = sha256(b'ZKL01/empty').digest()

def H(a,b): return sha256(b'ZKL01/node'+a+b).digest()
def zeros(d):
    z=[EMPTY]
    for _ in range(d): z.append(H(z[-1],z[-1]))
    return z

def need(x):
    if not x: raise ValueError('invalid transition')

def digest(x): return type(x) is bytes and len(x)==32

@dataclass(frozen=True)
class Frontier:
    d: int
    n: int
    slots: tuple
    @classmethod
    def empty(cls,d): return cls(d,0,(None,)*(d+1))
    def check(self):
        need(type(self.d) is int and 1<=self.d<=32)
        need(type(self.n) is int and 0<=self.n<=1<<self.d)
        need(type(self.slots) is tuple and len(self.slots)==self.d+1)
        for k,v in enumerate(self.slots):
            need(digest(v) if (self.n>>k)&1 else v is None)
    def root(self):
        self.check()
        if self.n==1<<self.d: return self.slots[self.d],0
        z=zeros(self.d); a=EMPTY
        for k in range(self.d):
            a=H(self.slots[k],a) if (self.n>>k)&1 else H(a,z[k])
        return a,self.d
    def append(self,xs):
        self.check(); need(0<len(xs)<= (1<<self.d)-self.n)
        n=self.n; f=list(self.slots); m=0
        for x in xs:
            need(digest(x) and x!=EMPTY)
            k=0
            while (n>>k)&1:
                x=H(f[k],x); m+=1; f[k]=None; k+=1
            f[k]=x; n+=1
        out=Frontier(self.d,n,tuple(f)); out.check()
        need(m==len(xs)+self.n.bit_count()-n.bit_count())
        return out,m

def transition(before,old,xs,after,new):
    need(before.root()[0]==old)
    out,_=before.append(xs)
    need(out==after and out.root()[0]==new)
    return out

class Reference:
    def __init__(self,d): self.d=d; self.z=zeros(d); self.t={}; self.n=0
    def get(self,k,i): return self.t.get((k,i),self.z[k])
    def root(self): return self.get(self.d,0)
    def path(self,i): return [self.get(k,(i>>k)^1) for k in range(self.d)]
    def append(self,x):
        i=self.n; self.t[0,i]=x
        for k in range(self.d):
            j=i>>k; self.t[k+1,j>>1]=H(self.get(k,j&~1),self.get(k,j|1))
        self.n+=1

def auth(d,root,n,i,x,path):
    need(type(i) is int and 0<=i<n<=1<<d and len(path)==d and digest(x))
    for k,p in enumerate(path):
        need(digest(p)); x=H(p,x) if (i>>k)&1 else H(x,p)
    need(x==root)

def fixture(n,scatter):
    rows=[(0,0),(1,0,0),(1,1,1),(2,),(3,3,0),(4,4,0),(6,4,0,5),(7,3,1,6),
          (3,3,1),(4,8,1),(6,8,1,9),(7,3,2,10)]
    rng=Random(20261125)
    for i in range(12,n+4):
        a=(rng.randrange(12,i) if i>12 and rng.randrange(2)==1 else 7) if scatter else (i-1 if i>12 else 7)
        rows.append((8,3,1,11,a))
    def reads(r):
        k,*a=r; s=set(a) if k not in (0,2) else set()
        if k==7: s.add(rows[a[2]][1])
        if k==8: s.add(rows[a[2]][2])
        return s
    def leaf(i,r):
        b=i.to_bytes(8,'big'); salt=sha256(b'fixture'+b).digest()
        return sha256(b'ZKL01/row'+b+bytes([len(r)])+b''.join(x.to_bytes(8,'big') for x in r)+salt).digest()
    return [leaf(i,r) for i,r in enumerate(rows)],[reads(r) for r in rows]

def bench(n,b,scatter,d=17):
    t=perf_counter(); leaves,reads=fixture(n,scatter)
    f=Frontier.empty(d); ref=Reference(d)
    for x in leaves[:4]: ref.append(x)
    f,_=f.append(leaves[:4]); need(f.root()[0]==ref.root())
    m=c=a=s=0
    for start in range(4,n+4,b):
        end=min(start+b,n+4); old=ref.root()
        hist={i for r in reads[start:end] for i in r if i<start}
        for i in hist: auth(d,old,start,i,leaves[i],ref.path(i))
        a+=len(hist); f,mm=f.append(leaves[start:end]); m+=mm
        for x in leaves[start:end]: ref.append(x)
        root,cc=f.root(); need(root==ref.root()); c+=cc; s+=1
    need(f.n==n+4)
    return dict(workload='scatter' if scatter else 'chain',rows=n,batch=b,steps=s,historical_reads=a,
                merges=m,boundary_hashes=c,old_write=2*d*n,new_write=m+c,
                old_total=d*a+2*d*n,new_total=d*a+m+c,seconds=round(perf_counter()-t,3))

def rejects(fn):
    try: fn()
    except (ValueError,TypeError): return
    raise AssertionError('forgery accepted')

def test():
    rng=Random(23); checked=0
    for d in range(1,11):
        f=Frontier.empty(d); ref=Reference(d)
        need(f.root()[0]==ref.root())
        while f.n<1<<d:
            k=min(rng.randint(1,31),(1<<d)-f.n)
            xs=[sha256(rng.randbytes(32)).digest() for _ in range(k)]
            out,_=f.append(xs)
            for x in xs: ref.append(x)
            transition(f,f.root()[0],xs,out,ref.root()); f=out; checked+=1
        rejects(lambda:f.append([bytes(32)]))
    f=Frontier.empty(5); xs=[sha256(bytes([i])).digest() for i in range(5)]
    f,_=f.append(xs[:3]); out,_=f.append(xs[3:]); root=out.root()[0]
    bad=bytes(32); slots=list(f.slots); slots[2]=bad
    attacks=[lambda:transition(f,bad,xs[3:],out,root),
             lambda:transition(f,f.root()[0],xs[3:],out,bad),
             lambda:transition(f,f.root()[0],xs[3:][::-1],out,root),
             lambda:transition(f,f.root()[0],xs[3:],f,root),
             lambda:Frontier(5,f.n,tuple(slots)).root(),
             lambda:Frontier(5,33,f.slots).root(),
             lambda:Frontier(5,-1,f.slots).root(),
             lambda:f.append([EMPTY]),lambda:f.append([b'bad']),lambda:f.append([]),
             lambda:auth(5,root,out.n,out.n,bad,[bad]*5),
             lambda:auth(5,root,out.n,0,bad,[bad]*5)]
    for fn in attacks: rejects(fn)
    return dict(random_transitions=checked,full_capacity_rejections=10,targeted_rejections=len(attacks))

if __name__=='__main__':
    print(json.dumps(test()),flush=True)
    n=int(sys.argv[1]) if len(sys.argv)>1 else 100000
    for scatter in (False,True):
        for b in (16,64,256): print(json.dumps(bench(n,b,scatter)),flush=True)
