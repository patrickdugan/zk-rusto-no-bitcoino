"""ZKL-NOVA-01 native authenticated implicational proof trace, no SNARK."""
from hashlib import sha256
from dataclasses import dataclass
from time import perf_counter
import json
import random

D = 17
EMPTY = sha256(b'ZKL01/empty').digest()

def h(left, right):
    return sha256(b'ZKL01/node' + left + right).digest()

def leaf(i, row, salt):
    return sha256(b'ZKL01/row' + i.to_bytes(8, 'big') + bytes([len(row)]) +
                  b''.join(x.to_bytes(8, 'big') for x in row) + salt).digest()

# Type: ATOM(label), ARR(domain,codomain); context: NIL, EXT(parent,type);
# lookup: HERE(ctx,type), THERE(ctx,type,prior_lookup);
# judgment: VAR(ctx,type,lookup), LAM(ctx,type,body), APP(ctx,type,fn,arg).
ATOM, ARR, NIL, EXT, HERE, THERE, VAR, LAM, APP = range(9)
ARITIES = (2, 3, 1, 3, 3, 4, 4, 4, 5)

def need(x):
    if not x:
        raise ValueError('invalid transition')

def shape(row):
    need(type(row) is tuple and len(row)>0 and all(type(x) is int and 0<=x<2**64 for x in row))
    need(row[0]<len(ARITIES) and len(row)==ARITIES[row[0]])

def refs(r):
    shape(r)
    return () if r[0] in (ATOM, NIL) else r[1:]

def semantic(r, get):
    shape(r)
    def ty(i):
        q=get(i); need(q[0] in (ATOM, ARR)); return q
    def ctx(i):
        q=get(i); need(q[0] in (NIL, EXT)); return q
    def lookup(i):
        q=get(i); need(q[0] in (HERE, THERE)); return q
    def jud(i):
        q=get(i); need(q[0] in (VAR,LAM,APP)); return q
    k,*a=r
    if k in (ATOM,NIL): return
    if k==ARR:
        ty(a[0]); ty(a[1]); return
    if k==EXT:
        ctx(a[0]); ty(a[1]); return
    if k==HERE:
        c=ctx(a[0]); ty(a[1]); need(c[0]==EXT and c[2]==a[1]); return
    if k==THERE:
        c=ctx(a[0]); ty(a[1]); q=lookup(a[2]); need(c[0]==EXT and q[1:3]==(c[1],a[1])); return
    c,t=a[:2]; ctx(c); T=ty(t)
    if k==VAR:
        q=lookup(a[2]); need(q[1:3]==(c,t))
    elif k==LAM:
        b=jud(a[2]); bc=ctx(b[1]); need(T[0]==ARR and bc==(EXT,c,T[1]) and b[2]==T[2])
    elif k==APP:
        f=jud(a[2]); x=jud(a[3]); ft=ty(f[2]); need(f[1]==c and x[1]==c and ft==(ARR,x[2],t))

class Tree:
    def __init__(self):
        self.zeros=[EMPTY]
        for _ in range(D): self.zeros.append(h(self.zeros[-1],self.zeros[-1]))
        self.nodes={}
    def get(self,l,i): return self.nodes.get((l,i),self.zeros[l])
    @property
    def root(self): return self.get(D,0)
    def path(self,i): return tuple(self.get(l,(i>>l)^1) for l in range(D))
    def write(self,i,v):
        self.nodes[0,i]=v
        for l in range(D):
            j=i>>l
            self.nodes[l+1,j>>1]=h(self.get(l,j&~1),self.get(l,j|1))

def ascend(i,v,path):
    need(type(i) is int and 0<=i<2**D and len(path)==D and all(type(p) is bytes and len(p)==32 for p in path))
    for l,p in enumerate(path): v=h(p,v) if (i>>l)&1 else h(v,p)
    return v

def salt(i):
    # Deterministic fixture only. Real witnesses require fresh random salts.
    return sha256(b'fixture'+i.to_bytes(8,'big')).digest()

@dataclass(frozen=True)
class State:
    root: bytes
    n: int
    goal: int
    empty_ctx: int
    env: bytes

def append(state,r,s,path):
    need(type(s) is bytes and len(s)==32 and state.n<2**D)
    need(ascend(state.n,EMPTY,path)==state.root)
    return State(ascend(state.n,leaf(state.n,r,s),path),state.n+1,state.goal,state.empty_ctx,state.env)

def batch(state, witnesses, openings):
    """Authenticate external reads against initial root; use local batch rows otherwise."""
    before=state; cache={}; local={}; used=set()
    for r,s,path in witnesses:
        def get(i):
            need(type(i) is int and 0<=i<state.n)
            if i>=before.n: return local[i]
            used.add(i)
            if i not in cache:
                need(i in openings); q,qs,qp=openings[i]; shape(q)
                need(type(qs) is bytes and len(qs)==32 and ascend(i,leaf(i,q,qs),qp)==before.root)
                cache[i]=q
            return cache[i]
        for i in refs(r): get(i)
        semantic(r,get)
        local[state.n]=r
        state=append(state,r,s,path)
    need(used==set(openings))
    return state,len(used)

GENESIS=((ATOM,0),(ARR,0,0),(ARR,1,1),(NIL,))

def genesis(goal=1):
    t=Tree()
    for i,r in enumerate(GENESIS): t.write(i,leaf(i,r,salt(i)))
    need(goal in (0,1,2))
    return State(t.root,len(GENESIS),goal,3,sha256(b'ZKL01/genesis'+t.root+goal.to_bytes(8,'big')).digest()),t

def finish(st,row,s,path):
    shape(row); need(type(s) is bytes and len(s)==32 and st.n>len(GENESIS))
    need(ascend(st.n-1,leaf(st.n-1,row,s),path)==st.root)
    need(row[0] in (VAR,LAM,APP) and row[1]==st.empty_ctx and row[2]==st.goal)

def trace(n, workload="chain"):
    base=[(EXT,3,0),(HERE,4,0),(VAR,4,0,5),(LAM,3,1,6),
          (EXT,3,1),(HERE,8,1),(VAR,8,1,9),(LAM,3,2,10)]
    need(n>=len(base)); rng=random.Random(20261125)
    for i in range(12,n+4):
        a=(i-1 if i>12 else 7) if workload=="chain" else (rng.randrange(12,i) if i>12 and rng.randrange(2)==1 else 7)
        base.append((APP,3,1,11,a))
    return base

class Builder:
    def __init__(self,goal=1): self.state,self.tree=genesis(goal); self.rows=list(GENESIS)
    def prepare(self,rows):
        openings={}; witnesses=[]; allreads=0; seen=set(); start=len(self.rows)
        for j,r in enumerate(rows,start):
            this=set()
            def get(i):
                need(0<=i<j); this.add(i); return self.rows[i] if i<start else rows[i-start]
            for i in refs(r): get(i)
            semantic(r,get); allreads+=len(this)
            seen.update(i for i in this if i<start)
        for i in sorted(seen): openings[i]=(self.rows[i],salt(i),self.tree.path(i))
        for r in rows:
            i=len(self.rows); s=salt(i); p=self.tree.path(i); witnesses.append((r,s,p))
            self.tree.write(i,leaf(i,r,s)); self.rows.append(r)
        return witnesses,openings,allreads
    def apply(self,rows):
        w,o,a=self.prepare(rows); self.state,b=batch(self.state,w,o); need(self.tree.root==self.state.root); return a,b
    def close(self):
        i=len(self.rows)-1; finish(self.state,self.rows[i],salt(i),self.tree.path(i))

def bench(n,b,workload="chain"):
    t0=perf_counter(); builder=Builder(); rows=trace(n,workload); a=c=0
    for k in range(0,n,b):
        x,y=builder.apply(rows[k:k+b]); a+=x; c+=y
    builder.close()
    return dict(workload=workload,rows=n,batch=b,reads_naive=a,reads_batched=c,append_paths=n,
                hash_nodes_naive=D*(a+2*n),hash_nodes_batched=D*(c+2*n),
                seconds=round(perf_counter()-t0,3))

def rejects(fn):
    try: fn()
    except (ValueError,KeyError): return
    raise AssertionError('accepted forgery')

def selftest():
    b=Builder(); b.apply(trace(24)); b.close()
    # Genuine weakening lookup and use in a larger context.
    b=Builder(); b.apply(trace(8)); b.apply([(EXT,4,1),(THERE,12,0,5),(VAR,12,0,13)])
    b=Builder(); b.apply(trace(8)); pre=b.state
    w,o,_=b.prepare([(APP,3,1,11,7)])
    st,_=batch(pre,w,o); finish(st,b.rows[-1],salt(12),b.tree.path(12))
    r,s,p=w[0]; q,qs,qp=o[7]
    direct=lambda row:semantic(row,lambda i:b.rows[i])
    attacks=[lambda:direct((APP,3,1,7,7)), # wrong function type
             lambda:direct((APP,4,1,11,7)), # wrong context
             lambda:direct((APP,3,0,11,7)), # wrong result type
             lambda:direct((VAR,4,1,5)), # wrong lookup type
             lambda:direct((LAM,3,2,6)), # wrong binder type
             lambda:direct((THERE,4,0,5)), # wrong parent lookup
             lambda:batch(pre,[((APP,3,1,11,12),s,p)],o), # self reference
             lambda:batch(pre,w,{**o,7:((LAM,3,2,6),qs,qp)}), # forged old row
             lambda:batch(pre,w,{**o,7:(q,bytes(32),qp)}), # forged salt
             lambda:batch(pre,w,{k:v for k,v in o.items() if k!=7}), # missing opening
             lambda:batch(pre,[(r,s,(bytes(32),)+p[1:])],o), # bad append proof
             lambda:batch(st,w,o), # replay at wrong position/root
             lambda:finish(State(st.root,st.n,0,st.empty_ctx,st.env),r,s,b.tree.path(12)), # wrong goal
             lambda:finish(st,(APP,3,1,11,11),s,b.tree.path(12))] # wrong terminal row
    for attack in attacks: rejects(attack)
    return len(attacks)

if __name__=='__main__':
    print(json.dumps({'forgeries_rejected':selftest()}),flush=True)
    for workload in ("chain","scatter"):
        for n in (1000,10000,100000):
            for b in (16,64,256):
                print(json.dumps(bench(n,b,workload)),flush=True)
