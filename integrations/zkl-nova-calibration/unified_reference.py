"""Compile ZKL-18 public source examples to explicit unified proof rows.
Native replay uses direct recursive semantics independently of the R1CS.
"""
import json
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'zkl18'))
import typing_reference as tr

# Lift, Sub, Eq, WF, Lookup, Ty. Public arena: sorts/vars/Pi/Lam/App/empty/extend.
ARITY = (0,0,0,2,2,2,0,0,0,0,3,3,2,0,1,2,1,2,2,2,0,2,1,2,1,2,2,2,2,2,3,3)
def kind(op): return 0 if op<6 else 1 if op<13 else 2 if op<20 else 3 if op<22 else 4 if op<24 else 5

class Build:
    def __init__(self):
        self.arena=[]; self.ids={}; self.rows=[]; self.memo={}
        self.term(tr.sort(0)); self.ctx(())
    def intern(self,key,node):
        if key not in self.ids:
            self.ids[key]=len(self.arena); self.arena.append(node)
        return self.ids[key]
    def term(self,t):
        key=('t',t)
        if key in self.ids: return self.ids[key]
        tag=t[0]; a,b=(t[1],0) if tag<2 else (self.term(t[1]),self.term(t[2]))
        return self.intern(key,[tag,a,b])
    def ctx(self,c):
        key=('c',c)
        if key in self.ids: return self.ids[key]
        return self.intern(key,[5,0,0] if not c else [6,self.ctx(c[1:]),self.term(c[0])])
    def emit(self,op,a,b,c,d,refs=(),extra=()):
        payload=(kind(op),a,b,c,d)
        if payload in self.memo: return self.memo[payload]
        assert len(refs)==ARITY[op] and len(extra)<=4
        self.memo[payload]=len(self.rows); self.rows.append([op,a,b,c,d,list(refs),list(extra)+[0]*(4-len(extra))]);return len(self.rows)-1
    def lift(self,t,k=0):
        op=t[0]; u=tr.lift(t,1,k);a,d=self.term(t),self.term(u)
        if (0,a,k,0,d) in self.memo: return self.memo[(0,a,k,0,d)]
        if op==tr.VAR: code,refs=(0 if t[1]<k else 1),()
        elif op==tr.SORT: code,refs=2,()
        else: code,refs=op+1,(self.lift(t[1],k),self.lift(t[2],k+int(op in (2,3))))
        return self.emit(code,a,k,0,d,refs)
    def sub(self,t,k,s):
        op=t[0];u=tr.sub(t,s,k);a,d,c=self.term(t),self.term(u),self.term(s)
        if (1,a,k,c,d) in self.memo: return self.memo[(1,a,k,c,d)]
        if op==tr.VAR: code,refs=(6 if t[1]<k else 7 if t[1]==k else 8),()
        elif op==tr.SORT: code,refs=9,()
        elif op in (2,3): code,refs=op+8,(self.sub(t[1],k,s),self.lift(s),self.sub(t[2],k+1,tr.lift(s)))
        else: code,refs=12,(self.sub(t[1],k,s),self.sub(t[2],k,s))
        return self.emit(code,a,k,c,d,refs,(c,))
    def eq(self,t,u):
        a,d=self.term(t),self.term(u)
        if (2,a,0,0,d) in self.memo:return self.memo[(2,a,0,0,d)]
        if t==u:return self.emit(13,a,0,0,d)
        # Produce explicit beta then congruence. Fixtures only need this restricted normalizer.
        if t[0]==4 and t[1][0]==3:
            reduced=tr.sub(t[1][2],t[2]); rid=self.emit(16,a,0,0,self.term(reduced),(self.sub(t[1][2],0,t[2]),),(self.term(t[1]),))
            if reduced==u:return rid
            return self.emit(15,a,0,0,d,(rid,self.eq(reduced,u)))
        if t[0]==u[0] and t[0] in (2,3,4):
            return self.emit(t[0]+15,a,0,0,d,(self.eq(t[1],u[1]),self.eq(t[2],u[2])))
        if u[0]==4 and u[1][0]==3:return self.emit(14,a,0,0,d,(self.eq(u,t),))
        raise ValueError('unsupported conversion fixture')
    def look(self,g,i):
        out=tr.lift(g[i],i+1);a,d=self.ctx(g),self.term(out)
        if (4,a,i,0,d) in self.memo:return self.memo[(4,a,i,0,d)]
        if i==0:return self.emit(22,a,i,0,d,(self.lift(g[0]),))
        old=tr.lift(g[i],i);return self.emit(23,a,i,0,d,(self.look(g[1:],i-1),self.lift(old)))
    def compile(self,case,keep_prefix=False):
        prefix=len(self.rows)
        terms=[]
        for tag,a,b in case['terms']:terms.append((tag,a) if tag<2 else (tag,terms[a],terms[b]))
        contexts=[()]
        for p,a in case['contexts'][1:]:contexts.append((terms[a],*contexts[p]))
        prior=[]
        for w in case['steps']:
            op,g,t,a,e,u,v=case['descriptors'][w['rule']];c=contexts[g];t0,a0,u0,v0=map(terms.__getitem__,(t,a,u,v));refs=tuple(prior[i] for i in w['refs'])
            G,T,A,E,U,V=self.ctx(c),self.term(t0),self.term(a0),self.ctx(contexts[e]),self.term(u0),self.term(v0)
            if op==0:r=self.emit(20,G,0,0,0)
            elif op==1:r=self.emit(21,G,0,0,0,refs,(0,0,U))
            elif op==2:r=self.emit(24,G,T,0,A,refs,(T,))
            elif op==3:r=self.emit(25,G,T,0,A,(*refs,self.look(c,t0[1])),(T,))
            elif op==4:
                code=26 if v0[1]==0 else 27 if u0[1]>=v0[1] else 28
                r=self.emit(code,G,T,0,A,refs,(T,E,U,V))
            elif op==5:r=self.emit(29,G,T,0,A,refs,(T,E,U))
            elif op==6:r=self.emit(30,G,T,0,A,(*refs,self.sub(u0[2],0,t0[2])),(T,U))
            elif op==7:r=self.emit(31,G,T,0,A,(*refs,self.eq(u0,a0)),(T,0,V))
            else:raise ValueError(op)
            prior.append(r)
        root=prior[-1];reachable=set()
        def visit(i):
            if i in reachable:return
            reachable.add(i)
            for p in self.rows[i][5]:visit(p)
        visit(root)
        if keep_prefix:
            for i in range(prefix):visit(i)
        rows=[];positions={}
        for i in sorted(reachable):
            row=list(self.rows[i]);row[5]=[positions[p] for p in row[5]];positions[i]=len(rows);rows.append(row)
        return {'name':case['name'],'arena':self.arena,'rows':rows,'goal':[rows[-1][2],rows[-1][4]]}

# Independent semantic replay of each row, including exact predecessor signatures.
def replay(case):
    arena=case['arena'];objects=[];seen=set()
    for i,(tag,a,b) in enumerate(arena):
        assert (tag,a,b) not in seen;seen.add((tag,a,b))
        if tag<2:assert b==0 and 0<=a<=65535;obj=(tag,a)
        elif tag<5:assert a<i and b<i and arena[a][0]<5 and arena[b][0]<5;obj=(tag,objects[a],objects[b])
        elif tag==5:assert i==1 and a==b==0;obj=()
        else:assert tag==6 and a<i and b<i and arena[a][0]>=5 and arena[b][0]<5;obj=(objects[b],*objects[a])
        objects.append(obj)
    rows=[]
    def oid(t,ctx=False):return next(i for i,x in enumerate(objects) if x==t and (arena[i][0]>=5)==ctx)
    def lf(t,k,u):return (0,oid(t),k,0,oid(u))
    def sb(t,k,s,u):return (1,oid(t),k,oid(s),oid(u))
    def eq(t,u):return (2,oid(t),0,0,oid(u))
    def wf(g):return (3,oid(g,True),0,0,0)
    def lk(g,i,a):return (4,oid(g,True),i,0,oid(a))
    def ty(g,t,a):return (5,oid(g,True),oid(t),0,oid(a))
    for op,a,b,c,d,refs,extra in case['rows']:
        assert 0<=op<32 and len(refs)==ARITY[op] and len(extra)==4 and all(0<=p<len(rows) for p in refs)
        A,D=objects[a],objects[d];X,Y,U,V=map(objects.__getitem__,extra);k=kind(op);want=[]
        if k==0:
            assert c==0 and D==tr.lift(A,1,b)
            if op==0:assert A[0]==1 and A[1]<b
            elif op==1:assert A[0]==1 and A[1]>=b
            elif op==2:assert A[0]==0
            else:assert A[0]==op-1;want=[lf(A[1],b,D[1]),lf(A[2],b+int(op!=5),D[2])]
        elif k==1:
            S=objects[c];assert X==S and D==tr.sub(A,S,b)
            if op in (6,7,8):assert A[0]==1 and (A[1]<b if op==6 else A[1]==b if op==7 else A[1]>b)
            elif op==9:assert A[0]==0
            elif op in (10,11):assert A[0]==op-8;Z=tr.lift(S);want=[sb(A[1],b,S,D[1]),lf(S,0,Z),sb(A[2],b+1,Z,D[2])]
            else:assert A[0]==4;want=[sb(A[1],b,S,D[1]),sb(A[2],b,S,D[2])]
        elif k==2:
            assert b==c==0
            if op==13:assert a==d
            elif op==14:want=[eq(D,A)]
            elif op==15:mid=objects[rows[refs[0]][4]];want=[eq(A,mid),eq(mid,D)]
            elif op==16:assert A[0]==4 and A[1][0]==3 and X==A[1];want=[sb(A[1][2],0,A[2],D)]
            else:assert A[0]==D[0]==op-15;want=[eq(A[1],D[1]),eq(A[2],D[2])]
        elif k==3:
            assert b==c==d==0
            if op==20:assert A==()
            else:assert A and U[0]==0;want=[wf(A[1:]),ty(A[1:],A[0],U)]
        elif k==4:
            assert c==0 and D==tr.lift(A[b],b+1)
            if op==22:assert b==0;want=[lf(A[0],0,D)]
            else:assert b>0;old=tr.lift(A[b],b);want=[lk(A[1:],b-1,old),lf(old,0,D)]
        else:
            T=objects[b];assert X==T and c==0
            if op==24:assert T[0]==0 and D==tr.sort(T[1]+1);want=[wf(A)]
            elif op==25:assert T[0]==1;want=[wf(A),lk(A,T[1],D)]
            elif op in (26,27,28):
                assert T[0]==2 and Y==(T[1],*A) and D==tr.sort(tr.imax(tr.level(U),tr.level(V)))
                assert (V[1]==0 if op==26 else V[1]>0 and (U[1]>=V[1] if op==27 else V[1]>=U[1]));want=[ty(A,T[1],U),ty(Y,T[2],V)]
            elif op==29:assert T[0]==3 and D[0]==2 and T[1]==D[1] and Y==(T[1],*A) and U[0]==0;want=[ty(A,D,U),ty(Y,T[2],D[2])]
            elif op==30:assert T[0]==4 and Y[0]==2;want=[ty(A,T[1],Y),ty(A,T[2],Y[1]),sb(Y[2],0,T[2],D)]
            else:old=objects[rows[refs[0]][4]];assert U[0]==0;want=[ty(A,T,old),ty(A,D,U),eq(old,D)]
        assert [rows[i] for i in refs]==want,(op,refs,want,[rows[i] for i in refs])
        rows.append((k,a,b,c,d))
    assert rows[-1]==(5,1,case['goal'][0],0,case['goal'][1]);return len(rows)

def main():
    cases=[Build().compile(c) for c in tr.fixtures()]
    b=Build();S=tr.sort(0);v=tr.var(0); redex=tr.app(tr.lam(S,v),S)
    b.lift(tr.lam(S,tr.var(1)));b.sub(v,1,S);b.sub(tr.pi(v,tr.var(1)),0,S);b.sub(tr.lam(v,tr.var(1)),0,S)
    b.eq(tr.lam(S,redex),tr.lam(S,S));b.eq(tr.app(v,redex),tr.app(v,S))
    # Explicit transitive beta chain, with distinct intermediate terms.
    t=tr.app(tr.lam(S,v),redex);p=b.eq(t,redex);q=b.eq(redex,S)
    b.emit(15,b.term(t),0,0,b.term(S),(p,q))
    extra=tr.fixtures()[0];extra['name']='operation_coverage';cases.append(b.compile(extra,keep_prefix=True))
    for c in cases: print(c['name'],len(c['arena']),replay(c))
    print('coverage',sorted(set(r[0] for c in cases for r in c['rows'])))
    out=Path(__file__).with_name('unified-fixtures.json');out.write_text(json.dumps({'schema':'zkl-unified-v1','cases':cases},sort_keys=True,separators=(',',':'))+'\n')
if __name__=='__main__': main()
