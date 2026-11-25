"""Fresh public typed-family capacity study; native equation checks only."""
import json
import random
from pathlib import Path
from unified_reference import Build, replay, tr
from unified_audit import check

P=('s',0);T=('s',1)
def lam(n,a,b):return ('l',n,a,b)
def pi(n,a,b):return ('p',n,a,b)
def app(f,x):return ('a',f,x)
def wrap(tag,binders,body):
    for name,ty in reversed(binders):body=tag(name,ty,body)
    return body

def generate(seed,family):
    rng=random.Random(seed);n=rng.randint(1,8)
    if family in ('weakening','conversion'):
        j=rng.randrange(n);params=[(f'A{i}',P) for i in range(n)]+[(f'x{i}',f'A{i}') for i in range(n)]
        term=wrap(lam,params,f'x{j}')
        goal=None
        if family=='conversion':
            redex=app(lam('Z',P,'Z'),f'A{j}')
            goal=wrap(pi,params,redex)
    else:
        j=rng.randrange(n);args=[(f'y{i}','A') for i in range(n)]
        fty=wrap(pi,args,app('B',f'y{j}'))
        params=[('A',T),('B',pi('z','A',T)),('f',fty)]+[(f'x{i}','A') for i in range(n)]
        body='f'
        for i in range(n):body=app(body,f'x{i}')
        term=wrap(lam,params,body);goal=None
    return tr.Builder().build(str(seed),tr.named(term),tr.named(goal) if goal else None)

def main():
    out={}
    for fi,family in enumerate(('weakening','dependent_app','conversion')):
        stats=dict(cases=64,hybrid_rows=0,unified_rows=0,objects=0,max_rows=0,max_objects=0,fit64=0,fit128=0,fit256=0)
        for seed in range(22000+fi*1000,22064+fi*1000):
            old=generate(seed,family);c=Build().compile(old)
            assert replay(c)==len(c['rows'])
            for i,r in enumerate(c['rows']):assert check(c,i,r),(family,seed,i)
            n=len(c['rows']);o=len(c['arena']);stats['hybrid_rows']+=len(old['steps']);stats['unified_rows']+=n;stats['objects']+=o
            stats['max_rows']=max(stats['max_rows'],n);stats['max_objects']=max(stats['max_objects'],o)
            for cap in (64,128,256):stats[f'fit{cap}']+=int(max(n,o)<=cap)
        out[family]=stats
    print(json.dumps(out,indent=2))
    Path(__file__).with_name('scaling-results.json').write_text(json.dumps(out,indent=2)+'\n')
if __name__=='__main__':main()
