"""Differential check of all static linear conditions and coherent mutations."""
import json
from pathlib import Path
from unified_reference import replay,kind
from rule_spec import make,linear
D=Path(__file__).parent
rules=json.loads((D/'unified-rules.json').read_text());batch=json.loads((D/'unified-fixtures.json').read_text())
assert rules==[dict(kind=s['kind'],arity=s['arity'],conditions=[linear(e) for e in s['conditions']]) for s in make()]

def check(c,i,row):
    op,a,b,s,d,refs,extra=row
    if not (0<=op<32 and 0<=b<=65535 and len(refs)==rules[op]['arity'] and all(0<=r<i for r in refs)):return False
    arena=c['arena'];payload=lambda row:[kind(row[0]),*row[1:5]]
    values=payload(row);nodes=[arena[j] for j in [a,d,*extra]]
    for j,n in zip([a,d,*extra],nodes,strict=True):values.extend([j,*n,int(n[0]<5)])
    for j in range(3):values.extend(payload(c['rows'][refs[j]]) if j<len(refs) else [0]*5)
    v=nodes[5][1];u=nodes[4][1];idx=nodes[0][1]
    gap=max(0,b-idx-1) if op in (0,6) else max(0,idx-b-int(op==8)) if op in (1,8) else max(0,u-v) if op==27 else max(0,v-u) if op==28 else 0
    values.extend([b+1,b-1,gap,max(0,v-1)])
    return all(k+sum(coef*values[j] for coef,j in eq)==0 for k,eq in rules[op]['conditions'])

count=0;bad=0;trials=0;coverage=set()
for c in batch['cases']:
    assert replay(c)==len(c['rows'])
    for i,r in enumerate(c['rows']):
        assert check(c,i,r),(c['name'],i,r)
        coverage.add(r[0]);count+=1
        # Coherent replacement of a preceding proof with one carrying another signature.
        for j,ref in enumerate(r[5]):
            for other in range(i):
                if c['rows'][other][1:5]==c['rows'][ref][1:5] and kind(c['rows'][other][0])==kind(c['rows'][ref][0]):continue
                m=list(r);m[5]=list(r[5]);m[5][j]=other;trials+=1
                assert not check(c,i,m),(c['name'],i,j,ref,other);bad+=1
assert coverage==set(range(32))
print(json.dumps(dict(cases=len(batch['cases']),rows=count,rules=len(coverage),coherent_wrong_premises=bad,attempts=trials)))
