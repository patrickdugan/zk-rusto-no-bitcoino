"""ZKL-21: public structurally checked binary jumps for raw context lookup."""
import argparse
import copy
import json
from pathlib import Path

import bulk_reference as bulk
from scaling import generate

D = Path(__file__).resolve().parent


def kind(op):
    return 4 if op == 32 else bulk.kind(op)


def payload(row):
    return [kind(row[0]), *row[1:5]]


def ancestor(arena, ctx, distance):
    for _ in range(distance):
        if arena[ctx][0] != 6:
            raise ValueError('jump beyond context')
        ctx = arena[ctx][1]
    return ctx


def structural(arena):
    if len(arena) < 2 or arena[:2] != [[0, 0, 0], [5, 0, 0]]:
        raise ValueError('canonical initial arena')
    seen = set()
    for i, node in enumerate(arena):
        if len(node) != 3 or any(type(x) is not int or x < 0 for x in node):
            raise ValueError('object fields')
        t, a, b = node
        if tuple(node) in seen:
            raise ValueError('duplicate')
        seen.add(tuple(node))
        if t in (0, 1):
            ok = b == 0 and a <= (7 if t == 0 else 65535)
        elif t in (2, 3, 4):
            ok = a < i and b < i and arena[a][0] < 5 and arena[b][0] < 5
        elif t == 5:
            ok = i == 1 and a == b == 0
        elif t == 6:
            ok = a < i and b < i and arena[a][0] in (5, 6) and arena[b][0] < 5
        elif 8 <= t <= 15:
            ok = (a < i and b < i and arena[a][0] == 6 and arena[b][0] == 6
                  and ancestor(arena, a, 1 << (t-7)) == b)
        else:
            ok = False
        if not ok:
            raise ValueError('invalid arena or jump')


def convert(case):
    """Rewrite a valid bulk certificate; keep shared earlier judgments when needed."""
    bulk.replay(case)
    out = copy.deepcopy(case)
    arena, rows = out['arena'], out['rows']
    seen = {tuple(n): i for i, n in enumerate(arena)}
    # Follow the original chain, even when its rows are rewritten in this pass.
    original = case['rows']
    for i, row in enumerate(rows):
        if row[0] != 23 or row[2] < 2:
            continue
        exp = min(8, row[2].bit_length()-1)
        distance = 1 << exp
        p = i
        for _ in range(distance):
            assert original[p][0] == 23
            p = original[p][5][0]
        target = original[p][1]
        assert original[p][2] == row[2]-distance and original[p][4] == row[4]
        jump = (7+exp, row[1], target)
        if jump not in seen:
            seen[jump] = len(arena)
            arena.append(list(jump))
        row[0] = 32
        row[5] = [p]
        row[6][0] = seen[jump]
    keep = set()
    def visit(i):
        if i not in keep:
            keep.add(i)
            for p in rows[i][5]:
                visit(p)
    # Preserve nonlookup operations, including the sixth coverage fixture.
    for i, row in enumerate(rows):
        if kind(row[0]) != 4:
            visit(i)
    mapping = {i: j for j, i in enumerate(sorted(keep))}
    out['rows'] = [rows[i] for i in sorted(keep)]
    for row in out['rows']:
        row[5] = [mapping[p] for p in row[5]]
    # All original syntax IDs stay fixed; only keep jump metadata actually opened.
    n = len(case['arena'])
    used = sorted({row[6][0] for row in out['rows'] if row[0] == 32})
    jm = {i: n+j for j, i in enumerate(used)}
    out['arena'] = arena[:n] + [arena[i] for i in used]
    for row in out['rows']:
        if row[0] == 32:
            row[6][0] = jm[row[6][0]]
    structural(out['arena'])
    assert len(out['rows']) <= len(case['rows'])
    return out


def expand_replay(case):
    """Expand each checked jump to unit raw lookup rules, then replay the old checker."""
    structural(case['arena'])
    arena = case['arena']
    n = next((i for i,v in enumerate(arena) if v[0] >= 8), len(arena))
    if any(v[0] < 8 for v in arena[n:]):
        raise ValueError('jump metadata must be trailing')
    out = {'name':case['name'], 'arena':arena[:n], 'goal':case['goal'], 'rows':[]}
    pos = []
    for i, row in enumerate(case['rows']):
        op,a,k,s,d,refs,extra = row
        if any(type(p) is not int or not 0 <= p < i for p in refs):
            raise ValueError('forward reference')
        if op == 32:
            if len(refs) != 1 or len(extra) != 4 or s != 0 or not n <= extra[0] < len(arena):
                raise ValueError('jump fields')
            tag,start,target = arena[extra[0]]
            distance = 1 << (tag-7)
            p = refs[0]
            if a != start or not distance <= k <= 65535 or payload(case['rows'][p]) != [4,target,k-distance,0,d]:
                raise ValueError('wrong jump premise')
            chain = [a]
            for _ in range(distance):
                chain.append(arena[chain[-1]][1])
            if chain[-1] != target:
                raise ValueError('wrong ancestor')
            ref = pos[p]
            for j in range(distance-1, -1, -1):
                out['rows'].append([23,chain[j],k-j,0,d,[ref],[0]*4])
                ref = len(out['rows'])-1
        else:
            rr = copy.deepcopy(row)
            rr[5] = [pos[p] for p in refs]
            out['rows'].append(rr)
            ref = len(out['rows'])-1
        pos.append(ref)
    bulk.replay(out)
    return len(case['rows'])


def rules():
    r = json.loads((D/'bulk-rules.json').read_text())
    # 54 existing values; 54=jump distance, 55=is valid jump tag (derived).
    eqs = [[0,[[1,5],[-1,1]]], [0,[[1,10],[-1,4]]], [-1,[[1,14]]], [0,[[1,9]]],
           [0,[[1,3]]], [-6,[[1,6]]], [-1,[[1,55]]], [0,[[1,17],[-1,1]]],
           [-4,[[1,35]]], [0,[[1,36],[-1,18]]], [0,[[1,37],[-1,2],[1,54]]],
           [0,[[1,38]]], [0,[[1,39],[-1,4]]]]
    r.append({'arity':1,'conditions':eqs,'kind':4})
    return r


RULES = rules()


def check(case, i, row):
    op,a,b,s,d,refs,extra = row
    if not (0<=op<33 and 0<=b<=65535 and 0<=s<=65535 and len(refs)==RULES[op]['arity'] and all(0<=r<i for r in refs)):
        return False
    arena=case['arena'];values=payload(row);nodes=[arena[j] for j in [a,d,*extra]]
    for j,n in zip([a,d,*extra],nodes,strict=True):values.extend([j,*n,int(n[0]<5)])
    for j in range(3):values.extend(payload(case['rows'][refs[j]]) if j<len(refs) else [0]*5)
    v=nodes[5][1];u=nodes[4][1];idx=nodes[0][1]
    gap=max(0,b-idx-1) if op in (0,6) else max(0,idx-b-int(op==8)) if op in (1,8) else max(0,u-v) if op==27 else max(0,v-u) if op==28 else 0
    values.extend([b+1,b-1,gap,max(0,v-1)])
    tag=nodes[2][0];is_jump=8<=tag<=15
    values.extend([1<<(tag-7) if is_jump else 0,int(is_jump)])
    assert len(values)==56
    return all(k+sum(coef*values[j] for coef,j in eq)==0 for k,eq in RULES[op]['conditions'])


def audit(case, mutations=False):
    n=expand_replay(case)
    bad=0
    for i,row in enumerate(case['rows']):
        assert check(case,i,row),(case['name'],i,row)
        if mutations:
            for j,p in enumerate(row[5]):
                for q in range(i):
                    if payload(case['rows'][p])==payload(case['rows'][q]):continue
                    r=copy.deepcopy(row);r[5][j]=q
                    assert not check(case,i,r),(case['name'],i,j,p,q)
                    bad+=1
    return n,bad


def main():
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,default=D);a=p.parse_args();a.out.mkdir(parents=True,exist_ok=True)
    fixtures=json.loads((D/'bulk-fixtures.json').read_text())['cases']
    fixed=[convert(c) for c in fixtures]
    stress=bulk.Build().compile(generate(23004,'dependent_app'));stress['name']='dependent-app-23004'
    fixed_stress=convert(stress)
    attacks=0
    for c in [*fixed,fixed_stress]:
        n,bad=audit(c,True);attacks+=bad
    # Structural false jump claims: coherent source/target/exponent mutations.
    structural_negatives=0
    for c in [*fixed,fixed_stress]:
        for i,(tag,src,dst) in enumerate(c['arena']):
            if tag<8:continue
            for node in [[tag,src,src],[tag,src,0],[tag+1,src,dst]]:
                m=copy.deepcopy(c['arena']);m[i]=node
                try:structural(m)
                except ValueError:structural_negatives+=1
                else:raise AssertionError('accepted false jump')
    result={'fixed':[{ 'name':x['name'],'old_rows':len(x['rows']),'new_rows':len(y['rows']),'old_objects':len(x['arena']),'new_objects':len(y['arena'])} for x,y in zip(fixtures,fixed,strict=True)],'stress':{'old_rows':len(stress['rows']),'new_rows':len(fixed_stress['rows']),'old_objects':len(stress['arena']),'new_objects':len(fixed_stress['arena'])},'wrong_premises':attacks,'structural_negatives':structural_negatives,'cohorts':{}}
    for start in (22000,32000,42000):
        cohort={}
        for fi,f in enumerate(('weakening','dependent_app','conversion')):
            st=dict(cases=64,old_rows=0,new_rows=0,old_objects=0,new_objects=0,old_fit64=0,new_fit64=0,old_fit128=0,new_fit128=0,old_fit256=0,new_fit256=0,old_fit512=0,new_fit512=0,better=0,equal=0)
            for seed in range(start+fi*1000,start+fi*1000+64):
                x=bulk.Build().compile(generate(seed,f));y=convert(x);n,_=audit(y)
                for prefix,c in [('old',x),('new',y)]:
                    st[prefix+'_rows']+=len(c['rows']);st[prefix+'_objects']+=len(c['arena'])
                    for cap in (64,128,256,512):st[f'{prefix}_fit{cap}']+=int(max(len(c['rows']),len(c['arena']))<=cap)
                st['better']+=n<len(x['rows']);st['equal']+=n==len(x['rows'])
            cohort[f]=st
        result['cohorts'][str(start)]=cohort
    for name,obj in [('skip-rules.json',RULES),('skip-fixtures.json',{'schema':'zkl-skip-v1','cases':fixed}),('skip-stress.json',{'schema':'zkl-skip-v1','cases':[fixed_stress]}),('skip-results.json',result)]:
        (a.out/name).write_text(json.dumps(obj,sort_keys=True,separators=(',',':'))+'\n')
    print(json.dumps(result,indent=2))

if __name__=='__main__':main()
