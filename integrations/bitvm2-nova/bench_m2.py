"""Generate bounded, streaming fixtures; no Nova proving or Bitcoin RPC calls."""
from collections import Counter
from hashlib import sha256
from pathlib import Path
import json
import platform
import random
import resource
import time
from script import P, Q, execute, num
from ipa_algebra import PALLAS, VESTA
from trace import multiplication_trace, change_field
from curve_trace import point_add_trace, EncodedPoint

OUT=Path(__file__).resolve().parent/'results'


def point_json(p):
    p=EncodedPoint.of(p)
    return {'infinity':p.infinity,'x_le':p.x.to_bytes(32,'little').hex(),
            'y_le':p.y.to_bytes(32,'little').hex()}


def curve_vectors():
    rows=[]
    rng=random.Random(20261105)
    for c in (PALLAS,VESTA):
        g=(c.p-1,2)
        pairs=[(None,None),(None,g),(g,None),(g,(g[0],c.p-2)),(g,g),(g,c.mul(g,2))]
        pairs.extend((c.mul(g,rng.randrange(1,c.q)),c.mul(g,rng.randrange(1,c.q))) for _ in range(24))
        for i,(a,b) in enumerate(pairs):
            result=c.add(a,b)
            rows.append(dict(name=f'{c.name}/valid/{i}',curve=c.name,left=point_json(a),
                             right=point_json(b),result=point_json(result),expected_success=True))
        for i,(a,b,r) in enumerate([(g,g,g),((1,1),g,g),(g,(1,1),g),(g,g,(1,1)),
                                    (EncodedPoint(1,1,0),g,g),(g,g,EncodedPoint(1,0,1)),
                                    (EncodedPoint(0,c.p,2),g,g)]):
            rows.append(dict(name=f'{c.name}/invalid/{i}',curve=c.name,left=point_json(a),
                             right=point_json(b),result=point_json(r),expected_success=False))
    return rows


def main():
    OUT.mkdir(exist_ok=True)
    start=time.perf_counter();count=0;negative=0;cases=[]
    path=OUT/'m2-engine-vectors.jsonl'
    with path.open('w') as out:
        def emit(bound,index,disprove,expected,name,override=None):
            nonlocal count,negative
            ws=bound.witness(index) if override is None else override
            row={'name':name,'script_hex':bound.script(index,disprove=disprove).hex(),
                 'witness_hex':[w.hex() for w in ws],'expected_success':expected}
            out.write(json.dumps(row,separators=(',',':'))+'\n')
            count+=1;negative+=int(not expected)

        for c in (PALLAS,VESTA):
            for typ in ('multiplication','point-add'):
                if typ=='multiplication':
                    p,v=multiplication_trace(c.name+'_base',c.p-19,c.p-73,
                        context=sha256(b'M2-benchmark').digest(),operation_id='benchmark/mul')
                else:
                    g=(c.p-1,2)
                    p,v=point_add_trace(c,g,c.mul(g,2),context=sha256(b'M2-benchmark').digest(),
                                       operation_id='benchmark/point')
                bound=p.bind(v)
                if bound.failures():raise AssertionError('honest fixture failed native constraints')
                shapes=Counter((cn.kind,cn.argument) for cn in p.constraints)
                seen=set();metrics=[]
                for i,cn in enumerate(p.constraints):
                    emit(bound,i,False,True,f'{c.name}/{typ}/correct/{i}')
                    key=(cn.kind,cn.argument)
                    if key in seen:continue
                    seen.add(key)
                    code=bound.script(i,disprove=False)
                    rr=execute(code,bound.witness(i))
                    if not rr.success:raise AssertionError((c.name,typ,i,rr))
                    metrics.append({'kind':cn.kind,'argument':cn.argument,'count':shapes[key],
                                    'correctness_script_bytes':len(code),
                                    'disproof_script_bytes':len(bound.script(i)),
                                    'witness_items':len(bound.witness(i)),
                                    'witness_payload_bytes':sum(map(len,bound.witness(i))),
                                    'reference_peak_stack_items':rr.peak_stack,
                                    'reference_executed_instructions':rr.op_count})
                    emit(bound,i,True,False,f'{c.name}/{typ}/honest-disproof/{i}')
                    wrong=list(bound.witness(i));wrong[0]=num(17) if wrong[0]!=num(17) else num(18)
                    emit(bound,i,True,False,f'{c.name}/{typ}/changed-opening/{i}',wrong)
                    emit(bound,i,True,False,f'{c.name}/{typ}/truncated/{i}',list(bound.witness(i))[:-1])
                if typ=='multiplication':
                    altered=[change_field(p,v,name,1) for name in
                             ('product/acc/0','product/acc/1','product/acc/128','product/acc/255','product')]
                    for bit in (0,28,29,231,232,254):
                        x=dict(v);x[f'product/bit/{bit}']^=1;altered.append(x)
                else:
                    altered=[]
                    for field in ('slope','left/y2','result/x','result/y','ordinary-slope','y-equation'):
                        ws=dict(p.fields)[field];old=sum(v[w]<<(29*j) for j,w in enumerate(ws))
                        altered.append(change_field(p,v,field,(old+1)%c.p))
                    for selector in (0,1,2,3):
                        x=dict(v);x['dispatch']=selector;altered.append(x)
                for j,changed in enumerate(altered):
                    bad=p.bind(changed)
                    for i in bad.failures():
                        emit(bad,i,True,True,f'{c.name}/{typ}/false-claim/{j}/{i}')
                        emit(bad,i,False,False,f'{c.name}/{typ}/false-correctness/{j}/{i}')
                cases.append({**bound.manifest(),'case':typ,'primitive_metrics':metrics,
                    'all_disproof_scripts_bytes':sum(r['count']*r['disproof_script_bytes'] for r in metrics),
                    'full_point_graph':typ=='point-add'})
            # Independently exercise the dispatch/geometry leaves for every edge case.
            g=(c.p-1,2)
            for j,(a,b,r) in enumerate([(None,g,g),(g,None,g),(None,None,None),(g,g,c.mul(g,2)),
                                       (g,(g[0],c.p-2),None),((1,1),g,g),
                                       (EncodedPoint(1,1,0),g,g),(g,g,(1,1))]):
                p,v=point_add_trace(c,a,b,claimed_output=r)
                bound=p.bind(v)
                for i,cn in enumerate(p.constraints):
                    if cn.kind not in ('point_form','dispatch','gate_equal','gate_small_equal','gate_nonzero'):continue
                    good=cn.native(bound.values,p.p)
                    emit(bound,i,False,good,f'{c.name}/edge/{j}/correct/{i}')
                    emit(bound,i,True,not good,f'{c.name}/edge/{j}/disproof/{i}')
    curves=curve_vectors()
    (OUT/'m2-curve-vectors.json').write_text(json.dumps(curves,indent=2)+'\n')
    h=sha256()
    with path.open('rb') as f:
        for block in iter(lambda:f.read(1024*1024),b''):h.update(block)
    rss=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    report={'schema':'bitvm2-nova-m2-evidence/v1','scope':'fixed-claim arithmetic and point trace',
            'python':platform.python_version(),'platform':platform.platform(),
            'script_vectors':count,'expected_script_rejections':negative,'curve_vectors':len(curves),
            'engine_fixture_bytes':path.stat().st_size,'engine_fixture_sha256':h.hexdigest(),
            'generation_seconds':time.perf_counter()-start,
            'python_peak_rss_bytes':rss if platform.system()=='Darwin' else rss*1024,
            'cases':cases,'trusted_setup':False,'production_transcript':False,
            'dynamic_bitvm2_assertions':False,'nova_proofs_verified':0,'transactions_broadcast':0}
    (OUT/'m2-bench.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:v for k,v in report.items() if k!='cases'},indent=2))


if __name__=='__main__':main()
