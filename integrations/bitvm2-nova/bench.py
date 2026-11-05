#!/usr/bin/env python3
"""Emit measured Script kernels and differential vectors. No proving job is run."""
import argparse
import hashlib
import json
import platform
import sys
import time
from pathlib import Path
from script import P, Q, BASE, kernel, witness, execute, bind_openings, push, num
from ipa_algebra import multiplication_steps


def run(vector_path):
    rows, vectors = [], []
    for name,p in [('pallas_base',P),('vesta_base',Q)]:
        for kind in ('add','mul_bit'):
            code = kernel(p,kind)
            disprove = kernel(p,kind,True)
            bit = 1 if kind=='mul_bit' else None
            x,y = p-2,p-3
            z = (x+y if bit is None else 2*x+y)%p
            ws = witness(x,y,z,bit)
            start=time.perf_counter()
            for _ in range(10):
                result=execute(code,ws)
                if not result.success:
                    raise RuntimeError(result)
            seconds=(time.perf_counter()-start)/10
            context=hashlib.sha256(b'bitvm2-nova-m1/'+name.encode()+b'/'+kind.encode()).digest()
            bound=bind_openings(disprove,ws,context)
            row=dict(field=name,kernel=kind,script_bytes=len(code),
                     fixed_claim_disproof_bytes=len(bound), witness_items=len(ws),
                     witness_payload_bytes=sum(map(len,ws)),
                     reference_peak_stack_items=result.peak_stack,
                     reference_executed_opcodes=result.op_count,
                     reference_seconds_per_run=seconds,script_sha256=hashlib.sha256(code).hexdigest())
            rows.append(row)
            # Valid/invalid output and fixed-claim dispute polarity.
            bad=witness(x,y,(z+1)%p,bit)
            cases=[('valid',code,ws,True),('wrong-output',code,bad,False),
                   ('honest-disproof',bound,ws,False),
                   ('false-claim-disproof',bind_openings(disprove,bad,context),bad,True)]
            changed=list(ws); changed[0]=num((int.from_bytes(ws[0],'little')+1)%(BASE-1))
            cases.append(('altered-opening',bound,changed,False))
            for label,s,w,expected in cases:
                r=execute(s,w)
                if r.success!=expected:
                    raise RuntimeError((name,kind,label,r))
                vectors.append(dict(name=f'{name}/{kind}/{label}',
                    # Upstream's helper begins with an empty stack; push the witness first.
                    script_hex=(b''.join(push(v) for v in w)+s).hex(),expected_success=expected))
    stream=[]
    for name,p in [('pallas_base',P),('vesta_base',Q)]:
        start=time.perf_counter(); count=0
        code=kernel(p,'mul_bit')
        for st in multiplication_steps(p-19,p-73,p):
            r=execute(code,witness(st['accumulator'],st['multiplicand'],st['output'],st['bit']))
            if not r.success: raise RuntimeError(r)
            count+=1
        stream.append(dict(field=name,microsteps=count,result_matches=st['output']==((p-19)*(p-73))%p,
                           reference_wall_seconds=time.perf_counter()-start))
    Path(vector_path).write_text(json.dumps(vectors,indent=2)+'\n')
    report=dict(schema='bitvm2-nova-kernels/v1',status='research-primitive-only',
        python=sys.version,platform=platform.platform(),
        measurement_scope='Python reference interpreter; excludes Rust engine and transaction graph',
        rows=rows,full_field_multiplication_checks=stream,upstream_vectors=len(vectors),
        nova_proofs_verified=0,bitcoin_transactions_broadcast=0,trusted_setup=False)
    return report


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--vectors',default='results/engine-vectors.json')
    p.add_argument('--report',default='results/kernel-bench.json')
    args=p.parse_args()
    for path in (args.vectors,args.report): Path(path).parent.mkdir(parents=True,exist_ok=True)
    report=run(args.vectors)
    Path(args.report).write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))
