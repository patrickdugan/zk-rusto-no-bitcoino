"""Stream bounded global-registry fixtures, without keys or proving jobs."""
from hashlib import sha256
from pathlib import Path
import json
import platform
import time
from script import P, Q, limbs
from trace import multiplication_trace, TraceBuilder
from curve_trace import point_add_trace
from ipa_algebra import PALLAS, VESTA
from wots_graph import GraphSpec, authenticated_shape
import itertools
from bench_compact import peak_rss


def main():
    start = time.perf_counter()
    cases, census = [], []
    for role, p in [('pallas_base', P), ('vesta_base', Q)]:
        pr, values = multiplication_trace(role, p-19, p-73,
            context=sha256(b'global-registry-test').digest(), operation_id='registry/mul')
        spec = GraphSpec.from_program(pr)
        shape = spec.json()
        fields = dict(spec.field_leaves)
        def emit(name, vals, checks=None, measure=False):
            cases.append({'name': f'{role}/{name}', 'spec': shape, 'expected_spec_id': spec.digest().hex(),
                          'words': [vals[w] for w, _ in spec.words], 'checks': checks or [], 'measure_all': measure})
        def field(vals, name, value):
            result = dict(vals)
            for w, v in zip(dict(pr.fields)[name], limbs(value), strict=True):
                result[w] = v
            return result
        def false_checks(*ordinals):
            return [dict(ordinal=i, expected_correct=False) for i in ordinals]
        emit('honest-full-multiplication', values, measure=True)
        old = sum(values[w] << (29*i) for i, w in enumerate(dict(pr.fields)['product/acc/128']))
        emit('broken-middle-link', field(values, 'product/acc/128', (old+1) % p), false_checks(145, 146))
        emit('nonzero-anchor', field(values, 'product/acc/0', 1), false_checks(9, 18))
        old = sum(values[w] << (29*i) for i, w in enumerate(dict(pr.fields)['product']))
        emit('false-final-result', field(values, 'product', (old+1) % p), false_checks(273))
        changed = dict(values); changed['product/bit/127'] ^= 1
        emit('wrong-bound-bit', changed, false_checks(4, 145))
        changed = dict(values); changed['product/bit/0'] = 2
        emit('invalid-signed-bit', changed, false_checks(0, 272))
        # An otherwise completely coherent multiplication by the noncanonical
        # integer p has all original arithmetic predicates true. Only the new
        # field-validity path refutes this inadmissible signed assertion.
        coherent = field(values, 'input/b', p)
        tv = 0
        for shift in range(255):
            coherent[f'product/bit/{shift}'] = (p >> shift) & 1
        coherent = field(coherent, 'product/acc/0', 0)
        for step, shift in enumerate(range(254, -1, -1), 1):
            tv = (2*tv + ((p >> shift) & 1)*(p-19)) % p
            coherent = field(coherent, f'product/acc/{step}', tv)
        coherent = field(coherent, 'product', tv)
        if not all(c.native(coherent, p) for c in pr.constraints):
            raise AssertionError('coherent malformed multiplier fixture is not arithmetic-valid')
        emit('coherent-noncanonical-multiplier', coherent, false_checks(fields['input/b']) +
             [dict(ordinal=i, expected_correct=True) for i in (*range(9), 18, 145, 272, 273)])
        emit('noncanonical-accumulator', field(values, 'product/acc/128', p),
             false_checks(fields['product/acc/128']))
        changed = dict(values); changed['input/a/l0'] = 0xffffffff
        emit('oversize-signed-word', changed, false_checks(18, fields['input/a']))
        _, wrong = multiplication_trace(role, p-19, p-74, context=pr.context, operation_id=pr.operation_id)
        for w in dict(pr.fields)['input/b']:
            wrong[w] = values[w]
        emit('coherent-wrong-multiplier', wrong, false_checks(0) +
             [dict(ordinal=i, expected_correct=True) for i in (18, 145, 272, 273)])
        census.append({'field_role': role, 'case': 'multiplication', 'words': len(spec.words),
                       'original_constraints': spec.original_constraints, 'field_validity_leaves': len(spec.field_leaves),
                       'authenticated_leaves': len(spec.leaves), 'predicate_bodies': len(spec.bodies)})
    for curve in (PALLAS, VESTA):
        g = (curve.p-1, 2)
        pr, values = point_add_trace(curve, g, curve.mul(g, 2),
            context=sha256(b'global-registry-test').digest(), operation_id='registry/point')
        spec = GraphSpec.from_program(pr)
        # Execute each distinct predicate/alias shape, while compiling and
        # measuring EVERY point leaf with actual global keys in Rust.
        seen, checks = set(), []
        for i, leaf in enumerate(spec.leaves):
            shape = authenticated_shape(spec, leaf)
            if shape not in seen:
                seen.add(shape)
                checks.append(dict(ordinal=i, expected_correct=True))
        cases.append({'name': f'{curve.name}/point-graph', 'spec': spec.json(),
                      'expected_spec_id': spec.digest().hex(), 'words': [values[w] for w, _ in spec.words],
                      'checks': checks, 'measure_all': True})
        bad_pr, bad_values = point_add_trace(curve, g, g, claimed_output=g,
            context=pr.context, operation_id=pr.operation_id)
        if bad_pr.digest() != pr.digest() or curve.add(g, g) == g:
            raise AssertionError('false-point fixture topology or independent group expectation')
        failures = [i for i, c in enumerate(bad_pr.constraints) if not c.native(bad_values, curve.p)]
        if not failures:
            raise AssertionError('wrong canonical point result has no disproof')
        cases.append({'name': f'{curve.name}/wrong-canonical-point-result', 'spec': cases[-1]['spec'],
                      'expected_spec_id': spec.digest().hex(), 'words': [bad_values[w] for w, _ in spec.words],
                      'checks': [dict(ordinal=i, expected_correct=False) for i in failures], 'measure_all': False})
        census.append({'field_role': curve.name+'_base', 'case': 'point-add', 'words': len(spec.words),
                       'original_constraints': spec.original_constraints, 'field_validity_leaves': len(spec.field_leaves),
                       'authenticated_leaves': len(spec.leaves), 'predicate_bodies': len(spec.bodies),
                       'executed_shapes': len(checks)})
    g = TraceBuilder('pallas_base', 'registry/unused-word', bytes(32))
    g.constant('zero', 0)
    g.small('unused', 1, 3)
    pr, values = g.finish()
    spec = GraphSpec.from_program(pr)
    for value in (1, 3):
        changed = dict(values); changed['unused'] = value
        cases.append({'name': f'bounds/unused-word/{value}', 'spec': spec.json(),
                      'expected_spec_id': spec.digest().hex(), 'words': [changed[w] for w, _ in spec.words],
                      'checks': [dict(ordinal=len(spec.leaves)-1, expected_correct=value < 3)],
                      'measure_all': False})
    # Exact truth tables and malformed signed bits for the Boolean predicates
    # used by the production Keccak trace. Every case has fresh one-time keys.
    for kind in ('bool_xor', 'bool_and', 'bool_not'):
        width = 2 if kind == 'bool_not' else 3
        g = TraceBuilder('pallas_base', 'boolean/'+kind, bytes(32))
        wires = [g.small(f'w{i}', 0, 2) for i in range(width)]
        g.check(kind, wires)
        pr, _ = g.finish()
        spec = GraphSpec.from_program(pr)
        for i, values in enumerate(itertools.product((0, 1), repeat=width)):
            expected = (1-values[0] if kind == 'bool_not' else
                        values[0] ^ values[1] if kind == 'bool_xor' else values[0] & values[1])
            cases.append({'name': f'boolean/{kind}/{i}', 'spec': spec.json(),
                          'expected_spec_id': spec.digest().hex(), 'words': list(values),
                          'checks': [dict(ordinal=0, expected_correct=values[-1] == expected)],
                          'measure_all': False})
        cases.append({'name': f'boolean/{kind}/invalid-signed-bit', 'spec': spec.json(),
                      'expected_spec_id': spec.digest().hex(), 'words': [2]+[0]*(width-1),
                      'checks': [dict(ordinal=0, expected_correct=False)], 'measure_all': False})
    out = Path(__file__).resolve().parent/'results'
    path = out/'registry-inputs.json'
    with path.open('w', encoding='ascii', newline='\n') as f:
        json.dump(cases, f, separators=(',', ':'))
        f.write('\n')
    if path.stat().st_size > 32*1024*1024:
        raise AssertionError('registry input fixture exceeds 32 MiB')
    h = sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1024*1024), b''):
            h.update(block)
    report = {'schema': 'bitvm2-nova-registry-generation/v1', 'cases': len(cases),
              'input_bytes': path.stat().st_size, 'input_sha256': h.hexdigest(), 'census': census,
              'generation_seconds': time.perf_counter()-start, 'python_peak_rss_bytes': peak_rss(),
              'platform': platform.platform(), 'enforced_memory_limit': False, 'nova_proofs_generated': 0}
    (out/'registry-local-generation.json').write_text(json.dumps(report, indent=2)+'\n', newline='\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
