"""Bounded convolution comparison and global-WOTS fixtures, without signing.

Fixed-claim ledgers stream each complete Script leaf once into the same
length-prefixed hash/accounting used by bench_compact. They do not create huge
Script-vector files. WOTS bytes must be measured separately by the hosted
registry oracle; fixed-claim sizes are never projected into signature savings.
"""
import argparse
from hashlib import sha256
import json
from pathlib import Path
import platform
import time

from bench_compact import BASELINE, BASELINE_STREAMS, peak_rss
from convolution import CARRY_OFFSET, multiplication_trace as convolution_trace
from curve_trace import point_add_trace
from ipa_algebra import PALLAS, VESTA
from script import BASE, limbs
from trace import multiplication_trace as horner_trace
from wots_graph import GraphSpec, authenticated_shape

MAX_CASES, MAX_INPUT_BYTES = 64, 32 << 20
REGISTRY_CONTEXT = sha256(b'global-registry-test').digest()
FIXED_CONTEXT = sha256(b'M2-benchmark').digest()


def _fixed_stats(bound, compiler):
    digest, total, largest = sha256(), 0, 0
    for ordinal in range(len(bound.program.constraints)):
        code = bound.script(ordinal, compiler=compiler)
        total += len(code)
        largest = max(largest, len(code))
        digest.update(len(code).to_bytes(4, 'little')+code)
    return {'leaves': len(bound.program.constraints), 'all_disproof_scripts_bytes': total,
            'largest_leaf_bytes': largest, 'leaf_stream_sha256': digest.hexdigest()}


def build_fixed_ledger():
    """Eight graph objects; baseline dual compilers and opt-in candidate only."""
    rows = []
    for curve in (PALLAS, VESTA):
        for kind in ('multiplication', 'point-add'):
            operation_id = 'benchmark/mul' if kind == 'multiplication' else 'benchmark/point'
            if kind == 'multiplication':
                baseline, values = horner_trace(curve.name+'_base', curve.p-19, curve.p-73,
                    context=FIXED_CONTEXT, operation_id=operation_id)
                candidate, candidate_values = convolution_trace(curve.name+'_base', curve.p-19, curve.p-73,
                    context=FIXED_CONTEXT, operation_id=operation_id)
            else:
                g = (curve.p-1, 2)
                baseline, values = point_add_trace(curve, g, curve.mul(g, 2),
                    context=FIXED_CONTEXT, operation_id=operation_id)
                candidate, candidate_values = point_add_trace(curve, g, curve.mul(g, 2),
                    context=FIXED_CONTEXT, operation_id=operation_id, multiplication_backend='convolution-v1')
            bound, alternate = baseline.bind(values), candidate.bind(candidate_values)
            if bound.failures() or alternate.failures():
                raise AssertionError('honest fixed-claim fixture has false native constraints')
            stats = {name: _fixed_stats(bound, name) for name in ('m2', 'compact-v1')}
            stats['convolution-v1'] = _fixed_stats(alternate, 'convolution-v1')
            expected = 1_268_152 if kind == 'multiplication' else 16_554_753
            compact_expected = 1_083_022 if kind == 'multiplication' else 14_148_063
            if (stats['m2']['all_disproof_scripts_bytes'] != expected
                    or stats['m2']['leaf_stream_sha256'] != BASELINE_STREAMS[curve.name, kind]
                    or stats['compact-v1']['all_disproof_scripts_bytes'] != compact_expected):
                raise AssertionError('original M2/compact baseline changed')
            delta = stats['convolution-v1']['all_disproof_scripts_bytes']-compact_expected
            rows.append({'field_role': curve.name+'_base', 'case': kind,
                'context_sha256': FIXED_CONTEXT.hex(), 'operation_id': operation_id,
                'baseline_program_sha256': baseline.digest().hex(),
                'candidate_program_sha256': candidate.digest().hex(),
                'baseline_words': len(baseline.words), 'candidate_words': len(candidate.words),
                'baseline_fields': len(baseline.fields), 'candidate_fields': len(candidate.fields),
                'compilers': stats, 'candidate_minus_compact_bytes': delta,
                'candidate_minus_compact_percent': 100*delta/compact_expected,
                'fixed_claim_improves_over_compact': delta < 0})
            del bound, alternate, baseline, candidate, values, candidate_values
    return {'schema': 'bitvm2-nova-convolution-fixed-ledger/v1',
        'baseline_commit': BASELINE, 'cases': rows,
        'accounting': 'Actual disproof Script bodies, each leaf once, including opening tags and exact witness guards; excludes signatures, control blocks and transaction framing',
        'wots_script_bytes_measured': False, 'wots_savings_projected': False,
        'nova_proofs_verified': 0, 'transactions_broadcast': 0}


def _field(program, values, name, value):
    result = dict(values)
    for word, digit in zip(dict(program.fields)[name], limbs(value), strict=True):
        result[word] = digit
    return result


def _coherent_assignment(program, seed, a, b, c, quotient):
    """Independent integer producer, including admissible NON-field inputs.

    This never binds a fixed claim: its purpose includes malformed authenticated
    WOTS assignments whose arithmetic is coherent and field validity is false.
    """
    if any(type(value) is not int or not 0 <= value < 1 << 256 for value in (a, b, c, quotient)):
        raise ValueError('unsigned 32-byte integer inputs required')
    values = dict(seed)
    arrays = []
    for short, name, value in (('a', 'input/a', a), ('b', 'input/b', b), ('c', 'product', c)):
        values = _field(program, values, name, value)
        digits = [(value >> (8*i)) & 255 for i in range(32)]
        arrays.append(digits)
        for i, digit in enumerate(digits):
            values[f'product/{short}/byte/{i}'] = digit
        for boundary in (29, 58, 87, 116, 145, 174, 203):
            i, low = divmod(boundary, 8)
            values[f'product/{short}/split/{i}/lo'] = digits[i] & ((1 << low)-1)
            values[f'product/{short}/split/{i}/hi'] = digits[i] >> low
    q = [(quotient >> (8*i)) & 255 for i in range(32)]
    for i, digit in enumerate(q):
        values[f'product/q/{i}'] = digit
    modulus = program.p.to_bytes(32, 'little')
    signed = 0
    values['product/carry/0'] = CARRY_OFFSET
    for column in range(64):
        pairs = [(i, column-i) for i in range(32) if 0 <= column-i < 32]
        ab = [sum(arrays[0][i]*arrays[1][j] for i, j in pairs[start:start+4])
              for start in range(0, len(pairs), 4)]
        pairs = [(modulus[i], column-i) for i in range(32) if modulus[i] and 0 <= column-i < 32]
        pq = [sum(coefficient*q[j] for coefficient, j in pairs[start:start+8])
              for start in range(0, len(pairs), 8)]
        for block, total in enumerate(ab):
            values[f'product/ab/{column}/{block}'] = total
        for block, total in enumerate(pq):
            values[f'product/pq/{column}/{block}'] = total
        signed = (sum(ab)+signed-(arrays[2][column] if column < 32 else 0)-sum(pq)) // 256
        values[f'product/carry/{column+1}'] = signed+CARRY_OFFSET
    if set(values) != dict(program.words).keys():
        raise AssertionError('independent assignment changed graph topology')
    return values


def _integer_failures(program, a, b, c, quotient):
    difference = a*b-c-program.p*quotient
    columns = [i for i, constraint in enumerate(program.constraints) if constraint.kind == 'conv_column']
    if len(columns) != 64:
        raise AssertionError('convolution must expose every integer column')
    failures = [ordinal for column, ordinal in enumerate(columns) if (difference >> (8*column)) & 255]
    if difference >> 512:
        failures.append(next(i for i, constraint in enumerate(program.constraints)
            if constraint.kind == 'const' and constraint.wires == ('product/carry/64',)))
    return failures


def _truth(program, spec, values, ordinal):
    if ordinal < len(program.constraints):
        return program.constraints[ordinal].native(values, program.p)
    fields = dict(program.fields)
    name = next(name for name, index in spec.field_leaves if index == ordinal)
    digits = [values[word] for word in fields[name]]
    return all(0 <= value < BASE for value in digits) and sum(value << (29*i) for i, value in enumerate(digits)) < program.p


def build_registry_cases():
    cases, census, diagnostics = [], [], []
    for curve in (PALLAS, VESTA):
        role, p = curve.name+'_base', curve.p
        a, b = p-19, p-73
        product, quotient = a*b % p, a*b // p
        program, honest = convolution_trace(role, a, b, context=REGISTRY_CONTEXT, operation_id='registry/mul')
        spec = GraphSpec.from_program(program)
        shape, field_leaves = spec.json(), dict(spec.field_leaves)
        words = dict(program.words)
        def emit(name, values, false=(), true=(), measure=False, reason=''):
            checks = ([{'ordinal': i, 'expected_correct': False} for i in false]
                      +[{'ordinal': i, 'expected_correct': True} for i in true])
            if len({check['ordinal'] for check in checks}) != len(checks):
                raise AssertionError('duplicate/contradictory expected leaf checks')
            if any(_truth(program, spec, values, check['ordinal']) != check['expected_correct'] for check in checks):
                raise AssertionError('independent adversarial expectation disagrees with reference predicate')
            full_name = f'{role}/{name}'
            cases.append({'name': full_name, 'spec': shape, 'expected_spec_id': spec.digest().hex(),
                'words': [values[word] for word, _ in spec.words], 'checks': checks, 'measure_all': measure})
            diagnostics.append({'name': full_name, 'expected_false_checks': len(false),
                                'expected_true_checks': len(true), 'reason': reason})
        def refs(word, kinds=None):
            return [i for i, constraint in enumerate(program.constraints)
                    if word in constraint.wires and (kinds is None or constraint.kind in kinds)]
        def mutate(word, value):
            result = dict(honest)
            result[word] = value
            return result
        emit('convolution-mul', honest, measure=True, reason='all489 authenticated truth leaves execute in both directions')
        if (len(spec.leaves), len(program.constraints), len(spec.field_leaves)) != (489, 486, 3):
            raise AssertionError('standalone convolution graph census changed')
        for name, c, q in (('coherent-wrong-product', product+1, quotient),
                            ('wrong-quotient', product, quotient-1),
                            ('unsigned-max-quotient', product, (1 << 256)-1),
                            ('quotient-is-modulus-integer', product, p)):
            values = _coherent_assignment(program, honest, a, b, c, q)
            false = _integer_failures(program, a, b, c, q)
            actual = [i for i, constraint in enumerate(program.constraints) if not constraint.native(values, p)]
            if not false or false != actual:
                raise AssertionError('integer telescoping expectation mismatch')
            emit(name, values, false, reason='a*b != c+p*q using independent integer equality/column digits')
        changed = _field(program, honest, 'product', product+1)
        false = [i for i, constraint in enumerate(program.constraints)
                 if constraint.kind == 'conv_reconstruct' and constraint.wires[0] in dict(program.fields)['product']
                 and changed[constraint.wires[0]] != honest[constraint.wires[0]]]
        emit('noncoherent-wrong-product', changed, false, reason='canonical claimed product disconnected from its unchanged bytes')
        representatives = list(dict.fromkeys(next(i for i, c in enumerate(program.constraints) if c.kind == kind)
                               for kind in sorted({c.kind for c in program.constraints})))
        for name, aa, bb, cc, qq, invalid_field in (
            ('coherent-field-modulus', p, 0, 0, 0, 'input/a'),
            ('coherent-field-modulus-plus-one', p+1, 0, 0, 0, 'input/a'),
            ('coherent-noncanonical-output', p-1, p-1, p+1, p-3, 'product')):
            values = _coherent_assignment(program, honest, aa, bb, cc, qq)
            if aa*bb != cc+p*qq or any(not c.native(values, p) for c in program.constraints):
                raise AssertionError('noncanonical counterexample must satisfy every original arithmetic constraint')
            emit(name, values, [field_leaves[invalid_field]], representatives,
                 reason='integer equality holds and every original predicate is true; appended field-validity path refutes it')
        high = _field(program, honest, 'input/a', BASE**9-1)
        top = dict(program.fields)['input/a'][-1]
        emit('field261-high-bits', high, refs(top, {'conv_reconstruct'})+[field_leaves['input/a']],
             reason='all original261 bits remain tied to the32-byte reconstruction and canonical field check')
        huge = mutate('input/a/l0', 0xffffffff)
        emit('oversized-field-limb', huge, refs('input/a/l0', {'conv_reconstruct'})+[field_leaves['input/a']],
             reason='authenticated unsigned32 word exceeds declared29-bit limb bound')
        for name, word, value in (('oversized-quotient-byte', 'product/q/0', 256),
            ('unsigned32-max-quotient-byte', 'product/q/0', 0xffffffff),
            ('oversized-input-byte', 'product/a/byte/0', 256)):
            false = refs(word)
            emit(name, mutate(word, value), false,
                 reason='authenticated word exceeds its byte decoder bound')
        for name, word in (('initial-carry-anchor', 'product/carry/0'),
                           ('middle-carry-link', 'product/carry/32'),
                           ('final-carry-anchor', 'product/carry/64')):
            emit(name, mutate(word, honest[word]+1), refs(word),
                 reason='shared signed carry or endpoint anchor changed without its neighbors')
        for side in ('lo', 'hi'):
            word = 'product/a/split/3/'+side
            emit('crossing-byte-split-'+side, mutate(word, (honest[word]+1) % words[word]), refs(word),
                 reason='byte crossing a29-bit boundary cannot float independently')
        word = 'product/a/split/3/lo'
        emit('oversized-crossing-split', mutate(word, words[word]), refs(word),
             reason='split piece must satisfy its exact declared bit width')
        census.append({'field_role': role, 'case': 'multiplication', 'words': len(spec.words),
            'original_constraints': spec.original_constraints, 'field_validity_leaves': len(spec.field_leaves),
            'authenticated_leaves': len(spec.leaves), 'predicate_bodies': len(spec.bodies),
            'executed_truth_leaves': len(spec.leaves)})
    for curve in (PALLAS, VESTA):
        g = (curve.p-1, 2)
        program, values = point_add_trace(curve, g, curve.mul(g, 2), context=REGISTRY_CONTEXT,
            operation_id='registry/point', multiplication_backend='convolution-v1')
        spec = GraphSpec.from_program(program)
        checks, seen = [], set()
        for ordinal, leaf in enumerate(spec.leaves):
            auth_shape = authenticated_shape(spec, leaf)
            if auth_shape not in seen:
                checks.append({'ordinal': ordinal, 'expected_correct': True})
                seen.add(auth_shape)
        if any(not constraint.native(values, curve.p) for constraint in program.constraints):
            raise AssertionError('honest complete point graph has false predicates')
        cases.append({'name': f'{curve.name}/convolution-point', 'spec': spec.json(),
            'expected_spec_id': spec.digest().hex(), 'words': [values[word] for word, _ in spec.words],
            'checks': checks, 'measure_all': True})
        bad_program, bad = point_add_trace(curve, g, g, claimed_output=g, context=REGISTRY_CONTEXT,
            operation_id='registry/point', multiplication_backend='convolution-v1')
        if bad_program.digest() != program.digest() or curve.add(g, g) == g:
            raise AssertionError('wrong point must retain topology and differ from independent curve addition')
        fields = dict(program.fields)
        false = [i for i, c in enumerate(program.constraints) if c.kind == 'gate_equal'
                 and c.argument == (3, 4) and c.wires[1:10] in (fields['slope2'], fields['y-equation'])]
        actual = [i for i, c in enumerate(program.constraints) if not c.native(bad, curve.p)]
        if len(false) != 2 or false != actual:
            raise AssertionError('independent doubling result equations must be the false predicates')
        cases.append({'name': f'{curve.name}/convolution-wrong-point-result', 'spec': cases[-1]['spec'],
            'expected_spec_id': spec.digest().hex(), 'words': [bad[word] for word, _ in spec.words],
            'checks': [{'ordinal': i, 'expected_correct': False} for i in false], 'measure_all': False})
        census.append({'field_role': curve.name+'_base', 'case': 'point-add', 'words': len(spec.words),
            'original_constraints': spec.original_constraints, 'field_validity_leaves': len(spec.field_leaves),
            'authenticated_leaves': len(spec.leaves), 'predicate_bodies': len(spec.bodies),
            'executed_authenticated_shapes': len(checks),
            'executed_alias_shapes': sum(len(set(spec.leaves[c['ordinal']].wires)) < len(spec.leaves[c['ordinal']].wires) for c in checks)})
    if not 0 < len(cases) <= MAX_CASES:
        raise AssertionError('convolution fixture case budget')
    return cases, census, diagnostics


def write_registry_inputs(cases, path):
    if type(cases) is not list or not 0 < len(cases) <= MAX_CASES:
        raise ValueError('bounded case list required')
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', encoding='ascii', newline='\n') as stream:
        json.dump(cases, stream, separators=(',', ':'), allow_nan=False)
        stream.write('\n')
    if path.stat().st_size > MAX_INPUT_BYTES:
        raise AssertionError('convolution input exceeds32MiB')
    digest = sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            digest.update(block)
    return {'input_bytes': path.stat().st_size, 'input_sha256': digest.hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, default=Path(__file__).resolve().parent/'results')
    parser.add_argument('--skip-ledger', action='store_true', help='reference coverage generation only; no fixed-claim byte claim')
    args = parser.parse_args()
    start = time.perf_counter()
    args.out.mkdir(parents=True, exist_ok=True)
    ledger = None if args.skip_ledger else build_fixed_ledger()
    if ledger is not None:
        (args.out/'convolution-fixed-ledger.json').write_text(json.dumps(ledger, indent=2)+'\n', encoding='ascii', newline='\n')
    cases, census, diagnostics = build_registry_cases()
    info = write_registry_inputs(cases, args.out/'convolution-registry-inputs.json')
    report = {'schema': 'bitvm2-nova-convolution-generation/v1', 'cases': len(cases), **info,
        'fixed_ledger_measured': ledger is not None, 'census': census, 'diagnostics': diagnostics,
        'generation_seconds': time.perf_counter()-start, 'python_peak_rss_bytes': peak_rss(),
        'platform': platform.platform(), 'memory_limit_enforced': False,
        'script_vector_files_generated': 0, 'wots_signatures_generated': 0,
        'wots_script_bytes_measured': False, 'wots_savings_projected': False,
        'nova_proofs_generated': 0, 'transactions_broadcast': 0}
    (args.out/'convolution-generation.json').write_text(json.dumps(report, indent=2)+'\n', encoding='ascii', newline='\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
