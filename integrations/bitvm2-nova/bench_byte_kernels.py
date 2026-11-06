"""Tiny BYTE-kernel fixtures and hosted authenticated cost measurements.

XOR/AND/NOT comparisons use the SAME external BYTE a/b/out ports. Boolean
baselines include every byte/bit bridge; their bare Boolean leaf subtotal is
only a diagnostic. Rotation/mask kernels are measured directly, with no full
permutation projection. Native execution is direct, hosted and resource capped.
"""
import argparse
from dataclasses import dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time

from bench_compact import peak_rss
from bench_keccak_endpoint import _write_json

CONTEXT = sha256(b'BITVM2-NOVA/BYTE-KERNEL-CONFORMANCE/v1').digest()
OPERATION = 'benchmark/byte-kernels/v1'
ROLES = ('pallas_scalar', 'vesta_scalar')
MASKS = (0, 1, 128, 129, 255)
MAX_CASES, MAX_INPUT_BYTES, MAX_RESULT_BYTES = 64, 32 << 20, 1 << 20


def _guard():
    if (os.environ.get('GITHUB_ACTIONS') != 'true'
            or os.environ.get('RUNNER_OS') != 'Linux' or sys.platform != 'linux'):
        raise ValueError('native BYTE-kernel conformance is hosted GitHub Linux only')


def _relation(kind, argument, values):
    if kind == 'byte_xor':
        return values[0] ^ values[1]
    if kind == 'byte_and':
        return values[0] & values[1]
    if kind == 'byte_not':
        return values[0] ^ 255
    if kind == 'byte_rol':
        r, = argument
        return ((values[0] << r) & 255) | (values[1] >> (8-r))
    if kind == 'byte_xor_const':
        return values[0] ^ argument[0]
    raise ValueError('unsupported independent BYTE relation')


def _truth(spec, values, ordinal):
    leaf = spec.leaves[ordinal]
    operands = []
    for index in leaf.wires:
        word, bound = spec.words[index]
        value = values[word]
        if type(value) is not int or not 0 <= value < bound:
            return False  # Authenticated decoder invalid-message flag only.
        operands.append(value)
    if leaf.kind.startswith('byte_'):
        return operands[-1] == _relation(leaf.kind, leaf.argument, operands[:-1])
    if leaf.kind == 'bits' and leaf.argument == (8,):
        return operands[0] == sum(bit << (7-i) for i, bit in enumerate(operands[1:]))
    if leaf.kind == 'conv_reconstruct' and leaf.argument == (8,):
        return operands[0] == operands[1]
    if leaf.kind == 'bool_xor':
        return operands[-1] == operands[0] ^ operands[1]
    if leaf.kind == 'bool_and':
        return operands[-1] == operands[0] & operands[1]
    if leaf.kind == 'bool_not':
        return operands[-1] == 1-operands[0]
    raise ValueError('unexpected byte benchmark leaf kind/shape')


def _auth_shape(spec, leaf):
    unique = tuple(dict.fromkeys(leaf.wires))
    positions = {word: i for i, word in enumerate(unique)}
    return leaf.body_sha256, tuple(spec.words[i][1] for i in unique), tuple(positions[i] for i in leaf.wires)


@dataclass(frozen=True)
class _Fixture:
    program: object
    assignment: tuple
    spec: object
    external: tuple
    bridges: tuple
    outputs: tuple


def _fixture(program, assignment, external, bridges=(), outputs=('out',)):
    from wots_graph import GraphSpec
    spec = GraphSpec.from_program(program)
    return _Fixture(program, tuple(assignment.items()), spec, tuple(external), tuple(bridges), tuple(outputs))


def _ports(kind, alias):
    """Choose satisfiable honest alias examples without specializing predicates."""
    if kind == 'byte_not':
        return {'a': 0x96, 'out': 0x69}, ('a', 'out')
    if alias == 'ab':
        return {'a': 0x96, 'out': 0 if kind == 'byte_xor' else 0x96}, ('a', 'a', 'out')
    if alias == 'out-a':
        return {'a': 0x96, 'b': 0 if kind == 'byte_xor' else 255}, ('a', 'b', 'a')
    if alias == 'all':
        return {'a': 0 if kind == 'byte_xor' else 0x96}, ('a', 'a', 'a')
    a, b = 0x96, 0x3d
    return {'a': a, 'b': b, 'out': _relation(kind, (), (a, b))}, ('a', 'b', 'out')


def _candidate(role, kind, alias=None):
    from byte_kernels import ByteTraceBuilder
    short, profile = kind.removeprefix('byte_'), 'honest' if alias is None else 'alias-'+alias
    builder = ByteTraceBuilder(role, f'{OPERATION}/candidate/{short}/{profile}', CONTEXT)
    values, formal = _ports(kind, alias)
    for word, value in values.items():
        builder.byte(word, value)
    builder.check(kind, formal, ())
    program, assignment = builder.finish()
    return _fixture(program, assignment, formal, outputs=(formal[-1],))


def _baseline(role, kind, alias=None):
    from convolution import ConvolutionTraceBuilder
    from script import BASE
    short, profile = kind.removeprefix('byte_'), 'honest' if alias is None else 'alias-'+alias
    builder = ConvolutionTraceBuilder(role, f'{OPERATION}/boolean/{short}/{profile}', CONTEXT)
    values, formal = _ports(kind, alias)
    for word, value in values.items():
        builder.small(word, value, 256)
    bridges = []
    for word, value in values.items():
        auxiliary = builder.small(word+'/aux', value, BASE)
        bits = tuple(builder.small(f'{word}/bits/{i}', (value >> i) & 1, 2) for i in range(8))
        builder.check('bits', (auxiliary,)+tuple(reversed(bits)), (8,))
        builder.check('conv_reconstruct', (auxiliary, word), (8,))
        bridges.append((word, auxiliary, bits))
    groups = {word: bits for word, _, bits in bridges}
    boolean = {'byte_xor': 'bool_xor', 'byte_and': 'bool_and', 'byte_not': 'bool_not'}[kind]
    for bit in range(8):
        builder.check(boolean, tuple(groups[word][bit] for word in formal), ())
    program, assignment = builder.finish()
    return _fixture(program, assignment, formal, bridges, outputs=(formal[-1],))


def _extras(role):
    from byte_kernels import ByteTraceBuilder
    builder = ByteTraceBuilder(role, f'{OPERATION}/candidate/extras/honest', CONTEXT)
    builder.byte('a', 0x96)
    builder.byte('b', 0x3d)
    outputs = []
    for r in range(1, 8):
        name = f'rol/{r}/out'
        expected = _relation('byte_rol', (r,), (0x96, 0x3d))
        builder.byte(name, expected)
        builder.check('byte_rol', ('a', 'b', name), (r,))
        outputs.append(name)
    for mask in MASKS:
        name = f'mask/{mask}/out'
        builder.byte(name, 0x96 ^ mask)
        builder.check('byte_xor_const', ('a', name), (mask,))
        outputs.append(name)
    program, assignment = builder.finish()
    return _fixture(program, assignment, ('a', 'b'), outputs=outputs)


def _case(name, fixture, values):
    spec = fixture.spec
    if set(values) != {word for word, _ in spec.words} or any(
            type(value) is not int or not 0 <= value <= 0xffffffff for value in values.values()):
        raise ValueError('complete unsigned32 diagnostic assignment required')
    false = [i for i in range(len(spec.leaves)) if not _truth(spec, values, i)]
    return dict(name=name, spec=spec.json(), expected_spec_id=spec.digest().hex(),
        words=[values[word] for word, _ in spec.words], measure_all=True,
        checks=[dict(ordinal=i, expected_correct=i not in false) for i in range(len(spec.leaves))]), false


def _wrong(fixture, *, coherent_baseline=False):
    values = dict(fixture.assignment)
    for word in fixture.outputs:
        values[word] ^= 1
    if coherent_baseline:
        for word, auxiliary, bits in fixture.bridges:
            values[auxiliary] = values[word]
            for bit, name in enumerate(bits):
                values[name] = (values[word] >> bit) & 1
    return values


def generate():
    """Build only tiny fixtures (672 words total); no native process or I/O."""
    cases, descriptions, comparisons = [], [], []
    distinct_bit_links = formal_bit_links = auxiliary_links = 0

    def add(name, fixture, values, profile, *, honest=False):
        nonlocal distinct_bit_links, formal_bit_links, auxiliary_links
        case, false = _case(name, fixture, values)
        if bool(false) == honest:
            raise ValueError('honest/wrong BYTE fixture predicate expectations mismatch')
        cases.append(case)
        descriptions.append(dict(case=name, profile=profile, false_predicates=false,
            external_formal_words=list(fixture.external), catalogue_id=case['expected_spec_id'],
            words=len(case['words']), leaves=len(case['spec']['leaves'])))
        if fixture.bridges:
            auxiliary_links += len(fixture.bridges)
            for leaf in fixture.spec.leaves:
                if leaf.kind.startswith('bool_'):
                    distinct_bit_links += len(set(leaf.wires))
                    formal_bit_links += len(leaf.wires)
        return case

    for role in ROLES:
        singles, baselines = {}, {}
        for short in ('xor', 'and', 'not'):
            kind = 'byte_'+short
            candidate, baseline = _candidate(role, kind), _baseline(role, kind)
            singles[short], baselines[short] = candidate, baseline
            expected = (20, 12) if short == 'not' else (30, 14)
            if (len(baseline.spec.words), len(baseline.spec.leaves)) != expected:
                raise ValueError('complete BYTE-to-bit Boolean baseline census changed')
            candidate_name, baseline_name = f'{role}/candidate-{short}', f'{role}/boolean-{short}'
            add(candidate_name, candidate, dict(candidate.assignment), 'candidate-honest', honest=True)
            add(baseline_name, baseline, dict(baseline.assignment), 'boolean-honest', honest=True)
            comparisons.append(dict(field_role=role, operation=short,
                candidate_case=candidate_name, baseline_case=baseline_name,
                external_formal_words=list(candidate.external),
                candidate_words=len(candidate.spec.words), baseline_words=len(baseline.spec.words),
                candidate_leaves=1, baseline_leaves=len(baseline.spec.leaves),
                baseline_boolean_leaves=8, baseline_bridges=len(baseline.bridges)*2))
        extras = _extras(role)
        add(f'{role}/candidate-extras', extras, dict(extras.assignment), 'rotation-mask-honest', honest=True)
        for short, fixture in tuple(singles.items())+(('extras', extras),):
            add(f'{role}/candidate-{short}-wrong', fixture, _wrong(fixture), 'wrong-bounded-output')
        for short in ('xor', 'and'):
            for alias in ('ab', 'out-a', 'all'):
                fixture = _candidate(role, 'byte_'+short, alias)
                add(f'{role}/candidate-{short}-alias-{alias}', fixture, dict(fixture.assignment),
                    'candidate-alias-honest', honest=True)
        for short, fixture in tuple(singles.items())+(('extras', extras),):
            values = dict(fixture.assignment)
            values['a'] = 0xffffffff
            add(f'{role}/candidate-{short}-oversized', fixture, values, 'signed-u32-decoder-invalid')
        for short, fixture in baselines.items():
            add(f'{role}/boolean-{short}-wrong', fixture, _wrong(fixture, coherent_baseline=True),
                'coherent-wrong-boolean-output')
        for short in ('xor', 'and'):
            for alias in ('ab', 'out-a', 'all'):
                fixture = _baseline(role, 'byte_'+short, alias)
                add(f'{role}/boolean-{short}-alias-{alias}', fixture, dict(fixture.assignment),
                    'boolean-alias-honest', honest=True)
    if len(cases) != 60 or len(cases) > MAX_CASES:
        raise ValueError('exact bounded two-role BYTE fixture census changed')
    words = sum(len(case['words']) for case in cases)
    checks = sum(len(case['checks']) for case in cases)
    shapes = 0
    for case in cases:
        # Use the actual ordered catalogue representation, including aliases.
        seen = set()
        for leaf in case['spec']['leaves']:
            unique = tuple(dict.fromkeys(leaf['wires']))
            positions = {wire: i for i, wire in enumerate(unique)}
            seen.add((leaf['body_sha256'], tuple(case['spec']['words'][i]['bound'] for i in unique),
                      tuple(positions[i] for i in leaf['wires'])))
        shapes += len(seen)
    guards = 14*shapes
    native = sum(22+2*(len(case['words']) > 1) for case in cases)
    if (words, checks, distinct_bit_links, formal_bit_links, auxiliary_links) != (672, 398, 416, 544, 52):
        raise ValueError('BYTE fixture word/leaf/shared-opening census changed')
    return cases, dict(cases=len(cases), words=words, leaves=checks, normal_leaf_checks=checks,
        authenticated_shapes=shapes, expected_guard_vectors=guards,
        expected_vectors=2*checks+guards, expected_rejections=checks+guards,
        expected_native_rejections=native, expected_signatures=words,
        expected_shared_baseline_bit_opening_links=distinct_bit_links,
        baseline_formal_bit_occurrences=formal_bit_links,
        expected_shared_baseline_aux_opening_links=auxiliary_links,
        expected_bare_exhaustive_pairs=131072, expected_bare_exhaustive_engine_executions=132608,
        expected_ordinary_false_inverse_probes=512, expected_correctness_inverse_probes=512,
        expected_bare_numeric_abort_probes=78, expected_bare_numeric_abort_engine_executions=156,
        descriptions=descriptions, comparisons=comparisons)


def _new_directory(path):
    cwd = Path.cwd().resolve()
    owner, target = (cwd/'results').resolve(), Path(path).resolve()
    if owner == cwd or not owner.is_relative_to(cwd) or target == owner or not target.is_relative_to(owner):
        raise ValueError('BYTE corpus must stay beneath canonical cwd/results')
    owner.mkdir(exist_ok=True)
    target.mkdir(parents=True, exist_ok=False, mode=0o700)
    return target


def _worker(path):
    source = Path(path)
    if source.is_symlink():
        raise ValueError('owned regular BYTE worker required')
    target = source.resolve()
    entry = target.lstat()
    if (not stat.S_ISREG(entry.st_mode) or entry.st_uid != os.getuid()
            or target.name != 'byte_kernels' or not os.access(target, os.X_OK)):
        raise ValueError('trusted configured owned byte_kernels worker required')
    return target


def _execute(worker, directory, input_sha256):
    output = directory/'native-execution.json'
    if output.exists():
        raise ValueError('fresh direct BYTE output required')
    command = ['/usr/bin/prlimit', '--as=536870912', '--cpu=300', '--fsize=16777216', '--',
               str(worker), str(directory/'inputs.json'), str(output), input_sha256]
    environment = dict(os.environ, RAYON_NUM_THREADS='2', CUDA_VISIBLE_DEVICES='', RUST_BACKTRACE='0')
    with tempfile.TemporaryFile(dir=directory) as stdout, tempfile.TemporaryFile(dir=directory) as stderr:
        try:
            result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                                    timeout=360, check=False, env=environment)
        except subprocess.TimeoutExpired as error:
            raise ValueError('direct BYTE worker exceeded wall-time limit') from error
        if result.returncode != 0:
            stderr.seek(0)
            raise ValueError(f'direct BYTE worker failed ({result.returncode}): '+stderr.read(8192).decode('utf-8', 'replace'))
        for stream in (stdout, stderr):
            stream.seek(0, 2)
            if stream.tell() > MAX_RESULT_BYTES:
                raise ValueError('BYTE diagnostic output cap exceeded')
    if not output.is_file() or output.is_symlink() or output.stat().st_size > MAX_RESULT_BYTES:
        raise ValueError('bounded direct BYTE result required')
    with output.open('rb') as stream:
        raw = stream.read(MAX_RESULT_BYTES+1)
    if len(raw) > MAX_RESULT_BYTES:
        raise ValueError('direct BYTE output grew beyond cap')
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError('duplicate direct BYTE result field')
            value[key] = item
        return value
    try:
        return json.loads(raw.decode('utf-8'), object_pairs_hook=unique,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite result')))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError('invalid direct BYTE result JSON') from error


def _equal(actual, expected, label):
    if type(actual) is not type(expected) or actual != expected:
        raise ValueError('direct BYTE result mismatch: '+label)


def _hex32(value):
    return type(value) is str and len(value) == 64 and all(c in '0123456789abcdef' for c in value)


def _validate(native, cases, census, info):
    if type(native) is not dict or native.get('passed') is not True:
        raise ValueError('successful direct BYTE result required')
    _equal(native.get('schema'), 'bitvm2-nova-byte-kernel-execution/v1', 'schema')
    _equal(native.get('input_sha256'), info['file_sha256'], 'exact input bytes')
    for flag in ('raw_vector_file_written', 'full_hash_verified', 'full_permutation_verified',
                 'complete_nova_verifier', 'panic_is_rejection', 'op_cat_enabled', 'transcript_verified',
                 'proof_verified', 'complete_bitvm2_verifier', 'production_assertion_binding',
                 'bitcoin_transaction_graph'):
        if native.get(flag) is not False:
            raise ValueError('BYTE conformance scope exceeded: '+flag)
    for flag in ('test_keys_only', 'stack_limit_enabled'):
        if native.get(flag) is not True:
            raise ValueError('required BYTE execution policy missing: '+flag)
    for key in ('setup_calls', 'proving_jobs', 'gpu_jobs', 'transactions_broadcast', 'native_proofs_verified'):
        _equal(native.get(key), 0, key)
    for key, value in (('cases', len(cases)), ('normal_leaf_checks', census['normal_leaf_checks']),
            ('signatures_generated_once_per_wire', census['expected_signatures']),
            ('guard_vectors', census['expected_guard_vectors']),
            ('native_rejections', census['expected_native_rejections']),
            ('shared_baseline_bit_opening_links', census['expected_shared_baseline_bit_opening_links']),
            ('shared_baseline_aux_opening_links', census['expected_shared_baseline_aux_opening_links']),
            ('bare_exhaustive_pairs', 131072), ('bare_exhaustive_engine_executions', 132608),
            ('ordinary_false_inverse_probes', 512), ('correctness_inverse_probes', 512),
            ('bare_numeric_abort_probes', 78), ('bare_numeric_abort_engine_executions', 156)):
        _equal(native.get(key), value, key)
    if native.get('body_equality_across_fields_checked') is not True:
        raise ValueError('BYTE body parity across both scalar roles required')
    metrics = native.get('metrics')
    if type(metrics) is not dict:
        raise ValueError('typed authenticated BYTE engine metrics required')
    _equal(metrics.get('vectors'), census['expected_vectors'], 'authenticated vectors')
    _equal(metrics.get('expected_rejections'), census['expected_rejections'], 'authenticated rejections')
    for key in ('max_stack_items', 'max_witness_items'):
        if type(metrics.get(key)) is not int or not 0 < metrics[key] <= 1000:
            raise ValueError('BYTE stack/witness bound exceeded')
    ledger = native.get('ledger')
    if type(ledger) is not list or len(ledger) != len(cases):
        raise ValueError('every complete BYTE catalogue must have an actual ledger')
    for measured, source in zip(ledger, cases, strict=True):
        if type(measured) is not dict:
            raise ValueError('typed BYTE ledger row required')
        for key, expected in (('case', source['name']), ('catalogue_id', source['expected_spec_id']),
                ('words', len(source['words'])), ('leaves', len(source['spec']['leaves'])),
                ('executed_leaves', len(source['checks']))):
            _equal(measured.get(key), expected, key)
        if not _hex32(measured.get('registry_id')) or not _hex32(measured.get('leaf_stream_sha256')):
            raise ValueError('actual BYTE registry/stream identity required')
        costs = measured.get('leaf_costs')
        if type(costs) is not list or len(costs) != len(source['spec']['leaves']):
            raise ValueError('complete ordered BYTE per-leaf costs required')
        total, largest = 0, 0
        for ordinal, (cost, leaf) in enumerate(zip(costs, source['spec']['leaves'], strict=True)):
            if type(cost) is not dict:
                raise ValueError('typed BYTE leaf cost row required')
            argument = cost.get('argument')
            if type(argument) is not list or any(type(value) is not int for value in argument):
                raise ValueError('BYTE leaf public arguments must be exact integer lists')
            for key, value in (('ordinal', ordinal), ('kind', leaf['kind']), ('argument', leaf['argument'])):
                _equal(cost.get(key), value, 'leaf '+key)
            size = cost.get('disproof_script_bytes')
            if type(size) is not int or not 0 < size <= 100_000:
                raise ValueError('BYTE per-leaf Script byte budget exceeded')
            total += size
            largest = max(largest, size)
        _equal(measured.get('all_disproof_script_bytes'), total, 'complete Script byte sum')
        _equal(measured.get('largest_disproof_leaf_bytes'), largest, 'largest Script leaf')
    return ledger


def _comparisons(ledger, census):
    measured = {row['case']: row for row in ledger}
    rows = []
    for source in census['comparisons']:
        candidate, baseline = measured[source['candidate_case']], measured[source['baseline_case']]
        boolean_only = sum(cost['disproof_script_bytes'] for cost in baseline['leaf_costs']
                           if cost['kind'].startswith('bool_'))
        full = baseline['all_disproof_script_bytes']
        actual = candidate['all_disproof_script_bytes']
        rows.append(dict(source, candidate_disproof_script_bytes=actual,
            full_boolean_baseline_disproof_script_bytes=full,
            boolean_leaf_only_diagnostic_bytes=boolean_only,
            conversion_bridge_disproof_script_bytes=full-boolean_only,
            candidate_minus_full_baseline_bytes=actual-full,
            full_statement_includes_conversion_bridges=True))
    return rows


def run(cases_dir, native_worker):
    _guard()  # Before requested-path I/O, native execution or fixture generation.
    started = time.perf_counter()
    worker, directory = _worker(native_worker), _new_directory(cases_dir)
    cases, census = generate()
    info = _write_json(directory/'inputs.json', cases, MAX_INPUT_BYTES)
    native = _execute(worker, directory, info['file_sha256'])
    ledger = _validate(native, cases, census, info)
    return dict(schema='bitvm2-nova-byte-kernel-conformance/v1', native=native,
        input=info, census=census, comparisons=_comparisons(ledger, census),
        context_sha256=CONTEXT.hex(), operation_id=OPERATION,
        direct_native_worker_executed=True, external_result_receipt_loaded=False,
        out_of_domain_bare_results_counted_as_disproofs=False,
        full_byte_permutation_constructed=False, full_permutation_cost_projected=False,
        full_hash_verified=False, transcript_verified=False, proof_verified=False,
        bitvm2_script_verified=False, complete_bitvm2_verifier=False,
        production_assertion_binding=False, bitcoin_transaction_graph=False,
        setup_calls=0, proving_jobs=0, transactions_broadcast=0,
        wall_seconds=time.perf_counter()-started, parent_peak_rss_bytes=peak_rss(),
        scope='tiny BYTE kernels and complete byte/bit Boolean statement baselines only')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cases-dir', type=Path, required=True)
    parser.add_argument('--native-worker', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    _guard()
    from bench_keccak_endpoint import _output_file
    output = _output_file(args.output)
    result = run(args.cases_dir, args.native_worker)
    _write_json(output, result, MAX_RESULT_BYTES)
    print(json.dumps(result, ensure_ascii=True, allow_nan=False))


if __name__ == '__main__':
    main()
