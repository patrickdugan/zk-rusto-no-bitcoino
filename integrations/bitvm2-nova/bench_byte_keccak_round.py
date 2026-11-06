"""Hosted streamed one-round BYTE Keccak and conversion-complete baseline.

All 64 cases are independent rounds, never a linked 24-round permutation.
Each source has a separate 200-copy diagnostic consumer whose costs are kept
separate. Fresh sealed factories produce every catalogue; no receipt or caller
graph/map is admitted. Actual native calls hash compact execution observations.
"""
import argparse
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

SCHEMA = 'bitvm2-nova-byte-keccak-round-run/v1'
CONTEXT = sha256(b'BITVM2-NOVA/BYTE-KECCAK-ROUND-CONFORMANCE/v1').digest()
OPERATION = 'benchmark/byte-keccak-round/v1'
ROLES = ('pallas_scalar', 'vesta_scalar')
MAX_CASES, MAX_CASE_BYTES, MAX_MANIFEST_BYTES, MAX_RESULT_BYTES = 64, 32 << 20, 1 << 20, 1 << 20
MAX_EXECUTION_RECORD_BYTES = 128 << 20


def _guard():
    if (os.environ.get('GITHUB_ACTIONS') != 'true'
            or os.environ.get('RUNNER_OS') != 'Linux' or sys.platform != 'linux'):
        raise ValueError('BYTE Keccak round conformance is hosted GitHub Linux only')


def _profiles():
    """Small deterministic request list, without graph construction or I/O."""
    for role in ROLES:
        for r in range(24):
            yield role, r, 'byte-honest'
        for r in (0, 23):
            yield role, r, 'byte-wrong-output'
        for r in (0, 23):
            yield role, r, 'byte-oversized'
        for r in (0, 1, 2, 23):
            yield role, r, 'boolean-honest'


def _initial(round_index):
    if type(round_index) is not int or not 0 <= round_index < 24:
        raise ValueError('canonical one-round index required')
    return bytes((37*i+11+17*round_index) & 255 for i in range(200))


def _name(role, r, profile):
    if profile == 'boolean-honest':
        return f'{role}/boolean-r{r}'
    return f'{role}/byte-r{r}-'+{'byte-honest': 'honest',
        'byte-wrong-output': 'wrong-output', 'byte-oversized': 'oversized'}[profile]


def _source_operations(r, boolean):
    """Caller prefix and actual round-bound Program identity are distinct."""
    kind = 'boolean' if boolean else 'byte'
    caller = f'{OPERATION}/{kind}/r{r}'
    return caller, caller if boolean else f'{caller}/round/{r}'


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('utf-8')


def _ids_hash(ids):
    return sha256(_canonical(list(ids))).hexdigest()


def _truth(spec, values, ordinal):
    leaf = spec.leaves[ordinal]
    if leaf.kind == 'const':
        if len(leaf.wires) != 1 or len(leaf.argument) != 1:
            raise ValueError('exact zero-anchor shape required')
        word, bound = spec.words[leaf.wires[0]]
        return type(values[word]) is int and 0 <= values[word] < bound and values[word] == leaf.argument[0]
    from bench_byte_kernels import _truth as byte_truth
    return byte_truth(spec, values, ordinal)


def _auth_shapes(spec):
    from bench_byte_kernels import _auth_shape
    return len({_auth_shape(spec, leaf) for leaf in spec.leaves})


def _ports(plan, spec, r, boolean):
    inputs, outputs, producers = tuple(plan.inputs), tuple(plan.outputs), tuple(plan.producer_ordinals)
    ids = tuple(plan.global_ids)
    slots = {word: i for i, (word, _) in enumerate(spec.words)}
    if (len(inputs) != 200 or len(outputs) != 200 or len(producers) != 200
            or len(set(inputs)) != 200 or len(set(outputs)) != 200 or set(inputs) & set(outputs)
            or len(slots) != len(spec.words) or len(ids) != len(slots) or len(set(ids)) != len(ids)):
        raise ValueError('distinct complete BYTE boundaries and injective global map required')
    for stage, words in ((r, inputs), (r+1, outputs)):
        for i, word in enumerate(words):
            if (word not in slots or spec.words[slots[word]][1] != 256
                    or ids[slots[word]] != f'byte-state/{stage}/l{i//8}/byte{i%8}'):
                raise ValueError('ordered external BYTE boundary/global decoder mismatch')
    for word, ordinal in zip(outputs, producers, strict=True):
        if type(ordinal) is not int or not 0 <= ordinal < len(spec.leaves):
            raise ValueError('bounded actual terminal producer ordinal required')
        leaf = spec.leaves[ordinal]
        if boolean:
            valid = leaf.kind == 'conv_reconstruct' and leaf.argument == (8,) and len(leaf.wires) == 2 and leaf.wires[1] == slots[word]
        else:
            valid = leaf.kind.startswith('byte_') and leaf.wires[-1] == slots[word]
        if not valid:
            raise ValueError('actual BYTE producer occurrence detached from terminal port')
    if {index for leaf in spec.leaves for index in leaf.wires} != set(range(len(spec.words))):
        raise ValueError('source catalogue must cover every declared word')
    return inputs, outputs, producers, ids


def _probe(name, role, r, boolean, raw_output):
    _guard()  # Private helper also guards actual graph allocation.
    from byte_kernels import ByteTraceBuilder
    from wots_graph import GraphSpec
    kind = 'boolean' if boolean else 'byte'
    builder = ByteTraceBuilder(role, f'{OPERATION}/probe/{kind}/r{r}', CONTEXT)
    incoming = tuple(builder.byte(f'probe/input/l{i//8}/byte{i%8}', value) for i, value in enumerate(raw_output))
    outgoing = tuple(builder.byte(f'probe/output/l{i//8}/byte{i%8}', value) for i, value in enumerate(raw_output))
    for left, right in zip(incoming, outgoing, strict=True):
        builder.check('byte_xor_const', (left, right), (0,))
    program, values = builder.finish()
    spec = GraphSpec.from_program(program)
    ids = tuple(f'byte-state/{r+1}/l{i//8}/byte{i%8}' for i in range(200)) + tuple(
        f'probe/{name}/l{i//8}/byte{i%8}' for i in range(200))
    if len(spec.words) != 400 or len(spec.leaves) != 200 or len(set(ids)) != 400:
        raise ValueError('complete diagnostic 200-copy probe required')
    return spec, values, ids


def _case(name, spec, values):
    if set(values) != {word for word, _ in spec.words} or any(
            type(value) is not int or not 0 <= value <= 0xffffffff for value in values.values()):
        raise ValueError('complete signed-u32 registry assignment required')
    false = [i for i in range(len(spec.leaves)) if not _truth(spec, values, i)]
    return dict(name=name, spec=spec.json(), expected_spec_id=spec.digest().hex(),
        words=[values[word] for word, _ in spec.words],
        checks=[dict(ordinal=i, expected_correct=i not in false) for i in range(len(spec.leaves))],
        measure_all=True), false


def _one(index, role, r, profile, directory):
    _guard()
    from keccak_trace import ROUND_CONSTANTS, keccak_f1600_round, state_from_bytes, state_to_bytes
    boolean = profile == 'boolean-honest'
    if boolean:
        from byte_keccak_baseline import build_boolean_byte_round as factory
    else:
        from byte_keccak_round import build_byte_keccak_round as factory
    kind, name = 'boolean' if boolean else 'byte', _name(role, r, profile)
    initial = _initial(r)
    reference = state_to_bytes(keccak_f1600_round(state_from_bytes(initial), r))
    expected_output = bytearray(reference)
    if profile == 'byte-wrong-output':
        expected_output[0 if r == 0 else 8] ^= 1
    expected_output = bytes(expected_output)
    caller_operation, program_operation = _source_operations(r, boolean)
    plan = factory(r, context=CONTEXT, role=role, operation_id=caller_operation)
    binding = plan.bind(initial, claimed_output=expected_output if profile == 'byte-wrong-output' else None)
    spec, values = binding.spec, binding.assignment
    if (binding.initial_state != initial or binding.reference_output != reference
            or binding.output_state != expected_output or spec.context != CONTEXT.hex()
            or spec.field_role != role or spec.operation_id != program_operation):
        raise ValueError('fresh sealed one-round fixture identity/reference mismatch')
    inputs, outputs, producers, ids = _ports(plan, spec, r, boolean)
    if profile == 'byte-oversized':
        values[inputs[0]] = 0xffffffff
    source, false = _case(name, spec, values)
    if profile == 'byte-wrong-output':
        expected_false = [producers[0 if r == 0 else 8]]
    elif profile == 'byte-oversized':
        slot = next(i for i, (word, _) in enumerate(spec.words) if word == inputs[0])
        expected_false = [i for i, leaf in enumerate(spec.leaves) if slot in leaf.wires]
    else:
        expected_false = []
    if false != expected_false or (profile != 'byte-honest' and not boolean and not false):
        raise ValueError('wrong-output/decoder-invalid source leaf expectations mismatch')
    if boolean:
        expected_words, expected_leaves = 12001+ROUND_CONSTANTS[r].bit_count(), 10401+ROUND_CONSTANTS[r].bit_count()
    else:
        n = sum(value != 0 for value in ROUND_CONSTANTS[r].to_bytes(8, 'little'))
        expected_words, expected_leaves = 1416+n, 1216+n
    if (len(spec.words), len(spec.leaves)) != (expected_words, expected_leaves):
        raise ValueError('complete one-round source word/leaf census changed')
    filename = f'case-{index:02d}.json'
    record = _write_json(directory/filename, source, MAX_CASE_BYTES)
    source_sha = plan.source_sha256.hex()
    boolean_program = plan.boolean_program_sha256 if boolean else None
    boolean_catalogue = plan.boolean_catalogue_id if boolean else None
    shapes = _auth_shapes(spec)
    source_ids = set(ids)
    output_ids = tuple(ids[next(i for i, (word, _) in enumerate(spec.words) if word == output)] for output in outputs)
    # Hold only small IDs after the source JSON is written. The probe is a
    # separate component and its cost never enters the source-round ledger.
    source_descriptor = dict(name=name, profile=profile, role=role, round=r,
        filename=filename, **record, catalogue_id=spec.digest().hex(), program_sha256=spec.program_sha256,
        source_sha256=source_sha, boolean_program_sha256=boolean_program,
        boolean_catalogue_id=boolean_catalogue, global_ids_sha256=_ids_hash(ids),
        words=len(spec.words), leaves=len(spec.leaves), input_state_hex=initial.hex(),
        expected_output_state_hex=expected_output.hex(), expected_false=false)
    expected_probe_values = bytes(values[word] for word in outputs)
    del source, values, spec, binding, plan, inputs, outputs, producers, ids
    probe_spec, probe_values, probe_ids = _probe(name, role, r, boolean, expected_probe_values)
    if source_ids & set(probe_ids) != set(output_ids) or tuple(probe_ids[:200]) != output_ids:
        raise ValueError('probe must share exactly the same 200 source output identities')
    probe, probe_false = _case(name+'/probe', probe_spec, probe_values)
    if probe_false:
        raise ValueError('diagnostic consumer must be coherent with the actual source outputs')
    probe_filename = f'probe-{index:02d}.json'
    probe_record = _write_json(directory/probe_filename, probe, MAX_CASE_BYTES)
    source_descriptor.update(probe_filename=probe_filename,
        probe_file_sha256=probe_record['file_sha256'], probe_file_bytes=probe_record['file_bytes'],
        probe_catalogue_id=probe_spec.digest().hex(), probe_program_sha256=probe_spec.program_sha256,
        probe_global_ids_sha256=_ids_hash(probe_ids), probe_words=400, probe_leaves=200)
    census = dict(normal_leaf_checks=source_descriptor['leaves']+200,
        source_guard_layouts=shapes, probe_guard_layouts=1, guard_vectors=14*(shapes+1),
        native_rejections=48, port_rejections=8, probe_cache_rejections=12)
    del probe_spec, probe_values, probe_ids, probe, source_ids, output_ids
    return source_descriptor, census


def _generate(directory):
    _guard()
    rows, coverage = [], []
    for index, (role, r, profile) in enumerate(_profiles()):
        descriptor, census = _one(index, role, r, profile, directory)
        rows.append(descriptor)
        coverage.append(census)
    if len(rows) != MAX_CASES:
        raise ValueError('exact64 streamed one-round cases required')
    manifest = dict(schema=SCHEMA, context=CONTEXT.hex(), operation_id=OPERATION, cases=rows)
    info = _write_json(directory/'manifest.json', manifest, MAX_MANIFEST_BYTES)
    return manifest, info, coverage


def _new_directory(path):
    cwd = Path.cwd().resolve()
    owner, target = (cwd/'results').resolve(), Path(path).resolve()
    if owner == cwd or not owner.is_relative_to(cwd) or target == owner or not target.is_relative_to(owner):
        raise ValueError('BYTE round corpus must stay beneath canonical cwd/results')
    owner.mkdir(exist_ok=True)
    target.mkdir(parents=True, exist_ok=False, mode=0o700)
    return target


def _worker(path):
    source = Path(path)
    if source.is_symlink():
        raise ValueError('owned regular byte_keccak_round executable required')
    target = source.resolve()
    entry = target.lstat()
    if (not stat.S_ISREG(entry.st_mode) or entry.st_uid != os.getuid()
            or target.name != 'byte_keccak_round' or not os.access(target, os.X_OK)):
        raise ValueError('trusted configured owned byte_keccak_round executable required')
    return target


def _execute(worker, directory, manifest_sha):
    output = directory/'native-execution.json'
    if output.exists():
        raise ValueError('fresh direct BYTE round result required')
    command = ['/usr/bin/prlimit', '--as=536870912', '--cpu=1200', '--fsize=16777216', '--',
        str(worker), str(directory/'manifest.json'), str(directory), str(output), manifest_sha]
    environment = dict(os.environ, RAYON_NUM_THREADS='2', CUDA_VISIBLE_DEVICES='', RUST_BACKTRACE='0')
    with tempfile.TemporaryFile(dir=directory) as stdout, tempfile.TemporaryFile(dir=directory) as stderr:
        try:
            result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                                    timeout=1260, check=False, env=environment)
        except subprocess.TimeoutExpired as error:
            raise ValueError('direct BYTE round worker exceeded wall-time limit') from error
        if result.returncode != 0:
            stderr.seek(0)
            raise ValueError(f'direct BYTE round worker failed ({result.returncode}): '+stderr.read(8192).decode('utf-8', 'replace'))
        for stream in (stdout, stderr):
            stream.seek(0, 2)
            if stream.tell() > MAX_RESULT_BYTES:
                raise ValueError('BYTE round diagnostic-output cap exceeded')
    if not output.is_file() or output.is_symlink() or output.stat().st_size > MAX_RESULT_BYTES:
        raise ValueError('bounded direct BYTE round output required')
    with output.open('rb') as stream:
        raw = stream.read(MAX_RESULT_BYTES+1)
    if len(raw) > MAX_RESULT_BYTES:
        raise ValueError('direct BYTE round output grew beyond cap')
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError('duplicate direct BYTE round result field')
            value[key] = item
        return value
    try:
        return json.loads(raw.decode('utf-8'), object_pairs_hook=unique,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite direct result')))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError('invalid direct BYTE round result JSON') from error


def _equal(actual, expected, label):
    if type(actual) is not type(expected) or actual != expected:
        raise ValueError('direct BYTE round result mismatch: '+label)


def _hex32(value):
    return type(value) is str and len(value) == 64 and all(c in '0123456789abcdef' for c in value)


def _validate(native, manifest, info, coverage):
    if type(native) is not dict or native.get('passed') is not True:
        raise ValueError('successful direct BYTE round result required')
    _equal(native.get('schema'), 'bitvm2-nova-byte-keccak-round-execution/v1', 'schema')
    _equal(native.get('input_manifest_sha256'), info['file_sha256'], 'manifest identity')
    for flag in ('test_keys_only', 'stack_limit_enabled', 'one_round_script_conformance_checked',
                 'all_source_and_probe_leaves_executed', 'producer_opening_links_checked'):
        if native.get(flag) is not True:
            raise ValueError('required BYTE round conformance missing: '+flag)
    for flag in ('raw_vector_file_written', 'op_cat_enabled', 'full_24_round_composition_verified',
                 'full_permutation_verified', 'full_hash_verified', 'transcript_verified', 'proof_verified',
                 'complete_nova_verifier', 'complete_bitvm2_verifier', 'production_assertion_binding',
                 'bitcoin_transaction_graph', 'panic_is_rejection', 'baseline_bytes_are_free'):
        if native.get(flag) is not False:
            raise ValueError('BYTE round conformance scope exceeded: '+flag)
    for key in ('setup_calls', 'proving_jobs', 'native_proofs_verified', 'gpu_jobs', 'transactions_broadcast'):
        _equal(native.get(key), 0, key)
    records = native.get('compact_execution_records_bytes')
    if type(records) is not int or not 0 < records <= MAX_EXECUTION_RECORD_BYTES or not _hex32(native.get('compact_execution_records_sha256')):
        raise ValueError('bounded compact execution observation stream required')
    rows = native.get('cases')
    if type(rows) is not list or len(rows) != 64 or len(coverage) != 64:
        raise ValueError('all64 streamed source/probe observations required')
    total_checks = total_guards = largest_script = 0
    for row, source, expected in zip(rows, manifest['cases'], coverage, strict=True):
        if type(row) is not dict:
            raise ValueError('typed BYTE round observation required')
        for key, value in (('name', source['name']), ('profile', source['profile']),
                           ('round', source['round']), ('field_role', source['role'])):
            _equal(row.get(key), value, key)
        for key in ('native_rejections', 'port_rejections', 'probe_cache_rejections',
                    'source_guard_layouts', 'probe_guard_layouts', 'guard_vectors'):
            _equal(row.get(key), expected[key], key)
        for key, value in (('source_predicates_checked', source['leaves']), ('probe_predicates_checked', 200),
                           ('producer_opening_links', 200), ('cached_output_entries', 200),
                           ('probe_input_key_value_bound_signature_matches', 200),
                           ('source_signature_entries_created', source['words']),
                           ('probe_fresh_signature_entries_created', 200),
                           ('probe_cached_signature_reuses', 200)):
            _equal(row.get(key), value, key)
        boolean = source['profile'] == 'boolean-honest'
        for key, value in (('baseline_internal_bit_opening_links', 4800 if boolean else 0),
                           ('baseline_input_bit_opening_links', 3200 if boolean else 0),
                           ('baseline_output_bit_opening_links', 1600 if boolean else 0),
                           ('baseline_aux_opening_links', 400 if boolean else 0)):
            _equal(row.get(key), value, key)
        for key, value in (('source_false_predicates', source['expected_false']), ('probe_false_predicates', [])):
            actual = row.get(key)
            if type(actual) is not list or any(type(x) is not int for x in actual):
                raise ValueError('exact integer false-predicate list required')
            _equal(actual, value, key)
        for part in ('source', 'probe'):
            measured = row.get(part)
            if type(measured) is not dict:
                raise ValueError('separate typed source/probe cost ledgers required')
            prefix = '' if part == 'source' else 'probe_'
            for key, value in (('catalogue_id', source[prefix+'catalogue_id']),
                    ('program_sha256', source[prefix+'program_sha256']), ('context', manifest['context']),
                    ('global_ids_sha256', source[prefix+'global_ids_sha256']),
                    ('words', source[prefix+'words']), ('leaves', source[prefix+'leaves']),
                    ('executed_leaves', source[prefix+'leaves'])):
                _equal(measured.get(key), value, part+' '+key)
            if part == 'source':
                _equal(measured.get('source_sha256'), source['source_sha256'], 'sealed source admission identity')
                for key in ('boolean_program_sha256', 'boolean_catalogue_id'):
                    if key not in measured:
                        raise ValueError('explicit preserved Boolean child identity required')
                    _equal(measured[key], source[key], 'preserved Boolean child '+key)
            for key in ('registry_id', 'compiled_stream_sha256'):
                if not _hex32(measured.get(key)):
                    raise ValueError('actual '+part+' registry/script stream identity required')
            size, largest = measured.get('compiled_script_bytes'), measured.get('largest_disproof_leaf_bytes')
            if type(size) is not int or not 0 < size <= 1 << 28 or type(largest) is not int or not 0 < largest <= 100_000 or largest > size:
                raise ValueError('actual '+part+' Script byte budget exceeded')
            largest_script = max(largest_script, largest)
        total_checks += expected['normal_leaf_checks']
        total_guards += expected['guard_vectors']
    _equal(native.get('fresh_signature_entries_created'),
           sum(source['words'] for source in manifest['cases'])+64*200, 'all fresh source/probe signatures')
    _equal(native.get('cached_signature_reuses'), 64*200, 'all cached source-output signatures')
    metrics = native.get('metrics')
    if type(metrics) is not dict:
        raise ValueError('actual compact native execution metrics required')
    _equal(metrics.get('vectors'), 2*total_checks+total_guards, 'all correctness/disproof executions')
    _equal(metrics.get('expected_rejections'), total_checks+total_guards, 'ordinary false/malformed executions')
    for key in ('max_stack_items', 'max_witness_items'):
        if type(metrics.get(key)) is not int or not 0 < metrics[key] <= 1000:
            raise ValueError('BYTE round stack/witness limit exceeded')
    _equal(metrics.get('max_script_bytes'), largest_script, 'actual maximum Script bytes')
    payload = metrics.get('max_witness_payload_bytes')
    if type(payload) is not int or not 0 < payload <= 520*metrics['max_witness_items']:
        raise ValueError('BYTE round witness payload bound exceeded')
    return rows


def _comparisons(rows):
    by_name, result = {row['name']: row for row in rows}, []
    for role in ROLES:
        for r in (0, 1, 2, 23):
            candidate = by_name[f'{role}/byte-r{r}-honest']
            baseline = by_name[f'{role}/boolean-r{r}']
            byte_cost, bit_cost = candidate['source']['compiled_script_bytes'], baseline['source']['compiled_script_bytes']
            result.append(dict(field_role=role, round=r,
                candidate_case=candidate['name'], baseline_case=baseline['name'],
                candidate_source_script_bytes=byte_cost, conversion_complete_boolean_source_script_bytes=bit_cost,
                candidate_minus_baseline_bytes=byte_cost-bit_cost,
                candidate_probe_script_bytes=candidate['probe']['compiled_script_bytes'],
                baseline_probe_script_bytes=baseline['probe']['compiled_script_bytes'],
                source_cost_excludes_copy_probe=True, baseline_includes_800_bridge_leaves=True))
    return result


def run(cases_dir, native_worker):
    _guard()
    started = time.perf_counter()
    worker, directory = _worker(native_worker), _new_directory(cases_dir)
    manifest, info, coverage = _generate(directory)
    native = _execute(worker, directory, info['file_sha256'])
    rows = _validate(native, manifest, info, coverage)
    return dict(schema='bitvm2-nova-byte-keccak-round-conformance/v1', native=native,
        manifest=info, context_sha256=CONTEXT.hex(), operation_id=OPERATION, cases=64,
        comparisons=_comparisons(rows), direct_native_worker_executed=True,
        external_result_receipt_loaded=False, source_cost_excludes_copy_probe=True,
        distinct_baseline_bit_words_per_case=3200, baseline_bit_opening_comparisons_per_case=4800,
        full_24_round_composition_verified=False, cross_round_linking_verified=False,
        full_permutation_cost_projected=False, full_hash_verified=False, transcript_verified=False,
        proof_verified=False, bitvm2_script_verified=False, complete_bitvm2_verifier=False,
        production_assertion_binding=False, bitcoin_transaction_graph=False,
        setup_calls=0, proving_jobs=0, gpu_jobs=0, transactions_broadcast=0,
        wall_seconds=time.perf_counter()-started, parent_peak_rss_bytes=peak_rss(),
        scope='independent one-round BYTE source/Boolean-baseline execution and actual terminal-copy links only')


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
