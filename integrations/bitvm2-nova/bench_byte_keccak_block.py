"""Hosted four-round single-registry conformance, streamed one case at a time.

Parent Script costs are measured directly. Child metadata authenticates the
fresh projection; it is not an independently executed isolated-child ledger.
The 32 cases do not compose six blocks or establish a full permutation/hash.
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

SCHEMA = 'bitvm2-nova-byte-keccak-block-run/v1'
CONTEXT = sha256(b'BITVM2-NOVA/BYTE-KECCAK-BLOCK-CONFORMANCE/v1').digest()
OPERATION = 'benchmark/byte-keccak-block/v1'
ROLES = ('pallas_scalar', 'vesta_scalar')
MAX_CASES, MAX_CASE_BYTES, MAX_MANIFEST_BYTES, MAX_RESULT_BYTES = 32, 32 << 20, 1 << 20, 1 << 20
MAX_EXECUTION_RECORD_BYTES = 128 << 20


def _guard():
    if (os.environ.get('GITHUB_ACTIONS') != 'true'
            or os.environ.get('RUNNER_OS') != 'Linux' or sys.platform != 'linux'):
        raise ValueError('BYTE Keccak block conformance is hosted GitHub Linux only')


def _requests():
    for role in ROLES:
        for start in (0, 4, 8, 12, 16, 20):
            yield role, start, 'honest', None, None
        for boundary in range(3):
            yield role, 0, 'middle-chi', boundary, 8
            yield role, 0, 'middle-iota', boundary, 0
        yield role, 20, 'final-chi', None, 8
        yield role, 20, 'final-iota', None, 0
        for start in (0, 20):
            yield role, start, 'oversized', None, None


def _name(role, start, profile, boundary):
    if profile.startswith('middle-'):
        return f'{role}/block-s{start}-middle-j{boundary+1}-'+profile.removeprefix('middle-')
    if profile.startswith('final-'):
        return f'{role}/block-s{start}-'+profile
    return f'{role}/block-s{start}-{profile}'


def _initial(start):
    if type(start) is not int or not 0 <= start <= 20:
        raise ValueError('canonical four-round start required')
    return bytes((37*i+11+17*start) & 255 for i in range(200))


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('utf-8')


def _hash_list(values):
    return sha256(_canonical(list(values))).hexdigest()


def _pipeline(start, initial, profile, boundary, slot):
    """Tiny independent word reference, with downstream arithmetic rewitnessed."""
    from keccak_trace import keccak_f1600_round, state_from_bytes, state_to_bytes
    current = initial
    claims, children = [None]*3, []
    final_claim = None
    for i in range(4):
        reference = state_to_bytes(keccak_f1600_round(state_from_bytes(current), start+i))
        output = reference
        if profile.startswith('middle-') and i == boundary:
            changed = bytearray(reference)
            changed[slot] ^= 1
            output = claims[i] = bytes(changed)
        if profile.startswith('final-') and i == 3:
            changed = bytearray(reference)
            changed[slot] ^= 1
            output = final_claim = bytes(changed)
        children.append((current, reference, output))
        current = output
    honest = initial
    for r in range(start, start+4):
        honest = state_to_bytes(keccak_f1600_round(state_from_bytes(honest), r))
    return tuple(claims), final_claim, children, honest


def _truth(spec, values, ordinal):
    from bench_byte_kernels import _truth as truth
    return truth(spec, values, ordinal)


def _producer(round_index, slot):
    from keccak_trace import ROUND_CONSTANTS
    if type(round_index) is not int or not 0 <= round_index < 24 or type(slot) is not int or not 0 <= slot < 200:
        raise ValueError('canonical round and terminal byte slot required')
    masks = ROUND_CONSTANTS[round_index].to_bytes(8, 'little')
    if slot < 8 and masks[slot]:
        return 1216+sum(mask != 0 for mask in masks[:slot]), 1
    return 1016+slot, 2


def _consumers(offset, slot):
    if type(offset) is not int or offset < 0 or type(slot) is not int or not 0 <= slot < 200:
        raise ValueError('canonical child offset and initial byte slot required')
    lane, byte = divmod(slot, 8)
    x, y = lane % 5, lane//5
    return ((offset+x*32+byte*4+max(y-1, 0), 0 if y == 0 else 1),
            (offset+240+slot, 0))


def _structure(plan, spec, start):
    ids = tuple(plan.global_ids)
    names = tuple(word for word, _ in spec.words)
    slots = {word: i for i, word in enumerate(names)}
    if (ids != names or len(slots) != len(names) or len(plan.children) != 4 or len(plan.joins) != 3
            or any(type(bound) is not int or bound != 256 for _, bound in spec.words)):
        raise ValueError('one injective BYTE parent catalogue required')
    for state, ports in ((start, plan.inputs), (start+4, plan.outputs)):
        expected = tuple(f'byte-state/{state}/l{i//8}/byte{i%8}' for i in range(200))
        if tuple(ports) != expected or any(word not in slots for word in expected):
            raise ValueError('parent initial/terminal ports are not the exact ordered BYTE states')
    maps, offsets, offset = [], [], 0
    for child in plan.children:
        child_ids = tuple(child.global_ids)
        mapping = tuple(slots[word] for word in child_ids)
        if len(mapping) != len(child.spec.words) or len(set(mapping)) != len(mapping):
            raise ValueError('every child word map must be injective')
        maps.append(mapping)
        offsets.append(offset)
        offset += len(child.spec.leaves)
    if offset != len(spec.leaves) or len(spec.words) != 200+len(spec.leaves):
        raise ValueError('parent must preserve every child leaf and one fresh output per gate')
    for i in range(4):
        for j in range(i+1, 4):
            expected = {slots[f'byte-state/{start+j}/l{k//8}/byte{k%8}'] for k in range(200)} if j == i+1 else set()
            if set(maps[i]) & set(maps[j]) != expected:
                raise ValueError('child intersections must contain only exact adjacent states')
    for i, join in enumerate(plan.joins):
        expected = tuple(f'byte-state/{start+i+1}/l{k//8}/byte{k%8}' for k in range(200))
        if (join.index != i or join.state_round != start+i+1 or tuple(join.words) != expected
                or tuple(join.indices) != tuple(slots[word] for word in expected)
                or len(join.producer_ordinals) != 200 or len(join.producer_occurrences) != 200
                or len(join.consumer_occurrences) != 200):
            raise ValueError('ordered three-join source map changed')
        for slot, (word, producer, occurrence, consumers) in enumerate(zip(expected, join.producer_ordinals,
                join.producer_occurrences, join.consumer_occurrences, strict=True)):
            local_producer, formal = _producer(start+i, slot)
            if (type(producer) is not int or producer != offsets[i]+local_producer
                    or type(occurrence) is not int or occurrence != formal
                    or spec.leaves[producer].wires[formal] != slots[word]
                    or tuple(consumers) != _consumers(offsets[i+1], slot)):
                raise ValueError('each shared BYTE requires its actual producer and two consumers')
            for ordinal, occurrence in consumers:
                if type(ordinal) is not int or type(occurrence) is not int:
                    raise ValueError('exact integer consumer occurrence coordinates required')
                leaf = spec.leaves[ordinal]
                if leaf.wires[occurrence] != slots[word] or leaf.kind != 'byte_xor':
                    raise ValueError('shared BYTE consumer occurrence detached from the parent word')
    if len(plan.producer_ordinals) != 200:
        raise ValueError('all natural terminal producers required')
    for slot, (word, producer) in enumerate(zip(plan.outputs, plan.producer_ordinals, strict=True)):
        local_producer, formal = _producer(start+3, slot)
        if type(producer) is not int or producer != offsets[3]+local_producer or spec.leaves[producer].wires[formal] != slots[word]:
            raise ValueError('natural final producer is not the actual terminal BYTE')
    if {index for leaf in spec.leaves for index in leaf.wires} != set(range(len(spec.words))):
        raise ValueError('whole parent word coverage required')
    return maps, offsets


def _one(index, role, start, profile, boundary, slot, directory):
    _guard()
    from byte_keccak_block import build_byte_keccak_block
    from bench_byte_keccak_round import _auth_shapes
    name, initial = _name(role, start, profile, boundary), _initial(start)
    claims, final, pipeline, honest = _pipeline(start, initial, profile, boundary, slot)
    caller = f'{OPERATION}/s{start}'
    plan = build_byte_keccak_block(start, context=CONTEXT, role=role, operation_id=caller)
    binding = plan.bind(initial, boundary_claims=claims, claimed_output=final)
    spec, values = binding.spec, binding.assignment
    if (spec.context != CONTEXT.hex() or spec.field_role != role
            or spec.operation_id != f'{caller}/rounds/{start}-{start+3}'
            or binding.initial_state != initial or binding.reference_output != honest
            or binding.output_state != pipeline[-1][2] or len(binding.children) != 4
            or tuple(binding.boundaries) != tuple(child[2] for child in pipeline[:3])):
        raise ValueError('fresh four-round identity/reference/pipeline mismatch')
    maps, offsets = _structure(plan, spec, start)
    children = []
    for i, (child, actual, expected) in enumerate(zip(plan.children, binding.children, pipeline, strict=True)):
        if (actual.initial_state, actual.reference_output, actual.output_state) != expected:
            raise ValueError('downstream child must be recomputed from the actual claimed boundary')
        children.append(dict(round=start+i, operation_id=child.spec.operation_id,
            program_sha256=child.spec.program_sha256, catalogue_id=child.spec.digest().hex(),
            source_sha256=child.source_sha256.hex(), wordmap_sha256=_hash_list(maps[i]),
            words=len(child.spec.words), leaves=len(child.spec.leaves), first_leaf=offsets[i],
            input_state_hex=actual.initial_state.hex(), output_state_hex=actual.output_state.hex()))
    if profile == 'oversized':
        values[plan.inputs[0]] = 0xffffffff
    false = [i for i in range(len(spec.leaves)) if not _truth(spec, values, i)]
    if profile.startswith('middle-'):
        expected_false = [plan.joins[boundary].producer_ordinals[slot]]
    elif profile.startswith('final-'):
        expected_false = [plan.producer_ordinals[slot]]
    elif profile == 'oversized':
        expected_false = [0, 240]
    else:
        expected_false = []
    if false != expected_false:
        raise ValueError('exact single-producer or decoder-invalid block failure required')
    if set(values) != {word for word, _ in spec.words} or any(type(v) is not int or not 0 <= v <= 0xffffffff for v in values.values()):
        raise ValueError('complete signed-u32 parent assertion required')
    case = dict(name=name, spec=spec.json(), expected_spec_id=spec.digest().hex(),
        words=[values[word] for word, _ in spec.words],
        checks=[dict(ordinal=i, expected_correct=i not in false) for i in range(len(spec.leaves))], measure_all=True)
    filename = f'case-{index:02d}.json'
    info = _write_json(directory/filename, case, MAX_CASE_BYTES)
    descriptor = dict(name=name, profile=profile, role=role, start_round=start,
        boundary_index=boundary, byte_slot=slot, filename=filename, **info,
        catalogue_id=spec.digest().hex(), program_sha256=spec.program_sha256,
        source_sha256=plan.source_sha256.hex(), global_ids_sha256=_hash_list(plan.global_ids),
        words=len(spec.words), leaves=len(spec.leaves), input_state_hex=initial.hex(),
        expected_terminal_state_hex=binding.output_state.hex(), expected_false=false, children=children)
    census = dict(normal_leaf_checks=len(spec.leaves), source_guard_layouts=_auth_shapes(spec))
    census['guard_vectors'] = 14*census['source_guard_layouts']
    del plan, binding, spec, values, maps, case
    return descriptor, census


def _generate(directory):
    _guard()
    rows, census = [], []
    for index, (role, start, profile, boundary, slot) in enumerate(_requests()):
        row, counts = _one(index, role, start, profile, boundary, slot, directory)
        rows.append(row)
        census.append(counts)
    if len(rows) != MAX_CASES:
        raise ValueError('exact32 streamed four-round parent cases required')
    manifest = dict(schema=SCHEMA, context=CONTEXT.hex(), operation_id=OPERATION, cases=rows)
    info = _write_json(directory/'manifest.json', manifest, MAX_MANIFEST_BYTES)
    return manifest, info, census


def _new_directory(path):
    cwd = Path.cwd().resolve()
    owner, target = (cwd/'results').resolve(), Path(path).resolve()
    if owner == cwd or not owner.is_relative_to(cwd) or target == owner or not target.is_relative_to(owner):
        raise ValueError('BYTE block corpus must stay beneath canonical cwd/results')
    owner.mkdir(exist_ok=True)
    target.mkdir(parents=True, exist_ok=False, mode=0o700)
    return target


def _worker(path):
    source = Path(path)
    if source.is_symlink():
        raise ValueError('owned regular byte_keccak_block executable required')
    target = source.resolve()
    entry = target.lstat()
    if (not stat.S_ISREG(entry.st_mode) or entry.st_uid != os.getuid()
            or target.name != 'byte_keccak_block' or not os.access(target, os.X_OK)):
        raise ValueError('trusted configured owned byte_keccak_block executable required')
    return target


def _execute(worker, directory, manifest_sha):
    output = directory/'native-execution.json'
    if output.exists():
        raise ValueError('fresh direct BYTE block result required')
    command = ['/usr/bin/prlimit', '--as=536870912', '--cpu=1200', '--fsize=16777216', '--',
        str(worker), str(directory/'manifest.json'), str(directory), str(output), manifest_sha]
    environment = dict(os.environ, RAYON_NUM_THREADS='2', CUDA_VISIBLE_DEVICES='', RUST_BACKTRACE='0')
    with tempfile.TemporaryFile(dir=directory) as stdout, tempfile.TemporaryFile(dir=directory) as stderr:
        try:
            result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                                    timeout=1260, check=False, env=environment)
        except subprocess.TimeoutExpired as error:
            raise ValueError('direct BYTE block worker exceeded wall-time limit') from error
        if result.returncode != 0:
            stderr.seek(0)
            raise ValueError(f'direct BYTE block worker failed ({result.returncode}): '+stderr.read(8192).decode('utf-8', 'replace'))
        for stream in (stdout, stderr):
            stream.seek(0, 2)
            if stream.tell() > MAX_RESULT_BYTES:
                raise ValueError('BYTE block diagnostic-output cap exceeded')
    if not output.is_file() or output.is_symlink() or output.stat().st_size > MAX_RESULT_BYTES:
        raise ValueError('bounded direct BYTE block output required')
    with output.open('rb') as stream:
        raw = stream.read(MAX_RESULT_BYTES+1)
    if len(raw) > MAX_RESULT_BYTES:
        raise ValueError('direct BYTE block output grew beyond cap')
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError('duplicate direct BYTE block result field')
            value[key] = item
        return value
    try:
        return json.loads(raw.decode('utf-8'), object_pairs_hook=unique,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite direct result')))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError('invalid direct BYTE block result JSON') from error


def _equal(actual, expected, label):
    if type(actual) is not type(expected) or actual != expected:
        raise ValueError('direct BYTE block result mismatch: '+label)


def _hex32(value):
    return type(value) is str and len(value) == 64 and all(c in '0123456789abcdef' for c in value)


def _validate(native, manifest, info, census):
    if type(native) is not dict or native.get('passed') is not True:
        raise ValueError('successful direct BYTE block result required')
    _equal(native.get('schema'), 'bitvm2-nova-byte-keccak-block-execution/v1', 'schema')
    _equal(native.get('input_manifest_sha256'), info['file_sha256'], 'fresh manifest identity')
    for flag in ('four_round_block_script_conformance_checked', 'all_parent_leaves_executed',
                 'boundary_opening_links_checked', 'children_projected_from_parent',
                 'test_keys_only', 'stack_limit_enabled'):
        if native.get(flag) is not True:
            raise ValueError('required four-round conformance missing: '+flag)
    for flag in ('raw_vector_file_written', 'op_cat_enabled', 'full_24_round_composition_verified',
                 'cross_block_linking_verified', 'full_permutation_verified', 'full_hash_verified',
                 'transcript_verified', 'proof_verified', 'complete_nova_verifier',
                 'complete_bitvm2_verifier', 'production_assertion_binding', 'bitcoin_transaction_graph',
                 'panic_is_rejection'):
        if native.get(flag) is not False:
            raise ValueError('BYTE block conformance scope exceeded: '+flag)
    for key in ('setup_calls', 'proving_jobs', 'native_proofs_verified', 'gpu_jobs', 'transactions_broadcast'):
        _equal(native.get(key), 0, key)
    records = native.get('compact_execution_records_bytes')
    if type(records) is not int or not 0 < records <= MAX_EXECUTION_RECORD_BYTES or not _hex32(native.get('compact_execution_records_sha256')):
        raise ValueError('bounded compact execution observations required')
    rows = native.get('cases')
    if type(rows) is not list or len(rows) != MAX_CASES or len(census) != MAX_CASES:
        raise ValueError('all32 streamed parent observations required')
    normal = guards = largest = 0
    for row, source, expected in zip(rows, manifest['cases'], census, strict=True):
        if type(row) is not dict:
            raise ValueError('typed four-round observation required')
        for key in ('name', 'profile', 'role', 'start_round', 'boundary_index', 'byte_slot'):
            if key not in row:
                raise ValueError('explicit BYTE block observation identity required')
            _equal(row[key], source[key], key)
        for key, value in (('cached_boundary_entries', 600), ('producer_consumer_opening_links', 1200),
                ('signature_entries_created', source['words']),
                ('child_declared_word_occurrences', source['words']+600),
                ('guard_layouts', expected['source_guard_layouts']),
                ('guard_vectors', expected['guard_vectors']), ('native_rejections', 24),
                ('map_rejections', 8), ('source_rejections', 12), ('cache_rejections', 18)):
            _equal(row.get(key), value, key)
        false = row.get('false_predicates')
        if type(false) is not list or any(type(i) is not int for i in false):
            raise ValueError('canonical integer false-predicate list required')
        _equal(false, source['expected_false'], 'exact actual parent false predicates')
        child_false = row.get('child_false_predicates')
        if type(child_false) is not list or len(child_false) != 4:
            raise ValueError('four child partitions of parent predicate results required')
        child_rows = row.get('children')
        if type(child_rows) is not list or len(child_rows) != 4:
            raise ValueError('all four preserved child identities required')
        for observed_child, child, observed_false in zip(child_rows, source['children'], child_false, strict=True):
            if type(observed_child) is not dict:
                raise ValueError('typed child projection metadata required')
            for key in ('round', 'operation_id', 'program_sha256', 'catalogue_id', 'source_sha256',
                        'wordmap_sha256', 'words', 'leaves', 'first_leaf'):
                _equal(observed_child.get(key), child[key], 'preserved child '+key)
            expected_false = [i-child['first_leaf'] for i in source['expected_false']
                              if child['first_leaf'] <= i < child['first_leaf']+child['leaves']]
            if type(observed_false) is not list or any(type(i) is not int for i in observed_false):
                raise ValueError('exact child-local integer predicate partition required')
            _equal(observed_false, expected_false, 'child-local parent predicate partition')
        joins = row.get('joins')
        if type(joins) is not list or len(joins) != 3:
            raise ValueError('all three authenticated joins required')
        for i, join in enumerate(joins):
            if type(join) is not dict:
                raise ValueError('typed authenticated join observation required')
            for key, value in (('index', i), ('state_round', source['start_round']+i+1),
                               ('cached_entries', 200), ('producer_consumer_opening_links', 400)):
                _equal(join.get(key), value, 'join '+key)
        parent = row.get('parent')
        if type(parent) is not dict:
            raise ValueError('sole parent cost ledger required')
        for key in ('program_sha256', 'catalogue_id', 'source_sha256', 'global_ids_sha256', 'words', 'leaves'):
            _equal(parent.get(key), source[key], 'parent '+key)
        _equal(parent.get('context'), manifest['context'], 'parent context')
        _equal(parent.get('executed_leaves'), source['leaves'], 'all parent leaves executed')
        for key in ('registry_id', 'compiled_stream_sha256'):
            if not _hex32(parent.get(key)):
                raise ValueError('actual parent registry/script stream identity required')
        size, leaf_max = parent.get('compiled_script_bytes'), parent.get('largest_disproof_leaf_bytes')
        if type(size) is not int or not 0 < size <= 1 << 28 or type(leaf_max) is not int or not 0 < leaf_max <= 100_000 or leaf_max > size:
            raise ValueError('parent Script accounting exceeds existing bounds')
        largest = max(largest, leaf_max)
        normal += expected['normal_leaf_checks']
        guards += expected['guard_vectors']
    words = sum(source['words'] for source in manifest['cases'])
    for key, value in (('signature_entries_created', words),
            ('child_declared_word_occurrences', words+32*600),
            ('cached_boundary_entries', 32*600), ('producer_consumer_opening_links', 32*1200)):
        _equal(native.get(key), value, 'all parents '+key)
    metrics = native.get('metrics')
    if type(metrics) is not dict:
        raise ValueError('actual parent execution metrics required')
    _equal(metrics.get('vectors'), 2*normal+guards, 'all correctness/disproof/guard executions')
    _equal(metrics.get('expected_rejections'), normal+guards, 'ordinary false modes and malformed guards')
    _equal(metrics.get('max_script_bytes'), largest, 'actual maximum Script size')
    for key in ('max_stack_items', 'max_witness_items'):
        if type(metrics.get(key)) is not int or not 0 < metrics[key] <= 1000:
            raise ValueError('parent stack/witness limit exceeded')
    payload = metrics.get('max_witness_payload_bytes')
    if type(payload) is not int or not 0 < payload <= 520*metrics['max_witness_items']:
        raise ValueError('parent witness payload limit exceeded')
    return rows


def run(cases_dir, native_worker):
    _guard()
    started = time.perf_counter()
    worker, directory = _worker(native_worker), _new_directory(cases_dir)
    manifest, info, census = _generate(directory)
    native = _execute(worker, directory, info['file_sha256'])
    rows = _validate(native, manifest, info, census)
    honest = [dict(name=row['name'], role=row['role'], start_round=row['start_round'],
        words=row['parent']['words'], leaves=row['parent']['leaves'],
        parent_script_bytes=row['parent']['compiled_script_bytes'],
        parent_registry_id=row['parent']['registry_id']) for row in rows if row['profile'] == 'honest']
    return dict(schema='bitvm2-nova-byte-keccak-block-conformance/v1', native=native,
        manifest=info, context_sha256=CONTEXT.hex(), operation_id=OPERATION, cases=MAX_CASES,
        honest_parent_ledger=honest, direct_native_worker_executed=True,
        external_result_receipt_loaded=False, parent_registry_components_per_case=1,
        rounds_per_parent=4, shared_boundary_words_per_parent=600,
        actual_opening_comparisons_per_parent=1200,
        isolated_child_costs_measured=False, parent_to_isolated_savings_ratio=None,
        full_24_round_composition_verified=False, cross_block_linking_verified=False,
        full_permutation_cost_projected=False, full_hash_verified=False, transcript_verified=False,
        proof_verified=False, bitvm2_script_verified=False, complete_bitvm2_verifier=False,
        production_assertion_binding=False, bitcoin_transaction_graph=False,
        setup_calls=0, proving_jobs=0, gpu_jobs=0, transactions_broadcast=0,
        wall_seconds=time.perf_counter()-started, parent_peak_rss_bytes=peak_rss(),
        scope='one four-round parent registry with three exact BYTE joins; no isolated-child cost ratio or full permutation claim')


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

