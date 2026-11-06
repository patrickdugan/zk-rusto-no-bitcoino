"""Hosted full24 BYTE catalogue execution and live selected Taproot membership.

The parent identity is a versioned manifest hash, not an oversized Program.
Fresh sealed factories, separate bounded canonical maps/manifests and a direct
trusted worker are mandatory. These eight fixtures establish no sponge/hash,
Nova transcript, proof or production transaction acceptance.
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

SCHEMA = 'bitvm2-nova-byte-keccak-permutation-run/v1'
CONTEXT = sha256(b'BITVM2-NOVA/BYTE-KECCAK-PERMUTATION-CONFORMANCE/v1').digest()
OPERATION = 'benchmark/byte-keccak-permutation/v1'
ROLES = ('pallas_scalar', 'vesta_scalar')
PROFILES = ('honest', 'middle-iota', 'final-chi', 'oversized')
WORDS, LEAVES = 29445, 29245
MAX_CASE_BYTES, MAX_MAP_BYTES, MAX_MANIFEST_BYTES, MAX_RESULT_BYTES = 32 << 20, 8 << 20, 1 << 20, 1 << 20
MAX_EXECUTION_RECORD_BYTES = 128 << 20


def _guard():
    if (os.environ.get('GITHUB_ACTIONS') != 'true'
            or os.environ.get('RUNNER_OS') != 'Linux' or sys.platform != 'linux'):
        raise ValueError('full BYTE permutation conformance is hosted GitHub Linux only')


def _requests():
    for role in ROLES:
        for profile in PROFILES:
            yield role, profile


def _name(role, profile):
    return f'{role}/perm-{profile}'


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('utf-8')


def _hash_list(values):
    return sha256(_canonical(list(values))).hexdigest()


def _record_budget():
    """Exact normal JSON byte count and conservative guard/tree bound, no graphs.

    Native records have exactly c/i/m/e/s/w, two64-hex hashes, compact JSON and
    newline. Normal i is integer; all guard/tree identifiers are <=64 bytes.
    Two tree calls/case are executed; four are budgeted conservatively here.
    """
    def size(name, ordinal, mode, expected):
        return len(_canonical(dict(c=name, i=ordinal, m=mode, e=expected,
                                   s='0'*64, w='0'*64)))+1
    from keccak_trace import ROUND_CONSTANTS
    masks = {byte for rc in ROUND_CONSTANTS for byte in rc.to_bytes(8, 'little') if byte}
    layouts = 10+len(masks)
    digits = sum(len(str(i)) for i in range(LEAVES))
    normal = guards = tree = 0
    for role, profile in _requests():
        name = _name(role, profile)
        normal += LEAVES*(size(name, 0, False, True)+size(name, 0, True, False))+2*(digits-LEAVES)
        maximum = max(size(name, 'g'*64, False, False), size(name, 'g'*64, True, False))
        guards += 14*layouts*maximum
        tree += 4*maximum
    result = dict(normal_records=2*8*LEAVES, normal_exact_bytes=normal,
        authenticated_layouts=layouts, guard_records=8*14*layouts,
        max_identifier_bytes=64, guard_upper_bytes=guards,
        conservative_tree_upper_bytes=tree, combined_upper_bytes=normal+guards+tree,
        hard_cap_bytes=MAX_EXECUTION_RECORD_BYTES)
    if result['combined_upper_bytes'] > MAX_EXECUTION_RECORD_BYTES:
        raise ValueError('full-permutation compact-record budget exceeds unchanged hard cap')
    return result


def _pipeline(profile):
    from keccak_trace import keccak_f1600_round, state_from_bytes, state_to_bytes
    initial = bytes((37*i+11) & 255 for i in range(200))
    claims, states, current, honest = [None]*23, [], initial, initial
    final_claim = None
    for r in range(24):
        output = state_to_bytes(keccak_f1600_round(state_from_bytes(current), r))
        honest = state_to_bytes(keccak_f1600_round(state_from_bytes(honest), r))
        if profile == 'middle-iota' and r == 3:
            changed = bytearray(output)
            changed[1] ^= 1  # Round3 byte0 has no Iota; BYTE1 has public mask128.
            output = claims[3] = bytes(changed)
        if profile == 'final-chi' and r == 23:
            changed = bytearray(output)
            changed[8] ^= 1
            output = final_claim = bytes(changed)
        current = output
        if r < 23:
            states.append(output)
    return initial, tuple(claims), final_claim, tuple(states), current, honest


def _structure(plan, spec):
    from bench_byte_keccak_block import _producer, _consumers
    from keccak_trace import ROUND_CONSTANTS
    names = tuple(word for word, _ in spec.words)
    indices = {word: i for i, word in enumerate(names)}
    if (len(spec.words), len(spec.leaves)) != (WORDS, LEAVES) or tuple(plan.global_ids) != names or len(indices) != WORDS:
        raise ValueError('complete injective full24 GraphSpec required')
    if any(type(bound) is not int or bound != 256 for _, bound in spec.words) or len(plan.blocks) != 6 or len(plan.joins) != 23:
        raise ValueError('full BYTE bounds, six block descriptors and23 joins required')
    for state, ports in ((0, plan.inputs), (24, plan.outputs)):
        if tuple(ports) != tuple(f'byte-state/{state}/l{i//8}/byte{i%8}' for i in range(200)):
            raise ValueError('exact ordered initial/final BYTE state ports required')
    offsets, offset = [], 0
    for r in range(24):
        offsets.append(offset)
        offset += 1216+sum(value != 0 for value in ROUND_CONSTANTS[r].to_bytes(8, 'little'))
    if offset != LEAVES:
        raise ValueError('independent absolute round leaf census mismatch')
    for r, join in enumerate(plan.joins):
        expected = tuple(f'byte-state/{r+1}/l{i//8}/byte{i%8}' for i in range(200))
        if (type(join.index) is not int or join.index != r or type(join.state_round) is not int or join.state_round != r+1
                or tuple(join.words) != expected or tuple(join.indices) != tuple(indices[word] for word in expected)
                or any(type(i) is not int for i in join.indices)
                or len(join.producer_ordinals) != 200 or len(join.producer_occurrences) != 200
                or len(join.consumer_occurrences) != 200):
            raise ValueError('exact ordered full-permutation join coordinates required')
        for slot, (word, producer, formal, consumers) in enumerate(zip(expected, join.producer_ordinals,
                join.producer_occurrences, join.consumer_occurrences, strict=True)):
            local, expected_formal = _producer(r, slot)
            if (type(producer) is not int or producer != offsets[r]+local
                    or type(formal) is not int or formal != expected_formal
                    or spec.leaves[producer].wires[formal] != indices[word]
                    or tuple(consumers) != _consumers(offsets[r+1], slot)):
                raise ValueError('actual producer and both distinct C/theta consumers required')
            for ordinal, occurrence in consumers:
                if (type(ordinal) is not int or type(occurrence) is not int
                        or spec.leaves[ordinal].wires[occurrence] != indices[word]):
                    raise ValueError('exact consumer occurrence must reuse the same full-parent BYTE')
    for slot, (word, producer, formal) in enumerate(zip(plan.outputs, plan.producer_ordinals, plan.producer_occurrences, strict=True)):
        local, expected_formal = _producer(23, slot)
        if (type(producer) is not int or producer != offsets[23]+local or type(formal) is not int
                or formal != expected_formal or spec.leaves[producer].wires[formal] != indices[word]):
            raise ValueError('natural final producer mapping changed')
    if {i for leaf in spec.leaves for i in leaf.wires} != set(range(WORDS)):
        raise ValueError('full parent catalogue must cover every asserted word')
    return offsets


def _one(index, role, profile, directory):
    _guard()
    from byte_keccak_permutation import build_byte_keccak_permutation, PROGRAM_DOMAIN, SOURCE_DOMAIN
    from bench_byte_keccak_round import _auth_shapes
    from bench_byte_kernels import _truth
    initial, claims, final, states, output, reference = _pipeline(profile)
    plan = build_byte_keccak_permutation(context=CONTEXT, role=role, operation_id=OPERATION)
    binding = plan.bind(initial, state_claims=claims, claimed_output=final)
    spec, values = binding.spec, binding.assignment
    if (binding.initial_state != initial or binding.states != states or binding.output_state != output
            or binding.reference_output != reference or spec.context != CONTEXT.hex()
            or spec.field_role != role or spec.operation_id != OPERATION):
        raise ValueError('fresh full24 identity/reference/state pipeline mismatch')
    _structure(plan, spec)
    if profile == 'oversized':
        values[plan.inputs[0]] = 0xffffffff
    selected = (plan.joins[3].producer_ordinals[1] if profile == 'middle-iota'
                else 0 if profile == 'oversized' else plan.producer_ordinals[8])
    false = [i for i in range(LEAVES) if not _truth(spec, values, i)]
    expected_false = [] if profile == 'honest' else [0, 240] if profile == 'oversized' else [selected]
    if false != expected_false or selected != (4870 if profile == 'middle-iota' else 0 if profile == 'oversized' else 29049):
        raise ValueError('full24 exact failed producer/decoder predicate expectations mismatch')
    if set(values) != set(plan.global_ids) or any(type(value) is not int or not 0 <= value <= 0xffffffff for value in values.values()):
        raise ValueError('complete signed-u32 full-parent assertion required')
    name = _name(role, profile)
    case = dict(name=name, spec=spec.json(), expected_spec_id=spec.digest().hex(),
        words=[values[word] for word, _ in spec.words],
        checks=[dict(ordinal=i, expected_correct=i not in false) for i in range(LEAVES)], measure_all=True)
    filename = f'case-{index:02d}.json'
    info = _write_json(directory/filename, case, MAX_CASE_BYTES)
    maps = plan.source_maps
    maps_filename = f'maps-{index:02d}.json'
    maps_info = _write_json(directory/maps_filename, maps, MAX_MAP_BYTES)
    if maps_info['file_sha256'] != plan.source_maps_sha256.hex():
        raise ValueError('canonical exported maps differ from the sealed plain SHA')
    del maps
    program_manifest, source_manifest = plan.program_manifest, plan.source_manifest
    program_filename, source_filename = f'program-{index:02d}.json', f'source-{index:02d}.json'
    program_info = _write_json(directory/program_filename, program_manifest, MAX_MANIFEST_BYTES)
    source_info = _write_json(directory/source_filename, source_manifest, MAX_MANIFEST_BYTES)
    if (sha256(PROGRAM_DOMAIN+_canonical(program_manifest)).digest() != plan.program_sha256
            or plan.program_sha256.hex() != spec.program_sha256
            or source_manifest['program_manifest_sha256'] != program_info['file_sha256']
            or sha256(SOURCE_DOMAIN+_canonical(source_manifest)).digest() != plan.source_sha256):
        raise ValueError('versioned manifest identities must differ from plain file digests')
    blocks = [block.json() for block in plan.blocks]
    descriptor = dict(name=name, profile=profile, role=role, filename=filename, **info,
        catalogue_id=spec.digest().hex(), program_sha256=spec.program_sha256,
        source_sha256=plan.source_sha256.hex(), global_ids_sha256=_hash_list(plan.global_ids),
        words=WORDS, leaves=LEAVES, input_state_hex=initial.hex(), expected_output_state_hex=output.hex(),
        expected_false=false, state_index=4 if profile == 'middle-iota' else None,
        byte_slot=1 if profile == 'middle-iota' else 8 if profile == 'final-chi' else None,
        maps_filename=maps_filename, maps_file_sha256=maps_info['file_sha256'], maps_file_bytes=maps_info['file_bytes'],
        source_maps_sha256=plan.source_maps_sha256.hex(),
        program_manifest_filename=program_filename, program_manifest_file_sha256=program_info['file_sha256'],
        program_manifest_file_bytes=program_info['file_bytes'],
        source_manifest_filename=source_filename, source_manifest_file_sha256=source_info['file_sha256'],
        source_manifest_file_bytes=source_info['file_bytes'], blocks=blocks)
    census = dict(normal_leaf_checks=LEAVES, guard_layouts=_auth_shapes(spec), selected_leaf=selected)
    if census['guard_layouts'] != _record_budget()['authenticated_layouts']:
        raise ValueError('actual authenticated layouts differ from the record budget')
    census['guard_vectors'] = 14*census['guard_layouts']
    del plan, binding, spec, values, case, program_manifest, source_manifest
    return descriptor, census


def _generate(directory):
    _guard()
    _record_budget()
    rows, census = [], []
    for index, (role, profile) in enumerate(_requests()):
        row, counts = _one(index, role, profile, directory)
        rows.append(row)
        census.append(counts)
    if len(rows) != 8:
        raise ValueError('exactly eight bounded full24 cases required')
    manifest = dict(schema=SCHEMA, context=CONTEXT.hex(), operation_id=OPERATION, cases=rows)
    info = _write_json(directory/'manifest.json', manifest, MAX_MANIFEST_BYTES)
    return manifest, info, census


def _new_directory(path):
    cwd = Path.cwd().resolve()
    owner, target = (cwd/'results').resolve(), Path(path).resolve()
    if owner == cwd or not owner.is_relative_to(cwd) or target == owner or not target.is_relative_to(owner):
        raise ValueError('full BYTE corpus must stay beneath canonical cwd/results')
    owner.mkdir(exist_ok=True)
    target.mkdir(parents=True, exist_ok=False, mode=0o700)
    return target


def _worker(path):
    source = Path(path)
    if source.is_symlink():
        raise ValueError('owned regular byte_keccak_permutation executable required')
    target = source.resolve()
    entry = target.lstat()
    if (not stat.S_ISREG(entry.st_mode) or entry.st_uid != os.getuid()
            or target.name != 'byte_keccak_permutation' or not os.access(target, os.X_OK)):
        raise ValueError('trusted configured owned byte_keccak_permutation executable required')
    return target


def _execute(worker, directory, manifest_sha):
    output = directory/'native-execution.json'
    if output.exists():
        raise ValueError('fresh direct full BYTE result required')
    command = ['/usr/bin/prlimit', '--as=536870912', '--cpu=1200', '--fsize=16777216', '--',
        str(worker), str(directory/'manifest.json'), str(directory), str(output), manifest_sha]
    environment = dict(os.environ, RAYON_NUM_THREADS='2', CUDA_VISIBLE_DEVICES='', RUST_BACKTRACE='0')
    with tempfile.TemporaryFile(dir=directory) as stdout, tempfile.TemporaryFile(dir=directory) as stderr:
        try:
            result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                                    timeout=1260, check=False, env=environment)
        except subprocess.TimeoutExpired as error:
            raise ValueError('direct full BYTE worker exceeded wall-time limit') from error
        if result.returncode != 0:
            stderr.seek(0)
            raise ValueError(f'direct full BYTE worker failed ({result.returncode}): '+stderr.read(8192).decode('utf-8', 'replace'))
        for stream in (stdout, stderr):
            stream.seek(0, 2)
            if stream.tell() > MAX_RESULT_BYTES:
                raise ValueError('full BYTE diagnostic-output cap exceeded')
    if not output.is_file() or output.is_symlink() or output.stat().st_size > MAX_RESULT_BYTES:
        raise ValueError('bounded direct full BYTE output required')
    with output.open('rb') as stream:
        raw = stream.read(MAX_RESULT_BYTES+1)
    if len(raw) > MAX_RESULT_BYTES:
        raise ValueError('direct full BYTE output grew beyond cap')
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError('duplicate direct full BYTE result field')
            value[key] = item
        return value
    try:
        return json.loads(raw.decode('utf-8'), object_pairs_hook=unique,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite direct result')))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError('invalid direct full BYTE result JSON') from error


def _equal(actual, expected, label):
    if type(actual) is not type(expected) or actual != expected:
        raise ValueError('direct full BYTE result mismatch: '+label)


def _hex32(value):
    return type(value) is str and len(value) == 64 and all(c in '0123456789abcdef' for c in value)


def _control_bytes(ordinal):
    if type(ordinal) is not int or not 0 <= ordinal < LEAVES:
        raise ValueError('bounded selected Taproot ordinal required')
    height = LEAVES.bit_length()-1
    deep_leaves = 2*(LEAVES-(1 << height))
    return 33+32*(height+int(ordinal < deep_leaves))


def _round_failures(false):
    from keccak_trace import ROUND_CONSTANTS
    result, offset = [], 0
    for rc in ROUND_CONSTANTS:
        count = 1216+sum(value != 0 for value in rc.to_bytes(8, 'little'))
        result.append([i-offset for i in false if offset <= i < offset+count])
        offset += count
    return result


def _validate(native, manifest, info, census):
    if type(native) is not dict or native.get('passed') is not True:
        raise ValueError('successful direct full BYTE result required')
    _equal(native.get('schema'), 'bitvm2-nova-byte-keccak-permutation-execution/v1', 'schema')
    _equal(native.get('input_manifest_sha256'), info['file_sha256'], 'fresh manifest identity')
    for flag in ('full_24_round_script_conformance_checked', 'all_parent_leaves_executed',
                 'boundary_opening_links_checked', 'children_projected_from_parent',
                 'test_keys_only', 'stack_limit_enabled', 'hierarchical_membership_verified'):
        if native.get(flag) is not True:
            raise ValueError('required full BYTE fixture conformance missing: '+flag)
    for flag in ('raw_vector_file_written', 'op_cat_enabled', 'full_permutation_verified',
                 'full_hash_verified', 'transcript_verified', 'proof_verified', 'complete_nova_verifier',
                 'complete_bitvm2_verifier', 'production_assertion_binding', 'bitcoin_transaction_graph',
                 'panic_is_rejection'):
        if native.get(flag) is not False:
            raise ValueError('full BYTE conformance scope exceeded: '+flag)
    for key in ('setup_calls', 'proving_jobs', 'native_proofs_verified', 'gpu_jobs', 'transactions_broadcast'):
        _equal(native.get(key), 0, key)
    budget = _record_budget()
    records = native.get('compact_execution_records_bytes')
    if (type(records) is not int or not budget['normal_exact_bytes'] <= records <= budget['combined_upper_bytes']
            or records > MAX_EXECUTION_RECORD_BYTES or not _hex32(native.get('compact_execution_records_sha256'))):
        raise ValueError('actual compact record stream exceeds its independently derived unchanged budget')
    rows = native.get('cases')
    if type(rows) is not list or len(rows) != 8 or len(census) != 8:
        raise ValueError('all eight full BYTE observations required')
    negatives = {'altered_script', 'branch', 'parity', 'internal_key', 'leaf_version',
                 'truncated_control', 'appended_control', 'root', 'output_key', 'ordinal', 'registry', 'catalogue'}
    totals = dict(signature_entries_created=0, round_declared_word_occurrences=0,
        block_declared_word_occurrences=0, cached_boundary_entries=0, producer_consumer_opening_links=0,
        internal_cached_boundary_entries=0, internal_producer_consumer_opening_links=0,
        cross_block_cached_boundary_entries=0, cross_block_producer_consumer_opening_links=0)
    normal = guards = largest = 0
    for row, source, expected in zip(rows, manifest['cases'], census, strict=True):
        if type(row) is not dict:
            raise ValueError('typed full BYTE observation required')
        for key in ('name', 'profile', 'role', 'state_index', 'byte_slot'):
            if key not in row:
                raise ValueError('explicit full BYTE case identity required')
            _equal(row[key], source[key], key)
        for key, value in (('signature_entries_created', WORDS),
                ('round_declared_word_occurrences', WORDS+4600), ('block_declared_word_occurrences', WORDS+1000),
                ('cached_boundary_entries', 4600), ('producer_consumer_opening_links', 9200),
                ('internal_cached_boundary_entries', 3600), ('internal_producer_consumer_opening_links', 7200),
                ('cross_block_cached_boundary_entries', 1000), ('cross_block_producer_consumer_opening_links', 2000)):
            _equal(row.get(key), value, key)
            totals[key] += value
        for key, value in (('guard_layouts', expected['guard_layouts']), ('guard_vectors', expected['guard_vectors']),
                           ('native_rejections', 24), ('map_rejections', 8), ('source_rejections', 12), ('cache_rejections', 18),
                           ('selected_leaf', expected['selected_leaf']), ('additional_selected_engine_executions', 2)):
            _equal(row.get(key), value, key)
        false = row.get('false_predicates')
        if type(false) is not list or any(type(i) is not int for i in false):
            raise ValueError('canonical integer parent false-predicate list required')
        _equal(false, source['expected_false'], 'exact actual full BYTE false predicates')
        partitions = row.get('round_false_predicates')
        if (type(partitions) is not list or len(partitions) != 24
                or any(type(items) is not list or any(type(i) is not int for i in items) for items in partitions)):
            raise ValueError('canonical round-local parent predicate partitions required')
        _equal(partitions, _round_failures(source['expected_false']), 'round-local parent predicate partitions')
        honest = source['profile'] == 'honest'
        if (row.get('selected_correctness_execution_success') is not honest
                or row.get('selected_disproof_execution_success') is not (not honest)):
            raise ValueError('actual selected correctness/disproof result mismatch')
        blocks = row.get('blocks')
        if type(blocks) is not list or len(blocks) != 6:
            raise ValueError('all six genuine block projection identities required')
        for observed, block in zip(blocks, source['blocks'], strict=True):
            if type(observed) is not dict:
                raise ValueError('typed block metadata required')
            for key, value in block.items():
                _equal(observed.get(key), value, 'block '+key)
        joins = row.get('joins')
        if type(joins) is not list or len(joins) != 23:
            raise ValueError('all23 actual BYTE joins required')
        for i, join in enumerate(joins):
            if type(join) is not dict:
                raise ValueError('typed BYTE join observation required')
            for key, value in (('index', i), ('state_round', i+1), ('cached_entries', 200),
                               ('producer_consumer_opening_links', 400)):
                _equal(join.get(key), value, 'join '+key)
        parent = row.get('parent')
        if type(parent) is not dict:
            raise ValueError('sole full-parent ledger required')
        for key in ('catalogue_id', 'program_sha256', 'source_sha256', 'global_ids_sha256', 'source_maps_sha256', 'words', 'leaves'):
            _equal(parent.get(key), source[key], 'parent '+key)
        _equal(parent.get('context'), manifest['context'], 'parent context')
        _equal(parent.get('executed_leaves'), LEAVES, 'every parent leaf actually executed')
        for key in ('registry_id', 'compiled_stream_sha256'):
            if not _hex32(parent.get(key)):
                raise ValueError('actual parent registry/script stream identity required')
        size, leaf_max = parent.get('compiled_script_bytes'), parent.get('largest_disproof_leaf_bytes')
        if (type(size) is not int or not 0 < size <= 256 << 20 or type(leaf_max) is not int
                or not 0 < leaf_max <= 100_000 or leaf_max > size):
            raise ValueError('actual full-parent Script accounting exceeds unchanged limits')
        tree = row.get('tree')
        if type(tree) is not dict:
            raise ValueError('actual freshly constructed full Taproot tree required')
        for key, value in (('leaf_count', LEAVES), ('compiled_script_bytes', size),
                           ('compiled_stream_sha256', parent['compiled_stream_sha256'])):
            _equal(tree.get(key), value, 'full disproof tree '+key)
        if tree.get('hierarchical_membership_verified') is not True or tree.get('roots_independently_pinned') is not False:
            raise ValueError('live selected membership must not imply independently pinned production roots')
        for key in ('merkle_root', 'output_key', 'control_block_sha256', 'selected_script_sha256'):
            if not _hex32(tree.get(key)):
                raise ValueError('actual full Taproot identity missing: '+key)
        control = tree.get('control_block_bytes')
        if type(control) is not int or control != _control_bytes(expected['selected_leaf']):
            raise ValueError('full-tree selected control depth outside unchanged balanced layout')
        rejected = tree.get('negative_counts')
        if (type(rejected) is not dict or set(rejected) != negatives
                or any(type(value) is not int or value != 1 for value in rejected.values())):
            raise ValueError('all12 selected Taproot negative controls required')
        normal += LEAVES
        guards += expected['guard_vectors']
        largest = max(largest, leaf_max)
    for key, value in totals.items():
        _equal(native.get(key), value, 'all permutations '+key)
    metrics = native.get('metrics')
    if type(metrics) is not dict:
        raise ValueError('actual native full permutation metrics required')
    _equal(metrics.get('vectors'), 2*normal+guards+2*8, 'all normal, guard and selected-tree executions')
    _equal(metrics.get('expected_rejections'), normal+guards+8, 'ordinary false modes, malformed guards and tree checks')
    _equal(metrics.get('max_script_bytes'), largest, 'actual maximum Script size')
    for key in ('max_stack_items', 'max_witness_items'):
        if type(metrics.get(key)) is not int or not 0 < metrics[key] <= 1000:
            raise ValueError('full permutation stack/witness limit exceeded')
    payload = metrics.get('max_witness_payload_bytes')
    if type(payload) is not int or not 0 < payload <= 520*metrics['max_witness_items']:
        raise ValueError('full permutation witness payload limit exceeded')
    return rows


def run(cases_dir, native_worker):
    _guard()
    started = time.perf_counter()
    budget = _record_budget()
    worker, directory = _worker(native_worker), _new_directory(cases_dir)
    manifest, info, census = _generate(directory)
    native = _execute(worker, directory, info['file_sha256'])
    rows = _validate(native, manifest, info, census)
    honest = [dict(name=row['name'], role=row['role'], words=row['parent']['words'],
        leaves=row['parent']['leaves'], parent_script_bytes=row['parent']['compiled_script_bytes'],
        parent_registry_id=row['parent']['registry_id'], merkle_root=row['tree']['merkle_root'],
        output_key=row['tree']['output_key']) for row in rows if row['profile'] == 'honest']
    return dict(schema='bitvm2-nova-byte-keccak-permutation-conformance/v1', native=native,
        manifest=info, compact_record_budget=budget, context_sha256=CONTEXT.hex(), operation_id=OPERATION,
        cases=8, honest_parent_ledger=honest, direct_native_worker_executed=True,
        external_result_receipt_loaded=False, program_identity_kind='domain-separated manifest hash; not Program.digest',
        full_24_round_script_conformance_checked=True, parent_registry_components_per_case=1,
        shared_boundary_words_per_parent=4600, actual_opening_comparisons_per_parent=9200,
        selected_live_taproot_disproof_membership_checked=True, roots_independently_pinned=False,
        full_permutation_verified=False, full_hash_verified=False, transcript_verified=False,
        proof_verified=False, bitvm2_script_verified=False, complete_nova_verifier=False,
        complete_bitvm2_verifier=False, production_assertion_binding=False, bitcoin_transaction_graph=False,
        setup_calls=0, proving_jobs=0, gpu_jobs=0, transactions_broadcast=0,
        wall_seconds=time.perf_counter()-started, parent_peak_rss_bytes=peak_rss(),
        scope='complete BYTE permutation fixture/Script conformance and live selected Taproot membership; no sponge, transcript, proof or production claim')


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

