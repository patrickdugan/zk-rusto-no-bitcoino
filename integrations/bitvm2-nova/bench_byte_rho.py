"""Hosted framed two-hash rho and reduction conformance with explicit coverage.

HI, LO and tail are streamed separately under one scenario key/signature pool.
Four cases execute every leaf; four targeted cases execute every tail leaf and
the specified source consumers. Every case still compiles all three catalogues,
checks all native reference predicates/links and builds the complete forest.
External message origins are not Nova-proof or prior-transcript Script binding.
"""
import argparse
from hashlib import sha256
import json
import math
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time

from bench_compact import peak_rss
from bench_keccak_endpoint import _write_json

SCHEMA = 'bitvm2-nova-byte-rho-run/v1'
CONTEXT = sha256(b'BITVM2-NOVA/BYTE-RHO-CONFORMANCE/v1').digest()
OPERATION = 'benchmark/byte-rho/v1'
COUNTERS = {'pallas_scalar': 59, 'vesta_scalar': 44}
PROFILES = ('honest', 'bad-hi-digest', 'bad-lo-frame', 'wrong-result')
BRANCHES = ('hi', 'lo', 'tail')
TRACE_FILE = Path(__file__).resolve().parent/'fixtures'/'nht4-genesis-0-2020-k5.trace.json'
TRACE_SHA256 = '394d90b302b2fe6b8f5c0a65ada372d820996f3230770a816961a75cefec59b8'
MAX_CASE_BYTES, MAX_MAP_BYTES, MAX_MANIFEST_BYTES, MAX_RESULT_BYTES = 32 << 20, 8 << 20, 1 << 20, 1 << 20
MAX_EXECUTION_RECORD_BYTES = 128 << 20


def _guard():
    if (os.environ.get('GITHUB_ACTIONS') != 'true'
            or os.environ.get('RUNNER_OS') != 'Linux' or sys.platform != 'linux'):
        raise ValueError('BYTE rho conformance is hosted GitHub Linux only')


def _requests():
    for role, counter in COUNTERS.items():
        for profile in PROFILES:
            yield role, counter, profile


def _name(role, profile):
    return f'{role}/rho-{profile}'


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('utf-8')


def _hash_list(values):
    return sha256(_canonical(list(values))).hexdigest()


def _selection(profile, component):
    if type(component) is not int or not 0 <= component < 3 or profile not in PROFILES:
        raise ValueError('canonical rho component and profile required')
    if profile in ('honest', 'bad-hi-digest') or component == 2:
        return 'all', None
    if profile == 'bad-lo-frame' and component == 1:
        return 'selected', [125, 351]
    return 'none', None


def _record_budget():
    """Exact normal records; conservative per-component guard/tree upper bound."""
    def size(name, index, mode, expected):
        return len(_canonical(dict(c=name, i=index, m=mode, e=expected,
                                   s='0'*64, w='0'*64)))+1
    leaves, tail = 29245, 453
    digits = sum(len(str(i)) for i in range(leaves))
    normal = normal_count = guards = tree = 0
    for role, _, profile in _requests():
        name = _name(role, profile)
        for component in range(3):
            mode, selected = _selection(profile, component)
            count = leaves if component < 2 else tail
            if mode == 'all' and component < 2:
                normal += count*(size(name, [component, 0], False, True)+size(name, [component, 0], True, False))+2*(digits-count)
                normal_count += 2*count
            elif mode != 'none':
                ordinals = range(count) if mode == 'all' else selected
                for ordinal in ordinals:
                    normal += size(name, [component, ordinal], False, True)+size(name, [component, ordinal], True, False)
                    normal_count += 2
        maximum = max(size(name, 'g'*64, False, False), size(name, 'g'*64, True, False))
        # Each tail leaf being its own authenticated shape is an intentionally
        # loose safe bound. Actual shapes are counted from fresh hosted sources.
        guards += 14*(23+23+tail)*maximum
        tree += 4*maximum
    result = dict(normal_records=normal_count, normal_exact_bytes=normal,
        maximum_tail_guard_layouts=tail, max_identifier_bytes=64,
        guard_upper_bytes=guards, conservative_tree_upper_bytes=tree,
        combined_upper_bytes=normal+guards+tree, hard_cap_bytes=MAX_EXECUTION_RECORD_BYTES)
    if result['combined_upper_bytes'] > MAX_EXECUTION_RECORD_BYTES:
        raise ValueError('rho compact-record budget exceeds unchanged hard cap')
    return result


def _role_input(role):
    """Bounded literal-pinned fixture selection, never proof receipt authority."""
    _guard()
    from production_transcript import keccak256
    from trace import ROLES
    if role not in COUNTERS:
        raise ValueError('supported scalar fixture role required')
    with TRACE_FILE.open('rb') as stream:
        raw = stream.read((1 << 20)+1)
    if len(raw) > 1 << 20 or sha256(raw).hexdigest() != TRACE_SHA256:
        raise ValueError('retained rho fixture differs from literal trace pin')
    trace = json.loads(raw.decode('utf-8'))
    engine, counter = ('pallas' if role == 'pallas_scalar' else 'vesta'), COUNTERS[role]
    streams = [s for s in trace['streams'] if s['kind'] == 'keccak' and s['engine'] == engine and s['session'] == 0]
    if len(streams) != 1:
        raise ValueError('one retained engine transcript required')
    events = streams[0]['events']
    matches = [(i, e) for i, e in enumerate(events) if e['op'] == 'squeeze'
               and e['label_hex'] == '72' and e['after']['round'] == counter+1]
    if len(matches) != 1 or matches[0][0] == 0:
        raise ValueError('one retained rho squeeze at the caller-owned counter required')
    i, event = matches[0]
    previous = events[i-1]
    eval_w, prior = bytes.fromhex(previous['repr_hex']), bytes.fromhex(previous['after']['state_hex'])
    if (previous['op'] != 'absorb' or previous['label_hex'] != '77' or len(eval_w) != 32 or len(prior) != 64
            or previous['after']['round'] != counter or bytes.fromhex(previous['after']['buffer_hex']) != b'w'+eval_w
            or int.from_bytes(eval_w, 'little') >= ROLES[role]):
        raise ValueError('retained canonical eval_W/prior/counter framing mismatch')
    prefix = b'w'+eval_w+b'NoDS'+counter.to_bytes(8, 'little')+prior+b'r'
    raw_state = keccak256(prefix+b'\0')+keccak256(prefix+b'\1')
    result = int.from_bytes(raw_state, 'little') % ROLES[role]
    if raw_state.hex() != event['after']['state_hex'] or result.to_bytes(32, 'little').hex() != event['challenge_le']:
        raise ValueError('mature retained two-hash/field reduction mismatch')
    return eval_w, prior, dict(trace_sha256=TRACE_SHA256, event_sequence=i,
        engine=engine, counter=counter, honest_raw_state_le=raw_state.hex(),
        honest_result_le=result.to_bytes(32, 'little').hex())


def _reference(eval_w, prior, counter):
    from byte_rho import framed_state_bytes
    from keccak_trace import keccak_f1600, state_from_bytes, state_to_bytes
    return tuple(state_to_bytes(keccak_f1600(state_from_bytes(
        framed_state_bytes(eval_w, prior, counter=counter, branch=branch)))) for branch in ('hi', 'lo'))


def _truth(spec, values, ordinal, program=None):
    if program is None:
        from bench_byte_kernels import _truth as byte_truth
        return byte_truth(spec, values, ordinal)
    from bench_digest_reduce import _truth as uniform_truth
    return uniform_truth(program, spec, values, ordinal)


def _case(name, spec, values, mode, ordinals, program=None):
    if set(values) != {word for word, _ in spec.words} or any(type(value) is not int or not 0 <= value <= 0xffffffff for value in values.values()):
        raise ValueError('complete signed-u32 component assertion required')
    false = [i for i in range(len(spec.leaves)) if not _truth(spec, values, i, program)]
    chosen = list(range(len(spec.leaves))) if mode == 'all' else [] if mode == 'none' else list(ordinals)
    return dict(name=name, spec=spec.json(), expected_spec_id=spec.digest().hex(),
        words=[values[word] for word, _ in spec.words], measure_all=True,
        checks=[dict(ordinal=i, expected_correct=i not in false) for i in chosen]), false, chosen


def _map_checks(maps):
    from bench_byte_keccak_block import _consumers, _producer
    from keccak_trace import ROUND_CONSTANTS
    components = maps['components']
    ids = [tuple(component['global_ids']) for component in components]
    if len(ids) != 3 or tuple(map(len, ids)) != (29445, 29445, 587) or any(len(set(part)) != len(part) for part in ids):
        raise ValueError('complete injective three-component maps required')
    sets = [set(part) for part in ids]
    if (len(sets[0] & sets[1]), len(sets[0] & sets[2]), len(sets[1] & sets[2]),
            len(sets[0] & sets[1] & sets[2]), len(set.union(*sets))) != (96, 136, 136, 0, 59109):
        raise ValueError('rho aliases exceed exact message/frame/digest intersections')
    if len(maps['messages']) != 96 or len(maps['frames']) != 208 or len(maps['digests']) != 64:
        raise ValueError('complete origin/frame/digest link maps required')
    if maps['uniform']['word_map'] != list(range(379)) or maps['uniform']['leaf_map'] != list(range(244))+[452]:
        raise ValueError('all245 original uniform leaf occurrences must survive')
    for i, message in enumerate(maps['messages']):
        hi, lo = message['hi_word'], message['lo_word']
        slot = i+1 if i < 32 else i-32+45
        expected_uses = [list(pair) for pair in _consumers(0, slot)]
        if (ids[0][hi] != message['global_id'] or ids[1][lo] != message['global_id'] or message['index'] != i
                or message['hi_consumer_occurrences'] != expected_uses
                or message['lo_consumer_occurrences'] != expected_uses):
            raise ValueError('both branches must consume identical declared message origins')
    for i, frame in enumerate(maps['frames']):
        branch = 0 if frame['branch'] == 'hi' else 1
        if (frame['index'] != i or frame['anchor_ordinal'] != 244+i
                or ids[branch][frame['source_word']] != frame['global_id']
                or ids[2][frame['tail_word']] != frame['global_id']
                or frame['source_consumer_occurrences'] != [list(pair) for pair in _consumers(0, frame['byte_index'])]):
            raise ValueError('each frame anchor must bind both actual initial-state consumers')
    for i, digest in enumerate(maps['digests']):
        branch = 1 if i < 32 else 0
        last_offset = sum(1216+sum(b != 0 for b in rc.to_bytes(8, 'little')) for rc in ROUND_CONSTANTS[:23])
        producer, occurrence = _producer(23, i % 32)
        if (digest['index'] != i or digest['branch'] != ('lo' if i < 32 else 'hi')
                or digest['byte_index'] != i % 32 or digest['consumer_ordinal'] != 1+i
                or digest['consumer_occurrence'] != 0
                or digest['producer_ordinal'] != last_offset+producer
                or digest['producer_occurrence'] != occurrence
                or ids[branch][digest['source_word']] != digest['global_id']
                or ids[2][digest['tail_word']] != digest['global_id']):
            raise ValueError('LO||HI must bind the exact original unit-adapter input ports')


def _one(index, role, counter, profile, directory):
    _guard()
    from byte_rho import build_byte_rho, SOURCE_DOMAIN
    from bench_byte_keccak_round import _auth_shapes
    from trace import ROLES
    name = _name(role, profile)
    eval_w, prior, fixture = _role_input(role)
    reference_hi, reference_lo = _reference(eval_w, prior, counter)
    honest_raw = reference_lo[:32]+reference_hi[:32]
    honest_result, honest_q = int.from_bytes(honest_raw, 'little') % ROLES[role], int.from_bytes(honest_raw, 'little')//ROLES[role]
    if honest_raw.hex() != fixture['honest_raw_state_le']:
        raise ValueError('independent word reference differs from pinned mature rho fixture')
    claims = {}
    if profile == 'bad-hi-digest':
        changed = bytearray(reference_hi)
        changed[0] ^= 1
        claims['claimed_hi_output'] = bytes(changed)
    elif profile == 'bad-lo-frame':
        claims['padding_fault'] = 'lo'
    elif profile == 'wrong-result':
        claims.update(claimed_result=honest_result-1 if honest_result else 1, claimed_quotient=honest_q)
    plan = build_byte_rho(context=CONTEXT, role=role, counter=counter, operation_id=OPERATION)
    binding = plan.bind(eval_w, prior, **claims)
    rho_maps, rho_source = plan.source_maps, plan.manifest
    _map_checks(rho_maps)
    rho_maps_filename, rho_source_filename = f'rho-maps-{index:02d}.json', f'rho-source-{index:02d}.json'
    map_info = _write_json(directory/rho_maps_filename, rho_maps, MAX_MAP_BYTES)
    source_info = _write_json(directory/rho_source_filename, rho_source, MAX_MANIFEST_BYTES)
    if (map_info['file_sha256'] != plan.source_maps_sha256.hex()
            or sha256(SOURCE_DOMAIN+_canonical(rho_source)).digest() != plan.source_sha256):
        raise ValueError('canonical rho files differ from their sealed identities')
    headers, census, seen = [], [], {}
    for record in binding.iter_components():
        component, branch = record.index, record.branch
        spec, values, ids = record.spec, record.assignment, tuple(record.global_ids)
        descriptor = record.descriptor.json()
        if branch != BRANCHES[component] or ids != tuple(rho_maps['components'][component]['global_ids']):
            raise ValueError('streamed component order/global map differs from sealed rho source')
        for global_id, (word, _) in zip(ids, spec.words, strict=True):
            if global_id in seen and seen[global_id] != values[word]:
                raise ValueError('same global key cannot assert conflicting component values')
            seen[global_id] = values[word]
        mode, selected = _selection(profile, component)
        program = record.tail.program if component == 2 else None
        case, false, chosen = _case(name+'/'+branch, spec, values, mode, selected, program)
        expected_false = [29241] if profile == 'bad-hi-digest' and component == 0 else [363] if profile == 'bad-lo-frame' and component == 2 else []
        if profile == 'wrong-result' and component == 2:
            if not false or (honest_result and false != [record.tail.uniform.column_constraints[0]]):
                raise ValueError('canonical wrong result must refute its integer reduction')
        elif false != expected_false:
            raise ValueError('rho exact source/anchor fault expectations mismatch')
        stem = f'{index:02d}-{branch}'
        filename = f'case-{stem}.json'
        case_info = _write_json(directory/filename, case, MAX_CASE_BYTES)
        child_maps = record.child_source_maps
        maps_filename, source_filename = f'maps-{stem}.json', f'source-{stem}.json'
        child_maps_info = _write_json(directory/maps_filename, child_maps, MAX_MAP_BYTES)
        child_source = record.child_source_manifest
        child_source_info = _write_json(directory/source_filename, child_source, MAX_MANIFEST_BYTES)
        child_program = record.child_program_manifest
        program_filename = f'program-{stem}.json' if child_program is not None else None
        program_info = _write_json(directory/program_filename, child_program, MAX_MANIFEST_BYTES) if child_program is not None else None
        if child_maps_info['file_sha256'] != descriptor['source_maps_sha256'] or _hash_list(ids) != descriptor['global_ids_sha256']:
            raise ValueError('component canonical map file/global projection differs from descriptor')
        full = None
        if component < 2:
            full = dict(name=name+'/'+branch, profile=profile, role=role,
                filename=filename, **case_info, catalogue_id=spec.digest().hex(), program_sha256=spec.program_sha256,
                source_sha256=descriptor['source_sha256'], global_ids_sha256=child_maps['global_ids_sha256'],
                words=len(spec.words), leaves=len(spec.leaves),
                input_state_hex=(binding.initial_hi if component == 0 else binding.initial_lo).hex(),
                expected_output_state_hex=(binding.hi_output if component == 0 else binding.lo_output).hex(),
                expected_false=false, state_index=None, byte_slot=None,
                maps_filename=maps_filename, maps_file_sha256=child_maps_info['file_sha256'], maps_file_bytes=child_maps_info['file_bytes'],
                source_maps_sha256=descriptor['source_maps_sha256'], program_manifest_filename=program_filename,
                program_manifest_file_sha256=program_info['file_sha256'], program_manifest_file_bytes=program_info['file_bytes'],
                source_manifest_filename=source_filename, source_manifest_file_sha256=child_source_info['file_sha256'],
                source_manifest_file_bytes=child_source_info['file_bytes'], blocks=child_program['blocks'])
        headers.append(dict(descriptor=descriptor, filename=filename, **case_info,
            maps_filename=maps_filename, maps_file_sha256=child_maps_info['file_sha256'], maps_file_bytes=child_maps_info['file_bytes'],
            program_manifest_filename=program_filename,
            program_manifest_file_sha256=None if program_info is None else program_info['file_sha256'],
            program_manifest_file_bytes=None if program_info is None else program_info['file_bytes'],
            source_manifest_filename=source_filename, source_manifest_file_sha256=child_source_info['file_sha256'],
            source_manifest_file_bytes=child_source_info['file_bytes'], execution_mode=mode,
            selected_ordinals=selected, expected_false=false, full=full))
        census.append(dict(selected_leaf_checks=len(chosen), guard_layouts=_auth_shapes(spec),
                           words=len(spec.words), leaves=len(spec.leaves)))
        # Release every large alias before asking the streaming factory for LO
        # or tail. Only scalar values/IDs and compact descriptors are retained.
        del record, spec, values, ids, case, child_maps, child_source, child_program, program
    if len(headers) != 3 or len(seen) != 59109:
        raise ValueError('complete three-component global assertion inventory required')
    group = dict(name=name, profile=profile, role=role, counter=counter,
        execution_mode='full' if profile in ('honest', 'bad-hi-digest') else 'targeted',
        source_sha256=plan.source_sha256.hex(), source_maps_sha256=plan.source_maps_sha256.hex(),
        eval_w_le=eval_w.hex(), prior_state_hex=prior.hex(), expected_hi_output_state_hex=binding.hi_output.hex(),
        expected_lo_output_state_hex=binding.lo_output.hex(), expected_raw_state_le=binding.raw_state.hex(),
        expected_result_le=binding.result_value.to_bytes(32, 'little').hex(),
        expected_quotient_le=binding.quotient_value.to_bytes(33, 'little').hex(),
        rho_source_filename=rho_source_filename, rho_source_file_sha256=source_info['file_sha256'], rho_source_file_bytes=source_info['file_bytes'],
        rho_maps_filename=rho_maps_filename, rho_maps_file_sha256=map_info['file_sha256'], rho_maps_file_bytes=map_info['file_bytes'],
        components=headers)
    del binding, plan, rho_maps, rho_source, seen
    return group, census


def _generate(directory):
    _guard()
    _record_budget()
    rows, census = [], []
    for index, (role, counter, profile) in enumerate(_requests()):
        row, counts = _one(index, role, counter, profile, directory)
        rows.append(row)
        census.append(counts)
    manifest = dict(schema=SCHEMA, context=CONTEXT.hex(), operation_id=OPERATION, cases=rows)
    info = _write_json(directory/'manifest.json', manifest, MAX_MANIFEST_BYTES)
    return manifest, info, census


def _new_directory(path):
    _guard()
    cwd = Path.cwd().resolve()
    owner, target = (cwd/'results').resolve(), Path(path).resolve()
    if owner == cwd or not owner.is_relative_to(cwd) or target == owner or not target.is_relative_to(owner):
        raise ValueError('rho corpus must stay beneath canonical cwd/results')
    owner.mkdir(exist_ok=True)
    target.mkdir(parents=True, exist_ok=False, mode=0o700)
    return target


def _worker(path):
    _guard()
    source = Path(path)
    if source.is_symlink():
        raise ValueError('owned regular byte_rho executable required')
    target = source.resolve()
    entry = target.lstat()
    if (not stat.S_ISREG(entry.st_mode) or entry.st_uid != os.getuid()
            or target.name != 'byte_rho' or not os.access(target, os.X_OK)):
        raise ValueError('trusted configured owned byte_rho executable required')
    return target


def _execute(worker, directory, manifest_sha):
    _guard()
    output = directory/'native-execution.json'
    if output.exists():
        raise ValueError('fresh direct rho result required')
    command = ['/usr/bin/prlimit', '--as=536870912', '--cpu=1200', '--fsize=16777216', '--',
        str(worker), str(directory/'manifest.json'), str(directory), str(output), manifest_sha]
    environment = dict(os.environ, RAYON_NUM_THREADS='2', CUDA_VISIBLE_DEVICES='', RUST_BACKTRACE='0')
    with tempfile.TemporaryFile(dir=directory) as stdout, tempfile.TemporaryFile(dir=directory) as stderr:
        try:
            result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                                    timeout=1260, check=False, env=environment)
        except subprocess.TimeoutExpired as error:
            raise ValueError('direct rho worker exceeded wall-time limit') from error
        if result.returncode != 0:
            stderr.seek(0)
            raise ValueError(f'direct rho worker failed ({result.returncode}): '+stderr.read(8192).decode('utf-8', 'replace'))
        for stream in (stdout, stderr):
            stream.seek(0, 2)
            if stream.tell() > MAX_RESULT_BYTES:
                raise ValueError('rho diagnostic-output cap exceeded')
    if not output.is_file() or output.is_symlink() or output.stat().st_size > MAX_RESULT_BYTES:
        raise ValueError('bounded direct rho output required')
    with output.open('rb') as stream:
        raw = stream.read(MAX_RESULT_BYTES+1)
    if len(raw) > MAX_RESULT_BYTES:
        raise ValueError('direct rho output grew beyond cap')
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError('duplicate direct rho result field')
            value[key] = item
        return value
    try:
        return json.loads(raw.decode('utf-8'), object_pairs_hook=unique,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite direct result')))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError('invalid direct rho result JSON') from error


def _equal(actual, expected, label):
    if type(actual) is not type(expected) or actual != expected:
        raise ValueError('direct rho result mismatch: '+label)
    if type(expected) is list:
        for i, (left, right) in enumerate(zip(actual, expected, strict=True)):
            _equal(left, right, f'{label}[{i}]')
    elif type(expected) is dict:
        for key in expected:
            _equal(actual[key], expected[key], label+'.'+key)


def _hex32(value):
    return type(value) is str and len(value) == 64 and all(c in '0123456789abcdef' for c in value)


def _selected(source):
    profile = source['profile']
    if profile == 'honest':
        return 2, 452
    if profile == 'bad-hi-digest':
        return 0, 29241
    if profile == 'bad-lo-frame':
        return 2, 363
    false = source['components'][2]['expected_false']
    if not false or any(type(i) is not int or not 0 <= i < 453 for i in false):
        raise ValueError('canonical wrong result requires an actual tail counterexample')
    return 2, false[0]


def _control_bytes(component, ordinal):
    if type(component) is not int or not 0 <= component < 3:
        raise ValueError('bounded selected rho component required')
    count = (29245, 29245, 453)[component]
    if type(ordinal) is not int or not 0 <= ordinal < count:
        raise ValueError('bounded selected rho leaf required')
    height = count.bit_length()-1
    deep = 2*(count-(1 << height))
    return 33+32*(height+int(ordinal < deep)+(2 if component < 2 else 1))


COUNTS = dict(signature_entries_created=59109, cached_signature_reuses=368,
    message_origins=96, message_consumer_opening_links=384,
    framing_anchors=208, framing_consumer_opening_links=416,
    digest_producer_consumer_links=64, internal_cached_boundary_entries=9200,
    internal_producer_consumer_opening_links=18400)
TRUE_FLAGS = ('framed_rho_script_conformance_checked', 'all_native_reference_predicates_checked',
    'boundary_opening_links_checked', 'framing_constants_script_bound',
    'both_digest_endpoints_script_bound', 'digest_reduction_script_bound',
    'test_keys_only', 'stack_limit_enabled', 'hierarchical_membership_verified')
FALSE_FLAGS = ('all_cases_full_statement_executed', 'raw_vector_file_written', 'op_cat_enabled',
    'full_permutation_verified', 'full_hash_verified', 'transcript_verified',
    'nova_transcript_verified_in_script', 'proof_verified', 'complete_nova_verifier',
    'complete_bitvm2_verifier', 'production_assertion_binding', 'bitcoin_transaction_graph',
    'panic_is_rejection', 'eval_w_canonicality_script_bound', 'dynamic_message_sources_script_bound',
    'eval_w_proof_origin_bound', 'prior_state_transcript_bound', 'complete_keccak_sponge')
FOREST_NEGATIVES = ('altered_script', 'branch', 'parity', 'internal_key', 'leaf_version',
    'truncated_control', 'appended_control', 'manifest', 'root', 'output_key',
    'component', 'ordinal', 'reordered_components')


def _validate(native, manifest, info, census):
    if type(native) is not dict or native.get('passed') is not True:
        raise ValueError('successful direct rho result required')
    _equal(native.get('schema'), 'bitvm2-nova-byte-rho-execution/v1', 'schema')
    _equal(native.get('input_manifest_sha256'), info['file_sha256'], 'fresh manifest identity')
    for flag in TRUE_FLAGS:
        if native.get(flag) is not True:
            raise ValueError('required bounded rho conformance missing: '+flag)
    for flag in FALSE_FLAGS:
        if native.get(flag) is not False:
            raise ValueError('bounded rho scope exceeded: '+flag)
    for key in ('setup_calls', 'proving_jobs', 'native_proofs_verified', 'gpu_jobs', 'transactions_broadcast'):
        _equal(native.get(key), 0, key)
    budget = _record_budget()
    size = native.get('compact_execution_records_bytes')
    if (type(size) is not int or not budget['normal_exact_bytes'] <= size <= budget['combined_upper_bytes']
            or size > MAX_EXECUTION_RECORD_BYTES or not _hex32(native.get('compact_execution_records_sha256'))):
        raise ValueError('actual rho record stream exceeds independent unchanged budget')
    rows = native.get('cases')
    if type(rows) is not list or len(rows) != 8 or len(census) != 8:
        raise ValueError('all eight ordered full/targeted rho observations required')
    normal = guards = largest = 0
    for row, source, counts in zip(rows, manifest['cases'], census, strict=True):
        if type(row) is not dict:
            raise ValueError('typed rho observation required')
        for key in ('name', 'profile', 'role', 'counter', 'execution_mode', 'source_sha256', 'source_maps_sha256',
                    'expected_raw_state_le', 'expected_result_le', 'expected_quotient_le'):
            _equal(row.get(key), source[key], key)
        for key, expected in COUNTS.items():
            _equal(row.get(key), expected, key)
        selected_component, selected_leaf = _selected(source)
        expected_checks = sum(count['selected_leaf_checks'] for count in counts)
        expected_guards = 14*sum(count['guard_layouts'] for count in counts)
        for key, expected in (('all_native_predicates_checked', 58943), ('selected_leaf_checks', expected_checks),
                ('guard_layouts', sum(count['guard_layouts'] for count in counts)), ('guard_vectors', expected_guards),
                ('native_rejections', 72), ('map_rejections', 8), ('source_rejections', 12), ('cache_rejections', 30),
                ('selected_component', selected_component), ('selected_leaf', selected_leaf),
                ('additional_selected_engine_executions', 2)):
            _equal(row.get(key), expected, key)
        honest = source['profile'] == 'honest'
        _equal(row.get('full_statement_executed'), source['execution_mode'] == 'full', 'full statement execution scope')
        if row.get('selected_correctness_execution_success') is not honest or row.get('selected_disproof_execution_success') is not (not honest):
            raise ValueError('actual selected rho correctness/disproof result mismatch')
        components = row.get('components')
        if type(components) is not list or len(components) != 3 or len(counts) != 3:
            raise ValueError('all three measured rho component ledgers required')
        compiled = 0
        for component, header, count in zip(components, source['components'], counts, strict=True):
            if type(component) is not dict:
                raise ValueError('typed measured rho component required')
            descriptor = header['descriptor']
            for key, value in descriptor.items():
                _equal(component.get(key), value, 'component '+key)
            _equal(component.get('context'), manifest['context'], 'component context')
            _equal(component.get('execution_mode'), header['execution_mode'], 'component execution mode')
            _equal(component.get('selected_ordinals'), header['selected_ordinals'], 'component selected ordinals')
            _equal(component.get('executed_leaves'), count['selected_leaf_checks'], 'actual selected leaf count')
            _equal(component.get('native_predicates_checked'), descriptor['leaves'], 'all native predicate truth')
            _equal(component.get('false_predicates'), header['expected_false'], 'complete native false-predicate list')
            _equal(component.get('guard_layouts'), count['guard_layouts'], 'component authenticated layouts')
            _equal(component.get('guard_vectors'), 14*count['guard_layouts'], 'component malformed witness guards')
            for key in ('registry_id', 'compiled_stream_sha256'):
                if not _hex32(component.get(key)):
                    raise ValueError('actual component registry/Script stream identity required')
            byte_count, maximum = component.get('compiled_script_bytes'), component.get('largest_disproof_leaf_bytes')
            if (type(byte_count) is not int or not 0 < byte_count <= 256 << 20 or type(maximum) is not int
                    or not 0 < maximum <= min(byte_count, 100_000)):
                raise ValueError('actual component Script accounting exceeds unchanged limits')
            compiled += byte_count
            largest = max(largest, maximum)
        forest = row.get('forest')
        if type(forest) is not dict:
            raise ValueError('fresh complete three-component Taproot forest required')
        for key, expected in (('components', 3), ('leaf_count', 58943), ('compiled_script_bytes', compiled),
                ('selected_component', selected_component), ('selected_leaf', selected_leaf),
                ('control_block_bytes', _control_bytes(selected_component, selected_leaf))):
            _equal(forest.get(key), expected, 'forest '+key)
        if compiled > 5 << 28:
            raise ValueError('whole rho forest Script accounting exceeds unchanged 1.25 GiB cap')
        if forest.get('hierarchical_membership_verified') is not True or forest.get('roots_independently_pinned') is not False:
            raise ValueError('live forest membership cannot imply pinned production roots')
        for key in ('merkle_root', 'output_key', 'control_block_sha256', 'selected_script_sha256',
                    'component_manifest_sha256', 'compiled_stream_sha256'):
            if not _hex32(forest.get(key)):
                raise ValueError('actual forest identity missing: '+key)
        _equal(forest.get('negative_counts'), {key: 1 for key in FOREST_NEGATIVES}, 'all13 forest negative controls')
        normal += expected_checks
        guards += expected_guards
    for key, value in COUNTS.items():
        _equal(native.get(key), 8*value, 'all rho cases '+key)
    for key, value in (('native_rejections', 72), ('map_rejections', 8), ('source_rejections', 12), ('cache_rejections', 30)):
        if key in native:
            _equal(native[key], 8*value, 'reported total '+key)
    _equal(native.get('full_statement_cases'), 4, 'full Script coverage cases')
    _equal(native.get('targeted_statement_cases'), 4, 'targeted Script coverage cases')
    metrics = native.get('metrics')
    if type(metrics) is not dict:
        raise ValueError('actual rho execution metrics required')
    _equal(metrics.get('vectors'), 2*normal+guards+16, 'all selected, guard and forest C/D executions')
    _equal(metrics.get('expected_rejections'), normal+guards+8, 'ordinary false modes, malformed guards and forest checks')
    _equal(metrics.get('max_script_bytes'), largest, 'actual maximum Script size')
    for key in ('max_stack_items', 'max_witness_items'):
        if type(metrics.get(key)) is not int or not 0 < metrics[key] <= 1000:
            raise ValueError('rho stack/witness limit exceeded')
    payload = metrics.get('max_witness_payload_bytes')
    if type(payload) is not int or not 0 < payload <= 520*metrics['max_witness_items']:
        raise ValueError('rho witness payload limit exceeded')
    wall = native.get('wall_seconds')
    if type(wall) not in (int, float) or not math.isfinite(wall) or not 0 <= wall <= 1260:
        raise ValueError('bounded actual native rho wall time required')
    return rows


def run(cases_dir, native_worker):
    _guard()
    started = time.perf_counter()
    budget = _record_budget()
    worker, directory = _worker(native_worker), _new_directory(cases_dir)
    manifest, info, census = _generate(directory)
    native = _execute(worker, directory, info['file_sha256'])
    rows = _validate(native, manifest, info, census)
    honest = [dict(name=row['name'], role=row['role'], counter=row['counter'],
        component_script_bytes=[part['compiled_script_bytes'] for part in row['components']],
        complete_forest_script_bytes=row['forest']['compiled_script_bytes'],
        merkle_root=row['forest']['merkle_root'], output_key=row['forest']['output_key'])
        for row in rows if row['profile'] == 'honest']
    return dict(schema='bitvm2-nova-byte-rho-conformance/v1', native=native, manifest=info,
        compact_record_budget=budget, context_sha256=CONTEXT.hex(), operation_id=OPERATION,
        cases=8, full_execution_cases=4, targeted_execution_cases=4, honest_forest_ledger=honest,
        direct_native_worker_executed=True, external_result_receipt_loaded=False,
        components_per_case=3, leaves_per_complete_forest=58943, unique_global_words_per_case=59109,
        shared_message_origins=96, framing_anchors=208, digest_to_reducer_opening_links=64,
        native_admission_rejections=sum(row['native_rejections'] for row in rows),
        map_rejections=sum(row['map_rejections'] for row in rows),
        source_rejections=sum(row['source_rejections'] for row in rows),
        cache_rejections=sum(row['cache_rejections'] for row in rows),
        dynamic_message_sources_script_bound=False, eval_w_canonicality_script_bound=False,
        eval_w_proof_origin_bound=False, prior_state_transcript_bound=False,
        full_permutation_verified=False, full_hash_verified=False, transcript_verified=False,
        proof_verified=False, bitvm2_script_verified=False, complete_nova_verifier=False,
        complete_bitvm2_verifier=False, production_assertion_binding=False, bitcoin_transaction_graph=False,
        setup_calls=0, proving_jobs=0, gpu_jobs=0, transactions_broadcast=0,
        wall_seconds=time.perf_counter()-started, parent_peak_rss_bytes=peak_rss(),
        scope='three-component framed two-hash/rho fixture conformance with explicit full/targeted Script coverage; external proof/transcript origins remain open')


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

