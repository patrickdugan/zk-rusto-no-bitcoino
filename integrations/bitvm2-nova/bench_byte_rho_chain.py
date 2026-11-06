"""Hosted rho-to-next-challenge fixture conformance with explicit coverage.

Only two honest cases execute all five full permutations. Fault cases retain
complete native reference/link checks and tree measurement, with bounded actual
Script selections. External proof and transcript origins remain open.
"""
from hashlib import sha256
import argparse
import json
import math
import os
from pathlib import Path
import stat
import sys
import time

from bench_byte_rho import (_canonical, _equal, _execute, _hex32, _new_directory,
                            _role_input, MAX_CASE_BYTES, MAX_MAP_BYTES,
                            MAX_MANIFEST_BYTES, MAX_RESULT_BYTES, TRACE_FILE, TRACE_SHA256)
from bench_compact import peak_rss
from bench_keccak_endpoint import _write_json


CONTEXT = sha256(b'BITVM2-NOVA/BYTE-RHO-CHAIN-CONFORMANCE/v1').digest()
OPERATION = 'benchmark/byte-rho-chain/v1'
SCHEMA = 'bitvm2-nova-byte-rho-chain-run/v1'
COMPONENT_LEAVES = (29245, 29245, 453, 111, 29245, 9, 29245, 29245, 245)
COMPONENT_WORDS = (29445, 29445, 587, 187, 29445, 23, 29445, 29445, 379)
BRANCHES = ('rho-hi', 'rho-lo', 'rho-tail', 'c-coeff-frame', 'c-prefix',
            'c-absorb', 'c-hi', 'c-lo', 'c-uniform')
FULL_COMPONENTS = frozenset((0, 1, 4, 6, 7))
MAX_EXECUTION_RECORD_BYTES = 128 << 20
MAX_TARGET_ENGINE_EXECUTIONS = 2048


def _guard():
    if (os.environ.get('GITHUB_ACTIONS') != 'true'
            or os.environ.get('RUNNER_OS') != 'Linux' or sys.platform != 'linux'):
        raise ValueError('BYTE rho chain conformance is hosted GitHub Linux only')


def _requests():
    # Short record labels map to semantic identities in the closed pinned run
    # header; no role/profile/context is omitted from admission authority.
    for prefix, role, counter in (('p', 'pallas_scalar', 59), ('v', 'vesta_scalar', 44)):
        yield prefix+'/h', role, counter, 'honest'
        yield prefix+'/r', role, counter, 'coherent-rho-raw'
        yield prefix+'/p', role, counter, 'coherent-prefix-capacity'


def _probe_requests():
    probes = ('coefficient-c0-modulus', 'coefficient-c2-modulus', 'frame-counter',
              'frame-NoDS', 'frame-tag', 'frame-zero-capacity', 'absorb-wrong-xor',
              'absorb-selector', 'absorb-delimiter', 'absorb-end-mask')
    for prefix, role in (('p', 'pallas_scalar'), ('v', 'vesta_scalar')):
        for index, kind in enumerate(probes):
            yield f'{prefix}/q{index}', role, kind, 3 if index < 6 else 5, 111 if index < 6 else 9


def _record_budget():
    """Exact normal bytes plus conservative unchanged guards/probe/tree caps.

    New small leaves may each be their own authenticated shape. Existing rho
    tail has 61 measured shapes; the unchanged uniform projection has at most
    61. The target reserve is
    2,048 actual engine calls per fault case in addition to small-leaf execution,
    every authenticated-shape guard and the two selected forest rechecks.
    """
    def size(name, index, mode, expected):
        return len(_canonical(dict(c=name, i=index, m=mode, e=expected,
                                   s='0'*64, w='0'*64)))+1

    def all_bytes(name, component, count):
        digits = 1+sum(max(0, min(count, 10**width)-10**(width-1))*width
                       for width in range(1, len(str(count-1))+1))
        return count*(size(name, [component, 0], False, True)
                      +size(name, [component, 0], True, False))+2*(digits-count)

    full = small = guards = tree = target = 0
    guard_layouts = 5*23+61+61+111+9
    for name, _, _, profile in _requests():
        for component, count in enumerate(COMPONENT_LEAVES):
            if component in FULL_COMPONENTS:
                if profile == 'honest':
                    full += all_bytes(name, component, count)
            else:
                small += all_bytes(name, component, count)
        maximum = max(size(name, 'g'*64, False, False), size(name, 'g'*64, True, False))
        guards += 14*guard_layouts*maximum
        tree += 2*maximum
        if profile != 'honest':
            target += MAX_TARGET_ENGINE_EXECUTIONS*maximum
    probe_normal = probe_guards = probe_tree = 0
    for name, _, _, _, count in _probe_requests():
        for ordinal in range(count):
            probe_normal += size(name, ordinal, False, True)+size(name, ordinal, True, False)
        maximum = max(size(name, 'g'*64, False, False), size(name, 'g'*64, True, False))
        probe_guards += 14*count*maximum
        probe_tree += 2*maximum
    main = full+small+guards+tree+target
    probes = probe_normal+probe_guards+probe_tree
    result = dict(full_honest_records=584900, full_honest_exact_bytes=full,
        all_small_records=9816, all_small_exact_bytes=small,
        max_authenticated_layouts_per_case=guard_layouts,
        guard_upper_bytes=guards, forest_recheck_upper_bytes=tree,
        max_target_engine_executions_per_fault=MAX_TARGET_ENGINE_EXECUTIONS,
        target_upper_bytes=target, max_identifier_bytes=64,
        main_upper_bytes=main, standalone_probe_records=2808,
        standalone_probe_exact_bytes=probe_normal,
        standalone_probe_guard_upper_bytes=probe_guards,
        standalone_probe_tree_upper_bytes=probe_tree, standalone_probe_upper_bytes=probes,
        combined_upper_bytes=main+probes,
        hard_cap_bytes=MAX_EXECUTION_RECORD_BYTES)
    if result['combined_upper_bytes'] > MAX_EXECUTION_RECORD_BYTES:
        raise ValueError('rho-chain record budget exceeds unchanged hard cap')
    return result


def _selection(profile, component):
    if type(component) is not int or not 0 <= component < 9:
        raise ValueError('bounded chain component required')
    if profile not in ('honest', 'coherent-rho-raw', 'coherent-prefix-capacity'):
        raise ValueError('closed chain profile required')
    if profile == 'honest' or component not in FULL_COMPONENTS:
        return 'all', None
    if profile == 'coherent-rho-raw':
        if component == 0:
            return 'selected', [_terminal_producer(31)[0]]
        if component in (6, 7):
            return 'selected', [16, 244]
    elif profile == 'coherent-prefix-capacity':
        if component == 4:
            return 'selected', [_terminal_producer(136)[0]]
        if component in (6, 7):
            return 'selected', [66, 376]
    return 'none', None


def _terminal_producer(byte):
    from bench_byte_keccak_block import _producer
    from keccak_trace import ROUND_CONSTANTS
    ordinal, formal = _producer(23, byte)
    offset = sum(1216+sum(value != 0 for value in rc.to_bytes(8, 'little'))
                 for rc in ROUND_CONSTANTS[:23])
    return offset+ordinal, formal


def _fixture(role):
    """Recompute the two retained squeezes; fixture provenance is not proof authority."""
    _guard()
    from production_transcript import keccak256
    from trace import ROLES
    eval_w, prior, rho = _role_input(role)
    with TRACE_FILE.open('rb') as stream:
        raw = stream.read((1 << 20)+1)
    if len(raw) > 1 << 20 or sha256(raw).hexdigest() != TRACE_SHA256:
        raise ValueError('following-c fixture differs from independent literal trace pin')
    trace = json.loads(raw.decode('utf-8'))
    streams = [value for value in trace['streams'] if value['kind'] == 'keccak'
               and value['engine'] == rho['engine'] and value['session'] == 0]
    if len(streams) != 1:
        raise ValueError('one pinned following-c stream required')
    events = streams[0]['events']
    squeeze, absorb, following = events[rho['event_sequence']:rho['event_sequence']+3]
    coefficients = bytes.fromhex(absorb['repr_hex'])
    rho_raw = bytes.fromhex(rho['honest_raw_state_le'])
    counter = rho['counter']+1
    if (len(coefficients) != 64 or absorb['op'] != 'absorb' or absorb['label_hex'] != '70'
            or absorb['after']['round'] != counter or bytes.fromhex(absorb['after']['buffer_hex']) != b'p'+coefficients
            or bytes.fromhex(absorb['after']['state_hex']) != rho_raw
            or following['op'] != 'squeeze' or following['label_hex'] != '63'
            or following['after']['round'] != counter+1 or following['after']['buffer_hex'] != ''
            or squeeze['sequence'] != rho['event_sequence']):
        raise ValueError('exact adjacent rho/p/c framing required')
    pair = coefficients[:32], coefficients[32:]
    if any(int.from_bytes(value, 'little') >= ROLES[role] for value in pair):
        raise ValueError('canonical compressed c0/c2 fixture required')
    message = b'p'+coefficients+b'NoDS'+counter.to_bytes(8, 'little')+rho_raw+b'c'
    wide = keccak256(message+b'\0')+keccak256(message+b'\1')
    result = (int.from_bytes(wide, 'little') % ROLES[role]).to_bytes(32, 'little')
    if len(message) != 142 or wide.hex() != following['after']['state_hex'] or result.hex() != following['challenge_le']:
        raise ValueError('independent mature143-byte following-c fixture mismatch')
    return eval_w, prior, pair, dict(rho, c_counter=counter, c_event_sequence=following['sequence'],
                                   honest_c_raw_state_le=wide.hex(), honest_c_result_le=result.hex())


def _truth(spec, values, ordinal, program):
    if program is None or spec.leaves[ordinal].kind.startswith('byte_'):
        from bench_byte_kernels import _truth as byte_truth
        return byte_truth(spec, values, ordinal)
    from bench_digest_reduce import _truth as arithmetic_truth
    return arithmetic_truth(program, spec, values, ordinal)


def _case(name, spec, values, mode, selected, program):
    if set(values) != {word for word, _ in spec.words} or any(type(value) is not int
            or not 0 <= value <= 0xffffffff for value in values.values()):
        raise ValueError('complete signed-u32 chain assertion required')
    false = [i for i in range(len(spec.leaves)) if not _truth(spec, values, i, program)]
    ordinals = list(range(len(spec.leaves))) if mode == 'all' else [] if mode == 'none' else list(selected)
    return dict(name=name, spec=spec.json(), expected_spec_id=spec.digest().hex(),
        words=[values[word] for word, _ in spec.words], measure_all=True,
        checks=[dict(ordinal=i, expected_correct=i not in false) for i in ordinals]), false, ordinals


def _worker(path):
    _guard()
    source = Path(path)
    if source.is_symlink():
        raise ValueError('owned regular byte_rho_chain executable required')
    target = source.resolve()
    entry = target.lstat()
    if (not stat.S_ISREG(entry.st_mode) or entry.st_uid != os.getuid()
            or target.name != 'byte_rho_chain' or not os.access(target, os.X_OK)):
        raise ValueError('trusted configured owned byte_rho_chain executable required')
    return target


CONNECTION_COUNTS = dict(rho_messages=96, rho_frames=208, rho_reduction=64,
    coefficients=64, prefix_frame=77, rho_raw_prefix=59, rho_raw_absorb=5,
    prefix_absorb=9, prefix_suffix=383, absorb_suffix=17, c_reduction=64)


def _check_interfaces(record, facts):
    """Check exposed occurrences against actual leaves, independently of values."""
    from bench_byte_keccak_block import _consumers
    spec, ids = record.spec, record.global_ids
    if (facts['index'] != record.index or facts['branch'] != record.branch
            or facts['global_ids_sha256'] != sha256(_canonical(list(ids))).hexdigest()):
        raise ValueError('actual streamed interface identity differs from sealed maps')
    for row in facts['interfaces']:
        word = row['word_index']
        if (type(word) is not int or not 0 <= word < len(spec.words)
                or ids[word] != row['global_id'] or type(row['bound']) is not int
                or spec.words[word][1] != row['bound'] or not row['occurrences']):
            raise ValueError('actual interface word identity or decoder bound differs')
        for ordinal, formal in row['occurrences']:
            if spec.leaves[ordinal].wires[formal] != word:
                raise ValueError('exposed interface must name an actual predicate occurrence')
    if record.index in FULL_COMPONENTS:
        lookup = {row['word_index']: row for row in facts['interfaces']}
        for byte, word in enumerate(facts['input_indices']):
            _equal(lookup[word]['occurrences'], [list(pair) for pair in _consumers(0, byte)], 'both actual initial-state consumers')
        for byte, word in enumerate(facts['output_indices']):
            producer, formal = _terminal_producer(byte)
            _equal(lookup[word]['occurrences'], [[producer, formal]], 'natural terminal BYTE producer')


def _full_states(binding, index):
    return {0:(binding.initial_rho_hi, binding.rho_hi_output),
            1:(binding.initial_rho_lo, binding.rho_lo_output),
            4:(binding.initial_prefix, binding.prefix_output),
            6:(binding.initial_c_hi, binding.c_hi_output),
            7:(binding.initial_c_lo, binding.c_lo_output)}[index]


def _one(index, name, role, rho_counter, profile, directory):
    _guard()
    from byte_rho_chain import build_byte_rho_chain, SOURCE_DOMAIN
    from bench_byte_keccak_round import _auth_shapes
    eval_w, prior, coefficients, fixture = _fixture(role)
    plan = build_byte_rho_chain(context=CONTEXT, role=role, rho_counter=rho_counter, operation_id=OPERATION)
    binding = plan.bind(eval_w, prior, coefficients)
    if (binding.raw_rho.hex() != fixture['honest_raw_state_le']
            or binding.raw_c.hex() != fixture['honest_c_raw_state_le']
            or binding.c_result_value.to_bytes(32, 'little').hex() != fixture['honest_c_result_le']):
        raise ValueError('fresh honest chain differs from pinned mature transcript fixtures')
    if profile == 'coherent-rho-raw':
        claim = bytearray(binding.rho_hi_output)
        claim[31] ^= 1
        binding = plan.bind(eval_w, prior, coefficients, claimed_rho_hi_output=bytes(claim))
    elif profile == 'coherent-prefix-capacity':
        claim = bytearray(binding.prefix_output)
        claim[136] ^= 1
        binding = plan.bind(eval_w, prior, coefficients, claimed_prefix_output=bytes(claim))
    maps, source = plan.source_maps, plan.manifest
    if ({key:len(value) for key,value in maps['connections'].items()} != CONNECTION_COUNTS
            or maps['unique_global_words'] != 147355 or maps['cached_signature_reuses'] != 1046):
        raise ValueError('complete closed cross-component connection inventory required')
    maps_name, source_name = f'chain-maps-{index:02d}.json', f'chain-source-{index:02d}.json'
    maps_info = _write_json(directory/maps_name, maps, MAX_MAP_BYTES)
    source_info = _write_json(directory/source_name, source, MAX_MANIFEST_BYTES)
    if (maps_info['file_sha256'] != plan.source_maps_sha256.hex()
            or sha256(SOURCE_DOMAIN+_canonical(source)).digest() != plan.source_sha256):
        raise ValueError('canonical chain sidecars changed their sealed source identities')
    headers, census, seen = [], [], {}
    for record in binding.iter_components():
        component, branch = record.index, record.branch
        spec, values, ids, program = record.spec, record.assignment, tuple(record.global_ids), record.program
        descriptor = record.descriptor.json()
        if (branch != BRANCHES[component] or (len(spec.words),len(spec.leaves))
                != (COMPONENT_WORDS[component],COMPONENT_LEAVES[component])):
            raise ValueError('exact nine-component order and census required')
        _check_interfaces(record, maps['components'][component])
        for global_id, (word, bound) in zip(ids, spec.words, strict=True):
            assertion = bound, values[word]
            if global_id in seen and seen[global_id] != assertion:
                raise ValueError('one global assertion cannot have different bounds or values')
            seen[global_id] = assertion
        mode, selected = _selection(profile, component)
        case, false, chosen = _case(name+'/'+branch, spec, values, mode, selected, program)
        expected_false = ([_terminal_producer(31)[0]] if profile == 'coherent-rho-raw' and component == 0 else
                          [_terminal_producer(136)[0]] if profile == 'coherent-prefix-capacity' and component == 4 else [])
        _equal(false, expected_false, 'only the controlled upstream producer may fail')
        stem = f'{index:02d}-{component}'
        filename, maps_filename, source_filename = f'case-{stem}.json', f'maps-{stem}.json', f'source-{stem}.json'
        case_info = _write_json(directory/filename, case, MAX_CASE_BYTES)
        child_maps, child_source, child_program = record.child_source_maps, record.child_source_manifest, record.child_program_manifest
        child_maps_info = _write_json(directory/maps_filename, child_maps, MAX_MAP_BYTES)
        child_source_info = _write_json(directory/source_filename, child_source, MAX_MANIFEST_BYTES)
        program_filename = f'program-{stem}.json' if child_program is not None else None
        program_info = _write_json(directory/program_filename, child_program, MAX_MANIFEST_BYTES) if child_program is not None else None
        if (child_maps_info['file_sha256'] != descriptor['source_maps_sha256']
                or sha256(_canonical(list(ids))).hexdigest() != descriptor['global_ids_sha256']):
            raise ValueError('fresh component maps/global-ID bytes differ from descriptor')
        full = None
        if component in FULL_COMPONENTS:
            initial, output = _full_states(binding, component)
            full = dict(name=case['name'], profile=profile, role=role, filename=filename, **case_info,
                catalogue_id=spec.digest().hex(), program_sha256=spec.program_sha256,
                source_sha256=descriptor['source_sha256'], global_ids_sha256=child_maps['global_ids_sha256'],
                words=len(spec.words), leaves=len(spec.leaves), input_state_hex=initial.hex(),
                expected_output_state_hex=output.hex(), expected_false=false, state_index=None, byte_slot=None,
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
        layouts = _auth_shapes(spec)
        maximum_layouts = 23 if component in FULL_COMPONENTS else 61 if component in (2,8) else COMPONENT_LEAVES[component]
        if layouts > maximum_layouts:
            raise ValueError('actual authenticated shapes exceed preflighted unchanged budget')
        census.append(dict(selected_leaf_checks=len(chosen), guard_layouts=layouts,
                           words=len(spec.words), leaves=len(spec.leaves)))
        del record, spec, values, ids, program, case, child_maps, child_source, child_program
    if len(headers) != 9 or len(seen) != 147355:
        raise ValueError('all nine catalogues and exact global word coverage required')
    group = dict(name=name, profile=profile, role=role, rho_counter=rho_counter, c_counter=rho_counter+1,
        execution_mode='full' if profile == 'honest' else 'targeted', source_sha256=plan.source_sha256.hex(),
        source_maps_sha256=plan.source_maps_sha256.hex(), eval_w_le=eval_w.hex(), prior_state_hex=prior.hex(),
        compressed_coefficients_le=[value.hex() for value in coefficients],
        expected_rho_hi_output_state_hex=binding.rho_hi_output.hex(), expected_rho_lo_output_state_hex=binding.rho_lo_output.hex(),
        expected_rho_raw_state_le=binding.raw_rho.hex(), expected_rho_result_le=binding.rho_result_value.to_bytes(32,'little').hex(),
        expected_rho_quotient_le=binding.rho_quotient_value.to_bytes(33,'little').hex(),
        expected_prefix_output_state_hex=binding.prefix_output.hex(), expected_c_hi_output_state_hex=binding.c_hi_output.hex(),
        expected_c_lo_output_state_hex=binding.c_lo_output.hex(), expected_c_raw_state_le=binding.raw_c.hex(),
        expected_c_result_le=binding.c_result_value.to_bytes(32,'little').hex(), expected_c_quotient_le=binding.c_quotient_value.to_bytes(33,'little').hex(),
        chain_source_filename=source_name, chain_source_file_sha256=source_info['file_sha256'], chain_source_file_bytes=source_info['file_bytes'],
        chain_maps_filename=maps_name, chain_maps_file_sha256=maps_info['file_sha256'], chain_maps_file_bytes=maps_info['file_bytes'],
        components=headers)
    del binding, plan, maps, source, seen
    return group, census


def _probe(index, request, honest, directory):
    _guard()
    from byte_sumcheck_frame import build_sumcheck_frame, _bind_modulus_fault, _bind_frame_fault
    from byte_sumcheck_absorb import build_sumcheck_absorb
    from bench_byte_keccak_round import _auth_shapes
    name, role, kind, component, leaves = request
    eval_w, prior, coefficients, fixture = _fixture(role)
    descriptor = honest['components'][component]['descriptor']
    operation = f'{OPERATION}/c/counter/{fixture["counter"]+1}/'+('coeff-frame' if component == 3 else 'absorb')
    if descriptor['operation_id'] != operation:
        raise ValueError('private probe must reconstruct the exact positive source operation')
    if component == 3:
        child = build_sumcheck_frame(context=CONTEXT, role=role, counter=fixture['counter']+1, operation_id=operation)
        if kind.startswith('coefficient-'):
            bound = _bind_modulus_fault(child, coefficients, 0 if kind == 'coefficient-c0-modulus' else 2)
        else:
            byte = {'frame-counter':69, 'frame-NoDS':65, 'frame-tag':0, 'frame-zero-capacity':136}[kind]
            anchor = next(row for row in child.source_maps['frame_anchors'] if row['byte_index'] == byte)
            bound = _bind_frame_fault(child, coefficients, byte, anchor['expected'] ^ 1)
        spec, program, values = bound.spec, bound.program, bound.assignment
    else:
        child = build_sumcheck_absorb(context=CONTEXT, role=role, operation_id=operation)
        prefix = bytes.fromhex(honest['expected_prefix_output_state_hex'])
        rho_raw = bytes.fromhex(honest['expected_rho_raw_state_le'])
        outputs = list(child.bind(prefix, rho_raw).outputs)
        output = {'absorb-wrong-xor':0, 'absorb-selector':8, 'absorb-delimiter':6, 'absorb-end-mask':7}[kind]
        claims = [None]*9
        claims[output] = outputs[output] ^ 1
        bound = child.bind(prefix, rho_raw, claimed_outputs=tuple(claims))
        spec, program, values = child.spec, child.program, bound.assignment
    if (spec.digest().hex() != descriptor['catalogue_id'] or spec.program_sha256 != descriptor['program_sha256']
            or child.source_sha256.hex() != descriptor['source_sha256'] or len(spec.leaves) != leaves):
        raise ValueError('fresh standalone probe changed positive source topology or identity')
    case, false, selected = _case(name, spec, values, 'all', None, program)
    expected = {'coefficient-c0-modulus':109, 'coefficient-c2-modulus':110,
        'frame-counter':37, 'frame-NoDS':33, 'frame-tag':32, 'frame-zero-capacity':45,
        'absorb-wrong-xor':0, 'absorb-selector':8, 'absorb-delimiter':6, 'absorb-end-mask':7}[kind]
    _equal(false, [expected], 'one independently classified standalone small fault')
    filename = f'probe-{index:02d}.json'
    info = _write_json(directory/filename, case, MAX_CASE_BYTES)
    header = dict(name=name, role=role, kind=kind, source_case=honest['name'], source_component=component,
        filename=filename, **info, catalogue_id=spec.digest().hex(), program_sha256=spec.program_sha256,
        source_sha256=descriptor['source_sha256'], words=len(spec.words), leaves=leaves,
        expected_false=false, selected_leaf=expected)
    return header, dict(selected_leaf_checks=len(selected), guard_layouts=_auth_shapes(spec),
                        words=len(spec.words), leaves=leaves)


def _generate(directory):
    _guard()
    _record_budget()
    groups, census, honest = [], [], {}
    for index, (name, role, counter, profile) in enumerate(_requests()):
        group, counts = _one(index, name, role, counter, profile, directory)
        groups.append(group)
        census.append(counts)
        if profile == 'honest':
            honest[role] = group
    probes, probe_census = [], []
    for index, request in enumerate(_probe_requests()):
        header, counts = _probe(index, request, honest[request[1]], directory)
        probes.append(header)
        probe_census.append(counts)
    manifest = dict(schema=SCHEMA, context=CONTEXT.hex(), operation_id=OPERATION, cases=groups, probes=probes)
    info = _write_json(directory/'manifest.json', manifest, MAX_MANIFEST_BYTES)
    return manifest, info, census, probe_census


OPENING_COUNTS = dict(rho_messages=384, rho_frames=416, rho_reduction=64,
    coefficients=128, prefix_frame=154, rho_raw_prefix=118, rho_raw_absorb=5,
    prefix_absorb=9, prefix_suffix=766, absorb_suffix=34, c_reduction=64)
MAIN_COUNTS = dict(signature_entries_created=147355, local_declared_words=148401,
    cached_signature_reuses=1046, canonical_internal_opening_links=46,
    internal_cached_boundary_entries=23000, internal_producer_consumer_opening_links=46000)
TRUE_FLAGS = ('rho_to_sumcheck_chain_script_conformance_checked', 'all_native_reference_predicates_checked',
    'boundary_opening_links_checked', 'rho_raw_state_linked_to_next_c', 'coefficients_canonical_script_bound',
    'prefix_unpadded_first_block_checked', 'second_absorption_rate_xor_checked',
    'capacity_forwarding_opening_links_checked', 'shared_prefix_used_once', 'digest_reduction_script_bound',
    'test_keys_only', 'stack_limit_enabled', 'hierarchical_membership_verified',
    'private_probe_keys_separate', 'private_probe_all_leaves_executed')
FALSE_FLAGS = ('all_cases_full_statement_executed', 'raw_vector_file_written', 'op_cat_enabled',
    'full_permutation_verified', 'full_hash_verified', 'transcript_verified', 'nova_transcript_verified_in_script',
    'proof_verified', 'complete_nova_verifier', 'complete_bitvm2_verifier', 'production_assertion_binding',
    'bitcoin_transaction_graph', 'panic_is_rejection', 'eval_w_canonicality_script_bound',
    'dynamic_message_sources_script_bound', 'eval_w_proof_origin_bound', 'prior_state_transcript_bound',
    'complete_keccak_sponge', 'coefficient_proof_origins_bound', 'spartan_sumcheck_equations_verified',
    'external_raw_state_input_loaded')
FOREST_NEGATIVES = ('altered_script', 'branch', 'parity', 'internal_key', 'leaf_version',
    'truncated_control', 'appended_control', 'manifest', 'root', 'output_key', 'component', 'ordinal', 'reordered_components')
LOCAL_NEGATIVES = ('altered_script', 'branch', 'parity', 'internal_key', 'leaf_version',
    'truncated_control', 'appended_control', 'root', 'output_key', 'ordinal', 'registry', 'catalogue')


def _depth(count, ordinal):
    if type(count) is not int or type(ordinal) is not int or not 0 <= ordinal < count:
        raise ValueError('bounded canonical tree depth required')
    height = count.bit_length()-1
    return height+int(ordinal < 2*(count-(1 << height)))


def _selected(source):
    if source['profile'] == 'honest':
        return 8, 244
    if source['profile'] == 'coherent-rho-raw':
        return 0, _terminal_producer(31)[0]
    return 4, _terminal_producer(136)[0]


def _cost(value, largest):
    for key in ('registry_id', 'compiled_stream_sha256'):
        if not _hex32(value.get(key)):
            raise ValueError('actual registry/Script stream identity required')
    size, maximum = value.get('compiled_script_bytes'), value.get('largest_disproof_leaf_bytes')
    if (type(size) is not int or not 0 < size <= 256 << 20 or type(maximum) is not int
            or not 0 < maximum <= min(size, 100_000)):
        raise ValueError('actual component Script accounting exceeds unchanged caps')
    return size, max(largest, maximum)


def _tree(tree, ledger, count, ordinal, control, negatives, *, component=None):
    if type(tree) is not dict:
        raise ValueError('fresh directly constructed Taproot tree required')
    for key, value in (('leaf_count', count), ('compiled_script_bytes', ledger['compiled_script_bytes']),
                       ('control_block_bytes', control)):
        _equal(tree.get(key), value, 'tree '+key)
    if component is None:
        _equal(tree.get('compiled_stream_sha256'), ledger['compiled_stream_sha256'], 'local tree Script stream')
        if tree.get('membership_verified') is not True:
            raise ValueError('actual local probe tree membership missing')
    else:
        for key, value in (('components',9), ('selected_component',component), ('selected_leaf',ordinal)):
            _equal(tree.get(key), value, 'forest '+key)
        if tree.get('hierarchical_membership_verified') is not True or not _hex32(tree.get('component_manifest_sha256')):
            raise ValueError('actual ordered nine-component forest membership missing')
    if tree.get('roots_independently_pinned') is not False:
        raise ValueError('test tree observations cannot become pinned production authority')
    for key in ('merkle_root','output_key','control_block_sha256','selected_script_sha256','compiled_stream_sha256'):
        if not _hex32(tree.get(key)):
            raise ValueError('actual Taproot identity missing: '+key)
    _equal(tree.get('negative_counts'), {name:1 for name in negatives}, 'exact Taproot negative inventory')


def _validate(native, manifest, info, census, probe_census):
    if type(native) is not dict or native.get('passed') is not True:
        raise ValueError('successful direct rho-chain result required')
    _equal(native.get('schema'), 'bitvm2-nova-byte-rho-chain-execution/v1', 'schema')
    _equal(native.get('input_manifest_sha256'), info['file_sha256'], 'fresh manifest identity')
    for flag in TRUE_FLAGS:
        if native.get(flag) is not True:
            raise ValueError('required bounded chain conformance missing: '+flag)
    for flag in FALSE_FLAGS:
        if native.get(flag) is not False:
            raise ValueError('bounded chain scope exceeded: '+flag)
    for key in ('setup_calls','proving_jobs','native_proofs_verified','gpu_jobs','transactions_broadcast'):
        _equal(native.get(key),0,key)
    budget = _record_budget()
    record_bytes = native.get('compact_execution_records_bytes')
    minimum = budget['full_honest_exact_bytes']+budget['all_small_exact_bytes']+budget['standalone_probe_exact_bytes']
    if (type(record_bytes) is not int or not minimum <= record_bytes <= budget['combined_upper_bytes']
            or record_bytes > MAX_EXECUTION_RECORD_BYTES or not _hex32(native.get('compact_execution_records_sha256'))):
        raise ValueError('actual chain records exceed independent unchanged byte budget')
    rows, probes = native.get('cases'), native.get('probes')
    if type(rows) is not list or len(rows) != 6 or len(census) != 6 or type(probes) is not list or len(probes) != 20 or len(probe_census) != 20:
        raise ValueError('six main chains and twenty separate small probes required')
    normal = guards = largest = 0
    for row, source, counts in zip(rows,manifest['cases'],census,strict=True):
        if type(row) is not dict or len(counts) != 9:
            raise ValueError('typed nine-component main observation required')
        for key in ('name','profile','role','rho_counter','c_counter','execution_mode','source_sha256','source_maps_sha256'):
            _equal(row.get(key),source[key],key)
        for key in source:
            if key.startswith('expected_'):
                _equal(row.get(key),source[key],key)
        for key,value in MAIN_COUNTS.items():
            _equal(row.get(key),value,key)
        selected_component, selected_leaf = _selected(source)
        selected_count = sum(count['selected_leaf_checks'] for count in counts)
        layout_count = sum(count['guard_layouts'] for count in counts)
        for key,value in (('all_native_predicates_checked',147043),('selected_leaf_checks',selected_count),
                ('guard_layouts',layout_count),('guard_vectors',14*layout_count),('native_rejections',216),
                ('map_rejections',12),('source_rejections',18),('cache_rejections',96),
                ('selected_component',selected_component),('selected_leaf',selected_leaf),('additional_selected_engine_executions',2)):
            _equal(row.get(key),value,key)
        honest = source['profile'] == 'honest'
        _equal(row.get('full_statement_executed'),honest,'actual full statement execution scope')
        if row.get('selected_correctness_execution_success') is not honest or row.get('selected_disproof_execution_success') is not (not honest):
            raise ValueError('actual selected main-chain correctness/disproof mismatch')
        connections = row.get('connections')
        if (type(connections) is not list or len(connections) != 11
                or any(type(item) is not dict or type(item.get('kind')) is not str for item in connections)):
            raise ValueError('all eleven actual cross-component link groups required')
        by_kind = {item.get('kind'):item for item in connections}
        if set(by_kind) != set(CONNECTION_COUNTS):
            raise ValueError('duplicate or missing cross-component link group')
        for kind, logical in CONNECTION_COUNTS.items():
            _equal(by_kind[kind].get('logical_links'),logical,kind+' logical links')
            _equal(by_kind[kind].get('opening_links'),OPENING_COUNTS[kind],kind+' actual opening links')
        components = row.get('components')
        if type(components) is not list or len(components) != 9:
            raise ValueError('all nine main component ledgers required')
        compiled = 0
        for part,header,count in zip(components,source['components'],counts,strict=True):
            if type(part) is not dict:
                raise ValueError('typed actual component ledger required')
            for key,value in header['descriptor'].items():
                _equal(part.get(key),value,'component '+key)
            for key,value in (('context',manifest['context']),('execution_mode',header['execution_mode']),
                    ('selected_ordinals',header['selected_ordinals']),('executed_leaves',count['selected_leaf_checks']),
                    ('native_predicates_checked',header['descriptor']['leaves']),('false_predicates',header['expected_false']),
                    ('guard_layouts',count['guard_layouts']),('guard_vectors',14*count['guard_layouts'])):
                _equal(part.get(key),value,'component '+key)
            size,largest = _cost(part,largest)
            compiled += size
        if compiled > 5 << 28:
            raise ValueError('whole nine-component forest exceeds unchanged 1.25 GiB cap')
        control = 33+32*(_depth(COMPONENT_LEAVES[selected_component],selected_leaf)+_depth(9,selected_component))
        _tree(row.get('forest'),dict(compiled_script_bytes=compiled),147043,selected_leaf,control,
              FOREST_NEGATIVES,component=selected_component)
        normal += selected_count
        guards += 14*layout_count
    for row,source,count in zip(probes,manifest['probes'],probe_census,strict=True):
        if type(row) is not dict:
            raise ValueError('typed separate small-probe observation required')
        for key in ('name','kind','role','source_case','source_component','source_sha256','catalogue_id','program_sha256','words','leaves','selected_leaf'):
            _equal(row.get(key),source[key],'private probe '+key)
        for key,value in (('context',manifest['context']),('executed_leaves',source['leaves']),
                ('false_predicates',source['expected_false']),('signature_entries_created',source['words']),
                ('guard_layouts',count['guard_layouts']),('guard_vectors',14*count['guard_layouts']),
                ('native_rejections',24),('additional_selected_engine_executions',2)):
            _equal(row.get(key),value,'private probe '+key)
        if row.get('selected_correctness_execution_success') is not False or row.get('selected_disproof_execution_success') is not True:
            raise ValueError('actual selected private probe must be a proper bounded counterexample')
        _,largest = _cost(row,largest)
        _tree(row.get('tree'),row,source['leaves'],source['selected_leaf'],
              33+32*_depth(source['leaves'],source['selected_leaf']),LOCAL_NEGATIVES)
        normal += source['leaves']
        guards += 14*count['guard_layouts']
    for key,value in MAIN_COUNTS.items():
        _equal(native.get(key),6*value,'all main chains '+key)
    for key,value in (('full_statement_cases',2),('targeted_statement_cases',4),
            ('private_probe_signature_entries_created',2428),('private_probe_registries',20),('private_probe_trees',20)):
        _equal(native.get(key),value,key)
    metrics = native.get('metrics')
    if type(metrics) is not dict:
        raise ValueError('actual native main/probe execution metrics required')
    _equal(metrics.get('vectors'),2*normal+guards+52,'all normal, guard and selected-tree executions')
    _equal(metrics.get('expected_rejections'),normal+guards+26,'actual false modes, abort guards and selected-tree checks')
    _equal(metrics.get('max_script_bytes'),largest,'actual maximum Script size')
    for key in ('max_stack_items','max_witness_items'):
        if type(metrics.get(key)) is not int or not 0 < metrics[key] <= 1000:
            raise ValueError('chain stack/witness hard cap exceeded')
    payload = metrics.get('max_witness_payload_bytes')
    if type(payload) is not int or not 0 < payload <= 520*metrics['max_witness_items']:
        raise ValueError('chain witness payload hard cap exceeded')
    wall = native.get('wall_seconds')
    if type(wall) not in (int,float) or not math.isfinite(wall) or not 0 <= wall <= 1260:
        raise ValueError('bounded actual native wall time required')
    return rows,probes


def run(cases_dir,native_worker):
    _guard()
    started = time.perf_counter()
    budget = _record_budget()
    worker,directory = _worker(native_worker),_new_directory(cases_dir)
    manifest,info,census,probe_census = _generate(directory)
    native = _execute(worker,directory,info['file_sha256'])
    rows,probes = _validate(native,manifest,info,census,probe_census)
    honest = [dict(name=row['name'],role=row['role'],component_script_bytes=[part['compiled_script_bytes'] for part in row['components']],
        complete_forest_script_bytes=row['forest']['compiled_script_bytes'],merkle_root=row['forest']['merkle_root'],
        output_key=row['forest']['output_key']) for row in rows if row['profile']=='honest']
    return dict(schema='bitvm2-nova-byte-rho-chain-conformance/v1',native=native,manifest=info,
        compact_record_budget=budget,cases=6,full_execution_cases=2,targeted_execution_cases=4,
        standalone_probe_registries=20,standalone_probe_trees=20,standalone_probe_keys_separate=True,
        honest_forest_ledger=honest,direct_native_worker_executed=True,external_result_receipt_loaded=False,
        components_per_case=9,leaves_per_complete_forest=147043,unique_global_words_per_case=147355,
        actual_cross_component_opening_links_per_case=2142,internal_opening_links_per_case=46000,
        context_sha256=CONTEXT.hex(),operation_id=OPERATION,full_permutation_verified=False,
        full_hash_verified=False,transcript_verified=False,proof_verified=False,bitvm2_script_verified=False,
        complete_nova_verifier=False,complete_bitvm2_verifier=False,production_assertion_binding=False,
        bitcoin_transaction_graph=False,coefficient_proof_origins_bound=False,spartan_sumcheck_equations_verified=False,
        eval_w_proof_origin_bound=False,prior_state_transcript_bound=False,
        setup_calls=0,proving_jobs=0,gpu_jobs=0,transactions_broadcast=0,
        wall_seconds=time.perf_counter()-started,parent_peak_rss_bytes=peak_rss(),
        scope='nine-component RHO-to-following-c fixture conformance with explicit full/targeted coverage; private probes have separate keys/trees and proof/transcript origins remain open')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cases-dir',type=Path,required=True)
    parser.add_argument('--native-worker',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    _guard()
    from bench_keccak_endpoint import _output_file
    output=_output_file(args.output)
    result=run(args.cases_dir,args.native_worker)
    _write_json(output,result,MAX_RESULT_BYTES)
    print(json.dumps(result,ensure_ascii=True,allow_nan=False))


if __name__=='__main__':
    main()
