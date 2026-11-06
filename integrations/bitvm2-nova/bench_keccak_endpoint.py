"""Hosted streamed LO-Keccak endpoint and framed reduction conformance.

Fresh sealed factories supply 12 pair catalogues and one endpoint tail. The
configured native worker is executed directly; imported execution receipts have
no API. HI and the dynamic eval_w/prior-state origins remain external claims.
Selected permutation shapes execute, while every tail leaf executes both modes.
This is not full hash, transcript, Nova proof or production Bitcoin acceptance.
"""
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import time

from bench_compact import peak_rss

SCHEMA = 'bitvm2-nova-keccak-endpoint-run/v1'
CONTEXT = sha256(b'BITVM2-NOVA/KECCAK-LO-ENDPOINT-CONFORMANCE/v1').digest()
ROLE, OPERATION = 'pallas_scalar', 'benchmark/keccak/endpoint'
MAX_CASE_BYTES, MAX_MANIFEST_BYTES, MAX_RESULT_BYTES = 32 << 20, 1 << 20, 1 << 20
TOTALS = dict(pairs=12, components=13, leaves=231715, pair_local_words=249710,
             tail_words=1787, global_words=232809, inter_pair_shared_words=17600,
             endpoint_shared_words=1088)
SCENARIOS = ('honest', 'coherent-output', 'wrong-padding')
FRAME_BYTES = (0,)+tuple(range(33, 45))+(109, 110)+tuple(range(111, 200))
_FRAME_NAME = re.compile(r'^frame/byte/([0-9]+)/bit/([0-7])$')


def _guard():
    if (os.environ.get('GITHUB_ACTIONS') != 'true'
            or os.environ.get('RUNNER_OS') != 'Linux' or sys.platform != 'linux'):
        raise ValueError('Keccak endpoint conformance is hosted GitHub Linux only')


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('utf-8')


def _write_json(path, value, limit):
    """Bound/hash the exact UTF-8 bytes written, with exclusive creation."""
    path = Path(path)
    temporary, total, digest, created = path.with_name(path.name+'.partial'), 0, sha256(), False
    try:
        with temporary.open('xb') as output:
            created = True
            for fragment in json.JSONEncoder(sort_keys=True, separators=(',', ':'),
                    ensure_ascii=True, allow_nan=False).iterencode(value):
                raw = fragment.encode('utf-8')
                total += len(raw)
                if total > limit:
                    raise ValueError('endpoint JSON file exceeds explicit byte cap')
                output.write(raw)
                digest.update(raw)
        if path.exists():
            raise ValueError('endpoint file already exists')
        temporary.replace(path)
    except BaseException:
        if created:
            temporary.unlink(missing_ok=True)
        raise
    return dict(file_bytes=total, file_sha256=digest.hexdigest())


def _source_input():
    """Read a literal-pinned fixture, independently recomputing its two digests."""
    from bench_digest_reduce import TRACE_FILE, TRACE_SHA256, _retained_input
    wide, source = _retained_input()
    with TRACE_FILE.open('rb') as stream:
        raw = stream.read((1 << 20)+1)
    if len(raw) > 1 << 20 or sha256(raw).hexdigest() != TRACE_SHA256:
        raise ValueError('retained endpoint source trace differs from literal pin')
    trace = json.loads(raw.decode('utf-8'))
    streams = [item for item in trace['streams'] if item['kind'] == 'keccak'
               and item['engine'] == 'pallas' and item['session'] == 0]
    if len(streams) != 1:
        raise ValueError('one retained primary transcript required')
    event = streams[0]['events'][102]
    before = event['after']
    buffer = bytes.fromhex(before['buffer_hex'])
    prior_state = bytes.fromhex(before['state_hex'])
    if (event['op'] != 'absorb' or event['label_hex'] != '77' or len(buffer) != 33
            or buffer[:1] != b'w' or before['round'] != 59 or len(prior_state) != 64
            or bytes.fromhex(event['repr_hex']) != buffer[1:]):
        raise ValueError('retained endpoint eval_w/counter/state framing mismatch')
    eval_w = buffer[1:]
    message = _message(eval_w, prior_state)
    from production_transcript import keccak256
    if len(message) != 111 or keccak256(message) != wide[:32] or keccak256(message[:-1]+b'\1') != wide[32:]:
        raise ValueError('mature retained LO/HI source check failed')
    source.update(eval_w_le=eval_w.hex(), prior_state_hex=prior_state.hex(), counter=59,
        branch0_message_hex=message.hex(), lo_hex=wide[:32].hex(), external_hi_hex=wide[32:].hex(),
        eval_w_canonical_in_script=False, eval_w_proof_origin_bound=False,
        prior_state_transcript_bound=False, hi_keccak_origin_bound=False)
    return eval_w, prior_state, wide[32:], source


def _message(eval_w, prior_state):
    if type(eval_w) is not bytes or len(eval_w) != 32 or type(prior_state) is not bytes or len(prior_state) != 64:
        raise ValueError('fixed-size endpoint source bytes required')
    return b'w'+eval_w+b'NoDS'+(59).to_bytes(8, 'little')+prior_state+b'r\0'


def _initial_state(eval_w, prior_state, scenario):
    from keccak_trace import keccak256_padded, state_from_bytes
    raw = bytearray(keccak256_padded(_message(eval_w, prior_state))+bytes(64))
    if len(raw) != 200 or raw[111] != 1:
        raise ValueError('exact single-block endpoint padding required')
    if scenario == 'wrong-padding':
        raw[111] ^= 1
    elif scenario not in ('honest', 'coherent-output'):
        raise ValueError('unsupported endpoint scenario')
    return state_from_bytes(bytes(raw))


def _ids_digest(ids):
    return sha256(_canonical(list(ids))).hexdigest()


def _tail_mapping(tail):
    """Independently derive the only permitted endpoint global aliases."""
    spec, ids, ports = tail.spec, tuple(tail.global_ids), tail.digest.ports
    lo = {word: f'state/24/l{i//64}/b{i%64}' for i, word in enumerate(ports['digest_lo_bits'])}
    expected, frame_ids = [], []
    for word, _ in spec.words:
        match = _FRAME_NAME.fullmatch(word)
        if match:
            byte, bit = map(int, match.groups())
            if byte not in FRAME_BYTES:
                raise ValueError('unexpected endpoint fixed-frame word')
            global_id = f'state/0/l{byte//8}/b{8*(byte%8)+bit}'
            frame_ids.append(global_id)
        else:
            global_id = lo.get(word, 'tail/'+word)
        expected.append(global_id)
    fixed = tuple(f'state/0/l{byte//8}/b{8*(byte%8)+bit}' for byte in FRAME_BYTES for bit in range(8))
    if (len(ids) != 1787 or len(set(ids)) != 1787 or tuple(expected) != ids
            or tuple(frame_ids) != fixed or len(lo) != 256 or len(tail.anchor_constraints) != 832
            or tuple(tail.anchor_constraints) != tuple(range(372, 1204))):
        raise ValueError('endpoint LO/fixed-frame maps or anchor census changed')
    return ids


def _scenario(plan, name, eval_w, prior_state, hi, directory):
    from bench_keccak_permutation import _selected, _truth
    from bench_digest_reduce import _truth as digest_truth
    from keccak_trace import keccak_f1600, state_to_bytes
    binding = plan.bind(eval_w, prior_state, hi, scenario=name)
    expected_initial = _initial_state(eval_w, prior_state, name)
    if binding.initial_state != expected_initial:
        raise ValueError('sealed initial state differs from independent frame preparation')
    reference = keccak_f1600(expected_initial)
    expected_output = list(reference)
    if name == 'coherent-output':
        expected_output[0] ^= 1
    expected_output = tuple(expected_output)
    if binding.reference_output_state != reference or binding.output_state != expected_output:
        raise ValueError('sealed output differs from independent 24-round word reference')
    target = directory/name
    target.mkdir()
    rows, false_rows, values_seen = [], [], {}
    leaves = words = checks = 0
    selected_pair = 12 if name == 'wrong-padding' else 11
    selected_leaf = 492 if name == 'wrong-padding' else plan.permutation.descriptors[-1].final_output_start

    def remember(ids, spec, values):
        for global_id, (word, _) in zip(ids, spec.words, strict=True):
            value = values[word]
            if global_id in values_seen and values_seen[global_id] != value:
                raise ValueError('same global word has conflicting signed assignments')
            values_seen[global_id] = value

    for item in binding.iter_pairs():
        index, pair_binding = item.index, item.pair_binding
        pair, spec, values = pair_binding.pair, pair_binding.spec, pair_binding.assignment
        ids = tuple(item.global_ids)
        if len(ids) != len(spec.words) or len(set(ids)) != len(ids) or _ids_digest(ids) != item.descriptor.global_ids_sha256:
            raise ValueError('fresh pair global map differs from sealed descriptor')
        remember(ids, spec, values)
        false = [i for i in range(len(spec.leaves)) if not _truth(spec, values, i)]
        expected_false = [selected_leaf] if name == 'coherent-output' and index == 11 else []
        if false != expected_false:
            raise ValueError('endpoint pair false predicates differ from coherent scenario')
        false_rows.extend(dict(pair=index, ordinal=i) for i in false)
        chosen = sorted(set(_selected(pair)+false+([selected_leaf] if index == selected_pair else [])))
        case = dict(name=f'keccak/endpoint/{name}/pair-{index:02d}', spec=spec.json(),
            expected_spec_id=spec.digest().hex(), words=[values[word] for word, _ in spec.words],
            checks=[dict(ordinal=i, expected_correct=i not in false) for i in chosen], measure_all=True)
        filename = f'{name}/pair-{index:02d}.json'
        record = _write_json(directory/filename, case, MAX_CASE_BYTES)
        maps = pair.source_maps
        rows.append(dict(index=index, first_round=2*index, filename=filename, **record,
            catalogue_id=spec.digest().hex(), program_sha256=spec.program_sha256,
            global_ids_sha256=_ids_digest(ids), words=len(spec.words), leaves=len(spec.leaves),
            first_child_leaves=len(maps['children'][0]['leaf_map']),
            initial_state_hex=state_to_bytes(pair_binding.initial_state).hex(),
            middle_state_hex=state_to_bytes(pair_binding.middle_state).hex(),
            output_state_hex=state_to_bytes(pair_binding.output_state).hex()))
        leaves += len(spec.leaves)
        words += len(spec.words)
        checks += len(chosen)
        # A for-loop requests its next item before rebinding the loop variable.
        # Drop all full-spec/assignment aliases before that next construction.
        del item, pair_binding, pair, spec, values, ids, case, maps
    if (len(rows), leaves, words, len(values_seen)) != (12, 230510, 249710, 232110):
        raise ValueError('streamed endpoint permutation census changed')
    tail = binding.regenerate_tail()
    spec, values = tail.spec, tail.assignment
    ids = _tail_mapping(tail)
    if _ids_digest(ids) != plan.tail_descriptor.global_ids_sha256:
        raise ValueError('fresh endpoint tail global map differs from sealed descriptor')
    remember(ids, spec, values)
    if len(spec.leaves) != 1205 or len(values_seen) != 232809:
        raise ValueError('13-component endpoint coverage changed')
    false = [i for i in range(1205) if not digest_truth(tail.program, spec, values, i)]
    if false != ([492] if name == 'wrong-padding' else []):
        raise ValueError('endpoint tail false predicates differ from framing scenario')
    false_rows.extend(dict(pair=12, ordinal=i) for i in false)
    if tail.digest.lo != state_to_bytes(expected_output)[:32] or tail.digest.hi != hi:
        raise ValueError('tail claimed digest values detached from output/global HI ports')
    from script import Q
    expected_result = int.from_bytes(state_to_bytes(expected_output)[:32]+hi, 'little') % Q
    if tail.digest.uniform.result_value != expected_result:
        raise ValueError('tail result differs from independent unsigned512-bit field reduction')
    case = dict(name=f'keccak/endpoint/{name}/tail', spec=spec.json(),
        expected_spec_id=spec.digest().hex(), words=[values[word] for word, _ in spec.words],
        checks=[dict(ordinal=i, expected_correct=i not in false) for i in range(1205)], measure_all=True)
    filename = f'{name}/tail.json'
    record = _write_json(directory/filename, case, MAX_CASE_BYTES)
    tail_row = dict(filename=filename, **record, catalogue_id=spec.digest().hex(),
        program_sha256=spec.program_sha256, global_ids_sha256=_ids_digest(ids), words=1787, leaves=1205)
    checks += 1205
    if false_rows != ([] if name == 'honest' else [dict(pair=selected_pair, ordinal=selected_leaf)]):
        raise ValueError('exact one-refutable-leaf endpoint scenario required')
    result = dict(name=name, initial_state_hex=state_to_bytes(expected_initial).hex(),
        expected_output_state_hex=state_to_bytes(expected_output).hex(), expected_false=false_rows,
        selected_pair=selected_pair, selected_leaf=selected_leaf, pairs=rows, tail=tail_row)
    del binding, tail, spec, values, ids, case, values_seen
    return result, checks


def _generate(directory):
    from keccak_endpoint import build_keccak_endpoint
    from keccak_trace import state_to_bytes, keccak_f1600
    from production_transcript import keccak256
    eval_w, prior_state, hi, source = _source_input()
    plan = build_keccak_endpoint(context=CONTEXT, role=ROLE, operation_id=OPERATION)
    reference = state_to_bytes(keccak_f1600(_initial_state(eval_w, prior_state, 'honest')))[:32]
    if reference != keccak256(_message(eval_w, prior_state)) or reference.hex() != source['lo_hex']:
        raise ValueError('mature Keccak honest endpoint fixture mismatch')
    scenarios, checks = [], 0
    for name in SCENARIOS:
        scenario, count = _scenario(plan, name, eval_w, prior_state, hi, directory)
        scenarios.append(scenario)
        checks += count
    manifest = dict(schema=SCHEMA, topology_sha256=plan.topology_sha256.hex(), context=CONTEXT.hex(),
                    role=ROLE, operation_id=OPERATION, totals=TOTALS, scenarios=scenarios)
    info = _write_json(directory/'manifest.json', manifest, MAX_MANIFEST_BYTES)
    return manifest, info, checks, source


def _new_directory(path):
    cwd = Path.cwd().resolve()
    owner, target = (cwd/'results').resolve(), Path(path).resolve()
    if owner == cwd or not owner.is_relative_to(cwd) or target == owner or not target.is_relative_to(owner):
        raise ValueError('new endpoint corpus directory must be beneath canonical cwd/results')
    owner.mkdir(exist_ok=True)
    target.mkdir(parents=True, exist_ok=False, mode=0o700)
    return target


def _worker(path):
    source = Path(path)
    if source.is_symlink():
        raise ValueError('trusted endpoint executable must be a regular owned file')
    target = source.resolve()
    entry = target.lstat()
    if (not stat.S_ISREG(entry.st_mode) or entry.st_uid != os.getuid()
            or target.name != 'keccak_endpoint' or not os.access(target, os.X_OK)):
        raise ValueError('trusted configured owned keccak_endpoint executable required')
    return target


def _execute(worker, directory, manifest_sha):
    output = directory/'native-execution.json'
    if output.exists():
        raise ValueError('fresh direct endpoint output required')
    command = ['/usr/bin/prlimit', '--as=536870912', '--cpu=1200', '--fsize=16777216', '--',
        str(worker), str(directory/'manifest.json'), str(directory), str(output), manifest_sha]
    environment = dict(os.environ, RAYON_NUM_THREADS='2', CUDA_VISIBLE_DEVICES='', RUST_BACKTRACE='0')
    with tempfile.TemporaryFile(dir=directory) as stdout, tempfile.TemporaryFile(dir=directory) as stderr:
        try:
            result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                timeout=1260, check=False, env=environment)
        except subprocess.TimeoutExpired as error:
            raise ValueError('direct endpoint worker exceeded wall-time limit') from error
        if result.returncode != 0:
            stderr.seek(0)
            message = stderr.read(8192).decode('utf-8', 'replace')
            raise ValueError(f'direct endpoint worker failed ({result.returncode}): {message}')
        for stream in (stdout, stderr):
            stream.seek(0, 2)
            if stream.tell() > MAX_RESULT_BYTES:
                raise ValueError('endpoint worker diagnostic-output cap exceeded')
    if not output.is_file() or output.is_symlink() or output.stat().st_size > MAX_RESULT_BYTES:
        raise ValueError('bounded direct endpoint worker output required')
    with output.open('rb') as stream:
        raw = stream.read(MAX_RESULT_BYTES+1)
    if len(raw) > MAX_RESULT_BYTES:
        raise ValueError('direct endpoint output grew beyond cap')
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError('duplicate direct endpoint result key')
            value[key] = item
        return value
    try:
        return json.loads(raw.decode('utf-8'), object_pairs_hook=unique,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite direct result')))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError('invalid direct endpoint worker JSON') from error


def _typed_equal(actual, expected, message):
    if type(actual) is not type(expected) or actual != expected:
        raise ValueError(message)


def _validate_execution(native, manifest, info, checks):
    if (type(native) is not dict or native.get('passed') is not True
            or native.get('schema') != 'bitvm2-nova-keccak-endpoint-execution/v1'
            or native.get('topology_sha256') != manifest['topology_sha256']
            or native.get('manifest_sha256') != info['file_sha256']):
        raise ValueError('direct endpoint worker identity/result mismatch')
    for flag in ('graph_compiled', 'reference_conformance_checked', 'hierarchical_membership_verified',
                 'test_keys_only', 'lo_keccak_endpoint_script_bound', 'framing_constants_script_bound'):
        if native.get(flag) is not True:
            raise ValueError('missing direct endpoint conformance: '+flag)
    for flag in ('raw_vector_file_written', 'full_permutation_verified', 'full_hash_verified',
                 'keccak256_verified', 'nova_transcript_verified_in_script', 'proof_verified',
                 'complete_bitvm2_verifier', 'production_assertion_binding', 'bitcoin_transaction_graph',
                 'production_transactions_verified', 'hi_keccak_endpoint_script_bound',
                 'eval_w_canonicality_script_bound', 'dynamic_message_sources_script_bound',
                 'complete_keccak_sponge'):
        if native.get(flag) is not False:
            raise ValueError('endpoint conformance scope exceeded: '+flag)
    for key in ('transactions_broadcast', 'native_proofs_verified', 'proving_jobs'):
        _typed_equal(native.get(key), 0, 'unexpected production/proving work: '+key)
    rows = native.get('scenarios')
    if type(rows) is not list or len(rows) != 3:
        raise ValueError('three direct endpoint scenarios required')
    negatives = {'forest_altered_script', 'forest_branch', 'forest_parity', 'forest_internal_key',
        'forest_leaf_version', 'forest_truncated_control', 'forest_appended_control', 'forest_manifest',
        'forest_root', 'forest_output_key', 'forest_component', 'forest_ordinal', 'forest_reordered_components'}
    normal = guards = compiled = 0
    for actual, expected in zip(rows, manifest['scenarios'], strict=True):
        if type(actual) is not dict or actual.get('name') != expected['name']:
            raise ValueError('direct endpoint scenario order/identity mismatch')
        counts = dict(components=13, unique_global_words=232809, signature_entries_created=232809,
            cached_signature_reuses=18688, internal_boundary_words=19200,
            internal_boundary_signature_links=38400, inter_boundary_words=17600,
            inter_boundary_signature_links=35200, endpoint_framing_cached_entries=832,
            endpoint_lo_cached_entries=256, endpoint_framing_opening_links=832,
            endpoint_lo_opening_links=256, endpoint_byte_opening_links=128,
            endpoint_carry_opening_links=64, endpoint_source_cache_rejections=12,
            tail_guarded_layouts=13,
            all_boolean_predicates_checked=230510, tail_predicates_checked=1205, tail_leaf_checks=1205,
            selected_component=expected['selected_pair'], selected_leaf=expected['selected_leaf'],
            guard_vectors=238, additional_selected_engine_executions=2)
        for key, value in counts.items():
            _typed_equal(actual.get(key), value, 'direct endpoint coverage mismatch: '+key)
        _typed_equal(actual.get('false_predicates'), expected['expected_false'], 'endpoint false predicate mismatch')
        if (actual.get('selected_correctness_execution_success') is not (expected['name'] == 'honest')
                or actual.get('selected_disproof_execution_success') is not (expected['name'] != 'honest')
                or actual.get('hierarchical_membership_verified') is not True
                or actual.get('roots_independently_pinned') is not False):
            raise ValueError('selected endpoint execution/membership mismatch')
        control = actual.get('global_control_bytes')
        if type(control) is not int or not 33 <= control <= 33+32*19 or (control-33) % 32:
            raise ValueError('endpoint forest control depth exceeds declared bounds')
        rejected = actual.get('forest_negative_counts')
        if (type(rejected) is not dict or set(rejected) != negatives
                or any(type(value) is not int or value != 1 for value in rejected.values())):
            raise ValueError('endpoint adversarial forest opening coverage missing')
        ledger = actual.get('local_ledger')
        if type(ledger) is not list or len(ledger) != 13:
            raise ValueError('all13 actual complete component ledgers required')
        source_tail = dict(expected['tail'], index=12, first_round=None)
        total = 0
        for measured, source in zip(ledger, expected['pairs']+[source_tail], strict=True):
            if type(measured) is not dict:
                raise ValueError('typed component ledger row required')
            for key in ('index', 'first_round', 'catalogue_id', 'words', 'leaves'):
                _typed_equal(measured.get(key), source[key], 'measured component detached from fresh source: '+key)
            size = measured.get('compiled_script_bytes')
            if type(size) is not int or not 0 < size <= 1 << 28:
                raise ValueError('endpoint component Script byte budget exceeded')
            total += size
        _typed_equal(actual.get('compiled_script_bytes'), total, 'endpoint compiled Script accounting mismatch')
        if total > 5 << 28:
            raise ValueError('endpoint complete forest Script byte budget exceeded')
        compiled += total
        count = actual.get('normal_leaf_checks')
        if type(count) is not int or count < 1205:
            raise ValueError('typed complete-tail/selected-pair check count required')
        normal += count
        guards += actual['guard_vectors']
    metrics = native.get('metrics')
    if type(metrics) is not dict or normal != checks:
        raise ValueError('direct endpoint selected check census mismatch')
    for key, value in (('vectors', 2*checks+guards), ('expected_rejections', checks+guards)):
        _typed_equal(metrics.get(key), value, 'direct endpoint vector/rejection census mismatch: '+key)
    for key in ('max_stack_items', 'max_witness_items'):
        if type(metrics.get(key)) is not int or not 0 < metrics[key] <= 1000:
            raise ValueError('endpoint stack/witness resource bound exceeded')
    return compiled


def run(cases_dir, native_worker):
    _guard()  # Before requested-path I/O, graphs, or subprocesses.
    started = time.perf_counter()
    worker = _worker(native_worker)
    directory = _new_directory(cases_dir)
    manifest, info, checks, source = _generate(directory)
    native = _execute(worker, directory, info['file_sha256'])
    _validate_execution(native, manifest, info, checks)
    return dict(schema='bitvm2-nova-keccak-endpoint-conformance/v1', native=native,
        topology_sha256=manifest['topology_sha256'], manifest_sha256=info['file_sha256'],
        normal_leaf_checks=checks, totals=TOTALS, scenarios=3, retained_source=source,
        direct_native_worker_executed=True, external_result_receipt_loaded=False,
        mature_keccak_reference_fixture_checked=True, endpoint_tail_leaves_executed=3*1205,
        lo_endpoint_global_mapping_checked=True, fixed_framing_global_mapping_checked=True,
        hi_keccak_origin_bound=False, eval_w_canonical_in_script=False, eval_w_proof_origin_bound=False,
        prior_state_transcript_bound=False, dynamic_message_sources_script_bound=False,
        complete_keccak_sponge=False, full_hash_verified=False, full_permutation_verified=False,
        nova_transcript_verified_in_script=False, proof_verified=False, bitvm2_script_verified=False,
        complete_bitvm2_verifier=False, production_assertion_binding=False,
        bitcoin_transaction_graph=False, transactions_broadcast=0, proving_jobs=0,
        wall_seconds=time.perf_counter()-started, parent_peak_rss_bytes=peak_rss(),
        scope='streamed claimed LO permutation endpoint, fixed framing and reduction-tail conformance; external HI and dynamic origins')


def _output_file(path):
    cwd = Path.cwd().resolve()
    owner, target = (cwd/'results').resolve(), Path(path).resolve()
    if owner == cwd or not owner.is_relative_to(cwd) or target == owner or not target.is_relative_to(owner):
        raise ValueError('endpoint result must stay beneath canonical cwd/results')
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        raise ValueError('fresh endpoint result file required')
    return target


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cases-dir', type=Path, required=True)
    parser.add_argument('--native-worker', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    _guard()
    output = _output_file(args.output)
    result = run(args.cases_dir, args.native_worker)
    _write_json(output, result, MAX_RESULT_BYTES)
    print(json.dumps(result, ensure_ascii=True, allow_nan=False))


if __name__ == '__main__':
    main()
