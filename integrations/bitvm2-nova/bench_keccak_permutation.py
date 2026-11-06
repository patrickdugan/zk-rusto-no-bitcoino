"""Host-only streamed full-permutation graph conformance, never hash acceptance.

Fresh sealed topology/bindings produce independently hashed per-pair inputs.
A trusted configured native worker directly builds every pair commitment and
the hierarchical selected proof. No result receipt is accepted as input.
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

SCHEMA = 'bitvm2-nova-keccak-full-run/v1'
CONTEXT = sha256(b'BITVM2-NOVA/FULL-KECCAK-STREAM-CONFORMANCE/v1').digest()
ROLE, OPERATION = 'pallas_scalar', 'benchmark/keccak/permutation'
MAX_CASE_BYTES, MAX_MANIFEST_BYTES, MAX_RESULT_BYTES = 32 << 20, 1 << 20, 1 << 20
TOTALS = dict(pairs=12, leaves=230510, pair_local_words=249710,
              global_words=232110, inter_pair_shared_words=17600)


def _guard():
    if (os.environ.get('GITHUB_ACTIONS') != 'true'
            or os.environ.get('RUNNER_OS') != 'Linux' or sys.platform != 'linux'):
        raise ValueError('full Keccak graph conformance is hosted GitHub Linux only')


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def _write_json(path, value, limit):
    """Hash exactly the bounded bytes written; leave existing files untouched."""
    path = Path(path)
    temporary = path.with_name(path.name+'.partial')
    total, digest, created = 0, sha256(), False
    try:
        with temporary.open('xb') as output:
            created = True
            for fragment in json.JSONEncoder(sort_keys=True, separators=(',', ':'),
                    ensure_ascii=True, allow_nan=False).iterencode(value):
                raw = fragment.encode('ascii')
                if total+len(raw) > limit:
                    raise ValueError('full Keccak JSON file exceeds explicit byte cap')
                output.write(raw)
                digest.update(raw)
                total += len(raw)
        if path.exists():
            raise ValueError('full Keccak input/output file already exists')
        temporary.replace(path)
    except BaseException:
        if created:
            temporary.unlink(missing_ok=True)
        raise
    return dict(file_bytes=total, file_sha256=digest.hexdigest())


def _truth(spec, values, ordinal):
    leaf = spec.leaves[ordinal]
    words = [values[spec.words[i][0]] for i in leaf.wires]
    if any(type(value) is not int or value not in (0, 1) for value in words):
        return False
    if leaf.kind == 'bool_xor':
        return words[2] == words[0]^words[1]
    if leaf.kind == 'bool_and':
        return words[2] == words[0]&words[1]
    if leaf.kind == 'bool_not':
        return words[1] == 1-words[0]
    if leaf.kind == 'const':
        return words[0] == leaf.argument[0]
    raise ValueError('unexpected full-permutation predicate kind')


def _selected(pair):
    from wots_graph import authenticated_shape
    spec, maps = pair.spec, pair.source_maps
    seen, selected = set(), set()
    for ordinal, leaf in enumerate(spec.leaves):
        shape = authenticated_shape(spec, leaf)
        if shape not in seen:
            selected.add(ordinal)
            seen.add(shape)
    for bit in (0, 63, 1599):
        selected.add(maps['producer_leaves'][bit])
        selected.update(maps['consumer_leaves'][bit])
    selected.add(len(spec.leaves)-1600)  # First final output, selected on pair0.
    return sorted(selected)


def _scenario(plan, name, initial, directory):
    from keccak_trace import keccak_f1600_round, state_to_bytes
    override = None
    if name == 'coherent-state2':
        changed = list(keccak_f1600_round(keccak_f1600_round(initial, 0), 1))
        changed[0] ^= 1
        override = {2: tuple(changed)}
    elif name != 'honest':
        raise ValueError('unsupported full-permutation scenario')
    target = directory/name
    target.mkdir()
    rows, observed_false, seen = [], [], set()
    local_words = leaves = checks = 0
    final = None
    for item in plan.iter_bindings(initial, claimed_states=override):
        index, binding = item.index, item.pair_binding
        pair, spec, values = binding.pair, binding.spec, binding.assignment
        global_ids = tuple(item.global_ids)
        if len(global_ids) != len(spec.words) or len(set(global_ids)) != len(global_ids):
            raise ValueError('complete injective local global-ID map required')
        encoded_ids = json.dumps(list(global_ids), separators=(',', ':'), ensure_ascii=True).encode('ascii')
        global_digest = sha256(encoded_ids).hexdigest()
        if item.descriptor.global_ids_sha256 != global_digest:
            raise ValueError('live global-ID map differs from sealed descriptor')
        seen.update(global_ids)
        false = [i for i in range(len(spec.leaves)) if not _truth(spec, values, i)]
        observed_false.extend(dict(pair=index, ordinal=i) for i in false)
        expected = [17606] if name == 'coherent-state2' and index == 0 else []
        if false != expected:
            raise ValueError('full-permutation false predicates differ from coherent scenario')
        chosen = sorted(set(_selected(pair)+false))
        case = dict(name=f'keccak/full/{name}/pair-{index:02d}', spec=spec.json(),
            expected_spec_id=spec.digest().hex(), words=[values[word] for word, _ in spec.words],
            checks=[dict(ordinal=i, expected_correct=i not in false) for i in chosen], measure_all=True)
        if index == 0 and 17606 not in chosen:
            raise ValueError('actual selected producer must execute before membership')
        filename = f'{name}/pair-{index:02d}.json'
        record = _write_json(directory/filename, case, MAX_CASE_BYTES)
        source_maps = pair.source_maps
        rows.append(dict(index=index, first_round=2*index, filename=filename, **record,
            catalogue_id=spec.digest().hex(), program_sha256=spec.program_sha256,
            global_ids_sha256=global_digest, words=len(spec.words), leaves=len(spec.leaves),
            first_child_leaves=len(source_maps['children'][0]['leaf_map']),
            initial_state_hex=state_to_bytes(binding.initial_state).hex(),
            middle_state_hex=state_to_bytes(binding.middle_state).hex(),
            output_state_hex=state_to_bytes(binding.output_state).hex()))
        local_words += len(spec.words)
        leaves += len(spec.leaves)
        checks += len(chosen)
        final = binding.output_state
        # The next streamed item is constructed before a for-loop rebinds item.
        # Release every large alias before requesting it.
        del item, binding, pair, spec, values, case, source_maps, global_ids, encoded_ids
    if (len(rows), leaves, local_words, len(seen)) != (12, 230510, 249710, 232110):
        raise ValueError('streamed full-permutation census mismatch')
    return dict(name=name, initial_state_hex=state_to_bytes(initial).hex(),
        expected_output_state_hex=state_to_bytes(final).hex(), expected_false=observed_false,
        selected_pair=0, selected_leaf=17606, pairs=rows), checks


def _generate(directory):
    from Cryptodome.Hash import keccak
    from keccak_permutation import build_keccak_permutation
    from keccak_trace import keccak256_padded, keccak_f1600, state_from_bytes, state_to_bytes
    plan = build_keccak_permutation(context=CONTEXT, role=ROLE, operation_id=OPERATION)
    initial = state_from_bytes(keccak256_padded(b'')+bytes(64))
    expected = state_to_bytes(keccak_f1600(initial))[:32]
    if expected != keccak.new(digest_bits=256, data=b'').digest():
        raise ValueError('independent mature empty-input Keccak known answer mismatch')
    scenarios, normal_checks = [], 0
    for name in ('honest', 'coherent-state2'):
        scenario, count = _scenario(plan, name, initial, directory)
        scenarios.append(scenario)
        normal_checks += count
    if scenarios[0]['expected_output_state_hex'][:64] != expected.hex():
        raise ValueError('streamed honest graph differs from independent full word reference')
    manifest = dict(schema=SCHEMA, topology_sha256=plan.topology_sha256.hex(),
        context=CONTEXT.hex(), role=ROLE, operation_id=OPERATION,
        totals=TOTALS, scenarios=scenarios)
    info = _write_json(directory/'manifest.json', manifest, MAX_MANIFEST_BYTES)
    return manifest, info, normal_checks


def _new_directory(path):
    cwd = Path.cwd().resolve()
    owner = (cwd/'results').resolve()
    target = Path(path).resolve()
    if not owner.is_relative_to(cwd) or owner == cwd:
        raise ValueError('results directory must stay inside canonical cwd')
    if target == owner or not target.is_relative_to(owner):
        raise ValueError('new full-permutation corpus directory must be beneath cwd/results')
    owner.mkdir(exist_ok=True)
    target.mkdir(parents=True, exist_ok=False, mode=0o700)
    return target


def _worker(path):
    target = Path(path).resolve()
    entry = target.lstat()
    if (not stat.S_ISREG(entry.st_mode) or entry.st_uid != os.getuid()
            or target.name != 'keccak_full' or not os.access(target, os.X_OK)):
        raise ValueError('trusted configured owned keccak_full executable required')
    return target


def _execute(worker, directory, manifest_sha):
    output = directory/'native-execution.json'
    command = ['/usr/bin/prlimit', '--as=536870912', '--cpu=1200', '--fsize=16777216', '--',
        str(worker), str(directory/'manifest.json'), str(directory), str(output), manifest_sha]
    environment = dict(os.environ, RAYON_NUM_THREADS='2', CUDA_VISIBLE_DEVICES='', RUST_BACKTRACE='0')
    with tempfile.TemporaryFile(dir=directory) as stdout, tempfile.TemporaryFile(dir=directory) as stderr:
        result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
            timeout=1260, check=False, env=environment)
        if result.returncode != 0:
            stderr.seek(0)
            message = stderr.read(8192).decode('utf-8', 'replace')
            raise ValueError(f'full-permutation worker failed ({result.returncode}): {message}')
        stdout.seek(0)
        if len(stdout.read(MAX_RESULT_BYTES+1)) > MAX_RESULT_BYTES:
            raise ValueError('full-permutation worker stdout cap')
    if not output.is_file() or output.stat().st_size > MAX_RESULT_BYTES:
        raise ValueError('bounded direct worker output required')
    with output.open('rb') as stream:
        raw = stream.read(MAX_RESULT_BYTES+1)
    if len(raw) > MAX_RESULT_BYTES:
        raise ValueError('direct worker output grew beyond byte cap')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate direct-worker result key')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite result')))


def _validate_execution(native, manifest, info, checks):
    if (type(native) is not dict or native.get('passed') is not True
            or native.get('schema') != 'bitvm2-nova-keccak-full-execution/v1'
            or native.get('topology_sha256') != manifest['topology_sha256']
            or native.get('manifest_sha256') != info['file_sha256']):
        raise ValueError('direct full-permutation worker identity/result mismatch')
    for flag in ('graph_compiled', 'reference_conformance_checked',
                 'hierarchical_membership_verified', 'test_keys_only'):
        if native.get(flag) is not True:
            raise ValueError('missing direct graph conformance: '+flag)
    for flag in ('raw_vector_file_written', 'full_permutation_verified', 'full_hash_verified',
                 'keccak256_verified', 'nova_transcript_verified_in_script', 'proof_verified',
                 'complete_bitvm2_verifier', 'production_assertion_binding',
                 'bitcoin_transaction_graph', 'production_transactions_verified'):
        if native.get(flag) is not False:
            raise ValueError('full-permutation conformance scope exceeded: '+flag)
    for key in ('transactions_broadcast', 'native_proofs_verified', 'proving_jobs'):
        if type(native.get(key)) is not int or native[key] != 0:
            raise ValueError('unexpected production/proving work: '+key)
    rows = native.get('scenarios')
    if type(rows) is not list or len(rows) != 2:
        raise ValueError('two direct full-permutation scenarios required')
    normal = guards = compiled = 0
    negatives = {'forest_altered_script', 'forest_branch', 'forest_parity',
        'forest_internal_key', 'forest_leaf_version', 'forest_truncated_control',
        'forest_appended_control', 'forest_manifest', 'forest_root', 'forest_output_key',
        'forest_component', 'forest_ordinal', 'forest_reordered_components'}
    for actual, expected in zip(rows, manifest['scenarios']):
        if actual.get('name') != expected['name']:
            raise ValueError('direct scenario ordering/identity mismatch')
        counts = dict(components=12, unique_global_words=232110,
            signature_entries_created=232110, cached_signature_reuses=17600,
            internal_boundary_words=19200, internal_boundary_signature_links=38400,
            inter_boundary_words=17600, inter_boundary_signature_links=35200,
            all_boolean_predicates_checked=230510, selected_component=0, selected_leaf=17606,
            guard_vectors=56, additional_selected_engine_executions=2)
        if any(type(actual.get(k)) is not int or actual[k] != value for k, value in counts.items()):
            raise ValueError('direct graph/witness/global-link coverage mismatch')
        if (actual.get('false_predicates') != expected['expected_false']
                or actual.get('selected_correctness_execution_success') is not (expected['name'] == 'honest')
                or actual.get('selected_disproof_execution_success') is not (expected['name'] != 'honest')
                or actual.get('hierarchical_membership_verified') is not True
                or actual.get('roots_independently_pinned') is not False):
            raise ValueError('actual producer execution/membership boundary mismatch')
        control = actual.get('global_control_bytes')
        if type(control) is not int or control != 609:
            raise ValueError('hierarchical proof depth outside bounded schedule')
        rejected = actual.get('forest_negative_counts')
        if (type(rejected) is not dict or set(rejected) != negatives
                or any(type(value) is not int or value != 1 for value in rejected.values())):
            raise ValueError('hierarchical adversarial opening coverage missing')
        ledger = actual.get('local_ledger')
        if type(ledger) is not list or len(ledger) != 12:
            raise ValueError('all twelve actual complete component ledgers required')
        total = 0
        for measured, source in zip(ledger, expected['pairs']):
            for key in ('index', 'first_round', 'catalogue_id', 'words', 'leaves'):
                if measured.get(key) != source[key] or type(measured.get(key)) is not type(source[key]):
                    raise ValueError('measured component detached from fresh source: '+key)
            size = measured.get('compiled_script_bytes')
            if type(size) is not int or not 0 < size <= 1 << 28:
                raise ValueError('component Script byte budget exceeded')
            total += size
        if actual.get('compiled_script_bytes') != total or not 0 < total <= 5 << 28:
            raise ValueError('global Script budget/accounting mismatch')
        compiled += total
        if type(actual.get('normal_leaf_checks')) is not int or actual['normal_leaf_checks'] <= 0:
            raise ValueError('typed actual selected leaf count required')
        normal += actual['normal_leaf_checks']
        guards += actual['guard_vectors']
    metrics = native.get('metrics', {})
    if (normal != checks or type(metrics.get('vectors')) is not int
            or metrics['vectors'] != 2*checks+guards):
        raise ValueError('direct selected Script vector census mismatch')
    if (type(metrics.get('expected_rejections')) is not int
            or metrics['expected_rejections'] != checks+guards
            or metrics.get('max_stack_items', 1001) > 1000
            or metrics.get('max_witness_items', 1001) > 1000):
        raise ValueError('direct rejection/stack/witness coverage mismatch')
    return compiled


def run(cases_dir, native_worker):
    _guard()  # Before requested-path I/O, graphs or subprocesses.
    started = time.perf_counter()
    worker = _worker(native_worker)
    directory = _new_directory(cases_dir)
    manifest, info, checks = _generate(directory)
    native = _execute(worker, directory, info['file_sha256'])
    _validate_execution(native, manifest, info, checks)
    return dict(schema='bitvm2-nova-keccak-full-conformance/v1', native=native,
        topology_sha256=manifest['topology_sha256'], manifest_sha256=info['file_sha256'],
        normal_leaf_checks=checks, totals=TOTALS, scenarios=2,
        direct_native_worker_executed=True, external_result_receipt_loaded=False,
        empty_input_known_answer_checked=True, input_padding_script_bound=False,
        full_hash_verified=False, nova_transcript_verified_in_script=False,
        proof_verified=False, complete_bitvm2_verifier=False, production_assertion_binding=False,
        bitcoin_transaction_graph=False, transactions_broadcast=0, proving_jobs=0,
        wall_seconds=time.perf_counter()-started, parent_peak_rss_bytes=peak_rss(),
        scope='streamed full-permutation topology/fixture execution and hierarchical membership only')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cases-dir', type=Path, required=True)
    parser.add_argument('--native-worker', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = run(args.cases_dir, args.native_worker)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    _write_json(args.output, result, MAX_RESULT_BYTES)
    print(json.dumps(result))


if __name__ == '__main__':
    main()
