"""Hosted M23 compressed-commitment decoding conformance, one curve role per run.

The asserted payload and coordinates come from closed recipes, independent of
any receipt. The unchanged BYTE tape and every commitment decoder of the role
run through the frozen legacy registry/interpreter in a direct native worker.
Point semantics, transcript, MSM/IPA and proof acceptance remain open.
"""
from collections import Counter
from hashlib import sha256
import argparse
import json
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import time

from bench_byte_rho import _new_directory, _equal, _hex32, MAX_CASE_BYTES, MAX_MANIFEST_BYTES
from bench_keccak_endpoint import _write_json
from bench_compact import peak_rss

CONTEXT = sha256(b'BITVM2-NOVA/PROOF-POINT-ORIGINS-CONFORMANCE/v1').digest()
OPERATION = 'benchmark/proof-point-origins/v1'
SCHEMA = 'bitvm2-nova-proof-point-origins-run/v1'
MAX_RESULT_BYTES = 1 << 20
MAX_RECORD_BYTES = 128 << 20
RECORD_LINE_BYTES = 218
GUARD_CAP = 512
MAX_JSON_NODES = 700_000
WORKER_SECONDS = 2280
SNAPSHOT_CRATES = ('rust-oracle', 'point-oracle', 'scalar-source-oracle', 'point-origins-oracle')
TRUE_FLAGS = ('test_keys_only', 'legacy_registry_and_engine_used',
    'source_preflight_before_keys', 'global_key_preflight_before_signatures',
    'physical_byte_opening_links_checked', 'strict_halo2_decoding_matches_leaf_relation',
    'canonical_coordinate_guards_preserved', 'raw_u32_diagnostics_preserved',
    'exact_witness_length_guards_checked', 'stack_limit_enabled',
    'correctness_bytes_equal_disproof_minus_one_checked')
EXTRA_FALSE = ('panic_is_rejection', 'op_cat_enabled', 'all_cases_full_statement_executed',
    'raw_vector_file_written', 'reference_hash_authenticates_claimed_payload')
ZERO_FIELDS = ('setup_calls', 'proving_jobs', 'native_proofs_verified', 'gpu_jobs',
    'transactions_broadcast', 'tree_calls')
METRIC_SUM = ('vectors', 'expected_rejections')
METRIC_MAX = ('max_script_bytes', 'max_witness_items', 'max_witness_payload_bytes', 'max_stack_items')


def _guard():
    if (os.environ.get('GITHUB_ACTIONS') != 'true'
            or os.environ.get('RUNNER_OS') != 'Linux' or sys.platform != 'linux'):
        raise ValueError('proof point origin execution is hosted GitHub Linux only')


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def _engine(engine):
    import proof_point_origins as m
    if type(engine) is not str or engine not in m.ENGINES:
        raise ValueError('explicit pallas or vesta role required')
    return engine


def record_budget(engine):
    """Closed engine-call/record bound before any graph or key exists."""
    import proof_point_origins as m
    components = len(m.component_plan(_engine(engine)))+1
    leaves = sum(m.component_census(engine, i)[3] for i in range(components))
    targeted = len(m.PROFILES)-1
    calls = 2*leaves + 14*GUARD_CAP*components + targeted*(2*m.TARGET_CAP+14*GUARD_CAP) + 1024
    size = calls*RECORD_LINE_BYTES
    if size > MAX_RECORD_BYTES:
        raise ValueError('closed corpus exceeds unchanged 128MiB record cap')
    return dict(components=components, leaves=leaves, full_statement_cases=1,
        targeted_statement_cases=targeted, total_engine_calls_upper=calls,
        record_line_bytes=RECORD_LINE_BYTES, combined_upper_bytes=size, hard_cap_bytes=MAX_RECORD_BYTES)


def _lexical_nodes(raw):
    if type(raw) is not bytes or len(raw) > MAX_CASE_BYTES:
        raise ValueError('bounded canonical ASCII case bytes required')
    quoted = escaped = False
    nodes = depth = string_bytes = 0
    for byte in raw:
        if byte > 127:
            raise ValueError('canonical ASCII case bytes required')
        if quoted:
            string_bytes += 1
            if string_bytes > 200000:
                raise ValueError('case JSON string work limit')
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        else:
            if byte == 34:
                quoted, string_bytes = True, 0
                nodes += 1
            elif byte in (91, 123):
                depth += 1
                nodes += 1
            elif byte in (93, 125):
                depth = max(0, depth-1)
            elif byte in (44, 58):
                nodes += 1
            if depth > 32 or nodes > MAX_JSON_NODES:
                raise ValueError('case JSON node/depth work limit')
    return nodes


def _hash_file(path, maximum):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError('bounded regular source file required')
    digest, size = sha256(), 0
    with path.open('rb') as stream:
        while chunk := stream.read(65536):
            size += len(chunk)
            if size > maximum:
                raise ValueError('source file exceeds byte cap')
            digest.update(chunk)
    return dict(bytes=size, sha256=digest.hexdigest())


def _worker(path):
    _guard()
    source = Path(path)
    if source.is_symlink():
        raise ValueError('regular configured proof_point_origins worker required')
    target = source.resolve()
    entry = target.lstat()
    if (not stat.S_ISREG(entry.st_mode) or entry.st_uid != os.getuid()
            or target.name != 'proof_point_origins' or not os.access(target, os.X_OK)):
        raise ValueError('owned configured point origins executable required')
    return target


def _source_snapshot(worker):
    _guard()
    root = Path(__file__).resolve().parent
    paths = set(root.glob('*.py'))
    rust = []
    for crate in SNAPSHOT_CRATES:
        source = root/crate/'src'
        if source.is_symlink() or not source.is_dir():
            raise ValueError('configured Rust source roots required')
        rust.extend(source.rglob('*.rs'))
        for filename in ('Cargo.toml', 'Cargo.lock'):
            path = root/crate/filename
            if path.is_symlink() or not path.is_file():
                raise ValueError('configured manifests and generated locks required')
            paths.add(path)
    paths.update(rust)
    required = root/'transcript-requirements.txt'
    if required.is_symlink() or not required.is_file():
        raise ValueError('required transcript dependency input snapshot incomplete')
    paths.add(required)
    for suffix in ('.expected.json', '.dimensions.json', '.nht4'):
        path = root/'fixtures'/('nht4-genesis-0-2020-k5'+suffix)
        if not path.is_file():
            raise ValueError('retained fixture snapshot incomplete')
        paths.add(path)
    pending, inspected = list(rust), set()
    while pending:
        path = pending.pop()
        if path in inspected:
            continue
        inspected.add(path)
        with path.open('rb') as stream:
            raw = stream.read((2 << 20)+1)
        if len(raw) > 2 << 20:
            raise ValueError('compiled source exceeds byte cap')
        text = raw.decode('utf-8')
        for relative in (re.findall(r'include_(?:bytes|str)!\s*\(\s*"([^"]+)"\s*\)', text)
                         + re.findall(r'#\s*\[\s*path\s*=\s*"([^"]+)"\s*\]', text)):
            target = (path.parent/relative).resolve()
            if not target.is_relative_to(root) or not target.is_file():
                raise ValueError('compiled input leaves integration root')
            paths.add(target)
            if target.suffix == '.rs':
                pending.append(target)
    if len(paths) > 256:
        raise ValueError('compiled dependency snapshot file-count cap exceeded')
    files, total = [], 0
    for path in sorted(paths):
        if path.is_symlink() or not path.resolve().is_relative_to(root):
            raise ValueError('source snapshot leaves integration root')
        info = _hash_file(path, 2 << 20)
        total += info['bytes']
        if total > 64 << 20:
            raise ValueError('source snapshot total cap exceeded')
        files.append(dict(path=path.relative_to(root).as_posix(), **info))
    return dict(schema='bitvm2-nova-worker-source-snapshot/v1', files=files,
        source_snapshot_sha256=sha256(_canonical(files)).hexdigest(),
        worker_executable=_hash_file(worker, 128 << 20),
        trusted_configured_library_boundary=True, binary_source_equivalence_attested=False)


def _reference_files(directory):
    _guard()
    from nht4 import load_expected_json, bind_container
    from proof_codec import load_dimensions_json
    root = Path(__file__).resolve().parent/'fixtures'
    stem = 'nht4-genesis-0-2020-k5'

    def read(suffix, maximum):
        path = root/(stem+suffix)
        if path.is_symlink() or not path.is_file():
            raise ValueError('regular pinned retained reference required')
        with path.open('rb') as stream:
            raw = stream.read(maximum+1)
        if len(raw) > maximum:
            raise ValueError('reference file exceeds transport cap')
        return raw
    raw = read('.nht4', 1 << 20)
    expected = load_expected_json(read('.expected.json', 8192))
    dimensions = load_dimensions_json(read('.dimensions.json', 16384), expected,
        expected_descriptor_sha256=bytes.fromhex(
            'de6333df2e41b5f5bae1c103fab862f8d6022fd54abeb80ba61920bc9f360edc'))
    bound = bind_container(raw, expected)
    if len(raw) != 13220 or len(bound.proof) != 12664:
        raise ValueError('retained 13220-byte container/12664-byte proof required')
    with (directory/'reference.nht4').open('xb') as stream:
        stream.write(raw)
    references = [dict(kind='bundle', filename='reference.nht4',
        file_sha256=sha256(raw).hexdigest(), file_bytes=len(raw))]
    for kind, filename, value, maximum in (
            ('expected', 'reference.expected.json', expected.json(), 8192),
            ('dimensions', 'reference.dimensions.json', dimensions.json(), 16384)):
        info = _write_json(directory/filename, value, maximum)
        references.append(dict(kind=kind, filename=filename, file_sha256=info['file_sha256'],
                               file_bytes=info['file_bytes']))
    return (raw, expected, dimensions), references


def _guard_ordinals(spec, selected, false, full):
    """First leaf of each authenticated layout among the selection, plus false leaves."""
    from wots_graph import authenticated_shape
    shapes = {}
    for ordinal in selected:
        shapes.setdefault(authenticated_shape(spec, spec.leaves[ordinal]), ordinal)
    chosen = set(shapes.values())
    if not full:
        chosen.update(false)
    result = sorted(chosen)
    if len(result) > GUARD_CAP:
        raise ValueError('closed guard ordinal budget exceeded')
    return result


def _generate(directory, engine):
    _guard()
    import proof_point_origins as m
    budget = record_budget(engine)
    reference, references = _reference_files(directory)
    plan = m.build_proof_point_origins(*reference, engine=engine, context=CONTEXT, operation_id=OPERATION)
    profiles, groups, census = [], [], []
    expected_reuses = 32*m.COMMITMENTS[engine]
    for group_index, profile in enumerate(m.PROFILES):
        name = f'd/{group_index:02d}'
        binding = plan.bind_profile(profile)
        full = profile == 'honest'
        headers, counts, seen = [], [], {}
        local = openings = selected_total = 0
        for record in binding.iter_components():
            spec, program, values = record.spec, record.program, record.assignment
            descriptor = dict(record.descriptor)
            index = descriptor['index']
            if index != len(headers) or spec.context != CONTEXT.hex():
                raise ValueError('closed component order/context differs')
            for key, value in (('words', len(spec.words)), ('leaves', len(spec.leaves)),
                    ('arithmetic_constraints', len(program.constraints)),
                    ('canonical_fields', len(spec.field_leaves)),
                    ('program_sha256', spec.program_sha256), ('catalogue_id', spec.digest().hex())):
                _equal(descriptor[key], value, 'sealed descriptor '+key)
            ids = record.global_ids
            for global_id, (word, bound) in zip(ids, spec.words, strict=True):
                value = values[word]
                if type(value) is not int or not 0 <= value <= 0xffffffff:
                    raise ValueError('all signed assertions must retain exact unsigned32 values')
                identity = (bound, value)
                if global_id in seen:
                    if seen[global_id] != identity or not global_id.startswith('proof/container-byte/'):
                        raise ValueError('shared physical source word has conflicting assertion')
                else:
                    seen[global_id] = identity
                local += 1
            truth = record.truth
            selected = list(record.selected_ordinals)
            if full and selected != list(range(len(spec.leaves))):
                raise ValueError('honest profile executes every leaf')
            false = [i for i, v in enumerate(truth) if v is False]
            abort = [i for i, v in enumerate(truth) if v is None]
            if abort or not set(false) <= set(selected) or (full and false):
                raise ValueError('closed selection/abort/false coverage differs')
            unique = [len(set(leaf.wires)) for leaf in spec.leaves]
            openings += sum(unique)
            selected_total += len(selected)
            guard = _guard_ordinals(spec, selected, false, full)
            kinds = Counter(spec.leaves[i].kind for i in selected)
            decoders = []
            if index:
                for local_index, d in enumerate(descriptor['decoders']):
                    leaves = m.decoder_leaf_ordinals(engine, index, local_index)
                    if set(leaves) <= set(selected):
                        decoders.append(d)
            counts.append(dict(selected=selected, false=false, guard=guard, kinds=dict(kinds),
                selected_unique_openings=sum(unique[i] for i in selected), costed_decoders=decoders))
            case = dict(name=f'{name}/{descriptor["name"]}', spec=spec.json(),
                expected_spec_id=spec.digest().hex(),
                words=[values[word] for word, _ in spec.words],
                checks=[dict(ordinal=i, expected_correct=truth[i]) for i in selected],
                measure_all=full)
            raw_case = _canonical(case)
            _lexical_nodes(raw_case)
            filename = f'case-{group_index:02d}-{index:02d}.json'
            info = _write_json(directory/filename, case, MAX_CASE_BYTES)
            header = dict(descriptor, decoders=list(descriptor['decoders']), filename=filename,
                file_sha256=info['file_sha256'], file_bytes=info['file_bytes'],
                execution_mode='all' if full else 'selected',
                selected_ordinals=None if full else selected,
                expected_false=false, expected_abort_ordinals=abort)
            headers.append(header)
            del record, spec, program, values, truth, case, raw_case
        if len(headers) != budget['components'] or local-len(seen) != expected_reuses:
            raise ValueError('whole-profile component census or physical BYTE reuse differs')
        if not full and selected_total > m.TARGET_CAP:
            raise ValueError('targeted union exceeds closed cap')
        group = dict(name=name, profile=profile, engine=engine, source_sha256=plan.source_sha256.hex(),
                     components=headers)
        filename = f'group-{group_index:02d}.json'
        info = _write_json(directory/filename, group, MAX_MANIFEST_BYTES)
        profiles.append(dict(name=name, profile=profile, group_filename=filename,
            group_hash=info['file_sha256'], group_bytes=info['file_bytes']))
        groups.append(group)
        census.append(dict(counts=counts, global_words=len(seen), local_words=local, openings=openings,
                           target=binding.target))
        del binding, seen
    manifest = dict(schema=SCHEMA, context=CONTEXT.hex(), operation_id=OPERATION, engine=engine,
                    references=references, cases=profiles)
    info = _write_json(directory/'manifest.json', manifest, MAX_MANIFEST_BYTES)
    expected_files = 4 + len(m.PROFILES)*(1+budget['components'])
    if len(list(directory.iterdir())) != expected_files:
        raise ValueError('exact closed source input inventory required')
    return manifest, info, groups, census, plan.summary()


def _execute(worker, directory, manifest_sha):
    """Direct worker execution under the unchanged 512MiB address-space cap."""
    _guard()
    output = directory/'native-execution.json'
    if output.exists():
        raise ValueError('fresh direct point result required')
    command = ['/usr/bin/prlimit', '--as=536870912', f'--cpu={WORKER_SECONDS}', '--fsize=16777216', '--',
        str(worker), str(directory/'manifest.json'), str(directory), str(output), manifest_sha]
    environment = dict(os.environ, RAYON_NUM_THREADS='2', CUDA_VISIBLE_DEVICES='', RUST_BACKTRACE='0')
    with tempfile.TemporaryFile(dir=directory) as stdout, tempfile.TemporaryFile(dir=directory) as stderr:
        try:
            result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                                    timeout=WORKER_SECONDS+60, check=False, env=environment)
        except subprocess.TimeoutExpired as error:
            raise ValueError('direct point worker exceeded wall-time limit') from error
        if result.returncode != 0:
            stderr.seek(0)
            raise ValueError(f'direct point worker failed ({result.returncode}): '
                             + stderr.read(8192).decode('utf-8', 'replace'))
        for stream in (stdout, stderr):
            stream.seek(0, 2)
            if stream.tell() > MAX_RESULT_BYTES:
                raise ValueError('point diagnostic-output cap exceeded')
    if not output.is_file() or output.is_symlink() or output.stat().st_size > MAX_RESULT_BYTES:
        raise ValueError('bounded direct point output required')
    with output.open('rb') as stream:
        raw = stream.read(MAX_RESULT_BYTES+1)
    if len(raw) > MAX_RESULT_BYTES:
        raise ValueError('direct point output grew beyond cap')

    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError('duplicate native JSON key')
            value[key] = item
        return value
    return json.loads(raw.decode('ascii'), object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))


def _expected_reference():
    return dict(schema='bitvm2-nova-proof-point-reference/v1', reference_admitted=True,
        network='testnet4', k=5, steps=404, header_revision='de607d3db17d400dd6c2923d357f1d4a7bf233c7',
        nova_version='0.76.0',
        expected_policy_sha256='cdfa31622881cc1863abd1eb252c136184501785b4b02e9985e6ba0850b2ac54',
        verifier_dimensions_sha256='de6333df2e41b5f5bae1c103fab862f8d6022fd54abeb80ba61920bc9f360edc',
        verifier_key_sha256='1ae88a7bcfdc5f14d030d0baafa06ec17fe904a5ebed42f9bd6fa6105fdc8c24',
        bundle_sha256='c3143d5627ef7291ab6a858b866a4ba19e356a168dea992d3e572ef6531904e9',
        proof_sha256='2137c6e8621cedb7423e0ef7f9ff7c27b2c6fdf3ceb227e644b3d9660d056617',
        bundle_bytes=13220, header_bytes=556, payload_bytes=12664, spans=485,
        pallas_commitments=43, vesta_commitments=35,
        reference_hash_authenticates_claimed_payload=False, proof_verified=False)


def _metrics(value, calls, rejects, label):
    keys = METRIC_SUM+METRIC_MAX
    if type(value) is not dict or set(value) != set(keys) or any(
            type(value[k]) is not int or value[k] < 0 for k in keys):
        raise ValueError('exact six-field integer metrics required: '+label)
    _equal(value['vectors'], calls, label+' engine calls')
    _equal(value['expected_rejections'], rejects, label+' expected rejections')
    if (not 0 < value['max_script_bytes'] <= 100000
            or not 0 < value['max_witness_items'] <= value['max_stack_items'] <= 1000
            or not 0 < value['max_witness_payload_bytes'] <= 520*value['max_witness_items']):
        raise ValueError('unchanged Script/witness/stack limits exceeded: '+label)
    return value


def _fold(target, metrics):
    for key in METRIC_SUM:
        target[key] += metrics[key]
    for key in METRIC_MAX:
        target[key] = max(target[key], metrics[key])


def _validate(native, engine, info, groups, census):
    """Check a direct worker observation; no receipt-loading public API exists."""
    import proof_point_origins as m
    if type(native) is not dict or native.get('passed') is not True:
        raise ValueError('successful direct point worker required')
    _equal(native.get('schema'), 'bitvm2-nova-proof-point-origins-execution/v1', 'schema')
    _equal(native.get('engine'), engine, 'engine')
    _equal(native.get('input_manifest_sha256'), info['file_sha256'], 'fresh manifest identity')
    _equal(native.get('reference'), _expected_reference(), 'complete native reference observation')
    for flag in TRUE_FLAGS:
        if native.get(flag) is not True:
            raise ValueError('required narrow source relation missing: '+flag)
    for flag in m.FALSE_FLAGS+EXTRA_FALSE:
        if native.get(flag) is not False:
            raise ValueError('source authority/scope exceeded: '+flag)
    for field in ZERO_FIELDS:
        _equal(native.get(field), 0, field)
    budget = record_budget(engine)
    _equal(native.get('closed_call_budget'), budget['total_engine_calls_upper'], 'closed call budget')
    _equal(native.get('full_statement_cases'), 1, 'full cases')
    _equal(native.get('targeted_statement_cases'), len(m.PROFILES)-1, 'targeted cases')
    size = native.get('compact_execution_records_bytes')
    if (type(size) is not int or not 0 < size <= budget['combined_upper_bytes']
            or not _hex32(native.get('compact_execution_records_sha256'))):
        raise ValueError('compact record bound/hash differs')
    rows = native.get('cases')
    if type(rows) is not list or len(rows) != len(groups) or len(groups) != len(m.PROFILES):
        raise ValueError('all closed source cases required')
    folded = {k: 0 for k in METRIC_SUM+METRIC_MAX}
    normal_fold = dict(folded)
    measurements, signatures = [], 0
    for row, group, count in zip(rows, groups, census, strict=True):
        full = group['profile'] == 'honest'
        for key in ('name', 'profile', 'source_sha256'):
            _equal(row.get(key), group[key], 'case '+key)
        coherent = group['profile'] in m.COHERENT
        for key, value in dict(local_words=count['local_words'], global_words=count['global_words'],
                source_reuses=32*m.COMMITMENTS[engine], signature_entries_created=count['global_words'],
                full_signature_signing_calls=count['global_words'],
                byte_opening_links=32*m.COMMITMENTS[engine], actual_opening_occurrences=count['openings'],
                actual_opening_repeats=count['openings']-count['global_words'],
                actual_opened_global_words=count['global_words'], opening_pass_all_leaves=True,
                native_accepted_decoders=m.COMMITMENTS[engine]-int(not coherent),
                native_rejected_decoders=int(not coherent)).items():
            _equal(row.get(key), value, key)
        signatures += count['global_words']
        parts = row.get('components')
        if type(parts) is not list or len(parts) != len(group['components']):
            raise ValueError('actual component ledgers required')
        compiled_total = 0
        decoder_bytes = {}
        for part, header, facts in zip(parts, group['components'], count['counts'], strict=True):
            for key in ('index', 'name', 'field_role', 'operation_id', 'program_identity_kind', 'words',
                    'arithmetic_constraints', 'canonical_fields', 'leaves', 'program_sha256', 'catalogue_id',
                    'global_ids_sha256', 'decoders'):
                _equal(part.get(key), header[key], 'component '+key)
            selected = facts['selected']
            _equal(part.get('measured_ordinals'), None if full else selected, 'measured ordinals')
            _equal(part.get('false_predicates'), header['expected_false'], 'false predicates')
            _equal(part.get('abort_predicates'), [], 'no abort predicates')
            for key, value in dict(measured_leaves=len(selected), normal_vectors=2*len(selected),
                    guarded_leaves=len(facts['guard']), standard_guard_vectors=14*len(facts['guard']),
                    proper_disproof_vectors=len(facts['false']), abort_leaf_checks=0,
                    native_rejections=9).items():
                _equal(part.get(key), value, key)
            for key in ('compiled_stream_sha256', 'registry_id'):
                if not _hex32(part.get(key)):
                    raise ValueError('actual legacy component identity missing: '+key)
            kinds = part.get('kind_costs')
            if type(kinds) is not dict or set(kinds) != set(facts['kinds']):
                raise ValueError('measured predicate-kind inventory differs')
            compiled = largest = 0
            for kind, cost in kinds.items():
                if (type(cost) is not list or len(cost) != 3 or any(type(v) is not int for v in cost)
                        or cost[0] != facts['kinds'][kind] or not 0 < cost[2] <= 100000
                        or not cost[2] <= cost[1] <= cost[0]*cost[2]):
                    raise ValueError('exact per-kind measured cost row required: '+kind)
                compiled += cost[1]
                largest = max(largest, cost[2])
            if compiled > 256 << 20:
                raise ValueError('component Script stream exceeds unchanged 256MiB cap')
            _equal(part.get('compiled_script_bytes'), compiled, 'actual measured disproof sum')
            _equal(part.get('largest_disproof_leaf_bytes'), largest, 'largest actual leaf')
            costs = part.get('decoder_costs')
            if type(costs) is not list or [c[0] for c in costs] != facts['costed_decoders']:
                raise ValueError('complete decoder cost rows required')
            for decoder, value in costs:
                if type(value) is not int or not 0 < value <= compiled:
                    raise ValueError('bounded decoder cost')
                decoder_bytes[decoder] = value
            if sum(c[1] for c in costs) > compiled:
                raise ValueError('decoder subtotals exceed component total')
            normals = 2*len(selected)
            normal_rejects = len(selected)
            guards = 14*len(facts['guard'])
            normal = _metrics(part.get('normal_metrics'), normals, normal_rejects, 'normal component')
            _equal(normal['max_script_bytes'], largest, 'normal peak equals measured leaf maximum')
            overall = _metrics(part.get('metrics'), normals+guards, normal_rejects+guards, 'guard component')
            _equal(overall['max_script_bytes'], largest, 'guards reuse measured catalogue scripts')
            for key in METRIC_MAX:
                if overall[key] < normal[key]:
                    raise ValueError('guard-inclusive peak below normal snapshot')
            _fold(normal_fold, normal)
            _fold(folded, overall)
            compiled_total += compiled
        if compiled_total > 5 << 28:
            raise ValueError('aggregate Script exceeds unchanged 1.25GiB cap')
        _equal(row.get('measured_disproof_script_bytes'), compiled_total, 'case Script total')
        if full and sorted(decoder_bytes) != list(range(m.COMMITMENTS[engine])):
            raise ValueError('honest profile must cost every decoder')
        measurements.append(dict(name=group['name'], profile=group['profile'],
            complete_statement_executed=full, measured_disproof_script_bytes=compiled_total,
            target_decoder=count['target'],
            decoder_bytes=dict(sorted(decoder_bytes.items())) if full else None))
    _equal(native.get('signature_entries_created'), signatures, 'signature total')
    _equal(native.get('full_signature_signing_calls'), signatures, 'signing total')
    _equal(_metrics(native.get('metrics'), folded['vectors'], folded['expected_rejections'], 'global'),
           folded, 'exact all-metrics fold')
    _equal(_metrics(native.get('normal_metrics'), normal_fold['vectors'], normal_fold['expected_rejections'],
                    'global normal'), normal_fold, 'exact normal-metrics fold')
    if folded['vectors'] > budget['total_engine_calls_upper']:
        raise ValueError('actual engine calls exceed closed pre-key budget')
    wall = native.get('wall_seconds')
    if type(wall) not in (int, float) or not math.isfinite(wall) or not 0 <= wall <= WORKER_SECONDS:
        raise ValueError('direct native wall-time scope exceeded')
    return measurements


def run(engine, cases_dir, native_worker):
    _guard()
    started = time.perf_counter()
    budget = record_budget(engine)
    worker = _worker(native_worker)
    snapshot = _source_snapshot(worker)
    directory = _new_directory(cases_dir)
    manifest, info, groups, census, summary = _generate(directory, engine)
    native = _execute(worker, directory, info['file_sha256'])
    measurements = _validate(native, engine, info, groups, census)
    _equal(_source_snapshot(worker), snapshot, 'configured sources/binary unchanged during direct execution')
    honest = measurements[0]
    result = dict(schema='bitvm2-nova-proof-point-origins-conformance/v1', engine=engine,
        native=native, manifest=info, source_snapshot=snapshot, record_budget=budget,
        source_summary=summary, actual_measurements=measurements,
        complete_honest_disproof_script_bytes=honest['measured_disproof_script_bytes'],
        direct_native_worker_executed=True, external_result_receipt_loaded=False,
        sources_unchanged_during_run=True, retained_max_width_profile_only=True,
        proof_header_excluded=True, all_cases_full_statement_executed=False,
        legacy_registry_and_engine_used=True, script_cost_includes_assertion_signatures=False,
        transaction_framing_included=False, witness_bytes_included_in_script_cost=False,
        setup_calls=0, proving_jobs=0, native_proofs_verified=0, gpu_jobs=0, transactions_broadcast=0,
        wall_seconds=time.perf_counter()-started, parent_peak_rss_bytes=peak_rss(),
        scope='commitment BYTEs -> canonical affine coordinates under a retained profile; coherent '
              'substitutions of other valid points pass; no point semantics/transcript/MSM/IPA/proof acceptance')
    import proof_point_origins as m
    result.update({flag: False for flag in m.FALSE_FLAGS})
    if len(_canonical(result)) > MAX_RESULT_BYTES:
        raise ValueError('complete published observation exceeds unchanged 1MiB summary cap')
    return result


def _load_report(path, engine):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_RESULT_BYTES:
        raise ValueError('bounded regular role report required')

    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError('duplicate report JSON key')
            value[key] = item
        return value
    report = json.loads(path.read_bytes().decode('ascii'), object_pairs_hook=unique)
    if (type(report) is not dict or report.get('schema') != 'bitvm2-nova-proof-point-origins-conformance/v1'
            or report.get('engine') != engine or report.get('direct_native_worker_executed') is not True
            or report.get('external_result_receipt_loaded') is not False
            or report.get('native', {}).get('passed') is not True
            or report['native'].get('engine') != engine):
        raise ValueError('direct role observation required: '+engine)
    return report


def aggregate(pallas_path, vesta_path):
    """Reconcile both role reports; reads observations only, never authorizes."""
    _guard()
    import proof_point_origins as m
    reports = dict(pallas=_load_report(pallas_path, 'pallas'), vesta=_load_report(vesta_path, 'vesta'))
    roles = {}
    for engine, report in reports.items():
        native = report['native']
        honest = report['actual_measurements'][0]
        if (honest['profile'] != 'honest' or not honest['complete_statement_executed']
                or sorted(int(k) for k in honest['decoder_bytes']) != list(range(m.COMMITMENTS[engine]))
                or report['complete_honest_disproof_script_bytes'] != honest['measured_disproof_script_bytes']):
            raise ValueError('complete honest role measurement required: '+engine)
        for flag in m.FALSE_FLAGS:
            if report.get(flag) is not False or native.get(flag) is not False:
                raise ValueError('role report exceeded scope: '+flag)
        roles[engine] = dict(decoders=m.COMMITMENTS[engine],
            complete_honest_disproof_script_bytes=honest['measured_disproof_script_bytes'],
            decoder_script_bytes=sum(honest['decoder_bytes'].values()),
            engine_calls=native['metrics']['vectors'],
            expected_rejections=native['metrics']['expected_rejections'],
            normal_calls=native['normal_metrics']['vectors'],
            max_script_bytes=native['metrics']['max_script_bytes'],
            max_stack_items=native['metrics']['max_stack_items'],
            wall_seconds=native['wall_seconds'], manifest_sha256=report['manifest']['file_sha256'])
    result = dict(schema='bitvm2-nova-proof-point-origins-accounting/v1', roles=roles,
        decoders=sum(r['decoders'] for r in roles.values()),
        decoder_script_bytes=sum(r['decoder_script_bytes'] for r in roles.values()),
        engine_calls=sum(r['engine_calls'] for r in roles.values()),
        expected_rejections=sum(r['expected_rejections'] for r in roles.values()),
        tape_counted_once_per_role=True, external_result_receipt_authorizes_acceptance=False)
    result.update({flag: False for flag in m.FALSE_FLAGS})
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--engine', choices=('pallas', 'vesta'))
    parser.add_argument('--cases-dir', type=Path)
    parser.add_argument('--native-worker', type=Path)
    parser.add_argument('--aggregate', action='store_true')
    parser.add_argument('--pallas-report', type=Path)
    parser.add_argument('--vesta-report', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    _guard()
    from bench_keccak_endpoint import _output_file
    output = _output_file(args.output)
    if args.aggregate:
        if args.engine or args.cases_dir or args.native_worker or not (args.pallas_report and args.vesta_report):
            raise ValueError('aggregate mode takes exactly the two role reports')
        result = aggregate(args.pallas_report, args.vesta_report)
        _write_json(output, result, MAX_RESULT_BYTES)
        print(json.dumps(result, ensure_ascii=True, allow_nan=False))
        return
    if not (args.engine and args.cases_dir and args.native_worker) or args.pallas_report or args.vesta_report:
        raise ValueError('role mode takes --engine, --cases-dir and --native-worker')
    result = run(args.engine, args.cases_dir, args.native_worker)
    _write_json(output, result, MAX_RESULT_BYTES)
    print(json.dumps(dict(engine=result['engine'],
        complete_honest_disproof_script_bytes=result['complete_honest_disproof_script_bytes'],
        actual_measurements=result['actual_measurements'], wall_seconds=result['wall_seconds'],
        parent_peak_rss_bytes=result['parent_peak_rss_bytes']), ensure_ascii=True, allow_nan=False))


if __name__ == '__main__':
    main()
