"""Hosted legacy proof-payload BYTE-to-scalar origin conformance.

The asserted payload is independent of the admitted retained reference. This
profile connects its physical BYTE positions to canonical scalar encodings;
opaque point bytes, container/header/hash/EOF and proof validity remain open.
Only the frozen legacy registry/interpreter is used. No receipt is an input.
"""
from hashlib import sha256
import argparse
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
import time

from bench_byte_rho import (_execute, _new_directory, _equal, _hex32,
    MAX_CASE_BYTES, MAX_MANIFEST_BYTES, MAX_RESULT_BYTES)
from bench_keccak_endpoint import _write_json
from bench_compact import peak_rss


CONTEXT = sha256(b'BITVM2-NOVA/PROOF-PAYLOAD-ORIGINS-CONFORMANCE/v1').digest()
OPERATION = 'benchmark/proof-payload-origins/v1'
SCHEMA = 'bitvm2-nova-proof-payload-origins-run/v1'
PROFILES = ('honest', 'coherent-p-eval', 'coherent-v-eval', 'p-mod', 'p-mod1',
    'v-mod', 'v-mod1', 'zn0-width', 'p-outer-count', 'v-outer-count',
    'opaque-p', 'opaque-v', 'byte-256', 'byte-max')
COMPONENT_WORDS = (12664, 9295, 6545)
COMPONENT_LEAVES = (12664, 2873, 2023)
COMPONENT_ROLES = ('pallas_scalar', 'pallas_scalar', 'vesta_scalar')
BRANCHES = ('tape', 'pallas', 'vesta')
LEAF_COST_COLUMNS = ['disproof_script_bytes', 'witness_items', 'witness_payload_bytes']
MAX_RECORD_BYTES = 128 << 20
MAX_TARGET_LEAVES = 128
MAX_JSON_NODES = 450000


def _guard():
    if (os.environ.get('GITHUB_ACTIONS') != 'true'
            or os.environ.get('RUNNER_OS') != 'Linux' or sys.platform != 'linux'):
        raise ValueError('proof payload origin execution is hosted GitHub Linux only')


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
        ensure_ascii=True, allow_nan=False).encode('ascii')


def _requests():
    return tuple((f'd/{index:02d}', profile) for index, profile in enumerate(PROFILES))


def _record_budget():
    """Closed serialized work bound before graph allocation or key generation."""
    normal = 2 * sum(COMPONENT_LEAVES)
    # A BYTE constant has at most256 values, plus word_valid. This bound does
    # not assume the retained prefix alphabet before the fresh layout exists.
    honest_guards = 14 * (257 + 17 + 17)
    targeted = 13 * MAX_TARGET_LEAVES * (2 + 14)
    reserve = 1024
    maximum = len(_canonical(dict(c=['d/13', 2], i='g'*32, m=False, e=False,
        s='0'*64, w='0'*64))) + 1
    calls = normal + honest_guards + targeted + reserve
    size = calls * maximum
    if size > MAX_RECORD_BYTES:
        raise ValueError('closed legacy origin corpus exceeds unchanged128MiB record cap')
    return dict(main_cases=14, full_statement_cases=1, targeted_statement_cases=13,
        honest_normal_calls=normal, honest_guard_calls_upper=honest_guards,
        targeted_calls_upper=targeted, additional_calls_reserve=reserve,
        total_engine_calls_upper=calls, record_bytes_upper=maximum,
        combined_upper_bytes=size, hard_cap_bytes=MAX_RECORD_BYTES)


def _summary_budget():
    rows = sum(COMPONENT_LEAVES) + 13 * MAX_TARGET_LEAVES
    row_bytes = len(_canonical([100000, 1000, 520000])) + 1
    metadata = 300000
    size = rows * row_bytes + metadata
    if size > MAX_RESULT_BYTES:
        raise ValueError('closed legacy origin summary exceeds unchanged1MiB cap')
    return dict(cost_rows_upper=rows, cost_row_bytes_upper=row_bytes,
        metadata_bytes_upper=metadata, combined_upper_bytes=size,
        hard_cap_bytes=MAX_RESULT_BYTES)


def _lexical_nodes(raw):
    """Bound the new fixed corpus's JSON token work before writing a Case."""
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
                quoted = True
                string_bytes = 0
                nodes += 1
            elif byte in (91, 123):
                depth += 1
                nodes += 1
            elif byte in (93, 125):
                depth = max(0, depth-1)
            elif byte in (44, 58):
                nodes += 1
            if depth > 32 or nodes > MAX_JSON_NODES:
                raise ValueError('fixed payload case JSON node/depth work limit')
    return nodes


def _hash_file(path, maximum):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError('bounded regular source file required')
    digest = sha256()
    size = 0
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
        raise ValueError('regular configured proof_payload_origins worker required')
    target = source.resolve()
    entry = target.lstat()
    if (not stat.S_ISREG(entry.st_mode) or entry.st_uid != os.getuid()
            or target.name != 'proof_payload_origins' or not os.access(target, os.X_OK)):
        raise ValueError('owned configured legacy origins executable required')
    return target


def _literal_dependencies(raw):
    source = raw.decode('utf-8')
    return tuple(re.findall(r'include_(?:bytes|str)!\s*\(\s*"([^"]+)"\s*\)', source)
        + re.findall(r'#\s*\[\s*path\s*=\s*"([^"]+)"\s*\]', source))


SNAPSHOT_CRATES = ('rust-oracle', 'point-oracle', 'scalar-source-oracle',
    'auth-cost-oracle', 'proof-payload-origins-oracle')


def _dependency_inventory(root):
    """Configured build inputs, separate from worker execution for small tests."""
    paths, rust = set(), []
    for crate in SNAPSHOT_CRATES:
        source = root/crate/'src'
        if source.is_symlink() or not source.is_dir():
            raise ValueError('all five configured Rust source roots required')
        rust.extend(source.rglob('*.rs'))
        for filename in ('Cargo.toml', 'Cargo.lock'):
            path = root/crate/filename
            if path.is_symlink() or not path.is_file():
                raise ValueError('all five configured manifests and locks required')
            paths.add(path)
    paths.update(rust)
    required = root/'transcript-requirements.txt'
    if required.is_symlink() or not required.is_file():
        raise ValueError('required transcript dependency input snapshot incomplete')
    paths.add(required)
    # Some completed profiles have this file; this repository need not. Never
    # invent an empty dependency file just to satisfy an observation inventory.
    optional = root/'requirements.txt'
    if optional.exists() or optional.is_symlink():
        if optional.is_symlink() or not optional.is_file():
            raise ValueError('optional requirements input must be a regular file')
        paths.add(optional)
    return paths, rust


def _source_snapshot(worker):
    _guard()
    root = Path(__file__).resolve().parent
    paths = set(root.glob('*.py'))
    dependencies, rust = _dependency_inventory(root)
    paths.update(dependencies)
    for suffix in ('.expected.json', '.dimensions.json', '.nht4', '.trace.json'):
        path = root/'fixtures'/('nht4-genesis-0-2020-k5'+suffix)
        if not path.is_file():
            raise ValueError('retained fixture snapshot incomplete')
        paths.add(path)
    pending = list(rust)
    inspected = set()
    while pending:
        path = pending.pop()
        if path in inspected:
            continue
        inspected.add(path)
        with path.open('rb') as stream:
            raw = stream.read((2 << 20)+1)
        if len(raw) > 2 << 20:
            raise ValueError('compiled source exceeds byte cap')
        for relative in _literal_dependencies(raw):
            target = (path.parent/relative).resolve()
            if not target.is_relative_to(root) or not target.is_file():
                raise ValueError('compiled input leaves integration root')
            paths.add(target)
            if target.suffix == '.rs':
                pending.append(target)
        if len(paths) > 256:
            raise ValueError('compiled dependency snapshot file-count cap exceeded')
    if len(paths) > 256 or not (root/'proof-payload-origins-oracle'/'src'/'main.rs').is_file():
        raise ValueError('complete bounded configured legacy source snapshot required')
    files = []
    total = 0
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
    if sha256(_canonical(expected.json())).hexdigest() != 'cdfa31622881cc1863abd1eb252c136184501785b4b02e9985e6ba0850b2ac54':
        raise ValueError('literal retained expected policy differs')
    bound = bind_container(raw, expected)
    if len(raw) != 13220 or len(bound.proof) != 12664:
        raise ValueError('retained13220-byte container/12664-byte proof required')
    with (directory/'reference.nht4').open('xb') as stream:
        stream.write(raw)
    references = [dict(kind='bundle', filename='reference.nht4',
        file_sha256=sha256(raw).hexdigest(), file_bytes=len(raw))]
    for kind, filename, value, maximum in (
            ('expected', 'reference.expected.json', expected.json(), 8192),
            ('dimensions', 'reference.dimensions.json', dimensions.json(), 16384)):
        references.append(dict(kind=kind, filename=filename,
            **_write_json(directory/filename, value, maximum)))
    return (raw, expected, dimensions), references


def _descriptor(value):
    result = value.json()
    if type(result) is not dict:
        raise ValueError('typed sealed source descriptor required')
    return result


def _classify(spec, program, values):
    result = []
    for ordinal, leaf in enumerate(spec.leaves):
        operands = [values[spec.words[slot][0]] for slot in leaf.wires]
        if any(type(value) is not int or not 0 <= value < spec.words[slot][1]
                for slot, value in zip(leaf.wires, operands, strict=True)):
            truth = False
        elif leaf.kind == 'word_valid':
            truth = True
        elif leaf.kind == 'field_valid':
            truth = sum(value << (29*i) for i, value in enumerate(operands)) < program.p
        else:
            if ordinal >= len(program.constraints):
                raise ValueError('noncanonical additional source predicate')
            truth = program.constraints[ordinal].native(values, program.p)
        if truth is not None and type(truth) is not bool:
            raise ValueError('strict Boolean/abort source classification required')
        result.append(truth)
    return tuple(result)


def _census(spec, selected, full):
    from wots_graph import authenticated_shape
    reps = {}
    for ordinal, leaf in enumerate(spec.leaves):
        reps.setdefault(authenticated_shape(spec, leaf), ordinal)
    guarded = list(reps.values()) if full else selected
    opened = {slot for ordinal in selected for slot in spec.leaves[ordinal].wires}
    unique = [len(set(leaf.wires)) for leaf in spec.leaves]
    occurrences = sum(unique[ordinal] for ordinal in selected)
    formal = sum(len(spec.leaves[ordinal].wires) for ordinal in selected)
    return dict(guard_layouts=len({authenticated_shape(spec, spec.leaves[i]) for i in guarded}),
        guarded_leaves=len(guarded), actual_opening_occurrences=occurrences,
        actual_opened_words=len(opened), shared_opening_links=occurrences-len(opened),
        alias_formal_reuses=formal-occurrences, unique_slots=unique, selected=selected)


def _work_premises(spec, index):
    """Check the fixed arities used in the450000-token parser-work proof."""
    if type(index) is not int or not 0 <= index < 3:
        raise ValueError('closed component index required')
    if len(spec.bodies) > (16 if index == 0 else 17):
        raise ValueError('fixed-topology body catalogue work premise differs')
    for leaf in spec.leaves:
        wires, arguments = len(leaf.wires), len(leaf.argument)
        if index == 0:
            valid = wires == 1 and arguments <= 1
        else:
            # Reconstruction has up to5 widths and6 wires; FV has9 wires.
            # Fifteen fixed lexical nodes plus this combined11 gives26.
            valid = 0 < wires <= 9 and arguments <= 5 and wires+max(1, arguments) <= 11
        if not valid:
            raise ValueError('fixed-topology leaf lexical work premise differs')


def _generate(directory):
    _guard()
    _record_budget()
    _summary_budget()
    from proof_payload_origins import build_proof_payload_origins
    reference, references = _reference_files(directory)
    plan = build_proof_payload_origins(*reference, context=CONTEXT, operation_id=OPERATION)
    profiles, groups, all_counts = [], [], []
    for group_index, (name, profile) in enumerate(_requests()):
        binding = plan.bind_profile(profile)
        headers, counts, seen = [], [], {}
        full = profile == 'honest'
        for record in binding.iter_components():
            spec, program, values = record.spec, record.program, record.assignment
            descriptor = _descriptor(record.descriptor)
            index = descriptor['index']
            if (type(index) is not int or index != len(headers) or index >= 3
                    or len(spec.words) != COMPONENT_WORDS[index]
                    or len(spec.leaves) != COMPONENT_LEAVES[index]
                    or spec.field_role != COMPONENT_ROLES[index]
                    or spec.context != CONTEXT.hex()):
                raise ValueError('closed three-component source census/identity differs')
            for key, value in (('words', len(spec.words)), ('leaves', len(spec.leaves)),
                    ('arithmetic_constraints', len(program.constraints)),
                    ('canonical_fields', len(spec.field_leaves)),
                    ('program_sha256', spec.program_sha256), ('catalogue_id', spec.digest().hex())):
                _equal(descriptor[key], value, 'sealed descriptor '+key)
            _work_premises(spec, index)
            ids = record.global_ids
            if (type(ids) is not tuple or len(ids) != len(spec.words)
                    or len(set(ids)) != len(ids)):
                raise ValueError('injective sealed physical source map required')
            if index == 0:
                _equal(ids, tuple(f'proof/container-byte/{556+i}' for i in range(12664)),
                    'physical container BYTE identities')
            else:
                engine = 'pallas' if index == 1 else 'vesta'
                spans = [span for span in plan.layout if span.kind == 'scalar' and span.engine == engine]
                if len(spans) != (169 if index == 1 else 119):
                    raise ValueError('complete physical scalar span inventory required')
                for scalar, span in enumerate(spans):
                    for local in range(55):
                        global_id = ids[55*scalar+local]
                        if 9 <= local < 41:
                            _equal(global_id, f'proof/container-byte/{556+span.start+local-9}',
                                'exact scalar BYTE source position')
                        elif global_id.startswith('proof/container-byte/'):
                            raise ValueError('private scalar witness unexpectedly aliases a payload BYTE')
            for global_id, (word, bound) in zip(ids, spec.words, strict=True):
                value = values[word]
                if type(value) is not int or not 0 <= value <= 0xffffffff:
                    raise ValueError('all signed assertions must retain exact unsigned32 values')
                identity = (bound, value)
                if global_id in seen and seen[global_id] != identity:
                    raise ValueError('shared physical source word has conflicting assertion')
                seen[global_id] = identity
            truth = _classify(spec, program, values)
            _equal(truth, record.truth, 'independent complete source classification')
            selected = list(record.selected_ordinals)
            if (selected != sorted(set(selected))
                    or any(type(i) is not int or not 0 <= i < len(spec.leaves) for i in selected)
                    or (full and selected != list(range(len(spec.leaves))))):
                raise ValueError('ordered closed full/targeted selection required')
            false = [i for i, value in enumerate(truth) if value is False]
            abort = [i for i, value in enumerate(truth) if value is None]
            if not set(false+abort) <= set(selected):
                raise ValueError('targeted coverage dropped a false/abort predicate')
            if full and (false or abort):
                raise ValueError('honest source contains false/abort predicates')
            facts = _census(spec, selected, full)
            facts.update(selected_false=len(false), selected_abort=len(abort))
            case = dict(name=name+'/'+BRANCHES[index], spec=spec.json(),
                expected_spec_id=spec.digest().hex(),
                words=[values[word] for word, _ in spec.words],
                checks=[dict(ordinal=i, expected_correct=truth[i]) for i in selected],
                measure_all=full)
            facts['input_lexical_nodes'] = _lexical_nodes(_canonical(case))
            filename = f'case-{group_index:02d}-{index}.json'
            header = dict(descriptor, filename=filename,
                **_write_json(directory/filename, case, MAX_CASE_BYTES),
                execution_mode='all' if full else 'selected',
                selected_ordinals=None if full else selected,
                expected_false=false, expected_abort_ordinals=abort)
            headers.append(header)
            counts.append(facts)
            # Release every live graph/value alias before advancing the stream.
            del record, spec, program, values, descriptor, ids, truth, case
        total_selected = sum(len(count['selected']) for count in counts)
        if (len(headers) != 3 or len(seen) != 19288
                or sum(header['words'] for header in headers) != 28504
                or (not full and total_selected > MAX_TARGET_LEAVES)):
            raise ValueError('whole-profile source/coverage budget differs')
        group = dict(name=name, profile=profile, source_sha256=plan.source_sha256.hex(),
            source_maps_sha256=plan.source_maps_sha256.hex(), components=headers)
        filename = f'group-{group_index:02d}.json'
        info = _write_json(directory/filename, group, MAX_MANIFEST_BYTES)
        profiles.append(dict(name=name, profile=profile, group_filename=filename,
            group_hash=info['file_sha256'], group_bytes=info['file_bytes']))
        groups.append(group)
        all_counts.append(counts)
        del binding, seen
    manifest = dict(schema=SCHEMA, context=CONTEXT.hex(), operation_id=OPERATION,
        references=references, cases=profiles)
    info = _write_json(directory/'manifest.json', manifest, MAX_MANIFEST_BYTES)
    if len(list(directory.iterdir())) != 60:
        raise ValueError('exact60-file source input inventory required')
    return manifest, info, groups, all_counts


METRIC_SUM_FIELDS = ('vectors', 'expected_rejections')
METRIC_MAX_FIELDS = ('max_script_bytes', 'max_witness_items',
    'max_witness_payload_bytes', 'max_stack_items')
TRUE_FLAGS = ('test_keys_only', 'legacy_registry_and_engine_used',
    'source_preflight_before_keys', 'global_key_preflight_before_signatures',
    'physical_byte_opening_links_checked', 'encoding_internal_opening_links_checked',
    'canonical_scalar_guards_preserved', 'raw_u32_diagnostics_preserved',
    'exact_witness_length_guards_checked', 'stack_limit_enabled',
    'correctness_bytes_equal_disproof_minus_one_checked')
FALSE_FLAGS = ('panic_is_rejection', 'op_cat_enabled', 'all_cases_full_statement_executed',
    'production_assertion_binding', 'proof_sha256_script_bound', 'bundle_sha256_script_bound',
    'proof_eof_script_bound', 'whole_container_script_bound', 'commitment_decoding_verified',
    'transcript_verified', 'proof_verified', 'complete_nova_verifier',
    'complete_bitvm2_verifier', 'candidate_taproot_tree_verified',
    'candidate_forest_verified', 'candidate_membership_verified',
    'bitcoin_transaction_graph', 'raw_vector_file_written',
    'reference_hash_authenticates_claimed_payload', 'public_state_to_zn_script_bound')
# These source/outer aliases are optional in the native ABI, but may never
# contradict its narrow scope if nested metadata includes them. Keep this
# literal policy independent of the source module's own declaration.
RECURSIVE_FALSE_FLAGS = frozenset(FALSE_FLAGS + (
    'blob_sha256_script_bound', 'proof_eof_authenticated',
    'container_header_script_bound', 'compressed_points_script_decoded',
    'generic_nova_decoder', 'source_authority', 'external_result_receipt_loaded',
    'script_cost_includes_assertion_signatures', 'transaction_framing_included',
    'witness_bytes_included_in_script_cost', 'taproot_or_forest_constructed',
    'binary_source_equivalence_attested'))
ZERO_FIELDS = ('setup_calls', 'proving_jobs', 'native_proofs_verified', 'gpu_jobs',
    'transactions_broadcast', 'tree_calls')


def _expected_reference():
    """Independent literal retained policy, never authority for asserted values."""
    return dict(schema='bitvm2-nova-proof-payload-reference/v1', reference_admitted=True,
        network='testnet4', k=5, steps=404,
        header_revision='de607d3db17d400dd6c2923d357f1d4a7bf233c7', nova_version='0.76.0',
        expected_policy_sha256='cdfa31622881cc1863abd1eb252c136184501785b4b02e9985e6ba0850b2ac54',
        verifier_dimensions_sha256='de6333df2e41b5f5bae1c103fab862f8d6022fd54abeb80ba61920bc9f360edc',
        verifier_key_sha256='1ae88a7bcfdc5f14d030d0baafa06ec17fe904a5ebed42f9bd6fa6105fdc8c24',
        bundle_sha256='c3143d5627ef7291ab6a858b866a4ba19e356a168dea992d3e572ef6531904e9',
        proof_sha256='2137c6e8621cedb7423e0ef7f9ff7c27b2c6fdf3ceb227e644b3d9660d056617',
        bundle_bytes=13220, header_bytes=556, payload_bytes=12664, spans=485,
        length_prefixes=119, scalar_atoms=288, commitment_atoms=78,
        pallas_scalars=169, vesta_scalars=119, pallas_commitments=43,
        vesta_commitments=35, length_anchor_bytes=952, state_width_anchor_bytes=431,
        constant_anchors=1383, reference_hash_authenticates_claimed_payload=False,
        proof_verified=False)


def _checked_metrics(value, calls, rejects, label):
    keys = METRIC_SUM_FIELDS+METRIC_MAX_FIELDS
    if type(value) is not dict or set(value) != set(keys):
        raise ValueError('exact six-field metrics required: '+label)
    if any(type(value[key]) is not int or value[key] < 0 for key in keys):
        raise ValueError('strict integer metrics required: '+label)
    _equal(value['vectors'], calls, label+' engine calls')
    _equal(value['expected_rejections'], rejects, label+' expected rejections')
    if (not 0 < value['max_script_bytes'] <= 100000
            or not 0 < value['max_witness_items'] <= value['max_stack_items'] <= 1000
            or not 0 < value['max_witness_payload_bytes'] <= 520*value['max_witness_items']):
        raise ValueError('unchanged Script/witness/stack limits exceeded: '+label)
    return value


def _fold(target, metrics):
    for key in METRIC_SUM_FIELDS:
        target[key] += metrics[key]
    for key in METRIC_MAX_FIELDS:
        target[key] = max(target[key], metrics[key])


def _metadata_bytes(value):
    """Count all published metadata, removing only lossless measured cost rows."""
    def without_costs(item):
        if type(item) is dict:
            return {key: ([] if key == 'leaf_costs' else without_costs(child))
                for key, child in item.items()}
        if type(item) is list:
            return [without_costs(child) for child in item]
        return item
    return len(_canonical(without_costs(value)))


def _validate(native, manifest, info, groups, census):
    """Check a direct worker observation; no receipt-loading public API exists."""
    if type(native) is not dict or native.get('passed') is not True:
        raise ValueError('successful direct legacy origin worker required')
    def narrow_scopes(item):
        if type(item) is dict:
            for key, value in item.items():
                if key in RECURSIVE_FALSE_FLAGS and value is not False:
                    raise ValueError('contradictory nested source authority/scope: '+key)
                narrow_scopes(value)
        elif type(item) is list:
            for value in item:
                narrow_scopes(value)
    narrow_scopes(native)
    _equal(native.get('schema'), 'bitvm2-nova-proof-payload-origins-execution/v1', 'schema')
    _equal(native.get('input_manifest_sha256'), info['file_sha256'], 'fresh manifest identity')
    _equal(native.get('reference'), _expected_reference(), 'complete native reference observation')
    _equal(native.get('leaf_cost_columns'), LEAF_COST_COLUMNS, 'lossless cost row schema')
    for flag in TRUE_FLAGS:
        if native.get(flag) is not True:
            raise ValueError('required narrow source relation missing: '+flag)
    for flag in FALSE_FLAGS:
        if native.get(flag) is not False:
            raise ValueError('source authority/scope exceeded: '+flag)
    for field in ZERO_FIELDS:
        _equal(native.get(field), 0, field)
    _equal(native.get('full_statement_cases'), 1, 'full cases')
    _equal(native.get('targeted_statement_cases'), 13, 'targeted cases')
    size = native.get('compact_execution_records_bytes')
    if (type(size) is not int or not 0 < size <= _record_budget()['combined_upper_bytes']
            or not _hex32(native.get('compact_execution_records_sha256'))):
        raise ValueError('compact record bound/hash differs')
    rows = native.get('cases')
    if (type(rows) is not list or len(rows) != 14 or len(groups) != 14
            or len(census) != 14 or len(manifest['cases']) != 14):
        raise ValueError('all fourteen closed source cases required')
    folded = {key: 0 for key in METRIC_SUM_FIELDS+METRIC_MAX_FIELDS}
    normal_fold = dict(folded)
    measurements = []
    for row, group, counts, request in zip(rows, groups, census, _requests(), strict=True):
        if type(row) is not dict:
            raise ValueError('typed source case observation required')
        name, profile = request
        full = profile == 'honest'
        for key in ('name', 'profile', 'source_sha256', 'source_maps_sha256'):
            _equal(row.get(key), group[key], 'case '+key)
        _equal(row['name'], name, 'closed case order')
        _equal(row['profile'], profile, 'closed profile order')
        for key, value in dict(local_words=28504, global_words=19288, source_reuses=9216,
                signature_entries_created=19288, full_signature_signing_calls=19288,
                scalar_byte_opening_links=9216, encoding_internal_opening_links=6624,
                actual_opening_occurrences=35128, actual_opening_repeats=15840,
                actual_opened_global_words=19288, opening_pass_all_leaves=True).items():
            _equal(row.get(key), value, key)
        parts = row.get('components')
        if type(parts) is not list or len(parts) != 3 or len(counts) != 3:
            raise ValueError('three actual component ledgers required')
        selected_total = compiled_total = 0
        for part, header, count in zip(parts, group['components'], counts, strict=True):
            if type(part) is not dict:
                raise ValueError('typed component ledger required')
            for key in ('index', 'name', 'field_role', 'operation_id', 'program_identity_kind',
                    'words', 'arithmetic_constraints', 'canonical_fields', 'leaves',
                    'program_sha256', 'catalogue_id', 'source_sha256', 'source_maps_sha256',
                    'global_ids_sha256'):
                _equal(part.get(key), header[key], 'component '+key)
            selected = count['selected']
            length = len(selected)
            selected_total += length
            _equal(part.get('measured_ordinals'), None if full else selected, 'actual measured ordinals')
            _equal(part.get('false_predicates'), header['expected_false'], 'complete false predicates')
            _equal(part.get('abort_predicates'), header['expected_abort_ordinals'], 'complete abort predicates')
            for key, value in dict(normal_vectors=2*length, guard_layouts=count['guard_layouts'],
                    guarded_leaves=count['guarded_leaves'], standard_guard_vectors=14*count['guarded_leaves'],
                    proper_disproof_vectors=count['selected_false'],
                    abort_leaf_checks=count['selected_abort'], native_rejections=9).items():
                _equal(part.get(key), value, key)
            for key in ('compiled_stream_sha256', 'registry_id'):
                if not _hex32(part.get(key)):
                    raise ValueError('actual legacy component identity missing: '+key)
            costs = part.get('leaf_costs')
            if type(costs) is not list or len(costs) != length:
                raise ValueError('every measured leaf requires a lossless cost row')
            compiled = maximum = items_max = payload_max = 0
            for ordinal, cost in zip(selected, costs, strict=True):
                if (type(cost) is not list or len(cost) != 3
                        or any(type(value) is not int for value in cost)):
                    raise ValueError('strict three-integer measured cost row required')
                dbytes, items, payload = cost
                if not 1 < dbytes <= 100000:
                    raise ValueError('per-leaf Script exceeds unchanged100000-byte cap')
                unique = count['unique_slots'][ordinal]
                _equal(items, 10*unique, 'legacy compact packet depth')
                _equal(payload, 200*unique, 'legacy compact hash-element payload')
                compiled += dbytes
                maximum = max(maximum, dbytes)
                items_max = max(items_max, items)
                payload_max = max(payload_max, payload)
            if compiled > 256 << 20:
                raise ValueError('component Script stream exceeds unchanged256MiB cap')
            _equal(part.get('compiled_script_bytes'), compiled, 'actual measured disproof sum')
            _equal(part.get('largest_disproof_leaf_bytes'), maximum, 'largest actual leaf')
            normals = 2*length
            normal_rejects = length+count['selected_abort']
            guards = 14*count['guarded_leaves']
            normal = _checked_metrics(part.get('normal_metrics'), normals, normal_rejects, 'normal component')
            for key, value in (('max_script_bytes', maximum), ('max_witness_items', items_max),
                    ('max_witness_payload_bytes', payload_max)):
                _equal(normal[key], value, 'normal measured maximum '+key)
            overall = _checked_metrics(part.get('metrics'), normals+guards,
                normal_rejects+guards, 'guard-inclusive component')
            _equal(overall['max_script_bytes'], maximum, 'guards reuse measured catalogue scripts')
            for key in METRIC_MAX_FIELDS:
                if overall[key] < normal[key]:
                    raise ValueError('guard-inclusive peak below normal snapshot')
            _fold(normal_fold, normal)
            _fold(folded, overall)
            compiled_total += compiled
        if (full and selected_total != 17560) or (not full and selected_total > MAX_TARGET_LEAVES):
            raise ValueError('whole-profile execution scope differs')
        measurements.append(dict(name=name, profile=profile, measured_leaves=selected_total,
            complete_statement_executed=full, measured_disproof_script_bytes=compiled_total))
    for key in ('signature_entries_created', 'full_signature_signing_calls'):
        _equal(native.get(key), 14*19288, key)
    _equal(_checked_metrics(native.get('metrics'), folded['vectors'],
        folded['expected_rejections'], 'global all'), folded, 'exact all-metrics fold')
    _equal(_checked_metrics(native.get('normal_metrics'), normal_fold['vectors'],
        normal_fold['expected_rejections'], 'global normal'), normal_fold, 'exact normal-metrics fold')
    if folded['vectors'] > _record_budget()['total_engine_calls_upper']:
        raise ValueError('actual engine calls exceed closed pre-key budget')
    wall = native.get('wall_seconds')
    if type(wall) not in (int, float) or not math.isfinite(wall) or not 0 <= wall <= 1260:
        raise ValueError('direct native wall-time scope exceeded')
    if _metadata_bytes(native) > _summary_budget()['metadata_bytes_upper']:
        raise ValueError('native metadata exceeds closed summary reserve')
    return measurements


def run(cases_dir, native_worker):
    _guard()
    started = time.perf_counter()
    record_budget, summary_budget = _record_budget(), _summary_budget()
    worker = _worker(native_worker)
    snapshot = _source_snapshot(worker)
    directory = _new_directory(cases_dir)
    manifest, info, groups, census = _generate(directory)
    native = _execute(worker, directory, info['file_sha256'])
    measurements = _validate(native, manifest, info, groups, census)
    _equal(_source_snapshot(worker), snapshot, 'configured sources/binary unchanged during direct execution')
    result = dict(schema='bitvm2-nova-proof-payload-origins-conformance/v1',
        native=native, manifest=info, source_snapshot=snapshot,
        compact_record_budget=record_budget, summary_budget=summary_budget,
        actual_measurements=measurements, direct_native_worker_executed=True,
        external_result_receipt_loaded=False, sources_unchanged_during_run=True,
        retained_max_width_profile_only=True, proof_header_excluded=True,
        all_cases_full_statement_executed=False, legacy_registry_and_engine_used=True,
        script_cost_includes_assertion_signatures=False, transaction_framing_included=False,
        witness_bytes_included_in_script_cost=False, taproot_or_forest_constructed=False,
        proof_sha256_script_bound=False, bundle_sha256_script_bound=False,
        proof_eof_script_bound=False, whole_container_script_bound=False,
        public_state_to_zn_script_bound=False,
        commitment_decoding_verified=False, transcript_verified=False, proof_verified=False,
        complete_nova_verifier=False, complete_bitvm2_verifier=False,
        production_assertion_binding=False, bitcoin_transaction_graph=False,
        setup_calls=0, proving_jobs=0, native_proofs_verified=0, gpu_jobs=0,
        transactions_broadcast=0, wall_seconds=time.perf_counter()-started,
        parent_peak_rss_bytes=peak_rss(),
        scope='legacy payload BYTE/scalar relations under a retained maximum-width profile; '
              'canonical coherent and opaque claims may pass; no blob/hash/EOF/header/proof/production acceptance')
    if (_metadata_bytes(result) > summary_budget['metadata_bytes_upper']
            or len(_canonical(result)) > MAX_RESULT_BYTES):
        raise ValueError('complete published observation exceeds closed unchanged summary budget')
    return result


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
