"""Hosted legacy-WOTS comparison of independent and conjunctive AB rows.

Every original word, column and field guard is preserved. The grouped adapter
checks each old row independently before BOOLAND; cancellation between rows is
not a valid replacement for their conjunction. No proof/production or tree
acceptance is claimed. Execution is direct; imported receipts are not inputs.
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

from bench_byte_rho import (_execute, _new_directory, _equal, _hex32,
    MAX_CASE_BYTES, MAX_MANIFEST_BYTES, MAX_RESULT_BYTES)
from bench_keccak_endpoint import _write_json
from bench_compact import peak_rss
from bench_proof_payload_origins import (_hash_file, _literal_dependencies,
    _checked_metrics, _metadata_bytes, _fold,
    METRIC_SUM_FIELDS, METRIC_MAX_FIELDS)


CONTEXT = sha256(b'BITVM2-NOVA/GROUPED-CONVOLUTION-CONFORMANCE/v1').digest()
OPERATION = 'benchmark/grouped-convolution/v1'
SCHEMA = 'bitvm2-nova-grouped-convolution-run/v1'
PROFILES = ('mul-distinct', 'mul-equal-distinct', 'square', 'point',
    'row-leading-0', 'row-leading-1', 'row-leading-2', 'row-leading-3',
    'row-middle-0', 'row-middle-1', 'row-middle-2', 'row-middle-3',
    'row-trailing-0', 'row-trailing-1', 'row-trailing-2',
    'cancel-equal', 'cancel-square', 'inactive-ab', 'byte-256', 'subtotal-max')
FIXTURES = ('mul-distinct', 'mul-equal-distinct', 'square', 'point')+('mul-distinct',)*11+(
    'mul-equal-distinct', 'square', 'point-inactive', 'mul-distinct', 'mul-distinct')
ADAPTERS = ('legacy-rows', 'grouped-and')
LEAF_COST_COLUMNS = ['disproof_script_bytes', 'witness_items', 'witness_payload_bytes']
COUNTS = {'mul-distinct': (634, 489, 281, 3, 1),
    'mul-equal-distinct': (634, 489, 281, 3, 1), 'square': (579, 472, 264, 2, 1),
    'point': (7476, 6151, 3447, 35, 13), 'point-inactive': (7476, 6151, 3447, 35, 13)}
MAX_TARGET_LEAVES = 128
MAX_RECORD_BYTES = 128 << 20
MAX_JSON_NODES = 550000
SNAPSHOT_CRATES = ('rust-oracle', 'point-oracle', 'scalar-source-oracle',
    'auth-cost-oracle', 'proof-payload-origins-oracle', 'grouped-convolution-oracle')


def _guard():
    if (os.environ.get('GITHUB_ACTIONS') != 'true'
            or os.environ.get('RUNNER_OS') != 'Linux' or sys.platform != 'linux'):
        raise ValueError('grouped convolution execution is hosted GitHub Linux only')


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
        ensure_ascii=True, allow_nan=False).encode('ascii')


def _requests():
    return tuple((f'{prefix}/{index:02d}', role, FIXTURES[index], profile, index < 4)
        for prefix, role in (('p', 'pallas_base'), ('v', 'vesta_base'))
        for index, profile in enumerate(PROFILES))


def _record_budget():
    honest = 2*((489+281)*2+(472+264)+(6151+3447))
    target = 32*MAX_TARGET_LEAVES
    rows = honest+target
    normal, guards, reserve = 2*rows, 14*rows, 2048
    calls = normal+guards+reserve
    maximum = len(_canonical(dict(c=['v/19', 1], i='g'*32, m=False,
        e=False, s='0'*64, w='0'*64)))+1
    size = calls*maximum
    if size > MAX_RECORD_BYTES:
        raise ValueError('closed grouping corpus exceeds unchanged128MiB record cap')
    return dict(cases=40, full_cases=8, targeted_cases=32, honest_measured_rows=honest,
        targeted_rows_upper=target, measured_rows_upper=rows, normal_calls_upper=normal,
        standard_guard_calls_upper=guards, late_auth_calls_reserve=reserve,
        engine_calls_upper=calls, record_bytes_upper=maximum,
        combined_upper_bytes=size, hard_cap_bytes=MAX_RECORD_BYTES)


def _summary_budget():
    rows = _record_budget()['measured_rows_upper']
    row_bytes = len(_canonical([100000, 1000, 520000]))+1
    metadata = 300000
    size = rows*row_bytes+metadata
    if size > MAX_RESULT_BYTES:
        raise ValueError('closed grouping summary exceeds unchanged1MiB cap')
    return dict(cost_rows_upper=rows, row_bytes_upper=row_bytes,
        metadata_bytes_upper=metadata, combined_upper_bytes=size, hard_cap_bytes=MAX_RESULT_BYTES)


def _lexical_nodes(raw):
    """New corpus-specific finite work cap; no completed parser is changed."""
    if type(raw) is not bytes or len(raw) > MAX_CASE_BYTES:
        raise ValueError('bounded canonical ASCII case bytes required')
    quoted = escaped = False
    nodes = depth = string_bytes = 0
    for byte in raw:
        if byte > 127:
            raise ValueError('canonical ASCII case required')
        if quoted:
            string_bytes += 1
            if string_bytes > 200000:
                raise ValueError('case JSON string work cap exceeded')
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
                raise ValueError('grouped-case JSON node/depth work cap exceeded')
    return nodes


def _truths(spec, program, values):
    truths = []
    for ordinal, leaf in enumerate(spec.leaves):
        operands = [values[spec.words[slot][0]] for slot in leaf.wires]
        integer = lambda digits: sum(value << (29*i) for i, value in enumerate(digits))
        if any(type(value) is not int or not 0 <= value < spec.words[slot][1]
                for slot, value in zip(leaf.wires, operands, strict=True)):
            truth = False
        elif leaf.kind == 'field_valid':
            truth = integer(operands) < program.p
        elif leaf.kind == 'word_valid':
            truth = True
        elif leaf.kind == 'add':
            if len(operands) != 27:
                raise ValueError('fixed canonical-input addition shape required')
            a, b, c = integer(operands[:9]), integer(operands[9:18]), integer(operands[18:])
            truth = None if a >= program.p or b >= program.p else (a+b) % program.p == c
        elif leaf.kind == 'conv_ab_all':
            if tuple(leaf.argument) not in ((1, 2, 3, 4), (4, 4, 4, 4), (3, 2, 1)):
                raise ValueError('closed grouped row-count pattern required')
            offset = 0
            truth = True
            for products in leaf.argument:
                row = operands[offset:offset+2*products+1]
                if len(row) != 2*products+1:
                    raise ValueError('complete independent row operands required')
                truth = (row[-1] == sum(row[2*i]*row[2*i+1] for i in range(products))) and truth
                offset += 2*products+1
            if offset != len(operands):
                raise ValueError('grouped predicate has surplus operands')
        else:
            if ordinal >= len(program.constraints):
                raise ValueError('unexpected additional source predicate')
            truth = program.constraints[ordinal].native(values, program.p)
        if truth is not None and type(truth) is not bool:
            raise ValueError('strict ordinary/abort classification required')
        truths.append(truth)
    return tuple(truths)


def _census(spec, selected, false, abort):
    opened = {slot for i in selected for slot in spec.leaves[i].wires}
    unique = [len(set(leaf.wires)) for leaf in spec.leaves]
    occurrences = sum(unique[i] for i in selected)
    formal = sum(len(spec.leaves[i].wires) for i in selected)
    return dict(selected=selected, unique_slots=unique, selected_false=len(false),
        selected_abort=len(abort), actual_opening_occurrences=occurrences,
        actual_opened_words=len(opened), shared_opening_links=occurrences-len(opened),
        alias_formal_reuses=formal-occurrences)


def _late_auth_facts(source, values, profile, adapter):
    if profile not in ('row-middle-0', 'subtotal-max'):
        return []
    old, candidate = source.baseline_spec, source.candidate_spec
    group = next((i for i, leaf in enumerate(candidate.leaves)
        if leaf.kind == 'conv_ab_all' and leaf.argument == (4, 4, 4, 4)), None)
    if group is None:
        raise ValueError('closed first all-four group missing')
    old_rows = source.projection.new_to_old[group]
    if len(old_rows) != 4:
        raise ValueError('all-four group must project four actual old rows')
    semantic_row = 0 if profile == 'row-middle-0' else 3
    semantic = old.leaves[old_rows[semantic_row]].wires[-1]
    if profile == 'subtotal-max' and values[old.words[semantic][0]] != 0xffffffff:
        raise ValueError('signedMAX belongs to last row of first all-four group')
    spec = old if adapter == 0 else candidate
    ordinal = old_rows[semantic_row] if adapter == 0 else group
    unique = tuple(dict.fromkeys(spec.leaves[ordinal].wires))
    if adapter == 1 and profile == 'row-middle-0':
        forged = old.leaves[old_rows[3]].wires[-1]
        forged_row = 3
    else:
        semantic_position = unique.index(semantic)
        forged = next((word for word in unique[:semantic_position]
            if values[spec.words[word][0]] < spec.words[word][1]), None)
        if forged is None:
            raise ValueError('valid actual operand after semantic output recovery missing')
        forged_row = None
    if (forged == semantic or forged not in unique
            or not 0 <= values[spec.words[forged][0]] < spec.words[forged][1]):
        raise ValueError('late-auth evidence requires a distinct valid actual operand')
    return [dict(ordinal=ordinal, semantic_word=semantic, forged_word=forged,
        semantic_unique_position=unique.index(semantic),
        forged_unique_position=unique.index(forged), forged_group_row=forged_row)]


def _generate(directory):
    _guard()
    _record_budget()
    _summary_budget()
    from grouped_convolution import build_grouped_source
    descriptors, census = [], []
    source = None
    owner = None
    for index, (name, role, fixture, profile, full) in enumerate(_requests()):
        if owner != (role, fixture):
            source = None
            source = build_grouped_source(role, fixture)
            owner = (role, fixture)
        bound = source.bind_profile(profile)
        values = bound.assignment
        programs = (source.baseline_program, source.candidate_program)
        specs = (source.baseline_spec, source.candidate_spec)
        _equal(specs[0].words, specs[1].words, 'identical ordered word catalogue')
        words, old_leaves, new_leaves, fields, products = COUNTS[fixture]
        if len(specs[0].words) != words or bound.complete is not full:
            raise ValueError('closed source word/execution census differs')
        ordered = [values[word] for word, _ in specs[0].words]
        if any(type(value) is not int or not 0 <= value <= 0xffffffff for value in ordered):
            raise ValueError('every signed assertion retains its exact raw u32')
        _equal(tuple(ordered), bound.values, 'closed paired assignment')
        headers, counts = [], []
        for adapter, (spec, program, expected_leaves, expected_truth, selection) in enumerate(zip(
                specs, programs, (old_leaves, new_leaves),
                (bound.baseline_truth, bound.candidate_truth),
                (bound.baseline_selected, bound.candidate_selected), strict=True)):
            if (spec.context != CONTEXT.hex() or spec.field_role != role
                    or spec.operation_id != OPERATION+'/'+fixture
                    or len(spec.words) != words or len(spec.leaves) != expected_leaves
                    or len(spec.field_leaves) != fields
                    or len(program.constraints) != expected_leaves-fields):
                raise ValueError('closed paired graph identity/census differs')
            if any(len(bytes.fromhex(body)) > 20000 for _, body in spec.bodies):
                raise ValueError('unchanged20000-byte predicate-body cap exceeded')
            if (len(spec.bodies) > 256 or any(len(leaf.wires) > 48
                    or len(leaf.argument) > 8 for leaf in spec.leaves)):
                raise ValueError('fixed typed premises for550000 lexical work cap differ')
            truth = _truths(spec, program, values)
            _equal(truth, expected_truth, 'independent per-row source truth')
            selected = list(selection)
            if (selected != sorted(set(selected)) or not selected
                    or any(type(i) is not int or not 0 <= i < expected_leaves for i in selected)
                    or (full and selected != list(range(expected_leaves)))):
                raise ValueError('closed measured ordinal coverage differs')
            false = [i for i, value in enumerate(truth) if value is False]
            abort = [i for i, value in enumerate(truth) if value is None]
            if not set(false+abort) <= set(selected):
                raise ValueError('selected coverage dropped false/abort predicates')
            if full and (false or abort):
                raise ValueError('honest graph has false or aborting predicates')
            case = dict(name=name+('/baseline' if adapter == 0 else '/candidate'),
                spec=spec.json(), expected_spec_id=spec.digest().hex(), words=ordered,
                checks=[dict(ordinal=i, expected_correct=truth[i]) for i in selected], measure_all=full)
            count = _census(spec, selected, false, abort)
            count['late_auth_evidence'] = _late_auth_facts(source, values, profile, adapter)
            count['input_lexical_nodes'] = _lexical_nodes(_canonical(case))
            filename = f'case-{index:02d}-{adapter}.json'
            headers.append(dict(index=adapter, label=ADAPTERS[adapter], filename=filename,
                **_write_json(directory/filename, case, MAX_CASE_BYTES),
                program_sha256=spec.program_sha256, catalogue_id=spec.digest().hex(),
                words=words, arithmetic_constraints=len(program.constraints), canonical_fields=fields,
                leaves=expected_leaves, execution_mode='all' if full else 'selected',
                selected_ordinals=None if full else selected,
                expected_false=false, expected_abort_ordinals=abort))
            counts.append(count)
            del spec, program, truth, case
        if not full and sum(len(count['selected']) for count in counts) > MAX_TARGET_LEAVES:
            raise ValueError('paired targeted coverage exceeds128 TOTAL leaves')
        descriptors.append(dict(name=name, profile=profile, role=role, fixture=fixture,
            source_sha256=source.source_sha256, source_maps_sha256=source.source_maps_sha256,
            word_catalogue_sha256=sha256(_canonical(specs[0].words)).hexdigest(),
            assignment_sha256=sha256(_canonical(ordered)).hexdigest(), adapters=headers))
        census.append(counts)
        del bound, values, programs, specs, ordered
    manifest = dict(schema=SCHEMA, context=CONTEXT.hex(), operation_id=OPERATION, cases=descriptors)
    info = _write_json(directory/'manifest.json', manifest, MAX_MANIFEST_BYTES)
    if len(list(directory.iterdir())) != 81:
        raise ValueError('exact81-file paired source inventory required')
    return manifest, info, census


def _worker(path):
    _guard()
    source = Path(path)
    if source.is_symlink():
        raise ValueError('regular configured grouped_convolution worker required')
    target = source.resolve()
    entry = target.lstat()
    if (not stat.S_ISREG(entry.st_mode) or entry.st_uid != os.getuid()
            or target.name != 'grouped_convolution' or not os.access(target, os.X_OK)):
        raise ValueError('trusted owned configured grouped_convolution executable required')
    return target


def _dependency_inventory(root):
    paths, rust = set(), []
    for crate in SNAPSHOT_CRATES:
        source = root/crate/'src'
        if source.is_symlink() or not source.is_dir():
            raise ValueError('all configured Rust source roots required')
        rust.extend(source.rglob('*.rs'))
        for filename in ('Cargo.toml', 'Cargo.lock'):
            path = root/crate/filename
            if path.is_symlink() or not path.is_file():
                raise ValueError('all configured Cargo manifests and locks required')
            paths.add(path)
    paths.update(rust)
    required = root/'transcript-requirements.txt'
    if required.is_symlink() or not required.is_file():
        raise ValueError('required transcript dependencies missing')
    paths.add(required)
    optional = root/'requirements.txt'
    if optional.exists() or optional.is_symlink():
        if optional.is_symlink() or not optional.is_file():
            raise ValueError('optional requirements must be a regular file')
        paths.add(optional)
    return paths, rust


def _source_snapshot(worker):
    _guard()
    root = Path(__file__).resolve().parent
    paths, rust = _dependency_inventory(root)
    paths.update(root.glob('*.py'))
    pending, inspected = list(rust), set()
    while pending:
        path = pending.pop()
        if path in inspected:
            continue
        inspected.add(path)
        with path.open('rb') as stream:
            raw = stream.read((2 << 20)+1)
        if len(raw) > 2 << 20:
            raise ValueError('compiled input exceeds per-file snapshot cap')
        for relative in _literal_dependencies(raw):
            target = (path.parent/relative).resolve()
            if target.is_symlink() or not target.is_relative_to(root) or not target.is_file():
                raise ValueError('literal compiled dependency leaves integration root')
            paths.add(target)
            if target.suffix == '.rs':
                pending.append(target)
        if len(paths) > 256:
            raise ValueError('configured source snapshot exceeds256-file cap')
    if not (root/'grouped-convolution-oracle'/'src'/'main.rs').is_file():
        raise ValueError('complete configured worker source required')
    files, total = [], 0
    for path in sorted(paths):
        if path.is_symlink() or not path.resolve().is_relative_to(root):
            raise ValueError('snapshot source leaves integration root')
        info = _hash_file(path, 2 << 20)
        total += info['bytes']
        if total > 64 << 20:
            raise ValueError('configured source snapshot exceeds64MiB cap')
        files.append(dict(path=path.relative_to(root).as_posix(), **info))
    return dict(schema='bitvm2-nova-worker-source-snapshot/v1', files=files,
        source_snapshot_sha256=sha256(_canonical(files)).hexdigest(),
        worker_executable=_hash_file(worker, 128 << 20),
        trusted_configured_library_boundary=True, binary_source_equivalence_attested=False)


def _verify_inputs(directory, manifest, info, *, executed=False):
    _guard()
    expected = {'manifest.json'}
    _equal(_hash_file(directory/'manifest.json', MAX_MANIFEST_BYTES),
        dict(bytes=info['file_bytes'], sha256=info['file_sha256']), 'unchanged manifest file')
    for case in manifest['cases']:
        for source in case['adapters']:
            filename = source['filename']
            expected.add(filename)
            _equal(_hash_file(directory/filename, MAX_CASE_BYTES),
                dict(bytes=source['file_bytes'], sha256=source['file_sha256']),
                'unchanged paired source file')
    if executed:
        expected.add('native-execution.json')
    _equal({path.name for path in directory.iterdir()}, expected, 'exclusive closed input/output inventory')


TRUE_FLAGS = ('legacy_registry_and_engine_used', 'same_full32_signature_material_checked',
    'paired_word_opening_pass_all_words', 'row_projection_checked',
    'canonical_guards_preserved', 'unchanged_kernels_preserved',
    'all_honest_catalogues_executed', 'correctness_bytes_equal_disproof_minus_one_checked',
    'test_keys_only', 'stack_limit_enabled')
FALSE_FLAGS = ('all_cases_full_statement_executed', 'raw_vector_file_written',
    'op_cat_enabled', 'panic_is_rejection', 'proof_verified', 'complete_nova_verifier',
    'complete_bitvm2_verifier', 'full_permutation_verified', 'full_hash_verified',
    'transcript_verified', 'production_assertion_binding', 'bitcoin_transaction_graph',
    'candidate_taproot_tree_verified', 'candidate_forest_verified',
    'candidate_membership_verified', 'savings_assumed')
RECURSIVE_FALSE_FLAGS = frozenset(FALSE_FLAGS+('complete_verifier',
    'nova_transcript_bound', 'taproot_coverage_verified', 'source_authority',
    'external_result_receipt_loaded', 'binary_source_equivalence_attested',
    'script_cost_includes_assertion_signatures', 'transaction_framing_included',
    'witness_bytes_included_in_script_cost', 'taproot_or_forest_constructed',
    'opening_link_pass_all_leaves'))
ZERO_FIELDS = ('setup_calls', 'proving_jobs', 'native_proofs_verified', 'gpu_jobs',
    'transactions_broadcast', 'tree_calls')
LEGACY_POINT_BYTES = {'pallas_base': 88586200, 'vesta_base': 88688588}


def _validate(native, manifest, info, census):
    """Strict direct-observation validation, never an external receipt API."""
    if type(native) is not dict or native.get('passed') is not True:
        raise ValueError('successful direct grouped-convolution worker required')
    def scopes(item):
        if type(item) is dict:
            for key, value in item.items():
                if key in RECURSIVE_FALSE_FLAGS and value is not False:
                    raise ValueError('contradictory nested scope claim: '+key)
                scopes(value)
        elif type(item) is list:
            for value in item:
                scopes(value)
    scopes(native)
    _equal(native.get('schema'), 'bitvm2-nova-grouped-convolution-execution/v1', 'schema')
    _equal(native.get('input_manifest_sha256'), info['file_sha256'], 'fresh manifest identity')
    _equal(native.get('leaf_cost_columns'), LEAF_COST_COLUMNS, 'lossless ordered cost schema')
    for key in TRUE_FLAGS:
        if native.get(key) is not True:
            raise ValueError('required narrow conformance evidence missing: '+key)
    for key in FALSE_FLAGS:
        if native.get(key) is not False:
            raise ValueError('convolution scope exceeded: '+key)
    for key in ZERO_FIELDS:
        _equal(native.get(key), 0, key)
    _equal(native.get('full_statement_cases'), 8, 'complete paired sources')
    _equal(native.get('targeted_statement_cases'), 32, 'targeted paired sources')
    size = native.get('compact_execution_records_bytes')
    if (type(size) is not int or not 0 < size <= _record_budget()['combined_upper_bytes']
            or not _hex32(native.get('compact_execution_records_sha256'))):
        raise ValueError('actual compact records exceed the closed derived budget')
    rows = native.get('cases')
    if (type(rows) is not list or len(rows) != 40 or len(census) != 40
            or len(manifest['cases']) != 40):
        raise ValueError('all forty closed paired cases required')
    all_fold = {key: 0 for key in METRIC_SUM_FIELDS+METRIC_MAX_FIELDS}
    normal_fold = dict(all_fold)
    signatures = late_calls = 0
    measured = []
    for row, header, counts, request in zip(rows, manifest['cases'], census, _requests(), strict=True):
        if type(row) is not dict or len(counts) != 2:
            raise ValueError('typed paired case observation required')
        name, role, fixture, profile, full = request
        for key in ('name', 'profile', 'role', 'fixture', 'source_sha256',
                'source_maps_sha256', 'word_catalogue_sha256', 'assignment_sha256'):
            _equal(row.get(key), header[key], 'paired '+key)
        for key, value in (('name', name), ('profile', profile), ('role', role), ('fixture', fixture)):
            _equal(row[key], value, 'closed '+key)
        words, old_leaves, _, fields, products = COUNTS[fixture]
        for key, value in dict(signature_entries_created=words, full_signature_signing_calls=words,
                cross_adapter_hash_links=10*words, old_ab_rows=280*products,
                grouped_ab_leaves=72*products, unchanged_leaf_projections=old_leaves-280*products,
                canonical_guard_projections=fields, subtotal_opening_links=280*products,
                carry_opening_links=63*products, opening_link_pass_all_leaves=False,
                opening_link_pass_all_mapped_coordinates=True,
                paired_word_opening_pass_all_words=True,
                legacy_equivalence_leaves=len(counts[0]['selected'])).items():
            _equal(row.get(key), value, key)
        curve = (dict(applicable=True, left_valid=True, right_valid=True,
            result_valid=True, addition_holds=True) if fixture in ('point', 'point-inactive')
            else dict(applicable=False))
        _equal(row.get('curve_verdict'), curve, 'complete independently expected mature curve observation')
        parts = row.get('adapters')
        if type(parts) is not list or len(parts) != 2:
            raise ValueError('both actual adapter ledgers required')
        costs, leaves_measured = [], []
        for adapter, (part, source, count) in enumerate(zip(parts, header['adapters'], counts, strict=True)):
            if type(part) is not dict:
                raise ValueError('typed measured adapter ledger required')
            for key in ('index', 'label', 'program_sha256', 'catalogue_id', 'words',
                    'arithmetic_constraints', 'canonical_fields', 'leaves', 'execution_mode'):
                _equal(part.get(key), source[key], 'adapter '+key)
            _equal(part['index'], adapter, 'adapter order')
            _equal(part['label'], ADAPTERS[adapter], 'adapter label')
            selected = count['selected']
            length = len(selected)
            leaves_measured.append(length)
            _equal(part.get('measured_ordinals'), None if full else selected, 'measured source ordinals')
            _equal(part.get('false_predicates'), source['expected_false'], 'all false predicates')
            _equal(part.get('abort_predicates'), source['expected_abort_ordinals'], 'all abort predicates')
            evidence = count['late_auth_evidence']
            extras = 2*len(evidence)
            _equal(part.get('late_auth_evidence'), evidence, 'closed actual late-auth coordinates')
            for key, value in dict(normal_vectors=2*length, guarded_leaves=length,
                    standard_guard_vectors=14*length, late_auth_vectors=extras,
                    proper_disproof_vectors=count['selected_false'], abort_leaf_checks=count['selected_abort'],
                    actual_opening_occurrences=count['actual_opening_occurrences'],
                    actual_opened_words=count['actual_opened_words'],
                    shared_opening_links=count['shared_opening_links'],
                    alias_formal_reuses=count['alias_formal_reuses'], native_rejections=9,
                    input_lexical_nodes=count['input_lexical_nodes'],
                    lexical_node_limit=MAX_JSON_NODES).items():
                _equal(part.get(key), value, key)
            if not 0 < part['input_lexical_nodes'] <= MAX_JSON_NODES:
                raise ValueError('finite input lexical budget exceeded')
            for key in ('registry_id', 'compiled_stream_sha256'):
                if not _hex32(part.get(key)):
                    raise ValueError('actual compiled source identity missing: '+key)
            leaf_costs = part.get('leaf_costs')
            if type(leaf_costs) is not list or len(leaf_costs) != length:
                raise ValueError('every measured source leaf requires its actual cost row')
            total = maximum = items_max = payload_max = 0
            for ordinal, entry in zip(selected, leaf_costs, strict=True):
                if (type(entry) is not list or len(entry) != 3
                        or any(type(value) is not int for value in entry)):
                    raise ValueError('strict three-integer lossless cost row required')
                dbytes, items, payload = entry
                if not 1 < dbytes <= 100000:
                    raise ValueError('per-leaf Script exceeds unchanged100000-byte cap')
                unique = count['unique_slots'][ordinal]
                _equal(items, 10*unique, 'frozen legacy packet depth')
                _equal(payload, 200*unique, 'frozen legacy signature payload')
                total += dbytes
                maximum = max(maximum, dbytes)
                items_max = max(items_max, items)
                payload_max = max(payload_max, payload)
            if total > 256 << 20:
                raise ValueError('measured component exceeds unchanged256MiB Script cap')
            _equal(part.get('compiled_script_bytes'), total, 'actual measured Script sum')
            _equal(part.get('largest_disproof_leaf_bytes'), maximum, 'largest actual Script')
            if full and fixture == 'point' and adapter == 0:
                _equal(total, LEGACY_POINT_BYTES[role], 'historical complete legacy point cost regression')
            calls, rejects = 2*length, length+count['selected_abort']
            guards = 14*length
            normal = _checked_metrics(part.get('normal_metrics'), calls, rejects, 'normal adapter')
            for key, value in (('max_script_bytes', maximum), ('max_witness_items', items_max),
                    ('max_witness_payload_bytes', payload_max)):
                _equal(normal[key], value, 'normal cost-derived maximum '+key)
            overall = _checked_metrics(part.get('metrics'), calls+guards+extras,
                rejects+guards+extras, 'all adapter')
            _equal(overall['max_script_bytes'], maximum, 'all probes reuse measured source Scripts')
            for key in METRIC_MAX_FIELDS:
                if overall[key] < normal[key]:
                    raise ValueError('all-metrics peak below its normal snapshot')
            _fold(normal_fold, normal)
            _fold(all_fold, overall)
            late_calls += extras
            costs.append(total)
        if not full and sum(leaves_measured) > MAX_TARGET_LEAVES:
            raise ValueError('targeted128-leaf cap applies to both adapters together')
        signatures += words
        measured.append(dict(name=name, role=role, fixture=fixture, profile=profile,
            complete_source_measured=full, measured_leaves=leaves_measured,
            baseline_disproof_script_bytes=costs[0], grouped_disproof_script_bytes=costs[1],
            grouped_minus_baseline_bytes=costs[1]-costs[0] if full else None,
            grouped_to_baseline_ratio=costs[1]/costs[0] if full else None))
    _equal(late_calls, 16, 'closed additional late-auth engine calls')
    _equal(signatures, 52508, 'actual once-signed corpus census')
    for key, value in (('signature_entries_created', signatures),
            ('full_signature_signing_calls', signatures), ('cross_adapter_hash_links', 10*signatures)):
        _equal(native.get(key), value, key)
    _equal(_checked_metrics(native.get('normal_metrics'), normal_fold['vectors'],
        normal_fold['expected_rejections'], 'global normal'), normal_fold, 'exact normal-metrics fold')
    _equal(_checked_metrics(native.get('metrics'), all_fold['vectors'],
        all_fold['expected_rejections'], 'global all'), all_fold, 'exact all-metrics fold')
    if all_fold['vectors'] > _record_budget()['engine_calls_upper']:
        raise ValueError('actual engine calls exceed the closed pre-key budget')
    wall = native.get('wall_seconds')
    if type(wall) not in (int, float) or not math.isfinite(wall) or not 0 <= wall <= 1260:
        raise ValueError('native execution exceeded bounded wall scope')
    if _metadata_bytes(native) > _summary_budget()['metadata_bytes_upper']:
        raise ValueError('native metadata exceeds the complete summary reserve')
    return measured


def run(cases_dir, native_worker):
    _guard()
    started = time.perf_counter()
    budgets = dict(records=_record_budget(), summary=_summary_budget())
    worker = _worker(native_worker)
    snapshot = _source_snapshot(worker)
    directory = _new_directory(cases_dir)
    manifest, info, census = _generate(directory)
    _verify_inputs(directory, manifest, info)
    native = _execute(worker, directory, info['file_sha256'])
    measurements = _validate(native, manifest, info, census)
    _verify_inputs(directory, manifest, info, executed=True)
    _equal(_source_snapshot(worker), snapshot, 'configured source/binary unchanged during direct execution')
    result = dict(schema='bitvm2-nova-grouped-convolution-conformance/v1', native=native,
        manifest=info, source_snapshot=snapshot, closed_budgets=budgets,
        actual_measurements=measurements, direct_native_worker_executed=True,
        external_result_receipt_loaded=False, inputs_unchanged_during_run=True,
        sources_unchanged_during_run=True, all_cases_full_statement_executed=False,
        proof_verified=False, complete_nova_verifier=False, complete_bitvm2_verifier=False,
        production_assertion_binding=False, bitcoin_transaction_graph=False,
        full_permutation_verified=False, full_hash_verified=False, transcript_verified=False,
        taproot_or_forest_constructed=False, savings_assumed=False,
        script_cost_includes_assertion_signatures=False, witness_bytes_included_in_script_cost=False,
        transaction_framing_included=False, setup_calls=0, proving_jobs=0,
        native_proofs_verified=0, gpu_jobs=0, transactions_broadcast=0, tree_calls=0,
        wall_seconds=time.perf_counter()-started, parent_peak_rss_bytes=peak_rss(),
        scope='paired legacy-WOTS convolution/point subgraphs; complete honest costs and scoped '
              'counterexamples; independent AB rows remain a conjunction; no proof/tree/production acceptance')
    if (_metadata_bytes(result) > budgets['summary']['metadata_bytes_upper']
            or len(_canonical(result)) > MAX_RESULT_BYTES):
        raise ValueError('complete observation exceeds unchanged1MiB/derived summary budget')
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
