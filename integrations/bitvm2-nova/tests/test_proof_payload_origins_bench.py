"""SYNTHETIC schema regressions only; no Script/cryptographic evidence.

The handcrafted observations below are never accepted as execution authority.
These tests call private transport validation without graphs, keys or a worker.
"""
from copy import deepcopy
import os
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import bench_proof_payload_origins as bench


def synthetic_observation():
    digest = '11'*32
    manifest = dict(cases=[dict(name=name, profile=profile) for name, profile in bench._requests()])
    info = dict(file_sha256=digest)
    groups, census, rows = [], [], []
    aggregate = {key: 0 for key in bench.METRIC_SUM_FIELDS+bench.METRIC_MAX_FIELDS}
    normals = dict(aggregate)
    for name, profile in bench._requests():
        full = profile == 'honest'
        headers, counts, parts = [], [], []
        for index, (words, leaves, role) in enumerate(zip(bench.COMPONENT_WORDS,
                bench.COMPONENT_LEAVES, bench.COMPONENT_ROLES, strict=True)):
            selected = list(range(leaves)) if full else [0, 1]
            false = [1] if profile in ('p-mod', 'v-mod', 'byte-256', 'byte-max') and index == 0 else []
            descriptor = dict(index=index, name=bench.BRANCHES[index], field_role=role,
                operation_id=bench.OPERATION+'/'+bench.BRANCHES[index],
                program_identity_kind='fixed-trace/v2', words=words,
                arithmetic_constraints=(1383, 2704, 1904)[index],
                canonical_fields=(0, 169, 119)[index], leaves=leaves,
                program_sha256=digest, catalogue_id=digest, source_sha256=digest,
                source_maps_sha256=digest, global_ids_sha256=digest,
                expected_false=false, expected_abort_ordinals=[])
            count = dict(selected=selected, unique_slots=[1]*leaves,
                guard_layouts=(9, 17, 17)[index] if full else 2,
                guarded_leaves=(9, 17, 17)[index] if full else 2,
                selected_false=len(false), selected_abort=0)
            costs = [[100+index, 10, 200] for _ in selected]
            normal = dict(vectors=2*len(selected), expected_rejections=len(selected),
                max_script_bytes=100+index, max_witness_items=10,
                max_witness_payload_bytes=200, max_stack_items=12)
            guards = 14*count['guarded_leaves']
            overall = dict(normal, vectors=normal['vectors']+guards,
                expected_rejections=normal['expected_rejections']+guards,
                max_stack_items=14)
            part = {key: value for key, value in descriptor.items()
                if key not in ('expected_false', 'expected_abort_ordinals')}
            part.update(false_predicates=false, abort_predicates=[],
                measured_ordinals=None if full else selected,
                compiled_script_bytes=(100+index)*len(selected),
                largest_disproof_leaf_bytes=100+index,
                compiled_stream_sha256=digest, registry_id=digest,
                normal_vectors=normal['vectors'], normal_metrics=normal, metrics=overall,
                guard_layouts=count['guard_layouts'], guarded_leaves=count['guarded_leaves'],
                standard_guard_vectors=guards, proper_disproof_vectors=len(false),
                abort_leaf_checks=0, native_rejections=9, leaf_costs=costs)
            headers.append(descriptor)
            counts.append(count)
            parts.append(part)
            bench._fold(aggregate, overall)
            bench._fold(normals, normal)
        groups.append(dict(name=name, profile=profile, source_sha256=digest,
            source_maps_sha256=digest, components=headers))
        census.append(counts)
        rows.append(dict(name=name, profile=profile, source_sha256=digest,
            source_maps_sha256=digest, local_words=28504, global_words=19288,
            source_reuses=9216, signature_entries_created=19288,
            full_signature_signing_calls=19288, scalar_byte_opening_links=9216,
            encoding_internal_opening_links=6624, actual_opening_occurrences=35128,
            actual_opening_repeats=15840, actual_opened_global_words=19288,
            opening_pass_all_leaves=True, components=parts))
    native = dict(schema='bitvm2-nova-proof-payload-origins-execution/v1', passed=True,
        input_manifest_sha256=digest, reference=bench._expected_reference(), cases=rows,
        metrics=aggregate, normal_metrics=normals, leaf_cost_columns=bench.LEAF_COST_COLUMNS,
        compact_execution_records_bytes=1000, compact_execution_records_sha256=digest,
        wall_seconds=1.0, full_statement_cases=1, targeted_statement_cases=13,
        signature_entries_created=270032, full_signature_signing_calls=270032)
    native.update({key: True for key in bench.TRUE_FLAGS})
    native.update({key: False for key in bench.FALSE_FLAGS})
    native.update({key: 0 for key in bench.ZERO_FIELDS})
    return native, manifest, info, groups, census


class ProofPayloadOriginBenchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = synthetic_observation()

    def reject(self, change):
        arguments = deepcopy(self.fixture)
        change(arguments)
        with self.assertRaises(ValueError):
            bench._validate(*arguments)

    def test_synthetic_transport_positive(self):
        result = bench._validate(*self.fixture)
        self.assertEqual(len(result), 14)
        self.assertTrue(result[0]['complete_statement_executed'])
        self.assertEqual(result[0]['measured_leaves'], 17560)
        self.assertTrue(all(not row['complete_statement_executed'] for row in result[1:]))

    def test_closed_budgets_before_graphs(self):
        record = bench._record_budget()
        self.assertEqual(record['total_engine_calls_upper'], 66842)
        self.assertEqual(record['record_bytes_upper'], 218)
        self.assertEqual(record['combined_upper_bytes'], 14571556)
        self.assertLess(record['combined_upper_bytes'], 128 << 20)
        self.assertEqual(bench._summary_budget()['combined_upper_bytes'], 703704)
        # Independent fixed-topology coarse lexical bound, including separators.
        tape = 8*12664+17*12664+7*12664+12664+4*16+1024
        scalar = 9*9295+26*2873+7*2873+1024
        self.assertEqual(tape, 419000)
        self.assertEqual(scalar, 179488)
        self.assertLess(tape, bench.MAX_JSON_NODES)
        self.assertEqual(len(bench._requests()), 14)

    def test_finite_json_work_bound(self):
        # Numeric arrays exercise exactly one opening token plus each comma.
        exact = b'['+b','.join([b'0']*bench.MAX_JSON_NODES)+b']'
        self.assertEqual(bench._lexical_nodes(exact), bench.MAX_JSON_NODES)
        with self.assertRaises(ValueError):
            bench._lexical_nodes(exact[:-1]+b',0]')
        with self.assertRaises(ValueError):
            bench._lexical_nodes(b'['*33+b'0'+b']'*33)
        with self.assertRaises(ValueError):
            bench._lexical_nodes(b'"'+b'a'*200001+b'"')
        # Scalar reconstruction uses several width arguments, not one. Its
        # combined wire/argument count is the premise for the26-node term.
        data = lambda wires, arguments: SimpleNamespace(wires=tuple(range(wires)),
            argument=tuple(range(arguments)))
        bench._work_premises(SimpleNamespace(bodies=range(17),
            leaves=(data(6, 5), data(9, 0), data(3, 1))), 1)
        with self.assertRaises(ValueError):
            bench._work_premises(SimpleNamespace(bodies=range(17), leaves=(data(7, 5),)), 1)
        with self.assertRaises(ValueError):
            bench._work_premises(SimpleNamespace(bodies=range(1), leaves=(data(1, 2),)), 0)

    def test_hosted_guard_precedes_io_and_graphs(self):
        with patch.dict(os.environ, {}, clear=True):
            for invoke in (lambda: bench.run(None, None), lambda: bench._generate(None),
                    lambda: bench._reference_files(None), lambda: bench._source_snapshot(None),
                    lambda: bench._worker(None)):
                with self.assertRaisesRegex(ValueError, 'hosted GitHub Linux'):
                    invoke()
        source = (b'#[path = "../../scalar-source-oracle/src/retained_scalar_block.rs"]\n'
            b'mod reference_admission;\n#[path="../../point-oracle/src/body_pins.rs"]\n'
            b'mod pins;\nconst POLICY:&str=include_str!("../../../fixtures/policy.json");')
        self.assertEqual(set(bench._literal_dependencies(source)), {
            '../../scalar-source-oracle/src/retained_scalar_block.rs',
            '../../point-oracle/src/body_pins.rs', '../../../fixtures/policy.json'})

    def test_reference_authority_and_nested_types(self):
        for key, value in (('proof_verified', True),
                ('reference_hash_authenticates_claimed_payload', True),
                ('scalar_atoms', True), ('payload_bytes', 12665),
                ('expected_policy_sha256', '22'*32)):
            with self.subTest(key=key):
                self.reject(lambda a, key=key, value=value: a[0]['reference'].__setitem__(key, value))
        self.reject(lambda a: a[0]['reference'].__setitem__('unknown_authority', False))
        self.reject(lambda a: a[0].__setitem__('proof_verified', True))
        self.reject(lambda a: a[0]['cases'][0].__setitem__('proof_verified', True))
        self.reject(lambda a: a[0].__setitem__('public_state_to_zn_script_bound', True))
        self.reject(lambda a: a[0]['cases'][0].__setitem__('public_state_to_zn_script_bound', True))

    def test_optional_source_and_outer_scope_aliases(self):
        # Independent literal aliases: not imported from the source's flags.
        aliases = ('blob_sha256_script_bound', 'proof_eof_authenticated',
            'container_header_script_bound', 'compressed_points_script_decoded',
            'generic_nova_decoder', 'source_authority', 'external_result_receipt_loaded',
            'script_cost_includes_assertion_signatures', 'transaction_framing_included',
            'witness_bytes_included_in_script_cost', 'taproot_or_forest_constructed',
            'binary_source_equivalence_attested')
        arguments = deepcopy(self.fixture)
        arguments[0]['cases'][0]['components'][0]['source_metadata'] = {
            key: False for key in aliases}
        bench._validate(*arguments)  # Optional aliases remain optional/false.
        for key in aliases:
            with self.subTest(key=key):
                self.reject(lambda a, key=key: a[0]['cases'][0]['components'][0].__setitem__(
                    'source_metadata', {key: True}))
        self.reject(lambda a: a[0]['cases'][0]['components'][0].__setitem__(
            'source_metadata', {'source_authority': 0}))

    def test_guard_link_and_scope_count_aliases(self):
        mutations = (
            lambda a: a[0]['cases'][0].__setitem__('scalar_byte_opening_links', True),
            lambda a: a[0]['cases'][0].__setitem__('encoding_internal_opening_links', 6623),
            lambda a: a[0]['cases'][0].__setitem__('opening_pass_all_leaves', 1),
            lambda a: a[0]['cases'][1]['components'][0].__setitem__('standard_guard_vectors', True),
            lambda a: a[0]['cases'][1]['components'][0].__setitem__('native_rejections', 8),
            lambda a: a[0]['cases'][1]['components'][0].__setitem__('measured_ordinals', [0, True]),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.reject(mutation)

    def test_lossless_packet_costs_and_metrics_folds(self):
        mutations = (
            lambda a: a[0]['cases'][0]['components'][0]['leaf_costs'][0].__setitem__(1, 20),
            lambda a: a[0]['cases'][0]['components'][0]['leaf_costs'][0].__setitem__(2, 199),
            lambda a: a[0]['cases'][0]['components'][0]['leaf_costs'][0].__setitem__(0, True),
            lambda a: a[0]['cases'][0]['components'][0]['leaf_costs'].pop(),
            lambda a: a[0]['cases'][0]['components'][0]['normal_metrics'].__setitem__('vectors', True),
            lambda a: a[0]['cases'][0]['components'][0]['metrics'].__setitem__('max_stack_items', 9),
            lambda a: a[0]['metrics'].__setitem__('expected_rejections', 0),
            lambda a: a[0].__setitem__('correctness_bytes_equal_disproof_minus_one_checked', False),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.reject(mutation)

    def test_false_abort_and_resource_boundaries(self):
        self.reject(lambda a: a[0]['cases'][3]['components'][0].__setitem__('false_predicates', []))
        self.reject(lambda a: a[0]['cases'][3]['components'][0].__setitem__('abort_predicates', [1]))
        self.reject(lambda a: a[0].__setitem__('compact_execution_records_bytes', 128 << 20))
        self.reject(lambda a: a[0].__setitem__('wall_seconds', float('nan')))
        self.reject(lambda a: a[0].__setitem__('candidate_forest_verified', True))

    def test_pure_raw_truth_retains_domain_and_abort_distinctions(self):
        # Plain data stubs only: no Program, GraphSpec or predicate compilation.
        leaf = lambda kind, *wires: SimpleNamespace(kind=kind, wires=wires)
        spec = SimpleNamespace(words=(('byte', 256), ('limb', 1 << 29)),
            leaves=(leaf('word_valid', 0), leaf('field_valid', 1), leaf('const', 0)))
        program = SimpleNamespace(p=17, constraints=(None, None,
            SimpleNamespace(native=lambda values, modulus: None)))
        self.assertEqual(bench._classify(spec, program, {'byte': 255, 'limb': 17}),
            (True, False, None))
        self.assertEqual(bench._classify(spec, program, {'byte': 256, 'limb': 18}),
            (False, False, False))
        self.assertEqual(bench._classify(spec, program, {'byte': 0xffffffff, 'limb': 16}),
            (False, True, False))


if __name__ == '__main__':
    unittest.main()
