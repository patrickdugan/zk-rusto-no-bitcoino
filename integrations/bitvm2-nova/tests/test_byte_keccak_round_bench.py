"""Small synthetic transport tests; no actual round graph or native execution.

The summaries below intentionally use invented catalogue hashes and byte costs.
They exercise the private checker only and cannot enter public run() as receipts.
"""
import copy
import os
import unittest
from unittest.mock import patch

import bench_byte_keccak_round as bench
from keccak_trace import ROUND_CONSTANTS


def _synthetic():
    sources, observed, coverage = [], [], []
    checks = guards = 0
    for role, r, profile in bench._profiles():
        boolean = profile == 'boolean-honest'
        n = ROUND_CONSTANTS[r].bit_count() if boolean else sum(x != 0 for x in ROUND_CONSTANTS[r].to_bytes(8, 'little'))
        words, leaves = (12001+n, 10401+n) if boolean else (1416+n, 1216+n)
        false = ([1216 if r == 0 else 1024] if profile == 'byte-wrong-output'
                 else [0, 240] if profile == 'byte-oversized' else [])
        source = dict(name=bench._name(role, r, profile), role=role, round=r, profile=profile,
            catalogue_id='11'*32, program_sha256='22'*32, source_sha256='33'*32,
            boolean_program_sha256='44'*32 if boolean else None,
            boolean_catalogue_id='55'*32 if boolean else None,
            global_ids_sha256='66'*32, words=words, leaves=leaves, expected_false=false,
            probe_catalogue_id='77'*32, probe_program_sha256='88'*32,
            probe_global_ids_sha256='99'*32, probe_words=400, probe_leaves=200)
        source_cost = dict(catalogue_id=source['catalogue_id'], program_sha256=source['program_sha256'],
            source_sha256=source['source_sha256'], boolean_program_sha256=source['boolean_program_sha256'],
            boolean_catalogue_id=source['boolean_catalogue_id'], context=bench.CONTEXT.hex(),
            global_ids_sha256=source['global_ids_sha256'], words=words, leaves=leaves,
            executed_leaves=leaves, registry_id='aa'*32, compiled_stream_sha256='bb'*32,
            compiled_script_bytes=100*leaves, largest_disproof_leaf_bytes=100)
        probe_cost = dict(catalogue_id=source['probe_catalogue_id'], program_sha256=source['probe_program_sha256'],
            context=bench.CONTEXT.hex(), global_ids_sha256=source['probe_global_ids_sha256'],
            words=400, leaves=200, executed_leaves=200, registry_id='cc'*32,
            compiled_stream_sha256='dd'*32, compiled_script_bytes=20000, largest_disproof_leaf_bytes=100)
        expected = dict(normal_leaf_checks=leaves+200, source_guard_layouts=3,
            probe_guard_layouts=1, guard_vectors=56, native_rejections=48, port_rejections=8,
            probe_cache_rejections=12)
        observed.append(dict(name=source['name'], profile=profile, round=r, field_role=role,
            source=source_cost, probe=probe_cost, source_false_predicates=list(false), probe_false_predicates=[],
            source_predicates_checked=leaves, probe_predicates_checked=200, producer_opening_links=200,
            cached_output_entries=200, probe_input_key_value_bound_signature_matches=200,
            source_signature_entries_created=words, probe_fresh_signature_entries_created=200,
            probe_cached_signature_reuses=200,
            baseline_internal_bit_opening_links=4800 if boolean else 0,
            baseline_input_bit_opening_links=3200 if boolean else 0,
            baseline_output_bit_opening_links=1600 if boolean else 0,
            baseline_aux_opening_links=400 if boolean else 0,
            **{key: value for key, value in expected.items() if key != 'normal_leaf_checks'}))
        sources.append(source)
        coverage.append(expected)
        checks += leaves+200
        guards += 56
    native = dict(schema='bitvm2-nova-byte-keccak-round-execution/v1', passed=True,
        input_manifest_sha256='ee'*32, compact_execution_records_bytes=1000,
        compact_execution_records_sha256='ff'*32, cases=observed,
        test_keys_only=True, stack_limit_enabled=True, one_round_script_conformance_checked=True,
        all_source_and_probe_leaves_executed=True, producer_opening_links_checked=True,
        raw_vector_file_written=False, op_cat_enabled=False, full_24_round_composition_verified=False,
        full_permutation_verified=False, full_hash_verified=False, transcript_verified=False,
        proof_verified=False, complete_nova_verifier=False, complete_bitvm2_verifier=False,
        production_assertion_binding=False, bitcoin_transaction_graph=False, panic_is_rejection=False,
        baseline_bytes_are_free=False, setup_calls=0, proving_jobs=0, native_proofs_verified=0,
        gpu_jobs=0, transactions_broadcast=0,
        fresh_signature_entries_created=sum(source['words'] for source in sources)+64*200,
        cached_signature_reuses=12800,
        metrics=dict(vectors=2*checks+guards, expected_rejections=checks+guards,
            max_stack_items=100, max_witness_items=20, max_script_bytes=100, max_witness_payload_bytes=400))
    manifest = dict(context=bench.CONTEXT.hex(), cases=sources)
    return native, manifest, dict(file_sha256='ee'*32), coverage


class ByteKeccakRoundBenchTests(unittest.TestCase):
    def test_small_profile_schedule_and_reference_inputs(self):
        requests = list(bench._profiles())
        self.assertEqual(len(requests), 64)
        for role in bench.ROLES:
            selected = [(r, profile) for actual_role, r, profile in requests if actual_role == role]
            self.assertEqual(sum(profile == 'byte-honest' for _, profile in selected), 24)
            self.assertEqual([r for r, profile in selected if profile == 'boolean-honest'], [0, 1, 2, 23])
        self.assertEqual(bench._initial(0)[:4], bytes((11, 48, 85, 122)))
        self.assertEqual(len(bench._initial(23)), 200)
        self.assertEqual(ROUND_CONSTANTS[5], ROUND_CONSTANTS[22])
        for r in (5, 22):
            caller, actual = bench._source_operations(r, False)
            self.assertEqual(caller, f'{bench.OPERATION}/byte/r{r}')
            self.assertEqual(actual, caller+f'/round/{r}')
            caller, actual = bench._source_operations(r, True)
            self.assertEqual(actual, caller)  # Existing composite baseline identity.
        with self.assertRaises(ValueError):
            bench._initial(True)

    def test_synthetic_transport_and_probe_cost_separation(self):
        native, manifest, info, coverage = _synthetic()
        rows = bench._validate(native, manifest, info, coverage)
        comparisons = bench._comparisons(rows)
        self.assertEqual(len(comparisons), 8)
        for row in comparisons:
            self.assertTrue(row['source_cost_excludes_copy_probe'])
            self.assertTrue(row['baseline_includes_800_bridge_leaves'])
            self.assertEqual(row['candidate_probe_script_bytes'], 20000)
            self.assertEqual(row['baseline_probe_script_bytes'], 20000)

    def test_strict_counts_scope_and_compact_record_bounds(self):
        native, manifest, info, coverage = _synthetic()
        mutations = (
            lambda x: x.__setitem__('compact_execution_records_bytes', True),
            lambda x: x.__setitem__('compact_execution_records_bytes', (128 << 20)+1),
            lambda x: x.__setitem__('full_24_round_composition_verified', True),
            lambda x: x.__setitem__('panic_is_rejection', True),
            lambda x: x['cases'][0].__setitem__('producer_opening_links', True),
            lambda x: x['cases'][0].__setitem__('probe_cache_rejections', 11),
            lambda x: x['cases'][0].__setitem__('source_signature_entries_created', True),
            lambda x: x['cases'][0].__setitem__('probe_fresh_signature_entries_created', 199),
            lambda x: x['cases'][0].__setitem__('probe_cached_signature_reuses', True),
            lambda x: x.__setitem__('fresh_signature_entries_created', True),
            lambda x: x.__setitem__('cached_signature_reuses', 12799),
            lambda x: x['cases'][26].__setitem__('source_false_predicates', [False, 240]),
        )
        for mutate in mutations:
            changed = copy.deepcopy(native)
            mutate(changed)
            with self.assertRaises(ValueError):
                bench._validate(changed, manifest, info, coverage)

    def test_detached_child_probe_and_cache_identity_reject(self):
        native, manifest, info, coverage = _synthetic()
        mutations = (
            lambda x: x['cases'][28]['source'].__setitem__('boolean_catalogue_id', '00'*32),
            lambda x: x['cases'][0]['source'].__setitem__('source_sha256', '00'*32),
            lambda x: x['cases'][0]['probe'].__setitem__('global_ids_sha256', '00'*32),
            lambda x: x['cases'][0].__setitem__('cached_output_entries', 199),
            lambda x: x['cases'][28].__setitem__('baseline_input_bit_opening_links', 1600),
        )
        for mutate in mutations:
            changed = copy.deepcopy(native)
            mutate(changed)
            with self.assertRaises(ValueError):
                bench._validate(changed, manifest, info, coverage)

    def test_observed_resource_metrics_cannot_be_missing_or_relaxed(self):
        native, manifest, info, coverage = _synthetic()
        mutations = (
            lambda x: x['metrics'].__setitem__('max_script_bytes', True),
            lambda x: x['metrics'].__setitem__('max_script_bytes', 99),
            lambda x: x['metrics'].__setitem__('max_witness_payload_bytes', 520001),
            lambda x: x['metrics'].__setitem__('max_witness_payload_bytes', 0),
            lambda x: x['cases'][0]['source'].__setitem__('largest_disproof_leaf_bytes', 100001),
        )
        for mutate in mutations:
            changed = copy.deepcopy(native)
            mutate(changed)
            with self.assertRaises(ValueError):
                bench._validate(changed, manifest, info, coverage)

    def test_hosted_guard_precedes_paths_and_actual_graph_helpers(self):
        with patch.dict(os.environ, {'GITHUB_ACTIONS': 'false'}), \
                patch.object(bench, '_worker', side_effect=AssertionError('path I/O')), \
                patch.object(bench, '_new_directory', side_effect=AssertionError('directory I/O')), \
                patch.object(bench, '_generate', side_effect=AssertionError('actual round graph')):
            with self.assertRaisesRegex(ValueError, 'hosted GitHub Linux'):
                bench.run('unused', 'unused')
            with self.assertRaisesRegex(ValueError, 'hosted GitHub Linux'):
                bench._probe('unused', 'pallas_scalar', 0, False, bytes(200))


if __name__ == '__main__':
    unittest.main()
