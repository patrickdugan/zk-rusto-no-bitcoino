"""Synthetic transport checks, never endpoint verification evidence.

The small hand-built contract below has no real catalogues, keys, Scripts,
worker execution or proof. Only the private result validator is exercised.
Public run() still requires fresh sealed factories and its direct worker.
"""
import copy
import os
import unittest
from unittest.mock import patch

import bench_keccak_endpoint as bench


def _synthetic_transport():
    """Literal contract-shaped observations with intentionally fake byte costs."""
    pair_rows = [dict(index=i, first_round=2*i, catalogue_id='11'*32,
                      words=20000, leaves=19000) for i in range(12)]
    tail_row = dict(catalogue_id='22'*32, words=1787, leaves=1205)
    negatives = ('forest_altered_script', 'forest_branch', 'forest_parity',
        'forest_internal_key', 'forest_leaf_version', 'forest_truncated_control',
        'forest_appended_control', 'forest_manifest', 'forest_root',
        'forest_output_key', 'forest_component', 'forest_ordinal', 'forest_reordered_components')
    scenarios, observations = [], []
    for name, component, leaf in (('honest', 11, 17606),
                                   ('coherent-output', 11, 17606), ('wrong-padding', 12, 492)):
        false = [] if name == 'honest' else [dict(pair=component, ordinal=leaf)]
        scenarios.append(dict(name=name, selected_pair=component, selected_leaf=leaf,
                              pairs=copy.deepcopy(pair_rows), tail=dict(tail_row), expected_false=false))
        # These are pinned transport expectations, not computed graph facts.
        coverage = dict(components=13, unique_global_words=232809,
            signature_entries_created=232809, cached_signature_reuses=18688,
            internal_boundary_words=19200, internal_boundary_signature_links=38400,
            inter_boundary_words=17600, inter_boundary_signature_links=35200,
            endpoint_framing_cached_entries=832, endpoint_lo_cached_entries=256,
            endpoint_framing_opening_links=832, endpoint_lo_opening_links=256,
            endpoint_byte_opening_links=128, endpoint_carry_opening_links=64,
            endpoint_source_cache_rejections=12, tail_guarded_layouts=13,
            all_boolean_predicates_checked=230510, tail_predicates_checked=1205,
            tail_leaf_checks=1205, selected_component=component, selected_leaf=leaf,
            guard_vectors=238, additional_selected_engine_executions=2)
        ledger = [row | {'compiled_script_bytes': 1} for row in pair_rows]
        ledger.append(tail_row | dict(index=12, first_round=None, compiled_script_bytes=1))
        observations.append(dict(name=name, **coverage, false_predicates=copy.deepcopy(false),
            selected_correctness_execution_success=name == 'honest',
            selected_disproof_execution_success=name != 'honest',
            hierarchical_membership_verified=True, roots_independently_pinned=False,
            global_control_bytes=609, forest_negative_counts={key: 1 for key in negatives},
            local_ledger=ledger, compiled_script_bytes=13, normal_leaf_checks=1205))
    native = dict(schema='bitvm2-nova-keccak-endpoint-execution/v1', passed=True,
        topology_sha256='33'*32, manifest_sha256='44'*32, scenarios=observations,
        graph_compiled=True, reference_conformance_checked=True,
        hierarchical_membership_verified=True, test_keys_only=True,
        lo_keccak_endpoint_script_bound=True, framing_constants_script_bound=True,
        raw_vector_file_written=False, full_permutation_verified=False,
        full_hash_verified=False, keccak256_verified=False,
        nova_transcript_verified_in_script=False, proof_verified=False,
        complete_bitvm2_verifier=False, production_assertion_binding=False,
        bitcoin_transaction_graph=False, production_transactions_verified=False,
        hi_keccak_endpoint_script_bound=False, eval_w_canonicality_script_bound=False,
        dynamic_message_sources_script_bound=False, complete_keccak_sponge=False,
        transactions_broadcast=0, native_proofs_verified=0, proving_jobs=0,
        metrics=dict(vectors=7944, expected_rejections=4329,
                     max_stack_items=100, max_witness_items=100))
    manifest = dict(topology_sha256='33'*32, scenarios=scenarios)
    return native, manifest, dict(file_sha256='44'*32), 3615


class KeccakEndpointBenchTransportTests(unittest.TestCase):
    def test_synthetic_contract_is_only_a_validator_fixture(self):
        native, manifest, info, checks = _synthetic_transport()
        self.assertEqual(bench._validate_execution(native, manifest, info, checks), 39)
        self.assertFalse(native['proof_verified'])
        self.assertFalse(native['hi_keccak_endpoint_script_bound'])

    def test_integer_count_bool_aliases_fail(self):
        for field in ('endpoint_carry_opening_links', 'endpoint_lo_cached_entries',
                       'endpoint_source_cache_rejections', 'tail_guarded_layouts'):
            native, manifest, info, checks = _synthetic_transport()
            native['scenarios'][0][field] = True
            with self.subTest(field=field), self.assertRaises(ValueError):
                bench._validate_execution(native, manifest, info, checks)

    def test_missing_carry_or_cached_source_bindings_fail(self):
        for field in ('endpoint_carry_opening_links', 'endpoint_framing_cached_entries',
                       'endpoint_lo_cached_entries', 'endpoint_source_cache_rejections'):
            native, manifest, info, checks = _synthetic_transport()
            del native['scenarios'][2][field]
            with self.subTest(field=field), self.assertRaises(ValueError):
                bench._validate_execution(native, manifest, info, checks)

    def test_proof_and_external_origin_scope_escalation_fail(self):
        for field in ('proof_verified', 'hi_keccak_endpoint_script_bound',
                       'dynamic_message_sources_script_bound', 'complete_keccak_sponge'):
            native, manifest, info, checks = _synthetic_transport()
            native[field] = True
            with self.subTest(field=field), self.assertRaises(ValueError):
                bench._validate_execution(native, manifest, info, checks)

    def test_detached_tail_catalogue_and_manifest_fail(self):
        native, manifest, info, checks = _synthetic_transport()
        native['scenarios'][1]['local_ledger'][12]['catalogue_id'] = '00'*32
        with self.assertRaises(ValueError):
            bench._validate_execution(native, manifest, info, checks)
        native, manifest, info, checks = _synthetic_transport()
        native['manifest_sha256'] = '00'*32
        with self.assertRaises(ValueError):
            bench._validate_execution(native, manifest, info, checks)

    def test_hosted_guard_precedes_path_io_and_worker(self):
        with patch.dict(os.environ, {'GITHUB_ACTIONS': 'false'}), \
                patch.object(bench, '_worker', side_effect=AssertionError('worker path inspected')), \
                patch.object(bench, '_new_directory', side_effect=AssertionError('directory created')), \
                patch.object(bench, '_generate', side_effect=AssertionError('graph generated')):
            with self.assertRaisesRegex(ValueError, 'hosted GitHub Linux'):
                bench.run('unused', 'unused')


if __name__ == '__main__':
    unittest.main()
