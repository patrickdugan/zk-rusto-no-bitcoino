"""Pure budgets and synthetic transport only: no rho graphs or native worker.

Invented hashes/costs used by the private checker are not execution evidence,
proofs, production roots or a receipt format accepted by public run().
"""
import copy
import os
import unittest
from unittest.mock import patch

import bench_byte_rho as bench


def _synthetic():
    """Small transport fixture; none of these invented costs/hashes is evidence."""
    sources, rows, census = [], [], []
    counts = dict(signature_entries_created=59109, cached_signature_reuses=368,
        message_origins=96, message_consumer_opening_links=384, framing_anchors=208,
        framing_consumer_opening_links=416, digest_producer_consumer_links=64,
        internal_cached_boundary_entries=9200, internal_producer_consumer_opening_links=18400)
    negative_names = ('altered_script', 'branch', 'parity', 'internal_key', 'leaf_version',
        'truncated_control', 'appended_control', 'manifest', 'root', 'output_key',
        'component', 'ordinal', 'reordered_components')
    for role, counter, profile in bench._requests():
        full = profile in ('honest', 'bad-hi-digest')
        headers, ledgers, component_counts = [], [], []
        for i, (branch, words, leaves) in enumerate((('hi', 29445, 29245), ('lo', 29445, 29245), ('tail', 587, 453))):
            mode = 'all' if full or i == 2 else 'selected' if profile == 'bad-lo-frame' and i == 1 else 'none'
            selected = [125, 351] if mode == 'selected' else None
            executed = leaves if mode == 'all' else 2 if mode == 'selected' else 0
            false = [29241] if profile == 'bad-hi-digest' and i == 0 else [363] if profile == 'bad-lo-frame' and i == 2 else [1] if profile == 'wrong-result' and i == 2 else []
            descriptor = dict(index=i, branch=branch, kind='full-permutation' if i < 2 else 'uniform-framing-tail',
                operation_id=f'test/{branch}', program_sha256='11'*32, catalogue_id='22'*32,
                source_sha256='33'*32, source_maps_sha256='44'*32, global_ids_sha256='55'*32,
                words=words, leaves=leaves, counter=counter, field_role=role,
                program_identity_kind='test-only invented identity')
            header = dict(descriptor=descriptor, execution_mode=mode, selected_ordinals=selected, expected_false=false)
            ledger = dict(descriptor, context=bench.CONTEXT.hex(), registry_id='66'*32,
                compiled_script_bytes=leaves*100, largest_disproof_leaf_bytes=100,
                compiled_stream_sha256='77'*32, execution_mode=mode, selected_ordinals=selected,
                executed_leaves=executed, native_predicates_checked=leaves, false_predicates=list(false),
                guard_layouts=23 if i < 2 else 5, guard_vectors=322 if i < 2 else 70)
            headers.append(header)
            ledgers.append(ledger)
            component_counts.append(dict(selected_leaf_checks=executed, guard_layouts=23 if i < 2 else 5,
                                         words=words, leaves=leaves))
        source = dict(name=bench._name(role, profile), profile=profile, role=role, counter=counter,
            execution_mode='full' if full else 'targeted', source_sha256='88'*32, source_maps_sha256='99'*32,
            expected_raw_state_le='aa'*64, expected_result_le='bb'*32, expected_quotient_le='00'*33, components=headers)
        selected_component = 0 if profile == 'bad-hi-digest' else 2
        selected_leaf = {'honest':452, 'bad-hi-digest':29241, 'bad-lo-frame':363, 'wrong-result':1}[profile]
        forest = dict(components=3, leaf_count=58943, compiled_script_bytes=5894300,
            selected_component=selected_component, selected_leaf=selected_leaf,
            control_block_bytes={'honest':321, 'bad-hi-digest':545, 'bad-lo-frame':353, 'wrong-result':353}[profile],
            merkle_root='12'*32, output_key='13'*32, control_block_sha256='14'*32,
            selected_script_sha256='15'*32, component_manifest_sha256='16'*32,
            compiled_stream_sha256='17'*32, hierarchical_membership_verified=True,
            roots_independently_pinned=False, negative_counts={key:1 for key in negative_names})
        row = {key:source[key] for key in ('name','profile','role','counter','execution_mode','source_sha256',
                                         'source_maps_sha256','expected_raw_state_le','expected_result_le','expected_quotient_le')}
        row.update(**counts, full_statement_executed=full, all_native_predicates_checked=58943,
            selected_leaf_checks=58943 if full else 455 if profile == 'bad-lo-frame' else 453,
            guard_layouts=51, guard_vectors=714, native_rejections=72,
            map_rejections=8, source_rejections=12, cache_rejections=30,
            selected_component=selected_component, selected_leaf=selected_leaf,
            additional_selected_engine_executions=2, selected_correctness_execution_success=profile == 'honest',
            selected_disproof_execution_success=profile != 'honest', components=ledgers, forest=forest)
        sources.append(source)
        rows.append(row)
        census.append(component_counts)
    native = dict(schema='bitvm2-nova-byte-rho-execution/v1', passed=True,
        input_manifest_sha256='18'*32, cases=rows, framed_rho_script_conformance_checked=True,
        all_native_reference_predicates_checked=True, boundary_opening_links_checked=True,
        framing_constants_script_bound=True, both_digest_endpoints_script_bound=True,
        digest_reduction_script_bound=True, test_keys_only=True, stack_limit_enabled=True,
        hierarchical_membership_verified=True, all_cases_full_statement_executed=False,
        raw_vector_file_written=False, op_cat_enabled=False, full_permutation_verified=False,
        full_hash_verified=False, transcript_verified=False, nova_transcript_verified_in_script=False,
        proof_verified=False, complete_nova_verifier=False, complete_bitvm2_verifier=False,
        production_assertion_binding=False, bitcoin_transaction_graph=False, panic_is_rejection=False,
        eval_w_canonicality_script_bound=False, dynamic_message_sources_script_bound=False,
        eval_w_proof_origin_bound=False, prior_state_transcript_bound=False, complete_keccak_sponge=False,
        setup_calls=0, proving_jobs=0, native_proofs_verified=0, gpu_jobs=0, transactions_broadcast=0,
        full_statement_cases=4, targeted_statement_cases=4, compact_execution_records_bytes=101000000,
        compact_execution_records_sha256='19'*32, wall_seconds=10.0,
        metrics=dict(vectors=480904, expected_rejections=243308, max_script_bytes=100,
                     max_stack_items=30, max_witness_items=20, max_witness_payload_bytes=400),
        **{key:value*8 for key,value in counts.items()})
    return native, dict(context=bench.CONTEXT.hex(), cases=sources), dict(file_sha256='18'*32), census


class ByteRhoBenchTests(unittest.TestCase):
    def test_exact_normal_and_conservative_record_budgets(self):
        budget = bench._record_budget()
        self.assertEqual(budget['normal_records'], 475176)
        self.assertEqual(budget['normal_exact_bytes'], 100077184)
        self.assertEqual(budget['maximum_tail_guard_layouts'], 453)
        self.assertEqual(budget['combined_upper_bytes'], 115189564)
        self.assertLess(budget['combined_upper_bytes'], 128 << 20)

    def test_full_and_targeted_coverage_are_distinct(self):
        requests = list(bench._requests())
        self.assertEqual(len(requests), 8)
        self.assertEqual([counter for role, counter, _ in requests if role == 'pallas_scalar'], [59]*4)
        self.assertEqual([counter for role, counter, _ in requests if role == 'vesta_scalar'], [44]*4)
        total = 0
        for _, _, profile in requests:
            counts = []
            for component, leaves in enumerate((29245, 29245, 453)):
                mode, chosen = bench._selection(profile, component)
                counts.append(leaves if mode == 'all' else len(chosen) if mode == 'selected' else 0)
            self.assertEqual(counts, [29245, 29245, 453] if profile in ('honest', 'bad-hi-digest')
                             else [0, 2, 453] if profile == 'bad-lo-frame' else [0, 0, 453])
            total += sum(counts)
        self.assertEqual(total, 237588)
        for component in (True, -1, 3):
            with self.assertRaises(ValueError):
                bench._selection('honest', component)

    def test_framing_and_native_consumers_without_graphs(self):
        from byte_rho import framed_state_bytes, fixed_frame_bytes
        from bench_byte_keccak_block import _consumers, _producer
        from keccak_trace import ROUND_CONSTANTS
        eval_w, prior = bytes(range(32)), bytes(range(64))
        for counter in (44, 59):
            hi = framed_state_bytes(eval_w, prior, counter=counter, branch='hi')
            lo = framed_state_bytes(eval_w, prior, counter=counter, branch='lo')
            prefix = b'w'+eval_w+b'NoDS'+counter.to_bytes(8, 'little')+prior+b'r'
            self.assertEqual(hi[:111], prefix+b'\1')
            self.assertEqual(lo[:111], prefix+b'\0')
            self.assertEqual(hi[111:], b'\1'+bytes(23)+b'\x80'+bytes(64))
            self.assertEqual(len(hi), 200)
            self.assertEqual([i for i, _ in fixed_frame_bytes(counter, 'lo')].index(111), 15)
        self.assertEqual(_consumers(0, 111), ((125, 1), (351, 0)))
        offset = sum(1216+sum(b != 0 for b in rc.to_bytes(8, 'little')) for rc in ROUND_CONSTANTS[:23])
        producer, formal = _producer(23, 0)
        self.assertEqual((offset+producer, formal), (29241, 1))

    def test_synthetic_full_targeted_ledgers_and_forest_contract(self):
        native, manifest, info, census = _synthetic()
        rows = bench._validate(native, manifest, info, census)
        self.assertEqual(len(rows), 8)
        self.assertEqual(sum(row['selected_leaf_checks'] for row in rows), 237588)
        self.assertEqual(sum(row['full_statement_executed'] for row in rows), 4)
        self.assertTrue(all(row['all_native_predicates_checked'] == 58943 for row in rows))
        self.assertEqual(sum(row['additional_selected_engine_executions'] for row in rows), 16)

    def test_scope_origin_counter_and_targeted_coverage_mutations_reject(self):
        native, manifest, info, census = _synthetic()
        mutations = (
            lambda x:x.__setitem__('proof_verified', True),
            lambda x:x.__setitem__('all_cases_full_statement_executed', True),
            lambda x:x.__setitem__('eval_w_canonicality_script_bound', True),
            lambda x:x.__setitem__('cached_signature_reuses', True),
            lambda x:x['cases'][0].__setitem__('digest_producer_consumer_links', True),
            lambda x:x['cases'][2].__setitem__('full_statement_executed', True),
            lambda x:x['cases'][2]['components'][1].__setitem__('selected_ordinals', [125,350]),
            lambda x:x['cases'][2]['components'][0].__setitem__('executed_leaves', 29245),
            lambda x:x['cases'][3]['components'][2].__setitem__('false_predicates', [True]),
            lambda x:x['cases'][0].__setitem__('counter', 60),
            lambda x:x['cases'][0].__setitem__('cache_rejections', True),
            lambda x:x['metrics'].__setitem__('vectors', 480888),
            lambda x:x.__setitem__('compact_execution_records_bytes', 100077183),
            lambda x:x.__setitem__('compact_execution_records_bytes', 115189565),
        )
        for mutate in mutations:
            changed = copy.deepcopy(native)
            mutate(changed)
            with self.assertRaises(ValueError):
                bench._validate(changed, manifest, info, census)

    def test_detached_component_forest_and_typed_cost_mutations_reject(self):
        native, manifest, info, census = _synthetic()
        mutations = (
            lambda x:x['cases'][0]['components'][1].__setitem__('source_maps_sha256', '00'*32),
            lambda x:x['cases'][0]['components'][2].__setitem__('global_ids_sha256', True),
            lambda x:x['cases'][0]['components'][0].__setitem__('compiled_script_bytes', 1.0),
            lambda x:x['cases'][0]['forest'].__setitem__('compiled_script_bytes', 5894301),
            lambda x:x['cases'][0]['forest'].__setitem__('control_block_bytes', 353),
            lambda x:x['cases'][1]['forest'].__setitem__('selected_component', 1),
            lambda x:x['cases'][0]['forest'].__setitem__('roots_independently_pinned', True),
            lambda x:x['cases'][0]['forest']['negative_counts'].__setitem__('branch', True),
            lambda x:x['cases'][0]['forest'].pop('component_manifest_sha256'),
            lambda x:x['metrics'].__setitem__('max_witness_payload_bytes', 520*21),
        )
        for mutate in mutations:
            changed = copy.deepcopy(native)
            mutate(changed)
            with self.assertRaises(ValueError):
                bench._validate(changed, manifest, info, census)

    def test_hosted_guard_precedes_io_and_any_graph_construction(self):
        with patch.dict(os.environ, {'GITHUB_ACTIONS': 'false'}), \
                patch.object(bench, '_worker', side_effect=AssertionError('path I/O')), \
                patch.object(bench, '_new_directory', side_effect=AssertionError('directory I/O')), \
                patch.object(bench, '_generate', side_effect=AssertionError('actual rho graph')):
            with self.assertRaisesRegex(ValueError, 'hosted GitHub Linux'):
                bench.run('unused', 'unused')
            with self.assertRaisesRegex(ValueError, 'hosted GitHub Linux'):
                bench._one(0, 'pallas_scalar', 59, 'honest', None)
            with self.assertRaisesRegex(ValueError, 'hosted GitHub Linux'):
                bench._execute(None, None, None)


if __name__ == '__main__':
    unittest.main()
