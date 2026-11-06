"""Pure budget and synthetic transport regressions; no real graph or worker.

Invented hashes/costs below are private-checker fixtures, not Taproot proofs,
registry acceptance, execution evidence or receipts accepted by public run().
"""
import copy
import os
import unittest
from unittest.mock import patch

import bench_byte_keccak_permutation as bench
from keccak_trace import ROUND_CONSTANTS


def _blocks():
    blocks, first = [], 0
    for i in range(6):
        start = 4*i
        leaves = sum(1216+sum(v != 0 for v in ROUND_CONSTANTS[r].to_bytes(8, 'little')) for r in range(start, start+4))
        caller = f'{bench.OPERATION}/block/{i}'
        blocks.append(dict(index=i, first_round=start, last_round=start+3,
            operation_id=caller, program_operation_id=caller+f'/rounds/{start}-{start+3}',
            source_sha256='11'*32, program_sha256='22'*32, catalogue_id='33'*32,
            global_ids_sha256='44'*32, words=leaves+200, leaves=leaves, leaf_offset=first,
            word_map_sha256='55'*32, leaf_map_sha256='66'*32))
        first += leaves
    return blocks


def _synthetic():
    descriptors, rows, census = [], [], []
    negatives = ('altered_script', 'branch', 'parity', 'internal_key', 'leaf_version',
                 'truncated_control', 'appended_control', 'root', 'output_key', 'ordinal', 'registry', 'catalogue')
    counts = dict(signature_entries_created=29445, round_declared_word_occurrences=34045,
        block_declared_word_occurrences=30445, cached_boundary_entries=4600,
        producer_consumer_opening_links=9200, internal_cached_boundary_entries=3600,
        internal_producer_consumer_opening_links=7200, cross_block_cached_boundary_entries=1000,
        cross_block_producer_consumer_opening_links=2000)
    for role, profile in bench._requests():
        selected = 4870 if profile == 'middle-iota' else 0 if profile == 'oversized' else 29049
        false = [] if profile == 'honest' else [0, 240] if profile == 'oversized' else [selected]
        source = dict(name=bench._name(role, profile), profile=profile, role=role,
            state_index=4 if profile == 'middle-iota' else None,
            byte_slot=1 if profile == 'middle-iota' else 8 if profile == 'final-chi' else None,
            words=29445, leaves=29245, blocks=_blocks(), expected_false=false,
            catalogue_id='77'*32, program_sha256='88'*32, source_sha256='99'*32,
            global_ids_sha256='aa'*32, source_maps_sha256='ab'*32)
        parent = {key: source[key] for key in ('catalogue_id', 'program_sha256', 'source_sha256',
                                             'global_ids_sha256', 'source_maps_sha256', 'words', 'leaves')}
        parent.update(context=bench.CONTEXT.hex(), executed_leaves=29245,
            registry_id='bb'*32, compiled_stream_sha256='cc'*32,
            compiled_script_bytes=2924500, largest_disproof_leaf_bytes=100)
        tree = dict(leaf_count=29245, compiled_script_bytes=2924500, compiled_stream_sha256='cc'*32,
            hierarchical_membership_verified=True, roots_independently_pinned=False,
            merkle_root='dd'*32, output_key='ee'*32, control_block_sha256='ff'*32,
            selected_script_sha256='12'*32, control_block_bytes=513 if selected < 25722 else 481,
            negative_counts={key: 1 for key in negatives})
        observed = {key: source[key] for key in ('name', 'profile', 'role', 'state_index', 'byte_slot')}
        observed.update(**counts, guard_layouts=23, guard_vectors=322, native_rejections=24,
            map_rejections=8, source_rejections=12, cache_rejections=18,
            selected_leaf=selected, additional_selected_engine_executions=2,
            selected_correctness_execution_success=profile == 'honest',
            selected_disproof_execution_success=profile != 'honest',
            false_predicates=list(false), round_false_predicates=bench._round_failures(false),
            parent=parent, tree=tree, blocks=copy.deepcopy(source['blocks']),
            joins=[dict(index=i, state_round=i+1, cached_entries=200,
                        producer_consumer_opening_links=400) for i in range(23)])
        descriptors.append(source)
        rows.append(observed)
        census.append(dict(normal_leaf_checks=29245, guard_layouts=23, selected_leaf=selected, guard_vectors=322))
    native = dict(schema='bitvm2-nova-byte-keccak-permutation-execution/v1', passed=True,
        input_manifest_sha256='13'*32, cases=rows,
        full_24_round_script_conformance_checked=True, all_parent_leaves_executed=True,
        boundary_opening_links_checked=True, children_projected_from_parent=True,
        test_keys_only=True, stack_limit_enabled=True, hierarchical_membership_verified=True,
        raw_vector_file_written=False, op_cat_enabled=False, full_permutation_verified=False,
        full_hash_verified=False, transcript_verified=False, proof_verified=False,
        complete_nova_verifier=False, complete_bitvm2_verifier=False, production_assertion_binding=False,
        bitcoin_transaction_graph=False, panic_is_rejection=False, setup_calls=0, proving_jobs=0,
        native_proofs_verified=0, gpu_jobs=0, transactions_broadcast=0,
        compact_execution_records_bytes=97298660, compact_execution_records_sha256='14'*32,
        metrics=dict(vectors=470512, expected_rejections=236544, max_script_bytes=100,
            max_stack_items=100, max_witness_items=20, max_witness_payload_bytes=400),
        **{key: value*8 for key, value in counts.items()})
    return native, dict(context=bench.CONTEXT.hex(), cases=descriptors), dict(file_sha256='13'*32), census


class ByteKeccakPermutationBenchTests(unittest.TestCase):
    def test_exact_short_record_budget_without_graphs(self):
        budget = bench._record_budget()
        self.assertEqual(budget['normal_records'], 467920)
        self.assertEqual(budget['normal_exact_bytes'], 96798660)
        self.assertEqual(budget['authenticated_layouts'], 23)
        self.assertEqual(budget['combined_upper_bytes'], 97500864)
        self.assertLess(budget['combined_upper_bytes'], 128 << 20)
        self.assertEqual(budget['max_identifier_bytes'], 64)

    def test_corrected_state4_iota_and_terminal_chi_producers(self):
        from bench_byte_keccak_block import _producer
        self.assertEqual(ROUND_CONSTANTS[3].to_bytes(8, 'little')[0], 0)
        self.assertEqual(ROUND_CONSTANTS[3].to_bytes(8, 'little')[1], 128)
        self.assertEqual(_producer(3, 0), (1016, 2))
        self.assertEqual(_producer(3, 1), (1216, 1))
        before_round3 = sum(1216+sum(v != 0 for v in ROUND_CONSTANTS[r].to_bytes(8, 'little')) for r in range(3))
        self.assertEqual(before_round3+_producer(3, 1)[0], 4870)
        before_round23 = sum(1216+sum(v != 0 for v in ROUND_CONSTANTS[r].to_bytes(8, 'little')) for r in range(23))
        self.assertEqual(before_round23+_producer(23, 8)[0], 29049)

    def test_synthetic_transport_counts_tree_and_blocks(self):
        native, manifest, info, census = _synthetic()
        rows = bench._validate(native, manifest, info, census)
        self.assertEqual(len(rows), 8)
        self.assertEqual(sum(row['additional_selected_engine_executions'] for row in rows), 16)
        for row in rows:
            self.assertEqual(row['parent']['compiled_script_bytes'], row['tree']['compiled_script_bytes'])
            self.assertEqual(len(row['blocks']), 6)
            self.assertEqual(len(row['joins']), 23)
            self.assertFalse(row['tree']['roots_independently_pinned'])

    def test_scope_counter_alias_and_record_budget_mutations_reject(self):
        native, manifest, info, census = _synthetic()
        mutations = (
            lambda x: x.__setitem__('proof_verified', True),
            lambda x: x.__setitem__('panic_is_rejection', True),
            lambda x: x.__setitem__('cached_boundary_entries', True),
            lambda x: x['cases'][0].__setitem__('round_declared_word_occurrences', True),
            lambda x: x['cases'][0]['joins'][3].__setitem__('producer_consumer_opening_links', 399),
            lambda x: x.__setitem__('compact_execution_records_bytes', 96798659),
            lambda x: x.__setitem__('compact_execution_records_bytes', 97500865),
            lambda x: x['metrics'].__setitem__('vectors', 470496),  # Missing actual tree rechecks.
            lambda x: x['cases'][0].pop('round_false_predicates'),
        )
        for mutate in mutations:
            changed = copy.deepcopy(native)
            mutate(changed)
            with self.assertRaises(ValueError):
                bench._validate(changed, manifest, info, census)

    def test_detached_tree_block_and_selected_leaf_mutations_reject(self):
        native, manifest, info, census = _synthetic()
        mutations = (
            lambda x: x['cases'][0]['tree'].__setitem__('compiled_stream_sha256', '00'*32),
            lambda x: x['cases'][0]['parent'].__setitem__('source_maps_sha256', '00'*32),
            lambda x: x['cases'][0]['parent'].__setitem__('source_maps_sha256', True),
            lambda x: x['cases'][0]['tree'].__setitem__('compiled_script_bytes', 2924501),
            lambda x: x['cases'][0]['tree'].__setitem__('roots_independently_pinned', True),
            lambda x: x['cases'][0]['tree']['negative_counts'].__setitem__('branch', True),
            lambda x: x['cases'][0]['tree'].__setitem__('control_block_bytes', 545),
            lambda x: x['cases'][0]['tree'].__setitem__('control_block_bytes', 513),
            lambda x: x['cases'][1].__setitem__('selected_leaf', 4871),
            lambda x: x['cases'][1].__setitem__('selected_disproof_execution_success', False),
            lambda x: x['cases'][0]['blocks'][0].__setitem__('word_map_sha256', '00'*32),
            lambda x: x['cases'][1]['round_false_predicates'].__setitem__(3, []),
        )
        for mutate in mutations:
            changed = copy.deepcopy(native)
            mutate(changed)
            with self.assertRaises(ValueError):
                bench._validate(changed, manifest, info, census)

    def test_hosted_guard_precedes_io_and_full_graph_build(self):
        with patch.dict(os.environ, {'GITHUB_ACTIONS': 'false'}), \
                patch.object(bench, '_worker', side_effect=AssertionError('path I/O')), \
                patch.object(bench, '_new_directory', side_effect=AssertionError('directory I/O')), \
                patch.object(bench, '_generate', side_effect=AssertionError('actual full graph')):
            with self.assertRaisesRegex(ValueError, 'hosted GitHub Linux'):
                bench.run('unused', 'unused')
            with self.assertRaisesRegex(ValueError, 'hosted GitHub Linux'):
                bench._one(0, 'pallas_scalar', 'honest', None)


if __name__ == '__main__':
    unittest.main()
