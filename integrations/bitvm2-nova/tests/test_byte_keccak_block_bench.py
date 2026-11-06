"""Pure reference and synthetic transport tests; no actual block or native run.

Fake identities and costs below exercise the private response checker only.
They cannot be supplied to public run() as execution receipts.
"""
import copy
import os
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import bench_byte_keccak_block as bench
from keccak_trace import ROUND_CONSTANTS


def _synthetic():
    descriptors, observations, census = [], [], []
    normal = guards = words_total = 0
    for role, start, profile, boundary, slot in bench._requests():
        children, first = [], 0
        for i in range(4):
            r = start+i
            leaves = 1216+sum(value != 0 for value in ROUND_CONSTANTS[r].to_bytes(8, 'little'))
            children.append(dict(round=r, operation_id=f'test-only/child/{i}/round/{r}',
                program_sha256='11'*32, catalogue_id='22'*32, source_sha256='33'*32,
                wordmap_sha256='44'*32, words=200+leaves, leaves=leaves, first_leaf=first))
            first += leaves
        false = []
        if profile.startswith('middle-'):
            false = [children[boundary]['first_leaf']+(1216 if slot == 0 else 1024)]
        elif profile.startswith('final-'):
            false = [children[3]['first_leaf']+(1216 if slot == 0 else 1024)]
        elif profile == 'oversized':
            false = [0, 240]
        source = dict(name=bench._name(role, start, profile, boundary), profile=profile,
            role=role, start_round=start, boundary_index=boundary, byte_slot=slot,
            program_sha256='55'*32, catalogue_id='66'*32, source_sha256='77'*32,
            global_ids_sha256='88'*32, words=first+200, leaves=first,
            expected_false=false, children=children)
        parent = {key: source[key] for key in ('program_sha256', 'catalogue_id', 'source_sha256',
                                             'global_ids_sha256', 'words', 'leaves')}
        parent.update(context=bench.CONTEXT.hex(), registry_id='99'*32,
            compiled_stream_sha256='aa'*32, executed_leaves=first,
            compiled_script_bytes=first*100, largest_disproof_leaf_bytes=100)
        child_false = [[ordinal-child['first_leaf'] for ordinal in false
                        if child['first_leaf'] <= ordinal < child['first_leaf']+child['leaves']]
                       for child in children]
        observed = {key: source[key] for key in ('name', 'profile', 'role', 'start_round', 'boundary_index', 'byte_slot')}
        observed.update(parent=parent, children=copy.deepcopy(children),
            false_predicates=list(false), child_false_predicates=child_false,
            joins=[dict(index=i, state_round=start+i+1, cached_entries=200,
                        producer_consumer_opening_links=400) for i in range(3)],
            cached_boundary_entries=600, producer_consumer_opening_links=1200,
            signature_entries_created=source['words'], child_declared_word_occurrences=source['words']+600,
            guard_layouts=5, guard_vectors=70, native_rejections=24,
            map_rejections=8, source_rejections=12, cache_rejections=18)
        descriptors.append(source)
        observations.append(observed)
        census.append(dict(normal_leaf_checks=first, source_guard_layouts=5, guard_vectors=70))
        normal += first
        guards += 70
        words_total += source['words']
    native = dict(schema='bitvm2-nova-byte-keccak-block-execution/v1', passed=True,
        input_manifest_sha256='bb'*32, cases=observations,
        four_round_block_script_conformance_checked=True, all_parent_leaves_executed=True,
        boundary_opening_links_checked=True, children_projected_from_parent=True,
        test_keys_only=True, stack_limit_enabled=True, raw_vector_file_written=False,
        op_cat_enabled=False, full_24_round_composition_verified=False, cross_block_linking_verified=False,
        full_permutation_verified=False, full_hash_verified=False, transcript_verified=False,
        proof_verified=False, complete_nova_verifier=False, complete_bitvm2_verifier=False,
        production_assertion_binding=False, bitcoin_transaction_graph=False, panic_is_rejection=False,
        setup_calls=0, proving_jobs=0, native_proofs_verified=0, gpu_jobs=0, transactions_broadcast=0,
        compact_execution_records_bytes=1000, compact_execution_records_sha256='cc'*32,
        signature_entries_created=words_total, child_declared_word_occurrences=words_total+32*600,
        cached_boundary_entries=19200, producer_consumer_opening_links=38400,
        metrics=dict(vectors=2*normal+guards, expected_rejections=normal+guards,
            max_script_bytes=100, max_stack_items=100, max_witness_items=20, max_witness_payload_bytes=400))
    return native, dict(context=bench.CONTEXT.hex(), cases=descriptors), dict(file_sha256='bb'*32), census


class ByteKeccakBlockBenchTests(unittest.TestCase):
    def test_exact_request_schedule_and_natural_occurrences(self):
        requests = list(bench._requests())
        self.assertEqual(len(requests), 32)
        for role in bench.ROLES:
            rows = [row for row in requests if row[0] == role]
            self.assertEqual(sum(row[2] == 'honest' for row in rows), 6)
            self.assertEqual(sum(row[2].startswith('middle-') for row in rows), 6)
            self.assertEqual(sum(row[2].startswith('final-') for row in rows), 2)
            self.assertEqual(sum(row[2] == 'oversized' for row in rows), 2)
        self.assertEqual(bench._producer(0, 0), (1216, 1))
        self.assertEqual(bench._producer(23, 8), (1024, 2))
        self.assertEqual(bench._consumers(0, 0), ((0, 0), (240, 0)))
        self.assertEqual(bench._consumers(0, 40), ((0, 1), (280, 0)))
        for slot in range(200):
            first, second = bench._consumers(5000, slot)
            self.assertNotEqual(first, second)
            self.assertLess(first[0], 5160)
            self.assertGreaterEqual(second[0], 5240)
        with self.assertRaises(ValueError):
            bench._producer(0, True)
        with self.assertRaises(ValueError):
            bench._initial(True)
        # Exact decoder declarations also matter on a private symbolic seam.
        plan = SimpleNamespace(global_ids=('x',), children=(None,)*4, joins=(None,)*3)
        with self.assertRaises(ValueError):
            bench._structure(plan, SimpleNamespace(words=(('x', 256.0),)), 0)

    def test_pure_pipeline_recomputes_after_each_middle_claim(self):
        initial = bench._initial(0)
        for boundary in range(3):
            claims, final, children, honest = bench._pipeline(0, initial, 'middle-iota', boundary, 0)
            self.assertIsNone(final)
            self.assertEqual(sum(claim is not None for claim in claims), 1)
            self.assertEqual(children[boundary][1][0] ^ children[boundary][2][0], 1)
            for i in range(1, 4):
                self.assertEqual(children[i][0], children[i-1][2])
            self.assertNotEqual(children[-1][2], honest)

    def test_synthetic_contract_has_only_parent_costs(self):
        native, manifest, info, census = _synthetic()
        rows = bench._validate(native, manifest, info, census)
        self.assertEqual(len(rows), 32)
        self.assertEqual(sum(row['profile'] == 'honest' for row in rows), 12)
        for row in rows:
            self.assertEqual(row['cached_boundary_entries'], 600)
            self.assertEqual(row['producer_consumer_opening_links'], 1200)
            self.assertNotIn('compiled_script_bytes', row['children'][0])

    def test_scope_count_alias_and_join_cache_mutations_reject(self):
        native, manifest, info, census = _synthetic()
        mutations = (
            lambda x: x.__setitem__('full_24_round_composition_verified', True),
            lambda x: x.__setitem__('panic_is_rejection', True),
            lambda x: x.__setitem__('cached_boundary_entries', True),
            lambda x: x['cases'][0].__setitem__('signature_entries_created', True),
            lambda x: x['cases'][0]['joins'][0].__setitem__('producer_consumer_opening_links', 399),
            lambda x: x['cases'][0].__setitem__('cache_rejections', 17),
            lambda x: x['cases'][0].__setitem__('map_rejections', 7),
            lambda x: x['cases'][0].__setitem__('source_rejections', 11),
        )
        for mutate in mutations:
            changed = copy.deepcopy(native)
            mutate(changed)
            with self.assertRaises(ValueError):
                bench._validate(changed, manifest, info, census)

    def test_child_identity_false_partition_and_resource_mutations_reject(self):
        native, manifest, info, census = _synthetic()
        mutations = (
            lambda x: x['cases'][0]['children'][0].__setitem__('wordmap_sha256', '00'*32),
            lambda x: x['cases'][0]['parent'].__setitem__('source_sha256', '00'*32),
            lambda x: x['cases'][6].__setitem__('child_false_predicates', [[], [], [], []]),
            lambda x: x['cases'][0]['joins'][1].__setitem__('index', True),
            lambda x: x['metrics'].__setitem__('max_script_bytes', True),
            lambda x: x['metrics'].__setitem__('max_witness_payload_bytes', 520001),
            lambda x: x.__setitem__('compact_execution_records_bytes', (128 << 20)+1),
        )
        for mutate in mutations:
            changed = copy.deepcopy(native)
            mutate(changed)
            with self.assertRaises(ValueError):
                bench._validate(changed, manifest, info, census)

    def test_hosted_guard_precedes_io_and_actual_block_build(self):
        with patch.dict(os.environ, {'GITHUB_ACTIONS': 'false'}), \
                patch.object(bench, '_worker', side_effect=AssertionError('path I/O')), \
                patch.object(bench, '_new_directory', side_effect=AssertionError('directory I/O')), \
                patch.object(bench, '_generate', side_effect=AssertionError('actual graph')):
            with self.assertRaisesRegex(ValueError, 'hosted GitHub Linux'):
                bench.run('unused', 'unused')
            with self.assertRaisesRegex(ValueError, 'hosted GitHub Linux'):
                bench._one(0, 'pallas_scalar', 0, 'honest', None, None, None)


if __name__ == '__main__':
    unittest.main()
