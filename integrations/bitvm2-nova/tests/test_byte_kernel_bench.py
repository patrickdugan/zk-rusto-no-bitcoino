"""Tiny graph/transport regressions; no native worker or full permutation.

Only672 words across all fixtures are constructed. Synthetic native summaries
below test response validation only and are not Script-execution evidence.
"""
import copy
import os
import unittest
from unittest.mock import patch

import bench_byte_kernels as bench


def _synthetic_native(cases, census):
    ledger = []
    for source in cases:
        costs = [dict(ordinal=i, kind=leaf['kind'], argument=leaf['argument'], disproof_script_bytes=1)
                 for i, leaf in enumerate(source['spec']['leaves'])]
        ledger.append(dict(case=source['name'], catalogue_id=source['expected_spec_id'],
            registry_id='11'*32, leaf_stream_sha256='22'*32, words=len(source['words']),
            leaves=len(costs), executed_leaves=len(costs), leaf_costs=costs,
            all_disproof_script_bytes=len(costs), largest_disproof_leaf_bytes=1))
    return dict(schema='bitvm2-nova-byte-kernel-execution/v1', passed=True, input_sha256='33'*32,
        raw_vector_file_written=False, full_hash_verified=False, transcript_verified=False,
        full_permutation_verified=False, complete_nova_verifier=False, panic_is_rejection=False,
        test_keys_only=True, stack_limit_enabled=True, op_cat_enabled=False, gpu_jobs=0,
        proof_verified=False, complete_bitvm2_verifier=False, production_assertion_binding=False,
        bitcoin_transaction_graph=False, setup_calls=0, proving_jobs=0, transactions_broadcast=0,
        native_proofs_verified=0, cases=60, normal_leaf_checks=398,
        signatures_generated_once_per_wire=672, guard_vectors=2436, native_rejections=1432,
        shared_baseline_bit_opening_links=416, shared_baseline_aux_opening_links=52,
        bare_exhaustive_pairs=131072, bare_exhaustive_engine_executions=132608,
        ordinary_false_inverse_probes=512, correctness_inverse_probes=512,
        bare_numeric_abort_probes=78, bare_numeric_abort_engine_executions=156,
        body_equality_across_fields_checked=True,
        metrics=dict(vectors=3232, expected_rejections=2834, max_stack_items=100, max_witness_items=100),
        ledger=ledger)


class ByteKernelBenchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases, cls.census = bench.generate()
        cls.by_name = {case['name']: case for case in cls.cases}

    def test_bounded_exact_fixture_and_authentication_census(self):
        self.assertEqual((len(self.cases), self.census['words'], self.census['leaves']), (60, 672, 398))
        self.assertEqual(self.census['authenticated_shapes'], 174)
        self.assertEqual(self.census['expected_shared_baseline_bit_opening_links'], 416)
        self.assertEqual(self.census['baseline_formal_bit_occurrences'], 544)
        self.assertEqual(self.census['expected_shared_baseline_aux_opening_links'], 52)
        for case in self.cases:
            self.assertTrue(case['measure_all'])
            self.assertEqual([check['ordinal'] for check in case['checks']], list(range(len(case['spec']['leaves']))))

    def test_same_external_bytes_and_complete_boolean_conversions(self):
        expected_outputs = {'xor': 0xab, 'and': 0x14, 'not': 0x69}
        for role in bench.ROLES:
            for operation, output in expected_outputs.items():
                candidate = self.by_name[f'{role}/candidate-{operation}']
                baseline = self.by_name[f'{role}/boolean-{operation}']
                cvalues = dict(zip((word['name'] for word in candidate['spec']['words']), candidate['words'], strict=True))
                bvalues = dict(zip((word['name'] for word in baseline['spec']['words']), baseline['words'], strict=True))
                self.assertEqual(cvalues['out'], output)
                for name in cvalues:
                    self.assertEqual(cvalues[name], bvalues[name])
                kinds = [leaf['kind'] for leaf in baseline['spec']['leaves']]
                unique_ports = 2 if operation == 'not' else 3
                self.assertEqual(kinds.count('bits'), unique_ports)
                self.assertEqual(kinds.count('conv_reconstruct'), unique_ports)
                self.assertEqual(kinds.count('bool_'+operation), 8)
                self.assertEqual(len(baseline['words']), 10*unique_ports)

    def test_wrong_outputs_keep_catalogues_and_coherent_bridge_values(self):
        for role in bench.ROLES:
            for operation in ('xor', 'and', 'not'):
                for prefix in ('candidate', 'boolean'):
                    honest = self.by_name[f'{role}/{prefix}-{operation}']
                    wrong = self.by_name[f'{role}/{prefix}-{operation}-wrong']
                    self.assertEqual(honest['expected_spec_id'], wrong['expected_spec_id'])
                    false = [check['ordinal'] for check in wrong['checks'] if not check['expected_correct']]
                    self.assertEqual(false, [0] if prefix == 'candidate' else [4 if operation == 'not' else 6])
                oversized = self.by_name[f'{role}/candidate-{operation}-oversized']
                self.assertEqual(oversized['words'][0], 0xffffffff)
                self.assertEqual(oversized['expected_spec_id'], self.by_name[f'{role}/candidate-{operation}']['expected_spec_id'])

    def test_alias_occurrences_and_cross_byte_rotation_ground_truth(self):
        for role in bench.ROLES:
            for operation in ('xor', 'and'):
                for profile, equal_positions in (('ab', (0, 1)), ('out-a', (0, 2)), ('all', (0, 1, 2))):
                    case = self.by_name[f'{role}/candidate-{operation}-alias-{profile}']
                    wires = case['spec']['leaves'][0]['wires']
                    self.assertEqual(len({wires[i] for i in equal_positions}), 1)
                    self.assertTrue(case['checks'][0]['expected_correct'])
            extras = self.by_name[f'{role}/candidate-extras']
            values = dict(zip((word['name'] for word in extras['spec']['words']), extras['words'], strict=True))
            for r in range(1, 8):
                self.assertEqual(values[f'rol/{r}/out'], (0x963d >> (8-r)) & 255)
            for mask in (0, 1, 128, 129, 255):
                self.assertEqual(values[f'mask/{mask}/out'], 0x96 ^ mask)

    def test_synthetic_cost_contract_and_complete_baseline_accounting(self):
        native = _synthetic_native(self.cases, self.census)
        ledger = bench._validate(native, self.cases, self.census, {'file_sha256': '33'*32})
        comparisons = bench._comparisons(ledger, self.census)
        self.assertEqual(len(comparisons), 6)
        for row in comparisons:
            self.assertEqual(row['candidate_disproof_script_bytes'], 1)
            self.assertEqual(row['boolean_leaf_only_diagnostic_bytes'], 8)
            self.assertEqual(row['full_boolean_baseline_disproof_script_bytes'], row['baseline_leaves'])
            self.assertTrue(row['full_statement_includes_conversion_bridges'])

    def test_synthetic_scope_counts_and_per_leaf_identity_mutations_reject(self):
        original = _synthetic_native(self.cases, self.census)
        mutations = (
            lambda x: x.__setitem__('normal_leaf_checks', True),
            lambda x: x.__setitem__('shared_baseline_bit_opening_links', 544),
            lambda x: x.__setitem__('proof_verified', True),
            lambda x: x.__setitem__('full_permutation_verified', True),
            lambda x: x.__setitem__('complete_nova_verifier', True),
            lambda x: x.__setitem__('panic_is_rejection', True),
            lambda x: x.__setitem__('op_cat_enabled', True),
            lambda x: x.__setitem__('test_keys_only', False),
            lambda x: x.__setitem__('stack_limit_enabled', False),
            lambda x: x.__setitem__('gpu_jobs', True),
            lambda x: x.__setitem__('bare_numeric_abort_probes', True),
            lambda x: x.__setitem__('bare_numeric_abort_engine_executions', 155),
            lambda x: x.__setitem__('input_sha256', '00'*32),
            lambda x: x['ledger'][0]['leaf_costs'][0].__setitem__('kind', 'byte_and'),
            lambda x: x['ledger'][6]['leaf_costs'][0].__setitem__('argument', [True]),
            lambda x: x['ledger'][6]['leaf_costs'][0].__setitem__('argument', [1.0]),
            lambda x: x['ledger'][0].__setitem__('all_disproof_script_bytes', 2),
            lambda x: x['ledger'][0]['leaf_costs'][0].__setitem__('disproof_script_bytes', 100_001),
        )
        for mutate in mutations:
            native = copy.deepcopy(original)
            mutate(native)
            with self.assertRaises(ValueError):
                bench._validate(native, self.cases, self.census, {'file_sha256': '33'*32})

    def test_hosted_guard_precedes_paths_generation_and_process(self):
        with patch.dict(os.environ, {'GITHUB_ACTIONS': 'false'}), \
                patch.object(bench, '_worker', side_effect=AssertionError('path I/O')), \
                patch.object(bench, '_new_directory', side_effect=AssertionError('directory I/O')), \
                patch.object(bench, 'generate', side_effect=AssertionError('generation')):
            with self.assertRaisesRegex(ValueError, 'hosted GitHub Linux'):
                bench.run('unused', 'unused')


if __name__ == '__main__':
    unittest.main()
