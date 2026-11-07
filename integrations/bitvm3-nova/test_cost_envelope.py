#!/usr/bin/env python3
import unittest
from cost_envelope import estimate


class CostEnvelopeTests(unittest.TestCase):
    def test_m2_predicate_bytes(self):
        self.assertEqual(estimate({'pasta_mul_predicate': 1})['priced_subtotal_stream_bytes'], 5_775_408)

    def test_m3_predicate_bytes(self):
        self.assertEqual(estimate({'pasta_point_add_predicate': 1})['priced_subtotal_stream_bytes'], 69_444_304)

    def test_twenty_million_multiplications(self):
        report = estimate({'pasta_mul_predicate': 20_000_000})
        self.assertEqual(report['priced_subtotal_nonfree_gates'], 7_219_260_000_000)
        self.assertEqual(report['priced_subtotal_stream_bytes'], 115_508_160_000_000)

    def test_decimal_gate_to_byte_conversion(self):
        for gates, gigabytes in [(10**8, 1.6), (10**9, 16), (10**10, 160)]:
            self.assertEqual(estimate({'other_nonfree': gates})['priced_subtotal_stream_decimal_GB'], gigabytes)

    def test_ram_does_not_determine_gates(self):
        a = estimate({'other_nonfree': 10**14}, ram_gib=1)
        b = estimate({'other_nonfree': 10**14}, ram_gib=9)
        self.assertEqual(a['priced_subtotal_nonfree_gates'], b['priced_subtotal_nonfree_gates'])
        self.assertIsNone(b['gate_limit_inferred_from_ram'])
        self.assertFalse(b['memory_limit_enforced'])

    def test_replication_is_explicit(self):
        report = estimate({'other_nonfree': 7}, emitted=11, retained=2)
        self.assertEqual(report['total_generated_ciphertext_subtotal_bytes'], 11 * 7 * 16)
        self.assertEqual(report['retained_ciphertext_subtotal_bytes'], 2 * 7 * 16)
        self.assertFalse(report['cut_and_choose_security_validated'])

    def test_unknown_costs_remain_visible(self):
        report = estimate({'smallfield_extension_mul': 200}, single_stream_cap_bytes=10**9)
        self.assertFalse(report['all_supplied_operations_priced'])
        self.assertEqual(report['unknown_cost_operations'], ['smallfield_extension_mul'])
        self.assertEqual(report['single_stream_cap_status'], 'unknown_costs_prevent_decision')
        self.assertFalse(report['full_verifier_coverage_established'])

    def test_known_cost_overrun(self):
        report = estimate({'other_nonfree': 100, 'unpriced': 2}, single_stream_cap_bytes=1000)
        self.assertEqual(report['single_stream_cap_status'], 'priced_subtotal_exceeds_declared_cap')

    def test_within_cap_does_not_certify_full_verifier(self):
        report = estimate({'other_nonfree': 10}, single_stream_cap_bytes=160)
        self.assertEqual(report['single_stream_cap_status'], 'priced_operations_within_cap_full_verifier_coverage_unverified')
        self.assertFalse(report['optimized_circuit_lower_bound'])

    def test_invalid_inputs_reject(self):
        for invalid in [-1, True, 1.5, '3']:
            with self.assertRaises(ValueError):
                estimate({'pasta_mul_predicate': invalid})
        for kwargs in [dict(emitted=0), dict(emitted=1, retained=2), dict(ram_gib=0), dict(single_stream_cap_bytes=-1)]:
            with self.assertRaises(ValueError):
                estimate({}, **kwargs)

    def test_analytic_keccak_is_labeled(self):
        report = estimate({'keccak_f1600_analytic': 1})
        self.assertEqual(report['priced_subtotal_nonfree_gates'], 38_400)
        self.assertIn('not a repo measurement', report['rows'][0]['price_source'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
