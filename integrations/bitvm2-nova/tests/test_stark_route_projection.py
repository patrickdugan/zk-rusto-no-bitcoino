"""Pure checks of the STARK-route projection (no proving or Script)."""
import unittest

import stark_route_projection as m


class StarkRouteProjection(unittest.TestCase):
    def test_assertion_of_the_counted_sp1_proof(self):
        self.assertEqual(m.assertion_bytes(1_272_893), 318_224*200)
        self.assertEqual(m.assertion_bytes(4), 200)
        self.assertEqual(m.proof_bytes_for(1), 8_000)
        self.assertEqual(m.proof_bytes_for(10), 80_000)
        with self.assertRaises(ValueError):
            m.assertion_bytes(0)

    def test_projection_scales_with_the_measured_block_cost(self):
        result = m.projection(1000)
        self.assertEqual(result['hash_script_bytes_lower_bound'], 39_727_000)
        self.assertEqual(result['proof_assertion_signature_bytes'], 63_644_800)
        self.assertEqual(result['standard_transactions_for_assertion'], 160)
        self.assertFalse(result['measured'])
        with self.assertRaises(ValueError):
            m.projection(0)


if __name__ == '__main__':
    unittest.main()
