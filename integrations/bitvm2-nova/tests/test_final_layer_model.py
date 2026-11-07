"""Pure checks of the M25a final-layer size model (no proving or Script)."""
import unittest

import final_layer_model as m


def shape(**overrides):
    base = dict(log_height=16, main_width=64, aux_width=8, quotient_width=4, log_blowup=9,
                queries=9, grinding_bits=20, log_arity=4, log_final=4, cap=4)
    base.update(overrides)
    return m.Shape(**base)


class FinalLayerModel(unittest.TestCase):
    def test_hand_counted_proof_size(self):
        s = shape()
        self.assertEqual(s.lde_log(), 25)
        self.assertEqual(s.fri_rounds(), 3)
        leaf = 64*4 + 8*16 + 4*16
        per_query = leaf + 3*(25-4)*32 + sum(16*16 + (25-4*(r+1)-4)*32 for r in range(3))
        expected = 9*per_query + (3+3)*16*32 + 2*(64+8+4)*16 + 16*16 + 8
        self.assertEqual(m.proof_bytes(s), expected)
        self.assertEqual(m.conjectured_bits(s), 101)

    def test_more_queries_or_height_never_shrink_the_proof(self):
        self.assertLess(m.proof_bytes(shape()), m.proof_bytes(shape(queries=10)))
        self.assertLess(m.proof_bytes(shape()), m.proof_bytes(shape(log_height=17)))
        self.assertGreater(m.proven_queries(shape(), 100), shape().queries)
        with self.assertRaises(ValueError):
            m.proof_bytes(shape(queries=0))

    def test_search_respects_bits_and_the_prover_budget(self):
        for height, width in ((16, 64), (20, 128)):
            result = m.search(height, width, bits=100)
            self.assertGreaterEqual(result['conjectured_bits'], 100)
            self.assertTrue(result['within_prover_budget'])
        small, large = m.search(16, 64)['proof_bytes'], m.search(22, 256)['proof_bytes']
        self.assertLessEqual(small, 80_000)
        self.assertGreater(large, 80_000)


if __name__ == '__main__':
    unittest.main()
