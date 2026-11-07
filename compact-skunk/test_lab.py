"""Small independent checks; no cryptographic or Bitcoin execution claims."""
import itertools
from pathlib import Path
import tempfile
import unittest

import lab


class BaselineTests(unittest.TestCase):
    def test_exact_roles(self):
        self.assertEqual(lab.pippenger(524288), (10027280, 15))
        self.assertEqual(lab.pippenger(16384), (479518, 10))

    def test_exact_totals(self):
        b = lab.baseline()
        self.assertEqual(b['disproof_script_bytes'], 646467120106606)
        self.assertEqual(b['assertion_signature_bytes'], 15709764369600)
        self.assertEqual(b['policy_bytes'], 1342177280)
        self.assertAlmostEqual(b['average_bytes_per_original_addition_at_policy'], 127.74370269610209)
        self.assertFalse(b['measured_complete_verifier'])

    def test_bad_parameters(self):
        for bad in (0, -1, True, 1.5):
            with self.subTest(value=bad), self.assertRaises(ValueError):
                lab.pippenger(bad)
            with self.subTest(bits=bad), self.assertRaises(ValueError):
                lab.pippenger(3, bad)

    def test_source_drift_fails_before_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / lab.SOURCE
            p.parent.mkdir(parents=True)
            p.write_text("raise RuntimeError('must not execute')\n", encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'source drift'):
                lab.check_upstream(Path(tmp))

    def test_missing_source_fails(self):
        with tempfile.TemporaryDirectory() as tmp, self.assertRaises(FileNotFoundError):
            lab.check_upstream(Path(tmp))


class GraphTests(unittest.TestCase):
    def test_chain_reuses_one_signed_identity(self):
        nodes = [lab.Add('a', 'g', 'g'), lab.Add('b', 'a', 'g'), lab.Add('c', 'b', 'a')]
        got = lab.cut_stats(nodes, {'g'}, 'c', 1)
        self.assertEqual(got['unique_signed_point_values'], 3)
        self.assertEqual(got['max_live_point_values_at_cut'], 2)
        self.assertEqual(got['raw_point_port_signature_bytes'], 3 * 19 * 200)

    def test_whole_graph_only_exposes_final_output(self):
        nodes, fixed, out = lab.bucket_dag([1, 2, 3, 1], 2)
        got = lab.cut_stats(nodes, fixed, out, len(nodes))
        self.assertEqual(got['unique_signed_point_values'], 1)
        self.assertIsNone(got['script_bytes'])
        self.assertFalse(got['dispute_soundness_established'])

    def test_more_than_two_live_bucket_points(self):
        nodes, fixed, out = lab.bucket_dag(list(range(1, 16)) * 2, 4)
        got = lab.cut_stats(nodes, fixed, out, 15)
        self.assertGreaterEqual(got['max_live_point_values_at_cut'], 15)

    def test_repeated_input_is_not_signed_twice(self):
        nodes = [lab.Add('a', 'g', 'g'), lab.Add('b', 'a', 'a')]
        got = lab.cut_stats(nodes, {'g'}, 'b', 1)
        self.assertEqual(got['unique_signed_point_values'], 2)
        self.assertEqual(got['max_chunk_point_ports'], 2)

    def test_bucket_semantics_exhaustive_tiny(self):
        for digits in itertools.product(range(4), repeat=4):
            nodes, fixed, out = lab.bucket_dag(list(digits), 2)
            values = {'zero': 0, **{f'g{i}': 3 * i + 2 for i in range(4)}}
            self.assertEqual(set(values), fixed)
            result = lab.evaluate(nodes, values)[out]
            self.assertEqual(result, sum(d * values[f'g{i}'] for i, d in enumerate(digits)) % 101)

    def test_zero_digits(self):
        nodes, _, out = lab.bucket_dag([0, 0], 1)
        self.assertEqual(lab.evaluate(nodes, {'zero': 0, 'g0': 7, 'g1': 11})[out], 0)

    def test_bad_digits(self):
        for digits, w in [([], 2), ([4], 2), ([-1], 2), ([True], 1), ([0], 0), ([0], 9)]:
            with self.subTest(digits=digits, w=w), self.assertRaises(ValueError):
                lab.bucket_dag(digits, w)

    def test_malformed_dags(self):
        cases = [([lab.Add('a', 'unknown', 'g')], {'g'}, 'a'),
                 ([lab.Add('g', 'g', 'g')], {'g'}, 'g'),
                 ([lab.Add('a', 'g', 'g'), lab.Add('a', 'g', 'g')], {'g'}, 'a'),
                 ([lab.Add('a', 'g', 'g')], {'g'}, 'missing')]
        for nodes, fixed, out in cases:
            with self.subTest(nodes=nodes), self.assertRaises(ValueError):
                lab.cut_stats(nodes, fixed, out, 1)

    def test_bad_chunk_parameters(self):
        nodes, fixed, out = lab.bucket_dag([1], 1)
        for bad in (0, -1, True):
            with self.assertRaises(ValueError):
                lab.cut_stats(nodes, fixed, out, bad)
            with self.assertRaises(ValueError):
                lab.cut_stats(nodes, fixed, out, 1, bad)

    def test_local_equations_can_pass_with_broken_join(self):
        first, second = (3, 5), (9, 11)
        self.assertEqual((first[0] + 2) % 101, first[1])
        self.assertEqual((second[0] + 2) % 101, second[1])
        self.assertNotEqual(first[1], second[0])
        # This counterexample explains why authenticating local values alone
        # cannot replace authentication of shared producer/consumer identity.

    def test_bad_toy_values(self):
        with self.assertRaises(ValueError):
            lab.evaluate([lab.Add('a', 'g', 'g')], {'g': 101})
        with self.assertRaises(ValueError):
            lab.evaluate([lab.Add('a', 'g', 'x')], {'g': 7})


class TensorTests(unittest.TestCase):
    def test_empty_challenge(self):
        self.assertEqual(lab.ipa_weights([]), [1])
        self.assertEqual(lab.tensor_terminal([17], []), 17)

    def test_exhaustive_three_challenges_over_f7(self):
        generators = [1, 4, 2, 6, 3, 0, 5, 2]
        for u in itertools.product(range(1, 7), repeat=3):
            weights = lab.ipa_weights(list(u), 7)
            direct = sum(g * s for g, s in zip(generators, weights)) % 7
            self.assertEqual(lab.tensor_terminal(generators, list(u), 7), direct)

    def test_first_bit_order(self):
        a, b, q = 3, 5, 101
        ai, bi = pow(a, -1, q), pow(b, -1, q)
        self.assertEqual(lab.ipa_weights([a, b]), [ai * bi % q, ai * b % q, a * bi % q, a * b % q])

    def test_proof_dependent_challenges(self):
        generators = [2, 7, 19, 31]
        self.assertNotEqual(lab.tensor_terminal(generators, [3, 5]),
                            lab.tensor_terminal(generators, [3, 6]))

    def test_invalid_tensor_inputs(self):
        for u, q in [([0], 101), ([101], 101), ([True], 101), ([1], 15), ([1] * 13, 101)]:
            with self.subTest(u=u, q=q), self.assertRaises(ValueError):
                lab.ipa_weights(u, q)
        with self.assertRaises(ValueError):
            lab.tensor_terminal([1, 2, 3], [3])
        with self.assertRaises(ValueError):
            lab.tensor_terminal([1, 101], [3])

    def test_reports_preserve_unknowns(self):
        r = lab.report()
        self.assertFalse(r['bitcoin_script_executed'])
        self.assertEqual(r['proofs_generated'], 0)
        self.assertEqual(len(r['bucket_cut_probes']), 15)
        self.assertTrue(all(x['script_bytes'] is None for x in r['bucket_cut_probes']))


if __name__ == '__main__':
    unittest.main()
