"""Exact RH-02 finite-field construction regression tests."""
import unittest

from research.rh_crypto26.ntt_prime_scan import (
    first_prime_in_class, is_prime_by_trial, ntt, naive_dft,
    primitive_power_of_two_root, run_case,
)


class NTTFieldTests(unittest.TestCase):
    def test_trial_primality(self):
        self.assertTrue(is_prime_by_trial(1019)[0])
        self.assertFalse(is_prime_by_trial(1021 * 3)[0])
        self.assertFalse(is_prime_by_trial(1)[0])

    def test_same_first_prime_by_two_searches(self):
        a = first_prime_in_class(16, 6, direct=True)
        b = first_prime_in_class(16, 6, direct=False)
        self.assertEqual(a["p"], b["p"])
        self.assertEqual(a["primality_checks"], b["primality_checks"])
        self.assertLess(a["integers_visited"], b["integers_visited"])
        self.assertEqual(a["p"] % 64, 1)

    def test_ntt_replay(self):
        p = first_prime_in_class(16, 6, direct=True)["p"]
        w, _ = primitive_power_of_two_root(p, 6)
        a = [i * i + 3 for i in range(64)]
        result, count = ntt(a, w, p)
        self.assertEqual(count, 64 * 3)
        self.assertEqual(result, naive_dft(a, w, p))
        reverse, _ = ntt(result, pow(w, -1, p), p)
        self.assertEqual([x * pow(64, -1, p) % p for x in reverse],
                         [x % p for x in a])
        with self.assertRaises(ValueError):
            ntt(a, 1, p)

    def test_full_receipt(self):
        r = run_case(16, 6, 5)
        self.assertTrue(r["independent_dft_equal"])
        self.assertTrue(r["inverse_equal"])
        self.assertEqual(r["transform_checked_length"], 32)


if __name__ == "__main__":
    unittest.main()
