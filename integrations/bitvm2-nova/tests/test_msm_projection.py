"""Pure checks of the IPA MSM size projection (no Script, graphs or keys)."""
import unittest

import msm_projection as m


class MsmProjection(unittest.TestCase):
    def test_pippenger_count_matches_a_direct_bucket_simulation_shape(self):
        additions, window = m.pippenger_additions(524_288)
        self.assertEqual(window, 15)
        self.assertEqual(additions, 17*(524_288+(1 << 16)) + 17*16)
        small, small_window = m.pippenger_additions(16_384)
        self.assertEqual(small_window, 10)
        self.assertEqual(small, 26*(16_384+(1 << 11)) + 26*11)
        with self.assertRaises(ValueError):
            m.pippenger_additions(0)

    def test_projection_exceeds_the_forest_policy_by_orders_of_magnitude(self):
        result = m.projection()
        self.assertFalse(result['measured'])
        self.assertEqual(result['roles']['primary']['point_additions'], 10_027_280)
        self.assertEqual(result['roles']['secondary']['point_additions'], 479_518)
        self.assertGreater(result['disproof_script_bytes'], 6*10**14)
        self.assertGreater(result['forest_policy_ratio'], 4*10**5)
        self.assertGreater(result['assertion_signature_bytes'], 10**13)


if __name__ == '__main__':
    unittest.main()
