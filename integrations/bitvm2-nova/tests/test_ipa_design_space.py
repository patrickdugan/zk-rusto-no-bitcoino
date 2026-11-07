"""Pure arithmetic tests. No graphs, signing keys, Script or proving."""
import unittest

import ipa_design_space as d
import msm_projection as m


class DesignSpace(unittest.TestCase):
    def test_breakpoint_exactly_tracks_existing_projection(self):
        got = d.breakpoint()
        old = m.projection()
        self.assertEqual(got['baseline_script_bytes'], old['disproof_script_bytes'])
        self.assertEqual(got['baseline_full_word_signature_bytes'],
                         old['assertion_signature_bytes'])
        self.assertEqual(got['total_projected_point_additions'], 10_506_798)
        self.assertEqual(got['required_combined_script_reduction_factor'], 481_656)
        self.assertLess(got['maximum_average_script_bytes_per_original_point_addition'], 128)
        self.assertGreater(got['maximum_average_script_bytes_per_original_point_addition'], 127)

    def test_one_per_chunk_matches_unreduced_script_baseline(self):
        got = d.scenario()
        self.assertEqual(got['total_model_script_bytes'],
                         m.projection()['disproof_script_bytes'])
        self.assertFalse(got['msm_script_within_policy'])
        self.assertFalse(got['sound_dispute_protocol_established'])
        self.assertEqual(got['roles']['primary']['model_point_additions'], 10_027_280)
        self.assertEqual(got['roles']['secondary']['model_point_additions'], 479_518)

    def test_changing_chunk_size_changes_only_illustrative_signatures(self):
        small = d.scenario(additions_per_chunk=1)
        large = d.scenario(additions_per_chunk=64)
        self.assertEqual(small['total_model_script_bytes'],
                         large['total_model_script_bytes'])
        self.assertLess(large['total_illustrative_boundary_signature_bytes'],
                        small['total_illustrative_boundary_signature_bytes'])
        # There are distinct initial and final boundaries for the two roles.
        expected = sum((d.ceiling_div(n, 64)+1)*36*200
                       for n in (10_027_280, 479_518))
        self.assertEqual(large['total_illustrative_boundary_signature_bytes'], expected)

    def test_narrow_script_fit_does_not_claim_whole_verifier_fit(self):
        below = d.scenario(script_cost_reduction=100_000)
        at = d.scenario(script_cost_reduction=500_000)
        self.assertFalse(below['msm_script_within_policy'])
        self.assertTrue(at['msm_script_within_policy'])
        self.assertLess(at['other_verifier_script_budget_bytes'], 50*1024*1024)
        self.assertFalse(at['includes_transcript_proof_decode_or_bitcoin_transactions'])

    def test_per_role_ceil_and_invalid_parameters(self):
        r = d.scenario(msm_operation_reduction=10_027_281,
                       script_cost_reduction=100_000_000, additions_per_chunk=10)
        self.assertEqual([v['model_point_additions'] for v in r['roles'].values()], [1, 1])
        self.assertEqual([v['boundary_count'] for v in r['roles'].values()], [2, 2])
        for arg in ('msm_operation_reduction', 'script_cost_reduction',
                    'additions_per_chunk', 'boundary_words'):
            for val in (0, -1, 1.5, True):
                with self.subTest(arg=arg, val=val), self.assertRaises(ValueError):
                    d.scenario(**{arg: val})

    def test_wrapper_is_unmeasured(self):
        report = d.comparison()
        wrapper = report['transparent_succinct_wrapper']
        self.assertIsNone(wrapper['script_bytes'])
        self.assertIsNone(wrapper['prover_peak_ram_bytes'])
        self.assertFalse(wrapper['sound_dispute_path_tested'])


if __name__ == '__main__':
    unittest.main()
