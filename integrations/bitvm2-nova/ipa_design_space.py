"""Illustrative non-interactive BitVM2/IPA MSM design sensitivities.

Imports the pinned source-of-truth baseline from msm_projection.py. All proposed
improvements are *inputs*, not performance claims. No Script is generated or run.
The signature scenario is boundary-only and intentionally leaves private state,
key authentication, root binding, transcript and dispute soundness unpriced.
"""

import argparse
import json

import msm_projection as base


def positive_integer(name, value):
    if type(value) is not int or value < 1:
        raise ValueError(f'{name} must be a positive integer')
    return value


def ceiling_div(numerator, denominator):
    return (numerator + denominator - 1) // denominator


def breakpoint():
    """Break-even thresholds for the *MSM alone*, excluding all other components."""
    previous = base.projection()
    total = sum(side['point_additions'] for side in previous['roles'].values())
    return {
        'forest_policy_bytes': base.FOREST_POLICY_BYTES,
        'required_combined_script_reduction_factor': ceiling_div(
            previous['disproof_script_bytes'], base.FOREST_POLICY_BYTES),
        'maximum_average_script_bytes_per_original_point_addition':
            base.FOREST_POLICY_BYTES / total,
        'total_projected_point_additions': total,
        'baseline_script_bytes': previous['disproof_script_bytes'],
        'baseline_full_word_signature_bytes': previous['assertion_signature_bytes'],
        'status': 'arithmetic break-even, not a deployability or soundness bound',
    }


def scenario(*, msm_operation_reduction=1, script_cost_reduction=1,
             additions_per_chunk=1, boundary_words=36):
    """Independent, hypothetical workload and boundary-signature reductions.

    msm_operation_reduction is a divisive scenario for a different MSM algorithm;
    script_cost_reduction is an independent divisive scenario per operation.
    Rounding is performed per IPA role. The alleged chunk boundaries consist of
    exactly boundary_words u32s at each end of a contiguous chunk; the model
    makes no assertion that those words suffice to authenticate a real MSM.
    """
    for name, value in (
        ('msm_operation_reduction', msm_operation_reduction),
        ('script_cost_reduction', script_cost_reduction),
        ('additions_per_chunk', additions_per_chunk),
        ('boundary_words', boundary_words),
    ):
        positive_integer(name, value)

    previous = base.projection()
    roles = {}
    for role, measured in previous['roles'].items():
        remaining = ceiling_div(measured['point_additions'], msm_operation_reduction)
        script_bytes = ceiling_div(remaining * base.COMPLETE_ADD_BYTES[role],
                                   script_cost_reduction)
        # One signed word-set per chunk boundary, including the initial state.
        # This is a hypothetical accounting exercise, not a secure protocol.
        chunk_boundaries = ceiling_div(remaining, additions_per_chunk) + 1
        signatures = chunk_boundaries * boundary_words * base.WOTS_SIGNATURE_BYTES
        roles[role] = {
            'model_point_additions': remaining,
            'model_script_bytes': script_bytes,
            'boundary_count': chunk_boundaries,
            'illustrative_boundary_signature_bytes': signatures,
        }
    total_script = sum(r['model_script_bytes'] for r in roles.values())
    total_signatures = sum(r['illustrative_boundary_signature_bytes']
                           for r in roles.values())
    return {
        'input': {
            'msm_operation_reduction': msm_operation_reduction,
            'script_cost_reduction': script_cost_reduction,
            'additions_per_chunk': additions_per_chunk,
            'boundary_words': boundary_words,
        },
        'roles': roles,
        'total_model_script_bytes': total_script,
        'total_illustrative_boundary_signature_bytes': total_signatures,
        'msm_script_within_policy': total_script <= base.FOREST_POLICY_BYTES,
        'other_verifier_script_budget_bytes': max(0, base.FOREST_POLICY_BYTES-total_script),
        'measured': False,
        'sound_dispute_protocol_established': False,
        'includes_transcript_proof_decode_or_bitcoin_transactions': False,
    }


def comparison():
    return {
        'source': 'integrations/bitvm2-nova/msm_projection.py (M22 measured additions)',
        'breakpoint': breakpoint(),
        'cases': {
            'baseline_boundary_illustration': scenario(),
            'coarse_boundaries_only_64': scenario(additions_per_chunk=64),
            'coarse_boundaries_only_256': scenario(additions_per_chunk=256),
            'hypothetical_1000x_per_op': scenario(script_cost_reduction=1000),
            'hypothetical_100000x_per_op': scenario(script_cost_reduction=100000),
            'hypothetical_500000x_per_op': scenario(script_cost_reduction=500000),
            'hypothetical_100x_fewer_ops_1000x_per_op': scenario(
                msm_operation_reduction=100, script_cost_reduction=1000,
                additions_per_chunk=64),
        },
        'transparent_succinct_wrapper': {
            'setup': 'intended transparent; system/parameters not yet selected',
            'script_bytes': None,
            'proof_bytes': None,
            'prover_peak_ram_bytes': None,
            'prover_seconds': None,
            'sound_dispute_path_tested': False,
            'measured': False,
        },
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--msm-operation-reduction', type=int, default=1)
    parser.add_argument('--script-cost-reduction', type=int, default=1)
    parser.add_argument('--additions-per-chunk', type=int, default=64)
    parser.add_argument('--boundary-words', type=int, default=36)
    parser.add_argument('--comparison', action='store_true')
    args = parser.parse_args()
    report = comparison() if args.comparison else scenario(
        msm_operation_reduction=args.msm_operation_reduction,
        script_cost_reduction=args.script_cost_reduction,
        additions_per_chunk=args.additions_per_chunk,
        boundary_words=args.boundary_words)
    print(json.dumps(report, sort_keys=True, indent=2))


if __name__ == '__main__':
    main()
