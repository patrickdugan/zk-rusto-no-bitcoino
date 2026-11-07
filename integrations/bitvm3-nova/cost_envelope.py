#!/usr/bin/env python3
"""Price supplied verifier operation counts; this does not run a prover or verifier."""
from __future__ import annotations
import argparse
import json
from typing import Mapping

# Predicate prices include admission/exception checks. An optimized internal
# arithmetic operation or fixed-base MSM must receive its own measured price.
PRICES = {
    'pasta_mul_predicate': 360_963,
    'pasta_point_add_predicate': 4_340_269,
    'keccak_f1600_analytic': 24 * 1600,
    'other_nonfree': 1,
}
SOURCES = {
    'pasta_mul_predicate': 'docs/nova-bitvm3-m2-radix4.md: measured predicate',
    'pasta_point_add_predicate': 'docs/nova-bitvm3-m3-results.md: measured predicate',
    'keccak_f1600_analytic': 'analytic 24 rounds x 1600 chi ANDs; not a repo measurement',
    'other_nonfree': 'caller-supplied already counted non-free gates',
}
CIPHERTEXT_BYTES_PER_GATE = 16


def nonnegative(value: object, name: str) -> int:
    if type(value) is not int or value < 0:
        raise ValueError(f'{name} must be a nonnegative integer')
    return value


def estimate(counts: Mapping[str, int], *, emitted: int = 1, retained: int = 1,
             ram_gib: int = 9, single_stream_cap_bytes: int | None = None) -> dict:
    emitted = nonnegative(emitted, 'emitted')
    retained = nonnegative(retained, 'retained')
    ram_gib = nonnegative(ram_gib, 'ram_gib')
    if emitted < 1 or retained > emitted or ram_gib < 1:
        raise ValueError('require emitted>=1, 0<=retained<=emitted, ram_gib>=1')
    if single_stream_cap_bytes is not None:
        nonnegative(single_stream_cap_bytes, 'single_stream_cap_bytes')
    rows, unknown = [], []
    subtotal = 0
    for operation, count in sorted(counts.items()):
        count = nonnegative(count, operation)
        if operation not in PRICES:
            if count:
                unknown.append(operation)
            continue
        gates = count * PRICES[operation]
        subtotal += gates
        rows.append({'operation': operation, 'count': count,
                     'nonfree_gate_price': PRICES[operation], 'nonfree_gates': gates,
                     'price_source': SOURCES[operation]})
    stream_bytes = subtotal * CIPHERTEXT_BYTES_PER_GATE
    status = 'not_specified'
    if single_stream_cap_bytes is not None:
        if stream_bytes > single_stream_cap_bytes:
            status = 'priced_subtotal_exceeds_declared_cap'
        elif unknown:
            status = 'unknown_costs_prevent_decision'
        else:
            status = 'priced_operations_within_cap_full_verifier_coverage_unverified'
    return {
        'scope': 'conditional_operation_cost_scenario',
        'counts_are_measured_by_this_tool': False,
        'full_verifier_coverage_established': False,
        'optimized_circuit_lower_bound': False,
        'rows': rows, 'unknown_cost_operations': unknown,
        'all_supplied_operations_priced': not unknown,
        'priced_subtotal_nonfree_gates': subtotal,
        'priced_subtotal_stream_bytes': stream_bytes,
        'priced_subtotal_stream_decimal_GB': stream_bytes / 10**9,
        'priced_subtotal_stream_GiB': stream_bytes / 2**30,
        'emitted_circuits': emitted,
        'total_generated_ciphertext_subtotal_bytes': emitted * stream_bytes,
        'retained_circuits': retained,
        'retained_ciphertext_subtotal_bytes': retained * stream_bytes,
        'ram_budget_bytes': ram_gib * 2**30,
        'ram_measurement_available': False,
        'memory_limit_enforced': False,
        'gate_limit_inferred_from_ram': None,
        'single_stream_cap_status': status,
        'protocol_overhead_included': False,
        'cut_and_choose_security_validated': False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pasta-muls', type=int, default=0)
    parser.add_argument('--point-adds', type=int, default=0,
                        help='checked point-addition predicates, not scalar multiplications')
    parser.add_argument('--keccak-permutations', type=int, default=0)
    parser.add_argument('--other-nonfree', type=int, default=0)
    parser.add_argument('--unknown', action='append', default=[])
    parser.add_argument('--emitted', type=int, default=1)
    parser.add_argument('--retained', type=int, default=1)
    parser.add_argument('--ram-gib', type=int, default=9)
    parser.add_argument('--single-stream-cap-bytes', type=int)
    args = parser.parse_args()
    counts = {'pasta_mul_predicate': args.pasta_muls,
              'pasta_point_add_predicate': args.point_adds,
              'keccak_f1600_analytic': args.keccak_permutations,
              'other_nonfree': args.other_nonfree}
    for name in args.unknown:
        if name in PRICES:
            parser.error('--unknown must name an unpriced operation')
        counts[name] = 1
    try:
        report = estimate(counts, emitted=args.emitted, retained=args.retained,
                          ram_gib=args.ram_gib,
                          single_stream_cap_bytes=args.single_stream_cap_bytes)
    except ValueError as error:
        parser.error(str(error))
    print(json.dumps(report, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
