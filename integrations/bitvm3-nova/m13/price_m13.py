#!/usr/bin/env python3
"""Garbled price of the M13 final verifier from recorded counts; runs nothing.

Inputs (all in this repo):
  results/verify-counts-c4.json            `m13-verify verify` on the committed
                                           fixture, built with the KoalaBear
                                           operation counters: every BLAKE3
                                           compression per role and every
                                           KoalaBear operation of one complete
                                           final verification
  results/verify-counts-second-guest.json  the same for a second guest's proof
  ../m12/gates/RESULTS.json                measured Boolean gate prices (M12)
  ../m12/results/pricing.json              the M12 figures this replaces
Writes results/pricing.json and prints it.

A garbled circuit has one fixed shape, so it must cover the most work any
proof can need. The counts move slightly with the transcript (challenges are
sampled by rejection; some verifier arithmetic depends on sampled values): two
proofs differed by 2 transcript squeezes and 37 multiplications. The circuit
therefore takes the larger of the two recorded runs per counter and adds
MARGIN_MULS multiplications (full price) and MARGIN_TRANSCRIPT compressions.

Pricing (non-free gates; XOR/NOT free):
  - BLAKE3 compression: measured blake3_compress.
  - Merkle node: one compression plus a 256-AND conditional swap of the
    children by the path bit (d = bit & (l ^ r); l ^= d; r ^= d).
  - Merkle root comparison: 255 AND per opened path (one per leaf hash).
  - KoalaBear mul_full and mul_2exp: koalabear_mul_mod; add, sub, n-ary sum
    terms, halve: koalabear_add_mod.
  - mul_const (an operand within 2^8 of 0 or p; mostly the 0, 1 and W = 3
    coefficients inside degree-4 extension products): three tiers.
    upper   - every one at koalabear_mul_mod;
    central - every one at the measured multiply-by-11 circuit (an 8-bit
              constant has at most 4 Booth digits, like 11);
    lower   - every one at the measured multiply-by-3 circuit (W = 3 is
              the commonest constant; products by 0 and 1 cost less).
  Not priced: byte serialization of field elements (wiring), the 31-bit
  rejection compares, and equality checks of sumcheck claims (at most 124
  gates each).
"""
from __future__ import annotations

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from cost_envelope import CIPHERTEXT_BYTES_PER_GATE  # noqa: E402

CUT_AND_CHOOSE = {'n': 181, 'f': 7, 'source': 'repo cut-and-choose parameters for 2^-40 (as in M12)'}
UPSTREAM_GROTH16_GATES = 11_200_000_000
MARGIN_MULS = 10_000
MARGIN_TRANSCRIPT = 64


def load(rel: str):
    with open(os.path.join(HERE, rel)) as f:
        return json.load(f)


def gb(g: int) -> dict:
    return {'non_free_gates': g, 'ciphertext_bytes': g * CIPHERTEXT_BYTES_PER_GATE,
            'ciphertext_gb': round(g * CIPHERTEXT_BYTES_PER_GATE / 1e9, 3)}


def main() -> int:
    gates = {k: v['non_free_gates'] for k, v in load('../m12/gates/RESULTS.json')['primitives'].items()}
    runs = [load('results/verify-counts-c4.json'), load('results/verify-counts-second-guest.json')]
    m12 = load('../m12/results/pricing.json')

    roles = ['merkle_leaf', 'merkle_node', 'transcript']
    blake = {r: {k: max(run['blake3'][r][k] for run in runs) for k in ('calls', 'compressions', 'bytes')} for r in roles}
    ops = {k: max(run['koalabear_ops'][k] for run in runs) for k in runs[0]['koalabear_ops']}
    variation = {
        'blake3_compressions_total': [run['blake3_compressions_total'] for run in runs],
        'muls_total': [run['koalabear_ops']['mul_full'] + run['koalabear_ops']['mul_const'] for run in runs],
    }
    for run in runs[1:]:
        assert run['wrap_proof_bytes'] == runs[0]['wrap_proof_bytes'], 'proof shapes differ'
        assert run['statement']['wrap_vk_sha256'] == runs[0]['statement']['wrap_vk_sha256'], 'wrap keys differ'

    compressions = sum(blake[r]['compressions'] for r in roles) + MARGIN_TRANSCRIPT
    nodes = blake['merkle_node']['calls']
    leaves = blake['merkle_leaf']['calls']
    g_blake = compressions * gates['blake3_compress']
    g_swaps = nodes * 256
    g_roots = leaves * 255

    mul, add, c11, c3 = (gates[k] for k in ('koalabear_mul_mod', 'koalabear_add_mod', 'koalabear_mul_by_11', 'koalabear_mul_by_3'))
    g_linear = (ops['add'] + ops['sub'] + ops['sum_adds'] + ops['halve']) * add
    g_full = (ops['mul_full'] + ops['mul_2exp'] + MARGIN_MULS) * mul
    g_const = {'upper': ops['mul_const'] * mul, 'central': ops['mul_const'] * c11, 'lower': ops['mul_const'] * c3}
    hash_part = g_blake + g_swaps + g_roots
    totals = {t: hash_part + g_linear + g_full + g_const[t] for t in ('upper', 'central', 'lower')}

    proof_bits = runs[0]['wrap_proof_bytes'] * 8
    poseidon = m12['final_verifier']['as_proved_poseidon2_koalabear']['non_free_gates']
    out = {
        'counts_files': ['results/verify-counts-c4.json', 'results/verify-counts-second-guest.json'],
        'prices': {k: gates[k] for k in ('blake3_compress', 'koalabear_mul_mod', 'koalabear_add_mod', 'koalabear_mul_by_11', 'koalabear_mul_by_3')},
        'circuit_counts': {'blake3_by_role_max': blake, 'koalabear_ops_max': ops,
                           'margin_muls': MARGIN_MULS, 'margin_transcript_compressions': MARGIN_TRANSCRIPT,
                           'observed_variation': variation},
        'gates': {'blake3_compressions': g_blake, 'merkle_swaps': g_swaps, 'merkle_root_compares': g_roots,
                  'field_linear': g_linear, 'field_mul_full_with_margin': g_full, 'field_mul_const': g_const},
        'final_verifier': {t: gb(v) for t, v in totals.items()},
        'share_upper': {'hash_and_merkle': round(hash_part / totals['upper'], 4),
                        'field': round((totals['upper'] - hash_part) / totals['upper'], 4)},
        'proof': {'wrap_proof_bytes': runs[0]['wrap_proof_bytes'], 'input_bits': proof_bits,
                  'input_label_bytes': proof_bits * CIPHERTEXT_BYTES_PER_GATE},
        'cut_and_choose': {**CUT_AND_CHOOSE,
                           'ciphertext_shipped_gb': {t: round(CUT_AND_CHOOSE['f'] * v * CIPHERTEXT_BYTES_PER_GATE / 1e9, 1)
                                                     for t, v in totals.items()}},
        'comparison': {
            'm12_sp1_compressed_poseidon2_as_proved': poseidon,
            'm12_same_shape_blake3_lower_bound_hash_only': m12['final_verifier']['same_shape_blake3_compress']['non_free_gates'],
            'upstream_groth16_garbled_total': UPSTREAM_GROTH16_GATES,
            'upstream_groth16_over_total': {t: round(UPSTREAM_GROTH16_GATES / v, 2) for t, v in totals.items()},
            'm12_poseidon2_over_total': {t: round(poseidon / v, 1) for t, v in totals.items()},
        },
    }
    with open(os.path.join(HERE, 'results/pricing.json'), 'w', newline='\n') as f:
        json.dump(out, f, indent=2)
        f.write('\n')
    print(json.dumps(out, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
