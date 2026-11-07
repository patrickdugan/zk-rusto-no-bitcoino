#!/usr/bin/env python3
"""Price the M12 candidates from recorded counts; runs no prover or verifier.

Inputs (all in this repo):
  ../fixtures/bitcoin-header/k20-testnet4-verifier-inventory.json  exact k=20 Nova verifier work
  results/k1-verifier-inventory.json                               exact k=1 Nova verifier work
  gates/RESULTS.json                                               measured Boolean gate prices
  results/sp1-*.json                                               SP1 executions (architecture A)
  results/decider-b-*.json                                         architecture B relation runs
  results/final-verifier-counts.json                               counted shape of the final proof
Writes results/pricing.json and prints a summary.
"""
from __future__ import annotations
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from cost_envelope import PRICES, CIPHERTEXT_BYTES_PER_GATE  # noqa: E402


def load(rel: str):
    p = os.path.join(HERE, rel)
    return json.load(open(p)) if os.path.exists(p) else None


G = load('gates/RESULTS.json')['primitives']
GATE = {k: v['non_free_gates'] for k, v in G.items()}

# Poseidon2 over KoalaBear, width 16, as Plonky3 instantiates it: S-box x^3,
# 8 external rounds (4 + 4) and 20 internal rounds. This is DERIVED from the
# measured field prices, not built as a circuit:
#   S-boxes: 8*16 + 20 = 148, two multiplications each;
#   round constants: 8*16 + 20 = 148 additions;
#   external linear layer (9 applications): per 4-word block M4 = 8 additions
#     and 2 doublings, then 12 + 16 additions to mix the four blocks;
#   internal linear layer (20 applications): 15 additions for the sum, 16
#     diagonal constant multiplications (priced as the measured x11 constant
#     multiplication, the dearest small constant measured) and 16 additions.
def poseidon2_koalabear_gates() -> dict:
    mul, add, c3, c11 = GATE['koalabear_mul_mod'], GATE['koalabear_add_mod'], GATE['koalabear_mul_by_3'], GATE['koalabear_mul_by_11']
    sbox = 148 * 2 * mul
    rc = 148 * add
    ext_layer = 4 * (8 * add + 2 * add) + (12 + 16) * add
    external = 9 * ext_layer
    internal = 20 * (15 * add + 16 * c11 + 16 * add)
    # Some KoalaBear diagonal entries are inverse powers of two (large residues),
    # so the upper bound prices every diagonal entry as a full multiplication.
    internal_upper = 20 * (15 * add + 16 * mul + 16 * add)
    total = sbox + rc + external + internal
    return {'total': total, 'total_upper': sbox + rc + external + internal_upper,
            'sbox_muls': sbox, 'round_constants': rc, 'external_layers': external,
            'internal_layers': internal, 'internal_layers_upper': internal_upper,
            'status': 'derived from measured mul/add/constant prices; not built. total prices diagonal '
                      'entries as the measured x11 constant multiplication; total_upper as full multiplications'}


def gb(g: int) -> dict:
    return {'non_free_gates': g, 'ciphertext_bytes': g * CIPHERTEXT_BYTES_PER_GATE,
            'ciphertext_tb': round(g * CIPHERTEXT_BYTES_PER_GATE / 1e12, 4)}


def direct_nova(inv: dict) -> dict:
    lw = inv['linear_verifier_work']
    muls, msm = lw['field_muls_in_matrix_eval_and_ipa_scalars'], lw['msm_terms_total']
    return {'field_muls': muls, 'msm_terms': msm,
            'muls_priced_as_pasta_mul_predicate': gb(muls * PRICES['pasta_mul_predicate']),
            'msm_sensitivity_12_point_adds_per_term': gb(msm * 12 * PRICES['pasta_point_add_predicate']),
            'vk_bytes': inv['verifier_key_bytes']}


def b_relation(inv: dict) -> dict:
    """Operations the B relation adds over the folded witness (primary + secondary)."""
    out = {'field_muls': 0, 'msm_terms': 0}
    for e in inv['engines']:
        nnz, rows, vars_ = e['nnz']['total'], e['padded_rows'], e['padded_vars']
        # Az, Bz, Cz: one multiplication per nonzero; then Az*Bz and u*Cz per row;
        # gamma*E for the combined binding: one per row.
        out['field_muls'] += nnz + 3 * rows
        # One combined MSM over max(|W|, |E|) generators plus the blinding term.
        out['msm_terms'] += max(rows, vars_) + 1
    return out


def main() -> int:
    inv20 = load('../fixtures/bitcoin-header/k20-testnet4-verifier-inventory.json')
    inv1 = load('results/k1-verifier-inventory.json')
    p2 = poseidon2_koalabear_gates()
    out = {
        'prices': {'measured_gates': GATE, 'pasta_mul_predicate': PRICES['pasta_mul_predicate'],
                   'pasta_point_add_predicate': PRICES['pasta_point_add_predicate'],
                   'poseidon2_koalabear_w16_derived': p2,
                   'ciphertext_bytes_per_gate': CIPHERTEXT_BYTES_PER_GATE},
        'direct_garbled_nova_verifier': {'k1': direct_nova(inv1), 'k20': direct_nova(inv20)},
        'b_relation_ops': {'k1': b_relation(inv1), 'k20': b_relation(inv20)},
    }
    sp1 = load('results/sp1-execute-k1.json') or load('results/sp1-execute-k1-run1.json')
    if sp1:
        c = sp1['instruction_count']
        ratio_msm = inv20['linear_verifier_work']['msm_terms_total'] / inv1['linear_verifier_work']['msm_terms_total']
        ratio_mul = inv20['linear_verifier_work']['field_muls_in_matrix_eval_and_ipa_scalars'] / inv1['linear_verifier_work']['field_muls_in_matrix_eval_and_ipa_scalars']
        ratio_vk = inv20['verifier_key_bytes'] / inv1['verifier_key_bytes']
        tr = sp1['cycle_tracker']
        verify, decode, sha = tr.get('nova_verify', 0), tr.get('decode_vk', 0), tr.get('sha256_vk', 0)
        if verify:
            rest = c - verify - decode - sha
            k20 = verify * max(ratio_msm, ratio_mul) + (decode + sha) * ratio_vk + rest
            rule = 'nova_verify x max(msm, mul ratio) + (decode_vk + sha256_vk) x vk-bytes ratio + rest'
        else:
            k20 = c * max(ratio_msm, ratio_mul, ratio_vk)
            rule = 'no per-phase split recorded: whole run x the largest of the three ratios'
        out['architecture_a_sp1'] = {
            'k1_measured_instructions': c, 'k1_cycle_tracker': tr,
            'k20_extrapolated_instructions': int(k20),
            # What remains if the pinned key reached the guest in a form needing no
            # point decompression or full-key hashing (a different pinned encoding).
            'verify_only_floor': {'k1_measured': verify,
                                  'k20_extrapolated': int(verify * max(ratio_msm, ratio_mul))},
            'scaling': {'msm_terms': ratio_msm, 'field_muls': ratio_mul, 'vk_bytes': ratio_vk, 'rule': rule},
        }
    direct = load('results/sp1-direct-headers.json')
    if direct:
        steady = direct['runs'][-1]
        per = steady['instructions_per_header']
        chains = {'testnet4_158970': 158_970, 'mainnet_974264': 974_264}
        c = {'instructions_per_header_measured': per, 'measured_over_headers': steady['headers'],
             'chain_heights_source': 'testnet4 158,970 = end of the genesis-anchored whole-chain k=5 Nova proof (zk-rusto-no-bitcoino e1a2c18); '
                                     'mainnet 974,264 = Bitcoin-BitVM tip record of 2026-11-02',
             'whole_chain_instructions': {k: int(per * n) for k, n in chains.items()}}
        if sp1:
            a1 = sp1['instruction_count']
            c['a_k1_over_whole_chain'] = {k: round(a1 / (per * n), 2) for k, n in chains.items()}
            if 'architecture_a_sp1' in out:
                a = out['architecture_a_sp1']
                a20 = a['k20_extrapolated_instructions']
                c['a_k20_over_whole_chain'] = {k: round(a20 / (per * n), 2) for k, n in chains.items()}
                if a['verify_only_floor']['k1_measured']:
                    for tag in ('k1_measured', 'k20_extrapolated'):
                        v = a['verify_only_floor'][tag]
                        c[f'a_verify_only_{tag}_over_whole_chain'] = {k: round(v / (per * n), 2) for k, n in chains.items()}
        out['control_c_direct'] = c
    fv = load('results/final-verifier-counts.json')
    if fv:
        h = fv['hash_permutations']
        hb = fv['byte_hash_compressions_same_shape']['total']
        ext = fv.get('ext_muls_lower_bound', 0)
        ext_g = ext * GATE['koalabear_ext4_mul']
        out['final_verifier'] = {
            'counts_file': 'results/final-verifier-counts.json',
            'hash_permutations_poseidon2': h, 'byte_hash_compressions': hb, 'ext_muls_lower_bound': ext,
            'ext_mul_gates_lower_bound': ext_g,
            'lower_bounds_note': 'hash work counted from the proof; extension work is a lower bound '
                                 '(chip constraint evaluation and jagged evaluation not counted)',
            'as_proved_poseidon2_koalabear': gb(h * p2['total'] + ext_g),
            'as_proved_poseidon2_koalabear_upper': gb(h * p2['total_upper'] + ext_g),
            'same_shape_blake3_compress': gb(hb * GATE['blake3_compress'] + ext_g),
            'same_shape_sha256_compress': gb(hb * GATE['sha256_compress'] + ext_g),
            'same_shape_keccak_f1600': gb(hb * GATE['keccak_f1600'] + ext_g),
            'reference_upstream_groth16_garbled_total_gates': 11_200_000_000,
        }
    with open(os.path.join(HERE, 'results/pricing.json'), 'w', newline='\n') as f:
        json.dump(out, f, indent=2)
        f.write('\n')
    print(json.dumps(out, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
