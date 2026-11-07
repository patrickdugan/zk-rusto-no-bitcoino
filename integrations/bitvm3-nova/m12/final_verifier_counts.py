#!/usr/bin/env python3
"""Count the verifier work of an SP1 6.9.0 compressed proof from its recorded shape.

Input: results/sp1-compressed-proof-shape.tsv, written by
`m12-wrapper shape PROOF` (sp1/script) from a real compressed proof. The
compressed proof's shape is fixed by SP1's recursion program, not by the guest.
Output: results/final-verifier-counts.json.

What is counted exactly from the proof:
  - BaseFold query count, Merkle path lengths and leaf widths;
  - every Merkle sibling digest (one 2-to-1 compression per path step);
  - every non-path proof element (absorbed into the Fiat-Shamir challenger).
What is derived:
  - leaf hashes: Poseidon2 sponge of rate 8 (ceil(width / 8) permutations);
    a byte hash at 4 bytes per KoalaBear element (ceil(bytes / 64) compressions);
  - extension multiplications, as a LOWER BOUND: one per BaseFold fold per
    query and round, plus Horner evaluation of every sumcheck round polynomial.
    Constraint evaluation of the chip AIRs at the opened point and the jagged
    evaluation are NOT counted.
"""
from __future__ import annotations
import json
import math
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
SHAPE = os.path.join(HERE, 'results/sp1-compressed-proof-shape.tsv')


def parse():
    rows = {}
    for line in open(SHAPE):
        path, arrays, leaves, lengths = line.rstrip('\n').split('\t')
        rows[path] = {
            'arrays': int(arrays.split('=')[1]),
            'leaves': int(leaves.split('=')[1]),
            'lengths': [int(x) for x in re.findall(r'\d+', lengths.split('=')[1])],
        }
    return rows


def main() -> int:
    r = parse()
    bf = '.Compressed.proof.evaluation_proof.pcs_proof.basefold_proof'
    comp = bf + '.component_polynomials_query_openings_and_proofs[]'
    fri = bf + '.query_phase_openings_and_proofs[]'
    widths = r['.Compressed.proof.evaluation_proof.pcs_proof.batch_evaluations.rounds[].evaluations.storage']['lengths']
    comp_path_digests = r[comp + '.proof.paths.storage']['lengths']          # per round: queries * depth
    comp_values = r[comp + '.values.storage']['lengths']                      # per round: queries * width
    queries = comp_values[0] // widths[0]
    assert [queries * w for w in widths] == comp_values, 'leaf values must be queries x batch widths'
    assert comp_path_digests[0] % queries == 0
    depth = comp_path_digests[0] // queries
    fri_rounds = r[bf + '.fri_commitments']['lengths'][0]
    fri_digests = r[fri + '.proof.paths.storage[]']['arrays']
    fri_values = r[fri + '.values.storage[]']['leaves']
    fri_leaf_width = fri_values // (fri_rounds * queries)
    path_digests = r[comp + '.proof.paths.storage[]']['arrays'] + fri_digests
    total_leaves = sum(v['leaves'] for v in r.values())
    path_leaves = r[comp + '.proof.paths.storage[][]']['leaves'] + r[fri + '.proof.paths.storage[][]']['leaves']
    opened_leaf_values = sum(comp_values) + fri_values
    transcript_elements = total_leaves - path_leaves - opened_leaf_values

    leaf_perm = queries * sum(math.ceil(w / 8) for w in widths) + fri_rounds * queries * math.ceil(fri_leaf_width / 8)
    leaf_bytes_compress = queries * sum(math.ceil(4 * w / 64) for w in widths) + fri_rounds * queries * math.ceil(4 * fri_leaf_width / 64)
    poseidon2 = {
        'merkle_node_compressions': path_digests,
        'leaf_sponge_permutations': leaf_perm,
        'transcript_absorb_permutations': math.ceil(transcript_elements / 8),
    }
    poseidon2['total'] = sum(poseidon2.values())
    byte_hash = {
        'merkle_node_compressions': path_digests,
        'leaf_compressions': leaf_bytes_compress,
        'transcript_compressions': math.ceil(4 * transcript_elements / 64),
    }
    byte_hash['total'] = sum(byte_hash.values())

    gkr = r['.Compressed.proof.logup_gkr_proof.round_proofs[].sumcheck_proof.univariate_polys[].coefficients']
    zc = r['.Compressed.proof.evaluation_proof.sumcheck_proof.univariate_polys[].coefficients']
    jg = r['.Compressed.proof.evaluation_proof.jagged_eval_proof.partial_sumcheck_proof.univariate_polys[].coefficients']
    bfu = r[bf + '.univariate_messages[]']
    horner = sum(v['arrays'] * (v['lengths'][0] - 1) for v in (gkr, zc, jg, bfu))
    folds = fri_rounds * queries
    out = {
        'source_proof': {'file': 'Raito-Scrypt proof-artifacts lighto-h1-20261025/final/s1.cmp.bin',
                         'bytes': 1272893,
                         'sha256': 'b6cf83499e3248ec409f01f1e276bf6a69f8c81a370db82fac72cda3e3a95a1e',
                         'sp1': '6.9.0 compressed (KoalaBear, degree-4 extension, Poseidon2 Merkle, BaseFold + jagged PCS, LogUp-GKR)'},
        'queries': queries, 'component_merkle_depth': depth, 'component_leaf_widths': widths,
        'fri_rounds': fri_rounds, 'fri_leaf_width': fri_leaf_width,
        'merkle_path_digests': path_digests, 'opened_leaf_values': opened_leaf_values,
        'transcript_elements': transcript_elements,
        'poseidon2_permutations': poseidon2,
        'hash_permutations': poseidon2['total'],
        'byte_hash_compressions_same_shape': byte_hash,
        'ext_muls_lower_bound': folds + horner,
        'ext_muls_lower_bound_parts': {'basefold_folds': folds, 'sumcheck_horner': horner},
        'not_counted': ['chip AIR constraint evaluation at the opened point', 'jagged evaluation',
                        'GKR layer combination arithmetic', 'grinding checks (2 permutations)'],
    }
    with open(os.path.join(HERE, 'results/final-verifier-counts.json'), 'w', newline='\n') as f:
        json.dump(out, f, indent=2)
        f.write('\n')
    print(json.dumps(out, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
