"""BitVM2 cost projection for the transparent STARK final-compression route.

Pure arithmetic over measured inputs; nothing here proves or executes.

* Final proof shape: SP1 6.9 compressed STARK, counted from a real proof in
  garbled-snark-verifier `nova-bitvm3/m12/README.md` (1,272,893 bytes, 124
  BaseFold queries, 33,976 Merkle compressions, 39,727 Poseidon2 permutations).
* Assertion price: 200 WOTS signature bytes per signed 32-bit word, the
  compact Wots4 packet measured by M23 (PROOF-POINT-ORIGINS.md).
* Hash price: the upstream BitVM BLAKE3 Script cost per 64-byte block,
  measured by M24 (STARK-ROUTE.md); passed in, not assumed.

Every value a disproof script reads must be WOTS-signed in BitVM2, so the
final proof's bytes are assertion data, whatever hash the verifier uses.
"""
from math import ceil

SP1_COMPRESSED = dict(proof_bytes=1_272_893, queries=124, merkle_compressions=33_976,
                      permutations=39_727, extension_multiplications_lower_bound=3_656)
WOTS_BYTES_PER_WORD = 200
WORD_BYTES = 4
STANDARD_TX_WEIGHT = 400_000  # witness bytes count one weight unit each


def assertion_bytes(proof_bytes):
    if type(proof_bytes) is not int or proof_bytes < 1:
        raise ValueError('positive proof size required')
    return ceil(proof_bytes/WORD_BYTES)*WOTS_BYTES_PER_WORD


def proof_bytes_for(transactions):
    """Largest final proof whose WOTS assertion fits that many standard txs."""
    if type(transactions) is not int or transactions < 1:
        raise ValueError('positive transaction count required')
    return transactions*STANDARD_TX_WEIGHT//WOTS_BYTES_PER_WORD*WORD_BYTES


def projection(blake3_block_script_bytes, shape=SP1_COMPRESSED):
    if type(blake3_block_script_bytes) is not int or blake3_block_script_bytes < 1:
        raise ValueError('measured positive BLAKE3 block cost required')
    signatures = assertion_bytes(shape['proof_bytes'])
    return dict(shape=dict(shape), blake3_block_script_bytes=blake3_block_script_bytes,
        hash_script_bytes_lower_bound=shape['permutations']*blake3_block_script_bytes,
        proof_assertion_signature_bytes=signatures,
        standard_transactions_for_assertion=ceil(signatures/STANDARD_TX_WEIGHT),
        proof_bytes_for_one_standard_tx=proof_bytes_for(1),
        proof_bytes_for_ten_standard_txs=proof_bytes_for(10), measured=False,
        excluded='chip constraint evaluation, jagged evaluation, field arithmetic, '
                 'transcript framing and the block-to-permutation mapping beyond one block each')
