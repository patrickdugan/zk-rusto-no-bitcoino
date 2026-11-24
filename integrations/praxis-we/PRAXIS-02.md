# PRAXIS-02 — independent algebra and throughput probes

2026-11-24. PRAXIS-01 CI green (45318292815, base head 0180864).
Source: https://eprint.iacr.org/2026/2971 (abstract).
Both primary PDF and eprint.iacr.asia mirror failed retrieval. No author reference
implementation or Lean source was located. Obtain and pin them before 01B/01C.

## Width-two identity

Over BN254 scalar field Fr, let U be n-by-2, V m-by-2, M=UV^T.
Encode U in G1, V in G2. Write P_ik=[U_ik]G1 and Q_jk=[V_jk]G2.
Then e(P_i1,Q_j1)e(P_i2,Q_j2)=g_T^(M_ij).

For public separable weights W_ij=a_i b_j,
the product of weighted target entries is exactly
e(sum_i a_i P_i1,sum_j b_j Q_j1) times
e(sum_i a_i P_i2,sum_j b_j Q_j2).

This follows from bilinearity and distributivity; the implementation compares
against dense weighted pairings and a clear scalar oracle. Factor bytes are
2*n*32+2*m*64 at standard compressed BN254 sizes, excluding framing.
Arkworks serializes Fq12 target group elements at a different size; measure it.

For r supplied separable terms in W, repeat contraction r times; arbitrary
entrywise W need not be separable at low rank. This identity alone says nothing
about the rank-gap security proof, distribution of Praxis weights, extension
field identities, ciphertext generation or search algorithm. Pairing term counts
exclude scalar multiplication and final exponentiation; speedup cannot be
equated with the count ratio.

## Measurement contract

```sh
cargo test --release --manifest-path integrations/praxis-we/Cargo.toml
cargo run --release --manifest-path integrations/praxis-we/Cargo.toml --bin rank2_kernels -- 1000000
```

Deterministic public data only. Fq and Fq2 products measured in eight lanes on
a single CPU thread, 8*rounds operations each. Record compiler, CPU, OS, flags,
wall time and rate; distinguish Fq2 products from base-field multiplications.
For n,m in (2,3),(4,4),(8,8),(16,16), count pair terms, serialized factors, dense
target bytes and time preweighting, dense contraction and factored contraction
independently. Require exact agreement on all sizes and mutation/zero-weight
controls. No GPU speedup or end-to-end Praxis time claimed. Subsequent work:
repeat on local RTX 5080 using a pinned audited GPU field library with host/device
differential tests, sweep batch sizes and data transfer, then implement the exact
paper kernels only when source is pinned.

## Related work watch

Hair/Sahai's rank-gap precursor: https://arxiv.org/abs/2609.18275.
Jutla, https://eprint.iacr.org/2026/2995 (Nov 23), claims a different
entropy-based replacement for rank gap in the prime-order generic group model.
Its asymptotic guarantees do not establish better concrete costs for Groth16.
Track independently rather than conflate the constructions.
