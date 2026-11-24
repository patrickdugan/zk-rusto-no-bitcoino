# PRAXIS-05 through PRAXIS-10 — implementation campaign

2026-11-24. Scope: independent research prototype. No mainnet funds; no production security claim.

## Source and reproducibility

Paper: https://arxiv.org/pdf/2611.28552 and https://eprint.iacr.org/2026/2971.
Reviewed figures 6, 7, 9, 10; equations (4), (6), (7); Definition 5.3 and
Lemmas 5.4/5.5; sections 6.1–6.4. The arXiv PDF was available for reading;
ePrint PDF was inaccessible, and a bytewise PDF checksum was not obtained.
Author formalization pinned to https://github.com/psivesely/praxis-lean/commit/60d3defeebd77caa0e57babe97991e672b948bb6.
Its README states the exact scope and gaps; no independent Lean build claimed.
In particular the formalization is exponent-model correctness, generic
group/RO extraction at fixed parameters, and the general inverse theorem.
The proof verifier encoding and concrete BN254 and MSIS costs lie outside
that certification. The paper derives H_key from GT, Lean from a sign-class
name; the present test code hashes canonical GT serialization with a test
domain, not a production oracle implementation.

## Executed and committed

| Stage | Artifact | Evidence |
|---|---|---|
| 03 | centered_search.rs | Prior native CI green |
| 04 | rank_gap_ties.js | Exact projective rank checks; CI green |
| 05 | praxis_full_reference.js | 288/288 recoveries, 864 invalid witnesses rejected, 15 mutations/wrong-statement controls, 15,664 sampler checks, forced zero xi rejected |
| 06 | bn254_replay.rs | Six real-group vectors, four Comb values checked, correct plaintext, XOR malleability control; CI run 45376722225 green |
| 07 | packed_search.rs | Reciprocal degree-12 recurrence, 12-byte records, bounded collision-checked BSGS; native CI gate |
| 08 | bqs_nonnative.js | 105 canonical Fp products and 635 invalid controls, exact column bound < Fr modulus |
| 09 | full_size_budget.py | Proposition 5.7 group counts; paper vs pointwise wire and throughput sensitivity |
| 10 | settlement_context.py | Fixed-width context, two 128-bit public limbs, independent BIP341/BIP340 checks and isolated payout/refund regtest harness; regtest requires Bitcoin Core |

## Local commands

```sh
node integrations/praxis-we/praxis_full_reference.js
node integrations/praxis-we/praxis_full_reference.js --fixtures
node integrations/praxis-we/bqs_nonnative.js
cargo test --release --manifest-path integrations/praxis-we/Cargo.toml
cargo run --release --manifest-path integrations/praxis-we/Cargo.toml --bin bn254_replay
cargo run --release --manifest-path integrations/praxis-we/Cargo.toml --bin packed_search -- 262144
python3 integrations/praxis-we/full_size_budget.py
python3 integrations/praxis-we/settlement_context.py
# Optional, requires bitcoind and bitcoin-cli on PATH:
python3 integrations/praxis-we/settlement_context.py --regtest
```

The JS reference implements the algebra with d_R=1, small BQS, deterministic
test coins and direct Lagrange interpolation, not production seed expansion.
The native group replay consumes scalar ciphertext fixtures plus sparse public
linear combination plans; those fixtures expose the keys and coins. It is a
group differential, not a deployable ciphertext format or complete Rust port.
The regtest harness signs using a local wallet; it does not verify a Groth16
settlement relation or use witness encryption to authorize spends. The
unmodified paper XOR interface is malleable; choose a domain-separated KDF
and authenticated DEM with a carefully analyzed composition for applications.

## Full-size implementation blockers (fail closed)

1. Implement the actual Groth16 verifier-to-BQS compiler: affine encoding,
   on-curve and subgroup checks, canonical coordinates, correct VK and
   public input handling, non-native Fp2/Fp6/Fp12 arithmetic, Miller loop
   and final exponentiation. For every accepted BQS assignment, decode a
   native verifier-accepted proof. The multiplication primitive is one
   building block; its naive bit count is not comparable to the paper's
   optimized full verifier. Differential-test both directions against
   independent native verifiers with malformed/off-curve/subgroup cases.
2. Build seed expansion, ring d_R=64 MSIS forms, FFT QAP, streamed Enc/Dec,
   point compression, fixed-base windows and MSMs. The current reference
   materializes toy fixtures. The paper's 7.88 GiB uses batch compression;
   pointwise serialization is larger. Audit subgroup checks, bounded I/O
   and exact framing. Obtain the concrete estimator and assess reduction
   loss (2^103.5 estimate vs 2^108 reduction cost for a 2^100 adversary).
3. Benchmark CPU and GPU end-to-end with 2^12, 2^16, 2^18, 2^20 table
   entries before scaling. Measure cold/warm tables, peak RSS and VRAM,
   sort, search, IO, group encoding and decoding, host/device transfer.
   Never multiply Fp microbench throughput into a claimed end-to-end
   time. RTX 5080 has 16 GB VRAM; paper's 12.35 GB fixed-base precomputation
   and 5.28 GB search table are separate peak stages, not a claim they
   coexist with GPU scratch buffers or ZK proving.
4. Bind exact settlement context in the recursive circuit, then wrap in
   Groth16 with honestly generated keys. Two public limbs must be computed
   from the actual checked transition; an externally supplied digest
   alone is insufficient. Proof must enforce state, finality, recipient,
   conservation, nullifier and epoch. Reject wrong network, outpoint,
   amount, fee, script, checkpoint, verifier and transaction signature hash.
5. Build a proof-conditioned presigned transaction release with actual
   Praxis ciphertext and independent Bitcoin Core acceptance on regtest.
   Test malformed ciphertext availability, zero key weight, wrong witness,
   compromised setup, premature publication, retained keys/signatures,
   reorgs, timelocked refund race, fee escalation, and ciphertext withholding.
   A party preparing a signed transaction can retain it; distributed signing
   alone does not prevent the combiner retaining it. Explore verifiable MPC
   that outputs only encrypted authorization, or keep the trust assumption.
   Do not claim keyless/operator-free release or reduced required collateral
   before this protocol is proved and measured.

## Capital accounting for UTXORef / BitVM3

Budget independent statements separately: one ciphertext per pinned release
condition unless reuse follows from a separately justified construction.
A universal Groth16 key amortizes setup but does not make arbitrary ciphertexts
reusable. At paper compression, 100 conditions are 788 GiB; 1000 are 7.695 TiB.
Report settlement latency as proving + witness conversion + decryption +
availability + confirmation, with parallel stages explicitly modeled. Compare
per-condition bytes, operator working capital, refund lockup and availability
failure against the current BitVM3 challenge path. Use the toy prototype to
exercise algebra, not to infer a capital advantage. A batch proof may permit
one ciphertext to authorize an exact batch transaction, but must bind every
payout and preserve independent exit rights; it does not solve signing trust.

The immediate high-value experiment is to build the real proof-to-BQS adapter
with a conservative small verifier and measure exact size before allocating
full-size GPU time. Keep CPU CI on the toy suites and the existing Groth16
artifact fixture; no Silico allocation is needed for this campaign.
