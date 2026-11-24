# PRAXIS-03 — paper-resolved centered GT search

2026-11-24. Primary source now accessible at https://arxiv.org/pdf/2611.28552v1
(66 pages; ePrint 2026/2971). Reviewed pp. 25, 29–32, 36–37, 46–47.
The formalization is identified by the paper as https://github.com/psivesely/praxis-lean.
Record exact PDF SHA256 and formalization commit before implementing full Enc/Dec;
this note does not certify their equivalence or the extraction theorem.

## Scope

Implement the post-Comb correctness kernel of Figure 10, lines 8–11, in real
arkworks BN254 GT. For valid witness weight xi != 0, the paper's Comb identity
is Lambda = xi K + r(w) Psi, and alpha-scaled copies satisfy the same identity.
Subtract xi K_alpha and c_w Psi_alpha, find t=(r(w)-c_w) using bounded BSGS,
and return xi^{-1}(Lambda-(c_w+t)Psi). Synthetic test fixtures manufacture
these inputs; this does not implement Comb or demonstrate witness encryption.

With m baby steps, index sign classes for b in [0,m), stride 2m-1, and visit
j=0,+1,-1,+2,-2,... . A fingerprint hit must check full GT equality for both
signs, including every index in a colliding bucket. For bounds below half the
prime group order the recovered exponent is unique (identity base special).
Exhaustion must return None, never a plausible key. The benchmark deliberately
uses ordinary GT arithmetic, full SHA-256 and a HashMap; it does NOT implement
the paper's 6-Fp-multiplication recurrence, sorted packed fingerprints or GPU search.
Its wall time is a baseline only.

## Gates

1. cargo test --release --manifest-path integrations/praxis-we/Cargo.toml
   (includes signed boundary, forced all-collision, out-of-range, zero weight,
   identity base, large center, and finite-budget tests).
2. cargo run --release --manifest-path integrations/praxis-we/Cargo.toml --bin centered_search -- 1024 -123456
   Record CPU, flags, baby/giant counts, time and RSS. Sweep m and signed distances.
3. Implement Definition 5.3 centered sampler and Lemma 5.5 bounds independently;
   compare empirical quantiles across witness weights with the certified bound.
4. Implement section 4 QAP test identities and extension-field ties in a toy
   prime field with honest and false systems. Exhaustive rank-1 checks; track
   surviving rank-2/3 cheats, not just valid witness paths.
5. Port Figure 9/10 with deterministic test vectors, pin Lean artifact/version,
   then independently compare Comb outputs with direct scalar reference.
6. Reproduce section 6.3 memory counts with streaming, packed 64-bit fingerprints
   + 32-bit indices, actual recurrence and verified collisions. No GPU extrapolation
   before native measurements; the paper reports ~2^28.7 baby steps and 5.28 GB
   search table for its concrete setting. This reference caps its table at 2^20.
7. Integrate proof-bound regtest settlement only after full Enc/Dec and negative
   controls. The existing seeded Groth16 test setup is unsuitable for security.

## Parameter caution

Table 4 gives N=391693, nc=1694, Fmax=2047, D=3861007, n=4608,
K1=192, K2=12, g approximately 2^50.6, and 6912 cells. At these parameters
the paper estimates 100-bit generic attack cost and an MSIS estimate of 2^103.5,
but the reductions cost about 2^108 for a 2^100 adversary; the proof alone does
not establish a tight concrete 100-bit guarantee from that estimate (p.36).
Neither the toy tests nor the existing Groth16 artifact checks resolve this.
Keep all deployment and capital claims blocked.
