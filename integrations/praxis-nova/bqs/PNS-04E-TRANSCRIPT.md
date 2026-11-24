# PNS-04E: exact transcript reduction and architecture gate

Date: 2026-11-24. Nova-only (Pallas/Vesta, Spartan/IPA). No additional proof wrapper.
Previous checkpoint 693a64bade86d28891b157d897a7573b8af3f28c passed both CI jobs:
https://github.com/patrickdugan/zk-rusto-no-bitcoino/actions/runs/45384923354

## Confirmed native results

Source: cpu-fold job 138413287519 and direct-nova-bqs job 138413287779 of that run.
Settlement PNS-01 has 4,996 step constraints; arity 11, 3 folded payouts,
10,912 compressed proof bytes, 18,984,584 VK bytes. Fold 0.359 s,
compression 5.843 s, verification 0.139 s on this CI host.
The independent native verifier accepted pinned artifacts and rejected its four
pin/terminal/malformed controls. These are test fixtures, not production authorization.

Both the arity-one SquarePlusFive and settlement keys have padded domain 16,384 on
each side (14 outer and 15 inner sumcheck rounds, 14 IPA rounds per side).
Square augmented pre-pad (constraints, variables): primary (9820,9812),
secondary (10349,10331). Settlement primary (16378,16381), secondary (10349,10331).
Each key has 16,384 vector generators plus one IPA auxiliary base per side,
and each opening has 28 variable L/R terms. At the existing 8-bit unshifted
group schedule, the combined two-side group-only estimate is 6,751,647,332
Boolean unknowns for either circuit, excluding transcript, scalar folding,
Spartan matrices, and Nova folding. This is a schedule estimate, not full
relation generation, runtime, or ciphertext measurement.

Actual joint one-round native IPA BQS (including original transcript):
| Curve | Previous | Compact | Compact equations |
|---|---:|---:|---:|
| Pallas | 13,569,899 | 7,044,914 | 4,003,714 |
| Vesta | 13,572,221 | 7,047,236 | 4,006,036 |

Both native positives passed; changed a_hat rejected at final group equality.
These are isolated openings of size two, not complete Nova proof verification.

## New exact wide reduction

The old transcript circuit implements 258 steps of Boolean modular reduction for
each 512-bit digest. The new variant exports the actual raw Keccak output bits,
retaining the native non-EVM Nova 0.76 transcript schedule. The same slots
are used by the arithmetic suffix, with no independent challenge input.
Use x = p*k+r with 512-bit x, unsigned 258-bit k and canonical 255-bit r.
Three radix-2^86 limbs for k and r, six limbs for x; six linear convolution
column equations and five signed 91-bit carries with fixed zero endpoints.
For B=2^86, S=2^90, absolute column residual <=3(B-1)^2+2(B-1)+(B+1)S,
below BN254 Fr, for every binary assignment. Consequently zero in Fr
implies integer equality, which telescopes; r < p and k >= 0 give uniqueness.
Canonical r uses the existing eight canonicality rows.
48 positive and 194 negative checks directly executed across both Pasta
fields (input digest, quotient, remainder, carry mutations and canonical alias).
Cost per digest: 1,230 new Boolean unknowns and 14 linear equations, input
digest bits already allocated. Native raw transcript + compact joint IPA
differential is registered in CI; do not claim its final counts before execution.

Files: wide_reduction.js, results/wide-reduction.json,
src/bin/ipa_raw_transcript.rs, ipa_joint.js.
Existing compiler and original transcript route remain available for comparison.

## Feasibility decision

Hold full-size witness encryption. The remaining dominant cost is the linear-size
Pedersen IPA MSM, even for the smallest Nova augmented circuit. Reducing
Keccak gates is useful but cannot eliminate this cost.

Research priorities:
- Eagen, *Zero Knowledge Proofs of Elliptic Curve Inner Products from Principal
  Divisors and Weil Reciprocity*, https://eprint.iacr.org/2022/596 .
  Investigate a direct algebraic certificate for fixed-generator MSM using
  divisors, function-field identities or logarithmic derivatives; prefer exact
  deterministic constraint equivalence. A probabilistic/Fiat-Shamir ECIP check
  changes the verification relation: derive a security reduction including
  extraction of the auxiliary certificate and challenge binding, or keep it
  as a separately labeled research variant. A fixed evaluation point or
  prover-selected challenge is not a sound replacement for checking identity.
- Pasta-specific GLV and signed fixed-base digit/window improvements are
  acceptable baseline comparisons, with subgroup and integer decomposition
  constraints and all table costs included. Do not extrapolate speedups from
  small tests. Fixed bases do not imply fixed transcript-dependent weights.
- Inspect Nova-native verifier/commitment variants as analytical alternatives
  only, with explicit curve, setup, compatibility and security consequences.
  Preserve the existing Pallas/Vesta Nova/IPA implementation. No Groth16,
  SP1, STARK, or additional proof wrapper. Do not change commitment schemes or
  introduce a new trust model without a separately reviewed decision.
- Continue real Spartan outer/inner and batch/matrix binding and both
  IPA openings from an actual arity-one proof. A partial or synthetic fixture
  is insufficient. Recompute all public state, keys, statement, and hashes.
  Consider an application-specific exact relation as a cost control; this
  is not equivalent to verifying a compressed Nova proof and must be labeled.
- Re-derive Praxis admissible parameters and reductions only after actual
  relation size and soundness are known. The paper's 7.88 GiB Groth16
  estimate does not transfer. Report a quantitative no-go if appropriate.

Claude handoff: CLAUDE_PNS04F.md.
