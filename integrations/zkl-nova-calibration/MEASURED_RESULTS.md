# ZKL-08 actual synthesis and recursive proof receipt

**Measured source commit:** [b3622dc406840613557b9e18a0836896486fe10f](https://github.com/patrickdugan/zk-rusto-no-bitcoino/commit/b3622dc406840613557b9e18a0836896486fe10f).
**Evidence:** [GitHub Actions run 45563952669, job 139034072986](https://github.com/patrickdugan/zk-rusto-no-bitcoino/actions/runs/45563952669/job/139034072986), completed success 2026-11-25. Hosted Ubuntu CI, release mode, two Rayon/build threads. No local Rust toolchain was available to the assistant; these are hosted measurements, not extrapolations.

| depth | max arity | raw step constraints | aux variables incl. five state inputs |
|---:|---:|---:|---:|
| 4 | 0 | 4163 | 4166 |
| 4 | 1 | 5747 | 5753 |
| 4 | 2 | 7331 | 7340 |
| 8 | 0 | 6687 | 6694 |
| 8 | 1 | 9539 | 9553 |
| 8 | 2 | 12391 | 12412 |
| 12 | 0 | 9211 | 9222 |
| 12 | 1 | 13331 | 13353 |
| 12 | 2 | 17451 | 17484 |

Exact empirical fit across measured shapes: C(d,a)=1639+631d+a*(316+317d), with depth d and maximum arity a. These are raw step counts, not the total constraints in Nova proving. Fixed-shape max arity 2 incurs the same measured count across active arities. Measured 13 targeted malformed witnesses rejected; 2 terminal host negatives rejected. All 18 honest transitions replayed in constraint assignments. Calibration process elapsed 2.55 s, maximum RSS 73368 KiB.

## Actual Nova recursion, depth 4, max arity 2

* Steps: 3 (one fact, one unary, one binary).
* Augmented primary/secondary constraints: 18707 / 10349.
* Augmented variables: 18711 / 10331.
* Public parameter setup: 3.207843631 s.
* Recursive initialization and folding: 0.371349722 s.
* Verification: 0.192429132 s.
* Serialized recursive proof: 2190776 B (bincode; excludes parameters).
* Process elapsed 3.95 s, maximum RSS 85344 KiB.
* Expected terminal state verified; wrong initial state and step count rejected.

The fixture proves derivability relative to a public four-rule environment. It is not a general Lean kernel. The recursive proof is not claimed to be zero knowledge and the deterministic proof-memory root can leak information. The terminal check is outside the circuit and must be applied to the verified output. The first measured run did not execute Spartan compression. A subsequent workflow step exercises existing --compress mode with the same fixture, still Nova/Spartan IPA only; no compressed result is assumed until the new run passes.

The companion DataGoblin PR #67 passed eight generated dependent-family theorem exports with Lean 4.19.0. The actual circuit here checks ground Horn rules, not arbitrary dependent terms, so neither cross-project result establishes zkLean equivalence. ZKL-09/10 measured a shared-DAG search baseline and admissible A*, with proof step count as the first proxy for uniform folding cost. Future work should bind indexed rule instantiation and reduction in the circuit and test independent implementations of the same typed relation. Use cost fits only in their measured scope.
