# ZKL-NOVA-17: equality and dependent transport

2026-11-25. The full gate passes: native conformance, the independent adversarial suite, Lean 4.24.0 kernel export checks, all 7,673 row assignments, 21 recursive proofs and 21 compressed proofs. Four CPU shards produced identical matrix and serialized verifier-key bytes. Hosted run [45608709882](https://github.com/patrickdugan/zk-rusto-no-bitcoino/actions/runs/45608709882) tested source `2849ae1124ff53066e8d143cacee19dc308ccf82`; [Rust CI 45608709578](https://github.com/patrickdugan/zk-rusto-no-bitcoino/actions/runs/45608709578) also passed on that source. The exact downloaded aggregate is retained in `nova17_hosted_receipt.json`, with artifact authentication and local replay evidence in `nova17_hosted_audit.json`.

## Verified Nat predecessor

Stage 16 passed its full [hosted run 45603149771](https://github.com/patrickdugan/zk-rusto-no-bitcoino/actions/runs/45603149771) on source `3c6d21d95bf2c0f2ca075dab8dda7bfb5ace689a`. Its 2,047 assignments produced ten recursive proofs and ten compressed proofs with one verifier key. All 320 altered-statement and count checks failed. The receipt and artifact audit are retained in `nova16_hosted_receipt.json`.

Stage 16 measured 49,711 primary augmented constraints, 10,349 secondary constraints, a 55,034,496-byte verifier key, and 11,632 bytes per compressed proof. Full assignment generation took 364.56 seconds with peak RSS 865,800 KiB. Its Rust proof process took 665.86 seconds with peak RSS 621,016 KiB. These separate hosted runs provide workload estimates; comparisons across stages also depend on runner variation and the changed circuit.

## Fixed equality environment

Preserve constants C0 through C5 and append this fixed syntax:

| ID | Declaration |
|---|---|
| C6 | `Eq : (A : Sort 1) → A → A → Sort 0` |
| C7 | `refl : (A : Sort 1) → (x : A) → Eq A x x` |
| C8 | Based path induction with motive in `Sort 0` |
| C9 | Based path induction with motive in `Sort 1` |
| C10 | Based path induction with motive in `Sort 2` |

For each admitted motive universe `v`, J has the following type:

```text
J (A : Sort 1) (x : A)
  (M : (y : A) → Eq A x y → Sort v)
  (d : M x (refl A x))
  (y : A) (p : Eq A x y) : M y p
```

The motive can depend on both the destination and the equality proof. This supports transport along a neutral hypothesis `p`, and supports proof-indexed families. Reflexivity gives the computation rule:

```text
J A x M d x (refl A x) ↦ d
```

The design follows Lean's [propositional equality](https://lean-lang.org/doc/reference/latest/Basic-Propositions/Propositional-Equality/) and based `Eq.rec` signature. `equality_environment.cjs` contains the verifier-owned, deeply frozen de Bruijn ASTs. The certificate cannot supply or replace these declarations. Rust independently hashes an exact literal copy of all eleven signatures with native Poseidon before using the matrix.

Extending the constant table exposed an inherited Nat guard that used the environment's upper bound. Both native occurrences now explicitly admit recursor IDs 3 through 5. The arithmetic Nat rules already had this exact bound. The adversarial suite exercises every C0 through C10 head against both Nat reduction cases.

## Native certificates and independent Lean checking

`equality.cjs` implements the locally nameless certificate relation, builder, and separate de Bruijn reference inference. It reuses checked semantic deduplication and backward dependency pruning. All ten previous optimized Nat certificates remain byte-identical. Twenty-one complete fixtures shrink from 29,625 rows to 7,673, with a maximum of 862. A depth-ten history tree retains capacity for every fixture.

| Fixture | Original rows | Checked pruned rows |
|---|---:|---:|
| polymorphic_identity | 52 | 33 |
| dependent_application | 340 | 133 |
| beta_conversion | 276 | 88 |
| impredicative_predicate_identity | 289 | 113 |
| nat_zero | 4 | 4 |
| nat_recursion | 350 | 193 |
| iota_zero_type | 376 | 193 |
| iota_succ_type | 528 | 227 |
| dependent_nat_elimination | 1865 | 538 |
| prop_nat_elimination | 1863 | 525 |
| equality_reflexivity | 42 | 40 |
| equality_symmetry | 2965 | 622 |
| equality_transitivity | 4699 | 862 |
| propositional_transport | 3964 | 767 |
| dependent_transport | 3966 | 774 |
| equality_congruence | 3216 | 705 |
| proof_dependent_elimination | 918 | 392 |
| equality_iota_type | 790 | 325 |
| equality_iota_value | 666 | 310 |
| equality_iota_proposition | 842 | 332 |
| equality_iota_proof_index | 1614 | 497 |
| Total | 29625 | 7673 |

The native suite rejects twelve malformed source cases, 21 wrong public statements, and 7,359 self-references. Among 1,680 deterministic mutations, 1,651 fail; the 29 accepted mutations preserve independently checked valid judgments. Forced conversion cases exercise J in all three supported motive universes.

The separately authored suite in `equality_adversarial.cjs` rebuilds complete valid term DAGs around candidate J steps. Its 2,592-case matrix accepts 36 valid candidates and rejects 2,556 invalid candidates. Additional controls cover 25 spine and scope cases, four correlated references to structurally identical terms at different row IDs, six invalid references, 22 Nat head cases, 55 fixed-signature cases, and seven coordinated application attacks with valid child typing premises. Ten independently authored source positives and six negatives exercise neutral transport, proof-dependent motives, beta conversion around J, and mixed Nat/J reduction. The old 2,047-row Nat corpus replays under the extended checker.

`equality_lean.cjs` translates every original proof and goal AST into explicit Lean declarations. `EqualityTransport.lean` checks the eleven wrapper signatures and defines all 21 fixtures using Lean's `Nat.rec` and `Eq.rec`. The official Lean 4.24.0 Linux compiler, commit `797c613eb9b6d4ec95db23e3e00af9ac6657f24b`, accepted the entire file in 0.639 seconds. All 21 declarations report zero axiom dependencies. `equality_lean_receipt.json` records the source and release archive hashes, observed declarations, and compiler result. The compiler issued 17 unused-binder warnings.

This export gives independent kernel evidence for the concrete source examples. General Lean parsing and declaration import remain future work. Native conversion uses the explicitly implemented beta, Nat iota and equality iota rules; Lean also has its own additional kernel conversion rules.

## Authenticated arithmetic

Append VJ as tag 30, preserving all earlier tag numbers. Increase the maximum number of historical reads from ten to eleven. Keep fourteen record fields, eleven bits per field, depth ten, and fourteen recursive state coordinates. Assign a fresh leaf domain to the stage-17 record encoding while retaining term and internal-node domains.

A VJ record authenticates the left and right endpoints, five partial J applications, the J constant, and the three-node reflexivity application spine, with shared nodes counted once in the actual history proof. Its eleven requested read slots check:

- The application has six explicit arguments and its head ID lies in 8 through 10.
- The proof argument is `refl A x`, whose head is C7.
- Both occurrences of the carrier and all correlated source/destination row IDs agree.
- The right endpoint is the exact base argument `d`, and both conversion endpoints are locally closed.

The exact reference requirements are deliberately conservative: structurally equal terms at distinct correlated IDs require a separately justified conversion path. Each used record is authenticated against the prior root; every address precedes the current row. The existing frontier relation binds every appended record to the next root and ten frontier slots. Admission requires a sealed empty-context typing judgment whose type digest equals the independently pinned public goal.

| Metric | Stage 16 | Stage 17 |
|---|---:|---:|
| Tags | 29 | 30 |
| Constant signatures | 6 | 11 |
| Historical read slots | 10 | 11 |
| Poseidon hashes per circuit | 97 | 104 |
| Hash constraints | 30264 | 32448 |
| Sparse R1CS constraints | 38298 | 41406 |
| Wires including ONE | 37236 | 40263 |
| Canonical nonzero terms | 935196 | 1021954 |
| Explicit constraints including state bindings | 38326 | 41434 |
| Recursive state arity | 14 | 14 |

The local sample checks 60 assignments from the 21 fixtures plus one supplementary VL assignment from the original beta fixture. These 61 assignments cover all thirty tags, every constant signature, and all three forced J conversion cases. Every one of the 7,673 native history transitions agrees with the independent full tree and extracted frontier. All 1,024 boundary insertions pass.

There are 84 targeted goal and assigned-wire rejections, together with 235 regenerated-input rejections. The latter include all eleven signature digests, eighteen invalid J equations, and nine coordinated changes that preserve the local J equations but fail history authentication. They also cover malformed shared-memory siblings, repeated-address conflicts, and frontier corruption. The full trace requests 28,409 raw reads, 25,166 unique within-row addresses, and 158,702 actual parent nodes before padding.

## Full hosted gate

The workflow `.github/workflows/zklean-nova-equality.yml` first reproduces both native suites, checks the deterministic Lean export and kernel result, and compares the arithmetic sample. It then partitions the 21 fixtures by original index modulo four. The four job sizes are 2,326, 1,943, 1,405 and 1,999 rows. Each CPU job has a sixty-minute limit, two build threads and two Rayon threads.

Every row receives a full assignment check. Rust recomputes the goal digest and genesis, validates the matrix pins and native Poseidon vectors, checks each explicit step, folds the complete derivation, and verifies its recursive and compressed endpoints. It tests every initial-state coordinate and two incorrect step counts against both proof verifiers. The observed total is 336 recursive and 336 compressed verifier rejections, with 42 malformed-step rejections. Every proof and verifier key passes a serialization round trip, and each unsealed prefix fails the admission policy.

The committed Cargo.lock comes from the successful local Rust 1.90.0 compile and pins transitive dependencies for every hosted build. Each shard retains the generated matrix, full conformance receipt, complete proof receipts, proof payloads, verifier key, dependency lockfile, hashes and measured process times. `equality_receipts.cjs` verifies the downloaded artifact contents and exact corpus coverage. The final gate requires all four matrix hashes and all four serialized verifier-key hashes to match. This gate passed for the complete corpus. All four matrix files, all four serialized verifier keys and all four dependency lockfiles are byte-identical.

```sh
node integrations/zklean-nova/equality.cjs --fixtures
node integrations/zklean-nova/equality_adversarial.cjs
node integrations/zklean-nova/equality_lean.cjs --check
lean integrations/zklean-nova/EqualityTransport.lean
node integrations/zklean-nova/equality_frontier.cjs
node integrations/zklean-nova/equality_frontier.cjs --full /tmp/equality-fixture --shard 0/4
cargo +1.90.0 run --release --locked --manifest-path integrations/zklean-nova/nova-smoke/Cargo.toml \
  --bin equality_frontier -- /tmp/equality-fixture /tmp/equality-proof --shard 0/4
```

## Hosted measurements and artifact audit

| Check | Observed result |
|---|---:|
| Complete derivations / folded transitions | 21 / 7673 |
| Full row assignments checked | 7673 |
| Supplementary VL assignments checked | 4 |
| Recursive / compressed verifier rejections | 336 / 336 |
| Malformed step rejections | 42 |
| Unsealed prefix refusals | 21 |
| Proof and key serialization round trips | 21 |
| Direct goal and assignment mutations rejected | 84 |
| Regenerated input attacks rejected across shards | 268 |

The partitioned full run repeats constant-signature and repeated-address controls per shard, which explains its 268 regenerated attacks compared with the single-process sample's 235. All eighteen malformed J equations and nine coordinated J-history attacks fail in both settings. Every concrete proof and goal also passed the hosted Lean check, whose output reports zero axiom dependencies for all 21 declarations.

| Shard | Proofs | Rows | Generation seconds | Rust proof process seconds | Rust peak RSS MiB |
|---|---:|---:|---:|---:|---:|
| 0 | 6 | 2326 | 466.64 | 760.10 | 651.60 |
| 1 | 5 | 1943 | 672.85 | 1033.19 | 640.98 |
| 2 | 5 | 1405 | 386.70 | 603.77 | 640.45 |
| 3 | 5 | 1999 | 416.58 | 646.13 | 641.14 |

The final job completed 33 minutes 44 seconds after run creation. Every measured process exited successfully with zero swaps. The highest generation peak RSS was 952.98 MiB. Across all proofs, mean steady fold times span 0.1937 to 0.3889 seconds, compression spans 9.173 to 16.713 seconds, and compressed verification spans 0.1824 to 0.3428 seconds. These measurements come from separate hosted runners. Shard 1 took longer in generation and proving while producing the same matrix and key, so architectural speed comparisons require a controlled host.

The aggregate artifact was downloaded and replayed through the source-owned `combine` command. Local output matches the hosted receipt byte for byte. All six artifact ZIP digests match GitHub's published digests, every per-case receipt agrees with its aggregate entry, and all compressed payload lengths and hashes were checked. The audit records source, run, job and artifact IDs plus archive hashes and expiry dates.

| Retained item | SHA-256 |
|---|---|
| Matrix, 78,541,025 bytes | `c583f594c0757e1910ec667c13e27ca081778e4167fed58188d1ea9d1dc12c04` |
| Shared verifier key, 58,504,816 bytes | `7e3b1dc3b54457d56ba6d63f973e5d7d3d90ac7fb542248b69f496338a02bf8b` |
| Exact aggregate, 584,345 bytes | `70bcd9b89af1697706fc02a75da1ca80b425a55f52b7fa0027ce0a0ad9bec638` |

## Why the serialized sizes changed

| Measure | Stage 16 | Stage 17 |
|---|---:|---:|
| Primary augmented constraints | 49711 | 52819 |
| Secondary constraints | 10349 | 10349 |
| Verifier-key bytes | 55034496 | 58504816 |
| Recursive-proof bytes | 4141592 | 4337912 |
| Compressed-proof bytes | 11632 | 11632 |

This build selects `spartan::snark::RelaxedR1CSSNARK` with IPA. That [backend retains the R1CS matrices in its verifier key](https://docs.rs/nova-snark/latest/nova_snark/spartan/snark/index.html). Inspection of the pinned Nova 0.76.0 source (`spartan/snark.rs` and `r1cs/sparse.rs`) shows that each extra nonzero contributes a 32-byte field coefficient and an 8-byte column index to the bincode encoding. The 86,758 added nonzeros therefore account exactly for the 3,470,320-byte key increase:

```text
40 × (1,021,954 − 935,196) = 3,470,320 bytes
```

The recursive proof retains error and witness vectors. Its 196,320-byte increase also matches the additional primary constraints and wires exactly:

```text
32 × ((41,406 − 38,298) + (40,263 − 37,236)) = 196,320 bytes
```

The primary and secondary padded dimensions remain 65,536 and 16,384. Their sumcheck and IPA round counts stay fixed, preserving the 11,632-byte compressed payload for every proof. All 21 payloads total 244,272 bytes, with the public statement and shared key supplied separately. This explains the measured storage sizes; the timing receipts remain the evidence for runtime.

## Scope and verifier trust

The proof statement is admission by this bounded relation with its fixed Nat and equality environment. A verifier must pin the matrix and key generated from trusted source, independently establish the public goal and genesis, and enforce the terminal admission rule. The harness reads its matrix from a verifier-owned local export; dimension checks alone do not authenticate arbitrary prover-supplied matrices. The hosted gate pins matrix/key bytes across its own reproducible artifacts.

Carriers for Eq currently inhabit `Sort 1`; motives have three concrete universe instances. General universes, arbitrary inductive declarations and positivity checks, quotients, eta, native proof irrelevance and complete Lean import remain outside the implemented relation. The source exporter establishes checks for this finite corpus under Lean's kernel. A formal soundness proof for the custom relation, hardened external parsing, proof privacy, production key distribution, and Bitcoin settlement remain separate milestones. All work in this gate uses CPU runners.
