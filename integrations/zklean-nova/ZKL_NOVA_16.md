# ZKL-NOVA-16: checked certificate deduplication and Nat/iota arithmetic

2026-11-25. Native optimization, expanded sparse R1CS synthesis, authenticated all-tag sample, and the full 2,047-row Nova and Spartan hosted run PASS. Both repaired predecessor circuits (13 and 14) have now passed all 957 assignments, four recursive proofs, four compressed proofs, and their respective verifier mutation gates.

## Verified predecessor results

- Shared paths: https://github.com/patrickdugan/zk-rusto-no-bitcoino/actions/runs/45600068432 (head 8fec08ae48298492333e6d3df538d6ce057a4303).
- Shared paths plus append frontier: https://github.com/patrickdugan/zk-rusto-no-bitcoino/actions/runs/45600216526 (head ecaaa297b788d436c2017066eb2134d6324b163c).
- Native Nat conformance: https://github.com/patrickdugan/zk-rusto-no-bitcoino/actions/runs/45600561055.

Exact hosted receipts: nova13_hosted_receipt.json and nova14_hosted_receipt.json. The repaired matrices have 897,078 and 822,076 canonical sparse terms. No constraint or wire-count changes were made in the canonicalization repair.

| Architecture | Primary augmented constraints | VK bytes | Compressed bytes | Dependent application mean fold (s) | Compression (s) | Compressed verify (s) |
|---|---:|---:|---:|---:|---:|---:|
| Independent (12) | 52620 | 58415656 | 11312 | 0.344267 | 13.011001 | 0.264605 |
| Shared paths (13) | 48054 | 53500576 | 11312 | 0.252123 | 10.151064 | 0.208772 |
| Frontier (14) | 45317 | 50508776 | 11600 | 0.315311 | 14.688496 | 0.292169 |

Frontier uses fewer augmented primary constraints and a smaller VK, but the observed fold, compress, and verify times are slower than 13. These are separate hosted runners, not controlled same-machine measurements. The frontier state also has nine more public coordinates and a 288-byte larger compressed payload. Both gates passed; retain both circuits. Prefer shared paths for the current observed speed baseline; benchmark both on the same host before deciding whether to retain the frontier for production. The frontier relation is used in 16 as a tested architectural option, not an empirically established speed winner.

## Certificate optimization

```sh
node integrations/zklean-nova/nat_optimize.cjs
node integrations/zklean-nova/nat_optimize.cjs --fixtures
```

Deduplicate in topological row order. For every tag, explicitly enumerate reference positions, remap them to accepted earlier rows, and validate the entire candidate with the native checker before deciding whether to retain it. Exact mode interns identical remapped row records. Semantic mode interns the checker-derived record: term constructor and child IDs, context parent/type, lookup context/level/type, instantiation source/index/replacement/result, conversion endpoints, or judgment context/subject/type. Equivalent conclusions can reuse an earlier validated justification. Distinct terms and contexts are not identified solely by universe or scope metadata. Keep the last judgment as the terminal row even if an identical conclusion appeared earlier. Then traverse the explicit dependency graph backward from the final judgment, retain its ancestors, remap every reference, and replay the resulting certificate. Derived references follow the explicit term and prior-judgment dependencies.

| Fixture | Original | Exact | Semantic | Pruned |
|---|---:|---:|---:|---:|
| polymorphic_identity | 52 | 33 | 33 | 33 |
| dependent_application | 340 | 133 | 133 | 133 |
| beta_conversion | 276 | 92 | 90 | 88 |
| impredicative_predicate_identity | 289 | 113 | 113 | 113 |
| nat_zero | 4 | 4 | 4 | 4 |
| nat_recursion | 350 | 218 | 206 | 193 |
| iota_zero_type | 376 | 224 | 211 | 193 |
| iota_succ_type | 528 | 275 | 252 | 227 |
| dependent_nat_elimination | 1865 | 556 | 549 | 538 |
| prop_nat_elimination | 1863 | 543 | 536 | 525 |
| Total | 5943 | 2191 | 2127 | 2047 |

All three optimized versions replay against the original theorem, with exact original proof AST parity and independent de Bruijn reference acceptance. All ten wrong-goal controls and 1,931 self-references into optimized certificates fail. Total pruning saves 3,896 rows (65.56%). Maximum certificate length falls from 1,865 to 538, allowing a depth-ten tree (1,024 rows) rather than depth eleven (2,048 rows). No proof-term reduction or new logical principle is used. This pass is validated on the fixed corpus, not a proven optimal compression algorithm.

## New authenticated arithmetic circuit

Extend the original 25 tags with C=26, JK=27, VZ=28, VN=29. Preserve old numerical tags and existing term/node domains. Increase the record field width from ten to eleven bits and use a distinct leaf domain for the new encoding. Fourteen record fields plus the row address occupy 165 bits, strictly below the Pasta field modulus. Counts and addresses fit the revised history capacity; sort and variable bounds retain the prior semantic limits.

- C(id): constrain id in [0,5] and zero scope metadata. Constants are inert atoms under locally nameless opening. Their term digest is H(term_domain+26,id,0).
- JK(ctx,constant,type): authenticate the context and both terms. Check the constant tag and bounded ID. Select exactly one of six constant signature digests from the verifier-owned syntax using equality flags. Bind the selected signature to the authenticated type term digest. No witness-provided environment or structural equality Boolean is admitted.
- VZ(lhs,rhs): authenticate both endpoints, the three partial application nodes, the recursor head, and the zero scrutinee (seven historical reads). Require a recursor ID 3..5, zero constant ID 1, and the exact base argument as RHS.
- VN(lhs,rhs): authenticate both endpoints, the three partial application nodes, recursor head, successor scrutinee and constructor, and the two RHS applications (ten historical reads). Require successor constant ID 2 and exact predecessor references in App(App(step,n),App(rec_partial,n)). Preserve the conversion endpoint metadata and locally closed conditions.

All read addresses, including derived references, are constrained to the specified row fields and are strictly earlier than the current count. The existing shared-path authenticator binds the historical record, digest and salt to the prior history root. The append-frontier relation updates the history root and ten frontier slots. Initial state is pinned to (empty depth-ten root, zero count, independently hashed public goal, unsealed, ten zero frontier slots). Final admission requires a sealed empty-context typing judgment whose type digest equals the pinned goal. The Nat signature digests are generated from fixed syntax at matrix synthesis, and the Rust verifier recomputes them from its own fixed environment table using native Poseidon. Production requires independently pinned verifier-owned matrix/key and authenticated genesis; do not accept prover-selected matrices.

| Metric | Observed synthesis |
|---|---:|
| Rule tags | 29 |
| Record fields / bits | 14 / 11 |
| Historical read capacity | 10 |
| History depth / capacity | 10 / 1024 |
| Poseidon hashes | 97 |
| Hash equations | 30264 |
| R1CS constraints | 38298 |
| Wires including ONE | 37236 |
| Canonical sparse terms | 935196 |
| Recursive state arity | 14 |

The Rust bridge adds 28 state bindings, giving an expected 38,326 explicit constraints before Nova recursion overhead. The sample checks 36 assignments across all ten optimized certificates, spanning 28 tags. Deduplication removes all VL (lambda-congruence) rows from this corpus. Retain the original 276-row beta fixture as a coverage-only control; check its first VL assignment with the expanded matrix, without including it in the 2,047-row folding corpus. This yields 37 sampled matrix assignments covering all 29 tags. All 2,047 native history transitions and the supplementary coverage trace agree with the independently updated reference tree and extracted frontier. All 1,024 boundary insertions pass. The complete trace contains 7,834 raw reads, 6,930 unique within-row addresses and 39,981 actual shared parent nodes before padding.

40 targeted assignment/goal mutations and 106 regenerated-input attacks rejected. The latter include eight signature-digest corruptions checked specifically against the constant-type constraints, four iota result-reference mutations, and 94 inherited memory/frontier attacks. Iota result corruption changes the raw referenced result index and regenerates auxiliary assignments; it is a targeted control, not an exhaustive coordinated forgery search. All observed samples use the same canonical matrix.

## Hosted gate and reproducibility

```sh
node integrations/zklean-nova/nat_optimize.cjs > /tmp/nat-opt.json
diff -u integrations/zklean-nova/nat_optimized_results.json /tmp/nat-opt.json
node integrations/zklean-nova/nat_frontier.cjs
node integrations/zklean-nova/nat_frontier.cjs --full /tmp/nat-frontier-fixture
cargo +1.90.0 run --release --manifest-path integrations/zklean-nova/nova-smoke/Cargo.toml --bin nat_frontier -- /tmp/nat-frontier-fixture /tmp/nat-frontier-proof
```

The full exporter checks all 2,047 optimized assignments, streams canonical 32-byte field wires to individual files, and checks the supplementary VL coverage sample. The Node CLI verifies the pinned Poseidon parameter fixture hash; the local connector run used the repository-pinned fixture and checked profile identity. Rust independently recomputes all six public signature digests, public goal digest and initial root with native Nova 0.76.0 Poseidon. One shared public parameter set and Spartan/IPA key are used for ten derivations. The verifier binds every initial-state coordinate, verifies the complete and unsealed prefix endpoints, checks altered states and counts, and uses another distinct supported goal for statement mutation (two certificates have the same Nat goal, so simply picking the next fixture would be incorrect). Expected mutation gate: 16 altered statement/count checks for each recursive proof and 16 for each compressed proof, 320 in total. Retain each proof receipt and payload, shared VK, artifact hashes, dependency lockfile, and peak RSS. Run in a bounded 60-minute CPU-only workflow, two build/Rayon threads. No paid GPU allocation. The full cryptographic gate passed on hosted CPU run [45603149771](https://github.com/patrickdugan/zk-rusto-no-bitcoino/actions/runs/45603149771), source head `3c6d21d95bf2c0f2ca075dab8dda7bfb5ace689a`. The audited receipt is `nova16_hosted_receipt.json`. All ten recursive and compressed proofs verified, all 320 altered statement/count checks failed, and 20 malformed-step checks failed. The primary augmented circuit contains 49,711 constraints and the secondary circuit 10,349. The shared verifier key occupies 55,034,496 bytes; every compressed proof occupies 11,632 bytes. Generation took 364.56 seconds with peak RSS 865,800 KiB; the Rust proof process took 665.86 seconds with peak RSS 621,016 KiB. Artifact hashes, source endpoints and individual receipts were checked against the uploaded artifact.

## Limits and next gate

Pinned Nat at three universe instances is a trusted primitive environment; arbitrary inductive declarations, positivity checking, indexed families, general universe polymorphism, eta/proof irrelevance, quotients and complete Lean import remain unsupported. The native certificate generator expands ASTs; no production hardened parser, formal soundness proof, proof privacy audit, or Bitcoin settlement is claimed. After the full hosted gate, compare shared-path and frontier architectures on the same host and add equality/transport or a small separately checked inductive family with a positivity gate. The compressed certificate is a proof of admission by this restricted relation, not a Lean kernel certificate.
