# ZKL-NOVA-12: shared depth-nine dependent theorem circuit

2026-11-25. ZKL-NOVA-11 hosted recursive and compressed dependent identity PASS. ZKL-NOVA-12 expanded matrix and sampled authenticated assignments PASS. Full 957-row, four-proof shared-key run submitted for hosted verification; the expanded proof results remain pending.

## Verified predecessor

Run https://github.com/patrickdugan/zk-rusto-no-bitcoino/actions/runs/45590203470, job 139122083899, source head 82fb7704a0bdd0b84bb84a5d65a02093d1e3cec0.

The 52-row proof of forall A : Type, A -> A folded and compressed successfully. The raw logged receipt is nova11_hosted_receipt.json. Explicit step constraints: 29,914. Primary/secondary Nova constraints: 41,289/10,349. Setup: 3.653 seconds. Recursive verification: 0.2077 seconds. Recursive payload: 3,610,264 bytes. Spartan compression: 9.333 seconds; compressed verification: 0.1853 seconds. Compressed payload: 11,312 bytes. Verifier key: 46,352,416 bytes. All 6 malformed-step checks, 6 recursive verifier mutations and 6 compressed verifier mutations rejected. Native node/leaf, public goal and empty genesis parity passed; the unsealed prefix was refused admission; proof serialization round trip passed. These are hosted measurements, not extrapolations.

## Expanded circuit

Depth 9 supports 512 rows per proof. The 25-rule local arithmetic relation, ten historical read slots, fourteen ten-bit record fields, canonical term digest, and four-field recursive state are unchanged. Independent Merkle paths remain the authentication baseline. Every active record is bound to its actual earlier address and the old history root. Each append proves an empty leaf at the current count and updates the root. Terminal admission requires an empty-context judgment whose type digest matches the verifier's independently computed public goal. No cross-proof history sharing; each proof starts at the same depth-nine empty root with its own public goal.

One fixed sparse matrix (41,237 equations; 40,448 wires including ONE; 1,019,955 sparse terms; 120 Poseidon calls, 37,440 hash equations) is synthesized and used for all four witnesses. The Rust step adds eight recursive state bindings, so its expected explicit size is 41,245 constraints before Nova overhead.

The native witness generator now maintains all levels of a sparse-prefix tree and updates exactly nine ancestor nodes after each insertion. Prior openings are constructed before modifying the tree. The leaf and term commitment definitions and pinned Poseidon profile are unchanged. The new empty root follows from nine identical-child node hashes. These implementation changes do not alter the cryptographic relation or remove its fixed authentication slots.

## Observed local gate

| Fixture | Rows | Authenticated sample checks | Targeted mutations rejected |
|---|---:|---:|---:|
| polymorphic_identity | 52 | 16 | 4 |
| dependent_application | 340 | 3 | 4 |
| beta_conversion | 276 | 8 | 4 |
| impredicative_predicate_identity | 289 | 1 | 4 |
| Total | 957 | 28 | 16 |

The deterministic sample includes the first occurrence of each of the 25 rule tags across the corpus and the terminal judgment of every proof. Every checked assignment satisfies the same synthesized matrix. All 957 native commitment transitions were generated with linked endpoints; the sample is not a full cryptographic check of all 957 assignments. Each terminal mutation test changes the goal consistently at both state endpoints or changes an authenticated sibling, salt, or output root. All were rejected.

## Hosted gate

```sh
node integrations/zklean-nova/dependent_scale.cjs
node integrations/zklean-nova/dependent_scale.cjs --full /tmp/dependent-scale-fixture
cargo +1.90.0 run --release --manifest-path integrations/zklean-nova/nova-smoke/Cargo.toml --bin dependent_scale -- /tmp/dependent-scale-fixture /tmp/dependent-scale-proof
```

The full Node exporter checks all 957 assignments and writes each canonical field assignment as a separate fixed-width little-endian binary file (32 bytes per wire). Assignment storage is 1,238,679,552 bytes in total before matrix and metadata. The exporter does not retain the whole corpus of assignments in memory. The Rust verifier reconstructs each public goal from hardcoded mathematical syntax, independently derives the empty history root, checks native Poseidon vectors, and uses one verifier-generated matrix, one pair of Nova public parameters, and one shared Spartan/IPA verifier key. It reads witnesses one step at a time, checks each with the actual frontend, folds and verifies the unsealed prefix and the sealed final state, then compresses each proof. Cross-goal substitutions use another actual supported goal, rather than only arbitrary scalar corruption. Require six recursive and six compressed verifier rejections per case, plus two malformed-step refusals per case. Save individual receipts immediately and retain the four compressed proof payloads, shared VK, lockfile, payload hashes and peak RSS. A 45-minute CPU-only CI job with two build/Rayon threads and a bounded Node heap is used for this larger run. No GPU allocated.

Expected proof sizes, timing, peak memory and cross-goal rejection counts for this expanded shape are not observations until hosted receipts are available. The verifier must pin the trusted matrix or resulting VK; generated fixtures and assignment files are experimental inputs, not a hardened untrusted file interface.

## Boundaries and next gates

The largest certificate has 340 rows; this is a capacity step, not Mathlib scale. The pilot has no inductives, universe polymorphism, quotient types, proof irrelevance, eta or full Lean import. Deterministic fixture salts are not hiding, and the privacy claim for a compressed theorem proof is still unestablished. The earlier multiproof/frontier work is not yet integrated into this dependent circuit. Once the hosted expanded run passes, compare actual fixed-shape constraint counts and folding costs for independent paths versus authenticated shared paths, with identical 25-rule semantics and statements. Then extend the kernel, starting with public constants and checked inductive reduction. No production or Bitcoin settlement claim.
