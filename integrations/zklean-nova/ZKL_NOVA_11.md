# ZKL-NOVA-11: fixed arithmetic dependent calculus and authenticated proof admission

2026-11-25. ZKL-NOVA-09 hosted Spartan compression PASS; ZKL-NOVA-10 hosted native reproduction PASS. ZKL-NOVA-11 local arithmetic relation PASS on all 957 certificate rows. Authenticated matrix synthesis and six sampled transitions PASS in the JavaScript sandbox. Complete 52-step recursive/compressed dependent theorem proof submitted for hosted CI, not yet observed.

## Verified predecessor

https://github.com/patrickdugan/zk-rusto-no-bitcoino/actions/runs/45585771216

The three admitted derivations and the unsealed prefix each compressed to 11,032 bincode bytes, using one 27,222,208-byte verifier key. Uncompressed recursive object: 2,424,952 bytes (219.81x compression). Compression took 9.024–9.288 seconds and verification 0.1879–0.1893 seconds. All 28 changed initial-state/step-count tests failed verification. The prefix verified cryptographically and was refused by the admission predicate. The proof and VK serialization round trips succeeded. Full copied job receipt: nova09_hosted_receipt.json. This is the restricted implicational circuit, not a proof of full Lean or a demonstrated privacy wrapper. The prior ZKL-NOVA-10 native dependent conformance run 45586290210 also succeeded.

## Arithmetic row relation

The same matrix checks 25 native certificate tags with six term constructors, contexts, lookups, instantiations, conversion and typing judgments. Encode a record with fourteen ten-bit fields: numeric tag 1..25, eight zero-padded syntax arguments, exact free and loose variable bounds F/G, context depth, and two conversion endpoint IDs. Unused fields are constrained to zero. Each logical rule uses a fixed ordered list of up to ten required historical record addresses (including derived references). One-hot rule flags bind each active address to the exact reference expression; active addresses are strictly earlier than the current index. Inactive records and addresses are zero. Every used historical record is constrained to the required kind. The local arithmetic relation takes the historical payloads as inputs: soundness here is conditional on their actual authentication and prior admission.

Maxima are enforced by bounded differences and a product-zero equation. Sort imax uses the zero test on the codomain universe. Scope checks enforce G=0 and F<=context depth for subjects and types. Instantiation checks the local substitution rule and explicit earlier child instantiations. Binder congruence checks a common fresh free level, domain/body conversions, and the two openings. Judgment rules verify earlier context, typing, conversion and instantiation records, including derived type/extended-context references. Terminal theorem identity is addressed by the integrated digest below, not assumed from an arbitrary row ID.

Observed local matrix:
- 3,412 equations, 2,647 wires, 13,954 sparse terms, 165 external witness inputs.
- 957/957 valid row assignments across four native fixtures.
- 1,030/1,030 targeted corruptions rejected (self/forward read indices and forged free-level scope metadata); 8/8 direct auxiliary wire mutations rejected.
- Fixed shape by construction: one sparse matrix object reused for every assignment. The full per-rule read-count histogram is in dependent_arithmetic_results.json.

## Authenticated integration

Use a depth-six append-only sparse Merkle tree with empty leaf zero; the initial root is independently computable. The state is (history_root, occupied_count, public_goal_digest, sealed). Each step begins unsealed, proves an empty leaf at the current index, authenticates all rule-selected historical records against the old root, checks the local relation, writes exactly one new row, increments count, and preserves the goal digest. It may set seal only on a typing judgment in the empty context whose type digest equals the pinned public goal.

The bounded record and ten-bit address are injectively packed into a 150-bit integer, then committed with the term digest and salt by one width-six Poseidon sponge permutation over four absorbed field elements [leaf_domain,packed_record,digest,salt]. Node hashes use a distinct domain with two payload elements. Nonzero active leaves distinguish occupied from empty positions. Historical salts, digests and paths are authenticated in the leaf commitment; inactive slots must be zero. Fixture salts are deterministic and provide no hiding. Real prover witnesses require fresh randomness and an explicit privacy policy.

The term digest is computed at admission: for atomic terms, hash [term_domain+tag,scalar,0]; for pairs/binders/applications, hash [term_domain+tag,left_digest,right_digest]. Child digests come from the exact authenticated term references. All nonterm rows have zero term digest. This binds the goal structurally, independently of the prover's choice of row IDs. The verifier computes the public theorem digest recursively from its trusted syntax, pins the empty genesis and requires a sealed verified final state. Security relies on collision resistance, canonical field encodings, a sound arithmetic relation and a trusted matrix/VK; no untrusted prover can select the relation.

The authenticated circuit includes 84 fixed Poseidon calls: one term digest, ten times seven hashes for read leaf and six path nodes, and one append leaf plus two six-node paths. At 312 multiplications per hash:
- 29,906 equations, 29,114 wires including ONE, 718,374 sparse terms.
- Six deterministic sampled row assignments of the 52-row identity trace checked in the sandbox (indices 0,1,3,9,25,51).
- 13 malformed assignment/goal mutations rejected.
- Full native commitment trace contains 53 linked endpoints from empty root to sealed identity.
- Complete all-52 integrated R1CS check and actual Nova execution are hosted gates, not observed yet.

Pinned public theorem: Pi(Sort 1, Pi(B 0, B 1)), i.e. forall A : Type, A -> A. Depth six has 64-row capacity. The proof fixture uses 52 appended rows. The other three dependent fixtures exceed this capacity, so only the local logical relation was checked for them.

## Hosted run

```sh
node integrations/zklean-nova/dependent_arithmetic.cjs
node integrations/zklean-nova/dependent_arithmetic.cjs --auth-sample
node integrations/zklean-nova/dependent_arithmetic.cjs --auth-fixture /tmp/dependent-fixture
cargo +1.90.0 run --release --manifest-path integrations/zklean-nova/nova-smoke/Cargo.toml --bin dependent -- /tmp/dependent-fixture /tmp/dependent-proof
```

The Node entry point pins the full Poseidon parameter-file SHA-256; the local connector sandbox used the pinned repository fixture and profile identity. The Rust bridge will independently check node/leaf vectors and reconstruct the empty root and goal digest with Nova's native sponge, check all 52 assignments against the same matrix, fold 52 steps, verify and refuse the unsealed 51-step prefix, verify the final sealed result and test changed genesis/state/count. It also attempts Spartan/IPA compression, serialization round trips, and mutated verifier input rejection. Expected explicit Rust step size: 29,914 constraints before recursion overhead. The CI job records actual timings, primary/secondary sizes, proof/VK bytes and peak RSS; execution is capped at two threads and twenty minutes. All actual proof results for the dependent circuit remain pending hosted evidence.

## Limits and decisions

Use independent Merkle paths for this first dependent integration, preserving the semantic baseline before adapting the earlier shared-path/frontier optimization. The circuit checks a bounded calculus-of-constructions fragment, not Lean's full kernel. Structural term equality for the public goal is hash-based; local premises still require exact row IDs. No inductives, universe polymorphism, quotients, proof irrelevance, eta, or full Lean import are implemented. No formal soundness proof, privacy audit, production verifier or Bitcoin settlement claim. No paid GPU allocation.
