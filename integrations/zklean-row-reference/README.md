# ZKL-04: native authenticated row reference

Original finite Horn proof-DAG relation inspired by the local certificate design in [zkLean](https://github.com/rain-1/zero-knowledge-lean/tree/d5279fcfb0f3583bc98dd04f0ae57256c6821f46). Upstream has no declared license; no upstream code is copied. The parallel proof-search pilot is [DataGoblin PR 67](https://github.com/MoralityLabAI/DataGoblin/pull/67).

Run `cargo test --manifest-path integrations/zklean-row-reference/Cargo.toml`. The Rust test includes hash vectors independently produced in a local Python implementation. The Python run accepted 256 fresh generated valid instances and rejected 10 targeted attacks. The Rust toolchain was unavailable in the assistant sandbox, so the Rust code and test have not been compiled or run; CI and review are required. The Rust test is a narrower fixture than the Python pilot.

## Relation

An ordered, versioned environment binds atom count, goal, memory depth, and every rule (head, arity, premises). Initialize with an empty Merkle tree. Authenticate each premise at an earlier index under the old root. Require the next append slot to be empty, update it to the derived atom, increment the cursor, and permit finalization only on the public goal. Finalization is valid only over a verified transition chain beginning at the canonical initial state. Sharing and unused valid rows are allowed. SHA-256 roots are native commitments, not zero-knowledge proofs.

## Nova-only gate

A future folding step circuit must bind the canonical environment root and goal, authenticate rule selection under a committed rule table, constrain range and index bits, enforce exactly the selected transition, and constrain both read paths and the append path. A fixed arity-two step uses at most four Merkle traversals (two reads, old empty leaf check, new leaf update), each depth d. At d=8 this is 32 parent hashes, plus leaf and rule authentication. Use a field-friendly, domain-separated hash with reviewed parameters for the eventual circuit; do not substitute it without a new encoding and test vectors.

Specify public input/state commitments and fixed padding before claiming witness privacy. Final acceptance requires the actual IVC verifier, correct initial state, valid finalization, and explicit step-count bounds. No Groth16 wrapping is planned. This integration does not implement Nova, Lean, Mathlib, or a BitVM3 settlement condition. Application-specific Bitcoin settlement remains out of scope. Keep the native reference optional and independent of the main crate. Before upgrading scope, add property-based malformed input tests, multiple proof instances, circuit/native equivalence, constraint accounting and a benchmark of the actual Nova proof path. Preserve the trusted environment elaboration boundary for full dependent types.
