# ZKL-08: actual Nova frontend calibration candidate

This isolated Rust executable pins nova-snark 0.76.0. It uses the library's narrow Poseidon sponge and scalar circuit gadget (domain-tagged leaves and nodes). It implements an original finite Horn proof-DAG relation, with a four-row public hypothesis table authenticated by its root. It does not copy zkLean code, use Groth16, or implement Lean's full typing relation.

State: [rule root, goal, memory root, cursor, last atom]. The verifier must reconstruct the public rule root, canonical empty memory root and zero cursor/last atom, pin depth/maximum arity and circuit parameters, check the exact step count, and check the expected terminal goal. A receipt is derivability relative to the provided rule hypotheses. Current fixture only uses 0/1/2 premise rules, 16-bit atom IDs, and a two-level rule tree. No arbitrary input parser or Bitcoin settlement. Finalization is a host check over the verified output; fixed padding and zero knowledge of the witness are separate unimplemented requirements. In particular the recursive proof/state and deterministic roots must not be sold as private theoremhood.

Run:
```sh
cargo run --release --manifest-path integrations/zkl-nova-calibration/Cargo.toml -- --calibrate
cargo run --release --manifest-path integrations/zkl-nova-calibration/Cargo.toml -- --fold
# optional, heavier; not required by the initial CI
cargo run --release --manifest-path integrations/zkl-nova-calibration/Cargo.toml -- --compress
```

Calibration synthesizes actual step constraints with Nova ShapeCS and checks assignments with its TestConstraintSystem, depths 4/8/12, max arities 0/1/2 (9 shapes). The padded max-arity-two fixture tests facts, unary rules, binary rules against the same shape. It attacks rule fields/membership, out-of-range indices, forward reference, premise path, append path, environment root, old root and cursor. The empty-slot check and new leaf update reuse the identical allocated siblings and index bits. Compare the raw step count with augmented primary/secondary counts from actual PublicParams. Constraint counts and elapsed timings are emitted only by running the backend. CI has a 15 minute cap, two compilation/Rayon threads and a 240 s proving timeout. No actual run results are claimed until CI succeeds.

--fold runs the 3-step fixture through RecursiveSNARK::new, prove_step, verify, and checks output and wrong step-count/initial input negatives. --compress additionally requests Spartan/IPA compression, with its own setup/prove/verify timings. No Groth16 wrapping. No proof privacy claim. Before relying on a proof, independently audit the constraints and add randomized differential checks, domain/encoding pins and a stronger terminal/padding statement.
