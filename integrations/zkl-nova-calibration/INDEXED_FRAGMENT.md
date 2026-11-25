# ZKL-15: dependent predicate instantiation in Nova

This is a bounded affine-index fragment, extending the earlier ground Horn circuit. A rule is either a ground fact/rule or a public hypothesis of the form forall n : Nat, P_i(n + k_i) -> ... -> P_h(n + k_h). Two predicate families are distinguished by one low bit in a packed 16-bit atom. Offsets are nonnegative. A canonical rule row binds the bound flag, arities, predicate families and offsets under a domain-separated Poseidon commitment. The prover supplies one 15-bit natural witness n per step. All instantiated atoms are separately constrained to 16 bits, and the same witness is used across the entire rule. Ground rules force n=0. Prior typed facts authenticate against the proof memory; the last derived atom must match the public goal.

The fragment gives substitution and equality of canonical affine natural indices by exact bounded arithmetic. It does not check arbitrary lambda terms, general dependent types, syntax-level beta/iota certificates or Lean elaboration. A source adapter must independently establish that the normalized rule table faithfully represents its source. No witness privacy or Bitcoin settlement claim. Public parameters and the canonical initial state must be reconstructed and pinned by the verifier. Domain tags differ from the ground circuit.

Fixture: P(3), forall n, P(n) -> Q(n+1), forall n, P(n) -> Q(n+1) -> P(n+2). The honest derivation instantiates n=3 and establishes P(5). A fourth schema exercises the packed upper boundary. Targeted malformed witnesses include inconsistent binders, out-of-range binders, changing the authenticated bound flag, ground rule with nonzero binder and coherent overflow under an authenticated boundary rule.

Run:
    cargo run --release --manifest-path integrations/zkl-nova-calibration/Cargo.toml --bin indexed -- --calibrate
    cargo run --release --manifest-path integrations/zkl-nova-calibration/Cargo.toml --bin indexed -- --compress

The existing ground baseline remains unchanged. The workflow runs nine shapes, honest fixtures, negative cases, and compressed Nova/Spartan IPA verification. Results are pending CI; do not quote unmeasured counts or privacy claims. Next add cross-language variable-size rule-table transport, Lean replay of exported certificates, then an explicit term/substitution relation for the next fragment. This scope is independently reviewable before extending toward general dependent type theory.
