# ZKL-NOVA-06: two-step recursive membership smoke test

2026-11-25. Matrix fixture export and 05 regression PASS in the JavaScript sandbox. Rust bridge and hosted Nova run SUBMITTED; uncompiled locally, cryptographic result pending CI. Keep PR #35 draft.

## Fixture

Run `node integrations/zklean-nova/r1cs.cjs --nova-fixture > fixture.json`. The ordinary CLI remains unchanged; its complete 05 receipt matched exactly in the sandbox. The export uses the same pinned width-6 Poseidon profile and packed D=4,K=5 circuit. An actual sparse matrix and three assignments were generated and checked with identical shape: 4,470 rows, 4,368 wires including ONE, 105,209 sparse terms. JSON length before trailing newline: 9,231,273 ASCII bytes. Historical tree has 11 occupied leaves with field digests i+1 and zero padding. Native root decimal:
`28444383152523492001806863032623493205850027174127485938082587742772458775681`.
Hash vector H(19,42):
`3189450979416672123379718128033158450810174494458308961147039301746121343378`.

Batches [0,1,10,1] and [2,4,6,8,10] contain nine active requests, with one repeated address in the first batch. Each request is an activity/index/digest triple; inactive slots are zero. Third assignment is an empty batch, used as a negative control. This tests membership only, with a synthetic tree. The generator exports trusted build-time matrices; the verifier must regenerate from checked-out source or authenticate an independently pinned matrix hash. Never accept a remote prover's choice of matrix as an assertion of membership. Parameter SHA-256 is checked by the Node entry point in CI.

## Rust bridge

`nova-smoke` uses nova-snark=0.76.0, Pallas primary/Vesta secondary, Vesta base/Pallas scalar field, and the same frontend interfaces as BitVM3 M17/M18. It independently recomputes the hash vector and root using Nova's native narrow sponge. It translates every sparse matrix row into a ConstraintSystem enforcement. Wire zero is CS::one; all remaining assignment wires are allocated privately. Public inputs of the JS membership relation are now constrained against the 33-field recursive state (root, occupied count, counter, two immutable 15-field request vectors).

Enforce counter Boolean, bind root/count, select every expected request component with the same counter, and constrain every output state field (only counter changes by +1). Expected explicit step count: 4470+1+2+15+33=4521 constraints before Nova's augmented-circuit overhead. Setup uses the exact same matrix across steps. Verification must use two steps and exact z0 and expected z2, which pins both nonempty required batches and prevents an empty-read witness or a one-step completion from satisfying the claim.

A Rust CheckCS checks two honest assignments and nine malformed steps (empty, wrong batch/replay, finished counter, altered S-box witness, changed root/count/request). The intended proof experiment folds two steps, verifies the endpoint, tests six altered verifier inputs/step counts, serializes the RecursiveSNARK and checks its round trip. The receipt will report actual primary and secondary augmented constraint counts, setup/fold/verify timings, uncompressed bincode proof size and max RSS from /usr/bin/time. No compressed proof or hiding wrapper is attempted. Host CI is capped at two build/Rayon threads and 20 minutes. The local environment has no Rust toolchain and no access to the dependency registry; these Rust outcomes are gates, not observed successes.

Reproduce after generating fixture:
```
cargo +1.90.0 run --release --manifest-path integrations/zklean-nova/nova-smoke/Cargo.toml -- fixture.json
```

## Next gate

Inspect hosted CI and resolve compile or parity errors before reporting a recursive proof. Then connect committed row encodings and the append frontier to every semantic reference, bind genesis and the final typing judgment. Pinned public request schedules in this smoke test deliberately reveal reads; an actual private theorem certificate requires a different state binding and explicit hiding policy. No Lean conformance, private theoremhood, production hash-security audit, or Bitcoin settlement is claimed. No GPU spend.
