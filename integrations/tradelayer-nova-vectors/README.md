# tradelayer-nova-vectors

Reference data for the zero-dependency Nova verifier in
[TradeLayer-Rust](https://github.com/patrickdugan/TradeLayer-Rust) (`src/zk_nova/`, profile
`PROFILE_PPSNARK_IPA_PASTA_V1`). TradeLayer-Rust admits no external crates, so the generator,
which links nova-snark 0.76.0, lives here and writes into its `fixtures/zk_nova`.

The Cargo.lock is copied from `nova-header-chain` (nova-snark 0.76.0, halo2curves 0.9.0, ff 0.13.1,
sha3 0.10.9, sha2 0.10.9, bincode 1.3.3); `rust-toolchain.toml` pins rustc 1.99.0. All randomness is
ChaCha20 seeded from `SHA-256("nova-vectors-0.76.0-seed-2026-11" || tag)`. The vectors are
reproducible; the proofs are not (Spartan blinding).

| binary | output |
|---|---|
| `gen_basic` | fields, curves, serialization, hash-to-curve |
| `gen_core` | generators, Keccak transcript, Poseidon |
| `gen_proofs [steps]` | the cubic test circuit (`z' = z^3 + z + 5`): registered key, proof, metadata. `NOVA_CUBIC_Z0` sets `z0[0]` (a binding element), `NOVA_CUBIC_NAME` the file prefix |
| `gen_trace <name>...` | every Poseidon squeeze and Keccak transcript operation of nova's own verifier on a stored proof |
| `gen_nhc1 <start> <k> <steps>` | the NHC1 header-chain circuit under the ppsnark CompressedSNARK; `NHC1_FIXTURES` = `integrations/nova-header-chain/fixtures` of `feat/cheap-btc-proofs` |
| `shape_probe` | R1CS sizes of a step circuit and the ppsnark key and proof sizes they imply |

```bash
cargo build --release --locked
NOVA_VEC_OUT=../TradeLayer-Rust/fixtures/zk_nova RAYON_NUM_THREADS=8 target/release/gen_basic
```

`NOVA_VEC_OUT` is required. TradeLayer-Rust's `ops/zk-staging` uses `gen_proofs` to make the
testnet4 staging proof.

`src/grain.rs` is copied from nova-snark and `src/h2c.rs` adapted from halo2curves; their licences
are in `THIRD_PARTY_LICENSES`.
