> **Current work:** [Nova v2 local receipts](nova/results/local-v2-2026-11-20.json) record verified Pallas transcript and separate Secq BIP340 proofs, with independent persisted Pallas verification. The [Nova guide](nova/README.md) describes current commands and scope. This file preserves the earlier native/SP1 record; its historical status labels belong to those experiments.

# Validation record

Recorded on 2026-11-20 against repository base
`a183eeffe63715cedca729100a1f74267a68200d`. The new shared relation passed
native tests and release-mode examples. Its status is
**`native_verified_unproved`**. The local SP1 proof run is deferred.

## Native checks

The standalone statement passed:

```sh
cargo fmt --manifest-path LNMarkets/statement/Cargo.toml -- --check
cargo check --locked --manifest-path LNMarkets/statement/Cargo.toml --lib --no-default-features
cargo test --locked --manifest-path LNMarkets/statement/Cargo.toml --all-targets
cargo clippy --locked --manifest-path LNMarkets/statement/Cargo.toml --all-targets -- -D warnings
cargo build --locked --release --manifest-path LNMarkets/statement/Cargo.toml --bin lnm-native
```

The suite contains **18 passing tests**: nine relation tests, eight
independent adversarial tests and one internal sparse-tree test.

| Area | Evidence |
| --- | --- |
| Schnorr semantics | Published BIP340 valid/invalid vectors and rejection of an additional message hash; all six per-row signatures individually tampered |
| Taproot derivation | Concrete UTXORef NUMS/template vector and independent `rust-bitcoin::TaprootBuilder` result |
| Transaction binding | Independent rust-bitcoin deserialization and txid calculation, expected inputs/outputs/sequence/locktime, and false-digest rejection |
| Hidden payout commitments | Changed path/index/amount cases, repeated oracle messages at incompatible indices, conservation and bounded amounts |
| Accepted set | Canonical order, missing rows, modified accepted root and altered final authorization root |
| Replay/context | Fresh signatures over stale contexts, duplicate outpoint under changed salt/ID, replay across epochs, wrong domains and externally retained journal pins |
| Sparse paths | Independent top-down reconstruction of full 256-bit roots and paths, with shared prefixes and both branch directions |
| Parsing | Truncation, trailing bytes, wrong magic, oversized frames, impossible row counts and noncanonical membership depth |

Each adversarial test that changes signed context deliberately refreshes
the appropriate fixture signatures where needed. This allows it to reach
the targeted constraint instead of stopping at an unrelated stale signature.

## Native baseline

The [machine-readable report](results/native-baseline.json) contains the
actual summaries, exact journal bytes, witness/transaction hashes,
statement-source hashes and compiler/CPU metadata. These numbers came from
one release-mode verification per batch size on the current workspace.
They exclude signing the fixture, compiling code and running a zkVM.

| Contracts | Private witness bytes | Public journal bytes | Unsigned transaction bytes | Native verification |
| ---: | ---: | ---: | ---: | ---: |
| 1 | 9,446 | 276 | 180 | 0.888 ms |
| 2 | 18,704 | 276 | 221 | 1.747 ms |
| 8 | 74,252 | 276 | 467 | 7.288 ms |
| 32 | 296,444 | 276 | 1,451 | 28.623 ms |

The demo uses three leaves per payout tree and the same payout scripts
across rows, so these examples aggregate into three outputs. A real batch
with distinct recipient scripts produces more outputs. Full 256-sibling
nullifier paths account for 8,192 bytes of each private row; later witness
compression can be evaluated separately from proof size.

Every persisted witness passed a separate native CLI invocation against
its saved expected journal:

```sh
LNMarkets/statement/target/release/lnm-native demo --rows 1 --out LNMarkets/.local/native-1
LNMarkets/statement/target/release/lnm-native verify --witness LNMarkets/.local/native-1/witness.bin --journal LNMarkets/.local/native-1/journal.bin
```

The same commands ran for 2, 8 and 32 rows. The committed report retains
public fixture metadata. Generated witness files and local run directories
are ignored by Git.

## Prover preparation

The guest and host are separate Cargo workspaces. Their lockfiles retain
SP1/slop 6.9.0 throughout. The guest's ordinary host-architecture `cargo
check` passed; this validates Rust compilation for the current host.
Building the RISC-V ELF and executing it remain steps for the later local
run. The shared relation also compiles with its native fixture/CLI feature
disabled and excludes the unused `k256/std` feature.

The optional host and its resumable binary passed a locked host-architecture
check with two build jobs. This workspace supplied `protoc 31.1` through a
local `grpcio-tools` installation, using `PROTOC` and `PROTOC_INCLUDE` for
the dependency build. Reproduce with those variables pointing to a local
Protocol Buffers compiler and its include directory:

```sh
cargo check --locked --manifest-path LNMarkets/sp1/program/Cargo.toml -j 2
cargo check --locked --manifest-path LNMarkets/sp1/host/Cargo.toml --all-targets --features resumable -j 2
python3 -m unittest discover -s LNMarkets/scripts -p 'test_*.py' -v
```

Both optional workspaces also passed `cargo fmt --check`. The compiler
reported an upstream `proc-macro-error2` future-compatibility notice; the
checks completed successfully. The dependency audit found ten SP1/slop
packages in the guest lock and 47 in the host lock, all pinned to 6.9.0.

The standard-library Python runner passed **11 tests** covering read-only preparation,
exact pin/file checks, byte limits, preserved existing outputs, compressed
execution/verification ordering, transitive version drift and release
circuit configuration. The runner prints commands until an explicit
action is invoked with `--run`.

The host requires an external ELF hash, program verification-key pin and
exact expected journal/digest. It invokes SP1's real cryptographic verifier,
checks proof mode and successful execution, and requires release circuit
artifacts. Private trace-dump settings are rejected or cleared by the
appropriate entry point. Independent source review covered these guards.

Actual ELF/program-key pins, guest cycle counts, final proof size, proving
time, peak memory and proof-verifier timings await the local experiment.
The 276-byte journal and native timing table supply no measurement of
those quantities. The final Groth16 path starts from the original witness;
importing a resumable compressed checkpoint into that wrapper remains
future work.

## CI and source provenance

[LN Markets batch statement](../.github/workflows/lnmarkets-batch.yml)
runs formatting, native tests, Clippy, the guest-compatible library check,
runner tests and the four native demos. It uploads only the public native
JSON summaries. Expensive proving remains an explicit local action.

The prior UTXORef Core regtest report was read as source evidence. This task
did not repeat that chain rehearsal, import its private keys or produce a
funded batch transaction. Its exact revision and the upstream cryptographic
references are retained in [SOURCES.md](SOURCES.md).
