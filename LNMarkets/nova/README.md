# LNMarkets Nova prototypes

The active batch relation is **`lnmarkets/sha256-transcript-accounting/v2`**.
It uses Nova 0.76 over Pallas/Vesta, with M18's Poseidon sponge. Each step hashes
an exact private signed transcript inside R1CS and binds its outpoint and
amounts to the accumulated settlement state. A separate Secq/Secp circuit
verifies a BIP340 signature over a 32-byte message.

These are separate proof statements. The current batch proof needs native
signature validation and independently prepared expectations. Combining the
signature circuit with the batch requires proving signer membership and signed
message derivation against the same contract records. Bitcoin spending and
BitVM3 final verification remain further integration work.

## Current Pallas statement

The native [batch verifier](../statement/src/lib.rs) checks all six BIP340
signatures per contract, the selected payout membership, two-of-three oracle
policy, UTXORef Taproot template, SHA256 replay transition and exact unsigned
Bitcoin transaction. It returns the 276-byte journal used by this experiment.

The Nova circuit now recomputes SHA256 of the **600-byte signed-row transcript**
using the existing SHA gadget. That transcript contains the summary and batch
consent digests, party and oracle signature bytes, outcome data and funding
outpoint. Exact byte constraints tie the payout amounts, outcome index and
outpoint to the same allocated values used in accounting and Poseidon. Each
step has a fixed shape independent of witness values.

Eight field elements carry the batch state:

| Index | Meaning |
| ---: | --- |
| 0 | Count, incremented by a literal one; at most 32 steps |
| 1 | Total collateral |
| 2 | Total trader, maker and anchor payouts |
| 3 | Total miner fee |
| 4 | Poseidon chain of signed transcript digests and economic fields |
| 5, 6 | SHA256 of the native journal, split into 128-bit limbs |
| 7 | Epoch |

Row amounts fit 51 bits. Conservation and bounded 56-bit running totals prevent
field-wrap ambiguity. The journal hash halves and epoch carry unchanged. The
receiver reconstructs the initial commitment and checks the final count and
amounts against its independently pinned journal.

The summary and batch-consent digests inside the transcript still need their
own derivation proof. The Pallas circuit commits the signature bytes but does
not establish signature validity. It also leaves outcome/nullifier membership,
transaction serialization, funding and spendability outside R1CS.
[SOUNDNESS.md](SOUNDNESS.md) gives the exact byte offsets and trust boundaries.

## Separate BIP340 relation

[src/bip340.rs](src/bip340.rs) uses Nova's existing secp256k1 ECC gadgets over
the Secq scalar field. It constrains canonical x-only public keys, curve
membership, even-y lifts, `s < n`, the tagged SHA256 challenge and
`sG − eP`. The resulting point must be finite, have even y and match the
signature's canonical r. All 256 challenge bits enter scalar multiplication.

A one-step proof starts at `[0, 0, 0]` and outputs
`[1, claim_low128, claim_high128]`, where the claim commits to the exact key,
32-byte message and 64-byte signature. Its R1CS has 135,730 constraints,
including the claim hash. The test suite includes all 15 official BIP340
vectors for 32-byte messages, boundary scalars and a complete shape comparison.

The proving benchmark is explicit. Its report path, and the persisted-test
bundle path below, resolve relative paths from the repository root; absolute
paths are accepted unchanged. Existing receipts are preserved.

```sh
mkdir -p LNMarkets/.local
RAYON_NUM_THREADS=2 CARGO_BUILD_JOBS=2 LNM_BIP340_REPORT=LNMarkets/.local/bip340-proof.json cargo test --locked --release --manifest-path LNMarkets/nova/Cargo.toml --lib bip340::tests::real_recursive_and_compressed_signature_proof -- --ignored --exact --nocapture --test-threads=1
```

A signature proof under a supplied key does not establish that the key belongs
to the correct DLC party or oracle. The next bridge must open the canonical
summary, select its authorized keys and recompute each application message.
The Pallas and Secq commitments live in different fields; a composed verifier
needs an explicit common byte commitment or a constrained bridge.

## Prepare, prove and verify locally

Use a current stable Rust toolchain. A two-thread starting point keeps the
initial CPU experiment reproducible:

```sh
cargo test --locked --manifest-path LNMarkets/nova/Cargo.toml --all-targets -- --test-threads=1
CARGO_BUILD_JOBS=2 cargo build --locked --release --manifest-path LNMarkets/nova/Cargo.toml --bin lnm-nova
mkdir -p LNMarkets/.local/nova-v2
RAYON_NUM_THREADS=2 LNMarkets/nova/target/release/lnm-nova prepare 2 --out LNMarkets/.local/nova-v2/expected.json
RAYON_NUM_THREADS=2 LNMarkets/nova/target/release/lnm-nova prove 2 --compressed --out LNMarkets/.local/nova-v2/bundle
RAYON_NUM_THREADS=2 LNMarkets/nova/target/release/lnm-nova verify --bundle LNMarkets/.local/nova-v2/bundle --expect LNMarkets/.local/nova-v2/expected.json
```

Run from the repository root. Parent directories must exist; output paths must
be new. Fixture counts 1, 2, 8 and 32 are accepted. A wallet exporter can replace
the count with `--witness FILE`, using the bounded 512-KiB native format.
The command always native-validates a supplied witness before preparing or
proving. `trace ROWS` only calculates the native trace.

`prepare` retains the expected journal hash, exact initial/final state, step
count and verifier-key identity. Protect that file through a trusted workflow.
Accepting expectations copied from a received proof bundle lets its producer
choose the statement.

`prove --compressed --out` writes:

| File | Contents |
| --- | --- |
| `proof.bin` | Spartan/IPA compressed proof |
| `journal.bin` | Exact 276-byte public journal |
| `manifest.json` | Claim fields and proof integrity hash |
| `report.json` | Public measurements and explicit scope/status flags |

The compressed verifier key includes large R1CS matrices. Both processes
rebuild it from the compiled circuit, stream its serialization into SHA256 and
compare the retained identity. The bundle carries its hash and serialized
size. No private witness, recursive checkpoint or full verifier key is exported.

The separate `verify` process uses bounded parsers, checks the expected
statement and rebuilds the current verifier key before cryptographic
verification. It does not rerun source signature checks and reports that fact.
A malformed Nova structure returns an error even when upstream verification
would panic. Builds with `panic=abort` are rejected because they would bypass
that containment.

After generating a bundle, run the proof-aware corruption checks:

```sh
LNM_NOVA_BUNDLE=LNMarkets/.local/nova-v2/bundle cargo test --locked --release --manifest-path LNMarkets/nova/Cargo.toml --test persisted_artifact -- --ignored --test-threads=1
```

They reject truncated/trailing bytes and malformed internal sumcheck/evaluation
vectors constructed from the real compressed proof.

## Verified local runs, 20 November 2026

[Full receipts and source hashes](results/local-v2-2026-11-20.json) record the
actual CPU runs. Both the two-contract Pallas proof and the separate BIP340
proof passed recursive and compressed verification. Pallas also passed a new
verifier process using the saved proof and independently prepared expectations.

| Measurement | Pallas batch, two contracts | Secq, one BIP340 signature |
| --- | ---: | ---: |
| Compressed proof bytes | 12,376 | 11,980 |
| Recursive prove | 0.583 s | 0.184 s |
| Compression prove | 100.081 s | 66.751 s |
| Compressed verification | 1.708 s, separate process | 0.963 s |
| Setup before proving | 32.552 s | 10.195 s |
| Primary constraint count | 275,234 including Nova augmentation | 135,730 application step only |

The whole Pallas proving command took 137.905 seconds and peaked at 989,892 KiB
of RSS, about 967 MiB. Its cold independent verifier took 34.366 seconds,
including 32.605 seconds to rebuild the public parameters and verifier key.
The public bundle is 16,329 bytes including journal, manifest and JSON report.
Its deterministic verifier key represents 101,826,448 serialized bytes, which
are hashed locally instead of being shipped with the bundle.

The Secq benchmark test itself took 80.01 seconds. Its measured command also
included 46.89 seconds of release compilation and peaked at 734,676 KiB across
the command's process tree. Its receipt records a proof hash; this test does
not save a separate binary signature proof bundle.

These are single synthetic smoke measurements on a shared Linux workspace
with two Rayon threads. Some compilation overlapped the Pallas proving run.
The results establish functioning proofs for the stated relations; a timing
distribution and measurements on the user's hardware remain separate work.

There are 28 active tests and three explicit expensive tests. All were run
successfully, including two malformed-proof cases that deserialize correctly
but trigger upstream Nova vector-length assumptions. The report records the
initial receipt-path failure and its corrected rerun.

## Evidence and version changes

[The historical CI measurements](results/ci-2026-11-20.json) belong to the first
opaque-digest relation at `faad8aa27a1fb7b5b8ac5aabb72e4751f16ea8b5`. That
circuit produced real proofs, but a later review found unconstrained count and
domain witnesses and separate hash/accounting allocations. The new circuit
fixes those gaps and adds SHA transcript binding. Its verifier key differs.
The old 10,816-byte result and 1–32-row timings cannot establish v2 performance
or security. They remain in the repository as historical measurements.

Current checks cover assignment-level attacks, official signature vectors,
exact native/circuit transcript agreement and persisted proof handling.
[The workflow](../../.github/workflows/lnmarkets-nova.yml) runs a two-contract
persisted Pallas proof and a separate BIP340 proof. Its manual entry point can
select a larger batch. Public fixture artifacts are retained for seven days.

## BitVM3 integration work

The [M18](../../integrations/bitvm3-nova/m18/README.md) map and chain window
provide separate funding evidence that must refer to the same outpoints.
M17's current script experiment covers legacy/P2SH/witness-v0 rules; the
actual UTXORef Taproot spending path needs BIP341, adaptor/refund and fresh
batch-signature support.

M12's existing header verifier expects 17 state fields. This application uses
eight fields for the Pallas batch and three for the single-signature experiment.
A composite verifier requires new pinned verification keys, shared-input
constraints and the matching M12–M15 final verifier artifacts.

The standalone SP1 application code under [../sp1](../sp1/README.md) remains
historical research. SP1 may still shrink the final Nova verifier in BitVM3.
The active application proof work lives here.

This crate is GPL-3.0-only, matching M18. The native statement remains MIT.
