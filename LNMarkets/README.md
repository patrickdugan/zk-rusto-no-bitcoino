# LN Markets: private DLC batches

This folder prototypes a venue-side batch coordinator for privately exchanged
DLCs. Wallets co-sign a contract summary and later authorize an exact settlement
proposal. The native verifier checks those signatures and produces a 276-byte
journal. The active proof backend uses **Nova 0.76**, with Pallas/Vesta and M18's
Poseidon parameters, as a component for the repository's BitVM3 architecture.

The current Pallas relation, `lnmarkets/sha256-transcript-accounting/v2`, proves
SHA-256 of each fixed 600-byte signed transcript, binds the transcript's payout
amounts and funding outpoint to the accounting equations, and folds an ordered
commitment through at most 32 rows. Its local CLI saves a compressed proof and
verifies that file in a separate process against expectations prepared before
proving. [Nova documentation](nova/README.md) defines the precise statement,
commands and evidence.

A separate Secq/Secp circuit now proves one BIP340 signature inside R1CS.
The [verified local runs](nova/results/local-v2-2026-11-20.json) produced a
12,376-byte two-contract batch proof and an 11,980-byte single-signature proof.
The two relations still require a shared authorization bridge.

The native verifier still establishes the authority of the supplied signatures.
Summary serialization, oracle selection, Bitcoin transaction reconstruction,
nullifier paths and funding/spend validity remain outside the Pallas relation.
A receiver that accepts a proof without those claims also accepts their absence.
The prototype cannot authorize funded settlement on its own.

## Where the work lives

| Path | Purpose |
| --- | --- |
| [statement/](statement/src/lib.rs) | Native DLC summary, oracle, consent, transaction and replay verifier |
| [nova/](nova/README.md) | Active SHA transcript/accounting circuit, proof producer and independent file verifier |
| [PROTOCOL.md](PROTOCOL.md) | Native batch format and wallet/coordinator responsibilities |
| [VALIDATION.md](VALIDATION.md) | Earlier native/SP1 experiment record, with links to current Nova evidence |
| [SOURCES.md](SOURCES.md) | Source revisions and external references |
| [sp1/](sp1/README.md) | Historical standalone SP1 application experiment |

Each expensive backend has an isolated Cargo workspace. The default
`rust-bitcoin-zk-adapter` crate keeps its current dependency graph. The existing
M12–M15 BitVM3 path may use SP1 to shrink a final Nova verifier proof; its
integration with this application's eight-field state remains unfinished.

## Proposed venue integration

A venue could keep its quote and order system while adding a coordinator that
collects wallet-held DLC recovery material and signed summaries. Each wallet
checks its own original recovery package before signing the summary. At the
selected oracle outcome, the coordinator builds the settlement transaction and
asks both parties for fresh consent to that exact proposal.

The receiver needs the independently accepted batch context and selected
contract set before accepting any proof. Consuming authorization state must be
atomic, with a defined policy for aborted signing, rejected transactions and
reorgs. The original contract's recovery path stays available until the
relevant Bitcoin funding output is spent.

This interface has not been connected to LN Markets' production backend. All
bundled fixtures use public test keys and synthetic outpoints. The experiment
has moved no customer funds.

## What the native verifier checks

| Check | Binding |
| --- | --- |
| Summary consent | Two BIP340 signatures over a salted summary containing the outpoint, keys, scripts, payout root, oracle event, timeouts and package digests |
| Funding template | UTXORef's NUMS-keyed Taproot output with a two-party CET leaf and CSV refund leaf |
| Selected outcome | SHA-256 payout membership and two distinct signatures from three pinned oracle keys |
| Amounts | Exact integer conservation of trader, maker, anchor and fee amounts |
| Batch consent | Fresh party signatures over the full context, exact transaction digest and old/new authorization roots |
| Replay state | Full 256-bit sparse nonmembership/update paths keyed by the funding outpoint |
| Accepted set | Unique sorted outpoints and the exact selected-summary root |
| Receiver context | Retained epoch, batch ID, selected set, old root, transaction digest and height window |

The binary witness parser accepts 1–32 rows within 512 KiB. Identical payout
scripts aggregate into one output. Every funding outpoint still needs a
Bitcoin input and a valid spending witness when the transaction is broadcast.

## Run locally

From the repository root, using a current stable Rust toolchain:

```sh
cargo test --locked --manifest-path LNMarkets/nova/Cargo.toml --all-targets -- --test-threads=1
CARGO_BUILD_JOBS=2 cargo build --locked --release --manifest-path LNMarkets/nova/Cargo.toml --bin lnm-nova
mkdir -p LNMarkets/.local/nova-v2
RAYON_NUM_THREADS=2 LNMarkets/nova/target/release/lnm-nova prepare 2 --out LNMarkets/.local/nova-v2/expected.json
RAYON_NUM_THREADS=2 LNMarkets/nova/target/release/lnm-nova prove 2 --compressed --out LNMarkets/.local/nova-v2/bundle
RAYON_NUM_THREADS=2 LNMarkets/nova/target/release/lnm-nova verify --bundle LNMarkets/.local/nova-v2/bundle --expect LNMarkets/.local/nova-v2/expected.json
```

Output paths must be new. Retain `expected.json` through a trusted preparation
path. Copying expectations supplied by an untrusted prover grants that prover
control over the accepted statement. `--witness FILE` can replace a fixture
count when a wallet exporter supplies the bounded native witness format.

The separate native example remains available:

```sh
cargo run --locked --release --manifest-path LNMarkets/statement/Cargo.toml --bin lnm-native -- demo --rows 2 --out LNMarkets/.local/native-2
cargo run --locked --release --manifest-path LNMarkets/statement/Cargo.toml --bin lnm-native -- verify --witness LNMarkets/.local/native-2/witness.bin --journal LNMarkets/.local/native-2/journal.bin
```

## Privacy, Taproot and proof composition

The coordinator sees the private witness it assembles. Nova's compressed
Spartan/IPA proof uses the library's random-instance folding path for hiding;
see [Nova's description](https://github.com/microsoft/Nova). The exported bundle
contains the compressed proof and public statement material. Recursive
checkpoints and private rows stay out of the bundle. The public journal reveals
batch count, aggregate amounts, state roots and transaction commitments.
Broadcast Bitcoin transactions expose their ordinary inputs and outputs.

An existing `SIGHASH_DEFAULT` CET signature binds its original transaction.
A combined settlement therefore requires fresh Bitcoin signatures for the
combined transaction, as specified by
[BIP341](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki).

[Shinigami](https://github.com/starkware-bitcoin/shinigami) is a Cairo Bitcoin
Script engine. This repository's [M17 experiment](../integrations/bitvm3-nova/m17/README.md)
currently covers legacy/P2SH/witness-v0 execution. Taproot, BIP341 and the actual
UTXORef adaptor/refund path require a further extension. M18 funding evidence
must refer to exactly the same outpoints and authenticated Bitcoin tip.

The next authorization work is to prove BIP340 against the keys committed by
the contract summary, recompute the signed messages, and bind that proof to
the same ordered rows as the Pallas batch. A later M12 verifier needs a new
pinned verifier key and the application's state layout before BitVM3 can check
the result. The application proof also needs a constrained replay transition
and a funded transaction acceptance test.

The native statement and historical SP1 guest use the repository's MIT
license. The Nova integration is GPL-3.0-only, following its M18 dependency.
