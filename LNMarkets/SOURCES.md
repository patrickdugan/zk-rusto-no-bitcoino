# Sources and claim boundaries

Reviewed on 2026-11-20. Repository links pin the source revisions used for
this prototype. Current upstream documentation may describe later releases;
the optional guest and host use SP1 6.9.0 and retain matching transitive
versions in their lockfiles.

## Existing work

| Source | What it supplies here |
| --- | --- |
| [ZK repository base a183eeff](https://github.com/patrickdugan/zk-rusto-no-bitcoino/tree/a183eeffe63715cedca729100a1f74267a68200d) | Protocol-neutral sidecar, isolated proof integrations and repository guidance |
| [M16 SP1 integration](https://github.com/patrickdugan/zk-rusto-no-bitcoino/tree/a183eeffe63715cedca729100a1f74267a68200d/integrations/bitvm3-nova/m16/sp1) | Existing SP1 6.9.0 integration and reviewed dependency family |
| [Resumable prover](https://github.com/patrickdugan/zk-rusto-no-bitcoino/tree/a183eeffe63715cedca729100a1f74267a68200d/integrations/bitvm3-nova/prover) | Local compressed-proof checkpoint pipeline, reused through the optional LNMarkets host feature |
| [M17 Script/Nova milestone](https://github.com/patrickdugan/zk-rusto-no-bitcoino/blob/a183eeffe63715cedca729100a1f74267a68200d/integrations/bitvm3-nova/m17/README.md) | Existing Script execution work and its explicit Taproot scope boundary |
| [UTXORef original LNMarkets prototype efe8d30d](https://github.com/patrickdugan/UTXO-Ref/tree/efe8d30d3739373ec4db33cf7c27e3cd78f34e6e/LNMarkets) | Original bilateral contract/recovery interface and digest pins |
| [UTXORef regtest revision f3ed53ff](https://github.com/patrickdugan/UTXO-Ref/tree/f3ed53ffe233af2de5376a482f12a84cdc95fa2e/LNMarkets) | Later funding and recovery work on the same draft PR; read as source evidence during this task |
| [Recorded Core rehearsal](https://github.com/patrickdugan/UTXO-Ref/blob/f3ed53ffe233af2de5376a482f12a84cdc95fa2e/LNMarkets/REGTEST_REPORT.md) | Reports two funded regtest UTXOs and separate CET/refund exits, including Core rejection cases and wallet/state checks; this run was not repeated for the new ZK relation |
| [UTXORef funding template](https://github.com/patrickdugan/UTXO-Ref/blob/f3ed53ffe233af2de5376a482f12a84cdc95fa2e/dlc_funding_output.js) | Public NUMS derivation and exact two-party Taproot template used for compatibility |
| [UTXORef contract binding](https://github.com/patrickdugan/UTXO-Ref/blob/f3ed53ffe233af2de5376a482f12a84cdc95fa2e/LNMarkets/src/contract.js) | Existing package construction and plan/recovery digest context; the new guest treats those original digests as opaque references |

The UTXORef regtest implementation uses its own actual package validation
and Bitcoin execution guards. This folder builds a new authorization
envelope and proves its own explicitly defined relation. A wallet exporter
connecting the two formats remains work for a later iteration.

## Cryptography and proof backend

| Primary source | Use |
| --- | --- |
| [BIP340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki) and [official vectors](https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv) | Schnorr signature semantics and independent known-answer tests |
| [k256 0.13.4 verifying code](https://github.com/RustCrypto/elliptic-curves/blob/k256/v0.13.4/k256/src/schnorr/verifying.rs) | `verify_raw` verifies the intended digest without adding a message hash |
| [BIP341](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki) | Taproot output construction and transaction signature commitments |
| [SP1 6.9.0](https://github.com/succinctlabs/sp1/tree/v6.9.0) | Guest/host API and verifier behavior for the pinned backend |
| [SP1 security model](https://docs.succinct.xyz/docs/sp1/security/security-model) | Individual STARK proofs currently lack a zero-knowledge guarantee; the final Groth16/PLONK wrappers supply hiding under their stated assumptions |
| [SP1 proof types](https://docs.succinct.xyz/docs/sp1/generating-proofs/proof-types) | Distinction between core/compressed and final proof modes; generic advertised sizes are not measurements for this program |
| [SP1 precompiles](https://docs.succinct.xyz/docs/sp1/optimizing-programs/precompiles) | Potential later acceleration; patches must match the selected SP1 version and require new program pins |

The statement implementation is independently written Rust under the
repository's MIT license. It uses mature curve/hash implementations.
`rust-bitcoin` is a development dependency for independent transaction and
Taproot cross-checks. The guest currently uses upstream `k256`/`sha2`; no
accelerator patch has been applied merely to reduce a projected cycle count.

## Shinigami composition

[Upstream Shinigami](https://github.com/starkware-bitcoin/shinigami) describes
a Cairo Bitcoin Script VM and transaction execution/proving system. The
local M17 milestone derives from related Script semantics and explicitly
leaves Taproot for later work. A correct future composition must establish
the exact spend statement, common transaction/prevout commitments and
pinned verifier identities.

UTXORef's earlier
[virtual-CET proof corpus](https://github.com/patrickdugan/UTXO-Ref/blob/f3ed53ffe233af2de5376a482f12a84cdc95fa2e/bitvm3/utxo_referee/shinigami/shinigami_virtual_cet_proof_corpus.js)
has recorded STWO artifacts for a limited arithmetic predicate. Its helper
mixes field values using `31*a + 17*b + 7`; replacing `(a,b)` with
`(a+17,b-31)` leaves that value unchanged modulo the field. This function
therefore cannot serve as a collision-resistant commitment. Those artifacts
also do not establish verification of the original parties' BIP340
signatures or a real SHA-256 Merkle path. This prototype implements those
checks directly in the new shared relation. Historical proof results have
not been rerun or independently verified during this task.

## LN Markets integration assumptions

The public [LN Markets organization](https://github.com/ln-markets) provides
the original research context. This folder proposes an internal
integration around bilateral contract records. It assumes a cooperating
venue, wallets and oracle adapters capable of signing the newly specified
messages. Public code supplies no evidence that LN Markets has adopted
this interface. Fee levels, open interest, trading volume and traction are
outside the claims of this prototype.
