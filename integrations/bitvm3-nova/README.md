# bitvm3-nova: a Nova verifier in BitVM3

The BitVM3 route for verifying this repository's Nova header-chain proofs (`NHT4`/`NHC1`
bundles, `integrations/nova-header-chain` keys). It replaces the BitVM2 route in
[`../bitvm2-nova`](../bitvm2-nova/README.md), which is paused.

The route: the pinned Nova 0.76.0 verifier runs inside SP1 (guest A), SP1's compressed proof is
shrunk and wrapped with BLAKE3 Merkle trees and transcript, and that final proof's verifier is a
fixed Boolean circuit that is garbled and evaluated.

| Directory | What it holds |
| --- | --- |
| root crate (`src/`, `tests/`) | M1–M11: verifier kernels, transcripts, sumcheck and Spartan chains, R1CS conformance, cost envelope |
| [`m12/`](m12/README.md) | Final-proof feasibility: guest A (complete Nova verifier in SP1) and control C (header transitions in SP1), measured; native and SP1 hosts |
| [`m13/`](m13/README.md) | SP1's wrap program proved with BLAKE3 (transcript v1 and v2); the native final verifier and its exact operation counts; the pins (`m13/pins.json`) |
| [`m14/`](m14/README.md) | The complete M13 final verifier as one garbled circuit (785,442,492 gates), checked against SP1 on real proofs, garbled and evaluated |
| [`m15/`](m15/README.md) | Guest A with the verifier key in raw form: 21.2 × 10^9 SP1 instructions instead of 72.3 × 10^9, same statement |
| [`m16/`](m16/README.md) | One SP1 guest for the mainnet header chain from genesis plus an SPV payment; proved on mainnet (tip 975,072, payment at 975,067) on the laptop GPU, wrapped, and accepted by the plain and garbled M14 circuit |
| [`m17/`](m17/README.md) | Bitcoin Script (legacy, P2SH, witness v0) as a Nova step circuit, following Shinigami's engine; agrees with Core on all 2,756 non-Taproot vectors |
| [`m18/`](m18/README.md) | A windowed UTXO map (indexed Merkle tree, Poseidon) folded in Nova over mainnet blocks H..T, sealed at T and bound to the M16 tip, for balance proofs; segmented folding and its verifier |
| [`prover/`](prover/README.md) | `nb3-prove`: resumable, disk-backed SP1 6.9 proving on one machine (CPU provers) |
| [`prover-gpu/`](prover-gpu/README.md) | `nb3-prove-gpu`: the same prover on SP1's CUDA provers, sized for GPUs below 24 GB |

## Where it came from

Developed in `nova-bitvm3/` on `patrickdugan/garbled-snark-verifier` (a fork of BitVM's
garbled-snark-verifier) and copied here at commit
`8fa7efe495ea1bd4675f9c8bbd29f0b6e8bee051`, so the work lives in this repository rather than in
the fork. Paths written `nova-bitvm3/...` in the documents below mean this directory. M15–M17
were copied from the fork on 2026-11-10 and M18 on 2026-11-11 (fork commit 9069761); their
crates are standalone workspaces and do not depend on the fork.

The circuit crates (the root crate, `m12/gates`, `m14/circuit`, `m14/e2e`) build on the
garbled-circuit framework of `garbled-snark-verifier`. They depend on it by git at that same
commit hash, which names the exact tree; nothing else in this directory depends on the fork.

CI: `.github/workflows/bitvm3-nova*.yml`, ported from the fork with paths rewritten.

## License

The crates here are GPL-3.0-only, as each `Cargo.toml` declares (the repository root is MIT).
`prover/src/node.rs` adapts SP1's local node (MIT/Apache-2.0); `prover-gpu` builds on SP1's GPU
crates (MIT/Apache-2.0).
