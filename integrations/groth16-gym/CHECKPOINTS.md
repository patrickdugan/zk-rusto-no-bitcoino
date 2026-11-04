# Resumable bounded-RAM Groth16 header proving

This is the home for the header-chain checkpoint experiment in `zk-rusto-no-bitcoino`, using the existing native arkworks BN254 `groth16-gym`.

The new `checkpoint_headers` binary proves **independently verified small consecutive header batches** and resumes from a verified checkpoint. Each batch contains a genuine Groth16 proof, verification key, and a manifest binding the adjacent batch, range, proof digest, verifying-key digest, and public statement. On restart the program cryptographically verifies all earlier proofs and checks that they form an unbroken header chain before continuing.

It is a **proof bundle**, not a recursive SNARK or a single succinct proof of the full chain. The reference fixture anchors ranges to known mainnet headers. Consensus validity is limited to the gym's existing within-epoch chaining, SHA256d and fixed-target PoW checks. This does not establish retargets, median-time-past, version rules, or canonical-chain selection.

## Build and run

From repository root:

```sh
cargo build --release --manifest-path integrations/groth16-gym/Cargo.toml --bin checkpoint_headers
integrations/groth16-gym/target/release/checkpoint_headers prove .proofs/groth16-headers \
  --start 959617 --end 959632 --chunk-size 2
```

Run the same command after an interruption. Sealed batches are independently verified from their Groth16 proof and vk. A missing seal causes that batch to be regenerated. A corrupt or mismatched seal is an error and stops recovery. After the target height has been proven, repeating the command is an idempotent verification pass.

Limit the number of newly generated batches to exercise restart:

```sh
integrations/groth16-gym/target/release/checkpoint_headers prove .proofs/groth16-headers \
  --start 959617 --end 959632 --chunk-size 2 --max-new-chunks 1
integrations/groth16-gym/target/release/checkpoint_headers prove .proofs/groth16-headers \
  --start 959617 --end 959632 --chunk-size 2
integrations/groth16-gym/target/release/checkpoint_headers verify .proofs/groth16-headers \
  --start 959617 --end 959632 --chunk-size 2
```

## 15 GB DDR4 Windows benchmark: 64 + 64 headers

The prior native arkworks header gym completed a 64-header proof on this class of machine. The two-batch checkpoint experiment targets mainnet heights **959617–959744**, staying inside one difficulty epoch. It will generate two independent 64-header proofs, simulate an interruption after the first checkpoint, resume the second, and then verify the full bundle.

From the repository root on the Windows laptop with Rust/MSVC installed:

```powershell
powershell -ExecutionPolicy Bypass -File integrations/groth16-gym/run-checkpoint-ddr4.ps1 -CapMB 13000
```

The driver builds the standalone gym, guards the checkpoint process at 13,000 MiB peak working set (sampled at 250 ms), and appends host memory, per-phase wall time, peak working set, exit status, and over-cap flags to `integrations/groth16-gym/.proofs/ddr4-64/ddr4-benchmark.jsonl`. If the first attempt exceeds the guard or causes memory pressure, run a **fresh output directory** with `-ChunkSize 32`, e.g. `-OutputDir C:\temp\groth16-32`. A sampled user-space guard is not an OS-enforced memory limit. Close heavy applications before the trial.

The 15 GB machine benchmark is a pending physical-device trial. GitHub CI exercises two one-header batches and does not establish RAM or runtime for 64-header batches on DDR4.

## Proof and memory constraints

- Each batch performs setup, proving, and verification with at most `--chunk-size` headers. The peak allocated prover data should scale with each batch circuit, although Rust's allocator may retain freed memory across batches inside the same process. The Windows trial measures this behavior. Use the existing `RESULTS.md` measurement to choose a feasible chunk size.
- The current cap is **64 headers per batch**. A larger cap needs fresh memory benchmarking.
- Setup uses the gym's fixed-seed RNG, which exposes toxic waste. These proofs are **benchmark-only** and never suitable for securing money.
- Proofs are compressed BN254 and are verified using arkworks. The separate verifying key for each circuit is saved beside the proof.
- Each batch is identified by `batch_<start>_to_<end>/` with `proof.bin`, `vk.bin`, and `checkpoint.json`. The manifest seals a complete batch and is written after proof verification. SHA-256 digests detect altered artifacts, and the verifier rejects invalid public statements.
- The checkpoint scheme is not suitable for a trusted remote checkpoint registry without separately authenticating the root statement and consensus parameters. The fixture-grounded verifier here checks the exact known public statement for each batch.

For actual **single-proof recursive aggregation**, the next step is a dedicated folding or recursion verifier circuit over these batch proof statements, with sound setup and final compression. That work must retain the same anchored state transition, nBits/target semantics, and public end-state. Adding hashes to a manifest provides no recursive cryptographic soundness.

## CI

The gym's independent workflow builds the binary, runs checkpoint tests, proves two one-header batches, repeats to verify recovery, and checks that tampering causes failure. This is separate from the default protocol-neutral crate. Full 4/8/16/32/64-header benchmarking remains a manual run.