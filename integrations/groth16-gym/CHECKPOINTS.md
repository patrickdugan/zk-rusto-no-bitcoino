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

## 15 GB DDR4 Windows benchmark: 4 × 32 headers

The experiment targets mainnet heights **959617–959744** (128 headers in one difficulty epoch). It proves one 32-header batch, simulates an interruption, resumes for the remaining three batches, and then verifies the full bundle.

**Why 32-header batches.** A 64-header proof does not fit a 15 GB laptop. Under an OS-enforced limit (`RESULTS.md`), committed memory is about 0.33 GiB per header, so 64 headers needs about 20.6 GiB. The MSI's 10.4 GB figure for 64 headers was a trimmed working set on a 31 GB machine. 32 headers needs about 10.3 GiB.

From the repository root on the Windows laptop with Rust/MSVC installed:

```powershell
powershell -ExecutionPolicy Bypass -File integrations/groth16-gym/run-checkpoint-ddr4.ps1 -CapMB 13000
```

The driver builds the standalone gym and guards the checkpoint process at 13,000 MiB peak working set, sampled every 250 ms. It appends host memory, per-phase wall time, peak working set, exit status and over-cap flags to `integrations/groth16-gym/.proofs/ddr4-<chunk>/ddr4-benchmark.jsonl`. The guard is a sampled user-space check of a figure Windows can trim, not an OS-enforced limit. Close heavy applications before the trial.

### Measured on an i5-11400H (12 threads, 23.8 GB), 2026-11-04

Raw receipts are in `results/subhanallah-checkpoint-20261104.jsonl`. The 15 GB laptop itself is still untested.

| Batch size | Phase | Result | Time | Peak working set |
| --- | --- | --- | --- | --- |
| 64 | first-batch | stopped by the 13,000 MiB guard; nothing sealed | 17 s | 13.0 GB |
| 32 | first-batch | 1 batch proved, verified and sealed | 98 s | 10.1 GB |
| 32 | resume | batch 1 re-verified; batches 2–4 proved and sealed | 367 s | 10.1 GB |
| 32 | verify | all 4 proofs and their links accepted | 0.3 s | under 0.1 GB |

Peak memory was the same for one batch and for three batches in one process, so it does not build up between batches. 128 headers took about 7.7 minutes in total, about 122 s per 32-header batch including setup.

GitHub CI exercises two one-header batches and does not run this PowerShell driver.

## Proof and memory constraints

- Each batch performs setup, proving, and verification with at most `--chunk-size` headers. Peak memory follows the batch circuit and did not build up across batches in one process (see above). Choose the chunk size from about 0.33 GiB of committed memory per header (`RESULTS.md`).
- The binary accepts up to **64 headers per batch**, which needs about 20.6 GiB. The driver defaults to 32.
- Setup uses the gym's fixed-seed RNG, which exposes toxic waste. These proofs are **benchmark-only** and never suitable for securing money.
- Proofs are compressed BN254 and are verified using arkworks. The separate verifying key for each circuit is saved beside the proof.
- Each batch is identified by `batch_<start>_to_<end>/` with `proof.bin`, `vk.bin`, and `checkpoint.json`. The manifest seals a complete batch and is written after proof verification. SHA-256 digests detect accidental corruption, and the verifier rejects invalid public statements.
- The verifying key is read from the batch directory and checked only against that directory's own manifest. It is not pinned to the header circuit. Someone who can write the directory can replace a batch with a verifying key and proof for a different circuit that has the same seven public inputs, and `verify` will accept it. To close this, pin the expected verifying-key digest for each batch size, or regenerate it from the circuit.
- The checkpoint scheme is not suitable for a trusted remote checkpoint registry without separately authenticating the root statement and consensus parameters. The fixture-grounded verifier here checks the exact known public statement for each batch.

For actual **single-proof recursive aggregation**, the next step is a dedicated folding or recursion verifier circuit over these batch proof statements, with sound setup and final compression. That work must retain the same anchored state transition, nBits/target semantics, and public end-state. Adding hashes to a manifest provides no recursive cryptographic soundness.

## CI

The gym's independent workflow builds the binary, runs checkpoint tests, proves two one-header batches, repeats to verify recovery, and checks that tampering causes failure. This is separate from the default protocol-neutral crate. Full 4/8/16/32/64-header benchmarking remains a manual run.