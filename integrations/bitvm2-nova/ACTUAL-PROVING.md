# Actual Nova proving with k-sized folds and aligned shards

This optional Windows coordinator enables real proving with the existing header
prover. Here **k is the number of headers per Nova fold**, which determines the
circuit size and its memory floor. Shard count, concurrency and Rayon threads
are separate controls. More folds extend a shard; they do not increase k.

The backend is the unchanged header package at revision
`de607d3db17d400dd6c2923d357f1d4a7bf233c7`, Nova 0.76.0, Pallas/Vesta and
transparent Spartan/IPA compression. No trusted setup is introduced. Original
prover defaults, the k=5 retained fixture and its verifier gates remain intact.
This is a separate fresh-proof path, not a relabeling of retained test evidence.

## Prepare and build

Run from this integration directory, with new source/cache/target directories
inside your workspace:

```powershell
python prepare_proving.py --owned-parent C:\your-workspace --source-root C:\your-workspace\nova-source
$env:CARGO_HOME='C:\your-workspace\nova-cargo'
$env:CARGO_TARGET_DIR='C:\your-workspace\nova-target'
$env:CARGO_BUILD_JOBS='2'
$env:NOVA_CHAIN_SOURCE_COMMIT='de607d3db17d400dd6c2923d357f1d4a7bf233c7'
cargo build --release --manifest-path C:\your-workspace\nova-source\integrations\nova-header-chain\Cargo.toml --bin nova-chain --bin btc-header-fold
```

The preparer downloads only 49 pinned package files, about 1.7 MB. It authenticates
the literal package Git tree `382633db86c5540500db8b8653b7996e5dd26448`, every
blob/mode/size and SHA-256, then independently rehashes the materialized package.
Existing directories and symlink/reparse paths are refused. Interrupted or failed
source markers prevent the proving coordinator from using that preparation.
The generated dependency lock is separately recorded and explicitly not Git-pinned.

Use the CPU backend. The validated pilot build admitted Nova features `default`
and `io`; EVM, test-utils and blitzar/GPU features were absent. The Nova crate
checksum was independently checked against
`c9bb3809a6c70057ea722c1c4fe5097cf29a3479d0b4671f3cddb1d81043bb31`.
The executables are operator-configured trusted programs. Their file hashes,
source identity and actual generated lock are audit records; source hashing is
not remote attestation that an arbitrary executable was compiled from it.

## Prove a small genuine shard set

```powershell
python proving_shards.py --source-root C:\your-workspace\nova-source `
  --bin-dir C:\your-workspace\nova-target\release `
  --out results\proving-k10-example --k 10 --to 40 --shards 2 `
  --parallel 1 --export-parallel 1 --threads 2 --memory-mib 6144
```

This uses the committed testnet4 headers from genesis. It produces shards
`(0,20]` and `(20,40]`, each with two k=10 folds. Each new shard deliberately
saves its first fold, then resumes with verification of the saved accumulator.
Both k and network stay fixed through a continuation. Outputs must be a fresh
directory beneath `integration/results`; prior runs are never silently skipped.
The CLI currently admits k=1..64, matching the upstream bundle decoder.

`--parallel` bounds active fold processes and `--export-parallel` bounds active
compression processes. Every child is created suspended, assigned to a Windows
Job Object, then resumed in a hidden window. Both process and aggregate job
committed-memory ceilings are enforced; closing the job kills descendants.
Wall time and combined stdout/stderr byte budgets are enforced too. Shared
cancellation stops active and queued tasks on errors or interruption.

The initial available-memory check requires all concurrent job ceilings plus
a six-GiB host reserve. It refuses insufficient capacity before starting a child;
it never silently changes k. Reduce concurrency explicitly when other programs
consume available RAM. This is a preflight capacity check, not a reservation
against memory use by unrelated applications. Job commit limits and queried
working-set peaks are distinct metrics.

## What is actually verified

The coordinator performs the existing native circuit/Core-fixture differential
check, then calls the real prover. `nova-chain export` verifies the compressed
SNARK and its complete native end state before writing an NHT4 bundle. Each
fresh bundle is subsequently cold-verified by `btc-header-fold verify-bundle`.
The actual bytes, proof hash, source/header identity, network, k, step count,
requested height range and all 17 canonical state scalars are checked.

Known testnet4 k=5 and k=10 keys must match their existing independent pins.
For other admitted k values the cold verifier reconstructs its key from the
trusted circuit; a proof-supplied key is not accepted as authority. Full-state
continuity includes epoch difficulty and MTP history, not only height/tip/work.
The first shard must start at the pinned genesis state, and every following
initial tuple must equal the preceding proven end tuple exactly.

The result is a **verified multiproof set**, not a recursively merged SNARK.
Only this invocation's freshly generated, coordinator-owned artifacts enter
the legacy native decoder in capped processes. Arbitrary third-party serialized
proof intake still needs the separate structural admission work. Existing
retained mathematical-conformance APIs intentionally continue to reject these
new proof identities.

`verified.json` is written only after all proofs and their joins pass. Process
failures, upstream panics, resource limits and incomplete process accounting are
failures; they never count as proof rejection evidence. Failure reports keep
their scope distinct. Ordinary Windows Job notifications are best effort, so the
observer retains process handles promptly and still fails closed if accounting
cannot be completed. Accumulators contain witness material and are not published
as zero-knowledge artifacts. Raw keys/continuations/logs remain in ignored outputs.

## Limits of this milestone

The actual run's measurements must be recorded after successful completion.
No live Bitcoin node, active-chain selection, wallet, transaction, signature,
broadcast or deployment is part of this fixture-based proving experiment.
Native Nova proof validity does not complete the BitVM2 Script verifier:
authenticated sponge/proof-byte linkage, remaining verifier composition,
production assertion/key lifecycle and the Bitcoin transaction graph stay open.
