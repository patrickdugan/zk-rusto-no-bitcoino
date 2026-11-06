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
  --parallel 2 --export-parallel 2 --threads 2 --memory-mib 6144 `
  --total-memory-mib 16384 --reserve-memory-mib 2048
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

The total proving budget defaults to **16 GiB**, as authorized for this host.
Two concurrent six-GiB Job ceilings reserve at most 12 GiB inside that budget.
The initial available-memory check also requires a configurable two-GiB host
reserve. It refuses insufficient capacity before starting a child;
it never silently changes k. Reduce concurrency explicitly when other programs
consume available RAM. This is a preflight capacity check, not a reservation
against memory use by unrelated applications. Job commit limits and queried
working-set peaks are distinct metrics. `--plan-only` validates and prints the
source, shard plan and live budget without starting a child or creating output.

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

## Actual k=10 pilot

A fresh Windows run completed two actual compressed proofs covering testnet4
headers `(0,20]` and `(20,40]`. Both used k=10, two folds and two Rayon threads.
Each proof was 12,976 bytes; each complete NHT4 bundle was 13,532 bytes.
Both cold native verifications passed against the existing k=10 key pin
`2495da9bf5965030e45fa2cef1a43ade78e099ca844b5d3a9abf56400447eabe`.
The initial state was the pinned genesis state; all 17 canonical scalars at the
height-20 boundary matched exactly. The Core fixture differential check also
passed at every height 0–40. The total run took 1,304.8303272 seconds
(21 minutes 44.83 seconds), excluding the earlier source build.

| Phase | Maximum Job commit | Maximum queried process working-set peak |
| --- | ---: | ---: |
| Folding/resume | 1,382.54 MiB (1.35 GiB) | 1,186.18 MiB (1.16 GiB) |
| Transparent compression/export | 2,284.18 MiB (2.23 GiB) | 2,076.99 MiB (2.03 GiB) |
| Cold native verification | 983.43 MiB (0.96 GiB) | 873.68 MiB (0.85 GiB) |

These are maxima across separate child jobs, not simultaneous aggregate peaks.
All ten child invocations had complete accounting and zero exit codes for both
the native executable and its short-lived console host. The six-GiB per-job
ceiling was never raised. Native `/proc` memory fields are unavailable on Windows;
the table uses the actual Job Object and queried working-set measurements.

The measured pilot was sequential: an earlier conservative six-GiB host reserve
refused parallel launch when available RAM fell to about 15 GiB. After the
16-GiB authorization, the coordinator gained the explicit total budget and
two-GiB reserve above. A live plan check admitted two six-GiB jobs with about
17.6 GiB available. The completed proof work was preserved; a full parallel
k=10 throughput run was not repeated or claimed.

The original fast genesis preflight exposed a console-host observation race.
It failed closed and was not counted as proof rejection. The dedicated observer
fix passed nine generic Windows Job tests and five actual genesis-command
regressions before the successful proving run. Proofs, keys, raw logs and the
complete verification report remain in local ignored output directories.
Automatic approval review rejected public binary proof upload; no binary proof
publication is claimed.

## Limits of this milestone

No live Bitcoin node, active-chain selection, wallet, transaction, signature,
broadcast or deployment is part of this fixture-based proving experiment.
The statement remains the pinned header circuit's rules and cumulative work,
not full-block transaction validity or best-chain selection.
Native Nova proof validity does not complete the BitVM2 Script verifier:
authenticated sponge/proof-byte linkage, remaining verifier composition,
production assertion/key lifecycle and the Bitcoin transaction graph stay open.
