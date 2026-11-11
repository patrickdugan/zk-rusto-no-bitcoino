# nb3-prove-gpu: nb3-prover on SP1's CUDA provers

The same resumable, disk-backed prover as [`../prover`](../prover/README.md) (same command line,
run directories, memo and output format), with SP1 6.9's CUDA shard provers in place of its CPU
ones. It runs on a laptop GPU: an RTX 5080 Laptop GPU with 16 GB.

SP1's own GPU setup (`sp1_gpu_prover::cuda_worker_builder` → `local_gpu_opts`) panics on any
GPU with less than 24 GB and sizes the core trace buffer for its largest shard (about
4 × 10^8 field elements). Device memory comes from CUDA's stream-ordered pool and follows the
shard actually proved, so this backend builds the same provers (`new_cuda_prover`, same
components) with the core trace buffer sized from the run's `--element-threshold`. The recursion,
shrink and wrap provers keep SP1's allocations, which its fixed recursion programs need.

Extra flag: `--trace-buffers N`, the pinned host trace buffers per core and recursion prover
(default 2).

## Build

SP1's GPU crates are not on crates.io. `Cargo.toml` takes them, and every other SP1 crate, from
SP1's repository at the v6.9.0 commit (`b8387fa6`), so the CUDA provers and the CPU-side node
share one set of types. With a checkout of that commit already on disk:

```
SP1_DIR=/path/to/sp1 CUDA_ARCHS=120 nova-bitvm3/prover-gpu/scripts/build-with-local-sp1.sh
```

rewrites the git entries to paths in the checkout and builds. Requirements: CUDA Toolkit 12.8 or
newer, cmake, clang; under WSL2 the driver's `libcuda` is in `/usr/lib/wsl/lib`.

## Measured (RTX 5080 Laptop GPU, 16 GB; WSL2, 20 GB)

| Guest | Shard size | Result |
| --- | --- | --- |
| control C, 4 headers (512,784 instructions) | SP1 default | proved in 2.8 s (CPU backend: 619–1,366 s); verified, statement `cd9beb30…`, program key `4686663f…` |
| guest A, the Nova verifier (72.3 × 10^9 instructions) | `--element-threshold 134217728` (2^27) | 27,058 shard tasks; compressed proof verified, statement `d3b478b0…`, program key `5df3760f…` (M13's pins); 14.9 h from first start to proof, including three hangs after the laptop slept and the restarts below |
| M16, the mainnet header chain and payment ([`../m16`](../m16/README.md), 34.1 × 10^9 instructions) | `--element-threshold 134217728` (2^27) | 13,290 shard tasks and 4,430 recursion tasks; compressed proof verified, statement `cae6068f…`, program key `dfc68a5d…`; the last attempt took 1 h 54 min (3,645 shards proved, 9,645 replayed from the memo, 11.6 GiB peak resident set under a 12 GiB cap) after attempts on 2026-11-10 that the memory guard and a WSL crash cut short (below) |

Guest A ran with these SP1 worker settings (environment): 8 core workers, 2 splicing workers, 4
in each recursion pool and `RAYON_NUM_THREADS=18`:

```
SP1_WORKER_NUM_CORE_WORKERS=8 SP1_WORKER_CORE_BUFFER_SIZE=8
SP1_WORKER_NUM_SPLICING_WORKERS=2 SP1_WORKER_SPLICING_BUFFER_SIZE=4
SP1_WORKER_NUM_RECURSION_EXECUTOR_WORKERS=4 SP1_WORKER_RECURSION_EXECUTOR_BUFFER_SIZE=4
SP1_WORKER_NUM_PREPARE_REDUCE_WORKERS=4 SP1_WORKER_PREPARE_REDUCE_BUFFER_SIZE=4
SP1_WORKER_NUM_RECURSION_PROVER_WORKERS=4 SP1_WORKER_RECURSION_PROVER_BUFFER_SIZE=4
```

Steady state was 0.55–0.77 shards per second, with 13.4–14.2 GB of device memory and a peak
resident set of 14.2 GB (cgroup cap 14 GiB plus swap). The GPU was busy about half the time:
host-side execution and trace generation set the pace. With one worker per pool (the CPU tool's
default) the GPU starved.

The compressed proof went through `m13 shrink-wrap` (1 min 41 s) and `m13 wrap-only-v2` (58 s);
the resulting final proof is `../m13/fixtures/a-wrap-blake3-v2.bin`.

## Long runs on a laptop

When Windows enters Modern Standby (the idle timer, the lid, or on many laptops just the display
turning off), the CUDA context under WSL2 can stop completing work that was in flight. The prover
then waits forever in a device-to-host copy with the GPU idle; nothing fails. Guest A's run hit
this three times. [`scripts/supervise.sh`](scripts/supervise.sh) restarts the run when its memo
records nothing for 15 minutes:

```
scripts/supervise.sh RUN_DIR -- nb3-prove-gpu prove ... --run-dir RUN_DIR ...
```

A restart replays every cached shard before proving new ones (about 30 minutes at 23,000 cached
shards here), and recursion tasks whose inputs regrouped are proved again. Keeping the machine
awake on AC power avoids the restarts:

```
powercfg /change standby-timeout-ac 0
powercfg /change monitor-timeout-ac 0
```

### Under a host memory guard

On a laptop shared with other work, a watchdog that stops the prover when Windows runs short of
memory keeps the machine usable. Two things went wrong with one during the M16 mainnet run
(2026-11-10):

- A killed prover leaves its SP1 shared-memory files in `/dev/shm`, about 0.5 to 4 GiB each, and
  they stay in RAM until removed. By 14:16 UTC files from earlier killed runs held 7.6 GiB, and from
  then on the guard killed every restart within a minute. `supervise.sh` now removes the files no
  process holds before each restart, and resumes after an outside SIGTERM or SIGKILL (exit 143 or
  137) instead of exiting. [`scripts/test-supervise.sh`](scripts/test-supervise.sh) checks this
  with a fake prover; the previous script fails it.
- The guard read `FreePhysicalMemory`, which leaves out the standby list that Windows hands back
  on demand: it saw 0.95 GiB with 3.95 GiB available. Reading available memory still killed
  restarts, because a restart takes about 5 GiB in under a minute, faster than Windows trims idle
  working sets. The run resumed under a guard that kills when available memory stays below
  1.5 GiB for 30 s, or falls below 0.8 GiB at any moment.

### Host disk

The memo and SP1's artifact store sit inside WSL's virtual disk, a file on the host that grows and
never shrinks; the artifact store alone reached 36 GB during the M16 run. At 15:16 UTC on
2026-11-10 the host drive holding that file filled, and the WSL VM died with the prover in it.
Memo entries are checksummed and renamed into place, so after space was freed the run resumed
from the 10,078 core shards and 5,635 recursion entries already recorded. The artifact store is
cleared at each start.
