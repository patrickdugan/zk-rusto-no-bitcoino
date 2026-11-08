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
