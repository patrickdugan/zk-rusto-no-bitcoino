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
