# Ark H100 pilot kits

Use one 80 GB H100 SXM to measure the height-679, four-VTXO Ark proving workload.
The desktop Compute tab shows local GPU telemetry and the two cloud plans.

- [Runpod pilot](runpod.md)
- [Hyperstack pilot](hyperstack.md)

Both plans use the same cached-GKR driver, SP1 6.9.0 revision
`b8387fa61e1361d90ee7de49f551863418ca0f08`, and original core partition,
recursion arity, and worker counts. The Hopper target is `sm_90`, built with
CUDA 12.8.1 (`nvcc V12.8.93`) and Rust 1.99.1. The build checks the locked
source inventory and verifies that the new binary contains Hopper code.

## Stage the local package

Use the prepared `hopper-build.tar.gz` and `checkpoint.tar` with their
`.sha256` sidecars. Keep the archived checkpoint, guest inputs and any M14
private state in operator-controlled storage. The old checkpoint may lag the
live laptop. Replay measurements establish which part of the copy is usable.

On compatible staging compute with the pilot volume mounted at `/workspace`,
install Rust 1.99.1, the CUDA 12.8.1 development toolkit,
`build-essential`, `clang`, `cmake`, `pkg-config`, `libssl-dev`,
`protobuf-compiler`, Python 3 and Git. If enabled by the build, use the Go
version declared by the bundled gnark module.

```bash
cd /workspace/ark-h100-upload
sha256sum -c hopper-build.sha256 checkpoint.sha256
umask 077
mkdir /workspace/ark-h100-kit /workspace/ark-h100-trial-01
tar -xzf hopper-build.tar.gz -C /workspace/ark-h100-kit
tar -xf checkpoint.tar -C /workspace/ark-h100-trial-01
cd /workspace/ark-h100-kit
bash build-hopper.sh
```

The build fetches Cargo dependencies against the lockfile and compiles for
Hopper. Allow time on staging compute before the paid GPU hour. Use the same
operating system and CUDA runtime on staging and GPU compute.

## Measure the pilot

```bash
bash /workspace/ark-h100-kit/run-pilot.sh /workspace/ark-h100-trial-01
```

The runner checks the GPU, binary, proving inputs, and cache configuration,
then gives its isolated prover up to 55 minutes. It leaves time in the
hour to stop GPU billing and retrieve the results. Collect
`pilot-result.json`, `prover.log`, `gpu-start.txt`, and any
`compressed.bin`. The throughput report counts distinct new checkpoints
after the first ten minutes and tracks replay counts. Extend if the run
sustains about **10 fresh core proofs/min** and continues generating new
recursion proofs. The observed laptop comparison was 4.8 fresh cores/min.

The proof remains subject to independent SDK verification, M13 statement
verification and the complete M14 checks.
