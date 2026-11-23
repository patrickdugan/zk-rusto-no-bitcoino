#!/usr/bin/env bash
set -euo pipefail
umask 077
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
cd "$here"
sha256sum -c --quiet sources.sha256

toolchain=1.99.1
export CUDA_PATH=/usr/local/cuda
export PATH="$CUDA_PATH/bin:$HOME/.cargo/bin:$PATH"
export CUDA_ARCHS=90
export CARGO_TARGET_DIR="$here/hopper-target"
export CARGO_BUILD_JOBS="${PILOT_BUILD_JOBS:-4}"
nvcc --version | grep -F 'V12.8.93'
nvcc --list-gpu-arch | grep -x 'compute_90'
rustc "+$toolchain" --version
manifest=prover-gpu-cached-gkr-20261122/Cargo.toml
bin=ark-prove-gpu-cached-gkr
cargo "+$toolchain" fetch --locked --manifest-path "$manifest"
cargo "+$toolchain" build --release --locked --offline --manifest-path "$manifest" --bin "$bin" \
    --config profile.release.package.nb3-prover-gpu.codegen-units=256
cuobjdump --list-elf "$CARGO_TARGET_DIR/release/$bin" > hopper-fatbins.txt
grep -m1 -E '\bsm_90([a.]|$)' hopper-fatbins.txt
sha256sum "hopper-target/release/$bin" > hopper-binary.sha256
