#!/bin/bash
# Builds nb3-prove-gpu against a local SP1 v6.9.0 checkout (SP1_DIR): the crate's git entries for
# SP1 (pinned to commit b8387fa6) are rewritten to paths in SP1_DIR, so cargo does not fetch the
# 0.6 GB repository again. CUDA_ARCHS selects the GPU architecture (120: RTX 50xx).
#
# usage: SP1_DIR=/path/to/sp1 [OUT_DIR=...] [CUDA_ARCHS=120] build-with-local-sp1.sh
# The binary lands in $CARGO_TARGET_DIR/release/nb3-prove-gpu (default $OUT_DIR/target).
set -euo pipefail
SP1=${SP1_DIR:?set SP1_DIR to a checkout of succinctlabs/sp1 at b8387fa6 (v6.9.0)}
SRC=$(cd "$(dirname "$0")/../.." && pwd)
OUT=${OUT_DIR:-$HOME/nb3-build}
export PATH=$HOME/.cargo/bin:/usr/local/cuda/bin:$PATH
export CUDA_PATH=${CUDA_PATH:-/usr/local/cuda} CUDACXX=${CUDACXX:-/usr/local/cuda/bin/nvcc} CUDA_ARCHS=${CUDA_ARCHS:-120}
export LD_LIBRARY_PATH=/usr/local/cuda/lib64:/usr/lib/wsl/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}
export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-$OUT/target} CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS:-8}
test "$(git -C "$SP1" rev-parse HEAD)" = "b8387fa61e1361d90ee7de49f551863418ca0f08"
mkdir -p "$OUT/prover" "$OUT/prover-gpu"
rsync -a --exclude target --exclude Cargo.lock "$SRC/prover/" "$OUT/prover/"
rsync -a --exclude target "$SRC/prover-gpu/" "$OUT/prover-gpu/"
find "$OUT/prover" "$OUT/prover-gpu" -name '*.rs' -o -name '*.toml' | xargs sed -i 's/\r$//'
# crate name -> path, from SP1's [workspace.dependencies]
awk -F'"' '/^(sp1|slop)-[a-z0-9-]+ = \{.*path = /{ split($0,a," "); n=a[1]; for(i=1;i<=NF;i++) if ($(i-1) ~ /path = $/) p=$i; gsub(/^\.\//,"",p); print n, p }' \
  "$SP1/Cargo.toml" > "$OUT/prover-gpu/sp1-paths.txt"
M=$OUT/prover-gpu/Cargo.toml
while read -r n p; do
  sed -i "s#^$n = { git = \"https://github.com/succinctlabs/sp1\", rev = \"b8387fa61e1361d90ee7de49f551863418ca0f08\" }#$n = { path = \"$SP1/$p\" }#" "$M"
done < "$OUT/prover-gpu/sp1-paths.txt"
if grep -q 'github.com/succinctlabs/sp1' "$M"; then echo "unmapped:"; grep 'github.com/succinctlabs/sp1' "$M"; exit 3; fi
cd "$OUT/prover-gpu"
cargo build --release
