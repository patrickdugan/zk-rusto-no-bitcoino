#!/bin/bash
# Syncs the crate into the WSL filesystem and runs cargo there: cargo.sh <cargo args...>
set -e
source /root/.toolenv
CRATE="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p /root/ark-nova/src
rsync -a --delete --exclude target --exclude Cargo.lock --exclude results "$CRATE"/ /root/ark-nova/src/
[ -f "$CRATE/Cargo.lock" ] && cp "$CRATE/Cargo.lock" /root/ark-nova/src/Cargo.lock
cd /root/ark-nova/src
export CARGO_TARGET_DIR=/root/ark-nova/target
export RAYON_NUM_THREADS=8
CARGO_BUILD_JOBS=8 cargo "$@"
cp /root/ark-nova/src/Cargo.lock "$CRATE/Cargo.lock"
