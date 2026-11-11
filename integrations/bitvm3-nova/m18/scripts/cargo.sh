#!/bin/bash
# Syncs m18 into the WSL filesystem and runs cargo there: cargo.sh <cargo args...>
set -e
export PATH=/root/.cargo/bin:/usr/local/bin:/usr/bin:/bin
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
mkdir -p /root/m18
rsync -a --delete --exclude target --exclude Cargo.lock $REPO/m18/ /root/m18/
[ -f $REPO/m18/Cargo.lock ] && cp $REPO/m18/Cargo.lock /root/m18/Cargo.lock
cd /root/m18
CARGO_BUILD_JOBS=${JOBS:-4} nice -n 10 cargo "$@"
cp /root/m18/Cargo.lock $REPO/m18/Cargo.lock
