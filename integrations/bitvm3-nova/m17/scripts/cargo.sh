#!/bin/bash
# Syncs m17 into the WSL filesystem and runs cargo there: cargo.sh <cargo args...>
set -e
export PATH=/root/.cargo/bin:/usr/local/bin:/usr/bin:/bin
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
mkdir -p /root/nb3/m17
rsync -a --delete --exclude target --exclude Cargo.lock $REPO/m17/ /root/nb3/m17/
[ -f $REPO/m17/Cargo.lock ] && cp $REPO/m17/Cargo.lock /root/nb3/m17/Cargo.lock
cd /root/nb3/m17
CARGO_BUILD_JOBS=${JOBS:-6} cargo "$@"
cp /root/nb3/m17/Cargo.lock $REPO/m17/Cargo.lock
