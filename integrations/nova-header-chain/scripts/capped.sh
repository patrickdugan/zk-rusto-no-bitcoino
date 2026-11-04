#!/bin/sh
# Run one command in a transient systemd unit with an OS-enforced memory cap
# (cgroup v2 memory.max, swap off). The cgroup also charges page cache the
# command writes. Output: OUT.json (stdout), OUT.err (stderr), OUT.unit
# (systemd's result line and cgroup peak), OUT.time (GNU time).
#   capped.sh NAME OUTDIR CAP_MIB -- command args...
set -eu
name=$1 out=$2 cap=$3
shift 4
mkdir -p "$out"
sudo systemctl reset-failed "$name" 2>/dev/null || true
sudo systemd-run --wait --collect --unit "$name" -p User="$(id -un)" \
  -p MemoryMax="${cap}M" -p MemorySwapMax=0 -p Nice=10 -p WorkingDirectory="$PWD" \
  -p StandardOutput=file:"$out/$name.json" -p StandardError=file:"$out/$name.err" \
  --setenv=HOME="$HOME" ${NOVA_CHAIN_CRASH:+--setenv=NOVA_CHAIN_CRASH=$NOVA_CHAIN_CRASH} \
  /usr/bin/time -v -o "$out/$name.time" "$@" > "$out/$name.unit" 2>&1 || true
grep -E "Finished with result|Memory peak|Main processes terminated" "$out/$name.unit" || true
