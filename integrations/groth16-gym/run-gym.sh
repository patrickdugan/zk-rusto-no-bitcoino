#!/usr/bin/env bash
# Groth16 gym (Linux/WSL): same sweep as run-gym.ps1.
#   ./run-gym.sh [CAP_GB=12] [MAX_HEADERS=256]
set -euo pipefail
cd "$(dirname "$0")"
CAP_GB=${1:-12}
MAX=${2:-256}
cargo build --release
BIN=${CARGO_TARGET_DIR:-target}/release/groth16-gym
mkdir -p results
OUT=results/$(hostname | tr 'A-Z' 'a-z')-$(date +%Y%m%d-%H%M).jsonl
RAM=$(awk '/MemTotal/{printf "%.1f", $2/1048576}' /proc/meminfo)
CPU=$(awk -F': ' '/model name/{print $2; exit}' /proc/cpuinfo)
echo "{\"machine\":{\"host\":\"$(hostname)\",\"ram_gb\":$RAM,\"cpu\":\"$CPU\",\"cap_gb\":$CAP_GB}}" >> "$OUT"
run() { line=$("$BIN" "$@" | tail -1); echo "$line" | tee -a "$OUT"; }
run spv
n=1
while [ "$n" -le "$MAX" ]; do
  line=$(run headers "$n")
  echo "$line"
  peak=$(echo "$line" | sed 's/.*"peak_rss_mb":\([0-9]*\).*/\1/')
  # Stop before the next doubling's predicted peak passes the cap.
  if [ $((peak * 2)) -gt $(awk "BEGIN{print int($CAP_GB*1024)}") ]; then break; fi
  n=$((n * 2))
done
echo "results: $OUT"
