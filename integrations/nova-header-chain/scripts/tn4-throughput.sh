#!/bin/sh
# Throughput of concurrent Nova segments on one machine: P processes with T
# threads each (RAYON_NUM_THREADS), each folding 200 testnet4 headers (k=5)
# from a different native start, all under one cgroup cap (CAP_MIB). Prints
# aggregate headers/second per configuration and the cgroup peak.
set -u
B=${B:-$HOME/tn4-build/nova-header-chain/target/release}
H=${H:-$HOME/tn4-data/headers.bin}
R=${R:-$HOME/tn4-runs}/throughput
CAP=${CAP_MIB:-15360}
mkdir -p "$R"
printf "procs\tthreads_each\theaders_total\twall_s\theaders_per_s\tcgroup_peak\n" > "$R/summary.tsv"
for cfg in 1:8 2:4 4:2 8:1; do
  P=${cfg%%:*} T=${cfg#*:}
  rm -rf "$R/p${P}"; mkdir -p "$R/p${P}"
  cat > "$R/p${P}/go.sh" <<EOF
#!/bin/sh
for i in \$(seq 1 $P); do
  s=\$((100000 + i * 1000))
  RAYON_NUM_THREADS=$T $B/nova-chain run --network testnet4 --k 5 --headers $H --start \$s --to \$((s + 200)) --every 1000 --out $R/p${P}/c\$i > $R/p${P}/c\$i.json 2> $R/p${P}/c\$i.err &
done
wait
EOF
  sudo systemctl reset-failed tput-$P 2>/dev/null || true
  t0=$(date +%s.%N)
  sudo systemd-run --wait --collect --unit tput-$P -p User="$(id -un)" -p MemoryMax=${CAP}M -p MemorySwapMax=0 \
    --setenv=HOME="$HOME" sh "$R/p${P}/go.sh" > "$R/p${P}/unit.txt" 2>&1
  t1=$(date +%s.%N)
  peak=$(grep -o "Memory peak: [0-9.]*[MG]" "$R/p${P}/unit.txt" | head -1)
  ok=$(grep -l '"ok":true' "$R"/p${P}/c*.json | wc -l)
  python3 - "$P" "$T" "$t0" "$t1" "$ok" "$peak" >> "$R/summary.tsv" <<'PY'
import sys
P, T, t0, t1, ok, peak = sys.argv[1:7]
wall = float(t1) - float(t0); hdr = 200 * int(ok)
print(f"{P}\t{T}\t{hdr}\t{wall:.1f}\t{hdr / wall:.2f}\t{peak}")
PY
done
cat "$R/summary.tsv"
echo THROUGHPUT-DONE
