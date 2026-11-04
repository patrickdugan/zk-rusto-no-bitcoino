#!/bin/sh
# Interruption tests (k=5, 1,536 MiB cap): an uninterrupted reference chain
# 100,700 -> 100,800 publishing every 4 steps, then the same chain aborted
# (NOVA_CHAIN_CRASH) during ingestion, folding, payload write, manifest write
# and between the generation rename and the LATEST update. Each interrupted
# chain is resumed to 100,800; its verified end state and step count must
# equal the reference. Writes $R/interrupt/summary.tsv.
set -u
B=${B:-$HOME/tn4-build/nova-header-chain/target/release}
H=${H:-$HOME/tn4-data/headers.bin}
R=${R:-$HOME/tn4-runs}/interrupt
CAP=1536
cd "$(dirname "$0")"
rm -rf "$R"
mkdir -p "$R"
c() { sh ./capped.sh "$@"; }
field() { python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print(d['chain'][sys.argv[2]])" "$1" "$2" 2>/dev/null; }

c ref "$R" 1536 -- "$B/nova-chain" run --network testnet4 --k 5 --headers "$H" --start 100700 --to 100800 --every 4 --out "$R/ref"
REF=$(field "$R/ref.json" end_state_sha256)
printf "case\tcrash_exit\tresumed_from\tend_state_sha256\tsteps\tmatches_reference\n" > "$R/summary.tsv"
printf "reference\t-\t-\t%s\t%s\t-\n" "$REF" "$(field "$R/ref.json" completed_steps)" >> "$R/summary.tsv"

for spec in ingest:7 fold:7 payload:2 manifest:2 publish:2 payload:4; do
  name=$(echo "$spec" | tr ':' '-')
  NOVA_CHAIN_CRASH=$spec c "crash-$name" "$R" $CAP -- "$B/nova-chain" run --network testnet4 --k 5 --headers "$H" --start 100700 --to 100800 --every 4 --out "$R/$name"
  ls "$R/$name/generations" > "$R/$name.after-crash.txt" 2>&1
  c "resume-$name" "$R" $CAP -- "$B/nova-chain" resume --dir "$R/$name" --headers "$H" --to 100800 --every 4
  END=$(field "$R/resume-$name.json" end_state_sha256)
  FROM=$(python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print(d['load']['selection']['loaded'])" "$R/resume-$name.json" 2>/dev/null)
  [ "$END" = "$REF" ] && m=yes || m=NO
  printf "%s\t%s\t%s\t%s\t%s\t%s\n" "$spec" "$(grep -o 'status=[0-9]*\|signal=[A-Z]*' "$R/crash-$name.unit" | head -1)" "$FROM" "$END" "$(field "$R/resume-$name.json" completed_steps)" "$m" >> "$R/summary.tsv"
done

# A torn payload in the newest generation: resume must fall back to the previous one.
cp -r "$R/ref" "$R/torn"
last=$(cat "$R/torn/LATEST")
head -c 1000 "$R/torn/generations/$last/accumulator.bin" > "$R/torn/x" && mv "$R/torn/x" "$R/torn/generations/$last/accumulator.bin"
c verify-torn "$R" $CAP -- "$B/nova-chain" verify-continuation --dir "$R/torn"
printf "torn-latest-payload\t-\t%s\t%s\t%s\t%s\n" \
  "$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['load']['selection']['loaded'])" "$R/verify-torn.json" 2>/dev/null)" \
  "$(field "$R/verify-torn.json" end_state_sha256)" "$(field "$R/verify-torn.json" completed_steps)" "fell back" >> "$R/summary.tsv"
cat "$R/summary.tsv"
echo INTERRUPT-DONE
