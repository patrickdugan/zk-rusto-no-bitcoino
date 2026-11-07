#!/usr/bin/env bash
# Full architecture A chain on one machine (Linux or WSL2, x86_64):
#   k=1 Nova proof (fixture) --SP1 6.9.0 guest A--> compressed STARK
#   --SP1 shrink--> --SP1 wrap program under BLAKE3--> final proof --> m13-verify
#
# Prerequisites: rustup, the SP1 6.9.0 toolchain (`sp1up --version v6.9.0`;
# `cargo prove --version` must print sp1 6.9.0), python3, about 25 GB of disk.
# Memory: SP1 6.9.0's CPU prover peaks at 19-30 GiB; RAM plus swap must cover
# that. Measured on the M12 host (20 threads): guest A executes 72.3e9
# instructions, so the compressed proof is a long run; this script logs each
# stage with wall time and peak RSS to $OUT/*.time.
#
# usage: nova-bitvm3/m13/run_full_a.sh OUT_DIR
set -euo pipefail
OUT=${1:?usage: run_full_a.sh OUT_DIR}
HERE=$(cd "$(dirname "$0")" && pwd)
NB3=$(cd "$HERE/.." && pwd)
mkdir -p "$OUT"
export M13_ENABLE_PROVING=1

echo "== build m12 native (k=1 key export) and m13 (prover, verifier)"
cargo build --release --locked --manifest-path "$NB3/m12/native/Cargo.toml"
cargo build --release --locked --manifest-path "$HERE/wrap/Cargo.toml"
cargo build --release --locked --manifest-path "$HERE/verify/Cargo.toml"
M12="$NB3/m12/native/target/release/m12"
M13="$HERE/wrap/target/release/m13"
VERIFY="$HERE/verify/target/release/m13-verify"

echo "== k=1 testnet4 key (expect 6894f490...c12a)"
[ -f "$OUT/k1.vk" ] || /usr/bin/time -v -o "$OUT/vk-export.time" "$M12" vk-export testnet4 1 "$OUT/k1.vk"
echo "6894f4903a9ff9713111bb1076b61663ac3592ad3d51b697d58125403fc5c12a  $OUT/k1.vk" | sha256sum -c -

BUNDLE="$NB3/m12/fixtures/testnet4-k1-0-4.nht4"
STATEMENT_SHA=d3b478b0ed0055bbd43a59775729c990a33d1df07bd0a66ee728a3573c832fa0

echo "== guest A compressed proof (complete Nova verifier inside SP1)"
[ -f "$OUT/a-k1.compressed.bin" ] || /usr/bin/time -v -o "$OUT/compress-a.time" \
  "$M13" compress-a "$OUT/k1.vk" "$BUNDLE" "$STATEMENT_SHA" "$OUT/a-k1.compressed.bin" | tee "$OUT/compress-a.log"
# SP1's logger shares stdout; the result is the one JSON line.
grep '^{' "$OUT/compress-a.log" | tail -1 > "$OUT/compress-a.json"

echo "== SP1 shrink, then SP1's wrap program proved with BLAKE3"
/usr/bin/time -v -o "$OUT/shrink-wrap-a.time" "$M13" shrink-wrap "$OUT/a-k1.compressed.bin" "$OUT/a-k1" | tee "$OUT/shrink-wrap-a.log"

echo "== final verifier with the pins"
python3 - "$OUT" "$STATEMENT_SHA" "$HERE" <<'PY'
import json, sys
out, sha, here = sys.argv[1:4]
st = json.load(open(f'{out}/a-k1/statement.json'))
pins = json.load(open(f'{here}/pins.json'))
compress = json.load(open(f'{out}/compress-a.json'))
assert st['committed_values_sha256'] == sha, 'final proof commits a different statement'
assert st['wrap_vk_sha256'] == pins['wrap_vk_sha256'], 'wrap key differs from the pinned key'
assert st['recursion_vk_root'] == pins['recursion_vk_root'], 'recursion key map differs'
assert st['program_vk_digest'] == compress['program_vk_digest'], 'guest program digest differs'
assert st['program_vk_digest'] == pins['programs']['architecture_a_nova_verifier']['program_vk_digest'], 'guest A key differs from the pin'
expect = dict(st)
json.dump(expect, open(f'{out}/a-k1/expect.json', 'w'), indent=2)
print('pins and statement match')
PY
"$VERIFY" verify "$OUT/a-k1/wrap.bin" "$OUT/a-k1/expect.json" | tee "$OUT/verify-a.json"
echo "done: $OUT/a-k1/wrap.bin"
