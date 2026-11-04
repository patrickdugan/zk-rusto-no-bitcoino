#!/bin/sh
# Phase E canary: a real testnet4 payment in block BLK proved without SP1.
#  A: the genesis-anchored continuation ($R/gen) forked at its last
#     generation at or below BLK and extended to BLK;
#  B: a chain from BLK to TIP (its start is the state the native rules derive
#     from genesis; verify-nst4.py requires it to equal A's proven end state);
#  then NST4 = A + B + Core's MerkleBlock + raw tx, verified offline against
#  Core, and SPV tamper cases. All proving under the 1,536 MiB cap.
set -u
B=${B:-$HOME/tn4-build/nova-header-chain/target/release}
H=${H:-$HOME/tn4-data/headers.bin}
R=${R:-$HOME/tn4-runs}
S=$R/spv
TIP=${TIP:-158970}
BLK=${BLK:-158965}
CLI="bitcoin-cli -datadir=$HOME/btc-testnet4"
cd "$(dirname "$0")"
rm -rf "$S"; mkdir -p "$S"
c() { sh ./capped.sh "$@"; }

BH=$($CLI getblockhash $BLK)
TXID=$($CLI getblock "$BH" 1 | python3 -c "import json,sys; t=json.load(sys.stdin)['tx']; print(t[1] if len(t)>1 else t[0])")
$CLI getrawtransaction "$TXID" false "$BH" > "$S/tx.hex"
$CLI gettxoutproof "[\"$TXID\"]" "$BH" > "$S/merkleblock.hex"
echo "block $BLK $BH tx $TXID" | tee "$S/target.txt"

cp -r "$R/gen" "$S/chainA"
G=$(python3 - "$S/chainA" $BLK <<'PY'
import json, os, sys
d, blk = sys.argv[1], int(sys.argv[2])
best = None
for g in sorted(os.listdir(f"{d}/generations")):
    m = json.load(open(f"{d}/generations/{g}/manifest.json"))
    if m["end_height"] <= blk and (blk - m["end_height"]) % m["k"] == 0:
        best = g
print(best)
PY
)
echo "$G" > "$S/chainA/LATEST"
c spv-chainA "$S" 1536 -- "$B/nova-chain" resume --dir "$S/chainA" --headers "$H" --to $BLK --every 400
c spv-chainA-export "$S" 1536 -- "$B/nova-chain" export --dir "$S/chainA" --bundle "$S/A.nht4"
c spv-chainB "$S" 1536 -- "$B/nova-chain" run --network testnet4 --k 5 --headers "$H" --start $BLK --to $TIP --out "$S/chainB"
c spv-chainB-export "$S" 1536 -- "$B/nova-chain" export --dir "$S/chainB" --bundle "$S/B.nht4"
"$B/btc-header-fold" pack-spv "$S/payment.nst4" 0 "$S/A.nht4" "$S/B.nht4" "$S/merkleblock.hex" "$S/tx.hex"

V="python3 ./verify-nst4.py --verifier $B/btc-header-fold --vk $R/tn4-k5.vk"
CORE="--core-datadir $HOME/btc-testnet4 --core-port 48352"
$V "$S/payment.nst4" $CORE --expect-txid "$TXID" --expect-vout 0 > "$S/receipt.json" 2>&1; echo "accept rc=$?" | tee "$S/summary.txt"
cat "$S/receipt.json"
printf "case\trefused\tdetail\n" >> "$S/summary.txt"
neg() { # name extra-args [bundle]
  f=${3:-$S/payment.nst4}
  $V "$f" $2 > "$S/neg-$1.json" 2>&1; rc=$?
  printf "%s\t%s\t%s\n" "$1" "$([ $rc -ne 0 ] && echo yes || echo NO)" "$(cut -c1-140 "$S/neg-$1.json")" >> "$S/summary.txt"
}
neg wrong_vout "--expect-vout 1"
neg wrong_txid "--expect-txid $(echo "$TXID" | sed 's/^./0/')"
neg wrong_value "--expect-value 1"
mut() { python3 - "$S/payment.nst4" "$S/$1.nst4" "$2" <<'PY'
import struct, sys
b = bytearray(open(sys.argv[1], 'rb').read())
o = [8]
for _ in range(3):
    n = struct.unpack('<I', b[o[-1]:o[-1] + 4])[0]; o.append(o[-1] + 4 + n)
A, Bp, M, T = o  # offsets of the four length prefixes
exec(sys.argv[3])
open(sys.argv[2], 'wb').write(bytes(b))
PY
}
mut tampered_merkle "b[M + 4 + 100] ^= 1"
neg tampered_merkle "" "$S/tampered_merkle.nst4"
mut tampered_tx "b[T + 4 + 10] ^= 1"
neg tampered_tx "" "$S/tampered_tx.nst4"
mut tampered_second_proof "b[M - 50] ^= 1"
neg tampered_second_proof "" "$S/tampered_second_proof.nst4"
# State-join mismatch: a valid NHT4 proof (100,700-100,900) as the second part.
python3 - "$S/payment.nst4" "$R/c200.nht4" "$S/join.nst4" "$S/anchor.nst4" <<'PY'
import struct, sys
b = open(sys.argv[1], 'rb').read(); other = open(sys.argv[2], 'rb').read()
parts, i = [], 8
for _ in range(4):
    n = struct.unpack('<I', b[i:i+4])[0]; parts.append(b[i+4:i+4+n]); i += 4 + n
pack = lambda ps: b[:8] + b''.join(struct.pack('<I', len(p)) + p for p in ps)
open(sys.argv[3], 'wb').write(pack([parts[0], other, parts[2], parts[3]]))
open(sys.argv[4], 'wb').write(pack([other, parts[1], parts[2], parts[3]]))
PY
neg join_mismatch "" "$S/join.nst4"
neg not_genesis_anchored "" "$S/anchor.nst4"
cat "$S/summary.txt"
echo SPV-CANARY-DONE
