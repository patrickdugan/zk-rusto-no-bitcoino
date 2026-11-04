#!/bin/sh
# Adversarial checks on a real exported bundle and continuation (1,536 MiB cap).
#   tn4-adversarial.sh BUNDLE VK CONTINUATION_DIR
# Each case must be rejected; writes $R/adversarial/summary.tsv.
set -u
B=${B:-$HOME/tn4-build/nova-header-chain/target/release}
H=${H:-$HOME/tn4-data/headers.bin}
R=${R:-$HOME/tn4-runs}/adversarial
BUNDLE=$1 VK=$2 DIR=$3
cd "$(dirname "$0")"
rm -rf "$R"
mkdir -p "$R"
c() { sh ./capped.sh "$@"; }
printf "case\taccepted\tdetail\n" > "$R/summary.tsv"
mut() { # name python-expression-on-bytearray b
  python3 - "$BUNDLE" "$R/$1.bundle" "$2" <<'PY'
import sys
b = bytearray(open(sys.argv[1], 'rb').read())
exec(sys.argv[3])
open(sys.argv[2], 'wb').write(bytes(b))
PY
}
for spec in \
  "proof_byte|b[-200]^=1" \
  "forged_chainwork|o=12+3*32; b[o]^=1" \
  "altered_start_height|o=12; b[o]^=1" \
  "altered_start_hash|o=12+32; b[o]^=1" \
  "altered_mtp_window|o=12+16*32; b[o]^=1" \
  "wrong_retarget_base_epoch_bits|o=12+4*32; b[o]^=1" \
  "omitted_or_extra_steps|b[4]^=1" \
  "relabelled_mainnet|b[0:4]=b'NHC1'" ; do
  name=${spec%%|*}; m=${spec#*|}
  mut "$name" "$m"
  c "adv-$name" "$R" 1536 -- "$B/btc-header-fold" verify-bundle "$R/$name.bundle" --vk "$VK"
  acc=$(grep -c '"verified":true' "$R/adv-$name.json"); printf "%s\t%s\t%s\n" "$name" "$acc" "$(cut -c1-160 "$R/adv-$name.json")" >> "$R/summary.tsv"
done
# The testnet4 bundle against the mainnet k=10 circuit (rebuilt mainnet key).
mut mainnet_key "b[0:4]=b'NHC1'; b[8:12]=(10).to_bytes(4,'little')"
c adv-mainnet_key "$R" 1536 -- "$B/btc-header-fold" verify-bundle "$R/mainnet_key.bundle"
printf "%s\t%s\t%s\n" mainnet_key "$(grep -c '"verified":true' "$R/adv-mainnet_key.json")" "$(cut -c1-160 "$R/adv-mainnet_key.json")" >> "$R/summary.tsv"

# Continuation tampering: each copy must fail verify-continuation (it may fall
# back to an older, intact generation; then the result must not claim the
# tampered height).
cont() { # name python-on-manifest-or-payload
  rm -rf "$R/$1"; cp -r "$DIR" "$R/$1"
  g=$(cat "$R/$1/LATEST"); rm -rf $(ls -d "$R/$1"/generations/gen-* | grep -v "$g")
  python3 - "$R/$1/generations/$g" "$2" <<'PY'
import json, sys, hashlib
d = sys.argv[1]
m = json.load(open(f"{d}/manifest.json"))
p = bytearray(open(f"{d}/accumulator.bin", 'rb').read())
exec(sys.argv[2])
open(f"{d}/manifest.json", 'w').write(json.dumps(m))
open(f"{d}/accumulator.bin", 'wb').write(bytes(p))
PY
  c "cont-$1" "$R" 1536 -- "$B/nova-chain" verify-continuation --dir "$R/$1"
  printf "%s\t%s\t%s\n" "continuation_$1" "$(grep -c '"verified":true' "$R/cont-$1.json")" "$(cut -c1-160 "$R/cont-$1.json")" >> "$R/summary.tsv"
}
cont payload_byte "p[len(p)//2]^=1; m['payload']['sha256']=hashlib.sha256(p).hexdigest()"
cont forged_steps "m['completed_steps']+=1; m['end_height']+=m['k']"
cont wrong_z0 "s=bytearray.fromhex(m['initial_state_hex']); s[3*32]^=1; m['initial_state_hex']=s.hex(); m['initial_state_sha256']=hashlib.sha256(s).hexdigest()"
cont wrong_end_state "s=bytearray.fromhex(m['end_state_hex']); s[3*32]^=1; m['end_state_hex']=s.hex(); m['end_state_sha256']=hashlib.sha256(s).hexdigest()"
cont changed_k "m['k']=1; m['completed_steps']*=5"
cont relabelled_network "m['network']='mainnet'"
cont swapped_params "m['public_params_digest']='00'*32"

# Resume with a different k, and against an input that does not continue the chain.
rm -rf "$R/k1"; cp -r "$DIR" "$R/k1"
c resume-k1 "$R" 1536 -- "$B/nova-chain" resume --dir "$R/k1" --headers "$H" --k 1 --to 999999
printf "%s\t%s\t%s\n" resume_changed_k "$(grep -c '"ok":true' "$R/resume-k1.json")" "$(cut -c1-160 "$R/resume-k1.json")" >> "$R/summary.tsv"
# Inputs that do not continue the chain, resumed from the generation ending
# at 100,800: a fork sharing only the height (block 100,850 altered) and an
# omitted block (100,830 removed, so later heights shift).
python3 - "$H" "$R/forked.bin" "$R/omitted.bin" <<'PY'
import sys
b = bytearray(open(sys.argv[1], 'rb').read())
f = bytearray(b); f[100850 * 80 + 76] ^= 1
open(sys.argv[2], 'wb').write(bytes(f))
open(sys.argv[3], 'wb').write(bytes(b[:100830 * 80] + b[100831 * 80:]))
PY
for case in forked omitted; do
  rm -rf "$R/$case"; cp -r "$DIR" "$R/$case"
  echo gen-000001 > "$R/$case/LATEST"
  c "resume-$case" "$R" 1536 -- "$B/nova-chain" resume --dir "$R/$case" --headers "$R/$case.bin" --to 100900
  printf "%s\t%s\t%s\n" "resume_input_$case" "$(grep -c '"ok":true' "$R/resume-$case.json")" "$(cut -c1-160 "$R/resume-$case.json")" >> "$R/summary.tsv"
done
rm -f "$R/forked.bin" "$R/omitted.bin"
cat "$R/summary.tsv"
echo ADVERSARIAL-DONE
