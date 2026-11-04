#!/bin/sh
# Phase D, second batch (k=5, 1,536 MiB cap): extend the genesis-rooted
# continuation in $R/gen (ending at 2,020) to 10,000, export and verify it,
# then to TIP, export and verify that (with the exported key and with a
# rebuilt key).
set -u
B=${B:-$HOME/tn4-build/nova-header-chain/target/release}
H=${H:-$HOME/tn4-data/headers.bin}
R=${R:-$HOME/tn4-runs}
TIP=${TIP:-158970}
CAP=1536
cd "$(dirname "$0")"
c() { sh ./capped.sh "$@"; }

c tn4-gen10k "$R" $CAP -- "$B/nova-chain" resume --dir "$R/gen" --headers "$H" --to 10000 --every 200
c tn4-gen10k-export "$R" $CAP -- "$B/nova-chain" export --dir "$R/gen" --bundle "$R/gen10000.nht4"
c tn4-gen10k-verify "$R" $CAP -- "$B/btc-header-fold" verify-bundle "$R/gen10000.nht4" --vk "$R/tn4-k5.vk"

c tn4-gentip "$R" $CAP -- "$B/nova-chain" resume --dir "$R/gen" --headers "$H" --to "$TIP" --every 400
c tn4-gentip-cold "$R" $CAP -- "$B/nova-chain" verify-continuation --dir "$R/gen"
c tn4-gentip-export "$R" $CAP -- "$B/nova-chain" export --dir "$R/gen" --bundle "$R/gentip.nht4"
c tn4-gentip-verify "$R" $CAP -- "$B/btc-header-fold" verify-bundle "$R/gentip.nht4" --vk "$R/tn4-k5.vk"
c tn4-gentip-verify-rebuild "$R" $CAP -- "$B/btc-header-fold" verify-bundle "$R/gentip.nht4"
echo PHASE-D2-DONE
