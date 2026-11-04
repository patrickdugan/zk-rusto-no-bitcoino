#!/bin/sh
# Phase D, first batch, all under a 1,536 MiB cgroup cap (k=5):
#  1. PR #14's 200 headers (100,701-100,900), now from the state the native
#     rules derive from genesis (chainwork matches Core at 100,700);
#  2. a genesis-rooted chain to 2,020 (the first retarget is at 2,016);
#  3. compressed export of each, verified by btc-header-fold verify-bundle,
#     once with the exported key and once rebuilding the key.
set -u
B=${B:-$HOME/tn4-build/nova-header-chain/target/release}
H=${H:-$HOME/tn4-data/headers.bin}
R=${R:-$HOME/tn4-runs}
CAP=1536
cd "$(dirname "$0")"
mkdir -p "$R"
c() { sh ./capped.sh "$@"; }

rm -rf "$R/c200" "$R/gen"
c tn4-r200 "$R" $CAP -- "$B/nova-chain" run --network testnet4 --k 5 --headers "$H" --start 100700 --to 100900 --every 20 --out "$R/c200"
c tn4-r200-export "$R" $CAP -- "$B/nova-chain" export --dir "$R/c200" --bundle "$R/c200.nht4" --vk-out "$R/tn4-k5.vk"
c tn4-r200-verify "$R" $CAP -- "$B/btc-header-fold" verify-bundle "$R/c200.nht4" --vk "$R/tn4-k5.vk"
c tn4-r200-verify-rebuild "$R" $CAP -- "$B/btc-header-fold" verify-bundle "$R/c200.nht4"

c tn4-gen2020 "$R" $CAP -- "$B/nova-chain" run --network testnet4 --k 5 --headers "$H" --to 2020 --every 101 --out "$R/gen"
c tn4-gen2020-cold "$R" $CAP -- "$B/nova-chain" verify-continuation --dir "$R/gen"
c tn4-gen2020-export "$R" $CAP -- "$B/nova-chain" export --dir "$R/gen" --bundle "$R/gen2020.nht4"
c tn4-gen2020-verify "$R" $CAP -- "$B/btc-header-fold" verify-bundle "$R/gen2020.nht4" --vk "$R/tn4-k5.vk"
echo PHASE-D1-DONE
