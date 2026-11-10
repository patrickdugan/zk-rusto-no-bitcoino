#!/bin/bash
# M16 mainnet header chain: native check, then two Nova shards in parallel (resumable).
# usage: fold-mainnet.sh [check|run|status]
B=/root/nhc/target/release; D=/mnt/d/m16-mainnet; W=/root/m16-nova; mkdir -p $W
H=$D/headers.bin; TIP=$(( $(stat -c %s $H) / 80 - 1 )); MID=$(( TIP / 2 ))
shard() { # name start end
  local dir=$W/$1
  if [ -f $dir/LATEST ]; then
    RAYON_NUM_THREADS=10 $B/nova-chain resume --dir $dir --headers $H --to $3 --every 2000
  else
    RAYON_NUM_THREADS=10 $B/nova-chain run --network mainnet --k 1 --headers $H --out $dir --start $2 --to $3 --every 2000
  fi
}
case "$1" in
  check)
    /usr/bin/time -f "native-check %e s %M KB" $B/nova-chain native-check --network mainnet --headers $H --core-ref $D/core_ref.tsv 2>&1 | tail -4 | cut -c1-400 ;;
  run)
    echo "tip $TIP mid $MID; start $(date -u +%FT%TZ)"
    ( shard s0 0 $MID > $W/s0.log 2>&1; echo "s0 exit $?" >> $W/s0.log ) &
    ( shard s1 $MID $TIP > $W/s1.log 2>&1; echo "s1 exit $?" >> $W/s1.log ) &
    wait; echo "end $(date -u +%FT%TZ)"; tail -2 $W/s0.log $W/s1.log | cut -c1-300 ;;
  status)
    date -u +%T; for s in s0 s1; do echo "$s: $(grep -E 'generation' $W/$s.log | tail -1 | cut -c1-120)"; done ;;
esac
