#!/bin/sh
for i in $(seq 1 1); do
  s=$((100000 + i * 1000))
  RAYON_NUM_THREADS=8 /home/ubuntu/tn4-build/nova-header-chain/target/release/nova-chain run --network testnet4 --k 5 --headers /home/ubuntu/tn4-data/headers.bin --start $s --to $((s + 200)) --every 1000 --out /home/ubuntu/tn4-runs/throughput/p1/c$i > /home/ubuntu/tn4-runs/throughput/p1/c$i.json 2> /home/ubuntu/tn4-runs/throughput/p1/c$i.err &
done
wait
