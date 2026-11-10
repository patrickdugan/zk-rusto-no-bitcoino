#!/bin/bash
# M16 mainnet after fold-mainnet.sh: export both shards, verify them natively, package the segments,
# CPU-execute the raw-key guest, check the compressed key is refused, then the 13 mutations.
set -o pipefail
export PATH=/root/.cargo/bin:/usr/local/bin:/usr/bin:/bin
B=/root/nhc/target/release; W=/root/m16-nova; T=/root/m16-main; mkdir -p $T; cd $T
X=/root/nb3/m16/sp1/script/target/release/m16-nova-spv-script
RAW=/root/m16-test/k1-mainnet-raw.vk; cp /mnt/d/m16-mainnet/payment.bin $T/payment.bin
echo "start $(date -u +%FT%TZ)"
for s in s0 s1; do
  [ -f $T/$s.nhc1 ] || /usr/bin/time -f "export $s %e s %M KB" $B/nova-chain export --dir $W/$s --bundle $T/$s.nhc1 --vk-out $T/k1.vk 2>&1 | tail -2 | cut -c1-300 || exit 1
  /usr/bin/time -f "verify-bundle $s %e s %M KB" $B/btc-header-fold verify-bundle $T/$s.nhc1 --vk $T/k1.vk 2>&1 | tail -2 | cut -c1-400 || exit 1
done
sha256sum $T/k1.vk /root/nhc/bench/k1-mainnet.vk $RAW $T/s0.nhc1 $T/s1.nhc1 $T/payment.bin /root/nb3/m16/m16.elf
$X segments $T/seg.bin $T/s0.nhc1 $T/s1.nhc1 || exit 1
echo "--- execute (raw key)"
M16_PUBLIC_OUT=$T/public.bin /usr/bin/time -f "execute %e s %M KB" $X execute $RAW $T/seg.bin $T/payment.bin > exec.json 2> exec.err; echo "execute rc $?"
cat exec.json; tail -3 exec.err; sha256sum $T/public.bin
echo "--- compressed key must be refused"
$X execute $T/k1.vk $T/seg.bin $T/payment.bin > /dev/null 2>&1; echo "compressed-key rc $? (nonzero = refused)"
echo "--- mutations"
/usr/bin/time -f "mutations %e s" $X mutations $RAW $T/seg.bin $T/payment.bin 2>&1 | grep -E '"case"|all mutations|mutations [0-9]|Error' | cut -c1-160
echo "end $(date -u +%FT%TZ)"
