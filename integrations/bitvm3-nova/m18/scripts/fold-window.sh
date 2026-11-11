#!/bin/bash
# fold-window.sh <work-dir> [m16-public.bin]
# Folds every traced segment of a work directory (`m18 trace`, then `m18 params`) in parallel,
# compresses the folded segments one at a time, then verifies the window. Rerunning resumes:
# folded segments are skipped and an interrupted segment restarts from its checkpoint.
# Env: B (m18 binary), THREADS (rayon threads per segment), EVERY (checkpoint interval, steps).
set -u
W=$1
M16=${2:-}
B=${B:-/root/m18/target/release/m18}
THREADS=${THREADS:-2}
EVERY=${EVERY:-250}
n=$(ls $W/seg-*.wit | wc -l)
echo "$(date -Is) start: $n segments, $THREADS threads each, checkpoint every $EVERY steps"
for i in $(seq 0 $((n - 1))); do
  (
    RAYON_NUM_THREADS=$THREADS nice -n 5 $B fold-seg $W $i $EVERY >> $W/seg-$i.out 2>&1 || { echo "$(date -Is) segment $i fold failed"; exit 1; }
    if [ ! -f $W/seg-$i.proof ]; then
      flock $W/compress.lock env RAYON_NUM_THREADS=8 $B compress-seg $W $i >> $W/seg-$i.out 2>&1 || { echo "$(date -Is) segment $i compress failed"; exit 1; }
    fi
    echo "$(date -Is) segment $i proved"
  ) &
done
wait
if [ $(ls $W/seg-*.proof | wc -l) -eq $n ]; then
  $B verify-window $W $M16 && echo "$(date -Is) window verified"
else
  echo "$(date -Is) not every segment proved"
fi
