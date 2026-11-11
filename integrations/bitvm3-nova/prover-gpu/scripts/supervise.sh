#!/bin/bash
# Runs an nb3-prove(-gpu) command and restarts it whenever the run directory's memo stops
# advancing, or when something outside the prover (a host memory guard) kills it. A laptop that
# sleeps (Windows Modern Standby, which also starts when the display turns off) can leave the CUDA
# context under WSL2 waiting forever on work that was in flight: the process stays alive with the
# GPU idle. Each restart resumes from the memo.
#
# A killed prover leaves its SP1 shared-memory files behind (up to several GiB each, held in RAM).
# Before each restart the files that no process holds are removed.
#
# usage: supervise.sh RUN_DIR -- nb3-prove-gpu prove ... --run-dir RUN_DIR ...
# env:   STALL_MIN   minutes without a new memo record before a restart (default 15)
#        MAX_TRIES   attempts in total (default 6)
#        RESUME_SEC  pause before restarting after an outside SIGTERM or SIGKILL (default 180)
#        STALL_SEC, POLL_SEC, SHM_GLOB  the stall limit and check interval in seconds, and the
#                    shared-memory files to clean (default /dev/shm/sp1_*) (tests)
set -u
RUN=$1; shift; [ "${1:-}" = "--" ] && shift
STALL=${STALL_SEC:-$(( ${STALL_MIN:-15} * 60 ))}; TRIES=${MAX_TRIES:-6}; POLL=${POLL_SEC:-60}
RESUME=${RESUME_SEC:-180}; SHM=${SHM_GLOB:-/dev/shm/sp1_*}
free_shm() {
  local f n=0
  for f in $SHM; do
    if [ -e "$f" ] && [ -z "$(fuser "$f" 2>/dev/null)" ]; then rm -f "$f"; n=$((n + 1)); fi
  done
  echo "$(date -u +%FT%TZ) removed $n orphaned shared-memory files"
}
for try in $(seq 1 "$TRIES"); do
  echo "$(date -u +%FT%TZ) attempt $try: $*"
  "$@" &
  PID=$!; START=$(date +%s); STALLED=0
  while kill -0 $PID 2>/dev/null; do
    sleep "$POLL"
    LAST=$(stat -c %Y "$RUN/progress.jsonl" 2>/dev/null || echo "$START")
    [ "$LAST" -lt "$START" ] && LAST=$START
    if [ $(( $(date +%s) - LAST )) -gt "$STALL" ]; then
      echo "$(date -u +%FT%TZ) no memo record for $STALL s; restarting"
      STALLED=1; kill $PID; sleep 20; kill -9 $PID 2>/dev/null
    fi
  done
  wait $PID; RC=$?
  if [ $STALLED = 1 ]; then free_shm; continue; fi
  if [ $RC = 143 ] || [ $RC = 137 ]; then
    echo "$(date -u +%FT%TZ) killed from outside (exit $RC); resuming in $RESUME s"
    free_shm; sleep "$RESUME"; continue
  fi
  echo "$(date -u +%FT%TZ) exit $RC"; exit $RC
done
echo "$(date -u +%FT%TZ) gave up after $TRIES attempts"; exit 1
