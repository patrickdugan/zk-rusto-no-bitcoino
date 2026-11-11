#!/bin/bash
# Exercises supervise.sh with a fake prover: an outside SIGTERM then success, a real failure, and a
# stall. Shared-memory cleanup runs on a temporary directory, never /dev/shm. Needs fuser (psmisc).
set -u
HERE=$(cd "$(dirname "$0")" && pwd); T=$(mktemp -d); trap 'kill $HOLD 2>/dev/null; rm -rf "$T"' EXIT
fail() { echo "FAIL: $*"; exit 1; }
export SHM_GLOB="$T/shm/sp1_*" RESUME_SEC=1 POLL_SEC=1
mkdir -p "$T/shm" "$T/run"

# 1. Killed from outside on the first attempt, finishes on the second. The orphaned file goes, the
#    file a live process holds stays.
cat > "$T/fake.sh" <<'EOF'
#!/bin/bash
if [ ! -e "$1/first" ]; then touch "$1/first" "$1/shm/sp1_orphan_t"; kill -TERM $$; fi
exit 0
EOF
chmod +x "$T/fake.sh"
touch "$T/shm/sp1_held_t"; sleep 60 < "$T/shm/sp1_held_t" & HOLD=$!
OUT=$(MAX_TRIES=3 bash "$HERE/supervise.sh" "$T/run" -- "$T/fake.sh" "$T"); RC=$?
[ $RC = 0 ] || fail "outside kill then success: exit $RC"; echo "$OUT" | grep -q 'attempt 2' || fail "no second attempt"
echo "$OUT" | grep -q 'killed from outside (exit 143)' || fail "SIGTERM not recognised"
[ -e "$T/shm/sp1_orphan_t" ] && fail "orphaned shm file kept"; [ -e "$T/shm/sp1_held_t" ] || fail "held shm file removed"
echo "ok: outside SIGTERM resumes, orphaned shm removed, held shm kept"

# 2. A real failure is not retried.
OUT=$(MAX_TRIES=3 bash "$HERE/supervise.sh" "$T/run" -- bash -c 'exit 3'); RC=$?
[ $RC = 3 ] || fail "real failure: exit $RC"; echo "$OUT" | grep -q 'attempt 2' && fail "real failure retried"
echo "ok: a real failure exits with its code, no retry"

# 3. A stalled run (no memo record) is restarted, then given up on.
touch "$T/shm/sp1_stalled_t"
OUT=$(MAX_TRIES=2 STALL_SEC=1 bash "$HERE/supervise.sh" "$T/run" -- sleep 120); RC=$?
[ $RC = 1 ] || fail "stall: exit $RC"; echo "$OUT" | grep -q 'gave up after 2 attempts' || fail "stall not given up"
[ -e "$T/shm/sp1_stalled_t" ] && fail "orphaned shm kept after a stall"
echo "ok: a stall restarts, cleans shm and gives up after MAX_TRIES"
echo "all supervise.sh tests passed"
