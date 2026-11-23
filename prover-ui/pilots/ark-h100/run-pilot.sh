#!/usr/bin/env bash
set -euo pipefail
umask 077
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
trial=$(realpath -- "${1:?pass the isolated directory containing the extracted cache}")
case "$trial" in
    /workspace/ark-h100-*) ;;
    *) printf 'Use a new /workspace/ark-h100-* trial directory.\n' >&2; exit 2 ;;
esac
cd "$trial"
test -d cache && test ! -L cache
exec 9>pilot.lock
flock -n 9
test ! -e pilot-start-unix && test ! -e compressed.bin

gpu=$(nvidia-smi --query-gpu=name,memory.total,compute_cap --format=csv,noheader,nounits)
printf '%s\n' "$gpu" > gpu-start.txt
test "$(printf '%s\n' "$gpu" | wc -l)" -eq 1
printf '%s\n' "$gpu" | grep -E 'H100.*(HBM3|SXM).*9\.0[[:space:]]*$'
test "$(df --output=avail -B1 . | tail -1)" -ge 34359738368
config_sha=a800d7026670d6d2a1240ea6e60d1f8171b2216ffe103b8e826cd36693ce3238
printf '%s  cache/run.json\n' "$config_sha" | sha256sum -c -
(cd "$here" && sha256sum -c hopper-binary.sha256 && sha256sum -c inputs.sha256)

export CUDA_VISIBLE_DEVICES=0
export CUDA_CACHE_PATH="$trial/cuda-cache"
export ARK_SP1_TRANSIENT_TRACES=1
export NB3_GPU_MEMORY_SAVER=1 NB3_GPU_RECOMPUTE_GKR=0 NB3_GPU_DROP_LDES=1
export NB3_GPU_COMPOSE_ARITY=2 SP1_WORKER_MAX_COMPOSE_ARITY=4
export SP1_WORKER_NORMALIZE_PROGRAM_CACHE_SIZE=0 RUST_LOG=info
for name in NUM_CORE_WORKERS NUM_SPLICING_WORKERS NUM_RECURSION_EXECUTOR_WORKERS \
    NUM_PREPARE_REDUCE_WORKERS NUM_RECURSION_PROVER_WORKERS NUM_SETUP_WORKERS \
    NUM_DEFERRED_WORKERS CORE_BUFFER_SIZE RECURSION_EXECUTOR_BUFFER_SIZE \
    RECURSION_PROVER_BUFFER_SIZE SETUP_BUFFER_SIZE NUMBER_OF_GAS_EXECUTORS \
    NUMBER_OF_SEND_SPLICE_WORKERS_PER_SPLICE SPLICING_BUFFER_SIZE; do
    export "SP1_WORKER_${name}=1"
done

seconds="${PILOT_SECONDS:-3300}"
[[ "$seconds" =~ ^[1-9][0-9]{0,3}$ ]] && (( seconds <= 3300 ))
date +%s > pilot-start-unix
status=0
timeout --signal=TERM --kill-after=20s "${seconds}s" \
    "$here/hopper-target/release/ark-prove-gpu-cached-gkr" prove \
    --elf "$here/inputs/guest.elf" \
    --input "$here/inputs/nova-vk.raw" --input "$here/inputs/nova-proof.arp" \
    --run-dir "$trial/cache" --out "$trial/compressed.bin" \
    --element-threshold 67108864 --height-threshold 4194304 --shard-size 16777216 \
    --trace-chunk-threshold 16777216 --trace-buffers 1 --trace-chunk-slots 1 \
    --permits 1 > prover.log 2>&1 || status=$?
date +%s > pilot-end-unix
printf '%s\n' "$status" > pilot-exit-code
python3 "$here/report-pilot.py" "$trial" > pilot-result.json
cat pilot-result.json
if (( status != 124 )); then
    exit "$status"
fi
