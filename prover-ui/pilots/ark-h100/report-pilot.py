"""Measure durable output during the pilot, excluding replay and warm-up."""
import json
from pathlib import Path
import sys


def summarize(trial):
    start = int((trial / "pilot-start-unix").read_text())
    end = int((trial / "pilot-end-unix").read_text())
    warmup_end = start + 600
    seen = {"shard": set(), "reduce": set()}
    measured = {"shard": 0, "reduce": 0}
    replays = {"shard": 0, "reduce": 0}
    with (trial / "cache/progress.jsonl").open() as progress:
        for line in progress:
            try:
                event = json.loads(line)
            except ValueError:
                continue
            kind, key, stamp, replayed = (event.get(name) for name in ("kind", "key", "t", "replayed"))
            if kind not in seen or not key or not isinstance(stamp, (int, float)):
                continue
            if start <= stamp <= end and replayed is True:
                replays[kind] += 1
            if key not in seen[kind] and warmup_end <= stamp <= end and replayed is False:
                measured[kind] += 1
            seen[kind].add(key)
    minutes = max(0, end - warmup_end) / 60
    return {
        "status": "throughput_sample" if minutes >= 30 else "insufficient_measurement_time",
        "exit_code": int((trial / "pilot-exit-code").read_text()),
        "sample_minutes": round(minutes, 2),
        "replays_during_pilot": replays,
        "fresh_after_warmup": measured,
        "per_minute": {kind: round(count / minutes, 2) if minutes else None for kind, count in measured.items()},
        "compressed_output_present": (trial / "compressed.bin").is_file(),
    }


if __name__ == "__main__":
    print(json.dumps(summarize(Path(sys.argv[1])), indent=2))
