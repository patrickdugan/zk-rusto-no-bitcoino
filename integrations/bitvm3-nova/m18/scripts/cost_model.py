#!/usr/bin/env python3
"""Cost model for M18 from the measured results: constraints and minutes per block and for the
window, per absorb width c. Reads results/*.json, prints a table and writes results/cost-model.json.

A step is c SHA-256 compressions of one transaction plus one map op (measured together by the
fold-timing circuit), plus the units the design puts in every step: one Merkle merge (3
compressions), the txid finish (1) and the header hash (3), each at the measured compression cost.
The step count of a block is the largest of its events, its absorb steps and its Merkle merges:
every event takes one step, and the absorb and merge streams must also fit.
"""
import json, os
R = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "results")
nat = json.load(open(f"{R}/native-975067-975072.json"))
con = json.load(open(f"{R}/constraints.json"))
runs = [json.load(open(f"{R}/{f}"))["rows"] for f in ("fold-timing-run1.json", "fold-timing.json")]
# Per-run, per-c step times vary with the load of the shared laptop; the model uses the pooled
# rate: total steady seconds over total million constraints, both runs and all three c.
rows_all = [r for run in runs for r in run]
pooled = sum(r["seconds_per_step_steady"] for r in rows_all) / sum(r["step_constraints"] / 1e6 for r in rows_all)
sha = con["sha256_compression"]
step_c = {r["c"]: r["constraints"] for r in con["bench_step_constraints_by_c"]}
out = {"sha256_compression": sha, "pooled_seconds_per_million_constraints": pooled, "rows": []}
print(f"pooled rate {pooled:.2f} s per million constraints")
for c in (1, 4, 8):
    per_step = step_c[c] + 7 * sha
    spm = pooled
    blocks = []
    for b in nat["blocks"]:
        events = b["creates"] + b["spends_in_window"] + b["spends_before_window"]
        steps = max(events, b[f"absorb_steps_c{c}"], b["merkle_merges"])
        blocks.append({"height": b["height"], "events": events, "steps": steps,
                       "constraints": steps * per_step,
                       "minutes": steps * per_step / 1e6 * spm / 60})
    tot_steps = sum(b["steps"] for b in blocks)
    row = {"c": c, "constraints_per_step": per_step, "seconds_per_million_constraints": spm,
           "seconds_per_step": per_step / 1e6 * spm,
           "steps_per_block_avg": tot_steps / len(blocks),
           "constraints_per_block_avg": tot_steps * per_step / len(blocks),
           "minutes_per_block_avg": sum(b["minutes"] for b in blocks) / len(blocks),
           "window_steps": tot_steps, "window_constraints": tot_steps * per_step,
           "window_hours": sum(b["minutes"] for b in blocks) / 60, "blocks": blocks}
    out["rows"].append(row)
    print(f"c={c}: {per_step} constraints/step, {row['seconds_per_step']:.1f} s/step, "
          f"{row['steps_per_block_avg']:.0f} steps/block, {row['constraints_per_block_avg']/1e9:.2f} G constraints/block, "
          f"{row['minutes_per_block_avg']:.0f} min/block, window {row['window_hours']:.1f} h")
json.dump(out, open(f"{R}/cost-model.json", "w"), indent=2)
