"""Regression checks for the Ark H100 throughput report."""

import json
from pathlib import Path
import runpy
import tempfile
import unittest


PILOT = Path(__file__).resolve().parents[1] / "pilots" / "ark-h100"
summarize = runpy.run_path(str(PILOT / "report-pilot.py"))["summarize"]


class PilotReportTests(unittest.TestCase):
    def summarize_run(self, events, duration):
        with tempfile.TemporaryDirectory() as directory:
            trial = Path(directory)
            (trial / "cache").mkdir()
            (trial / "pilot-start-unix").write_text("1000", encoding="ascii")
            (trial / "pilot-end-unix").write_text(str(1000 + duration), encoding="ascii")
            (trial / "pilot-exit-code").write_text("124", encoding="ascii")
            (trial / "cache" / "progress.jsonl").write_text(
                "\n".join(json.dumps(dict(kind=kind, key=key, t=stamp, replayed=replayed))
                          for kind, key, stamp, replayed in events),
                encoding="utf-8",
            )
            return summarize(trial)

    def test_counts_only_fresh_unique_checkpoints_after_warmup(self):
        result = self.summarize_run(
            [
                ("shard", "retained", 999, False),
                ("shard", "retained", 1700, True),
                ("shard", "warm", 1200, False),
                ("shard", "warm", 1750, False),
                ("shard", "fresh", 1800, False),
                ("shard", "fresh", 1801, False),
                ("reduce", "fresh", 1900, False),
                ("shard", "outside", 4000, False),
            ],
            duration=2400,
        )
        self.assertEqual(result["status"], "throughput_sample")
        self.assertEqual(result["fresh_after_warmup"], {"shard": 1, "reduce": 1})
        self.assertEqual(result["replays_during_pilot"], {"shard": 1, "reduce": 0})
        self.assertEqual(result["per_minute"], {"shard": 0.03, "reduce": 0.03})
        self.assertFalse(result["compressed_output_present"])

    def test_short_run_is_missing_a_comparable_sample(self):
        result = self.summarize_run([], duration=599)
        self.assertEqual(result["status"], "insufficient_measurement_time")
        self.assertEqual(result["per_minute"], {"shard": None, "reduce": None})
