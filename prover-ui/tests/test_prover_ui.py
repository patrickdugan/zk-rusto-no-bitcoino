"""Unit and HTTP integration tests for ZK Rusto no Bitcoino Prover UI."""
from __future__ import annotations

from http.client import HTTPConnection
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest

from rbzk_prover_ui.campaigns import load_campaigns
from rbzk_prover_ui.correlator import (
    circuit_basis_points,
    estimate_ark_live_completion,
    estimate_workload,
)
from rbzk_prover_ui.server import ProverUIApp, create_server
from rbzk_prover_ui.telemetry import ProgressTailCache, TelemetryCollector


class ProverUITestSuite(unittest.TestCase):
    def test_incremental_progress_cache_deduplicates_replays(self) -> None:
        cache = ProgressTailCache()
        with tempfile.TemporaryDirectory() as tmp:
            prog = Path(tmp) / "progress.jsonl"
            now = int(time.time())
            prog.write_text(
                "\n".join(
                    [
                        json.dumps({"key": "k1", "kind": "shard", "ms": 31000, "replayed": True, "t": now - 40}),
                        json.dumps({"key": "k2", "kind": "shard", "ms": 42000, "replayed": False, "t": now - 30}),
                        json.dumps({"key": "r1", "kind": "reduce", "ms": 51000, "replayed": False, "t": now - 20}),
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            first = cache.read(prog)
            self.assertEqual(first["unique_shards"], 2)
            self.assertEqual(first["unique_reduces"], 1)
            self.assertEqual(first["total_rows"], 3)

            # Append another replay of k1 and a new reduce r2
            with prog.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps({"key": "k1", "kind": "shard", "ms": 5, "replayed": True, "t": now - 10}) + "\n")
                fh.write(json.dumps({"key": "r2", "kind": "reduce", "ms": 48000, "replayed": False, "t": now - 5}) + "\n")

            second = cache.read(prog)
            self.assertEqual(second["unique_shards"], 2)
            self.assertEqual(second["unique_reduces"], 2)
            self.assertEqual(second["total_rows"], 5)
            self.assertEqual(second["replayed_rows_by_kind"]["shard"], 2)
            self.assertEqual(second["proved_rows_by_kind"]["reduce"], 2)

    def test_campaign_inventory_has_no_fixtures(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.assertEqual(load_campaigns(root)["campaigns"], [])
            (root / "results").mkdir()
            report = root / "results/proof.json"
            report.write_text('{"status":"pending"}')
            self.assertEqual(load_campaigns(root)["campaigns"][0]["summary"]["status"], "pending")
            report.unlink()
            self.assertEqual(load_campaigns(root)["campaigns"], [])

    def test_correlator_matches_m16_measured_baseline_and_scales(self) -> None:
        m16_est = estimate_workload(
            {
                "header_blocks": 975072,
                "nova_header_shards": 2,
                "utxo_window_blocks": 0,
                "payment_utxos": 1,
                "shinigami_leaves": 0,
                "ark_vtxos": 0,
                "element_threshold_exp": 27,
                "hardware_profile": "rtx5080_12gib",
            }
        )
        self.assertEqual(m16_est["evidence_level"], "analytical-projection-from-measured-constants")
        # Within 1% of measured 13,290 core shards and 4,430 recursion shards
        self.assertAlmostEqual(m16_est["sp1"]["core_shards"], 13290, delta=120)
        self.assertAlmostEqual(m16_est["sp1"]["recursion_shards"], 4430, delta=50)

        # Halving element threshold from 2^27 to 2^26 doubles shard count
        bounded = estimate_workload(
            {
                "header_blocks": 975072,
                "nova_header_shards": 2,
                "payment_utxos": 1,
                "element_threshold_exp": 26,
                "hardware_profile": "rtx5080_bounded_2gib",
            }
        )
        self.assertGreater(bounded["sp1"]["core_shards"], m16_est["sp1"]["core_shards"] * 1.9)
        self.assertEqual(bounded["resources"]["linux_cgroup_ram_gib"], 2.0)

        # Adding M18 window blocks, Shinigami leaves, and Ark VTXOs increases constraints & shards
        combo = estimate_workload(
            {
                "header_blocks": 1000,
                "nova_header_shards": 1,
                "utxo_window_blocks": 6,
                "payment_utxos": 4,
                "shinigami_leaves": 32,
                "ark_vtxos": 64,
                "element_threshold_exp": 27,
            }
        )
        self.assertEqual(combo["nova"]["m18_window_segments"], 8)
        self.assertGreater(combo["sp1"]["shard_attribution"]["shinigami_leaves"], 0)
        self.assertGreater(combo["sp1"]["shard_attribution"]["ark_vtxo_policy"], 0)

        # Commitment-basis scaling: ARK1 (19,113 -> 2^15+2^14=49,152) is 1/3 of NHC1 (82,809 -> 147,456)
        self.assertEqual(circuit_basis_points(82_809), 147_456)
        self.assertEqual(circuit_basis_points(19_113), 49_152)

        comp = estimate_ark_live_completion(
            unique_shards=1247,
            unique_reduces=1201,
            element_threshold=67_108_864,
            ark_vtxos=4,
            session_summary={
                "session_shards_proved": 116,
                "session_shards_replayed": 1131,
                "session_recursion_proved": 169,
                "session_recursion_replayed": 236,
            },
            rates={"shard_per_min_15m": 2.4},
            compressed_verified=False,
        )
        self.assertFalse(comp["is_exact"])
        self.assertEqual(comp["active_tree_reduce_done"], 405)
        self.assertEqual(comp["regrouped_extra_reduces"], 796)
        self.assertGreater(comp["core_total_est"], 5500)
        self.assertLess(comp["core_total_est"], 7200)
        self.assertGreater(comp["overall_pct"], 15.0)
        self.assertLess(comp["overall_pct"], 25.0)
        self.assertIsNotNone(comp["eta_hours_est"])
        self.assertGreater(comp["core_eta_seconds"], 0)
        self.assertGreater(comp["sp1_eta_seconds"], comp["core_eta_seconds"])
        self.assertGreater(comp["e2e_eta_seconds"], comp["sp1_eta_seconds"])

    def test_http_endpoints_and_host_header_guard(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            prover_dir = root / "prover-transient"
            prover_dir.mkdir()
            phase_dir = root / "pipeline-gpu-100"
            phase_dir.mkdir()
            (root / "pipeline-status.json").write_text(
                json.dumps(
                    {
                        "status": "gpu",
                        "prover_backend": "CUDA test backend",
                        "phases": {"gpu": str(phase_dir)},
                    }
                ),
                encoding="utf-8",
            )
            # Rewrite _wsl_path_to_windows behavior implicitly when path is already local via custom collector
            (prover_dir / "progress.jsonl").write_text(
                json.dumps({"key": "a1", "kind": "shard", "ms": 12000, "replayed": False, "t": int(time.time())})
                + "\n",
                encoding="utf-8",
            )
            hb = root / "host.json"
            hb.write_text(
                json.dumps(
                    {
                        "schema": "ark-host-resources-v1",
                        "sample_unix": time.time(),
                        "total_bytes": 50592600064,
                        "available_bytes": 8589934592,
                        "memory_floor_bytes": 3221225472,
                        "immediate_memory_floor_bytes": 536870912,
                        "stop_reason": None,
                    }
                ),
                encoding="utf-8",
            )

            app = ProverUIApp(wsl_ark_base=root, host_heartbeat_path=hb, pipeline_log_path=root / "pipe.log", ark_dir=root)
            srv = create_server(host="127.0.0.1", port=0, app=app)
            port = srv.server_address[1]
            thread = threading.Thread(target=srv.serve_forever, daemon=True)
            thread.start()
            try:
                conn = HTTPConnection("127.0.0.1", port, timeout=5)
                conn.request("GET", "/")
                res = conn.getresponse()
                html = res.read().decode("utf-8")
                self.assertEqual(res.status, 200)
                self.assertIn("zk-rusto-no-bitcoino", html)

                conn.request("GET", "/api/live")
                res = conn.getresponse()
                live = json.loads(res.read().decode("utf-8"))
                self.assertEqual(res.status, 200)
                self.assertEqual(live["wsl_prover"]["progress"]["unique_shards"], 1)
                self.assertEqual(live["wsl_prover"]["progress"]["seq"], 1)
                self.assertEqual(len(live["wsl_prover"]["progress"]["mosaic_tail"]), 1)
                self.assertFalse(live["wsl_prover"]["phase_running"])
                self.assertIn("mode", live["wsl_prover"]["liveness"])
                self.assertIsNone(live["wsl_prover"]["completion"])
                self.assertIn("completion", live["wsl_prover"])
                self.assertIsNone(live["wsl_prover"]["completion"])
                self.assertTrue(live["host_guard"]["fresh"])

                # Test SSE /api/stream emits a telemetry frame immediately
                sse_conn = HTTPConnection("127.0.0.1", port, timeout=5)
                sse_conn.request("GET", "/api/stream")
                sse_res = sse_conn.getresponse()
                self.assertEqual(sse_res.status, 200)
                self.assertIn("text/event-stream", sse_res.getheader("Content-Type") or "")
                event_line = sse_res.fp.readline().decode("utf-8")
                data_line = sse_res.fp.readline().decode("utf-8")
                self.assertEqual(event_line.strip(), "event: telemetry")
                self.assertTrue(data_line.startswith("data: "))
                sse_payload = json.loads(data_line[len("data: ") :])
                self.assertEqual(sse_payload["wsl_prover"]["progress"]["unique_shards"], 1)
                sse_conn.close()

                conn.request("GET", "/api/campaigns")
                res = conn.getresponse()
                camps = json.loads(res.read().decode("utf-8"))
                self.assertEqual(res.status, 200)
                self.assertEqual(camps["campaigns"], [])

                conn.request(
                    "POST",
                    "/api/correlate",
                    body=json.dumps({"header_blocks": 975072, "nova_header_shards": 2, "payment_utxos": 1}),
                    headers={"Content-Type": "application/json"},
                )
                res = conn.getresponse()
                corr = json.loads(res.read().decode("utf-8"))
                self.assertEqual(res.status, 200)
                self.assertGreater(corr["sp1"]["core_shards"], 13000)

                # Non-loopback Host header must be rejected
                conn.request("GET", "/api/live", headers={"Host": "evil.example.com"})
                res = conn.getresponse()
                res.read()
                self.assertEqual(res.status, 403)
                conn.close()
            finally:
                srv.shutdown()
                srv.server_close()


if __name__ == "__main__":
    unittest.main()
