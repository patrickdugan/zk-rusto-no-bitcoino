"""Synthetic structural tests only. No Bitcoin or SNARK verification occurs."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import recursive_checkpoint_gate as gate


class GateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        payload = b"SYNTHETIC UNIT TEST REPORT: no proof was verified.\n"
        (self.root / "report.log").write_bytes(payload)
        self.doc = gate.template()
        # Testing the accepted structural shape requires operator_report. These
        # generated in-memory values are fake and are never shipped as evidence.
        self.doc["evidence_kind"] = "operator_report"
        self.doc["candidate"] = {
            "commit": "a" * 40, "backend": gate.BACKEND, "network": "mainnet",
            "profile": "small-k5", "binary_sha256": "1" * 64,
            "verifier_key_sha256": "2" * 64, "lockfile_sha256": "3" * 64,
            "checkpoint_state_sha256": "4" * 64, "anchor_policy_sha256": "5" * 64,
        }
        self.doc["artifacts"] = {"report": {
            "path": "report.log", "sha256": hashlib.sha256(payload).hexdigest(),
            "size_bytes": len(payload),
        }}
        for check in self.doc["checks"]:
            check.update(status="pass", artifacts=["report"], notes="SYNTHETIC: tests input shape only.")
        for phase in gate.PHASES:
            self.doc["benchmarks"].append(self.run_record(phase, 1000, 1000))
        self.doc["benchmarks"].append(self.run_record("fold", 10000, 1050))

    @staticmethod
    def run_record(phase, headers, peak):
        return {"phase": phase, "headers": headers, "k": 5, "wall_seconds": 12.5,
                "peak_mib": peak, "hard_limit_mib": 1536, "containment": "cgroup-v2",
                "metric": "memory.peak", "swap_max_mib": 0, "process_tree_covered": True,
                "exit_code": 0, "artifact": "report"}

    def review(self, doc=None):
        return gate.review(self.doc if doc is None else doc, self.root)

    def test_complete_shape_never_authorizes_deploy_or_pruning(self):
        out = self.review()
        self.assertEqual(out["status"], "EVIDENCE_COMPLETE_OPERATOR_REVIEW_REQUIRED")
        self.assertFalse(out["deploy_authorized"])
        self.assertFalse(out["prune_authorized"])
        self.assertEqual(out["proofs_cryptographically_verified_by_this_tool"], 0)

    def test_pending_template_is_blocked(self):
        self.assertEqual(self.review(gate.template())["status"], "BLOCKED")

    def test_explicit_synthetic_evidence_is_blocked(self):
        self.doc["evidence_kind"] = "synthetic"
        self.assertEqual(self.review()["status"], "BLOCKED")

    def test_failed_prerequisite_is_blocked(self):
        self.doc["checks"][0]["status"] = "fail"
        self.assertEqual(self.review()["status"], "BLOCKED")

    def test_pending_spv_prerequisite_is_blocked(self):
        self.doc["checks"][1]["status"] = "pending"
        self.assertEqual(self.review()["status"], "BLOCKED")

    def test_missing_candidate_is_blocked(self):
        self.doc["candidate"] = None
        self.doc["benchmarks"] = []
        self.assertEqual(self.review()["status"], "BLOCKED")

    def test_missing_phase_is_blocked(self):
        self.doc["benchmarks"] = [r for r in self.doc["benchmarks"] if r["phase"] != "compress"]
        self.assertEqual(self.review()["status"], "BLOCKED")

    def test_missing_long_run_is_blocked(self):
        self.doc["benchmarks"].pop()
        self.assertEqual(self.review()["status"], "BLOCKED")

    def test_large_memory_growth_is_blocked(self):
        self.doc["benchmarks"][-1]["peak_mib"] = 1200
        self.assertEqual(self.review()["status"], "BLOCKED")

    def test_128_mib_tolerance_boundary(self):
        self.doc["benchmarks"][-1]["peak_mib"] = 1128
        self.assertEqual(self.review()["status"], "EVIDENCE_COMPLETE_OPERATOR_REVIEW_REQUIRED")

    def test_exceeded_cap_is_blocked(self):
        self.doc["benchmarks"][0]["peak_mib"] = 1537
        self.assertEqual(self.review()["status"], "BLOCKED")

    def test_failed_process_is_blocked(self):
        self.doc["benchmarks"][0]["exit_code"] = 137
        self.assertEqual(self.review()["status"], "BLOCKED")

    def test_incomplete_process_tree_is_blocked(self):
        self.doc["benchmarks"][0]["process_tree_covered"] = False
        self.assertEqual(self.review()["status"], "BLOCKED")

    def test_unsupported_claim_fields_rejected(self):
        for field in ("full_consensus_verified", "prune_authorized", "deploy_authorized"):
            with self.subTest(field=field):
                doc = copy.deepcopy(self.doc)
                doc[field] = True
                with self.assertRaises(gate.InvalidEvidence):
                    self.review(doc)

    def test_changed_baseline_rejected(self):
        self.doc["baseline_commit"] = "b" * 40
        with self.assertRaises(gate.InvalidEvidence):
            self.review()

    def test_wrong_network_rejected(self):
        self.doc["candidate"]["network"] = "testnet4"
        with self.assertRaises(gate.InvalidEvidence):
            self.review()

    def test_other_backend_rejected(self):
        self.doc["candidate"]["backend"] = "groth16"
        with self.assertRaises(gate.InvalidEvidence):
            self.review()

    def test_zero_pin_rejected(self):
        self.doc["candidate"]["verifier_key_sha256"] = "0" * 64
        with self.assertRaises(gate.InvalidEvidence):
            self.review()

    def test_nonhex_pin_rejected(self):
        self.doc["candidate"]["binary_sha256"] = "G" * 64
        with self.assertRaises(gate.InvalidEvidence):
            self.review()

    def test_width_change_rejected(self):
        self.doc["benchmarks"][0]["k"] = 10
        with self.assertRaises(gate.InvalidEvidence):
            self.review()

    def test_nondivisible_workload_rejected(self):
        self.doc["benchmarks"][0]["headers"] = 1001
        with self.assertRaises(gate.InvalidEvidence):
            self.review()

    def test_boolean_integer_rejected(self):
        self.doc["benchmarks"][0]["headers"] = True
        with self.assertRaises(gate.InvalidEvidence):
            self.review()

    def test_wrong_cap_rejected(self):
        self.doc["benchmarks"][0]["hard_limit_mib"] = 8192
        with self.assertRaises(gate.InvalidEvidence):
            self.review()

    def test_working_set_metric_rejected(self):
        self.doc["benchmarks"][0]["metric"] = "PeakWorkingSetSize"
        with self.assertRaises(gate.InvalidEvidence):
            self.review()

    def test_polling_only_limit_rejected(self):
        self.doc["benchmarks"][0]["containment"] = "psutil-polling"
        with self.assertRaises(gate.InvalidEvidence):
            self.review()

    def test_linux_swap_rejected(self):
        self.doc["benchmarks"][0]["swap_max_mib"] = 1024
        with self.assertRaises(gate.InvalidEvidence):
            self.review()

    def test_windows_committed_memory_shape(self):
        for r in self.doc["benchmarks"]:
            r.update(containment="windows-job", metric="peak-job-commit", swap_max_mib=None)
        self.assertEqual(self.review()["status"], "EVIDENCE_COMPLETE_OPERATOR_REVIEW_REQUIRED")

    def test_missing_log_is_rejected(self):
        (self.root / "report.log").unlink()
        with self.assertRaises(OSError):
            self.review()

    def test_corrupt_log_is_rejected(self):
        (self.root / "report.log").write_bytes(b"changed")
        with self.assertRaises(gate.InvalidEvidence):
            self.review()

    def test_wrong_log_digest_rejected(self):
        self.doc["artifacts"]["report"]["sha256"] = "7" * 64
        with self.assertRaises(gate.InvalidEvidence):
            self.review()

    def test_empty_evidence_for_pass_is_blocked(self):
        self.doc["checks"][0]["artifacts"] = []
        self.assertEqual(self.review()["status"], "BLOCKED")

    def test_unknown_artifact_rejected(self):
        self.doc["checks"][0]["artifacts"] = ["missing"]
        with self.assertRaises(gate.InvalidEvidence):
            self.review()

    def test_duplicate_check_rejected(self):
        self.doc["checks"][1] = copy.deepcopy(self.doc["checks"][0])
        with self.assertRaises(gate.InvalidEvidence):
            self.review()

    def test_unknown_check_rejected(self):
        self.doc["checks"][0]["id"] = "approve_deploy"
        with self.assertRaises(gate.InvalidEvidence):
            self.review()

    def test_duplicate_fold_workload_rejected(self):
        self.doc["benchmarks"].append(copy.deepcopy(self.doc["benchmarks"][-1]))
        with self.assertRaises(gate.InvalidEvidence):
            self.review()

    def test_path_traversal_rejected(self):
        for path in ("../report.log", "/tmp/report.log", "a/../report.log", "C:\\report.log", "a//b"):
            with self.subTest(path=path):
                doc = copy.deepcopy(self.doc)
                doc["artifacts"]["report"]["path"] = path
                with self.assertRaises(gate.InvalidEvidence):
                    self.review(doc)

    def test_symlink_rejected(self):
        try:
            (self.root / "alias").symlink_to(self.root / "report.log")
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable")
        self.doc["artifacts"]["report"]["path"] = "alias"
        with self.assertRaises(gate.InvalidEvidence):
            self.review()

    def test_duplicate_json_key_rejected(self):
        p = self.root / "input.json"
        p.write_text('{"schema": "a", "schema": "b"}')
        with self.assertRaises(gate.InvalidEvidence):
            gate.load_json(p)

    def test_nonfinite_json_rejected(self):
        for value in ("NaN", "Infinity", "-Infinity"):
            with self.subTest(value=value):
                p = self.root / "input.json"
                p.write_text('{"x": ' + value + '}')
                with self.assertRaises(gate.InvalidEvidence):
                    gate.load_json(p)

    def test_nonfinite_metrics_rejected(self):
        for value in (float("nan"), float("inf"), -1, 0, True):
            with self.subTest(value=value):
                doc = copy.deepcopy(self.doc)
                doc["benchmarks"][0]["peak_mib"] = value
                with self.assertRaises(gate.InvalidEvidence):
                    self.review(doc)

    def test_oversize_json_rejected(self):
        p = self.root / "input.json"
        p.write_bytes(b" " * (gate.MAX_JSON + 1))
        with self.assertRaises(gate.InvalidEvidence):
            gate.load_json(p)

    def test_template_roundtrip(self):
        p = self.root / "input.json"
        p.write_text(json.dumps(gate.template()))
        self.assertEqual(gate.load_json(p), gate.template())


if __name__ == "__main__":
    unittest.main()
