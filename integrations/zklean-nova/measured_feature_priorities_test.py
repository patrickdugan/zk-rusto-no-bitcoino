#!/usr/bin/env python3
"""Implementation tests; these records never enter measured corpus coverage."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import measured_feature_priorities as measured


class MeasuredFeatureTests(unittest.TestCase):
    def record(self):
        return {"schema": measured.RESULT_SCHEMA, "lane": "unit", "name": "Unit.proof", "kind": "theorem",
                "is_proof": True, "status": "unrepresentable",
                "remaining_blockers": ["unknown_constant", "definition_unavailable", "unknown_constant"],
                "original_blockers": ["unknown_constant"], "eligibility_blockers": [],
                "eligibility": {**{key: True for key in measured.ELIGIBILITY_KEYS}, "axioms": []},
                "original": {"module": "Unit", "provenance": {"kernel_check": {"status": "passed"}}},
                "lowering": {"details": [{"tag": "definition_unavailable", "name": "Eq.symm", "kind": "theorem"}],
                             "events": []},
                "node_counts": {"expression_nodes": 2, "level_nodes": 0,
                                "goal_expression_nodes": 1, "proof_expression_nodes": 1,
                                "constant_occurrences": {"Eq.symm": 2}, "expression_tags": {"const": 2}}}

    def test_per_declaration_histograms_and_occurrences_have_distinct_units(self):
        scope = measured.Scope()
        record = self.record()
        record["lowering"]["details"] *= 2
        scope.add(record)
        report = scope.result()
        self.assertEqual(report["remaining_blockers"]["unknown_constant"], 1)
        self.assertEqual(report["raw_constant_declarations"]["Eq.symm"], 1)
        self.assertEqual(report["raw_constant_occurrences"]["Eq.symm"], 2)
        self.assertEqual(report["observed_unresolved_constants"]["Eq.symm"], 1)
        self.assertEqual(report["probe_candidates"]["only_theorem_dependencies_observed"], 1)

    def test_probe_excludes_capped_or_mixed_unresolved_diagnostics(self):
        record = self.record()
        record["lowering"]["details"] *= 200
        self.assertFalse(measured.candidates(record)["only_theorem_dependencies_observed"])
        record = self.record()
        record["lowering"]["details"].append({"tag": "definition_unavailable", "name": "Other", "kind": "opaque"})
        self.assertFalse(measured.candidates(record)["only_theorem_dependencies_observed"])

    def fixture(self, root):
        source = {"repository": "unit/only", "commit": "0" * 40, "path": "Unit.lean",
                  "sha256": "0" * 64, "module": "Unit"}
        first = self.record()
        second = {**copy.deepcopy(first), "name": "Unit.data", "kind": "definition", "is_proof": False}
        records = [first, second]
        lane_dir = root / "unit" / "import"
        lane_dir.mkdir(parents=True)
        result_path = lane_dir / "results.jsonl"
        summary = {"schema": measured.SUMMARY_SCHEMA, "lane": "unit", "source_build": {"source_files": [source]},
                   "denominators": {"identified_proof_declarations": 1}}
        collection = {"schema": "zkl-nova-18/owned-export-collection-v1", "status": "completed",
                      "batches": [{"status": "completed", "lane": "unit", "records": 2,
                                   "identified_proofs": 1, "source_files": [source]}],
                      "exporter_sha256": "0" * 64, "source_file_denominator": 1, "build_statuses": {"compiled": 1},
                      "failed_module_export_count": 0, "full_catalog_proof_coverage_known": False,
                      "declaration_denominator_scope": "Unit test only, excluded from corpus coverage."}
        cohort = {"lanes": [{"id": "unit", "names": [r["name"] for r in records], "source_files": [source]}]}
        (root / "collection.json").write_text(json.dumps(collection))
        (root / "cohort.json").write_text(json.dumps(cohort))

        def write(rows):
            encoded = ("\n".join(json.dumps(r) for r in rows) + "\n").encode()
            result_path.write_bytes(encoded)
            summary["results_file"] = {"bytes": len(encoded), "sha256": hashlib.sha256(encoded).hexdigest()}
            (lane_dir / "summary.json").write_text(json.dumps(summary))
        write(records)
        return result_path, records, write

    def test_streamed_measurement_requires_hash_and_exact_cohort_order(self):
        with tempfile.TemporaryDirectory(prefix="measured-feature-unit-") as directory:
            root = Path(directory)
            result, records, write = self.fixture(root)
            report = measured.measure(root / "collection.json")
            self.assertEqual(report["denominators"]["identified_proof_declarations"], 1)
            self.assertEqual(report["proof_scopes"]["fully_eligible_proofs"]["proof_declarations"], 1)
            result.write_bytes(result.read_bytes() + b"\n")
            with self.assertRaisesRegex(ValueError, "lane result hash"):
                measured.measure(root / "collection.json")
            write(list(reversed(records)))
            with self.assertRaisesRegex(ValueError, "fixed cohort name/order"):
                measured.measure(root / "collection.json")

    def test_source_join_rejects_changed_module_pin(self):
        with tempfile.TemporaryDirectory(prefix="measured-feature-unit-") as directory:
            root = Path(directory)
            self.fixture(root)
            cohort_path = root / "cohort.json"
            cohort = json.loads(cohort_path.read_text())
            cohort["lanes"][0]["source_files"][0]["sha256"] = "1" * 64
            cohort_path.write_text(json.dumps(cohort))
            with self.assertRaisesRegex(ValueError, "cohort source join"):
                measured.measure(root / "collection.json")


if __name__ == "__main__":
    unittest.main()
