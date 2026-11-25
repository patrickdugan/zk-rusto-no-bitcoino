#!/usr/bin/env python3
"""Reproduce feature counts from authenticated actual-corpus result files.

Usage:
  python measured_feature_priorities.py --collection EXPORT/collection.json \
    --output measured-feature-priorities.json

Only completed collection batches enter the declaration denominator. Split
retries are excluded. Each result file is streamed, its recorded SHA256 and byte
count are checked, and names must match the fixed cohort in exact order. This
program reads prior measurements; it performs no new lowering or proof checks.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path


RESULT_SCHEMA = "zkl-nova-18/corpus-import-result-v1"
SUMMARY_SCHEMA = "zkl-nova-18/corpus-import-summary-v1"
MAX_RECORD_BYTES = 64 * 1024 * 1024
ELIGIBILITY_KEYS = ("fresh_source_build", "kernel_rechecked", "safe_declaration", "axiom_eligible")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def file_info(path):
    path = Path(path)
    digest, size = hashlib.sha256(), 0
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
            size += len(chunk)
    return {"path": str(path.resolve()), "bytes": size, "sha256": digest.hexdigest()}


def read_json(path):
    data = Path(path).read_bytes()
    return json.loads(data), {"path": str(Path(path).resolve()), "bytes": len(data),
                              "sha256": hashlib.sha256(data).hexdigest()}


def ranked(counter):
    return dict(sorted(counter.items(), key=lambda item: (-item[1], item[0])))


def source_key(source):
    return tuple(source.get(k) for k in ("repository", "commit", "path", "sha256", "module"))


def candidates(record):
    """Bounded experiment cohorts, without estimating future acceptance."""
    remaining = set(record.get("remaining_blockers", []))
    details = record.get("lowering", {}).get("details", [])
    unresolved = {(d.get("name"), d.get("kind")) for d in details
                  if d.get("tag") == "definition_unavailable" and d.get("name")}
    return {
        "only_theorem_dependencies_observed": bool(remaining)
        and remaining <= {"unknown_constant", "definition_unavailable"}
        and bool(unresolved) and len(details) < 200
        and all(kind == "theorem" for _, kind in unresolved),
        "only_symbolic_universe": remaining == {"symbolic_universe"},
        "only_nat_literal_limit": remaining == {"nat_literal_limit"},
        "has_extra_inductive": "unsupported_inductive" in remaining,
        "has_projection": "projection" in remaining,
        "has_unsupported_universe_instance": "unsupported_universe_instance" in remaining,
    }


class Scope:
    def __init__(self):
        self.count = 0
        self.counters = {name: Counter() for name in (
            "statuses", "kinds", "original_blockers", "remaining_blockers", "eligibility_blockers",
            "remaining_blocker_combinations", "raw_constant_declarations", "raw_constant_occurrences",
            "expression_tags", "level_tags", "node_totals", "lowering_events", "axiom_declarations",
            "kernel_check_statuses", "kernel_check_errors", "observed_unresolved_constants",
            "observed_unresolved_constant_kinds", "unsupported_primitive_instances", "probe_candidates",
            "acceptance", "native_row_counts")}
        self.details_at_cap = 0
        self.theorem_only_constants = Counter()

    def add(self, record):
        self.count += 1
        c = self.counters
        c["statuses"][record["status"]] += 1
        c["kinds"][record.get("kind", "unknown")] += 1
        for field in ("original_blockers", "remaining_blockers", "eligibility_blockers"):
            c[field].update(set(record.get(field, [])))
        combination = ", ".join(sorted(set(record.get("remaining_blockers", [])))) or "(none)"
        c["remaining_blocker_combinations"][combination] += 1
        nodes = record.get("node_counts", {})
        for field in ("expression_nodes", "level_nodes", "goal_expression_nodes", "proof_expression_nodes"):
            c["node_totals"][field] += nodes.get(field, 0)
        for field in ("expression_tags", "level_tags"):
            c[field].update(nodes.get(field, {}))
        c["raw_constant_occurrences"].update(nodes.get("constant_occurrences", {}))
        c["raw_constant_declarations"].update(nodes.get("constant_occurrences", {}).keys())
        for event in record.get("lowering", {}).get("events", []):
            c["lowering_events"][event["kind"]] += event["occurrences"]
        eligibility = record.get("eligibility", {})
        c["axiom_declarations"].update(set(eligibility.get("axioms", [])))
        check = record.get("original", {}).get("provenance", {}).get("kernel_check", {})
        c["kernel_check_statuses"][check.get("status", "missing")] += 1
        if check.get("error"):
            c["kernel_check_errors"][check["error"]] += 1
        details = record.get("lowering", {}).get("details", [])
        self.details_at_cap += len(details) >= 200
        unresolved = {(d["name"], d.get("kind", "unknown")) for d in details
                      if d.get("tag") == "definition_unavailable" and d.get("name")}
        c["observed_unresolved_constants"].update(name for name, _ in unresolved)
        c["observed_unresolved_constant_kinds"].update(set(kind for _, kind in unresolved))
        c["unsupported_primitive_instances"].update(set(
            d["name"] + ".{" + ",".join(map(str, d.get("levels", []))) + "}"
            for d in details if d.get("tag") == "unsupported_universe_instance" and d.get("name")))
        probe = candidates(record)
        c["probe_candidates"].update(name for name, selected in probe.items() if selected)
        if probe["only_theorem_dependencies_observed"]:
            self.theorem_only_constants.update(name for name, _ in unresolved)
        for field in ("representable", "native_certificate_accepted", "eligible_native_accepted",
                      "strict_whole_declaration_accepted", "transparent_lowering_accepted"):
            if record.get(field) is True:
                c["acceptance"][field] += 1
        native = record.get("native", {})
        if record.get("native_certificate_accepted"):
            for field in ("rows_le_1024", "current_arithmetic_capacity"):
                if native.get(field):
                    c["acceptance"][field] += 1
            if record.get("eligible_native_accepted") and native.get("current_arithmetic_capacity"):
                c["acceptance"]["eligible_current_arithmetic_capacity"] += 1
            if isinstance(native.get("rows"), int):
                c["native_row_counts"][str(native["rows"])] += 1

    def result(self):
        acceptance = self.counters["acceptance"]
        return {"proof_declarations": self.count,
                **{name: ranked(counter) for name, counter in self.counters.items()},
                "coverage": {name: {"numerator": acceptance[name], "denominator": self.count,
                                    "percent": 100 * acceptance[name] / self.count if self.count else None}
                             for name in ("native_certificate_accepted", "eligible_native_accepted",
                                          "strict_whole_declaration_accepted", "eligible_current_arithmetic_capacity")},
                "lowering_details_at_200_entry_cap": self.details_at_cap,
                "theorem_only_observed_constant_declarations": ranked(self.theorem_only_constants)}


def measure(collection_path, cohort_path=None):
    collection_path = Path(collection_path)
    root = collection_path.parent
    collection, collection_info = read_json(collection_path)
    cohort, cohort_info = read_json(cohort_path or root / "cohort.json")
    require(collection.get("schema") == "zkl-nova-18/owned-export-collection-v1", "collection schema")
    require(collection.get("status") in ("completed", "partial"), "collection has not finished")
    completed = [b for b in collection["batches"] if b["status"] == "completed"]
    require(len({b["lane"] for b in completed}) == len(completed), "duplicate completed lane")
    batches = {b["lane"]: b for b in completed}
    require(len({l["id"] for l in cohort["lanes"]}) == len(cohort["lanes"]), "duplicate cohort lane")
    require(set(batches) == {l["id"] for l in cohort["lanes"]}, "cohort/completed lane mismatch")
    scopes = {name: Scope() for name in ("all_identified_proofs", "source_safe_axiom_eligible_proofs",
                                       "fully_eligible_proofs")}
    repositories, native_records, lane_evidence = {}, [], []
    records, non_proofs, unclassified = 0, 0, 0
    seen_sources, seen_declarations = set(), set()
    for lane in cohort["lanes"]:
        lane_id, names, batch = lane["id"], lane["names"], batches[lane["id"]]
        require(len(set(names)) == len(names), "duplicate fixed cohort names")
        summary, summary_info = read_json(root / lane_id / "import" / "summary.json")
        require(summary.get("schema") == SUMMARY_SCHEMA and summary.get("lane") == lane_id,
                "lane summary identity")
        sources = batch["source_files"]
        expected_sources = sorted(source_key(s) for s in sources)
        require(expected_sources == sorted(source_key(s) for s in lane["source_files"]), "cohort source join")
        require(expected_sources == sorted(source_key(s) for s in summary["source_build"]["source_files"]),
                "summary source join")
        for key in expected_sources:
            require(key not in seen_sources, "source module counted in multiple completed batches")
            seen_sources.add(key)
        by_module = {s["module"]: s for s in sources}
        require(len(by_module) == len(sources), "ambiguous module owner in lane")
        expected = summary["results_file"]
        result_path = root / lane_id / "import" / "results.jsonl"
        digest, byte_count, index, lane_proofs = hashlib.sha256(), 0, 0, 0
        with result_path.open("rb") as stream:
            while line := stream.readline(MAX_RECORD_BYTES + 1):
                require(len(line) <= MAX_RECORD_BYTES, "result record exceeds bounded reader")
                digest.update(line)
                byte_count += len(line)
                if not line.strip():
                    continue
                record = json.loads(line)
                require(record.get("schema") == RESULT_SCHEMA and record.get("lane") == lane_id,
                        "result schema/lane identity")
                require(index < len(names) and record.get("name") == names[index], "fixed cohort name/order")
                index += 1
                records += 1
                if record.get("is_proof") is not True:
                    non_proofs += record.get("is_proof") is False
                    unclassified += record.get("is_proof") is not False
                    continue
                lane_proofs += 1
                eligibility = record.get("eligibility", {})
                module = record.get("original", {}).get("module") or eligibility.get("source_binding", {}).get("module")
                require(module in by_module, "proof module lacks selected source owner")
                source = by_module[module]
                identity = (*source_key(source), record["name"])
                require(identity not in seen_declarations, "duplicate source-bound declaration")
                seen_declarations.add(identity)
                repository = source["repository"]
                if repository not in repositories:
                    repositories[repository] = Scope()
                repositories[repository].add(record)
                scopes["all_identified_proofs"].add(record)
                if all(eligibility.get(k) is True for k in ELIGIBILITY_KEYS if k != "kernel_rechecked"):
                    scopes["source_safe_axiom_eligible_proofs"].add(record)
                if all(eligibility.get(k) is True for k in ELIGIBILITY_KEYS):
                    scopes["fully_eligible_proofs"].add(record)
                if record.get("native_certificate_accepted"):
                    native_records.append({"lane": lane_id, "name": record["name"], "source": source,
                        "rows": record.get("native", {}).get("rows"),
                        "eligible": record.get("eligible_native_accepted") is True,
                        "strict": record.get("strict_whole_declaration_accepted") is True,
                        "current_arithmetic_capacity": record.get("native", {}).get("current_arithmetic_capacity") is True})
        require(index == len(names), "fixed cohort record count")
        require(byte_count == expected["bytes"] and digest.hexdigest() == expected["sha256"], "lane result hash")
        require(index == batch["records"] and lane_proofs == batch["identified_proofs"], "collection count join")
        require(lane_proofs == summary["denominators"]["identified_proof_declarations"], "summary proof count join")
        lane_evidence.append({"lane": lane_id, "records": index, "proofs": lane_proofs,
            "summary": summary_info, "results": {"path": str(result_path.resolve()), "bytes": byte_count,
            "sha256": digest.hexdigest()}, "input_versions": summary.get("inputs", {})})
    all_proofs = scopes["all_identified_proofs"]
    return {"schema": "zkl-nova-18/measured-feature-priorities-v1",
        "analysis_helper": file_info(__file__), "collection": collection_info, "cohort": cohort_info,
        "scope": {"collection_status": collection["status"], "collection_exporter_sha256": collection["exporter_sha256"],
            "source_file_denominator": collection["source_file_denominator"], "build_statuses": collection["build_statuses"],
            "completed_lanes": len(completed), "exported_source_modules": len(seen_sources),
            "failed_module_export_count": collection["failed_module_export_count"],
            "full_catalog_proof_coverage_known": collection["full_catalog_proof_coverage_known"],
            "description": collection["declaration_denominator_scope"]},
        "denominators": {"result_records": records, "identified_proof_declarations": all_proofs.count,
            "identified_non_proof_declarations": non_proofs, "unclassified_candidates": unclassified},
        "interpretation": {
            "blockers": "Each label counts proof declarations once; overlapping labels must not be added.",
            "nodes": "Original declaration-local DAG nodes reachable from type/proof, including erased syntax; goal and proof counts overlap.",
            "unresolved_constants": "Observed bounded lowering diagnostics; counts are lower bounds when a declaration reaches the 200-entry detail cap.",
            "probe_candidates": "Observed blocker cohorts for experiments. Expanding theorem bodies may expose other features, so candidate counts are not projected acceptance gains.",
            "universes": "Whole symbolic-universe declarations remain unsupported; these measurements include no invented monomorphic instances.",
            "conversion": "Absence of eta or proof-irrelevance labels does not establish absence of these conversions."},
        "proof_scopes": {name: scope.result() for name, scope in scopes.items()},
        "repositories": {name: scope.result() for name, scope in sorted(repositories.items())},
        "native_certificates": native_records, "lane_evidence": lane_evidence}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--collection", required=True, type=Path)
    parser.add_argument("--cohort", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    report = measure(args.collection, args.cohort)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    scope = report["proof_scopes"]["all_identified_proofs"]
    print(json.dumps({"schema": report["schema"], "output": str(args.output.resolve()),
        "denominators": report["denominators"], "acceptance": scope["acceptance"],
        "remaining_blockers": scope["remaining_blockers"]}, indent=2))


if __name__ == "__main__":
    main()
