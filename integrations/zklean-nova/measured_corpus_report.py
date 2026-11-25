#!/usr/bin/env python3
"""Join authenticated owned/hosted corpus evidence into compact JSON and Markdown.

All large JSONL inputs are streamed. Source inventories, selected declaration
names, source receipts, target lines and result files are joined before output.
The generated files contain measured data; this program performs no proof search
or kernel extension. Unit implementation records cannot enter this interface.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path

from measured_feature_priorities import Scope, file_info, read_json, require


HERE = Path(__file__).resolve().parent
EXPR_CHILDREN = {"bvar": (), "fvar": (), "mvar": (), "sort": (), "const": (),
                 "app": ("fn", "arg"), "lam": ("type", "body"), "forall": ("type", "body"),
                 "let": ("type", "value", "body"), "lit": (), "mdata": ("expr",), "proj": ("expr",)}
LEVEL_CHILDREN = {"zero": (), "param": (), "mvar": (), "succ": ("of",),
                  "max": ("left", "right"), "imax": ("left", "right",)}
RESULT_SCHEMA = "zkl-nova-18/corpus-import-result-v1"
SUMMARY_SCHEMA = "zkl-nova-18/corpus-import-summary-v1"
RECORD_LIMIT = 64 * 1024 * 1024


def encoded(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def digest(domain, value):
    return hashlib.sha256(domain.encode() + b"\0" + encoded(value)).hexdigest()


def check_info(observed, expected, label):
    require(observed["bytes"] == expected["bytes"] and observed["sha256"] == expected["sha256"], label)


def verified_json(path, expected=None):
    value, info = read_json(path)
    if expected:
        check_info(info, expected, "JSON evidence hash: " + str(path))
    return value, info


def jsonl(path, expected):
    h, size = hashlib.sha256(), 0
    with Path(path).open("rb") as stream:
        number = 0
        while line := stream.readline(RECORD_LIMIT + 1):
            require(len(line) <= RECORD_LIMIT, "bounded JSONL record size")
            h.update(line)
            size += len(line)
            number += 1
            if not line.strip():
                continue
            body = line.rstrip(b"\r\n")
            yield number, hashlib.sha256(body).hexdigest(), json.loads(body)
    check_info({"bytes": size, "sha256": h.hexdigest()}, expected, "JSONL evidence hash: " + str(path))


def expr_fingerprints(record):
    """Exact Expr structure, independent of local DAG numbering and sharing."""
    if record.get("status") != "ok" or record.get("proof_root") is None:
        return None
    levels, exprs = [], []
    require(len(record["expr_nodes"]) <= 200000 and len(record["level_nodes"]) <= 200000, "DAG fingerprint limit")

    def ref(values, index):
        require(type(index) is int and 0 <= index < len(values), "DAG fingerprint forward/invalid reference")
        return values[index]

    for node in record["level_nodes"]:
        require(node.get("tag") in LEVEL_CHILDREN, "unknown Level fingerprint tag")
        value = dict(node)
        for key in LEVEL_CHILDREN[node["tag"]]:
            value[key] = {"level_sha256": ref(levels, node[key])}
        levels.append(digest("zkl-nova-18/exact-level-v1", value))
    for node in record["expr_nodes"]:
        require(node.get("tag") in EXPR_CHILDREN, "unknown Expr fingerprint tag")
        value = dict(node)
        for key in EXPR_CHILDREN[node["tag"]]:
            value[key] = {"expr_sha256": ref(exprs, node[key])}
        if node["tag"] == "sort":
            value["level"] = {"level_sha256": ref(levels, node["level"])}
        elif node["tag"] == "const":
            value["levels"] = [{"level_sha256": ref(levels, index)} for index in node["levels"]]
        exprs.append(digest("zkl-nova-18/exact-expr-v1", value))
    goal, proof = ref(exprs, record["type_root"]), ref(exprs, record["proof_root"])
    context = {"level_params": record.get("level_params", []), "level_param_parts": record.get("level_param_parts"),
               "goal": goal, "proof": proof}
    return {"goal_sha256": goal, "proof_sha256": proof,
            "pair_sha256": digest("zkl-nova-18/exact-proof-goal-v1", context)}


def source_tuple(source):
    return tuple(source.get(k) for k in ("path", "sha256", "module"))


def public_source(source, cohort, kind):
    repo = source.get("repository") or cohort["source"]["repo"]
    commit = source.get("commit") or cohort["source"]["revision"]
    return {"repository": repo, "commit": commit, "path": source["path"], "module": source["module"],
            "sha256": source["sha256"], "url": f"https://github.com/{repo}/blob/{commit}/{source['path']}"}


def scope_view(scope, constants=False):
    value = scope.result()
    keys = ("proof_declarations", "kinds", "statuses", "acceptance", "coverage", "original_blockers",
            "remaining_blockers", "eligibility_blockers", "node_totals", "expression_tags", "level_tags",
            "axiom_declarations", "kernel_check_statuses", "kernel_check_errors", "lowering_events",
            "probe_candidates", "theorem_only_observed_constant_declarations", "unsupported_primitive_instances",
            "lowering_details_at_200_entry_cap")
    if constants:
        keys += ("raw_constant_declarations", "raw_constant_occurrences")
    return {key: value[key] for key in keys}


def summary_view(summary):
    keys = ("denominators", "counts", "coverage", "statuses", "original_blocker_histogram",
            "remaining_blocker_histogram", "eligibility_blocker_histogram", "transitive_axioms",
            "conversion_feature_assessment", "expression_nodes", "lowering_events", "capacity_policy")
    out = {key: summary[key] for key in keys}
    out["expression_nodes"] = {key: value for key, value in summary["expression_nodes"].items()
                               if key not in ("constant_occurrences", "constant_declarations")}
    out["constant_histograms_evidence"] = "Full exact per-constant histograms remain in the hash-linked aggregate."
    return out


def compare_scope(scope, aggregate):
    value = scope.result()
    require(scope.count == aggregate["denominators"]["identified_proof_declarations"], "aggregate proof count")
    for field in ("original", "remaining", "eligibility"):
        expected = {k: v for k, v in aggregate[field + "_blocker_histogram"].items() if v}
        require(value[field + "_blockers"] == expected, "aggregate blocker histogram: " + field)
    for key in ("native_certificate_accepted", "eligible_native_accepted", "strict_whole_declaration_accepted",
                "transparent_lowering_accepted", "eligible_current_arithmetic_capacity"):
        require(value["acceptance"].get(key, 0) == aggregate["counts"][key], "aggregate acceptance: " + key)
    nodes = aggregate["expression_nodes"]
    require(value["expression_tags"] == nodes["tags"] and value["level_tags"] == nodes["level_tags"], "aggregate node tags")
    for field, name in (("expression_nodes", "reachable_unique"), ("level_nodes", "level_nodes"),
                        ("goal_expression_nodes", "goal_reachable"), ("proof_expression_nodes", "proof_reachable")):
        require(value["node_totals"].get(field, 0) == nodes[name], "aggregate node count: " + field)


class Measurement:
    def __init__(self):
        self.all = Scope()
        self.eligible = Scope()
        self.families, self.family_info = {}, {}
        self.raw_pairs, self.structural_pairs, self.lowered_pairs = {}, {}, {}
        self.accepted, self.evidence, self.datasets = [], [], {}
        self.fingerprint_status = Counter()
        self.current_owned = {}

    def add_pair(self, table, key, goal, proof, member):
        group = table.setdefault(key, {"pair_sha256": key, "goal_sha256": goal, "proof_sha256": proof, "members": []})
        group["members"].append(member)

    def load(self, root, kind):
        root = Path(root)
        collection, collection_info = verified_json(root / "collection.json")
        cohort, cohort_info = verified_json(root / "cohort.json")
        aggregate, aggregate_info = verified_json(root / "aggregate.json")
        expected_schema = "zkl-nova-18/owned-export-collection-v1" if kind == "owned" else "zkl-nova-18/solved-source-collection-v1"
        require(collection.get("schema") == expected_schema, "actual collection schema")
        require(collection.get("status") in ("completed", "partial", "completed_with_blocked_lanes"), "unfinished collection")
        require(collection.get("aggregate_command", {}).get("exit_code") == 0, "collection aggregate did not pass")
        require(aggregate.get("schema") == SUMMARY_SCHEMA and aggregate.get("lane") == "aggregate", "aggregate schema")
        check_info(cohort_info, aggregate["cohort"], "aggregate cohort hash")
        lanes = cohort["lanes"]
        require(len({lane["id"] for lane in lanes}) == len(lanes), "duplicate cohort lane")
        aggregate_lanes = {item["lane"]: item for item in aggregate["lanes"]}
        require(set(aggregate_lanes) == {lane["id"] for lane in lanes}, "aggregate lane coverage")
        if kind == "owned":
            require(cohort["source"].get("kind") == "owned_sources", "owned corpus provenance")
            batches = {b["lane"]: b for b in collection["batches"] if b["status"] == "completed"}
            require(set(batches) == set(aggregate_lanes), "owned completed cohort join")
            require(cohort["source"]["inventory_sha256"] == collection["source_manifest_sha256"], "owned inventory hash")
            source_scope = {key: collection[key] for key in ("source_file_denominator", "build_statuses", "exported_module_count",
                "failed_module_export_count", "full_catalog_proof_coverage_known", "declaration_denominator_scope")}
            source_scope["compiler"] = collection["compiler"]
        else:
            require(cohort["source"]["repo"] == "1337isnot1337/solved-conjectures", "hosted actual source repository")
            require(cohort_info["sha256"] == collection["cohort_sha256"], "hosted frozen cohort hash")
            source_scope = {"repository": cohort["source"]["repo"], "commit": cohort["source"]["revision"],
                "catalog_primary_source_files": cohort["source"]["primary_source_files"],
                "catalog_all_lean_paths": cohort["source"]["all_lean_paths"], "selected_source_files": sum(len(l["source_files"]) for l in lanes),
                "selected_theorem_constants": sum(len(l["names"]) for l in lanes),
                "full_catalog_proof_coverage_known": False, "toolchain": cohort["source"]["toolchain"],
                "source_build_statuses": {l["id"]: l.get("build_status", "unknown") for l in collection["lanes"]}}
        dataset_scope, seen_sources, total_records = Scope(), set(), 0
        for lane in lanes:
            lane_id = lane["id"]
            directory = root / lane_id
            summary, summary_info = verified_json(directory / "import" / "summary.json")
            require(summary == aggregate_lanes[lane_id], "lane summary differs from aggregate")
            require(summary.get("schema") == SUMMARY_SCHEMA and summary.get("lane") == lane_id, "lane identity")
            names = lane["names"]
            require(len(set(names)) == len(names), "duplicate selected declaration")
            sources = lane["source_files"]
            require(sorted(map(source_tuple, sources)) == sorted(map(source_tuple, summary["source_build"]["source_files"])), "source receipt pins")
            if kind == "owned":
                require(sorted(map(source_tuple, sources)) == sorted(map(source_tuple, batches[lane_id]["source_files"])), "collection source pins")
            by_module = {source["module"]: public_source(source, cohort, kind) for source in sources}
            require(len(by_module) == len(sources), "ambiguous selected module")
            for source in by_module.values():
                source_id = (source["repository"], source["commit"], source["path"])
                require(source_id not in seen_sources, "source counted in multiple lanes")
                seen_sources.add(source_id)
            inputs, files = summary["inputs"], {"summary": summary_info}
            for key, filename in (("build_receipt", "build-receipt.json"), ("manifest", "export-summary.json")):
                value, files[key] = verified_json(directory / filename, inputs[key])
                require(value == summary["source_build" if key == "build_receipt" else "export_manifest"], "embedded evidence differs")
            if inputs.get("dependencies"):
                files["dependencies"] = file_info(directory / "dependencies.jsonl")
                check_info(files["dependencies"], inputs["dependencies"], "dependency export hash")
            targets = {}
            if inputs.get("targets"):
                target_path = directory / "targets.jsonl"
                for number, line_hash, target in jsonl(target_path, inputs["targets"]):
                    require(target.get("schema") == "zkl-nova-18/lean-expr-v1" and target.get("role") == "target", "actual exported target schema")
                    name = target["name"]
                    require(name in names and name not in targets, "target cohort membership/uniqueness")
                    targets[name] = {"line": number, "line_sha256": line_hash, "module": target.get("provenance", {}).get("module"),
                                     "fingerprints": expr_fingerprints(target) if target.get("is_proof") is True else None}
                files["targets"] = {**inputs["targets"], "path": str(target_path.resolve())}
            count, lane_scope = 0, Scope()
            result_path = directory / "import" / "results.jsonl"
            for _, _, record in jsonl(result_path, summary["results_file"]):
                require(record.get("schema") == RESULT_SCHEMA and record.get("lane") == lane_id, "result schema/lane")
                require(count < len(names) and record.get("name") == names[count], "exact result names/order")
                count += 1
                total_records += 1
                name = record["name"]
                target = targets.get(name)
                if target:
                    source_line = record.get("source", {})
                    require(source_line.get("line") == target["line"] and source_line.get("line_sha256") == target["line_sha256"], "result/target line binding")
                    check_info(source_line["input"], inputs["targets"], "result target input hash")
                if kind == "owned":
                    self.current_owned[(lane_id, name)] = compact_comparison(record)
                if record.get("is_proof") is not True:
                    continue
                require(target is not None, "identified proof missing exported target")
                module = record.get("original", {}).get("module") or record.get("eligibility", {}).get("source_binding", {}).get("module")
                require(module == target["module"] and module in by_module, "proof/source module binding")
                source = by_module[module]
                family = "owned/" + source["repository"] if kind == "owned" else lane["contamination_family"]
                if family not in self.families:
                    self.families[family] = Scope()
                    self.family_info[family] = {"dataset": kind, "repository": source["repository"],
                        "assignment": "repository group; problem-family mapping unresolved" if kind == "owned" else lane["family_assignment_source"]}
                for scope in (self.all, dataset_scope, lane_scope, self.families[family]):
                    scope.add(record)
                if all(record.get("eligibility", {}).get(k) is True for k in ("fresh_source_build", "kernel_rechecked", "safe_declaration", "axiom_eligible")):
                    self.eligible.add(record)
                member = {"dataset": kind, "lane": lane_id, "name": name, "family": family}
                original = record.get("original", {})
                goal_hash = (original.get("raw_goal") or {}).get("sha256")
                proof_hash = (original.get("raw_proof") or {}).get("sha256")
                if goal_hash and proof_hash:
                    key = digest("zkl-nova-18/raw-receipt-proof-goal-v1", [goal_hash, proof_hash])
                    self.add_pair(self.raw_pairs, key, goal_hash, proof_hash, member)
                fingerprints = target["fingerprints"]
                self.fingerprint_status["available" if fingerprints else "unavailable"] += 1
                if fingerprints:
                    self.add_pair(self.structural_pairs, fingerprints["pair_sha256"], fingerprints["goal_sha256"], fingerprints["proof_sha256"], member)
                lowered_pair = None
                if record.get("lowered_goal_sha256") and record.get("lowered_proof_sha256"):
                    lowered_pair = digest("zkl-nova-18/lowered-proof-goal-v1", [record["lowered_goal_sha256"], record["lowered_proof_sha256"]])
                    self.add_pair(self.lowered_pairs, lowered_pair, record["lowered_goal_sha256"], record["lowered_proof_sha256"], member)
                if record.get("native_certificate_accepted"):
                    certificate = record["certificate"]
                    certificate_path = directory / "import" / "certificates" / certificate["file"]
                    certificate_info = file_info(certificate_path)
                    check_info(certificate_info, certificate, "accepted certificate file hash")
                    require(certificate["rows"] == record["native"]["rows"], "accepted row count")
                    self.accepted.append({**member, "source": source, "goal_sha256": goal_hash, "proof_sha256": proof_hash,
                        "structural_fingerprints": fingerprints, "lowered_pair_sha256": lowered_pair,
                        "rows": certificate["rows"], "eligible": record.get("eligible_native_accepted") is True,
                        "strict": record.get("strict_whole_declaration_accepted") is True,
                        "current_arithmetic_capacity": record["native"].get("current_arithmetic_capacity") is True,
                        "eligibility": {k: v for k, v in record["eligibility"].items() if k != "source_binding"},
                        "certificate": certificate_info, "target_line": target["line"], "target_line_sha256": target["line_sha256"]})
            require(count == len(names), "result candidate count")
            compare_scope(lane_scope, summary)
            files["results"] = {**summary["results_file"], "path": str(result_path.resolve())}
            self.evidence.append({"dataset": kind, "lane": lane_id, "files": files,
                "code_versions": {key: inputs[key] for key in ("importer", "kernel", "fixed_environment")},
                "proof_declarations": lane_scope.count, "selected_declarations": count})
        compare_scope(dataset_scope, aggregate)
        require(total_records == aggregate["denominators"]["observed_result_records"], "aggregate record count")
        proof_denominator = dataset_scope.count if kind == "owned" else sum(len(lane["names"]) for lane in lanes)
        self.datasets[kind] = {"collection_status": collection["status"], "proof_cohort_denominator": proof_denominator,
            "proof_denominator_basis": "identified proof declarations from exported freshly compiled modules" if kind == "owned" else "fixed upstream theorem-name inventory, including extraction failures",
            "source_scope": source_scope, "summary": summary_view(aggregate),
            "evidence": {"collection": collection_info, "cohort": cohort_info, "aggregate": aggregate_info},
            "pipeline_versions": {key: collection.get(key) for key in ("collector_sha256", "exporter_sha256", "importer_sha256", "workflow_sha", "run_id")}}

    def result(self):
        denominator = sum(dataset["proof_cohort_denominator"] for dataset in self.datasets.values())
        acceptance = self.all.counters["acceptance"]
        coverage = {key: {"numerator": acceptance[key], "denominator": denominator,
                          "percent": 100 * acceptance[key] / denominator if denominator else None}
                    for key in ("native_certificate_accepted", "eligible_native_accepted", "strict_whole_declaration_accepted", "eligible_current_arithmetic_capacity")}

        def duplicates(table):
            groups = [{**value, "count": len(value["members"])} for _, value in sorted(table.items()) if len(value["members"]) > 1]
            return {"fingerprinted_declarations": sum(len(value["members"]) for value in table.values()),
                    "unique_pairs": len(table), "duplicate_groups": len(groups),
                    "declarations_in_duplicate_groups": sum(group["count"] for group in groups),
                    "duplicate_excess": sum(group["count"] - 1 for group in groups), "groups": groups}

        return {"schema": "zkl-nova-18/measured-corpus-report-v1", "generator": file_info(__file__),
            "feature_helper": file_info(HERE / "measured_feature_priorities.py"), "datasets": self.datasets,
            "proof_cohort_denominator": denominator, "coverage": coverage,
            "full_catalog_proof_coverage": None, "all_identified_proofs": scope_view(self.all),
            "transitive_axiom_audits": {"complete": sum(d["summary"]["transitive_axioms"]["complete_audits"] for d in self.datasets.values()),
                "incomplete_or_missing": sum(d["summary"]["transitive_axioms"]["incomplete_or_missing_audits"] for d in self.datasets.values()),
                "histogram_scope": "Recorded per-declaration axiom dependencies; bounded audits can omit further dependencies."},
            "top_raw_constants_by_proof_declarations": [{"name": name, "proof_declarations": count,
                "node_occurrences": self.all.counters["raw_constant_occurrences"][name]}
                for name, count in self.all.counters["raw_constant_declarations"].most_common(50)],
            "fully_eligible_proofs": scope_view(self.eligible),
            "source_families": {key: {**self.family_info[key], **scope_view(value)} for key, value in sorted(self.families.items())},
            "duplicate_fingerprints": {"status": dict(self.fingerprint_status),
                "raw_receipt_pairs": duplicates(self.raw_pairs), "exact_expr_pairs": duplicates(self.structural_pairs),
                "lowered_fixed_kernel_pairs": duplicates(self.lowered_pairs),
                "definitions": {"raw_receipt_pairs": "SHA256 pair of importer raw goal/proof receipts; these include local DAG node IDs.",
                    "exact_expr_pairs": "Domain-separated SHA256 of exact exported Expr/Level structure and ordered universe parameters. Local DAG numbering and sharing are removed. Binder names, metadata, constants and every other encoded field remain. No semantic or alpha equivalence is inferred.",
                    "lowered_fixed_kernel_pairs": "Pairs of importer hashes for lowered fixed-kernel goal and proof; counts may include native rejection.",
                    "coverage_policy": "Declaration coverage retains the fixed inventory denominator; duplicate counts are a separate measurement."}},
            "accepted_ledger": self.accepted, "lane_evidence": self.evidence,
            "interpretation": {"corpus": "Actual pinned source cohorts only; implementation fixtures and standard-library prototypes are excluded.",
                "scope": "Unknown declaration counts in unbuilt or unselected source files prevent a full-catalog support percentage.",
                "histograms": "Feature and axiom labels overlap. Each label counts a proof declaration once; raw node occurrences have their own counters.",
                "source_families": "Owned families group repositories. Hosted families use the pinned upstream family assignments; these groups are not inferred DataGoblin problem roots.",
                "probes": "Theorem-dependency cohorts identify experiments, without predicting acceptance after expansion.",
                "arithmetic": "Capacity flags are native row-budget measurements. They do not assert an arithmetic proof or Nova proof was produced."}}


def compact_comparison(record):
    original, native = record.get("original", {}), record.get("native", {})
    return {"raw_goal": (original.get("raw_goal") or {}).get("sha256"),
            "raw_proof": (original.get("raw_proof") or {}).get("sha256"),
            "lowered_goal": record.get("lowered_goal_sha256"), "lowered_proof": record.get("lowered_proof_sha256"),
            "node_counts": digest("node-counts", record.get("node_counts")),
            "remaining_blockers": record.get("remaining_blockers"),
            "native": {"accepted": record.get("native_certificate_accepted"), "reference": native.get("reference_accepted"),
                       "replay": native.get("certificate_replay_accepted"), "rows": native.get("rows"),
                       "capacity": native.get("current_arithmetic_capacity")},
            "eligible": record.get("eligible_native_accepted"), "strict": record.get("strict_whole_declaration_accepted"),
            "kernel_rechecked": record.get("eligibility", {}).get("kernel_rechecked")}


def compare_previous(previous_root, current):
    root = Path(previous_root)
    collection, collection_info = verified_json(root / "collection.json")
    cohort, cohort_info = verified_json(root / "cohort.json")
    old, changes = {}, Counter()
    examples = {}
    for lane in cohort["lanes"]:
        summary, _ = verified_json(root / lane["id"] / "import" / "summary.json")
        for index, (_, _, record) in enumerate(jsonl(root / lane["id"] / "import" / "results.jsonl", summary["results_file"])):
            require(index < len(lane["names"]) and record["name"] == lane["names"][index], "previous exact cohort names")
            key = (lane["id"], record["name"])
            require(key not in old, "duplicate previous record")
            old[key] = compact_comparison(record)
    require(set(old) == set(current), "old/new selected declaration inventory differs")
    for key in old:
        for field in old[key]:
            if old[key][field] != current[key][field]:
                changes[field] += 1
                if len(examples.setdefault(field, [])) < 20:
                    examples[field].append({"lane": key[0], "name": key[1], "before": old[key][field], "after": current[key][field]})
    semantic_fields = ("raw_goal", "raw_proof", "lowered_goal", "lowered_proof", "node_counts", "remaining_blockers", "native")
    return {"previous_collection": collection_info, "previous_cohort": cohort_info,
            "previous_exporter_sha256": collection["exporter_sha256"], "compared_declarations": len(old),
            "corpus_and_native_outcomes_unchanged": not any(changes[field] for field in semantic_fields),
            "changed_fields": dict(changes), "change_examples_first_20_per_field": examples}


def owned_inventory(report, root, manifest_path, build_path):
    manifest, manifest_info = verified_json(manifest_path)
    build, build_info = verified_json(build_path or Path(root).parent / "build_receipt.json")
    collection, _ = verified_json(Path(root) / "collection.json")
    require(manifest_info["sha256"] == collection["source_manifest_sha256"], "owned source manifest hash")
    require(build_info["sha256"] == collection["build_receipt_sha256"], "owned parent build receipt hash")
    statuses = {}
    for item in build["files"]:
        statuses.setdefault(item["repository"], Counter())[item["build_status"]] += 1
    rows = []
    for repository in manifest["repositories"]:
        name = repository["repository"]
        family = report["source_families"].get("owned/" + name, {})
        rows.append({"repository": name, "visibility": repository.get("visibility", "private" if repository.get("status") == "private_source_excluded" else "unknown"),
                     "inventory_status": repository.get("status", "public_inventory"), "commit": repository.get("commit"),
                     "inventoried_lean_files": sum(f["kind"] == "lean_source" for f in repository.get("files", [])),
                     "historical_excluded_lean_files": repository.get("historical_lean_files"),
                     "build_statuses": dict(statuses.get(name, {})), "identified_proofs": family.get("proof_declarations", 0),
                     "acceptance": family.get("acceptance", {})})
    report["owned_repository_inventory"] = {"manifest": manifest_info, "build_receipt": build_info, "repositories": rows}


def markdown(report):
    lines = ["# Measured corpus results", "", "## Proof denominators and acceptance", "",
             "| Dataset | Proof cohort | Identified proofs | Native | Eligible native | Strict | Eligible within capacity |",
             "|---|---:|---:|---:|---:|---:|---:|"]
    for name, dataset in report["datasets"].items():
        s = dataset["summary"]
        c = s["counts"]
        lines.append(f"| {name} | {dataset['proof_cohort_denominator']:,} | {s['denominators']['identified_proof_declarations']:,} | {c['native_certificate_accepted']} | {c['eligible_native_accepted']} | {c['strict_whole_declaration_accepted']} | {c['eligible_current_arithmetic_capacity']} |")
    lines += ["", "Coverage uses the measured proof cohort. Declaration counts for unbuilt and unselected source files remain unknown.", "",
              "| Combined measure | Fraction | Percent |", "|---|---:|---:|"]
    for name, value in report["coverage"].items():
        lines.append(f"| {name} | {value['numerator']}/{value['denominator']} | {value['percent']:.6f}% |")
    lines += ["", "## Remaining blockers", "", "Labels overlap and count each identified proof once.", "",
              "| Feature | Proof declarations |", "|---|---:|"]
    for name, count in sorted(report["all_identified_proofs"]["remaining_blockers"].items(), key=lambda x: (-x[1], x[0])):
        lines.append(f"| {name} | {count:,} |")
    lines += ["", "## Source families", "", "| Family | Identified proofs | Eligible native | Strict |", "|---|---:|---:|---:|"]
    for name, family in report["source_families"].items():
        c = family["acceptance"]
        lines.append(f"| {name} | {family['proof_declarations']:,} | {c.get('eligible_native_accepted', 0)} | {c.get('strict_whole_declaration_accepted', 0)} |")
    lines += ["", "## Transitive axioms", "", "| Axiom | Identified proof declarations |", "|---|---:|"]
    for name, count in report["all_identified_proofs"]["axiom_declarations"].items():
        lines.append(f"| {name} | {count:,} |")
    lines += ["", "## Duplicate proof and goal pairs", "", "| Fingerprint | Declarations | Unique pairs | Duplicate groups | Duplicate excess |", "|---|---:|---:|---:|---:|"]
    for key in ("raw_receipt_pairs", "exact_expr_pairs", "lowered_fixed_kernel_pairs"):
        value = report["duplicate_fingerprints"][key]
        lines.append(f"| {key} | {value['fingerprinted_declarations']:,} | {value['unique_pairs']:,} | {value['duplicate_groups']:,} | {value['duplicate_excess']:,} |")
    lines += ["", "Fingerprint definitions and every duplicate member are recorded in JSON. The declaration denominator remains unchanged.", "",
              "## Accepted native certificates", "", "| Declaration | Source | Rows | Eligible | Strict | Within capacity |", "|---|---|---:|---|---|---|"]
    for item in report["accepted_ledger"]:
        source = item["source"]
        lines.append(f"| `{item['name']}` | [{source['repository']}/{source['path']}]({source['url']}) | {item['rows']} | {item['eligible']} | {item['strict']} | {item['current_arithmetic_capacity']} |")
    lines += ["", "Original goal/proof hashes, certificate file hashes, target line hashes and source pins accompany each accepted declaration in JSON.", ""]
    return "\n".join(lines)


def self_test():
    import copy
    record = {"status": "ok", "level_params": [], "expr_nodes": [{"tag": "bvar", "index": 0},
        {"tag": "sort", "level": 0}, {"tag": "lam", "name": "x", "binder_info": "default", "type": 1, "body": 0}],
        "level_nodes": [{"tag": "zero"}], "type_root": 1, "proof_root": 2}
    a = expr_fingerprints(record)
    reordered = copy.deepcopy(record)
    reordered["expr_nodes"] = [record["expr_nodes"][1], record["expr_nodes"][0],
                              {**record["expr_nodes"][2], "type": 0, "body": 1}]
    reordered["type_root"] = 0
    assert expr_fingerprints(reordered) == a
    renamed = copy.deepcopy(record)
    renamed["expr_nodes"][2]["name"] = "y"
    assert expr_fingerprints(renamed)["pair_sha256"] != a["pair_sha256"]
    changed = copy.deepcopy(record)
    changed["expr_nodes"][0]["index"] = 1
    assert expr_fingerprints(changed)["proof_sha256"] != a["proof_sha256"]
    cyclic = copy.deepcopy(record)
    cyclic["expr_nodes"][2]["body"] = 2
    try:
        expr_fingerprints(cyclic)
        raise AssertionError("cycle accepted")
    except ValueError:
        pass
    print("PASS: exact structural fingerprints preserve syntax and reject DAG cycles; 0 corpus observations")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--owned", type=Path)
    parser.add_argument("--solved", type=Path)
    parser.add_argument("--previous-owned", type=Path)
    parser.add_argument("--owned-manifest", type=Path, default=HERE / "corpus" / "owned_sources.json")
    parser.add_argument("--owned-build-receipt", type=Path)
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--markdown-out", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    require(args.owned and args.json_out and args.markdown_out, "--owned, --json-out and --markdown-out required")
    measured = Measurement()
    measured.load(args.owned, "owned")
    if args.solved:
        measured.load(args.solved, "solved")
    report = measured.result()
    owned_inventory(report, args.owned, args.owned_manifest, args.owned_build_receipt)
    if args.previous_owned:
        report["owned_refresh_comparison"] = compare_previous(args.previous_owned, measured.current_owned)
    for output in (args.json_out, args.markdown_out):
        output.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    args.markdown_out.write_text(markdown(report))
    print(json.dumps({"schema": report["schema"], "proof_cohort_denominator": report["proof_cohort_denominator"],
                      "coverage": report["coverage"], "json_bytes": args.json_out.stat().st_size,
                      "markdown_bytes": args.markdown_out.stat().st_size}, indent=2))


if __name__ == "__main__":
    main()
