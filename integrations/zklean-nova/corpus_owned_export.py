#!/usr/bin/env python3
"""Export every successfully compiled owned source module, then measure support.

The source-file cohort is fixed by owned_sources.json. The declaration denominator
becomes known after Lean loads a successful module. Failed files and failed module
exports therefore remain separate coverage gaps with unknown declaration counts.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import time

from corpus_collect import digest, write_json

HERE = Path(__file__).resolve().parent


def run_bounded(command, cwd, env, log, timeout, byte_root, byte_limit):
    started = time.monotonic()
    log.parent.mkdir(parents=True, exist_ok=True)
    timed_out, output_limited = False, False
    with log.open("wb") as stream:
        process = subprocess.Popen(command, cwd=cwd, env=env, stdout=stream,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        try:
            while process.poll() is None:
                if time.monotonic() - started > timeout:
                    timed_out = True
                    break
                if sum(p.stat().st_size for p in byte_root.rglob("*") if p.is_file()) > byte_limit:
                    output_limited = True
                    break
                try:
                    process.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    pass
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
    output_limited = output_limited or sum(p.stat().st_size for p in byte_root.rglob("*") if p.is_file()) > byte_limit
    return {"command": command, "exit_code": 124 if timed_out or output_limited else process.returncode,
            "process_exit_code": process.returncode,
            "timeout": timed_out, "output_limit": output_limited,
            "seconds": round(time.monotonic() - started, 6),
            "log_sha256": digest(log.read_bytes()), "log_path": str(log)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-receipt", type=Path, required=True)
    parser.add_argument("--source-manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--lean", required=True)
    parser.add_argument("--budget-seconds", type=int, default=1200)
    parser.add_argument("--batch-seconds", type=int, default=120)
    parser.add_argument("--batch-plan", type=Path,
                        help="Reuse an earlier complete module partition after validating the same source/build hashes")
    args = parser.parse_args()
    args.output = args.output.resolve()
    args.output.mkdir(parents=True, exist_ok=True)
    manifest_bytes = args.source_manifest.read_bytes()
    build_bytes = args.build_receipt.read_bytes()
    build = json.loads(build_bytes)
    if build["manifest_sha256"] != digest(manifest_bytes):
        raise ValueError("source manifest differs from completed build receipt")
    if digest(Path(args.lean).read_bytes()) != build["compiler"]["binary_sha256"]:
        raise ValueError("export compiler differs from source compiler")
    if not 1 <= args.budget_seconds <= 3600 or not 1 <= args.batch_seconds <= 300:
        raise ValueError("invalid process wall budget")
    deadline = time.monotonic() + args.budget_seconds
    groups = defaultdict(list)
    for item in build["files"]:
        if item["build_status"] == "compiled":
            if digest(Path(item["source_path"]).read_bytes()) != item["sha256"]:
                raise ValueError("source changed after compilation: " + item["path"])
            if digest(Path(item["object_path"]).read_bytes()) != item["olean_sha256"]:
                raise ValueError("object changed after compilation: " + item["path"])
            groups[(item["repository"], item["project_root"])].append(item)
    report = {"schema": "zkl-nova-18/owned-export-collection-v1",
              "source_manifest_sha256": digest(manifest_bytes), "build_receipt_sha256": digest(build_bytes),
              "compiler": build["compiler"], "source_file_denominator": build["source_file_denominator"],
              "build_statuses": dict(Counter(x["build_status"] for x in build["files"])),
              "declaration_denominator_scope": "Only declarations exported from freshly compiled source modules; excluded and failed files have unknown declaration counts.",
              "full_catalog_proof_coverage_known": False, "initial_project_groups": len(groups),
              "batches": [], "failed_module_exports": [], "exported_modules": [],
              "collector_sha256": digest(Path(__file__).read_bytes()),
              "exporter_sha256": digest((HERE / "corpus_export.lean").read_bytes()),
              "importer_sha256": digest((HERE / "corpus_import.cjs").read_bytes())}
    cohort = {"schema": "zkl-nova-18/owned-observed-declarations-v1",
              "source": {"kind": "owned_sources", "inventory_sha256": digest(manifest_bytes)},
              "selection": "All value-bearing declarations owned by successfully compiled and exported modules; source files were selected before compilation.",
              "lanes": []}
    queue = [sorted(items, key=lambda x: x["module"]) for _, items in sorted(groups.items())]
    if args.batch_plan is not None:
        previous_bytes = args.batch_plan.read_bytes()
        previous = json.loads(previous_bytes)
        if previous["source_manifest_sha256"] != digest(manifest_bytes) or previous["build_receipt_sha256"] != digest(build_bytes):
            raise ValueError("batch plan uses a different source inventory or build")
        expected = {(x["repository"], x["path"]): x for items in queue for x in items}
        seen, refined = set(), []
        for batch in previous["batches"]:
            if batch["status"] == "split_retry":
                continue
            items = []
            for selected in batch["source_files"]:
                key = (selected["repository"], selected["path"])
                if key not in expected or key in seen:
                    raise ValueError("batch plan contains an extra or duplicate source")
                item = expected[key]
                if any(selected[field] != item[field] for field in ("commit", "module", "sha256", "git_blob_sha1", "olean_sha256")):
                    raise ValueError("batch plan source/object pin mismatch")
                seen.add(key)
                items.append(item)
            if items:
                refined.append(items)
        if seen != set(expected):
            raise ValueError("batch plan omits compiled source modules")
        queue = refined
        report["reused_batch_plan_sha256"] = digest(previous_bytes)
        report["reused_batch_count"] = len(queue)
        report["reused_batch_module_count"] = len(seen)
    imports = []
    while queue:
        items = queue.pop(0)
        lane = "owned_" + digest(json.dumps([(x["repository"], x["path"], x["sha256"]) for x in items]).encode())[:16]
        directory = args.output / lane
        directory.mkdir(parents=True, exist_ok=True)
        sources = [{k: x[k] for k in ("repository", "commit", "path", "module", "sha256", "git_blob_sha1", "olean_sha256")} for x in items]
        receipt = {"schema": "zkl-nova-18/source-build-receipt-v1", "status": "passed", "exit_code": 0,
                   "fresh_source_compilation": True, "source_files": sources, "compiler": build["compiler"],
                   "requested_modules": [x["module"] for x in items],
                   "parent_build_receipt_sha256": digest(build_bytes), "lane": lane}
        write_json(directory / "build-receipt.json", receipt)
        same_repo = [x for x in build["files"] if x["repository"] == items[0]["repository"] and x["build_status"] == "compiled"]
        search_paths = [items[0]["object_root"]] + sorted({x["object_root"] for x in same_repo} - {items[0]["object_root"]})
        command = [args.lean, "-j1", "-M2048", "--run", str(HERE / "corpus_export.lean"),
                   "--out", str(directory / "targets.jsonl"),
                   "--dependency-out", str(directory / "dependencies.jsonl"),
                   "--summary-out", str(directory / "export-summary.json")]
        for search in search_paths:
            command += ["--search-path", search]
        for item in items:
            command += ["--module", item["module"]]
        remaining = max(0, deadline - time.monotonic())
        event = {"lane": lane, "source_files": sources, "source_module_count": len(items)}
        if remaining > 1:
            event["export_command"] = run_bounded(command, HERE, dict(os.environ, LEAN_PATH=os.pathsep.join(search_paths)),
                        directory / "export.log", min(args.batch_seconds, remaining), directory, 536870912)
        else:
            event["export_command"] = {"exit_code": 124, "timeout": True, "reason": "collector wall budget exhausted"}
        summary_path = directory / "export-summary.json"
        summary = json.loads(summary_path.read_text()) if summary_path.exists() else {}
        success = event["export_command"]["exit_code"] == 0 and summary.get("status") == "completed"
        if not success:
            event["status"] = "split_retry" if len(items) > 1 and time.monotonic() < deadline else "failed"
            report["batches"].append(event)
            if event["status"] == "split_retry":
                middle = len(items) // 2
                queue[0:0] = [items[:middle], items[middle:]]
            else:
                report["failed_module_exports"].extend(sources)
            write_json(args.output / "collection.json", report)
            continue
        expected_objects = {x["module"]: x for x in items}
        reported_objects = summary.get("module_files", [])
        if len(reported_objects) != len(items) or {x["module"] for x in reported_objects} != set(expected_objects):
            raise ValueError("exported object inventory differs from selected modules")
        for obj in reported_objects:
            expected = expected_objects[obj["module"]]
            actual_path = Path(obj["olean_path"]).resolve()
            if actual_path != Path(expected["object_path"]).resolve() or digest(actual_path.read_bytes()) != expected["olean_sha256"]:
                raise ValueError("export used an object outside the fresh build receipt")
            if digest(Path(expected["source_path"]).read_bytes()) != expected["sha256"]:
                raise ValueError("source changed during export")
        records = [json.loads(line) for line in (directory / "targets.jsonl").read_text().splitlines() if line]
        expected_modules = {x["module"] for x in items}
        if len({r["name"] for r in records}) != len(records) or any(r["role"] != "target" or r["provenance"]["module"] not in expected_modules for r in records):
            raise ValueError("duplicate or foreign target in owned export")
        names = [r["name"] for r in records]
        receipt["selected_names"] = names
        write_json(directory / "build-receipt.json", receipt)
        event.update(status="exported", records=len(records), identified_proofs=sum(r.get("is_proof") is True for r in records))
        command = ["node", str(HERE / "corpus_import.cjs"), "--input", str(directory / "targets.jsonl"),
                   "--dependencies", str(directory / "dependencies.jsonl"),
                   "--manifest", str(summary_path), "--build-receipt", str(directory / "build-receipt.json"),
                   "--lane", lane, "--output", str(directory / "import"), "--certificates"]
        event["import_command"] = run_bounded(command, HERE, os.environ.copy(), directory / "import.log",
                                               min(180, max(1, deadline - time.monotonic())), directory, 536870912)
        if event["import_command"]["exit_code"] == 0:
            event["status"] = "completed"
            imports.append(str(directory / "import"))
        else:
            event["status"] = "import_failed"
        cohort["lanes"].append({"id": lane, "names": names, "source_files": sources,
                                "observed_proof_declarations": event["identified_proofs"]})
        report["batches"].append(event)
        report["exported_modules"].extend(sources)
        write_json(args.output / "cohort.json", cohort)
        write_json(args.output / "collection.json", report)
        print(json.dumps({"lane": lane, "modules": len(items), "records": len(records), "proofs": event["identified_proofs"], "status": event["status"]}), flush=True)
    write_json(args.output / "cohort.json", cohort)
    if imports:
        command = ["node", str(HERE / "corpus_import.cjs"), "aggregate", "--inputs", *imports,
                   "--cohort", str(args.output / "cohort.json"), "--output", str(args.output / "aggregate.json")]
        report["aggregate_command"] = run_bounded(command, HERE, os.environ.copy(), args.output / "aggregate.log", 120, args.output, 2147483648)
    report["status"] = "completed" if not report["failed_module_exports"] and all(x["status"] in ("completed", "split_retry") for x in report["batches"]) and report.get("aggregate_command", {}).get("exit_code") == 0 else "partial"
    report["exported_module_count"] = len(report["exported_modules"])
    report["failed_module_export_count"] = len(report["failed_module_exports"])
    write_json(args.output / "collection.json", report)
    print(json.dumps({"status": report["status"], "exported_modules": report["exported_module_count"], "failed_exports": report["failed_module_export_count"]}), flush=True)


if __name__ == "__main__":
    main()
