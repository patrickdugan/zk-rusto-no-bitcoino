#!/usr/bin/env python3
"""Collect two fixed Lean 4.35 source cohorts with bounded, recorded failures.

Run collection through `lake env python3` from the pinned source's lean/
directory. Initialization and finalization require no Lean installation.
The selected names are frozen before compilation; every outcome retains them.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import posixpath
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone


HERE = Path(__file__).resolve().parent
SCHEMA = "zkl-nova-18/solved-conjectures-cohort-v1"


def utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read(path: Path):
    return json.loads(path.read_text())


def write(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n")
    temporary.replace(path)


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise ValueError(reason)


def control_paths(controls: dict) -> dict:
    normalized = {}
    for name, digest in controls.items():
        require(isinstance(name, str) and "\\" not in name and not name.startswith("/"),
                "control path must be repository-relative")
        path = posixpath.normpath(name)
        require(path not in {".", ".."} and not path.startswith("../"), "control path escapes repository")
        require(path not in normalized, "duplicate control path alias")
        normalized[path] = digest
    return normalized


def manifest_check(manifest: dict) -> None:
    require(manifest.get("schema") == SCHEMA, "unexpected cohort schema")
    lanes = manifest["lanes"]
    require(len({lane["id"] for lane in lanes}) == len(lanes), "duplicate lane")
    total = 0
    for lane in lanes:
        require(lane["id"].isalnum(), "unsafe lane id")
        names = lane["names"]
        require(names == sorted(set(names)), "names must be unique and sorted")
        require(len(names) == lane["theorem_inventory_count"], "wrong inventory denominator")
        require(len(set(lane["modules"])) == len(lane["modules"]), "duplicate module")
        require([f["module"] for f in lane["source_files"]] == lane["modules"],
                "source files must preserve the pinned compilation order")
        for item in lane["source_files"]:
            require(item["path"] == "lean/" + item["module"].replace(".", "/") + ".lean",
                    "unexpected source path")
        require(lane["verification_script"].startswith("scripts/verify_"), "unexpected verifier")
        require(lane["verification_artifact_directory"].startswith(".candidate-artifacts/"),
                "unexpected verifier output")
        for field in ["verification_script", "verification_artifact_directory"]:
            require(".." not in Path(lane[field]).parts, "unsafe verifier path")
        control_paths(lane["upstream"]["control_sha256"])
        total += len(names)
    require(total == manifest["selection"]["cohort_theorem_constants"], "wrong cohort denominator")


def base_build(lane: dict, reason: str = "collection has not started") -> dict:
    return {
        "schema": "zkl-nova-18/source-build-receipt-v1",
        "status": "not_attempted", "exit_code": None, "lane": lane["id"],
        "requested_modules": lane["modules"], "selected_names": lane["names"],
        "source_files": lane["source_files"], "reason": reason,
        "fresh_source_compilation": False,
    }


def failed_export(lane: dict, reason: str, status: str = "not_attempted") -> dict:
    return {
        "schema": "zkl-nova-18/lean-expr-summary-v1", "status": status,
        "requested_modules": lane["modules"], "selected_names": lane["names"],
        "missing_selected_names": lane["names"], "target_records": 0,
        "reason": reason, "source_compilation_evidence": "build-receipt.json",
    }


def initialize(args, manifest: dict) -> dict:
    args.output.mkdir(parents=True, exist_ok=True)
    report_path = args.output / "collection.json"
    if report_path.is_file():
        report = read(report_path)
        require(report["cohort_sha256"] == sha(args.manifest), "cohort changed during collection")
        return report
    write(args.output / "cohort.json", manifest)
    report = {
        "schema": "zkl-nova-18/solved-source-collection-v1", "status": "initialized",
        "started_at": utc(), "cohort_sha256": sha(args.manifest),
        "source_revision": manifest["source"]["revision"],
        "workflow_sha": os.environ.get("GITHUB_SHA"), "run_id": os.environ.get("GITHUB_RUN_ID"),
        "selected_theorem_constants": manifest["selection"]["cohort_theorem_constants"],
        "full_corpus_support_inference": False,
        "limits": {"collector_wall_seconds": args.budget_seconds,
                   "lane_build_wall_seconds": 300, "lane_export_wall_seconds": 240,
                   "lane_import_wall_seconds": 60, "lane_output_bytes": args.max_output_bytes},
        "lanes": [{"id": lane["id"], "selected_names": lane["names"],
                   "status": "not_attempted", "commands": []} for lane in manifest["lanes"]],
    }
    for lane in manifest["lanes"]:
        directory = args.output / lane["id"]
        write(directory / "build-receipt.json", base_build(lane))
        write(directory / "export-summary.json", failed_export(lane, "collection has not started"))
    write(report_path, report)
    return report


def source_check(source: Path, manifest: dict, dependencies: bool = False) -> None:
    def git(directory, *arguments):
        return subprocess.check_output(["git", "-C", str(directory), *arguments], text=True).strip()
    require(git(source, "rev-parse", "HEAD") == manifest["source"]["revision"], "source revision mismatch")
    require(git(source, "rev-parse", "HEAD^{tree}") == manifest["source"]["tree"], "source tree mismatch")
    expected = {f["path"]: f["sha256"] for f in manifest["source"]["configuration_files"]}
    for lane in manifest["lanes"]:
        expected.update({f["path"]: f["sha256"] for f in lane["source_files"]})
        expected.update(lane["upstream"]["control_sha256"])
    for name, digest in expected.items():
        require(sha(source / name) == digest, "source/control hash mismatch: " + name)
    if dependencies:
        for package in manifest["source"]["dependencies"]:
            directory = source / "lean/.lake/packages" / package["name"]
            require(git(directory, "rev-parse", "HEAD") == package["revision"],
                    "dependency revision mismatch: " + package["name"])


def stop(process) -> None:
    if process.poll() is not None:
        return
    # The pinned Feldheim verifier starts Lean in a new session. Capture the
    # descendant tree before stopping its parent so that the budget includes
    # those children as well as the wrapper's process group.
    descendants = []
    children_by_parent = {}
    for path in Path("/proc").iterdir():
        if not path.name.isdigit():
            continue
        try:
            fields = (path / "stat").read_text().rsplit(")", 1)[1].split()
            children_by_parent.setdefault(int(fields[1]), []).append((int(path.name), fields[19]))
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            continue
    pending = [process.pid]
    while pending:
        pid = pending.pop()
        for child, identity in children_by_parent.get(pid, []):
            descendants.append((child, identity))
            pending.append(child)
    for pid, _ in reversed(descendants):
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
    for pid, identity in reversed(descendants):
        try:
            current = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[19]
            if current == identity:
                os.kill(pid, signal.SIGKILL)
        except (FileNotFoundError, ProcessLookupError):
            pass


def command(args, record: dict, label: str, argv: list[str], cwd: Path,
            env: dict, seconds: float, deadline: float) -> dict:
    directory = args.output / record["id"]
    directory.mkdir(parents=True, exist_ok=True)
    log = directory / (label + ".log")
    start = time.monotonic()
    available = min(seconds, max(0, deadline - start))
    item = {"label": label, "command": argv, "started_at": utc(), "exit_code": None,
            "timed_out": False, "output_limit": False}
    print(f"{utc()} {record['id']} {label}", flush=True)
    if available < 1:
        log.write_text("Collector deadline exhausted before command.\n")
        item.update(exit_code=124, timed_out=True)
    else:
        with log.open("w") as output:
            process = subprocess.Popen(argv, cwd=cwd, env=env, stdout=output,
                                       stderr=subprocess.STDOUT, start_new_session=True)
            try:
                while process.poll() is None:
                    if time.monotonic() - start >= available:
                        item["timed_out"] = True
                        stop(process)
                        break
                    written = sum(p.stat().st_size for p in directory.rglob("*") if p.is_file())
                    if written > args.max_output_bytes:
                        item["output_limit"] = True
                        stop(process)
                        break
                    try:
                        process.wait(timeout=min(3, available))
                    except subprocess.TimeoutExpired:
                        pass
                item["exit_code"] = 124 if item["timed_out"] or item["output_limit"] else process.returncode
            finally:
                stop(process)
    item.update(seconds=round(time.monotonic() - start, 6), finished_at=utc(), log_sha256=sha(log))
    record["commands"].append(item)
    return item


def validate_build(source: Path, lane: dict, manifest: dict, evidence: Path) -> tuple[dict, dict]:
    receipt = read(evidence / "receipt.json")
    inventory = read(evidence / "declaration-inventory.json")
    require(receipt["status"] == "passed", "upstream verifier did not pass")
    require(receipt["project_modules"] == lane["modules"], "compiled module order changed")
    require(set(receipt["exact_kernel_replay_set"]) == set(lane["modules"]), "incomplete stock-kernel replay")
    expected = {f["path"].removeprefix("lean/"): f["sha256"] for f in lane["source_files"]}
    require(receipt["source_sha256"] == expected, "build receipt source mismatch")
    require(control_paths(receipt["control_sha256"]) == control_paths(lane["upstream"]["control_sha256"]),
            "build controls changed")
    require(receipt["lean_sha256"] == manifest["source"]["lean_sha256"], "compiler hash mismatch")
    require(receipt["leanchecker_sha256"] == manifest["source"]["leanchecker_sha256"], "checker hash mismatch")
    require(all(x["exit_code"] == 0 for x in receipt["steps"]), "failed verification command")
    require(sha(evidence / "declaration-inventory.json") == receipt["declaration_inventory_sha256"],
            "fresh inventory hash mismatch")
    names = sorted(n for n, decl in inventory["declarations"].items() if decl["kind"] == "theorem")
    require(names == lane["names"], "fresh theorem inventory differs from frozen cohort")
    require(inventory["summary"]["declarations"] == lane["all_declaration_inventory_count"],
            "fresh declaration count differs from frozen inventory")
    objects = {str(p.relative_to(evidence / "lib/lean")): sha(p)
               for p in (evidence / "lib/lean").rglob("*.olean*")}
    require(objects == receipt["object_sha256"], "fresh object hashes differ from receipt")
    require(len(objects) >= len(lane["modules"]), "missing compiled objects")
    source_check(source, manifest)
    return receipt, inventory


def validate_export(lane: dict, directory: Path, object_root: Path | None = None,
                    object_hashes: dict | None = None) -> dict:
    summary = read(directory / "export-summary.json")
    require(summary["status"] == "completed", "export did not complete")
    require(summary.get("missing_selected_names") == [], "export omitted selected names")
    records = [json.loads(line) for line in (directory / "targets.jsonl").read_text().splitlines() if line]
    require(sorted(r["name"] for r in records) == lane["names"], "export target set differs from cohort")
    require(summary["target_records"] == len(records), "export count mismatch")
    require(all(r["kind"] == "theorem" and r["role"] == "target" for r in records),
            "unexpected target declaration kind")
    require(all(r.get("provenance", {}).get("module") in lane["modules"] for r in records),
            "export target ownership mismatch")
    if object_root is not None:
        files = summary.get("module_files", [])
        require(sorted(f["module"] for f in files) == sorted(lane["modules"]),
                "export imported module set differs from compiled cohort")
        for item in files:
            relative = item["module"].replace(".", "/") + ".olean"
            require(Path(item["olean_path"]).resolve() == (object_root / relative).resolve(),
                    "export imported a different module object")
            require(object_hashes is not None and sha(object_root / relative) == object_hashes[relative],
                    "compiled object changed during export")
        require(summary["lean_version"] == "4.35.0", "unexpected exporter compiler version")
    require((directory / "dependencies.jsonl").is_file(), "dependency export absent")
    return summary


def importer(args, lane: dict, record: dict, ready: bool, deadline: float) -> bool:
    directory = args.output / lane["id"]
    argv = ["node", str(HERE / "corpus_import.cjs"), "--manifest", str(directory / "export-summary.json"),
            "--build-receipt", str(directory / "build-receipt.json"), "--cohort", str(args.manifest),
            "--lane", lane["id"], "--output", str(directory / "import")]
    if ready:
        argv += ["--input", str(directory / "targets.jsonl"),
                 "--dependencies", str(directory / "dependencies.jsonl"), "--certificates"]
    item = command(args, record, "import", argv, HERE, os.environ.copy(), 60, deadline)
    record["import_status"] = "completed" if item["exit_code"] == 0 else "failed"
    return item["exit_code"] == 0


def collect(args, manifest: dict, report: dict) -> int:
    deadline = time.monotonic() + args.budget_seconds
    require(args.source is not None, "--source is required for collection")
    source_check(args.source, manifest, dependencies=True)
    lean = shutil.which("lean")
    checker = shutil.which("leanchecker")
    require(bool(lean and checker and os.environ.get("LEAN_PATH")), "run through lake env")
    require(sha(Path(lean)) == manifest["source"]["lean_sha256"], "installed Lean hash mismatch")
    require(sha(Path(checker)) == manifest["source"]["leanchecker_sha256"], "installed checker hash mismatch")
    report["status"] = "running"
    report["collector_sha256"] = sha(Path(__file__))
    report["exporter_sha256"] = sha(HERE / "corpus_export.lean")
    report["importer_sha256"] = sha(HERE / "corpus_import.cjs")
    write(args.output / "collection.json", report)
    for lane, record in zip(manifest["lanes"], report["lanes"]):
        directory = args.output / lane["id"]
        build = base_build(lane)
        ready = False
        evidence = args.source / lane["verification_artifact_directory"]
        try:
            require(not evidence.exists(), "verifier output already exists; a fresh build is required")
            item = command(args, record, "source-build",
                           [sys.executable, str(args.source / lane["verification_script"])],
                           args.source / "lean", os.environ.copy(), 300, deadline)
            build.update(exit_code=item["exit_code"], command=item,
                         status="resource_limit" if item["timed_out"] or item["output_limit"] else "failed")
            if evidence.exists():
                shutil.copytree(evidence, directory / "source-build")
            require(item["exit_code"] == 0, "source build failed or exceeded its budget")
            receipt, _ = validate_build(args.source, lane, manifest, evidence)
            build.update(status="passed", fresh_source_compilation=True, reason=None,
                         lean_sha256=receipt["lean_sha256"], lean_version=receipt["lean_version"],
                         stock_kernel_replay_modules=receipt["exact_kernel_replay_set"],
                         upstream_verification_receipt_sha256=sha(evidence / "receipt.json"),
                         object_files=receipt["object_sha256"],
                         control_path_comparison={
                             "normalization": "POSIX repository-relative paths; escapes and duplicate aliases rejected",
                             "expected": control_paths(lane["upstream"]["control_sha256"]),
                             "observed": control_paths(receipt["control_sha256"])},
                         dependencies=manifest["source"]["dependencies"],
                         external_dependency_objects_independently_rebuilt=False)
            write(directory / "build-receipt.json", build)
            record["build_status"] = "passed"
            argv = [lean, "-j1", "-M4500", "--run", str(HERE / "corpus_export.lean"),
                    "--search-path", str(evidence / "lib/lean"),
                    "--out", str(directory / "targets.jsonl"),
                    "--dependency-out", str(directory / "dependencies.jsonl"),
                    "--summary-out", str(directory / "export-summary.json")]
            for module in lane["modules"]:
                argv += ["--module", module]
            for name in lane["names"]:
                argv += ["--name", name]
            environment = os.environ.copy()
            excluded = {(args.source / "lean/.lake/build/lib/lean").resolve(),
                        (args.source / "lean").resolve()}
            dependencies = [p for p in environment["LEAN_PATH"].split(os.pathsep)
                            if p and Path(p).resolve() not in excluded]
            environment["LEAN_PATH"] = os.pathsep.join([str(evidence / "lib/lean"), *dependencies])
            environment["LEAN_NUM_THREADS"] = "1"
            environment["UV_USE_IO_URING"] = "0"
            item = command(args, record, "export", argv, args.source / "lean", environment, 240, deadline)
            if item["exit_code"]:
                previous = directory / "export-summary.json"
                if previous.is_file():
                    shutil.copyfile(previous, directory / "partial-export-summary.json")
                write(previous, failed_export(lane, "export command failed or reached its budget",
                      "resource_limit" if item["timed_out"] or item["output_limit"] else "export_error"))
            require(item["exit_code"] == 0, "export command failed or reached its budget")
            validate_export(lane, directory, evidence / "lib/lean", receipt["object_sha256"])
            source_check(args.source, manifest)
            ready = True
            record["status"] = "exported"
        except (ValueError, OSError, KeyError, json.JSONDecodeError) as error:
            record["status"] = "blocked"
            record["reason"] = str(error)
            if build["status"] != "passed":
                build["reason"] = str(error)
                record["build_status"] = build["status"]
                write(directory / "build-receipt.json", build)
                write(directory / "export-summary.json", failed_export(lane, str(error)))
            else:
                previous = directory / "export-summary.json"
                if previous.is_file() and read(previous).get("status") == "completed":
                    shutil.copyfile(previous, directory / "invalid-export-summary.json")
                    write(previous, failed_export(lane, str(error), "export_error"))
        write(args.output / "collection.json", report)
        importer(args, lane, record, ready, deadline)
        write(args.output / "collection.json", report)
    imported = all(x.get("import_status") == "completed" for x in report["lanes"])
    exported = all(x.get("status") == "exported" for x in report["lanes"])
    report["status"] = "completed" if imported and exported else "completed_with_blocked_lanes" if imported else "incomplete"
    report["finished_at"] = utc()
    write(args.output / "collection.json", report)
    return 0 if report["status"] == "completed" else 1


def finalize(args, manifest: dict, report: dict) -> int:
    deadline = time.monotonic() + 150
    for lane, record in zip(manifest["lanes"], report["lanes"]):
        directory = args.output / lane["id"]
        if not (directory / "import/summary.json").is_file():
            reason = record.get("reason", report.get("error", "collection did not finish; inspect workflow and command logs"))
            record.setdefault("reason", reason)
            record["status"] = "blocked"
            if read(directory / "build-receipt.json")["status"] == "not_attempted":
                write(directory / "build-receipt.json", base_build(lane, reason))
            if read(directory / "export-summary.json")["status"] == "not_attempted":
                write(directory / "export-summary.json", failed_export(lane, reason))
            importer(args, lane, record, False, deadline)
    aggregate = {"id": "aggregate", "commands": []}
    argv = ["node", str(HERE / "corpus_import.cjs"), "aggregate", "--inputs"]
    argv += [str(args.output / lane["id"] / "import") for lane in manifest["lanes"]]
    argv += ["--cohort", str(args.manifest), "--output", str(args.output / "aggregate.json")]
    item = command(args, aggregate, "aggregate", argv, HERE, os.environ.copy(), 30, deadline)
    report["aggregate_command"] = item
    report["finalized_at"] = utc()
    report["artifacts_sha256"] = {
        str(path.relative_to(args.output)): sha(path)
        for path in sorted(args.output.rglob("*"))
        if path.is_file() and path.name not in {"collection.json", "collection.json.tmp"}
    }
    write(args.output / "collection.json", report)
    return 0 if item["exit_code"] == 0 and report["status"] == "completed" else 1


def self_test() -> None:
    digest = "ab" * 32
    controls = {"scripts/verify_example.py": digest}
    require(control_paths(controls) == controls, "canonical control path changed")
    require(control_paths({"lean/../scripts/verify_example.py": digest}) == controls,
            "equivalent upstream invocation path rejected")
    for bad in [{"../escape.py": digest}, {"lean/../../escape.py": digest},
                {"/absolute.py": digest},
                {"scripts/verify_example.py": digest, "lean/../scripts/verify_example.py": digest}]:
        try:
            control_paths(bad)
        except ValueError:
            pass
        else:
            raise AssertionError("unsafe or duplicate control path accepted")
    lane = {"id": "toy", "modules": ["Toy"], "names": ["Toy.a", "Toy.b"]}
    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        summary = {"status": "completed", "missing_selected_names": [], "target_records": 2}
        write(directory / "export-summary.json", summary)
        records = [{"name": n, "kind": "theorem", "role": "target", "provenance": {"module": "Toy"}}
                   for n in lane["names"]]
        target = directory / "targets.jsonl"
        target.write_text("".join(json.dumps(r) + "\n" for r in records))
        (directory / "dependencies.jsonl").write_text("")
        validate_export(lane, directory)
        for bad in [records[:1], [records[0], records[0]],
                    [records[0], {**records[1], "provenance": {"module": "Other"}}],
                    [records[0], {**records[1], "kind": "definition"}]]:
            target.write_text("".join(json.dumps(r) + "\n" for r in bad))
            try:
                validate_export(lane, directory)
            except ValueError:
                pass
            else:
                raise AssertionError("bad cohort export accepted")
        child_pid = directory / "child-pid.txt"
        child_code = "import os,time,pathlib; pathlib.Path(" + repr(str(child_pid)) + ").write_text(str(os.getpid())); time.sleep(20)"
        parent_code = "import subprocess,sys; subprocess.run([sys.executable,'-c'," + repr(child_code) + "], start_new_session=True)"
        process = subprocess.Popen([sys.executable, "-c", parent_code], start_new_session=True)
        try:
            for _ in range(100):
                if child_pid.is_file():
                    break
                time.sleep(0.01)
            require(child_pid.is_file(), "timeout control child failed to start")
            pid = int(child_pid.read_text())
            stop(process)
            for _ in range(100):
                stat = Path(f"/proc/{pid}/stat")
                if not stat.exists() or stat.read_text().rsplit(")", 1)[1].split()[0] == "Z":
                    break
                time.sleep(0.01)
            else:
                raise AssertionError("new-session child survived command timeout cleanup")
        finally:
            stop(process)
    print("PASS: exact control hashes accept both invocation paths and reject escapes/aliases; complete export accepted; missing, duplicate, foreign and non-theorem targets rejected; nested-session timeout cleanup passed")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=HERE / "corpus/solved_conjectures_manifest.json")
    parser.add_argument("--source", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--phase", choices=["initialize", "check-pins", "collect", "finalize"], default="collect")
    parser.add_argument("--budget-seconds", type=int, default=1200)
    parser.add_argument("--max-output-bytes", type=int, default=536870912)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    args.manifest = args.manifest.resolve()
    if args.source is not None:
        args.source = args.source.resolve()
    manifest = read(args.manifest)
    manifest_check(manifest)
    if args.phase == "check-pins":
        require(args.source is not None, "--source required")
        source_check(args.source, manifest)
        print("PASS: source revision, tree, 38 source files and verifier controls match pinned cohort")
        return 0
    require(args.output is not None, "--output required")
    require(1 <= args.budget_seconds <= 1200, "collector budget must be 1..1200 seconds")
    args.output = args.output.resolve()
    report = initialize(args, manifest)
    try:
        if args.phase == "initialize":
            return 0
        if args.phase == "finalize":
            return finalize(args, manifest, report)
        return collect(args, manifest, report)
    except Exception as error:
        report["status"] = "failed"
        report["error"] = str(error)
        report["finished_at"] = utc()
        write(args.output / "collection.json", report)
        print(str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
