#!/usr/bin/env python3
"""Pinned, bounded public-source compatibility sweep for ZKL-NOVA-18.

Source selection comes entirely from the committed manifest, before compilation.
The compiler decides whether a file elaborates; import scanning only schedules work.
This script does not modify source, install packages, or admit training examples.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import selectors
import shutil
import signal
import subprocess
import time
import urllib.error
import urllib.request


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_json(path: Path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
    tmp.replace(path)


def safe_path(path: str) -> str:
    p = PurePosixPath(path)
    if p.is_absolute() or ".." in p.parts or not p.parts:
        raise ValueError(f"unsafe manifest path: {path}")
    return str(p)


def fetch_one(root: Path, repo: dict, item: dict, budget: int):
    rel = safe_path(item["path"])
    result = {**item, "repository": repo["repository"], "commit": repo["commit"]}
    if item["kind"] == "lean_source" and item["bytes"] > budget:
        return {**result, "fetch_status": "source_budget_exceeded"}
    local = root / "sources" / repo["repository"] / rel
    url = f'https://raw.githubusercontent.com/{repo["repository"]}/{repo["commit"]}/{rel}'
    result["source_url"] = url
    try:
        if local.exists():
            data = local.read_bytes()
        else:
            for attempt in range(3):
                try:
                    request = urllib.request.Request(url, headers={"User-Agent": "ZKL-NOVA-18-corpus-audit"})
                    with urllib.request.urlopen(request, timeout=30) as response:
                        data = response.read(max(item["bytes"], budget) + 1)
                    break
                except (OSError, urllib.error.URLError):
                    if attempt == 2:
                        raise
        blob = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        if len(data) != item["bytes"] or blob != item["git_blob_sha1"]:
            raise ValueError("source length or git blob hash mismatch")
        local.parent.mkdir(parents=True, exist_ok=True)
        local.write_bytes(data)
        return {**result, "fetch_status": "verified", "sha256": digest(data), "local_path": str(local)}
    except Exception as exc:
        return {**result, "fetch_status": "fetch_failed", "error": str(exc)}


def validate_fetch_inventory(manifest: dict, fetched: list, root: Path | None = None):
    """Join a cached receipt to the exact public manifest before scheduling.

    Recorded fetch failures retain their place in the fixed denominator. Every
    other fetchable entry must be verified, and oversized Lean sources must
    retain their budget exclusion. When root is supplied, verified cache bytes
    are checked again against the manifest's Git blob and the receipt's SHA-256.
    """
    budget = manifest["selection"]["max_source_bytes"]
    if type(budget) is not int or budget < 0 or not isinstance(fetched, list):
        raise ValueError("invalid fetch inventory or source budget")
    expected, public_repositories = {}, set()
    expected_sources = expected_oversize = 0
    for repo in manifest["repositories"]:
        if repo.get("visibility") != "public":
            continue
        repository, commit = repo["repository"], repo["commit"]
        if not isinstance(repository, str) or safe_path(repository) != repository or len(PurePosixPath(repository).parts) != 2:
            raise ValueError("invalid public repository identifier")
        if repository in public_repositories:
            raise ValueError("duplicate public repository in source manifest: " + repository)
        public_repositories.add(repository)
        if not isinstance(commit, str) or not re.fullmatch(r"[a-f0-9]{40}", commit):
            raise ValueError("invalid pinned public repository commit")
        for item in repo["files"]:
            rel = item["path"]
            if not isinstance(rel, str) or safe_path(rel) != rel:
                raise ValueError("noncanonical manifest file path")
            if item["kind"] not in ("lean_source", "project_metadata", "build_config"):
                raise ValueError("unknown manifest file kind")
            if type(item["bytes"]) is not int or item["bytes"] < 0:
                raise ValueError("invalid manifest file byte count")
            if not isinstance(item["git_blob_sha1"], str) or not re.fullmatch(r"[a-f0-9]{40}", item["git_blob_sha1"]):
                raise ValueError("invalid manifest Git blob hash")
            key = (repository, rel)
            if key in expected:
                raise ValueError("duplicate manifest file: " + repository + "/" + rel)
            expected[key] = {**item, "repository": repository, "commit": commit}
            expected_sources += item["kind"] == "lean_source"
            expected_oversize += item["kind"] == "lean_source" and item["bytes"] > budget
    seen = set()
    verified = failed = excluded = byte_checks = 0
    for entry in fetched:
        if not isinstance(entry, dict):
            raise ValueError("non-object cached fetch entry")
        key = (entry.get("repository"), entry.get("path"))
        if key in seen:
            raise ValueError("duplicate cached fetch entry: " + repr(key))
        seen.add(key)
        if key not in expected:
            raise ValueError("cached fetch entry outside source manifest: " + repr(key))
        item = expected[key]
        for field in ("repository", "commit", "path", "kind", "git_blob_sha1", "bytes"):
            if type(entry.get(field)) is not type(item[field]) or entry[field] != item[field]:
                raise ValueError("cached fetch metadata mismatch: " + repr(key) + " field " + field)
        oversize = item["kind"] == "lean_source" and item["bytes"] > budget
        status = entry.get("fetch_status")
        if oversize:
            if status != "source_budget_exceeded":
                raise ValueError("oversized source admitted by cached fetch receipt: " + repr(key))
            excluded += 1
            continue
        if status not in ("verified", "fetch_failed"):
            raise ValueError("invalid fetch status for budget-eligible file: " + repr(key))
        url = f'https://raw.githubusercontent.com/{item["repository"]}/{item["commit"]}/{item["path"]}'
        if entry.get("source_url") != url:
            raise ValueError("cached source URL differs from pinned inventory: " + repr(key))
        if status == "fetch_failed":
            if not isinstance(entry.get("error"), str) or not entry["error"]:
                raise ValueError("cached fetch failure has no diagnostic: " + repr(key))
            failed += 1
            continue
        if not isinstance(entry.get("sha256"), str) or not re.fullmatch(r"[a-f0-9]{64}", entry["sha256"]):
            raise ValueError("verified cache entry has no SHA-256: " + repr(key))
        if not isinstance(entry.get("local_path"), str) or not entry["local_path"]:
            raise ValueError("verified cache entry has no local path: " + repr(key))
        if root is not None:
            local = root / "sources" / item["repository"] / item["path"]
            resolved = local.resolve()
            if not resolved.is_relative_to((root / "sources").resolve()) or Path(entry["local_path"]).resolve() != resolved:
                raise ValueError("cached file path differs from selected source: " + repr(key))
            data = local.read_bytes()
            blob = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
            if len(data) != item["bytes"] or blob != item["git_blob_sha1"] or digest(data) != entry["sha256"]:
                raise ValueError("verified cached bytes differ from pinned source: " + repr(key))
            byte_checks += 1
        verified += 1
    missing = set(expected) - seen
    if missing:
        raise ValueError("cached fetch inventory is missing selected files: " + repr(sorted(missing)[:10]))
    fetchable = len(expected) - expected_oversize
    if excluded != expected_oversize or verified + failed != fetchable:
        raise ValueError("cached fetch status counts differ from selected inventory")
    return {"public_repositories": len(public_repositories), "expected_files": len(expected),
            "receipt_files": len(fetched), "expected_source_files": expected_sources,
            "expected_metadata_files": len(expected) - expected_sources,
            "expected_oversized_sources": expected_oversize, "excluded_oversized_sources": excluded,
            "expected_fetchable_files": fetchable, "verified_files": verified,
            "fetch_failed_files": failed, "verified_byte_checks": byte_checks,
            "all_fetchable_verified": verified == fetchable, "inventory_matches": True}


def strip_comments(text: str) -> str:
    # Header scheduling only. Lean itself parses and checks the unchanged input.
    result, i, depth, quoted = [], 0, 0, False
    while i < len(text):
        pair = text[i:i + 2]
        if depth:
            if pair == "/-":
                depth += 1
                i += 2
            elif pair == "-/":
                depth -= 1
                i += 2
            else:
                result.append("\n" if text[i] == "\n" else " ")
                i += 1
        elif not quoted and pair == "/-":
            depth = 1
            i += 2
        elif not quoted and pair == "--":
            end = text.find("\n", i)
            i = len(text) if end < 0 else end
        else:
            if text[i] == '"' and (i == 0 or text[i - 1] != "\\"):
                quoted = not quoted
            result.append(text[i])
            i += 1
    return "".join(result)


def build_plan(manifest: dict, fetched: list, root: Path):
    by_repo = {}
    for entry in fetched:
        by_repo.setdefault(entry["repository"], []).append(entry)
    plan = []
    for repository, files in by_repo.items():
        source_root = root / "sources" / repository
        project_roots = {source_root}
        for item in files:
            if Path(item["path"]).name in ("lean-toolchain", "lakefile.toml", "lakefile.lean"):
                project_roots.add((source_root / item["path"]).parent)
        targets = []
        for item in files:
            if item["kind"] != "lean_source":
                continue
            path = source_root / item["path"]
            candidates = [p for p in project_roots if p == path.parent or p in path.parents]
            project = max(candidates, key=lambda p: len(p.parts))
            relative = path.relative_to(project)
            module = ".".join(relative.with_suffix("").parts)
            object_root = root / "objects" / repository / project.relative_to(source_root)
            object_path = object_root / relative.with_suffix(".olean")
            declared = project / "lean-toolchain"
            text = path.read_text() if path.exists() else ""
            imports = []
            for match in re.finditer(r"^\s*(?:public\s+|private\s+)?(?:meta\s+)?import\s+([^\n]+)", strip_comments(text), re.M):
                imports.extend(part for part in match[1].split() if re.fullmatch(r"[\w.«»']+", part))
            targets.append({**item, "module": module, "source_path": str(path),
                            "project_root": str(project), "object_root": str(object_root),
                            "object_path": str(object_path), "imports_for_scheduling": imports,
                            "declared_toolchain": declared.read_text().strip() if declared.exists() else None})
        for target in targets:
            dependencies = []
            ambiguous = []
            for imp in target["imports_for_scheduling"]:
                suffix = imp.replace(".", "/") + ".lean"
                candidates = [t for t in targets if t["path"] == suffix or t["path"].endswith("/" + suffix)]
                exact = [t for t in candidates if t["project_root"] == target["project_root"]]
                if exact:
                    candidates = exact
                if len(candidates) == 1:
                    dep = candidates[0]
                    if dep["path"] != target["path"]:
                        dependencies.append(dep["path"])
                elif len(candidates) > 1:
                    ambiguous.append(imp)
            target["local_dependencies"] = sorted(set(dependencies))
            target["ambiguous_imports"] = ambiguous
            target["search_paths"] = [target["object_root"]] + sorted({t["object_root"] for t in targets} - {target["object_root"]})
        plan.extend(targets)
    return sorted(plan, key=lambda x: (x["repository"], x["path"]))


def compile_one(entry: dict, lean: str, root: Path, timeout: int):
    receipt = {k: v for k, v in entry.items() if k != "search_paths"}
    if entry["fetch_status"] != "verified":
        return {**receipt, "build_status": entry["fetch_status"]}
    try:
        source_bytes = Path(entry["source_path"]).read_bytes()
        if digest(source_bytes) != entry["sha256"]:
            return {**receipt, "build_status": "source_hash_mismatch"}
    except OSError as exc:
        return {**receipt, "build_status": "source_unavailable", "error": str(exc)}
    output = Path(entry["object_path"])
    output.parent.mkdir(parents=True, exist_ok=True)
    # Stale objects must never supply evidence for the new invocation.
    output.unlink(missing_ok=True)
    command = [lean, "-t", "0", "-j", "1", "-M", "2048", "--root", entry["project_root"], "-o", str(output), entry["source_path"]]
    env = dict(os.environ, LEAN_PATH=os.pathsep.join(entry["search_paths"]))
    started = time.monotonic()
    process = None
    log_path = root / "logs" / entry["repository"] / (entry["path"] + ".log")
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_limit = 8 * 1024 * 1024
    timed_out = output_limited = False
    try:
        process = subprocess.Popen(command, cwd=entry["project_root"], env=env,
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   start_new_session=True)
        with log_path.open("wb") as log_stream, selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            written, stream_open = 0, True
            while stream_open or process.poll() is None:
                if time.monotonic() - started > timeout:
                    timed_out = True
                    break
                for key, _ in selector.select(timeout=0.1):
                    block = os.read(key.fileobj.fileno(), 65536)
                    if not block:
                        selector.unregister(key.fileobj)
                        stream_open = False
                        continue
                    remaining = log_limit - written
                    log_stream.write(block[:remaining])
                    written += min(len(block), remaining)
                    if len(block) > remaining:
                        output_limited = True
                        break
                if output_limited:
                    break
            if timed_out or output_limited:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
            else:
                process.wait()
        process.stdout.close()
        log = log_path.read_bytes()
        status = "compile_timeout" if timed_out else "compile_output_limit" if output_limited else "compiled" if process.returncode == 0 and output.exists() else "lean_error"
        code = process.returncode
    except OSError as exc:
        log = str(exc).encode()
        status, code = "compiler_process_error", None
        if process is not None and process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
    elapsed = time.monotonic() - started
    log_path.write_bytes(log)
    receipt.update(build_status=status, exit_code=code, seconds=round(elapsed, 6),
                   command=command, log_path=str(log_path), log_sha256=digest(log),
                   log_tail=log[-12000:].decode(errors="replace"), log_byte_limit=log_limit,
                   output_limited=output_limited, timed_out=timed_out)
    if status == "compiled":
        receipt["olean_sha256"] = digest(output.read_bytes())
    else:
        output.unlink(missing_ok=True)
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--lean", required=True)
    parser.add_argument("--phase", choices=("fetch", "build", "all"), default="all")
    parser.add_argument("--fetch-workers", type=int, default=24)
    parser.add_argument("--build-workers", type=int, default=4)
    args = parser.parse_args()
    root = args.work_dir.resolve()
    root.mkdir(parents=True, exist_ok=True)
    raw = args.manifest.read_bytes()
    manifest = json.loads(raw)
    selection = manifest["selection"]
    if args.phase in ("fetch", "all"):
        work = [(repo, item) for repo in manifest["repositories"] if repo.get("visibility") == "public" for item in repo["files"]]
        fetched = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.fetch_workers) as pool:
            futures = [pool.submit(fetch_one, root, repo, item, selection["max_source_bytes"]) for repo, item in work]
            for index, future in enumerate(concurrent.futures.as_completed(futures), 1):
                fetched.append(future.result())
                if index % 100 == 0 or index == len(work):
                    print(json.dumps({"phase": "fetch", "finished": index, "total": len(work)}), flush=True)
        fetched.sort(key=lambda x: (x["repository"], x["path"]))
        write_json(root / "fetch_receipt.json", {"schema": "zkl-nova-18/source-fetch-v1", "manifest_sha256": digest(raw), "files": fetched})
    if args.phase in ("build", "all"):
        fetch = json.loads((root / "fetch_receipt.json").read_text())
        if fetch["manifest_sha256"] != digest(raw):
            raise ValueError("fetch manifest digest mismatch")
        validate_fetch_inventory(manifest, fetch["files"], root)
        version = subprocess.check_output([args.lean, "--version"], text=True).strip()
        compiler = {"version": version, "binary_sha256": digest(Path(args.lean).read_bytes()), "binary_path": args.lean}
        plan = build_plan(manifest, fetch["files"], root)
        # Objects are generated only in this dedicated work directory. Clearing
        # the whole tree prevents stale imports from helping a fresh build pass.
        object_root = root / "objects"
        if object_root.exists():
            if object_root.is_symlink():
                raise ValueError("generated object root must not be a symlink")
            shutil.rmtree(object_root)
        object_root.mkdir(parents=True)
        write_json(root / "build_plan.json", {"compiler": compiler, "manifest_sha256": digest(raw), "files": plan})
        pending = {(x["repository"], x["path"]): x for x in plan}
        done, results = set(), []
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.build_workers) as pool:
            active = {}
            while pending or active:
                for key, entry in list(pending.items()):
                    dependencies = {(entry["repository"], p) for p in entry["local_dependencies"]}
                    if dependencies <= done and len(active) < args.build_workers:
                        future = pool.submit(compile_one, entry, args.lean, root, selection["per_file_timeout_seconds"])
                        active[future] = key
                        del pending[key]
                if not active and pending:
                    # Preserve an explicit scheduling-cycle outcome for every target.
                    for key, entry in pending.items():
                        results.append({**entry, "build_status": "local_dependency_cycle"})
                    pending.clear()
                    break
                completed, _ = concurrent.futures.wait(active, return_when=concurrent.futures.FIRST_COMPLETED)
                for future in completed:
                    key = active.pop(future)
                    done.add(key)
                    result = future.result()
                    results.append(result)
                    if len(results) % 50 == 0 or len(results) == len(plan):
                        counts = {}
                        for r in results:
                            counts[r["build_status"]] = counts.get(r["build_status"], 0) + 1
                        print(json.dumps({"phase": "build", "finished": len(results), "total": len(plan), "counts": counts}), flush=True)
                        write_json(root / "build_checkpoint.json", {"compiler": compiler, "files": results})
        results.sort(key=lambda x: (x["repository"], x["path"]))
        write_json(root / "build_receipt.json", {"schema": "zkl-nova-18/owned-build-v1", "manifest_sha256": digest(raw),
                   "compiler": compiler, "semantics": "unchanged-source compatibility sweep; external packages are not installed",
                   "source_file_denominator": len(plan), "files": results})


if __name__ == "__main__":
    main()
