#!/usr/bin/env python3
"""Offline evidence review for the recursive-checkpoint experiment.

This tool never proves, verifies a SNARK, launches a process, or authorizes
publication/pruning. PASS means the operator's evidence package is complete.
The operator remains responsible for the provenance and truth of that evidence.
Python 3.10+, standard library only.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import sys
from pathlib import Path
from typing import Any

SCHEMA = "recursive-checkpoint-evidence/v1"
REPOSITORY = "patrickdugan/zk-rusto-no-bitcoino"
BASELINE = "eb1bc5438cc9ad2830d19ef3e438e30e85ba3377"
BACKEND = "nova-pallas-vesta-ipa-spartan"
MAX_JSON = 131072
MAX_ARTIFACT_BYTES = 32 * 1024 * 1024
REQUIRED_CHECKS = (
    "recursive_sharding_benches_finished", "spv_prototypes_finished",
    "candidate_build_and_pins", "header_semantics_and_retarget",
    "bounded_input_streaming", "resume_after_process_kill",
    "resume_corruption_rejected", "parameter_mismatch_rejected",
    "authenticated_checkpoint", "spv_expected_output_binding",
    "full_state_join_and_fork_rejection", "reorg_and_stale_tip_handling",
    "no_unsafe_pruning", "rollback_rehearsal",
)
PHASES = (
    "setup", "fold", "checkpoint_write", "checkpoint_restore",
    "compress", "verify_cold", "verify_warm",
)
PROFILES = {
    "small-k1": {"k": 1, "cap_mib": 1536},
    "small-k5": {"k": 5, "cap_mib": 1536},
    "laptop-k10": {"k": 10, "cap_mib": 8192},
}


class InvalidEvidence(ValueError):
    """Malformed input; distinct from a valid pending/failed experiment."""


def require(ok: bool, message: str) -> None:
    if not ok:
        raise InvalidEvidence(message)


def exact_keys(obj: Any, keys: set[str], where: str) -> None:
    require(type(obj) is dict, f"{where}: expected object")
    require(set(obj) == keys, f"{where}: missing/unknown fields: {sorted(set(obj) ^ keys)}")


def text(value: Any, where: str, limit: int = 1024) -> str:
    require(type(value) is str and 0 < len(value) <= limit, f"{where}: invalid string")
    return value


def digest(value: Any, where: str, digits: int = 64) -> str:
    require(type(value) is str and re.fullmatch(rf"[0-9a-f]{{{digits}}}", value) is not None,
            f"{where}: expected lowercase {digits}-hex digest")
    require(value != "0" * digits, f"{where}: zero digest is a placeholder")
    return value


def integer(value: Any, where: str, lo: int, hi: int) -> int:
    require(type(value) is int and lo <= value <= hi, f"{where}: integer out of range")
    return value


def number(value: Any, where: str) -> float:
    require(type(value) in (int, float) and math.isfinite(value) and value > 0,
            f"{where}: expected finite positive number")
    return float(value)


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _constant(value: str) -> None:
    raise InvalidEvidence(f"non-finite JSON number: {value}")


def load_json(path: Path) -> dict[str, Any]:
    with path.open("rb") as stream:
        raw = stream.read(MAX_JSON + 1)
    require(len(raw) <= MAX_JSON, "evidence JSON exceeds 128 KiB")
    try:
        result = json.loads(raw, object_pairs_hook=_pairs, parse_constant=_constant)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise InvalidEvidence(f"invalid JSON: {exc}") from exc
    require(type(result) is dict, "evidence root must be an object")
    return result


def artifact_hash(root: Path, record: dict[str, Any]) -> str:
    exact_keys(record, {"path", "sha256", "size_bytes"}, "artifact")
    relative = text(record["path"], "artifact.path", 240)
    require("\\" not in relative and ":" not in relative, "artifact path must be portable and relative")
    path = Path(relative)
    require(not path.is_absolute() and all(p not in (".", "..") for p in relative.split("/")),
            "artifact path traversal")
    require(all(relative.split("/")), "artifact path has empty component")
    base = root.resolve(strict=True)
    target = (base / path).resolve(strict=True)
    require(target.is_relative_to(base), "artifact escapes evidence root")
    # Refuse symlinks even when their current target is inside the evidence root.
    cursor = base
    for part in path.parts:
        cursor /= part
        require(not cursor.is_symlink(), "artifact symlink is forbidden")
    require(target.is_file(), "artifact must be a regular file")
    expected_size = integer(record["size_bytes"], "artifact.size_bytes", 1, MAX_ARTIFACT_BYTES)
    expected_hash = digest(record["sha256"], "artifact.sha256")
    h = hashlib.sha256()
    size = 0
    with target.open("rb") as stream:
        while chunk := stream.read(65536):
            size += len(chunk)
            require(size <= MAX_ARTIFACT_BYTES, "artifact exceeds 32 MiB")
            h.update(chunk)
    require(size == expected_size, "artifact length differs from manifest")
    require(h.hexdigest() == expected_hash, "artifact SHA-256 differs from manifest")
    return expected_hash+

def template() -> dict[str, Any]:
    return {
        "schema": SCHEMA, "repository": REPOSITORY, "baseline_commit": BASELINE,
        "evidence_kind": "pending", "candidate": None, "artifacts": {},
        "checks": [{"id": name, "status": "pending", "artifacts": [],
                    "notes": "Await measured results and operator review."} for name in REQUIRED_CHECKS],
        "benchmarks": [],
    }


def review(doc: dict[str, Any], root: Path) -> dict[str, Any]:
    exact_keys(doc, {"schema", "repository", "baseline_commit", "evidence_kind", "candidate",
                     "artifacts", "checks", "benchmarks"}, "evidence")
    require(doc["schema"] == SCHEMA, "wrong schema")
    require(doc["repository"] == REPOSITORY, "wrong repository")
    require(doc["baseline_commit"] == BASELINE, "baseline changed; re-audit and version this gate")
    require(doc["evidence_kind"] in ("pending", "operator_report", "synthetic"), "wrong evidence kind")
    blockers: list[str] = []
    if doc["evidence_kind"] != "operator_report":
        blockers.append(f"evidence_kind={doc['evidence_kind']}")
    candidate = doc["candidate"]
    profile = None
    if candidate is None:
        blockers.append("candidate pins are missing")
    else:
        exact_keys(candidate, {"commit", "backend", "network", "profile", "binary_sha256",
                               "verifier_key_sha256", "lockfile_sha256", "checkpoint_state_sha256",
                               "anchor_policy_sha256"}, "candidate")
        digest(candidate["commit"], "candidate.commit", 40)
        for field in ("binary_sha256", "verifier_key_sha256", "lockfile_sha256",
                      "checkpoint_state_sha256", "anchor_policy_sha256"):
            digest(candidate[field], f"candidate.{field}")
        require(candidate["network"] == "mainnet", "mainnet-only gate; testnet4 requires a separate policy")
        require(candidate["backend"] == BACKEND, "backend changed; re-audit required")
        require(type(candidate["profile"]) is str and candidate["profile"] in PROFILES, "unknown profile")
        profile = PROFILES[candidate["profile"]]
    artifacts = doc["artifacts"]
    require(type(artifacts) is dict and len(artifacts) <= 128, "invalid artifacts map")
    checked: dict[str, str] = {}
    for name, artifact in artifacts.items():
        require(re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", name) is not None, "invalid artifact id")
        checked[name] = artifact_hash(root, artifact)
    checks = doc["checks"]
    require(type(checks) is list and len(checks) == len(REQUIRED_CHECKS), "wrong check count")
    seen: set[str] = set()
    for check in checks:
        exact_keys(check, {"id", "status", "artifacts", "notes"}, "check")
        name = text(check["id"], "check.id", 80)
        require(name in REQUIRED_CHECKS and name not in seen, "unknown or duplicate check")
        seen.add(name)
        status = check["status"]
        require(status in ("pending", "pass", "fail"), "invalid check status")
        refs = check["artifacts"]
        require(type(refs) is list and len(refs) <= 16, "invalid check artifact list")
        require(all(type(x) is str and x in checked for x in refs), "unknown artifact reference")
        require(len(refs) == len(set(refs)), "duplicate artifact reference")
        text(check["notes"], "check.notes", 2048)
        if status != "pass":
            blockers.append(f"{name}: {status}")
        elif not refs:
            blockers.append(f"{name}: passing assertion has no retained evidence")
    runs = doc["benchmarks"]
    require(type(runs) is list and len(runs) <= 128, "invalid benchmark list")
    observed: set[str] = set()
    fold_peaks: dict[int, float] = {}
    for run in runs:
        exact_keys(run, {"phase", "headers", "k", "wall_seconds", "peak_mib", "hard_limit_mib",
                         "containment", "metric", "swap_max_mib", "process_tree_covered",
                         "exit_code", "artifact"}, "benchmark")
        phase = text(run["phase"], "benchmark.phase", 40)
        require(phase in PHASES, "unknown benchmark phase")
        require(profile is not None, "benchmark needs candidate pins")
        headers = integer(run["headers"], "benchmark.headers", 1, 10000000)
        k = integer(run["k"], "benchmark.k", 1, 64)
        require(k == profile["k"] and headers % k == 0, "fold width/workload mismatch")
        number(run["wall_seconds"], "benchmark.wall_seconds")
        peak = number(run["peak_mib"], "benchmark.peak_mib")
        cap = integer(run["hard_limit_mib"], "benchmark.hard_limit_mib", 1, 131072)
        require(cap == profile["cap_mib"], "hard cap differs from profile")
        require(type(run["process_tree_covered"]) is bool, "process_tree_covered must be boolean")
        integer(run["exit_code"], "benchmark.exit_code", -255, 255)
        metric = run["metric"]
        method = run["containment"]
        if method == "cgroup-v2":
            require(metric == "memory.peak", "cgroup-v2 requires memory.peak")
            require(type(run["swap_max_mib"]) is int and run["swap_max_mib"] == 0,
                    "Linux memory runs require swap.max=0")
        elif method == "windows-job":
            require(metric == "peak-job-commit", "Windows requires job committed memory")
            require(run["swap_max_mib"] is None, "Windows commit cap has no swap.max field")
        else:
            raise InvalidEvidence("OS-enforced cgroup/job containment is required")
        require(type(run["artifact"]) is str and run["artifact"] in checked, "benchmark has no retained report")
        if not run["process_tree_covered"] or run["exit_code"] != 0 or peak > cap:
            blockers.append(f"{phase}/{headers}: failed or exceeded resource contract")
            continue
        observed.add(phase)
        if phase == "fold" and headers in (1000, 10000):
            require(headers not in fold_peaks, "duplicate long-run fold workload")
            fold_peaks[headers] = peak
    for phase in PHASES:
        if phase not in observed:
            blockers.append(f"missing successful phase measurement: {phase}")
    if set(fold_peaks) != {1000, 10000}:
        blockers.append("need 1,000- and 10,000-header folding measurements")
    elif fold_peaks[10000] > fold_peaks[1000] + 128:
        blockers.append("long-run fold memory grew by more than the 128 MiB review tolerance")
    return {
        "schema": "recursive-checkpoint-review/v1",
        "status": "BLOCKED" if blockers else "EVIDENCE_COMPLETE_OPERATOR_REVIEW_REQUIRED",
        "blockers": blockers, "artifact_files_checked": len(checked),
        "candidate_commit": None if candidate is None else candidate["commit"],
        "proofs_cryptographically_verified_by_this_tool": 0,
        "deploy_authorized": False, "prune_authorized": False,
        "interpretation": "Operator-supplied evidence consistency only; manual review and real verification remain required.",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("template", help="print an all-pending evidence template")
    r = sub.add_parser("review", help="check retained local evidence; never execute anything")
    r.add_argument("evidence", type=Path)
    r.add_argument("--root", required=True, type=Path, help="immutable local evidence directory")
    args = parser.parse_args(argv)
    if args.command == "template":
        print(json.dumps(template(), indent=2))
        return 0
    try:
        result = review(load_json(args.evidence), args.root)
    except (InvalidEvidence, OSError, OverflowError, RecursionError) as exc:
        print(json.dumps({"status": "INVALID_EVIDENCE", "error": str(exc),
                          "deploy_authorized": False, "prune_authorized": False}))
        return 3
    print(json.dumps(result, indent=2))
    return 2 if result["blockers"] else 0


if __name__ == "__main__":
    sys.exit(main())
