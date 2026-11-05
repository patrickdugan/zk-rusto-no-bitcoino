#!/usr/bin/env python3
"""Check a declared research plan; generate a matrix without running a prover.

This is a configuration check. It cannot attest the selected binary, inspect
cryptographic soundness, enforce an OS memory limit, or verify a chain proof.
Python 3.10+; standard library only.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any

MAX_PLAN_BYTES = 65536
APPROVED_STAGES = ("nova-pallas-vesta-pedersen", "spartan-ipa")
SOURCE = {
    "repository": "patrickdugan/zk-rusto-no-bitcoino",
    "revision": "de607d3db17d400dd6c2923d357f1d4a7bf233c7",
    "integration_path": "integrations/nova-header-chain",
    "nova_snark_version": "0.76.0",
}
STATEMENTS = {
    "mainnet": "btc_header_chain_v1",
    "testnet4": "btc_header_chain_testnet4_v1",
}


class PolicyError(ValueError):
    """The declared plan failed a required policy check."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PolicyError(message)


def keys(value: Any, expected: set[str], label: str) -> None:
    require(type(value) is dict, f"{label}: expected an object")
    require(set(value) == expected, f"{label}: missing or unknown fields")


def uint(value: Any, lower: int, upper: int, label: str) -> None:
    require(type(value) is int and lower <= value <= upper,
            f"{label}: expected integer in [{lower}, {upper}]")


def digest(value: Any, label: str) -> None:
    require(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None,
            f"{label}: expected lowercase SHA-256 hex")


def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def reject_constant(value: str) -> None:
    raise PolicyError(f"non-finite JSON constant: {value}")


def load_plan(path: Path) -> dict[str, Any]:
    with path.open("rb") as stream:
        raw = stream.read(MAX_PLAN_BYTES + 1)
    require(len(raw) <= MAX_PLAN_BYTES, "plan exceeds 64 KiB")
    try:
        plan = json.loads(raw.decode("utf-8"), object_pairs_hook=no_duplicates,
                          parse_constant=reject_constant)
    except (UnicodeError, ValueError, RecursionError) as error:
        raise PolicyError(f"invalid plan JSON: {error}") from error
    validate(plan)
    return plan


def validate(plan: Any) -> None:
    keys(plan, {"schema", "profile", "stages", "trusted_setup", "post_quantum_claim",
                "zero_knowledge_claim", "source", "workload", "budget"}, "plan")
    require(plan["schema"] == "transparent-snarks-plan/v1", "unknown schema")
    require(plan["profile"] == "nova-spartan-ipa", "profile requires explicit review")
    require(type(plan["stages"]) is list and plan["stages"] == list(APPROVED_STAGES),
            "pipeline must end with Spartan/IPA; extra or changed stages require review")
    require(plan["trusted_setup"] == "forbidden", "trusted setup must stay forbidden")
    require(plan["post_quantum_claim"] is False, "IPA profile has no post-quantum claim")
    require(plan["zero_knowledge_claim"] is False,
            "privacy needs separate review; continuations contain witness material")
    keys(plan["source"], set(SOURCE), "source")
    require(plan["source"] == SOURCE, "source pin changed: review code and update policy")

    w = plan["workload"]
    keys(w, {"unit", "network", "statement", "anchor_mode", "start_height",
             "checkpoint_state_sha256", "fixture_sha256", "headers_per_step",
             "total_headers"}, "workload")
    require(w["unit"] == "headers", "use header counts, never ambiguous rows")
    require(type(w["network"]) is str and w["network"] in STATEMENTS, "unknown network")
    require(w["statement"] == STATEMENTS[w["network"]], "network/statement mismatch")
    uint(w["start_height"], 0, 2**32 - 1, "start_height")
    if w["anchor_mode"] == "genesis":
        require(w["start_height"] == 0 and w["checkpoint_state_sha256"] is None,
                "genesis mode requires height zero and no external checkpoint")
    elif w["anchor_mode"] == "authenticated-checkpoint":
        require(w["start_height"] > 0, "checkpoint mode requires a positive start height")
        digest(w["checkpoint_state_sha256"], "checkpoint_state_sha256")
    else:
        raise PolicyError("unknown anchor mode")
    if w["fixture_sha256"] is not None:
        digest(w["fixture_sha256"], "fixture_sha256")
    for field, max_value in (("headers_per_step", 1024), ("total_headers", 10000000)):
        values = w[field]
        require(type(values) is list and 1 <= len(values) <= 32, f"{field}: invalid list")
        for value in values:
            uint(value, 1, max_value, field)
        require(len(set(values)) == len(values), f"{field}: duplicate entries")
    for total in w["total_headers"]:
        require(w["start_height"] + total <= 2**32 - 1, "end height overflows u32")
        for width in w["headers_per_step"]:
            require(total % width == 0, "total headers must divide exactly into fold steps")

    b = plan["budget"]
    keys(b, {"memory_max_bytes", "memory_swap_max_bytes"}, "budget")
    uint(b["memory_max_bytes"], 1, 13 * 2**30, "memory_max_bytes")
    uint(b["memory_swap_max_bytes"], 0, 0, "memory_swap_max_bytes")


def matrix(plan: dict[str, Any]) -> dict[str, Any]:
    validate(plan)
    encoded = json.dumps(plan, sort_keys=True, separators=(",", ":")).encode()
    w = plan["workload"]
    return {
        "kind": "benchmark-plan-only",
        "plan_sha256": hashlib.sha256(encoded).hexdigest(),
        "proof_executed": False,
        "os_memory_limit_enforced": False,
        "fixture_pinned": w["fixture_sha256"] is not None,
        "checkpoint_trust_required": w["anchor_mode"] == "authenticated-checkpoint",
        "cases": [
            {"network": w["network"], "statement": w["statement"],
             "start_height": w["start_height"], "end_height": w["start_height"] + total,
             "total_headers": total, "headers_per_step": width, "fold_steps": total // width,
             "memory_max_bytes": plan["budget"]["memory_max_bytes"],
             "memory_swap_max_bytes": 0}
            for total in w["total_headers"] for width in w["headers_per_step"]
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("check", "matrix"))
    parser.add_argument("plan", type=Path)
    args = parser.parse_args()
    try:
        plan = load_plan(args.plan)
        result = matrix(plan) if args.action == "matrix" else {
            "ok": True, "scope": "declared-plan-only", "profile": plan["profile"],
            "source_revision": plan["source"]["revision"],
            "proof_executed": False,
        }
        print(json.dumps(result, indent=2, sort_keys=True, allow_nan=False))
        return 0
    except (OSError, PolicyError) as error:
        print(json.dumps({"ok": False, "error": str(error)}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
