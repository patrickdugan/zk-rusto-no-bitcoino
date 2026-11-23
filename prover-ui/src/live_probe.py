"""Read-only Linux runtime probe. No job starts, restarts, or control writes.

Extends the original incremental progress collector with process identity,
systemd/cgroup measurements and hash-bound independent-verifier receipts.
Only a bounded, public summary crosses back to the desktop.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

MAX_JSON = 2 * 1024 * 1024


def read_json(path):
    try:
        if path.stat().st_size > MAX_JSON:
            return None
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return None


def command(args):
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=2)
        return p.stdout[:65536] if p.returncode == 0 else ""
    except (OSError, subprocess.TimeoutExpired):
        return ""


def number(value):
    try:
        n = int(value)
        return n if 0 <= n < 2**63 else None
    except (ValueError, TypeError):
        return None


def receipt(root, filename, proof_name):
    path = root / filename
    data = read_json(path)
    result = {"path": str(path), "present": path.is_file(), "valid": False}
    if not isinstance(data, dict):
        return result
    proof = root / proof_name
    expected = data.get("proof_sha256")
    actual = None
    try:
        # Proofs are hashed only after an audit appears, never while being written.
        if proof.stat().st_size <= 512 * 1024 * 1024 and isinstance(expected, str):
            with proof.open("rb") as f:
                actual = hashlib.file_digest(f, "sha256").hexdigest()
    except OSError:
        pass
    controls = data.get("negative_controls", [])
    if not isinstance(controls, list):
        controls = []
    checks = sum(isinstance(c, dict) and c.get("exit_code") == 1 for c in controls)
    valid = (data.get("status") == "independently_verified_with_negative_controls"
             and data.get("stark_verified") is True and actual is not None
             and expected == actual and isinstance(controls, list) and len(controls) >= 15
             and checks == len(controls))
    result.update(status=data.get("status"), valid=valid, proof_sha256=actual,
                  hash_matches=actual is not None and actual == expected,
                  negative_controls_passed=checks, negative_controls_total=len(controls),
                  statement=data.get("claim"), modified_at_unix=path.stat().st_mtime,
                  proof_bytes=proof.stat().st_size if proof.exists() else None)
    return result


def inspect_unit(name, expected_exe):
    props = ["Id", "ActiveState", "SubState", "MainPID", "Result", "ExecMainStatus",
             "MemoryCurrent", "MemoryPeak", "MemoryMax", "MemorySwapCurrent",
             "MemorySwapMax", "CPUQuotaPerSecUSec", "CPUUsageNSec", "ControlGroup"]
    raw = command(["systemctl", "show", name, "--property=" + ",".join(props)])
    fields = dict(line.split("=", 1) for line in raw.splitlines() if "=" in line)
    pid = number(fields.get("MainPID"))
    identity = None
    if pid:
        try:
            proc = Path("/proc") / str(pid)
            executable = os.readlink(proc / "exe").removesuffix(" (deleted)")
            stat = (proc / "stat").read_text().rsplit(")", 1)[1].split()
            cgroup = (proc / "cgroup").read_text()
            if executable == expected_exe and name in cgroup and stat[0] != "Z":
                identity = {"pid": pid, "start_ticks": int(stat[19]),
                            "executable": executable, "state": stat[0]}
        except (OSError, ValueError, IndexError):
            pass
    running = identity is not None and fields.get("ActiveState") == "active"
    logs = command(["journalctl", "--unit=" + name, "-n", "12", "--no-pager", "-o", "cat"])
    logs = re.sub(r"\x1b\[[0-9;]*m", "", logs)
    lines = [line[-400:] for line in logs.splitlines() if line.strip()][-8:]
    phase = next((line.split(": enter")[0].strip() for line in reversed(lines)
                  if ": enter" in line), None)
    if phase:
        phase = phase.split("prove:", 1)[-1].split(": ", 1)[0]
    cpu_ns = number(fields.get("CPUUsageNSec"))
    return {"unit": name, "observed_state": fields.get("ActiveState", "unavailable"),
            "running": running, "process": identity, "phase": phase, "log_tail": lines,
            "exit_code": number(fields.get("ExecMainStatus")), "result": fields.get("Result"),
            "cpu_seconds": cpu_ns / 1e9 if cpu_ns is not None else None,
            "ram_bytes": number(fields.get("MemoryCurrent")),
            "peak_ram_bytes": number(fields.get("MemoryPeak")),
            "swap_bytes": number(fields.get("MemorySwapCurrent")),
            "ram_limit_bytes": number(fields.get("MemoryMax")),
            "swap_limit_bytes": number(fields.get("MemorySwapMax"))}


def scan_provers():
    # Process names alone do not establish GPU use; report the observed executable.
    names = {"ark-prove-gpu-cached-gkr", "ark-prove-gpu", "nb3-prove-gpu", "nb3-prove"}
    processes = []
    for proc in Path("/proc").iterdir():
        if not proc.name.isdigit():
            continue
        try:
            exe = os.readlink(proc / "exe").removesuffix(" (deleted)")
            if Path(exe).name not in names:
                continue
            stat = (proc / "stat").read_text().rsplit(")", 1)[1].split()
            if stat[0] != "Z":
                processes.append({"pid": int(proc.name), "executable": exe,
                                  "start_ticks": int(stat[19]), "state": stat[0]})
        except (OSError, ValueError, IndexError):
            pass
    return processes[:16]


def collect(config):
    root = Path(config.get("proof_root", "/var/tmp/proof-grove-shinigami-20261123"))
    jobs = []
    defaults = [
        ("Testnet4 Tapleaf", "proof-grove-real-tapleaf-proof-20261123.service",
         "testnet4-real-tapleaf.proof.json", "tapleaf-independent-audit.json"),
        ("Testnet4 Legacy Payment", "proof-grove-shinigami-canonical-20261123.service",
         "testnet4-canonical.proof.json", "independent-audit.json"),
    ]
    specs = config.get("jobs", [dict(title=label, unit=unit, proof=proof, audit=audit,
                                    executable="/root/build/s3o/prove-clean",
                                    backend="Stwo SIMD / CPU", network="testnet4")
                                for label, unit, proof, audit in defaults])
    for spec in specs[:16]:
        label, unit, proof, audit = (spec[k] for k in ("title", "unit", "proof", "audit"))
        job = inspect_unit(unit, spec["executable"])
        job.update(id=unit, title=label, backend=spec.get("backend"), network=spec.get("network"),
                   audit=receipt(root, audit, proof))
        job["status"] = ("running" if job["running"] else
                         "failed" if job["observed_state"] == "failed" else
                         "verified receipt" if job["audit"]["valid"] else "inactive")
        jobs.append(job)
    ark_progress = Path(config.get("ark_root", "/var/tmp/ark-asp-full-20261117")) / "prover-transient/progress.jsonl"
    return {"sampled_at_unix": time.time(), "reachable": True, "jobs": jobs,
            "ark_progress_path": str(ark_progress.resolve()) if ark_progress.is_file() else None,
            "ark_processes": scan_provers(), "source": "systemd + /proc + cgroup v2 + local audit files"}


if __name__ == "__main__":
    try:
        print(json.dumps(collect(json.load(sys.stdin)), separators=(",", ":")))
    except Exception as exc:
        print(json.dumps({"reachable": False, "error": type(exc).__name__,
                          "sampled_at_unix": time.time()}))
