#!/usr/bin/env python3
"""Prepare or explicitly run the isolated LNMarkets SP1 workflow.

No arguments, --dry-run, and every invocation without --run are read-only.
The runner never installs software, chooses a network prover, or trusts a pin
from a proof bundle. Pin values come from the caller's reviewed configuration.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess
import sys
import time
import tomllib

ROOT = Path(__file__).resolve().parents[2]
LNM = ROOT / "LNMarkets"
SP1_VERSION = "6.9.0"
# The SP1 CLI prints its tagged source commit instead of semantic version.
SP1_CLI_TAG_COMMIT = "b8387fa61e1361d90ee7de49f551863418ca0f08"
MAX_WITNESS_BYTES = 512 * 1024
MAX_ELF_BYTES = 64 * 1024 * 1024
MAX_PROOF_BYTES = 64 * 1024 * 1024
# The host enforces the shared relation's exact JOURNAL_LEN.
MAX_JOURNAL_BYTES = 4096
WORKER_ENV = (
    "SP1_WORKER_NUM_CORE_WORKERS",
    "SP1_WORKER_NUM_RECURSION_PROVER_WORKERS",
    "SP1_WORKER_NUM_RECURSION_EXECUTOR_WORKERS",
    "SP1_WORKER_NUM_PREPARE_REDUCE_WORKERS",
    "SP1_WORKER_NUM_SETUP_WORKERS",
    "SP1_WORKER_NUM_SPLICING_WORKERS",
    "SP1_WORKER_NUM_DEFERRED_WORKERS",
    "SP1_WORKER_CORE_BUFFER_SIZE",
    "SP1_WORKER_RECURSION_EXECUTOR_BUFFER_SIZE",
    "SP1_WORKER_RECURSION_PROVER_BUFFER_SIZE",
    "SP1_WORKER_SETUP_BUFFER_SIZE",
    "SP1_WORKER_NUMBER_OF_GAS_EXECUTORS",
    "SP1_WORKER_NUMBER_OF_SEND_SPLICE_WORKERS_PER_SPLICE",
    "SP1_WORKER_SPLICING_BUFFER_SIZE",
)
PRIVATE_DUMP_ENV = (
    "SP1_DUMP", "SP1_RECORD_WRITE_DIR", "SP1_RECORD_MAX_ARITY_INPUT", "SP1_RECORD_SHRINK_INPUT",
)


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "action", nargs="?", default="prepare",
        choices=("prepare", "build", "describe", "execute", "compressed", "groth16", "verify"),
    )
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--run", action="store_true", help="execute this explicit action locally")
    mode.add_argument("--dry-run", action="store_true", help="inspect files and print commands only")
    p.add_argument("--work-dir", type=Path, default=LNM / ".local" / "prover")
    p.add_argument("--elf", type=Path)
    p.add_argument("--witness", type=Path)
    p.add_argument("--journal", type=Path)
    p.add_argument("--elf-sha256")
    p.add_argument("--program-vk")
    p.add_argument("--journal-sha256")
    p.add_argument("--proof", type=Path, help="existing proof for verify")
    p.add_argument("--mode", choices=("compressed", "groth16"), help="required by verify")
    p.add_argument("--host", type=Path, default=LNM / "sp1" / "host" / "target" / "release" / "lnm-sp1-host")
    p.add_argument("--nb3-prove", type=Path, default=LNM / "sp1" / "host" / "target" / "release" / "lnm-nb3-prove")
    return p


def normalized_pin(value: str | None, name: str) -> str:
    if value is None:
        raise ValueError(f"missing {name}")
    value = value.removeprefix("0x")
    if not re.fullmatch(r"[0-9a-fA-F]{64}", value):
        raise ValueError(f"{name} must contain exactly 32 hex bytes")
    return value.lower()


def file_info(path: Path, cap: int) -> dict:
    with path.open("rb") as file:
        metadata = os.fstat(file.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > cap:
            raise ValueError(f"{path} must be a regular file of at most {cap} bytes")
        data = file.read(cap + 1)
    if len(data) > cap:
        raise ValueError(f"{path} grew beyond its byte cap")
    return {"path": str(path.resolve()), "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def executable(path: Path) -> bool:
    return path.is_file() and os.access(path, os.X_OK)


def check_sp1_lock(path: Path) -> int:
    """Require the whole protocol family to share the reviewed SDK version."""
    with path.open("rb") as file:
        packages = tomllib.load(file)["package"]
    family = [p for p in packages if p["name"].startswith(("sp1-", "slop-"))]
    if not family:
        raise ValueError(f"SP1 lock contains no protocol packages: {path}")
    drift = [f'{p["name"]}={p["version"]}' for p in family if p["version"] != SP1_VERSION]
    if drift:
        raise ValueError(f"SP1 dependency drift in {path}: {', '.join(drift)}")
    return len(family)


def make_plan(args: argparse.Namespace) -> dict:
    """Pure preflight: inspect local files and return argv arrays, never spawn."""
    work = args.work_dir.resolve()
    host = args.host.resolve()
    nb3 = args.nb3_prove.resolve()
    plan = {
        "schema": "lnm-local-prover-plan/v1",
        "status": "prepared_unrun",
        "action": args.action,
        "sp1_sdk_version": SP1_VERSION,
        "sp1_circuit_mode": "release",
        "work_dir": str(work),
        "zero_knowledge_proof_verified": False,
        "proofs_started": False,
        "backend": "local_cpu",
        "tooling": {
            "cargo": shutil.which("cargo"),
            "cargo_prove": shutil.which("cargo-prove"),
            "host": str(host) if executable(host) else None,
            "nb3_prove": str(nb3) if executable(nb3) else None,
        },
        "files": {}, "commands": [], "blockers": [], "outputs": [],
    }
    blockers = plan["blockers"]
    if os.environ.get("SP1_CIRCUIT_MODE", "release") != "release":
        blockers.append("SP1_CIRCUIT_MODE must be unset or release; development circuit verification is unsupported")

    def add_command(argv: list[str], cwd: Path = ROOT) -> None:
        plan["commands"].append({"argv": argv, "cwd": str(cwd), "display": shlex.join(argv)})

    def check_file(name: str, path: Path | None, cap: int, required: bool) -> dict | None:
        if path is None:
            if required:
                blockers.append(f"missing --{name}")
            return None
        try:
            info = file_info(path, cap)
            plan["files"][name] = info
            return info
        except (OSError, ValueError) as error:
            blockers.append(str(error))
            return None

    def add_output(name: str) -> str:
        path = work / name
        if path.exists():
            blockers.append(f"output already exists: {path}; choose another --work-dir or use verify")
        plan["outputs"].append(str(path))
        return str(path)

    if args.action == "prepare":
        check_file("witness", args.witness, MAX_WITNESS_BYTES, False)
        check_file("journal", args.journal, MAX_JOURNAL_BYTES, False)
        check_file("elf", args.elf, MAX_ELF_BYTES, False)
        plan["next_steps"] = [
            "Generate and inspect synthetic fixtures with lnm-native.",
            "Review the pinned SP1 6.9.0 toolchain, then run the build action.",
            "Run describe, review the ELF hash and program key, and pin the expected journal externally.",
            "Execute with all pins before requesting an explicit compressed or Groth16 proof.",
        ]
    elif args.action == "build":
        if not plan["tooling"]["cargo"]:
            blockers.append("cargo is unavailable")
        if not plan["tooling"]["cargo_prove"]:
            blockers.append("SP1 cargo-prove 6.9.0 is unavailable")
        for crate in ("program", "host"):
            lock = LNM / "sp1" / crate / "Cargo.lock"
            try:
                check_sp1_lock(lock)
            except (OSError, ValueError, KeyError) as error:
                blockers.append(str(error))
        add_command([
            "cargo", "prove", "build", "--locked", "--output-directory", str(work / "elf"),
            "--elf-name", "lnm-batch.elf",
        ], LNM / "sp1" / "program")
        add_command(["cargo", "build", "--locked", "--release", "--manifest-path", str(LNM / "sp1" / "host" / "Cargo.toml")])
        plan["additional_build"] = {
            "purpose": "Build the optional resumable compressed prover when choosing compressed later.",
            "argv": ["cargo", "build", "--locked", "--release", "--manifest-path", str(LNM / "sp1" / "host" / "Cargo.toml"), "--features", "resumable", "--bin", "lnm-nb3-prove"],
        }
    else:
        needs_pins = args.action != "describe"
        needs_witness = args.action in ("execute", "compressed", "groth16")
        elf = check_file("elf", args.elf, MAX_ELF_BYTES, True)
        journal = check_file("journal", args.journal, MAX_JOURNAL_BYTES, needs_pins)
        check_file("witness", args.witness, MAX_WITNESS_BYTES, needs_witness)
        if not executable(host):
            blockers.append(f"host executable is unavailable: {host}")
        common: list[str] = []
        if elf is not None:
            common = ["--elf", elf["path"]]
        pins = {}
        if needs_pins:
            for name, value in (("elf-sha256", args.elf_sha256), ("program-vk", args.program_vk), ("journal-sha256", args.journal_sha256)):
                try:
                    pins[name] = normalized_pin(value, f"--{name}")
                except ValueError as error:
                    blockers.append(str(error))
            for name, info in (("elf-sha256", elf), ("journal-sha256", journal)):
                if info is not None and name in pins and info["sha256"] != pins[name]:
                    blockers.append(f"{name} does not match the supplied file")
            if len(pins) == 3 and journal is not None:
                common += [
                    "--expect-elf-sha256", pins["elf-sha256"], "--expect-program-vk", pins["program-vk"],
                    "--journal", journal["path"], "--expect-journal-sha256", pins["journal-sha256"],
                ]
        witness_args = ["--witness", str(args.witness.resolve())] if args.witness is not None else []
        if args.action == "describe":
            add_command([str(host), "describe-program", *common, "--report", add_output("program-candidate.json")])
        elif args.action == "execute":
            add_command([str(host), "execute", *common, *witness_args, "--report", add_output("execution.json")])
        elif args.action == "compressed":
            if not executable(nb3):
                blockers.append(f"resumable CPU prover is unavailable: {nb3}")
            preexecute = add_output(f"precompressed-execution-{time.time_ns()}.json")
            proof = add_output("compressed-proof.bin")
            verification = add_output("compressed-verification.json")
            add_command([str(host), "execute", *common, *witness_args, "--report", preexecute])
            if elf is not None and args.witness is not None and "journal-sha256" in pins:
                add_command([
                    str(nb3), "prove", "--elf", elf["path"], "--input", str(args.witness.resolve()),
                    "--run-dir", str(work / "compressed-checkpoints"), "--out", proof,
                    "--permits", "1", "--trace-chunk-slots", "1",
                    "--expect-public-sha256", pins["journal-sha256"],
                ])
            add_command([str(host), "verify-proof", *common, "--mode", "compressed", "--proof", proof, "--report", verification])
            plan["proof_mode"] = "compressed_stark_not_zk"
        elif args.action == "groth16":
            add_command([
                str(host), "prove-groth16", *common, *witness_args, "--proof", add_output("groth16-proof.bin"),
                "--report", add_output("groth16-verification.json"), "--allow-cpu-proving",
            ])
            plan["proof_mode"] = "groth16_full_cpu_from_witness"
        elif args.action == "verify":
            proof = check_file("proof", args.proof, MAX_PROOF_BYTES, True)
            if args.mode is None:
                blockers.append("verify requires --mode compressed|groth16")
            if proof is not None and args.mode is not None:
                add_command([
                    str(host), "verify-proof", *common, "--mode", args.mode, "--proof", proof["path"],
                    "--report", add_output(f"{args.mode}-public-verification.json"),
                ])
    plan["ready"] = not blockers
    return plan


def is_pinned_sp1_cli(version_output: str) -> bool:
    """Match the SP1 v6.9.0 tag's source SHA in cargo-prove's version string."""
    pattern = r"\bsp1\s+\(" + re.escape(SP1_CLI_TAG_COMMIT[:7]) + r"[0-9a-f]{0,33}\s+[^)]*\)"
    return re.search(pattern, version_output) is not None


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    plan = make_plan(args)
    print(json.dumps(plan, indent=2), flush=True)
    if not args.run or args.action == "prepare":
        return 0
    if plan["blockers"]:
        print("Local run blocked by the listed preflight errors.", file=sys.stderr)
        return 2
    env = os.environ.copy()
    for key in PRIVATE_DUMP_ENV:
        env.pop(key, None)
    env["SP1_PROVER"] = "cpu"
    env["SP1_CIRCUIT_MODE"] = "release"
    for key in WORKER_ENV:
        env.setdefault(key, "1")
    if args.action == "build":
        version = subprocess.run(["cargo", "prove", "--version"], text=True, capture_output=True, check=True, env=env)
        if not is_pinned_sp1_cli(version.stdout + version.stderr):
            print("Build requires cargo-prove built from SP1 v6.9.0 tag b8387fa.", file=sys.stderr)
            return 2
    os.umask(0o077)
    work = args.work_dir.resolve()
    work.mkdir(parents=True, exist_ok=True, mode=0o700)
    work.chmod(0o700)
    for command in plan["commands"]:
        subprocess.run(command["argv"], cwd=command["cwd"], env=env, check=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, subprocess.CalledProcessError, ValueError) as error:
        print(f"local prover: {error}", file=sys.stderr)
        raise SystemExit(2)
