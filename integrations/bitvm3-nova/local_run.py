#!/usr/bin/env python3
"""Run bounded-concurrency Nova component tests; native suite proves a toy only."""
from __future__ import annotations
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone

FEATURES = 'native-reference,curve-reference'

def positive(value: str) -> int:
    result = int(value)
    if result < 1:
        raise argparse.ArgumentTypeError('must be at least 1')
    return result

def ram_snapshot() -> dict[str, int | None]:
    try:
        if sys.platform == 'win32':
            class Memory(ctypes.Structure):
                _fields_ = [('length', ctypes.c_ulong), ('load', ctypes.c_ulong)] + [
                    (name, ctypes.c_ulonglong) for name in
                    ('total', 'available', 'page_total', 'page_available', 'virtual_total', 'virtual_available', 'extended')]
            status = Memory()
            status.length = ctypes.sizeof(status)
            if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
                raise OSError('GlobalMemoryStatusEx failed')
            return {'total_bytes': status.total, 'available_bytes': status.available}
        if Path('/proc/meminfo').exists():
            items = {}
            for line in Path('/proc/meminfo').read_text().splitlines():
                key, rest = line.split(':', 1)
                items[key] = int(rest.split()[0]) * 1024
            return {'total_bytes': items.get('MemTotal'), 'available_bytes': items.get('MemAvailable')}
        return {'total_bytes': os.sysconf('SC_PHYS_PAGES') * os.sysconf('SC_PAGE_SIZE'), 'available_bytes': None}
    except (OSError, ValueError, AttributeError):
        return {'total_bytes': None, 'available_bytes': None}

def plans(suite: str, output: Path) -> list[tuple[str, list[str], list[str]]]:
    common = ['--release', '--locked', '--manifest-path', 'nova-bitvm3/Cargo.toml']
    flags = ['--features', FEATURES]
    targets = {
        'smoke': ['--lib'],
        'transcript': ['--test', 'transcript', '--test', 'boolean_transcript', '--test', 'structured_transcript'],
        'curves': ['--test', 'curves'],
        'sumcheck': ['--test', 'sumcheck'],
        'all': ['--lib', '--test', 'curves', '--test', 'transcript', '--test', 'boolean_transcript', '--test', 'structured_transcript', '--test', 'sumcheck'],
    }
    if suite == 'native':
        target = ['--features', 'native-reference', '--bin', 'nova-reference']
        return [('native_toy', ['build', *common, *target],
                 ['run', *common, *target, '--', str(output / 'native-toy')])]
    target = targets[suite]
    return [(suite, ['test', *common, *flags, *target, '--no-run'],
             ['test', *common, *flags, *target, '--no-fail-fast', '--', '--nocapture', '--test-threads=1'])]

def optional_command(args: list[str], cwd: Path) -> str | None:
    try:
        result = subprocess.run(args, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, check=False, timeout=15)
        return result.stdout.strip() if result.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired):
        return None

def run_logged(args: list[str], cwd: Path, env: dict[str, str], log: Path, timeout: int) -> dict:
    start = time.monotonic()
    print(f'Running {log.name}: {subprocess.list2cmdline(args)}', flush=True)
    status = {'command': args, 'log': str(log), 'status': 'running'}
    kwargs = {'start_new_session': True} if os.name != 'nt' else {}
    with log.open('wb') as stream:
        process = subprocess.Popen(args, cwd=cwd, env=env, stdout=stream, stderr=subprocess.STDOUT, **kwargs)
        try:
            code = process.wait(timeout=timeout)
            status.update(status='passed' if code == 0 else 'failed', exit_code=code)
        except (subprocess.TimeoutExpired, KeyboardInterrupt) as error:
            if os.name == 'nt':
                subprocess.run(['taskkill', '/PID', str(process.pid), '/T', '/F'],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
                process.kill()
            else:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            process.wait()
            status.update(status='timeout' if isinstance(error, subprocess.TimeoutExpired) else 'interrupted', exit_code=process.returncode)
    status['elapsed_seconds'] = time.monotonic() - start
    status['log_sha256'] = hashlib.sha256(log.read_bytes()).hexdigest()
    print(f"{status['status']}: {log.name} ({status['elapsed_seconds']:.2f}s)", flush=True)
    return status

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--suite', choices=['smoke', 'transcript', 'curves', 'sumcheck', 'all', 'native'], default='transcript')
    parser.add_argument('--jobs', type=positive, default=2, help='Cargo build parallelism')
    parser.add_argument('--threads', type=positive, default=2, help='Rayon parallelism; tests stay serial')
    parser.add_argument('--timeout-minutes', type=positive, default=30, help='per command, not total run')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--lockfile', type=Path, help='reuse a CI artifact lockfile; refuses conflicting existing lock')
    parser.add_argument('--build-only', action='store_true')
    parser.add_argument('--plan', action='store_true', help='print commands without requiring Cargo or writing files')
    args = parser.parse_args(argv)
    repo = Path(__file__).resolve().parent.parent
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    output = (args.output or repo / 'nova-bitvm3' / 'results' / f'local-{stamp}').resolve()
    plan = plans(args.suite, output)
    if args.plan:
        commands = []
        for name, build, execute in plan:
            commands.append({'phase': f'{name}_build', 'argv': ['cargo', '+1.90.0', *build]})
            if not args.build_only:
                commands.append({'phase': f'{name}_run', 'argv': ['cargo', '+1.90.0', *execute]})
        print(json.dumps({'commands': commands, 'CARGO_BUILD_JOBS': args.jobs,
                          'RAYON_NUM_THREADS': args.threads, 'suite': args.suite,
                          'full_garbled_nova_verifier': False}, indent=2))
        return 0
    cargo = shutil.which('cargo')
    if cargo is None:
        parser.error('Cargo is missing. Install Rust with rustup and toolchain 1.90.0.')
    if not (repo / 'nova-bitvm3' / 'Cargo.toml').is_file():
        parser.error('run this script from its checked-out nova-bitvm3 directory')
    lock = repo / 'nova-bitvm3' / 'Cargo.lock'
    supplied_lock = args.lockfile.resolve() if args.lockfile else None
    if supplied_lock and not supplied_lock.is_file():
        parser.error('--lockfile must point to an existing CI artifact Cargo.lock')
    if supplied_lock and lock.exists() and supplied_lock.read_bytes() != lock.read_bytes():
        parser.error('existing Cargo.lock differs; keep it or move it aside explicitly before importing the CI lock')
    if output.exists():
        parser.error('output directory exists; choose a fresh path to preserve prior evidence')
    output.mkdir(parents=True)
    env = os.environ.copy()
    env.update(CARGO_BUILD_JOBS=str(args.jobs), RAYON_NUM_THREADS=str(args.threads), CARGO_INCREMENTAL='0')
    env.setdefault('RUSTFLAGS', '-C debuginfo=0')
    receipt = {
        'schema': 'nova-bitvm3-local-v1', 'started_utc': stamp,
        'git_commit': optional_command(['git', 'rev-parse', 'HEAD'], repo),
        'tracked_worktree_status': optional_command(['git', 'status', '--porcelain', '--untracked-files=no'], repo),
        'platform': platform.platform(), 'python': platform.python_version(),
        'logical_cpus': os.cpu_count(), 'ram': ram_snapshot(),
        'free_disk_bytes': shutil.disk_usage(output).free,
        'suite': args.suite, 'build_only': args.build_only, 'steps': [],
        'env': {k: env[k] for k in ['CARGO_BUILD_JOBS', 'RAYON_NUM_THREADS', 'CARGO_INCREMENTAL', 'RUSTFLAGS']},
        'scope': 'native_toy_proof' if args.suite == 'native' else 'component_conformance',
        'hard_memory_limit_enforced': False, 'runtime_peak_rss_measured': False,
        'full_garbled_nova_verifier': False, 'status': 'running',
        'cargo_version': optional_command([cargo, '+1.90.0', '--version'], repo),
    }
    receipt_path = output / 'receipt.json'
    def save() -> None:
        temporary = output / 'receipt.tmp'
        temporary.write_text(json.dumps(receipt, indent=2) + '\n', encoding='utf-8')
        temporary.replace(receipt_path)
    def step(name: str, command: list[str]) -> bool:
        result = run_logged(command, repo, env, output / f'{name}.log', args.timeout_minutes * 60)
        receipt['steps'].append(result)
        save()
        return result['status'] == 'passed'
    save()
    try:
        if supplied_lock and not lock.exists():
            shutil.copyfile(supplied_lock, lock)
        if not lock.exists():
            receipt['lock_origin'] = 'resolved_locally'
            if not step('dependency_resolution', [cargo, '+1.90.0', 'generate-lockfile', '--manifest-path', 'nova-bitvm3/Cargo.toml']):
                receipt['status'] = 'failed'
                return 1
        else:
            receipt['lock_origin'] = 'supplied_ci' if supplied_lock else 'existing'
        shutil.copyfile(lock, output / 'Cargo.lock')
        receipt['lock_sha256'] = hashlib.sha256(lock.read_bytes()).hexdigest()
        if not step('dependencies', [cargo, '+1.90.0', 'tree', '--locked', '--manifest-path', 'nova-bitvm3/Cargo.toml', '--features', FEATURES]):
            receipt['status'] = 'failed'
            return 1
        for name, build, execute in plan:
            if not step(f'{name}_build', [cargo, '+1.90.0', *build]):
                receipt['status'] = 'failed'; return 1
            if not args.build_only and not step(f'{name}_run', [cargo, '+1.90.0', *execute]):
                receipt['status'] = 'failed'; return 1
        receipt['status'] = 'build_passed' if args.build_only else 'passed'
        return 0
    except (OSError, KeyboardInterrupt) as error:
        receipt['status'] = 'failed'; receipt['error'] = str(error)
        return 1
    finally:
        receipt['artifacts'] = {str(p.relative_to(output)): hashlib.sha256(p.read_bytes()).hexdigest()
                                for p in output.rglob('*') if p.is_file() and p.name not in {'receipt.json', 'receipt.tmp'}}
        receipt['finished_utc'] = datetime.now(timezone.utc).isoformat()
        save()
        print(f'Receipt: {receipt_path}', flush=True)

if __name__ == '__main__':
    raise SystemExit(main())
