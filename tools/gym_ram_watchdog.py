"""Guard a CPU-only gym command: reclaim idle, large leaf workers under RAM pressure."""
import argparse
import json
import math
import subprocess
import sys
import time


def positive(value):
    n = float(value)
    if not math.isfinite(n) or n <= 0:
        raise argparse.ArgumentTypeError("expected a finite positive number")
    return n


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--reserve-mib", type=positive, default=2048)
    p.add_argument("--worker-mib", type=positive, default=512)
    p.add_argument("--idle-seconds", type=positive, default=120)
    p.add_argument("--sample-seconds", type=positive, default=5)
    p.add_argument("--cpu-percent", type=positive, default=1)
    p.add_argument("--cpu-only", action="store_true", required=True,
                   help="attest this run has no accelerator workers; do not use for GPU/TPU jobs")
    p.add_argument("--kill-grace-seconds", type=positive, default=15)
    p.add_argument("--report-only", action="store_true")
    p.add_argument("command", nargs=argparse.REMAINDER)
    a = p.parse_args()
    cmd = a.command[1:] if a.command[:1] == ["--"] else a.command
    if not cmd:
        p.error("supply a command after --")
    try:
        import psutil
    except ImportError:
        p.error("psutil is required; no command was started")
    root_child = subprocess.Popen(cmd)
    samples = {}
    acted = {}
    triggered = False
    mib = 1024 ** 2
    try:
        root = psutil.Process(root_child.pid)
        while root_child.poll() is None:
            now = time.monotonic()
            try:
                free = psutil.virtual_memory().available / mib
                children = root.children(recursive=True)
            except (psutil.Error, OSError):
                samples.clear()
                time.sleep(a.sample_seconds)
                continue
            fresh = {}
            for worker in children:
                try:
                    key = (worker.pid, worker.create_time())
                    cpu = worker.cpu_times()
                    ticks = cpu.user + cpu.system
                    rss = worker.memory_info().rss / mib
                    eligible = (free < a.reserve_mib and rss >= a.worker_mib
                                and worker.status() not in (psutil.STATUS_STOPPED,
                                                            psutil.STATUS_ZOMBIE)
                                and not worker.children())
                    if not eligible:
                        continue
                    last = samples.get(key)
                    since = now
                    if last is not None:
                        stamp, previous, start = last
                        rate = 100 * (ticks - previous) / (now - stamp)
                        if 0 <= rate < a.cpu_percent and now - stamp <= 3 * a.sample_seconds:
                            since = start
                    fresh[key] = (now, ticks, since)
                    prior = acted.get(key)
                    if (now - since < a.idle_seconds or
                            (prior is not None and (a.report_only or prior[1] or
                                                    now - prior[0] < a.kill_grace_seconds))):
                        continue
                    # Confirm that this exact process still belongs to this run.
                    if (root_child.poll() is not None or not root.is_running()
                            or not worker.is_running() or worker.children()
                            or worker not in root.children(recursive=True)
                            or psutil.virtual_memory().available / mib >= a.reserve_mib):
                        continue
                    event = {"event": "gym_ram_watchdog", "pid": key[0],
                             "rss_mib": round(rss), "available_mib": round(free),
                             "idle_seconds": round(now - since, 2),
                             "action": ("would_terminate" if a.report_only else
                                        "kill" if prior else "terminate")}
                    if not a.report_only:
                        if prior:
                            worker.kill()
                        else:
                            worker.terminate()
                        triggered = True
                    acted[key] = (now, bool(prior))
                    print(json.dumps(event), file=sys.stderr, flush=True)
                    break  # Recheck memory before reclaiming another worker.
                except (psutil.Error, OSError):
                    # Measurement/identity errors are never a reason to signal a process.
                    continue
            samples = fresh
            try:
                root_child.wait(timeout=a.sample_seconds)
            except subprocess.TimeoutExpired:
                pass
    except psutil.NoSuchProcess:
        pass
    rc = root_child.wait()
    return 86 if triggered and rc == 0 else (128 - rc if rc < 0 else rc)


if __name__ == "__main__":
    sys.exit(main())
