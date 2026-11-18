"""Read-only live telemetry collector for Windows host, NVIDIA GPU, and WSL provers.

Designed to impose near-zero memory/CPU overhead and never contend with
`windows_guard.py` atomic renames or `bounded_run.py` cgroup v2 controllers.
"""
from __future__ import annotations

import collections
import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import threading
import time
from typing import Any


DEFAULT_WSL_ARK_BASE = Path(r"\\wsl.localhost\Ubuntu-24.04\var\tmp\ark-asp-full-20261117")
DEFAULT_HOST_HEARTBEAT = Path(
    r"C:\Users\patri\Documents\Codex\2026-11-15\new-chat\work\ark-run-20261118\host.json"
)
DEFAULT_PIPELINE_LOG = Path(
    r"C:\Users\patri\Documents\Codex\2026-11-15\new-chat\work\ark-run-20261118\pipeline.log"
)

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
_PROGRESS_LOG_RE = re.compile(
    r"progress\s+(?P<elapsed>\d+)\s*s:\s*shards\s+proved\s+(?P<shards_proved>\d+)\s+"
    r"replayed\s+(?P<shards_replayed>\d+)(?:\s*\(mean\s+(?P<mean_s>[0-9.]+)\s*s\))?,\s*"
    r"recursion\s+proved\s+(?P<rec_proved>\d+)\s+replayed\s+(?P<rec_replayed>\d+),\s*"
    r"store\s+(?P<store_mib>\d+)\s*MiB"
)


def strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text)


def read_shared_text(path: Path, max_bytes: int = 65536) -> str | None:
    """Read a file on Windows with FILE_SHARE_READ|WRITE|DELETE so writers never block."""
    if not path.exists():
        return None
    if os.name != "nt":
        try:
            with path.open("rb") as fh:
                return fh.read(max_bytes).decode("utf-8", errors="replace")
        except OSError:
            return None

    GENERIC_READ = 0x80000000
    FILE_SHARE_ALL = 0x00000001 | 0x00000002 | 0x00000004
    OPEN_EXISTING = 3
    FILE_ATTRIBUTE_NORMAL = 0x80
    INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

    kernel32 = ctypes.windll.kernel32
    kernel32.CreateFileW.restype = wintypes.HANDLE
    handle = kernel32.CreateFileW(
        ctypes.c_wchar_p(str(path)),
        GENERIC_READ,
        FILE_SHARE_ALL,
        None,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        None,
    )
    if handle == INVALID_HANDLE_VALUE or handle is None:
        return None
    try:
        buf = ctypes.create_string_buffer(max_bytes)
        read_count = wintypes.DWORD(0)
        ok = kernel32.ReadFile(handle, buf, max_bytes, ctypes.byref(read_count), None)
        if not ok:
            return None
        return buf.raw[: read_count.value].decode("utf-8", errors="replace")
    finally:
        kernel32.CloseHandle(handle)


def tail_bytes(path: Path, max_bytes: int = 16384) -> str:
    try:
        with path.open("rb") as fh:
            fh.seek(0, os.SEEK_END)
            end = fh.tell()
            fh.seek(max(0, end - max_bytes))
            return fh.read().decode("utf-8", errors="replace")
    except OSError:
        return ""


def windows_memory_snapshot() -> dict[str, Any]:
    """Query GlobalMemoryStatusEx and vmmemWSL working-set vs private-commit in <1 ms."""
    if os.name != "nt":
        return {"supported": False}

    class MEMORYSTATUSEX(ctypes.Structure):
        _fields_ = [
            ("dwLength", wintypes.DWORD),
            ("dwMemoryLoad", wintypes.DWORD),
            ("ullTotalPhys", ctypes.c_ulonglong),
            ("ullAvailPhys", ctypes.c_ulonglong),
            ("ullTotalPageFile", ctypes.c_ulonglong),
            ("ullAvailPageFile", ctypes.c_ulonglong),
            ("ullTotalVirtual", ctypes.c_ulonglong),
            ("ullAvailVirtual", ctypes.c_ulonglong),
            ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
        ]

    stat = MEMORYSTATUSEX()
    stat.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
    if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat)):
        return {"supported": False}

    used_phys = max(0, stat.ullTotalPhys - stat.ullAvailPhys)
    used_commit = max(0, stat.ullTotalPageFile - stat.ullAvailPageFile)

    wsl_vm = _inspect_wsl_vm_memory()
    disks: dict[str, dict[str, int]] = {}
    for drive in ("C:\\", "D:\\"):
        if os.path.exists(drive):
            try:
                usage = shutil.disk_usage(drive)
                disks[drive] = {
                    "total_bytes": usage.total,
                    "free_bytes": usage.free,
                    "used_bytes": usage.used,
                }
            except OSError:
                pass

    return {
        "supported": True,
        "load_percent": int(stat.dwMemoryLoad),
        "total_phys_bytes": int(stat.ullTotalPhys),
        "avail_phys_bytes": int(stat.ullAvailPhys),
        "used_phys_bytes": int(used_phys),
        "total_commit_bytes": int(stat.ullTotalPageFile),
        "avail_commit_bytes": int(stat.ullAvailPageFile),
        "used_commit_bytes": int(used_commit),
        "vmmem_wsl": wsl_vm,
        "disks": disks,
    }


def _inspect_wsl_vm_memory() -> dict[str, Any] | None:
    """Inspect vmmemWSL / vmmem working set vs private commit via NtQuerySystemInformation.

    Protected system VM processes (`vmmemWSL`) deny `OpenProcess`, whereas
    `SystemProcessInformation` (class 5) exposes `WorkingSetSize` and `PagefileUsage`
    to unprivileged callers in <1 ms (matching Task Manager).
    """
    if os.name != "nt":
        return None

    class UNICODE_STRING(ctypes.Structure):
        _fields_ = [
            ("Length", wintypes.USHORT),
            ("MaximumLength", wintypes.USHORT),
            ("Buffer", ctypes.c_void_p),
        ]

    try:
        ntdll = ctypes.windll.ntdll
        size = wintypes.ULONG(512 * 1024)
        for _ in range(6):
            buf = ctypes.create_string_buffer(size.value)
            ret = wintypes.ULONG(0)
            status = ntdll.NtQuerySystemInformation(5, buf, size, ctypes.byref(ret))
            if status == 0:
                break
            if (status & 0xFFFFFFFF) == 0xC0000004:  # STATUS_INFO_LENGTH_MISMATCH
                size = wintypes.ULONG(max(size.value * 2, ret.value + 65536))
                continue
            return None
        else:
            return None

        raw = ctypes.addressof(buf)
        offset = 0
        is_64 = ctypes.sizeof(ctypes.c_void_p) == 8
        # x64 SYSTEM_PROCESS_INFORMATION exact offsets:
        # 0x00 NextEntryOffset (ULONG), 0x04 NumberOfThreads (ULONG)
        # 0x08 WorkingSetPrivateSize (LARGE_INTEGER)
        # 0x38 ImageName (UNICODE_STRING: 16 bytes on x64)
        # 0x50 UniqueProcessId (HANDLE)
        # 0x88 PeakWorkingSetSize (SIZE_T)
        # 0x90 WorkingSetSize (SIZE_T)
        # 0xB8 PagefileUsage / PrivateCommit (SIZE_T)
        # 0xC0 PeakPagefileUsage (SIZE_T)
        if not is_64:
            return None

        while True:
            next_off = ctypes.c_uint32.from_address(raw + offset).value
            ustr = UNICODE_STRING.from_address(raw + offset + 0x38)
            if ustr.Length > 0 and ustr.Buffer:
                name = ctypes.wstring_at(ustr.Buffer, ustr.Length // 2)
                low = name.lower()
                if low in ("vmmemwsl", "vmmemwsl.exe", "vmmem", "vmmem.exe"):
                    pid = ctypes.c_size_t.from_address(raw + offset + 0x50).value
                    peak_ws = ctypes.c_size_t.from_address(raw + offset + 0x88).value
                    ws = ctypes.c_size_t.from_address(raw + offset + 0x90).value
                    priv = ctypes.c_size_t.from_address(raw + offset + 0xB8).value
                    peak_pf = ctypes.c_size_t.from_address(raw + offset + 0xC0).value
                    return {
                        "name": name,
                        "pid": int(pid),
                        "working_set_bytes": int(ws),
                        "peak_working_set_bytes": int(peak_ws),
                        "private_commit_bytes": int(priv),
                        "pagefile_bytes": int(peak_pf),
                        "nonresident_commit_bytes": max(0, int(priv) - int(ws)),
                    }
            if next_off == 0:
                break
            offset += next_off
    except Exception:
        return None
    return None


class ProgressTailCache:
    """Incremental reader for SP1 `progress.jsonl` so polling 10k+ tasks takes <1 ms."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._path: Path | None = None
        self._offset = 0
        self._inode_sig: tuple[int, int] | None = None
        self._unique_by_key: dict[str, dict[str, Any]] = {}
        self._total_rows_by_kind: collections.Counter[str] = collections.Counter()
        self._proved_rows_by_kind: collections.Counter[str] = collections.Counter()
        self._replayed_rows_by_kind: collections.Counter[str] = collections.Counter()
        self._recent_events: collections.deque[dict[str, Any]] = collections.deque(maxlen=60)
        self._proved_timestamps: dict[str, collections.deque[int]] = {
            "shard": collections.deque(maxlen=400),
            "reduce": collections.deque(maxlen=400),
        }
        self._proved_durations_ms: dict[str, collections.deque[int]] = {
            "shard": collections.deque(maxlen=200),
            "reduce": collections.deque(maxlen=200),
        }

    def _reset(self, path: Path | None) -> None:
        self._path = path
        self._offset = 0
        self._inode_sig = None
        self._unique_by_key.clear()
        self._total_rows_by_kind.clear()
        self._proved_rows_by_kind.clear()
        self._replayed_rows_by_kind.clear()
        self._recent_events.clear()
        for dq in self._proved_timestamps.values():
            dq.clear()
        for dq in self._proved_durations_ms.values():
            dq.clear()

    def read(self, path: Path) -> dict[str, Any]:
        with self._lock:
            if not path.exists():
                return {
                    "exists": False,
                    "unique_shards": 0,
                    "unique_reduces": 0,
                    "total_rows": 0,
                }
            try:
                st = path.stat()
            except OSError:
                return {"exists": False, "unique_shards": 0, "unique_reduces": 0, "total_rows": 0}

            sig = (st.st_dev, st.st_ino)
            if self._path != path or self._inode_sig != sig or st.st_size < self._offset:
                self._reset(path)
                self._inode_sig = sig

            if st.st_size > self._offset:
                try:
                    with path.open("rb") as fh:
                        fh.seek(self._offset)
                        chunk = fh.read()
                        last_nl = chunk.rfind(b"\n")
                        if last_nl >= 0:
                            complete = chunk[: last_nl + 1]
                            self._offset += len(complete)
                            for raw_line in complete.decode("utf-8", errors="replace").splitlines():
                                raw_line = raw_line.strip()
                                if not raw_line:
                                    continue
                                try:
                                    obj = json.loads(raw_line)
                                except ValueError:
                                    continue
                                kind = str(obj.get("kind", "unknown"))
                                key = str(obj.get("key", ""))
                                replayed = bool(obj.get("replayed", False))
                                ms = int(obj.get("ms", 0) or 0)
                                ts = int(obj.get("t", 0) or 0)
                                self._total_rows_by_kind[kind] += 1
                                if replayed:
                                    self._replayed_rows_by_kind[kind] += 1
                                else:
                                    self._proved_rows_by_kind[kind] += 1
                                    if kind in self._proved_timestamps and ts > 0:
                                        self._proved_timestamps[kind].append(ts)
                                    if kind in self._proved_durations_ms and ms > 0:
                                        self._proved_durations_ms[kind].append(ms)
                                if key:
                                    prev = self._unique_by_key.get(key)
                                    if prev is None or (prev.get("replayed") and not replayed):
                                        self._unique_by_key[key] = {
                                            "kind": kind,
                                            "replayed": replayed,
                                            "ms": ms,
                                            "t": ts,
                                        }
                                self._recent_events.append(
                                    {
                                        "key": key,
                                        "kind": kind,
                                        "ms": ms,
                                        "replayed": replayed,
                                        "t": ts,
                                    }
                                )
                except OSError:
                    pass

            unique_counts: collections.Counter[str] = collections.Counter()
            for info in self._unique_by_key.values():
                unique_counts[info["kind"]] += 1

            now = time.time()
            rates = {}
            mean_ms = {}
            for kind in ("shard", "reduce"):
                stamps = self._proved_timestamps[kind]
                recent_5m = [t for t in stamps if now - t <= 300]
                recent_15m = [t for t in stamps if now - t <= 900]
                if len(recent_5m) >= 2:
                    span = max(30.0, now - recent_5m[0])
                    rates[f"{kind}_per_min_5m"] = round(len(recent_5m) * 60.0 / span, 2)
                elif len(recent_5m) == 1:
                    rates[f"{kind}_per_min_5m"] = round(60.0 / 300.0, 2)
                else:
                    rates[f"{kind}_per_min_5m"] = 0.0

                if len(recent_15m) >= 2:
                    span15 = max(60.0, now - recent_15m[0])
                    rates[f"{kind}_per_min_15m"] = round(len(recent_15m) * 60.0 / span15, 2)
                else:
                    rates[f"{kind}_per_min_15m"] = rates[f"{kind}_per_min_5m"]

                durs = list(self._proved_durations_ms[kind])
                mean_ms[kind] = int(sum(durs) / len(durs)) if durs else 0

            return {
                "exists": True,
                "path": str(path),
                "size_bytes": st.st_size,
                "mtime_unix": st.st_mtime,
                "unique_shards": int(unique_counts.get("shard", 0)),
                "unique_reduces": int(unique_counts.get("reduce", 0)),
                "total_rows": int(sum(self._total_rows_by_kind.values())),
                "total_rows_by_kind": dict(self._total_rows_by_kind),
                "proved_rows_by_kind": dict(self._proved_rows_by_kind),
                "replayed_rows_by_kind": dict(self._replayed_rows_by_kind),
                "rates": rates,
                "mean_proved_ms": mean_ms,
                "recent_events": list(self._recent_events)[-30:],
            }


class TelemetryCollector:
    """Thread-safe read-only collector for GPU, Host RAM, and WSL Prover state."""

    def __init__(
        self,
        wsl_ark_base: Path | None = None,
        host_heartbeat_path: Path | None = None,
        pipeline_log_path: Path | None = None,
    ) -> None:
        self.wsl_ark_base = wsl_ark_base or DEFAULT_WSL_ARK_BASE
        self.host_heartbeat_path = host_heartbeat_path or DEFAULT_HOST_HEARTBEAT
        self.pipeline_log_path = pipeline_log_path or DEFAULT_PIPELINE_LOG
        self._progress_cache = ProgressTailCache()
        self._gpu_lock = threading.Lock()
        self._gpu_cache: tuple[float, dict[str, Any]] = (0.0, {"available": False})
        self._gpu_history: collections.deque[dict[str, Any]] = collections.deque(maxlen=180)

    def query_gpu(self) -> dict[str, Any]:
        now = time.monotonic()
        with self._gpu_lock:
            if now - self._gpu_cache[0] < 1.5:
                return self._gpu_cache[1]

        creationflags = 0x08000000 if os.name == "nt" else 0  # CREATE_NO_WINDOW
        gpu_info: dict[str, Any] = {"available": False}
        try:
            proc = subprocess.run(
                [
                    "nvidia-smi",
                    "--query-gpu=name,utilization.gpu,utilization.memory,memory.used,memory.free,memory.total,temperature.gpu,power.draw,power.limit,clocks.current.sm,clocks.current.memory,pstate",
                    "--format=csv,noheader,nounits",
                ],
                capture_output=True,
                text=True,
                timeout=2.5,
                creationflags=creationflags,
                check=False,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                parts = [p.strip() for p in proc.stdout.strip().splitlines()[0].split(",")]
                if len(parts) >= 12:
                    def _num(val: str, kind: type = float) -> Any:
                        try:
                            return kind(val)
                        except ValueError:
                            return None

                    gpu_info = {
                        "available": True,
                        "name": parts[0],
                        "util_gpu_pct": _num(parts[1], float) or 0.0,
                        "util_mem_pct": _num(parts[2], float) or 0.0,
                        "vram_used_mib": _num(parts[3], float) or 0.0,
                        "vram_free_mib": _num(parts[4], float) or 0.0,
                        "vram_total_mib": _num(parts[5], float) or 16303.0,
                        "temp_c": _num(parts[6], int) or 0,
                        "power_draw_w": _num(parts[7], float) or 0.0,
                        "power_limit_w": _num(parts[8], float),
                        "clock_sm_mhz": _num(parts[9], int) or 0,
                        "clock_mem_mhz": _num(parts[10], int) or 0,
                        "pstate": parts[11],
                        "processes": [],
                    }
                    apps = subprocess.run(
                        [
                            "nvidia-smi",
                            "--query-compute-apps=pid,process_name,used_gpu_memory",
                            "--format=csv,noheader,nounits",
                        ],
                        capture_output=True,
                        text=True,
                        timeout=2.0,
                        creationflags=creationflags,
                        check=False,
                    )
                    if apps.returncode == 0 and apps.stdout.strip():
                        for line in apps.stdout.strip().splitlines():
                            ap = [x.strip() for x in line.split(",")]
                            if len(ap) >= 3:
                                gpu_info["processes"].append(
                                    {
                                        "pid": _num(ap[0], int),
                                        "name": ap[1],
                                        "used_mib": _num(ap[2], float),
                                    }
                                )
        except (OSError, subprocess.SubprocessError):
            gpu_info = {"available": False}

        sample_unix = time.time()
        with self._gpu_lock:
            self._gpu_cache = (now, gpu_info)
            if gpu_info.get("available"):
                self._gpu_history.append(
                    {
                        "t": round(sample_unix, 1),
                        "util_gpu_pct": gpu_info["util_gpu_pct"],
                        "util_mem_pct": gpu_info["util_mem_pct"],
                        "vram_used_mib": gpu_info["vram_used_mib"],
                        "power_draw_w": gpu_info["power_draw_w"],
                        "temp_c": gpu_info["temp_c"],
                    }
                )
            gpu_info["history"] = list(self._gpu_history)[-120:]
        return gpu_info

    def _wsl_path_to_windows(self, wsl_path: str) -> Path:
        clean = wsl_path.strip()
        if clean.startswith("/mnt/") and len(clean) > 6 and clean[6] == "/":
            drive = clean[5].upper()
            rest = clean[7:].replace("/", "\\")
            return Path(f"{drive}:\\{rest}")
        rel = clean.lstrip("/").replace("/", "\\")
        return Path(r"\\wsl.localhost\Ubuntu-24.04") / rel

    def query_wsl_prover(self) -> dict[str, Any]:
        base = self.wsl_ark_base
        if not base.exists():
            return {"reachable": False, "base_dir": str(base)}

        status_path = base / "pipeline-status.json"
        pipeline_state: dict[str, Any] = {}
        if status_path.exists():
            try:
                pipeline_state = json.loads(status_path.read_text(encoding="utf-8", errors="replace"))
            except (OSError, ValueError):
                pipeline_state = {}

        progress_path = base / "prover-transient" / "progress.jsonl"
        if not progress_path.exists() and (base / "prover" / "progress.jsonl").exists():
            progress_path = base / "prover" / "progress.jsonl"
        progress = self._progress_cache.read(progress_path)

        phases = pipeline_state.get("phases") or {}
        active_phase_name = str(pipeline_state.get("status", "unknown"))
        phase_wsl_str = phases.get(active_phase_name) or (
            next(reversed(phases.values())) if phases else None
        )
        phase_dir = self._wsl_path_to_windows(phase_wsl_str) if phase_wsl_str else None

        resources_series: list[dict[str, Any]] = []
        latest_resource: dict[str, Any] | None = None
        cgroup_peaks = {"memory_peak_bytes": 0, "swap_peak_bytes": 0}
        phase_log_tail = ""
        latest_progress_line: dict[str, Any] | None = None

        if phase_dir and phase_dir.exists():
            res_file = phase_dir / "resources.jsonl"
            if res_file.exists():
                raw_res = tail_bytes(res_file, max_bytes=49152)
                for line in raw_res.splitlines():
                    line = line.strip()
                    if not line.startswith("{"):
                        continue
                    try:
                        item = json.loads(line)
                    except ValueError:
                        continue
                    mem_b = int(item.get("memory_bytes", 0) or 0)
                    swp_b = int(item.get("swap_bytes", 0) or 0)
                    cgroup_peaks["memory_peak_bytes"] = max(cgroup_peaks["memory_peak_bytes"], mem_b)
                    cgroup_peaks["swap_peak_bytes"] = max(cgroup_peaks["swap_peak_bytes"], swp_b)
                    resources_series.append(
                        {
                            "elapsed_s": round(float(item.get("elapsed_seconds", 0.0)), 1),
                            "cgroup_ram_mib": round(mem_b / (1024 * 1024), 1),
                            "cgroup_swap_mib": round(swp_b / (1024 * 1024), 1),
                            "wsl_avail_gib": round(
                                float(item.get("available_bytes", 0)) / (1024**3), 2
                            ),
                            "host_avail_gib": round(
                                float(item.get("host_available_bytes", 0)) / (1024**3), 2
                            ),
                            "d_free_gib": round(
                                float((item.get("disk_free") or {}).get("/mnt/d", 0)) / (1024**3),
                                2,
                            ),
                        }
                    )
                if resources_series:
                    latest_resource = resources_series[-1]

            log_file = phase_dir / "phase.log"
            if log_file.exists():
                cleaned = strip_ansi(tail_bytes(log_file, max_bytes=8192))
                lines = [ln for ln in cleaned.splitlines() if ln.strip()]
                phase_log_tail = "\n".join(lines[-28:])
                for ln in reversed(lines):
                    m = _PROGRESS_LOG_RE.search(ln)
                    if m:
                        latest_progress_line = {
                            "elapsed_s": int(m.group("elapsed")),
                            "session_shards_proved": int(m.group("shards_proved")),
                            "session_shards_replayed": int(m.group("shards_replayed")),
                            "mean_shard_s": float(m.group("mean_s")) if m.group("mean_s") else None,
                            "session_recursion_proved": int(m.group("rec_proved")),
                            "session_recursion_replayed": int(m.group("rec_replayed")),
                            "artifact_store_mib": int(m.group("store_mib")),
                        }
                        break

        guard_events: list[dict[str, Any]] = []
        if self.pipeline_log_path.exists():
            raw_pipe = read_shared_text(self.pipeline_log_path, max_bytes=32768) or ""
            for ln in raw_pipe.splitlines():
                ln_s = ln.strip()
                if ln_s.startswith("{") and "stop_reason" in ln_s:
                    try:
                        ev = json.loads(ln_s)
                        guard_events.append(
                            {
                                "exit_code": ev.get("exit_code"),
                                "stop_reason": ev.get("stop_reason"),
                                "elapsed_s": round(float(ev.get("elapsed_seconds", 0.0)), 1),
                                "memory_peak_mib": round(
                                    float(ev.get("memory_peak_bytes", 0)) / (1024 * 1024), 1
                                ),
                                "swap_peak_mib": round(
                                    float(ev.get("swap_peak_bytes", 0)) / (1024 * 1024), 1
                                ),
                                "cleaned_shm_count": len(ev.get("removed_owned_shared_files") or []),
                                "completed_at_unix": ev.get("completed_at_unix"),
                            }
                        )
                    except ValueError:
                        pass

        compressed_exists = (base / "compressed.bin").exists()
        wrap_exists = (base / "m13" / "wrap-v2.bin").exists()

        return {
            "reachable": True,
            "base_dir": str(base),
            "status": active_phase_name,
            "prover_backend": pipeline_state.get("prover_backend"),
            "prover_binary_sha256": pipeline_state.get("prover_binary_sha256"),
            "started_at_unix": pipeline_state.get("started_at_unix"),
            "startup_host_reserve_mib": pipeline_state.get("startup_host_reserve_mib", 6144),
            "active_phase_dir": phase_dir.name if phase_dir else None,
            "compressed_exists": compressed_exists,
            "wrap_v2_exists": wrap_exists,
            "limits": {
                "cpu_cores": 2,
                "linux_ram_soft_mib": 1024,
                "linux_ram_hard_mib": 2048,
                "swap_max_mib": 4096,
                "host_free_floor_mib": 3072,
                "host_start_reserve_mib": int(pipeline_state.get("startup_host_reserve_mib", 6144)),
                "cuda_pool_release_mib": 256,
                "element_threshold": 67108864,
            },
            "progress": progress,
            "session_summary": latest_progress_line,
            "latest_resource": latest_resource,
            "cgroup_peaks_mib": {
                "ram_peak_mib": round(cgroup_peaks["memory_peak_bytes"] / (1024 * 1024), 1),
                "swap_peak_mib": round(cgroup_peaks["swap_peak_bytes"] / (1024 * 1024), 1),
            },
            "resources_series": resources_series[-150:],
            "phase_log_tail": phase_log_tail,
            "guard_events": guard_events[-12:],
        }

    def query_host_heartbeat(self) -> dict[str, Any]:
        raw = read_shared_text(self.host_heartbeat_path, max_bytes=4096)
        if not raw:
            return {"present": False}
        try:
            obj = json.loads(raw)
        except ValueError:
            return {"present": False}
        age_s = round(max(0.0, time.time() - float(obj.get("sample_unix", 0.0))), 2)
        return {
            "present": True,
            "age_seconds": age_s,
            "fresh": age_s < 30.0,
            "memory_floor_bytes": obj.get("memory_floor_bytes", 3221225472),
            "immediate_memory_floor_bytes": obj.get("immediate_memory_floor_bytes", 536870912),
            "stop_reason": obj.get("stop_reason"),
            "sample_unix": obj.get("sample_unix"),
        }

    def snapshot(self) -> dict[str, Any]:
        return {
            "schema": "rbzk-prover-telemetry-v1",
            "sampled_at_unix": round(time.time(), 3),
            "host_memory": windows_memory_snapshot(),
            "host_guard": self.query_host_heartbeat(),
            "gpu": self.query_gpu(),
            "wsl_prover": self.query_wsl_prover(),
        }
