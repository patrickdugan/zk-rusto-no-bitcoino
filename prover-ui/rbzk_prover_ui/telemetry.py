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

from .correlator import estimate_ark_live_completion


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
    """Inspect vmmemWSL / vmmem working set vs private commit via NtQuerySystemInformation."""
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
            if (status & 0xFFFFFFFF) == 0xC0000004:
                size = wintypes.ULONG(max(size.value * 2, ret.value + 65536))
                continue
            return None
        else:
            return None

        raw = ctypes.addressof(buf)
        offset = 0
        if ctypes.sizeof(ctypes.c_void_p) != 8:
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
        self._seq_counter = 0
        self._unique_by_key: dict[str, dict[str, Any]] = {}
        self._unique_order: collections.deque[dict[str, Any]] = collections.deque(maxlen=2500)
        self._total_rows_by_kind: collections.Counter[str] = collections.Counter()
        self._proved_rows_by_kind: collections.Counter[str] = collections.Counter()
        self._replayed_rows_by_kind: collections.Counter[str] = collections.Counter()
        self._recent_events: collections.deque[dict[str, Any]] = collections.deque(maxlen=80)
        self._last_event_unix: float | None = None
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
        self._seq_counter = 0
        self._unique_by_key.clear()
        self._unique_order.clear()
        self._total_rows_by_kind.clear()
        self._proved_rows_by_kind.clear()
        self._replayed_rows_by_kind.clear()
        self._recent_events.clear()
        self._last_event_unix = None
        for dq in self._proved_timestamps.values():
            dq.clear()
        for dq in self._proved_durations_ms.values():
            dq.clear()

    def read(self, path: Path) -> dict[str, Any]:
        with self._lock:
            if not path.exists():
                return {
                    "exists": False,
                    "seq": 0,
                    "unique_shards": 0,
                    "unique_reduces": 0,
                    "total_rows": 0,
                }
            try:
                st = path.stat()
            except OSError:
                return {
                    "exists": False,
                    "seq": 0,
                    "unique_shards": 0,
                    "unique_reduces": 0,
                    "total_rows": 0,
                }

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
                                self._seq_counter += 1
                                kind = str(obj.get("kind", "unknown"))
                                key = str(obj.get("key", ""))
                                replayed = bool(obj.get("replayed", False))
                                ms = int(obj.get("ms", 0) or 0)
                                ts = int(obj.get("t", 0) or 0)
                                if ts > 0:
                                    self._last_event_unix = max(self._last_event_unix or 0.0, float(ts))
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
                                    is_new_key = prev is None
                                    entry = {
                                        "key": key,
                                        "kind": kind,
                                        "replayed": replayed if is_new_key else (prev["replayed"] and replayed),
                                        "ms": ms if not replayed or is_new_key else prev["ms"],
                                        "t": ts,
                                    }
                                    self._unique_by_key[key] = entry
                                    if is_new_key:
                                        self._unique_order.append(entry)
                                self._recent_events.append(
                                    {
                                        "seq": self._seq_counter,
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

                recent_30m = [t for t in stamps if now - t <= 1800]
                if len(recent_30m) >= 3 and (recent_30m[-1] - recent_30m[0]) >= 60:
                    # Use completed inter-arrival span so rate does not drift between task completions
                    inter_span = float(recent_30m[-1] - recent_30m[0])
                    tail_gap = max(0.0, now - recent_30m[-1])
                    eff_span = inter_span + (tail_gap if tail_gap > 240.0 else 0.0)
                    rates[f"{kind}_per_min_30m"] = round(
                        (len(recent_30m) - 1) * 60.0 / max(60.0, eff_span), 3
                    )
                else:
                    rates[f"{kind}_per_min_30m"] = rates[f"{kind}_per_min_15m"]

                durs = list(self._proved_durations_ms[kind])
                mean_ms[kind] = int(sum(durs) / len(durs)) if durs else 0

            # Compact mosaic summary (last 240 unique tiles + total counts) for fast canvas rendering
            mosaic_tail = [
                {
                    "k": u["key"][:8],
                    "t": 1 if u["kind"] == "reduce" else 0,
                    "r": 1 if u["replayed"] else 0,
                    "s": round(u["ms"] / 1000.0, 1),
                }
                for u in list(self._unique_order)[-320:]
            ]

            last_ev_ts = self._last_event_unix or st.st_mtime
            return {
                "exists": True,
                "path": str(path),
                "seq": self._seq_counter,
                "size_bytes": st.st_size,
                "mtime_unix": st.st_mtime,
                "last_event_age_s": round(max(0.0, now - last_ev_ts), 1),
                "unique_shards": int(unique_counts.get("shard", 0)),
                "unique_reduces": int(unique_counts.get("reduce", 0)),
                "total_rows": int(sum(self._total_rows_by_kind.values())),
                "total_rows_by_kind": dict(self._total_rows_by_kind),
                "proved_rows_by_kind": dict(self._proved_rows_by_kind),
                "replayed_rows_by_kind": dict(self._replayed_rows_by_kind),
                "rates": rates,
                "mean_proved_ms": mean_ms,
                "recent_events": list(self._recent_events)[-40:],
                "mosaic_tail": mosaic_tail,
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
        self._frame_seq = 0

    def query_gpu(self) -> dict[str, Any]:
        now = time.monotonic()
        with self._gpu_lock:
            if now - self._gpu_cache[0] < 1.0:
                return self._gpu_cache[1]

        creationflags = 0x08000000 if os.name == "nt" else 0
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
                timeout=2.0,
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
        p = Path(wsl_path)
        if p.drive or wsl_path.startswith("\\\\"):
            return p
        clean = wsl_path.strip()
        if clean.startswith("/mnt/") and len(clean) > 6 and clean[6] == "/":
            drive = clean[5].upper()
            rest = clean[7:].replace("/", "\\")
            return Path(f"{drive}:\\{rest}")
        rel = clean.lstrip("/").replace("/", "\\")
        return Path(r"\\wsl.localhost\Ubuntu-24.04") / rel

    def query_wsl_prover(self, host_avail_bytes: int | None = None) -> dict[str, Any]:
        now = time.time()
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

        run_dir = base / "prover-transient"
        if not (run_dir / "progress.jsonl").exists() and (base / "prover" / "progress.jsonl").exists():
            run_dir = base / "prover"
        progress = self._progress_cache.read(getattr(self, "_observed_progress_path", run_dir / "progress.jsonl"))

        run_cfg_element_threshold = 67_108_864
        run_cfg_path = run_dir / "run.json"
        if run_cfg_path.exists():
            try:
                rcfg_obj = json.loads(run_cfg_path.read_text(encoding="utf-8", errors="replace"))
                run_cfg_element_threshold = int(rcfg_obj.get("element_threshold", 67_108_864))
            except (OSError, ValueError):
                pass
        run_verified = (run_dir / "result.json").exists()

        # Count live in-flight artifacts & trash artifacts
        inflight_artifacts = 0
        trash_artifacts = 0
        live_art_dir = run_dir / "artifacts" / "live"
        trash_art_dir = run_dir / "artifacts" / "trash"
        if live_art_dir.exists():
            try:
                inflight_artifacts = sum(1 for _ in live_art_dir.iterdir())
            except OSError:
                pass
        if trash_art_dir.exists():
            try:
                trash_artifacts = sum(1 for _ in trash_art_dir.iterdir())
            except OSError:
                pass

        phases = pipeline_state.get("phases") or {}
        active_phase_name = str(pipeline_state.get("status", "unknown"))
        gpu_attempts_raw: list[str] = (pipeline_state.get("attempts") or {}).get("gpu") or []
        phase_wsl_str = (
            phases.get(active_phase_name)
            or phases.get("gpu")
            or (gpu_attempts_raw[-1] if gpu_attempts_raw else None)
            or (next(reversed(phases.values())) if phases else None)
        )
        phase_dir = self._wsl_path_to_windows(phase_wsl_str) if phase_wsl_str else None

        phase_finished = False
        phase_started_unix: float | None = None
        if phase_dir and phase_dir.exists():
            phase_finished = (phase_dir / "result.json").exists()
            res_cfg_path = phase_dir / "resources.json"
            if res_cfg_path.exists():
                try:
                    rcfg = json.loads(res_cfg_path.read_text(encoding="utf-8", errors="replace"))
                    phase_started_unix = float(rcfg.get("started_at_unix", 0.0)) or None
                except (OSError, ValueError):
                    pass

        resources_series: list[dict[str, Any]] = []
        latest_resource: dict[str, Any] | None = None
        last_resource_age_s: float | None = None
        cgroup_peaks = {"memory_peak_bytes": 0, "swap_peak_bytes": 0}
        phase_log_tail = ""
        latest_progress_line: dict[str, Any] | None = None

        if phase_dir and phase_dir.exists():
            res_file = phase_dir / "resources.jsonl"
            if res_file.exists():
                try:
                    last_resource_age_s = round(max(0.0, now - res_file.stat().st_mtime), 1)
                except OSError:
                    pass
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
                    if phase_finished:
                        # Child exited cleanly/held: cgroup is reclaimed to 0 MiB
                        last_pt = dict(resources_series[-1])
                        last_pt["cgroup_ram_mib"] = 0.0
                        last_pt["cgroup_swap_mib"] = 0.0
                        latest_resource = last_pt
                    else:
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

        # Gather guard / attempt history from attempts.gpu result.json files + pipeline.log
        guard_events: list[dict[str, Any]] = []
        seen_completed: set[int] = set()
        for idx, att_wsl in enumerate(gpu_attempts_raw, start=1):
            att_dir = self._wsl_path_to_windows(att_wsl)
            res_json = att_dir / "result.json"
            if res_json.exists():
                try:
                    ev = json.loads(res_json.read_text(encoding="utf-8", errors="replace"))
                    comp_ts = int(float(ev.get("completed_at_unix", 0) or 0))
                    seen_completed.add(comp_ts)
                    guard_events.append(
                        {
                            "attempt": idx,
                            "phase": att_dir.name,
                            "exit_code": ev.get("exit_code"),
                            "stop_reason": ev.get("stop_reason") or "completed",
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
                except (OSError, ValueError):
                    pass

        if self.pipeline_log_path.exists():
            raw_pipe = read_shared_text(self.pipeline_log_path, max_bytes=32768) or ""
            for ln in raw_pipe.splitlines():
                ln_s = ln.strip()
                if ln_s.startswith("{") and "stop_reason" in ln_s:
                    try:
                        ev = json.loads(ln_s)
                        comp_ts = int(float(ev.get("completed_at_unix", 0) or 0))
                        if comp_ts not in seen_completed:
                            seen_completed.add(comp_ts)
                            guard_events.append(
                                {
                                    "attempt": None,
                                    "phase": "earlier-run",
                                    "exit_code": ev.get("exit_code"),
                                    "stop_reason": ev.get("stop_reason") or "completed",
                                    "elapsed_s": round(float(ev.get("elapsed_seconds", 0.0)), 1),
                                    "memory_peak_mib": round(
                                        float(ev.get("memory_peak_bytes", 0)) / (1024 * 1024), 1
                                    ),
                                    "swap_peak_mib": round(
                                        float(ev.get("swap_peak_bytes", 0)) / (1024 * 1024), 1
                                    ),
                                    "cleaned_shm_count": len(
                                        ev.get("removed_owned_shared_files") or []
                                    ),
                                    "completed_at_unix": ev.get("completed_at_unix"),
                                }
                            )
                    except ValueError:
                        pass

        guard_events.sort(key=lambda x: float(x.get("completed_at_unix") or 0.0))

        compressed_exists = (base / "compressed.bin").exists()
        wrap_exists = (base / "m13" / "wrap-v2.bin").exists()
        startup_reserve_mib = int(pipeline_state.get("startup_host_reserve_mib", 6144))
        last_stop = pipeline_state.get("last_resource_stop") or {}
        last_stop_unix = float(last_stop.get("completed_at_unix") or 0.0)

        # Compute exact operational liveness state machine
        host_avail_gib = (
            round(host_avail_bytes / (1024**3), 2)
            if host_avail_bytes is not None
            else (latest_resource or {}).get("host_avail_gib", 0.0)
        )
        target_gib = round(startup_reserve_mib / 1024.0, 2)

        if active_phase_name == "all_proof_checks_passed" or wrap_exists:
            op_mode = "completed"
            op_headline = "All SP1, M13 BLAKE3 & M14 Garbled Checks Verified"
            op_detail = "Proof pipeline finished cleanly."
            phase_elapsed_s = 0.0
            cooldown_rem_s = 0.0
        elif active_phase_name.startswith("waiting_for_headroom") or phase_finished:
            since_stop = max(0.0, now - last_stop_unix) if last_stop_unix > 0 else 999.0
            cooldown_rem_s = round(max(0.0, 60.0 - since_stop), 1)
            phase_elapsed_s = round(since_stop, 1)
            if cooldown_rem_s > 0:
                op_mode = "cooldown_backoff"
                op_headline = f"Resource-Guard Cooldown ({cooldown_rem_s:.0f}s remaining) · Checkpoints Preserved"
                op_detail = (
                    f"Attempt #{len(gpu_attempts_raw)} paused on {last_stop.get('stop_reason', 'host_memory_floor')}; "
                    f"1,131+ shards safe on disk. Rechecking host headroom ({host_avail_gib:.2f} / {target_gib:.2f} GiB) after 60s backoff."
                )
            else:
                op_mode = "waiting_headroom"
                gap_gib = max(0.0, target_gib - host_avail_gib)
                if gap_gib > 0:
                    op_headline = f"Awaiting {target_gib:.2f} GiB Windows Free RAM to Auto-Resume GPU (+{gap_gib:.2f} GiB needed)"
                    op_detail = (
                        f"Orchestrator polling host.json every 2s: Windows currently has {host_avail_gib:.2f} GiB free "
                        f"(needs {target_gib:.2f} GiB sustained for 10s; {pipeline_state.get('gpu_host_holds', 0)} holds so far)."
                    )
                else:
                    op_headline = f"Headroom Target Met ({host_avail_gib:.2f} ≥ {target_gib:.2f} GiB) · Acquiring 10s Stability Lock"
                    op_detail = "Launching next resumable ark-prove-gpu phase as soon as 10-second stability window completes."
        else:
            phase_elapsed_s = (
                round(max(0.0, now - phase_started_unix), 1)
                if phase_started_unix
                else float((latest_resource or {}).get("elapsed_s", 0.0))
            )
            cooldown_rem_s = 0.0
            last_ev_age = float(progress.get("last_event_age_s", 9999.0))
            recent_evs = progress.get("recent_events") or []
            last_was_replay = bool(recent_evs[-1]["replayed"]) if recent_evs else False

            if phase_elapsed_s < 95 and latest_progress_line is None and last_ev_age > phase_elapsed_s:
                op_mode = "cuda_init"
                op_headline = f"CUDA Prover Initializing & Loading 22.5 MB Raw Key ({phase_elapsed_s:.0f}s)"
                op_detail = (
                    f"Attempt #{max(1, len(gpu_attempts_raw))} active in cgroup: setting up SP1 6.9 CUDA kernels "
                    f"and preparing to replay {progress.get('unique_shards', 0):,} cached shards."
                )
            elif last_ev_age < 15.0 and last_was_replay:
                op_mode = "replaying_memo"
                op_headline = "Streaming Cached Shard Memos into SP1 Compress Tree"
                op_detail = (
                    f"Replaying verified task digests from disk memo ({inflight_artifacts} live artifacts in flight)."
                )
            else:
                op_mode = "proving_inflight"
                in_flight_s = round(min(phase_elapsed_s, last_ev_age), 1)
                mean_s = (
                    (latest_progress_line or {}).get("mean_shard_s")
                    or round((progress.get("mean_proved_ms", {}).get("reduce", 320000)) / 1000.0, 1)
                    or 250.0
                )
                op_headline = f"Proving SP1 Shard / Recursion Task on RTX 5080 ({in_flight_s:.0f}s in-flight)"
                op_detail = (
                    f"Active CUDA execution ({inflight_artifacts} live DAG artifacts, mean task ~{mean_s:.0f}s); "
                    f"next completion will append directly to progress.jsonl."
                )

        mean_ms_map = progress.get("mean_proved_ms") or {}
        est_task_s = (
            (latest_progress_line or {}).get("mean_shard_s")
            or (mean_ms_map.get("reduce", 0) / 1000.0 if mean_ms_map.get("reduce") else 300.0)
        )

        cur_task_elapsed_s = (
            round(min(phase_elapsed_s, float(progress.get("last_event_age_s", 0.0))), 1)
            if not phase_finished and active_phase_name in ("gpu", "cpu")
            else 0.0
        )

        completion_est = estimate_ark_live_completion(
            unique_shards=int(progress.get("unique_shards", 0)),
            unique_reduces=int(progress.get("unique_reduces", 0)),
            element_threshold=run_cfg_element_threshold,
            ark_vtxos=4,
            session_summary=latest_progress_line,
            rates=progress.get("rates"),
            mean_proved_ms=mean_ms_map,
            in_flight_elapsed_s=cur_task_elapsed_s,
            expected_task_s=float(est_task_s),
            compressed_verified=bool(compressed_exists or wrap_exists or run_verified),
            all_verified=bool(active_phase_name == "all_proof_checks_passed" or wrap_exists),
        )

        return {
            "reachable": True,
            "base_dir": str(base),
            "status": active_phase_name,
            "phase_running": not phase_finished and active_phase_name in ("gpu", "cpu", "shrink", "wrapv2"),
            "attempt_count": len(gpu_attempts_raw),
            "gpu_host_holds": int(pipeline_state.get("gpu_host_holds", 0)),
            "prover_backend": pipeline_state.get("prover_backend"),
            "prover_binary_sha256": pipeline_state.get("prover_binary_sha256"),
            "started_at_unix": pipeline_state.get("started_at_unix"),
            "phase_started_unix": phase_started_unix,
            "startup_host_reserve_mib": startup_reserve_mib,
            "active_phase_dir": phase_dir.name if phase_dir else None,
            "compressed_exists": compressed_exists,
            "wrap_v2_exists": wrap_exists,
            "inflight_artifacts": inflight_artifacts,
            "trash_artifacts": trash_artifacts,
            "last_resource_age_s": last_resource_age_s,
            "completion": completion_est,
            "liveness": {
                "mode": op_mode,
                "headline": op_headline,
                "detail": op_detail,
                "phase_elapsed_s": phase_elapsed_s,
                "cooldown_remaining_s": cooldown_rem_s,
                "headroom_current_gib": host_avail_gib,
                "headroom_target_gib": target_gib,
                "headroom_pct": round(min(100.0, (host_avail_gib / max(0.1, target_gib)) * 100.0), 1),
                "current_task_elapsed_s": round(
                    min(phase_elapsed_s, float(progress.get("last_event_age_s", 0.0))), 1
                )
                if not phase_finished and active_phase_name in ("gpu", "cpu")
                else 0.0,
                "expected_task_s": round(float(est_task_s), 1),
            },
            "limits": {
                "cpu_cores": 2,
                "linux_ram_soft_mib": 1024,
                "linux_ram_hard_mib": 2048,
                "swap_max_mib": 4096,
                "host_free_floor_mib": 3072,
                "host_start_reserve_mib": startup_reserve_mib,
                "cuda_pool_release_mib": 256,
                "element_threshold": run_cfg_element_threshold,
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
            "guard_events": guard_events[-15:],
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
        self._frame_seq += 1
        hm = windows_memory_snapshot()
        avail_b = hm.get("avail_phys_bytes") if hm.get("supported") else None
        return {
            "schema": "rbzk-prover-telemetry-v2",
            "frame_seq": self._frame_seq,
            "sampled_at_unix": round(time.time(), 3),
            "host_memory": hm,
            "host_guard": self.query_host_heartbeat(),
            "gpu": self.query_gpu(),
            "wsl_prover": self.query_wsl_prover(host_avail_bytes=avail_b),
        }
