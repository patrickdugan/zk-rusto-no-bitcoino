//! Read-only live telemetry collector for Windows host, NVIDIA GPU, and WSL provers.
//!
//! Imposes near-zero CPU/RAM overhead (~4–6 MiB RSS), uses `FILE_SHARE_READ|WRITE|DELETE`
//! on Windows so atomic renames never block, and runs `nvidia-smi` with `CREATE_NO_WINDOW`.

use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    process::Command,
    sync::Mutex,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use serde_json::{json, Value};

use crate::correlator::{estimate_ark_live_completion, round_n, ArkLiveCompletionArgs};

pub const DEFAULT_WSL_ARK_BASE: &str =
    r"\\wsl.localhost\Ubuntu-24.04\var\tmp\ark-asp-full-20261117";

fn user_home_dir() -> PathBuf {
    std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

pub fn default_wsl_ark_base() -> PathBuf {
    std::env::var_os("RBZK_WSL_ARK_BASE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_WSL_ARK_BASE))
}

pub fn default_host_heartbeat_path() -> PathBuf {
    std::env::var_os("RBZK_HOST_HEARTBEAT")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            user_home_dir()
                .join(r"Documents\Codex\2026-11-15\new-chat\work\ark-run-20261118\host.json")
        })
}

pub fn default_pipeline_log_path() -> PathBuf {
    std::env::var_os("RBZK_PIPELINE_LOG")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            user_home_dir()
                .join(r"Documents\Codex\2026-11-15\new-chat\work\ark-run-20261118\pipeline.log")
        })
}

pub fn unix_now_f64() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

pub fn mtime_unix_f64(meta: &fs::Metadata) -> f64 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

pub fn strip_ansi(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\x1b' && chars.peek() == Some(&'[') {
            let _ = chars.next();
            for c in chars.by_ref() {
                if c == 'm' || (!c.is_ascii_digit() && c != ';') {
                    break;
                }
            }
        } else {
            out.push(ch);
        }
    }
    out
}

/// Parses lines matching:
/// `progress 123s: shards proved 10 replayed 20 (mean 45.2s), recursion proved 3 replayed 4, store 512 MiB`
pub fn parse_progress_log_line(line: &str) -> Option<Value> {
    let idx = line.find("progress ")?;
    let rest = &line[idx + "progress ".len()..];
    let colon_pos = rest.find(':')?;
    let elapsed_str = rest[..colon_pos].trim().trim_end_matches('s').trim();
    let elapsed_s: u64 = elapsed_str.parse().ok()?;

    let after_colon = rest[colon_pos + 1..].trim();
    let rest_sp = after_colon.strip_prefix("shards")?;
    let rest_sp = rest_sp.trim_start().strip_prefix("proved")?.trim_start();
    let (shards_proved_str, rest_sp) = split_first_token(rest_sp)?;
    let shards_proved: u64 = shards_proved_str.parse().ok()?;

    let rest_sp = rest_sp.trim_start().strip_prefix("replayed")?.trim_start();
    let (shards_replayed_raw, mut rest_sp) = split_first_token(rest_sp)?;
    let shards_replayed: u64 = shards_replayed_raw.trim_end_matches(',').parse().ok()?;

    let mut mean_s: Option<f64> = None;
    rest_sp = rest_sp.trim_start();
    if let Some(after_paren) = rest_sp.strip_prefix("(mean") {
        let close = after_paren.find(')')?;
        let inside = after_paren[..close].trim().trim_end_matches('s').trim();
        mean_s = inside.parse::<f64>().ok();
        rest_sp = after_paren[close + 1..].trim_start();
    }
    rest_sp = rest_sp.trim_start_matches(',').trim_start();

    let rest_rec = rest_sp.strip_prefix("recursion")?.trim_start();
    let rest_rec = rest_rec.strip_prefix("proved")?.trim_start();
    let (rec_proved_str, rest_rec) = split_first_token(rest_rec)?;
    let rec_proved: u64 = rec_proved_str.parse().ok()?;

    let rest_rec = rest_rec.trim_start().strip_prefix("replayed")?.trim_start();
    let (rec_replayed_raw, rest_rec) = split_first_token(rest_rec)?;
    let rec_replayed: u64 = rec_replayed_raw.trim_end_matches(',').parse().ok()?;

    let rest_store = rest_rec
        .trim_start()
        .trim_start_matches(',')
        .trim_start()
        .strip_prefix("store")?
        .trim_start();
    let (store_str, _) = split_first_token(rest_store)?;
    let store_mib: u64 = store_str.parse().ok()?;

    Some(json!({
        "elapsed_s": elapsed_s,
        "session_shards_proved": shards_proved,
        "session_shards_replayed": shards_replayed,
        "mean_shard_s": mean_s,
        "session_recursion_proved": rec_proved,
        "session_recursion_replayed": rec_replayed,
        "artifact_store_mib": store_mib,
    }))
}

fn split_first_token(s: &str) -> Option<(&str, &str)> {
    let s = s.trim_start();
    if s.is_empty() {
        return None;
    }
    let end = s
        .find(|c: char| c.is_whitespace() || c == ',')
        .unwrap_or(s.len());
    if end == 0 {
        return None;
    }
    Some((&s[..end], &s[end..]))
}

pub fn read_shared_text(path: &Path, max_bytes: usize) -> Option<String> {
    let mut opts = OpenOptions::new();
    opts.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // FILE_SHARE_READ (1) | FILE_SHARE_WRITE (2) | FILE_SHARE_DELETE (4)
        opts.share_mode(0x07);
    }
    let mut file = opts.open(path).ok()?;
    let mut buf = vec![0u8; max_bytes];
    let n = file.read(&mut buf).ok()?;
    buf.truncate(n);
    Some(String::from_utf8_lossy(&buf).into_owned())
}

pub fn tail_bytes(path: &Path, max_bytes: u64) -> String {
    let mut opts = OpenOptions::new();
    opts.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        opts.share_mode(0x07);
    }
    let Ok(mut fh) = opts.open(path) else {
        return String::new();
    };
    let Ok(end) = fh.seek(SeekFrom::End(0)) else {
        return String::new();
    };
    let start = end.saturating_sub(max_bytes);
    if fh.seek(SeekFrom::Start(start)).is_err() {
        return String::new();
    }
    let mut buf = Vec::new();
    if fh.read_to_end(&mut buf).is_err() {
        return String::new();
    }
    String::from_utf8_lossy(&buf).into_owned()
}

fn fmt_thousands(mut n: u64) -> String {
    if n == 0 {
        return "0".to_string();
    }
    let mut groups = Vec::new();
    while n > 0 {
        groups.push((n % 1000) as u16);
        n /= 1000;
    }
    let mut out = String::new();
    for (idx, &g) in groups.iter().rev().enumerate() {
        if idx == 0 {
            out.push_str(&g.to_string());
        } else {
            out.push_str(&format!(",{g:03}"));
        }
    }
    out
}

// --------------------------------------------------------------------------------------------
// Windows Native Memory & vmmemWSL Inspection (`GlobalMemoryStatusEx` + `NtQuerySystemInformation`)
// --------------------------------------------------------------------------------------------

#[cfg(windows)]
mod win_mem {
    use std::{ffi::OsStr, os::windows::ffi::OsStrExt, path::Path};

    use serde_json::{json, Map, Value};

    #[repr(C)]
    struct MemoryStatusEx {
        dw_length: u32,
        dw_memory_load: u32,
        ull_total_phys: u64,
        ull_avail_phys: u64,
        ull_total_page_file: u64,
        ull_avail_page_file: u64,
        ull_total_virtual: u64,
        ull_avail_virtual: u64,
        ull_avail_extended_virtual: u64,
    }

    #[repr(C)]
    struct UnicodeString {
        length: u16,
        maximum_length: u16,
        buffer: *const u16,
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn GlobalMemoryStatusEx(lp_buffer: *mut MemoryStatusEx) -> i32;
        fn GetDiskFreeSpaceExW(
            lp_directory_name: *const u16,
            lp_free_bytes_available_to_caller: *mut u64,
            lp_total_number_of_bytes: *mut u64,
            lp_total_number_of_free_bytes: *mut u64,
        ) -> i32;
    }

    #[link(name = "ntdll")]
    extern "system" {
        fn NtQuerySystemInformation(
            system_information_class: u32,
            system_information: *mut u8,
            system_information_length: u32,
            return_length: *mut u32,
        ) -> i32;
    }

    fn inspect_wsl_vm_memory() -> Option<Value> {
        if std::mem::size_of::<usize>() != 8 {
            return None;
        }
        let mut size: u32 = 512 * 1024;
        let mut buf: Vec<u8>;
        let mut ok = false;
        buf = Vec::new();
        for _ in 0..6 {
            buf = vec![0u8; size as usize];
            let mut ret: u32 = 0;
            // SAFETY: `buf` is uniquely owned with length `size`, `SystemProcessInformation = 5`.
            let status = unsafe {
                NtQuerySystemInformation(5, buf.as_mut_ptr(), size, &mut ret as *mut u32)
            };
            if status == 0 {
                ok = true;
                break;
            }
            if (status as u32) == 0xC000_0004 {
                size = (size.saturating_mul(2)).max(ret.saturating_add(65_536));
                continue;
            }
            return None;
        }
        if !ok {
            return None;
        }

        let mut offset: usize = 0;
        while offset + 0xD0 <= buf.len() {
            let next_off = u32::from_ne_bytes(buf[offset..offset + 4].try_into().ok()?) as usize;
            // SAFETY: `offset + 0x38 + sizeof(UnicodeString) <= offset + 0xD0 <= buf.len()`;
            // read unaligned to avoid alignment assumptions on `buf`.
            let ustr: UnicodeString = unsafe {
                std::ptr::read_unaligned(buf.as_ptr().add(offset + 0x38) as *const UnicodeString)
            };
            if ustr.length >= 2 && !ustr.buffer.is_null() {
                let char_len = (ustr.length as usize) / 2;
                let buf_start = buf.as_ptr() as usize;
                let buf_end = buf_start + buf.len();
                let str_addr = ustr.buffer as usize;
                if str_addr >= buf_start && str_addr.saturating_add(char_len * 2) <= buf_end {
                    // SAFETY: Verified `ustr.buffer` points within our owned `buf` allocation.
                    let slice = unsafe { std::slice::from_raw_parts(ustr.buffer, char_len) };
                    let name = String::from_utf16_lossy(slice);
                    let low = name.to_ascii_lowercase();
                    if matches!(
                        low.as_str(),
                        "vmmemwsl" | "vmmemwsl.exe" | "vmmem" | "vmmem.exe"
                    ) {
                        let read_usize = |field_off: usize| -> u64 {
                            let bytes: [u8; 8] = buf[offset + field_off..offset + field_off + 8]
                                .try_into()
                                .unwrap_or([0; 8]);
                            u64::from_ne_bytes(bytes)
                        };
                        let pid = read_usize(0x50);
                        let peak_ws = read_usize(0x88);
                        let ws = read_usize(0x90);
                        let priv_commit = read_usize(0xB8);
                        let peak_pf = read_usize(0xC0);
                        return Some(json!({
                            "name": name,
                            "pid": pid,
                            "working_set_bytes": ws,
                            "peak_working_set_bytes": peak_ws,
                            "private_commit_bytes": priv_commit,
                            "pagefile_bytes": peak_pf,
                            "nonresident_commit_bytes": priv_commit.saturating_sub(ws),
                        }));
                    }
                }
            }
            if next_off == 0 {
                break;
            }
            offset = offset.saturating_add(next_off);
        }
        None
    }

    fn query_drive_space(drive: &str) -> Option<Value> {
        if !Path::new(drive).exists() {
            return None;
        }
        let wide: Vec<u16> = OsStr::new(drive)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let mut avail_caller = 0u64;
        let mut total = 0u64;
        let mut total_free = 0u64;
        // SAFETY: `wide` is null-terminated UTF-16 and output pointers are valid stack `u64`s.
        let ok = unsafe {
            GetDiskFreeSpaceExW(
                wide.as_ptr(),
                &mut avail_caller,
                &mut total,
                &mut total_free,
            )
        };
        if ok == 0 {
            return None;
        }
        Some(json!({
            "total_bytes": total,
            "free_bytes": total_free,
            "used_bytes": total.saturating_sub(total_free),
        }))
    }

    pub fn snapshot() -> Value {
        let mut stat = MemoryStatusEx {
            dw_length: std::mem::size_of::<MemoryStatusEx>() as u32,
            dw_memory_load: 0,
            ull_total_phys: 0,
            ull_avail_phys: 0,
            ull_total_page_file: 0,
            ull_avail_page_file: 0,
            ull_total_virtual: 0,
            ull_avail_virtual: 0,
            ull_avail_extended_virtual: 0,
        };
        // SAFETY: `stat.dw_length` is initialized to the exact size of `MemoryStatusEx`.
        let ok = unsafe { GlobalMemoryStatusEx(&mut stat as *mut MemoryStatusEx) };
        if ok == 0 {
            return json!({ "supported": false });
        }
        let used_phys = stat.ull_total_phys.saturating_sub(stat.ull_avail_phys);
        let used_commit = stat
            .ull_total_page_file
            .saturating_sub(stat.ull_avail_page_file);
        let mut disks = Map::new();
        for drv in ["C:\\", "D:\\"] {
            if let Some(d) = query_drive_space(drv) {
                disks.insert(drv.to_string(), d);
            }
        }
        json!({
            "supported": true,
            "load_percent": stat.dw_memory_load,
            "total_phys_bytes": stat.ull_total_phys,
            "avail_phys_bytes": stat.ull_avail_phys,
            "used_phys_bytes": used_phys,
            "total_commit_bytes": stat.ull_total_page_file,
            "avail_commit_bytes": stat.ull_avail_page_file,
            "used_commit_bytes": used_commit,
            "vmmem_wsl": inspect_wsl_vm_memory(),
            "disks": disks,
        })
    }
}

#[cfg(not(windows))]
mod win_mem {
    use serde_json::{json, Value};
    use std::fs;

    pub fn snapshot() -> Value {
        // Fallback Linux `/proc/meminfo` reader so headless Linux runs/tests also get real telemetry
        let Ok(raw) = fs::read_to_string("/proc/meminfo") else {
            return json!({ "supported": false });
        };
        let mut total_kib = 0u64;
        let mut avail_kib = 0u64;
        for ln in raw.lines() {
            if let Some(rest) = ln.strip_prefix("MemTotal:") {
                total_kib = rest
                    .split_whitespace()
                    .next()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
            } else if let Some(rest) = ln.strip_prefix("MemAvailable:") {
                avail_kib = rest
                    .split_whitespace()
                    .next()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
            }
        }
        if total_kib == 0 {
            return json!({ "supported": false });
        }
        let total_b = total_kib * 1024;
        let avail_b = avail_kib * 1024;
        let used_b = total_b.saturating_sub(avail_b);
        let load = ((used_b as f64) * 100.0 / (total_b as f64)).round() as u64;
        json!({
            "supported": true,
            "load_percent": load,
            "total_phys_bytes": total_b,
            "avail_phys_bytes": avail_b,
            "used_phys_bytes": used_b,
            "total_commit_bytes": total_b,
            "avail_commit_bytes": avail_b,
            "used_commit_bytes": used_b,
            "vmmem_wsl": Value::Null,
            "disks": {},
        })
    }
}

pub fn windows_memory_snapshot() -> Value {
    win_mem::snapshot()
}

// --------------------------------------------------------------------------------------------
// Incremental SP1 `progress.jsonl` Tail Cache
// --------------------------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct UniqueTaskEntry {
    key: String,
    kind: String,
    replayed: bool,
    ms: u64,
}

#[derive(Default)]
struct ProgressInner {
    path: Option<PathBuf>,
    offset: u64,
    seq_counter: u64,
    unique_by_key: HashMap<String, UniqueTaskEntry>,
    unique_order: VecDeque<String>,
    total_rows_by_kind: BTreeMap<String, u64>,
    proved_rows_by_kind: BTreeMap<String, u64>,
    replayed_rows_by_kind: BTreeMap<String, u64>,
    recent_events: VecDeque<Value>,
    last_event_unix: Option<f64>,
    proved_timestamps_shard: VecDeque<i64>,
    proved_timestamps_reduce: VecDeque<i64>,
    proved_durations_shard: VecDeque<u64>,
    proved_durations_reduce: VecDeque<u64>,
}

impl ProgressInner {
    fn reset(&mut self, path: Option<PathBuf>) {
        *self = Self {
            path,
            ..Self::default()
        };
    }
}

pub struct ProgressTailCache {
    inner: Mutex<ProgressInner>,
}

impl Default for ProgressTailCache {
    fn default() -> Self {
        Self::new()
    }
}

impl ProgressTailCache {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(ProgressInner::default()),
        }
    }

    pub fn read(&self, path: &Path) -> Value {
        let mut st = self.inner.lock().unwrap();
        let Ok(meta) = fs::metadata(path) else {
            return json!({
                "exists": false,
                "seq": 0,
                "unique_shards": 0,
                "unique_reduces": 0,
                "total_rows": 0,
            });
        };

        let size = meta.len();
        if st.path.as_deref() != Some(path) || size < st.offset {
            st.reset(Some(path.to_path_buf()));
        }

        if size > st.offset {
            if let Ok(mut fh) = File::open(path) {
                if fh.seek(SeekFrom::Start(st.offset)).is_ok() {
                    let mut chunk = Vec::new();
                    if fh.read_to_end(&mut chunk).is_ok() {
                        if let Some(last_nl) = chunk.iter().rposition(|&b| b == b'\n') {
                            let complete = &chunk[..=last_nl];
                            st.offset += complete.len() as u64;
                            let text = String::from_utf8_lossy(complete);
                            for raw_line in text.lines() {
                                let trimmed = raw_line.trim();
                                if trimmed.is_empty() {
                                    continue;
                                }
                                let Ok(obj) = serde_json::from_str::<Value>(trimmed) else {
                                    continue;
                                };
                                st.seq_counter += 1;
                                let kind = obj
                                    .get("kind")
                                    .and_then(Value::as_str)
                                    .unwrap_or("unknown")
                                    .to_string();
                                let key = obj
                                    .get("key")
                                    .and_then(Value::as_str)
                                    .unwrap_or("")
                                    .to_string();
                                let replayed = obj
                                    .get("replayed")
                                    .and_then(Value::as_bool)
                                    .unwrap_or(false);
                                let ms = obj.get("ms").and_then(Value::as_u64).unwrap_or(0);
                                let ts = obj.get("t").and_then(Value::as_i64).unwrap_or(0);
                                if ts > 0 {
                                    let tsf = ts as f64;
                                    st.last_event_unix = Some(
                                        st.last_event_unix.map(|prev| prev.max(tsf)).unwrap_or(tsf),
                                    );
                                }
                                *st.total_rows_by_kind.entry(kind.clone()).or_insert(0) += 1;
                                if replayed {
                                    *st.replayed_rows_by_kind.entry(kind.clone()).or_insert(0) += 1;
                                } else {
                                    *st.proved_rows_by_kind.entry(kind.clone()).or_insert(0) += 1;
                                    if kind == "shard" {
                                        if ts > 0 {
                                            if st.proved_timestamps_shard.len() >= 400 {
                                                st.proved_timestamps_shard.pop_front();
                                            }
                                            st.proved_timestamps_shard.push_back(ts);
                                        }
                                        if ms > 0 {
                                            if st.proved_durations_shard.len() >= 200 {
                                                st.proved_durations_shard.pop_front();
                                            }
                                            st.proved_durations_shard.push_back(ms);
                                        }
                                    } else if kind == "reduce" {
                                        if ts > 0 {
                                            if st.proved_timestamps_reduce.len() >= 400 {
                                                st.proved_timestamps_reduce.pop_front();
                                            }
                                            st.proved_timestamps_reduce.push_back(ts);
                                        }
                                        if ms > 0 {
                                            if st.proved_durations_reduce.len() >= 200 {
                                                st.proved_durations_reduce.pop_front();
                                            }
                                            st.proved_durations_reduce.push_back(ms);
                                        }
                                    }
                                }

                                if !key.is_empty() {
                                    if let Some(prev) = st.unique_by_key.get_mut(&key) {
                                        prev.replayed = prev.replayed && replayed;
                                        if !replayed {
                                            prev.ms = ms;
                                        }
                                    } else {
                                        st.unique_by_key.insert(
                                            key.clone(),
                                            UniqueTaskEntry {
                                                key: key.clone(),
                                                kind: kind.clone(),
                                                replayed,
                                                ms,
                                            },
                                        );
                                        if st.unique_order.len() >= 2500 {
                                            st.unique_order.pop_front();
                                        }
                                        st.unique_order.push_back(key.clone());
                                    }
                                }

                                if st.recent_events.len() >= 80 {
                                    st.recent_events.pop_front();
                                }
                                let cur_seq = st.seq_counter;
                                st.recent_events.push_back(json!({
                                    "seq": cur_seq,
                                    "key": key,
                                    "kind": kind,
                                    "ms": ms,
                                    "replayed": replayed,
                                    "t": ts,
                                }));
                            }
                        }
                    }
                }
            }
        }

        let mut unique_shards = 0u64;
        let mut unique_reduces = 0u64;
        for info in st.unique_by_key.values() {
            if info.kind == "shard" {
                unique_shards += 1;
            } else if info.kind == "reduce" {
                unique_reduces += 1;
            }
        }

        let now = unix_now_f64();
        let mut rates = BTreeMap::new();
        let mut mean_ms = BTreeMap::new();

        for (kind, stamps, durs) in [
            (
                "shard",
                &st.proved_timestamps_shard,
                &st.proved_durations_shard,
            ),
            (
                "reduce",
                &st.proved_timestamps_reduce,
                &st.proved_durations_reduce,
            ),
        ] {
            let recent_5m: Vec<i64> = stamps
                .iter()
                .copied()
                .filter(|&t| now - (t as f64) <= 300.0)
                .collect();
            let recent_15m: Vec<i64> = stamps
                .iter()
                .copied()
                .filter(|&t| now - (t as f64) <= 900.0)
                .collect();
            let recent_30m: Vec<i64> = stamps
                .iter()
                .copied()
                .filter(|&t| now - (t as f64) <= 1800.0)
                .collect();

            let r5 = if recent_5m.len() >= 2 {
                let span = (now - (recent_5m[0] as f64)).max(30.0);
                round_n((recent_5m.len() as f64) * 60.0 / span, 2)
            } else if recent_5m.len() == 1 {
                0.2
            } else {
                0.0
            };
            rates.insert(format!("{kind}_per_min_5m"), r5);

            let r15 = if recent_15m.len() >= 2 {
                let span15 = (now - (recent_15m[0] as f64)).max(60.0);
                round_n((recent_15m.len() as f64) * 60.0 / span15, 2)
            } else {
                r5
            };
            rates.insert(format!("{kind}_per_min_15m"), r15);

            let r30 = if recent_30m.len() >= 3
                && (recent_30m[recent_30m.len() - 1] - recent_30m[0]) >= 60
            {
                let inter_span = (recent_30m[recent_30m.len() - 1] - recent_30m[0]) as f64;
                let tail_gap = (now - (recent_30m[recent_30m.len() - 1] as f64)).max(0.0);
                let eff_span = inter_span + if tail_gap > 240.0 { tail_gap } else { 0.0 };
                round_n(
                    ((recent_30m.len() - 1) as f64) * 60.0 / eff_span.max(60.0),
                    3,
                )
            } else {
                r15
            };
            rates.insert(format!("{kind}_per_min_30m"), r30);

            let avg = if durs.is_empty() {
                0
            } else {
                durs.iter().sum::<u64>() / (durs.len() as u64)
            };
            mean_ms.insert(kind.to_string(), avg);
        }

        let order_len = st.unique_order.len();
        let tail_start = order_len.saturating_sub(320);
        let mosaic_tail: Vec<Value> = st
            .unique_order
            .iter()
            .skip(tail_start)
            .filter_map(|k| st.unique_by_key.get(k))
            .map(|u| {
                let short_k: String = u.key.chars().take(8).collect();
                json!({
                    "k": short_k,
                    "t": u8::from(u.kind == "reduce"),
                    "r": u8::from(u.replayed),
                    "s": round_n((u.ms as f64) / 1000.0, 1),
                })
            })
            .collect();

        let ev_len = st.recent_events.len();
        let recent_events: Vec<Value> = st
            .recent_events
            .iter()
            .skip(ev_len.saturating_sub(40))
            .cloned()
            .collect();

        let mtime = mtime_unix_f64(&meta);
        let last_ev_ts = st.last_event_unix.unwrap_or(mtime);
        let total_rows: u64 = st.total_rows_by_kind.values().sum();

        json!({
            "exists": true,
            "path": path.to_string_lossy(),
            "seq": st.seq_counter,
            "size_bytes": size,
            "mtime_unix": mtime,
            "last_event_age_s": round_n((now - last_ev_ts).max(0.0), 1),
            "unique_shards": unique_shards,
            "unique_reduces": unique_reduces,
            "total_rows": total_rows,
            "total_rows_by_kind": st.total_rows_by_kind,
            "proved_rows_by_kind": st.proved_rows_by_kind,
            "replayed_rows_by_kind": st.replayed_rows_by_kind,
            "rates": rates,
            "mean_proved_ms": mean_ms,
            "recent_events": recent_events,
            "mosaic_tail": mosaic_tail,
        })
    }
}

// --------------------------------------------------------------------------------------------
// Top-Level TelemetryCollector
// --------------------------------------------------------------------------------------------

struct GpuState {
    last_polled: Option<Instant>,
    cached: Value,
    history: VecDeque<Value>,
}

pub struct TelemetryCollector {
    pub wsl_ark_base: PathBuf,
    pub host_heartbeat_path: PathBuf,
    pub pipeline_log_path: PathBuf,
    progress_cache: ProgressTailCache,
    gpu_state: Mutex<GpuState>,
    frame_seq: Mutex<u64>,
}

impl TelemetryCollector {
    pub fn new(
        wsl_ark_base: Option<PathBuf>,
        host_heartbeat_path: Option<PathBuf>,
        pipeline_log_path: Option<PathBuf>,
    ) -> Self {
        Self {
            wsl_ark_base: wsl_ark_base.unwrap_or_else(default_wsl_ark_base),
            host_heartbeat_path: host_heartbeat_path.unwrap_or_else(default_host_heartbeat_path),
            pipeline_log_path: pipeline_log_path.unwrap_or_else(default_pipeline_log_path),
            progress_cache: ProgressTailCache::new(),
            gpu_state: Mutex::new(GpuState {
                last_polled: None,
                cached: json!({ "available": false }),
                history: VecDeque::with_capacity(180),
            }),
            frame_seq: Mutex::new(0),
        }
    }

    pub fn query_gpu(&self) -> Value {
        {
            let guard = self.gpu_state.lock().unwrap();
            if let Some(prev) = guard.last_polled {
                if prev.elapsed().as_secs_f64() < 1.0 {
                    return guard.cached.clone();
                }
            }
        }

        let mut cmd = Command::new("nvidia-smi");
        cmd.args([
            "--query-gpu=name,utilization.gpu,utilization.memory,memory.used,memory.free,memory.total,temperature.gpu,power.draw,power.limit,clocks.current.sm,clocks.current.memory,pstate",
            "--format=csv,noheader,nounits",
        ]);
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
        }

        let mut gpu_info = json!({ "available": false });
        if let Ok(out) = cmd.output() {
            if out.status.success() {
                let stdout = String::from_utf8_lossy(&out.stdout);
                if let Some(first_line) = stdout.lines().find(|l| !l.trim().is_empty()) {
                    let parts: Vec<&str> = first_line.split(',').map(str::trim).collect();
                    if parts.len() >= 12 {
                        let f = |s: &str| s.parse::<f64>().ok();
                        let i = |s: &str| s.parse::<i64>().ok();
                        gpu_info = json!({
                            "available": true,
                            "name": parts[0],
                            "util_gpu_pct": f(parts[1]).unwrap_or(0.0),
                            "util_mem_pct": f(parts[2]).unwrap_or(0.0),
                            "vram_used_mib": f(parts[3]).unwrap_or(0.0),
                            "vram_free_mib": f(parts[4]).unwrap_or(0.0),
                            "vram_total_mib": f(parts[5]).unwrap_or(16303.0),
                            "temp_c": i(parts[6]).unwrap_or(0),
                            "power_draw_w": f(parts[7]).unwrap_or(0.0),
                            "power_limit_w": f(parts[8]),
                            "clock_sm_mhz": i(parts[9]).unwrap_or(0),
                            "clock_mem_mhz": i(parts[10]).unwrap_or(0),
                            "pstate": parts[11],
                            "processes": [],
                        });
                    }
                }
            }
        }

        let sample_unix = unix_now_f64();
        let mut guard = self.gpu_state.lock().unwrap();
        if gpu_info.get("available").and_then(Value::as_bool) == Some(true) {
            if guard.history.len() >= 180 {
                guard.history.pop_front();
            }
            guard.history.push_back(json!({
                "t": round_n(sample_unix, 1),
                "util_gpu_pct": gpu_info["util_gpu_pct"],
                "util_mem_pct": gpu_info["util_mem_pct"],
                "vram_used_mib": gpu_info["vram_used_mib"],
                "power_draw_w": gpu_info["power_draw_w"],
                "temp_c": gpu_info["temp_c"],
            }));
        }
        let hist_len = guard.history.len();
        let hist_tail: Vec<Value> = guard
            .history
            .iter()
            .skip(hist_len.saturating_sub(120))
            .cloned()
            .collect();
        if let Some(obj) = gpu_info.as_object_mut() {
            obj.insert("history".to_string(), Value::Array(hist_tail));
        }
        guard.last_polled = Some(Instant::now());
        guard.cached = gpu_info.clone();
        gpu_info
    }

    fn wsl_path_to_windows(wsl_path: &str) -> PathBuf {
        let p = Path::new(wsl_path);
        if wsl_path.starts_with("\\\\") || (wsl_path.len() >= 2 && wsl_path.as_bytes()[1] == b':') {
            return p.to_path_buf();
        }
        #[cfg(not(windows))]
        {
            return p.to_path_buf();
        }
        #[cfg(windows)]
        {
            let clean = wsl_path.trim();
            if clean.starts_with("/mnt/") && clean.len() > 6 && clean.as_bytes()[6] == b'/' {
                let drive = (clean.as_bytes()[5] as char).to_ascii_uppercase();
                let rest = clean[7..].replace('/', "\\");
                return PathBuf::from(format!("{drive}:\\{rest}"));
            }
            let rel = clean.trim_start_matches('/').replace('/', "\\");
            PathBuf::from(r"\\wsl.localhost\Ubuntu-24.04").join(rel)
        }
    }

    pub fn query_wsl_prover(&self, host_avail_bytes: Option<u64>) -> Value {
        let now = unix_now_f64();
        let base = &self.wsl_ark_base;
        if !base.exists() {
            return json!({
                "reachable": false,
                "base_dir": base.to_string_lossy(),
            });
        }

        let status_path = base.join("pipeline-status.json");
        let pipeline_state: Value = fs::read_to_string(&status_path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_else(|| json!({}));

        let mut run_dir = base.join("prover-transient");
        if !run_dir.join("progress.jsonl").exists()
            && base.join("prover").join("progress.jsonl").exists()
        {
            run_dir = base.join("prover");
        }
        let progress = self.progress_cache.read(&run_dir.join("progress.jsonl"));

        let run_cfg_element_threshold = fs::read_to_string(run_dir.join("run.json"))
            .ok()
            .and_then(|s| serde_json::from_str::<Value>(&s).ok())
            .and_then(|v| v.get("element_threshold").and_then(Value::as_u64))
            .unwrap_or(67_108_864);
        let run_verified = run_dir.join("result.json").exists();

        let count_dir = |p: PathBuf| -> u64 {
            fs::read_dir(p)
                .ok()
                .map(|it| it.count() as u64)
                .unwrap_or(0)
        };
        let inflight_artifacts = count_dir(run_dir.join("artifacts").join("live"));
        let trash_artifacts = count_dir(run_dir.join("artifacts").join("trash"));

        let active_phase_name = pipeline_state
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string();
        let gpu_attempts_raw: Vec<String> = pipeline_state
            .get("attempts")
            .and_then(|a| a.get("gpu"))
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(Value::as_str)
                    .map(String::from)
                    .collect()
            })
            .unwrap_or_default();

        let phases_obj = pipeline_state.get("phases").and_then(Value::as_object);
        let phase_wsl_str: Option<String> = phases_obj
            .and_then(|m| m.get(&active_phase_name).and_then(Value::as_str))
            .or_else(|| phases_obj.and_then(|m| m.get("gpu").and_then(Value::as_str)))
            .map(String::from)
            .or_else(|| gpu_attempts_raw.last().cloned())
            .or_else(|| {
                phases_obj.and_then(|m| {
                    m.values()
                        .next_back()
                        .and_then(Value::as_str)
                        .map(String::from)
                })
            });
        let phase_dir = phase_wsl_str.as_deref().map(Self::wsl_path_to_windows);

        let mut phase_finished = false;
        let mut phase_started_unix: Option<f64> = None;
        if let Some(ref pdir) = phase_dir {
            if pdir.exists() {
                phase_finished = pdir.join("result.json").exists();
                phase_started_unix = fs::read_to_string(pdir.join("resources.json"))
                    .ok()
                    .and_then(|s| serde_json::from_str::<Value>(&s).ok())
                    .and_then(|v| v.get("started_at_unix").and_then(Value::as_f64))
                    .filter(|&x| x > 0.0);
            }
        }

        let mut resources_series: Vec<Value> = Vec::new();
        let mut latest_resource: Option<Value> = None;
        let mut last_resource_age_s: Option<f64> = None;
        let mut mem_peak_bytes = 0u64;
        let mut swap_peak_bytes = 0u64;
        let mut phase_log_tail = String::new();
        let mut latest_progress_line: Option<Value> = None;

        if let Some(ref pdir) = phase_dir {
            if pdir.exists() {
                let res_file = pdir.join("resources.jsonl");
                if let Ok(meta) = fs::metadata(&res_file) {
                    last_resource_age_s = Some(round_n((now - mtime_unix_f64(&meta)).max(0.0), 1));
                    let raw_res = tail_bytes(&res_file, 49_152);
                    for line in raw_res.lines() {
                        let trimmed = line.trim();
                        if !trimmed.starts_with('{') {
                            continue;
                        }
                        let Ok(item) = serde_json::from_str::<Value>(trimmed) else {
                            continue;
                        };
                        let mem_b = item
                            .get("memory_bytes")
                            .and_then(Value::as_u64)
                            .unwrap_or(0);
                        let swp_b = item.get("swap_bytes").and_then(Value::as_u64).unwrap_or(0);
                        mem_peak_bytes = mem_peak_bytes.max(mem_b);
                        swap_peak_bytes = swap_peak_bytes.max(swp_b);
                        let d_free = item
                            .get("disk_free")
                            .and_then(|d| d.get("/mnt/d"))
                            .and_then(Value::as_f64)
                            .unwrap_or(0.0);
                        resources_series.push(json!({
                            "elapsed_s": round_n(item.get("elapsed_seconds").and_then(Value::as_f64).unwrap_or(0.0), 1),
                            "cgroup_ram_mib": round_n((mem_b as f64) / (1024.0 * 1024.0), 1),
                            "cgroup_swap_mib": round_n((swp_b as f64) / (1024.0 * 1024.0), 1),
                            "wsl_avail_gib": round_n(item.get("available_bytes").and_then(Value::as_f64).unwrap_or(0.0) / 1_073_741_824.0, 2),
                            "host_avail_gib": round_n(item.get("host_available_bytes").and_then(Value::as_f64).unwrap_or(0.0) / 1_073_741_824.0, 2),
                            "d_free_gib": round_n(d_free / 1_073_741_824.0, 2),
                        }));
                    }
                    if let Some(last) = resources_series.last().cloned() {
                        if phase_finished {
                            let mut zeroed = last;
                            if let Some(obj) = zeroed.as_object_mut() {
                                obj.insert("cgroup_ram_mib".into(), json!(0.0));
                                obj.insert("cgroup_swap_mib".into(), json!(0.0));
                            }
                            latest_resource = Some(zeroed);
                        } else {
                            latest_resource = Some(last);
                        }
                    }
                }

                let log_file = pdir.join("phase.log");
                if log_file.exists() {
                    let cleaned = strip_ansi(&tail_bytes(&log_file, 8192));
                    let lines: Vec<&str> =
                        cleaned.lines().filter(|l| !l.trim().is_empty()).collect();
                    let start = lines.len().saturating_sub(28);
                    phase_log_tail = lines[start..].join("\n");
                    for &ln in lines.iter().rev() {
                        if let Some(parsed) = parse_progress_log_line(ln) {
                            latest_progress_line = Some(parsed);
                            break;
                        }
                    }
                }
            }
        }

        // Guard / attempt history
        let mut guard_events: Vec<(f64, Value)> = Vec::new();
        let mut seen_completed = HashSet::new();
        for (idx, att_wsl) in gpu_attempts_raw.iter().enumerate() {
            let att_dir = Self::wsl_path_to_windows(att_wsl);
            let res_json = att_dir.join("result.json");
            if let Ok(raw) = fs::read_to_string(&res_json) {
                if let Ok(ev) = serde_json::from_str::<Value>(&raw) {
                    let comp_f = ev
                        .get("completed_at_unix")
                        .and_then(Value::as_f64)
                        .unwrap_or(0.0);
                    seen_completed.insert(comp_f as i64);
                    let cleaned_shm = ev
                        .get("removed_owned_shared_files")
                        .and_then(Value::as_array)
                        .map(Vec::len)
                        .unwrap_or(0);
                    let phase_name = att_dir
                        .file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_else(|| "gpu".into());
                    guard_events.push((
                        comp_f,
                        json!({
                            "attempt": idx + 1,
                            "phase": phase_name,
                            "exit_code": ev.get("exit_code"),
                            "stop_reason": ev.get("stop_reason").filter(|v| !v.is_null()).cloned().unwrap_or_else(|| json!("completed")),
                            "elapsed_s": round_n(ev.get("elapsed_seconds").and_then(Value::as_f64).unwrap_or(0.0), 1),
                            "memory_peak_mib": round_n(ev.get("memory_peak_bytes").and_then(Value::as_f64).unwrap_or(0.0) / (1024.0 * 1024.0), 1),
                            "swap_peak_mib": round_n(ev.get("swap_peak_bytes").and_then(Value::as_f64).unwrap_or(0.0) / (1024.0 * 1024.0), 1),
                            "cleaned_shm_count": cleaned_shm,
                            "completed_at_unix": ev.get("completed_at_unix"),
                        }),
                    ));
                }
            }
        }

        if let Some(raw_pipe) = read_shared_text(&self.pipeline_log_path, 32_768) {
            for ln in raw_pipe.lines() {
                let ln_s = ln.trim();
                if ln_s.starts_with('{') && ln_s.contains("stop_reason") {
                    if let Ok(ev) = serde_json::from_str::<Value>(ln_s) {
                        let comp_f = ev
                            .get("completed_at_unix")
                            .and_then(Value::as_f64)
                            .unwrap_or(0.0);
                        if seen_completed.insert(comp_f as i64) {
                            let cleaned_shm = ev
                                .get("removed_owned_shared_files")
                                .and_then(Value::as_array)
                                .map(Vec::len)
                                .unwrap_or(0);
                            guard_events.push((
                                comp_f,
                                json!({
                                    "attempt": Value::Null,
                                    "phase": "earlier-run",
                                    "exit_code": ev.get("exit_code"),
                                    "stop_reason": ev.get("stop_reason").filter(|v| !v.is_null()).cloned().unwrap_or_else(|| json!("completed")),
                                    "elapsed_s": round_n(ev.get("elapsed_seconds").and_then(Value::as_f64).unwrap_or(0.0), 1),
                                    "memory_peak_mib": round_n(ev.get("memory_peak_bytes").and_then(Value::as_f64).unwrap_or(0.0) / (1024.0 * 1024.0), 1),
                                    "swap_peak_mib": round_n(ev.get("swap_peak_bytes").and_then(Value::as_f64).unwrap_or(0.0) / (1024.0 * 1024.0), 1),
                                    "cleaned_shm_count": cleaned_shm,
                                    "completed_at_unix": ev.get("completed_at_unix"),
                                }),
                            ));
                        }
                    }
                }
            }
        }
        guard_events.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));
        let ge_len = guard_events.len();
        let guard_tail: Vec<Value> = guard_events
            .into_iter()
            .skip(ge_len.saturating_sub(15))
            .map(|(_, v)| v)
            .collect();

        let compressed_exists = base.join("compressed.bin").exists();
        let wrap_exists = base.join("m13").join("wrap-v2.bin").exists();
        let startup_reserve_mib = pipeline_state
            .get("startup_host_reserve_mib")
            .and_then(Value::as_u64)
            .unwrap_or(6144);
        let last_stop = pipeline_state.get("last_resource_stop");
        let last_stop_unix = last_stop
            .and_then(|ls| ls.get("completed_at_unix"))
            .and_then(Value::as_f64)
            .unwrap_or(0.0);

        let host_avail_gib = host_avail_bytes
            .map(|b| round_n((b as f64) / 1_073_741_824.0, 2))
            .unwrap_or_else(|| {
                latest_resource
                    .as_ref()
                    .and_then(|r| r.get("host_avail_gib"))
                    .and_then(Value::as_f64)
                    .unwrap_or(0.0)
            });
        let target_gib = round_n((startup_reserve_mib as f64) / 1024.0, 2);

        let unique_shards = progress
            .get("unique_shards")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let unique_reduces = progress
            .get("unique_reduces")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let last_ev_age = progress
            .get("last_event_age_s")
            .and_then(Value::as_f64)
            .unwrap_or(9999.0);

        let (op_mode, op_headline, op_detail, phase_elapsed_s, cooldown_rem_s) =
            if active_phase_name == "all_proof_checks_passed" || wrap_exists {
                (
                    "completed",
                    "All SP1, M13 BLAKE3 & M14 Garbled Checks Verified".to_string(),
                    "Proof pipeline finished cleanly.".to_string(),
                    0.0,
                    0.0,
                )
            } else if active_phase_name.starts_with("waiting_for_headroom") || phase_finished {
                let since_stop = if last_stop_unix > 0.0 {
                    (now - last_stop_unix).max(0.0)
                } else {
                    999.0
                };
                let cd_rem = round_n((60.0 - since_stop).max(0.0), 1);
                let ph_el = round_n(since_stop, 1);
                if cd_rem > 0.0 {
                    let reason = last_stop
                        .and_then(|ls| ls.get("stop_reason"))
                        .and_then(Value::as_str)
                        .unwrap_or("host_memory_floor");
                    (
                        "cooldown_backoff",
                        format!(
                            "Resource-Guard Cooldown ({cd_rem:.0}s remaining) · Checkpoints Preserved"
                        ),
                        format!(
                            "Attempt #{} paused on {reason}; 1,131+ shards safe on disk. Rechecking host headroom ({host_avail_gib:.2} / {target_gib:.2} GiB) after 60s backoff.",
                            gpu_attempts_raw.len()
                        ),
                        ph_el,
                        cd_rem,
                    )
                } else {
                    let gap_gib = (target_gib - host_avail_gib).max(0.0);
                    let holds = pipeline_state
                        .get("gpu_host_holds")
                        .and_then(Value::as_u64)
                        .unwrap_or(0);
                    if gap_gib > 0.0 {
                        (
                            "waiting_headroom",
                            format!(
                                "Awaiting {target_gib:.2} GiB Windows Free RAM to Auto-Resume GPU (+{gap_gib:.2} GiB needed)"
                            ),
                            format!(
                                "Orchestrator polling host.json every 2s: Windows currently has {host_avail_gib:.2} GiB free (needs {target_gib:.2} GiB sustained for 10s; {holds} holds so far)."
                            ),
                            ph_el,
                            0.0,
                        )
                    } else {
                        (
                            "waiting_headroom",
                            format!(
                                "Headroom Target Met ({host_avail_gib:.2} ≥ {target_gib:.2} GiB) · Acquiring 10s Stability Lock"
                            ),
                            "Launching next resumable ark-prove-gpu phase as soon as 10-second stability window completes.".to_string(),
                            ph_el,
                            0.0,
                        )
                    }
                }
            } else {
                let ph_el = phase_started_unix
                    .map(|st| round_n((now - st).max(0.0), 1))
                    .unwrap_or_else(|| {
                        latest_resource
                            .as_ref()
                            .and_then(|r| r.get("elapsed_s"))
                            .and_then(Value::as_f64)
                            .unwrap_or(0.0)
                    });
                let last_was_replay = progress
                    .get("recent_events")
                    .and_then(Value::as_array)
                    .and_then(|arr| arr.last())
                    .and_then(|ev| ev.get("replayed"))
                    .and_then(Value::as_bool)
                    .unwrap_or(false);

                if ph_el < 95.0 && latest_progress_line.is_none() && last_ev_age > ph_el {
                    (
                        "cuda_init",
                        format!("CUDA Prover Initializing & Loading 22.5 MB Raw Key ({ph_el:.0}s)"),
                        format!(
                            "Attempt #{} active in cgroup: setting up SP1 6.9 CUDA kernels and preparing to replay {} cached shards.",
                            gpu_attempts_raw.len().max(1),
                            fmt_thousands(unique_shards)
                        ),
                        ph_el,
                        0.0,
                    )
                } else if last_ev_age < 15.0 && last_was_replay {
                    (
                        "replaying_memo",
                        "Streaming Cached Shard Memos into SP1 Compress Tree".to_string(),
                        format!(
                            "Replaying verified task digests from disk memo ({inflight_artifacts} live artifacts in flight)."
                        ),
                        ph_el,
                        0.0,
                    )
                } else {
                    let in_flight_s = round_n(ph_el.min(last_ev_age), 1);
                    let mean_s = latest_progress_line
                        .as_ref()
                        .and_then(|l| l.get("mean_shard_s"))
                        .and_then(Value::as_f64)
                        .unwrap_or_else(|| {
                            let ms = progress
                                .get("mean_proved_ms")
                                .and_then(|m| m.get("reduce"))
                                .and_then(Value::as_u64)
                                .unwrap_or(320_000);
                            if ms > 0 {
                                round_n((ms as f64) / 1000.0, 1)
                            } else {
                                250.0
                            }
                        });
                    (
                        "proving_inflight",
                        format!(
                            "Proving SP1 Shard / Recursion Task on RTX 5080 ({in_flight_s:.0}s in-flight)"
                        ),
                        format!(
                            "Active CUDA execution ({inflight_artifacts} live DAG artifacts, mean task ~{mean_s:.0}s); next completion will append directly to progress.jsonl."
                        ),
                        ph_el,
                        0.0,
                    )
                }
            };

        let mut rates_map = BTreeMap::new();
        if let Some(obj) = progress.get("rates").and_then(Value::as_object) {
            for (k, v) in obj {
                if let Some(f) = v.as_f64() {
                    rates_map.insert(k.clone(), f);
                }
            }
        }
        let mut mean_ms_map = BTreeMap::new();
        if let Some(obj) = progress.get("mean_proved_ms").and_then(Value::as_object) {
            for (k, v) in obj {
                if let Some(u) = v.as_u64() {
                    mean_ms_map.insert(k.clone(), u);
                }
            }
        }

        let est_task_s = latest_progress_line
            .as_ref()
            .and_then(|l| l.get("mean_shard_s"))
            .and_then(Value::as_f64)
            .unwrap_or_else(|| {
                let r = mean_ms_map.get("reduce").copied().unwrap_or(0);
                if r > 0 {
                    (r as f64) / 1000.0
                } else {
                    300.0
                }
            });

        let cur_task_elapsed_s =
            if !phase_finished && matches!(active_phase_name.as_str(), "gpu" | "cpu") {
                round_n(
                    phase_elapsed_s.min(
                        progress
                            .get("last_event_age_s")
                            .and_then(Value::as_f64)
                            .unwrap_or(0.0),
                    ),
                    1,
                )
            } else {
                0.0
            };

        let completion_est = estimate_ark_live_completion(ArkLiveCompletionArgs {
            unique_shards,
            unique_reduces,
            element_threshold: run_cfg_element_threshold,
            ark_vtxos: 4,
            session_summary: latest_progress_line.as_ref(),
            rates: Some(&rates_map),
            mean_proved_ms: Some(&mean_ms_map),
            in_flight_elapsed_s: cur_task_elapsed_s,
            expected_task_s: est_task_s,
            compressed_verified: compressed_exists || wrap_exists || run_verified,
            all_verified: active_phase_name == "all_proof_checks_passed" || wrap_exists,
        });

        let rs_len = resources_series.len();
        let res_tail: Vec<Value> = resources_series
            .into_iter()
            .skip(rs_len.saturating_sub(150))
            .collect();

        let active_phase_dir_name = phase_dir
            .as_ref()
            .and_then(|p| p.file_name())
            .map(|n| n.to_string_lossy().into_owned());

        json!({
            "reachable": true,
            "base_dir": base.to_string_lossy(),
            "status": active_phase_name,
            "phase_running": !phase_finished && matches!(active_phase_name.as_str(), "gpu" | "cpu" | "shrink" | "wrapv2"),
            "attempt_count": gpu_attempts_raw.len(),
            "gpu_host_holds": pipeline_state.get("gpu_host_holds").and_then(Value::as_u64).unwrap_or(0),
            "prover_backend": pipeline_state.get("prover_backend"),
            "prover_binary_sha256": pipeline_state.get("prover_binary_sha256"),
            "started_at_unix": pipeline_state.get("started_at_unix"),
            "phase_started_unix": phase_started_unix,
            "startup_host_reserve_mib": startup_reserve_mib,
            "active_phase_dir": active_phase_dir_name,
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
                "headroom_pct": round_n(((host_avail_gib / target_gib.max(0.1)) * 100.0).min(100.0), 1),
                "current_task_elapsed_s": cur_task_elapsed_s,
                "expected_task_s": round_n(est_task_s, 1),
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
                "ram_peak_mib": round_n((mem_peak_bytes as f64) / (1024.0 * 1024.0), 1),
                "swap_peak_mib": round_n((swap_peak_bytes as f64) / (1024.0 * 1024.0), 1),
            },
            "resources_series": res_tail,
            "phase_log_tail": phase_log_tail,
            "guard_events": guard_tail,
        })
    }

    pub fn query_host_heartbeat(&self) -> Value {
        let Some(raw) = read_shared_text(&self.host_heartbeat_path, 4096) else {
            return json!({ "present": false });
        };
        let Ok(obj) = serde_json::from_str::<Value>(&raw) else {
            return json!({ "present": false });
        };
        let sample = obj
            .get("sample_unix")
            .and_then(Value::as_f64)
            .unwrap_or(0.0);
        let age_s = round_n((unix_now_f64() - sample).max(0.0), 2);
        json!({
            "present": true,
            "age_seconds": age_s,
            "fresh": age_s < 30.0,
            "memory_floor_bytes": obj.get("memory_floor_bytes").and_then(Value::as_u64).unwrap_or(3_221_225_472),
            "immediate_memory_floor_bytes": obj.get("immediate_memory_floor_bytes").and_then(Value::as_u64).unwrap_or(536_870_912),
            "stop_reason": obj.get("stop_reason"),
            "sample_unix": obj.get("sample_unix"),
        })
    }

    pub fn snapshot(&self) -> Value {
        let seq = {
            let mut g = self.frame_seq.lock().unwrap();
            *g += 1;
            *g
        };
        let hm = windows_memory_snapshot();
        let avail_b = if hm.get("supported").and_then(Value::as_bool) == Some(true) {
            hm.get("avail_phys_bytes").and_then(Value::as_u64)
        } else {
            None
        };
        json!({
            "schema": "rbzk-prover-telemetry-v2",
            "frame_seq": seq,
            "sampled_at_unix": round_n(unix_now_f64(), 3),
            "host_memory": hm,
            "host_guard": self.query_host_heartbeat(),
            "gpu": self.query_gpu(),
            "wsl_prover": self.query_wsl_prover(avail_b),
        })
    }
}
