//! Embedded Loopback HTTP/1.1 + 1s SSE Telemetry Server (`std::net::TcpListener`).
//!
//! Bakes `web/index.html`, `web/styles.css`, `web/app.js`, and `web/icon.svg` directly
//! into the compiled Rust binary so the desktop executable runs with zero external files.

use std::{
    collections::HashMap,
    io::{BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Condvar, Mutex,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use anyhow::{Context, Result};
use serde_json::{json, Map, Value};

use crate::{
    campaigns::load_campaigns, correlator::estimate_workload, telemetry::TelemetryCollector,
};

const EMBED_INDEX_HTML: &[u8] = include_bytes!("../web/index.html");
const EMBED_STYLES_CSS: &[u8] = include_bytes!("../web/styles.css");
const EMBED_APP_JS: &[u8] = include_bytes!("../web/app.js");
const EMBED_ICON_SVG: &[u8] = include_bytes!("../web/icon.svg");
const EMBED_MECHA_ICON_WEBP: &[u8] = include_bytes!("../web/mecha-icon.webp");
const EMBED_MECHA_HERO_WEBP: &[u8] = include_bytes!("../web/mecha-hero.webp");
const EMBED_MECHA_REACTOR_WEBP: &[u8] = include_bytes!("../web/mecha-reactor.webp");

const CSP_HEADER: &str = "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'";

pub struct ProverUIApp {
    pub telemetry: TelemetryCollector,
    ark_dir: Option<PathBuf>,
    runtime: crate::runtime::RuntimeCollector,
    runpod: crate::runtime::RuntimeCollector,
    hyperstack_snapshot: Option<PathBuf>,
    hyperstack_ark_state: Option<PathBuf>,
    hyperstack_ark_seed: Option<PathBuf>,
    stop_flag: AtomicBool,
    stop_cv: (Mutex<bool>, Condvar),
}

impl ProverUIApp {
    pub fn new(
        wsl_ark_base: Option<PathBuf>,
        host_heartbeat_path: Option<PathBuf>,
        pipeline_log_path: Option<PathBuf>,
        ark_dir: Option<PathBuf>,
    ) -> Self {
        Self {
            telemetry: TelemetryCollector::new(
                wsl_ark_base,
                host_heartbeat_path,
                pipeline_log_path,
            ),
            ark_dir,
            runtime: crate::runtime::RuntimeCollector::new(),
            runpod: crate::runtime::RuntimeCollector::runpod(),
            hyperstack_snapshot: std::env::var_os("RBZK_HYPERSTACK_BENCHMARK_JSON")
                .map(PathBuf::from),
            hyperstack_ark_state: std::env::var_os("RBZK_HYPERSTACK_ARK_STATE_JSON").map(PathBuf::from),
            hyperstack_ark_seed: std::env::var_os("RBZK_HYPERSTACK_ARK_SEED_JOURNAL").map(PathBuf::from),
            stop_flag: AtomicBool::new(false),
            stop_cv: (Mutex::new(false), Condvar::new()),
        }
    }

    pub fn is_stopped(&self) -> bool {
        self.stop_flag.load(Ordering::Acquire)
    }

    pub fn signal_stop(&self) {
        self.stop_flag.store(true, Ordering::Release);
        let (lock, cv) = &self.stop_cv;
        if let Ok(mut stopped) = lock.lock() {
            *stopped = true;
            cv.notify_all();
        }
    }

    /// Waits up to `dur`, returning `true` immediately if shutdown was requested.
    pub fn wait_or_stop(&self, dur: Duration) -> bool {
        if self.is_stopped() {
            return true;
        }
        let (lock, cv) = &self.stop_cv;
        let Ok(guard) = lock.lock() else {
            return true;
        };
        if *guard {
            return true;
        }
        let Ok((guard_after, _)) = cv.wait_timeout(guard, dur) else {
            return true;
        };
        *guard_after || self.is_stopped()
    }

    pub fn live_payload(&self) -> Value {
        let runtime = self.runtime.snapshot();
        if runtime["fresh"] == true {
            if let Some(path) = runtime["ark_progress_path"].as_str() {
                self.telemetry.observe_progress_path(path);
            }
        }
        let mut live = self.telemetry.snapshot();
        let ark_running = runtime["fresh"] == true
            && runtime["ark_processes"]
                .as_array()
                .is_some_and(|p| !p.is_empty());
        let wsl = &mut live["wsl_prover"];
        if runtime["fresh"] == true {
            if let Some(path) = runtime["ark_progress_path"].as_str() {
                wsl["progress_source"] = json!(path);
            }
        }
        wsl["phase_running"] = json!(ark_running);
        wsl["artifact_presence_is_verification"] = json!(false);
        wsl["completion"] = Value::Null;
        wsl["limits"] = Value::Null;
        wsl["liveness"] = json!({"mode":if ark_running {"process_observed"} else {"inactive"}});
        // Preserve Carbon's incremental shard counters as cache history. Never
        // turn a stale pipeline-status.json or an output filename into liveness.
        if !ark_running {
            wsl["status"] = json!(if runtime["fresh"] == true {
                "inactive"
            } else {
                "unknown"
            });
            wsl["liveness"] =
                json!({"mode":"inactive", "headline":"No live Ark SP1 process observed"});
            wsl["completion"] = Value::Null;
        }
        live["runtime"] = runtime;
        live["cloud_runpod"] = self.runpod.snapshot();
        live["cloud_hyperstack_ark"] = self
            .hyperstack_ark_state
            .as_deref()
            .and_then(|path| read_hyperstack_ark_state(path, self.hyperstack_ark_seed.as_deref()))
            .unwrap_or(Value::Null);
        live["cloud_hyperstack"] = self
            .hyperstack_snapshot
            .as_deref()
            .and_then(read_hyperstack_snapshot)
            .unwrap_or(Value::Null);
        live
    }

    pub fn campaigns_payload(&self) -> Value {
        load_campaigns(self.ark_dir.as_deref())
    }
}

fn read_seed_progress(path: &Path) -> Option<(u64, usize, u64)> {
    let file = std::fs::File::open(path).ok()?;
    let meta = file.metadata().ok()?;
    if !meta.is_file() || meta.len() > 2_000_000 {
        return None;
    }
    let stamp = meta.modified().ok()?.duration_since(std::time::UNIX_EPOCH).ok()?.as_secs();
    let mut bytes = Vec::new();
    file.take(2_000_001).read_to_end(&mut bytes).ok()?;
    if bytes.len() > 2_000_000 {
        return None;
    }
    let parts = bytes.split(|byte| *byte == b'\n').filter_map(|line| {
        let entry: Value = serde_json::from_slice(line).ok()?;
        entry["bytes"].as_u64().filter(|bytes| (1..=4194304).contains(bytes))
    });
    let (total, count) = parts.fold((0, 0), |(sum, count), part| (sum + part, count + 1));
    Some((total, count, stamp))
}

fn read_hyperstack_ark_state(path: &Path, journal: Option<&Path>) -> Option<Value> {
    let (raw, file_time) = read_bounded_cloud_state(path)?;
    let suffix = raw["name"].as_str()?.strip_prefix("ark-mnr04-a100-")?;
    if suffix.len() != 10 || !suffix.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let stage = raw["stage"].as_str()?;
    let Some(vm_id) = raw["vm_id"].as_u64().filter(|id| *id > 0) else {
        let phase = match stage {
            "private_transport_ready" => "staging",
            "overnight_staged" | "overnight_requested" => "queued",
            "overnight_waiting_stock" => "waiting_stock",
            _ => return None,
        };
        let (bytes, count, stamp) = journal.and_then(read_seed_progress).unwrap_or((0, 0, file_time));
        return Some(json!({
            "stage": phase, "sampled_at_unix": file_time.max(stamp), "active": true,
            "seed_bytes": bytes, "seed_parts": count,
        }));
    };
    let started = raw["requested_at"].as_u64()?;
    let mut sample = json!({
        "vm_id": vm_id,
        "started_at_unix": started,
        "sampled_at_unix": file_time,
        "active": true,
        "stage": "starting",
    });
    if let Some(end) = raw["lease_ends_at_unix"].as_u64()
        .filter(|end| *end > started && *end - started <= 8 * 3600)
    {
        sample["lease_ends_at_unix"] = json!(end);
    }
    sample["spot"] = raw["spot"].clone();
    if raw["cleanup"] == "vm_deleted" {
        sample["active"] = json!(false);
        sample["stage"] = json!("stopped");
    } else if stage.starts_with("ark_heartbeat|") {
        let fields: Vec<_> = stage.split('|').collect();
        let ["ark_heartbeat", stamp, phase, progress, core, recursion, replay_core, replay_recursion, vram, ark, nova] =
            fields.as_slice()
        else {
            return None;
        };
        if !matches!(*phase, "starting" | "replay" | "shard" | "reduce" | "stopped") {
            return None;
        }
        let stamp: u64 = stamp.parse().ok()?;
        let progress: u64 = progress.parse().ok()?;
        if stamp < started || (progress != 0 && !(started..=stamp.saturating_add(2)).contains(&progress)) {
            return None;
        }
        let parse_counter = |text: &str| text.parse::<u64>().ok().filter(|v| *v <= 100_000_000);
        let parse_bit = |text: &str| match text {
            "0" => Some(false),
            "1" => Some(true),
            _ => None,
        };
        sample["sampled_at_unix"] = json!(stamp);
        sample["stage"] = json!(phase);
        sample["last_checkpoint_at_unix"] = json!(progress);
        sample["core_new"] = json!(parse_counter(core)?);
        sample["recursion_new"] = json!(parse_counter(recursion)?);
        sample["core_replayed"] = json!(parse_counter(replay_core)?);
        sample["recursion_replayed"] = json!(parse_counter(replay_recursion)?);
        sample["vram_used_mib"] = json!(parse_counter(vram)?);
        sample["ark_running"] = json!(parse_bit(ark)?);
        sample["nova_running"] = json!(parse_bit(nova)?);
    } else {
        sample["stage"] = json!(match stage {
            "storage_vm_provisioned" => "provisioning",
            "preparing_inputs" => "preparing",
            "parallel_ark_and_mnr04" | "ark_overnight" => "starting",
            "finished" | "results_retrieved" => "returning",
            "failed" => "failed",
            _ => return None,
        });
    }
    Some(sample)
}

fn read_bounded_cloud_state(path: &Path) -> Option<(Value, u64)> {
    let file = std::fs::File::open(path).ok()?;
    let metadata = file.metadata().ok()?;
    if !metadata.is_file() {
        return None;
    }
    const MAX_BYTES: u64 = 4096;
    let mut bytes = Vec::new();
    file.take(MAX_BYTES + 1).read_to_end(&mut bytes).ok()?;
    if bytes.len() as u64 > MAX_BYTES {
        return None;
    }
    let modified = metadata.modified().ok()?.duration_since(std::time::UNIX_EPOCH).ok()?.as_secs();
    Some((serde_json::from_slice(&bytes).ok()?, modified))
}

fn read_hyperstack_snapshot(path: &Path) -> Option<Value> {
    let (raw, _) = read_bounded_cloud_state(path)?;
    if raw["schema"] != "rbzk/hyperstack-benchmark/v1" || raw["vm_id"].as_u64()? == 0 {
        return None;
    }
    let active = raw["active"].as_bool()?;
    let stage = raw["stage"].as_str()?;
    let terminal = match stage {
        "verified" | "failed" | "cleanup_unconfirmed" => true,
        "provisioning"
        | "booted"
        | "benchmark_started"
        | "benchmark_running"
        | "started"
        | "execute"
        | "prove"
        | "verify"
        | "reject_changed_anchor_amount"
        | "reject_changed_commitment"
        | "fresh_proof_independently_verified"
        | "retrieving"
        | "local_verification" => false,
        _ => return None,
    };
    if terminal == active || raw["sampled_at_unix"].as_u64()? < raw["started_at_unix"].as_u64()? {
        return None;
    }
    let mut result = json!({
        "vm_id": raw["vm_id"], "stage": stage, "active": active,
        "sampled_at_unix": raw["sampled_at_unix"], "started_at_unix": raw["started_at_unix"],
        "a100_confirmed": raw["a100_confirmed"] == true,
    });
    for key in [
        "rate_usd_per_hour",
        "logical_cpus",
        "threads",
        "host_ram_gib",
        "host_ram_used_gib",
        "prove_seconds",
        "peak_prove_ram_gib",
    ] {
        if raw[key].as_f64().is_some_and(|value| value >= 0.0) {
            result[key] = raw[key].clone();
        }
    }
    Some(result)
}

#[cfg(test)]
mod hyperstack_tests {
    use super::*;

    #[test]
    fn ark_seed_transfer_has_progress_without_allocating_a_vm() -> Result<()> {
        let root = std::env::temp_dir();
        let state = root.join(format!("rbzk-seed-state-{}.json", std::process::id()));
        let progress = root.join(format!("rbzk-seed-parts-{}.jsonl", std::process::id()));
        std::fs::write(&state, serde_json::to_vec(&json!({
            "name": "ark-mnr04-a100-123abcdef0", "stage": "private_transport_ready", "vm_id": null
        }))?)?;
        std::fs::write(&progress, b"{\"bytes\":4194304}\n{\"bytes\":1234}\n{\"bytes\":")?;
        let sample = read_hyperstack_ark_state(&state, Some(&progress))
            .context("valid staging state was discarded");
        std::fs::remove_file(state)?;
        std::fs::remove_file(progress)?;
        let sample = sample?;
        assert_eq!(sample["stage"], "staging");
        assert_eq!(sample["seed_bytes"], 4195538);
        assert_eq!(sample["seed_parts"], 2);
        assert!(sample.get("vm_id").is_none());
        Ok(())
    }

    #[test]
    fn ark_cloud_state_checks_heartbeat_and_ended_vm() -> Result<()> {
        let path = std::env::temp_dir().join(format!("rbzk-ark-cloud-{}.json", std::process::id()));
        let mut state = json!({
            "name": "ark-mnr04-a100-123abcdef0", "vm_id": 456, "requested_at": 900,
            "stage": "ark_heartbeat|1000|shard|999|5|3|18|20|8192|1|0",
            "storage_key_id": 8,
        });
        std::fs::write(&path, serde_json::to_vec(&state)?)?;
        let live = read_hyperstack_ark_state(&path, None).context("valid Ark heartbeat was discarded")?;
        assert_eq!(live["core_new"], 5);
        assert_eq!(live["core_replayed"], 18);
        assert_eq!(live["sampled_at_unix"], 1000);
        assert_eq!(live["ark_running"], true);
        assert!(live.get("storage_key_id").is_none());

        state["stage"] = json!("ark_heartbeat|899|shard|999|5|3|18|20|8192|1|0");
        std::fs::write(&path, serde_json::to_vec(&state)?)?;
        assert!(read_hyperstack_ark_state(&path, None).is_none());

        state["cleanup"] = json!("vm_deleted");
        std::fs::write(&path, serde_json::to_vec(&state)?)?;
        let ended = read_hyperstack_ark_state(&path, None).context("ended pilot state was discarded")?;
        std::fs::remove_file(path)?;
        assert_eq!(ended["active"], false);
        assert_eq!(ended["stage"], "stopped");
        Ok(())
    }

    #[test]
    fn publishes_only_recognized_benchmark_fields() -> Result<()> {
        let path =
            std::env::temp_dir().join(format!("rbzk-hyperstack-{}.json", std::process::id()));
        let mut snapshot = json!({
            "schema": "rbzk/hyperstack-benchmark/v1", "vm_id": 123, "stage": "prove",
            "active": true, "sampled_at_unix": 1000, "started_at_unix": 900,
            "threads": 16, "host_ram_gib": "invalid", "private_field": "discarded",
        });
        std::fs::write(&path, serde_json::to_vec(&snapshot)?)?;
        let published = read_hyperstack_snapshot(&path).context("valid benchmark was rejected");
        snapshot["stage"] = json!("verified");
        std::fs::write(&path, serde_json::to_vec(&snapshot)?)?;
        let contradictory = read_hyperstack_snapshot(&path);
        std::fs::remove_file(path)?;
        let published = published?;
        assert_eq!(published["threads"], 16);
        assert!(published.get("host_ram_gib").is_none());
        assert!(published.get("private_field").is_none());
        assert!(contradictory.is_none());
        Ok(())
    }
}

pub struct RunningServer {
    pub addr: SocketAddr,
    pub app: Arc<ProverUIApp>,
    accept_handle: Option<JoinHandle<()>>,
}

impl RunningServer {
    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    pub fn shutdown(&mut self) {
        self.app.signal_stop();
        // Nudge blocking `accept()` with a quick loopback connect
        let _ = TcpStream::connect_timeout(&self.addr, Duration::from_millis(80));
        if let Some(h) = self.accept_handle.take() {
            let _ = h.join();
        }
    }

    pub fn wait_forever(&mut self) {
        if let Some(h) = self.accept_handle.take() {
            let _ = h.join();
        }
    }
}

impl Drop for RunningServer {
    fn drop(&mut self) {
        self.shutdown();
    }
}

pub fn start_server(host: &str, port: u16, app: Arc<ProverUIApp>) -> Result<RunningServer> {
    let listener =
        TcpListener::bind((host, port)).with_context(|| format!("bind {host}:{port}"))?;
    let addr = listener.local_addr()?;
    let app_clone = Arc::clone(&app);

    let accept_handle = thread::Builder::new()
        .name("rbzk-http-accept".into())
        .spawn(move || {
            for incoming in listener.incoming() {
                if app_clone.is_stopped() {
                    break;
                }
                if let Ok(stream) = incoming {
                    let conn_app = Arc::clone(&app_clone);
                    let _ = thread::Builder::new()
                        .name("rbzk-http-conn".into())
                        .spawn(move || {
                            let _ = handle_connection(stream, conn_app);
                        });
                }
            }
        })?;

    Ok(RunningServer {
        addr,
        app,
        accept_handle: Some(accept_handle),
    })
}

fn is_loopback_host(host_header: Option<&str>) -> bool {
    let Some(raw) = host_header else {
        return true;
    };
    let trimmed = raw.trim().to_ascii_lowercase();
    if trimmed.is_empty() {
        return true;
    }
    let host_only = if trimmed.starts_with('[') {
        trimmed
            .find(']')
            .map(|idx| &trimmed[..=idx])
            .unwrap_or(trimmed.as_str())
    } else {
        trimmed.split(':').next().unwrap_or("")
    };
    matches!(host_only, "127.0.0.1" | "localhost" | "[::1]" | "::1" | "")
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'+' {
            out.push(b' ');
            i += 1;
        } else if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(hex_str) = std::str::from_utf8(&bytes[i + 1..i + 3]) {
                if let Ok(val) = u8::from_str_radix(hex_str, 16) {
                    out.push(val);
                    i += 3;
                    continue;
                }
            }
            out.push(bytes[i]);
            i += 1;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn parse_query_to_json(query: &str) -> Value {
    let mut map = Map::new();
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = match pair.split_once('=') {
            Some((k, v)) => (percent_decode(k), percent_decode(v)),
            None => (percent_decode(pair), String::new()),
        };
        if !k.is_empty() {
            map.insert(k, Value::String(v));
        }
    }
    Value::Object(map)
}

fn send_json(stream: &mut TcpStream, status: u16, reason: &str, payload: &Value) -> Result<()> {
    let mut body = serde_json::to_vec(payload)?;
    body.push(b'\n');
    let header = format!(
        "HTTP/1.1 {status} {reason}\r\nServer: RBZKProverUI-Rust/0.2\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(&body)?;
    stream.flush()?;
    Ok(())
}

fn send_static(stream: &mut TcpStream, content_type: &str, body: &[u8]) -> Result<()> {
    let header = format!(
        "HTTP/1.1 200 OK\r\nServer: RBZKProverUI-Rust/0.2\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-cache\r\nX-Content-Type-Options: nosniff\r\nContent-Security-Policy: {CSP_HEADER}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()?;
    Ok(())
}

fn resolve_static_asset(route: &str) -> Option<(&'static str, Vec<u8>)> {
    let (file_name, content_type, embedded) = match route {
        "/" | "/index.html" => ("index.html", "text/html; charset=utf-8", EMBED_INDEX_HTML),
        "/styles.css" => ("styles.css", "text/css; charset=utf-8", EMBED_STYLES_CSS),
        "/app.js" => (
            "app.js",
            "application/javascript; charset=utf-8",
            EMBED_APP_JS,
        ),
        "/icon.svg" => ("icon.svg", "image/svg+xml", EMBED_ICON_SVG),
        "/mecha-icon.webp" => ("mecha-icon.webp", "image/webp", EMBED_MECHA_ICON_WEBP),
        "/mecha-hero.webp" => ("mecha-hero.webp", "image/webp", EMBED_MECHA_HERO_WEBP),
        "/mecha-reactor.webp" => ("mecha-reactor.webp", "image/webp", EMBED_MECHA_REACTOR_WEBP),
        _ => return None,
    };

    if let Some(dev_dir) = std::env::var_os("RBZK_PROVER_UI_DEV_WEB") {
        let base = if dev_dir == "1" {
            PathBuf::from("web")
        } else {
            PathBuf::from(dev_dir)
        };
        if let Ok(disk_bytes) = std::fs::read(base.join(file_name)) {
            return Some((content_type, disk_bytes));
        }
    }
    Some((content_type, embedded.to_vec()))
}

fn serve_sse(mut stream: TcpStream, app: Arc<ProverUIApp>) -> Result<()> {
    let _ = stream.set_nodelay(true);
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
    let header = "HTTP/1.1 200 OK\r\nServer: RBZKProverUI-Rust/0.2\r\nContent-Type: text/event-stream; charset=utf-8\r\nCache-Control: no-cache, no-store\r\nConnection: keep-alive\r\nX-Content-Type-Options: nosniff\r\n\r\n";
    stream.write_all(header.as_bytes())?;
    stream.flush()?;

    while !app.is_stopped() {
        let snap = app.live_payload();
        let data = serde_json::to_string(&snap)?;
        let frame = format!("event: telemetry\ndata: {data}\n\n");
        if stream.write_all(frame.as_bytes()).is_err() || stream.flush().is_err() {
            break;
        }
        if app.wait_or_stop(Duration::from_secs(1)) {
            break;
        }
    }
    Ok(())
}

fn handle_connection(mut stream: TcpStream, app: Arc<ProverUIApp>) -> Result<()> {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let mut reader = BufReader::new(stream.try_clone()?);

    let mut request_line = String::new();
    if reader.read_line(&mut request_line)? == 0 {
        return Ok(());
    }
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        return Ok(());
    }
    let method = parts[0];
    let full_target = parts[1];

    let mut headers: HashMap<String, String> = HashMap::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
        }
        if let Some((k, v)) = trimmed.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
        if headers.len() > 64 {
            break;
        }
    }

    if !is_loopback_host(headers.get("host").map(String::as_str)) {
        return send_json(
            &mut stream,
            403,
            "Forbidden",
            &json!({ "error": "invalid_host" }),
        );
    }

    let (route, query) = match full_target.split_once('?') {
        Some((r, q)) => (r, q),
        None => (full_target, ""),
    };

    match method {
        "GET" => {
            if let Some((ctype, bytes)) = resolve_static_asset(route) {
                return send_static(&mut stream, ctype, &bytes);
            }
            match route {
                "/api/health" => send_json(
                    &mut stream,
                    200,
                    "OK",
                    &json!({ "ok": true, "service": "rbzk-prover-ui", "runtime": "rust-desktop" }),
                ),
                "/api/stream" => serve_sse(stream, app),
                "/api/live" => send_json(&mut stream, 200, "OK", &app.live_payload()),
                "/api/campaigns" => send_json(&mut stream, 200, "OK", &app.campaigns_payload()),
                "/api/correlate" => {
                    let params = parse_query_to_json(query);
                    match estimate_workload(&params) {
                        Ok(res) => send_json(&mut stream, 200, "OK", &res),
                        Err(e) => {
                            send_json(&mut stream, 400, "Bad Request", &json!({ "error": e }))
                        }
                    }
                }
                _ => send_json(
                    &mut stream,
                    404,
                    "Not Found",
                    &json!({ "error": "not_found" }),
                ),
            }
        }
        "POST" => {
            if route != "/api/correlate" {
                return send_json(
                    &mut stream,
                    404,
                    "Not Found",
                    &json!({ "error": "not_found" }),
                );
            }
            let content_len = headers
                .get("content-length")
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(0);
            if content_len == 0 || content_len > 16_384 {
                return send_json(
                    &mut stream,
                    400,
                    "Bad Request",
                    &json!({ "error": "invalid_body_size" }),
                );
            }
            let mut body = vec![0u8; content_len];
            reader.read_exact(&mut body)?;
            let Ok(parsed) = serde_json::from_slice::<Value>(&body) else {
                return send_json(
                    &mut stream,
                    400,
                    "Bad Request",
                    &json!({ "error": "invalid_json" }),
                );
            };
            if !parsed.is_object() {
                return send_json(
                    &mut stream,
                    400,
                    "Bad Request",
                    &json!({ "error": "JSON object required" }),
                );
            }
            match estimate_workload(&parsed) {
                Ok(res) => send_json(&mut stream, 200, "OK", &res),
                Err(e) => send_json(&mut stream, 400, "Bad Request", &json!({ "error": e })),
            }
        }
        _ => send_json(
            &mut stream,
            405,
            "Method Not Allowed",
            &json!({ "error": "method_not_allowed" }),
        ),
    }
}
