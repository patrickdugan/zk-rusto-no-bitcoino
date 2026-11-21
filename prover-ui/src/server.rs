//! Embedded Loopback HTTP/1.1 + 1s SSE Telemetry Server (`std::net::TcpListener`).
//!
//! Bakes `web/index.html`, `web/styles.css`, `web/app.js`, and `web/icon.svg` directly
//! into the compiled Rust binary so the desktop executable runs with zero external files.

use std::{
    collections::HashMap,
    io::{BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::PathBuf,
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
    campaigns_base: Value,
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
        let campaigns_base = load_campaigns(ark_dir.as_deref());
        Self {
            telemetry: TelemetryCollector::new(
                wsl_ark_base,
                host_heartbeat_path,
                pipeline_log_path,
            ),
            campaigns_base,
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
        self.telemetry.snapshot()
    }

    pub fn campaigns_payload(&self) -> Value {
        let mut data = self.campaigns_base.clone();
        let wsl = self.telemetry.query_wsl_prover(None);
        let prog = wsl.get("progress");
        let comp = wsl.get("completion");

        let unique_shards = prog
            .and_then(|p| p.get("unique_shards"))
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let unique_reduces = prog
            .and_then(|p| p.get("unique_reduces"))
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let core_total_est = comp
            .and_then(|c| c.get("core_total_est"))
            .cloned()
            .unwrap_or(Value::Null);
        let is_exact = comp
            .and_then(|c| c.get("is_exact"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let active_reduce = comp
            .and_then(|c| c.get("active_tree_reduce_done"))
            .and_then(Value::as_u64)
            .unwrap_or(unique_reduces);
        let reduce_total_est = comp
            .and_then(|c| c.get("reduce_total_est"))
            .cloned()
            .unwrap_or(Value::Null);
        let overall_pct = comp
            .and_then(|c| c.get("overall_pct"))
            .cloned()
            .unwrap_or(Value::Null);
        let compressed_exists = wsl
            .get("compressed_exists")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let wrap_exists = wsl
            .get("wrap_v2_exists")
            .and_then(Value::as_bool)
            .unwrap_or(false);

        if let Some(arr) = data.get_mut("campaigns").and_then(Value::as_array_mut) {
            for camp in arr {
                if camp.get("id").and_then(Value::as_str) == Some("ark-cashu-live") {
                    if let Some(sm) = camp
                        .get_mut("summary_metrics")
                        .and_then(Value::as_object_mut)
                    {
                        sm.insert("sp1_core_shards".into(), json!(unique_shards));
                        sm.insert("sp1_core_shards_total".into(), core_total_est.clone());
                        sm.insert("sp1_core_shards_is_est".into(), json!(!is_exact));
                        sm.insert("sp1_recursion_shards".into(), json!(active_reduce));
                        sm.insert("sp1_recursion_memo_total".into(), json!(unique_reduces));
                        sm.insert(
                            "sp1_recursion_shards_total".into(),
                            reduce_total_est.clone(),
                        );
                        sm.insert("completion_pct".into(), overall_pct.clone());
                    }
                    if let Some(stages) = camp
                        .get_mut("pipeline_stages")
                        .and_then(Value::as_array_mut)
                    {
                        if compressed_exists && stages.len() > 3 {
                            stages[3]["state"] = json!("verified");
                        }
                        if wrap_exists && stages.len() > 4 {
                            stages[4]["state"] = json!("verified");
                        }
                    }
                }
            }
        }
        data
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
