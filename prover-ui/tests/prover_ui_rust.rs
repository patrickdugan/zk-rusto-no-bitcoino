//! Unit, calibration, and HTTP/SSE security tests for the native Rust Prover UI.

use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::{BufRead, BufReader, Read, Write},
    net::TcpStream,
    sync::Arc,
    time::Duration,
};

use rbzk_prover_ui::{
    campaigns::load_campaigns,
    correlator::{
        circuit_basis_points, estimate_ark_live_completion, estimate_workload,
        ArkLiveCompletionArgs,
    },
    server::{start_server, ProverUIApp},
    telemetry::{parse_progress_log_line, strip_ansi, unix_now_f64, ProgressTailCache},
};
use serde_json::{json, Value};

#[test]
fn incremental_progress_cache_deduplicates_replays_and_parses_logs() {
    let tmp = std::env::temp_dir().join(format!("rbzk-ui-test-prog-{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp).unwrap();

    let prog = tmp.join("progress.jsonl");
    let now = unix_now_f64() as i64;
    fs::write(
        &prog,
        format!(
            "{}\n{}\n{}\n",
            json!({"key": "k1", "kind": "shard", "ms": 31000, "replayed": true, "t": now - 40}),
            json!({"key": "k2", "kind": "shard", "ms": 42000, "replayed": false, "t": now - 30}),
            json!({"key": "r1", "kind": "reduce", "ms": 51000, "replayed": false, "t": now - 20}),
        ),
    )
    .unwrap();

    let cache = ProgressTailCache::new();
    let first = cache.read(&prog);
    assert_eq!(first["unique_shards"], 2);
    assert_eq!(first["unique_reduces"], 1);
    assert_eq!(first["total_rows"], 3);

    {
        let mut fh = OpenOptions::new().append(true).open(&prog).unwrap();
        writeln!(
            fh,
            "{}",
            json!({"key": "k1", "kind": "shard", "ms": 5, "replayed": true, "t": now - 10})
        )
        .unwrap();
        writeln!(
            fh,
            "{}",
            json!({"key": "r2", "kind": "reduce", "ms": 48000, "replayed": false, "t": now - 5})
        )
        .unwrap();
    }

    let second = cache.read(&prog);
    assert_eq!(second["unique_shards"], 2);
    assert_eq!(second["unique_reduces"], 2);
    assert_eq!(second["total_rows"], 5);
    assert_eq!(second["replayed_rows_by_kind"]["shard"], 2);
    assert_eq!(second["proved_rows_by_kind"]["reduce"], 2);

    let cleaned = strip_ansi("\x1b[32mprogress 410s: shards proved 12 replayed 1131 (mean 41.5s), recursion proved 4 replayed 8, store 612 MiB\x1b[0m");
    let parsed = parse_progress_log_line(&cleaned).expect("parse progress log line");
    assert_eq!(parsed["elapsed_s"], 410);
    assert_eq!(parsed["session_shards_proved"], 12);
    assert_eq!(parsed["session_shards_replayed"], 1131);
    assert_eq!(parsed["mean_shard_s"], 41.5);
    assert_eq!(parsed["session_recursion_proved"], 4);
    assert_eq!(parsed["session_recursion_replayed"], 8);
    assert_eq!(parsed["artifact_store_mib"], 612);

    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn campaigns_bind_real_and_embedded_provenance_artifacts() {
    let data = load_campaigns(None);
    let camps = data["campaigns"].as_array().unwrap();
    let by_id: BTreeMap<&str, &Value> = camps
        .iter()
        .map(|c| (c["id"].as_str().unwrap(), c))
        .collect();

    assert!(by_id.contains_key("ark-cashu-live"));
    assert!(by_id.contains_key("m16-mainnet-pay"));
    assert!(by_id.contains_key("m18-mainnet-utxo"));
    assert!(by_id.contains_key("m17-shinigami-leaves"));
    assert!(by_id.contains_key("tn4-recursive-chain"));

    let m16 = by_id["m16-mainnet-pay"];
    assert_eq!(m16["summary_metrics"]["sp1_core_shards"], 13290);
    assert_eq!(m16["summary_metrics"]["sp1_recursion_shards"], 4430);
    assert_eq!(m16["summary_metrics"]["final_gates"], 785442492u64);
    assert_eq!(m16["payment_utxo"]["value_sats"], 940000);
    assert!(m16["pins"]["m16_statement_file_sha256"].is_string());

    let m18 = by_id["m18-mainnet-utxo"];
    let blocks = m18["blocks"].as_array().unwrap();
    let segs = m18["segments"].as_array().unwrap();
    assert_eq!(blocks.len(), 6);
    assert_eq!(segs.len(), 8);
    let total_steps: u64 = blocks
        .iter()
        .map(|b| b["nova_steps"].as_u64().unwrap())
        .sum();
    assert_eq!(total_steps, 224_790);
    assert_eq!(m18["utxo_map"]["final_leaves"], 74_593);
    assert_eq!(m18["utxo_map"]["pay1_leaf"]["index"], 8);
    assert_eq!(m18["utxo_map"]["pay1_leaf"]["leaf"]["spent"], false);
}

#[test]
fn correlator_matches_m16_baseline_and_completion_etas() {
    let m16_est = estimate_workload(&json!({
        "header_blocks": 975072,
        "nova_header_shards": 2,
        "utxo_window_blocks": 0,
        "payment_utxos": 1,
        "shinigami_leaves": 0,
        "ark_vtxos": 0,
        "element_threshold_exp": 27,
        "hardware_profile": "rtx5080_12gib",
    }))
    .unwrap();
    let core = m16_est["sp1"]["core_shards"].as_i64().unwrap();
    let rec = m16_est["sp1"]["recursion_shards"].as_i64().unwrap();
    assert!((core - 13_290).abs() <= 120, "got core={core}");
    assert!((rec - 4_430).abs() <= 50, "got rec={rec}");

    assert_eq!(circuit_basis_points(82_809), 147_456);
    assert_eq!(circuit_basis_points(19_113), 49_152);

    let session = json!({
        "session_shards_proved": 116,
        "session_shards_replayed": 1131,
        "session_recursion_proved": 169,
        "session_recursion_replayed": 236,
    });
    let mut rates = BTreeMap::new();
    rates.insert("shard_per_min_15m".into(), 2.4);

    let comp = estimate_ark_live_completion(ArkLiveCompletionArgs {
        unique_shards: 1247,
        unique_reduces: 1201,
        element_threshold: 67_108_864,
        ark_vtxos: 4,
        session_summary: Some(&session),
        rates: Some(&rates),
        mean_proved_ms: None,
        in_flight_elapsed_s: 0.0,
        expected_task_s: 95.0,
        compressed_verified: false,
        all_verified: false,
    });
    assert_eq!(comp["is_exact"], false);
    assert_eq!(comp["active_tree_reduce_done"], 405);
    assert_eq!(comp["regrouped_extra_reduces"], 796);
    let ct = comp["core_total_est"].as_u64().unwrap();
    assert!(ct > 5500 && ct < 7200);
    assert!(comp["sp1_eta_seconds"].as_f64().unwrap() > comp["core_eta_seconds"].as_f64().unwrap());
    assert!(comp["e2e_eta_seconds"].as_f64().unwrap() > comp["sp1_eta_seconds"].as_f64().unwrap());
}

fn raw_http_request(port: u16, req: &str) -> (u16, String) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream.write_all(req.as_bytes()).unwrap();
    stream.flush().unwrap();

    let mut resp = Vec::new();
    stream.read_to_end(&mut resp).unwrap();
    let text = String::from_utf8_lossy(&resp).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").unwrap();
    let status: u16 = head
        .lines()
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    (status, body.to_string())
}

#[test]
fn http_sse_endpoints_and_host_guard_work_end_to_end() {
    let root = std::env::temp_dir().join(format!("rbzk-ui-http-test-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    let prover_dir = root.join("prover-transient");
    let phase_dir = root.join("pipeline-gpu-100");
    fs::create_dir_all(&prover_dir).unwrap();
    fs::create_dir_all(&phase_dir).unwrap();

    fs::write(
        root.join("pipeline-status.json"),
        json!({
            "status": "gpu",
            "prover_backend": "CUDA test backend",
            "phases": {"gpu": phase_dir.to_string_lossy()},
        })
        .to_string(),
    )
    .unwrap();
    fs::write(
        prover_dir.join("progress.jsonl"),
        format!(
            "{}\n",
            json!({"key": "a1", "kind": "shard", "ms": 12000, "replayed": false, "t": unix_now_f64() as i64})
        ),
    )
    .unwrap();
    let hb = root.join("host.json");
    fs::write(
        &hb,
        json!({
            "schema": "ark-host-resources-v1",
            "sample_unix": unix_now_f64(),
            "memory_floor_bytes": 3221225472u64,
            "immediate_memory_floor_bytes": 536870912u64,
            "stop_reason": null,
        })
        .to_string(),
    )
    .unwrap();

    let app = Arc::new(ProverUIApp::new(
        Some(root.clone()),
        Some(hb),
        Some(root.join("pipe.log")),
        None,
    ));
    let mut srv = start_server("127.0.0.1", 0, app).unwrap();
    let port = srv.addr.port();

    let (st_root, html) = raw_http_request(
        port,
        &format!("GET / HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n"),
    );
    assert_eq!(st_root, 200);
    assert!(html.contains("zk-rusto-no-bitcoino"));

    let (st_live, live_str) = raw_http_request(
        port,
        &format!("GET /api/live HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n"),
    );
    assert_eq!(st_live, 200);
    let live: Value = serde_json::from_str(&live_str).unwrap();
    assert_eq!(live["wsl_prover"]["progress"]["unique_shards"], 1);
    assert_eq!(live["host_guard"]["fresh"], true);

    // Verify immediate SSE frame on /api/stream
    {
        let mut sse_stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
        sse_stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        write!(
            sse_stream,
            "GET /api/stream HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n"
        )
        .unwrap();
        let mut rdr = BufReader::new(sse_stream);
        let mut line = String::new();
        loop {
            line.clear();
            rdr.read_line(&mut line).unwrap();
            if line == "\r\n" {
                break;
            }
        }
        let mut ev_line = String::new();
        let mut data_line = String::new();
        rdr.read_line(&mut ev_line).unwrap();
        rdr.read_line(&mut data_line).unwrap();
        assert_eq!(ev_line.trim(), "event: telemetry");
        assert!(data_line.starts_with("data: "));
        let sse_val: Value = serde_json::from_str(&data_line["data: ".len()..]).unwrap();
        assert_eq!(sse_val["wsl_prover"]["progress"]["unique_shards"], 1);
    }

    let post_body = r#"{"header_blocks":975072,"nova_header_shards":2,"payment_utxos":1}"#;
    let (st_corr, corr_str) = raw_http_request(
        port,
        &format!(
            "POST /api/correlate HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{post_body}",
            post_body.len()
        ),
    );
    assert_eq!(st_corr, 200);
    let corr: Value = serde_json::from_str(&corr_str).unwrap();
    assert!(corr["sp1"]["core_shards"].as_u64().unwrap() > 13_000);

    // Non-loopback Host header must be rejected with 403
    let (st_evil, _) = raw_http_request(
        port,
        "GET /api/live HTTP/1.1\r\nHost: evil.example.com\r\n\r\n",
    );
    assert_eq!(st_evil, 403);

    srv.shutdown();
    let _ = fs::remove_dir_all(&root);
}
