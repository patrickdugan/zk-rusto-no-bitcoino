//! Bounded background observations; stale files never imply a running prover.
use crate::telemetry::unix_now_f64;
use serde_json::{json, Value};
use std::{
    fs,
    io::{Read, Write},
    path::PathBuf,
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};

const PROBE: &str = include_str!("live_probe.py");

pub struct RuntimeCollector {
    state: Arc<Mutex<Value>>,
    stop: Arc<AtomicBool>,
}

impl Default for RuntimeCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl RuntimeCollector {
    pub fn new() -> Self {
        let state = Arc::new(Mutex::new(
            json!({"reachable": false, "status": "connecting", "jobs": []}),
        ));
        let stop = Arc::new(AtomicBool::new(false));
        let (shared, stopping) = (state.clone(), stop.clone());
        let _ = thread::Builder::new()
            .name("rbzk-runtime".into())
            .spawn(move || {
                while !stopping.load(Ordering::Acquire) {
                    let result = probe().unwrap_or_else(
                        || json!({"reachable":false,"status":"unavailable","jobs":[]}),
                    );
                    if let Ok(mut cache) = shared.lock() {
                        *cache = result;
                    }
                    for _ in 0..30 {
                        if stopping.load(Ordering::Acquire) {
                            return;
                        }
                        thread::sleep(Duration::from_millis(100));
                    }
                }
            });
        Self { state, stop }
    }

    pub fn snapshot(&self) -> Value {
        let mut value = self
            .state
            .lock()
            .map(|v| v.clone())
            .unwrap_or_else(|_| json!({}));
        let age = value["sampled_at_unix"]
            .as_f64()
            .filter(|t| *t <= unix_now_f64() + 2.0)
            .map(|t| (unix_now_f64() - t).max(0.0));
        let fresh = value["reachable"] == true && age.is_some_and(|a| a <= 15.0);
        value["age_seconds"] = json!(age);
        value["fresh"] = json!(fresh);
        if !fresh {
            if let Some(jobs) = value["jobs"].as_array_mut() {
                for job in jobs {
                    job["running"] = json!(false);
                    job["status"] = json!("stale / unknown");
                }
            }
        }
        value
    }
}

impl Drop for RuntimeCollector {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
    }
}

fn probe() -> Option<Value> {
    let config = std::env::var_os("RBZK_LIVE_CONFIG")
        .and_then(|p| {
            let p = PathBuf::from(p);
            (fs::metadata(&p).ok()?.len() <= 65536).then_some(())?;
            serde_json::from_slice::<Value>(&fs::read(p).ok()?).ok()
        })
        .unwrap_or_else(|| json!({}));
    #[cfg(windows)]
    let mut cmd = {
        use std::os::windows::process::CommandExt;
        let mut c = Command::new("wsl.exe");
        c.args([
            "-d",
            "Ubuntu-24.04",
            "-u",
            "root",
            "--",
            "python3",
            "-c",
            PROBE,
        ]);
        c.creation_flags(0x0800_0000);
        c
    };
    #[cfg(not(windows))]
    let mut cmd = {
        let mut c = Command::new("python3");
        c.args(["-c", PROBE]);
        c
    };
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    child
        .stdin
        .take()?
        .write_all(config.to_string().as_bytes())
        .ok()?;
    // Drain concurrently: a Windows anonymous pipe can be smaller than one JSON sample.
    let stdout = child.stdout.take()?;
    let reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout.take(65537).read_to_end(&mut bytes).ok()?;
        (bytes.len() <= 65536).then_some(bytes)
    });
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if !status.success() {
                    return None;
                }
                return serde_json::from_slice(&reader.join().ok()??).ok();
            }
            Ok(None) if start.elapsed() < Duration::from_secs(12) => {
                thread::sleep(Duration::from_millis(50))
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
}
