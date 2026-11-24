//! Read-only cloud Pod telemetry. Credentials remain on the native host.

use serde_json::{json, Value};
use std::{
    env, fs,
    io::{Read, Write},
    path::PathBuf,
    process::{Command, Stdio},
};

use crate::telemetry::unix_now_f64;

const RUNPOD_ENDPOINT: &str = "https://api.runpod.io/graphql";
const PRIME_ENDPOINT: &str = "https://api.primeintellect.ai/api/v1/pods/";
const HYPERSTACK_API_BASE: &str = "https://infrahub-api.nexgencloud.com/v1";
const PODS_QUERY: &str = "query DesktopPodTelemetry { myself { pods {
    id name desiredStatus machine { gpuDisplayName }
    runtime { uptimeInSeconds gpus { gpuUtilPercent memoryUtilPercent }
    container { cpuPercent memoryPercent } } } } }";
const RESPONSE_LIMIT: u64 = 262_144;

fn home_directory() -> Option<PathBuf> {
    env::var_os("USERPROFILE")
        .or_else(|| env::var_os("HOME"))
        .map(PathBuf::from)
}

fn validate_key(value: &str) -> Option<String> {
    let trimmed = value.trim();
    ((16..=512).contains(&trimmed.len())
        && trimmed
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.:+/=".contains(&b)))
    .then(|| trimmed.to_owned())
}

fn runpod_credential() -> Option<String> {
    env::var("RUNPOD_API_KEY")
        .ok()
        .and_then(|key| validate_key(&key))
        .or_else(|| {
            let explicit_path = env::var_os("RBZK_RUNPOD_API_KEY_FILE").map(PathBuf::from);
            let path = explicit_path
                .or_else(|| home_directory().map(|home| home.join(".runpod").join("api-key")))?;
            let mut content = String::new();
            fs::File::open(path)
                .ok()?
                .take(1025)
                .read_to_string(&mut content)
                .ok()?;
            if content.len() > 1024 {
                return None;
            }
            validate_key(&content)
        })
}

fn prime_credential() -> Option<String> {
    env::var("PRIME_API_KEY")
        .ok()
        .and_then(|key| validate_key(&key))
        .or_else(|| {
            let path = home_directory()?.join(".prime").join("config.json");
            let mut content = String::new();
            fs::File::open(path)
                .ok()?
                .take(16385)
                .read_to_string(&mut content)
                .ok()?;
            if content.len() > 16384 {
                return None;
            }
            let config: Value = serde_json::from_str(&content).ok()?;
            validate_key(config["api_key"].as_str()?)
        })
}

fn state(status: &str, authenticated: bool) -> Value {
    json!({"status":status,"authenticated":authenticated,"reachable":authenticated,
           "sampled_at_unix":unix_now_f64(),"provider":"Runpod"})
}

fn prime_state(status: &str, authenticated: bool) -> Value {
    let mut result = state(status, authenticated);
    result["provider"] = json!("Prime Intellect");
    result
}

fn gpu_name(pod: &Value) -> Option<&str> {
    pod["machine"]["gpuDisplayName"]
        .as_str()
        .filter(|name| !name.trim().is_empty())
}

fn running_gpu_pod(pod: &Value) -> bool {
    pod["desiredStatus"] == "RUNNING"
        && pod["id"].as_str().is_some_and(|id| !id.is_empty())
        && gpu_name(pod).is_some()
        && pod["runtime"]["uptimeInSeconds"]
            .as_u64()
            .is_some_and(|uptime| uptime > 0)
        && pod["runtime"]["gpus"]
            .as_array()
            .is_some_and(|gpus| !gpus.is_empty())
}

fn percent(value: &Value) -> Option<f64> {
    value.as_f64().filter(|n| (0.0..=100.0).contains(n))
}

fn display_snapshot(response: &Value, selected: Option<&str>) -> Value {
    if response["errors"]
        .as_array()
        .is_some_and(|errors| !errors.is_empty())
    {
        return state("unavailable", false);
    }
    let Some(pods) = response["data"]["myself"]["pods"].as_array() else {
        return state("unavailable", false);
    };
    let pod = if let Some(id) = selected {
        match pods.iter().find(|pod| pod["id"].as_str() == Some(id)) {
            Some(pod) if running_gpu_pod(pod) => pod,
            _ => return state("pod_not_running", true),
        }
    } else {
        let mut candidates = pods.iter().filter(|pod| running_gpu_pod(pod));
        match (candidates.next(), candidates.next()) {
            (Some(pod), None) => pod,
            (Some(_), Some(_)) => return state("multiple_pods", true),
            _ => return state("no_running_pod", true),
        }
    };

    let runtime = &pod["runtime"];
    let average = |field: &str| {
        let values: Vec<_> = runtime["gpus"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|gpu| percent(&gpu[field]))
            .collect();
        (!values.is_empty()).then(|| values.iter().sum::<f64>() / values.len() as f64)
    };
    let mut result = state("running", true);
    result["pod"] = json!({
        "id":pod["id"], "name":pod["name"].as_str().unwrap_or("Runpod Pod"),
        "gpu_name":gpu_name(pod), "desired_status":"RUNNING",
    });
    result["metrics"] = json!({
        "gpu_util_percent":average("gpuUtilPercent"), "gpu_memory_percent":average("memoryUtilPercent"),
        "cpu_util_percent":percent(&runtime["container"]["cpuPercent"]),
        "mem_util_percent":percent(&runtime["container"]["memoryPercent"]),
        "uptime_seconds":runtime["uptimeInSeconds"].as_u64(),
    });
    result
}

fn request(key: &str, endpoint: &str, payload: Option<&str>) -> Option<(u16, Value)> {
    let mut command = Command::new(if cfg!(windows) { "curl.exe" } else { "curl" });
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000);
    }
    command
        .env_remove("RUNPOD_API_KEY")
        .env_remove("PRIME_API_KEY")
        .args([
            "--disable",
            "--silent",
            "--proto",
            "=https",
            "--connect-timeout",
            "3",
            "--max-time",
            "6",
            "--max-filesize",
            "262144",
            "--header",
            "@-",
            "--write-out",
            "\n%{http_code}",
            endpoint,
        ]);
    if let Some(body) = payload {
        command.args([
            "--header",
            "Content-Type: application/json",
            "--data-binary",
            body,
        ]);
    }
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let header = child
        .stdin
        .take()?
        .write_all(format!("Authorization: Bearer {key}\n").as_bytes());
    let output = child.wait_with_output().ok()?;
    if header.is_err()
        || !output.status.success()
        || output.stdout.len() as u64 > RESPONSE_LIMIT + 4
    {
        return None;
    }
    let (body, code) = std::str::from_utf8(&output.stdout)
        .ok()?
        .rsplit_once('\n')?;
    let status: u16 = code.parse().ok()?;
    let payload = if status == 200 {
        serde_json::from_str(body).ok()?
    } else {
        Value::Null
    };
    Some((status, payload))
}

fn poll_runpod(key: &str) -> Value {
    let query = json!({"query":PODS_QUERY}).to_string();
    match request(key, RUNPOD_ENDPOINT, Some(&query)) {
        Some((200, document)) => {
            let selected = env::var("RUNPOD_POD_ID").ok();
            display_snapshot(
                &document,
                selected
                    .as_deref()
                    .map(str::trim)
                    .filter(|id| !id.is_empty()),
            )
        }
        Some((401 | 403, _)) => state("unauthorized", false),
        _ => state("unavailable", false),
    }
}

fn running_prime_pod(pod: &Value) -> bool {
    matches!(
        pod["status"].as_str(),
        Some("ACTIVE" | "RUNNING" | "active" | "running")
    ) && pod["id"].as_str().is_some_and(|id| !id.is_empty())
        && pod["gpuCount"].as_u64().is_some_and(|count| count > 0)
        && pod["gpuName"]
            .as_str()
            .is_some_and(|name| !name.trim().is_empty())
}

fn prime_snapshot(document: &Value, explicit: bool) -> Value {
    let data = &document["data"];
    let pod = if explicit {
        if !running_prime_pod(data) {
            return prime_state("pod_not_running", true);
        }
        data
    } else {
        let Some(pods) = data.as_array() else {
            return prime_state("unavailable", false);
        };
        if document["total_count"]
            .as_u64()
            .is_some_and(|total| total > pods.len() as u64)
        {
            return prime_state("multiple_pods", true);
        }
        let mut candidates = pods.iter().filter(|pod| running_prime_pod(pod));
        match (candidates.next(), candidates.next()) {
            (Some(pod), None) => pod,
            (Some(_), Some(_)) => return prime_state("multiple_pods", true),
            _ => return prime_state("no_running_pod", true),
        }
    };
    let mut result = prime_state("running", true);
    result["pod"] = json!({
        "id":pod["id"], "name":pod["name"].as_str().unwrap_or("Prime Pod"),
        "gpu_name":pod["gpuName"], "desired_status":"RUNNING",
        "upstream_provider":pod["providerType"].as_str(),
    });
    result["metrics"] = json!({});
    result
}

fn poll_prime(key: &str) -> Value {
    let selected = env::var("PRIME_POD_ID").ok().filter(|id| {
        !id.is_empty()
            && id.len() <= 100
            && id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
    });
    let endpoint = selected.as_ref().map_or_else(
        || format!("{PRIME_ENDPOINT}?limit=50"),
        |id| format!("{PRIME_ENDPOINT}{id}"),
    );
    match request(key, &endpoint, None) {
        Some((200, document)) => prime_snapshot(&document, selected.is_some()),
        Some((404, _)) if selected.is_some() => prime_state("pod_not_running", true),
        Some((401 | 403, _)) => prime_state("unauthorized", false),
        _ => prime_state("unavailable", false),
    }
}

pub(crate) fn probe() -> Value {
    if let Some(key) = runpod_credential() {
        return poll_runpod(&key);
    }
    if let Some(key) = prime_credential() {
        return poll_prime(&key);
    }
    state("credentials_required", false)
}

fn read_key_file(path: &std::path::Path) -> Option<String> {
    let mut content = String::new();
    fs::File::open(path)
        .ok()?
        .take(1025)
        .read_to_string(&mut content)
        .ok()?;
    if content.len() > 1024 {
        return None;
    }
    let first = content
        .trim_start_matches('\u{feff}')
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())?;
    validate_key(first)
}

#[cfg(windows)]
fn desktop_directory() -> Option<PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    #[link(name = "shell32")]
    extern "system" {
        fn SHGetFolderPathW(
            hwnd: *mut core::ffi::c_void,
            csidl: i32,
            token: *mut core::ffi::c_void,
            flags: u32,
            path: *mut u16,
        ) -> i32;
    }
    const CSIDL_DESKTOPDIRECTORY: i32 = 0x0010;
    let mut buf = [0u16; 260];
    let hr = unsafe {
        SHGetFolderPathW(
            core::ptr::null_mut(),
            CSIDL_DESKTOPDIRECTORY,
            core::ptr::null_mut(),
            0,
            buf.as_mut_ptr(),
        )
    };
    if hr != 0 {
        return None;
    }
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    (len > 0).then(|| PathBuf::from(std::ffi::OsString::from_wide(&buf[..len])))
}

#[cfg(not(windows))]
fn desktop_directory() -> Option<PathBuf> {
    home_directory().map(|home| home.join("Desktop"))
}

fn hyperstack_credential() -> Option<String> {
    if let Ok(key) = env::var("HYPERSTACK_API_KEY") {
        if let Some(valid) = validate_key(&key) {
            return Some(valid);
        }
    }
    if let Some(explicit) = env::var_os("RBZK_HYPERSTACK_API_KEY_FILE") {
        if let Some(valid) = read_key_file(&PathBuf::from(explicit)) {
            return Some(valid);
        }
    }
    let mut candidates = Vec::new();
    if let Some(home) = home_directory() {
        candidates.push(home.join(".hyperstack").join("api-key"));
        candidates.push(home.join("Desktop").join("hyper.txt.txt"));
        candidates.push(home.join("Desktop").join("hyper.txt"));
    }
    if let Some(desktop) = desktop_directory() {
        candidates.push(desktop.join("hyper.txt.txt"));
        candidates.push(desktop.join("hyper.txt"));
    }
    for candidate in candidates {
        if let Some(valid) = read_key_file(&candidate) {
            return Some(valid);
        }
    }
    None
}

fn hyperstack_request(key: &str, path: &str) -> Option<(u16, Value)> {
    let endpoint = format!("{HYPERSTACK_API_BASE}/{path}");
    let mut command = Command::new(if cfg!(windows) { "curl.exe" } else { "curl" });
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000);
    }
    command
        .env_remove("HYPERSTACK_API_KEY")
        .env_remove("RUNPOD_API_KEY")
        .env_remove("PRIME_API_KEY")
        .args([
            "--disable",
            "--silent",
            "--proto",
            "=https",
            "--connect-timeout",
            "4",
            "--max-time",
            "8",
            "--max-filesize",
            "524288",
            "--header",
            "@-",
            "--header",
            "Accept: application/json",
            "--write-out",
            "\n%{http_code}",
            &endpoint,
        ]);
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let header = child
        .stdin
        .take()?
        .write_all(format!("api_key: {key}\n").as_bytes());
    let output = child.wait_with_output().ok()?;
    if header.is_err() || !output.status.success() || output.stdout.len() as u64 > 524_292 {
        return None;
    }
    let (body, code) = std::str::from_utf8(&output.stdout)
        .ok()?
        .rsplit_once('\n')?;
    let status: u16 = code.parse().ok()?;
    let payload = if status == 200 {
        serde_json::from_str(body).ok()?
    } else {
        Value::Null
    };
    Some((status, payload))
}

fn latest_metric_value(metrics_doc: &Value, key: &str) -> Option<f64> {
    let series = metrics_doc.get(key)?;
    let rows = series.get("data")?.as_array()?;
    for row in rows.iter().rev() {
        if let Some(arr) = row.as_array() {
            if let Some(val) = arr.last().and_then(Value::as_f64).filter(|v| v.is_finite()) {
                return Some(val);
            }
        } else if let Some(val) = row.as_f64().filter(|v| v.is_finite()) {
            return Some(val);
        }
    }
    None
}

fn parse_hyperstack_metrics(metrics_doc: &Value) -> Value {
    let mut out = serde_json::Map::new();
    if let Some(cpu) = latest_metric_value(metrics_doc, "cpu") {
        out.insert("cpu_percent".into(), json!(cpu));
    }
    if let Some(mem) = latest_metric_value(metrics_doc, "memory.usages") {
        let unit = metrics_doc["memory.usages"]["unit"]
            .as_str()
            .unwrap_or("")
            .to_ascii_lowercase();
        let mem_gib = if unit.contains("gib") || unit == "gb" {
            mem
        } else if unit.contains("mib") || unit == "mb" {
            mem / 1024.0
        } else if unit.contains("kib") || unit == "kb" {
            mem / (1024.0 * 1024.0)
        } else if mem > 10_000_000.0 {
            mem / 1_073_741_824.0
        } else if mem > 2048.0 {
            mem / 1024.0
        } else {
            mem
        };
        out.insert("memory_used_gib".into(), json!((mem_gib * 100.0).round() / 100.0));
    }
    if let Some(dr) = latest_metric_value(metrics_doc, "disk.read") {
        out.insert("disk_read".into(), json!(dr));
    }
    if let Some(dw) = latest_metric_value(metrics_doc, "disk.write") {
        out.insert("disk_write".into(), json!(dw));
    }
    Value::Object(out)
}

fn scrub_hyperstack_vm(vm: &Value, metrics: Option<Value>) -> Option<Value> {
    let id = vm["id"].as_u64().filter(|id| *id > 0)?;
    let name = vm["name"].as_str()?.trim();
    if name.is_empty() {
        return None;
    }
    let flavor = &vm["flavor"];
    let env_obj = &vm["environment"];
    let flavor_name = flavor["name"].as_str().unwrap_or("");
    let gpu = flavor["gpu"]
        .as_str()
        .filter(|s| !s.trim().is_empty() && !s.eq_ignore_ascii_case("none"))
        .map(str::to_owned);
    let gpu_count = flavor["gpu_count"].as_u64().unwrap_or(0);
    let spot = flavor["features"]["spot"].as_bool().unwrap_or_else(|| {
        flavor_name.to_ascii_lowercase().contains("spot")
    });
    let status = vm["status"].as_str().unwrap_or("UNKNOWN");
    let power_state = vm["power_state"].as_str();
    let vm_state = vm["vm_state"].as_str();
    let active = matches!(
        status.to_ascii_uppercase().as_str(),
        "ACTIVE" | "RUNNING" | "BUILD" | "CREATING" | "PROVISIONING" | "REBOOTING" | "STARTING"
    );

    Some(json!({
        "id": id,
        "name": name,
        "status": status,
        "active": active,
        "power_state": power_state,
        "vm_state": vm_state,
        "flavor": flavor_name,
        "gpu": gpu,
        "gpu_count": gpu_count,
        "cpu": flavor["cpu"].as_u64(),
        "ram_gib": flavor["ram"].as_f64(),
        "disk_gb": flavor["disk"].as_u64(),
        "region": env_obj["region"].as_str(),
        "environment": env_obj["name"].as_str(),
        "image": vm["image"]["name"].as_str(),
        "spot": spot,
        "created_at": vm["created_at"].as_str(),
        "labels": vm["labels"].as_array().map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .take(12)
                .collect::<Vec<_>>()
        }).unwrap_or_default(),
        "metrics": metrics.unwrap_or_else(|| json!({})),
    }))
}

fn hyperstack_inventory_snapshot(
    vms_doc: &Value,
    buckets_doc: Option<&Value>,
    metrics_by_id: &std::collections::HashMap<u64, Value>,
) -> Value {
    let instances: Vec<Value> = vms_doc["instances"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|vm| {
            let id = vm["id"].as_u64()?;
            scrub_hyperstack_vm(vm, metrics_by_id.get(&id).cloned())
        })
        .collect();

    let buckets: Vec<Value> = buckets_doc
        .and_then(|doc| doc["buckets"].as_array())
        .into_iter()
        .flatten()
        .filter_map(|b| {
            let name = b["name"].as_str()?;
            Some(json!({
                "name": name,
                "region": b["region"].as_str(),
                "num_objects": b["num_objects"].as_u64(),
                "size_bytes": b["size_bytes"].as_u64(),
                "created_at": b["created_at"].as_str(),
            }))
        })
        .collect();

    let running_count = instances.iter().filter(|vm| vm["active"] == true).count();
    let status = if running_count > 0 {
        "active"
    } else if !instances.is_empty() {
        "stopped"
    } else {
        "no_running_vm"
    };

    json!({
        "provider": "Hyperstack",
        "authenticated": true,
        "reachable": true,
        "status": status,
        "sampled_at_unix": unix_now_f64(),
        "running_count": running_count,
        "total_count": instances.len(),
        "instances": instances,
        "buckets": buckets,
    })
}

pub(crate) fn probe_hyperstack() -> Value {
    let Some(key) = hyperstack_credential() else {
        return json!({
            "provider": "Hyperstack",
            "authenticated": false,
            "reachable": false,
            "status": "credentials_required",
            "sampled_at_unix": unix_now_f64(),
            "running_count": 0,
            "total_count": 0,
            "instances": [],
            "buckets": [],
        });
    };

    let vms_doc = match hyperstack_request(&key, "core/virtual-machines?page=1&pageSize=50") {
        Some((200, doc)) => doc,
        Some((401 | 403, _)) => {
            return json!({
                "provider": "Hyperstack",
                "authenticated": false,
                "reachable": false,
                "status": "unauthorized",
                "sampled_at_unix": unix_now_f64(),
                "running_count": 0,
                "total_count": 0,
                "instances": [],
                "buckets": [],
            });
        }
        _ => {
            return json!({
                "provider": "Hyperstack",
                "authenticated": true,
                "reachable": false,
                "status": "unavailable",
                "sampled_at_unix": unix_now_f64(),
                "running_count": 0,
                "total_count": 0,
                "instances": [],
                "buckets": [],
            });
        }
    };

    let mut metrics_by_id = std::collections::HashMap::new();
    if let Some(arr) = vms_doc["instances"].as_array() {
        for vm in arr
            .iter()
            .filter(|v| v["status"].as_str() == Some("ACTIVE"))
            .take(4)
        {
            if let Some(id) = vm["id"].as_u64() {
                if let Some((200, mdoc)) =
                    hyperstack_request(&key, &format!("core/virtual-machines/{id}/metrics"))
                {
                    metrics_by_id.insert(id, parse_hyperstack_metrics(&mdoc));
                }
            }
        }
    }

    let buckets_doc = hyperstack_request(&key, "object-storage/buckets")
        .and_then(|(code, doc)| (code == 200).then_some(doc));

    hyperstack_inventory_snapshot(&vms_doc, buckets_doc.as_ref(), &metrics_by_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pod(id: &str, status: &str) -> Value {
        json!({"id":id,"name":"Hopper pilot","desiredStatus":status,
               "machine":{"gpuDisplayName":"NVIDIA H100 80GB HBM3"},
               "runtime":{"uptimeInSeconds":40,
                          "gpus":[{"gpuUtilPercent":0,"memoryUtilPercent":30}],
                          "container":{"cpuPercent":17}}})
    }

    fn response(pods: Vec<Value>) -> Value {
        json!({"data":{"myself":{"pods":pods}}})
    }

    #[test]
    fn exposes_only_observed_running_pod_and_metrics() {
        let mut fixture = pod("gpu-1", "RUNNING");
        fixture["hidden"] = json!("unrelated credential");
        let snapshot = display_snapshot(&response(vec![fixture]), None);
        assert_eq!(snapshot["status"], "running");
        assert_eq!(snapshot["pod"]["id"], "gpu-1");
        assert_eq!(snapshot["metrics"]["gpu_util_percent"].as_f64(), Some(0.0));
        assert!(snapshot["metrics"]["mem_util_percent"].is_null());
        assert!(!snapshot.to_string().contains("unrelated credential"));
    }

    #[test]
    fn only_switches_for_a_confirmed_single_or_explicit_gpu_pod() {
        let multiple = response(vec![pod("a", "RUNNING"), pod("b", "RUNNING")]);
        assert_eq!(display_snapshot(&multiple, None)["status"], "multiple_pods");
        assert_eq!(display_snapshot(&multiple, Some("b"))["pod"]["id"], "b");
        assert_eq!(
            display_snapshot(&multiple, Some("missing"))["status"],
            "pod_not_running"
        );
        let mut pending = pod("starting", "RUNNING");
        pending["runtime"] = Value::Null;
        assert_eq!(
            display_snapshot(&response(vec![pending]), None)["status"],
            "no_running_pod"
        );
        assert_eq!(
            display_snapshot(&response(vec![pod("a", "EXITED")]), None)["status"],
            "no_running_pod"
        );
    }

    #[test]
    fn prime_status_reports_the_actual_provider_without_inventing_metrics() {
        let running = json!({"id":"prime-1","status":"ACTIVE","gpuName":"H100_80GB","gpuCount":1,
                             "providerType":"runpod","sshConnection":"private connection string"});
        let live = prime_snapshot(&json!({"data":[running.clone()],"total_count":1}), false);
        assert_eq!(live["provider"], "Prime Intellect");
        assert_eq!(live["pod"]["upstream_provider"], "runpod");
        assert_eq!(live["status"], "running");
        assert!(live["metrics"].as_object().unwrap().is_empty());
        assert!(!live.to_string().contains("private connection string"));
        assert_eq!(
            prime_snapshot(&json!({"data":[],"total_count":0}), false)["status"],
            "no_running_pod"
        );
        assert_eq!(
            prime_snapshot(&json!({"data":[running],"total_count":2}), false)["status"],
            "multiple_pods"
        );
    }

    #[test]
    fn hyperstack_inventory_discovers_named_nodes_and_redacts_network_secrets() {
        let vms = json!({
            "instances": [
                {
                    "id": 1180123,
                    "name": "cashu-shinigami-a100-live",
                    "status": "ACTIVE",
                    "power_state": "Running",
                    "vm_state": "active",
                    "floating_ip": "198.51.100.42",
                    "keypair": {"public_key": "ssh-ed25519 AAAA..."},
                    "flavor": {"name": "n3-A100x1-spot", "gpu": "A100-80G-PCIe", "gpu_count": 1, "cpu": 28, "ram": 118.0, "disk": 200},
                    "environment": {"name": "default-CANADA-1", "region": "CANADA-1"},
                    "image": {"name": "Ubuntu 24.04 CUDA 12.8"},
                    "created_at": "2026-11-23T22:20:00",
                    "labels": ["cashu", "prover"]
                }
            ]
        });
        let buckets = json!({
            "buckets": [
                {"name": "ark-mnr04-a100-a6e283d956", "region": "CANADA-1", "num_objects": 3855, "size_bytes": 17578195145u64}
            ]
        });
        let mut metrics = std::collections::HashMap::new();
        metrics.insert(
            1180123,
            parse_hyperstack_metrics(&json!({
                "cpu": {"unit": "%", "data": [[1700000000, 64.5]]},
                "memory.usages": {"unit": "MiB", "data": [[1700000000, 16384.0]]}
            })),
        );
        let snap = hyperstack_inventory_snapshot(&vms, Some(&buckets), &metrics);
        assert_eq!(snap["status"], "active");
        assert_eq!(snap["running_count"], 1);
        assert_eq!(snap["instances"][0]["name"], "cashu-shinigami-a100-live");
        assert_eq!(snap["instances"][0]["spot"], true);
        assert_eq!(snap["instances"][0]["metrics"]["cpu_percent"], 64.5);
        assert_eq!(snap["instances"][0]["metrics"]["memory_used_gib"], 16.0);
        assert_eq!(snap["buckets"][0]["num_objects"], 3855);
        assert!(!snap.to_string().contains("198.51.100.42"));
        assert!(!snap.to_string().contains("ssh-ed25519"));
    }
}
