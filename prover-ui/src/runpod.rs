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
}
