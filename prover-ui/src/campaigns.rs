//! Runtime artifact inventory. No embedded results or synthetic campaign totals.
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    time::UNIX_EPOCH,
};

fn default_ark_dir() -> PathBuf {
    if let Some(p) = std::env::var_os("RBZK_ARK_DIR") {
        return p.into();
    }
    let home = std::env::var_os("USERPROFILE").or_else(|| std::env::var_os("HOME"));
    PathBuf::from(home.unwrap_or_default())
        .join("Documents/Codex/2026-11-15/new-chat/outputs/zk-rusto-no-bitcoino-ark/Ark")
}

pub fn load_campaigns(ark_dir: Option<&Path>) -> Value {
    let base = ark_dir
        .map(Path::to_path_buf)
        .unwrap_or_else(default_ark_dir);
    let root = base.join("results");
    let mut records = Vec::new();
    let mut files: Vec<_> = fs::read_dir(&root)
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .collect();
    files.sort();
    for path in files.into_iter().take(64) {
        let Ok(file) = fs::File::open(&path) else {
            continue;
        };
        let mut raw = Vec::new();
        if file.take(2_097_153).read_to_end(&mut raw).is_err() || raw.len() > 2_097_152 {
            continue;
        }
        let Ok(data) = serde_json::from_slice::<Value>(&raw) else {
            continue;
        };
        let mut summary = Map::new();
        for key in [
            "schema",
            "status",
            "network",
            "verified",
            "stark_verified",
            "new_mint_funding",
            "full_ark_sp1_bitvm3_complete",
            "proof_sha256",
            "proof_bytes",
        ] {
            if let Some(v) = data.get(key).filter(|v| !v.is_array() && !v.is_object()) {
                summary.insert(key.into(), v.clone());
            }
        }
        let modified = fs::metadata(&path)
            .ok()
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|t| t.as_secs_f64());
        records.push(json!({"id": path.to_string_lossy(), "title": path.file_name().unwrap_or_default().to_string_lossy(),
            "path": path.to_string_lossy(), "sha256": hex::encode(Sha256::digest(&raw)),
            "bytes":raw.len(), "modified_at_unix":modified, "kind":"recorded evidence", "summary":summary}));
    }
    json!({"schema":"rbzk-artifact-inventory-v1", "sampled_at_unix":crate::telemetry::unix_now_f64(),
           "root":root.to_string_lossy(), "available":root.is_dir(), "campaigns":records})
}
