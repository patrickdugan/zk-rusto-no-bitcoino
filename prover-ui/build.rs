//! Embeds `assets/icon.ico` into Windows `.exe` PE resources via Windows SDK `rc.exe`.

use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

fn find_windows_rc() -> Option<PathBuf> {
    if let Ok(status) = Command::new("rc.exe").arg("/?").output() {
        if status.status.success() || !status.stdout.is_empty() || !status.stderr.is_empty() {
            return Some(PathBuf::from("rc.exe"));
        }
    }
    let kits_bin = Path::new(r"C:\Program Files (x86)\Windows Kits\10\bin");
    let Ok(entries) = fs::read_dir(kits_bin) else {
        return None;
    };
    let mut candidates: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|e| e.path().join("x64").join("rc.exe"))
        .filter(|p| p.exists())
        .collect();
    candidates.sort();
    candidates.pop()
}

fn main() {
    println!("cargo:rerun-if-changed=assets/app.rc");
    println!("cargo:rerun-if-changed=assets/icon.ico");

    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_env = env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    if target_os != "windows" || target_env != "msvc" {
        return;
    }

    let Some(rc_exe) = find_windows_rc() else {
        println!("cargo:warning=Windows SDK rc.exe not found; skipping PE icon embedding");
        return;
    };

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let res_file = out_dir.join("rbzk_app_icon.res");
    let rc_file = manifest_dir.join("assets").join("app.rc");

    let status = Command::new(rc_exe)
        .arg("/nologo")
        .arg("/fo")
        .arg(&res_file)
        .arg(&rc_file)
        .current_dir(manifest_dir.join("assets"))
        .status()
        .expect("invoke rc.exe");

    assert!(status.success(), "rc.exe failed to compile assets/app.rc");
    println!("cargo:rustc-link-arg-bins={}", res_file.display());
}
