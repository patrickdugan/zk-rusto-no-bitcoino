//! Pure-GUI Native Desktop Binary (`rbzk-prover-desktop.exe`).
//!
//! Uses `windows_subsystem = "windows"` so launching from Explorer / Start Menu / shortcut
//! opens the native dark desktop window directly with zero console window behind it.
#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

use std::path::PathBuf;

use rbzk_prover_ui::desktop::{run_desktop, DesktopLaunchOptions};

fn main() {
    let mut opts = DesktopLaunchOptions::default();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--host" => {
                if let Some(v) = args.next() {
                    opts.host = v;
                }
            }
            "--port" => {
                if let Some(v) = args.next().and_then(|s| s.parse::<u16>().ok()) {
                    opts.preferred_port = v;
                }
            }
            "--wsl-run-dir" => {
                opts.wsl_run_dir = args.next().map(PathBuf::from);
            }
            "--host-heartbeat" => {
                opts.host_heartbeat = args.next().map(PathBuf::from);
            }
            "--smoke-exit-ms" => {
                opts.smoke_exit_ms = args.next().and_then(|s| s.parse::<u64>().ok());
            }
            _ => {}
        }
    }

    if let Err(err) = run_desktop(opts) {
        eprintln!("rbzk-prover-desktop error: {err:#}");
        std::process::exit(1);
    }
}
