//! Unified CLI & Desktop Launcher (`rbzk-prover-ui`).
//!
//! Subcommands:
//! - `rbzk-prover-ui` / `rbzk-prover-ui desktop` -> Opens native desktop window + loopback server
//! - `rbzk-prover-ui serve`                      -> Runs headless loopback HTTP + 1s SSE server
//! - `rbzk-prover-ui status`                     -> Prints one live JSON telemetry snapshot
//! - `rbzk-prover-ui correlate`                  -> Estimates recursive shards & RAM/VRAM envelope

use std::{path::PathBuf, sync::Arc};

use anyhow::Result;
use rbzk_prover_ui::{
    correlator::estimate_workload,
    server::{start_server, ProverUIApp},
};
use serde_json::{Map, Value};

fn print_help() {
    println!(
        "\
ZK Rusto no Bitcoino · Native Rust Prover Console (v0.2.0)

USAGE:
  rbzk-prover-ui [SUBCOMMAND] [OPTIONS]

SUBCOMMANDS:
  desktop     Open the native desktop GUI window (default when compiled with `desktop` feature)
  serve       Run headless loopback HTTP + 1s SSE server (default port 8788)
  status      Print a single read-only live telemetry JSON snapshot
  correlate   Estimate recursive shards, R1CS basis, and RAM/VRAM from measured unit constants

COMMON OPTIONS:
  --host <ADDR>             Loopback bind address [default: 127.0.0.1]
  --port <PORT>             Loopback port [default: 8788]
  --wsl-run-dir <PATH>      Override WSL prover run directory
  --host-heartbeat <PATH>   Override Windows host guard heartbeat file
  --smoke-exit-ms <MS>      Auto-close desktop window after <MS> milliseconds (for CI smoke tests)

CORRELATE OPTIONS:
  --header-blocks <N>          [default: 975072]
  --nova-header-shards <N>     [default: 2]
  --utxo-window-blocks <N>     [default: 0]
  --avg-tx-per-block <N>       [default: 5449]
  --payment-utxos <N>          [default: 1]
  --shinigami-leaves <N>       [default: 0]
  --shinigami-script-type <S>  [default: p2wpkh]
  --ark-vtxos <N>              [default: 0]
  --element-threshold-exp <E>  25..28 [default: 27]
  --hardware-profile <P>       rtx5080_12gib | rtx5080_bounded_2gib | cpu_20t
"
    );
}

fn main() -> Result<()> {
    let raw_args: Vec<String> = std::env::args().skip(1).collect();
    if raw_args
        .iter()
        .any(|a| a == "-h" || a == "--help" || a == "help")
    {
        print_help();
        return Ok(());
    }

    let (cmd, rest) = match raw_args.first().map(String::as_str) {
        Some("desktop" | "serve" | "status" | "correlate") => {
            (raw_args[0].as_str(), &raw_args[1..])
        }
        Some(flag) if flag.starts_with('-') => {
            #[cfg(feature = "desktop")]
            {
                ("desktop", raw_args.as_slice())
            }
            #[cfg(not(feature = "desktop"))]
            {
                ("serve", raw_args.as_slice())
            }
        }
        None => {
            #[cfg(feature = "desktop")]
            {
                ("desktop", raw_args.as_slice())
            }
            #[cfg(not(feature = "desktop"))]
            {
                ("serve", raw_args.as_slice())
            }
        }
        Some(other) => {
            anyhow::bail!("unknown subcommand `{other}` (run with --help for usage)");
        }
    };

    let mut host = "127.0.0.1".to_string();
    let mut port: u16 = 8788;
    let mut wsl_run_dir: Option<PathBuf> = None;
    let mut host_heartbeat: Option<PathBuf> = None;
    let mut smoke_exit_ms: Option<u64> = None;
    let mut corr_map = Map::new();

    let mut i = 0;
    while i < rest.len() {
        let flag = rest[i].as_str();
        let next_val = rest.get(i + 1).cloned();
        match flag {
            "--host" => {
                if let Some(v) = next_val {
                    host = v;
                    i += 2;
                    continue;
                }
            }
            "--port" => {
                if let Some(v) = next_val {
                    port = v.parse::<u16>()?;
                    i += 2;
                    continue;
                }
            }
            "--wsl-run-dir" => {
                if let Some(v) = next_val {
                    wsl_run_dir = Some(PathBuf::from(v));
                    i += 2;
                    continue;
                }
            }
            "--host-heartbeat" => {
                if let Some(v) = next_val {
                    host_heartbeat = Some(PathBuf::from(v));
                    i += 2;
                    continue;
                }
            }
            "--smoke-exit-ms" => {
                if let Some(v) = next_val {
                    smoke_exit_ms = Some(v.parse::<u64>()?);
                    i += 2;
                    continue;
                }
            }
            _ if flag.starts_with("--") => {
                let key = flag.trim_start_matches("--").replace('-', "_");
                if let Some(v) = next_val {
                    corr_map.insert(key, Value::String(v));
                    i += 2;
                    continue;
                }
            }
            _ => {}
        }
        i += 1;
    }

    match cmd {
        "status" => {
            let app = ProverUIApp::new(wsl_run_dir, host_heartbeat, None, None);
            println!("{}", serde_json::to_string_pretty(&app.live_payload())?);
        }
        "correlate" => {
            let res =
                estimate_workload(&Value::Object(corr_map)).map_err(|e| anyhow::anyhow!(e))?;
            println!("{}", serde_json::to_string_pretty(&res)?);
        }
        "serve" => {
            let app = Arc::new(ProverUIApp::new(wsl_run_dir, host_heartbeat, None, None));
            let mut srv = start_server(&host, port, app)?;
            println!(
                "ZK Rusto no Bitcoino · Rust Prover UI listening at {}",
                srv.url()
            );
            srv.wait_forever();
        }
        "desktop" => {
            #[cfg(feature = "desktop")]
            {
                rbzk_prover_ui::desktop::run_desktop(
                    rbzk_prover_ui::desktop::DesktopLaunchOptions {
                        host,
                        preferred_port: port,
                        wsl_run_dir,
                        host_heartbeat,
                        smoke_exit_ms,
                    },
                )?;
            }
            #[cfg(not(feature = "desktop"))]
            {
                let _ = smoke_exit_ms;
                anyhow::bail!("compiled without `desktop` feature; use `serve` subcommand instead");
            }
        }
        _ => unreachable!(),
    }
    Ok(())
}
