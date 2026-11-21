//! Native Desktop Window Shell (`tao` + `wry` WebView2 / WebKit) for `rbzk-prover-ui`.

use std::{
    path::PathBuf,
    process::Command,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use tao::{
    dpi::LogicalSize,
    event::{Event, WindowEvent},
    event_loop::{ControlFlow, EventLoop},
    window::{Icon, Theme, WindowBuilder},
};
use wry::{WebContext, WebViewBuilder};

use crate::server::{start_server, ProverUIApp};

#[derive(Debug, Clone)]
pub struct DesktopLaunchOptions {
    pub host: String,
    pub preferred_port: u16,
    pub wsl_run_dir: Option<PathBuf>,
    pub host_heartbeat: Option<PathBuf>,
    pub smoke_exit_ms: Option<u64>,
}

impl Default for DesktopLaunchOptions {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".into(),
            preferred_port: 8788,
            wsl_run_dir: None,
            host_heartbeat: None,
            smoke_exit_ms: None,
        }
    }
}

const EMBED_ICON_32_RGBA: &[u8] = include_bytes!("../assets/icon-32.rgba");

/// Loads the supersampled 32×32 RGBA window & taskbar icon matching `assets/icon.ico` / `web/icon.svg`.
fn build_app_icon() -> Option<Icon> {
    Icon::from_rgba(EMBED_ICON_32_RGBA.to_vec(), 32, 32).ok()
}

fn webview_data_dir() -> PathBuf {
    #[cfg(windows)]
    {
        if let Some(local) = std::env::var_os("LOCALAPPDATA") {
            return PathBuf::from(local)
                .join("rbzk-prover-ui")
                .join("webview2-profile");
        }
    }
    std::env::temp_dir().join("rbzk-prover-ui-webview")
}

fn open_external_url(url: &str) {
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        return;
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        let _ = Command::new("rundll32.exe")
            .args(["url.dll,FileProtocolHandler", url])
            .creation_flags(0x0800_0000)
            .spawn();
    }
    #[cfg(target_os = "macos")]
    {
        let _ = Command::new("open").arg(url).spawn();
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let _ = Command::new("xdg-open").arg(url).spawn();
    }
}

pub fn run_desktop(opts: DesktopLaunchOptions) -> Result<()> {
    let app = Arc::new(ProverUIApp::new(
        opts.wsl_run_dir.clone(),
        opts.host_heartbeat.clone(),
        None,
        None,
    ));

    // Bind preferred port (`8788` by default so external browser tabs on `:8788` also connect),
    // falling back seamlessly to an ephemeral loopback port if `8788` is already occupied.
    let mut server = match start_server(&opts.host, opts.preferred_port, Arc::clone(&app)) {
        Ok(srv) => srv,
        Err(_) => start_server(&opts.host, 0, Arc::clone(&app))
            .context("bind ephemeral loopback port for desktop UI")?,
    };
    let app_url = server.url();
    let allowed_prefix_ip = format!("http://127.0.0.1:{}", server.addr.port());
    let allowed_prefix_lh = format!("http://localhost:{}", server.addr.port());

    let event_loop = EventLoop::new();
    let window = WindowBuilder::new()
        .with_title("ZK Rusto no Bitcoino · Prover & Recursive Shard Console")
        .with_inner_size(LogicalSize::new(1480.0, 940.0))
        .with_min_inner_size(LogicalSize::new(980.0, 640.0))
        .with_theme(Some(Theme::Dark))
        .with_window_icon(build_app_icon())
        .build(&event_loop)
        .context("create native desktop window")?;

    let data_dir = webview_data_dir();
    let _ = std::fs::create_dir_all(&data_dir);
    let mut web_context = WebContext::new(Some(data_dir));

    let nav_ip = allowed_prefix_ip.clone();
    let nav_lh = allowed_prefix_lh.clone();
    let _webview = WebViewBuilder::with_web_context(&mut web_context)
        .with_url(&app_url)
        .with_background_color((10, 14, 23, 255))
        .with_devtools(true)
        .with_navigation_handler(move |uri: String| {
            if uri.starts_with(&nav_ip) || uri.starts_with(&nav_lh) || uri == "about:blank" {
                true
            } else {
                open_external_url(&uri);
                false
            }
        })
        .with_new_window_req_handler(|uri: String| {
            open_external_url(&uri);
            false
        })
        .build(&window)
        .context("initialize native WebView engine")?;

    let smoke_deadline = opts
        .smoke_exit_ms
        .map(|ms| Instant::now() + Duration::from_millis(ms));

    event_loop.run(move |event, _, control_flow| {
        if let Some(deadline) = smoke_deadline {
            if Instant::now() >= deadline {
                server.shutdown();
                *control_flow = ControlFlow::Exit;
                return;
            }
            *control_flow = ControlFlow::WaitUntil(deadline);
        } else {
            *control_flow = ControlFlow::Wait;
        }

        if let Event::WindowEvent {
            event: WindowEvent::CloseRequested,
            ..
        } = event
        {
            server.shutdown();
            *control_flow = ControlFlow::Exit;
        }
    });
}
