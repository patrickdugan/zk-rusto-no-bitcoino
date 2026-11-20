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

/// Renders a crisp 32×32 RGBA window & taskbar icon matching `web/icon.svg`
/// (obsidian badge + cyan/violet/amber concentric recursive shard rings).
fn build_app_icon() -> Option<Icon> {
    const W: u32 = 32;
    const H: u32 = 32;
    let mut rgba = vec![0u8; (W * H * 4) as usize];
    let cx = 15.5f32;
    let cy = 15.5f32;

    for y in 0..H {
        for x in 0..W {
            let fx = x as f32;
            let fy = y as f32;
            // Rounded square mask (radius 6px)
            let dx_box = (fx - cx).abs() - 9.5;
            let dy_box = (fy - cy).abs() - 9.5;
            let box_dist = (dx_box.max(0.0).powi(2) + dy_box.max(0.0).powi(2)).sqrt()
                + dx_box.max(dy_box).min(0.0);
            if box_dist > 6.0 {
                continue;
            }
            let edge_alpha = (6.3 - box_dist).clamp(0.0, 1.0);

            let dist = ((fx - cx).powi(2) + (fy - cy).powi(2)).sqrt();
            // Base obsidian background (#0b101b)
            let mut r = 11.0f32;
            let mut g = 16.0f32;
            let mut b = 27.0f32;

            // Outer cyan ring (`r ≈ 11.2`, #38bdf8)
            let d_outer = (dist - 11.2).abs();
            if d_outer < 1.5 {
                let t = (1.5 - d_outer) / 1.5;
                r = r * (1.0 - t) + 56.0 * t;
                g = g * (1.0 - t) + 189.0 * t;
                b = b * (1.0 - t) + 248.0 * t;
            }
            // Middle violet recursion ring (`r ≈ 7.2`, #a78bfa)
            let d_mid = (dist - 7.2).abs();
            if d_mid < 1.35 {
                let t = (1.35 - d_mid) / 1.35;
                r = r * (1.0 - t) + 167.0 * t;
                g = g * (1.0 - t) + 139.0 * t;
                b = b * (1.0 - t) + 250.0 * t;
            }
            // Inner amber core shard (`r <= 3.3`, #fbbf24)
            if dist < 3.5 {
                let t = ((3.5 - dist) / 1.4).clamp(0.0, 1.0);
                r = r * (1.0 - t) + 251.0 * t;
                g = g * (1.0 - t) + 191.0 * t;
                b = b * (1.0 - t) + 36.0 * t;
            }

            let idx = ((y * W + x) * 4) as usize;
            rgba[idx] = r.round().clamp(0.0, 255.0) as u8;
            rgba[idx + 1] = g.round().clamp(0.0, 255.0) as u8;
            rgba[idx + 2] = b.round().clamp(0.0, 255.0) as u8;
            rgba[idx + 3] = (edge_alpha * 255.0).round() as u8;
        }
    }
    Icon::from_rgba(rgba, W, H).ok()
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
