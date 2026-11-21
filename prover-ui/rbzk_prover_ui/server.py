"""Loopback HTTP + SSE server for the ZK Rusto no Bitcoino Prover UI."""
from __future__ import annotations

from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import threading
import time
from typing import Any
from urllib.parse import parse_qs, urlparse

from .campaigns import load_campaigns
from .correlator import estimate_workload
from .telemetry import TelemetryCollector


WEB_DIR = Path(__file__).resolve().parents[1] / "web"

STATIC_FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/styles.css": ("styles.css", "text/css; charset=utf-8"),
    "/app.js": ("app.js", "application/javascript; charset=utf-8"),
    "/icon.svg": ("icon.svg", "image/svg+xml"),
    "/mecha-icon.webp": ("mecha-icon.webp", "image/webp"),
    "/mecha-hero.webp": ("mecha-hero.webp", "image/webp"),
    "/mecha-reactor.webp": ("mecha-reactor.webp", "image/webp"),
}


class ProverUIApp:
    def __init__(
        self,
        wsl_ark_base: Path | None = None,
        host_heartbeat_path: Path | None = None,
        pipeline_log_path: Path | None = None,
        ark_dir: Path | None = None,
    ) -> None:
        self.telemetry = TelemetryCollector(
            wsl_ark_base=wsl_ark_base,
            host_heartbeat_path=host_heartbeat_path,
            pipeline_log_path=pipeline_log_path,
        )
        self._ark_dir = ark_dir
        self._campaigns_base = load_campaigns(ark_dir=ark_dir)
        self.stop_event = threading.Event()

    def live_payload(self) -> dict[str, Any]:
        return self.telemetry.snapshot()

    def campaigns_payload(self) -> dict[str, Any]:
        data = json.loads(json.dumps(self._campaigns_base))
        wsl = self.telemetry.query_wsl_prover()
        prog = wsl.get("progress") or {}
        comp = wsl.get("completion") or {}
        for camp in data.get("campaigns", []):
            if camp.get("id") == "ark-cashu-live":
                sm = camp["summary_metrics"]
                sm["sp1_core_shards"] = prog.get("unique_shards", 0)
                sm["sp1_core_shards_total"] = comp.get("core_total_est")
                sm["sp1_core_shards_is_est"] = not bool(comp.get("is_exact", False))
                sm["sp1_recursion_shards"] = comp.get(
                    "active_tree_reduce_done", prog.get("unique_reduces", 0)
                )
                sm["sp1_recursion_memo_total"] = prog.get("unique_reduces", 0)
                sm["sp1_recursion_shards_total"] = comp.get("reduce_total_est")
                sm["completion_pct"] = comp.get("overall_pct")
                if wsl.get("compressed_exists"):
                    camp["pipeline_stages"][3]["state"] = "verified"
                if wsl.get("wrap_v2_exists"):
                    camp["pipeline_stages"][4]["state"] = "verified"
        return data


class StoppableThreadingHTTPServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, server_address: tuple[str, int], RequestHandlerClass: Any, ui_app: ProverUIApp) -> None:
        super().__init__(server_address, RequestHandlerClass)
        self.ui_app = ui_app

    def shutdown(self) -> None:
        self.ui_app.stop_event.set()
        super().shutdown()


def make_handler(app: ProverUIApp) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "RBZKProverUI/0.2"

        def log_message(self, fmt: str, *args: Any) -> None:
            return

        def _check_loopback_host(self) -> bool:
            host = (self.headers.get("Host") or "").split(":")[0].lower()
            return host in ("127.0.0.1", "localhost", "[::1]", "")

        def _send_json(self, payload: Any, status: int = HTTPStatus.OK) -> None:
            body = (json.dumps(payload, separators=(",", ":")) + "\n").encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

        def _send_static(self, filename: str, content_type: str) -> None:
            target = WEB_DIR / filename
            if not target.exists():
                self._send_json({"error": "not_found"}, HTTPStatus.NOT_FOUND)
                return
            body = target.read_bytes()
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-cache")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'",
            )
            self.end_headers()
            self.wfile.write(body)

        def _serve_sse(self) -> None:
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-cache, no-store")
            self.send_header("Connection", "keep-alive")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            try:
                while not app.stop_event.is_set():
                    snap = app.live_payload()
                    frame = f"event: telemetry\ndata: {json.dumps(snap, separators=(',', ':'))}\n\n"
                    self.wfile.write(frame.encode("utf-8"))
                    self.wfile.flush()
                    if app.stop_event.wait(1.0):
                        break
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, OSError):
                return

        def do_GET(self) -> None:
            if not self._check_loopback_host():
                self._send_json({"error": "invalid_host"}, HTTPStatus.FORBIDDEN)
                return

            parsed = urlparse(self.path)
            route = parsed.path

            if route in STATIC_FILES:
                fname, ctype = STATIC_FILES[route]
                self._send_static(fname, ctype)
                return

            if route == "/api/health":
                self._send_json({"ok": True, "service": "rbzk-prover-ui"})
                return

            if route == "/api/stream":
                self._serve_sse()
                return

            if route == "/api/live":
                self._send_json(app.live_payload())
                return

            if route == "/api/campaigns":
                self._send_json(app.campaigns_payload())
                return

            if route == "/api/correlate":
                qs = {k: v[-1] for k, v in parse_qs(parsed.query).items() if v}
                try:
                    self._send_json(estimate_workload(qs))
                except (ValueError, TypeError) as exc:
                    self._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
                return

            self._send_json({"error": "not_found"}, HTTPStatus.NOT_FOUND)

        def do_POST(self) -> None:
            if not self._check_loopback_host():
                self._send_json({"error": "invalid_host"}, HTTPStatus.FORBIDDEN)
                return

            parsed = urlparse(self.path)
            if parsed.path != "/api/correlate":
                self._send_json({"error": "not_found"}, HTTPStatus.NOT_FOUND)
                return

            try:
                length = int(self.headers.get("Content-Length") or "0")
            except ValueError:
                length = 0
            if length <= 0 or length > 16384:
                self._send_json({"error": "invalid_body_size"}, HTTPStatus.BAD_REQUEST)
                return
            try:
                raw = self.rfile.read(length)
                data = json.loads(raw.decode("utf-8"))
                if not isinstance(data, dict):
                    raise ValueError("JSON object required")
                self._send_json(estimate_workload(data))
            except (ValueError, TypeError) as exc:
                self._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)

    return Handler


def create_server(
    host: str = "127.0.0.1",
    port: int = 8788,
    app: ProverUIApp | None = None,
) -> ThreadingHTTPServer:
    ui_app = app or ProverUIApp()
    return StoppableThreadingHTTPServer((host, port), make_handler(ui_app), ui_app)
