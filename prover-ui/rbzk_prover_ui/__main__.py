"""CLI entrypoint for ZK Rusto no Bitcoino Prover UI."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from .correlator import estimate_workload
from .server import ProverUIApp, create_server


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="rbzk_prover_ui",
        description="Telemetry & recursive-shard prover console for zk-rusto-no-bitcoino.",
    )
    sub = parser.add_subparsers(dest="cmd")

    serve_p = sub.add_parser("serve", help="Run loopback prover UI HTTP server")
    serve_p.add_argument("--host", default="127.0.0.1")
    serve_p.add_argument("--port", type=int, default=8788)
    serve_p.add_argument("--wsl-run-dir", type=Path, default=None)
    serve_p.add_argument("--host-heartbeat", type=Path, default=None)

    status_p = sub.add_parser("status", help="Print one read-only live telemetry JSON snapshot")
    status_p.add_argument("--wsl-run-dir", type=Path, default=None)

    corr_p = sub.add_parser("correlate", help="Estimate recursive shards and RAM/VRAM for a workload")
    corr_p.add_argument("--header-blocks", type=int, default=975072)
    corr_p.add_argument("--nova-header-shards", type=int, default=2)
    corr_p.add_argument("--utxo-window-blocks", type=int, default=0)
    corr_p.add_argument("--payment-utxos", type=int, default=1)
    corr_p.add_argument("--shinigami-leaves", type=int, default=0)
    corr_p.add_argument("--shinigami-script-type", default="p2wpkh")
    corr_p.add_argument("--ark-vtxos", type=int, default=0)
    corr_p.add_argument("--element-threshold-exp", type=int, default=27)
    corr_p.add_argument("--hardware-profile", default="rtx5080_12gib")

    args = parser.parse_args()
    cmd = args.cmd or "serve"

    if cmd == "status":
        app = ProverUIApp(wsl_ark_base=args.wsl_run_dir)
        print(json.dumps(app.live_payload(), indent=2))
        return

    if cmd == "correlate":
        res = estimate_workload(
            {
                "header_blocks": args.header_blocks,
                "nova_header_shards": args.nova_header_shards,
                "utxo_window_blocks": args.utxo_window_blocks,
                "payment_utxos": args.payment_utxos,
                "shinigami_leaves": args.shinigami_leaves,
                "shinigami_script_type": args.shinigami_script_type,
                "ark_vtxos": args.ark_vtxos,
                "element_threshold_exp": args.element_threshold_exp,
                "hardware_profile": args.hardware_profile,
            }
        )
        print(json.dumps(res, indent=2))
        return

    app = ProverUIApp(
        wsl_ark_base=getattr(args, "wsl_run_dir", None),
        host_heartbeat_path=getattr(args, "host_heartbeat", None),
    )
    srv = create_server(host=args.host, port=args.port, app=app)
    addr, actual_port = srv.server_address[:2]
    print(f"ZK Rusto no Bitcoino · Prover UI listening at http://{addr}:{actual_port}", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()


if __name__ == "__main__":
    main()
