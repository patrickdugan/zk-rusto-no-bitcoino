# Native prover console

The Mecha desktop UI now displays observed runtime data, with no embedded campaign results, static payment balances, invented shard totals, countdowns, or simulated proof activity.

The original incremental shard cache and measured-unit planner remain available. Cache counts are labeled history; the planner is labeled a projection. Neither establishes a running prover or verification.

## Sources

- Windows physical/commit memory and WSL working set/private commit: native OS queries.
- GPU name, compute activity, VRAM, temperature and clocks: NVIDIA telemetry. Unsupported readings remain unavailable. GPU-wide activity is not attributed to a proof process.
- Proof processes: systemd state plus executable, PID, start ticks and cgroup membership. The background probe reads the existing WSL Ubuntu-24.04 environment every three seconds. It starts no proof jobs.
- CPU time, RAM/swap and limits: actual unit/cgroup counters.
- Proof stage: the unit journal, including ANSI stripping. No stage progress is synthesized from elapsed time.
- Independent verification: a successful audit receipt, all fifteen negative controls and the actual output file's matching SHA-256. The UI observes those verifier results; it does not rerun cryptographic verification itself.
- Local evidence: bounded JSON reports reread from `Ark/results`, with source path, modification time and SHA-256. Reports remain historical evidence.
- Payment claims: exact public claims from observed audit receipts. No live wallet balance source is configured.

Samples older than fifteen seconds become stale/unknown; disconnecting or pausing the display never leaves an active indicator. Pausing the display does not stop proving.

## Build and run

```powershell
cargo +1.90.0-x86_64-pc-windows-msvc build --locked --release -j 1
.\target\release\rbzk-prover-desktop.exe
```

Run from `prover-ui`. The bundled older `releases/windows-x64` binaries are preserved; use the freshly built executable above for live observations. Install the shortcut with `scripts/install-desktop-shortcut.ps1 -ExePath <absolute path to the new executable>`.

Headless: `cargo test --locked --no-default-features`; Python parity and receipt regressions: `python -m unittest discover -s tests -v`. CI already executes both suites. The Python fallback uses the same probe and frontend.

## Configuration

`RBZK_ARK_DIR` selects the Ark directory containing `results/`. `RBZK_WSL_ARK_BASE` selects the existing incremental SP1 run/cache. No fixture is substituted for missing sources.

`RBZK_LIVE_CONFIG` optionally names a local JSON file, reread on every observation. Default jobs are the current testnet4 tapleaf and legacy-payment units. To observe another proof run, configure its real unit, executable and output/audit paths:

```json
{
  "proof_root": "/var/tmp/my-proof-run",
  "jobs": [{
    "title": "My proof run",
    "unit": "my-proof.service",
    "executable": "/absolute/path/to/prover",
    "proof": "proof.json",
    "audit": "independent-audit.json",
    "backend": "Actual backend name",
    "network": "testnet4"
  }]
}
```

Configuration registers observation sources; it never launches or resumes a prover. A raw proof filename alone cannot establish verification. Full Ark SP1/BitVM3 completion, current unspentness, mint funding and removal of a trusted administrator are separate claims.
