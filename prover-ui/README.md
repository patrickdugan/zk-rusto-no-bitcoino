# Native prover console

The Mecha desktop UI displays observed runtime data, proof receipts, and a deadline planner for the Ark SP1 → M13 → BitVM3 campaign.

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

The dashboard also discovers the running Ark CUDA executable from fresh runtime
process observations, adds its campaign card, and selects active work until the
user chooses another campaign. Its RAM/swap values require fresh phase samples;
completed script receipts remain separate. A running process is never a verified
proof receipt.

To load the checked-in frontend with the existing native engine during a proof
run, install the shortcut with `-LiveAssets -ExePath <native executable>`. This
uses `scripts/launch-live-desktop.ps1` and the existing opt-in local asset loader;
it does not rebuild or restart a prover. Regular portable launches use embedded
assets. Rebuilding embeds the updated frontend as usual.

## Cloud compute telemetry

Open **Compute** to sign in to Runpod, Prime Intellect, or Hyperstack in
the provider console.
For Runpod telemetry, configure a read-only Pod API key through
`RUNPOD_API_KEY`, a file selected by `RBZK_RUNPOD_API_KEY_FILE`, or the local
`~/.runpod/api-key` file. The native app reads the key server-side and polls
the Runpod control plane independently of the laptop telemetry.

A fresh, authenticated Runpod GPU Pod becomes the hardware ribbon source.
The Compute tab retains the laptop readings alongside the cloud readings.
Set `RUNPOD_POD_ID` to select a specific Pod if the account has several
running GPU Pods. Runpod GPU and container usage describe the rented
instance. The Ark proof tracker continues to use observations of its own
proof producer.

The app also reads the existing Prime CLI configuration at
`~/.prime/config.json` or `PRIME_API_KEY`. It polls the account's Compute Pod
list and shows the upstream host when Prime reports it. Set `PRIME_POD_ID`
to select a specific Prime Pod instead of the sole active GPU Pod. The Prime
Pod list supplies lifecycle and hardware information. Utilization is
available from the direct Runpod metrics feed.

## ETA and motion

The Ark campaign tracks the height-679 regtest maintenance policy for four VTXOs
and 79,440 sats. Coordinator phases track SP1 compression, independent SDK verification,
M13 shrink and transcript-v2 wrap, exact statement verification and the Ark policy
gate, negative controls, and M14 evaluation. The terminal coordinator report
requires honest M14 acceptance and a full-circuit bit-flip rejection. Publication
and the Cashu demo package remain manual milestones. The historical Shinigami
testnet4 receipts support a separate claim.

The M14 setup can run in parallel with SP1. The setup report clears its own
milestone and removes its budget from the remaining critical path. During M14
evaluation the coordinator rechecks those artifacts and binds the release to the
verified Ark wrap. The setup timing does not estimate honest or adversarial
evaluation.

The **Cashu Roadmap** tab covers the Friday demo and the remaining milestones for
admin-trust-free Cashu. The demo uses the recorded CDK/Bark integration and exit
results in Proofdesk's `docs/cashu-ark-integration.json` and
`docs/cashu-ark-exit-integration.json`. It looks for both historical Shinigami
receipts in the Evidence inventory. The four-VTXO off-chain proof is contingent
on verifier checks and an evidence audit. The milestones for live backing and
liabilities, proof-bound issuance, funded mint-refusal redemption, and
adversarial integration have no ETA.

The planner compares the entered scenario against the
[Nut November cutoff](https://nutnovember.org/) on 27 November 2026 at 23:59 UTC.
It needs a scenario core total and a remaining time budget for each unfinished
stage. Core and recursive work overlap, so the SP1 budget covers only the
recursion and compression expected after the core target. The finish window
combines observed core pace with the entered budgets. The delivery window adds
the manual evidence and demo budget. Both assume continuous resources and normal
refusals. If inputs are missing, the app shows how many saved cores could fit
before the deadline at the observed pace after any entered reserves. That number
is a capacity ceiling. Pending unbudgeted work and resource holds lower it.

The separate live checkpoint tracker forecasts the next hundred saved core proofs using observed
15-minute throughput, with 5- and 30-minute rates providing a recent-pace range.
It can instead project an explicitly entered core target, saved per campaign.
The countdown stays anchored between saved core completions. Replays do not
supply new-proof rates; stale samples, a stopped producer, pauses and long gaps
hold the estimate. This tracker measures progress toward its selected saved-core
target. It never advances a proof verification milestone.

Only newly observed proof completions receive a short, small tile animation.
Historical cache loading does not trigger it. Tab changes have a short fade;
there are no perpetual proof pulses. The motion toggle persists, and the OS
reduced-motion preference is always honored. Polling preserves expanded evidence,
keyboard focus and unapplied target drafts.

Run the ETA regressions with `node --test tests/eta_model.cjs`; the existing CI
workflow now includes them alongside the Rust and Python checks.
