# Prover & Recursive Shard Desktop App (`prover-ui/`)

A standalone **native Rust desktop application** (`tao` + `wry` WebView2/WebKit) and ultra-low-overhead (~5 MiB RSS) read-only telemetry console for `zk-rusto-no-bitcoino`.

It connects live hardware telemetry (Windows host RAM via `GlobalMemoryStatusEx`, `vmmemWSL` working-set vs private commit via `NtQuerySystemInformation`, Linux cgroup v2 RAM/swap, and NVIDIA RTX 5080 CUDA utilization) with the repository's Nova 0.76, SP1 6.9, Shinigami Script/Taproot, Mainnet `M16`/`M18`, BABE-Nova transparent soldering, and Ark/Cashu (`ARK1` / Proof Grove) proving pipelines.

All frontend assets (`index.html`, `styles.css`, `app.js`, `icon.svg`) and provenance JSON receipts are baked directly into the compiled Rust binary (`include_bytes!`), producing a **single portable `.exe`** with zero Python, Node, or external asset dependencies.

---

## Build & Launch (Native Rust Desktop App)

```powershell
cd prover-ui

# Build optimized standalone binaries (rbzk-prover-desktop.exe & rbzk-prover-ui.exe)
cargo +1.90.0-x86_64-pc-windows-msvc build --release

# Launch native dark-themed desktop GUI window (zero console window)
.\target\release\rbzk-prover-desktop.exe

# Or use the unified CLI + GUI binary:
.\target\release\rbzk-prover-ui.exe desktop --port 8788
.\target\release\rbzk-prover-ui.exe serve --host 127.0.0.1 --port 8788
.\target\release\rbzk-prover-ui.exe status
.\target\release\rbzk-prover-ui.exe correlate --header-blocks 975072 --nova-header-shards 2 --payment-utxos 1
```

### Headless / CI Builds (Without GUI Windowing Dependencies)

```bash
cargo test --no-default-features --locked
cargo build --release --no-default-features --locked
```

*(A zero-dependency Python 3.11+ fallback `python -m rbzk_prover_ui serve --port 8788` is also retained in `rbzk_prover_ui/`.)*

---

## What It Shows

1. **Live RAM / GPU & WSL Prover Telemetry (`01`)**
   - **RTX 5080 Laptop GPU (16 GB)**: Live compute %, VRAM residency, SM clock, power draw, temperature (`CREATE_NO_WINDOW`), and `ARK_CUDA_POOL_RELEASE_MIB=256` / `ARK_SP1_TRANSIENT_TRACES=1` pool controls.
   - **Host vs WSL Memory Accounting**: Queries `GlobalMemoryStatusEx` and `NtQuerySystemInformation` on `vmmemWSL` in `<0.5 ms`, separating **resident working set** from **non-resident pagefile/compressed commit** alongside Linux cgroup v2 `memory.current` (`2,048 MiB` hard cap), `memory.swap.current` (`4,096 MiB` cap), and `host.json` (`FILE_SHARE_READ|WRITE|DELETE`).
   - **Incremental SP1 Checkpoint Stream**: Tails `progress.jsonl` by byte offset (`<1 ms`/poll) to track unique `ProveShard` (core) and `RecursionReduce` (recursive) memo tasks, proved vs replayed counts, rolling 5m/15m/30m throughput, monotonic `HH:MM:SS` ETA countdowns, and 60fps shard mosaic bursts.

2. **Recursive Shards ↔ Blocks, Shinigami Leaves & UTXOs (`02`)**
   - **5-Layer Reduction Hierarchy**: Maps Bitcoin domain primitives → Nova 0.76 relaxed-R1CS segments → SP1 core shards → 3:1 recursive compression tree → `M13` BLAKE3 transcript-v2 wrap → `M14` `785,442,492`-gate garbled verifier.
   - **M16 Mainnet (`0 .. 975,072`)**: Shows the two `NHC1` Nova header shards (`s0`, `s1`) and exact `34,055,622,753`-instruction guest attribution across `13,290` core shards and `4,430` recursion tasks.
   - **M18 Windowed UTXO Map (`975,067 .. 975,072`)**: Per-block breakdown of transactions, UTXO creates, in-window/pre-window spends, SHA-256 producer compressions, depth-20 Poseidon leaf updates, and the `8` parallel `fold-seg` `z0 → zn` chains (`224,790` steps, `74,593` leaves).
   - **Shinigami Script, Taproot Leaves & BABE-Nova Soldering**: Compares `M17` Nova step-circuit scripts (`2,756` Core vectors), `shinigami/taproot-provable` Cairo/Stwo Ark VTXO exit chains (`4,977` Core checks), `FC03` `644 vB` Taproot refutation envelopes, and `babe-nova/pasta-ec-w4` (`769,351` gates, `11.74 MiB` ciphertext, `88.4 kvB` standard `AssertLabelsTx`).

3. **Payment UTXOs, Ark VTXOs & Cashu Desk (`03`)**
   - **Mainnet `PAY1` + `M18` Leaf #8**: Displays `a652ab0c…0045:0` (`940,000 sats` at height `975,067`, 6 confirmations under `975,072`) with its verified depth-20 Poseidon Indexed Merkle Tree unspent proof (`Leaf #8`, all 20 siblings, sealed root `7e18b083…2d1c`).
   - **Ark ASP Policy (`ARK1`) & Cashu Proof Grove**: Displays the `4` Proof Grove Bark VTXOs at height `679` (`79,440 sats` managed), the `25,000 sat` Cashu NUT-09/20 DLEQ → `10,000 sat` Bark VTXO → `9,165 sat` offline exit flow, and SHA-256 verifier pins.

4. **Shard & Hardware Planner (`04`)**
   - Interactive workload estimator computing Nova segments/constraints, R1CS commitment basis ($2^{\lceil\log_2 C_1\rceil} + 2^{\lceil\log_2 C_2\rceil}$), SP1 instructions, core & recursive shard counts, and RAM/swap/VRAM envelopes across `2^25`..`2^28` shard thresholds. See [`SHARD_ESTIMATION.md`](SHARD_ESTIMATION.md).
