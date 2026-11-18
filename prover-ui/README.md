# Prover & Recursive Shard UI (`prover-ui/`)

A zero-dependency, read-only local prover console and recursive-shard attribution explorer for `zk-rusto-no-bitcoino`.

It connects live hardware telemetry (Windows host RAM, `vmmemWSL` resident vs committed memory, Linux cgroup v2 RAM/swap, and NVIDIA RTX 5080 CUDA utilization) with the repository's Nova 0.76, SP1 6.9, Shinigami Script/Taproot, Mainnet `M16`/`M18`, and Ark/Cashu (`ARK1` / Proof Grove) proving pipelines.

## Launch

Requires Python 3.11+ with **no external pip or npm dependencies** (~18 MiB RSS, imposing zero memory pressure on active GPU/WSL proof runs).

```powershell
cd C:\Users\patri\OneDrive\Documents\GitHub\rbzk-prover-ui\prover-ui
python -m rbzk_prover_ui serve --port 8788
```

Open <http://127.0.0.1:8788>.

### CLI utilities

```powershell
# Print a single live JSON snapshot (GPU, Windows RAM, vmmemWSL, WSL prover shards)
python -m rbzk_prover_ui status

# Estimate recursive shards, R1CS constraints, and RAM/VRAM from measured unit costs
python -m rbzk_prover_ui correlate --header-blocks 975072 --nova-header-shards 2 --utxo-window-blocks 6 --payment-utxos 1

# Run unit, calibration, and HTTP security tests
python -m unittest discover -s tests -v
```

## What It Shows

1. **Live RAM / GPU & WSL Prover Telemetry (`01`)**
   - **RTX 5080 Laptop GPU (16 GB)**: Live compute %, VRAM residency, SM clock, power draw, temperature, and `ARK_CUDA_POOL_RELEASE_MIB=256` / `ARK_SP1_TRANSIENT_TRACES=1` pool controls via `nvidia-smi`.
   - **Host vs WSL Memory Accounting**: Queries `GlobalMemoryStatusEx` and Win32 `K32GetProcessMemoryInfo` on `vmmemWSL` directly, separating **resident working set** from **non-resident pagefile/compressed commit** alongside Linux cgroup v2 `memory.current` (`2,048 MiB` hard cap), `memory.swap.current` (`4,096 MiB` cap), and the `3.0 GiB` Windows host reserve floor (`host.json` read with `FILE_SHARE_DELETE` so atomic renames never block).
   - **Incremental SP1 Checkpoint Stream**: Tails `progress.jsonl` by byte offset (<1 ms per poll) to track unique `ProveShard` (core) and `RecursionReduce` (recursive) memo tasks, proved vs replayed counts, rolling throughput, artifact store MiB, and `/dev/shm` sparse-file cleanup receipts.

2. **Recursive Shards ↔ Blocks, Shinigami Leaves & UTXOs (`02`)**
   - **5-Layer Reduction Hierarchy**: Maps Bitcoin domain primitives → Nova 0.76 relaxed-R1CS segments → SP1 core shards → 3:1 recursive compression tree → `M13` BLAKE3 transcript-v2 wrap → `M14` `785,442,492`-gate garbled verifier.
   - **M16 Mainnet (`0 .. 975,072`)**: Shows the two `NHC1` Nova header shards (`s0`, `s1`) and exact `34,055,622,753`-instruction guest attribution across `13,290` core shards and `4,430` recursion tasks.
   - **M18 Windowed UTXO Map (`975,067 .. 975,072`)**: Per-block breakdown of transactions, UTXO creates, in-window/pre-window spends, SHA-256 producer compressions, depth-20 Poseidon leaf updates, producer idle steps, and the `8` parallel `fold-seg` `z0 → zn` chains (`224,790` steps, `74,593` leaves).
   - **Shinigami Script & Taproot Leaves**: Compares `M17` Nova step-circuit scripts (`P2PKH`, `P2WSH`, `P2WPKH`, `P2SH-Multisig`, `2,756` Core vectors), `shinigami/taproot-provable` Cairo/Stwo Ark VTXO exit chains (`board`, `round1`, `arkoor3`, `4,977` Core checks), and `FC03` `644 vB` Taproot leaf-script refutation envelopes.

3. **Payment UTXOs, Ark VTXOs & Cashu Desk (`03`)**
   - **Mainnet `PAY1` + `M18` Leaf #8**: Displays `a652ab0c…0045:0` (`940,000 sats` at height `975,067`, 6 confirmations under `975,072`) together with its verified depth-20 Poseidon Indexed Merkle Tree unspent proof (`Leaf #8`, all 20 Merkle siblings, sealed root `7e18b083…2d1c`).
   - **Ark ASP Policy (`ARK1`) & Cashu Proof Grove**: Displays the `4` Proof Grove Bark VTXOs at height `679` (`79,440 sats` managed → `1` refresh + `3` liquidity deferrals), the `25,000 sat` Cashu NUT-09/20 DLEQ → `10,000 sat` Bark VTXO → `9,165 sat` offline exit flow, and SHA-256 verifier pins (including cross-program `M16 → ARK1` refusal).

4. **Shard & Hardware Planner (`04`)**
   - Interactive workload estimator computing Nova segments/constraints, R1CS commitment basis ($2^{\lceil\log_2 C_1\rceil} + 2^{\lceil\log_2 C_2\rceil}$), SP1 instructions, core & recursive shard counts, and RAM/swap/VRAM envelopes across `2^26`..`2^28` shard thresholds. Projections are explicitly badged `ANALYTICAL PROJECTION · MEASURED UNIT CONSTANTS` and never conflated with verified proof receipts.
   - See [`SHARD_ESTIMATION.md`](SHARD_ESTIMATION.md) for the full 3-stage shard estimation derivation, measured `M15`/`M16`/`M18`/`ARK1` constants, and restart recursion-regrouping accounting.
