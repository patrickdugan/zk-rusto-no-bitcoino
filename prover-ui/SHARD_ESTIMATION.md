# Estimating Total SP1 Core & Recursive Shards from Blocks, Transactions, Leaves & VTXOs

This note documents how Bitcoin domain workloads (blocks, transactions, inputs/outputs, UTXO leaves, Shinigami script leaves, and Ark VTXOs) map to SP1 6.9 `ProveShard` (core/memory/precompile) and `RecursionReduce` (compression tree) task counts in `zk-rusto-no-bitcoino`.

All constants below are calibrated to measured runs in `integrations/bitvm3-nova/` (`m15`, `m16`, `m17`, `m18`, `prover`, `prover-gpu`) and `Ark/`. Analytical estimates remain explicitly separated from verified proof receipts.

---

## 1. Why Domain Counts Do Not Scale SP1 Shards Linearly

In this two-tier architecture, **Nova 0.76 absorbs step count before SP1 executes**:

- **Empirical proof (`integrations/bitvm3-nova/m16/README.md`)**:
  - Test chain (`800` headers folded into `2` Nova segments + `1` `PAY1` payment): **`34,064,279,163` SP1 instructions**
  - Full Bitcoin mainnet (`975,072` headers folded into `2` Nova segments + `1` `PAY1` payment): **`34,055,622,753` SP1 instructions** (`0.025%` delta)

Blocks, transactions, and tree updates determine **Nova folding steps ($S$)** and CPU folding wall-time. SP1 shard counts change only when:
1. $S$ is partitioned into more **parallel Nova segments ($m$)** (trading CPU folding wall-time against extra Spartan-IPA verifications inside SP1),
2. The Nova step circuit changes its **R1CS power-of-two commitment basis ($G$)** and **M15 raw verifier-key (`RAW.vk`) byte size**,
3. Additional witness checks (e.g. `PAY1` Merkle branches, `M18` leaf openings, or deferred Shinigami signature claims) execute **directly inside the SP1 guest**, or
4. `--element-threshold` ($T_e$) is changed (e.g. `2^27` vs `2^26` bounded-RAM mode).

---

## 2. Three-Stage Closed-Form Estimator

### Stage A — Domain Primitives $\rightarrow$ Nova Steps ($S$) & Segments ($m$)

1. **Header Chain (`NHC1`, `82,809` R1CS/step)**:
   - $S_{\text{hdr}} = B_{\text{headers}}$ (`1` step per header), split into $m_{\text{hdr}}$ operator-chosen segments (`m = 2` on M16 mainnet `0..975,072`).
2. **Windowed UTXO Map (`M18`, `51,404` R1CS/step)**:
   - Each step runs one SHA-256 compression slot (producer) alongside one depth-20 Poseidon indexed-Merkle leaf update (consumer). Per block:
     $$S_{\text{block}} \approx \max\!\big(C_{\text{sha256}},\, N_{\text{in}} + 2N_{\text{out}}\big) + \varepsilon$$
     where $C_{\text{sha256}} \approx \lceil \text{nonwitness\_bytes}/64 \rceil + N_{\text{tx}} + 3N_{\text{merkle\_merges}} + 3$, each input costs `1` leaf update (`SPEND_IN` or `SPEND_PRE`), and each created output costs `2` updates (`CREATE_LOW` + `CREATE_NEW`).
   - Across mainnet `975,067..975,072` (`6` blocks, `32,693` txs, `47,238` inputs, `74,592` outputs), measured $S = 224{,}790$ (`37,465` steps/block avg); partitioned at `28,099` steps/segment $\Rightarrow m_{\text{m18}} = \lceil S / 28{,}099 \rceil = 8$.
3. **Shinigami Script Leaves (`M17`, `6,808` R1CS/step)** & **Ark Policy Book (`ARK1`, `19,113` R1CS/step)**:
   - $S_{\text{m17}} = \sum \text{leaves}_i \cdot \text{steps}(\text{script}_i)$ (`10` P2PKH, `17` P2WSH, `21` P2WPKH, `30` P2SH-P2WPKH, `31` P2SH-Multisig) $\Rightarrow$ typically $m_{\text{m17}} = 1$.
   - $S_{\text{ark}} = N_{\text{vtxos}}$ (`1` step per VTXO record, up to `512` per book) $\Rightarrow m_{\text{ark}} = 1$.

---

### Stage B — Nova Segments & Guest Checks $\rightarrow$ SP1 Instructions ($I_{\text{sp1}}$)

Inside SP1 (`m15` raw-affine key format + `uint256_mulmod` & Keccak precompiles), verifying a Nova circuit family $k$ scales with:
- Its **commitment-key generator count** on `(Pallas, Vesta)`:
  $$G_k = 2^{\lceil \log_2 C_{1,k} \rceil} + 2^{\lceil \log_2 C_{2,k} \rceil}, \qquad C_{2,k} = 10{,}349 \implies 2^{14} = 16{,}384$$
- Its **raw verifier-key byte ratio** $r_{\text{vk},k} = \text{bytes}(\text{RAW.vk}_k) / 46{,}916{,}520$.

| Circuit Family | Primary $C_1$ | Generator Basis $G_k$ | Basis Ratio $r_{G,k}$ | Raw `VK` Size | `VK` Decode + Hash | 1st Segment Verify | Marginal Extra Segment |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `NHC1` (M15 / M16 Headers) | `82,809` | $2^{17}+2^{14} = 147{,}456$ | `1.000` | `46.92 MB` | `4.82B` | `16.38B` | `+12.88B` |
| `M18` (Windowed UTXO Map) | `51,404` | $2^{16}+2^{14} = 81{,}920$ | `0.556` | `~29.1 MB` | `~2.86B` | `~9.63B` | `+7.58B` |
| `ARK1` (Ark ASP VTXO Policy) | `19,113` | $2^{15}+2^{14} = 49{,}152$ | `0.333` | `22.48 MB` | `~2.01B` | `~6.26B` | `+4.93B` |
| `M17` (Shinigami Script VM) | `6,808` | $2^{13}+2^{14} = 24{,}576$ | `0.167` | `~11.3 MB` | `~1.01B` | `~3.73B` | `+2.94B` |

*(Check on `M15`: $2^{17} + 2^{14} = 147{,}456$ matches `m15/README.md`'s measured `147,464` commitment-key points within `8` generators; `M16` `4.82B + 16.38B + 12.875B = 34.075B` matches measured `34.056B` within `0.06%`.)*

Add linear **direct SP1 guest checks** (outside Nova):
- `PAY1` non-witness tx parse + Merkle branch: **`259,390` instr / UTXO** (measured on M16)
- `M18` balance claim (`SHA-256d` tx + depth-20 Poseidon path): **`~420,000` instr / UTXO**
- Deferred Shinigami signature/sighash claim in SP1 precompiles: **`~1,850,000` instr / leaf**
- `ARK1` public statement / VTXO commitment scan: **`~85,000` instr / VTXO**

---

### Stage C — SP1 Instructions $\rightarrow$ `ProveShard` ($N_{\text{core}}$) & `RecursionReduce` ($N_{\text{rec}}$)

SP1 6.9 slices execution into `ProveShard` tasks across CPU, precompile (`uint256_mulmod`, `keccak_permute`, `sha256`), and memory-finalize chips whenever a chip's trace elements reach `--element-threshold` ($T_e$) or `--height-threshold` ($T_h$).

Across measured Nova-verifier runs at $T_e = 2^{27}$ (`134,217,728`):
- **Guest A** (`72.3B` instr $\rightarrow$ `27,058` `ProveShard`): **`2.672M` instr / shard**
- **M16 Mainnet** (`34.056B` instr $\rightarrow$ `13,290` `ProveShard`): **`2.563M` instr / shard**

Scaling with $T_e$:

$$N_{\text{core}} \approx \left\lceil \frac{I_{\text{sp1}}}{2.5625 \times 10^6 \cdot (T_e / 2^{27})} \right\rceil, \qquad N_{\text{rec, tree}} \approx \left\lceil \frac{N_{\text{core}}}{3} \right\rceil, \qquad N_{\text{total, tree}} = N_{\text{core}} + N_{\text{rec, tree}}$$

- **M16 Mainnet check ($T_e = 2^{27}$)**: `13,290` `ProveShard` + `4,430` `RecursionReduce` (`13,290 / 4,430 = 3.000` exact 3:1 compression ratio) = **`17,720` total tasks**.
- **Ongoing `ARK1` GPU run ($T_e = 2^{26}$)**: $I_{\text{ARK1}} \approx 8.27\text{B} \implies N_{\text{core}} \approx \mathbf{6{,}457}$ `ProveShard` + $N_{\text{rec, tree}} \approx \mathbf{2{,}152}$ active-tree `RecursionReduce` = **`~8,609` active-tree tasks**.

#### Important Restart Caveat (`RecursionReduce` Memo Regrouping)
As documented in `integrations/bitvm3-nova/prover/README.md`:
- **`ProveShard` keys are deterministic** (`SHA256(run.json)` + shard trace record): replaying after a `host_memory_floor` stop adds **`0` extra core shards**.
- **`RecursionReduce` pairs proofs in arrival order**: when a run restarts, partial subtrees can regroup over different child proof bytes, writing additional `reduce` memo entries beyond the active tree's `N_core / 3`.
- **UI Completion Rule**: Completion percentage (`n / total`) is therefore computed from deterministic unique `ProveShard` progress and the **current session's active recursion tree** (`shards_proved + shards_replayed` and `recursion_proved + recursion_replayed` reported in `phase.log`), while displaying historical regrouped memo entries separately so progress is never artificially inflated by prior restarts.

---

## 3. Pre-Proving Tight & Exact Methods

1. **~2–4% Pre-Prove Estimate (`nb3-prove execute`)**:
   Running `nb3-prove execute --elf ELF --input ...` (with gas/syscall reporting enabled) outputs exact `instructions`, `touched_memory_addresses`, and `syscalls` (`KECCAK_PERMUTE`, `UINT256_MUL`, `SHA_COMPRESS`) without running STARK provers, eliminating instruction-count uncertainty.
2. **100% Exact `ProveShard` Count (SP1 Executor/Splicer Pass)**:
   `ProveShard` boundaries depend strictly on `RunConfig` (`element_threshold`, `height_threshold`, `shard_size`) and guest `stdin`. Running SP1's trace splicer alone yields the exact integer `ProveShard` count prior to GPU proving.
