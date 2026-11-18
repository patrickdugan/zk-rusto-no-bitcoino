# Preregistered Experimental Protocol: BABE-Inspired Transparent Nova Soldering Pilot

- **Protocol ID**: `RBZK-BABE-NOVA-PILOT-2026-11`
- **Status**: Preregistered prior to Phase 4 performance measurements
- **Target Repository**: `patrickdugan/zk-rusto-no-bitcoino` (`integrations/bitvm3-nova/babe-pilot`)
- **Primary Proof System**: Transparent Nova IVC over the Pallas/Vesta cycle (`nova-snark = 0.76.0`) compressed with zero-knowledge Spartan/IPA (`CompressedSNARK` over `RelaxedR1CSSNARK` + `ipa_pc::EvaluationEngine`)
- **Baseline Comparator 1**: `M14` full garbled BLAKE3/STARK SP1 wrap verifier (`785,442,492` non-free gates, `12,567,079,872` ciphertext bytes per circuit, `8,635,080` input bits)
- **Baseline Comparator 2**: `FC03` (`flatcheck-lab`) authenticated local Nova checks (`7,285,647` non-free gates for real `HeaderStep` 1-bit `BindingStep`; `50,177,670` modelled gates at p99 `Row` width; `1,150,138,072` modelled gates at max `Row` width)
- **Optional Literature Comparator**: Babylon's January 2026 `BABE` Groth16/BN254 garbled verifier (`~22.16 MiB` ciphertext/instance, `(N=115, M=39)` cut-and-choose, trusted circuit-specific CRS)

---

## 1. Research Objectives and Falsifiable Hypotheses

This experiment evaluates whether Babylon's January 2026 BABE garbled-verification architecture—two-phase Cut-and-Choose (`C&C`), zero-knowledge input-label soldering across retained instances, `CheckLampSigsMatch` base-label authentication, and witness-assisted local elliptic-curve/algebraic checks—can be adapted to a **100% transparent Nova + Spartan/IPA stack** without trusted setup, GPU proving, or monolithic 785M-gate garbling.

### Preregistered Hypotheses

1. **H1 — Functional & Sound Multi-Instance Soldering (`M` Retained Circuits)**:
   Using Free-XOR affine translation deltas $(S_{j,i} = L_{j,i,0} \oplus L_{b,i,0},\; \Gamma_j = \Delta_j \oplus \Delta_b)$ from base retained instance $b = \min(\mathcal{R})$ to every other retained instance $j \in \mathcal{R} \setminus \{b\}$, an isolated evaluator given **only** public artifacts, a verified `CompressedSNARK` soldering certificate, and **one** base active-label vector $\{L_{b,i,x_i}\}_{i=0}^{W-1}$ deterministically recovers $\{L_{j,i,x_i}\}$ and obtains the exact committed `accept` or `refute` output label across all honest retained instances.
2. **H2 — True Zero-Knowledge Certificate without Trusted Setup**:
   Unlike `nova_snark::spartan::direct::DirectSNARK` (which reveals witness blinding `blind_r_W` in the clear and would compromise secret wire labels), `nova_snark::nova::CompressedSNARK` over `(PallasEngine, VestaEngine)` with `ipa_pc::EvaluationEngine` proves the soldering relation $\mathcal{R}_{\text{solder}}$ in zero knowledge using only transparent public parameters, while rejecting any single-bit mutation in $S_{j,i}$, $\Gamma_j$, wire commitments, `circuit_id`, `session_id`, or challenger `nonce`.
3. **H3 — Malicious-Garbler 1-of-`M` Refutation & Withholding Recovery**:
   Because a soldering proof alone establishes only input-wire consistency and **not** honest gate-table construction, combining two-phase `(N, M)` C&C opening of $N - M$ deterministic 256-bit seeds with a 1-of-$M$ `Disprove` Taptree ensures that even if an adversarial garbler corrupts $M - 1$ retained garbled circuits, a single honest retained instance $j^\star \in \mathcal{R}$ yields the valid `refute` preimage on an invalid claim; furthermore, withholding base active labels triggers deterministic challenger recovery after timeout $D_{\text{label}}$.
4. **H4 — Bounded Indexed Check + Windowed Witness-Assisted Binding Cost Reduction**:
   Replacing monolithic wrap verification (`785.4M` gates) with an indexed local check circuit, and replacing 1-bit projective RCB EC transitions with $w$-bit windowed witness-assisted affine slope checks, reduces per-circuit ciphertext size by $>100\times$ vs `M14` and reduces Pedersen binding trace length by $w\times$ vs `FC03`.

---

## 2. Fixed Pilot Parameters (CPU-Only CI Budget)

To comply strictly with the resource constraint (zero GPU usage, fast execution on ordinary 2-vCPU / 7–16 GB GitHub-hosted `ubuntu-latest` runners), the runnable CPU pilot fixes the following parameters before benchmarking:

| Parameter | Pilot Value | Production Extrapolation Target | Rationale |
| :--- | :--- | :--- | :--- |
| Cut-and-Choose `(N, M)` | `(N = 7, M = 3)` (`4` opened, `3` retained) | `(N = 115, M = 39)` ($2^{-53.05}$ soundness) | Exercises full multi-instance soldering (`1` base + `2` soldered instances, `4` opened C&C seeds, `M-1 = 2` corrupted-instance adversarial tests) within seconds on CPU CI. |
| Soldering batch size `B` per Nova IVC step | `B = 8` wires $\times 2$ soldered instances/step | `B = 64` wires/step | Keeps per-step R1CS shape small (~$7\text{k}–12\text{k}$ constraints/step) so `CompressedSNARK::setup` completes in `< 5 s` on CPU without SRS caching. |
| Reference Dispute Circuit $\mathcal{C}_{\text{pilot}}$ | Indexed `4`-leaf SHA-256 authenticated chunked witness check (`64`-bit scalar arithmetic + `4`-bit windowed witness-assisted affine check, `W = 200`–`600` input bits) | Real `FC03` / `BABE` Pasta 255-bit indexed local check (`W ≈ 19,168`–`21,864` bits) | Small enough for full `(N=7, M=3)` garbling, opening, Nova `CompressedSNARK` proving, and all adversarial tests in `< 30 s` on CPU, while separately measuring exact gate counts of full 255-bit Pasta witness-assisted EC gadgets in `ExecuteMode`. |
| Garbling Primitive | `GarbleMode::new_with_seed` (`256`-bit ChaCha20 seed, `AesCcrGateHasher` 1-ciphertext Half-Gates) | Same | Exact parity with hardened `garbled-snark-verifier` PR #4 and `m14-claim` PR #25. |

---

## 3. Preregistered Acceptance & Adversarial Test Matrix

Every test in the matrix below must pass on CPU before Phase 4 benchmark numbers are recorded:

1. **`e2e_honest_accept_and_refute_across_retained_instances`**:
   Full `(N=7, M=3)` two-phase setup, deterministic C&C verification of all `4` opened seeds, Nova `CompressedSNARK` soldering proof generation & verification, base active-label delivery, unsoldering across all `3` retained instances, confirming `accept` on valid witness and `refute` on invalid witness across all `3` retained circuits.
2. **`rejects_mutated_translation_deltas_and_global_gamma`**:
   Flipping any bit of $S_{j,i}$ or $\Gamma_j$ causes either `CompressedSNARK::verify` or public boundary binding verification to reject.
3. **`rejects_altered_label_commitments`**:
   Mutating either a SHA-256 base commitment $H^{\text{btc}}_{b,i,\beta}$ or an algebraic Poseidon label commitment root $R^{\text{pos}}_j$ causes independent verification to reject before evaluation.
4. **`rejects_substituted_circuit_id_and_replayed_session_or_nonce`**:
   Substituting `circuit_id`, replaying a valid `CompressedSNARK` under a fresh `session_id` or challenger `nonce`, or swapping soldered deltas across instances is deterministically rejected via `z_0 / z_n` public IO binding.
5. **`evaluator_isolation_holds_without_garbler_secrets`**:
   Evaluator API consumes exclusively `(PublicSetup, SolderingCertificate, ActiveBaseLabels)`—no `seed`, no Free-XOR $\Delta_j$, and no inactive labels $L_{j,i,1-x_i}$ exist in evaluator memory or types.
6. **`malicious_garbler_one_of_m_honest_instance_recovers_refute`**:
   Adversarial test in which `M - 1 = 2` of the `3` retained garbled circuits have corrupted ciphertext tables (slipping past C&C with low probability), verifying that the `1` honest retained circuit still produces the valid `refute` preimage matching its Tapscript `Disprove` leaf hashlock.
7. **`adversarial_withholding_and_malformed_artifacts`**:
   Tests covering: (a) corrupted opened C&C seed caught during Phase 1 inspection; (b) base-label equivocation caught by `CheckLampSigsMatch` SHA-256 commitments; (c) base-label withholding resolved via deterministic challenger timeout path; and (d) truncated/corrupted serialized public bundles rejected cleanly without panicking.

---

## 4. Measurement Protocol (Phase 4)

All measurements will be collected on CPU via a deterministic release binary (`cargo run --release --locked --bin babe-pilot-bench`) and contrasted against committed `M14` (`integrations/bitvm3-nova/m14/circuit/RESULTS.json`, `m14/README.md`) and `FC03` (`FC03_RESULTS.json`) figures:

1. **Single-circuit metrics**: non-free gates (= 16-byte Half-Gates ciphertexts), ciphertext bytes, input wire count $W$, SHA-256 & Poseidon commitment bytes, garble + evaluate wall time.
2. **Full `(N, M)` protocol metrics**: total generated setup bytes ($N$ instances), retained setup bytes ($M$ instances), opened seed verification bytes ($N - M$ seeds), soldering delta bytes ($(M-1)(16W + 16)$), active-label delivery bytes ($16W$).
3. **Nova `CompressedSNARK` metrics**: step R1CS constraint count (`|A|, |B|, |C|`, variables, constraints), number of IVC folding steps, `PublicParams` + `CompressedSNARK::setup` time, `RecursiveSNARK` folding time, `CompressedSNARK::prove` time, `CompressedSNARK::verify` time, serialized certificate byte size.
4. **System resource metrics**: peak process RSS (`VmHWM` on Linux / `GetProcessMemoryInfo` on Windows) and on-disk artifact directory byte sizes.
5. **Bitcoin witness & transaction metrics**: exact serialized Taproot transaction virtual bytes (`vsize`) and witness weight units (`WU`) for `Claim`, `Challenge`, `AssertLabels` (`CheckLampSigsMatch`), `Disprove` (`1-of-M` Taptree leaf), and `WithholdingTimeout`, distinguishing directly constructed script witnesses from scaled `(N=115, M=39)` analytical projections.
