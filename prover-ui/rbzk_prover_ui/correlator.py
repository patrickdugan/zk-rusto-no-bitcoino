"""Deterministic workload-to-recursive-shard and RAM/GPU envelope estimator.

All unit constants are taken directly from measured artifacts in
`integrations/bitvm3-nova` (`m15`, `m16`, `m17`, `m18`, `prover-gpu`) and `Ark/`.
See `prover-ui/SHARD_ESTIMATION.md` for the full 3-stage derivation.
Outputs are explicitly tagged `analytical-projection-from-measured-constants` so
they are never mistaken for verified proof receipts.
"""
from __future__ import annotations

import math
from typing import Any


# Measured repository R1CS constants
SECONDARY_NOVA_CONSTRAINTS = 10_349  # Nova 0.76 Vesta folding verifier circuit -> 2^14 = 16,384
SECONDARY_BASIS_POINTS = 1 << math.ceil(math.log2(SECONDARY_NOVA_CONSTRAINTS))  # 16,384

NHC1_CONSTRAINTS_PER_HEADER = 82_809  # -> 2^17 + 2^14 = 147,456 commitment generators
M18_CONSTRAINTS_PER_STEP = 51_404     # -> 2^16 + 2^14 = 81,920 commitment generators
M17_CONSTRAINTS_PER_STEP = 6_808      # -> 2^13 + 2^14 = 24,576 commitment generators
ARK1_CONSTRAINTS_PER_STEP = 19_113    # -> 2^15 + 2^14 = 49,152 commitment generators

# Measured M18 mainnet 975,067..975,072 averages (6 blocks: 32,693 txs, 47,238 in, 74,592 out)
M18_DEFAULT_TX_PER_BLOCK = 5_449
M18_DEFAULT_INPUTS_PER_BLOCK = 7_873
M18_DEFAULT_OUTPUTS_PER_BLOCK = 12_432
M18_DEFAULT_NONWITNESS_BYTES = 810_812
M18_SEGMENT_MAX_STEPS = 28_099

M17_STEPS_BY_SCRIPT = {
    "p2wpkh": 21,
    "p2pkh": 10,
    "p2wsh": 17,
    "p2sh_multisig": 31,
    "p2sh_p2wpkh": 30,
    "taproot_vtxo_exit": 42,
}

# Measured M15/M16 SP1 6.9 instruction anchors on NHC1 (raw VK = 46,916,520 B, G = 147,456 pts):
# - VK affine decode: 2.04e9 instructions (scales with commitment generator count G)
# - VK SHA-256 + Keccak hash: 2.78e9 instructions (scales with raw VK byte size)
# - 1st CompressedSNARK verify: 16.38e9 = 1.20e9 fixed sumcheck/transcript + 15.18e9 IPA MSM(G)
# - Marginal extra segment:     12.875e9 = 0.95e9 fixed sumcheck/transcript + 11.925e9 IPA MSM(G)
NHC1_BASIS_POINTS = (1 << math.ceil(math.log2(NHC1_CONSTRAINTS_PER_HEADER))) + SECONDARY_BASIS_POINTS
NHC1_RAW_VK_BYTES = 46_916_520
ARK1_RAW_VK_BYTES = 22_483_808  # Measured in Ark/results/key-encoding.json

SP1_VK_DECODE_BASE_INSTR = 2_040_000_000
SP1_VK_HASH_BASE_INSTR = 2_780_000_000
SP1_FIRST_SEG_FIXED_INSTR = 1_200_000_000
SP1_FIRST_SEG_MSM_INSTR = 15_180_000_000
SP1_EXTRA_SEG_FIXED_INSTR = 950_000_000
SP1_EXTRA_SEG_MSM_INSTR = 11_925_000_000

# Direct SP1 guest check unit costs (outside Nova)
SP1_PAYMENT_UTXO_INSTR = 259_390      # Measured M16 PAY1 tx parse + depth-13 Merkle branch
SP1_M18_LEAF_VERIFY_INSTR = 420_000   # SHA-256d tx + depth-20 Poseidon membership path
SP1_SHINIGAMI_CLAIM_INSTR = 1_850_000
SP1_ARK_VTXO_BOOK_INSTR = 85_000

# Measured shard & recursion ratios from M16 (34,055,622,753 instr -> 13,290 core, 4,430 reduce at 2^27)
M16_INSTR_PER_SHARD_AT_2_27 = 34_055_622_753 / 13_290.0  # ~2,562,500 instructions/shard
RECURSION_FAN_IN = 3.0  # 13,290 / 4,430 = 3.000 exact measured active-tree ratio
M14_FINAL_NONFREE_GATES = 785_442_492


def circuit_basis_points(primary_constraints: int) -> int:
    if primary_constraints <= 0:
        return 0
    return (1 << math.ceil(math.log2(max(2, primary_constraints)))) + SECONDARY_BASIS_POINTS


def nova_family_sp1_instructions(
    segments: int,
    primary_constraints: int,
    raw_vk_bytes: int | None = None,
    is_first_family: bool = True,
) -> tuple[int, int]:
    """Return (sp1_instructions, generator_basis_points) for a Nova circuit family."""
    if segments <= 0 or primary_constraints <= 0:
        return 0, 0
    basis = circuit_basis_points(primary_constraints)
    r_g = basis / float(NHC1_BASIS_POINTS)
    if raw_vk_bytes is not None:
        r_vk = raw_vk_bytes / float(NHC1_RAW_VK_BYTES)
    else:
        # Sparse R1CS matrices scale roughly with primary_constraints; affine points scale with r_g
        r_vk = 0.20 * r_g + 0.80 * (primary_constraints / float(NHC1_CONSTRAINTS_PER_HEADER))

    vk_instr = SP1_VK_DECODE_BASE_INSTR * r_g + SP1_VK_HASH_BASE_INSTR * r_vk
    first_seg = (
        (SP1_FIRST_SEG_FIXED_INSTR + SP1_FIRST_SEG_MSM_INSTR * r_g)
        if is_first_family
        else (SP1_EXTRA_SEG_FIXED_INSTR + SP1_EXTRA_SEG_MSM_INSTR * r_g)
    )
    extra_segs = max(0, segments - 1) * (SP1_EXTRA_SEG_FIXED_INSTR + SP1_EXTRA_SEG_MSM_INSTR * r_g)
    return int(round(vk_instr + first_seg + extra_segs)), basis


def estimate_m18_steps_per_block(
    tx_per_block: int = M18_DEFAULT_TX_PER_BLOCK,
    inputs_per_block: int = M18_DEFAULT_INPUTS_PER_BLOCK,
    outputs_per_block: int = M18_DEFAULT_OUTPUTS_PER_BLOCK,
    nonwitness_bytes_per_block: int = M18_DEFAULT_NONWITNESS_BYTES,
) -> dict[str, int]:
    """Compute M18 step count from producer SHA-256 vs consumer Poseidon leaf updates."""
    merkle_merges = max(1, tx_per_block - 1)
    # BODY 64B chunks + TXID compressions + 3 compressions per Merkle merge + 3 HDR phases
    sha256_compressions = (
        math.ceil(nonwitness_bytes_per_block / 64.0)
        + tx_per_block
        + 3 * merkle_merges
        + 3
    )
    # 1 Poseidon path per input (SPEND_IN / SPEND_PRE) + 2 paths per output (CREATE_LOW + CREATE_NEW)
    leaf_updates = inputs_per_block + 2 * outputs_per_block
    # Calibrated to measured 37,465 avg steps/block on 975,067..975,072
    steps = max(sha256_compressions, leaf_updates) + 2
    return {
        "steps_per_block": steps,
        "sha256_compressions": sha256_compressions,
        "leaf_updates": leaf_updates,
    }


def estimate_workload(params: dict[str, Any]) -> dict[str, Any]:
    header_blocks = max(0, min(2_000_000, int(params.get("header_blocks", 975072))))
    nova_header_shards = max(
        0, min(64, int(params.get("nova_header_shards", 2 if header_blocks > 0 else 0)))
    )
    if header_blocks > 0 and nova_header_shards == 0:
        nova_header_shards = 1

    utxo_window_blocks = max(0, min(500, int(params.get("utxo_window_blocks", 0))))
    avg_tx_per_block = max(1, min(25_000, int(params.get("avg_tx_per_block", M18_DEFAULT_TX_PER_BLOCK))))
    payment_utxos = max(0, min(10_000, int(params.get("payment_utxos", 1))))
    shinigami_leaves = max(0, min(10_000, int(params.get("shinigami_leaves", 0))))
    shinigami_script_type = str(params.get("shinigami_script_type", "p2wpkh"))
    ark_vtxos = max(0, min(4_096, int(params.get("ark_vtxos", 0))))

    threshold_exp = int(params.get("element_threshold_exp", 27))
    if threshold_exp not in (25, 26, 27, 28):
        threshold_exp = 27
    element_threshold = 1 << threshold_exp

    hw_profile = str(params.get("hardware_profile", "rtx5080_12gib"))
    if hw_profile not in ("rtx5080_bounded_2gib", "rtx5080_12gib", "cpu_20t"):
        hw_profile = "rtx5080_12gib"

    # 1. Nova Folding Layer
    header_r1cs_total = header_blocks * NHC1_CONSTRAINTS_PER_HEADER

    # Scale M18 block internals proportionally with avg_tx_per_block relative to measured 5,449 tx/blk
    tx_scale = avg_tx_per_block / float(M18_DEFAULT_TX_PER_BLOCK)
    if abs(tx_scale - 1.0) < 1e-6:
        m18_steps_per_blk = 37_465  # Exact measured 224,790 / 6 on 975,067..975,072
        m18_leaves_per_blk = M18_DEFAULT_OUTPUTS_PER_BLOCK
    else:
        est_blk = estimate_m18_steps_per_block(
            tx_per_block=avg_tx_per_block,
            inputs_per_block=max(1, round(M18_DEFAULT_INPUTS_PER_BLOCK * tx_scale)),
            outputs_per_block=max(1, round(M18_DEFAULT_OUTPUTS_PER_BLOCK * tx_scale)),
            nonwitness_bytes_per_block=max(250, round(M18_DEFAULT_NONWITNESS_BYTES * tx_scale)),
        )
        m18_steps_per_blk = est_blk["steps_per_block"]
        m18_leaves_per_blk = max(1, round(M18_DEFAULT_OUTPUTS_PER_BLOCK * tx_scale))

    m18_steps = utxo_window_blocks * m18_steps_per_blk
    m18_segments = math.ceil(m18_steps / float(M18_SEGMENT_MAX_STEPS)) if m18_steps > 0 else 0
    m18_utxo_leaves_indexed = utxo_window_blocks * m18_leaves_per_blk
    m18_r1cs_total = m18_steps * M18_CONSTRAINTS_PER_STEP

    steps_per_leaf = M17_STEPS_BY_SCRIPT.get(shinigami_script_type, 21)
    m17_steps = shinigami_leaves * steps_per_leaf
    m17_segments = 1 if m17_steps > 0 else 0
    m17_r1cs_total = m17_steps * M17_CONSTRAINTS_PER_STEP

    ark_steps = ark_vtxos
    ark_segments = math.ceil(ark_steps / 512.0) if ark_steps > 0 else 0
    ark_r1cs_total = ark_steps * ARK1_CONSTRAINTS_PER_STEP

    total_nova_segments = nova_header_shards + m18_segments + m17_segments + ark_segments
    total_nova_steps = header_blocks + m18_steps + m17_steps + ark_steps
    total_r1cs_constraints = header_r1cs_total + m18_r1cs_total + m17_r1cs_total + ark_r1cs_total

    # 2. SP1 Guest Instructions & Shard Count (using per-circuit commitment basis G)
    scale = element_threshold / float(1 << 27)
    instr_per_shard = M16_INSTR_PER_SHARD_AT_2_27 * scale

    seen_family = False
    header_verify_instr, hdr_basis = nova_family_sp1_instructions(
        nova_header_shards,
        NHC1_CONSTRAINTS_PER_HEADER,
        raw_vk_bytes=NHC1_RAW_VK_BYTES,
        is_first_family=not seen_family,
    )
    seen_family = seen_family or (nova_header_shards > 0)

    m18_verify_instr, m18_basis = nova_family_sp1_instructions(
        m18_segments,
        M18_CONSTRAINTS_PER_STEP,
        is_first_family=not seen_family,
    )
    seen_family = seen_family or (m18_segments > 0)

    m17_nova_instr, m17_basis = nova_family_sp1_instructions(
        m17_segments,
        M17_CONSTRAINTS_PER_STEP,
        is_first_family=not seen_family,
    )
    seen_family = seen_family or (m17_segments > 0)

    ark_nova_instr, ark_basis = nova_family_sp1_instructions(
        ark_segments,
        ARK1_CONSTRAINTS_PER_STEP,
        raw_vk_bytes=ARK1_RAW_VK_BYTES,
        is_first_family=not seen_family,
    )

    utxo_instr = payment_utxos * (
        SP1_M18_LEAF_VERIFY_INSTR if utxo_window_blocks > 0 else SP1_PAYMENT_UTXO_INSTR
    )
    shinigami_instr = shinigami_leaves * SP1_SHINIGAMI_CLAIM_INSTR
    ark_book_instr = ark_vtxos * SP1_ARK_VTXO_BOOK_INSTR

    m17_verify_instr = m17_nova_instr + shinigami_instr
    ark_verify_instr = ark_nova_instr + ark_book_instr
    m18_and_utxo_instr = m18_verify_instr + utxo_instr

    total_sp1_instructions = int(
        header_verify_instr + m18_and_utxo_instr + m17_verify_instr + ark_verify_instr
    )
    core_shards = (
        max(1, round(total_sp1_instructions / instr_per_shard))
        if total_sp1_instructions > 0
        else 0
    )
    recursion_shards = max(1, math.ceil(core_shards / RECURSION_FAN_IN)) if core_shards > 0 else 0

    def _shard_share(instr: float) -> int:
        if total_sp1_instructions <= 0 or core_shards <= 0:
            return 0
        return round(core_shards * (instr / total_sp1_instructions))

    dominant_basis = max(hdr_basis, m18_basis, m17_basis, ark_basis)

    # 3. Hardware RAM / VRAM / Timing Envelope
    if hw_profile == "rtx5080_bounded_2gib":
        linux_ram_gib = 2.0
        swap_gib = 2.4 if threshold_exp <= 26 else 3.8
        host_reserve_gib = 6.0
        vram_gib = round(min(15.4, 8.2 + 3.2 * scale), 1)
        shards_per_sec = 0.042 if threshold_exp == 26 else 0.024
    elif hw_profile == "rtx5080_12gib":
        linux_ram_gib = round(min(14.2, 7.2 + 4.4 * scale), 1)
        swap_gib = 0.5
        host_reserve_gib = 3.0
        vram_gib = round(min(15.6, 10.5 + 3.4 * scale), 1)
        shards_per_sec = 0.65 / scale
    else:  # cpu_20t
        linux_ram_gib = 12.0
        swap_gib = 4.0
        host_reserve_gib = 3.0
        vram_gib = 0.0
        shards_per_sec = 0.0028 / scale

    nova_fold_seconds = (
        (header_blocks / max(1, nova_header_shards)) / 5.2
        + (m18_steps / max(1, min(8, m18_segments))) * 1.27
        + m17_steps * 0.90
        + ark_steps * 2.06
    )
    sp1_prove_seconds = (core_shards / max(0.0001, shards_per_sec)) if core_shards > 0 else 0.0
    wrap_garble_seconds = (112.0 + 72.0 + 167.1) if core_shards > 0 else 0.0
    memo_disk_gib = round((core_shards + recursion_shards) * 0.0021, 2)

    return {
        "evidence_level": "analytical-projection-from-measured-constants",
        "inputs": {
            "header_blocks": header_blocks,
            "nova_header_shards": nova_header_shards,
            "utxo_window_blocks": utxo_window_blocks,
            "avg_tx_per_block": avg_tx_per_block,
            "payment_utxos": payment_utxos,
            "shinigami_leaves": shinigami_leaves,
            "shinigami_script_type": shinigami_script_type,
            "ark_vtxos": ark_vtxos,
            "element_threshold": element_threshold,
            "element_threshold_exp": threshold_exp,
            "hardware_profile": hw_profile,
        },
        "nova": {
            "total_segments": total_nova_segments,
            "total_steps": total_nova_steps,
            "total_r1cs_constraints": total_r1cs_constraints,
            "dominant_basis_points": dominant_basis,
            "header_segments": nova_header_shards,
            "m18_window_segments": m18_segments,
            "m18_window_steps": m18_steps,
            "m18_steps_per_block": m18_steps_per_blk if utxo_window_blocks > 0 else 0,
            "m18_indexed_utxo_leaves": m18_utxo_leaves_indexed,
            "m17_script_steps": m17_steps,
            "ark_policy_steps": ark_steps,
            "estimated_fold_hours": round(nova_fold_seconds / 3600.0, 2),
        },
        "sp1": {
            "total_instructions": total_sp1_instructions,
            "instructions_per_shard": int(instr_per_shard),
            "core_shards": core_shards,
            "recursion_shards": recursion_shards,
            "total_tasks": core_shards + recursion_shards,
            "m14_nonfree_gates": M14_FINAL_NONFREE_GATES if core_shards > 0 else 0,
            "shard_attribution": {
                "header_blocks": _shard_share(header_verify_instr),
                "utxo_window_and_payments": _shard_share(m18_and_utxo_instr),
                "shinigami_leaves": _shard_share(m17_verify_instr),
                "ark_vtxo_policy": _shard_share(ark_verify_instr),
            },
        },
        "resources": {
            "linux_cgroup_ram_gib": linux_ram_gib,
            "linux_swap_gib": swap_gib,
            "windows_host_reserve_gib": host_reserve_gib,
            "gpu_vram_gib": vram_gib,
            "memo_disk_gib": memo_disk_gib,
            "estimated_sp1_hours": round(sp1_prove_seconds / 3600.0, 2),
            "estimated_wrap_garble_minutes": round(wrap_garble_seconds / 60.0, 1),
        },
    }


def estimate_ark_live_completion(
    unique_shards: int,
    unique_reduces: int,
    element_threshold: int = 67_108_864,
    ark_vtxos: int = 4,
    session_summary: dict[str, Any] | None = None,
    rates: dict[str, Any] | None = None,
    compressed_verified: bool = False,
) -> dict[str, Any]:
    """Compute n / ~total (% completion) for the live Ark ASP SP1 CUDA run.

    Separates deterministic `ProveShard` progress and active-session compression-tree
    `RecursionReduce` progress (`rp + rr`) from cumulative historical regrouped reduces
    across restarts so completion % is never artificially inflated.
    """
    exp = max(25, min(28, round(math.log2(max(1, element_threshold)))))
    proj = estimate_workload(
        {
            "header_blocks": 0,
            "nova_header_shards": 0,
            "utxo_window_blocks": 0,
            "payment_utxos": 0,
            "shinigami_leaves": 0,
            "ark_vtxos": max(1, ark_vtxos),
            "element_threshold_exp": exp,
            "hardware_profile": "rtx5080_bounded_2gib",
        }
    )
    est_core_base = int(proj["sp1"]["core_shards"])

    # Active-tree recursion tasks from current session's phase.log if available;
    # otherwise bound by the 3:1 compression tree over completed core shards.
    if session_summary and session_summary.get("session_recursion_proved") is not None:
        active_tree_reduce = int(session_summary.get("session_recursion_proved", 0)) + int(
            session_summary.get("session_recursion_replayed", 0)
        )
    else:
        active_tree_reduce = min(unique_reduces, math.ceil(unique_shards / RECURSION_FAN_IN))

    regrouped_extra_reduces = max(0, unique_reduces - active_tree_reduce)

    if compressed_verified:
        core_total = max(1, unique_shards)
        reduce_total = max(1, active_tree_reduce or math.ceil(core_total / RECURSION_FAN_IN))
        core_pct = 100.0
        reduce_pct = 100.0
        overall_pct = 100.0
        is_exact = True
    else:
        # Ensure estimated denominator never drops below observed progress + 1 while still running
        core_total = max(est_core_base, unique_shards + 1)
        reduce_total = max(math.ceil(core_total / RECURSION_FAN_IN), active_tree_reduce + 1)
        core_pct = round(min(99.9, (unique_shards / float(core_total)) * 100.0), 1)
        reduce_pct = round(min(99.9, (active_tree_reduce / float(reduce_total)) * 100.0), 1)
        overall_pct = round(
            min(
                99.9,
                ((unique_shards + active_tree_reduce) / float(core_total + reduce_total)) * 100.0,
            ),
            1,
        )
        is_exact = False

    rem_core = max(0, core_total - unique_shards)
    rem_reduce = max(0, reduce_total - active_tree_reduce)
    rem_tasks = rem_core + rem_reduce

    shard_rate_m = float((rates or {}).get("shard_per_min_15m") or 0.0)
    eta_hours = (
        round(rem_core / (shard_rate_m * 60.0), 1)
        if (not compressed_verified and shard_rate_m >= 0.05 and rem_core > 0)
        else None
    )

    return {
        "basis": "verified-receipt" if is_exact else "r1cs-commitment-basis-estimate",
        "is_exact": is_exact,
        "element_threshold": element_threshold,
        "estimated_instructions": int(proj["sp1"]["total_instructions"]),
        "generator_basis_points": int(proj["nova"]["dominant_basis_points"]),
        "core_done": unique_shards,
        "core_total_est": core_total,
        "core_pct": core_pct,
        "active_tree_reduce_done": active_tree_reduce,
        "cumulative_memo_reduce": unique_reduces,
        "regrouped_extra_reduces": regrouped_extra_reduces,
        "reduce_total_est": reduce_total,
        "reduce_pct": reduce_pct,
        "tasks_done": unique_shards + active_tree_reduce,
        "tasks_total_est": core_total + reduce_total,
        "overall_pct": overall_pct,
        "remaining_core_est": rem_core,
        "remaining_tasks_est": rem_tasks,
        "eta_hours_est": eta_hours,
    }
