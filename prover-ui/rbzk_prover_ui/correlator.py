"""Deterministic workload-to-recursive-shard and RAM/GPU envelope estimator.

All unit constants are taken directly from measured artifacts in
`integrations/bitvm3-nova` (`m15`, `m16`, `m17`, `m18`, `prover-gpu`) and `Ark/`.
Outputs are explicitly tagged `analytical-projection-from-measured-constants` so
they are never mistaken for verified proof receipts.
"""
from __future__ import annotations

import math
from typing import Any


# Measured repository constants
NHC1_CONSTRAINTS_PER_HEADER = 82_809
M18_CONSTRAINTS_PER_STEP = 51_404
M18_AVG_STEPS_PER_BLOCK = 37_465  # 224,790 / 6 measured on mainnet 975,067..975,072
M18_AVG_LEAVES_PER_BLOCK = 12_432  # 74,592 / 6 measured
M17_CONSTRAINTS_PER_STEP = 6_808
M17_STEPS_BY_SCRIPT = {
    "p2wpkh": 21,
    "p2pkh": 10,
    "p2wsh": 17,
    "p2sh_multisig": 31,
    "p2sh_p2wpkh": 30,
    "taproot_vtxo_exit": 42,  # M17-equivalent step envelope + claim check
}
ARK1_CONSTRAINTS_PER_STEP = 19_113

# Measured SP1 6.9 instruction model (from M15 + M16 README measurements):
# - 1 Nova verifier segment (M15 raw VK): 21.2e9 instructions total
#   = 4.82e9 VK decode+hash + 16.38e9 first Nova CompressedSNARK verification
# - 2 Nova verifier segments (M16 mainnet): 34.0556e9 instructions total
#   => marginal Nova segment inside SP1 = ~12.88e9 instructions
# - SPV payment Merkle + non-witness tx check (PAY1): ~259,390 instructions/UTXO
# - Deferred Shinigami sigcheck/hash claim inside SP1 precompile: ~1,850,000 instructions/leaf
SP1_VK_OVERHEAD_INSTR = 4_820_000_000
SP1_FIRST_NOVA_SEG_INSTR = 16_380_000_000
SP1_EXTRA_NOVA_SEG_INSTR = 12_875_000_000
SP1_PAYMENT_UTXO_INSTR = 259_390
SP1_M18_LEAF_VERIFY_INSTR = 420_000  # Poseidon depth-20 path + SHA-256d tx binding
SP1_SHINIGAMI_CLAIM_INSTR = 1_850_000

# Measured shard & recursion ratios from M16 (34.0556e9 instr -> 13,290 core shards, 4,430 recursion tasks at 2^27)
M16_INSTR_PER_SHARD_AT_2_27 = 34_055_622_753 / 13_290.0  # ~2,562,500 instructions/shard
RECURSION_FAN_IN = 3.0  # 13,290 / 4,430 = 3.000 exact measured ratio!
M14_FINAL_NONFREE_GATES = 785_442_492


def estimate_workload(params: dict[str, Any]) -> dict[str, Any]:
    header_blocks = max(0, min(2_000_000, int(params.get("header_blocks", 975072))))
    nova_header_shards = max(0, min(64, int(params.get("nova_header_shards", 2 if header_blocks > 0 else 0))))
    if header_blocks > 0 and nova_header_shards == 0:
        nova_header_shards = 1

    utxo_window_blocks = max(0, min(500, int(params.get("utxo_window_blocks", 0))))
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
    m18_steps = utxo_window_blocks * M18_AVG_STEPS_PER_BLOCK
    m18_segments = math.ceil(m18_steps / 28_099) if m18_steps > 0 else 0
    m18_utxo_leaves_indexed = utxo_window_blocks * M18_AVG_LEAVES_PER_BLOCK
    m18_r1cs_total = m18_steps * M18_CONSTRAINTS_PER_STEP

    steps_per_leaf = M17_STEPS_BY_SCRIPT.get(shinigami_script_type, 21)
    m17_steps = shinigami_leaves * steps_per_leaf
    m17_segments = 1 if m17_steps > 0 else 0
    m17_r1cs_total = m17_steps * M17_CONSTRAINTS_PER_STEP

    ark_steps = ark_vtxos
    ark_segments = 1 if ark_steps > 0 else 0
    ark_r1cs_total = ark_steps * ARK1_CONSTRAINTS_PER_STEP

    total_nova_segments = nova_header_shards + m18_segments + m17_segments + ark_segments
    total_nova_steps = header_blocks + m18_steps + m17_steps + ark_steps
    total_r1cs_constraints = header_r1cs_total + m18_r1cs_total + m17_r1cs_total + ark_r1cs_total

    # 2. SP1 Guest Instructions & Shard Count
    # Scale instructions per shard linearly with element_threshold relative to 2^27
    scale = element_threshold / float(1 << 27)
    instr_per_shard = M16_INSTR_PER_SHARD_AT_2_27 * scale

    vk_families = sum(
        1 for x in (nova_header_shards, m18_segments, m17_segments, ark_segments) if x > 0
    )
    if total_nova_segments > 0:
        nova_verify_instr = (
            vk_families * SP1_VK_OVERHEAD_INSTR
            + SP1_FIRST_NOVA_SEG_INSTR
            + max(0, total_nova_segments - 1) * SP1_EXTRA_NOVA_SEG_INSTR
        )
    else:
        nova_verify_instr = 0

    utxo_instr = payment_utxos * (
        SP1_M18_LEAF_VERIFY_INSTR if utxo_window_blocks > 0 else SP1_PAYMENT_UTXO_INSTR
    )
    shinigami_instr = shinigami_leaves * SP1_SHINIGAMI_CLAIM_INSTR
    ark_book_instr = ark_vtxos * 85_000

    total_sp1_instructions = int(nova_verify_instr + utxo_instr + shinigami_instr + ark_book_instr)
    core_shards = max(1, round(total_sp1_instructions / instr_per_shard)) if total_sp1_instructions > 0 else 0
    recursion_shards = max(1, round(core_shards / RECURSION_FAN_IN)) if core_shards > 0 else 0

    # Attribution of SP1 core shards by primitive family
    def _shard_share(instr: float) -> int:
        if total_sp1_instructions <= 0 or core_shards <= 0:
            return 0
        return round(core_shards * (instr / total_sp1_instructions))

    header_Verify_instr = (
        (SP1_VK_OVERHEAD_INSTR + SP1_FIRST_NOVA_SEG_INSTR + max(0, nova_header_shards - 1) * SP1_EXTRA_NOVA_SEG_INSTR)
        if nova_header_shards > 0
        else 0
    )
    m18_verify_instr = (
        (SP1_VK_OVERHEAD_INSTR + m18_segments * SP1_EXTRA_NOVA_SEG_INSTR)
        if m18_segments > 0
        else 0
    )
    m17_verify_instr = (
        (SP1_VK_OVERHEAD_INSTR + SP1_EXTRA_NOVA_SEG_INSTR + shinigami_instr)
        if m17_segments > 0
        else 0
    )
    ark_verify_instr = (
        (SP1_VK_OVERHEAD_INSTR + (SP1_FIRST_NOVA_SEG_INSTR if nova_header_shards == 0 else SP1_EXTRA_NOVA_SEG_INSTR) + ark_book_instr)
        if ark_segments > 0
        else 0
    )

    # 3. Hardware RAM / VRAM / Timing Envelope
    if hw_profile == "rtx5080_bounded_2gib":
        linux_ram_gib = 2.0
        swap_gib = 2.4 if threshold_exp <= 26 else 3.8
        host_reserve_gib = 6.0
        vram_gib = round(min(15.4, 8.2 + 3.2 * scale), 1)
        shards_per_sec = 0.085 if threshold_exp == 26 else 0.045
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
            "header_segments": nova_header_shards,
            "m18_window_segments": m18_segments,
            "m18_window_steps": m18_steps,
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
                "header_blocks": _shard_share(header_Verify_instr),
                "utxo_window_and_payments": _shard_share(m18_verify_instr + utxo_instr),
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
