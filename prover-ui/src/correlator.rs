//! Deterministic workload-to-recursive-shard and RAM/GPU envelope estimator.
//!
//! All unit constants match measured artifacts in `integrations/bitvm3-nova` (`m15`..`m18`,
//! `prover-gpu`) and `Ark/`. Outputs are tagged `analytical-projection-from-measured-constants`.

use std::collections::BTreeMap;

use serde_json::{json, Value};

pub const SECONDARY_NOVA_CONSTRAINTS: u64 = 10_349;
pub const SECONDARY_BASIS_POINTS: u64 = 16_384; // 2^ceil(log2(10_349))

pub const NHC1_CONSTRAINTS_PER_HEADER: u64 = 82_809;
pub const M18_CONSTRAINTS_PER_STEP: u64 = 51_404;
pub const M17_CONSTRAINTS_PER_STEP: u64 = 6_808;
pub const ARK1_CONSTRAINTS_PER_STEP: u64 = 19_113;

pub const M18_DEFAULT_TX_PER_BLOCK: u64 = 5_449;
pub const M18_DEFAULT_INPUTS_PER_BLOCK: u64 = 7_873;
pub const M18_DEFAULT_OUTPUTS_PER_BLOCK: u64 = 12_432;
pub const M18_DEFAULT_NONWITNESS_BYTES: u64 = 810_812;
pub const M18_SEGMENT_MAX_STEPS: u64 = 28_099;

pub const NHC1_BASIS_POINTS: u64 = 131_072 + SECONDARY_BASIS_POINTS; // 147,456
pub const NHC1_RAW_VK_BYTES: u64 = 46_916_520;
pub const ARK1_RAW_VK_BYTES: u64 = 22_483_808;

pub const SP1_VK_DECODE_BASE_INSTR: f64 = 2_040_000_000.0;
pub const SP1_VK_HASH_BASE_INSTR: f64 = 2_780_000_000.0;
pub const SP1_FIRST_SEG_FIXED_INSTR: f64 = 1_200_000_000.0;
pub const SP1_FIRST_SEG_MSM_INSTR: f64 = 15_180_000_000.0;
pub const SP1_EXTRA_SEG_FIXED_INSTR: f64 = 950_000_000.0;
pub const SP1_EXTRA_SEG_MSM_INSTR: f64 = 11_925_000_000.0;

pub const SP1_PAYMENT_UTXO_INSTR: u64 = 259_390;
pub const SP1_M18_LEAF_VERIFY_INSTR: u64 = 420_000;
pub const SP1_SHINIGAMI_CLAIM_INSTR: u64 = 1_850_000;
pub const SP1_ARK_VTXO_BOOK_INSTR: u64 = 85_000;

pub const M16_INSTR_PER_SHARD_AT_2_27: f64 = 34_055_622_753.0 / 13_290.0;
pub const RECURSION_FAN_IN: f64 = 3.0;
pub const M14_FINAL_NONFREE_GATES: u64 = 785_442_492;

#[inline]
pub fn round_n(v: f64, decimals: i32) -> f64 {
    let f = 10f64.powi(decimals);
    (v * f).round() / f
}

pub fn circuit_basis_points(primary_constraints: u64) -> u64 {
    if primary_constraints == 0 {
        return 0;
    }
    let p = primary_constraints.max(2).next_power_of_two();
    p + SECONDARY_BASIS_POINTS
}

pub fn nova_family_sp1_instructions(
    segments: u64,
    primary_constraints: u64,
    raw_vk_bytes: Option<u64>,
    is_first_family: bool,
) -> (u64, u64) {
    if segments == 0 || primary_constraints == 0 {
        return (0, 0);
    }
    let basis = circuit_basis_points(primary_constraints);
    let r_g = (basis as f64) / (NHC1_BASIS_POINTS as f64);
    let r_vk = match raw_vk_bytes {
        Some(b) => (b as f64) / (NHC1_RAW_VK_BYTES as f64),
        None => {
            0.20 * r_g
                + 0.80 * ((primary_constraints as f64) / (NHC1_CONSTRAINTS_PER_HEADER as f64))
        }
    };

    let vk_instr = SP1_VK_DECODE_BASE_INSTR * r_g + SP1_VK_HASH_BASE_INSTR * r_vk;
    let first_seg = if is_first_family {
        SP1_FIRST_SEG_FIXED_INSTR + SP1_FIRST_SEG_MSM_INSTR * r_g
    } else {
        SP1_EXTRA_SEG_FIXED_INSTR + SP1_EXTRA_SEG_MSM_INSTR * r_g
    };
    let extra_segs = (segments.saturating_sub(1) as f64)
        * (SP1_EXTRA_SEG_FIXED_INSTR + SP1_EXTRA_SEG_MSM_INSTR * r_g);
    ((vk_instr + first_seg + extra_segs).round() as u64, basis)
}

pub fn estimate_m18_steps_per_block(
    tx_per_block: u64,
    inputs_per_block: u64,
    outputs_per_block: u64,
    nonwitness_bytes_per_block: u64,
) -> (u64, u64, u64) {
    let merkle_merges = tx_per_block.saturating_sub(1).max(1);
    let sha256_compressions =
        nonwitness_bytes_per_block.div_ceil(64) + tx_per_block + 3 * merkle_merges + 3;
    let leaf_updates = inputs_per_block + 2 * outputs_per_block;
    let steps = sha256_compressions.max(leaf_updates) + 2;
    (steps, sha256_compressions, leaf_updates)
}

fn get_u64_param(params: &Value, key: &str, default: u64) -> Result<u64, String> {
    let Some(v) = params.get(key) else {
        return Ok(default);
    };
    if v.is_null() {
        return Ok(default);
    }
    if let Some(u) = v.as_u64() {
        return Ok(u);
    }
    if let Some(i) = v.as_i64() {
        return Ok(i.max(0) as u64);
    }
    if let Some(f) = v.as_f64() {
        if f.is_finite() {
            return Ok(f.max(0.0).round() as u64);
        }
    }
    if let Some(s) = v.as_str() {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return Ok(default);
        }
        return trimmed
            .parse::<i64>()
            .map(|i| i.max(0) as u64)
            .map_err(|e| format!("invalid integer for {key}: {e}"));
    }
    Err(format!("invalid parameter type for {key}"))
}

fn get_str_param<'a>(params: &'a Value, key: &str, default: &'a str) -> String {
    params
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or(default)
        .to_string()
}

fn m17_steps_for_script(script_type: &str) -> u64 {
    match script_type {
        "p2wpkh" => 21,
        "p2pkh" => 10,
        "p2wsh" => 17,
        "p2sh_multisig" => 31,
        "p2sh_p2wpkh" => 30,
        "taproot_vtxo_exit" => 42,
        _ => 21,
    }
}

pub fn estimate_workload(params: &Value) -> Result<Value, String> {
    let header_blocks = get_u64_param(params, "header_blocks", 975_072)?.min(2_000_000);
    let default_hdr_shards = if header_blocks > 0 { 2 } else { 0 };
    let mut nova_header_shards =
        get_u64_param(params, "nova_header_shards", default_hdr_shards)?.min(64);
    if header_blocks > 0 && nova_header_shards == 0 {
        nova_header_shards = 1;
    }

    let utxo_window_blocks = get_u64_param(params, "utxo_window_blocks", 0)?.min(500);
    let avg_tx_per_block =
        get_u64_param(params, "avg_tx_per_block", M18_DEFAULT_TX_PER_BLOCK)?.clamp(1, 25_000);
    let payment_utxos = get_u64_param(params, "payment_utxos", 1)?.min(10_000);
    let shinigami_leaves = get_u64_param(params, "shinigami_leaves", 0)?.min(10_000);
    let shinigami_script_type = get_str_param(params, "shinigami_script_type", "p2wpkh");
    let ark_vtxos = get_u64_param(params, "ark_vtxos", 0)?.min(4_096);

    let mut threshold_exp = get_u64_param(params, "element_threshold_exp", 27)?;
    if !matches!(threshold_exp, 25..=28) {
        threshold_exp = 27;
    }
    let element_threshold: u64 = 1u64 << threshold_exp;

    let mut hw_profile = get_str_param(params, "hardware_profile", "rtx5080_12gib");
    if !matches!(
        hw_profile.as_str(),
        "rtx5080_bounded_2gib" | "rtx5080_12gib" | "cpu_20t"
    ) {
        hw_profile = "rtx5080_12gib".to_string();
    }

    // 1. Nova Folding Layer
    let header_r1cs_total = header_blocks * NHC1_CONSTRAINTS_PER_HEADER;

    let tx_scale = (avg_tx_per_block as f64) / (M18_DEFAULT_TX_PER_BLOCK as f64);
    let (m18_steps_per_blk, m18_leaves_per_blk) = if (tx_scale - 1.0).abs() < 1e-6 {
        (37_465u64, M18_DEFAULT_OUTPUTS_PER_BLOCK)
    } else {
        let inp = ((M18_DEFAULT_INPUTS_PER_BLOCK as f64) * tx_scale)
            .round()
            .max(1.0) as u64;
        let outp = ((M18_DEFAULT_OUTPUTS_PER_BLOCK as f64) * tx_scale)
            .round()
            .max(1.0) as u64;
        let nwb = ((M18_DEFAULT_NONWITNESS_BYTES as f64) * tx_scale)
            .round()
            .max(250.0) as u64;
        let (steps, _, _) = estimate_m18_steps_per_block(avg_tx_per_block, inp, outp, nwb);
        (steps, outp)
    };

    let m18_steps = utxo_window_blocks * m18_steps_per_blk;
    let m18_segments = if m18_steps > 0 {
        m18_steps.div_ceil(M18_SEGMENT_MAX_STEPS)
    } else {
        0
    };
    let m18_utxo_leaves_indexed = utxo_window_blocks * m18_leaves_per_blk;
    let m18_r1cs_total = m18_steps * M18_CONSTRAINTS_PER_STEP;

    let steps_per_leaf = m17_steps_for_script(&shinigami_script_type);
    let m17_steps = shinigami_leaves * steps_per_leaf;
    let m17_segments = u64::from(m17_steps > 0);
    let m17_r1cs_total = m17_steps * M17_CONSTRAINTS_PER_STEP;

    let ark_steps = ark_vtxos;
    let ark_segments = if ark_steps > 0 {
        ark_steps.div_ceil(512)
    } else {
        0
    };
    let ark_r1cs_total = ark_steps * ARK1_CONSTRAINTS_PER_STEP;

    let total_nova_segments = nova_header_shards + m18_segments + m17_segments + ark_segments;
    let total_nova_steps = header_blocks + m18_steps + m17_steps + ark_steps;
    let total_r1cs_constraints =
        header_r1cs_total + m18_r1cs_total + m17_r1cs_total + ark_r1cs_total;

    // 2. SP1 Guest Instructions & Shard Count
    let scale = (element_threshold as f64) / ((1u64 << 27) as f64);
    let instr_per_shard = M16_INSTR_PER_SHARD_AT_2_27 * scale;

    let mut seen_family = false;
    let (header_verify_instr, hdr_basis) = nova_family_sp1_instructions(
        nova_header_shards,
        NHC1_CONSTRAINTS_PER_HEADER,
        Some(NHC1_RAW_VK_BYTES),
        !seen_family,
    );
    seen_family |= nova_header_shards > 0;

    let (m18_verify_instr, m18_basis) =
        nova_family_sp1_instructions(m18_segments, M18_CONSTRAINTS_PER_STEP, None, !seen_family);
    seen_family |= m18_segments > 0;

    let (m17_nova_instr, m17_basis) =
        nova_family_sp1_instructions(m17_segments, M17_CONSTRAINTS_PER_STEP, None, !seen_family);
    seen_family |= m17_segments > 0;

    let (ark_nova_instr, ark_basis) = nova_family_sp1_instructions(
        ark_segments,
        ARK1_CONSTRAINTS_PER_STEP,
        Some(ARK1_RAW_VK_BYTES),
        !seen_family,
    );

    let utxo_instr = payment_utxos
        * if utxo_window_blocks > 0 {
            SP1_M18_LEAF_VERIFY_INSTR
        } else {
            SP1_PAYMENT_UTXO_INSTR
        };
    let shinigami_instr = shinigami_leaves * SP1_SHINIGAMI_CLAIM_INSTR;
    let ark_book_instr = ark_vtxos * SP1_ARK_VTXO_BOOK_INSTR;

    let m17_verify_instr = m17_nova_instr + shinigami_instr;
    let ark_verify_instr = ark_nova_instr + ark_book_instr;
    let m18_and_utxo_instr = m18_verify_instr + utxo_instr;

    let total_sp1_instructions =
        header_verify_instr + m18_and_utxo_instr + m17_verify_instr + ark_verify_instr;
    let core_shards = if total_sp1_instructions > 0 {
        ((total_sp1_instructions as f64) / instr_per_shard)
            .round()
            .max(1.0) as u64
    } else {
        0
    };
    let recursion_shards = if core_shards > 0 {
        ((core_shards as f64) / RECURSION_FAN_IN).ceil().max(1.0) as u64
    } else {
        0
    };

    let shard_share = |instr: u64| -> u64 {
        if total_sp1_instructions == 0 || core_shards == 0 {
            return 0;
        }
        ((core_shards as f64) * ((instr as f64) / (total_sp1_instructions as f64))).round() as u64
    };

    let dominant_basis = hdr_basis.max(m18_basis).max(m17_basis).max(ark_basis);

    // 3. Hardware RAM / VRAM / Timing Envelope
    let (linux_ram_gib, swap_gib, host_reserve_gib, vram_gib, shards_per_sec) =
        match hw_profile.as_str() {
            "rtx5080_bounded_2gib" => (
                2.0,
                if threshold_exp <= 26 { 2.4 } else { 3.8 },
                6.0,
                round_n((8.2 + 3.2 * scale).min(15.4), 1),
                if threshold_exp == 26 { 0.042 } else { 0.024 },
            ),
            "rtx5080_12gib" => (
                round_n((7.2 + 4.4 * scale).min(14.2), 1),
                0.5,
                3.0,
                round_n((10.5 + 3.4 * scale).min(15.6), 1),
                0.65 / scale,
            ),
            _ => (12.0, 4.0, 3.0, 0.0, 0.0028 / scale),
        };

    let nova_fold_seconds = ((header_blocks as f64) / (nova_header_shards.max(1) as f64)) / 5.2
        + ((m18_steps as f64) / (m18_segments.clamp(1, 8) as f64)) * 1.27
        + (m17_steps as f64) * 0.90
        + (ark_steps as f64) * 2.06;
    let sp1_prove_seconds = if core_shards > 0 {
        (core_shards as f64) / shards_per_sec.max(0.0001)
    } else {
        0.0
    };
    let wrap_garble_seconds = if core_shards > 0 {
        112.0 + 72.0 + 167.1
    } else {
        0.0
    };
    let memo_disk_gib = round_n(((core_shards + recursion_shards) as f64) * 0.0021, 2);

    Ok(json!({
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
            "m18_steps_per_block": if utxo_window_blocks > 0 { m18_steps_per_blk } else { 0 },
            "m18_indexed_utxo_leaves": m18_utxo_leaves_indexed,
            "m17_script_steps": m17_steps,
            "ark_policy_steps": ark_steps,
            "estimated_fold_hours": round_n(nova_fold_seconds / 3600.0, 2),
        },
        "sp1": {
            "total_instructions": total_sp1_instructions,
            "instructions_per_shard": instr_per_shard as u64,
            "core_shards": core_shards,
            "recursion_shards": recursion_shards,
            "total_tasks": core_shards + recursion_shards,
            "m14_nonfree_gates": if core_shards > 0 { M14_FINAL_NONFREE_GATES } else { 0 },
            "shard_attribution": {
                "header_blocks": shard_share(header_verify_instr),
                "utxo_window_and_payments": shard_share(m18_and_utxo_instr),
                "shinigami_leaves": shard_share(m17_verify_instr),
                "ark_vtxo_policy": shard_share(ark_verify_instr),
            },
        },
        "resources": {
            "linux_cgroup_ram_gib": linux_ram_gib,
            "linux_swap_gib": swap_gib,
            "windows_host_reserve_gib": host_reserve_gib,
            "gpu_vram_gib": vram_gib,
            "memo_disk_gib": memo_disk_gib,
            "estimated_sp1_hours": round_n(sp1_prove_seconds / 3600.0, 2),
            "estimated_wrap_garble_minutes": round_n(wrap_garble_seconds / 60.0, 1),
        },
    }))
}

#[derive(Debug, Clone)]
pub struct ArkLiveCompletionArgs<'a> {
    pub unique_shards: u64,
    pub unique_reduces: u64,
    pub element_threshold: u64,
    pub ark_vtxos: u64,
    pub session_summary: Option<&'a Value>,
    pub rates: Option<&'a BTreeMap<String, f64>>,
    pub mean_proved_ms: Option<&'a BTreeMap<String, u64>>,
    pub in_flight_elapsed_s: f64,
    pub expected_task_s: f64,
    pub compressed_verified: bool,
    pub all_verified: bool,
}

pub fn estimate_ark_live_completion(args: ArkLiveCompletionArgs<'_>) -> Value {
    let exp = ((args.element_threshold.max(1) as f64).log2().round() as u64).clamp(25, 28);
    let proj = estimate_workload(&json!({
        "header_blocks": 0,
        "nova_header_shards": 0,
        "utxo_window_blocks": 0,
        "payment_utxos": 0,
        "shinigami_leaves": 0,
        "ark_vtxos": args.ark_vtxos.max(1),
        "element_threshold_exp": exp,
        "hardware_profile": "rtx5080_bounded_2gib",
    }))
    .expect("static ark projection valid");

    let est_core_base = proj["sp1"]["core_shards"].as_u64().unwrap_or(1);
    let est_instr = proj["sp1"]["total_instructions"].as_u64().unwrap_or(0);
    let gen_basis = proj["nova"]["dominant_basis_points"].as_u64().unwrap_or(0);

    let active_tree_reduce = if let Some(ss) = args.session_summary {
        if let Some(rp) = ss.get("session_recursion_proved").and_then(Value::as_u64) {
            let rr = ss
                .get("session_recursion_replayed")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            rp + rr
        } else {
            args.unique_reduces
                .min(((args.unique_shards as f64) / RECURSION_FAN_IN).ceil() as u64)
        }
    } else {
        args.unique_reduces
            .min(((args.unique_shards as f64) / RECURSION_FAN_IN).ceil() as u64)
    };

    let regrouped_extra_reduces = args.unique_reduces.saturating_sub(active_tree_reduce);

    let (core_total, reduce_total, core_pct, reduce_pct, overall_pct, is_exact) =
        if args.compressed_verified {
            let ct = args.unique_shards.max(1);
            let rt = if active_tree_reduce > 0 {
                active_tree_reduce
            } else {
                (((ct as f64) / RECURSION_FAN_IN).ceil() as u64).max(1)
            };
            (ct, rt, 100.0, 100.0, 100.0, true)
        } else {
            let ct = est_core_base.max(args.unique_shards + 1);
            let rt = (((ct as f64) / RECURSION_FAN_IN).ceil() as u64).max(active_tree_reduce + 1);
            let cp = round_n(
                (((args.unique_shards as f64) / (ct as f64)) * 100.0).min(99.9),
                1,
            );
            let rp = round_n(
                (((active_tree_reduce as f64) / (rt as f64)) * 100.0).min(99.9),
                1,
            );
            let op = round_n(
                ((((args.unique_shards + active_tree_reduce) as f64) / ((ct + rt) as f64)) * 100.0)
                    .min(99.9),
                1,
            );
            (ct, rt, cp, rp, op, false)
        };

    let rem_core = core_total.saturating_sub(args.unique_shards);
    let rem_reduce = reduce_total.saturating_sub(active_tree_reduce);
    let rem_tasks = rem_core + rem_reduce;

    let rate_30m = args
        .rates
        .and_then(|r| r.get("shard_per_min_30m"))
        .copied()
        .unwrap_or(0.0);
    let rate_15m = args
        .rates
        .and_then(|r| r.get("shard_per_min_15m"))
        .copied()
        .unwrap_or(0.0);
    let shard_rate_m = if rate_30m >= 0.05 { rate_30m } else { rate_15m };

    let mut mean_shard_s = (args
        .mean_proved_ms
        .and_then(|m| m.get("shard"))
        .copied()
        .unwrap_or(0) as f64)
        / 1000.0;
    let mut mean_reduce_s = (args
        .mean_proved_ms
        .and_then(|m| m.get("reduce"))
        .copied()
        .unwrap_or(0) as f64)
        / 1000.0;
    if mean_reduce_s <= 1.0 {
        mean_reduce_s = 36.0;
    }
    if mean_shard_s <= 1.0 {
        mean_shard_s = 45.0;
    }

    let m13_m14_tail_s = 448.0;
    let tree_levels = ((core_total.max(3) as f64).ln() / RECURSION_FAN_IN.ln())
        .ceil()
        .max(3.0);
    let tree_tail_s = round_n(tree_levels * mean_reduce_s, 1);
    let in_flight_credit_s = args
        .in_flight_elapsed_s
        .max(0.0)
        .min(args.expected_task_s.max(15.0));

    let (core_eta_s, sp1_eta_s, e2e_eta_s) = if args.all_verified {
        (0.0, 0.0, 0.0)
    } else if args.compressed_verified {
        (0.0, 0.0, m13_m14_tail_s)
    } else {
        let core_wall_rate_s = if shard_rate_m >= 0.05 {
            shard_rate_m / 60.0
        } else {
            1.0 / (mean_shard_s * 0.5).clamp(24.0, 60.0)
        };
        let (ce, se) = if rem_core > 0 {
            let ce = round_n(
                ((rem_core as f64) / core_wall_rate_s - in_flight_credit_s).max(0.0),
                1,
            );
            (ce, round_n(ce + tree_tail_s, 1))
        } else {
            let se = round_n(
                ((rem_reduce as f64) * mean_reduce_s - in_flight_credit_s).max(0.0),
                1,
            );
            (0.0, se)
        };
        (ce, se, round_n(se + m13_m14_tail_s, 1))
    };

    let eta_hours: Option<f64> = if sp1_eta_s > 0.0 {
        Some(round_n(sp1_eta_s / 3600.0, 1))
    } else {
        None
    };
    let next_task_rem_s = round_n(
        (args.expected_task_s - args.in_flight_elapsed_s).max(0.0),
        1,
    );

    json!({
        "basis": if is_exact { "verified-receipt" } else { "r1cs-commitment-basis-estimate" },
        "is_exact": is_exact,
        "element_threshold": args.element_threshold,
        "estimated_instructions": est_instr,
        "generator_basis_points": gen_basis,
        "core_done": args.unique_shards,
        "core_total_est": core_total,
        "core_pct": core_pct,
        "active_tree_reduce_done": active_tree_reduce,
        "cumulative_memo_reduce": args.unique_reduces,
        "regrouped_extra_reduces": regrouped_extra_reduces,
        "reduce_total_est": reduce_total,
        "reduce_pct": reduce_pct,
        "tasks_done": args.unique_shards + active_tree_reduce,
        "tasks_total_est": core_total + reduce_total,
        "overall_pct": overall_pct,
        "remaining_core_est": rem_core,
        "remaining_tasks_est": rem_tasks,
        "eta_hours_est": eta_hours,
        "core_eta_seconds": core_eta_s,
        "sp1_eta_seconds": sp1_eta_s,
        "e2e_eta_seconds": e2e_eta_s,
        "m13_m14_tail_seconds": m13_m14_tail_s,
        "next_task_eta_seconds": next_task_rem_s,
    })
}
