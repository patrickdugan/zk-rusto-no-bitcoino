//! Provenance-pinned campaign data loader for ZK Rusto no Bitcoino Prover UI.
//!
//! Dynamically reads live repository artifacts when available and falls back to
//! compile-time embedded provenance JSONs so `rbzk-prover-desktop.exe` remains
//! 100% portable when moved to Desktop or standalone directories.

use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::correlator::round_n;

fn default_ark_dir() -> PathBuf {
    if let Some(env_p) = std::env::var_os("RBZK_ARK_DIR") {
        return PathBuf::from(env_p);
    }
    let home = std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    home.join(r"Documents\Codex\2026-11-15\new-chat\outputs\zk-rusto-no-bitcoino-ark\Ark")
}

const EMBED_M13_PINS: &[u8] = include_bytes!("../../integrations/bitvm3-nova/m13/pins.json");
const EMBED_M16_STMT: &[u8] =
    include_bytes!("../../integrations/bitvm3-nova/m13/fixtures/m16-statement.json");
const EMBED_M14_RESULTS: &[u8] =
    include_bytes!("../../integrations/bitvm3-nova/m14/circuit/RESULTS.json");
const EMBED_M18_NATIVE: &[u8] =
    include_bytes!("../../integrations/bitvm3-nova/m18/results/native-975067-975072.json");
const EMBED_M18_TRACE: &[u8] =
    include_bytes!("../../integrations/bitvm3-nova/m18/results/trace-975067-975072.json");
const EMBED_M18_SEG: &[u8] =
    include_bytes!("../../integrations/bitvm3-nova/m18/results/segmented-975067-975072.json");
const EMBED_M18_BAL: &[u8] =
    include_bytes!("../../integrations/bitvm3-nova/m18/results/balance-975067-975072.json");

fn discover_repo_root() -> PathBuf {
    if let Ok(exe) = std::env::current_exe() {
        for anc in exe.ancestors() {
            if anc.join("integrations").join("bitvm3-nova").exists() {
                return anc.to_path_buf();
            }
        }
    }
    if let Ok(cwd) = std::env::current_dir() {
        for anc in cwd.ancestors() {
            if anc.join("integrations").join("bitvm3-nova").exists() {
                return anc.to_path_buf();
            }
        }
    }
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

fn load_json_with_fallback(
    path: &Path,
    fallback: Option<&[u8]>,
) -> (Option<Value>, Option<String>) {
    if let Ok(raw) = fs::read(path) {
        if let Ok(val) = serde_json::from_slice::<Value>(&raw) {
            let digest = hex::encode(Sha256::digest(&raw));
            return (Some(val), Some(digest));
        }
    }
    if let Some(bytes) = fallback {
        if let Ok(val) = serde_json::from_slice::<Value>(bytes) {
            let digest = hex::encode(Sha256::digest(bytes));
            return (Some(val), Some(digest));
        }
    }
    (None, None)
}

pub fn load_campaigns(ark_dir: Option<&Path>) -> Value {
    let repo_root = discover_repo_root();
    let bitvm3_dir = repo_root.join("integrations").join("bitvm3-nova");
    let ark_base = ark_dir
        .map(Path::to_path_buf)
        .unwrap_or_else(default_ark_dir);

    let (m13_pins, m13_pins_sha) =
        load_json_with_fallback(&bitvm3_dir.join("m13/pins.json"), Some(EMBED_M13_PINS));
    let (m16_stmt, m16_stmt_sha) = load_json_with_fallback(
        &bitvm3_dir.join("m13/fixtures/m16-statement.json"),
        Some(EMBED_M16_STMT),
    );
    let (m14_res, m14_res_sha) = load_json_with_fallback(
        &bitvm3_dir.join("m14/circuit/RESULTS.json"),
        Some(EMBED_M14_RESULTS),
    );
    let (m18_native, m18_native_sha) = load_json_with_fallback(
        &bitvm3_dir.join("m18/results/native-975067-975072.json"),
        Some(EMBED_M18_NATIVE),
    );
    let (m18_trace, m18_trace_sha) = load_json_with_fallback(
        &bitvm3_dir.join("m18/results/trace-975067-975072.json"),
        Some(EMBED_M18_TRACE),
    );
    let (m18_seg, m18_seg_sha) = load_json_with_fallback(
        &bitvm3_dir.join("m18/results/segmented-975067-975072.json"),
        Some(EMBED_M18_SEG),
    );
    let (m18_bal, m18_bal_sha) = load_json_with_fallback(
        &bitvm3_dir.join("m18/results/balance-975067-975072.json"),
        Some(EMBED_M18_BAL),
    );

    let (ark_live_inv, ark_live_sha) =
        load_json_with_fallback(&ark_base.join("results/live-inventory-nova.json"), None);
    let (ark_pins, ark_pins_sha) = load_json_with_fallback(
        &ark_base.join("fixtures/bitvm3-pins.proof-grove.json"),
        None,
    );

    // Merge M18 block native stats + step-machine trace stats
    let mut m18_blocks = Vec::new();
    if let (Some(ref native_v), Some(ref trace_v)) = (&m18_native, &m18_trace) {
        let mut trace_by_h: HashMap<u64, &Value> = HashMap::new();
        if let Some(arr) = trace_v.get("blocks").and_then(Value::as_array) {
            for b in arr {
                if let Some(h) = b.get("height").and_then(Value::as_u64) {
                    trace_by_h.insert(h, b);
                }
            }
        }
        let mut cum_steps = 0u64;
        if let Some(arr) = native_v.get("blocks").and_then(Value::as_array) {
            for nb in arr {
                let h = nb.get("height").and_then(Value::as_u64).unwrap_or(0);
                let tb = trace_by_h.get(&h).copied();
                let steps = tb
                    .and_then(|t| t.get("steps"))
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                let seg_start = cum_steps / 28_099;
                let seg_end = seg_start.max((cum_steps + steps.max(1) - 1) / 28_099);
                cum_steps += steps;
                let idle_steps = tb
                    .and_then(|t| t.get("idle_steps"))
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                let seg_span = if seg_start == seg_end {
                    format!("seg-{seg_start}")
                } else {
                    format!("seg-{seg_start}..seg-{seg_end}")
                };
                m18_blocks.push(json!({
                    "height": h,
                    "hash": nb.get("hash"),
                    "transactions": nb.get("transactions"),
                    "inputs": nb.get("inputs"),
                    "outputs": nb.get("outputs"),
                    "creates": nb.get("creates"),
                    "spends_in_window": nb.get("spends_in_window"),
                    "spends_before_window": nb.get("spends_before_window"),
                    "raw_bytes": nb.get("raw_bytes"),
                    "nonwitness_bytes": nb.get("nonwitness_bytes"),
                    "merkle_merges": nb.get("merkle_merges"),
                    "nova_steps": steps,
                    "sha256_compressions": tb.and_then(|t| t.get("compressions")).and_then(Value::as_u64).unwrap_or(0),
                    "poseidon_leaf_updates": tb.and_then(|t| t.get("leaf_updates")).and_then(Value::as_u64).unwrap_or(0),
                    "idle_steps": idle_steps,
                    "dominant_unit": if idle_steps > 0 { "consumer_leaves" } else { "producer_sha256" },
                    "segment_span": seg_span,
                    "native_seconds": round_n(nb.get("seconds").and_then(Value::as_f64).unwrap_or(0.0), 1),
                    "contains_pay1": h == 975_067,
                }));
            }
        }
    }

    let mut m18_segments = Vec::new();
    if let Some(ref seg_v) = m18_seg {
        if let Some(arr) = seg_v.get("segments").and_then(Value::as_array) {
            for seg in arr {
                let fold = seg.get("fold");
                let comp = seg.get("compress");
                let fold_s = fold
                    .and_then(|f| f.get("fold_seconds_this_run"))
                    .and_then(Value::as_f64)
                    .unwrap_or(0.0);
                let steps = seg.get("steps").and_then(Value::as_u64).unwrap_or(1).max(1);
                m18_segments.push(json!({
                    "index": seg.get("index"),
                    "start_step": seg.get("start"),
                    "steps": seg.get("steps"),
                    "z0_sha256": seg.get("z0_sha256"),
                    "zn_sha256": seg.get("zn_sha256"),
                    "fold_hours": round_n(fold_s / 3600.0, 2),
                    "sec_per_step": round_n(fold_s / (steps as f64), 3),
                    "proof_bytes": comp.and_then(|c| c.get("proof_bytes")).and_then(Value::as_u64).unwrap_or(13_800),
                    "proof_sha256": comp.and_then(|c| c.get("proof_sha256")),
                    "compress_prove_s": round_n(comp.and_then(|c| c.get("prove_seconds")).and_then(Value::as_f64).unwrap_or(0.0), 2),
                    "compress_verify_s": round_n(comp.and_then(|c| c.get("verify_seconds")).and_then(Value::as_f64).unwrap_or(0.0), 3),
                }));
            }
        }
    }

    let ark_decisions = ark_live_inv
        .as_ref()
        .and_then(|v| v.get("plan"))
        .and_then(|p| p.get("decisions"))
        .cloned()
        .unwrap_or_else(|| {
            json!([
                {
                    "id": "bf687c94e942309e62782eeda4e1d748b68867222fa26a91d205966113da7d56:0",
                    "action": "defer_liquidity",
                    "before_sats": 49670,
                    "after_sats": 49670,
                    "fee_sats": 0,
                    "expiry_height": 8173,
                    "owner_commitment": "f144def1924cbaaabd5a9753b61c09289b24ba96393b9b29d9f4309a9a04925a",
                },
                {
                    "id": "12b61f02c215bd8931a57324117042d423f2dde1e9b6baec27a48f9b3d58bd0c:0",
                    "action": "refresh",
                    "before_sats": 10000,
                    "after_sats": 9770,
                    "fee_sats": 230,
                    "expiry_height": 12679,
                    "owner_commitment": "e0996b32a2ecd3f8cb6e5893cc931ef1caafd242f87ef763e7fc7ac064e88d56",
                },
                {
                    "id": "b9fdffcf88db333cd25f98f8b5ff548f123b39124fa1af8d0b43a5ca59b758ae:0",
                    "action": "defer_liquidity",
                    "before_sats": 10000,
                    "after_sats": 10000,
                    "fee_sats": 0,
                    "expiry_height": 8182,
                    "owner_commitment": "430b63fabfe049f82cb0eae99eddbc366c7dd826b144c30d3e613d97e40fd477",
                },
                {
                    "id": "f7127c8aa6960108645b81df825a3a155c0fc4e4837bf530485828f48d405533:0",
                    "action": "defer_liquidity",
                    "before_sats": 9770,
                    "after_sats": 9770,
                    "fee_sats": 0,
                    "expiry_height": 8205,
                    "owner_commitment": "66d42618bf43c0afbf495aff7f2bae80739816b79fc432baf7c26593dfe61050",
                },
            ])
        });

    let ark_prog_vk = ark_pins
        .as_ref()
        .and_then(|v| v.get("program_vk_digest"))
        .and_then(Value::as_str)
        .unwrap_or("832da00cf8403627f4b1341701e7a95387c55133c59d3571ab063c2670642c65");
    let ark_nova_vk = ark_pins
        .as_ref()
        .and_then(|v| v.get("nova_vk_sha256"))
        .and_then(Value::as_str)
        .unwrap_or("848ca2bf2276e80dba419033209757055faf957da3baf0d685c81b09adc52506");

    let m16_comm_sha = m16_stmt
        .as_ref()
        .and_then(|v| v.get("committed_values_sha256"))
        .and_then(Value::as_str)
        .unwrap_or("cae6068f7ad8c4891cb3220702a88b0bc3df54013f45e65df11a9ced531bc869");
    let m16_prog_vk = m16_stmt
        .as_ref()
        .and_then(|v| v.get("program_vk_digest"))
        .and_then(Value::as_str)
        .unwrap_or("dfc68a5d579b86244a60ba0baee7852348cf0d2a3bb13910ebb95a3e625fcb60");
    let wrap_vk_sha = m13_pins
        .as_ref()
        .and_then(|v| v.get("wrap_vk_sha256"))
        .and_then(Value::as_str)
        .unwrap_or("d42c63e3c873b35576b4c95fa8c41770a8c6b8a9f16ba74732c5b52a43b0b0d7");

    let pay1_leaf = m18_bal
        .as_ref()
        .and_then(|v| v.get("pay1_output"))
        .cloned()
        .unwrap_or_else(|| json!({}));
    let m14_prims = m14_res
        .as_ref()
        .and_then(|v| v.get("non_free_gates"))
        .cloned()
        .unwrap_or_else(|| json!({}));

    json!({
        "schema": "rbzk-campaigns-v1",
        "repo_root": repo_root.to_string_lossy(),
        "m14_gate_primitives": m14_prims,
        "campaigns": [
            {
                "id": "ark-cashu-live",
                "title": "Ark ASP Policy + Cashu Proof Grove (ARK1)",
                "subtitle": "Active Codex CUDA run · 4 Bark VTXOs + Cashu DLEQ bridge → Nova 0.76 → SP1 6.9 GPU → BitVM3",
                "evidence_level": "live-proving-and-regtest-verified",
                "evidence_badge": "LIVE GPU PROVING · NOVA VERIFIED",
                "network": "regtest (Proof Grove Core height 679)",
                "hardware": "RTX 5080 Laptop GPU (16 GB) · 2 CPU / 2 GiB cgroup / 4 GiB swap / 3 GiB host floor",
                "summary_metrics": {
                    "domain_items_label": "4 Bark VTXOs · 6 Cashu DLEQ",
                    "nova_segments": 1,
                    "nova_steps": 4,
                    "constraints_per_step": 19113,
                    "sp1_element_threshold": 67108864,
                    "sp1_core_shards": Value::Null,
                    "sp1_recursion_shards": Value::Null,
                    "ram_peak_label": "2.00 GiB Linux cap + 256 MiB CUDA pool",
                    "vram_peak_label": "Transient exact-trace lease (16 GB card)",
                    "final_gates": 785442492u64,
                },
                "pipeline_stages": [
                    {
                        "stage": "01 · Bark + Cashu Intake",
                        "state": "verified",
                        "detail": "25,000 sat deposit → 6 NUT-09/20 DLEQ Cashu proofs → 10,000 sat Bark VTXO (12b61f02…:0) + 15,000 sat change; 4-VTXO ASP book (79,440 sats) exported at height 679.",
                        "artifact": "proof-grove-regtest.json",
                    },
                    {
                        "stage": "02 · Nova 0.76 Policy Fold",
                        "state": "verified",
                        "detail": "Arity-24 Pallas/Vesta circuit (19,113 primary / 10,349 secondary constraints): 4 ordered VTXO steps folded in 8.26 s, Spartan-IPA compressed in 20.43 s → 11,640 B ARP1 proof.",
                        "artifact": "vk 848ca2bf…52506 · bundle 50d4f80f…d81f",
                    },
                    {
                        "stage": "03 · SP1 Guest Execution",
                        "state": "verified",
                        "detail": "ark-asp-nova-guest with M15 raw VK (22.48 MB, gas estimator off): verified Nova proof in 41.52 s at 251 MiB peak RSS; 1,616-byte ARK1 statement matched.",
                        "artifact": "public dd352842…8f41 · prog_vk 832da00c…2c65",
                    },
                    {
                        "stage": "04 · SP1 CUDA Core & Recursion Shards",
                        "state": "running",
                        "detail": "ark-prove-gpu (--element-threshold 2^26, ARK_SP1_TRANSIENT_TRACES=1, 256 MiB CUDA pool cap) checkpointing resumable ProveShard and RecursionReduce memos.",
                        "artifact": "bin 52a2069d…2d11 · /var/tmp/ark-asp-full-20261117",
                    },
                    {
                        "stage": "05 · M13 BLAKE3 v2 Shrink/Wrap",
                        "state": "queued",
                        "detail": "Queued automatically in ark_full_pipeline.py upon compressed.bin completion; cross-program M16 substitution already tested and refused.",
                        "artifact": "wrap_vk d42c63e3…b0d7 · rec_root 7487c217…f257",
                    },
                    {
                        "stage": "06 · M14 Garbled Circuit Gate",
                        "state": "queued",
                        "detail": "785,442,492 non-free AND gates (m14-claim hardened single-use setup/evaluate accept + bit-flip reject queued behind M13 wrap-v2.bin).",
                        "artifact": "m14-claim · 785.4M ciphertexts",
                    },
                ],
                "ark_vtxo_decisions": ark_decisions,
                "cashu_bridge": {
                    "deposit_sats": 25000,
                    "cashu_dleq_proofs": 6,
                    "ark_vtxo_sats": 10000,
                    "ark_refreshed_sats": 9770,
                    "ark_refresh_fee_sats": 230,
                    "cashu_change_sats": 15000,
                    "offline_exit_claim_sats": 9165,
                    "offline_exit_claim_fee_sats": 645,
                    "cpfp_fixture_fee_sats": 3180,
                    "hosted_demo_url": "https://patrickdugan.github.io/Spiral/proof-grove/",
                },
                "pins": {
                    "ark_pins_sha256": ark_pins_sha,
                    "ark_live_result_sha256": ark_live_sha,
                    "program_vk_digest": ark_prog_vk,
                    "nova_vk_sha256": ark_nova_vk,
                    "expected_public_sha256": "dd352842409878b3da279ce254d39ff95e4425ef5c256fdbbf6426acffa88f41",
                },
            },
            {
                "id": "m16-mainnet-pay",
                "title": "Mainnet Chainstate + SPV Payment (M16 · Tip 975,072)",
                "subtitle": "Genesis 0..975,072 Nova fold + 940,000 sat payment at 975,067 → SP1 GPU → M13 BLAKE3 → M14 Garbled",
                "evidence_level": "mainnet-proved-and-garbled",
                "evidence_badge": "MAINNET PROVED · M14 GARBLED ACCEPTED",
                "network": "Bitcoin mainnet (Genesis → 975,072)",
                "hardware": "Ryzen AI 9 365 (2×10 CPU fold) + RTX 5080 Laptop GPU (16 GB VRAM, 12 GiB RSS cap)",
                "summary_metrics": {
                    "domain_items_label": "975,072 blocks · 1 PAY1 UTXO",
                    "nova_segments": 2,
                    "nova_steps": 975072,
                    "constraints_per_step": 82809,
                    "sp1_instructions": 34055622753u64,
                    "sp1_element_threshold": 134217728,
                    "sp1_core_shards": 13290,
                    "sp1_core_shards_total": 13290,
                    "sp1_core_shards_is_est": false,
                    "sp1_recursion_shards": 4430,
                    "sp1_recursion_shards_total": 4430,
                    "completion_pct": 100.0,
                    "ram_peak_label": "11.6 GiB SP1 RSS (345 MB/shard Nova)",
                    "vram_peak_label": "13.4–14.2 GB VRAM (RTX 5080)",
                    "final_gates": 785442492u64,
                },
                "instruction_breakdown": [
                    {"component": "Nova 2-segment verification (s0 + s1)", "instructions": 29180000000u64, "share_pct": 85.68},
                    {"component": "SHA-256 hashing of raw M15 verifier key", "instructions": 2780000000u64, "share_pct": 8.16},
                    {"component": "Raw M15 verifier-key point decoding", "instructions": 2040000000u64, "share_pct": 5.99},
                    {"component": "NHC1 compressed proof bundle decoding", "instructions": 52000000u64, "share_pct": 0.15},
                    {"component": "PAY1 tx parse + depth-13 Merkle branch", "instructions": 259390u64, "share_pct": 0.0008},
                    {"component": "Tip header hash & chainwork link check", "instructions": 14192u64, "share_pct": 0.0001},
                ],
                "header_shards": [
                    {
                        "shard_id": "s0",
                        "height_range": "0 .. 487,536",
                        "headers": 487536,
                        "threads": 10,
                        "rss_mb": 345,
                        "wall_hours": 37.9,
                        "export_s": 44.5,
                        "bundle_bytes": 12596,
                        "bundle_sha256": "217334e1…e084",
                        "sp1_core_shards_attributed": 6645,
                        "sp1_recursion_shards_attributed": 2215,
                    },
                    {
                        "shard_id": "s1",
                        "height_range": "487,536 .. 975,072",
                        "headers": 487536,
                        "threads": 10,
                        "rss_mb": 345,
                        "wall_hours": 38.18,
                        "export_s": 31.1,
                        "bundle_bytes": 12596,
                        "bundle_sha256": "a7bb0ddf…7af02",
                        "sp1_core_shards_attributed": 6645,
                        "sp1_recursion_shards_attributed": 2215,
                    },
                ],
                "payment_utxo": {
                    "block_height": 975067,
                    "block_hash": "000000000000000000017809af97fdd5530149e411b2ab091db4f405e355fe22",
                    "tip_height": 975072,
                    "tip_hash": "000000000000000000013ec209c5510205d35f80f657c20ef1ea16f73f6ff792",
                    "tip_chainwork": "0x156c4c3c54ad473bac5daf261",
                    "confirmations": 6,
                    "block_tx_count": 6153,
                    "txid": "a652ab0cf381413ae854a86bb7e4784811b2d4158a65f26ff64a69eb3eb20045",
                    "vout": 0,
                    "value_sats": 940000,
                    "script_pubkey": "00148e0461b1590aed0a723e21ac16f48317cdb2ea96",
                    "script_sha256": "58432f41ce2b63d9a8e65e9b5bed183cd2ed12a03fe2b6020cda00235c147283",
                    "merkle_depth": 13,
                },
                "pipeline_stages": [
                    {
                        "stage": "01 · Core Header Sync & Differential Check",
                        "state": "verified",
                        "detail": "975,073 headers dumped from Bitcoin Core 31.1; nova-chain native-check matched hash, chainwork, bits, time & MTP at every height (535 s).",
                        "artifact": "headers.bin bc9d6ecb…21de",
                    },
                    {
                        "stage": "02 · 2-Shard Nova Header Fold (NHC1)",
                        "state": "verified",
                        "detail": "Shards 0..487,536 & 487,536..975,072 folded in 38.2 h (345 MB RSS/process), exported to two 12,596-byte Spartan-IPA bundles.",
                        "artifact": "segments 25,204 B · bdbd28e6…c878",
                    },
                    {
                        "stage": "03 · M16 SP1 Guest Execution",
                        "state": "verified",
                        "detail": "34,055,622,753 instructions (1,283 s, 7.5 GB RSS); all 13 adversarial mutations & compressed-key substitution refused.",
                        "artifact": "m16.elf bb7d51b0…4790 · stmt cae6068f…c869",
                    },
                    {
                        "stage": "04 · nb3-prove-gpu CUDA Shards & Recursion",
                        "state": "verified",
                        "detail": "13,290 core shard tasks + 4,430 recursion tasks (--element-threshold 2^27); final resume proved 3,645 shards + replayed 9,645 in 1h 54m under 12 GiB cap (11.6 GiB peak RSS).",
                        "artifact": "prog_vk dfc68a5d…cb60",
                    },
                    {
                        "stage": "05 · M13 BLAKE3 Shrink + Wrap v2",
                        "state": "verified",
                        "detail": "shrink-wrap in 1m 52s, wrap-only-v2 in 1m 12s; accepted by native m13-verify v1 & v2.",
                        "artifact": "wrap_vk d42c63e3…b0d7",
                    },
                    {
                        "stage": "06 · M14 Plain & Garbled Circuit",
                        "state": "verified",
                        "detail": "785,442,492 non-free AND gates accepted plain (96.8 s) and garbled/evaluated to accept label (167.1 s); bit-flip rejected.",
                        "artifact": "m14/circuit · 785,442,492 gates",
                    },
                ],
                "pins": {
                    "m13_pins_file_sha256": m13_pins_sha,
                    "m16_statement_file_sha256": m16_stmt_sha,
                    "m14_results_file_sha256": m14_res_sha,
                    "committed_values_sha256": m16_comm_sha,
                    "program_vk_digest": m16_prog_vk,
                    "wrap_vk_sha256": wrap_vk_sha,
                },
            },
            {
                "id": "m18-mainnet-utxo",
                "title": "Mainnet Windowed UTXO Map & Balance Proof (M18 · 975,067..975,072)",
                "subtitle": "Depth-20 Poseidon Indexed Merkle Tree folded across 6 mainnet blocks (8 segments, 224,790 steps, 74,593 leaves)",
                "evidence_level": "mainnet-nova-verified",
                "evidence_badge": "MAINNET FOLDED · 8 SEGMENTS VERIFIED",
                "network": "Bitcoin mainnet window 975,067 .. 975,072 (bound to M16 tip)",
                "hardware": "8 parallel fold-seg processes × 2 threads (9.96 h wall, checkpoint every 250 steps)",
                "summary_metrics": {
                    "domain_items_label": "6 blocks · 74,593 UTXO leaves",
                    "nova_segments": 8,
                    "nova_steps": 224790,
                    "constraints_per_step": 51404,
                    "sp1_element_threshold": 134217728,
                    "sp1_core_shards": 8,
                    "sp1_core_shards_total": 8,
                    "sp1_core_shards_is_est": false,
                    "sp1_recursion_shards": 8,
                    "sp1_recursion_shards_total": 8,
                    "completion_pct": 100.0,
                    "projected_sp1_core_shards_2_27": 25600,
                    "ram_peak_label": "72.7 MB pp.bin + 8 × 29.95 MB witness",
                    "vram_peak_label": "CPU MSM fold (6.27 steps/s aggregate)",
                    "final_gates": 785442492u64,
                },
                "blocks": m18_blocks,
                "segments": m18_segments,
                "utxo_map": {
                    "depth": 20,
                    "capacity_leaves": 1048576,
                    "final_leaves": 74593,
                    "root_le_hex": "7e18b0838195310d993131ebe62839d3ddca587b26f194c66310cd1369962d1c",
                    "r_s_le_hex": "efec1a32a67d0d3892a725a37fe9cc3d125bf67f05ce882c2858c4c3a2b25b10",
                    "total_transactions": 32693,
                    "total_inputs": 47238,
                    "creates": 74592,
                    "spends_in_window": 26447,
                    "spends_before_window": 20791,
                    "nonwitness_bytes": 4864871,
                    "pay1_leaf": pay1_leaf,
                },
                "pins": {
                    "native_sha256": m18_native_sha,
                    "trace_sha256": m18_trace_sha,
                    "segmented_sha256": m18_seg_sha,
                    "balance_sha256": m18_bal_sha,
                    "vk_sha256": "a259c50c559c768e929bf4df09a70279afdd180d1dd3b947dcf38bea95231939",
                    "pp_sha256": "2a19124c…3101",
                },
            },
            {
                "id": "m17-shinigami-leaves",
                "title": "Shinigami Script Leaves, Taproot Exit Chains & BABE-Nova Soldering",
                "subtitle": "M17 Nova Script VM (2,756 Core vectors) + Shinigami Taproot Stwo (4,977 checks) + FC03 / BABE-Nova Dispute Leaves",
                "evidence_level": "core-vectors-and-nova-proved",
                "evidence_badge": "2,756 NOVA + 4,977 CAIRO CORE VECTORS",
                "network": "Bitcoin consensus vectors + regtest Taproot leaf-script dispute",
                "hardware": "Laptop WSL2 (4 threads Nova M17 @ 197 MB RSS; 2 threads BABE-Nova @ 438 MB RSS; Stwo @ 15.5 GB)",
                "summary_metrics": {
                    "domain_items_label": "2,756 M17 + 4,977 Taproot checks",
                    "nova_segments": 10,
                    "nova_steps": 29121,
                    "constraints_per_step": 6808,
                    "sp1_element_threshold": 134217728,
                    "sp1_core_shards": 10,
                    "sp1_core_shards_total": 10,
                    "sp1_core_shards_is_est": false,
                    "sp1_recursion_shards": 3,
                    "sp1_recursion_shards_total": 3,
                    "completion_pct": 100.0,
                    "ram_peak_label": "19 MB M17 / 197 MB IPA / 438 MB BABE-Nova",
                    "vram_peak_label": "CPU Poseidon/IPA + Stwo SIMD",
                    "final_gates": 785442492u64,
                },
                "shinigami_leaves": [
                    {
                        "id": "script_tests/1055",
                        "kind": "P2PKH (M17 Nova Step)",
                        "engine": "Nova 0.76 (Pallas/Vesta, 6,808 R1CS/step)",
                        "steps": 10,
                        "deferred_claims": 1,
                        "prove_s": 8.0,
                        "verify_s": 0.75,
                        "proof_bytes": 11480,
                        "peak_ram_mb": 197,
                        "taproot_leaf": false,
                    },
                    {
                        "id": "script_tests/1134",
                        "kind": "P2WSH Witness v0 (M17 Nova Step)",
                        "engine": "Nova 0.76 (Pallas/Vesta, 6,808 R1CS/step)",
                        "steps": 17,
                        "deferred_claims": 2,
                        "prove_s": 14.2,
                        "verify_s": 0.75,
                        "proof_bytes": 11480,
                        "peak_ram_mb": 197,
                        "taproot_leaf": false,
                    },
                    {
                        "id": "script_tests/1135",
                        "kind": "P2WPKH Witness v0 (M17 Nova Step)",
                        "engine": "Nova 0.76 (Pallas/Vesta, 6,808 R1CS/step)",
                        "steps": 21,
                        "deferred_claims": 2,
                        "prove_s": 17.4,
                        "verify_s": 0.71,
                        "proof_bytes": 11480,
                        "peak_ram_mb": 197,
                        "taproot_leaf": false,
                    },
                    {
                        "id": "script_tests/1136",
                        "kind": "P2SH(P2WSH) Nested (M17 Nova Step)",
                        "engine": "Nova 0.76 (Pallas/Vesta, 6,808 R1CS/step)",
                        "steps": 26,
                        "deferred_claims": 3,
                        "prove_s": 25.8,
                        "verify_s": 0.87,
                        "proof_bytes": 11480,
                        "peak_ram_mb": 197,
                        "taproot_leaf": false,
                    },
                    {
                        "id": "script_tests/1137",
                        "kind": "P2SH(P2WPKH) Nested (M17 Nova Step)",
                        "engine": "Nova 0.76 (Pallas/Vesta, 6,808 R1CS/step)",
                        "steps": 30,
                        "deferred_claims": 3,
                        "prove_s": 29.5,
                        "verify_s": 0.78,
                        "proof_bytes": 11480,
                        "peak_ram_mb": 197,
                        "taproot_leaf": false,
                    },
                    {
                        "id": "script_tests/1059",
                        "kind": "P2SH Multisig Compressed (M17 Nova Step)",
                        "engine": "Nova 0.76 + Spartan-IPA",
                        "steps": 31,
                        "deferred_claims": 2,
                        "prove_s": 34.0,
                        "verify_s": 0.84,
                        "proof_bytes": 11480,
                        "peak_ram_mb": 197,
                        "taproot_leaf": false,
                    },
                    {
                        "id": "vtxo-exit/board",
                        "kind": "Ark VTXO Exit `board` (1 Taproot key-path)",
                        "engine": "Shinigami taproot-provable (Cairo / Stwo)",
                        "steps": 796937,
                        "deferred_claims": 0,
                        "prove_s": 158.0,
                        "verify_s": 0.20,
                        "proof_bytes": 15833497,
                        "peak_ram_mb": 15872,
                        "taproot_leaf": true,
                    },
                    {
                        "id": "vtxo-exit/round1",
                        "kind": "Ark VTXO Exit `round1` (2 key-path + 1 Taproot script leaf)",
                        "engine": "Shinigami taproot-provable (Cairo / Stwo)",
                        "steps": 3435430,
                        "deferred_claims": 0,
                        "prove_s": 234.0,
                        "verify_s": 0.20,
                        "proof_bytes": 15833497,
                        "peak_ram_mb": 15872,
                        "taproot_leaf": true,
                    },
                    {
                        "id": "vtxo-exit/arkoor3",
                        "kind": "Ark VTXO Exit `arkoor3` (4 key-path + 1 Taproot script leaf)",
                        "engine": "Shinigami taproot-provable (Cairo / Stwo)",
                        "steps": 5028714,
                        "deferred_claims": 0,
                        "prove_s": 269.0,
                        "verify_s": 0.20,
                        "proof_bytes": 15938355,
                        "peak_ram_mb": 15872,
                        "taproot_leaf": true,
                    },
                    {
                        "id": "fc03/leaf-envelope",
                        "kind": "FC03 FlatMerkle Dispute Leaf Envelope (644 vB standard)",
                        "engine": "BitVM3 Tapscript + Garbled Row/BindingStep",
                        "steps": 256,
                        "deferred_claims": 1,
                        "prove_s": 0.66,
                        "verify_s": 0.01,
                        "proof_bytes": 2044,
                        "peak_ram_mb": 308,
                        "taproot_leaf": true,
                    },
                    {
                        "id": "babe-nova/pasta-ec-w4",
                        "kind": "BABE-Nova 255-bit Pasta w=4 Affine EC + ZK Solder (769,351 gates · 88.4 kvB AssertLabels)",
                        "engine": "Transparent Nova CompressedSNARK + 11.74 MiB Half-Gates",
                        "steps": 64,
                        "deferred_claims": 0,
                        "prove_s": 189.1,
                        "verify_s": 1.04,
                        "proof_bytes": 11688,
                        "peak_ram_mb": 438,
                        "taproot_leaf": true,
                    },
                ],
                "pins": {
                    "shinigami_fork_commit": "19cb9fa (patrickdugan/shinigami taproot-provable)",
                    "fc03_branch_commit": "7ce50ba (feat/flatmerkle-bitvm3-checks)",
                    "babe_nova_pilot_commit": "6f2ee19 (exp/carbon-babe-nova-pilot PR #27)",
                    "m17_tamper_refusals": "1,955 tampered steps tested; all read-field mutations refused",
                },
            },
            {
                "id": "tn4-recursive-chain",
                "title": "Testnet4 Whole-Chain Recursive Continuation (0 .. 158,970)",
                "subtitle": "Genesis-anchored k=5 Nova folding under strict 1.5 GiB cgroup cap + Burger 160,000..161,016 GPU run",
                "evidence_level": "testnet4-verified",
                "evidence_badge": "TESTNET4 VERIFIED · <1.5 GiB CGROUP",
                "network": "Bitcoin testnet4 (BIP94 timewarp + min-difficulty rules)",
                "hardware": "Linux cgroup v2 memory.max=1,536 MiB, swap=0 (87 durable generations)",
                "summary_metrics": {
                    "domain_items_label": "158,970 blocks (78 retargets)",
                    "nova_segments": 1,
                    "nova_steps": 31794,
                    "constraints_per_step": 414045,
                    "sp1_element_threshold": 134217728,
                    "sp1_core_shards": 27058,
                    "sp1_core_shards_total": 27058,
                    "sp1_core_shards_is_est": false,
                    "sp1_recursion_shards": 9019,
                    "sp1_recursion_shards_total": 9019,
                    "completion_pct": 100.0,
                    "ram_peak_label": "1,169 MiB fold / 1,444 MiB export (cap 1,536 MiB)",
                    "vram_peak_label": "13.4–14.2 GB VRAM (Guest A / m16-tn4)",
                    "final_gates": 785442492u64,
                },
                "milestones": [
                    {
                        "range": "0 → 2,020 (first retarget)",
                        "folds": 404,
                        "sec_per_header": 0.124,
                        "fold_peak_mib": 935,
                        "export_peak_mib": 1473,
                        "anchor": "Consensus Genesis",
                    },
                    {
                        "range": "0 → 10,000",
                        "folds": 2000,
                        "sec_per_header": 0.155,
                        "fold_peak_mib": 1106,
                        "export_peak_mib": 1362,
                        "anchor": "Consensus Genesis",
                    },
                    {
                        "range": "0 → 158,970 (whole chain)",
                        "folds": 31794,
                        "sec_per_header": 0.123,
                        "fold_peak_mib": 1169,
                        "export_peak_mib": 1444,
                        "anchor": "Consensus Genesis",
                    },
                    {
                        "range": "160,000 → 161,016 (Spiral Burger m16-tn4)",
                        "folds": 1016,
                        "sec_per_header": 0.125,
                        "fold_peak_mib": 1150,
                        "export_peak_mib": 1450,
                        "anchor": "Pinned Checkpoint 160,000",
                    },
                ],
                "pins": {
                    "nht4_bundle_sha256": "f0bbf308a26875edce56bd2dde85ccd975159fb5d8f6a0bf3b47a3bcd93e0f8b",
                    "vk_sha256": "1ae88a7bcfdc5f14d030d0baafa06ec17fe904a5ebed42f9bd6fa6105fdc8c24",
                    "circuit_id": "730c0463ef01bce15b4429aae164217ded34ee8b70edd86821bc2be952a5d44e",
                },
            },
        ],
    })
}
