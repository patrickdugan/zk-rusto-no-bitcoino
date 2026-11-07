//! M13 host.
//!
//!   m13 compress-direct HEADERS.bin N OUT.bin          (needs M13_ENABLE_PROVING=1)
//!       SP1 compressed proof of the control-C guest over testnet4 heights 1..=N.
//!   m13 compress-a VK BUNDLE EXPECT_STATEMENT_SHA256 OUT.bin   (needs M13_ENABLE_PROVING=1)
//!       SP1 compressed proof of the architecture A guest (complete Nova verifier).
//!   m13 shrink-wrap COMPRESSED.bin OUTDIR   |   m13 wrap-only OUTDIR (reuses OUTDIR/shrink.bin)
//!       SP1's shrink step, then SP1's wrap program proved under BLAKE3. Writes
//!       shrink.bin, shrink-shape.json, wrap.bin, statement.json, report.json.
//!   m13 wrap-only-v2 OUTDIR
//!       The wrap step of OUTDIR/shrink.bin under transcript v2 (fixed-cost
//!       challenges). Writes wrap-v2.bin, statement-v2.json, report-v2.json.
//!   m13 verify WRAP.bin EXPECT.json
//!       The complete final verifier (pinned key, STARK, statement fields) with
//!       BLAKE3 compression counts per role.
//!   m13 mutations WRAP.bin EXPECT.json
//!       Altered proofs and statements; every one must be refused.
//!   m13 program-vk
//!       Key digests of guests A and C (SP1 light client setup; no proving).
//!   m13 check-wrap-program SHRINK_SHAPE.json
//!       The wrap program built here gives SP1's shipped BN254 wrap key.
use std::{collections::BTreeMap, path::Path, time::Instant};

use anyhow::{bail, ensure, Context, Result};
use m13_blake3_wrap::{ctx, pipeline};
use sha2::{Digest, Sha256};
use sp1_sdk::{include_elf, Elf, HashableKey, ProveRequest, Prover, ProverClient, ProvingKey, SP1Proof, SP1ProofWithPublicValues, SP1Stdin};

const ELF_A: Elf = include_elf!("m12-nova-wrapper-program");
const ELF_C: Elf = include_elf!("m12-direct-headers-program");

fn sha_hex(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

fn proving_enabled() -> Result<()> {
    ensure!(matches!(std::env::var("M13_ENABLE_PROVING"), Ok(ref v) if v == "1"), "set M13_ENABLE_PROVING=1");
    Ok(())
}

fn write_json(path: &Path, v: &serde_json::Value) -> Result<()> {
    std::fs::write(path, serde_json::to_string_pretty(v)? + "\n")?;
    Ok(())
}

async fn compress(elf: Elf, stdin: SP1Stdin, out: &str, label: &str) -> Result<()> {
    proving_enabled()?;
    let client = ProverClient::builder().cpu().build().await;
    let t = Instant::now();
    let pk = client.setup(elf.clone()).await?;
    let setup_s = t.elapsed().as_secs_f64();
    let t = Instant::now();
    let proof = client.prove(&pk, stdin).compressed().await?;
    let prove_s = t.elapsed().as_secs_f64();
    client.verify(&proof, pk.verifying_key(), None)?;
    proof.save(out)?;
    let vk_digest: Vec<u8> =
        pk.verifying_key().hash_koalabear().iter().flat_map(|x| x.as_canonical_u32().to_le_bytes()).collect();
    println!(
        "{}",
        serde_json::json!({
            "status": "compressed_proof_verified", "guest": label,
            "elf_sha256": sha_hex(elf.as_ref()),
            "program_vk_digest": hex::encode(vk_digest),
            "program_vkey_bytes32": pk.verifying_key().bytes32(),
            "public_values_bytes": proof.public_values.as_slice().len(),
            "committed_values_sha256": sha_hex(proof.public_values.as_slice()),
            "setup_seconds": setup_s, "prove_seconds": prove_s,
            "proof_file_bytes": std::fs::metadata(out)?.len(), "proof_path": out,
        })
    );
    Ok(())
}

use slop_algebra::PrimeField32;

#[tokio::main]
async fn main() -> Result<()> {
    sp1_sdk::utils::setup_logger();
    let a: Vec<String> = std::env::args().collect();
    ensure!(a.len() >= 2, "usage: see the header of src/bin/m13.rs");
    match a[1].as_str() {
        "compress-direct" => {
            let hs = std::fs::read(&a[2])?;
            let n: usize = a[3].parse()?;
            ensure!(hs.len() >= 80 * (n + 1), "not enough headers");
            let mut s = SP1Stdin::new();
            s.write_vec(vec![1u8]);
            s.write_vec(hs[80..80 * (n + 1)].to_vec());
            compress(ELF_C, s, &a[4], &format!("control C, testnet4 heights 1..={n}")).await?;
        }
        "compress-a" => {
            let (vk, bundle) = (std::fs::read(&a[2])?, std::fs::read(&a[3])?);
            let mut s = SP1Stdin::new();
            s.write_vec(vk.clone());
            s.write_vec(bundle.clone());
            // Refuse to spend proving time on an input the guest would reject.
            let light = ProverClient::builder().light().build().await;
            let (pv, report) = light.execute(ELF_A, s.clone()).await?;
            ensure!(report.exit_code == 0, "guest exits with code {}", report.exit_code);
            ensure!(sha_hex(pv.as_slice()) == a[4], "committed statement differs");
            compress(ELF_A, s, &a[5], "architecture A, complete Nova verifier").await?;
        }
        "wrap-only-v2" => {
            // wrap-only-v2 OUTDIR: the wrap step of OUTDIR/shrink.bin under transcript v2.
            let out = Path::new(&a[2]).to_path_buf();
            let vks = pipeline::recursion_vks();
            let mut t = pipeline::PhaseTimes::default();
            let shrink: pipeline::ShrinkProof = bincode::deserialize(&std::fs::read(out.join("shrink.bin"))?)?;
            let shape: BTreeMap<String, usize> = serde_json::from_slice(&std::fs::read(out.join("shrink-shape.json"))?)?;
            let committed = std::fs::read_to_string(out.join("committed.sha256")).map(|s| s.trim().to_string()).unwrap_or_default();
            let wrap = pipeline::wrap_blake3_v2(shrink, shape, &vks, &mut t).await?;
            let wrap_bytes = bincode::serialize(&wrap)?;
            std::fs::write(out.join("wrap-v2.bin"), &wrap_bytes)?;
            let st = pipeline::final_statement(&wrap)?;
            ensure!(committed.is_empty() || st.committed_values_sha256 == committed, "wrap commits a different statement digest");
            write_json(&out.join("statement-v2.json"), &serde_json::to_value(&st)?)?;
            let proof_only = bincode::serialize(&wrap.proof)?;
            write_json(
                &out.join("report-v2.json"),
                &serde_json::json!({
                    "transcript": "v2", "times": t, "statement": st,
                    "wrap_file_bytes": wrap_bytes.len(),
                    "wrap_proof_bytes": proof_only.len(),
                    "wrap_vk_bytes": wrap_bytes.len() - proof_only.len(),
                    "wrap_proof_sha256": sha_hex(&wrap_bytes),
                }),
            )?;
            println!("{}", std::fs::read_to_string(out.join("report-v2.json"))?);
        }
        "shrink-wrap" | "wrap-only" => {
            // shrink-wrap COMPRESSED.bin OUTDIR
            // wrap-only   OUTDIR   (reuses OUTDIR/shrink.bin, shrink-shape.json, committed.sha256)
            let only = a[1] == "wrap-only";
            let out = Path::new(if only { &a[2] } else { &a[3] }).to_path_buf();
            std::fs::create_dir_all(&out)?;
            let vks = pipeline::recursion_vks();
            let mut t = pipeline::PhaseTimes::default();
            let (shrink, shape, committed) = if only {
                let shrink: pipeline::ShrinkProof = bincode::deserialize(&std::fs::read(out.join("shrink.bin"))?)?;
                let shape: BTreeMap<String, usize> = serde_json::from_slice(&std::fs::read(out.join("shrink-shape.json"))?)?;
                let committed = std::fs::read_to_string(out.join("committed.sha256")).map(|s| s.trim().to_string()).unwrap_or_default();
                (shrink, shape, committed)
            } else {
                let compressed = SP1ProofWithPublicValues::load(&a[2])?;
                let committed = sha_hex(compressed.public_values.as_slice());
                let inner = match compressed.proof {
                    SP1Proof::Compressed(p) => *p,
                    _ => bail!("not a compressed proof"),
                };
                let (shrink, shape) = pipeline::shrink(inner, &vks, &mut t).await?;
                std::fs::write(out.join("shrink.bin"), bincode::serialize(&shrink)?)?;
                write_json(&out.join("shrink-shape.json"), &serde_json::to_value(&shape)?)?;
                std::fs::write(out.join("committed.sha256"), format!("{committed}\n"))?;
                (shrink, shape, committed)
            };
            let shrink_bytes = bincode::serialize(&shrink)?;
            let wrap = pipeline::wrap_blake3(shrink, shape, &vks, &mut t).await?;
            let wrap_bytes = bincode::serialize(&wrap)?;
            std::fs::write(out.join("wrap.bin"), &wrap_bytes)?;
            let st = pipeline::final_statement(&wrap)?;
            ensure!(committed.is_empty() || st.committed_values_sha256 == committed, "wrap commits a different statement digest");
            write_json(&out.join("statement.json"), &serde_json::to_value(&st)?)?;
            let proof_only = bincode::serialize(&wrap.proof)?;
            write_json(
                &out.join("report.json"),
                &serde_json::json!({
                    "times": t, "statement": st,
                    "shrink_proof_bytes": shrink_bytes.len(),
                    "wrap_file_bytes": wrap_bytes.len(),
                    "wrap_proof_bytes": proof_only.len(),
                    "wrap_vk_bytes": wrap_bytes.len() - proof_only.len(),
                    "wrap_proof_sha256": sha_hex(&wrap_bytes),
                }),
            )?;
            println!("{}", std::fs::read_to_string(out.join("report.json"))?);
        }
        "verify" => {
            let wrap: pipeline::Blake3WrapProof = bincode::deserialize(&std::fs::read(&a[2])?)?;
            let expect: pipeline::FinalStatement = serde_json::from_slice(&std::fs::read(&a[3])?)?;
            ctx::reset_counters();
            let t = Instant::now();
            let got = pipeline::verify_final(&wrap, &expect)?;
            let secs = t.elapsed().as_secs_f64();
            let counts = ctx::read_counters();
            let by_role: BTreeMap<_, _> = ctx::ROLE_NAMES.iter().zip(counts.iter()).map(|(k, v)| (*k, *v)).collect();
            let total: u64 = counts.iter().map(|c| c.compressions).sum();
            println!(
                "{}",
                serde_json::json!({"status": "verified", "seconds": secs, "statement": got,
                    "blake3": by_role, "blake3_compressions_total": total})
            );
        }
        "mutations" => {
            let bytes = std::fs::read(&a[2])?;
            let expect: pipeline::FinalStatement = serde_json::from_slice(&std::fs::read(&a[3])?)?;
            let wrap: pipeline::Blake3WrapProof = bincode::deserialize(&bytes)?;
            pipeline::verify_final(&wrap, &expect).context("the honest proof must verify")?;
            let mut all = true;
            let mut report = |name: &str, r: Result<pipeline::FinalStatement>| {
                let refused = r.is_err();
                all &= refused;
                println!(
                    "{}",
                    serde_json::json!({"case": name, "refused": refused,
                        "error": r.err().map(|e| format!("{e:#}").chars().take(160).collect::<String>())})
                );
            };
            for (k, frac) in [(0usize, 0.05f64), (1, 0.25), (2, 0.5), (3, 0.75), (4, 0.97)] {
                let mut b = bytes.clone();
                let at = ((b.len() as f64) * frac) as usize;
                b[at] ^= 1;
                let r = bincode::deserialize::<pipeline::Blake3WrapProof>(&b)
                    .map_err(anyhow::Error::from)
                    .and_then(|w| pipeline::verify_final(&w, &expect));
                report(&format!("wrap file byte {at} flipped (case {k})"), r);
            }
            let mut e = expect.clone();
            e.committed_values_sha256 = sha_hex(b"another statement");
            report("expected statement digest altered", pipeline::verify_final(&wrap, &e));
            let mut e = expect.clone();
            e.program_vk_digest = "00".repeat(32);
            report("expected guest program altered", pipeline::verify_final(&wrap, &e));
            let mut e = expect.clone();
            e.wrap_vk_sha256 = sha_hex(b"another key");
            report("pinned wrap key altered", pipeline::verify_final(&wrap, &e));
            for (name, idx_fn) in [
                ("public value: exit code set to 1", 0usize),
                ("public value: committed digest byte altered", 1),
                ("public value: program key digest altered", 2),
                ("public value: is_complete cleared", 3),
            ] {
                let mut w = wrap.clone();
                {
                    use std::borrow::BorrowMut;
                    let pv: &mut sp1_recursion_executor::RecursionPublicValues<sp1_primitives::SP1Field> =
                        w.proof.public_values.as_mut_slice().borrow_mut();
                    use slop_algebra::AbstractField;
                    let one = sp1_primitives::SP1Field::one();
                    match idx_fn {
                        0 => pv.exit_code = one,
                        1 => pv.committed_value_digest[0][0] += one,
                        2 => pv.sp1_vk_digest[0] += one,
                        _ => pv.is_complete = sp1_primitives::SP1Field::zero(),
                    }
                }
                report(name, pipeline::verify_final(&w, &expect));
            }
            ensure!(all, "an altered proof or statement was accepted");
            println!("all mutations refused");
        }
        "program-vk" => {
            // Key digests of both guests (no proving): the values pins.json pins.
            let light = ProverClient::builder().light().build().await;
            let mut out = serde_json::Map::new();
            for (name, elf) in [("architecture_a_nova_verifier", ELF_A), ("control_c_direct_headers", ELF_C)] {
                let pk = light.setup(elf.clone()).await?;
                let d: Vec<u8> = pk.verifying_key().hash_koalabear().iter().flat_map(|x| x.as_canonical_u32().to_le_bytes()).collect();
                out.insert(
                    name.into(),
                    serde_json::json!({"elf_sha256": sha_hex(elf.as_ref()), "program_vk_digest": hex::encode(d),
                                       "program_vkey_bytes32": pk.verifying_key().bytes32()}),
                );
            }
            println!("{}", serde_json::Value::Object(out));
        }
        "check-wrap-program" => {
            let shape: BTreeMap<String, usize> = serde_json::from_slice(&std::fs::read(&a[2])?)?;
            let t = Instant::now();
            let (eq, built, shipped) = pipeline::bn254_wrap_vk_matches_sp1(shape).await?;
            println!(
                "{}",
                serde_json::json!({"bn254_wrap_key_equal_to_sp1": eq, "built_sha256": built,
                    "sp1_shipped_sha256": shipped, "seconds": t.elapsed().as_secs_f64()})
            );
            ensure!(eq, "wrap program differs from SP1's");
        }
        _ => bail!("unknown command"),
    }
    Ok(())
}
