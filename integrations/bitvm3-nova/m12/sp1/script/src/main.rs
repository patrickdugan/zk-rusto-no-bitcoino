//! Host for the architecture A wrapper guest.
//!
//!   m12-wrapper execute VK BUNDLE EXPECT_PUBLIC_SHA256
//!       Execute the guest (no proof): print cycles per phase and require the
//!       committed statement to hash to EXPECT_PUBLIC_SHA256 (the
//!       `public_statement_sha256` printed by the native `m12 verify`).
//!   m12-wrapper mutations VK BUNDLE END_STATE_SHA256
//!       Execute the guest on each altered input; every one must be refused
//!       (an executor error or a nonzero guest exit code: a panicking guest
//!       exits with code 1, and SP1 proofs carry that code).
//!       END_STATE_SHA256 locates the proof's own zn inside the bundle.
//!   m12-wrapper prove VK BUNDLE EXPECT_PUBLIC_SHA256 OUT   (needs M12_ENABLE_PROVING=1)
//!       Compressed SP1 proof (STARK; no Groth16/PLONK wrap), then verify it.
//!   m12-wrapper verify PROOF EXPECT_PUBLIC_SHA256
//!   m12-wrapper direct HEADERS.bin N
//!       Control C: execute the direct header-transition guest on heights 1..=N
//!       (no Nova) and print cycles per header and the end-state SHA-256.
use anyhow::{bail, ensure, Result};
use sha2::{Digest, Sha256};
use sp1_sdk::{include_elf, Elf, HashableKey, ProveRequest, Prover, ProverClient, ProvingKey, SP1ProofWithPublicValues, SP1Stdin};
use std::time::Instant;

const ELF: Elf = include_elf!("m12-nova-wrapper-program");
const ELF_DIRECT: Elf = include_elf!("m12-direct-headers-program");
const ZB: usize = 17 * 32;

fn stdin(vk: &[u8], bundle: &[u8]) -> SP1Stdin {
    let mut s = SP1Stdin::new();
    s.write_vec(vk.to_vec());
    s.write_vec(bundle.to_vec());
    s
}

fn sha_hex(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

fn flip(b: &[u8], at: usize) -> Vec<u8> {
    let mut v = b.to_vec();
    v[at] ^= 1;
    v
}

/// Position of the proof's own zn (17 canonical scalars, 544 bytes) inside
/// the bundle: the window whose SHA-256 is the statement's end_state_sha256.
fn zn_offset(bundle: &[u8], end_state_sha256: &str) -> Option<usize> {
    bundle[12 + ZB..].windows(ZB).position(|w| sha_hex(w) == end_state_sha256).map(|p| p + 12 + ZB)
}

#[tokio::main]
async fn main() -> Result<()> {
    let a: Vec<String> = std::env::args().collect();
    ensure!(a.len() >= 2, "usage: see the header of src/main.rs");
    let client = ProverClient::builder().light().build().await;
    match a[1].as_str() {
        "execute" => {
            let (vk, bundle) = (std::fs::read(&a[2])?, std::fs::read(&a[3])?);
            let t = Instant::now();
            let (pv, report) = client.execute(ELF, stdin(&vk, &bundle)).await?;
            let secs = t.elapsed().as_secs_f64();
            let public = pv.as_slice();
            let got = sha_hex(public);
            let mut tracker: Vec<_> = report.cycle_tracker.iter().collect();
            tracker.sort();
            println!(
                "{}",
                serde_json::json!({
                    "status": "executed_unproved",
                    "elf_sha256": sha_hex(ELF.as_ref()),
                    "vk_sha256": sha_hex(&vk), "bundle_sha256": sha_hex(&bundle),
                    "instruction_count": report.total_instruction_count(),
                    "syscall_count": report.total_syscall_count(),
                    "cycle_tracker": tracker.into_iter().map(|(k, v)| (k.clone(), *v)).collect::<std::collections::BTreeMap<_, _>>(),
                    "execute_seconds": secs,
                    "exit_code": report.exit_code,
                    "public_statement_bytes": public.len(),
                    "public_statement_sha256": got,
                })
            );
            ensure!(report.exit_code == 0, "guest exited with code {}", report.exit_code);
            ensure!(got == a[4], "committed statement differs from the native verifier's");
        }
        "mutations" => {
            let (vk, bundle) = (std::fs::read(&a[2])?, std::fs::read(&a[3])?);
            let proof_len = bundle.len() - 12 - ZB;
            let mut cases: Vec<(String, Vec<u8>, Vec<u8>)> = vec![];
            for at in [8usize, proof_len / 4, proof_len / 2, proof_len - 40] {
                cases.push((format!("proof byte {at} flipped"), vk.clone(), flip(&bundle, 12 + ZB + at)));
            }
            match zn_offset(&bundle, &a[4]) {
                Some(off) => cases.push(("final tip: zn inside the proof altered".into(), vk.clone(), flip(&bundle, off))),
                None => bail!("zn not found in the proof bytes"),
            }
            cases.push(("verifier key byte flipped".into(), flip(&vk, vk.len() / 2), bundle.clone()));
            cases.push(("checkpoint chainwork z0[3] altered".into(), vk.clone(), flip(&bundle, 12 + 3 * 32)));
            cases.push(("checkpoint tip hash z0[1] altered".into(), vk.clone(), flip(&bundle, 12 + 32)));
            cases.push(("checkpoint height z0[0] altered".into(), vk.clone(), flip(&bundle, 12)));
            let mut b = bundle.clone();
            b[4..8].copy_from_slice(&(u32::from_le_bytes(bundle[4..8].try_into()?) + 1).to_le_bytes());
            cases.push(("step count + 1".into(), vk.clone(), b));
            let mut b = bundle.clone();
            b[..4].copy_from_slice(b"NHC1");
            cases.push(("network relabelled NHT4 -> NHC1".into(), vk.clone(), b));
            let mut b = bundle.clone();
            b[8..12].copy_from_slice(&5u32.to_le_bytes());
            cases.push(("fold width relabelled k -> 5".into(), vk.clone(), b));
            cases.push(("truncated proof".into(), vk.clone(), bundle[..bundle.len() - 1].to_vec()));
            let mut all = true;
            for (name, v, b) in cases {
                let t = Instant::now();
                let r = client.execute(ELF, stdin(&v, &b)).await;
                let (refused, exit_code, error, committed) = match r {
                    Err(e) => (true, None, Some(format!("{e}").chars().take(200).collect::<String>()), 0),
                    Ok((pv, rep)) => (rep.exit_code != 0, Some(rep.exit_code), None, pv.as_slice().len()),
                };
                all &= refused;
                println!(
                    "{}",
                    serde_json::json!({"case": name, "refused": refused, "exit_code": exit_code,
                                       "committed_bytes": committed, "seconds": t.elapsed().as_secs_f64(), "error": error})
                );
            }
            ensure!(all, "a mutated input was accepted");
            println!("all mutations refused");
        }
        "prove" => {
            ensure!(matches!(std::env::var("M12_ENABLE_PROVING"), Ok(ref v) if v == "1"), "set M12_ENABLE_PROVING=1");
            let (vk, bundle) = (std::fs::read(&a[2])?, std::fs::read(&a[3])?);
            let client = ProverClient::builder().cpu().build().await;
            let t = Instant::now();
            let pk = client.setup(ELF).await?;
            let proof = client.prove(&pk, stdin(&vk, &bundle)).compressed().await?;
            let prove_s = t.elapsed().as_secs_f64();
            ensure!(sha_hex(proof.public_values.as_slice()) == a[4], "committed statement differs");
            proof.save(&a[5])?;
            let t = Instant::now();
            client.verify(&proof, pk.verifying_key(), None)?;
            println!(
                "{}",
                serde_json::json!({"status": "compressed_proof_verified", "prove_seconds": prove_s,
                                   "verify_seconds": t.elapsed().as_secs_f64(), "program_vkey": pk.verifying_key().bytes32(),
                                   "proof_path": a[5]})
            );
        }
        "direct" => {
            let hs = std::fs::read(&a[2])?;
            let n: usize = a[3].parse()?;
            ensure!(hs.len() >= 80 * (n + 1), "not enough headers");
            let mut s = SP1Stdin::new();
            s.write_vec(vec![1u8]);
            s.write_vec(hs[80..80 * (n + 1)].to_vec());
            let t = Instant::now();
            let (pv, report) = client.execute(ELF_DIRECT, s).await?;
            let secs = t.elapsed().as_secs_f64();
            ensure!(report.exit_code == 0, "guest exited with code {}", report.exit_code);
            let p = pv.as_slice();
            ensure!(p.len() == 8 + 2 * ZB, "public values length");
            let c = report.total_instruction_count();
            println!(
                "{}",
                serde_json::json!({"status": "executed_unproved", "elf_sha256": sha_hex(ELF_DIRECT.as_ref()), "headers": n,
                    "instruction_count": c, "instructions_per_header": c as f64 / n as f64,
                    "cycle_tracker": report.cycle_tracker.iter().map(|(k, v)| (k.clone(), *v)).collect::<std::collections::BTreeMap<_, _>>(),
                    "checkpoint_state_sha256": sha_hex(&p[8..8 + ZB]), "end_state_sha256": sha_hex(&p[8 + ZB..]),
                    "execute_seconds": secs})
            );
        }
        "shape" => {
            // Structure of a compressed SP1 6.9.0 proof: every JSON path (array
            // indices collapsed to []) with how many arrays sit there and their
            // lengths, and how many numeric leaves sit under it.
            let proof = SP1ProofWithPublicValues::load(&a[2])?;
            let v = serde_json::to_value(&proof.proof)?;
            let mut acc: std::collections::BTreeMap<String, (u64, u64, std::collections::BTreeSet<usize>)> = Default::default();
            fn walk(v: &serde_json::Value, path: String, acc: &mut std::collections::BTreeMap<String, (u64, u64, std::collections::BTreeSet<usize>)>) {
                match v {
                    serde_json::Value::Array(xs) => {
                        let e = acc.entry(path.clone()).or_default();
                        e.0 += 1;
                        e.2.insert(xs.len());
                        for x in xs {
                            walk(x, format!("{path}[]"), acc);
                        }
                    }
                    serde_json::Value::Object(m) => {
                        for (k, x) in m {
                            walk(x, format!("{path}.{k}"), acc);
                        }
                    }
                    serde_json::Value::Number(_) => {
                        acc.entry(path).or_default().1 += 1;
                    }
                    _ => {}
                }
            }
            walk(&v, String::new(), &mut acc);
            for (p, (arrays, leaves, lens)) in acc {
                let lens: Vec<_> = lens.into_iter().take(8).collect();
                println!("{p}\tarrays={arrays}\tnumeric_leaves={leaves}\tlengths={lens:?}");
            }
        }
        "verify" => {
            let proof = SP1ProofWithPublicValues::load(&a[2])?;
            let pk = client.setup(ELF).await?;
            let t = Instant::now();
            client.verify(&proof, pk.verifying_key(), None)?;
            ensure!(sha_hex(proof.public_values.as_slice()) == a[3], "committed statement differs");
            println!("{}", serde_json::json!({"status": "verified", "seconds": t.elapsed().as_secs_f64()}));
        }
        _ => bail!("unknown command"),
    }
    Ok(())
}
