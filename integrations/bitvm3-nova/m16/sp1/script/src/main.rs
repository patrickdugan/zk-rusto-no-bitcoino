//! Host for the M16 guest (guest A's Nova verifier plus an SPV payment).
//!
//!   m16-spv elf OUT
//!       Write the guest ELF (for nb3-prove / nb3-prove-gpu).
//!   m16-spv segments OUT BUNDLE [BUNDLE ...]
//!       Pack header-chain bundles, in chain order, into the guest's segments input.
//!   m16-spv execute VK SEGMENTS PAY [EXPECT_PUBLIC_SHA256]
//!       Execute the guest (no proof): cycles per phase, the committed statement's SHA-256 and
//!       the decoded payment record.
//!   m16-spv mutations VK SEGMENTS PAY
//!       Execute the guest on altered segment and payment inputs; every one must be refused.
//!   m16-spv decode PUBLIC_VALUES.bin
//!       Decode a committed statement (as saved by nb3-prove next to its proof, or by `execute`).
use anyhow::{bail, ensure, Result};
use sha2::{Digest, Sha256};
use sp1_sdk::{include_elf, Elf, Prover, ProverClient, SP1Stdin};
use std::time::Instant;

const ELF: Elf = include_elf!("m16-nova-spv-program");
const ZB: usize = 17 * 32;
const BASE: usize = 12 + 2 * ZB + 64;

fn stdin(vk: &[u8], bundle: &[u8], pay: &[u8]) -> SP1Stdin {
    let mut s = SP1Stdin::new();
    s.write_vec(vk.to_vec());
    s.write_vec(bundle.to_vec());
    s.write_vec(pay.to_vec());
    s
}

fn sha_hex(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

/// Display order (reversed) for block hashes and txids.
fn rev_hex(b: &[u8]) -> String {
    let mut v = b.to_vec();
    v.reverse();
    hex::encode(v)
}

fn u32le(b: &[u8]) -> u32 {
    u32::from_le_bytes(b[..4].try_into().unwrap())
}

fn decode(p: &[u8]) -> Result<serde_json::Value> {
    ensure!(p.len() == BASE + 128, "statement is {} bytes, expected {}", p.len(), BASE + 128);
    let zn = &p[12 + ZB..12 + 2 * ZB];
    let pay = &p[BASE..];
    ensure!(&pay[..4] == b"PAY1", "payment record magic");
    let mut tip = [0u8; 32];
    tip[..16].copy_from_slice(&zn[32..48]);
    tip[16..].copy_from_slice(&zn[64..80]);
    Ok(serde_json::json!({
        "network": String::from_utf8_lossy(&p[..4]),
        "k": u32le(&p[4..]),
        "steps": u32le(&p[8..]),
        "z0_height": u32le(&p[12..]),
        "tip_height": u32le(zn),
        "tip_hash": rev_hex(&tip),
        "chainwork_hex_le": hex::encode(&zn[96..128]),
        "vk_sha256": hex::encode(&p[12 + 2 * ZB..12 + 2 * ZB + 32]),
        "nova_proof_sha256": hex::encode(&p[12 + 2 * ZB + 32..BASE]),
        "segments": u32le(&pay[4..]),
        "payment": {
            "block_height": u32le(&pay[8..]),
            "block_hash": rev_hex(&pay[12..44]),
            "confirmations": u32le(&pay[44..]),
            "txid": rev_hex(&pay[48..80]),
            "vout": u32le(&pay[80..]),
            "value_sats": u64::from_le_bytes(pay[84..92].try_into().unwrap()),
            "script_bytes": u32le(&pay[92..]),
            "script_sha256": hex::encode(&pay[96..128]),
        },
        "public_statement_sha256": sha_hex(p),
    }))
}

/// Field offsets inside the payment blob, for the mutation cases.
struct Layout {
    n: usize,
    vout_at: usize,
    tx_at: usize,
    tx_len: usize,
    depth: usize,
    sib_at: usize,
    index_at: usize,
}

fn layout(pay: &[u8]) -> Layout {
    let n = u32le(pay) as usize;
    let vout_at = 4 + 80 * n;
    let tx_len = u32le(&pay[vout_at + 4..]) as usize;
    let tx_at = vout_at + 8;
    let depth = u32le(&pay[tx_at + tx_len..]) as usize;
    let sib_at = tx_at + tx_len + 4;
    Layout { n, vout_at, tx_at, tx_len, depth, sib_at, index_at: sib_at + 32 * depth }
}

#[tokio::main]
async fn main() -> Result<()> {
    let a: Vec<String> = std::env::args().collect();
    ensure!(a.len() >= 2, "usage: see the header of src/main.rs");
    match a[1].as_str() {
        "elf" => {
            std::fs::write(&a[2], ELF.as_ref())?;
            println!("{}", serde_json::json!({"elf": a[2], "elf_sha256": sha_hex(ELF.as_ref()), "bytes": ELF.as_ref().len()}));
        }
        "segments" => {
            let mut out = vec![];
            let bundles: Vec<Vec<u8>> = a[3..].iter().map(std::fs::read).collect::<std::io::Result<_>>()?;
            ensure!(!bundles.is_empty(), "no bundles");
            out.extend_from_slice(&(bundles.len() as u32).to_le_bytes());
            for b in &bundles {
                out.extend_from_slice(&(b.len() as u32).to_le_bytes());
                out.extend_from_slice(b);
            }
            std::fs::write(&a[2], &out)?;
            println!("{}", serde_json::json!({"segments": bundles.len(), "bytes": out.len(), "sha256": sha_hex(&out)}));
        }
        "decode" => println!("{}", serde_json::to_string_pretty(&decode(&std::fs::read(&a[2])?)?)?),
        "execute" => {
            let (vk, bundle, pay) = (std::fs::read(&a[2])?, std::fs::read(&a[3])?, std::fs::read(&a[4])?);
            let client = ProverClient::builder().light().build().await;
            let t = Instant::now();
            let (pv, report) = client.execute(ELF, stdin(&vk, &bundle, &pay)).await?;
            let secs = t.elapsed().as_secs_f64();
            ensure!(report.exit_code == 0, "guest exited with code {}", report.exit_code);
            let p = pv.as_slice();
            if let Some(out) = std::env::var_os("M16_PUBLIC_OUT") {
                std::fs::write(out, p)?;
            }
            let mut tracker: Vec<_> = report.cycle_tracker.iter().collect();
            tracker.sort();
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "status": "executed_unproved",
                    "elf_sha256": sha_hex(ELF.as_ref()),
                    "vk_sha256": sha_hex(&vk), "bundle_sha256": sha_hex(&bundle), "payment_sha256": sha_hex(&pay),
                    "instruction_count": report.total_instruction_count(),
                    "syscall_count": report.total_syscall_count(),
                    "cycle_tracker": tracker.into_iter().map(|(k, v)| (k.clone(), *v)).collect::<std::collections::BTreeMap<_, _>>(),
                    "execute_seconds": secs,
                    "statement": decode(p)?,
                }))?
            );
            if let Some(e) = a.get(5) {
                ensure!(&sha_hex(p) == e, "committed statement differs from the expected one");
            }
        }
        "mutations" => {
            let (vk, bundle, pay) = (std::fs::read(&a[2])?, std::fs::read(&a[3])?, std::fs::read(&a[4])?);
            let client = ProverClient::builder().light().build().await;
            let l = layout(&pay);
            let flip = |at: usize| {
                let mut v = pay.clone();
                v[at] ^= 1;
                v
            };
            let set32 = |at: usize, x: u32| {
                let mut v = pay.clone();
                v[at..at + 4].copy_from_slice(&x.to_le_bytes());
                v
            };
            let mut cases: Vec<(String, Vec<u8>)> = vec![
                ("tip header nonce flipped".into(), flip(4 + 80 * (l.n - 1) + 76)),
                ("payment block's Merkle root flipped".into(), flip(4 + 36)),
                ("transaction byte flipped (output value)".into(), flip(l.tx_at + l.tx_len - 20)),
                ("vout out of range".into(), set32(l.vout_at, 1_000)),
                ("index flipped".into(), set32(l.index_at, u32le(&pay[l.index_at..]) ^ 1)),
                ("trailing byte".into(), [pay.as_slice(), &[0]].concat()),
            ];
            if l.depth > 0 {
                cases.push(("Merkle sibling flipped".into(), flip(l.sib_at)));
            }
            if l.n > 1 {
                // Drop the tip header: the last one is then not the proven tip.
                let mut v = pay.clone();
                v.drain(4 + 80 * (l.n - 1)..4 + 80 * l.n);
                v[..4].copy_from_slice(&((l.n - 1) as u32).to_le_bytes());
                cases.push(("tip header dropped".into(), v));
                cases.push(("middle link broken".into(), flip(4 + 80 + 4)));
            }
            let mut runs: Vec<(String, Vec<u8>, Vec<u8>)> = cases.into_iter().map(|(n, p)| (n, bundle.clone(), p)).collect();
            // Segment cases: the input is u32 m | m × (u32 len | bundle).
            let m = u32le(&bundle) as usize;
            let mut at = 4;
            let mut spans = vec![];
            for _ in 0..m {
                let len = u32le(&bundle[at..]) as usize;
                spans.push((at, len));
                at += 4 + len;
            }
            let (s0, l0) = spans[0];
            let mut b = bundle.clone();
            b[s0 + 4 + 12] ^= 1;
            runs.push(("first segment's start height altered".into(), b, pay.clone()));
            let mut b = bundle.clone();
            b[s0 + 4 + l0 - 40] ^= 1;
            runs.push(("first segment's proof byte flipped".into(), b, pay.clone()));
            if m > 1 {
                let (s1, _) = spans[1];
                let mut b = bundle.clone();
                b[s1 + 4 + 12 + 32] ^= 1;
                runs.push(("second segment starts off the first one's end (tip hash z0[1])".into(), b, pay.clone()));
                // Segments in the other order: the second no longer starts at the first's end.
                let mut b = bundle[..4].to_vec();
                b.extend_from_slice(&bundle[s1..s1 + 4 + u32le(&bundle[s1..]) as usize]);
                b.extend_from_slice(&bundle[s0..s1]);
                b.extend_from_slice(&bundle[s1 + 4 + u32le(&bundle[s1..]) as usize..]);
                runs.push(("first two segments swapped".into(), b, pay.clone()));
            }
            let mut all = true;
            for (name, bundle, p) in runs {
                let t = Instant::now();
                let r = client.execute(ELF, stdin(&vk, &bundle, &p)).await;
                let (refused, exit_code, error) = match r {
                    Err(e) => (true, None, Some(format!("{e}").chars().take(200).collect::<String>())),
                    Ok((_, rep)) => (rep.exit_code != 0, Some(rep.exit_code), None),
                };
                all &= refused;
                println!(
                    "{}",
                    serde_json::json!({"case": name, "refused": refused, "exit_code": exit_code,
                                       "seconds": t.elapsed().as_secs_f64(), "error": error})
                );
            }
            ensure!(all, "a mutated payment was accepted");
            println!("all mutations refused");
        }
        _ => bail!("unknown command"),
    }
    Ok(())
}
