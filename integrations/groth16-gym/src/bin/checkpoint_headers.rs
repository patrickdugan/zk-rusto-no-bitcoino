//! Resumable fixture-grounded Groth16 header batches with fixed per-batch RAM.
//! This is a bundle of independently verifiable Groth16 proofs, not a
//! recursive Groth16 proof, and does not authenticate canonical chain selection.
//! Setup RNG is seeded for a reproducible gym ONLY: keys have known toxic waste.
use ark_bn254::Bn254;
use ark_groth16::{Groth16, Proof, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use groth16_gym::{chain_from_txt, target_from_nbits, Bytes32, ChainPublic};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, Read, Write};
use std::path::Path;

const HEADERS: &str = include_str!("../../fixtures/headers_959617_959994.txt");
const FIRST: u32 = 959_617;
const LAST: u32 = 959_994;
const FORMAT: u32 = 1;
const MAX_HEADERS_PER_BATCH: u32 = 64;
const MAX_PROOF_BYTES: u64 = 4096;
const MAX_VK_BYTES: u64 = 65_536;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    version: u32,
    start: u32,
    end: u32,
    start_prev_hex: String,
    end_hash_hex: String,
    nbits: u32,
    target_hex: String,
    parent_proof_sha256: Option<String>,
    proof_sha256: String,
    vk_sha256: String,
}

/// A single length-delimited batch. Entire history recovery verifies each proof.
fn batch_path(root: &Path, start: u32, end: u32) -> PathBuf {
    root.join(format!("batch_{start}_to_{end}"))
}

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn read_bounded(path: &Path, max: u64) -> Result<Vec<u8>, String> {
    let len = fs::metadata(path).map_err(|e| e.to_string())?.len();
    if len == 0 || len > max {
        return Err(format!("invalid artifact size at {}", path.display()));
    }
    let mut bytes = Vec::with_capacity(len as usize);
    File::open(path)
        .map_err(|e| e.to_string())?
        .take(max + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 != len {
        return Err("artifact length changed during read".into());
    }
    Ok(bytes)
}

fn write_sync(path: &Path, content: &[u8]) -> Result<(), String> {
    let tmp = path.with_extension("tmp");
    let mut options = OpenOptions::new();
    options.create(true).write(true).truncate(true);
    let mut file = options.open(&tmp).map_err(|e| e.to_string())?;
    file.write_all(content).map_err(|e| e.to_string())?;
    file.sync_all().map_err(|e| e.to_string())?;
    // A killed worker may leave prior unsealed output; replace only the
    // precisely named artifact. The checkpoint manifest is written last.
    if path.exists() {
        fs::remove_file(path).map_err(|e| e.to_string())?;
    }
    fs::rename(&tmp, path).map_err(|e| e.to_string())
}

fn public_from_receipt(r: &Receipt) -> Result<ChainPublic, String> {
    fn read32(hexstr: &str) -> Result<Bytes32, String> {
        let bytes = hex::decode(hexstr).map_err(|e| e.to_string())?;
        bytes
            .try_into()
            .map_err(|_| "expected 32 bytes".to_string())
    }
    if target_from_nbits(r.nbits)? != read32(&r.target_hex)? {
        return Err("target does not match compact nBits".into());
    }
    Ok(ChainPublic {
        prev: read32(&r.start_prev_hex)?,
        end: read32(&r.end_hash_hex)?,
        nbits: r.nbits,
        target: read32(&r.target_hex)?,
    })
}

fn assert_range(start: u32, end: u32, max_chunk: u32) -> Result<(), String> {
    if start < FIRST
        || end > LAST
        || end < start
        || end - start + 1 > max_chunk
        || start / 2016 != end / 2016
    {
        return Err("header range invalid or crosses an epoch".into());
    }
    Ok(())
}

fn verified_batch(
    root: &Path,
    start: u32,
    end: u32,
    parent: Option<&str>,
) -> Result<Receipt, String> {
    assert_range(start, end, MAX_HEADERS_PER_BATCH)?;
    let path = batch_path(root, start, end);
    let metadata = read_bounded(&path.join("checkpoint.json"), 16_384)?;
    let receipt: Receipt = serde_json::from_slice(&metadata).map_err(|e| e.to_string())?;
    if receipt.version != FORMAT
        || receipt.start != start
        || receipt.end != end
        || receipt.parent_proof_sha256.as_deref() != parent
    {
        return Err("checkpoint version, range, or predecessor mismatch".into());
    }
    let expected = chain_from_txt(HEADERS, end, (end - start + 1) as usize)?;
    let claimed = public_from_receipt(&receipt)?;
    if claimed != expected.public {
        return Err("checkpoint public statement differs from pinned fixture".into());
    }

    let proof_bytes = read_bounded(&path.join("proof.bin"), MAX_PROOF_BYTES)?;
    let vk_bytes = read_bounded(&path.join("vk.bin"), MAX_VK_BYTES)?;
    if digest(&proof_bytes) != receipt.proof_sha256 || digest(&vk_bytes) != receipt.vk_sha256 {
        return Err("checkpoint artifact SHA-256 mismatch".into());
    }
    let proof = Proof::<Bn254>::deserialize_compressed(&mut BufReader::new(proof_bytes.as_slice()))
        .map_err(|e| e.to_string())?;
    let vk =
        VerifyingKey::<Bn254>::deserialize_compressed(&mut BufReader::new(vk_bytes.as_slice()))
            .map_err(|e| e.to_string())?;
    let pvk = Groth16::<Bn254>::process_vk(&vk).map_err(|e| e.to_string())?;
    let valid = Groth16::<Bn254>::verify_with_processed_vk(&pvk, &claimed.inputs(), &proof)
        .map_err(|e| e.to_string())?;
    if !valid {
        return Err("cryptographic Groth16 verification failed".into());
    }
    Ok(receipt)
}

fn make_batch(
    root: &Path,
    start: u32,
    end: u32,
    parent: Option<String>,
) -> Result<Receipt, String> {
    assert_range(start, end, MAX_HEADERS_PER_BATCH)?;
    let path = batch_path(root, start, end);
    fs::create_dir_all(&path).map_err(|e| e.to_string())?;
    let circuit = chain_from_txt(HEADERS, end, (end - start + 1) as usize)?;
    let public = circuit.public.clone();
    // This deterministic benchmark setup must never be used for funds.
    let mut rng = StdRng::seed_from_u64(0x0067_796d);
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit.clone(), &mut rng)
        .map_err(|e| e.to_string())?;
    let proof = Groth16::<Bn254>::prove(&pk, circuit, &mut rng).map_err(|e| e.to_string())?;
    drop(pk);
    let pvk = Groth16::<Bn254>::process_vk(&vk).map_err(|e| e.to_string())?;
    if !Groth16::<Bn254>::verify_with_processed_vk(&pvk, &public.inputs(), &proof)
        .map_err(|e| e.to_string())?
    {
        return Err("generated proof failed verification".into());
    }

    let mut pb = Vec::new();
    let mut vb = Vec::new();
    proof
        .serialize_compressed(&mut pb)
        .map_err(|e| e.to_string())?;
    vk.serialize_compressed(&mut vb)
        .map_err(|e| e.to_string())?;
    let receipt = Receipt {
        version: FORMAT,
        start,
        end,
        start_prev_hex: hex::encode(public.prev),
        end_hash_hex: hex::encode(public.end),
        nbits: public.nbits,
        target_hex: hex::encode(public.target),
        parent_proof_sha256: parent,
        proof_sha256: digest(&pb),
        vk_sha256: digest(&vb),
    };
    write_sync(&path.join("proof.bin"), &pb)?;
    write_sync(&path.join("vk.bin"), &vb)?;
    let manifest = serde_json::to_vec_pretty(&receipt).map_err(|e| e.to_string())?;
    // The manifest is the last write: it seals an independently verified proof.
    write_sync(&path.join("checkpoint.json"), &manifest)?;
    verified_batch(root, start, end, receipt.parent_proof_sha256.as_deref())
}

/// Scan every requested header range and cryptographically verify on recovery.
/// No resume decision uses a file's existence without full Groth16 verification.
fn run(
    root: &Path,
    start: u32,
    end: u32,
    chunk: u32,
    verify_only: bool,
    max_new: Option<u32>,
) -> Result<(usize, usize), String> {
    if chunk == 0
        || chunk > MAX_HEADERS_PER_BATCH
        || start < FIRST
        || end > LAST
        || end < start
        || start / 2016 != end / 2016
    {
        return Err("invalid requested range or chunk size".into());
    }
    if !verify_only {
        fs::create_dir_all(root).map_err(|e| e.to_string())?;
    }
    let (mut existing, mut created) = (0usize, 0usize);
    let mut current = start;
    let mut parent: Option<String> = None;
    let mut previous_end_hash: Option<String> = None;
    while current <= end {
        let last = end.min(current.saturating_add(chunk - 1));
        let path = batch_path(root, current, last);
        let seal = path.join("checkpoint.json");
        let checkpoint = if seal.exists() {
            existing += 1;
            verified_batch(root, current, last, parent.as_deref())?
        } else if verify_only {
            return Err(format!("unsealed or missing checkpoint at {current}"));
        } else {
            if max_new.is_some_and(|cap| created >= cap as usize) {
                break;
            }
            created += 1;
            make_batch(root, current, last, parent.clone())?
        };
        if let Some(prior_end) = previous_end_hash.as_ref() {
            if checkpoint.start_prev_hex != *prior_end {
                return Err("disconnected header-chain proof batch".into());
            }
        }
        parent = Some(checkpoint.proof_sha256.clone());
        previous_end_hash = Some(checkpoint.end_hash_hex.clone());
        current = last.checked_add(1).ok_or("height overflow")?;
    }
    Ok((existing, created))
}

fn parse_u32(value: Option<&String>, field: &str) -> u32 {
    value
        .unwrap_or_else(|| panic!("missing {field}"))
        .parse::<u32>()
        .unwrap_or_else(|_| panic!("invalid {field}"))
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 || (args[1] != "prove" && args[1] != "verify") {
        eprintln!("usage: checkpoint_headers prove|verify DIRECTORY [--start 959617] [--end 959620] [--chunk-size 1] [--max-new-chunks N]");
        std::process::exit(2);
    }
    let value = |key: &str| {
        args.iter()
            .position(|x| x == key)
            .and_then(|i| args.get(i + 1))
    };
    let start = value("--start")
        .map(|x| parse_u32(Some(x), "start"))
        .unwrap_or(FIRST);
    let end = value("--end")
        .map(|x| parse_u32(Some(x), "end"))
        .unwrap_or(FIRST + 3);
    let chunk = value("--chunk-size")
        .map(|x| parse_u32(Some(x), "chunk-size"))
        .unwrap_or(1);
    let cap = value("--max-new-chunks").map(|x| parse_u32(Some(x), "max-new-chunks"));
    let result = run(
        Path::new(&args[2]),
        start,
        end,
        chunk,
        args[1] == "verify",
        cap,
    );
    match result {
        Ok((existing, created)) => {
            println!("verified_existing={existing} created_and_verified={created}")
        }
        Err(e) => {
            eprintln!("checkpoint proving failed: {e}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn range_check_rejects_invalid_or_oversized_batches() {
        assert!(assert_range(FIRST, FIRST, 1).is_ok());
        assert!(assert_range(FIRST, FIRST + 64, 64).is_err());
        assert!(assert_range(FIRST - 1, FIRST, 64).is_err());
        assert!(assert_range(FIRST + 1, FIRST, 64).is_err());
        assert!(assert_range(FIRST, FIRST, 0).is_err());
    }
    #[test]
    fn public_statement_fails_if_target_is_changed() {
        let c = chain_from_txt(HEADERS, FIRST, 1).unwrap();
        let receipt = Receipt {
            version: FORMAT,
            start: FIRST,
            end: FIRST,
            start_prev_hex: hex::encode(c.public.prev),
            end_hash_hex: hex::encode(c.public.end),
            nbits: c.public.nbits,
            target_hex: hex::encode([0u8; 32]),
            parent_proof_sha256: None,
            proof_sha256: String::new(),
            vk_sha256: String::new(),
        };
        assert!(public_from_receipt(&receipt).is_err());
    }
}
