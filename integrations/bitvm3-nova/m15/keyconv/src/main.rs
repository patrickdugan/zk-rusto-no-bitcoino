//! Re-encodes a pinned Nova 0.76.0 verifier key with uncompressed affine points.
//!
//!   m15-keyconv to-raw KEY.vk RAW.vk
//!
//! Nova serializes the commitment-key generators compressed, and decoding one costs a square
//! root. Inside SP1 that decode was 71% of guest A (51.6 × 10^9 of 72.3 × 10^9 instructions). The
//! raw encoding carries (x, y) and decodes with an on-curve check.
//!
//! The conversion is checked both ways before RAW.vk is written: KEY.vk decodes (compressed), the
//! key encodes raw, RAW.vk decodes (raw) and re-encodes compressed to exactly KEY.vk's bytes. Both
//! files therefore describe the same key, and the guest may commit KEY.vk's SHA-256 (the pinned
//! digest every statement already carries) after checking RAW.vk's.
use anyhow::{bail, ensure, Context, Result};
use ff::PrimeField;
use halo2curves::serde::set_raw_affine_serde;
use nova_snark::{
    frontend::{num::AllocatedNum, ConstraintSystem, SynthesisError},
    nova::VerifierKey,
    provider::{ipa_pc, PallasEngine, VestaEngine},
    spartan::snark::RelaxedR1CSSNARK,
    traits::{circuit::StepCircuit, Engine},
};
use sha2::{Digest, Sha256};

type E1 = PallasEngine;
type E2 = VestaEngine;
type F = <E1 as Engine>::Scalar;
type S1 = RelaxedR1CSSNARK<E1, ipa_pc::EvaluationEngine<E1>>;
type S2 = RelaxedR1CSSNARK<E2, ipa_pc::EvaluationEngine<E2>>;

/// Verification never synthesizes the step circuit; only its arity (17) is used (as in guest A).
#[derive(Clone, Debug)]
struct Arity17;
impl StepCircuit<F> for Arity17 {
    fn arity(&self) -> usize {
        17
    }
    fn synthesize<CS: ConstraintSystem<F>>(&self, _: &mut CS, z: &[AllocatedNum<F>]) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
        Ok(z.to_vec())
    }
}

type Vk = VerifierKey<E1, E2, Arity17, S1, S2>;

fn sha_hex(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

fn decode(bytes: &[u8], raw: bool) -> Result<Vk> {
    set_raw_affine_serde(raw);
    bincode::deserialize(bytes).with_context(|| format!("decoding the key ({})", if raw { "raw" } else { "compressed" }))
}

fn encode(vk: &Vk, raw: bool) -> Result<Vec<u8>> {
    set_raw_affine_serde(raw);
    Ok(bincode::serialize(vk)?)
}

fn main() -> Result<()> {
    let a: Vec<String> = std::env::args().collect();
    if a.len() != 4 || a[1] != "to-raw" {
        bail!("usage: m15-keyconv to-raw KEY.vk RAW.vk");
    }
    let compressed = std::fs::read(&a[2]).with_context(|| format!("reading {}", a[2]))?;
    let vk = decode(&compressed, false)?;
    ensure!(encode(&vk, false)? == compressed, "the compressed key does not re-encode to itself");
    let raw = encode(&vk, true)?;
    let back = decode(&raw, true)?;
    ensure!(encode(&back, false)? == compressed, "the raw key does not re-encode to the compressed key");
    ensure!(encode(&back, true)? == raw, "the raw key does not re-encode to itself");
    std::fs::write(&a[3], &raw)?;
    let _ = F::NUM_BITS;
    println!(
        "{}",
        serde_json::json!({
            "compressed_sha256": sha_hex(&compressed), "compressed_bytes": compressed.len(),
            "raw_sha256": sha_hex(&raw), "raw_bytes": raw.len(),
            "added_bytes": raw.len() - compressed.len(),
            "points": (raw.len() - compressed.len()) / 32,
        })
    );
    Ok(())
}
