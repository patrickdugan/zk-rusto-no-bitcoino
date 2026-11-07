//! M13 final-proof verifier.
//!
//! The final proof is SP1 6.9.0's wrap layer (the STARK SP1 hands to gnark)
//! proved under [`ctx::Blake3KoalaBear`] instead of BN254 Poseidon2. This
//! crate holds everything a verifier needs and nothing a prover needs:
//! the configuration, the wrap machine and parameters, the statement decoding
//! and [`verify_final`]. `m13/wrap` builds the proofs on top of it.

pub mod ctx;
pub mod opcount;

use std::borrow::Borrow;

use anyhow::{anyhow, ensure, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use slop_algebra::PrimeField32;
use slop_challenger::IopCtx;
use sp1_hypercube::{
    MachineVerifier, MachineVerifyingKey, SP1PcsProof, SP1WrapProof, ShardContextImpl, ShardVerifier, SP1Pcs,
};
use sp1_primitives::{fri_params::wrap_fri_config, SP1Field};
use sp1_recursion_executor::RecursionPublicValues;
use sp1_recursion_machine::RecursionAir;
use sp1_verifier::compressed::RECURSION_MAX_LOG_ROW_COUNT;

pub use ctx::{Blake3KoalaBear, Blake3KoalaBearV2};

/// sp1-prover 6.9.0 `components::WRAP_LOG_STACKING_HEIGHT` (crate-private there).
pub const WRAP_LOG_STACKING_HEIGHT: u32 = 21;

/// sp1-prover 6.9.0 `WrapAir<F>` = `RecursionAir<F, WRAP_DEGREE = 3, 1>`.
pub type WrapAir = RecursionAir<SP1Field, 3, 1>;
pub type Blake3WrapSC = ShardContextImpl<Blake3KoalaBear, SP1Pcs<Blake3KoalaBear>, WrapAir>;
pub type Blake3WrapProof = SP1WrapProof<Blake3KoalaBear, SP1PcsProof<Blake3KoalaBear>>;
/// Transcript v2 (fixed-cost challenges, [`ctx::Blake3ChallengerV2`]).
pub type Blake3WrapSCV2 = ShardContextImpl<Blake3KoalaBearV2, SP1Pcs<Blake3KoalaBearV2>, WrapAir>;
pub type Blake3WrapProofV2 = SP1WrapProof<Blake3KoalaBearV2, SP1PcsProof<Blake3KoalaBearV2>>;

/// The BLAKE3 wrap verifier: SP1's wrap machine and FRI parameters, BLAKE3 hashing.
pub fn wrap_verifier() -> MachineVerifier<Blake3KoalaBear, Blake3WrapSC> {
    MachineVerifier::new(ShardVerifier::from_basefold_parameters(
        wrap_fri_config(),
        WRAP_LOG_STACKING_HEIGHT,
        RECURSION_MAX_LOG_ROW_COUNT,
        WrapAir::wrap_machine(),
    ))
}

/// [`wrap_verifier`] with transcript v2.
pub fn wrap_verifier_v2() -> MachineVerifier<Blake3KoalaBearV2, Blake3WrapSCV2> {
    MachineVerifier::new(ShardVerifier::from_basefold_parameters(
        wrap_fri_config(),
        WRAP_LOG_STACKING_HEIGHT,
        RECURSION_MAX_LOG_ROW_COUNT,
        WrapAir::wrap_machine(),
    ))
}

/// A final-layer configuration: its STARK check.
pub trait FinalLayer: IopCtx<F = SP1Field> {
    fn verify_stark(wrap: &SP1WrapProof<Self, SP1PcsProof<Self>>) -> Result<()>;
}
impl FinalLayer for Blake3KoalaBear {
    fn verify_stark(wrap: &Blake3WrapProof) -> Result<()> {
        verify_wrap_proof(wrap)
    }
}
impl FinalLayer for Blake3KoalaBearV2 {
    fn verify_stark(wrap: &Blake3WrapProofV2) -> Result<()> {
        verify_wrap_proof_v2(wrap)
    }
}

/// [`verify_wrap_proof`] with transcript v2.
pub fn verify_wrap_proof_v2(wrap: &Blake3WrapProofV2) -> Result<()> {
    let mut challenger = Blake3KoalaBearV2::default_challenger();
    wrap.vk.observe_into(&mut challenger);
    wrap_verifier_v2()
        .verify_shard(&wrap.vk, &wrap.proof, &mut challenger)
        .map_err(|e| anyhow!("BLAKE3 wrap proof (transcript v2) rejected: {e:?}"))
}

pub fn sha_hex(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

pub fn vk_sha256<GC: IopCtx>(vk: &MachineVerifyingKey<GC>) -> String {
    sha_hex(&bincode::serialize(vk).expect("vk serializes"))
}

/// The STARK check alone: the BLAKE3 wrap proof verifies under its own key.
pub fn verify_wrap_proof(wrap: &Blake3WrapProof) -> Result<()> {
    let mut challenger = Blake3KoalaBear::default_challenger();
    wrap.vk.observe_into(&mut challenger);
    wrap_verifier()
        .verify_shard(&wrap.vk, &wrap.proof, &mut challenger)
        .map_err(|e| anyhow!("BLAKE3 wrap proof rejected: {e:?}"))
}

/// What the final proof attests, decoded from the wrap proof's public values.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FinalStatement {
    /// SHA-256 of the bincode wrap verifying key (the pinned final key).
    pub wrap_vk_sha256: String,
    /// The guest program's SP1 key digest: 8 KoalaBear elements, hex of their LE u32s.
    pub program_vk_digest: String,
    /// SHA-256 of the guest's committed public values (SP1 commits this digest).
    pub committed_values_sha256: String,
    pub exit_code: u32,
    pub is_complete: u32,
    /// Root of SP1's recursion key map: 8 KoalaBear elements, hex of their LE u32s.
    pub recursion_vk_root: String,
}

fn felts_hex(xs: &[SP1Field]) -> String {
    hex::encode(xs.iter().flat_map(|x| x.as_canonical_u32().to_le_bytes()).collect::<Vec<u8>>())
}

pub fn final_statement<GC: FinalLayer>(wrap: &SP1WrapProof<GC, SP1PcsProof<GC>>) -> Result<FinalStatement> {
    ensure!(
        wrap.proof.public_values.len() >= std::mem::size_of::<RecursionPublicValues<u8>>(),
        "public values too short"
    );
    let pv: &RecursionPublicValues<SP1Field> = wrap.proof.public_values.as_slice().borrow();
    let mut digest = Vec::with_capacity(32);
    for word in pv.committed_value_digest.iter() {
        for b in word.iter() {
            let v = b.as_canonical_u32();
            ensure!(v < 256, "committed value digest limb {v} is not a byte");
            digest.push(v as u8);
        }
    }
    Ok(FinalStatement {
        wrap_vk_sha256: vk_sha256(&wrap.vk),
        program_vk_digest: felts_hex(&pv.sp1_vk_digest),
        committed_values_sha256: hex::encode(digest),
        exit_code: pv.exit_code.as_canonical_u32(),
        is_complete: pv.is_complete.as_canonical_u32(),
        recursion_vk_root: felts_hex(&pv.vk_root),
    })
}

/// The complete final-proof verifier: the pinned wrap key, the STARK, and
/// every statement field. `expect` carries the pins (wrap key, guest program,
/// recursion key map) and the statement digest the caller requires.
pub fn verify_final<GC: FinalLayer>(
    wrap: &SP1WrapProof<GC, SP1PcsProof<GC>>,
    expect: &FinalStatement,
) -> Result<FinalStatement> {
    let got = final_statement(wrap)?;
    ensure!(got.wrap_vk_sha256 == expect.wrap_vk_sha256, "wrap key is not the pinned key");
    GC::verify_stark(wrap)?;
    ensure!(got.exit_code == 0, "guest exit code {} (a refused input)", got.exit_code);
    ensure!(got.is_complete == 1, "proof is not complete");
    ensure!(got.program_vk_digest == expect.program_vk_digest, "different guest program");
    ensure!(got.recursion_vk_root == expect.recursion_vk_root, "different recursion key map");
    ensure!(got.committed_values_sha256 == expect.committed_values_sha256, "different committed statement");
    Ok(got)
}
