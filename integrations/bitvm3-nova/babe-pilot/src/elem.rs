//! Pasta field, Poseidon sponge, and canonical encoding helpers for the BABE-Nova pilot.

use std::sync::OnceLock;

use anyhow::{ensure, Result};
use ff::PrimeField;
use generic_array::typenum::U5;
use nova_snark::{
    frontend::gadgets::poseidon::{
        IOPattern, PoseidonConstants, Simplex, Sponge, SpongeAPI, SpongeOp, SpongeTrait, Strength,
    },
    provider::{ipa_pc::EvaluationEngine, PallasEngine, VestaEngine},
    spartan::snark::RelaxedR1CSSNARK,
    traits::Engine,
};

pub type E1 = PallasEngine;
pub type E2 = VestaEngine;
pub type F = <E1 as Engine>::Scalar;
pub type S1 = RelaxedR1CSSNARK<E1, EvaluationEngine<E1>>;
pub type S2 = RelaxedR1CSSNARK<E2, EvaluationEngine<E2>>;

pub fn poseidon_constants() -> &'static PoseidonConstants<F, U5> {
    static C: OnceLock<PoseidonConstants<F, U5>> = OnceLock::new();
    C.get_or_init(|| Sponge::<F, U5>::api_constants(Strength::Standard))
}

/// Deterministic Poseidon sponge over Pallas scalar field (`absorb(xs.len()), squeeze(1)`).
pub fn poseidon_hash(xs: &[F]) -> F {
    let mut sponge = Sponge::new_with_constants(poseidon_constants(), Simplex);
    let acc = &mut ();
    sponge.start(
        IOPattern(vec![
            SpongeOp::Absorb(xs.len() as u32),
            SpongeOp::Squeeze(1),
        ]),
        None,
        acc,
    );
    SpongeAPI::absorb(&mut sponge, xs.len() as u32, xs, acc);
    let out = SpongeAPI::squeeze(&mut sponge, 1, acc);
    sponge.finish(acc).expect("Poseidon sponge finish");
    out[0]
}

pub fn fu(x: u64) -> F {
    F::from(x)
}

pub fn u128_to_f(x: u128) -> F {
    let mut repr = <F as PrimeField>::Repr::default();
    repr.as_mut()[..16].copy_from_slice(&x.to_le_bytes());
    F::from_repr(repr).expect("128-bit integer is strictly below Pallas scalar modulus")
}

pub fn f_to_le(f: &F) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(f.to_repr().as_ref());
    out
}

pub fn f_from_canonical(bytes: &[u8; 32]) -> Result<F> {
    let mut repr = <F as PrimeField>::Repr::default();
    repr.as_mut().copy_from_slice(bytes);
    let opt: Option<F> = F::from_repr(repr).into();
    ensure!(opt.is_some(), "non-canonical Pallas scalar encoding");
    Ok(opt.unwrap())
}

/// Encodes a 32-byte SHA-256 digest as two 128-bit big-endian halves matching `words_to_state`.
pub fn sha256_digest_halves(digest: &[u8; 32]) -> (F, F) {
    let hi_be = u128::from_be_bytes(digest[..16].try_into().unwrap());
    let lo_be = u128::from_be_bytes(digest[16..].try_into().unwrap());
    (u128_to_f(hi_be), u128_to_f(lo_be))
}

/// Encodes an arbitrary 32-byte identifier (e.g. `session_id`, `circuit_id`, `nonce`) into 2 field limbs.
pub fn bytes32_to_limbs(bytes: &[u8; 32]) -> [F; 2] {
    let lo = u128::from_le_bytes(bytes[..16].try_into().unwrap());
    let hi = u128::from_le_bytes(bytes[16..].try_into().unwrap());
    [u128_to_f(lo), u128_to_f(hi)]
}
