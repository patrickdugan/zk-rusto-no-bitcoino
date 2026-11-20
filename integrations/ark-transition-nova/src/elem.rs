//! Field elements, the shared Poseidon hash, and the byte encodings.
//!
//! Mapping from bytes to the Pallas scalar field:
//! - 32-byte `spend_id` / `commit`: the first 31 bytes, big-endian, as a 248-bit integer;
//! - `statement_digest`: two 128-bit limbs, hi = bytes[0..16], lo = bytes[16..32], big-endian;
//! - field elements in JSON: 64 hex characters, 32 bytes big-endian.

use ff::{Field, PrimeField};
use generic_array::typenum::U5;
use nova_snark::frontend::gadgets::poseidon::{IOPattern, PoseidonConstants, Simplex, Sponge, SpongeAPI, SpongeOp, SpongeTrait, Strength};
use nova_snark::provider::PallasEngine;
use nova_snark::traits::Engine;
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

pub type F = <PallasEngine as Engine>::Scalar;

pub const TAG_DOMAIN: &str = "ArkTransitionV1/nova";
pub const TAG_GAMMA: &str = "ArkTransitionV1/nova/gamma";

pub fn constants() -> &'static PoseidonConstants<F, U5> {
  static C: OnceLock<PoseidonConstants<F, U5>> = OnceLock::new();
  C.get_or_init(|| Sponge::<F, U5>::api_constants(Strength::Standard))
}

/// Poseidon over the input sequence (sponge: absorb n, squeeze 1); the circuit does the same.
pub fn hash(xs: &[F]) -> F {
  let mut sponge = Sponge::new_with_constants(constants(), Simplex);
  let acc = &mut ();
  sponge.start(IOPattern(vec![SpongeOp::Absorb(xs.len() as u32), SpongeOp::Squeeze(1)]), None, acc);
  SpongeAPI::absorb(&mut sponge, xs.len() as u32, xs, acc);
  let out = SpongeAPI::squeeze(&mut sponge, 1, acc);
  sponge.finish(acc).unwrap();
  out[0]
}

pub fn fu(x: u64) -> F {
  F::from(x)
}

pub fn pow2(k: u32) -> F {
  F::from(2u64).pow_vartime([k as u64])
}

/// Big-endian bytes (at most 32) as a field element, if the integer is below the modulus.
pub fn f_from_be(b: &[u8]) -> Option<F> {
  if b.len() > 32 {
    return None;
  }
  let mut repr = <F as PrimeField>::Repr::default();
  for (i, x) in b.iter().rev().enumerate() {
    repr.as_mut()[i] = *x;
  }
  Option::from(F::from_repr(repr))
}

pub fn f_to_be(f: &F) -> [u8; 32] {
  let mut out = [0u8; 32];
  out.copy_from_slice(f.to_repr().as_ref());
  out.reverse();
  out
}

pub fn f_hex(f: &F) -> String {
  hex::encode(f_to_be(f))
}

pub fn f_from_hex(s: &str) -> Option<F> {
  let b = hex::decode(s).ok()?;
  if b.len() != 32 {
    return None;
  }
  f_from_be(&b)
}

/// First 31 bytes of a 32-byte value, big-endian, as a 248-bit field element.
pub fn id31(b: &[u8; 32]) -> F {
  f_from_be(&b[..31]).unwrap()
}

/// (hi, lo) 128-bit limbs of the statement digest.
pub fn limbs(d: &[u8; 32]) -> (F, F) {
  (f_from_be(&d[..16]).unwrap(), f_from_be(&d[16..]).unwrap())
}

/// A domain constant: the first 31 bytes of SHA-256(tag), big-endian.
pub fn domain(tag: &str) -> F {
  let h = Sha256::digest(tag.as_bytes());
  f_from_be(&h[..31]).unwrap()
}

pub fn sha256_hex(b: &[u8]) -> String {
  hex::encode(Sha256::digest(b))
}
