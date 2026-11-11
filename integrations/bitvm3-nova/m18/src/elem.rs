//! Field helpers and the Poseidon hash shared by the native map and the circuit gadgets. The
//! hash is M17's: a sponge over the Pallas scalar field, absorb n, squeeze 1.

use ff::PrimeField;
use generic_array::typenum::U5;
use nova_snark::frontend::gadgets::poseidon::{
  IOPattern, PoseidonConstants, Simplex, Sponge, SpongeAPI, SpongeOp, SpongeTrait, Strength,
};
use nova_snark::provider::PallasEngine;
use nova_snark::traits::Engine;
use std::sync::OnceLock;

pub type F = <PallasEngine as Engine>::Scalar;

pub fn constants() -> &'static PoseidonConstants<F, U5> {
  static C: OnceLock<PoseidonConstants<F, U5>> = OnceLock::new();
  C.get_or_init(|| Sponge::<F, U5>::api_constants(Strength::Standard))
}

/// Poseidon over the input sequence (sponge, absorb n, squeeze 1).
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

/// Little-endian bytes (at most 31) as a field element.
pub fn f_from_le(b: &[u8]) -> F {
  assert!(b.len() <= 31);
  let mut repr = <F as PrimeField>::Repr::default();
  repr.as_mut()[..b.len()].copy_from_slice(b);
  F::from_repr(repr).unwrap()
}

pub fn f_to_le(f: &F) -> [u8; 32] {
  let mut out = [0u8; 32];
  out.copy_from_slice(f.to_repr().as_ref());
  out
}

/// The low 248 bits of x as a field element.
pub fn low248(x: &F) -> F {
  f_from_le(&f_to_le(x)[..31])
}

/// Integer order of two field elements below 2^248 (or any canonical elements).
pub fn lt(a: &F, b: &F) -> bool {
  let (x, y) = (f_to_le(a), f_to_le(b));
  x.iter().rev().cmp(y.iter().rev()) == std::cmp::Ordering::Less
}
