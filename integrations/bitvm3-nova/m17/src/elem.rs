//! Field encoding of stack elements, and the Poseidon hash shared by the native engine and the
//! circuit.
//!
//! Every stack element is one field element G:
//! - short (at most 30 bytes): G = len + sum b[i] * 2^(8(i+1)), so G < 2^248 and the circuit can
//!   read the length and bytes back by bit decomposition;
//! - long (31 to 520 bytes): G = 2^249 + (H(TAG_LONG, len, 31-byte chunks...) mod 2^248).
//!
//! Bit 249 tells long from short. The encoding is injective up to Poseidon collisions on 248
//! bits. The circuit never computes a long encoding; long elements only enter the stack from the
//! program (pushes, compiled by the checker) or from claim witnesses the checker verifies.

use ff::{Field, PrimeField};
use generic_array::typenum::U5;
use nova_snark::frontend::gadgets::poseidon::{
  IOPattern, PoseidonConstants, Simplex, Sponge, SpongeAPI, SpongeOp, SpongeTrait, Strength,
};
use nova_snark::provider::PallasEngine;
use nova_snark::traits::Engine;
use std::sync::OnceLock;

pub type F = <PallasEngine as Engine>::Scalar;

pub const SHORT_MAX: usize = 30;
const TAG_LONG: u64 = 0x4c4f4e47; // "LONG"

pub fn constants() -> &'static PoseidonConstants<F, U5> {
  static C: OnceLock<PoseidonConstants<F, U5>> = OnceLock::new();
  C.get_or_init(|| Sponge::<F, U5>::api_constants(Strength::Standard))
}

/// Poseidon over the input sequence (sponge, absorb n, squeeze 1), the same as `circuit::hash`.
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

/// 2^k as a field element.
pub fn pow2(k: u32) -> F {
  F::from(2u64).pow_vartime([k as u64])
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

/// Field element as u64, if it fits.
pub fn f_to_u64(f: &F) -> Option<u64> {
  let b = f_to_le(f);
  if b[8..].iter().any(|&x| x != 0) {
    return None;
  }
  Some(u64::from_le_bytes(b[..8].try_into().unwrap()))
}

pub fn enc(bytes: &[u8]) -> F {
  if bytes.len() <= SHORT_MAX {
    let mut b = vec![bytes.len() as u8];
    b.extend_from_slice(bytes);
    f_from_le(&b)
  } else {
    let mut xs = vec![fu(TAG_LONG), fu(bytes.len() as u64)];
    for c in bytes.chunks(31) {
      xs.push(f_from_le(c));
    }
    let h = f_to_le(&hash(&xs));
    let mut t = [0u8; 31];
    t.copy_from_slice(&h[..31]); // low 248 bits
    f_from_le(&t) + pow2(249)
  }
}

pub fn is_long(g: &F) -> bool {
  f_to_le(g)[31] & 0x02 != 0
}

/// Field encoding of a CScriptNum value (minimal encoding).
pub fn enc_num(v: i64) -> F {
  enc(&script_num(v))
}

pub fn script_num(v: i64) -> Vec<u8> {
  if v == 0 {
    return vec![];
  }
  let neg = v < 0;
  let mut m = v.unsigned_abs();
  let mut out = vec![];
  while m > 0 {
    out.push((m & 0xff) as u8);
    m >>= 8;
  }
  if out.last().unwrap() & 0x80 != 0 {
    out.push(if neg { 0x80 } else { 0 });
  } else if neg {
    *out.last_mut().unwrap() |= 0x80;
  }
  out
}

/// The commitment of a stack given bottom to top, as the circuit chains it.
pub fn stack_commit(gs: &[F]) -> F {
  gs.iter().fold(F::ZERO, |s, g| hash(&[s, *g]))
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn short_and_long() {
    assert_eq!(enc(&[]), F::ZERO);
    assert_eq!(enc(&[1]), fu(257));
    assert!(!is_long(&enc(&[7u8; 30])));
    assert!(is_long(&enc(&[7u8; 31])));
    assert_ne!(enc(&[7u8; 31]), enc(&[7u8; 32]));
    assert_eq!(script_num(-1), vec![0x81]);
    assert_eq!(script_num(128), vec![0x80, 0]);
    assert_eq!(script_num(-255), vec![0xff, 0x80]);
  }
}
