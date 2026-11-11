//! Segmented folding: the window's steps are split into segments folded by separate processes.
//! Segment i starts from the state segment i-1 ended in, so a verifier accepts the window when
//! every segment's proof verifies, the first z0 is the window's initial state, each z0 equals the
//! previous segment's zn, and the last zn is sealed.
//!
//! Files in a work directory: `seg-<i>.wit` (fixed-size witness records), `seg-<i>.z0` and
//! `seg-<i>.zn` (the state vectors, 72 x 32 bytes, canonical little-endian field elements).

use crate::elem::{f_to_le, F};
use crate::machine::{State, StepWitness, NZ};
use crate::native::{limbs, UtxoMap, D};
use ff::PrimeField;

/// flags | block 64 | open_tx 2x32 | op | ev 3x32 | leaf 6x32 | idx u64 | siblings D x 32
pub const WIT_BYTES: usize = 1 + 64 + 64 + 1 + 96 + 192 + 8 + 32 * D;

pub fn f_from_canonical(b: &[u8]) -> Result<F, String> {
  let mut repr = <F as PrimeField>::Repr::default();
  repr.as_mut().copy_from_slice(b);
  Option::from(F::from_repr(repr)).ok_or_else(|| "non-canonical field element".to_string())
}

pub fn wit_to_bytes(w: &StepWitness) -> Vec<u8> {
  assert_eq!(w.sibs.len(), D);
  let mut v = Vec::with_capacity(WIT_BYTES);
  v.push((w.idle as u8) | (w.last as u8) << 1 | (w.end as u8) << 2 | (w.close as u8) << 3 | (w.open as u8) << 4);
  v.extend_from_slice(&w.block);
  for x in &w.open_tx {
    v.extend_from_slice(&f_to_le(x));
  }
  v.push(w.op);
  for x in w.ev.iter().chain(w.leaf.iter()) {
    v.extend_from_slice(&f_to_le(x));
  }
  v.extend_from_slice(&w.idx.to_le_bytes());
  for x in &w.sibs {
    v.extend_from_slice(&f_to_le(x));
  }
  debug_assert_eq!(v.len(), WIT_BYTES);
  v
}

pub fn wit_from_bytes(b: &[u8]) -> Result<StepWitness, String> {
  if b.len() != WIT_BYTES {
    return Err(format!("witness record of {} bytes", b.len()));
  }
  let flags = b[0];
  if flags >> 5 != 0 {
    return Err("unknown witness flag".into());
  }
  let fe = |o: usize| f_from_canonical(&b[o..o + 32]);
  let mut w = StepWitness {
    idle: flags & 1 != 0,
    last: flags & 2 != 0,
    end: flags & 4 != 0,
    close: flags & 8 != 0,
    open: flags & 16 != 0,
    ..Default::default()
  };
  w.block.copy_from_slice(&b[1..65]);
  w.open_tx = [fe(65)?, fe(97)?];
  w.op = b[129];
  let mut o = 130;
  for x in w.ev.iter_mut().chain(w.leaf.iter_mut()) {
    *x = fe(o)?;
    o += 32;
  }
  w.idx = u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
  o += 8;
  w.sibs = (0..D).map(|i| fe(o + 32 * i)).collect::<Result<_, _>>()?;
  Ok(w)
}

pub fn z_to_bytes(z: &[F]) -> Vec<u8> {
  z.iter().flat_map(|x| f_to_le(x)).collect()
}

pub fn z_from_bytes(b: &[u8]) -> Result<Vec<F>, String> {
  if b.len() != NZ * 32 {
    return Err(format!("state of {} bytes, want {}", b.len(), NZ * 32));
  }
  b.chunks(32).map(f_from_canonical).collect()
}

/// The window's initial state is fixed by hash(H-1) and H, except `r_s` and `r`, which the seal
/// checks. Refuses any other z0.
pub fn check_initial(z0: &[F], prev_hash: &[u8; 32], height0: u64) -> Result<State, String> {
  let s = State::from_vec(z0)?;
  let want = State::initial(prev_hash, height0, s.r_s, s.r, UtxoMap::with_rs(s.r_s).root());
  if want.to_vec() != z0 {
    return Err("z0 is not the window's initial state".into());
  }
  Ok(s)
}

/// What a sealed window proves, read from its final state.
#[derive(Debug, Clone)]
pub struct WindowResult {
  pub first_height: u64,
  pub last_height: u64,
  pub prev_hash: [F; 2], // hash(H-1), limbs
  pub tip_hash: [F; 2],  // hash(T), limbs
  pub root: F,
  pub leaves: u64,
  pub r_s: F,
}

pub fn window_result(z0: &State, zn: &[F]) -> Result<WindowResult, String> {
  let s = State::from_vec(zn)?;
  if !s.sealed {
    return Err("the window is not sealed".into());
  }
  if s.h0 != z0.h0 || s.r_s != z0.r_s || s.r != z0.r {
    return Err("window constants changed".into());
  }
  Ok(WindowResult {
    first_height: z0.height,
    last_height: s.height - 1,
    prev_hash: s.h0,
    tip_hash: s.prev,
    root: s.root,
    leaves: s.leaf_count,
    r_s: s.r_s,
  })
}

/// The guest A part of an M16 public statement: `magic | k | steps | z0 (17 x 32) | zn (17 x 32)
/// | ...`. zn[0] is the tip height, zn[1], zn[2] the tip hash as two 16-byte little-endian limbs
/// of the internal-order hash (nova-header-chain `State::to_z`), the same encoding as M18's.
pub struct ChainTip {
  pub magic: [u8; 4],
  pub height: u64,
  pub hash: [F; 2],
}

pub fn m16_tip(public: &[u8]) -> Result<ChainTip, String> {
  const ZB: usize = 17 * 32;
  if public.len() < 12 + 2 * ZB {
    return Err("statement too short".into());
  }
  let magic: [u8; 4] = public[..4].try_into().unwrap();
  let zn = &public[12 + ZB..12 + 2 * ZB];
  let h = f_from_canonical(&zn[..32])?;
  let hb = f_to_le(&h);
  if hb[8..].iter().any(|&x| x != 0) {
    return Err("tip height is not a u64".into());
  }
  Ok(ChainTip {
    magic,
    height: u64::from_le_bytes(hb[..8].try_into().unwrap()),
    hash: [f_from_canonical(&zn[32..64])?, f_from_canonical(&zn[64..96])?],
  })
}

/// Internal-order hash bytes from limbs.
pub fn hash_of_limbs(l: &[F; 2]) -> [u8; 32] {
  let mut out = [0u8; 32];
  out[..16].copy_from_slice(&f_to_le(&l[0])[..16]);
  out[16..].copy_from_slice(&f_to_le(&l[1])[..16]);
  out
}

pub fn same_hash(l: &[F; 2], h: &[u8; 32]) -> bool {
  *l == limbs(h)
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::elem::fu;

  #[test]
  fn witness_record_roundtrip() {
    let mut w = StepWitness::default();
    w.idle = true;
    w.end = true;
    w.open = true;
    w.block = core::array::from_fn(|i| i as u8 * 3);
    w.open_tx = [fu(7), fu(1 << 40)];
    w.op = 4;
    w.ev = [fu(1), fu(2), -fu(3)];
    w.leaf = core::array::from_fn(|i| fu(100 + i as u64));
    w.idx = 12345;
    w.sibs = (0..D).map(|i| fu(i as u64) * fu(0x1234_5678_9abc)).collect();
    let b = wit_to_bytes(&w);
    assert_eq!(b.len(), WIT_BYTES);
    let v = wit_from_bytes(&b).unwrap();
    assert_eq!(wit_to_bytes(&v), b);
    assert_eq!((v.idle, v.last, v.end, v.close, v.open), (true, false, true, false, true));
    assert_eq!(v.ev, w.ev);
    assert_eq!(v.sibs, w.sibs);
  }

  #[test]
  fn initial_state_is_pinned() {
    let prev = [9u8; 32];
    let r_s = fu(11);
    let s = State::initial(&prev, 500, r_s, fu(13), UtxoMap::with_rs(r_s).root());
    let z = s.to_vec();
    assert!(check_initial(&z, &prev, 500).is_ok());
    assert!(check_initial(&z, &prev, 501).is_err());
    let mut bad = z.clone();
    bad[NZ - 14] += fu(1); // the map root
    assert!(check_initial(&bad, &prev, 500).is_err());
    assert_eq!(z_from_bytes(&z_to_bytes(&z)).unwrap(), z);
  }
}
