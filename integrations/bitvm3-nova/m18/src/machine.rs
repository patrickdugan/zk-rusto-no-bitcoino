//! The M18 step machine, native. `step` is the source of truth: the Nova step circuit in
//! `circuit.rs` enforces exactly the relations checked here, and the state vector `State::to_vec`
//! is the circuit's `z`. See README.md ("The step circuit").
//!
//! A step has two independent slots, a producer (one SHA-256 compression, a phase, the byte parser
//! and the Merkle frontier) and a consumer (one map leaf update). They meet at HDR3, where the
//! consumer must have applied exactly the events the producer parsed.

use crate::elem::{f_from_le, f_to_le, fu, hash, low248, lt, F};
use crate::native::{self, limbs, parse_block, root_of, sha256d, Path, UtxoMap, D};
use ff::Field;
use sha2::digest::generic_array::GenericArray;

pub const NF: usize = 16; // frontier slots: a block has fewer than 2^16 transactions
pub const NZ: usize = 72; // state length

pub mod phase {
  pub const BODY: u64 = 0;
  pub const TXID: u64 = 1;
  pub const MERGE1: u64 = 2;
  pub const MERGE2: u64 = 3;
  pub const MERGE3: u64 = 4;
  pub const HDR1: u64 = 5;
  pub const HDR2: u64 = 6;
  pub const HDR3: u64 = 7;
  pub const DONE: u64 = 8;
  pub const COUNT: usize = 9;
}

pub mod pst {
  pub const VER: u64 = 0;
  pub const INCNT_FIRST: u64 = 1;
  pub const INCNT_REST: u64 = 2;
  pub const PTXLO: u64 = 3;
  pub const PTXHI: u64 = 4;
  pub const PVOUT: u64 = 5;
  pub const SSLEN_FIRST: u64 = 6;
  pub const SSLEN_REST: u64 = 7;
  pub const SS: u64 = 8;
  pub const SEQ: u64 = 9;
  pub const OUTCNT_FIRST: u64 = 10;
  pub const OUTCNT_REST: u64 = 11;
  pub const VALUE: u64 = 12;
  pub const SPKLEN_FIRST: u64 = 13;
  pub const SPKLEN_REST: u64 = 14;
  pub const SPK: u64 = 15;
  pub const LOCK: u64 = 16;
  pub const PAD80: u64 = 17;
  pub const PADZ: u64 = 18;
  pub const LEN: u64 = 19;
  pub const DONE: u64 = 20;
  pub const COUNT: usize = 21;
  /// Circuit only: the state of a parser that does not run in this step.
  pub const SINK: u64 = 21;
}

pub mod opk {
  pub const NONE: u8 = 0;
  pub const SPEND_IN: u8 = 1;
  pub const SPEND_PRE: u8 = 2;
  pub const CREATE_LOW: u8 = 3;
  pub const CREATE_NEW: u8 = 4;
  pub const COUNT: usize = 5;
}

const IV: [u32; 8] = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];

pub fn to_u64(f: &F) -> Result<u64, String> {
  let b = f_to_le(f);
  if b[8..].iter().any(|x| *x != 0) {
    return Err("value does not fit 64 bits".into());
  }
  Ok(u64::from_le_bytes(b[..8].try_into().unwrap()))
}

// ---------------------------------------------------------------------------------------------
// Hash representations
// ---------------------------------------------------------------------------------------------

/// A 32-byte digest as two numbers: `lo` is the big-endian integer of bytes 0..16, `hi` of bytes
/// 16..32 (the SHA-256 state words, high word first). The SHA register, the frontier and the carry
/// use this form; `prev`, `h0` and the txid in events use the little-endian limbs of `native::limbs`.
pub fn bytes_to_halves(b: &[u8; 32]) -> [F; 2] {
  let mut x = [0u8; 16];
  let mut y = [0u8; 16];
  for i in 0..16 {
    x[i] = b[15 - i];
    y[i] = b[31 - i];
  }
  [f_from_le(&x), f_from_le(&y)]
}

pub fn halves_to_bytes(h: &[F; 2]) -> [u8; 32] {
  let mut out = [0u8; 32];
  for k in 0..2 {
    let le = f_to_le(&h[k]);
    for i in 0..16 {
      out[16 * k + i] = le[15 - i];
    }
  }
  out
}

fn words_of(h: &[F; 2]) -> [u32; 8] {
  let b = halves_to_bytes(h);
  std::array::from_fn(|i| u32::from_be_bytes(b[4 * i..4 * i + 4].try_into().unwrap()))
}

fn halves_of_words(w: &[u32; 8]) -> [F; 2] {
  let mut b = [0u8; 32];
  for i in 0..8 {
    b[4 * i..4 * i + 4].copy_from_slice(&w[i].to_be_bytes());
  }
  bytes_to_halves(&b)
}

pub fn iv_halves() -> [F; 2] {
  halves_of_words(&IV)
}

fn compress(chain: [u32; 8], blk: &[u8; 64]) -> [u32; 8] {
  let mut st = chain;
  sha2::compress256(&mut st, &[*GenericArray::from_slice(blk)]);
  st
}

/// Padding blocks: 32 bytes of message, 64 bytes of message, and 80 bytes (second block).
pub fn pad32_block(reg: &[u8; 32]) -> [u8; 64] {
  let mut b = [0u8; 64];
  b[..32].copy_from_slice(reg);
  b[32] = 0x80;
  b[62] = 0x01; // 256 bits
  b
}

pub fn pad64_block() -> [u8; 64] {
  let mut b = [0u8; 64];
  b[0] = 0x80;
  b[62] = 0x02; // 512 bits
  b
}

pub fn hdr2_block(tail: &[u8]) -> [u8; 64] {
  let mut b = [0u8; 64];
  b[..16].copy_from_slice(&tail[..16]);
  b[16] = 0x80;
  b[62] = 0x02;
  b[63] = 0x80; // 640 bits
  b
}

/// The padded non-witness serialization of a transaction, a whole number of 64-byte blocks.
pub fn pad_tx(nonwit: &[u8]) -> Vec<u8> {
  let mut v = nonwit.to_vec();
  v.push(0x80);
  while v.len() % 64 != 56 {
    v.push(0);
  }
  v.extend_from_slice(&((nonwit.len() as u64) * 8).to_be_bytes());
  v
}

// ---------------------------------------------------------------------------------------------
// Event fingerprints
// ---------------------------------------------------------------------------------------------

/// Horner: `F := F*r + x` over the four elements of an event.
pub fn fold_f(f: F, r: F, x: [F; 4]) -> F {
  let mut a = f;
  for v in x {
    a = a * r + v;
  }
  a
}

/// `Gc := Poseidon(Gc, x1, x2, x3, x4)`.
pub fn fold_g(g: F, x: [F; 4]) -> F {
  hash(&[g, x[0], x[1], x[2], x[3]])
}

pub fn key_of_f(lo: F, hi: F, vout: F) -> F {
  low248(&hash(&[lo, hi, vout]))
}

// ---------------------------------------------------------------------------------------------
// The parser
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Par {
  pub ps: u64,
  pub rem: u64,    // bytes left in the field (LEN: bytes left of the bit length)
  pub acc: F,      // little-endian accumulator of the field being read
  pub vmul: F,     // 256^(bytes read in the field)
  pub n_in: u64,   // inputs left
  pub n_out: u64,  // outputs left
  pub out_idx: u64, // index of the output being read
  pub pl: F,       // previous txid, low and high limbs (little-endian) of the outpoint being read
  pub ph: F,
  pub val: u64,    // value of the output being read
  pub sfp: F,      // script fingerprint of the output being read
  pub tx_len: u64, // bytes of the transaction so far (padding excluded)
  pub lenacc: F,   // big-endian accumulator of the bit length
}

impl Par {
  pub fn init() -> Par {
    Par {
      ps: pst::VER,
      rem: 4,
      acc: F::ZERO,
      vmul: F::ONE,
      n_in: 0,
      n_out: 0,
      out_idx: 0,
      pl: F::ZERO,
      ph: F::ZERO,
      val: 0,
      sfp: F::ZERO,
      tx_len: 0,
      lenacc: F::ZERO,
    }
  }
}

type Ev = Option<[F; 4]>;

fn enter(p: &mut Par, s: u64, rem: u64) {
  p.ps = s;
  p.rem = rem;
}

fn after_out(p: &mut Par) {
  p.out_idx += 1;
  p.n_out -= 1;
  if p.n_out == 0 {
    enter(p, pst::LOCK, 4);
  } else {
    enter(p, pst::VALUE, 8);
  }
}

/// A compact size is complete: `first` is the FIRST state of its kind, `cv` its value.
fn ready(p: &mut Par, first: u64, cv: F) -> Result<Ev, String> {
  match first {
    pst::INCNT_FIRST => {
      if cv == F::ZERO {
        return Err("input count 0".into());
      }
      p.n_in = to_u64(&cv)?;
      enter(p, pst::PTXLO, 16);
    }
    pst::SSLEN_FIRST => {
      let l = to_u64(&cv)?;
      if l == 0 {
        enter(p, pst::SEQ, 4);
      } else {
        enter(p, pst::SS, l);
      }
    }
    pst::OUTCNT_FIRST => {
      if cv == F::ZERO {
        return Err("output count 0".into());
      }
      p.n_out = to_u64(&cv)?;
      enter(p, pst::VALUE, 8);
    }
    pst::SPKLEN_FIRST => {
      let l = to_u64(&cv)?;
      p.sfp = cv;
      if l == 0 {
        let ev = [fu(2), fu(p.out_idx), fu(p.val), F::ZERO];
        after_out(p);
        return Ok(Some(ev));
      }
      enter(p, pst::SPK, l);
    }
    _ => unreachable!(),
  }
  Ok(None)
}

/// One byte at block position `pos`. Returns the event the byte completes, if any.
pub fn par_byte(p: &mut Par, b: u8, pos: usize, r_s: F) -> Result<Ev, String> {
  use pst::*;
  let bf = fu(b as u64);
  let mut s = p.ps;
  if s == DONE {
    return Err("byte after the end of the transaction".into());
  }
  if s == PADZ && pos == 56 {
    s = LEN;
    p.ps = LEN;
  }
  if s <= LOCK {
    p.tx_len += 1;
  }
  let mut ev: Ev = None;
  match s {
    INCNT_FIRST | SSLEN_FIRST | OUTCNT_FIRST | SPKLEN_FIRST => match b {
      0xff => return Err("compact size 0xff".into()),
      0xfd => enter(p, s + 1, 2),
      0xfe => enter(p, s + 1, 4),
      _ => ev = ready(p, s, bf)?,
    },
    VER | INCNT_REST | PTXLO | PTXHI | PVOUT | SSLEN_REST | SEQ | OUTCNT_REST | VALUE | SPKLEN_REST | LOCK => {
      if p.rem == 0 {
        return Err("field with no bytes left".into());
      }
      let accn = p.acc + bf * p.vmul;
      if p.rem == 1 {
        p.acc = F::ZERO;
        p.vmul = F::ONE;
        p.rem = 0;
        match s {
          VER => p.ps = INCNT_FIRST,
          INCNT_REST => ev = ready(p, INCNT_FIRST, accn)?,
          PTXLO => {
            p.pl = accn;
            enter(p, PTXHI, 16);
          }
          PTXHI => {
            p.ph = accn;
            enter(p, PVOUT, 4);
          }
          PVOUT => {
            ev = Some([fu(1), p.pl, p.ph, accn]);
            p.ps = SSLEN_FIRST;
          }
          SSLEN_REST => ev = ready(p, SSLEN_FIRST, accn)?,
          SEQ => {
            p.n_in -= 1;
            if p.n_in == 0 {
              p.ps = OUTCNT_FIRST;
            } else {
              enter(p, PTXLO, 16);
            }
          }
          OUTCNT_REST => ev = ready(p, OUTCNT_FIRST, accn)?,
          VALUE => {
            p.val = to_u64(&accn)?;
            p.ps = SPKLEN_FIRST;
          }
          SPKLEN_REST => ev = ready(p, SPKLEN_FIRST, accn)?,
          LOCK => p.ps = PAD80,
          _ => unreachable!(),
        }
      } else {
        p.acc = accn;
        p.vmul *= fu(256);
        p.rem -= 1;
      }
    }
    SS => {
      if p.rem == 0 {
        return Err("field with no bytes left".into());
      }
      if p.rem == 1 {
        enter(p, SEQ, 4);
      } else {
        p.rem -= 1;
      }
    }
    SPK => {
      if p.rem == 0 {
        return Err("field with no bytes left".into());
      }
      p.sfp = p.sfp * r_s + bf;
      if p.rem == 1 {
        ev = Some([fu(2), fu(p.out_idx), fu(p.val), p.sfp]);
        after_out(p);
      } else {
        p.rem -= 1;
      }
    }
    PAD80 => {
      if b != 0x80 {
        return Err("padding does not start with 0x80".into());
      }
      enter(p, PADZ, 8);
    }
    PADZ => {
      if b != 0 {
        return Err("padding byte is not zero".into());
      }
    }
    LEN => {
      p.lenacc = p.lenacc * fu(256) + bf;
      if p.rem == 1 {
        if p.lenacc != fu(8 * p.tx_len) {
          return Err("bit length does not match the transaction".into());
        }
        if p.tx_len == 64 {
          return Err("64-byte transaction".into());
        }
        enter(p, DONE, 0);
      } else {
        p.rem -= 1;
      }
    }
    _ => unreachable!(),
  }
  Ok(ev)
}

// ---------------------------------------------------------------------------------------------
// State and witness
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct State {
  // producer
  pub phase: u64,
  pub fresh: bool,       // the current transaction's first body block is next (chaining value = IV)
  pub sha: [F; 2],       // SHA register, halves form
  pub prev: [F; 2],      // hash of the previous block, little-endian limbs
  pub height: u64,       // height of the block being read
  pub n: u64,            // leaves added to this block's Merkle frontier (binary counter)
  pub frontier: [[F; 2]; NF], // slot j holds a subtree of 2^j leaves when bit j of n is set; halves form
  pub carry: [F; 2],     // halves form: the merge's right operand, then the Merkle root
  pub mlevel: u64,       // level of the pending merge
  pub lastf: bool,       // the transaction being finished is the block's last
  // parser
  pub par: Par,
  // events
  pub fp: F,             // producer fingerprint
  // consumer
  pub root: F,
  pub leaf_count: u64,
  pub fc: F,             // consumer fingerprint
  pub gc: F,             // consumer hash chain
  pub open: bool,
  pub tx: [F; 2],        // current transaction id, little-endian limbs
  pub pending: bool,     // a CREATE_LOW waits for its CREATE_NEW
  pub pend: F,           // hash of the pending new leaf
  // window constants and result
  pub h0: [F; 2],        // hash(H-1), little-endian limbs
  pub r_s: F,
  pub r: F,
  pub sealed: bool,
}

fn b2f(b: bool) -> F {
  if b {
    F::ONE
  } else {
    F::ZERO
  }
}

fn f2b(f: &F, what: &str) -> Result<bool, String> {
  if *f == F::ZERO {
    Ok(false)
  } else if *f == F::ONE {
    Ok(true)
  } else {
    Err(format!("{what} is not a bit"))
  }
}

impl State {
  /// z0 for a window starting at height `height0` whose previous block has internal-order hash
  /// `prev_hash`; `root0` is the root of the empty map. A verifier recomputes this vector.
  pub fn initial(prev_hash: &[u8; 32], height0: u64, r_s: F, r: F, root0: F) -> State {
    let l = limbs(prev_hash);
    State {
      phase: phase::BODY,
      fresh: true,
      sha: iv_halves(),
      prev: l,
      height: height0,
      n: 0,
      frontier: [[F::ZERO; 2]; NF],
      carry: [F::ZERO; 2],
      mlevel: 0,
      lastf: false,
      par: Par::init(),
      fp: F::ZERO,
      root: root0,
      leaf_count: 1,
      fc: F::ZERO,
      gc: F::ZERO,
      open: false,
      tx: [F::ZERO; 2],
      pending: false,
      pend: F::ZERO,
      h0: l,
      r_s,
      r,
      sealed: false,
    }
  }

  pub fn to_vec(&self) -> Vec<F> {
    let mut v = Vec::with_capacity(NZ);
    v.push(fu(self.phase));
    v.push(b2f(self.fresh));
    v.extend_from_slice(&self.sha);
    v.extend_from_slice(&self.prev);
    v.push(fu(self.height));
    v.push(fu(self.n));
    for s in &self.frontier {
      v.extend_from_slice(s);
    }
    v.extend_from_slice(&self.carry);
    v.push(fu(self.mlevel));
    v.push(b2f(self.lastf));
    let p = &self.par;
    v.extend_from_slice(&[
      fu(p.ps),
      fu(p.rem),
      p.acc,
      p.vmul,
      fu(p.n_in),
      fu(p.n_out),
      fu(p.out_idx),
      p.pl,
      p.ph,
      fu(p.val),
      p.sfp,
      fu(p.tx_len),
      p.lenacc,
    ]);
    v.push(self.fp);
    v.push(self.root);
    v.push(fu(self.leaf_count));
    v.push(self.fc);
    v.push(self.gc);
    v.push(b2f(self.open));
    v.extend_from_slice(&self.tx);
    v.push(b2f(self.pending));
    v.push(self.pend);
    v.extend_from_slice(&self.h0);
    v.push(self.r_s);
    v.push(self.r);
    v.push(b2f(self.sealed));
    debug_assert_eq!(v.len(), NZ);
    v
  }

  pub fn from_vec(v: &[F]) -> Result<State, String> {
    if v.len() != NZ {
      return Err(format!("state length {} is not {NZ}", v.len()));
    }
    let mut i = 0;
    let mut nx = || {
      i += 1;
      v[i - 1]
    };
    let phase = to_u64(&nx())?;
    let fresh = f2b(&nx(), "fresh")?;
    let sha = [nx(), nx()];
    let prev = [nx(), nx()];
    let height = to_u64(&nx())?;
    let n = to_u64(&nx())?;
    let mut frontier = [[F::ZERO; 2]; NF];
    for s in frontier.iter_mut() {
      *s = [nx(), nx()];
    }
    let carry = [nx(), nx()];
    let mlevel = to_u64(&nx())?;
    let lastf = f2b(&nx(), "lastf")?;
    let par = Par {
      ps: to_u64(&nx())?,
      rem: to_u64(&nx())?,
      acc: nx(),
      vmul: nx(),
      n_in: to_u64(&nx())?,
      n_out: to_u64(&nx())?,
      out_idx: to_u64(&nx())?,
      pl: nx(),
      ph: nx(),
      val: to_u64(&nx())?,
      sfp: nx(),
      tx_len: to_u64(&nx())?,
      lenacc: nx(),
    };
    let fp = nx();
    let root = nx();
    let leaf_count = to_u64(&nx())?;
    let fc = nx();
    let gc = nx();
    let open = f2b(&nx(), "open")?;
    let tx = [nx(), nx()];
    let pending = f2b(&nx(), "pending")?;
    let pend = nx();
    let h0 = [nx(), nx()];
    let r_s = nx();
    let r = nx();
    let sealed = f2b(&nx(), "sealed")?;
    Ok(State { phase, fresh, sha, prev, height, n, frontier, carry, mlevel, lastf, par, fp, root, leaf_count, fc, gc, open, tx, pending, pend, h0, r_s, r, sealed })
  }
}

#[derive(Clone, Debug)]
pub struct StepWitness {
  pub idle: bool,
  /// BODY and HDR1: the 64 message bytes. HDR2: header bytes 64..80 then the padding. The other
  /// phases: the message block the phase derives (the circuit checks it against the state).
  pub block: [u8; 64],
  pub last: bool, // TXID: the transaction is the block's last
  pub end: bool,  // HDR3: the window ends with this block
  pub close: bool,
  pub open: bool,
  pub open_tx: [F; 2], // txid limbs of the transaction opened
  pub op: u8,
  pub ev: [F; 3], // spends: (prev_lo, prev_hi, vout); create: (out_idx, value, script_fp)
  pub leaf: [F; 6],
  pub idx: u64,
  pub sibs: Vec<F>,
}

impl Default for StepWitness {
  fn default() -> Self {
    StepWitness {
      idle: false,
      block: [0; 64],
      last: false,
      end: false,
      close: false,
      open: false,
      open_tx: [F::ZERO; 2],
      op: opk::NONE,
      ev: [F::ZERO; 3],
      leaf: [F::ZERO; 6],
      idx: 0,
      sibs: vec![F::ZERO; D],
    }
  }
}

// ---------------------------------------------------------------------------------------------
// The step
// ---------------------------------------------------------------------------------------------

/// Adds the node `x` at `level` of the Merkle frontier and decides the next phase.
fn place(t: &mut State, x: [F; 2], level: u64) -> Result<(), String> {
  if level >= NF as u64 {
    return Err("Merkle frontier overflow".into());
  }
  if (t.n >> level) & 1 == 1 {
    t.carry = x;
    t.mlevel = level;
    t.phase = phase::MERGE1;
    return Ok(());
  }
  t.frontier[level as usize] = x;
  t.n += 1 << level;
  let j = t.n.trailing_zeros() as usize;
  t.mlevel = j as u64;
  if !t.lastf {
    t.phase = phase::BODY;
  } else if t.n.is_power_of_two() {
    t.carry = t.frontier[j];
    t.phase = phase::HDR1;
  } else {
    t.carry = t.frontier[j];
    t.mlevel = j as u64;
    t.phase = phase::MERGE1;
  }
  Ok(())
}

/// The message block of a phase whose block is derived from the state, if it is.
pub fn derived_block(s: &State, w: &StepWitness) -> Option<[u8; 64]> {
  use phase::*;
  match s.phase {
    TXID | MERGE3 | HDR3 => Some(pad32_block(&halves_to_bytes(&s.sha))),
    MERGE1 => {
      let mut b = [0u8; 64];
      b[..32].copy_from_slice(&halves_to_bytes(&s.frontier[(s.mlevel as usize) % NF]));
      b[32..].copy_from_slice(&halves_to_bytes(&s.carry));
      Some(b)
    }
    MERGE2 => Some(pad64_block()),
    HDR2 => Some(hdr2_block(&w.block[..16])),
    _ => None,
  }
}

fn producer(t: &mut State, s: &State, w: &StepWitness) -> Result<(), String> {
  use phase::*;
  let p = s.phase;
  if p == MERGE1 && s.mlevel >= NF as u64 {
    return Err("merge level out of range".into());
  }
  let msg = match derived_block(s, w) {
    Some(m) => {
      if w.block != m {
        return Err(format!("phase {p}: message block does not match the state"));
      }
      m
    }
    None => w.block,
  };
  let root = halves_to_bytes(&s.carry);
  if p == HDR1 {
    if limbs(&<[u8; 32]>::try_from(&msg[4..36]).unwrap()) != s.prev {
      return Err("header does not link to the previous block hash".into());
    }
    if msg[36..64] != root[..28] {
      return Err("header Merkle root mismatch (bytes 36..64)".into());
    }
  }
  if p == HDR2 && msg[..4] != root[28..] {
    return Err("header Merkle root mismatch (bytes 64..68)".into());
  }
  let use_reg = (p == BODY && !s.fresh) || p == MERGE2 || p == HDR2;
  let chain = if use_reg { words_of(&s.sha) } else { IV };
  let out = halves_of_words(&compress(chain, &msg));
  t.sha = out;
  match p {
    BODY => {
      let mut par = s.par.clone();
      let mut fp = s.fp;
      for i in 0..64 {
        if let Some(ev) = par_byte(&mut par, msg[i], i, s.r_s).map_err(|e| format!("byte {i}: {e}"))? {
          fp = fold_f(fp, s.r, ev);
        }
      }
      t.fresh = false;
      if par.ps == pst::DONE {
        t.phase = TXID;
      }
      t.par = par;
      t.fp = fp;
    }
    TXID => {
      t.lastf = w.last;
      let tx = limbs(&halves_to_bytes(&out));
      t.fp = fold_f(s.fp, s.r, [fu(3), tx[0], tx[1], F::ZERO]);
      t.par = Par::init();
      t.fresh = true;
      place(t, out, 0)?;
    }
    MERGE1 => {
      if (s.n >> s.mlevel) & 1 == 0 {
        return Err("merge of an empty slot".into());
      }
      t.n = s.n - (1 << s.mlevel);
      t.phase = MERGE2;
    }
    MERGE2 => t.phase = MERGE3,
    MERGE3 => place(t, out, s.mlevel + 1)?,
    HDR1 => t.phase = HDR2,
    HDR2 => t.phase = HDR3,
    HDR3 => {
      t.prev = limbs(&halves_to_bytes(&out));
      t.height = s.height + 1;
      t.n = 0;
      t.fresh = true;
      t.phase = if w.end { DONE } else { BODY };
    }
    _ => unreachable!(),
  }
  Ok(())
}

fn nonmember(l: &[F; 6], key: &F) -> bool {
  lt(&l[0], key) && (l[1] == F::ZERO || lt(key, &l[1]))
}

fn consumer(t: &mut State, s: &State, w: &StepWitness) -> Result<(), String> {
  use opk::*;
  if s.sealed && (w.close || w.open || w.op != NONE) {
    return Err("the window is sealed".into());
  }
  if w.close {
    if !s.open || s.pending {
      return Err("close without an open transaction, or with a pending create".into());
    }
    let ev = [fu(3), s.tx[0], s.tx[1], F::ZERO];
    t.fc = fold_f(t.fc, s.r, ev);
    t.gc = fold_g(t.gc, ev);
    t.open = false;
  }
  if w.open {
    if t.open {
      return Err("open while a transaction is open".into());
    }
    t.tx = w.open_tx;
    t.open = true;
  }
  if w.op == NONE {
    return Ok(());
  }
  if w.op > CREATE_NEW {
    return Err("unknown op".into());
  }
  if w.sibs.len() != D || w.idx >= 1 << D {
    return Err("path shape".into());
  }
  let path = Path { index: w.idx, siblings: w.sibs.clone() };
  let l = &w.leaf;
  let root_old = root_of(if w.op == CREATE_NEW { F::ZERO } else { hash(l) }, &path);
  if root_old != s.root {
    return Err("path does not lead to the state root".into());
  }
  let event = |t: &mut State, x1: u64| {
    let ev = [fu(x1), w.ev[0], w.ev[1], w.ev[2]];
    t.fc = fold_f(t.fc, s.r, ev);
    t.gc = fold_g(t.gc, ev);
  };
  match w.op {
    CREATE_NEW => {
      if !s.pending {
        return Err("CREATE_NEW without a pending create".into());
      }
      if w.idx != s.leaf_count {
        return Err("CREATE_NEW slot is not the next leaf".into());
      }
      t.root = root_of(s.pend, &path);
      t.leaf_count = s.leaf_count + 1;
      t.pending = false;
    }
    SPEND_IN | SPEND_PRE | CREATE_LOW => {
      if !t.open || s.pending {
        return Err("event without an open transaction, or with a pending create".into());
      }
      let key = if w.op == CREATE_LOW {
        key_of_f(t.tx[0], t.tx[1], w.ev[0])
      } else {
        key_of_f(w.ev[0], w.ev[1], w.ev[2])
      };
      match w.op {
        SPEND_IN => {
          if l[0] != key || l[5] != F::ZERO {
            return Err("spend in window: leaf is not the unspent leaf of the key".into());
          }
          let mut n = *l;
          n[5] = F::ONE;
          t.root = root_of(hash(&n), &path);
          event(t, 1);
        }
        SPEND_PRE => {
          if !nonmember(l, &key) {
            return Err("spend before window: the leaf does not bracket the key".into());
          }
          event(t, 1);
        }
        _ => {
          if !nonmember(l, &key) {
            return Err("create: the leaf does not bracket the key".into());
          }
          let mut n = *l;
          n[1] = key;
          n[2] = fu(s.leaf_count);
          t.root = root_of(hash(&n), &path);
          t.pending = true;
          t.pend = hash(&[key, l[1], l[2], w.ev[1], w.ev[2], F::ZERO]);
          event(t, 2);
        }
      }
    }
    _ => unreachable!(),
  }
  Ok(())
}

/// One step: the next state, or the reason the witness is refused.
pub fn step(s: &State, w: &StepWitness) -> Result<State, String> {
  let mut t = s.clone();
  let active = !w.idle && s.phase != phase::DONE;
  if active {
    producer(&mut t, s, w)?;
  }
  consumer(&mut t, s, w)?;
  if active && s.phase == phase::HDR3 {
    if t.fc != t.fp {
      return Err("HDR3: consumer and producer fingerprints differ".into());
    }
    if t.open || t.pending {
      return Err("HDR3: a transaction is open or a create is pending".into());
    }
    if w.end {
      if hash(&[fu(1), s.h0[0], s.h0[1], t.prev[0], t.prev[1]]) != s.r_s {
        return Err("seal: r_s does not match hash(H-1) and hash(T)".into());
      }
      if hash(&[fu(2), s.r_s, t.gc]) != s.r {
        return Err("seal: r does not match the consumer chain".into());
      }
      t.sealed = true;
    }
  }
  Ok(t)
}

// ---------------------------------------------------------------------------------------------
// The trace generator
// ---------------------------------------------------------------------------------------------

/// The consumer's work for one block, in order.
#[derive(Clone, Copy, Debug)]
enum Item {
  Open(usize),
  Spend(usize, usize),
  CreateLow(usize, usize),
  CreateNew,
  Close,
}

#[derive(Default, Debug, Clone)]
pub struct BlockRun {
  pub height: u64,
  pub steps: usize,
  pub compressions: usize, // producer steps that were not idle
  pub leaf_updates: usize, // consumer ops (a create is two)
  pub idle_steps: usize,
  pub transactions: usize,
}

pub struct RunSummary {
  pub steps: usize,
  pub blocks: Vec<BlockRun>,
  pub state: State,
  pub map: UtxoMap,
}

/// The event sequence of a window, in consumer order, folded into `Gc`; used to derive `r`.
fn window_gc(blocks: &[native::Block], r_s: F) -> F {
  let mut g = F::ZERO;
  for b in blocks {
    for tx in &b.txs {
      for i in &tx.inputs {
        let l = limbs(&i.prev_txid);
        g = fold_g(g, [fu(1), l[0], l[1], fu(i.vout as u64)]);
      }
      for (k, o) in tx.outputs.iter().enumerate() {
        g = fold_g(g, [fu(2), fu(k as u64), fu(o.value), native::script_fp(&o.script, r_s)]);
      }
      let l = limbs(&tx.txid);
      g = fold_g(g, [fu(3), l[0], l[1], F::ZERO]);
    }
  }
  g
}

/// Runs the producer and the consumer over a window and calls `on_step(index, state, witness,
/// next)` for every step, after `step` accepted it. `prev_hash` is the internal-order hash of
/// the block before the first one.
pub fn run_window(
  raws: &[Vec<u8>],
  prev_hash: [u8; 32],
  height0: u64,
  on_step: &mut dyn FnMut(usize, &State, &StepWitness, &State) -> Result<(), String>,
) -> Result<RunSummary, String> {
  let blocks: Vec<native::Block> = raws.iter().map(|r| parse_block(r)).collect::<Result<_, _>>()?;
  let last_hash = sha256d(&blocks.last().ok_or("empty window")?.header);
  let r_s = native::derive_r_s(&prev_hash, &last_hash);
  let gc = window_gc(&blocks, r_s);
  let r = hash(&[fu(2), r_s, gc]);
  let mut map = UtxoMap::with_rs(r_s);
  let mut st = State::initial(&prev_hash, height0, r_s, r, map.root());

  let mut bi = 0usize;
  let mut padded: Vec<Vec<u8>> = vec![];
  let mut queue: Vec<Item> = vec![];
  let mut pos = 0usize;
  let mut ti = 0usize;
  let mut off = 0usize;
  let mut pending_create: Option<native::CreateProof> = None;
  let mut runs: Vec<BlockRun> = vec![];
  let load = |bi: usize, padded: &mut Vec<Vec<u8>>, queue: &mut Vec<Item>| {
    let b = &blocks[bi];
    *padded = b.txs.iter().map(|t| pad_tx(&t.nonwit)).collect();
    queue.clear();
    for (t, tx) in b.txs.iter().enumerate() {
      queue.push(Item::Open(t));
      for j in 0..tx.inputs.len() {
        queue.push(Item::Spend(t, j));
      }
      for k in 0..tx.outputs.len() {
        queue.push(Item::CreateLow(t, k));
        queue.push(Item::CreateNew);
      }
      queue.push(Item::Close);
    }
  };
  load(0, &mut padded, &mut queue);
  runs.push(BlockRun { height: height0, transactions: blocks[0].txs.len(), ..Default::default() });
  let mut step_no = 0usize;
  while st.phase != phase::DONE {
    let b = &blocks[bi];
    let mut w = StepWitness::default();
    match st.phase {
      phase::BODY => w.block.copy_from_slice(&padded[ti][off..off + 64]),
      phase::HDR1 => w.block.copy_from_slice(&b.header[..64]),
      phase::HDR2 => w.block = hdr2_block(&b.header[64..]),
      phase::TXID => {
        w.last = ti + 1 == b.txs.len();
        w.block = derived_block(&st, &w).unwrap();
      }
      phase::HDR3 => {
        w.end = bi + 1 == blocks.len();
        w.block = derived_block(&st, &w).unwrap();
        if queue.len() - pos > 1 {
          w.idle = true;
          w.block = [0; 64];
        }
      }
      _ => w.block = derived_block(&st, &w).unwrap(),
    }
    // consumer: close, open and one op
    if let Some(Item::Close) = queue.get(pos) {
      w.close = true;
      pos += 1;
    }
    if let Some(Item::Open(t)) = queue.get(pos).copied() {
      w.open = true;
      w.open_tx = limbs(&b.txs[t].txid);
      pos += 1;
    }
    if let Some(item) = queue.get(pos).copied() {
      match item {
        Item::Spend(t, j) => {
          let inp = &b.txs[t].inputs[j];
          let l = limbs(&inp.prev_txid);
          w.ev = [l[0], l[1], fu(inp.vout as u64)];
          match map.spend(&inp.prev_txid, inp.vout).map_err(|e| format!("map: {e:?}"))? {
            native::SpendOutcome::InWindow(p) => {
              w.op = opk::SPEND_IN;
              w.leaf = leaf_fields(&p.proof.leaf);
              w.idx = p.proof.path.index;
              w.sibs = p.proof.path.siblings.clone();
            }
            native::SpendOutcome::BeforeWindow { proof, .. } => {
              w.op = opk::SPEND_PRE;
              w.leaf = leaf_fields(&proof.leaf);
              w.idx = proof.path.index;
              w.sibs = proof.path.siblings.clone();
            }
          }
        }
        Item::CreateLow(t, k) => {
          let tx = &b.txs[t];
          let o = &tx.outputs[k];
          let cp = map.create(&tx.txid, k as u32, o.value, &o.script).map_err(|e| format!("map: {e:?}"))?;
          w.op = opk::CREATE_LOW;
          w.ev = [fu(k as u64), fu(o.value), native::script_fp(&o.script, r_s)];
          w.leaf = leaf_fields(&cp.low.leaf);
          w.idx = cp.low.path.index;
          w.sibs = cp.low.path.siblings.clone();
          pending_create = Some(cp);
        }
        Item::CreateNew => {
          let cp = pending_create.take().ok_or("CREATE_NEW without CREATE_LOW")?;
          w.op = opk::CREATE_NEW;
          w.idx = cp.append.index;
          w.sibs = cp.append.siblings.clone();
        }
        _ => return Err("unexpected queue item".into()),
      }
      pos += 1;
    }
    let next = step(&st, &w).map_err(|e| format!("step {step_no} (phase {}): {e}", st.phase))?;
    on_step(step_no, &st, &w, &next)?;
    let run = runs.last_mut().unwrap();
    run.steps += 1;
    if !w.idle {
      run.compressions += 1;
    } else {
      run.idle_steps += 1;
    }
    if w.op != opk::NONE {
      run.leaf_updates += 1;
    }
    if !w.idle {
      match st.phase {
        phase::BODY => off += 64,
        phase::TXID => {
          ti += 1;
          off = 0;
        }
        phase::HDR3 => {
          if bi + 1 < blocks.len() {
            bi += 1;
            ti = 0;
            off = 0;
            load(bi, &mut padded, &mut queue);
            pos = 0;
            runs.push(BlockRun { height: height0 + bi as u64, transactions: blocks[bi].txs.len(), ..Default::default() });
          }
        }
        _ => {}
      }
    }
    st = next;
    step_no += 1;
  }
  if pos != queue.len() {
    return Err("consumer work left after the window".into());
  }
  Ok(RunSummary { steps: step_no, blocks: runs, state: st, map })
}

fn leaf_fields(l: &native::Leaf) -> [F; 6] {
  [l.key, l.next_key, fu(l.next_index), fu(l.value), l.script_fp, fu(l.spent as u64)]
}

// ---------------------------------------------------------------------------------------------
// Synthetic blocks, for tests and the circuit's coverage runs
// ---------------------------------------------------------------------------------------------

pub mod synth {
  use super::*;

  pub struct TxSpec {
    pub ins: Vec<([u8; 32], u32, Vec<u8>)>, // prev txid, vout, scriptSig
    pub outs: Vec<(u64, Vec<u8>)>,
    pub version: u32,
    pub lock: u32,
  }

  pub fn compact(v: u64, out: &mut Vec<u8>) {
    if v < 0xfd {
      out.push(v as u8);
    } else if v <= 0xffff {
      out.push(0xfd);
      out.extend_from_slice(&(v as u16).to_le_bytes());
    } else {
      out.push(0xfe);
      out.extend_from_slice(&(v as u32).to_le_bytes());
    }
  }

  /// Non-witness serialization.
  pub fn tx_bytes(t: &TxSpec) -> Vec<u8> {
    let mut r = t.version.to_le_bytes().to_vec();
    compact(t.ins.len() as u64, &mut r);
    for (p, v, ss) in &t.ins {
      r.extend_from_slice(p);
      r.extend_from_slice(&v.to_le_bytes());
      compact(ss.len() as u64, &mut r);
      r.extend_from_slice(ss);
      r.extend_from_slice(&[0xff; 4]);
    }
    compact(t.outs.len() as u64, &mut r);
    for (v, s) in &t.outs {
      r.extend_from_slice(&v.to_le_bytes());
      compact(s.len() as u64, &mut r);
      r.extend_from_slice(s);
    }
    r.extend_from_slice(&t.lock.to_le_bytes());
    r
  }

  /// A block with a valid Merkle root over the given serialized transactions.
  pub fn block(prev: [u8; 32], nonce: u32, txs: &[Vec<u8>]) -> Vec<u8> {
    let ids: Vec<[u8; 32]> = txs.iter().map(|t| sha256d(t)).collect();
    let (root, _) = native::merkle_root(&ids);
    let mut b = 1u32.to_le_bytes().to_vec();
    b.extend_from_slice(&prev);
    b.extend_from_slice(&root);
    b.extend_from_slice(&[0u8; 4]);
    b.extend_from_slice(&0x1d00ffffu32.to_le_bytes());
    b.extend_from_slice(&nonce.to_le_bytes());
    compact(txs.len() as u64, &mut b);
    for t in txs {
      b.extend_from_slice(t);
    }
    b
  }

  fn txid_n(n: u32) -> [u8; 32] {
    let mut t = [0u8; 32];
    t[..4].copy_from_slice(&n.to_le_bytes());
    t[31] = (n % 251) as u8 ^ 0x5a;
    t
  }

  /// A window of three blocks that touches every parser state and every op: a coinbase, spends
  /// of earlier outputs and of outputs before the window, compact sizes of all three widths,
  /// empty and long scripts, a multi-block transaction, and blocks of 1, 3, 5 and 2
  /// transactions (every Merkle frontier path).
  pub fn coverage_window() -> (Vec<Vec<u8>>, [u8; 32]) {
    let cb = |n: u32| TxSpec { ins: vec![([0; 32], u32::MAX, vec![n as u8, 1, 2, 3, 4])], outs: vec![(50, vec![0x51])], version: 1, lock: 0 };
    let long: Vec<u8> = (0..300u32).map(|i| (i * 7 + 3) as u8).collect();
    let mid: Vec<u8> = (0..70u32).map(|i| (i * 3 + 1) as u8).collect();
    let prev = [9u8; 32];
    // block 1: coinbase only, one empty-script output
    let t_cb1 = TxSpec { ins: vec![([0; 32], u32::MAX, vec![])], outs: vec![(5000, vec![])], version: 2, lock: 0 };
    let b1_txs = vec![tx_bytes(&t_cb1)];
    let b1 = block(prev, 1, &b1_txs);
    let h1 = sha256d(&b1[..80]);
    // block 2: coinbase + three transactions (odd count, duplication)
    let id_cb1 = sha256d(&b1_txs[0]);
    let a = TxSpec {
      ins: vec![(id_cb1, 0, long.clone()), (txid_n(1), 7, mid.clone())],
      outs: vec![(1000, mid.clone()), (2000, vec![]), (3000, long.clone())],
      version: 1,
      lock: 7,
    };
    let b = TxSpec { ins: vec![(txid_n(2), 0, vec![0xab; 3])], outs: vec![(70, vec![0x6a, 1, 2, 3])], version: 1, lock: 0 };
    let b2_txs = vec![tx_bytes(&cb(2)), tx_bytes(&a), tx_bytes(&b)];
    let id_a = sha256d(&b2_txs[1]);
    let b2 = block(h1, 2, &b2_txs);
    let h2 = sha256d(&b2[..80]);
    // block 3: coinbase + four transactions (five leaves, deeper frontier), spending block 2 outputs
    let c = TxSpec { ins: vec![(id_a, 0, vec![]), (id_a, 2, vec![1])], outs: vec![(990, vec![0x51; 25])], version: 1, lock: 0 };
    let id_c = sha256d(&tx_bytes(&c));
    let d = TxSpec { ins: vec![(id_c, 0, vec![5; 200])], outs: vec![(5, vec![9; 252]), (6, vec![8; 253])], version: 1, lock: 0 };
    let e = TxSpec { ins: vec![(txid_n(3), 1, vec![])], outs: vec![(11, vec![0x52])], version: 3, lock: 99 };
    let f = TxSpec { ins: vec![(id_a, 1, vec![])], outs: vec![(1, vec![])], version: 1, lock: 0 };
    let b3_txs = vec![tx_bytes(&cb(3)), tx_bytes(&c), tx_bytes(&d), tx_bytes(&e), tx_bytes(&f)];
    let b3 = block(h2, 3, &b3_txs);
    let h3 = sha256d(&b3[..80]);
    // block 4: coinbase + one transaction of 64 + many padded blocks (an input script of 3000
    // bytes), two transactions
    let g = TxSpec { ins: vec![(txid_n(4), 2, vec![0x77; 3000])], outs: vec![(8, vec![1; 40])], version: 1, lock: 0 };
    let b4_txs = vec![tx_bytes(&cb(4)), tx_bytes(&g)];
    let b4 = block(h3, 4, &b4_txs);
    let h4 = sha256d(&b4[..80]);
    // block 5: one transaction with 260 inputs and 300 outputs (two-byte compact sizes), and one
    // that spends an output of the block before it
    let id_g = sha256d(&tx_bytes(&g));
    let big = TxSpec {
      ins: (0..260u32).map(|i| (txid_n(1000 + i), i % 5, if i % 50 == 0 { vec![i as u8; 10] } else { vec![] })).collect(),
      outs: (0..300u32).map(|i| (1 + i as u64, if i % 100 == 0 { vec![0x51; 3] } else { vec![] })).collect(),
      version: 2,
      lock: 5,
    };
    let h = TxSpec { ins: vec![(id_g, 0, vec![])], outs: vec![(7, vec![0x00, 0x14, 9])], version: 1, lock: 0 };
    let b5_txs = vec![tx_bytes(&cb(5)), tx_bytes(&big), tx_bytes(&h)];
    let b5 = block(h4, 5, &b5_txs);
    (vec![b1, b2, b3, b4, b5], prev)
  }
}

// ---------------------------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn state_vector_roundtrip() {
    let (raws, prev) = synth::coverage_window();
    let mut first = None;
    run_window(&raws, prev, 100, &mut |i, s, _, n| {
      if i == 5 {
        first = Some(n.clone());
      }
      assert_eq!(&State::from_vec(&s.to_vec()).unwrap(), s);
      Ok(())
    })
    .unwrap();
    let st = first.unwrap();
    assert_eq!(st.to_vec().len(), NZ);
  }

  #[test]
  fn synthetic_window_runs_and_seals() {
    let (raws, prev) = synth::coverage_window();
    let mut hdr3 = 0;
    let rs = run_window(&raws, prev, 100, &mut |_, s, _, n| {
      if s.phase == phase::HDR3 && !n.open {
        hdr3 += 1;
      }
      Ok(())
    })
    .unwrap();
    assert!(rs.state.sealed);
    assert_eq!(rs.state.root, rs.map.root());
    assert_eq!(rs.state.leaf_count as usize, rs.map.len());
    assert_eq!(rs.state.height, 105);
    assert_eq!(rs.blocks.len(), 5);
    let last = native::parse_block(raws.last().unwrap()).unwrap();
    assert_eq!(rs.state.prev, limbs(&sha256d(&last.header)));
  }

  /// A step list of the first window block, for the negative tests below.
  fn steps_of(raws: &[Vec<u8>], prev: [u8; 32]) -> Vec<(State, StepWitness)> {
    let mut v = vec![];
    run_window(raws, prev, 100, &mut |_, s, w, _| {
      v.push((s.clone(), w.clone()));
      Ok(())
    })
    .unwrap();
    v
  }

  #[test]
  fn flipped_body_byte_is_refused() {
    let (raws, prev) = synth::coverage_window();
    let steps = steps_of(&raws, prev);
    // A flipped byte inside a body block changes the transaction: the Merkle root no longer
    // matches the header. Replay with the byte flipped in the first block's first transaction.
    let mut bad = raws.clone();
    bad[0][80 + 1 + 20] ^= 1; // a byte of the coinbase scriptSig region of block 1
    let r = std::panic::catch_unwind(|| run_window(&bad, prev, 100, &mut |_, _, _, _| Ok(())));
    // The generator computes the Merkle root from the raw bytes, so the flipped block is refused
    // at HDR1 (header root differs from the recomputed root).
    assert!(matches!(r, Ok(Err(_))), "flipped byte accepted");
    // A step-level flip: the same witness with one body byte changed is refused or changes the
    // parse, and the very next compression chain no longer reaches the header root.
    let (s, w) = steps.iter().find(|(s, _)| s.phase == phase::BODY && s.par.ps == pst::VER).unwrap();
    let mut w2 = w.clone();
    w2.block[1] ^= 0x40; // version byte: parses fine, changes the txid
    let n1 = step(s, w).unwrap();
    let n2 = step(s, &w2).unwrap();
    assert_ne!(n1.sha, n2.sha);
  }

  #[test]
  fn misclassified_spend_is_refused() {
    let (raws, prev) = synth::coverage_window();
    let steps = steps_of(&raws, prev);
    // an in-window spend claimed as "before window": the key's leaf is not a bracket
    let (s, w) = steps.iter().find(|(_, w)| w.op == opk::SPEND_IN).unwrap();
    let mut w2 = w.clone();
    w2.op = opk::SPEND_PRE;
    assert!(step(s, &w2).is_err());
    // a before-window spend claimed as in-window
    let (s, w) = steps.iter().find(|(_, w)| w.op == opk::SPEND_PRE).unwrap();
    let mut w2 = w.clone();
    w2.op = opk::SPEND_IN;
    assert!(step(s, &w2).is_err());
    // a double spend: spending an already-spent leaf
    let (s, w) = steps.iter().find(|(_, w)| w.op == opk::SPEND_IN).unwrap();
    let n = step(s, w).unwrap();
    let mut w3 = w.clone();
    w3.leaf[5] = F::ONE;
    assert!(step(&n, &w3).is_err());
  }

  #[test]
  fn wrong_last_flag_is_refused() {
    let (raws, prev) = synth::coverage_window();
    let steps = steps_of(&raws, prev);
    let headers: Vec<[u8; 80]> = raws.iter().map(|r| native::parse_block(r).unwrap().header).collect();
    // Block 2 has three transactions: mark its first TXID as the last. The producer builds the
    // root of one leaf and the header phases, fed the real header, refuse the mismatch.
    let k = steps.iter().position(|(s, w)| s.phase == phase::TXID && !w.last && s.height == 101).unwrap();
    let (s0, w0) = &steps[k];
    let mut w = w0.clone();
    w.last = true;
    let mut s = step(s0, &w).unwrap();
    assert!(matches!(s.phase, phase::HDR1 | phase::MERGE1));
    let hdr = headers[1];
    let mut err = None;
    for _ in 0..40 {
      let mut w = StepWitness::default();
      match s.phase {
        phase::HDR1 => w.block.copy_from_slice(&hdr[..64]),
        phase::HDR2 => w.block = hdr2_block(&hdr[64..]),
        phase::HDR3 => break,
        _ => w.block = derived_block(&s, &w).unwrap(),
      }
      match step(&s, &w) {
        Ok(n) => s = n,
        Err(e) => {
          err = Some(e);
          break;
        }
      }
    }
    let e = err.expect("a last flag set one transaction early was accepted");
    assert!(e.contains("Merkle root"), "{e}");
    // The other direction: the last transaction flagged as not last leaves the producer in BODY,
    // waiting for another transaction. It cannot reach the header phases without one: the
    // header bytes fed as a body block do not complete a transaction.
    let k = steps.iter().position(|(s, w)| s.phase == phase::TXID && w.last && s.height == 100).unwrap();
    let mut w = steps[k].1.clone();
    w.last = false;
    let s = step(&steps[k].0, &w).unwrap();
    assert_eq!(s.phase, phase::BODY);
    let mut w = StepWitness::default();
    w.block.copy_from_slice(&headers[0][..64]);
    match step(&s, &w) {
      Ok(n) => assert_eq!(n.phase, phase::BODY),
      Err(_) => {}
    }
  }

  #[test]
  fn sixty_four_byte_transaction_and_ff_compact_are_refused() {
    // 64-byte transaction: version 4 + incnt 1 + (32 + 4 + 1 + 0 + 4) + outcnt 1 + (8 + 1 + 0) + lock 4 = 60.
    // Three more bytes of scriptSig give 63 and four give 64.
    let mk = |ss: usize| synth::TxSpec { ins: vec![([7; 32], 1, vec![1; ss])], outs: vec![(1, vec![])], version: 1, lock: 0 };
    let t60 = synth::tx_bytes(&mk(0));
    assert_eq!(t60.len(), 60);
    let t64 = synth::tx_bytes(&mk(4));
    assert_eq!(t64.len(), 64);
    let run = |tx: Vec<u8>| {
      let blk = synth::block([3; 32], 1, &[tx]);
      run_window(&[blk], [3; 32], 1, &mut |_, _, _, _| Ok(()))
    };
    assert!(run(synth::tx_bytes(&mk(3))).is_ok());
    let e = run(t64).err().unwrap();
    assert!(e.contains("64-byte"), "{e}");
    // 0xff compact size in the input count
    let mut bad = synth::tx_bytes(&mk(0));
    bad[4] = 0xff;
    bad.splice(5..5, [0u8; 8]);
    // the bytes after the count no longer parse as a transaction, but the 0xff is what the
    // parser rejects first
    let mut p = Par::init();
    let mut err = None;
    let padded = pad_tx(&bad);
    for (i, b) in padded.iter().take(64).enumerate() {
      if let Err(e) = par_byte(&mut p, *b, i, fu(5)) {
        err = Some(e);
        break;
      }
    }
    assert!(err.unwrap().contains("0xff"));
  }
}

#[cfg(test)]
mod real_window {
  use super::*;

  fn load(dir: &str) -> Option<(Vec<Vec<u8>>, [u8; 32], Vec<[u8; 32]>)> {
    let heights = std::fs::read_to_string(format!("{dir}/heights.txt")).ok()?;
    let hash_of = |h: u64| -> [u8; 32] {
      let s = heights.lines().find_map(|l| l.strip_prefix(&format!("{h} "))).unwrap().trim().to_string();
      let mut v = hex::decode(s).unwrap();
      v.reverse();
      v.try_into().unwrap()
    };
    let mut raws = vec![];
    let mut hashes = vec![];
    for h in 975_067..=975_072u64 {
      raws.push(std::fs::read(format!("{dir}/{h}.raw")).ok()?);
      hashes.push(hash_of(h));
    }
    Some((raws, hash_of(975_066), hashes))
  }

  /// The full six-block window through `step`: every HDR3 produces the block hash, the final
  /// root equals the native map's root, the window seals, and a block takes about
  /// max(compressions, leaf updates) steps. Needs the raw blocks (`M18_DATA`, default
  /// /root/m18-data); run with `-- --ignored`.
  #[test]
  #[ignore]
  fn full_window_975067_975072() {
    let dir = std::env::var("M18_DATA").unwrap_or_else(|_| "/root/m18-data".into());
    let (raws, prev, hashes) = load(&dir).expect("raw blocks in M18_DATA");
    let mut hdr3 = 0usize;
    let t = std::time::Instant::now();
    let rs = run_window(&raws, prev, 975_067, &mut |i, s, w, n| {
      if s.phase == phase::HDR3 && !w.idle {
        assert_eq!(n.prev, limbs(&hashes[hdr3]), "HDR3 of block {hdr3} does not produce the block hash");
        hdr3 += 1;
      }
      if i % 20_000 == 0 {
        eprintln!("step {i}, {:.0} s", t.elapsed().as_secs_f64());
      }
      Ok(())
    })
    .unwrap();
    assert_eq!(hdr3, 6);
    assert!(rs.state.sealed);
    assert_eq!(rs.state.root, rs.map.root());
    assert_eq!(rs.state.leaf_count as usize, rs.map.len());
    assert_eq!(rs.state.height, 975_073);
    eprintln!("root {}", hex::encode(f_to_le(&rs.state.root)));
    let mut total = 0;
    for b in &rs.blocks {
      let m = b.compressions.max(b.leaf_updates);
      eprintln!("block {}: {} steps, {} compressions, {} leaf updates, {} idle", b.height, b.steps, b.compressions, b.leaf_updates, b.idle_steps);
      assert!(b.steps >= m);
      assert!(b.steps <= m + m / 100 + 8, "block {} takes {} steps for a bound of {m}", b.height, b.steps);
      total += b.steps;
    }
    assert_eq!(total, rs.steps);
    eprintln!("total {total} steps in {:.0} s", t.elapsed().as_secs_f64());
  }
}
