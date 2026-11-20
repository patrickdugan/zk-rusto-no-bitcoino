//! The native machine: state layout, one step, and the plan (step list, Fiat-Shamir challenge, z0).

use crate::elem::{domain, f_from_be, fu, hash, id31, limbs, F, TAG_DOMAIN, TAG_GAMMA};
use crate::witness::{PItem, Parsed};
use ff::Field;

pub const ARITY: usize = 17;
pub type State = [F; ARITY];

pub mod z {
  pub const DIG_HI: usize = 0;
  pub const DIG_LO: usize = 1;
  pub const FEE_BOUND: usize = 2;
  pub const GAMMA: usize = 3;
  pub const ACC: usize = 4;
  pub const SUM_IN: usize = 5;
  pub const SUM_OUT: usize = 6;
  pub const SUM_FEE: usize = 7;
  pub const R1: usize = 8;
  pub const P1: usize = 9;
  pub const R2: usize = 10;
  pub const P2: usize = 11;
  pub const LAST: usize = 12;
  pub const N_IN1: usize = 13;
  pub const N_IN2: usize = 14;
  pub const N_TX: usize = 15;
  pub const PHASE: usize = 16;
}

pub const K_IN: u8 = 0;
pub const K_OUT: u8 = 1;
pub const K_CLOSE: u8 = 2;
pub const K_SORTED: u8 = 3;

/// The witness of one step. `val` is the value (input, output) or the fee (close).
#[derive(Clone, Debug)]
pub struct Wit {
  pub kind: u8,
  pub spend: F,
  pub val: F,
  pub commit: F,
}

impl Default for Wit {
  fn default() -> Self {
    Wit { kind: K_IN, spend: F::ZERO, val: F::ZERO, commit: F::ZERO }
  }
}

/// R0 = Poseidon(DOMAIN, dig_hi, dig_lo, fee_bound).
pub fn r0(statement: &[u8; 32], fee_bound: u64) -> F {
  let (hi, lo) = limbs(statement);
  hash(&[domain(TAG_DOMAIN), hi, lo, fu(fee_bound)])
}

pub fn gamma_of(r1: F, r2: F) -> F {
  hash(&[domain(TAG_GAMMA), r1, r2])
}

pub fn z0(statement: &[u8; 32], fee_bound: u64, gamma: F) -> State {
  let (hi, lo) = limbs(statement);
  let r = r0(statement, fee_bound);
  let mut z = [F::ZERO; ARITY];
  z[z::DIG_HI] = hi;
  z[z::DIG_LO] = lo;
  z[z::FEE_BOUND] = fu(fee_bound);
  z[z::GAMMA] = gamma;
  z[z::R1] = r;
  z[z::P1] = F::ONE;
  z[z::R2] = r;
  z[z::P2] = F::ONE;
  z
}

/// The record-chain update for a record step (input, output or close).
pub fn record_hash(r1: F, w: &Wit) -> F {
  match w.kind {
    K_IN => hash(&[r1, fu(1), w.spend, w.val]),
    K_OUT => hash(&[r1, fu(2), w.val, w.commit]),
    K_CLOSE => hash(&[r1, fu(3), w.val, F::ZERO]),
    _ => r1,
  }
}

/// The next state. Pure arithmetic: it never refuses; the circuit does.
pub fn step(s: &State, w: &Wit) -> State {
  let mut n = *s;
  match w.kind {
    K_IN => {
      n[z::ACC] = s[z::ACC] + w.val;
      n[z::SUM_IN] = s[z::SUM_IN] + w.val;
      n[z::R1] = record_hash(s[z::R1], w);
      n[z::P1] = s[z::P1] * (s[z::GAMMA] - w.spend);
      n[z::N_IN1] = s[z::N_IN1] + F::ONE;
    }
    K_OUT => {
      n[z::ACC] = s[z::ACC] - w.val;
      n[z::SUM_OUT] = s[z::SUM_OUT] + w.val;
      n[z::R1] = record_hash(s[z::R1], w);
    }
    K_CLOSE => {
      n[z::ACC] = F::ZERO;
      n[z::SUM_FEE] = s[z::SUM_FEE] + w.val;
      n[z::N_TX] = s[z::N_TX] + F::ONE;
      n[z::R1] = record_hash(s[z::R1], w);
    }
    _ => {
      n[z::PHASE] = F::ONE;
      n[z::LAST] = w.spend;
      n[z::R2] = hash(&[s[z::R2], w.spend]);
      n[z::P2] = s[z::P2] * (s[z::GAMMA] - w.spend);
      n[z::N_IN2] = s[z::N_IN2] + F::ONE;
    }
  }
  n
}

pub struct Plan {
  pub steps: Vec<Wit>,
  pub z0: State,
  pub zn: State,
  pub gamma: F,
  pub r1: F,
}

/// The record steps of the item list.
pub fn record_steps(items: &[PItem]) -> Vec<Wit> {
  items
    .iter()
    .map(|it| match it {
      PItem::In { spend, value } => Wit { kind: K_IN, spend: id31(spend), val: fu(*value), commit: F::ZERO },
      PItem::Out { value, commit } => Wit { kind: K_OUT, spend: F::ZERO, val: fu(*value), commit: id31(commit) },
      PItem::Close { fee } => Wit { kind: K_CLOSE, spend: F::ZERO, val: fu(*fee), commit: F::ZERO },
    })
    .collect()
}

pub fn run(z: &State, steps: &[Wit]) -> State {
  steps.iter().fold(*z, |s, w| step(&s, w))
}

/// All steps in order (records, then the sorted spend list), the challenge, z0 and the final state.
/// No validity checks: a bad witness yields a plan the circuit refuses.
pub fn plan(p: &Parsed) -> Plan {
  let mut steps = record_steps(&p.items);
  let mut ids: Vec<[u8; 31]> = p
    .items
    .iter()
    .filter_map(|it| if let PItem::In { spend, .. } = it { Some(spend[..31].try_into().unwrap()) } else { None })
    .collect();
  ids.sort();
  for id in ids {
    steps.push(Wit { kind: K_SORTED, spend: f_from_be(&id).unwrap(), val: F::ZERO, commit: F::ZERO });
  }
  let probe = run(&z0(&p.statement, p.fee_bound, F::ZERO), &steps);
  let gamma = gamma_of(probe[z::R1], probe[z::R2]);
  let z0v = z0(&p.statement, p.fee_bound, gamma);
  let zn = run(&z0v, &steps);
  Plan { steps, z0: z0v, zn, gamma, r1: probe[z::R1] }
}

/// The record chain over the item list, from R0 (full-data verification).
pub fn chain_r1(p: &Parsed) -> F {
  record_steps(&p.items).iter().fold(r0(&p.statement, p.fee_bound), |r, w| record_hash(r, w))
}
