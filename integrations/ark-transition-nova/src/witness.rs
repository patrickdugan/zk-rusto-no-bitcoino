//! The witness file written by the bitcoin-rs `ark-nm2` tool, its parsing, and the native semantic
//! checks the prover runs before it folds anything.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

pub const SCHEMA: &str = "ark-transition-nova-witness-v1";

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct Witness {
  pub schema: String,
  pub statement_digest: String,
  pub fee_bound_sat: u64,
  pub items: Vec<Item>,
  pub expect: Expect,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
pub enum Item {
  Input { spend_id: String, value_sat: u64 },
  Output { value_sat: u64, commit: String },
  Close { fee_sat: u64 },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Expect {
  pub tx_count: u64,
  pub input_count: u64,
  pub sum_in_sat: u64,
  pub sum_out_sat: u64,
  pub sum_fee_sat: u64,
}

#[derive(Clone, Debug)]
pub enum PItem {
  In { spend: [u8; 32], value: u64 },
  Out { value: u64, commit: [u8; 32] },
  Close { fee: u64 },
}

#[derive(Clone, Debug)]
pub struct Parsed {
  pub statement: [u8; 32],
  pub fee_bound: u64,
  pub items: Vec<PItem>,
  pub expect: Expect,
}

fn hex32(s: &str, what: &str) -> Result<[u8; 32], String> {
  let b = hex::decode(s).map_err(|e| format!("{what}: not hex ({e})"))?;
  b.try_into().map_err(|b: Vec<u8>| format!("{what}: {} bytes, need 32", b.len()))
}

pub fn parse_str(s: &str) -> Result<(Witness, Parsed), String> {
  let w: Witness = serde_json::from_str(s).map_err(|e| format!("witness json: {e}"))?;
  let p = parse(&w)?;
  Ok((w, p))
}

/// Syntax: schema, hex lengths. No semantic checks.
pub fn parse(w: &Witness) -> Result<Parsed, String> {
  if w.schema != SCHEMA {
    return Err(format!("unknown schema {:?}", w.schema));
  }
  let statement = hex32(&w.statement_digest, "statement_digest")?;
  let mut items = vec![];
  for (i, it) in w.items.iter().enumerate() {
    items.push(match it {
      Item::Input { spend_id, value_sat } => PItem::In { spend: hex32(spend_id, &format!("item {i} spend_id"))?, value: *value_sat },
      Item::Output { value_sat, commit } => PItem::Out { value: *value_sat, commit: hex32(commit, &format!("item {i} commit"))? },
      Item::Close { fee_sat } => PItem::Close { fee: *fee_sat },
    });
  }
  Ok(Parsed { statement, fee_bound: w.fee_bound_sat, items, expect: w.expect.clone() })
}

#[derive(Debug, PartialEq, Eq)]
pub struct Tallies {
  pub tx_count: u128,
  pub input_count: u128,
  pub sum_in: u128,
  pub sum_out: u128,
  pub sum_fee: u128,
}

impl Tallies {
  pub fn matches(&self, e: &Expect) -> bool {
    self.tx_count == e.tx_count as u128
      && self.input_count == e.input_count as u128
      && self.sum_in == e.sum_in_sat as u128
      && self.sum_out == e.sum_out_sat as u128
      && self.sum_fee == e.sum_fee_sat as u128
  }
}

/// Tallies over the item list (no validity checks).
pub fn tallies(items: &[PItem]) -> Tallies {
  let mut t = Tallies { tx_count: 0, input_count: 0, sum_in: 0, sum_out: 0, sum_fee: 0 };
  for it in items {
    match it {
      PItem::In { value, .. } => {
        t.input_count += 1;
        t.sum_in += *value as u128;
      }
      PItem::Out { value, .. } => t.sum_out += *value as u128,
      PItem::Close { fee } => {
        t.tx_count += 1;
        t.sum_fee += *fee as u128;
      }
    }
  }
  t
}

/// The native precheck: graph shape, per-transaction conservation, fee bound, single-use spend
/// identities (compared as the 31-byte prefixes the circuit sees), and the `expect` block.
pub fn check_semantics(p: &Parsed) -> Result<Tallies, String> {
  let (mut tx_in, mut tx_out, mut seen_out) = (0u128, 0u128, false);
  let (mut n_in, mut n_out) = (0usize, 0usize);
  let mut ids: HashSet<[u8; 31]> = HashSet::new();
  let mut tx = 0usize;
  for (i, it) in p.items.iter().enumerate() {
    match it {
      PItem::In { spend, value } => {
        if seen_out {
          return Err(format!("item {i}: input after an output within tx {tx}"));
        }
        let id: [u8; 31] = spend[..31].try_into().unwrap();
        if id == [0u8; 31] {
          return Err(format!("item {i}: spend_id with an all-zero 31-byte prefix"));
        }
        if !ids.insert(id) {
          return Err(format!("item {i}: duplicate spend_id {}", hex::encode(spend)));
        }
        tx_in += *value as u128;
        n_in += 1;
      }
      PItem::Out { value, .. } => {
        seen_out = true;
        tx_out += *value as u128;
        n_out += 1;
      }
      PItem::Close { fee } => {
        if n_in == 0 || n_out == 0 {
          return Err(format!("tx {tx}: needs at least one input and one output"));
        }
        if *fee > p.fee_bound {
          return Err(format!("tx {tx}: fee {fee} above fee_bound {}", p.fee_bound));
        }
        if tx_in != tx_out + *fee as u128 {
          return Err(format!("tx {tx}: inputs {tx_in} != outputs {tx_out} + fee {fee}"));
        }
        tx += 1;
        tx_in = 0;
        tx_out = 0;
        seen_out = false;
        n_in = 0;
        n_out = 0;
      }
    }
  }
  if n_in != 0 || n_out != 0 {
    return Err("items end without a close for the last transaction".into());
  }
  let t = tallies(&p.items);
  if !t.matches(&p.expect) {
    return Err(format!("expect block does not match the items (computed {t:?})"));
  }
  Ok(t)
}
