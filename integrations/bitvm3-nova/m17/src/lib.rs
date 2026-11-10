//! M17: Bitcoin Script on Nova. See README.md.

pub mod circuit;
pub mod compile;
pub mod elem;
pub mod engine;
pub mod isa;
pub mod sigcheck;

use serde::Deserialize;

/// One verification from Core's vectors (scripts/export_vectors.py).
#[derive(Deserialize, Clone)]
pub struct Case {
  pub id: String,
  pub category: String,
  pub flags: String,
  pub flag_bits: u32,
  pub expect_valid: bool,
  pub description: String,
  pub tx: String,
  pub prevouts: Vec<(i64, String)>,
  pub index: usize,
}

pub enum Verdict {
  Valid(engine::Trace, compile::Program, sigcheck::Tx),
  Invalid(&'static str),
  Unsupported(&'static str),
}

/// Compiles and runs one case natively.
pub fn run_case(c: &Case, record: bool) -> Verdict {
  let tx = match sigcheck::parse_tx(&hex::decode(&c.tx).unwrap()) {
    Ok(t) => t,
    Err(_) => return Verdict::Unsupported("TX_PARSE"),
  };
  let (amount, spk_hex) = &c.prevouts[c.index];
  let spk = hex::decode(spk_hex).unwrap();
  let prog = match compile::compile(&tx, c.index, &spk, c.flag_bits) {
    Ok(p) => p,
    Err("UNSUPPORTED_TAPROOT") => return Verdict::Unsupported("TAPROOT"),
    Err(e) => return Verdict::Invalid(e),
  };
  let ctx = engine::Ctx { tx: &tx, n_in: c.index, amount: *amount, flags: c.flag_bits };
  let mut m = engine::Machine::new(&prog, ctx);
  match m.run(record) {
    Ok(t) => {
      drop(m);
      Verdict::Valid(t, prog, tx)
    }
    Err(e) => Verdict::Invalid(e),
  }
}
