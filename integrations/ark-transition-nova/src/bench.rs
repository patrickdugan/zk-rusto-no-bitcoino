//! Ark-shaped witnesses for the benchmark: a commitment transaction with N boarding inputs and one
//! liquidity input, spending into a batch output and change, and a binary tree of N-1 transactions
//! (each one input, two outputs) that splits the batch output into N leaf outputs.

use crate::elem::sha256_hex;
use crate::witness::{parse, tallies, Expect, Item, Witness, SCHEMA};

const LEAF: u64 = 1000;
const TREE_FEE: u64 = 100;
const COMMIT_FEE: u64 = 500;
const BOARDING: u64 = 2000;
const LIQUIDITY: u64 = 50_000;

fn id(tag: &str, i: u64) -> String {
  sha256_hex(format!("ark-bench-{tag}-{i}").as_bytes())
}

/// Input amount of the tree transaction over n leaves.
fn amount(n: u64) -> u64 {
  if n <= 1 {
    LEAF
  } else {
    let l = n / 2;
    amount(l) + amount(n - l) + TREE_FEE
  }
}

fn emit(n: u64, items: &mut Vec<Item>, ctr: &mut u64) {
  let (l, r) = (n / 2, n - n / 2);
  *ctr += 1;
  items.push(Item::Input { spend_id: id("tree-spend", *ctr), value_sat: amount(n) });
  for c in [l, r] {
    *ctr += 1;
    items.push(Item::Output { value_sat: amount(c), commit: id("tree-commit", *ctr) });
  }
  items.push(Item::Close { fee_sat: TREE_FEE });
  for c in [l, r] {
    if c >= 2 {
      emit(c, items, ctr);
    }
  }
}

pub fn synth(n: u64) -> Witness {
  let mut items = vec![];
  for i in 0..n {
    items.push(Item::Input { spend_id: id("boarding", i), value_sat: BOARDING });
  }
  items.push(Item::Input { spend_id: id("liquidity", 0), value_sat: LIQUIDITY });
  let batch = amount(n);
  items.push(Item::Output { value_sat: batch, commit: id("batch", 0) });
  items.push(Item::Output { value_sat: n * BOARDING + LIQUIDITY - batch - COMMIT_FEE, commit: id("change", 0) });
  items.push(Item::Close { fee_sat: COMMIT_FEE });
  let mut ctr = 0;
  if n >= 2 {
    emit(n, &mut items, &mut ctr);
  }
  let mut w = Witness {
    schema: SCHEMA.into(),
    statement_digest: id("statement", n),
    fee_bound_sat: 5000,
    items,
    expect: Expect { tx_count: 0, input_count: 0, sum_in_sat: 0, sum_out_sat: 0, sum_fee_sat: 0 },
  };
  let t = tallies(&parse(&w).unwrap().items);
  w.expect = Expect {
    tx_count: t.tx_count as u64,
    input_count: t.input_count as u64,
    sum_in_sat: t.sum_in as u64,
    sum_out_sat: t.sum_out as u64,
    sum_fee_sat: t.sum_fee as u64,
  };
  w
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::witness::check_semantics;

  #[test]
  fn synthesized_graphs_are_valid() {
    for n in [1u64, 2, 4, 5, 16, 64] {
      let p = parse(&synth(n)).unwrap();
      let t = check_semantics(&p).unwrap();
      assert_eq!(t.tx_count as u64, n); // 1 commitment tx + (n-1) tree txs
      assert_eq!(t.input_count as u64, n + 1 + (n - 1));
    }
  }
}
