//! nova-script: Bitcoin Script on Nova.
//!
//!   nova-script vectors CASES.jsonl            native run of every case against Core's verdict
//!   nova-script circuit CASES.jsonl [N]        every step of the first N valid cases through the
//!                                              step circuit (satisfied, and the same next state)
//!   nova-script prove CASES.jsonl ID...        Nova proof of each named case, verified by the checker
//!   nova-script mutate CASES.jsonl ID...       tampered witnesses must leave the circuit unsatisfied
//!   nova-script compress CASES.jsonl ID        compressed (Spartan) proof of one case: size, times

use m17_nova_script::{circuit, run_case, Case, Verdict};
use std::collections::BTreeMap;
use std::io::BufRead;

fn load(path: &str) -> Vec<Case> {
  let f = std::fs::File::open(path).expect("cases file");
  std::io::BufReader::new(f).lines().map(|l| serde_json::from_str(&l.unwrap()).expect("case")).collect()
}

fn vectors(path: &str) {
  let cases = load(path);
  let (mut agree, mut unsupported) = (0, 0);
  let mut by_cat: BTreeMap<String, (u32, u32)> = BTreeMap::new();
  let mut bad = vec![];
  for c in &cases {
    let v = run_case(c, false);
    let got = match &v {
      Verdict::Valid(..) => Some(true),
      Verdict::Invalid(_) => Some(false),
      Verdict::Unsupported(_) => None,
    };
    let Some(got) = got else {
      unsupported += 1;
      continue;
    };
    let e = by_cat.entry(c.category.clone()).or_default();
    e.0 += 1;
    if got == c.expect_valid {
      agree += 1;
    } else {
      e.1 += 1;
      let why = if let Verdict::Invalid(e) = v { e } else { "accepted" };
      bad.push(format!("{} [{}] got {} ({}) | {}", c.id, c.category, got, why, c.description));
    }
  }
  for (k, (n, b)) in &by_cat {
    println!("{k:40} {n:5} disagree {b}");
  }
  for b in &bad {
    println!("DISAGREE {b}");
  }
  println!("cases {} checked {} agree {} disagree {} unsupported (taproot) {}", cases.len(), agree + bad.len(), agree, bad.len(), unsupported);
  if !bad.is_empty() {
    std::process::exit(1);
  }
}

fn main() {
  let args: Vec<String> = std::env::args().collect();
  match args.get(1).map(String::as_str) {
    Some("vectors") => vectors(&args[2]),
    Some("circuit") => circuit::check_cases(&load(&args[2]), args.get(3).map(|n| n.parse().unwrap()).unwrap_or(usize::MAX)),
    Some("prove") => circuit::prove_cases(&load(&args[2]), &args[3..]),
    Some("mutate") => circuit::mutate_cases(&load(&args[2]), &args[3..]),
    Some("compress") => circuit::compress_case(&load(&args[2]), &args[3]),
    _ => {
      eprintln!("usage: nova-script vectors|circuit|prove|mutate CASES.jsonl ...");
      std::process::exit(2);
    }
  }
}
