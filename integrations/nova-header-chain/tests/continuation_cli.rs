//! nova-chain end to end on committed testnet4 data (heights 0-4,100 from a
//! Bitcoin Core 31.1 node; see fixtures/testnet4/core_dump_158970.json):
//! the native rules from the consensus genesis agree with Core at every
//! height, and a genesis-anchored continuation interrupted and resumed
//! reaches the same verified state as an uninterrupted one.
//! Run with `cargo test --release`.
use serde_json::Value;
use std::path::PathBuf;
use std::process::Command;

fn fixture(name: &str) -> String {
  PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/testnet4").join(name).to_string_lossy().into_owned()
}

fn nova_chain(args: &[&str]) -> (bool, Value) {
  let out = Command::new(env!("CARGO_BIN_EXE_nova-chain")).args(args).output().unwrap();
  let line = String::from_utf8_lossy(&out.stdout).lines().last().unwrap_or("{}").to_owned();
  (out.status.success(), serde_json::from_str(&line).unwrap_or(Value::Null))
}

#[test]
fn native_rules_from_genesis_agree_with_bitcoin_core_through_two_retargets() {
  let (ok, v) = nova_chain(&[
    "native-check", "--network", "testnet4", "--headers", &fixture("headers_0_4100.bin"),
    "--core-ref", &fixture("core_ref_0_4100.tsv"),
  ]);
  assert!(ok, "{v}");
  assert_eq!(v["stats"]["retargets"], 2);
  assert_eq!(v["end"]["hash"], "0000000004425bfe196f40337e6cc198977b0825f8dff6a89bcedab3f5a1a620");
  assert_eq!(v["end"]["chainwork"], "0x2bb02bb02bb0");
}

#[test]
#[cfg_attr(debug_assertions, ignore = "release only: Nova folding is slow unoptimized")]
fn interrupted_continuation_resumes_to_the_uninterrupted_state() {
  let tmp = std::env::temp_dir().join(format!("nova-chain-test-{}", std::process::id()));
  let _ = std::fs::remove_dir_all(&tmp);
  let (a, b) = (tmp.join("a"), tmp.join("b"));
  let h = fixture("headers_0_4100.bin");
  let common = ["--network", "testnet4", "--k", "5", "--headers", h.as_str(), "--to", "40", "--every", "2"];

  let (ok, reference) = nova_chain(&[&["run", "--out", a.to_str().unwrap()], &common[..]].concat());
  assert!(ok, "{reference}");
  assert_eq!(reference["chain"]["anchor_policy"], "genesis/testnet4/00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043");

  // Stop after 3 steps (one generation at step 2 plus the final one at 3), then resume.
  let (ok, part) = nova_chain(&[&["run", "--out", b.to_str().unwrap(), "--max-steps", "3"], &common[..]].concat());
  assert!(ok, "{part}");
  assert_eq!(part["chain"]["end"]["height"], 15);
  let (ok, resumed) = nova_chain(&["resume", "--dir", b.to_str().unwrap(), "--headers", &h, "--to", "40", "--every", "2"]);
  assert!(ok, "{resumed}");
  assert_eq!(resumed["chain"]["end_state_sha256"], reference["chain"]["end_state_sha256"]);
  assert_eq!(resumed["chain"]["completed_steps"], 8);

  let (ok, cold) = nova_chain(&["verify-continuation", "--dir", b.to_str().unwrap()]);
  assert!(ok && cold["verified"] == true, "{cold}");

  // A resume asking for a different k or network is refused.
  let (ok, _) = nova_chain(&["resume", "--dir", b.to_str().unwrap(), "--headers", &h, "--to", "45", "--k", "1"]);
  assert!(!ok);
  let (ok, _) = nova_chain(&["resume", "--dir", b.to_str().unwrap(), "--headers", &h, "--to", "45", "--network", "mainnet"]);
  assert!(!ok);
  // A non-multiple of k is refused before folding.
  let (ok, _) = nova_chain(&["resume", "--dir", b.to_str().unwrap(), "--headers", &h, "--to", "43"]);
  assert!(!ok);
  let _ = std::fs::remove_dir_all(&tmp);
}
