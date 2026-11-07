//! The k=1 testnet4 fixture (genesis to height 4) against its pinned key,
//! rebuilt here from the circuit shape, so CI performs real Nova verification
//! with no external key file. Every bound field of the statement is mutated.
use nova_bitvm3_m12::{
  bundle::{Bundle, PublicStatement, Statement, Z_BYTES},
  nova_io::{self, sha256_hex},
  pins,
};
use nova_header_chain::native::Network;
use std::sync::OnceLock;

const FIXTURE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../fixtures/testnet4-k1-0-4.nht4");
const EXPECTED: &str = include_str!("../../fixtures/testnet4-k1-0-4.statement.json");

fn vk() -> &'static Vec<u8> {
  static VK: OnceLock<Vec<u8>> = OnceLock::new();
  VK.get_or_init(|| nova_io::vk_export(Network::Testnet4, 1))
}

fn bundle() -> Vec<u8> {
  std::fs::read(FIXTURE).unwrap()
}

#[test]
fn k1_key_rebuilds_to_its_pin() {
  assert_eq!(sha256_hex(vk()), pins::pinned(Network::Testnet4, 1).unwrap());
  assert_eq!(vk().len(), 42_270_392);
}

#[test]
fn fixture_verifies_and_binds_the_whole_statement() {
  let b = bundle();
  assert_eq!(sha256_hex(&b), "ffa1fdbc8a7ef712941434db51c2c780232f5a2190f225bca640ab5a4d6c5f3c");
  let v = nova_io::verify_statement(&b, vk()).expect("real k=1 proof verifies");
  let expected: Statement = serde_json::from_str(EXPECTED).unwrap();
  assert_eq!(v.statement, expected);
  // Testnet4 height 4 per Bitcoin Core 31.1 (core_ref_0_4100.tsv upstream).
  assert_eq!(v.statement.end_tip_hash, "000000008f5794caa45c418a0184303e848e9d6756e4d77234c9aada983b4265");
  assert_eq!(v.statement.end_chainwork, "0x500050005");
  // Genesis anchor state.
  assert_eq!(v.statement.checkpoint_state_sha256, "9c82dffe8b6005378775c8f2028b7644039defadb0fcc1d77820b7aaced6de9c");
  let enc = v.public.encode();
  assert_eq!(PublicStatement::decode(&enc).unwrap(), v.public);
  assert_eq!(sha256_hex(&enc), expected.public_statement_sha256);
}

fn rejected(b: &[u8], vk: &[u8]) -> bool {
  nova_io::verify_statement(b, vk).is_err()
}

#[test]
fn altered_proofs_are_rejected() {
  let b = bundle();
  let proof_start = 12 + Z_BYTES;
  let n = b.len() - proof_start;
  for at in [8, n / 4, n / 2, n - 40] {
    let mut m = b.clone();
    m[proof_start + at] ^= 1;
    assert!(rejected(&m, vk()), "proof byte {at}");
  }
  assert!(rejected(&b[..b.len() - 1], vk()), "truncated proof");
  // The proof carries its own zn; altering it must fail (the final tip).
  let v = nova_io::verify_statement(&b, vk()).unwrap();
  let off = b[proof_start..].windows(32).position(|w| w == &v.public.zn[..32]).expect("zn inside proof") + proof_start;
  let mut m = b.clone();
  m[off] ^= 1;
  assert!(rejected(&m, vk()), "zn inside the proof");
}

#[test]
fn altered_checkpoint_steps_network_and_width_are_rejected() {
  let b = bundle();
  for (field, name) in [(0, "height"), (1, "hash lo"), (2, "hash hi"), (3, "chainwork"), (4, "epoch bits"), (16, "newest timestamp")] {
    let mut m = b.clone();
    m[12 + 32 * field] ^= 1;
    assert!(rejected(&m, vk()), "z0 {name}");
  }
  let mut p = Bundle::parse(&b).unwrap();
  p.steps += 1;
  assert!(rejected(&p.to_bytes(), vk()), "steps + 1");
  p.steps -= 2;
  assert!(rejected(&p.to_bytes(), vk()), "steps - 1");
  let mut p = Bundle::parse(&b).unwrap();
  p.net = Network::Mainnet;
  let e = nova_io::verify_statement(&p.to_bytes(), vk()).unwrap_err();
  assert!(e.contains("pinned to testnet4 k=1"), "{e}");
  let mut p = Bundle::parse(&b).unwrap();
  p.k = 10;
  let e = nova_io::verify_statement(&p.to_bytes(), vk()).unwrap_err();
  assert!(e.contains("pinned"), "{e}");
}

#[test]
fn altered_or_unpinned_keys_are_rejected() {
  let b = bundle();
  let mut k = vk().clone();
  let mid = k.len() / 2;
  k[mid] ^= 1;
  let e = nova_io::verify_statement(&b, &k).unwrap_err();
  assert!(e.contains("differs from the pinned"), "{e}");
  // Without the pin the altered key must still fail to decode or verify.
  assert!(nova_io::verify_unpinned(&b, &k).is_err());
  // A different valid key (k=2 shape) is not the pinned one and does not verify.
  let k2 = nova_io::vk_export(Network::Testnet4, 2);
  assert!(nova_io::verify_statement(&b, &k2).is_err());
  assert!(nova_io::verify_unpinned(&b, &k2).is_err());
}
