//! Real testnet4 bundles (k=5) from capped VPS runs, checked with the
//! verifier binary:
//! - genesis_0_2020_k5: genesis-anchored, through the first retarget;
//! - auth_100700_100900_k5: PR #14's 200 headers, from the state the native
//!   rules derive from genesis (Core-matched chainwork, unproven start).
//! Also the network binding of a supplied key: a testnet4 bundle relabelled
//! NHC1 must not yield a mainnet receipt, even with the testnet4 key.
//! Run with `cargo test --release` (rebuilds the testnet4 k=5 key).
use std::path::PathBuf;
use std::process::Command;

const TN4_K5: &str = "1ae88a7bcfdc5f14d030d0baafa06ec17fe904a5ebed42f9bd6fa6105fdc8c24";
const GENESIS_ANCHOR: &str = "9c82dffe8b6005378775c8f2028b7644039defadb0fcc1d77820b7aaced6de9c";

fn fixture(name: &str) -> PathBuf {
  PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/testnet4").join(name)
}

fn verify(bundle: &[u8], vk: &std::path::Path, tag: &str) -> (bool, String) {
  let p = std::env::temp_dir().join(format!("tn4-{}-{tag}", std::process::id()));
  std::fs::write(&p, bundle).unwrap();
  let out = Command::new(env!("CARGO_BIN_EXE_btc-header-fold"))
    .args(["verify-bundle", p.to_str().unwrap(), "--vk", vk.to_str().unwrap()])
    .output()
    .unwrap();
  std::fs::remove_file(p).unwrap();
  (out.status.success(), String::from_utf8(out.stdout).unwrap())
}

#[test]
#[cfg_attr(debug_assertions, ignore = "release only")]
fn real_testnet4_bundles_verify_and_relabelling_is_refused() {
  let vk = std::env::temp_dir().join(format!("tn4-vk-{}", std::process::id()));
  let out = Command::new(env!("CARGO_BIN_EXE_btc-header-fold"))
    .args(["vk-export", "5", vk.to_str().unwrap(), "--network", "testnet4"])
    .output()
    .unwrap();
  assert!(String::from_utf8_lossy(&out.stdout).contains(TN4_K5), "testnet4 k=5 key drifted");

  let genesis = std::fs::read(fixture("genesis_0_2020_k5.nht4")).unwrap();
  let (ok, r) = verify(&genesis, &vk, "genesis");
  assert!(ok, "{r}");
  for want in [
    "\"statement\":\"btc_header_chain_testnet4_v1\"",
    &format!("\"checkpoint_state_sha256\":\"{GENESIS_ANCHOR}\""),
    "\"checkpoint\":{\"height\":0,\"tip_hash\":\"00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043\",\"chainwork\":\"0x100010001\"}",
    "\"end\":{\"height\":2020,\"tip_hash\":\"00000000360b7ae1602c56dd58e7c0676f526a852f4693c44fcf0e99a4f5ee36\",\"chainwork\":\"0x7f407f407f4\"}",
  ] {
    assert!(r.contains(want), "missing {want} in {r}");
  }

  let auth = std::fs::read(fixture("auth_100700_100900_k5.nht4")).unwrap();
  let (ok, r) = verify(&auth, &vk, "auth");
  assert!(ok && r.contains("\"chainwork\":\"0x54596fd7758cafd453c\""), "{r}");

  // Relabelled as mainnet and verified with the testnet4 key: refused.
  let mut relabel = genesis.clone();
  relabel[..4].copy_from_slice(b"NHC1");
  let (ok, r) = verify(&relabel, &vk, "relabel");
  assert!(!ok && !r.contains("\"verified\":true"), "{r}");
  assert!(r.contains("pinned to testnet4"), "{r}");

  // Tampered start state (genesis chainwork) and proof bytes: refused.
  let mut cw = genesis.clone();
  cw[12 + 3 * 32] ^= 1;
  assert!(!verify(&cw, &vk, "cw").0);
  let mut pb = genesis;
  let n = pb.len();
  pb[n - 100] ^= 1;
  assert!(!verify(&pb, &vk, "proof").0);
  std::fs::remove_file(vk).unwrap();
}
