//! M16 guest: guest A's pinned Nova 0.76.0 verifier for a Bitcoin header chain, plus an SPV
//! payment proven against the chain's verified tip.
//!
//! Private inputs (in order):
//! 1. the bincode verifier key, raw-encoded (`m15-keyconv to-raw`: commitment-key points as
//!    uncompressed affine (x, y), so decoding needs no square roots);
//! 2. the header-chain segments: u32 m | m × (u32 len | NHC1/NHT4 bundle), each bundle being
//!    magic | steps | k | z0 | compressed proof. Segment i + 1 must start at segment i's end
//!    state, so the segments prove one chain from the first z0;
//! 3. the payment blob:
//!    u32 n | n block headers B..T (80 bytes each) | u32 vout | u32 len | tx (len bytes, no
//!    witness) | u32 depth | depth Merkle siblings (32 bytes each) | u32 index.
//!
//! The guest refuses (panics, so no proof exists) unless:
//! - the key is the one pinned for the segments' (network, k), Nova's verifier accepts every
//!   segment, and each segment starts at the previous one's end state;
//! - header T hashes to the proof's final tip (zn's previous-block hash);
//! - each header B..T-1 hashes to the previous-hash field of the next one, so B is T's ancestor
//!   at height h_T - (n - 1). Their proof of work was checked by the Nova proof, which validated
//!   every header up to T;
//! - the transaction is not 64 bytes (no Merkle inner node can pose as it), parses fully as a
//!   transaction with at least one input, and has output `vout`;
//! - its txid, folded with the siblings at `index`, gives header B's Merkle root.
//!
//! `sha256(vk)` in the statement is the digest of the key's compressed encoding, the one every pin
//! and statement uses; the guest checks the raw key against the raw digest pinned next to it (M15).
//!
//! Public output: guest A's 1,164-byte statement layout
//! (magic | k | steps | z0 | zn | sha256(vk) | proofs digest), with steps summed over the
//! segments, z0 of the first and zn of the last. The proofs digest is sha256(proof) for one
//! segment (guest A's value) and sha256 of the per-proof SHA-256s in order for several. Then the
//! 128-byte payment record: "PAY1" | u32 segments | u32 height_B | hash_B | u32 confirmations (n)
//! | txid | u32 vout | u64 value | u32 script length | sha256(scriptPubKey). Hashes are in
//! internal byte order.
#![no_main]
sp1_zkvm::entrypoint!(main);

use ff::PrimeField;
use nova_snark::{
  frontend::{num::AllocatedNum, ConstraintSystem, SynthesisError},
  nova::{CompressedSNARK, VerifierKey},
  provider::{ipa_pc, PallasEngine, VestaEngine},
  spartan::snark::RelaxedR1CSSNARK,
  traits::{circuit::StepCircuit, Engine},
};
use sha2::{Digest, Sha256};

type E1 = PallasEngine;
type E2 = VestaEngine;
type F = <E1 as Engine>::Scalar;
type S1 = RelaxedR1CSSNARK<E1, ipa_pc::EvaluationEngine<E1>>;
type S2 = RelaxedR1CSSNARK<E2, ipa_pc::EvaluationEngine<E2>>;

/// Verification never synthesizes the step circuit; only its arity (17) is used.
#[derive(Clone, Debug)]
struct Arity17;
impl StepCircuit<F> for Arity17 {
  fn arity(&self) -> usize {
    17
  }
  fn synthesize<CS: ConstraintSystem<F>>(&self, _: &mut CS, z: &[AllocatedNum<F>]) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
    Ok(z.to_vec())
  }
}

/// (magic, k, SHA-256 of the raw-encoded key, SHA-256 of the same key compressed). The pair is one
/// key: m15-keyconv converts compressed to raw and checks the round trip back to the same bytes.
const PINS: [(&[u8; 4], u32, &str, &str); 2] = [
  (
    b"NHC1",
    1,
    "4e815db864116def3aa6556d3ff9ff5540a48e6b1bd59f4a2f3c925cec937615",
    "6aa50d09397c51d0b89d78b3a918d3fe0962251225c8b6ca91e83199a4e6da1d",
  ),
  (
    b"NHT4",
    1,
    "63f91f1ec5c6b2d19185df0578311a5dfb8404441631c1ae515d07a8198dd20e",
    "6894f4903a9ff9713111bb1076b61663ac3592ad3d51b697d58125403fc5c12a",
  ),
];

fn hex32(s: &str) -> [u8; 32] {
  let n = |c: u8| match c {
    b'0'..=b'9' => c - b'0',
    b'a'..=b'f' => c - b'a' + 10,
    _ => panic!("pin hex"),
  };
  let b = s.as_bytes();
  core::array::from_fn(|i| n(b[2 * i]) << 4 | n(b[2 * i + 1]))
}

const ZB: usize = 17 * 32;

fn sha256d(b: &[u8]) -> [u8; 32] {
  Sha256::digest(Sha256::digest(b)).into()
}

/// Bounded reader over the payment blob and the transaction.
struct Rd<'a> {
  b: &'a [u8],
  at: usize,
}
impl<'a> Rd<'a> {
  fn take(&mut self, n: usize) -> &'a [u8] {
    let end = self.at.checked_add(n).expect("length overflow");
    assert!(end <= self.b.len(), "input truncated");
    let s = &self.b[self.at..end];
    self.at = end;
    s
  }
  fn u32(&mut self) -> u32 {
    u32::from_le_bytes(self.take(4).try_into().unwrap())
  }
  fn u64(&mut self) -> u64 {
    u64::from_le_bytes(self.take(8).try_into().unwrap())
  }
  /// Bitcoin CompactSize, canonical encodings only.
  fn varint(&mut self) -> u64 {
    let v = match self.take(1)[0] {
      0xfd => {
        let v = u16::from_le_bytes(self.take(2).try_into().unwrap()) as u64;
        assert!(v >= 0xfd, "non-canonical varint");
        v
      }
      0xfe => {
        let v = self.u32() as u64;
        assert!(v > 0xffff, "non-canonical varint");
        v
      }
      0xff => {
        let v = self.u64();
        assert!(v > 0xffff_ffff, "non-canonical varint");
        v
      }
      x => x as u64,
    };
    assert!(v <= 4_000_000, "count out of range");
    v
  }
  fn done(&self) -> bool {
    self.at == self.b.len()
  }
}

/// (value, scriptPubKey) of output `vout` of a transaction in its no-witness serialization.
fn output(tx: &[u8], vout: u32) -> (u64, &[u8]) {
  let mut r = Rd { b: tx, at: 0 };
  r.take(4); // version
  let n_in = r.varint();
  assert!(n_in >= 1, "no inputs (a witness serialization is not accepted)");
  for _ in 0..n_in {
    r.take(36); // previous outpoint
    let l = r.varint() as usize;
    r.take(l);
    r.take(4); // sequence
  }
  let n_out = r.varint();
  assert!((vout as u64) < n_out, "no such output");
  let mut found = None;
  for i in 0..n_out {
    let value = r.u64();
    let l = r.varint() as usize;
    let script = r.take(l);
    if i == vout as u64 {
      found = Some((value, script));
    }
  }
  r.take(4); // lock time
  assert!(r.done(), "trailing bytes after the transaction");
  found.unwrap()
}

/// zn's previous-block hash: two 128-bit little-endian halves (z[1] low, z[2] high).
fn tip_hash(zn: &[F]) -> [u8; 32] {
  let mut h = [0u8; 32];
  for (i, f) in zn[1..3].iter().enumerate() {
    let r = f.to_repr();
    assert!(r.as_ref()[16..].iter().all(|&b| b == 0), "tip hash half exceeds 128 bits");
    h[16 * i..16 * i + 16].copy_from_slice(&r.as_ref()[..16]);
  }
  h
}

fn small_u32(f: &F) -> u32 {
  let r = f.to_repr();
  assert!(r.as_ref()[4..].iter().all(|&b| b == 0), "height exceeds 32 bits");
  u32::from_le_bytes(r.as_ref()[..4].try_into().unwrap())
}

pub fn main() {
  let vk_bytes = sp1_zkvm::io::read_vec();
  let segments = sp1_zkvm::io::read_vec();
  let pay = sp1_zkvm::io::read_vec();

  // The payment checks that do not need the proven tip run first, so a bad payment input
  // fails before the Nova verification.
  println!("cycle-tracker-report-start: spv_payment");
  let mut r = Rd { b: &pay, at: 0 };
  let n = r.u32();
  assert!((1..=4032).contains(&n), "header count out of range");
  let headers: Vec<&[u8]> = (0..n).map(|_| r.take(80)).collect();
  for w in headers.windows(2) {
    assert!(sha256d(w[0]) == w[1][4..36], "headers do not link");
  }
  let block = headers[0];
  let block_hash = sha256d(block);
  let vout = r.u32();
  let tx_len = r.u32() as usize;
  let tx = r.take(tx_len);
  assert!(tx.len() != 64, "a 64-byte transaction can be confused with a Merkle node");
  let (value, script) = output(tx, vout);
  let txid = sha256d(tx);
  let depth = r.u32();
  assert!(depth <= 32, "Merkle branch too deep");
  let siblings: Vec<&[u8]> = (0..depth).map(|_| r.take(32)).collect();
  let index = r.u32();
  assert!(depth == 32 || (index as u64) >> depth == 0, "index outside the tree");
  assert!(r.done(), "trailing bytes in the payment input");
  let mut node = txid;
  let mut buf = [0u8; 64];
  for (j, s) in siblings.iter().enumerate() {
    if (index >> j) & 1 == 1 {
      buf[..32].copy_from_slice(s);
      buf[32..].copy_from_slice(&node);
    } else {
      buf[..32].copy_from_slice(&node);
      buf[32..].copy_from_slice(s);
    }
    node = sha256d(&buf);
  }
  assert!(node == block[36..68], "transaction is not in the block's Merkle tree");
  println!("cycle-tracker-report-end: spv_payment");

  println!("cycle-tracker-report-start: parse_and_pin");
  let mut sr = Rd { b: &segments, at: 0 };
  let count = sr.u32();
  assert!((1..=64).contains(&count), "segment count out of range");
  let bundles: Vec<&[u8]> = (0..count)
    .map(|_| {
      let len = sr.u32() as usize;
      assert!(len > 12 + ZB && len <= 1 << 20, "bundle size");
      sr.take(len)
    })
    .collect();
  assert!(sr.done(), "trailing bytes after the segments");
  let magic: [u8; 4] = bundles[0][..4].try_into().unwrap();
  assert!(&magic == b"NHC1" || &magic == b"NHT4", "unknown network magic");
  let k = u32::from_le_bytes(bundles[0][8..12].try_into().unwrap());
  assert!(k > 0 && k <= 64, "fold width out of range");
  for b in &bundles {
    assert!(b[..4] == magic && b[8..12] == k.to_le_bytes(), "segments differ in network or fold width");
  }
  println!("cycle-tracker-report-end: parse_and_pin");

  println!("cycle-tracker-report-start: sha256_vk");
  let raw_sha: [u8; 32] = Sha256::digest(&vk_bytes).into();
  println!("cycle-tracker-report-end: sha256_vk");
  for (m, kk, raw, _) in PINS {
    if hex32(raw) == raw_sha {
      assert!(m == &magic && kk == k, "verifier key is pinned to another network or fold width");
    }
  }
  let pin = PINS.iter().find(|(m, kk, _, _)| *m == &magic && *kk == k).expect("no pinned key for this network and fold width");
  assert!(hex32(pin.2) == raw_sha, "verifier key differs from the pinned key");
  let vk_sha = hex32(pin.3);

  println!("cycle-tracker-report-start: decode_vk");
  // Raw affine encoding for decoding the key only: Nova's verifier recomputes the key's digest by
  // serializing it, and that digest is over the compressed encoding keygen used.
  halo2curves::serde::set_raw_affine_serde(true);
  let vk: VerifierKey<E1, E2, Arity17, S1, S2> = bincode::deserialize(&vk_bytes).expect("verifier key decodes");
  halo2curves::serde::set_raw_affine_serde(false);
  println!("cycle-tracker-report-end: decode_vk");
  drop(vk_bytes);

  // Each segment must start exactly where the previous one ended (canonical bytes).
  let z0_bytes = &bundles[0][12..12 + ZB];
  let mut zn: Vec<F> = vec![];
  let mut steps: u32 = 0;
  let mut proofs_sha = Sha256::new();
  for (i, b) in bundles.iter().enumerate() {
    let s = u32::from_le_bytes(b[4..8].try_into().unwrap());
    assert!(s > 0, "empty segment");
    steps = steps.checked_add(s).expect("step count overflow");
    let z0: Vec<F> = b[12..12 + ZB]
      .chunks(32)
      .map(|c| {
        let mut r = <F as PrimeField>::Repr::default();
        r.as_mut().copy_from_slice(c);
        Option::<F>::from(F::from_repr(r)).expect("canonical z0")
      })
      .collect();
    if i > 0 {
      assert!(z0 == zn, "segment does not start at the previous segment's end state");
    }
    let proof = &b[12 + ZB..];
    proofs_sha.update(Sha256::digest(proof));
    println!("cycle-tracker-report-start: decode_proof");
    let snark: CompressedSNARK<E1, E2, Arity17, S1, S2> = bincode::deserialize(proof).expect("proof decodes");
    println!("cycle-tracker-report-end: decode_proof");
    println!("cycle-tracker-report-start: nova_verify");
    zn = snark.verify(&vk, s as usize, &z0).expect("Nova verifier rejects the proof");
    println!("cycle-tracker-report-end: nova_verify");
  }
  // One segment: SHA-256 of its proof, as guest A commits. Several: SHA-256 of the
  // concatenated per-proof SHA-256s, in order.
  let proof_sha: [u8; 32] = if count == 1 {
    Sha256::digest(&bundles[0][12 + ZB..]).into()
  } else {
    proofs_sha.finalize().into()
  };

  println!("cycle-tracker-report-start: spv_tip");
  let tip_height = small_u32(&zn[0]);
  assert!(tip_height >= n - 1, "more headers than the chain holds");
  assert!(sha256d(headers[n as usize - 1]) == tip_hash(&zn), "last header is not the proven tip");
  println!("cycle-tracker-report-end: spv_tip");


  let mut out = Vec::with_capacity(12 + 2 * ZB + 64 + 128);
  out.extend_from_slice(&magic);
  out.extend_from_slice(&k.to_le_bytes());
  out.extend_from_slice(&steps.to_le_bytes());
  out.extend_from_slice(z0_bytes);
  for f in &zn {
    out.extend_from_slice(f.to_repr().as_ref());
  }
  out.extend_from_slice(&vk_sha);
  out.extend_from_slice(&proof_sha);
  out.extend_from_slice(b"PAY1");
  out.extend_from_slice(&count.to_le_bytes());
  out.extend_from_slice(&(tip_height - (n - 1)).to_le_bytes());
  out.extend_from_slice(&block_hash);
  out.extend_from_slice(&n.to_le_bytes());
  out.extend_from_slice(&txid);
  out.extend_from_slice(&vout.to_le_bytes());
  out.extend_from_slice(&value.to_le_bytes());
  out.extend_from_slice(&(script.len() as u32).to_le_bytes());
  out.extend_from_slice(&Sha256::digest(script));
  sp1_zkvm::io::commit_slice(&out);
}
