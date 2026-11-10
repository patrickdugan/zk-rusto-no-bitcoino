//! Guest A, M15: the complete pinned Nova 0.76.0 compressed verifier (as M12's guest A), reading
//! the verifier key with uncompressed commitment-key points, with SHA3 (Nova's key digest) through
//! SP1's Keccak precompile.
//!
//! Private inputs: the raw-encoded bincode verifier key (`m15-keyconv to-raw`) and the NHT4/NHC1
//! bundle. Public output (1,164 bytes, unchanged from M12): magic | k | steps | z0 | zn |
//! sha256(vk) | sha256(proof).
//!
//! `sha256(vk)` is the digest of the key's compressed encoding, the one every pin and statement
//! already uses. The guest checks the raw key against the raw digest pinned next to it; the pair is
//! the same key (`m15-keyconv` re-encodes one to the other and checks both directions), so the
//! committed statement is byte-identical to M12's for the same key and bundle.
//!
//! The guest refuses (panics, so no proof exists) unless the key is the one pinned for the bundle's
//! (network, k) and Nova's verifier accepts.
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

/// (magic, k, SHA-256 of the raw-encoded key, SHA-256 of the same key compressed, as pinned by M12).
const PINS: [(&[u8; 4], u32, &str, &str); 1] = [(
  b"NHT4",
  1,
  "63f91f1ec5c6b2d19185df0578311a5dfb8404441631c1ae515d07a8198dd20e",
  "6894f4903a9ff9713111bb1076b61663ac3592ad3d51b697d58125403fc5c12a",
)];

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

pub fn main() {
  let vk_bytes = sp1_zkvm::io::read_vec();
  let bundle = sp1_zkvm::io::read_vec();

  println!("cycle-tracker-report-start: parse_and_pin");
  assert!(bundle.len() > 12 + ZB && bundle.len() <= 1 << 20, "bundle size");
  let magic: [u8; 4] = bundle[..4].try_into().unwrap();
  assert!(&magic == b"NHC1" || &magic == b"NHT4", "unknown network magic");
  let steps = u32::from_le_bytes(bundle[4..8].try_into().unwrap());
  let k = u32::from_le_bytes(bundle[8..12].try_into().unwrap());
  assert!(steps > 0 && k > 0 && k <= 64, "steps or fold width out of range");
  let z0_bytes = &bundle[12..12 + ZB];
  let proof = &bundle[12 + ZB..];
  println!("cycle-tracker-report-end: parse_and_pin");

  println!("cycle-tracker-report-start: sha256_vk");
  let raw_sha: [u8; 32] = Sha256::digest(&vk_bytes).into();
  println!("cycle-tracker-report-end: sha256_vk");
  let proof_sha: [u8; 32] = Sha256::digest(proof).into();
  for (m, kk, raw, _) in PINS {
    if hex32(raw) == raw_sha {
      assert!(m == &magic && kk == k, "verifier key is pinned to another network or fold width");
    }
  }
  let pin = PINS.iter().find(|(m, kk, _, _)| *m == &magic && *kk == k).expect("no pinned key for this network and fold width");
  assert!(hex32(pin.2) == raw_sha, "verifier key differs from the pinned key");
  let vk_sha = hex32(pin.3);

  let z0: Vec<F> = z0_bytes
    .chunks(32)
    .map(|c| {
      let mut r = <F as PrimeField>::Repr::default();
      r.as_mut().copy_from_slice(c);
      Option::<F>::from(F::from_repr(r)).expect("canonical z0")
    })
    .collect();

  // Raw affine encoding for decoding the key only: Nova's verifier recomputes the key's digest by
  // serializing it, and that digest is over the compressed encoding keygen used.
  println!("cycle-tracker-report-start: decode_vk");
  halo2curves::serde::set_raw_affine_serde(true);
  let vk: VerifierKey<E1, E2, Arity17, S1, S2> = bincode::deserialize(&vk_bytes).expect("verifier key decodes");
  halo2curves::serde::set_raw_affine_serde(false);
  println!("cycle-tracker-report-end: decode_vk");
  drop(vk_bytes);
  println!("cycle-tracker-report-start: decode_proof");
  let snark: CompressedSNARK<E1, E2, Arity17, S1, S2> = bincode::deserialize(proof).expect("proof decodes");
  println!("cycle-tracker-report-end: decode_proof");

  println!("cycle-tracker-report-start: nova_verify");
  let zn = snark.verify(&vk, steps as usize, &z0).expect("Nova verifier rejects the proof");
  println!("cycle-tracker-report-end: nova_verify");

  let mut out = Vec::with_capacity(12 + 2 * ZB + 64);
  out.extend_from_slice(&magic);
  out.extend_from_slice(&k.to_le_bytes());
  out.extend_from_slice(&steps.to_le_bytes());
  out.extend_from_slice(z0_bytes);
  for f in &zn {
    out.extend_from_slice(f.to_repr().as_ref());
  }
  out.extend_from_slice(&vk_sha);
  out.extend_from_slice(&proof_sha);
  sp1_zkvm::io::commit_slice(&out);
}
