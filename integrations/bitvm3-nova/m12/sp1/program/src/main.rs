//! Architecture A guest: the complete pinned Nova 0.76.0 compressed verifier
//! for a Bitcoin-header bundle, run inside SP1 (a transparent STARK zkVM when
//! proved in core or compressed mode; no Groth16 wrap is used).
//!
//! Private inputs: the bincode verifier key and the NHT4/NHC1 bundle.
//! Public output (1,164 bytes): magic | k | steps | z0 | zn | sha256(vk) | sha256(proof),
//! the same encoding as `nova-bitvm3-m12::bundle::PublicStatement`.
//!
//! The guest refuses (panics, so no proof exists) unless the key is the one
//! pinned for the bundle's (network, k) and Nova's verifier accepts.
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

/// (magic, k, SHA-256 of the bincode verifier key): the pins of
/// zk-rusto-no-bitcoino de607d3 plus the M12 pins.
const PINS: [(&[u8; 4], u32, &str); 5] = [
  (b"NHC1", 10, "e46bb06929d701f1986d320e004e8ed744b0e5f74eb9f5e9c9bd0e2fe6ad1698"),
  (b"NHT4", 5, "1ae88a7bcfdc5f14d030d0baafa06ec17fe904a5ebed42f9bd6fa6105fdc8c24"),
  (b"NHT4", 10, "2495da9bf5965030e45fa2cef1a43ade78e099ca844b5d3a9abf56400447eabe"),
  (b"NHT4", 1, "6894f4903a9ff9713111bb1076b61663ac3592ad3d51b697d58125403fc5c12a"),
  (b"NHT4", 20, "9e94b9083b5be30e796e974218804214b7106284c071eeec9b15945735321727"),
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
  let vk_sha: [u8; 32] = Sha256::digest(&vk_bytes).into();
  println!("cycle-tracker-report-end: sha256_vk");
  let proof_sha: [u8; 32] = Sha256::digest(proof).into();
  for (m, kk, d) in PINS {
    if hex32(d) == vk_sha {
      assert!(m == &magic && kk == k, "verifier key is pinned to another network or fold width");
    }
  }
  let pin = PINS.iter().find(|(m, kk, _)| *m == &magic && *kk == k).expect("no pinned key for this network and fold width");
  assert!(hex32(pin.2) == vk_sha, "verifier key differs from the pinned key");

  let z0: Vec<F> = z0_bytes
    .chunks(32)
    .map(|c| {
      let mut r = <F as PrimeField>::Repr::default();
      r.as_mut().copy_from_slice(c);
      Option::<F>::from(F::from_repr(r)).expect("canonical z0")
    })
    .collect();

  println!("cycle-tracker-report-start: decode_vk");
  let vk: VerifierKey<E1, E2, Arity17, S1, S2> = bincode::deserialize(&vk_bytes).expect("verifier key decodes");
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
