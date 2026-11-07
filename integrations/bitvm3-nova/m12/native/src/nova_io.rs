//! Nova 0.76.0 types, the genesis-anchored small prover and the
//! statement-bound native verifier.
use crate::bundle::{self, Bundle, PublicStatement, Statement, ARITY, Z_BYTES};
use crate::pins;
use ff::PrimeField;
use nova_header_chain::{
  native::{self, Header, Network, State},
  HeaderStep,
};
use nova_snark::{
  nova::{CompressedSNARK, PublicParams, RecursiveSNARK, VerifierKey},
  provider::{ipa_pc, PallasEngine, VestaEngine},
  spartan::snark::RelaxedR1CSSNARK,
  traits::{snark::RelaxedR1CSSNARKTrait, Engine},
};
use sha2::{Digest, Sha256};
use std::time::Instant;

pub type E1 = PallasEngine;
pub type E2 = VestaEngine;
pub type F1 = <E1 as Engine>::Scalar;
pub type F2 = <E2 as Engine>::Scalar;
pub type S1 = RelaxedR1CSSNARK<E1, ipa_pc::EvaluationEngine<E1>>;
pub type S2 = RelaxedR1CSSNARK<E2, ipa_pc::EvaluationEngine<E2>>;
pub type C = HeaderStep;
pub type Pp = PublicParams<E1, E2, C>;
pub type Vk = VerifierKey<E1, E2, C, S1, S2>;
pub type Snark = CompressedSNARK<E1, E2, C, S1, S2>;
pub type Rs = RecursiveSNARK<E1, E2, C>;

pub fn sha256(b: &[u8]) -> [u8; 32] {
  Sha256::digest(b).into()
}

pub fn sha256_hex(b: &[u8]) -> String {
  hex::encode(sha256(b))
}

pub fn z_bytes(z: &[F1]) -> Vec<u8> {
  z.iter().flat_map(|f| f.to_repr().as_ref().to_vec()).collect()
}

pub fn z_from_bytes(b: &[u8]) -> Result<Vec<F1>, String> {
  if b.len() != Z_BYTES {
    return Err("state must hold 17 field elements".into());
  }
  b.chunks(32)
    .map(|c| {
      let mut r = <F1 as PrimeField>::Repr::default();
      r.as_mut().copy_from_slice(c);
      Option::<F1>::from(F1::from_repr(r)).ok_or_else(|| "non-canonical field element in state".to_string())
    })
    .collect()
}

/// Public parameters for fold width k (the shape does not depend on header values).
pub fn setup(net: Network, k: usize) -> Pp {
  let shape = HeaderStep::on(net, vec![[0u8; 80]; k]);
  PublicParams::<E1, E2, C>::setup(&shape, &*S1::ck_floor(), &*S2::ck_floor()).expect("public parameters")
}

/// The deterministic verifier key, bincode 1.x encoded (as `btc-header-fold vk-export`).
pub fn vk_export(net: Network, k: usize) -> Vec<u8> {
  let pp = setup(net, k);
  let (_, vk) = Snark::setup(&pp).expect("compressed setup");
  bincode::serialize(&vk).expect("vk encodes")
}

/// Raw 80-byte headers indexed by height from genesis.
pub fn load_headers_bin(b: &[u8], net: Network) -> Result<Vec<Header>, String> {
  if b.len() % 80 != 0 || b.is_empty() {
    return Err("header file length is not a positive multiple of 80".into());
  }
  let hs: Vec<Header> = b.chunks(80).map(|c| c.try_into().unwrap()).collect();
  if hs[0] != native::genesis_header(net) {
    return Err(format!("header file does not start with the {} genesis block", net.name()));
  }
  Ok(hs)
}

pub struct SmallProof {
  pub z0: Vec<F1>,
  pub zn: Vec<F1>,
  pub rs: Rs,
  pub rs_bytes: Vec<u8>,
  pub bundle: Vec<u8>,
  pub vk: Vec<u8>,
  pub report: serde_json::Value,
}

/// Fold `steps` x `k` headers from the consensus genesis state, compress, and
/// return the RecursiveSNARK (it holds the folded witness architecture B needs),
/// the compressed bundle and the verifier key.
pub fn prove_from_genesis(net: Network, k: usize, steps: usize, hs: &[Header]) -> Result<SmallProof, String> {
  if hs.len() < 1 + k * steps {
    return Err("not enough headers".into());
  }
  let mut state = State::genesis(net);
  let mut circuits = Vec::with_capacity(steps);
  for s in 0..steps {
    let headers: Vec<Header> = (0..k).map(|i| hs[1 + s * k + i]).collect();
    for h in &headers {
      state = state.apply_on(net, h).map_err(|e| format!("native rules reject a header: {e}"))?;
    }
    circuits.push(HeaderStep::on(net, headers));
  }
  let t = Instant::now();
  let pp = setup(net, k);
  let setup_s = t.elapsed().as_secs_f64();
  let (cons1, cons2) = pp.num_constraints();
  let (vars1, vars2) = pp.num_variables();
  let z0 = State::genesis(net).to_z::<F1>();
  let t = Instant::now();
  let mut rs = Rs::new(&pp, &circuits[0], &z0).map_err(|e| format!("{e:?}"))?;
  for c in &circuits {
    rs.prove_step(&pp, c).map_err(|e| format!("{e:?}"))?;
  }
  let fold_s = t.elapsed().as_secs_f64();
  let zn = rs.verify(&pp, steps, &z0).map_err(|e| format!("recursive verify: {e:?}"))?;
  if zn != state.to_z::<F1>() {
    return Err("folded output differs from the native final state".into());
  }
  let t = Instant::now();
  let (pk, vk) = Snark::setup(&pp).map_err(|e| format!("{e:?}"))?;
  let snark_setup_s = t.elapsed().as_secs_f64();
  let t = Instant::now();
  let snark = Snark::prove(&pp, &pk, &rs).map_err(|e| format!("{e:?}"))?;
  let compress_s = t.elapsed().as_secs_f64();
  let proof = bincode::serialize(&snark).unwrap();
  let vk_b = bincode::serialize(&vk).unwrap();
  let rs_bytes = bincode::serialize(&rs).unwrap();
  let bundle = Bundle { net, steps: steps as u32, k: k as u32, z0: z_bytes(&z0), proof: proof.clone() }.to_bytes();
  let report = serde_json::json!({
    "network": net.name(), "k": k, "steps": steps, "headers": k * steps,
    "constraints": {"primary": cons1, "secondary": cons2},
    "variables": {"primary": vars1, "secondary": vars2},
    "setup_seconds": setup_s, "fold_seconds": fold_s,
    "compressed_setup_seconds": snark_setup_s, "compress_seconds": compress_s,
    "proof_bytes": proof.len(), "vk_bytes": vk_b.len(), "recursive_snark_bytes": rs_bytes.len(),
    "vk_sha256": sha256_hex(&vk_b), "proof_sha256": sha256_hex(&proof), "bundle_sha256": sha256_hex(&bundle),
    "checkpoint_state_sha256": sha256_hex(&z_bytes(&z0)), "end_state_sha256": sha256_hex(&z_bytes(&zn)),
  });
  Ok(SmallProof { z0, zn, rs, rs_bytes, bundle, vk: vk_b, report })
}

fn tip_display(state: &State) -> String {
  let mut h = state.prev;
  h.reverse();
  hex::encode(h)
}

/// What the native statement verifier did, with timings.
#[derive(Debug)]
pub struct Verified {
  pub statement: Statement,
  pub public: PublicStatement,
  pub vk_decode_seconds: f64,
  pub verify_seconds: f64,
}

/// Verify a bundle under a key: the key must be the one pinned for the
/// bundle's (network, k), the proof must verify with Nova 0.76.0, and the
/// accepted statement binds network, k, steps, z0, zn and both digests.
pub fn verify_statement(bundle_bytes: &[u8], vk_bytes: &[u8]) -> Result<Verified, String> {
  let b = Bundle::parse(bundle_bytes)?;
  let vk_sha = sha256(vk_bytes);
  pins::check(b.net, b.k as usize, &hex::encode(vk_sha))?;
  verify_parsed(&b, vk_bytes, vk_sha)
}

/// As [`verify_statement`] without the pin check, for keys under test.
pub fn verify_unpinned(bundle_bytes: &[u8], vk_bytes: &[u8]) -> Result<Verified, String> {
  let b = Bundle::parse(bundle_bytes)?;
  verify_parsed(&b, vk_bytes, sha256(vk_bytes))
}

fn verify_parsed(b: &Bundle, vk_bytes: &[u8], vk_sha: [u8; 32]) -> Result<Verified, String> {
  let z0 = z_from_bytes(&b.z0)?;
  let t = Instant::now();
  let vk: Vk = bincode::deserialize(vk_bytes).map_err(|e| format!("vk decode: {e}"))?;
  let vk_decode_seconds = t.elapsed().as_secs_f64();
  let snark: Snark = bincode::deserialize(&b.proof).map_err(|e| format!("proof decode: {e}"))?;
  let t = Instant::now();
  let zn = snark.verify(&vk, b.steps as usize, &z0).map_err(|e| format!("rejected: {e:?}"))?;
  let verify_seconds = t.elapsed().as_secs_f64();
  if zn.len() != ARITY {
    return Err("output arity".into());
  }
  let start = State::from_z(&z0).ok_or("z0 is not a canonical header state")?;
  let end = State::from_z(&zn).ok_or("zn is not a canonical header state")?;
  let public = PublicStatement {
    net: b.net,
    k: b.k,
    steps: b.steps,
    z0: b.z0.clone(),
    zn: z_bytes(&zn),
    vk_sha256: vk_sha,
    proof_sha256: sha256(&b.proof),
  };
  let statement = Statement {
    statement: bundle::STATEMENT_ID.into(),
    network: b.net.name().into(),
    k: b.k,
    steps: b.steps,
    headers: b.k as u64 * b.steps as u64,
    vk_sha256: hex::encode(vk_sha),
    proof_sha256: hex::encode(public.proof_sha256),
    checkpoint_state_sha256: sha256_hex(&b.z0),
    end_state_sha256: sha256_hex(&public.zn),
    start_height: start.height,
    end_height: end.height,
    end_tip_hash: tip_display(&end),
    end_chainwork: format!("0x{}", end.chainwork.to_str_radix(16)),
    public_statement_sha256: sha256_hex(&public.encode()),
  };
  Ok(Verified { statement, public, vk_decode_seconds, verify_seconds })
}
