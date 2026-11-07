//! Field-for-field serde mirrors of Nova 0.76.0 types whose fields are
//! crate-private. Inner types are Nova's own public types, so the decoders
//! reuse Nova's serde for scalars, points, commitments, keys and matrices.
//! Decoding uses bincode 1.x fixed-int encoding with `reject_trailing_bytes`,
//! so a successful decode accounts for every byte of the input.
use crate::nova_io::{E1, E2, F1, F2};
use bincode::Options;
use nova_snark::{
  provider::{
    pedersen::{Commitment, CommitmentKey},
    traits::DlogGroup,
  },
  r1cs::SparseMatrix,
  traits::{commitment::CommitmentEngineTrait, evm_serde::EvmCompatSerde, Engine, ROConstants},
};
use serde::Deserialize;
use serde_with::serde_as;
use std::marker::PhantomData;

pub fn decode_exact<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, String> {
  bincode::DefaultOptions::new()
    .with_fixint_encoding()
    .reject_trailing_bytes()
    .deserialize(bytes)
    .map_err(|e| format!("mirror decode: {e}"))
}

// ---- verifier key: nova::VerifierKey -> spartan::snark::VerifierKey -> (ipa vk, R1CSShape)

#[derive(Deserialize)]
#[serde(bound = "")]
pub struct IpaVk<E: Engine>
where
  E::GE: DlogGroup,
{
  pub ck_v: CommitmentKey<E>,
  pub ck_s: CommitmentKey<E>,
}

/// The padded R1CS shape stored in the Spartan verifier key (Z = W || u || X,
/// with X's columns shifted to start at the padded `num_vars`).
#[derive(Deserialize)]
#[serde(bound = "")]
pub struct Shape<E: Engine> {
  pub num_cons: usize,
  pub num_vars: usize,
  pub num_io: usize,
  pub A: SparseMatrix<E::Scalar>,
  pub B: SparseMatrix<E::Scalar>,
  pub C: SparseMatrix<E::Scalar>,
}

#[derive(Deserialize)]
#[serde(bound = "")]
pub struct SpartanVk<E: Engine>
where
  E::GE: DlogGroup,
{
  pub vk_ee: IpaVk<E>,
  pub S: Shape<E>,
}

#[derive(Deserialize)]
#[serde(bound = "")]
pub struct CompressedVk {
  pub F_arity: usize,
  pub ro_consts_primary: ROConstants<E1>,
  pub ro_consts_secondary: ROConstants<E2>,
  pub pp_digest: F1,
  pub vk_primary: SpartanVk<E1>,
  pub vk_secondary: SpartanVk<E2>,
  pub dk_primary: <<E1 as Engine>::CE as CommitmentEngineTrait<E1>>::DerandKey,
  pub dk_secondary: <<E2 as Engine>::CE as CommitmentEngineTrait<E2>>::DerandKey,
}

// ---- RecursiveSNARK (the folded running instances and their witnesses)

#[derive(Clone, Deserialize)]
#[serde(bound = "")]
pub struct RelaxedWitness<E: Engine> {
  pub W: Vec<E::Scalar>,
  pub r_W: E::Scalar,
  pub E: Vec<E::Scalar>,
  pub r_E: E::Scalar,
}

#[serde_as]
#[derive(Clone, Deserialize)]
#[serde(bound = "")]
pub struct RelaxedInstance<E: Engine>
where
  E::GE: DlogGroup,
{
  pub comm_W: Commitment<E>,
  pub comm_E: Commitment<E>,
  #[serde_as(as = "Vec<EvmCompatSerde>")]
  pub X: Vec<E::Scalar>,
  #[serde_as(as = "EvmCompatSerde")]
  pub u: E::Scalar,
}

#[derive(Clone, Deserialize)]
#[serde(bound = "")]
pub struct Witness<E: Engine> {
  pub W: Vec<E::Scalar>,
  pub r_W: E::Scalar,
}

#[serde_as]
#[derive(Clone, Deserialize)]
#[serde(bound = "")]
pub struct Instance<E: Engine>
where
  E::GE: DlogGroup,
{
  pub comm_W: Commitment<E>,
  #[serde_as(as = "Vec<EvmCompatSerde>")]
  pub X: Vec<E::Scalar>,
}

#[derive(Clone, Deserialize)]
#[serde(bound = "")]
pub struct RecursiveMirror {
  pub z0: Vec<F1>,
  pub r_W_primary: RelaxedWitness<E1>,
  pub r_U_primary: RelaxedInstance<E1>,
  pub ri_primary: F1,
  pub r_W_secondary: RelaxedWitness<E2>,
  pub r_U_secondary: RelaxedInstance<E2>,
  pub ri_secondary: F2,
  pub l_w_secondary: Witness<E2>,
  pub l_u_secondary: Instance<E2>,
  pub i: usize,
  pub zi: Vec<F1>,
  pub _p: PhantomData<()>,
}
