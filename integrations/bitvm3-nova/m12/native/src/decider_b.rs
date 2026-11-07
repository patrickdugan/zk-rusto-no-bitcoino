//! Architecture B: a replacement decider over Nova's folded witness.
//!
//! Nova's running primary instance U = (comm_W, comm_E, X, u) is satisfied by
//! (W, r_W, E, r_E) when
//!   (1) A z o B z = u * C z + E  for z = W || u || X   (relaxed R1CS), and
//!   (2) comm_W = Com(W; r_W), comm_E = Com(E; r_E)     (Pedersen binding).
//! A decider that re-commits W and E with a hash-based PCS must establish both.
//! Without (2), (1) alone proves nothing: for ANY W', setting
//! E' = A z' o B z' - u * C z' satisfies (1). [`forge_error`] builds exactly
//! that, and the tests show a hash-PCS-only verifier accepting it while the
//! binding check rejects it.
//!
//! Here the binding is evaluated as a relation over the full committed
//! vectors: the relation a succinct B decider must prove. Proving it
//! succinctly needs the same Pallas MSM inside the outer proof that wrapping
//! the IPA verifier (architecture A) needs; see `../README.md`.
use crate::mirror::{RelaxedInstance, Shape};
use crate::nova_io::{E1, F1};
use crate::pcs::{self, Committed, Opening, Transcript};
use ff::Field;
use nova_snark::{
  provider::{
    pedersen::{Commitment, CommitmentKey},
    traits::{DlogGroup, DlogGroupExt},
  },
  traits::{commitment::CommitmentEngineTrait, Engine},
};

/// (A z, B z, C z) for z = W (zero-padded to the padded num_vars) || u || X.
pub fn products<E: Engine>(s: &Shape<E>, W: &[E::Scalar], u: E::Scalar, X: &[E::Scalar]) -> Result<[Vec<E::Scalar>; 3], String> {
  if W.len() > s.num_vars {
    return Err("witness longer than the shape".into());
  }
  if X.len() != s.num_io {
    return Err(format!("public IO length {} differs from the shape's {}", X.len(), s.num_io));
  }
  let n = s.num_vars;
  let z = |c: usize| -> Option<E::Scalar> {
    if c < n {
      Some(W.get(c).copied().unwrap_or(E::Scalar::ZERO))
    } else if c == n {
      Some(u)
    } else {
      X.get(c - n - 1).copied()
    }
  };
  let mul = |m: &nova_snark::r1cs::SparseMatrix<E::Scalar>| -> Result<Vec<E::Scalar>, String> {
    if m.indptr.len() != s.num_cons + 1 {
      return Err("row pointer length".into());
    }
    (0..s.num_cons)
      .map(|row| {
        let mut acc = E::Scalar::ZERO;
        for k in m.indptr[row]..m.indptr[row + 1] {
          acc += m.data[k] * z(m.indices[k]).ok_or("column out of range")?;
        }
        Ok(acc)
      })
      .collect()
  };
  Ok([mul(&s.A)?, mul(&s.B)?, mul(&s.C)?])
}

/// Check A z o B z = u * C z + E (E zero-padded to the padded num_cons).
pub fn relaxed_sat<E: Engine>(s: &Shape<E>, W: &[E::Scalar], Ev: &[E::Scalar], u: E::Scalar, X: &[E::Scalar]) -> Result<(), String> {
  if Ev.len() > s.num_cons {
    return Err("error vector longer than the shape".into());
  }
  let [a, b, c] = products(s, W, u, X)?;
  for row in 0..s.num_cons {
    let e = Ev.get(row).copied().unwrap_or(E::Scalar::ZERO);
    if a[row] * b[row] != u * c[row] + e {
      return Err(format!("relaxed R1CS fails at row {row}"));
    }
  }
  Ok(())
}

/// The error vector that makes ANY witness satisfy the relaxed relation.
pub fn forge_error<E: Engine>(s: &Shape<E>, W: &[E::Scalar], u: E::Scalar, X: &[E::Scalar]) -> Result<Vec<E::Scalar>, String> {
  let [a, b, c] = products(s, W, u, X)?;
  Ok((0..s.num_cons).map(|i| a[i] * b[i] - u * c[i]).collect())
}

pub fn pedersen<E: Engine>(ck: &CommitmentKey<E>, v: &[E::Scalar], r: &E::Scalar) -> Commitment<E>
where
  E::GE: DlogGroup + DlogGroupExt,
  E: Engine<CE = nova_snark::provider::pedersen::CommitmentEngine<E>>,
{
  <E::CE as CommitmentEngineTrait<E>>::commit(ck, v, r)
}

/// comm_W + gamma comm_E == Com(W + gamma E; r_W + gamma r_E): one MSM over
/// the shared generators instead of two. gamma must be drawn after both
/// commitments are fixed.
#[allow(clippy::too_many_arguments)]
pub fn binds_combined<E: Engine>(
  ck: &CommitmentKey<E>,
  comm_W: &Commitment<E>,
  comm_E: &Commitment<E>,
  W: &[E::Scalar],
  Ev: &[E::Scalar],
  r_W: E::Scalar,
  r_E: E::Scalar,
  gamma: E::Scalar,
) -> bool
where
  E::GE: DlogGroup + DlogGroupExt,
  E: Engine<CE = nova_snark::provider::pedersen::CommitmentEngine<E>>,
{
  let n = W.len().max(Ev.len());
  let combined: Vec<E::Scalar> = (0..n)
    .map(|i| W.get(i).copied().unwrap_or(E::Scalar::ZERO) + gamma * Ev.get(i).copied().unwrap_or(E::Scalar::ZERO))
    .collect();
  let lhs = *comm_W + *comm_E * gamma;
  lhs == pedersen(ck, &combined, &(r_W + gamma * r_E))
}

fn log2_ceil(n: usize) -> usize {
  n.next_power_of_two().trailing_zeros() as usize
}

/// A hash-PCS commitment to (W, E) of a primary running instance, opened at a
/// Fiat-Shamir point. In a full decider the points come from Spartan's
/// sumchecks; here they come from the transcript after both roots.
#[derive(Clone, Debug)]
pub struct ProofB {
  pub num_vars_w: usize,
  pub num_vars_e: usize,
  pub root_w: [u8; 32],
  pub root_e: [u8; 32],
  pub eval_w: F1,
  pub eval_e: F1,
  pub open_w: Opening,
  pub open_e: Opening,
}

impl ProofB {
  pub fn size_bytes(&self) -> usize {
    64 + 64 + self.open_w.size_bytes() + self.open_e.size_bytes()
  }
}

fn instance_transcript(U: &RelaxedInstance<E1>) -> Transcript {
  let mut tr = Transcript::new(b"M12-decider-B-v1");
  tr.absorb(b"comm_W", &bincode::serialize(&U.comm_W).unwrap());
  tr.absorb(b"comm_E", &bincode::serialize(&U.comm_E).unwrap());
  tr.absorb_fields(b"X", &U.X);
  tr.absorb_fields(b"u", &[U.u]);
  tr
}

/// Commit W and E with the hash PCS and open both. Returns the proof, the
/// commitments (prover state) and the transcript's gamma for the binding.
pub fn prove(U: &RelaxedInstance<E1>, W: &[F1], Ev: &[F1], num_vars_w: usize, num_vars_e: usize) -> (ProofB, Committed, Committed) {
  let mut tr = instance_transcript(U);
  let cw = pcs::commit(W, num_vars_w);
  let ce = pcs::commit(Ev, num_vars_e);
  tr.absorb(b"root_W", &cw.root);
  tr.absorb(b"root_E", &ce.root);
  let point_w = tr.challenges(b"point_W", num_vars_w);
  let point_e = tr.challenges(b"point_E", num_vars_e);
  let (eval_w, open_w) = pcs::open(&cw, &point_w, &mut tr);
  let (eval_e, open_e) = pcs::open(&ce, &point_e, &mut tr);
  (ProofB { num_vars_w, num_vars_e, root_w: cw.root, root_e: ce.root, eval_w, eval_e, open_w, open_e }, cw, ce)
}

/// The hash-PCS checks alone. Accepting here says only that the roots commit
/// to SOME vectors with these evaluations, not that they are Nova's W and E.
pub fn verify_pcs_only(U: &RelaxedInstance<E1>, p: &ProofB) -> Result<Transcript, String> {
  let mut tr = instance_transcript(U);
  tr.absorb(b"root_W", &p.root_w);
  tr.absorb(b"root_E", &p.root_e);
  let point_w = tr.challenges(b"point_W", p.num_vars_w);
  let point_e = tr.challenges(b"point_E", p.num_vars_e);
  pcs::verify(&p.root_w, p.num_vars_w, &point_w, p.eval_w, &p.open_w, &mut tr)?;
  pcs::verify(&p.root_e, p.num_vars_e, &point_e, p.eval_e, &p.open_e, &mut tr)?;
  Ok(tr)
}

/// The complete B relation for the primary running instance: PCS checks, the
/// committed vectors are (W, E), relaxed R1CS holds, and Pedersen binds them
/// to U's commitments.
#[allow(clippy::too_many_arguments)]
pub fn verify_with_binding(
  U: &RelaxedInstance<E1>,
  p: &ProofB,
  shape: &Shape<E1>,
  ck: &CommitmentKey<E1>,
  W: &[F1],
  Ev: &[F1],
  r_W: F1,
  r_E: F1,
) -> Result<(), String> {
  let mut tr = verify_pcs_only(U, p)?;
  if pcs::commit(W, p.num_vars_w).root != p.root_w {
    return Err("W is not the vector under root_W".into());
  }
  if pcs::commit(Ev, p.num_vars_e).root != p.root_e {
    return Err("E is not the vector under root_E".into());
  }
  relaxed_sat(shape, W, Ev, U.u, &U.X)?;
  let gamma = tr.challenge(b"binding-gamma");
  if !binds_combined(ck, &U.comm_W, &U.comm_E, W, Ev, r_W, r_E, gamma) {
    return Err("Pedersen binding fails: the hash-committed witness is not the one Nova committed".into());
  }
  Ok(())
}

/// Variables needed to commit a vector of length n.
pub fn num_vars_for(n: usize) -> usize {
  log2_ceil(n.max(2))
}
