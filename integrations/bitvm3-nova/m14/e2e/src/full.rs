//! The complete final verifier as one circuit: `m13_verify::verify_final` with transcript v2.
//!
//! - The wrap key is a circuit constant (the pinned key): its transcript bytes and preprocessed
//!   commitment are built in, so a proof under another key cannot verify.
//! - The STARK: preamble, LogUp-GKR, zerocheck, jagged PCS with stacked BaseFold.
//! - The statement: exit code 0, complete, and the guest key digest, recursion key root and
//!   committed-values digest equal to the pinned ones.
//! - The public-values digest: those fields and the proof nonce hash (SP1's Poseidon2) to the
//!   `digest` slots, the only public values the wrap AIR constrains. Without it the statement
//!   fields are whatever the prover wrote.
//!
//! Output: one wire, 1 iff the proof verifies and states the pinned statement.
use std::borrow::Borrow;

use garbled_snark_verifier::CircuitContext;
use m12_gates::W;
use m13_verify::{FinalStatement, ValidatedFinalStatement};
use m14_circuit::{
    field::{self as f, Fe},
    hash::Transcript,
    poseidon2,
};

use slop_uni_stark::SymbolicExpression;
use sp1_recursion_executor::RecursionPublicValues;

use crate::{
    native::{self, Item, Proof, F},
    pcs::{self, PcsShape},
    verifier::{self, Inputs, Shape},
};

/// Input wires of [`final_verifier`] for the pinned (c4) proof shape.
pub const INPUT_BITS: u64 = 8_635_080;
/// Non-free gates of [`final_verifier`] for that shape, the same for every statement:
/// 785,442,492 for the STARK and the statement equalities, plus [`ROOT_DIGEST_GATES`].
pub const NON_FREE_GATES: u64 = 785_442_492 + ROOT_DIGEST_GATES;
/// What the public-values digest adds: the Poseidon2 hash of 53 elements, 8 comparisons and their
/// conjunction into the statement.
pub const ROOT_DIGEST_GATES: u64 = 7_104_181;

/// Everything fixed when the circuit is built: the pinned key and proof shape, the AIR
/// constraints, and the pinned statement.
pub struct Known {
    pub shape: Shape,
    pub pcs: PcsShape,
    pub constraints: Vec<Vec<SymbolicExpression<F>>>,
    pub vk_preprocessed_commit: [u8; 32],
    expect: ValidatedFinalStatement,
}

impl Known {
    /// From the pinned proof (key and shape) and the pinned statement.
    pub fn new(reference: &Proof, expect: &FinalStatement) -> Self {
        Self::try_new(reference, expect).expect("valid statement and reference key")
    }

    /// Validate all pins before reading the reference shape or building any circuit objects.
    pub fn try_new(reference: &Proof, expect: &FinalStatement) -> anyhow::Result<Self> {
        let expect = expect.validate()?;
        anyhow::ensure!(
            &m13_verify::vk_sha256_bytes(&reference.vk) == expect.wrap_vk_sha256(),
            "reference proof is not under the pinned key"
        );
        let machine = native::machine();
        let shape = Shape::new(&machine, &reference.vk, &reference.proof);
        let constraints = shape.chips.iter().map(verifier::chip_constraints).collect();
        Ok(Known {
            shape,
            pcs: PcsShape::new(&reference.proof),
            constraints,
            vk_preprocessed_commit: reference.vk.preprocessed_commit.into(),
            expect,
        })
    }
}

/// The circuit inputs of a proof, in order. The proof must have the pinned shape.
pub fn items(proof: &Proof) -> Vec<Item> {
    let machine = native::machine();
    let mut v = native::items_logup(&machine, &proof.proof);
    v.extend(native::items_zerocheck(&proof.proof));
    v.extend(native::items_pcs(&proof.proof));
    v
}

/// Offset of each `RecursionPublicValues` field in the public values (SP1's own layout).
fn pv_offsets() -> RecursionPublicValues<u32> {
    let n = std::mem::size_of::<RecursionPublicValues<u8>>() as u32;
    let idx: Vec<u32> = (0..n).collect();
    let pv: &RecursionPublicValues<u32> = idx.as_slice().borrow();
    pv.clone()
}

/// The statement checks of `verify_final` on the public values.
pub fn statement<C: CircuitContext>(c: &mut C, pv: &[Fe], e: &ValidatedFinalStatement) -> W {
    assert_eq!(pv.len(), std::mem::size_of::<RecursionPublicValues<u8>>(), "public-value shape");
    let o = pv_offsets();
    let mut oks = Vec::new();
    let mut is = |c: &mut C, at: u32, v: u32| {
        let w = f::eq(c, &pv[at as usize], &Fe::constant(v));
        oks.push(w);
    };
    is(c, o.exit_code, 0);
    is(c, o.is_complete, 1);
    for i in 0..8 {
        is(c, o.sp1_vk_digest[i], e.program_vk_digest()[i]);
    }
    for i in 0..8 {
        is(c, o.vk_root[i], e.recursion_vk_root()[i]);
    }
    for i in 0..32 {
        is(c, o.committed_value_digest[i / 4][i % 4], e.committed_values_sha256()[i] as u32);
    }
    oks.extend(root_digest(c, pv, &o));
    f::and_all(c, &oks)
}

/// `m13_verify::check_public_values_digest`: the `digest` slots equal SP1's root digest of
/// `sp1_vk_digest`, `committed_value_digest`, `exit_code`, `vk_root` and `proof_nonce`. The hash
/// reads the public-value wires, not the pinned constants, so the gate count does not depend on
/// the statement. One wire per digest element.
fn root_digest<C: CircuitContext>(c: &mut C, pv: &[Fe], o: &RecursionPublicValues<u32>) -> Vec<W> {
    let at = |i: &u32| pv[*i as usize].clone();
    let input: Vec<Fe> = o
        .sp1_vk_digest
        .iter()
        .chain(o.committed_value_digest.iter().flatten())
        .chain(std::iter::once(&o.exit_code))
        .chain(o.vk_root.iter())
        .chain(o.proof_nonce.iter())
        .map(at)
        .collect();
    let digest = poseidon2::hash(c, &input);
    digest.iter().zip(o.digest.iter()).map(|(d, slot)| f::eq(c, d, &pv[*slot as usize])).collect()
}

/// The whole final verifier on input wires `w` (the bits of [`items`]).
pub fn final_verifier<C: CircuitContext>(c: &mut C, k: &Known, w: &[W]) -> W {
    let mut t = Transcript::new(verifier::DOMAIN_V2);
    let mut inp = Inputs::new(w);
    let pre = verifier::preamble(c, &mut t, &k.shape, &mut inp);
    let g = verifier::logup(c, &mut t, &k.shape, &mut inp);
    let z = verifier::zerocheck(c, &mut t, &k.shape, &mut inp, &pre.public_values, &g, &k.constraints);
    let p = pcs::pcs(c, &mut t, &k.pcs, &mut inp, k.vk_preprocessed_commit, &pre.main_commitment, &z);
    let p_all = f::and_all(c, &p);
    let s = statement(c, &pre.public_values, &k.expect);
    assert_eq!(inp.used(), w.len(), "every input wire is consumed");
    let canonical = inp.all_canonical(c);
    f::and_all(c, &[g.ok, z.ok, p_all, s, canonical])
}

/// Every check separately (tests): [LogUp-GKR, zerocheck, statement, canonical inputs], then the
/// PCS stage's checks in order.
pub fn final_verifier_parts<C: CircuitContext>(c: &mut C, k: &Known, w: &[W]) -> Vec<W> {
    let mut t = Transcript::new(verifier::DOMAIN_V2);
    let mut inp = Inputs::new(w);
    let pre = verifier::preamble(c, &mut t, &k.shape, &mut inp);
    let g = verifier::logup(c, &mut t, &k.shape, &mut inp);
    let z = verifier::zerocheck(c, &mut t, &k.shape, &mut inp, &pre.public_values, &g, &k.constraints);
    let p = pcs::pcs(c, &mut t, &k.pcs, &mut inp, k.vk_preprocessed_commit, &pre.main_commitment, &z);
    let s = statement(c, &pre.public_values, &k.expect);
    let canonical = inp.all_canonical(c);
    let mut v = vec![g.ok, z.ok, s, canonical];
    v.extend(p);
    v
}
