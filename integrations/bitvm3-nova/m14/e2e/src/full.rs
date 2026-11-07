//! The complete final verifier as one circuit: `m13_verify::verify_final` with transcript v2.
//!
//! - The wrap key is a circuit constant (the pinned key): its transcript bytes and preprocessed
//!   commitment are built in, so a proof under another key cannot verify.
//! - The STARK: preamble, LogUp-GKR, zerocheck, jagged PCS with stacked BaseFold.
//! - The statement: exit code 0, complete, and the guest key digest, recursion key root and
//!   committed-values digest equal to the pinned ones.
//!
//! Output: one wire, 1 iff the proof verifies and states the pinned statement.
use std::borrow::Borrow;

use garbled_snark_verifier::CircuitContext;
use m12_gates::W;
use m13_verify::FinalStatement;
use m14_circuit::{
    field::{self as f, Fe},
    hash::Transcript,
};

use slop_uni_stark::SymbolicExpression;
use sp1_recursion_executor::RecursionPublicValues;

use crate::{
    native::{self, Item, Proof, F},
    pcs::{self, PcsShape},
    verifier::{self, Inputs, Shape},
};

/// Everything fixed when the circuit is built: the pinned key and proof shape, the AIR
/// constraints, and the pinned statement.
pub struct Known {
    pub shape: Shape,
    pub pcs: PcsShape,
    pub constraints: Vec<Vec<SymbolicExpression<F>>>,
    pub vk_preprocessed_commit: [u8; 32],
    pub expect: FinalStatement,
}

impl Known {
    /// From the pinned proof (key and shape) and the pinned statement.
    pub fn new(reference: &Proof, expect: &FinalStatement) -> Self {
        assert_eq!(m13_verify::vk_sha256(&reference.vk), expect.wrap_vk_sha256, "reference proof is not under the pinned key");
        let machine = native::machine();
        let shape = Shape::new(&machine, &reference.vk, &reference.proof);
        let constraints = shape.chips.iter().map(verifier::chip_constraints).collect();
        Known {
            shape,
            pcs: PcsShape::new(&reference.proof),
            constraints,
            vk_preprocessed_commit: reference.vk.preprocessed_commit.into(),
            expect: expect.clone(),
        }
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

fn hex_felts(h: &str) -> Vec<u32> {
    let b = hex_bytes(h);
    b.chunks(4).map(|c| u32::from_le_bytes(c.try_into().unwrap())).collect()
}
fn hex_bytes(h: &str) -> Vec<u8> {
    (0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap()).collect()
}

/// The statement checks of `verify_final` on the public values.
pub fn statement<C: CircuitContext>(c: &mut C, pv: &[Fe], e: &FinalStatement) -> W {
    let o = pv_offsets();
    let mut oks = Vec::new();
    let mut is = |c: &mut C, at: u32, v: u32| {
        let w = f::eq(c, &pv[at as usize], &Fe::constant(v));
        oks.push(w);
    };
    is(c, o.exit_code, 0);
    is(c, o.is_complete, 1);
    assert_eq!(e.exit_code, 0);
    assert_eq!(e.is_complete, 1);
    for (at, v) in o.sp1_vk_digest.iter().zip(hex_felts(&e.program_vk_digest)) {
        is(c, *at, v);
    }
    for (at, v) in o.vk_root.iter().zip(hex_felts(&e.recursion_vk_root)) {
        is(c, *at, v);
    }
    let digest = hex_bytes(&e.committed_values_sha256);
    for (at, v) in o.committed_value_digest.iter().flatten().zip(digest) {
        is(c, *at, v as u32);
    }
    f::and_all(c, &oks)
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
