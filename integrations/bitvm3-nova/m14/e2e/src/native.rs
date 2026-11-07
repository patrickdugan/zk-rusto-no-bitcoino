//! Native side: SP1 types, the committed final proof, the wrap machine, a challenger that records
//! the bytes SP1's own code observes (for the parts of the transcript fixed by the pinned key and
//! shape), and the circuit's input encoding of a proof.
use std::collections::{BTreeMap, BTreeSet};

use m13_verify::{ctx, Blake3KoalaBearV2, Blake3WrapProofV2, WrapAir};
use serde::{Deserialize, Serialize};
use slop_algebra::{AbstractExtensionField, AbstractField, PrimeField32};
use slop_challenger::{CanObserve, CanSample, CanSampleBits, FieldChallenger, GrindingChallenger, IopCtx};
use slop_symmetric::Hash;
use sp1_hypercube::{air::MachineAir, Chip, Machine, MachineVerifyingKey, SP1PcsProof, ShardProof};
use sp1_primitives::{SP1ExtensionField, SP1Field};

pub type GC = Blake3KoalaBearV2;
pub type F = SP1Field;
pub type EF = SP1ExtensionField;
pub type Proof = Blake3WrapProofV2;
pub type Shard = ShardProof<GC, SP1PcsProof<GC>>;
pub type WrapChip = Chip<F, WrapAir>;

pub const FIXTURE_V2: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../m13/fixtures/c4-wrap-blake3-v2.bin");

pub fn load(path: &str) -> Proof {
    bincode::deserialize(&std::fs::read(path).expect("proof file")).expect("v2 wrap proof")
}

pub fn machine() -> Machine<F, WrapAir> {
    WrapAir::wrap_machine()
}

/// The shard's chips in SP1's order (as `verify_shard` builds them).
pub fn shard_chips(machine: &Machine<F, WrapAir>, proof: &Shard) -> BTreeSet<WrapChip> {
    machine.chips().iter().filter(|c| proof.opened_values.chips.contains_key(c.name())).cloned().collect()
}

pub fn fe(x: F) -> u32 {
    x.as_canonical_u32()
}
pub fn ef(x: EF) -> [u32; 4] {
    let s: &[F] = <EF as AbstractExtensionField<F>>::as_base_slice(&x);
    [fe(s[0]), fe(s[1]), fe(s[2]), fe(s[3])]
}

// ------------------------------------------------------------------ recording challenger
/// Records every byte SP1 code observes (canonical 4-byte LE field elements, digest bytes);
/// sampling is not allowed.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Recorder {
    pub bytes: Vec<u8>,
}
impl CanObserve<F> for Recorder {
    fn observe(&mut self, v: F) {
        self.bytes.extend(v.as_canonical_u32().to_le_bytes());
    }
}
impl<const N: usize> CanObserve<Hash<F, u8, N>> for Recorder {
    fn observe(&mut self, v: Hash<F, u8, N>) {
        self.bytes.extend(v);
    }
}
impl CanSample<F> for Recorder {
    fn sample(&mut self) -> F {
        unreachable!("the recorder only observes")
    }
}
impl CanSampleBits<usize> for Recorder {
    fn sample_bits(&mut self, _: usize) -> usize {
        unreachable!("the recorder only observes")
    }
}
impl GrindingChallenger for Recorder {
    type Witness = F;
    fn grind(&mut self, _: usize) -> F {
        unreachable!("the recorder only observes")
    }
}
impl FieldChallenger<F> for Recorder {}

/// `Blake3KoalaBearV2` with the recording challenger, to run SP1's observe code.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq, std::hash::Hash)]
pub struct RecCtx;
impl IopCtx for RecCtx {
    type F = F;
    type EF = EF;
    type Digest = ctx::Digest;
    type Challenger = Recorder;
    type Hasher = ctx::LeafHasher;
    type Compressor = ctx::NodeCompressor;
    fn default_hasher_and_compressor() -> (Self::Hasher, Self::Compressor) {
        (ctx::LeafHasher, ctx::NodeCompressor)
    }
    fn default_challenger() -> Recorder {
        Recorder::default()
    }
}

/// Bytes `vk.observe_into` observes, by SP1's own code.
pub fn vk_bytes(vk: &MachineVerifyingKey<GC>) -> Vec<u8> {
    let rec_vk = MachineVerifyingKey::<RecCtx> {
        pc_start: vk.pc_start,
        initial_global_cumulative_sum: vk.initial_global_cumulative_sum,
        preprocessed_commit: vk.preprocessed_commit,
        untrusted_config: vk.untrusted_config.clone(),
    };
    let mut r = Recorder::default();
    rec_vk.observe_into(&mut r);
    r.bytes
}

/// Bytes `verify_shard` observes after the main commitment: the chip count, then per chip its
/// height, name length and name bytes (all fixed by the shape).
pub fn shape_bytes(proof: &Shard) -> Vec<u8> {
    let mut r = Recorder::default();
    r.observe(F::from_canonical_usize(proof.opened_values.chips.len()));
    for (name, chip_values) in proof.opened_values.chips.iter() {
        let acc = chip_values.degree.iter().fold(F::zero(), |acc, &x| x + F::two() * acc);
        r.observe(acc);
        r.observe(F::from_canonical_usize(name.len()));
        for byte in name.as_bytes() {
            r.observe(F::from_canonical_u8(*byte));
        }
    }
    r.bytes
}

// ------------------------------------------------------------------ input encoding
/// A circuit input value: a base element, an extension element or a digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Item {
    Fe(u32),
    Ext([u32; 4]),
    Digest([u8; 32]),
}

/// Bits of the items, in order (31 per base element, 124 per extension element, 256 per digest).
pub fn bits(items: &[Item]) -> Vec<bool> {
    let fbits = |v: u32| (0..31).map(move |i| (v >> i) & 1 == 1);
    items
        .iter()
        .flat_map(|it| -> Vec<bool> {
            match it {
                Item::Fe(v) => fbits(*v).collect(),
                Item::Ext(v) => v.iter().flat_map(|x| fbits(*x)).collect(),
                Item::Digest(d) => d.iter().flat_map(|b| (0..8).map(move |i| (b >> i) & 1 == 1)).collect(),
            }
        })
        .collect()
}

/// Number of public values the wrap machine uses; the rest must be zero (not inputs).
pub fn num_pv(machine: &Machine<F, WrapAir>) -> usize {
    machine.num_pv_elts()
}

/// Items of the preamble and LogUp-GKR stages of `proof`, in the circuit's consumption order.
pub fn items_logup(machine: &Machine<F, WrapAir>, proof: &Shard) -> Vec<Item> {
    let mut v = Vec::new();
    v.extend(proof.public_values[..num_pv(machine)].iter().map(|x| Item::Fe(fe(*x))));
    let d: [u8; 32] = proof.main_commitment.into();
    v.push(Item::Digest(d));
    let g = &proof.logup_gkr_proof;
    v.push(Item::Fe(fe(g.witness)));
    v.extend(g.circuit_output.numerator.guts().as_slice().iter().map(|x| Item::Ext(ef(*x))));
    v.extend(g.circuit_output.denominator.guts().as_slice().iter().map(|x| Item::Ext(ef(*x))));
    for r in &g.round_proofs {
        for p in &r.sumcheck_proof.univariate_polys {
            v.extend(p.coefficients.iter().map(|x| Item::Ext(ef(*x))));
        }
        v.extend([r.numerator_0, r.numerator_1, r.denominator_0, r.denominator_1].map(|x| Item::Ext(ef(x))));
    }
    for o in g.logup_evaluations.chip_openings.values() {
        if let Some(p) = o.preprocessed_trace_evaluations.as_ref() {
            v.extend(p.evaluations().as_slice().iter().map(|x| Item::Ext(ef(*x))));
        }
        v.extend(o.main_trace_evaluations.evaluations().as_slice().iter().map(|x| Item::Ext(ef(*x))));
    }
    v
}

/// Degree bits per chip (the shape), in chip order.
pub fn degrees(proof: &Shard) -> BTreeMap<String, Vec<u32>> {
    proof.opened_values.chips.iter().map(|(n, c)| (n.clone(), c.degree.iter().map(|x| fe(*x)).collect())).collect()
}

/// Items of the zerocheck stage: the sumcheck polynomials, then per chip the opened preprocessed
/// and main values.
pub fn items_zerocheck(proof: &Shard) -> Vec<Item> {
    let mut v = Vec::new();
    for p in &proof.zerocheck_proof.univariate_polys {
        v.extend(p.coefficients.iter().map(|x| Item::Ext(ef(*x))));
    }
    for o in proof.opened_values.chips.values() {
        v.extend(o.preprocessed.local.iter().map(|x| Item::Ext(ef(*x))));
        v.extend(o.main.local.iter().map(|x| Item::Ext(ef(*x))));
    }
    v
}

/// Items of the PCS stage (jagged PCS, stacked PCS, BaseFold), in the circuit's order.
pub fn items_pcs(proof: &Shard) -> Vec<Item> {
    let mut v = Vec::new();
    let ep = &proof.evaluation_proof;
    for d in ep.merkle_tree_commitments.iter() {
        let d: [u8; 32] = (*d).into();
        v.push(Item::Digest(d));
    }
    for p in &ep.sumcheck_proof.univariate_polys {
        v.extend(p.coefficients.iter().map(|x| Item::Ext(ef(*x))));
    }
    let je = &ep.jagged_eval_proof.partial_sumcheck_proof;
    v.push(Item::Ext(ef(je.claimed_sum)));
    for p in &je.univariate_polys {
        v.extend(p.coefficients.iter().map(|x| Item::Ext(ef(*x))));
    }
    v.push(Item::Ext(ef(ep.expected_eval)));
    let pcs = &ep.pcs_proof;
    for r in pcs.batch_evaluations.iter() {
        v.extend(r.iter().map(|x| Item::Ext(ef(*x))));
    }
    let b = &pcs.basefold_proof;
    v.push(Item::Fe(fe(b.batch_grinding_witness)));
    for (m, d) in b.univariate_messages.iter().zip(&b.fri_commitments) {
        v.extend(m.iter().map(|x| Item::Ext(ef(*x))));
        let d: [u8; 32] = (*d).into();
        v.push(Item::Digest(d));
    }
    v.push(Item::Ext(ef(b.final_poly)));
    v.push(Item::Fe(fe(b.pow_witness)));
    for o in b.component_polynomials_query_openings_and_proofs.iter().chain(&b.query_phase_openings_and_proofs) {
        let root: [u8; 32] = o.proof.merkle_root.into();
        v.push(Item::Digest(root));
        let width = o.proof.width;
        let vals = o.values.as_slice();
        let paths = o.proof.paths.as_slice();
        let depth = o.proof.log_tensor_height;
        for q in 0..vals.len() / width {
            v.extend(vals[q * width..(q + 1) * width].iter().map(|x| Item::Fe(fe(*x))));
            for d in &paths[q * depth..(q + 1) * depth] {
                let d: [u8; 32] = (*d).into();
                v.push(Item::Digest(d));
            }
        }
    }
    v
}

/// The leaf hash (`ctx::LeafHasher`) of constant field elements.
pub fn leaf_hash_const(xs: &[usize]) -> [u8; 32] {
    use slop_symmetric::CryptographicHasher;
    CryptographicHasher::<F, [u8; 32]>::hash_iter(&ctx::LeafHasher, xs.iter().map(|x| F::from_canonical_usize(*x)))
}
pub fn two_adic_generator(bits: usize) -> u32 {
    use slop_algebra::TwoAdicField;
    fe(F::two_adic_generator(bits))
}

pub fn inverse(x: u32) -> u32 {
    use slop_algebra::Field;
    fe(F::from_canonical_u32(x).inverse())
}
