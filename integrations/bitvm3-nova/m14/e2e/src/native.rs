//! Native side: SP1 types, the committed final proof, the wrap machine, a challenger that records
//! the bytes SP1's own code observes (for the parts of the transcript fixed by the pinned key and
//! shape), and the circuit's input encoding of a proof.
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{Cursor, Read},
    path::Path,
};

use anyhow::{ensure, Context, Result};
use bincode::Options;
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

/// The committed wrap proofs are about 1.1 MB. Keep untrusted parsing bounded independently of
/// any length advertised by the proof or claim manifest.
pub const MAX_PROOF_BYTES: usize = 8 * 1024 * 1024;

/// Bounded, fallible decoding of the fixed-integer, little-endian bincode format used by the
/// committed fixtures. This only parses a proof; an invalid proof of the supported shape must
/// remain available to the garbled verifier so that it can produce the reject label.
pub fn try_decode(bytes: &[u8]) -> Result<Proof> {
    ensure!(
        bytes.len() <= MAX_PROOF_BYTES,
        "proof exceeds the {MAX_PROOF_BYTES}-byte limit"
    );
    // bincode 1.3's slice `deserialize` replaces the configured limit with Infinite. Its reader
    // API preserves the limit, but does not check trailing bytes, hence the explicit cursor
    // check below. The byte limit also checks a string/byte-buffer length before allocation.
    // Proof vectors use serde's capped (1 MiB) preallocation and contain non-zero-sized encoded
    // elements; an enormous declared count therefore fails within this bounded input budget.
    // Catch malformed-value panics in upstream serde implementations at this IO boundary.
    std::panic::catch_unwind(|| -> Result<Proof> {
        let mut reader = Cursor::new(bytes);
        let proof: Proof = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_little_endian()
            .with_limit(bytes.len() as u64)
            .deserialize_from(&mut reader)
            .context("malformed v2 wrap proof")?;
        ensure!(
            reader.position() == bytes.len() as u64,
            "trailing bytes after v2 wrap proof"
        );
        let canonical = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_little_endian()
            .with_limit(MAX_PROOF_BYTES as u64)
            .serialize(&proof)
            .context("serialize parsed proof canonically")?;
        ensure!(canonical == bytes, "non-canonical v2 wrap proof encoding");
        Ok(proof)
    })
    .map_err(|_| anyhow::anyhow!("malformed v2 wrap proof: serde panicked"))?
}

/// Read at most the local proof limit plus one sentinel byte, including if a file grows after
/// its metadata was inspected. Pipes/devices are not accepted by the claim-file interface.
pub fn try_load(path: impl AsRef<Path>) -> Result<Proof> {
    let path = path.as_ref();
    // The common opener also uses O_NONBLOCK on Unix to avoid a FIFO replacement blocking
    // between the path metadata check and opening the file.
    let file = m14_claim::io::open_regular(path).with_context(|| format!("open proof {}", path.display()))?;
    let metadata = file.metadata().context("read proof metadata")?;
    ensure!(
        metadata.len() <= MAX_PROOF_BYTES as u64,
        "proof exceeds the {MAX_PROOF_BYTES}-byte limit"
    );
    let mut bytes = Vec::new();
    file.take(MAX_PROOF_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .context("read proof")?;
    try_decode(&bytes)
}

/// Convenience for trusted fixture-based tests. Claim commands use [`try_load`] instead.
pub fn load(path: &str) -> Proof {
    try_load(path).expect("trusted v2 wrap proof fixture")
}

/// Check every collection layout and shape constant consumed by `full::items` and the fixed
/// circuit against a trusted, pinned reference. Proof values are deliberately left unchecked:
/// a well-formed proof with incorrect arithmetic or Merkle data must reach garbled rejection.
/// Call this before extracting items or constructing a shape from untrusted proof metadata.
pub fn validate_proof_shape(reference: &Proof, proof: &Proof) -> Result<()> {
    validate_proof_shape_with_used_pv(reference, proof, num_pv(&machine()))
}

fn validate_proof_shape_with_used_pv(
    reference: &Proof,
    proof: &Proof,
    used_pv: usize,
) -> Result<()> {
    macro_rules! tensor_shape {
        ($reference:expr, $proof:expr, $name:literal) => {{
            let (expected, actual) = ($reference, $proof);
            ensure!(
                expected.has_valid_shape() && actual.has_valid_shape(),
                concat!($name, " storage length does not match its dimensions")
            );
            ensure!(
                expected.sizes() == actual.sizes(),
                concat!($name, " shape differs from reference")
            );
        }};
    }

    fn sumcheck_shape(
        reference: &slop_sumcheck::PartialSumcheckProof<EF>,
        proof: &slop_sumcheck::PartialSumcheckProof<EF>,
    ) -> Result<()> {
        ensure!(
            reference.univariate_polys.len() == proof.univariate_polys.len(),
            "sumcheck round count differs from reference"
        );
        ensure!(
            reference.point_and_eval.0.len() == proof.point_and_eval.0.len(),
            "sumcheck point length differs from reference"
        );
        for (expected, actual) in reference.univariate_polys.iter().zip(&proof.univariate_polys) {
            ensure!(
                expected.coefficients.len() == actual.coefficients.len(),
                "sumcheck polynomial degree differs from reference"
            );
        }
        Ok(())
    }

    ensure!(
        bincode::serialize(&reference.vk)? == bincode::serialize(&proof.vk)?,
        "wrap verification key differs from reference"
    );
    let (r, p) = (&reference.proof, &proof.proof);
    ensure!(
        r.public_values.len() == sp1_hypercube::PROOF_MAX_NUM_PVS,
        "reference public-value length is unsupported"
    );
    ensure!(
        p.public_values.len() == r.public_values.len(),
        "public-value length differs from reference"
    );
    ensure!(
        used_pv <= r.public_values.len(),
        "used public-value count exceeds proof public-value length"
    );
    ensure!(
        r.public_values[used_pv..].iter().all(|x| *x == F::zero()),
        "reference trailing public values are non-zero"
    );
    ensure!(
        p.public_values[used_pv..].iter().all(|x| *x == F::zero()),
        "unused trailing public values must be zero"
    );

    let (rg, pg) = (&r.logup_gkr_proof, &p.logup_gkr_proof);
    tensor_shape!(
        rg.circuit_output.numerator.guts(),
        pg.circuit_output.numerator.guts(),
        "LogUp numerator"
    );
    tensor_shape!(
        rg.circuit_output.denominator.guts(),
        pg.circuit_output.denominator.guts(),
        "LogUp denominator"
    );
    ensure!(
        rg.round_proofs.len() == pg.round_proofs.len(),
        "LogUp round count differs from reference"
    );
    for (expected, actual) in rg.round_proofs.iter().zip(&pg.round_proofs) {
        sumcheck_shape(&expected.sumcheck_proof, &actual.sumcheck_proof).context("LogUp sumcheck shape")?;
    }
    ensure!(
        rg.logup_evaluations.point.len() == pg.logup_evaluations.point.len(),
        "LogUp evaluation point length differs from reference"
    );
    let (ro, po) = (&rg.logup_evaluations.chip_openings, &pg.logup_evaluations.chip_openings);
    ensure!(ro.keys().eq(po.keys()), "LogUp chip names differ from reference");
    for (expected, actual) in ro.values().zip(po.values()) {
        tensor_shape!(
            expected.main_trace_evaluations.evaluations(),
            actual.main_trace_evaluations.evaluations(),
            "LogUp main trace"
        );
        match (
            &expected.preprocessed_trace_evaluations,
            &actual.preprocessed_trace_evaluations,
        ) {
            (None, None) => {}
            (Some(expected), Some(actual)) => {
                tensor_shape!(expected.evaluations(), actual.evaluations(), "LogUp preprocessed trace")
            }
            _ => anyhow::bail!("LogUp preprocessed trace presence differs from reference"),
        }
    }

    sumcheck_shape(&r.zerocheck_proof, &p.zerocheck_proof).context("zerocheck shape")?;
    let (ro, po) = (&r.opened_values.chips, &p.opened_values.chips);
    ensure!(ro.keys().eq(po.keys()), "opened chip names differ from reference");
    for (expected, actual) in ro.values().zip(po.values()) {
        ensure!(
            expected.degree.iter().eq(actual.degree.iter()),
            "chip degree differs from reference"
        );
        ensure!(
            expected.main.local.len() == actual.main.local.len(),
            "main opening width differs from reference"
        );
        ensure!(
            expected.preprocessed.local.len() == actual.preprocessed.local.len(),
            "preprocessed opening width differs from reference"
        );
    }

    let (re, pe) = (&r.evaluation_proof, &p.evaluation_proof);
    ensure!(
        re.log_m == pe.log_m && re.max_log_row_count == pe.max_log_row_count,
        "jagged logarithmic dimensions differ from reference"
    );
    ensure!(
        re.row_counts_and_column_counts
            .iter()
            .eq(pe.row_counts_and_column_counts.iter()),
        "jagged row/column counts differ from reference"
    );
    ensure!(
        re.merkle_tree_commitments.len() == pe.merkle_tree_commitments.len(),
        "jagged commitment count differs from reference"
    );
    sumcheck_shape(&re.sumcheck_proof, &pe.sumcheck_proof).context("jagged sumcheck shape")?;
    sumcheck_shape(
        &re.jagged_eval_proof.partial_sumcheck_proof,
        &pe.jagged_eval_proof.partial_sumcheck_proof,
    )
    .context("jagged evaluation shape")?;
    let (rb, pb) = (&re.pcs_proof.batch_evaluations, &pe.pcs_proof.batch_evaluations);
    ensure!(rb.len() == pb.len(), "batch evaluation count differs from reference");
    for (expected, actual) in rb.iter().zip(pb.iter()) {
        tensor_shape!(expected.evaluations(), actual.evaluations(), "batch evaluation");
    }

    let (rb, pb) = (&re.pcs_proof.basefold_proof, &pe.pcs_proof.basefold_proof);
    ensure!(
        rb.univariate_messages.len() == pb.univariate_messages.len(),
        "BaseFold message count differs from reference"
    );
    ensure!(
        rb.fri_commitments.len() == pb.fri_commitments.len(),
        "FRI commitment count differs from reference"
    );
    for (expected, actual) in [
        (
            &rb.component_polynomials_query_openings_and_proofs,
            &pb.component_polynomials_query_openings_and_proofs,
        ),
        (&rb.query_phase_openings_and_proofs, &pb.query_phase_openings_and_proofs),
    ] {
        ensure!(
            expected.len() == actual.len(),
            "Merkle opening count differs from reference"
        );
        for (expected, actual) in expected.iter().zip(actual) {
            ensure!(expected.proof.width > 0, "reference Merkle opening width is zero");
            ensure!(
                expected.proof.width == actual.proof.width,
                "Merkle opening width differs from reference"
            );
            ensure!(
                expected.proof.log_tensor_height == actual.proof.log_tensor_height,
                "Merkle opening depth differs from reference"
            );
            tensor_shape!(&expected.values, &actual.values, "Merkle opening value");
            tensor_shape!(&expected.proof.paths, &actual.proof.paths, "Merkle path");
        }
    }
    Ok(())
}

pub fn machine() -> Machine<F, WrapAir> {
    WrapAir::wrap_machine()
}

/// The shard's chips in SP1's order (as `verify_shard` builds them).
pub fn shard_chips(machine: &Machine<F, WrapAir>, proof: &Shard) -> BTreeSet<WrapChip> {
    machine
        .chips()
        .iter()
        .filter(|c| proof.opened_values.chips.contains_key(c.name()))
        .cloned()
        .collect()
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
    v.extend(
        g.circuit_output
            .numerator
            .guts()
            .as_slice()
            .iter()
            .map(|x| Item::Ext(ef(*x))),
    );
    v.extend(
        g.circuit_output
            .denominator
            .guts()
            .as_slice()
            .iter()
            .map(|x| Item::Ext(ef(*x))),
    );
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
        v.extend(
            o.main_trace_evaluations
                .evaluations()
                .as_slice()
                .iter()
                .map(|x| Item::Ext(ef(*x))),
        );
    }
    v
}

/// Degree bits per chip (the shape), in chip order.
pub fn degrees(proof: &Shard) -> BTreeMap<String, Vec<u32>> {
    proof
        .opened_values
        .chips
        .iter()
        .map(|(n, c)| (n.clone(), c.degree.iter().map(|x| fe(*x)).collect()))
        .collect()
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
    for o in b
        .component_polynomials_query_openings_and_proofs
        .iter()
        .chain(&b.query_phase_openings_and_proofs)
    {
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

#[cfg(test)]
mod proof_io_tests {
    use super::*;

    const A_PROOF: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../m13/fixtures/a-wrap-blake3-v2.bin");
    const M16_PROOF: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../m13/fixtures/m16-wrap-blake3-v2.bin");

    #[test]
    fn committed_fixtures_parse_and_have_the_pinned_shape() {
        let reference = try_load(FIXTURE_V2).unwrap();
        for path in [FIXTURE_V2, A_PROOF, M16_PROOF] {
            let proof = try_load(path).unwrap();
            validate_proof_shape(&reference, &proof).unwrap();
            // The explicit options preserve the historical bincode::serialize format.
            assert_eq!(bincode::serialize(&proof).unwrap(), std::fs::read(path).unwrap());
        }
    }

    #[test]
    fn decoder_rejects_truncated_trailing_and_oversized_data() {
        let bytes = std::fs::read(FIXTURE_V2).unwrap();
        for length in [0, 1, 8, bytes.len() / 2, bytes.len() - 1] {
            assert!(try_decode(&bytes[..length]).is_err(), "accepted truncation at {length}");
        }
        let mut extra = bytes;
        extra.push(0);
        assert!(try_decode(&extra).err().unwrap().to_string().contains("trailing"));
        assert!(try_decode(&vec![0; MAX_PROOF_BYTES + 1]).is_err());
    }

    #[test]
    fn enormous_declared_vector_length_is_a_bounded_error() {
        let proof = try_load(FIXTURE_V2).unwrap();
        let mut bytes = bincode::serialize(&proof).unwrap();
        // The first field after the serialized key is the public-values Vec length.
        let at = bincode::serialized_size(&proof.vk).unwrap() as usize;
        bytes[at..at + 8].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(try_decode(&bytes).is_err());
    }

    #[test]
    fn shape_guard_refuses_metadata_that_would_break_item_extraction() {
        let reference = try_load(FIXTURE_V2).unwrap();
        let mutations: &[fn(&mut Proof)] = &[
            |p| p.proof.public_values.clear(),
            |p| {
                p.proof.logup_gkr_proof.round_proofs.pop();
            },
            |p| {
                p.proof.zerocheck_proof.univariate_polys[0].coefficients.pop();
            },
            |p| {
                p.proof.opened_values.chips.pop_first();
            },
            |p| p.proof.evaluation_proof.log_m = usize::MAX,
            |p| {
                p.proof.evaluation_proof.pcs_proof.basefold_proof.fri_commitments.pop();
            },
            |p| {
                p.proof
                    .evaluation_proof
                    .pcs_proof
                    .basefold_proof
                    .component_polynomials_query_openings_and_proofs[0]
                    .proof
                    .width = 0
            },
            |p| {
                p.proof
                    .evaluation_proof
                    .pcs_proof
                    .basefold_proof
                    .query_phase_openings_and_proofs[0]
                    .proof
                    .log_tensor_height = usize::MAX
            },
        ];
        for (index, mutate) in mutations.iter().enumerate() {
            let mut proof = reference.clone();
            mutate(&mut proof);
            assert!(
                validate_proof_shape(&reference, &proof).is_err(),
                "accepted shape mutation {index}"
            );
        }
    }

    #[test]
    fn shape_guard_covers_all_wrap_public_values_and_refuses_nonzero_unused_slots() {
        let reference = try_load(FIXTURE_V2).unwrap();
        let used = num_pv(&machine());
        assert_eq!(used, sp1_hypercube::PROOF_MAX_NUM_PVS);

        let reduced_used = used - 1;
        let mut baseline = reference.clone();
        baseline.proof.public_values[reduced_used] = F::zero();
        validate_proof_shape_with_used_pv(&baseline, &baseline, reduced_used).unwrap();

        let mut mutated = baseline.clone();
        mutated.proof.public_values[reduced_used] = F::one();
        let err = validate_proof_shape_with_used_pv(&baseline, &mutated, reduced_used).unwrap_err();
        assert!(
            err.to_string().contains("unused trailing public values"),
            "{err}"
        );
    }

    #[test]
    fn same_shape_invalid_values_are_left_for_garbled_rejection() {
        let reference = try_load(FIXTURE_V2).unwrap();
        let mut proof = reference.clone();
        proof.proof.public_values[0] += F::one();
        proof.proof.zerocheck_proof.univariate_polys[0].coefficients[0] += EF::one();
        validate_proof_shape(&reference, &proof).unwrap();
        let decoded = try_decode(&bincode::serialize(&proof).unwrap()).unwrap();
        validate_proof_shape(&reference, &decoded).unwrap();
    }

    #[test]
    fn shape_guard_and_decoder_refuse_inconsistent_tensor_storage() {
        let reference = try_load(FIXTURE_V2).unwrap();
        let mutations: &[fn(&mut Proof)] = &[
            |p| {
                p.proof
                    .logup_gkr_proof
                    .circuit_output
                    .numerator
                    .guts_mut()
                    .storage
                    .clear()
            },
            |p| {
                p.proof
                    .evaluation_proof
                    .pcs_proof
                    .basefold_proof
                    .component_polynomials_query_openings_and_proofs[0]
                    .values
                    .storage
                    .clear()
            },
            |p| {
                p.proof
                    .evaluation_proof
                    .pcs_proof
                    .basefold_proof
                    .query_phase_openings_and_proofs[0]
                    .proof
                    .paths
                    .storage
                    .clear()
            },
        ];
        for (index, mutate) in mutations.iter().enumerate() {
            let mut proof = reference.clone();
            mutate(&mut proof);
            assert!(
                validate_proof_shape(&reference, &proof).is_err(),
                "accepted tensor storage mutation {index}"
            );
            assert!(
                try_decode(&bincode::serialize(&proof).unwrap()).is_err(),
                "decoded malformed tensor {index}"
            );
        }
    }

    #[test]
    fn file_loader_reports_missing_truncated_and_oversized_files() {
        struct TempFile(std::path::PathBuf);
        impl Drop for TempFile {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(&self.0);
            }
        }
        let path = std::env::temp_dir().join(format!(
            "m14-proof-{}-{}.bin",
            std::process::id(),
            rand::random::<u64>()
        ));
        let temp = TempFile(path);
        assert!(try_load(&temp.0).is_err());
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp.0)
            .unwrap();
        std::io::Write::write_all(&mut file, &[0; 8]).unwrap();
        assert!(try_load(&temp.0).is_err());
        file.set_len(MAX_PROOF_BYTES as u64 + 1).unwrap();
        assert!(try_load(&temp.0).is_err());
        assert!(try_load(std::env::temp_dir()).is_err());
    }
}
