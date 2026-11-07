//! Stage-by-stage checks of the circuit verifier on the committed v2 final proof (c4) against
//! SP1's own verifier code.
use garbled_snark_verifier::{
    WireId,
    circuit::{CircuitBuilder, CircuitInput, CircuitMode, EncodeInput, ExecuteMode, StreamingResult},
};
use m14_circuit::hash::Transcript;
use m14_e2e::{
    native::{self, Item, F, GC},
    verifier::{self, Inputs, Shape},
};
use slop_algebra::AbstractField;
use slop_challenger::{CanObserve, IopCtx, VariableLengthChallenger};
use sp1_hypercube::{air::MachineAir, LogUpGkrVerifier};

const CAP: usize = 1 << 24;

struct Plain(Vec<bool>);
impl CircuitInput for Plain {
    type WireRepr = Vec<WireId>;
    fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
        (0..self.0.len()).map(|_| issue()).collect()
    }
    fn collect_wire_ids(w: &Self::WireRepr) -> Vec<WireId> {
        w.clone()
    }
}
impl EncodeInput<ExecuteMode> for Plain {
    fn encode(&self, w: &Self::WireRepr, mode: &mut ExecuteMode) {
        for (id, v) in w.iter().zip(&self.0) {
            mode.feed_wire(*id, *v);
        }
    }
}

/// Observed bytes of the recorded native verification of the c4 v2 proof.
fn native_observed() -> Vec<u8> {
    let raw = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/../circuit/fixtures/c4-v2-transcript.bin")).unwrap();
    let (mut at, mut out) = (0, Vec::new());
    while at < raw.len() {
        let n = u32::from_le_bytes(raw[at + 1..at + 5].try_into().unwrap()) as usize;
        if raw[at] == 0 {
            out.extend_from_slice(&raw[at + 5..at + 5 + n]);
        }
        at += 5 + n;
    }
    out
}

fn bytes_of(bits: &[bool]) -> Vec<u8> {
    bits.chunks(8).map(|c| c.iter().enumerate().fold(0u8, |a, (i, &b)| a | ((b as u8) << i))).collect()
}

fn stage_logup(items: &[Item], shape: &Shape) -> (bool, Vec<u8>, usize) {
    let input = native::bits(items);
    let n = input.len();
    let r: StreamingResult<ExecuteMode, _, Vec<bool>> = CircuitBuilder::streaming_execute(Plain(input), CAP, |c, w| {
        let mut t = Transcript::new(verifier::DOMAIN_V2);
        let mut inp = Inputs::new(w);
        verifier::preamble(c, &mut t, shape, &mut inp);
        let out = verifier::logup(c, &mut t, shape, &mut inp);
        assert_eq!(inp.used(), n, "inputs consumed");
        let mut o = vec![out.ok];
        o.extend(t.log.iter().copied());
        o
    });
    let gates = r.gate_count.nonfree_gate_count() as usize;
    (r.output_value[0], bytes_of(&r.output_value[1..]), gates)
}

#[test]
fn logup_gkr_matches_sp1_on_the_real_proof() {
    let proof = native::load(native::FIXTURE_V2);
    let machine = native::machine();
    let shard = &proof.proof;

    // SP1 natively: the same preamble, then its LogUp-GKR verifier.
    let mut ch = GC::default_challenger();
    proof.vk.observe_into(&mut ch);
    <m13_verify::ctx::Blake3ChallengerV2 as VariableLengthChallenger<F, m13_verify::ctx::Digest>>::observe_constant_length_extension_slice::<F>(&mut ch, &shard.public_values);
    ch.observe(shard.main_commitment);
    ch.observe(F::from_canonical_usize(shard.opened_values.chips.len()));
    for (name, cv) in shard.opened_values.chips.iter() {
        let acc = cv.degree.iter().fold(F::zero(), |acc, &x| x + F::two() * acc);
        ch.observe(acc);
        ch.observe(F::from_canonical_usize(name.len()));
        name.as_bytes().iter().for_each(|b| ch.observe(F::from_canonical_u8(*b)));
    }
    let chips = native::shard_chips(&machine, shard);
    let degrees = shard.opened_values.chips.iter().map(|(n, c)| (n.clone(), c.degree.clone())).collect();
    LogUpGkrVerifier::<GC, m13_verify::Blake3WrapSCV2>::verify_logup_gkr(
        &chips,
        &degrees,
        sp1_verifier::compressed::RECURSION_MAX_LOG_ROW_COUNT,
        &shard.logup_gkr_proof,
        &shard.public_values,
        &mut ch,
    )
    .expect("SP1 accepts the real proof's LogUp-GKR");

    // The circuit.
    let shape = Shape::new(&machine, &proof.vk, shard);
    eprintln!(
        "chips {} interactions {} niv {} beta_seed_dim {} public values {}",
        shape.chips.len(),
        shape.num_interactions,
        shape.niv,
        shape.beta_seed_dim,
        shape.num_pv
    );
    assert!(chips.iter().map(|c| c.name()).eq(shape.chips.iter().map(|c| c.name())));
    let items = native::items_logup(&machine, shard);
    let (ok, observed, gates) = stage_logup(&items, &shape);
    eprintln!("M14-E2E logup stage: {} input items, {gates} gates", items.len());
    let want = native_observed();
    assert_eq!(observed[..], want[..observed.len()], "circuit observations differ from SP1's transcript");
    assert!(ok, "circuit rejects the real LogUp-GKR");

    // A changed round message is rejected.
    let mut bad = items.clone();
    let k = items.len() - 40;
    if let Item::Ext(v) = &mut bad[k] {
        v[0] = (v[0] + 1) % 0x7f00_0001;
    } else {
        panic!("item {k} is not an extension element");
    }
    assert!(!stage_logup(&bad, &shape).0, "changed opening accepted");
}

type SV = sp1_hypercube::ShardVerifier<GC, m13_verify::Blake3WrapSCV2>;

fn ef_of(v: [u32; 4]) -> native::EF {
    use slop_algebra::AbstractExtensionField;
    native::EF::from_base_slice(&v.map(F::from_canonical_u32))
}

/// Each chip's constraints evaluated by the circuit equal SP1's `eval_constraints` and
/// `compute_padded_row_adjustment` on the real proof's openings and public values.
#[test]
fn constraint_evaluation_matches_sp1_per_chip() {
    let proof = native::load(native::FIXTURE_V2);
    let machine = native::machine();
    let shard = &proof.proof;
    let shape = Shape::new(&machine, &proof.vk, shard);
    let alpha = [123_456_789u32, 987_654_321, 5, 7];
    let num_pv = shape.num_pv;
    for (chip, (name, opening)) in shape.chips.iter().zip(shard.opened_values.chips.iter()) {
        assert_eq!(chip.name(), name.as_str());
        let want = native::ef(SV::eval_constraints(chip, opening, ef_of(alpha), &shard.public_values));
        let want_pad = native::ef(SV::compute_padded_row_adjustment(chip, ef_of(alpha), &shard.public_values));
        let constraints = verifier::chip_constraints(chip);
        let mut items = vec![Item::Ext(alpha)];
        items.extend(shard.public_values[..num_pv].iter().map(|x| Item::Fe(native::fe(*x))));
        items.extend(opening.preprocessed.local.iter().map(|x| Item::Ext(native::ef(*x))));
        items.extend(opening.main.local.iter().map(|x| Item::Ext(native::ef(*x))));
        let (pw, w) = (opening.preprocessed.local.len(), opening.main.local.len());
        let r: StreamingResult<ExecuteMode, _, Vec<bool>> = CircuitBuilder::streaming_execute(Plain(native::bits(&items)), CAP, |c, wires| {
            let mut inp = Inputs::new(wires);
            let a = inp.ext();
            let mut pv: Vec<m14_circuit::field::Fe> = (0..num_pv).map(|_| inp.fe()).collect();
            pv.resize(sp1_hypercube::PROOF_MAX_NUM_PVS, m14_circuit::field::Fe::zero());
            let prep: Vec<_> = (0..pw).map(|_| inp.ext()).collect();
            let main: Vec<_> = (0..w).map(|_| inp.ext()).collect();
            let got = verifier::eval_constraints(c, &constraints, &prep, &main, &a, &pv);
            let zp = vec![m14_circuit::ext::Ext::zero(); pw];
            let zm = vec![m14_circuit::ext::Ext::zero(); w];
            let pad = verifier::eval_constraints(c, &constraints, &zp, &zm, &a, &pv);
            got.0.iter().chain(pad.0.iter()).flat_map(|x| x.0.clone()).collect()
        });
        let vals: Vec<u32> = r.output_value.chunks(31).map(|b| b.iter().enumerate().fold(0u32, |a, (i, &x)| a | ((x as u32) << i))).collect();
        eprintln!("chip {name}: {} constraints, {} gates", constraints.len(), r.gate_count.nonfree_gate_count());
        assert_eq!(vals[..4], want, "chip {name}: constraint evaluation");
        assert_eq!(vals[4..], want_pad, "chip {name}: padded-row adjustment");
    }
}

/// Preamble, LogUp-GKR and zerocheck on the real proof: SP1 accepts natively; the circuit accepts,
/// observes exactly SP1's transcript bytes, and rejects a changed opening.
#[test]
fn zerocheck_matches_sp1_on_the_real_proof() {
    let proof = native::load(native::FIXTURE_V2);
    let machine = native::machine();
    let shard = &proof.proof;
    let shape = Shape::new(&machine, &proof.vk, shard);
    let constraints: Vec<_> = shape.chips.iter().map(verifier::chip_constraints).collect();

    // SP1 natively up to the end of the zerocheck.
    let sv = m13_verify::wrap_verifier_v2();
    let mut ch = GC::default_challenger();
    proof.vk.observe_into(&mut ch);
    <m13_verify::ctx::Blake3ChallengerV2 as VariableLengthChallenger<F, m13_verify::ctx::Digest>>::observe_constant_length_extension_slice::<F>(&mut ch, &shard.public_values);
    ch.observe(shard.main_commitment);
    ch.observe(F::from_canonical_usize(shard.opened_values.chips.len()));
    for (name, cv) in shard.opened_values.chips.iter() {
        let acc = cv.degree.iter().fold(F::zero(), |acc, &x| x + F::two() * acc);
        ch.observe(acc);
        ch.observe(F::from_canonical_usize(name.len()));
        name.as_bytes().iter().for_each(|b| ch.observe(F::from_canonical_u8(*b)));
    }
    let chips = native::shard_chips(&machine, shard);
    let degrees = shard.opened_values.chips.iter().map(|(n, c)| (n.clone(), c.degree.clone())).collect();
    LogUpGkrVerifier::<GC, m13_verify::Blake3WrapSCV2>::verify_logup_gkr(&chips, &degrees, shape.max_log_row_count, &shard.logup_gkr_proof, &shard.public_values, &mut ch).unwrap();
    sv.shard_verifier()
        .verify_zerocheck(&chips, &shard.opened_values, &shard.logup_gkr_proof.logup_evaluations, shard, &shard.public_values, &mut ch)
        .expect("SP1 accepts the real zerocheck");

    let run = |items: &[Item]| -> (bool, bool, Vec<u8>, u64) {
        let input = native::bits(items);
        let n = input.len();
        let r: StreamingResult<ExecuteMode, _, Vec<bool>> = CircuitBuilder::streaming_execute(Plain(input), CAP, |c, w| {
            let mut t = Transcript::new(verifier::DOMAIN_V2);
            let mut inp = Inputs::new(w);
            let pre = verifier::preamble(c, &mut t, &shape, &mut inp);
            let g = verifier::logup(c, &mut t, &shape, &mut inp);
            let z = verifier::zerocheck(c, &mut t, &shape, &mut inp, &pre.public_values, &g, &constraints);
            assert_eq!(inp.used(), n, "inputs consumed");
            let mut o = vec![g.ok, z.ok];
            o.extend(t.log.iter().copied());
            o
        });
        (r.output_value[0], r.output_value[1], bytes_of(&r.output_value[2..]), r.gate_count.nonfree_gate_count())
    };
    let mut items = native::items_logup(&machine, shard);
    let n_logup = items.len();
    items.extend(native::items_zerocheck(shard));
    let (ok_g, ok_z, observed, gates) = run(&items);
    eprintln!("M14-E2E preamble+logup+zerocheck: {} input items, {gates} gates", items.len());
    let want = native_observed();
    assert_eq!(observed[..], want[..observed.len()], "circuit observations differ from SP1's transcript");
    assert!(ok_g && ok_z, "circuit rejects the real proof (logup {ok_g}, zerocheck {ok_z})");

    let mut bad = items.clone();
    let k = n_logup + 200;
    if let Item::Ext(v) = &mut bad[k] {
        v[1] = (v[1] + 1) % 0x7f00_0001;
    }
    let (_, ok_bad, _, _) = run(&bad);
    assert!(!ok_bad, "changed zerocheck input accepted");
}

#[test]
#[ignore]
fn print_pcs_shape() {
    let proof = native::load(native::FIXTURE_V2);
    let ep = &proof.proof.evaluation_proof;
    eprintln!("row_counts_and_column_counts {:?}", ep.row_counts_and_column_counts);
    eprintln!("log_m {} max_log_row_count {}", ep.log_m, ep.max_log_row_count);
    eprintln!("jagged sumcheck rounds {} deg {}", ep.sumcheck_proof.univariate_polys.len(), ep.sumcheck_proof.univariate_polys[0].coefficients.len() - 1);
    let je = &ep.jagged_eval_proof.partial_sumcheck_proof;
    eprintln!("jagged eval sumcheck rounds {} deg {}", je.univariate_polys.len(), je.univariate_polys[0].coefficients.len() - 1);
    let pcs = serde_json::to_value(&ep.pcs_proof).unwrap();
    let keys: Vec<String> = pcs.as_object().map(|o| o.keys().cloned().collect()).unwrap_or_default();
    eprintln!("pcs proof fields {keys:?}");
    eprintln!("pcs proof json bytes {}", serde_json::to_string(&ep.pcs_proof).unwrap().len());
}

#[test]
#[ignore]
fn print_basefold_shape() {
    let proof = native::load(native::FIXTURE_V2);
    let ep = &proof.proof.evaluation_proof;
    let sv = m13_verify::wrap_verifier_v2();
    let bf = &sv.shard_verifier().jagged_pcs_verifier.pcs_verifier.basefold_verifier;
    eprintln!("fri log_blowup {} queries {} pow {}", bf.fri_config.log_blowup(), bf.fri_config.num_queries, bf.fri_config.proof_of_work_bits);
    let p = &ep.pcs_proof;
    eprintln!("batch evaluation lens {:?}", p.batch_evaluations.iter().map(|r| r.num_evaluations()).collect::<Vec<_>>());
    let b = &p.basefold_proof;
    eprintln!("univariate messages {} fri commitments {}", b.univariate_messages.len(), b.fri_commitments.len());
    for o in &b.component_polynomials_query_openings_and_proofs {
        eprintln!("component values {:?} paths {:?} log_h {} width {}", o.values.sizes(), o.proof.paths.sizes(), o.proof.log_tensor_height, o.proof.width);
    }
    let q0 = &b.query_phase_openings_and_proofs[0];
    eprintln!("query phase rounds {} first: values {:?} paths {:?} log_h {} width {}", b.query_phase_openings_and_proofs.len(), q0.values.sizes(), q0.proof.paths.sizes(), q0.proof.log_tensor_height, q0.proof.width);
}
