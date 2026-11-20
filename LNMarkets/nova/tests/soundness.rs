//! Assignment-level regression tests for the settlement relation.
//!
//! Nova's ordinary TestConstraintSystem exposes honest witness evaluation only.
//! This recorder allows an adversarial prover to replace variables *after*
//! synthesis, including all intermediate Poseidon witnesses for a different
//! commitment, while evaluating the original unchanged R1CS equations.

use ff::Field;
use lnm_bitvm3_nova::{native_step, validated_trace, NovaSettlementStep, DOMAIN, STATE_ARITY};
use m18_utxo_window::{
    cost::G,
    elem::{fu, F},
};
use nova_snark::{
    frontend::{
        gadgets::num::AllocatedNum, ConstraintSystem, Index, LinearCombination, SynthesisError,
        Variable,
    },
    traits::circuit::StepCircuit,
};
use std::collections::BTreeMap;

type Equation = (
    LinearCombination<F>,
    LinearCombination<F>,
    LinearCombination<F>,
    String,
);

#[derive(Clone)]
struct Assignments {
    inputs: Vec<F>,
    aux: Vec<F>,
    names: BTreeMap<String, Variable>,
    namespace: Vec<String>,
    equations: Vec<Equation>,
}

impl Default for Assignments {
    fn default() -> Self {
        Self {
            inputs: vec![F::ONE],
            aux: Vec::new(),
            names: BTreeMap::new(),
            namespace: Vec::new(),
            equations: Vec::new(),
        }
    }
}

impl Assignments {
    fn path(&self, name: String) -> String {
        self.namespace
            .iter()
            .cloned()
            .chain([name])
            .collect::<Vec<_>>()
            .join("/")
    }

    fn value(&self, var: Variable) -> F {
        match var.get_unchecked() {
            Index::Input(i) => self.inputs[i],
            Index::Aux(i) => self.aux[i],
        }
    }

    fn set(&mut self, name: &str, value: F) {
        let var = *self
            .names
            .get(name)
            .unwrap_or_else(|| panic!("missing assignment {name}"));
        match var.get_unchecked() {
            Index::Input(i) => self.inputs[i] = value,
            Index::Aux(i) => self.aux[i] = value,
        }
    }

    fn eval(&self, lc: &LinearCombination<F>) -> F {
        lc.iter()
            .fold(F::ZERO, |sum, (var, coeff)| sum + self.value(var) * coeff)
    }

    fn failure(&self) -> Option<&str> {
        self.equations
            .iter()
            .find(|(a, b, c, _)| self.eval(a) * self.eval(b) != self.eval(c))
            .map(|(_, _, _, name)| name.as_str())
    }

    fn replace_namespace_assignments(&mut self, other: &Self, prefix: &str) {
        let mut replacements = 0;
        for (name, &var) in &other.names {
            if name.starts_with(prefix) {
                self.set(name, other.value(var));
                replacements += 1;
            }
        }
        assert!(replacements > 100, "must replace intermediate witnesses");
    }

    fn replace_hash_assignments(&mut self, other: &Self) {
        self.replace_namespace_assignments(other, "row hash/");
    }
}

impl ConstraintSystem<F> for Assignments {
    type Root = Self;

    fn alloc<V, A, AR>(&mut self, annotation: A, value: V) -> Result<Variable, SynthesisError>
    where
        V: FnOnce() -> Result<F, SynthesisError>,
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        let var = Variable::new_unchecked(Index::Aux(self.aux.len()));
        self.aux.push(value()?);
        assert!(self
            .names
            .insert(self.path(annotation().into()), var)
            .is_none());
        Ok(var)
    }

    fn alloc_input<V, A, AR>(&mut self, annotation: A, value: V) -> Result<Variable, SynthesisError>
    where
        V: FnOnce() -> Result<F, SynthesisError>,
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        let var = Variable::new_unchecked(Index::Input(self.inputs.len()));
        self.inputs.push(value()?);
        assert!(self
            .names
            .insert(self.path(annotation().into()), var)
            .is_none());
        Ok(var)
    }

    fn enforce<A, AR, LA, LB, LC>(&mut self, annotation: A, a: LA, b: LB, c: LC)
    where
        A: FnOnce() -> AR,
        AR: Into<String>,
        LA: FnOnce(LinearCombination<F>) -> LinearCombination<F>,
        LB: FnOnce(LinearCombination<F>) -> LinearCombination<F>,
        LC: FnOnce(LinearCombination<F>) -> LinearCombination<F>,
    {
        self.equations.push((
            a(LinearCombination::zero()),
            b(LinearCombination::zero()),
            c(LinearCombination::zero()),
            self.path(annotation().into()),
        ));
    }

    fn push_namespace<NR, N>(&mut self, name: N)
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        self.namespace.push(name().into());
    }

    fn pop_namespace(&mut self) {
        self.namespace.pop().expect("namespace");
    }
    fn get_root(&mut self) -> &mut Self {
        self
    }
}

fn synthesize(step: &NovaSettlementStep, state: &[F]) -> Assignments {
    let mut cs = Assignments::default();
    let inputs = state
        .iter()
        .enumerate()
        .map(|(i, &v)| AllocatedNum::alloc_infallible(cs.namespace(|| format!("state {i}")), || v))
        .collect::<Vec<_>>();
    step.synthesize(&mut cs, &inputs).unwrap();
    cs
}

fn hash_inputs(step: &NovaSettlementStep, state: &[F]) -> [F; 13] {
    let r = &step.row;
    [
        fu(DOMAIN),
        state[4],
        r.lo,
        r.hi,
        r.funding_lo,
        r.funding_hi,
        fu(r.funding_vout as u64),
        fu(r.outcome_index as u64),
        fu(r.collateral),
        fu(r.trader),
        fu(r.maker),
        fu(r.anchor),
        fu(r.fee),
    ]
}

fn forged_hash(inputs: &[F]) -> Assignments {
    let mut cs = Assignments::default();
    let inputs = inputs
        .iter()
        .enumerate()
        .map(|(i, &v)| AllocatedNum::alloc_infallible(cs.namespace(|| format!("input {i}")), || v))
        .collect::<Vec<_>>();
    G::new(&mut cs.namespace(|| "row hash")).hash(&inputs);
    assert_eq!(cs.failure(), None);
    cs
}

#[test]
fn malicious_assignments_cannot_change_domain_count_or_amount_commitments() {
    let batch = lnm_batch_statement::fixture::demo_batch(1).unwrap();
    let trace = validated_trace(&batch).unwrap();
    let step = &trace.steps[0];
    let mut cs = synthesize(step, &trace.initial);
    assert_eq!(cs.failure(), None);
    let inputs = hash_inputs(step, &trace.initial);
    let honest_hash = forged_hash(&inputs);

    // Recompute the complete hash witness under a forged domain. The domain
    // equation must reject it, even when every Poseidon equation is satisfied.
    let mut forged = inputs;
    forged[0] += F::ONE;
    cs.set("domain/num", forged[0]);
    cs.replace_hash_assignments(&forged_hash(&forged));
    assert_eq!(cs.failure(), Some("fixed domain"));
    cs.set("domain/num", inputs[0]);
    cs.replace_hash_assignments(&honest_hash);
    assert_eq!(cs.failure(), None);

    cs.set("count/num", fu(7));
    assert_eq!(cs.failure(), Some("increment count"));
    cs.set("count/num", fu(1));

    // Keep all accounting witnesses fixed but supply a complete valid hash
    // witness committing to a different economic amount. A duplicate free
    // amount allocation would permit this splice.
    for amount_index in 8..13 {
        let mut forged = inputs;
        forged[amount_index] += F::ONE;
        cs.replace_hash_assignments(&forged_hash(&forged));
        assert!(
            cs.failure()
                .is_some_and(|name| name.starts_with("row hash/")),
            "amount {amount_index} must share its accounting wire with Poseidon"
        );
        cs.replace_hash_assignments(&honest_hash);
        assert_eq!(cs.failure(), None);
    }
}

#[test]
fn rehashed_out_of_range_limb_and_index_assignments_are_rejected() {
    let batch = lnm_batch_statement::fixture::demo_batch(1).unwrap();
    let trace = validated_trace(&batch).unwrap();
    let step = &trace.steps[0];
    let inputs = hash_inputs(step, &trace.initial);
    let honest_hash = forged_hash(&inputs);
    let mut cs = synthesize(step, &trace.initial);
    for (index, name, bits) in [
        (2, "digest low/num", 128),
        (3, "digest high/num", 128),
        (4, "funding low/num", 128),
        (5, "funding high/num", 128),
        (6, "funding vout/num", 32),
        (7, "outcome index/num", 32),
    ] {
        let mut forged = inputs;
        forged[index] += fu(2).pow_vartime([bits]);
        cs.set(name, forged[index]);
        cs.replace_hash_assignments(&forged_hash(&forged));
        assert!(cs.failure().is_some(), "unbounded encoded value {name}");
        cs.set(name, inputs[index]);
        cs.replace_hash_assignments(&honest_hash);
        assert_eq!(cs.failure(), None);
    }
}

#[test]
fn state_count_and_total_bounds_agree_with_native_mirror() {
    let batch = lnm_batch_statement::fixture::demo_batch(1).unwrap();
    let trace = validated_trace(&batch).unwrap();
    let step = &trace.steps[0];
    let initial: [F; STATE_ARITY] = trace.initial.clone().try_into().unwrap();
    let mut last = initial;
    last[0] = fu(31);
    assert!(native_step(&last, &step.row).is_ok());
    assert_eq!(synthesize(step, &last).failure(), None);
    for (slot, value) in [
        (0, fu(32)),
        (0, -F::ONE),
        (1, fu(2).pow_vartime([56]) - F::ONE),
        (5, fu(2).pow_vartime([128])),
        (6, fu(2).pow_vartime([128])),
        (7, fu(2).pow_vartime([64])),
    ] {
        let mut invalid = initial;
        invalid[slot] = value;
        assert!(native_step(&invalid, &step.row).is_err());
        assert!(synthesize(step, &invalid).failure().is_some());
    }
}

#[test]
fn setup_and_real_witnesses_produce_identical_constraint_shapes() {
    let batch = lnm_batch_statement::fixture::demo_batch(1).unwrap();
    let trace = validated_trace(&batch).unwrap();
    let blank = synthesize(&NovaSettlementStep::blank(), &[F::ZERO; STATE_ARITY]);
    let real = synthesize(&trace.steps[0], &trace.initial);
    assert_eq!(real.failure(), None);
    assert_eq!(blank.inputs.len(), real.inputs.len());
    assert_eq!(blank.aux.len(), real.aux.len());
    assert_eq!(
        blank.equations, real.equations,
        "constraint shape must be witness-independent"
    );
}

fn rehash_transcript(step: &mut NovaSettlementStep) {
    let digest = lnm_batch_statement::sha256(&step.row.transcript);
    step.row.lo = m18_utxo_window::elem::f_from_le(&digest[..16]);
    step.row.hi = m18_utxo_window::elem::f_from_le(&digest[16..]);
}

#[test]
fn transcript_mutations_require_the_same_digest_and_outpoint() {
    let batch = lnm_batch_statement::fixture::demo_batch(1).unwrap();
    let trace = validated_trace(&batch).unwrap();
    let original = &trace.steps[0];
    let initial: [F; STATE_ARITY] = trace.initial.clone().try_into().unwrap();

    let mut stale_signature = original.clone();
    stale_signature.row.transcript[110] ^= 1;
    assert!(native_step(&initial, &stale_signature.row).is_err());
    assert!(synthesize(&stale_signature, &initial).failure().is_some());

    let mut different_outpoint = original.clone();
    different_outpoint.row.transcript[564] ^= 1;
    rehash_transcript(&mut different_outpoint);
    assert!(native_step(&initial, &different_outpoint.row).is_err());
    assert_eq!(
        synthesize(&different_outpoint, &initial).failure(),
        Some("signed transcript/funding low")
    );

    let mut forged_digest = original.clone();
    forged_digest.row.lo += F::ONE;
    assert!(native_step(&initial, &forged_digest.row).is_err());
    assert_eq!(
        synthesize(&forged_digest, &initial).failure(),
        Some("signed transcript/digest low")
    );

    // The tag is an implicit fixed constant in R1CS. Hashing another tag on the
    // host cannot produce the circuit's committed digest.
    let mut forged_tag = original.clone();
    forged_tag.row.transcript[0] ^= 1;
    rehash_transcript(&mut forged_tag);
    assert!(native_step(&initial, &forged_tag.row).is_err());
    assert!(synthesize(&forged_tag, &initial).failure().is_some());
}

#[test]
fn complete_sha_witness_spliced_under_stale_digest_is_rejected() {
    let batch = lnm_batch_statement::fixture::demo_batch(1).unwrap();
    let trace = validated_trace(&batch).unwrap();
    let original = &trace.steps[0];
    let initial: [F; STATE_ARITY] = trace.initial.clone().try_into().unwrap();
    let mut cs = synthesize(original, &initial);
    assert_eq!(cs.failure(), None);

    let mut altered = original.clone();
    altered.row.transcript[110] ^= 1;
    rehash_transcript(&mut altered);
    let altered_cs = synthesize(&altered, &initial);
    // This is deliberately a digest/accounting statement. It permits arbitrary
    // signature bytes if their digest is updated consistently. BIP340 validity
    // still belongs to the independently pinned external statement.
    assert_eq!(altered_cs.failure(), None);
    assert_ne!(
        native_step(&initial, &altered.row).unwrap()[4],
        trace.final_state[4]
    );

    // Copy every changed byte and every intermediate SHA witness while keeping
    // the old committed digest and Poseidon chain. All internal SHA equations
    // remain satisfied; its output-to-digest binding must reject this attack.
    cs.replace_namespace_assignments(&altered_cs, "signed transcript/");
    assert_eq!(cs.failure(), Some("signed transcript/digest low"));
}
