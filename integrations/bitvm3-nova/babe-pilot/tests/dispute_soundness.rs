use babe_pilot::dispute_circuit::{
    compute_pasta_step_hash, compute_step_auth_tag, deterministic_pasta_window_points,
    eval_indexed_dispute_circuit, eval_pasta_window_ec_step, execute_boolean_circuit,
    pallas_base_modulus, IndexedDisputeInput, IndexedDisputeSpec, PastaWindowStepWitness,
    PastaWindowTable, PILOT_PRIME,
};
use num_bigint::BigUint;
use num_traits::{One, Zero};

fn indexed(spec: &IndexedDisputeSpec, input: &IndexedDisputeInput, expected: bool) {
    assert_eq!(spec.native_refutes(input), expected);
    let (result, _) = execute_boolean_circuit(input.to_bits(), |c, w| {
        eval_indexed_dispute_circuit(c, spec, w)
    });
    assert_eq!(result, vec![expected]);
}

fn pasta(table: &PastaWindowTable, input: &PastaWindowStepWitness, expected: bool) {
    assert_eq!(table.native_refutes(input), expected);
    let (result, _) = execute_boolean_circuit(input.to_bits(), |c, w| {
        eval_pasta_window_ec_step(c, table, w)
    });
    assert_eq!(result, vec![expected]);
}

#[test]
fn indexed_malformed_challenger_openings_do_not_refute_honest_claim() {
    let (spec, inputs) = IndexedDisputeSpec::sample_honest_trace([0x5a; 32]);
    indexed(&spec, &inputs[3], false);
    let mut bad = inputs[3].clone();
    bad.witness_quotient ^= 1;
    indexed(&spec, &bad, false);
    bad = inputs[3].clone();
    bad.s_out ^= 1;
    indexed(&spec, &bad, false);
    bad = inputs[3].clone();
    bad.index = 9;
    indexed(&spec, &bad, false);
}

#[test]
fn indexed_authenticated_invalid_operator_steps_are_refuted() {
    let (original, inputs) = IndexedDisputeSpec::sample_honest_trace([0x5a; 32]);
    for field in 0..3 {
        let mut bad = inputs[3].clone();
        match field {
            0 => bad.witness_quotient ^= 1,
            1 => bad.s_out ^= 1,
            _ => bad.s_in = PILOT_PRIME as u32,
        }
        let mut spec = original.clone();
        spec.commit_step(&bad); // operator commits the bad tuple before setup
        assert_ne!(spec.circuit_id, original.circuit_id);
        indexed(&spec, &bad, true);
        indexed(&spec, &inputs[3], false);
    }
}

#[test]
fn indexed_full_digest_generator_context_and_integer_boundaries() {
    let (mut spec, inputs) = IndexedDisputeSpec::sample_honest_trace([7; 32]);
    let mut bad = inputs[0].clone();
    bad.witness_quotient ^= 1;
    spec.commit_step(&bad);
    indexed(&spec, &bad, true);
    spec.step_auth_tags[0][31] ^= 1; // a prefix-only comparator would miss this
    spec.recompute_circuit_id();
    indexed(&spec, &bad, false);

    spec.commit_step(&bad);
    let before = compute_step_auth_tag(&spec.claim_id, spec.generators[0], &bad);
    spec.generators[0] += 1;
    assert_ne!(
        before,
        compute_step_auth_tag(&spec.claim_id, spec.generators[0], &bad)
    );
    spec.recompute_circuit_id();
    indexed(&spec, &bad, false);

    for (sin, val) in [(0, 0), (PILOT_PRIME - 1, PILOT_PRIME - 1)] {
        let product = ((sin + spec.generators[15] as u64) % PILOT_PRIME) * val;
        let edge = IndexedDisputeInput {
            index: 15,
            s_in: sin as u32,
            step_val: val as u32,
            s_out: (product % PILOT_PRIME) as u32,
            witness_quotient: (product / PILOT_PRIME) as u32,
        };
        spec.commit_step(&edge);
        indexed(&spec, &edge, false);
    }
}

#[test]
fn fixed_width_encoders_reject_aliases() {
    let (spec, inputs) = IndexedDisputeSpec::sample_honest_trace([9; 32]);
    let mut bad = inputs[0].clone();
    bad.index = 16;
    assert!(!spec.native_refutes(&bad));
    assert!(std::panic::catch_unwind(|| bad.to_bits()).is_err());
    bad.index = 0;
    bad.s_in = 1 << 31;
    assert!(!spec.native_refutes(&bad));
    assert!(std::panic::catch_unwind(|| bad.to_bits()).is_err());

    let (table, mut ec) = PastaWindowTable::sample_valid();
    ec.x1 += BigUint::one() << 255;
    assert!(!table.native_refutes(&ec));
    assert!(std::panic::catch_unwind(|| ec.to_bits()).is_err());
}

#[test]
fn pasta_every_committed_field_and_context_affects_full_hash() {
    let (table, honest) = PastaWindowTable::sample_valid();
    for field in 0..18 {
        let mut changed = honest.clone();
        match field {
            0 => changed.x1 ^= BigUint::one() << 200,
            1 => changed.y1 ^= BigUint::one() << 200,
            2 => changed.x3 ^= BigUint::one() << 200,
            3 => changed.y3 ^= BigUint::one() << 200,
            4 => changed.inv ^= BigUint::one(),
            5 => changed.lambda ^= BigUint::one(),
            6 => changed.x1_sq ^= BigUint::one(),
            7 => changed.lam_sq ^= BigUint::one(),
            8 => changed.lam_dx3 ^= BigUint::one(),
            9..=13 => changed.quotients[field - 9] ^= BigUint::one(),
            14 => changed.window ^= 1,
            15 => changed.inf1 = !changed.inf1,
            16 => changed.inf3 = !changed.inf3,
            _ => changed.sibling_hash[31] ^= 1,
        }
        assert_ne!(
            compute_pasta_step_hash(&table, &changed),
            table.expected_step_hash
        );
        assert!(!table.native_refutes(&changed));
    }
    let mut context = table.clone();
    context.claim_id[31] ^= 1;
    assert_ne!(
        compute_pasta_step_hash(&context, &honest),
        table.expected_step_hash
    );
    context = table.clone();
    context.step_index += 1;
    assert_ne!(
        compute_pasta_step_hash(&context, &honest),
        table.expected_step_hash
    );
    context = table.clone();
    context.window_index = 1;
    context.points = deterministic_pasta_window_points(1);
    assert_ne!(
        compute_pasta_step_hash(&context, &honest),
        table.expected_step_hash
    );
    context.points[3].1 += BigUint::one();
    assert!(!context.valid_configuration());
}

#[test]
fn pasta_uncommitted_auxiliary_and_coordinate_changes_cannot_refute() {
    let (table, honest) = PastaWindowTable::sample_valid();
    let mut bad_q = honest.clone();
    bad_q.quotients[0] ^= BigUint::one();
    pasta(&table, &bad_q, false);
    let mut bad_y = honest.clone();
    bad_y.y3 += BigUint::one();
    pasta(&table, &bad_y, false);

    let mut bad_claim = table.clone();
    bad_claim.commit_step(&bad_q);
    pasta(&bad_claim, &bad_q, true);
    bad_claim.expected_step_hash[31] ^= 1;
    pasta(&bad_claim, &bad_q, false);
    bad_claim.commit_step(&bad_y);
    pasta(&bad_claim, &bad_y, true);
}

#[test]
fn pasta_complete_addition_cases_and_canonical_point_checks() {
    let (mut table, honest) = PastaWindowTable::sample_valid();
    pasta(&table, &honest, false);
    let p = pallas_base_modulus();
    let infinity = (true, BigUint::zero(), BigUint::zero());
    let g5 = table.points[5].clone();
    let inverse = (false, g5.1.clone(), &p - &g5.2);
    for (point, window) in [
        (g5.clone(), 5),       // doubling
        (inverse, 5),          // inverse
        (infinity.clone(), 5), // left identity
        (g5, 0),               // right identity
        (infinity, 0),         // both infinity
    ] {
        let opening = table.honest_witness(point, window);
        table.commit_step(&opening);
        pasta(&table, &opening, false);
    }

    let mut off_curve = table.honest_witness(table.points[3].clone(), 0);
    off_curve.y1 += BigUint::one();
    off_curve.y3 = off_curve.y1.clone(); // identity equality still holds
    table.commit_step(&off_curve);
    pasta(&table, &off_curve, true);

    let mut noncanonical = honest.clone();
    noncanonical.x1 = p;
    table.commit_step(&noncanonical);
    pasta(&table, &noncanonical, true);
}

#[test]
fn pasta_last_scalar_window_rejects_an_operator_committed_high_bit() {
    let mut table = PastaWindowTable::new([3; 32], 63, 63);
    let mut opening = table.honest_witness((true, BigUint::zero(), BigUint::zero()), 7);
    table.commit_step(&opening);
    pasta(&table, &opening, false);
    opening.window = 15;
    opening.inf3 = table.points[15].0;
    opening.x3 = table.points[15].1.clone();
    opening.y3 = table.points[15].2.clone(); // identity arithmetic is otherwise valid
    table.commit_step(&opening);
    pasta(&table, &opening, true);
}
