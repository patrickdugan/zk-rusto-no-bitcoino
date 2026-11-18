use babe_pilot::{
    dispute_circuit::execute_boolean_circuit,
    gates as g,
    trace::{
        digest, eval_trace_dispute_circuit, verify_publication, TraceDisputeSpec, TraceLimits,
        TraceProgram, TracePublication, TraceResponse, VerifierBinding,
    },
};
use garbled_snark_verifier::{CircuitContext, Gate, GateType, WireId};

fn binding() -> VerifierBinding {
    VerifierBinding {
        source: digest(b"all Boolean gate families test verifier v1"),
        parameters: digest(b"two proof input bits"),
        statement: digest(b"expected complete gate truth vector"),
        input_schema: digest(b"two bytes, each encodes one Boolean"),
    }
}

fn families() -> Vec<GateType> {
    vec![
        GateType::And,
        GateType::Nand,
        GateType::Nimp,
        GateType::Imp,
        GateType::Ncimp,
        GateType::Cimp,
        GateType::Nor,
        GateType::Or,
        GateType::Xor,
        GateType::Xnor,
        GateType::Not,
    ]
}

fn all_gates(a: bool, b: bool) -> TraceProgram {
    let mut pins = binding();
    pins.statement = digest(&[u8::from(a), u8::from(b)]);
    TraceProgram::compile(pins, 2, TraceLimits::default(), |c, w| {
        families()
            .into_iter()
            .map(|kind| {
                let output = c.issue_wire();
                let gate = Gate::new(kind, w[0], w[1], output);
                let expected = gate.execute(a, b);
                c.add_gate(gate);
                if expected {
                    output
                } else {
                    g::not(c, output)
                }
            })
            .collect()
    })
    .unwrap()
}

fn assert_local(spec: &TraceDisputeSpec, response: &TraceResponse, expected: bool) {
    assert_eq!(spec.native_refutes(response), expected);
    let (result, _) = execute_boolean_circuit(response.to_bits(spec).unwrap(), |c, w| {
        eval_trace_dispute_circuit(c, spec, w)
    });
    assert_eq!(result, vec![expected]);
}

#[test]
fn every_gate_family_and_truth_assignment_has_an_authenticated_local_check() {
    for (a, b) in [(false, false), (false, true), (true, false), (true, true)] {
        let program = all_gates(a, b);
        let proof = [u8::from(a), u8::from(b)];
        let input = program
            .bind_inputs(&proof, digest(&proof), &[a, b])
            .unwrap();
        let values = program.execute(&input).unwrap();
        let (claim, publication) =
            TracePublication::create(&program, &input, [7; 32], &values).unwrap();
        let spec = TraceDisputeSpec::new(&program, &input, [7; 32], &claim).unwrap();
        let available = verify_publication(&program, &spec, &publication).unwrap();
        assert!(available.first_refutation(&program).unwrap().is_none());
        // Every captured instruction is covered, including free XOR/NOT gates.
        for (index, record) in program.checks().iter().enumerate() {
            assert!(!spec.native_refutes(&available.response(&program, index as u64).unwrap()));
            if record.kind == 1 {
                let mut bad_values = values.clone();
                bad_values[record.c as usize] ^= true;
                let (bad_claim, bad_publication) =
                    TracePublication::create(&program, &input, [7; 32], &bad_values).unwrap();
                let bad_spec =
                    TraceDisputeSpec::new(&program, &input, [7; 32], &bad_claim).unwrap();
                let bad_data = verify_publication(&program, &bad_spec, &bad_publication).unwrap();
                assert_local(
                    &bad_spec,
                    &bad_data.response(&program, index as u64).unwrap(),
                    true,
                );
            }
        }
        assert_local(
            &spec,
            &available
                .response(&program, program.pin().check_count - 1)
                .unwrap(),
            false,
        );
    }
}

#[test]
fn initial_constants_proof_inputs_and_terminal_acceptance_are_enforced() {
    let program = all_gates(false, true);
    let input = program
        .bind_inputs(&[0, 1], digest(&[0, 1]), &[false, true])
        .unwrap();
    let values = program.execute(&input).unwrap();
    for index in 0..program.pin().input_count {
        let mut changed = values.clone();
        changed[index as usize] ^= true;
        let (claim, publication) =
            TracePublication::create(&program, &input, [8; 32], &changed).unwrap();
        let spec = TraceDisputeSpec::new(&program, &input, [8; 32], &claim).unwrap();
        let available = verify_publication(&program, &spec, &publication).unwrap();
        assert_local(&spec, &available.response(&program, index).unwrap(), true);
    }

    // A fully correct execution of a rejecting proof has no invalid gate. Its
    // explicit accepting-output endpoint supplies the refutation.
    let rejecting_input = program
        .bind_inputs(&[1, 1], digest(&[1, 1]), &[true, true])
        .unwrap();
    let rejecting_values = program.execute(&rejecting_input).unwrap();
    let (claim, publication) =
        TracePublication::create(&program, &rejecting_input, [8; 32], &rejecting_values).unwrap();
    let spec = TraceDisputeSpec::new(&program, &rejecting_input, [8; 32], &claim).unwrap();
    let available = verify_publication(&program, &spec, &publication).unwrap();
    let response = available.first_refutation(&program).unwrap().unwrap();
    assert_eq!(response.record.kind, 2);
    assert_local(&spec, &response, true);
}

#[test]
fn changed_challenger_openings_never_refute_an_honest_full_trace() {
    let program = all_gates(true, false);
    let input = program
        .bind_inputs(&[1, 0], digest(&[1, 0]), &[true, false])
        .unwrap();
    let values = program.execute(&input).unwrap();
    let (claim, publication) =
        TracePublication::create(&program, &input, [9; 32], &values).unwrap();
    let spec = TraceDisputeSpec::new(&program, &input, [9; 32], &claim).unwrap();
    let available = verify_publication(&program, &spec, &publication).unwrap();
    let honest = available
        .response(&program, program.pin().input_count)
        .unwrap();
    assert_local(&spec, &honest, false);
    let mut changed = honest.clone();
    changed.c.value ^= true;
    assert_local(&spec, &changed, false);
    changed = honest.clone();
    changed.a.value ^= true;
    assert_local(&spec, &changed, false);
    changed = honest.clone();
    changed.program_path[0][31] ^= 1;
    assert_local(&spec, &changed, false);
    changed = honest.clone();
    changed.c.path.last_mut().unwrap()[31] ^= 1;
    assert_local(&spec, &changed, false);
    changed = honest.clone();
    changed.record.truth_table ^= 1;
    assert_local(&spec, &changed, false);
    changed = honest.clone();
    changed.check_index |= 1 << 63;
    assert_local(&spec, &changed, false);
    changed = honest;
    changed.record.a ^= 1;
    assert_local(&spec, &changed, false);
}

#[test]
fn one_wire_commitment_links_every_producer_and_consumer() {
    let program = TraceProgram::compile(binding(), 2, TraceLimits::default(), |c, w| {
        let shared = g::and(c, w[0], w[1]);
        let first = g::xor(c, shared, w[0]);
        let second = g::xor(c, shared, w[1]);
        vec![g::not(c, first), g::not(c, second)]
    })
    .unwrap();
    let input = program
        .bind_inputs(&[1, 1], digest(&[1, 1]), &[true, true])
        .unwrap();
    let values = program.execute(&input).unwrap();
    let shared_index = program.pin().input_count;
    assert_eq!(program.checks()[shared_index as usize].c, shared_index);
    assert_eq!(program.checks()[shared_index as usize + 1].a, shared_index);
    assert_eq!(program.checks()[shared_index as usize + 2].a, shared_index);
    let mut changed = values;
    changed[shared_index as usize] ^= true;
    let (claim, publication) =
        TracePublication::create(&program, &input, [3; 32], &changed).unwrap();
    let spec = TraceDisputeSpec::new(&program, &input, [3; 32], &claim).unwrap();
    let available = verify_publication(&program, &spec, &publication).unwrap();
    for index in shared_index..=shared_index + 2 {
        assert_local(&spec, &available.response(&program, index).unwrap(), true);
    }
    // A consumer cannot open a different value for the same shared wire.
    let mut substituted = available.response(&program, shared_index + 1).unwrap();
    substituted.a.value ^= true;
    assert_local(&spec, &substituted, false);
}

#[test]
fn independent_program_proof_statement_and_session_pins_reject_substitution() {
    let program = all_gates(false, false);
    let input = program
        .bind_inputs(&[0, 0], digest(&[0, 0]), &[false, false])
        .unwrap();
    let values = program.execute(&input).unwrap();
    let (claim, _) = TracePublication::create(&program, &input, [4; 32], &values).unwrap();
    assert!(TraceDisputeSpec::new(&program, &input, [5; 32], &claim).is_err());
    let other = all_gates(true, true);
    assert_ne!(program.pin().id, other.pin().id);
    assert!(TraceDisputeSpec::new(&other, &input, [4; 32], &claim).is_err());
    assert!(program
        .bind_inputs(&[1, 0], digest(&[0, 0]), &[false, false])
        .is_err());
    let other_input = program
        .bind_inputs(&[1, 0], digest(&[1, 0]), &[true, false])
        .unwrap();
    assert!(TraceDisputeSpec::new(&program, &other_input, [4; 32], &claim).is_err());
    let mut changed = claim.clone();
    changed.values_root[31] ^= 1;
    assert!(TraceDisputeSpec::new(&program, &input, [4; 32], &changed).is_err());
}

#[test]
fn decoded_claim_digest_is_checked_before_issuing_availability_capability() {
    let program = all_gates(false, false);
    let input = program
        .bind_inputs(&[0, 0], digest(&[0, 0]), &[false, false])
        .unwrap();
    let values = program.execute(&input).unwrap();
    let (claim, publication) =
        TracePublication::create(&program, &input, [4; 32], &values).unwrap();
    let spec = TraceDisputeSpec::new(&program, &input, [4; 32], &claim).unwrap();
    verify_publication(&program, &spec, &publication).unwrap();

    // The roots and published data are unchanged. The decoded claim itself has
    // an inconsistent ID and must fail before receiving an availability handle.
    let mut encoded = serde_json::to_value(&spec).unwrap();
    let first = encoded["claim"]["id"][0].as_u64().unwrap();
    encoded["claim"]["id"][0] = serde_json::json!(first ^ 1);
    let decoded: TraceDisputeSpec = serde_json::from_value(encoded).unwrap();
    assert!(decoded.validate().is_err());
    assert!(verify_publication(&program, &decoded, &publication).is_err());
}

#[test]
fn full_publication_is_required_before_a_trace_can_answer_challenges() {
    let program = all_gates(true, true);
    let input = program
        .bind_inputs(&[1, 1], digest(&[1, 1]), &[true, true])
        .unwrap();
    let values = program.execute(&input).unwrap();
    assert!(
        TracePublication::create(&program, &input, [6; 32], &values[..values.len() - 1]).is_err()
    );
    let (claim, publication) =
        TracePublication::create(&program, &input, [6; 32], &values).unwrap();
    let spec = TraceDisputeSpec::new(&program, &input, [6; 32], &claim).unwrap();
    let mut changed = publication.clone();
    changed.proof_bytes.clear();
    assert!(verify_publication(&program, &spec, &changed).is_err());
    changed = publication.clone();
    changed.wire_values.pop();
    assert!(verify_publication(&program, &spec, &changed).is_err());
    changed = publication.clone();
    changed.wire_values[0] ^= 1;
    assert!(verify_publication(&program, &spec, &changed).is_err());
    changed = publication.clone();
    changed.input_bits[0] ^= 1;
    assert!(verify_publication(&program, &spec, &changed).is_err());
    changed = publication;
    changed.input_bits[0] |= 0x80;
    assert!(verify_publication(&program, &spec, &changed).is_err());
}

#[test]
fn compilation_limits_and_incomplete_schedules_never_publish_a_program_pin() {
    let limits = TraceLimits {
        max_gates: 1,
        ..TraceLimits::default()
    };
    let too_large = TraceProgram::compile(binding(), 2, limits, |c, w| {
        let a = g::and(c, w[0], w[1]);
        vec![g::xor(c, a, w[1])]
    });
    assert!(too_large.is_err());
    assert!(TraceProgram::compile(binding(), 2, TraceLimits::default(), |_c, _w| vec![]).is_err());
    assert!(
        TraceProgram::compile(binding(), 2, TraceLimits::default(), |c, _w| vec![
            c.issue_wire()
        ])
        .is_err()
    );
    assert!(
        TraceProgram::compile(binding(), 2, TraceLimits::default(), |c, w| {
            let o = c.issue_wire();
            c.add_gate(Gate::and(w[0], WireId(999), o));
            vec![o]
        })
        .is_err()
    );
    assert!(
        TraceProgram::compile(binding(), 2, TraceLimits::default(), |c, w| {
            c.add_gate(Gate::and(w[0], w[1], w[0]));
            vec![w[0]]
        })
        .is_err()
    );
}
