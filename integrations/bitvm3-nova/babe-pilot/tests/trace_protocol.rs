//! One complete small verifier travels through the actual universal local
//! checker, cut-and-choose, Nova/Spartan certificate and retained evaluations.
//! The relation here accepts a false proof bit through Boolean NOT. The optional M14 adapter checks
//! that the production verifier entry point refuses partial trace compilation.
use babe_pilot::{
    gates,
    protocol::{
        evaluate_retained_instances, resolve_dispute, verify_public_setup, DisputeResolution,
        GarblerSession, InstanceVerdict,
    },
    trace::{
        digest, verify_publication, TraceDisputeSpec, TraceLimits, TraceProgram, TracePublication,
        VerifierBinding,
    },
};

#[test]
fn complete_trace_fault_survives_real_nova_soldering_and_retained_evaluation() {
    let started = std::time::Instant::now();
    let binding = VerifierBinding {
        source: digest(b"complete one-input NOT verifier v1"),
        parameters: digest(b"one Boolean input, one accepting output"),
        statement: digest(b"the proof bit must be false"),
        input_schema: digest(b"one canonical Boolean byte"),
    };
    let program = TraceProgram::compile(binding, 1, TraceLimits::default(), |c, w| {
        vec![gates::not(c, w[0])]
    })
    .unwrap();
    let input = program.bind_inputs(&[0], digest(&[0]), &[false]).unwrap();
    let honest_values = program.execute(&input).unwrap();
    let mut bad_values = honest_values.clone();
    let gate_index = program.pin().input_count;
    bad_values[gate_index as usize] = false;
    let session = [0x54; 32];
    let nonce = [0x71; 32];
    let (claim, publication) =
        TracePublication::create(&program, &input, session, &bad_values).unwrap();
    let spec = TraceDisputeSpec::new(&program, &input, session, &claim).unwrap();
    let available = verify_publication(&program, &spec, &publication).unwrap();
    let response = available.response(&program, gate_index).unwrap();
    let bits = response.to_bits(&spec).unwrap();
    assert!(spec.native_refutes(&response));
    assert_eq!(bits.len(), 3092);
    let another_input = available
        .response(&program, 0)
        .unwrap()
        .to_bits(&spec)
        .unwrap();

    let mut garbler = GarblerSession::<TraceDisputeSpec>::setup(session, spec.clone(), [0x82; 32]);
    let manifest = garbler.pre_challenge_manifest();
    let commit1 = manifest.commit1_digest().unwrap();
    let gates = manifest.headers[0].ciphertext_count;
    assert_eq!(manifest.num_wires, bits.len());
    let (setup, timings) = garbler.finalize_cut_and_choose(nonce).unwrap();

    let wrong_nonce = [0x72; 32];
    assert!(garbler
        .release_active_base_labels(wrong_nonce, &bits)
        .is_err());
    assert!(garbler
        .release_active_base_labels(nonce, &bits[..bits.len() - 1])
        .is_err());
    let delivery = garbler.release_active_base_labels(nonce, &bits).unwrap();
    assert_eq!(
        garbler.release_active_base_labels(nonce, &bits).unwrap(),
        delivery
    );
    assert!(garbler
        .release_active_base_labels(nonce, &another_input)
        .is_err());
    drop(garbler);

    let (honest_claim, _) =
        TracePublication::create(&program, &input, session, &honest_values).unwrap();
    let substituted_spec = TraceDisputeSpec::new(&program, &input, session, &honest_claim).unwrap();
    assert!(verify_public_setup(&session, &substituted_spec, &commit1, &nonce, &setup).is_err());
    assert!(verify_public_setup(&session, &spec, &commit1, &wrong_nonce, &setup).is_err());
    let mut wrong_commit1 = commit1;
    wrong_commit1[31] ^= 1;
    assert!(verify_public_setup(&session, &spec, &wrong_commit1, &nonce, &setup).is_err());
    let verified = verify_public_setup(&session, &spec, &commit1, &nonce, &setup).unwrap();
    let verdicts = evaluate_retained_instances(&verified, &bits, &delivery).unwrap();
    assert!(verdicts
        .iter()
        .all(|v| matches!(v, InstanceVerdict::Refute { .. })));
    let resolution = resolve_dispute(&verified, &bits, Some(&delivery)).unwrap();
    assert!(matches!(
        resolution,
        DisputeResolution::AuthenticatedRefutation { .. }
    ));
    assert!(evaluate_retained_instances(&verified, &another_input, &delivery).is_err());
    eprintln!(
        "TRACE-PROTOCOL: {} inputs, {} local non-free gates, {:?}, total {:.2}s",
        bits.len(),
        gates,
        timings,
        started.elapsed().as_secs_f64()
    );
}
