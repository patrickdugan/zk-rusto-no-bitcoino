//! Local native validation, Nova folding, and independent persisted verification.
use lnm_bitvm3_nova::artifact::{
    read_bounded, serialize_bounded, setup_params, verifier_identity, verify_bundle, write_bundle,
    write_new, write_pins, Cs, Rs, VerifierPins, MAX_PROOF_BYTES, RELATION_ID,
};
use lnm_bitvm3_nova::validated_trace;
use m18_utxo_window::elem::f_to_le;
use serde_json::json;
use std::{env, path::PathBuf, time::Instant};

const USAGE: &str = "usage:\n  lnm-nova trace ROWS\n  lnm-nova prepare ROWS --out EXPECT.json\n  lnm-nova prove ROWS [--compressed [--out BUNDLE_DIR]]\n  lnm-nova verify --bundle BUNDLE_DIR --expect EXPECT.json\nReplace ROWS with --witness FILE for a native-validated binary batch. Fixture ROWS=1,2,8,32. Output paths must be new.";

#[derive(Debug)]
enum Input {
    Fixture(usize),
    Witness(PathBuf),
}

#[derive(Debug)]
enum Command {
    Produce {
        action: String,
        input: Input,
        compressed: bool,
        out: Option<PathBuf>,
    },
    Verify {
        bundle: PathBuf,
        expected: PathBuf,
    },
}

fn value(args: &[String], i: &mut usize, flag: &str) -> Result<PathBuf, String> {
    *i += 1;
    let result = args.get(*i).ok_or_else(|| format!("{flag} needs a path"))?;
    if result.is_empty() || result.starts_with("--") {
        return Err(format!("{flag} needs a path"));
    }
    Ok(result.into())
}

fn parse(args: &[String]) -> Result<Command, String> {
    let action = args.first().ok_or(USAGE)?;
    if action == "verify" {
        let mut bundle = None;
        let mut expected = None;
        let mut i = 1;
        while i < args.len() {
            match args[i].as_str() {
                "--bundle" if bundle.is_none() => bundle = Some(value(args, &mut i, "--bundle")?),
                "--expect" if expected.is_none() => {
                    expected = Some(value(args, &mut i, "--expect")?)
                }
                flag => return Err(format!("unknown or repeated verification argument: {flag}")),
            }
            i += 1;
        }
        return Ok(Command::Verify {
            bundle: bundle.ok_or("verify requires --bundle")?,
            expected: expected.ok_or("verify requires independently supplied --expect")?,
        });
    }
    if !["trace", "prepare", "prove"].contains(&action.as_str()) {
        return Err(USAGE.into());
    }
    let mut input = None;
    let mut compressed = false;
    let mut out = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--witness" if input.is_none() => {
                input = Some(Input::Witness(value(args, &mut i, "--witness")?))
            }
            "--out" if out.is_none() => out = Some(value(args, &mut i, "--out")?),
            "--compressed" if !compressed => compressed = true,
            number if input.is_none() => {
                let n = number
                    .parse()
                    .map_err(|_| format!("invalid argument: {number}"))?;
                if ![1, 2, 8, 32].contains(&n) {
                    return Err("fixture ROWS must be 1,2,8,32".into());
                }
                input = Some(Input::Fixture(n));
            }
            other => return Err(format!("unknown or repeated argument: {other}")),
        }
        i += 1;
    }
    let input = input.ok_or("supply ROWS or --witness FILE")?;
    if compressed && action != "prove" {
        return Err("--compressed is accepted only by prove".into());
    }
    if action == "prepare" && out.is_none() {
        return Err("prepare requires --out EXPECT.json".into());
    }
    if out.is_some() && (action == "trace" || (action == "prove" && !compressed)) {
        return Err("--out requires prepare or prove --compressed".into());
    }
    Ok(Command::Produce {
        action: action.clone(),
        input,
        compressed,
        out,
    })
}

fn main_run() -> Result<serde_json::Value, String> {
    let args: Vec<_> = env::args().skip(1).collect();
    let (action, input, compressed, out) = match parse(&args)? {
        Command::Verify { bundle, expected } => return verify_bundle(&bundle, &expected),
        Command::Produce {
            action,
            input,
            compressed,
            out,
        } => (action, input, compressed, out),
    };
    if let Some(path) = &out {
        if path.try_exists().map_err(|e| e.to_string())? {
            return Err(format!("output path already exists: {}", path.display()));
        }
    }
    let source = match &input {
        Input::Fixture(_) => "synthetic_fixture",
        Input::Witness(_) => "supplied_binary_witness",
    };
    let witness = match input {
        Input::Fixture(n) => lnm_batch_statement::fixture::demo_batch(n)?,
        Input::Witness(path) => {
            let bytes = read_bounded(&path, lnm_batch_statement::MAX_WITNESS_BYTES)?;
            lnm_batch_statement::decode_batch(&bytes)?
        }
    };
    let trace = validated_trace(&witness)?;
    let initial_sha256 = lnm_batch_statement::sha256(&trace.journal_bytes);
    let initial_root = hex::encode(f_to_le(&trace.initial[4]));
    let final_root = hex::encode(f_to_le(&trace.final_state[4]));
    let mut native = json!({
        "schema":"lnmarkets-bitvm3-nova/v2",
        "relation":RELATION_ID,
        "status":"native_validated_unproved",
        "nova_recursive_verified":false,
        "nova_compressed_verified":false,
        "source":source,
        "rows":trace.steps.len(),
        "native_bip340_and_oracle_checks":true,
        "native_signature_checks_in_this_process":true,
        "sha256_nullifier_and_transaction_checks_outside_nova":true,
        "row_transcript_sha256_constrained":true,
        "row_transcript_digests_constrained_as_opaque_witnesses":false,
        "bitcoin_spendability_proved":false,
        "standalone_signature_snark_proved":false,
        "native_journal_sha256":hex::encode(initial_sha256),
        "nova_poseidon_root_z0":initial_root,
        "nova_poseidon_root_zn":final_root,
        "native_journal_bytes":trace.journal_bytes.len(),
        "nova_state_arity":trace.initial.len(),
        "nova_step_count":trace.steps.len(),
    });
    if action == "trace" {
        return Ok(native);
    }
    let start = Instant::now();
    let pp = setup_params()?;
    let setup = start.elapsed().as_secs_f64();
    native["nova_augmented_constraints_primary"] = json!(pp.num_constraints().0);
    native["nova_augmented_constraints_secondary"] = json!(pp.num_constraints().1);
    native["nova_augmented_variables_primary"] = json!(pp.num_variables().0);
    native["nova_augmented_variables_secondary"] = json!(pp.num_variables().1);
    native["nova_public_params_digest"] = json!(hex::encode(f_to_le(&pp.digest())));
    if action == "prepare" {
        let t = Instant::now();
        let (_, vk) = Cs::setup(&pp).map_err(|e| format!("Nova compressed setup: {e:?}"))?;
        let vk_identity = verifier_identity(&vk)?;
        let pins = VerifierPins::from_trace(&trace, &vk_identity)?;
        let out = out.ok_or("prepare requires --out")?;
        write_pins(&out, &pins)?;
        let mut report = native;
        report["status"] = json!("expected_claim_prepared_native_validated_unproved");
        report["expectations_path"] = json!(out);
        report["verifier_key_sha256"] = json!(pins.verifier_key_sha256);
        report["verifier_key_serialized_bytes"] = json!(pins.verifier_key_serialized_bytes);
        report["nova_setup_seconds"] = json!(setup);
        report["compressed_setup_seconds"] = json!(t.elapsed().as_secs_f64());
        return Ok(report);
    }
    let start = Instant::now();
    let mut recursive = Rs::new(&pp, &trace.steps[0], &trace.initial)
        .map_err(|e| format!("Nova initialization: {e:?}"))?;
    for (i, step) in trace.steps.iter().enumerate() {
        recursive
            .prove_step(&pp, step)
            .map_err(|e| format!("Nova step {i}: {e:?}"))?;
    }
    let prove = start.elapsed().as_secs_f64();
    let start = Instant::now();
    let output = recursive
        .verify(&pp, trace.steps.len(), &trace.initial)
        .map_err(|e| format!("Nova recursive verification: {e:?}"))?;
    if output != trace.final_state {
        return Err("Nova folded output differs from independently computed native trace".into());
    }
    let verify = start.elapsed().as_secs_f64();
    let mut report = native;
    report["proof"] = json!("recursive_nova_0_76");
    report["status"] = json!("recursive_proven_limited_relation");
    report["nova_recursive_verified"] = json!(true);
    report["nova_setup_seconds"] = json!(setup);
    report["nova_prove_seconds"] = json!(prove);
    report["nova_verify_seconds"] = json!(verify);
    if compressed {
        let t = Instant::now();
        let (pk, vk) = Cs::setup(&pp).map_err(|e| format!("Nova compressed setup: {e:?}"))?;
        report["compressed_setup_seconds"] = json!(t.elapsed().as_secs_f64());
        let t = Instant::now();
        let proof =
            Cs::prove(&pp, &pk, &recursive).map_err(|e| format!("Nova compressed proof: {e:?}"))?;
        report["compressed_prove_seconds"] = json!(t.elapsed().as_secs_f64());
        let t = Instant::now();
        let checked = proof
            .verify(&vk, trace.steps.len(), &trace.initial)
            .map_err(|e| format!("Nova compressed verification: {e:?}"))?;
        if checked != trace.final_state {
            return Err("compressed Nova proof differs from pinned native trace".into());
        }
        report["compressed_verify_seconds"] = json!(t.elapsed().as_secs_f64());
        let proof_bytes = serialize_bounded(&proof, MAX_PROOF_BYTES)?;
        let vk_identity = verifier_identity(&vk)?;
        report["compressed_bytes"] = json!(proof_bytes.len());
        report["verifier_key_sha256"] = json!(vk_identity.sha256);
        report["verifier_key_serialized_bytes"] = json!(vk_identity.serialized_bytes);
        report["proof_sha256"] = json!(hex::encode(lnm_batch_statement::sha256(&proof_bytes)));
        report["proof"] = json!("compressed_nova_spartan_ipa");
        report["status"] = json!("compressed_proven_limited_relation");
        report["nova_compressed_verified"] = json!(true);
        if let Some(out) = out {
            write_bundle(&out, &trace, &proof_bytes, &vk_identity)?;
            report["bundle_path"] = json!(out);
            report["private_witness_exported"] = json!(false);
            write_new(
                &out.join("report.json"),
                &serde_json::to_vec_pretty(&report).map_err(|e| e.to_string())?,
            )?;
        }
    }
    Ok(report)
}

fn main() {
    match main_run() {
        Ok(value) => println!("{}", serde_json::to_string_pretty(&value).unwrap()),
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|v| (*v).into()).collect()
    }

    #[test]
    fn existing_modes_and_independent_verification_parse() {
        assert!(parse(&args(&["trace", "2"])).is_ok());
        assert!(parse(&args(&["prove", "2", "--compressed"])).is_ok());
        assert!(parse(&args(&[
            "prepare",
            "--witness",
            "input.bin",
            "--out",
            "expected.json"
        ]))
        .is_ok());
        assert!(parse(&args(&[
            "verify",
            "--bundle",
            "proof",
            "--expect",
            "expected.json"
        ]))
        .is_ok());
    }

    #[test]
    fn ambiguous_or_incomplete_modes_are_refused() {
        for invalid in [
            vec!["trace", "2", "--compressed"],
            vec!["prove", "2", "--out", "bundle"],
            vec!["prove", "2", "--witness", "input.bin"],
            vec!["prepare", "1"],
            vec!["verify", "--bundle", "bundle"],
            vec![
                "verify", "--bundle", "bundle", "--expect", "a", "--expect", "b",
            ],
            vec!["prove", "1", "--compressed", "--compressed"],
            vec!["prove", "1", "--compressed", "--out", "--witness"],
        ] {
            assert!(parse(&args(&invalid)).is_err(), "accepted {invalid:?}");
        }
    }
}
