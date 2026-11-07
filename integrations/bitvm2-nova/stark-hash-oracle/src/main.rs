//! M24: measured Script cost of the upstream BitVM hash implementations at the
//! pinned revision, the dominant primitive of a transparent STARK final verifier.
//!
//! Each case pushes a deterministic message, runs the upstream compute script
//! and compares the result with a reference digest (the `blake3` crate or
//! bitcoin_hashes SHA-256). The same script with one changed expected digest
//! byte must fail. Execution uses the pinned interpreter with Tapscript rules,
//! minimal encoding, the 1,000-item stack limit and OP_CAT disabled. No proof,
//! transcript, Merkle path or verifier is executed here; projections live in
//! `stark_route_projection.py`.
use bitcoin::{
    hashes::{sha256, Hash},
    taproot::TapLeafHash,
    ScriptBuf, Transaction,
};
use bitcoin_script_stack::optimizer;
use bitcoin_scriptexec::{Exec, ExecCtx, Experimental, Options, TxTemplate};
use bitvm::hash::blake3::{
    blake3_compute_script, blake3_push_message_script_with_limb, blake3_verify_output_script,
};
use bitvm::hash::sha256::sha256 as sha256_script;
use bitvm::treepp::script;
use serde_json::{json, Value};
use std::{error::Error, fs};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

const BLAKE3_LENGTHS: [usize; 5] = [32, 64, 136, 208, 1024];
const SHA256_LENGTHS: [usize; 3] = [32, 64, 80];

fn require(yes: bool, message: &str) -> Result<()> {
    if yes {
        Ok(())
    } else {
        Err(message.into())
    }
}

/// Pinned interpreter, Tapscript context, consensus-like flags, no OP_CAT.
fn execute(code: &ScriptBuf) -> Result<(bool, usize)> {
    let options = Options {
        require_minimal: true,
        verify_cltv: true,
        verify_csv: true,
        verify_minimal_if: true,
        enforce_stack_limit: true,
        experimental: Experimental { op_cat: false },
    };
    let template = TxTemplate {
        tx: Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        },
        prevouts: vec![],
        input_idx: 0,
        taproot_annex_scriptleaf: Some((TapLeafHash::all_zeros(), None)),
    };
    let mut exec = Exec::new(
        ExecCtx::Tapscript,
        options,
        template,
        code.clone(),
        Vec::new(),
    )
    .map_err(|e| format!("interpreter initialization: {e:?}"))?;
    while exec.exec_next().is_ok() {}
    let result = exec.result().ok_or("interpreter produced no result")?;
    Ok((result.success, exec.stats().max_nb_stack_items))
}

fn message(length: usize) -> Vec<u8> {
    (0..length).map(|i| ((i * 37 + 11) & 255) as u8).collect()
}

fn concat(parts: &[&ScriptBuf]) -> ScriptBuf {
    let mut bytes = Vec::new();
    for part in parts {
        bytes.extend_from_slice(part.as_bytes());
    }
    ScriptBuf::from_bytes(bytes)
}

fn blake3_case(length: usize) -> Result<Value> {
    let data = message(length);
    let push = blake3_push_message_script_with_limb(&data, 29).compile();
    let plain = blake3_compute_script(length).compile();
    let compute = optimizer::optimize(plain.clone());
    let expected: [u8; 32] = *blake3::hash(&data).as_bytes();
    let mut wrong = expected;
    wrong[0] ^= 1;
    let (accepted, stack) = execute(&concat(&[
        &push,
        &compute,
        &blake3_verify_output_script(expected).compile(),
    ]))?;
    let (rejected, _) = execute(&concat(&[
        &push,
        &compute,
        &blake3_verify_output_script(wrong).compile(),
    ]))?;
    require(
        accepted && !rejected,
        &format!("BLAKE3 {length}-byte reference digest check"),
    )?;
    Ok(
        json!({"hash":"blake3","message_bytes":length,"blocks":length.div_ceil(64),
        "compute_script_bytes":compute.len(),"unoptimized_compute_script_bytes":plain.len(),
        "push_script_bytes":push.len(),"max_stack_items":stack,"reference_digest":hex::encode(expected),
        "correct_digest_accepted":accepted,"changed_digest_rejected":!rejected}),
    )
}

fn sha256_case(length: usize) -> Result<Value> {
    let data = message(length);
    let push = script! {
        for byte in data.iter().copied() {
            { byte }
        }
    }
    .compile();
    let compute = sha256_script(length).compile();
    let expected = sha256::Hash::hash(&data).to_byte_array();
    let verify = |digest: [u8; 32]| {
        script! {
            for byte in digest {
                { byte }
            }
            for _ in 0..32 {
                OP_TOALTSTACK
            }
            for i in 1..32 {
                { i }
                OP_ROLL
            }
            for _ in 0..32 {
                OP_FROMALTSTACK
                OP_EQUALVERIFY
            }
            OP_TRUE
        }
        .compile()
    };
    let mut wrong = expected;
    wrong[31] ^= 1;
    let (accepted, stack) = execute(&concat(&[&push, &compute, &verify(expected)]))?;
    let (rejected, _) = execute(&concat(&[&push, &compute, &verify(wrong)]))?;
    require(
        accepted && !rejected,
        &format!("SHA-256 {length}-byte reference digest check"),
    )?;
    Ok(
        json!({"hash":"sha256","message_bytes":length,"blocks":(length+9).div_ceil(64),
        "compute_script_bytes":compute.len(),"push_script_bytes":push.len(),"max_stack_items":stack,
        "reference_digest":hex::encode(expected),"correct_digest_accepted":accepted,
        "changed_digest_rejected":!rejected}),
    )
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    require(args.len() == 2, "usage: stark_hash_cost OUTPUT_JSON")?;
    let mut cases = Vec::new();
    for length in BLAKE3_LENGTHS {
        cases.push(blake3_case(length)?);
    }
    for length in SHA256_LENGTHS {
        cases.push(sha256_case(length)?);
    }
    let report = json!({"schema":"bitvm2-nova-stark-hash-cost/v1",
        "bitvm_revision":"c620dbfaacebdf778e765a6681985350389973b1",
        "interpreter_revision":"ba96bc2bd76774c9d1b011461cb79d983c2c43a1",
        "flags":{"context":"tapscript","require_minimal":true,"enforce_stack_limit":true,"op_cat":false},
        "cases":cases,"stark_verifier_executed":false,"merkle_path_executed":false,
        "proof_verified":false,"complete_bitvm2_verifier":false});
    fs::write(&args[1], serde_json::to_vec_pretty(&report)?)?;
    println!("{}", serde_json::to_string(&report)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn messages_are_deterministic_and_reference_digests_differ() {
        assert_eq!(message(3), vec![11, 48, 85]);
        assert_ne!(
            blake3::hash(&message(64)).as_bytes(),
            &sha256::Hash::hash(&message(64)).to_byte_array()
        );
    }
    #[test]
    fn one_blake3_block_matches_its_reference_under_the_stack_limit() {
        let row = blake3_case(64).unwrap();
        assert_eq!(row["correct_digest_accepted"], true);
        assert_eq!(row["changed_digest_rejected"], true);
        assert!(row["max_stack_items"].as_u64().unwrap() <= 1000);
    }
}
