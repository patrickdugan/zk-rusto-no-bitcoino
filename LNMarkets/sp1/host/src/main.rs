//! Optional SP1 6.9.0 host. Default invocation prints usage and performs no work.
//! The local runner documents every command; full proving needs an explicit flag.

use anyhow::{bail, ensure, Context, Result};
use bincode::Options;
use lnm_batch_statement::{verify_batch_bytes, JOURNAL_LEN, MAX_WITNESS_BYTES};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sp1_sdk::{
    Elf, HashableKey, ProveRequest, Prover, ProverClient, ProvingKey, SP1Proof,
    SP1ProofWithPublicValues, SP1Stdin,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::Path,
    time::Instant,
};

const SP1_VERSION: &str = "6.9.0";
const MAX_ELF_BYTES: usize = 64 * 1024 * 1024;
const MAX_PROOF_BYTES: usize = 64 * 1024 * 1024;
const USAGE: &str = "lnm-sp1-host COMMAND [OPTIONS]\n\
  describe-program --elf FILE --report FILE\n\
  execute --witness FILE <pins> --report FILE\n\
  prove-groth16 --witness FILE <pins> --proof FILE --report FILE --allow-cpu-proving\n\
  verify-proof <pins> --proof FILE --mode compressed|groth16 --report FILE\n\
  <pins>: --elf FILE --expect-elf-sha256 HEX --expect-program-vk HEX\n\
          --journal FILE --expect-journal-sha256 HEX\n\
describe-program emits candidate pins for independent review. Every other command\n\
requires approved pins and the exact expected public journal. Output files must\n\
be new. See LNMarkets/sp1/README.md for the local proof workflow.";

struct Args {
    command: String,
    values: BTreeMap<String, String>,
    switches: BTreeSet<String>,
}

impl Args {
    fn parse() -> Result<Self> {
        let mut iter = std::env::args().skip(1);
        let command = iter.next().unwrap_or_else(|| "help".into());
        let allowed: &[&str] = match command.as_str() {
            "help" | "--help" | "-h" => &[],
            "describe-program" => &["--elf", "--report"],
            "execute" => &[
                "--elf",
                "--report",
                "--witness",
                "--journal",
                "--expect-elf-sha256",
                "--expect-program-vk",
                "--expect-journal-sha256",
            ],
            "prove-groth16" => &[
                "--elf",
                "--report",
                "--witness",
                "--journal",
                "--expect-elf-sha256",
                "--expect-program-vk",
                "--expect-journal-sha256",
                "--proof",
                "--allow-cpu-proving",
            ],
            "verify-proof" => &[
                "--elf",
                "--report",
                "--journal",
                "--expect-elf-sha256",
                "--expect-program-vk",
                "--expect-journal-sha256",
                "--proof",
                "--mode",
            ],
            _ => bail!("unknown command {command}\n{USAGE}"),
        };
        let mut args = Self {
            command,
            values: BTreeMap::new(),
            switches: BTreeSet::new(),
        };
        while let Some(flag) = iter.next() {
            ensure!(allowed.contains(&flag.as_str()), "unknown option {flag}");
            if flag == "--allow-cpu-proving" {
                ensure!(args.switches.insert(flag), "duplicate proving switch");
            } else {
                let value = iter
                    .next()
                    .with_context(|| format!("missing value for {flag}"))?;
                ensure!(!value.starts_with("--"), "missing value for {flag}");
                ensure!(
                    args.values.insert(flag.clone(), value).is_none(),
                    "duplicate {flag}"
                );
            }
        }
        Ok(args)
    }

    fn need(&self, name: &str) -> Result<&str> {
        self.values
            .get(name)
            .map(String::as_str)
            .with_context(|| format!("missing {name}"))
    }
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn pin(value: &str) -> Result<String> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    ensure!(
        value.len() == 64 && value.bytes().all(|c| c.is_ascii_hexdigit()),
        "pin must be 32 hex bytes"
    );
    Ok(value.to_ascii_lowercase())
}

fn read_bounded(path: &str, cap: usize) -> Result<Vec<u8>> {
    let file = File::open(path).with_context(|| format!("open {path}"))?;
    let metadata = file.metadata()?;
    ensure!(metadata.is_file(), "expected a regular file: {path}");
    ensure!(
        metadata.len() <= cap as u64,
        "{path} exceeds {cap} byte cap"
    );
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(cap as u64 + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= cap, "{path} grew past its byte cap");
    Ok(bytes)
}

fn ensure_new_output(path: &str) -> Result<()> {
    ensure!(!Path::new(path).exists(), "output already exists: {path}");
    let parent = Path::new(path)
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    ensure!(
        parent.is_dir(),
        "create output directory first: {}",
        parent.display()
    );
    Ok(())
}

fn write_new_private(path: &str, bytes: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("create {path}"))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn emit_report(path: &str, report: &Value) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(report)?;
    write_new_private(path, &bytes)?;
    println!("{}", String::from_utf8(bytes)?);
    Ok(())
}

fn stdin(witness: &[u8]) -> SP1Stdin {
    let mut input = SP1Stdin::new();
    input.write_vec(witness.to_vec());
    input
}

fn checked_proof_mode(proof: &SP1ProofWithPublicValues, expected: &str) -> Result<()> {
    ensure!(
        proof.tee_proof.is_none(),
        "TEE envelopes are outside this local proof interface"
    );
    match (&proof.proof, expected) {
        (SP1Proof::Compressed(_), "compressed") => Ok(()),
        (SP1Proof::Groth16(p), "groth16") => {
            ensure!(
                !p.encoded_proof.is_empty(),
                "empty/mock Groth16 proof rejected"
            );
            hex::decode(&p.encoded_proof).context("malformed Groth16 encoding")?;
            Ok(())
        }
        _ => bail!("proof mode differs from the requested compressed/groth16 mode"),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse()?;
    if matches!(args.command.as_str(), "help" | "--help" | "-h") {
        println!("{USAGE}");
        return Ok(());
    }
    for variable in [
        "SP1_DUMP",
        "SP1_RECORD_WRITE_DIR",
        "SP1_RECORD_MAX_ARITY_INPUT",
        "SP1_RECORD_SHRINK_INPUT",
    ] {
        ensure!(
            std::env::var_os(variable).is_none(),
            "unset {variable} before handling private witnesses"
        );
    }
    ensure!(
        std::env::var("SP1_CIRCUIT_MODE")
            .map(|mode| mode == "release")
            .unwrap_or_else(|error| matches!(error, std::env::VarError::NotPresent)),
        "SP1_CIRCUIT_MODE must be unset or release; development circuit verification is unsupported"
    );
    let report_path = args.need("--report")?;
    ensure_new_output(report_path)?;
    if args.command == "prove-groth16" {
        ensure!(
            args.switches.contains("--allow-cpu-proving"),
            "full proving requires --allow-cpu-proving"
        );
        ensure_new_output(args.need("--proof")?)?;
        ensure!(
            args.need("--proof")? != report_path,
            "proof and report paths must differ"
        );
    }
    let elf_bytes = read_bounded(args.need("--elf")?, MAX_ELF_BYTES)?;
    ensure!(elf_bytes.starts_with(b"\x7fELF"), "ELF magic mismatch");
    let elf_sha256 = sha256(&elf_bytes);
    let elf = Elf::from(elf_bytes);
    let is_description = args.command == "describe-program";
    let expected_journal = if is_description {
        Vec::new()
    } else {
        ensure!(
            elf_sha256 == pin(args.need("--expect-elf-sha256")?)?,
            "ELF hash differs from approved pin"
        );
        let journal = read_bounded(args.need("--journal")?, JOURNAL_LEN)?;
        ensure!(
            journal.len() == JOURNAL_LEN,
            "expected journal length differs from the schema"
        );
        ensure!(
            sha256(&journal) == pin(args.need("--expect-journal-sha256")?)?,
            "expected journal differs from its approved digest"
        );
        journal
    };

    // LightProver uses real cryptographic verification. SDK network support is
    // disabled, and no client is selected through SP1_PROVER/from_env.
    let setup_started = Instant::now();
    let client = ProverClient::builder().light().build().await;
    let pk = client.setup(elf.clone()).await?;
    let setup_seconds = setup_started.elapsed().as_secs_f64();
    let vk = pk.verifying_key();
    let vk_bytes: Vec<u8> = vk.hash_u32().iter().flat_map(|v| v.to_le_bytes()).collect();
    let vk_digest = hex::encode(vk_bytes);
    let mut report = json!({
        "schema": "lnm-sp1-local-run/v1",
        "sp1_sdk_version": SP1_VERSION,
        "sp1_circuit_mode": "release",
        "elf_sha256": elf_sha256,
        "program_vk_digest": vk_digest,
        "program_vkey_bytes32": vk.bytes32(),
        "setup_seconds": setup_seconds,
        "backend": "local_cpu_light",
        "proof_mode": "none",
        "zero_knowledge_proof_verified": false,
        "statement_scope": "bilateral_batch_authorization_and_nullifier_transition",
        "bitcoin_spendability_verified": false,
    });
    if is_description {
        report["status"] = json!("candidate_program_pins_for_review");
        return emit_report(report_path, &report);
    }
    ensure!(
        vk_digest == pin(args.need("--expect-program-vk")?)?,
        "program verification key differs from approved pin"
    );
    report["expected_journal_sha256"] = json!(sha256(&expected_journal));
    report["journal_bytes"] = json!(expected_journal.len());

    if args.command == "verify-proof" {
        let mode = args.need("--mode")?;
        ensure!(
            matches!(mode, "compressed" | "groth16"),
            "unsupported proof mode"
        );
        let bytes = read_bounded(args.need("--proof")?, MAX_PROOF_BYTES)?;
        // SP1 save uses bincode's legacy fixed-int encoding. Apply a byte budget
        // and reject trailing data when reading an externally supplied proof.
        let proof: SP1ProofWithPublicValues = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_limit(MAX_PROOF_BYTES as u64)
            .reject_trailing_bytes()
            .deserialize(&bytes)
            .context("decode bounded SP1 proof")?;
        checked_proof_mode(&proof, mode)?;
        ensure!(
            proof.public_values.as_slice() == expected_journal,
            "proof public journal differs from the expected bytes"
        );
        let started = Instant::now();
        client
            .verify(&proof, vk, None)
            .context("cryptographic proof verification failed")?;
        report["verify_seconds"] = json!(started.elapsed().as_secs_f64());
        report["status"] = json!(if mode == "groth16" {
            "groth16_proof_verified"
        } else {
            "compressed_proof_verified_not_zk"
        });
        report["proof_mode"] = json!(mode);
        report["zero_knowledge_proof_verified"] = json!(mode == "groth16");
        report["proof_sha256"] = json!(sha256(&bytes));
        report["proof_bytes"] = json!(bytes.len());
        return emit_report(report_path, &report);
    }

    let witness = read_bounded(args.need("--witness")?, MAX_WITNESS_BYTES)?;
    let native_started = Instant::now();
    let native_journal = verify_batch_bytes(&witness).map_err(anyhow::Error::msg)?;
    ensure!(
        native_journal == expected_journal,
        "native relation journal differs from the expected bytes"
    );
    report["native_verify_seconds"] = json!(native_started.elapsed().as_secs_f64());
    report["input_sha256"] = json!(sha256(&witness));
    report["input_bytes"] = json!(witness.len());

    let execute_started = Instant::now();
    let (public_values, execution) = client.execute(elf.clone(), stdin(&witness)).await?;
    ensure!(
        execution.exit_code == 0,
        "guest failed with exit code {}",
        execution.exit_code
    );
    ensure!(
        public_values.as_slice() == expected_journal,
        "guest journal differs from the expected bytes"
    );
    report["execute_seconds"] = json!(execute_started.elapsed().as_secs_f64());
    report["instruction_count"] = json!(execution.total_instruction_count());
    report["syscall_count"] = json!(execution.total_syscall_count());
    report["exit_code"] = json!(execution.exit_code);
    if args.command == "execute" {
        report["status"] = json!("executed_unproved");
        return emit_report(report_path, &report);
    }

    // This is an explicit full CPU proof, including SP1's Groth16 wrapper. It
    // reruns proving and does not import nb3-prove's compressed checkpoint.
    let cpu_started = Instant::now();
    let cpu = ProverClient::builder().cpu().build().await;
    let cpu_pk = cpu.setup(elf).await?;
    ensure!(
        cpu_pk.verifying_key().hash_u32() == vk.hash_u32(),
        "CPU/light program key mismatch"
    );
    report["cpu_setup_seconds"] = json!(cpu_started.elapsed().as_secs_f64());
    let prove_started = Instant::now();
    let proof = cpu.prove(&cpu_pk, stdin(&witness)).groth16().await?;
    report["prove_seconds"] = json!(prove_started.elapsed().as_secs_f64());
    checked_proof_mode(&proof, "groth16")?;
    ensure!(
        proof.public_values.as_slice() == expected_journal,
        "proven journal differs from the expected bytes"
    );
    let verify_started = Instant::now();
    client
        .verify(&proof, vk, None)
        .context("Groth16 cryptographic verification failed")?;
    report["verify_seconds"] = json!(verify_started.elapsed().as_secs_f64());
    let proof_bytes = bincode::serialize(&proof)?;
    ensure!(
        proof_bytes.len() <= MAX_PROOF_BYTES,
        "proof bundle exceeds local cap"
    );
    write_new_private(args.need("--proof")?, &proof_bytes)?;
    report["status"] = json!("groth16_proof_verified");
    report["backend"] = json!("local_cpu");
    report["proof_mode"] = json!("groth16");
    report["zero_knowledge_proof_verified"] = json!(true);
    report["proof_sha256"] = json!(sha256(&proof_bytes));
    report["proof_bytes"] = json!(proof_bytes.len());
    report["groth16_wire_bytes"] = json!(proof.bytes().len());
    emit_report(report_path, &report)
}
