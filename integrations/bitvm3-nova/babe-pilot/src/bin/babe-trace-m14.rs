//! Bounded compiler entry point for M14's complete final verifier.
//!
//! Every proof/key/statement pin must be supplied independently. A gate-cap
//! refusal creates no output artifact. This in-memory command deliberately has
//! a small default cap; the full M14 circuit requires a separate storage budget.
use std::{collections::BTreeMap, fs, io::Read, path::Path};

use anyhow::{bail, ensure, Context, Result};
use babe_pilot::trace::{self, digest, TraceDisputeSpec, TraceLimits, TracePublication};

fn hex32(s: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(s).context("invalid hex digest")?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("expected a 32-byte digest"))
}

fn bounded_file(path: &Path, limit: usize) -> Result<Vec<u8>> {
    ensure!(
        fs::metadata(path)?.is_file(),
        "input must be a regular file"
    );
    #[cfg(unix)]
    let file = {
        use rustix::fs::{open, Mode, OFlags};
        fs::File::from(open(
            path,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK | OFlags::NOFOLLOW,
            Mode::empty(),
        )?)
    };
    #[cfg(not(unix))]
    let file = fs::File::open(path)?;
    ensure!(
        file.metadata()?.is_file(),
        "opened input must be a regular file"
    );
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= limit, "input exceeds byte limit");
    Ok(bytes)
}

fn main() -> Result<()> {
    let mut args = BTreeMap::new();
    let mut argv = std::env::args().skip(1);
    while let Some(flag) = argv.next() {
        ensure!(flag.starts_with("--"), "expected --flag value");
        let value = argv.next().context("missing flag value")?;
        ensure!(args.insert(flag, value).is_none(), "duplicate flag");
    }
    let required = |key: &str| -> Result<&str> {
        args.get(key)
            .map(String::as_str)
            .with_context(|| format!("missing {key}"))
    };
    for key in args.keys() {
        if ![
            "--reference",
            "--reference-sha256",
            "--proof",
            "--proof-sha256",
            "--statement",
            "--statement-sha256",
            "--session",
            "--max-gates",
            "--output",
        ]
        .contains(&key.as_str())
        {
            bail!("unknown option {key}");
        }
    }
    let limits = TraceLimits {
        max_gates: args
            .get("--max-gates")
            .map(|s| s.parse())
            .transpose()?
            .unwrap_or(100_000),
        ..TraceLimits::default()
    };
    let reference = bounded_file(Path::new(required("--reference")?), limits.max_proof_bytes)?;
    let proof = bounded_file(Path::new(required("--proof")?), limits.max_proof_bytes)?;
    let statement = bounded_file(Path::new(required("--statement")?), 16 * 1024)?;
    let session = hex32(required("--session")?)?;
    let output = Path::new(required("--output")?);
    ensure!(!output.exists(), "output already exists");
    let (program, inputs) = trace::m14::compile(
        &reference,
        hex32(required("--reference-sha256")?)?,
        &proof,
        hex32(required("--proof-sha256")?)?,
        &statement,
        hex32(required("--statement-sha256")?)?,
        limits,
    )?;
    let values = program.execute(&inputs)?;
    let (claim, publication) = TracePublication::create(&program, &inputs, session, &values)?;
    let spec = TraceDisputeSpec::new(&program, &inputs, session, &claim)?;
    let available = trace::verify_publication(&program, &spec, &publication)?;
    let first_refutation = available.first_refutation(&program)?;
    let manifest = serde_json::json!({
        "scope": "complete M14 Boolean verifier trace; Bitcoin funding is a separate step",
        "program": program.pin(), "specification": spec,
        "proof_sha256": hex::encode(digest(&proof)),
        "local_check_input_bits": spec.input_bits(),
        "first_refutation": first_refutation,
        "publication": publication,
    });
    // Create only after compilation, full publication validation and local
    // search completed. create_new prevents replacing an existing artifact.
    use std::io::Write;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)?;
    serde_json::to_writer(&mut file, &manifest)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    println!(
        "Wrote complete M14 trace: {} wires, {} checks",
        program.pin().wire_count,
        program.pin().check_count
    );
    Ok(())
}
