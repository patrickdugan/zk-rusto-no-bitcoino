//! M14 claim artifact CLI. See ../../README.md and the claim crate's SECURITY.md.
use std::{io::Read, path::Path};

use anyhow::{ensure, Context, Result};
use m14_claim::{self as claim, CircuitSpec};
use m14_e2e::{
    full::{self, Known},
    native,
};
use sha2::{Digest, Sha256};

const CAPACITY: usize = 1 << 24;
const INPUT_BITS: u64 = 8_635_080;
const CIPHERTEXTS: u64 = 785_442_492;
const REFERENCE: &[u8] = include_bytes!("../../../../m13/fixtures/c4-wrap-blake3-v2.bin");
const USAGE: &str = "usage:
  m14-claim setup STATEMENT.json PUBLIC_DIR PRIVATE_DIR
  m14-claim verify-artifacts PUBLIC_DIR MANIFEST_SHA256
  m14-claim release PUBLIC_DIR MANIFEST_SHA256 PRIVATE_DIR PROOF.bin RELEASE_DIR
  m14-claim evaluate PUBLIC_DIR MANIFEST_SHA256 PROOF.bin RELEASE_DIR RELEASE_SHA256 REPORT.json

Output directories/files must be new. Keep PRIVATE_DIR with the garbler.
Supply MANIFEST_SHA256 from the agreed setup and RELEASE_SHA256 from the agreed release,\nindependently of the artifact directories.";

fn spec() -> CircuitSpec {
    // Length-prefixed source files, in this fixed order, bind the code that constructs the
    // verifier, its arithmetic and transcript, the claim transport, and resolved dependencies.
    // This is intentionally build-specific: participants agree on one build before setup.
    let sources: &[&[u8]] = &[
        include_bytes!("m14-claim.rs"),
        include_bytes!("../lib.rs"),
        include_bytes!("../full.rs"),
        include_bytes!("../verifier.rs"),
        include_bytes!("../pcs.rs"),
        include_bytes!("../native.rs"),
        include_bytes!("../../../circuit/src/lib.rs"),
        include_bytes!("../../../circuit/src/field.rs"),
        include_bytes!("../../../circuit/src/ext.rs"),
        include_bytes!("../../../circuit/src/hash.rs"),
        include_bytes!("../../../circuit/src/sample.rs"),
        include_bytes!("../../../circuit/src/sumcheck.rs"),
        include_bytes!("../../../circuit/src/multilinear.rs"),
        include_bytes!("../../../../m12/gates/src/lib.rs"),
        include_bytes!("../../../../m13/verify/src/lib.rs"),
        include_bytes!("../../../../m13/verify/src/ctx.rs"),
        include_bytes!("../../../../m13/statement/src/lib.rs"),
        include_bytes!("../../../claim/src/lib.rs"),
        include_bytes!("../../../claim/src/io.rs"),
        include_bytes!("../../../claim/Cargo.toml"),
        include_bytes!("../../../circuit/Cargo.toml"),
        include_bytes!("../../../../m12/gates/Cargo.toml"),
        include_bytes!("../../../../m13/verify/Cargo.toml"),
        include_bytes!("../../../../m13/statement/Cargo.toml"),
        include_bytes!("../../Cargo.toml"),
        include_bytes!("../../Cargo.lock"),
    ];
    let mut hash = Sha256::new();
    hash.update(b"m14-claim/circuit-sources/v1\0");
    for source in sources {
        hash.update((source.len() as u64).to_le_bytes());
        hash.update(source);
    }
    CircuitSpec {
        id: "m14/sp1-6.9.0/blake3-v2/c4-shape/claim-v1".into(),
        source_sha256: hash.finalize().into(),
        reference_sha256: claim::sha256(REFERENCE),
        input_bits: INPUT_BITS,
        ciphertexts: CIPHERTEXTS,
    }
}

fn proof_input(path: &Path, reference: &native::Proof) -> Result<([u8; 32], Vec<bool>)> {
    let file =
        claim::io::open_regular(path).with_context(|| format!("open proof {}", path.display()))?;
    let mut bytes = Vec::new();
    file.take(native::MAX_PROOF_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= native::MAX_PROOF_BYTES as usize,
        "proof exceeds size limit"
    );
    let proof = native::try_decode(&bytes)?;
    native::validate_proof_shape(reference, &proof)?;
    let bits = native::bits(&full::items(&proof));
    ensure!(
        bits.len() as u64 == INPUT_BITS,
        "proof input count differs from the supported circuit"
    );
    Ok((claim::sha256(&bytes), bits))
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let command = args.get(1).map(String::as_str).context(USAGE)?;
    let expected = match command {
        "setup" => 5,
        "verify-artifacts" => 4,
        "release" => 7,
        "evaluate" => 8,
        _ => anyhow::bail!(USAGE),
    };
    ensure!(args.len() == expected, USAGE);
    let supported = spec();
    if command == "verify-artifacts" {
        let public = Path::new(&args[2]);
        let pin = claim::parse_pin(&args[3])?;
        let manifest = claim::load_manifest(public, pin, &supported)?;
        claim::verify_artifacts(public, &manifest)?;
        println!("verified artifacts for manifest {}", hex(&pin));
        return Ok(());
    }
    let reference = native::try_decode(REFERENCE).context("embedded reference proof")?;
    if command == "setup" {
        let statement = claim::io::read_json(Path::new(&args[2]))?;
        let known = Known::try_new(&reference, &statement)?;
        let manifest = claim::setup(
            Path::new(&args[3]),
            Path::new(&args[4]),
            statement,
            supported,
            CAPACITY,
            |c, w| vec![full::final_verifier(c, &known, w)],
        )?;
        println!("manifest_sha256={}", hex(&manifest.digest()?));
        return Ok(());
    }
    let public = Path::new(&args[2]);
    let pin = claim::parse_pin(&args[3])?;
    let manifest = claim::load_manifest(public, pin, &supported)?;
    let known = Known::try_new(&reference, &manifest.statement)?;
    if command == "release" {
        let (proof_hash, bits) = proof_input(Path::new(&args[5]), &reference)?;
        let released = claim::release(
            public,
            Path::new(&args[4]),
            Path::new(&args[6]),
            &manifest,
            &supported,
            pin,
            proof_hash,
            &bits,
        )?;
        println!("release_sha256={}", hex(&released.digest()?));
    } else {
        let (proof_hash, bits) = proof_input(Path::new(&args[4]), &reference)?;
        let report = claim::evaluate(
            public,
            Path::new(&args[5]),
            &manifest,
            &supported,
            pin,
            claim::parse_pin(&args[6])?,
            proof_hash,
            &bits,
            CAPACITY,
            |c, w| vec![full::final_verifier(c, &known, w)],
        )?;
        claim::io::write_json_new(Path::new(&args[7]), &report, false)?;
        println!(
            "{}: output_label_sha256={}",
            report.verdict,
            hex(&report.output_label_sha256)
        );
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
