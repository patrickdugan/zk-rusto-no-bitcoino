//! Single-use, off-chain claim artifacts. This binds honest setup artifacts and role boundaries;
//! a malicious garbler still requires a separately verified setup protocol (for example C&C).
#![forbid(unsafe_code)]

pub mod io;

use std::{fs, path::Path};

use anyhow::{bail, ensure, Context, Result};
use garbled_snark_verifier::{
    circuit::{
        CiphertextHandler, CiphertextSource, CircuitBuilder, CircuitInput, CircuitMode,
        EncodeInput, EvaluateMode, StreamingMode, StreamingResult,
    },
    AesCcrGateHasher, EvaluatedWire, GarbleMode, GarbledWire, GateHasher, WireId, S,
};
use m13_statement::FinalStatement;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use io::{ArtifactWriter, CheckedReader};

pub const FORMAT: &str = "m14-claim-v1";
pub const MANIFEST: &str = "manifest.json";
pub const CIPHERTEXTS: &str = "ciphertexts.bin";
pub const INPUT_COMMITMENTS: &str = "input-commitments.bin";
pub const SELECTED_LABELS: &str = "selected-labels.bin";
pub const RELEASE: &str = "release.json";
const PRIVATE: &str = "private.json";
const RESERVATION: &str = "release-reservation.json";
const HASHER: &str = "gsv-aes-ccr-v1-le128";
const MAX_INPUT_BITS: u64 = 10_000_000;
const MAX_CIPHERTEXTS: u64 = 1_000_000_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CircuitSpec {
    pub id: String,
    pub source_sha256: [u8; 32],
    pub reference_sha256: [u8; 32],
    pub input_bits: u64,
    pub ciphertexts: u64,
}

impl CircuitSpec {
    fn validate(&self) -> Result<()> {
        ensure!(
            !self.id.is_empty() && self.id.len() <= 256,
            "invalid circuit ID"
        );
        ensure!(
            (1..=MAX_INPUT_BITS).contains(&self.input_bits),
            "unsupported input count"
        );
        ensure!(
            self.ciphertexts <= MAX_CIPHERTEXTS,
            "unsupported ciphertext count"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    pub bytes: u64,
    pub sha256: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub format: String,
    pub instance_id: [u8; 32],
    pub circuit: CircuitSpec,
    pub statement: FinalStatement,
    pub hasher: String,
    pub public_salt: [u8; 16],
    pub true_label: [u8; 16],
    pub false_label: [u8; 16],
    pub ciphertexts: Artifact,
    pub input_commitments: Artifact,
    pub accept_label_sha256: [u8; 32],
    pub reject_label_sha256: [u8; 32],
}

impl Manifest {
    pub fn validate(&self, supported: &CircuitSpec) -> Result<()> {
        ensure!(
            self.format == FORMAT && self.hasher == HASHER,
            "unsupported manifest version or hasher"
        );
        supported.validate()?;
        ensure!(
            self.circuit == *supported,
            "manifest circuit differs from the locally supported circuit"
        );
        self.statement.validate()?;
        ensure!(
            self.ciphertexts.bytes == supported.ciphertexts * 16,
            "ciphertext count mismatch"
        );
        ensure!(
            self.input_commitments.bytes == supported.input_bits * 64,
            "input commitment count mismatch"
        );
        ensure!(
            self.accept_label_sha256 != self.reject_label_sha256,
            "output commitments coincide"
        );
        Ok(())
    }

    /// Canonical v1 encoding: compact serde JSON in this struct's declared field order, with
    /// byte arrays encoded as decimal arrays and no optional fields, prefixed by this domain.
    /// The caller pins the resulting hash through an authenticated channel outside the artifact.
    pub fn digest(&self) -> Result<[u8; 32]> {
        let mut hash = Sha256::new();
        hash.update(b"m14-claim/manifest/v1\0");
        hash.update(serde_json::to_vec(self)?);
        Ok(hash.finalize().into())
    }
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct PrivateState {
    format: String,
    instance_id: [u8; 32],
    manifest_sha256: [u8; 32],
    seed: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Binding {
    format: String,
    instance_id: [u8; 32],
    manifest_sha256: [u8; 32],
    proof_sha256: [u8; 32],
    input_sha256: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Release {
    binding: Binding,
    pub labels: Artifact,
}

impl Release {
    /// Authenticate this header independently of the files it accompanies. Input commitments
    /// bind circuit bits; this additional pin binds the exact proof file, including derived
    /// fields that the circuit does not consume as inputs.
    pub fn digest(&self) -> Result<[u8; 32]> {
        let mut hash = Sha256::new();
        hash.update(b"m14-claim/release/v1\0");
        hash.update(serde_json::to_vec(self)?);
        Ok(hash.finalize().into())
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evaluation {
    pub format: String,
    pub instance_id: [u8; 32],
    pub manifest_sha256: [u8; 32],
    pub release_sha256: [u8; 32],
    pub proof_sha256: [u8; 32],
    pub input_sha256: [u8; 32],
    pub verdict: String,
    pub output_label: [u8; 16],
    pub output_label_sha256: [u8; 32],
    pub ciphertexts: u64,
}

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

pub fn parse_pin(value: &str) -> Result<[u8; 32]> {
    ensure!(value.len() == 64, "pin must contain 64 hex characters");
    let mut out = [0; 32];
    hex::decode_to_slice(value, &mut out)?;
    Ok(out)
}

pub fn load_manifest(public: &Path, pin: [u8; 32], supported: &CircuitSpec) -> Result<Manifest> {
    let manifest: Manifest = io::read_json(&public.join(MANIFEST))?;
    manifest.validate(supported)?;
    ensure!(
        manifest.digest()? == pin,
        "manifest hash differs from the independently supplied pin"
    );
    Ok(manifest)
}

pub fn verify_artifacts(
    public: &Path,
    manifest: &Manifest,
    supported: &CircuitSpec,
    pin: [u8; 32],
) -> Result<()> {
    manifest.validate(supported)?;
    ensure!(
        manifest.digest()? == pin,
        "manifest hash differs from the independently supplied pin"
    );
    for (name, expected) in [
        (CIPHERTEXTS, &manifest.ciphertexts),
        (INPUT_COMMITMENTS, &manifest.input_commitments),
    ] {
        CheckedReader::open(&public.join(name), expected)?.preflight()?;
    }
    Ok(())
}

fn input_digest(bits: &[bool]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"m14-claim/input-bits/v1\0");
    h.update((bits.len() as u64).to_le_bytes());
    // Explicit little-endian bit packing; the final byte's unused high bits are zero.
    for chunk in bits.chunks(8) {
        let byte = chunk
            .iter()
            .enumerate()
            .fold(0, |out, (i, bit)| out | (u8::from(*bit) << i));
        h.update([byte]);
    }
    h.finalize().into()
}

fn label_commitment(instance: &[u8; 32], index: u64, bit: bool, label: S) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"m14-claim/input-label/v1\0");
    h.update(instance);
    h.update(index.to_le_bytes());
    h.update([u8::from(bit)]);
    h.update(label.to_le_bytes());
    h.finalize().into()
}

fn binding(
    manifest: &Manifest,
    supported: &CircuitSpec,
    pin: [u8; 32],
    proof_sha256: [u8; 32],
    bits: &[bool],
) -> Result<Binding> {
    manifest.validate(supported)?;
    ensure!(
        bits.len() as u64 == manifest.circuit.input_bits,
        "proof input count mismatch"
    );
    ensure!(manifest.digest()? == pin, "manifest pin mismatch");
    Ok(Binding {
        format: FORMAT.into(),
        instance_id: manifest.instance_id,
        manifest_sha256: pin,
        proof_sha256,
        input_sha256: input_digest(bits),
    })
}

struct GIn(usize);
impl CircuitInput for GIn {
    type WireRepr = Vec<WireId>;
    fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
        (0..self.0).map(|_| issue()).collect()
    }
    fn collect_wire_ids(w: &Self::WireRepr) -> Vec<WireId> {
        w.clone()
    }
}
impl<H: GateHasher, C: CiphertextHandler> EncodeInput<GarbleMode<H, C>> for GIn {
    fn encode(&self, wires: &Self::WireRepr, mode: &mut GarbleMode<H, C>) {
        for id in wires {
            let value = mode.issue_garbled_wire();
            mode.feed_wire(*id, value);
        }
    }
}

// This type cannot carry a pair of garbled labels. The bit is obtained from the bound proof.
struct EIn<'a> {
    labels: Vec<S>,
    bits: &'a [bool],
}
impl CircuitInput for EIn<'_> {
    type WireRepr = Vec<WireId>;
    fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
        (0..self.bits.len()).map(|_| issue()).collect()
    }
    fn collect_wire_ids(w: &Self::WireRepr) -> Vec<WireId> {
        w.clone()
    }
}
impl<H: GateHasher, C: CiphertextSource> EncodeInput<EvaluateMode<H, C>> for EIn<'_> {
    fn encode(&self, wires: &Self::WireRepr, mode: &mut EvaluateMode<H, C>) {
        for (index, id) in wires.iter().enumerate() {
            mode.feed_wire(
                *id,
                EvaluatedWire::new(self.labels[index], self.bits[index]),
            );
        }
    }
}

#[derive(Debug)]
pub struct IoResult<T>(Result<T>);
impl<T> Default for IoResult<T> {
    fn default() -> Self {
        Self(Err(anyhow::anyhow!("artifact stream was not finalized")))
    }
}

pub struct CiphertextWriter {
    writer: ArtifactWriter,
    error: Option<anyhow::Error>,
}
impl CiphertextHandler for CiphertextWriter {
    type Result = IoResult<Artifact>;
    fn handle(&mut self, ct: S) {
        if self.error.is_none() {
            if let Err(error) = self.writer.write(&ct.to_le_bytes()) {
                self.error = Some(error);
            }
        }
    }
    fn finalize(self) -> Self::Result {
        if let Some(error) = self.error {
            return IoResult(Err(error));
        }
        IoResult(self.writer.finish())
    }
}

pub struct CiphertextReader {
    reader: CheckedReader,
    error: Option<anyhow::Error>,
}
impl CiphertextSource for CiphertextReader {
    type Result = IoResult<()>;
    fn recv(&mut self) -> Option<S> {
        // The dependency's evaluator panics on None. Preserve IO failures and feed a dummy label
        // so finalization can return a normal error before any output label/report is exposed.
        let mut bytes = [0; 16];
        if self.error.is_none() {
            if let Err(error) = self.reader.read_exact(&mut bytes) {
                self.error = Some(error);
            }
        }
        Some(S::from_le_bytes(bytes))
    }
    fn finalize(self) -> Self::Result {
        if let Some(error) = self.error {
            return IoResult(Err(error));
        }
        IoResult(self.reader.finish())
    }
}

pub type Garbler = StreamingMode<GarbleMode<AesCcrGateHasher, CiphertextWriter>>;
pub type Evaluator = StreamingMode<EvaluateMode<AesCcrGateHasher, CiphertextReader>>;

pub fn setup<F>(
    public: &Path,
    private: &Path,
    statement: FinalStatement,
    spec: CircuitSpec,
    capacity: usize,
    circuit: F,
) -> Result<Manifest>
where
    F: Fn(&mut Garbler, &Vec<WireId>) -> Vec<WireId>,
{
    statement.validate()?;
    spec.validate()?;
    fs::create_dir(public).context("public output directory must be new")?;
    let public_absolute = public.canonicalize()?;
    let private_parent = io::parent_directory(private).canonicalize()?;
    ensure!(
        !private_parent.starts_with(&public_absolute),
        "private state must be outside the public artifact directory"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new()
            .mode(0o700)
            .create(private)
            .context("private output directory must be new")?;
    }
    #[cfg(not(unix))]
    bail!("private claim setup currently requires Unix file permissions");
    let mut seed = Zeroizing::new([0; 32]);
    let mut instance_id = [0; 32];
    OsRng
        .try_fill_bytes(&mut *seed)
        .context("OS randomness for garbler seed")?;
    OsRng
        .try_fill_bytes(&mut instance_id)
        .context("OS randomness for instance ID")?;
    let handler = CiphertextWriter {
        writer: ArtifactWriter::new(&public.join(CIPHERTEXTS))?,
        error: None,
    };
    let mode = GarbleMode::<AesCcrGateHasher, _>::new_with_seed(capacity, *seed, handler);
    let public_salt = mode.gate_hasher_seed().to_le_bytes();
    let garbled: StreamingResult<_, _, Vec<GarbledWire>> =
        CircuitBuilder::run_streaming(GIn(spec.input_bits as usize), mode, circuit);
    ensure!(
        garbled.output_value.len() == 1,
        "claim circuit must have one output"
    );
    ensure!(
        garbled.gate_count.nonfree_gate_count() as u64 == spec.ciphertexts,
        "circuit ciphertext count changed"
    );
    let ciphertexts = garbled.ciphertext_handler_result.0?;
    let mut commitments = ArtifactWriter::new(&public.join(INPUT_COMMITMENTS))?;
    for (index, wire) in garbled.input_wire_values.iter().enumerate() {
        for bit in [false, true] {
            commitments.write(&label_commitment(
                &instance_id,
                index as u64,
                bit,
                wire.select(bit),
            ))?;
        }
    }
    let out = &garbled.output_value[0];
    let manifest = Manifest {
        format: FORMAT.into(),
        instance_id,
        circuit: spec.clone(),
        statement,
        hasher: HASHER.into(),
        public_salt,
        true_label: garbled.true_wire_constant.select(true).to_le_bytes(),
        false_label: garbled.false_wire_constant.select(false).to_le_bytes(),
        ciphertexts,
        input_commitments: commitments.finish()?,
        accept_label_sha256: sha256(&out.select(true).to_le_bytes()),
        reject_label_sha256: sha256(&out.select(false).to_le_bytes()),
    };
    manifest.validate(&spec)?;
    io::write_json_new(
        &private.join(PRIVATE),
        &PrivateState {
            format: FORMAT.into(),
            instance_id,
            manifest_sha256: manifest.digest()?,
            seed: *seed,
        },
        true,
    )?;
    seed.zeroize();
    io::sync_directory(io::parent_directory(private))?;
    // Publish the manifest last. Interrupted setup cannot present a complete claim instance.
    io::sync_directory(public)?;
    io::write_json_new(&public.join(MANIFEST), &manifest, false)?;
    io::sync_directory(io::parent_directory(public))?;
    Ok(manifest)
}

fn reserve(private: &Path, wanted: &Binding) -> Result<()> {
    io::verify_private_directory(private)?;
    let path = private.join(RESERVATION);
    match io::create_new(&path, true) {
        Ok(mut file) => {
            serde_json::to_writer(&mut file, wanted)?;
            file.sync_all()?;
        }
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::AlreadyExists) =>
        {
            io::verify_private_file(&path)?;
            let existing: Binding = io::read_json(&path)
                .context("release reservation is incomplete; instance remains locked")?;
            ensure!(
                &existing == wanted,
                "this instance already released/reserved labels for a different proof"
            );
            // A concurrent same-proof retry also persists the original record before using it.
            io::open_regular(&path)?.sync_all()?;
        }
        Err(error) => return Err(error),
    }
    io::sync_directory(private)
}

pub fn release(
    public: &Path,
    private: &Path,
    out: &Path,
    manifest: &Manifest,
    supported: &CircuitSpec,
    pin: [u8; 32],
    proof_sha256: [u8; 32],
    bits: &[bool],
) -> Result<Release> {
    let wanted = binding(manifest, supported, pin, proof_sha256, bits)?;
    io::verify_private_directory(private)?;
    let state: PrivateState = io::read_json_private(&private.join(PRIVATE))?;
    ensure!(
        state.format == FORMAT
            && state.instance_id == manifest.instance_id
            && state.manifest_sha256 == pin,
        "private state belongs to another manifest"
    );
    let mut mode = GarbleMode::<AesCcrGateHasher, ()>::new_with_seed(1, state.seed, ());
    ensure!(
        mode.gate_hasher_seed().to_le_bytes() == manifest.public_salt
            && mode.true_value().select(true).to_le_bytes() == manifest.true_label
            && mode.false_value().select(false).to_le_bytes() == manifest.false_label,
        "private seed does not match public parameters"
    );
    let mut commitments =
        CheckedReader::open(&public.join(INPUT_COMMITMENTS), &manifest.input_commitments)?;
    commitments.preflight()?;
    // This durable reservation precedes the first externally visible selected label.
    reserve(private, &wanted)?;
    fs::create_dir(out).context(
        "release output directory must be new (same-proof retries may use another directory)",
    )?;
    let mut labels = ArtifactWriter::new(&out.join(SELECTED_LABELS))?;
    for (index, bit) in bits.iter().enumerate() {
        let wire = mode.issue_garbled_wire();
        let mut committed = [0; 64];
        commitments.read_exact(&mut committed)?;
        for choice in [false, true] {
            let offset = usize::from(choice) * 32;
            ensure!(
                committed[offset..offset + 32]
                    == label_commitment(
                        &manifest.instance_id,
                        index as u64,
                        choice,
                        wire.select(choice)
                    ),
                "private input label differs from setup at wire {index}"
            );
        }
        labels.write(&wire.select(*bit).to_le_bytes())?;
    }
    commitments.finish()?;
    let released = Release {
        binding: wanted,
        labels: labels.finish()?,
    };
    io::sync_directory(out)?;
    io::write_json_new(&out.join(RELEASE), &released, false)?;
    io::sync_directory(io::parent_directory(out))?;
    Ok(released)
}

pub fn evaluate<F>(
    public: &Path,
    released: &Path,
    manifest: &Manifest,
    supported: &CircuitSpec,
    pin: [u8; 32],
    release_pin: [u8; 32],
    proof_sha256: [u8; 32],
    bits: &[bool],
    capacity: usize,
    circuit: F,
) -> Result<Evaluation>
where
    F: Fn(&mut Evaluator, &Vec<WireId>) -> Vec<WireId>,
{
    let wanted = binding(manifest, supported, pin, proof_sha256, bits)?;
    let released_info: Release = io::read_json(&released.join(RELEASE))?;
    ensure!(
        released_info.digest()? == release_pin,
        "release header differs from the independently supplied release pin"
    );
    ensure!(
        released_info.binding == wanted,
        "released labels belong to a different instance or proof"
    );
    ensure!(
        released_info.labels.bytes == manifest.circuit.input_bits * 16,
        "selected label count mismatch"
    );
    let mut selected = CheckedReader::open(&released.join(SELECTED_LABELS), &released_info.labels)?;
    let mut commitments =
        CheckedReader::open(&public.join(INPUT_COMMITMENTS), &manifest.input_commitments)?;
    let mut labels = Vec::with_capacity(bits.len());
    for (index, bit) in bits.iter().enumerate() {
        let mut label = [0; 16];
        let mut pair = [0; 64];
        selected.read_exact(&mut label)?;
        commitments.read_exact(&mut pair)?;
        let label = S::from_le_bytes(label);
        let offset = usize::from(*bit) * 32;
        ensure!(
            pair[offset..offset + 32]
                == label_commitment(&manifest.instance_id, index as u64, *bit, label),
            "selected label does not match proof bit at wire {index}"
        );
        labels.push(label);
    }
    selected.finish()?;
    commitments.finish()?;
    let mut reader = CheckedReader::open(&public.join(CIPHERTEXTS), &manifest.ciphertexts)?;
    reader.preflight()?;
    let evaluated: StreamingResult<_, _, Vec<EvaluatedWire>> = CircuitBuilder::streaming_evaluation(
        EIn { labels, bits },
        capacity,
        u128::from_le_bytes(manifest.true_label),
        u128::from_le_bytes(manifest.false_label),
        AesCcrGateHasher::from_seed(S::from_le_bytes(manifest.public_salt)),
        CiphertextReader {
            reader,
            error: None,
        },
        circuit,
    );
    evaluated.ciphertext_handler_result.0?;
    ensure!(
        evaluated.gate_count.nonfree_gate_count() as u64 == manifest.circuit.ciphertexts,
        "evaluated circuit gate count changed"
    );
    ensure!(
        evaluated.output_value.len() == 1,
        "claim circuit must have one output"
    );
    let output_label = evaluated.output_value[0].active_label.to_le_bytes();
    let output_label_sha256 = sha256(&output_label);
    let verdict = if output_label_sha256 == manifest.accept_label_sha256 {
        "accept"
    } else if output_label_sha256 == manifest.reject_label_sha256 {
        "reject"
    } else {
        bail!("output label opens neither committed outcome");
    };
    Ok(Evaluation {
        format: FORMAT.into(),
        instance_id: manifest.instance_id,
        manifest_sha256: pin,
        release_sha256: release_pin,
        proof_sha256,
        input_sha256: wanted.input_sha256,
        verdict: verdict.into(),
        output_label,
        output_label_sha256,
        ciphertexts: manifest.circuit.ciphertexts,
    })
}
