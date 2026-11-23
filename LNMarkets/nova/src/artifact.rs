//! Bounded persistence for the limited LNMarkets Nova relation.
//!
//! The receiver supplies expected claims obtained independently of a received
//! bundle. Verification rebuilds the verifier key from this executable's exact
//! circuit and compares its digest before parsing a proof. Signature checks are
//! a native producer responsibility and are outside the proved relation.
#[cfg(panic = "abort")]
compile_error!(
    "LNMarkets proof verification requires panic=unwind for malformed-proof containment"
);

use crate::{initial_state, NovaSettlementStep, VerifiedNovaTrace, ROWS_MAX, STATE_ARITY};
use bincode::Options;
use ff::PrimeField;
use lnm_batch_statement::{
    decode_journal, sha256, verify_expected_journal, JournalPins, JOURNAL_LEN,
};
use m18_utxo_window::elem::{f_to_le, fu, F};
use nova_snark::nova::{CompressedSNARK, PublicParams, RecursiveSNARK, VerifierKey};
use nova_snark::provider::ipa_pc::EvaluationEngine;
use nova_snark::provider::{PallasEngine, VestaEngine};
use nova_snark::spartan::snark::RelaxedR1CSSNARK;
use nova_snark::traits::snark::RelaxedR1CSSNARKTrait;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;
use std::time::Instant;

pub type Pp = PublicParams<PallasEngine, VestaEngine, NovaSettlementStep>;
pub type Rs = RecursiveSNARK<PallasEngine, VestaEngine, NovaSettlementStep>;
pub type S1 = RelaxedR1CSSNARK<PallasEngine, EvaluationEngine<PallasEngine>>;
pub type S2 = RelaxedR1CSSNARK<VestaEngine, EvaluationEngine<VestaEngine>>;
pub type Cs = CompressedSNARK<PallasEngine, VestaEngine, NovaSettlementStep, S1, S2>;
pub type Vk = VerifierKey<PallasEngine, VestaEngine, NovaSettlementStep, S1, S2>;

pub use crate::RELATION_ID;
pub const NOVA_VERSION: &str = "0.76.0";
pub const MAX_PROOF_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_VK_SERIALIZED_BYTES: u64 = 512 * 1024 * 1024;
pub const MAX_METADATA_BYTES: usize = 32 * 1024;
const EXPECT_SCHEMA: &str = "lnmarkets-nova-expect/v2";
const BUNDLE_SCHEMA: &str = "lnmarkets-nova-bundle/v2";

/// Receiver-owned expected statement, prepared independently of a received proof.
/// The proof digest is intentionally absent: randomized proofs of the same claim
/// may differ. The verifier key identifies this exact circuit shape.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VerifierPins {
    pub schema: String,
    pub relation: String,
    pub nova_version: String,
    pub verifier_key_sha256: String,
    pub verifier_key_serialized_bytes: u64,
    pub journal_sha256: String,
    pub steps: u32,
    pub initial_state: [String; STATE_ARITY],
    pub final_state: [String; STATE_ARITY],
}

/// The manifest is untrusted metadata. Its claims must match receiver-owned pins.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BundleManifest {
    pub schema: String,
    pub proof_sha256: String,
    pub claim: VerifierPins,
}

/// The full Spartan key includes R1CS matrices. Only this streamed identity is
/// persisted; receivers build their own key from the compiled circuit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifierIdentity {
    pub sha256: String,
    pub serialized_bytes: u64,
}

struct HashWriter {
    hash: Sha256,
    bytes: u64,
    limit: u64,
}

impl Write for HashWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let next = self.bytes.checked_add(bytes.len() as u64).ok_or_else(|| {
            std::io::Error::other("verifier key serialization byte count overflow")
        })?;
        if next > self.limit {
            return Err(std::io::Error::other(
                "verifier key exceeds streamed byte limit",
            ));
        }
        self.hash.update(bytes);
        self.bytes = next;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn streamed_identity<T: Serialize>(value: &T, limit: u64) -> Result<VerifierIdentity, String> {
    let mut writer = HashWriter {
        hash: Sha256::new(),
        bytes: 0,
        limit,
    };
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(limit)
        .serialize_into(&mut writer, value)
        .map_err(|e| format!("streamed verifier key encoding: {e}"))?;
    Ok(VerifierIdentity {
        sha256: hex::encode(writer.hash.finalize()),
        serialized_bytes: writer.bytes,
    })
}

pub fn verifier_identity(vk: &Vk) -> Result<VerifierIdentity, String> {
    streamed_identity(vk, MAX_VK_SERIALIZED_BYTES)
}

pub fn setup_params() -> Result<Pp, String> {
    Pp::setup(
        &NovaSettlementStep::blank(),
        &*S1::ck_floor(),
        &*S2::ck_floor(),
    )
    .map_err(|e| format!("Nova setup: {e:?}"))
}

/// Fixint matches the existing artifact format; trailing data is rejected by
/// the matching decoder. Limits apply to both encoding and decoding.
pub fn serialize_bounded<T: Serialize>(value: &T, limit: usize) -> Result<Vec<u8>, String> {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(limit as u64)
        .serialize(value)
        .map_err(|e| format!("bounded binary encoding: {e}"))
}

pub fn decode_proof(bytes: &[u8]) -> Result<Cs, String> {
    if bytes.is_empty() || bytes.len() > MAX_PROOF_BYTES {
        return Err("proof size is outside the allowed range".into());
    }
    catch_unwind(AssertUnwindSafe(|| {
        bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_limit(MAX_PROOF_BYTES as u64)
            .reject_trailing_bytes()
            .deserialize(bytes)
            .map_err(|e| format!("invalid compressed proof encoding: {e}"))
    }))
    .map_err(|_| "malformed compressed proof caused decoder rejection".to_string())?
}

/// Nova 0.76 has unchecked internal vector assumptions on malformed proofs.
/// Keep upstream decode and verification panics inside a fail-closed boundary.
/// Rust builds must retain unwind panic behavior for this boundary to operate.
pub fn verify_proof_bytes(
    bytes: &[u8],
    vk: &Vk,
    steps: usize,
    initial: &[F],
) -> Result<Vec<F>, String> {
    let proof = decode_proof(bytes)?;
    verify_decoded_proof(&proof, vk, steps, initial)
}

fn verify_decoded_proof(
    proof: &Cs,
    vk: &Vk,
    steps: usize,
    initial: &[F],
) -> Result<Vec<F>, String> {
    if steps == 0 || steps > ROWS_MAX || initial.len() != STATE_ARITY {
        return Err("invalid proof step count or initial state arity".into());
    }
    catch_unwind(AssertUnwindSafe(|| {
        proof
            .verify(vk, steps, initial)
            .map_err(|e| format!("Nova compressed verification: {e:?}"))
    }))
    .map_err(|_| "malformed compressed proof caused verifier rejection".to_string())?
}

pub fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>, String> {
    let meta = fs::symlink_metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if !meta.is_file() || meta.file_type().is_symlink() {
        return Err(format!("{} must be a regular file", path.display()));
    }
    if meta.len() > limit as u64 {
        return Err(format!("{} exceeds the {limit}-byte limit", path.display()));
    }
    let file = File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    if bytes.len() > limit {
        return Err(format!("{} grew beyond the file limit", path.display()));
    }
    Ok(bytes)
}

pub fn write_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| format!("refusing to replace {}: {e}", path.display()))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|e| format!("{}: {e}", path.display()))
}

fn canonical_hash(text: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(text).map_err(|_| "expected canonical 32-byte hex".to_string())?;
    let result: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "expected exactly 32 bytes".to_string())?;
    if hex::encode(result) != text {
        return Err("hex must use canonical lowercase encoding".into());
    }
    Ok(result)
}

pub fn encode_state(state: &[F]) -> Result<[String; STATE_ARITY], String> {
    if state.len() != STATE_ARITY {
        return Err("expected exactly eight state elements".into());
    }
    Ok(std::array::from_fn(|i| hex::encode(f_to_le(&state[i]))))
}

fn decode_state(state: &[String; STATE_ARITY]) -> Result<Vec<F>, String> {
    state
        .iter()
        .map(|text| {
            let bytes = canonical_hash(text)?;
            let mut repr = <F as PrimeField>::Repr::default();
            repr.as_mut().copy_from_slice(&bytes);
            Option::<F>::from(F::from_repr(repr))
                .ok_or_else(|| "noncanonical Nova field element".into())
        })
        .collect()
}

impl VerifierPins {
    pub fn from_trace(trace: &VerifiedNovaTrace, vk: &VerifierIdentity) -> Result<Self, String> {
        let pins = Self {
            schema: EXPECT_SCHEMA.into(),
            relation: RELATION_ID.into(),
            nova_version: NOVA_VERSION.into(),
            verifier_key_sha256: vk.sha256.clone(),
            verifier_key_serialized_bytes: vk.serialized_bytes,
            journal_sha256: hex::encode(sha256(&trace.journal_bytes)),
            steps: trace.steps.len() as u32,
            initial_state: encode_state(&trace.initial)?,
            final_state: encode_state(&trace.final_state)?,
        };
        pins.validate()?;
        Ok(pins)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema != EXPECT_SCHEMA
            || self.relation != RELATION_ID
            || self.nova_version != NOVA_VERSION
        {
            return Err("unsupported expected-claim schema, relation or Nova version".into());
        }
        if self.steps == 0 || self.steps as usize > ROWS_MAX {
            return Err("expected row count must be in 1..32".into());
        }
        canonical_hash(&self.verifier_key_sha256)?;
        if self.verifier_key_serialized_bytes == 0
            || self.verifier_key_serialized_bytes > MAX_VK_SERIALIZED_BYTES
        {
            return Err("verifier key serialized size exceeds the streamed limit".into());
        }
        canonical_hash(&self.journal_sha256)?;
        decode_state(&self.initial_state)?;
        decode_state(&self.final_state)?;
        Ok(())
    }
}

pub fn read_pins(path: &Path) -> Result<VerifierPins, String> {
    let bytes = read_bounded(path, MAX_METADATA_BYTES)?;
    let pins: VerifierPins =
        serde_json::from_slice(&bytes).map_err(|e| format!("invalid expected claims: {e}"))?;
    pins.validate()?;
    Ok(pins)
}

pub fn write_pins(path: &Path, pins: &VerifierPins) -> Result<(), String> {
    pins.validate()?;
    write_new(
        path,
        &serde_json::to_vec_pretty(pins).map_err(|e| e.to_string())?,
    )
}

pub fn write_bundle(
    directory: &Path,
    trace: &VerifiedNovaTrace,
    proof_bytes: &[u8],
    vk: &VerifierIdentity,
) -> Result<VerifierPins, String> {
    if proof_bytes.is_empty() || proof_bytes.len() > MAX_PROOF_BYTES {
        return Err("proof exceeds artifact limits".into());
    }
    let pins = VerifierPins::from_trace(trace, vk)?;
    validate_journal_states(&trace.journal_bytes, &pins)?;
    let manifest = BundleManifest {
        schema: BUNDLE_SCHEMA.into(),
        proof_sha256: hex::encode(sha256(proof_bytes)),
        claim: pins.clone(),
    };
    let metadata = serde_json::to_vec_pretty(&manifest).map_err(|e| e.to_string())?;
    fs::create_dir(directory)
        .map_err(|e| format!("bundle directory must be new, {}: {e}", directory.display()))?;
    write_new(&directory.join("proof.bin"), proof_bytes)?;
    write_new(&directory.join("journal.bin"), &trace.journal_bytes)?;
    // Write the manifest last. A directory without it is an incomplete bundle.
    write_new(&directory.join("manifest.json"), &metadata)?;
    Ok(pins)
}

fn validate_journal_states(bytes: &[u8], pins: &VerifierPins) -> Result<(Vec<F>, Vec<F>), String> {
    if sha256(bytes) != canonical_hash(&pins.journal_sha256)? {
        return Err("journal digest differs from independently retained expectations".into());
    }
    let j = decode_journal(bytes)?;
    // The exact journal has already been pinned above. This check additionally
    // validates its domain, height window and integer accounting conventions.
    verify_expected_journal(
        bytes,
        &JournalPins {
            epoch: j.epoch,
            batch_id: j.batch_id,
            evaluation_height: j.evaluation_height,
            valid_until_height: j.valid_until_height,
            row_count: j.row_count,
            accepted_contracts_root: j.accepted_contracts_root,
            old_nullifier_root: j.old_nullifier_root,
            batch_tx_digest: j.batch_tx_digest,
        },
    )?;
    let journal: &[u8; JOURNAL_LEN] = bytes
        .try_into()
        .map_err(|_| "journal must be exactly 276 bytes".to_string())?;
    let initial = decode_state(&pins.initial_state)?;
    let final_state = decode_state(&pins.final_state)?;
    if initial != initial_state(journal, j.epoch)
        || pins.steps != j.row_count
        || final_state[0] != fu(j.row_count as u64)
        || final_state[1] != fu(j.total_collateral_sats)
        || final_state[2] != fu(j.total_payout_sats)
        || final_state[3] != fu(j.total_fee_sats)
        || final_state[5..8] != initial[5..8]
    {
        return Err("Nova state differs from the pinned journal context or totals".into());
    }
    Ok((initial, final_state))
}

/// Independently verifies a persisted proof against receiver-owned expectations.
/// No private rows or source signature checks occur in this process.
pub fn verify_bundle(directory: &Path, expected: &Path) -> Result<serde_json::Value, String> {
    let pins = read_pins(expected)?;
    let metadata = read_bounded(&directory.join("manifest.json"), MAX_METADATA_BYTES)?;
    let manifest: BundleManifest =
        serde_json::from_slice(&metadata).map_err(|e| format!("invalid bundle manifest: {e}"))?;
    if manifest.schema != BUNDLE_SCHEMA || manifest.claim != pins {
        return Err("bundle claim differs from independently retained expectations".into());
    }
    let proof_hash = canonical_hash(&manifest.proof_sha256)?;
    let journal = read_bounded(&directory.join("journal.bin"), JOURNAL_LEN)?;
    let (initial, final_state) = validate_journal_states(&journal, &pins)?;
    let proof_bytes = read_bounded(&directory.join("proof.bin"), MAX_PROOF_BYTES)?;
    if sha256(&proof_bytes) != proof_hash {
        return Err("proof digest differs from bundle manifest".into());
    }
    // Reject malformed encodings before rebuilding the larger circuit key.
    let proof = decode_proof(&proof_bytes)?;
    let setup_start = Instant::now();
    let pp = setup_params()?;
    let (_, vk) = Cs::setup(&pp).map_err(|e| format!("Nova compressed setup: {e:?}"))?;
    let rebuilt_vk = verifier_identity(&vk)?;
    if rebuilt_vk.sha256 != pins.verifier_key_sha256
        || rebuilt_vk.serialized_bytes != pins.verifier_key_serialized_bytes
    {
        return Err("pinned verifier key does not match this executable's circuit".into());
    }
    let setup_seconds = setup_start.elapsed().as_secs_f64();
    let start = Instant::now();
    let output = verify_decoded_proof(&proof, &vk, pins.steps as usize, &initial)?;
    if output != final_state {
        return Err("proof output differs from independently retained final state".into());
    }
    Ok(json!({
        "schema": "lnmarkets-nova-verification/v2",
        "status": "compressed_verified_limited_relation",
        "relation": RELATION_ID,
        "nova_version": NOVA_VERSION,
        "nova_compressed_verified": true,
        "verifier_key_rebuilt_from_current_circuit": true,
        "independently_supplied_expectations_matched": true,
        "native_signature_checks_in_this_process": false,
        "standalone_signature_snark_proved": false,
        "bitcoin_spendability_proved": false,
        "rows": pins.steps,
        "nova_augmented_constraints_primary": pp.num_constraints().0,
        "nova_augmented_constraints_secondary": pp.num_constraints().1,
        "nova_augmented_variables_primary": pp.num_variables().0,
        "nova_augmented_variables_secondary": pp.num_variables().1,
        "nova_public_params_digest": hex::encode(f_to_le(&pp.digest())),
        "proof_sha256": manifest.proof_sha256,
        "verifier_key_sha256": pins.verifier_key_sha256,
        "verifier_key_serialized_bytes": pins.verifier_key_serialized_bytes,
        "native_journal_sha256": pins.journal_sha256,
        "compressed_bytes": proof_bytes.len(),
        "verifier_setup_seconds": setup_seconds,
        "compressed_verify_seconds": start.elapsed().as_secs_f64(),
        "final_state": pins.final_state,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct TempDir(std::path::PathBuf);
    impl TempDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "lnm-nova-artifact-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn test_key() -> VerifierIdentity {
        VerifierIdentity {
            sha256: hex::encode(sha256(b"test verifier key")),
            serialized_bytes: 17,
        }
    }

    fn pins() -> (VerifiedNovaTrace, VerifierPins) {
        let fixture = lnm_batch_statement::fixture::demo_batch(1).unwrap();
        let trace = crate::validated_trace(&fixture).unwrap();
        let pins = VerifierPins::from_trace(&trace, &test_key()).unwrap();
        (trace, pins)
    }

    #[test]
    fn journal_and_state_are_bound_to_external_expectations() {
        let (trace, mut expect) = pins();
        assert!(validate_journal_states(&trace.journal_bytes, &expect).is_ok());
        expect.final_state[1] = hex::encode(f_to_le(&fu(1)));
        assert!(validate_journal_states(&trace.journal_bytes, &expect).is_err());
        let (_, expect) = pins();
        let mut changed = trace.journal_bytes;
        changed[8] ^= 1;
        assert!(validate_journal_states(&changed, &expect).is_err());
    }

    #[test]
    fn pins_reject_noncanonical_field_hex_unknown_keys_and_row_counts() {
        let (_, mut expect) = pins();
        expect.final_state[4] = "ff".repeat(32);
        assert!(expect.validate().is_err());
        let (_, mut expect) = pins();
        expect.verifier_key_sha256 = expect.verifier_key_sha256.to_uppercase();
        assert!(expect.validate().is_err());
        let (_, mut expect) = pins();
        expect.steps = 33;
        assert!(expect.validate().is_err());
        let (_, expect) = pins();
        let mut value = serde_json::to_value(expect).unwrap();
        value["invented_trust"] = json!(true);
        assert!(serde_json::from_value::<VerifierPins>(value).is_err());
    }

    #[test]
    fn bounded_files_and_create_new_preserve_existing_data() {
        let temp = TempDir::new();
        let path = temp.0.join("sample");
        write_new(&path, b"original").unwrap();
        assert!(write_new(&path, b"replacement").is_err());
        assert!(read_bounded(&path, 7).is_err());
        assert_eq!(read_bounded(&path, 8).unwrap(), b"original");
        assert!(read_bounded(&temp.0, 100).is_err());
    }

    #[test]
    fn bundle_tampering_is_rejected_before_proof_deserialization() {
        let temp = TempDir::new();
        let directory = temp.0.join("bundle");
        let expected_path = temp.0.join("expected.json");
        let (trace, _) = pins();
        // Deliberately invalid proof bytes. Integrity checks must fail before any
        // cryptographic setup or proof decode is reached.
        let pins = write_bundle(&directory, &trace, b"proof", &test_key()).unwrap();
        write_pins(&expected_path, &pins).unwrap();
        fs::write(directory.join("proof.bin"), b"changed").unwrap();
        let error = verify_bundle(&directory, &expected_path).unwrap_err();
        assert!(error.contains("proof digest"), "{error}");
        fs::write(directory.join("proof.bin"), b"proof").unwrap();
        let mut changed_pins = pins;
        changed_pins.final_state[4] = hex::encode(f_to_le(&fu(9)));
        fs::write(&expected_path, serde_json::to_vec(&changed_pins).unwrap()).unwrap();
        let error = verify_bundle(&directory, &expected_path).unwrap_err();
        assert!(error.contains("bundle claim"), "{error}");
        assert!(write_bundle(&directory, &trace, b"proof", &test_key()).is_err());
    }

    #[test]
    fn streamed_identity_matches_canonical_bytes_and_enforces_limit() {
        let value = (17u64, vec![1u32, 2, 3]);
        let encoded = serialize_bounded(&value, 100).unwrap();
        let streamed = streamed_identity(&value, encoded.len() as u64).unwrap();
        assert_eq!(streamed.serialized_bytes, encoded.len() as u64);
        assert_eq!(streamed.sha256, hex::encode(sha256(&encoded)));
        assert!(streamed_identity(&value, encoded.len() as u64 - 1).is_err());
        let mut writer = HashWriter {
            hash: Sha256::new(),
            bytes: 0,
            limit: 2,
        };
        writer.write_all(b"ab").unwrap();
        assert!(writer.write_all(b"c").is_err());
    }

    #[test]
    fn malformed_binary_proof_is_refused() {
        assert!(decode_proof(&[]).is_err());
        assert!(decode_proof(&[0; 8]).is_err());
        assert!(decode_proof(&[255; 128]).is_err());
    }
}
