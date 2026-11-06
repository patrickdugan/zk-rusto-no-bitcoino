//! Actual retained compressed-Nova verification with forwarding transcript/RO traces.
//! This is a verification-only hosted oracle, not a Bitcoin Script verifier.
#[path = "../dimensions.rs"]
mod dimensions;
#[path = "../key_bindings.rs"]
mod key_bindings;
#[path = "../matrix_profile.rs"]
mod matrix_profile;
#[path = "../matrix_stream.rs"]
mod matrix_stream;
#[path = "../poseidon_parameters.rs"]
mod poseidon_parameters;
#[path = "../tracing.rs"]
mod tracing;

use bincode::Options;
use ff::PrimeField;
use nova_header_chain::{
    native::{Network, State},
    HeaderStep,
};
use nova_snark::{
    nova::{CompressedSNARK, PublicParams, VerifierKey},
    provider::ipa_pc,
    spartan::snark::RelaxedR1CSSNARK,
    traits::{snark::RelaxedR1CSSNARKTrait, Engine},
};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
    time::Instant,
};
use tracing::{TracePallas as E1, TraceVesta as E2};

type F = <E1 as Engine>::Scalar;
type S1 = RelaxedR1CSSNARK<E1, ipa_pc::EvaluationEngine<E1>>;
type S2 = RelaxedR1CSSNARK<E2, ipa_pc::EvaluationEngine<E2>>;
type Proof = CompressedSNARK<E1, E2, HeaderStep, S1, S2>;
type Vk = VerifierKey<E1, E2, HeaderStep, S1, S2>;
type Result<T> = std::result::Result<T, String>;
const HEADER_BYTES: usize = 12 + 17 * 32;
const BUNDLE_BYTES: usize = 13220;
const PROOF_BYTES: usize = 12664;
const BUNDLE_SHA: &str = "c3143d5627ef7291ab6a858b866a4ba19e356a168dea992d3e572ef6531904e9";
const PROOF_SHA: &str = "2137c6e8621cedb7423e0ef7f9ff7c27b2c6fdf3ceb227e644b3d9660d056617";
const VK_SHA: &str = "1ae88a7bcfdc5f14d030d0baafa06ec17fe904a5ebed42f9bd6fa6105fdc8c24";
const DIM_SHA: &str = "de6333df2e41b5f5bae1c103fab862f8d6022fd54abeb80ba61920bc9f360edc";
const MATRIX_PROFILE_SHA: &str = "7a69cdd0c39601c988c39719bbfc67386762d516eea8a3fcfc0e23c7938ac921";
const END_SHA: &str = "9c2c618540f1c52e25974c19e9ca6835a2336cc0debb35bf95b087087561a81c";
const REVISION: &str = "de607d3db17d400dd6c2923d357f1d4a7bf233c7";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Expected {
    schema: String,
    network: String,
    k: u32,
    steps: u32,
    initial_state_le: Vec<String>,
    checkpoint_origin: String,
    verifier_key_sha256: String,
    proof_bytes: usize,
    proof_sha256: String,
    bundle_bytes: usize,
    bundle_sha256: String,
    end_state_sha256: String,
    header_revision: String,
    nova_version: String,
}

fn check(ok: bool, message: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(message.to_owned())
    }
}
fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn read(path: &str, cap: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|e| e.to_string())?
        .take((cap + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    check(bytes.len() <= cap, "input byte budget")?;
    Ok(bytes)
}
fn z_bytes(z: &[F]) -> Vec<u8> {
    z.iter()
        .flat_map(|v| v.to_repr().as_ref().to_vec())
        .collect()
}
fn scalar(value: &str) -> Result<F> {
    check(
        value.len() == 64
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "canonical initial scalar hex",
    )?;
    let bytes = hex::decode(value).map_err(|e| e.to_string())?;
    let mut repr = <F as PrimeField>::Repr::default();
    repr.as_mut().copy_from_slice(&bytes);
    Option::<F>::from(F::from_repr(repr)).ok_or_else(|| "noncanonical initial scalar".into())
}

fn bind_retained(raw: &[u8], e: &Expected) -> Result<Vec<F>> {
    // Pin the complete known bundle before any inner proof deserialization.
    check(
        raw.len() == BUNDLE_BYTES && sha(raw) == BUNDLE_SHA,
        "retained bundle scope",
    )?;
    check(
        e.schema == "bitvm2-nova-expected-bundle/v1"
            && e.network == "testnet4"
            && e.k == 5
            && e.steps == 404
            && e.checkpoint_origin == "genesis"
            && e.header_revision == REVISION
            && e.nova_version == "0.76.0",
        "retained policy/backend scope",
    )?;
    check(
        e.verifier_key_sha256 == VK_SHA
            && e.proof_bytes == PROOF_BYTES
            && e.proof_sha256 == PROOF_SHA
            && e.bundle_bytes == BUNDLE_BYTES
            && e.bundle_sha256 == BUNDLE_SHA
            && e.end_state_sha256 == END_SHA,
        "retained policy pins",
    )?;
    check(
        &raw[..4] == b"NHT4"
            && u32::from_le_bytes(raw[4..8].try_into().map_err(|_| "step encoding")?) == 404
            && u32::from_le_bytes(raw[8..12].try_into().map_err(|_| "k encoding")?) == 5,
        "retained framing",
    )?;
    check(e.initial_state_le.len() == 17, "initial state arity")?;
    let z0: Vec<_> = e
        .initial_state_le
        .iter()
        .map(|value| scalar(value))
        .collect::<Result<_>>()?;
    check(
        z0 == State::genesis(Network::Testnet4).to_z::<F>()
            && z_bytes(&z0).as_slice() == &raw[12..HEADER_BYTES],
        "retained initial/genesis state",
    )?;
    check(
        sha(&raw[HEADER_BYTES..]) == PROOF_SHA,
        "retained inner proof identity",
    )?;
    Ok(z0)
}

struct HashWriter(Sha256);
impl Write for HashWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn key() -> Result<Vk> {
    let shape = HeaderStep::on(Network::Testnet4, vec![[0u8; 80]; 5]);
    let pp = PublicParams::<E1, E2, HeaderStep>::setup(&shape, &*S1::ck_floor(), &*S2::ck_floor())
        .map_err(|e| format!("transparent parameter reconstruction: {e:?}"))?;
    let (pk, vk) = Proof::setup(&pp).map_err(|e| format!("verifier key reconstruction: {e:?}"))?;
    drop(pk);
    drop(pp);
    let mut writer = HashWriter(Sha256::new());
    bincode::serialize_into(&mut writer, &vk).map_err(|e| e.to_string())?;
    check(
        hex::encode(writer.0.finalize()) == VK_SHA,
        "forwarding-engine full VK differs from original pin",
    )?;
    Ok(vk)
}

fn run() -> Result<Value> {
    let args: Vec<_> = std::env::args().collect();
    check(
        args.len() == 4 || (args.len() == 6 && args[4] == "--matrix-output"),
        "usage: replay RETAINED.nht4 EXPECTED.json PINNED_DIMENSIONS.json [--matrix-output NEW_DIR]",
    )?;
    let raw = read(&args[1], 1 << 20)?;
    let expected: Expected =
        serde_json::from_slice(&read(&args[2], 1 << 14)?).map_err(|e| e.to_string())?;
    let z0 = bind_retained(&raw, &expected)?;
    let proof_raw = &raw[HEADER_BYTES..];
    let proof: Proof = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_little_endian()
        .with_limit(PROOF_BYTES as u64)
        .reject_trailing_bytes()
        .deserialize(proof_raw)
        .map_err(|e| format!("strict retained proof decoding: {e}"))?;
    check(
        bincode::serialize(&proof)
            .map_err(|e| e.to_string())?
            .as_slice()
            == proof_raw,
        "retained proof canonical roundtrip",
    )?;
    let dim_raw = read(&args[3], 1 << 14)?;
    check(
        sha(&dim_raw) == DIM_SHA,
        "pinned canonical descriptor bytes",
    )?;
    let dim_expected: Value = serde_json::from_slice(&dim_raw).map_err(|e| e.to_string())?;

    let started = Instant::now();
    let vk = key()?;
    let key_reconstruction_seconds = started.elapsed().as_secs_f64();
    let started = Instant::now();
    let (dims, dimension_export) = dimensions::export(&vk, VK_SHA, "testnet4", 5)?;
    check(
        dimensions::canonical_sha256(&dims)? == DIM_SHA
            && serde_json::to_value(&dims).map_err(|e| e.to_string())? == dim_expected,
        "forwarding-engine dimensions differ from original pin",
    )?;
    let (key_bindings, key_binding_export) = key_bindings::export(&vk, VK_SHA, DIM_SHA)?;
    let key_bindings_sha256 = key_bindings::canonical_sha256(&key_bindings)?;
    let (poseidon_parameters, poseidon_parameter_export) =
        poseidon_parameters::export_authenticated_vk(&vk, VK_SHA, DIM_SHA, "testnet4", 5)?;
    let poseidon_parameters_sha256 = poseidon_parameters::canonical_sha256(&poseidon_parameters)?;
    let (matrix_profile, matrix_profile_export) =
        matrix_profile::export_authenticated_vk(&vk, VK_SHA, DIM_SHA, "testnet4", 5)?;
    for role in ["primary", "secondary"] {
        for field in ["num_cons", "num_vars", "num_io"] {
            let expected = dim_expected[role][field]
                .as_u64()
                .ok_or("pinned matrix logical dimension missing")?;
            check(
                matrix_profile[role][field].as_u64() == Some(expected),
                "matrix logical dimensions differ from the independent descriptor",
            )?;
        }
    }
    let matrix_profile_sha256 = matrix_profile::canonical_sha256(&matrix_profile)?;
    check(
        matrix_profile_sha256 == MATRIX_PROFILE_SHA,
        "actual matrix profile differs from independent hosted pin",
    )?;
    let metadata_export_seconds = started.elapsed().as_secs_f64();
    let (
        matrix_collection,
        matrix_collection_sha256,
        matrix_payload_export,
        matrix_payload_export_seconds,
    ) = if let Some(directory) = args.get(5) {
        let started = Instant::now();
        let (collection, stats) =
            matrix_stream::export_authenticated_vk(&vk, &matrix_profile, Path::new(directory))?;
        let digest = matrix_stream::canonical_sha256(&collection)?;
        (
            Some(collection),
            Some(digest),
            Some(stats),
            Some(started.elapsed().as_secs_f64()),
        )
    } else {
        (None, None, None, None)
    };

    // Never capture setup, metadata hashing or negative-verification loops.
    tracing::begin_capture()?;
    let started = Instant::now();
    let verified = proof.verify(&vk, 404, &z0);
    let verify_seconds = started.elapsed().as_secs_f64();
    let trace = tracing::finish_capture()?;
    let zn = verified.map_err(|e| format!("actual retained Nova proof rejected: {e:?}"))?;
    let final_state = State::from_z(&zn).ok_or("verified output width")?;
    check(
        final_state.height == 2020 && sha(&z_bytes(&zn)) == END_SHA,
        "verified output state pin",
    )?;
    Ok(
        json!({"schema":"bitvm2-nova-native-production-replay/v1","passed":true,
        "native_nova_proofs_verified":1,"network":"testnet4","k":5,"steps":404,
        "nova_version":"0.76.0","header_revision":REVISION,"bundle_sha256":BUNDLE_SHA,
        "proof_sha256":PROOF_SHA,"proof_bytes":PROOF_BYTES,"verifier_key_sha256":VK_SHA,
        "verifier_dimensions_sha256":DIM_SHA,"verifier_dimensions":dims,"dimension_export":dimension_export,
        "key_bindings":key_bindings,"key_bindings_sha256":key_bindings_sha256,"key_binding_export":key_binding_export,
        "poseidon_parameters":poseidon_parameters,"poseidon_parameters_sha256":poseidon_parameters_sha256,
        "poseidon_parameter_export":poseidon_parameter_export,
        "matrix_profile":matrix_profile,"matrix_profile_sha256":matrix_profile_sha256,
        "matrix_profile_export":matrix_profile_export,
        "matrix_collection":matrix_collection,"matrix_collection_sha256":matrix_collection_sha256,
        "matrix_payload_export":matrix_payload_export,"matrix_payload_export_seconds":matrix_payload_export_seconds,
        "trace":trace,"end_state_sha256":END_SHA,"end_height":final_state.height,
        "key_reconstruction_seconds":key_reconstruction_seconds,"metadata_export_seconds":metadata_export_seconds,
        "verify_seconds":verify_seconds,"setup_calls":1,"proving_jobs":0,"transactions_broadcast":0,
        "bitcoin_script_verified":false,"independent_poseidon_verification":false,"complete_bitvm2_verifier":false}),
    )
}

fn main() {
    match run() {
        Ok(value) => println!("{}", serde_json::to_string_pretty(&value).unwrap()),
        Err(error) => {
            eprintln!("native production replay failed: {error}");
            std::process::exit(1);
        }
    }
}
