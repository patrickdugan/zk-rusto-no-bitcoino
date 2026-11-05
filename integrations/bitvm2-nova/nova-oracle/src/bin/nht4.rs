//! Bounded NHC1/NHT4 framing and retained-proof verification; never proves.
//! Run parameter reconstruction only in hosted CI under an external RAM/time cap.
use bincode::Options;
use ff::{Field, PrimeField};
use nova_header_chain::{
    native::{self, Network, State},
    HeaderStep,
};
use nova_snark::{
    nova::{CompressedSNARK, PublicParams, VerifierKey},
    provider::{ipa_pc, pedersen::Commitment, traits::DlogGroup, PallasEngine, VestaEngine},
    spartan::snark::RelaxedR1CSSNARK,
    traits::{snark::RelaxedR1CSSNARKTrait, Engine},
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{Read, Write},
    time::Instant,
};

type E1 = PallasEngine;
type E2 = VestaEngine;
type F = <E1 as Engine>::Scalar;
type S1 = RelaxedR1CSSNARK<E1, ipa_pc::EvaluationEngine<E1>>;
type S2 = RelaxedR1CSSNARK<E2, ipa_pc::EvaluationEngine<E2>>;
type Proof = CompressedSNARK<E1, E2, HeaderStep, S1, S2>;
type Vk = VerifierKey<E1, E2, HeaderStep, S1, S2>;
type Result<T> = std::result::Result<T, String>;
const REVISION: &str = "de607d3db17d400dd6c2923d357f1d4a7bf233c7";
const HEADER_BYTES: usize = 12 + 17 * 32;
const MAX_BUNDLE: usize = 1 << 20;
const RETAINED_SHA: &str = "c3143d5627ef7291ab6a858b866a4ba19e356a168dea992d3e572ef6531904e9";

#[derive(Clone, Deserialize)]
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    name: String,
    bundle_hex: String,
    expected: Expected,
    accept: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Cases {
    schema: String,
    cases: Vec<Case>,
}

struct Bound {
    network: Network,
    steps: u32,
    k: u32,
    z0: Vec<F>,
    proof: Vec<u8>,
}

fn check(ok: bool, message: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(message.to_owned())
    }
}

fn sha(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

fn unhex(value: &str, max_bytes: usize) -> Result<Vec<u8>> {
    check(
        value.len() <= max_bytes * 2 && value.len() % 2 == 0,
        "hex length out of bounds",
    )?;
    check(
        value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "noncanonical hex",
    )?;
    hex::decode(value).map_err(|e| e.to_string())
}

fn digest(value: &str) -> Result<()> {
    check(
        unhex(value, 32)?.len() == 32,
        "digest must contain 32 bytes",
    )
}

fn state(raw: &[u8]) -> Result<Vec<F>> {
    check(raw.len() == 17 * 32, "state must hold exactly 17 scalars")?;
    let mut z = Vec::with_capacity(17);
    for bytes in raw.chunks_exact(32) {
        let mut repr = <F as PrimeField>::Repr::default();
        repr.as_mut().copy_from_slice(bytes);
        z.push(Option::<F>::from(F::from_repr(repr)).ok_or("noncanonical scalar")?);
    }
    check(State::from_z(&z).is_some(), "state width out of bounds")?;
    Ok(z)
}

fn z_bytes(z: &[F]) -> Vec<u8> {
    z.iter()
        .flat_map(|f| f.to_repr().as_ref().to_vec())
        .collect()
}

fn expected(e: &Expected) -> Result<(Network, Vec<F>)> {
    check(
        e.schema == "bitvm2-nova-expected-bundle/v1",
        "policy schema",
    )?;
    check(
        e.header_revision == REVISION && e.nova_version == "0.76.0",
        "backend pin",
    )?;
    let net = match e.network.as_str() {
        "mainnet" => Network::Mainnet,
        "testnet4" => Network::Testnet4,
        _ => return Err("unsupported network".into()),
    };
    check(
        (1..=64).contains(&e.k) && e.steps > 0,
        "expected k/steps range",
    )?;
    check(e.initial_state_le.len() == 17, "expected state arity")?;
    let mut bytes = Vec::with_capacity(17 * 32);
    for value in &e.initial_state_le {
        let word = unhex(value, 32)?;
        check(word.len() == 32, "expected scalar width")?;
        bytes.extend(word);
    }
    let z = state(&bytes)?;
    let initial = State::from_z(&z).ok_or("expected state widths")?;
    check(
        initial.height as u64 + e.steps as u64 * e.k as u64 <= u32::MAX as u64,
        "expected final height overflow",
    )?;
    match e.checkpoint_origin.as_str() {
        "genesis" => check(
            z == State::genesis(net).to_z::<F>(),
            "consensus genesis mismatch",
        )?,
        "operator_pinned" => (),
        _ => return Err("checkpoint origin missing".into()),
    }
    for value in [
        &e.verifier_key_sha256,
        &e.proof_sha256,
        &e.bundle_sha256,
        &e.end_state_sha256,
    ] {
        digest(value)?;
    }
    if let Some(pin) = native::pinned_verifier_key(net, e.k as usize) {
        check(pin == e.verifier_key_sha256, "network/k key mismatch")?;
    }
    if let Some((owner, k)) = native::pinned_key_owner(&e.verifier_key_sha256) {
        check(
            owner == net && k == e.k as usize,
            "key belongs to other network/k",
        )?;
    }
    check(
        e.proof_bytes > 0 && e.proof_bytes <= MAX_BUNDLE - HEADER_BYTES,
        "expected proof length",
    )?;
    check(
        e.bundle_bytes == HEADER_BYTES + e.proof_bytes && e.bundle_bytes <= MAX_BUNDLE,
        "expected container length",
    )?;
    Ok((net, z))
}

fn bind(raw: &[u8], e: &Expected) -> Result<Bound> {
    let (network, z0) = expected(e)?;
    check(
        raw.len() == e.bundle_bytes,
        "exact container length mismatch",
    )?;
    check(
        raw.len() > HEADER_BYTES && raw.len() <= MAX_BUNDLE,
        "container length",
    )?;
    let selected = match &raw[..4] {
        b"NHC1" => Network::Mainnet,
        b"NHT4" => Network::Testnet4,
        _ => return Err("unknown container magic".into()),
    };
    let word = |offset| u32::from_le_bytes(raw[offset..offset + 4].try_into().unwrap());
    let (steps, k) = (word(4), word(8));
    check(
        steps > 0 && (1..=64).contains(&k),
        "container k/steps range",
    )?;
    let actual = state(&raw[12..HEADER_BYTES])?;
    check(
        selected == network && steps == e.steps && k == e.k && actual == z0,
        "network/k/steps/initial state mismatch",
    )?;
    let proof = &raw[HEADER_BYTES..];
    check(
        proof.len() == e.proof_bytes && sha(proof) == e.proof_sha256,
        "proof identity",
    )?;
    check(sha(raw) == e.bundle_sha256, "container identity")?;
    Ok(Bound {
        network,
        steps,
        k,
        z0,
        proof: proof.to_vec(),
    })
}

fn canonical_bincode<T: DeserializeOwned + Serialize>(bytes: &[u8]) -> Result<T> {
    // bincode::serialize's legacy fixed-width LE encoding, with strict EOF.
    check(
        !bytes.is_empty() && bytes.len() <= MAX_BUNDLE,
        "inner proof byte limit",
    )?;
    let decoded: T = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_little_endian()
        .with_limit(MAX_BUNDLE as u64)
        .reject_trailing_bytes()
        .deserialize(bytes)
        .map_err(|e| format!("strict proof decode: {e}"))?;
    // The checked group decoder admits an alternate sign bit for identity.
    // Require canonical byte-for-byte reserialization before proof verification.
    let canonical = bincode::serialize(&decoded).map_err(|e| e.to_string())?;
    check(
        canonical.len() <= MAX_BUNDLE && canonical.as_slice() == bytes,
        "noncanonical compressed-proof encoding",
    )?;
    Ok(decoded)
}

fn decode(proof: &[u8]) -> Result<Proof> {
    canonical_bincode(proof)
}

fn identity_alias<E: Engine>(engine: &str) -> Result<Value>
where
    E::GE: DlogGroup,
{
    let canonical = bincode::serialize(&Commitment::<E>::default()).map_err(|e| e.to_string())?;
    check(
        canonical.len() == 32 && canonical.iter().all(|byte| *byte == 0),
        "unexpected canonical Pasta identity encoding",
    )?;
    let mut alias = canonical.clone();
    alias[31] = 0x80;
    // Exercise the pinned upstream alias directly, with no parameters or proof.
    let upstream: Commitment<E> = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_little_endian()
        .with_limit(32)
        .reject_trailing_bytes()
        .deserialize(&alias)
        .map_err(|e| format!("upstream identity alias regression: {e}"))?;
    check(
        bincode::serialize(&upstream).map_err(|e| e.to_string())? == canonical,
        "upstream alias did not represent the canonical identity",
    )?;
    check(
        canonical_bincode::<Commitment<E>>(&alias).is_err(),
        "identity sign alias passed canonical admission",
    )?;
    Ok(json!({"name":format!("{engine}_identity_sign_alias"),
              "stage":"strict_bincode_roundtrip","rejected":true,
              "upstream_alias_decoded":true}))
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

fn rebuild_vk(bound: &Bound, e: &Expected) -> Result<Vk> {
    // Keep the hosted job bounded to this independently retained k5 fixture.
    check(
        bound.network == Network::Testnet4
            && bound.k == 5
            && bound.steps == 404
            && e.bundle_sha256 == RETAINED_SHA
            && e.checkpoint_origin == "genesis",
        "native fixture verification scope",
    )?;
    let shape = HeaderStep::on(bound.network, vec![[0u8; 80]; bound.k as usize]);
    let pp = PublicParams::<E1, E2, HeaderStep>::setup(&shape, &*S1::ck_floor(), &*S2::ck_floor())
        .map_err(|e| format!("public parameter reconstruction: {e:?}"))?;
    let (pk, vk) = Proof::setup(&pp).map_err(|e| format!("verifier key reconstruction: {e:?}"))?;
    drop(pk);
    drop(pp);
    let mut writer = HashWriter(Sha256::new());
    bincode::serialize_into(&mut writer, &vk).map_err(|e| format!("key serialization: {e}"))?;
    check(
        hex::encode(writer.0.finalize()) == e.verifier_key_sha256,
        "reconstructed verifier key pin mismatch",
    )?;
    Ok(vk)
}

fn rejected(checks: &mut Vec<Value>, name: &str, stage: &str, failed: bool) -> Result<()> {
    check(failed, &format!("negative case accepted: {name}"))?;
    checks.push(json!({"name":name,"stage":stage,"rejected":true}));
    Ok(())
}

fn bind_end(zn: &[F], e: &Expected) -> Result<()> {
    check(State::from_z(zn).is_some(), "invalid final-state widths")?;
    check(
        sha(&z_bytes(zn)) == e.end_state_sha256,
        "claimed end-state mismatch",
    )
}

fn verify_retained(bound: &Bound, e: &Expected) -> Result<Value> {
    let proof = decode(&bound.proof)?;
    let started = Instant::now();
    let vk = rebuild_vk(bound, e)?;
    let reconstruction_seconds = started.elapsed().as_secs_f64();
    let started = Instant::now();
    let zn = proof
        .verify(&vk, bound.steps as usize, &bound.z0)
        .map_err(|e| format!("native Nova proof rejected: {e:?}"))?;
    let verify_seconds = started.elapsed().as_secs_f64();
    bind_end(&zn, e)?;
    let final_state = State::from_z(&zn).ok_or("final state")?;
    check(final_state.height == 2020, "final height mismatch")?;
    let mut negatives = Vec::new();
    negatives.push(identity_alias::<E1>("pallas")?);
    negatives.push(identity_alias::<E2>("vesta")?);
    for (name, steps) in [
        ("zero_steps", 0),
        ("changed_steps", bound.steps as usize + 1),
    ] {
        rejected(
            &mut negatives,
            name,
            "native_nova_verify",
            proof.verify(&vk, steps, &bound.z0).is_err(),
        )?;
    }
    let mut changed = bound.z0.clone();
    changed[0] += F::ONE;
    rejected(
        &mut negatives,
        "changed_initial_height",
        "native_nova_verify",
        proof.verify(&vk, bound.steps as usize, &changed).is_err(),
    )?;
    changed = bound.z0.clone();
    changed[1] += F::ONE;
    rejected(
        &mut negatives,
        "changed_initial_hash",
        "native_nova_verify",
        proof.verify(&vk, bound.steps as usize, &changed).is_err(),
    )?;
    rejected(
        &mut negatives,
        "short_initial_state",
        "native_nova_verify",
        proof
            .verify(&vk, bound.steps as usize, &bound.z0[..16])
            .is_err(),
    )?;
    changed = bound.z0.clone();
    changed.push(F::ZERO);
    rejected(
        &mut negatives,
        "surplus_initial_state",
        "native_nova_verify",
        proof.verify(&vk, bound.steps as usize, &changed).is_err(),
    )?;
    let mut surplus = bound.proof.clone();
    surplus.push(0);
    rejected(
        &mut negatives,
        "appended_inner_proof",
        "strict_bincode_decode",
        decode(&surplus).is_err(),
    )?;
    rejected(
        &mut negatives,
        "truncated_inner_proof",
        "strict_bincode_decode",
        decode(&bound.proof[..bound.proof.len() - 1]).is_err(),
    )?;
    let mut tampered = bound.proof.clone();
    *tampered.last_mut().ok_or("empty proof")? ^= 1;
    match decode(&tampered) {
        Err(_) => rejected(
            &mut negatives,
            "tampered_inner_proof",
            "strict_bincode_decode",
            true,
        )?,
        Ok(p) => rejected(
            &mut negatives,
            "tampered_inner_proof",
            "native_nova_verify",
            p.verify(&vk, bound.steps as usize, &bound.z0).is_err(),
        )?,
    }
    let mut wrong_end = e.clone();
    wrong_end.end_state_sha256 = "00".repeat(32);
    rejected(
        &mut negatives,
        "wrong_expected_end_state",
        "verified_output_binding",
        bind_end(&zn, &wrong_end).is_err(),
    )?;
    // This is proof-only serde output (not matrices, keys, or private witnesses).
    // Consumers may check real coefficient shapes; replay needs transcript claims.
    let value = serde_json::to_value(&proof).map_err(|e| e.to_string())?;
    let mut altered = value.clone();
    let coefficient = altered
        .pointer_mut("/snark_primary/sc_proof_outer/compressed_polys/0/coeffs_except_linear_term/0")
        .ok_or("missing genuine outer sumcheck coefficient")?;
    let zero = serde_json::to_value(F::ZERO).map_err(|e| e.to_string())?;
    *coefficient = if *coefficient == zero {
        serde_json::to_value(F::ONE).map_err(|e| e.to_string())?
    } else {
        zero
    };
    let altered_proof: Proof = serde_json::from_value(altered).map_err(|e| e.to_string())?;
    rejected(
        &mut negatives,
        "changed_canonical_sumcheck_coefficient",
        "native_nova_verify",
        altered_proof
            .verify(&vk, bound.steps as usize, &bound.z0)
            .is_err(),
    )?;
    let components = json!({"snark_primary":value.get("snark_primary").ok_or("primary proof component")?,
                            "snark_secondary":value.get("snark_secondary").ok_or("secondary proof component")?});
    check(
        serde_json::to_vec(&components)
            .map_err(|e| e.to_string())?
            .len()
            <= 1 << 20,
        "proof component export exceeds budget",
    )?;
    Ok(
        json!({"native_nova_proofs_verified":1,"verifier_key_sha256":e.verifier_key_sha256,
              "end_state_sha256":sha(&z_bytes(&zn)),"end_height":final_state.height,
              "key_reconstruction_seconds":reconstruction_seconds,"verify_seconds":verify_seconds,
              "negative_checks":negatives,"proof_components":components}),
    )
}

fn run() -> Result<Value> {
    let args: Vec<_> = std::env::args().collect();
    check(args.len() == 2, "usage: nht4 CASES.json")?;
    let mut raw = Vec::new();
    File::open(&args[1])
        .map_err(|e| e.to_string())?
        .take((8 << 20) + 1)
        .read_to_end(&mut raw)
        .map_err(|e| e.to_string())?;
    check(raw.len() <= 8 << 20, "case JSON exceeds budget")?;
    let input: Cases = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
    check(
        input.schema == "bitvm2-nova-nht4-cases/v1" && input.cases.len() <= 64,
        "case schema/count",
    )?;
    let mut rows = Vec::new();
    let mut accepted = 0;
    let mut native = None;
    let mut names = std::collections::BTreeSet::new();
    for case in &input.cases {
        check(names.insert(&case.name), "duplicate case name")?;
        let bytes = unhex(&case.bundle_hex, MAX_BUNDLE)?;
        let result = bind(&bytes, &case.expected);
        check(
            result.is_ok() == case.accept,
            &format!("framing expectation mismatch: {}", case.name),
        )?;
        rows.push(
            json!({"name":case.name,"accepted":result.is_ok(),"stage":"framing_identity_binding"}),
        );
        if let Ok(bound) = result {
            accepted += 1;
            check(
                native.is_none(),
                "exactly one native retained fixture required",
            )?;
            native = Some(verify_retained(&bound, &case.expected)?);
        }
    }
    check(
        accepted == 1,
        "exactly one genuine accepted fixture required",
    )?;
    Ok(json!({"passed":true,"framing_cases":rows,"native":native,
              "proving_jobs":0,"bitvm2_script_verified":false,"transactions_broadcast":0,
              "scope":"native Nova SNARK verification and framing only; no Bitcoin verifier completeness claim"}))
}

fn main() {
    match run() {
        Ok(result) => println!("{}", serde_json::to_string_pretty(&result).unwrap()),
        Err(error) => {
            eprintln!("nht4 verification failed: {error}");
            std::process::exit(1);
        }
    }
}
