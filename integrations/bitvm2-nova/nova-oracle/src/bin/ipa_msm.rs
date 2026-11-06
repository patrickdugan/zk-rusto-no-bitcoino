//! Hosted CPU-only IPA terminal relation checker, not a proof verifier.
//!
//! A sealed Python builder derives the request by replaying the admitted proof.
//! This command checks only the mathematical relation for that exact request.
//! It authenticates every generator byte consumed before invoking Nova's public
//! mature CPU MSM. No proving, setup, GPU, or receipt-as-proof path exists here.
use ff::{Field, PrimeField};
use halo2curves::group::GroupEncoding;
use nova_snark::{
    provider::{
        traits::{DlogGroup, DlogGroupExt},
        PallasEngine, VestaEngine,
    },
    traits::{Engine, Group},
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{BufReader, Read},
    time::Instant,
};

type Result<T> = std::result::Result<T, String>;
const REQUEST_SCHEMA: &str = "bitvm2-nova-ipa-request/v1";
const COLLECTION_SCHEMA: &str = "bitvm2-nova-ipa-generators/v1";
const COLLECTION_SHA: &str = "db1f7cc9a47e0523635f7c52476f784e9c1cfe4e3686c98a54636c1d1a4134d4";
const KEY_SHA: &str = "c8b117ea587c80bfdbdfc0cc262cdf68b1b4c07b3b45ba871413c7768aa62b9a";
const DIM_SHA: &str = "de6333df2e41b5f5bae1c103fab862f8d6022fd54abeb80ba61920bc9f360edc";
const VK_SHA: &str = "1ae88a7bcfdc5f14d030d0baafa06ec17fe904a5ebed42f9bd6fa6105fdc8c24";
const TRACE_SHA: &str = "394d90b302b2fe6b8f5c0a65ada372d820996f3230770a816961a75cefec59b8";
const POSEIDON_SHA: &str = "b55fa125133315243cb299ee7603c5f0508d68abf64f0dab43ecba4a0d09fa67";
const PROOF_SHA: &str = "2137c6e8621cedb7423e0ef7f9ff7c27b2c6fdf3ceb227e644b3d9660d056617";
const BUNDLE_SHA: &str = "c3143d5627ef7291ab6a858b866a4ba19e356a168dea992d3e572ef6531904e9";
const END_SHA: &str = "9c2c618540f1c52e25974c19e9ca6835a2336cc0debb35bf95b087087561a81c";
const NOVA_SHA: &str = "c9bb3809a6c70057ea722c1c4fe5097cf29a3479d0b4671f3cddb1d81043bb31";
const REVISION: &str = "de607d3db17d400dd6c2923d357f1d4a7bf233c7";
const MAX_JSON: usize = 32 << 10;
const MAX_GENERATOR_BYTES: u64 = 32 << 20;
const PRIMARY_N: usize = 524288;
const SECONDARY_N: usize = 16384;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String,
    nova_version: String,
    nova_crate_sha256: String,
    header_revision: String,
    network: String,
    k: u32,
    steps: u32,
    bundle_sha256: String,
    end_state_sha256: String,
    role: String,
    engine: String,
    proof_sha256: String,
    verifier_key_sha256: String,
    verifier_dimensions_sha256: String,
    key_bindings_sha256: String,
    native_trace_sha256: String,
    poseidon_parameters_sha256: String,
    generator_collection_sha256: String,
    ipa_dimension: usize,
    generator_count: usize,
    joint_commitment: String,
    joint_evaluation_le: String,
    batch_point_le: Vec<String>,
    ipa_initial_challenge_le: String,
    #[serde(rename = "L_vec")]
    left: Vec<String>,
    #[serde(rename = "R_vec")]
    right: Vec<String>,
    challenges_le: Vec<String>,
    a_hat_le: String,
    generator_residual: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct KeyBindings {
    schema: String,
    nova_version: String,
    header_revision: String,
    network: String,
    k: u32,
    verifier_key_sha256: String,
    verifier_dimensions_sha256: String,
    pp_digest_le: String,
    primary: RoleKey,
    secondary: RoleKey,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RoleKey {
    engine: String,
    derand_key: DerandKey,
    ipa_scalar_key: ScalarKey,
    spartan_vk_digest_le: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DerandKey {
    h: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ScalarKey {
    ck: Vec<String>,
    h: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Collection {
    schema: String,
    nova_version: String,
    nova_crate_sha256: String,
    header_revision: String,
    network: String,
    k: u32,
    verifier_key_sha256: String,
    verifier_dimensions_sha256: String,
    encoding: String,
    total_bytes: u64,
    files: Vec<GeneratorFile>,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct GeneratorFile {
    role: String,
    engine: String,
    base_field_role: String,
    scalar_field_role: String,
    filename: String,
    count: usize,
    bytes: u64,
    sha256: String,
    segments: Vec<Segment>,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Segment {
    name: String,
    offset: u64,
    bytes: u64,
    sha256: String,
}

fn check(ok: bool, message: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(message.into())
    }
}
fn sha(raw: &[u8]) -> String {
    hex::encode(Sha256::digest(raw))
}
fn hex32(text: &str) -> Result<[u8; 32]> {
    check(
        text.len() == 64
            && text
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
        "canonical lowercase32-byte hex required",
    )?;
    let mut output = [0; 32];
    hex::decode_to_slice(text, &mut output).map_err(|e| e.to_string())?;
    Ok(output)
}
fn read(path: &str, cap: usize) -> Result<Vec<u8>> {
    let mut raw = Vec::new();
    File::open(path)
        .map_err(|e| e.to_string())?
        .take((cap + 1) as u64)
        .read_to_end(&mut raw)
        .map_err(|e| e.to_string())?;
    check(!raw.is_empty() && raw.len() <= cap, "JSON byte budget")?;
    Ok(raw)
}
fn depth_guard(raw: &[u8]) -> Result<()> {
    let (mut depth, mut string, mut escaped) = (0usize, false, false);
    for byte in raw {
        if string {
            if escaped {
                escaped = false;
            } else if *byte == b'\\' {
                escaped = true;
            } else if *byte == b'"' {
                string = false;
            }
        } else {
            match byte {
                b'"' => string = true,
                b'{' | b'[' => {
                    depth += 1;
                    check(depth <= 8, "JSON depth budget")?;
                }
                b'}' | b']' => depth = depth.checked_sub(1).ok_or("JSON depth underflow")?,
                _ => (),
            }
        }
    }
    check(depth == 0 && !string, "incomplete JSON transport")
}
fn canonical(value: &Value, out: &mut Vec<u8>) -> Result<()> {
    match value {
        Value::Object(fields) => {
            out.push(b'{');
            let mut keys: Vec<_> = fields.keys().collect();
            keys.sort_unstable();
            for (i, key) in keys.iter().enumerate() {
                if i != 0 {
                    out.push(b',');
                }
                serde_json::to_writer(&mut *out, key).map_err(|e| e.to_string())?;
                out.push(b':');
                canonical(&fields[*key], out)?;
            }
            out.push(b'}');
        }
        Value::Array(items) => {
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i != 0 {
                    out.push(b',');
                }
                canonical(item, out)?;
            }
            out.push(b']');
        }
        _ => serde_json::to_writer(out, value).map_err(|e| e.to_string())?,
    }
    Ok(())
}
fn typed_json<T: DeserializeOwned + Serialize>(raw: &[u8]) -> Result<T> {
    check(!raw.is_empty() && raw.len() <= MAX_JSON, "JSON byte budget")?;
    depth_guard(raw)?;
    // Every object is a deny_unknown_fields derived struct. Its derived map
    // visitor rejects duplicate fields; no untyped object can hide duplicates.
    let result: T = serde_json::from_slice(raw).map_err(|e| e.to_string())?;
    let value = serde_json::to_value(&result).map_err(|e| e.to_string())?;
    let mut encoded = Vec::new();
    canonical(&value, &mut encoded)?;
    check(
        encoded == raw,
        "canonical compact sorted JSON bytes required",
    )?;
    Ok(result)
}
fn bind_request(raw: &[u8], expected_sha256: &str) -> Result<Request> {
    check(
        !raw.is_empty() && raw.len() <= MAX_JSON,
        "request byte budget",
    )?;
    hex32(expected_sha256)?;
    check(
        sha(raw) == expected_sha256,
        "caller-owned exact request digest",
    )?;
    typed_json(raw)
}
fn scalar<F: PrimeField>(text: &str) -> Result<F> {
    let bytes = hex32(text)?;
    let mut repr = F::Repr::default();
    check(repr.as_ref().len() == 32, "Pasta scalar encoding width")?;
    repr.as_mut().copy_from_slice(&bytes);
    Option::<F>::from(F::from_repr(repr)).ok_or_else(|| "noncanonical role scalar".into())
}
fn affine_bytes<G: DlogGroup>(bytes: &[u8; 32], finite: bool) -> Result<G::AffineGroupElement> {
    let mut repr = <G::AffineGroupElement as GroupEncoding>::Repr::default();
    check(repr.as_ref().len() == 32, "Pasta point encoding width")?;
    repr.as_mut().copy_from_slice(bytes);
    let point = Option::<G::AffineGroupElement>::from(G::AffineGroupElement::from_bytes(&repr))
        .ok_or("invalid canonical role point")?;
    check(
        point.to_bytes().as_ref() == bytes,
        "noncanonical point encoding alias",
    )?;
    check(
        !finite || G::group(&point) != G::zero(),
        "finite generator required",
    )?;
    Ok(point)
}
fn affine<G: DlogGroup>(text: &str, finite: bool) -> Result<G::AffineGroupElement> {
    affine_bytes::<G>(&hex32(text)?, finite)
}
fn point_hex<G: DlogGroup>(point: &G) -> String {
    hex::encode(point.affine().to_bytes().as_ref())
}

fn admit_scope(request: &Request) -> Result<usize> {
    check(
        request.schema == REQUEST_SCHEMA
            && request.nova_version == "0.76.0"
            && request.nova_crate_sha256 == NOVA_SHA
            && request.header_revision == REVISION
            && request.network == "testnet4"
            && request.k == 5
            && request.steps == 404,
        "retained IPA request backend/policy identity",
    )?;
    check(
        request.proof_sha256 == PROOF_SHA
            && request.bundle_sha256 == BUNDLE_SHA
            && request.end_state_sha256 == END_SHA
            && request.verifier_key_sha256 == VK_SHA
            && request.verifier_dimensions_sha256 == DIM_SHA
            && request.key_bindings_sha256 == KEY_SHA
            && request.native_trace_sha256 == TRACE_SHA
            && request.poseidon_parameters_sha256 == POSEIDON_SHA
            && request.generator_collection_sha256 == COLLECTION_SHA,
        "retained IPA request pins",
    )?;
    let count = match (request.role.as_str(), request.engine.as_str()) {
        ("primary", "pallas") => PRIMARY_N,
        ("secondary", "vesta") => SECONDARY_N,
        _ => return Err("IPA role/engine identity".into()),
    };
    check(
        request.ipa_dimension == count && request.generator_count == count,
        "authenticated IPA dimension",
    )?;
    Ok(count)
}
fn bind_keys(raw: &[u8]) -> Result<KeyBindings> {
    check(sha(raw) == KEY_SHA, "independent key-binding pin")?;
    let keys: KeyBindings = typed_json(raw)?;
    check(
        keys.schema == "bitvm2-nova-replay-key-bindings/v1"
            && keys.nova_version == "0.76.0"
            && keys.header_revision == REVISION
            && keys.network == "testnet4"
            && keys.k == 5
            && keys.verifier_key_sha256 == VK_SHA
            && keys.verifier_dimensions_sha256 == DIM_SHA
            && keys.primary.engine == "pallas"
            && keys.secondary.engine == "vesta"
            && keys.primary.ipa_scalar_key.ck.len() == 1
            && keys.secondary.ipa_scalar_key.ck.len() == 1,
        "key-binding identity/scalar-key arity",
    )?;
    Ok(keys)
}
fn bind_collection(raw: &[u8]) -> Result<Collection> {
    hex32(COLLECTION_SHA).map_err(|_| "actual authenticated generator export is not pinned yet")?;
    check(
        sha(raw) == COLLECTION_SHA,
        "independent generator collection pin",
    )?;
    let collection: Collection = typed_json(raw)?;
    check(
        collection.schema == COLLECTION_SCHEMA
            && collection.nova_version == "0.76.0"
            && collection.nova_crate_sha256 == NOVA_SHA
            && collection.header_revision == REVISION
            && collection.network == "testnet4"
            && collection.k == 5
            && collection.verifier_key_sha256 == VK_SHA
            && collection.verifier_dimensions_sha256 == DIM_SHA
            && collection.encoding == "bincode-1.3.3-legacy-fixed-little-endian"
            && collection.files.len() == 2,
        "generator collection policy identity",
    )?;
    let mut total = 0u64;
    for (record, (role, engine, count)) in collection.files.iter().zip([
        ("primary", "pallas", PRIMARY_N),
        ("secondary", "vesta", SECONDARY_N),
    ]) {
        check(
            record.role == role
                && record.engine == engine
                && record.base_field_role == format!("{engine}_base")
                && record.scalar_field_role == format!("{engine}_scalar")
                && record.filename == format!("{role}-generators.bin")
                && record.count == count,
            "generator file role/dimension identity",
        )?;
        validate_record(record, count)?;
        total = total
            .checked_add(record.bytes)
            .ok_or("generator total overflow")?;
    }
    check(
        total == collection.total_bytes && total <= MAX_GENERATOR_BYTES,
        "generator collection byte budget",
    )?;
    Ok(collection)
}
fn validate_record(record: &GeneratorFile, count: usize) -> Result<()> {
    check(
        count.is_power_of_two() && count <= PRIMARY_N && record.count == count,
        "generator count budget",
    )?;
    let points_bytes = (count as u64)
        .checked_mul(32)
        .ok_or("generator byte overflow")?;
    let bytes = points_bytes
        .checked_add(8)
        .ok_or("generator byte overflow")?;
    check(
        record.bytes == bytes && bytes <= MAX_GENERATOR_BYTES && record.segments.len() == 2,
        "generator file byte/segment bounds",
    )?;
    let head = &record.segments[0];
    let points = &record.segments[1];
    check(
        head.name == "count"
            && head.offset == 0
            && head.bytes == 8
            && points.name == "points"
            && points.offset == 8
            && points.bytes == points_bytes,
        "generator segment order/coverage",
    )?;
    hex32(&record.sha256)?;
    hex32(&head.sha256)?;
    hex32(&points.sha256)?;
    Ok(())
}
fn read_generators<G: DlogGroup, R: Read>(
    mut reader: R,
    record: &GeneratorFile,
    count: usize,
) -> Result<Vec<G::AffineGroupElement>> {
    validate_record(record, count)?;
    let mut header = [0; 8];
    reader
        .read_exact(&mut header)
        .map_err(|_| "truncated generator count")?;
    check(
        u64::from_le_bytes(header) == count as u64,
        "generator count prefix",
    )?;
    check(
        sha(&header) == record.segments[0].sha256,
        "generator count segment digest",
    )?;
    let mut whole = Sha256::new();
    whole.update(header);
    let mut points = Sha256::new();
    let mut bases = Vec::with_capacity(count);
    for _ in 0..count {
        let mut encoded = [0; 32];
        reader
            .read_exact(&mut encoded)
            .map_err(|_| "truncated generator point stream")?;
        whole.update(encoded);
        points.update(encoded);
        bases.push(affine_bytes::<G>(&encoded, true)?);
    }
    let mut extra = [0; 1];
    check(
        reader.read(&mut extra).map_err(|e| e.to_string())? == 0,
        "surplus generator bytes",
    )?;
    check(
        hex::encode(points.finalize()) == record.segments[1].sha256
            && hex::encode(whole.finalize()) == record.sha256,
        "exact consumed generator stream digest",
    )?;
    // The immutable points used below are decoded from exactly the bytes just
    // hashed. No reopen/re-read of a mutable pathname occurs after this check.
    Ok(bases)
}

struct Statement<G: DlogGroup> {
    commitment: G::AffineGroupElement,
    evaluation: G::Scalar,
    point: Vec<G::Scalar>,
    r0: G::Scalar,
    left: Vec<G::AffineGroupElement>,
    right: Vec<G::AffineGroupElement>,
    challenges: Vec<G::Scalar>,
    inverses: Vec<G::Scalar>,
    a_hat: G::Scalar,
    python_residual: G::AffineGroupElement,
}
fn decode_statement<G: DlogGroup>(request: &Request, count: usize) -> Result<Statement<G>> {
    check(
        count.is_power_of_two() && count <= PRIMARY_N,
        "IPA dimension budget",
    )?;
    let rounds = count.trailing_zeros() as usize;
    check(
        request.batch_point_le.len() == rounds
            && request.left.len() == rounds
            && request.right.len() == rounds
            && request.challenges_le.len() == rounds,
        "IPA round/vector arity",
    )?;
    let challenges: Vec<G::Scalar> = request
        .challenges_le
        .iter()
        .map(|s| scalar(s))
        .collect::<Result<_>>()?;
    let inverses = challenges
        .iter()
        .map(|u| {
            Option::<G::Scalar>::from(u.invert())
                .ok_or_else(|| "zero IPA inversion challenge".to_owned())
        })
        .collect::<Result<_>>()?;
    Ok(Statement {
        commitment: affine::<G>(&request.joint_commitment, false)?,
        evaluation: scalar(&request.joint_evaluation_le)?,
        point: request
            .batch_point_le
            .iter()
            .map(|s| scalar(s))
            .collect::<Result<_>>()?,
        r0: scalar(&request.ipa_initial_challenge_le)?,
        left: request
            .left
            .iter()
            .map(|s| affine::<G>(s, false))
            .collect::<Result<_>>()?,
        right: request
            .right
            .iter()
            .map(|s| affine::<G>(s, false))
            .collect::<Result<_>>()?,
        challenges,
        inverses,
        a_hat: scalar(&request.a_hat_le)?,
        python_residual: affine::<G>(&request.generator_residual, false)?,
    })
}
fn tensor_weights<F: PrimeField>(challenges: &[F], inverses: &[F], count: usize) -> Result<Vec<F>> {
    check(
        challenges.len() <= 19
            && challenges.len() == inverses.len()
            && count
                == 1usize
                    .checked_shl(challenges.len() as u32)
                    .ok_or("IPA shift budget")?,
        "IPA tensor dimensions",
    )?;
    let mut weights = vec![F::ZERO; count];
    weights[0] = inverses.iter().copied().fold(F::ONE, |a, b| a * b);
    let squares: Vec<_> = challenges.iter().map(|u| u.square()).collect();
    for i in 1..count {
        let position = (usize::BITS - 1 - i.leading_zeros()) as usize;
        weights[i] = weights[i - (1usize << position)] * squares[challenges.len() - 1 - position];
    }
    Ok(weights)
}
fn b_hat<G: DlogGroup>(statement: &Statement<G>) -> G::Scalar {
    statement
        .point
        .iter()
        .zip(&statement.challenges)
        .zip(&statement.inverses)
        .fold(G::Scalar::ONE, |product, ((point, challenge), inverse)| {
            product * ((G::Scalar::ONE - *point) * inverse + *point * challenge)
        })
}
fn small_side<G: DlogGroup>(statement: &Statement<G>, u0: &G::AffineGroupElement) -> G {
    let mut residual =
        G::group(&statement.commitment) + G::group(u0) * (statement.r0 * statement.evaluation);
    for ((left, right), (challenge, inverse)) in statement
        .left
        .iter()
        .zip(&statement.right)
        .zip(statement.challenges.iter().zip(&statement.inverses))
    {
        residual += G::group(left) * challenge.square();
        residual += G::group(right) * inverse.square();
    }
    residual - G::group(u0) * (statement.r0 * statement.a_hat * b_hat(statement))
}
fn relation<G: DlogGroupExt>(
    statement: &Statement<G>,
    u0: &G::AffineGroupElement,
    bases: &[G::AffineGroupElement],
) -> Result<Value> {
    let count = bases.len();
    check(
        count.is_power_of_two()
            && count <= PRIMARY_N
            && statement.point.len() == statement.challenges.len()
            && statement.left.len() == statement.challenges.len()
            && statement.right.len() == statement.challenges.len()
            && statement.inverses.len() == statement.challenges.len()
            && statement.challenges.len() <= 19
            && count == (1usize << statement.challenges.len()),
        "terminal relation dimensions",
    )?;
    let residual = small_side(statement, u0);
    check(
        residual == G::group(&statement.python_residual),
        "independent small-side residual mismatch",
    )?;
    let weights = tensor_weights(&statement.challenges, &statement.inverses, count)?;
    check(
        weights.len() == bases.len(),
        "mature MSM equal-length precondition",
    )?;
    let mut weight_digest = Sha256::new();
    for weight in &weights {
        weight_digest.update(weight.to_repr().as_ref());
    }
    let started = Instant::now();
    // Original Nova public CPU API. No private/new curve arithmetic or MSM.
    let generator_sum = G::vartime_multiscalar_mul(&weights, bases);
    let scaled = generator_sum * statement.a_hat;
    Ok(json!({"relation_holds": residual == scaled,
        "residual_matches_python": true, "generators_consumed": count,
        "weights_computed": weights.len(), "ipa_rounds": statement.challenges.len(),
        "weights_sha256": hex::encode(weight_digest.finalize()),
        "factorized_b_hat_le": hex::encode(b_hat(statement).to_repr().as_ref()),
        "generator_sum": point_hex(&generator_sum), "scaled_generator_sum": point_hex(&scaled),
        "required_generator_residual": point_hex(&residual),
        "msm_seconds": started.elapsed().as_secs_f64()}))
}
fn execute_role<G: DlogGroupExt>(
    request: &Request,
    key: &RoleKey,
    record: &GeneratorFile,
    path: &str,
    count: usize,
) -> Result<Value> {
    let statement = decode_statement::<G>(request, count)?;
    check(key.ipa_scalar_key.ck.len() == 1, "scalar key arity")?;
    let u0 = affine::<G>(&key.ipa_scalar_key.ck[0], true)?;
    let file = File::open(path).map_err(|e| e.to_string())?;
    check(
        file.metadata().map_err(|e| e.to_string())?.len() == record.bytes,
        "generator file length",
    )?;
    let bases = read_generators::<G, _>(BufReader::new(file), record, count)?;
    relation(&statement, &u0, &bases)
}
fn run() -> Result<Value> {
    let args: Vec<_> = std::env::args().collect();
    check(
        args.len() == 6,
        "usage: ipa_msm REQUEST.json KEY_BINDINGS.json COLLECTION.json GENERATORS.bin EXPECTED_REQUEST_SHA256",
    )?;
    let started = Instant::now();
    let raw = read(&args[1], MAX_JSON)?;
    // The trusted direct caller supplies this digest out of band from its
    // sealed preparation object. Hash the same immutable bytes decoded below.
    let request = bind_request(&raw, &args[5])?;
    let count = admit_scope(&request)?;
    let collection_raw = read(&args[3], MAX_JSON)?;
    let collection = bind_collection(&collection_raw)?;
    let keys = bind_keys(&read(&args[2], MAX_JSON)?)?;
    let terminal = match request.role.as_str() {
        "primary" => execute_role::<<PallasEngine as Engine>::GE>(
            &request,
            &keys.primary,
            &collection.files[0],
            &args[4],
            count,
        )?,
        "secondary" => execute_role::<<VestaEngine as Engine>::GE>(
            &request,
            &keys.secondary,
            &collection.files[1],
            &args[4],
            count,
        )?,
        _ => return Err("unsupported IPA role".into()),
    };
    Ok(
        json!({"schema":"bitvm2-nova-ipa-msm-result/v1", "request_sha256":sha(&raw),
        "generator_collection_sha256":COLLECTION_SHA,"key_bindings_sha256":KEY_SHA,
        "role":request.role,"engine":request.engine,"ipa_dimension":count,"terminal":terminal,
        "generator_bytes_authenticated":true,"cpu_only":true,"wall_seconds":started.elapsed().as_secs_f64(),
        "native_proofs_verified":0,"proving_jobs":0,"proof_verified":false,"bitvm2_script_verified":false,
        "scope":"mathematical IPA terminal relation for exact supplied request, not proof acceptance"}),
    )
}
fn main() {
    match run() {
        Ok(result) => println!(
            "{}",
            serde_json::to_string_pretty(&result).expect("JSON result")
        ),
        Err(error) => {
            eprintln!("IPA terminal check failed: {error}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn toy<G: DlogGroupExt>(
        zero_r0: bool,
    ) -> (
        Statement<G>,
        G::AffineGroupElement,
        Vec<G::AffineGroupElement>,
    ) {
        let challenges = vec![G::Scalar::from(2), G::Scalar::from(3), G::Scalar::from(5)];
        let inverses = challenges
            .iter()
            .map(|u| Option::<G::Scalar>::from(u.invert()).unwrap())
            .collect::<Vec<_>>();
        let bases = (1..=8)
            .map(|i| (G::gen() * G::Scalar::from(i)).affine())
            .collect::<Vec<_>>();
        let u0 = (G::gen() * G::Scalar::from(37)).affine();
        let mut statement = Statement {
            commitment: G::zero().affine(),
            evaluation: G::Scalar::from(23),
            point: vec![G::Scalar::from(7), G::Scalar::from(11), G::Scalar::from(13)],
            r0: if zero_r0 {
                G::Scalar::ZERO
            } else {
                G::Scalar::from(17)
            },
            left: (29..32)
                .map(|i| (G::gen() * G::Scalar::from(i)).affine())
                .collect(),
            right: (41..44)
                .map(|i| (G::gen() * G::Scalar::from(i)).affine())
                .collect(),
            challenges,
            inverses,
            a_hat: G::Scalar::from(19),
            python_residual: G::zero().affine(),
        };
        // Independent explicit MSB-order tensor products and naive small MSM.
        let mut target = G::zero();
        for (index, base) in bases.iter().enumerate() {
            let mut weight = G::Scalar::ONE;
            for j in 0..3 {
                weight *= if (index >> (2 - j)) & 1 == 0 {
                    statement.inverses[j]
                } else {
                    statement.challenges[j]
                };
            }
            target += G::group(base) * weight;
        }
        target = target * statement.a_hat;
        let offset = small_side(&statement, &u0);
        statement.commitment = (target - offset).affine();
        statement.python_residual = target.affine();
        (statement, u0, bases)
    }
    fn toy_relations<G: DlogGroupExt>() {
        for zero_r0 in [false, true] {
            let (mut statement, u0, mut bases) = toy::<G>(zero_r0);
            assert_eq!(
                relation(&statement, &u0, &bases).unwrap()["relation_holds"],
                true
            );
            bases.swap(0, 1);
            assert_eq!(
                relation(&statement, &u0, &bases).unwrap()["relation_holds"],
                false
            );
            bases.swap(0, 1);
            statement.a_hat += G::Scalar::ONE;
            statement.python_residual = small_side(&statement, &u0).affine();
            assert_eq!(
                relation(&statement, &u0, &bases).unwrap()["relation_holds"],
                false
            );
        }
    }
    fn toy_request<G: DlogGroup>(statement: &Statement<G>) -> Request {
        let field = |value: &G::Scalar| hex::encode(value.to_repr().as_ref());
        let point = |value: &G::AffineGroupElement| hex::encode(value.to_bytes().as_ref());
        Request {
            schema: REQUEST_SCHEMA.into(),
            nova_version: "0.76.0".into(),
            nova_crate_sha256: NOVA_SHA.into(),
            header_revision: REVISION.into(),
            network: "testnet4".into(),
            k: 5,
            steps: 404,
            bundle_sha256: BUNDLE_SHA.into(),
            end_state_sha256: END_SHA.into(),
            role: "primary".into(),
            engine: "pallas".into(),
            proof_sha256: PROOF_SHA.into(),
            verifier_key_sha256: VK_SHA.into(),
            verifier_dimensions_sha256: DIM_SHA.into(),
            key_bindings_sha256: KEY_SHA.into(),
            native_trace_sha256: TRACE_SHA.into(),
            poseidon_parameters_sha256: POSEIDON_SHA.into(),
            generator_collection_sha256: COLLECTION_SHA.into(),
            ipa_dimension: 8,
            generator_count: 8,
            joint_commitment: point(&statement.commitment),
            joint_evaluation_le: field(&statement.evaluation),
            batch_point_le: statement.point.iter().map(field).collect(),
            ipa_initial_challenge_le: field(&statement.r0),
            left: statement.left.iter().map(point).collect(),
            right: statement.right.iter().map(point).collect(),
            challenges_le: statement.challenges.iter().map(field).collect(),
            a_hat_le: field(&statement.a_hat),
            generator_residual: point(&statement.python_residual),
        }
    }
    #[test]
    fn toy_cpu_msm_terminal_relations_both_scalar_roles() {
        toy_relations::<<PallasEngine as Engine>::GE>();
        toy_relations::<<VestaEngine as Engine>::GE>();
    }
    #[test]
    fn canonical_point_and_scalar_guards_reject_aliases() {
        type P = <PallasEngine as Engine>::GE;
        type V = <VestaEngine as Engine>::GE;
        let mut alias = [0; 32];
        alias[31] = 128;
        assert!(affine_bytes::<P>(&alias, false).is_err());
        assert!(affine_bytes::<V>(&alias, false).is_err());
        assert!(affine_bytes::<P>(&[0; 32], true).is_err());
        assert!(affine_bytes::<V>(&[0; 32], true).is_err());
        assert!(scalar::<<PallasEngine as Engine>::Scalar>(&"ff".repeat(32)).is_err());
        assert!(scalar::<<VestaEngine as Engine>::Scalar>(&"ff".repeat(32)).is_err());
        assert!(hex32(&"AA".repeat(32)).is_err());
    }
    #[test]
    fn decoded_input_arity_zero_challenge_and_retained_scope_guards() {
        type G = <PallasEngine as Engine>::GE;
        let (statement, _, _) = toy::<G>(true);
        let mut request = toy_request(&statement);
        assert!(decode_statement::<G>(&request, 8).is_ok());
        assert!(admit_scope(&request).is_err()); // Toy dimensions never enter CLI scope.
        request.a_hat_le = "00".repeat(32);
        request.ipa_initial_challenge_le = "00".repeat(32);
        assert!(decode_statement::<G>(&request, 8).is_ok()); // r0 and a_hat may be zero.
        request.challenges_le[0] = "00".repeat(32);
        assert!(decode_statement::<G>(&request, 8).is_err());
        request = toy_request(&statement);
        request.right.pop();
        assert!(decode_statement::<G>(&request, 8).is_err());
        request = toy_request(&statement);
        request.ipa_dimension = usize::MAX;
        request.generator_count = usize::MAX;
        assert!(admit_scope(&request).is_err());
        request = toy_request(&statement);
        request.role = "secondary".into();
        assert!(admit_scope(&request).is_err());
    }
    #[test]
    fn caller_digest_binds_exact_canonical_request_snapshot() {
        type G = <PallasEngine as Engine>::GE;
        let (statement, _, _) = toy::<G>(false);
        let request = toy_request(&statement);
        let mut raw = Vec::new();
        canonical(&serde_json::to_value(request).unwrap(), &mut raw).unwrap();
        let expected = sha(&raw);
        assert!(bind_request(&raw, &expected).is_ok());
        assert!(bind_request(&raw, &"00".repeat(32)).is_err());
        raw.push(b'\n');
        assert!(bind_request(&raw, &expected).is_err());
        assert!(bind_request(&raw, &sha(&raw)).is_err()); // Hash alone cannot admit noncanonical transport.
        assert!(bind_request(&vec![b' '; MAX_JSON + 1], &"00".repeat(32)).is_err());
    }
    #[test]
    fn tensor_weights_match_explicit_msb_order_and_reject_bad_dimensions() {
        type F = <PallasEngine as Engine>::Scalar;
        let challenges = [F::from(2), F::from(3), F::from(5)];
        let inverses = challenges
            .iter()
            .map(|u| Option::<F>::from(u.invert()).unwrap())
            .collect::<Vec<_>>();
        let weights = tensor_weights(&challenges, &inverses, 8).unwrap();
        for (index, actual) in weights.iter().enumerate() {
            let expected = (0..3).fold(F::ONE, |a, j| {
                a * if (index >> (2 - j)) & 1 == 0 {
                    inverses[j]
                } else {
                    challenges[j]
                }
            });
            assert_eq!(*actual, expected);
        }
        assert!(tensor_weights(&challenges, &inverses, 7).is_err());
        assert!(tensor_weights(&challenges, &inverses[..2], 8).is_err());
    }
    fn toy_record<G: DlogGroup>() -> (GeneratorFile, Vec<u8>) {
        let mut raw = 8u64.to_le_bytes().to_vec();
        for i in 1..=8 {
            raw.extend_from_slice((G::gen() * G::Scalar::from(i)).affine().to_bytes().as_ref());
        }
        let record = GeneratorFile {
            role: "toy".into(),
            engine: "toy".into(),
            base_field_role: "toy".into(),
            scalar_field_role: "toy".into(),
            filename: "toy.bin".into(),
            count: 8,
            bytes: raw.len() as u64,
            sha256: sha(&raw),
            segments: vec![
                Segment {
                    name: "count".into(),
                    offset: 0,
                    bytes: 8,
                    sha256: sha(&raw[..8]),
                },
                Segment {
                    name: "points".into(),
                    offset: 8,
                    bytes: 256,
                    sha256: sha(&raw[8..]),
                },
            ],
        };
        (record, raw)
    }
    #[test]
    fn generator_stream_prefix_eof_and_exact_consumed_hash_are_checked() {
        type G = <PallasEngine as Engine>::GE;
        let (record, raw) = toy_record::<G>();
        assert_eq!(
            read_generators::<G, _>(Cursor::new(&raw), &record, 8)
                .unwrap()
                .len(),
            8
        );
        assert!(read_generators::<G, _>(Cursor::new(&raw[..raw.len() - 1]), &record, 8).is_err());
        let mut extra = raw.clone();
        extra.push(0);
        assert!(read_generators::<G, _>(Cursor::new(extra), &record, 8).is_err());
        let mut wrong_count = raw.clone();
        wrong_count[..8].copy_from_slice(&7u64.to_le_bytes());
        assert!(read_generators::<G, _>(Cursor::new(wrong_count), &record, 8).is_err());
        let mut reordered = raw.clone();
        reordered[8..40].copy_from_slice(&raw[40..72]);
        reordered[40..72].copy_from_slice(&raw[8..40]);
        assert!(read_generators::<G, _>(Cursor::new(reordered), &record, 8).is_err());
    }
    #[test]
    fn typed_transport_rejects_duplicate_unknown_and_deep_json() {
        #[derive(Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Tiny {
            count: usize,
        }
        assert!(typed_json::<Tiny>(br#"{"count":8}"#).is_ok());
        for invalid in [
            br#"{"count":8,"count":8}"#.as_slice(),
            br#"{"count":true}"#,
            br#"{"count":8,"other":0}"#,
            br#"{ "count":8}"#,
        ] {
            assert!(typed_json::<Tiny>(invalid).is_err());
        }
        assert!(depth_guard(b"[[[[[[[[[0]]]]]]]]]").is_err());
        assert!(depth_guard(br#"{"string":"[[[[[[[[[["}"#).is_ok());
    }
}
