//! Bounded conformance using actual public Nova0.76 SumcheckProof verification.
//! Synthetic algebra/transcript cases are not full Spartan/Nova proof validity.
//! Strict admission excludes known upstream panic paths; no catch_unwind.
use ff::{Field, PrimeField};
use nova_snark::{
    provider::{keccak::Keccak256Transcript, PallasEngine, VestaEngine},
    spartan::{
        polys::{eq::EqPolynomial, multilinear::SparsePolynomial, univariate::UniPoly},
        sumcheck::SumcheckProof,
    },
    traits::Engine,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{env, fs, io::Read};

const MAX_FILE: u64 = 2 << 20;
const MAX_ROUNDS: usize = 32;
const MAX_INSTANCES: usize = 64;
#[derive(Debug)]
enum Failure {
    Admission(String),
    Upstream,
    Terminal,
    Conformance(String),
}
type Result<T> = std::result::Result<T, Failure>;
fn admission(message: &str) -> Failure {
    Failure::Admission(message.to_owned())
}
fn conformance(message: &str) -> Failure {
    Failure::Conformance(message.to_owned())
}
fn get<'a>(value: &'a Value, key: &str) -> Result<&'a Value> {
    value.get(key).ok_or_else(|| admission("missing field"))
}
fn array(value: &Value, limit: usize) -> Result<&Vec<Value>> {
    let array = value
        .as_array()
        .ok_or_else(|| admission("array required"))?;
    if array.len() > limit {
        return Err(admission("array bound exceeded"));
    }
    Ok(array)
}
fn count(value: &Value, max: usize) -> Result<usize> {
    let n = value
        .as_u64()
        .ok_or_else(|| admission("unsigned count required"))?;
    if n > max as u64 {
        return Err(admission("count bound exceeded"));
    }
    Ok(n as usize)
}
fn scalar<F: PrimeField>(value: &Value) -> Result<F> {
    let encoded = value
        .as_str()
        .ok_or_else(|| admission("field hex required"))?;
    if encoded.len() != 64 {
        return Err(admission("field must be exactly 32 bytes"));
    }
    let bytes = hex::decode(encoded).map_err(|_| admission("invalid field hex"))?;
    let mut repr = F::Repr::default();
    if repr.as_ref().len() != bytes.len() {
        return Err(admission("unsupported field size"));
    }
    repr.as_mut().copy_from_slice(&bytes);
    Option::from(F::from_repr(repr)).ok_or_else(|| admission("noncanonical field"))
}
fn scalars<F: PrimeField>(value: &Value, max: usize) -> Result<Vec<F>> {
    array(value, max)?.iter().map(scalar).collect()
}
fn repr<F: PrimeField>(value: &F) -> Value {
    Value::String(hex::encode(value.to_repr().as_ref()))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    round: u64,
    state: Vec<u8>,
    #[serde(default)]
    transcript_buffer: Vec<u8>,
}
fn snapshot_check(value: &Value, rounds: usize) -> Result<()> {
    let snapshot: Snapshot = serde_json::from_value(value.clone())
        .map_err(|_| admission("invalid transcript snapshot"))?;
    if snapshot.state.len() != 64 || snapshot.transcript_buffer.len() > (1 << 20) - 257 {
        return Err(admission("snapshot state/buffer length"));
    }
    if snapshot.round.checked_add(rounds as u64).is_none() {
        return Err(admission("transcript round overflow"));
    }
    Ok(())
}

fn run<E>(case: &Value) -> Result<usize>
where
    E: Engine<TE = Keccak256Transcript<E>>,
{
    let degree = count(get(case, "degree")?, 3)?;
    if degree != 2 && degree != 3 {
        return Err(admission("unsupported degree"));
    }
    let rounds = count(get(case, "rounds")?, MAX_ROUNDS)?;
    let initial_claim = scalar::<E::Scalar>(get(case, "initial_claim")?)?;
    let rows = array(get(case, "proof")?, MAX_ROUNDS)?;
    // Construct using the public coefficients field, not from_coeffs(), which
    // normalizes trailing zeroes and would erase encoded degree failures.
    let mut compressed = Vec::with_capacity(rows.len());
    for row in rows {
        let row = scalars::<E::Scalar>(row, 8)?;
        if row.is_empty() {
            return Err(admission(
                "empty compressed polynomial would panic upstream",
            ));
        }
        let coefficients = [vec![row[0], E::Scalar::ZERO], row[1..].to_vec()].concat();
        compressed.push(
            UniPoly {
                coeffs: coefficients,
            }
            .compress(),
        );
    }
    let snapshot = get(case, "snapshot")?;
    snapshot_check(snapshot, rounds)?;
    let mut transcript: Keccak256Transcript<E> = serde_json::from_value(snapshot.clone())
        .map_err(|_| conformance("upstream transcript deserialize"))?;
    let proof = SumcheckProof::<E>::new(compressed);
    let folded = if let Some(batch) = case.get("batch") {
        let claims = scalars::<E::Scalar>(get(batch, "claims")?, MAX_INSTANCES)?;
        let coefficients = scalars::<E::Scalar>(get(batch, "coefficients")?, MAX_INSTANCES)?;
        let counts: Vec<usize> = array(get(batch, "rounds")?, MAX_INSTANCES)?
            .iter()
            .map(|n| count(n, MAX_ROUNDS))
            .collect::<Result<_>>()?;
        if claims.is_empty() || counts.len() != claims.len() || coefficients.len() != claims.len() {
            return Err(admission(
                "empty or mismatched batch vectors would panic upstream",
            ));
        }
        // Also prove the adapter's externally supplied max-round expectation.
        if *counts.iter().max().unwrap() != rounds {
            return Err(admission("batch verifier round expectation mismatch"));
        }
        proof.verify_batch(&claims, &counts, &coefficients, degree, &mut transcript)
    } else {
        proof.verify(initial_claim, rounds, degree, &mut transcript)
    };
    let (final_claim, challenges) = folded.map_err(|_| Failure::Upstream)?;
    let expected_final = scalar::<E::Scalar>(get(case, "expected_final")?)?;
    if final_claim != expected_final {
        return Err(Failure::Terminal);
    }
    let expected_challenges = scalars::<E::Scalar>(get(case, "challenges")?, MAX_ROUNDS)?;
    if challenges != expected_challenges {
        return Err(conformance("actual upstream challenges differ"));
    }
    if serde_json::to_value(&transcript).map_err(|_| conformance("snapshot serialize"))?
        != *get(case, "expected_snapshot")?
    {
        return Err(conformance("actual upstream transcript state differs"));
    }
    // Independently call the actual upstream decompressor on every row.
    let expected_polys = array(get(case, "decompressed")?, MAX_ROUNDS)?;
    if expected_polys.len() != rows.len() {
        return Err(conformance("expected decompressed round count"));
    }
    let mut claim = if let Some(batch) = case.get("batch") {
        let claims = scalars::<E::Scalar>(get(batch, "claims")?, MAX_INSTANCES)?;
        let coefficients = scalars::<E::Scalar>(get(batch, "coefficients")?, MAX_INSTANCES)?;
        let counts = array(get(batch, "rounds")?, MAX_INSTANCES)?;
        let mut value = E::Scalar::ZERO;
        for ((c, coefficient), n) in claims.iter().zip(&coefficients).zip(counts) {
            value += *c
                * *coefficient
                * E::Scalar::from(2u64).pow_vartime([(rounds - count(n, MAX_ROUNDS)?) as u64]);
        }
        value
    } else {
        initial_claim
    };
    for ((compressed, expected), challenge) in proof
        .compressed_polys()
        .iter()
        .zip(expected_polys)
        .zip(&challenges)
    {
        let poly = compressed.decompress(&claim);
        if poly.coeffs != scalars::<E::Scalar>(expected, 9)? {
            return Err(conformance(
                "actual upstream coefficient reconstruction differs",
            ));
        }
        claim = poly.evaluate(challenge);
    }
    Ok(rounds)
}

fn terminal<E: Engine>(case: &Value) -> Result<usize> {
    let v = get(case, "values")?;
    let f = |name: &str| -> Result<E::Scalar> { scalar(get(v, name)?) };
    let vec = |name: &str| -> Result<Vec<E::Scalar>> { scalars(get(v, name)?, MAX_INSTANCES) };
    let tau = vec("tau")?;
    let rx = vec("rx")?;
    let ry = vec("ry")?;
    if tau.len() != rx.len() || rx.len() > MAX_ROUNDS || ry.is_empty() || ry.len() > MAX_ROUNDS {
        return Err(admission("terminal point dimension"));
    }
    let eq = EqPolynomial::new(tau).evaluate(&rx);
    let outer = eq * (f("az")? * f("bz")? - f("u")? * f("cz")? - f("eval_e")?);
    let mut public = vec("public_inputs")?;
    public.insert(0, f("u")?);
    // Upstream sparse evaluate subtracts 1+ceil(log2(Z.len())) from num_vars.
    // Guard it before execution; this also bounds its temporary equality table.
    let log_values = public.len().next_power_of_two().trailing_zeros() as usize;
    if public.len() > MAX_INSTANCES || ry.len() - 1 < 1 + log_values {
        return Err(admission("unsafe upstream sparse dimensions"));
    }
    let sparse = SparsePolynomial::new(ry.len() - 1, public).evaluate(&ry[1..]);
    let z = (E::Scalar::ONE - ry[0]) * f("eval_w")? + ry[0] * sparse;
    let rho = f("rho")?;
    let inner = z * (f("a")? + rho * f("b")? + rho * rho * f("c")?);
    let evals = vec("batch_evals")?;
    let coefficients = vec("batch_coefficients")?;
    let points = array(get(v, "batch_points")?, MAX_INSTANCES)?;
    if evals.is_empty() || evals.len() != coefficients.len() || evals.len() != points.len() {
        return Err(admission("terminal batch length mismatch"));
    }
    let mut batch = E::Scalar::ZERO;
    for ((value, coefficient), point) in evals.iter().zip(&coefficients).zip(points) {
        let point = scalars::<E::Scalar>(point, MAX_ROUNDS)?;
        if point.len() > rx.len() {
            return Err(admission("terminal batch point dimension"));
        }
        let n = point.len();
        batch += *value * *coefficient * EqPolynomial::new(point).evaluate(&rx[rx.len() - n..]);
    }
    let expected = get(case, "expected")?;
    for (name, actual) in [
        ("eq", eq),
        ("sparse", sparse),
        ("outer", outer),
        ("inner", inner),
        ("batch", batch),
    ] {
        if repr(&actual) != *get(expected, name)? {
            return Err(conformance(
                "terminal field/equality/sparse equation mismatch",
            ));
        }
    }
    Ok(5)
}

fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let path = env::args().nth(1).ok_or("usage: sumcheck CASES.json")?;
    let file = fs::File::open(path)?;
    if file.metadata()?.len() > MAX_FILE {
        return Err("case file too large".into());
    }
    let mut bytes = Vec::new();
    file.take(MAX_FILE + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_FILE {
        return Err("case file too large".into());
    }
    let input: Value = serde_json::from_slice(&bytes)?;
    let cases = input["cases"].as_array().ok_or("cases required")?;
    if cases.len() > 256 {
        return Err("case count limit".into());
    }
    let (mut accepted, mut admitted, mut upstream, mut terminal_rejections, mut rounds) =
        (0, 0, 0, 0, 0);
    for case in cases {
        let actual = match case["engine"].as_str() {
            Some("pallas") => run::<PallasEngine>(case),
            Some("vesta") => run::<VestaEngine>(case),
            _ => Err(admission("unsupported engine")),
        };
        match (case["expect"].as_str(), actual) {
            (Some("accept"), Ok(n)) => {
                accepted += 1;
                rounds += n;
            }
            (Some("admission"), Err(Failure::Admission(reason))) if !reason.is_empty() => {
                admitted += 1
            }
            (Some("upstream"), Err(Failure::Upstream)) => upstream += 1,
            (Some("terminal"), Err(Failure::Terminal)) => terminal_rejections += 1,
            (_, Err(Failure::Conformance(reason))) => {
                return Err(format!("{}: {reason}", case["name"]).into())
            }
            (expect, actual) => {
                return Err(
                    format!("{} expected {expect:?}, actual {actual:?}", case["name"]).into(),
                )
            }
        }
    }
    let terminals = input["terminals"]
        .as_array()
        .ok_or("terminal cases required")?;
    if terminals.len() > 128 {
        return Err("terminal count limit".into());
    }
    let mut equations = 0;
    for case in terminals {
        equations += match case["engine"].as_str() {
            Some("pallas") => terminal::<PallasEngine>(case),
            Some("vesta") => terminal::<VestaEngine>(case),
            _ => Err(admission("unsupported terminal engine")),
        }
        .map_err(|e| format!("terminal conformance: {e:?}"))?;
    }
    println!(
        "{}",
        json!({"backend":"nova-snark=0.76.0/non-EVM", "cases":cases.len(),
        "accepted":accepted,"accepted_rounds":rounds,"admission_rejections":admitted,
        "upstream_verifier_rejections":upstream,"terminal_rejections":terminal_rejections,
        "actual_upstream_verifier_calls":accepted+upstream+terminal_rejections,
        "terminal_equations":equations,"panic_is_rejection":false,"proving":false,
        "full_proof_transcript_replay":false,"complete_verifier":false})
    );
    Ok(())
}
