//! Bounded proof admission differential oracle, not proof verification.
//! All variable lengths are checked before actual Nova bincode deserialization.
use bincode::Options;
use nova_header_chain::HeaderStep;
use nova_snark::{
    nova::CompressedSNARK,
    provider::{ipa_pc, PallasEngine, VestaEngine},
    spartan::snark::RelaxedR1CSSNARK,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs::File, io::Read};

type E1 = PallasEngine;
type E2 = VestaEngine;
type S1 = RelaxedR1CSSNARK<E1, ipa_pc::EvaluationEngine<E1>>;
type S2 = RelaxedR1CSSNARK<E2, ipa_pc::EvaluationEngine<E2>>;
type Proof = CompressedSNARK<E1, E2, HeaderStep, S1, S2>;
type Result<T> = std::result::Result<T, String>;
const MAX_PROOF: usize = 1 << 20;
const MAX_CASES: usize = 256;
const MAX_DIMENSION: usize = 1 << 24;
const REVISION: &str = "de607d3db17d400dd6c2923d357f1d4a7bf233c7";
const CRATE_SHA: &str = "c9bb3809a6c70057ea722c1c4fe5097cf29a3479d0b4671f3cddb1d81043bb31";
// Replaced only from the independently rebuilt, key-bound descriptor in CI.
// Never accept a corpus/report supplied replacement for this verifier-owned pin.
const PINNED_DIMENSIONS_SHA256: &str =
    "de6333df2e41b5f5bae1c103fab862f8d6022fd54abeb80ba61920bc9f360edc";

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct CurveDimensions {
    engine: String,
    num_cons: usize,
    num_vars: usize,
    num_io: usize,
    outer_rounds: usize,
    inner_rounds: usize,
    batch_rounds: usize,
    ipa_rounds: usize,
    ipa_dimension: usize,
    ck_v_generators: usize,
    ck_s_generators: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Dimensions {
    schema: String,
    nova_version: String,
    nova_crate_sha256: String,
    header_revision: String,
    network: String,
    k: usize,
    verifier_key_sha256: String,
    outer_arity: usize,
    max_ipa_dimension: usize,
    primary: CurveDimensions,
    secondary: CurveDimensions,
}

#[derive(Deserialize)]
struct ExpectedIdentity {
    schema: String,
    nova_version: String,
    header_revision: String,
    network: String,
    k: usize,
    verifier_key_sha256: String,
    proof_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Source {
    native_report_sha256: String,
    verifier_dimensions_sha256: String,
    retained_proof_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    name: String,
    proof_hex: String,
    accept: bool,
    expected_value: Option<Value>,
    expected_spans: Option<Vec<Span>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Cases {
    schema: String,
    source: Source,
    cases: Vec<Case>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct Span {
    path: String,
    kind: String,
    start: usize,
    size: usize,
    engine: Option<String>,
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
    let mut raw = Vec::new();
    File::open(path)
        .map_err(|e| e.to_string())?
        .take((cap + 1) as u64)
        .read_to_end(&mut raw)
        .map_err(|e| e.to_string())?;
    check(raw.len() <= cap, "input byte budget")?;
    Ok(raw)
}

fn unhex(value: &str) -> Result<Vec<u8>> {
    check(
        value.len() <= 2 * MAX_PROOF && value.len() % 2 == 0,
        "proof hex byte budget",
    )?;
    check(
        value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "noncanonical proof hex",
    )?;
    hex::decode(value).map_err(|e| e.to_string())
}

fn canonical(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let sorted: BTreeMap<_, _> =
                map.iter().map(|(k, v)| (k.clone(), canonical(v))).collect();
            Value::Object(sorted.into_iter().collect())
        }
        Value::Array(rows) => Value::Array(rows.iter().map(canonical).collect()),
        _ => value.clone(),
    }
}

fn curve_dimensions(d: &CurveDimensions, engine: &str, cap: usize) -> Result<()> {
    check(d.engine == engine, "descriptor curve role")?;
    check(
        d.num_cons.is_power_of_two() && d.num_vars.is_power_of_two(),
        "descriptor power-of-two dimensions",
    )?;
    check(
        d.num_cons <= cap && d.num_vars <= cap && d.num_vars >= 8 && d.num_io == 2,
        "descriptor dimension/IO budget",
    )?;
    let mc = d.num_cons.trailing_zeros() as usize;
    let mv = d.num_vars.trailing_zeros() as usize;
    let m = mc.max(mv);
    let n = d.num_cons.max(d.num_vars);
    check(
        m < 32
            && d.outer_rounds == mc
            && d.inner_rounds == mv + 1
            && d.batch_rounds == m
            && d.ipa_rounds == m
            && d.ipa_dimension == n,
        "descriptor derived rounds",
    )?;
    check(
        d.ck_v_generators >= n
            && d.ck_v_generators <= cap
            && d.ck_s_generators >= 1
            && d.ck_s_generators <= cap,
        "descriptor commitment key capacity",
    )
}

fn load_dimensions(raw: &[u8], report: &Value, expected: &ExpectedIdentity) -> Result<Dimensions> {
    // Parse original transport too: Value normalization would erase duplicate
    // object fields before the typed loader could reject them.
    let d: Dimensions = serde_json::from_slice(raw).map_err(|e| e.to_string())?;
    let value: Value = serde_json::from_slice(raw).map_err(|e| e.to_string())?;
    let digest = sha(&serde_json::to_vec(&canonical(&value)).map_err(|e| e.to_string())?);
    check(
        digest == PINNED_DIMENSIONS_SHA256,
        "verifier-owned descriptor pin mismatch",
    )?;
    let native = report
        .get("native")
        .ok_or("native report missing native object")?;
    check(
        report.get("passed") == Some(&json!(true))
            && native.get("native_nova_proofs_verified") == Some(&json!(1)),
        "native report did not verify retained proof",
    )?;
    check(
        native.get("verifier_dimensions_sha256") == Some(&json!(digest)),
        "native descriptor digest mismatch",
    )?;
    let emitted = native
        .get("verifier_dimensions")
        .ok_or("native descriptor missing")?;
    check(
        canonical(emitted) == canonical(&value),
        "native descriptor differs from pinned descriptor",
    )?;
    check(
        expected.schema == "bitvm2-nova-expected-bundle/v1"
            && expected.nova_version == "0.76.0"
            && expected.header_revision == REVISION,
        "expected backend identity",
    )?;
    check(
        d.schema == "bitvm2-nova-verifier-dimensions/v1"
            && d.nova_version == "0.76.0"
            && d.nova_crate_sha256 == CRATE_SHA
            && d.header_revision == REVISION,
        "descriptor backend identity",
    )?;
    check(
        d.network == expected.network
            && d.k == expected.k
            && d.verifier_key_sha256 == expected.verifier_key_sha256
            && native.get("verifier_key_sha256") == Some(&json!(expected.verifier_key_sha256)),
        "descriptor policy/key identity",
    )?;
    check(
        d.outer_arity == 17
            && d.max_ipa_dimension >= 8
            && d.max_ipa_dimension.is_power_of_two()
            && d.max_ipa_dimension <= MAX_DIMENSION,
        "descriptor arity/resource budget",
    )?;
    curve_dimensions(&d.primary, "pallas", d.max_ipa_dimension)?;
    curve_dimensions(&d.secondary, "vesta", d.max_ipa_dimension)?;
    Ok(d)
}

struct Cursor<'a> {
    raw: &'a [u8],
    at: usize,
    spans: Vec<Span>,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, path: &str, kind: &str, size: usize, engine: &str) -> Result<&'a [u8]> {
        let end = self.at.checked_add(size).ok_or("cursor overflow")?;
        check(end <= self.raw.len(), &format!("truncated {path}"))?;
        let start = self.at;
        self.at = end;
        self.spans.push(Span {
            path: path.to_owned(),
            kind: kind.to_owned(),
            start,
            size,
            engine: if kind == "length" {
                None
            } else {
                Some(engine.to_owned())
            },
        });
        Ok(&self.raw[start..end])
    }
    fn length(
        &mut self,
        path: &str,
        engine: &str,
        low: usize,
        high: usize,
        item_size: usize,
    ) -> Result<usize> {
        let bytes = self.take(path, "length", 8, engine)?;
        let n = u64::from_le_bytes(bytes.try_into().map_err(|_| "length bytes")?);
        check(
            n >= low as u64 && n <= high as u64,
            &format!("length bound {path}"),
        )?;
        let count = usize::try_from(n).map_err(|_| "length conversion")?;
        let needed = count
            .checked_mul(item_size)
            .ok_or("length product overflow")?;
        check(
            needed <= self.raw.len() - self.at,
            &format!("length exceeds remaining bytes {path}"),
        )?;
        Ok(count)
    }
    fn scalar(&mut self, path: &str, engine: &str) -> Result<()> {
        self.take(path, "scalar", 32, engine).map(|_| ())
    }
    fn commitment(&mut self, path: &str, engine: &str) -> Result<()> {
        self.take(&format!("{path}.comm"), "commitment", 32, engine)
            .map(|_| ())
    }
    fn scalars(&mut self, path: &str, engine: &str, count: usize) -> Result<()> {
        self.length(path, engine, count, count, 32)?;
        for i in 0..count {
            self.scalar(&format!("{path}[{i}]"), engine)?;
        }
        Ok(())
    }
    fn relaxed(&mut self, path: &str, engine: &str) -> Result<()> {
        self.commitment(&format!("{path}.comm_W"), engine)?;
        self.commitment(&format!("{path}.comm_E"), engine)?;
        self.scalars(&format!("{path}.X"), engine, 2)?;
        self.scalar(&format!("{path}.u"), engine)
    }
    fn sumcheck(&mut self, path: &str, engine: &str, rounds: usize, degree: usize) -> Result<()> {
        let rows = format!("{path}.compressed_polys");
        self.length(&rows, engine, rounds, rounds, 8 + 32)?;
        for i in 0..rounds {
            let row = format!("{rows}[{i}].coeffs_except_linear_term");
            let n = self.length(&row, engine, 1, degree, 32)?;
            for j in 0..n {
                self.scalar(&format!("{row}[{j}]"), engine)?;
            }
        }
        Ok(())
    }
    fn spartan(&mut self, path: &str, d: &CurveDimensions) -> Result<()> {
        let e = d.engine.as_str();
        self.sumcheck(&format!("{path}.sc_proof_outer"), e, d.outer_rounds, 3)?;
        for i in 0..3 {
            self.scalar(&format!("{path}.claims_outer[{i}]"), e)?;
        }
        self.scalar(&format!("{path}.eval_E"), e)?;
        self.sumcheck(&format!("{path}.sc_proof_inner"), e, d.inner_rounds, 2)?;
        self.scalar(&format!("{path}.eval_W"), e)?;
        self.sumcheck(&format!("{path}.sc_proof_batch"), e, d.batch_rounds, 2)?;
        self.scalars(&format!("{path}.evals_batch"), e, 2)?;
        for side in ["L_vec", "R_vec"] {
            let p = format!("{path}.eval_arg.{side}");
            self.length(&p, e, d.ipa_rounds, d.ipa_rounds, 32)?;
            for i in 0..d.ipa_rounds {
                self.commitment(&format!("{p}[{i}]"), e)?;
            }
        }
        self.scalar(&format!("{path}.eval_arg.a_hat"), e)
    }
}

fn preflight(raw: &[u8], d: &Dimensions) -> Result<Vec<Span>> {
    check(
        !raw.is_empty() && raw.len() <= MAX_PROOF,
        "proof byte budget",
    )?;
    let mut c = Cursor {
        raw,
        at: 0,
        spans: Vec::new(),
    };
    c.relaxed("r_U_secondary", "vesta")?;
    c.scalar("ri_secondary", "vesta")?;
    c.commitment("l_u_secondary.comm_W", "vesta")?;
    c.scalars("l_u_secondary.X", "vesta", 2)?;
    c.commitment("nifs_Uf_secondary.comm_T", "vesta")?;
    c.relaxed("l_ur_secondary", "vesta")?;
    c.commitment("nifs_Un_secondary.comm_T", "vesta")?;
    c.relaxed("r_U_primary", "pallas")?;
    c.scalar("ri_primary", "pallas")?;
    c.relaxed("l_ur_primary", "pallas")?;
    c.commitment("nifs_Un_primary.comm_T", "pallas")?;
    for (path, engine) in [
        ("wit_blind_r_Wn_primary", "pallas"),
        ("err_blind_r_Wn_primary", "pallas"),
        ("wit_blind_r_Wn_secondary", "vesta"),
        ("err_blind_r_Wn_secondary", "vesta"),
    ] {
        c.scalar(path, engine)?;
    }
    c.spartan("snark_primary", &d.primary)?;
    c.spartan("snark_secondary", &d.secondary)?;
    c.length("zn", "pallas", d.outer_arity, d.outer_arity, 32)?;
    for i in 0..d.outer_arity {
        let bytes = c.take(&format!("zn[{i}]"), "scalar", 32, "pallas")?;
        let width = match i {
            1 | 2 => 128,
            3 => 200,
            _ => 32,
        };
        check(
            bytes[width / 8..].iter().all(|byte| *byte == 0),
            "header output-state width",
        )?;
    }
    check(c.at == raw.len(), "surplus inner proof bytes")?;
    Ok(c.spans)
}

struct Failure {
    stage: &'static str,
    message: String,
}

fn admit(raw: &[u8], d: &Dimensions) -> std::result::Result<(Value, Vec<Span>), Failure> {
    let spans = preflight(raw, d).map_err(|message| Failure {
        stage: "structural_preflight",
        message,
    })?;
    let proof: Proof = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_little_endian()
        .with_limit(MAX_PROOF as u64)
        .reject_trailing_bytes()
        .deserialize(raw)
        .map_err(|e| Failure {
            stage: "upstream_serde",
            message: e.to_string(),
        })?;
    let canonical = bincode::serialize(&proof).map_err(|e| Failure {
        stage: "canonical_roundtrip",
        message: e.to_string(),
    })?;
    if canonical.len() > MAX_PROOF || canonical.as_slice() != raw {
        return Err(Failure {
            stage: "canonical_roundtrip",
            message: "noncanonical proof encoding".into(),
        });
    }
    let value = serde_json::to_value(&proof).map_err(|e| Failure {
        stage: "upstream_serde_json",
        message: e.to_string(),
    })?;
    Ok((value, spans))
}

fn run() -> Result<Value> {
    let args: Vec<_> = std::env::args().collect();
    check(args.len() == 5, "usage: admission CASES.json NATIVE_REPORT.json EXPECTED_BUNDLE.json PINNED_DIMENSIONS.json")?;
    let input: Cases =
        serde_json::from_slice(&read(&args[1], 8 << 20)?).map_err(|e| e.to_string())?;
    check(
        input.schema == "bitvm2-nova-admission-cases/v1"
            && !input.cases.is_empty()
            && input.cases.len() <= MAX_CASES,
        "case schema/count",
    )?;
    let report_raw = read(&args[2], 2 << 20)?;
    let report: Value = serde_json::from_slice(&report_raw).map_err(|e| e.to_string())?;
    let expected: ExpectedIdentity =
        serde_json::from_slice(&read(&args[3], 1 << 16)?).map_err(|e| e.to_string())?;
    let dimensions = load_dimensions(&read(&args[4], 1 << 14)?, &report, &expected)?;
    check(
        input.source.native_report_sha256 == sha(&report_raw)
            && input.source.verifier_dimensions_sha256 == PINNED_DIMENSIONS_SHA256
            && input.source.retained_proof_sha256 == expected.proof_sha256,
        "case corpus source identity",
    )?;
    let mut names = std::collections::BTreeSet::new();
    let mut accepted = 0;
    let mut upstream_calls = 0;
    let mut stages = BTreeMap::<String, usize>::new();
    let mut rows = Vec::new();
    for case in &input.cases {
        check(
            !case.name.is_empty() && case.name.len() <= 192 && names.insert(case.name.as_str()),
            "case name",
        )?;
        let result = match unhex(&case.proof_hex) {
            Ok(raw) => admit(&raw, &dimensions),
            Err(message) => Err(Failure {
                stage: "input_encoding",
                message,
            }),
        };
        check(
            result.is_ok() == case.accept,
            &format!("admission mismatch: {}", case.name),
        )?;
        match result {
            Ok((value, spans)) => {
                upstream_calls += 1;
                accepted += 1;
                check(
                    case.expected_value.as_ref() == Some(&value),
                    &format!("decoded value mismatch: {}", case.name),
                )?;
                check(
                    case.expected_spans.as_ref() == Some(&spans),
                    &format!("structural offset mismatch: {}", case.name),
                )?;
                rows.push(json!({"name":case.name,"admitted":true,"proof_verified":false}));
            }
            Err(failure) => {
                if failure.stage != "input_encoding" && failure.stage != "structural_preflight" {
                    upstream_calls += 1;
                }
                *stages.entry(failure.stage.to_owned()).or_default() += 1;
                rows.push(json!({"name":case.name,"admitted":false,"stage":failure.stage,"error":failure.message}));
            }
        }
    }
    Ok(
        json!({"passed":true,"cases":input.cases.len(),"accepted":accepted,"rejected":input.cases.len()-accepted,
              "upstream_deserializations":upstream_calls,"rejection_stages":stages,"verifier_dimensions_sha256":PINNED_DIMENSIONS_SHA256,
              "case_results":rows,"native_proofs_verified":0,"panic_is_rejection":false,"setup_calls":0,"proving_jobs":0,
              "scope":"bounded proof structure, actual upstream serde and canonical byte/decoded-value conformance only"}),
    )
}

fn main() {
    match run() {
        Ok(value) => println!("{}", serde_json::to_string_pretty(&value).unwrap()),
        Err(error) => {
            eprintln!("admission conformance failed: {error}");
            std::process::exit(1);
        }
    }
}
