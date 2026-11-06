//! Hosted-only differential oracle for unsigned 512-bit Pasta field reduction.
//!
//! Uses the released mature FromUniformBytes<64> implementation, never a local
//! reduction port. A matching expected value is arithmetic conformance evidence,
//! not proof verification, production assertion binding or an acceptance receipt.
use ff::{FromUniformBytes, PrimeField};
use halo2curves::pasta::{Fp, Fq};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    collections::HashSet,
    fs::File,
    io::{self, Read, Write},
};

type Result<T> = std::result::Result<T, String>;
const INPUT_SCHEMA: &str = "bitvm2-nova-uniform-reduce-input/v1";
const OUTPUT_SCHEMA: &str = "bitvm2-nova-uniform-reduce-oracle/v1";
const OP_ENDIAN: &str = "unsigned-little-endian-512-to-canonical-little-endian-32";
const MAX_INPUT_BYTES: usize = 64 << 10;
const MAX_OUTPUT_BYTES: usize = 64 << 10;
const MAX_CASES: usize = 64;
const P_HEX: &str = "40000000000000000000000000000000224698fc094cf91b992d30ed00000001";
const Q_HEX: &str = "40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Corpus {
    schema: String,
    cases: Vec<Case>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    name: String,
    field_role: String,
    input_le: String,
    expected_le: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Domain {
    Fp,
    Fq,
}
impl Domain {
    fn role(role: &str) -> Result<Self> {
        // Matches the existing Script roles and the actual curve-field aliases:
        // Pallas base / Vesta scalar = Fp(P); the complementary roles = Fq(Q).
        match role {
            "pallas_base" | "vesta_scalar" => Ok(Self::Fp),
            "pallas_scalar" | "vesta_base" => Ok(Self::Fq),
            _ => Err("unsupported Pasta field role".into()),
        }
    }
    fn name(self) -> &'static str {
        match self {
            Self::Fp => "Fp",
            Self::Fq => "Fq",
        }
    }
    fn modulus(self) -> &'static str {
        match self {
            Self::Fp => P_HEX,
            Self::Fq => Q_HEX,
        }
    }
    fn canonical(self, bytes: &[u8; 32]) -> bool {
        match self {
            Self::Fp => {
                let mut repr = <Fp as PrimeField>::Repr::default();
                repr.as_mut().copy_from_slice(bytes);
                bool::from(Fp::from_repr(repr).is_some())
            }
            Self::Fq => {
                let mut repr = <Fq as PrimeField>::Repr::default();
                repr.as_mut().copy_from_slice(bytes);
                bool::from(Fq::from_repr(repr).is_some())
            }
        }
    }
    fn reduce(self, bytes: &[u8; 64]) -> Result<[u8; 32]> {
        let repr = match self {
            Self::Fp => Fp::from_uniform_bytes(bytes).to_repr().as_ref().to_vec(),
            Self::Fq => Fq::from_uniform_bytes(bytes).to_repr().as_ref().to_vec(),
        };
        repr.try_into()
            .map_err(|_| "mature Pasta repr is not exactly 32 bytes".into())
    }
}
fn lower_hex(value: &str, bytes: usize) -> bool {
    value.len() == bytes * 2
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn decode<const N: usize>(value: &str) -> Result<[u8; N]> {
    if !lower_hex(value, N) {
        return Err(format!("canonical lowercase {}-byte hex required", N));
    }
    hex::decode(value)
        .map_err(|e| e.to_string())?
        .try_into()
        .map_err(|_| "hex width mismatch".into())
}
fn modulus<F: PrimeField>() -> Result<&'static str> {
    let value = F::MODULUS.strip_prefix("0x").unwrap_or(F::MODULUS);
    if !lower_hex(value, 32) || F::Repr::default().as_ref().len() != 32 {
        return Err("mature field modulus/repr encoding changed".into());
    }
    Ok(value)
}
fn verify_moduli() -> Result<()> {
    // Fail closed on an actual dependency/role reversal; output identities below
    // are emitted only after these checks against the mature field constants.
    if modulus::<Fp>()? != P_HEX || modulus::<Fq>()? != Q_HEX {
        return Err("actual mature Fp/Fq moduli differ from existing Pasta roles".into());
    }
    Ok(())
}
fn hosted_values(actions: Option<&str>, runner: Option<&str>, linux: bool) -> Result<()> {
    if actions != Some("true") || runner != Some("Linux") || !linux {
        return Err("uniform reduction oracle is hosted GitHub Linux only".into());
    }
    Ok(())
}
fn hosted_guard() -> Result<()> {
    hosted_values(
        std::env::var("GITHUB_ACTIONS").ok().as_deref(),
        std::env::var("RUNNER_OS").ok().as_deref(),
        cfg!(target_os = "linux"),
    )
}
fn read_bounded<R: Read>(reader: R) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader
        .take((MAX_INPUT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.is_empty() || bytes.len() > MAX_INPUT_BYTES {
        return Err("uniform reduction input byte budget".into());
    }
    Ok(bytes)
}
struct Admitted {
    name: String,
    field_role: String,
    domain: Domain,
    input: [u8; 64],
    expected: [u8; 32],
}
fn admit(raw: &[u8]) -> Result<Vec<Admitted>> {
    if raw.is_empty() || raw.len() > MAX_INPUT_BYTES {
        return Err("uniform reduction input byte budget".into());
    }
    verify_moduli()?;
    let corpus: Corpus = serde_json::from_slice(raw).map_err(|e| e.to_string())?;
    if corpus.schema != INPUT_SCHEMA || !(1..=MAX_CASES).contains(&corpus.cases.len()) {
        return Err("uniform reduction schema/case count mismatch".into());
    }
    let mut names = HashSet::new();
    let mut admitted = Vec::with_capacity(corpus.cases.len());
    // Validate the ENTIRE corpus before any from_uniform_bytes computation.
    for case in corpus.cases {
        if case.name.is_empty()
            || case.name.len() > 96
            || !case
                .name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.:/-".contains(&b))
            || !names.insert(case.name.clone())
        {
            return Err("invalid or duplicate uniform reduction case name".into());
        }
        let domain = Domain::role(&case.field_role)?;
        let input = decode::<64>(&case.input_le)?;
        let expected = decode::<32>(&case.expected_le)?;
        if !domain.canonical(&expected) {
            return Err("expected reduction is not a canonical declared-field scalar".into());
        }
        admitted.push(Admitted {
            name: case.name,
            field_role: case.field_role,
            domain,
            input,
            expected,
        });
    }
    Ok(admitted)
}
fn compute(cases: &[Admitted]) -> Result<Value> {
    let mut results = Vec::with_capacity(cases.len());
    let (mut fp, mut fq) = (0usize, 0usize);
    for case in cases {
        let reduced = case.domain.reduce(&case.input)?;
        if reduced != case.expected {
            return Err(format!(
                "mature reduction differs from expected result: {}",
                case.name
            ));
        }
        match case.domain {
            Domain::Fp => fp += 1,
            Domain::Fq => fq += 1,
        }
        results.push(json!({"name":case.name,"field_role":case.field_role,"field":case.domain.name(),
            "modulus_be":case.domain.modulus(),"input_le":hex::encode(case.input),
            "reduced_le":hex::encode(reduced),"expected_le":hex::encode(case.expected),"matched":true}));
    }
    Ok(
        json!({"schema":OUTPUT_SCHEMA,"passed":true,"case_count":cases.len(),"native_reductions":cases.len(),
        "halo2curves_version":"0.9.0","ff_version":"0.13","op_endian":OP_ENDIAN,
        "moduli":{"Fp":P_HEX,"Fq":Q_HEX},"fields_checked":{"Fp":fp,"Fq":fq},"results":results,
        "scope":"mature field reduction differential conformance only",
        "proof_verified":false,"bitvm2_script_verified":false,"production_assertion_binding":false,
        "complete_nova_verifier":false,"bitcoin_transaction_graph":false,"trusted_acceptance_receipt":false,
        "native_proofs_verified":0,"setup_calls":0,"proving_jobs":0,"matrix_jobs":0,"msm_jobs":0,
        "gpu_jobs":0,"transactions_broadcast":0,"panic_is_rejection":false}),
    )
}
fn encode_report(report: &Value) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec(report).map_err(|e| e.to_string())?;
    bytes.push(b'\n');
    if bytes.len() > MAX_OUTPUT_BYTES {
        return Err("uniform reduction output byte budget".into());
    }
    Ok(bytes)
}
fn run() -> Result<()> {
    hosted_guard()?; // MUST precede argv/file/stdout I/O and all reduction work.
    verify_moduli()?;
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 2 {
        return Err("usage: uniform_reduce INPUT.json".into());
    }
    let raw = read_bounded(File::open(&args[1]).map_err(|e| e.to_string())?)?;
    let cases = admit(&raw)?;
    let bytes = encode_report(&compute(&cases)?)?;
    io::stdout()
        .lock()
        .write_all(&bytes)
        .map_err(|e| e.to_string())
}
fn main() {
    // No panic catcher: unexpected upstream panics fail the process/hosted job.
    if let Err(error) = run() {
        eprintln!("uniform reduction oracle failed: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn case(role: &str, input: [u8; 64], expected: [u8; 32]) -> Value {
        json!({"name":"tiny/case","field_role":role,"input_le":hex::encode(input),"expected_le":hex::encode(expected)})
    }
    fn raw(cases: Vec<Value>) -> Vec<u8> {
        serde_json::to_vec(&json!({"schema":INPUT_SCHEMA,"cases":cases})).unwrap()
    }
    #[test]
    fn parsing_rejects_unknown_duplicate_noncanonical_and_oversized_inputs() {
        let good = case("pallas_base", [0; 64], [0; 32]);
        assert!(admit(&raw(vec![good.clone()])).is_ok());
        for field in ["input_le", "expected_le"] {
            for value in [
                "00".into(),
                "GG".repeat(if field == "input_le" { 64 } else { 32 }),
                "AA".repeat(if field == "input_le" { 64 } else { 32 }),
            ] {
                let mut bad = good.clone();
                bad[field] = json!(value);
                assert!(admit(&raw(vec![bad])).is_err());
            }
        }
        for name in ["", "bad name", "é"] {
            let mut bad = good.clone();
            bad["name"] = json!(name);
            assert!(admit(&raw(vec![bad])).is_err());
        }
        let mut unknown = good.clone();
        unknown["extra"] = json!(1);
        assert!(admit(&raw(vec![unknown])).is_err());
        let mut role = good.clone();
        role["field_role"] = json!("unknown");
        assert!(admit(&raw(vec![role])).is_err());
        let mut noncanonical = good.clone();
        noncanonical["expected_le"] = json!(hex::encode({
            let mut b = decode::<32>(P_HEX).unwrap();
            b.reverse();
            b
        }));
        assert!(admit(&raw(vec![noncanonical])).is_err());
        assert!(admit(&raw(vec![good.clone(), good.clone()])).is_err());
        assert!(admit(&raw(vec![])).is_err());
        assert!(admit(&raw(vec![good; 65])).is_err());
        assert!(admit(&vec![b' '; MAX_INPUT_BYTES + 1]).is_err());
        assert!(admit(br#"{"schema":"a","schema":"b","cases":[]}"#).is_err());
        let valid_case = serde_json::to_string(&case("pallas_base", [0; 64], [0; 32])).unwrap();
        let duplicate_name = valid_case.replacen('"', "\"name\":\"duplicate\",\"", 1);
        assert!(admit(
            format!("{{\"schema\":\"{INPUT_SCHEMA}\",\"cases\":[{duplicate_name}]}}").as_bytes()
        )
        .is_err());
        let mut trailing = raw(vec![case("pallas_base", [0; 64], [0; 32])]);
        trailing.extend(b"{}");
        assert!(admit(&trailing).is_err());
    }
    #[test]
    fn explicit_roles_match_actual_mature_field_moduli_and_canonicality() {
        verify_moduli().unwrap();
        assert_eq!(modulus::<Fp>().unwrap(), P_HEX);
        assert_eq!(modulus::<Fq>().unwrap(), Q_HEX);
        for role in ["pallas_base", "vesta_scalar"] {
            assert_eq!(Domain::role(role).unwrap(), Domain::Fp);
        }
        for role in ["pallas_scalar", "vesta_base"] {
            assert_eq!(Domain::role(role).unwrap(), Domain::Fq);
        }
        let mut p = decode::<32>(P_HEX).unwrap();
        p.reverse();
        assert!(!Domain::Fp.canonical(&p));
        assert!(Domain::Fq.canonical(&p));
        let mut wide = [0; 64];
        wide[..32].copy_from_slice(&p);
        assert_eq!(Domain::Fp.reduce(&wide).unwrap(), [0; 32]);
        assert_eq!(Domain::Fq.reduce(&wide).unwrap(), p);
    }
    #[test]
    fn wide_unsigned_little_endian_vectors_match_independent_integer_goldens() {
        // Goldens independently calculated with Python int.from_bytes(...,'little')%p.
        let mut one = [0; 64];
        one[0] = 1;
        let mut expected = [0; 32];
        expected[0] = 1;
        for domain in [Domain::Fp, Domain::Fq] {
            assert_eq!(domain.reduce(&one).unwrap(), expected);
        }
        for (position, p, q) in [
            (
                32,
                "fdffffff386d7834ad1419e40b352c99ffffffffffffffffffffffffffffff3f",
                "fdffffff9c3e2b5b670542e30b352c99ffffffffffffffffffffffffffffff3f",
            ),
            (
                63,
                "010000d0fb03c0e263844c0213491c395dc9c39ba9977714b79c7baf416d493c",
                "01000010d3590b750f0d8e824831acb0f5cc041023ae7fa9dacf7caf416d493c",
            ),
        ] {
            let mut input = [0; 64];
            input[position] = 1;
            assert_eq!(Domain::Fp.reduce(&input).unwrap(), decode::<32>(p).unwrap());
            assert_eq!(Domain::Fq.reduce(&input).unwrap(), decode::<32>(q).unwrap());
        }
        assert_eq!(
            Domain::Fp.reduce(&[0xff; 64]).unwrap(),
            decode::<32>("0e000000b3ec788ce7e00d8bbd0dd3d7185dc9c39ba9977714b79c7baf416d09")
                .unwrap()
        );
        assert_eq!(
            Domain::Fq.reduce(&[0xff; 64]).unwrap(),
            decode::<32>("0e000000ff7896fce3161a893d43bb6790f5cc041023ae7fa9dacf7caf416d09")
                .unwrap()
        );
    }
    #[test]
    fn mismatches_fail_and_maximum_corpus_report_is_bounded_and_nonproof() {
        let mut expected = [0; 32];
        expected[0] = 1;
        let cases = admit(&raw(vec![case("pallas_base", [0; 64], expected)])).unwrap();
        assert!(compute(&cases).is_err());
        let corpus = (0..64)
            .map(|i| {
                let mut value = case(
                    if i % 2 == 0 {
                        "pallas_base"
                    } else {
                        "pallas_scalar"
                    },
                    [0; 64],
                    [0; 32],
                );
                value["name"] = json!(format!("case/{i}"));
                value
            })
            .collect();
        let report = compute(&admit(&raw(corpus)).unwrap()).unwrap();
        assert_eq!(report["case_count"], 64);
        assert_eq!(report["fields_checked"]["Fp"], 32);
        assert_eq!(report["fields_checked"]["Fq"], 32);
        assert!(encode_report(&report).unwrap().len() <= MAX_OUTPUT_BYTES);
        assert_eq!(report["op_endian"], OP_ENDIAN);
        for flag in [
            "proof_verified",
            "bitvm2_script_verified",
            "production_assertion_binding",
            "trusted_acceptance_receipt",
            "panic_is_rejection",
        ] {
            assert_eq!(report[flag], false);
        }
        assert!(read_bounded(io::Cursor::new(vec![0; MAX_INPUT_BYTES + 1])).is_err());
    }
    #[test]
    fn hosted_guard_requires_all_conditions_before_io() {
        hosted_values(Some("true"), Some("Linux"), true).unwrap();
        for (actions, runner, linux) in [
            (None, Some("Linux"), true),
            (Some("false"), Some("Linux"), true),
            (Some("true"), Some("Windows"), true),
            (Some("true"), Some("Linux"), false),
        ] {
            assert!(hosted_values(actions, runner, linux).is_err());
        }
    }
}
