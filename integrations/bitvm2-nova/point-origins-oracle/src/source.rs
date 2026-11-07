//! Independent retained commitment-decoding source (M23), one curve role.
//!
//! The verifier re-derives the retained MAX-width layout, the unchanged BYTE
//! tape, every decoder's word/predicate schedule (with frozen legacy body
//! pins), the raw-u32 assignment of each closed profile, every leaf's truth,
//! the targeted selection and the aggregate source identity. Claimed values
//! never drive a parser, offset, loop bound or decoder. Mature halo2curves
//! strict decoding is compared with the leaf relation for every decoder of
//! every profile. No setup, proving, proof acceptance or production origin.
use crate::{
    reference_admission,
    transport::{Case, Group},
};
use bitcoin::{
    hashes::{sha256, Hash, HashEngine},
    script::Builder,
};
use bitvm2_nova_script_oracle::{
    registry::GraphSpec,
    wots::{id32, Result},
};
use ff::PrimeField;
use halo2curves::{
    group::GroupEncoding,
    pasta::{PallasAffine, VestaAffine},
    CurveAffine,
};
use num_bigint::BigUint;
use serde::Serialize;
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    fs,
    io::Read,
    path::Path,
};

pub const HEADER: usize = 556;
pub const PAYLOAD: usize = 12664;
pub const BUNDLE: usize = 13220;
const BASE: u32 = 1 << 29;
const BOUNDARIES: [usize; 7] = [29, 58, 87, 116, 145, 174, 203];
pub const BATCH: usize = 7;
pub const DECODER_WORDS: usize = 1696;
pub const DECODER_CONSTRAINTS: usize = 1400;
pub const DECODER_FIELDS: usize = 6;
const CONSTANT_WORDS: usize = 10;
pub const CONSTANT_CONSTRAINTS: usize = 10;
const CONSTANT_FIELDS: usize = 1;
const TAPE_CENSUS: (usize, usize, usize, usize) = (12664, 1383, 0, 12664);
pub const TARGET_CAP: usize = 2048;
pub const PROFILES: [&str; 12] = [
    "honest",
    "coherent-negate",
    "coherent-identity",
    "sign-flip",
    "wrong-root",
    "x-noncanonical",
    "off-curve",
    "identity-alias",
    "identity-finite-flag",
    "infinity-lie",
    "byte-256",
    "byte-max",
];
pub const COHERENT: [&str; 3] = ["honest", "coherent-negate", "coherent-identity"];
const DOMAIN: &[u8] = b"BITVM2-NOVA/PROOF-POINT-ORIGINS/v1\0";
const ENCODING: &str =
    "halo2curves 0.9 Pasta compressed: x LE with y-sign in bit 255; identity = 32 zero bytes";
const RELATION: &str =
    "asserted payload BYTEs -> canonical (infinity, x, y) with y^2=x^3+5 and parity(y)=sign";
const SCOPE: &str = "commitment decoding only; point semantics, transcript, MSM/IPA and proof acceptance remain open";
pub const FALSE_FLAGS: [&str; 15] = [
    "blob_sha256_script_bound",
    "proof_eof_authenticated",
    "container_header_script_bound",
    "public_state_to_zn_script_bound",
    "commitment_semantics_bound",
    "affine_transcript_encoding_bound",
    "generic_nova_decoder",
    "transcript_verified",
    "msm_or_ipa_verified",
    "proof_verified",
    "complete_nova_verifier",
    "complete_bitvm2_verifier",
    "production_assertion_binding",
    "bitcoin_transaction_graph",
    "taproot_or_forest_constructed",
];
const P_TEXT: &str =
    "28948022309329048855892746252171976963363056481941560715954676764349967630337";
const Q_TEXT: &str =
    "28948022309329048855892746252171976963363056481941647379679742748393362948097";

fn require(yes: bool, message: &str) -> Result<()> {
    if yes {
        Ok(())
    } else {
        Err(message.into())
    }
}
fn canonical(value: &Value) -> Result<Vec<u8>> {
    reference_admission::canonical(value)
}
fn sha(raw: &[u8]) -> String {
    hex::encode(sha256::Hash::hash(raw))
}
fn hash(value: &Value) -> Result<String> {
    Ok(sha(&canonical(value)?))
}
fn domain_hash(domain: &[u8], value: &Value) -> Result<String> {
    let mut h = sha256::Hash::engine();
    h.input(domain);
    h.input(&canonical(value)?);
    Ok(hex::encode(sha256::Hash::from_engine(h)))
}
fn bounded(path: &Path, cap: usize) -> Result<Vec<u8>> {
    let info = fs::symlink_metadata(path)?;
    require(
        info.file_type().is_file() && info.len() <= cap as u64,
        "regular bounded reference file required",
    )?;
    let mut raw = Vec::new();
    fs::File::open(path)?
        .take((cap + 1) as u64)
        .read_to_end(&mut raw)?;
    require(raw.len() <= cap, "reference grew beyond cap")?;
    Ok(raw)
}

// ---------------------------------------------------------------------------
// Closed role/component plan.

pub fn commitments(engine: &str) -> Result<usize> {
    match engine {
        "pallas" => Ok(43),
        "vesta" => Ok(35),
        _ => Err("explicit pallas or vesta commitment role required".into()),
    }
}
pub fn base_role(engine: &str) -> Result<&'static str> {
    match engine {
        "pallas" => Ok("pallas_base"),
        "vesta" => Ok("vesta_base"),
        _ => Err("explicit commitment engine required".into()),
    }
}
fn role_modulus_text(role: &str) -> Result<&'static str> {
    match role {
        "pallas_base" | "vesta_scalar" => Ok(P_TEXT),
        "vesta_base" | "pallas_scalar" => Ok(Q_TEXT),
        _ => Err("exact Pasta role required".into()),
    }
}
fn role_modulus(role: &str) -> Result<BigUint> {
    BigUint::parse_bytes(role_modulus_text(role)?.as_bytes(), 10)
        .ok_or_else(|| "fixed Pasta modulus".into())
}
pub fn modulus(engine: &str) -> Result<BigUint> {
    role_modulus(base_role(engine)?)
}
pub fn plan(engine: &str) -> Result<Vec<Vec<usize>>> {
    let count = commitments(engine)?;
    let rows: Vec<Vec<usize>> = (0..count)
        .step_by(BATCH)
        .map(|start| (start..(start + BATCH).min(count)).collect())
        .collect();
    require(
        rows.len() < 16
            && rows
                .iter()
                .all(|row| CONSTANT_CONSTRAINTS + DECODER_CONSTRAINTS * row.len() <= 10_000),
        "decoder plan exceeds unchanged Program/component caps",
    )?;
    Ok(rows)
}
pub fn census(engine: &str, index: usize) -> Result<(usize, usize, usize, usize)> {
    if index == 0 {
        return Ok(TAPE_CENSUS);
    }
    let n = plan(engine)?
        .get(index - 1)
        .ok_or("decoder component index")?
        .len();
    let arithmetic = CONSTANT_CONSTRAINTS + DECODER_CONSTRAINTS * n;
    let fields = CONSTANT_FIELDS + DECODER_FIELDS * n;
    Ok((
        CONSTANT_WORDS + DECODER_WORDS * n,
        arithmetic,
        fields,
        arithmetic + fields,
    ))
}
pub fn component_name(engine: &str, index: usize) -> Result<String> {
    commitments(engine)?;
    Ok(if index == 0 {
        "tape".to_string()
    } else {
        format!("{engine}-points-{}", index - 1)
    })
}
pub fn component_role(engine: &str, index: usize) -> Result<&'static str> {
    if index == 0 {
        commitments(engine)?;
        Ok("pallas_scalar")
    } else {
        base_role(engine)
    }
}
pub fn operation(op: &str, engine: &str, index: usize) -> Result<String> {
    commitments(engine)?;
    Ok(if index == 0 {
        format!("{op}/tape")
    } else {
        format!("{op}/{engine}-points/{}", index - 1)
    })
}
pub fn identity_kind(index: usize) -> &'static str {
    if index == 0 {
        "ByteProgram.digest (byte-v1)"
    } else {
        "ConvolutionProgram.digest (fixed-trace/v2)"
    }
}
pub fn decoder_leaves(engine: &str, index: usize, local: usize) -> Result<Vec<usize>> {
    let (_, arithmetic, _, _) = census(engine, index)?;
    let start = CONSTANT_CONSTRAINTS + DECODER_CONSTRAINTS * local;
    let fields = arithmetic + CONSTANT_FIELDS + DECODER_FIELDS * local;
    Ok((start..start + DECODER_CONSTRAINTS)
        .chain(fields..fields + DECODER_FIELDS)
        .collect())
}

// ---------------------------------------------------------------------------
// Retained MAX-width layout (same grammar as the completed payload oracle).

#[derive(Clone, Serialize)]
pub struct Span {
    pub path: String,
    pub kind: String,
    pub start: usize,
    pub size: usize,
    pub engine: Option<String>,
    pub width_bits: Option<usize>,
    pub minimum: Option<usize>,
    pub maximum: Option<usize>,
}
struct LayoutCursor<'a> {
    raw: &'a [u8],
    at: usize,
    spans: Vec<Span>,
}
impl LayoutCursor<'_> {
    #[allow(clippy::too_many_arguments)]
    fn take(
        &mut self,
        path: &str,
        kind: &str,
        size: usize,
        engine: Option<&str>,
        width: Option<usize>,
        minimum: Option<usize>,
        maximum: Option<usize>,
    ) -> Result<&[u8]> {
        let end = self.at.checked_add(size).ok_or("payload cursor overflow")?;
        require(
            end <= self.raw.len(),
            "truncated retained reference payload",
        )?;
        let start = self.at;
        self.at = end;
        self.spans.push(Span {
            path: path.into(),
            kind: kind.into(),
            start,
            size,
            engine: engine.map(str::to_owned),
            width_bits: width,
            minimum,
            maximum,
        });
        Ok(&self.raw[start..end])
    }
    fn length(&mut self, path: &str, value: usize, minimum: usize, maximum: usize) -> Result<()> {
        let raw = self.take(path, "length", 8, None, None, Some(minimum), Some(maximum))?;
        require(
            u64::from_le_bytes(raw.try_into()?) == value as u64,
            "reference must use the exact retained MAX-width serialization profile",
        )
    }
    fn scalar(&mut self, path: &str, engine: &str, width: Option<usize>) -> Result<()> {
        self.take(path, "scalar", 32, Some(engine), width, None, None)
            .map(|_| ())
    }
    fn point(&mut self, path: &str, engine: &str) -> Result<()> {
        self.take(
            &format!("{path}.comm"),
            "commitment",
            32,
            Some(engine),
            None,
            None,
            None,
        )
        .map(|_| ())
    }
    fn scalars(&mut self, path: &str, engine: &str, n: usize) -> Result<()> {
        self.length(path, n, n, n)?;
        for i in 0..n {
            self.scalar(&format!("{path}[{i}]"), engine, None)?;
        }
        Ok(())
    }
    fn relaxed(&mut self, path: &str, engine: &str) -> Result<()> {
        self.point(&format!("{path}.comm_W"), engine)?;
        self.point(&format!("{path}.comm_E"), engine)?;
        self.scalars(&format!("{path}.X"), engine, 2)?;
        self.scalar(&format!("{path}.u"), engine, None)
    }
    fn sumcheck(&mut self, path: &str, engine: &str, rounds: usize, degree: usize) -> Result<()> {
        let rows = format!("{path}.compressed_polys");
        self.length(&rows, rounds, rounds, rounds)?;
        for i in 0..rounds {
            let row = format!("{rows}[{i}].coeffs_except_linear_term");
            self.length(&row, degree, 1, degree)?;
            for j in 0..degree {
                self.scalar(&format!("{row}[{j}]"), engine, None)?;
            }
        }
        Ok(())
    }
    fn spartan(
        &mut self,
        path: &str,
        engine: &str,
        outer: usize,
        inner: usize,
        batch: usize,
    ) -> Result<()> {
        self.sumcheck(&format!("{path}.sc_proof_outer"), engine, outer, 3)?;
        for i in 0..3 {
            self.scalar(&format!("{path}.claims_outer[{i}]"), engine, None)?;
        }
        self.scalar(&format!("{path}.eval_E"), engine, None)?;
        self.sumcheck(&format!("{path}.sc_proof_inner"), engine, inner, 2)?;
        self.scalar(&format!("{path}.eval_W"), engine, None)?;
        self.sumcheck(&format!("{path}.sc_proof_batch"), engine, batch, 2)?;
        self.scalars(&format!("{path}.evals_batch"), engine, 2)?;
        for side in ["L_vec", "R_vec"] {
            let row = format!("{path}.eval_arg.{side}");
            self.length(&row, batch, batch, batch)?;
            for i in 0..batch {
                self.point(&format!("{row}[{i}]"), engine)?;
            }
        }
        self.scalar(&format!("{path}.eval_arg.a_hat"), engine, None)
    }
}
fn layout(raw: &[u8]) -> Result<Vec<Span>> {
    require(
        raw.len() == PAYLOAD,
        "exact12664 reference payload required",
    )?;
    let mut c = LayoutCursor {
        raw,
        at: 0,
        spans: Vec::new(),
    };
    c.relaxed("r_U_secondary", "vesta")?;
    c.scalar("ri_secondary", "vesta", None)?;
    c.point("l_u_secondary.comm_W", "vesta")?;
    c.scalars("l_u_secondary.X", "vesta", 2)?;
    c.point("nifs_Uf_secondary.comm_T", "vesta")?;
    c.relaxed("l_ur_secondary", "vesta")?;
    c.point("nifs_Un_secondary.comm_T", "vesta")?;
    c.relaxed("r_U_primary", "pallas")?;
    c.scalar("ri_primary", "pallas", None)?;
    c.relaxed("l_ur_primary", "pallas")?;
    c.point("nifs_Un_primary.comm_T", "pallas")?;
    for (path, engine) in [
        ("wit_blind_r_Wn_primary", "pallas"),
        ("err_blind_r_Wn_primary", "pallas"),
        ("wit_blind_r_Wn_secondary", "vesta"),
        ("err_blind_r_Wn_secondary", "vesta"),
    ] {
        c.scalar(path, engine, None)?;
    }
    c.spartan("snark_primary", "pallas", 19, 20, 19)?;
    c.spartan("snark_secondary", "vesta", 14, 15, 14)?;
    c.length("zn", 17, 17, 17)?;
    for i in 0..17 {
        let width = match i {
            1 | 2 => 128,
            3 => 200,
            _ => 32,
        };
        c.scalar(&format!("zn[{i}]"), "pallas", Some(width))?;
    }
    require(
        c.at == PAYLOAD && c.spans.len() == 485,
        "retained span partition/EOF",
    )?;
    for (engine, count) in [("pallas", 43), ("vesta", 35)] {
        require(
            c.spans
                .iter()
                .filter(|s| s.kind == "commitment" && s.engine.as_deref() == Some(engine))
                .count()
                == count,
            "retained commitment census",
        )?;
    }
    Ok(c.spans)
}

pub struct Reference {
    payload: Vec<u8>,
    layout: Vec<Span>,
    summary: Value,
}
impl Reference {
    pub fn summary(&self) -> Value {
        self.summary.clone()
    }
    fn commitment_spans(&self, engine: &str) -> Result<Vec<&Span>> {
        let spans: Vec<_> = self
            .layout
            .iter()
            .filter(|s| s.kind == "commitment" && s.engine.as_deref() == Some(engine))
            .collect();
        require(
            spans.len() == commitments(engine)? && spans.iter().all(|s| s.size == 32),
            "retained commitment spans",
        )?;
        Ok(spans)
    }
}
pub fn reference(
    bundle_path: &Path,
    expected_path: &Path,
    dimensions_path: &Path,
) -> Result<Reference> {
    let expected: Value = serde_json::from_slice(&bounded(expected_path, 8192)?)?;
    let dimensions: Value = serde_json::from_slice(&bounded(dimensions_path, 16384)?)?;
    require(
        hash(&expected)? == reference_admission::POLICY_SHA256
            && hash(&dimensions)? == reference_admission::DIMENSIONS_SHA256,
        "independently compiled reference policy/dimension pins",
    )?;
    // The completed strict admission checks every canonical scalar/point,
    // header field and EOF of the fixed reference. It sees no claims.
    let admitted = reference_admission::reference(bundle_path, "pallas_scalar")?;
    let raw = bounded(bundle_path, BUNDLE)?;
    require(
        raw.len() == BUNDLE
            && sha(&raw) == reference_admission::BUNDLE_SHA256
            && sha(&raw[HEADER..]) == reference_admission::PROOF_SHA256
            && admitted.expected_policy_sha256 == reference_admission::POLICY_SHA256
            && admitted.dimensions_sha256 == reference_admission::DIMENSIONS_SHA256,
        "owned immutable reference snapshot must match the old strict reference",
    )?;
    let payload = raw[HEADER..].to_vec();
    let spans = layout(&payload)?;
    let summary = json!({"schema":"bitvm2-nova-proof-point-reference/v1","reference_admitted":true,
        "network":"testnet4","k":5,"steps":404,"header_revision":"de607d3db17d400dd6c2923d357f1d4a7bf233c7",
        "nova_version":"0.76.0","expected_policy_sha256":reference_admission::POLICY_SHA256,
        "verifier_dimensions_sha256":reference_admission::DIMENSIONS_SHA256,
        "verifier_key_sha256":reference_admission::VK_SHA256,"bundle_sha256":reference_admission::BUNDLE_SHA256,
        "proof_sha256":reference_admission::PROOF_SHA256,"bundle_bytes":BUNDLE,"header_bytes":HEADER,
        "payload_bytes":PAYLOAD,"spans":485,"pallas_commitments":43,"vesta_commitments":35,
        "reference_hash_authenticates_claimed_payload":false,"proof_verified":false});
    Ok(Reference {
        payload,
        layout: spans,
        summary,
    })
}

// ---------------------------------------------------------------------------
// Unchanged BYTE tape (same recipe as the completed M17 tape).

struct Anchor {
    payload_offset: usize,
    expected: u8,
}
fn anchors(reference: &Reference) -> Result<Vec<Anchor>> {
    let mut result = BTreeMap::new();
    for span in &reference.layout {
        if span.kind == "length" {
            let count = span.maximum.ok_or("length MAX metadata")?;
            for i in 0..8 {
                require(
                    result
                        .insert(span.start + i, (count as u64).to_le_bytes()[i])
                        .is_none(),
                    "overlapping tape anchors",
                )?;
            }
        }
        if let Some(bits) = span.width_bits {
            for i in bits / 8..32 {
                require(
                    result.insert(span.start + i, 0).is_none(),
                    "overlapping state-width anchors",
                )?;
            }
        }
    }
    require(
        result.len() == 1383,
        "952 prefix+431 state-width anchors required",
    )?;
    Ok(result
        .into_iter()
        .map(|(payload_offset, expected)| Anchor {
            payload_offset,
            expected,
        })
        .collect())
}
fn tape_order(reference: &Reference) -> Result<Vec<usize>> {
    let fixed = anchors(reference)?;
    let set: HashSet<_> = fixed.iter().map(|a| a.payload_offset).collect();
    Ok(fixed
        .iter()
        .map(|a| a.payload_offset)
        .chain((0..PAYLOAD).filter(|i| !set.contains(i)))
        .collect())
}
fn tape_ordinals(reference: &Reference) -> Result<Vec<usize>> {
    let mut out = vec![0; PAYLOAD];
    for (ordinal, offset) in tape_order(reference)?.into_iter().enumerate() {
        out[offset] = ordinal;
    }
    Ok(out)
}
fn const_body(value: u8) -> Vec<u8> {
    let mut code = Builder::new()
        .push_int(i64::from(value))
        .into_script()
        .into_bytes();
    code.extend([
        0x51, 0x79, 0x51, 0x79, 0x87, 0x00, 0x79, 0x6b, 0x75, 0x75, 0x75, 0x6c,
    ]);
    code
}
fn check_tape(spec: &GraphSpec, reference: &Reference) -> Result<()> {
    require(
        spec.words.len() == PAYLOAD && spec.leaves.len() == PAYLOAD,
        "Tape12664 words/leaves required",
    )?;
    for (i, w) in spec.words.iter().enumerate() {
        require(
            w.name == format!("payload/byte/{i}") && w.bound == 256,
            "Tape ordered BYTE declaration differs",
        )?;
    }
    let anchor = anchors(reference)?;
    let order = tape_order(reference)?;
    let mut bodies = BTreeMap::new();
    for (ordinal, offset) in order.iter().enumerate() {
        let leaf = &spec.leaves[ordinal];
        let (kind, args, body) = if ordinal < 1383 {
            (
                "const",
                vec![i64::from(anchor[ordinal].expected)],
                const_body(anchor[ordinal].expected),
            )
        } else {
            ("word_valid", Vec::new(), vec![0x75, 0x51])
        };
        let digest = sha(&body);
        require(
            leaf.kind == kind
                && leaf.argument == args
                && leaf.wires == [*offset]
                && leaf.body_sha256 == digest,
            "Tape exact constant/validity occurrence or body differs",
        )?;
        bodies.insert(digest, hex::encode(body));
    }
    require(
        bodies.len() == 9 && spec.bodies == bodies,
        "Tape eight constants plus word-valid exact body catalogue",
    )?;
    spec.identity().map(|_| ())
}
fn plain_digest(
    spec: &GraphSpec,
    arithmetic: usize,
    fields: &[(String, Vec<usize>)],
) -> Result<String> {
    let field_rows = fields
        .iter()
        .map(|(name, words)| {
            json!([
                name,
                words
                    .iter()
                    .map(|i| spec.words[*i].name.clone())
                    .collect::<Vec<_>>()
            ])
        })
        .collect::<Vec<_>>();
    let constraints: Vec<_> = spec.leaves[..arithmetic]
        .iter()
        .map(|l| {
            json!([
                l.kind,
                l.wires
                    .iter()
                    .map(|i| spec.words[*i].name.clone())
                    .collect::<Vec<_>>(),
                l.argument
            ])
        })
        .collect();
    hash(
        &json!({"schema":"bitvm2-nova-fixed-trace/v2","field_role":spec.field_role,
        "modulus":role_modulus_text(&spec.field_role)?,"operation_id":spec.operation_id,"context":spec.context,
        "words":spec.words.iter().map(|w|json!([w.name,w.bound])).collect::<Vec<_>>(),
        "fields":field_rows,"constraints":constraints}),
    )
}
fn tape_program_digest(spec: &GraphSpec) -> Result<String> {
    let plain = plain_digest(spec, 1383, &[])?;
    let mut h = sha256::Hash::engine();
    h.input(b"BITVM2-NOVA/BYTE-TRACE/v1\0");
    h.input(&hex::decode(plain)?);
    Ok(hex::encode(sha256::Hash::from_engine(h)))
}

// ---------------------------------------------------------------------------
// Independent decoder topology cursor (frozen legacy predicates and pins).

fn concat(parts: &[&[usize]]) -> Vec<usize> {
    parts.iter().flat_map(|part| part.iter().copied()).collect()
}
fn aliases(wires: &[usize]) -> Vec<usize> {
    let mut first = BTreeMap::new();
    wires
        .iter()
        .map(|wire| {
            let next = first.len();
            *first.entry(*wire).or_insert(next)
        })
        .collect()
}
struct Cursor<'a> {
    spec: &'a GraphSpec,
    word: usize,
    leaf: usize,
    fields: Vec<(String, Vec<usize>)>,
    byte_fields: BTreeMap<Vec<usize>, Vec<usize>>,
    bodies: BTreeMap<(String, Vec<i64>, Vec<usize>), String>,
    modulus_bytes: Vec<u8>,
}
impl Cursor<'_> {
    fn word(&mut self, name: String, bound: u32) -> Result<usize> {
        let index = self.word;
        let actual = self
            .spec
            .words
            .get(index)
            .ok_or("decoder words truncated")?;
        if actual.name != name || actual.bound != bound {
            return Err(format!("decoder declaration {index} differs: {name}/{bound}").into());
        }
        self.word += 1;
        Ok(index)
    }
    fn gate(&mut self, kind: &str, wires: &[usize], argument: &[i64]) -> Result<usize> {
        let ordinal = self.leaf;
        let actual = self
            .spec
            .leaves
            .get(ordinal)
            .ok_or("decoder predicates truncated")?;
        if actual.kind != kind || actual.wires != wires || actual.argument != argument {
            return Err(format!("decoder predicate {ordinal} differs: {kind}").into());
        }
        // Frozen legacy compiler outputs, compiled into this verifier. Neither
        // the case file nor its first observed body chooses allowed bytes.
        crate::legacy_body_pins::check(
            &self.spec.field_role,
            kind,
            argument,
            wires,
            &actual.body_sha256,
        )?;
        let shape = (kind.to_string(), argument.to_vec(), aliases(wires));
        if let Some(body) = self.bodies.get(&shape) {
            require(
                *body == actual.body_sha256,
                "same closed predicate shape changed body",
            )?;
        } else {
            self.bodies.insert(shape, actual.body_sha256.clone());
        }
        self.leaf += 1;
        Ok(ordinal)
    }
    fn field(&mut self, name: &str) -> Result<Vec<usize>> {
        require(
            !self.fields.iter().any(|(old, _)| old == name),
            "duplicate cursor field",
        )?;
        let result = (0..9)
            .map(|i| self.word(format!("{name}/l{i}"), BASE))
            .collect::<Result<Vec<_>>>()?;
        self.fields.push((name.to_string(), result.clone()));
        Ok(result)
    }
    fn constant(&mut self, name: &str, value: u32) -> Result<Vec<usize>> {
        let result = self.field(name)?;
        for (index, word) in result.iter().enumerate() {
            self.gate(
                "const",
                &[*word],
                &[if index == 0 { i64::from(value) } else { 0 }],
            )?;
        }
        Ok(result)
    }
    fn small_constant(&mut self, name: &str, value: u32, bound: u32) -> Result<usize> {
        let word = self.word(name.to_string(), bound)?;
        self.gate("const", &[word], &[i64::from(value)])?;
        Ok(word)
    }
    fn add(&mut self, name: &str, x: &[usize], y: &[usize]) -> Result<Vec<usize>> {
        let result = self.field(name)?;
        self.gate("add", &concat(&[x, y, &result]), &[])?;
        Ok(result)
    }
    fn bytes_from(&mut self, name: &str, field: &[usize], digits: &[usize]) -> Result<()> {
        require(
            field.len() == 9
                && digits.len() == 32
                && self.fields.iter().any(|(_, words)| words == field)
                && !self.byte_fields.contains_key(field),
            "cursor BYTE adapter requires a fresh declared exact field",
        )?;
        let mut crossings = BTreeMap::new();
        for boundary in BOUNDARIES {
            let (index, low) = (boundary / 8, boundary % 8);
            let lo = self.word(format!("{name}/split/{index}/lo"), 1u32 << low)?;
            let hi = self.word(format!("{name}/split/{index}/hi"), 1u32 << (8 - low))?;
            self.gate(
                "conv_split",
                &[digits[index], lo, hi],
                &[i64::try_from(low)?],
            )?;
            crossings.insert(index, (lo, hi));
        }
        for (limb, original) in field.iter().enumerate() {
            let (start, end) = (limb * 29, (limb * 29 + 29).min(256));
            let mut pieces = vec![*original];
            let mut widths = Vec::new();
            for index in start / 8..end.div_ceil(8) {
                let (low, high) = (start.max(index * 8), end.min(index * 8 + 8));
                let part = if low == index * 8 && high == index * 8 + 8 {
                    digits[index]
                } else {
                    let (lo, hi) = crossings
                        .get(&index)
                        .ok_or("cursor crossing split missing")?;
                    if low == index * 8 {
                        *lo
                    } else {
                        *hi
                    }
                };
                pieces.push(part);
                widths.push(i64::try_from(high - low)?);
            }
            self.gate("conv_reconstruct", &pieces, &widths)?;
        }
        self.byte_fields.insert(field.to_vec(), digits.to_vec());
        Ok(())
    }
    fn bytes(&mut self, name: &str, field: &[usize]) -> Result<Vec<usize>> {
        if let Some(result) = self.byte_fields.get(field) {
            return Ok(result.clone());
        }
        let digits = (0..32)
            .map(|i| self.word(format!("{name}/byte/{i}"), 256))
            .collect::<Result<Vec<_>>>()?;
        self.bytes_from(name, field, &digits)?;
        Ok(digits)
    }
    fn mul(&mut self, name: &str, x: &[usize], y: &[usize]) -> Result<Vec<usize>> {
        let result = self.field(name)?;
        let a = self.bytes(&format!("{name}/a"), x)?;
        let b = self.bytes(&format!("{name}/b"), y)?;
        let c = self.bytes(&format!("{name}/c"), &result)?;
        let q = (0..32)
            .map(|i| self.word(format!("{name}/q/{i}"), 256))
            .collect::<Result<Vec<_>>>()?;
        let mut carry = self.small_constant(&format!("{name}/carry/0"), 8192, 16384)?;
        for column in 0..64usize {
            let products: Vec<_> = (0..32)
                .filter_map(|i| column.checked_sub(i).filter(|j| *j < 32).map(|j| (i, j)))
                .collect();
            let mut ab = Vec::new();
            for (block, pairs) in products.chunks(4).enumerate() {
                let out = self.word(format!("{name}/ab/{column}/{block}"), 1 << 18)?;
                let mut wires = Vec::new();
                for (i, j) in pairs {
                    wires.extend([a[*i], b[*j]]);
                }
                wires.push(out);
                self.gate("conv_ab", &wires, &[i64::try_from(pairs.len())?])?;
                ab.push(out);
            }
            let products: Vec<_> = self
                .modulus_bytes
                .iter()
                .enumerate()
                .filter_map(|(i, coefficient)| {
                    if *coefficient == 0 {
                        None
                    } else {
                        column
                            .checked_sub(i)
                            .filter(|j| *j < 32)
                            .map(|j| (*coefficient, j))
                    }
                })
                .collect();
            let mut pq = Vec::new();
            for (block, pairs) in products.chunks(8).enumerate() {
                let out = self.word(format!("{name}/pq/{column}/{block}"), 1 << 19)?;
                let mut wires = pairs.iter().map(|(_, j)| q[*j]).collect::<Vec<_>>();
                wires.push(out);
                let coefficients = pairs
                    .iter()
                    .map(|(coefficient, _)| i64::from(*coefficient))
                    .collect::<Vec<_>>();
                self.gate("conv_pq", &wires, &coefficients)?;
                pq.push(out);
            }
            let outgoing = self.word(format!("{name}/carry/{}", column + 1), 16384)?;
            let mut wires = concat(&[&ab, &pq, &[carry, outgoing]]);
            if column < 32 {
                wires.push(c[column]);
            }
            self.gate(
                "conv_column",
                &wires,
                &[
                    i64::try_from(ab.len())?,
                    i64::try_from(pq.len())?,
                    if column < 32 { 1 } else { 0 },
                ],
            )?;
            carry = outgoing;
        }
        self.gate("const", &[carry], &[8192])?;
        Ok(result)
    }
    fn decoder(&mut self, d: usize, five: &[usize], zero_hi: usize) -> Result<Vec<usize>> {
        let name = format!("point/{d}");
        let infinity = self.word(format!("{name}/infinity"), 2)?;
        let x = self.field(&format!("{name}/x"))?;
        let y = self.field(&format!("{name}/y"))?;
        let encoding = (0..32)
            .map(|i| self.word(format!("{name}/encoding/byte/{i}"), 256))
            .collect::<Result<Vec<_>>>()?;
        let lo = self.word(format!("{name}/encoding/sign-split/lo"), 128)?;
        let sign = self.word(format!("{name}/encoding/sign"), 2)?;
        let x31 = self.word(format!("{name}/x/byte/31"), 256)?;
        self.gate("conv_split", &[encoding[31], lo, sign], &[7])?;
        self.gate("conv_split", &[x31, lo, zero_hi], &[7])?;
        let mut digits = encoding[..31].to_vec();
        digits.push(x31);
        self.bytes_from(&format!("{name}/x"), &x, &digits)?;
        self.gate("point_form", &concat(&[&[infinity], &x, &y]), &[])?;
        let y_digits = self.bytes(&format!("{name}/y"), &y)?;
        let y_high = self.word(format!("{name}/y/parity-split/hi"), 128)?;
        self.gate("conv_split", &[y_digits[0], sign, y_high], &[1])?;
        let xx = self.mul(&format!("{name}/x2"), &x, &x)?;
        let xxx = self.mul(&format!("{name}/x3"), &xx, &x)?;
        let yy = self.mul(&format!("{name}/y2"), &y, &y)?;
        let rhs = self.add(&format!("{name}/curve-rhs"), &xxx, five)?;
        self.gate("gate_equal", &concat(&[&[infinity], &yy, &rhs]), &[0])?;
        Ok(encoding)
    }
}

/// Exact decoder component topology; returns canonical fields and the actual
/// encoding BYTE words of each decoder, in decoder order.
fn check_points(
    spec: &GraphSpec,
    engine: &str,
    index: usize,
) -> Result<(Vec<(String, Vec<usize>)>, Vec<Vec<usize>>)> {
    let (words, arithmetic, fields, leaves) = census(engine, index)?;
    require(
        spec.field_role == base_role(engine)?
            && spec.words.len() == words
            && spec.leaves.len() == leaves,
        "decoder component role/census",
    )?;
    let modulus_bytes = modulus(engine)?.to_bytes_le();
    require(modulus_bytes.len() == 32, "Pasta base modulus width")?;
    let mut cursor = Cursor {
        spec,
        word: 0,
        leaf: 0,
        fields: Vec::new(),
        byte_fields: BTreeMap::new(),
        bodies: BTreeMap::new(),
        modulus_bytes,
    };
    let five = cursor.constant("constant/five", 5)?;
    let zero_hi = cursor.small_constant("constant/zero-hi", 0, 2)?;
    let mut encodings = Vec::new();
    for d in &plan(engine)?[index - 1] {
        encodings.push(cursor.decoder(*d, &five, zero_hi)?);
    }
    require(
        cursor.leaf == arithmetic && cursor.fields.len() == fields,
        "decoder arithmetic/field census",
    )?;
    for (_, field) in cursor.fields.clone() {
        cursor.gate("field_valid", &field, &[])?;
    }
    require(
        (cursor.word, cursor.leaf) == (words, leaves),
        "decoder final census; no unused validity leaves",
    )?;
    let used: BTreeSet<_> = spec.leaves.iter().map(|l| l.body_sha256.clone()).collect();
    require(
        used.len() == spec.bodies.len() && spec.bodies.keys().all(|h| used.contains(h)),
        "decoder catalogue has exactly the used pinned bodies",
    )?;
    spec.identity()?;
    Ok((cursor.fields, encodings))
}

fn global_ids(
    engine: &str,
    index: usize,
    spec: &GraphSpec,
    reference: &Reference,
) -> Result<Vec<String>> {
    if index == 0 {
        return Ok((0..PAYLOAD)
            .map(|i| format!("proof/container-byte/{}", HEADER + i))
            .collect());
    }
    let spans = reference.commitment_spans(engine)?;
    spec.words
        .iter()
        .map(|word| {
            let parts: Vec<&str> = word.name.split('/').collect();
            if parts.len() == 5
                && parts[0] == "point"
                && parts[2] == "encoding"
                && parts[3] == "byte"
            {
                let d: usize = parts[1].parse()?;
                let i: usize = parts[4].parse()?;
                let span = spans.get(d).ok_or("decoder span")?;
                require(i < 32, "encoding byte index")?;
                Ok(format!("proof/container-byte/{}", HEADER + span.start + i))
            } else if parts[0] == "point" {
                Ok(format!(
                    "proof/point/{engine}/{}",
                    &word.name["point/".len()..]
                ))
            } else {
                Ok(format!(
                    "proof/point/{engine}/component/{index}/{}",
                    word.name
                ))
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Raw-u32 value model (mirrors the frozen builder; no host field admission).

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Claim {
    pub infinity: u32,
    pub x: BigUint,
    pub y: BigUint,
}
fn limbs(value: &BigUint) -> Vec<u32> {
    let mask = BigUint::from(BASE - 1);
    (0..9)
        .map(|i| {
            let limb: BigUint = (value >> (29 * i)) & &mask;
            limb.to_u32_digits().first().copied().unwrap_or(0)
        })
        .collect()
}
fn bytes32(value: &BigUint) -> Result<Vec<u32>> {
    require(value.bits() <= 256, "unsigned 256-bit integer required")?;
    let mut raw = value.to_bytes_le();
    raw.resize(32, 0);
    Ok(raw.into_iter().map(u32::from).collect())
}
fn digits_integer(digits: &[u32]) -> BigUint {
    BigUint::from_bytes_le(&digits.iter().map(|d| *d as u8).collect::<Vec<_>>())
}
fn crossings(digits: &[u32]) -> Vec<u32> {
    let mut out = Vec::new();
    for boundary in BOUNDARIES {
        let (index, low) = (boundary / 8, boundary % 8);
        out.extend([digits[index] & ((1 << low) - 1), digits[index] >> low]);
    }
    out
}
fn mul_values(a: &[u32], b: &[u32], p: &BigUint) -> Result<(BigUint, Vec<u32>, Vec<u32>)> {
    require(
        a.len() == 32 && b.len() == 32 && a.iter().chain(b).all(|d| *d < 256),
        "BYTE digit operands",
    )?;
    let product = digits_integer(a) * digits_integer(b);
    let c = &product % p;
    let q = &product / p;
    let c_digits = bytes32(&c)?;
    let q_digits = bytes32(&q)?;
    let modulus = p.to_bytes_le();
    let mut words = limbs(&c);
    words.extend(&c_digits);
    words.extend(crossings(&c_digits));
    words.extend(&q_digits);
    words.push(8192);
    let mut signed: i64 = 0;
    for column in 0..64usize {
        let pairs: Vec<(usize, usize)> = (0..32)
            .filter_map(|i| column.checked_sub(i).filter(|j| *j < 32).map(|j| (i, j)))
            .collect();
        let ab: Vec<i64> = pairs
            .chunks(4)
            .map(|block| {
                block
                    .iter()
                    .map(|(i, j)| i64::from(a[*i]) * i64::from(b[*j]))
                    .sum()
            })
            .collect();
        let coefficients: Vec<(i64, usize)> = modulus
            .iter()
            .enumerate()
            .filter_map(|(i, k)| {
                if *k == 0 {
                    None
                } else {
                    column
                        .checked_sub(i)
                        .filter(|j| *j < 32)
                        .map(|j| (i64::from(*k), j))
                }
            })
            .collect();
        let pq: Vec<i64> = coefficients
            .chunks(8)
            .map(|block| block.iter().map(|(k, j)| k * i64::from(q_digits[*j])).sum())
            .collect();
        let output = if column < 32 {
            i64::from(c_digits[column])
        } else {
            0
        };
        signed =
            (ab.iter().sum::<i64>() + signed - output - pq.iter().sum::<i64>()).div_euclid(256);
        for value in ab.iter().chain(&pq) {
            words.push(u32::try_from(*value)?);
        }
        words.push(u32::try_from(signed + 8192)?);
    }
    require(signed == 0, "convolution carry chain must close")?;
    Ok((c, c_digits, words))
}
fn decoder_values(
    claimed: &[u32],
    claim: &Claim,
    p: &BigUint,
    reference: &[u8],
) -> Result<Vec<u32>> {
    require(
        claimed.len() == 32
            && reference.len() == 32
            && claim.infinity <= 1
            && claim.x.bits() <= 255
            && claim.y.bits() <= 255,
        "closed decoder claim required",
    )?;
    let use_claimed = claimed.iter().all(|v| *v < 256);
    let derived: Vec<u32> = if use_claimed {
        claimed.to_vec()
    } else {
        reference.iter().map(|b| u32::from(*b)).collect()
    };
    let (lo, sign) = (derived[31] & 127, derived[31] >> 7);
    let mut x_digits = derived[..31].to_vec();
    x_digits.push(lo);
    if use_claimed {
        require(
            digits_integer(&x_digits) == claim.x,
            "decoder recipes keep x limbs coherent with the asserted bytes",
        )?;
    }
    let y_digits = bytes32(&claim.y)?;
    let mut words = vec![claim.infinity];
    words.extend(limbs(&claim.x));
    words.extend(limbs(&claim.y));
    words.extend(claimed);
    words.extend([lo, sign, lo]);
    words.extend(crossings(&x_digits));
    words.extend(&y_digits);
    words.extend(crossings(&y_digits));
    words.push(y_digits[0] >> 1);
    let (_, x2_digits, part) = mul_values(&x_digits, &x_digits, p)?;
    words.extend(part);
    let (x3, _, part) = mul_values(&x2_digits, &x_digits, p)?;
    words.extend(part);
    let (_, _, part) = mul_values(&y_digits, &y_digits, p)?;
    words.extend(part);
    words.extend(limbs(&((x3 + BigUint::from(5u32)) % p)));
    require(words.len() == DECODER_WORDS, "decoder value census")?;
    Ok(words)
}
fn component_values(
    engine: &str,
    index: usize,
    reference: &Reference,
    payload: &[u32],
    claims: &[Claim],
) -> Result<Vec<u32>> {
    if index == 0 {
        return Ok(payload.to_vec());
    }
    let spans = reference.commitment_spans(engine)?;
    let p = modulus(engine)?;
    let mut words = vec![5, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    for d in &plan(engine)?[index - 1] {
        let span = spans[*d];
        words.extend(decoder_values(
            &payload[span.start..span.start + 32],
            &claims[*d],
            &p,
            &reference.payload[span.start..span.start + 32],
        )?);
    }
    Ok(words)
}

// ---------------------------------------------------------------------------
// Mature strict decoding and closed recipes.

fn halo2<A>(raw: &[u8]) -> Result<Option<Claim>>
where
    A: CurveAffine + GroupEncoding,
{
    let mut repr = <A as GroupEncoding>::Repr::default();
    require(
        raw.len() == 32 && repr.as_ref().len() == 32,
        "fixed point encoding width",
    )?;
    repr.as_mut().copy_from_slice(raw);
    let point = match Option::<A>::from(<A as GroupEncoding>::from_bytes(&repr)) {
        Some(point) => point,
        None => return Ok(None),
    };
    // Upstream from_bytes accepts x=0/sign=1 as the identity; the strict
    // round trip rejects that alias, matching the repository codec.
    if <A as GroupEncoding>::to_bytes(&point).as_ref() != raw {
        return Ok(None);
    }
    if bool::from(point.is_identity()) {
        return Ok(Some(Claim {
            infinity: 1,
            x: BigUint::from(0u32),
            y: BigUint::from(0u32),
        }));
    }
    let coordinates = point.coordinates();
    require(
        bool::from(coordinates.is_some()),
        "finite point coordinates",
    )?;
    let coordinates = coordinates.unwrap();
    Ok(Some(Claim {
        infinity: 0,
        x: BigUint::from_bytes_le(coordinates.x().to_repr().as_ref()),
        y: BigUint::from_bytes_le(coordinates.y().to_repr().as_ref()),
    }))
}
pub fn strict_decode(raw: &[u8], engine: &str) -> Result<Option<Claim>> {
    match engine {
        "pallas" => halo2::<PallasAffine>(raw),
        "vesta" => halo2::<VestaAffine>(raw),
        _ => Err("strict decoder engine".into()),
    }
}
fn nonresidue(value: &BigUint, p: &BigUint) -> bool {
    let exponent = (p - BigUint::from(1u32)) >> 1;
    (value % p).modpow(&exponent, p) == p - BigUint::from(1u32)
}
fn encode(x: &BigUint, sign: u32) -> Result<Vec<u32>> {
    require(x.bits() <= 255 && sign <= 1, "255-bit x and Boolean sign")?;
    bytes32(&(x | (BigUint::from(sign) << 255)))
}

pub struct Recipe {
    pub payload: Vec<u32>,
    pub claims: Vec<Claim>,
    pub changed: Vec<usize>,
    pub target: Option<usize>,
}
fn profile_claims(reference: &Reference, engine: &str, profile: &str) -> Result<Recipe> {
    require(PROFILES.contains(&profile), "closed profile")?;
    let spans = reference.commitment_spans(engine)?;
    let p = modulus(engine)?;
    let mut payload: Vec<u32> = reference.payload.iter().map(|b| u32::from(*b)).collect();
    let mut claims = Vec::new();
    for span in &spans {
        claims.push(
            strict_decode(&reference.payload[span.start..span.start + 32], engine)?
                .ok_or("retained reference commitment is not canonical")?,
        );
    }
    if profile == "honest" {
        return Ok(Recipe {
            payload,
            claims,
            changed: Vec::new(),
            target: None,
        });
    }
    let limit = BigUint::from(1u32) << 255;
    let target = if profile == "x-noncanonical" {
        claims
            .iter()
            .position(|c| c.infinity == 0 && &c.x + &p < limit)
            .ok_or("no retained commitment admits a 255-bit noncanonical x")?
    } else {
        0
    };
    let span = spans[target];
    let honest = claims[target].clone();
    require(honest.infinity == 0, "finite reference target")?;
    let sign = u32::from(honest.y.bit(0));
    let negated_y = &p - &honest.y;
    let zero = || BigUint::from(0u32);
    let mut raw: Vec<u32> = payload[span.start..span.start + 32].to_vec();
    let mut claim = honest.clone();
    match profile {
        "coherent-negate" => {
            raw = encode(&honest.x, 1 - sign)?;
            claim.y = negated_y;
        }
        "coherent-identity" => {
            raw = vec![0; 32];
            claim = Claim {
                infinity: 1,
                x: zero(),
                y: zero(),
            };
        }
        "sign-flip" => raw = encode(&honest.x, 1 - sign)?,
        "wrong-root" => claim.y = negated_y,
        "x-noncanonical" => {
            let shifted = &honest.x + &p;
            raw = encode(&shifted, sign)?;
            claim.x = shifted;
        }
        "off-curve" => {
            let mut shifted = &honest.x + BigUint::from(1u32);
            while shifted < p
                && !nonresidue(&(&shifted * &shifted * &shifted + BigUint::from(5u32)), &p)
            {
                shifted += BigUint::from(1u32);
            }
            require(shifted < p, "unsupported off-curve recipe boundary")?;
            raw = encode(&shifted, sign)?;
            claim.x = shifted;
        }
        "identity-alias" => {
            raw = vec![0; 32];
            raw[31] = 0x80;
            claim = Claim {
                infinity: 1,
                x: zero(),
                y: zero(),
            };
        }
        "identity-finite-flag" => {
            raw = vec![0; 32];
            claim = Claim {
                infinity: 0,
                x: zero(),
                y: zero(),
            };
        }
        "infinity-lie" => claim.infinity = 1,
        "byte-256" => raw[0] = 256,
        "byte-max" => raw[0] = u32::MAX,
        _ => return Err("closed targeted recipe".into()),
    }
    payload[span.start..span.start + 32].copy_from_slice(&raw);
    claims[target] = claim;
    let changed: Vec<usize> = (span.start..span.start + 32)
        .filter(|i| payload[*i] != u32::from(reference.payload[*i]))
        .collect();
    require(
        matches!(profile, "wrong-root" | "infinity-lie") || !changed.is_empty(),
        "targeted byte recipe changed no payload position",
    )?;
    Ok(Recipe {
        payload,
        claims,
        changed,
        target: Some(target),
    })
}

// ---------------------------------------------------------------------------
// Leaf truth (Some(false) = authenticated range/predicate failure, None = abort).

fn integer(limbs: &[u32]) -> BigUint {
    limbs
        .iter()
        .enumerate()
        .fold(BigUint::from(0u32), |value, (index, limb)| {
            value + (BigUint::from(*limb) << (29 * index))
        })
}
fn predicate(kind: &str, argument: &[i64], v: &[u32], p: &BigUint) -> Result<Option<bool>> {
    let active = || argument.contains(&i64::from(v[0]));
    let result = match kind {
        "word_valid" => true,
        "const" => u64::from(v[0]) == u64::try_from(argument[0])?,
        "add" => {
            let x = integer(&v[..9]);
            let y = integer(&v[9..18]);
            let z = integer(&v[18..27]);
            if &x >= p || &y >= p {
                return Ok(None);
            }
            (x + y) % p == z
        }
        "point_form" => v[0] == 0 || v[1..].iter().all(|word| *word == 0),
        "gate_equal" => !active() || v[1..10] == v[10..19],
        "conv_split" => {
            u64::from(v[0]) == u64::from(v[1]) + (u64::from(v[2]) << u32::try_from(argument[0])?)
        }
        "conv_reconstruct" => {
            let mut shift = 0u32;
            let mut total = 0u64;
            for (value, width) in v[1..].iter().zip(argument) {
                total += u64::from(*value) << shift;
                shift += u32::try_from(*width)?;
            }
            u64::from(v[0]) == total
        }
        "conv_ab" => {
            let count = usize::try_from(argument[0])?;
            u64::from(v[2 * count])
                == (0..count)
                    .map(|i| u64::from(v[2 * i]) * u64::from(v[2 * i + 1]))
                    .sum::<u64>()
        }
        "conv_pq" => {
            let mut total = 0u64;
            for (value, coefficient) in v[..v.len() - 1].iter().zip(argument) {
                total += u64::from(*value) * u64::try_from(*coefficient)?;
            }
            u64::from(*v.last().ok_or("PQ output")?) == total
        }
        "conv_column" => {
            let ab = usize::try_from(argument[0])?;
            let pq = usize::try_from(argument[1])?;
            let incoming = u64::from(v[ab + pq]);
            let outgoing = u64::from(v[ab + pq + 1]);
            let c = if argument[2] == 1 {
                u64::from(*v.last().ok_or("column c")?)
            } else {
                0
            };
            v[..ab].iter().map(|x| u64::from(*x)).sum::<u64>() + incoming + 255 * 8192
                == c + v[ab..ab + pq].iter().map(|x| u64::from(*x)).sum::<u64>() + 256 * outgoing
        }
        "field_valid" => &integer(v) < p,
        _ => return Err("unsupported closed proof-point predicate".into()),
    };
    Ok(Some(result))
}
fn component_truth(spec: &GraphSpec, values: &[u32]) -> Result<Vec<Option<bool>>> {
    require(values.len() == spec.words.len(), "complete assignment")?;
    let p = role_modulus(&spec.field_role)?;
    spec.leaves
        .iter()
        .map(|leaf| {
            let mut operands = Vec::with_capacity(leaf.wires.len());
            for index in &leaf.wires {
                let value = *values.get(*index).ok_or("truth assignment index")?;
                if value >= spec.words.get(*index).ok_or("truth word")?.bound {
                    return Ok(Some(false));
                }
                operands.push(value);
            }
            predicate(&leaf.kind, &leaf.argument, &operands, &p)
        })
        .collect()
}

fn selection(
    engine: &str,
    reference: &Reference,
    profile: &str,
    truths: &[Vec<Option<bool>>],
    changed: &[usize],
    target: Option<usize>,
) -> Result<Vec<Vec<usize>>> {
    if profile == "honest" {
        return Ok(truths.iter().map(|t| (0..t.len()).collect()).collect());
    }
    let target = target.ok_or("targeted recipe target")?;
    let mut selected: Vec<BTreeSet<usize>> = truths
        .iter()
        .map(|t| {
            t.iter()
                .enumerate()
                .filter(|(_, v)| **v != Some(true))
                .map(|(i, _)| i)
                .collect()
        })
        .collect();
    let anchors = anchors(reference)?;
    let mut seen = HashSet::new();
    for (ordinal, anchor) in anchors.iter().enumerate() {
        if seen.insert(anchor.expected) {
            selected[0].insert(ordinal);
        }
    }
    selected[0].insert(anchors.len());
    let tape = tape_ordinals(reference)?;
    for offset in changed {
        selected[0].insert(tape[*offset]);
    }
    for (row_index, row) in plan(engine)?.iter().enumerate() {
        let index = row_index + 1;
        if let Some(local) = row.iter().position(|d| *d == target) {
            selected[index].extend(0..CONSTANT_CONSTRAINTS);
            selected[index].extend(decoder_leaves(engine, index, local)?);
            selected[index].insert(census(engine, index)?.1);
        } else {
            selected[index].insert(0);
        }
    }
    require(
        selected.iter().map(BTreeSet::len).sum::<usize>() <= TARGET_CAP,
        "targeted selection exceeds closed cap; no counterexample omitted",
    )?;
    Ok(selected
        .into_iter()
        .map(|s| s.into_iter().collect())
        .collect())
}

// ---------------------------------------------------------------------------
// Facts and admission.

pub struct ComponentFacts {
    pub values: Vec<u32>,
    pub truth: Vec<Option<bool>>,
    pub false_ordinals: Vec<usize>,
    pub abort_ordinals: Vec<usize>,
    pub selected_ordinals: Vec<usize>,
    pub global_ids: Vec<String>,
    pub program_sha256: String,
    pub catalogue_id: String,
    /// (decoder index, all leaf ordinals of that decoder) for this component.
    pub decoders: Vec<(usize, Vec<usize>)>,
}
pub struct ByteLink {
    pub source_word: usize,
    pub source_ordinal: usize,
    pub target_component: usize,
    pub target_word: usize,
    pub target_ordinal: usize,
    pub target_occurrence: usize,
    pub global_id: String,
}
pub struct SourceFacts {
    pub components: Vec<ComponentFacts>,
    pub source_sha256: String,
    pub byte_links: Vec<ByteLink>,
    pub native_accepted_decoders: usize,
    pub native_rejected_decoders: usize,
    pub global_words: usize,
    pub opening_occurrences: usize,
}

fn descriptor(
    engine: &str,
    index: usize,
    op: &str,
    program: &str,
    catalogue: &str,
    ids: &[String],
) -> Result<Value> {
    let (words, arithmetic, fields, leaves) = census(engine, index)?;
    Ok(
        json!({"index":index,"name":component_name(engine,index)?,"field_role":component_role(engine,index)?,
        "operation_id":operation(op,engine,index)?,"program_identity_kind":identity_kind(index),
        "words":words,"arithmetic_constraints":arithmetic,"canonical_fields":fields,"leaves":leaves,
        "program_sha256":program,"catalogue_id":catalogue,"global_ids_sha256":hash(&json!(ids))?,
        "decoders":if index==0{Vec::new()}else{plan(engine)?[index-1].clone()}}),
    )
}
fn manifest(
    engine: &str,
    reference: &Reference,
    descriptors: &[Value],
    context: &str,
    op: &str,
) -> Result<Value> {
    let decoders: Vec<Value> = reference
        .commitment_spans(engine)?
        .iter()
        .enumerate()
        .map(|(d, s)| {
            json!({"decoder":d,"path":s.path,"proof_start":s.start,"container_start":HEADER+s.start,
            "component":1+d/BATCH,"local":d%BATCH})
        })
        .collect();
    let mut meta = json!({"schema":"bitvm2-nova-proof-point-origins/v1","context":context,"operation_id":op,
        "engine":engine,"field_role":base_role(engine)?,"expected_policy_sha256":reference_admission::POLICY_SHA256,
        "verifier_dimensions_sha256":reference_admission::DIMENSIONS_SHA256,"payload_bytes":PAYLOAD,
        "container_bytes":BUNDLE,"header_bytes_excluded":HEADER,"components":descriptors,"decoders":decoders,
        "profiles":PROFILES,"encoding":ENCODING,"relation":RELATION,"scope":SCOPE});
    let object = meta.as_object_mut().ok_or("manifest object")?;
    for flag in FALSE_FLAGS {
        object.insert(flag.into(), json!(false));
    }
    require(canonical(&meta)?.len() <= 1 << 20, "source manifest cap")?;
    Ok(meta)
}

pub(crate) fn admit(
    cases: &[Case],
    group: &Group,
    reference: &Reference,
    context: &str,
    op: &str,
    engine: &str,
) -> Result<SourceFacts> {
    let profile = PROFILES
        .iter()
        .position(|p| *p == group.profile)
        .ok_or("closed point profile required")?;
    let n = plan(engine)?.len() + 1;
    require(
        group.name == format!("d/{profile:02}")
            && group.engine == engine
            && op == crate::transport::OPERATION
            && context == crate::transport::context()
            && hex::encode(id32(context)?) == context
            && cases.len() == n
            && group.components.len() == n,
        "verifier-owned conformance context/op/profile/component count",
    )?;
    // Every expected value is reconstructed before any claimed array is read.
    let recipe = profile_claims(reference, engine, &group.profile)?;
    let spans = reference.commitment_spans(engine)?;
    let mut facts = Vec::new();
    let mut descriptors = Vec::new();
    let mut truths = Vec::new();
    let mut encodings = vec![Vec::new()];
    for index in 0..n {
        let case = &cases[index];
        let d = &group.components[index];
        require(
            case.name == format!("{}/{}", group.name, component_name(engine, index)?)
                && case.spec.context == context
                && case.spec.field_role == component_role(engine, index)?
                && case.spec.operation_id == operation(op, engine, index)?,
            "closed component role/context/op",
        )?;
        let program = if index == 0 {
            check_tape(&case.spec, reference)?;
            tape_program_digest(&case.spec)?
        } else {
            let (fields, enc) = check_points(&case.spec, engine, index)?;
            encodings.push(enc);
            plain_digest(&case.spec, census(engine, index)?.1, &fields)?
        };
        let catalogue = hex::encode(case.spec.identity()?);
        let ids = global_ids(engine, index, &case.spec, reference)?;
        require(
            ids.len() == case.spec.words.len()
                && ids.iter().collect::<HashSet<_>>().len() == ids.len(),
            "injective component global identity map",
        )?;
        let values = component_values(engine, index, reference, &recipe.payload, &recipe.claims)?;
        require(
            case.words == values,
            "all claimed component words must match the closed raw-u32 recipe",
        )?;
        let truth = component_truth(&case.spec, &values)?;
        let desc = descriptor(engine, index, op, &program, &catalogue, &ids)?;
        require(
            case.spec.program_sha256 == program
                && case.expected_spec_id == catalogue
                && d.program_sha256 == program
                && d.catalogue_id == catalogue
                && d.global_ids_sha256 == desc["global_ids_sha256"],
            "independently reconstructed component program/catalogue/global identity differs",
        )?;
        let decoders = if index == 0 {
            Vec::new()
        } else {
            plan(engine)?[index - 1]
                .iter()
                .enumerate()
                .map(|(local, dec)| Ok((*dec, decoder_leaves(engine, index, local)?)))
                .collect::<Result<Vec<_>>>()?
        };
        descriptors.push(desc);
        truths.push(truth.clone());
        facts.push(ComponentFacts {
            values,
            truth,
            false_ordinals: Vec::new(),
            abort_ordinals: Vec::new(),
            selected_ordinals: Vec::new(),
            global_ids: ids,
            program_sha256: program,
            catalogue_id: catalogue,
            decoders,
        });
    }
    // Mature strict decoding must agree with the complete leaf relation for
    // EVERY decoder of this profile, including the unchanged ones.
    let (mut accepted, mut rejected) = (0usize, 0usize);
    for fact in facts.iter().skip(1) {
        for (dec, leaves) in &fact.decoders {
            let span = spans[*dec];
            let claimed = &recipe.payload[span.start..span.start + 32];
            let native = claimed.iter().all(|v| *v < 256)
                && strict_decode(
                    &claimed.iter().map(|v| *v as u8).collect::<Vec<_>>(),
                    engine,
                )?
                .as_ref()
                    == Some(&recipe.claims[*dec]);
            let script = leaves.iter().all(|i| fact.truth[*i] == Some(true));
            require(
                native == script,
                &format!("decoder {dec}: strict halo2 decoding and leaf relation disagree"),
            )?;
            if native {
                accepted += 1;
            } else {
                rejected += 1;
            }
        }
        require(
            (0..CONSTANT_CONSTRAINTS).all(|i| fact.truth[i] == Some(true)),
            "fixed constants hold in every profile",
        )?;
    }
    let coherent = COHERENT.contains(&group.profile.as_str());
    require(
        accepted + rejected == spans.len()
            && rejected == usize::from(!coherent)
            && (coherent || recipe.target.is_some()),
        "exactly the targeted decoder is rejected outside coherent profiles",
    )?;
    let chosen = selection(
        engine,
        reference,
        &group.profile,
        &truths,
        &recipe.changed,
        recipe.target,
    )?;
    for (index, fact) in facts.iter_mut().enumerate() {
        let d = &group.components[index];
        let case = &cases[index];
        fact.false_ordinals = fact
            .truth
            .iter()
            .enumerate()
            .filter_map(|(i, t)| (*t == Some(false)).then_some(i))
            .collect();
        fact.abort_ordinals = fact
            .truth
            .iter()
            .enumerate()
            .filter_map(|(i, t)| t.is_none().then_some(i))
            .collect();
        fact.selected_ordinals = chosen[index].clone();
        require(
            d.expected_false == fact.false_ordinals
                && d.expected_abort_ordinals == fact.abort_ordinals
                && fact.abort_ordinals.is_empty()
                && case.measure_all == (profile == 0)
                && (if profile == 0 {
                    d.execution_mode == "all" && d.selected_ordinals.is_none()
                } else {
                    d.execution_mode == "selected"
                        && d.selected_ordinals.as_ref() == Some(&chosen[index])
                })
                && case.checks.len() == chosen[index].len()
                && case
                    .checks
                    .iter()
                    .zip(&chosen[index])
                    .all(|(c, i)| c.ordinal == *i && c.expected_correct == fact.truth[*i]),
            "full/targeted C/D/abort scope differs from independent truth",
        )?;
    }
    let meta = manifest(engine, reference, &descriptors, context, op)?;
    let source_sha = domain_hash(DOMAIN, &meta)?;
    require(
        group.source_sha256 == source_sha,
        "independently reconstructed aggregate source identity differs",
    )?;
    // Global census: only physical payload BYTEs are shared across components.
    let mut globals: BTreeMap<&str, (u32, u32)> = BTreeMap::new();
    let (mut local, mut openings) = (0usize, 0usize);
    for (index, fact) in facts.iter().enumerate() {
        let spec = &cases[index].spec;
        for (i, id) in fact.global_ids.iter().enumerate() {
            let value = (spec.words[i].bound, fact.values[i]);
            if let Some(previous) = globals.get(id.as_str()) {
                require(
                    *previous == value && id.starts_with("proof/container-byte/") && index > 0,
                    "cross-component reuse must preserve the same physical BYTE assertion",
                )?;
            } else {
                globals.insert(id, value);
            }
            local += 1;
        }
        for leaf in &spec.leaves {
            openings += leaf.wires.iter().collect::<HashSet<_>>().len();
        }
    }
    require(
        local - globals.len() == 32 * spans.len(),
        "exactly the decoder encoding BYTEs reuse tape assertions",
    )?;
    let global_words = globals.len();
    drop(globals);
    // Physical BYTE links: the tape leaf and the first actual decoder occurrence.
    let tape = tape_ordinals(reference)?;
    let mut byte_links = Vec::new();
    for index in 1..n {
        let spec = &cases[index].spec;
        let mut first = BTreeMap::new();
        for (ordinal, leaf) in spec.leaves.iter().enumerate() {
            for (formal, word) in leaf.wires.iter().enumerate() {
                first.entry(*word).or_insert((ordinal, formal));
            }
        }
        for (local, enc) in encodings[index].iter().enumerate() {
            let dec = plan(engine)?[index - 1][local];
            let span = spans[dec];
            for (byte, word) in enc.iter().enumerate() {
                let source = span.start + byte;
                let (ordinal, formal) = *first.get(word).ok_or("encoding BYTE has no opener")?;
                let id = facts[index].global_ids[*word].clone();
                require(
                    id == facts[0].global_ids[source]
                        && cases[0].spec.leaves[tape[source]].wires == [source]
                        && facts[index].values[*word] == facts[0].values[source],
                    "actual tape/decoder BYTE coordinate or raw value differs",
                )?;
                byte_links.push(ByteLink {
                    source_word: source,
                    source_ordinal: tape[source],
                    target_component: index,
                    target_word: *word,
                    target_ordinal: ordinal,
                    target_occurrence: formal,
                    global_id: id,
                });
            }
        }
    }
    require(
        byte_links.len() == 32 * spans.len(),
        "complete physical BYTE link census",
    )?;
    Ok(SourceFacts {
        components: facts,
        source_sha256: source_sha,
        byte_links,
        native_accepted_decoders: accepted,
        native_rejected_decoders: rejected,
        global_words,
        opening_occurrences: openings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_and_census_respect_unchanged_caps() {
        assert_eq!(plan("pallas").unwrap().len(), 7);
        assert_eq!(plan("vesta").unwrap().len(), 5);
        assert_eq!(plan("pallas").unwrap()[6], vec![42]);
        assert_eq!(census("pallas", 1).unwrap(), (11882, 9810, 43, 9853));
        assert_eq!(census("pallas", 7).unwrap(), (1706, 1410, 7, 1417));
        assert!(plan("other").is_err());
        let ordinals = decoder_leaves("vesta", 2, 6).unwrap();
        assert_eq!(ordinals.len(), 1406);
        assert_eq!(ordinals[0], 10 + 6 * 1400);
        assert_eq!(*ordinals.last().unwrap(), 9810 + 1 + 6 * 6 + 5);
    }

    #[test]
    fn value_model_census_and_carry_chain_close() {
        for engine in ["pallas", "vesta"] {
            let p = modulus(engine).unwrap();
            let x = BigUint::from(3u32);
            let y = BigUint::from(7u32);
            let raw = encode(&x, 1).unwrap();
            let reference: Vec<u8> = raw.iter().map(|v| *v as u8).collect();
            let claim = Claim {
                infinity: 0,
                x: x.clone(),
                y,
            };
            let words = decoder_values(&raw, &claim, &p, &reference).unwrap();
            assert_eq!(words.len(), DECODER_WORDS);
            assert_eq!(words[52], 1);
            let big = &p - BigUint::from(1u32);
            let digits = bytes32(&big).unwrap();
            let (c, _, _) = mul_values(&digits, &digits, &p).unwrap();
            assert_eq!(c, BigUint::from(1u32));
        }
    }

    #[test]
    fn strict_decoding_rejects_the_identity_alias_and_noncanonical_x() {
        for engine in ["pallas", "vesta"] {
            let p = modulus(engine).unwrap();
            assert_eq!(
                strict_decode(&[0u8; 32], engine).unwrap().unwrap().infinity,
                1
            );
            let mut alias = [0u8; 32];
            alias[31] = 0x80;
            assert!(strict_decode(&alias, engine).unwrap().is_none());
            let mut raw = p.to_bytes_le();
            raw.resize(32, 0);
            assert!(strict_decode(&raw, engine).unwrap().is_none());
            assert!(nonresidue(&BigUint::from(5u32), &p));
        }
    }

    #[test]
    fn predicates_keep_false_and_abort_distinct() {
        let p = modulus("pallas").unwrap();
        let mut v = vec![0u32; 27];
        v[8] = BASE - 1;
        assert_eq!(predicate("add", &[], &v, &p).unwrap(), None);
        assert_eq!(
            predicate("conv_split", &[1], &[3, 1, 1], &p).unwrap(),
            Some(true)
        );
        assert_eq!(
            predicate("conv_split", &[1], &[3, 0, 1], &p).unwrap(),
            Some(false)
        );
        let mut form = vec![0u32; 19];
        form[0] = 1;
        form[3] = 1;
        assert_eq!(
            predicate("point_form", &[], &form, &p).unwrap(),
            Some(false)
        );
    }
}
