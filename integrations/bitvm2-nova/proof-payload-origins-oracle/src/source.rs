//! Independent retained MAX-width payload grammar and scalar-origin relation.
//! Strict admission applies to the fixed reference only. Claimed commitments
//! remain opaque; claimed scalars retain all256bits for the Script field guard.
//! No setup, proving, full-proof acceptance, production origin or M19 helper.
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
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    fs,
    io::Read,
    path::Path,
};

const HEADER: usize = 556;
const PAYLOAD: usize = 12664;
const BUNDLE: usize = 13220;
const BASE: u32 = 1 << 29;
const CROSSINGS: [(usize, usize); 7] =
    [(3, 5), (7, 2), (10, 7), (14, 4), (18, 1), (21, 6), (25, 3)];
pub const PROFILES: [&str; 14] = [
    "honest",
    "coherent-p-eval",
    "coherent-v-eval",
    "p-mod",
    "p-mod1",
    "v-mod",
    "v-mod1",
    "zn0-width",
    "p-outer-count",
    "v-outer-count",
    "opaque-p",
    "opaque-v",
    "byte-256",
    "byte-max",
];
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
fn scalar_role(engine: &str) -> Result<&'static str> {
    match engine {
        "pallas" => Ok("pallas_scalar"),
        "vesta" => Ok("vesta_scalar"),
        _ => Err("exact scalar engine required".into()),
    }
}
fn modulus_text(engine: &str) -> Result<&'static str> {
    match engine {
        "pallas" => {
            Ok("28948022309329048855892746252171976963363056481941647379679742748393362948097")
        }
        "vesta" => {
            Ok("28948022309329048855892746252171976963363056481941560715954676764349967630337")
        }
        _ => Err("exact scalar engine required".into()),
    }
}
fn modulus(engine: &str) -> Result<BigUint> {
    BigUint::parse_bytes(modulus_text(engine)?.as_bytes(), 10)
        .ok_or_else(|| "fixed scalar modulus".into())
}

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
struct Cursor<'a> {
    raw: &'a [u8],
    at: usize,
    spans: Vec<Span>,
}
impl Cursor<'_> {
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
    let mut c = Cursor {
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
    require(
        c.spans.iter().filter(|s| s.kind == "length").count() == 119
            && c.spans
                .iter()
                .filter(|s| s.kind == "scalar" && s.engine.as_deref() == Some("pallas"))
                .count()
                == 169
            && c.spans
                .iter()
                .filter(|s| s.kind == "scalar" && s.engine.as_deref() == Some("vesta"))
                .count()
                == 119
            && c.spans
                .iter()
                .filter(|s| s.kind == "commitment" && s.engine.as_deref() == Some("pallas"))
                .count()
                == 43
            && c.spans
                .iter()
                .filter(|s| s.kind == "commitment" && s.engine.as_deref() == Some("vesta"))
                .count()
                == 35,
        "retained typed atom census",
    )?;
    Ok(c.spans)
}
#[derive(Deserialize, Serialize)]
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
#[derive(Deserialize, Serialize)]
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
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Dimensions {
    schema: String,
    nova_version: String,
    nova_crate_sha256: String,
    header_revision: String,
    network: String,
    k: u32,
    verifier_key_sha256: String,
    outer_arity: usize,
    max_ipa_dimension: usize,
    primary: CurveDimensions,
    secondary: CurveDimensions,
}

pub struct Reference {
    payload: Vec<u8>,
    layout: Vec<Span>,
    pub summary: Value,
}
impl Reference {
    pub fn summary(&self) -> Value {
        self.summary.clone()
    }
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
    pub fn spans(&self) -> &[Span] {
        &self.layout
    }
}
pub fn reference(
    bundle_path: &Path,
    expected_path: &Path,
    dimensions_path: &Path,
) -> Result<Reference> {
    // Typed parsing rejects even same-value duplicate keys before canonical pinning.
    let expected: Expected = serde_json::from_slice(&bounded(expected_path, 8192)?)?;
    let dimensions: Dimensions = serde_json::from_slice(&bounded(dimensions_path, 16384)?)?;
    require(
        hash(&serde_json::to_value(&expected)?)? == reference_admission::POLICY_SHA256
            && hash(&serde_json::to_value(&dimensions)?)? == reference_admission::DIMENSIONS_SHA256,
        "independently compiled reference policy/dimension pins",
    )?;
    // The completed legacy helper admits the actual fixed reference, including
    // all canonical scalars/points, header fields and EOF. It sees no claims.
    let admitted = reference_admission::reference(bundle_path, "pallas_scalar")?;
    let raw = bounded(bundle_path, BUNDLE)?;
    require(
        raw.len() == BUNDLE
            && sha(&raw) == reference_admission::BUNDLE_SHA256
            && sha(&raw[HEADER..]) == reference_admission::PROOF_SHA256,
        "owned immutable reference snapshot must match the old strict reference",
    )?;
    require(
        admitted.expected_policy_sha256 == reference_admission::POLICY_SHA256
            && admitted.dimensions_sha256 == reference_admission::DIMENSIONS_SHA256,
        "legacy strict reference identity mismatch",
    )?;
    let payload = raw[HEADER..].to_vec();
    let spans = layout(&payload)?;
    let mut summary = json!({"schema":"bitvm2-nova-proof-payload-reference/v1","reference_admitted":true,"network":"testnet4","k":5,"steps":404,
        "header_revision":"de607d3db17d400dd6c2923d357f1d4a7bf233c7","nova_version":"0.76.0",
        "expected_policy_sha256":reference_admission::POLICY_SHA256,"verifier_dimensions_sha256":reference_admission::DIMENSIONS_SHA256,
        "verifier_key_sha256":reference_admission::VK_SHA256,"bundle_sha256":reference_admission::BUNDLE_SHA256,"proof_sha256":reference_admission::PROOF_SHA256});
    summary.as_object_mut().ok_or("reference summary")?.extend(json!({
        "bundle_bytes":BUNDLE,"header_bytes":HEADER,"payload_bytes":PAYLOAD,"spans":485,"length_prefixes":119,"scalar_atoms":288,"commitment_atoms":78,
        "pallas_scalars":169,"vesta_scalars":119,"pallas_commitments":43,"vesta_commitments":35,"length_anchor_bytes":952,
        "state_width_anchor_bytes":431,"constant_anchors":1383,"reference_hash_authenticates_claimed_payload":false,"proof_verified":false}).as_object().ok_or("reference continuation")?.clone());
    Ok(Reference {
        payload,
        layout: spans,
        summary,
    })
}

#[derive(Clone, Serialize)]
struct Anchor {
    payload_offset: usize,
    expected: u8,
    kind: String,
    path: String,
}
fn anchors(reference: &Reference) -> Result<Vec<Anchor>> {
    let mut result = BTreeMap::new();
    for span in &reference.layout {
        if span.kind == "length" {
            let count = span.maximum.ok_or("length MAX metadata")?;
            for i in 0..8 {
                let offset = span.start + i;
                require(
                    result
                        .insert(
                            offset,
                            Anchor {
                                payload_offset: offset,
                                expected: (count as u64).to_le_bytes()[i],
                                kind: "length".into(),
                                path: span.path.clone(),
                            },
                        )
                        .is_none(),
                    "overlapping tape anchors",
                )?;
            }
        }
        if let Some(bits) = span.width_bits {
            for i in bits / 8..32 {
                let offset = span.start + i;
                require(
                    result
                        .insert(
                            offset,
                            Anchor {
                                payload_offset: offset,
                                expected: 0,
                                kind: "zn-width".into(),
                                path: span.path.clone(),
                            },
                        )
                        .is_none(),
                    "overlapping state-width anchors",
                )?;
            }
        }
    }
    require(
        result.len() == 1383,
        "952 prefix+431 state-width anchors required",
    )?;
    Ok(result.into_values().collect())
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
fn scalar_body(spec: &GraphSpec, ordinal: usize, engine: &str) -> Result<()> {
    // Compiler-byte lookup uses the matching modulus in the COMPLETED legacy
    // table. This explicit proxy does not alias either protocol field role.
    let proxy = match engine {
        "pallas" => "vesta_base",
        "vesta" => "pallas_base",
        _ => return Err("scalar pin engine".into()),
    };
    let leaf = &spec.leaves[ordinal];
    crate::legacy_body_pins::check(
        proxy,
        &leaf.kind,
        &leaf.argument,
        &leaf.wires,
        &leaf.body_sha256,
    )
}

#[derive(Clone)]
struct Template {
    kind: &'static str,
    args: Vec<i64>,
    wires: Vec<usize>,
}
fn encoding_template() -> Result<(Vec<u32>, Vec<Template>)> {
    let mut bounds = vec![BASE; 9];
    bounds.extend([256; 32]);
    for (_, width) in CROSSINGS {
        bounds.extend([1 << width, 1 << (8 - width)]);
    }
    let mut leaves = Vec::new();
    for (i, (byte, width)) in CROSSINGS.into_iter().enumerate() {
        leaves.push(Template {
            kind: "conv_split",
            args: vec![width as i64],
            wires: vec![9 + byte, 41 + 2 * i, 42 + 2 * i],
        });
    }
    for limb in 0usize..9 {
        let (start, end) = (29 * limb, (29 * limb + 29).min(256));
        let mut wires = vec![limb];
        let mut widths = Vec::new();
        for byte in start / 8..end.div_ceil(8) {
            let (low, high) = (start.max(8 * byte), end.min(8 * byte + 8));
            let word = if low == 8 * byte && high == 8 * byte + 8 {
                9 + byte
            } else {
                let cross = CROSSINGS
                    .iter()
                    .position(|(b, _)| *b == byte)
                    .ok_or("missing crossing")?;
                41 + 2 * cross + usize::from(low != 8 * byte)
            };
            wires.push(word);
            widths.push((high - low) as i64);
        }
        leaves.push(Template {
            kind: "conv_reconstruct",
            args: widths,
            wires,
        });
    }
    Ok((bounds, leaves))
}
fn scalar_spans(reference: &Reference, index: usize) -> Result<Vec<&Span>> {
    let engine = match index {
        1 => "pallas",
        2 => "vesta",
        _ => return Err("scalar component1 or2 required".into()),
    };
    Ok(reference
        .layout
        .iter()
        .filter(|s| s.kind == "scalar" && s.engine.as_deref() == Some(engine))
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
fn count(index: usize) -> Result<usize> {
    match index {
        0 => Ok(PAYLOAD),
        1 => Ok(169),
        2 => Ok(119),
        _ => Err("component index0..2 required".into()),
    }
}
fn name(index: usize) -> Result<&'static str> {
    match index {
        0 => Ok("tape"),
        1 => Ok("pallas"),
        2 => Ok("vesta"),
        _ => Err("component index0..2 required".into()),
    }
}
fn engine(index: usize) -> Result<&'static str> {
    match index {
        1 => Ok("pallas"),
        2 => Ok("vesta"),
        _ => Err("scalar component index1..2 required".into()),
    }
}
fn role(index: usize) -> Result<&'static str> {
    match index {
        0 | 1 => Ok("pallas_scalar"),
        2 => Ok("vesta_scalar"),
        _ => Err("component index0..2 required".into()),
    }
}
fn operation(op: &str, index: usize) -> Result<String> {
    Ok(format!(
        "{op}/{}",
        match index {
            0 => "tape",
            1 => "pallas-scalars",
            2 => "vesta-scalars",
            _ => return Err("component index".into()),
        }
    ))
}
fn census(index: usize) -> Result<(usize, usize, usize, usize)> {
    match index {
        0 => Ok((12664, 1383, 0, 12664)),
        1 => Ok((9295, 2704, 169, 2873)),
        2 => Ok((6545, 1904, 119, 2023)),
        _ => Err("component census index".into()),
    }
}
fn scalar_local_name(scalar: usize, local: usize) -> Result<String> {
    Ok(if local < 9 {
        format!("scalar/{scalar}/l{local}")
    } else if local < 41 {
        format!("scalar/{scalar}/encoding/byte/{}", local - 9)
    } else if local < 55 {
        let part = local - 41;
        format!(
            "scalar/{scalar}/encoding/split/{}/{}",
            CROSSINGS[part / 2].0,
            if part % 2 == 0 { "lo" } else { "hi" }
        )
    } else {
        return Err("scalar local word index".into());
    })
}
fn component_globals(index: usize, spec: &GraphSpec, reference: &Reference) -> Result<Vec<String>> {
    if index == 0 {
        return Ok((0..PAYLOAD)
            .map(|i| format!("proof/container-byte/{}", HEADER + i))
            .collect());
    }
    let spans = scalar_spans(reference, index)?;
    let mut ids = Vec::new();
    for (i, span) in spans.iter().enumerate() {
        for local in 0..55 {
            ids.push(if (9..41).contains(&local) {
                format!("proof/container-byte/{}", HEADER + span.start + local - 9)
            } else {
                format!(
                    "proof/scalar/{}/{i}/{}",
                    engine(index)?,
                    spec.words[55 * i + local].name
                )
            });
        }
    }
    Ok(ids)
}
fn exact_catalogue(spec: &GraphSpec, expected: &BTreeMap<String, String>) -> Result<()> {
    require(
        &spec.bodies == expected,
        "exact closed predicate body catalogue required",
    )?;
    spec.identity().map(|_| ())
}
fn check_tape(spec: &GraphSpec, reference: &Reference) -> Result<()> {
    require(
        spec.words.len() == 12664 && spec.leaves.len() == 12664,
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
        bodies.len() == 9,
        "Tape eight constants plus word-valid body census",
    )?;
    exact_catalogue(spec, &bodies)
}
fn check_scalars(spec: &GraphSpec, index: usize, reference: &Reference) -> Result<()> {
    let n = scalar_spans(reference, index)?.len();
    let (bounds, template) = encoding_template()?;
    require(
        spec.words.len() == 55 * n && spec.leaves.len() == 17 * n,
        "scalar batch exact word/leaf census",
    )?;
    for scalar in 0..n {
        for (local, bound) in bounds.iter().enumerate() {
            let w = &spec.words[55 * scalar + local];
            require(
                w.name == scalar_local_name(scalar, local)? && w.bound == *bound,
                "scalar batch declaration order/name/bound differs",
            )?;
        }
        for (j, t) in template.iter().enumerate() {
            let ordinal = 16 * scalar + j;
            let leaf = &spec.leaves[ordinal];
            let wires: Vec<_> = t.wires.iter().map(|w| 55 * scalar + w).collect();
            require(
                leaf.kind == t.kind && leaf.argument == t.args && leaf.wires == wires,
                "scalar exact reconstruction/split formal topology differs",
            )?;
            scalar_body(spec, ordinal, engine(index)?)?;
        }
        let ordinal = 16 * n + scalar;
        let leaf = &spec.leaves[ordinal];
        require(
            leaf.kind == "field_valid"
                && leaf.argument.is_empty()
                && leaf.wires == (55 * scalar..55 * scalar + 9).collect::<Vec<_>>(),
            "scalar canonical field guard detached",
        )?;
        scalar_body(spec, ordinal, engine(index)?)?;
    }
    let used: HashSet<_> = spec.leaves.iter().map(|l| l.body_sha256.clone()).collect();
    require(
        used.len() == 17
            && used.len() == spec.bodies.len()
            && spec.bodies.keys().all(|h| used.contains(h)),
        "scalar17 pinned bodies/no extra unused body",
    )?;
    spec.identity().map(|_| ())
}
fn program_digest(spec: &GraphSpec, index: usize) -> Result<String> {
    let (_, arith, fields, _) = census(index)?;
    let field_rows: Vec<_> = (0..fields)
        .map(|i| {
            json!([
                format!("scalar/{i}"),
                (0..9)
                    .map(|j| format!("scalar/{i}/l{j}"))
                    .collect::<Vec<_>>()
            ])
        })
        .collect();
    let constraints: Vec<_> = spec.leaves[..arith]
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
    let plain = hash(
        &json!({"schema":"bitvm2-nova-fixed-trace/v2","field_role":spec.field_role,"modulus":modulus_text(if index==2{"vesta"}else{"pallas"})?,
        "operation_id":spec.operation_id,"context":spec.context,"words":spec.words.iter().map(|w|json!([w.name,w.bound])).collect::<Vec<_>>(),
        "fields":field_rows,"constraints":constraints}),
    )?;
    if index != 0 {
        return Ok(plain);
    }
    let mut h = sha256::Hash::engine();
    h.input(b"BITVM2-NOVA/BYTE-TRACE/v1\0");
    h.input(&hex::decode(plain)?);
    Ok(hex::encode(sha256::Hash::from_engine(h)))
}
#[derive(Clone, Serialize)]
pub struct InternalLink {
    pub component_index: usize,
    pub word_index: usize,
    pub source_ordinal: usize,
    pub source_occurrence: usize,
    pub target_ordinal: usize,
    pub target_occurrence: usize,
    pub global_id: String,
}
#[derive(Clone, Serialize)]
pub struct ByteLink {
    pub source_component: usize,
    pub source_word: usize,
    pub source_ordinal: usize,
    pub source_occurrence: usize,
    pub target_component: usize,
    pub target_word: usize,
    pub target_ordinal: usize,
    pub target_occurrence: usize,
    pub global_id: String,
}
fn byte_occurrences(template: &[Template]) -> Result<Vec<(usize, usize)>> {
    (0..32)
        .map(|byte| {
            template
                .iter()
                .enumerate()
                .find_map(|(i, t)| {
                    t.wires
                        .iter()
                        .position(|w| *w == 9 + byte)
                        .map(|formal| (i, formal))
                })
                .ok_or_else(|| "scalar byte has no exact opener".into())
        })
        .collect()
}
fn scalar_map(reference: &Reference, index: usize) -> Result<Value> {
    let spans = scalar_spans(reference, index)?;
    let (_, template) = encoding_template()?;
    let byte_occ = byte_occurrences(&template)?;
    let mut rows = Vec::new();
    for (i, span) in spans.iter().enumerate() {
        let (base, leaf) = (55 * i, 16 * i);
        let mut links = Vec::new();
        for limb in 0..9 {
            links.push(
                json!({"word_index":base+limb,"source_ordinal":leaf+7+limb,"source_occurrence":0,
            "target_ordinal":16*spans.len()+i,"target_occurrence":limb}),
            );
        }
        for part in 0..14 {
            let word = 41 + part;
            let (target, formal) = template
                .iter()
                .enumerate()
                .skip(7)
                .find_map(|(j, t)| {
                    t.wires
                        .iter()
                        .position(|w| *w == word)
                        .map(|slot| (j, slot))
                })
                .ok_or("split consumer missing")?;
            links.push(json!({"word_index":base+word,"source_ordinal":leaf+part/2,"source_occurrence":1+part%2,"target_ordinal":leaf+target,"target_occurrence":formal}));
        }
        rows.push(json!({"scalar_index":i,"path":span.path,"proof_start":span.start,"container_start":HEADER+span.start,"width_bits":span.width_bits,
            "limb_words":(base..base+9).collect::<Vec<_>>(),"byte_words":(base+9..base+41).collect::<Vec<_>>(),"split_words":(base+41..base+55).collect::<Vec<_>>(),
            "byte_occurrences":byte_occ.iter().map(|(j,f)|(leaf+j,*f)).collect::<Vec<_>>(),"field_valid_ordinal":16*spans.len()+i,"canonical_links":links}));
    }
    Ok(
        json!({"schema":"bitvm2-nova-proof-scalar-batch-maps/v1","engine":engine(index)?,"field_role":role(index)?,"scalar_count":spans.len(),"scalars":rows}),
    )
}
fn component_maps(reference: &Reference, index: usize) -> Result<Value> {
    if index != 0 {
        return scalar_map(reference, index);
    }
    let anchor = anchors(reference)?;
    let rows:Vec<_>=anchor.iter().enumerate().map(|(i,a)|json!({"payload_offset":a.payload_offset,"container_offset":HEADER+a.payload_offset,
        "word_index":a.payload_offset,"ordinal":i,"expected":a.expected,"reason":a.kind,"path":a.path})).collect();
    Ok(
        json!({"schema":"bitvm2-nova-proof-payload-tape-maps/v1","byte_ordinals":tape_ordinals(reference)?,"anchors":rows,"controls":controls(reference,0)?,
        "length_prefixes":119,"variable_prefixes_fixed_at_max":101,"width_zero_bytes":431,"payload_bytes":PAYLOAD}),
    )
}

fn find_span<'a>(reference: &'a Reference, path: &str) -> Result<&'a Span> {
    reference
        .layout
        .iter()
        .find(|s| s.path == path)
        .ok_or_else(|| "closed profile span missing".into())
}
fn profile_values(reference: &Reference, profile: &str) -> Result<(Vec<u32>, Vec<usize>)> {
    require(
        PROFILES.contains(&profile),
        "exact closed proof-payload profile required",
    )?;
    let mut values: Vec<_> = reference.payload.iter().map(|b| u32::from(*b)).collect();
    let mut changed = Vec::new();
    let primary = find_span(reference, "snark_primary.eval_W")?;
    let secondary = find_span(reference, "snark_secondary.eval_W")?;
    let mut replace = |span: &Span, raw: &[u8]| -> Result<()> {
        require(raw.len() == span.size, "closed profile replacement width")?;
        for (i, b) in raw.iter().enumerate() {
            values[span.start + i] = u32::from(*b);
        }
        changed = (span.start..span.start + span.size).collect();
        Ok(())
    };
    match profile {
        "coherent-p-eval" | "coherent-v-eval" => {
            let p = profile == "coherent-p-eval";
            let span = if p { primary } else { secondary };
            let engine = if p { "pallas" } else { "vesta" };
            let value = BigUint::from_bytes_le(&reference.payload[span.start..span.start + 32])
                + BigUint::from(1u32);
            require(
                value < modulus(engine)?,
                "closed coherent scalar increment boundary",
            )?;
            let mut raw = value.to_bytes_le();
            raw.resize(32, 0);
            replace(span, &raw)?;
        }
        "p-mod" | "p-mod1" | "v-mod" | "v-mod1" => {
            let p = profile.starts_with("p-");
            let span = if p { primary } else { secondary };
            let value = modulus(if p { "pallas" } else { "vesta" })?
                + BigUint::from(u32::from(profile.ends_with('1')));
            let mut raw = value.to_bytes_le();
            raw.resize(32, 0);
            replace(span, &raw)?;
        }
        "zn0-width" => {
            let mut raw = [0u8; 32];
            raw[4] = 1;
            replace(find_span(reference, "zn[0]")?, &raw)?;
        }
        "p-outer-count" | "v-outer-count" => {
            let owner = if profile == "p-outer-count" {
                "primary"
            } else {
                "secondary"
            };
            replace(find_span(reference,&format!("snark_{owner}.sc_proof_outer.compressed_polys[0].coeffs_except_linear_term"))?,&2u64.to_le_bytes())?;
        }
        "opaque-p" | "opaque-v" => {
            let engine = if profile == "opaque-p" {
                "pallas"
            } else {
                "vesta"
            };
            let span = reference
                .layout
                .iter()
                .find(|s| s.kind == "commitment" && s.engine.as_deref() == Some(engine))
                .ok_or("opaque commitment span")?;
            replace(span, &[255u8; 32])?;
        }
        "byte-256" | "byte-max" => {
            values[primary.start] = if profile == "byte-256" { 256 } else { u32::MAX };
            changed = vec![primary.start];
        }
        "honest" => {}
        _ => return Err("unsupported payload profile".into()),
    }
    Ok((values, changed))
}
fn encoding_values(raw: &[u8]) -> Result<(Vec<u32>, Vec<u32>)> {
    require(raw.len() == 32, "scalar integer width32")?;
    let value = BigUint::from_bytes_le(raw);
    let mask = BigUint::from(BASE - 1);
    let limbs = (0usize..9)
        .map(|i| {
            ((&value >> (29 * i)) & &mask)
                .to_u32_digits()
                .first()
                .copied()
                .unwrap_or(0)
        })
        .collect();
    let pieces = CROSSINGS
        .iter()
        .flat_map(|(byte, width)| {
            let v = u32::from(raw[*byte]);
            [v & ((1 << width) - 1), v >> width]
        })
        .collect();
    Ok((limbs, pieces))
}
fn raw_component(reference: &Reference, index: usize, payload: &[u32]) -> Result<Vec<u32>> {
    require(
        payload.len() == PAYLOAD,
        "exact raw-u32 payload count required",
    )?;
    if index == 0 {
        return Ok(payload.to_vec());
    }
    let mut assigned = Vec::new();
    for span in scalar_spans(reference, index)? {
        let claimed = &payload[span.start..span.start + 32];
        let raw: Vec<u8> = if claimed.iter().all(|v| *v < 256) {
            claimed.iter().map(|v| *v as u8).collect()
        } else {
            reference.payload[span.start..span.start + 32].to_vec()
        };
        let (limbs, pieces) = encoding_values(&raw)?;
        assigned.extend(limbs);
        assigned.extend_from_slice(claimed);
        assigned.extend(pieces);
    }
    Ok(assigned)
}
fn component_truth(spec: &GraphSpec, index: usize, values: &[u32]) -> Result<Vec<Option<bool>>> {
    let mut truth = Vec::with_capacity(spec.leaves.len());
    for leaf in &spec.leaves {
        let v: Vec<_> = leaf.wires.iter().map(|i| values[*i]).collect();
        if leaf
            .wires
            .iter()
            .zip(&v)
            .any(|(i, v)| *v >= spec.words[*i].bound)
        {
            truth.push(Some(false));
            continue;
        }
        let correct = match leaf.kind.as_str() {
            "const" => v[0] as i64 == leaf.argument[0],
            "word_valid" => true,
            "conv_split" => {
                u64::from(v[0]) == u64::from(v[1]) + (u64::from(v[2]) << (leaf.argument[0] as u32))
            }
            "conv_reconstruct" => {
                let (mut shift, mut total) = (0u32, 0u64);
                for (part, width) in v[1..].iter().zip(&leaf.argument) {
                    total += u64::from(*part) << shift;
                    shift += *width as u32;
                }
                u64::from(v[0]) == total
            }
            "field_valid" => {
                let value = v
                    .iter()
                    .enumerate()
                    .fold(BigUint::from(0u32), |acc, (i, v)| {
                        acc + (BigUint::from(*v) << (29 * i))
                    });
                value < modulus(engine(index)?)?
            }
            _ => return Err("non-approved payload predicate".into()),
        };
        truth.push(Some(correct));
    }
    Ok(truth)
}
fn controls(reference: &Reference, index: usize) -> Result<Vec<usize>> {
    if index != 0 {
        let mut out: Vec<usize> = (0..16).collect();
        out.push(16 * count(index)?);
        return Ok(out);
    }
    let mut values = HashSet::new();
    let mut out = Vec::new();
    for (i, a) in anchors(reference)?.iter().enumerate() {
        if values.insert(a.expected) {
            out.push(i);
        }
    }
    out.push(1383);
    require(out.len() == 9, "Tape nine authenticated shape controls")?;
    Ok(out)
}
fn selection(
    reference: &Reference,
    profile: &str,
    truths: &[Vec<Option<bool>>; 3],
    changed: &[usize],
) -> Result<[Vec<usize>; 3]> {
    if profile == "honest" {
        return Ok(std::array::from_fn(|i| (0..truths[i].len()).collect()));
    }
    let mut chosen: [BTreeSet<usize>; 3] = [BTreeSet::new(), BTreeSet::new(), BTreeSet::new()];
    for i in 0..3 {
        chosen[i].extend(controls(reference, i)?);
        chosen[i].extend(
            truths[i]
                .iter()
                .enumerate()
                .filter_map(|(j, t)| (*t != Some(true)).then_some(j)),
        );
    }
    let ord = tape_ordinals(reference)?;
    chosen[0].extend(changed.iter().map(|i| ord[*i]));
    let affected: HashSet<_> = changed.iter().copied().collect();
    for index in [1, 2] {
        for (i, span) in scalar_spans(reference, index)?.iter().enumerate() {
            if (span.start..span.start + 32).any(|p| affected.contains(&p)) {
                chosen[index].extend(16 * i..16 * i + 16);
                chosen[index].insert(16 * count(index)? + i);
            }
        }
    }
    require(
        chosen.iter().map(BTreeSet::len).sum::<usize>() <= 128,
        "all-failure/affected/control target union exceeds128 TOTAL",
    )?;
    Ok(chosen.map(|set| set.into_iter().collect()))
}
pub struct ComponentFacts {
    pub values: Vec<u32>,
    pub truth: Vec<Option<bool>>,
    pub false_ordinals: Vec<usize>,
    pub abort_ordinals: Vec<usize>,
    pub selected_ordinals: Vec<usize>,
    pub global_ids: Vec<String>,
    pub program_sha256: String,
    pub catalogue_id: String,
    pub source_sha256: String,
    pub source_maps_sha256: String,
    pub manifest: Value,
    pub source_maps: Value,
}
pub struct SourceFacts {
    pub components: [ComponentFacts; 3],
    pub source_sha256: String,
    pub source_maps_sha256: String,
    pub manifest: Value,
    pub source_maps: Value,
    pub byte_links: Vec<ByteLink>,
    pub internal_links: Vec<InternalLink>,
}
fn component_metadata(
    spec: &GraphSpec,
    index: usize,
    reference: &Reference,
    context: &str,
    op: &str,
) -> Result<(Value, Value, Value, Vec<String>)> {
    let maps = component_maps(reference, index)?;
    let maps_sha = hash(&maps)?;
    let ids = component_globals(index, spec, reference)?;
    require(
        ids.len() == spec.words.len() && ids.iter().collect::<HashSet<_>>().len() == ids.len(),
        "injective component global identity map",
    )?;
    let (words, arith, fields, leaves) = census(index)?;
    let program = program_digest(spec, index)?;
    let catalogue = hex::encode(spec.identity()?);
    let meta = json!({"schema":"bitvm2-nova-proof-payload-component/v1","index":index,"name":name(index)?,"context":context,"field_role":role(index)?,
        "operation_id":operation(op,index)?,"program_sha256":program,"catalogue_id":catalogue,"source_maps_sha256":maps_sha,
        "words":words,"arithmetic_constraints":arith,"canonical_fields":fields,"leaves":leaves,
        "profile":"retained maximum-width serialization; not a generic decoder","source_authority":false});
    let descriptor = json!({"index":index,"name":name(index)?,"field_role":role(index)?,"operation_id":operation(op,index)?,
        "program_identity_kind":if index==0{"ByteProgram.digest (byte-v1)"}else{"ConvolutionProgram.digest (fixed-trace/v2)"},
        "words":words,"arithmetic_constraints":arith,"canonical_fields":fields,"leaves":leaves,"program_sha256":program,"catalogue_id":catalogue,
        "source_sha256":domain_hash(b"BITVM2-NOVA/PROOF-PAYLOAD-COMPONENT/v1\0",&meta)?,"source_maps_sha256":maps_sha,"global_ids_sha256":hash(&json!(ids))?});
    Ok((maps, meta, descriptor, ids))
}
const FALSE_FLAGS: [&str; 12] = [
    "blob_sha256_script_bound",
    "proof_eof_authenticated",
    "container_header_script_bound",
    "compressed_points_script_decoded",
    "generic_nova_decoder",
    "transcript_verified",
    "proof_verified",
    "complete_nova_verifier",
    "complete_bitvm2_verifier",
    "production_assertion_binding",
    "bitcoin_transaction_graph",
    "public_state_to_zn_script_bound",
];
fn outer_metadata(
    reference: &Reference,
    descriptors: &[Value; 3],
    context: &str,
    op: &str,
) -> Result<(Value, Value)> {
    let tape = tape_ordinals(reference)?;
    let mut joins = Vec::new();
    for index in [1, 2] {
        let smap = scalar_map(reference, index)?;
        for row in smap["scalars"].as_array().ok_or("scalar rows")? {
            let start = row["proof_start"].as_u64().ok_or("scalar proof start")? as usize;
            joins.push(json!({"component":index,"scalar_index":row["scalar_index"],"path":row["path"],"proof_start":row["proof_start"],"container_start":row["container_start"],
            "tape_words":(start..start+32).collect::<Vec<_>>(),"tape_ordinals":(start..start+32).map(|i|tape[i]).collect::<Vec<_>>(),
            "encoder_words":row["byte_words"],"encoder_occurrences":row["byte_occurrences"],"field_valid_ordinal":row["field_valid_ordinal"],"canonical_links":row["canonical_links"]}));
        }
    }
    let maps = json!({"schema":"bitvm2-nova-proof-payload-origins-maps/v1","layout":reference.layout,"components":descriptors,"scalar_joins":joins,
        "byte_joins":9216,"canonical_internal_links":6624,"local_words":28504,"unique_global_words":19288,"cached_signature_reuses":9216,"leaves":17560,"container_offset_bias":HEADER});
    let mut meta = json!({"schema":"bitvm2-nova-proof-payload-origins/v1","context":context,"operation_id":op,
        "expected_policy_sha256":reference_admission::POLICY_SHA256,"verifier_dimensions_sha256":reference_admission::DIMENSIONS_SHA256,
        "payload_bytes":PAYLOAD,"container_bytes":BUNDLE,"header_bytes_excluded":HEADER,"component_order":["tape","pallas","vesta"],"components":descriptors,
        "source_maps_sha256":hash(&maps)?,"profiles":PROFILES,"scalar_counts":{"pallas":169,"vesta":119},"opaque_point_counts":{"pallas":43,"vesta":35}});
    meta.as_object_mut().ok_or("outer meta")?.extend(json!({"length_prefixes":119,"fixed_prefixes":18,"variable_prefixes_fixed_at_max":101,
        "prefix_constant_bytes":952,"width_zero_bytes":431,"constant_bytes":1383,"local_words":28504,"unique_global_words":19288,"cached_signature_reuses":9216,"leaves":17560,
        "relation":"asserted retained maximum-width payload BYTEs -> canonical scalar encodings and fixed lengths/zn widths",
        "scope":"opaque point BYTEs; no asserted blob SHA/EOF/header, transcript, proof or production origins"}).as_object().ok_or("outer continuation")?.clone());
    for flag in FALSE_FLAGS {
        meta.as_object_mut()
            .ok_or("outer false flags")?
            .insert(flag.into(), json!(false));
    }
    require(
        canonical(&maps)?.len() <= 8 << 20 && canonical(&meta)?.len() <= 1 << 20,
        "outer source sidecar caps",
    )?;
    Ok((maps, meta))
}

fn links(
    reference: &Reference,
    components: &[ComponentFacts; 3],
    cases: &[Case; 3],
) -> Result<(Vec<ByteLink>, Vec<InternalLink>)> {
    let mut bytes = Vec::new();
    let mut internal = Vec::new();
    let tape = tape_ordinals(reference)?;
    let (_, template) = encoding_template()?;
    let byte_occ = byte_occurrences(&template)?;
    for index in [1, 2] {
        for (i, span) in scalar_spans(reference, index)?.iter().enumerate() {
            for byte in 0..32 {
                let source = span.start + byte;
                let (target, formal) = byte_occ[byte];
                let target = 16 * i + target;
                let word = 55 * i + 9 + byte;
                let global = components[0].global_ids[source].clone();
                require(
                    cases[0].spec.leaves[tape[source]].wires == [source]
                        && cases[index].spec.leaves[target].wires[formal] == word,
                    "actual Tape/scalar BYTE opening coordinate differs",
                )?;
                require(
                    components[index].global_ids[word] == global
                        && components[index].values[word] == components[0].values[source],
                    "actual Tape/scalar raw-u32 global value differs",
                )?;
                bytes.push(ByteLink {
                    source_component: 0,
                    source_word: source,
                    source_ordinal: tape[source],
                    source_occurrence: 0,
                    target_component: index,
                    target_word: word,
                    target_ordinal: target,
                    target_occurrence: formal,
                    global_id: global,
                });
            }
            for limb in 0..9 {
                internal.push(InternalLink {
                    component_index: index,
                    word_index: 55 * i + limb,
                    source_ordinal: 16 * i + 7 + limb,
                    source_occurrence: 0,
                    target_ordinal: 16 * count(index)? + i,
                    target_occurrence: limb,
                    global_id: components[index].global_ids[55 * i + limb].clone(),
                });
            }
            for part in 0..14 {
                let word = 41 + part;
                let (target, formal) = template
                    .iter()
                    .enumerate()
                    .skip(7)
                    .find_map(|(j, t)| t.wires.iter().position(|w| *w == word).map(|f| (j, f)))
                    .ok_or("internal split consumer")?;
                internal.push(InternalLink {
                    component_index: index,
                    word_index: 55 * i + word,
                    source_ordinal: 16 * i + part / 2,
                    source_occurrence: 1 + part % 2,
                    target_ordinal: 16 * i + target,
                    target_occurrence: formal,
                    global_id: components[index].global_ids[55 * i + word].clone(),
                });
            }
        }
    }
    for link in &internal {
        let spec = &cases[link.component_index].spec;
        require(
            spec.leaves[link.source_ordinal].wires[link.source_occurrence] == link.word_index
                && spec.leaves[link.target_ordinal].wires[link.target_occurrence]
                    == link.word_index,
            "actual private canonical limb/split coordinate differs",
        )?;
    }
    require(
        bytes.len() == 9216 && internal.len() == 6624,
        "complete byte/internal source link census",
    )?;
    Ok((bytes, internal))
}
fn check_component_header(
    index: usize,
    case: &Case,
    group: &Group,
    context: &str,
    op: &str,
) -> Result<()> {
    let d = &group.components[index];
    let (words, arith, fields, leaves) = census(index)?;
    require(
        d.index == index
            && d.name == name(index)?
            && d.field_role == role(index)?
            && d.operation_id == operation(op, index)?
            && d.program_identity_kind
                == if index == 0 {
                    "ByteProgram.digest (byte-v1)"
                } else {
                    "ConvolutionProgram.digest (fixed-trace/v2)"
                },
        "closed source component identity kind differs",
    )?;
    require(
        (
            d.words,
            d.arithmetic_constraints,
            d.canonical_fields,
            d.leaves,
        ) == (words, arith, fields, leaves)
            && case.name == format!("{}/{}", group.name, name(index)?)
            && case.spec.context == context
            && case.spec.field_role == role(index)?
            && case.spec.operation_id == operation(op, index)?
            && case.spec.words.len() == words
            && case.spec.leaves.len() == leaves,
        "closed component role/context/op/census differs",
    )
}
pub(crate) fn admit(
    cases: &[Case; 3],
    group: &Group,
    reference: &Reference,
    context: &str,
    op: &str,
) -> Result<SourceFacts> {
    let profile = PROFILES
        .iter()
        .position(|p| *p == group.profile)
        .ok_or("closed payload profile required")?;
    require(
        group.name == format!("d/{profile:02}")
            && op == "benchmark/proof-payload-origins/v1"
            && context == sha(b"BITVM2-NOVA/PROOF-PAYLOAD-ORIGINS-CONFORMANCE/v1")
            && hex::encode(id32(context)?) == context,
        "verifier-owned conformance context/op/profile name required",
    )?;
    // The claimed array never drives a parser, scalar from_repr, point decoder,
    // offset or loop bound. Every expected value is reconstructed first.
    let (payload, changed) = profile_values(reference, &group.profile)?;
    let values = [
        raw_component(reference, 0, &payload)?,
        raw_component(reference, 1, &payload)?,
        raw_component(reference, 2, &payload)?,
    ];
    for index in 0..3 {
        check_component_header(index, &cases[index], group, context, op)?;
        if index == 0 {
            check_tape(&cases[index].spec, reference)?;
        } else {
            check_scalars(&cases[index].spec, index, reference)?;
        }
        require(
            cases[index].words == values[index],
            "all claimed component words must match the closed raw-u32 recipe",
        )?;
    }
    let truths = [
        component_truth(&cases[0].spec, 0, &values[0])?,
        component_truth(&cases[1].spec, 1, &values[1])?,
        component_truth(&cases[2].spec, 2, &values[2])?,
    ];
    let chosen = selection(reference, &group.profile, &truths, &changed)?;
    let mut facts = Vec::new();
    let mut descriptors = Vec::new();
    for index in 0..3 {
        let case = &cases[index];
        let d = &group.components[index];
        let false_ordinals: Vec<_> = truths[index]
            .iter()
            .enumerate()
            .filter_map(|(i, t)| (*t == Some(false)).then_some(i))
            .collect();
        let abort_ordinals: Vec<_> = truths[index]
            .iter()
            .enumerate()
            .filter_map(|(i, t)| t.is_none().then_some(i))
            .collect();
        require(
            d.expected_false == false_ordinals
                && d.expected_abort_ordinals == abort_ordinals
                && abort_ordinals.is_empty()
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
                    .all(|(c, i)| c.ordinal == *i && c.expected_correct == truths[index][*i]),
            "full/targeted C/D/abort scope differs from independent truth",
        )?;
        let (maps, meta, descriptor, ids) =
            component_metadata(&case.spec, index, reference, context, op)?;
        let program = program_digest(&case.spec, index)?;
        let catalogue = hex::encode(case.spec.identity()?);
        let maps_sha = hash(&maps)?;
        let source_sha = domain_hash(b"BITVM2-NOVA/PROOF-PAYLOAD-COMPONENT/v1\0", &meta)?;
        require(
            case.spec.program_sha256 == program
                && case.expected_spec_id == catalogue
                && d.program_sha256 == program
                && d.catalogue_id == catalogue
                && d.source_sha256 == source_sha
                && d.source_maps_sha256 == maps_sha
                && d.global_ids_sha256 == hash(&json!(ids))?,
            "independently reconstructed component program/catalogue/source/maps identity differs",
        )?;
        descriptors.push(descriptor);
        facts.push(ComponentFacts {
            values: values[index].clone(),
            truth: truths[index].clone(),
            false_ordinals,
            abort_ordinals,
            selected_ordinals: chosen[index].clone(),
            global_ids: ids,
            program_sha256: program,
            catalogue_id: catalogue,
            source_sha256: source_sha,
            source_maps_sha256: maps_sha,
            manifest: meta,
            source_maps: maps,
        });
    }
    let components: [ComponentFacts; 3] = facts.try_into().map_err(|_| "three component facts")?;
    let descriptors: [Value; 3] = descriptors
        .try_into()
        .map_err(|_| "three component source descriptors")?;
    let (maps, meta) = outer_metadata(reference, &descriptors, context, op)?;
    let maps_sha = hash(&maps)?;
    let source_sha = domain_hash(b"BITVM2-NOVA/PROOF-PAYLOAD-ORIGINS/v1\0", &meta)?;
    require(
        group.source_sha256 == source_sha && group.source_maps_sha256 == maps_sha,
        "independently reconstructed aggregate source/maps identity differs",
    )?;
    let mut globals: BTreeMap<&str, (u32, u32)> = BTreeMap::new();
    let mut declarations = 0;
    let mut openings = 0;
    for index in 0..3 {
        let spec = &cases[index].spec;
        for (i, id) in components[index].global_ids.iter().enumerate() {
            let value = (spec.words[i].bound, components[index].values[i]);
            if let Some(previous) = globals.get(id.as_str()) {
                require(
                    *previous == value,
                    "cross-role physical BYTE/field-bound/global value mismatch",
                )?;
            } else {
                globals.insert(id, value);
            }
            declarations += 1;
        }
        for leaf in &spec.leaves {
            openings += leaf.wires.iter().collect::<HashSet<_>>().len();
        }
    }
    require(
        globals.len() == 19288 && declarations == 28504 && openings == 35128,
        "unique/global/local/opening source census differs",
    )?;
    drop(globals);
    let (byte_links, internal_links) = links(reference, &components, cases)?;
    Ok(SourceFacts {
        components,
        source_sha256: source_sha,
        source_maps_sha256: maps_sha,
        manifest: meta,
        source_maps: maps,
        byte_links,
        internal_links,
    })
}

// Saved for the hosted Cargo test stage; no native/Script/graph test was run
// locally while implementing this independent source boundary.
#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Reference {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures");
        reference(
            &root.join("nht4-genesis-0-2020-k5.nht4"),
            &root.join("nht4-genesis-0-2020-k5.expected.json"),
            &root.join("nht4-genesis-0-2020-k5.dimensions.json"),
        )
        .expect("independently pinned completed reference")
    }

    #[test]
    fn eight_constant_bodies_match_completed_m17_recipe() {
        // Independent literal push encodings include minimally encoded 17+.
        // The suffix is the completed M17 one-word equality body, not an
        // observed caller body or a newly selected compiler implementation.
        let values = [0u8, 2, 3, 14, 15, 17, 19, 20];
        let prefixes = ["00", "52", "53", "5e", "5f", "0111", "0113", "0114"];
        let mut digests = HashSet::new();
        for (value, prefix) in values.into_iter().zip(prefixes) {
            let literal = hex::decode(format!("{prefix}517951798700796b7575756c")).unwrap();
            let actual = const_body(value);
            assert_eq!(actual, literal);
            assert_eq!(sha(&actual), sha(&literal));
            assert!(digests.insert(sha(&actual)));
        }
        assert_ne!(sha(&[0x75, 0x51]), *digests.iter().next().unwrap());
    }

    #[test]
    fn scalar_template_covers_all256_bits_and_exact_private_links() {
        let (bounds, template) = encoding_template().unwrap();
        assert_eq!(bounds.len(), 55);
        assert_eq!(template.len(), 16);
        assert_eq!(&bounds[..9], &[BASE; 9]);
        assert_eq!(&bounds[9..41], &[256; 32]);
        let mut covered = Vec::new();
        for (limb, leaf) in template[7..].iter().enumerate() {
            assert_eq!(leaf.kind, "conv_reconstruct");
            assert_eq!(leaf.wires[0], limb);
            assert_eq!(
                leaf.args.iter().sum::<i64>(),
                if limb == 8 { 24 } else { 29 }
            );
            let mut bit = 29 * limb;
            for width in &leaf.args {
                for next in bit..bit + *width as usize {
                    covered.push(next);
                }
                bit += *width as usize;
            }
        }
        assert_eq!(covered, (0..256).collect::<Vec<_>>());
        let occurrences = byte_occurrences(&template).unwrap();
        assert_eq!(occurrences.len(), 32);
        for (byte, (ordinal, formal)) in occurrences.into_iter().enumerate() {
            assert_eq!(template[ordinal].wires[formal], 9 + byte);
        }
        for part in 0..14 {
            let word = 41 + part;
            assert_eq!(template[part / 2].wires[1 + part % 2], word);
            assert_eq!(
                template[7..]
                    .iter()
                    .flat_map(|l| &l.wires)
                    .filter(|w| **w == word)
                    .count(),
                1
            );
        }
        // 69 encoding openings plus the 9 canonical-field openings.
        assert_eq!(
            template.iter().map(|l| l.wires.len()).sum::<usize>() + 9,
            78
        );
    }

    #[test]
    fn pinned_reference_has_exact_retained_max_partition_and_widths() {
        let reference = fixture();
        assert_eq!(reference.payload.len(), 12664);
        assert_eq!(reference.layout.len(), 485);
        assert_eq!(
            reference
                .layout
                .iter()
                .filter(|s| s.kind == "length" && s.minimum == s.maximum)
                .count(),
            18
        );
        assert_eq!(
            reference
                .layout
                .iter()
                .filter(|s| s.kind == "length" && s.minimum != s.maximum)
                .count(),
            101
        );
        assert!(reference
            .layout
            .windows(2)
            .all(|w| w[0].start + w[0].size == w[1].start));
        assert_eq!(
            reference.layout.last().unwrap().start + reference.layout.last().unwrap().size,
            PAYLOAD
        );
        assert_eq!(
            find_span(&reference, "snark_primary.eval_W").unwrap().start,
            4624
        );
        assert_eq!(
            find_span(&reference, "snark_secondary.eval_W")
                .unwrap()
                .start,
            10048
        );
        let constants = anchors(&reference).unwrap();
        assert_eq!(constants.iter().filter(|a| a.kind == "length").count(), 952);
        assert_eq!(
            constants.iter().filter(|a| a.kind == "zn-width").count(),
            431
        );
        assert_eq!(
            constants
                .iter()
                .map(|a| a.expected)
                .collect::<BTreeSet<_>>(),
            [0, 2, 3, 14, 15, 17, 19, 20].into_iter().collect()
        );
        assert_eq!(
            reference.summary["reference_hash_authenticates_claimed_payload"],
            false
        );
        assert_eq!(reference.summary["proof_verified"], false);
    }

    #[test]
    fn every_reference_prefix_and_eof_is_checked_before_claim_processing() {
        let reference = fixture();
        for prefix in reference.layout.iter().filter(|s| s.kind == "length") {
            let mut raw = reference.payload.clone();
            raw[prefix.start..prefix.start + 8].fill(255);
            assert!(layout(&raw).is_err(), "{}", prefix.path);
        }
        assert!(layout(&reference.payload[..PAYLOAD - 1]).is_err());
        let mut extra = reference.payload.clone();
        extra.push(0);
        assert!(layout(&extra).is_err());
        extra.insert(0, 0);
        assert!(layout(&extra).is_err());
    }

    #[test]
    fn raw_noncanonical_and_opaque_recipes_are_not_normalized_or_decoded() {
        let reference = fixture();
        let primary = find_span(&reference, "snark_primary.eval_W").unwrap().start;
        for (profile, index, engine, increment) in [
            ("p-mod", 1, "pallas", 0u32),
            ("p-mod1", 1, "pallas", 1),
            ("v-mod", 2, "vesta", 0),
            ("v-mod1", 2, "vesta", 1),
        ] {
            let (payload, changed) = profile_values(&reference, profile).unwrap();
            let wanted = modulus(engine).unwrap() + BigUint::from(increment);
            let row = scalar_spans(&reference, index)
                .unwrap()
                .iter()
                .position(|s| s.start == changed[0])
                .unwrap();
            let values = raw_component(&reference, index, &payload).unwrap();
            let represented = values[55 * row..55 * row + 9]
                .iter()
                .enumerate()
                .fold(BigUint::from(0u32), |a, (i, v)| {
                    a + (BigUint::from(*v) << (29 * i))
                });
            assert_eq!(represented, wanted);
            assert!(represented >= modulus(engine).unwrap());
        }
        for profile in ["opaque-p", "opaque-v"] {
            let (payload, changed) = profile_values(&reference, profile).unwrap();
            assert_eq!(changed.len(), 32);
            assert!(changed.iter().all(|i| payload[*i] == 255));
            assert_eq!(
                raw_component(&reference, 1, &payload).unwrap(),
                raw_component(
                    &reference,
                    1,
                    &reference
                        .payload
                        .iter()
                        .map(|b| u32::from(*b))
                        .collect::<Vec<_>>()
                )
                .unwrap()
            );
            assert_eq!(
                raw_component(&reference, 2, &payload).unwrap(),
                raw_component(
                    &reference,
                    2,
                    &reference
                        .payload
                        .iter()
                        .map(|b| u32::from(*b))
                        .collect::<Vec<_>>()
                )
                .unwrap()
            );
        }
        for (profile, value) in [("byte-256", 256), ("byte-max", u32::MAX)] {
            let (payload, changed) = profile_values(&reference, profile).unwrap();
            assert_eq!(changed, [primary]);
            assert_eq!(payload[primary], value);
            let spans = scalar_spans(&reference, 1).unwrap();
            let scalar = spans.iter().position(|s| s.start == primary).unwrap();
            let assigned = raw_component(&reference, 1, &payload).unwrap();
            assert_eq!(assigned[55 * scalar + 9], value);
            let (limbs, pieces) =
                encoding_values(&reference.payload[primary..primary + 32]).unwrap();
            assert_eq!(assigned[55 * scalar..55 * scalar + 9], limbs);
            assert_eq!(assigned[55 * scalar + 41..55 * scalar + 55], pieces);
        }
    }

    #[test]
    fn target_cap_is_total_and_never_drops_any_failure() {
        let reference = fixture();
        let truth = [
            vec![Some(true); 12664],
            vec![Some(true); 2873],
            vec![Some(true); 2023],
        ];
        let selected = selection(&reference, "opaque-p", &truth, &[]).unwrap();
        assert_eq!(selected.iter().map(Vec::len).sum::<usize>(), 43);
        let mut many = truth;
        many[0][2000..2129].fill(Some(false));
        assert!(selection(&reference, "opaque-p", &many, &[]).is_err());
        assert_eq!(PROFILES.len(), 14);
        assert!(FALSE_FLAGS.contains(&"public_state_to_zn_script_bound"));
    }
}
