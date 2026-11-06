//! Independent retained-reference admission and the112-BYTE local tape.
//! Reference hashes authenticate the fixed native reference, never the values
//! asserted by WOTS. No setup, proving, proof verification or generic bincode
//! deserialization occurs here. Every vector count precedes its bounded loop.
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
    pasta::{Fp, Fq, PallasAffine, VestaAffine},
};
use serde_json::{json, Map, Value};
use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::Read,
    path::Path,
};

pub const POLICY_SHA256: &str = "cdfa31622881cc1863abd1eb252c136184501785b4b02e9985e6ba0850b2ac54";
pub const DIMENSIONS_SHA256: &str =
    "de6333df2e41b5f5bae1c103fab862f8d6022fd54abeb80ba61920bc9f360edc";
pub const VK_SHA256: &str = "1ae88a7bcfdc5f14d030d0baafa06ec17fe904a5ebed42f9bd6fa6105fdc8c24";
pub const PROOF_SHA256: &str = "2137c6e8621cedb7423e0ef7f9ff7c27b2c6fdf3ceb227e644b3d9660d056617";
pub const BUNDLE_SHA256: &str = "c3143d5627ef7291ab6a858b866a4ba19e356a168dea992d3e572ef6531904e9";
const REVISION: &str = "de607d3db17d400dd6c2923d357f1d4a7bf233c7";
const CRATE_SHA256: &str = "c9bb3809a6c70057ea722c1c4fe5097cf29a3479d0b4671f3cddb1d81043bb31";
const HEADER: usize = 556;
pub const BLOCK_BYTES: usize = 112;
const PROOF_BYTES: usize = 12664;
const BUNDLE_BYTES: usize = HEADER + PROOF_BYTES;
const SOURCE_DOMAIN: &[u8] = b"BITVM2-NOVA/RETAINED-SCALAR-BLOCK/v1\0";
const FALSE_FLAGS: [&str; 14] = [
    "proof_byte_origins_bound",
    "whole_container_script_bound",
    "proof_length_script_bound",
    "proof_eof_script_bound",
    "proof_sha256_script_bound",
    "bundle_sha256_script_bound",
    "scalar_canonicality_script_bound",
    "transcript_verified",
    "proof_verified",
    "bitvm2_script_verified",
    "complete_nova_verifier",
    "complete_bitvm2_verifier",
    "production_assertion_binding",
    "bitcoin_transaction_graph",
];

pub fn canonical(value: &Value) -> Result<Vec<u8>> {
    fn ordered(value: &Value, depth: usize) -> Result<Value> {
        if depth > 24 {
            return Err("retained scalar metadata depth".into());
        }
        Ok(match value {
            Value::Object(items) => {
                let mut result = Map::new();
                let mut keys: Vec<_> = items.keys().collect();
                keys.sort_unstable();
                for key in keys {
                    if !key.is_ascii() {
                        return Err("metadata ASCII keys required".into());
                    }
                    result.insert(key.clone(), ordered(&items[key], depth + 1)?);
                }
                Value::Object(result)
            }
            Value::Array(items) => Value::Array(
                items
                    .iter()
                    .map(|v| ordered(v, depth + 1))
                    .collect::<Result<_>>()?,
            ),
            Value::String(s) if !s.is_ascii() => {
                return Err("metadata ASCII string required".into())
            }
            Value::Number(n) if n.as_i64().is_none() && n.as_u64().is_none() => {
                return Err("metadata integer required".into())
            }
            _ => value.clone(),
        })
    }
    Ok(serde_json::to_vec(&ordered(value, 0)?)?)
}
fn sha(bytes: &[u8]) -> String {
    hex::encode(sha256::Hash::hash(bytes))
}
fn json_sha(value: &Value) -> Result<String> {
    Ok(sha(&canonical(value)?))
}
fn require(yes: bool, error: &str) -> Result<()> {
    if yes {
        Ok(())
    } else {
        Err(error.into())
    }
}
fn role_parameters(role: &str) -> Result<(&'static str, &'static str, usize, usize, u64)> {
    match role {
        "pallas_scalar" => Ok(("primary", "pallas", 19, 4624, 59)),
        "vesta_scalar" => Ok(("secondary", "vesta", 14, 10048, 44)),
        _ => Err("retained scalar source needs the exact Pasta scalar role".into()),
    }
}
fn modulus(role: &str) -> Result<&'static str> {
    match role {
        "pallas_scalar" => {
            Ok("28948022309329048855892746252171976963363056481941647379679742748393362948097")
        }
        "vesta_scalar" => {
            Ok("28948022309329048855892746252171976963363056481941560715954676764349967630337")
        }
        _ => Err("unknown scalar role".into()),
    }
}
fn identifier(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 192
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.:/-".contains(&b))
}

#[derive(Clone)]
pub struct Reference {
    pub raw_span: [u8; BLOCK_BYTES],
    pub eval_w: [u8; 32],
    pub c0: [u8; 32],
    pub c2: [u8; 32],
    pub role: String,
    pub engine: String,
    pub proof_offset: usize,
    pub bundle_offset: usize,
    pub proof_bytes: usize,
    pub bundle_bytes: usize,
    pub proof_sha256: String,
    pub bundle_sha256: String,
    pub dimensions_sha256: String,
    pub verifier_key_sha256: String,
    pub expected_policy_sha256: String,
    pub spans: Value,
}
impl Reference {
    pub fn expected_assignment(&self) -> Vec<u32> {
        self.raw_span.iter().map(|b| u32::from(*b)).collect()
    }
    pub fn summary(&self) -> Value {
        json!({"reference_admitted":true,"field_role":self.role,"engine":self.engine,
            "proof_relative_start":self.proof_offset,"container_relative_start":self.bundle_offset,
            "proof_bytes":self.proof_bytes,"bundle_bytes":self.bundle_bytes,
            "proof_sha256":self.proof_sha256,"bundle_sha256":self.bundle_sha256,
            "verifier_dimensions_sha256":self.dimensions_sha256,"verifier_key_sha256":self.verifier_key_sha256,
            "expected_policy_sha256":self.expected_policy_sha256,"reference_block_sha256":sha(&self.raw_span),
            "reference_hash_authenticates_asserted_values":false,"proof_verified":false})
    }
}

#[derive(Clone)]
struct Span {
    path: String,
    kind: &'static str,
    start: usize,
    size: usize,
    engine: Option<&'static str>,
}
impl Span {
    fn json(&self) -> Value {
        json!({"path":self.path,"kind":self.kind,"start":self.start,"size":self.size,"engine":self.engine})
    }
}
struct Cursor<'a> {
    raw: &'a [u8],
    at: usize,
    spans: Vec<Span>,
}
fn scalar<F: PrimeField>(bytes: &[u8]) -> Result<()> {
    let mut repr = F::Repr::default();
    require(
        bytes.len() == 32 && repr.as_ref().len() == 32,
        "fixed scalar encoding width",
    )?;
    repr.as_mut().copy_from_slice(bytes);
    let value = Option::<F>::from(F::from_repr(repr)).ok_or("noncanonical scalar")?;
    require(
        value.to_repr().as_ref() == bytes,
        "scalar canonical roundtrip",
    )
}
fn point<G: GroupEncoding>(bytes: &[u8]) -> Result<()> {
    let mut repr = G::Repr::default();
    require(
        bytes.len() == 32 && repr.as_ref().len() == 32,
        "fixed point encoding width",
    )?;
    repr.as_mut().copy_from_slice(bytes);
    let value =
        Option::<G>::from(G::from_bytes(&repr)).ok_or("noncanonical/off-curve compressed point")?;
    // In particular upstream from_bytes accepts x=0/sign=1 as identity;
    // to_bytes comparison rejects that alias while preserving canonical zero.
    require(
        value.to_bytes().as_ref() == bytes,
        "compressed point canonical roundtrip",
    )
}
impl<'a> Cursor<'a> {
    fn take(
        &mut self,
        path: &str,
        kind: &'static str,
        n: usize,
        engine: Option<&'static str>,
    ) -> Result<&'a [u8]> {
        let end = self.at.checked_add(n).ok_or("cursor overflow")?;
        require(end <= self.raw.len(), "truncated bounded proof")?;
        let start = self.at;
        self.at = end;
        self.spans.push(Span {
            path: path.into(),
            kind,
            start,
            size: n,
            engine,
        });
        Ok(&self.raw[start..end])
    }
    fn length(&mut self, path: &str, low: usize, high: usize, item_size: usize) -> Result<usize> {
        let raw = self.take(path, "length", 8, None)?;
        let count = u64::from_le_bytes(raw.try_into()?);
        require(
            count >= low as u64 && count <= high as u64,
            "untrusted vector count outside trusted dimension",
        )?;
        let count = usize::try_from(count)?;
        let needed = count
            .checked_mul(item_size)
            .ok_or("vector byte multiplication overflow")?;
        require(
            needed <= self.raw.len() - self.at,
            "vector count exceeds remaining bytes",
        )?;
        Ok(count)
    }
    fn scalar(&mut self, path: &str, engine: &'static str) -> Result<()> {
        let bytes = self.take(path, "scalar", 32, Some(engine))?;
        match engine {
            "pallas" => scalar::<Fq>(bytes),
            "vesta" => scalar::<Fp>(bytes),
            _ => Err("scalar engine".into()),
        }
    }
    fn commitment(&mut self, path: &str, engine: &'static str) -> Result<()> {
        let bytes = self.take(&format!("{path}.comm"), "commitment", 32, Some(engine))?;
        match engine {
            "pallas" => point::<PallasAffine>(bytes),
            "vesta" => point::<VestaAffine>(bytes),
            _ => Err("point engine".into()),
        }
    }
    fn scalars(&mut self, path: &str, engine: &'static str, n: usize) -> Result<()> {
        self.length(path, n, n, 32)?;
        for index in 0..n {
            self.scalar(&format!("{path}[{index}]"), engine)?;
        }
        Ok(())
    }
    fn relaxed(&mut self, path: &str, engine: &'static str) -> Result<()> {
        self.commitment(&format!("{path}.comm_W"), engine)?;
        self.commitment(&format!("{path}.comm_E"), engine)?;
        self.scalars(&format!("{path}.X"), engine, 2)?;
        self.scalar(&format!("{path}.u"), engine)
    }
    fn sumcheck(
        &mut self,
        path: &str,
        engine: &'static str,
        rounds: usize,
        degree: usize,
    ) -> Result<()> {
        let rows = format!("{path}.compressed_polys");
        self.length(&rows, rounds, rounds, 40)?;
        for index in 0..rounds {
            let row = format!("{rows}[{index}].coeffs_except_linear_term");
            let n = self.length(&row, 1, degree, 32)?;
            for j in 0..n {
                self.scalar(&format!("{row}[{j}]"), engine)?;
            }
        }
        Ok(())
    }
    fn spartan(
        &mut self,
        path: &str,
        engine: &'static str,
        outer: usize,
        inner: usize,
        batch: usize,
    ) -> Result<()> {
        self.sumcheck(&format!("{path}.sc_proof_outer"), engine, outer, 3)?;
        for j in 0..3 {
            self.scalar(&format!("{path}.claims_outer[{j}]"), engine)?;
        }
        self.scalar(&format!("{path}.eval_E"), engine)?;
        self.sumcheck(&format!("{path}.sc_proof_inner"), engine, inner, 2)?;
        self.scalar(&format!("{path}.eval_W"), engine)?;
        self.sumcheck(&format!("{path}.sc_proof_batch"), engine, batch, 2)?;
        self.scalars(&format!("{path}.evals_batch"), engine, 2)?;
        for side in ["L_vec", "R_vec"] {
            let field = format!("{path}.eval_arg.{side}");
            self.length(&field, batch, batch, 32)?;
            for j in 0..batch {
                self.commitment(&format!("{field}[{j}]"), engine)?;
            }
        }
        self.scalar(&format!("{path}.eval_arg.a_hat"), engine)
    }
}
fn admit_proof(raw: &[u8]) -> Result<Vec<Span>> {
    require(
        !raw.is_empty() && raw.len() <= (1 << 20),
        "bounded inner proof required",
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
    c.spartan("snark_primary", "pallas", 19, 20, 19)?;
    c.spartan("snark_secondary", "vesta", 14, 15, 14)?;
    c.length("zn", 17, 17, 32)?;
    for i in 0..17 {
        let start = c.at;
        c.scalar(&format!("zn[{i}]"), "pallas")?;
        let width = match i {
            1 | 2 => 16,
            3 => 25,
            _ => 4,
        };
        require(
            raw[start + width..start + 32].iter().all(|b| *b == 0),
            "end state declared width",
        )?;
    }
    require(c.at == raw.len(), "surplus inner proof bytes")?;
    Ok(c.spans)
}

/// Only the fixed independent native reference is admitted here. Caller-owned
/// assertion values are accepted separately and are never compared to its hash.
pub fn reference(path: &Path, role: &str) -> Result<Reference> {
    let (owner, engine, rounds, start, _) = role_parameters(role)?;
    let expected_raw = include_bytes!("../../fixtures/nht4-genesis-0-2020-k5.expected.json");
    let dimensions_raw = include_bytes!("../../fixtures/nht4-genesis-0-2020-k5.dimensions.json");
    // The expected JSON may be checked out with LF or CRLF; its independent
    // pin authenticates canonical semantic JSON rather than EOL bytes.
    require(
        sha(dimensions_raw) == DIMENSIONS_SHA256,
        "compiled dimensions raw pin",
    )?;
    let policy: Value = serde_json::from_slice(expected_raw)?;
    let dimensions: Value = serde_json::from_slice(dimensions_raw)?;
    require(
        json_sha(&policy)? == POLICY_SHA256 && json_sha(&dimensions)? == DIMENSIONS_SHA256,
        "compiled canonical policy/dimensions pin",
    )?;
    require(
        policy["network"] == "testnet4"
            && policy["k"] == 5
            && policy["steps"] == 404
            && policy["header_revision"] == REVISION
            && policy["nova_version"] == "0.76.0"
            && policy["verifier_key_sha256"] == VK_SHA256
            && policy["proof_sha256"] == PROOF_SHA256
            && policy["bundle_sha256"] == BUNDLE_SHA256
            && policy["proof_bytes"] == PROOF_BYTES
            && policy["bundle_bytes"] == BUNDLE_BYTES
            && policy["checkpoint_origin"] == "genesis",
        "compiled retained reference identities",
    )?;
    require(
        dimensions["verifier_key_sha256"] == VK_SHA256
            && dimensions["network"] == "testnet4"
            && dimensions["k"] == 5
            && dimensions["header_revision"] == REVISION
            && dimensions["nova_version"] == "0.76.0"
            && dimensions["nova_crate_sha256"] == CRATE_SHA256
            && dimensions["outer_arity"] == 17
            && dimensions["primary"]["outer_rounds"] == 19
            && dimensions["primary"]["inner_rounds"] == 20
            && dimensions["primary"]["ipa_rounds"] == 19
            && dimensions["primary"]["batch_rounds"] == 19
            && dimensions["secondary"]["outer_rounds"] == 14
            && dimensions["secondary"]["inner_rounds"] == 15
            && dimensions["secondary"]["ipa_rounds"] == 14
            && dimensions["secondary"]["batch_rounds"] == 14,
        "compiled trusted shape differs",
    )?;
    let metadata = fs::symlink_metadata(path)?;
    require(
        metadata.file_type().is_file() && metadata.len() == BUNDLE_BYTES as u64,
        "reference must be a regular exact-size retained container",
    )?;
    let mut raw = Vec::with_capacity(BUNDLE_BYTES);
    File::open(path)?
        .take((BUNDLE_BYTES + 1) as u64)
        .read_to_end(&mut raw)?;
    require(
        raw.len() == BUNDLE_BYTES && sha(&raw) == BUNDLE_SHA256,
        "retained whole container pin/EOF",
    )?;
    require(
        &raw[..4] == b"NHT4"
            && u32::from_le_bytes(raw[4..8].try_into()?) == 404
            && u32::from_le_bytes(raw[8..12].try_into()?) == 5,
        "retained network/steps/k framing",
    )?;
    let z0 = policy["initial_state_le"]
        .as_array()
        .ok_or("policy initial state")?;
    require(z0.len() == 17, "initial arity")?;
    for (i, expected) in z0.iter().enumerate() {
        let bytes = &raw[12 + 32 * i..44 + 32 * i];
        scalar::<Fq>(bytes)?;
        let width = match i {
            1 | 2 => 16,
            3 => 25,
            _ => 4,
        };
        require(
            bytes[width..].iter().all(|b| *b == 0)
                && hex::encode(bytes) == expected.as_str().ok_or("state hex")?,
            "retained canonical genesis state/width",
        )?;
    }
    let proof = &raw[HEADER..];
    require(sha(proof) == PROOF_SHA256, "retained proof pin")?;
    let spans = admit_proof(proof)?;
    require(
        spans.len() == 485
            && spans.iter().filter(|s| s.kind == "length").count() == 119
            && spans.iter().filter(|s| s.kind == "scalar").count() == 288
            && spans.iter().filter(|s| s.kind == "commitment").count() == 78,
        "retained span census",
    )?;
    let root = format!("snark_{owner}");
    let vector = format!("{root}.sc_proof_batch.compressed_polys");
    let row = format!("{vector}[0].coeffs_except_linear_term");
    let paths = [
        format!("{root}.eval_W"),
        vector,
        row.clone(),
        format!("{row}[0]"),
        format!("{row}[1]"),
    ];
    let mut selected = Vec::new();
    for ((path, offset), size) in paths
        .iter()
        .zip([0, 32, 40, 48, 80])
        .zip([32, 8, 8, 32, 32])
    {
        let span = spans
            .iter()
            .find(|s| &s.path == path)
            .ok_or("retained scalar path missing")?;
        require(
            span.start == start + offset
                && span.size == size
                && span.kind == if size == 8 { "length" } else { "scalar" }
                && span.engine == if size == 8 { None } else { Some(engine) },
            "exact contiguous retained scalar path",
        )?;
        selected.push(span.json());
    }
    let block: [u8; BLOCK_BYTES] = proof[start..start + BLOCK_BYTES].try_into()?;
    require(
        u64::from_le_bytes(block[32..40].try_into()?) == rounds as u64
            && u64::from_le_bytes(block[40..48].try_into()?) == 2,
        "retained batch count/quadratic width",
    )?;
    Ok(Reference {
        raw_span: block,
        eval_w: block[..32].try_into()?,
        c0: block[48..80].try_into()?,
        c2: block[80..].try_into()?,
        role: role.into(),
        engine: engine.into(),
        proof_offset: start,
        bundle_offset: HEADER + start,
        proof_bytes: PROOF_BYTES,
        bundle_bytes: BUNDLE_BYTES,
        proof_sha256: PROOF_SHA256.into(),
        bundle_sha256: BUNDLE_SHA256.into(),
        dimensions_sha256: DIMENSIONS_SHA256.into(),
        verifier_key_sha256: VK_SHA256.into(),
        expected_policy_sha256: POLICY_SHA256.into(),
        spans: Value::Array(selected),
    })
}

pub struct CheckedTape {
    pub source_maps: Value,
    pub metadata: Value,
    pub source_sha256: String,
    pub source_maps_sha256: String,
    pub program_sha256: String,
    pub catalogue_id: String,
    pub byte_indices: Vec<usize>,
    pub byte_occurrences: Vec<(usize, usize)>,
    pub prefix_ordinals: Vec<usize>,
    pub eval_w_indices: Vec<usize>,
    pub coefficient_indices: [Vec<usize>; 2],
}
fn const_body(value: u8) -> Vec<u8> {
    let mut body = Builder::new()
        .push_int(i64::from(value))
        .into_script()
        .into_bytes();
    body.extend([
        0x51, 0x79, 0x51, 0x79, 0x87, 0x00, 0x79, 0x6b, 0x75, 0x75, 0x75, 0x6c,
    ]);
    body
}
pub fn check(
    spec: &GraphSpec,
    context: &str,
    role: &str,
    counter: u64,
    operation_id: &str,
    raw_maps: &Value,
    r: &Reference,
) -> Result<CheckedTape> {
    let (_, _, rounds, start, fixed_counter) = role_parameters(role)?;
    require(
        counter == fixed_counter
            && identifier(operation_id)
            && hex::encode(id32(context)?) == context
            && spec.context == context
            && spec.field_role == role
            && spec.operation_id == operation_id
            && spec.words.len() == 112
            && spec.leaves.len() == 112
            && r.role == role
            && r.proof_offset == start,
        "tape exact parameters/census/reference required",
    )?;
    for (i, word) in spec.words.iter().enumerate() {
        require(
            word.name == format!("block/byte/{i}") && word.bound == 256,
            "tape exact BYTE word order/bounds",
        )?;
    }
    let catalogue = hex::encode(spec.identity()?);
    let mut prefix = (rounds as u64).to_le_bytes().to_vec();
    prefix.extend(2u64.to_le_bytes());
    let mut bodies = BTreeMap::new();
    let mut constraints = Vec::new();
    let mut occurrences = vec![(0, 0); 112];
    let mut anchors = Vec::new();
    for (ordinal, leaf) in spec.leaves.iter().enumerate() {
        let (wire, kind, args, body) = if ordinal < 16 {
            (
                32 + ordinal,
                "const",
                vec![i64::from(prefix[ordinal])],
                const_body(prefix[ordinal]),
            )
        } else {
            (
                if ordinal < 48 { ordinal - 16 } else { ordinal },
                "word_valid",
                Vec::new(),
                vec![0x75, 0x51],
            )
        };
        let body_sha = sha(&body);
        require(
            leaf.kind == kind
                && leaf.argument == args
                && leaf.wires == [wire]
                && leaf.body_sha256 == body_sha,
            "tape exact const/validity schedule or actual body changed",
        )?;
        bodies.insert(body_sha, hex::encode(body));
        occurrences[wire] = (ordinal, 0);
        if ordinal < 16 {
            constraints.push(json!(["const", [format!("block/byte/{wire}")], args]));
            anchors.push(json!({"block_index":wire,"word_index":wire,"expected":prefix[ordinal],"ordinal":ordinal,"formal":0}));
        }
    }
    require(spec.bodies == bodies, "tape exact small body catalogue")?;
    let plain = json_sha(
        &json!({"schema":"bitvm2-nova-fixed-trace/v2","field_role":role,"modulus":modulus(role)?,
        "operation_id":operation_id,"context":context,"words":spec.words.iter().map(|w|json!([w.name,w.bound])).collect::<Vec<_>>(),
        "fields":[],"constraints":constraints}),
    )?;
    let mut program_hash = sha256::Hash::engine();
    program_hash.input(b"BITVM2-NOVA/BYTE-TRACE/v1\0");
    program_hash.input(&hex::decode(plain)?);
    let program = hex::encode(sha256::Hash::from_engine(program_hash));
    require(
        spec.program_sha256 == program,
        "versioned BYTE program identity differs",
    )?;
    let words: Vec<_> = (0..112).map(|i| format!("block/byte/{i}")).collect();
    let ports = json!({"block_bytes":words,"eval_w":words[..32],"row_count":words[32..40],"row_width":words[40..48],
        "coefficient_bytes":[&words[48..80],&words[80..112]]});
    let maps = json!({"schema":"bitvm2-nova-retained-scalar-block-maps/v1","proof_relative_start":start,
        "container_relative_start":HEADER+start,"block_indices":(0..112).collect::<Vec<_>>(),
        "source_byte_offsets":(0..112).map(|i|HEADER+start+i).collect::<Vec<_>>(),"byte_occurrences":occurrences,
        "prefix_anchors":anchors,"eval_w_indices":(0..32).collect::<Vec<_>>(),"row_count_indices":(32..40).collect::<Vec<_>>(),
        "row_width_indices":(40..48).collect::<Vec<_>>(),"coefficient_byte_indices":[(48..80).collect::<Vec<_>>(),(80..112).collect::<Vec<_>>()],
        "spans":r.spans,"ports":ports});
    require(
        raw_maps == &maps,
        "tape raw source maps differ from independent actual coordinates",
    )?;
    let maps_sha = json_sha(&maps)?;
    let mut metadata = json!({"schema":"bitvm2-nova-retained-scalar-block/v1","context":context,"field_role":role,
        "operation_id":operation_id,"program_sha256":program,"catalogue_id":catalogue,"source_maps_sha256":maps_sha,
        "expected_policy_sha256":POLICY_SHA256,"verifier_dimensions_sha256":DIMENSIONS_SHA256,"verifier_key_sha256":VK_SHA256,
        "header_revision":REVISION,"nova_version":"0.76.0","network":"testnet4","k":5,"steps":404,
        "proof_bytes":PROOF_BYTES,"proof_sha256":PROOF_SHA256,"bundle_bytes":BUNDLE_BYTES,"bundle_sha256":BUNDLE_SHA256});
    metadata.as_object_mut().ok_or("metadata object")?.extend(json!({
        "proof_relative_start":start,"container_relative_start":HEADER+start,"block_bytes":112,"row_count":rounds,"row_width":2,
        "reference_block_sha256":sha(&r.raw_span),"reference_inputs":{"eval_w":hex::encode(r.eval_w),"coefficients":[hex::encode(r.c0),hex::encode(r.c2)]},
        "source_authority":false,"scope":"retained reference admission and local asserted BYTE/length-prefix relations; whole-proof and production origins remain unbound"})
        .as_object().ok_or("metadata continuation")?.clone());
    for flag in FALSE_FLAGS {
        metadata
            .as_object_mut()
            .ok_or("metadata object")?
            .insert(flag.into(), json!(false));
    }
    let mut source = sha256::Hash::engine();
    source.input(SOURCE_DOMAIN);
    source.input(&canonical(&metadata)?);
    Ok(CheckedTape {
        source_maps: maps,
        metadata,
        source_sha256: hex::encode(sha256::Hash::from_engine(source)),
        source_maps_sha256: maps_sha,
        program_sha256: program,
        catalogue_id: catalogue,
        byte_indices: (0..112).collect(),
        byte_occurrences: occurrences,
        prefix_ordinals: (0..16).collect(),
        eval_w_indices: (0..32).collect(),
        coefficient_indices: [(48..80).collect(), (80..112).collect()],
    })
}

/// Exact signed-u32 values are intentionally preserved for authenticated
/// out-of-bound BYTE probes. This never authenticates their proof origin.
pub fn expected_assignment(asserted: &[u32; 112]) -> Vec<u32> {
    asserted.to_vec()
}
pub fn truth(spec: &GraphSpec, values: &[u32], ordinal: usize) -> Result<bool> {
    require(
        spec.words.len() == 112 && spec.leaves.len() == 112 && values.len() == 112 && ordinal < 112,
        "tape truth census",
    )?;
    let wire = if ordinal < 16 {
        32 + ordinal
    } else if ordinal < 48 {
        ordinal - 16
    } else {
        ordinal
    };
    let leaf = &spec.leaves[ordinal];
    require(
        leaf.wires == [wire] && spec.words[wire].bound == 256,
        "tape truth actual occurrence",
    )?;
    if values[wire] >= 256 {
        return Ok(false);
    }
    if ordinal < 16 {
        let (_, _, rounds, _, _) = role_parameters(&spec.field_role)?;
        let mut prefix = (rounds as u64).to_le_bytes().to_vec();
        prefix.extend(2u64.to_le_bytes());
        require(
            leaf.kind == "const" && leaf.argument == [i64::from(prefix[ordinal])],
            "tape truth constant",
        )?;
        Ok(values[wire] == u32::from(prefix[ordinal]))
    } else {
        require(
            leaf.kind == "word_valid" && leaf.argument.is_empty(),
            "tape truth validity",
        )?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn length_bombs_and_truncation_fail_before_any_atom_or_loop() {
        for count in [0, u64::MAX, 1u64 << 32] {
            let raw = count.to_le_bytes();
            let mut c = Cursor {
                raw: &raw,
                at: 0,
                spans: Vec::new(),
            };
            assert!(c.length("test", 2, 2, 32).is_err());
            assert_eq!(c.spans.len(), 1);
        }
        for n in 0..8 {
            let raw = [0u8; 8];
            let mut c = Cursor {
                raw: &raw[..n],
                at: 0,
                spans: Vec::new(),
            };
            assert!(c.length("test", 2, 2, 32).is_err());
        }
    }
    #[test]
    fn scalar_and_point_canonical_atoms_preserve_identity_and_reject_aliases() {
        assert!(scalar::<Fq>(&[0; 32]).is_ok());
        assert!(scalar::<Fp>(&[0; 32]).is_ok());
        assert!(scalar::<Fq>(&[255; 32]).is_err());
        assert!(scalar::<Fp>(&[255; 32]).is_err());
        assert!(point::<PallasAffine>(&[0; 32]).is_ok());
        assert!(point::<VestaAffine>(&[0; 32]).is_ok());
        let mut alias = [0u8; 32];
        alias[31] = 128;
        assert!(point::<PallasAffine>(&alias).is_err());
        assert!(point::<VestaAffine>(&alias).is_err());
    }
    #[test]
    fn assertion_values_are_not_pinned_reference_values() {
        let mut values = [0u32; 112];
        values[0] = 256;
        values[111] = u32::MAX;
        assert_eq!(expected_assignment(&values), values.to_vec());
        assert_ne!(const_body(0), const_body(2));
        assert_eq!(const_body(19)[0..2], [1, 19]);
    }
}
