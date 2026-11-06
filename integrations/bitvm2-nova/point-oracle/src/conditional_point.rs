//! Independent closed topology and integer oracle for E=A+P; R=A+bP.
//!
//! This module neither signs nor executes Script. A false integer predicate is
//! distinct from an out-of-domain bare-Script abort. Mature Halo2 parsing checks
//! all four points, including P when b=0, without reducing a noncanonical value.
use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitvm2_nova_script_oracle::{
    registry::GraphSpec,
    wots::{id32, Result},
};
use ff::PrimeField;
use halo2curves::{
    group::Curve,
    pasta::{PallasAffine, VestaAffine},
    CurveAffine,
};
use num_bigint::BigUint;
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;

const BASE: u32 = 1 << 29;
const WORDS: usize = 7498;
const ARITHMETIC: usize = 6124;
const LEAVES: usize = 6161;
const CHILD_WORDS: usize = 7476;
const CHILD_ARITHMETIC: usize = 6116;
const DOMAIN: &[u8] = b"BITVM2-NOVA/CONDITIONAL-POINT/v1\0";
const BIT_OCCURRENCES: [(usize, usize); 5] =
    [(6117, 0), (6119, 0), (6120, 0), (6121, 0), (6122, 0)];
const SELECTORS: [(&str, usize); 8] = [
    ("infinity_delta", 6116),
    ("infinity_masked", 6117),
    ("infinity_result", 6118),
    ("x_from_A", 6119),
    ("y_from_A", 6120),
    ("x_from_E", 6121),
    ("y_from_E", 6122),
    ("point_form", 6123),
];

#[derive(Clone)]
pub struct PointPorts {
    pub infinity: usize,
    pub x: [usize; 9],
    pub y: [usize; 9],
}

pub struct CheckedPoint {
    pub bit_index: usize,
    pub source_maps: Value,
    pub metadata: Value,
    pub source_sha256: String,
    pub source_maps_sha256: String,
    pub program_sha256: String,
    pub catalogue_id: String,
    pub child_program_sha256: String,
    pub child_catalogue_id: String,
    pub child_word_map: Vec<usize>,
    pub child_leaf_map: Vec<usize>,
    pub a: PointPorts,
    pub p: PointPorts,
    pub e: PointPorts,
    pub r: PointPorts,
    pub bit: usize,
    pub delta: usize,
    pub masked: usize,
    pub bit_occurrences: Vec<(usize, usize)>,
    pub r_field_guards: [usize; 2],
    pub fields: Vec<(String, Vec<usize>)>,
}

#[derive(Clone, Copy)]
pub struct CurveVerdict {
    pub a_valid: bool,
    pub p_valid: bool,
    pub e_valid: bool,
    pub r_valid: bool,
    pub bit_valid: bool,
    pub addition_holds: bool,
    pub selection_holds: bool,
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 192
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.:/-".contains(&b))
}

fn modulus_text(role: &str) -> Result<&'static str> {
    match role {
        "pallas_base" => {
            Ok("28948022309329048855892746252171976963363056481941560715954676764349967630337")
        }
        "vesta_base" => {
            Ok("28948022309329048855892746252171976963363056481941647379679742748393362948097")
        }
        _ => Err("conditional point requires the exact Pasta base role".into()),
    }
}

fn modulus(role: &str) -> Result<BigUint> {
    BigUint::parse_bytes(modulus_text(role)?.as_bytes(), 10)
        .ok_or_else(|| "fixed Pasta modulus".into())
}

fn canonical(value: &Value) -> Result<Vec<u8>> {
    fn ordered(value: &Value, depth: usize) -> Result<Value> {
        if depth > 16 {
            return Err("conditional point metadata depth".into());
        }
        Ok(match value {
            Value::Object(object) => {
                let mut keys: Vec<_> = object.keys().collect();
                keys.sort_unstable();
                let mut result = Map::new();
                for key in keys {
                    if !key.is_ascii() {
                        return Err("conditional point ASCII key".into());
                    }
                    result.insert(
                        key.clone(),
                        ordered(object.get(key).ok_or("metadata key")?, depth + 1)?,
                    );
                }
                Value::Object(result)
            }
            Value::Array(values) => Value::Array(
                values
                    .iter()
                    .map(|v| ordered(v, depth + 1))
                    .collect::<Result<_>>()?,
            ),
            Value::String(text) if !text.is_ascii() => {
                return Err("conditional point ASCII string".into())
            }
            Value::Number(n) if n.as_i64().is_none() && n.as_u64().is_none() => {
                return Err("conditional point integer metadata".into())
            }
            _ => value.clone(),
        })
    }
    Ok(serde_json::to_vec(&ordered(value, 0)?)?)
}

fn hash(value: &Value) -> Result<String> {
    Ok(hex::encode(sha256::Hash::hash(&canonical(value)?)))
}

fn names(spec: &GraphSpec, indices: &[usize]) -> Result<Vec<String>> {
    indices
        .iter()
        .map(|index| {
            spec.words
                .get(*index)
                .map(|word| word.name.clone())
                .ok_or_else(|| "conditional point word index".into())
        })
        .collect()
}

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

/// This cursor derives the declaration/gate schedule from public curve rules,
/// never from a claimed word map or a success receipt. Field-byte caching is by
/// exact limb identities, preserving squaring aliases and all crossing splits.
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
            .ok_or("conditional point words truncated")?;
        if actual.name != name || actual.bound != bound {
            return Err(
                format!("conditional point declaration {index} differs: {name}/{bound}").into(),
            );
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
            .ok_or("conditional point predicates truncated")?;
        if actual.kind != kind || actual.wires != wires || actual.argument != argument {
            return Err(format!("conditional point predicate {ordinal} differs: {kind}").into());
        }
        // The table is compiled into this verifier from the frozen legacy
        // compiler. Neither the case file nor its first observed body chooses
        // which bytes a closed predicate shape is allowed to contain.
        crate::body_pins::check(
            &self.spec.field_role,
            kind,
            argument,
            wires,
            &actual.body_sha256,
        )?;
        // expansion_script consumes distinct openings and replays every formal
        // alias. Its bytes depend on first-occurrence alias indices, never on
        // the global numeric word IDs themselves.
        let shape = (kind.to_string(), argument.to_vec(), aliases(wires));
        if let Some(body) = self.bodies.get(&shape) {
            if *body != actual.body_sha256 {
                return Err("same closed predicate shape changed body".into());
            }
        } else {
            self.bodies.insert(shape, actual.body_sha256.clone());
        }
        self.leaf += 1;
        Ok(ordinal)
    }

    fn field(&mut self, name: &str) -> Result<Vec<usize>> {
        if self.fields.iter().any(|(old, _)| old == name) {
            return Err("duplicate cursor field".into());
        }
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

    fn sub(&mut self, name: &str, x: &[usize], y: &[usize]) -> Result<Vec<usize>> {
        let result = self.field(name)?;
        self.gate("add", &concat(&[y, &result, x]), &[])?;
        Ok(result)
    }

    fn bytes(&mut self, name: &str, field: &[usize]) -> Result<Vec<usize>> {
        if let Some(result) = self.byte_fields.get(field) {
            return Ok(result.clone());
        }
        if field.len() != 9 || !self.fields.iter().any(|(_, words)| words == field) {
            return Err("cursor BYTE adapter requires a declared exact field".into());
        }
        let digits = (0..32)
            .map(|i| self.word(format!("{name}/byte/{i}"), 256))
            .collect::<Result<Vec<_>>>()?;
        let mut crossings = BTreeMap::new();
        for boundary in [29usize, 58, 87, 116, 145, 174, 203] {
            let (index, low) = (boundary / 8, boundary % 8);
            let lo = self.word(format!("{name}/split/{index}/lo"), 1u32 << low)?;
            let hi = self.word(format!("{name}/split/{index}/hi"), 1u32 << (8 - low))?;
            self.gate(
                "conv_split",
                &[digits[index], lo, hi],
                &[i64::try_from(low)?],
            )?;
            crossings.insert(index, (low, lo, hi));
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
                    let (_, lo, hi) = crossings
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
        self.byte_fields.insert(field.to_vec(), digits.clone());
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
}

fn point_schedule(
    cursor: &mut Cursor<'_>,
) -> Result<(
    PointPorts,
    PointPorts,
    PointPorts,
    PointPorts,
    usize,
    usize,
    usize,
)> {
    cursor.constant("constant/zero", 0)?;
    let five = cursor.constant("constant/five", 5)?;
    let zero_flag = cursor.small_constant("constant/false", 0, 2)?;
    let one_flag = cursor.small_constant("constant/true", 1, 2)?;
    let mut points = Vec::new();
    for name in ["left", "right", "result"] {
        let infinity = cursor.word(format!("{name}/infinity"), 2)?;
        let x = cursor.field(&format!("{name}/x"))?;
        let y = cursor.field(&format!("{name}/y"))?;
        cursor.gate("point_form", &concat(&[&[infinity], &x, &y]), &[])?;
        let xx = cursor.mul(&format!("{name}/x2"), &x, &x)?;
        let xxx = cursor.mul(&format!("{name}/x3"), &xx, &x)?;
        let yy = cursor.mul(&format!("{name}/y2"), &y, &y)?;
        let rhs = cursor.add(&format!("{name}/curve-rhs"), &xxx, &five)?;
        cursor.gate("gate_equal", &concat(&[&[infinity], &yy, &rhs]), &[0])?;
        points.push((
            PointPorts {
                infinity,
                x: x.try_into().map_err(|_| "point x width")?,
                y: y.try_into().map_err(|_| "point y width")?,
            },
            xx,
        ));
    }
    let a = points[0].0.clone();
    let p = points[1].0.clone();
    let e = points[2].0.clone();
    let sy = cursor.add("sum-y", &a.y, &p.y)?;
    let selector = cursor.word("dispatch".to_string(), 5)?;
    cursor.gate(
        "dispatch",
        &concat(&[
            &[a.infinity, p.infinity],
            &a.x,
            &a.y,
            &p.x,
            &p.y,
            &sy,
            &[selector],
        ]),
        &[],
    )?;
    let dx = cursor.sub("dx", &p.x, &a.x)?;
    let dy = cursor.sub("dy", &p.y, &a.y)?;
    let twice_y = cursor.add("twice-y", &a.y, &a.y)?;
    let twice_xx = cursor.add("twice-x2", &points[0].1, &points[0].1)?;
    let thrice_xx = cursor.add("thrice-x2", &twice_xx, &points[0].1)?;
    let lam = cursor.field("slope")?;
    let ordinary = cursor.mul("ordinary-slope", &dx, &lam)?;
    let doubling = cursor.mul("double-slope", &twice_y, &lam)?;
    cursor.gate("gate_nonzero", &concat(&[&[selector], &dx]), &[4])?;
    cursor.gate("gate_nonzero", &concat(&[&[selector], &twice_y]), &[3])?;
    cursor.gate("gate_equal", &concat(&[&[selector], &ordinary, &dy]), &[4])?;
    cursor.gate(
        "gate_equal",
        &concat(&[&[selector], &doubling, &thrice_xx]),
        &[3],
    )?;
    let lsq = cursor.mul("slope2", &lam, &lam)?;
    let sx = cursor.add("sum-x", &a.x, &p.x)?;
    let sxr = cursor.add("sum-x-result", &sx, &e.x)?;
    cursor.gate("gate_equal", &concat(&[&[selector], &lsq, &sxr]), &[3, 4])?;
    let difference = cursor.sub("left-x-minus-result-x", &a.x, &e.x)?;
    let lhs = cursor.mul("y-equation", &lam, &difference)?;
    let ysum = cursor.add("left-y-plus-result-y", &a.y, &e.y)?;
    cursor.gate("gate_equal", &concat(&[&[selector], &lhs, &ysum]), &[3, 4])?;
    cursor.gate(
        "gate_small_equal",
        &[selector, e.infinity, zero_flag],
        &[3, 4],
    )?;
    cursor.gate("gate_small_equal", &[selector, e.infinity, one_flag], &[2])?;
    for (case, source) in [(0, &p), (1, &a)] {
        cursor.gate(
            "gate_small_equal",
            &[selector, e.infinity, source.infinity],
            &[case],
        )?;
        cursor.gate(
            "gate_equal",
            &concat(&[&[selector], &e.x, &source.x]),
            &[case],
        )?;
        cursor.gate(
            "gate_equal",
            &concat(&[&[selector], &e.y, &source.y]),
            &[case],
        )?;
    }
    if (cursor.word, cursor.leaf, cursor.fields.len()) != (CHILD_WORDS, CHILD_ARITHMETIC, 35) {
        return Err("independent complete-add schedule changed original7476/6116/35 census".into());
    }
    let bit = cursor.word("select/bit".to_string(), 2)?;
    let delta = cursor.word("select/infinity-delta".to_string(), 2)?;
    let masked = cursor.word("select/infinity-masked".to_string(), 2)?;
    let infinity = cursor.word("selected/infinity".to_string(), 2)?;
    let x = cursor.field("selected/x")?;
    let y = cursor.field("selected/y")?;
    let r = PointPorts {
        infinity,
        x: x.try_into().map_err(|_| "selected x width")?,
        y: y.try_into().map_err(|_| "selected y width")?,
    };
    cursor.gate("bool_xor", &[a.infinity, e.infinity, delta], &[])?;
    cursor.gate("bool_and", &[bit, delta, masked], &[])?;
    cursor.gate("bool_xor", &[a.infinity, masked, r.infinity], &[])?;
    for (case, source) in [(0, &a), (1, &e)] {
        cursor.gate("gate_equal", &concat(&[&[bit], &r.x, &source.x]), &[case])?;
        cursor.gate("gate_equal", &concat(&[&[bit], &r.y, &source.y]), &[case])?;
    }
    cursor.gate("point_form", &concat(&[&[r.infinity], &r.x, &r.y]), &[])?;
    if cursor.leaf != ARITHMETIC {
        return Err("independent point selector arithmetic census".into());
    }
    for (_, field) in cursor.fields.clone() {
        cursor.gate("field_valid", &field, &[])?;
    }
    if (cursor.word, cursor.leaf) != (WORDS, LEAVES) {
        return Err("independent point final census".into());
    }
    Ok((a, p, e, r, bit, delta, masked))
}

fn program_digest(
    spec: &GraphSpec,
    operation: &str,
    words: usize,
    arithmetic: usize,
    fields: &[(String, Vec<usize>)],
) -> Result<String> {
    let declarations = spec.words[..words]
        .iter()
        .map(|word| json!([word.name, word.bound]))
        .collect::<Vec<_>>();
    let field_rows = fields
        .iter()
        .map(|(name, indices)| Ok(json!([name, names(spec, indices)?])))
        .collect::<Result<Vec<_>>>()?;
    let constraints = spec.leaves[..arithmetic]
        .iter()
        .map(|leaf| Ok(json!([leaf.kind, names(spec, &leaf.wires)?, leaf.argument])))
        .collect::<Result<Vec<_>>>()?;
    hash(
        &json!({"schema":"bitvm2-nova-fixed-trace/v2","field_role":spec.field_role,
        "modulus":modulus_text(&spec.field_role)?,"operation_id":operation,"context":spec.context,
        "words":declarations,"fields":field_rows,"constraints":constraints}),
    )
}

fn port_values(
    a: &PointPorts,
    p: &PointPorts,
    e: &PointPorts,
    r: &PointPorts,
    bit: usize,
    delta: usize,
    masked: usize,
) -> Value {
    let mut result = Map::new();
    result.insert("bit".to_string(), json!(bit));
    result.insert("infinity_delta".to_string(), json!(delta));
    result.insert("infinity_masked".to_string(), json!(masked));
    for (name, point) in [("A", a), ("P", p), ("E", e), ("R", r)] {
        result.insert(format!("{name}_infinity"), json!(point.infinity));
        result.insert(format!("{name}_x"), json!(point.x));
        result.insert(format!("{name}_y"), json!(point.y));
    }
    Value::Object(result)
}

pub fn check(
    spec: &GraphSpec,
    context: &str,
    role: &str,
    bit_index: usize,
    operation_id: &str,
    raw_maps: &Value,
) -> Result<CheckedPoint> {
    let p = modulus(role)?;
    if bit_index >= 255
        || !identifier(operation_id)
        || !identifier(&format!("{operation_id}/complete-add"))
        || hex::encode(id32(context)?) != context
        || spec.context != context
        || spec.field_role != role
        || spec.operation_id != operation_id
        || spec.words.len() != WORDS
        || spec.leaves.len() != LEAVES
    {
        return Err("conditional point exact source parameters/census required".into());
    }
    let catalogue = hex::encode(spec.identity()?);
    let mut cursor = Cursor {
        spec,
        word: 0,
        leaf: 0,
        fields: Vec::new(),
        byte_fields: BTreeMap::new(),
        bodies: BTreeMap::new(),
        modulus_bytes: p.to_bytes_le(),
    };
    if cursor.modulus_bytes.len() != 32 {
        return Err("Pasta base modulus width".into());
    }
    let (a, p_ports, e, r, bit, delta, masked) = point_schedule(&mut cursor)?;
    let fields = cursor.fields;
    let program = program_digest(spec, operation_id, WORDS, ARITHMETIC, &fields)?;
    if program != spec.program_sha256 {
        return Err("conditional point plain Program digest differs".into());
    }
    let child_operation = format!("{operation_id}/complete-add");
    let child_program = program_digest(
        spec,
        &child_operation,
        CHILD_WORDS,
        CHILD_ARITHMETIC,
        &fields[..35],
    )?;
    let child_word_map = (0..CHILD_WORDS).collect::<Vec<_>>();
    let child_leaf_map = (0..CHILD_ARITHMETIC)
        .chain(ARITHMETIC..ARITHMETIC + 35)
        .collect::<Vec<_>>();
    let child_leaves = child_leaf_map
        .iter()
        .map(|i| spec.leaves[*i].clone())
        .collect::<Vec<_>>();
    let child_bodies = child_leaves
        .iter()
        .map(|leaf| {
            Ok((
                leaf.body_sha256.clone(),
                spec.bodies
                    .get(&leaf.body_sha256)
                    .ok_or("complete-add body missing")?
                    .clone(),
            ))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    let child = GraphSpec {
        program_sha256: child_program.clone(),
        context: context.to_string(),
        field_role: role.to_string(),
        operation_id: child_operation.clone(),
        words: spec.words[..CHILD_WORDS].to_vec(),
        leaves: child_leaves,
        bodies: child_bodies,
    };
    let child_catalogue = hex::encode(child.identity()?);
    let actual_bits = spec
        .leaves
        .iter()
        .enumerate()
        .flat_map(|(ordinal, leaf)| {
            leaf.wires
                .iter()
                .enumerate()
                .filter_map(move |(formal, word)| (*word == bit).then_some((ordinal, formal)))
        })
        .collect::<Vec<_>>();
    if bit != 7476 || actual_bits != BIT_OCCURRENCES {
        return Err("conditional point actual bit occurrences changed".into());
    }
    let port_indices = port_values(&a, &p_ports, &e, &r, bit, delta, masked);
    let mut ports = Map::new();
    for (name, value) in port_indices.as_object().ok_or("point port object")? {
        let named = if let Some(index) = value.as_u64() {
            json!(spec.words[usize::try_from(index)?].name)
        } else {
            let mut indices = Vec::new();
            for value in value.as_array().ok_or("point port list")? {
                indices.push(usize::try_from(
                    value.as_u64().ok_or("point port integer")?,
                )?);
            }
            json!(names(spec, &indices)?)
        };
        ports.insert(name.clone(), named);
    }
    let selector_constraints = SELECTORS
        .iter()
        .map(|(name, ordinal)| (name.to_string(), json!(ordinal)))
        .collect::<Map<_, _>>();
    let maps = json!({"schema":"bitvm2-nova-conditional-point-maps/v1",
        "child":{"operation_id":child_operation,"program_sha256":child_program,"catalogue_id":child_catalogue,
            "word_map":child_word_map,"leaf_map":child_leaf_map,"fields":fields[..35].iter().map(|(name,_)|name).collect::<Vec<_>>()},
        "ports":ports,"port_indices":port_indices,"selector_constraints":selector_constraints,
        "selected_bit_occurrences":BIT_OCCURRENCES,"R_canonical_field_leaves":[6159,6160],
        "original_field_leaves":(6124..6159).collect::<Vec<_>>(),"point_form_ordinal":6123,
        "bit_index":bit_index,"coordinate_outputs_are_asserted_ports":true,"all_child_predicates_active":true});
    if raw_maps != &maps {
        return Err("conditional point raw maps differ from independently rebuilt topology".into());
    }
    let maps_sha = hash(&maps)?;
    let curve = if role == "pallas_base" {
        "pallas"
    } else {
        "vesta"
    };
    let metadata = json!({"schema":"bitvm2-nova-conditional-point/v1","context":context,"field_role":role,
        "scalar_field_role":format!("{curve}_scalar"),"curve":curve,"bit_index":bit_index,
        "operation_id":operation_id,"program_sha256":program,"catalogue_id":catalogue,
        "source_maps_sha256":maps_sha,"words":7498,"arithmetic_constraints":6124,"canonical_fields":37,
        "leaves":6161,"relation":"E=A+P; R=A if b=0 else E",
        "infinity_relation":"d=A_inf XOR E_inf; m=b AND d; R_inf=A_inf XOR m",
        "scope":"one conditional point relation given an external bit and A/P ports; origins/IPA remain open"});
    let mut source = sha256::Hash::engine();
    source.input(DOMAIN);
    source.input(&canonical(&metadata)?);
    Ok(CheckedPoint {
        bit_index,
        source_maps: maps,
        metadata,
        source_sha256: hex::encode(sha256::Hash::from_engine(source)),
        source_maps_sha256: maps_sha,
        program_sha256: program,
        catalogue_id: catalogue,
        child_program_sha256: child_program,
        child_catalogue_id: child_catalogue,
        child_word_map,
        child_leaf_map,
        a,
        p: p_ports,
        e,
        r,
        bit,
        delta,
        masked,
        bit_occurrences: actual_bits,
        r_field_guards: [6159, 6160],
        fields,
    })
}

/// Raw radix2^29 integer, retaining all261 potential bits. No field conversion
/// or modular reduction is performed by this decoder.
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
        "const" => u64::from(v[0]) == u64::try_from(argument[0])?,
        "bool_xor" => v[2] == (v[0] ^ v[1]),
        "bool_and" => v[2] == (v[0] & v[1]),
        "add" => {
            let x = integer(&v[..9]);
            let y = integer(&v[9..18]);
            let z = integer(&v[18..27]);
            if &x >= p || &y >= p {
                return Ok(None);
            }
            (x + y) % p == z
        }
        "equal" => v[..9] == v[9..18],
        "point_form" => v[0] == 0 || v[1..].iter().all(|word| *word == 0),
        "gate_equal" => !active() || v[1..10] == v[10..19],
        "gate_nonzero" => !active() || v[1..10].iter().any(|word| *word != 0),
        "gate_small_equal" => !active() || v[1] == v[2],
        "dispatch" => {
            let same_x = v[2..11] == v[20..29];
            let same_y = v[11..20] == v[29..38];
            let inverse = same_x && v[38..47].iter().all(|word| *word == 0);
            let expected = if v[0] != 0 {
                0
            } else if v[1] != 0 {
                1
            } else if inverse {
                2
            } else if same_x && same_y {
                3
            } else {
                4
            };
            v[47] == expected
        }
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
            u64::from(*v.last().ok_or("PQ output")?)
                == v[..v.len() - 1]
                    .iter()
                    .zip(argument)
                    .map(
                        |(value, coefficient)| Ok(u64::from(*value) * u64::try_from(*coefficient)?),
                    )
                    .collect::<Result<Vec<_>>>()?
                    .iter()
                    .sum::<u64>()
        }
        "conv_column" => {
            let ab = usize::try_from(argument[0])?;
            let pq = usize::try_from(argument[1])?;
            let has_c = argument[2] == 1;
            let incoming = u64::from(v[ab + pq]);
            let outgoing = u64::from(v[ab + pq + 1]);
            let c = if has_c {
                u64::from(*v.last().ok_or("column c")?)
            } else {
                0
            };
            v[..ab].iter().map(|x| u64::from(*x)).sum::<u64>() + incoming + 255 * 8192
                == c + v[ab..ab + pq].iter().map(|x| u64::from(*x)).sum::<u64>() + 256 * outgoing
        }
        "field_valid" => &integer(v) < p,
        _ => return Err("unsupported closed conditional-point predicate".into()),
    };
    Ok(Some(result))
}

/// Some(false) is an authenticated Registry range/ordinary-predicate failure.
/// None denotes canonical-input VERIFY aborts; it must never be negated into a
/// successful disproof. Actual Script observations are the worker's separate job.
pub fn truth(spec: &GraphSpec, values: &[u32], ordinal: usize) -> Result<Option<bool>> {
    if spec.words.len() != WORDS
        || spec.leaves.len() != LEAVES
        || values.len() != WORDS
        || ordinal >= LEAVES
    {
        return Err("conditional point truth exact closed census/assignment required".into());
    }
    let leaf = &spec.leaves[ordinal];
    let mut operands = Vec::with_capacity(leaf.wires.len());
    for index in &leaf.wires {
        let word = spec.words.get(*index).ok_or("truth word index")?;
        let value = *values.get(*index).ok_or("truth assignment index")?;
        if value >= word.bound {
            return Ok(Some(false));
        }
        operands.push(value);
    }
    // check() establishes exact formal arities and public parameters once,
    // before this per-leaf helper is called. Reject a wrong standalone shape.
    let lengths = match leaf.kind.as_str() {
        "const" => (1, 1),
        "bool_xor" | "bool_and" => (3, 0),
        "add" => (27, 0),
        "equal" => (18, 0),
        "point_form" => (19, 0),
        "gate_equal" => (19, leaf.argument.len()),
        "gate_nonzero" => (10, leaf.argument.len()),
        "gate_small_equal" => (3, leaf.argument.len()),
        "dispatch" => (48, 0),
        "field_valid" => (9, 0),
        "conv_split" => (3, 1),
        "conv_reconstruct" => (leaf.argument.len() + 1, leaf.argument.len()),
        "conv_ab" => {
            if leaf.argument.len() != 1 || !(1..=4).contains(&leaf.argument[0]) {
                return Err("AB shape".into());
            }
            (2 * usize::try_from(leaf.argument[0])? + 1, 1)
        }
        "conv_pq" => (leaf.argument.len() + 1, leaf.argument.len()),
        "conv_column" => {
            if leaf.argument.len() != 3
                || !(0..=8).contains(&leaf.argument[0])
                || !(0..=4).contains(&leaf.argument[1])
                || !(0..=1).contains(&leaf.argument[2])
            {
                return Err("column shape".into());
            }
            (
                usize::try_from(leaf.argument[0] + leaf.argument[1] + 2 + leaf.argument[2])?,
                3,
            )
        }
        _ => return Err("unknown closed point truth kind".into()),
    };
    if operands.len() != lengths.0 || leaf.argument.len() != lengths.1 {
        return Err("closed point truth arity".into());
    }
    if leaf.kind == "conv_split" && !(1..=7).contains(&leaf.argument[0]) {
        return Err("split width".into());
    }
    if leaf.kind == "conv_reconstruct"
        && (leaf.argument.is_empty()
            || leaf.argument.len() > 5
            || leaf.argument.iter().any(|w| !(1..=8).contains(w))
            || leaf.argument.iter().sum::<i64>() > 29)
    {
        return Err("reconstruction widths".into());
    }
    if leaf.kind == "conv_pq"
        && (leaf.argument.is_empty()
            || leaf.argument.len() > 8
            || leaf.argument.iter().any(|c| !(1..=255).contains(c)))
    {
        return Err("PQ coefficients".into());
    }
    predicate(
        &leaf.kind,
        &leaf.argument,
        &operands,
        &modulus(&spec.field_role)?,
    )
}

fn affine<A: CurveAffine>(flag: u32, x: &BigUint, y: &BigUint, p: &BigUint) -> Option<A> {
    if flag > 1 || x >= p || y >= p {
        return None;
    }
    if flag == 1 {
        return if *x == BigUint::from(0u32) && *y == BigUint::from(0u32) {
            Some(A::identity())
        } else {
            None
        };
    }
    let decode = |value: &BigUint| -> Option<A::Base> {
        let bytes = value.to_bytes_le();
        let mut repr = <A::Base as PrimeField>::Repr::default();
        if bytes.len() > 32 || repr.as_ref().len() != 32 {
            return None;
        }
        repr.as_mut().fill(0);
        repr.as_mut()[..bytes.len()].copy_from_slice(&bytes);
        Option::<A::Base>::from(A::Base::from_repr(repr))
    };
    Option::<A>::from(A::from_xy(decode(x)?, decode(y)?))
}

fn native_point<A: CurveAffine>(
    values: &[u32],
    ports: &PointPorts,
    p: &BigUint,
) -> Result<Option<A>> {
    let coordinate = |indices: &[usize; 9]| -> Result<BigUint> {
        let limbs = indices
            .iter()
            .map(|index| {
                values
                    .get(*index)
                    .copied()
                    .ok_or_else(|| "point limb assignment index".into())
            })
            .collect::<Result<Vec<_>>>()?;
        if limbs.iter().any(|limb| *limb >= BASE) {
            return Ok(p.clone());
        }
        Ok(integer(&limbs))
    };
    Ok(affine::<A>(
        *values.get(ports.infinity).ok_or("point flag index")?,
        &coordinate(&ports.x)?,
        &coordinate(&ports.y)?,
        p,
    ))
}

fn curve_verdict<A: CurveAffine>(
    values: &[u32],
    a: &PointPorts,
    p_ports: &PointPorts,
    e: &PointPorts,
    r: &PointPorts,
    bit: usize,
    p: &BigUint,
) -> Result<CurveVerdict> {
    let a = native_point::<A>(values, a, p)?;
    let point = native_point::<A>(values, p_ports, p)?;
    let e = native_point::<A>(values, e, p)?;
    let r = native_point::<A>(values, r, p)?;
    let bit = *values.get(bit).ok_or("selected point bit index")?;
    let mut result = CurveVerdict {
        a_valid: a.is_some(),
        p_valid: point.is_some(),
        e_valid: e.is_some(),
        r_valid: r.is_some(),
        bit_valid: bit <= 1,
        addition_holds: false,
        selection_holds: false,
    };
    if let (Some(a), Some(point), Some(e), Some(r)) = (a, point, e, r) {
        result.addition_holds = (a.to_curve() + point.to_curve()).to_affine() == e;
        if bit <= 1 {
            result.selection_holds = r == if bit == 0 { a } else { e };
        }
    }
    Ok(result)
}

/// Direct mature curve check, independent of raw-predicate truth and Script.
/// Every A/P/E/R decoder runs before selection; invalid unused P is never hidden.
pub fn checked_curve(spec: &GraphSpec, values: &[u32]) -> Result<CurveVerdict> {
    if spec.words.len() != WORDS || spec.leaves.len() != LEAVES || values.len() != WORDS {
        return Err("point curve oracle closed census".into());
    }
    let point = |prefix: &str| -> Result<PointPorts> {
        let find = |name: &str| -> Result<usize> {
            spec.words
                .iter()
                .position(|word| word.name == name)
                .ok_or_else(|| "native point port name".into())
        };
        Ok(PointPorts {
            infinity: find(&format!("{prefix}/infinity"))?,
            x: (0..9)
                .map(|i| find(&format!("{prefix}/x/l{i}")))
                .collect::<Result<Vec<_>>>()?
                .try_into()
                .map_err(|_| "native x width")?,
            y: (0..9)
                .map(|i| find(&format!("{prefix}/y/l{i}")))
                .collect::<Result<Vec<_>>>()?
                .try_into()
                .map_err(|_| "native y width")?,
        })
    };
    let a = point("left")?;
    let p_ports = point("right")?;
    let e = point("result")?;
    let r = point("selected")?;
    let bit = spec
        .words
        .iter()
        .position(|word| word.name == "select/bit")
        .ok_or("native bit word")?;
    let p = modulus(&spec.field_role)?;
    match spec.field_role.as_str() {
        "pallas_base" => curve_verdict::<PallasAffine>(values, &a, &p_ports, &e, &r, bit, &p),
        "vesta_base" => curve_verdict::<VestaAffine>(values, &a, &p_ports, &e, &r, bit, &p),
        _ => Err("native point oracle requires an exact base role".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn body_shape_uses_formal_aliases_without_global_ids() {
        assert_eq!(aliases(&[7, 7, 9]), [0, 0, 1]);
        assert_eq!(aliases(&[7, 7, 9]), aliases(&[13, 13, 2]));
        assert_ne!(aliases(&[7, 7, 9]), aliases(&[7, 9, 9]));
    }

    #[test]
    fn raw_limb_decoder_retains_bits_above254() {
        let mut limbs = [0u32; 9];
        limbs[8] = 1 << 23;
        assert_eq!(integer(&limbs), BigUint::from(1u32) << 255usize);
        assert!(integer(&limbs) >= modulus("pallas_base").unwrap());
        limbs[8] = BASE - 1;
        assert!(integer(&limbs).bits() > 255);
    }

    #[test]
    fn raw_add_distinguishes_aborts_from_false_canonical_output_relation() {
        let p = modulus("pallas_base").unwrap();
        let mut v = vec![0u32; 27];
        let mut bits = p.clone();
        let mask = BigUint::from(BASE - 1);
        for limb in v.iter_mut().take(9) {
            *limb = (&bits & &mask)
                .to_u32_digits()
                .first()
                .copied()
                .unwrap_or(0);
            bits >>= 29usize;
        }
        assert_eq!(predicate("add", &[], &v, &p).unwrap(), None);
        let mut z = vec![0u32; 27];
        z[18..].copy_from_slice(&v[..9]);
        assert_eq!(predicate("add", &[], &z, &p).unwrap(), Some(false));
        assert_eq!(
            predicate("point_form", &[], &[0; 19], &p).unwrap(),
            Some(true)
        );
    }

    fn affine_boundaries<A: CurveAffine>(role: &str) {
        let p = modulus(role).unwrap();
        let zero = BigUint::from(0u32);
        let two = BigUint::from(2u32);
        assert!(affine::<A>(1, &zero, &zero, &p).is_some());
        assert!(affine::<A>(0, &zero, &zero, &p).is_none());
        assert!(affine::<A>(1, &two, &zero, &p).is_none());
        assert!(affine::<A>(2, &zero, &zero, &p).is_none());
        assert!(affine::<A>(0, &p, &two, &p).is_none());
        assert!(affine::<A>(0, &(&p + BigUint::from(1u32)), &two, &p).is_none());
        assert!(affine::<A>(0, &(BigUint::from(1u32) << 255usize), &two, &p).is_none());
        assert!(affine::<A>(0, &(&p - BigUint::from(1u32)), &two, &p).is_some());
    }

    #[test]
    fn mature_curve_parsers_reject_noncanonical_high_bits_and_invalid_flags() {
        affine_boundaries::<PallasAffine>("pallas_base");
        affine_boundaries::<VestaAffine>("vesta_base");
    }

    #[test]
    fn canonical_json_is_sorted_compact_ascii() {
        assert_eq!(
            canonical(&json!({"z":[1,0],"a":"test"})).unwrap(),
            br#"{"a":"test","z":[1,0]}"#
        );
        assert!(canonical(&json!({"a":1.25})).is_err());
        assert!(canonical(&json!({"a":"\u{00e9}"})).is_err());
    }
}
