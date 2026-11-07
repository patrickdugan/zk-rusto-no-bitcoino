//! Independent closed legacy/grouped convolution source admission.
//! Derived only from completed conditional_point/probe_run baseline schedules.
//! No authentication replacement, proving, production origins or paused M19 code.
//! Completed baseline source provenance: conditional_point.rs SHA256
//! 882d1b3b6bbb18e5e70722bf744a6c46f80ee426c8d3c8f762f4cef3eb32b504;
//! probe_run.rs c5d7a91e97aea770baf30247dda92a951d6a4fd00ae25a113bd3c431dfa33f72.
use crate::{
    registry::{GraphSpec, Leaf},
    transport::{Case, Descriptor},
};
use bitcoin::{
    hashes::{sha256, Hash, HashEngine},
    script::Builder,
};
use bitvm2_nova_script_oracle::wots::{id32, Result};
use ff::PrimeField;
use halo2curves::{
    group::Curve,
    pasta::{PallasAffine, VestaAffine},
    CurveAffine,
};
use num_bigint::BigUint;
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet, HashSet};
const BASE: u32 = 1 << 29;
const PROGRAM_DOMAIN: &[u8] = b"BITVM2-NOVA/GROUPED-CONVOLUTION-PROGRAM/v1\0";
const PATTERNS: [&[i64]; 3] = [&[1, 2, 3, 4], &[4, 4, 4, 4], &[3, 2, 1]];
const PROFILES: [&str; 20] = [
    "mul-distinct",
    "mul-equal-distinct",
    "square",
    "point",
    "row-leading-0",
    "row-leading-1",
    "row-leading-2",
    "row-leading-3",
    "row-middle-0",
    "row-middle-1",
    "row-middle-2",
    "row-middle-3",
    "row-trailing-0",
    "row-trailing-1",
    "row-trailing-2",
    "cancel-equal",
    "cancel-square",
    "inactive-ab",
    "byte-256",
    "subtotal-max",
];
fn require(ok: bool, msg: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(msg.into())
    }
}
fn canonical(v: &Value) -> Result<Vec<u8>> {
    fn ordered(v: &Value, d: usize) -> Result<Value> {
        require(d <= 32, "source JSON depth")?;
        Ok(match v {
            Value::Object(o) => {
                let mut out = Map::new();
                let mut keys = o.keys().collect::<Vec<_>>();
                keys.sort_unstable();
                for k in keys {
                    require(k.is_ascii(), "ASCII key")?;
                    out.insert(k.clone(), ordered(&o[k], d + 1)?);
                }
                Value::Object(out)
            }
            Value::Array(a) => {
                Value::Array(a.iter().map(|x| ordered(x, d + 1)).collect::<Result<_>>()?)
            }
            Value::String(s) => {
                require(s.is_ascii(), "ASCII string")?;
                v.clone()
            }
            Value::Number(n) => {
                require(n.as_i64().is_some() || n.as_u64().is_some(), "integer JSON")?;
                v.clone()
            }
            _ => v.clone(),
        })
    }
    Ok(serde_json::to_vec(&ordered(v, 0)?)?)
}
fn sha(raw: &[u8]) -> String {
    hex::encode(sha256::Hash::hash(raw))
}
fn hash(v: &Value) -> Result<String> {
    Ok(sha(&canonical(v)?))
}
fn domain_hash(domain: &[u8], v: &Value) -> Result<String> {
    let mut h = sha256::Hash::engine();
    h.input(domain);
    h.input(&canonical(v)?);
    Ok(hex::encode(sha256::Hash::from_engine(h)))
}
fn concat(parts: &[&[usize]]) -> Vec<usize> {
    parts.iter().flat_map(|p| p.iter().copied()).collect()
}
fn names(spec: &GraphSpec, indices: &[usize]) -> Result<Vec<String>> {
    indices
        .iter()
        .map(|i| {
            spec.words
                .get(*i)
                .map(|w| w.name.clone())
                .ok_or_else(|| "word index".into())
        })
        .collect()
}
fn aliases(wires: &[usize]) -> Vec<usize> {
    let mut seen = BTreeMap::new();
    wires
        .iter()
        .map(|w| {
            let n = seen.len();
            *seen.entry(*w).or_insert(n)
        })
        .collect()
}
fn modulus_text(role: &str) -> Result<&'static str> {
    match role {
        "pallas_base" => {
            Ok("28948022309329048855892746252171976963363056481941560715954676764349967630337")
        }
        "vesta_base" => {
            Ok("28948022309329048855892746252171976963363056481941647379679742748393362948097")
        }
        _ => Err("exact Pasta base role".into()),
    }
}
fn modulus(role: &str) -> Result<BigUint> {
    BigUint::parse_bytes(modulus_text(role)?.as_bytes(), 10).ok_or_else(|| "modulus".into())
}
fn sub(x: &BigUint, y: &BigUint, p: &BigUint) -> BigUint {
    (x + p - y) % p
}
fn inverse(x: &BigUint, p: &BigUint) -> Result<BigUint> {
    require(*x != BigUint::from(0u32), "zero denominator")?;
    Ok(x.modpow(&(p - BigUint::from(2u32)), p))
}
fn digits(value: &BigUint) -> Result<[u32; 9]> {
    require(value.bits() <= 261, "unsigned261bit integer")?;
    let mask = BigUint::from(BASE - 1);
    let mut out = [0; 9];
    for (i, v) in out.iter_mut().enumerate() {
        *v = ((value >> (29 * i)) & &mask)
            .to_u32_digits()
            .first()
            .copied()
            .unwrap_or(0);
    }
    Ok(out)
}
#[derive(Clone)]
pub struct PointPorts {
    pub infinity: usize,
    pub x: [usize; 9],
    pub y: [usize; 9],
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
        crate::legacy_body_pins::check(
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

fn point_schedule(cursor: &mut Cursor<'_>) -> Result<(PointPorts, PointPorts, PointPorts)> {
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
    require(
        (cursor.word, cursor.leaf, cursor.fields.len()) == (7476, 6116, 35),
        "complete point7476/6116/35 schedule",
    )?;
    Ok((a, p, e))
}

#[derive(Clone, PartialEq, Eq)]
struct Point {
    infinity: u32,
    x: BigUint,
    y: BigUint,
}
impl Point {
    fn identity() -> Self {
        Self {
            infinity: 1,
            x: 0u32.into(),
            y: 0u32.into(),
        }
    }
}
fn add(a: &Point, b: &Point, p: &BigUint) -> Result<Point> {
    if a.infinity == 1 {
        return Ok(b.clone());
    }
    if b.infinity == 1 {
        return Ok(a.clone());
    }
    if a.x == b.x && (&a.y + &b.y) % p == BigUint::from(0u32) {
        return Ok(Point::identity());
    }
    let (num, den) = if a == b {
        (
            BigUint::from(3u32) * &a.x * &a.x % p,
            BigUint::from(2u32) * &a.y % p,
        )
    } else {
        (sub(&b.y, &a.y, p), sub(&b.x, &a.x, p))
    };
    let slope = num * inverse(&den, p)? % p;
    let x = sub(&sub(&(&slope * &slope % p), &a.x, p), &b.x, p);
    let y = sub(&(&slope * sub(&a.x, &x, p) % p), &a.y, p);
    Ok(Point { infinity: 0, x, y })
}
struct Witness<'a> {
    spec: &'a GraphSpec,
    slots: BTreeMap<&'a str, usize>,
    values: Vec<Option<u32>>,
    fields: BTreeMap<String, BigUint>,
    byte_fields: BTreeMap<String, [u32; 32]>,
    modulus: BigUint,
    cancel: bool,
}
impl<'a> Witness<'a> {
    fn new(spec: &'a GraphSpec, p: &BigUint, cancel: bool) -> Result<Self> {
        let slots = spec
            .words
            .iter()
            .enumerate()
            .map(|(i, w)| (w.name.as_str(), i))
            .collect::<BTreeMap<_, _>>();
        if slots.len() != spec.words.len() {
            return Err("duplicate witness declaration".into());
        }
        Ok(Self {
            spec,
            slots,
            values: vec![None; spec.words.len()],
            fields: BTreeMap::new(),
            byte_fields: BTreeMap::new(),
            modulus: p.clone(),
            cancel,
        })
    }
    fn set(&mut self, name: &str, value: u32) -> Result<()> {
        let slot = *self
            .slots
            .get(name)
            .ok_or_else(|| format!("missing closed witness word {name}"))?;
        let bound = self.spec.words[slot].bound;
        if value >= bound || self.values[slot].is_some() {
            return Err(format!("closed witness bound/duplicate: {name}").into());
        }
        self.values[slot] = Some(value);
        Ok(())
    }
    fn field(&mut self, name: &str, value: BigUint) -> Result<()> {
        if self.fields.contains_key(name) {
            return Err("duplicate witness field".into());
        }
        if value >= self.modulus {
            return Err("legacy field intermediate is noncanonical".into());
        }
        for (i, word) in digits(&value)?.into_iter().enumerate() {
            self.set(&format!("{name}/l{i}"), word)?;
        }
        self.fields.insert(name.to_string(), value);
        Ok(())
    }
    fn value(&self, name: &str) -> Result<BigUint> {
        self.fields
            .get(name)
            .cloned()
            .ok_or_else(|| format!("missing closed field {name}").into())
    }
    fn add(&mut self, name: &str, x: &str, y: &str) -> Result<()> {
        self.field(name, (self.value(x)? + self.value(y)?) % &self.modulus)
    }
    fn sub(&mut self, name: &str, x: &str, y: &str) -> Result<()> {
        self.field(name, sub(&self.value(x)?, &self.value(y)?, &self.modulus))
    }
    fn bytes(&mut self, name: &str, field: &str) -> Result<[u32; 32]> {
        if let Some(values) = self.byte_fields.get(field) {
            return Ok(*values);
        }
        let raw = self.value(field)?.to_bytes_le();
        if raw.len() > 32 {
            return Err("closed field/BYTE adapter overflow".into());
        }
        let mut values = [0u32; 32];
        for (i, byte) in raw.iter().enumerate() {
            values[i] = u32::from(*byte);
        }
        for (i, value) in values.iter().enumerate() {
            self.set(&format!("{name}/byte/{i}"), *value)?;
        }
        for boundary in [29usize, 58, 87, 116, 145, 174, 203] {
            let (i, low) = (boundary / 8, boundary % 8);
            self.set(
                &format!("{name}/split/{i}/lo"),
                values[i] & ((1 << low) - 1),
            )?;
            self.set(&format!("{name}/split/{i}/hi"), values[i] >> low)?;
        }
        self.byte_fields.insert(field.to_string(), values);
        Ok(values)
    }
    fn mul(&mut self, name: &str, x: &str, y: &str) -> Result<()> {
        let product = self.value(x)? * self.value(y)?;
        let quotient = &product / &self.modulus;
        self.field(
            name,
            if self.cancel && name == "product" {
                BigUint::from(65794u32)
            } else {
                &product % &self.modulus
            },
        )?;
        let a = self.bytes(&format!("{name}/a"), x)?;
        let b = self.bytes(&format!("{name}/b"), y)?;
        let c = self.bytes(&format!("{name}/c"), name)?;
        let raw_q = quotient.to_bytes_le();
        if raw_q.len() > 32 {
            return Err("closed multiplication quotient overflow".into());
        }
        let mut q = [0u32; 32];
        for (i, byte) in raw_q.iter().enumerate() {
            q[i] = u32::from(*byte);
        }
        for (i, value) in q.iter().enumerate() {
            self.set(&format!("{name}/q/{i}"), *value)?;
        }
        let modulus = self.modulus.to_bytes_le();
        if modulus.len() != 32 {
            return Err("fixed modulus width".into());
        }
        let mut carry = 0i64;
        self.set(&format!("{name}/carry/0"), 8192)?;
        for column in 0..64usize {
            let products = (0..32)
                .filter_map(|i| column.checked_sub(i).filter(|j| *j < 32).map(|j| (i, j)))
                .collect::<Vec<_>>();
            let mut ab_total = 0i64;
            for (block, pairs) in products.chunks(4).enumerate() {
                let mut value = pairs.iter().map(|(i, j)| a[*i] * b[*j]).sum::<u32>();
                if self.cancel && name == "product" && block == 0 {
                    if column == 0 {
                        value += 1;
                    }
                    if column == 1 {
                        value -= 1;
                    }
                }
                ab_total += i64::from(value);
                self.set(&format!("{name}/ab/{column}/{block}"), value)?;
            }
            let products = modulus
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
                .collect::<Vec<_>>();
            let mut pq_total = 0i64;
            for (block, pairs) in products.chunks(8).enumerate() {
                let value = pairs
                    .iter()
                    .map(|(coefficient, j)| u32::from(*coefficient) * q[*j])
                    .sum::<u32>();
                pq_total += i64::from(value);
                self.set(&format!("{name}/pq/{column}/{block}"), value)?;
            }
            let numerator =
                ab_total + carry - pq_total - if column < 32 { i64::from(c[column]) } else { 0 };
            if numerator.rem_euclid(256) != 0 {
                return Err("closed multiplication column not exactly divisible".into());
            }
            carry = numerator.div_euclid(256);
            self.set(
                &format!("{name}/carry/{}", column + 1),
                u32::try_from(carry + 8192)?,
            )?;
        }
        if carry != 0 {
            return Err("closed multiplication final carry differs".into());
        }
        Ok(())
    }
    fn point(&mut self, name: &str, point: &Point) -> Result<()> {
        self.set(&format!("{name}/infinity"), point.infinity)?;
        self.field(&format!("{name}/x"), point.x.clone())?;
        self.field(&format!("{name}/y"), point.y.clone())?;
        self.mul(
            &format!("{name}/x2"),
            &format!("{name}/x"),
            &format!("{name}/x"),
        )?;
        self.mul(
            &format!("{name}/x3"),
            &format!("{name}/x2"),
            &format!("{name}/x"),
        )?;
        self.mul(
            &format!("{name}/y2"),
            &format!("{name}/y"),
            &format!("{name}/y"),
        )?;
        self.add(
            &format!("{name}/curve-rhs"),
            &format!("{name}/x3"),
            "constant/five",
        )
    }
    fn finish(self) -> Result<Vec<u32>> {
        self.values
            .into_iter()
            .map(|value| value.ok_or_else(|| "unwritten closed numeric witness word".into()))
            .collect()
    }
}

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
    let decoded = Option::<A>::from(A::from_xy(decode(x)?, decode(y)?))?;
    // Halo2 accepts (0,0) as its affine identity sentinel. The finite flag
    // must reject that sentinel; only flag1 with zero coordinates encodes O.
    if bool::from(decoded.is_identity()) {
        None
    } else {
        Some(decoded)
    }
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

struct Baseline {
    fields: Vec<(String, Vec<usize>)>,
    arithmetic: usize,
    points: Option<(PointPorts, PointPorts, PointPorts)>,
}
fn baseline(spec: &GraphSpec, fixture: &str) -> Result<Baseline> {
    let mut cursor = Cursor {
        spec,
        word: 0,
        leaf: 0,
        fields: Vec::new(),
        byte_fields: BTreeMap::new(),
        bodies: BTreeMap::new(),
        modulus_bytes: modulus(&spec.field_role)?.to_bytes_le(),
    };
    let points = if matches!(fixture, "point" | "point-inactive") {
        Some(point_schedule(&mut cursor)?)
    } else {
        require(
            matches!(fixture, "mul-distinct" | "mul-equal-distinct" | "square"),
            "closed fixture",
        )?;
        let a = cursor.field("input/a")?;
        let b = if fixture == "square" {
            a.clone()
        } else {
            cursor.field("input/b")?
        };
        cursor.mul("product", &a, &b)?;
        None
    };
    let arithmetic = cursor.leaf;
    for (_, field) in cursor.fields.clone() {
        cursor.gate("field_valid", &field, &[])?;
    }
    let wanted = match fixture {
        "point" | "point-inactive" => (7476, 6116, 35, 6151),
        "square" => (579, 470, 2, 472),
        _ => (634, 486, 3, 489),
    };
    require(
        (cursor.word, arithmetic, cursor.fields.len(), cursor.leaf) == wanted
            && spec.words.len() == wanted.0
            && spec.leaves.len() == wanted.3,
        "closed baseline census",
    )?;
    let used = cursor.bodies.values().collect::<HashSet<_>>();
    require(
        used.len() == spec.bodies.len() && spec.bodies.keys().all(|k| used.contains(k)),
        "exact used legacy body catalogue",
    )?;
    // The frozen legacy identity rejects malformed bytes and unused bodies.
    let legacy: bitvm2_nova_script_oracle::registry::GraphSpec =
        serde_json::from_value(serde_json::to_value(spec)?)?;
    require(
        hex::encode(legacy.identity()?) == hex::encode(spec.identity()?),
        "old/new baseline catalogue encoding parity",
    )?;
    Ok(Baseline {
        fields: cursor.fields,
        arithmetic,
        points,
    })
}
fn program_digest(
    spec: &GraphSpec,
    arithmetic: usize,
    fields: &[(String, Vec<usize>)],
    grouped: bool,
) -> Result<String> {
    let shape = json!({"schema":"bitvm2-nova-fixed-trace/v2","field_role":spec.field_role,"modulus":modulus_text(&spec.field_role)?,"operation_id":spec.operation_id,"context":spec.context,
        "words":spec.words.iter().map(|w|json!([w.name,w.bound])).collect::<Vec<_>>(),"fields":fields.iter().map(|(n,ws)|Ok(json!([n,names(spec,ws)?]))).collect::<Result<Vec<_>>>()?,
        "constraints":spec.leaves[..arithmetic].iter().map(|l|Ok(json!([l.kind,names(spec,&l.wires)?,l.argument]))).collect::<Result<Vec<_>>>()?});
    let plain = hash(&shape)?;
    if !grouped {
        return Ok(plain);
    }
    let mut h = sha256::Hash::engine();
    h.input(PROGRAM_DOMAIN);
    h.input(&hex::decode(plain)?);
    Ok(hex::encode(sha256::Hash::from_engine(h)))
}
fn expected_values(spec: &GraphSpec, fixture: &str, cancel: bool) -> Result<Vec<u32>> {
    let p = modulus(&spec.field_role)?;
    let mut w = Witness::new(spec, &p, cancel)?;
    if !matches!(fixture, "point" | "point-inactive") {
        w.field("input/a", 257u32.into())?;
        if fixture != "square" {
            w.field(
                "input/b",
                if fixture == "mul-distinct" {
                    259u32.into()
                } else {
                    257u32.into()
                },
            )?;
        }
        w.mul(
            "product",
            "input/a",
            if fixture == "square" {
                "input/a"
            } else {
                "input/b"
            },
        )?;
        return w.finish();
    }
    let g = Point {
        infinity: 0,
        x: &p - BigUint::from(1u32),
        y: 2u32.into(),
    };
    let a = if fixture == "point-inactive" {
        Point::identity()
    } else {
        g.clone()
    };
    let b = if fixture == "point-inactive" {
        g.clone()
    } else {
        add(&g, &g, &p)?
    };
    let e = add(&a, &b, &p)?;
    w.field("constant/zero", 0u32.into())?;
    w.field("constant/five", 5u32.into())?;
    w.set("constant/false", 0)?;
    w.set("constant/true", 1)?;
    w.point("left", &a)?;
    w.point("right", &b)?;
    w.point("result", &e)?;
    w.add("sum-y", "left/y", "right/y")?;
    let selector = if a.infinity == 1 {
        0
    } else if b.infinity == 1 {
        1
    } else if a.x == b.x && (&a.y + &b.y) % &p == BigUint::from(0u32) {
        2
    } else if a == b {
        3
    } else {
        4
    };
    w.set("dispatch", selector)?;
    w.sub("dx", "right/x", "left/x")?;
    w.sub("dy", "right/y", "left/y")?;
    w.add("twice-y", "left/y", "left/y")?;
    w.add("twice-x2", "left/x2", "left/x2")?;
    w.add("thrice-x2", "twice-x2", "left/x2")?;
    let (den, num) = if selector == 4 {
        (sub(&b.x, &a.x, &p), sub(&b.y, &a.y, &p))
    } else {
        (
            BigUint::from(2u32) * &a.y % &p,
            BigUint::from(3u32) * &a.x * &a.x % &p,
        )
    };
    let slope = if matches!(selector, 3 | 4) && den != BigUint::from(0u32) {
        num * inverse(&den, &p)? % &p
    } else {
        0u32.into()
    };
    w.field("slope", slope)?;
    w.mul("ordinary-slope", "dx", "slope")?;
    w.mul("double-slope", "twice-y", "slope")?;
    w.mul("slope2", "slope", "slope")?;
    w.add("sum-x", "left/x", "right/x")?;
    w.add("sum-x-result", "sum-x", "result/x")?;
    w.sub("left-x-minus-result-x", "left/x", "result/x")?;
    w.mul("y-equation", "slope", "left-x-minus-result-x")?;
    w.add("left-y-plus-result-y", "left/y", "result/y")?;
    w.finish()
}
#[derive(Clone)]
struct Cell {
    column: usize,
    block: usize,
    pairs: Vec<(usize, usize)>,
}
fn cells() -> Vec<Cell> {
    let mut out = Vec::new();
    for column in 0usize..63 {
        let start = column.saturating_sub(31);
        let end = column.min(31);
        for (block, first) in (start..=end).step_by(4).enumerate() {
            out.push(Cell {
                column,
                block,
                pairs: (first..=end.min(first + 3))
                    .map(|i| (i, column - i))
                    .collect(),
            });
        }
    }
    out
}
fn groups() -> Result<Vec<Vec<Cell>>> {
    let cells = cells();
    let mut out = Vec::new();
    for (lo, hi) in [(0, 31), (32, 62)] {
        for block in 0..8 {
            let strip = cells
                .iter()
                .filter(|c| lo <= c.column && c.column <= hi && c.block == block)
                .cloned()
                .collect::<Vec<_>>();
            out.extend(strip.chunks(4).map(|x| x.to_vec()));
        }
    }
    require(
        out.len() == 72
            && out.iter().map(Vec::len).sum::<usize>() == 280
            && out.iter().all(|g| {
                PATTERNS.contains(
                    &g.iter()
                        .map(|c| c.pairs.len() as i64)
                        .collect::<Vec<_>>()
                        .as_slice(),
                )
            }),
        "72-group exact partition",
    )?;
    Ok(out)
}
fn number(code: &mut Vec<u8>, n: usize) {
    code.extend_from_slice(Builder::new().push_int(n as i64).into_script().as_bytes());
}
fn expansion(wires: &[usize]) -> Vec<u8> {
    let a = aliases(wires);
    let unique = a.iter().max().map_or(0, |m| m + 1);
    if unique == a.len() {
        return Vec::new();
    }
    let mut code = Vec::new();
    for index in a.iter().rev() {
        let depth = unique - 1 - index;
        match depth {
            0 => code.push(0x76),
            1 => code.push(0x78),
            _ => {
                number(&mut code, depth);
                code.push(0x79);
            }
        }
        code.push(0x6b);
    }
    for _ in 0..unique / 2 {
        code.push(0x6d);
    }
    if unique % 2 == 1 {
        code.push(0x75);
    }
    for _ in &a {
        code.push(0x6c);
    }
    code
}

fn grouped_body(role: &str, args: &[i64], wires: &[usize]) -> Result<Vec<u8>> {
    require(PATTERNS.contains(&args), "closed grouped pattern")?;
    let formal = args.iter().map(|n| 2 * (*n as usize) + 1).sum::<usize>();
    require(formal == wires.len(), "grouped formal framing")?;
    let mut raw = vec![0x51];
    let mut offset = 0;
    for n in args {
        let length = 2 * (*n as usize) + 1;
        for _ in 0..length {
            number(&mut raw, formal - offset);
            raw.push(0x79);
        }
        raw.extend(crate::body_pins::frozen_row_body(*n as usize)?);
        raw.push(0x9a);
        offset += length;
    }
    raw.push(0x6b);
    raw.extend(std::iter::repeat(0x6d).take(formal / 2));
    if formal % 2 == 1 {
        raw.push(0x75);
    }
    raw.push(0x6c);
    require(
        sha(&raw) == crate::body_pins::expected_raw_body_sha256(role, args)?,
        "independent frozen-row wrapper differs",
    )?;
    let mut body = expansion(wires);
    body.extend(raw);
    require(
        body.len() <= 20000
            && sha(&body) == crate::body_pins::expected_body_sha256(role, args, &aliases(wires))?,
        "new grouped body pin/unchanged cap",
    )?;
    Ok(body)
}
pub struct Projection {
    pub old_to_new: Vec<(usize, Option<usize>)>,
    pub new_to_old: Vec<Vec<usize>>,
    pub multiplication_prefixes: Vec<String>,
    pub groups: Vec<(String, usize, Vec<usize>)>,
}
impl Projection {
    fn json(&self) -> Value {
        json!({"schema":"bitvm2-nova-grouped-convolution-projection/v1","old_to_new":self.old_to_new,"new_to_old":self.new_to_old,"multiplication_prefixes":self.multiplication_prefixes,"groups":self.groups})
    }
}
fn transformed(old: &GraphSpec, new: &GraphSpec, b: &Baseline) -> Result<Projection> {
    let mut batches: Vec<(String, BTreeMap<(usize, usize), usize>)> = Vec::new();
    for (i, l) in old.leaves[..b.arithmetic].iter().enumerate() {
        if l.kind != "conv_ab" {
            continue;
        }
        let name = &old.words[*l.wires.last().ok_or("AB output")?].name;
        let (prefix, tail) = name.rsplit_once("/ab/").ok_or("AB source path")?;
        let (k, r) = tail.split_once('/').ok_or("AB cell path")?;
        let key = (k.parse::<usize>()?, r.parse::<usize>()?);
        let pos = if let Some(pos) = batches.iter().position(|(p, _)| p == prefix) {
            pos
        } else {
            batches.push((prefix.into(), BTreeMap::new()));
            batches.len() - 1
        };
        require(batches[pos].1.insert(key, i).is_none(), "duplicate AB cell")?;
    }
    require(
        batches.len() == if b.points.is_some() { 13 } else { 1 },
        "closed multiplication batch count",
    )?;
    let mut replacements = BTreeMap::new();
    let mut removed = HashSet::new();
    for (prefix, batch) in &batches {
        require(batch.len() == 280, "complete280AB batch")?;
        for (gi, g) in groups()?.iter().enumerate() {
            let rows = g
                .iter()
                .map(|c| {
                    batch
                        .get(&(c.column, c.block))
                        .copied()
                        .ok_or_else(|| "missing AB cell".into())
                })
                .collect::<Result<Vec<_>>>()?;
            let anchor = *rows.iter().min().ok_or("group anchor")?;
            replacements.insert(anchor, (prefix.clone(), gi, rows.clone()));
            removed.extend(rows);
        }
    }
    let mut expected = Vec::new();
    let mut reverse = Vec::new();
    let mut forward = vec![(usize::MAX, None); old.leaves.len()];
    let mut records = Vec::new();
    let mut bodies = BTreeMap::new();
    for i in 0..b.arithmetic {
        if let Some((prefix, gi, rows)) = replacements.get(&i) {
            let wires = rows
                .iter()
                .flat_map(|j| old.leaves[*j].wires.iter().copied())
                .collect::<Vec<_>>();
            let args = rows
                .iter()
                .map(|j| old.leaves[*j].argument[0])
                .collect::<Vec<_>>();
            let body = grouped_body(&old.field_role, &args, &wires)?;
            let sha = sha(&body);
            bodies.insert(sha.clone(), hex::encode(body));
            let ordinal = expected.len();
            expected.push(Leaf {
                kind: "conv_ab_all".into(),
                argument: args,
                wires,
                body_sha256: sha,
            });
            reverse.push(rows.clone());
            for (row, previous) in rows.iter().enumerate() {
                forward[*previous] = (ordinal, Some(row));
            }
            records.push((prefix.clone(), *gi, rows.clone()));
        } else if !removed.contains(&i) {
            let ordinal = expected.len();
            let l = old.leaves[i].clone();
            bodies.insert(l.body_sha256.clone(), old.bodies[&l.body_sha256].clone());
            expected.push(l);
            reverse.push(vec![i]);
            forward[i] = (ordinal, None);
        }
    }
    for i in b.arithmetic..old.leaves.len() {
        let ordinal = expected.len();
        let l = old.leaves[i].clone();
        bodies.insert(l.body_sha256.clone(), old.bodies[&l.body_sha256].clone());
        expected.push(l);
        reverse.push(vec![i]);
        forward[i] = (ordinal, None);
    }
    require(
        expected.len() == old.leaves.len() - 208 * batches.len()
            && new.leaves.len() == expected.len()
            && new.bodies == bodies,
        "candidate exact new leaf/body catalogue",
    )?;
    for (a, e) in new.leaves.iter().zip(&expected) {
        require(
            a.kind == e.kind
                && a.argument == e.argument
                && a.wires == e.wires
                && a.body_sha256 == e.body_sha256,
            "candidate grouped/unchanged occurrence projection",
        )?;
    }
    require(
        forward.iter().all(|x| x.0 != usize::MAX),
        "all old leaves projected",
    )?;
    new.identity()?;
    Ok(Projection {
        old_to_new: forward,
        new_to_old: reverse,
        multiplication_prefixes: batches.into_iter().map(|x| x.0).collect(),
        groups: records,
    })
}
fn truth(spec: &GraphSpec, values: &[u32]) -> Result<Vec<Option<bool>>> {
    let p = modulus(&spec.field_role)?;
    spec.leaves
        .iter()
        .map(|l| {
            let v = l
                .wires
                .iter()
                .map(|i| values.get(*i).copied().ok_or_else(|| "truth word".into()))
                .collect::<Result<Vec<_>>>()?;
            if l.wires
                .iter()
                .zip(&v)
                .any(|(i, v)| *v >= spec.words[*i].bound)
            {
                return Ok(Some(false));
            }
            if l.kind != "conv_ab_all" {
                return predicate(&l.kind, &l.argument, &v, &p);
            }
            let mut at = 0;
            let mut all = true;
            for n in &l.argument {
                let len = 2 * (*n as usize) + 1;
                let row =
                    predicate("conv_ab", &[*n], &v[at..at + len], &p)?.ok_or("AB never aborts")?;
                all &= row;
                at += len;
            }
            require(at == v.len(), "all grouped rows covered")?;
            Ok(Some(all))
        })
        .collect()
}

fn fixture(profile: usize) -> &'static str {
    match profile {
        0 | 4..=14 | 18 | 19 => "mul-distinct",
        1 | 15 => "mul-equal-distinct",
        2 | 16 => "square",
        3 => "point",
        17 => "point-inactive",
        _ => "invalid",
    }
}
fn recipe(spec: &GraphSpec, profile: usize) -> Result<(Vec<u32>, BTreeSet<usize>)> {
    let base = expected_values(spec, fixture(profile), false)?;
    let mut values = if matches!(profile, 15 | 16) {
        expected_values(spec, fixture(profile), true)?
    } else {
        base.clone()
    };
    let word = if (4..=14).contains(&profile) {
        let (shape, row) = if profile < 8 {
            (0, profile - 4)
        } else if profile < 12 {
            (1, profile - 8)
        } else {
            (2, profile - 12)
        };
        let groups = groups()?;
        let g = groups
            .iter()
            .find(|g| g.iter().map(|c| c.pairs.len() as i64).collect::<Vec<_>>() == PATTERNS[shape])
            .ok_or("profile row group")?;
        let c = &g[row];
        Some((format!("product/ab/{}/{}", c.column, c.block), None))
    } else {
        match profile {
            17 => Some(("left/x2/ab/0/0".into(), None)),
            18 => Some(("product/a/byte/0".into(), Some(256))),
            19 => {
                let groups = groups()?;
                let group = groups
                    .iter()
                    .find(|g| {
                        g.iter().map(|c| c.pairs.len() as i64).collect::<Vec<_>>() == PATTERNS[1]
                    })
                    .ok_or("first all-four group for late signed-invalid subtotal")?;
                let cell = group.last().ok_or("late all-four row")?;
                Some((
                    format!("product/ab/{}/{}", cell.column, cell.block),
                    Some(u32::MAX),
                ))
            }
            _ => None,
        }
    };
    if let Some((name, replacement)) = word {
        let i = spec
            .words
            .iter()
            .position(|w| w.name == name)
            .ok_or("profile exact word")?;
        values[i] = replacement.unwrap_or(values[i] + 1);
    }
    let changed = values
        .iter()
        .zip(&base)
        .enumerate()
        .filter_map(|(i, (a, b))| (a != b).then_some(i))
        .collect();
    Ok((values, changed))
}
fn selected(
    spec: &GraphSpec,
    t: &[Option<bool>],
    changed: &BTreeSet<usize>,
    all: bool,
) -> Vec<usize> {
    if all {
        return (0..spec.leaves.len()).collect();
    }
    let mut out = t
        .iter()
        .enumerate()
        .filter_map(|(i, v)| (*v != Some(true)).then_some(i))
        .collect::<BTreeSet<_>>();
    let mut kinds = HashSet::new();
    for (i, l) in spec.leaves.iter().enumerate() {
        if kinds.insert(l.kind.as_str())
            || l.kind == "field_valid"
            || l.wires.iter().any(|w| changed.contains(w))
        {
            out.insert(i);
        }
    }
    out.into_iter().collect()
}
pub struct ComponentFacts {
    pub values: Vec<u32>,
    pub truth: Vec<Option<bool>>,
    pub false_ordinals: Vec<usize>,
    pub abort_ordinals: Vec<usize>,
    pub selected_ordinals: Vec<usize>,
    pub program_sha256: String,
    pub catalogue_id: String,
    pub global_ids: Vec<String>,
}
pub struct SubtotalLink {
    pub word_index: usize,
    pub baseline_ab_ordinal: usize,
    pub baseline_ab_occurrence: usize,
    pub candidate_group_ordinal: usize,
    pub candidate_group_occurrence: usize,
    pub baseline_column_ordinal: usize,
    pub baseline_column_occurrence: usize,
    pub candidate_column_ordinal: usize,
    pub candidate_column_occurrence: usize,
}
pub struct CarryLink {
    pub word_index: usize,
    pub baseline_producer: usize,
    pub baseline_producer_occurrence: usize,
    pub baseline_consumer: usize,
    pub baseline_consumer_occurrence: usize,
    pub candidate_producer: usize,
    pub candidate_producer_occurrence: usize,
    pub candidate_consumer: usize,
    pub candidate_consumer_occurrence: usize,
}
pub struct SourceFacts {
    pub baseline: ComponentFacts,
    pub candidate: ComponentFacts,
    pub values: Vec<u32>,
    pub source_sha256: String,
    pub source_maps_sha256: String,
    pub manifest: Value,
    pub source_maps: Value,
    pub projection: Projection,
    pub curve_verdict: Value,
    pub subtotal_links: Vec<SubtotalLink>,
    pub carry_links: Vec<CarryLink>,
}
fn actual_links(
    old: &GraphSpec,
    new: &GraphSpec,
    pr: &Projection,
) -> Result<(Vec<SubtotalLink>, Vec<CarryLink>)> {
    let mut sub = Vec::new();
    for (i, l) in old.leaves.iter().enumerate() {
        if l.kind != "conv_ab" {
            continue;
        }
        let word = *l.wires.last().ok_or("AB last formal")?;
        let (gi, row) = pr.old_to_new[i];
        let row = row.ok_or("AB grouped row")?;
        let offset = pr.new_to_old[gi][..row]
            .iter()
            .map(|j| old.leaves[*j].wires.len())
            .sum::<usize>();
        let formal = offset + l.wires.len() - 1;
        let (column, occurrence) = old
            .leaves
            .iter()
            .enumerate()
            .filter(|(_, l)| l.kind == "conv_column")
            .find_map(|(j, l)| l.wires.iter().position(|w| *w == word).map(|f| (j, f)))
            .ok_or("subtotal actual column consumer")?;
        let candidate_column = pr.old_to_new[column].0;
        require(
            new.leaves[gi].wires[formal] == word
                && new.leaves[candidate_column].wires[occurrence] == word,
            "subtotal coordinate projection",
        )?;
        sub.push(SubtotalLink {
            word_index: word,
            baseline_ab_ordinal: i,
            baseline_ab_occurrence: l.wires.len() - 1,
            candidate_group_ordinal: gi,
            candidate_group_occurrence: formal,
            baseline_column_ordinal: column,
            baseline_column_occurrence: occurrence,
            candidate_column_ordinal: candidate_column,
            candidate_column_occurrence: occurrence,
        });
    }
    let mut carry = Vec::new();
    for prefix in &pr.multiplication_prefixes {
        for k in 1..64 {
            let name = format!("{prefix}/carry/{k}");
            let word = old
                .words
                .iter()
                .position(|w| w.name == name)
                .ok_or("carry word")?;
            let occurrences = old
                .leaves
                .iter()
                .enumerate()
                .filter(|(_, l)| l.kind == "conv_column")
                .flat_map(|(i, l)| {
                    l.wires
                        .iter()
                        .enumerate()
                        .filter(move |(_, w)| **w == word)
                        .map(move |(f, _)| (i, f))
                })
                .collect::<Vec<_>>();
            require(
                occurrences.len() == 2,
                "carry has exactly2adjacent column occurrences",
            )?;
            let (a, af) = occurrences[0];
            let (b, bf) = occurrences[1];
            require(
                old.leaves[a].argument[0] + old.leaves[a].argument[1] + 1 == af as i64
                    && old.leaves[b].argument[0] + old.leaves[b].argument[1] == bf as i64,
                "carry outgoing/incoming formal order",
            )?;
            let ca = pr.old_to_new[a].0;
            let cb = pr.old_to_new[b].0;
            require(
                new.leaves[ca].wires[af] == word && new.leaves[cb].wires[bf] == word,
                "candidate exact carry identity",
            )?;
            carry.push(CarryLink {
                word_index: word,
                baseline_producer: a,
                baseline_producer_occurrence: af,
                baseline_consumer: b,
                baseline_consumer_occurrence: bf,
                candidate_producer: ca,
                candidate_producer_occurrence: af,
                candidate_consumer: cb,
                candidate_consumer_occurrence: bf,
            });
        }
    }
    require(
        sub.len() == 280 * pr.multiplication_prefixes.len()
            && carry.len() == 63 * pr.multiplication_prefixes.len(),
        "all subtotal/carry links",
    )?;
    Ok((sub, carry))
}
fn mature<A: CurveAffine>(
    ports: &(PointPorts, PointPorts, PointPorts),
    values: &[u32],
    p: &BigUint,
) -> Result<Value> {
    let a = native_point::<A>(values, &ports.0, p)?;
    let b = native_point::<A>(values, &ports.1, p)?;
    let c = native_point::<A>(values, &ports.2, p)?;
    let valid = a.is_some() && b.is_some() && c.is_some();
    let addition = if let (Some(a), Some(b), Some(c)) = (a, b, c) {
        (a + b).to_affine() == c
    } else {
        false
    };
    require(
        valid && addition,
        "closed points must pass actual matureHalo2decode/addition",
    )?;
    Ok(
        json!({"applicable":true,"left_valid":valid,"right_valid":valid,"result_valid":valid,"addition_holds":addition}),
    )
}
fn source_metadata(
    old: &GraphSpec,
    new: &GraphSpec,
    b: &Baseline,
    p: &Projection,
    fixture: &str,
) -> Result<(Value, Value)> {
    let word_catalogue = old
        .words
        .iter()
        .map(|w| json!([w.name, w.bound]))
        .collect::<Vec<_>>();
    let candidate_arithmetic = new.leaves.len() - b.fields.len();
    let maps = json!({"schema":"bitvm2-nova-grouped-convolution-source-maps/v1","compiler":"grouped-convolution-v1","word_catalogue_sha256":hash(&json!(word_catalogue))?,"baseline_field_leaves":b.fields.iter().enumerate().map(|(i,(n,_))|json!([n,b.arithmetic+i])).collect::<Vec<_>>(),"candidate_field_leaves":b.fields.iter().enumerate().map(|(i,(n,_))|json!([n,candidate_arithmetic+i])).collect::<Vec<_>>(),"old_to_new":p.old_to_new,"new_to_old":p.new_to_old,"multiplication_prefixes":p.multiplication_prefixes,"groups":p.groups});
    let mut meta = json!({"schema":"bitvm2-nova-grouped-convolution-source/v1","compiler":"grouped-convolution-v1","context":old.context,"field_role":old.field_role,"modulus":modulus_text(&old.field_role)?,"operation_id":old.operation_id,"fixture":fixture,"baseline_program_sha256":old.program_sha256,"candidate_program_sha256":new.program_sha256,"baseline_catalogue_id":hex::encode(old.identity()?),"candidate_catalogue_id":hex::encode(new.identity()?),"words":old.words.len(),"baseline_leaves":old.leaves.len(),"candidate_leaves":new.leaves.len(),"canonical_fields":b.fields.len(),"multiplications":p.multiplication_prefixes.len(),"source_maps_sha256":hash(&maps)?,"scope":"closed-matched-cost-experiment-frozen-legacy-WOTS"});
    for name in [
        "complete_verifier",
        "proof_verified",
        "nova_transcript_bound",
        "production_assertion_binding",
        "bitcoin_transaction_graph",
        "taproot_coverage_verified",
    ] {
        meta.as_object_mut()
            .ok_or("metadata")?
            .insert(name.into(), json!(false));
    }
    Ok((maps, meta))
}
pub(crate) fn admit(
    baseline_case: &Case,
    candidate_case: &Case,
    d: &Descriptor,
    context: &str,
    op: &str,
) -> Result<SourceFacts> {
    let profile = PROFILES
        .iter()
        .position(|x| *x == d.profile)
        .ok_or("closed40caseprofile")?;
    let role = &d.role;
    modulus_text(role)?;
    require(
        context == sha(b"BITVM2-NOVA/GROUPED-CONVOLUTION-CONFORMANCE/v1")
            && op == "benchmark/grouped-convolution/v1"
            && d.fixture == fixture(profile)
            && d.name
                == format!(
                    "{}/{profile:02}",
                    if role == "pallas_base" { "p" } else { "v" }
                ),
        "fixed context/role/op/profile/fixture",
    )?;
    id32(context)?;
    let old = &baseline_case.spec;
    let new = &candidate_case.spec;
    for (index, case) in [baseline_case, candidate_case].iter().enumerate() {
        require(
            case.name
                == format!(
                    "{}/{}",
                    d.name,
                    if index == 0 { "baseline" } else { "candidate" }
                )
                && case.spec.context == context
                && case.spec.field_role == *role
                && case.spec.operation_id == format!("{op}/{}", d.fixture),
            "paired case identity",
        )?;
    }
    require(
        old.words.len() == new.words.len()
            && old
                .words
                .iter()
                .zip(&new.words)
                .all(|(a, b)| a.name == b.name && a.bound == b.bound),
        "exact identical paired word declarations/bounds",
    )?;
    let b = baseline(old, &d.fixture)?;
    let projection = transformed(old, new, &b)?;
    let (old_program, new_program) = (
        program_digest(old, b.arithmetic, &b.fields, false)?,
        program_digest(new, new.leaves.len() - b.fields.len(), &b.fields, true)?,
    );
    require(
        old.program_sha256 == old_program && new.program_sha256 == new_program,
        "independent program/domain identities",
    )?;
    let (values, changed) = recipe(old, profile)?;
    require(
        baseline_case.words == values && candidate_case.words == values,
        "all independent raw-u32 values paired before keys",
    )?;
    let all = profile < 4;
    let ta = truth(old, &values)?;
    let tb = truth(new, &values)?;
    let sa = selected(old, &ta, &changed, all);
    let sb = selected(new, &tb, &changed, all);
    require(
        all || sa.len() + sb.len() <= 128,
        "all false/abort/affected/control union TOTAL<=128",
    )?;
    let facts = |index: usize,
                 case: &Case,
                 t: Vec<Option<bool>>,
                 s: Vec<usize>|
     -> Result<ComponentFacts> {
        let a = &d.adapters[index];
        let false_ordinals = t
            .iter()
            .enumerate()
            .filter_map(|(i, v)| (*v == Some(false)).then_some(i))
            .collect::<Vec<_>>();
        let abort_ordinals = t
            .iter()
            .enumerate()
            .filter_map(|(i, v)| v.is_none().then_some(i))
            .collect::<Vec<_>>();
        require(
            a.index == index && a.label == crate::transport::LABELS[index],
            "adapterindex/label",
        )?;
        require(
            a.words == old.words.len()
                && a.leaves == case.spec.leaves.len()
                && a.arithmetic_constraints == case.spec.leaves.len() - b.fields.len()
                && a.canonical_fields == b.fields.len()
                && a.expected_false == false_ordinals
                && a.expected_abort_ordinals == abort_ordinals
                && case.measure_all == all,
            "independent completeclassification/census",
        )?;
        require(
            if all {
                a.execution_mode == "all" && a.selected_ordinals.is_none()
            } else {
                a.execution_mode == "selected" && a.selected_ordinals.as_ref() == Some(&s)
            },
            "exact measured scope",
        )?;
        require(
            case.checks.len() == s.len()
                && case
                    .checks
                    .iter()
                    .zip(&s)
                    .all(|(c, i)| c.ordinal == *i && c.expected_correct == t[*i]),
            "ordered checks from independent truth",
        )?;
        let program = case.spec.program_sha256.clone();
        let catalogue = hex::encode(case.spec.identity()?);
        require(
            a.program_sha256 == program
                && a.catalogue_id == catalogue
                && case.expected_spec_id == catalogue,
            "program/catalogue expectedpins",
        )?;
        Ok(ComponentFacts {
            values: values.clone(),
            truth: t,
            false_ordinals,
            abort_ordinals,
            selected_ordinals: s,
            program_sha256: program,
            catalogue_id: catalogue,
            global_ids: old.words.iter().map(|w| w.name.clone()).collect(),
        })
    };
    let baseline = facts(0, baseline_case, ta, sa)?;
    let candidate = facts(1, candidate_case, tb, sb)?;
    let (maps, meta) = source_metadata(old, new, &b, &projection, &d.fixture)?;
    let maps_sha = hash(&maps)?;
    let source_sha = domain_hash(b"BITVM2-NOVA/GROUPED-CONVOLUTION-SOURCE/v1\0", &meta)?;
    require(
        d.source_maps_sha256 == maps_sha
            && d.source_sha256 == source_sha
            && d.word_catalogue_sha256
                == hash(&json!(old
                    .words
                    .iter()
                    .map(|w| json!([w.name, w.bound]))
                    .collect::<Vec<_>>()))?
            && d.assignment_sha256 == hash(&json!(values))?,
        "independent source/maps/wordcatalogue/assignment pins",
    )?;
    let (subtotal_links, carry_links) = actual_links(old, new, &projection)?;
    let curve_verdict = if let Some(ports) = &b.points {
        let p = modulus(role)?;
        if role == "pallas_base" {
            mature::<PallasAffine>(ports, &values, &p)?
        } else {
            mature::<VestaAffine>(ports, &values, &p)?
        }
    } else {
        json!({"applicable":false})
    };
    Ok(SourceFacts {
        baseline,
        candidate,
        values,
        source_sha256: source_sha,
        source_maps_sha256: maps_sha,
        manifest: meta,
        source_maps: maps,
        projection,
        curve_verdict,
        subtotal_links,
        carry_links,
    })
}

// Hosted Cargo units only; none were executed locally during implementation.
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn deterministic_partition_and_alias_union() {
        let groups = groups().unwrap();
        let original = cells();
        let mut all = BTreeSet::new();
        let mut layouts = BTreeSet::new();
        let mut ordinary = 0;
        let mut square = 0;
        for is_square in [false, true] {
            for g in &groups {
                let mut wires = Vec::new();
                for c in g {
                    if !is_square {
                        assert!(all.insert((c.column, c.block)));
                    }
                    for (i, j) in &c.pairs {
                        wires.extend([*i, if is_square { *j } else { 32 + *j }]);
                    }
                    wires.push(64 + c.column * 8 + c.block);
                }
                let count = wires.iter().collect::<HashSet<_>>().len();
                if is_square {
                    square += count
                } else {
                    ordinary += count
                }
                assert!(count <= 15);
                layouts.insert((
                    g.iter().map(|c| c.pairs.len() as i64).collect::<Vec<_>>(),
                    aliases(&wires),
                ));
            }
        }
        assert_eq!(all.len(), 280);
        assert_eq!(original.iter().map(|c| c.pairs.len()).sum::<usize>(), 1024);
        assert_eq!(groups.len(), 72);
        assert_eq!(ordinary, 1008);
        assert_eq!(square, 952);
        assert_eq!(layouts.len(), 10);
        for role in ["pallas_base", "vesta_base"] {
            for (args, alias) in &layouts {
                let body = grouped_body(role, args, alias).unwrap();
                assert!(body.len() <= 20000);
                assert_eq!(
                    sha(&body),
                    crate::body_pins::expected_body_sha256(role, args, alias).unwrap()
                );
            }
        }
    }
    #[test]
    fn coherent_cancel_does_not_become_residual_sum() {
        let a = [1u32, 1];
        let mut old = BTreeMap::new();
        for c in cells() {
            let value = c
                .pairs
                .iter()
                .map(|(i, j)| a.get(*i).copied().unwrap_or(0) * a.get(*j).copied().unwrap_or(0))
                .sum::<u32>();
            old.insert((c.column, c.block), value);
        }
        let mut forged = old.clone();
        forged.insert((0, 0), 2);
        forged.insert((1, 0), 1);
        let c = 65794u32.to_le_bytes();
        let mut carry = 0i64;
        for k in 0usize..64 {
            let ab = forged
                .iter()
                .filter(|((column, _), _)| *column == k)
                .map(|(_, v)| i64::from(*v))
                .sum::<i64>();
            let byte = i64::from(c.get(k).copied().unwrap_or(0));
            let next = ab + carry - byte;
            assert_eq!(next.rem_euclid(256), 0);
            carry = next.div_euclid(256);
            assert_eq!(carry, 0);
        }
        assert_eq!(
            (forged[&(0, 0)] as i64 - old[&(0, 0)] as i64)
                + (forged[&(1, 0)] as i64 - old[&(1, 0)] as i64),
            0
        );
        let first = &groups().unwrap()[0];
        assert!(!first
            .iter()
            .all(|cell| forged[&(cell.column, cell.block)] == old[&(cell.column, cell.block)]));
    }
    #[test]
    fn range_false_and_canonical_input_abort_are_distinct() {
        let p = modulus("pallas_base").unwrap();
        let mut values = vec![0; 27];
        values[..9].copy_from_slice(&digits(&p).unwrap());
        assert_eq!(predicate("add", &[], &values, &p).unwrap(), None);
        assert_eq!(
            predicate("field_valid", &[], &values[..9], &p).unwrap(),
            Some(false)
        );
        assert_eq!(
            predicate("conv_ab", &[1], &[1, 1, 2], &p).unwrap(),
            Some(false)
        );
    }
    #[test]
    fn strict_finite_identity_and_canonical_coordinates() {
        let p = modulus("pallas_base").unwrap();
        let z = BigUint::from(0u32);
        assert!(affine::<PallasAffine>(0, &z, &z, &p).is_none());
        assert!(affine::<PallasAffine>(1, &z, &z, &p).is_some());
        assert!(affine::<PallasAffine>(2, &z, &z, &p).is_none());
        assert!(affine::<PallasAffine>(0, &p, &z, &p).is_none());
    }
}
