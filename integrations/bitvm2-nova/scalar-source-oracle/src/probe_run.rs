//! Closed private point fixtures, independently reconstructed before signing.
//!
//! No supplied success/false-list, point map or numeric assignment is authority.
//! The caller's positive source is re-admitted, the entire private witness is
//! derived from a prescribed recipe, and only then may the generic runner sign.
use crate::{
    chain::{
        self,
        permutation::{self, Case},
        Basis, RecordSink,
    },
    conditional_point::{self, CheckedPoint, CurveVerdict},
    legacy_transport::{PointInputs, PointValue},
    Group, Probe, Run,
};
use bitvm2_nova_script_oracle::{engine::Metrics, registry::GraphSpec, wots::Result};
use num_bigint::BigUint;
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    path::Path,
};

const BASE: u32 = 1 << 29;
const WORDS: usize = 7498;
const LEAVES: usize = 6161;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Edge(usize),
    InvalidP,
    WrongE,
    WrongR,
    WrongFlag,
    NonzeroInfinity,
    Auxiliary,
    SignedBit,
    CoordinateModulus,
    CoordinateModulusPlusOne,
}

impl Kind {
    fn parse(category: &str, kind: &str, name: &str, prefix: &str) -> Result<Self> {
        if category == "point-edge" {
            for index in 0..6 {
                if kind == format!("point-edge-{index}") && name == format!("{prefix}/e{index}") {
                    return Ok(Self::Edge(index));
                }
            }
        } else if category == "point-negative" {
            for (index, (text, value)) in [
                ("invalid-P-b0", Self::InvalidP),
                ("wrong-E-b0", Self::WrongE),
                ("wrong-selected-R", Self::WrongR),
                ("wrong-R-flag", Self::WrongFlag),
                ("nonzero-infinity", Self::NonzeroInfinity),
                ("auxiliary-flip", Self::Auxiliary),
                ("signed-bit-two", Self::SignedBit),
                ("coordinate-modulus", Self::CoordinateModulus),
                (
                    "coordinate-modulus-plus-one",
                    Self::CoordinateModulusPlusOne,
                ),
            ]
            .into_iter()
            .enumerate()
            {
                if kind == text && name == format!("{prefix}/n{index}") {
                    return Ok(value);
                }
            }
        }
        Err("closed point edge/negative kind and identity required".into())
    }
}

fn modulus(role: &str) -> Result<BigUint> {
    let value = match role {
        "pallas_base" => {
            b"40000000000000000000000000000000224698fc094cf91b992d30ed00000001".as_slice()
        }
        "vesta_base" => {
            b"40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001".as_slice()
        }
        _ => return Err("closed point probe base ROLE NAME required".into()),
    };
    BigUint::parse_bytes(value, 16).ok_or_else(|| "fixed Pasta base modulus".into())
}

fn sub(x: &BigUint, y: &BigUint, p: &BigUint) -> BigUint {
    (x + p - y) % p
}
fn inverse(x: &BigUint, p: &BigUint) -> Result<BigUint> {
    if x == &BigUint::from(0u32) {
        return Err("zero denominator in finite point recipe".into());
    }
    Ok(x.modpow(&(p - BigUint::from(2u32)), p))
}
fn le32(value: &BigUint) -> Result<String> {
    let raw = value.to_bytes_le();
    if raw.len() > 32 {
        return Err("point recipe LE32 overflow".into());
    }
    let mut bytes = [0u8; 32];
    bytes[..raw.len()].copy_from_slice(&raw);
    Ok(hex::encode(bytes))
}
fn digits(value: &BigUint) -> Result<[u32; 9]> {
    if value.bits() > 261 {
        return Err("raw nine-limb integer overflow".into());
    }
    Ok(std::array::from_fn(|i| {
        ((value >> (29 * i))
            .to_u32_digits()
            .first()
            .copied()
            .unwrap_or(0))
            & (BASE - 1)
    }))
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Point {
    infinity: u32,
    x: BigUint,
    y: BigUint,
}
impl Point {
    fn identity() -> Self {
        Self {
            infinity: 1,
            x: BigUint::from(0u32),
            y: BigUint::from(0u32),
        }
    }
    fn finite(x: BigUint, y: BigUint) -> Self {
        Self { infinity: 0, x, y }
    }
    fn value(&self) -> Result<PointValue> {
        Ok(PointValue {
            infinity: self.infinity,
            x_le: le32(&self.x)?,
            y_le: le32(&self.y)?,
        })
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
    let (numerator, denominator) = if a == b {
        (
            (BigUint::from(3u32) * &a.x * &a.x) % p,
            (BigUint::from(2u32) * &a.y) % p,
        )
    } else {
        (sub(&b.y, &a.y, p), sub(&b.x, &a.x, p))
    };
    let slope = numerator * inverse(&denominator, p)? % p;
    let x = sub(&sub(&(&slope * &slope % p), &a.x, p), &b.x, p);
    let y = sub(&(&slope * sub(&a.x, &x, p) % p), &a.y, p);
    Ok(Point::finite(x, y))
}
fn fixed_points(p: &BigUint) -> Result<(Point, Point)> {
    let g = Point::finite(p - BigUint::from(1u32), BigUint::from(2u32));
    // Independent rational doubling formula for (-1,2), rather than a supplied
    // generator receipt or the witness-producing curve factory.
    let x = BigUint::from(41u32) * inverse(&BigUint::from(16u32), p)? % p;
    let y = sub(
        &BigUint::from(0u32),
        &(BigUint::from(299u32) * inverse(&BigUint::from(64u32), p)? % p),
        p,
    );
    Ok((g, Point::finite(x, y)))
}

struct Recipe {
    a: Point,
    p: Point,
    e: Point,
    r: Point,
    bit: u32,
    origin_bit: u32,
    delta_flip: bool,
}
impl Recipe {
    fn inputs(&self) -> Result<PointInputs> {
        Ok(PointInputs {
            bit: self.bit,
            point_A: self.a.value()?,
            point_P: self.p.value()?,
            point_E: self.e.value()?,
            point_R: self.r.value()?,
        })
    }
}
fn recipe(kind: Kind, p: &BigUint, canonical_bit: u32) -> Result<Recipe> {
    if canonical_bit > 1 {
        return Err("closed canonical selected bit required".into());
    }
    let (g, h) = fixed_points(p)?;
    let (mut a, mut point, mut bit) = (g.clone(), h.clone(), canonical_bit);
    if let Kind::Edge(index) = kind {
        let inverse = Point::finite(g.x.clone(), sub(&BigUint::from(0u32), &g.y, p));
        (a, point) = match index {
            0 => (Point::identity(), Point::identity()),
            1 => (Point::identity(), g.clone()),
            2 => (g.clone(), Point::identity()),
            3 => (g.clone(), inverse),
            4 => (g.clone(), g.clone()),
            5 => (g.clone(), h.clone()),
            _ => return Err("closed six edge indices required".into()),
        };
        bit = u32::from(index % 2 == 1);
    } else {
        match kind {
            Kind::InvalidP => {
                point = Point::finite(BigUint::from(1u32), BigUint::from(1u32));
                bit = 0;
            }
            Kind::WrongE | Kind::Auxiliary | Kind::SignedBit => bit = 0,
            Kind::NonzeroInfinity => {
                point = Point::finite(g.x.clone(), sub(&BigUint::from(0u32), &g.y, p));
                bit = 1;
            }
            _ => {}
        }
    }
    let e = match kind {
        Kind::InvalidP => h,
        Kind::WrongE => g,
        _ => add(&a, &point, p)?,
    };
    let mut r = if bit == 0 { a.clone() } else { e.clone() };
    match kind {
        Kind::WrongR => r = if bit == 0 { e.clone() } else { a.clone() },
        Kind::WrongFlag => r.infinity = 2,
        Kind::NonzeroInfinity => r.x = BigUint::from(1u32),
        Kind::CoordinateModulus => r.x = p.clone(),
        Kind::CoordinateModulusPlusOne => r.x = p + BigUint::from(1u32),
        _ => {}
    }
    Ok(Recipe {
        a,
        p: point,
        e,
        r,
        bit: if kind == Kind::SignedBit { 2 } else { bit },
        origin_bit: bit,
        delta_flip: kind == Kind::Auxiliary,
    })
}

/// Numerical witness producer for the already independently checked topology.
/// Every word must be written once. There is no zero-filled fallback and no
/// reading of the supplied assertion vector while producing expected values.
struct Witness<'a> {
    spec: &'a GraphSpec,
    slots: BTreeMap<&'a str, usize>,
    values: Vec<Option<u32>>,
    fields: BTreeMap<String, BigUint>,
    byte_fields: BTreeMap<String, [u32; 32]>,
    modulus: BigUint,
    exceptional: Option<&'static str>,
}
impl<'a> Witness<'a> {
    fn new(spec: &'a GraphSpec, p: &BigUint, kind: Kind) -> Result<Self> {
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
            exceptional: match kind {
                Kind::WrongFlag => Some("selected/infinity"),
                Kind::SignedBit => Some("select/bit"),
                _ => None,
            },
        })
    }
    fn set(&mut self, name: &str, value: u32) -> Result<()> {
        let slot = *self
            .slots
            .get(name)
            .ok_or_else(|| format!("missing closed witness word {name}"))?;
        let bound = self.spec.words[slot].bound;
        if (value >= bound && !(self.exceptional == Some(name) && bound == 2 && value == 2))
            || self.values[slot].is_some()
        {
            return Err(format!("closed witness bound/duplicate write differs: {name}").into());
        }
        self.values[slot] = Some(value);
        Ok(())
    }
    fn field(&mut self, name: &str, value: BigUint) -> Result<()> {
        if self.fields.contains_key(name) {
            return Err("duplicate witness field".into());
        }
        if !name.starts_with("selected/") && value >= self.modulus {
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
        self.field(name, &product % &self.modulus)?;
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
                let value = pairs.iter().map(|(i, j)| a[*i] * b[*j]).sum::<u32>();
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

fn expected_assignment(spec: &GraphSpec, r: &Recipe, p: &BigUint, kind: Kind) -> Result<Vec<u32>> {
    let mut w = Witness::new(spec, p, kind)?;
    w.field("constant/zero", BigUint::from(0u32))?;
    w.field("constant/five", BigUint::from(5u32))?;
    w.set("constant/false", 0)?;
    w.set("constant/true", 1)?;
    w.point("left", &r.a)?;
    w.point("right", &r.p)?;
    w.point("result", &r.e)?;
    w.add("sum-y", "left/y", "right/y")?;
    let case = if r.a.infinity == 1 {
        0
    } else if r.p.infinity == 1 {
        1
    } else if r.a.x == r.p.x && (&r.a.y + &r.p.y) % p == BigUint::from(0u32) {
        2
    } else if r.a == r.p {
        3
    } else {
        4
    };
    w.set("dispatch", case)?;
    w.sub("dx", "right/x", "left/x")?;
    w.sub("dy", "right/y", "left/y")?;
    w.add("twice-y", "left/y", "left/y")?;
    w.add("twice-x2", "left/x2", "left/x2")?;
    w.add("thrice-x2", "twice-x2", "left/x2")?;
    let (denominator, numerator) = if case == 4 {
        (sub(&r.p.x, &r.a.x, p), sub(&r.p.y, &r.a.y, p))
    } else {
        (
            (BigUint::from(2u32) * &r.a.y) % p,
            (BigUint::from(3u32) * &r.a.x * &r.a.x) % p,
        )
    };
    let slope = if matches!(case, 3 | 4) && denominator != BigUint::from(0u32) {
        numerator * inverse(&denominator, p)? % p
    } else {
        BigUint::from(0u32)
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
    let delta = r.a.infinity ^ r.e.infinity;
    w.set("select/bit", r.bit)?;
    w.set("select/infinity-delta", delta ^ u32::from(r.delta_flip))?;
    w.set("select/infinity-masked", r.origin_bit & delta)?;
    w.set("selected/infinity", r.r.infinity)?;
    w.field("selected/x", r.r.x.clone())?;
    w.field("selected/y", r.r.y.clone())?;
    w.finish()
}

fn same_inputs(a: &PointInputs, b: &PointInputs) -> bool {
    a.bit == b.bit
        && a.point_A == b.point_A
        && a.point_P == b.point_P
        && a.point_E == b.point_E
        && a.point_R == b.point_R
}
fn classify(case: &Case) -> Result<(Vec<usize>, Vec<usize>)> {
    let mut false_rows = Vec::new();
    let mut abort = Vec::new();
    for ordinal in 0..LEAVES {
        match conditional_point::truth(&case.spec, &case.words, ordinal)? {
            Some(true) => {}
            Some(false) => false_rows.push(ordinal),
            None => abort.push(ordinal),
        }
    }
    Ok((false_rows, abort))
}
fn selections(
    kind: Kind,
    spec: &GraphSpec,
    checked: &CheckedPoint,
    false_rows: &[usize],
    abort: &[usize],
    r: &Recipe,
) -> Result<(Vec<usize>, usize)> {
    let selected = if let Kind::Edge(_) = kind {
        let mut selected = (6116..6124)
            .chain([6159, 6160])
            .chain(false_rows.iter().copied())
            .collect::<BTreeSet<_>>();
        let mut shapes = HashSet::new();
        for ordinal in 0..LEAVES {
            if shapes.insert(permutation::auth_shape(spec, ordinal)) {
                selected.insert(ordinal);
            }
        }
        if shapes.len() > 107 {
            return Err("closed point edge auth-shape budget".into());
        }
        selected.into_iter().collect::<Vec<_>>()
    } else {
        match kind {
            Kind::InvalidP => {
                let field = |name: &str| {
                    checked
                        .fields
                        .iter()
                        .find(|(actual, _)| actual == name)
                        .map(|(_, indices)| indices)
                        .ok_or("closed field absent")
                };
                let y2 = field("right/y2")?;
                let rhs = field("right/curve-rhs")?;
                spec.leaves
                    .iter()
                    .enumerate()
                    .filter_map(|(i, leaf)| {
                        (leaf.kind == "gate_equal"
                            && leaf.argument == [0]
                            && leaf.wires.len() == 19
                            && leaf.wires[1..10] == y2[..]
                            && leaf.wires[10..19] == rhs[..])
                            .then_some(i)
                    })
                    .collect()
            }
            Kind::WrongE => vec![*false_rows
                .iter()
                .find(|i| **i < 6116)
                .ok_or("wrong E must refute the complete child")?],
            Kind::WrongR => vec![if r.origin_bit == 0 { 6119 } else { 6121 }],
            Kind::WrongFlag => vec![6118, 6123],
            Kind::NonzeroInfinity => vec![6121, 6123],
            Kind::Auxiliary => vec![6116],
            Kind::SignedBit => vec![6117, 6119, 6120, 6121, 6122],
            Kind::CoordinateModulus | Kind::CoordinateModulusPlusOne => vec![6159],
            Kind::Edge(_) => return Err("edge selection internal dispatch".into()),
        }
    };
    let edge = matches!(kind, Kind::Edge(_));
    if selected.is_empty()
        || selected.len() > if edge { 128 } else { 12 }
        || selected.windows(2).any(|pair| pair[0] >= pair[1])
        || selected.iter().any(|i| *i >= LEAVES || abort.contains(i))
        || (!edge && selected.iter().any(|i| !false_rows.contains(i)))
    {
        return Err("closed point selected source/false/abort set differs".into());
    }
    if kind == Kind::InvalidP && selected.len() != 1 {
        return Err("one exact invalid-P membership path required".into());
    }
    let chosen = if edge { 6123 } else { selected[0] };
    Ok((selected, chosen))
}
fn mature_verdict(kind: Kind, v: CurveVerdict) -> Result<()> {
    let all = v.a_valid && v.p_valid && v.e_valid && v.r_valid;
    let accepted = match kind {
        Kind::Edge(_) | Kind::Auxiliary => {
            all && v.bit_valid && v.addition_holds && v.selection_holds
        }
        Kind::InvalidP => {
            v.a_valid && !v.p_valid && v.e_valid && v.r_valid && v.bit_valid && !v.selection_holds
        }
        Kind::WrongE => all && v.bit_valid && !v.addition_holds && v.selection_holds,
        Kind::WrongR => all && v.bit_valid && v.addition_holds && !v.selection_holds,
        Kind::SignedBit => all && !v.bit_valid && v.addition_holds && !v.selection_holds,
        Kind::WrongFlag
        | Kind::NonzeroInfinity
        | Kind::CoordinateModulus
        | Kind::CoordinateModulusPlusOne => {
            v.a_valid && v.p_valid && v.e_valid && !v.r_valid && v.bit_valid && !v.selection_holds
        }
    };
    if !accepted {
        return Err(
            "independent mature all-point curve classification differs from closed recipe".into(),
        );
    }
    Ok(())
}

pub(crate) fn run(
    request: &Probe,
    root: &Path,
    g: &Group,
    run: &Run,
    _basis: &Basis,
    main_keys: &HashSet<[u8; 32]>,
    records: &mut RecordSink,
    metrics: &mut Metrics,
) -> Result<Value> {
    let prefix = match g.role.as_str() {
        "pallas_scalar" if g.base_role == "pallas_base" => "p",
        "vesta_scalar" if g.base_role == "vesta_base" => "v",
        _ => return Err("closed scalar/base role NAME pairing required".into()),
    };
    if g.profile != "honest"
        || g.name != format!("{prefix}/h")
        || request.source_case != g.name
        || request.role != g.role
        || request.field_role != g.base_role
        || request.source_component != Some(10)
        || g.bit_index != 0
        || g.selected_bit != g.canonical_bit
    {
        return Err("private point requires its actual positive fixed-bit source".into());
    }
    let kind = Kind::parse(&request.category, &request.kind, &request.name, prefix)?;
    let p = modulus(&g.base_role)?;
    let (fixed_g, fixed_h) = fixed_points(&p)?;
    if g.point_A != fixed_g.value()? || g.point_P != fixed_h.value()? {
        return Err("closed TEST points G/H differ".into());
    }
    let closed = recipe(kind, &p, g.canonical_bit)?;
    if !same_inputs(&request.point_inputs()?, &closed.inputs()?) {
        return Err("closed typed point/bit inputs differ".into());
    }
    let (positive, source) = crate::prepare_point_source(run, g, root)?;
    drop(positive); // Keep no second full point catalogue while loading the probe.
    if request.source_sha256 != source.source_sha256
        || request.source_maps_sha256 != source.source_maps_sha256
        || request.program_sha256 != source.program_sha256
        || request.catalogue_id != source.catalogue_id
        || request.operation_id != g.components[10].descriptor.operation_id
        || request.words != WORDS
        || request.leaves != LEAVES
    {
        return Err(
            "private point must retain the independently re-admitted source identity".into(),
        );
    }
    let raw = chain::checked_file(
        root,
        &request.filename,
        chain::INPUT_CAP,
        &request.file_sha256,
        request.file_bytes,
    )?;
    let case: Case = serde_json::from_slice(&raw)?;
    if case.name != request.name
        || !case.measure_all
        || case.words.len() != WORDS
        || case.expected_spec_id != source.catalogue_id
        || case.spec.identity()? != permutation::digest(&source.catalogue_id)?
    {
        return Err("private point case exact source/name/count differs".into());
    }
    let checked = conditional_point::check(
        &case.spec,
        &run.context,
        &g.base_role,
        g.bit_index,
        &request.operation_id,
        &source.source_maps,
    )?;
    drop(source);
    drop(raw);
    let expected = expected_assignment(&case.spec, &closed, &p, kind)?;
    if case.words != expected {
        return Err("all7498 independently reconstructed private witness words differ".into());
    }
    drop(expected);
    let (false_rows, abort) = classify(&case)?;
    if !abort.is_empty()
        || request.expected_false != false_rows
        || request.expected_abort_ordinals != abort
    {
        return Err(
            "closed private false/abort classification differs; abort is not disproof".into(),
        );
    }
    if matches!(kind, Kind::Edge(_)) && !false_rows.is_empty() {
        return Err("valid point edge has a false predicate".into());
    }
    let (selected, chosen) = selections(kind, &case.spec, &checked, &false_rows, &abort, &closed)?;
    if request.execution_mode != "selected"
        || request.selected_ordinals.as_deref() != Some(selected.as_slice())
        || request.selected_leaf != chosen
        || request.expected_selected_correct == false_rows.contains(&chosen)
        || case.checks.len() != selected.len()
        || case.checks.iter().zip(&selected).any(|(check, ordinal)| {
            check.ordinal != *ordinal || check.expected_correct == false_rows.contains(ordinal)
        })
    {
        return Err("closed private selected ordinal/truth observations differ".into());
    }
    mature_verdict(
        kind,
        conditional_point::checked_curve(&case.spec, &case.words)?,
    )?;
    crate::execute_private(request, &case, main_keys, records, metrics)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::legacy_transport::fixed_hex;
    #[test]
    fn closed_probe_names_do_not_accept_aliases_or_new_categories() {
        assert_eq!(
            Kind::parse("point-edge", "point-edge-0", "p/e0", "p").unwrap(),
            Kind::Edge(0)
        );
        assert_eq!(
            Kind::parse("point-negative", "signed-bit-two", "v/n6", "v").unwrap(),
            Kind::SignedBit
        );
        for (category, kind, name) in [
            ("point-edge", "point-edge-00", "p/e0"),
            ("point-edge", "point-edge-6", "p/e6"),
            ("point-edge", "point-edge-0", "v/e0"),
            ("point-negative", "signed-bit-two", "p/n5"),
            ("receipt", "point-edge-0", "p/e0"),
        ] {
            assert!(Kind::parse(category, kind, name, "p").is_err());
        }
    }
    #[test]
    fn all_six_recipes_cover_complete_addition_and_both_boolean_values() {
        for role in ["pallas_base", "vesta_base"] {
            let p = modulus(role).unwrap();
            let (g, h) = fixed_points(&p).unwrap();
            assert_eq!(add(&g, &g, &p).unwrap(), h);
            let mut bits = HashSet::new();
            for index in 0..6 {
                let r = recipe(Kind::Edge(index), &p, 1).unwrap();
                bits.insert(r.bit);
                assert_eq!(r.e, add(&r.a, &r.p, &p).unwrap());
                assert_eq!(r.r, if r.bit == 0 { r.a.clone() } else { r.e.clone() });
            }
            assert_eq!(bits, HashSet::from([0, 1]));
        }
    }
    #[test]
    fn signed_and_noncanonical_negative_ports_are_preserved_not_reduced() {
        for role in ["pallas_base", "vesta_base"] {
            let p = modulus(role).unwrap();
            let bit = recipe(Kind::SignedBit, &p, 1).unwrap();
            assert_eq!((bit.bit, bit.origin_bit), (2, 0));
            let flag = recipe(Kind::WrongFlag, &p, 1).unwrap();
            assert_eq!(flag.r.infinity, 2);
            let nonzero = recipe(Kind::NonzeroInfinity, &p, 0).unwrap();
            assert_eq!((nonzero.r.infinity, nonzero.r.x), (1, BigUint::from(1u32)));
            for (kind, offset) in [
                (Kind::CoordinateModulus, 0u32),
                (Kind::CoordinateModulusPlusOne, 1),
            ] {
                let r = recipe(kind, &p, 0).unwrap();
                assert_eq!(r.r.x, &p + BigUint::from(offset));
                assert_eq!(
                    BigUint::from_bytes_le(
                        &fixed_hex::<32>(&r.inputs().unwrap().point_R.x_le).unwrap()
                    ),
                    r.r.x
                );
            }
        }
        assert_eq!(
            digits(&(BigUint::from(1u32) << 255usize)).unwrap()[8],
            1 << 23
        );
    }
    #[test]
    fn numeric_writer_rejects_missing_duplicate_and_undeclared_range_writes() {
        use bitvm2_nova_script_oracle::registry::Word;
        let spec = GraphSpec {
            program_sha256: "00".repeat(32),
            context: "00".repeat(32),
            field_role: "pallas_base".into(),
            operation_id: "tiny".into(),
            words: vec![
                Word {
                    name: "a".into(),
                    bound: 2,
                },
                Word {
                    name: "b".into(),
                    bound: 2,
                },
            ],
            leaves: vec![],
            bodies: BTreeMap::new(),
        };
        let p = modulus("pallas_base").unwrap();
        let mut w = Witness::new(&spec, &p, Kind::Edge(0)).unwrap();
        assert!(w.set("missing", 0).is_err());
        assert!(w.set("a", 2).is_err());
        w.set("a", 0).unwrap();
        assert!(w.set("a", 0).is_err());
        assert!(w.finish().is_err());
    }
}
