//! Project the exact optimized Poseidon parameters from an authenticated VK.
//!
//! Nova 0.76.0 vendors the Neptune-derived implementation. Its supported serde
//! schema exposes optimized constants; raw round keys and unused inverse caches
//! are neither needed nor inspected here. Every selected sequence is bounded
//! before allocating JSON nodes. The caller must authenticate the full key first.
use ff::PrimeField;
use nova_snark::{
    provider::{poseidon::PoseidonConstantsCircuit, PallasEngine, VestaEngine},
    traits::Engine,
};
use serde::{ser, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::fmt;

const VK_SHA: &str = "1ae88a7bcfdc5f14d030d0baafa06ec17fe904a5ebed42f9bd6fa6105fdc8c24";
const DIM_SHA: &str = "de6333df2e41b5f5bae1c103fab862f8d6022fd54abeb80ba61920bc9f360edc";
const REVISION: &str = "de607d3db17d400dd6c2923d357f1d4a7bf233c7";
const CRATE_SHA: &str = "c9bb3809a6c70057ea722c1c4fe5097cf29a3479d0b4671f3cddb1d81043bb31";
const MAX_SCALARS: usize = 32768;
const MAX_NODES: usize = 65536;
const MAX_JSON: usize = 2 << 20;

#[derive(Debug)]
struct Error(String);
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for Error {}
impl ser::Error for Error {
    fn custom<T: fmt::Display>(message: T) -> Self {
        Self(message.to_string())
    }
}
fn error() -> Error {
    Error("unsupported or oversized Poseidon parameter serialization".into())
}

#[derive(Default, Serialize)]
pub struct ExportStats {
    selected_scalar_fields: usize,
    selected_json_nodes: usize,
    selected_leaves: usize,
    skipped_fields: usize,
    full_key_materialized: bool,
    inverse_caches_materialized: bool,
}
impl ExportStats {
    fn node(&mut self) -> Result<(), Error> {
        self.selected_json_nodes = self.selected_json_nodes.checked_add(1).ok_or_else(error)?;
        if self.selected_json_nodes > MAX_NODES {
            return Err(error());
        }
        Ok(())
    }
    fn scalar(&mut self) -> Result<(), Error> {
        self.selected_scalar_fields = self
            .selected_scalar_fields
            .checked_add(1)
            .ok_or_else(error)?;
        if self.selected_scalar_fields > MAX_SCALARS {
            return Err(error());
        }
        self.node()
    }
}

#[derive(Clone, Copy)]
enum Field {
    PallasBase,
    VestaBase,
}
fn canonical_field<F: PrimeField>(value: &str) -> bool {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return false;
    }
    let Ok(bytes) = hex::decode(value) else {
        return false;
    };
    let mut repr = F::Repr::default();
    if repr.as_ref().len() != 32 {
        return false;
    }
    repr.as_mut().copy_from_slice(&bytes);
    F::from_repr(repr).is_some().into()
}
impl Field {
    fn valid(self, value: &str) -> bool {
        match self {
            Self::PallasBase => canonical_field::<<PallasEngine as Engine>::Base>(value),
            Self::VestaBase => canonical_field::<<VestaEngine as Engine>::Base>(value),
        }
    }
}

#[derive(Clone)]
enum Shape {
    Scalar(Field),
    Number(u64),
    Unit(&'static str),
    Sequence {
        min: usize,
        max: usize,
        element: Box<Shape>,
    },
    Sparse {
        width: usize,
        field: Field,
    },
}
fn sequence(min: usize, max: usize, element: Shape) -> Shape {
    Shape::Sequence {
        min,
        max,
        element: Box::new(element),
    }
}
fn vector(n: usize, field: Field) -> Shape {
    sequence(n, n, Shape::Scalar(field))
}
fn matrix(n: usize, field: Field) -> Shape {
    sequence(n, n, vector(n, field))
}

struct Build<'a> {
    shape: Shape,
    stats: &'a mut ExportStats,
}
struct Sequence<'a> {
    element: Shape,
    length: usize,
    values: Vec<Value>,
    stats: &'a mut ExportStats,
}
struct Sparse<'a> {
    width: usize,
    field: Field,
    values: Map<String, Value>,
    stats: &'a mut ExportStats,
}

macro_rules! reject_values {
    ($($method:ident($ty:ty)),* $(,)?)=>{$(fn $method(self,_:$ty)->Result<Self::Ok,Self::Error>{Err(error())})*};
}
impl Build<'_> {
    fn number(self, value: u64) -> Result<Value, Error> {
        match self.shape {
            Shape::Number(max) if value <= max => {
                self.stats.node()?;
                Ok(json!(value))
            }
            _ => Err(error()),
        }
    }
}
impl<'a> ser::Serializer for Build<'a> {
    type Ok = Value;
    type Error = Error;
    type SerializeSeq = Sequence<'a>;
    type SerializeTuple = ser::Impossible<Value, Error>;
    type SerializeTupleStruct = ser::Impossible<Value, Error>;
    type SerializeTupleVariant = ser::Impossible<Value, Error>;
    type SerializeMap = ser::Impossible<Value, Error>;
    type SerializeStruct = Sparse<'a>;
    type SerializeStructVariant = ser::Impossible<Value, Error>;
    reject_values!(
        serialize_bool(bool),
        serialize_i8(i8),
        serialize_i16(i16),
        serialize_i32(i32),
        serialize_i64(i64),
        serialize_i128(i128),
        serialize_f32(f32),
        serialize_f64(f64),
        serialize_char(char),
        serialize_bytes(&[u8])
    );
    fn serialize_u8(self, value: u8) -> Result<Value, Error> {
        self.number(value.into())
    }
    fn serialize_u16(self, value: u16) -> Result<Value, Error> {
        self.number(value.into())
    }
    fn serialize_u32(self, value: u32) -> Result<Value, Error> {
        self.number(value.into())
    }
    fn serialize_u64(self, value: u64) -> Result<Value, Error> {
        self.number(value)
    }
    fn serialize_u128(self, value: u128) -> Result<Value, Error> {
        self.number(u64::try_from(value).map_err(|_| error())?)
    }
    fn serialize_str(self, value: &str) -> Result<Value, Error> {
        match self.shape {
            Shape::Scalar(field) if field.valid(value) => {
                self.stats.scalar()?;
                Ok(Value::String(value.into()))
            }
            _ => Err(error()),
        }
    }
    fn serialize_unit_variant(
        self,
        _: &'static str,
        _: u32,
        variant: &'static str,
    ) -> Result<Value, Error> {
        match self.shape {
            Shape::Unit(expected) if expected == variant => {
                self.stats.node()?;
                Ok(Value::String(variant.into()))
            }
            _ => Err(error()),
        }
    }
    fn serialize_none(self) -> Result<Value, Error> {
        Err(error())
    }
    fn serialize_some<T: ?Sized + Serialize>(self, _: &T) -> Result<Value, Error> {
        Err(error())
    }
    fn serialize_unit(self) -> Result<Value, Error> {
        Err(error())
    }
    fn serialize_unit_struct(self, _: &'static str) -> Result<Value, Error> {
        Err(error())
    }
    fn serialize_newtype_struct<T: ?Sized + Serialize>(
        self,
        _: &'static str,
        _: &T,
    ) -> Result<Value, Error> {
        Err(error())
    }
    fn serialize_newtype_variant<T: ?Sized + Serialize>(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        _: &T,
    ) -> Result<Value, Error> {
        Err(error())
    }
    fn serialize_seq(self, length: Option<usize>) -> Result<Self::SerializeSeq, Error> {
        let Shape::Sequence { min, max, element } = self.shape else {
            return Err(error());
        };
        let length = length.ok_or_else(error)?;
        if length < min || length > max {
            return Err(error());
        }
        self.stats.node()?;
        Ok(Sequence {
            element: *element,
            length,
            values: Vec::with_capacity(length),
            stats: self.stats,
        })
    }
    fn serialize_tuple(self, _: usize) -> Result<Self::SerializeTuple, Error> {
        Err(error())
    }
    fn serialize_tuple_struct(
        self,
        _: &'static str,
        _: usize,
    ) -> Result<Self::SerializeTupleStruct, Error> {
        Err(error())
    }
    fn serialize_tuple_variant(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        _: usize,
    ) -> Result<Self::SerializeTupleVariant, Error> {
        Err(error())
    }
    fn serialize_map(self, _: Option<usize>) -> Result<Self::SerializeMap, Error> {
        Err(error())
    }
    fn serialize_struct(
        self,
        _: &'static str,
        length: usize,
    ) -> Result<Self::SerializeStruct, Error> {
        let Shape::Sparse { width, field } = self.shape else {
            return Err(error());
        };
        if length != 2 {
            return Err(error());
        }
        self.stats.node()?;
        Ok(Sparse {
            width,
            field,
            values: Map::new(),
            stats: self.stats,
        })
    }
    fn serialize_struct_variant(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        _: usize,
    ) -> Result<Self::SerializeStructVariant, Error> {
        Err(error())
    }
    fn is_human_readable(&self) -> bool {
        true
    }
}
impl ser::SerializeSeq for Sequence<'_> {
    type Ok = Value;
    type Error = Error;
    fn serialize_element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Error> {
        if self.values.len() >= self.length {
            return Err(error());
        }
        self.values.push(value.serialize(Build {
            shape: self.element.clone(),
            stats: &mut *self.stats,
        })?);
        Ok(())
    }
    fn end(self) -> Result<Value, Error> {
        if self.values.len() != self.length {
            Err(error())
        } else {
            Ok(Value::Array(self.values))
        }
    }
}
impl ser::SerializeStruct for Sparse<'_> {
    type Ok = Value;
    type Error = Error;
    fn serialize_field<T: ?Sized + Serialize>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), Error> {
        let n = match key {
            "w_hat" => self.width,
            "v_rest" => self.width - 1,
            _ => return Err(error()),
        };
        if self.values.contains_key(key) {
            return Err(error());
        }
        self.values.insert(
            key.into(),
            value.serialize(Build {
                shape: vector(n, self.field),
                stats: &mut *self.stats,
            })?,
        );
        Ok(())
    }
    fn end(self) -> Result<Value, Error> {
        if self.values.len() != 2 {
            Err(error())
        } else {
            Ok(Value::Object(self.values))
        }
    }
}

#[derive(Default)]
struct Facts {
    values: [Option<Value>; 32],
    stats: ExportStats,
}
impl Facts {
    fn take(&mut self, slot: usize) -> Result<Value, Error> {
        self.values[slot].take().ok_or_else(error)
    }
    fn get(&self, slot: usize) -> Result<&Value, Error> {
        self.values[slot].as_ref().ok_or_else(error)
    }
}
#[derive(Clone, Copy)]
enum Mode {
    Root,
    Pair(usize),
    Profile(usize),
    Mds(usize),
}
enum Target {
    Nested(Mode),
    Leaf(usize, Shape),
}
fn width(profile: usize) -> usize {
    if profile % 2 == 0 {
        25
    } else {
        6
    }
}
fn field(profile: usize) -> Field {
    if profile < 2 {
        Field::PallasBase
    } else {
        Field::VestaBase
    }
}
impl Mode {
    fn target(self, key: &str) -> Option<Target> {
        match (self, key) {
            (Self::Root, "ro_consts_primary") => Some(Target::Nested(Self::Pair(0))),
            (Self::Root, "ro_consts_secondary") => Some(Target::Nested(Self::Pair(2))),
            (Self::Pair(base), "wide") => Some(Target::Nested(Self::Profile(base))),
            (Self::Pair(base), "narrow") => Some(Target::Nested(Self::Profile(base + 1))),
            (Self::Profile(id), "mds") => Some(Target::Nested(Self::Mds(id))),
            (Self::Mds(id), "m") => Some(Target::Leaf(id * 8, matrix(width(id), field(id)))),
            (Self::Profile(id), "crc") => Some(Target::Leaf(
                id * 8 + 1,
                sequence(1, 16 * width(id) + 128, Shape::Scalar(field(id))),
            )),
            (Self::Profile(id), "psm") => {
                Some(Target::Leaf(id * 8 + 2, matrix(width(id), field(id))))
            }
            (Self::Profile(id), "sm") => Some(Target::Leaf(
                id * 8 + 3,
                sequence(
                    1,
                    128,
                    Shape::Sparse {
                        width: width(id),
                        field: field(id),
                    },
                ),
            )),
            (Self::Profile(id), "rf") => Some(Target::Leaf(id * 8 + 4, Shape::Number(16))),
            (Self::Profile(id), "rp") => Some(Target::Leaf(id * 8 + 5, Shape::Number(128))),
            (Self::Profile(id), "s") => Some(Target::Leaf(id * 8 + 6, Shape::Unit("Standard"))),
            (Self::Profile(id), "ht") => Some(Target::Leaf(id * 8 + 7, Shape::Unit("Sponge"))),
            _ => None,
        }
    }
}
struct Probe<'a> {
    facts: &'a mut Facts,
    mode: Mode,
}
impl<'a> ser::Serializer for Probe<'a> {
    type Ok = ();
    type Error = Error;
    type SerializeSeq = ser::Impossible<(), Error>;
    type SerializeTuple = ser::Impossible<(), Error>;
    type SerializeTupleStruct = ser::Impossible<(), Error>;
    type SerializeTupleVariant = ser::Impossible<(), Error>;
    type SerializeMap = ser::Impossible<(), Error>;
    type SerializeStruct = Self;
    type SerializeStructVariant = ser::Impossible<(), Error>;
    reject_values!(
        serialize_bool(bool),
        serialize_i8(i8),
        serialize_i16(i16),
        serialize_i32(i32),
        serialize_i64(i64),
        serialize_i128(i128),
        serialize_u8(u8),
        serialize_u16(u16),
        serialize_u32(u32),
        serialize_u64(u64),
        serialize_u128(u128),
        serialize_f32(f32),
        serialize_f64(f64),
        serialize_char(char),
        serialize_str(&str),
        serialize_bytes(&[u8])
    );
    fn serialize_none(self) -> Result<(), Error> {
        Err(error())
    }
    fn serialize_some<T: ?Sized + Serialize>(self, _: &T) -> Result<(), Error> {
        Err(error())
    }
    fn serialize_unit(self) -> Result<(), Error> {
        Err(error())
    }
    fn serialize_unit_struct(self, _: &'static str) -> Result<(), Error> {
        Err(error())
    }
    fn serialize_unit_variant(self, _: &'static str, _: u32, _: &'static str) -> Result<(), Error> {
        Err(error())
    }
    fn serialize_newtype_struct<T: ?Sized + Serialize>(
        self,
        _: &'static str,
        _: &T,
    ) -> Result<(), Error> {
        Err(error())
    }
    fn serialize_newtype_variant<T: ?Sized + Serialize>(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        _: &T,
    ) -> Result<(), Error> {
        Err(error())
    }
    fn serialize_seq(self, _: Option<usize>) -> Result<Self::SerializeSeq, Error> {
        Err(error())
    }
    fn serialize_tuple(self, _: usize) -> Result<Self::SerializeTuple, Error> {
        Err(error())
    }
    fn serialize_tuple_struct(
        self,
        _: &'static str,
        _: usize,
    ) -> Result<Self::SerializeTupleStruct, Error> {
        Err(error())
    }
    fn serialize_tuple_variant(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        _: usize,
    ) -> Result<Self::SerializeTupleVariant, Error> {
        Err(error())
    }
    fn serialize_map(self, _: Option<usize>) -> Result<Self::SerializeMap, Error> {
        Err(error())
    }
    fn serialize_struct(self, _: &'static str, _: usize) -> Result<Self::SerializeStruct, Error> {
        Ok(self)
    }
    fn serialize_struct_variant(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        _: usize,
    ) -> Result<Self::SerializeStructVariant, Error> {
        Err(error())
    }
    fn is_human_readable(&self) -> bool {
        true
    }
}
impl ser::SerializeStruct for Probe<'_> {
    type Ok = ();
    type Error = Error;
    fn serialize_field<T: ?Sized + Serialize>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), Error> {
        match self.mode.target(key) {
            Some(Target::Nested(mode)) => value.serialize(Probe {
                facts: &mut *self.facts,
                mode,
            }),
            Some(Target::Leaf(slot, shape)) => {
                if self.facts.values[slot].is_some() {
                    return Err(error());
                }
                let projected = value.serialize(Build {
                    shape,
                    stats: &mut self.facts.stats,
                })?;
                self.facts.values[slot] = Some(projected);
                self.facts.stats.selected_leaves += 1;
                Ok(())
            }
            None => {
                self.facts.stats.skipped_fields += 1;
                Ok(())
            }
        }
    }
    fn end(self) -> Result<(), Error> {
        Ok(())
    }
}

fn profile(facts: &mut Facts, id: usize) -> Result<Value, Error> {
    let base = id * 8;
    let t = width(id);
    let rf = facts.get(base + 4)?.as_u64().ok_or_else(error)?;
    let rp = facts.get(base + 5)?.as_u64().ok_or_else(error)?;
    if rf == 0 || rf % 2 != 0 || rp == 0 {
        return Err(error());
    }
    let keys = facts.get(base + 1)?.as_array().ok_or_else(error)?.len();
    let sparse = facts.get(base + 3)?.as_array().ok_or_else(error)?.len();
    if keys != rf as usize * t + rp as usize || sparse != rp as usize {
        return Err(error());
    }
    Ok(json!({"arity":t-1,"width":t,"rate":t-1,"capacity":1,
        "mds":facts.take(base)?,"crc":facts.take(base+1)?,"psm":facts.take(base+2)?,"sm":facts.take(base+3)?,
        "rf":facts.take(base+4)?,"rp":facts.take(base+5)?,"s":facts.take(base+6)?,"ht":facts.take(base+7)?}))
}
fn branch(facts: &mut Facts, base: usize) -> Result<Value, Error> {
    let (engine, role) = if base == 0 {
        ("pallas", "pallas_base")
    } else {
        ("vesta", "vesta_base")
    };
    let wide = profile(facts, base)?;
    let narrow = profile(facts, base + 1)?;
    Ok(json!({"engine":engine,"field_role":role,"wide":wide,"narrow":narrow}))
}

/// Projection is trusted only after the caller's full reconstructed VK SHA check.
pub fn export_authenticated_vk<T: Serialize>(
    key: &T,
    key_sha256: &str,
    dimensions_sha256: &str,
    network: &str,
    k: u32,
) -> Result<(Value, ExportStats), String> {
    if key_sha256 != VK_SHA || dimensions_sha256 != DIM_SHA || network != "testnet4" || k != 5 {
        return Err("Poseidon export is scoped to the authenticated retained key".into());
    }
    let mut facts = Facts::default();
    key.serialize(Probe {
        facts: &mut facts,
        mode: Mode::Root,
    })
    .map_err(|e| e.to_string())?;
    let primary = branch(&mut facts, 0).map_err(|e| e.to_string())?;
    let secondary = branch(&mut facts, 2).map_err(|e| e.to_string())?;
    let value = json!({"schema":"bitvm2-nova-poseidon-parameters/v1","nova_version":"0.76.0",
        "nova_crate_sha256":CRATE_SHA,"header_revision":REVISION,"network":network,"k":k,
        "verifier_key_sha256":key_sha256,"verifier_dimensions_sha256":dimensions_sha256,
        "primary":primary,"secondary":secondary});
    canonical_sha256(&value)?;
    Ok((value, facts.stats))
}

/// Project a native default only for exact comparison with an independently
/// authenticated actual-key branch. This function does not establish trust.
pub fn project_default<F: PrimeField + Serialize>(
    constants: &PoseidonConstantsCircuit<F>,
    engine: &str,
    role: &str,
) -> Result<Value, String> {
    let base = match (engine, role) {
        ("pallas", "pallas_base")
            if F::MODULUS == <<PallasEngine as Engine>::Base as PrimeField>::MODULUS =>
        {
            0
        }
        ("vesta", "vesta_base")
            if F::MODULUS == <<VestaEngine as Engine>::Base as PrimeField>::MODULUS =>
        {
            2
        }
        _ => return Err("default Poseidon field identity mismatch".into()),
    };
    let mut facts = Facts::default();
    constants
        .serialize(Probe {
            facts: &mut facts,
            mode: Mode::Pair(base),
        })
        .map_err(|e| e.to_string())?;
    branch(&mut facts, base).map_err(|e| e.to_string())
}

pub fn canonical_sha256(value: &Value) -> Result<String, String> {
    fn sorted(value: &Value, depth: usize) -> Result<Value, String> {
        if depth > 16 {
            return Err("Poseidon parameter JSON depth".into());
        }
        match value {
            Value::Object(object) => {
                let mut fields: Vec<_> = object.iter().collect();
                fields.sort_by(|a, b| a.0.cmp(b.0));
                let mut out = Map::new();
                for (key, value) in fields {
                    if !key.is_ascii() {
                        return Err("non-ASCII parameter key".into());
                    }
                    out.insert(key.clone(), sorted(value, depth + 1)?);
                }
                Ok(Value::Object(out))
            }
            Value::Array(values) => Ok(Value::Array(
                values
                    .iter()
                    .map(|v| sorted(v, depth + 1))
                    .collect::<Result<_, _>>()?,
            )),
            Value::String(s) if s.is_ascii() => Ok(value.clone()),
            Value::Number(n) if n.as_u64().is_some() => Ok(value.clone()),
            _ => Err("unsupported parameter JSON value".into()),
        }
    }
    let canonical = serde_json::to_vec(&sorted(value, 0)?).map_err(|e| e.to_string())?;
    if canonical.len() > MAX_JSON {
        return Err("Poseidon parameter JSON byte budget".into());
    }
    Ok(hex::encode(Sha256::digest(canonical)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::ser::{SerializeSeq, SerializeStruct};
    use std::sync::atomic::{AtomicUsize, Ordering};
    static VISITS: AtomicUsize = AtomicUsize::new(0);
    struct Never;
    impl Serialize for Never {
        fn serialize<S: ser::Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
            VISITS.fetch_add(1, Ordering::SeqCst);
            Err(ser::Error::custom("unused key object visited"))
        }
    }
    #[derive(Serialize)]
    struct Mds {
        m: Vec<Vec<String>>,
        m_inv: Never,
        m_hat: Never,
    }
    #[derive(Serialize)]
    struct SparseMatrix {
        w_hat: Vec<String>,
        v_rest: Vec<String>,
    }
    #[derive(Serialize)]
    enum Strength {
        Standard,
    }
    #[derive(Serialize)]
    enum HashType {
        Sponge,
    }
    #[derive(Serialize)]
    struct Constants {
        mds: Mds,
        crc: Vec<String>,
        psm: Vec<Vec<String>>,
        sm: Vec<SparseMatrix>,
        rf: u64,
        rp: u64,
        s: Strength,
        ht: HashType,
    }
    #[derive(Serialize)]
    struct Pair {
        wide: Constants,
        narrow: Constants,
    }
    #[derive(Serialize)]
    struct FakeKey {
        ro_consts_primary: Pair,
        ro_consts_secondary: Pair,
        vk_primary: Never,
        vk_secondary: Never,
    }
    fn constants(t: usize) -> Constants {
        let zero = "00".repeat(32);
        Constants {
            mds: Mds {
                m: vec![vec![zero.clone(); t]; t],
                m_inv: Never,
                m_hat: Never,
            },
            crc: vec![zero.clone(); 2 * t + 1],
            psm: vec![vec![zero.clone(); t]; t],
            sm: vec![SparseMatrix {
                w_hat: vec![zero.clone(); t],
                v_rest: vec![zero; t - 1],
            }],
            rf: 2,
            rp: 1,
            s: Strength::Standard,
            ht: HashType::Sponge,
        }
    }
    fn pair() -> Pair {
        Pair {
            wide: constants(25),
            narrow: constants(6),
        }
    }
    fn key() -> FakeKey {
        FakeKey {
            ro_consts_primary: pair(),
            ro_consts_secondary: pair(),
            vk_primary: Never,
            vk_secondary: Never,
        }
    }
    fn export(key: &FakeKey) -> Result<(Value, ExportStats), String> {
        export_authenticated_vk(key, VK_SHA, DIM_SHA, "testnet4", 5)
    }
    #[test]
    fn selects_all_four_profiles_without_key_or_inverse_cache_visits() {
        let (value, stats) = export(&key()).unwrap();
        assert_eq!(
            value["primary"]["wide"]["mds"].as_array().unwrap().len(),
            25
        );
        assert_eq!(value["secondary"]["narrow"]["width"], 6);
        assert_eq!(stats.selected_leaves, 32);
        assert!(!stats.full_key_materialized);
        assert!(!stats.inverse_caches_materialized);
        assert_eq!(VISITS.load(Ordering::SeqCst), 0);
    }
    #[test]
    fn canonical_fields_shapes_and_round_coupling_fail_closed() {
        let mut bad = key();
        bad.ro_consts_primary.wide.mds.m[0].pop();
        assert!(export(&bad).is_err());
        bad = key();
        bad.ro_consts_primary.wide.crc.pop();
        assert!(export(&bad).is_err());
        bad = key();
        bad.ro_consts_secondary.narrow.rf = 3;
        assert!(export(&bad).is_err());
        bad = key();
        bad.ro_consts_secondary.narrow.sm.clear();
        assert!(export(&bad).is_err());
        bad = key();
        bad.ro_consts_primary.wide.crc[0] = "ff".repeat(32);
        assert!(export(&bad).is_err());
        bad = key();
        bad.ro_consts_secondary.narrow.rp = 129;
        assert!(export(&bad).is_err());
    }
    #[test]
    fn sequence_length_is_checked_before_visiting_any_element() {
        struct Oversized;
        impl Serialize for Oversized {
            fn serialize<S: ser::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                let mut seq = s.serialize_seq(Some(usize::MAX))?;
                seq.serialize_element(&Never)?;
                seq.end()
            }
        }
        let mut stats = ExportStats::default();
        assert!(Oversized
            .serialize(Build {
                shape: vector(25, Field::PallasBase),
                stats: &mut stats
            })
            .is_err());
        assert_eq!(VISITS.load(Ordering::SeqCst), 0);
        assert_eq!(stats.selected_json_nodes, 0);
        struct Duplicate;
        impl Serialize for Duplicate {
            fn serialize<S: ser::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                let mut st = s.serialize_struct("SparseMatrix", 2)?;
                let values = vec!["00".repeat(32); 25];
                st.serialize_field("w_hat", &values)?;
                st.serialize_field("w_hat", &values)?;
                st.end()
            }
        }
        assert!(Duplicate
            .serialize(Build {
                shape: Shape::Sparse {
                    width: 25,
                    field: Field::PallasBase
                },
                stats: &mut stats
            })
            .is_err());
    }
    #[test]
    fn default_projection_is_field_bound_and_not_intrinsically_authenticated() {
        type P = <PallasEngine as Engine>::Base;
        let constants = PoseidonConstantsCircuit::<P>::default();
        let projected = project_default(&constants, "pallas", "pallas_base").unwrap();
        assert_eq!(projected["wide"]["ht"], "Sponge");
        assert!(project_default(&constants, "vesta", "vesta_base").is_err());
        assert!(export_authenticated_vk(&key(), &"00".repeat(32), DIM_SHA, "testnet4", 5).is_err());
    }
    #[test]
    fn canonical_parameter_digest_matches_independent_ascii_reference() {
        let value = json!({"z": 2, "a": {"x": [1, "00"]}});
        assert_eq!(
            canonical_sha256(&value).unwrap(),
            "63fee996985eddf1154dd76942ebe09225110f233b9bf2417e0259080b161a53"
        );
        assert!(canonical_sha256(&json!({"float": 1.0})).is_err());
        assert!(canonical_sha256(&json!({"unicode": "\u{00e9}"})).is_err());
    }
}
