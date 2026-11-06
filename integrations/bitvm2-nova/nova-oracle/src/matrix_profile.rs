//! Length-only census of the six CSR matrices in an authenticated Nova VK.
//!
//! Matrix sequence serialization stops before the first element. This does not
//! inspect coefficients, indices or pointer values, and is not matrix validation
//! or polynomial evaluation. The caller must first authenticate the whole VK.
use serde::{ser, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::fmt;

const VK_SHA: &str = "1ae88a7bcfdc5f14d030d0baafa06ec17fe904a5ebed42f9bd6fa6105fdc8c24";
const DIM_SHA: &str = "de6333df2e41b5f5bae1c103fab862f8d6022fd54abeb80ba61920bc9f360edc";
const REVISION: &str = "de607d3db17d400dd6c2923d357f1d4a7bf233c7";
const CRATE_SHA: &str = "c9bb3809a6c70057ea722c1c4fe5097cf29a3479d0b4671f3cddb1d81043bb31";
const MAX_DIMENSION: u64 = 1 << 24;
// A mathematical metadata bound, not permission to export this much payload.
const MAX_METADATA_ENTRIES: u64 = 1 << 49;

#[derive(Default, Serialize)]
pub struct ExportStats {
    numeric_fields_read: usize,
    sequence_lengths_read: usize,
    matrices_profiled: usize,
    skipped_fields: usize,
    matrix_elements_read: usize,
    matrix_payloads_materialized: bool,
    full_key_materialized: bool,
}
#[derive(Default)]
struct Facts {
    values: [Option<u64>; 30],
    stats: ExportStats,
}
impl Facts {
    fn record(&mut self, slot: usize, value: u64) -> Result<(), Error> {
        if self.values[slot].replace(value).is_some() {
            return Err(Error::Message("duplicate matrix profile field".into()));
        }
        Ok(())
    }
    fn get(&self, slot: usize) -> Result<u64, String> {
        self.values[slot].ok_or_else(|| format!("missing trusted matrix profile slot{slot}"))
    }
}
#[derive(Clone, Copy)]
enum SequenceKind {
    DataOrIndices,
    Indptr,
}
impl SequenceKind {
    fn accepts(self, length: u64) -> bool {
        match self {
            Self::DataOrIndices => length <= MAX_METADATA_ENTRIES,
            Self::Indptr => (1..=MAX_DIMENSION + 1).contains(&length),
        }
    }
}
#[derive(Clone, Copy)]
enum Mode {
    Root,
    Snark(usize),
    Shape(usize),
    Matrix(usize),
    Number(usize),
    Length(usize, SequenceKind),
}
impl Mode {
    fn child(self, key: &str) -> Option<Self> {
        match (self, key) {
            (Self::Root, "vk_primary") => Some(Self::Snark(0)),
            (Self::Root, "vk_secondary") => Some(Self::Snark(15)),
            (Self::Snark(base), "S") => Some(Self::Shape(base)),
            (Self::Shape(base), "num_cons") => Some(Self::Number(base)),
            (Self::Shape(base), "num_vars") => Some(Self::Number(base + 1)),
            (Self::Shape(base), "num_io") => Some(Self::Number(base + 2)),
            (Self::Shape(base), "A") => Some(Self::Matrix(base + 3)),
            (Self::Shape(base), "B") => Some(Self::Matrix(base + 7)),
            (Self::Shape(base), "C") => Some(Self::Matrix(base + 11)),
            (Self::Matrix(base), "data") => Some(Self::Length(base, SequenceKind::DataOrIndices)),
            (Self::Matrix(base), "indices") => {
                Some(Self::Length(base + 1, SequenceKind::DataOrIndices))
            }
            (Self::Matrix(base), "indptr") => Some(Self::Length(base + 2, SequenceKind::Indptr)),
            (Self::Matrix(base), "cols") => Some(Self::Number(base + 3)),
            _ => None,
        }
    }
}
#[derive(Debug)]
enum Error {
    Message(String),
    LengthCaptured,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Message(message) => f.write_str(message),
            Self::LengthCaptured => f.write_str("internal matrix length capture"),
        }
    }
}
impl std::error::Error for Error {}
impl ser::Error for Error {
    fn custom<T: fmt::Display>(message: T) -> Self {
        Self::Message(message.to_string())
    }
}
fn unexpected() -> Error {
    Error::Message("unexpected or oversized trusted matrix profile serialization".into())
}
struct Probe<'a> {
    facts: &'a mut Facts,
    mode: Mode,
}
impl Probe<'_> {
    fn number(self, value: u64) -> Result<(), Error> {
        match self.mode {
            Mode::Number(slot) if value <= MAX_METADATA_ENTRIES => {
                self.facts.record(slot, value)?;
                self.facts.stats.numeric_fields_read += 1;
                Ok(())
            }
            _ => Err(unexpected()),
        }
    }
}
macro_rules! reject_values{
    ($($method:ident($ty:ty)),* $(,)?)=>{$(fn $method(self,_:$ty)->Result<Self::Ok,Self::Error>{Err(unexpected())})*};
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
        serialize_f32(f32),
        serialize_f64(f64),
        serialize_char(char),
        serialize_str(&str),
        serialize_bytes(&[u8])
    );
    fn serialize_u8(self, value: u8) -> Result<(), Error> {
        self.number(value.into())
    }
    fn serialize_u16(self, value: u16) -> Result<(), Error> {
        self.number(value.into())
    }
    fn serialize_u32(self, value: u32) -> Result<(), Error> {
        self.number(value.into())
    }
    fn serialize_u64(self, value: u64) -> Result<(), Error> {
        self.number(value)
    }
    fn serialize_u128(self, value: u128) -> Result<(), Error> {
        self.number(u64::try_from(value).map_err(|_| unexpected())?)
    }
    fn serialize_none(self) -> Result<(), Error> {
        Err(unexpected())
    }
    fn serialize_some<T: ?Sized + Serialize>(self, _: &T) -> Result<(), Error> {
        Err(unexpected())
    }
    fn serialize_unit(self) -> Result<(), Error> {
        Err(unexpected())
    }
    fn serialize_unit_struct(self, _: &'static str) -> Result<(), Error> {
        Err(unexpected())
    }
    fn serialize_unit_variant(self, _: &'static str, _: u32, _: &'static str) -> Result<(), Error> {
        Err(unexpected())
    }
    fn serialize_newtype_struct<T: ?Sized + Serialize>(
        self,
        _: &'static str,
        _: &T,
    ) -> Result<(), Error> {
        Err(unexpected())
    }
    fn serialize_newtype_variant<T: ?Sized + Serialize>(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        _: &T,
    ) -> Result<(), Error> {
        Err(unexpected())
    }
    fn serialize_seq(self, length: Option<usize>) -> Result<Self::SerializeSeq, Error> {
        let Mode::Length(slot, kind) = self.mode else {
            return Err(unexpected());
        };
        let length = u64::try_from(length.ok_or_else(unexpected)?).map_err(|_| unexpected())?;
        if !kind.accepts(length) {
            return Err(unexpected());
        }
        self.facts.record(slot, length)?;
        self.facts.stats.sequence_lengths_read += 1;
        // Vec's serializer exits here, before iterating any element. The marker
        // is caught only at this exact selected sequence field, not as rejection.
        Err(Error::LengthCaptured)
    }
    fn serialize_tuple(self, _: usize) -> Result<Self::SerializeTuple, Error> {
        Err(unexpected())
    }
    fn serialize_tuple_struct(
        self,
        _: &'static str,
        _: usize,
    ) -> Result<Self::SerializeTupleStruct, Error> {
        Err(unexpected())
    }
    fn serialize_tuple_variant(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        _: usize,
    ) -> Result<Self::SerializeTupleVariant, Error> {
        Err(unexpected())
    }
    fn serialize_map(self, _: Option<usize>) -> Result<Self::SerializeMap, Error> {
        Err(unexpected())
    }
    fn serialize_struct(self, _: &'static str, _: usize) -> Result<Self::SerializeStruct, Error> {
        match self.mode {
            Mode::Number(_) | Mode::Length(_, _) => Err(unexpected()),
            _ => Ok(self),
        }
    }
    fn serialize_struct_variant(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        _: usize,
    ) -> Result<Self::SerializeStructVariant, Error> {
        Err(unexpected())
    }
    fn is_human_readable(&self) -> bool {
        false
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
        let Some(mode) = self.mode.child(key) else {
            self.facts.stats.skipped_fields += 1;
            return Ok(());
        };
        let result = value.serialize(Probe {
            facts: &mut *self.facts,
            mode,
        });
        match (mode, result) {
            (Mode::Length(_, _), Err(Error::LengthCaptured)) => Ok(()),
            (_, result) => result,
        }
    }
    fn end(self) -> Result<(), Error> {
        Ok(())
    }
}

fn matrix(facts: &mut Facts, base: usize, nc: u64, evaluation_cols: u64) -> Result<Value, String> {
    let data = facts.get(base)?;
    let indices = facts.get(base + 1)?;
    let indptr = facts.get(base + 2)?;
    let cols = facts.get(base + 3)?;
    let rows = indptr.checked_sub(1).ok_or("empty trusted CSR indptr")?;
    let dense_bound = rows
        .checked_mul(cols)
        .ok_or("matrix density arithmetic overflow")?;
    if rows > nc || cols > evaluation_cols || data != indices || data > dense_bound {
        return Err("inconsistent trusted CSR length metadata".into());
    }
    facts.stats.matrices_profiled += 1;
    Ok(
        json!({"data_len":data,"indices_len":indices,"indptr_len":indptr,"cols":cols,"csr_rows":rows}),
    )
}
fn curve(facts: &mut Facts, base: usize, engine: &str, role: &str) -> Result<Value, String> {
    let nc = facts.get(base)?;
    let nv = facts.get(base + 1)?;
    let io = facts.get(base + 2)?;
    if !nc.is_power_of_two()
        || !nv.is_power_of_two()
        || nc > MAX_DIMENSION
        || nv > MAX_DIMENSION
        || nv < 8
        || io != 2
    {
        return Err("unsupported trusted matrix logical dimensions".into());
    }
    let evaluation_cols = nv.checked_mul(2).ok_or("matrix column domain overflow")?;
    let a = matrix(facts, base + 3, nc, evaluation_cols)?;
    let b = matrix(facts, base + 7, nc, evaluation_cols)?;
    let c = matrix(facts, base + 11, nc, evaluation_cols)?;
    Ok(
        json!({"engine":engine,"field_role":role,"num_cons":nc,"num_vars":nv,"num_io":io,
        "evaluation_rows":nc,"evaluation_cols":evaluation_cols,"matrices":{"A":a,"B":b,"C":c}}),
    )
}

/// Length metadata is authoritative only after authenticating the actual full VK.
pub fn export_authenticated_vk<T: Serialize>(
    key: &T,
    key_sha256: &str,
    dimensions_sha256: &str,
    network: &str,
    k: u32,
) -> Result<(Value, ExportStats), String> {
    if key_sha256 != VK_SHA || dimensions_sha256 != DIM_SHA || network != "testnet4" || k != 5 {
        return Err("matrix profile is scoped to the authenticated retained key".into());
    }
    let mut facts = Facts::default();
    key.serialize(Probe {
        facts: &mut facts,
        mode: Mode::Root,
    })
    .map_err(|e| e.to_string())?;
    let primary = curve(&mut facts, 0, "pallas", "pallas_scalar")?;
    let secondary = curve(&mut facts, 15, "vesta", "vesta_scalar")?;
    let value = json!({"schema":"bitvm2-nova-matrix-profile/v1","nova_version":"0.76.0",
        "nova_crate_sha256":CRATE_SHA,"header_revision":REVISION,"network":network,"k":k,
        "verifier_key_sha256":key_sha256,"verifier_dimensions_sha256":dimensions_sha256,
        "scope":"CSR lengths and declared columns only","primary":primary,"secondary":secondary});
    canonical_sha256(&value)?;
    Ok((value, facts.stats))
}

pub fn canonical_sha256(value: &Value) -> Result<String, String> {
    fn sorted(value: &Value, depth: usize) -> Result<Value, String> {
        if depth > 16 {
            return Err("matrix profile JSON depth".into());
        }
        match value {
            Value::Object(object) => {
                let mut fields: Vec<_> = object.iter().collect();
                fields.sort_by(|a, b| a.0.cmp(b.0));
                let mut out = Map::new();
                for (key, value) in fields {
                    if !key.is_ascii() {
                        return Err("non-ASCII profile key".into());
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
            _ => Err("unsupported matrix profile JSON value".into()),
        }
    }
    let bytes = serde_json::to_vec(&sorted(value, 0)?).map_err(|e| e.to_string())?;
    if bytes.len() > 16384 {
        return Err("matrix profile JSON byte budget".into());
    }
    Ok(hex::encode(Sha256::digest(bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::ser::SerializeSeq;
    use std::sync::atomic::{AtomicUsize, Ordering};
    static VISITS: AtomicUsize = AtomicUsize::new(0);
    struct Never;
    impl Serialize for Never {
        fn serialize<S: ser::Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
            VISITS.fetch_add(1, Ordering::SeqCst);
            Err(ser::Error::custom(
                "matrix element or unrelated key value visited",
            ))
        }
    }
    struct Length(Option<usize>);
    impl Serialize for Length {
        fn serialize<S: ser::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            let mut sequence = s.serialize_seq(self.0)?;
            sequence.serialize_element(&Never)?;
            sequence.end()
        }
    }
    #[derive(Serialize)]
    struct Matrix {
        data: Length,
        indices: Length,
        indptr: Length,
        cols: u64,
    }
    #[allow(non_snake_case)]
    #[derive(Serialize)]
    struct Shape {
        num_cons: u64,
        num_vars: u64,
        num_io: u64,
        A: Matrix,
        B: Matrix,
        C: Matrix,
    }
    #[allow(non_snake_case)]
    #[derive(Serialize)]
    struct Snark {
        S: Shape,
        vk_ee: Never,
    }
    #[derive(Serialize)]
    struct Key {
        vk_primary: Snark,
        vk_secondary: Snark,
        ro_consts_primary: Never,
    }
    fn matrix_fake(entries: usize, rows: usize, cols: u64) -> Matrix {
        Matrix {
            data: Length(Some(entries)),
            indices: Length(Some(entries)),
            indptr: Length(Some(rows + 1)),
            cols,
        }
    }
    fn shape(nc: u64, nv: u64) -> Shape {
        Shape {
            num_cons: nc,
            num_vars: nv,
            num_io: 2,
            A: matrix_fake(5, nc as usize - 1, nv + 3),
            B: matrix_fake(0, 0, 0),
            C: matrix_fake(11, nc as usize, nv + 3),
        }
    }
    fn key() -> Key {
        Key {
            vk_primary: Snark {
                S: shape(32, 16),
                vk_ee: Never,
            },
            vk_secondary: Snark {
                S: shape(8, 8),
                vk_ee: Never,
            },
            ro_consts_primary: Never,
        }
    }
    fn export(key: &Key) -> Result<(Value, ExportStats), String> {
        export_authenticated_vk(key, VK_SHA, DIM_SHA, "testnet4", 5)
    }
    #[test]
    fn all_six_matrices_are_counted_without_visiting_any_elements() {
        let (value, stats) = export(&key()).unwrap();
        assert_eq!(stats.numeric_fields_read, 12);
        assert_eq!(stats.sequence_lengths_read, 18);
        assert_eq!(stats.matrices_profiled, 6);
        assert_eq!(stats.matrix_elements_read, 0);
        assert!(!stats.matrix_payloads_materialized);
        assert!(!stats.full_key_materialized);
        assert_eq!(value["primary"]["field_role"], "pallas_scalar");
        assert_eq!(value["secondary"]["field_role"], "vesta_scalar");
        assert_eq!(value["primary"]["evaluation_cols"], 32);
        assert_eq!(value["primary"]["matrices"]["A"]["cols"], 19);
        assert_eq!(VISITS.load(Ordering::SeqCst), 0);
    }
    #[test]
    fn trailing_logical_zero_rows_and_non_square_shapes_are_preserved() {
        let (value, _) = export(&key()).unwrap();
        assert_eq!(value["primary"]["num_cons"], 32);
        assert_eq!(value["primary"]["num_vars"], 16);
        assert_eq!(value["primary"]["matrices"]["A"]["csr_rows"], 31);
        assert_eq!(value["primary"]["matrices"]["B"]["csr_rows"], 0);
        assert_eq!(value["primary"]["matrices"]["B"]["data_len"], 0);
    }
    #[test]
    fn inconsistent_lengths_shapes_and_domains_fail_closed() {
        let mut bad = key();
        bad.vk_primary.S.A.indices = Length(Some(4));
        assert!(export(&bad).is_err());
        bad = key();
        bad.vk_primary.S.A.indptr = Length(Some(0));
        assert!(export(&bad).is_err());
        bad = key();
        bad.vk_primary.S.A.indptr = Length(Some(34));
        assert!(export(&bad).is_err());
        bad = key();
        bad.vk_primary.S.A.cols = 33;
        assert!(export(&bad).is_err());
        bad = key();
        bad.vk_primary.S.A.cols = 0;
        assert!(export(&bad).is_err());
        bad = key();
        bad.vk_primary.S.num_vars = 0;
        assert!(export(&bad).is_err());
        bad = key();
        bad.vk_secondary.S.num_cons = 1 << 25;
        assert!(export(&bad).is_err());
        bad = key();
        bad.vk_primary.S.num_io = 3;
        assert!(export(&bad).is_err());
    }
    #[test]
    fn unknown_or_oversized_sequence_lengths_stop_before_element_visits() {
        let mut bad = key();
        bad.vk_primary.S.A.data = Length(None);
        assert!(export(&bad).is_err());
        bad = key();
        bad.vk_primary.S.A.data = Length(Some(usize::MAX));
        assert!(export(&bad).is_err());
        bad = key();
        bad.vk_primary.S.A.indptr = Length(Some(MAX_DIMENSION as usize + 2));
        assert!(export(&bad).is_err());
        assert_eq!(VISITS.load(Ordering::SeqCst), 0);
    }
    #[test]
    fn identity_and_canonical_digest_are_independent_of_json_field_order() {
        assert!(export_authenticated_vk(&key(), &"00".repeat(32), DIM_SHA, "testnet4", 5).is_err());
        assert!(export_authenticated_vk(&key(), VK_SHA, &"00".repeat(32), "testnet4", 5).is_err());
        assert!(export_authenticated_vk(&key(), VK_SHA, DIM_SHA, "mainnet", 5).is_err());
        assert!(export_authenticated_vk(&key(), VK_SHA, DIM_SHA, "testnet4", 10).is_err());
        assert_eq!(
            canonical_sha256(&json!({"z":2,"a":{"x":[1,"00"]}})).unwrap(),
            "63fee996985eddf1154dd76942ebe09225110f233b9bf2417e0259080b161a53"
        );
        assert!(canonical_sha256(&json!({"bad":1.0})).is_err());
    }
}
