//! Read dimensions from an already authenticated Nova 0.76.0 verifier key.
//!
//! Private upstream fields are inspected through their pinned serde schema.
//! Unselected fields are never serialized. Generator vectors stop at the
//! sequence-length callback, before any generator is visited or copied.
//! This exports metadata; the caller must first authenticate the complete key.
use serde::{ser, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fmt;

const MAX_DIMENSION: u64 = 1 << 24;
const REVISION: &str = "de607d3db17d400dd6c2923d357f1d4a7bf233c7";
const CRATE_SHA: &str = "c9bb3809a6c70057ea722c1c4fe5097cf29a3479d0b4671f3cddb1d81043bb31";

#[derive(Serialize)]
pub struct CurveDimensions {
    engine: &'static str,
    num_cons: u64,
    num_vars: u64,
    num_io: u64,
    outer_rounds: u32,
    inner_rounds: u32,
    batch_rounds: u32,
    ipa_rounds: u32,
    ipa_dimension: u64,
    ck_v_generators: u64,
    ck_s_generators: u64,
}

#[derive(Serialize)]
pub struct VerifierDimensions {
    schema: &'static str,
    nova_version: &'static str,
    nova_crate_sha256: &'static str,
    header_revision: &'static str,
    network: String,
    k: u32,
    verifier_key_sha256: String,
    outer_arity: u64,
    max_ipa_dimension: u64,
    primary: CurveDimensions,
    secondary: CurveDimensions,
}

#[derive(Default, Serialize)]
pub struct ExportStats {
    numeric_fields_read: usize,
    generator_lengths_read: usize,
    skipped_fields: usize,
    generator_elements_read: usize,
    full_key_materialized: bool,
}

#[derive(Default)]
struct Facts {
    // F_arity, then Nc/Nv/IO/ck_v/ck_s separately for each curve.
    values: [Option<u64>; 11],
    stats: ExportStats,
}

impl Facts {
    fn record(&mut self, slot: usize, value: u64) -> Result<(), ProbeError> {
        if self.values[slot].replace(value).is_some() {
            return Err(ProbeError::Message("duplicate dimension field".into()));
        }
        Ok(())
    }

    fn get(&self, slot: usize) -> Result<u64, String> {
        self.values[slot].ok_or_else(|| format!("missing trusted key dimension slot {slot}"))
    }
}

#[derive(Clone, Copy)]
enum Mode {
    Root,
    Snark(usize),
    Shape(usize),
    Evaluation(usize),
    Key(usize),
    Number(usize),
    Length(usize),
}

impl Mode {
    fn child(self, field: &str) -> Option<Self> {
        match (self, field) {
            (Self::Root, "F_arity") => Some(Self::Number(0)),
            (Self::Root, "vk_primary") => Some(Self::Snark(1)),
            (Self::Root, "vk_secondary") => Some(Self::Snark(6)),
            (Self::Snark(base), "S") => Some(Self::Shape(base)),
            (Self::Snark(base), "vk_ee") => Some(Self::Evaluation(base)),
            (Self::Shape(base), "num_cons") => Some(Self::Number(base)),
            (Self::Shape(base), "num_vars") => Some(Self::Number(base + 1)),
            (Self::Shape(base), "num_io") => Some(Self::Number(base + 2)),
            (Self::Evaluation(base), "ck_v") => Some(Self::Key(base + 3)),
            (Self::Evaluation(base), "ck_s") => Some(Self::Key(base + 4)),
            (Self::Key(slot), "ck") => Some(Self::Length(slot)),
            _ => None,
        }
    }
}

#[derive(Debug)]
enum ProbeError {
    Message(String),
    // Private control flow, caught only at the selected generator vector field.
    // It is never evidence of proof rejection and never catches an upstream panic.
    LengthCaptured,
}

impl fmt::Display for ProbeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Message(message) => f.write_str(message),
            Self::LengthCaptured => f.write_str("internal generator length capture"),
        }
    }
}
impl std::error::Error for ProbeError {}
impl ser::Error for ProbeError {
    fn custom<T: fmt::Display>(message: T) -> Self {
        Self::Message(message.to_string())
    }
}

struct Probe<'a> {
    facts: &'a mut Facts,
    mode: Mode,
}

fn unexpected() -> ProbeError {
    ProbeError::Message("unexpected trusted key serialization shape".into())
}

impl Probe<'_> {
    fn number(self, value: u64) -> Result<(), ProbeError> {
        if let Mode::Number(slot) = self.mode {
            self.facts.record(slot, value)?;
            self.facts.stats.numeric_fields_read += 1;
            Ok(())
        } else {
            Err(unexpected())
        }
    }
}

macro_rules! reject_values {
    ($($method:ident($ty:ty)),* $(,)?) => {
        $(fn $method(self, _: $ty) -> Result<Self::Ok, Self::Error> {
            Err(unexpected())
        })*
    };
}

impl<'a> ser::Serializer for Probe<'a> {
    type Ok = ();
    type Error = ProbeError;
    type SerializeSeq = ser::Impossible<(), ProbeError>;
    type SerializeTuple = ser::Impossible<(), ProbeError>;
    type SerializeTupleStruct = ser::Impossible<(), ProbeError>;
    type SerializeTupleVariant = ser::Impossible<(), ProbeError>;
    type SerializeMap = ser::Impossible<(), ProbeError>;
    type SerializeStruct = Self;
    type SerializeStructVariant = ser::Impossible<(), ProbeError>;

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

    fn serialize_u8(self, value: u8) -> Result<(), ProbeError> {
        self.number(value.into())
    }
    fn serialize_u16(self, value: u16) -> Result<(), ProbeError> {
        self.number(value.into())
    }
    fn serialize_u32(self, value: u32) -> Result<(), ProbeError> {
        self.number(value.into())
    }
    fn serialize_u64(self, value: u64) -> Result<(), ProbeError> {
        self.number(value)
    }
    fn serialize_u128(self, value: u128) -> Result<(), ProbeError> {
        self.number(u64::try_from(value).map_err(|_| unexpected())?)
    }
    fn serialize_none(self) -> Result<(), ProbeError> {
        Err(unexpected())
    }
    fn serialize_some<T: ?Sized + Serialize>(self, _: &T) -> Result<(), ProbeError> {
        Err(unexpected())
    }
    fn serialize_unit(self) -> Result<(), ProbeError> {
        Err(unexpected())
    }
    fn serialize_unit_struct(self, _: &'static str) -> Result<(), ProbeError> {
        Err(unexpected())
    }
    fn serialize_unit_variant(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
    ) -> Result<(), ProbeError> {
        Err(unexpected())
    }
    fn serialize_newtype_struct<T: ?Sized + Serialize>(
        self,
        _: &'static str,
        _: &T,
    ) -> Result<(), ProbeError> {
        Err(unexpected())
    }
    fn serialize_newtype_variant<T: ?Sized + Serialize>(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        _: &T,
    ) -> Result<(), ProbeError> {
        Err(unexpected())
    }
    fn serialize_seq(self, length: Option<usize>) -> Result<Self::SerializeSeq, ProbeError> {
        if let Mode::Length(slot) = self.mode {
            let length = length.ok_or_else(unexpected)?;
            self.facts
                .record(slot, u64::try_from(length).map_err(|_| unexpected())?)?;
            self.facts.stats.generator_lengths_read += 1;
            Err(ProbeError::LengthCaptured)
        } else {
            Err(unexpected())
        }
    }
    fn serialize_tuple(self, _: usize) -> Result<Self::SerializeTuple, ProbeError> {
        Err(unexpected())
    }
    fn serialize_tuple_struct(
        self,
        _: &'static str,
        _: usize,
    ) -> Result<Self::SerializeTupleStruct, ProbeError> {
        Err(unexpected())
    }
    fn serialize_tuple_variant(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        _: usize,
    ) -> Result<Self::SerializeTupleVariant, ProbeError> {
        Err(unexpected())
    }
    fn serialize_map(self, _: Option<usize>) -> Result<Self::SerializeMap, ProbeError> {
        Err(unexpected())
    }
    fn serialize_struct(
        self,
        _: &'static str,
        _: usize,
    ) -> Result<Self::SerializeStruct, ProbeError> {
        match self.mode {
            Mode::Number(_) | Mode::Length(_) => Err(unexpected()),
            _ => Ok(self),
        }
    }
    fn serialize_struct_variant(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        _: usize,
    ) -> Result<Self::SerializeStructVariant, ProbeError> {
        Err(unexpected())
    }
    fn is_human_readable(&self) -> bool {
        false
    }
}

impl ser::SerializeStruct for Probe<'_> {
    type Ok = ();
    type Error = ProbeError;

    fn serialize_field<T: ?Sized + Serialize>(
        &mut self,
        field: &'static str,
        value: &T,
    ) -> Result<(), ProbeError> {
        let Some(mode) = self.mode.child(field) else {
            self.facts.stats.skipped_fields += 1;
            return Ok(());
        };
        let result = value.serialize(Probe {
            facts: &mut *self.facts,
            mode,
        });
        match (mode, result) {
            (Mode::Length(_), Err(ProbeError::LengthCaptured)) => Ok(()),
            (_, result) => result,
        }
    }

    fn end(self) -> Result<(), ProbeError> {
        Ok(())
    }
}

fn curve(facts: &Facts, base: usize, engine: &'static str) -> Result<CurveDimensions, String> {
    let (nc, nv, io) = (facts.get(base)?, facts.get(base + 1)?, facts.get(base + 2)?);
    let (ck_v, ck_s) = (facts.get(base + 3)?, facts.get(base + 4)?);
    if !nc.is_power_of_two() || !nv.is_power_of_two() || io != 2 || nv < 8 {
        return Err(format!("{engine}: unsupported trusted R1CS dimensions"));
    }
    let n = nc.max(nv);
    if n > MAX_DIMENSION || ck_v < n || ck_v > MAX_DIMENSION || ck_s == 0 || ck_s > MAX_DIMENSION {
        return Err(format!("{engine}: trusted IPA capacity/resource bound"));
    }
    let (mc, mv) = (nc.trailing_zeros(), nv.trailing_zeros());
    let m = mc.max(mv);
    if m >= 32 {
        return Err(format!("{engine}: IPA shift bound"));
    }
    Ok(CurveDimensions {
        engine,
        num_cons: nc,
        num_vars: nv,
        num_io: io,
        outer_rounds: mc,
        inner_rounds: mv + 1,
        batch_rounds: m,
        ipa_rounds: m,
        ipa_dimension: n,
        ck_v_generators: ck_v,
        ck_s_generators: ck_s,
    })
}

/// Call only after checking the complete reconstructed key's pinned SHA-256.
pub fn export<T: Serialize>(
    key: &T,
    key_sha256: &str,
    network: &str,
    k: u32,
) -> Result<(VerifierDimensions, ExportStats), String> {
    if key_sha256.len() != 64
        || !key_sha256
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || !matches!(network, "mainnet" | "testnet4")
        || !(1..=64).contains(&k)
    {
        return Err("invalid authenticated dimension identity".into());
    }
    let mut facts = Facts::default();
    key.serialize(Probe {
        facts: &mut facts,
        mode: Mode::Root,
    })
    .map_err(|e| e.to_string())?;
    let arity = facts.get(0)?;
    if arity != 17 {
        return Err("trusted key F_arity must equal header arity17".into());
    }
    let primary = curve(&facts, 1, "pallas")?;
    let secondary = curve(&facts, 6, "vesta")?;
    Ok((
        VerifierDimensions {
            schema: "bitvm2-nova-verifier-dimensions/v1",
            nova_version: "0.76.0",
            nova_crate_sha256: CRATE_SHA,
            header_revision: REVISION,
            network: network.into(),
            k,
            verifier_key_sha256: key_sha256.into(),
            outer_arity: arity,
            max_ipa_dimension: MAX_DIMENSION,
            primary,
            secondary,
        },
        facts.stats,
    ))
}

/// ASCII descriptor fields, sorted object keys and compact JSON, no newline.
/// Pin this digest independently; an embedded key digest cannot authenticate
/// arbitrary descriptor JSON supplied by an untrusted proof or transport.
pub fn canonical_sha256(descriptor: &VerifierDimensions) -> Result<String, String> {
    fn sorted(value: Value) -> Value {
        match value {
            Value::Object(object) => {
                let mut fields: Vec<_> = object.into_iter().collect();
                fields.sort_by(|a, b| a.0.cmp(&b.0));
                Value::Object(
                    fields
                        .into_iter()
                        .map(|(key, value)| (key, sorted(value)))
                        .collect(),
                )
            }
            Value::Array(values) => Value::Array(values.into_iter().map(sorted).collect()),
            other => other,
        }
    }
    let value = serde_json::to_value(descriptor).map_err(|e| e.to_string())?;
    let canonical = serde_json::to_vec(&sorted(value)).map_err(|e| e.to_string())?;
    Ok(hex::encode(Sha256::digest(canonical)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::ser::SerializeSeq;

    struct Never;
    impl Serialize for Never {
        fn serialize<S: ser::Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
            Err(ser::Error::custom("unselected key object was visited"))
        }
    }
    struct Generators(usize);
    impl Serialize for Generators {
        fn serialize<S: ser::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            let mut seq = serializer.serialize_seq(Some(self.0))?;
            seq.serialize_element(&Never)?;
            seq.end()
        }
    }
    #[derive(Serialize)]
    struct Key {
        ck: Generators,
        h: Never,
    }
    #[derive(Serialize)]
    struct Evaluation {
        ck_v: Key,
        ck_s: Key,
    }
    #[allow(non_snake_case)]
    #[derive(Serialize)]
    struct Shape {
        num_cons: u64,
        num_vars: u64,
        num_io: u64,
        A: Never,
        B: Never,
        C: Never,
    }
    #[allow(non_snake_case)]
    #[derive(Serialize)]
    struct Snark {
        vk_ee: Evaluation,
        S: Shape,
    }
    #[allow(non_snake_case)]
    #[derive(Serialize)]
    struct Root {
        F_arity: u64,
        vk_primary: Snark,
        vk_secondary: Snark,
        ro_consts_primary: Never,
    }

    fn snark(nc: u64, nv: u64, ck_v: usize, ck_s: usize) -> Snark {
        Snark {
            vk_ee: Evaluation {
                ck_v: Key {
                    ck: Generators(ck_v),
                    h: Never,
                },
                ck_s: Key {
                    ck: Generators(ck_s),
                    h: Never,
                },
            },
            S: Shape {
                num_cons: nc,
                num_vars: nv,
                num_io: 2,
                A: Never,
                B: Never,
                C: Never,
            },
        }
    }
    fn root() -> Root {
        Root {
            F_arity: 17,
            vk_primary: snark(32, 16, 32, 1),
            vk_secondary: snark(8, 8, 8, 1),
            ro_consts_primary: Never,
        }
    }
    fn exported(key: &Root) -> Result<(VerifierDimensions, ExportStats), String> {
        export(key, &"00".repeat(32), "testnet4", 5)
    }

    #[test]
    fn exact_fields_skip_matrices_constants_and_generator_elements() {
        let (d, stats) = exported(&root()).expect("bounded synthetic key");
        assert_eq!(
            (
                d.primary.outer_rounds,
                d.primary.inner_rounds,
                d.primary.ipa_rounds
            ),
            (5, 5, 5)
        );
        assert_eq!(
            (
                d.primary.num_cons,
                d.primary.num_vars,
                d.primary.ipa_dimension
            ),
            (32, 16, 32)
        );
        assert_eq!(
            (stats.numeric_fields_read, stats.generator_lengths_read),
            (7, 4)
        );
        assert_eq!(stats.generator_elements_read, 0);
        assert!(!stats.full_key_materialized);
        // Independent Python sort_keys/compact/ensure_ascii reference vector.
        assert_eq!(
            canonical_sha256(&d).unwrap(),
            "7b3454850a22970014551061bc9e3a9b53109219b0b3545baa0c99c9f8294ab7"
        );
    }
    #[test]
    fn trusted_dimension_bounds_reject_before_downstream_verification() {
        for (nc, nv, ck_v, ck_s) in [
            (0, 8, 8, 1),
            (9, 8, 16, 1),
            (8, 4, 8, 1),
            (16, 8, 8, 1),
            (8, 8, 8, 0),
            (1 << 25, 8, 1 << 25, 1),
        ] {
            let mut key = root();
            key.vk_primary = snark(nc, nv, ck_v, ck_s);
            assert!(exported(&key).is_err());
        }
        let mut key = root();
        key.F_arity = 16;
        assert!(exported(&key).is_err());
        key = root();
        key.vk_primary.S.num_io = 3;
        assert!(exported(&key).is_err());
    }
    #[test]
    fn missing_fields_and_invalid_identity_fail_closed() {
        #[derive(Serialize)]
        struct Missing {
            unrelated: u64,
        }
        assert!(export(&Missing { unrelated: 17 }, &"00".repeat(32), "testnet4", 5).is_err());
        assert!(export(&root(), &"FF".repeat(32), "testnet4", 5).is_err());
        assert!(export(&root(), &"00".repeat(32), "other", 5).is_err());
    }
}
