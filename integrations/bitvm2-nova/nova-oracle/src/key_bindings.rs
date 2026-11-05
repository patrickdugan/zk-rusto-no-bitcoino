//! Export small semantic bindings from an already authenticated retained VK.
//! No full key JSON/Vec is materialized. Actual Nova DigestComputer streams
//! each selected Spartan key using the released bincode2/SHA3/low250 algorithm.
use ff::PrimeField;
use nova_snark::{
    digest::{DigestComputer, SimpleDigestible},
    provider::{PallasEngine, VestaEngine},
    traits::Engine,
};
use serde::{ser, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{fmt, io::Write};

const VK_SHA: &str = "1ae88a7bcfdc5f14d030d0baafa06ec17fe904a5ebed42f9bd6fa6105fdc8c24";
const DIM_SHA: &str = "de6333df2e41b5f5bae1c103fab862f8d6022fd54abeb80ba61920bc9f360edc";
const REVISION: &str = "de607d3db17d400dd6c2923d357f1d4a7bf233c7";

struct View<'a, T: ?Sized>(&'a T);
impl<T: ?Sized + Serialize> Serialize for View<'_, T> {
    fn serialize<S: ser::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}
impl<T: ?Sized + Serialize> SimpleDigestible for View<'_, T> {}

fn key_digest<F: PrimeField, T: ?Sized + Serialize>(value: &T) -> Result<String, Error> {
    let view = View(value);
    let digest = DigestComputer::<F, _>::new(&view)
        .digest()
        .map_err(|e| Error(e.to_string()))?;
    Ok(hex::encode(digest.to_repr()))
}

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

struct TinyWriter(Vec<u8>);
impl Write for TinyWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > 512 - self.0.len() {
            return Err(std::io::Error::other("tiny key JSON budget"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn tiny<T: ?Sized + Serialize>(value: &T) -> Result<Value, Error> {
    let mut writer = TinyWriter(Vec::new());
    serde_json::to_writer(&mut writer, value).map_err(|e| Error(e.to_string()))?;
    serde_json::from_slice(&writer.0).map_err(|e| Error(e.to_string()))
}

fn hex32(value: &Value) -> Result<(), Error> {
    let value = value
        .as_str()
        .ok_or_else(|| Error("expected scalar/point hex".into()))?;
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Error("noncanonical key scalar/point hex".into()));
    }
    Ok(())
}
fn small_key(value: &Value, scalar_key: bool) -> Result<(), Error> {
    let map = value
        .as_object()
        .ok_or_else(|| Error("expected tiny key object".into()))?;
    if map.len() != if scalar_key { 2 } else { 1 } || !map.contains_key("h") {
        return Err(Error("unexpected tiny key fields".into()));
    }
    hex32(&map["h"])?;
    if scalar_key {
        let ck = map
            .get("ck")
            .and_then(Value::as_array)
            .ok_or_else(|| Error("missing scalar generators".into()))?;
        if ck.len() != 1 {
            return Err(Error("expected exactly one scalar generator".into()));
        }
        hex32(&ck[0])?;
    }
    Ok(())
}

#[derive(Default, Serialize)]
pub struct ExportStats {
    streamed_spartan_key_digests: usize,
    tiny_fields_materialized: usize,
    skipped_fields: usize,
    full_key_materialized: bool,
}
#[derive(Default)]
struct Facts {
    // pp digest, primary/secondary Spartan digest, dk, and scalar commitment key.
    values: [Option<Value>; 7],
    stats: ExportStats,
}
impl Facts {
    fn record(&mut self, slot: usize, value: Value) -> Result<(), Error> {
        if self.values[slot].replace(value).is_some() {
            return Err(Error("duplicate key binding".into()));
        }
        Ok(())
    }
    fn get(&self, slot: usize) -> Result<Value, Error> {
        self.values[slot]
            .clone()
            .ok_or_else(|| Error(format!("missing key binding {slot}")))
    }
}

#[derive(Clone, Copy)]
enum Mode {
    Root,
    Spartan(usize),
    Evaluation(usize),
}
struct Probe<'a> {
    facts: &'a mut Facts,
    mode: Mode,
}
fn unexpected() -> Error {
    Error("unexpected key binding serialization shape".into())
}
macro_rules! reject_values {
    ($($method:ident($ty:ty)),* $(,)?) => { $(
        fn $method(self, _: $ty) -> Result<Self::Ok, Self::Error> { Err(unexpected()) }
    )* };
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
    fn serialize_seq(self, _: Option<usize>) -> Result<Self::SerializeSeq, Error> {
        Err(unexpected())
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
        Ok(self)
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
        field: &'static str,
        value: &T,
    ) -> Result<(), Error> {
        match (self.mode, field) {
            (Mode::Root, "pp_digest") => {
                let value = tiny(value)?;
                hex32(&value)?;
                self.facts.record(0, value)?;
                self.facts.stats.tiny_fields_materialized += 1;
            }
            (Mode::Root, "vk_primary" | "vk_secondary") => {
                let i = usize::from(field == "vk_secondary");
                let digest = if i == 0 {
                    key_digest::<<PallasEngine as Engine>::Scalar, _>(value)?
                } else {
                    key_digest::<<VestaEngine as Engine>::Scalar, _>(value)?
                };
                self.facts.record(1 + i, json!(digest))?;
                self.facts.stats.streamed_spartan_key_digests += 1;
                value.serialize(Probe {
                    facts: &mut *self.facts,
                    mode: Mode::Spartan(i),
                })?;
            }
            (Mode::Root, "dk_primary" | "dk_secondary") => {
                let i = usize::from(field == "dk_secondary");
                let value = tiny(value)?;
                small_key(&value, false)?;
                self.facts.record(3 + i, value)?;
                self.facts.stats.tiny_fields_materialized += 1;
            }
            (Mode::Spartan(i), "vk_ee") => value.serialize(Probe {
                facts: &mut *self.facts,
                mode: Mode::Evaluation(i),
            })?,
            (Mode::Evaluation(i), "ck_s") => {
                let value = tiny(value)?;
                small_key(&value, true)?;
                self.facts.record(5 + i, value)?;
                self.facts.stats.tiny_fields_materialized += 1;
            }
            _ => self.facts.stats.skipped_fields += 1,
        }
        Ok(())
    }
    fn end(self) -> Result<(), Error> {
        Ok(())
    }
}

pub fn export<T: Serialize>(
    key: &T,
    key_sha: &str,
    dimensions_sha: &str,
) -> Result<(Value, ExportStats), String> {
    if key_sha != VK_SHA || dimensions_sha != DIM_SHA {
        return Err("retained key/dimension pin required".into());
    }
    let mut facts = Facts::default();
    key.serialize(Probe {
        facts: &mut facts,
        mode: Mode::Root,
    })
    .map_err(|e| e.to_string())?;
    let value = (|| -> Result<Value, Error> {
        Ok(json!({"schema":"bitvm2-nova-replay-key-bindings/v1","header_revision":REVISION,
            "nova_version":"0.76.0","network":"testnet4","k":5,"verifier_key_sha256":key_sha,
            "verifier_dimensions_sha256":dimensions_sha,"pp_digest_le":facts.get(0)?,
            "primary":{"engine":"pallas","spartan_vk_digest_le":facts.get(1)?,"derand_key":facts.get(3)?,"ipa_scalar_key":facts.get(5)?},
            "secondary":{"engine":"vesta","spartan_vk_digest_le":facts.get(2)?,"derand_key":facts.get(4)?,"ipa_scalar_key":facts.get(6)?}}))
    })().map_err(|e| e.to_string())?;
    Ok((value, facts.stats))
}

pub fn canonical_sha256(value: &Value) -> Result<String, String> {
    fn sorted(value: &Value) -> Value {
        match value {
            Value::Object(map) => {
                let mut rows: Vec<_> = map.iter().collect();
                rows.sort_by(|a, b| a.0.cmp(b.0));
                Value::Object(
                    rows.into_iter()
                        .map(|(k, v)| (k.clone(), sorted(v)))
                        .collect(),
                )
            }
            Value::Array(rows) => Value::Array(rows.iter().map(sorted).collect()),
            _ => value.clone(),
        }
    }
    let bytes = serde_json::to_vec(&sorted(value)).map_err(|e| e.to_string())?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[derive(Serialize)]
    struct DigestFixture {
        i: u64,
        bytes: Vec<u8>,
        #[serde(skip)]
        cache: u64,
    }
    impl SimpleDigestible for DigestFixture {}
    #[test]
    fn transparent_view_uses_actual_upstream_digest_and_ignores_cache() {
        type F = <PallasEngine as Engine>::Scalar;
        let value = DigestFixture {
            i: 42,
            bytes: vec![1, 2, 3, 4],
            cache: 7,
        };
        let native = DigestComputer::<F, _>::new(&value).digest().unwrap();
        assert_eq!(
            key_digest::<F, _>(&value).unwrap(),
            hex::encode(native.to_repr())
        );
        let changed_cache = DigestFixture {
            cache: 999,
            ..value
        };
        assert_eq!(
            key_digest::<F, _>(&changed_cache).unwrap(),
            hex::encode(native.to_repr())
        );
        assert_eq!(changed_cache.cache, 999);
    }
    #[test]
    fn tiny_json_has_a_hard_materialization_budget() {
        assert!(tiny(&vec![255u8; 1024]).is_err());
        assert!(small_key(&json!({"h":"00".repeat(32),"ck":[]}), true).is_err());
        assert!(small_key(
            &json!({"h":"00".repeat(32),"ck":["00".repeat(32),"00".repeat(32)]}),
            true
        )
        .is_err());
    }
    struct Never;
    impl Serialize for Never {
        fn serialize<S: ser::Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
            panic!("unselected whole-key field was serialized")
        }
    }
    #[derive(Serialize)]
    struct FakeScalarKey {
        ck: Vec<String>,
        h: String,
    }
    #[derive(Serialize)]
    struct FakeEvaluation {
        ck_s: FakeScalarKey,
        unrelated: Vec<u8>,
    }
    #[allow(non_snake_case)]
    #[derive(Serialize)]
    struct FakeSpartan {
        vk_ee: FakeEvaluation,
        S: Vec<u8>,
    }
    #[derive(Serialize)]
    struct FakeDerand {
        h: String,
    }
    #[derive(Serialize)]
    struct FakeRoot {
        pp_digest: String,
        vk_primary: FakeSpartan,
        vk_secondary: FakeSpartan,
        dk_primary: FakeDerand,
        dk_secondary: FakeDerand,
        ro_constants: Never,
    }
    fn fake_spartan() -> FakeSpartan {
        FakeSpartan {
            vk_ee: FakeEvaluation {
                ck_s: FakeScalarKey {
                    ck: vec!["00".repeat(32)],
                    h: "00".repeat(32),
                },
                unrelated: vec![1, 2, 3],
            },
            S: vec![4, 5, 6],
        }
    }
    #[test]
    fn selective_metadata_skips_unselected_root_fields() {
        let key = FakeRoot {
            pp_digest: "01".repeat(32),
            vk_primary: fake_spartan(),
            vk_secondary: fake_spartan(),
            dk_primary: FakeDerand { h: "00".repeat(32) },
            dk_secondary: FakeDerand { h: "00".repeat(32) },
            ro_constants: Never,
        };
        let (value, stats) = export(&key, VK_SHA, DIM_SHA).unwrap();
        assert_eq!(value["pp_digest_le"], json!("01".repeat(32)));
        assert_eq!(
            value["primary"]["ipa_scalar_key"]["ck"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(stats.streamed_spartan_key_digests, 2);
        assert_eq!(stats.tiny_fields_materialized, 5);
        assert!(!stats.full_key_materialized);
    }
}
