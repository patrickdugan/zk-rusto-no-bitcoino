//! Optional borrowed export of actual ordered IPA vector generators.
//!
//! The caller authenticates the full VK before entry. This module authenticates
//! the independent dimension descriptor before creating any output. It does no
//! MSM and emits no proof-verification receipt. Only the selected original Vec
//! serializer visits generators; no complete key/vector is cloned or buffered.
use serde::{ser, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::{
    fmt,
    fs::{self, OpenOptions},
    io::{self, BufWriter, Write},
    path::{Component, Path, PathBuf},
};

const VK_SHA: &str = "1ae88a7bcfdc5f14d030d0baafa06ec17fe904a5ebed42f9bd6fa6105fdc8c24";
const DIM_SHA: &str = "de6333df2e41b5f5bae1c103fab862f8d6022fd54abeb80ba61920bc9f360edc";
const REVISION: &str = "de607d3db17d400dd6c2923d357f1d4a7bf233c7";
const CRATE_SHA: &str = "c9bb3809a6c70057ea722c1c4fe5097cf29a3479d0b4671f3cddb1d81043bb31";
const FILE_CAP: u64 = 32 << 20;
const TOTAL_CAP: u64 = 32 << 20;
const BUFFER_BYTES: usize = 64 << 10;
const ROLES: [&str; 2] = ["primary", "secondary"];
const ENGINES: [&str; 2] = ["pallas", "vesta"];
const BASES: [&str; 2] = ["pallas_base", "vesta_base"];
const SCALARS: [&str; 2] = ["pallas_scalar", "vesta_scalar"];
const FILENAMES: [&str; 2] = ["primary-generators.bin", "secondary-generators.bin"];
const COUNTS: [u64; 2] = [524288, 16384];
type Result<T> = std::result::Result<T, String>;

#[derive(Clone)]
struct Plan {
    role: usize,
    count: u64,
    bytes: u64,
}
impl Plan {
    fn new(role: usize, count: u64) -> Result<Self> {
        let bytes = count
            .checked_mul(32)
            .and_then(|bytes| bytes.checked_add(8))
            .ok_or("IPA generator length overflow")?;
        if role >= 2 || count == 0 || bytes > FILE_CAP {
            return Err("unsupported IPA generator role/count/file cap".into());
        }
        Ok(Self { role, count, bytes })
    }
}
fn total_bytes(plans: &[Plan; 2]) -> Result<u64> {
    let total = plans[0]
        .bytes
        .checked_add(plans[1].bytes)
        .ok_or("IPA generator total overflow")?;
    if total > TOTAL_CAP {
        return Err("IPA generator collection exceeds 32 MiB cap".into());
    }
    Ok(total)
}
fn plans(dimensions: &Value) -> Result<[Plan; 2]> {
    if canonical_sha256(dimensions)? != DIM_SHA
        || dimensions["schema"] != "bitvm2-nova-verifier-dimensions/v1"
        || dimensions["nova_version"] != "0.76.0"
        || dimensions["nova_crate_sha256"] != CRATE_SHA
        || dimensions["header_revision"] != REVISION
        || dimensions["network"] != "testnet4"
        || dimensions["k"] != 5
        || dimensions["verifier_key_sha256"] != VK_SHA
    {
        return Err("IPA export requires independently pinned actual VK dimensions".into());
    }
    let mut result = Vec::with_capacity(2);
    for role in 0..2 {
        let curve = &dimensions[ROLES[role]];
        let count = curve["ck_v_generators"]
            .as_u64()
            .ok_or("missing trusted IPA generator count")?;
        if curve["engine"] != ENGINES[role]
            || count != COUNTS[role]
            || curve["ipa_dimension"].as_u64() != Some(count)
            || curve["ck_s_generators"] != 1
        {
            return Err("IPA generator count/curve differs from retained scope".into());
        }
        result.push(Plan::new(role, count)?);
    }
    let plans: [Plan; 2] = result.try_into().map_err(|_| "two IPA roles required")?;
    total_bytes(&plans)?;
    Ok(plans)
}

struct CheckedWriter<W> {
    inner: W,
    plan: Plan,
    position: u64,
    whole: Sha256,
    count_hash: Sha256,
    points_hash: Sha256,
}
impl<W: Write> CheckedWriter<W> {
    fn new(inner: W, plan: Plan) -> Self {
        Self {
            inner,
            plan,
            position: 0,
            whole: Sha256::new(),
            count_hash: Sha256::new(),
            points_hash: Sha256::new(),
        }
    }
    fn finish(mut self) -> Result<Value> {
        if self.position != self.plan.bytes {
            return Err("IPA serializer produced truncated generator payload".into());
        }
        self.inner.flush().map_err(|e| e.to_string())?;
        Ok(
            json!({"role":ROLES[self.plan.role],"engine":ENGINES[self.plan.role],
            "base_field_role":BASES[self.plan.role],"scalar_field_role":SCALARS[self.plan.role],
            "filename":FILENAMES[self.plan.role],"count":self.plan.count,"bytes":self.position,
            "sha256":hex::encode(self.whole.finalize()),"segments":[
                {"name":"count","offset":0,"bytes":8,"sha256":hex::encode(self.count_hash.finalize())},
                {"name":"points","offset":8,"bytes":self.plan.bytes-8,"sha256":hex::encode(self.points_hash.finalize())}]}),
        )
    }
}
fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
impl<W: Write> Write for CheckedWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let length = u64::try_from(bytes.len()).map_err(|_| invalid("IPA write length"))?;
        let end = self
            .position
            .checked_add(length)
            .ok_or_else(|| invalid("IPA generator write overflow"))?;
        if end > self.plan.bytes || end > FILE_CAP {
            return Err(invalid("IPA serializer exceeded exact file size/cap"));
        }
        if self.position < 8 {
            let stop = end.min(8);
            if bytes[..(stop - self.position) as usize]
                != self.plan.count.to_le_bytes()[self.position as usize..stop as usize]
            {
                return Err(invalid("IPA generator Vec count/layout mismatch"));
            }
        }
        let written = self.inner.write(bytes)?;
        if written > bytes.len() {
            return Err(invalid("underlying IPA writer returned impossible count"));
        }
        let end = self.position + written as u64;
        self.whole.update(&bytes[..written]);
        if self.position < 8 {
            self.count_hash
                .update(&bytes[..(end.min(8) - self.position) as usize]);
        }
        if end > 8 {
            self.points_hash
                .update(&bytes[(8u64.saturating_sub(self.position)) as usize..written]);
        }
        self.position = end;
        Ok(written)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[derive(Default, Serialize)]
pub struct ExportStats {
    files_written: usize,
    total_bytes: u64,
    selected_generator_fields: usize,
    skipped_fields: usize,
    per_file_cap_bytes: u64,
    total_cap_bytes: u64,
    writer_buffer_bytes: usize,
    full_key_materialized: bool,
    generator_vectors_materialized: bool,
}
struct Context<'a> {
    directory: &'a Path,
    plans: [Plan; 2],
    seen: [bool; 8],
    files: [Option<Value>; 2],
    stats: ExportStats,
}
impl Context<'_> {
    fn write<T: ?Sized + Serialize>(&mut self, role: usize, value: &T) -> Result<()> {
        if self.files[role].is_some() {
            return Err("duplicate selected IPA generator vector".into());
        }
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(self.directory.join(FILENAMES[role]))
            .map_err(|e| format!("create IPA generator file: {e}"))?;
        let writer = CheckedWriter::new(file, self.plans[role].clone());
        let mut buffer = BufWriter::with_capacity(BUFFER_BYTES, writer);
        // Original affine Vec serde, directly borrowed from the authenticated VK.
        bincode::serialize_into(&mut buffer, value).map_err(|e| e.to_string())?;
        buffer.flush().map_err(|e| e.to_string())?;
        let writer = buffer.into_inner().map_err(|e| e.to_string())?;
        let result = writer.finish()?;
        self.stats.total_bytes = self
            .stats
            .total_bytes
            .checked_add(self.plans[role].bytes)
            .ok_or("IPA written total overflow")?;
        if self.stats.total_bytes > TOTAL_CAP {
            return Err("IPA written total exceeds cap".into());
        }
        self.stats.files_written += 1;
        self.stats.selected_generator_fields += 1;
        self.files[role] = Some(result);
        Ok(())
    }
}
#[derive(Clone, Copy)]
enum Mode {
    Root,
    Spartan(usize),
    Evaluation(usize),
    Key(usize),
    Vector(usize),
}
impl Mode {
    fn child(self, name: &str) -> Option<(Self, usize)> {
        match (self, name) {
            (Self::Root, "vk_primary") => Some((Self::Spartan(0), 0)),
            (Self::Root, "vk_secondary") => Some((Self::Spartan(1), 1)),
            (Self::Spartan(role), "vk_ee") => Some((Self::Evaluation(role), 2 + role)),
            (Self::Evaluation(role), "ck_v") => Some((Self::Key(role), 4 + role)),
            (Self::Key(role), "ck") => Some((Self::Vector(role), 6 + role)),
            _ => None,
        }
    }
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
fn unexpected() -> Error {
    Error("unexpected selected IPA generator path/type".into())
}
struct Select<'a, 'b> {
    context: &'a mut Context<'b>,
    mode: Mode,
}
macro_rules! reject_values {
    ($($method:ident($ty:ty)),* $(,)?)=>{$(fn $method(self,_:$ty)->std::result::Result<Self::Ok,Self::Error>{Err(unexpected())})*};
}
impl<'a, 'b> ser::Serializer for Select<'a, 'b> {
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
    fn serialize_none(self) -> std::result::Result<(), Error> {
        Err(unexpected())
    }
    fn serialize_some<T: ?Sized + Serialize>(self, _: &T) -> std::result::Result<(), Error> {
        Err(unexpected())
    }
    fn serialize_unit(self) -> std::result::Result<(), Error> {
        Err(unexpected())
    }
    fn serialize_unit_struct(self, _: &'static str) -> std::result::Result<(), Error> {
        Err(unexpected())
    }
    fn serialize_unit_variant(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
    ) -> std::result::Result<(), Error> {
        Err(unexpected())
    }
    fn serialize_newtype_struct<T: ?Sized + Serialize>(
        self,
        _: &'static str,
        _: &T,
    ) -> std::result::Result<(), Error> {
        Err(unexpected())
    }
    fn serialize_newtype_variant<T: ?Sized + Serialize>(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        _: &T,
    ) -> std::result::Result<(), Error> {
        Err(unexpected())
    }
    fn serialize_seq(self, _: Option<usize>) -> std::result::Result<Self::SerializeSeq, Error> {
        Err(unexpected())
    }
    fn serialize_tuple(self, _: usize) -> std::result::Result<Self::SerializeTuple, Error> {
        Err(unexpected())
    }
    fn serialize_tuple_struct(
        self,
        _: &'static str,
        _: usize,
    ) -> std::result::Result<Self::SerializeTupleStruct, Error> {
        Err(unexpected())
    }
    fn serialize_tuple_variant(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        _: usize,
    ) -> std::result::Result<Self::SerializeTupleVariant, Error> {
        Err(unexpected())
    }
    fn serialize_map(self, _: Option<usize>) -> std::result::Result<Self::SerializeMap, Error> {
        Err(unexpected())
    }
    fn serialize_struct(
        self,
        _: &'static str,
        _: usize,
    ) -> std::result::Result<Self::SerializeStruct, Error> {
        if matches!(self.mode, Mode::Vector(_)) {
            Err(unexpected())
        } else {
            Ok(self)
        }
    }
    fn serialize_struct_variant(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        _: usize,
    ) -> std::result::Result<Self::SerializeStructVariant, Error> {
        Err(unexpected())
    }
    fn is_human_readable(&self) -> bool {
        false
    }
}
impl ser::SerializeStruct for Select<'_, '_> {
    type Ok = ();
    type Error = Error;
    fn serialize_field<T: ?Sized + Serialize>(
        &mut self,
        name: &'static str,
        value: &T,
    ) -> std::result::Result<(), Error> {
        let Some((mode, slot)) = self.mode.child(name) else {
            self.context.stats.skipped_fields += 1;
            return Ok(());
        };
        if std::mem::replace(&mut self.context.seen[slot], true) {
            return Err(Error("duplicate selected IPA generator path".into()));
        }
        if let Mode::Vector(role) = mode {
            self.context.write(role, value).map_err(Error)
        } else {
            value.serialize(Select {
                context: &mut *self.context,
                mode,
            })
        }
    }
    fn end(self) -> std::result::Result<(), Error> {
        Ok(())
    }
}
fn selected<T: Serialize>(
    key: &T,
    directory: &Path,
    plans: [Plan; 2],
) -> Result<(Vec<Value>, ExportStats)> {
    let total = total_bytes(&plans)?;
    let mut context = Context {
        directory,
        plans,
        seen: [false; 8],
        files: [None, None],
        stats: ExportStats {
            per_file_cap_bytes: FILE_CAP,
            total_cap_bytes: TOTAL_CAP,
            writer_buffer_bytes: BUFFER_BYTES,
            ..ExportStats::default()
        },
    };
    key.serialize(Select {
        context: &mut context,
        mode: Mode::Root,
    })
    .map_err(|e| e.to_string())?;
    if context.seen.iter().any(|seen| !seen)
        || context.stats.files_written != 2
        || context.stats.total_bytes != total
    {
        return Err("incomplete selected IPA generator collection".into());
    }
    let files = context
        .files
        .into_iter()
        .map(|file| file.ok_or_else(|| "missing selected IPA generator result".to_owned()))
        .collect::<Result<_>>()?;
    Ok((files, context.stats))
}
fn output_path(directory: &Path, current: &Path) -> Result<PathBuf> {
    let components: Vec<_> = directory.components().collect();
    if components.len() < 2
        || components.first() != Some(&Component::Normal(std::ffi::OsStr::new("results")))
        || components
            .iter()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err("IPA output must be a relative new child under results".into());
    }
    let current = fs::canonicalize(current).map_err(|e| e.to_string())?;
    let results = fs::canonicalize(current.join("results")).map_err(|e| e.to_string())?;
    let parent = fs::canonicalize(current.join(directory.parent().ok_or("IPA output parent")?))
        .map_err(|e| e.to_string())?;
    if !results.starts_with(&current) || !parent.starts_with(&results) {
        return Err("IPA output parent escapes owned hosted results".into());
    }
    Ok(parent.join(directory.file_name().ok_or("IPA output name")?))
}
fn canonical_bytes(value: &Value) -> Result<Vec<u8>> {
    fn sorted(value: &Value, depth: usize) -> Result<Value> {
        if depth > 16 {
            return Err("IPA collection JSON depth".into());
        }
        match value {
            Value::Object(object) => {
                let mut fields: Vec<_> = object.iter().collect();
                fields.sort_by(|a, b| a.0.cmp(b.0));
                let mut result = Map::new();
                for (key, value) in fields {
                    if !key.is_ascii() {
                        return Err("non-ASCII IPA collection key".into());
                    }
                    result.insert(key.clone(), sorted(value, depth + 1)?);
                }
                Ok(Value::Object(result))
            }
            Value::Array(values) => Ok(Value::Array(
                values
                    .iter()
                    .map(|value| sorted(value, depth + 1))
                    .collect::<Result<_>>()?,
            )),
            Value::String(value) if value.is_ascii() => Ok(Value::String(value.clone())),
            Value::Number(value) if value.as_u64().is_some() => Ok(Value::Number(value.clone())),
            _ => Err("unsupported IPA collection JSON value".into()),
        }
    }
    let bytes = serde_json::to_vec(&sorted(value, 0)?).map_err(|e| e.to_string())?;
    if bytes.len() > 16384 {
        return Err("IPA collection JSON byte cap".into());
    }
    Ok(bytes)
}
pub fn canonical_sha256(value: &Value) -> Result<String> {
    Ok(hex::encode(Sha256::digest(canonical_bytes(value)?)))
}
/// Full VK authentication must have succeeded at the call site. The independently
/// pinned descriptor binds counts but cannot authenticate an arbitrary key object.
pub fn export_authenticated_vk<T: Serialize>(
    key: &T,
    dimensions: &Value,
    directory: &Path,
) -> Result<(Value, ExportStats)> {
    let plans = plans(dimensions)?;
    let directory = output_path(
        directory,
        &std::env::current_dir().map_err(|e| e.to_string())?,
    )?;
    fs::create_dir(&directory).map_err(|e| format!("create new IPA output directory: {e}"))?;
    let (files, stats) = selected(key, &directory, plans)?;
    let collection = json!({"schema":"bitvm2-nova-ipa-generators/v1","nova_version":"0.76.0",
        "nova_crate_sha256":CRATE_SHA,"header_revision":REVISION,"network":"testnet4","k":5,
        "verifier_key_sha256":VK_SHA,"verifier_dimensions_sha256":DIM_SHA,
        "encoding":"bincode-1.3.3-legacy-fixed-little-endian","total_bytes":stats.total_bytes,"files":files});
    let bytes = canonical_bytes(&collection)?;
    let mut manifest = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(directory.join("collection.json"))
        .map_err(|e| e.to_string())?;
    manifest.write_all(&bytes).map_err(|e| e.to_string())?;
    manifest.flush().map_err(|e| e.to_string())?;
    Ok((collection, stats))
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2curves::group::GroupEncoding;
    use nova_snark::{
        provider::{traits::DlogGroup, PallasEngine, VestaEngine},
        traits::Engine,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};
    type A = <<PallasEngine as Engine>::GE as DlogGroup>::AffineGroupElement;
    type B = <<VestaEngine as Engine>::GE as DlogGroup>::AffineGroupElement;
    fn primary() -> Vec<A> {
        vec![
            <PallasEngine as Engine>::GE::gen().affine(),
            <PallasEngine as Engine>::GE::zero().affine(),
        ]
    }
    fn secondary() -> Vec<B> {
        vec![
            <VestaEngine as Engine>::GE::gen().affine(),
            <VestaEngine as Engine>::GE::zero().affine(),
        ]
    }
    fn raw() -> Vec<u8> {
        bincode::serialize(&primary()).unwrap()
    }
    fn toy_plan() -> Plan {
        Plan::new(0, 2).unwrap()
    }
    fn sha(bytes: &[u8]) -> String {
        hex::encode(Sha256::digest(bytes))
    }
    #[test]
    fn actual_affine_serde_for_both_curves_matches_mature_compressed_encoding_and_hashes() {
        let p = primary();
        let s = secondary();
        for (bytes, points) in [
            (
                bincode::serialize(&p).unwrap(),
                p.iter()
                    .map(|point| point.to_bytes().as_ref().to_vec())
                    .collect::<Vec<_>>(),
            ),
            (
                bincode::serialize(&s).unwrap(),
                s.iter()
                    .map(|point| point.to_bytes().as_ref().to_vec())
                    .collect::<Vec<_>>(),
            ),
        ] {
            let mut expected = 2u64.to_le_bytes().to_vec();
            for point in points {
                assert_eq!(point.len(), 32);
                expected.extend(point);
            }
            assert_eq!(bytes, expected);
            assert_eq!(bytes.len(), 8 + 32 * 2);
            assert_eq!(&bytes[40..], &[0u8; 32]);
        }
        let bytes = raw();
        let mut writer = CheckedWriter::new(Vec::new(), toy_plan());
        for byte in &bytes {
            writer.write_all(&[*byte]).unwrap();
        }
        let result = writer.finish().unwrap();
        assert_eq!(result["sha256"], sha(&bytes));
        assert_eq!(result["segments"][0]["sha256"], sha(&bytes[..8]));
        assert_eq!(result["segments"][1]["sha256"], sha(&bytes[8..]));
    }
    #[test]
    fn count_prefix_exact_size_overflow_and_resource_caps_fail_closed() {
        let bytes = raw();
        for i in 0..8 {
            let mut bad = bytes.clone();
            bad[i] ^= 1;
            assert!(CheckedWriter::new(Vec::new(), toy_plan())
                .write_all(&bad)
                .is_err());
        }
        let mut short = CheckedWriter::new(Vec::new(), toy_plan());
        short.write_all(&bytes[..bytes.len() - 1]).unwrap();
        assert!(short.finish().is_err());
        let mut long = CheckedWriter::new(Vec::new(), toy_plan());
        long.write_all(&bytes).unwrap();
        assert!(long.write_all(&[0]).is_err());
        assert!(Plan::new(2, 2).is_err());
        assert!(Plan::new(0, 0).is_err());
        assert!(Plan::new(0, u64::MAX).is_err());
        assert!(Plan::new(0, 1 << 20).is_err());
        let plan = Plan::new(0, (1 << 20) - 1).unwrap();
        assert!(total_bytes(&[plan.clone(), plan]).is_err());
    }
    struct ShortWriter {
        bytes: Vec<u8>,
        fail_after: Option<usize>,
        fail_flush: bool,
    }
    impl Write for ShortWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.fail_after == Some(self.bytes.len()) {
                return Err(io::Error::other("injected IPA write failure"));
            }
            let n = bytes.len().min(3).min(
                self.fail_after
                    .map_or(usize::MAX, |limit| limit - self.bytes.len()),
            );
            self.bytes.extend_from_slice(&bytes[..n]);
            Ok(n)
        }
        fn flush(&mut self) -> io::Result<()> {
            if self.fail_flush {
                Err(io::Error::other("injected IPA flush failure"))
            } else {
                Ok(())
            }
        }
    }
    #[test]
    fn partial_write_hashes_only_successful_bytes_and_io_errors_propagate() {
        let bytes = raw();
        let mut writer = CheckedWriter::new(
            ShortWriter {
                bytes: vec![],
                fail_after: None,
                fail_flush: false,
            },
            toy_plan(),
        );
        writer.write_all(&bytes).unwrap();
        assert_eq!(writer.finish().unwrap()["sha256"], sha(&bytes));
        let mut writer = CheckedWriter::new(
            ShortWriter {
                bytes: vec![],
                fail_after: Some(9),
                fail_flush: false,
            },
            toy_plan(),
        );
        assert!(writer.write_all(&bytes).is_err());
        assert_eq!(writer.position, 9);
        assert_eq!(
            hex::encode(writer.whole.clone().finalize()),
            sha(&bytes[..9])
        );
        assert!(writer.finish().is_err());
        let mut writer = CheckedWriter::new(
            ShortWriter {
                bytes: vec![],
                fail_after: None,
                fail_flush: true,
            },
            toy_plan(),
        );
        writer.write_all(&bytes).unwrap();
        assert!(writer.finish().is_err());
    }
    struct Never;
    impl Serialize for Never {
        fn serialize<S: ser::Serializer>(&self, _: S) -> std::result::Result<S::Ok, S::Error> {
            Err(ser::Error::custom("unselected IPA key field visited"))
        }
    }
    #[derive(Serialize)]
    struct Ck<T> {
        ck: Vec<T>,
        h: Never,
    }
    #[derive(Serialize)]
    struct Evaluation<T> {
        ck_v: Ck<T>,
        ck_s: Never,
    }
    #[derive(Serialize)]
    #[allow(non_snake_case)]
    struct Spartan<T> {
        vk_ee: Evaluation<T>,
        S: Never,
    }
    #[derive(Serialize)]
    struct Key {
        vk_primary: Spartan<A>,
        vk_secondary: Spartan<B>,
        ignored: Never,
    }
    fn key() -> Key {
        Key {
            vk_primary: Spartan {
                vk_ee: Evaluation {
                    ck_v: Ck {
                        ck: primary(),
                        h: Never,
                    },
                    ck_s: Never,
                },
                S: Never,
            },
            vk_secondary: Spartan {
                vk_ee: Evaluation {
                    ck_v: Ck {
                        ck: secondary(),
                        h: Never,
                    },
                    ck_s: Never,
                },
                S: Never,
            },
            ignored: Never,
        }
    }
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    fn directory() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "nova-ipa-generators-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        path
    }
    #[test]
    fn exact_private_routes_skip_unselected_keys_and_fail_on_missing_duplicate_or_overwrite() {
        let plans = [Plan::new(0, 2).unwrap(), Plan::new(1, 2).unwrap()];
        let path = directory();
        let (files, stats) = selected(&key(), &path, plans.clone()).unwrap();
        assert_eq!(files.len(), 2);
        assert_eq!(stats.selected_generator_fields, 2);
        assert_eq!(fs::read(path.join(FILENAMES[0])).unwrap(), raw());
        assert_eq!(
            fs::read(path.join(FILENAMES[1])).unwrap(),
            bincode::serialize(&secondary()).unwrap()
        );
        assert!(selected(&key(), &path, plans.clone()).is_err());
        assert!(selected(&7u64, &path, plans.clone()).is_err());
        #[derive(Serialize)]
        struct Missing {
            ignored: Never,
        }
        assert!(selected(&Missing { ignored: Never }, &path, plans.clone()).is_err());
        for name in FILENAMES {
            fs::remove_file(path.join(name)).unwrap();
        }
        struct Duplicate(Key);
        impl Serialize for Duplicate {
            fn serialize<S: ser::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
                use ser::SerializeStruct;
                let mut s = s.serialize_struct("Key", 2)?;
                s.serialize_field("vk_primary", &self.0.vk_primary)?;
                s.serialize_field("vk_primary", &self.0.vk_primary)?;
                s.end()
            }
        }
        assert!(selected(&Duplicate(key()), &path, plans).is_err());
        assert!(!path.join("collection.json").exists());
        fs::remove_file(path.join(FILENAMES[0])).unwrap();
        fs::remove_dir(path).unwrap();
    }
    #[test]
    fn dimension_identity_canonical_hash_and_hosted_path_boundaries_are_enforced() {
        let dimensions: Value = serde_json::from_str(include_str!(
            "../../fixtures/nht4-genesis-0-2020-k5.dimensions.json"
        ))
        .unwrap();
        let actual = plans(&dimensions).unwrap();
        assert_eq!(total_bytes(&actual).unwrap(), 17_301_520);
        let mut edited = dimensions;
        edited["primary"]["ck_v_generators"] = json!(2);
        assert!(plans(&edited).is_err());
        assert_eq!(
            canonical_sha256(&json!({"z":2,"a":{"x":[1,"00"]}})).unwrap(),
            "63fee996985eddf1154dd76942ebe09225110f233b9bf2417e0259080b161a53"
        );
        assert!(canonical_bytes(&json!({"x":true})).is_err());
        let root = directory();
        let results = root.join("results");
        fs::create_dir(&results).unwrap();
        assert_eq!(
            output_path(Path::new("results/new"), &root).unwrap(),
            fs::canonicalize(&results).unwrap().join("new")
        );
        for invalid in [
            "elsewhere/new",
            "results/../new",
            "results/missing/new",
            "./results/new",
        ] {
            assert!(output_path(Path::new(invalid), &root).is_err());
        }
        assert!(output_path(&results.join("absolute"), &root).is_err());
        fs::remove_dir(results).unwrap();
        fs::remove_dir(root).unwrap();
    }
}
