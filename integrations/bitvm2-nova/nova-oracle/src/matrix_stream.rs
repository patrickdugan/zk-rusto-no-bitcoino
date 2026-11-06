//! Optional bounded, borrowed serialization of the authenticated VK's six CSR matrices.
//!
//! The caller must authenticate the complete VK first. The independently pinned
//! length profile is checked before creating any output. No matrix is cloned or
//! serialized to a Vec; the original bincode serializer writes through a 64 KiB
//! buffer to a size/header-checking, segment-hashing file writer.
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
const PROFILE_SHA: &str = "7a69cdd0c39601c988c39719bbfc67386762d516eea8a3fcfc0e23c7938ac921";
const REVISION: &str = "de607d3db17d400dd6c2923d357f1d4a7bf233c7";
const CRATE_SHA: &str = "c9bb3809a6c70057ea722c1c4fe5097cf29a3479d0b4671f3cddb1d81043bb31";
const FILE_CAP: u64 = 64 << 20;
const TOTAL_CAP: u64 = 160 << 20;
const BUFFER_BYTES: usize = 64 << 10;
const JSON_CAP: usize = 32 << 10;
const ROLES: [&str; 2] = ["primary", "secondary"];
const ENGINES: [&str; 2] = ["pallas", "vesta"];
const FIELDS: [&str; 2] = ["pallas_scalar", "vesta_scalar"];
const MATRICES: [&str; 3] = ["A", "B", "C"];
const FILENAMES: [&str; 6] = [
    "primary-A.csr.bin",
    "primary-B.csr.bin",
    "primary-C.csr.bin",
    "secondary-A.csr.bin",
    "secondary-B.csr.bin",
    "secondary-C.csr.bin",
];

type Result<T> = std::result::Result<T, String>;

#[derive(Clone)]
struct Segment {
    name: &'static str,
    offset: u64,
    bytes: u64,
    header: [u8; 8],
}
#[derive(Clone)]
struct Plan {
    role: usize,
    matrix: usize,
    num_cons: u64,
    num_vars: u64,
    num_io: u64,
    data_len: u64,
    indptr_len: u64,
    cols: u64,
    bytes: u64,
    segments: [Segment; 4],
}
fn count(value: &Value, key: &str) -> Result<u64> {
    value[key]
        .as_u64()
        .ok_or_else(|| format!("missing unsigned matrix stream metadata {key}"))
}
fn segment(name: &'static str, offset: u64, count: u64, width: u64) -> Result<Segment> {
    let bytes = count
        .checked_mul(width)
        .and_then(|n| n.checked_add(8))
        .ok_or("matrix segment length overflow")?;
    Ok(Segment {
        name,
        offset,
        bytes,
        header: count.to_le_bytes(),
    })
}
impl Plan {
    fn new(role: usize, matrix: usize, curve: &Value, csr: &Value) -> Result<Self> {
        if role >= 2 || matrix >= 3 {
            return Err("invalid matrix stream role".into());
        }
        let num_cons = count(curve, "num_cons")?;
        let num_vars = count(curve, "num_vars")?;
        let num_io = count(curve, "num_io")?;
        let data_len = count(csr, "data_len")?;
        let indices_len = count(csr, "indices_len")?;
        let indptr_len = count(csr, "indptr_len")?;
        let rows = indptr_len.checked_sub(1).ok_or("empty matrix indptr")?;
        let cols = count(csr, "cols")?;
        if !num_cons.is_power_of_two()
            || !num_vars.is_power_of_two()
            || num_cons > 1 << 24
            || !(8..=1 << 24).contains(&num_vars)
            || num_io != 2
            || data_len != indices_len
            || rows != count(csr, "csr_rows")?
            || rows > num_cons
            || cols > num_vars.checked_mul(2).ok_or("column domain overflow")?
            || data_len > rows.checked_mul(cols).ok_or("matrix density overflow")?
        {
            return Err("inconsistent matrix stream lengths".into());
        }
        let data = segment("data", 0, data_len, 32)?;
        let indices = segment("indices", data.bytes, data_len, 8)?;
        let indptr_offset = indices
            .offset
            .checked_add(indices.bytes)
            .ok_or("matrix stream offset overflow")?;
        let indptr = segment("indptr", indptr_offset, indptr_len, 8)?;
        let cols_offset = indptr
            .offset
            .checked_add(indptr.bytes)
            .ok_or("matrix stream offset overflow")?;
        let bytes = cols_offset.checked_add(8).ok_or("matrix length overflow")?;
        if bytes > FILE_CAP {
            return Err("matrix file exceeds 64 MiB cap".into());
        }
        Ok(Self {
            role,
            matrix,
            num_cons,
            num_vars,
            num_io,
            data_len,
            indptr_len,
            cols,
            bytes,
            segments: [
                data,
                indices,
                indptr,
                Segment {
                    name: "cols",
                    offset: cols_offset,
                    bytes: 8,
                    header: cols.to_le_bytes(),
                },
            ],
        })
    }
    fn filename(&self) -> &'static str {
        FILENAMES[3 * self.role + self.matrix]
    }
}
fn total_bytes(plans: &[Plan]) -> Result<u64> {
    let total = plans.iter().try_fold(0u64, |total, plan| {
        total.checked_add(plan.bytes).ok_or("matrix total overflow")
    })?;
    if total > TOTAL_CAP {
        return Err("matrix collection exceeds 160 MiB cap".into());
    }
    Ok(total)
}
fn plans(profile: &Value) -> Result<Vec<Plan>> {
    if crate::matrix_profile::canonical_sha256(profile)? != PROFILE_SHA
        || profile["schema"] != "bitvm2-nova-matrix-profile/v1"
        || profile["nova_version"] != "0.76.0"
        || profile["nova_crate_sha256"] != CRATE_SHA
        || profile["header_revision"] != REVISION
        || profile["network"] != "testnet4"
        || profile["k"] != 5
        || profile["verifier_key_sha256"] != VK_SHA
        || profile["verifier_dimensions_sha256"] != DIM_SHA
    {
        return Err("matrix stream requires independently pinned actual VK profile".into());
    }
    let mut plans = Vec::with_capacity(6);
    for role in 0..2 {
        let curve = &profile[ROLES[role]];
        if curve["engine"] != ENGINES[role] || curve["field_role"] != FIELDS[role] {
            return Err("matrix stream field role mismatch".into());
        }
        for matrix in 0..3 {
            plans.push(Plan::new(
                role,
                matrix,
                curve,
                &curve["matrices"][MATRICES[matrix]],
            )?);
        }
    }
    total_bytes(&plans)?;
    Ok(plans)
}

/// Hash only bytes the underlying writer reports as successfully accepted.
/// The outer BufWriter coalesces scalar serde's small writes into bounded chunks.
struct CheckedWriter<W> {
    inner: W,
    plan: Plan,
    position: u64,
    whole: Sha256,
    parts: [Sha256; 4],
}
impl<W: Write> CheckedWriter<W> {
    fn new(inner: W, plan: Plan) -> Self {
        Self {
            inner,
            plan,
            position: 0,
            whole: Sha256::new(),
            parts: std::array::from_fn(|_| Sha256::new()),
        }
    }
    fn finish(mut self) -> Result<Value> {
        if self.position != self.plan.bytes {
            return Err("matrix serializer produced truncated payload".into());
        }
        self.inner.flush().map_err(|e| e.to_string())?;
        let segments: Vec<_> = self
            .plan
            .segments
            .iter()
            .zip(self.parts)
            .map(|(segment, hash)| {
                json!({"name":segment.name,"offset":segment.offset,"bytes":segment.bytes,
                    "sha256":hex::encode(hash.finalize())})
            })
            .collect();
        Ok(
            json!({"role":ROLES[self.plan.role],"engine":ENGINES[self.plan.role],
            "field_role":FIELDS[self.plan.role],"matrix":MATRICES[self.plan.matrix],
            "filename":self.plan.filename(),"num_cons":self.plan.num_cons,
            "num_vars":self.plan.num_vars,"num_io":self.plan.num_io,
            "data_len":self.plan.data_len,"indices_len":self.plan.data_len,
            "indptr_len":self.plan.indptr_len,"csr_rows":self.plan.indptr_len-1,"cols":self.plan.cols,
            "bytes":self.position,"sha256":hex::encode(self.whole.finalize()),"segments":segments}),
        )
    }
}
fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
impl<W: Write> Write for CheckedWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let length = u64::try_from(bytes.len()).map_err(|_| invalid("matrix write length"))?;
        let end = self
            .position
            .checked_add(length)
            .ok_or_else(|| invalid("matrix write overflow"))?;
        if end > self.plan.bytes || end > FILE_CAP {
            return Err(invalid("matrix serializer exceeded exact file size/cap"));
        }
        // Every Vec prefix and the final cols word are checked even if the
        // serializer/write boundary splits a header into individual bytes.
        for segment in &self.plan.segments {
            let start = self.position.max(segment.offset);
            let stop = end.min(segment.offset + 8);
            if start < stop {
                let source = (start - self.position) as usize..(stop - self.position) as usize;
                let expected = (start - segment.offset) as usize..(stop - segment.offset) as usize;
                if bytes[source] != segment.header[expected] {
                    return Err(invalid("matrix serializer header/layout mismatch"));
                }
            }
        }
        let written = self.inner.write(bytes)?;
        if written > bytes.len() {
            return Err(invalid("underlying writer returned impossible count"));
        }
        let end = self.position + written as u64;
        self.whole.update(&bytes[..written]);
        for (segment, hash) in self.plan.segments.iter().zip(&mut self.parts) {
            let start = self.position.max(segment.offset);
            let stop = end.min(segment.offset + segment.bytes);
            if start < stop {
                hash.update(
                    &bytes[(start - self.position) as usize..(stop - self.position) as usize],
                );
            }
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
    selected_matrix_fields: usize,
    skipped_fields: usize,
    per_file_cap_bytes: u64,
    total_cap_bytes: u64,
    writer_buffer_bytes: usize,
    full_key_materialized: bool,
    matrix_payloads_materialized: bool,
}
struct Context<'a> {
    directory: &'a Path,
    plans: Vec<Plan>,
    seen: [bool; 10],
    files: [Option<Value>; 6],
    stats: ExportStats,
}
impl Context<'_> {
    fn write<T: ?Sized + Serialize>(&mut self, index: usize, value: &T) -> Result<()> {
        if self.files[index].is_some() {
            return Err("duplicate selected matrix".into());
        }
        let plan = self.plans[index].clone();
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(self.directory.join(plan.filename()))
            .map_err(|e| format!("create matrix {}: {e}", plan.filename()))?;
        let writer = CheckedWriter::new(file, plan);
        let mut buffer = BufWriter::with_capacity(BUFFER_BYTES, writer);
        // This is the original mature serde/bincode implementation, borrowed
        // directly from the authenticated private VK.S.A/B/C field.
        bincode::serialize_into(&mut buffer, value).map_err(|e| e.to_string())?;
        buffer.flush().map_err(|e| e.to_string())?;
        let writer = buffer.into_inner().map_err(|e| e.to_string())?;
        let result = writer.finish()?;
        self.stats.total_bytes = self
            .stats
            .total_bytes
            .checked_add(self.plans[index].bytes)
            .ok_or("matrix written total overflow")?;
        if self.stats.total_bytes > TOTAL_CAP {
            return Err("matrix written total exceeds cap".into());
        }
        self.stats.files_written += 1;
        self.stats.selected_matrix_fields += 1;
        self.files[index] = Some(result);
        Ok(())
    }
}
#[derive(Clone, Copy)]
enum Mode {
    Root,
    Snark(usize),
    Shape(usize),
    Matrix(usize),
}
impl Mode {
    fn child(self, key: &str) -> Option<(Self, usize)> {
        match (self, key) {
            (Self::Root, "vk_primary") => Some((Self::Snark(0), 0)),
            (Self::Root, "vk_secondary") => Some((Self::Snark(1), 1)),
            (Self::Snark(role), "S") => Some((Self::Shape(role), 2 + role)),
            (Self::Shape(role), "A") => Some((Self::Matrix(3 * role), 4 + 3 * role)),
            (Self::Shape(role), "B") => Some((Self::Matrix(3 * role + 1), 5 + 3 * role)),
            (Self::Shape(role), "C") => Some((Self::Matrix(3 * role + 2), 6 + 3 * role)),
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
    Error("unexpected selected matrix path/type".into())
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
        if matches!(self.mode, Mode::Matrix(_)) {
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
        key: &'static str,
        value: &T,
    ) -> std::result::Result<(), Error> {
        let Some((mode, slot)) = self.mode.child(key) else {
            self.context.stats.skipped_fields += 1;
            return Ok(());
        };
        if std::mem::replace(&mut self.context.seen[slot], true) {
            return Err(Error("duplicate selected matrix path".into()));
        }
        if let Mode::Matrix(index) = mode {
            self.context.write(index, value).map_err(Error)
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
    plans: Vec<Plan>,
) -> Result<(Vec<Value>, ExportStats)> {
    let expected_total = total_bytes(&plans)?;
    if plans.len() != 6 {
        return Err("exactly six matrix plans required".into());
    }
    let mut context = Context {
        directory,
        plans,
        seen: [false; 10],
        files: std::array::from_fn(|_| None),
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
        || context.stats.files_written != 6
        || context.stats.total_bytes != expected_total
    {
        return Err("incomplete selected matrix collection".into());
    }
    let files = context
        .files
        .into_iter()
        .map(|value| value.ok_or_else(|| "missing selected matrix result".to_owned()))
        .collect::<Result<_>>()?;
    Ok((files, context.stats))
}

pub fn canonical_bytes(value: &Value) -> Result<Vec<u8>> {
    fn sorted(value: &Value, depth: usize) -> Result<Value> {
        if depth > 16 {
            return Err("matrix collection JSON depth".into());
        }
        match value {
            Value::Object(object) => {
                let mut fields: Vec<_> = object.iter().collect();
                fields.sort_by(|a, b| a.0.cmp(b.0));
                let mut result = Map::new();
                for (key, value) in fields {
                    if !key.is_ascii() {
                        return Err("non-ASCII collection key".into());
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
            _ => Err("unsupported matrix collection JSON value".into()),
        }
    }
    let bytes = serde_json::to_vec(&sorted(value, 0)?).map_err(|e| e.to_string())?;
    if bytes.len() > JSON_CAP {
        return Err("matrix collection JSON byte cap".into());
    }
    Ok(bytes)
}
pub fn canonical_sha256(value: &Value) -> Result<String> {
    Ok(hex::encode(Sha256::digest(canonical_bytes(value)?)))
}

/// Only new children beneath this hosted working directory's existing results
/// directory are allowed. Existing directories are rejected. Any error returns
/// no successful report; an incomplete directory must not be reused.
fn output_path(directory: &Path, current: &Path) -> Result<PathBuf> {
    let components: Vec<_> = directory.components().collect();
    if components.len() < 2
        || components.first() != Some(&Component::Normal(std::ffi::OsStr::new("results")))
        || components
            .iter()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err("matrix output must be a relative new child under results".into());
    }
    let current = fs::canonicalize(current).map_err(|e| e.to_string())?;
    let results = fs::canonicalize(current.join("results")).map_err(|e| e.to_string())?;
    let parent = fs::canonicalize(current.join(directory.parent().ok_or("matrix output parent")?))
        .map_err(|e| e.to_string())?;
    if !results.starts_with(&current) || !parent.starts_with(&results) {
        return Err("matrix output parent escapes owned hosted results".into());
    }
    Ok(parent.join(directory.file_name().ok_or("matrix output name")?))
}
/// Explicit optional export only. Full VK and dimensions authentication must
/// have succeeded at the call site; a profile label never authenticates a key.
pub fn export_authenticated_vk<T: Serialize>(
    key: &T,
    profile: &Value,
    directory: &Path,
) -> Result<(Value, ExportStats)> {
    let plans = plans(profile)?;
    let directory = output_path(
        directory,
        &std::env::current_dir().map_err(|e| e.to_string())?,
    )?;
    fs::create_dir(&directory).map_err(|e| format!("create new matrix output directory: {e}"))?;
    let (files, stats) = selected(key, &directory, plans)?;
    let value = json!({"schema":"bitvm2-nova-matrix-collection/v1","nova_version":"0.76.0",
        "nova_crate_sha256":CRATE_SHA,"header_revision":REVISION,"network":"testnet4","k":5,
        "verifier_key_sha256":VK_SHA,"verifier_dimensions_sha256":DIM_SHA,"matrix_profile_sha256":PROFILE_SHA,
        "encoding":"bincode-1.3.3-legacy-fixed-little-endian","total_bytes":stats.total_bytes,"files":files});
    let bytes = canonical_bytes(&value)?;
    let mut manifest = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(directory.join("collection.json"))
        .map_err(|e| e.to_string())?;
    manifest.write_all(&bytes).map_err(|e| e.to_string())?;
    manifest.flush().map_err(|e| e.to_string())?;
    Ok((value, stats))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff::PrimeField;
    use nova_snark::{
        provider::{PallasEngine, VestaEngine},
        r1cs::SparseMatrix,
        traits::Engine,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};
    type F = <PallasEngine as Engine>::Scalar;

    fn toy_plan() -> Plan {
        Plan::new(
            0,
            0,
            &json!({"num_cons":8,"num_vars":8,"num_io":2}),
            &json!({"data_len":2,"indices_len":2,"indptr_len":3,"csr_rows":2,"cols":11}),
        )
        .unwrap()
    }
    fn toy() -> SparseMatrix<F> {
        SparseMatrix {
            data: vec![F::from(3), -F::from(1)],
            indices: vec![0, 10],
            indptr: vec![0, 1, 2],
            cols: 11,
        }
    }
    fn raw() -> Vec<u8> {
        bincode::serialize(&toy()).unwrap()
    }
    fn sha(bytes: &[u8]) -> String {
        hex::encode(Sha256::digest(bytes))
    }

    #[test]
    fn public_sparse_matrix_layout_and_four_segment_hashes_match_original_serializer() {
        let matrix = toy();
        let bytes = raw();
        let mut independently_encoded = 2u64.to_le_bytes().to_vec();
        for scalar in &matrix.data {
            independently_encoded.extend_from_slice(scalar.to_repr().as_ref());
        }
        independently_encoded.extend_from_slice(&2u64.to_le_bytes());
        for index in [0u64, 10] {
            independently_encoded.extend_from_slice(&index.to_le_bytes());
        }
        independently_encoded.extend_from_slice(&3u64.to_le_bytes());
        for pointer in [0u64, 1, 2] {
            independently_encoded.extend_from_slice(&pointer.to_le_bytes());
        }
        independently_encoded.extend_from_slice(&11u64.to_le_bytes());
        assert_eq!(bytes, independently_encoded);
        assert_eq!(bytes.len(), 32 + 40 * 2 + 8 * 3);
        type G = <VestaEngine as Engine>::Scalar;
        let secondary = SparseMatrix {
            data: vec![G::from(3), -G::from(1)],
            indices: vec![0, 10],
            indptr: vec![0, 1, 2],
            cols: 11,
        };
        let secondary_bytes = bincode::serialize(&secondary).unwrap();
        let mut expected_secondary = independently_encoded.clone();
        for (index, scalar) in secondary.data.iter().enumerate() {
            expected_secondary[8 + index * 32..8 + (index + 1) * 32]
                .copy_from_slice(scalar.to_repr().as_ref());
        }
        assert_eq!(secondary_bytes, expected_secondary);
        let mut writer = CheckedWriter::new(Vec::new(), toy_plan());
        for byte in &bytes {
            writer.write_all(&[*byte]).unwrap();
        }
        let result = writer.finish().unwrap();
        assert_eq!(result["sha256"], sha(&bytes));
        for segment in result["segments"].as_array().unwrap() {
            let start = segment["offset"].as_u64().unwrap() as usize;
            let end = start + segment["bytes"].as_u64().unwrap() as usize;
            assert_eq!(segment["sha256"], sha(&bytes[start..end]));
        }
    }

    #[test]
    fn malformed_headers_short_payload_extra_bytes_and_caps_fail_closed() {
        let bytes = raw();
        for segment in toy_plan().segments {
            let mut malformed = bytes.clone();
            malformed[segment.offset as usize] ^= 1;
            let mut writer = CheckedWriter::new(Vec::new(), toy_plan());
            assert!(writer.write_all(&malformed).is_err());
        }
        let mut writer = CheckedWriter::new(Vec::new(), toy_plan());
        writer.write_all(&bytes[..bytes.len() - 1]).unwrap();
        assert!(writer.finish().is_err());
        let mut writer = CheckedWriter::new(Vec::new(), toy_plan());
        writer.write_all(&bytes).unwrap();
        assert!(writer.write_all(&[0]).is_err());
        assert!(Plan::new(0,0,&json!({"num_cons":1<<24,"num_vars":1<<24,"num_io":2}),
            &json!({"data_len":2_000_000,"indices_len":2_000_000,"indptr_len":2,"csr_rows":1,"cols":1<<25})).is_err());
        let mut excessive = toy_plan();
        excessive.bytes = FILE_CAP;
        assert!(total_bytes(&[excessive.clone(), excessive.clone(), excessive]).is_err());
        assert!(segment("data", 0, u64::MAX, 32).is_err());
    }

    struct ShortWriter {
        bytes: Vec<u8>,
        fail_after: Option<usize>,
        fail_flush: bool,
    }
    impl Write for ShortWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.fail_after == Some(self.bytes.len()) {
                return Err(io::Error::other("injected write error"));
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
                Err(io::Error::other("injected flush error"))
            } else {
                Ok(())
            }
        }
    }
    #[test]
    fn partial_write_hashes_count_only_accepted_bytes_and_write_flush_errors_propagate() {
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
            Err(ser::Error::custom("unselected field visited"))
        }
    }
    #[derive(Serialize)]
    #[allow(non_snake_case)]
    struct Shape {
        A: SparseMatrix<F>,
        B: SparseMatrix<F>,
        C: SparseMatrix<F>,
        ignored: Never,
    }
    #[derive(Serialize)]
    #[allow(non_snake_case)]
    struct Snark {
        S: Shape,
        ignored: Never,
    }
    #[derive(Serialize)]
    struct Key {
        vk_primary: Snark,
        vk_secondary: Snark,
        ignored: Never,
    }
    fn key() -> Key {
        let snark = || Snark {
            S: Shape {
                A: toy(),
                B: toy(),
                C: toy(),
                ignored: Never,
            },
            ignored: Never,
        };
        Key {
            vk_primary: snark(),
            vk_secondary: snark(),
            ignored: Never,
        }
    }
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    fn directory() -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "nova-matrix-stream-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        path
    }
    #[test]
    fn selected_paths_skip_unrelated_fields_and_fixed_names_never_overwrite() {
        let plans: Vec<_> = (0..6)
            .map(|i| {
                let mut p = toy_plan();
                p.role = i / 3;
                p.matrix = i % 3;
                p
            })
            .collect();
        let path = directory();
        let (files, stats) = selected(&key(), &path, plans.clone()).unwrap();
        assert_eq!(files.len(), 6);
        assert_eq!(stats.selected_matrix_fields, 6);
        assert_eq!(stats.total_bytes, 6 * raw().len() as u64);
        for name in FILENAMES {
            assert_eq!(fs::read(path.join(name)).unwrap(), raw());
        }
        assert!(selected(&key(), &path, plans.clone()).is_err());
        assert!(selected(&7u64, &path, plans.clone()).is_err());
        #[derive(Serialize)]
        struct Missing {
            ignored: Never,
        }
        assert!(selected(&Missing { ignored: Never }, &path, plans).is_err());
        // Only test-created files in this freshly created, uniquely named dir.
        for name in FILENAMES {
            fs::remove_file(path.join(name)).unwrap();
        }
        fs::remove_dir(path).unwrap();
    }

    #[test]
    fn independent_profile_pin_and_canonical_collection_hash_are_required() {
        assert!(plans(&json!({})).is_err());
        let profile: Value = serde_json::from_str(include_str!(
            "../../fixtures/nht4-genesis-0-2020-k5.matrix-profile.json"
        ))
        .unwrap();
        let actual_plans = plans(&profile).unwrap();
        assert_eq!(total_bytes(&actual_plans).unwrap(), 119_674_848);
        assert_eq!(
            actual_plans.iter().map(|plan| plan.bytes).max(),
            Some(50_321_224)
        );
        assert_eq!(
            canonical_sha256(&json!({"z":2,"a":{"x":[1,"00"]}})).unwrap(),
            "63fee996985eddf1154dd76942ebe09225110f233b9bf2417e0259080b161a53"
        );
        assert!(canonical_bytes(&json!({"x":true})).is_err());
        assert!(canonical_bytes(&json!({"x":"\u{e9}"})).is_err());
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
