//! Closed, canonical transport for one curve role of the M23 commitment source.
//! Reference pins come from the completed strict reference admission module.
use crate::source;
use bitcoin::hashes::{sha256, Hash};
use bitvm2_nova_script_oracle::{registry::GraphSpec, wots::Result};
use serde::{de, Deserialize, Serialize};
use serde_json::{Map, Value};
use std::{collections::HashSet, fmt, fs, io::Read, path::Path};

pub const SCHEMA: &str = "bitvm2-nova-proof-point-origins-run/v1";
pub const OPERATION: &str = "benchmark/proof-point-origins/v1";
const FILE_CAP: usize = 32 << 20;
const GROUP_CAP: usize = 1 << 20;
const MANIFEST_CAP: usize = 1 << 20;
// NEW bounded transport. A full seven-decoder case has 11,882 word entries
// (<= 8 tokens), 9,853 leaves (<= 15 fixed + 3 arguments + 27 wires + 1),
// 9,853 checks (<= 7), 11,882 values and <= 512 bodies (<= 4):
// 95,056 + 453,238 + 68,971 + 11,882 + 2,048 + 64 = 631,259 < 700,000.
// The 12,664-leaf tape case is bounded by 430,576 tokens.
pub const MAX_JSON_NODES: usize = 700_000;
const MAX_JSON_DEPTH: usize = 32;
const MAX_JSON_STRING: usize = 200_000;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReferenceFile {
    pub kind: String,
    pub filename: String,
    pub file_sha256: String,
    pub file_bytes: usize,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Run {
    pub schema: String,
    pub context: String,
    pub operation_id: String,
    pub engine: String,
    pub references: [ReferenceFile; 3],
    pub cases: Vec<ProfileDescriptor>,
}
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProfileDescriptor {
    pub name: String,
    pub profile: String,
    pub group_filename: String,
    pub group_hash: String,
    pub group_bytes: usize,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Group {
    pub name: String,
    pub profile: String,
    pub engine: String,
    pub source_sha256: String,
    pub components: Vec<ComponentDescriptor>,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentDescriptor {
    pub index: usize,
    pub name: String,
    pub field_role: String,
    pub operation_id: String,
    pub program_identity_kind: String,
    pub words: usize,
    pub arithmetic_constraints: usize,
    pub canonical_fields: usize,
    pub leaves: usize,
    pub program_sha256: String,
    pub catalogue_id: String,
    pub global_ids_sha256: String,
    pub decoders: Vec<usize>,
    pub filename: String,
    pub file_sha256: String,
    pub file_bytes: usize,
    pub execution_mode: String,
    pub selected_ordinals: Option<Vec<usize>>,
    pub expected_false: Vec<usize>,
    pub expected_abort_ordinals: Vec<usize>,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Check {
    pub ordinal: usize,
    pub expected_correct: Option<bool>,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Case {
    pub name: String,
    pub spec: GraphSpec,
    pub expected_spec_id: String,
    pub words: Vec<u32>,
    pub checks: Vec<Check>,
    pub measure_all: bool,
}

fn require(yes: bool, message: &str) -> Result<()> {
    if yes {
        Ok(())
    } else {
        Err(message.into())
    }
}
pub fn hex32(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub fn context() -> String {
    sha256::Hash::hash(b"BITVM2-NOVA/PROOF-POINT-ORIGINS-CONFORMANCE/v1").to_string()
}
fn read(path: &Path, cap: usize) -> Result<Vec<u8>> {
    let info = fs::symlink_metadata(path)?;
    require(
        info.is_file() && !info.file_type().is_symlink(),
        "regular immutable input file required",
    )?;
    require(info.len() <= cap as u64, "input file byte cap")?;
    let mut raw = Vec::new();
    fs::File::open(path)?
        .take((cap + 1) as u64)
        .read_to_end(&mut raw)?;
    require(raw.len() <= cap, "input grew beyond byte cap")?;
    Ok(raw)
}
pub fn lexical_budget(raw: &[u8]) -> Result<()> {
    let (mut quoted, mut escaped, mut depth, mut nodes, mut string_bytes) =
        (false, false, 0usize, 0usize, 0usize);
    for &byte in raw {
        require(byte.is_ascii(), "canonical ASCII JSON transport required")?;
        if quoted {
            string_bytes += 1;
            require(string_bytes <= MAX_JSON_STRING, "JSON string cap")?;
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                quoted = false;
            }
        } else {
            match byte {
                b'"' => {
                    quoted = true;
                    string_bytes = 0;
                    nodes += 1;
                }
                b'[' | b'{' => {
                    depth += 1;
                    nodes += 1;
                }
                b']' | b'}' => depth = depth.saturating_sub(1),
                b',' | b':' => nodes += 1,
                _ => {}
            }
            require(
                depth <= MAX_JSON_DEPTH && nodes <= MAX_JSON_NODES,
                "JSON node/depth cap",
            )?;
        }
    }
    Ok(())
}
struct Unique(Value);
impl<'de> Deserialize<'de> for Unique {
    fn deserialize<D: de::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        struct Visitor;
        impl<'de> de::Visitor<'de> for Visitor {
            type Value = Unique;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("bounded unique JSON")
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> std::result::Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> std::result::Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> std::result::Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_f64<E: de::Error>(self, _: f64) -> std::result::Result<Unique, E> {
                Err(E::custom("integer JSON required"))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_unit<E: de::Error>(self) -> std::result::Result<Unique, E> {
                Ok(Unique(Value::Null))
            }
            fn visit_none<E: de::Error>(self) -> std::result::Result<Unique, E> {
                Ok(Unique(Value::Null))
            }
            fn visit_seq<A: de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> std::result::Result<Unique, A::Error> {
                let mut out = Vec::new();
                while let Some(v) = seq.next_element::<Unique>()? {
                    out.push(v.0);
                }
                Ok(Unique(Value::Array(out)))
            }
            fn visit_map<A: de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<Unique, A::Error> {
                let mut out = Map::new();
                while let Some((key, v)) = map.next_entry::<String, Unique>()? {
                    if out.insert(key, v.0).is_some() {
                        return Err(de::Error::custom("duplicate JSON object field"));
                    }
                }
                Ok(Unique(Value::Object(out)))
            }
        }
        deserializer.deserialize_any(Visitor)
    }
}
fn parse<T: serde::de::DeserializeOwned + Serialize>(raw: &[u8]) -> Result<T> {
    lexical_budget(raw)?;
    let unique: Unique = serde_json::from_slice(raw)?;
    require(
        serde_json::to_vec(&unique.0)? == raw,
        "canonical compact JSON bytes required",
    )?;
    let typed: T = serde_json::from_value(unique.0.clone())?;
    require(
        serde_json::to_value(&typed)? == unique.0,
        "unknown or noncanonical nested field",
    )?;
    Ok(typed)
}
fn sorted(values: &[usize], leaves: usize) -> bool {
    values.iter().all(|i| *i < leaves) && values.windows(2).all(|p| p[0] < p[1])
}
impl Run {
    pub fn components(&self) -> Result<usize> {
        Ok(source::plan(&self.engine)?.len() + 1)
    }
    pub fn validate(&self) -> Result<()> {
        require(
            self.schema == SCHEMA
                && self.context == context()
                && self.operation_id == OPERATION
                && source::commitments(&self.engine).is_ok()
                && self.cases.len() == source::PROFILES.len(),
            "closed proof-point run identity",
        )?;
        let refs = [
            (
                "bundle",
                "reference.nht4",
                crate::reference_admission::BUNDLE_SHA256,
            ),
            (
                "expected",
                "reference.expected.json",
                crate::reference_admission::POLICY_SHA256,
            ),
            (
                "dimensions",
                "reference.dimensions.json",
                crate::reference_admission::DIMENSIONS_SHA256,
            ),
        ];
        for (i, (kind, filename, hash)) in refs.iter().enumerate() {
            let r = &self.references[i];
            require(
                r.kind == *kind
                    && r.filename == *filename
                    && r.file_sha256 == *hash
                    && (1..=MANIFEST_CAP).contains(&r.file_bytes)
                    && (i != 0 || r.file_bytes == source::BUNDLE),
                "independently compiled retained-reference pins",
            )?;
        }
        for (i, d) in self.cases.iter().enumerate() {
            require(
                d.name == format!("d/{i:02}")
                    && d.profile == source::PROFILES[i]
                    && d.group_filename == format!("group-{i:02}.json")
                    && hex32(&d.group_hash)
                    && (1..=GROUP_CAP).contains(&d.group_bytes),
                "closed profile descriptors",
            )?;
        }
        Ok(())
    }
    pub fn load(manifest: &Path, directory: &Path, expected: &str) -> Result<Self> {
        require(hex32(expected), "external canonical manifest pin")?;
        let info = fs::symlink_metadata(directory)?;
        require(
            info.is_dir()
                && !info.file_type().is_symlink()
                && manifest.file_name().and_then(|n| n.to_str()) == Some("manifest.json")
                && manifest.canonicalize()? == directory.join("manifest.json").canonicalize()?,
            "fixed input directory and manifest",
        )?;
        let raw = read(manifest, MANIFEST_CAP)?;
        require(
            sha256::Hash::hash(&raw).to_string() == expected,
            "out-of-band manifest pin",
        )?;
        let run: Self = parse(&raw)?;
        run.validate()?;
        let components = run.components()?;
        let mut expected_files: HashSet<String> = std::iter::once("manifest.json".to_string())
            .chain(run.references.iter().map(|r| r.filename.clone()))
            .chain(run.cases.iter().map(|d| d.group_filename.clone()))
            .collect();
        for i in 0..run.cases.len() {
            for component in 0..components {
                expected_files.insert(format!("case-{i:02}-{component:02}.json"));
            }
        }
        let mut actual = HashSet::new();
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let info = fs::symlink_metadata(entry.path())?;
            require(
                info.is_file() && !info.file_type().is_symlink(),
                "regular pinned input files only",
            )?;
            actual.insert(
                entry
                    .file_name()
                    .to_str()
                    .ok_or("ASCII input filename")?
                    .to_string(),
            );
        }
        require(
            actual == expected_files && actual.len() == 4 + run.cases.len() * (1 + components),
            "exact closed input file inventory",
        )?;
        run.verify_references(directory)?;
        Ok(run)
    }
    pub fn verify_references(&self, directory: &Path) -> Result<()> {
        self.validate()?;
        for r in &self.references {
            let raw = read(&directory.join(&r.filename), MANIFEST_CAP)?;
            require(
                raw.len() == r.file_bytes && sha256::Hash::hash(&raw).to_string() == r.file_sha256,
                "exact retained-reference input bytes",
            )?;
        }
        Ok(())
    }
    pub fn load_group(&self, d: &ProfileDescriptor, directory: &Path) -> Result<Group> {
        self.validate()?;
        require(
            self.cases.iter().any(|known| known == d),
            "profile not in pinned run",
        )?;
        let raw = read(&directory.join(&d.group_filename), GROUP_CAP)?;
        require(
            raw.len() == d.group_bytes && sha256::Hash::hash(&raw).to_string() == d.group_hash,
            "exact group pin bytes",
        )?;
        let group: Group = parse(&raw)?;
        let components = self.components()?;
        let plan = source::plan(&self.engine)?;
        require(
            group.name == d.name
                && group.profile == d.profile
                && group.engine == self.engine
                && hex32(&group.source_sha256)
                && group.components.len() == components,
            "profile group identity",
        )?;
        let profile_index = self
            .cases
            .iter()
            .position(|known| known == d)
            .ok_or("pinned profile index")?;
        let full = profile_index == 0;
        let mut total_selected = 0usize;
        for (index, c) in group.components.iter().enumerate() {
            let (words, arithmetic, fields, leaves) = source::census(&self.engine, index)?;
            let decoders = if index == 0 {
                Vec::new()
            } else {
                plan[index - 1].clone()
            };
            require(
                c.index == index
                    && c.name == source::component_name(&self.engine, index)?
                    && c.field_role == source::component_role(&self.engine, index)?
                    && c.operation_id
                        == source::operation(&self.operation_id, &self.engine, index)?
                    && c.program_identity_kind == source::identity_kind(index)
                    && c.words == words
                    && c.leaves == leaves
                    && c.arithmetic_constraints == arithmetic
                    && c.canonical_fields == fields
                    && c.decoders == decoders
                    && c.filename == format!("case-{profile_index:02}-{index:02}.json")
                    && (1..=FILE_CAP).contains(&c.file_bytes),
                "closed component descriptor shape",
            )?;
            require(
                [
                    &c.program_sha256,
                    &c.catalogue_id,
                    &c.global_ids_sha256,
                    &c.file_sha256,
                ]
                .iter()
                .all(|h| hex32(h)),
                "canonical component hash pins",
            )?;
            require(
                sorted(&c.expected_false, c.leaves)
                    && sorted(&c.expected_abort_ordinals, c.leaves)
                    && c.expected_false
                        .iter()
                        .all(|i| !c.expected_abort_ordinals.contains(i)),
                "disjoint false and abort census",
            )?;
            if full {
                require(
                    c.execution_mode == "all"
                        && c.selected_ordinals.is_none()
                        && c.expected_false.is_empty()
                        && c.expected_abort_ordinals.is_empty(),
                    "honest full component execution",
                )?;
            } else {
                let selected = c
                    .selected_ordinals
                    .as_ref()
                    .ok_or("target selection required")?;
                require(
                    c.execution_mode == "selected"
                        && !selected.is_empty()
                        && sorted(selected, c.leaves)
                        && c.expected_false
                            .iter()
                            .chain(&c.expected_abort_ordinals)
                            .all(|i| selected.binary_search(i).is_ok()),
                    "target selection preserves every false and abort",
                )?;
                total_selected += selected.len();
            }
        }
        require(
            full || (1..=source::TARGET_CAP).contains(&total_selected),
            "target cap applies to the union of all components",
        )?;
        Ok(group)
    }
    pub fn load_case(&self, group: &Group, index: usize, directory: &Path) -> Result<Case> {
        let d = group.components.get(index).ok_or("component index")?;
        let raw = read(&directory.join(&d.filename), FILE_CAP)?;
        require(
            raw.len() == d.file_bytes && sha256::Hash::hash(&raw).to_string() == d.file_sha256,
            "exact consumed component bytes",
        )?;
        let c: Case = parse(&raw)?;
        require(
            c.spec.bodies.len() <= if index == 0 { 16 } else { 512 }
                && c.spec.leaves.iter().all(|leaf| {
                    leaf.wires.len() <= if index == 0 { 1 } else { 27 }
                        && leaf.argument.len() <= if index == 0 { 1 } else { 8 }
                }),
            "typed new-parser work premises before source/key admission",
        )?;
        require(
            c.name == format!("{}/{}", group.name, d.name)
                && c.expected_spec_id == d.catalogue_id
                && c.measure_all == (d.execution_mode == "all")
                && c.words.len() == d.words
                && c.spec.words.len() == d.words
                && c.spec.leaves.len() == d.leaves
                && c.spec.program_sha256 == d.program_sha256
                && c.spec.context == self.context
                && c.spec.field_role == d.field_role
                && c.spec.operation_id == d.operation_id
                && hex::encode(c.spec.identity()?) == d.catalogue_id,
            "actual consumed component identity",
        )?;
        let selected: Vec<usize> = d
            .selected_ordinals
            .clone()
            .unwrap_or_else(|| (0..d.leaves).collect());
        require(
            c.checks.len() == selected.len(),
            "exact selected check count",
        )?;
        for (check, ordinal) in c.checks.iter().zip(selected) {
            let expected = if d.expected_abort_ordinals.binary_search(&ordinal).is_ok() {
                None
            } else {
                Some(d.expected_false.binary_search(&ordinal).is_err())
            };
            require(
                check.ordinal == ordinal && check.expected_correct == expected,
                "typed ordinary false versus abort observation",
            )?;
        }
        Ok(c)
    }
    pub fn load_cases(&self, group: &Group, directory: &Path) -> Result<Vec<Case>> {
        (0..group.components.len())
            .map(|index| self.load_case(group, index, directory))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[derive(Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    struct Tiny {
        value: u32,
    }
    #[test]
    fn raw_json_is_unique_compact_and_integer() {
        assert!(parse::<Tiny>(br#"{"value":1}"#).is_ok());
        for raw in [
            br#"{"value":1,"value":1}"#.as_slice(),
            br#"{"value":1.0}"#,
            br#"{ "value":1}"#,
            br#"{"value":1,"extra":0}"#,
        ] {
            assert!(parse::<Tiny>(raw).is_err());
        }
    }
    #[test]
    fn null_abort_and_ordinary_false_remain_distinct() {
        assert_eq!(
            parse::<Check>(br#"{"expected_correct":null,"ordinal":0}"#)
                .unwrap()
                .expected_correct,
            None
        );
        assert_eq!(
            parse::<Check>(br#"{"expected_correct":false,"ordinal":0}"#)
                .unwrap()
                .expected_correct,
            Some(false)
        );
    }
    #[test]
    fn parser_work_bound_is_derived_and_rejects_one_token_over() {
        let full = 8 * 11882 + 46 * 9853 + 7 * 9853 + 11882 + 4 * 512 + 64;
        assert_eq!(full, 631259);
        assert!(full < MAX_JSON_NODES);
        let tape = 8 * 12664 + 18 * 12664 + 7 * 12664 + 12664;
        assert_eq!(tape, 430576);
        assert!(tape < MAX_JSON_NODES);
        let mut raw = vec![b'['];
        for _ in 1..MAX_JSON_NODES {
            raw.extend_from_slice(b"0,");
        }
        raw.extend_from_slice(b"0]");
        lexical_budget(&raw).unwrap();
        let end = raw.len() - 1;
        raw.splice(end..end, [b',', b'0']);
        assert!(lexical_budget(&raw).is_err());
    }
}
