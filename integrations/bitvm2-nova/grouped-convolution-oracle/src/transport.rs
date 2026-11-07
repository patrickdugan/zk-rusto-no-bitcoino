//! Bounded flat M21 corpus. Source maps/verdicts are rebuilt before keys.
use crate::{registry::GraphSpec, wots::Result};
use bitcoin::hashes::{sha256, Hash};
use serde::{de, Deserialize, Serialize};
use serde_json::{Map, Value};
use std::{collections::HashSet, fmt, fs, io::Read, path::Path};
pub const SCHEMA: &str = "bitvm2-nova-grouped-convolution-run/v1";
pub const OPERATION: &str = "benchmark/grouped-convolution/v1";
const FILE_CAP: usize = 32 << 20;
const MANIFEST_CAP: usize = 1 << 20;
// Independently bounded NEW parser:8*7476+6151*(16+48+7)+7*6151
// +7476+4*256+1024=549110. No frozen parser limit is changed.
const MAX_JSON_NODES: usize = 550000;
const MAX_JSON_DEPTH: usize = 32;
const MAX_JSON_STRING: usize = 200000;
pub const PROFILES: [&str; 20] = [
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
pub const LABELS: [&str; 2] = ["legacy-rows", "grouped-and"];
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Run {
    pub schema: String,
    pub context: String,
    pub operation_id: String,
    pub cases: Vec<Descriptor>,
}
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Descriptor {
    pub name: String,
    pub profile: String,
    pub role: String,
    pub fixture: String,
    pub source_sha256: String,
    pub source_maps_sha256: String,
    pub word_catalogue_sha256: String,
    pub assignment_sha256: String,
    pub adapters: [AdapterDescriptor; 2],
}
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AdapterDescriptor {
    pub index: usize,
    pub label: String,
    pub filename: String,
    pub file_sha256: String,
    pub file_bytes: usize,
    pub program_sha256: String,
    pub catalogue_id: String,
    pub words: usize,
    pub arithmetic_constraints: usize,
    pub canonical_fields: usize,
    pub leaves: usize,
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
    sha256::Hash::hash(b"BITVM2-NOVA/GROUPED-CONVOLUTION-CONFORMANCE/v1").to_string()
}
pub fn fixture(index: usize) -> &'static str {
    match index {
        0 => "mul-distinct",
        1 => "mul-equal-distinct",
        2 => "square",
        3 => "point",
        15 => "mul-equal-distinct",
        16 => "square",
        17 => "point-inactive",
        _ => "mul-distinct",
    }
}
fn census(fixture: &str, adapter: usize) -> Result<(usize, usize, usize, usize)> {
    match (fixture, adapter) {
        ("mul-distinct" | "mul-equal-distinct", 0) => Ok((634, 486, 3, 489)),
        ("mul-distinct" | "mul-equal-distinct", 1) => Ok((634, 278, 3, 281)),
        ("square", 0) => Ok((579, 470, 2, 472)),
        ("square", 1) => Ok((579, 262, 2, 264)),
        ("point" | "point-inactive", 0) => Ok((7476, 6116, 35, 6151)),
        ("point" | "point-inactive", 1) => Ok((7476, 3412, 35, 3447)),
        _ => Err("closed fixture/adapter census".into()),
    }
}
fn sorted(values: &[usize], leaves: usize) -> bool {
    values.iter().all(|i| *i < leaves) && values.windows(2).all(|p| p[0] < p[1])
}
fn read(path: &Path, cap: usize) -> Result<Vec<u8>> {
    let info = fs::symlink_metadata(path)?;
    require(
        info.is_file() && !info.file_type().is_symlink() && info.len() <= cap as u64,
        "regular bounded immutable input file",
    )?;
    let mut raw = Vec::new();
    fs::File::open(path)?
        .take((cap + 1) as u64)
        .read_to_end(&mut raw)?;
    require(raw.len() <= cap, "input grew beyond cap")?;
    Ok(raw)
}
pub fn lexical_nodes(raw: &[u8]) -> Result<usize> {
    let (mut quoted, mut escaped, mut depth, mut nodes, mut length) =
        (false, false, 0usize, 0usize, 0usize);
    for &byte in raw {
        require(byte.is_ascii(), "canonical ASCII transport")?;
        if quoted {
            length += 1;
            require(length <= MAX_JSON_STRING, "JSON string cap")?;
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
                    length = 0;
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
                "JSON lexical node/depth cap",
            )?;
        }
    }
    Ok(nodes)
}
struct Unique(Value);
impl<'de> Deserialize<'de> for Unique {
    fn deserialize<D: de::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct Visitor;
        impl<'de> de::Visitor<'de> for Visitor {
            type Value = Unique;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("bounded unique canonical JSON")
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
                        return Err(de::Error::custom("duplicate JSON field"));
                    }
                }
                Ok(Unique(Value::Object(out)))
            }
        }
        d.deserialize_any(Visitor)
    }
}
fn parse<T: serde::de::DeserializeOwned + Serialize>(raw: &[u8]) -> Result<T> {
    lexical_nodes(raw)?;
    let v: Unique = serde_json::from_slice(raw)?;
    require(
        serde_json::to_vec(&v.0)? == raw,
        "canonical compact input JSON",
    )?;
    let typed: T = serde_json::from_value(v.0.clone())?;
    require(
        serde_json::to_value(&typed)? == v.0,
        "unknown/noncanonical nested input field",
    )?;
    Ok(typed)
}
impl Run {
    pub fn validate(&self) -> Result<()> {
        require(
            self.schema == SCHEMA
                && self.context == context()
                && self.operation_id == OPERATION
                && self.cases.len() == 40,
            "closed grouped-convolution run identity",
        )?;
        for (i, d) in self.cases.iter().enumerate() {
            let local = i % 20;
            let (short, role) = if i < 20 {
                ("p", "pallas_base")
            } else {
                ("v", "vesta_base")
            };
            require(
                d.name == format!("{short}/{local:02}")
                    && d.profile == PROFILES[local]
                    && d.role == role
                    && d.fixture == fixture(local),
                "closed paired case order/profile/role/fixture",
            )?;
            require(
                [
                    &d.source_sha256,
                    &d.source_maps_sha256,
                    &d.word_catalogue_sha256,
                    &d.assignment_sha256,
                ]
                .iter()
                .all(|h| hex32(h)),
                "canonical paired source hashes",
            )?;
            let mut target_total = 0usize;
            for (adapter, a) in d.adapters.iter().enumerate() {
                let (words, arith, fields, leaves) = census(&d.fixture, adapter)?;
                require(
                    a.index == adapter
                        && a.label == LABELS[adapter]
                        && a.filename == format!("case-{i:02}-{adapter}.json")
                        && (1..=FILE_CAP).contains(&a.file_bytes)
                        && a.words == words
                        && a.arithmetic_constraints == arith
                        && a.canonical_fields == fields
                        && a.leaves == leaves
                        && [&a.file_sha256, &a.program_sha256, &a.catalogue_id]
                            .iter()
                            .all(|h| hex32(h)),
                    "closed paired adapter descriptor",
                )?;
                require(
                    sorted(&a.expected_false, leaves)
                        && sorted(&a.expected_abort_ordinals, leaves)
                        && a.expected_false
                            .iter()
                            .all(|n| !a.expected_abort_ordinals.contains(n)),
                    "disjoint ordered false/abort census",
                )?;
                if local < 4 {
                    require(
                        a.execution_mode == "all"
                            && a.selected_ordinals.is_none()
                            && a.expected_false.is_empty()
                            && a.expected_abort_ordinals.is_empty(),
                        "eight full honest paired statements",
                    )?;
                } else {
                    let selected = a
                        .selected_ordinals
                        .as_ref()
                        .ok_or("target selection missing")?;
                    require(
                        a.execution_mode == "selected"
                            && selected.len() <= 128
                            && sorted(selected, leaves)
                            && a.expected_false
                                .iter()
                                .chain(&a.expected_abort_ordinals)
                                .all(|n| selected.contains(n)),
                        "target selection preserves every false/abort",
                    )?;
                    target_total += selected.len();
                }
            }
            require(
                local < 4 || (1..=128).contains(&target_total),
                "target128 cap covers both adapters together",
            )?;
        }
        Ok(())
    }
    pub fn load(manifest: &Path, dir: &Path, expected: &str) -> Result<Self> {
        require(hex32(expected), "canonical out-of-band manifest pin")?;
        let info = fs::symlink_metadata(dir)?;
        require(
            info.is_dir()
                && !info.file_type().is_symlink()
                && manifest.file_name().and_then(|n| n.to_str()) == Some("manifest.json")
                && manifest.canonicalize()? == dir.join("manifest.json").canonicalize()?,
            "fixed paired input directory/manifest",
        )?;
        let raw = read(manifest, MANIFEST_CAP)?;
        require(
            sha256::Hash::hash(&raw).to_string() == expected,
            "raw manifest pin",
        )?;
        let run: Self = parse(&raw)?;
        run.validate()?;
        let expected_files: HashSet<_> = std::iter::once("manifest.json".to_string())
            .chain(
                run.cases
                    .iter()
                    .flat_map(|d| d.adapters.iter().map(|a| a.filename.clone())),
            )
            .collect();
        let mut actual = HashSet::new();
        for entry in fs::read_dir(dir)? {
            let e = entry?;
            let info = fs::symlink_metadata(e.path())?;
            require(
                info.is_file() && !info.file_type().is_symlink(),
                "regular paired input files only",
            )?;
            actual.insert(
                e.file_name()
                    .to_str()
                    .ok_or("ASCII input filename")?
                    .to_string(),
            );
        }
        require(
            actual == expected_files && actual.len() == 81,
            "exact eighty-one input files",
        )?;
        Ok(run)
    }
    pub fn load_case(&self, d: &Descriptor, adapter: usize, dir: &Path) -> Result<(Case, usize)> {
        self.validate()?;
        require(
            adapter < 2 && self.cases.iter().any(|known| known == d),
            "pinned paired descriptor/adapter",
        )?;
        let a = &d.adapters[adapter];
        let raw = read(&dir.join(&a.filename), FILE_CAP)?;
        require(
            raw.len() == a.file_bytes && sha256::Hash::hash(&raw).to_string() == a.file_sha256,
            "consumed paired case byte pin",
        )?;
        let nodes = lexical_nodes(&raw)?;
        let c: Case = parse(&raw)?;
        require(
            c.spec.words.len() <= 7476
                && c.spec.leaves.len() <= 6151
                && c.checks.len() <= 6151
                && c.spec.bodies.len() <= 256
                && c.spec
                    .leaves
                    .iter()
                    .all(|leaf| leaf.wires.len() <= 48 && leaf.argument.len() <= 8),
            "typed independent parser-work premises before source/keys",
        )?;
        require(
            c.name
                == format!(
                    "{}/{}",
                    d.name,
                    if adapter == 0 {
                        "baseline"
                    } else {
                        "candidate"
                    }
                )
                && c.expected_spec_id == a.catalogue_id
                && c.words.len() == a.words
                && c.spec.words.len() == a.words
                && c.spec.leaves.len() == a.leaves
                && c.spec.program_sha256 == a.program_sha256
                && c.spec.context == self.context
                && c.spec.field_role == d.role
                && c.spec.operation_id == format!("{}/{}", self.operation_id, d.fixture)
                && c.measure_all == (a.execution_mode == "all")
                && hex::encode(c.spec.identity()?) == a.catalogue_id,
            "actual paired case identity",
        )?;
        let selected: Vec<_> = a
            .selected_ordinals
            .clone()
            .unwrap_or_else(|| (0..a.leaves).collect());
        require(
            c.checks.len() == selected.len(),
            "exact paired selected check count",
        )?;
        for (check, ordinal) in c.checks.iter().zip(selected) {
            let expected = if a.expected_abort_ordinals.contains(&ordinal) {
                None
            } else {
                Some(!a.expected_false.contains(&ordinal))
            };
            require(
                check.ordinal == ordinal && check.expected_correct == expected,
                "paired tri-state selected observation",
            )?;
        }
        Ok((c, nodes))
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
    fn closed_raw_json_is_unique_compact_and_integer() {
        assert!(parse::<Tiny>(br#"{"value":1}"#).is_ok());
        for raw in [
            br#"{"value":1,"value":2}"#.as_slice(),
            br#"{"value":1.0}"#,
            br#"{ "value":1}"#,
            br#"{"value":1,"x":0}"#,
        ] {
            assert!(parse::<Tiny>(raw).is_err());
        }
    }
    #[test]
    fn separate_parser_formula_and_profile_census_are_explicit() {
        assert_eq!(
            8 * 7476 + 6151 * (16 + 48 + 7) + 7 * 6151 + 7476 + 4 * 256 + 1024,
            549110
        );
        assert!(549110 < MAX_JSON_NODES);
        assert_eq!(PROFILES.len(), 20);
        assert_eq!(census("square", 0).unwrap(), (579, 470, 2, 472));
        assert_eq!(census("point", 1).unwrap(), (7476, 3412, 35, 3447));
    }
    #[test]
    fn lexical_limit_rejects_one_more_separator() {
        let mut raw = vec![b'['];
        for _ in 1..MAX_JSON_NODES {
            raw.extend_from_slice(b"0,");
        }
        raw.extend_from_slice(b"0]");
        assert_eq!(lexical_nodes(&raw).unwrap(), MAX_JSON_NODES);
        let end = raw.len() - 1;
        raw.splice(end..end, [b',', b'0']);
        assert!(lexical_nodes(&raw).is_err());
    }
    #[test]
    fn null_abort_is_not_ordinary_false() {
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
}
