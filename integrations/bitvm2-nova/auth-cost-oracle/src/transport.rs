//! Closed, bounded M18 transport. No adapter mode or receipt is an input.
use bitcoin::hashes::{sha256, Hash};
use bitvm2_nova_script_oracle::{registry::GraphSpec, wots::Result};
use serde::{de, Deserialize, Serialize};
use serde_json::{Map, Value};
use std::{collections::HashSet, fmt, fs, io::Read, path::Path};

pub(crate) const SCHEMA: &str = "bitvm2-nova-auth-cost-run/v1";
pub(crate) const OPERATION: &str = "benchmark/auth-cost/v1";
pub(crate) const CASE_CAP: usize = 32 << 20;
pub(crate) const MANIFEST_CAP: usize = 1 << 20;
pub(crate) const RESULT_CAP: usize = 1 << 20;
pub(crate) const RECORD_CAP: usize = 128 << 20;
const MAX_JSON_NODES: usize = 250_000;
const MAX_JSON_DEPTH: usize = 32;
const MAX_JSON_STRING: usize = 200_000;
const MIXED: [&str; 9] = [
    "a0",
    "a1",
    "a9",
    "a255",
    "bad-aux",
    "bad-square",
    "a256",
    "a-max",
    "auth-order",
];

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Run {
    pub(crate) schema: String,
    pub(crate) context: String,
    pub(crate) operation_id: String,
    pub(crate) cases: Vec<CaseDescriptor>,
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct CaseDescriptor {
    pub(crate) name: String,
    pub(crate) fixture: String,
    pub(crate) profile: String,
    pub(crate) role: String,
    pub(crate) filename: String,
    pub(crate) file_sha256: String,
    pub(crate) file_bytes: usize,
    pub(crate) program_sha256: String,
    pub(crate) catalogue_id: String,
    pub(crate) source_sha256: String,
    pub(crate) source_maps_sha256: String,
    pub(crate) words: usize,
    pub(crate) leaves: usize,
    pub(crate) expected_false: Vec<usize>,
    pub(crate) expected_abort_ordinals: Vec<usize>,
}

pub(crate) type Descriptor = CaseDescriptor;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Check {
    pub(crate) ordinal: usize,
    pub(crate) expected_correct: bool,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Case {
    pub(crate) name: String,
    pub(crate) spec: GraphSpec,
    pub(crate) expected_spec_id: String,
    pub(crate) words: Vec<u32>,
    pub(crate) checks: Vec<Check>,
    pub(crate) measure_all: bool,
}

fn require(yes: bool, message: &str) -> Result<()> {
    if yes {
        Ok(())
    } else {
        Err(message.into())
    }
}

pub(crate) fn hex32(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub(crate) fn context() -> String {
    sha256::Hash::hash(b"BITVM2-NOVA/AUTH-COST-CONFORMANCE/v1").to_string()
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

/// Bound token work before serde allocates nested containers. This is not a
/// JSON parser: serde still checks grammar, types and every duplicate object.
fn lexical_budget(raw: &[u8]) -> Result<()> {
    let mut quoted = false;
    let mut escaped = false;
    let mut depth = 0usize;
    let mut nodes = 0usize;
    let mut string_bytes = 0usize;
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
                b']' | b'}' => {
                    depth = depth.saturating_sub(1);
                }
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
            fn visit_bool<E: de::Error>(self, value: bool) -> std::result::Result<Unique, E> {
                Ok(Unique(Value::Bool(value)))
            }
            fn visit_i64<E: de::Error>(self, value: i64) -> std::result::Result<Unique, E> {
                Ok(Unique(value.into()))
            }
            fn visit_u64<E: de::Error>(self, value: u64) -> std::result::Result<Unique, E> {
                Ok(Unique(value.into()))
            }
            fn visit_f64<E: de::Error>(self, _: f64) -> std::result::Result<Unique, E> {
                Err(E::custom("integer JSON required"))
            }
            fn visit_str<E: de::Error>(self, value: &str) -> std::result::Result<Unique, E> {
                Ok(Unique(Value::String(value.into())))
            }
            fn visit_string<E: de::Error>(self, value: String) -> std::result::Result<Unique, E> {
                Ok(Unique(Value::String(value)))
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
                while let Some(value) = seq.next_element::<Unique>()? {
                    out.push(value.0);
                }
                Ok(Unique(Value::Array(out)))
            }
            fn visit_map<A: de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<Unique, A::Error> {
                let mut out = Map::new();
                while let Some((key, value)) = map.next_entry::<String, Unique>()? {
                    if out.insert(key, value.0).is_some() {
                        return Err(de::Error::custom("duplicate JSON object field"));
                    }
                }
                Ok(Unique(Value::Object(out)))
            }
        }
        deserializer.deserialize_any(Visitor)
    }
}

fn parse<T>(raw: &[u8]) -> Result<T>
where
    T: serde::de::DeserializeOwned + Serialize,
{
    lexical_budget(raw)?;
    let unique: Unique = serde_json::from_slice(raw)?;
    require(
        serde_json::to_vec(&unique.0)? == raw,
        "canonical compact JSON bytes required",
    )?;
    let typed: T = serde_json::from_value(unique.0.clone())?;
    // Some shared baseline nested DTOs predate deny_unknown_fields. This exact
    // roundtrip rejects anything their serde reader would otherwise discard.
    require(
        serde_json::to_value(&typed)? == unique.0,
        "unknown or noncanonical nested input field",
    )?;
    Ok(typed)
}

fn closed(
    index: usize,
) -> Result<(
    String,
    &'static str,
    &'static str,
    &'static str,
    usize,
    usize,
)> {
    require(index < 22, "closed twenty-two case inventory")?;
    if index < 18 {
        let primary = index < 9;
        Ok((
            format!("{}/m{}", if primary { "p" } else { "v" }, index % 9),
            "mixed",
            MIXED[index % 9],
            if primary {
                "pallas_scalar"
            } else {
                "vesta_scalar"
            },
            3,
            2,
        ))
    } else {
        let primary = index < 20;
        let honest = index % 2 == 0;
        Ok((
            format!(
                "{}/r{}",
                if primary { "p" } else { "v" },
                if honest { "h" } else { "f" }
            ),
            "round",
            if honest { "honest" } else { "producer-fault" },
            if primary {
                "pallas_scalar"
            } else {
                "vesta_scalar"
            },
            1417,
            1217,
        ))
    }
}

impl Run {
    pub(crate) fn validate(&self) -> Result<()> {
        require(
            self.schema == SCHEMA
                && self.context == context()
                && self.operation_id == OPERATION
                && self.cases.len() == 22,
            "fixed auth-cost schema/context/operation/inventory required",
        )?;
        for (index, d) in self.cases.iter().enumerate() {
            let (name, fixture, profile, role, words, leaves) = closed(index)?;
            require(
                d.name == name
                    && d.fixture == fixture
                    && d.profile == profile
                    && d.role == role
                    && d.words == words
                    && d.leaves == leaves
                    && d.filename == format!("case-{index:02}.json")
                    && d.file_bytes > 0
                    && d.file_bytes <= CASE_CAP,
                "closed case descriptor differs",
            )?;
            require(
                [
                    &d.file_sha256,
                    &d.program_sha256,
                    &d.catalogue_id,
                    &d.source_sha256,
                    &d.source_maps_sha256,
                ]
                .iter()
                .all(|hash| hex32(hash)),
                "canonical descriptor hashes required",
            )?;
            require(
                d.expected_abort_ordinals.is_empty()
                    && d.expected_false.iter().all(|ordinal| *ordinal < leaves)
                    && d.expected_false.windows(2).all(|pair| pair[0] < pair[1]),
                "bounded sorted raw truth observations required",
            )?;
        }
        Ok(())
    }

    pub(crate) fn load(manifest: &Path, directory: &Path, expected_sha256: &str) -> Result<Self> {
        require(
            hex32(expected_sha256),
            "external exact manifest SHA256 required",
        )?;
        let info = fs::symlink_metadata(directory)?;
        require(
            info.is_dir() && !info.file_type().is_symlink(),
            "regular case directory required",
        )?;
        require(
            manifest.file_name().and_then(|n| n.to_str()) == Some("manifest.json")
                && manifest.canonicalize()? == directory.join("manifest.json").canonicalize()?,
            "manifest must belong to exact case directory",
        )?;
        let raw = read(manifest, MANIFEST_CAP)?;
        require(
            sha256::Hash::hash(&raw).to_string() == expected_sha256,
            "out-of-band manifest hash mismatch",
        )?;
        let run: Self = parse(&raw)?;
        run.validate()?;
        let expected: HashSet<String> = std::iter::once("manifest.json".to_string())
            .chain(run.cases.iter().map(|d| d.filename.clone()))
            .collect();
        let mut actual = HashSet::new();
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let info = fs::symlink_metadata(entry.path())?;
            require(
                info.is_file() && !info.file_type().is_symlink(),
                "case directory contains non-regular entry",
            )?;
            actual.insert(
                entry
                    .file_name()
                    .to_str()
                    .ok_or("ASCII case filename required")?
                    .to_string(),
            );
        }
        require(
            actual == expected && actual.len() == 23,
            "exact twenty-three input files required",
        )?;
        Ok(run)
    }

    pub(crate) fn load_case(&self, descriptor: &CaseDescriptor, directory: &Path) -> Result<Case> {
        self.validate()?;
        require(
            self.cases.contains(descriptor),
            "case descriptor must belong to the pinned run",
        )?;
        let raw = read(&directory.join(&descriptor.filename), CASE_CAP)?;
        require(
            raw.len() == descriptor.file_bytes
                && sha256::Hash::hash(&raw).to_string() == descriptor.file_sha256,
            "exact consumed case bytes differ",
        )?;
        let case: Case = parse(&raw)?;
        let op = format!(
            "{}/{}",
            self.operation_id,
            if descriptor.fixture == "mixed" {
                "mixed"
            } else {
                "round/round/0"
            }
        );
        require(
            case.name == descriptor.name
                && case.measure_all
                && case.expected_spec_id == descriptor.catalogue_id
                && case.spec.program_sha256 == descriptor.program_sha256
                && case.spec.context == self.context
                && case.spec.field_role == descriptor.role
                && case.spec.operation_id == op
                && case.words.len() == descriptor.words
                && case.spec.words.len() == descriptor.words
                && case.spec.leaves.len() == descriptor.leaves
                && case.checks.len() == descriptor.leaves,
            "closed consumed case/source shape differs",
        )?;
        require(
            hex::encode(case.spec.identity()?) == descriptor.catalogue_id,
            "actual catalogue identity differs",
        )?;
        for (ordinal, check) in case.checks.iter().enumerate() {
            require(
                check.ordinal == ordinal
                    && check.expected_correct == !descriptor.expected_false.contains(&ordinal),
                "every ordered correctness/disproof pair required",
            )?;
        }
        // Independent source::admit must still reconstruct both source hashes,
        // every body/alias/bound, assignment and truth before any keys exist.
        Ok(case)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    struct Small {
        value: u32,
    }

    #[test]
    fn duplicate_unknown_and_noncanonical_transport_fail() {
        assert!(parse::<Small>(br#"{"value":1}"#).is_ok());
        for raw in [
            br#"{"value":1,"value":1}"#.as_slice(),
            br#"{"extra":0,"value":1}"#,
            br#"{"value":true}"#,
            br#"{"value":1.0}"#,
            br#"{ "value":1}"#,
        ] {
            assert!(parse::<Small>(raw).is_err());
        }
    }

    #[test]
    fn lexical_depth_and_string_budgets_precede_serde() {
        let depth = [
            vec![b'['; MAX_JSON_DEPTH + 1],
            vec![b']'; MAX_JSON_DEPTH + 1],
        ]
        .concat();
        assert!(lexical_budget(&depth).is_err());
        let text = [vec![b'"'], vec![b'a'; MAX_JSON_STRING + 1], vec![b'"']].concat();
        assert!(lexical_budget(&text).is_err());
        assert!(lexical_budget(b"[1,2,3]").is_ok());
    }

    #[test]
    fn closed_profiles_include_both_round_diagnostics() {
        assert_eq!(closed(0).unwrap().0, "p/m0");
        assert_eq!(closed(17).unwrap().0, "v/m8");
        assert_eq!(closed(18).unwrap().0, "p/rh");
        assert_eq!(closed(19).unwrap().0, "p/rf");
        assert_eq!(closed(20).unwrap().0, "v/rh");
        assert_eq!(closed(21).unwrap().0, "v/rf");
        assert!(closed(22).is_err());
    }

    #[test]
    fn hash_types_are_lowercase_exact_width() {
        assert!(hex32(&"01".repeat(32)));
        assert!(!hex32(&"AB".repeat(32)));
        assert!(!hex32(&"0".repeat(63)));
    }
}
