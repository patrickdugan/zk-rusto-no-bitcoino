//! Closed, bounded hosted fixture transport. These pins are supplied by the
//! directly invoked verifier-owned Python source, not a production proof codec.
use crate::chain::{self, Header};
use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitvm2_nova_script_oracle::wots::Result;
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::HashSet, fs, io::Read, path::Path};

pub(crate) const SCHEMA: &str = "bitvm2-nova-byte-c-bit-point-run/v1";
pub(crate) const OPERATION: &str = "benchmark/byte-c-bit-point/v1";
const CONTEXT: &[u8] = b"BITVM2-NOVA/BYTE-C-BIT-POINT-CONFORMANCE/v1";
const NAMES: [&str; 11] = [
    "rho-hi",
    "rho-lo",
    "rho-tail",
    "c-coeff-frame",
    "c-prefix",
    "c-absorb",
    "c-hi",
    "c-lo",
    "c-uniform",
    "scalar-bits",
    "conditional-point",
];
const WORDS: [usize; 11] = [
    29445, 29445, 587, 187, 29445, 23, 29445, 29445, 379, 264, 7498,
];
const LEAVES: [usize; 11] = [29245, 29245, 453, 111, 29245, 9, 29245, 29245, 245, 9, 6161];
const FULL: [usize; 5] = [0, 1, 4, 6, 7];
const OLD_PROBES: [&str; 10] = [
    "coefficient-c0-modulus",
    "coefficient-c2-modulus",
    "frame-counter",
    "frame-NoDS",
    "frame-tag",
    "frame-zero-capacity",
    "absorb-wrong-xor",
    "absorb-selector",
    "absorb-delimiter",
    "absorb-end-mask",
];
const NEGATIVES: [&str; 9] = [
    "invalid-P-b0",
    "wrong-E-b0",
    "wrong-selected-R",
    "wrong-R-flag",
    "nonzero-infinity",
    "auxiliary-flip",
    "signed-bit-two",
    "coordinate-modulus",
    "coordinate-modulus-plus-one",
];
const MAP_CAP: u64 = 8 << 20;
const SMALL_CAP: u64 = 1 << 20;
const CASE_CAP: u64 = 32 << 20;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Run {
    pub(crate) schema: String,
    pub(crate) context: String,
    pub(crate) operation_id: String,
    pub(crate) cases: Vec<Group>,
    pub(crate) probes: Vec<Probe>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Group {
    pub(crate) name: String,
    pub(crate) profile: String,
    pub(crate) role: String,
    pub(crate) base_role: String,
    pub(crate) rho_counter: u64,
    pub(crate) c_counter: u64,
    pub(crate) bit_index: usize,
    pub(crate) execution_mode: String,
    pub(crate) source_sha256: String,
    pub(crate) source_maps_sha256: String,
    pub(crate) chain_source_sha256: String,
    pub(crate) chain_source_maps_sha256: String,
    pub(crate) eval_w_le: String,
    pub(crate) prior_state_hex: String,
    pub(crate) compressed_coefficients_le: [String; 2],
    pub(crate) expected_rho_hi_output_state_hex: String,
    pub(crate) expected_rho_lo_output_state_hex: String,
    pub(crate) expected_rho_raw_state_le: String,
    pub(crate) expected_rho_result_le: String,
    pub(crate) expected_rho_quotient_le: String,
    pub(crate) expected_prefix_output_state_hex: String,
    pub(crate) expected_c_hi_output_state_hex: String,
    pub(crate) expected_c_lo_output_state_hex: String,
    pub(crate) expected_c_raw_state_le: String,
    pub(crate) expected_c_result_le: String,
    pub(crate) expected_c_quotient_le: String,
    pub(crate) asserted_scalar_le: String,
    pub(crate) asserted_scalar_quotient_le: String,
    pub(crate) selected_bit: u32,
    pub(crate) canonical_bit: u32,
    pub(crate) point_A: PointValue,
    pub(crate) point_P: PointValue,
    pub(crate) expected_E: PointValue,
    pub(crate) expected_R: PointValue,
    pub(crate) point_source_filename: String,
    pub(crate) point_source_file_sha256: String,
    pub(crate) point_source_file_bytes: u64,
    pub(crate) point_maps_filename: String,
    pub(crate) point_maps_file_sha256: String,
    pub(crate) point_maps_file_bytes: u64,
    pub(crate) chain_source_filename: String,
    pub(crate) chain_source_file_sha256: String,
    pub(crate) chain_source_file_bytes: u64,
    pub(crate) chain_maps_filename: String,
    pub(crate) chain_maps_file_sha256: String,
    pub(crate) chain_maps_file_bytes: u64,
    pub(crate) components: Vec<Header>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PointValue {
    pub(crate) infinity: u32,
    pub(crate) x_le: String,
    pub(crate) y_le: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PointInputs {
    pub(crate) bit: u32,
    pub(crate) point_A: PointValue,
    pub(crate) point_P: PointValue,
    pub(crate) point_E: PointValue,
    pub(crate) point_R: PointValue,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ScalarInputs {
    raw_c_le: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Probe {
    pub(crate) name: String,
    pub(crate) kind: String,
    pub(crate) category: String,
    pub(crate) role: String,
    pub(crate) field_role: String,
    pub(crate) source_case: String,
    pub(crate) source_component: Option<usize>,
    pub(crate) operation_id: String,
    pub(crate) filename: String,
    pub(crate) file_sha256: String,
    pub(crate) file_bytes: u64,
    pub(crate) source_sha256: String,
    pub(crate) source_maps_sha256: String,
    pub(crate) catalogue_id: String,
    pub(crate) program_sha256: String,
    pub(crate) words: usize,
    pub(crate) leaves: usize,
    pub(crate) execution_mode: String,
    pub(crate) selected_ordinals: Option<Vec<usize>>,
    pub(crate) expected_false: Vec<usize>,
    pub(crate) expected_abort_ordinals: Vec<usize>,
    pub(crate) selected_leaf: usize,
    pub(crate) expected_selected_correct: bool,
    #[serde(deserialize_with = "strict_inputs")]
    pub(crate) inputs: Value,
}

fn strict_inputs<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Value, D::Error> {
    use serde::de::{DeserializeSeed, Error, MapAccess, Visitor};
    struct InputSeed(usize);
    struct InputVisitor(usize);
    impl<'de> DeserializeSeed<'de> for InputSeed {
        type Value = Value;
        fn deserialize<D: serde::Deserializer<'de>>(
            self,
            d: D,
        ) -> std::result::Result<Value, D::Error> {
            if self.0 > 3 {
                return Err(D::Error::custom("closed probe input nesting exceeded"));
            }
            d.deserialize_any(InputVisitor(self.0))
        }
    }
    impl<'de> Visitor<'de> for InputVisitor {
        type Value = Value;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("bounded unique probe objects, unsigned integers or fixed hex strings")
        }
        fn visit_u64<E: Error>(self, value: u64) -> std::result::Result<Value, E> {
            Ok(Value::from(value))
        }
        fn visit_str<E: Error>(self, value: &str) -> std::result::Result<Value, E> {
            if value.len() > 128 || !value.is_ascii() {
                return Err(E::custom("closed probe string cap/ASCII"));
            }
            Ok(Value::String(value.to_string()))
        }
        fn visit_string<E: Error>(self, value: String) -> std::result::Result<Value, E> {
            self.visit_str(&value)
        }
        fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> std::result::Result<Value, M::Error> {
            let mut value = serde_json::Map::new();
            while let Some(key) = map.next_key::<String>()? {
                if key.len() > 32 || !key.is_ascii() || value.len() >= 8 || value.contains_key(&key)
                {
                    return Err(M::Error::custom(
                        "duplicate/unbounded closed probe input key",
                    ));
                }
                value.insert(key, map.next_value_seed(InputSeed(self.0 + 1))?);
            }
            Ok(Value::Object(value))
        }
    }
    InputSeed(0).deserialize(deserializer)
}

#[derive(Clone)]
pub(crate) struct FilePin {
    pub(crate) filename: String,
    pub(crate) sha256: String,
    pub(crate) bytes: u64,
    pub(crate) cap: u64,
}

pub(crate) fn fixed_hex<const N: usize>(value: &str) -> Result<[u8; N]> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err("exact lowercase fixed-width hex required".into());
    }
    hex::decode(value)?
        .try_into()
        .map_err(|_| "fixed hex width".into())
}

fn modulus(role: &str) -> Result<BigUint> {
    let text = match role {
        "pallas_base" => {
            "28948022309329048855892746252171976963363056481941560715954676764349967630337"
        }
        "vesta_base" => {
            "28948022309329048855892746252171976963363056481941647379679742748393362948097"
        }
        _ => return Err("point encoding requires named base role".into()),
    };
    BigUint::parse_bytes(text.as_bytes(), 10).ok_or_else(|| "fixed base modulus".into())
}

impl PointValue {
    pub(crate) fn coordinates(&self) -> Result<([u8; 32], [u8; 32])> {
        Ok((fixed_hex(&self.x_le)?, fixed_hex(&self.y_le)?))
    }
    /// Canonical coordinate/flag admission only; curve membership is separate.
    pub(crate) fn validate(&self, role: &str) -> Result<()> {
        self.validate_raw(role, false, false, false)
    }
    fn validate_raw(
        &self,
        role: &str,
        invalid_flag: bool,
        noncanonical_x: bool,
        nonzero_infinity: bool,
    ) -> Result<()> {
        let (x, y) = self.coordinates()?;
        let p = modulus(role)?;
        if self.infinity > if invalid_flag { 2 } else { 1 }
            || (!noncanonical_x && BigUint::from_bytes_le(&x) >= p)
            || BigUint::from_bytes_le(&y) >= p
            || (!nonzero_infinity && self.infinity == 1 && (x != [0; 32] || y != [0; 32]))
        {
            return Err(
                "point flag/coordinate/infinity encoding differs from closed profile".into(),
            );
        }
        Ok(())
    }
}

fn sorted_ordinals(values: &[usize], cap: usize) -> bool {
    values.len() <= cap
        && values.iter().all(|value| *value < cap)
        && values.windows(2).all(|pair| pair[0] < pair[1])
}

fn pin(
    out: &mut Vec<FilePin>,
    name: &str,
    expected: String,
    hash: &str,
    bytes: u64,
    cap: u64,
) -> Result<()> {
    fixed_hex::<32>(hash)?;
    if name != expected || bytes == 0 || bytes > cap {
        return Err("closed bounded file pin differs".into());
    }
    out.push(FilePin {
        filename: expected,
        sha256: hash.to_string(),
        bytes,
        cap,
    });
    Ok(())
}

impl Group {
    pub(crate) fn chain_group(&self) -> chain::Group {
        chain::Group {
            name: self.name.clone(),
            profile: self.profile.clone(),
            role: self.role.clone(),
            rho_counter: self.rho_counter,
            c_counter: self.c_counter,
            execution_mode: self.execution_mode.clone(),
            source_sha256: self.chain_source_sha256.clone(),
            source_maps_sha256: self.chain_source_maps_sha256.clone(),
            eval_w_le: self.eval_w_le.clone(),
            prior_state_hex: self.prior_state_hex.clone(),
            compressed_coefficients_le: self.compressed_coefficients_le.clone(),
            expected_rho_hi_output_state_hex: self.expected_rho_hi_output_state_hex.clone(),
            expected_rho_lo_output_state_hex: self.expected_rho_lo_output_state_hex.clone(),
            expected_rho_raw_state_le: self.expected_rho_raw_state_le.clone(),
            expected_rho_result_le: self.expected_rho_result_le.clone(),
            expected_rho_quotient_le: self.expected_rho_quotient_le.clone(),
            expected_prefix_output_state_hex: self.expected_prefix_output_state_hex.clone(),
            expected_c_hi_output_state_hex: self.expected_c_hi_output_state_hex.clone(),
            expected_c_lo_output_state_hex: self.expected_c_lo_output_state_hex.clone(),
            expected_c_raw_state_le: self.expected_c_raw_state_le.clone(),
            expected_c_result_le: self.expected_c_result_le.clone(),
            expected_c_quotient_le: self.expected_c_quotient_le.clone(),
            chain_source_filename: self.chain_source_filename.clone(),
            chain_source_file_sha256: self.chain_source_file_sha256.clone(),
            chain_source_file_bytes: self.chain_source_file_bytes,
            chain_maps_filename: self.chain_maps_filename.clone(),
            chain_maps_file_sha256: self.chain_maps_file_sha256.clone(),
            chain_maps_file_bytes: self.chain_maps_file_bytes,
            components: self.components.iter().take(9).cloned().collect(),
        }
    }
    fn validate(&self, index: usize, out: &mut Vec<FilePin>) -> Result<()> {
        let prefix = if index < 3 { "p" } else { "v" };
        let (profile, suffix) = match index % 3 {
            0 => ("honest", "h"),
            1 => ("coherent-bit", "b"),
            _ => ("coherent-scalar-alias", "a"),
        };
        let scalar = if index < 3 {
            "pallas_scalar"
        } else {
            "vesta_scalar"
        };
        let base = if index < 3 {
            "pallas_base"
        } else {
            "vesta_base"
        };
        let counter = if index < 3 { 59 } else { 44 };
        if self.name != format!("{prefix}/{suffix}")
            || self.profile != profile
            || self.role != scalar
            || self.base_role != base
            || self.rho_counter != counter
            || self.c_counter != counter + 1
            || self.bit_index != 0
            || self.execution_mode
                != if profile == "honest" {
                    "full"
                } else {
                    "targeted"
                }
            || self.components.len() != 11
            || self.selected_bit > 1
            || self.canonical_bit > 1
        {
            return Err("closed ordered main profile differs".into());
        }
        for hash in [
            &self.source_sha256,
            &self.source_maps_sha256,
            &self.chain_source_sha256,
            &self.chain_source_maps_sha256,
        ] {
            fixed_hex::<32>(hash)?;
        }
        if self.point_maps_file_sha256 != self.source_maps_sha256
            || self.chain_maps_file_sha256 != self.chain_source_maps_sha256
        {
            return Err("outer raw map pin must equal canonical source-map hash".into());
        }
        fixed_hex::<32>(&self.eval_w_le)?;
        fixed_hex::<64>(&self.prior_state_hex)?;
        for raw in &self.compressed_coefficients_le {
            fixed_hex::<32>(raw)?;
        }
        for raw in [
            &self.expected_rho_hi_output_state_hex,
            &self.expected_rho_lo_output_state_hex,
            &self.expected_prefix_output_state_hex,
            &self.expected_c_hi_output_state_hex,
            &self.expected_c_lo_output_state_hex,
        ] {
            fixed_hex::<200>(raw)?;
        }
        fixed_hex::<64>(&self.expected_rho_raw_state_le)?;
        fixed_hex::<32>(&self.expected_rho_result_le)?;
        fixed_hex::<33>(&self.expected_rho_quotient_le)?;
        let c = fixed_hex::<32>(&self.expected_c_result_le)?;
        let q = fixed_hex::<33>(&self.expected_c_quotient_le)?;
        let raw = fixed_hex::<64>(&self.expected_c_raw_state_le)?;
        let asserted = fixed_hex::<32>(&self.asserted_scalar_le)?;
        let asserted_q = fixed_hex::<33>(&self.asserted_scalar_quotient_le)?;
        if self.canonical_bit != u32::from(c[0] & 1) {
            return Err("canonical selected bit detached from retained c".into());
        }
        if profile == "coherent-scalar-alias" {
            let alias = crate::uniform_alias::alias_values(&raw, scalar)?;
            if asserted != alias.result_le
                || asserted_q != alias.quotient_le
                || self.selected_bit == self.canonical_bit
            {
                return Err("closed scalar alias c+p/q-1 differs".into());
            }
        } else if asserted != c
            || asserted_q != q
            || self.selected_bit != (self.canonical_bit ^ u32::from(profile == "coherent-bit"))
        {
            return Err("closed honest/changed bit assertion differs".into());
        }
        for point in [
            &self.point_A,
            &self.point_P,
            &self.expected_E,
            &self.expected_R,
        ] {
            point.validate(base)?;
        }
        if self.expected_R
            != if self.selected_bit == 0 {
                self.point_A.clone()
            } else {
                self.expected_E.clone()
            }
        {
            return Err("coherent selected R differs from actual asserted bit".into());
        }
        let stem = format!("{index:02}");
        pin(
            out,
            &self.point_source_filename,
            format!("point-source-{stem}.json"),
            &self.point_source_file_sha256,
            self.point_source_file_bytes,
            SMALL_CAP,
        )?;
        pin(
            out,
            &self.point_maps_filename,
            format!("point-maps-{stem}.json"),
            &self.point_maps_file_sha256,
            self.point_maps_file_bytes,
            MAP_CAP,
        )?;
        pin(
            out,
            &self.chain_source_filename,
            format!("chain-source-{stem}.json"),
            &self.chain_source_file_sha256,
            self.chain_source_file_bytes,
            SMALL_CAP,
        )?;
        pin(
            out,
            &self.chain_maps_filename,
            format!("chain-maps-{stem}.json"),
            &self.chain_maps_file_sha256,
            self.chain_maps_file_bytes,
            MAP_CAP,
        )?;
        let mut selected_large = 0;
        for (component, header) in self.components.iter().enumerate() {
            let d = &header.descriptor;
            if d.index != component
                || d.branch != NAMES[component]
                || d.words != WORDS[component]
                || d.leaves != LEAVES[component]
                || d.field_role != if component == 10 { base } else { scalar }
                || d.counter != if component < 3 { counter } else { counter + 1 }
                || !sorted_ordinals(&header.expected_false, d.leaves)
                || !header.expected_abort_ordinals.is_empty()
            {
                return Err("main component shape/role/counter/false-domain differs".into());
            }
            for hash in [
                &d.program_sha256,
                &d.catalogue_id,
                &d.source_sha256,
                &d.source_maps_sha256,
                &d.global_ids_sha256,
            ] {
                fixed_hex::<32>(hash)?;
            }
            if header.maps_file_sha256 != d.source_maps_sha256 {
                return Err("component raw map pin must equal canonical source-map hash".into());
            }
            let expected_false = if profile == "coherent-bit" && component == 9 {
                vec![0]
            } else if profile == "coherent-scalar-alias" && component == 8 {
                vec![244]
            } else {
                vec![]
            };
            if header.expected_false != expected_false {
                return Err("main exact false predicate inventory differs".into());
            }
            if profile == "honest" || (!FULL.contains(&component) && component != 10) {
                if header.execution_mode != "all" || header.selected_ordinals.is_some() {
                    return Err("complete main execution selection differs".into());
                }
            } else if FULL.contains(&component) {
                if header.execution_mode != "none" || header.selected_ordinals.is_some() {
                    return Err(
                        "unchanged permutation normal selection must be empty in targeted profiles"
                            .into(),
                    );
                }
            } else {
                let selected = header
                    .selected_ordinals
                    .as_ref()
                    .ok_or("point target selection missing")?;
                if header.execution_mode != "selected"
                    || selected.is_empty()
                    || !sorted_ordinals(selected, d.leaves)
                    || selected.len() > 128
                    || !(6116..6124).all(|leaf| selected.contains(&leaf))
                    || !selected.contains(&6159)
                    || !selected.contains(&6160)
                {
                    return Err("point selected normal inventory differs".into());
                }
                selected_large += selected.len();
            }
            let local = format!("{stem}-{component}");
            pin(
                out,
                &header.filename,
                format!("case-{local}.json"),
                &header.file_sha256,
                header.file_bytes,
                CASE_CAP,
            )?;
            pin(
                out,
                &header.maps_filename,
                format!("maps-{local}.json"),
                &header.maps_file_sha256,
                header.maps_file_bytes,
                MAP_CAP,
            )?;
            pin(
                out,
                &header.source_manifest_filename,
                format!("source-{local}.json"),
                &header.source_manifest_file_sha256,
                header.source_manifest_file_bytes,
                SMALL_CAP,
            )?;
            match (
                &header.program_manifest_filename,
                &header.program_manifest_file_sha256,
                header.program_manifest_file_bytes,
                header.full.as_ref(),
            ) {
                (Some(name), Some(hash), Some(bytes), Some(_)) if FULL.contains(&component) => pin(
                    out,
                    name,
                    format!("program-{local}.json"),
                    hash,
                    bytes,
                    SMALL_CAP,
                )?,
                (None, None, None, None) if !FULL.contains(&component) => {}
                _ => return Err("full component program/source pin tuple differs".into()),
            }
        }
        if selected_large > 128 {
            return Err("combined targeted main reserve exceeds128 leaves".into());
        }
        Ok(())
    }
}

impl Probe {
    pub(crate) fn point_inputs(&self) -> Result<PointInputs> {
        Ok(serde_json::from_value(self.inputs.clone())?)
    }
    pub(crate) fn scalar_input(&self) -> Result<[u8; 64]> {
        let parsed: ScalarInputs = serde_json::from_value(self.inputs.clone())?;
        fixed_hex(&parsed.raw_c_le)
    }
    fn validate(&self, index: usize, honest: &Group, out: &mut Vec<FilePin>) -> Result<()> {
        let local = index % 26;
        let prefix = if index < 26 { "p" } else { "v" };
        let (category, kind, name, component, words, leaves) = if local < 10 {
            (
                "chain",
                OLD_PROBES[local].to_string(),
                format!("{prefix}/q{local}"),
                Some(if local < 6 { 3 } else { 5 }),
                if local < 6 { 187 } else { 23 },
                if local < 6 { 111 } else { 9 },
            )
        } else if local < 16 {
            let edge = local - 10;
            (
                "point-edge",
                format!("point-edge-{edge}"),
                format!("{prefix}/e{edge}"),
                Some(10),
                7498,
                6161,
            )
        } else if local == 16 {
            (
                "scalar-alias",
                "scalar-plus-modulus".to_string(),
                format!("{prefix}/s"),
                None,
                634,
                254,
            )
        } else {
            let negative = local - 17;
            (
                "point-negative",
                NEGATIVES[negative].to_string(),
                format!("{prefix}/n{negative}"),
                Some(10),
                7498,
                6161,
            )
        };
        let role = if category.starts_with("point-") {
            &honest.base_role
        } else {
            &honest.role
        };
        if self.name != name
            || self.kind != kind
            || self.category != category
            || self.role != honest.role
            || self.field_role != *role
            || self.source_case != honest.name
            || self.source_component != component
            || self.words != words
            || self.leaves != leaves
            || self.selected_leaf >= leaves
            || !sorted_ordinals(&self.expected_false, leaves)
            || !sorted_ordinals(&self.expected_abort_ordinals, leaves)
            || self
                .expected_false
                .iter()
                .any(|i| self.expected_abort_ordinals.contains(i))
        {
            return Err("closed ordered private probe profile differs".into());
        }
        for hash in [
            &self.source_sha256,
            &self.source_maps_sha256,
            &self.catalogue_id,
            &self.program_sha256,
        ] {
            fixed_hex::<32>(hash)?;
        }
        let selected = if category == "chain" || category == "scalar-alias" {
            if self.execution_mode != "all" || self.selected_ordinals.is_some() {
                return Err("complete small probe selection differs".into());
            }
            (0..leaves).collect::<Vec<_>>()
        } else {
            let value = self
                .selected_ordinals
                .as_ref()
                .ok_or("point probe selection missing")?;
            if self.execution_mode != "selected"
                || value.is_empty()
                || !sorted_ordinals(value, leaves)
                || value.len() > if category == "point-edge" { 128 } else { 12 }
            {
                return Err("private point selection exceeds closed reserve".into());
            }
            value.clone()
        };
        if !selected.contains(&self.selected_leaf)
            || selected
                .iter()
                .any(|i| self.expected_abort_ordinals.contains(i))
            || self.expected_selected_correct == self.expected_false.contains(&self.selected_leaf)
        {
            return Err("selected actual probe verdict/abort domain differs".into());
        }
        match category {
            "chain" => {
                if !self
                    .inputs
                    .as_object()
                    .is_some_and(|value| value.is_empty())
                {
                    return Err("frame/absorb inputs must be empty".into());
                }
                let false_leaf = [109, 110, 37, 33, 32, 45, 0, 8, 6, 7][local];
                if self.expected_false != [false_leaf]
                    || self.selected_leaf != false_leaf
                    || !self.expected_abort_ordinals.is_empty()
                {
                    return Err("old probe closed false inventory differs".into());
                }
            }
            "scalar-alias" => {
                if self.scalar_input()? != fixed_hex::<64>(&honest.expected_c_raw_state_le)?
                    || self.expected_false != [253]
                    || self.selected_leaf != 253
                    || !self.expected_abort_ordinals.is_empty()
                {
                    return Err("closed merged alias fixture differs".into());
                }
            }
            _ => {
                let inputs = self.point_inputs()?;
                let signed_bit = kind == "signed-bit-two";
                if inputs.bit > if signed_bit { 2 } else { 1 }
                    || (signed_bit && inputs.bit != 2)
                    || (category == "point-edge" && inputs.bit != u32::from((local - 10) % 2 == 1))
                {
                    return Err("closed private selected bit differs".into());
                }
                inputs.point_A.validate(&honest.base_role)?;
                inputs.point_P.validate(&honest.base_role)?;
                inputs.point_E.validate(&honest.base_role)?;
                inputs.point_R.validate_raw(
                    &honest.base_role,
                    kind == "wrong-R-flag",
                    kind.starts_with("coordinate-modulus"),
                    kind == "nonzero-infinity",
                )?;
                if kind == "wrong-R-flag" && inputs.point_R.infinity != 2 {
                    return Err("closed signed R flag must be2".into());
                }
                if category == "point-edge" {
                    if !self.expected_false.is_empty()
                        || !self.expected_abort_ordinals.is_empty()
                        || self.selected_leaf != 6123
                    {
                        return Err(
                            "honest point edge cannot contain a false/abort predicate".into()
                        );
                    }
                } else if self.expected_selected_correct {
                    return Err("negative probe requires actual selected disproof".into());
                }
            }
        }
        if let Some(component) = component {
            let d = &honest.components[component].descriptor;
            if self.operation_id != d.operation_id
                || self.source_sha256 != d.source_sha256
                || self.source_maps_sha256 != d.source_maps_sha256
                || self.catalogue_id != d.catalogue_id
                || self.program_sha256 != d.program_sha256
            {
                return Err("private source must retain positive source identity".into());
            }
        } else if self.operation_id != format!("{OPERATION}/probe/scalar-alias/{prefix}") {
            return Err("private scalar alias operation differs".into());
        }
        pin(
            out,
            &self.filename,
            format!("probe-{index:02}.json"),
            &self.file_sha256,
            self.file_bytes,
            CASE_CAP,
        )
    }
}

impl Run {
    /// Return304 pinned payload files. The separately CLI-pinned manifest makes305.
    pub(crate) fn validate(&self) -> Result<Vec<FilePin>> {
        if self.schema != SCHEMA
            || self.operation_id != OPERATION
            || self.context != sha256::Hash::hash(CONTEXT).to_string()
            || self.cases.len() != 6
            || self.probes.len() != 52
        {
            return Err("closed conformance schema/context/corpus differs".into());
        }
        let mut result = Vec::with_capacity(304);
        for (index, group) in self.cases.iter().enumerate() {
            group.validate(index, &mut result)?;
        }
        for (index, probe) in self.probes.iter().enumerate() {
            probe.validate(
                index,
                &self.cases[if index < 26 { 0 } else { 3 }],
                &mut result,
            )?;
        }
        let names: HashSet<_> = result.iter().map(|pin| pin.filename.as_str()).collect();
        if result.len() != 304 || names.len() != 304 {
            return Err("closed payload file inventory must contain304 unique files".into());
        }
        Ok(result)
    }
    pub(crate) fn chain_run(&self) -> chain::Run {
        chain::Run {
            schema: "bitvm2-nova-byte-rho-chain-run/v1".to_string(),
            context: self.context.clone(),
            operation_id: format!("{}/chain", self.operation_id),
            cases: self.cases.iter().map(Group::chain_group).collect(),
            probes: vec![],
        }
    }
    /// Call before keys/output creation. No payload receipts substitute for source checks.
    pub(crate) fn validate_directory(&self, directory: &Path) -> Result<()> {
        let files = self.validate()?;
        let metadata = fs::symlink_metadata(directory)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err("owned regular fixture directory required".into());
        }
        let mut expected: HashSet<String> = files.iter().map(|pin| pin.filename.clone()).collect();
        expected.insert("manifest.json".to_string());
        let mut actual = HashSet::new();
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| "ASCII fixture filename required")?;
            if !entry.file_type()?.is_file() || !actual.insert(name) {
                return Err("unexpected/symlink fixture entry".into());
            }
        }
        if actual != expected || actual.len() != 305 {
            return Err("fixture directory must match exact305-file inventory".into());
        }
        for pin in files {
            let path = directory.join(&pin.filename);
            let metadata = fs::symlink_metadata(&path)?;
            if !metadata.is_file()
                || metadata.file_type().is_symlink()
                || metadata.len() != pin.bytes
                || metadata.len() > pin.cap
            {
                return Err("pinned payload changed type/size".into());
            }
            let mut file = fs::File::open(&path)?;
            let mut engine = sha256::Hash::engine();
            let mut total = 0u64;
            let mut buffer = [0u8; 16384];
            loop {
                let count = file.read(&mut buffer)?;
                if count == 0 {
                    break;
                }
                total += count as u64;
                if total > pin.bytes || total > pin.cap {
                    return Err("pinned payload grew during read".into());
                }
                engine.input(&buffer[..count]);
            }
            if total != pin.bytes || sha256::Hash::from_engine(engine).to_string() != pin.sha256 {
                return Err("payload SHA/length changed before native admission".into());
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[derive(Deserialize)]
    struct InputsOnly {
        #[serde(deserialize_with = "strict_inputs")]
        inputs: Value,
    }
    #[test]
    fn nested_probe_input_duplicates_and_noninteger_shapes_reject() {
        let good: InputsOnly = serde_json::from_str(
            r#"{"inputs":{"bit":0,"point_A":{"infinity":1,"x_le":"00","y_le":"00"}}}"#,
        )
        .unwrap();
        assert_eq!(good.inputs["bit"], 0);
        for bad in [
            r#"{"inputs":{"bit":0,"bit":1}}"#,
            r#"{"inputs":{"point_A":{"infinity":0,"infinity":1}}}"#,
            r#"{"inputs":{"bit":true}}"#,
            r#"{"inputs":{"bit":1.0}}"#,
            r#"{"inputs":{"bit":-1}}"#,
            r#"{"inputs":[]}"#,
            r#"{"inputs":{"raw_c_le":null}}"#,
        ] {
            assert!(serde_json::from_str::<InputsOnly>(bad).is_err());
        }
    }
    #[test]
    fn fixed_hex_and_point_flags_are_strict_without_graphs() {
        assert_eq!(fixed_hex::<2>("00ff").unwrap(), [0, 255]);
        for bad in ["0", "00FF", "00fg", "000000"] {
            assert!(fixed_hex::<2>(bad).is_err());
        }
        let point = PointValue {
            infinity: 1,
            x_le: "00".repeat(32),
            y_le: "00".repeat(32),
        };
        point.validate("pallas_base").unwrap();
        let mut bad = point.clone();
        bad.infinity = 2;
        assert!(bad.validate("pallas_base").is_err());
        bad = point.clone();
        bad.x_le = format!("01{}", "00".repeat(31));
        assert!(bad.validate("pallas_base").is_err());
        assert!(point.validate("pallas_scalar").is_err());
        assert!(serde_json::from_value::<PointValue>(
            serde_json::json!({"infinity":true,"x_le":"00".repeat(32),"y_le":"00".repeat(32)})
        )
        .is_err());
        assert!(serde_json::from_value::<PointValue>(serde_json::json!({"infinity":1,"x_le":"00".repeat(32),"y_le":"00".repeat(32),"extra":1})).is_err());
    }
    #[test]
    fn selection_order_and_payload_pin_bounds_are_closed() {
        assert!(sorted_ordinals(&[0, 28, 29], 30));
        for values in [vec![1, 1], vec![2, 1], vec![30]] {
            assert!(!sorted_ordinals(&values, 30));
        }
        let mut files = vec![];
        pin(
            &mut files,
            "probe-00.json",
            "probe-00.json".to_string(),
            &"00".repeat(32),
            10,
            CASE_CAP,
        )
        .unwrap();
        assert!(pin(
            &mut files,
            "../probe-00.json",
            "probe-00.json".to_string(),
            &"00".repeat(32),
            10,
            CASE_CAP
        )
        .is_err());
        assert!(pin(
            &mut files,
            "probe-00.json",
            "probe-00.json".to_string(),
            &"00".repeat(32),
            CASE_CAP + 1,
            CASE_CAP
        )
        .is_err());
    }
}
