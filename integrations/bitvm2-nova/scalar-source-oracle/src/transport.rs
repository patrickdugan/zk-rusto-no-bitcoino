//! Closed thirteen-component retained scalar-source transport.
//! Reference pins authenticate a native fixture, never the asserted BYTE block.
use crate::{
    chain::{self, Header},
    legacy_transport::{fixed_hex, FilePin, Group, Probe},
};
use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitvm2_nova_script_oracle::wots::Result;
use num_bigint::BigUint;
use serde::Deserialize;
use std::{
    collections::HashSet,
    fs,
    io::Read,
    path::{Path, PathBuf},
};

pub(crate) const SCHEMA: &str = "bitvm2-nova-retained-scalar-sources-run/v1";
pub(crate) const OPERATION: &str = "benchmark/retained-scalar-sources/v1";
const CONTEXT: &[u8] = b"BITVM2-NOVA/RETAINED-SCALAR-SOURCES-CONFORMANCE/v1";
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
pub(crate) struct SourceRun {
    pub(crate) schema: String,
    pub(crate) context: String,
    pub(crate) operation_id: String,
    pub(crate) reference_bundle_file: String,
    pub(crate) reference_bundle_sha256: String,
    pub(crate) reference_expected_file: String,
    pub(crate) reference_expected_sha256: String,
    pub(crate) reference_dimensions_file: String,
    pub(crate) reference_dimensions_sha256: String,
    pub(crate) cases: Vec<SourceGroup>,
    pub(crate) probes: Vec<Probe>,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SourceGroup {
    pub(crate) point: Group,
    pub(crate) block_component: Header,
    pub(crate) eval_w_component: Header,
    pub(crate) source_file: String,
    pub(crate) source_file_sha256: String,
    pub(crate) source_sha256: String,
    pub(crate) maps_file: String,
    pub(crate) maps_file_sha256: String,
    pub(crate) maps_sha256: String,
    pub(crate) asserted_block_hex: String,
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

fn validate_point(point: &Group, index: usize, out: &mut Vec<FilePin>) -> Result<()> {
    let prefix = if index < 3 { "p" } else { "v" };
    let (profile, suffix) = match index % 3 {
        0 => ("honest", "h"),
        1 => ("coherent-coefficient", "c"),
        _ => ("coherent-eval-w", "w"),
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
    if point.name != format!("{prefix}/{suffix}")
        || point.profile != profile
        || point.role != scalar
        || point.base_role != base
        || point.rho_counter != counter
        || point.c_counter != counter + 1
        || point.bit_index != 0
        || point.execution_mode
            != if profile == "honest" {
                "full"
            } else {
                "targeted"
            }
        || point.components.len() != 11
        || point.selected_bit > 1
        || point.canonical_bit > 1
    {
        return Err("closed ordered main profile differs".into());
    }
    for hash in [
        &point.source_sha256,
        &point.source_maps_sha256,
        &point.chain_source_sha256,
        &point.chain_source_maps_sha256,
    ] {
        fixed_hex::<32>(hash)?;
    }
    if point.point_maps_file_sha256 != point.source_maps_sha256
        || point.chain_maps_file_sha256 != point.chain_source_maps_sha256
    {
        return Err("outer raw map pin must equal canonical source-map hash".into());
    }
    fixed_hex::<32>(&point.eval_w_le)?;
    fixed_hex::<64>(&point.prior_state_hex)?;
    for raw in &point.compressed_coefficients_le {
        fixed_hex::<32>(raw)?;
    }
    for raw in [
        &point.expected_rho_hi_output_state_hex,
        &point.expected_rho_lo_output_state_hex,
        &point.expected_prefix_output_state_hex,
        &point.expected_c_hi_output_state_hex,
        &point.expected_c_lo_output_state_hex,
    ] {
        fixed_hex::<200>(raw)?;
    }
    fixed_hex::<64>(&point.expected_rho_raw_state_le)?;
    fixed_hex::<32>(&point.expected_rho_result_le)?;
    fixed_hex::<33>(&point.expected_rho_quotient_le)?;
    let c = fixed_hex::<32>(&point.expected_c_result_le)?;
    let q = fixed_hex::<33>(&point.expected_c_quotient_le)?;
    let raw = fixed_hex::<64>(&point.expected_c_raw_state_le)?;
    let asserted = fixed_hex::<32>(&point.asserted_scalar_le)?;
    let asserted_q = fixed_hex::<33>(&point.asserted_scalar_quotient_le)?;
    if point.canonical_bit != u32::from(c[0] & 1) {
        return Err("canonical selected bit detached from retained c".into());
    }
    if asserted != c || asserted_q != q || point.selected_bit != point.canonical_bit {
        return Err("canonical claimed scalar and reconstructed bit required".into());
    }
    for point in [
        &point.point_A,
        &point.point_P,
        &point.expected_E,
        &point.expected_R,
    ] {
        point.validate(base)?;
    }
    if point.expected_R
        != if point.selected_bit == 0 {
            point.point_A.clone()
        } else {
            point.expected_E.clone()
        }
    {
        return Err("coherent selected R differs from actual asserted bit".into());
    }
    let stem = format!("{index:02}");
    pin(
        out,
        &point.point_source_filename,
        format!("point-source-{stem}.json"),
        &point.point_source_file_sha256,
        point.point_source_file_bytes,
        SMALL_CAP,
    )?;
    pin(
        out,
        &point.point_maps_filename,
        format!("point-maps-{stem}.json"),
        &point.point_maps_file_sha256,
        point.point_maps_file_bytes,
        MAP_CAP,
    )?;
    pin(
        out,
        &point.chain_source_filename,
        format!("chain-source-{stem}.json"),
        &point.chain_source_file_sha256,
        point.chain_source_file_bytes,
        SMALL_CAP,
    )?;
    pin(
        out,
        &point.chain_maps_filename,
        format!("chain-maps-{stem}.json"),
        &point.chain_maps_file_sha256,
        point.chain_maps_file_bytes,
        MAP_CAP,
    )?;
    let mut selected_large = 0;
    for (component, header) in point.components.iter().enumerate() {
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
        let expected_false: Vec<usize> = vec![];
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

fn validate_raw_point(
    point: &crate::legacy_transport::PointValue,
    role: &str,
    invalid_flag: bool,
    noncanonical_x: bool,
    nonzero_infinity: bool,
) -> Result<()> {
    let (x, y) = point.coordinates()?;
    let p = modulus(role)?;
    if point.infinity > if invalid_flag { 2 } else { 1 }
        || (!noncanonical_x && BigUint::from_bytes_le(&x) >= p)
        || BigUint::from_bytes_le(&y) >= p
        || (!nonzero_infinity && point.infinity == 1 && (x != [0; 32] || y != [0; 32]))
    {
        return Err("closed point diagnostic encoding differs".into());
    }
    Ok(())
}
fn validate_legacy_probe(
    probe: &Probe,
    index: usize,
    honest: &Group,
    out: &mut Vec<FilePin>,
) -> Result<()> {
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
    if probe.name != name
        || probe.kind != kind
        || probe.category != category
        || probe.role != honest.role
        || probe.field_role != *role
        || probe.source_case != honest.name
        || probe.source_component != component
        || probe.words != words
        || probe.leaves != leaves
        || probe.selected_leaf >= leaves
        || !sorted_ordinals(&probe.expected_false, leaves)
        || !sorted_ordinals(&probe.expected_abort_ordinals, leaves)
        || probe
            .expected_false
            .iter()
            .any(|i| probe.expected_abort_ordinals.contains(i))
    {
        return Err("closed ordered private probe profile differs".into());
    }
    for hash in [
        &probe.source_sha256,
        &probe.source_maps_sha256,
        &probe.catalogue_id,
        &probe.program_sha256,
    ] {
        fixed_hex::<32>(hash)?;
    }
    let selected = if category == "chain" || category == "scalar-alias" {
        if probe.execution_mode != "all" || probe.selected_ordinals.is_some() {
            return Err("complete small probe selection differs".into());
        }
        (0..leaves).collect::<Vec<_>>()
    } else {
        let value = probe
            .selected_ordinals
            .as_ref()
            .ok_or("point probe selection missing")?;
        if probe.execution_mode != "selected"
            || value.is_empty()
            || !sorted_ordinals(value, leaves)
            || value.len() > if category == "point-edge" { 128 } else { 12 }
        {
            return Err("private point selection exceeds closed reserve".into());
        }
        value.clone()
    };
    if !selected.contains(&probe.selected_leaf)
        || selected
            .iter()
            .any(|i| probe.expected_abort_ordinals.contains(i))
        || probe.expected_selected_correct == probe.expected_false.contains(&probe.selected_leaf)
    {
        return Err("selected actual probe verdict/abort domain differs".into());
    }
    match category {
        "chain" => {
            if !probe
                .inputs
                .as_object()
                .is_some_and(|value| value.is_empty())
            {
                return Err("frame/absorb inputs must be empty".into());
            }
            let false_leaf = [109, 110, 37, 33, 32, 45, 0, 8, 6, 7][local];
            if probe.expected_false != [false_leaf]
                || probe.selected_leaf != false_leaf
                || !probe.expected_abort_ordinals.is_empty()
            {
                return Err("old probe closed false inventory differs".into());
            }
        }
        "scalar-alias" => {
            if probe.scalar_input()? != fixed_hex::<64>(&honest.expected_c_raw_state_le)?
                || probe.expected_false != [253]
                || probe.selected_leaf != 253
                || !probe.expected_abort_ordinals.is_empty()
            {
                return Err("closed merged alias fixture differs".into());
            }
        }
        _ => {
            let inputs = probe.point_inputs()?;
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
            validate_raw_point(
                &inputs.point_R,
                &honest.base_role,
                kind == "wrong-R-flag",
                kind.starts_with("coordinate-modulus"),
                kind == "nonzero-infinity",
            )?;
            if kind == "wrong-R-flag" && inputs.point_R.infinity != 2 {
                return Err("closed signed R flag must be2".into());
            }
            if category == "point-edge" {
                if !probe.expected_false.is_empty()
                    || !probe.expected_abort_ordinals.is_empty()
                    || probe.selected_leaf != 6123
                {
                    return Err("honest point edge cannot contain a false/abort predicate".into());
                }
            } else if probe.expected_selected_correct {
                return Err("negative probe requires actual selected disproof".into());
            }
        }
    }
    if let Some(component) = component {
        let d = &honest.components[component].descriptor;
        if probe.operation_id != d.operation_id
            || probe.source_sha256 != d.source_sha256
            || probe.source_maps_sha256 != d.source_maps_sha256
            || probe.catalogue_id != d.catalogue_id
            || probe.program_sha256 != d.program_sha256
        {
            return Err("private source must retain positive source identity".into());
        }
    } else if probe.operation_id != format!("{OPERATION}/point/probe/scalar-alias/{prefix}") {
        return Err("private scalar alias operation differs".into());
    }
    pin(
        out,
        &probe.filename,
        format!("probe-{index:02}.json"),
        &probe.file_sha256,
        probe.file_bytes,
        CASE_CAP,
    )
}

impl SourceGroup {
    pub(crate) fn point_group(&self) -> Group {
        self.point.clone()
    }
    pub(crate) fn headers(&self) -> Vec<Header> {
        let mut headers = self.point.components.clone();
        headers.push(self.block_component.clone());
        headers.push(self.eval_w_component.clone());
        headers
    }
    fn validate(&self, index: usize, out: &mut Vec<FilePin>) -> Result<()> {
        validate_point(&self.point, index, out)?;
        for hash in [
            &self.source_sha256,
            &self.maps_sha256,
            &self.source_file_sha256,
            &self.maps_file_sha256,
        ] {
            fixed_hex::<32>(hash)?;
        }
        if self.maps_file_sha256 != self.maps_sha256 {
            return Err("outer maps must retain canonical raw digest".into());
        }
        let raw = fixed_hex::<112>(&self.asserted_block_hex)?;
        let rows: u64 = if self.point.role == "pallas_scalar" {
            19
        } else {
            14
        };
        if raw[..32] != fixed_hex::<32>(&self.point.eval_w_le)?
            || raw[32..40] != rows.to_le_bytes()
            || raw[40..48] != 2u64.to_le_bytes()
            || raw[48..80] != fixed_hex::<32>(&self.point.compressed_coefficients_le[0])?
            || raw[80..112] != fixed_hex::<32>(&self.point.compressed_coefficients_le[1])?
        {
            return Err(
                "claimed scalar block differs from canonical consumer inputs/counts".into(),
            );
        }
        let stem = format!("{index:02}");
        for (name, expected, hash, cap) in [
            (
                &self.source_file,
                format!("scalar-source-{stem}.json"),
                &self.source_file_sha256,
                SMALL_CAP,
            ),
            (
                &self.maps_file,
                format!("scalar-maps-{stem}.json"),
                &self.maps_file_sha256,
                MAP_CAP,
            ),
        ] {
            pin_unmeasured(out, name, expected, hash, cap)?;
        }
        for (i, h, branch, words, leaves) in [
            (11, &self.block_component, "retained-scalar-block", 112, 112),
            (12, &self.eval_w_component, "eval-w-encoding", 55, 17),
        ] {
            let d = &h.descriptor;
            if d.index != i
                || d.branch != branch
                || d.kind != branch
                || d.words != words
                || d.leaves != leaves
                || d.field_role != self.point.role
                || d.counter != self.point.rho_counter
                || !h.expected_false.is_empty()
                || !h.expected_abort_ordinals.is_empty()
                || h.execution_mode != "all"
                || h.selected_ordinals.is_some()
                || h.full.is_some()
                || h.program_manifest_filename.is_some()
                || h.program_manifest_file_sha256.is_some()
                || h.program_manifest_file_bytes.is_some()
            {
                return Err("closed scalar source component shape/selection differs".into());
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
            if h.maps_file_sha256 != d.source_maps_sha256 {
                return Err("new component canonical map digest differs".into());
            }
            let local = format!("{stem}-{i}");
            pin(
                out,
                &h.filename,
                format!("case-{local}.json"),
                &h.file_sha256,
                h.file_bytes,
                CASE_CAP,
            )?;
            pin(
                out,
                &h.maps_filename,
                format!("maps-{local}.json"),
                &h.maps_file_sha256,
                h.maps_file_bytes,
                MAP_CAP,
            )?;
            pin(
                out,
                &h.source_manifest_filename,
                format!("source-{local}.json"),
                &h.source_manifest_file_sha256,
                h.source_manifest_file_bytes,
                SMALL_CAP,
            )?;
        }
        Ok(())
    }
}
fn pin_unmeasured(
    out: &mut Vec<FilePin>,
    name: &str,
    expected: String,
    hash: &str,
    cap: u64,
) -> Result<()> {
    fixed_hex::<32>(hash)?;
    if name != expected || cap == 0 {
        return Err("closed variable-size file pin differs".into());
    }
    out.push(FilePin {
        filename: expected,
        sha256: hash.to_string(),
        bytes: 0,
        cap,
    });
    Ok(())
}

fn validate_new_probe(
    p: &Probe,
    index: usize,
    honest: &SourceGroup,
    out: &mut Vec<FilePin>,
) -> Result<()> {
    const U: [&str; 7] = [
        "eval-w-modulus",
        "eval-w-modulus-plus-one",
        "eval-w-bit255",
        "eval-w-byte-only",
        "eval-w-limb-only",
        "eval-w-split-only",
        "eval-w-byte-u32-max",
    ];
    const T: [&str; 4] = [
        "scalar-block-batch-count-low",
        "scalar-block-coefficient-count-low",
        "scalar-block-batch-count-high",
        "scalar-block-byte-256",
    ];
    let local = (index - 52) % 11;
    let encoding = local < 7;
    let sub = if encoding { local } else { local - 7 };
    let point = &honest.point;
    let prefix = if index < 63 { "p" } else { "v" };
    let component = if encoding { 12 } else { 11 };
    let h = if encoding {
        &honest.eval_w_component
    } else {
        &honest.block_component
    };
    let d = &h.descriptor;
    let category = if encoding {
        "eval-w-encoding"
    } else {
        "scalar-block"
    };
    let name = format!("{prefix}/{}{sub}", if encoding { "u" } else { "t" });
    let kind = if encoding { U[sub] } else { T[sub] };
    if p.name != name
        || p.kind != kind
        || p.category != category
        || p.role != point.role
        || p.field_role != point.role
        || p.source_case != point.name
        || p.source_component != Some(component)
        || p.words != d.words
        || p.leaves != d.leaves
        || p.operation_id != d.operation_id
        || p.source_sha256 != d.source_sha256
        || p.source_maps_sha256 != d.source_maps_sha256
        || p.catalogue_id != d.catalogue_id
        || p.program_sha256 != d.program_sha256
        || !p.inputs.as_object().is_some_and(|v| v.is_empty())
        || !p.expected_abort_ordinals.is_empty()
        || p.expected_selected_correct
        || !sorted_ordinals(&p.expected_false, p.leaves)
        || p.expected_false.is_empty()
        || p.selected_leaf >= p.leaves
        || !p.expected_false.contains(&p.selected_leaf)
    {
        return Err("closed new source probe identity/verdict differs".into());
    }
    if encoding {
        if p.execution_mode != "all" || p.selected_ordinals.is_some() {
            return Err("all17 encoder probes required".into());
        }
    } else {
        let selected = [0, 8, 7, 16][sub];
        if p.execution_mode != "selected"
            || p.selected_ordinals.as_deref() != Some(&[selected])
            || p.expected_false != [selected]
            || p.selected_leaf != selected
        {
            return Err("exact one-leaf tape diagnostic required".into());
        }
    }
    pin(
        out,
        &p.filename,
        format!("probe-{index:02}.json"),
        &p.file_sha256,
        p.file_bytes,
        CASE_CAP,
    )
}
impl SourceRun {
    pub(crate) fn point_run(&self) -> crate::Run {
        crate::Run {
            schema: crate::legacy_transport::SCHEMA.into(),
            context: self.context.clone(),
            operation_id: format!("{}/point", self.operation_id),
            cases: self.cases.iter().map(SourceGroup::point_group).collect(),
            probes: self.probes.clone(),
        }
    }
    pub(crate) fn reference_path(&self, root: &Path) -> Result<PathBuf> {
        if self.reference_bundle_file != "reference.nht4" {
            return Err("fixed native reference filename required".into());
        }
        Ok(root.join(&self.reference_bundle_file))
    }
    pub(crate) fn validate(&self) -> Result<Vec<FilePin>> {
        if self.schema != SCHEMA
            || self.operation_id != OPERATION
            || self.context != sha256::Hash::hash(CONTEXT).to_string()
            || self.cases.len() != 6
            || self.probes.len() != 74
        {
            return Err("closed retained source schema/context/corpus differs".into());
        }
        let mut out = Vec::with_capacity(377);
        for (i, g) in self.cases.iter().enumerate() {
            g.validate(i, &mut out)?;
        }
        for (i, p) in self.probes.iter().enumerate() {
            if i < 52 {
                validate_legacy_probe(
                    p,
                    i,
                    &self.cases[if i < 26 { 0 } else { 3 }].point,
                    &mut out,
                )?;
            } else {
                validate_new_probe(p, i, &self.cases[if i < 63 { 0 } else { 3 }], &mut out)?;
            }
        }
        use crate::retained_scalar_block as r;
        for (name, expected, hash, pinned, bytes) in [
            (
                &self.reference_bundle_file,
                "reference.nht4",
                &self.reference_bundle_sha256,
                r::BUNDLE_SHA256,
                13220,
            ),
            (
                &self.reference_expected_file,
                "reference-expected.json",
                &self.reference_expected_sha256,
                r::POLICY_SHA256,
                0,
            ),
            (
                &self.reference_dimensions_file,
                "reference-dimensions.json",
                &self.reference_dimensions_sha256,
                r::DIMENSIONS_SHA256,
                808,
            ),
        ] {
            if hash != pinned {
                return Err("fixed independently pinned reference digest required".into());
            }
            if bytes == 0 {
                pin_unmeasured(&mut out, name, expected.into(), hash, SMALL_CAP)?;
            } else {
                pin(&mut out, name, expected.into(), hash, bytes, SMALL_CAP)?;
            }
        }
        let names = out.iter().map(|p| &p.filename).collect::<HashSet<_>>();
        if out.len() != 377 || names.len() != 377 {
            return Err("closed377 payload inventory required".into());
        }
        Ok(out)
    }
    pub(crate) fn validate_directory(&self, directory: &Path) -> Result<()> {
        let mut files = self.validate()?;
        let metadata = fs::symlink_metadata(directory)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err("owned regular fixture directory required".into());
        }
        let mut expected = files
            .iter()
            .map(|p| p.filename.clone())
            .collect::<HashSet<_>>();
        expected.insert("manifest.json".into());
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
        if actual != expected || actual.len() != 378 {
            return Err("exact378-file fixture inventory required".into());
        }
        for pin in &mut files {
            let path = directory.join(&pin.filename);
            let metadata = fs::symlink_metadata(&path)?;
            if !metadata.is_file()
                || metadata.file_type().is_symlink()
                || metadata.len() == 0
                || metadata.len() > pin.cap
            {
                return Err("pinned payload type/size changed".into());
            }
            // Variable-size JSON sidecars have no caller size receipt. Fix their actual
            // bounded size here, then require EOF and the independently transported SHA.
            if pin.bytes == 0 {
                pin.bytes = metadata.len();
            }
            if metadata.len() != pin.bytes {
                return Err("pinned payload length differs".into());
            }
            let mut file = fs::File::open(path)?;
            let mut engine = sha256::Hash::engine();
            let mut total = 0u64;
            let mut buffer = [0; 16384];
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
                return Err("payload SHA/EOF changed before native admission".into());
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn source_run_rejects_unknown_duplicate_and_empty_corpus() {
        let minimal = serde_json::json!({"schema":SCHEMA,"context":sha256::Hash::hash(CONTEXT).to_string(),"operation_id":OPERATION,
   "reference_bundle_file":"reference.nht4","reference_bundle_sha256":crate::retained_scalar_block::BUNDLE_SHA256,
   "reference_expected_file":"reference-expected.json","reference_expected_sha256":crate::retained_scalar_block::POLICY_SHA256,
   "reference_dimensions_file":"reference-dimensions.json","reference_dimensions_sha256":crate::retained_scalar_block::DIMENSIONS_SHA256,"cases":[],"probes":[]});
        let run: SourceRun = serde_json::from_value(minimal.clone()).unwrap();
        assert!(run.validate().is_err());
        let mut extra = minimal.clone();
        extra["caller_offsets"] = serde_json::json!([4624]);
        assert!(serde_json::from_value::<SourceRun>(extra).is_err());
        let raw = serde_json::to_string(&minimal).unwrap();
        let duplicate = format!("{{\"schema\":\"duplicate\",{}", &raw[1..]);
        assert!(serde_json::from_str::<SourceRun>(&duplicate).is_err());
    }
    #[test]
    fn variable_size_pins_still_require_closed_paths_and_hashes() {
        let mut out = vec![];
        let hash = "00".repeat(32);
        pin_unmeasured(
            &mut out,
            "scalar-source-00.json",
            "scalar-source-00.json".into(),
            &hash,
            SMALL_CAP,
        )
        .unwrap();
        assert_eq!(out[0].bytes, 0);
        assert_eq!(out[0].cap, SMALL_CAP);
        assert!(pin_unmeasured(
            &mut out,
            "../scalar-source-00.json",
            "scalar-source-00.json".into(),
            &hash,
            SMALL_CAP
        )
        .is_err());
        assert!(pin_unmeasured(
            &mut out,
            "scalar-source-00.json",
            "scalar-source-00.json".into(),
            "00",
            SMALL_CAP
        )
        .is_err());
    }
}
