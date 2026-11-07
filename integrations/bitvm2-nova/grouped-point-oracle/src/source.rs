//! Independent compact source composition for the eleven mixed-role components.
//!
//! The caller MUST derive descriptors/facts from freshly validated actual
//! component bytes, including scalar_bits::check and conditional_point::check.
//! In particular the point's whole-word-map/program/source digests are checked
//! there before its one exposed bit interface is passed here. This internal
//! composition API does not accept imported execution-receipt authority.

#[path = "../../point-oracle/src/source.rs"]
pub mod legacy;
use crate::grouped_point::{CheckedPoint, Reference};
pub use legacy::{chain, ComponentDescriptor, ComponentFacts, Interface};

use bitcoin::hashes::{sha256, Hash};
use bitvm2_nova_script_oracle::wots::{id32, Result};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, HashSet};

const SOURCE_DOMAIN: &[u8] = b"BITVM2-NOVA/GROUPED-BYTE-C-BIT-POINT-SOURCE/v1\0";
const MAP_CAP: usize = 8 << 20;
const MANIFEST_CAP: usize = 1 << 20;
const BASE: u32 = 1 << 29;
pub const BIT_OCCURRENCES: [(usize, usize); 5] =
    [(3413, 0), (3415, 0), (3416, 0), (3417, 0), (3418, 0)];

pub struct CheckedSource {
    pub maps: Value,
    pub manifest: Value,
    pub source_sha256: String,
    pub source_maps_sha256: String,
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 192
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.:/-".contains(&b))
}
fn digest(value: &str) -> Result<()> {
    if hex::encode(id32(value)?) != value {
        return Err("canonical lowercase32 source digest required".into());
    }
    Ok(())
}
fn decimal(value: &str, high: usize) -> Result<usize> {
    let number: usize = value.parse()?;
    if number > high || number.to_string() != value {
        return Err("canonical bounded decimal identity required".into());
    }
    Ok(number)
}
pub fn point_role_for_scalar(role: &str) -> Result<&'static str> {
    match role {
        "pallas_scalar" => Ok("pallas_base"),
        "vesta_scalar" => Ok("vesta_base"),
        _ => Err("explicit scalar ROLE NAME required for point-curve dispatch".into()),
    }
}
fn curve_name(role: &str) -> Result<&'static str> {
    Ok(if point_role_for_scalar(role)? == "pallas_base" {
        "pallas"
    } else {
        "vesta"
    })
}
fn bit_id(index: usize) -> Result<String> {
    if index >= 255 {
        return Err("fixed bit index0..254 required".into());
    }
    Ok(format!("c/bits/bit/{index}"))
}
pub fn component_operation(operation: &str, bit_index: usize, index: usize) -> Result<String> {
    if !identifier(operation) || bit_index >= 255 || index >= 11 {
        return Err("bounded mixed-role operation/index required".into());
    }
    match index {
        9 => Ok(format!("{operation}/scalar-bits/bit/{bit_index}")),
        10 => Ok(format!("{operation}/point/bit/{bit_index}")),
        _ => Err("old chain operations derive from the nested chain source".into()),
    }
}

/// Apply only after the caller has checked the component's entire closed
/// topology. Private point names cannot be supplied as arbitrary source graphs.
pub fn global_id(index: usize, local: &str, scalar_role: &str, bit_index: usize) -> Result<String> {
    let curve = curve_name(scalar_role)?;
    if index >= 11 || bit_index >= 255 {
        return Err("mixed-role component/fixed-bit bound".into());
    }
    if index < 9 {
        return chain::global_id(index, local);
    }
    let result = if index == 9 {
        if let Some(tail) = local.strip_prefix("scalar/l") {
            format!("c/reduction/result/l{}", decimal(tail, 8)?)
        } else if let Some(tail) = local.strip_prefix("bit/") {
            bit_id(decimal(tail, 254)?)?
        } else {
            return Err("closed nine-limb/255-bit bridge names required".into());
        }
    } else {
        if !identifier(local) {
            return Err("checked point local identity required".into());
        }
        if local == "select/bit" {
            bit_id(bit_index)?
        } else {
            format!("point/{curve}/{local}")
        }
    };
    if !identifier(&result) {
        return Err("mixed-role global identity exceeds existing cap".into());
    }
    Ok(result)
}

pub fn validate_policy(
    context: &str,
    scalar_role: &str,
    rho_counter: u64,
    bit_index: usize,
    operation: &str,
) -> Result<()> {
    point_role_for_scalar(scalar_role)?;
    if bit_index >= 255 || !identifier(operation) {
        return Err("verifier-fixed bit and bounded outer operation required".into());
    }
    chain::validate_policy(
        context,
        scalar_role,
        rho_counter,
        &format!("{operation}/chain"),
    )?;
    let bits = component_operation(operation, bit_index, 9)?;
    let point = component_operation(operation, bit_index, 10)?;
    if !identifier(&bits) || !identifier(&point) || !identifier(&format!("{point}/complete-add")) {
        return Err("derived scalar/point child operation exceeds existing cap".into());
    }
    Ok(())
}

fn canonical(value: &Value) -> Result<Vec<u8>> {
    fn ordered(value: &Value, depth: usize) -> Result<Value> {
        if depth > 16 {
            return Err("mixed-role canonical JSON depth cap".into());
        }
        Ok(match value {
            Value::Object(object) => {
                let mut keys: Vec<_> = object.keys().collect();
                keys.sort_unstable();
                let mut out = Map::new();
                for key in keys {
                    if !key.is_ascii() {
                        return Err("ASCII source key required".into());
                    }
                    out.insert(key.clone(), ordered(&object[key], depth + 1)?);
                }
                Value::Object(out)
            }
            Value::Array(items) => Value::Array(
                items
                    .iter()
                    .map(|v| ordered(v, depth + 1))
                    .collect::<Result<_>>()?,
            ),
            Value::String(text) if !text.is_ascii() => {
                return Err("ASCII source string required".into())
            }
            Value::Number(n) if n.as_i64().is_none() && n.as_u64().is_none() => {
                return Err("source integer required".into())
            }
            other => other.clone(),
        })
    }
    Ok(serde_json::to_vec(&ordered(value, 0)?)?)
}
fn hash(value: &Value) -> Result<String> {
    Ok(sha256::Hash::hash(&canonical(value)?).to_string())
}

fn check_new_descriptor(
    d: &ComponentDescriptor,
    f: &ComponentFacts,
    index: usize,
    role: &str,
    counter: u64,
    bit_index: usize,
    operation: &str,
) -> Result<()> {
    let bits = index == 9;
    let name = if bits {
        "scalar-bits"
    } else {
        "conditional-point"
    };
    let expected_role = if bits {
        role
    } else {
        point_role_for_scalar(role)?
    };
    let shape = if bits { (264, 9) } else { (7498, 3457) };
    let identity = if bits {
        "Program.digest (fixed-trace/v2)"
    } else {
        "GroupedProgram.digest (grouped-convolution/v1)"
    };
    if d.index != index
        || d.branch != name
        || d.kind
            != if bits {
                "scalar-bits"
            } else {
                "grouped-conditional-point"
            }
        || d.field_role != expected_role
        || d.counter != counter + 1
        || d.operation_id != component_operation(operation, bit_index, index)?
        || (d.words, d.leaves) != shape
        || d.program_identity_kind != identity
        || f.index != index
        || f.branch != name
        || f.global_ids_sha256 != d.global_ids_sha256
        || !f.input_indices.is_empty()
        || !f.output_indices.is_empty()
        || !f.producer_ordinals.is_empty()
        || !f.producer_occurrences.is_empty()
    {
        return Err("closed scalar/base mixed-role child policy differs".into());
    }
    for value in [
        &d.program_sha256,
        &d.catalogue_id,
        &d.source_sha256,
        &d.source_maps_sha256,
        &d.global_ids_sha256,
    ] {
        digest(value)?;
    }
    if bits {
        if f.interfaces.len() != 264 {
            return Err("all264 actual scalar bridge word interfaces required".into());
        }
        let mut ids = Vec::new();
        for (word, row) in f.interfaces.iter().enumerate() {
            let (id, bound, occ) = if word < 9 {
                (format!("c/reduction/result/l{word}"), BASE, (word, 0))
            } else {
                let bit = word - 9;
                (
                    bit_id(bit)?,
                    2,
                    (bit / 29, (29 * (bit / 29 + 1)).min(255) - bit),
                )
            };
            if row.word_index != word
                || row.global_id != id
                || row.bound != bound
                || row.occurrences != [occ]
            {
                return Err("actual scalar limb/LSB bit/MSB predicate occurrence differs".into());
            }
            ids.push(id);
        }
        if hash(&json!(ids))? != f.global_ids_sha256 {
            return Err("actual264-word scalar map hash differs".into());
        }
    } else {
        let expected = Interface {
            word_index: 7476,
            global_id: bit_id(bit_index)?,
            bound: 2,
            occurrences: BIT_OCCURRENCES.to_vec(),
        };
        if f.interfaces != [expected] {
            return Err("only chosen bound2 bit may be exposed across point/scalar roles".into());
        }
    }
    Ok(())
}

fn new_joins(facts: &[ComponentFacts], bit_index: usize) -> Result<(Value, Value)> {
    let mut scalar_links = Vec::new();
    for i in 0..9 {
        let source = facts[8]
            .interfaces
            .iter()
            .find(|r| r.word_index == 129 + i)
            .ok_or("missing actual Uniform result interface")?;
        let target = &facts[9].interfaces[i];
        let id = format!("c/reduction/result/l{i}");
        if source.global_id != id
            || source.bound != BASE
            || source.occurrences != [(72 + i, 0), (244, i)]
            || target.global_id != id
            || target.bound != BASE
            || target.occurrences != [(i, 0)]
        {
            return Err("Uniform actual reconstruction/canonical guard must feed the same scalar bridge limb".into());
        }
        scalar_links.push(json!({"global_id":id,"source_component":8,"source_word":129+i,
            "source_ordinal":72+i,"source_occurrence":0,"canonical_ordinal":244,"canonical_occurrence":i,
            "target_component":9,"target_word":i,"target_ordinal":i,"target_occurrence":0}));
    }
    let ordinal = bit_index / 29;
    let width = if ordinal < 8 { 29 } else { 23 };
    let formal = width - bit_index % 29;
    let source = &facts[9].interfaces[9 + bit_index];
    let target = &facts[10].interfaces[0];
    if source.global_id != target.global_id
        || source.bound != 2
        || target.bound != 2
        || source.occurrences != [(ordinal, formal)]
        || target.occurrences != BIT_OCCURRENCES
    {
        return Err(
            "chosen scalar bit and allfive actual point consumers must share bound2".into(),
        );
    }
    Ok((
        json!(scalar_links),
        json!({"global_id":bit_id(bit_index)?,"source_component":9,"source_word":9+bit_index,
        "source_ordinal":ordinal,"source_occurrence":formal,"target_component":10,"target_word":7476,
        "target_occurrences":BIT_OCCURRENCES,"cross_role_bound":2}),
    ))
}

fn check_histogram(facts: &[ComponentFacts]) -> Result<()> {
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for component in facts {
        let mut unique = HashSet::new();
        for row in &component.interfaces {
            if !unique.insert(&row.global_id) {
                return Err("injective component interface IDs required".into());
            }
            *counts.entry(&row.global_id).or_default() += 1;
        }
    }
    if counts.values().filter(|n| **n == 2).count() != 528
        || counts.values().filter(|n| **n == 3).count() != 264
        || counts.values().any(|n| *n > 3)
        || counts.values().map(|n| n - 1).sum::<usize>() != 1056
    {
        return Err("mixed-role shared quotient must be528 doubles/264triples/1056reuses".into());
    }
    Ok(())
}

pub fn build(
    context: &str,
    scalar_role: &str,
    rho_counter: u64,
    bit_index: usize,
    outer_op: &str,
    descriptors: &[ComponentDescriptor],
    facts: &[ComponentFacts],
    reference: &Reference,
    point: &CheckedPoint,
) -> Result<CheckedSource> {
    validate_policy(context, scalar_role, rho_counter, bit_index, outer_op)?;
    if descriptors.len() != 11 || facts.len() != 11 {
        return Err("eleven exact fresh component descriptors/facts required".into());
    }
    let _nested = chain::build(
        context,
        scalar_role,
        rho_counter,
        &format!("{outer_op}/chain"),
        &descriptors[..9],
        &facts[..9],
    )?;
    for index in [9, 10] {
        check_new_descriptor(
            &descriptors[index],
            &facts[index],
            index,
            scalar_role,
            rho_counter,
            bit_index,
            outer_op,
        )?;
    }
    let mut programs = HashSet::new();
    let mut catalogues = HashSet::new();
    let mut sources = HashSet::new();
    for d in descriptors {
        if !programs.insert(&d.program_sha256)
            || !catalogues.insert(&d.catalogue_id)
            || !sources.insert(&d.source_sha256)
        {
            return Err(
                "distinct actual child source/program/catalogue identities required".into(),
            );
        }
    }
    check_histogram(facts)?;
    let (scalar_links, bit_link) = new_joins(facts, bit_index)?;

    let local: usize = descriptors.iter().map(|d| d.words).sum();
    let leaves: usize = descriptors.iter().map(|d| d.leaves).sum();
    if local != 156163
        || leaves != 150509
        || 147355 + 255 + 7497 != 155107
        || local - 1056 != 155107
    {
        return Err("closed eleven-component declaration census differs".into());
    }
    if reference.spec.context != context
        || reference.spec.field_role != point_role_for_scalar(scalar_role)?
        || reference.spec.operation_id != component_operation(outer_op, bit_index, 10)?
        || reference.checked.bit_index != bit_index
        || point.bit_index != bit_index
        || point.reference_sha256 != reference.sha256
        || point.program_sha256 != descriptors[10].program_sha256
        || point.catalogue_id != descriptors[10].catalogue_id
        || point.source_sha256 != descriptors[10].source_sha256
        || point.source_maps_sha256 != descriptors[10].source_maps_sha256
        || point.bit_occurrences != BIT_OCCURRENCES
    {
        return Err("grouped actual point admission and outer descriptor disagree".into());
    }
    // Rebuild the historical outer source under the SAME caller policy. These
    // are real old descriptors/facts from the independently admitted reference;
    // no grouped leaf is ever reheadered or fed to the old Registry.
    let mut old_descriptors = descriptors.to_vec();
    let d = &mut old_descriptors[10];
    d.kind = "conditional-point".into();
    d.program_sha256 = reference.checked.program_sha256.clone();
    d.catalogue_id = reference.checked.catalogue_id.clone();
    d.source_sha256 = reference.checked.source_sha256.clone();
    d.source_maps_sha256 = reference.checked.source_maps_sha256.clone();
    d.leaves = 6161;
    d.program_identity_kind = "ConvolutionProgram.digest (fixed-trace/v2)".into();
    let mut old_facts = facts.to_vec();
    old_facts[10].interfaces[0].occurrences = reference.checked.bit_occurrences.clone();
    let old = legacy::build(
        context,
        scalar_role,
        rho_counter,
        bit_index,
        outer_op,
        &old_descriptors,
        &old_facts,
    )?;
    let mut maps = old.maps.clone();
    let object = maps.as_object_mut().ok_or("legacy outer maps object")?;
    object.insert(
        "schema".into(),
        json!("bitvm2-nova-grouped-byte-c-bit-point-maps/v1"),
    );
    object.insert("components".into(), serde_json::to_value(descriptors)?);
    object.insert("leaves".into(), json!(150509));
    object.insert("legacy_source_sha256".into(), json!(old.source_sha256));
    object.insert(
        "legacy_source_maps_sha256".into(),
        json!(old.source_maps_sha256),
    );
    object.insert("point_grouping".into(), point.grouping.clone());
    object.insert("selected_bit_to_point".into(), bit_link);
    // Uniform-to-bit joins remain exact, including canonical guard244.
    if maps["scalar_to_bits"] != scalar_links {
        return Err("all nine canonical scalar reconstruction joins must remain exact".into());
    }
    let raw_maps = canonical(&maps)?;
    if raw_maps.len() > MAP_CAP {
        return Err("compact mixed-role maps exceed unchanged8MiB cap".into());
    }
    let maps_sha = sha256::Hash::hash(&raw_maps).to_string();
    let mut manifest = old.manifest;
    let object = manifest
        .as_object_mut()
        .ok_or("legacy outer manifest object")?;
    object.insert(
        "schema".into(),
        json!("bitvm2-nova-grouped-byte-c-bit-point-source/v1"),
    );
    object.insert("components".into(), serde_json::to_value(descriptors)?);
    object.insert("leaves".into(), json!(150509));
    object.insert("source_maps_sha256".into(), json!(maps_sha));
    object.insert("legacy_source_sha256".into(), json!(old.source_sha256));
    object.insert(
        "legacy_source_maps_sha256".into(),
        json!(old.source_maps_sha256),
    );
    object.insert("point_grouping".into(), point.grouping.clone());
    object.insert("scope".into(), json!("grouped one verifier-fixed challenge-bit conditional point relation; proof/key origins, scalar multiplication and IPA remain open"));
    let raw = canonical(&manifest)?;
    if raw.len() > MANIFEST_CAP {
        return Err("compact mixed-role source exceeds unchanged1MiB cap".into());
    }
    let mut committed = SOURCE_DOMAIN.to_vec();
    committed.extend_from_slice(&raw);
    Ok(CheckedSource {
        maps,
        manifest,
        source_sha256: sha256::Hash::hash(&committed).to_string(),
        source_maps_sha256: maps_sha,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty(index: usize, branch: &str) -> ComponentFacts {
        ComponentFacts {
            index,
            branch: branch.to_owned(),
            global_ids_sha256: "00".repeat(32),
            input_indices: vec![],
            output_indices: vec![],
            producer_ordinals: vec![],
            producer_occurrences: vec![],
            interfaces: vec![],
        }
    }
    fn row(word: usize, id: String, bound: u32, occurrences: Vec<(usize, usize)>) -> Interface {
        Interface {
            word_index: word,
            global_id: id,
            bound,
            occurrences,
        }
    }
    fn new_facts(bit_index: usize) -> Vec<ComponentFacts> {
        let mut out: Vec<_> = (0..11).map(|i| empty(i, "symbolic")).collect();
        for i in 0..9 {
            out[8].interfaces.push(row(
                129 + i,
                format!("c/reduction/result/l{i}"),
                BASE,
                vec![(72 + i, 0), (244, i)],
            ));
        }
        out[9].branch = "scalar-bits".to_owned();
        for word in 0..264 {
            let (id, bound, occ) = if word < 9 {
                (format!("c/reduction/result/l{word}"), BASE, (word, 0))
            } else {
                let bit = word - 9;
                (
                    bit_id(bit).unwrap(),
                    2,
                    (bit / 29, (29 * (bit / 29 + 1)).min(255) - bit),
                )
            };
            out[9].interfaces.push(row(word, id, bound, vec![occ]));
        }
        out[9].global_ids_sha256 = hash(&json!(out[9]
            .interfaces
            .iter()
            .map(|r| &r.global_id)
            .collect::<Vec<_>>()))
        .unwrap();
        out[10].branch = "conditional-point".to_owned();
        out[10].interfaces.push(row(
            7476,
            bit_id(bit_index).unwrap(),
            2,
            BIT_OCCURRENCES.to_vec(),
        ));
        out
    }
    fn desc(index: usize, role: &str, bit_index: usize, global_hash: &str) -> ComponentDescriptor {
        let bits = index == 9;
        ComponentDescriptor {
            index,
            branch: if bits {
                "scalar-bits"
            } else {
                "conditional-point"
            }
            .to_owned(),
            kind: if bits {
                "scalar-bits"
            } else {
                "grouped-conditional-point"
            }
            .to_owned(),
            operation_id: component_operation("outer", bit_index, index).unwrap(),
            program_sha256: "11".repeat(32),
            catalogue_id: "22".repeat(32),
            source_sha256: "33".repeat(32),
            source_maps_sha256: "44".repeat(32),
            global_ids_sha256: global_hash.to_owned(),
            words: if bits { 264 } else { 7498 },
            leaves: if bits { 9 } else { 3457 },
            counter: 60,
            field_role: if bits {
                role
            } else {
                point_role_for_scalar(role).unwrap()
            }
            .to_owned(),
            program_identity_kind: if bits {
                "Program.digest (fixed-trace/v2)"
            } else {
                "GroupedProgram.digest (grouped-convolution/v1)"
            }
            .to_owned(),
        }
    }

    #[test]
    fn role_dispatch_is_by_name_and_only_the_chosen_bit_crosses_roles() {
        assert_eq!(
            point_role_for_scalar("pallas_scalar").unwrap(),
            "pallas_base"
        );
        assert_eq!(point_role_for_scalar("vesta_scalar").unwrap(), "vesta_base");
        for role in ["pallas_base", "vesta_base", "Pallas_scalar", "unknown"] {
            assert!(point_role_for_scalar(role).is_err());
        }
        for role in ["pallas_scalar", "vesta_scalar"] {
            assert_eq!(
                global_id(9, "bit/254", role, 254).unwrap(),
                global_id(10, "select/bit", role, 254).unwrap()
            );
            assert_ne!(
                global_id(10, "left/x/l0", role, 0).unwrap(),
                global_id(9, "scalar/l0", role, 0).unwrap()
            );
            let old = "byte-state/0/l0/byte1";
            assert_eq!(
                global_id(0, old, role, 0).unwrap(),
                chain::global_id(0, old).unwrap()
            );
        }
        assert_eq!(
            global_id(10, "selected/y/l8", "pallas_scalar", 0).unwrap(),
            "point/pallas/selected/y/l8"
        );
        assert_eq!(
            global_id(10, "selected/y/l8", "vesta_scalar", 0).unwrap(),
            "point/vesta/selected/y/l8"
        );
    }

    #[test]
    fn scalar_bridge_word_map_and_bit_endianness_are_closed() {
        let ids: Vec<_> = (0..9)
            .map(|i| global_id(9, &format!("scalar/l{i}"), "pallas_scalar", 0).unwrap())
            .chain((0..255).map(|i| global_id(9, &format!("bit/{i}"), "pallas_scalar", 0).unwrap()))
            .collect();
        assert_eq!(ids.len(), 264);
        assert_eq!(ids.iter().collect::<HashSet<_>>().len(), 264);
        for name in [
            "scalar/l9",
            "scalar/l00",
            "bit/255",
            "bit/00",
            "bit/-1",
            "other/0",
        ] {
            assert!(global_id(9, name, "pallas_scalar", 0).is_err());
        }
        for bit in [0, 28, 29, 231, 232, 254] {
            let facts = new_facts(bit);
            let (limbs, chosen) = new_joins(&facts, bit).unwrap();
            assert_eq!(limbs.as_array().unwrap().len(), 9);
            assert_eq!(chosen["source_ordinal"], json!(bit / 29));
            assert_eq!(
                chosen["source_occurrence"],
                json!((29 * (bit / 29 + 1)).min(255) - bit)
            );
            assert_eq!(chosen["target_occurrences"], json!(BIT_OCCURRENCES));
        }
    }

    #[test]
    fn all_derived_ids_and_counter_limits_are_checked_before_components() {
        let context = "00".repeat(32);
        validate_policy(&context, "pallas_scalar", 59, 0, "outer").unwrap();
        validate_policy(&context, "vesta_scalar", u64::MAX - 1, 254, "outer").unwrap();
        assert!(validate_policy(&context, "pallas_scalar", u64::MAX, 0, "outer").is_err());
        assert!(validate_policy(&context, "pallas_scalar", 59, 255, "outer").is_err());
        assert!(validate_policy(&context, "pallas_scalar", 59, 0, &"x".repeat(192)).is_err());
        assert!(validate_policy(&"AA".repeat(32), "pallas_scalar", 59, 0, "outer").is_err());
        assert!(legacy::build(&context, "pallas_scalar", 59, 0, "outer", &[], &[]).is_err());
        assert_eq!(
            component_operation("outer", 254, 9).unwrap(),
            "outer/scalar-bits/bit/254"
        );
        assert_eq!(
            component_operation("outer", 254, 10).unwrap(),
            "outer/point/bit/254"
        );
    }

    #[test]
    fn actual_canonical_guard_and_all_five_point_occurrences_are_required() {
        let facts = new_facts(0);
        let bits = desc(9, "pallas_scalar", 0, &facts[9].global_ids_sha256);
        let point = desc(10, "pallas_scalar", 0, &facts[10].global_ids_sha256);
        check_new_descriptor(&bits, &facts[9], 9, "pallas_scalar", 59, 0, "outer").unwrap();
        check_new_descriptor(&point, &facts[10], 10, "pallas_scalar", 59, 0, "outer").unwrap();
        let mut old_kind = point.clone();
        old_kind.kind = "conditional-point".into();
        assert!(
            check_new_descriptor(&old_kind, &facts[10], 10, "pallas_scalar", 59, 0, "outer")
                .is_err()
        );
        let mut old_identity = point.clone();
        old_identity.program_identity_kind = "ConvolutionProgram.digest (fixed-trace/v2)".into();
        assert!(check_new_descriptor(
            &old_identity,
            &facts[10],
            10,
            "pallas_scalar",
            59,
            0,
            "outer"
        )
        .is_err());
        let mut old_occurrences = facts.clone();
        old_occurrences[10].interfaces[0].occurrences = legacy::BIT_OCCURRENCES.to_vec();
        assert!(check_new_descriptor(
            &point,
            &old_occurrences[10],
            10,
            "pallas_scalar",
            59,
            0,
            "outer"
        )
        .is_err());
        let mut wrong = facts.clone();
        wrong[8].interfaces[0].occurrences[1] = (243, 0);
        assert!(new_joins(&wrong, 0).is_err());
        let mut wrong = facts.clone();
        wrong[10].interfaces[0].bound = 5;
        assert!(new_joins(&wrong, 0).is_err());
        let mut wrong = facts.clone();
        wrong[10].interfaces[0].occurrences.pop();
        assert!(
            check_new_descriptor(&point, &wrong[10], 10, "pallas_scalar", 59, 0, "outer").is_err()
        );
        let mut wrong = point.clone();
        wrong.field_role = "vesta_scalar".to_owned();
        assert!(
            check_new_descriptor(&wrong, &facts[10], 10, "pallas_scalar", 59, 0, "outer").is_err()
        );
        let mut wrong = facts.clone();
        wrong[9].interfaces[9].occurrences[0] = (0, 1);
        assert!(
            check_new_descriptor(&bits, &wrong[9], 9, "pallas_scalar", 59, 0, "outer").is_err()
        );
    }

    #[test]
    fn quotient_histogram_adds_only_nine_limbs_and_one_bit() {
        // Histogram-only symbolic interfaces; not complete component graphs.
        let mut facts: Vec<_> = (0..11).map(|i| empty(i, "symbolic")).collect();
        for i in 0..518 {
            for component in [0, 1] {
                facts[component]
                    .interfaces
                    .push(row(i, format!("double/{i}"), 2, vec![(0, 0)]));
            }
        }
        for i in 0..264 {
            for component in [0, 1, 2] {
                facts[component].interfaces.push(row(
                    i + 518,
                    format!("triple/{i}"),
                    2,
                    vec![(0, 0)],
                ));
            }
        }
        let new = new_facts(0);
        facts[8].interfaces = new[8].interfaces.clone();
        facts[9].interfaces = new[9].interfaces.clone();
        facts[10].interfaces = new[10].interfaces.clone();
        check_histogram(&facts).unwrap();
        facts[10]
            .interfaces
            .push(row(0, "triple/0".to_owned(), 2, vec![(0, 0)]));
        assert!(check_histogram(&facts).is_err());
    }

    #[test]
    fn canonical_source_json_rejects_nonascii_floats_and_deep_objects() {
        assert_eq!(
            canonical(&json!({"z":u64::MAX,"a":[0,254]})).unwrap(),
            b"{\"a\":[0,254],\"z\":18446744073709551615}"
        );
        assert!(canonical(&json!({"a":1.5})).is_err());
        assert!(canonical(&json!({"a":"\u{e9}"})).is_err());
        let mut value = json!(0);
        for _ in 0..18 {
            value = json!([value]);
        }
        assert!(canonical(&value).is_err());
    }
}
