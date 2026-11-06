//! Independent coefficient/frame source check using a freshly checked Uniform
//! projection. No keys, Scripts, imported verdicts or proof acceptance live here.
use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitvm2_nova_script_oracle::{
    registry::{GraphSpec, Leaf},
    wots::{id32, Result},
};
use serde_json::{json, Map, Value};
use std::collections::HashSet;

const BASE: u32 = 1 << 29;
const DEGREES: [usize; 2] = [0, 2];
const CROSSINGS: [(usize, usize); 7] =
    [(3, 5), (7, 2), (10, 7), (14, 4), (18, 1), (21, 6), (25, 3)];
const DOMAIN: &[u8] = b"BITVM2-NOVA/BYTE-SUMCHECK-FRAME/v1\0";

#[derive(Clone)]
pub struct OpeningLink {
    pub kind: String,
    pub word_index: usize,
    pub source_ordinal: usize,
    pub source_occurrence: usize,
    pub target_ordinal: usize,
    pub target_occurrence: usize,
}
impl OpeningLink {
    fn json(&self) -> Value {
        json!({"kind":self.kind,"word_index":self.word_index,
            "source_ordinal":self.source_ordinal,"source_occurrence":self.source_occurrence,
            "target_ordinal":self.target_ordinal,"target_occurrence":self.target_occurrence})
    }
}

#[derive(Clone)]
pub struct FrameAnchor {
    pub byte_index: usize,
    pub expected: u32,
    pub word: String,
    pub word_index: usize,
    pub anchor_ordinal: usize,
}
impl FrameAnchor {
    fn json(&self) -> Value {
        json!({"byte_index":self.byte_index,"expected":self.expected,"word":self.word,
            "anchor_ordinal":self.anchor_ordinal,"word_index":self.word_index})
    }
}

pub struct CheckedFrame {
    pub source_maps: Value,
    pub metadata: Value,
    pub source_sha256: String,
    pub source_maps_sha256: String,
    pub program_sha256: String,
    pub coefficient_byte_indices: Vec<Vec<usize>>,
    pub coefficient_field_indices: Vec<Vec<usize>>,
    pub byte_opening_occurrences: Vec<Vec<(usize, usize)>>,
    pub canonical_internal_links: Vec<OpeningLink>,
    pub frame_anchors: Vec<FrameAnchor>,
    pub canonical_field_leaves: [usize; 2],
}

fn modulus(role: &str) -> Result<([u8; 32], &'static str)> {
    let (le, decimal) = match role {
        "pallas_scalar" => (
            "0100000021eb468cdda89409fc98462200000000000000000000000000000040",
            "28948022309329048855892746252171976963363056481941647379679742748393362948097",
        ),
        "vesta_scalar" => (
            "01000000ed302d991bf94c09fc98462200000000000000000000000000000040",
            "28948022309329048855892746252171976963363056481941560715954676764349967630337",
        ),
        _ => return Err("coefficient/frame requires a Pasta scalar role".into()),
    };
    Ok((
        hex::decode(le)?
            .try_into()
            .map_err(|_| "scalar modulus size")?,
        decimal,
    ))
}

fn canonical(value: &Value) -> Result<Vec<u8>> {
    fn ordered(value: &Value, depth: usize) -> Result<Value> {
        if depth > 16 {
            return Err("frame metadata nesting bound".into());
        }
        Ok(match value {
            Value::Object(object) => {
                let mut keys: Vec<_> = object.keys().collect();
                keys.sort_unstable();
                let mut result = Map::new();
                for key in keys {
                    if !key.is_ascii() {
                        return Err("frame metadata ASCII key".into());
                    }
                    result.insert(
                        key.clone(),
                        ordered(object.get(key).ok_or("metadata key")?, depth + 1)?,
                    );
                }
                Value::Object(result)
            }
            Value::Array(values) => Value::Array(
                values
                    .iter()
                    .map(|v| ordered(v, depth + 1))
                    .collect::<Result<_>>()?,
            ),
            Value::String(text) if !text.is_ascii() => {
                return Err("frame metadata ASCII string".into())
            }
            Value::Number(number) if number.as_i64().is_none() && number.as_u64().is_none() => {
                return Err("frame metadata integer".into())
            }
            _ => value.clone(),
        })
    }
    Ok(serde_json::to_vec(&ordered(value, 0)?)?)
}

fn hash(value: &Value) -> Result<String> {
    Ok(sha256::Hash::hash(&canonical(value)?).to_string())
}

fn names(spec: &GraphSpec, indices: &[usize]) -> Result<Vec<String>> {
    indices
        .iter()
        .map(|slot| {
            spec.words
                .get(*slot)
                .map(|word| word.name.clone())
                .ok_or_else(|| "frame name index".into())
        })
        .collect()
}

fn program_digest(
    spec: &GraphSpec,
    arithmetic: usize,
    fields: &[(String, Vec<usize>)],
) -> Result<String> {
    let (_, decimal) = modulus(&spec.field_role)?;
    let mut constraints = Vec::new();
    for leaf in spec
        .leaves
        .get(..arithmetic)
        .ok_or("Program constraint prefix")?
    {
        constraints.push(json!([leaf.kind, names(spec, &leaf.wires)?, leaf.argument]));
    }
    let field_values = fields
        .iter()
        .map(|(name, wires)| Ok(json!([name, names(spec, wires)?])))
        .collect::<Result<Vec<_>>>()?;
    hash(
        &json!({"schema":"bitvm2-nova-fixed-trace/v2","field_role":spec.field_role,
        "modulus":decimal,"operation_id":spec.operation_id,"context":spec.context,
        "words":spec.words.iter().map(|word|json!([word.name,word.bound])).collect::<Vec<_>>(),
        "fields":field_values,"constraints":constraints}),
    )
}

fn fixed_prefix(counter: u64) -> Vec<(usize, u32)> {
    let mut state = [0u8; 200];
    state[0] = b'p';
    state[65..69].copy_from_slice(b"NoDS");
    state[69..77].copy_from_slice(&counter.to_le_bytes());
    std::iter::once(0)
        .chain(65..77)
        .chain(136..200)
        .map(|i| (i, u32::from(state[i])))
        .collect()
}

fn same_projection(
    actual: &GraphSpec,
    ordinal: usize,
    original: &GraphSpec,
    original_ordinal: usize,
    map: &[usize],
) -> Result<()> {
    let a = actual.leaves.get(ordinal).ok_or("frame projected leaf")?;
    let b = original
        .leaves
        .get(original_ordinal)
        .ok_or("reference encoding leaf")?;
    let wires = b
        .wires
        .iter()
        .map(|slot| {
            map.get(*slot)
                .copied()
                .ok_or_else(|| "reference wire map".into())
        })
        .collect::<Result<Vec<_>>>()?;
    if a.kind != b.kind
        || a.argument != b.argument
        || a.wires != wires
        || a.body_sha256 != b.body_sha256
        || actual.bodies.get(&a.body_sha256) != original.bodies.get(&b.body_sha256)
    {
        return Err("frame encoding body/alias/bound projection differs".into());
    }
    Ok(())
}

/// `uniform_reference` is an actual 379-word/245-leaf projection obtained by
/// the worker from its freshly independently checked old-RHO tail. The worker
/// rebinds its operation and Program digest; it never supplies an ID receipt.
pub fn check(
    spec: &GraphSpec,
    context: &str,
    role: &str,
    counter: u64,
    operation_id: &str,
    raw_maps: &Value,
    uniform_reference: &GraphSpec,
) -> Result<CheckedFrame> {
    modulus(role)?;
    id32(context)?;
    if context
        .bytes()
        .any(|b| !b.is_ascii_digit() && !(b'a'..=b'f').contains(&b))
        || spec.context != context
        || spec.field_role != role
        || spec.operation_id != operation_id
        || spec.words.len() != 187
        || spec.leaves.len() != 111
    {
        return Err("frame context/role/operation/census differs".into());
    }
    spec.identity()?;
    let reference_op = format!("{operation_id}/uniform-reference");
    if uniform_reference.context != context
        || uniform_reference.field_role != role
        || uniform_reference.operation_id != reference_op
        || uniform_reference.words.len() != 379
        || uniform_reference.leaves.len() != 245
    {
        return Err("fresh actual Uniform reference scope differs".into());
    }
    let reference_fields: Vec<usize> = (129..138).collect();
    let field_leaf = &uniform_reference.leaves[244];
    if field_leaf.kind != "field_valid"
        || !field_leaf.argument.is_empty()
        || field_leaf.wires != reference_fields
    {
        return Err("Uniform reference canonical field differs".into());
    }
    let reference_program = program_digest(
        uniform_reference,
        244,
        &[("result".into(), reference_fields)],
    )?;
    if uniform_reference.program_sha256 != reference_program {
        return Err("Uniform reference actual fixed-trace/v2 digest differs".into());
    }
    let reference_catalogue = hex::encode(uniform_reference.identity()?);
    // Assert exact expected names/bounds in the reusable encoding declaration.
    let mut expected_words = (0..9)
        .map(|i| (format!("result/l{i}"), BASE))
        .collect::<Vec<_>>();
    expected_words.extend((0..32).map(|i| (format!("result/encoding/byte/{i}"), 256)));
    for (byte, width) in CROSSINGS {
        expected_words.push((format!("result/encoding/split/{byte}/lo"), 1 << width));
        expected_words.push((format!("result/encoding/split/{byte}/hi"), 1 << (8 - width)));
    }
    for (slot, (name, bound)) in expected_words.iter().enumerate() {
        let word = &uniform_reference.words[129 + slot];
        if word.name != *name || word.bound != *bound {
            return Err("Uniform reference scalar encoding declaration differs".into());
        }
    }
    let uniform_word_map: Vec<_> = (129..184).collect();
    let mut uniform_leaf_map: Vec<_> = (65..81).collect();
    uniform_leaf_map.push(244);
    let mut children = Vec::new();
    let mut ports_fields = Vec::new();
    let mut ports_bytes = Vec::new();
    let mut ports_aux = Vec::new();
    let mut all_bytes = Vec::new();
    let mut all_fields = Vec::new();
    let mut byte_openings = Vec::new();
    let mut links = Vec::new();
    for (child, degree) in DEGREES.iter().enumerate() {
        let prefix = format!("coefficient/{degree}/");
        let base = 55 * child;
        let arithmetic = 16 * child;
        let word_map: Vec<_> = (base..base + 55).collect();
        let mut leaf_map: Vec<_> = (arithmetic..arithmetic + 16).collect();
        leaf_map.push(109 + child);
        for (local, (name, bound)) in expected_words.iter().enumerate() {
            let actual = &spec.words[base + local];
            if actual.name != format!("{prefix}{name}") || actual.bound != *bound {
                return Err("coefficient degree/declaration/order/bound differs".into());
            }
        }
        let mut reference_to_parent = vec![usize::MAX; 379];
        for (local, original) in uniform_word_map.iter().enumerate() {
            reference_to_parent[*original] = base + local;
        }
        for (local, original) in uniform_leaf_map.iter().enumerate() {
            same_projection(
                spec,
                leaf_map[local],
                uniform_reference,
                *original,
                &reference_to_parent,
            )?;
        }
        let mut child_leaves = Vec::new();
        for ordinal in &uniform_leaf_map {
            let leaf = &uniform_reference.leaves[*ordinal];
            let mut wires = Vec::new();
            for wire in &leaf.wires {
                let local = wire
                    .checked_sub(129)
                    .ok_or("encoding projection lower bound")?;
                if local >= 55 {
                    return Err("encoding projection upper bound".into());
                }
                wires.push(local);
            }
            child_leaves.push(Leaf {
                kind: leaf.kind.clone(),
                argument: leaf.argument.clone(),
                wires,
                body_sha256: leaf.body_sha256.clone(),
            });
        }
        let used: HashSet<_> = child_leaves.iter().map(|l| l.body_sha256.clone()).collect();
        let child_op = format!("{operation_id}/coefficient/{degree}");
        let mut child_spec = GraphSpec {
            program_sha256: "00".repeat(32),
            context: context.into(),
            field_role: role.into(),
            operation_id: child_op.clone(),
            words: uniform_reference.words[129..184].to_vec(),
            leaves: child_leaves,
            bodies: uniform_reference
                .bodies
                .iter()
                .filter(|(id, _)| used.contains(*id))
                .map(|(id, body)| (id.clone(), body.clone()))
                .collect(),
        };
        child_spec.program_sha256 =
            program_digest(&child_spec, 16, &[("result".into(), (0..9).collect())])?;
        let child_catalogue = hex::encode(child_spec.identity()?);
        children.push(json!({"degree":degree,"operation_id":child_op,"program_sha256":child_spec.program_sha256,
            "catalogue_id":child_catalogue,"word_map":word_map,"leaf_map":leaf_map,
            "uniform_word_map":uniform_word_map,"uniform_leaf_map":uniform_leaf_map}));
        let fields: Vec<_> = (base..base + 9).collect();
        let bytes: Vec<_> = (base + 9..base + 41).collect();
        let aux: Vec<_> = (base + 41..base + 55).collect();
        let mut openings = Vec::new();
        for (byte, slot) in bytes.iter().enumerate() {
            let matches = if let Some(crossing) =
                CROSSINGS.iter().position(|(index, _)| *index == byte)
            {
                vec![(arithmetic + crossing, 0)]
            } else {
                let mut found = Vec::new();
                for ordinal in arithmetic + 7..arithmetic + 16 {
                    for (formal, wire) in spec.leaves[ordinal].wires.iter().enumerate().skip(1) {
                        if wire == slot {
                            found.push((ordinal, formal));
                        }
                    }
                }
                found
            };
            if matches.len() != 1 || spec.leaves[matches[0].0].wires[matches[0].1] != *slot {
                return Err("coefficient BYTE opening occurrence differs".into());
            }
            openings.push(matches[0]);
        }
        for limb in 0..9 {
            links.push(OpeningLink {
                kind: "limb-to-field-valid".into(),
                word_index: base + limb,
                source_ordinal: arithmetic + 7 + limb,
                source_occurrence: 0,
                target_ordinal: 109 + child,
                target_occurrence: limb,
            });
        }
        for (part, slot) in aux.iter().enumerate() {
            let mut targets = Vec::new();
            for ordinal in arithmetic + 7..arithmetic + 16 {
                for (formal, wire) in spec.leaves[ordinal].wires.iter().enumerate().skip(1) {
                    if wire == slot {
                        targets.push((ordinal, formal));
                    }
                }
            }
            if targets.len() != 1 {
                return Err("split auxiliary reconstruction occurrence differs".into());
            }
            links.push(OpeningLink {
                kind: "split-to-reconstruction".into(),
                word_index: *slot,
                source_ordinal: arithmetic + part / 2,
                source_occurrence: 1 + part % 2,
                target_ordinal: targets[0].0,
                target_occurrence: targets[0].1,
            });
        }
        ports_fields.push(names(spec, &fields)?);
        ports_bytes.push(names(spec, &bytes)?);
        ports_aux.push(names(spec, &aux)?);
        all_fields.push(fields);
        all_bytes.push(bytes);
        byte_openings.push(openings);
    }
    let mut anchors = Vec::new();
    for (index, (byte, expected)) in fixed_prefix(counter).into_iter().enumerate() {
        let word_index = 110 + index;
        let ordinal = 32 + index;
        let word = format!("prefix/frame/byte/{byte}");
        let actual = &spec.words[word_index];
        let leaf = &spec.leaves[ordinal];
        if actual.name != word
            || actual.bound != 256
            || leaf.kind != "const"
            || leaf.argument != [i64::from(expected)]
            || leaf.wires != [word_index]
        {
            return Err("prefix fixed BYTE anchor topology differs".into());
        }
        anchors.push(FrameAnchor {
            byte_index: byte,
            expected,
            word,
            word_index,
            anchor_ordinal: ordinal,
        });
    }
    for link in &links {
        if spec.leaves[link.source_ordinal]
            .wires
            .get(link.source_occurrence)
            != Some(&link.word_index)
            || spec.leaves[link.target_ordinal]
                .wires
                .get(link.target_occurrence)
                != Some(&link.word_index)
        {
            return Err("canonical internal opening link detached from its word".into());
        }
    }
    if links.len() != 46 || anchors.len() != 77 {
        return Err("frame canonical/anchor coverage differs".into());
    }
    let fields: Vec<_> = DEGREES
        .iter()
        .enumerate()
        .map(|(i, degree)| {
            (
                format!("coefficient/{degree}/result"),
                all_fields[i].clone(),
            )
        })
        .collect();
    let program_sha256 = program_digest(spec, 109, &fields)?;
    if spec.program_sha256 != program_sha256 {
        return Err("coefficient/frame actual Program digest differs".into());
    }
    let ports = json!({"coefficient_bytes":ports_bytes,"coefficient_fields":ports_fields,"split_auxiliaries":ports_aux,
        "frame_bytes":anchors.iter().map(|anchor|anchor.word.clone()).collect::<Vec<_>>()});
    let source_maps = json!({"schema":"bitvm2-nova-byte-sumcheck-frame-maps/v1","children":children,
        "uniform_reference":{"operation_id":reference_op,"program_sha256":reference_program,"catalogue_id":reference_catalogue},
        "coefficient_degrees":DEGREES,"coefficient_byte_indices":all_bytes,"coefficient_field_indices":all_fields,
        "byte_opening_occurrences":byte_openings,"canonical_field_leaves":[109,110],
        "canonical_internal_links":links.iter().map(OpeningLink::json).collect::<Vec<_>>(),
        "frame_anchors":anchors.iter().map(FrameAnchor::json).collect::<Vec<_>>(),"ports":ports});
    if &source_maps != raw_maps {
        return Err("coefficient/frame raw maps differ from actual reconstruction".into());
    }
    let source_maps_sha256 = hash(&source_maps)?;
    let metadata = json!({"schema":"bitvm2-nova-byte-sumcheck-frame/v1","context":context,"field_role":role,
        "counter":counter,"operation_id":operation_id,"program_sha256":program_sha256,
        "catalogue_id":hex::encode(spec.identity()?),"source_maps_sha256":source_maps_sha256,
        "coefficient_encoding":"compressed quadratic c0_LE32||c2_LE32; no linear term or length prefix",
        "canonicality":"original9radix2^29 limbs,32LEbytes,7splits,9reconstructions,field_valid per scalar",
        "scope":"canonical scalar/BYTE relations and following-c prefix constants; proof origins remain external"});
    let mut source = sha256::Hash::engine();
    source.input(DOMAIN);
    source.input(&canonical(&metadata)?);
    Ok(CheckedFrame {
        source_maps,
        metadata,
        source_sha256: sha256::Hash::from_engine(source).to_string(),
        source_maps_sha256,
        program_sha256,
        coefficient_byte_indices: all_bytes,
        coefficient_field_indices: all_fields,
        byte_opening_occurrences: byte_openings,
        canonical_internal_links: links,
        frame_anchors: anchors,
        canonical_field_leaves: [109, 110],
    })
}

/// Exact honest/closed-SMALL-probe assignment, independently of Python values.
/// Input bytes themselves are canonical; a selected modulus fault is applied
/// only afterward and preserves every encoding equality while refuting its guard.
pub fn expected_assignment(
    coefficients: &[[u8; 32]; 2],
    role: &str,
    counter: u64,
    modulus_fault: Option<usize>,
    frame_fault: Option<(usize, u8)>,
) -> Result<Vec<u32>> {
    let (p, _) = modulus(role)?;
    if modulus_fault.is_some() && frame_fault.is_some() {
        return Err("choose only one closed small probe".into());
    }
    if modulus_fault.is_some_and(|degree| !DEGREES.contains(&degree)) {
        return Err("modulus probe degree must be0 or2".into());
    }
    let fixed = fixed_prefix(counter);
    if frame_fault.is_some_and(|(index, _)| !fixed.iter().any(|(byte, _)| *byte == index)) {
        return Err("frame probe must select one fixed77 position".into());
    }
    let mut values = Vec::with_capacity(187);
    for (slot, raw) in coefficients.iter().enumerate() {
        if raw.iter().rev().cmp(p.iter().rev()).is_ge() {
            return Err("native host coefficient admission is canonical-only".into());
        }
        let actual = if modulus_fault == Some(DEGREES[slot]) {
            &p
        } else {
            raw
        };
        let mut limbs = [0u32; 9];
        for bit in 0..256 {
            limbs[bit / 29] |= u32::from((actual[bit / 8] >> (bit % 8)) & 1) << (bit % 29);
        }
        values.extend(limbs);
        values.extend(actual.iter().map(|byte| u32::from(*byte)));
        for (byte, width) in CROSSINGS {
            values.push(u32::from(actual[byte] & ((1u8 << width) - 1)));
            values.push(u32::from(actual[byte] >> width));
        }
    }
    for (byte, expected) in fixed {
        values.push(
            frame_fault
                .filter(|(index, _)| *index == byte)
                .map_or(expected, |(_, replacement)| u32::from(replacement)),
        );
    }
    if values.len() != 187 {
        return Err("native coefficient/frame assertion census".into());
    }
    Ok(values)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pure_assignment_canonical_and_closed_faults() {
        for role in ["pallas_scalar", "vesta_scalar"] {
            let zero = [[0u8; 32]; 2];
            let values = expected_assignment(&zero, role, 60, None, None).unwrap();
            assert_eq!(values.len(), 187);
            assert!(values[..110].iter().all(|value| *value == 0));
            assert_eq!(values[110], u32::from(b'p'));
            for degree in DEGREES {
                let bad = expected_assignment(&zero, role, 60, Some(degree), None).unwrap();
                let (p, _) = modulus(role).unwrap();
                let base = if degree == 0 { 0 } else { 55 };
                let expected: Vec<_> = p.iter().map(|b| u32::from(*b)).collect();
                assert_eq!(&bad[base + 9..base + 41], expected.as_slice());
                assert!(bad[base..base + 9].iter().all(|v| *v < BASE));
            }
            assert!(expected_assignment(&zero, role, 60, Some(1), None).is_err());
            assert!(expected_assignment(&zero, role, 60, None, Some((1, 0))).is_err());
            assert!(expected_assignment(&zero, role, 60, Some(0), Some((0, 0))).is_err());
        }
    }

    #[test]
    fn fixed_prefix_has_only_the77_public_positions() {
        let fixed = fixed_prefix(45);
        assert_eq!(fixed.len(), 77);
        assert_eq!(fixed.iter().find(|(i, _)| *i == 69), Some(&(69, 45)));
        assert!(!fixed
            .iter()
            .any(|(i, _)| (1..65).contains(i) || (77..136).contains(i)));
    }
}
