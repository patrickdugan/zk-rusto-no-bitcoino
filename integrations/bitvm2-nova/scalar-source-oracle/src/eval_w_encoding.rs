//! Exact unsigned256 eval_W encoding, independently checked against a fresh
//! actual Uniform result projection. Noncanonical integers are not reduced or
//! rejected by host field admission; the original field_valid16 returns false.
use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitvm2_nova_script_oracle::{
    registry::GraphSpec,
    wots::{id32, Result},
};
use serde_json::{json, Map, Value};

const BASE: u32 = 1 << 29;
const DOMAIN: &[u8] = b"BITVM2-NOVA/EVAL-W-ENCODING/v1\0";
const CROSSINGS: [(usize, usize); 7] =
    [(3, 5), (7, 2), (10, 7), (14, 4), (18, 1), (21, 6), (25, 3)];

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
        json!({"kind":self.kind,"word_index":self.word_index,"source_ordinal":self.source_ordinal,
            "source_occurrence":self.source_occurrence,"target_ordinal":self.target_ordinal,
            "target_occurrence":self.target_occurrence})
    }
}

pub struct CheckedEncoding {
    pub source_maps: Value,
    pub metadata: Value,
    pub ports: Value,
    pub source_sha256: String,
    pub source_maps_sha256: String,
    pub program_sha256: String,
    pub catalogue_id: String,
    pub input_byte_indices: Vec<usize>,
    pub scalar_limb_indices: Vec<usize>,
    pub split_auxiliary_indices: Vec<usize>,
    pub byte_opening_occurrences: Vec<(usize, usize)>,
    pub limb_reconstruction_occurrences: Vec<(usize, usize)>,
    pub canonical_field_ordinal: usize,
    pub canonical_field_occurrences: Vec<(usize, usize)>,
    pub split_source_occurrences: Vec<(usize, usize)>,
    pub split_consumer_occurrences: Vec<(usize, usize)>,
    pub canonical_internal_links: Vec<OpeningLink>,
}

fn modulus(role: &str) -> Result<([u8; 32], &'static str)> {
    let (raw, decimal) = match role {
        "pallas_scalar" => (
            "0100000021eb468cdda89409fc98462200000000000000000000000000000040",
            "28948022309329048855892746252171976963363056481941647379679742748393362948097",
        ),
        "vesta_scalar" => (
            "01000000ed302d991bf94c09fc98462200000000000000000000000000000040",
            "28948022309329048855892746252171976963363056481941560715954676764349967630337",
        ),
        _ => return Err("eval_W encoding requires an exact Pasta scalar role".into()),
    };
    Ok((
        hex::decode(raw)?
            .try_into()
            .map_err(|_| "scalar modulus size")?,
        decimal,
    ))
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 192
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.:/-".contains(&byte))
}

fn canonical(value: &Value) -> Result<Vec<u8>> {
    fn ordered(value: &Value, depth: usize) -> Result<Value> {
        if depth > 12 {
            return Err("eval_W metadata depth".into());
        }
        Ok(match value {
            Value::Object(object) => {
                let mut keys: Vec<_> = object.keys().collect();
                keys.sort_unstable();
                let mut output = Map::new();
                for key in keys {
                    if !key.is_ascii() {
                        return Err("eval_W metadata ASCII key".into());
                    }
                    output.insert(
                        key.clone(),
                        ordered(object.get(key).ok_or("eval_W metadata key")?, depth + 1)?,
                    );
                }
                Value::Object(output)
            }
            Value::Array(items) => Value::Array(
                items
                    .iter()
                    .map(|item| ordered(item, depth + 1))
                    .collect::<Result<_>>()?,
            ),
            Value::String(text) if !text.is_ascii() => {
                return Err("eval_W metadata ASCII text".into())
            }
            Value::Number(number) if number.as_i64().is_none() && number.as_u64().is_none() => {
                return Err("eval_W metadata integer".into())
            }
            _ => value.clone(),
        })
    }
    Ok(serde_json::to_vec(&ordered(value, 0)?)?)
}

fn hash(value: &Value) -> Result<String> {
    Ok(hex::encode(sha256::Hash::hash(&canonical(value)?)))
}

pub fn check(
    spec: &GraphSpec,
    context: &str,
    role: &str,
    operation_id: &str,
    raw_maps: &Value,
    uniform_reference: &GraphSpec,
) -> Result<CheckedEncoding> {
    let (_, decimal) = modulus(role)?;
    let reference_op = format!("{operation_id}/uniform-reference");
    if !identifier(operation_id)
        || !identifier(&reference_op)
        || hex::encode(id32(context)?) != context
        || spec.context != context
        || spec.field_role != role
        || spec.operation_id != operation_id
        || spec.words.len() != 55
        || spec.leaves.len() != 17
        || uniform_reference.context != context
        || uniform_reference.field_role != role
        || uniform_reference.operation_id != reference_op
        || uniform_reference.words.len() != 379
        || uniform_reference.leaves.len() != 245
    {
        return Err("eval_W exact parameters and fresh Uniform reference required".into());
    }
    let catalogue = hex::encode(spec.identity()?);
    uniform_reference.identity()?;
    let scalar_names: Vec<_> = (0..9).map(|i| format!("scalar/l{i}")).collect();
    let byte_names: Vec<_> = (0..32)
        .map(|i| format!("scalar/encoding/byte/{i}"))
        .collect();
    let aux_names: Vec<_> = CROSSINGS
        .iter()
        .flat_map(|(byte, _)| {
            [
                format!("scalar/encoding/split/{byte}/lo"),
                format!("scalar/encoding/split/{byte}/hi"),
            ]
        })
        .collect();
    for (index, actual) in spec.words.iter().enumerate() {
        let name = if index < 9 {
            &scalar_names[index]
        } else if index < 41 {
            &byte_names[index - 9]
        } else {
            &aux_names[index - 41]
        };
        let old = &uniform_reference.words[129 + index];
        if &actual.name != name
            || old.name
                != format!(
                    "result{}",
                    name.strip_prefix("scalar").ok_or("encoding name prefix")?
                )
            || actual.bound != old.bound
        {
            return Err("eval_W original limb/BYTE/split word projection differs".into());
        }
    }
    let legacy_leaf_map: Vec<_> = (65..81).chain(std::iter::once(244)).collect();
    for (ordinal, original) in legacy_leaf_map.iter().enumerate() {
        let leaf = &spec.leaves[ordinal];
        let old = &uniform_reference.leaves[*original];
        let mut projection = Vec::new();
        for wire in &old.wires {
            if !(129..184).contains(wire) {
                return Err("eval_W legacy projection has a foreign word".into());
            }
            projection.push(*wire - 129);
        }
        if leaf.kind != old.kind
            || leaf.argument != old.argument
            || leaf.wires != projection
            || leaf.body_sha256 != old.body_sha256
            || spec.bodies.get(&leaf.body_sha256) != uniform_reference.bodies.get(&old.body_sha256)
        {
            return Err("eval_W original predicate body/alias/leaf projection differs".into());
        }
    }
    if spec.leaves[16].kind != "field_valid" || spec.leaves[16].wires != (0..9).collect::<Vec<_>>()
    {
        return Err("eval_W canonical scalar guard must remain at16".into());
    }
    let constraints: Vec<_> = spec.leaves[..16]
        .iter()
        .map(|leaf| {
            json!([
                leaf.kind,
                leaf.wires
                    .iter()
                    .map(|i| spec.words[*i].name.clone())
                    .collect::<Vec<_>>(),
                leaf.argument
            ])
        })
        .collect();
    let program = hash(
        &json!({"schema":"bitvm2-nova-fixed-trace/v2","field_role":role,"modulus":decimal,
        "operation_id":operation_id,"context":context,
        "words":spec.words.iter().map(|word|json!([word.name,word.bound])).collect::<Vec<_>>(),
        "fields":[["scalar",scalar_names]],"constraints":constraints}),
    )?;
    if program != spec.program_sha256 {
        return Err("eval_W actual ConvolutionProgram identity differs".into());
    }
    let input_byte_indices: Vec<_> = (9..41).collect();
    let scalar_limb_indices: Vec<_> = (0..9).collect();
    let split_auxiliary_indices: Vec<_> = (41..55).collect();
    let mut byte_occurrences = Vec::new();
    for byte in 0..32 {
        let word = 9 + byte;
        let found = if let Some(crossing) = CROSSINGS.iter().position(|(index, _)| *index == byte) {
            vec![(crossing, 0)]
        } else {
            (7..16)
                .flat_map(|ordinal| {
                    spec.leaves[ordinal].wires.iter().enumerate().filter_map(
                        move |(formal, wire)| {
                            (formal > 0 && *wire == word).then_some((ordinal, formal))
                        },
                    )
                })
                .collect::<Vec<_>>()
        };
        if found.len() != 1 || spec.leaves[found[0].0].wires[found[0].1] != word {
            return Err("eval_W BYTE opening coordinate detached from original encoding".into());
        }
        byte_occurrences.push(found[0]);
    }
    let mut links = Vec::new();
    for limb in 0..9 {
        if spec.leaves[7 + limb].wires[0] != limb || spec.leaves[16].wires[limb] != limb {
            return Err("eval_W reconstructed limb detached from field guard".into());
        }
        links.push(OpeningLink {
            kind: "limb-to-field-valid".into(),
            word_index: limb,
            source_ordinal: 7 + limb,
            source_occurrence: 0,
            target_ordinal: 16,
            target_occurrence: limb,
        });
    }
    let mut sources = Vec::new();
    let mut consumers = Vec::new();
    for part in 0..14 {
        let (word, source, formal) = (41 + part, part / 2, 1 + part % 2);
        let found = (7..16)
            .flat_map(|ordinal| {
                spec.leaves[ordinal].wires.iter().enumerate().filter_map(
                    move |(occurrence, wire)| {
                        (occurrence > 0 && *wire == word).then_some((ordinal, occurrence))
                    },
                )
            })
            .collect::<Vec<_>>();
        if found.len() != 1 || spec.leaves[source].wires[formal] != word {
            return Err("eval_W split/reconstruction actual opening link differs".into());
        }
        let (target, occurrence) = found[0];
        sources.push((source, formal));
        consumers.push((target, occurrence));
        links.push(OpeningLink {
            kind: "split-to-reconstruction".into(),
            word_index: word,
            source_ordinal: source,
            source_occurrence: formal,
            target_ordinal: target,
            target_occurrence: occurrence,
        });
    }
    let limbs: Vec<_> = (0..9).map(|i| (7 + i, 0)).collect();
    let guards: Vec<_> = (0..9).map(|i| (16, i)).collect();
    let ports =
        json!({"input_bytes":byte_names,"scalar_limbs":scalar_names,"split_auxiliaries":aux_names});
    let maps = json!({"schema":"bitvm2-nova-eval-w-encoding-maps/v1",
        "input_byte_indices":input_byte_indices,"scalar_limb_indices":scalar_limb_indices,
        "split_auxiliary_indices":split_auxiliary_indices,"byte_opening_occurrences":byte_occurrences,
        "limb_reconstruction_occurrences":limbs,"canonical_field_ordinal":16,"canonical_field_occurrences":guards,
        "split_source_occurrences":sources,"split_consumer_occurrences":consumers,
        "canonical_internal_links":links.iter().map(OpeningLink::json).collect::<Vec<_>>(),
        "legacy_uniform_word_map":(129..184).collect::<Vec<_>>(),"legacy_uniform_leaf_map":legacy_leaf_map,"ports":ports});
    if raw_maps != &maps {
        return Err("eval_W actual source maps differ from independent encoding projection".into());
    }
    let maps_sha = hash(&maps)?;
    let metadata = json!({"schema":"bitvm2-nova-eval-w-encoding/v1","context":context,"field_role":role,
        "operation_id":operation_id,"program_sha256":program,"catalogue_id":catalogue,"source_maps_sha256":maps_sha,
        "words":55,"arithmetic_constraints":16,"canonical_fields":1,"leaves":17,
        "relation":"exact unsigned256LE bytes = nine radix2^29 limbs; scalar canonicality at field_valid16",
        "input_encoding":"unsigned256-bit little endian; no modular reduction",
        "encoding_relation_constructed":true,"source_authority":false,
        "scope":"BYTE/limb scalar encoding only; proof/hash/root origins require outer authenticated joins",
        "encoding_relation_verified":false,"canonicality_verified":false,"proof_byte_origins_bound":false,
        "hash_verified":false,"transcript_verified":false,"proof_verified":false,"root_verified":false,
        "production_assertion_binding":false,"bitcoin_transaction_graph":false,
        "complete_nova_verifier":false,"complete_bitvm2_verifier":false});
    let mut source = sha256::Hash::engine();
    source.input(DOMAIN);
    source.input(&canonical(&metadata)?);
    Ok(CheckedEncoding {
        source_maps: maps,
        metadata,
        ports,
        source_sha256: hex::encode(sha256::Hash::from_engine(source)),
        source_maps_sha256: maps_sha,
        program_sha256: program,
        catalogue_id: catalogue,
        input_byte_indices,
        scalar_limb_indices,
        split_auxiliary_indices,
        byte_opening_occurrences: byte_occurrences,
        limb_reconstruction_occurrences: limbs,
        canonical_field_ordinal: 16,
        canonical_field_occurrences: guards,
        split_source_occurrences: sources,
        split_consumer_occurrences: consumers,
        canonical_internal_links: links,
    })
}

/// Preserve all256 claimed bits, including bit255 and integers at/above p.
pub fn expected_assignment(raw: &[u8; 32]) -> Vec<u32> {
    let mut limbs = [0u32; 9];
    for bit in 0..256 {
        limbs[bit / 29] |= u32::from((raw[bit / 8] >> (bit % 8)) & 1) << (bit % 29);
    }
    let mut values = limbs.to_vec();
    values.extend(raw.iter().map(|byte| u32::from(*byte)));
    for (byte, width) in CROSSINGS {
        let value = u32::from(raw[byte]);
        values.extend([value & ((1 << width) - 1), value >> width]);
    }
    values
}

pub fn truth(spec: &GraphSpec, values: &[u32], ordinal: usize) -> Result<bool> {
    if spec.words.len() != 55 || spec.leaves.len() != 17 || values.len() != 55 || ordinal >= 17 {
        return Err("eval_W truth exact assignment/census required".into());
    }
    let leaf = &spec.leaves[ordinal];
    let mut v = Vec::new();
    for wire in &leaf.wires {
        let word = spec.words.get(*wire).ok_or("eval_W truth word")?;
        let value = *values.get(*wire).ok_or("eval_W truth value")?;
        if value >= word.bound {
            return Ok(false);
        }
        v.push(u64::from(value));
    }
    Ok(match leaf.kind.as_str() {
        "conv_split"
            if v.len() == 3 && leaf.argument.len() == 1 && (1..=7).contains(&leaf.argument[0]) =>
        {
            v[0] == v[1] + (v[2] << (leaf.argument[0] as u32))
        }
        "conv_reconstruct"
            if !leaf.argument.is_empty()
                && leaf.argument.len() <= 5
                && v.len() == leaf.argument.len() + 1
                && leaf.argument.iter().all(|width| (1..=8).contains(width))
                && leaf.argument.iter().sum::<i64>() <= 29 =>
        {
            let mut offset = 0;
            let mut sum = 0;
            for (value, width) in v[1..].iter().zip(&leaf.argument) {
                sum += value << offset;
                offset += *width as u32;
            }
            v[0] == sum
        }
        "field_valid" if leaf.argument.is_empty() && v.len() == 9 => {
            let (raw, _) = modulus(&spec.field_role)?;
            let mut p = [0u64; 9];
            for bit in 0..256 {
                p[bit / 29] |= u64::from((raw[bit / 8] >> (bit % 8)) & 1) << (bit % 29);
            }
            v.iter().rev().cmp(p.iter().rev()).is_lt()
        }
        _ => return Err("eval_W truth unsupported or malformed predicate".into()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unsigned_encoding_keeps_bit255_and_modulus_without_field_admission() {
        for role in ["pallas_scalar", "vesta_scalar"] {
            let (p, _) = modulus(role).unwrap();
            let values = expected_assignment(&p);
            assert_eq!(values.len(), 55);
            assert_eq!(&values[9..41], &p.map(u32::from));
        }
        let mut raw = [0u8; 32];
        raw[31] = 128;
        let values = expected_assignment(&raw);
        assert_eq!(values[8], 1 << 23);
        assert_eq!(values[40], 128);
        assert_eq!(expected_assignment(&[255; 32])[8], (1 << 24) - 1);
    }
}
