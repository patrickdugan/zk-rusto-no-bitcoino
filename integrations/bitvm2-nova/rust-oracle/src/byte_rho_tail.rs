//! Independent bounded topology and integer checks for the new BYTE rho tail.
//!
//! This module creates no keys, Scripts, receipts or verification verdicts.
//! The streamed worker separately authenticates assertions and executes Script.
use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitvm2_nova_script_oracle::{
    registry::GraphSpec,
    wots::{id32, Result},
};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, HashSet};

const BASE: u32 = 1 << 29;
const BYTE: u32 = 256;
const CARRY_BOUND: u32 = 1 << 14;
const CARRY_OFFSET: u32 = 8192;
const PQ_BOUND: u32 = 1 << 19;
const AB_BOUND: u32 = 1 << 18;
const TAIL_DOMAIN: &[u8] = b"BITVM2-NOVA/BYTE-RHO-TAIL/v1\0";

#[derive(Clone)]
pub struct Frame {
    pub branch: String,
    pub byte_index: usize,
    pub word_index: usize,
    pub anchor_ordinal: usize,
    pub expected: u32,
    pub global_id: String,
}

pub struct CheckedTail {
    pub global_ids: Vec<String>,
    pub source_maps: Value,
    pub source_manifest: Value,
    pub source_sha256: String,
    pub source_maps_sha256: String,
    pub program_sha256: String,
    pub uniform_program_sha256: String,
    pub uniform_catalogue_id: String,
    pub uniform_metadata: Value,
    pub digest_indices: Vec<usize>,
    pub frame_records: Vec<Frame>,
    pub result_indices: Vec<usize>,
}

fn modulus(role: &str) -> Result<([u8; 32], &'static str)> {
    let (encoded, decimal) = match role {
        "pallas_scalar" => (
            "0100000021eb468cdda89409fc98462200000000000000000000000000000040",
            "28948022309329048855892746252171976963363056481941647379679742748393362948097",
        ),
        "vesta_scalar" => (
            "01000000ed302d991bf94c09fc98462200000000000000000000000000000040",
            "28948022309329048855892746252171976963363056481941560715954676764349967630337",
        ),
        _ => return Err("rho tail requires an explicit Pasta scalar role".into()),
    };
    Ok((
        hex::decode(encoded)?
            .try_into()
            .map_err(|_| "modulus size")?,
        decimal,
    ))
}

fn canonical(value: &Value) -> Result<Vec<u8>> {
    fn ordered(value: &Value, depth: usize) -> Result<Value> {
        if depth > 16 {
            return Err("tail canonical JSON nesting bound".into());
        }
        Ok(match value {
            Value::Object(values) => {
                let mut keys: Vec<_> = values.keys().collect();
                keys.sort_unstable();
                let mut result = Map::new();
                for key in keys {
                    if !key.is_ascii() {
                        return Err("tail canonical ASCII key required".into());
                    }
                    result.insert(
                        key.clone(),
                        ordered(values.get(key).ok_or("canonical object key")?, depth + 1)?,
                    );
                }
                Value::Object(result)
            }
            Value::Array(values) => Value::Array(
                values
                    .iter()
                    .map(|item| ordered(item, depth + 1))
                    .collect::<Result<_>>()?,
            ),
            Value::String(text) if !text.is_ascii() => {
                return Err("tail canonical ASCII string required".into());
            }
            Value::Number(number) if number.as_i64().is_none() && number.as_u64().is_none() => {
                return Err("tail canonical integer required".into());
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
        .map(|i| {
            spec.words
                .get(*i)
                .map(|word| word.name.clone())
                .ok_or_else(|| "tail name index".into())
        })
        .collect()
}

/// ConvolutionProgram currently inherits the plain fixed-trace/v2 digest.
/// Its bound-leaf compiler domain is separate and is not a Program wrapper.
fn program_digest(
    spec: &GraphSpec,
    operation: &str,
    words: usize,
    constraints: usize,
    result: &[usize],
) -> Result<String> {
    let (_, decimal) = modulus(&spec.field_role)?;
    let declarations: Vec<_> = spec.words[..words]
        .iter()
        .map(|word| json!([word.name, word.bound]))
        .collect();
    let mut rows = Vec::with_capacity(constraints);
    for leaf in &spec.leaves[..constraints] {
        rows.push(json!([leaf.kind, names(spec, &leaf.wires)?, leaf.argument]));
    }
    hash(
        &json!({"schema":"bitvm2-nova-fixed-trace/v2","field_role":spec.field_role,
        "modulus":decimal,"operation_id":operation,"context":spec.context,"words":declarations,
        "fields":[["result",names(spec,result)?]],"constraints":rows}),
    )
}

struct Cursor<'a> {
    spec: &'a GraphSpec,
    word: usize,
    leaf: usize,
}
impl Cursor<'_> {
    fn word(&mut self, name: String, bound: u32) -> Result<usize> {
        let slot = self.word;
        let actual = self
            .spec
            .words
            .get(slot)
            .ok_or("tail word stream truncated")?;
        if actual.name != name || actual.bound != bound {
            return Err(format!("tail declaration {slot} differs: expected {name}/{bound}").into());
        }
        self.word += 1;
        Ok(slot)
    }
    fn gate(&mut self, kind: &str, wires: &[usize], arguments: &[i64]) -> Result<usize> {
        let ordinal = self.leaf;
        let actual = self
            .spec
            .leaves
            .get(ordinal)
            .ok_or("tail leaf stream truncated")?;
        if actual.kind != kind || actual.wires != wires || actual.argument != arguments {
            return Err(
                format!("tail predicate {ordinal} differs from exact {kind} topology").into(),
            );
        }
        self.leaf += 1;
        Ok(ordinal)
    }
}

fn fixed_bytes(counter: u64, branch: &str) -> Vec<(usize, u32)> {
    let mut state = [0u8; 200];
    state[0] = b'w';
    state[33..37].copy_from_slice(b"NoDS");
    state[37..45].copy_from_slice(&counter.to_le_bytes());
    state[109] = b'r';
    state[110] = u8::from(branch == "hi");
    state[111] = 1;
    state[135] = 128;
    std::iter::once(0)
        .chain(33..45)
        .chain([109, 110])
        .chain(111..200)
        .map(|i| (i, u32::from(state[i])))
        .collect()
}

fn state_id(branch: &str, state: usize, byte: usize) -> String {
    format!(
        "branch/{branch}/byte-state/{state}/l{}/byte{}",
        byte / 8,
        byte % 8
    )
}

/// Check one exact tail. operation_id is the actual tail operation ID.
pub fn check(
    spec: &GraphSpec,
    context: &str,
    role: &str,
    counter: u64,
    operation_id: &str,
    raw_maps: &Value,
) -> Result<CheckedTail> {
    let (modulus_bytes, _) = modulus(role)?;
    id32(context)?;
    if context
        .bytes()
        .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
    {
        return Err("canonical lowercase tail context required".into());
    }
    if spec.context != context
        || spec.field_role != role
        || spec.operation_id != operation_id
        || spec.words.len() != 587
        || spec.leaves.len() != 453
    {
        return Err("rho tail context/role/operation/census differs".into());
    }
    spec.identity()?; // Original registry bounds, shapes, body hashes and coverage.
    let mut c = Cursor {
        spec,
        word: 0,
        leaf: 0,
    };
    let unit = c.word("constant/byte-one".into(), BYTE)?;
    let unit_anchor = c.gate("const", &[unit], &[1])?;
    let inputs = (0..64)
        .map(|i| c.word(format!("input/byte/{i}"), BYTE))
        .collect::<Result<Vec<_>>>()?;
    let mut subtotals = Vec::new();
    let mut adapters = Vec::new();
    for (i, input) in inputs.iter().enumerate() {
        let out = c.word(format!("input/subtotal/{i}"), AB_BOUND)?;
        adapters.push(c.gate("conv_ab", &[*input, unit, out], &[1])?);
        subtotals.push(out);
    }
    let result = (0..9)
        .map(|i| c.word(format!("result/l{i}"), BASE))
        .collect::<Result<Vec<_>>>()?;
    let result_bytes = (0..32)
        .map(|i| c.word(format!("result/encoding/byte/{i}"), BYTE))
        .collect::<Result<Vec<_>>>()?;
    let mut crossings = BTreeMap::new();
    for boundary in [29, 58, 87, 116, 145, 174, 203] {
        let (index, width) = (boundary / 8, boundary % 8);
        let low = c.word(format!("result/encoding/split/{index}/lo"), 1 << width)?;
        let high = c.word(
            format!("result/encoding/split/{index}/hi"),
            1 << (8 - width),
        )?;
        c.gate(
            "conv_split",
            &[result_bytes[index], low, high],
            &[width as i64],
        )?;
        crossings.insert(index, (low, high));
    }
    for (limb, original) in result.iter().enumerate() {
        let (start, end) = (limb * 29, (limb * 29 + 29).min(256));
        let mut pieces = vec![*original];
        let mut widths = Vec::new();
        for byte in start / 8..end.div_ceil(8) {
            let (low, high) = (start.max(byte * 8), end.min(byte * 8 + 8));
            pieces.push(if low == byte * 8 && high == byte * 8 + 8 {
                result_bytes[byte]
            } else {
                let split = crossings.get(&byte).ok_or("missing limb crossing")?;
                if low == byte * 8 {
                    split.0
                } else {
                    split.1
                }
            });
            widths.push((high - low) as i64);
        }
        c.gate("conv_reconstruct", &pieces, &widths)?;
    }
    let quotient = (0..33)
        .map(|i| c.word(format!("quotient/byte/{i}"), BYTE))
        .collect::<Result<Vec<_>>>()?;
    let top_low = c.word("quotient/top/lo".into(), 4)?;
    let top_high = c.word("quotient/top/hi".into(), 64)?;
    c.gate("conv_split", &[quotient[32], top_low, top_high], &[2])?;
    let top_anchor = c.gate("const", &[top_high], &[0])?;
    let initial_carry = c.word("carry/0".into(), CARRY_BOUND)?;
    let initial_anchor = c.gate("const", &[initial_carry], &[i64::from(CARRY_OFFSET)])?;
    let mut carries = vec![initial_carry];
    let mut incoming = initial_carry;
    let mut columns = Vec::new();
    let mut pq_blocks = Vec::new();
    let mut pq_ordinals = Vec::new();
    for column in 0..65 {
        let terms: Vec<_> = modulus_bytes
            .iter()
            .enumerate()
            .filter_map(|(i, coefficient)| {
                if *coefficient != 0 && column >= i && column - i < 33 {
                    Some((i64::from(*coefficient), quotient[column - i]))
                } else {
                    None
                }
            })
            .collect();
        let mut blocks = Vec::new();
        let mut ordinals = Vec::new();
        for (block, cells) in terms.chunks(8).enumerate() {
            let out = c.word(format!("reduction/pq/{column}/{block}"), PQ_BOUND)?;
            let mut wires: Vec<_> = cells.iter().map(|(_, slot)| *slot).collect();
            wires.push(out);
            ordinals.push(
                c.gate(
                    "conv_pq",
                    &wires,
                    &cells
                        .iter()
                        .map(|(coefficient, _)| *coefficient)
                        .collect::<Vec<_>>(),
                )?,
            );
            blocks.push(out);
        }
        let outgoing = c.word(format!("carry/{}", column + 1), CARRY_BOUND)?;
        let mut wires = Vec::new();
        if column < 64 {
            wires.push(subtotals[column]);
        }
        wires.extend(&blocks);
        wires.extend([incoming, outgoing]);
        if column < 32 {
            wires.push(result_bytes[column]);
        }
        columns.push(c.gate(
            "conv_column",
            &wires,
            &[
                i64::from(column < 64),
                blocks.len() as i64,
                i64::from(column < 32),
            ],
        )?);
        carries.push(outgoing);
        pq_blocks.push(blocks);
        pq_ordinals.push(ordinals);
        incoming = outgoing;
    }
    let final_anchor = c.gate("const", &[incoming], &[i64::from(CARRY_OFFSET)])?;
    if (c.word, c.leaf) != (379, 244) {
        return Err("uniform reducer exact word/constraint census changed".into());
    }
    let uniform_operation = format!("{operation_id}/uniform");
    let uniform_program = program_digest(spec, &uniform_operation, 379, 244, &result)?;
    let mut frame_records = Vec::new();
    let mut frame_json = Vec::new();
    for branch in ["hi", "lo"] {
        for (byte_index, expected) in fixed_bytes(counter, branch) {
            let local_word = format!("frame/{branch}/byte/{byte_index}");
            let word_index = c.word(local_word.clone(), BYTE)?;
            let anchor_ordinal = c.gate("const", &[word_index], &[i64::from(expected)])?;
            let global_id = state_id(branch, 0, byte_index);
            frame_json.push(json!({"branch":branch,"byte_index":byte_index,"expected":expected,
                "local_word":local_word,"anchor_ordinal":anchor_ordinal,"word_index":word_index,"global_id":global_id}));
            frame_records.push(Frame {
                branch: branch.into(),
                byte_index,
                word_index,
                anchor_ordinal,
                expected,
                global_id,
            });
        }
    }
    c.gate("field_valid", &result, &[])?;
    if (c.word, c.leaf) != (587, 453) {
        return Err("rho tail declaration/predicate stream not exhausted exactly".into());
    }
    let tail_program = program_digest(spec, operation_id, 587, 452, &result)?;
    if spec.program_sha256 != tail_program {
        return Err("rho tail actual fixed-trace/v2 Program digest differs".into());
    }
    let mut uniform_leaves = spec.leaves[..244].to_vec();
    uniform_leaves.push(spec.leaves[452].clone());
    let used: HashSet<_> = uniform_leaves
        .iter()
        .map(|leaf| leaf.body_sha256.clone())
        .collect();
    let uniform_spec = GraphSpec {
        program_sha256: uniform_program.clone(),
        context: context.into(),
        field_role: role.into(),
        operation_id: uniform_operation.clone(),
        words: spec.words[..379].to_vec(),
        leaves: uniform_leaves,
        bodies: spec
            .bodies
            .iter()
            .filter(|(id, _)| used.contains(*id))
            .map(|(id, body)| (id.clone(), body.clone()))
            .collect(),
    };
    let uniform_catalogue = hex::encode(uniform_spec.identity()?);
    let ports = json!({"input_bytes":names(spec,&inputs)?,"input_subtotals":names(spec,&subtotals)?,
        "quotient_bytes":names(spec,&quotient)?,"result_field":names(spec,&result)?,"result_bytes":names(spec,&result_bytes)?,
        "carries":names(spec,&carries)?,"quotient_top_low":spec.words[top_low].name,
        "quotient_top_high":spec.words[top_high].name,"constant_one":spec.words[unit].name,
        "pq_blocks":pq_blocks.iter().map(|slots|names(spec,slots)).collect::<Result<Vec<_>>>()?});
    let sum: i64 = modulus_bytes.iter().map(|byte| i64::from(*byte)).sum();
    let uniform_metadata = json!({"schema":"bitvm2-nova-uniform-reduction/v1","field_role":role,
        "context":context,"operation_id":uniform_operation,"program_sha256":uniform_program,"relation":"X = c + p*q",
        "input_encoding":"unsigned512-bit-little-endian","input_bits":512,
        "quotient_encoding":"unsigned258-bit-integer-in33-little-endian-bytes","quotient_is_field_element":false,
        "quotient_top_byte_exclusive_bound":4,"modulus_le":hex::encode(modulus_bytes),"columns":65,"overflow_column":64,
        "carry_offset":8192,"encoded_carry_bound":16384,"reference_carry_min":-(sum+1),"reference_carry_max":0,
        "max_pq_column_sum":255*sum,"column_intermediate_exclusive_bound":1<<23,"reconstruction_exclusive_bound":1<<29,
        "ports":ports,"column_ordinals":columns,"input_adapter_ordinals":adapters,"pq_ordinals":pq_ordinals,
        "initial_anchor_ordinal":initial_anchor,"final_anchor_ordinal":final_anchor,"unit_anchor_ordinal":unit_anchor,
        "quotient_top_anchor_ordinal":top_anchor,"terminal_anchor_may_be_redundant":true,
        "scope":"arithmetic graph only; no hash/transcript/proof or production assertion binding"});
    let mut global_ids = Vec::with_capacity(587);
    for (i, word) in spec.words.iter().enumerate() {
        let global = if let Some(byte) = inputs.iter().position(|slot| *slot == i) {
            state_id(if byte < 32 { "lo" } else { "hi" }, 24, byte % 32)
        } else if let Some(frame) = frame_records.iter().find(|frame| frame.word_index == i) {
            frame.global_id.clone()
        } else {
            format!("reduction/{}", word.name)
        };
        global_ids.push(global);
    }
    let mut uniform_leaf_map: Vec<_> = (0..244).collect();
    uniform_leaf_map.push(452);
    let source_maps = json!({"uniform_word_map":(0..379).collect::<Vec<_>>(),"uniform_leaf_map":uniform_leaf_map,
        "uniform_program_sha256":uniform_program,"uniform_catalogue_id":uniform_catalogue,
        "uniform_metadata_sha256":hash(&uniform_metadata)?,"uniform_ports":ports,
        "frame_anchors":frame_json,"digest_input_indices":inputs,"result_field_indices":result,
        "global_ids":global_ids,"global_ids_sha256":hash(&json!(global_ids))?});
    if &source_maps != raw_maps {
        return Err("rho tail raw maps differ from independently reconstructed topology".into());
    }
    let source_maps_sha256 = hash(&source_maps)?;
    let source_manifest = json!({"schema":"bitvm2-nova-byte-rho-tail/v1","context":context,"field_role":role,
        "counter":counter,"operation_id":operation_id,"program_sha256":tail_program,
        "catalogue_id":hex::encode(spec.identity()?),"source_maps_sha256":source_maps_sha256,
        "scope":"unchanged unsigned512 reduction plus208 BYTE framing constants"});
    let mut source_hash = sha256::Hash::engine();
    source_hash.input(TAIL_DOMAIN);
    source_hash.input(&canonical(&source_manifest)?);
    Ok(CheckedTail {
        global_ids,
        source_maps,
        source_manifest,
        source_sha256: sha256::Hash::from_engine(source_hash).to_string(),
        source_maps_sha256,
        program_sha256: tail_program,
        uniform_program_sha256: uniform_program,
        uniform_catalogue_id: uniform_catalogue,
        uniform_metadata,
        digest_indices: inputs,
        frame_records,
        result_indices: result,
    })
}

/// Independent mathematical predicate checks; Script execution is separate.
pub fn truth(spec: &GraphSpec, values: &[u32], ordinal: usize) -> Result<bool> {
    if values.len() != spec.words.len() {
        return Err("tail assignment cardinality".into());
    }
    let leaf = spec.leaves.get(ordinal).ok_or("tail truth ordinal")?;
    let mut v = Vec::new();
    for slot in &leaf.wires {
        let word = spec.words.get(*slot).ok_or("tail truth wire")?;
        let value = *values.get(*slot).ok_or("tail truth value")?;
        if value >= word.bound {
            return Ok(false);
        }
        v.push(u64::from(value));
    }
    let a = &leaf.argument;
    Ok(match leaf.kind.as_str() {
        "const" if v.len() == 1 && a.len() == 1 && a[0] >= 0 => v[0] == a[0] as u64,
        "conv_split" if v.len() == 3 && a.len() == 1 && (1..=7).contains(&a[0]) => {
            v[0] == v[1] + (v[2] << (a[0] as u32))
        }
        "conv_reconstruct"
            if !a.is_empty()
                && a.len() <= 5
                && v.len() == a.len() + 1
                && a.iter().all(|width| (1..=8).contains(width))
                && a.iter().sum::<i64>() <= 29 =>
        {
            let mut offset = 0;
            let mut sum = 0;
            for (digit, width) in v[1..].iter().zip(a) {
                sum += digit << offset;
                offset += *width as u32;
            }
            v[0] == sum
        }
        "conv_ab"
            if a.len() == 1 && (1..=4).contains(&a[0]) && v.len() == 2 * a[0] as usize + 1 =>
        {
            v[v.len() - 1]
                == v[..v.len() - 1]
                    .chunks_exact(2)
                    .map(|pair| pair[0] * pair[1])
                    .sum::<u64>()
        }
        "conv_pq"
            if !a.is_empty()
                && a.len() <= 8
                && v.len() == a.len() + 1
                && a.iter().all(|n| (1..=255).contains(n)) =>
        {
            v[v.len() - 1]
                == v[..v.len() - 1]
                    .iter()
                    .zip(a)
                    .map(|(digit, k)| digit * (*k as u64))
                    .sum::<u64>()
        }
        "conv_column"
            if a.len() == 3
                && (0..=8).contains(&a[0])
                && (0..=4).contains(&a[1])
                && (0..=1).contains(&a[2])
                && v.len() == (a[0] + a[1] + 2 + a[2]) as usize =>
        {
            let (ab, pq) = (a[0] as usize, a[1] as usize);
            let out = if a[2] == 1 { v[v.len() - 1] } else { 0 };
            v[..ab].iter().sum::<u64>() + v[ab + pq] + 255 * 8192
                == out + v[ab..ab + pq].iter().sum::<u64>() + 256 * v[ab + pq + 1]
        }
        "field_valid" if a.is_empty() && v.len() == 9 => {
            let (raw, _) = modulus(&spec.field_role)?;
            let mut limbs = [0u64; 9];
            for bit in 0..256 {
                limbs[bit / 29] |= u64::from((raw[bit / 8] >> (bit % 8)) & 1) << (bit % 29);
            }
            v.iter().rev().cmp(limbs.iter().rev()).is_lt()
        }
        _ => return Err("unsupported or malformed rho tail truth predicate".into()),
    })
}

/// Fixed-size binary long division; no field library or proving dependency.
pub fn reduction(input: &[u8; 64], role: &str) -> Result<([u8; 32], [u8; 33])> {
    let (p, _) = modulus(role)?;
    let mut modulus = [0u8; 33];
    modulus[..32].copy_from_slice(&p);
    let mut remainder = [0u8; 33];
    let mut quotient = [0u8; 64];
    for bit in (0..512).rev() {
        let mut carry = (input[bit / 8] >> (bit % 8)) & 1;
        for byte in &mut remainder {
            let next = *byte >> 7;
            *byte = (*byte << 1) | carry;
            carry = next;
        }
        if carry != 0 {
            return Err("unsigned reduction remainder overflow".into());
        }
        if remainder.iter().rev().cmp(modulus.iter().rev()).is_ge() {
            let mut borrow = 0i16;
            for (value, divisor) in remainder.iter_mut().zip(&modulus) {
                let difference = i16::from(*value) - i16::from(*divisor) - borrow;
                *value = difference.rem_euclid(256) as u8;
                borrow = i16::from(difference < 0);
            }
            if borrow != 0 {
                return Err("unsigned reduction subtraction borrow".into());
            }
            quotient[bit / 8] |= 1 << (bit % 8);
        }
    }
    if remainder[32] != 0 || quotient[33..].iter().any(|byte| *byte != 0) || quotient[32] >= 4 {
        return Err("unsigned reduction result/258-bit quotient bound".into());
    }
    let mut result = [0u8; 32];
    result.copy_from_slice(&remainder[..32]);
    let mut q = [0u8; 33];
    q.copy_from_slice(&quotient[..33]);
    Ok((result, q))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_size_reduction_zero_one_modulus_and_roles() {
        for role in ["pallas_scalar", "vesta_scalar"] {
            let zero = reduction(&[0; 64], role).unwrap();
            assert_eq!(zero, ([0; 32], [0; 33]));
            let mut input = [0u8; 64];
            input[0] = 1;
            assert_eq!(reduction(&input, role).unwrap().0[0], 1);
            let (p, _) = modulus(role).unwrap();
            input[..32].copy_from_slice(&p);
            let (r, q) = reduction(&input, role).unwrap();
            assert_eq!(r, [0; 32]);
            assert_eq!(q[0], 1);
            assert!(q[1..].iter().all(|byte| *byte == 0));
            assert!(reduction(&[255; 64], role).unwrap().1[32] < 4);
        }
        assert!(reduction(&[0; 64], "pallas_base").is_err());
    }

    #[test]
    fn framing_exact104_and_counter_shared_selector_distinct() {
        for counter in [44, 59, u64::MAX] {
            let hi = fixed_bytes(counter, "hi");
            let lo = fixed_bytes(counter, "lo");
            assert_eq!(hi.len(), 104);
            assert_eq!(lo.len(), 104);
            let different: Vec<_> = hi.iter().zip(&lo).filter(|(a, b)| a != b).collect();
            assert_eq!(different.len(), 1);
            assert_eq!(*different[0].0, (110, 1));
            assert_eq!(*different[0].1, (110, 0));
        }
    }

    #[test]
    fn maximum_unsigned512_matches_independent_integer_reference() {
        // Python integer divmod(2**512-1,p), without a field reduction library.
        for (role, remainder, quotient) in [
            (
                "pallas_scalar",
                "0e000000ff7896fce3161a893d43bb6790f5cc041023ae7fa9dacf7caf416d09",
                "f1ffffffef4d913b2772b5663f7096dbfdffffffffffffffffffffffffffffff03",
            ),
            (
                "vesta_scalar",
                "0e000000b3ec788ce7e00d8bbd0dd3d7185dc9c39ba9977714b79c7baf416d09",
                "f1ffffff2ff12c6d466e306b3f7096dbfdffffffffffffffffffffffffffffff03",
            ),
        ] {
            let (r, q) = reduction(&[255; 64], role).unwrap();
            assert_eq!(hex::encode(r), remainder);
            assert_eq!(hex::encode(q), quotient);
        }
    }

    #[test]
    fn canonical_metadata_json_is_sorted_ascii_and_integer_only() {
        assert_eq!(
            canonical(&json!({"z":2,"a":1})).unwrap(),
            b"{\"a\":1,\"z\":2}"
        );
        assert!(canonical(&json!({"x":1.5})).is_err());
        assert!(canonical(&json!({"x":"\u{00e9}"})).is_err());
    }
}
