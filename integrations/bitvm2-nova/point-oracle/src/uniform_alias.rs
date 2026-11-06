//! Closed unsigned c+p,q-1 witnesses and exact private Uniform/bits composition.
//! The Uniform reference must be a freshly independently checked actual native
//! projection. No imported assignment, field decode, alias reduction or Script
//! execution is admitted here. The private merged probe fixes selected bit0.
use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitvm2_nova_script_oracle::{
    registry::{GraphSpec, Word},
    wots::{id32, Result},
};
use num_bigint::BigUint;
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, HashSet};

const BASE: u32 = 1 << 29;
const CARRY_OFFSET: i64 = 8192;
const DOMAIN: &[u8] = b"BITVM2-NOVA/CLOSED-SCALAR-ALIAS/v1\0";

pub struct AliasValues {
    pub input: BigUint,
    pub canonical_result: BigUint,
    pub canonical_quotient: BigUint,
    pub result: BigUint,
    pub quotient: BigUint,
    pub result_le: [u8; 32],
    pub quotient_le: [u8; 33],
    pub limbs: [u32; 9],
}

pub struct CheckedAlias {
    pub source_maps: Value,
    pub metadata: Value,
    pub source_sha256: String,
    pub source_maps_sha256: String,
    pub program_sha256: String,
    pub catalogue_id: String,
    pub uniform_word_map: Vec<usize>,
    pub uniform_leaf_map: Vec<usize>,
    pub bit_indices: Vec<usize>,
    pub selected_bit: usize,
    pub canonical_leaf: usize,
    pub uniform_program_sha256: String,
    pub uniform_catalogue_id: String,
    pub bits_program_sha256: String,
    pub bits_catalogue_id: String,
    role: String,
    spec: GraphSpec,
    uniform: GraphSpec,
}

fn modulus(role: &str) -> Result<(BigUint, &'static str)> {
    let decimal = match role {
        "pallas_scalar" => {
            "28948022309329048855892746252171976963363056481941647379679742748393362948097"
        }
        "vesta_scalar" => {
            "28948022309329048855892746252171976963363056481941560715954676764349967630337"
        }
        _ => return Err("closed scalar alias requires a Pasta scalar role".into()),
    };
    Ok((
        BigUint::parse_bytes(decimal.as_bytes(), 10).ok_or("scalar modulus decimal")?,
        decimal,
    ))
}

fn fixed_bytes<const N: usize>(value: &BigUint) -> Result<[u8; N]> {
    let raw = value.to_bytes_le();
    if raw.len() > N {
        return Err("closed unsigned integer exceeds its fixed byte width".into());
    }
    let mut result = [0; N];
    result[..raw.len()].copy_from_slice(&raw);
    Ok(result)
}

pub fn alias_values(raw: &[u8; 64], role: &str) -> Result<AliasValues> {
    let (p, _) = modulus(role)?;
    let input = BigUint::from_bytes_le(raw);
    let canonical_quotient = &input / &p;
    let canonical_result = &input % &p;
    let result = &canonical_result + &p;
    if canonical_quotient == BigUint::from(0u32) || result >= (BigUint::from(1u32) << 255usize) {
        return Err("closed alias requires q>0 and c+p below2^255".into());
    }
    let quotient = &canonical_quotient - BigUint::from(1u32);
    if quotient.bits() > 258 || input != &result + &p * &quotient || result < p {
        return Err("closed c+p,q-1 unsigned integer relation differs".into());
    }
    let result_le = fixed_bytes::<32>(&result)?;
    let quotient_le = fixed_bytes::<33>(&quotient)?;
    if quotient_le[32] >= 4 {
        return Err("closed alias quotient exceeds unsigned258 bits".into());
    }
    let mut limbs = [0u32; 9];
    for bit in 0..255 {
        limbs[bit / 29] |= u32::from((result_le[bit / 8] >> (bit % 8)) & 1) << (bit % 29);
    }
    Ok(AliasValues {
        input,
        canonical_result,
        canonical_quotient,
        result,
        quotient,
        result_le,
        quotient_le,
        limbs,
    })
}

/// Independently enumerate the original Uniform word schedule and its closed
/// integer witness. Neither a caller assignment nor an alternative c/q enters.
pub fn expected_uniform_assignment(raw: &[u8; 64], role: &str) -> Result<Vec<u32>> {
    let alias = alias_values(raw, role)?;
    let (p, _) = modulus(role)?;
    let p_bytes = fixed_bytes::<32>(&p)?;
    let mut values = Vec::with_capacity(379);
    values.push(1); // constant/byte-one
    values.extend(raw.iter().map(|value| u32::from(*value)));
    values.extend(raw.iter().map(|value| u32::from(*value))); // input * unit
    values.extend(alias.limbs);
    values.extend(alias.result_le.iter().map(|value| u32::from(*value)));
    for boundary in [29, 58, 87, 116, 145, 174, 203] {
        let (byte, width) = (boundary / 8, boundary % 8);
        let value = u32::from(alias.result_le[byte]);
        values.extend([value & ((1 << width) - 1), value >> width]);
    }
    values.extend(alias.quotient_le.iter().map(|value| u32::from(*value)));
    values.extend([
        u32::from(alias.quotient_le[32] & 3),
        u32::from(alias.quotient_le[32] >> 2),
        CARRY_OFFSET as u32,
    ]);
    if values.len() != 220 || values[218] != 0 {
        return Err("closed alias fixed Uniform declaration prefix differs".into());
    }
    let mut carry = 0i64;
    for column in 0..65 {
        let products: Vec<_> = p_bytes
            .iter()
            .enumerate()
            .filter_map(|(index, coefficient)| {
                (coefficient != &0 && column >= index && column - index < 33)
                    .then(|| i64::from(*coefficient) * i64::from(alias.quotient_le[column - index]))
            })
            .collect();
        let pq = products.iter().sum::<i64>();
        for block in products.chunks(8) {
            let subtotal = block.iter().sum::<i64>();
            if !(0..1 << 19).contains(&subtotal) {
                return Err("closed alias PQ subtotal bound".into());
            }
            values.push(u32::try_from(subtotal)?);
        }
        let input = i64::from(raw.get(column).copied().unwrap_or(0));
        let result = i64::from(alias.result_le.get(column).copied().unwrap_or(0));
        let numerator = input + carry - result - pq;
        if numerator.rem_euclid(256) != 0 {
            return Err("closed alias has a false integer column".into());
        }
        carry = numerator.div_euclid(256);
        let encoded = carry + CARRY_OFFSET;
        if !(0..16384).contains(&encoded) {
            return Err("closed alias carry exceeds unchanged signed range".into());
        }
        values.push(u32::try_from(encoded)?);
    }
    if values.len() != 379 || carry != 0 || values[219] != 8192 || values[378] != 8192 {
        return Err("closed alias Uniform census or either carry endpoint differs".into());
    }
    Ok(values)
}

fn canonical(value: &Value) -> Result<Vec<u8>> {
    fn ordered(value: &Value, depth: usize) -> Result<Value> {
        if depth > 12 {
            return Err("closed alias metadata depth".into());
        }
        Ok(match value {
            Value::Object(object) => {
                let mut keys: Vec<_> = object.keys().collect();
                keys.sort_unstable();
                let mut result = Map::new();
                for key in keys {
                    if !key.is_ascii() {
                        return Err("closed alias metadata ASCII key".into());
                    }
                    result.insert(key.clone(), ordered(&object[key], depth + 1)?);
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
                return Err("closed alias metadata ASCII string".into())
            }
            Value::Number(n) if n.as_i64().is_none() && n.as_u64().is_none() => {
                return Err("closed alias metadata integer".into())
            }
            _ => value.clone(),
        })
    }
    Ok(serde_json::to_vec(&ordered(value, 0)?)?)
}

fn hash(value: &Value) -> Result<String> {
    Ok(hex::encode(sha256::Hash::hash(&canonical(value)?)))
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 192
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.:/-".contains(&b))
}

fn program_digest(spec: &GraphSpec, arithmetic: usize, field: bool) -> Result<String> {
    let (_, decimal) = modulus(&spec.field_role)?;
    let constraints = spec
        .leaves
        .get(..arithmetic)
        .ok_or("alias Program arithmetic prefix")?
        .iter()
        .map(|leaf| {
            let names = leaf
                .wires
                .iter()
                .map(|wire| {
                    spec.words
                        .get(*wire)
                        .map(|word| word.name.clone())
                        .ok_or_else(|| "alias Program wire".into())
                })
                .collect::<Result<Vec<_>>>()?;
            Ok(json!([leaf.kind, names, leaf.argument]))
        })
        .collect::<Result<Vec<_>>>()?;
    let fields = if field {
        json!([[
            "result",
            (129..138)
                .map(|i| spec.words[i].name.clone())
                .collect::<Vec<_>>()
        ]])
    } else {
        json!([])
    };
    hash(
        &json!({"schema":"bitvm2-nova-fixed-trace/v2","field_role":spec.field_role,
        "modulus":decimal,"operation_id":spec.operation_id,"context":spec.context,
        "words":spec.words.iter().map(|word|json!([word.name,word.bound])).collect::<Vec<_>>(),
        "fields":fields,"constraints":constraints}),
    )
}

fn scalar_maps() -> Value {
    json!({"schema":"bitvm2-nova-scalar-bits-maps/v1",
        "input_limb_indices":(0..9).collect::<Vec<_>>(),"bit_indices":(9..264).collect::<Vec<_>>(),
        "selected_index":9,"limb_occurrences":(0..9).map(|i|(i,0)).collect::<Vec<_>>(),
        "bit_occurrences":(0..255).map(|i|(i/29,(29*(i/29+1)).min(255)-i)).collect::<Vec<_>>(),
        "limb_widths":[29,29,29,29,29,29,29,29,23],
        "upstream_uniform":{"component_index":8,"result_word_indices":(129..138).collect::<Vec<_>>(),
            "result_byte_indices":(138..170).collect::<Vec<_>>(),
            "result_reconstruction_occurrences":(0..9).map(|i|(72+i,0)).collect::<Vec<_>>(),
            "field_valid_ordinal":244,"field_valid_occurrences":(0..9).map(|i|(244,i)).collect::<Vec<_>>(),
            "canonicality_required":true},
        "required_limb_global_ids":(0..9).map(|i|format!("c/reduction/result/l{i}")).collect::<Vec<_>>(),
        "bit_global_ids":(0..255).map(|i|format!("c/bits/bit/{i}")).collect::<Vec<_>>(),
        "selected_point_consumers":[[6117,0],[6119,0],[6120,0],[6121,0],[6122,0]],
        "ports":{"input_limbs":(0..9).map(|i|format!("scalar/l{i}")).collect::<Vec<_>>(),
            "bits":(0..255).map(|i|format!("bit/{i}")).collect::<Vec<_>>(),"selected_bit":"bit/0"}})
}

pub fn rebuild(
    spec: &GraphSpec,
    context: &str,
    role: &str,
    operation_id: &str,
    uniform_reference: &GraphSpec,
) -> Result<CheckedAlias> {
    modulus(role)?;
    if !identifier(operation_id)
        || !identifier(&format!("{operation_id}/uniform"))
        || !identifier(&format!("{operation_id}/bits"))
        || hex::encode(id32(context)?) != context
        || spec.context != context
        || spec.field_role != role
        || spec.operation_id != operation_id
        || spec.words.len() != 634
        || spec.leaves.len() != 254
        || uniform_reference.context != context
        || uniform_reference.field_role != role
        || uniform_reference.operation_id != format!("{operation_id}/uniform")
        || uniform_reference.words.len() != 379
        || uniform_reference.leaves.len() != 245
    {
        return Err("closed alias exact source parameters/census required".into());
    }
    let catalogue = hex::encode(spec.identity()?);
    let uniform_catalogue = hex::encode(uniform_reference.identity()?);
    if program_digest(uniform_reference, 244, true)? != uniform_reference.program_sha256
        || spec.words[..379]
            .iter()
            .zip(&uniform_reference.words)
            .any(|(a, b)| a.name != b.name || a.bound != b.bound)
    {
        return Err("closed alias original Uniform words/Program differ".into());
    }
    let uniform_word_map: Vec<_> = (0..379).collect();
    let uniform_leaf_map: Vec<_> = (0..244).chain(std::iter::once(253)).collect();
    for (before, after) in uniform_leaf_map.iter().enumerate() {
        let old = &uniform_reference.leaves[before];
        let new = &spec.leaves[*after];
        if old.kind != new.kind
            || old.argument != new.argument
            || old.wires != new.wires
            || old.body_sha256 != new.body_sha256
            || uniform_reference.bodies.get(&old.body_sha256) != spec.bodies.get(&new.body_sha256)
        {
            return Err("closed alias original Uniform body/alias/leaf projection differs".into());
        }
    }
    if uniform_reference.leaves[244].kind != "field_valid"
        || uniform_reference.leaves[244].wires != (129..138).collect::<Vec<_>>()
    {
        return Err("closed alias must retain the original result field guard".into());
    }
    for i in 0..255 {
        if spec.words[379 + i].name != format!("scalar-alias/bit/{i}")
            || spec.words[379 + i].bound != 2
        {
            return Err("closed alias appended Boolean word schedule differs".into());
        }
    }
    let mut bits = GraphSpec {
        program_sha256: "00".repeat(32),
        context: context.into(),
        field_role: role.into(),
        operation_id: format!("{operation_id}/bits"),
        words: (0..9)
            .map(|i| Word {
                name: format!("scalar/l{i}"),
                bound: BASE,
            })
            .chain((0..255).map(|i| Word {
                name: format!("bit/{i}"),
                bound: 2,
            }))
            .collect(),
        leaves: spec.leaves[244..253].to_vec(),
        bodies: BTreeMap::new(),
    };
    for leaf in &mut bits.leaves {
        for wire in &mut leaf.wires {
            *wire = if (129..138).contains(wire) {
                *wire - 129
            } else if (379..634).contains(wire) {
                9 + *wire - 379
            } else {
                return Err("closed alias bits projection has a foreign word".into());
            };
        }
    }
    let needed: HashSet<_> = bits
        .leaves
        .iter()
        .map(|leaf| leaf.body_sha256.clone())
        .collect();
    bits.bodies = spec
        .bodies
        .iter()
        .filter(|(id, _)| needed.contains(*id))
        .map(|(id, body)| (id.clone(), body.clone()))
        .collect();
    bits.program_sha256 = program_digest(&bits, 9, false)?;
    let checked_bits = crate::scalar_bits::check(
        &bits,
        context,
        role,
        0,
        &format!("{operation_id}/bits"),
        &scalar_maps(),
    )?;
    let program = program_digest(spec, 253, true)?;
    if program != spec.program_sha256 {
        return Err("closed alias parent plain Program identity differs".into());
    }
    let bit_indices: Vec<_> = (379..634).collect();
    let maps = json!({"schema":"bitvm2-nova-closed-scalar-alias/v1",
        "uniform_word_map":uniform_word_map,"uniform_leaf_map":uniform_leaf_map,
        "bits_word_map":(129..138).chain(379..634).collect::<Vec<_>>(),"bits_leaf_map":(244..253).collect::<Vec<_>>(),
        "field_valid_ordinal":253,"selected_bit_index":379,
        "uniform_program_sha256":uniform_reference.program_sha256,"uniform_catalogue_id":uniform_catalogue,
        "bits_program_sha256":checked_bits.program_sha256,"bits_catalogue_id":checked_bits.catalogue_id});
    let maps_sha = hash(&maps)?;
    let metadata = json!({"schema":"bitvm2-nova-closed-scalar-alias/v1","context":context,"field_role":role,
        "operation_id":operation_id,"bit_index":0,"program_sha256":program,"catalogue_id":catalogue,
        "source_maps_sha256":maps_sha,"words":634,"leaves":254,"arithmetic_predicates":253,"field_valid_ordinal":253,
        "construction":"closed c+p,q-1 only; fresh Uniform and scalar bits children",
        "production_assertion_binding":false,"proof_verified":false,"bitcoin_transaction_graph":false});
    let mut source = sha256::Hash::engine();
    source.input(DOMAIN);
    source.input(&canonical(&metadata)?);
    Ok(CheckedAlias {
        source_maps: maps,
        metadata,
        source_sha256: hex::encode(sha256::Hash::from_engine(source)),
        source_maps_sha256: maps_sha,
        program_sha256: program,
        catalogue_id: catalogue,
        uniform_word_map,
        uniform_leaf_map,
        bit_indices,
        selected_bit: 379,
        canonical_leaf: 253,
        uniform_program_sha256: uniform_reference.program_sha256.clone(),
        uniform_catalogue_id: uniform_catalogue,
        bits_program_sha256: checked_bits.program_sha256,
        bits_catalogue_id: checked_bits.catalogue_id,
        role: role.into(),
        spec: spec.clone(),
        uniform: uniform_reference.clone(),
    })
}

/// Optional explicit map transport check. The private runner uses `rebuild`
/// directly and pins its computed identities without accepting another file.
pub fn check(
    spec: &GraphSpec,
    context: &str,
    role: &str,
    operation_id: &str,
    raw_maps: &Value,
    uniform_reference: &GraphSpec,
) -> Result<CheckedAlias> {
    let checked = rebuild(spec, context, role, operation_id, uniform_reference)?;
    if raw_maps != &checked.source_maps {
        return Err(
            "closed alias raw source maps differ from exact independent projections".into(),
        );
    }
    Ok(checked)
}

pub fn expected_assignment(checked: &CheckedAlias, raw: &[u8; 64], role: &str) -> Result<Vec<u32>> {
    if role != checked.role {
        return Err("closed alias assignment role differs from checked source".into());
    }
    let mut values = expected_uniform_assignment(raw, role)?;
    for ordinal in 0..245 {
        if truth(&checked.uniform, &values, ordinal)? != Some(ordinal != 244) {
            return Err("closed original Uniform alias must have only field_valid244 false".into());
        }
    }
    let limbs: [u32; 9] = values[129..138]
        .try_into()
        .map_err(|_| "closed alias limb projection")?;
    let bits = crate::scalar_bits::expected_assignment(&limbs, 0, None)?;
    values.extend_from_slice(&bits[9..]);
    for ordinal in 0..254 {
        if truth(&checked.spec, &values, ordinal)? != Some(ordinal != 253) {
            return Err("closed merged scalar alias must have only field_valid253 false".into());
        }
    }
    Ok(values)
}

pub fn truth(spec: &GraphSpec, values: &[u32], ordinal: usize) -> Result<Option<bool>> {
    if values.len() != spec.words.len() {
        return Err("closed alias truth assignment census".into());
    }
    let leaf = spec
        .leaves
        .get(ordinal)
        .ok_or("closed alias truth ordinal")?;
    for wire in &leaf.wires {
        if values.get(*wire).ok_or("closed alias truth value")?
            >= &spec
                .words
                .get(*wire)
                .ok_or("closed alias truth word")?
                .bound
        {
            // The registry's unsigned recovery validity flag makes this a
            // false correctness predicate and a true disproof predicate.
            return Ok(Some(false));
        }
    }
    if leaf.kind == "bits" {
        if leaf.argument.len() != 1
            || !(1..=29).contains(&leaf.argument[0])
            || leaf.wires.len() != leaf.argument[0] as usize + 1
        {
            return Err("closed alias truth malformed bits predicate".into());
        }
        let reconstructed = leaf.wires[1..]
            .iter()
            .fold(0u32, |sum, wire| (sum << 1) | values[*wire]);
        return Ok(Some(values[leaf.wires[0]] == reconstructed));
    }
    Ok(Some(crate::rho_tail::truth(spec, values, ordinal)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closed_integer_alias_is_exact_and_never_field_reduced() {
        for role in ["pallas_scalar", "vesta_scalar"] {
            let (p, _) = modulus(role).unwrap();
            let raw = fixed_bytes::<64>(&p).unwrap();
            let alias = alias_values(&raw, role).unwrap();
            assert_eq!(alias.result, p);
            assert_eq!(alias.quotient, BigUint::from(0u32));
            assert_eq!(alias.canonical_result, BigUint::from(0u32));
            let values = expected_uniform_assignment(&raw, role).unwrap();
            assert_eq!(values.len(), 379);
            assert_eq!(&values[129..138], &alias.limbs);
            assert_eq!(values[219], 8192);
            assert_eq!(values[378], 8192);
            assert!(alias_values(&[0; 64], role).is_err());
            let too_high =
                fixed_bytes::<64>(&(BigUint::from(2u32) * &p - BigUint::from(1u32))).unwrap();
            assert!(alias_values(&too_high, role).is_err());
            let maximal = expected_uniform_assignment(&[255; 64], role).unwrap();
            assert_eq!(maximal.len(), 379);
            assert_eq!(maximal[378], 8192);
        }
    }
}
