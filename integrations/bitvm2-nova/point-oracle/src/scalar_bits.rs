//! Independent source/topology/assignment check for the scalar Boolean bridge.
//! No field admission, modulo reduction, keys, Script execution or imported
//! verdicts. The outer source retains Uniform's actual canonicality leaf244.
use bitcoin::{
    hashes::{sha256, Hash, HashEngine},
    script::Builder,
};
use bitvm2_nova_script_oracle::{
    registry::GraphSpec,
    wots::{id32, Result},
};
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;

const BASE: u32 = 1 << 29;
const DOMAIN: &[u8] = b"BITVM2-NOVA/SCALAR-BITS/v1\0";
const POINT_CONSUMERS: [(usize, usize); 5] =
    [(6117, 0), (6119, 0), (6120, 0), (6121, 0), (6122, 0)];

pub struct CheckedBits {
    pub bit_index: usize,
    pub source_maps: Value,
    pub metadata: Value,
    pub source_sha256: String,
    pub source_maps_sha256: String,
    pub program_sha256: String,
    pub catalogue_id: String,
    pub limb_indices: Vec<usize>,
    pub bit_indices: Vec<usize>,
    pub selected_index: usize,
    pub limb_occurrences: Vec<(usize, usize)>,
    pub bit_occurrences: Vec<(usize, usize)>,
    pub selected_point_consumers: Vec<(usize, usize)>,
}

impl CheckedBits {
    pub fn expected_assignment(
        &self,
        limbs: &[u32; 9],
        claimed_bit: Option<u32>,
    ) -> Result<Vec<u32>> {
        expected_assignment(limbs, self.bit_index, claimed_bit)
    }
}

fn canonical(value: &Value) -> Result<Vec<u8>> {
    fn ordered(value: &Value, depth: usize) -> Result<Value> {
        if depth > 12 {
            return Err("scalar bits metadata depth".into());
        }
        Ok(match value {
            Value::Object(object) => {
                let mut keys: Vec<_> = object.keys().collect();
                keys.sort_unstable();
                let mut result = Map::new();
                for key in keys {
                    if !key.is_ascii() {
                        return Err("scalar bits metadata ASCII key".into());
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
                    .map(|value| ordered(value, depth + 1))
                    .collect::<Result<_>>()?,
            ),
            Value::String(text) if !text.is_ascii() => {
                return Err("scalar bits metadata ASCII string".into())
            }
            Value::Number(number) if number.as_i64().is_none() && number.as_u64().is_none() => {
                return Err("scalar bits metadata integer".into())
            }
            _ => value.clone(),
        })
    }
    Ok(serde_json::to_vec(&ordered(value, 0)?)?)
}

fn hash(value: &Value) -> Result<String> {
    Ok(hex::encode(sha256::Hash::hash(&canonical(value)?)))
}

fn scalar_modulus(role: &str) -> Result<&'static str> {
    match role {
        "pallas_scalar" => {
            Ok("28948022309329048855892746252171976963363056481941647379679742748393362948097")
        }
        "vesta_scalar" => {
            Ok("28948022309329048855892746252171976963363056481941560715954676764349967630337")
        }
        _ => Err("scalar bit bridge requires the exact Pasta scalar role".into()),
    }
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 192
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.:/-".contains(&byte))
}

// Independently emit the existing simple bits predicate. Symbolic slots model
// exactly which stack value each PICK copies; there is no Script interpreter.
struct BitsBody {
    code: Vec<u8>,
    stack: Vec<usize>,
    next: usize,
}

impl BitsBody {
    fn number(&mut self, value: i64) {
        self.code
            .extend_from_slice(Builder::new().push_int(value).into_script().as_bytes());
    }

    fn fresh(&mut self) -> usize {
        let variable = self.next;
        self.next += 1;
        self.stack.push(variable);
        variable
    }

    fn literal(&mut self, value: i64) -> usize {
        self.number(value);
        self.fresh()
    }

    fn copy(&mut self, variable: usize) -> Result<()> {
        let position = self
            .stack
            .iter()
            .position(|item| *item == variable)
            .ok_or("bits emitter missing symbolic slot")?;
        self.number(i64::try_from(self.stack.len() - 1 - position)?);
        self.code.push(0x79); // PICK
        self.fresh();
        Ok(())
    }

    fn binary(&mut self, opcode: u8, left: usize, right: usize) -> Result<usize> {
        self.copy(left)?;
        self.copy(right)?;
        self.code.push(opcode);
        self.stack.truncate(self.stack.len() - 2);
        Ok(self.fresh())
    }

    fn range(&mut self, variable: usize, bound: u32) -> Result<()> {
        self.copy(variable)?;
        self.literal(0);
        self.literal(i64::from(bound));
        self.code.push(0xa5); // WITHIN
        self.stack.truncate(self.stack.len() - 3);
        self.code.push(0x69); // VERIFY
        Ok(())
    }
}

fn bits_body(width: usize) -> Result<Vec<u8>> {
    if !matches!(width, 23 | 29) {
        return Err("scalar reconstruction width must be29 or23".into());
    }
    let mut builder = BitsBody {
        code: Vec::new(),
        stack: (0..=width).collect(),
        next: width + 1,
    };
    builder.range(0, BASE)?;
    let mut accumulator = builder.literal(0);
    for bit in 1..=width {
        builder.range(bit, 2)?;
        let doubled = builder.binary(0x93, accumulator, accumulator)?; // ADD
        accumulator = builder.binary(0x93, doubled, bit)?;
    }
    let equal = builder.binary(0x87, accumulator, 0)?; // EQUAL
    builder.copy(equal)?;
    builder.code.push(0x6b); // TOALTSTACK
    builder.stack.pop();
    builder
        .code
        .extend(std::iter::repeat(0x75).take(builder.stack.len())); // DROP
    builder.code.push(0x6c); // FROMALTSTACK
    Ok(builder.code)
}

pub fn check(
    spec: &GraphSpec,
    context: &str,
    role: &str,
    bit_index: usize,
    operation_id: &str,
    raw_maps: &Value,
) -> Result<CheckedBits> {
    let modulus = scalar_modulus(role)?;
    if bit_index >= 255
        || !identifier(operation_id)
        || hex::encode(id32(context)?) != context
        || spec.context != context
        || spec.field_role != role
        || spec.operation_id != operation_id
        || spec.words.len() != 264
        || spec.leaves.len() != 9
    {
        return Err("scalar bits exact parameters/census required".into());
    }
    let catalogue = hex::encode(spec.identity()?);
    let limb_names: Vec<_> = (0..9).map(|i| format!("scalar/l{i}")).collect();
    let bit_names: Vec<_> = (0..255).map(|i| format!("bit/{i}")).collect();
    for (index, word) in spec.words.iter().enumerate() {
        let (name, bound) = if index < 9 {
            (&limb_names[index], BASE)
        } else {
            (&bit_names[index - 9], 2)
        };
        if &word.name != name || word.bound != bound {
            return Err("scalar bits word order/name/bound changed".into());
        }
    }
    let mut expected_bodies = BTreeMap::new();
    let mut constraints = Vec::new();
    let mut widths = Vec::new();
    for (ordinal, leaf) in spec.leaves.iter().enumerate() {
        let low = 29 * ordinal;
        let high = (low + 29).min(255);
        let width = high - low;
        widths.push(width);
        let mut wires = vec![ordinal];
        wires.extend((low..high).rev().map(|bit| 9 + bit));
        let body = bits_body(width)?;
        let body_sha = hex::encode(sha256::Hash::hash(&body));
        if leaf.kind != "bits"
            || leaf.argument != [i64::try_from(width)?]
            || leaf.wires != wires
            || leaf.body_sha256 != body_sha
        {
            return Err("scalar bits exact MSB reconstruction/body differs".into());
        }
        expected_bodies.insert(body_sha, hex::encode(body));
        constraints.push(json!([
            "bits",
            wires
                .iter()
                .map(|wire| spec.words[*wire].name.clone())
                .collect::<Vec<_>>(),
            [width]
        ]));
    }
    if spec.bodies != expected_bodies {
        return Err("scalar bits actual predicate byte catalogue differs".into());
    }
    let program = hash(&json!({"schema":"bitvm2-nova-fixed-trace/v2",
        "field_role":role,"modulus":modulus,"operation_id":operation_id,"context":context,
        "words":spec.words.iter().map(|word|json!([word.name,word.bound])).collect::<Vec<_>>(),
        "fields":[],"constraints":constraints}))?;
    if program != spec.program_sha256 {
        return Err("scalar bits plain Program digest differs".into());
    }
    let limb_indices: Vec<_> = (0..9).collect();
    let bit_indices: Vec<_> = (9..264).collect();
    let limb_occurrences: Vec<_> = (0..9).map(|i| (i, 0)).collect();
    let bit_occurrences: Vec<_> = (0..255)
        .map(|index| (index / 29, (29 * (index / 29 + 1)).min(255) - index))
        .collect();
    let selected_index = 9 + bit_index;
    let maps = json!({"schema":"bitvm2-nova-scalar-bits-maps/v1",
        "input_limb_indices":limb_indices,"bit_indices":bit_indices,"selected_index":selected_index,
        "limb_occurrences":limb_occurrences,"bit_occurrences":bit_occurrences,"limb_widths":widths,
        "upstream_uniform":{"component_index":8,"result_word_indices":(129..138).collect::<Vec<_>>(),
            "result_byte_indices":(138..170).collect::<Vec<_>>(),
            "result_reconstruction_occurrences":(0..9).map(|i|(72+i,0)).collect::<Vec<_>>(),
            "field_valid_ordinal":244,"field_valid_occurrences":(0..9).map(|i|(244,i)).collect::<Vec<_>>(),
            "canonicality_required":true},
        "required_limb_global_ids":(0..9).map(|i|format!("c/reduction/result/l{i}")).collect::<Vec<_>>(),
        "bit_global_ids":(0..255).map(|i|format!("c/bits/bit/{i}")).collect::<Vec<_>>(),
        "selected_point_consumers":POINT_CONSUMERS,
        "ports":{"input_limbs":limb_names,"bits":bit_names,"selected_bit":format!("bit/{bit_index}")}});
    if raw_maps != &maps {
        return Err("scalar bits raw maps differ from the actual independent topology".into());
    }
    let maps_sha = hash(&maps)?;
    let metadata = json!({"schema":"bitvm2-nova-scalar-bits/v1","context":context,
        "field_role":role,"bit_index":bit_index,"operation_id":operation_id,
        "program_sha256":program,"catalogue_id":catalogue,"source_maps_sha256":maps_sha,
        "words":264,"leaves":9,"fields":0,
        "input_encoding":"nine little-endian radix2^29 upstream limbs",
        "bit_order":"public LSB indices0..254; predicate formal operands MSB first per limb",
        "upstream_canonicality_required":true,
        "canonicality_source":"upstream Uniform result field_valid ordinal244; no local field guard",
        "source_authority":false,
        "scope":"upstream limb/Boolean reconstruction only; canonical challenge and point origins require outer joins",
        "canonical_challenge_script_bound":false,"curve_operation_verified":false,
        "scalar_multiplication_verified":false,"transcript_verified":false,"proof_verified":false,
        "production_assertion_binding":false,"bitcoin_transaction_graph":false});
    let mut source = sha256::Hash::engine();
    source.input(DOMAIN);
    source.input(&canonical(&metadata)?);
    Ok(CheckedBits {
        bit_index,
        source_maps: maps,
        metadata,
        source_sha256: hex::encode(sha256::Hash::from_engine(source)),
        source_maps_sha256: maps_sha,
        program_sha256: program,
        catalogue_id: catalogue,
        limb_indices,
        bit_indices,
        selected_index,
        limb_occurrences,
        bit_occurrences,
        selected_point_consumers: POINT_CONSUMERS.to_vec(),
    })
}

/// Preserve all nine original29-bit limbs, including any noncanonical alias.
/// No scalar decode or modular reduction occurs; only the selected bit can be
/// overwritten by the closed diagnostic after the full255-bit reconstruction.
pub fn expected_assignment(
    limbs: &[u32; 9],
    bit_index: usize,
    claimed_bit: Option<u32>,
) -> Result<Vec<u32>> {
    if bit_index >= 255 || limbs.iter().any(|limb| *limb >= BASE) {
        return Err("scalar bits fixed index or BASE-bound input differs".into());
    }
    if claimed_bit.is_some_and(|value| value > 1) {
        return Err("scalar bits claimed bit must be0 or1".into());
    }
    let mut values = limbs.to_vec();
    values.extend((0..255).map(|bit| (limbs[bit / 29] >> (bit % 29)) & 1));
    if let Some(bit) = claimed_bit {
        values[9 + bit_index] = bit;
    }
    Ok(values)
}

pub fn truth(spec: &GraphSpec, values: &[u32], ordinal: usize) -> Result<bool> {
    if spec.words.len() != 264 || spec.leaves.len() != 9 || values.len() != 264 || ordinal >= 9 {
        return Err("scalar bits truth exact assignment/census required".into());
    }
    let leaf = &spec.leaves[ordinal];
    let low = 29 * ordinal;
    let high = (low + 29).min(255);
    let mut wires = vec![ordinal];
    wires.extend((low..high).rev().map(|bit| 9 + bit));
    if leaf.kind != "bits" || leaf.argument != [i64::try_from(high - low)?] || leaf.wires != wires {
        return Err("scalar bits truth exact leaf topology required".into());
    }
    if leaf
        .wires
        .iter()
        .any(|wire| values[*wire] >= spec.words[*wire].bound)
    {
        return Ok(false);
    }
    let reconstructed = leaf.wires[1..]
        .iter()
        .fold(0u32, |value, wire| (value << 1) | values[*wire]);
    Ok(values[ordinal] == reconstructed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pure_assignment_retains_all_limbs_without_field_decode() {
        let limbs = [BASE - 1; 9];
        let values = expected_assignment(&limbs, 254, None).unwrap();
        assert_eq!(&values[..9], &limbs);
        assert_eq!(values.len(), 264);
        assert!(values[9..].iter().all(|bit| *bit == 1));
        // The top limb intentionally retains its six unsupported high bits;
        // the actual23-bit reconstruction will reject them, not truncate it.
        assert_eq!(values[8], BASE - 1);
        assert_ne!(values[8], (1 << 23) - 1);
    }

    #[test]
    fn selected_diagnostic_changes_exactly_one_boolean() {
        for bit_index in [0, 28, 29, 231, 232, 254] {
            let honest = expected_assignment(&[0; 9], bit_index, None).unwrap();
            let changed = expected_assignment(&[0; 9], bit_index, Some(1)).unwrap();
            let changed_slots: Vec<_> = honest
                .iter()
                .zip(&changed)
                .enumerate()
                .filter_map(|(index, (left, right))| (left != right).then_some(index))
                .collect();
            assert_eq!(changed_slots, [9 + bit_index]);
        }
        assert!(expected_assignment(&[0; 9], 255, None).is_err());
        assert!(expected_assignment(&[BASE; 9], 0, None).is_err());
        assert!(expected_assignment(&[0; 9], 0, Some(2)).is_err());
    }
}
