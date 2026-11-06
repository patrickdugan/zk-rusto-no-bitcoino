//! Independent nine-gate BYTE suffix absorption schedule and source identity.
//! No keys, signing, Script execution, receipts or imported roots are created.
use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitvm2_nova_script_oracle::{
    registry::GraphSpec,
    wots::{id32, Result},
};
use serde_json::{json, Map, Value};

const DOMAIN: &[u8] = b"BITVM2-NOVA/BYTE-SUMCHECK-ABSORB/v1\0";
const BYTE_PROGRAM_DOMAIN: &[u8] = b"BITVM2-NOVA/BYTE-TRACE/v1\0";
pub const PREFIX_POSITIONS: [usize; 9] = [0, 1, 2, 3, 4, 5, 6, 7, 135];
pub const COMMON_POSITIONS: [usize; 8] = [0, 1, 2, 3, 4, 5, 7, 135];
const GATE_POSITIONS: [usize; 9] = [0, 1, 2, 3, 4, 5, 7, 135, 6];
// Frozen bare bodies of the unchanged BYTE compiler. The new public mask99
// and the existing masks1/128 have no field-dependent arithmetic. A different
// body cannot be admitted merely by updating an untrusted JSON body digest.
const XOR_BODY: &str = "b4a544526deaf3557478650e8fa05f05b4118116071cf83e9d14553cca5a8e95";
const MASK99_BODY: &str = "ce75d0472d93116fbbc4c0d8833c43a0a595f0b72e85d44253cf70af3b46f538";
const MASK1_BODY: &str = "700a387788d8409796048689ddcddd7af467aab26f7c703b66a9ace21740a730";
const MASK128_BODY: &str = "49d8e0f632bed8422014884d03ebed03db235e73205647e002ac5f2a4784b447";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InputRoute {
    Prefix(usize),
    /// The local assertion slot in the 23-word absorption component.
    Output(usize),
}

pub struct CheckedAbsorb {
    pub source_maps: Value,
    pub source_manifest: Value,
    pub source_sha256: String,
    pub source_maps_sha256: String,
    pub program_sha256: String,
    pub prefix_indices: Vec<usize>,
    pub raw_indices: Vec<usize>,
    pub output_indices: Vec<usize>,
    pub prefix_occurrences: Vec<(usize, usize, usize)>,
    pub raw_occurrences: Vec<(usize, usize, usize)>,
    pub producer_occurrences: Vec<(usize, usize)>,
    pub lo_routes: Vec<InputRoute>,
    pub hi_routes: Vec<InputRoute>,
}

fn canonical(value: &Value) -> Result<Vec<u8>> {
    fn ordered(value: &Value, depth: usize) -> Result<Value> {
        if depth > 16 {
            return Err("absorption canonical nesting bound".into());
        }
        Ok(match value {
            Value::Object(values) => {
                let mut keys: Vec<_> = values.keys().collect();
                keys.sort_unstable();
                let mut result = Map::new();
                for key in keys {
                    if !key.is_ascii() {
                        return Err("absorption ASCII key required".into());
                    }
                    result.insert(
                        key.clone(),
                        ordered(values.get(key).ok_or("absorption object key")?, depth + 1)?,
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
                return Err("absorption ASCII value required".into())
            }
            Value::Number(n) if n.as_i64().is_none() && n.as_u64().is_none() => {
                return Err("absorption integer required".into())
            }
            _ => value.clone(),
        })
    }
    Ok(serde_json::to_vec(&ordered(value, 0)?)?)
}
fn hash(value: &Value) -> Result<String> {
    Ok(sha256::Hash::hash(&canonical(value)?).to_string())
}
fn identifier(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 192
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.:/-".contains(&b))
}
fn modulus(role: &str) -> Result<&'static str> {
    match role {
        "pallas_scalar" => {
            Ok("28948022309329048855892746252171976963363056481941647379679742748393362948097")
        }
        "vesta_scalar" => {
            Ok("28948022309329048855892746252171976963363056481941560715954676764349967630337")
        }
        _ => Err("absorption requires an explicit scalar role".into()),
    }
}
fn prefix_names() -> Vec<String> {
    PREFIX_POSITIONS
        .iter()
        .map(|i| format!("prefix/byte/{i}"))
        .collect()
}
fn raw_names() -> Vec<String> {
    (59..64).map(|i| format!("raw/byte/{i}")).collect()
}
fn output_names() -> Vec<String> {
    COMMON_POSITIONS
        .iter()
        .map(|i| format!("shared/byte/{i}"))
        .chain(std::iter::once("hi/selector".into()))
        .collect()
}
fn prefix_occurrences() -> Vec<(usize, usize, usize)> {
    GATE_POSITIONS
        .iter()
        .enumerate()
        .map(|(i, p)| (*p, i, 0))
        .collect()
}
fn raw_occurrences() -> Vec<(usize, usize, usize)> {
    (0..5).map(|i| (59 + i, i, 1)).collect()
}
fn producers() -> Vec<(usize, usize)> {
    (0..9).map(|i| (i, if i < 5 { 2 } else { 1 })).collect()
}
fn routes(hi: bool) -> Vec<InputRoute> {
    (0..200)
        .map(|i| {
            if let Some(slot) = COMMON_POSITIONS.iter().position(|p| *p == i) {
                InputRoute::Output(14 + slot)
            } else if hi && i == 6 {
                InputRoute::Output(22)
            } else {
                InputRoute::Prefix(i)
            }
        })
        .collect()
}
fn json_routes(hi: bool) -> Vec<Value> {
    routes(hi)
        .iter()
        .map(|r| match r {
            InputRoute::Prefix(i) => json!(["prefix", i]),
            InputRoute::Output(i) => json!(["output", output_names()[*i - 14]]),
        })
        .collect()
}
fn maps() -> Value {
    let outputs = output_names();
    json!({"schema":"bitvm2-nova-byte-sumcheck-absorb-maps/v1",
        "ports":{"prefix_bytes":prefix_names(),"prefix_byte_positions":PREFIX_POSITIONS,
            "raw_bytes":raw_names(),"raw_byte_positions":[59,60,61,62,63],
            "common_outputs":outputs[..8],"common_byte_positions":COMMON_POSITIONS,
            "hi_selector":outputs[8],"gate_outputs":outputs,
            "gate_output_positions":GATE_POSITIONS,"gate_constraints":[0,1,2,3,4,5,6,7,8],
            "prefix_occurrences":prefix_occurrences(),"raw_occurrences":raw_occurrences(),
            "producer_occurrences":producers()},
        "lo_inputs":json_routes(false),"hi_inputs":json_routes(true),
        "shared_final_input_positions":(0..200).filter(|i|*i!=6).collect::<Vec<_>>(),
        "prefix_lo_forward_positions":(0..200).filter(|i|!COMMON_POSITIONS.contains(i)).collect::<Vec<_>>(),
        "prefix_hi_forward_positions":(0..200).filter(|i|!COMMON_POSITIONS.contains(i)&&*i!=6).collect::<Vec<_>>(),
        "capacity_positions":(136..200).collect::<Vec<_>>(),"first_block_unpadded":true,
        "final_capacity_zero_anchored":false,"forwarding_is_structural":true,"value_selected_aliases":false})
}

/// Rebuild the complete static schedule, BYTE body identities and both source hashes.
pub fn check(
    spec: &GraphSpec,
    context: &str,
    role: &str,
    operation: &str,
    raw_maps: &Value,
) -> Result<CheckedAbsorb> {
    if hex::encode(id32(context)?) != context
        || !identifier(operation)
        || spec.context != context
        || spec.field_role != role
        || spec.operation_id != operation
        || spec.words.len() != 23
        || spec.leaves.len() != 9
    {
        return Err("absorption exact catalogue/parameters required".into());
    }
    let decimal = modulus(role)?;
    let all_names: Vec<_> = prefix_names()
        .into_iter()
        .chain(raw_names())
        .chain(output_names())
        .collect();
    if spec
        .words
        .iter()
        .zip(&all_names)
        .any(|(word, name)| word.name != *name || word.bound != 256)
    {
        return Err("absorption exact BYTE declaration order differs".into());
    }
    for (i, leaf) in spec.leaves.iter().enumerate() {
        let (kind, args, wires, body): (&str, Vec<i64>, Vec<usize>, &str) = if i < 5 {
            ("byte_xor", vec![], vec![i, 9 + i, 14 + i], XOR_BODY)
        } else {
            let (input, mask, body) = match i {
                5 => (5, 99, MASK99_BODY),
                6 => (7, 1, MASK1_BODY),
                7 => (8, 128, MASK128_BODY),
                _ => (6, 1, MASK1_BODY),
            };
            ("byte_xor_const", vec![mask], vec![input, 14 + i], body)
        };
        if leaf.kind != kind
            || leaf.argument != args
            || leaf.wires != wires
            || leaf.body_sha256 != body
        {
            return Err(format!("absorption predicate/body/alias schedule differs at {i}").into());
        }
    }
    // identity() also checks every exact body hash, bound, alias and covered word.
    let catalogue = spec.identity()?;
    let declarations: Vec<_> = spec
        .words
        .iter()
        .map(|w| json!([w.name, w.bound]))
        .collect();
    let constraints: Vec<_> = spec
        .leaves
        .iter()
        .map(|l| {
            json!([
                l.kind,
                l.wires
                    .iter()
                    .map(|i| spec.words[*i].name.clone())
                    .collect::<Vec<_>>(),
                l.argument
            ])
        })
        .collect();
    let shape = json!({"schema":"bitvm2-nova-fixed-trace/v2","field_role":role,"modulus":decimal,
        "operation_id":operation,"context":context,"words":declarations,"fields":[],"constraints":constraints});
    let plain = sha256::Hash::hash(&canonical(&shape)?);
    let mut engine = sha256::Hash::engine();
    engine.input(BYTE_PROGRAM_DOMAIN);
    engine.input(plain.as_byte_array());
    let program = sha256::Hash::from_engine(engine).to_string();
    if spec.program_sha256 != program {
        return Err("absorption actual ByteProgram digest differs".into());
    }
    let expected_maps = maps();
    if canonical(raw_maps)? != canonical(&expected_maps)? {
        return Err("absorption canonical routing maps differ".into());
    }
    let maps_sha = hash(&expected_maps)?;
    let manifest = json!({"schema":"bitvm2-nova-byte-sumcheck-absorb/v1","context":context,
        "field_role":role,"operation_id":operation,"program_sha256":program,
        "program_identity_kind":"ByteProgram.digest (byte domain over fixed-trace/v2)",
        "catalogue_id":hex::encode(catalogue),"source_maps_sha256":maps_sha,"words":23,"leaves":9,
        "shared_suffix_transforms":8,"hi_selector_transforms":1,"prefix_input_bytes":9,"raw_tail_bytes":5,
        "capacity_forward_bytes":64,"source_authority":false,"proof_origin_bound":false,
        "full_transcript_verified":false,"production_assertion_binding":false});
    let mut engine = sha256::Hash::engine();
    engine.input(DOMAIN);
    engine.input(&canonical(&manifest)?);
    Ok(CheckedAbsorb {
        source_maps: expected_maps,
        source_manifest: manifest,
        source_sha256: sha256::Hash::from_engine(engine).to_string(),
        source_maps_sha256: maps_sha,
        program_sha256: program,
        prefix_indices: (0..9).collect(),
        raw_indices: (9..14).collect(),
        output_indices: (14..23).collect(),
        prefix_occurrences: prefix_occurrences(),
        raw_occurrences: raw_occurrences(),
        producer_occurrences: producers(),
        lo_routes: routes(false),
        hi_routes: routes(true),
    })
}

/// Full reference assignment for the honest nine-gate relation, without Script.
pub fn assignment_reference(prefix: &[u8; 200], raw: &[u8; 64]) -> Vec<u32> {
    let mut values: Vec<_> = PREFIX_POSITIONS
        .iter()
        .map(|i| u32::from(prefix[*i]))
        .collect();
    values.extend(raw[59..64].iter().map(|b| u32::from(*b)));
    values.extend((0..5).map(|i| u32::from(prefix[i] ^ raw[59 + i])));
    values.extend(
        [
            prefix[5] ^ 99,
            prefix[7] ^ 1,
            prefix[135] ^ 128,
            prefix[6] ^ 1,
        ]
        .into_iter()
        .map(u32::from),
    );
    values
}

/// Route claimed, bounded gate outputs; caller separately checks every predicate.
pub fn route_states(prefix: &[u8; 200], values: &[u32]) -> Result<([u8; 200], [u8; 200])> {
    if values.len() != 23 || values.iter().any(|v| *v >= 256) {
        return Err("absorption assignment BYTE domain".into());
    }
    let mut states = [[0u8; 200]; 2];
    for (branch, state) in states.iter_mut().enumerate() {
        for (i, route) in routes(branch == 1).iter().enumerate() {
            state[i] = match route {
                InputRoute::Prefix(i) => prefix[*i],
                InputRoute::Output(i) => u8::try_from(values[*i])?,
            };
        }
    }
    Ok((states[0], states[1]))
}

pub fn truth(values: &[u32], ordinal: usize) -> Result<bool> {
    if values.len() != 23 || ordinal >= 9 || values.iter().any(|v| *v >= 256) {
        return Err("absorption truth domain/ordinal".into());
    }
    Ok(if ordinal < 5 {
        values[14 + ordinal] == (values[ordinal] ^ values[9 + ordinal])
    } else {
        let (input, mask) = match ordinal {
            5 => (5, 99),
            6 => (7, 1),
            7 => (8, 128),
            _ => (6, 1),
        };
        values[14 + ordinal] == (values[input] ^ mask)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn suffix_rate_and_nonzero_capacity_are_forwarded() {
        let prefix = std::array::from_fn(|i| ((i * 37 + 11) % 256) as u8);
        let raw = std::array::from_fn(|i| ((i * 19 + 7) % 256) as u8);
        let values = assignment_reference(&prefix, &raw);
        let (lo, hi) = route_states(&prefix, &values).unwrap();
        assert_eq!(lo[136..], prefix[136..]);
        assert_eq!(hi[136..], prefix[136..]);
        for i in 0..200 {
            let mask = match i {
                0..=4 => raw[59 + i],
                5 => 99,
                7 => 1,
                135 => 128,
                _ => 0,
            };
            assert_eq!(lo[i], prefix[i] ^ mask);
            assert_eq!(hi[i], lo[i] ^ u8::from(i == 6));
        }
        assert!((0..9).all(|i| truth(&values, i).unwrap()));
        for ordinal in 0..9 {
            let mut bad = values.clone();
            bad[14 + ordinal] ^= 1;
            assert_eq!(
                (0..9)
                    .filter(|i| !truth(&bad, *i).unwrap())
                    .collect::<Vec<_>>(),
                vec![ordinal]
            );
        }
    }
    #[test]
    fn source_routes_share_199_inputs_and_never_reset_capacity() {
        let lo = routes(false);
        let hi = routes(true);
        assert_eq!(lo.iter().zip(&hi).filter(|(l, r)| l == r).count(), 199);
        assert_eq!(
            lo.iter()
                .filter(|r| matches!(r, InputRoute::Prefix(_)))
                .count(),
            192
        );
        assert_eq!(
            hi.iter()
                .filter(|r| matches!(r, InputRoute::Prefix(_)))
                .count(),
            191
        );
        for i in 136..200 {
            assert_eq!(lo[i], InputRoute::Prefix(i));
            assert_eq!(hi[i], InputRoute::Prefix(i));
        }
        assert!(route_states(&[0; 200], &[0; 22]).is_err());
        let mut values = vec![0; 23];
        values[0] = 256;
        assert!(route_states(&[0; 200], &values).is_err());
        assert!(truth(&values, 0).is_err());
        assert!(truth(&[0; 23], 9).is_err());
    }
}
