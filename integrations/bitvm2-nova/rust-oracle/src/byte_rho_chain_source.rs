//! Independent compact outer source assembly for the nine BYTE-rho chain components.
//!
//! The worker supplies facts freshly derived from independently validated actual
//! component bytes. These types are not an imported-receipt acceptance boundary.
//! No keys, signatures, full graph allocation or proof acceptance lives here.
use bitcoin::hashes::{sha256, Hash};
use bitvm2_nova_script_oracle::wots::{id32, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet, HashSet};

const SOURCE_DOMAIN: &[u8] = b"BITVM2-NOVA/BYTE-RHO-CHAIN-SOURCE/v1\0";
const MAP_CAP: usize = 8 << 20;
const MANIFEST_CAP: usize = 1 << 20;
const BASE: u32 = 1 << 29;
pub const ORDER: [&str; 9] = [
    "rho-hi",
    "rho-lo",
    "rho-tail",
    "c-coeff-frame",
    "c-prefix",
    "c-absorb",
    "c-hi",
    "c-lo",
    "c-uniform",
];
pub const SIZES: [(usize, usize); 9] = [
    (29445, 29245),
    (29445, 29245),
    (587, 453),
    (187, 111),
    (29445, 29245),
    (23, 9),
    (29445, 29245),
    (29445, 29245),
    (379, 245),
];
const FULL: [usize; 5] = [0, 1, 4, 6, 7];
const PREFIX: [usize; 9] = [0, 1, 2, 3, 4, 5, 6, 7, 135];
const COMMON: [usize; 8] = [0, 1, 2, 3, 4, 5, 7, 135];

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentDescriptor {
    pub index: usize,
    pub branch: String,
    pub kind: String,
    pub operation_id: String,
    pub program_sha256: String,
    pub catalogue_id: String,
    pub source_sha256: String,
    pub source_maps_sha256: String,
    pub global_ids_sha256: String,
    pub words: usize,
    pub leaves: usize,
    pub counter: u64,
    pub field_role: String,
    pub program_identity_kind: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Interface {
    pub word_index: usize,
    pub global_id: String,
    pub bound: u32,
    pub occurrences: Vec<(usize, usize)>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentFacts {
    pub index: usize,
    pub branch: String,
    pub global_ids_sha256: String,
    pub input_indices: Vec<usize>,
    pub output_indices: Vec<usize>,
    pub producer_ordinals: Vec<usize>,
    pub producer_occurrences: Vec<usize>,
    pub interfaces: Vec<Interface>,
}

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
        return Err("canonical lowercase32 source identity required".into());
    }
    Ok(())
}
fn decimal(text: &str, high: usize) -> Result<usize> {
    let value: usize = text.parse()?;
    if value > high || value.to_string() != text {
        return Err("canonical bounded decimal component required".into());
    }
    Ok(value)
}
fn state_local(state: usize, byte: usize) -> String {
    format!("byte-state/{state}/l{}/byte{}", byte / 8, byte % 8)
}
fn parse_local(local: &str) -> Result<Option<(usize, usize)>> {
    if !identifier(local) {
        return Err("canonical BYTE local identity required".into());
    }
    if let Some(tail) = local.strip_prefix("byte-state/") {
        let parts: Vec<_> = tail.split('/').collect();
        if parts.len() != 3 {
            return Err("exact BYTE state/lane/byte identity required".into());
        }
        let state = decimal(parts[0], 24)?;
        let lane = decimal(parts[1].strip_prefix('l').ok_or("lane prefix")?, 24)?;
        let byte = decimal(parts[2].strip_prefix("byte").ok_or("byte prefix")?, 7)?;
        return Ok(Some((state, 8 * lane + byte)));
    }
    let tail = local
        .strip_prefix("byte-round/")
        .ok_or("absolute BYTE round prefix")?;
    let (round, suffix) = tail.split_once('/').ok_or("nonempty BYTE round suffix")?;
    decimal(round, 23)?;
    if suffix.is_empty() {
        return Err("nonempty BYTE round suffix required".into());
    }
    Ok(None)
}
fn old_rho_id(branch: &str, local: &str) -> Result<String> {
    if !["hi", "lo"].contains(&branch) {
        return Err("explicit rho branch required".into());
    }
    if let Some((0, byte)) = parse_local(local)? {
        if (1..33).contains(&byte) {
            return Ok(format!("message/eval_w/byte/{}", byte - 1));
        }
        if (45..109).contains(&byte) {
            return Ok(format!("message/prior_state/byte/{}", byte - 45));
        }
    }
    Ok(format!("branch/{branch}/{local}"))
}
pub fn rho_raw_global_id(index: usize) -> Result<String> {
    if index >= 64 {
        return Err("rho raw BYTE index0..63 required".into());
    }
    Ok(format!(
        "rho/{}",
        old_rho_id(
            if index < 32 { "lo" } else { "hi" },
            &state_local(24, index % 32)
        )?
    ))
}
pub fn coefficient_global_id(degree: usize, byte: usize) -> Result<String> {
    if ![0, 2].contains(&degree) || byte >= 32 {
        return Err("coefficient degree0/2 and BYTE0..31 required".into());
    }
    Ok(format!("c/coeff/{degree}/byte/{byte}"))
}
pub fn prefix_id(state: usize, byte: usize) -> Result<String> {
    if state > 24 || byte >= 200 {
        return Err("absolute prefix BYTE state bound".into());
    }
    Ok(format!("c/prefix/{}", state_local(state, byte)))
}
fn common_id(byte: usize) -> String {
    format!("c/suffix/shared/byte/{byte}")
}
pub fn suffix_input_id(branch: &str, byte: usize) -> Result<String> {
    if !["hi", "lo"].contains(&branch) || byte >= 200 {
        return Err("explicit suffix branch/BYTE required".into());
    }
    if COMMON.contains(&byte) {
        return Ok(common_id(byte));
    }
    if branch == "hi" && byte == 6 {
        return Ok("c/suffix/hi/byte/6".to_owned());
    }
    prefix_id(24, byte)
}
pub fn full_global_id(index: usize, local: &str) -> Result<String> {
    if !FULL.contains(&index) {
        return Err("full chain component required".into());
    }
    let parsed = parse_local(local)?;
    let result = match index {
        0 | 1 => format!(
            "rho/{}",
            old_rho_id(if index == 0 { "hi" } else { "lo" }, local)?
        ),
        4 => match parsed {
            Some((0, byte)) if (1..=64).contains(&byte) => {
                coefficient_global_id(if byte <= 32 { 0 } else { 2 }, (byte - 1) % 32)?
            }
            Some((0, byte)) if (77..136).contains(&byte) => rho_raw_global_id(byte - 77)?,
            _ => format!("c/prefix/{local}"),
        },
        _ => {
            let branch = if index == 6 { "hi" } else { "lo" };
            match parsed {
                Some((0, byte)) => suffix_input_id(branch, byte)?,
                _ => format!("c/branch/{branch}/{local}"),
            }
        }
    };
    if !identifier(&result) {
        return Err("projected global identity exceeds existing cap".into());
    }
    Ok(result)
}

/// Project the actual ordered words of an independently checked component.
/// Private names are permitted only after that component's closed topology has
/// been checked; this function is not an arbitrary graph/name admission API.
pub fn global_id(index: usize, local: &str) -> Result<String> {
    if FULL.contains(&index) {
        return full_global_id(index, local);
    }
    if !identifier(local) || ![2, 3, 5, 8].contains(&index) {
        return Err("checked small component/local name required".into());
    }
    let result = match index {
        2 | 8 => {
            if let Some(tail) = local.strip_prefix("input/byte/") {
                let byte = decimal(tail, 63)?;
                if index == 2 {
                    rho_raw_global_id(byte)?
                } else {
                    format!(
                        "c/branch/{}/{}",
                        if byte < 32 { "lo" } else { "hi" },
                        state_local(24, byte % 32)
                    )
                }
            } else if index == 2 && local.starts_with("frame/") {
                let tail = local.strip_prefix("frame/").ok_or("frame prefix")?;
                let (branch, number) = tail.split_once("/byte/").ok_or("rho frame byte grammar")?;
                let byte = decimal(number, 199)?;
                if !rho_frame_positions().contains(&byte) {
                    return Err("fixed rho framing BYTE required".into());
                }
                format!("rho/{}", old_rho_id(branch, &state_local(0, byte))?)
            } else {
                format!(
                    "{}/{}",
                    if index == 2 {
                        "rho/reduction"
                    } else {
                        "c/reduction"
                    },
                    local
                )
            }
        }
        3 => {
            if let Some(tail) = local.strip_prefix("prefix/frame/byte/") {
                let byte = decimal(tail, 199)?;
                if !fixed_prefix(0).iter().any(|(i, _)| *i == byte) {
                    return Err("fixed prefix frame BYTE required".into());
                }
                prefix_id(0, byte)?
            } else if let Some((head, tail)) = local.split_once("/result/encoding/byte/") {
                let degree = decimal(
                    head.strip_prefix("coefficient/")
                        .ok_or("coefficient byte prefix")?,
                    2,
                )?;
                coefficient_global_id(degree, decimal(tail, 31)?)?
            } else {
                format!("c/coeff-frame/{local}")
            }
        }
        5 => {
            if let Some(tail) = local.strip_prefix("prefix/byte/") {
                let byte = decimal(tail, 199)?;
                if !PREFIX.contains(&byte) {
                    return Err("absorption prefix operand".into());
                }
                prefix_id(24, byte)?
            } else if let Some(tail) = local.strip_prefix("raw/byte/") {
                let byte = decimal(tail, 63)?;
                if byte < 59 {
                    return Err("absorption raw tail operand".into());
                }
                rho_raw_global_id(byte)?
            } else if let Some(tail) = local.strip_prefix("shared/byte/") {
                let byte = decimal(tail, 199)?;
                if !COMMON.contains(&byte) {
                    return Err("common absorption output".into());
                }
                common_id(byte)
            } else if local == "hi/selector" {
                "c/suffix/hi/byte/6".to_owned()
            } else {
                return Err("closed absorption word names required".into());
            }
        }
        _ => return Err("small component kind".into()),
    };
    if !identifier(&result) {
        return Err("projected global identity cap".into());
    }
    Ok(result)
}

fn rho_frame_positions() -> Vec<usize> {
    std::iter::once(0)
        .chain(33..45)
        .chain([109, 110])
        .chain(111..200)
        .collect()
}

pub fn component_operation(operation: &str, rho_counter: u64, index: usize) -> Result<String> {
    if index >= 9 || !identifier(operation) || rho_counter == u64::MAX {
        return Err("chain operation/index/counter bound".into());
    }
    Ok(if index < 3 {
        format!(
            "{operation}/rho/counter/{rho_counter}/{}",
            ["hi", "lo", "tail"][index]
        )
    } else {
        format!(
            "{operation}/c/counter/{}/{}",
            rho_counter + 1,
            ["coeff-frame", "prefix", "absorb", "hi", "lo", "uniform"][index - 3]
        )
    })
}
fn full_operation(operation: &str) -> Result<()> {
    if !identifier(operation) {
        return Err("full operation cap".into());
    }
    for block in 0..6 {
        let first = 4 * block;
        let caller = format!("{operation}/block/{block}");
        if !identifier(&caller) || !identifier(&format!("{caller}/rounds/{first}-{}", first + 3)) {
            return Err("derived block operation cap".into());
        }
        for child in 0..4 {
            if !identifier(&format!("{caller}/child/{child}/round/{}", first + child)) {
                return Err("derived absolute round operation cap".into());
            }
        }
    }
    Ok(())
}
fn preflight(context: &str, role: &str, counter: u64, operation: &str) -> Result<()> {
    digest(context)?;
    if counter == u64::MAX
        || !["pallas_scalar", "vesta_scalar"].contains(&role)
        || !identifier(operation)
    {
        return Err("typed nonoverflowing chain policy required".into());
    }
    for index in FULL {
        full_operation(&component_operation(operation, counter, index)?)?;
    }
    for suffix in ["/coefficient/0", "/coefficient/2", "/uniform-reference"] {
        if !identifier(&(component_operation(operation, counter, 3)? + suffix)) {
            return Err("derived coefficient/reference operation cap".into());
        }
    }
    for op in [
        component_operation(operation, counter, 2)? + "/uniform",
        component_operation(operation, counter, 5)?,
        component_operation(operation, counter, 8)?,
    ] {
        if !identifier(&op) {
            return Err("derived small component operation cap".into());
        }
    }
    Ok(())
}

/// Check all nested IDs/counter policy before the worker loads any component.
pub fn validate_policy(
    context: &str,
    role: &str,
    rho_counter: u64,
    operation_id: &str,
) -> Result<()> {
    preflight(context, role, rho_counter, operation_id)
}

pub fn fixed_prefix(counter: u64) -> Vec<(usize, u32)> {
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
fn rho_frames(branch: &str) -> Result<Vec<String>> {
    std::iter::once(0)
        .chain(33..45)
        .chain([109, 110])
        .chain(111..200)
        .map(|i| Ok(format!("rho/{}", old_rho_id(branch, &state_local(0, i))?)))
        .collect()
}
fn messages() -> Vec<String> {
    (0..32)
        .map(|i| format!("rho/message/eval_w/byte/{i}"))
        .chain((0..64).map(|i| format!("rho/message/prior_state/byte/{i}")))
        .collect()
}
fn raw_ids() -> Result<Vec<String>> {
    (0..64).map(rho_raw_global_id).collect()
}

fn canonical(value: &Value) -> Result<Vec<u8>> {
    fn ordered(v: &Value, depth: usize) -> Result<Value> {
        if depth > 16 {
            return Err("chain source canonical depth cap".into());
        }
        Ok(match v {
            Value::Object(values) => {
                let mut keys: Vec<_> = values.keys().collect();
                keys.sort_unstable();
                let mut result = Map::new();
                for key in keys {
                    if !key.is_ascii() {
                        return Err("ASCII chain source key required".into());
                    }
                    result.insert(key.clone(), ordered(&values[key], depth + 1)?);
                }
                Value::Object(result)
            }
            Value::Array(values) => Value::Array(
                values
                    .iter()
                    .map(|x| ordered(x, depth + 1))
                    .collect::<Result<_>>()?,
            ),
            Value::String(text) if !text.is_ascii() => {
                return Err("ASCII chain source string required".into())
            }
            Value::Number(n) if n.as_i64().is_none() && n.as_u64().is_none() => {
                return Err("canonical source integer required".into())
            }
            other => other.clone(),
        })
    }
    Ok(serde_json::to_vec(&ordered(value, 0)?)?)
}
fn hash(value: &Value) -> Result<String> {
    Ok(sha256::Hash::hash(&canonical(value)?).to_string())
}

fn descriptor(
    d: &ComponentDescriptor,
    f: &ComponentFacts,
    index: usize,
    role: &str,
    counter: u64,
    operation: &str,
) -> Result<()> {
    let full = FULL.contains(&index);
    let kind = if full {
        "full-permutation"
    } else {
        match index {
            2 => "uniform-framing-tail",
            3 => "canonical-coefficients-frame",
            5 => "suffix-absorption",
            8 => "uniform-reduction",
            _ => return Err("component kind".into()),
        }
    };
    let identity = if full {
        "domain-separated manifest hash; not Program.digest"
    } else if index == 5 {
        "ByteProgram.digest (byte-v1)"
    } else {
        "ConvolutionProgram.digest (fixed-trace/v2)"
    };
    if d.index != index
        || d.branch != ORDER[index]
        || d.kind != kind
        || d.operation_id != component_operation(operation, counter, index)?
        || d.counter != if index < 3 { counter } else { counter + 1 }
        || d.field_role != role
        || d.program_identity_kind != identity
        || (d.words, d.leaves) != SIZES[index]
        || f.index != index
        || f.branch != ORDER[index]
        || d.global_ids_sha256 != f.global_ids_sha256
    {
        return Err("closed chain component descriptor/facts policy mismatch".into());
    }
    for s in [
        &d.program_sha256,
        &d.catalogue_id,
        &d.source_sha256,
        &d.source_maps_sha256,
        &d.global_ids_sha256,
    ] {
        digest(s)?;
    }
    Ok(())
}

fn output_producer(byte: usize) -> (usize, usize) {
    // Absolute round23 starts at leaf28025. Nonzero Iota bytes are0,1,3,7.
    if byte < 8 && [0, 1, 3, 7].contains(&byte) {
        (
            29241 + [0, 1, 3, 7].iter().filter(|j| **j < byte).count(),
            1,
        )
    } else {
        (29041 + byte, 2)
    }
}
fn full_interfaces(f: &ComponentFacts) -> Result<()> {
    let inputs: Vec<_> = (0..200).collect();
    let producers: Vec<_> = (0..200).map(output_producer).collect();
    let outputs: Vec<_> = producers.iter().map(|(o, _)| 200 + o).collect();
    if f.input_indices != inputs
        || f.output_indices != outputs
        || f.producer_ordinals != producers.iter().map(|x| x.0).collect::<Vec<_>>()
        || f.producer_occurrences != producers.iter().map(|x| x.1).collect::<Vec<_>>()
    {
        return Err("actual natural full ports/producers required".into());
    }
    let mut expected = Vec::new();
    for byte in 0..200 {
        let lane = byte / 8;
        let j = byte % 8;
        let x = lane % 5;
        let y = lane / 5;
        expected.push(Interface {
            word_index: byte,
            global_id: full_global_id(f.index, &state_local(0, byte))?,
            bound: 256,
            occurrences: vec![
                (
                    x * 32 + j * 4 + y.saturating_sub(1),
                    if y == 0 { 0 } else { 1 },
                ),
                (240 + byte, 0),
            ],
        });
        let (ordinal, formal) = output_producer(byte);
        expected.push(Interface {
            word_index: 200 + ordinal,
            global_id: full_global_id(f.index, &state_local(24, byte))?,
            bound: 256,
            occurrences: vec![(ordinal, formal)],
        });
    }
    expected.sort_by_key(|x| x.word_index);
    if f.interfaces != expected {
        return Err("full interface IDs/ordered actual occurrences differ".into());
    }
    Ok(())
}

fn small_interfaces(f: &ComponentFacts) -> Result<()> {
    if !f.input_indices.is_empty()
        || !f.output_indices.is_empty()
        || !f.producer_ordinals.is_empty()
        || !f.producer_occurrences.is_empty()
        || f.interfaces.len() != SIZES[f.index].0
    {
        return Err("small components expose all words and no invented SSA ports".into());
    }
    let ids: Vec<_> = f.interfaces.iter().map(|r| r.global_id.clone()).collect();
    if hash(&json!(ids))? != f.global_ids_sha256 {
        return Err("small full word-map bytes/hash differ".into());
    }
    for (word, row) in f.interfaces.iter().enumerate() {
        if row.word_index != word {
            return Err("complete ordered small interface indices required".into());
        }
        match f.index {
            2 | 8 => {
                if (1..=64).contains(&word) {
                    let expected = if f.index == 2 {
                        rho_raw_global_id(word - 1)?
                    } else {
                        format!(
                            "c/branch/{}/{}",
                            if word <= 32 { "lo" } else { "hi" },
                            state_local(24, (word - 1) % 32)
                        )
                    };
                    if row.global_id != expected
                        || row.bound != 256
                        || row.occurrences != [(word, 0)]
                    {
                        return Err("unchanged uniform input adapter occurrence differs".into());
                    }
                } else if f.index == 2 && word >= 379 {
                    let pos = word - 379;
                    let branch = if pos < 104 { "hi" } else { "lo" };
                    let byte = rho_frame_positions()[pos % 104];
                    let expected = format!("rho/{}", old_rho_id(branch, &state_local(0, byte))?);
                    if row.global_id != expected
                        || row.bound != 256
                        || row.occurrences != [(244 + pos, 0)]
                    {
                        return Err("unchanged rho frame anchor occurrence differs".into());
                    }
                } else if !row.global_id.starts_with(if f.index == 2 {
                    "rho/reduction/"
                } else {
                    "c/reduction/"
                }) {
                    return Err("private uniform namespace required".into());
                }
                if (129..138).contains(&word) {
                    let limb = word - 129;
                    let guard = if f.index == 2 { 452 } else { 244 };
                    if row.bound != BASE || row.occurrences != [(72 + limb, 0), (guard, limb)] {
                        return Err("unchanged uniform canonical result path differs".into());
                    }
                }
            }
            3 => {
                if word >= 110 {
                    let pos = word - 110;
                    let byte = fixed_prefix(0)[pos].0;
                    if row.global_id != prefix_id(0, byte)?
                        || row.bound != 256
                        || row.occurrences != [(32 + pos, 0)]
                    {
                        return Err("prefix constant actual occurrence differs".into());
                    }
                } else {
                    let slot = word / 55;
                    let local = word % 55;
                    let degree = if slot == 0 { 0 } else { 2 };
                    if (9..41).contains(&local) {
                        if row.global_id != coefficient_global_id(degree, local - 9)?
                            || row.bound != 256
                        {
                            return Err("canonical coefficient BYTE port differs".into());
                        }
                    } else if !row.global_id.starts_with("c/coeff-frame/") {
                        return Err("private canonical field/split namespace required".into());
                    }
                    if local < 9
                        && (row.bound != BASE
                            || row.occurrences != [(slot * 16 + 7 + local, 0), (109 + slot, local)])
                    {
                        return Err("canonical coefficient limb-to-guard occurrence differs".into());
                    }
                }
            }
            5 => {
                let (id, occ) = if word < 9 {
                    let byte = PREFIX[word];
                    let ordinal = [0, 1, 2, 3, 4, 5, 8, 6, 7][word];
                    (prefix_id(24, byte)?, (ordinal, 0))
                } else if word < 14 {
                    (rho_raw_global_id(59 + word - 9)?, (word - 9, 1))
                } else {
                    let gate = word - 14;
                    (
                        if gate < 8 {
                            common_id(COMMON[gate])
                        } else {
                            "c/suffix/hi/byte/6".to_owned()
                        },
                        (gate, if gate < 5 { 2 } else { 1 }),
                    )
                };
                if row.global_id != id || row.bound != 256 || row.occurrences != [occ] {
                    return Err("closed nine-gate absorption occurrence differs".into());
                }
            }
            _ => return Err("small component required".into()),
        }
    }
    Ok(())
}
fn check_facts(f: &ComponentFacts) -> Result<()> {
    if f.index >= 9 {
        return Err("component index bound".into());
    }
    let expected = if FULL.contains(&f.index) {
        400
    } else {
        SIZES[f.index].0
    };
    if f.interfaces.len() != expected {
        return Err("bounded compact interface count differs".into());
    }
    let mut names = HashSet::new();
    let mut previous = None;
    for row in &f.interfaces {
        if row.word_index >= SIZES[f.index].0
            || previous.is_some_and(|p| p >= row.word_index)
            || !identifier(&row.global_id)
            || !names.insert(&row.global_id)
            || !(1..=BASE).contains(&row.bound)
            || row.occurrences.is_empty()
            || row.occurrences.len() > 65
        {
            return Err("ordered distinct bounded actual interfaces required".into());
        }
        let mut before = None;
        for cell in &row.occurrences {
            if cell.0 >= SIZES[f.index].1 || cell.1 >= 64 || before.is_some_and(|p| p >= *cell) {
                return Err("ordered bounded actual formal occurrences required".into());
            }
            before = Some(*cell);
        }
        previous = Some(row.word_index);
    }
    if FULL.contains(&f.index) {
        full_interfaces(f)
    } else {
        small_interfaces(f)
    }
}

fn expected_intersection(left: usize, right: usize) -> Result<BTreeSet<String>> {
    let raw = raw_ids()?;
    let values: Vec<String> = match (left, right) {
        (0, 1) => messages(),
        (0, 2) | (1, 2) => {
            let mut v = rho_frames(if left == 0 { "hi" } else { "lo" })?;
            v.extend_from_slice(if left == 0 { &raw[32..] } else { &raw[..32] });
            v
        }
        (0, 4) => raw[32..59].to_vec(),
        (1, 4) => raw[..32].to_vec(),
        (2, 4) => raw[..59].to_vec(),
        (0, 5) | (2, 5) => raw[59..].to_vec(),
        (3, 4) => {
            let mut v = Vec::new();
            for degree in [0, 2] {
                for byte in 0..32 {
                    v.push(coefficient_global_id(degree, byte)?);
                }
            }
            for (byte, _) in fixed_prefix(0) {
                v.push(prefix_id(0, byte)?);
            }
            v
        }
        (4, 5) => PREFIX
            .iter()
            .map(|b| prefix_id(24, *b))
            .collect::<Result<_>>()?,
        (4, 6) | (4, 7) => {
            let branch = if right == 6 { "hi" } else { "lo" };
            let mut v = Vec::new();
            for byte in 0..200 {
                let p = prefix_id(24, byte)?;
                if suffix_input_id(branch, byte)? == p {
                    v.push(p);
                }
            }
            v
        }
        (5, 6) => {
            let mut v: Vec<_> = COMMON.iter().map(|b| common_id(*b)).collect();
            v.push("c/suffix/hi/byte/6".to_owned());
            v
        }
        (5, 7) => {
            let mut v: Vec<_> = COMMON.iter().map(|b| common_id(*b)).collect();
            v.push(prefix_id(24, 6)?);
            v
        }
        (6, 7) => (0..200)
            .filter(|b| *b != 6)
            .map(|b| suffix_input_id("hi", b))
            .collect::<Result<_>>()?,
        (6, 8) | (7, 8) => (0..32)
            .map(|b| {
                format!(
                    "c/branch/{}/{}",
                    if left == 6 { "hi" } else { "lo" },
                    state_local(24, b)
                )
            })
            .collect(),
        _ => Vec::new(),
    };
    Ok(values.into_iter().collect())
}
fn intersections(facts: &[ComponentFacts]) -> Result<Value> {
    let sets: Vec<BTreeSet<_>> = facts
        .iter()
        .map(|f| f.interfaces.iter().map(|r| r.global_id.clone()).collect())
        .collect();
    let mut histogram: BTreeMap<&str, usize> = BTreeMap::new();
    for f in facts {
        for row in &f.interfaces {
            *histogram.entry(&row.global_id).or_default() += 1;
        }
    }
    if histogram.values().filter(|n| **n == 2).count() != 518
        || histogram.values().filter(|n| **n == 3).count() != 264
        || histogram.values().any(|n| *n > 3)
        || histogram.values().map(|n| n - 1).sum::<usize>() != 1046
    {
        return Err("closed782 shared identities /1046 aliases differ".into());
    }
    let mut rows = Vec::new();
    for left in 0..9 {
        for right in left + 1..9 {
            let common: BTreeSet<_> = sets[left].intersection(&sets[right]).cloned().collect();
            if common != expected_intersection(left, right)? {
                return Err("unexpected chain component intersection".into());
            }
            rows.push(json!({"left":left,"right":right,"words":common.len(),"global_ids_sha256":hash(&json!(common.into_iter().collect::<Vec<_>>()))?}));
        }
    }
    Ok(json!(rows))
}

fn connection(facts: &[ComponentFacts], source: usize, target: usize, id: &str) -> Result<Value> {
    let a = facts[source]
        .interfaces
        .iter()
        .find(|r| r.global_id == id)
        .ok_or("missing actual source interface")?;
    let b = facts[target]
        .interfaces
        .iter()
        .find(|r| r.global_id == id)
        .ok_or("missing actual target interface")?;
    if a.bound != 256 || b.bound != 256 {
        return Err("every cross-component port must retain BYTE bounds".into());
    }
    Ok(
        json!({"global_id":id,"source_component":source,"source_word":a.word_index,"source_occurrences":a.occurrences,
        "target_component":target,"target_word":b.word_index,"target_occurrences":b.occurrences}),
    )
}
fn connections(facts: &[ComponentFacts]) -> Result<Value> {
    let mut groups = Map::new();
    let mut emit = |name: &str, cells: Vec<(usize, usize, String)>, count: usize| -> Result<()> {
        if cells.len() != count {
            return Err("closed actual connection census differs".into());
        }
        groups.insert(
            name.to_owned(),
            json!(cells
                .iter()
                .map(|(s, t, id)| connection(facts, *s, *t, id))
                .collect::<Result<Vec<_>>>()?),
        );
        Ok(())
    };
    emit(
        "rho_messages",
        messages().into_iter().map(|id| (0, 1, id)).collect(),
        96,
    )?;
    let mut cells = Vec::new();
    for (index, branch) in [(0, "hi"), (1, "lo")] {
        for id in rho_frames(branch)? {
            cells.push((2, index, id));
        }
    }
    emit("rho_frames", cells, 208)?;
    emit(
        "rho_reduction",
        raw_ids()?
            .into_iter()
            .enumerate()
            .map(|(i, id)| (if i < 32 { 1 } else { 0 }, 2, id))
            .collect(),
        64,
    )?;
    let mut cells = Vec::new();
    for degree in [0, 2] {
        for byte in 0..32 {
            cells.push((3, 4, coefficient_global_id(degree, byte)?));
        }
    }
    emit("coefficients", cells, 64)?;
    emit(
        "prefix_frame",
        fixed_prefix(0)
            .into_iter()
            .map(|(b, _)| Ok((3, 4, prefix_id(0, b)?)))
            .collect::<Result<_>>()?,
        77,
    )?;
    emit(
        "rho_raw_prefix",
        (0..59)
            .map(|i| Ok((if i < 32 { 1 } else { 0 }, 4, rho_raw_global_id(i)?)))
            .collect::<Result<_>>()?,
        59,
    )?;
    emit(
        "rho_raw_absorb",
        (59..64)
            .map(|i| Ok((0, 5, rho_raw_global_id(i)?)))
            .collect::<Result<_>>()?,
        5,
    )?;
    emit(
        "prefix_absorb",
        PREFIX
            .iter()
            .map(|b| Ok((4, 5, prefix_id(24, *b)?)))
            .collect::<Result<_>>()?,
        9,
    )?;
    let mut cells = Vec::new();
    for (index, branch) in [(6, "hi"), (7, "lo")] {
        for byte in 0..200 {
            let p = prefix_id(24, byte)?;
            if suffix_input_id(branch, byte)? == p {
                cells.push((4, index, p));
            }
        }
    }
    emit("prefix_suffix", cells, 383)?;
    let mut cells = Vec::new();
    for index in [6, 7] {
        for byte in COMMON {
            cells.push((5, index, common_id(byte)));
        }
    }
    cells.push((5, 6, "c/suffix/hi/byte/6".to_owned()));
    emit("absorb_suffix", cells, 17)?;
    let mut cells = Vec::new();
    for (index, branch) in [(7, "lo"), (6, "hi")] {
        for byte in 0..32 {
            cells.push((
                index,
                8,
                format!("c/branch/{branch}/{}", state_local(24, byte)),
            ));
        }
    }
    emit("c_reduction", cells, 64)?;
    Ok(Value::Object(groups))
}

pub fn build(
    context: &str,
    role: &str,
    rho_counter: u64,
    operation_id: &str,
    descriptors: &[ComponentDescriptor],
    facts: &[ComponentFacts],
) -> Result<CheckedSource> {
    preflight(context, role, rho_counter, operation_id)?;
    if descriptors.len() != 9 || facts.len() != 9 {
        return Err("nine exact ordered descriptors/fresh facts required".into());
    }
    let mut programs = HashSet::new();
    let mut catalogues = HashSet::new();
    let mut sources = HashSet::new();
    for index in 0..9 {
        descriptor(
            &descriptors[index],
            &facts[index],
            index,
            role,
            rho_counter,
            operation_id,
        )?;
        check_facts(&facts[index])?;
        if !programs.insert(&descriptors[index].program_sha256)
            || !catalogues.insert(&descriptors[index].catalogue_id)
            || !sources.insert(&descriptors[index].source_sha256)
        {
            return Err("distinct component program/catalogue/source identities required".into());
        }
    }
    let pair_intersections = intersections(facts)?;
    let maps = json!({"schema":"bitvm2-nova-byte-rho-chain-maps/v1","components":facts,"pair_intersections":pair_intersections,
        "connections":connections(facts)?,
        "normative_global_maps":{
            "rho":"rho/<unchanged-rho-global-ID>","coefficients":"c/coeff/{0,2}/byte/{0..31}",
            "prefix":"c/prefix/<full-local>; state0coeff/raw slots alias their exact existing ports",
            "common_absorption":"c/suffix/shared/byte/{0,1,2,3,4,5,7,135}","hi_selector":"c/suffix/hi/byte/6; LO6 routes prefix output6",
            "suffix":"c/branch/{hi,lo}/<full-local>; state0 routes actual prefix/absorption ports",
            "reduction":"c/reduction/<unchanged-uniform-local>; input64 aliases LO32||HI32"},
        "first_block":{"rate_bytes":136,"unpadded":true,"raw_rho_prefix_bytes":59,"fixed_byte_indices":fixed_prefix(rho_counter+1).into_iter().map(|x|x.0).collect::<Vec<_>>()},
        "second_block":{"raw_rho_indices":(59..64).collect::<Vec<_>>(),"common_transformed_slots":COMMON,"hi_only_selector_slot":6,"delimiter_slot":7,"rate_end_slot":135,"forwarded_capacity":(136..200).collect::<Vec<_>>()},
        "coefficient_degrees":[0,2],"leaves":147043,"local_declared_words":148401,"unique_global_words":147355,"cached_signature_reuses":1046});
    let raw_maps = canonical(&maps)?;
    if raw_maps.len() > MAP_CAP {
        return Err("compact chain maps exceed unchanged8MiB cap".into());
    }
    let maps_sha = sha256::Hash::hash(&raw_maps).to_string();
    let manifest = json!({"schema":"bitvm2-nova-byte-rho-chain-source/v1","context":context,"field_role":role,
        "operation_id":operation_id,"rho_counter":rho_counter,"c_counter":rho_counter+1,"component_order":ORDER,"components":descriptors,
        "source_maps_sha256":maps_sha,"leaves":147043,"local_declared_words":148401,"unique_global_words":147355,"cached_signature_reuses":1046,
        "message_encoding":"p||c0_LE32||c2_LE32||NoDS||c_counter_LE8||rho_LO32||rho_HI32||c||selector",
        "digest_encoding":"LO32||HI32 unsigned512-bit little-endian",
        "commitment_order":"external context -> source/maps -> global keys -> nine registries -> Scripts -> forest",
        "scope":"RHO to following quadratic c relation; proof/transcript origins and sumcheck equation remain open"});
    let raw = canonical(&manifest)?;
    if raw.len() > MANIFEST_CAP {
        return Err("compact chain manifest exceeds unchanged1MiB cap".into());
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

    #[test]
    fn first_prefix_and_second_capacity_routes_are_exact() {
        let fixed = fixed_prefix(60);
        assert_eq!(fixed.len(), 77);
        assert_eq!(fixed[0], (0, u32::from(b'p')));
        assert_eq!(fixed.iter().find(|x| x.0 == 69).unwrap().1, 60);
        assert!(fixed.iter().filter(|x| x.0 >= 136).all(|x| x.1 == 0));
        for byte in 0..200 {
            let hi = full_global_id(6, &state_local(0, byte)).unwrap();
            let lo = full_global_id(7, &state_local(0, byte)).unwrap();
            assert_eq!(hi == lo, byte != 6);
            if byte >= 136 {
                assert_eq!(hi, prefix_id(24, byte).unwrap());
                assert_eq!(lo, prefix_id(24, byte).unwrap());
            }
        }
        assert_eq!(expected_intersection(4, 6).unwrap().len(), 191);
        assert_eq!(expected_intersection(4, 7).unwrap().len(), 192);
        assert_eq!(expected_intersection(6, 7).unwrap().len(), 199);
        assert_eq!(expected_intersection(5, 7).unwrap().len(), 9);
    }

    #[test]
    fn semantic_c0_c2_and_raw59_plus5_ports_do_not_reverse() {
        for byte in 0..64 {
            assert_eq!(
                full_global_id(4, &state_local(0, byte + 1)).unwrap(),
                coefficient_global_id(if byte < 32 { 0 } else { 2 }, byte % 32).unwrap()
            );
        }
        for byte in 0..59 {
            assert_eq!(
                full_global_id(4, &state_local(0, 77 + byte)).unwrap(),
                rho_raw_global_id(byte).unwrap()
            );
        }
        for byte in 59..64 {
            assert_eq!(
                global_id(5, &format!("raw/byte/{byte}")).unwrap(),
                rho_raw_global_id(byte).unwrap()
            );
        }
        assert_ne!(
            rho_raw_global_id(0).unwrap(),
            rho_raw_global_id(32).unwrap()
        );
        assert_eq!(
            global_id(2, "input/byte/63").unwrap(),
            rho_raw_global_id(63).unwrap()
        );
        assert_eq!(
            global_id(8, "input/byte/32").unwrap(),
            "c/branch/hi/byte-state/24/l0/byte0"
        );
        assert_eq!(
            global_id(3, "coefficient/2/result/encoding/byte/31").unwrap(),
            coefficient_global_id(2, 31).unwrap()
        );
        assert_eq!(
            global_id(3, "prefix/frame/byte/136").unwrap(),
            prefix_id(0, 136).unwrap()
        );
        for (index, name) in [
            (5, "raw/byte/58"),
            (5, "shared/byte/6"),
            (5, "prefix/byte/136"),
            (3, "coefficient/1/result/encoding/byte/0"),
            (2, "frame/hi/byte/1"),
            (4, "byte-state/00/l0/byte0"),
            (4, "byte-state/25/l0/byte0"),
            (4, "byte-round/24/x"),
        ] {
            assert!(global_id(index, name).is_err());
        }
    }

    #[test]
    fn all_nested_operations_and_counter_growth_are_checked_before_facts() {
        let context = "00".repeat(32);
        preflight(&context, "pallas_scalar", 59, "chain").unwrap();
        preflight(&context, "vesta_scalar", u64::MAX - 1, "chain").unwrap();
        assert!(preflight(&context, "pallas_scalar", u64::MAX, "chain").is_err());
        assert!(preflight(&context, "pallas_base", 59, "chain").is_err());
        assert!(preflight(&"AA".repeat(32), "pallas_scalar", 59, "chain").is_err());
        assert!(preflight(&context, "pallas_scalar", 9, &"x".repeat(192)).is_err());
        assert_eq!(
            component_operation("chain", 59, 0).unwrap(),
            "chain/rho/counter/59/hi"
        );
        assert_eq!(
            component_operation("chain", 59, 4).unwrap(),
            "chain/c/counter/60/prefix"
        );
        assert!(build(&context, "pallas_scalar", 59, "chain", &[], &[]).is_err());
    }

    fn symbolic(index: usize, names: Vec<String>) -> ComponentFacts {
        ComponentFacts {
            index,
            branch: ORDER[index].to_owned(),
            global_ids_sha256: "00".repeat(32),
            input_indices: vec![],
            output_indices: vec![],
            producer_ordinals: vec![],
            producer_occurrences: vec![],
            interfaces: names
                .into_iter()
                .enumerate()
                .map(|(word_index, global_id)| Interface {
                    word_index,
                    global_id,
                    bound: 256,
                    occurrences: vec![(0, 0)],
                })
                .collect(),
        }
    }
    fn symbolic_interfaces() -> Vec<ComponentFacts> {
        // Only3176 symbolic interface IDs, never a Program, GraphSpec or MSM.
        let full = |index| -> Vec<String> {
            [0, 24]
                .into_iter()
                .flat_map(|state| (0..200).map(move |b| (state, b)))
                .map(|(s, b)| full_global_id(index, &state_local(s, b)).unwrap())
                .collect()
        };
        let mut rho_tail = raw_ids().unwrap();
        rho_tail.extend(rho_frames("hi").unwrap());
        rho_tail.extend(rho_frames("lo").unwrap());
        rho_tail.extend((0..315).map(|i| format!("rho/reduction/private/{i}")));
        let mut frame = Vec::new();
        for degree in [0, 2] {
            for byte in 0..32 {
                frame.push(coefficient_global_id(degree, byte).unwrap());
            }
        }
        frame.extend(
            fixed_prefix(0)
                .into_iter()
                .map(|(b, _)| prefix_id(0, b).unwrap()),
        );
        frame.extend((0..46).map(|i| format!("c/coeff-frame/private/{i}")));
        let mut absorb: Vec<_> = PREFIX
            .into_iter()
            .map(|b| prefix_id(24, b).unwrap())
            .collect();
        absorb.extend((59..64).map(|b| rho_raw_global_id(b).unwrap()));
        absorb.extend(COMMON.into_iter().map(common_id));
        absorb.push("c/suffix/hi/byte/6".to_owned());
        let mut uniform = Vec::new();
        for branch in ["lo", "hi"] {
            for byte in 0..32 {
                uniform.push(format!("c/branch/{branch}/{}", state_local(24, byte)));
            }
        }
        uniform.extend((0..315).map(|i| format!("c/reduction/private/{i}")));
        vec![
            symbolic(0, full(0)),
            symbolic(1, full(1)),
            symbolic(2, rho_tail),
            symbolic(3, frame),
            symbolic(4, full(4)),
            symbolic(5, absorb),
            symbolic(6, full(6)),
            symbolic(7, full(7)),
            symbolic(8, uniform),
        ]
    }
    #[test]
    fn exact_shared_quotient_has_518_doubles_264_triples_and_no_other_aliases() {
        let mut facts = symbolic_interfaces();
        assert_eq!(
            facts.iter().map(|f| f.interfaces.len()).sum::<usize>(),
            3176
        );
        assert_eq!(intersections(&facts).unwrap().as_array().unwrap().len(), 36);
        let mut histogram = BTreeMap::new();
        for f in &facts {
            for row in &f.interfaces {
                *histogram.entry(row.global_id.clone()).or_insert(0usize) += 1;
            }
        }
        assert_eq!(histogram.values().filter(|v| **v == 2).count(), 518);
        assert_eq!(histogram.values().filter(|v| **v == 3).count(), 264);
        assert_eq!(
            148401 - histogram.values().map(|v| v - 1).sum::<usize>(),
            147355
        );
        facts[7].interfaces[136].global_id = "c/forged/capacity/136".to_owned();
        assert!(intersections(&facts).is_err());
    }

    #[test]
    fn full_ports_use_actual_c_theta_and_scattered_iota_or_chi_formals() {
        let mut f = ComponentFacts {
            index: 4,
            branch: ORDER[4].to_owned(),
            global_ids_sha256: "00".repeat(32),
            input_indices: (0..200).collect(),
            output_indices: vec![],
            producer_ordinals: vec![],
            producer_occurrences: vec![],
            interfaces: vec![],
        };
        for byte in 0usize..200 {
            let lane = byte / 8;
            let x = lane % 5;
            let y = lane / 5;
            let j = byte % 8;
            f.interfaces.push(Interface {
                word_index: byte,
                global_id: full_global_id(4, &state_local(0, byte)).unwrap(),
                bound: 256,
                occurrences: vec![
                    (
                        x * 32 + j * 4 + y.saturating_sub(1),
                        if y == 0 { 0 } else { 1 },
                    ),
                    (240 + byte, 0),
                ],
            });
            let (ordinal, formal) = output_producer(byte);
            f.output_indices.push(200 + ordinal);
            f.producer_ordinals.push(ordinal);
            f.producer_occurrences.push(formal);
            f.interfaces.push(Interface {
                word_index: 200 + ordinal,
                global_id: full_global_id(4, &state_local(24, byte)).unwrap(),
                bound: 256,
                occurrences: vec![(ordinal, formal)],
            });
        }
        f.interfaces.sort_by_key(|r| r.word_index);
        check_facts(&f).unwrap();
        assert_eq!(output_producer(0), (29241, 1));
        assert_eq!(output_producer(8), (29049, 2));
        f.interfaces[136].occurrences[1].1 = 1;
        assert!(check_facts(&f).is_err());
    }

    #[test]
    fn canonical_source_json_is_ascii_integer_bounded_and_sorted() {
        assert_eq!(
            canonical(&json!({"z":u64::MAX,"a":[0,2]})).unwrap(),
            b"{\"a\":[0,2],\"z\":18446744073709551615}"
        );
        assert!(canonical(&json!({"a":"\u{e9}"})).is_err());
        assert!(canonical(&json!({"a":1.25})).is_err());
        let mut value = json!(0);
        for _ in 0..18 {
            value = json!([value]);
        }
        assert!(canonical(&value).is_err());
    }
}
