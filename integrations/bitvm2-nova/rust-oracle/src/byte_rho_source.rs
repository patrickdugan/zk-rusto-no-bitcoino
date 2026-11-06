//! Independent outer BYTE-rho source/map assembly. No keys or proof verdicts.
//!
//! The worker passes facts freshly reconstructed and checked by its independent
//! full-permutation and tail validators. Imported receipts are not authority.
use bitcoin::hashes::{sha256, Hash};
use bitvm2_nova_script_oracle::wots::{id32, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::collections::HashSet;

const SOURCE_DOMAIN: &[u8] = b"BITVM2-NOVA/BYTE-RHO-SOURCE/v1\0";
const MAP_CAP: usize = 8 << 20;
const MANIFEST_CAP: usize = 1 << 20;

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

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentFacts {
    pub index: usize,
    pub branch: String,
    pub global_ids: Vec<String>,
    pub global_ids_sha256: String,
    pub input_indices: Vec<usize>,
    pub output_indices: Vec<usize>,
    pub producer_ordinals: Vec<usize>,
    pub producer_occurrences: Vec<usize>,
    pub input_consumer_occurrences: Vec<Vec<(usize, usize)>>,
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
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.:/-".contains(&byte))
}

fn digest(value: &str) -> Result<()> {
    if hex::encode(id32(value)?) != value {
        return Err("canonical lowercase32-byte source identity required".into());
    }
    Ok(())
}

fn decimal(value: &str, high: usize) -> Result<usize> {
    let number: usize = value.parse()?;
    if number > high || number.to_string() != value {
        return Err("canonical bounded decimal identity component required".into());
    }
    Ok(number)
}

pub fn branch_global_id(branch: &str, local: &str) -> Result<String> {
    if !["hi", "lo"].contains(&branch) || !identifier(local) {
        return Err("explicit branch and canonical local identity required".into());
    }
    if let Some(rest) = local.strip_prefix("byte-state/") {
        let parts: Vec<_> = rest.split('/').collect();
        if parts.len() != 3 {
            return Err("canonical absolute BYTE state identity required".into());
        }
        let state = decimal(parts[0], 24)?;
        let lane = decimal(parts[1].strip_prefix('l').ok_or("lane prefix")?, 24)?;
        let byte = decimal(parts[2].strip_prefix("byte").ok_or("byte prefix")?, 7)?;
        if state == 0 {
            let index = 8 * lane + byte;
            if (1..33).contains(&index) {
                return Ok(format!("message/eval_w/byte/{}", index - 1));
            }
            if (45..109).contains(&index) {
                return Ok(format!("message/prior_state/byte/{}", index - 45));
            }
        }
    } else if let Some(rest) = local.strip_prefix("byte-round/") {
        let (round, suffix) = rest.split_once('/').ok_or("round suffix")?;
        decimal(round, 23)?;
        if suffix.is_empty() {
            return Err("nonempty BYTE round suffix required".into());
        }
    } else {
        return Err("canonical BYTE state/round identity required".into());
    }
    let result = format!("branch/{branch}/{local}");
    if !identifier(&result) {
        return Err("derived branch identity exceeds existing cap".into());
    }
    Ok(result)
}

fn state_id(branch: &str, state: usize, byte: usize) -> Result<String> {
    branch_global_id(
        branch,
        &format!("byte-state/{state}/l{}/byte{}", byte / 8, byte % 8),
    )
}

pub fn fixed_frame(counter: u64, branch: &str) -> Result<Vec<(usize, u32)>> {
    if !["hi", "lo"].contains(&branch) {
        return Err("explicit HI/LO framing branch required".into());
    }
    let mut bytes = [0u8; 200];
    bytes[0] = b'w';
    bytes[33..37].copy_from_slice(b"NoDS");
    bytes[37..45].copy_from_slice(&counter.to_le_bytes());
    bytes[109] = b'r';
    bytes[110] = u8::from(branch == "hi");
    bytes[111] = 1;
    bytes[135] = 128;
    Ok(std::iter::once(0)
        .chain(33..45)
        .chain([109, 110])
        .chain(111..200)
        .map(|index| (index, u32::from(bytes[index])))
        .collect())
}

fn canonical(value: &Value) -> Result<Vec<u8>> {
    fn ordered(value: &Value, depth: usize) -> Result<Value> {
        if depth > 16 {
            return Err("rho source canonical JSON depth cap".into());
        }
        Ok(match value {
            Value::Object(values) => {
                let mut keys: Vec<_> = values.keys().collect();
                keys.sort_unstable();
                let mut result = Map::new();
                for key in keys {
                    if !key.is_ascii() {
                        return Err("rho source ASCII key required".into());
                    }
                    result.insert(key.clone(), ordered(&values[key], depth + 1)?);
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
                return Err("rho source ASCII string required".into());
            }
            Value::Number(number) if number.as_i64().is_none() && number.as_u64().is_none() => {
                return Err("rho source canonical integer required".into());
            }
            other => other.clone(),
        })
    }
    Ok(serde_json::to_vec(&ordered(value, 0)?)?)
}

fn hash(value: &Value) -> Result<String> {
    Ok(sha256::Hash::hash(&canonical(value)?).to_string())
}

fn keys(value: &Value, expected: &[&str]) -> Result<()> {
    let object = value.as_object().ok_or("source object required")?;
    if object.len() != expected.len() || expected.iter().any(|key| !object.contains_key(*key)) {
        return Err("closed rho source object schema required".into());
    }
    Ok(())
}

fn usize_value(value: &Value) -> Result<usize> {
    usize::try_from(value.as_u64().ok_or("unsigned source index required")?)
        .map_err(|_| "source index exceeds usize".into())
}

fn array(value: &Value, count: usize) -> Result<&Vec<Value>> {
    let values = value.as_array().ok_or("source array required")?;
    if values.len() != count {
        return Err("exact bounded source array length required".into());
    }
    Ok(values)
}

fn check_preflight(context: &str, role: &str, counter: u64, operation: &str) -> Result<()> {
    digest(context)?;
    if !["pallas_scalar", "vesta_scalar"].contains(&role) || !identifier(operation) {
        return Err("explicit scalar role and bounded rho operation required".into());
    }
    for branch in ["hi", "lo"] {
        for block in 0..6 {
            let caller = format!("{operation}/counter/{counter}/{branch}/block/{block}");
            let first = 4 * block;
            if !identifier(&format!("{caller}/rounds/{first}-{}", first + 3)) {
                return Err("derived block operation cap".into());
            }
            for child in 0..4 {
                if !identifier(&format!("{caller}/child/{child}/round/{}", first + child)) {
                    return Err("derived absolute round operation cap".into());
                }
            }
        }
    }
    if !identifier(&format!("{operation}/counter/{counter}/tail/uniform")) {
        return Err("derived uniform tail operation cap".into());
    }
    Ok(())
}

fn check_descriptor(
    descriptor: &ComponentDescriptor,
    facts: &ComponentFacts,
    index: usize,
    role: &str,
    counter: u64,
    operation: &str,
) -> Result<()> {
    let branch = ["hi", "lo", "tail"][index];
    let (words, leaves, kind, identity) = if index < 2 {
        (
            29445,
            29245,
            "full-permutation",
            "domain-separated manifest hash; not Program.digest",
        )
    } else {
        (
            587,
            453,
            "uniform-framing-tail",
            "ConvolutionProgram.digest (fixed-trace/v2)",
        )
    };
    if descriptor.index != index
        || descriptor.branch != branch
        || descriptor.kind != kind
        || descriptor.operation_id != format!("{operation}/counter/{counter}/{branch}")
        || descriptor.words != words
        || descriptor.leaves != leaves
        || descriptor.counter != counter
        || descriptor.field_role != role
        || descriptor.program_identity_kind != identity
        || facts.index != index
        || facts.branch != branch
        || facts.global_ids.len() != words
        || facts.global_ids.iter().any(|name| !identifier(name))
        || facts.global_ids.iter().collect::<HashSet<_>>().len() != words
    {
        return Err("rho descriptor/role/counter/operation/count mismatch".into());
    }
    for value in [
        &descriptor.program_sha256,
        &descriptor.catalogue_id,
        &descriptor.source_sha256,
        &descriptor.source_maps_sha256,
        &descriptor.global_ids_sha256,
        &facts.global_ids_sha256,
    ] {
        digest(value)?;
    }
    let actual = hash(&serde_json::to_value(&facts.global_ids)?)?;
    if actual != facts.global_ids_sha256 || actual != descriptor.global_ids_sha256 {
        return Err("actual namespaced global identity hash mismatch".into());
    }
    Ok(())
}

fn check_full(facts: &ComponentFacts) -> Result<()> {
    let branch = facts.branch.as_str();
    let origins = message_ids();
    if facts.input_indices != (0..200).collect::<Vec<_>>()
        || facts.output_indices.len() != 200
        || facts.producer_ordinals.len() != 200
        || facts.producer_occurrences.len() != 200
        || facts.input_consumer_occurrences.len() != 200
    {
        return Err("full source requires exact ordered200 BYTE endpoints".into());
    }
    for name in &facts.global_ids {
        if let Some(local) = name.strip_prefix(&format!("branch/{branch}/")) {
            if branch_global_id(branch, local)? != *name {
                return Err("dynamic message origin was improperly branch-private".into());
            }
        } else if !origins.contains(name) {
            return Err("unexpected global namespace in full rho branch".into());
        }
    }
    // Final-round23 RC is0x8000000080008008. Its four Iota producers are
    // scattered amongst natural Chi outputs; no last200-word shortcut applies.
    let masks = [8u8, 128, 0, 128, 0, 0, 0, 128];
    for slot in 0..200 {
        if facts.global_ids[slot] != state_id(branch, 0, slot)? {
            return Err("full initial byte port/global identity mismatch".into());
        }
        let lane = slot / 8;
        let byte = slot % 8;
        let iota = lane == 0 && masks[byte] != 0;
        let producer = if iota {
            29241 + masks[..byte].iter().filter(|value| **value != 0).count()
        } else {
            29041 + slot
        };
        let formal = if iota { 1 } else { 2 };
        if facts.output_indices[slot] != 200 + producer
            || facts.producer_ordinals[slot] != producer
            || facts.producer_occurrences[slot] != formal
            || facts.global_ids[facts.output_indices[slot]] != state_id(branch, 24, slot)?
        {
            return Err("actual final natural Chi/Iota producer mapping mismatch".into());
        }
        let x = lane % 5;
        let y = lane / 5;
        let expected = vec![
            (x * 32 + byte * 4 + y.saturating_sub(1), usize::from(y != 0)),
            (240 + slot, 0),
        ];
        if facts.input_consumer_occurrences[slot] != expected {
            return Err("initial BYTE must retain both actual C/Theta occurrences".into());
        }
    }
    Ok(())
}

fn message_ids() -> HashSet<String> {
    (0..32)
        .map(|index| format!("message/eval_w/byte/{index}"))
        .chain((0..64).map(|index| format!("message/prior_state/byte/{index}")))
        .collect()
}

fn check_intersections(facts: &[ComponentFacts], counter: u64) -> Result<()> {
    let sets: Vec<HashSet<&str>> = facts
        .iter()
        .map(|item| item.global_ids.iter().map(String::as_str).collect())
        .collect();
    let intersection = |a: usize, b: usize, expected: &HashSet<String>| {
        sets[a].intersection(&sets[b]).count() == expected.len()
            && expected
                .iter()
                .all(|name| sets[a].contains(name.as_str()) && sets[b].contains(name.as_str()))
    };
    if !intersection(0, 1, &message_ids()) {
        return Err("HI/LO must share only96 explicit message origins".into());
    }
    for (index, branch) in ["hi", "lo"].into_iter().enumerate() {
        let mut expected: HashSet<String> = fixed_frame(counter, branch)?
            .iter()
            .map(|(byte, _)| state_id(branch, 0, *byte))
            .collect::<Result<_>>()?;
        for byte in 0..32 {
            expected.insert(state_id(branch, 24, byte)?);
        }
        if expected.len() != 136 || !intersection(index, 2, &expected) {
            return Err("each branch/tail intersection must be104frame+32digest ports".into());
        }
    }
    if sets[0]
        .intersection(&sets[1])
        .any(|name| sets[2].contains(*name))
        || sets
            .iter()
            .flat_map(|set| set.iter().copied())
            .collect::<HashSet<_>>()
            .len()
            != 59109
    {
        return Err("rho global quotient must be triple-empty with59109 words".into());
    }
    Ok(())
}

fn check_tail_maps(tail: &ComponentFacts, maps: &Value, counter: u64) -> Result<()> {
    keys(
        maps,
        &[
            "uniform_word_map",
            "uniform_leaf_map",
            "uniform_program_sha256",
            "uniform_catalogue_id",
            "uniform_metadata_sha256",
            "uniform_ports",
            "frame_anchors",
            "digest_input_indices",
            "result_field_indices",
            "global_ids",
            "global_ids_sha256",
        ],
    )?;
    if canonical(maps)?.len() > MAP_CAP {
        return Err("bounded independently checked tail maps required".into());
    }
    for (index, value) in array(&maps["uniform_word_map"], 379)?.iter().enumerate() {
        if usize_value(value)? != index {
            return Err("all379 original uniform words must remain unchanged".into());
        }
    }
    for (index, value) in array(&maps["uniform_leaf_map"], 245)?.iter().enumerate() {
        if usize_value(value)? != if index == 244 { 452 } else { index } {
            return Err("uniform244 canonical-field leaf must relocate exactly to452".into());
        }
    }
    for key in [
        "uniform_program_sha256",
        "uniform_catalogue_id",
        "uniform_metadata_sha256",
    ] {
        digest(maps[key].as_str().ok_or("uniform source digest string")?)?;
    }
    keys(
        &maps["uniform_ports"],
        &[
            "input_bytes",
            "input_subtotals",
            "quotient_bytes",
            "result_field",
            "result_bytes",
            "carries",
            "quotient_top_low",
            "quotient_top_high",
            "constant_one",
            "pq_blocks",
        ],
    )?;
    array(&maps["global_ids"], 587)?;
    array(&maps["digest_input_indices"], 64)?;
    array(&maps["result_field_indices"], 9)?;
    let ids: Vec<String> = serde_json::from_value(maps["global_ids"].clone())?;
    let input: Vec<usize> = serde_json::from_value(maps["digest_input_indices"].clone())?;
    let output: Vec<usize> = serde_json::from_value(maps["result_field_indices"].clone())?;
    if ids != tail.global_ids
        || maps["global_ids_sha256"].as_str() != Some(tail.global_ids_sha256.as_str())
        || input != (1..65).collect::<Vec<_>>()
        || input != tail.input_indices
        || output != (129..138).collect::<Vec<_>>()
        || output != tail.output_indices
        || !tail.producer_ordinals.is_empty()
        || !tail.producer_occurrences.is_empty()
        || tail.input_consumer_occurrences
            != (1..65)
                .map(|ordinal| vec![(ordinal, 0)])
                .collect::<Vec<_>>()
    {
        return Err("tail digest/result endpoints must match original uniform ports".into());
    }
    for (index, word) in tail.input_indices.iter().enumerate() {
        let branch = if index < 32 { "lo" } else { "hi" };
        if tail.global_ids[*word] != state_id(branch, 24, index % 32)? {
            return Err("tail must consume actual LO32 then HI32 bytes without reversal".into());
        }
    }
    let mut count = 0;
    for branch in ["hi", "lo"] {
        for (byte, expected) in fixed_frame(counter, branch)? {
            let record = &array(&maps["frame_anchors"], 208)?[count];
            keys(
                record,
                &[
                    "branch",
                    "byte_index",
                    "expected",
                    "local_word",
                    "anchor_ordinal",
                    "word_index",
                    "global_id",
                ],
            )?;
            let global = state_id(branch, 0, byte)?;
            if record["branch"] != branch
                || usize_value(&record["byte_index"])? != byte
                || record["expected"].as_u64() != Some(u64::from(expected))
                || record["local_word"] != format!("frame/{branch}/byte/{byte}")
                || usize_value(&record["anchor_ordinal"])? != 244 + count
                || usize_value(&record["word_index"])? != 379 + count
                || record["global_id"] != global
                || tail.global_ids[379 + count] != global
            {
                return Err("exact208 frame constant/index/global aliases required".into());
            }
            count += 1;
        }
    }
    if tail
        .global_ids
        .iter()
        .filter(|name| name.starts_with("reduction/"))
        .count()
        != 315
    {
        return Err("only315 uniform words are private reduction identities".into());
    }
    Ok(())
}

pub fn build(
    context: &str,
    role: &str,
    counter: u64,
    operation_id: &str,
    descriptors: &[ComponentDescriptor],
    facts: &[ComponentFacts],
    tail_maps: &Value,
) -> Result<CheckedSource> {
    check_preflight(context, role, counter, operation_id)?;
    if descriptors.len() != 3 || facts.len() != 3 {
        return Err("exactly HI,LO,tail source records required".into());
    }
    for index in 0..3 {
        check_descriptor(
            &descriptors[index],
            &facts[index],
            index,
            role,
            counter,
            operation_id,
        )?;
    }
    check_full(&facts[0])?;
    check_full(&facts[1])?;
    check_intersections(facts, counter)?;
    check_tail_maps(&facts[2], tail_maps, counter)?;
    let (hi, lo, tail) = (&facts[0], &facts[1], &facts[2]);
    let mut messages = vec![];
    for index in 0..96 {
        let (kind, local, byte) = if index < 32 {
            ("eval_w", index, index + 1)
        } else {
            ("prior_state", index - 32, index - 32 + 45)
        };
        let global_id = format!("message/{kind}/byte/{local}");
        let (hi_word, lo_word) = (hi.input_indices[byte], lo.input_indices[byte]);
        if hi.global_ids[hi_word] != global_id || lo.global_ids[lo_word] != global_id {
            return Err("both hashes must use identical authenticated message origins".into());
        }
        messages.push(json!({"index":index,"kind":kind,"byte_index":local,"global_id":global_id,
            "hi_word":hi_word,"lo_word":lo_word,"hi_consumer_occurrences":hi.input_consumer_occurrences[byte],
            "lo_consumer_occurrences":lo.input_consumer_occurrences[byte]}));
    }
    let mut frames = vec![];
    for (index, record) in array(&tail_maps["frame_anchors"], 208)?.iter().enumerate() {
        let branch = record["branch"].as_str().ok_or("frame branch")?;
        let full = if branch == "hi" { hi } else { lo };
        let byte = usize_value(&record["byte_index"])?;
        let source_word = full.input_indices[byte];
        if full.global_ids[source_word] != record["global_id"] {
            return Err("framing anchors must share actual initial BYTE openings".into());
        }
        frames.push(json!({"index":index,"branch":branch,"byte_index":byte,"expected":record["expected"],
            "global_id":record["global_id"],"source_word":source_word,"tail_word":record["word_index"],
            "anchor_ordinal":record["anchor_ordinal"],"source_consumer_occurrences":full.input_consumer_occurrences[byte]}));
    }
    let mut digests = vec![];
    for (index, tail_word) in tail.input_indices.iter().enumerate() {
        let (branch, full) = if index < 32 { ("lo", lo) } else { ("hi", hi) };
        let byte = index % 32;
        let source_word = full.output_indices[byte];
        let global_id = &full.global_ids[source_word];
        if global_id != &tail.global_ids[*tail_word] {
            return Err("digest source/actual unit adapter global identity mismatch".into());
        }
        digests.push(
            json!({"index":index,"branch":branch,"byte_index":byte,"global_id":global_id,
            "source_word":source_word,"producer_ordinal":full.producer_ordinals[byte],
            "producer_occurrence":full.producer_occurrences[byte],"tail_word":tail_word,
            "consumer_ordinal":1+index,"consumer_occurrence":0}),
        );
    }
    let maps = json!({"schema":"bitvm2-nova-byte-rho-maps/v1","components":facts,
        "messages":messages,"frames":frames,"digests":digests,"uniform":{
            "program_sha256":tail_maps["uniform_program_sha256"],"catalogue_id":tail_maps["uniform_catalogue_id"],
            "metadata_sha256":tail_maps["uniform_metadata_sha256"],"word_map":tail_maps["uniform_word_map"],
            "leaf_map":tail_maps["uniform_leaf_map"],"ports":tail_maps["uniform_ports"]}});
    let raw_maps = canonical(&maps)?;
    if raw_maps.len() > MAP_CAP {
        return Err("raw rho source maps exceed unchanged separate8MiB cap".into());
    }
    let source_maps_sha256 = sha256::Hash::hash(&raw_maps).to_string();
    let manifest = json!({"schema":"bitvm2-nova-byte-rho-source/v1","context":context,
        "field_role":role,"counter":counter,"operation_id":operation_id,"component_order":["hi","lo","tail"],
        "components":descriptors,"source_maps_sha256":source_maps_sha256,
        "message_encoding":"w||eval_W_LE32||NoDS||counter_LE8||prior64||r||selector;Keccak-pad111;zero-capacity64",
        "digest_encoding":"LO32||HI32 unsigned512-bit little-endian","leaves":58943,"unique_global_words":59109,
        "commitment_order":"external context -> source/maps -> global keys -> registries -> Scripts -> forest",
        "scope":"both framed Keccak hashes and unchanged uniform reduction; external proof/transcript origins remain open"});
    let raw = canonical(&manifest)?;
    if raw.len() > MANIFEST_CAP {
        return Err("compact rho source manifest exceeds unchanged1MiB cap".into());
    }
    let mut preimage = SOURCE_DOMAIN.to_vec();
    preimage.extend_from_slice(&raw);
    let source_sha256 = sha256::Hash::hash(&preimage).to_string();
    Ok(CheckedSource {
        maps,
        manifest,
        source_sha256,
        source_maps_sha256,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_frame_partition_counter_and_selectors() {
        for counter in [0, 44, 59, u64::MAX] {
            let hi = fixed_frame(counter, "hi").unwrap();
            let lo = fixed_frame(counter, "lo").unwrap();
            assert_eq!(hi.len(), 104);
            assert_eq!(lo.len(), 104);
            for ((index, high), (other, low)) in hi.iter().zip(&lo) {
                assert_eq!(index, other);
                if *index == 110 {
                    assert_eq!((*high, *low), (1, 0));
                } else {
                    assert_eq!(high, low);
                }
                if (37..45).contains(index) {
                    assert_eq!(*high, u32::from(counter.to_le_bytes()[index - 37]));
                }
                if *index == 111 {
                    assert_eq!(*high, 1);
                }
                if *index == 135 {
                    assert_eq!(*high, 128);
                }
                if *index >= 136 {
                    assert_eq!(*high, 0);
                }
                assert!(!(1..33).contains(index) && !(45..109).contains(index));
            }
        }
    }

    #[test]
    fn explicit96_origin_aliases_and_private_frame_digest_names() {
        let mut shared = 0;
        for byte in 0..200 {
            let hi = state_id("hi", 0, byte).unwrap();
            let lo = state_id("lo", 0, byte).unwrap();
            if (1..33).contains(&byte) || (45..109).contains(&byte) {
                assert_eq!(hi, lo);
                shared += 1;
            } else {
                assert_ne!(hi, lo);
            }
        }
        assert_eq!(shared, 96);
        assert_ne!(
            state_id("hi", 24, 0).unwrap(),
            state_id("lo", 24, 0).unwrap()
        );
        for local in [
            "byte-state/00/l0/byte0",
            "byte-state/25/l0/byte0",
            "byte-round/24/x",
            "byte-round/0/",
            "state/0/l0/b0",
        ] {
            assert!(branch_global_id("hi", local).is_err());
        }
    }

    #[test]
    fn canonical_source_json_rejects_noninteger_nonascii_and_nested_values() {
        assert_eq!(
            canonical(&json!({"z":u64::MAX,"a":[1,2]})).unwrap(),
            b"{\"a\":[1,2],\"z\":18446744073709551615}"
        );
        assert!(canonical(&json!({"a":1.5})).is_err());
        assert!(canonical(&json!({"a":"\u{00e9}"})).is_err());
        let mut value = json!(0);
        for _ in 0..18 {
            value = json!([value]);
        }
        assert!(canonical(&value).is_err());
        assert!(build(&"00".repeat(32), "invalid", 59, "rho", &[], &[], &json!({})).is_err());
    }
}
