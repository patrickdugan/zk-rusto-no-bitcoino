//! Actual assertion captures and independently scheduled BYTE round joins.
//! All registries/material are live, admitted worker objects, not JSON receipts.
use bitvm::signatures::{CompactWots, Wots, Wots4};
use bitvm2_nova_script_oracle::{
    registry::{Registry, Signature},
    wots::{PublicKey, Result},
};
use std::collections::HashSet;

const RC: [u64; 24] = [
    0x1,
    0x8082,
    0x800000000000808a,
    0x8000000080008000,
    0x808b,
    0x80000001,
    0x8000000080008081,
    0x8000000000008009,
    0x8a,
    0x88,
    0x80008009,
    0x8000000a,
    0x8000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x80000001,
    0x8000000080008008,
];

#[derive(Clone)]
pub struct Capture {
    pub id: String,
    pub bound: u32,
    pub value: u32,
    pub key: PublicKey,
    pub signature: Signature,
    pub opening: Vec<Vec<u8>>,
}

/// Constructed by the worker from independently rebuilt round layouts only.
/// This deliberately has no deserializer or public receipt-admission function.
pub struct Join {
    pub producer_occurrences: Vec<(usize, usize)>,
    pub consumer_occurrences: Vec<Vec<(usize, usize)>>,
}

/// Once per registry, before a sequence of captures; do not hash every full
/// registry anew for each one of its thousands of actual opening comparisons.
pub fn validate_material(
    registry: &Registry,
    keys: &[PublicKey],
    sigs: &[Signature],
    values: &[u32],
    ids: &[String],
) -> Result<()> {
    let count = registry.spec().words.len();
    if count == 0
        || keys.len() != count
        || sigs.len() != count
        || values.len() != count
        || ids.len() != count
        || registry.spec().key_identity(keys)? != registry.identity()
        || ids.iter().any(|id| id.is_empty())
    {
        return Err("actual opening material/registry identity differs".into());
    }
    Ok(())
}

pub fn capture(
    registry: &Registry,
    keys: &[PublicKey],
    sigs: &[Signature],
    values: &[u32],
    ids: &[String],
    ordinal: usize,
    formal: usize,
) -> Result<Capture> {
    let spec = registry.spec();
    let count = spec.words.len();
    if keys.len() != count || sigs.len() != count || values.len() != count || ids.len() != count {
        return Err("actual capture material lengths differ".into());
    }
    let leaf = spec.leaves.get(ordinal).ok_or("capture leaf ordinal")?;
    let slot = *leaf.wires.get(formal).ok_or("capture formal occurrence")?;
    let word = spec.words.get(slot).ok_or("capture word index")?;
    if values[slot] >= word.bound || ids[slot].is_empty() {
        return Err("capture word bound or global identity differs".into());
    }
    let unique = registry.unique_slots(ordinal)?;
    let position = unique
        .iter()
        .position(|i| *i == slot)
        .ok_or("capture slot is not in actual witness")?;
    let width = Wots4::TOTAL_DIGIT_LEN as usize;
    let witness = registry.witness(ordinal, sigs)?;
    if witness.len()
        != unique
            .len()
            .checked_mul(width)
            .ok_or("capture witness size overflow")?
    {
        return Err("actual capture witness length differs".into());
    }
    let start = position
        .checked_mul(width)
        .ok_or("capture witness offset overflow")?;
    let opening = witness
        .get(start..start + width)
        .ok_or("capture witness slice")?
        .to_vec();
    let expected: Vec<_> = sigs[slot].iter().map(|digit| digit.to_vec()).collect();
    if opening != expected || opening.iter().any(|digit| digit.len() != 20) {
        return Err("actual unique-slot witness chunk differs from the signed assertion".into());
    }
    Ok(Capture {
        id: ids[slot].clone(),
        bound: word.bound,
        value: values[slot],
        key: keys[slot],
        signature: sigs[slot],
        opening,
    })
}

pub fn same_assertion(left: &Capture, right: &Capture) -> Result<()> {
    if left.id != right.id
        || left.bound != right.bound
        || left.value != right.value
        || left.key != right.key
        || left.signature != right.signature
        || left.opening != right.opening
    {
        return Err("actual ID/bound/value/key/signature/opening assertion link differs".into());
    }
    Ok(())
}

/// These six mutation checks use precisely the comparator used for real links.
/// They are native metadata negatives, not Script execution rejections.
pub fn negatives(entry: &Capture, foreign: &Capture) -> Result<usize> {
    if entry.id == foreign.id || entry.key == foreign.key {
        return Err("cache mutation needs a distinct actual assertion/key".into());
    }
    same_assertion(entry, entry)?;
    let mut cases = Vec::new();
    let mut bad = entry.clone();
    bad.value ^= 1;
    cases.push(bad);
    let mut bad = entry.clone();
    bad.bound = if bad.bound == (1 << 29) {
        bad.bound - 1
    } else {
        bad.bound + 1
    };
    cases.push(bad);
    let mut bad = entry.clone();
    bad.key = foreign.key;
    cases.push(bad);
    let mut bad = entry.clone();
    let first = bad.signature.first_mut().ok_or("cache signature empty")?;
    *first.first_mut().ok_or("cache signature digit empty")? ^= 1;
    cases.push(bad);
    let mut bad = entry.clone();
    let digit = bad.opening.first_mut().ok_or("cache opening empty")?;
    *digit.first_mut().ok_or("cache opening digit empty")? ^= 1;
    cases.push(bad);
    let mut bad = entry.clone();
    bad.id = foreign.id.clone();
    cases.push(bad);
    for bad in &cases {
        if same_assertion(entry, bad).is_ok() {
            return Err("stale or foreign capture substitution accepted".into());
        }
    }
    Ok(cases.len())
}

fn starts() -> [usize; 25] {
    let mut out = [0usize; 25];
    for (r, constant) in RC.iter().enumerate() {
        out[r + 1] = out[r] + 1216 + constant.to_le_bytes().iter().filter(|b| **b != 0).count();
    }
    out
}
fn producer(round: usize, byte: usize, first: usize) -> (usize, usize) {
    let masks = RC[round].to_le_bytes();
    if byte < 8 && masks[byte] != 0 {
        (
            first + 1216 + masks[..byte].iter().filter(|b| **b != 0).count(),
            1,
        )
    } else {
        (first + 1016 + byte, 2)
    }
}
fn consumers(byte: usize, first: usize) -> [(usize, usize); 2] {
    let lane = byte / 8;
    let j = byte % 8;
    let x = lane % 5;
    let y = lane / 5;
    [
        (
            first + 32 * x + 4 * j + y.saturating_sub(1),
            usize::from(y != 0),
        ),
        (first + 240 + byte, 0),
    ]
}

pub fn internal(
    registry: &Registry,
    keys: &[PublicKey],
    sigs: &[Signature],
    values: &[u32],
    ids: &[String],
    joins: &[Join],
) -> Result<(usize, usize, usize)> {
    validate_material(registry, keys, sigs, values, ids)?;
    let spec = registry.spec();
    if joins.len() != 23 || spec.words.len() != 29445 || spec.leaves.len() != 29245 {
        return Err("internal links require one unchanged complete24-round BYTE component".into());
    }
    let firsts = starts();
    if firsts[24] != 29245 {
        return Err("independent full BYTE schedule count differs".into());
    }
    let mut entries = 0;
    let mut links = 0;
    let mut boundary_ids = HashSet::new();
    let mut samples = Vec::new();
    for (r, join) in joins.iter().enumerate() {
        if join.producer_occurrences.len() != 200 || join.consumer_occurrences.len() != 200 {
            return Err("internal state must have exactly200 producer/consumer entries".into());
        }
        let mut state_slots = HashSet::new();
        for byte in 0..200 {
            let expected_producer = producer(r, byte, firsts[r]);
            let expected_consumers = consumers(byte, firsts[r + 1]);
            if join.producer_occurrences[byte] != expected_producer
                || join.consumer_occurrences[byte] != expected_consumers
            {
                return Err(
                    "actual join differs from independent Chi/Iota and C/Theta schedule".into(),
                );
            }
            let (ordinal, formal) = expected_producer;
            let leaf = &spec.leaves[ordinal];
            let mask = if byte < 8 {
                RC[r].to_le_bytes()[byte]
            } else {
                0
            };
            if formal + 1 != leaf.wires.len()
                || leaf.kind
                    != if mask == 0 {
                        "byte_xor"
                    } else {
                        "byte_xor_const"
                    }
                || leaf.argument
                    != if mask == 0 {
                        vec![]
                    } else {
                        vec![i64::from(mask)]
                    }
            {
                return Err(
                    "actual internal producer is not its natural terminal BYTE gate".into(),
                );
            }
            let slot = leaf.wires[formal];
            let expected_name = format!("byte-state/{}/l{}/byte{}", r + 1, byte / 8, byte % 8);
            if spec.words[slot].name != expected_name
                || spec.words[slot].bound != 256
                || !state_slots.insert(slot)
                || !boundary_ids.insert(ids[slot].clone())
            {
                return Err("actual boundary state word/name/BYTE alias differs".into());
            }
            let saved = capture(registry, keys, sigs, values, ids, ordinal, formal)?;
            for (consumer, occurrence) in expected_consumers {
                let leaf = &spec.leaves[consumer];
                if leaf.kind != "byte_xor"
                    || !leaf.argument.is_empty()
                    || leaf.wires.get(occurrence) != Some(&slot)
                {
                    return Err("actual C/Theta consumer does not recover the producer slot".into());
                }
                let used = capture(registry, keys, sigs, values, ids, consumer, occurrence)?;
                same_assertion(&saved, &used)?;
                links += 1;
            }
            entries += 1;
            if samples.len() < 2 {
                samples.push(saved);
            }
        }
        if state_slots.len() != 200 {
            return Err("internal BYTE state is not injective".into());
        }
    }
    if entries != 4600 || links != 9200 || boundary_ids.len() != 4600 {
        return Err("complete internal BYTE opening census differs".into());
    }
    let rejected = negatives(&samples[0], &samples[1])?;
    Ok((entries, links, rejected))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn dummy(id: &str, byte: u8) -> Capture {
        // Synthetic bytes only test comparison, not a valid signature verdict.
        let key: PublicKey = vec![[byte; 20]; Wots4::TOTAL_DIGIT_LEN as usize]
            .try_into()
            .unwrap();
        let signature: Signature =
            vec![[byte.wrapping_add(1); 20]; Wots4::TOTAL_DIGIT_LEN as usize]
                .try_into()
                .unwrap();
        let opening = signature.iter().map(|d| d.to_vec()).collect();
        Capture {
            id: id.into(),
            bound: 256,
            value: 7,
            key,
            signature,
            opening,
        }
    }
    #[test]
    fn all_six_assertion_attributes_are_checked_without_crypto_or_execution() {
        let one = dummy("first", 0);
        let other = dummy("second", 9);
        assert!(same_assertion(&one, &one.clone()).is_ok());
        assert_eq!(negatives(&one, &other).unwrap(), 6);
        assert!(negatives(&one, &one).is_err());
    }
    #[test]
    fn natural_producers_and_actual_consumer_boundaries_are_absolute() {
        let starts = starts();
        assert_eq!(starts[24], 29245);
        assert_eq!(producer(23, 0, starts[23]), (29241, 1));
        assert_eq!(producer(23, 31, starts[23]), (29072, 2));
        assert_eq!(producer(23, 136, starts[23]), (29177, 2));
        assert_eq!(consumers(4, 0), [(16, 0), (244, 0)]);
        assert_eq!(consumers(136, 0), [(66, 1), (376, 0)]);
        assert_eq!(consumers(199, 0), [(159, 1), (439, 0)]);
    }
}
