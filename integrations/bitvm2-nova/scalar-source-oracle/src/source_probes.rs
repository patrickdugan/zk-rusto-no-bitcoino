//! Closed tiny scalar-source probes, independently reconstructed before keys.
//! These deliberately mutate one authenticated assertion, not the fixed native
//! reference. An ordinary false predicate and decoder-validity failure are
//! distinct from a bare Script VERIFY abort; no panic is caught as rejection.
use crate::{chain, eval_w_encoding, retained_scalar_block, Probe, SourcePrepared};
use bitvm2_nova_script_oracle::{engine::Metrics, wots::Result};
use num_bigint::BigUint;
use serde_json::Value;
use std::{collections::HashSet, path::Path};

const ENCODING_KINDS: [&str; 7] = [
    "eval-w-modulus",
    "eval-w-modulus-plus-one",
    "eval-w-bit255",
    "eval-w-byte-only",
    "eval-w-limb-only",
    "eval-w-split-only",
    "eval-w-byte-u32-max",
];
const TAPE_KINDS: [&str; 4] = [
    "scalar-block-batch-count-low",
    "scalar-block-coefficient-count-low",
    "scalar-block-batch-count-high",
    "scalar-block-byte-256",
];

fn modulus(role: &str) -> Result<[u8; 32]> {
    let encoded = match role {
        "pallas_scalar" => "0100000021eb468cdda89409fc98462200000000000000000000000000000040",
        "vesta_scalar" => "01000000ed302d991bf94c09fc98462200000000000000000000000000000040",
        _ => return Err("closed scalar probe exact Pasta role required".into()),
    };
    Ok(hex::decode(encoded)?
        .try_into()
        .map_err(|_| "modulus size")?)
}
fn encoding_recipe(role: &str, index: usize, reference: &[u8; 32]) -> Result<Vec<u32>> {
    let p = modulus(role)?;
    let raw = match index {
        0 => p,
        1 => {
            let mut value = p;
            value[0] = value[0].checked_add(1).ok_or("modulus-plus-one carry")?;
            value
        }
        2 => {
            let mut value = [0u8; 32];
            value[31] = 128;
            value
        }
        3..=6 => *reference,
        _ => return Err("closed encoding probe index0..6 required".into()),
    };
    let mut values = eval_w_encoding::expected_assignment(&raw);
    match index {
        3 => values[9] ^= 1,
        4 => {
            let scalar = BigUint::from_bytes_le(reference) ^ BigUint::from(1u32);
            if scalar >= BigUint::from_bytes_le(&p) {
                return Err("closed limb-only probe must keep canonical field".into());
            }
            values[0] ^= 1;
        }
        5 => values[41] ^= 1,
        6 => values[9] = u32::MAX,
        _ => {}
    }
    Ok(values)
}
fn tape_recipe(index: usize, reference: &[u8; 112]) -> Result<(Vec<u32>, usize)> {
    let mut values: Vec<_> = reference.iter().map(|b| u32::from(*b)).collect();
    let selected = match index {
        0 => {
            values[32] = 0;
            0
        }
        1 => {
            values[40] = 0;
            8
        }
        2 => {
            values[39] = 1;
            7
        }
        3 => {
            values[0] = 256;
            16
        }
        _ => return Err("closed tape probe index0..3 required".into()),
    };
    Ok((values, selected))
}

pub(crate) fn run(
    p: &Probe,
    root: &Path,
    source: &SourcePrepared,
    reference: &retained_scalar_block::Reference,
    main_keys: &HashSet<[u8; 32]>,
    records: &mut chain::RecordSink,
    metrics: &mut Metrics,
) -> Result<Value> {
    let name = p.name.as_bytes();
    if name.len() != 4
        || !matches!(name[0], b'p' | b'v')
        || name[1] != b'/'
        || !matches!(name[2], b'u' | b't')
        || !name[3].is_ascii_digit()
    {
        return Err("closed p/v u0..6 or t0..3 probe identity required".into());
    }
    let role = if name[0] == b'p' {
        "pallas_scalar"
    } else {
        "vesta_scalar"
    };
    let prefix = if name[0] == b'p' { "p" } else { "v" };
    let index = usize::from(name[3] - b'0');
    let encoding = name[2] == b'u';
    let (component, words, leaves, category, kind) = if encoding {
        (
            12,
            55,
            17,
            "eval-w-encoding",
            *ENCODING_KINDS.get(index).ok_or("closed u probe index")?,
        )
    } else {
        (
            11,
            112,
            112,
            "scalar-block",
            *TAPE_KINDS.get(index).ok_or("closed t probe index")?,
        )
    };
    let original = &source.core.case;
    let (source_sha, maps_sha, program, catalogue) = if encoding {
        let checked = source
            .encoding
            .as_ref()
            .ok_or("fresh independently checked encoder source required")?;
        if source.tape.is_some() {
            return Err("encoder prepared source cannot be a tape".into());
        }
        (
            &checked.source_sha256,
            &checked.source_maps_sha256,
            &checked.program_sha256,
            &checked.catalogue_id,
        )
    } else {
        let checked = source
            .tape
            .as_ref()
            .ok_or("fresh independently checked tape source required")?;
        if source.encoding.is_some() {
            return Err("tape prepared source cannot be an encoder".into());
        }
        (
            &checked.source_sha256,
            &checked.source_maps_sha256,
            &checked.program_sha256,
            &checked.catalogue_id,
        )
    };
    if main_keys.len() != 155_146
        || reference.role != role
        || p.role != role
        || p.field_role != role
        || p.source_case != format!("{prefix}/h")
        || p.source_component != Some(component)
        || p.category != category
        || p.kind != kind
        || p.words != words
        || p.leaves != leaves
        || !p.inputs.as_object().is_some_and(|v| v.is_empty())
        || p.operation_id != original.spec.operation_id
        || p.source_sha256 != *source_sha
        || p.source_maps_sha256 != *maps_sha
        || p.program_sha256 != *program
        || p.catalogue_id != *catalogue
        || original.spec.words.len() != words
        || original.spec.leaves.len() != leaves
        || original.spec.field_role != role
        || original.spec.program_sha256 != *program
        || hex::encode(original.spec.identity()?) != *catalogue
    {
        return Err(
            "private source probe must retain its exact honest source/role/identity inventory"
                .into(),
        );
    }
    // A prepared source is not a claimed assignment oracle. Recompute its
    // actual honest assignment from the independently admitted reference too.
    let positive = if encoding {
        eval_w_encoding::expected_assignment(&reference.eval_w)
    } else {
        reference.expected_assignment()
    };
    if original.words != positive {
        return Err("prepared positive source differs from the fixed native reference".into());
    }
    let (expected, tape_selected) = if encoding {
        (encoding_recipe(role, index, &reference.eval_w)?, None)
    } else {
        let (values, ordinal) = tape_recipe(index, &reference.raw_span)?;
        (values, Some(ordinal))
    };
    let raw = chain::checked_file(
        root,
        &p.filename,
        chain::INPUT_CAP,
        &p.file_sha256,
        p.file_bytes,
    )?;
    let case: chain::permutation::Case = serde_json::from_slice(&raw)?;
    drop(raw);
    if case.name != p.name
        || !case.measure_all
        || case.expected_spec_id != *catalogue
        || case.spec.context != original.spec.context
        || case.spec.field_role != role
        || case.spec.operation_id != p.operation_id
        || case.spec.program_sha256 != *program
        || serde_json::to_value(&case.spec)? != serde_json::to_value(&original.spec)?
        || hex::encode(case.spec.identity()?) != *catalogue
        || case.words != expected
    {
        return Err("closed private source case must preserve every source word/body/map and numeric recipe".into());
    }
    let mut truth = Vec::with_capacity(leaves);
    for ordinal in 0..leaves {
        truth.push(if encoding {
            eval_w_encoding::truth(&case.spec, &expected, ordinal)?
        } else {
            retained_scalar_block::truth(&case.spec, &expected, ordinal)?
        });
    }
    let false_ordinals: Vec<_> = truth
        .iter()
        .enumerate()
        .filter_map(|(i, correct)| (!*correct).then_some(i))
        .collect();
    let selected = *false_ordinals
        .first()
        .ok_or("closed private source probe must actually refute a predicate")?;
    if p.expected_false != false_ordinals
        || !p.expected_abort_ordinals.is_empty()
        || p.selected_leaf != selected
        || p.expected_selected_correct
        || tape_selected.is_some_and(|expected| expected != selected)
    {
        return Err(
            "private source false/abort/selected observation differs from independent truth".into(),
        );
    }
    let checks: Vec<_> = if encoding {
        (0..17).collect()
    } else {
        vec![selected]
    };
    if (encoding && (p.execution_mode != "all" || p.selected_ordinals.is_some()))
        || (!encoding
            && (p.execution_mode != "selected" || p.selected_ordinals.as_ref() != Some(&checks)))
        || case.checks.len() != checks.len()
        || case.checks.iter().zip(checks).any(|(check, ordinal)| {
            check.ordinal != ordinal || check.expected_correct != truth[ordinal]
        })
    {
        return Err("private source ordered execution checks differ from the closed policy".into());
    }
    crate::execute_private(p, &case, main_keys, records, metrics)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unsigned_noncanonical_probes_preserve_the_exact256bit_integer() {
        for role in ["pallas_scalar", "vesta_scalar"] {
            let p = modulus(role).unwrap();
            for index in 0..3 {
                let values = encoding_recipe(role, index, &[0; 32]).unwrap();
                assert_eq!(values.len(), 55);
                if index == 0 {
                    assert_eq!(&values[9..41], p.map(u32::from).as_slice());
                }
                if index == 1 {
                    assert_eq!(values[9], 2);
                }
                if index == 2 {
                    assert_eq!(values[40], 128);
                    assert_eq!(values[8], 1 << 23);
                }
            }
        }
    }
    #[test]
    fn closed_single_word_encoding_faults_do_not_rewitness_other_words() {
        let reference = [1u8; 32];
        let positive = eval_w_encoding::expected_assignment(&reference);
        for (index, slot) in [(3, 9), (4, 0), (5, 41), (6, 9)] {
            let changed = encoding_recipe("pallas_scalar", index, &reference).unwrap();
            assert_eq!(
                positive
                    .iter()
                    .zip(&changed)
                    .enumerate()
                    .filter_map(|(i, (a, b))| (a != b).then_some(i))
                    .collect::<Vec<_>>(),
                [slot]
            );
        }
    }
    #[test]
    fn tape_faults_have_the_closed_value_and_selected_ordinal() {
        let mut raw = [0u8; 112];
        raw[32] = 19;
        raw[40] = 2;
        for (index, slot, value, ordinal) in
            [(0, 32, 0, 0), (1, 40, 0, 8), (2, 39, 1, 7), (3, 0, 256, 16)]
        {
            let (values, selected) = tape_recipe(index, &raw).unwrap();
            assert_eq!(selected, ordinal);
            assert_eq!(values[slot], value);
            assert_eq!(
                values
                    .iter()
                    .zip(raw)
                    .enumerate()
                    .filter_map(|(i, (a, b))| (*a != u32::from(b)).then_some(i))
                    .collect::<Vec<_>>(),
                [slot]
            );
        }
    }
}
