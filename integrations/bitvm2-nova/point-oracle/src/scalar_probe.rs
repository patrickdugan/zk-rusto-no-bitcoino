//! Closed private c+p,q-1 probe admission before any key generation/execution.
//! The raw challenge is recomputed from the admitted honest chain, and the
//! Uniform child comes from the actual independently checked small rho tail.
//! Numeric inputs, topology, identities and complete truth selection are fixed
//! here; the main worker owns the shared private execution/tree/guard machinery.
use crate::{chain, uniform_alias, Group, Probe, Run};
use bitvm2_nova_script_oracle::{engine::Metrics, wots::Result};
use serde_json::Value;
use std::{collections::HashSet, path::Path};

pub(crate) fn run(
    request: &Probe,
    root: &Path,
    honest: &Group,
    run: &Run,
    basis: &chain::Basis,
    main_keys: &HashSet<[u8; 32]>,
    records: &mut chain::RecordSink,
    metrics: &mut Metrics,
) -> Result<Value> {
    let (prefix, base_role) = match honest.role.as_str() {
        "pallas_scalar" => ("p", "pallas_base"),
        "vesta_scalar" => ("v", "vesta_base"),
        _ => return Err("private scalar alias requires an admitted Pasta scalar role".into()),
    };
    let expected_operation = format!("{}/probe/scalar-alias/{prefix}", run.operation_id);
    if honest.name != format!("{prefix}/h")
        || honest.profile != "honest"
        || honest.base_role != base_role
        || honest.bit_index != 0
        || honest.components.len() != 11
        || request.name != format!("{prefix}/s")
        || request.category != "scalar-alias"
        || request.kind != "scalar-plus-modulus"
        || request.role != honest.role
        || request.field_role != honest.role
        || request.source_case != honest.name
        || request.source_component.is_some()
        || request.operation_id != expected_operation
        || request.words != 634
        || request.leaves != 254
        || request.execution_mode != "all"
        || request.selected_ordinals.is_some()
        || request.expected_false != [253]
        || !request.expected_abort_ordinals.is_empty()
        || request.selected_leaf != 253
        || request.expected_selected_correct
        || main_keys.len() != 155_107
    {
        return Err("private scalar alias must use the exact closed honest-case inventory".into());
    }

    // ScalarInputs admits exactly one canonical LE64 field. Its content must
    // match the independent framed Keccak word reference, not just a header's
    // self-consistent c/q pair or a caller-selected unsigned integer.
    let raw = request.scalar_input()?;
    let references = chain::references(&honest.chain_group())?;
    if raw != references.c_raw {
        return Err(
            "private scalar alias raw input differs from the actual honest challenge".into(),
        );
    }
    drop(references);
    let tail_header = &honest.components[2].descriptor;
    if basis.spec.context != run.context
        || basis.spec.field_role != honest.role
        || basis.spec.operation_id != tail_header.operation_id
        || basis.spec.program_sha256 != tail_header.program_sha256
        || basis.spec.identity()? != chain::permutation::digest(&tail_header.catalogue_id)?
    {
        return Err("private scalar alias basis is not the actual admitted honest tail".into());
    }
    let (uniform, _) = chain::project_uniform(
        &basis.spec,
        &basis.checked,
        &format!("{expected_operation}/uniform"),
    )?;

    let bytes = chain::checked_file(
        root,
        &request.filename,
        chain::INPUT_CAP,
        &request.file_sha256,
        request.file_bytes,
    )?;
    let case: chain::permutation::Case = serde_json::from_slice(&bytes)?;
    drop(bytes);
    if case.name != request.name
        || !case.measure_all
        || case.spec.context != run.context
        || case.spec.field_role != honest.role
        || case.spec.operation_id != expected_operation
        || case.words.len() != 634
        || case.spec.words.len() != 634
        || case.spec.leaves.len() != 254
        || case.expected_spec_id != request.catalogue_id
        || case.spec.program_sha256 != request.program_sha256
    {
        return Err("private scalar alias actual case dimensions/identity differ".into());
    }
    // No extra maps file or supplied source receipt is accepted. Rebuild every
    // map, child identity and metadata byte from this actual source projection.
    let checked = uniform_alias::rebuild(
        &case.spec,
        &run.context,
        &honest.role,
        &expected_operation,
        &uniform,
    )?;
    if checked.source_sha256 != request.source_sha256
        || checked.source_maps_sha256 != request.source_maps_sha256
        || checked.program_sha256 != request.program_sha256
        || checked.catalogue_id != request.catalogue_id
        || checked.selected_bit != 379
        || checked.canonical_leaf != 253
    {
        return Err(
            "private scalar alias rebuilt source identities differ from pinned request".into(),
        );
    }
    let expected = uniform_alias::expected_assignment(&checked, &raw, &honest.role)?;
    if case.words != expected
        || case
            .spec
            .words
            .iter()
            .zip(&case.words)
            .any(|(word, value)| *value >= word.bound)
        || case.checks.len() != 254
        || case.checks.iter().enumerate().any(|(ordinal, check)| {
            check.ordinal != ordinal || check.expected_correct != (ordinal != 253)
        })
    {
        return Err(
            "private scalar alias must re-witness every word with sole false field_valid253".into(),
        );
    }
    let shapes: HashSet<_> = (0..254)
        .map(|ordinal| chain::permutation::auth_shape(&case.spec, ordinal))
        .collect();
    if shapes.len() > 63 {
        return Err(
            "private scalar alias exceeds the unchanged63 authenticated-shape reserve".into(),
        );
    }
    drop(shapes);
    drop(expected);
    drop(checked);
    drop(uniform);
    crate::execute_private(request, &case, main_keys, records, metrics)
}
