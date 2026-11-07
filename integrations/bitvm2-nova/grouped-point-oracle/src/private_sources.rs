//! Closed private frame/absorption/scalar-alias SOURCE and numeric admission.
//!
//! Copies the completed point worker's pure recipes and independently rebuilds
//! every expected word, old source identity and complete predicate selection.
//! No keys, signatures, Script execution, tree or imported verdict authority.
use crate::{
    chain, runtime,
    transport::{Group, Probe, Run},
    uniform_alias,
};
use bitvm2_nova_script_oracle::wots::Result;
use std::{collections::HashSet, path::Path};

fn require(yes: bool, message: &str) -> Result<()> {
    if yes {
        Ok(())
    } else {
        Err(message.into())
    }
}
fn local_case(old: chain::permutation::Case) -> Result<runtime::Case> {
    let source_id = old.spec.identity()?;
    let case = runtime::Case {
        name: old.name,
        spec: runtime::into_local(old.spec)?,
        expected_spec_id: old.expected_spec_id,
        words: old.words,
        checks: old
            .checks
            .into_iter()
            .map(|c| runtime::Check {
                ordinal: c.ordinal,
                expected_correct: Some(c.expected_correct),
            })
            .collect(),
        measure_all: old.measure_all,
    };
    require(
        case.spec.identity()? == source_id,
        "private old/local catalogue parity",
    )?;
    Ok(case)
}
fn complete_truth(case: &runtime::Case, request: &Probe, truth: &[Option<bool>]) -> Result<()> {
    require(
        truth.len() == case.spec.leaves.len()
            && case.checks.len() == truth.len()
            && case.measure_all
            && request.execution_mode == "all"
            && request.selected_ordinals.is_none(),
        "private small complete catalogue/check selection",
    )?;
    let false_rows = truth
        .iter()
        .enumerate()
        .filter_map(|(i, t)| (*t == Some(false)).then_some(i))
        .collect::<Vec<_>>();
    let abort_rows = truth
        .iter()
        .enumerate()
        .filter_map(|(i, t)| t.is_none().then_some(i))
        .collect::<Vec<_>>();
    require(
        abort_rows.is_empty()
            && request.expected_abort_ordinals == abort_rows
            && request.expected_false == false_rows
            && request.selected_leaf < truth.len()
            && truth[request.selected_leaf] == Some(request.expected_selected_correct)
            && case
                .checks
                .iter()
                .enumerate()
                .all(|(i, c)| c.ordinal == i && c.expected_correct == truth[i]),
        "independent complete private truth/false/abort/check inventory",
    )?;
    Ok(())
}
fn common(request: &Probe, g: &Group, run: &Run) -> Result<()> {
    let role = run.role;
    require(
        run.schema == crate::transport::SCHEMA
            && run.operation_id == crate::transport::OPERATION
            && g.role == role.as_str()
            && g.base_role == role.base_role()
            && g.name == format!("{}/h", role.prefix())
            && g.profile == "honest"
            && g.rho_counter == role.counter()
            && g.c_counter == role.counter() + 1
            && g.bit_index == 0
            && g.components.len() == 11
            && request.role == g.role
            && request.field_role == g.role
            && request.source_case == g.name
            && request.expected_abort_ordinals.is_empty(),
        "private small source must be its closed honest role/policy",
    )
}
fn chain_source(
    run: &Run,
    g: &Group,
    p: &Probe,
    root: &Path,
    basis: &chain::Basis,
) -> Result<runtime::Case> {
    let index = p.source_component.ok_or("chain private component absent")?;
    if ![3, 5].contains(&index)
        || p.source_case != g.name
        || g.profile != "honest"
        || p.role != g.role
    {
        return Err("closed private chain source case required".into());
    }
    let refs = chain::references(&g.chain_group())?;
    let source = chain::prepare(
        &crate::nested_run(run),
        &g.chain_group(),
        index,
        root,
        &refs,
        Some(basis),
    )?;
    let d = &g.components[index].descriptor;
    if p.source_sha256 != d.source_sha256
        || p.source_maps_sha256 != d.source_maps_sha256
        || p.program_sha256 != d.program_sha256
        || p.catalogue_id != d.catalogue_id
        || p.operation_id != d.operation_id
    {
        return Err("fresh private chain source pins differ".into());
    }
    let case: chain::permutation::Case = serde_json::from_slice(&chain::checked_file(
        root,
        &p.filename,
        chain::INPUT_CAP,
        &p.file_sha256,
        p.file_bytes,
    )?)?;
    if serde_json::to_value(&case.spec)? != serde_json::to_value(&source.case.spec)? {
        return Err("private graph is not independently admitted positive graph".into());
    }
    let (expected, selected) = if index == 3 {
        let f = source.frame.as_ref().ok_or("fresh frame absent")?;
        if p.kind == "coefficient-c0-modulus" || p.kind == "coefficient-c2-modulus" {
            let field = usize::from(p.kind == "coefficient-c2-modulus");
            (
                chain::frame::expected_assignment(
                    &refs.coefficients,
                    &g.role,
                    g.c_counter,
                    Some([0, 2][field]),
                    None,
                )?,
                f.canonical_field_leaves[field],
            )
        } else {
            let byte = match p.kind.as_str() {
                "frame-counter" => 69,
                "frame-NoDS" => 65,
                "frame-tag" => 0,
                "frame-zero-capacity" => 136,
                _ => return Err("closed private frame fault".into()),
            };
            let anchor = f
                .frame_anchors
                .iter()
                .find(|a| a.byte_index == byte)
                .ok_or("actual fixed frame anchor absent")?;
            (
                chain::frame::expected_assignment(
                    &refs.coefficients,
                    &g.role,
                    g.c_counter,
                    None,
                    Some((byte, u8::try_from(anchor.expected)? ^ 1)),
                )?,
                anchor.anchor_ordinal,
            )
        }
    } else {
        let a = source.absorb.as_ref().ok_or("fresh absorb source absent")?;
        let ordinal = match p.kind.as_str() {
            "absorb-wrong-xor" => 0,
            "absorb-selector" => 8,
            "absorb-delimiter" => 6,
            "absorb-end-mask" => 7,
            _ => return Err("closed private absorption fault".into()),
        };
        let mut values = chain::absorb::assignment_reference(&refs.full_outputs[&4], &refs.rho_raw);
        values[*a
            .output_indices
            .get(ordinal)
            .ok_or("actual absorb output absent")?] ^= 1;
        (values, ordinal)
    };
    if case.words != expected
        || p.selected_leaf != selected
        || p.expected_false != vec![selected]
        || !p.expected_abort_ordinals.is_empty()
        || chain::native_false(&case, index)? != vec![selected]
        || p.execution_mode != "all"
        || p.expected_selected_correct
    {
        return Err("independent closed chain probe recipe/truth differs".into());
    }
    require(
        case.name == p.name
            && case.expected_spec_id == p.catalogue_id
            && case.spec.context == run.context
            && case.spec.field_role == g.role
            && case.spec.operation_id == p.operation_id
            && case.spec.program_sha256 == p.program_sha256
            && case.spec.identity()? == chain::permutation::digest(&p.catalogue_id)?
            && case.words.len() == p.words
            && case.spec.words.len() == p.words
            && case.spec.leaves.len() == p.leaves
            && case
                .spec
                .words
                .iter()
                .zip(&case.words)
                .all(|(w, v)| *v < w.bound),
        "actual private chain case exact name/identity/range census",
    )?;
    let truth = (0..case.spec.leaves.len())
        .map(|i| {
            if index == 5 {
                chain::permutation::truth(&case.spec, &case.words, i).map(Some)
            } else {
                crate::rho_tail::truth(&case.spec, &case.words, i).map(Some)
            }
        })
        .collect::<Result<Vec<_>>>()?;
    let local = local_case(case)?;
    complete_truth(&local, p, &truth)?;
    Ok(local)
}
fn scalar_source(
    request: &Probe,
    root: &Path,
    honest: &Group,
    run: &Run,
    basis: &chain::Basis,
) -> Result<runtime::Case> {
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
    let truth = (0..case.spec.leaves.len())
        .map(|i| uniform_alias::truth(&case.spec, &case.words, i))
        .collect::<Result<Vec<_>>>()?;
    let local = local_case(case)?;
    complete_truth(&local, request, &truth)?;
    Ok(local)
}

pub(crate) fn prepare(
    request: &Probe,
    root: &Path,
    honest: &Group,
    run: &Run,
    basis: &chain::Basis,
) -> Result<runtime::Case> {
    run.validate()?;
    common(request, honest, run)?;
    // The fixed manifest inventory is rechecked before opening a private file.
    // No input vector or expected-verdict list chooses a recipe here.
    match request.category.as_str() {
        "chain" => {
            let kinds = [
                "coefficient-c0-modulus",
                "coefficient-c2-modulus",
                "frame-counter",
                "frame-NoDS",
                "frame-tag",
                "frame-zero-capacity",
                "absorb-wrong-xor",
                "absorb-selector",
                "absorb-delimiter",
                "absorb-end-mask",
            ];
            let i = kinds
                .iter()
                .position(|k| *k == request.kind)
                .ok_or("closed private chain kind")?;
            let component = if i < 6 { 3 } else { 5 };
            require(
                request.name == format!("{}/q{i}", run.role.prefix())
                    && request.source_component == Some(component)
                    && (request.words, request.leaves)
                        == if component == 3 { (187, 111) } else { (23, 9) }
                    && request.expected_false == [[109, 110, 37, 33, 32, 45, 0, 8, 6, 7][i]]
                    && request.selected_leaf == request.expected_false[0]
                    && !request.expected_selected_correct,
                "closed private q0..9 identity/shape/fault",
            )?;
            chain_source(run, honest, request, root, basis)
        }
        "scalar-alias" => scalar_source(request, root, honest, run, basis),
        _ => Err("private small source handles only chain or scalar alias".into()),
    }
}
