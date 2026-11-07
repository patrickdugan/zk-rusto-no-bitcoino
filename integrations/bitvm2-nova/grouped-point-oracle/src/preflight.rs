//! Stream every closed source and private recipe before any fixture key exists.
//!
//! This gate never seals declarations, generates keys, signs, executes Script or
//! constructs a commitment. Failure propagates to the worker before execution.
use crate::{
    chain,
    grouped_point::Reference,
    keys::Declarations,
    runtime,
    transport::{Group, Run},
};
use serde_json::Value;
use std::path::Path;

fn require(yes: bool, message: &str) -> crate::wots::Result<()> {
    if yes {
        Ok(())
    } else {
        Err(message.into())
    }
}

fn sidecar(
    root: &Path,
    filename: &str,
    digest: &str,
    bytes: u64,
    cap: u64,
    expected: &Value,
) -> crate::wots::Result<()> {
    let actual = chain::checked_file(root, filename, cap, digest, bytes)?;
    require(
        actual == chain::permutation::canonical(expected)?,
        "preflight actual source sidecar differs from native reconstruction",
    )
}

fn group(
    run: &Run,
    g: &Group,
    root: &Path,
    reference: &Reference,
) -> crate::wots::Result<chain::Basis> {
    require(
        g.components.len() == 11,
        "preflight eleven exact components",
    )?;
    crate::source::validate_policy(
        &run.context,
        &g.role,
        g.rho_counter,
        g.bit_index,
        &run.operation_id,
    )?;
    let nested = crate::nested_run(run);
    let chain_group = g.chain_group();
    let references = chain::references(&chain_group)?;
    let mut basis = None;
    let mut point = None;
    let mut declarations = Declarations::new();
    let mut facts = Vec::with_capacity(11);
    let mut leaves = 0usize;
    for index in 0..11 {
        let mut prepared = if index == 10 {
            let (prepared, checked) = crate::prepare_point_source(run, g, root, reference)?;
            point = Some(checked);
            prepared
        } else {
            crate::prepare(run, g, index, root, &references, basis.as_ref(), reference)?
        };
        let words = prepared.case.spec.words.len();
        require(
            words == prepared.case.words.len()
                && words == prepared.global_ids.len()
                && prepared.truth.len() == prepared.case.spec.leaves.len()
                && prepared.facts.index == index,
            "preflight exact assignment/global-ID/truth coverage",
        )?;
        leaves = leaves
            .checked_add(prepared.case.spec.leaves.len())
            .ok_or("preflight leaf census overflow")?;
        require(leaves <= 150_509, "preflight full forest leaf cap")?;
        for ((id, word), value) in prepared
            .global_ids
            .iter()
            .zip(&prepared.case.spec.words)
            .zip(&prepared.case.words)
        {
            declarations.add(id, word.bound, *value)?;
        }
        facts.push(prepared.facts.clone());
        if index == 2 {
            basis = Some(chain::Basis {
                spec: runtime::old_view(&prepared.case.spec)?,
                checked: prepared
                    .tail
                    .take()
                    .ok_or("preflight actual tail basis missing")?,
            });
        }
        // The large component catalogue and values die here before the next one.
    }
    require(
        leaves == 150_509
            && declarations.len() == 155_107
            && declarations.local_declarations() == 156_163
            && declarations.cached_signature_reuses() == 1_056,
        "preflight complete global/local/leaf/reuse census",
    )?;
    let descriptors = g
        .components
        .iter()
        .map(|h| h.descriptor.clone())
        .collect::<Vec<_>>();
    let old = chain::checked_outer(&nested, &chain_group, &descriptors[..9], &facts[..9])?;
    let point = point.ok_or("preflight actual grouped point admission missing")?;
    let checked = crate::checked_source(run, g, &descriptors, &facts, reference, &point)?;
    for (filename, digest, bytes, cap, expected) in [
        (
            &g.chain_source_filename,
            &g.chain_source_file_sha256,
            g.chain_source_file_bytes,
            chain::MANIFEST_CAP,
            &old.manifest,
        ),
        (
            &g.chain_maps_filename,
            &g.chain_maps_file_sha256,
            g.chain_maps_file_bytes,
            chain::MAP_CAP,
            &old.maps,
        ),
        (
            &g.point_source_filename,
            &g.point_source_file_sha256,
            g.point_source_file_bytes,
            chain::MANIFEST_CAP,
            &checked.manifest,
        ),
        (
            &g.point_maps_filename,
            &g.point_maps_file_sha256,
            g.point_maps_file_bytes,
            chain::MAP_CAP,
            &checked.maps,
        ),
    ] {
        sidecar(root, filename, digest, bytes, cap, expected)?;
    }
    // No seal call occurs: admitted declarations contain no key material.
    basis.ok_or_else(|| "preflight complete tail basis missing".into())
}

pub(crate) fn all(
    run: &Run,
    root: &Path,
    reference: &Reference,
) -> crate::wots::Result<chain::Basis> {
    require(
        run.cases.len() == 3 && run.probes.len() == 27,
        "preflight closed one-role three-main/27-private corpus",
    )?;
    let mut honest = None;
    let mut honest_basis = None;
    for g in &run.cases {
        require(
            g.role == run.role.as_str(),
            "preflight cross-role main rejected",
        )?;
        let basis = group(run, g, root, reference)?;
        if g.profile == "honest" {
            require(honest.is_none(), "preflight duplicate honest source")?;
            honest = Some(g);
            honest_basis = Some(basis);
        }
    }
    let honest = honest.ok_or("preflight honest source missing")?;
    let basis = honest_basis.ok_or("preflight honest basis missing")?;
    for request in &run.probes {
        require(
            request.role == run.role.as_str(),
            "preflight cross-role private probe rejected",
        )?;
        // prepare derives and compares the complete prescribed assignment,
        // source, tri-state truth and selected paths; it has no signing API.
        let admitted = crate::probes::prepare(request, root, honest, run, &basis, reference)?;
        drop(admitted);
    }
    Ok(basis)
}
