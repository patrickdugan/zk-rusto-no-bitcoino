//! Frozen point fixture core copied into the isolated scalar-source boundary.
//! Baseline files remain unchanged; only adapters and a new test key domain are used.
pub(crate) use crate::legacy_transport::{Group, Probe, Run};
use crate::old_chain as chain;
use crate::source::point as source;
use crate::{conditional_point, keys, probe, scalar_bits, uniform_alias};
use bitcoin::{
    hashes::{sha256, Hash, HashEngine},
    ScriptBuf,
};
use bitvm::signatures::{CompactWots, Wots, Wots4};
use bitvm2_nova_script_oracle::{
    engine::{self, Metrics},
    registry::{GraphSpec, Registry, Signature},
    taproot_commitment::TaprootCommitment,
    taproot_forest::TaprootForest,
    wots::{PublicKey, Result},
};
use chain::{
    permutation::{self, Case},
    Basis, Prepared, RecordSink,
};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, HashSet},
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
    time::Instant,
};
pub(crate) const WORDS: [usize; 11] = [
    29445, 29445, 587, 187, 29445, 23, 29445, 29445, 379, 264, 7498,
];
pub(crate) const LEAVES: [usize; 11] =
    [29245, 29245, 453, 111, 29245, 9, 29245, 29245, 245, 9, 6161];
pub(crate) const BRANCHES: [&str; 11] = [
    "rho-hi",
    "rho-lo",
    "rho-tail",
    "c-coeff-frame",
    "c-prefix",
    "c-absorb",
    "c-hi",
    "c-lo",
    "c-uniform",
    "scalar-bits",
    "conditional-point",
];
pub(crate) const TOTAL_WORDS: usize = 155107;
pub(crate) const LOCAL_WORDS: usize = 156163;
pub(crate) const TOTAL_LEAVES: usize = 153213;
pub(crate) const RECORD_UPPER: u64 = 132472024;
pub(crate) fn nested_run(run: &Run) -> chain::Run {
    chain::Run {
        schema: "internal independently admitted chain view".into(),
        context: run.context.clone(),
        operation_id: format!("{}/chain", run.operation_id),
        cases: vec![],
        probes: vec![],
    }
}
pub(crate) fn json_equal(a: &impl serde::Serialize, b: &impl serde::Serialize) -> Result<bool> {
    Ok(permutation::canonical(&serde_json::to_value(a)?)?
        == permutation::canonical(&serde_json::to_value(b)?)?)
}
pub(crate) fn basis_for(run: &Run, g: &Group, root: &Path) -> Result<Basis> {
    let old = nested_run(run);
    let cg = g.chain_group();
    let refs = chain::references(&cg)?;
    let mut p = chain::prepare(&old, &cg, 2, root, &refs, None)?;
    Ok(Basis {
        spec: p.case.spec.clone(),
        checked: p.tail.take().ok_or("checked rho-tail basis absent")?,
    })
}
pub(crate) fn common_new(
    run: &Run,
    g: &Group,
    index: usize,
    root: &Path,
) -> Result<(Case, Value, Vec<String>)> {
    if !(9..11).contains(&index) {
        return Err("new component index".into());
    }
    let h = &g.components[index];
    let d = &h.descriptor;
    let expected_role = if index == 10 { &g.base_role } else { &g.role };
    let op = source::component_operation(&run.operation_id, g.bit_index, index)?;
    let case: Case = serde_json::from_slice(&chain::checked_file(
        root,
        &h.filename,
        chain::INPUT_CAP,
        &h.file_sha256,
        h.file_bytes,
    )?)?;
    if case.name != format!("{}/{}", g.name, BRANCHES[index])
        || !case.measure_all
        || case.words.len() != WORDS[index]
        || case.spec.words.len() != WORDS[index]
        || case.spec.leaves.len() != LEAVES[index]
        || case.spec.context != run.context
        || &case.spec.field_role != expected_role
        || case.spec.operation_id != op
        || d.operation_id != op
        || case.spec.program_sha256 != d.program_sha256
        || case.expected_spec_id != d.catalogue_id
        || case.spec.identity()? != permutation::digest(&d.catalogue_id)?
        || case
            .spec
            .words
            .iter()
            .zip(&case.words)
            .any(|(w, v)| *v >= w.bound)
        || h.full.is_some()
        || h.program_manifest_filename.is_some()
        || h.program_manifest_file_sha256.is_some()
        || h.program_manifest_file_bytes.is_some()
    {
        return Err("actual new component identity/ranges/closed header differ".into());
    }
    let raw = chain::checked_file(
        root,
        &h.maps_filename,
        chain::MAP_CAP,
        &h.maps_file_sha256,
        h.maps_file_bytes,
    )?;
    let maps: Value = serde_json::from_slice(&raw)?;
    if permutation::canonical(&maps)? != raw
        || sha256::Hash::hash(&raw).to_string() != d.source_maps_sha256
        || h.maps_file_sha256 != d.source_maps_sha256
    {
        return Err("new actual maps canonical pin differs".into());
    }
    let ids = case
        .spec
        .words
        .iter()
        .map(|w| source::global_id(index, &w.name, &g.role, g.bit_index))
        .collect::<Result<Vec<_>>>()?;
    if ids.iter().collect::<HashSet<_>>().len() != ids.len()
        || sha256::Hash::hash(&permutation::canonical(&json!(ids))?).to_string()
            != d.global_ids_sha256
    {
        return Err("independently derived whole-word map differs".into());
    }
    Ok((case, maps, ids))
}
pub(crate) fn sidecar(
    run: &Run,
    g: &Group,
    index: usize,
    root: &Path,
    metadata: &Value,
    source_hash: &str,
) -> Result<()> {
    let h = &g.components[index];
    if source_hash != h.descriptor.source_sha256
        || metadata["context"] != json!(run.context)
        || metadata["catalogue_id"] != json!(h.descriptor.catalogue_id)
        || chain::checked_file(
            root,
            &h.source_manifest_filename,
            chain::MANIFEST_CAP,
            &h.source_manifest_file_sha256,
            h.source_manifest_file_bytes,
        )? != permutation::canonical(metadata)?
    {
        return Err("new independently rebuilt source metadata differs".into());
    }
    Ok(())
}
pub(crate) fn classified_point(case: &Case) -> Result<(Vec<usize>, Vec<usize>)> {
    let mut bad = vec![];
    let mut abort = vec![];
    for i in 0..case.spec.leaves.len() {
        match conditional_point::truth(&case.spec, &case.words, i)? {
            Some(true) => {}
            Some(false) => bad.push(i),
            None => abort.push(i),
        }
    }
    Ok((bad, abort))
}
pub(crate) fn point_selection(
    spec: &GraphSpec,
    false_rows: &[usize],
    abort: &[usize],
) -> Result<Vec<usize>> {
    let mut selected: std::collections::BTreeSet<usize> = (6116..6124)
        .chain([6159, 6160])
        .chain(false_rows.iter().copied())
        .collect();
    let mut shapes = HashSet::new();
    for i in 0..spec.leaves.len() {
        if shapes.insert(permutation::auth_shape(spec, i)) {
            selected.insert(i);
        }
    }
    let out: Vec<_> = selected.into_iter().collect();
    if shapes.len() > 107 || out.len() > 128 || out.iter().any(|i| abort.contains(i)) {
        return Err("point selected scope exceeds closed record budget or includes abort".into());
    }
    Ok(out)
}
pub(crate) fn check_selection(
    case: &Case,
    h: &chain::Header,
    ordinals: &[usize],
    false_rows: &[usize],
    abort: &[usize],
) -> Result<()> {
    let mode = if ordinals.len() == case.spec.leaves.len() {
        "all"
    } else if ordinals.is_empty() {
        "none"
    } else {
        "selected"
    };
    if h.execution_mode != mode
        || h.selected_ordinals.as_deref()
            != if mode == "selected" {
                Some(ordinals)
            } else {
                None
            }
        || h.expected_false != false_rows
        || h.expected_abort_ordinals != abort
        || case.checks.len() != ordinals.len()
        || case.checks.iter().zip(ordinals).any(|(c, i)| {
            c.ordinal != *i || abort.contains(i) || c.expected_correct == false_rows.contains(i)
        })
    {
        return Err("actual selected Script truth/order differs".into());
    }
    Ok(())
}
pub(crate) fn point_payload(values: &[u32], p: &conditional_point::PointPorts) -> Result<Value> {
    use num_bigint::BigUint;
    let integer = |indices: &[usize; 9]| -> Result<String> {
        let mut x = BigUint::from(0u8);
        for (j, i) in indices.iter().enumerate() {
            x += BigUint::from(*values.get(*i).ok_or("point limb index")?) << (29 * j);
        }
        let raw = x.to_bytes_le();
        if raw.len() > 32 {
            return Err("point coordinate high bits before LE32 conversion".into());
        }
        let mut bytes = [0u8; 32];
        bytes[..raw.len()].copy_from_slice(&raw);
        Ok(hex::encode(bytes))
    };
    Ok(
        json!({"infinity":*values.get(p.infinity).ok_or("point flag index")?,"x_le":integer(&p.x)?,"y_le":integer(&p.y)?}),
    )
}
pub(crate) fn prepare_point_source(
    run: &Run,
    g: &Group,
    root: &Path,
) -> Result<(Prepared, conditional_point::CheckedPoint)> {
    let (case, maps, ids) = common_new(run, g, 10, root)?;
    let d = &g.components[10].descriptor;
    let checked = conditional_point::check(
        &case.spec,
        &run.context,
        &g.base_role,
        g.bit_index,
        &d.operation_id,
        &maps,
    )?;
    if checked.program_sha256 != d.program_sha256
        || checked.catalogue_id != d.catalogue_id
        || checked.source_maps_sha256 != d.source_maps_sha256
    {
        return Err("actual conditional point source identity differs".into());
    }
    sidecar(run, g, 10, root, &checked.metadata, &checked.source_sha256)?;
    let (bad, abort) = classified_point(&case)?;
    if !bad.is_empty() || !abort.is_empty() {
        return Err(
            "main point must remain a valid conditional relation for its authenticated bit".into(),
        );
    }
    let verdict = conditional_point::checked_curve(&case.spec, &case.words)?;
    if !(verdict.a_valid
        && verdict.p_valid
        && verdict.e_valid
        && verdict.r_valid
        && verdict.bit_valid
        && verdict.addition_holds
        && verdict.selection_holds)
        || case.words[checked.bit] != g.selected_bit
        || point_payload(&case.words, &checked.a)? != serde_json::to_value(&g.point_A)?
        || point_payload(&case.words, &checked.p)? != serde_json::to_value(&g.point_P)?
        || point_payload(&case.words, &checked.e)? != serde_json::to_value(&g.expected_E)?
        || point_payload(&case.words, &checked.r)? != serde_json::to_value(&g.expected_R)?
    {
        return Err("mature independent curve oracle or exact point/bit ports differ".into());
    }
    let ordinals = if g.profile == "honest" {
        (0..6161).collect()
    } else {
        point_selection(&case.spec, &bad, &abort)?
    };
    check_selection(&case, &g.components[10], &ordinals, &bad, &abort)?;
    let facts = source::ComponentFacts {
        index: 10,
        branch: BRANCHES[10].into(),
        global_ids_sha256: d.global_ids_sha256.clone(),
        input_indices: vec![],
        output_indices: vec![],
        producer_ordinals: vec![],
        producer_occurrences: vec![],
        interfaces: vec![source::Interface {
            word_index: checked.bit,
            global_id: ids[checked.bit].clone(),
            bound: 2,
            occurrences: checked.bit_occurrences.clone(),
        }],
    };
    Ok((
        Prepared {
            case,
            global_ids: ids,
            facts,
            full: None,
            tail: None,
            frame: None,
            absorb: None,
        },
        checked,
    ))
}
pub(crate) fn prepare_bits(
    run: &Run,
    g: &Group,
    root: &Path,
    refs: &chain::References,
) -> Result<Prepared> {
    let (case, maps, ids) = common_new(run, g, 9, root)?;
    let d = &g.components[9].descriptor;
    let checked = scalar_bits::check(
        &case.spec,
        &run.context,
        &g.role,
        g.bit_index,
        &d.operation_id,
        &maps,
    )?;
    if checked.program_sha256 != d.program_sha256
        || checked.catalogue_id != d.catalogue_id
        || checked.source_maps_sha256 != d.source_maps_sha256
    {
        return Err("actual scalar bits identity differs".into());
    }
    sidecar(run, g, 9, root, &checked.metadata, &checked.source_sha256)?;
    let alias = if g.profile == "coherent-scalar-alias" {
        Some(uniform_alias::alias_values(&refs.c_raw, &g.role)?)
    } else {
        None
    };
    let raw = alias.as_ref().map(|a| a.result_le).unwrap_or(refs.c_result);
    let q = alias
        .as_ref()
        .map(|a| a.quotient_le)
        .unwrap_or(refs.c_quotient);
    if hex::encode(raw) != g.asserted_scalar_le
        || hex::encode(q) != g.asserted_scalar_quotient_le
        || g.canonical_bit != u32::from(refs.c_result[0] & 1)
    {
        return Err("independent canonical versus asserted scalar bytes differ".into());
    }
    let mut limbs = [0u32; 9];
    for bit in 0..255 {
        limbs[bit / 29] |= u32::from((raw[bit / 8] >> (bit % 8)) & 1) << (bit % 29);
    }
    let expected = checked.expected_assignment(
        &limbs,
        if g.profile == "coherent-bit" {
            Some(g.canonical_bit ^ 1)
        } else {
            None
        },
    )?;
    if case.words != expected || case.words[checked.selected_index] != g.selected_bit {
        return Err("actual scalar bit reconstruction/claimed bit assignment differs".into());
    }
    let bad = (0..9)
        .filter_map(|i| match scalar_bits::truth(&case.spec, &case.words, i) {
            Ok(true) => None,
            Ok(false) => Some(Ok(i)),
            Err(e) => Some(Err(e)),
        })
        .collect::<Result<Vec<_>>>()?;
    let expected_bad = if g.profile == "coherent-bit" {
        vec![g.bit_index / 29]
    } else {
        vec![]
    };
    if bad != expected_bad {
        return Err("closed bit false predicate differs".into());
    }
    check_selection(
        &case,
        &g.components[9],
        &(0..9).collect::<Vec<_>>(),
        &bad,
        &[],
    )?;
    let mut facts = chain::compact_facts(&case, 8, &ids, None)?;
    facts.index = 9;
    facts.branch = BRANCHES[9].into();
    Ok(Prepared {
        case,
        global_ids: ids,
        facts,
        full: None,
        tail: None,
        frame: None,
        absorb: None,
    })
}
pub(crate) fn prepare(
    run: &Run,
    g: &Group,
    index: usize,
    root: &Path,
    refs: &chain::References,
    basis: Option<&Basis>,
) -> Result<Prepared> {
    if index < 9 {
        chain::prepare(&nested_run(run), &g.chain_group(), index, root, refs, basis)
    } else if index == 9 {
        prepare_bits(run, g, root, refs)
    } else if index == 10 {
        Ok(prepare_point_source(run, g, root)?.0)
    } else {
        Err("component bound".into())
    }
}
pub(crate) fn depth(count: usize, index: usize) -> Result<usize> {
    if count == 0 || index >= count {
        return Err("tree bounded index".into());
    }
    let height = (usize::BITS - 1 - count.leading_zeros()) as usize;
    let short = 1usize << height;
    Ok(height + usize::from(index < 2 * (count - short)))
}
pub(crate) fn foreign_key(source: &str, name: &str, index: usize) -> Result<PublicKey> {
    let mut seed = b"BITVM2-NOVA/TEST-ONLY-RETAINED-SCALAR-SOURCES-FOREIGN/v1\0".to_vec();
    seed.extend_from_slice(&permutation::digest(source)?);
    seed.extend_from_slice(&(name.len() as u16).to_le_bytes());
    seed.extend_from_slice(name.as_bytes());
    seed.extend_from_slice(&(index as u32).to_le_bytes());
    Ok(Wots4::generate_public_key(
        &sha256::Hash::hash(&seed).to_byte_array().to_vec(),
    ))
}

/// Caller has independently reconstructed the closed private recipe and source.
/// This function admits only the actual case, then signs in a separate domain.
pub(crate) fn execute_private(
    request: &Probe,
    case: &Case,
    main_keys: &HashSet<[u8; 32]>,
    records: &mut RecordSink,
    metrics: &mut Metrics,
) -> Result<Value> {
    let selected = match request.execution_mode.as_str() {
        "all" => {
            if request.selected_ordinals.is_some() {
                return Err("all probe cannot transport selectors".into());
            }
            (0..request.leaves).collect::<Vec<_>>()
        }
        "selected" => request
            .selected_ordinals
            .clone()
            .ok_or("selected private ordinals absent")?,
        _ => return Err("private execution selector".into()),
    };
    if !case.measure_all
        || case.name != request.name
        || case.spec.context.is_empty()
        || case.spec.field_role != request.field_role
        || case.spec.operation_id != request.operation_id
        || case.spec.program_sha256 != request.program_sha256
        || case.spec.identity()? != permutation::digest(&request.catalogue_id)?
        || case.expected_spec_id != request.catalogue_id
        || case.words.len() != request.words
        || case.spec.words.len() != request.words
        || case.spec.leaves.len() != request.leaves
        || case.checks.len() != selected.len()
        || selected.windows(2).any(|a| a[0] >= a[1])
        || selected
            .iter()
            .any(|i| *i >= request.leaves || request.expected_abort_ordinals.contains(i))
        || case.checks.iter().zip(&selected).any(|(c, i)| {
            c.ordinal != *i || c.expected_correct == request.expected_false.contains(i)
        })
        || request.expected_selected_correct
            == request.expected_false.contains(&request.selected_leaf)
        || request
            .expected_abort_ordinals
            .contains(&request.selected_leaf)
    {
        return Err("private case identity/selection/truth differs".into());
    }
    let (registry, public, signatures) = probe::material(
        &case.spec,
        &case.words,
        &request.source_sha256,
        &request.name,
        request.source_component,
        main_keys,
    )?;
    let ids = case
        .spec
        .words
        .iter()
        .map(|w| format!("probe/{}/{}", request.name, w.name))
        .collect::<Vec<_>>();
    chain::openings::validate_material(&registry, &public, &signatures, &case.words, &ids)?;
    let eval_internal = if request.category == "eval-w-encoding" {
        crate::encoding_internal_openings(case, &registry, &public, &signatures, &ids)?
    } else {
        0
    };
    let foreign = foreign_key(
        &request.source_sha256,
        &request.name,
        request.source_component.unwrap_or(9),
    )?;
    if public.contains(&foreign) {
        return Err("private foreign key collision".into());
    }
    let native = permutation::native_negatives(case, &public, &signatures, foreign, &registry)?;
    let mut stream = sha256::Hash::engine();
    let mut compiled = 0u64;
    let mut largest = 0usize;
    let mut executed = 0usize;
    for ordinal in 0..case.spec.leaves.len() {
        let disproof = registry.script(ordinal, true)?;
        engine::validate(&disproof)?;
        compiled = compiled
            .checked_add(disproof.len() as u64)
            .ok_or("private byte overflow")?;
        if compiled > 256 << 20 {
            return Err("private tree Script cap".into());
        }
        largest = largest.max(disproof.len());
        stream.input(&(disproof.len() as u32).to_le_bytes());
        stream.input(disproof.as_bytes());
        if case
            .checks
            .get(executed)
            .is_some_and(|c| c.ordinal == ordinal)
        {
            let expected = case.checks[executed].expected_correct;
            let witness = registry.witness(ordinal, &signatures)?;
            for mode in [false, true] {
                let code = if mode {
                    disproof.clone()
                } else {
                    registry.script(ordinal, false)?
                };
                chain::record(
                    records,
                    metrics,
                    &code,
                    &witness,
                    expected != mode,
                    &request.name,
                    json!(ordinal),
                    mode,
                )?;
            }
            executed += 1;
        }
    }
    if executed != case.checks.len() {
        return Err("private checks left unexecuted".into());
    }
    let max_shapes = match request.category.as_str() {
        "chain" => {
            if request.source_component == Some(3) {
                24
            } else {
                4
            }
        }
        "point-edge" => 107,
        "point-negative" => 12,
        "scalar-alias" => 63,
        "eval-w-encoding" => 17,
        "scalar-block" => 1,
        _ => return Err("closed private category".into()),
    };
    let layouts = chain::guard_subset(
        &registry,
        &signatures,
        records,
        metrics,
        &request.name,
        request.source_component.unwrap_or(9),
        if request.category == "point-negative" || request.category == "scalar-block" {
            Some(&selected)
        } else {
            None
        },
        max_shapes,
    )?;
    let tree = TaprootCommitment::new(&registry, request.selected_leaf)?;
    if tree.compiled_script_bytes() != compiled
        || tree.compiled_stream_sha256()
            != sha256::Hash::from_engine(stream.clone()).to_byte_array()
        || tree.leaf_count() != case.spec.leaves.len()
        || tree.control_block_bytes().len()
            != 33 + 32 * depth(request.leaves, request.selected_leaf)?
    {
        return Err("private actual tree differs from measured catalogue".into());
    }
    tree.verify_member(
        &registry,
        tree.merkle_root(),
        tree.output_key(),
        request.selected_leaf,
    )?;
    let witness = registry.witness(request.selected_leaf, &signatures)?;
    for mode in [false, true] {
        chain::record(
            records,
            metrics,
            &registry.script(request.selected_leaf, mode)?,
            &witness,
            request.expected_selected_correct != mode,
            &request.name,
            json!(format!(
                "{}/tree/{}",
                request.source_component.unwrap_or(9),
                request.selected_leaf
            )),
            mode,
        )?;
    }
    let negatives = probe::tree_negatives(&tree, &registry, &public)?;
    let mut row = serde_json::to_value(request)?;
    permutation::extend_object(
        &mut row,
        json!({"eval_w_internal_opening_links":eval_internal}),
    )?;
    permutation::extend_object(
        &mut row,
        json!({"context":case.spec.context,"registry_id":hex::encode(registry.identity()),"executed_leaves":executed,"false_predicates":request.expected_false,"abort_predicates":request.expected_abort_ordinals,"signature_entries_created":public.len(),"guard_layouts":layouts,"guard_vectors":14*layouts,"native_rejections":native,"additional_selected_engine_executions":2,"selected_correctness_execution_success":request.expected_selected_correct,"selected_disproof_execution_success":!request.expected_selected_correct}),
    )?;
    permutation::extend_object(
        &mut row,
        json!({"compiled_script_bytes":compiled,"largest_disproof_leaf_bytes":largest,"compiled_stream_sha256":sha256::Hash::from_engine(stream).to_string(),"native_predicates_classified":case.spec.leaves.len(),"tree":{"leaf_count":tree.leaf_count(),"compiled_script_bytes":compiled,"control_block_bytes":tree.control_block_bytes().len(),"merkle_root":hex::encode(tree.merkle_root().to_byte_array()),"output_key":hex::encode(tree.output_key().serialize()),"control_block_sha256":sha256::Hash::hash(&tree.control_block_bytes()).to_string(),"selected_script_sha256":sha256::Hash::hash(tree.selected_script().as_bytes()).to_string(),"compiled_stream_sha256":hex::encode(tree.compiled_stream_sha256()),"membership_verified":true,"roots_independently_pinned":false,"negative_counts":negatives}}),
    )?;
    Ok(row)
}

pub(crate) fn new_openings(
    checked: &source::CheckedSource,
    store: &chain::OpeningStore,
) -> Result<(usize, usize, usize, usize)> {
    let rows = checked.maps["scalar_to_bits"]
        .as_array()
        .ok_or("actual scalar links absent")?;
    if rows.len() != 9 {
        return Err("nine scalar limbs required".into());
    }
    let mut direct = 0;
    let mut canonical = 0;
    let mut bit_links = 0;
    let mut negatives = 0;
    let actual = |c: usize, o: usize, f: usize| -> Result<&chain::StoredOpening> {
        store
            .get(&(c, o, f))
            .ok_or_else(|| "actual new opening missing".into())
    };
    for (i, row) in rows.iter().enumerate() {
        if row["source_component"] != json!(8)
            || row["target_component"] != json!(9)
            || row["source_word"] != json!(129 + i)
            || row["target_word"] != json!(i)
            || row["source_ordinal"] != json!(72 + i)
            || row["source_occurrence"] != json!(0)
            || row["canonical_ordinal"] != json!(244)
            || row["canonical_occurrence"] != json!(i)
            || row["target_ordinal"] != json!(i)
            || row["target_occurrence"] != json!(0)
        {
            return Err("new scalar link topology differs".into());
        }
        let a = actual(8, 72 + i, 0)?;
        let b = actual(9, i, 0)?;
        let c = actual(8, 244, i)?;
        if a.word != 129 + i || b.word != i || c.word != 129 + i || a.assertion.bound != 1 << 29 {
            return Err("new scalar actual word/bound differs".into());
        }
        chain::openings::same_assertion(&a.assertion, &b.assertion)?;
        chain::openings::same_assertion(&a.assertion, &c.assertion)?;
        direct += 1;
        canonical += 1;
    }
    let row = &checked.maps["selected_bit_to_point"];
    let ordinal = row["source_ordinal"].as_u64().ok_or("bit source ordinal")? as usize;
    let formal = row["source_occurrence"]
        .as_u64()
        .ok_or("bit source occurrence")? as usize;
    let a = actual(9, ordinal, formal)?;
    if a.assertion.bound != 2
        || row["cross_role_bound"] != json!(2)
        || row["source_component"] != json!(9)
        || row["target_component"] != json!(10)
    {
        return Err("only a bound2 bit crosses roles".into());
    }
    for (o, f) in source::BIT_OCCURRENCES {
        let b = actual(10, o, f)?;
        if b.word != 7476 || b.assertion.bound != 2 {
            return Err("point bit actual port differs".into());
        }
        chain::openings::same_assertion(&a.assertion, &b.assertion)?;
        bit_links += 1;
    }
    let foreign = store
        .values()
        .find(|b| b.assertion.id != a.assertion.id)
        .ok_or("independent new cache negative assertion")?;
    negatives += chain::openings::negatives(&a.assertion, &foreign.assertion)?;
    let scalar = actual(8, 72, 0)?;
    negatives += chain::openings::negatives(&scalar.assertion, &a.assertion)?;
    if (direct, canonical, bit_links, negatives) != (9, 9, 5, 12) {
        return Err("all23 actual new opening comparisons and12 cache negatives required".into());
    }
    Ok((direct, canonical, bit_links, negatives))
}

pub(crate) fn checked_source(
    run: &Run,
    g: &Group,
    descriptors: &[source::ComponentDescriptor],
    facts: &[source::ComponentFacts],
) -> Result<source::CheckedSource> {
    let checked = source::build(
        &run.context,
        &g.role,
        g.rho_counter,
        g.bit_index,
        &run.operation_id,
        descriptors,
        facts,
    )?;
    if checked.source_sha256 != g.source_sha256
        || checked.source_maps_sha256 != g.source_maps_sha256
    {
        return Err("fresh mixed-role source does not match external scenario pin".into());
    }
    Ok(checked)
}
pub(crate) fn new_admission_negatives(
    run: &Run,
    g: &Group,
    descriptors: &[source::ComponentDescriptor],
    facts: &[source::ComponentFacts],
) -> Result<(usize, usize)> {
    let mut maps = 0;
    let mut source_count = 0;
    for mutation in 0..10 {
        let mut bad = facts.to_vec();
        match mutation {
            0 => bad[9].interfaces[0].global_id = "c/reduction/result/l1".into(),
            1 => bad[9].interfaces[1].bound = 2,
            2 => bad[9].interfaces[9].global_id = "c/bits/bit/1".into(),
            3 => bad[9].interfaces[263].bound = 1 << 29,
            4 => bad[9].interfaces[9].occurrences[0].1 -= 1,
            5 => bad[10].interfaces[0].global_id = "c/bits/bit/1".into(),
            6 => bad[10].interfaces[0].bound = 1 << 29,
            7 => bad[10].interfaces[0].occurrences.swap(0, 1),
            8 => bad[8].interfaces[129]
                .occurrences
                .pop()
                .map(|_| ())
                .unwrap_or(()),
            _ => bad[10].global_ids_sha256 = permutation::changed(&bad[10].global_ids_sha256)?,
        };
        if checked_source(run, g, descriptors, &bad).is_ok() {
            return Err("substituted mixed-role scalar/bit/point map accepted".into());
        }
        maps += 1;
    }
    for mutation in 0..12 {
        let mut bad = descriptors.to_vec();
        match mutation {
            0 => bad[9].field_role = g.base_role.clone(),
            1 => bad[10].field_role = g.role.clone(),
            2 => bad[9].operation_id.push_str("/wrong-bit"),
            3 => bad[10].operation_id.push_str("/wrong-curve"),
            4 => bad[9].program_sha256 = permutation::changed(&bad[9].program_sha256)?,
            5 => bad[10].catalogue_id = permutation::changed(&bad[10].catalogue_id)?,
            6 => bad[9].source_sha256 = permutation::changed(&bad[9].source_sha256)?,
            7 => bad[10].source_maps_sha256 = permutation::changed(&bad[10].source_maps_sha256)?,
            8 => bad[10].global_ids_sha256 = permutation::changed(&bad[10].global_ids_sha256)?,
            9 => bad[9].words += 1,
            10 => bad[10].leaves -= 1,
            _ => bad.swap(9, 10),
        }
        if checked_source(run, g, &bad, facts).is_ok() {
            return Err("substituted mixed-role child identity accepted".into());
        }
        source_count += 1;
    }
    Ok((maps, source_count))
}
pub(crate) fn chain_probe_run(
    run: &Run,
    g: &Group,
    p: &Probe,
    root: &Path,
    basis: &Basis,
    main_keys: &HashSet<[u8; 32]>,
    records: &mut RecordSink,
    metrics: &mut Metrics,
) -> Result<Value> {
    let index = p.source_component.ok_or("chain private component absent")?;
    if ![3, 5].contains(&index)
        || p.source_case != g.name
        || g.profile != "honest"
        || p.role != g.role
    {
        return Err("closed private chain source case required".into());
    }
    let refs = chain::references(&g.chain_group())?;
    let source = prepare(run, g, index, root, &refs, Some(basis))?;
    let d = &g.components[index].descriptor;
    if p.source_sha256 != d.source_sha256
        || p.source_maps_sha256 != d.source_maps_sha256
        || p.program_sha256 != d.program_sha256
        || p.catalogue_id != d.catalogue_id
        || p.operation_id != d.operation_id
    {
        return Err("fresh private chain source pins differ".into());
    }
    let case: Case = serde_json::from_slice(&chain::checked_file(
        root,
        &p.filename,
        chain::INPUT_CAP,
        &p.file_sha256,
        p.file_bytes,
    )?)?;
    if !json_equal(&case.spec, &source.case.spec)? {
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
    execute_private(p, &case, main_keys, records, metrics)
}
