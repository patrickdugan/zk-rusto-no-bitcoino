//! Hosted TEST-ONLY canonical challenge bit and conditional Pasta point fixture.
//! One immutable assertion pool, serial registries and live eleven-component forest.
//! This is not a proof verifier, scalar multiplication, IPA or production binding.
mod body_pins;
#[allow(dead_code, unused_imports)]
mod chain;
mod conditional_point;
mod keys;
mod probe;
mod probe_run;
#[path = "../../rust-oracle/src/byte_rho_tail.rs"]
mod rho_tail;
mod scalar_bits;
mod scalar_probe;
mod source;
mod transport;
mod uniform_alias;
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
pub(crate) use transport::{Group, Probe, Run};
const WORDS: [usize; 11] = [
    29445, 29445, 587, 187, 29445, 23, 29445, 29445, 379, 264, 7498,
];
const LEAVES: [usize; 11] = [29245, 29245, 453, 111, 29245, 9, 29245, 29245, 245, 9, 6161];
const BRANCHES: [&str; 11] = [
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
const TOTAL_WORDS: usize = 155107;
const LOCAL_WORDS: usize = 156163;
const TOTAL_LEAVES: usize = 153213;
const RECORD_UPPER: u64 = 132472024;
fn nested_run(run: &Run) -> chain::Run {
    chain::Run {
        schema: "internal independently admitted chain view".into(),
        context: run.context.clone(),
        operation_id: format!("{}/chain", run.operation_id),
        cases: vec![],
        probes: vec![],
    }
}
fn json_equal(a: &impl serde::Serialize, b: &impl serde::Serialize) -> Result<bool> {
    Ok(permutation::canonical(&serde_json::to_value(a)?)?
        == permutation::canonical(&serde_json::to_value(b)?)?)
}
fn basis_for(run: &Run, g: &Group, root: &Path) -> Result<Basis> {
    let old = nested_run(run);
    let cg = g.chain_group();
    let refs = chain::references(&cg)?;
    let mut p = chain::prepare(&old, &cg, 2, root, &refs, None)?;
    Ok(Basis {
        spec: p.case.spec.clone(),
        checked: p.tail.take().ok_or("checked rho-tail basis absent")?,
    })
}
fn common_new(
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
fn sidecar(
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
fn classified_point(case: &Case) -> Result<(Vec<usize>, Vec<usize>)> {
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
fn point_selection(spec: &GraphSpec, false_rows: &[usize], abort: &[usize]) -> Result<Vec<usize>> {
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
fn check_selection(
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
fn point_payload(values: &[u32], p: &conditional_point::PointPorts) -> Result<Value> {
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
fn prepare_bits(run: &Run, g: &Group, root: &Path, refs: &chain::References) -> Result<Prepared> {
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
fn prepare(
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
fn depth(count: usize, index: usize) -> Result<usize> {
    if count == 0 || index >= count {
        return Err("tree bounded index".into());
    }
    let height = (usize::BITS - 1 - count.leading_zeros()) as usize;
    let short = 1usize << height;
    Ok(height + usize::from(index < 2 * (count - short)))
}
fn foreign_key(source: &str, name: &str, index: usize) -> Result<PublicKey> {
    let mut seed = b"BITVM2-NOVA/TEST-ONLY-BYTE-C-BIT-POINT-FOREIGN/v1\0".to_vec();
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
        _ => return Err("closed private category".into()),
    };
    let layouts = chain::guard_subset(
        &registry,
        &signatures,
        records,
        metrics,
        &request.name,
        request.source_component.unwrap_or(9),
        if request.category == "point-negative" {
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
        json!({"context":case.spec.context,"registry_id":hex::encode(registry.identity()),"executed_leaves":executed,"false_predicates":request.expected_false,"abort_predicates":request.expected_abort_ordinals,"signature_entries_created":public.len(),"guard_layouts":layouts,"guard_vectors":14*layouts,"native_rejections":native,"additional_selected_engine_executions":2,"selected_correctness_execution_success":request.expected_selected_correct,"selected_disproof_execution_success":!request.expected_selected_correct}),
    )?;
    permutation::extend_object(
        &mut row,
        json!({"compiled_script_bytes":compiled,"largest_disproof_leaf_bytes":largest,"compiled_stream_sha256":sha256::Hash::from_engine(stream).to_string(),"native_predicates_classified":case.spec.leaves.len(),"tree":{"leaf_count":tree.leaf_count(),"compiled_script_bytes":compiled,"control_block_bytes":tree.control_block_bytes().len(),"merkle_root":hex::encode(tree.merkle_root().to_byte_array()),"output_key":hex::encode(tree.output_key().serialize()),"control_block_sha256":sha256::Hash::hash(&tree.control_block_bytes()).to_string(),"selected_script_sha256":sha256::Hash::hash(tree.selected_script().as_bytes()).to_string(),"compiled_stream_sha256":hex::encode(tree.compiled_stream_sha256()),"membership_verified":true,"roots_independently_pinned":false,"negative_counts":negatives}}),
    )?;
    Ok(row)
}

fn new_openings(
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

fn checked_source(
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
fn new_admission_negatives(
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
fn group_run(
    run: &Run,
    g: &Group,
    root: &Path,
    records: &mut RecordSink,
    metrics: &mut Metrics,
) -> Result<(Value, Option<HashSet<[u8; 32]>>)> {
    source::validate_policy(
        &run.context,
        &g.role,
        g.rho_counter,
        g.bit_index,
        &run.operation_id,
    )?;
    let nr = nested_run(run);
    let cg = g.chain_group();
    let refs = chain::references(&cg)?;
    let mut basis = None;
    let mut declarations = keys::Declarations::new();
    let mut facts = vec![];
    for index in 0..11 {
        let mut p = prepare(run, g, index, root, &refs, basis.as_ref())?;
        for ((id, w), value) in p
            .global_ids
            .iter()
            .zip(&p.case.spec.words)
            .zip(&p.case.words)
        {
            declarations.add(id, w.bound, *value)?;
        }
        facts.push(p.facts.clone());
        if index == 2 {
            basis = Some(Basis {
                spec: p.case.spec.clone(),
                checked: p.tail.take().ok_or("actual tail basis absent")?,
            });
        }
    }
    if declarations.len() != TOTAL_WORDS
        || declarations.local_declarations() != LOCAL_WORDS
        || declarations.cached_signature_reuses() != 1056
    {
        return Err("independent mixed-role global declaration census differs".into());
    }
    let descriptors = g
        .components
        .iter()
        .map(|h| h.descriptor.clone())
        .collect::<Vec<_>>();
    let old = chain::checked_outer(&nr, &cg, &descriptors[..9], &facts[..9])?;
    let checked = checked_source(run, g, &descriptors, &facts)?;
    for (file, sha, bytes, cap, value) in [
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
        if chain::checked_file(root, file, cap, sha, bytes)? != permutation::canonical(value)? {
            return Err(
                "actual old/new compact source sidecar differs from native reconstruction".into(),
            );
        }
    }
    let (old_maps, old_sources) =
        chain::admission_negatives(&nr, &cg, &descriptors[..9], &facts[..9])?;
    let (new_maps, new_sources) = new_admission_negatives(run, g, &descriptors, &facts)?;
    drop(descriptors);
    drop(facts);
    let pool = declarations.seal(&g.source_sha256, &g.name)?;
    let positive = if g.profile == "honest" {
        let hashes = pool.public_key_hashes();
        if hashes.len() != TOTAL_WORDS {
            return Err("complete positive key collision".into());
        }
        Some(hashes)
    } else {
        None
    };
    let (chosen_component, chosen_leaf) = match g.profile.as_str() {
        "honest" => (10, 6160),
        "coherent-bit" => (9, g.bit_index / 29),
        "coherent-scalar-alias" => (8, 244),
        _ => return Err("closed point profile".into()),
    };
    let mut components = vec![];
    let mut live = vec![];
    let mut store = chain::OpeningStore::new();
    let mut global_stream = sha256::Hash::engine();
    let mut native = 0;
    let mut canonical = 0;
    let mut internal_entries = 0;
    let mut internal_links = 0;
    let mut cache_negative = 0;
    let mut normal = 0;
    let mut shapes = 0;
    for index in 0..11 {
        let p = prepare(run, g, index, root, &refs, basis.as_ref())?;
        let h = &g.components[index];
        let (registry, public, signatures) = chain::registry_for(&p, &pool)?;
        let foreign = foreign_key(&g.source_sha256, &g.name, index)?;
        if public.contains(&foreign) {
            return Err("foreign key collision".into());
        }
        native += permutation::native_negatives(&p.case, &public, &signatures, foreign, &registry)?;
        let measured = chain::measure_execute(
            &p,
            h,
            &registry,
            &signatures,
            records,
            metrics,
            &g.name,
            &mut global_stream,
            false,
        )?;
        shapes += measured["guard_layouts"]
            .as_u64()
            .ok_or("layout count type")? as usize;
        normal += p.case.checks.len();
        if let Some(full) = &p.full {
            let (entries, links, rejections) = chain::openings::internal(
                &registry,
                &public,
                &signatures,
                &p.case.words,
                &p.global_ids,
                &chain::internal_joins(full),
            )?;
            internal_entries += entries;
            internal_links += links;
            cache_negative += rejections;
        } else {
            chain::openings::validate_material(
                &registry,
                &public,
                &signatures,
                &p.case.words,
                &p.global_ids,
            )?;
        }
        canonical += chain::capture_interfaces(&p, &registry, &public, &signatures, &mut store)?;
        let selected = if index == chosen_component {
            chosen_leaf
        } else {
            0
        };
        let tree = TaprootCommitment::new(&registry, selected)?;
        if tree.registry_id() != registry.identity()
            || tree.catalogue_id() != permutation::digest(&h.descriptor.catalogue_id)?
            || tree.leaf_count() != LEAVES[index]
            || tree.compiled_script_bytes()
                != measured["compiled_script_bytes"]
                    .as_u64()
                    .ok_or("compiled bytes type")?
            || hex::encode(tree.compiled_stream_sha256())
                != measured["compiled_stream_sha256"]
                    .as_str()
                    .ok_or("stream hash type")?
        {
            return Err("live component tree differs from complete measured stream".into());
        }
        tree.verify_member(&registry, tree.merkle_root(), tree.output_key(), selected)?;
        let mut ledger = serde_json::to_value(&h.descriptor)?;
        permutation::extend_object(&mut ledger, measured)?;
        components.push(ledger);
        live.push(tree);
        drop(registry);
        drop(public);
        drop(signatures);
        drop(p);
    }
    let (connections, connection_negatives) = chain::verify_connections(&old, &store)?;
    cache_negative += connection_negatives;
    let (scalar_links, scalar_canonical, bit_links, new_cache) = new_openings(&checked, &store)?;
    cache_negative += new_cache;
    drop(store);
    drop(old);
    drop(checked);
    if canonical != 46
        || internal_entries != 23000
        || internal_links != 46000
        || native != 264
        || old_maps != 12
        || old_sources != 18
        || new_maps != 10
        || new_sources != 12
        || cache_negative != 108
        || shapes > 466
        || normal
            > if g.profile == "honest" {
                TOTAL_LEAVES
            } else {
                827 + 128
            }
    {
        return Err("closed source/opening/execution census differs".into());
    }
    if g.profile == "honest" && normal != TOTAL_LEAVES {
        return Err("complete honest statement not executed".into());
    }
    let selected = prepare(run, g, chosen_component, root, &refs, basis.as_ref())?;
    let (registry, public, signatures) = chain::registry_for(&selected, &pool)?;
    chain::openings::validate_material(
        &registry,
        &public,
        &signatures,
        &selected.case.words,
        &selected.global_ids,
    )?;
    let forest = TaprootForest::new(&live, chosen_component)?;
    forest.verify_member(
        &registry,
        forest.component_manifest_sha256(),
        forest.merkle_root(),
        forest.output_key(),
        chosen_component,
        chosen_leaf,
    )?;
    let compiled = components
        .iter()
        .map(|c| {
            c["compiled_script_bytes"]
                .as_u64()
                .ok_or_else(|| "component byte type".into())
        })
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .sum::<u64>();
    if forest.component_count() != 11
        || forest.leaf_count() != TOTAL_LEAVES as u64
        || forest.compiled_script_bytes() != compiled
        || compiled > 5 << 28
        || forest.selected_script().as_bytes() != registry.script(chosen_leaf, true)?.as_bytes()
        || forest.control_block_bytes().len()
            != 33
                + 32 * (depth(LEAVES[chosen_component], chosen_leaf)?
                    + depth(11, chosen_component)?)
    {
        return Err("complete eleven-component live forest differs".into());
    }
    let correct = g.profile == "honest";
    if selected
        .case
        .checks
        .iter()
        .find(|c| c.ordinal == chosen_leaf)
        .is_none_or(|c| c.expected_correct != correct)
    {
        return Err(
            "selected genuine false/correct predicate missing from actual executed source".into(),
        );
    }
    let witness = registry.witness(chosen_leaf, &signatures)?;
    for mode in [false, true] {
        chain::record(
            records,
            metrics,
            &registry.script(chosen_leaf, mode)?,
            &witness,
            correct != mode,
            &g.name,
            json!(format!("{chosen_component}/tree/{chosen_leaf}")),
            mode,
        )?;
    }
    let negatives = chain::forest_negatives(&forest, &registry, &mut live)?;
    let tree = json!({"components":11,"leaf_count":forest.leaf_count(),"compiled_script_bytes":compiled,"selected_component":chosen_component,"selected_leaf":chosen_leaf,"control_block_bytes":forest.control_block_bytes().len(),"merkle_root":hex::encode(forest.merkle_root().to_byte_array()),"output_key":hex::encode(forest.output_key().serialize()),"control_block_sha256":sha256::Hash::hash(&forest.control_block_bytes()).to_string(),"selected_script_sha256":sha256::Hash::hash(forest.selected_script().as_bytes()).to_string(),"component_manifest_sha256":hex::encode(forest.component_manifest_sha256()),"compiled_stream_sha256":sha256::Hash::from_engine(global_stream).to_string(),"hierarchical_membership_verified":true,"roots_independently_pinned":false,"negative_counts":negatives});
    let mut row = result_identity(g);
    permutation::extend_object(
        &mut row,
        json!({"components":components,"connections":connections,"forest":tree,"full_statement_executed":correct,"signature_entries_created":pool.len(),"local_declared_words":pool.local_declarations(),"cached_signature_reuses":pool.cached_signature_reuses(),"all_native_predicates_classified":TOTAL_LEAVES,"scalar_limb_opening_links":scalar_links,"scalar_canonical_opening_links":scalar_canonical,"selected_bit_opening_links":bit_links}),
    )?;
    permutation::extend_object(
        &mut row,
        json!({"canonical_internal_opening_links":canonical,"internal_cached_boundary_entries":internal_entries,"internal_producer_consumer_opening_links":internal_links,"selected_leaf_checks":normal,"guard_layouts":shapes,"guard_vectors":14*shapes,"native_rejections":native,"map_rejections":old_maps+new_maps,"source_rejections":old_sources+new_sources,"cache_rejections":cache_negative,"selected_component":chosen_component,"selected_leaf":chosen_leaf,"additional_selected_engine_executions":2,"selected_correctness_execution_success":correct,"selected_disproof_execution_success":!correct}),
    )?;
    Ok((row, positive))
}

fn chain_probe_run(
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
fn result_identity(g: &Group) -> Value {
    let mut row = json!({"name":g.name,"profile":g.profile,"role":g.role,"base_role":g.base_role,"rho_counter":g.rho_counter,"c_counter":g.c_counter,"bit_index":g.bit_index,"execution_mode":g.execution_mode,"source_sha256":g.source_sha256,"source_maps_sha256":g.source_maps_sha256,"chain_source_sha256":g.chain_source_sha256,"chain_source_maps_sha256":g.chain_source_maps_sha256});
    for (key, value) in [
        ("asserted_scalar_le", json!(g.asserted_scalar_le)),
        (
            "asserted_scalar_quotient_le",
            json!(g.asserted_scalar_quotient_le),
        ),
        ("selected_bit", json!(g.selected_bit)),
        ("canonical_bit", json!(g.canonical_bit)),
        ("point_A", json!(g.point_A)),
        ("point_P", json!(g.point_P)),
        ("expected_E", json!(g.expected_E)),
        ("expected_R", json!(g.expected_R)),
        (
            "expected_rho_hi_output_state_hex",
            json!(g.expected_rho_hi_output_state_hex),
        ),
        (
            "expected_rho_lo_output_state_hex",
            json!(g.expected_rho_lo_output_state_hex),
        ),
        (
            "expected_rho_raw_state_le",
            json!(g.expected_rho_raw_state_le),
        ),
        ("expected_rho_result_le", json!(g.expected_rho_result_le)),
        (
            "expected_rho_quotient_le",
            json!(g.expected_rho_quotient_le),
        ),
        (
            "expected_prefix_output_state_hex",
            json!(g.expected_prefix_output_state_hex),
        ),
        (
            "expected_c_hi_output_state_hex",
            json!(g.expected_c_hi_output_state_hex),
        ),
        (
            "expected_c_lo_output_state_hex",
            json!(g.expected_c_lo_output_state_hex),
        ),
        ("expected_c_raw_state_le", json!(g.expected_c_raw_state_le)),
        ("expected_c_result_le", json!(g.expected_c_result_le)),
        ("expected_c_quotient_le", json!(g.expected_c_quotient_le)),
    ] {
        row.as_object_mut()
            .expect("local identity object")
            .insert(key.into(), value);
    }
    row
}
fn run() -> Result<Value> {
    let started = Instant::now();
    let args = std::env::args().collect::<Vec<_>>();
    if args.len() != 5 {
        return Err(
            "usage: byte_c_bit_point MANIFEST CASE_DIRECTORY OUTPUT EXPECTED_MANIFEST_SHA256"
                .into(),
        );
    }
    let root = Path::new(&args[2]);
    let manifest = Path::new(&args[1]);
    if manifest.file_name().and_then(|s| s.to_str()) != Some("manifest.json")
        || manifest.canonicalize()? != root.join("manifest.json").canonicalize()?
    {
        return Err("pinned manifest must belong to fresh case directory".into());
    }
    if Path::new(&args[3]).exists() {
        return Err("fresh output file required".into());
    }
    let pin = permutation::digest(&args[4])?;
    let raw = permutation::snapshot(manifest, chain::MANIFEST_CAP, pin)?;
    let run: Run = serde_json::from_slice(&raw)?;
    run.validate_directory(root)?;
    drop(raw);
    let mut records = RecordSink {
        hash: sha256::Hash::engine(),
        bytes: 0,
    };
    let mut metrics = Metrics::default();
    let mut cases = vec![];
    let mut probes = vec![];
    let mut probe_names = HashSet::new();
    for g in &run.cases {
        let (row, hashes) = group_run(&run, g, root, &mut records, &mut metrics)?;
        cases.push(row);
        if let Some(hashes) = hashes {
            let basis = basis_for(&run, g, root)?;
            let mut count = 0;
            for p in run.probes.iter().filter(|p| p.source_case == g.name) {
                if !probe_names.insert(p.name.clone()) {
                    return Err("private probe domain ID reused".into());
                }
                let row = match p.category.as_str() {
                    "chain" => chain_probe_run(
                        &run,
                        g,
                        p,
                        root,
                        &basis,
                        &hashes,
                        &mut records,
                        &mut metrics,
                    )?,
                    "scalar-alias" => scalar_probe::run(
                        p,
                        root,
                        g,
                        &run,
                        &basis,
                        &hashes,
                        &mut records,
                        &mut metrics,
                    )?,
                    "point-edge" | "point-negative" => probe_run::run(
                        p,
                        root,
                        g,
                        &run,
                        &basis,
                        &hashes,
                        &mut records,
                        &mut metrics,
                    )?,
                    _ => return Err("closed probe category".into()),
                };
                probes.push(row);
                count += 1;
            }
            if count != 26 {
                return Err("all26 private probes for each positive role required".into());
            }
            drop(hashes);
        }
    }
    if cases.len() != 6 || probes.len() != 52 || probe_names.len() != 52 {
        return Err("complete closed main/private corpus required".into());
    }
    let guards = cases
        .iter()
        .chain(&probes)
        .map(|row| {
            row["guard_vectors"]
                .as_u64()
                .ok_or_else(|| "actual guard count".into())
        })
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .sum::<u64>() as usize;
    let normal = cases
        .iter()
        .map(|row| {
            row["selected_leaf_checks"]
                .as_u64()
                .ok_or_else(|| "actual main execution count".into())
        })
        .chain(probes.iter().map(|row| {
            row["executed_leaves"]
                .as_u64()
                .ok_or_else(|| "actual probe execution count".into())
        }))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .sum::<u64>() as usize;
    if metrics.vectors != 2 * normal + guards + 116
        || metrics.expected_rejections != normal + guards + 58
        || records.bytes == 0
        || records.bytes > RECORD_UPPER
        || records.bytes > chain::RECORD_CAP
        || started.elapsed().as_secs_f64() > 1260.0
    {
        return Err(
            "actual calls/records/wall exceed independently closed unchanged budget".into(),
        );
    }
    let private_words = run.probes.iter().map(|p| p.words).sum::<usize>();
    let mut result = json!({"schema":"bitvm2-nova-byte-c-bit-point-execution/v1","passed":true,"input_manifest_sha256":hex::encode(pin),"cases":cases,"probes":probes,"metrics":metrics,"compact_execution_records_bytes":records.bytes,"compact_execution_records_sha256":sha256::Hash::from_engine(records.hash).to_string(),"wall_seconds":started.elapsed().as_secs_f64(),"full_statement_cases":2,"targeted_statement_cases":4});
    permutation::extend_object(
        &mut result,
        json!({"signature_entries_created":6*TOTAL_WORDS,"local_declared_words":6*LOCAL_WORDS,"cached_signature_reuses":6*1056,"canonical_internal_opening_links":6*46,"scalar_canonical_opening_links":6*9,"scalar_limb_opening_links":6*9,"selected_bit_opening_links":6*5,"internal_cached_boundary_entries":6*23000,"internal_producer_consumer_opening_links":6*46000,"private_probe_signature_entries_created":private_words,"private_probe_registries":52,"private_probe_trees":52}),
    )?;
    for name in [
        "challenge_bit_point_script_conformance_checked",
        "all_native_reference_predicates_checked",
        "boundary_opening_links_checked",
        "scalar_bits_reconstructed",
        "selected_bit_point_linked",
        "complete_addition_active_when_bit_zero",
        "point_edge_cases_checked",
        "private_probe_keys_separate",
        "private_probe_selected_scope_checked",
        "test_keys_only",
        "stack_limit_enabled",
        "hierarchical_membership_verified",
    ] {
        result
            .as_object_mut()
            .ok_or("summary object")?
            .insert(name.into(), json!(true));
    }
    for name in [
        "all_cases_full_statement_executed",
        "raw_vector_file_written",
        "op_cat_enabled",
        "full_permutation_verified",
        "full_hash_verified",
        "transcript_verified",
        "nova_transcript_verified_in_script",
        "proof_verified",
        "complete_nova_verifier",
        "complete_bitvm2_verifier",
        "production_assertion_binding",
        "bitcoin_transaction_graph",
        "panic_is_rejection",
        "eval_w_canonicality_script_bound",
        "dynamic_message_sources_script_bound",
        "eval_w_proof_origin_bound",
        "prior_state_transcript_bound",
        "complete_keccak_sponge",
        "coefficient_proof_origins_bound",
        "spartan_sumcheck_equations_verified",
        "external_raw_state_input_loaded",
        "scalar_multiplication_verified",
        "ipa_verified",
        "A_proof_origin_bound",
        "P_key_origin_bound",
        "all_negative_probe_leaves_executed",
    ] {
        result
            .as_object_mut()
            .ok_or("summary object")?
            .insert(name.into(), json!(false));
    }
    for name in [
        "setup_calls",
        "proving_jobs",
        "native_proofs_verified",
        "gpu_jobs",
        "transactions_broadcast",
    ] {
        result
            .as_object_mut()
            .ok_or("summary object")?
            .insert(name.into(), json!(0));
    }
    let raw = serde_json::to_vec(&result)?;
    if raw.len() > chain::SUMMARY_CAP {
        return Err("native summary exceeds unchanged1MiB".into());
    }
    let mut output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&args[3])?;
    output.write_all(&raw)?;
    Ok(result)
}
fn main() -> Result<()> {
    println!("{}", run()?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn census_is_explicit_mixed_role() {
        assert_eq!(WORDS.iter().sum::<usize>(), 156163);
        assert_eq!(LEAVES.iter().sum::<usize>(), 153213);
        assert_eq!(LOCAL_WORDS - TOTAL_WORDS, 1056);
        assert_eq!(keys::EXPECTED_UNIQUE_WORDS, TOTAL_WORDS);
        assert_eq!(keys::EXPECTED_LOCAL_DECLARATIONS, LOCAL_WORDS);
    }
    #[test]
    fn full_local_and_outer_depths_stay_bounded() {
        for (c, count) in LEAVES.iter().enumerate() {
            for index in [0, count - 1] {
                assert!(depth(*count, index).unwrap() + depth(11, c).unwrap() <= 19);
            }
        }
        assert!(depth(0, 0).is_err());
        assert!(depth(9, 9).is_err());
        // Frozen TaprootCommitment uses complete-left-filled-dfs, rather than
        // recursively splitting each subtree at the largest power of two.
        assert_eq!(depth(245, 244).unwrap(), 7);
        assert_eq!(depth(111, 109).unwrap(), 6);
        assert_eq!(depth(11, 10).unwrap(), 3);
        assert_eq!(depth(9, 0).unwrap(), 4);
        assert_eq!(depth(29245, 0).unwrap(), 15);
        assert_eq!(depth(29245, 29244).unwrap(), 14);
    }
    #[test]
    fn noncanonical_fixed_hex_is_rejected() {
        assert!(chain::fixed_hex::<1>("ff").is_ok());
        assert!(chain::fixed_hex::<1>("FF").is_err());
        assert!(chain::fixed_hex::<1>("0ff").is_err());
    }
    #[test]
    fn no_existing_baseline_count_gate_was_reused() {
        assert_eq!(chain::MAIN_UNIQUE_WORDS, 147355);
        assert_ne!(chain::MAIN_UNIQUE_WORDS, keys::EXPECTED_UNIQUE_WORDS);
        assert!(RECORD_UPPER < chain::RECORD_CAP);
    }
}
