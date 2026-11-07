//! Hosted TEST-ONLY grouped conditional point and live eleven-component forest.
#[path = "../../point-oracle/src/body_pins.rs"]
mod body_pins;
#[path = "../../point-oracle/src/chain.rs"]
#[allow(dead_code, unused_imports)]
mod chain;
#[path = "../../point-oracle/src/conditional_point.rs"]
mod conditional_point;
#[path = "../../grouped-convolution-oracle/src/body_pins.rs"]
mod grouped_body_pins;
mod grouped_point;
mod keys;
mod openings;
mod preflight;
mod private_sources;
mod probe_values;
mod probes;
#[path = "../../grouped-convolution-oracle/src/registry.rs"]
mod registry;
#[path = "../../rust-oracle/src/byte_rho_tail.rs"]
mod rho_tail;
mod runtime;
#[path = "../../point-oracle/src/scalar_bits.rs"]
mod scalar_bits;
mod source;
#[path = "../../rust-oracle/src/taproot_commitment.rs"]
mod taproot_commitment;
#[path = "../../rust-oracle/src/taproot_forest.rs"]
mod taproot_forest;
mod transport;
#[path = "../../point-oracle/src/uniform_alias.rs"]
mod uniform_alias;
use bitcoin::{
    hashes::{sha256, Hash, HashEngine},
    ScriptBuf,
};
use bitvm::signatures::{CompactWots, Wots, Wots4};
pub use bitvm2_nova_script_oracle::{engine, wots};
use chain::{self as legacy_chain, permutation, Basis};
use engine::Metrics;
use registry::{GraphSpec, Registry, Signature};
use runtime::{Case, Prepared, RecordSink};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, HashSet},
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
    time::Instant,
};
use taproot_commitment::TaprootCommitment;
use taproot_forest::TaprootForest;
pub(crate) use transport::{Group, Probe, Run};
use wots::{PublicKey, Result};
const WORDS: [usize; 11] = [
    29445, 29445, 587, 187, 29445, 23, 29445, 29445, 379, 264, 7498,
];
const LEAVES: [usize; 11] = [29245, 29245, 453, 111, 29245, 9, 29245, 29245, 245, 9, 3457];
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
const TOTAL_LEAVES: usize = 150509;
const RECORD_UPPER: u64 = 65235280;
pub(crate) fn nested_run(run: &Run) -> chain::Run {
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
fn point_selection(
    reference: &grouped_point::Reference,
    checked: &grouped_point::CheckedPoint,
) -> Result<Vec<usize>> {
    let mut selected: std::collections::BTreeSet<usize> =
        (6116..6124).chain([6159, 6160]).collect();
    let mut shapes = HashSet::new();
    for i in 0..reference.spec.leaves.len() {
        if shapes.insert(permutation::auth_shape(&reference.spec, i)) {
            selected.insert(i);
        }
    }
    if shapes.len() > 107 {
        return Err("old point layout bound".into());
    }
    let projected: std::collections::BTreeSet<_> = selected
        .into_iter()
        .map(|i| checked.projection.old_to_new[i].0)
        .collect();
    if projected.len() > 128 {
        return Err("projected point scope".into());
    }
    Ok(projected.into_iter().collect())
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
            c.ordinal != *i
                || abort.contains(i)
                || c.expected_correct != Some(!false_rows.contains(i))
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
    reference: &grouped_point::Reference,
) -> Result<(Prepared, grouped_point::CheckedPoint)> {
    let (case, maps, ids) = common_new(run, g, 10, root)?;
    let d = &g.components[10].descriptor;
    let checked = grouped_point::check(&case.spec, reference, &maps)?;
    if checked.program_sha256 != d.program_sha256
        || checked.catalogue_id != d.catalogue_id
        || checked.source_maps_sha256 != d.source_maps_sha256
    {
        return Err("actual conditional point source identity differs".into());
    }
    sidecar(run, g, 10, root, &checked.metadata, &checked.source_sha256)?;
    let truth = grouped_point::truth_all(&case.spec, &case.words, reference, &checked)?;
    let bad: Vec<_> = truth
        .iter()
        .enumerate()
        .filter_map(|(i, t)| (*t == Some(false)).then_some(i))
        .collect();
    let abort: Vec<_> = truth
        .iter()
        .enumerate()
        .filter_map(|(i, t)| t.is_none().then_some(i))
        .collect();
    if !bad.is_empty() || !abort.is_empty() {
        return Err(
            "main point must remain a valid conditional relation for its authenticated bit".into(),
        );
    }
    let verdict = grouped_point::checked_curve(reference, &case.words)?;
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
        (0..3457).collect()
    } else {
        point_selection(reference, &checked)?
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
            truth,
        },
        checked,
    ))
}
fn prepare_bits(run: &Run, g: &Group, root: &Path, refs: &chain::References) -> Result<Prepared> {
    let (case, maps, ids) = common_new(run, g, 9, root)?;
    let d = &g.components[9].descriptor;
    let old_spec = runtime::old_view(&case.spec)?;
    let checked = scalar_bits::check(
        &old_spec,
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
        .filter_map(|i| match scalar_bits::truth(&old_spec, &case.words, i) {
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
    let interfaces = (0..case.spec.words.len())
        .map(|word_index| source::Interface {
            word_index,
            global_id: ids[word_index].clone(),
            bound: case.spec.words[word_index].bound,
            occurrences: case
                .spec
                .leaves
                .iter()
                .enumerate()
                .flat_map(|(o, l)| {
                    l.wires
                        .iter()
                        .enumerate()
                        .filter_map(move |(f, w)| (*w == word_index).then_some((o, f)))
                })
                .collect(),
        })
        .collect();
    let mut facts = source::ComponentFacts {
        index: 9,
        branch: BRANCHES[9].into(),
        global_ids_sha256: d.global_ids_sha256.clone(),
        input_indices: vec![],
        output_indices: vec![],
        producer_ordinals: vec![],
        producer_occurrences: vec![],
        interfaces,
    };
    let truth = (0..9)
        .map(|i| scalar_bits::truth(&old_spec, &case.words, i).map(Some))
        .collect::<Result<Vec<_>>>()?;
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
        truth,
    })
}
pub(crate) fn prepare(
    run: &Run,
    g: &Group,
    index: usize,
    root: &Path,
    refs: &chain::References,
    basis: Option<&Basis>,
    reference: &grouped_point::Reference,
) -> Result<Prepared> {
    if index < 9 {
        runtime::from_legacy(chain::prepare(
            &nested_run(run),
            &g.chain_group(),
            index,
            root,
            refs,
            basis,
        )?)
    } else if index == 9 {
        prepare_bits(run, g, root, refs)
    } else if index == 10 {
        Ok(prepare_point_source(run, g, root, reference)?.0)
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
    let mut seed = b"BITVM2-NOVA/TEST-ONLY-GROUPED-C-BIT-POINT-FOREIGN/v1\0".to_vec();
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
            c.ordinal != *i || c.expected_correct != Some(!request.expected_false.contains(i))
        })
        || request.expected_selected_correct
            == request.expected_false.contains(&request.selected_leaf)
        || request
            .expected_abort_ordinals
            .contains(&request.selected_leaf)
    {
        return Err("private case identity/selection/truth differs".into());
    }
    let (registry, public, signatures) = probes::material(
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
    openings::validate_material(&registry, &public, &signatures, &case.words, &ids)?;
    let foreign = foreign_key(
        &request.source_sha256,
        &request.name,
        request.source_component.unwrap_or(9),
    )?;
    if public.contains(&foreign) {
        return Err("private foreign key collision".into());
    }
    let native = runtime::native_negatives(case, &public, &signatures, foreign, &registry)?;
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
                runtime::record(
                    records,
                    metrics,
                    &code,
                    &witness,
                    expected == Some(!mode),
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
    let normal_metrics = serde_json::to_value(&*metrics)?;
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
    let layouts = runtime::guard_subset(
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
        runtime::record(
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
    let negatives = probes::tree_negatives(&tree, &registry, &public)?;
    let mut row = serde_json::to_value(request)?;
    permutation::extend_object(
        &mut row,
        json!({"normal_metrics":normal_metrics,"metrics":serde_json::to_value(&*metrics)?,"context":case.spec.context,"registry_id":hex::encode(registry.identity()),"executed_leaves":executed,"false_predicates":request.expected_false,"abort_predicates":request.expected_abort_ordinals,"signature_entries_created":public.len(),"guard_layouts":layouts,"guard_vectors":14*layouts,"native_rejections":native,"additional_selected_engine_executions":2,"selected_correctness_execution_success":request.expected_selected_correct,"selected_disproof_execution_success":!request.expected_selected_correct}),
    )?;
    permutation::extend_object(
        &mut row,
        json!({"compiled_script_bytes":compiled,"largest_disproof_leaf_bytes":largest,"compiled_stream_sha256":sha256::Hash::from_engine(stream).to_string(),"native_predicates_classified":case.spec.leaves.len(),"tree":{"leaf_count":tree.leaf_count(),"compiled_script_bytes":compiled,"control_block_bytes":tree.control_block_bytes().len(),"merkle_root":hex::encode(tree.merkle_root().to_byte_array()),"output_key":hex::encode(tree.output_key().serialize()),"control_block_sha256":sha256::Hash::hash(&tree.control_block_bytes()).to_string(),"selected_script_sha256":sha256::Hash::hash(tree.selected_script().as_bytes()).to_string(),"compiled_stream_sha256":hex::encode(tree.compiled_stream_sha256()),"membership_verified":true,"roots_independently_pinned":false,"negative_counts":negatives}}),
    )?;
    Ok(row)
}

fn new_openings(
    checked: &source::CheckedSource,
    store: &runtime::OpeningStore,
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
    let actual = |c: usize, o: usize, f: usize| -> Result<&runtime::StoredOpening> {
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
        openings::same_assertion(&a.assertion, &b.assertion)?;
        openings::same_assertion(&a.assertion, &c.assertion)?;
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
        openings::same_assertion(&a.assertion, &b.assertion)?;
        bit_links += 1;
    }
    let foreign = store
        .values()
        .find(|b| b.assertion.id != a.assertion.id)
        .ok_or("independent new cache negative assertion")?;
    negatives += openings::negatives(&a.assertion, &foreign.assertion)?;
    let scalar = actual(8, 72, 0)?;
    negatives += openings::negatives(&scalar.assertion, &a.assertion)?;
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
    reference: &grouped_point::Reference,
    point: &grouped_point::CheckedPoint,
) -> Result<source::CheckedSource> {
    let checked = source::build(
        &run.context,
        &g.role,
        g.rho_counter,
        g.bit_index,
        &run.operation_id,
        descriptors,
        facts,
        reference,
        point,
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
    reference: &grouped_point::Reference,
    point: &grouped_point::CheckedPoint,
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
        if checked_source(run, g, descriptors, &bad, reference, point).is_ok() {
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
        if checked_source(run, g, &bad, facts, reference, point).is_ok() {
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
    reference: &grouped_point::Reference,
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
        let mut p = prepare(run, g, index, root, &refs, basis.as_ref(), reference)?;
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
                spec: runtime::old_view(&p.case.spec)?,
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
    let (_, point_checked) = prepare_point_source(run, g, root, reference)?;
    let old = chain::checked_outer(&nr, &cg, &descriptors[..9], &facts[..9])?;
    let checked = checked_source(run, g, &descriptors, &facts, reference, &point_checked)?;
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
    let (new_maps, new_sources) =
        new_admission_negatives(run, g, &descriptors, &facts, reference, &point_checked)?;
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
        "honest" => (10, 3456),
        "coherent-bit" => (9, g.bit_index / 29),
        "coherent-scalar-alias" => (8, 244),
        _ => return Err("closed point profile".into()),
    };
    let mut components = vec![];
    let mut live = vec![];
    let mut store = runtime::OpeningStore::new();
    let mut global_stream = sha256::Hash::engine();
    let mut native = 0;
    let mut canonical = 0;
    let mut internal_entries = 0;
    let mut internal_links = 0;
    let mut cache_negative = 0;
    let mut normal = 0;
    let mut shapes = 0;
    let mut retained_point = None;
    for index in 0..11 {
        let p = prepare(run, g, index, root, &refs, basis.as_ref(), reference)?;
        let h = &g.components[index];
        let (registry, public, signatures) = runtime::registry_for(&p, &pool)?;
        let foreign = foreign_key(&g.source_sha256, &g.name, index)?;
        if public.contains(&foreign) {
            return Err("foreign key collision".into());
        }
        native += runtime::native_negatives(&p.case, &public, &signatures, foreign, &registry)?;
        let mut component_metrics = Metrics::default();
        let measured = runtime::measure_execute(
            &p,
            h,
            &registry,
            &signatures,
            records,
            &mut component_metrics,
            &g.name,
            &mut global_stream,
            false,
        )?;
        runtime::fold(metrics, &component_metrics);
        shapes += measured["guard_layouts"]
            .as_u64()
            .ok_or("layout count type")? as usize;
        normal += p.case.checks.len();
        if let Some(full) = &p.full {
            let (entries, links, rejections) = openings::internal(
                &registry,
                &public,
                &signatures,
                &p.case.words,
                &p.global_ids,
                &chain::internal_joins(full)
                    .into_iter()
                    .map(|j| openings::Join {
                        producer_occurrences: j.producer_occurrences,
                        consumer_occurrences: j.consumer_occurrences,
                    })
                    .collect::<Vec<_>>(),
            )?;
            internal_entries += entries;
            internal_links += links;
            cache_negative += rejections;
        } else {
            openings::validate_material(
                &registry,
                &public,
                &signatures,
                &p.case.words,
                &p.global_ids,
            )?;
        }
        canonical += runtime::capture_interfaces(&p, &registry, &public, &signatures, &mut store)?;
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
        if index == 9 && g.profile == "honest" {
            old_registry_tree_parity(&registry, &public, &signatures, &tree, selected)?;
        }
        let mut ledger = serde_json::to_value(&h.descriptor)?;
        permutation::extend_object(&mut ledger, measured)?;
        permutation::extend_object(
            &mut ledger,
            json!({"merkle_root":hex::encode(tree.merkle_root().to_byte_array()),"output_key":hex::encode(tree.output_key().serialize())}),
        )?;
        if index == 10 {
            let ordinal = p
                .case
                .spec
                .leaves
                .iter()
                .position(|l| l.kind == "conv_ab_all")
                .ok_or("first actual grouped AB absent")?;
            permutation::extend_object(
                &mut ledger,
                json!({"group_ordinal":ordinal,"group_witness_sha256":runtime::witness_hash(&registry.witness(ordinal,&signatures)?),"assertion_material_sha256":runtime::material_hash(&registry,&public,&signatures,&p.case.words,&p.global_ids)?}),
            )?;
        }
        components.push(ledger);
        live.push(tree);
        if g.profile == "honest" && index == 10 {
            retained_point = Some((p, registry, public, signatures));
        } else {
            drop(registry);
            drop(public);
            drop(signatures);
            drop(p);
        }
    }
    let (connections, connection_negatives) = runtime::verify_connections(&old, &store)?;
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
    let (selected, registry, public, signatures) = if let Some(retained) = retained_point {
        retained
    } else {
        let p = prepare(
            run,
            g,
            chosen_component,
            root,
            &refs,
            basis.as_ref(),
            reference,
        )?;
        let (r, k, s) = runtime::registry_for(&p, &pool)?;
        (p, r, k, s)
    };
    openings::validate_material(
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
        .is_none_or(|c| c.expected_correct != Some(correct))
    {
        return Err(
            "selected genuine false/correct predicate missing from actual executed source".into(),
        );
    }
    let mut primary_metrics = Metrics::default();
    let witness = registry.witness(chosen_leaf, &signatures)?;
    for mode in [false, true] {
        runtime::record(
            records,
            &mut primary_metrics,
            &registry.script(chosen_leaf, mode)?,
            &witness,
            correct != mode,
            &g.name,
            json!(format!("{chosen_component}/tree/{chosen_leaf}")),
            mode,
        )?;
    }
    runtime::fold(metrics, &primary_metrics);
    let negatives = runtime::forest_negatives(&forest, &registry, &mut live)?;
    let tree = json!({"components":11,"leaf_count":forest.leaf_count(),"compiled_script_bytes":compiled,"selected_component":chosen_component,"selected_leaf":chosen_leaf,"control_block_bytes":forest.control_block_bytes().len(),"merkle_root":hex::encode(forest.merkle_root().to_byte_array()),"output_key":hex::encode(forest.output_key().serialize()),"control_block_sha256":sha256::Hash::hash(&forest.control_block_bytes()).to_string(),"selected_script_sha256":sha256::Hash::hash(forest.selected_script().as_bytes()).to_string(),"component_manifest_sha256":hex::encode(forest.component_manifest_sha256()),"compiled_stream_sha256":sha256::Hash::from_engine(global_stream.clone()).to_string(),"hierarchical_membership_verified":true,"roots_independently_pinned":false,"negative_counts":negatives});
    let alternate = if correct {
        Some(alternate_point(
            &selected,
            &registry,
            &public,
            &signatures,
            &pool,
            &mut live,
            &forest,
            &components[10],
            &tree,
            &global_stream,
            records,
            metrics,
            &g.name,
        )?)
    } else {
        None
    };
    let mut row = result_identity(g);
    permutation::extend_object(
        &mut row,
        json!({"primary_selection_metrics":primary_metrics,"alternate_point":alternate,"components":components,"connections":connections,"forest":tree,"full_statement_executed":correct,"signature_entries_created":pool.len(),"local_declared_words":pool.local_declarations(),"cached_signature_reuses":pool.cached_signature_reuses(),"all_native_predicates_classified":TOTAL_LEAVES,"scalar_limb_opening_links":scalar_links,"scalar_canonical_opening_links":scalar_canonical,"selected_bit_opening_links":bit_links}),
    )?;
    permutation::extend_object(
        &mut row,
        json!({"canonical_internal_opening_links":canonical,"internal_cached_boundary_entries":internal_entries,"internal_producer_consumer_opening_links":internal_links,"selected_leaf_checks":normal,"guard_layouts":shapes,"guard_vectors":14*shapes,"native_rejections":native,"map_rejections":old_maps+new_maps,"source_rejections":old_sources+new_sources,"cache_rejections":cache_negative,"selected_component":chosen_component,"selected_leaf":chosen_leaf,"additional_selected_engine_executions":2,"selected_correctness_execution_success":correct,"selected_disproof_execution_success":!correct}),
    )?;
    Ok((row, positive))
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

fn local_tree_json(tree: &TaprootCommitment, negative_counts: Value) -> Value {
    json!({"leaf_count":tree.leaf_count(),"compiled_script_bytes":tree.compiled_script_bytes(),"control_block_bytes":tree.control_block_bytes().len(),"merkle_root":hex::encode(tree.merkle_root().to_byte_array()),"output_key":hex::encode(tree.output_key().serialize()),"control_block_sha256":sha256::Hash::hash(&tree.control_block_bytes()).to_string(),"selected_script_sha256":sha256::Hash::hash(tree.selected_script().as_bytes()).to_string(),"compiled_stream_sha256":hex::encode(tree.compiled_stream_sha256()),"membership_verified":true,"roots_independently_pinned":false,"negative_counts":negative_counts})
}

/// A genuine unchanged small component, using the SAME already admitted keys
/// and signatures. No baseline proving, signing or Script engine calls occur.
fn old_registry_tree_parity(
    registry: &Registry,
    public: &[PublicKey],
    signatures: &[Signature],
    tree: &TaprootCommitment,
    selected: usize,
) -> Result<()> {
    let old = runtime::old_view(registry.spec())?;
    let catalogue = old.identity()?;
    let id = old.key_identity(public)?;
    let baseline =
        bitvm2_nova_script_oracle::registry::Registry::new(old, public.to_vec(), catalogue, id)?;
    if baseline.identity() != registry.identity() {
        return Err("unchanged registry identity differs".into());
    }
    for i in 0..registry.spec().leaves.len() {
        if baseline.witness(i, signatures)? != registry.witness(i, signatures)? {
            return Err("unchanged witness parity".into());
        }
        for mode in [false, true] {
            if baseline.script(i, mode)?.as_bytes() != registry.script(i, mode)?.as_bytes() {
                return Err("unchanged Script parity".into());
            }
        }
    }
    let prior =
        bitvm2_nova_script_oracle::taproot_commitment::TaprootCommitment::new(&baseline, selected)?;
    if prior.registry_id() != tree.registry_id()
        || prior.catalogue_id() != tree.catalogue_id()
        || prior.merkle_root() != tree.merkle_root()
        || prior.output_key() != tree.output_key()
        || prior.compiled_script_bytes() != tree.compiled_script_bytes()
        || prior.compiled_stream_sha256() != tree.compiled_stream_sha256()
        || prior.control_block_bytes() != tree.control_block_bytes()
        || prior.selected_script() != tree.selected_script()
    {
        return Err("unchanged live tree/control/u32 stream parity differs".into());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn alternate_point(
    selected: &Prepared,
    registry: &Registry,
    public: &[PublicKey],
    signatures: &[Signature],
    _pool: &keys::GlobalPool,
    live: &mut Vec<TaprootCommitment>,
    primary: &TaprootForest,
    point_ledger: &Value,
    primary_forest: &Value,
    global_stream: &sha256::HashEngine,
    records: &mut RecordSink,
    all: &mut Metrics,
    name: &str,
) -> Result<Value> {
    let ordinal = selected
        .case
        .spec
        .leaves
        .iter()
        .position(|l| l.kind == "conv_ab_all")
        .ok_or("actual grouped AB leaf missing")?;
    if selected.truth[ordinal] != Some(true) {
        return Err("honest grouped AB must be true".into());
    }
    let material = runtime::material_hash(
        registry,
        public,
        signatures,
        &selected.case.words,
        &selected.global_ids,
    )?;
    let witness = registry.witness(ordinal, signatures)?;
    if point_ledger["group_ordinal"] != json!(ordinal)
        || point_ledger["group_witness_sha256"] != json!(runtime::witness_hash(&witness))
        || point_ledger["assertion_material_sha256"] != json!(material)
    {
        return Err("same actual grouped assertion material differs".into());
    }
    let alternate = TaprootCommitment::new(registry, ordinal)?;
    let previous = live.get(10).ok_or("live point tree missing")?;
    if alternate.registry_id() != previous.registry_id()
        || alternate.catalogue_id() != previous.catalogue_id()
        || alternate.merkle_root() != previous.merkle_root()
        || alternate.output_key() != previous.output_key()
        || alternate.compiled_script_bytes() != previous.compiled_script_bytes()
        || alternate.compiled_stream_sha256() != previous.compiled_stream_sha256()
        || alternate.leaf_count() != previous.leaf_count()
    {
        return Err("alternate grouped leaf changed actual local tree".into());
    }
    alternate.verify_member(
        registry,
        alternate.merkle_root(),
        alternate.output_key(),
        ordinal,
    )?;
    let local_neg = probes::tree_negatives(&alternate, registry, public)?;
    let local = local_tree_json(&alternate, json!(local_neg));
    // The same first ten live objects remain in this vector; no tree receipts or clones.
    let original = std::mem::replace(&mut live[10], alternate);
    let forest = TaprootForest::new(live, 10)?;
    if forest.component_manifest_sha256() != primary.component_manifest_sha256()
        || forest.manifest() != primary.manifest()
        || forest.merkle_root() != primary.merkle_root()
        || forest.output_key() != primary.output_key()
        || forest.compiled_script_bytes() != primary.compiled_script_bytes()
        || forest.leaf_count() != primary.leaf_count()
    {
        return Err("alternate group changed actual live forest".into());
    }
    forest.verify_member(
        registry,
        forest.component_manifest_sha256(),
        forest.merkle_root(),
        forest.output_key(),
        10,
        ordinal,
    )?;
    let negatives = runtime::forest_negatives(&forest, registry, live)?;
    let mut forest_json = primary_forest.clone();
    let obj = forest_json.as_object_mut().ok_or("primary forest object")?;
    for (k, v) in [
        ("selected_component", json!(10)),
        ("selected_leaf", json!(ordinal)),
        (
            "control_block_bytes",
            json!(forest.control_block_bytes().len()),
        ),
        (
            "control_block_sha256",
            json!(sha256::Hash::hash(&forest.control_block_bytes()).to_string()),
        ),
        (
            "selected_script_sha256",
            json!(sha256::Hash::hash(forest.selected_script().as_bytes()).to_string()),
        ),
        ("negative_counts", json!(negatives)),
    ] {
        obj.insert(k.into(), v);
    }
    if forest_json["compiled_stream_sha256"]
        != json!(sha256::Hash::from_engine(global_stream.clone()).to_string())
    {
        return Err("alternate whole stream mismatch".into());
    }
    let mut metrics = Metrics::default();
    for mode in [false, true] {
        runtime::record(
            records,
            &mut metrics,
            &registry.script(ordinal, mode)?,
            &witness,
            !mode,
            name,
            json!(format!("10/ab/{ordinal}")),
            mode,
        )?;
    }
    let layouts = runtime::guard_subset(
        registry,
        signatures,
        records,
        &mut metrics,
        name,
        10,
        Some(&[ordinal]),
        1,
    )?;
    if layouts != 1 || metrics.vectors != 16 || metrics.expected_rejections != 15 {
        return Err("alternate group actual execution census".into());
    }
    runtime::fold(all, &metrics);
    let _alternate = std::mem::replace(&mut live[10], original);
    let mut row = json!({"selected_component":10,"selected_leaf":ordinal,"registry_id":hex::encode(registry.identity()),"catalogue_id":hex::encode(registry.spec().identity()?),"assertion_material_sha256":material,"selected_witness_sha256":runtime::witness_hash(&witness),"local_tree":local,"forest":forest_json});
    permutation::extend_object(
        &mut row,
        json!({"guard_vectors":14,"additional_selected_engine_executions":2,"selected_correctness_execution_success":true,"selected_disproof_execution_success":false,"metrics":metrics}),
    )?;
    Ok(row)
}

fn fold_json(target: &mut Metrics, row: &Value) -> Result<()> {
    let n = |k: &str| -> Result<usize> {
        row[k]
            .as_u64()
            .map(|x| x as usize)
            .ok_or_else(|| format!("actual metrics {k} absent").into())
    };
    let m = Metrics {
        vectors: n("vectors")?,
        expected_rejections: n("expected_rejections")?,
        max_script_bytes: n("max_script_bytes")?,
        max_witness_items: n("max_witness_items")?,
        max_witness_payload_bytes: n("max_witness_payload_bytes")?,
        max_stack_items: n("max_stack_items")?,
    };
    runtime::fold(target, &m);
    Ok(())
}

fn run() -> Result<Value> {
    let started = Instant::now();
    let args = std::env::args().collect::<Vec<_>>();
    if args.len() != 7 || args[1] != "--role" {
        return Err("usage: grouped_byte_c_bit_point --role ROLE MANIFEST CASE_DIRECTORY OUTPUT EXPECTED_SHA".into());
    }
    let role = transport::Role::parse(&args[2])?;
    let manifest = Path::new(&args[3]);
    let root = Path::new(&args[4]);
    if manifest.file_name().and_then(|x| x.to_str()) != Some("manifest.json")
        || manifest.canonicalize()? != root.join("manifest.json").canonicalize()?
    {
        return Err("manifest must belong to fresh corpus directory".into());
    }
    if Path::new(&args[5]).exists() {
        return Err("fresh output file required".into());
    }
    let run = transport::load_run(manifest, role, &args[6])?;
    run.validate_directory(root)?;
    let (spec, maps, reference_hash) = run.legacy_reference(root)?;
    let reference = grouped_point::admit_reference(
        spec,
        maps,
        &reference_hash,
        &run.context,
        role.base_role(),
        0,
        &format!("{}/point/bit/0", run.operation_id),
    )?;
    // Every source, assignment and closed private recipe is admitted before ANY key generation.
    let basis = preflight::all(&run, root, &reference)?;
    let mut records = RecordSink::new();
    let mut metrics = Metrics::default();
    let mut normal_metrics = Metrics::default();
    let mut cases = vec![];
    let mut probes = vec![];
    let mut names = HashSet::new();
    for g in &run.cases {
        let (row, hashes) = group_run(&run, g, root, &reference, &mut records, &mut metrics)?;
        for c in row["components"]
            .as_array()
            .ok_or("actual component ledgers")?
        {
            fold_json(&mut normal_metrics, &c["normal_metrics"])?;
        }
        cases.push(row);
        if let Some(hashes) = hashes {
            for request in run.probes.iter().filter(|p| p.source_case == g.name) {
                if !names.insert(request.name.clone()) {
                    return Err("private domain reused".into());
                }
                let mut private_metrics = Metrics::default();
                let row = probes::run(
                    request,
                    root,
                    g,
                    &run,
                    &basis,
                    &reference,
                    &hashes,
                    &mut records,
                    &mut private_metrics,
                )?;
                fold_json(&mut normal_metrics, &row["normal_metrics"])?;
                runtime::fold(&mut metrics, &private_metrics);
                probes.push(row);
            }
        }
    }
    if cases.len() != 3 || probes.len() != 27 || names.len() != 27 {
        return Err("complete role-filtered 3+27 corpus required".into());
    }
    let guards = cases
        .iter()
        .chain(&probes)
        .map(|r| {
            r["guard_vectors"]
                .as_u64()
                .ok_or("actual guard vectors absent")
        })
        .collect::<std::result::Result<Vec<_>, _>>()?
        .into_iter()
        .sum::<u64>() as usize;
    let normal = normal_metrics.vectors / 2;
    if normal_metrics.vectors % 2 != 0
        || metrics.vectors != 2 * normal + guards + 14 + 62
        || metrics.expected_rejections != normal + guards + 14 + 31
        || metrics.vectors > 341804
        || metrics.expected_rejections > 187520
        || records.bytes == 0
        || records.bytes > RECORD_UPPER
        || started.elapsed().as_secs_f64() > 1260.0
    {
        return Err("actual role calls/records/wall exceed closed budget".into());
    }
    let private_words = run.probes.iter().map(|p| p.words).sum::<usize>();
    let mut result = json!({"schema":"bitvm2-nova-grouped-byte-c-bit-point-execution/v1","passed":true,"role":role.as_str(),"input_manifest_sha256":args[6],"script_stream_framing":"u32le-length-script/v1","cases":cases,"probes":probes,"metrics":metrics,"normal_metrics":normal_metrics,"compact_execution_records_bytes":records.bytes,"compact_execution_records_sha256":sha256::Hash::from_engine(records.hash).to_string(),"wall_seconds":started.elapsed().as_secs_f64(),"full_statement_cases":1,"targeted_statement_cases":2});
    permutation::extend_object(
        &mut result,
        json!({"signature_entries_created":3*TOTAL_WORDS,"local_declared_words":3*LOCAL_WORDS,"cached_signature_reuses":3*1056,"canonical_internal_opening_links":3*46,"scalar_canonical_opening_links":3*9,"scalar_limb_opening_links":3*9,"selected_bit_opening_links":3*5,"internal_cached_boundary_entries":3*23000,"internal_producer_consumer_opening_links":3*46000,"private_probe_signature_entries_created":private_words,"private_probe_registries":27,"private_probe_trees":27}),
    )?;
    permutation::extend_object(
        &mut result,
        json!({"legacy_point_reference":{"file_sha256":reference.sha256,"program_sha256":reference.checked.program_sha256,"catalogue_id":reference.checked.catalogue_id,"words":7498,"leaves":6161,"executed":false,"committed":false}}),
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
        "grouped_point_projection_checked",
        "frozen_nonpoint_identities_checked",
        "alternate_point_membership_checked",
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
        return Err("native summary unchanged1MiB cap".into());
    }
    OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&args[5])?
        .write_all(&raw)?;
    Ok(result)
}
fn main() -> Result<()> {
    println!("{}", run()?);
    Ok(())
}
