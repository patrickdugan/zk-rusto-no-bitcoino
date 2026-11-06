//! Isolated retained scalar-source fixture. No production proof/root acceptance.
#[allow(dead_code, unused_imports)]
mod backend;
#[allow(dead_code, unused_imports)]
pub(crate) mod old_chain;
pub(crate) use old_chain as chain;
#[path = "../../point-oracle/src/body_pins.rs"]
mod body_pins;
#[path = "../../point-oracle/src/conditional_point.rs"]
mod conditional_point;
mod eval_w_encoding;
mod keys;
#[path = "../../point-oracle/src/transport.rs"]
mod legacy_transport;
mod probe;
mod probe_run;
mod retained_scalar_block;
#[path = "../../rust-oracle/src/byte_rho_tail.rs"]
mod rho_tail;
#[path = "../../point-oracle/src/scalar_bits.rs"]
mod scalar_bits;
mod scalar_probe;
mod source;
mod source_probes;
mod transport;
#[path = "../../point-oracle/src/uniform_alias.rs"]
mod uniform_alias;
use bitvm2_nova_script_oracle::{
    engine::Metrics,
    registry::{Registry, Signature},
    wots::{PublicKey, Result},
};
pub(crate) use legacy_transport::{Group, Probe, Run};
use serde_json::Value;
use std::{collections::HashSet, path::Path};

pub(crate) struct SourcePrepared {
    pub(crate) core: chain::Prepared,
    pub(crate) tape: Option<retained_scalar_block::CheckedTape>,
    pub(crate) encoding: Option<eval_w_encoding::CheckedEncoding>,
}

// Stable aliases required by the frozen algebra/probe modules. New thirteen-
// component transport is kept separate and explicitly adapts its first eleven.
pub(crate) fn prepare_point_source(
    run: &Run,
    g: &Group,
    root: &Path,
) -> Result<(chain::Prepared, conditional_point::CheckedPoint)> {
    backend::prepare_point_source(run, g, root)
}
pub(crate) fn execute_private(
    request: &Probe,
    case: &chain::permutation::Case,
    keys: &HashSet<[u8; 32]>,
    records: &mut chain::RecordSink,
    metrics: &mut Metrics,
) -> Result<Value> {
    backend::execute_private(request, case, keys, records, metrics)
}

/// The caller has validated complete registry material before this batch.
/// All comparisons use real Registry witness chunks, not equality of metadata.
pub(crate) fn encoding_internal_openings(
    case: &chain::permutation::Case,
    registry: &Registry,
    keys: &[PublicKey],
    sigs: &[Signature],
    ids: &[String],
) -> Result<usize> {
    if case.spec.words.len() != 55 || case.spec.leaves.len() != 17 || case.words.len() != 55 {
        return Err("exact55/17 encoding required before internal opening capture".into());
    }
    let pair = |word: usize, a: (usize, usize), b: (usize, usize)| -> Result<()> {
        for (ordinal, formal) in [a, b] {
            if case
                .spec
                .leaves
                .get(ordinal)
                .and_then(|leaf| leaf.wires.get(formal))
                != Some(&word)
            {
                return Err("encoding internal pair detached from actual source word".into());
            }
        }
        let x = chain::openings::capture(registry, keys, sigs, &case.words, ids, a.0, a.1)?;
        let y = chain::openings::capture(registry, keys, sigs, &case.words, ids, b.0, b.1)?;
        chain::openings::same_assertion(&x, &y)
    };
    let mut count = 0;
    for limb in 0..9 {
        pair(limb, (7 + limb, 0), (16, limb))?;
        count += 1;
    }
    for aux in 0..14 {
        let word = 41 + aux;
        let consumers = (7..16)
            .flat_map(|ordinal| {
                case.spec.leaves[ordinal]
                    .wires
                    .iter()
                    .enumerate()
                    .filter_map(move |(formal, index)| {
                        (formal > 0 && *index == word).then_some((ordinal, formal))
                    })
            })
            .collect::<Vec<_>>();
        if consumers.len() != 1 {
            return Err("split auxiliary must have one reconstruction consumer".into());
        }
        pair(word, (aux / 2, 1 + aux % 2), consumers[0])?;
        count += 1;
    }
    if count != 23 {
        return Err("all23 canonical/split opening links required".into());
    }
    Ok(count)
}

fn new_global_id(
    index: usize,
    name: &str,
    reference: &retained_scalar_block::Reference,
) -> Result<String> {
    if index == 11 {
        let text = name
            .strip_prefix("block/byte/")
            .ok_or("actual retained BYTE local name")?;
        let i: usize = text.parse()?;
        if i >= 112 || i.to_string() != text {
            return Err("canonical retained BYTE index".into());
        }
        Ok(if i < 32 {
            format!("rho/message/eval_w/byte/{i}")
        } else if i >= 48 {
            format!(
                "c/coeff/{}/byte/{}",
                if i < 80 { 0 } else { 2 },
                (i - 48) % 32
            )
        } else {
            format!("proof/container-byte/{}", reference.bundle_offset + i)
        })
    } else if index == 12 {
        if let Some(text) = name.strip_prefix("scalar/encoding/byte/") {
            let i: usize = text.parse()?;
            if i >= 32 || i.to_string() != text {
                return Err("canonical eval_W BYTE index".into());
            }
            Ok(format!("rho/message/eval_w/byte/{i}"))
        } else {
            let id = format!("eval-w/{name}");
            if !chain::permutation::identifier(&id) {
                return Err("bounded encoding private ID".into());
            }
            Ok(id)
        }
    } else {
        Err("new scalar component index".into())
    }
}

fn prepare_addition(
    context: &str,
    operation: &str,
    role: &str,
    counter: u64,
    group: &str,
    index: usize,
    h: &chain::Header,
    asserted: &[u32; 112],
    root: &Path,
    basis: &chain::Basis,
    reference: &retained_scalar_block::Reference,
) -> Result<SourcePrepared> {
    use bitcoin::hashes::{sha256, Hash};
    use serde_json::json;
    if ![11, 12].contains(&index) || reference.role != role || asserted.iter().any(|v| *v >= 256) {
        return Err("typed main scalar-source parameters".into());
    }
    let branch = if index == 11 {
        "retained-scalar-block"
    } else {
        "eval-w-encoding"
    };
    let op = format!(
        "{operation}/proof/{}",
        if index == 11 {
            "scalar-block"
        } else {
            "eval-w"
        }
    );
    let d = &h.descriptor;
    let bytes = chain::checked_file(
        root,
        &h.filename,
        chain::INPUT_CAP,
        &h.file_sha256,
        h.file_bytes,
    )?;
    let case: chain::permutation::Case = serde_json::from_slice(&bytes)?;
    drop(bytes);
    if case.name != format!("{group}/{branch}")
        || !case.measure_all
        || case.spec.context != context
        || case.spec.field_role != role
        || case.spec.operation_id != op
        || d.operation_id != op
        || d.counter != counter
        || d.index != index
        || d.field_role != role
        || d.branch != branch
        || d.kind != branch
        || case.spec.program_sha256 != d.program_sha256
        || case.expected_spec_id != d.catalogue_id
        || case.spec.identity()? != chain::permutation::digest(&d.catalogue_id)?
        || case.words.len() != d.words
        || case.spec.words.len() != d.words
        || case.spec.leaves.len() != d.leaves
        || h.full.is_some()
        || h.program_manifest_filename.is_some()
        || h.program_manifest_file_sha256.is_some()
        || h.program_manifest_file_bytes.is_some()
    {
        return Err("actual new scalar-source graph/header identity differs".into());
    }
    let raw = chain::checked_file(
        root,
        &h.maps_filename,
        chain::MAP_CAP,
        &h.maps_file_sha256,
        h.maps_file_bytes,
    )?;
    let maps: Value = serde_json::from_slice(&raw)?;
    if chain::permutation::canonical(&maps)? != raw
        || sha256::Hash::hash(&raw).to_string() != d.source_maps_sha256
        || h.maps_file_sha256 != d.source_maps_sha256
    {
        return Err("new scalar-source canonical maps differ".into());
    }
    let mut tape = None;
    let mut encoding = None;
    let metadata = if index == 11 {
        let checked = retained_scalar_block::check(
            &case.spec, context, role, counter, &op, &maps, reference,
        )?;
        if d.words != 112
            || d.leaves != 112
            || case.words != retained_scalar_block::expected_assignment(asserted)
            || checked.source_sha256 != d.source_sha256
        {
            return Err("actual asserted tape/source hash differs".into());
        }
        let value = checked.metadata.clone();
        tape = Some(checked);
        value
    } else {
        let (uniform, _) = chain::project_uniform(
            &basis.spec,
            &basis.checked,
            &format!("{op}/uniform-reference"),
        )?;
        let checked = eval_w_encoding::check(&case.spec, context, role, &op, &maps, &uniform)?;
        let raw: [u8; 32] = asserted[..32]
            .iter()
            .map(|v| u8::try_from(*v))
            .collect::<std::result::Result<Vec<_>, _>>()?
            .try_into()
            .map_err(|_| "eval_W exact raw32")?;
        if d.words != 55
            || d.leaves != 17
            || case.words != eval_w_encoding::expected_assignment(&raw)
            || checked.source_sha256 != d.source_sha256
        {
            return Err("actual eval_W unsigned witness/source hash differs".into());
        }
        let value = checked.metadata.clone();
        encoding = Some(checked);
        value
    };
    if chain::checked_file(
        root,
        &h.source_manifest_filename,
        chain::MANIFEST_CAP,
        &h.source_manifest_file_sha256,
        h.source_manifest_file_bytes,
    )? != chain::permutation::canonical(&metadata)?
    {
        return Err("new scalar-source actual metadata differs".into());
    }
    let ids = case
        .spec
        .words
        .iter()
        .map(|w| new_global_id(index, &w.name, reference))
        .collect::<Result<Vec<_>>>()?;
    if ids.iter().collect::<HashSet<_>>().len() != ids.len()
        || sha256::Hash::hash(&chain::permutation::canonical(&json!(ids))?).to_string()
            != d.global_ids_sha256
    {
        return Err("actual scalar-source global map differs".into());
    }
    let false_rows = (0..case.spec.leaves.len())
        .filter_map(|i| {
            match if index == 11 {
                retained_scalar_block::truth(&case.spec, &case.words, i)
            } else {
                eval_w_encoding::truth(&case.spec, &case.words, i)
            } {
                Ok(true) => None,
                Ok(false) => Some(Ok(i)),
                Err(e) => Some(Err(e)),
            }
        })
        .collect::<Result<Vec<_>>>()?;
    if !false_rows.is_empty()
        || !h.expected_false.is_empty()
        || !h.expected_abort_ordinals.is_empty()
        || h.execution_mode != "all"
        || h.selected_ordinals.is_some()
        || case.checks.len() != case.spec.leaves.len()
        || case
            .checks
            .iter()
            .enumerate()
            .any(|(i, c)| c.ordinal != i || !c.expected_correct)
    {
        return Err("all main added scalar predicates must be true and fully executed".into());
    }
    let mut facts = chain::compact_facts(&case, 8, &ids, None)?;
    facts.index = index;
    facts.branch = branch.into();
    Ok(SourcePrepared {
        core: chain::Prepared {
            case,
            global_ids: ids,
            facts,
            full: None,
            tail: None,
            frame: None,
            absorb: None,
        },
        tape,
        encoding,
    })
}

use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitvm2_nova_script_oracle::{
    taproot_commitment::TaprootCommitment, taproot_forest::TaprootForest,
};
use serde_json::json;
use std::{collections::BTreeMap, fs::OpenOptions, io::Write, time::Instant};
use transport::{SourceGroup, SourceRun};
const TOTAL_WORDS: usize = 155146;
const LOCAL_WORDS: usize = 156330;
const TOTAL_LEAVES: usize = 153342;
const RECORD_UPPER: u64 = 133969276;
const WORDS: [usize; 13] = [
    29445, 29445, 587, 187, 29445, 23, 29445, 29445, 379, 264, 7498, 112, 55,
];
const LEAVES: [usize; 13] = [
    29245, 29245, 453, 111, 29245, 9, 29245, 29245, 245, 9, 6161, 112, 17,
];
fn claimed_block(g: &SourceGroup, r: &retained_scalar_block::Reference) -> Result<[u32; 112]> {
    let mut expected = r.raw_span;
    match g.point.profile.as_str() {
        "honest" => {}
        "coherent-coefficient" => expected[48] ^= 1,
        "coherent-eval-w" => expected[0] ^= 1,
        _ => return Err("closed retained claim profile".into()),
    }
    let actual = chain::fixed_hex::<112>(&g.asserted_block_hex)?;
    if actual != expected {
        return Err(
            "claim must be the exact independent reference or closed coherent byte mutation".into(),
        );
    }
    for scalar in [&actual[..32], &actual[48..80], &actual[80..112]] {
        let raw: [u8; 32] = scalar.try_into().map_err(|_| "scalar claim width")?;
        chain::canonical_scalar(&raw, &g.point.role)?;
    }
    Ok(actual.map(u32::from))
}
fn prepare_component(
    run: &SourceRun,
    g: &SourceGroup,
    index: usize,
    root: &Path,
    refs: &chain::References,
    basis: Option<&chain::Basis>,
    reference: &retained_scalar_block::Reference,
    asserted: &[u32; 112],
) -> Result<SourcePrepared> {
    if index < 11 {
        Ok(SourcePrepared {
            core: backend::prepare(&run.point_run(), &g.point_group(), index, root, refs, basis)?,
            tape: None,
            encoding: None,
        })
    } else {
        let h = if index == 11 {
            &g.block_component
        } else if index == 12 {
            &g.eval_w_component
        } else {
            return Err("source component index bound".into());
        };
        prepare_addition(
            &run.context,
            &run.operation_id,
            &g.point.role,
            g.point.rho_counter,
            &g.point.name,
            index,
            h,
            asserted,
            root,
            basis.ok_or("independently checked Uniform basis absent")?,
            reference,
        )
    }
}
fn rebuilt_source(
    run: &SourceRun,
    g: &SourceGroup,
    headers: &[chain::Header],
    facts: &[source::ComponentFacts],
    r: &retained_scalar_block::Reference,
) -> Result<source::CheckedSource> {
    let d = headers
        .iter()
        .map(|h| h.descriptor.clone())
        .collect::<Vec<_>>();
    let checked = source::build(
        &run.context,
        &g.point.role,
        g.point.rho_counter,
        g.point.bit_index,
        &run.operation_id,
        &d,
        facts,
        r,
    )?;
    if checked.source_sha256 != g.source_sha256 || checked.source_maps_sha256 != g.maps_sha256 {
        return Err("independent retained scalar source differs from scenario pin".into());
    }
    Ok(checked)
}
fn source_admission_negatives(
    run: &SourceRun,
    g: &SourceGroup,
    headers: &[chain::Header],
    facts: &[source::ComponentFacts],
    r: &retained_scalar_block::Reference,
) -> Result<(usize, usize)> {
    let mut map_count = 0;
    let mut source_count = 0;
    for mutation in 0..12 {
        let mut bad = facts.to_vec();
        match mutation {
            0 => bad[11].interfaces[0].global_id = bad[11].interfaces[1].global_id.clone(),
            1 => bad[11].interfaces[0].bound = 1 << 29,
            2 => {
                bad[11].interfaces[32].global_id =
                    format!("proof/container-byte/{}", r.bundle_offset + 33)
            }
            3 => bad[11].interfaces[48].global_id = "c/coeff/2/byte/0".into(),
            4 => bad[11].interfaces[0].occurrences[0].0 += 1,
            5 => bad[12].interfaces[9].global_id = "rho/message/eval_w/byte/1".into(),
            6 => bad[12].interfaces[0].bound = 256,
            7 => bad[12].interfaces[41].occurrences[0].1 = 0,
            8 => bad[11].input_indices.push(0),
            9 => bad[12].producer_ordinals.push(0),
            10 => {
                bad[11].global_ids_sha256 = chain::permutation::changed(&bad[11].global_ids_sha256)?
            }
            _ => {
                bad[12].global_ids_sha256 = chain::permutation::changed(&bad[12].global_ids_sha256)?
            }
        };
        if rebuilt_source(run, g, headers, &bad, r).is_ok() {
            return Err("substituted tape/encoding map accepted".into());
        }
        map_count += 1;
    }
    for mutation in 0..12 {
        let mut bad = headers.to_vec();
        match mutation {
            0 => bad[11].descriptor.field_role = g.point.base_role.clone(),
            1 => bad[12].descriptor.counter += 1,
            2 => bad[11].descriptor.operation_id.push_str("/other"),
            3 => {
                bad[12].descriptor.program_sha256 =
                    chain::permutation::changed(&bad[12].descriptor.program_sha256)?
            }
            4 => {
                bad[11].descriptor.catalogue_id =
                    chain::permutation::changed(&bad[11].descriptor.catalogue_id)?
            }
            5 => {
                bad[12].descriptor.source_sha256 =
                    chain::permutation::changed(&bad[12].descriptor.source_sha256)?
            }
            6 => {
                bad[11].descriptor.source_maps_sha256 =
                    chain::permutation::changed(&bad[11].descriptor.source_maps_sha256)?
            }
            7 => {
                bad[12].descriptor.global_ids_sha256 =
                    chain::permutation::changed(&bad[12].descriptor.global_ids_sha256)?
            }
            8 => bad[11].descriptor.words += 1,
            9 => bad[12].descriptor.leaves += 1,
            10 => bad.swap(11, 12),
            _ => bad[11].descriptor.program_identity_kind = "plain unrelated Program".into(),
        };
        if rebuilt_source(run, g, &bad, facts, r).is_ok() {
            return Err("substituted tape/encoding descriptor accepted".into());
        }
        source_count += 1;
    }
    Ok((map_count, source_count))
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct TapeTarget {
    component_index: usize,
    word_index: usize,
    occurrences: Vec<(usize, usize)>,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct TapeLink {
    global_id: String,
    source_component: usize,
    source_word: usize,
    source_ordinal: usize,
    source_occurrence: usize,
    targets: Vec<TapeTarget>,
}
fn tape_openings(
    checked: &source::CheckedSource,
    store: &chain::OpeningStore,
) -> Result<(usize, usize)> {
    let links: Vec<TapeLink> = serde_json::from_value(checked.maps["tape_to_consumers"].clone())?;
    if links.len() != 96 {
        return Err("exact96 dynamic tape interfaces required".into());
    }
    let mut count = 0;
    let mut representatives = BTreeMap::new();
    for link in &links {
        if link.source_component != 11
            || link.source_word >= 112
            || (32..48).contains(&link.source_word)
        {
            return Err("actual tape dynamic source differs".into());
        }
        let a = store
            .get(&(11, link.source_ordinal, link.source_occurrence))
            .ok_or("actual tape source witness opening absent")?;
        if a.word != link.source_word
            || a.assertion.id != link.global_id
            || a.assertion.bound != 256
        {
            return Err("actual tape source word/global/bound differs".into());
        }
        for target in &link.targets {
            if ![0, 1, 3, 4, 12].contains(&target.component_index) {
                return Err("closed tape target component".into());
            }
            for (ordinal, formal) in &target.occurrences {
                let b = store
                    .get(&(target.component_index, *ordinal, *formal))
                    .ok_or("actual tape consumer opening absent")?;
                if b.word != target.word_index
                    || b.assertion.id != link.global_id
                    || b.assertion.bound != 256
                {
                    return Err("actual tape consumer word/global/bound differs".into());
                }
                chain::openings::same_assertion(&a.assertion, &b.assertion)?;
                count += 1;
                representatives
                    .entry(target.component_index)
                    .or_insert(&a.assertion);
            }
        }
    }
    if count != 352 || representatives.len() != 5 {
        return Err("all352 direct tape consumer assertions required".into());
    }
    let mut negatives = 0;
    for original in representatives.values() {
        let foreign = store
            .values()
            .find(|x| x.assertion.id != original.id)
            .ok_or("foreign tape assertion absent")?;
        negatives += chain::openings::negatives(original, &foreign.assertion)?;
    }
    let internal = store
        .get(&(12, 7, 0))
        .ok_or("new eval canonical source missing")?;
    let foreign = store
        .values()
        .find(|x| x.assertion.id != internal.assertion.id)
        .ok_or("foreign eval assertion absent")?;
    negatives += chain::openings::negatives(&internal.assertion, &foreign.assertion)?;
    if negatives != 36 {
        return Err("all36 tape/encoding cache mutation checks required".into());
    }
    Ok((count, negatives))
}

fn group_run(
    run: &SourceRun,
    g: &SourceGroup,
    root: &Path,
    records: &mut chain::RecordSink,
    metrics: &mut Metrics,
) -> Result<(
    Value,
    Option<HashSet<[u8; 32]>>,
    retained_scalar_block::Reference,
)> {
    let point_run = run.point_run();
    let point = g.point_group();
    source::validate_policy(
        &run.context,
        &point.role,
        point.rho_counter,
        point.bit_index,
        &run.operation_id,
    )?;
    let reference = retained_scalar_block::reference(&run.reference_path(root)?, &point.role)?;
    let asserted = claimed_block(g, &reference)?;
    let headers = g.headers();
    let refs = chain::references(&point.chain_group())?;
    let mut basis = None;
    let mut declarations = keys::Declarations::new();
    let mut facts = vec![];
    for index in 0..13 {
        let mut p = prepare_component(
            run,
            g,
            index,
            root,
            &refs,
            basis.as_ref(),
            &reference,
            &asserted,
        )?;
        for ((id, w), value) in p
            .core
            .global_ids
            .iter()
            .zip(&p.core.case.spec.words)
            .zip(&p.core.case.words)
        {
            declarations.add(id, w.bound, *value)?;
        }
        facts.push(p.core.facts.clone());
        if index == 2 {
            basis = Some(chain::Basis {
                spec: p.core.case.spec.clone(),
                checked: p
                    .core
                    .tail
                    .take()
                    .ok_or("actual small rho-tail basis absent")?,
            });
        }
    }
    if declarations.len() != TOTAL_WORDS
        || declarations.local_declarations() != LOCAL_WORDS
        || declarations.cached_signature_reuses() != 1184
    {
        return Err("independent thirteen-component declaration census differs".into());
    }
    let descriptors = headers
        .iter()
        .map(|h| h.descriptor.clone())
        .collect::<Vec<_>>();
    let point_checked =
        backend::checked_source(&point_run, &point, &descriptors[..11], &facts[..11])?;
    let chain_run = backend::nested_run(&point_run);
    let chain_group = point.chain_group();
    let chain_checked =
        chain::checked_outer(&chain_run, &chain_group, &descriptors[..9], &facts[..9])?;
    let checked = rebuilt_source(run, g, &headers, &facts, &reference)?;
    for (file, pin, cap, value) in [
        (
            &point.chain_source_filename,
            &point.chain_source_file_sha256,
            chain::MANIFEST_CAP,
            &chain_checked.manifest,
        ),
        (
            &point.chain_maps_filename,
            &point.chain_maps_file_sha256,
            chain::MAP_CAP,
            &chain_checked.maps,
        ),
        (
            &point.point_source_filename,
            &point.point_source_file_sha256,
            chain::MANIFEST_CAP,
            &point_checked.manifest,
        ),
        (
            &point.point_maps_filename,
            &point.point_maps_file_sha256,
            chain::MAP_CAP,
            &point_checked.maps,
        ),
        (
            &g.source_file,
            &g.source_file_sha256,
            chain::MANIFEST_CAP,
            &checked.manifest,
        ),
        (
            &g.maps_file,
            &g.maps_file_sha256,
            chain::MAP_CAP,
            &checked.maps,
        ),
    ] {
        let size = std::fs::symlink_metadata(root.join(file))?.len();
        if chain::checked_file(root, file, cap, pin, size)? != chain::permutation::canonical(value)?
        {
            return Err("fresh actual compact source sidecar differs".into());
        }
    }
    let (old_maps, old_sources) =
        chain::admission_negatives(&chain_run, &chain_group, &descriptors[..9], &facts[..9])?;
    let (point_maps, point_sources) =
        backend::new_admission_negatives(&point_run, &point, &descriptors[..11], &facts[..11])?;
    let (new_maps, new_sources) = source_admission_negatives(run, g, &headers, &facts, &reference)?;
    drop(descriptors);
    drop(facts);
    let pool = declarations.seal(&g.source_sha256, &point.name)?;
    let positive = if point.profile == "honest" {
        let h = pool.public_key_hashes();
        if h.len() != TOTAL_WORDS {
            return Err("complete positive key catalogue collision".into());
        }
        Some(h)
    } else {
        None
    };
    let mut components = vec![];
    let mut live = vec![];
    let mut store = chain::OpeningStore::new();
    let mut stream = sha256::Hash::engine();
    let mut native = 0;
    let mut internal_entries = 0;
    let mut internal_links = 0;
    let mut canonical = 0;
    let mut eval_internal = 0;
    let mut cache_negative = 0;
    let mut normal = 0;
    let mut shapes = 0;
    for index in 0..13 {
        let p = prepare_component(
            run,
            g,
            index,
            root,
            &refs,
            basis.as_ref(),
            &reference,
            &asserted,
        )?;
        let core = &p.core;
        let h = &headers[index];
        let (registry, public, signatures) = chain::registry_for(core, &pool)?;
        let foreign = backend::foreign_key(&g.source_sha256, &point.name, index)?;
        if public.contains(&foreign) {
            return Err("foreign test key collision".into());
        }
        native += chain::permutation::native_negatives(
            &core.case,
            &public,
            &signatures,
            foreign,
            &registry,
        )?;
        let measured = chain::measure_execute(
            core,
            h,
            &registry,
            &signatures,
            records,
            metrics,
            &point.name,
            &mut stream,
            false,
        )?;
        normal += core.case.checks.len();
        shapes += measured["guard_layouts"]
            .as_u64()
            .ok_or("actual layout count type")? as usize;
        if let Some(full) = &core.full {
            let (entries, links, negatives) = chain::openings::internal(
                &registry,
                &public,
                &signatures,
                &core.case.words,
                &core.global_ids,
                &chain::internal_joins(full),
            )?;
            internal_entries += entries;
            internal_links += links;
            cache_negative += negatives;
        } else {
            chain::openings::validate_material(
                &registry,
                &public,
                &signatures,
                &core.case.words,
                &core.global_ids,
            )?;
        }
        canonical += chain::capture_interfaces(core, &registry, &public, &signatures, &mut store)?;
        if index == 12 {
            eval_internal += encoding_internal_openings(
                &core.case,
                &registry,
                &public,
                &signatures,
                &core.global_ids,
            )?;
        }
        let chosen = if index == 12 { 16 } else { 0 };
        let tree = TaprootCommitment::new(&registry, chosen)?;
        if tree.registry_id() != registry.identity()
            || tree.catalogue_id() != chain::permutation::digest(&h.descriptor.catalogue_id)?
            || tree.leaf_count() != LEAVES[index]
            || tree.compiled_script_bytes()
                != measured["compiled_script_bytes"]
                    .as_u64()
                    .ok_or("compiled byte type")?
            || hex::encode(tree.compiled_stream_sha256())
                != measured["compiled_stream_sha256"]
                    .as_str()
                    .ok_or("stream digest type")?
        {
            return Err("live tree differs from complete measured component".into());
        }
        tree.verify_member(&registry, tree.merkle_root(), tree.output_key(), chosen)?;
        let mut row = serde_json::to_value(&h.descriptor)?;
        chain::permutation::extend_object(&mut row, measured)?;
        components.push(row);
        live.push(tree);
        drop(registry);
        drop(public);
        drop(signatures);
        drop(p);
    }
    let (connections, old_cache) = chain::verify_connections(&chain_checked, &store)?;
    cache_negative += old_cache;
    let (scalar_links, scalar_canonical, bit_links, point_cache) =
        backend::new_openings(&point_checked, &store)?;
    cache_negative += point_cache;
    let (tape_links, new_cache) = tape_openings(&checked, &store)?;
    cache_negative += new_cache;
    drop(store);
    drop(point_checked);
    drop(chain_checked);
    drop(checked);
    let map_count = old_maps + point_maps + new_maps;
    let source_count = old_sources + point_sources + new_sources;
    if native != 312
        || map_count != 34
        || source_count != 42
        || cache_negative != 144
        || canonical != 46
        || internal_entries != 23000
        || internal_links != 46000
        || scalar_links != 9
        || scalar_canonical != 9
        || bit_links != 5
        || tape_links != 352
        || eval_internal != 23
        || normal
            != if point.profile == "honest" {
                TOTAL_LEAVES
            } else {
                1063
            }
        || shapes > 487
    {
        return Err("closed scalar-source execution/opening/negative census differs".into());
    }
    let selected = prepare_component(
        run,
        g,
        12,
        root,
        &refs,
        basis.as_ref(),
        &reference,
        &asserted,
    )?;
    let (registry, public, signatures) = chain::registry_for(&selected.core, &pool)?;
    chain::openings::validate_material(
        &registry,
        &public,
        &signatures,
        &selected.core.case.words,
        &selected.core.global_ids,
    )?;
    let forest = TaprootForest::new(&live, 12)?;
    forest.verify_member(
        &registry,
        forest.component_manifest_sha256(),
        forest.merkle_root(),
        forest.output_key(),
        12,
        16,
    )?;
    let compiled = components
        .iter()
        .map(|c| {
            c["compiled_script_bytes"]
                .as_u64()
                .ok_or_else(|| "compiled component byte type".into())
        })
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .sum::<u64>();
    if forest.component_count() != 13
        || forest.leaf_count() != TOTAL_LEAVES as u64
        || forest.compiled_script_bytes() != compiled
        || compiled > 5 << 28
        || forest.control_block_bytes().len() != 257
        || forest.selected_script().as_bytes() != registry.script(16, true)?.as_bytes()
    {
        return Err("complete thirteen-component live forest differs".into());
    }
    let witness = registry.witness(16, &signatures)?;
    for mode in [false, true] {
        chain::record(
            records,
            metrics,
            &registry.script(16, mode)?,
            &witness,
            !mode,
            &point.name,
            json!("12/tree/16"),
            mode,
        )?;
    }
    let negatives = chain::forest_negatives(&forest, &registry, &mut live)?;
    let tree = json!({"components":13,"leaf_count":forest.leaf_count(),"compiled_script_bytes":compiled,"selected_component":12,"selected_leaf":16,"control_block_bytes":forest.control_block_bytes().len(),"merkle_root":hex::encode(forest.merkle_root().to_byte_array()),"output_key":hex::encode(forest.output_key().serialize()),"control_block_sha256":sha256::Hash::hash(&forest.control_block_bytes()).to_string(),"selected_script_sha256":sha256::Hash::hash(forest.selected_script().as_bytes()).to_string(),"component_manifest_sha256":hex::encode(forest.component_manifest_sha256()),"compiled_stream_sha256":sha256::Hash::from_engine(stream).to_string(),"hierarchical_membership_verified":true,"roots_independently_pinned":false,"negative_counts":negatives});
    let mut row = point_identity(&point);
    let claimed_bytes = asserted
        .iter()
        .map(|v| u8::try_from(*v))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    chain::permutation::extend_object(
        &mut row,
        json!({"point_source_sha256":point.source_sha256,"point_source_maps_sha256":point.source_maps_sha256,"source_sha256":g.source_sha256,"source_maps_sha256":g.maps_sha256,"asserted_block_hex":g.asserted_block_hex,"asserted_block_sha256":sha256::Hash::hash(&claimed_bytes).to_string(),"reference_block_sha256":sha256::Hash::hash(&reference.raw_span).to_string(),"asserted_equals_reference":claimed_bytes==reference.raw_span,"reference_admitted_native":true,"reference":reference.summary(),"full_statement_executed":point.profile=="honest","components":components,"connections":connections,"forest":tree}),
    )?;
    chain::permutation::extend_object(
        &mut row,
        json!({"signature_entries_created":pool.len(),"local_declared_words":pool.local_declarations(),"cached_signature_reuses":pool.cached_signature_reuses(),"all_native_predicates_classified":TOTAL_LEAVES,"selected_leaf_checks":normal,"guard_layouts":shapes,"guard_vectors":14*shapes,"canonical_internal_opening_links":canonical,"internal_cached_boundary_entries":internal_entries,"internal_producer_consumer_opening_links":internal_links,"scalar_limb_opening_links":scalar_links,"scalar_canonical_opening_links":scalar_canonical,"selected_bit_opening_links":bit_links,"tape_consumer_opening_links":tape_links,"eval_w_internal_opening_links":eval_internal}),
    )?;
    chain::permutation::extend_object(
        &mut row,
        json!({"native_rejections":native,"map_rejections":map_count,"source_rejections":source_count,"cache_rejections":cache_negative,"selected_component":12,"selected_leaf":16,"additional_selected_engine_executions":2,"selected_correctness_execution_success":true,"selected_disproof_execution_success":false}),
    )?;
    Ok((row, positive, reference))
}

fn point_identity(g: &Group) -> Value {
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
        return Err("usage: retained_scalar_sources MANIFEST CASE_DIRECTORY OUTPUT EXPECTED_MANIFEST_SHA256".into());
    }
    let root = Path::new(&args[2]);
    let manifest = Path::new(&args[1]);
    if manifest.file_name().and_then(|s| s.to_str()) != Some("manifest.json")
        || manifest.canonicalize()? != root.join("manifest.json").canonicalize()?
    {
        return Err("pinned manifest must belong to fresh case directory".into());
    }
    if Path::new(&args[3]).exists() {
        return Err("fresh direct native result required".into());
    }
    let pin = chain::permutation::digest(&args[4])?;
    let raw = chain::permutation::snapshot(manifest, chain::MANIFEST_CAP, pin)?;
    let run: SourceRun = serde_json::from_slice(&raw)?;
    run.validate_directory(root)?;
    drop(raw);
    let mut records = chain::RecordSink {
        hash: sha256::Hash::engine(),
        bytes: 0,
    };
    let mut metrics = Metrics::default();
    let mut cases = vec![];
    let mut probe_rows = BTreeMap::new();
    for g in &run.cases {
        let (row, positive, reference) = group_run(&run, g, root, &mut records, &mut metrics)?;
        cases.push(row);
        if let Some(keys) = positive {
            let point_run = run.point_run();
            let point = g.point_group();
            let refs = chain::references(&point.chain_group())?;
            let basis = backend::basis_for(&point_run, &point, root)?;
            let asserted = claimed_block(g, &reference)?;
            let mut count = 0;
            for p in run.probes.iter().filter(|p| p.source_case == point.name) {
                if probe_rows.contains_key(&p.name) {
                    return Err("one-time private probe ID reused".into());
                }
                let row = match p.category.as_str() {
                    "chain" => backend::chain_probe_run(
                        &point_run,
                        &point,
                        p,
                        root,
                        &basis,
                        &keys,
                        &mut records,
                        &mut metrics,
                    )?,
                    "scalar-alias" => scalar_probe::run(
                        p,
                        root,
                        &point,
                        &point_run,
                        &basis,
                        &keys,
                        &mut records,
                        &mut metrics,
                    )?,
                    "point-edge" | "point-negative" => probe_run::run(
                        p,
                        root,
                        &point,
                        &point_run,
                        &basis,
                        &keys,
                        &mut records,
                        &mut metrics,
                    )?,
                    "eval-w-encoding" | "scalar-block" => {
                        let index = p
                            .source_component
                            .ok_or("new private scalar component absent")?;
                        let source = prepare_component(
                            &run,
                            g,
                            index,
                            root,
                            &refs,
                            Some(&basis),
                            &reference,
                            &asserted,
                        )?;
                        source_probes::run(
                            p,
                            root,
                            &source,
                            &reference,
                            &keys,
                            &mut records,
                            &mut metrics,
                        )?
                    }
                    _ => return Err("closed private source category".into()),
                };
                probe_rows.insert(p.name.clone(), row);
                count += 1;
            }
            if count != 37 {
                return Err("all37 private probes per honest role required".into());
            }
            drop(keys);
        }
    }
    if cases.len() != 6 || probe_rows.len() != 74 {
        return Err("complete six-source/seventy-four-probe execution required".into());
    }
    // One complete positive key catalogue lives at a time; report rows retain the
    // declared manifest order, independently of that resource-safe dispatch order.
    let mut probes = Vec::with_capacity(74);
    for p in &run.probes {
        probes.push(
            probe_rows
                .remove(&p.name)
                .ok_or("executed probe row missing")?,
        );
    }
    if !probe_rows.is_empty() {
        return Err("undeclared private probe result".into());
    }
    let guards = cases
        .iter()
        .chain(&probes)
        .map(|row| {
            row["guard_vectors"]
                .as_u64()
                .ok_or_else(|| "actual guard count type".into())
        })
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .sum::<u64>() as usize;
    let normal = cases
        .iter()
        .map(|row| {
            row["selected_leaf_checks"]
                .as_u64()
                .ok_or_else(|| "actual main count type".into())
        })
        .chain(probes.iter().map(|row| {
            row["executed_leaves"]
                .as_u64()
                .ok_or_else(|| "actual private count type".into())
        }))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .sum::<u64>() as usize;
    let private_internal = probes
        .iter()
        .map(|row| {
            row["eval_w_internal_opening_links"]
                .as_u64()
                .ok_or_else(|| "actual private internal link count".into())
        })
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .sum::<u64>();
    if normal != 314408
        || metrics.vectors != 2 * normal + guards + 160
        || metrics.expected_rejections != normal + guards + 80
        || private_internal != 322
        || records.bytes == 0
        || records.bytes > RECORD_UPPER
        || records.bytes > chain::RECORD_CAP
        || started.elapsed().as_secs_f64() > 1260.0
    {
        return Err("actual record/call/wall/link census violates closed unchanged budget".into());
    }
    let private_words = run.probes.iter().map(|p| p.words).sum::<usize>();
    let mut result = json!({"schema":"bitvm2-nova-retained-scalar-sources-execution/v1","passed":true,"input_manifest_sha256":hex::encode(pin),"cases":cases,"probes":probes,"metrics":metrics,"compact_execution_records_bytes":records.bytes,"compact_execution_records_sha256":sha256::Hash::from_engine(records.hash).to_string(),"wall_seconds":started.elapsed().as_secs_f64(),"full_statement_cases":2,"targeted_statement_cases":4});
    chain::permutation::extend_object(
        &mut result,
        json!({"signature_entries_created":6*TOTAL_WORDS,"local_declared_words":6*LOCAL_WORDS,"cached_signature_reuses":6*1184,"private_probe_signature_entries_created":private_words,"private_probe_registries":74,"private_probe_trees":74,"tape_consumer_opening_links":6*352,"eval_w_internal_opening_links":6*23,"private_eval_w_internal_opening_links":private_internal}),
    )?;
    chain::permutation::extend_object(
        &mut result,
        json!({"canonical_internal_opening_links":6*46,"scalar_canonical_opening_links":6*9,"scalar_limb_opening_links":6*9,"selected_bit_opening_links":6*5,"internal_cached_boundary_entries":6*23000,"internal_producer_consumer_opening_links":6*46000,"main_opening_comparisons":291516}),
    )?;
    for flag in [
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
        "retained_scalar_source_script_conformance_checked",
        "reference_container_admitted",
        "source_block_prefix_constants_checked",
        "tape_to_scalar_byte_opening_links_checked",
        "eval_w_canonicality_script_relation_checked",
        "coherent_changed_claims_accepted",
    ] {
        result
            .as_object_mut()
            .ok_or("summary object")?
            .insert(flag.into(), json!(true));
    }
    for flag in [
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
        "proof_byte_origins_bound",
        "whole_container_script_bound",
        "proof_length_script_bound",
        "proof_eof_script_bound",
        "proof_sha256_script_bound",
        "bundle_sha256_script_bound",
        "reference_hash_authenticates_asserted_block",
        "asserted_proof_validated_native",
    ] {
        result
            .as_object_mut()
            .ok_or("summary object")?
            .insert(flag.into(), json!(false));
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
        return Err("summary exceeds unchanged1MiB".into());
    }
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
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
    fn fixed_profile_census_is_new_not_old_gate() {
        assert_eq!(WORDS.iter().sum::<usize>(), 156330);
        assert_eq!(LEAVES.iter().sum::<usize>(), 153342);
        assert_eq!(LOCAL_WORDS - TOTAL_WORDS, 1184);
        assert_eq!(keys::EXPECTED_UNIQUE_WORDS, TOTAL_WORDS);
        assert_eq!(keys::EXPECTED_LOCAL_DECLARATIONS, LOCAL_WORDS);
        assert_ne!(TOTAL_WORDS, backend::TOTAL_WORDS);
    }
    #[test]
    fn complete_left_filled_tree_depth_stays_under_oldcap() {
        for (i, n) in LEAVES.iter().enumerate() {
            for ordinal in [0, n - 1] {
                assert!(
                    backend::depth(*n, ordinal).unwrap() + backend::depth(13, i).unwrap() <= 19
                );
            }
        }
        assert_eq!(
            33 + 32 * (backend::depth(17, 16).unwrap() + backend::depth(13, 12).unwrap()),
            257
        );
    }
    #[test]
    fn record_budget_remains_below_unmodified_hardcap() {
        assert_eq!(chain::RECORD_CAP, 128 << 20);
        assert_eq!(RECORD_UPPER, 133969276);
        assert!(chain::RECORD_CAP - RECORD_UPPER >= 248452);
    }
}
