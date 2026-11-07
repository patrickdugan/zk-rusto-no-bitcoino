//! M23 retained compressed-commitment decoding under the frozen legacy adapter.
//! One curve role per run: the unchanged BYTE tape plus every commitment
//! decoder of that role. Assertion-local evidence, not proof, tree or
//! production binding. Panics and process failures never count as rejection.
mod keys;
#[path = "../../point-oracle/src/body_pins.rs"]
mod legacy_body_pins;
#[path = "../../scalar-source-oracle/src/retained_scalar_block.rs"]
mod reference_admission;
mod source;
mod transport;
use bitcoin::{
    hashes::{sha256, Hash, HashEngine},
    ScriptBuf,
};
use bitvm2_nova_script_oracle::{
    engine::{self, Metrics},
    registry::{GraphSpec, Registry},
    wots::{id32, Result},
};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fs,
    io::{self, Write},
    path::Path,
    time::Instant,
};

const RECORD_CAP: usize = 128 << 20;
const SUMMARY_CAP: usize = 1 << 20;
const RECORD_LINE_BUDGET: usize = 218;
const GUARD_CAP: usize = 512;
const LEAF_SCRIPT_CAP: usize = 100_000;
const COMPONENT_SCRIPT_CAP: usize = 256 << 20;
const AGGREGATE_SCRIPT_CAP: usize = 5 << 28;
const WALL_CAP_SECONDS: f64 = 2280.0;

fn require(yes: bool, message: &str) -> Result<()> {
    if yes {
        Ok(())
    } else {
        Err(message.into())
    }
}
fn sha(raw: &[u8]) -> String {
    sha256::Hash::hash(raw).to_string()
}
fn framed(h: &mut sha256::HashEngine, raw: &[u8]) {
    h.input(&(raw.len() as u64).to_le_bytes());
    h.input(raw);
}
fn witness_hash(witness: &[Vec<u8>]) -> String {
    let mut h = sha256::Hash::engine();
    h.input(&(witness.len() as u64).to_le_bytes());
    for item in witness {
        framed(&mut h, item);
    }
    sha256::Hash::from_engine(h).to_string()
}
fn fold(total: &mut Metrics, local: &Metrics) {
    total.vectors += local.vectors;
    total.expected_rejections += local.expected_rejections;
    total.max_script_bytes = total.max_script_bytes.max(local.max_script_bytes);
    total.max_witness_items = total.max_witness_items.max(local.max_witness_items);
    total.max_witness_payload_bytes = total
        .max_witness_payload_bytes
        .max(local.max_witness_payload_bytes);
    total.max_stack_items = total.max_stack_items.max(local.max_stack_items);
}

/// Closed engine-call bound, fixed before any graph is loaded or key generated.
fn call_budget(engine: &str) -> Result<usize> {
    let components = source::plan(engine)?.len() + 1;
    let leaves = (0..components)
        .map(|index| source::census(engine, index).map(|c| c.3))
        .sum::<Result<usize>>()?;
    let targeted = source::PROFILES.len() - 1;
    Ok(2 * leaves
        + 14 * GUARD_CAP * components
        + targeted * (2 * source::TARGET_CAP + 14 * GUARD_CAP)
        + 1024)
}

struct RecordSink {
    bytes: usize,
    cap: usize,
    hash: sha256::HashEngine,
}
impl RecordSink {
    fn new(cap: usize) -> Self {
        Self {
            bytes: 0,
            cap,
            hash: sha256::Hash::engine(),
        }
    }
}
impl Write for RecordSink {
    fn write(&mut self, raw: &[u8]) -> io::Result<usize> {
        let total = self
            .bytes
            .checked_add(raw.len())
            .ok_or_else(|| io::Error::other("record overflow"))?;
        if total > RECORD_CAP || total > self.cap {
            return Err(io::Error::other("compact execution-record byte bound"));
        }
        self.bytes = total;
        self.hash.input(raw);
        Ok(raw.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn owned_guard_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 32
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/_.:-".contains(&b))
}
#[allow(clippy::too_many_arguments)]
fn record(
    out: &mut RecordSink,
    metrics: &mut Metrics,
    name: &str,
    component: usize,
    index: Value,
    disprove: bool,
    script: &ScriptBuf,
    witness: &[Vec<u8>],
    expected: bool,
) -> Result<()> {
    require(
        name.len() == 4
            && name.starts_with("d/")
            && name.as_bytes()[2..].iter().all(u8::is_ascii_digit)
            && component < 16,
        "closed compact record case/component",
    )?;
    match &index {
        Value::String(value) => {
            require(owned_guard_id(value), "owned escapeless guard identifier")?
        }
        Value::Number(n) => require(n.as_u64().is_some_and(|n| n < 30000), "record leaf ordinal")?,
        _ => return Err("record index type".into()),
    };
    require(
        script.len() <= LEAF_SCRIPT_CAP,
        "per-leaf Script exceeds unchanged100000-byte cap",
    )?;
    let (actual, stack) = engine::execute(script, witness.to_vec())?;
    require(
        actual == expected,
        &format!("{name}/{component}/{index}: expected{expected}, got{actual}"),
    )?;
    metrics.vectors += 1;
    metrics.expected_rejections += usize::from(!expected);
    metrics.max_script_bytes = metrics.max_script_bytes.max(script.len());
    metrics.max_witness_items = metrics.max_witness_items.max(witness.len());
    metrics.max_witness_payload_bytes = metrics
        .max_witness_payload_bytes
        .max(witness.iter().map(Vec::len).sum());
    metrics.max_stack_items = metrics.max_stack_items.max(stack);
    require(
        stack <= 1000 && witness.len() <= 1000,
        "unchanged 1000-item stack limit",
    )?;
    let mut line = serde_json::to_vec(
        &json!({"c":[name,component],"i":index,"m":disprove,"e":expected,"s":sha(script.as_bytes()),"w":witness_hash(witness)}),
    )?;
    line.push(b'\n');
    require(
        line.len() <= RECORD_LINE_BUDGET,
        "actual compact record exceeds derived218-byte bound",
    )?;
    out.write_all(&line)?;
    Ok(())
}
#[allow(clippy::too_many_arguments)]
fn reject_both(
    out: &mut RecordSink,
    metrics: &mut Metrics,
    r: &Registry,
    name: &str,
    component: usize,
    ordinal: usize,
    label: &str,
    witness: &[Vec<u8>],
) -> Result<usize> {
    for disprove in [false, true] {
        record(
            out,
            metrics,
            name,
            component,
            json!(label),
            disprove,
            &r.script(ordinal, disprove)?,
            witness,
            false,
        )?;
    }
    Ok(2)
}
fn layout(spec: &GraphSpec, ordinal: usize) -> Result<String> {
    let leaf = spec.leaves.get(ordinal).ok_or("layout ordinal")?;
    let mut unique = Vec::new();
    let mut aliases = Vec::new();
    for word in &leaf.wires {
        let index = if let Some(index) = unique.iter().position(|old| old == word) {
            index
        } else {
            unique.push(*word);
            unique.len() - 1
        };
        aliases.push(index);
    }
    let bounds: Vec<_> = unique.iter().map(|word| spec.words[*word].bound).collect();
    Ok(serde_json::to_string(&(
        leaf.body_sha256.clone(),
        bounds,
        aliases,
    ))?)
}
/// First ordinal of every authenticated layout among `ordinals`.
fn representatives(spec: &GraphSpec, ordinals: &[usize]) -> Result<Vec<usize>> {
    let mut shapes = BTreeMap::new();
    for ordinal in ordinals {
        shapes.entry(layout(spec, *ordinal)?).or_insert(*ordinal);
    }
    let mut result: Vec<_> = shapes.into_values().collect();
    result.sort_unstable();
    Ok(result)
}
fn preflight(cases: &[transport::Case]) -> Result<()> {
    require(cases.len() <= 16, "unchanged 16-component source policy")?;
    for case in cases {
        case.spec.identity()?;
        require(
            case.spec.leaves.len() <= 1 << 19,
            "unchanged future depth19 structural cap",
        )?;
        let all: Vec<usize> = (0..case.spec.leaves.len()).collect();
        require(
            representatives(&case.spec, &all)?.len() <= GUARD_CAP,
            "closed per-component guard layout budget",
        )?;
        for leaf in &case.spec.leaves {
            let count = leaf.wires.iter().collect::<HashSet<_>>().len();
            require(count * 10 <= 1000, "pre-key legacy witness1000 cap")?;
        }
    }
    Ok(())
}

#[derive(Clone, PartialEq, Eq)]
struct Capture {
    global_id: String,
    bound: u32,
    value: u32,
    key: Vec<u8>,
    signature: Vec<u8>,
    packet: Vec<Vec<u8>>,
}
struct OpeningPass {
    occurrences: usize,
    repeats: usize,
    global_words: usize,
    byte_links: usize,
}
fn opening_pass(
    registries: &[Registry],
    material: &keys::Material,
    facts: &source::SourceFacts,
) -> Result<OpeningPass> {
    let mut cache = HashMap::<usize, Capture>::new();
    let mut positions = HashMap::<(usize, usize, usize), usize>::new();
    let (mut occurrences, mut repeats) = (0usize, 0usize);
    for (component, r) in registries.iter().enumerate() {
        for ordinal in 0..r.spec().leaves.len() {
            let witness = r.witness(ordinal, &material.signatures[component])?;
            let slots = r.unique_slots(ordinal)?;
            require(
                witness.len() == slots.len() * 10,
                "actual legacy unique-word witness layout",
            )?;
            for (slot, word) in slots.iter().copied().enumerate() {
                let global = material.global_indices[component][word];
                let key: &[[u8; 20]] = material.keys[component][word].as_ref();
                let expected: Vec<Vec<u8>> = material.signatures[component][word]
                    .iter()
                    .map(|cell| cell.to_vec())
                    .collect();
                let packet = witness[10 * slot..10 * (slot + 1)].to_vec();
                require(
                    packet == expected,
                    "actual compact opening differs from once-signed material",
                )?;
                let capture = Capture {
                    global_id: facts.components[component].global_ids[word].clone(),
                    bound: r.spec().words[word].bound,
                    value: material.values[component][word],
                    key: key.iter().flatten().copied().collect(),
                    signature: material.signatures[component][word]
                        .iter()
                        .flatten()
                        .copied()
                        .collect(),
                    packet,
                };
                if let Some(old) = cache.get(&global) {
                    require(
                        *old == capture,
                        "actual global key/value/bound/signature/opening conflict",
                    )?;
                    repeats += 1;
                } else {
                    cache.insert(global, capture);
                }
                require(
                    positions
                        .insert((component, ordinal, word), global)
                        .is_none(),
                    "duplicate per-leaf unique opening coordinate",
                )?;
                occurrences += 1;
            }
        }
    }
    let mut seen = HashSet::new();
    for link in &facts.byte_links {
        let a = *positions
            .get(&(0, link.source_ordinal, link.source_word))
            .ok_or("tape opening not captured")?;
        let b = *positions
            .get(&(link.target_component, link.target_ordinal, link.target_word))
            .ok_or("decoder opening not captured")?;
        let target = registries[link.target_component]
            .spec()
            .leaves
            .get(link.target_ordinal)
            .ok_or("decoder link leaf")?;
        require(
            a == b
                && target.wires.get(link.target_occurrence) == Some(&link.target_word)
                && cache.get(&a).is_some_and(|capture| {
                    capture.global_id == link.global_id && capture.bound == 256
                })
                && seen.insert((link.target_component, link.target_word)),
            "physical tape/decoder BYTE opening link/duplicate",
        )?;
    }
    require(
        cache.len() == facts.global_words
            && occurrences == facts.opening_occurrences
            && positions.len() == occurrences
            && seen.len() == facts.byte_links.len(),
        "complete actual opening and source-link census",
    )?;
    Ok(OpeningPass {
        occurrences,
        repeats,
        global_words: cache.len(),
        byte_links: seen.len(),
    })
}
#[allow(clippy::too_many_arguments)]
fn guards(
    out: &mut RecordSink,
    metrics: &mut Metrics,
    r: &Registry,
    material: &keys::Material,
    name: &str,
    component: usize,
    ordinals: &[usize],
) -> Result<usize> {
    let mut calls = 0usize;
    for (number, &ordinal) in ordinals.iter().enumerate() {
        let original = r.witness(ordinal, &material.signatures[component])?;
        let slots = r.unique_slots(ordinal)?;
        require(
            !original.is_empty() && original.iter().all(|cell| cell.len() == 20),
            "actual compact witness hash dimensions",
        )?;
        let mut variants = vec![Vec::new(), original[..original.len() - 1].to_vec()];
        let mut prepend = vec![vec![]];
        prepend.extend(original.clone());
        variants.push(prepend);
        let mut append = original.clone();
        append.push(vec![]);
        variants.push(append);
        let mut first = original.clone();
        first[0][0] ^= 1;
        variants.push(first);
        let mut last = original.clone();
        let end = last.len() - 1;
        last[end][0] ^= 1;
        variants.push(last);
        let mut cross = original.clone();
        if slots.len() >= 2 {
            cross[..10].clone_from_slice(&original[10..20]);
            cross[10..20].clone_from_slice(&original[..10]);
        } else {
            let word = slots[0];
            let foreign = (0..r.spec().words.len())
                .find(|index| {
                    *index != word && r.spec().words[*index].bound == r.spec().words[word].bound
                })
                .ok_or("actual distinct same-bound foreign key")?;
            require(
                material.keys[component][foreign] != material.keys[component][word],
                "genuine different-key substitution",
            )?;
            let packet: Vec<Vec<u8>> = material.signatures[component][foreign]
                .iter()
                .map(|cell| cell.to_vec())
                .collect();
            cross[..10].clone_from_slice(&packet);
        }
        variants.push(cross);
        for (variant, bad) in variants.iter().enumerate() {
            calls += reject_both(
                out,
                metrics,
                r,
                name,
                component,
                ordinal,
                &format!("g/{number}/{variant}"),
                bad,
            )?;
        }
    }
    require(calls == 14 * ordinals.len(), "frozen standard guard census")?;
    Ok(calls)
}
fn native_negatives(
    r: &Registry,
    keys: &[bitvm2_nova_script_oracle::wots::PublicKey],
    signatures: &[bitvm2_nova_script_oracle::registry::Signature],
) -> Result<usize> {
    let spec_id = r.spec().identity()?;
    let registry_id = r.identity();
    let mut wrong = spec_id;
    wrong[0] ^= 1;
    require(
        Registry::new(r.spec().clone(), keys.to_vec(), wrong, registry_id).is_err(),
        "wrong source pin admitted",
    )?;
    wrong = registry_id;
    wrong[0] ^= 1;
    require(
        Registry::new(r.spec().clone(), keys.to_vec(), spec_id, wrong).is_err(),
        "wrong registry pin admitted",
    )?;
    let mut changed = keys.to_vec();
    changed.swap(0, 1);
    require(
        Registry::new(r.spec().clone(), changed, spec_id, registry_id).is_err(),
        "swapped keys admitted",
    )?;
    let mut changed = keys.to_vec();
    changed[1] = changed[0].clone();
    require(
        Registry::new(r.spec().clone(), changed, spec_id, registry_id).is_err(),
        "duplicate keys admitted",
    )?;
    require(
        Registry::new(
            r.spec().clone(),
            keys[..keys.len() - 1].to_vec(),
            spec_id,
            registry_id,
        )
        .is_err(),
        "missing key admitted",
    )?;
    require(
        r.script(r.spec().leaves.len(), false).is_err(),
        "correctness ordinal overflow admitted",
    )?;
    require(
        r.script(r.spec().leaves.len(), true).is_err(),
        "disproof ordinal overflow admitted",
    )?;
    require(
        r.witness(0, &signatures[..signatures.len() - 1]).is_err(),
        "missing signatures admitted",
    )?;
    let mut extra = signatures.to_vec();
    extra.push(signatures[0].clone());
    require(r.witness(0, &extra).is_err(), "surplus signatures admitted")?;
    Ok(9)
}
#[allow(clippy::too_many_arguments)]
fn component_run(
    out: &mut RecordSink,
    global: &mut Metrics,
    normal_global: &mut Metrics,
    r: &Registry,
    material: &keys::Material,
    group: &transport::Group,
    component: usize,
    facts: &source::ComponentFacts,
) -> Result<(Value, usize)> {
    let d = &group.components[component];
    let full = d.execution_mode == "all";
    let mut local = Metrics::default();
    let mut stream = sha256::Hash::engine();
    let (mut bytes, mut largest, mut aborts, mut disproofs) = (0usize, 0usize, 0usize, 0usize);
    let mut kinds: BTreeMap<String, [usize; 3]> = BTreeMap::new();
    let mut leaf_bytes = HashMap::new();
    for &ordinal in &facts.selected_ordinals {
        let witness = r.witness(ordinal, &material.signatures[component])?;
        let correct = r.script(ordinal, false)?;
        let disproof = r.script(ordinal, true)?;
        require(
            correct.len().checked_add(1) == Some(disproof.len()),
            "actual C/D byte-length relation",
        )?;
        let unique = r.unique_slots(ordinal)?.len();
        require(
            witness.len() == 10 * unique
                && witness.iter().map(Vec::len).sum::<usize>() == 200 * unique,
            "legacy compact packet depth and payload",
        )?;
        let truth = facts.truth[ordinal];
        aborts += usize::from(truth.is_none());
        disproofs += usize::from(truth == Some(false));
        record(
            out,
            &mut local,
            &group.name,
            component,
            json!(ordinal),
            false,
            &correct,
            &witness,
            truth == Some(true),
        )?;
        record(
            out,
            &mut local,
            &group.name,
            component,
            json!(ordinal),
            true,
            &disproof,
            &witness,
            truth == Some(false),
        )?;
        bytes = bytes
            .checked_add(disproof.len())
            .ok_or("compiled stream overflow")?;
        require(
            bytes <= COMPONENT_SCRIPT_CAP,
            "unchanged compiled component256MiB cap",
        )?;
        largest = largest.max(disproof.len());
        framed(&mut stream, disproof.as_bytes());
        let row = kinds
            .entry(r.spec().leaves[ordinal].kind.clone())
            .or_insert([0; 3]);
        row[0] += 1;
        row[1] += disproof.len();
        row[2] = row[2].max(disproof.len());
        leaf_bytes.insert(ordinal, disproof.len());
    }
    require(
        local.vectors == 2 * facts.selected_ordinals.len()
            && local.expected_rejections == facts.selected_ordinals.len() + aborts,
        "selected ordinary/abort execution census",
    )?;
    let normal_metrics = serde_json::to_value(&local)?;
    fold(normal_global, &local);
    let guard_ordinals = if full {
        representatives(r.spec(), &facts.selected_ordinals)?
    } else {
        let mut chosen = representatives(r.spec(), &facts.selected_ordinals)?;
        chosen.extend(&facts.false_ordinals);
        chosen.sort_unstable();
        chosen.dedup();
        chosen
    };
    require(
        guard_ordinals.len() <= GUARD_CAP,
        "closed guard ordinal budget",
    )?;
    let guard_calls = guards(
        out,
        &mut local,
        r,
        material,
        &group.name,
        component,
        &guard_ordinals,
    )?;
    let native_rejections = native_negatives(
        r,
        &material.keys[component],
        &material.signatures[component],
    )?;
    require(
        local.vectors == 2 * facts.selected_ordinals.len() + guard_calls
            && local.expected_rejections == facts.selected_ordinals.len() + aborts + guard_calls,
        "complete normal/guard vector census",
    )?;
    fold(global, &local);
    let guard_layouts = guard_ordinals
        .iter()
        .map(|ordinal| layout(r.spec(), *ordinal))
        .collect::<Result<HashSet<_>>>()?
        .len();
    let mut decoder_costs = Vec::new();
    for (decoder, leaves) in &facts.decoders {
        if leaves.iter().all(|i| leaf_bytes.contains_key(i)) {
            decoder_costs.push(json!([
                decoder,
                leaves.iter().map(|i| leaf_bytes[i]).sum::<usize>()
            ]));
        }
    }
    let kind_costs: serde_json::Map<String, Value> = kinds
        .into_iter()
        .map(|(kind, row)| (kind, json!(row)))
        .collect();
    Ok((
        json!({"index":d.index,"name":d.name,"field_role":d.field_role,"operation_id":d.operation_id,
        "program_identity_kind":d.program_identity_kind,"words":d.words,"arithmetic_constraints":d.arithmetic_constraints,
        "canonical_fields":d.canonical_fields,"leaves":d.leaves,"program_sha256":facts.program_sha256,
        "catalogue_id":facts.catalogue_id,"global_ids_sha256":d.global_ids_sha256,"decoders":d.decoders,
        "false_predicates":facts.false_ordinals,"abort_predicates":facts.abort_ordinals,
        "measured_ordinals":if full{None}else{Some(facts.selected_ordinals.clone())},
        "measured_leaves":facts.selected_ordinals.len(),"compiled_script_bytes":bytes,
        "largest_disproof_leaf_bytes":largest,"compiled_stream_sha256":sha256::Hash::from_engine(stream).to_string(),
        "registry_id":hex::encode(r.identity()),"normal_vectors":2*facts.selected_ordinals.len(),
        "normal_metrics":normal_metrics,"metrics":local,"guard_layouts":guard_layouts,
        "guarded_leaves":guard_ordinals.len(),"standard_guard_vectors":guard_calls,
        "proper_disproof_vectors":disproofs,"abort_leaf_checks":aborts,"native_rejections":native_rejections,
        "kind_costs":kind_costs,"decoder_costs":decoder_costs}),
        bytes,
    ))
}
fn case_run(
    run: &transport::Run,
    d: &transport::ProfileDescriptor,
    reference: &source::Reference,
    dir: &Path,
    out: &mut RecordSink,
    metrics: &mut Metrics,
    normal_metrics: &mut Metrics,
) -> Result<Value> {
    let group = run.load_group(d, dir)?;
    let cases = run.load_cases(&group, dir)?;
    let facts = source::admit(
        &cases,
        &group,
        reference,
        &run.context,
        &run.operation_id,
        &run.engine,
    )?;
    preflight(&cases)?;
    let inputs: Vec<keys::Input<'_>> = cases
        .iter()
        .zip(&facts.components)
        .map(|(case, fact)| keys::Input {
            spec: &case.spec,
            values: &fact.values,
            global_ids: &fact.global_ids,
        })
        .collect();
    let material = keys::generate(
        &inputs,
        &facts.source_sha256,
        &group.name,
        facts.byte_links.len(),
    )?;
    drop(inputs);
    let mut registries = Vec::new();
    for (component, case) in cases.iter().enumerate() {
        let spec = case.spec.clone();
        let spec_id = spec.identity()?;
        let registry_id = spec.key_identity(&material.keys[component])?;
        registries.push(Registry::new(
            spec,
            material.keys[component].clone(),
            spec_id,
            registry_id,
        )?);
    }
    drop(cases);
    let openings = opening_pass(&registries, &material, &facts)?;
    let mut components = Vec::new();
    let mut compiled = 0usize;
    for (component, registry) in registries.iter().enumerate() {
        let (row, bytes) = component_run(
            out,
            metrics,
            normal_metrics,
            registry,
            &material,
            &group,
            component,
            &facts.components[component],
        )?;
        compiled += bytes;
        components.push(row);
    }
    require(
        compiled <= AGGREGATE_SCRIPT_CAP,
        "unchanged aggregate1.25GiB Script cap",
    )?;
    Ok(
        json!({"name":group.name,"profile":group.profile,"source_sha256":facts.source_sha256,
        "local_words":material.local_words,"global_words":material.global_words,"source_reuses":material.source_reuses,
        "signature_entries_created":material.global_words,"full_signature_signing_calls":material.global_words,
        "byte_opening_links":openings.byte_links,"actual_opening_occurrences":openings.occurrences,
        "actual_opening_repeats":openings.repeats,"actual_opened_global_words":openings.global_words,
        "opening_pass_all_leaves":true,"native_accepted_decoders":facts.native_accepted_decoders,
        "native_rejected_decoders":facts.native_rejected_decoders,"measured_disproof_script_bytes":compiled,
        "components":components}),
    )
}
fn run(manifest: &Path, dir: &Path, output: &Path, expected: &str) -> Result<()> {
    let started = Instant::now();
    let run = transport::Run::load(manifest, dir, expected)?;
    let budget = call_budget(&run.engine)?;
    let record_cap = budget * RECORD_LINE_BUDGET;
    require(
        record_cap <= RECORD_CAP,
        "closed call budget exceeds unchanged128MiB record cap",
    )?;
    let reference = source::reference(
        &dir.join(&run.references[0].filename),
        &dir.join(&run.references[1].filename),
        &dir.join(&run.references[2].filename),
    )?;
    // ALL source groups, every typed case and every packet precede ANY key.
    for d in &run.cases {
        let group = run.load_group(d, dir)?;
        let cases = run.load_cases(&group, dir)?;
        source::admit(
            &cases,
            &group,
            &reference,
            &run.context,
            &run.operation_id,
            &run.engine,
        )?;
        preflight(&cases)?;
    }
    let mut out = RecordSink::new(record_cap);
    let mut metrics = Metrics::default();
    let mut normal = Metrics::default();
    let mut cases = Vec::new();
    for d in &run.cases {
        cases.push(
            case_run(
                &run,
                d,
                &reference,
                dir,
                &mut out,
                &mut metrics,
                &mut normal,
            )
            .map_err(|error| format!("case {}: {error}", d.name))?,
        );
    }
    let final_run = transport::Run::load(manifest, dir, expected)?;
    for d in &final_run.cases {
        let group = final_run.load_group(d, dir)?;
        final_run.load_cases(&group, dir)?;
    }
    final_run.verify_references(dir)?;
    require(
        metrics.vectors <= budget && out.bytes <= record_cap,
        "closed call/record budget",
    )?;
    let wall = started.elapsed().as_secs_f64();
    require(wall <= WALL_CAP_SECONDS, "native wall cap")?;
    let (mut signatures, mut vectors, mut rejections) = (0usize, 0usize, 0usize);
    for case in &cases {
        signatures += case["signature_entries_created"]
            .as_u64()
            .ok_or("typed signature counter")? as usize;
        for component in case["components"]
            .as_array()
            .ok_or("component report inventory")?
        {
            vectors += component["metrics"]["vectors"]
                .as_u64()
                .ok_or("typed vector counter")? as usize;
            rejections += component["metrics"]["expected_rejections"]
                .as_u64()
                .ok_or("typed rejection counter")? as usize;
        }
    }
    require(
        vectors == metrics.vectors && rejections == metrics.expected_rejections,
        "actual execution aggregate census",
    )?;
    let mut report = json!({"schema":"bitvm2-nova-proof-point-origins-execution/v1","passed":true,
        "engine":run.engine,"input_manifest_sha256":expected,"reference":reference.summary(),"cases":cases,
        "metrics":metrics,"normal_metrics":normal,"compact_execution_records_bytes":out.bytes,
        "compact_execution_records_sha256":sha256::Hash::from_engine(out.hash).to_string(),
        "closed_call_budget":budget,"record_byte_budget":record_cap,"wall_seconds":wall,
        "full_statement_cases":1,"targeted_statement_cases":source::PROFILES.len()-1,
        "signature_entries_created":signatures,"full_signature_signing_calls":signatures});
    let object = report.as_object_mut().ok_or("report object")?;
    for flag in [
        "test_keys_only",
        "legacy_registry_and_engine_used",
        "source_preflight_before_keys",
        "global_key_preflight_before_signatures",
        "physical_byte_opening_links_checked",
        "strict_halo2_decoding_matches_leaf_relation",
        "canonical_coordinate_guards_preserved",
        "raw_u32_diagnostics_preserved",
        "exact_witness_length_guards_checked",
        "stack_limit_enabled",
        "correctness_bytes_equal_disproof_minus_one_checked",
    ] {
        require(
            object.insert(flag.into(), json!(true)).is_none(),
            "duplicate true report flag",
        )?;
    }
    for flag in source::FALSE_FLAGS.iter().copied().chain([
        "panic_is_rejection",
        "op_cat_enabled",
        "all_cases_full_statement_executed",
        "raw_vector_file_written",
        "reference_hash_authenticates_claimed_payload",
    ]) {
        require(
            object.insert(flag.into(), json!(false)).is_none(),
            "duplicate false report flag",
        )?;
    }
    for key in [
        "setup_calls",
        "proving_jobs",
        "native_proofs_verified",
        "gpu_jobs",
        "transactions_broadcast",
        "tree_calls",
    ] {
        require(
            object.insert(key.into(), json!(0)).is_none(),
            "duplicate zero report counter",
        )?;
    }
    let raw = serde_json::to_vec(&report)?;
    require(raw.len() <= SUMMARY_CAP, "unchanged 1MiB summary cap")?;
    fs::write(output, raw)?;
    Ok(())
}
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().collect();
    require(
        args.len() == 5,
        "usage: proof_point_origins MANIFEST CASE_DIR OUTPUT EXPECTED_SHA256",
    )?;
    let expected = args[4].to_str().ok_or("ASCII manifest SHA")?;
    require(
        hex::encode(id32(expected)?) == expected,
        "canonical external manifest pin",
    )?;
    run(
        Path::new(&args[1]),
        Path::new(&args[2]),
        Path::new(&args[3]),
        expected,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn guard_identifiers_cannot_expand_json_record_budget() {
        assert!(owned_guard_id("g/511/6"));
        for value in ["x\"", "x\\", "x\n", ""] {
            assert!(!owned_guard_id(value));
        }
        assert!(!owned_guard_id(&"x".repeat(33)));
    }
    #[test]
    fn closed_call_and_record_budgets_fit_unchanged_caps() {
        assert_eq!(call_budget("pallas").unwrap(), 328_670);
        assert_eq!(call_budget("vesta").unwrap(), 291_794);
        for engine in ["pallas", "vesta"] {
            assert!(call_budget(engine).unwrap() * RECORD_LINE_BUDGET <= RECORD_CAP);
        }
        assert_eq!(AGGREGATE_SCRIPT_CAP, 1_342_177_280);
    }
    #[test]
    fn record_sink_rejects_overflow_without_writing() {
        let mut sink = RecordSink::new(10);
        sink.bytes = 10;
        assert!(sink.write(&[0]).is_err());
        assert_eq!(sink.bytes, 10);
    }
}
