//! Standalone retained-payload scalar origins using the frozen legacy adapter.
//! Assertion-local encoding/cost evidence, not proof, tree or production binding.
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
const CALL_BUDGET: usize = 66842;
const RECORD_LINE_BUDGET: usize = 218;
const RECORD_DERIVED_CAP: usize = 14571556;
const SUMMARY_DERIVED_CAP: usize = 703704;
const MAX_MEASURED_ROWS: usize = 19224;
const METADATA_BUDGET: usize = 300000;

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
struct RecordSink {
    bytes: usize,
    hash: sha256::HashEngine,
}
impl RecordSink {
    fn new() -> Self {
        Self {
            bytes: 0,
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
        if total > RECORD_CAP || total > RECORD_DERIVED_CAP {
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
            && component < 3,
        "closed compact record case/component",
    )?;
    match &index {
        Value::String(value) => {
            require(owned_guard_id(value), "owned escapeless guard identifier")?
        }
        Value::Number(n) => require(n.as_u64().is_some_and(|n| n < 12664), "record leaf ordinal")?,
        _ => return Err("record index type".into()),
    };
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
fn reject_both(
    out: &mut RecordSink,
    metrics: &mut Metrics,
    r: &Registry,
    material: &keys::Material,
    name: &str,
    component: usize,
    ordinal: usize,
    label: &str,
    witness: &[Vec<u8>],
) -> Result<usize> {
    let _ = material;
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
fn representatives(spec: &GraphSpec) -> Result<Vec<usize>> {
    let mut shapes = BTreeMap::new();
    for ordinal in 0..spec.leaves.len() {
        shapes.entry(layout(spec, ordinal)?).or_insert(ordinal);
    }
    Ok(shapes.into_values().collect())
}
fn preflight(cases: &[transport::Case; 3]) -> Result<()> {
    let mut shapes = 0usize;
    for (component, case) in cases.iter().enumerate() {
        case.spec.identity()?;
        require(
            case.spec.leaves.len() <= 1 << 19,
            "unchanged future depth19 structural cap",
        )?;
        let reps = representatives(&case.spec)?;
        require(
            reps.len() == [9, 17, 17][component],
            "closed43 authenticated layouts",
        )?;
        shapes += reps.len();
        for leaf in &case.spec.leaves {
            let count = leaf.wires.iter().collect::<HashSet<_>>().len();
            require(count * 10 <= 1000, "pre-key legacy witness1000 cap")?;
        }
    }
    require(
        shapes <= 291 && cases.len() <= 16,
        "unchanged component/source guard budget",
    )?;
    Ok(())
}

#[derive(Clone, PartialEq, Eq)]
struct Capture {
    global: usize,
    global_id: String,
    bound: u32,
    value: u32,
    key: Vec<u8>,
    signature: Vec<u8>,
    packet: Vec<Vec<u8>>,
}
fn same_assertion(a: &Capture, b: &Capture) -> Result<()> {
    require(
        a == b,
        "actual global key/value/bound/signature/opening conflict",
    )
}
struct OpeningPass {
    occurrences: usize,
    repeats: usize,
    global_words: usize,
    byte_links: usize,
    internal_links: usize,
}
fn opening_pass(
    registries: &[Registry; 3],
    material: &keys::Material,
    facts: &source::SourceFacts,
) -> Result<OpeningPass> {
    let mut cache = HashMap::<usize, Capture>::new();
    let mut positions = HashMap::<(usize, usize, usize), usize>::new();
    let (mut occurrences, mut repeats) = (0usize, 0usize);
    for component in 0..3 {
        let r = &registries[component];
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
                    global,
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
                    same_assertion(old, &capture)?;
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
    let coordinate = |component: usize,
                      word: usize,
                      ordinal: usize,
                      occurrence: usize,
                      id: &str|
     -> Result<usize> {
        let r = registries.get(component).ok_or("opening component")?;
        let leaf = r.spec().leaves.get(ordinal).ok_or("opening leaf")?;
        require(
            leaf.wires.get(occurrence) == Some(&word),
            "actual formal opening occurrence mismatch",
        )?;
        let global = *positions
            .get(&(component, ordinal, word))
            .ok_or("actual opening coordinate not captured")?;
        require(
            facts.components[component]
                .global_ids
                .get(word)
                .is_some_and(|actual| actual == id)
                && cache
                    .get(&global)
                    .is_some_and(|capture| capture.global_id == id),
            "actual opening physical global identity",
        )?;
        Ok(global)
    };
    let mut byte_seen = HashSet::new();
    for link in &facts.byte_links {
        let a = coordinate(
            link.source_component,
            link.source_word,
            link.source_ordinal,
            link.source_occurrence,
            &link.global_id,
        )?;
        let b = coordinate(
            link.target_component,
            link.target_word,
            link.target_ordinal,
            link.target_occurrence,
            &link.global_id,
        )?;
        require(
            a == b
                && link.source_component == 0
                && (1..=2).contains(&link.target_component)
                && registries[0].spec().words[link.source_word].bound == 256
                && registries[link.target_component].spec().words[link.target_word].bound == 256
                && byte_seen.insert((link.source_word, link.target_component, link.target_word)),
            "physical scalar BYTE opening link/duplicate",
        )?;
    }
    let mut internal_seen = HashSet::new();
    for link in &facts.internal_links {
        let a = coordinate(
            link.component_index,
            link.word_index,
            link.source_ordinal,
            link.source_occurrence,
            &link.global_id,
        )?;
        let b = coordinate(
            link.component_index,
            link.word_index,
            link.target_ordinal,
            link.target_occurrence,
            &link.global_id,
        )?;
        require(
            a == b
                && (1..=2).contains(&link.component_index)
                && internal_seen.insert((
                    link.component_index,
                    link.word_index,
                    link.source_ordinal,
                    link.source_occurrence,
                    link.target_ordinal,
                    link.target_occurrence,
                )),
            "canonical encoder internal opening link/duplicate",
        )?;
    }
    require(
        cache.len() == 19288
            && occurrences == 35128
            && repeats == 15840
            && positions.len() == occurrences
            && byte_seen.len() == 9216
            && internal_seen.len() == 6624,
        "complete actual opening and source-link census",
    )?;
    Ok(OpeningPass {
        occurrences,
        repeats,
        global_words: cache.len(),
        byte_links: byte_seen.len(),
        internal_links: internal_seen.len(),
    })
}
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
                material,
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
fn component_run(
    out: &mut RecordSink,
    global: &mut Metrics,
    normal_global: &mut Metrics,
    r: &Registry,
    material: &keys::Material,
    group: &transport::Group,
    component: usize,
    facts: &source::ComponentFacts,
) -> Result<Value> {
    let d = &group.components[component];
    let full = d.execution_mode == "all";
    let mut local = Metrics::default();
    let mut stream = sha256::Hash::engine();
    let (mut bytes, mut largest, mut aborts, mut disproofs) = (0usize, 0usize, 0usize, 0usize);
    let mut costs = Vec::new();
    for &ordinal in &facts.selected_ordinals {
        let witness = r.witness(ordinal, &material.signatures[component])?;
        let correct = r.script(ordinal, false)?;
        let disproof = r.script(ordinal, true)?;
        require(
            correct.len().checked_add(1) == Some(disproof.len()),
            "actual C/D byte-length relation",
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
        require(bytes <= 256 << 20, "unchanged compiled component256MiB cap")?;
        largest = largest.max(disproof.len());
        framed(&mut stream, disproof.as_bytes());
        let row = json!([
            disproof.len(),
            witness.len(),
            witness.iter().map(Vec::len).sum::<usize>()
        ]);
        require(
            serde_json::to_vec(&row)?.len() + 1 <= 21,
            "derived compact leaf-cost row bound",
        )?;
        costs.push(row);
    }
    require(
        local.vectors == 2 * facts.selected_ordinals.len()
            && local.expected_rejections == facts.selected_ordinals.len() + aborts,
        "selected ordinary/abort execution census",
    )?;
    let normal_metrics = serde_json::to_value(&local)?;
    fold(normal_global, &local);
    let guard_ordinals = if full {
        representatives(r.spec())?
    } else {
        facts.selected_ordinals.clone()
    };
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
    Ok(
        json!({"index":d.index,"name":d.name,"field_role":d.field_role,"operation_id":d.operation_id,"program_identity_kind":d.program_identity_kind,
        "words":d.words,"arithmetic_constraints":d.arithmetic_constraints,"canonical_fields":d.canonical_fields,"leaves":d.leaves,
        "program_sha256":facts.program_sha256,"catalogue_id":facts.catalogue_id,"source_sha256":facts.source_sha256,"source_maps_sha256":facts.source_maps_sha256,"global_ids_sha256":d.global_ids_sha256,
        "false_predicates":facts.false_ordinals,"abort_predicates":facts.abort_ordinals,"measured_ordinals":if full{None}else{Some(facts.selected_ordinals.clone())},
        "compiled_script_bytes":bytes,"largest_disproof_leaf_bytes":largest,"compiled_stream_sha256":sha256::Hash::from_engine(stream).to_string(),"registry_id":hex::encode(r.identity()),
        "normal_vectors":2*facts.selected_ordinals.len(),"normal_metrics":normal_metrics,"metrics":local,"guard_layouts":guard_layouts,"guarded_leaves":guard_ordinals.len(),"standard_guard_vectors":guard_calls,
        "proper_disproof_vectors":disproofs,"abort_leaf_checks":aborts,"native_rejections":native_rejections,"leaf_costs":costs}),
    )
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
    let facts = source::admit(&cases, &group, reference, &run.context, &run.operation_id)?;
    preflight(&cases)?;
    let inputs = std::array::from_fn(|index| keys::Input {
        spec: &cases[index].spec,
        values: &facts.components[index].values,
        global_ids: &facts.components[index].global_ids,
    });
    let material = keys::generate(&inputs, &facts.source_sha256, &group.name)?;
    let mut constructed = Vec::new();
    for component in 0..3 {
        let spec = cases[component].spec.clone();
        let spec_id = spec.identity()?;
        let registry_id = spec.key_identity(&material.keys[component])?;
        constructed.push(Registry::new(
            spec,
            material.keys[component].clone(),
            spec_id,
            registry_id,
        )?);
    }
    let registries: [Registry; 3] = constructed
        .try_into()
        .map_err(|_| "exact three legacy registries")?;
    let openings = opening_pass(&registries, &material, &facts)?;
    let mut components = Vec::new();
    let mut compiled = 0usize;
    for component in 0..3 {
        let row = component_run(
            out,
            metrics,
            normal_metrics,
            &registries[component],
            &material,
            &group,
            component,
            &facts.components[component],
        )?;
        compiled += row["compiled_script_bytes"]
            .as_u64()
            .ok_or("typed compiled byte counter")? as usize;
        components.push(row);
    }
    require(
        compiled <= 5usize << 28,
        "unchanged aggregate1.25GiB Script cap",
    )?;
    Ok(
        json!({"name":group.name,"profile":group.profile,"source_sha256":facts.source_sha256,"source_maps_sha256":facts.source_maps_sha256,
        "local_words":material.local_words,"global_words":material.global_words,"source_reuses":material.source_reuses,
        "signature_entries_created":material.global_words,"full_signature_signing_calls":material.global_words,
        "scalar_byte_opening_links":openings.byte_links,"encoding_internal_opening_links":openings.internal_links,"actual_opening_occurrences":openings.occurrences,
        "actual_opening_repeats":openings.repeats,"actual_opened_global_words":openings.global_words,"opening_pass_all_leaves":true,"components":components}),
    )
}
fn run(manifest: &Path, dir: &Path, output: &Path, expected: &str) -> Result<()> {
    let started = Instant::now();
    let run = transport::Run::load(manifest, dir, expected)?;
    let reference = source::reference(
        &dir.join(&run.references[0].filename),
        &dir.join(&run.references[1].filename),
        &dir.join(&run.references[2].filename),
    )?;
    // ALL fourteen source groups, every typed map and every packet precede ANY key.
    for d in &run.cases {
        let group = run.load_group(d, dir)?;
        let cases = run.load_cases(&group, dir)?;
        source::admit(&cases, &group, &reference, &run.context, &run.operation_id)?;
        preflight(&cases)?;
    }
    let mut out = RecordSink::new();
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
        metrics.vectors <= CALL_BUDGET && out.bytes <= RECORD_DERIVED_CAP,
        "closed call/record budget",
    )?;
    let wall = started.elapsed().as_secs_f64();
    require(wall <= 1260.0, "native wall1260 cap")?;
    let mut signatures = 0usize;
    let mut signing_calls = 0usize;
    let mut reported_vectors = 0usize;
    let mut reported_rejections = 0usize;
    for case in &cases {
        signatures += case["signature_entries_created"]
            .as_u64()
            .ok_or("typed signature counter")? as usize;
        signing_calls += case["full_signature_signing_calls"]
            .as_u64()
            .ok_or("typed signing counter")? as usize;
        for component in case["components"]
            .as_array()
            .ok_or("component report inventory")?
        {
            reported_vectors += component["metrics"]["vectors"]
                .as_u64()
                .ok_or("typed vector counter")? as usize;
            reported_rejections += component["metrics"]["expected_rejections"]
                .as_u64()
                .ok_or("typed rejection counter")? as usize;
        }
    }
    require(
        signatures == 270032
            && signing_calls == signatures
            && reported_vectors == metrics.vectors
            && reported_rejections == metrics.expected_rejections,
        "actual global material and execution aggregate census",
    )?;
    let mut report = json!({"schema":"bitvm2-nova-proof-payload-origins-execution/v1","passed":true,"input_manifest_sha256":expected,
        "reference":reference.summary(),"cases":cases,"metrics":metrics,"normal_metrics":normal,"leaf_cost_columns":["disproof_script_bytes","witness_items","witness_payload_bytes"],
        "compact_execution_records_bytes":out.bytes,"compact_execution_records_sha256":sha256::Hash::from_engine(out.hash).to_string(),"wall_seconds":wall,
        "full_statement_cases":1,"targeted_statement_cases":13,"signature_entries_created":signatures,"full_signature_signing_calls":signing_calls});
    let object = report.as_object_mut().ok_or("report object")?;
    for flag in [
        "test_keys_only",
        "legacy_registry_and_engine_used",
        "source_preflight_before_keys",
        "global_key_preflight_before_signatures",
        "physical_byte_opening_links_checked",
        "encoding_internal_opening_links_checked",
        "canonical_scalar_guards_preserved",
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
    for flag in [
        "panic_is_rejection",
        "op_cat_enabled",
        "all_cases_full_statement_executed",
        "production_assertion_binding",
        "proof_sha256_script_bound",
        "bundle_sha256_script_bound",
        "proof_eof_script_bound",
        "whole_container_script_bound",
        "public_state_to_zn_script_bound",
        "commitment_decoding_verified",
        "transcript_verified",
        "proof_verified",
        "complete_nova_verifier",
        "complete_bitvm2_verifier",
        "candidate_taproot_tree_verified",
        "candidate_forest_verified",
        "candidate_membership_verified",
        "bitcoin_transaction_graph",
        "raw_vector_file_written",
        "reference_hash_authenticates_claimed_payload",
    ] {
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
    let mut metadata = report.clone();
    let mut measured_rows = 0usize;
    for case in metadata["cases"].as_array_mut().ok_or("report cases")? {
        for component in case["components"]
            .as_array_mut()
            .ok_or("report components")?
        {
            measured_rows += component["leaf_costs"]
                .as_array()
                .ok_or("compact leaf costs")?
                .len();
            component["leaf_costs"] = json!([]);
        }
    }
    require(
        measured_rows <= MAX_MEASURED_ROWS
            && serde_json::to_vec(&metadata)?.len() <= METADATA_BUDGET,
        "derived summary row/metadata budget",
    )?;
    let raw = serde_json::to_vec(&report)?;
    require(
        raw.len() <= SUMMARY_DERIVED_CAP && raw.len() <= SUMMARY_CAP,
        "derived and hard summary byte caps",
    )?;
    fs::write(output, raw)?;
    Ok(())
}
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().collect();
    require(
        args.len() == 5,
        "usage: proof_payload_origins MANIFEST CASE_DIR OUTPUT EXPECTED_SHA256",
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
        assert!(owned_guard_id("g/12663/6"));
        for value in ["x\"", "x\\", "x\n", ""] {
            assert!(!owned_guard_id(value));
        }
        assert!(!owned_guard_id(&"x".repeat(33)));
    }
    #[test]
    fn independent_resource_budgets_are_explicit() {
        assert_eq!(CALL_BUDGET * RECORD_LINE_BUDGET, RECORD_DERIVED_CAP);
        assert!(RECORD_DERIVED_CAP < RECORD_CAP);
        assert_eq!(
            MAX_MEASURED_ROWS * 21 + METADATA_BUDGET,
            SUMMARY_DERIVED_CAP
        );
        assert!(SUMMARY_DERIVED_CAP < SUMMARY_CAP);
    }
    #[test]
    fn record_sink_rejects_overflow_without_writing() {
        let mut sink = RecordSink::new();
        sink.bytes = RECORD_DERIVED_CAP;
        assert!(sink.write(&[0]).is_err());
        assert_eq!(sink.bytes, RECORD_DERIVED_CAP);
    }
}
