//! Thin local-type execution/capture orchestration for the committed algorithms.
use crate::{
    chain, openings,
    registry::{GraphSpec, Registry, Signature},
    source,
    taproot_commitment::TaprootCommitment,
    taproot_forest::TaprootForest,
};
use bitcoin::{
    hashes::{sha256, Hash, HashEngine},
    ScriptBuf,
};
use bitvm2_nova_script_oracle::{
    engine::{execute, Metrics},
    wots::{PublicKey, Result},
};
use chain::permutation::{changed, digest};
use chain::{is_full, COMPONENT_COUNTS, CONNECTION_COUNTS};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, HashSet},
    io::{self, Write},
};
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Check {
    pub ordinal: usize,
    pub expected_correct: Option<bool>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Case {
    pub name: String,
    pub spec: GraphSpec,
    pub expected_spec_id: String,
    pub words: Vec<u32>,
    pub checks: Vec<Check>,
    pub measure_all: bool,
}
pub struct Prepared {
    pub case: Case,
    pub global_ids: Vec<String>,
    pub facts: source::ComponentFacts,
    pub full: Option<chain::permutation::Full>,
    pub tail: Option<crate::rho_tail::CheckedTail>,
    pub frame: Option<chain::frame::CheckedFrame>,
    pub absorb: Option<chain::absorb::CheckedAbsorb>,
    pub truth: Vec<Option<bool>>,
}
pub fn into_local(old: bitvm2_nova_script_oracle::registry::GraphSpec) -> Result<GraphSpec> {
    let expected = old.identity()?;
    let encoded = serde_json::to_vec(&old)?;
    let new = GraphSpec {
        program_sha256: old.program_sha256,
        context: old.context,
        field_role: old.field_role,
        operation_id: old.operation_id,
        words: old
            .words
            .into_iter()
            .map(|w| crate::registry::Word {
                name: w.name,
                bound: w.bound,
            })
            .collect(),
        leaves: old
            .leaves
            .into_iter()
            .map(|l| crate::registry::Leaf {
                kind: l.kind,
                argument: l.argument,
                wires: l.wires,
                body_sha256: l.body_sha256,
            })
            .collect(),
        bodies: old.bodies,
    };
    if new.identity()? != expected || serde_json::to_vec(&new)? != encoded {
        return Err("nominal old/local type bridge changed typed data or catalogue".into());
    }
    Ok(new)
}
pub fn old_view(spec: &GraphSpec) -> Result<bitvm2_nova_script_oracle::registry::GraphSpec> {
    if spec.leaves.iter().any(|l| l.kind == "conv_ab_all") {
        return Err("grouped kind cannot enter a legacy view".into());
    }
    let encoded = serde_json::to_vec(spec)?;
    let old: bitvm2_nova_script_oracle::registry::GraphSpec = serde_json::from_slice(&encoded)?;
    if old.identity()? != spec.identity()? || serde_json::to_vec(&old)? != encoded {
        return Err("old-kind view changed typed data or catalogue".into());
    }
    Ok(old)
}
pub fn from_legacy(p: chain::Prepared) -> Result<Prepared> {
    let index = p.facts.index;
    let truth = (0..p.case.spec.leaves.len())
        .map(|i| {
            if is_full(index) || index == 5 {
                chain::permutation::truth(&p.case.spec, &p.case.words, i).map(Some)
            } else {
                crate::rho_tail::truth(&p.case.spec, &p.case.words, i).map(Some)
            }
        })
        .collect::<Result<Vec<_>>>()?;
    let c = p.case;
    Ok(Prepared {
        case: Case {
            name: c.name,
            spec: into_local(c.spec)?,
            expected_spec_id: c.expected_spec_id,
            words: c.words,
            checks: c
                .checks
                .into_iter()
                .map(|c| Check {
                    ordinal: c.ordinal,
                    expected_correct: Some(c.expected_correct),
                })
                .collect(),
            measure_all: c.measure_all,
        },
        global_ids: p.global_ids,
        facts: p.facts,
        full: p.full,
        tail: p.tail,
        frame: p.frame,
        absorb: p.absorb,
        truth,
    })
}
pub struct RecordSink {
    pub bytes: u64,
    pub hash: sha256::HashEngine,
}
impl RecordSink {
    pub fn new() -> Self {
        Self {
            bytes: 0,
            hash: sha256::Hash::engine(),
        }
    }
}
impl Write for RecordSink {
    fn write(&mut self, raw: &[u8]) -> io::Result<usize> {
        let n = self
            .bytes
            .checked_add(raw.len() as u64)
            .ok_or_else(|| io::Error::other("record overflow"))?;
        if n > 65235280 || n > 128 << 20 {
            return Err(io::Error::other("role record cap"));
        }
        self.bytes = n;
        self.hash.input(raw);
        Ok(raw.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
pub fn fold(a: &mut Metrics, b: &Metrics) {
    a.vectors += b.vectors;
    a.expected_rejections += b.expected_rejections;
    a.max_script_bytes = a.max_script_bytes.max(b.max_script_bytes);
    a.max_stack_items = a.max_stack_items.max(b.max_stack_items);
    a.max_witness_items = a.max_witness_items.max(b.max_witness_items);
    a.max_witness_payload_bytes = a.max_witness_payload_bytes.max(b.max_witness_payload_bytes);
}
pub fn outcomes(truth: Option<bool>) -> [bool; 2] {
    [truth == Some(true), truth == Some(false)]
}
pub fn material_hash(
    registry: &Registry,
    public: &[PublicKey],
    sigs: &[Signature],
    values: &[u32],
    ids: &[String],
) -> Result<String> {
    openings::validate_material(registry, public, sigs, values, ids)?;
    let mut h = sha256::Hash::engine();
    h.input(b"BITVM2-NOVA/GROUPED-POINT-MATERIAL/v1\0");
    h.input(&registry.identity());
    h.input(&(values.len() as u32).to_le_bytes());
    for (((id, w), v), (key, sig)) in ids
        .iter()
        .zip(&registry.spec().words)
        .zip(values)
        .zip(public.iter().zip(sigs))
    {
        h.input(&(id.len() as u16).to_le_bytes());
        h.input(id.as_bytes());
        h.input(&w.bound.to_le_bytes());
        h.input(&v.to_le_bytes());
        for x in key {
            h.input(x);
        }
        for x in sig {
            h.input(x);
        }
    }
    Ok(sha256::Hash::from_engine(h).to_string())
}
pub fn witness_hash(w: &[Vec<u8>]) -> String {
    let mut h = sha256::Hash::engine();
    h.input(&(w.len() as u32).to_le_bytes());
    for x in w {
        h.input(&(x.len() as u32).to_le_bytes());
        h.input(x);
    }
    sha256::Hash::from_engine(h).to_string()
}
pub struct StoredOpening {
    pub word: usize,
    pub assertion: openings::Capture,
}
pub type OpeningStore = BTreeMap<(usize, usize, usize), StoredOpening>;
type Connection = chain::Connection;
fn reject<T>(
    r: Result<T>,
    name: &'static str,
    counts: &mut BTreeMap<&'static str, usize>,
) -> Result<()> {
    if r.is_ok() {
        return Err(format!("membership negative accepted: {name}").into());
    }
    *counts.entry(name).or_default() += 1;
    Ok(())
}

pub(crate) fn record(
    sink: &mut RecordSink,
    metrics: &mut Metrics,
    code: &ScriptBuf,
    witness: &[Vec<u8>],
    expected: bool,
    group: &str,
    id: Value,
    disprove: bool,
) -> Result<()> {
    if let Some(id) = id.as_str() {
        let component = id.split('/').next().and_then(|s| s.parse::<usize>().ok());
        let private = group.split('/').nth(1).unwrap_or("");
        let new_identifier = component.is_some_and(|i| i >= 9)
            || private.starts_with('e')
            || private.starts_with('n')
            || private == "s"
            || (id.contains("/tree/") && !private.starts_with('q'));
        let maximum = if new_identifier { 32 } else { 64 };
        if id.len() > maximum {
            return Err("compact identifier exceeds its closed old64/new32 policy".into());
        }
    }
    let (success, stack) = execute(code, witness.to_vec())?;
    if success != expected {
        return Err(format!("{group}/{id}/{disprove}: expected{expected}, got{success}").into());
    }
    metrics.vectors += 1;
    metrics.expected_rejections += usize::from(!expected);
    metrics.max_script_bytes = metrics.max_script_bytes.max(code.len());
    metrics.max_stack_items = metrics.max_stack_items.max(stack);
    metrics.max_witness_items = metrics.max_witness_items.max(witness.len());
    metrics.max_witness_payload_bytes = metrics
        .max_witness_payload_bytes
        .max(witness.iter().map(Vec::len).sum::<usize>());
    let mut hash = sha256::Hash::engine();
    hash.input(&(witness.len() as u32).to_le_bytes());
    for item in witness {
        hash.input(&(item.len() as u32).to_le_bytes());
        hash.input(item);
    }
    serde_json::to_writer(
        &mut *sink,
        &json!({"c":group,"i":id,"m":disprove,"e":expected,"s":sha256::Hash::hash(code.as_bytes()).to_string(),"w":sha256::Hash::from_engine(hash).to_string()}),
    )?;
    sink.write_all(b"\n")?;
    Ok(())
}

pub(crate) fn auth_shape(spec: &GraphSpec, ordinal: usize) -> (String, Vec<u32>, Vec<usize>) {
    let leaf = &spec.leaves[ordinal];
    let mut unique = Vec::new();
    let mut aliases = Vec::new();
    for wire in &leaf.wires {
        let position = if let Some(i) = unique.iter().position(|i| i == wire) {
            i
        } else {
            unique.push(*wire);
            unique.len() - 1
        };
        aliases.push(position);
    }
    (
        leaf.body_sha256.clone(),
        unique.iter().map(|i| spec.words[*i].bound).collect(),
        aliases,
    )
}

pub(crate) fn guards(
    registry: &Registry,
    signatures: &[Signature],
    sink: &mut RecordSink,
    metrics: &mut Metrics,
    group: &str,
    component: usize,
) -> Result<usize> {
    let maximum = if is_full(component) {
        23
    } else if [2, 8].contains(&component) {
        61
    } else if component == 9 {
        2
    } else if component == 10 {
        107
    } else {
        COMPONENT_COUNTS
            .get(component)
            .ok_or("guard component bound")?
            .1
    };
    let count = guard_subset(
        registry, signatures, sink, metrics, group, component, None, maximum,
    )?;
    if is_full(component) && count != 23 {
        return Err("all23 permutation authenticated layouts required".into());
    }
    Ok(count)
}

pub(crate) fn guard_subset(
    registry: &Registry,
    signatures: &[Signature],
    sink: &mut RecordSink,
    metrics: &mut Metrics,
    group: &str,
    component: usize,
    selected: Option<&[usize]>,
    maximum: usize,
) -> Result<usize> {
    let mut shapes = HashSet::new();
    for ordinal in 0..registry.spec().leaves.len() {
        if selected.is_some_and(|list| !list.contains(&ordinal)) {
            continue;
        }
        if !shapes.insert(auth_shape(registry.spec(), ordinal)) {
            continue;
        }
        let witness = registry.witness(ordinal, signatures)?;
        if witness.is_empty() {
            return Err("guard requires a real authenticated opening".into());
        }
        for disprove in [false, true] {
            let code = registry.script(ordinal, disprove)?;
            for (i, bad) in [
                vec![],
                witness[..witness.len() - 1].to_vec(),
                [vec![vec![]], witness.clone()].concat(),
                [witness.clone(), vec![vec![]]].concat(),
            ]
            .iter()
            .enumerate()
            {
                record(
                    sink,
                    metrics,
                    &code,
                    bad,
                    false,
                    group,
                    json!(format!("{component}/l/{ordinal}/{i}")),
                    disprove,
                )?;
            }
            for position in [0, witness.len() - 1] {
                let mut bad = witness.clone();
                *bad[position].first_mut().ok_or("empty signature digit")? ^= 1;
                record(
                    sink,
                    metrics,
                    &code,
                    &bad,
                    false,
                    group,
                    json!(format!("{component}/f/{ordinal}/{position}")),
                    disprove,
                )?;
            }
            let slot = registry.unique_slots(ordinal)?[0];
            let mut bad = signatures.to_vec();
            bad[slot] = signatures[(slot + 1) % signatures.len()];
            record(
                sink,
                metrics,
                &code,
                &registry.witness(ordinal, &bad)?,
                false,
                group,
                json!(format!("{component}/x/{ordinal}")),
                disprove,
            )?;
        }
    }
    if shapes.len() > maximum {
        return Err(
            "authenticated-layout census exceeds independently closed record budget".into(),
        );
    }
    Ok(shapes.len())
}

pub(crate) fn native_negatives(
    case: &Case,
    keys: &[PublicKey],
    signatures: &[Signature],
    foreign: PublicKey,
    registry: &Registry,
) -> Result<usize> {
    let spec = &case.spec;
    let expected = digest(&case.expected_spec_id)?;
    let id = registry.identity();
    let mut variants = Vec::new();
    let mut x = spec.clone();
    x.context = changed(&x.context)?;
    variants.push(x);
    let mut x = spec.clone();
    x.program_sha256 = changed(&x.program_sha256)?;
    variants.push(x);
    let mut x = spec.clone();
    x.field_role = if x.field_role == "pallas_scalar" {
        "vesta_scalar"
    } else {
        "pallas_scalar"
    }
    .into();
    variants.push(x);
    let mut x = spec.clone();
    x.operation_id.push_str("/different");
    variants.push(x);
    let mut x = spec.clone();
    x.words[0].name.push_str("/different");
    variants.push(x);
    let mut x = spec.clone();
    x.words[0].bound = if x.words[0].bound == 256 { 255 } else { 256 };
    variants.push(x);
    let mut x = spec.clone();
    x.leaves[0].wires[0] = x.words.len();
    variants.push(x);
    let mut x = spec.clone();
    x.leaves[0].kind = "unknown".into();
    variants.push(x);
    let mut x = spec.clone();
    x.bodies
        .insert(x.leaves[0].body_sha256.clone(), "51".into());
    variants.push(x);
    let mut x = spec.clone();
    x.leaves[0].body_sha256 = changed(&x.leaves[0].body_sha256)?;
    variants.push(x);
    let mut x = spec.clone();
    x.leaves[0].argument.push(i64::MAX);
    variants.push(x);
    let mut x = spec.clone();
    x.leaves.push(x.leaves[0].clone());
    variants.push(x);
    let mut x = spec.clone();
    x.leaves[0].kind = "field_valid".into();
    x.leaves[0].argument.clear();
    x.leaves[0].wires = vec![0; 9];
    variants.push(x);
    let mut count = 0;
    for other in variants {
        if Registry::new(other, keys.to_vec(), expected, id).is_ok() {
            return Err("byte catalogue substitution accepted".into());
        }
        count += 1;
    }
    for other_keys in [keys[..keys.len() - 1].to_vec(), [keys, &keys[..1]].concat()] {
        if Registry::new(spec.clone(), other_keys, expected, id).is_ok() {
            return Err("byte key count substitution accepted".into());
        }
        count += 1;
    }
    let mut wrong = id;
    wrong[0] ^= 1;
    if Registry::new(spec.clone(), keys.to_vec(), expected, wrong).is_ok() {
        return Err("wrong byte registry accepted".into());
    }
    count += 1;
    let mut wrong = expected;
    wrong[0] ^= 1;
    if Registry::new(spec.clone(), keys.to_vec(), wrong, id).is_ok() {
        return Err("wrong byte catalogue accepted".into());
    }
    count += 1;
    let mut foreign_keys = keys.to_vec();
    foreign_keys[0] = foreign;
    if Registry::new(spec.clone(), foreign_keys, expected, id).is_ok() {
        return Err("foreign byte key accepted".into());
    }
    count += 1;
    if keys.len() > 1 {
        let mut swapped = keys.to_vec();
        swapped.swap(0, 1);
        if Registry::new(spec.clone(), swapped, expected, id).is_ok() {
            return Err("byte key permutation accepted".into());
        }
        count += 1;
        let mut duplicate = keys.to_vec();
        duplicate[1] = duplicate[0];
        if Registry::new(spec.clone(), duplicate, expected, id).is_ok() {
            return Err("duplicate byte key accepted".into());
        }
        count += 1;
    }
    let mut surplus = signatures.to_vec();
    surplus.push(signatures[0]);
    if registry
        .witness(0, &signatures[..signatures.len() - 1])
        .is_ok()
        || registry.witness(0, &surplus).is_ok()
        || registry.script(usize::MAX, true).is_ok()
        || registry.witness(usize::MAX, signatures).is_ok()
    {
        return Err("byte signature count/ordinal guard failed".into());
    }
    count += 4;
    if count != 22 + 2 * usize::from(keys.len() > 1) {
        return Err("native byte rejection census changed".into());
    }
    Ok(count)
}

pub(crate) fn capture_interfaces(
    p: &Prepared,
    registry: &Registry,
    public: &[PublicKey],
    signatures: &[Signature],
    store: &mut OpeningStore,
) -> Result<usize> {
    let mut canonical = 0usize;
    for interface in &p.facts.interfaces {
        for (ordinal, formal) in &interface.occurrences {
            if registry
                .spec()
                .leaves
                .get(*ordinal)
                .and_then(|l| l.wires.get(*formal))
                != Some(&interface.word_index)
            {
                return Err("actual interface formal does not contain its declared word".into());
            }
            let assertion = openings::capture(
                registry,
                public,
                signatures,
                &p.case.words,
                &p.global_ids,
                *ordinal,
                *formal,
            )?;
            if assertion.id != interface.global_id
                || assertion.bound != interface.bound
                || store
                    .insert(
                        (p.facts.index, *ordinal, *formal),
                        StoredOpening {
                            word: interface.word_index,
                            assertion,
                        },
                    )
                    .is_some()
            {
                return Err("actual interface identity/bound/coordinate duplicate differs".into());
            }
        }
    }
    if let Some(frame) = &p.frame {
        for link in &frame.canonical_internal_links {
            let a = store
                .get(&(3, link.source_ordinal, link.source_occurrence))
                .ok_or("actual canonical source opening absent")?;
            let b = store
                .get(&(3, link.target_ordinal, link.target_occurrence))
                .ok_or("actual canonical target opening absent")?;
            if a.word != link.word_index || b.word != link.word_index {
                return Err("canonical encoding/field link uses another word".into());
            }
            openings::same_assertion(&a.assertion, &b.assertion)?;
            canonical += 1;
        }
        if canonical != 46 {
            return Err("all46 actual coefficient encoding/internal field links required".into());
        }
    }
    Ok(canonical)
}

pub(crate) fn verify_connections(
    checked: &source::chain::CheckedSource,
    store: &OpeningStore,
) -> Result<(Vec<Value>, usize)> {
    let connections: BTreeMap<String, Vec<Connection>> =
        serde_json::from_value(checked.maps["connections"].clone())?;
    if connections.len() != 11 {
        return Err("exact eleven actual connection groups required".into());
    }
    let mut rows = Vec::new();
    let mut negatives = 0usize;
    for (kind, logical, expected_openings) in CONNECTION_COUNTS {
        let links = connections
            .get(kind)
            .ok_or("closed connection kind missing")?;
        if links.len() != logical {
            return Err("actual logical alias census differs".into());
        }
        let mut count = 0usize;
        let mut representative = None;
        for link in links {
            if link.source_component >= 9
                || link.target_component >= 9
                || link.source_component == link.target_component
                || link.source_occurrences.is_empty()
                || link.target_occurrences.is_empty()
            {
                return Err("actual connection endpoints differ".into());
            }
            for (source_ordinal, source_formal) in &link.source_occurrences {
                let a = store
                    .get(&(link.source_component, *source_ordinal, *source_formal))
                    .ok_or("source actual opening absent")?;
                if a.word != link.source_word
                    || a.assertion.id != link.global_id
                    || a.assertion.bound != 256
                {
                    return Err("actual source BYTE/global/word differs".into());
                }
                representative.get_or_insert(&a.assertion);
                for (target_ordinal, target_formal) in &link.target_occurrences {
                    let b = store
                        .get(&(link.target_component, *target_ordinal, *target_formal))
                        .ok_or("target actual opening absent")?;
                    if b.word != link.target_word
                        || b.assertion.id != link.global_id
                        || b.assertion.bound != 256
                    {
                        return Err("actual target BYTE/global/word differs".into());
                    }
                    openings::same_assertion(&a.assertion, &b.assertion)?;
                    count += 1;
                }
            }
        }
        if count != expected_openings {
            return Err("actual producer/consumer opening census differs".into());
        }
        let original = representative.ok_or("connection representative missing")?;
        let foreign = store
            .values()
            .find(|entry| entry.assertion.id != original.id)
            .ok_or("independent foreign assertion missing")?;
        negatives += openings::negatives(original, &foreign.assertion)?;
        rows.push(json!({"kind":kind,"logical_links":logical,"opening_links":count}));
    }
    if negatives != 66 {
        return Err("all66 actual intercomponent cache mutants required".into());
    }
    Ok((rows, negatives))
}

pub(crate) fn forest_negatives(
    forest: &TaprootForest,
    registry: &Registry,
    live: &mut [TaprootCommitment],
) -> Result<BTreeMap<&'static str, usize>> {
    use bitcoin::{secp256k1::XOnlyPublicKey, taproot::TapNodeHash};
    let mut counts = BTreeMap::new();
    let manifest = forest.component_manifest_sha256();
    let root = forest.merkle_root();
    let key = forest.output_key();
    let component = forest.selected_component();
    let ordinal = forest.selected_ordinal();
    let script = forest.selected_script();
    let control = forest.control_block_bytes();
    let mut altered = script.as_bytes().to_vec();
    *altered.first_mut().ok_or("empty selected forest Script")? ^= 1;
    reject(
        forest.verify_opening(
            registry,
            manifest,
            root,
            key,
            component,
            ordinal,
            &ScriptBuf::from_bytes(altered),
            &control,
        ),
        "altered_script",
        &mut counts,
    )?;
    for (name, index, mask) in [
        ("branch", 33, 1),
        ("parity", 0, 1),
        ("internal_key", 1, 1),
        ("leaf_version", 0, 2),
    ] {
        let mut bad = control.clone();
        *bad.get_mut(index).ok_or("forest control mutation bounds")? ^= mask;
        reject(
            forest.verify_opening(
                registry, manifest, root, key, component, ordinal, script, &bad,
            ),
            name,
            &mut counts,
        )?;
    }
    reject(
        forest.verify_opening(
            registry,
            manifest,
            root,
            key,
            component,
            ordinal,
            script,
            &control[..control.len() - 1],
        ),
        "truncated_control",
        &mut counts,
    )?;
    let mut appended = control.clone();
    appended.push(0);
    reject(
        forest.verify_opening(
            registry, manifest, root, key, component, ordinal, script, &appended,
        ),
        "appended_control",
        &mut counts,
    )?;
    let mut bad = manifest;
    bad[0] ^= 1;
    reject(
        forest.verify_member(registry, bad, root, key, component, ordinal),
        "manifest",
        &mut counts,
    )?;
    let mut bad = root.to_byte_array();
    bad[0] ^= 1;
    reject(
        forest.verify_member(
            registry,
            manifest,
            TapNodeHash::assume_hidden(bad),
            key,
            component,
            ordinal,
        ),
        "root",
        &mut counts,
    )?;
    let other = XOnlyPublicKey::from_slice(&hex::decode(
        "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    )?)?;
    if other == key {
        return Err("independent alternate forest key collision".into());
    }
    reject(
        forest.verify_member(registry, manifest, root, other, component, ordinal),
        "output_key",
        &mut counts,
    )?;
    reject(
        forest.verify_member(registry, manifest, root, key, (component + 1) % 11, ordinal),
        "component",
        &mut counts,
    )?;
    reject(
        forest.verify_member(registry, manifest, root, key, component, usize::MAX),
        "ordinal",
        &mut counts,
    )?;
    // HI/LO branches are ordered by the component manifest even when sorted
    // TapBranch hashing would preserve the same physical root after swapping.
    live.swap(0, 1);
    let swapped_component = if component < 2 {
        1 - component
    } else {
        component
    };
    let reordered = TaprootForest::new(live, swapped_component);
    live.swap(0, 1);
    match reordered {
        Ok(other) => reject(
            other.verify_member(registry, manifest, root, key, swapped_component, ordinal),
            "reordered_components",
            &mut counts,
        )?,
        Err(_) => {
            counts.insert("reordered_components", 1);
        }
    }
    if counts.len() != 13 || counts.values().any(|n| *n != 1) {
        return Err("all13 forest negative controls required".into());
    }
    Ok(counts)
}

pub(crate) fn registry_for(
    prepared: &Prepared,
    pool: &crate::keys::GlobalPool,
) -> Result<(Registry, Vec<PublicKey>, Vec<Signature>)> {
    let mut public = Vec::with_capacity(prepared.case.words.len());
    let mut signatures = Vec::with_capacity(prepared.case.words.len());
    for ((id, word), value) in prepared
        .global_ids
        .iter()
        .zip(&prepared.case.spec.words)
        .zip(&prepared.case.words)
    {
        let (key, sig) = pool.lookup(id, word.bound, *value)?;
        public.push(*key);
        signatures.push(*sig);
    }
    let identity = prepared.case.spec.key_identity(&public)?;
    let registry = Registry::new(
        prepared.case.spec.clone(),
        public.clone(),
        digest(&prepared.case.expected_spec_id)?,
        identity,
    )?;
    Ok((registry, public, signatures))
}

pub(crate) fn measure_execute(
    p: &Prepared,
    h: &chain::Header,
    registry: &Registry,
    signatures: &[Signature],
    sink: &mut RecordSink,
    metrics: &mut Metrics,
    group: &str,
    global_stream: &mut sha256::HashEngine,
    private_probe: bool,
) -> Result<Value> {
    let mut compiled = 0u64;
    let mut largest = 0usize;
    let mut stream = sha256::Hash::engine();
    let mut check = 0usize;
    for ordinal in 0..p.case.spec.leaves.len() {
        let disproof = registry.script(ordinal, true)?;
        crate::engine::validate(&disproof)?;
        compiled = compiled
            .checked_add(disproof.len() as u64)
            .ok_or("compiled byte overflow")?;
        if compiled > 256 << 20 {
            return Err("component compiled Scripts exceed unchanged256MiB cap".into());
        }
        largest = largest.max(disproof.len());
        for hash in [&mut stream, &mut *global_stream] {
            hash.input(&(disproof.len() as u32).to_le_bytes());
            hash.input(disproof.as_bytes());
        }
        if p.case
            .checks
            .get(check)
            .is_some_and(|c| c.ordinal == ordinal)
        {
            let expected = p.case.checks[check].expected_correct;
            if p.truth.get(ordinal) != Some(&expected) {
                return Err("execution check disagrees with independent tri-state truth".into());
            }
            let witness = registry.witness(ordinal, signatures)?;
            record(
                sink,
                metrics,
                &registry.script(ordinal, false)?,
                &witness,
                outcomes(expected)[0],
                group,
                if private_probe {
                    json!(ordinal)
                } else {
                    json!([h.descriptor.index, ordinal])
                },
                false,
            )?;
            record(
                sink,
                metrics,
                &disproof,
                &witness,
                outcomes(expected)[1],
                group,
                if private_probe {
                    json!(ordinal)
                } else {
                    json!([h.descriptor.index, ordinal])
                },
                true,
            )?;
            check += 1;
        }
    }
    if check != p.case.checks.len() {
        return Err("unexecuted selected predicate".into());
    }
    let normal_metrics = serde_json::to_value(&*metrics)?;
    let layouts = guards(
        registry,
        signatures,
        sink,
        metrics,
        group,
        h.descriptor.index,
    )?;
    let mut ledger = json!({});
    chain::permutation::extend_object(
        &mut ledger,
        json!({"normal_metrics":normal_metrics,"metrics":serde_json::to_value(&*metrics)?,"context":p.case.spec.context,"registry_id":hex::encode(registry.identity()),"compiled_script_bytes":compiled,"largest_disproof_leaf_bytes":largest,"compiled_stream_sha256":sha256::Hash::from_engine(stream).to_string(),"execution_mode":h.execution_mode,"selected_ordinals":h.selected_ordinals,"executed_leaves":check,"native_predicates_checked":p.case.spec.leaves.len(),"false_predicates":h.expected_false,"abort_predicates":h.expected_abort_ordinals,"guard_layouts":layouts,"guard_vectors":14*layouts}),
    )?;
    Ok(ledger)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn abort_is_neither_correctness_nor_a_disproof() {
        assert_eq!(outcomes(Some(true)), [true, false]);
        assert_eq!(outcomes(Some(false)), [false, true]);
        assert_eq!(outcomes(None), [false, false]);
    }
    #[test]
    fn unchanged_type_bridge_preserves_exact_fields_and_identity() {
        let body = vec![0x75, 0x51];
        let sha = sha256::Hash::hash(&body).to_string();
        let old = bitvm2_nova_script_oracle::registry::GraphSpec {
            program_sha256: "00".repeat(32),
            context: "00".repeat(32),
            field_role: "pallas_scalar".into(),
            operation_id: "typed-parity".into(),
            words: vec![bitvm2_nova_script_oracle::registry::Word {
                name: "b".into(),
                bound: 2,
            }],
            leaves: vec![bitvm2_nova_script_oracle::registry::Leaf {
                kind: "word_valid".into(),
                argument: vec![],
                wires: vec![0],
                body_sha256: sha.clone(),
            }],
            bodies: BTreeMap::from([(sha, hex::encode(body))]),
        };
        let local = into_local(old.clone()).unwrap();
        assert_eq!(
            serde_json::to_vec(&old).unwrap(),
            serde_json::to_vec(&local).unwrap()
        );
        assert_eq!(
            serde_json::to_vec(&old).unwrap(),
            serde_json::to_vec(&old_view(&local).unwrap()).unwrap()
        );
        let mut grouped = local;
        grouped.leaves[0].kind = "conv_ab_all".into();
        assert!(old_view(&grouped).is_err());
    }
}
