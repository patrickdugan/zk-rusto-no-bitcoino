//! Hosted TEST-ONLY one complete BYTE Keccak permutation in one parent registry.
//! Fresh input bytes are pinned out of band. No raw vectors, proofs, transaction
//! constructors, production keys, panic catcher or acceptance receipts.
use bitcoin::{
    hashes::{sha256, Hash, HashEngine},
    secp256k1::XOnlyPublicKey,
    taproot::TapNodeHash,
    ScriptBuf,
};
use bitvm::signatures::{CompactWots, Wots, Wots4};
use bitvm2_nova_script_oracle::{
    engine::{execute, Metrics},
    registry::{GraphSpec, Registry, Signature},
    taproot_commitment::{verify_opening, TaprootCommitment},
    wots::{id32, PublicKey, Result},
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::Path,
    time::Instant,
};

const INPUT_CAP: u64 = 32 << 20;
const MANIFEST_CAP: u64 = 1 << 20;
const SUMMARY_CAP: usize = 1 << 20;
const VECTOR_HASH_CAP: u64 = 128 << 20;
const BYTE_KINDS: [&str; 5] = [
    "byte_xor",
    "byte_and",
    "byte_not",
    "byte_rol",
    "byte_xor_const",
];

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Check {
    ordinal: usize,
    expected_correct: bool,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    name: String,
    spec: GraphSpec,
    expected_spec_id: String,
    words: Vec<u32>,
    checks: Vec<Check>,
    measure_all: bool,
}
const MAP_CAP: u64 = 8 << 20;
const LEAVES: usize = 29245;
const WORDS: usize = 29445;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema: String,
    context: String,
    operation_id: String,
    cases: Vec<Descriptor>,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Descriptor {
    name: String,
    profile: String,
    role: String,
    filename: String,
    file_sha256: String,
    file_bytes: u64,
    catalogue_id: String,
    program_sha256: String,
    source_sha256: String,
    global_ids_sha256: String,
    words: usize,
    leaves: usize,
    input_state_hex: String,
    expected_output_state_hex: String,
    expected_false: Vec<usize>,
    state_index: Option<usize>,
    byte_slot: Option<usize>,
    maps_filename: String,
    maps_file_sha256: String,
    maps_file_bytes: u64,
    source_maps_sha256: String,
    program_manifest_filename: String,
    program_manifest_file_sha256: String,
    program_manifest_file_bytes: u64,
    source_manifest_filename: String,
    source_manifest_file_sha256: String,
    source_manifest_file_bytes: u64,
    blocks: Vec<BlockDescriptor>,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BlockDescriptor {
    index: usize,
    first_round: usize,
    last_round: usize,
    operation_id: String,
    program_operation_id: String,
    source_sha256: String,
    program_sha256: String,
    catalogue_id: String,
    global_ids_sha256: String,
    words: usize,
    leaves: usize,
    leaf_offset: usize,
    word_map_sha256: String,
    leaf_map_sha256: String,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BlockRecord {
    index: usize,
    first_round: usize,
    last_round: usize,
    operation_id: String,
    program_operation_id: String,
    source_sha256: String,
    program_sha256: String,
    catalogue_id: String,
    global_ids_sha256: String,
    words: usize,
    leaves: usize,
    leaf_offset: usize,
    word_map_sha256: String,
    leaf_map_sha256: String,
    word_map: Vec<usize>,
    leaf_map: Vec<usize>,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RoundRecord {
    index: usize,
    round_index: usize,
    operation_id: String,
    program_operation_id: String,
    source_sha256: String,
    program_sha256: String,
    catalogue_id: String,
    global_ids_sha256: String,
    block_index: usize,
    child_index: usize,
    word_map: Vec<usize>,
    leaf_map: Vec<usize>,
    input_indices: Vec<usize>,
    output_indices: Vec<usize>,
    producer_ordinals: Vec<usize>,
    producer_occurrences: Vec<usize>,
    input_consumer_occurrences: Vec<Vec<(usize, usize)>>,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct JoinRecord {
    index: usize,
    state_round: usize,
    words: Vec<String>,
    indices: Vec<usize>,
    producer_ordinals: Vec<usize>,
    producer_occurrences: Vec<usize>,
    consumer_occurrences: Vec<Vec<(usize, usize)>>,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RawMaps {
    schema: String,
    blocks: Vec<BlockRecord>,
    rounds: Vec<RoundRecord>,
    input_indices: Vec<usize>,
    output_indices: Vec<usize>,
    producer_ordinals: Vec<usize>,
    producer_occurrences: Vec<usize>,
    global_ids: Vec<String>,
    global_ids_sha256: String,
    joins: Vec<JoinRecord>,
}
#[derive(Clone)]
struct ChildDescriptor {
    round: usize,
    operation_id: String,
    program_sha256: String,
    catalogue_id: String,
    source_sha256: String,
    wordmap_sha256: String,
    words: usize,
    leaves: usize,
    first_leaf: usize,
}
#[derive(Clone)]
struct SegmentDescriptor {
    start_round: usize,
    program_sha256: String,
    catalogue_id: String,
    source_sha256: String,
    global_ids_sha256: String,
    children: Vec<ChildDescriptor>,
}
#[derive(Clone)]
struct View {
    spec: GraphSpec,
    map: Vec<usize>,
    first_leaf: usize,
    layout: ChildLayout,
}
#[derive(Clone)]
struct Block {
    views: Vec<View>,
    inputs: Vec<usize>,
    outputs: Vec<usize>,
}
struct Segment {
    spec: GraphSpec,
    map: Vec<usize>,
    first_leaf: usize,
    block: Block,
    metadata: SegmentDescriptor,
    maps: Value,
}
struct Full {
    segments: Vec<Segment>,
    rounds: Vec<View>,
    inputs: Vec<usize>,
    outputs: Vec<usize>,
    maps: Value,
}
fn segment(
    parent: &GraphSpec,
    d: &BlockDescriptor,
    raw: &RawMaps,
    root_op: &str,
) -> Result<Segment> {
    let i = d.index;
    if i >= 6 {
        return Err("block index bound".into());
    }
    let first = 4 * i;
    let leaves = (first..first + 4)
        .map(|r| 1216 + RC[r].to_le_bytes().iter().filter(|m| **m != 0).count())
        .sum::<usize>();
    let caller = format!("{root_op}/block/{i}");
    let operation = format!("{caller}/rounds/{first}-{}", first + 3);
    if i >= 6
        || d.first_round != first
        || d.last_round != first + 3
        || d.operation_id != caller
        || d.program_operation_id != operation
        || d.words != leaves + 200
        || d.leaves != leaves
    {
        return Err("genuine four-round block descriptor differs".into());
    }
    let by_name: HashMap<_, _> = parent
        .words
        .iter()
        .enumerate()
        .map(|(i, w)| (w.name.as_str(), i))
        .collect();
    let mut map = Vec::new();
    for l in 0..25 {
        for j in 0..8 {
            let name = format!("byte-state/{first}/l{l}/byte{j}");
            map.push(
                *by_name
                    .get(name.as_str())
                    .ok_or("missing aligned block input")?,
            );
        }
    }
    let fresh = 200 + d.leaf_offset;
    for index in fresh..fresh + leaves {
        if index >= parent.words.len() {
            return Err("block fresh word span exceeds parent".into());
        }
        map.push(index);
    }
    if map.iter().collect::<HashSet<_>>().len() != map.len() {
        return Err("aligned block word map is not injective".into());
    }
    let inverse: HashMap<_, _> = map
        .iter()
        .enumerate()
        .map(|(local, parent)| (*parent, local))
        .collect();
    let words = map.iter().map(|j| parent.words[*j].clone()).collect();
    let mut projected = Vec::new();
    for leaf in parent
        .leaves
        .get(d.leaf_offset..d.leaf_offset + leaves)
        .ok_or("block leaf span exceeds parent")?
    {
        let wires = leaf
            .wires
            .iter()
            .map(|w| {
                inverse
                    .get(w)
                    .copied()
                    .ok_or("block leaf references a foreign word")
            })
            .collect::<std::result::Result<Vec<_>, _>>()?;
        projected.push(bitvm2_nova_script_oracle::registry::Leaf {
            kind: leaf.kind.clone(),
            argument: leaf.argument.clone(),
            wires,
            body_sha256: leaf.body_sha256.clone(),
        });
    }
    let needed: HashSet<_> = projected.iter().map(|l| l.body_sha256.as_str()).collect();
    let bodies = parent
        .bodies
        .iter()
        .filter(|(id, _)| needed.contains(id.as_str()))
        .map(|(a, b)| (a.clone(), b.clone()))
        .collect();
    let spec = GraphSpec {
        program_sha256: d.program_sha256.clone(),
        context: parent.context.clone(),
        field_role: parent.field_role.clone(),
        operation_id: operation,
        words,
        leaves: projected,
        bodies,
    };
    if program_digest(&spec)? != digest(&d.program_sha256)?
        || spec.identity()? != digest(&d.catalogue_id)?
        || map_hash(&map)? != d.word_map_sha256
        || map_hash(&(d.leaf_offset..d.leaf_offset + leaves).collect::<Vec<_>>())?
            != d.leaf_map_sha256
    {
        return Err("actual projected block Program/catalogue/map SHA differs".into());
    }
    let mut children = Vec::new();
    for j in 0..4 {
        let record = raw
            .rounds
            .get(4 * i + j)
            .ok_or("missing closed round descriptor")?;
        if record.index != j
            || record.child_index != j
            || record.block_index != i
            || record.round_index != first + j
        {
            return Err("round order or block/child namespace differs".into());
        }
        let local_map = record
            .word_map
            .iter()
            .map(|w| {
                inverse
                    .get(w)
                    .copied()
                    .ok_or("raw round map points outside its exact block")
            })
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let local_leaf = record
            .leaf_map
            .first()
            .ok_or("missing child leaf map")?
            .checked_sub(d.leaf_offset)
            .ok_or("child leaf precedes block")?;
        children.push(ChildDescriptor {
            round: first + j,
            operation_id: record.program_operation_id.clone(),
            program_sha256: record.program_sha256.clone(),
            catalogue_id: record.catalogue_id.clone(),
            source_sha256: record.source_sha256.clone(),
            wordmap_sha256: map_hash(&local_map)?,
            words: local_map.len(),
            leaves: record.leaf_map.len(),
            first_leaf: local_leaf,
        });
    }
    let metadata = SegmentDescriptor {
        start_round: first,
        program_sha256: d.program_sha256.clone(),
        catalogue_id: d.catalogue_id.clone(),
        source_sha256: d.source_sha256.clone(),
        global_ids_sha256: d.global_ids_sha256.clone(),
        children,
    };
    let block = project(&spec, &metadata, &caller)?;
    validate_maps(&spec, &block, first)?;
    let maps = validate_sources(&spec, &metadata, &block, &caller)?;
    Ok(Segment {
        spec,
        map,
        first_leaf: d.leaf_offset,
        block,
        metadata,
        maps,
    })
}
fn compose(parent: &GraphSpec, d: &Descriptor, raw: &RawMaps, root_op: &str) -> Result<Full> {
    if parent.words.len() != WORDS
        || parent.leaves.len() != LEAVES
        || parent.words.iter().any(|w| w.bound != 256)
        || parent
            .leaves
            .iter()
            .any(|l| !BYTE_KINDS.contains(&l.kind.as_str()))
        || d.blocks.len() != 6
        || raw.blocks.len() != 6
        || raw.rounds.len() != 24
        || raw.joins.len() != 23
    {
        return Err("exact full24 single BYTE GraphSpec required".into());
    }
    let mut segments = Vec::new();
    let mut offset = 0;
    let mut images = Vec::new();
    let mut union = HashSet::new();
    let mut encountered = Vec::new();
    let mut rounds = Vec::new();
    let mut records = Vec::new();
    let mut block_records = Vec::new();
    for i in 0..6 {
        let dto = &d.blocks[i];
        if dto.index != i || dto.leaf_offset != offset {
            return Err("block order or leaf offset differs".into());
        }
        let segment = segment(parent, dto, raw, root_op)?;
        let mut value = serde_json::to_value(dto)?;
        extend_object(
            &mut value,
            json!({"word_map":segment.map,"leaf_map":(offset..offset+dto.leaves).collect::<Vec<_>>()}),
        )?;
        block_records.push(serde_json::from_value::<BlockRecord>(value)?);
        for j in 0..4 {
            let local = &segment.block.views[j];
            let map = local.map.iter().map(|k| segment.map[*k]).collect();
            rounds.push(View {
                spec: local.spec.clone(),
                map,
                first_leaf: offset + local.first_leaf,
                layout: local.layout.clone(),
            });
            let mut record = segment.maps["children"][j].clone();
            let view = rounds.last().ok_or("missing projected round view")?;
            for (key, value) in [
                ("word_map", json!(view.map)),
                (
                    "leaf_map",
                    json!((view.first_leaf..view.first_leaf + view.spec.leaves.len())
                        .collect::<Vec<_>>()),
                ),
                (
                    "input_indices",
                    json!(view
                        .layout
                        .ports
                        .inputs
                        .iter()
                        .map(|k| view.map[*k])
                        .collect::<Vec<_>>()),
                ),
                (
                    "output_indices",
                    json!(view
                        .layout
                        .ports
                        .outputs
                        .iter()
                        .map(|k| view.map[*k])
                        .collect::<Vec<_>>()),
                ),
                (
                    "producer_ordinals",
                    json!(view
                        .layout
                        .ports
                        .producers
                        .iter()
                        .map(|p| view.first_leaf + p.0)
                        .collect::<Vec<_>>()),
                ),
                ("input_consumer_occurrences", json!(consumers(view))),
                ("block_index", json!(i)),
                ("child_index", json!(j)),
            ] {
                record
                    .as_object_mut()
                    .ok_or("round source record object")?
                    .insert(key.into(), value);
            }
            records.push(serde_json::from_value::<RoundRecord>(record)?);
        }
        let image: HashSet<_> = segment.map.iter().copied().collect();
        for k in &segment.map {
            if union.insert(*k) {
                encountered.push(*k);
            }
        }
        images.push(image);
        offset += dto.leaves;
        segments.push(segment);
    }
    if offset != LEAVES || encountered != (0..WORDS).collect::<Vec<_>>() || union.len() != WORDS {
        return Err("full first-encounter block quotient/coverage differs".into());
    }
    for i in 0..6 {
        for j in i + 1..6 {
            let shared: HashSet<_> = images[i].intersection(&images[j]).copied().collect();
            if j == i + 1 {
                let left = &rounds[4 * i + 3];
                let right = &rounds[4 * j];
                let out: Vec<_> = left
                    .layout
                    .ports
                    .outputs
                    .iter()
                    .map(|k| left.map[*k])
                    .collect();
                let input: Vec<_> = right
                    .layout
                    .ports
                    .inputs
                    .iter()
                    .map(|k| right.map[*k])
                    .collect();
                if out != input || shared != out.into_iter().collect() || shared.len() != 200 {
                    return Err("five exact adjacent outer block joins required".into());
                }
            } else if !shared.is_empty() {
                return Err("nonadjacent full block images share a word".into());
            }
        }
    }
    let inputs: Vec<_> = rounds[0]
        .layout
        .ports
        .inputs
        .iter()
        .map(|k| rounds[0].map[*k])
        .collect();
    let outputs: Vec<_> = rounds[23]
        .layout
        .ports
        .outputs
        .iter()
        .map(|k| rounds[23].map[*k])
        .collect();
    if inputs != (0..200).collect::<Vec<_>>() || inputs.iter().any(|k| outputs.contains(k)) {
        return Err("exact external and final natural endpoints required".into());
    }
    let mut uses: HashMap<usize, Vec<(usize, usize)>> = HashMap::new();
    let mut produced = HashMap::new();
    for (ordinal, leaf) in parent.leaves.iter().enumerate() {
        let (out, ins) = leaf.wires.split_last().ok_or("empty full BYTE leaf")?;
        if *out != 200 + ordinal
            || ins.iter().any(|w| *w >= *out)
            || produced
                .insert(*out, (ordinal, leaf.wires.len() - 1))
                .is_some()
        {
            return Err("full global BYTE SSA gate order changed".into());
        }
        for (formal, w) in ins.iter().enumerate() {
            uses.entry(*w).or_default().push((ordinal, formal));
        }
    }
    let terminals: HashSet<_> = produced
        .keys()
        .filter(|k| !uses.contains_key(k))
        .copied()
        .collect();
    if terminals != outputs.iter().copied().collect() || terminals.len() != 200 {
        return Err("only final200 natural outputs may remain terminal".into());
    }
    let mut joins = Vec::new();
    for i in 0..23 {
        let left = &rounds[i];
        let right = &rounds[i + 1];
        let indices: Vec<_> = left
            .layout
            .ports
            .outputs
            .iter()
            .map(|k| left.map[*k])
            .collect();
        let incoming: Vec<_> = right
            .layout
            .ports
            .inputs
            .iter()
            .map(|k| right.map[*k])
            .collect();
        if indices != incoming {
            return Err("full ordered round state join changed".into());
        }
        let mut producer_ordinals = Vec::new();
        let mut producer_occurrences = Vec::new();
        let mut actual_consumers = Vec::new();
        let expected = consumers(right);
        for (slot, k) in indices.iter().enumerate() {
            let source = *produced.get(k).ok_or("missing actual state producer")?;
            let actual = uses.get(k).ok_or("missing actual state consumers")?;
            if source
                != (
                    left.first_leaf + left.layout.ports.producers[slot].0,
                    left.layout.ports.producers[slot].1,
                )
                || *actual != expected[slot]
                || actual.len() != 2
            {
                return Err("full actual source/two-consumer incidence differs".into());
            }
            producer_ordinals.push(source.0);
            producer_occurrences.push(source.1);
            actual_consumers.push(actual.clone());
        }
        joins.push(JoinRecord {
            index: i,
            state_round: i + 1,
            words: indices
                .iter()
                .map(|k| parent.words[*k].name.clone())
                .collect(),
            indices,
            producer_ordinals,
            producer_occurrences,
            consumer_occurrences: actual_consumers,
        });
    }
    let final_view = &rounds[23];
    let ids: Vec<_> = parent.words.iter().map(|w| w.name.clone()).collect();
    let global_sha = sha256::Hash::hash(&canonical(&json!(ids))?).to_string();
    let rebuilt = RawMaps {
        schema: "bitvm2-nova-byte-keccak-permutation-maps/v1".into(),
        blocks: block_records,
        rounds: records,
        input_indices: inputs.clone(),
        output_indices: outputs.clone(),
        producer_ordinals: final_view
            .layout
            .ports
            .producers
            .iter()
            .map(|p| final_view.first_leaf + p.0)
            .collect(),
        producer_occurrences: final_view
            .layout
            .ports
            .producers
            .iter()
            .map(|p| p.1)
            .collect(),
        global_ids: ids,
        global_ids_sha256: global_sha,
        joins,
    };
    let maps = serde_json::to_value(rebuilt)?;
    if canonical(&maps)? != canonical(&serde_json::to_value(raw)?)? {
        return Err(
            "raw full source maps differ from independently reconstructed block/round/SSA maps"
                .into(),
        );
    }
    Ok(Full {
        segments,
        rounds,
        inputs,
        outputs,
        maps,
    })
}
fn identities(case: &Case, d: &Descriptor, full: &Full, root_op: &str) -> Result<(Value, Value)> {
    if case.spec.operation_id != root_op {
        return Err("full parent operation is the caller-owned manifest identity".into());
    }
    let map_sha = sha256::Hash::hash(&canonical(&full.maps)?).to_string();
    if map_sha != d.source_maps_sha256
        || full.maps["global_ids_sha256"].as_str() != Some(d.global_ids_sha256.as_str())
    {
        return Err("full map/global-list SHA differs".into());
    }
    let bodies: Vec<_> = case
        .spec
        .bodies
        .iter()
        .map(|(k, v)| json!([k, v]))
        .collect();
    let body_sha = sha256::Hash::hash(&canonical(&json!(bodies))?).to_string();
    let mut program = json!({"schema":"bitvm2-nova-byte-keccak-permutation-program/v1","program_identity_kind":"domain-separated manifest hash; not Program.digest",
        "context":case.spec.context,"field_role":case.spec.field_role,"operation_id":case.spec.operation_id,
        "first_round":0,"rounds":24,"words":WORDS,"leaves":LEAVES});
    extend_object(
        &mut program,
        json!({"source_maps_sha256":map_sha,"body_catalogue_sha256":body_sha,"blocks":d.blocks}),
    )?;
    let program_sha = domain_hash(
        b"BITVM2-NOVA/BYTE-KECCAK-PERMUTATION-PROGRAM/v1\0",
        &program,
    )?;
    if program_sha != case.spec.program_sha256
        || program_sha != d.program_sha256
        || hex::encode(case.spec.identity()?) != d.catalogue_id
    {
        return Err("full domain-separated manifest-as-program/catalogue identity differs".into());
    }
    let source = json!({"schema":"bitvm2-nova-byte-keccak-permutation-source/v1","context":case.spec.context,"field_role":case.spec.field_role,
        "operation_id":case.spec.operation_id,"program_sha256":program_sha,"catalogue_id":d.catalogue_id,
        "program_manifest_sha256":sha256::Hash::hash(&canonical(&program)?).to_string(),"source_maps_sha256":map_sha,
        "scope":"one complete BYTE Keccak-f1600 permutation; no sponge, transcript, proof or production assertion"});
    if domain_hash(b"BITVM2-NOVA/BYTE-KECCAK-PERMUTATION-SOURCE/v1\0", &source)? != d.source_sha256
    {
        return Err("separate acyclic full source-manifest identity differs".into());
    }
    Ok((program, source))
}
fn record(
    sink: &mut VectorSink,
    metrics: &mut Metrics,
    code: &ScriptBuf,
    witness: &[Vec<u8>],
    expected: bool,
    case: &str,
    id: Value,
    disprove: bool,
) -> Result<()> {
    if id.as_str().is_some_and(|s| s.len() > 64) {
        return Err("compact guard/tree identifier exceeds64bytes".into());
    }
    let (success, stack) = execute(code, witness.to_vec())?;
    if success != expected {
        return Err(format!("{case}/{id}/{disprove}: expected{expected}, got{success}").into());
    }
    metrics.vectors += 1;
    metrics.expected_rejections += usize::from(!expected);
    metrics.max_script_bytes = metrics.max_script_bytes.max(code.len());
    metrics.max_stack_items = metrics.max_stack_items.max(stack);
    metrics.max_witness_items = metrics.max_witness_items.max(witness.len());
    metrics.max_witness_payload_bytes = metrics
        .max_witness_payload_bytes
        .max(witness.iter().map(Vec::len).sum::<usize>());
    let mut h = sha256::Hash::engine();
    h.input(&(witness.len() as u32).to_le_bytes());
    for item in witness {
        h.input(&(item.len() as u32).to_le_bytes());
        h.input(item);
    }
    serde_json::to_writer(
        &mut *sink,
        &json!({"c":case,"i":id,"m":disprove,"e":expected,"s":sha256::Hash::hash(code.as_bytes()).to_string(),"w":sha256::Hash::from_engine(h).to_string()}),
    )?;
    sink.write_all(b"\n")?;
    Ok(())
}
fn execute_catalogue(
    case: &Case,
    registry: &Registry,
    signatures: &[Signature],
    sink: &mut VectorSink,
    metrics: &mut Metrics,
) -> Result<Value> {
    let mut bytes = 0u64;
    let mut largest = 0usize;
    let mut stream = sha256::Hash::engine();
    for check in &case.checks {
        let witness = registry.witness(check.ordinal, signatures)?;
        for disprove in [false, true] {
            let code = registry.script(check.ordinal, disprove)?;
            record(
                sink,
                metrics,
                &code,
                &witness,
                check.expected_correct != disprove,
                &case.name,
                json!(check.ordinal),
                disprove,
            )?;
            if disprove {
                bytes += code.len() as u64;
                largest = largest.max(code.len());
                stream.input(&(code.len() as u32).to_le_bytes());
                stream.input(code.as_bytes());
            }
        }
    }
    if bytes > 256 << 20 {
        return Err("full compiled Scripts exceed unchanged256MiB component cap".into());
    }
    Ok(
        json!({"catalogue_id":case.expected_spec_id,"program_sha256":case.spec.program_sha256,"context":case.spec.context,"registry_id":hex::encode(registry.identity()),"words":case.spec.words.len(),"leaves":case.spec.leaves.len(),"executed_leaves":case.checks.len(),"compiled_script_bytes":bytes,"largest_disproof_leaf_bytes":largest,"compiled_stream_sha256":sha256::Hash::from_engine(stream).to_string()}),
    )
}
fn guards(
    registry: &Registry,
    signatures: &[Signature],
    sink: &mut VectorSink,
    metrics: &mut Metrics,
    case: &str,
) -> Result<usize> {
    let mut shapes = HashSet::new();
    for ordinal in 0..registry.spec().leaves.len() {
        if !shapes.insert(auth_shape(registry.spec(), ordinal)) {
            continue;
        }
        let witness = registry.witness(ordinal, signatures)?;
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
                    case,
                    json!(format!("l/{ordinal}/{i}")),
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
                    case,
                    json!(format!("f/{ordinal}/{position}")),
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
                case,
                json!(format!("x/{ordinal}")),
                disprove,
            )?;
        }
    }
    if shapes.len() != 23 {
        return Err("all23 actual BYTE parameter/layout guard shapes required".into());
    }
    Ok(14 * shapes.len())
}
fn validate_manifest(manifest: &Manifest) -> Result<()> {
    if manifest.schema != "bitvm2-nova-byte-keccak-permutation-run/v1"
        || !identifier(&manifest.operation_id)
        || manifest.cases.len() != 8
    {
        return Err("exact eight-case full24 manifest required".into());
    }
    digest(&manifest.context)?;
    let mut profiles = HashSet::new();
    for (i, d) in manifest.cases.iter().enumerate() {
        if !["pallas_scalar", "vesta_scalar"].contains(&d.role.as_str())
            || !["honest", "middle-iota", "final-chi", "oversized"].contains(&d.profile.as_str())
            || !profiles.insert((d.role.as_str(), d.profile.as_str()))
            || d.name != format!("{}/perm-{}", d.role, d.profile)
            || d.words != WORDS
            || d.leaves != LEAVES
            || d.blocks.len() != 6
        {
            return Err("full24 case identity/profile/count differs".into());
        }
        let expected = match d.profile.as_str() {
            "middle-iota" => (Some(4), Some(1)),
            "final-chi" => (None, Some(8)),
            _ => (None, None),
        };
        if (d.state_index, d.byte_slot) != expected {
            return Err("exact Iota state4BYTE1/terminalChiBYTE8 profile required".into());
        }
        for (name, sha, bytes, cap, prefix) in [
            (&d.filename, &d.file_sha256, d.file_bytes, INPUT_CAP, "case"),
            (
                &d.maps_filename,
                &d.maps_file_sha256,
                d.maps_file_bytes,
                MAP_CAP,
                "maps",
            ),
            (
                &d.program_manifest_filename,
                &d.program_manifest_file_sha256,
                d.program_manifest_file_bytes,
                MANIFEST_CAP,
                "program",
            ),
            (
                &d.source_manifest_filename,
                &d.source_manifest_file_sha256,
                d.source_manifest_file_bytes,
                MANIFEST_CAP,
                "source",
            ),
        ] {
            if *name != format!("{prefix}-{i:02}.json") || bytes == 0 || bytes > cap {
                return Err("canonical bounded full24 file descriptor differs".into());
            }
            digest(sha)?;
        }
        for sha in [
            &d.catalogue_id,
            &d.program_sha256,
            &d.source_sha256,
            &d.global_ids_sha256,
            &d.source_maps_sha256,
        ] {
            digest(sha)?;
        }
        state(&d.input_state_hex)?;
        state(&d.expected_output_state_hex)?;
        for b in &d.blocks {
            for sha in [
                &b.program_sha256,
                &b.catalogue_id,
                &b.source_sha256,
                &b.global_ids_sha256,
                &b.word_map_sha256,
                &b.leaf_map_sha256,
            ] {
                digest(sha)?;
            }
        }
    }
    for role in ["pallas_scalar", "vesta_scalar"] {
        for profile in ["honest", "middle-iota", "final-chi", "oversized"] {
            if !profiles.contains(&(role, profile)) {
                return Err("all four full24 scenarios for both roles required".into());
            }
        }
    }
    Ok(())
}
fn validate_case(case: &Case, manifest: &Manifest, d: &Descriptor) -> Result<()> {
    if case.name != d.name
        || !case.measure_all
        || case.expected_spec_id != d.catalogue_id
        || case.spec.program_sha256 != d.program_sha256
        || case.spec.context != manifest.context
        || case.spec.field_role != d.role
        || case.spec.operation_id != manifest.operation_id
        || case.spec.words.len() != WORDS
        || case.words.len() != WORDS
        || case.spec.leaves.len() != LEAVES
        || case.checks.len() != LEAVES
        || case.checks.iter().enumerate().any(|(i, c)| c.ordinal != i)
        || case.spec.identity()? != digest(&d.catalogue_id)?
    {
        return Err("full parent case differs from trusted descriptor".into());
    }
    Ok(())
}
fn assignment(
    case: &Case,
    d: &Descriptor,
    full: &Full,
) -> Result<(Vec<usize>, Vec<Vec<usize>>, usize)> {
    let initial: Vec<_> = (0..200).map(|i| ((37 * i + 11) & 255) as u8).collect();
    let mut current: [u8; 200] = initial
        .try_into()
        .map_err(|_| "fixed200byte initial state")?;
    if state(&d.input_state_hex)? != current {
        return Err("full reference initial state differs".into());
    }
    for (r, view) in full.rounds.iter().enumerate() {
        for j in 0..200 {
            let expected = if d.profile == "oversized" && r == 0 && j == 0 {
                u32::MAX
            } else {
                u32::from(current[j])
            };
            if case.words[view.map[view.layout.ports.inputs[j]]] != expected {
                return Err("actual input is not the preceding claimed full24 state".into());
            }
        }
        let mut out = reference(&current, r);
        if d.profile == "middle-iota" && r == 3 {
            if RC[r].to_le_bytes()[1] != 128 {
                return Err("state4IotaBYTE1 profile no longer names Iota".into());
            }
            out[1] ^= 1;
        }
        if d.profile == "final-chi" && r == 23 {
            out[8] ^= 1;
        }
        for j in 0..200 {
            if case.words[view.map[view.layout.ports.outputs[j]]] != u32::from(out[j]) {
                return Err(
                    "actual full24 output differs from native word reference/controlled claim"
                        .into(),
                );
            }
        }
        current = out;
    }
    if state(&d.expected_output_state_hex)? != current {
        return Err("full terminal reference differs".into());
    }
    for (i, (w, v)) in case.spec.words.iter().zip(&case.words).enumerate() {
        if *v >= w.bound && !(d.profile == "oversized" && i == full.inputs[0] && *v == u32::MAX) {
            return Err("unexpected invalid full parent BYTE word".into());
        }
    }
    let chosen = if d.profile == "middle-iota" {
        let v = &full.rounds[3];
        let (local, formal) = v.layout.ports.producers[1];
        let ordinal = v.first_leaf + local;
        let leaf = &case.spec.leaves[ordinal];
        if formal != 1 || leaf.kind != "byte_xor_const" || leaf.argument != [128] {
            return Err("selected state4 producer is not actual IotaBYTE1".into());
        }
        ordinal
    } else if d.profile == "oversized" {
        0
    } else {
        let v = &full.rounds[23];
        let (local, formal) = v.layout.ports.producers[8];
        let ordinal = v.first_leaf + local;
        if formal != 2 || case.spec.leaves[ordinal].kind != "byte_xor" {
            return Err("selected terminal producer is not natural ChiBYTE8".into());
        }
        ordinal
    };
    let mut false_rows = Vec::new();
    for check in &case.checks {
        let actual = truth(&case.spec, &case.words, check.ordinal)?;
        if actual != check.expected_correct {
            return Err("full24 predicate expectation differs from native integer truth".into());
        }
        if !actual {
            false_rows.push(check.ordinal);
        }
    }
    let expected = if d.profile == "honest" {
        vec![]
    } else if d.profile == "oversized" {
        case.spec
            .leaves
            .iter()
            .enumerate()
            .filter(|(_, l)| l.wires.contains(&full.inputs[0]))
            .map(|(i, _)| i)
            .collect::<Vec<_>>()
    } else {
        vec![chosen]
    };
    if false_rows != expected || false_rows != d.expected_false {
        return Err("exact full24 controlled false-producer/decoder profile differs".into());
    }
    let partitions = full
        .rounds
        .iter()
        .map(|v| {
            false_rows
                .iter()
                .filter(|i| **i >= v.first_leaf && **i < v.first_leaf + v.spec.leaves.len())
                .map(|i| i - v.first_leaf)
                .collect::<Vec<_>>()
        })
        .collect();
    Ok((false_rows, partitions, chosen))
}
#[derive(Clone)]
struct Cached {
    join: usize,
    slot: usize,
    word: usize,
    producer: (usize, usize),
    name: String,
    value: u32,
    bound: u32,
    key: PublicKey,
    signature: Signature,
    opening: Vec<Vec<u8>>,
}
fn make_cache(
    registry: &Registry,
    keys: &[PublicKey],
    signatures: &[Signature],
    values: &[u32],
    full: &Full,
) -> Result<Vec<Vec<Cached>>> {
    let mut result = Vec::new();
    for join in 0..23 {
        let view = &full.rounds[join];
        let mut entries = Vec::new();
        for slot in 0..200 {
            let word = view.map[view.layout.ports.outputs[slot]];
            let (local, formal) = view.layout.ports.producers[slot];
            let producer = (view.first_leaf + local, formal);
            if registry
                .spec()
                .leaves
                .get(producer.0)
                .and_then(|l| l.wires.get(formal))
                != Some(&word)
            {
                return Err("cache source is not actual full parent producer operand".into());
            }
            let w = registry
                .spec()
                .words
                .get(word)
                .ok_or("cache global word bound")?;
            entries.push(Cached {
                join,
                slot,
                word,
                producer,
                name: w.name.clone(),
                value: *values.get(word).ok_or("cache value bound")?,
                bound: w.bound,
                key: *keys.get(word).ok_or("cache key bound")?,
                signature: *signatures.get(word).ok_or("cache signature bound")?,
                opening: opening(registry, signatures, producer.0, word)?,
            });
        }
        result.push(entries);
    }
    Ok(result)
}
fn verify_cache(
    registry: &Registry,
    keys: &[PublicKey],
    signatures: &[Signature],
    values: &[u32],
    full: &Full,
    cache: &[Vec<Cached>],
) -> Result<Vec<Value>> {
    if cache.len() != 23 || cache.iter().any(|c| c.len() != 200) {
        return Err("all23 complete200-entry boundary caches required".into());
    }
    let mut rows = Vec::new();
    let spec = registry.spec();
    for join in 0..23 {
        let left = &full.rounds[join];
        let right = &full.rounds[join + 1];
        let uses = consumers(right);
        let mut links = 0;
        for slot in 0..200 {
            let word = left.map[left.layout.ports.outputs[slot]];
            let incoming = right.map[right.layout.ports.inputs[slot]];
            let entry = &cache[join][slot];
            let producer = (
                left.first_leaf + left.layout.ports.producers[slot].0,
                left.layout.ports.producers[slot].1,
            );
            let w = spec.words.get(word).ok_or("actual boundary word bound")?;
            if word != incoming
                || entry.join != join
                || entry.slot != slot
                || entry.word != word
                || entry.name != w.name
                || entry.producer != producer
                || entry.value != values[word]
                || entry.bound != 256
                || entry.bound != w.bound
                || entry.key != keys[word]
                || entry.signature != signatures[word]
                || entry.opening != opening(registry, signatures, producer.0, word)?
            {
                return Err(
                    "original source identity/value/bound/key/signature/opening changed".into(),
                );
            }
            if values[incoming] != entry.value
                || spec.words[incoming].bound != entry.bound
                || keys[incoming] != entry.key
                || signatures[incoming] != entry.signature
            {
                return Err("next-round view does not reuse original parent assertion".into());
            }
            for (ordinal, formal) in &uses[slot] {
                let leaf = spec
                    .leaves
                    .get(*ordinal)
                    .ok_or("actual consumer ordinal bound")?;
                if leaf.kind != "byte_xor"
                    || leaf.wires.get(*formal) != Some(&word)
                    || entry.opening != opening(registry, signatures, *ordinal, word)?
                {
                    return Err("full actual producer-to-C/Theta consumer opening differs".into());
                }
                links += 1;
            }
        }
        if links != 400 {
            return Err("exact400 actual comparisons per state join required".into());
        }
        rows.push(json!({"index":join,"state_round":join+1,"cached_entries":200,"producer_consumer_opening_links":links}));
    }
    Ok(rows)
}
fn cache_negatives(
    registry: &Registry,
    keys: &[PublicKey],
    signatures: &[Signature],
    values: &[u32],
    full: &Full,
    cache: &[Vec<Cached>],
) -> Result<usize> {
    let mut count = 0;
    for (join, slot) in [(0, 0), (3, 1), (22, 0)] {
        for mutation in 0..6 {
            let mut bad = cache.to_vec();
            match mutation {
                0 => bad[join][slot].value ^= 1,
                1 => bad[join][slot].bound = 2,
                2 => bad[join][slot].key = bad[join][(slot + 1) % 200].key,
                3 => bad[join][slot].signature = bad[join][(slot + 1) % 200].signature,
                4 => {
                    *bad[join][slot]
                        .opening
                        .first_mut()
                        .and_then(|p| p.first_mut())
                        .ok_or("empty original boundary opening")? ^= 1
                }
                _ => bad[join][slot] = bad[(join + 1) % 23][slot].clone(),
            }
            if verify_cache(registry, keys, signatures, values, full, &bad).is_ok() {
                return Err("altered/swapped internal or cross-block cache accepted".into());
            }
            count += 1;
        }
    }
    Ok(count)
}
fn map_negatives(case: &Case, d: &Descriptor, raw: &RawMaps, root_op: &str) -> Result<usize> {
    let mut variants = Vec::new();
    let mut x = raw.clone();
    x.blocks[1].word_map[0] = x.blocks[1].word_map[1];
    variants.push(x);
    let mut x = raw.clone();
    x.blocks[1].word_map.swap(0, 1);
    variants.push(x);
    let mut x = raw.clone();
    x.blocks[1].word_map[0] = x.blocks[0].word_map[0];
    variants.push(x);
    let mut x = raw.clone();
    x.blocks[1].word_map[0] = WORDS;
    variants.push(x);
    let mut x = raw.clone();
    x.rounds[4].word_map[0] = x.rounds[4].word_map[1];
    variants.push(x);
    let mut x = raw.clone();
    x.rounds[4].leaf_map.swap(0, 1);
    variants.push(x);
    let mut x = raw.clone();
    x.joins[3].indices[0] = x.joins[3].indices[1];
    variants.push(x);
    let mut x = raw.clone();
    x.rounds.swap(0, 1);
    variants.push(x);
    for other in &variants {
        if compose(&case.spec, d, other, root_op).is_ok() {
            return Err("substituted private raw map/round/join accepted".into());
        }
    }
    Ok(variants.len())
}
fn source_negatives(case: &Case, d: &Descriptor, raw: &RawMaps, root_op: &str) -> Result<usize> {
    let mut variants = Vec::new();
    let mut x = d.clone();
    x.blocks[1].program_sha256 = changed(&x.blocks[1].program_sha256)?;
    variants.push(x);
    let mut x = d.clone();
    x.blocks[1].catalogue_id = changed(&x.blocks[1].catalogue_id)?;
    variants.push(x);
    let mut x = d.clone();
    x.blocks[1].source_sha256 = changed(&x.blocks[1].source_sha256)?;
    variants.push(x);
    let mut x = d.clone();
    x.blocks[1].program_operation_id = x.blocks[0].program_operation_id.clone();
    variants.push(x);
    let mut x = d.clone();
    x.blocks[1].operation_id = x.blocks[0].operation_id.clone();
    variants.push(x);
    let mut x = d.clone();
    x.blocks[1].first_round += 1;
    variants.push(x);
    let mut x = d.clone();
    x.blocks[1].leaf_offset += 1;
    variants.push(x);
    let mut x = d.clone();
    x.blocks[1].word_map_sha256 = changed(&x.blocks[1].word_map_sha256)?;
    variants.push(x);
    let mut x = d.clone();
    x.blocks[1].leaf_map_sha256 = changed(&x.blocks[1].leaf_map_sha256)?;
    variants.push(x);
    let mut x = d.clone();
    x.blocks.swap(0, 1);
    variants.push(x);
    let mut x = d.clone();
    x.source_sha256 = changed(&x.source_sha256)?;
    variants.push(x);
    let mut x = d.clone();
    x.program_sha256 = changed(&x.program_sha256)?;
    variants.push(x);
    for other in &variants {
        let rejected = match compose(&case.spec, other, raw, root_op) {
            Err(_) => true,
            Ok(full) => identities(case, other, &full, root_op).is_err(),
        };
        if !rejected {
            return Err("substituted parent/block/round source identity accepted".into());
        }
    }
    Ok(variants.len())
}
fn reject<T>(
    result: Result<T>,
    name: &'static str,
    counts: &mut BTreeMap<&'static str, usize>,
) -> Result<()> {
    if result.is_ok() {
        return Err(format!("negative full tree opening accepted: {name}").into());
    }
    *counts.entry(name).or_default() += 1;
    Ok(())
}
fn tree_negatives(
    tree: &TaprootCommitment,
    registry: &Registry,
    keys: &[PublicKey],
    case: &Case,
) -> Result<BTreeMap<&'static str, usize>> {
    let mut counts = BTreeMap::new();
    let root = tree.merkle_root();
    let key = tree.output_key();
    let ordinal = tree.selected_ordinal();
    let script = tree.selected_script();
    let control = tree.control_block_bytes();
    let mut bad = script.as_bytes().to_vec();
    *bad.first_mut().ok_or("empty selected tree script")? ^= 1;
    reject(
        verify_opening(
            registry,
            root,
            key,
            ordinal,
            ScriptBuf::from_bytes(bad).as_script(),
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
        *bad.get_mut(index)
            .ok_or("selected control mutation bound")? ^= mask;
        reject(
            verify_opening(registry, root, key, ordinal, script, &bad),
            name,
            &mut counts,
        )?;
    }
    reject(
        verify_opening(
            registry,
            root,
            key,
            ordinal,
            script,
            &control[..control.len() - 1],
        ),
        "truncated_control",
        &mut counts,
    )?;
    let mut bad = control.clone();
    bad.push(0);
    reject(
        verify_opening(registry, root, key, ordinal, script, &bad),
        "appended_control",
        &mut counts,
    )?;
    let mut raw = root.to_byte_array();
    raw[0] ^= 1;
    reject(
        tree.verify_member(registry, TapNodeHash::assume_hidden(raw), key, ordinal),
        "root",
        &mut counts,
    )?;
    let wrong = XOnlyPublicKey::from_slice(&hex::decode(
        "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    )?)?;
    if wrong == key {
        return Err("negative output key equals actual tree key".into());
    }
    reject(
        tree.verify_member(registry, root, wrong, ordinal),
        "output_key",
        &mut counts,
    )?;
    reject(
        tree.verify_member(registry, root, key, (ordinal + 1) % LEAVES),
        "ordinal",
        &mut counts,
    )?;
    let mut foreign = keys.to_vec();
    foreign[0] = Wots4::generate_public_key(&seed(
        &digest(&case.expected_spec_id)?,
        &case.name,
        "foreign/tree/registry",
    ));
    if foreign[0] == keys[0] {
        return Err("foreign tree key collision".into());
    }
    let id = case.spec.key_identity(&foreign)?;
    let other = Registry::new(
        case.spec.clone(),
        foreign,
        digest(&case.expected_spec_id)?,
        id,
    )?;
    reject(
        tree.verify_member(&other, root, key, ordinal),
        "registry",
        &mut counts,
    )?;
    let mut changed_spec = case.spec.clone();
    changed_spec.context = changed(&changed_spec.context)?;
    let catalogue = changed_spec.identity()?;
    let id = changed_spec.key_identity(keys)?;
    let other = Registry::new(changed_spec, keys.to_vec(), catalogue, id)?;
    reject(
        tree.verify_member(&other, root, key, ordinal),
        "catalogue",
        &mut counts,
    )?;
    if counts.len() != 12 || counts.values().any(|n| *n != 1) {
        return Err("exact12 selected tree rejection classes required".into());
    }
    Ok(counts)
}
fn checked_file(root: &Path, name: &str, cap: u64, sha: &str, bytes: u64) -> Result<Vec<u8>> {
    let raw = snapshot(&root.join(name), cap, digest(sha)?)?;
    if raw.len() as u64 != bytes {
        return Err("exact full24 file length differs".into());
    }
    Ok(raw)
}
fn case_run(
    manifest: &Manifest,
    d: &Descriptor,
    root: &Path,
    sink: &mut VectorSink,
    metrics: &mut Metrics,
    all_keys: &mut HashSet<[u8; 32]>,
    all_signatures: &mut HashSet<[u8; 32]>,
) -> Result<Value> {
    let started = Instant::now();
    let raw = checked_file(root, &d.filename, INPUT_CAP, &d.file_sha256, d.file_bytes)?;
    let case: Case = serde_json::from_slice(&raw)?;
    drop(raw);
    validate_case(&case, manifest, d)?;
    let raw_bytes = checked_file(
        root,
        &d.maps_filename,
        MAP_CAP,
        &d.maps_file_sha256,
        d.maps_file_bytes,
    )?;
    let raw: RawMaps = serde_json::from_slice(&raw_bytes)?;
    let full = compose(&case.spec, d, &raw, &manifest.operation_id)?;
    if canonical(&full.maps)? != raw_bytes {
        return Err("raw map file is not exact canonical independently rebuilt source maps".into());
    }
    drop(raw_bytes);
    let (program, source) = identities(&case, d, &full, &manifest.operation_id)?;
    let bytes = checked_file(
        root,
        &d.program_manifest_filename,
        MANIFEST_CAP,
        &d.program_manifest_file_sha256,
        d.program_manifest_file_bytes,
    )?;
    if bytes != canonical(&program)? {
        return Err("compact program file differs from actual acyclic manifest identity".into());
    }
    let bytes = checked_file(
        root,
        &d.source_manifest_filename,
        MANIFEST_CAP,
        &d.source_manifest_file_sha256,
        d.source_manifest_file_bytes,
    )?;
    if bytes != canonical(&source)? {
        return Err(
            "compact source file differs from independently rebuilt source identity".into(),
        );
    }
    let map_rejections = map_negatives(&case, d, &raw, &manifest.operation_id)?;
    let source_rejections = source_negatives(&case, d, &raw, &manifest.operation_id)?;
    let (false_rows, round_false, selected) = assignment(&case, d, &full)?;
    let expected = digest(&case.expected_spec_id)?;
    let secrets: Vec<_> = case
        .spec
        .words
        .iter()
        .map(|w| seed(&expected, &case.name, &w.name))
        .collect();
    let keys: Vec<PublicKey> = secrets.iter().map(Wots4::generate_public_key).collect();
    let signatures: Vec<Signature> = secrets
        .iter()
        .zip(&case.words)
        .map(|(s, v)| Wots4::compact_sign(s, &v.to_le_bytes()))
        .collect();
    collision_check(&keys, &signatures, all_keys, all_signatures)?;
    let registry_id = case.spec.key_identity(&keys)?;
    let registry = Registry::new(case.spec.clone(), keys.clone(), expected, registry_id)?;
    let foreign =
        Wots4::generate_public_key(&seed(&expected, &case.name, "foreign/parent/test-only"));
    if keys.contains(&foreign) {
        return Err("foreign parent key collision".into());
    }
    let native_rejections = native_negatives(&case, &keys, &signatures, foreign, &registry)?;
    let mut parent = execute_catalogue(&case, &registry, &signatures, sink, metrics)?;
    extend_object(
        &mut parent,
        json!({"source_sha256":d.source_sha256,"global_ids_sha256":d.global_ids_sha256,"source_maps_sha256":d.source_maps_sha256}),
    )?;
    let guard_vectors = guards(&registry, &signatures, sink, metrics, &case.name)?;
    let cache = make_cache(&registry, &keys, &signatures, &case.words, &full)?;
    let joins = verify_cache(&registry, &keys, &signatures, &case.words, &full, &cache)?;
    let cache_rejections =
        cache_negatives(&registry, &keys, &signatures, &case.words, &full, &cache)?;
    let tree = TaprootCommitment::new(&registry, selected)?;
    if tree.registry_id() != registry.identity()
        || tree.catalogue_id() != expected
        || tree.leaf_count() != LEAVES
        || tree.compiled_script_bytes()
            != parent["compiled_script_bytes"]
                .as_u64()
                .ok_or("compiled parent byte count type")?
        || hex::encode(tree.compiled_stream_sha256())
            != parent["compiled_stream_sha256"]
                .as_str()
                .ok_or("compiled parent hash type")?
    {
        return Err("live full tree differs from exact complete parent Script stream".into());
    }
    tree.verify_member(&registry, tree.merkle_root(), tree.output_key(), selected)?;
    let control = tree.control_block_bytes();
    let expected_control = if selected < 25722 { 513 } else { 481 };
    if control.len() != expected_control {
        return Err("actual full tree control differs from complete-left-filled schedule".into());
    }
    let correct = case.checks[selected].expected_correct;
    let witness = registry.witness(selected, &signatures)?;
    if tree.selected_script().as_bytes() != registry.script(selected, true)?.as_bytes() {
        return Err("selected member Script is not the actual parent disproof leaf".into());
    }
    record(
        sink,
        metrics,
        &registry.script(selected, false)?,
        &witness,
        correct,
        &case.name,
        json!(format!("t/{selected}")),
        false,
    )?;
    record(
        sink,
        metrics,
        &ScriptBuf::from_bytes(tree.selected_script().as_bytes().to_vec()),
        &witness,
        !correct,
        &case.name,
        json!(format!("t/{selected}")),
        true,
    )?;
    let negatives = tree_negatives(&tree, &registry, &keys, &case)?;
    if native_rejections != 24
        || map_rejections != 8
        || source_rejections != 12
        || cache_rejections != 18
        || guard_vectors != 322
        || joins.len() != 23
    {
        return Err("exact full24 admission/map/source/cache/guard census differs".into());
    }
    let mut tree_row = json!({"leaf_count":tree.leaf_count(),"compiled_script_bytes":tree.compiled_script_bytes(),"compiled_stream_sha256":hex::encode(tree.compiled_stream_sha256()),
        "merkle_root":tree.merkle_root().to_string(),"output_key":tree.output_key().to_string(),"control_block_bytes":control.len(),"control_block_sha256":sha256::Hash::hash(&control).to_string(),"selected_script_sha256":sha256::Hash::hash(tree.selected_script().as_bytes()).to_string()});
    extend_object(
        &mut tree_row,
        json!({"hierarchical_membership_verified":true,"roots_independently_pinned":false,"negative_counts":negatives}),
    )?;
    let mut row = json!({"name":d.name,"profile":d.profile,"role":d.role,"state_index":d.state_index,"byte_slot":d.byte_slot,"parent":parent,
        "blocks":d.blocks,"joins":joins,"false_predicates":false_rows,"round_false_predicates":round_false,"tree":tree_row});
    extend_object(
        &mut row,
        json!({"signature_entries_created":WORDS,"round_declared_word_occurrences":34045,"block_declared_word_occurrences":30445,
        "cached_boundary_entries":4600,"producer_consumer_opening_links":9200,"internal_cached_boundary_entries":3600,
        "internal_producer_consumer_opening_links":7200,"cross_block_cached_boundary_entries":1000,"cross_block_producer_consumer_opening_links":2000}),
    )?;
    extend_object(
        &mut row,
        json!({"selected_leaf":selected,"selected_correctness_execution_success":correct,"selected_disproof_execution_success":!correct,
        "additional_selected_engine_executions":2,"guard_layouts":23,"guard_vectors":guard_vectors,"native_rejections":native_rejections,
        "map_rejections":map_rejections,"source_rejections":source_rejections,"cache_rejections":cache_rejections,"wall_seconds":started.elapsed().as_secs_f64()}),
    )?;
    Ok(row)
}
fn run() -> Result<Value> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 5 {
        return Err(
            "usage: byte_keccak_permutation MANIFEST CASE_DIR OUTPUT EXPECTED_MANIFEST_SHA256"
                .into(),
        );
    }
    if std::env::var("GITHUB_ACTIONS").as_deref() != Ok("true")
        || std::env::var("RUNNER_OS").as_deref() != Ok("Linux")
        || !cfg!(target_os = "linux")
    {
        return Err("full BYTE permutation execution is hosted GitHub Linux only".into());
    }
    let started = Instant::now();
    let expected = digest(&args[4])?;
    let raw = snapshot(Path::new(&args[1]), MANIFEST_CAP, expected)?;
    let manifest: Manifest = serde_json::from_slice(&raw)?;
    drop(raw);
    validate_manifest(&manifest)?;
    let source = Path::new(&args[2]);
    if fs::symlink_metadata(source)?.file_type().is_symlink() {
        return Err("full fixture directory symlink forbidden".into());
    }
    let root = fs::canonicalize(source)?;
    if !root.is_dir() || fs::canonicalize(&args[1])? != root.join("manifest.json") {
        return Err("exact canonical full fixture directory/manifest required".into());
    }
    let mut inventory = HashSet::from(["manifest.json".to_owned()]);
    for d in &manifest.cases {
        for name in [
            &d.filename,
            &d.maps_filename,
            &d.program_manifest_filename,
            &d.source_manifest_filename,
        ] {
            inventory.insert(name.clone());
        }
    }
    let observed: HashSet<_> = fs::read_dir(&root)?
        .map(|e| e.map(|e| e.file_name().to_string_lossy().into_owned()))
        .collect::<std::io::Result<_>>()?;
    if observed != inventory {
        return Err("full fixture inventory must contain exactly33 trusted files".into());
    }
    let mut sink = VectorSink {
        hash: sha256::Hash::engine(),
        bytes: 0,
    };
    let mut metrics = Metrics::default();
    let mut rows = Vec::new();
    let mut keys = HashSet::new();
    let mut signatures = HashSet::new();
    for d in &manifest.cases {
        rows.push(case_run(
            &manifest,
            d,
            &root,
            &mut sink,
            &mut metrics,
            &mut keys,
            &mut signatures,
        )?);
    }
    if keys.len() != 8 * WORDS || signatures.len() != 8 * WORDS {
        return Err("one actual fresh key/signature per parent word/session required".into());
    }
    let mut result = json!({"schema":"bitvm2-nova-byte-keccak-permutation-execution/v1","passed":true,"input_manifest_sha256":hex::encode(expected),
        "metrics":metrics,"cases":rows,"compact_execution_records_bytes":sink.bytes,"compact_execution_records_sha256":sha256::Hash::from_engine(sink.hash).to_string()});
    extend_object(
        &mut result,
        json!({"signature_entries_created":8*WORDS,"round_declared_word_occurrences":8*34045,"block_declared_word_occurrences":8*30445,
        "cached_boundary_entries":8*4600,"producer_consumer_opening_links":8*9200,"internal_cached_boundary_entries":8*3600,"internal_producer_consumer_opening_links":8*7200,
        "cross_block_cached_boundary_entries":8*1000,"cross_block_producer_consumer_opening_links":8*2000}),
    )?;
    extend_object(
        &mut result,
        json!({"full_24_round_script_conformance_checked":true,"all_parent_leaves_executed":true,"boundary_opening_links_checked":true,
        "children_projected_from_parent":true,"test_keys_only":true,"stack_limit_enabled":true,"hierarchical_membership_verified":true,
        "raw_vector_file_written":false,"op_cat_enabled":false,"full_permutation_verified":false,"full_hash_verified":false}),
    )?;
    extend_object(
        &mut result,
        json!({"transcript_verified":false,"proof_verified":false,"complete_nova_verifier":false,"complete_bitvm2_verifier":false,
        "production_assertion_binding":false,"bitcoin_transaction_graph":false,"panic_is_rejection":false,"setup_calls":0,"proving_jobs":0,
        "native_proofs_verified":0,"gpu_jobs":0,"transactions_broadcast":0,"wall_seconds":started.elapsed().as_secs_f64()}),
    )?;
    let raw = serde_json::to_vec(&result)?;
    if raw.len() > SUMMARY_CAP {
        return Err("full native summary exceeds unchanged1MiB cap".into());
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
    // Metadata-only hash/cap stubs. The dummy OP_TRUE body is never presented
    // as an arithmetic proof, a production opening or a full permutation.
    fn tiny(role: &str) -> GraphSpec {
        let body = sha256::Hash::hash(&[0x51]).to_string();
        GraphSpec {
            program_sha256: "00".repeat(32),
            context: "00".repeat(32),
            field_role: role.into(),
            operation_id: "test/canonical-byte-program".into(),
            words: ["a", "b", "out"]
                .iter()
                .map(|name| bitvm2_nova_script_oracle::registry::Word {
                    name: (*name).into(),
                    bound: 256,
                })
                .collect(),
            leaves: vec![bitvm2_nova_script_oracle::registry::Leaf {
                kind: "byte_xor".into(),
                argument: vec![],
                wires: vec![0, 1, 2],
                body_sha256: body.clone(),
            }],
            bodies: [(body, "51".into())].into_iter().collect(),
        }
    }
    #[test]
    fn genuine_child_program_hashes_match_independent_python_goldens() {
        for (role, expected) in [
            (
                "pallas_scalar",
                "1568ed4e3edcfd2e138e61b3c48395cfe06348f1bcabc493b9881944d480a5e9",
            ),
            (
                "vesta_scalar",
                "db881dc2f7eedb09cf050ec0b233393dcd76fdff25f774dbc95268b0d6abeb16",
            ),
        ] {
            assert_eq!(hex::encode(program_digest(&tiny(role)).unwrap()), expected);
        }
    }
    #[test]
    fn oversized_parent_cannot_be_relabelled_as_a_byte_program() {
        let mut data = tiny("pallas_scalar");
        data.leaves = vec![data.leaves[0].clone(); 10_001];
        assert!(program_digest(&data).is_err());
        assert!(LEAVES > 10_000 && LEAVES < 30_000);
        assert_eq!(WORDS, LEAVES + 200);
    }
    #[test]
    fn program_and_source_manifest_domains_are_separate() {
        let value = json!({"schema":"test","a":[1,2]});
        let program =
            domain_hash(b"BITVM2-NOVA/BYTE-KECCAK-PERMUTATION-PROGRAM/v1\0", &value).unwrap();
        let source =
            domain_hash(b"BITVM2-NOVA/BYTE-KECCAK-PERMUTATION-SOURCE/v1\0", &value).unwrap();
        assert_ne!(program, source);
        assert_ne!(
            program,
            sha256::Hash::hash(&canonical(&value).unwrap()).to_string()
        );
    }
    #[test]
    fn canonical_source_json_sorts_nested_objects_and_preserves_arrays() {
        assert_eq!(
            String::from_utf8(canonical(&json!({"z":{"b":2,"a":1},"a":[2,1]})).unwrap()).unwrap(),
            r#"{"a":[2,1],"z":{"a":1,"b":2}}"#
        );
    }
    #[test]
    fn selected_iota_is_byte_one_and_terminal_chi_is_scattered() {
        let prefix = (0..3)
            .map(|r| 1216 + RC[r].to_le_bytes().iter().filter(|m| **m != 0).count())
            .sum::<usize>();
        assert_eq!(RC[3].to_le_bytes()[0], 0);
        assert_eq!(RC[3].to_le_bytes()[1], 128);
        assert_eq!(prefix + 1216, 4870);
        let final_prefix = (0..23)
            .map(|r| 1216 + RC[r].to_le_bytes().iter().filter(|m| **m != 0).count())
            .sum::<usize>();
        assert_eq!(final_prefix + 1016 + 8, 29049);
        assert_eq!(2 * (LEAVES - (1 << 14)), 25722);
    }
    #[test]
    fn compact_identifier_and_record_caps_fail_without_large_allocations() {
        let mut sink = VectorSink {
            hash: sha256::Hash::engine(),
            bytes: VECTOR_HASH_CAP - 1,
        };
        assert!(sink.write_all(&[0, 0]).is_err());
        assert_eq!(sink.bytes, VECTOR_HASH_CAP - 1);
        let mut metrics = Metrics::default();
        let code = ScriptBuf::from_bytes(vec![0x51]);
        assert!(record(
            &mut sink,
            &mut metrics,
            &code,
            &[],
            true,
            "test",
            json!("x".repeat(65)),
            false
        )
        .is_err());
        assert_eq!(metrics.vectors, 0);
    }
    #[test]
    fn closed_json_rejects_duplicate_unknown_and_non_integer_coordinates() {
        for raw in [
            r#"{"ordinal":0,"ordinal":1,"expected_correct":true}"#,
            r#"{"ordinal":1.0,"expected_correct":true}"#,
            r#"{"ordinal":false,"expected_correct":true}"#,
            r#"{"ordinal":0,"expected_correct":true,"extra":0}"#,
        ] {
            assert!(serde_json::from_str::<Check>(raw).is_err());
        }
        for name in [
            "byte-state/4/l00/byte1",
            "byte-state/3/l0/byte1",
            "byte-state/4/l25/byte0",
            "byte-state/4/l0/byte8",
        ] {
            assert!(state_word(name, 4).is_err());
        }
    }
    #[test]
    fn each_absolute_round_view_has_two_exact_consumer_occurrences() {
        let view = View {
            spec: tiny("pallas_scalar"),
            map: vec![],
            first_leaf: 1000,
            layout: ChildLayout {
                ports: Ports {
                    inputs: vec![],
                    outputs: vec![],
                    producers: vec![],
                },
            },
        };
        let actual = consumers(&view);
        assert_eq!(actual.len(), 200);
        assert_eq!(actual[0], vec![(1000, 0), (1240, 0)]);
        assert_eq!(actual[40], vec![(1000, 1), (1280, 0)]);
        assert_eq!(actual[199], vec![(1159, 1), (1439, 0)]);
        assert!(actual
            .iter()
            .all(|cells| cells.len() == 2 && cells[0] != cells[1]));
    }
}
const RC: [u64; 24] = [
    1,
    0x8082,
    0x800000000000808a,
    0x8000000080008000,
    0x808b,
    0x80000001,
    0x8000000080008081,
    0x8000000000008009,
    0x8a,
    0x88,
    0x80008009,
    0x8000000a,
    0x8000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x80000001,
    0x8000000080008008,
];
const RHO: [[u32; 5]; 5] = [
    [0, 1, 62, 28, 27],
    [36, 44, 6, 55, 20],
    [3, 10, 43, 25, 39],
    [41, 45, 15, 21, 8],
    [18, 2, 61, 56, 14],
];

#[derive(Clone)]
struct Ports {
    inputs: Vec<usize>,
    outputs: Vec<usize>,
    producers: Vec<(usize, usize)>,
}
#[derive(Clone)]
struct ChildLayout {
    ports: Ports,
}
struct Checker<'a> {
    spec: &'a GraphSpec,
    word: usize,
    leaf: usize,
}
impl<'a> Checker<'a> {
    fn new(spec: &'a GraphSpec) -> Self {
        Self {
            spec,
            word: 0,
            leaf: 0,
        }
    }
    fn word(&mut self, name: String, bound: u32) -> Result<usize> {
        let item = self
            .spec
            .words
            .get(self.word)
            .ok_or("missing scheduled source word")?;
        if item.name != name || item.bound != bound {
            return Err(format!("scheduled source word/bound differs: {name}").into());
        }
        let index = self.word;
        self.word += 1;
        Ok(index)
    }
    fn leaf(&mut self, kind: &str, args: &[i64], wires: &[usize]) -> Result<usize> {
        let item = self
            .spec
            .leaves
            .get(self.leaf)
            .ok_or("missing scheduled source leaf")?;
        if item.kind != kind || item.argument != args || item.wires != wires {
            return Err(format!("scheduled source predicate differs at {}", self.leaf).into());
        }
        let ordinal = self.leaf;
        self.leaf += 1;
        Ok(ordinal)
    }
    fn gate(
        &mut self,
        name: String,
        kind: &str,
        args: &[i64],
        inputs: &[usize],
        bound: u32,
    ) -> Result<usize> {
        let output = self.word(name, bound)?;
        let mut wires = inputs.to_vec();
        wires.push(output);
        self.leaf(kind, args, &wires)?;
        Ok(output)
    }
    fn finish(&self) -> Result<()> {
        if self.word != self.spec.words.len() || self.leaf != self.spec.leaves.len() {
            return Err("source has extra/missing scheduled words or leaves".into());
        }
        Ok(())
    }
}
fn byte_layout(spec: &GraphSpec, r: usize) -> Result<ChildLayout> {
    let mut c = Checker::new(spec);
    let mut input = [[0usize; 8]; 25];
    for l in 0..25 {
        for j in 0..8 {
            input[l][j] = c.word(format!("input/l{l}/byte{j}"), 256)?;
        }
    }
    let mut parity = [[0usize; 8]; 5];
    for x in 0..5 {
        for j in 0..8 {
            let mut acc = input[x][j];
            for y in 1..5 {
                acc = c.gate(
                    format!("theta/c/x{x}/byte{j}/step{y}"),
                    "byte_xor",
                    &[],
                    &[acc, input[x + 5 * y][j]],
                    256,
                )?;
            }
            parity[x][j] = acc;
        }
    }
    let mut rotated = [[0usize; 8]; 5];
    for x in 0..5 {
        for j in 0..8 {
            rotated[x][j] = c.gate(
                format!("theta/d/rot/x{x}/byte{j}"),
                "byte_rol",
                &[1],
                &[parity[(x + 1) % 5][j], parity[(x + 1) % 5][(j + 7) % 8]],
                256,
            )?;
        }
    }
    let mut d = [[0usize; 8]; 5];
    for x in 0..5 {
        for j in 0..8 {
            d[x][j] = c.gate(
                format!("theta/d/x{x}/byte{j}"),
                "byte_xor",
                &[],
                &[parity[(x + 4) % 5][j], rotated[x][j]],
                256,
            )?;
        }
    }
    let mut mixed = [[0usize; 8]; 25];
    for l in 0..25 {
        for j in 0..8 {
            mixed[l][j] = c.gate(
                format!("theta/t/l{l}/byte{j}"),
                "byte_xor",
                &[],
                &[input[l][j], d[l % 5][j]],
                256,
            )?;
        }
    }
    let mut b = [[0usize; 8]; 25];
    for l in 0..25 {
        let x = l % 5;
        let y = l / 5;
        let shift = RHO[y][x] as usize;
        let q = shift / 8;
        let bits = shift % 8;
        for j in 0..8 {
            let low = mixed[l][(j + 8 - q) % 8];
            let value = if bits == 0 {
                low
            } else {
                c.gate(
                    format!("rho/l{l}/byte{j}"),
                    "byte_rol",
                    &[bits as i64],
                    &[low, mixed[l][(j + 15 - q) % 8]],
                    256,
                )?
            };
            b[y + 5 * ((2 * x + 3 * y) % 5)][j] = value;
        }
    }
    let mut neg = [[0usize; 8]; 25];
    for l in 0..25 {
        for j in 0..8 {
            neg[l][j] = c.gate(
                format!("chi/not/l{l}/byte{j}"),
                "byte_not",
                &[],
                &[b[(l % 5 + 1) % 5 + 5 * (l / 5)][j]],
                256,
            )?;
        }
    }
    let mut and = [[0usize; 8]; 25];
    for l in 0..25 {
        for j in 0..8 {
            and[l][j] = c.gate(
                format!("chi/and/l{l}/byte{j}"),
                "byte_and",
                &[],
                &[neg[l][j], b[(l % 5 + 2) % 5 + 5 * (l / 5)][j]],
                256,
            )?;
        }
    }
    let mut out = [[0usize; 8]; 25];
    for l in 0..25 {
        for j in 0..8 {
            out[l][j] = c.gate(
                format!("chi/out/l{l}/byte{j}"),
                "byte_xor",
                &[],
                &[b[l][j], and[l][j]],
                256,
            )?;
        }
    }
    for (j, mask) in RC[r].to_le_bytes().iter().enumerate() {
        if *mask != 0 {
            out[0][j] = c.gate(
                format!("iota/byte{j}"),
                "byte_xor_const",
                &[i64::from(*mask)],
                &[out[0][j]],
                256,
            )?;
        }
    }
    c.finish()?;
    let outputs: Vec<_> = out.into_iter().flatten().collect();
    let producers = outputs
        .iter()
        .map(|slot| {
            let ordinal = slot
                .checked_sub(200)
                .ok_or("source output is not fresh SSA")?;
            let leaf = spec
                .leaves
                .get(ordinal)
                .ok_or("source output producer out of bounds")?;
            Ok((ordinal, leaf.wires.len() - 1))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(ChildLayout {
        ports: Ports {
            inputs: input.into_iter().flatten().collect(),
            outputs,
            producers,
        },
    })
}
struct VectorSink {
    hash: sha256::HashEngine,
    bytes: u64,
}
impl Write for VectorSink {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        let next = self
            .bytes
            .checked_add(data.len() as u64)
            .ok_or_else(|| std::io::Error::other("compact execution record size overflow"))?;
        if next > VECTOR_HASH_CAP {
            return Err(std::io::Error::other(
                "compact execution records exceed unchanged128MiB cap",
            ));
        }
        self.hash.input(data);
        self.bytes = next;
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn canonical(value: &Value) -> Result<Vec<u8>> {
    fn write(out: &mut Vec<u8>, value: &Value) -> Result<()> {
        match value {
            Value::Object(map) => {
                out.push(b'{');
                let sorted: BTreeMap<_, _> = map.iter().collect();
                for (i, (key, value)) in sorted.into_iter().enumerate() {
                    if i != 0 {
                        out.push(b',');
                    }
                    serde_json::to_writer(&mut *out, key)?;
                    out.push(b':');
                    write(out, value)?;
                }
                out.push(b'}');
            }
            Value::Array(items) => {
                out.push(b'[');
                for (i, item) in items.iter().enumerate() {
                    if i != 0 {
                        out.push(b',');
                    }
                    write(out, item)?;
                }
                out.push(b']');
            }
            _ => serde_json::to_writer(out, value)?,
        }
        Ok(())
    }
    let mut out = Vec::new();
    write(&mut out, value)?;
    Ok(out)
}
fn domain_hash(domain: &[u8], value: &Value) -> Result<String> {
    let mut h = sha256::Hash::engine();
    h.input(domain);
    h.input(&canonical(value)?);
    Ok(sha256::Hash::from_engine(h).to_string())
}
fn consumers(view: &View) -> Vec<Vec<(usize, usize)>> {
    (0..200)
        .map(|slot| {
            let lane = slot / 8;
            let byte = slot % 8;
            let x = lane % 5;
            let y = lane / 5;
            vec![
                (
                    view.first_leaf + x * 32 + byte * 4 + y.saturating_sub(1),
                    if y == 0 { 0 } else { 1 },
                ),
                (view.first_leaf + 240 + slot, 0),
            ]
        })
        .collect()
}
fn state(value: &str) -> Result<[u8; 200]> {
    if value.len() != 400
        || !value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err("canonical200-byte state hex required".into());
    }
    Ok(hex::decode(value)?
        .try_into()
        .map_err(|_| "state byte count")?)
}
fn reference(input: &[u8; 200], r: usize) -> [u8; 200] {
    let mut a = [0u64; 25];
    for (lane, raw) in a.iter_mut().zip(input.chunks_exact(8)) {
        *lane = u64::from_le_bytes(raw.try_into().unwrap());
    }
    let mut c = [0u64; 5];
    for x in 0..5 {
        c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
    }
    let mut d = [0u64; 5];
    for x in 0..5 {
        d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
    }
    let mut b = [0u64; 25];
    for y in 0..5 {
        for x in 0..5 {
            b[y + 5 * ((2 * x + 3 * y) % 5)] = (a[x + 5 * y] ^ d[x]).rotate_left(RHO[y][x]);
        }
    }
    let mut output = [0u8; 200];
    for y in 0..5 {
        for x in 0..5 {
            let l = x + 5 * y;
            let mut v = b[l] ^ ((!b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y]);
            if l == 0 {
                v ^= RC[r];
            }
            output[8 * l..8 * l + 8].copy_from_slice(&v.to_le_bytes());
        }
    }
    output
}
fn extend_object(target: &mut Value, extra: Value) -> Result<()> {
    let (Value::Object(target), Value::Object(extra)) = (target, extra) else {
        return Err("internal round summary object type".into());
    };
    for (key, value) in extra {
        if target.insert(key, value).is_some() {
            return Err("duplicate round summary field".into());
        }
    }
    Ok(())
}
fn collision_check(
    keys: &[PublicKey],
    signatures: &[Signature],
    all_keys: &mut HashSet<[u8; 32]>,
    all_signatures: &mut HashSet<[u8; 32]>,
) -> Result<()> {
    if keys.len() != signatures.len() {
        return Err("fresh key/signature census mismatch".into());
    }
    for (key, signature) in keys.iter().zip(signatures) {
        let key: Vec<_> = key.iter().flat_map(|p| p.iter().copied()).collect();
        let signature: Vec<_> = signature.iter().flat_map(|p| p.iter().copied()).collect();
        if key.len() != 200
            || signature.len() != 200
            || !all_keys.insert(sha256::Hash::hash(&key).to_byte_array())
            || !all_signatures.insert(sha256::Hash::hash(&signature).to_byte_array())
        {
            return Err("independent test-session WOTS key/signature collision or reuse".into());
        }
    }
    Ok(())
}
fn digest(value: &str) -> Result<[u8; 32]> {
    let raw = id32(value)?;
    if hex::encode(raw) != value {
        return Err("canonical lowercase32 digest required".into());
    }
    Ok(raw)
}
fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 192
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.:/-".contains(&b))
}
fn snapshot(path: &Path, cap: u64, expected: [u8; 32]) -> Result<Vec<u8>> {
    let before = fs::symlink_metadata(path)?;
    if before.file_type().is_symlink() || !before.is_file() || before.len() > cap {
        return Err("bounded regular byte fixture required".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.nlink() != 1 {
            return Err("hard-linked byte fixture forbidden".into());
        }
    }
    let file = File::open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let opened = file.metadata()?;
        if (before.dev(), before.ino(), before.len()) != (opened.dev(), opened.ino(), opened.len())
        {
            return Err("byte fixture changed during open".into());
        }
    }
    let mut raw = Vec::new();
    file.take(cap + 1).read_to_end(&mut raw)?;
    if raw.len() as u64 != before.len()
        || raw.len() as u64 > cap
        || sha256::Hash::hash(&raw).to_byte_array() != expected
    {
        return Err("byte input snapshot length/digest mismatch".into());
    }
    Ok(raw)
}
fn truth(spec: &GraphSpec, values: &[u32], ordinal: usize) -> Result<bool> {
    let leaf = spec.leaves.get(ordinal).ok_or("byte truth ordinal")?;
    // Called only after full catalogue shape validation; WOTS signed-u32 range
    // flags are false claims, unlike bare predicate range VERIFY aborts.
    if leaf
        .wires
        .iter()
        .any(|i| values[*i] >= spec.words[*i].bound)
    {
        return Ok(false);
    }
    let v: Vec<u32> = leaf.wires.iter().map(|i| values[*i]).collect();
    Ok(match leaf.kind.as_str() {
        "byte_xor" | "bool_xor" => v[2] == (v[0] ^ v[1]),
        "byte_and" | "bool_and" => v[2] == (v[0] & v[1]),
        "byte_not" => v[1] == 255 - v[0],
        "bool_not" => v[1] == 1 - v[0],
        "byte_rol" => {
            let r = leaf.argument[0] as u32;
            v[2] == ((v[0] << r) & 255) + (v[1] >> (8 - r))
        }
        "byte_xor_const" => v[1] == (v[0] ^ (leaf.argument[0] as u32)),
        "const" => v[0] as i64 == leaf.argument[0],
        "bits" => v[0] == v[1..].iter().fold(0u32, |a, b| 2 * a + b),
        "conv_reconstruct" => {
            let mut value = 0u32;
            let mut shift = 0;
            for (digit, width) in v[1..].iter().zip(&leaf.argument) {
                value += digit << shift;
                shift += width;
            }
            v[0] == value
        }
        _ => return Err("unsupported byte truth kind".into()),
    })
}
fn seed(expected: &[u8; 32], case: &str, word: &str) -> Vec<u8> {
    let mut h = sha256::Hash::engine();
    h.input(b"BITVM2-NOVA/TEST-ONLY-BYTE-KECCAK-PERMUTATION-WOTS/v1\0");
    h.input(expected);
    for value in [case, word] {
        h.input(&(value.len() as u16).to_le_bytes());
        h.input(value.as_bytes());
    }
    sha256::Hash::from_engine(h).to_byte_array().to_vec()
}
fn changed(value: &str) -> Result<String> {
    let mut raw = digest(value)?;
    raw[0] ^= 1;
    Ok(hex::encode(raw))
}
fn native_negatives(
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

fn auth_shape(spec: &GraphSpec, ordinal: usize) -> (String, Vec<u32>, Vec<usize>) {
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
fn opening(
    registry: &Registry,
    signatures: &[Signature],
    ordinal: usize,
    wire: usize,
) -> Result<Vec<Vec<u8>>> {
    let unique = registry.unique_slots(ordinal)?;
    let position = unique
        .iter()
        .position(|i| *i == wire)
        .ok_or("baseline opening absent")?;
    let witness = registry.witness(ordinal, signatures)?;
    let width = Wots4::TOTAL_DIGIT_LEN as usize;
    Ok(witness
        .get(position * width..(position + 1) * width)
        .ok_or("baseline opening segment bound")?
        .to_vec())
}
fn program_digest(spec: &GraphSpec) -> Result<[u8; 32]> {
    if spec.leaves.len() > 10_000
        || spec.words.len() > 100_000
        || spec.words.iter().any(|w| w.bound != 256)
        || spec
            .leaves
            .iter()
            .any(|l| !BYTE_KINDS.contains(&l.kind.as_str()))
    {
        return Err("actual bounded BYTE Program required".into());
    }
    let modulus = match spec.field_role.as_str() {
        "pallas_scalar" => {
            "28948022309329048855892746252171976963363056481941647379679742748393362948097"
        }
        "vesta_scalar" => {
            "28948022309329048855892746252171976963363056481941560715954676764349967630337"
        }
        _ => return Err("explicit supported scalar field role required".into()),
    };
    let constraints: Vec<_> = spec
        .leaves
        .iter()
        .map(|l| {
            let wires: Vec<_> = l
                .wires
                .iter()
                .map(|i| {
                    spec.words
                        .get(*i)
                        .map(|w| w.name.clone())
                        .ok_or("Program wire index bound")
                })
                .collect::<std::result::Result<_, _>>()?;
            Ok(json!([l.kind, wires, l.argument]))
        })
        .collect::<Result<_>>()?;
    let words: Vec<_> = spec
        .words
        .iter()
        .map(|w| json!([w.name, w.bound]))
        .collect();
    // Explicit BTreeMap ordering matches Python's canonical sort_keys JSON,
    // independently of any serde_json preserve_order feature in dependencies.
    let shape: BTreeMap<String, Value> = [
        ("schema", json!("bitvm2-nova-fixed-trace/v2")),
        ("field_role", json!(spec.field_role)),
        ("modulus", json!(modulus)),
        ("operation_id", json!(spec.operation_id)),
        ("context", json!(spec.context)),
        ("words", json!(words)),
        ("fields", json!([])),
        ("constraints", json!(constraints)),
    ]
    .into_iter()
    .map(|(k, v)| (k.into(), v))
    .collect();
    let base = sha256::Hash::hash(&serde_json::to_vec(&shape)?);
    let mut h = sha256::Hash::engine();
    h.input(b"BITVM2-NOVA/BYTE-TRACE/v1\0");
    h.input(base.as_byte_array());
    Ok(sha256::Hash::from_engine(h).to_byte_array())
}
fn map_hash(map: &[usize]) -> Result<String> {
    Ok(sha256::Hash::hash(&serde_json::to_vec(map)?).to_string())
}
fn state_word(name: &str, round: usize) -> Result<(usize, usize)> {
    let prefix = format!("byte-state/{round}/l");
    let rest = name
        .strip_prefix(&prefix)
        .ok_or("exact state round namespace required")?;
    let (lane, byte) = rest
        .split_once("/byte")
        .ok_or("canonical state lane/byte name required")?;
    let l: usize = lane.parse()?;
    let j: usize = byte.parse()?;
    if l >= 25 || j >= 8 || lane != l.to_string() || byte != j.to_string() {
        return Err("state name alias or bound".into());
    }
    Ok((l, j))
}
fn project(parent: &GraphSpec, d: &SegmentDescriptor, root_op: &str) -> Result<Block> {
    if d.children.len() != 4
        || parent.words.len() != parent.leaves.len() + 200
        || parent.words.iter().any(|w| w.bound != 256)
        || parent
            .leaves
            .iter()
            .any(|l| !BYTE_KINDS.contains(&l.kind.as_str()))
    {
        return Err("exact four-child BYTE parent topology required".into());
    }
    let by_name: HashMap<_, _> = parent
        .words
        .iter()
        .enumerate()
        .map(|(i, w)| (w.name.as_str(), i))
        .collect();
    let mut cursor = 200;
    let mut offset = 0;
    let mut views = Vec::new();
    let mut union = HashSet::new();
    let mut images = Vec::new();
    for i in 0..4 {
        let child = &d.children[i];
        let r = d.start_round + i;
        let masks = RC[r].to_le_bytes();
        let leaves = 1216 + masks.iter().filter(|m| **m != 0).count();
        let operation = format!("{root_op}/child/{i}/round/{r}");
        if child.round != r
            || child.operation_id != operation
            || child.first_leaf != offset
            || child.leaves != leaves
            || child.words != leaves + 200
        {
            return Err("child round/operation/offset/census differs".into());
        }
        let mut map = Vec::new();
        let mut words = Vec::new();
        for l in 0..25 {
            for j in 0..8 {
                let name = format!("byte-state/{r}/l{l}/byte{j}");
                let slot = *by_name
                    .get(name.as_str())
                    .ok_or("missing canonical child state input")?;
                if (i == 0 && slot != 8 * l + j) || (i > 0 && slot >= cursor) {
                    return Err(
                        "child input map violates first-encounter/shared state order".into(),
                    );
                }
                map.push(slot);
                words.push(bitvm2_nova_script_oracle::registry::Word {
                    name: format!("input/l{l}/byte{j}"),
                    bound: 256,
                });
            }
        }
        for slot in cursor..cursor + leaves {
            let word = parent
                .words
                .get(slot)
                .ok_or("missing child fresh SSA span")?;
            let local = if let Some(local) = word.name.strip_prefix(&format!("byte-round/{r}/")) {
                local.to_owned()
            } else {
                let (l, j) = state_word(&word.name, r + 1)?;
                if l == 0 && masks[j] != 0 {
                    format!("iota/byte{j}")
                } else {
                    format!("chi/out/l{l}/byte{j}")
                }
            };
            map.push(slot);
            words.push(bitvm2_nova_script_oracle::registry::Word {
                name: local,
                bound: 256,
            });
        }
        let image: HashSet<_> = map.iter().copied().collect();
        if image.len() != map.len() {
            return Err("child map aliases distinct local words".into());
        }
        let inverse: HashMap<_, _> = map
            .iter()
            .enumerate()
            .map(|(local, parent)| (*parent, local))
            .collect();
        let raw = parent
            .leaves
            .get(offset..offset + leaves)
            .ok_or("missing child leaf span")?;
        let mut child_leaves = Vec::new();
        for leaf in raw {
            let wires = leaf
                .wires
                .iter()
                .map(|w| {
                    inverse
                        .get(w)
                        .copied()
                        .ok_or("child predicate uses a word outside its exact image")
                })
                .collect::<std::result::Result<Vec<_>, _>>()?;
            child_leaves.push(bitvm2_nova_script_oracle::registry::Leaf {
                kind: leaf.kind.clone(),
                argument: leaf.argument.clone(),
                wires,
                body_sha256: leaf.body_sha256.clone(),
            });
        }
        let needed: HashSet<_> = child_leaves
            .iter()
            .map(|l| l.body_sha256.as_str())
            .collect();
        let bodies = parent
            .bodies
            .iter()
            .filter(|(id, _)| needed.contains(id.as_str()))
            .map(|(a, b)| (a.clone(), b.clone()))
            .collect();
        let mut spec = GraphSpec {
            program_sha256: child.program_sha256.clone(),
            context: parent.context.clone(),
            field_role: parent.field_role.clone(),
            operation_id: operation,
            words,
            leaves: child_leaves,
            bodies,
        };
        let actual = program_digest(&spec)?;
        if actual != digest(&child.program_sha256)? {
            return Err("actual canonical child ByteProgram SHA differs".into());
        }
        spec.program_sha256 = hex::encode(actual);
        if spec.identity()? != digest(&child.catalogue_id)?
            || map_hash(&map)? != child.wordmap_sha256
        {
            return Err("child projected catalogue/word-map identity differs".into());
        }
        let layout = byte_layout(&spec, r)?;
        // The parent word names themselves are the exact child global IDs.
        for local in 0..map.len() {
            let expected = if let Some(j) = layout.ports.inputs.iter().position(|w| *w == local) {
                format!("byte-state/{r}/l{}/byte{}", j / 8, j % 8)
            } else if let Some(j) = layout.ports.outputs.iter().position(|w| *w == local) {
                format!("byte-state/{}/l{}/byte{}", r + 1, j / 8, j % 8)
            } else {
                format!("byte-round/{r}/{}", spec.words[local].name)
            };
            if parent.words[map[local]].name != expected {
                return Err("parent/child namespace or natural terminal map differs".into());
            }
        }
        union.extend(map.iter().copied());
        images.push(image);
        views.push(View {
            spec,
            map,
            first_leaf: offset,
            layout,
        });
        cursor += leaves;
        offset += leaves;
    }
    if cursor != parent.words.len()
        || offset != parent.leaves.len()
        || union.len() != parent.words.len()
    {
        return Err("four child maps do not exactly cover parent".into());
    }
    for a in 0..4 {
        for b in a + 1..4 {
            let shared: HashSet<_> = images[a].intersection(&images[b]).copied().collect();
            if b == a + 1 {
                let left: Vec<_> = views[a]
                    .layout
                    .ports
                    .outputs
                    .iter()
                    .map(|i| views[a].map[*i])
                    .collect();
                let right: Vec<_> = views[b]
                    .layout
                    .ports
                    .inputs
                    .iter()
                    .map(|i| views[b].map[*i])
                    .collect();
                if left != right || shared != left.into_iter().collect() || shared.len() != 200 {
                    return Err("adjacent ordered200-word state join differs".into());
                }
            } else if !shared.is_empty() {
                return Err("nonadjacent child images unexpectedly alias".into());
            }
        }
    }
    let inputs = views[0]
        .layout
        .ports
        .inputs
        .iter()
        .map(|i| views[0].map[*i])
        .collect();
    let outputs = views[3]
        .layout
        .ports
        .outputs
        .iter()
        .map(|i| views[3].map[*i])
        .collect();
    Ok(Block {
        views,
        inputs,
        outputs,
    })
}
fn round_source(
    parent: &GraphSpec,
    d: &SegmentDescriptor,
    view: &View,
    index: usize,
    root_op: &str,
) -> Result<(String, String)> {
    let r = d.start_round + index;
    let ids: Vec<_> = view
        .map
        .iter()
        .map(|i| parent.words[*i].name.clone())
        .collect();
    let ids_sha = sha256::Hash::hash(&canonical(&json!(ids))?).to_string();
    let inputs: Vec<_> = view
        .layout
        .ports
        .inputs
        .iter()
        .map(|i| view.spec.words[*i].name.clone())
        .collect();
    let outputs: Vec<_> = view
        .layout
        .ports
        .outputs
        .iter()
        .map(|i| view.spec.words[*i].name.clone())
        .collect();
    let producers: Vec<_> = view.layout.ports.producers.iter().map(|p| p.0).collect();
    let phases = json!({"theta_c":160,"theta_d_rot":40,"theta_d_xor":40,"theta_mix":200,"rho":176,"chi_not":200,"chi_and":200,"chi_xor":200,"iota":RC[r].to_le_bytes().iter().filter(|b|**b!=0).count()});
    let maps = json!({"schema":"bitvm2-nova-byte-keccak-round-maps/v1","round_index":r,
        "input_indices":view.layout.ports.inputs,"output_indices":view.layout.ports.outputs,
        "producer_ordinals":producers,"global_ids":ids,"global_ids_sha256":ids_sha,"phase_counts":phases});
    let mut source = json!({"schema":"bitvm2-nova-byte-keccak-round/v1","round_index":r,"context":parent.context,"role":parent.field_role,
        "operation_id":format!("{root_op}/child/{index}"),"program_operation_id":view.spec.operation_id,
        "program_sha256":view.spec.program_sha256,"catalogue_id":hex::encode(view.spec.identity()?)});
    extend_object(
        &mut source,
        json!({"round_constant_le":hex::encode(RC[r].to_le_bytes()),
        "input_encoding":"25lanes(x+5*y),8bytesLEperlane","output_encoding":"natural terminal Chi/Iota producer words; no copies",
        "inputs":inputs,"outputs":outputs,"source_maps":maps,
        "scope":"one BYTE Keccak round; no sponge, transcript, proof or production assertion"}),
    )?;
    let hash = domain_hash(b"BITVM2-NOVA/BYTE-KECCAK-ROUND/v1\0", &source)?;
    if hash != d.children[index].source_sha256 {
        return Err("independently rebuilt child source manifest SHA differs".into());
    }
    Ok((hash, ids_sha))
}
fn validate_sources(
    parent: &GraphSpec,
    d: &SegmentDescriptor,
    block: &Block,
    root_op: &str,
) -> Result<Value> {
    if program_digest(parent)? != digest(&parent.program_sha256)?
        || parent.program_sha256 != d.program_sha256
        || hex::encode(parent.identity()?) != d.catalogue_id
    {
        return Err("actual canonical parent Program/catalogue SHA differs".into());
    }
    let ids: Vec<_> = parent.words.iter().map(|w| w.name.clone()).collect();
    let ids_sha = sha256::Hash::hash(&canonical(&json!(ids))?).to_string();
    if ids_sha != d.global_ids_sha256 {
        return Err("actual parent global ID list SHA differs".into());
    }
    let mut records = Vec::new();
    for (i, view) in block.views.iter().enumerate() {
        let r = d.start_round + i;
        let (source, global_sha) = round_source(parent, d, view, i, root_op)?;
        let inputs: Vec<_> = view
            .layout
            .ports
            .inputs
            .iter()
            .map(|j| view.map[*j])
            .collect();
        let outputs: Vec<_> = view
            .layout
            .ports
            .outputs
            .iter()
            .map(|j| view.map[*j])
            .collect();
        let producers: Vec<_> = view
            .layout
            .ports
            .producers
            .iter()
            .map(|p| view.first_leaf + p.0)
            .collect();
        let occurrences: Vec<_> = view.layout.ports.producers.iter().map(|p| p.1).collect();
        let mut record = json!({"index":i,"round_index":r,"operation_id":format!("{root_op}/child/{i}"),"program_operation_id":view.spec.operation_id,
            "source_sha256":source,"program_sha256":view.spec.program_sha256,"catalogue_id":hex::encode(view.spec.identity()?),"global_ids_sha256":global_sha});
        extend_object(
            &mut record,
            json!({"word_map":view.map,"leaf_map":(view.first_leaf..view.first_leaf+view.spec.leaves.len()).collect::<Vec<_>>(),
            "input_indices":inputs,"output_indices":outputs,"producer_ordinals":producers,"producer_occurrences":occurrences,
            "input_consumer_occurrences":consumers(view)}),
        )?;
        records.push(record);
    }
    let mut joins = Vec::new();
    for i in 0..3 {
        let left = &block.views[i];
        let right = &block.views[i + 1];
        let indices: Vec<_> = left
            .layout
            .ports
            .outputs
            .iter()
            .map(|j| left.map[*j])
            .collect();
        let words: Vec<_> = indices
            .iter()
            .map(|j| parent.words[*j].name.clone())
            .collect();
        let producers: Vec<_> = left
            .layout
            .ports
            .producers
            .iter()
            .map(|p| left.first_leaf + p.0)
            .collect();
        let occurrences: Vec<_> = left.layout.ports.producers.iter().map(|p| p.1).collect();
        joins.push(json!({"index":i,"state_round":d.start_round+i+1,"words":words,"indices":indices,"producer_ordinals":producers,"producer_occurrences":occurrences,"consumer_occurrences":consumers(right)}));
    }
    let final_view = &block.views[3];
    let producers: Vec<_> = final_view
        .layout
        .ports
        .producers
        .iter()
        .map(|p| final_view.first_leaf + p.0)
        .collect();
    let occurrences: Vec<_> = final_view
        .layout
        .ports
        .producers
        .iter()
        .map(|p| p.1)
        .collect();
    let maps = json!({"schema":"bitvm2-nova-byte-keccak-block-maps/v1","first_round":d.start_round,"children":records,
        "input_indices":block.inputs,"output_indices":block.outputs,"producer_ordinals":producers,"producer_occurrences":occurrences,
        "global_ids":ids,"global_ids_sha256":ids_sha,"joins":joins});
    let input_names: Vec<_> = block
        .inputs
        .iter()
        .map(|j| parent.words[*j].name.clone())
        .collect();
    let output_names: Vec<_> = block
        .outputs
        .iter()
        .map(|j| parent.words[*j].name.clone())
        .collect();
    let mut manifest = json!({"schema":"bitvm2-nova-byte-keccak-block/v1","first_round":d.start_round,"last_round":d.start_round+3,
        "context":parent.context,"role":parent.field_role,"operation_id":root_op,
        "program_operation_id":parent.operation_id,"program_sha256":parent.program_sha256,"catalogue_id":hex::encode(parent.identity()?)});
    extend_object(
        &mut manifest,
        json!({"inputs":input_names,"outputs":output_names,"source_maps":maps,
        "commitment_order":"external context -> source topology -> keys -> registry -> Script",
        "scope":"four consecutive BYTE rounds only; no full permutation, sponge, transcript or proof"}),
    )?;
    if domain_hash(b"BITVM2-NOVA/BYTE-KECCAK-BLOCK/v1\0", &manifest)? != d.source_sha256 {
        return Err("independently rebuilt block source/map/join manifest SHA differs".into());
    }
    Ok(maps)
}
fn validate_maps(parent: &GraphSpec, block: &Block, start: usize) -> Result<()> {
    if block.views.len() != 4 {
        return Err("exact four private child views required".into());
    }
    let mut images = Vec::new();
    let mut union = HashSet::new();
    let mut order = Vec::new();
    for (i, view) in block.views.iter().enumerate() {
        let r = start + i;
        if view.map.len() != view.spec.words.len()
            || view.map.iter().collect::<HashSet<_>>().len() != view.map.len()
        {
            return Err("child map shape/injection changed".into());
        }
        for (local, index) in view.map.iter().enumerate() {
            let actual = parent
                .words
                .get(*index)
                .ok_or("child map index outside parent")?;
            let expected =
                if let Some(j) = view.layout.ports.inputs.iter().position(|w| *w == local) {
                    format!("byte-state/{r}/l{}/byte{}", j / 8, j % 8)
                } else if let Some(j) = view.layout.ports.outputs.iter().position(|w| *w == local) {
                    format!("byte-state/{}/l{}/byte{}", r + 1, j / 8, j % 8)
                } else {
                    format!("byte-round/{r}/{}", view.spec.words[local].name)
                };
            if actual.name != expected || actual.bound != view.spec.words[local].bound {
                return Err("child map name/round/decoder bound differs".into());
            }
            if union.insert(*index) {
                order.push(*index);
            }
        }
        for (ordinal, leaf) in view.spec.leaves.iter().enumerate() {
            let actual = parent
                .leaves
                .get(view.first_leaf + ordinal)
                .ok_or("child leaf offset outside parent")?;
            let wires = leaf
                .wires
                .iter()
                .map(|j| {
                    view.map
                        .get(*j)
                        .copied()
                        .ok_or("child formal wire map bound")
                })
                .collect::<std::result::Result<Vec<_>, _>>()?;
            if actual.kind != leaf.kind
                || actual.argument != leaf.argument
                || actual.wires != wires
                || actual.body_sha256 != leaf.body_sha256
                || parent.bodies.get(&actual.body_sha256) != view.spec.bodies.get(&leaf.body_sha256)
            {
                return Err("child predicate/body/alias projection differs".into());
            }
        }
        images.push(view.map.iter().copied().collect::<HashSet<_>>());
    }
    if order != (0..parent.words.len()).collect::<Vec<_>>() || union.len() != parent.words.len() {
        return Err("child first-encounter/full-union map differs".into());
    }
    for i in 0..4 {
        for j in i + 1..4 {
            let actual: HashSet<_> = images[i].intersection(&images[j]).copied().collect();
            if j == i + 1 {
                let left: Vec<_> = block.views[i]
                    .layout
                    .ports
                    .outputs
                    .iter()
                    .map(|w| block.views[i].map[*w])
                    .collect();
                let right: Vec<_> = block.views[j]
                    .layout
                    .ports
                    .inputs
                    .iter()
                    .map(|w| block.views[j].map[*w])
                    .collect();
                if left != right || actual != left.into_iter().collect() || actual.len() != 200 {
                    return Err("child join intersection/order changed".into());
                }
            } else if !actual.is_empty() {
                return Err("nonadjacent child maps share a word".into());
            }
        }
    }
    Ok(())
}
