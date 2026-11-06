//! Hosted TEST-ONLY four-round BYTE Keccak blocks in one parent registry.
//! Fresh input bytes are pinned out of band. No raw vectors, proofs, transaction
//! constructors, production keys, panic catcher or acceptance receipts.
use bitcoin::{
    hashes::{sha256, Hash, HashEngine},
    ScriptBuf,
};
use bitvm::signatures::{CompactWots, Wots, Wots4};
use bitvm2_nova_script_oracle::{
    engine::{execute, Metrics},
    registry::{GraphSpec, Registry, Signature},
    wots::{id32, PublicKey, Result},
};
use serde::Deserialize;
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
    start_round: usize,
    boundary_index: Option<usize>,
    byte_slot: Option<usize>,
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
    expected_terminal_state_hex: String,
    expected_false: Vec<usize>,
    children: Vec<ChildDescriptor>,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
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
    input_state_hex: String,
    output_state_hex: String,
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
fn project(parent: &GraphSpec, d: &Descriptor, root_op: &str) -> Result<Block> {
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
        let operation = format!("{root_op}/s{}/child/{i}/round/{r}", d.start_round);
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
fn round_source(
    parent: &GraphSpec,
    d: &Descriptor,
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
        "operation_id":format!("{root_op}/s{}/child/{index}",d.start_round),"program_operation_id":view.spec.operation_id,
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
    d: &Descriptor,
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
        let mut record = json!({"index":i,"round_index":r,"operation_id":format!("{root_op}/s{}/child/{i}",d.start_round),"program_operation_id":view.spec.operation_id,
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
        "context":parent.context,"role":parent.field_role,"operation_id":format!("{root_op}/s{}",d.start_round),
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
fn map_negatives(parent: &GraphSpec, block: &Block, start: usize) -> Result<usize> {
    let mut variants = Vec::new();
    let mut x = block.clone();
    x.views[1].map[0] = x.views[1].map[1];
    variants.push(x);
    let mut x = block.clone();
    x.views[1].map.swap(0, 1);
    variants.push(x);
    let mut x = block.clone();
    x.views[1].map[200] = x.views[1].map[0];
    variants.push(x);
    let mut x = block.clone();
    x.views[1].map[0] = parent.words.len();
    variants.push(x);
    let mut x = block.clone();
    x.views[2].map[0] = x.views[0].map[0];
    variants.push(x);
    let mut x = block.clone();
    x.views[1].map.pop();
    variants.push(x);
    let mut x = block.clone();
    x.views.swap(0, 1);
    variants.push(x);
    let mut x = block.clone();
    x.views.pop();
    variants.push(x);
    for other in &variants {
        if validate_maps(parent, other, start).is_ok() {
            return Err("substituted private child map accepted".into());
        }
    }
    Ok(variants.len())
}
fn source_negatives(parent: &GraphSpec, d: &Descriptor, root_op: &str) -> Result<usize> {
    let mut variants = Vec::new();
    let mut x = d.clone();
    x.children[0].round += 1;
    variants.push(x);
    let mut x = d.clone();
    x.children[1].operation_id = x.children[0].operation_id.clone();
    variants.push(x);
    let mut x = d.clone();
    x.children[1].program_sha256 = changed(&x.children[1].program_sha256)?;
    variants.push(x);
    let mut x = d.clone();
    x.children[1].catalogue_id = changed(&x.children[1].catalogue_id)?;
    variants.push(x);
    let mut x = d.clone();
    x.children[1].wordmap_sha256 = changed(&x.children[1].wordmap_sha256)?;
    variants.push(x);
    let mut x = d.clone();
    x.children[1].source_sha256 = changed(&x.children[1].source_sha256)?;
    variants.push(x);
    let mut x = d.clone();
    x.children.swap(0, 1);
    variants.push(x);
    let mut x = d.clone();
    x.children[1].first_leaf += 1;
    variants.push(x);
    let mut x = d.clone();
    x.children[1].words += 1;
    variants.push(x);
    let mut x = d.clone();
    x.source_sha256 = changed(&x.source_sha256)?;
    variants.push(x);
    let mut x = d.clone();
    x.global_ids_sha256 = changed(&x.global_ids_sha256)?;
    variants.push(x);
    let mut x = d.clone();
    x.program_sha256 = changed(&x.program_sha256)?;
    variants.push(x);
    for other in &variants {
        let rejected = match project(parent, other, root_op) {
            Err(_) => true,
            Ok(block) => validate_sources(parent, other, &block, root_op).is_err(),
        };
        if !rejected {
            return Err("substituted child/round/program/source identity accepted".into());
        }
    }
    Ok(variants.len())
}
fn validate_manifest(manifest: &Manifest) -> Result<()> {
    if manifest.schema != "bitvm2-nova-byte-keccak-block-run/v1"
        || !identifier(&manifest.operation_id)
        || manifest.cases.len() != 32
    {
        return Err("exact32-case block manifest required".into());
    }
    digest(&manifest.context)?;
    let mut names = HashSet::new();
    let mut coverage = HashSet::new();
    for (index, d) in manifest.cases.iter().enumerate() {
        if !["pallas_scalar", "vesta_scalar"].contains(&d.role.as_str())
            || d.start_round > 20
            || d.filename != format!("case-{index:02}.json")
            || d.file_bytes == 0
            || d.file_bytes > INPUT_CAP
            || d.children.len() != 4
            || !names.insert(d.name.as_str())
            || !coverage.insert((
                d.role.as_str(),
                d.start_round,
                d.profile.as_str(),
                d.boundary_index,
            ))
        {
            return Err("block case identity/role/round/filename/census differs".into());
        }
        let suffix = match d.profile.as_str() {
            "honest"
                if [0, 4, 8, 12, 16, 20].contains(&d.start_round)
                    && d.boundary_index.is_none()
                    && d.byte_slot.is_none() =>
            {
                "honest".to_owned()
            }
            "oversized"
                if [0, 20].contains(&d.start_round)
                    && d.boundary_index.is_none()
                    && d.byte_slot.is_none() =>
            {
                "oversized".to_owned()
            }
            "middle-chi" | "middle-iota"
                if d.start_round == 0
                    && d.boundary_index.is_some_and(|i| i < 3)
                    && d.byte_slot == Some(if d.profile == "middle-chi" { 8 } else { 0 }) =>
            {
                format!(
                    "middle-j{}-{}",
                    d.boundary_index.unwrap() + 1,
                    if d.profile == "middle-chi" {
                        "chi"
                    } else {
                        "iota"
                    }
                )
            }
            "final-chi" | "final-iota"
                if d.start_round == 20
                    && d.boundary_index.is_none()
                    && d.byte_slot == Some(if d.profile == "final-chi" { 8 } else { 0 }) =>
            {
                format!(
                    "final-{}",
                    if d.profile == "final-chi" {
                        "chi"
                    } else {
                        "iota"
                    }
                )
            }
            _ => return Err("unsupported exact block diagnostic profile".into()),
        };
        let leaves = (d.start_round..d.start_round + 4)
            .map(|r| 1216 + RC[r].to_le_bytes().iter().filter(|b| **b != 0).count())
            .sum::<usize>();
        if d.name != format!("{}/block-s{}-{suffix}", d.role, d.start_round)
            || d.leaves != leaves
            || d.words != leaves + 200
        {
            return Err("block name/complete Program census differs".into());
        }
        for value in [
            &d.file_sha256,
            &d.catalogue_id,
            &d.program_sha256,
            &d.source_sha256,
            &d.global_ids_sha256,
        ] {
            digest(value)?;
        }
        state(&d.input_state_hex)?;
        state(&d.expected_terminal_state_hex)?;
        for child in &d.children {
            for value in [
                &child.program_sha256,
                &child.catalogue_id,
                &child.source_sha256,
                &child.wordmap_sha256,
            ] {
                digest(value)?;
            }
            state(&child.input_state_hex)?;
            state(&child.output_state_hex)?;
        }
    }
    for role in ["pallas_scalar", "vesta_scalar"] {
        for start in [0, 4, 8, 12, 16, 20] {
            if !coverage.contains(&(role, start, "honest", None)) {
                return Err("six aligned honest blocks for both roles required".into());
            }
        }
        for boundary in 0..3 {
            for profile in ["middle-chi", "middle-iota"] {
                if !coverage.contains(&(role, 0, profile, Some(boundary))) {
                    return Err("all three coherent Chi/Iota joins required".into());
                }
            }
        }
        for profile in ["final-chi", "final-iota"] {
            if !coverage.contains(&(role, 20, profile, None)) {
                return Err("both final output producers required".into());
            }
        }
        for start in [0, 20] {
            if !coverage.contains(&(role, start, "oversized", None)) {
                return Err("both signed oversized initial input profiles required".into());
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
        || case.spec.operation_id
            != format!(
                "{}/s{}/rounds/{}-{}",
                manifest.operation_id,
                d.start_round,
                d.start_round,
                d.start_round + 3
            )
        || case.spec.words.len() != d.words
        || case.words.len() != d.words
        || case.spec.leaves.len() != d.leaves
        || case.checks.len() != d.leaves
        || case.checks.iter().enumerate().any(|(i, c)| c.ordinal != i)
        || case.spec.identity()? != digest(&d.catalogue_id)?
    {
        return Err("parent source differs from exact trusted block descriptor".into());
    }
    Ok(())
}
fn assignment(case: &Case, d: &Descriptor, block: &Block) -> Result<(Vec<usize>, Vec<Vec<usize>>)> {
    let initial: Vec<_> = (0..200)
        .map(|i| ((37 * i + 11 + 17 * d.start_round) & 255) as u8)
        .collect();
    let mut current: [u8; 200] = initial
        .try_into()
        .map_err(|_| "fixed initial state length")?;
    if state(&d.input_state_hex)? != current {
        return Err("block initial reference state differs".into());
    }
    for (i, view) in block.views.iter().enumerate() {
        let child = &d.children[i];
        if state(&child.input_state_hex)? != current {
            return Err("child input is not the actual preceding claimed boundary".into());
        }
        for j in 0..200 {
            let slot = view.map[view.layout.ports.inputs[j]];
            let expected = if d.profile == "oversized" && i == 0 && j == 0 {
                u32::MAX
            } else {
                u32::from(current[j])
            };
            if case.words[slot] != expected {
                return Err("actual signed child input differs from coherent pipeline".into());
            }
        }
        let mut output = reference(&current, d.start_round + i);
        if (d.profile.starts_with("middle-") && d.boundary_index == Some(i))
            || (d.profile.starts_with("final-") && i == 3)
        {
            output[d.byte_slot.ok_or("diagnostic byte slot missing")?] ^= 1;
        }
        if state(&child.output_state_hex)? != output {
            return Err("child word reference/controlled producer claim differs".into());
        }
        for j in 0..200 {
            if case.words[view.map[view.layout.ports.outputs[j]]] != u32::from(output[j]) {
                return Err("actual signed child output differs from controlled reference".into());
            }
        }
        current = output;
    }
    if state(&d.expected_terminal_state_hex)? != current {
        return Err("actual final terminal state differs".into());
    }
    for (i, (word, value)) in case.spec.words.iter().zip(&case.words).enumerate() {
        if *value >= word.bound
            && !(d.profile == "oversized" && i == block.inputs[0] && *value == u32::MAX)
        {
            return Err("unexpected out-of-bound parent assertion word".into());
        }
    }
    let mut false_rows = Vec::new();
    for check in &case.checks {
        let actual = truth(&case.spec, &case.words, check.ordinal)?;
        if actual != check.expected_correct {
            return Err(
                "parent expectation differs from independent integer predicate truth".into(),
            );
        }
        if !actual {
            false_rows.push(check.ordinal);
        }
    }
    let expected = if d.profile.starts_with("middle-") {
        let view = &block.views[d.boundary_index.ok_or("missing coherent join")?];
        vec![
            view.first_leaf
                + view.layout.ports.producers[d.byte_slot.ok_or("missing fault byte")?].0,
        ]
    } else if d.profile.starts_with("final-") {
        let view = &block.views[3];
        vec![
            view.first_leaf
                + view.layout.ports.producers[d.byte_slot.ok_or("missing fault byte")?].0,
        ]
    } else if d.profile == "oversized" {
        case.spec
            .leaves
            .iter()
            .enumerate()
            .filter(|(_, l)| l.wires.contains(&block.inputs[0]))
            .map(|(i, _)| i)
            .collect::<Vec<_>>()
    } else {
        vec![]
    };
    if false_rows != expected || false_rows != d.expected_false {
        return Err("exact origin-producer/decoder-fault profile differs".into());
    }
    let child_false = block
        .views
        .iter()
        .map(|view| {
            false_rows
                .iter()
                .filter(|i| {
                    **i >= view.first_leaf && **i < view.first_leaf + view.spec.leaves.len()
                })
                .map(|i| i - view.first_leaf)
                .collect::<Vec<_>>()
        })
        .collect();
    Ok((false_rows, child_false))
}
#[derive(Clone)]
struct Cached {
    join: usize,
    slot: usize,
    word: usize,
    name: String,
    producer: (usize, usize),
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
    block: &Block,
) -> Result<Vec<Vec<Cached>>> {
    let mut result = Vec::new();
    for join in 0..3 {
        let left = &block.views[join];
        let mut entries = Vec::new();
        for slot in 0..200 {
            let local = left.layout.ports.outputs[slot];
            let word = left.map[local];
            let (ordinal, formal) = left.layout.ports.producers[slot];
            let producer = (left.first_leaf + ordinal, formal);
            if registry
                .spec()
                .leaves
                .get(producer.0)
                .and_then(|l| l.wires.get(producer.1))
                != Some(&word)
            {
                return Err("cached origin does not match actual parent producer operand".into());
            }
            let declared = registry
                .spec()
                .words
                .get(word)
                .ok_or("boundary word out of parent bounds")?;
            entries.push(Cached {
                join,
                slot,
                word,
                name: declared.name.clone(),
                producer,
                value: *values.get(word).ok_or("boundary value bound")?,
                bound: declared.bound,
                key: *keys.get(word).ok_or("boundary public-key bound")?,
                signature: *signatures.get(word).ok_or("boundary signature bound")?,
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
    block: &Block,
    cached: &[Vec<Cached>],
) -> Result<Vec<Value>> {
    if cached.len() != 3 || cached.iter().any(|v| v.len() != 200) {
        return Err("three exact200-entry source boundary caches required".into());
    }
    let spec = registry.spec();
    let mut rows = Vec::new();
    for join in 0..3 {
        let left = &block.views[join];
        let right = &block.views[join + 1];
        let uses = consumers(right);
        let mut links = 0;
        for slot in 0..200 {
            let entry = &cached[join][slot];
            let word = left.map[left.layout.ports.outputs[slot]];
            let right_word = right.map[right.layout.ports.inputs[slot]];
            let expected = (
                left.first_leaf + left.layout.ports.producers[slot].0,
                left.layout.ports.producers[slot].1,
            );
            let declared = spec.words.get(word).ok_or("actual join word bound")?;
            if word != right_word
                || entry.join != join
                || entry.slot != slot
                || entry.word != word
                || entry.name != declared.name
                || entry.producer != expected
                || entry.value != *values.get(word).ok_or("join value bound")?
                || entry.bound != 256
                || entry.bound != declared.bound
                || entry.key != *keys.get(word).ok_or("join key bound")?
                || entry.signature != *signatures.get(word).ok_or("join signature bound")?
                || spec
                    .leaves
                    .get(expected.0)
                    .and_then(|l| l.wires.get(expected.1))
                    != Some(&word)
                || entry.opening != opening(registry, signatures, expected.0, word)?
            {
                return Err(
                    "original boundary source identity/value/bound/key/signature/opening changed"
                        .into(),
                );
            }
            // The next child's view must recover exactly these same parent
            // values/keys/signatures. No child registry or re-signing exists.
            if values[right_word] != entry.value
                || spec.words[right_word].bound != entry.bound
                || keys[right_word] != entry.key
                || signatures[right_word] != entry.signature
            {
                return Err("child input view changed original signed source assertion".into());
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
                    return Err(
                        "actual next-round C/Theta consumer opening differs from source producer"
                            .into(),
                    );
                }
                links += 1;
            }
        }
        if links != 400 {
            return Err("two actual consumer openings for each200 state bytes required".into());
        }
        rows.push(json!({"index":join,"state_round":left.spec.operation_id.rsplit('/').next().ok_or("round source operation suffix")?.parse::<usize>()?+1,"cached_entries":200,"producer_consumer_opening_links":links}));
    }
    Ok(rows)
}
fn cache_negatives(
    registry: &Registry,
    keys: &[PublicKey],
    signatures: &[Signature],
    values: &[u32],
    block: &Block,
    cached: &[Vec<Cached>],
) -> Result<usize> {
    let mut count = 0;
    for join in 0..3 {
        for mutation in 0..6 {
            let mut bad = cached.to_vec();
            match mutation {
                0 => bad[join][0].value ^= 1,
                1 => bad[join][0].bound = 2,
                2 => bad[join][0].key = bad[join][1].key,
                3 => bad[join][0].signature = bad[join][1].signature,
                4 => {
                    *bad[join][0]
                        .opening
                        .first_mut()
                        .and_then(|p| p.first_mut())
                        .ok_or("empty original opening")? ^= 1
                }
                _ => bad[join][0] = bad[(join + 1) % 3][0].clone(),
            }
            if verify_cache(registry, keys, signatures, values, block, &bad).is_ok() {
                return Err("altered/swapped actual boundary source cache accepted".into());
            }
            count += 1;
        }
    }
    Ok(count)
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
    let raw = snapshot(&root.join(&d.filename), INPUT_CAP, digest(&d.file_sha256)?)?;
    if raw.len() as u64 != d.file_bytes {
        return Err("parent exact input byte length differs".into());
    }
    let case: Case = serde_json::from_slice(&raw)?;
    drop(raw);
    validate_case(&case, manifest, d)?;
    let block = project(&case.spec, d, &manifest.operation_id)?;
    validate_maps(&case.spec, &block, d.start_round)?;
    validate_sources(&case.spec, d, &block, &manifest.operation_id)?;
    let map_rejections = map_negatives(&case.spec, &block, d.start_round)?;
    let source_rejections = source_negatives(&case.spec, d, &manifest.operation_id)?;
    let (false_rows, child_false) = assignment(&case, d, &block)?;
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
        json!({"source_sha256":d.source_sha256,"global_ids_sha256":d.global_ids_sha256}),
    )?;
    let guard_vectors = guards(&registry, &signatures, sink, metrics, &case.name)?;
    // Every producer and both actual consumers have now executed in both modes.
    // Cache only their original parent-registry openings, never child receipts.
    let cache = make_cache(&registry, &keys, &signatures, &case.words, &block)?;
    let joins = verify_cache(&registry, &keys, &signatures, &case.words, &block, &cache)?;
    let cache_rejections =
        cache_negatives(&registry, &keys, &signatures, &case.words, &block, &cache)?;
    if native_rejections != 24
        || map_rejections != 8
        || source_rejections != 12
        || cache_rejections != 18
        || joins.len() != 3
    {
        return Err("exact parent admission/map/source/cache rejection census differs".into());
    }
    let mut children = Vec::new();
    for (i, view) in block.views.iter().enumerate() {
        children.push(json!({"round":d.start_round+i,"operation_id":view.spec.operation_id,"program_sha256":view.spec.program_sha256,"catalogue_id":hex::encode(view.spec.identity()?),"source_sha256":d.children[i].source_sha256,"wordmap_sha256":map_hash(&view.map)?,"words":view.spec.words.len(),"leaves":view.spec.leaves.len(),"first_leaf":view.first_leaf}));
    }
    let mut row = json!({"name":d.name,"profile":d.profile,"role":d.role,"start_round":d.start_round,
        "boundary_index":d.boundary_index,"byte_slot":d.byte_slot,"parent":parent,"children":children,
        "false_predicates":false_rows,"child_false_predicates":child_false,"joins":joins});
    extend_object(
        &mut row,
        json!({"cached_boundary_entries":600,"producer_consumer_opening_links":1200,
        "signature_entries_created":case.words.len(),"child_declared_word_occurrences":case.words.len()+600,
        "guard_layouts":guard_vectors/14,"guard_vectors":guard_vectors,"native_rejections":native_rejections,
        "map_rejections":map_rejections,"source_rejections":source_rejections,"cache_rejections":cache_rejections,
        "wall_seconds":started.elapsed().as_secs_f64()}),
    )?;
    Ok(row)
}
fn run() -> Result<Value> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 5 {
        return Err(
            "usage: byte_keccak_block MANIFEST CASE_DIR OUTPUT EXPECTED_MANIFEST_SHA256".into(),
        );
    }
    if std::env::var("GITHUB_ACTIONS").as_deref() != Ok("true")
        || std::env::var("RUNNER_OS").as_deref() != Ok("Linux")
        || !cfg!(target_os = "linux")
    {
        return Err("four-round BYTE block execution is hosted GitHub Linux only".into());
    }
    let started = Instant::now();
    let expected = digest(&args[4])?;
    let raw = snapshot(Path::new(&args[1]), MANIFEST_CAP, expected)?;
    let manifest: Manifest = serde_json::from_slice(&raw)?;
    drop(raw);
    validate_manifest(&manifest)?;
    let source = Path::new(&args[2]);
    if fs::symlink_metadata(source)?.file_type().is_symlink() {
        return Err("block fixture directory symlink forbidden".into());
    }
    let root = fs::canonicalize(source)?;
    if !root.is_dir() || fs::canonicalize(&args[1])? != root.join("manifest.json") {
        return Err("exact canonical block manifest/directory required".into());
    }
    let mut inventory = HashSet::from(["manifest.json".to_owned()]);
    for d in &manifest.cases {
        inventory.insert(d.filename.clone());
    }
    let actual: HashSet<_> = fs::read_dir(&root)?
        .map(|e| e.map(|e| e.file_name().to_string_lossy().into_owned()))
        .collect::<std::io::Result<_>>()?;
    if actual != inventory {
        return Err("block fixture directory must contain exactly33trustedfiles".into());
    }
    let mut sink = VectorSink {
        hash: sha256::Hash::engine(),
        bytes: 0,
    };
    let mut metrics = Metrics::default();
    let mut rows = Vec::new();
    let mut keys = HashSet::new();
    let mut signatures = HashSet::new();
    let mut declared = 0usize;
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
        declared += d.words + 600;
    }
    if keys.len() != signatures.len() {
        return Err("one signature/key per actual parent word required".into());
    }
    let mut result = json!({"schema":"bitvm2-nova-byte-keccak-block-execution/v1","passed":true,
        "input_manifest_sha256":hex::encode(expected),"metrics":metrics,"cases":rows,
        "compact_execution_records_bytes":sink.bytes,"compact_execution_records_sha256":sha256::Hash::from_engine(sink.hash).to_string(),
        "signature_entries_created":keys.len(),"child_declared_word_occurrences":declared,
        "cached_boundary_entries":32*600,"producer_consumer_opening_links":32*1200});
    extend_object(
        &mut result,
        json!({"four_round_block_script_conformance_checked":true,"all_parent_leaves_executed":true,
        "boundary_opening_links_checked":true,"children_projected_from_parent":true,"test_keys_only":true,"stack_limit_enabled":true,
        "raw_vector_file_written":false,"op_cat_enabled":false,"full_24_round_composition_verified":false,"cross_block_linking_verified":false}),
    )?;
    extend_object(
        &mut result,
        json!({"full_permutation_verified":false,"full_hash_verified":false,"transcript_verified":false,
        "proof_verified":false,"complete_nova_verifier":false,"complete_bitvm2_verifier":false,
        "production_assertion_binding":false,"bitcoin_transaction_graph":false,"panic_is_rejection":false}),
    )?;
    extend_object(
        &mut result,
        json!({"setup_calls":0,"proving_jobs":0,"native_proofs_verified":0,"gpu_jobs":0,
        "transactions_broadcast":0,"wall_seconds":started.elapsed().as_secs_f64()}),
    )?;
    let raw = serde_json::to_vec(&result)?;
    if raw.len() > SUMMARY_CAP {
        return Err("block native summary exceeds unchanged1MiB cap".into());
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
    // Three-word digest/admission stubs only. OP_TRUE is never executed and
    // these metadata fixtures make no byte arithmetic or cryptographic claim.
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
    fn canonical_actual_program_digest_matches_independent_python_goldens() {
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
    fn canonical_source_json_sorts_nested_objects_without_reordering_arrays() {
        let raw = canonical(&json!({"z":{"b":2,"a":1},"a":[{"y":4,"x":3},false,null]})).unwrap();
        assert_eq!(
            String::from_utf8(raw).unwrap(),
            r#"{"a":[{"x":3,"y":4},false,null],"z":{"a":1,"b":2}}"#
        );
    }
    #[test]
    fn actual_program_digest_binds_context_operation_role_order_and_parameters() {
        let original = tiny("pallas_scalar");
        let id = program_digest(&original).unwrap();
        let mut bad = original.clone();
        bad.context = "01".repeat(32);
        assert_ne!(program_digest(&bad).unwrap(), id);
        let mut bad = original.clone();
        bad.operation_id.push_str("/other");
        assert_ne!(program_digest(&bad).unwrap(), id);
        let mut bad = original.clone();
        bad.field_role = "vesta_scalar".into();
        assert_ne!(program_digest(&bad).unwrap(), id);
        let mut bad = original.clone();
        bad.leaves[0].wires.swap(0, 1);
        assert_ne!(program_digest(&bad).unwrap(), id);
        let mut bad = original;
        bad.leaves[0].kind = "byte_rol".into();
        bad.leaves[0].argument = vec![1];
        assert_ne!(program_digest(&bad).unwrap(), id);
    }
    #[test]
    fn repeated_round_constants_do_not_remove_absolute_program_identity() {
        assert_eq!(RC[5], RC[22]);
        let mut left = tiny("pallas_scalar");
        left.operation_id = "test/caller/round/5".into();
        let mut right = left.clone();
        right.operation_id = "test/caller/round/22".into();
        assert_ne!(
            program_digest(&left).unwrap(),
            program_digest(&right).unwrap()
        );
    }
    #[test]
    fn strict_integer_and_duplicate_json_fields_are_rejected() {
        for raw in [
            r#"{"ordinal":0,"ordinal":1,"expected_correct":true}"#,
            r#"{"ordinal":0.0,"expected_correct":true}"#,
            r#"{"ordinal":false,"expected_correct":true}"#,
            r#"{"ordinal":-1,"expected_correct":true}"#,
            r#"{"ordinal":0,"expected_correct":true,"extra":0}"#,
        ] {
            assert!(serde_json::from_str::<Check>(raw).is_err());
        }
    }
    #[test]
    fn malformed_maps_and_noncanonical_transport_fail_before_indexing() {
        let block = Block {
            views: vec![],
            inputs: vec![],
            outputs: vec![],
        };
        assert!(validate_maps(&tiny("pallas_scalar"), &block, 0).is_err());
        assert!(digest(&"AA".repeat(32)).is_err());
        assert!(state(&"00".repeat(199)).is_err());
        for name in [
            "byte-state/0/l00/byte0",
            "byte-state/1/l0/byte0",
            "byte-state/0/l25/byte0",
            "byte-state/0/l0/byte8",
        ] {
            assert!(state_word(name, 0).is_err());
        }
    }
    #[test]
    fn each_state_byte_has_exact_c_and_theta_formal_consumers() {
        let view = View {
            spec: tiny("pallas_scalar"),
            map: vec![],
            first_leaf: 17,
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
        assert_eq!(actual[0], vec![(17, 0), (257, 0)]);
        assert_eq!(actual[40], vec![(17, 1), (297, 0)]);
        assert_eq!(actual[80], vec![(18, 1), (337, 0)]);
        assert_eq!(actual[199], vec![(176, 1), (456, 0)]);
        assert!(actual
            .iter()
            .all(|uses| uses.len() == 2 && uses[0] != uses[1]));
    }
    #[test]
    fn zero_state_round_reference_contains_only_the_round_constant() {
        for r in [0, 1, 2, 23] {
            let actual = reference(&[0; 200], r);
            assert_eq!(&actual[..8], &RC[r].to_le_bytes());
            assert!(actual[8..].iter().all(|b| *b == 0));
        }
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
fn record(
    sink: &mut VectorSink,
    metrics: &mut Metrics,
    code: &ScriptBuf,
    witness: &[Vec<u8>],
    expected: bool,
    label: &str,
) -> Result<()> {
    let (success, stack) = execute(code, witness.to_vec())?;
    if success != expected {
        return Err(format!("{label}: expected{expected}, got{success}").into());
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
        &json!({"label":label,"script_sha256":sha256::Hash::hash(code.as_bytes()).to_string(),"witness_sha256":sha256::Hash::from_engine(h).to_string(),"expected_success":expected}),
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
    let mut sum = 0u64;
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
                &format!("{}/leaf/{}/{disprove}", case.name, check.ordinal),
            )?;
            if disprove {
                sum += code.len() as u64;
                largest = largest.max(code.len());
                stream.input(&(code.len() as u32).to_le_bytes());
                stream.input(code.as_bytes());
            }
        }
    }
    if sum > 1 << 28 {
        return Err("compiled source/probe exceeds existing256MiB component cap".into());
    }
    Ok(
        json!({"catalogue_id":case.expected_spec_id,"program_sha256":case.spec.program_sha256,"context":case.spec.context,"registry_id":hex::encode(registry.identity()),"words":case.spec.words.len(),"leaves":case.spec.leaves.len(),"executed_leaves":case.checks.len(),"compiled_script_bytes":sum,"largest_disproof_leaf_bytes":largest,"compiled_stream_sha256":sha256::Hash::from_engine(stream).to_string()}),
    )
}
fn guards(
    registry: &Registry,
    signatures: &[Signature],
    sink: &mut VectorSink,
    metrics: &mut Metrics,
    label: &str,
) -> Result<usize> {
    let mut seen = HashSet::new();
    let mut count = 0;
    for ordinal in 0..registry.spec().leaves.len() {
        if !seen.insert(auth_shape(registry.spec(), ordinal)) {
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
                    &format!("{label}/length/{ordinal}/{i}/{disprove}"),
                )?;
            }
            for position in [0, witness.len() - 1] {
                let mut bad = witness.clone();
                *bad[position]
                    .first_mut()
                    .ok_or("empty WOTS signature digit")? ^= 1;
                record(
                    sink,
                    metrics,
                    &code,
                    &bad,
                    false,
                    &format!("{label}/forgery/{ordinal}/{position}/{disprove}"),
                )?;
            }
            let slot = registry.unique_slots(ordinal)?[0];
            let mut other = signatures.to_vec();
            other[slot] = signatures[(slot + 1) % signatures.len()];
            record(
                sink,
                metrics,
                &code,
                &registry.witness(ordinal, &other)?,
                false,
                &format!("{label}/cross-wire/{ordinal}/{disprove}"),
            )?;
        }
        count += 14;
    }
    Ok(count)
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
    h.input(b"BITVM2-NOVA/TEST-ONLY-BYTE-KECCAK-BLOCK-WOTS/v1\0");
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
