//! Closed M18 source and raw-u32 assignment admission before key generation.
//! No imported verdict/map/receipt supplies source authority. Compiler body
//! hashes pin the frozen research compiler; this is not a second compiler.
use crate::transport::{Case, CaseDescriptor};
use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitvm2_nova_script_oracle::{
    registry::GraphSpec,
    wots::{id32, Result},
};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, HashMap, HashSet};

const CONTEXT_DOMAIN: &[u8] = b"BITVM2-NOVA/AUTH-COST-CONFORMANCE/v1";
const OPERATION: &str = "benchmark/auth-cost/v1";
const BASE: u32 = 1 << 29;
const AB: u32 = 1 << 18;
pub const MIXED_PROFILES: [&str; 9] = [
    "a0",
    "a1",
    "a9",
    "a255",
    "bad-aux",
    "bad-square",
    "a256",
    "a-max",
    "auth-order",
];
const MIXED_VALUES: [[u32; 3]; 9] = [
    [0, 0, 0],
    [1, 1, 1],
    [9, 9, 81],
    [255, 255, 65025],
    [9, 8, 81],
    [9, 9, 80],
    [256, 256, 65536],
    [u32::MAX, 0, 0],
    [9, u32::MAX, u32::MAX],
];

pub struct SourceFacts {
    pub values: Vec<u32>,
    pub truth: Vec<bool>,
    pub false_ordinals: Vec<usize>,
    pub abort_ordinals: Vec<usize>,
    pub source_maps: Value,
    pub manifest: Value,
    pub source_sha256: String,
    pub source_maps_sha256: String,
    pub program_sha256: String,
    pub catalogue_id: String,
    pub global_ids: Vec<String>,
    /// (word index, producer leaf ordinal, final formal occurrence).
    pub first_producer: Option<(usize, usize, usize)>,
}
fn require(yes: bool, message: &str) -> Result<()> {
    if yes {
        Ok(())
    } else {
        Err(message.into())
    }
}
pub fn canonical(value: &Value) -> Result<Vec<u8>> {
    fn ordered(value: &Value, depth: usize) -> Result<Value> {
        if depth > 24 {
            return Err("auth-cost source JSON depth".into());
        }
        Ok(match value {
            Value::Object(items) => {
                let mut out = Map::new();
                let mut keys: Vec<_> = items.keys().collect();
                keys.sort_unstable();
                for key in keys {
                    if !key.is_ascii() {
                        return Err("ASCII metadata key required".into());
                    }
                    out.insert(key.clone(), ordered(&items[key], depth + 1)?);
                }
                Value::Object(out)
            }
            Value::Array(items) => Value::Array(
                items
                    .iter()
                    .map(|v| ordered(v, depth + 1))
                    .collect::<Result<_>>()?,
            ),
            Value::String(s) if !s.is_ascii() => {
                return Err("ASCII metadata string required".into())
            }
            Value::Number(n) if n.as_u64().is_none() && n.as_i64().is_none() => {
                return Err("integer metadata required".into())
            }
            _ => value.clone(),
        })
    }
    Ok(serde_json::to_vec(&ordered(value, 0)?)?)
}
fn hash_json(value: &Value) -> Result<String> {
    Ok(sha256::Hash::hash(&canonical(value)?).to_string())
}
fn domain_hash(domain: &[u8], value: &Value) -> Result<String> {
    let mut h = sha256::Hash::engine();
    h.input(domain);
    h.input(&canonical(value)?);
    Ok(sha256::Hash::from_engine(h).to_string())
}
fn role(role: &str) -> Result<(&'static str, u8, &'static str)> {
    match role {
        "pallas_scalar" => Ok((
            "p",
            59,
            "28948022309329048855892746252171976963363056481941647379679742748393362948097",
        )),
        "vesta_scalar" => Ok((
            "v",
            44,
            "28948022309329048855892746252171976963363056481941560715954676764349967630337",
        )),
        _ => Err("closed Pasta scalar role required".into()),
    }
}
pub fn mixed_values(profile: &str) -> Result<[u32; 3]> {
    let index = MIXED_PROFILES
        .iter()
        .position(|p| *p == profile)
        .ok_or("closed mixed source profile required")?;
    Ok(MIXED_VALUES[index])
}
pub fn synthetic_input(field_role: &str) -> Result<[u8; 200]> {
    let (_, counter, _) = role(field_role)?;
    let mut out = [0u8; 200];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = ((17 * i + usize::from(counter)) & 255) as u8;
    }
    Ok(out)
}
fn byte_value(kind: &str, args: &[i64], v: &[u32]) -> Result<u32> {
    Ok(match kind {
        "byte_xor" if args.is_empty() && v.len() == 2 => v[0] ^ v[1],
        "byte_and" if args.is_empty() && v.len() == 2 => v[0] & v[1],
        "byte_not" if args.is_empty() && v.len() == 1 => v[0] ^ 255,
        "byte_rol" if args.len() == 1 && (1..=7).contains(&args[0]) && v.len() == 2 => {
            ((v[0] << (args[0] as u32)) & 255) | (v[1] >> (8 - args[0] as u32))
        }
        "byte_xor_const" if args == [1] && v.len() == 1 => v[0] ^ 1,
        _ => return Err("closed round gate/argument/arity required".into()),
    })
}
fn aliases(wires: &[usize]) -> Vec<usize> {
    let mut unique = Vec::new();
    wires
        .iter()
        .map(|w| match unique.iter().position(|x| x == w) {
            Some(i) => i,
            None => {
                unique.push(*w);
                unique.len() - 1
            }
        })
        .collect()
}

// Exact schedule copied without semantic edits from committed old source
// rust-oracle/src/bin/byte_keccak_round.rs at main0fae1f7; raw SHA256
// 2799369adbc1e02c2a9f9cfbfaea3def4e30c7de795603c20d5932e5fdf5c64e.
// Only byte_layout(spec,0) is admitted below. Body pins are checked separately.
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
struct Bridge {
    byte: usize,
    aux: usize,
    bits: Vec<usize>,
    bit_leaf: usize,
    reconstruct: usize,
    output: bool,
}
struct Layout {
    ports: Ports,
    bridges: Vec<Bridge>,
    old_words: usize,
    old_leaves: usize,
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
fn byte_layout(spec: &GraphSpec, r: usize) -> Result<Layout> {
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
    Ok(Layout {
        ports: Ports {
            inputs: input.into_iter().flatten().collect(),
            outputs,
            producers,
        },
        bridges: vec![],
        old_words: 0,
        old_leaves: 0,
    })
}

fn program_id(spec: &GraphSpec, byte_program: bool) -> Result<String> {
    let (_, _, modulus) = role(&spec.field_role)?;
    let constraints: Vec<_> = spec
        .leaves
        .iter()
        .map(|leaf| {
            json!([
                leaf.kind,
                leaf.wires
                    .iter()
                    .map(|i| spec.words[*i].name.clone())
                    .collect::<Vec<_>>(),
                leaf.argument
            ])
        })
        .collect();
    let plain = hash_json(
        &json!({"schema":"bitvm2-nova-fixed-trace/v2","field_role":spec.field_role,"modulus":modulus,
        "operation_id":spec.operation_id,"context":spec.context,"words":spec.words.iter().map(|w|json!([w.name,w.bound])).collect::<Vec<_>>(),
        "fields":[],"constraints":constraints}),
    )?;
    if !byte_program {
        return Ok(plain);
    }
    let mut h = sha256::Hash::engine();
    h.input(b"BITVM2-NOVA/BYTE-TRACE/v1\0");
    h.input(&hex::decode(plain)?);
    Ok(sha256::Hash::from_engine(h).to_string())
}

fn exact_bodies(spec: &GraphSpec) -> Result<()> {
    let mut used = HashSet::new();
    for leaf in &spec.leaves {
        // Schedule and formal aliases were checked before this lookup. Pins
        // authenticate unchanged compiler outputs, not independent semantics.
        crate::body_pins::check(
            &spec.field_role,
            &leaf.kind,
            &leaf.argument,
            &leaf.wires,
            &leaf.body_sha256,
        )?;
        used.insert(leaf.body_sha256.clone());
    }
    require(
        used.len() == spec.bodies.len() && spec.bodies.keys().all(|key| used.contains(key)),
        "exact pinned body catalogue; no unused extra body",
    )
}
fn mixed_layout(spec: &GraphSpec) -> Result<()> {
    require(
        spec.words.len() == 3 && spec.leaves.len() == 2,
        "exact mixed3word2leaf census",
    )?;
    for (word, (name, bound)) in spec
        .words
        .iter()
        .zip([("a", 256), ("aux", BASE), ("sq", AB)])
    {
        require(
            word.name == name && word.bound == bound,
            "mixed word order/name/decoder bound differs",
        )?;
    }
    let a = &spec.leaves[0];
    let b = &spec.leaves[1];
    require(
        a.kind == "conv_reconstruct"
            && a.argument == [8]
            && a.wires == [1, 0]
            && b.kind == "conv_ab"
            && b.argument == [1]
            && b.wires == [0, 0, 2],
        "mixed body/argument/formal alias topology differs",
    )
}
fn round_honest_values(spec: &GraphSpec, field_role: &str, layout: &Layout) -> Result<Vec<u32>> {
    let raw = synthetic_input(field_role)?;
    let mut values = vec![0u32; spec.words.len()];
    require(
        layout.ports.inputs == (0..200).collect::<Vec<_>>(),
        "actual ordered BYTE input ports required",
    )?;
    for (i, byte) in raw.iter().enumerate() {
        values[i] = u32::from(*byte);
    }
    for (ordinal, leaf) in spec.leaves.iter().enumerate() {
        let (&output, inputs) = leaf.wires.split_last().ok_or("empty SSA gate")?;
        require(
            output == 200 + ordinal && inputs.iter().all(|input| *input < output),
            "exact forward SSA round assignment required",
        )?;
        let input_values: Vec<_> = inputs.iter().map(|i| values[*i]).collect();
        values[output] = byte_value(&leaf.kind, &leaf.argument, &input_values)?;
        require(values[output] < 256, "computed BYTE result outside range")?;
    }
    let expected = independent_round_zero(&raw);
    require(
        layout.ports.outputs.len() == 200
            && layout
                .ports
                .outputs
                .iter()
                .zip(expected)
                .all(|(i, v)| values[*i] == u32::from(v)),
        "fresh SSA round disagrees with independent word-level round0",
    )?;
    Ok(values)
}
fn independent_round_zero(raw: &[u8; 200]) -> [u8; 200] {
    let mut state = [0u64; 25];
    for (i, lane) in state.iter_mut().enumerate() {
        *lane = u64::from_le_bytes(raw[8 * i..8 * i + 8].try_into().expect("fixed lane width"));
    }
    let mut parity = [0u64; 5];
    for x in 0..5 {
        parity[x] = (0..5).fold(0, |acc, y| acc ^ state[x + 5 * y]);
    }
    let mut theta = [0u64; 25];
    for i in 0..25 {
        let x = i % 5;
        theta[i] = state[i] ^ parity[(x + 4) % 5] ^ parity[(x + 1) % 5].rotate_left(1);
    }
    let mut offsets = [0u32; 25];
    let (mut x, mut y) = (1usize, 0usize);
    for step in 0..24 {
        offsets[x + 5 * y] = ((step + 1) * (step + 2) / 2 % 64) as u32;
        let next = y;
        y = (2 * x + 3 * y) % 5;
        x = next;
    }
    let mut pi = [0u64; 25];
    for i in 0..25 {
        let (x, y) = (i % 5, i / 5);
        pi[y + 5 * ((2 * x + 3 * y) % 5)] = theta[i].rotate_left(offsets[i]);
    }
    let mut result = [0u8; 200];
    for i in 0..25 {
        let (x, y) = (i % 5, i / 5);
        let mut lane = pi[i] ^ ((!pi[(x + 1) % 5 + 5 * y]) & pi[(x + 2) % 5 + 5 * y]);
        if i == 0 {
            lane ^= 1;
        }
        result[i * 8..i * 8 + 8].copy_from_slice(&lane.to_le_bytes());
    }
    result
}
fn truth(spec: &GraphSpec, values: &[u32], ordinal: usize) -> Result<bool> {
    let leaf = spec.leaves.get(ordinal).ok_or("truth ordinal")?;
    let v: Vec<_> = leaf.wires.iter().map(|i| values[*i]).collect();
    if leaf
        .wires
        .iter()
        .zip(&v)
        .any(|(wire, value)| *value >= spec.words[*wire].bound)
    {
        return Ok(false);
    }
    Ok(match leaf.kind.as_str() {
        "conv_reconstruct" if leaf.argument == [8] && v.len() == 2 => v[0] == v[1],
        "conv_ab" if leaf.argument == [1] && v.len() == 3 => {
            u64::from(v[2]) == u64::from(v[0]) * u64::from(v[1])
        }
        _ => {
            let (&output, inputs) = v.split_last().ok_or("empty truth gate")?;
            output == byte_value(&leaf.kind, &leaf.argument, inputs)?
        }
    })
}
fn validate_natural_ports(spec: &GraphSpec, layout: &Layout) -> Result<()> {
    let produced: HashSet<_> = spec
        .leaves
        .iter()
        .filter_map(|leaf| leaf.wires.last().copied())
        .collect();
    let consumed: HashSet<_> = spec
        .leaves
        .iter()
        .flat_map(|leaf| leaf.wires[..leaf.wires.len() - 1].iter().copied())
        .collect();
    let terminals: HashSet<_> = produced.difference(&consumed).copied().collect();
    let outputs: HashSet<_> = layout.ports.outputs.iter().copied().collect();
    require(
        produced.len() == 1217
            && layout.ports.outputs.len() == 200
            && outputs.len() == 200
            && outputs == terminals,
        "natural terminal producer set differs; no copies/zero anchors admitted",
    )?;
    for ((output, (ordinal, formal)), expected) in layout
        .ports
        .outputs
        .iter()
        .zip(&layout.ports.producers)
        .zip(0..200)
    {
        let leaf = &spec.leaves[*ordinal];
        let lane = expected / 8;
        let byte = expected % 8;
        let name = if lane == 0 && byte == 0 {
            "iota/byte0".to_owned()
        } else {
            format!("chi/out/l{lane}/byte{byte}")
        };
        require(
            spec.words[*output].name == name
                && *formal == leaf.wires.len() - 1
                && leaf.wires[*formal] == *output,
            "ordered scattered Chi/Iota terminal producer coordinate differs",
        )?;
    }
    Ok(())
}
fn child_round_metadata(
    spec: &GraphSpec,
    layout: &Layout,
    catalogue: &str,
) -> Result<(String, String)> {
    let incoming: HashMap<_, _> = layout
        .ports
        .inputs
        .iter()
        .enumerate()
        .map(|(slot, word)| (*word, slot))
        .collect();
    let outgoing: HashMap<_, _> = layout
        .ports
        .outputs
        .iter()
        .enumerate()
        .map(|(slot, word)| (*word, slot))
        .collect();
    let ids: Vec<_> = spec
        .words
        .iter()
        .enumerate()
        .map(|(i, word)| {
            if let Some(slot) = incoming.get(&i) {
                format!("byte-state/0/l{}/byte{}", slot / 8, slot % 8)
            } else if let Some(slot) = outgoing.get(&i) {
                format!("byte-state/1/l{}/byte{}", slot / 8, slot % 8)
            } else {
                format!("byte-round/0/{}", word.name)
            }
        })
        .collect();
    let inputs: Vec<_> = layout
        .ports
        .inputs
        .iter()
        .map(|i| spec.words[*i].name.clone())
        .collect();
    let outputs: Vec<_> = layout
        .ports
        .outputs
        .iter()
        .map(|i| spec.words[*i].name.clone())
        .collect();
    let maps = json!({"schema":"bitvm2-nova-byte-keccak-round-maps/v1","round_index":0,
        "input_indices":layout.ports.inputs,"output_indices":layout.ports.outputs,
        "producer_ordinals":layout.ports.producers.iter().map(|p|p.0).collect::<Vec<_>>(),
        "global_ids":ids,"global_ids_sha256":hash_json(&json!(ids))?,
        "phase_counts":{"theta_c":160,"theta_d_rot":40,"theta_d_xor":40,"theta_mix":200,"rho":176,
            "chi_not":200,"chi_and":200,"chi_xor":200,"iota":1}});
    let manifest = json!({"schema":"bitvm2-nova-byte-keccak-round/v1","round_index":0,
        "context":spec.context,"role":spec.field_role,"operation_id":format!("{OPERATION}/round"),
        "program_operation_id":spec.operation_id,"program_sha256":spec.program_sha256,"catalogue_id":catalogue,
        "round_constant_le":"0100000000000000","input_encoding":"25lanes(x+5*y),8bytesLEperlane",
        "output_encoding":"natural terminal Chi/Iota producer words; no copies","inputs":inputs,"outputs":outputs,
        "source_maps":maps,"scope":"one BYTE Keccak round; no sponge, transcript, proof or production assertion"});
    Ok((
        domain_hash(b"BITVM2-NOVA/BYTE-KECCAK-ROUND/v1\0", &manifest)?,
        hash_json(&maps)?,
    ))
}
fn source_metadata(
    spec: &GraphSpec,
    fixture: &str,
    catalogue: &str,
    layout: Option<&Layout>,
) -> Result<(Value, Value, Vec<String>)> {
    let global_ids: Vec<_> = spec
        .words
        .iter()
        .map(|w| format!("auth-cost/{fixture}/{}", w.name))
        .collect();
    require(
        global_ids.iter().collect::<HashSet<_>>().len() == spec.words.len(),
        "injective source global IDs required",
    )?;
    let mut occurrences = vec![Vec::new(); spec.words.len()];
    for (ordinal, leaf) in spec.leaves.iter().enumerate() {
        for (formal, wire) in leaf.wires.iter().enumerate() {
            occurrences[*wire].push((ordinal, formal));
        }
    }
    require(
        occurrences.iter().all(|items| !items.is_empty()),
        "every source word must have an actual opening coordinate",
    )?;
    let rows: Vec<_> = spec
        .words
        .iter()
        .enumerate()
        .map(|(i, w)| {
            json!({"word_index":i,"local_name":w.name,"global_id":global_ids[i],
        "bound":w.bound,"occurrences":occurrences[i]})
        })
        .collect();
    let (ports, first, child_source, child_maps) = if let Some(layout) = layout {
        let leaf = &spec.leaves[0];
        let wire = *leaf.wires.last().ok_or("first producer")?;
        require(
            wire == 200
                && leaf.kind == "byte_xor"
                && leaf.argument.is_empty()
                && leaf.wires == [0, 40, 200],
            "closed first actual producer required",
        )?;
        let ports = json!({"inputs":layout.ports.inputs.iter().map(|i|spec.words[*i].name.clone()).collect::<Vec<_>>(),
            "outputs":layout.ports.outputs.iter().map(|i|spec.words[*i].name.clone()).collect::<Vec<_>>()});
        let first = json!({"word_index":wire,"local_name":spec.words[wire].name,"ordinal":0,"occurrence":leaf.wires.len()-1});
        let (source, maps) = child_round_metadata(spec, layout, catalogue)?;
        (ports, first, Some(source), Some(maps))
    } else {
        (
            json!({"a":"a","aux":"aux","sq":"sq"}),
            Value::Null,
            None,
            None,
        )
    };
    let maps = json!({"schema":"bitvm2-nova-auth-cost-source-maps/v1","fixture":fixture,"words":rows,"ports":ports,"first_producer":first});
    let round = layout.is_some();
    let profiles = if round {
        json!(["honest", "producer-fault"])
    } else {
        json!(MIXED_PROFILES)
    };
    let manifest = json!({"schema":"bitvm2-nova-auth-cost-source/v1","fixture":fixture,"context":spec.context,
        "field_role":spec.field_role,"operation_id":spec.operation_id,
        "program_identity_kind":if round{"ByteProgram.digest (byte-v1)"}else{"ConvolutionProgram.digest (fixed-trace/v2)"},
        "program_sha256":spec.program_sha256,"catalogue_id":catalogue,"source_maps_sha256":hash_json(&maps)?,
        "child_source_sha256":child_source,"child_source_maps_sha256":child_maps,"words":spec.words.len(),"leaves":spec.leaves.len(),"fields":0,
        "profiles":profiles,"input_recipe":if round{"synthetic cost fixture: byte((17*i+roleCounter)&255), i=0..199; roleCounter=59/44"}else{"closed raw-u32 triples in word order a,aux,sq"},
        "fault_recipe":if round{"flip bit0 of first actual SSA gate output; keep all other words"}else{"closed raw-u32 triples without modular reduction or truncation"},
        "scope":"adapter cost/conformance on synthetic statements; no Nova transcript or proof verification"});
    require(
        canonical(&maps)?.len() <= (1 << 20) && canonical(&manifest)?.len() <= (1 << 20),
        "source sidecar budget",
    )?;
    Ok((maps, manifest, global_ids))
}

pub(crate) fn admit(
    case: &Case,
    d: &CaseDescriptor,
    context: &str,
    op: &str,
) -> Result<SourceFacts> {
    let (prefix, _, _) = role(&d.role)?;
    let expected_context = sha256::Hash::hash(CONTEXT_DOMAIN).to_string();
    require(
        context == expected_context && hex::encode(id32(context)?) == context && op == OPERATION,
        "verifier-owned context and operation required",
    )?;
    let round = match d.fixture.as_str() {
        "mixed" => false,
        "round" => true,
        _ => return Err("closed mixed/round source fixture required".into()),
    };
    let name = if round {
        match d.profile.as_str() {
            "honest" => format!("{prefix}/rh"),
            "producer-fault" => format!("{prefix}/rf"),
            _ => return Err("closed round profile required".into()),
        }
    } else {
        let i = MIXED_PROFILES
            .iter()
            .position(|p| *p == d.profile)
            .ok_or("closed mixed profile required")?;
        format!("{prefix}/m{i}")
    };
    let spec = &case.spec;
    let (words, leaves) = if round { (1417, 1217) } else { (3, 2) };
    let actual_operation = if round {
        format!("{op}/round/round/0")
    } else {
        format!("{op}/mixed")
    };
    require(
        case.name == name
            && d.name == name
            && case.measure_all
            && case.words.len() == words
            && spec.words.len() == words
            && spec.leaves.len() == leaves
            && d.words == words
            && d.leaves == leaves
            && spec.context == context
            && spec.field_role == d.role
            && spec.operation_id == actual_operation,
        "closed source name/role/census/identity header differs",
    )?;
    let layout = if round {
        let layout = byte_layout(spec, 0)?;
        validate_natural_ports(spec, &layout)?;
        Some(layout)
    } else {
        mixed_layout(spec)?;
        None
    };
    // Normative topology and aliases precede all trusted compiler pin lookups.
    exact_bodies(spec)?;
    let catalogue = hex::encode(spec.identity()?);
    let program = program_id(spec, round)?;
    require(
        spec.program_sha256 == program
            && d.program_sha256 == program
            && d.catalogue_id == catalogue
            && case.expected_spec_id == catalogue,
        "actual source program/catalogue identity differs",
    )?;
    let mut values = if let Some(layout) = &layout {
        round_honest_values(spec, &d.role, layout)?
    } else {
        mixed_values(&d.profile)?.to_vec()
    };
    let first_producer = if round {
        let leaf = &spec.leaves[0];
        let word = *leaf.wires.last().ok_or("first producer")?;
        if d.profile == "producer-fault" {
            values[word] ^= 1;
        }
        Some((word, 0, leaf.wires.len() - 1))
    } else {
        None
    };
    require(
        case.words == values,
        "every source assertion must match the closed raw-u32 recipe",
    )?;
    let mut truths = Vec::with_capacity(leaves);
    for ordinal in 0..leaves {
        truths.push(truth(spec, &values, ordinal)?);
    }
    let false_ordinals: Vec<_> = truths
        .iter()
        .enumerate()
        .filter_map(|(i, v)| (!*v).then_some(i))
        .collect();
    require(
        d.expected_false == false_ordinals
            && d.expected_abort_ordinals.is_empty()
            && case.checks.len() == leaves
            && case
                .checks
                .iter()
                .enumerate()
                .all(|(i, c)| c.ordinal == i && c.expected_correct == truths[i]),
        "independent source truth/abort/ordered checks differ",
    )?;
    let (maps, manifest, global_ids) =
        source_metadata(spec, &d.fixture, &catalogue, layout.as_ref())?;
    let maps_sha = hash_json(&maps)?;
    let source_sha = domain_hash(b"BITVM2-NOVA/AUTH-COST-SOURCE/v1\0", &manifest)?;
    require(
        d.source_sha256 == source_sha && d.source_maps_sha256 == maps_sha,
        "independently reconstructed source JSON hashes differ",
    )?;
    Ok(SourceFacts {
        values,
        truth: truths,
        false_ordinals,
        abort_ordinals: Vec::new(),
        source_maps: maps,
        manifest,
        source_sha256: source_sha,
        source_maps_sha256: maps_sha,
        program_sha256: program,
        catalogue_id: catalogue,
        global_ids,
        first_producer,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mixed_recipes_preserve_raw_unsigned_values_and_all_authentication_order_faults() {
        for (profile, expected) in MIXED_PROFILES.iter().zip(MIXED_VALUES) {
            assert_eq!(mixed_values(profile).unwrap(), expected);
        }
        assert_eq!(mixed_values("a256").unwrap(), [256, 256, 65536]);
        assert_eq!(mixed_values("a-max").unwrap(), [u32::MAX, 0, 0]);
        assert_eq!(mixed_values("auth-order").unwrap(), [9, u32::MAX, u32::MAX]);
        assert!(mixed_values("a09").is_err());
    }
    #[test]
    fn synthetic_messages_are_bounded_asymmetric_and_role_specific() {
        let p = synthetic_input("pallas_scalar").unwrap();
        let v = synthetic_input("vesta_scalar").unwrap();
        for i in 0..200 {
            assert_eq!(p[i], ((17 * i + 59) & 255) as u8);
            assert_eq!(v[i], ((17 * i + 44) & 255) as u8);
        }
        assert_ne!(p, v);
        assert!(synthetic_input("pallas_base").is_err());
    }
    #[test]
    fn formal_aliases_depend_on_actual_indices_not_equal_numeric_values() {
        assert_eq!(aliases(&[0, 0, 2]), [0, 0, 1]);
        assert_eq!(aliases(&[1, 0]), [0, 1]);
        assert_eq!(aliases(&[11, 12, 11, 13]), [0, 1, 0, 2]);
    }

    fn symbolic_mixed() -> GraphSpec {
        use bitvm2_nova_script_oracle::registry::{Leaf, Word};
        GraphSpec {
            program_sha256: "0".repeat(64),
            context: "0".repeat(64),
            field_role: "pallas_scalar".into(),
            operation_id: format!("{OPERATION}/mixed"),
            words: vec![
                Word {
                    name: "a".into(),
                    bound: 256,
                },
                Word {
                    name: "aux".into(),
                    bound: BASE,
                },
                Word {
                    name: "sq".into(),
                    bound: AB,
                },
            ],
            leaves: vec![
                Leaf {
                    kind: "conv_reconstruct".into(),
                    argument: vec![8],
                    wires: vec![1, 0],
                    body_sha256: "0".repeat(64),
                },
                Leaf {
                    kind: "conv_ab".into(),
                    argument: vec![1],
                    wires: vec![0, 0, 2],
                    body_sha256: "0".repeat(64),
                },
            ],
            bodies: BTreeMap::new(),
        }
    }
    #[test]
    fn symbolic_mixed_truth_preserves_range_failures_and_formal_aliases() {
        let spec = symbolic_mixed();
        mixed_layout(&spec).unwrap();
        let expected = [
            [true, true],
            [true, true],
            [true, true],
            [true, true],
            [false, true],
            [true, false],
            [false, false],
            [false, false],
            [false, false],
        ];
        for (values, answer) in MIXED_VALUES.iter().zip(expected) {
            assert_eq!(
                [
                    truth(&spec, values, 0).unwrap(),
                    truth(&spec, values, 1).unwrap()
                ],
                answer
            );
        }
        let mut bad = spec.clone();
        bad.leaves[1].wires = vec![0, 2, 0];
        assert!(mixed_layout(&bad).is_err());
        let mut bad = spec.clone();
        bad.words[0].bound = BASE;
        assert!(mixed_layout(&bad).is_err());
        let mut bad = spec.clone();
        bad.leaves[0].argument = vec![7];
        assert!(mixed_layout(&bad).is_err());
    }
    #[test]
    fn word_reference_zero_round_zero_has_only_the_iota_bit() {
        let mut expected = [0u8; 200];
        expected[0] = 1;
        assert_eq!(independent_round_zero(&[0; 200]), expected);
    }
}
