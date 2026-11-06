//! Hosted TEST-ONLY single BYTE Keccak rounds and conversion-complete baselines.
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
    collections::{HashMap, HashSet},
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
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Descriptor {
    name: String,
    profile: String,
    role: String,
    round: usize,
    filename: String,
    file_sha256: String,
    file_bytes: u64,
    catalogue_id: String,
    program_sha256: String,
    global_ids_sha256: String,
    source_sha256: String,
    words: usize,
    leaves: usize,
    input_state_hex: String,
    expected_output_state_hex: String,
    expected_false: Vec<usize>,
    boolean_program_sha256: Option<String>,
    boolean_catalogue_id: Option<String>,
    probe_filename: String,
    probe_file_sha256: String,
    probe_file_bytes: u64,
    probe_catalogue_id: String,
    probe_program_sha256: String,
    probe_global_ids_sha256: String,
    probe_words: usize,
    probe_leaves: usize,
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
fn boolean_layout(spec: &GraphSpec, r: usize) -> Result<Layout> {
    let mut c = Checker::new(spec);
    let mut input = [[0usize; 64]; 25];
    for l in 0..25 {
        for bit in 0..64 {
            input[l][bit] = c.word(format!("boolean/input/l{l}/b{bit}"), 2)?;
        }
    }
    let p = format!("keccak/r{r}");
    let mut parity = [[0usize; 64]; 5];
    for x in 0..5 {
        for bit in 0..64 {
            let mut acc = input[x][bit];
            for y in 1..5 {
                acc = c.gate(
                    format!("{p}/c/{x}/{bit}/{y}"),
                    "bool_xor",
                    &[],
                    &[acc, input[x + 5 * y][bit]],
                    2,
                )?;
            }
            parity[x][bit] = acc;
        }
    }
    let mut d = [[0usize; 64]; 5];
    for x in 0..5 {
        for bit in 0..64 {
            d[x][bit] = c.gate(
                format!("{p}/d/{x}/{bit}"),
                "bool_xor",
                &[],
                &[
                    parity[(x + 4) % 5][bit],
                    parity[(x + 1) % 5][(bit + 63) % 64],
                ],
                2,
            )?;
        }
    }
    let mut t = [[0usize; 64]; 25];
    for l in 0..25 {
        for bit in 0..64 {
            t[l][bit] = c.gate(
                format!("{p}/t/{l}/{bit}"),
                "bool_xor",
                &[],
                &[input[l][bit], d[l % 5][bit]],
                2,
            )?;
        }
    }
    let mut b = [[0usize; 64]; 25];
    for l in 0..25 {
        let x = l % 5;
        let y = l / 5;
        let target = y + 5 * ((2 * x + 3 * y) % 5);
        for bit in 0..64 {
            b[target][(bit + RHO[y][x] as usize) % 64] = t[l][bit];
        }
    }
    let mut out = [[0usize; 64]; 25];
    for y in 0..5 {
        for x in 0..5 {
            let l = x + 5 * y;
            for bit in 0..64 {
                let n = c.gate(
                    format!("{p}/chi/n/{l}/{bit}"),
                    "bool_not",
                    &[],
                    &[b[(x + 1) % 5 + 5 * y][bit]],
                    2,
                )?;
                let a = c.gate(
                    format!("{p}/chi/a/{l}/{bit}"),
                    "bool_and",
                    &[],
                    &[n, b[(x + 2) % 5 + 5 * y][bit]],
                    2,
                )?;
                out[l][bit] = c.gate(
                    format!("{p}/chi/x/{l}/{bit}"),
                    "bool_xor",
                    &[],
                    &[b[l][bit], a],
                    2,
                )?;
            }
        }
    }
    for bit in 0..64 {
        if (RC[r] >> bit) & 1 != 0 {
            out[0][bit] = c.gate(
                format!("{p}/iota/{bit}"),
                "bool_not",
                &[],
                &[out[0][bit]],
                2,
            )?;
        }
    }
    let zero = c.gate(format!("{p}/zero"), "const", &[0], &[], 2)?;
    let mut old_outputs = [[0usize; 64]; 25];
    for l in 0..25 {
        for bit in 0..64 {
            old_outputs[l][bit] = c.gate(
                format!("boolean/output/l{l}/b{bit}"),
                "bool_xor",
                &[],
                &[out[l][bit], zero],
                2,
            )?;
        }
    }
    let old_words = c.word;
    let old_leaves = c.leaf;
    if old_words != 11201 + RC[r].count_ones() as usize
        || old_leaves != 9601 + RC[r].count_ones() as usize
    {
        return Err("preserved Boolean child census differs".into());
    }
    let mut bridges = Vec::new();
    let mut inputs = Vec::new();
    let mut outputs = Vec::new();
    let mut producers = Vec::new();
    for output in [false, true] {
        let side = if output { "output" } else { "input" };
        let bit_words = if output { &old_outputs } else { &input };
        for l in 0..25 {
            for j in 0..8 {
                let byte = c.word(format!("{side}/l{l}/byte{j}"), 256)?;
                let aux = c.word(format!("bridge/{side}/l{l}/byte{j}/aux"), 1 << 29)?;
                let bits: Vec<_> = (0..8).map(|bit| bit_words[l][8 * j + bit]).collect();
                let mut wires = vec![aux];
                wires.extend(bits.iter().rev());
                let bit_leaf = c.leaf("bits", &[8], &wires)?;
                let reconstruct = c.leaf("conv_reconstruct", &[8], &[aux, byte])?;
                bridges.push(Bridge {
                    byte,
                    aux,
                    bits,
                    bit_leaf,
                    reconstruct,
                    output,
                });
                if output {
                    outputs.push(byte);
                    producers.push((reconstruct, 1));
                } else {
                    inputs.push(byte);
                }
            }
        }
    }
    c.finish()?;
    Ok(Layout {
        ports: Ports {
            inputs,
            outputs,
            producers,
        },
        bridges,
        old_words,
        old_leaves,
    })
}
fn validate_ports(spec: &GraphSpec, r: usize, boolean: bool, ports: &Ports) -> Result<()> {
    if ports.inputs.len() != 200
        || ports.outputs.len() != 200
        || ports.producers.len() != 200
        || ports.inputs.iter().collect::<HashSet<_>>().len() != 200
        || ports.outputs.iter().collect::<HashSet<_>>().len() != 200
        || ports.inputs.iter().any(|i| ports.outputs.contains(i))
    {
        return Err("exact200 distinct/disjoint ordered source ports required".into());
    }
    let masks = RC[r].to_le_bytes();
    let old_leaves = 9601 + RC[r].count_ones() as usize;
    for i in 0..200 {
        let l = i / 8;
        let j = i % 8;
        let input = spec
            .words
            .get(ports.inputs[i])
            .ok_or("source input index bound")?;
        let output = spec
            .words
            .get(ports.outputs[i])
            .ok_or("source output index bound")?;
        let name = if boolean {
            format!("output/l{l}/byte{j}")
        } else if l == 0 && masks[j] != 0 {
            format!("iota/byte{j}")
        } else {
            format!("chi/out/l{l}/byte{j}")
        };
        let expected = if boolean {
            (old_leaves + 401 + 2 * i, 1)
        } else if l == 0 && masks[j] != 0 {
            (1216 + masks[..j].iter().filter(|v| **v != 0).count(), 1)
        } else {
            (1016 + i, 2)
        };
        if input.name != format!("input/l{l}/byte{j}")
            || input.bound != 256
            || output.name != name
            || output.bound != 256
            || ports.producers[i] != expected
        {
            return Err("ordered input/output/actual producer port differs".into());
        }
        let (ordinal, formal) = ports.producers[i];
        let leaf = spec
            .leaves
            .get(ordinal)
            .ok_or("source producer ordinal bound")?;
        if leaf.wires.get(formal) != Some(&ports.outputs[i])
            || leaf
                .wires
                .iter()
                .enumerate()
                .any(|(p, w)| p != formal && *w == ports.outputs[i])
        {
            return Err("source terminal producer operand differs".into());
        }
        for (other, node) in spec.leaves.iter().enumerate() {
            if other != ordinal && node.wires.contains(&ports.outputs[i]) {
                return Err("declared terminal BYTE output is consumed or reproduced".into());
            }
        }
    }
    Ok(())
}
fn port_negatives(spec: &GraphSpec, r: usize, boolean: bool, ports: &Ports) -> Result<usize> {
    let mut variants = Vec::new();
    let mut x = ports.clone();
    x.inputs[1] = x.inputs[0];
    variants.push(x);
    let mut x = ports.clone();
    x.inputs.swap(0, 1);
    variants.push(x);
    let mut x = ports.clone();
    x.outputs[1] = x.outputs[0];
    variants.push(x);
    let mut x = ports.clone();
    x.outputs.swap(0, 1);
    variants.push(x);
    let mut x = ports.clone();
    x.outputs[0] = x.inputs[0];
    variants.push(x);
    let mut x = ports.clone();
    x.producers[0].0 = x.producers[1].0;
    variants.push(x);
    let mut x = ports.clone();
    x.producers[0].1 = 0;
    variants.push(x);
    let mut x = ports.clone();
    x.producers.pop();
    variants.push(x);
    for other in &variants {
        if validate_ports(spec, r, boolean, other).is_ok() {
            return Err("source port/producer substitution accepted".into());
        }
    }
    Ok(variants.len())
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
fn source_names(spec: &GraphSpec, r: usize, boolean: bool, ports: &Ports) -> Result<Vec<String>> {
    let input: HashMap<_, _> = ports
        .inputs
        .iter()
        .enumerate()
        .map(|(i, w)| (*w, i))
        .collect();
    let output: HashMap<_, _> = ports
        .outputs
        .iter()
        .enumerate()
        .map(|(i, w)| (*w, i))
        .collect();
    let mut names = Vec::new();
    for (i, w) in spec.words.iter().enumerate() {
        let name = if let Some(j) = input.get(&i) {
            format!("byte-state/{r}/l{}/byte{}", j / 8, j % 8)
        } else if let Some(j) = output.get(&i) {
            format!("byte-state/{}/l{}/byte{}", r + 1, j / 8, j % 8)
        } else {
            format!(
                "{}-round/{r}/{}",
                if boolean { "boolean" } else { "byte" },
                w.name
            )
        };
        if !identifier(&name) {
            return Err("derived global identity exceeds existing bound".into());
        }
        names.push(name);
    }
    if names.iter().collect::<HashSet<_>>().len() != spec.words.len() {
        return Err("source global identity alias".into());
    }
    Ok(names)
}
fn validate_projection(case: &Case, desc: &Descriptor, layout: &Layout) -> Result<()> {
    let program = desc
        .boolean_program_sha256
        .as_ref()
        .ok_or("missing preserved Boolean program ID")?;
    let expected = desc
        .boolean_catalogue_id
        .as_ref()
        .ok_or("missing preserved Boolean catalogue ID")?;
    let leaves = case.spec.leaves[..layout.old_leaves].to_vec();
    let needed: HashSet<_> = leaves.iter().map(|l| l.body_sha256.as_str()).collect();
    let bodies = case
        .spec
        .bodies
        .iter()
        .filter(|(id, _)| needed.contains(id.as_str()))
        .map(|(a, b)| (a.clone(), b.clone()))
        .collect();
    let projection = GraphSpec {
        program_sha256: program.clone(),
        context: case.spec.context.clone(),
        field_role: case.spec.field_role.clone(),
        operation_id: format!("{}/boolean/round/{}", case.spec.operation_id, desc.round),
        words: case.spec.words[..layout.old_words].to_vec(),
        leaves,
        bodies,
    };
    if projection.identity()? != digest(expected)? {
        return Err("original Boolean word/leaf/body/zero/output projection differs".into());
    }
    Ok(())
}
fn validate_manifest(manifest: &Manifest) -> Result<()> {
    if manifest.schema != "bitvm2-nova-byte-keccak-round-run/v1"
        || !identifier(&manifest.operation_id)
        || manifest.cases.len() != 64
    {
        return Err("exact64-case single-round manifest required".into());
    }
    digest(&manifest.context)?;
    let mut names = HashSet::new();
    let mut coverage = HashSet::new();
    for (index, d) in manifest.cases.iter().enumerate() {
        if d.round >= 24
            || !["pallas_scalar", "vesta_scalar"].contains(&d.role.as_str())
            || !names.insert(d.name.as_str())
            || !coverage.insert((d.role.as_str(), d.round, d.profile.as_str()))
            || d.filename != format!("case-{index:02}.json")
            || d.probe_filename != format!("probe-{index:02}.json")
            || d.file_bytes == 0
            || d.file_bytes > INPUT_CAP
            || d.probe_file_bytes == 0
            || d.probe_file_bytes > INPUT_CAP
            || d.probe_words != 400
            || d.probe_leaves != 200
        {
            return Err("round descriptor identity/filename/census differs".into());
        }
        let boolean = d.profile == "boolean-honest";
        let short = match d.profile.as_str() {
            "byte-honest" => "honest",
            "byte-wrong-output" if [0, 23].contains(&d.round) => "wrong-output",
            "byte-oversized" if [0, 23].contains(&d.round) => "oversized",
            "boolean-honest" if [0, 1, 2, 23].contains(&d.round) => "",
            _ => return Err("unrecognized exact diagnostic profile".into()),
        };
        let name = if boolean {
            format!("{}/boolean-r{}", d.role, d.round)
        } else {
            format!("{}/byte-r{}-{short}", d.role, d.round)
        };
        let count = RC[d.round]
            .to_le_bytes()
            .iter()
            .filter(|b| **b != 0)
            .count();
        let leaves = if boolean {
            10401 + RC[d.round].count_ones() as usize
        } else {
            1216 + count
        };
        let words = if boolean {
            12001 + RC[d.round].count_ones() as usize
        } else {
            200 + leaves
        };
        let legacy_labels_valid = if boolean {
            d.boolean_program_sha256.is_some() && d.boolean_catalogue_id.is_some()
        } else {
            d.boolean_program_sha256.is_none() && d.boolean_catalogue_id.is_none()
        };
        if d.name != name || d.leaves != leaves || d.words != words || !legacy_labels_valid {
            return Err("descriptor topology or original Boolean identity differs".into());
        }
        for value in [
            &d.file_sha256,
            &d.catalogue_id,
            &d.program_sha256,
            &d.global_ids_sha256,
            &d.source_sha256,
            &d.probe_file_sha256,
            &d.probe_catalogue_id,
            &d.probe_program_sha256,
            &d.probe_global_ids_sha256,
        ] {
            digest(value)?;
        }
        if let Some(value) = &d.boolean_program_sha256 {
            digest(value)?;
        }
        if let Some(value) = &d.boolean_catalogue_id {
            digest(value)?;
        }
        let input = state(&d.input_state_hex)?;
        let expected_input: Vec<_> = (0..200)
            .map(|i| ((37 * i + 11 + 17 * d.round) & 255) as u8)
            .collect();
        if input.as_slice() != expected_input.as_slice() {
            return Err("round reference input differs from independently fixed fixture".into());
        }
        let mut output = reference(&input, d.round);
        if d.profile == "byte-wrong-output" {
            output[if d.round == 0 { 0 } else { 8 }] ^= 1;
        }
        if state(&d.expected_output_state_hex)? != output {
            return Err("reference round output or controlled claimed output differs".into());
        }
    }
    for role in ["pallas_scalar", "vesta_scalar"] {
        for r in 0..24 {
            if !coverage.contains(&(role, r, "byte-honest")) {
                return Err("all24 honest byte rounds for both roles required".into());
            }
        }
        for r in [0, 23] {
            for profile in ["byte-wrong-output", "byte-oversized"] {
                if !coverage.contains(&(role, r, profile)) {
                    return Err("both diagnostic rounds/roles required".into());
                }
            }
        }
        for r in [0, 1, 2, 23] {
            if !coverage.contains(&(role, r, "boolean-honest")) {
                return Err("all four complete Boolean baseline rounds/roles required".into());
            }
        }
    }
    Ok(())
}
fn validate_case(case: &Case, manifest: &Manifest, d: &Descriptor, probe: bool) -> Result<()> {
    let boolean = d.profile == "boolean-honest";
    let expected_name = if probe {
        format!("{}/probe", d.name)
    } else {
        d.name.clone()
    };
    let op = if probe {
        format!(
            "{}/probe/{}/r{}",
            manifest.operation_id,
            if boolean { "boolean" } else { "byte" },
            d.round
        )
    } else if boolean {
        format!("{}/boolean/r{}", manifest.operation_id, d.round)
    } else {
        // Some round constants repeat (notably rounds5/22). The actual BYTE
        // Program identity must bind the explicit round even for one caller ID.
        format!(
            "{}/byte/r{}/round/{}",
            manifest.operation_id, d.round, d.round
        )
    };
    let (catalogue, program, words, leaves) = if probe {
        (
            &d.probe_catalogue_id,
            &d.probe_program_sha256,
            d.probe_words,
            d.probe_leaves,
        )
    } else {
        (&d.catalogue_id, &d.program_sha256, d.words, d.leaves)
    };
    if case.name != expected_name
        || !case.measure_all
        || case.expected_spec_id != *catalogue
        || case.spec.program_sha256 != *program
        || case.spec.context != manifest.context
        || case.spec.field_role != d.role
        || case.spec.operation_id != op
        || case.spec.words.len() != words
        || case.spec.leaves.len() != leaves
        || case.words.len() != words
        || case.checks.len() != leaves
        || case.checks.iter().enumerate().any(|(i, c)| c.ordinal != i)
        || case.spec.identity()? != digest(catalogue)?
        || case.spec.leaves.iter().any(|l| {
            !BYTE_KINDS.contains(&l.kind.as_str())
                && !matches!(
                    l.kind.as_str(),
                    "bits" | "conv_reconstruct" | "bool_xor" | "bool_and" | "bool_not" | "const"
                )
        })
    {
        return Err("round source/probe differs from trusted case descriptor".into());
    }
    Ok(())
}
fn check_assignment(case: &Case, d: &Descriptor, layout: &Layout) -> Result<Vec<usize>> {
    let input = state(&d.input_state_hex)?;
    let output = state(&d.expected_output_state_hex)?;
    for i in 0..200 {
        let expected = if d.profile == "byte-oversized" && i == 0 {
            u32::MAX
        } else {
            u32::from(input[i])
        };
        if case.words[layout.ports.inputs[i]] != expected
            || case.words[layout.ports.outputs[i]] != u32::from(output[i])
        {
            return Err(
                "actual signed source state differs from exact reference/diagnostic claim".into(),
            );
        }
    }
    for (i, (word, value)) in case.spec.words.iter().zip(&case.words).enumerate() {
        if *value >= word.bound
            && !(d.profile == "byte-oversized" && i == layout.ports.inputs[0] && *value == u32::MAX)
        {
            return Err("unexpected out-of-bound source assignment".into());
        }
    }
    let mut false_rows = Vec::new();
    for check in &case.checks {
        let actual = truth(&case.spec, &case.words, check.ordinal)?;
        if actual != check.expected_correct {
            return Err("round Script expectation differs from independent integer truth".into());
        }
        if !actual {
            false_rows.push(check.ordinal);
        }
    }
    let expected = match d.profile.as_str() {
        "byte-wrong-output" => vec![layout.ports.producers[if d.round == 0 { 0 } else { 8 }].0],
        "byte-oversized" => case
            .spec
            .leaves
            .iter()
            .enumerate()
            .filter(|(_, l)| l.wires.contains(&layout.ports.inputs[0]))
            .map(|(i, _)| i)
            .collect(),
        _ => vec![],
    };
    if false_rows != expected || false_rows != d.expected_false {
        return Err("source false predicates differ from exact controlled diagnostic".into());
    }
    Ok(false_rows)
}
fn validate_probe(case: &Case, d: &Descriptor) -> Result<Vec<String>> {
    let mut c = Checker::new(&case.spec);
    for side in ["input", "output"] {
        for l in 0..25 {
            for j in 0..8 {
                c.word(format!("probe/{side}/l{l}/byte{j}"), 256)?;
            }
        }
    }
    for i in 0..200 {
        c.leaf("byte_xor_const", &[0], &[i, 200 + i])?;
    }
    c.finish()?;
    let mut names = Vec::new();
    for i in 0..200 {
        names.push(format!(
            "byte-state/{}/l{}/byte{}",
            d.round + 1,
            i / 8,
            i % 8
        ));
    }
    for i in 0..200 {
        names.push(format!("probe/{}/l{}/byte{}", d.name, i / 8, i % 8));
    }
    if names.iter().collect::<HashSet<_>>().len() != 400
        || names.iter().any(|n| !identifier(n))
        || sha256::Hash::hash(&serde_json::to_vec(&names)?).to_byte_array()
            != digest(&d.probe_global_ids_sha256)?
    {
        return Err("probe normative ordered global identities differ".into());
    }
    for i in 0..200 {
        if case.words[i] >= 256 || case.words[i] != case.words[200 + i] {
            return Err("independent probe copy assignment differs".into());
        }
    }
    for check in &case.checks {
        if !check.expected_correct || !truth(&case.spec, &case.words, check.ordinal)? {
            return Err("probe must have200 correct independent copy leaves".into());
        }
    }
    Ok(names)
}
#[derive(Clone)]
struct Cached {
    name: String,
    key: PublicKey,
    signature: Signature,
    value: u32,
    bound: u32,
    opening: Vec<Vec<u8>>,
}
fn output_cache(
    registry: &Registry,
    keys: &[PublicKey],
    signatures: &[Signature],
    values: &[u32],
    names: &[String],
    ports: &Ports,
) -> Result<Vec<Cached>> {
    (0..200)
        .map(|i| {
            let slot = *ports.outputs.get(i).ok_or("missing ordered terminal")?;
            let (ordinal, formal) = *ports.producers.get(i).ok_or("missing ordered producer")?;
            if registry
                .spec()
                .leaves
                .get(ordinal)
                .and_then(|l| l.wires.get(formal))
                != Some(&slot)
            {
                return Err("cache source is not actual terminal producer".into());
            }
            Ok(Cached {
                name: names[slot].clone(),
                key: keys[slot],
                signature: signatures[slot],
                value: values[slot],
                bound: registry.spec().words[slot].bound,
                opening: opening(registry, signatures, ordinal, slot)?,
            })
        })
        .collect()
}
fn probe_links(
    registry: &Registry,
    keys: &[PublicKey],
    signatures: &[Signature],
    values: &[u32],
    names: &[String],
    cached: &[Cached],
) -> Result<usize> {
    if cached.len() != 200
        || keys.len() != 400
        || signatures.len() != 400
        || values.len() != 400
        || names.len() != 400
    {
        return Err("exact source/probe linkage census required".into());
    }
    for (i, entry) in cached.iter().enumerate() {
        if names[i] != entry.name
            || values[i] != entry.value
            || registry.spec().words.get(i).map(|w| w.bound) != Some(entry.bound)
            || keys[i] != entry.key
            || signatures[i] != entry.signature
            || entry.opening != opening(registry, signatures, i, i)?
        {
            return Err(
                "probe changed source terminal identity/value/bound/key/signature/opening".into(),
            );
        }
    }
    Ok(cached.len())
}
fn cache_negatives(
    registry: &Registry,
    keys: &[PublicKey],
    signatures: &[Signature],
    values: &[u32],
    names: &[String],
    cached: &[Cached],
) -> Result<usize> {
    let mut count = 0;
    for index in [0, 199] {
        for mutation in 0..6 {
            let mut bad = cached.to_vec();
            match mutation {
                0 => bad[index].value ^= 1,
                1 => bad[index].bound = 2,
                2 => bad[index].key = bad[(index + 1) % 200].key,
                3 => bad[index].signature = bad[(index + 1) % 200].signature,
                4 => {
                    *bad[index]
                        .opening
                        .first_mut()
                        .and_then(|p| p.first_mut())
                        .ok_or("empty cached output opening")? ^= 1
                }
                _ => bad[index].name = bad[(index + 1) % 200].name.clone(),
            }
            if probe_links(registry, keys, signatures, values, names, &bad).is_ok() {
                return Err("altered original terminal cache accepted".into());
            }
            count += 1;
        }
    }
    Ok(count)
}
fn baseline_links(
    registry: &Registry,
    signatures: &[Signature],
    layout: &Layout,
) -> Result<(usize, usize, usize)> {
    if layout.bridges.is_empty() {
        return Ok((0, 0, 0));
    }
    let spec = registry.spec();
    let mut input_links = 0;
    let mut output_links = 0;
    let mut aux = 0;
    let mut producers = HashMap::new();
    let mut consumers: HashMap<usize, Vec<usize>> = HashMap::new();
    for (ordinal, leaf) in spec.leaves[..layout.old_leaves].iter().enumerate() {
        let (output, inputs) = leaf
            .wires
            .split_last()
            .ok_or("empty preserved Boolean leaf")?;
        if producers.insert(*output, ordinal).is_some() {
            return Err("preserved Boolean source output has multiple producers".into());
        }
        for wire in inputs {
            consumers.entry(*wire).or_default().push(ordinal);
        }
    }
    for bridge in &layout.bridges {
        if spec.leaves[bridge.reconstruct].wires != [bridge.aux, bridge.byte] {
            return Err("baseline BYTE reconstruction source differs".into());
        }
        if opening(registry, signatures, bridge.bit_leaf, bridge.aux)?
            != opening(registry, signatures, bridge.reconstruct, bridge.aux)?
        {
            return Err("baseline bits-to-reconstruction aux opening differs".into());
        }
        aux += 1;
        for bit in &bridge.bits {
            if bridge.output {
                let producer = *producers
                    .get(bit)
                    .ok_or("old output bit producer missing")?;
                if spec.leaves[producer].kind != "bool_xor" {
                    return Err("baseline old output copy producer differs".into());
                }
                if opening(registry, signatures, producer, *bit)?
                    != opening(registry, signatures, bridge.bit_leaf, *bit)?
                {
                    return Err("baseline old output-to-BYTE bit opening differs".into());
                }
                output_links += 1;
            } else {
                let uses = consumers
                    .get(bit)
                    .ok_or("old input bit consumers missing")?;
                if uses.len() != 2 {
                    return Err("exact two-use old input bit topology required".into());
                }
                for consumer in uses {
                    if opening(registry, signatures, bridge.bit_leaf, *bit)?
                        != opening(registry, signatures, *consumer, *bit)?
                    {
                        return Err("baseline BYTE-to-old input bit opening differs".into());
                    }
                    input_links += 1;
                }
            }
        }
    }
    if input_links != 3200 || output_links != 1600 || aux != 400 {
        return Err("baseline actual shared opening census differs".into());
    }
    Ok((input_links, output_links, aux))
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
        return Err("source exact byte length differs".into());
    }
    let source: Case = serde_json::from_slice(&raw)?;
    drop(raw);
    validate_case(&source, manifest, d, false)?;
    let boolean = d.profile == "boolean-honest";
    let layout = if boolean {
        boolean_layout(&source.spec, d.round)?
    } else {
        byte_layout(&source.spec, d.round)?
    };
    validate_ports(&source.spec, d.round, boolean, &layout.ports)?;
    let port_rejections = port_negatives(&source.spec, d.round, boolean, &layout.ports)?;
    if boolean {
        validate_projection(&source, d, &layout)?;
    }
    let source_names = source_names(&source.spec, d.round, boolean, &layout.ports)?;
    if sha256::Hash::hash(&serde_json::to_vec(&source_names)?).to_byte_array()
        != digest(&d.global_ids_sha256)?
    {
        return Err("source normative global identities differ".into());
    }
    let false_rows = check_assignment(&source, d, &layout)?;
    let expected = digest(&source.expected_spec_id)?;
    let secrets: Vec<_> = source_names
        .iter()
        .map(|n| seed(&expected, &source.name, n))
        .collect();
    let keys: Vec<_> = secrets.iter().map(Wots4::generate_public_key).collect();
    let signatures: Vec<_> = secrets
        .iter()
        .zip(&source.words)
        .map(|(s, v)| Wots4::compact_sign(s, &v.to_le_bytes()))
        .collect();
    collision_check(&keys, &signatures, all_keys, all_signatures)?;
    let source_id = source.spec.key_identity(&keys)?;
    let registry = Registry::new(source.spec.clone(), keys.clone(), expected, source_id)?;
    let foreign =
        Wots4::generate_public_key(&seed(&expected, &source.name, "foreign/source/test-only"));
    if keys.contains(&foreign) {
        return Err("foreign source key collision".into());
    }
    let mut native_rejections = native_negatives(&source, &keys, &signatures, foreign, &registry)?;
    let (input_links, output_links, aux_links) = baseline_links(&registry, &signatures, &layout)?;
    let mut source_ledger = execute_catalogue(&source, &registry, &signatures, sink, metrics)?;
    extend_object(
        &mut source_ledger,
        json!({"global_ids_sha256":d.global_ids_sha256,"source_sha256":d.source_sha256,"boolean_program_sha256":d.boolean_program_sha256,"boolean_catalogue_id":d.boolean_catalogue_id}),
    )?;
    let source_guards = guards(&registry, &signatures, sink, metrics, &source.name)?;
    let cached = output_cache(
        &registry,
        &keys,
        &signatures,
        &source.words,
        &source_names,
        &layout.ports,
    )?;
    // Source registries/keys remain live until their original output openings
    // have been checked against the separately generated consumer catalogue.
    let raw = snapshot(
        &root.join(&d.probe_filename),
        INPUT_CAP,
        digest(&d.probe_file_sha256)?,
    )?;
    if raw.len() as u64 != d.probe_file_bytes {
        return Err("probe exact byte length differs".into());
    }
    let probe: Case = serde_json::from_slice(&raw)?;
    drop(raw);
    validate_case(&probe, manifest, d, true)?;
    let probe_names = validate_probe(&probe, d)?;
    let mut probe_keys: Vec<_> = cached.iter().map(|e| e.key).collect();
    let mut probe_signatures: Vec<_> = cached.iter().map(|e| e.signature).collect();
    for i in 200..400 {
        let secret = seed(&expected, &source.name, &probe_names[i]);
        probe_keys.push(Wots4::generate_public_key(&secret));
        probe_signatures.push(Wots4::compact_sign(&secret, &probe.words[i].to_le_bytes()));
    }
    collision_check(
        &probe_keys[200..],
        &probe_signatures[200..],
        all_keys,
        all_signatures,
    )?;
    let probe_id = probe.spec.key_identity(&probe_keys)?;
    let probe_registry = Registry::new(
        probe.spec.clone(),
        probe_keys.clone(),
        digest(&probe.expected_spec_id)?,
        probe_id,
    )?;
    let links = probe_links(
        &probe_registry,
        &probe_keys,
        &probe_signatures,
        &probe.words,
        &probe_names,
        &cached,
    )?;
    let cache_rejections = cache_negatives(
        &probe_registry,
        &probe_keys,
        &probe_signatures,
        &probe.words,
        &probe_names,
        &cached,
    )?;
    let foreign =
        Wots4::generate_public_key(&seed(&expected, &source.name, "foreign/probe/test-only"));
    if probe_keys.contains(&foreign) {
        return Err("foreign probe key collision".into());
    }
    native_rejections += native_negatives(
        &probe,
        &probe_keys,
        &probe_signatures,
        foreign,
        &probe_registry,
    )?;
    let mut probe_ledger =
        execute_catalogue(&probe, &probe_registry, &probe_signatures, sink, metrics)?;
    extend_object(
        &mut probe_ledger,
        json!({"global_ids_sha256":d.probe_global_ids_sha256}),
    )?;
    let probe_guards = guards(
        &probe_registry,
        &probe_signatures,
        sink,
        metrics,
        &probe.name,
    )?;
    if native_rejections != 48
        || port_rejections != 8
        || cache_rejections != 12
        || links != 200
        || probe_guards != 14
    {
        return Err("single-round exact guard/opening rejection census differs".into());
    }
    let mut row = json!({"name":d.name,"profile":d.profile,"round":d.round,"field_role":d.role,"source":source_ledger,"probe":probe_ledger,"source_false_predicates":false_rows,"probe_false_predicates":[],"source_predicates_checked":source.spec.leaves.len(),"probe_predicates_checked":200});
    extend_object(
        &mut row,
        json!({"producer_opening_links":links,"cached_output_entries":cached.len(),"probe_input_key_value_bound_signature_matches":links,"baseline_input_bit_opening_links":input_links,"baseline_output_bit_opening_links":output_links,"baseline_internal_bit_opening_links":input_links+output_links,"baseline_aux_opening_links":aux_links}),
    )?;
    extend_object(
        &mut row,
        json!({"guard_vectors":source_guards+probe_guards,"source_guard_layouts":source_guards/14,"probe_guard_layouts":probe_guards/14,"native_rejections":native_rejections,"port_rejections":port_rejections,"probe_cache_rejections":cache_rejections,"source_signature_entries_created":source.words.len(),"probe_fresh_signature_entries_created":200,"probe_cached_signature_reuses":200,"wall_seconds":started.elapsed().as_secs_f64()}),
    )?;
    Ok(row)
}
fn run() -> Result<Value> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 5 {
        return Err(
            "usage: byte_keccak_round MANIFEST CASE_DIR OUTPUT EXPECTED_MANIFEST_SHA256".into(),
        );
    }
    if std::env::var("GITHUB_ACTIONS").as_deref() != Ok("true")
        || std::env::var("RUNNER_OS").as_deref() != Ok("Linux")
        || !cfg!(target_os = "linux")
    {
        return Err("single BYTE Keccak round execution is hosted GitHub Linux only".into());
    }
    let started = Instant::now();
    let expected = digest(&args[4])?;
    let raw = snapshot(Path::new(&args[1]), MANIFEST_CAP, expected)?;
    let manifest: Manifest = serde_json::from_slice(&raw)?;
    drop(raw);
    validate_manifest(&manifest)?;
    let source = Path::new(&args[2]);
    if fs::symlink_metadata(source)?.file_type().is_symlink() {
        return Err("case directory symlink forbidden".into());
    }
    let root = fs::canonicalize(source)?;
    if !root.is_dir() || fs::canonicalize(&args[1])? != root.join("manifest.json") {
        return Err("exact canonical source directory/manifest required".into());
    }
    let mut inventory = HashSet::from(["manifest.json".to_owned()]);
    for d in &manifest.cases {
        inventory.insert(d.filename.clone());
        inventory.insert(d.probe_filename.clone());
    }
    let actual: HashSet<_> = fs::read_dir(&root)?
        .map(|e| e.map(|e| e.file_name().to_string_lossy().into_owned()))
        .collect::<std::io::Result<_>>()?;
    if actual != inventory {
        return Err(
            "source directory must contain exactly the trusted129manifest/case/probe files".into(),
        );
    }
    let mut sink = VectorSink {
        hash: sha256::Hash::engine(),
        bytes: 0,
    };
    let mut metrics = Metrics::default();
    let mut rows = Vec::new();
    let mut keys = HashSet::new();
    let mut signatures = HashSet::new();
    for desc in &manifest.cases {
        rows.push(case_run(
            &manifest,
            desc,
            &root,
            &mut sink,
            &mut metrics,
            &mut keys,
            &mut signatures,
        )?);
    }
    if keys.len() != signatures.len() {
        return Err("all fresh key/signature creation counts differ".into());
    }
    let mut result = json!({"schema":"bitvm2-nova-byte-keccak-round-execution/v1","passed":true,
        "input_manifest_sha256":hex::encode(expected),"metrics":metrics,"cases":rows,
        "compact_execution_records_bytes":sink.bytes,"compact_execution_records_sha256":sha256::Hash::from_engine(sink.hash).to_string(),
        "fresh_signature_entries_created":keys.len(),"cached_signature_reuses":64*200});
    extend_object(
        &mut result,
        json!({"test_keys_only":true,"stack_limit_enabled":true,
        "one_round_script_conformance_checked":true,"all_source_and_probe_leaves_executed":true,
        "producer_opening_links_checked":true,"raw_vector_file_written":false,"op_cat_enabled":false,
        "full_24_round_composition_verified":false,"full_permutation_verified":false,"full_hash_verified":false}),
    )?;
    extend_object(
        &mut result,
        json!({"transcript_verified":false,"proof_verified":false,
        "complete_nova_verifier":false,"complete_bitvm2_verifier":false,"production_assertion_binding":false,
        "bitcoin_transaction_graph":false,"panic_is_rejection":false,"baseline_bytes_are_free":false}),
    )?;
    extend_object(
        &mut result,
        json!({"setup_calls":0,"proving_jobs":0,"native_proofs_verified":0,
        "gpu_jobs":0,"transactions_broadcast":0,"wall_seconds":started.elapsed().as_secs_f64()}),
    )?;
    let encoded = serde_json::to_vec(&result)?;
    if encoded.len() > SUMMARY_CAP {
        return Err("single-round summary exceeds unchanged1MiB cap".into());
    }
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&args[3])?;
    output.write_all(&encoded)?;
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
    fn strict_json_rejects_duplicate_unknown_and_non_integer_fields() {
        for raw in [
            r#"{"ordinal":0,"ordinal":1,"expected_correct":true}"#,
            r#"{"ordinal":1.0,"expected_correct":true}"#,
            r#"{"ordinal":0,"expected_correct":1}"#,
            r#"{"ordinal":0,"expected_correct":true,"extra":0}"#,
        ] {
            assert!(serde_json::from_str::<Check>(raw).is_err());
        }
    }
    #[test]
    fn digest_and_state_transport_is_canonical_and_bounded() {
        assert!(digest(&"00".repeat(32)).is_ok());
        assert!(digest(&"AA".repeat(32)).is_err());
        assert!(state(&"00".repeat(200)).is_ok());
        assert!(state(&"00".repeat(199)).is_err());
        assert!(state(&"AA".repeat(200)).is_err());
    }
    #[test]
    fn round_reference_matches_the_zero_state_first_round_constant() {
        let actual = reference(&[0; 200], 0);
        assert_eq!(actual[0], 1);
        assert!(actual[1..].iter().all(|b| *b == 0));
        let actual = reference(&[0; 200], 23);
        assert_eq!(&actual[..8], &RC[23].to_le_bytes());
        assert!(actual[8..].iter().all(|b| *b == 0));
    }
    #[test]
    fn sparse_iota_bytes_select_natural_actual_producers_not_last200_words() {
        for r in 0..24 {
            let masks = RC[r].to_le_bytes();
            let n = masks.iter().filter(|m| **m != 0).count();
            assert!((1..=4).contains(&n));
            let mut ordinals = HashSet::new();
            for slot in 0..200 {
                let ordinal = if slot < 8 && masks[slot] != 0 {
                    1216 + masks[..slot].iter().filter(|m| **m != 0).count()
                } else {
                    1016 + slot
                };
                assert!(ordinals.insert(ordinal));
                assert!(ordinal < 1216 + n);
            }
            assert_eq!(ordinals.len(), 200);
        }
    }
    #[test]
    fn rho_pi_schedule_is_bijective_and_keeps_176_cross_byte_gates() {
        let mut targets = HashSet::new();
        let mut gates = 0;
        for y in 0..5 {
            for x in 0..5 {
                assert!(targets.insert(y + 5 * ((2 * x + 3 * y) % 5)));
                if RHO[y][x] % 8 != 0 {
                    gates += 8;
                }
            }
        }
        assert_eq!(targets.len(), 25);
        assert_eq!(gates, 176);
    }
    // Descriptor-admission-only fixtures: placeholder hashes are never used to
    // construct a graph, create a key or execute a purported Script proof.
    fn manifest_fixture() -> Manifest {
        let mut cases = Vec::new();
        for role in ["pallas_scalar", "vesta_scalar"] {
            let mut profiles: Vec<_> = (0..24).map(|r| (r, "byte-honest")).collect();
            profiles.extend([
                (0, "byte-wrong-output"),
                (23, "byte-wrong-output"),
                (0, "byte-oversized"),
                (23, "byte-oversized"),
                (0, "boolean-honest"),
                (1, "boolean-honest"),
                (2, "boolean-honest"),
                (23, "boolean-honest"),
            ]);
            for (r, profile) in profiles {
                let index = cases.len();
                let boolean = profile == "boolean-honest";
                let short = profile.strip_prefix("byte-").unwrap_or("");
                let input: Vec<_> = (0..200)
                    .map(|i| ((37 * i + 11 + 17 * r) & 255) as u8)
                    .collect();
                let input: [u8; 200] = input.try_into().unwrap();
                let mut out = reference(&input, r);
                if profile == "byte-wrong-output" {
                    out[if r == 0 { 0 } else { 8 }] ^= 1;
                }
                let leaves = if boolean {
                    10401 + RC[r].count_ones() as usize
                } else {
                    1216 + RC[r].to_le_bytes().iter().filter(|b| **b != 0).count()
                };
                cases.push(Descriptor {
                    name: if boolean {
                        format!("{role}/boolean-r{r}")
                    } else {
                        format!("{role}/byte-r{r}-{short}")
                    },
                    profile: profile.into(),
                    role: role.into(),
                    round: r,
                    filename: format!("case-{index:02}.json"),
                    file_sha256: "00".repeat(32),
                    file_bytes: 1,
                    catalogue_id: "00".repeat(32),
                    program_sha256: "00".repeat(32),
                    global_ids_sha256: "00".repeat(32),
                    source_sha256: "00".repeat(32),
                    words: if boolean {
                        12001 + RC[r].count_ones() as usize
                    } else {
                        200 + leaves
                    },
                    leaves,
                    input_state_hex: hex::encode(input),
                    expected_output_state_hex: hex::encode(out),
                    expected_false: vec![],
                    boolean_program_sha256: boolean.then(|| "00".repeat(32)),
                    boolean_catalogue_id: boolean.then(|| "00".repeat(32)),
                    probe_filename: format!("probe-{index:02}.json"),
                    probe_file_sha256: "00".repeat(32),
                    probe_file_bytes: 1,
                    probe_catalogue_id: "00".repeat(32),
                    probe_program_sha256: "00".repeat(32),
                    probe_global_ids_sha256: "00".repeat(32),
                    probe_words: 400,
                    probe_leaves: 200,
                });
            }
        }
        Manifest {
            schema: "bitvm2-nova-byte-keccak-round-run/v1".into(),
            context: "00".repeat(32),
            operation_id: "test/manifest-admission".into(),
            cases,
        }
    }
    #[test]
    fn manifest_rejects_partial_legacy_labels_and_incomplete_round_coverage() {
        let mut m = manifest_fixture();
        assert!(validate_manifest(&m).is_ok());
        m.cases[0].boolean_program_sha256 = Some("00".repeat(32));
        assert!(validate_manifest(&m).is_err());
        m.cases[0].boolean_program_sha256 = None;
        m.cases[0].boolean_catalogue_id = Some("00".repeat(32));
        assert!(validate_manifest(&m).is_err());
        m.cases[0].boolean_catalogue_id = None;
        m.cases[28].boolean_program_sha256 = None;
        assert!(validate_manifest(&m).is_err());
        let mut m = manifest_fixture();
        m.cases.pop();
        assert!(validate_manifest(&m).is_err());
    }
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
    h.input(b"BITVM2-NOVA/TEST-ONLY-BYTE-KECCAK-ROUND-WOTS/v1\0");
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
