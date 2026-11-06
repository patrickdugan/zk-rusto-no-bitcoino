//! Hosted TEST-ONLY byte predicates and complete Boolean conversion baselines.
//! Fresh input bytes are pinned out of band. No raw vectors, proofs, transaction
//! constructors, production keys, panic catcher or acceptance receipts.
use bitcoin::{
    hashes::{sha256, Hash, HashEngine},
    ScriptBuf,
};
use bitvm::signatures::{CompactWots, Wots, Wots4};
use bitvm2_nova_script_oracle::{
    engine::{emit, execute, Metrics},
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
fn snapshot(path: &Path, expected: [u8; 32]) -> Result<Vec<u8>> {
    let before = fs::symlink_metadata(path)?;
    if before.file_type().is_symlink() || !before.is_file() || before.len() > INPUT_CAP {
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
    file.take(INPUT_CAP + 1).read_to_end(&mut raw)?;
    if raw.len() as u64 != before.len()
        || raw.len() as u64 > INPUT_CAP
        || sha256::Hash::hash(&raw).to_byte_array() != expected
    {
        return Err("byte input snapshot length/digest mismatch".into());
    }
    Ok(raw)
}
fn validate_case(case: &Case) -> Result<()> {
    if !identifier(&case.name)
        || !case.measure_all
        || case.spec.words.len() > 4096
        || case.spec.leaves.len() > 4096
        || case.words.len() != case.spec.words.len()
        || case.checks.len() != case.spec.leaves.len()
        || case.checks.iter().enumerate().any(|(i, c)| c.ordinal != i)
        || case.spec.identity()? != digest(&case.expected_spec_id)?
        || case.spec.leaves.iter().any(|l| {
            !BYTE_KINDS.contains(&l.kind.as_str())
                && !matches!(
                    l.kind.as_str(),
                    "bits" | "conv_reconstruct" | "bool_xor" | "bool_and" | "bool_not" | "const"
                )
        })
    {
        return Err("exact bounded byte case/catalogue/check census required".into());
    }
    Ok(())
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
    h.input(b"BITVM2-NOVA/TEST-ONLY-BYTE-KERNEL-WOTS/v1\0");
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

struct VectorSink {
    hash: sha256::HashEngine,
    bytes: u64,
}
impl Write for VectorSink {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        let next = self
            .bytes
            .checked_add(data.len() as u64)
            .ok_or_else(|| std::io::Error::other("byte vector size overflow"))?;
        if next > VECTOR_HASH_CAP {
            return Err(std::io::Error::other("byte vector hash cap"));
        }
        self.hash.input(data);
        self.bytes = next;
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
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
fn guards(
    registry: &Registry,
    signatures: &[Signature],
    foreign: Signature,
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
                emit(
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
                *bad[position].first_mut().ok_or("empty byte WOTS digit")? ^= 1;
                emit(
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
            other[slot] = if signatures.len() > 1 {
                signatures[(slot + 1) % signatures.len()]
            } else {
                foreign
            };
            emit(
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
fn baseline_links(
    case: &Case,
    registry: &Registry,
    signatures: &[Signature],
) -> Result<(usize, usize)> {
    if !case.name.contains("/boolean-") {
        return Ok((0, 0));
    }
    let spec = &case.spec;
    let kind = if case.name.contains("/boolean-xor") {
        "bool_xor"
    } else if case.name.contains("/boolean-and") {
        "bool_and"
    } else if case.name.contains("/boolean-not") {
        "bool_not"
    } else {
        return Err("unknown complete Boolean baseline".into());
    };
    let ports: Vec<_> = spec
        .words
        .iter()
        .enumerate()
        .filter(|(_, w)| w.bound == 256)
        .collect();
    if ports.is_empty()
        || ports.len() > 3
        || spec.words.len() != 10 * ports.len()
        || spec.leaves.len() != 2 * ports.len() + 8
    {
        return Err("complete BYTE conversion baseline census required".into());
    }
    let mut bit_sources = HashMap::new();
    let mut aux_links = 0;
    for (byte, word) in &ports {
        if !["a", "b", "out"].contains(&word.name.as_str()) {
            return Err("baseline external BYTE port name".into());
        }
        let find = |name: String, bound: u32| -> Result<usize> {
            spec.words
                .iter()
                .position(|w| w.name == name && w.bound == bound)
                .ok_or_else(|| "missing exact baseline reconstruction wire".into())
        };
        let aux = find(format!("{}/aux", word.name), 1 << 29)?;
        let mut bits = Vec::new();
        for bit in 0..8 {
            bits.push(find(format!("{}/bits/{bit}", word.name), 2)?);
        }
        let mut wires = vec![aux];
        wires.extend(bits.iter().rev());
        let producers: Vec<_> = spec
            .leaves
            .iter()
            .enumerate()
            .filter(|(_, l)| l.kind == "bits" && l.argument == [8] && l.wires == wires)
            .collect();
        let consumers: Vec<_> = spec
            .leaves
            .iter()
            .enumerate()
            .filter(|(_, l)| {
                l.kind == "conv_reconstruct" && l.argument == [8] && l.wires == [aux, *byte]
            })
            .collect();
        if producers.len() != 1 || consumers.len() != 1 {
            return Err("baseline BYTE reconstruction missing/aliased".into());
        }
        let producer = producers[0].0;
        let consumer = consumers[0].0;
        if opening(registry, signatures, producer, aux)?
            != opening(registry, signatures, consumer, aux)?
        {
            return Err("baseline aux opening differs".into());
        }
        aux_links += 1;
        for (bit, wire) in bits.iter().enumerate() {
            if bit_sources
                .insert(*wire, (producer, bit, word.name.as_str()))
                .is_some()
            {
                return Err("baseline bit aliases between BYTE ports".into());
            }
        }
    }
    let bools: Vec<_> = spec
        .leaves
        .iter()
        .enumerate()
        .filter(|(_, l)| l.kind == kind)
        .collect();
    if bools.len() != 8 {
        return Err("baseline must retain all eight Boolean predicates".into());
    }
    let mut formal_ports = None;
    let mut bit_links = 0;
    for (bit, (ordinal, leaf)) in bools.iter().enumerate() {
        let mut formal = Vec::new();
        for wire in &leaf.wires {
            let (_, source_bit, port) =
                bit_sources.get(wire).ok_or("baseline bool source absent")?;
            if *source_bit != bit {
                return Err("baseline bool byte bit order differs".into());
            }
            formal.push(*port);
        }
        if let Some(expected) = &formal_ports {
            if *expected != formal {
                return Err("baseline formal alias partition changes by bit".into());
            }
        } else {
            formal_ports = Some(formal);
        }
        for wire in registry.unique_slots(*ordinal)? {
            let (producer, _, _) = bit_sources.get(&wire).ok_or("baseline bit owner absent")?;
            if opening(registry, signatures, *producer, wire)?
                != opening(registry, signatures, *ordinal, wire)?
            {
                return Err("baseline bit opening differs".into());
            }
            bit_links += 1;
        }
    }
    let expected_ports = if kind == "bool_not" {
        vec!["a", "out"]
    } else if case.name.ends_with("-alias-ab") {
        vec!["a", "a", "out"]
    } else if case.name.ends_with("-alias-out-a") {
        vec!["a", "b", "a"]
    } else if case.name.ends_with("-alias-all") {
        vec!["a", "a", "a"]
    } else {
        vec!["a", "b", "out"]
    };
    if formal_ports != Some(expected_ports.clone())
        || ports.len() != expected_ports.into_iter().collect::<HashSet<_>>().len()
    {
        return Err("baseline BYTE formal ports differ from exact comparison/alias profile".into());
    }
    Ok((bit_links, aux_links))
}
fn script_num(mut value: u32) -> Vec<u8> {
    if value == 0 {
        return vec![];
    }
    let mut raw = Vec::new();
    while value != 0 {
        raw.push((value & 255) as u8);
        value >>= 8;
    }
    if raw.last().is_some_and(|n| n & 128 != 0) {
        raw.push(0);
    }
    raw
}
fn family(role: &str) -> Result<&'static str> {
    match role {
        "pallas_base" | "vesta_scalar" => Ok("P"),
        "pallas_scalar" | "vesta_base" => Ok("Q"),
        _ => Err("unsupported byte field role".into()),
    }
}
fn exhaustive(bodies: &BTreeMap<(String, String), Vec<u8>>) -> Result<Value> {
    let mut pairs = 0;
    let mut executions = 0;
    let mut stack = 0;
    let mut inverse_probes = 0;
    let started = Instant::now();
    let boundaries = [
        0, 1, 2, 7, 15, 16, 31, 63, 64, 85, 127, 128, 129, 170, 254, 255,
    ];
    for kind in ["byte_xor", "byte_and"] {
        let p = bodies
            .get(&(kind.into(), "P".into()))
            .ok_or("missing P bare byte body")?;
        let q = bodies
            .get(&(kind.into(), "Q".into()))
            .ok_or("missing Q bare byte body")?;
        if p != q {
            return Err("actual P/Q bare byte predicate bodies differ".into());
        }
        let code = ScriptBuf::from_bytes(p.clone());
        let mut inverse = p.clone();
        inverse.push(0x91);
        let inverse = ScriptBuf::from_bytes(inverse);
        for a in 0..256u32 {
            for b in 0..256u32 {
                let out = if kind == "byte_xor" { a ^ b } else { a & b };
                let mut probes = vec![(out, &code, true)];
                if boundaries.contains(&a) && boundaries.contains(&b) {
                    probes.extend([
                        (out, &inverse, false),
                        (out ^ 1, &code, false),
                        (out ^ 1, &inverse, true),
                    ]);
                    inverse_probes += 1;
                }
                for (value, script, expected) in probes {
                    let (success, peak) = execute(
                        script,
                        vec![script_num(a), script_num(b), script_num(value)],
                    )?;
                    if success != expected {
                        return Err(format!("bare exhaustive {kind}({a},{b},{value}) ordinary truth/inverse mismatch").into());
                    }
                    executions += 1;
                    stack = stack.max(peak);
                }
                pairs += 1;
            }
        }
    }
    Ok(
        json!({"pairs":pairs,"engine_executions":executions,"max_stack_items":stack,"p_q_actual_body_bytes_equal":true,"ordinary_false_inverse_probes":inverse_probes,"correctness_inverse_probes":inverse_probes,"panic_is_rejection":false,"wall_seconds":started.elapsed().as_secs_f64()}),
    )
}

fn numeric_abort_probes(bodies: &BTreeMap<String, (Vec<u8>, Vec<u32>)>) -> Result<(usize, usize)> {
    if bodies.len() != 5 {
        return Err("all five canonical byte bodies needed for numeric abort probes".into());
    }
    let invalid = [
        vec![0x00],
        vec![0x80],
        vec![0x01, 0x00],
        vec![0x01, 0x00, 0x00, 0x00, 0x00],
        vec![0x81],
        vec![0x00, 0x01],
    ];
    let mut probes = 0;
    let mut executions = 0;
    for (body, values) in bodies.values() {
        let code = ScriptBuf::from_bytes(body.clone());
        let mut inverse = body.clone();
        inverse.push(0x91);
        let inverse = ScriptBuf::from_bytes(inverse);
        let witness: Vec<_> = values.iter().map(|v| script_num(*v)).collect();
        for formal in 0..values.len() {
            for value in &invalid {
                let mut bad = witness.clone();
                bad[formal] = value.clone();
                for script in [&code, &inverse] {
                    if execute(script, bad.clone())?.0 {
                        return Err(
                            "bare malformed numeric operand became correctness or disproof success"
                                .into(),
                        );
                    }
                    executions += 1;
                }
                probes += 1;
            }
        }
    }
    if probes != 78 || executions != 156 {
        return Err("bare malformed numeric probe census changed".into());
    }
    Ok((probes, executions))
}
fn extend_object(target: &mut Value, extra: Value) -> Result<()> {
    let (Value::Object(target), Value::Object(extra)) = (target, extra) else {
        return Err("internal byte summary object type".into());
    };
    for (key, value) in extra {
        if target.insert(key, value).is_some() {
            return Err("duplicate byte summary field".into());
        }
    }
    Ok(())
}
fn run() -> Result<Value> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 4 {
        return Err("usage: byte_kernels INPUT OUTPUT EXPECTED_INPUT_SHA256".into());
    }
    if std::env::var("GITHUB_ACTIONS").as_deref() != Ok("true")
        || std::env::var("RUNNER_OS").as_deref() != Ok("Linux")
        || !cfg!(target_os = "linux")
    {
        return Err("byte kernel execution is hosted GitHub Linux only".into());
    }
    let started = Instant::now();
    let expected = digest(&args[3])?;
    let raw = snapshot(Path::new(&args[1]), expected)?;
    let cases: Vec<Case> = serde_json::from_slice(&raw)?;
    drop(raw);
    if cases.is_empty() || cases.len() > 64 {
        return Err("byte case count1..64 required".into());
    }
    let mut names = HashSet::new();
    for case in &cases {
        validate_case(case)?;
        if !names.insert(&case.name) {
            return Err("duplicate byte signing session".into());
        }
    }
    let mut metrics = Metrics::default();
    let mut sink = VectorSink {
        hash: sha256::Hash::engine(),
        bytes: 0,
    };
    let mut ledger = Vec::new();
    let mut native_rejections = 0;
    let mut normal = 0;
    let mut guard_vectors = 0;
    let mut signatures_count = 0;
    let mut bit_links = 0;
    let mut aux_links = 0;
    let mut bare_bodies = BTreeMap::new();
    let mut numeric_bodies = BTreeMap::new();
    let mut field_bodies: BTreeMap<(String, Vec<i64>, Vec<usize>), BTreeMap<String, Vec<u8>>> =
        BTreeMap::new();
    for case in &cases {
        let expected = digest(&case.expected_spec_id)?;
        let secrets: Vec<_> = case
            .spec
            .words
            .iter()
            .map(|w| seed(&expected, &case.name, &w.name))
            .collect();
        let keys: Vec<PublicKey> = secrets.iter().map(Wots4::generate_public_key).collect();
        let id = case.spec.key_identity(&keys)?;
        let registry = Registry::new(case.spec.clone(), keys.clone(), expected, id)?;
        let signatures: Vec<Signature> = secrets
            .iter()
            .zip(&case.words)
            .map(|(s, v)| Wots4::compact_sign(s, &v.to_le_bytes()))
            .collect();
        signatures_count += signatures.len();
        let foreign_secret = seed(&expected, &case.name, "foreign/test-only/key");
        let foreign_key = Wots4::generate_public_key(&foreign_secret);
        if keys.contains(&foreign_key) {
            return Err("foreign byte fixture key collides with a declared wire".into());
        }
        let foreign_signature = Wots4::compact_sign(&foreign_secret, &case.words[0].to_le_bytes());
        native_rejections += native_negatives(case, &keys, &signatures, foreign_key, &registry)?;
        let (bits, aux) = baseline_links(case, &registry, &signatures)?;
        bit_links += bits;
        aux_links += aux;
        let mut costs = Vec::new();
        let mut sum = 0usize;
        let mut largest = 0usize;
        let mut stream = sha256::Hash::engine();
        for check in &case.checks {
            if truth(&case.spec, &case.words, check.ordinal)? != check.expected_correct {
                return Err(
                    "byte case expected claim differs from independent integer truth".into(),
                );
            }
            let witness = registry.witness(check.ordinal, &signatures)?;
            for disprove in [false, true] {
                let code = registry.script(check.ordinal, disprove)?;
                emit(
                    &mut sink,
                    &mut metrics,
                    &code,
                    &witness,
                    check.expected_correct != disprove,
                    &format!("{}/leaf/{}/{disprove}", case.name, check.ordinal),
                )?;
                if disprove {
                    sum += code.len();
                    largest = largest.max(code.len());
                    stream.input(&(code.len() as u32).to_le_bytes());
                    stream.input(code.as_bytes());
                    costs.push(json!({"ordinal":check.ordinal,"kind":case.spec.leaves[check.ordinal].kind,"argument":case.spec.leaves[check.ordinal].argument,"disproof_script_bytes":code.len()}));
                }
            }
            normal += 1;
            let leaf = &case.spec.leaves[check.ordinal];
            if ["byte_xor", "byte_and"].contains(&leaf.kind.as_str())
                && leaf.wires.iter().collect::<HashSet<_>>().len() == 3
            {
                let body = hex::decode(
                    case.spec
                        .bodies
                        .get(&leaf.body_sha256)
                        .ok_or("bare byte body absent")?,
                )?;
                let key = (leaf.kind.clone(), family(&case.spec.field_role)?.to_owned());
                if let Some(old) = bare_bodies.insert(key, body.clone()) {
                    if old != body {
                        return Err("same field/kind plain byte bodies differ".into());
                    }
                }
            }
            if BYTE_KINDS.contains(&leaf.kind.as_str()) {
                let (_, _, aliases) = auth_shape(&case.spec, check.ordinal);
                let shape = (leaf.kind.clone(), leaf.argument.clone(), aliases);
                let body = hex::decode(
                    case.spec
                        .bodies
                        .get(&leaf.body_sha256)
                        .ok_or("byte field comparison body absent")?,
                )?;
                let field_family = family(&case.spec.field_role)?.to_owned();
                let entry = field_bodies.entry(shape).or_default();
                if let Some(old) = entry.insert(field_family, body.clone()) {
                    if old != body {
                        return Err("byte body shape changed within one field family".into());
                    }
                }
                if family(&case.spec.field_role)? == "P"
                    && check.expected_correct
                    && leaf.wires.iter().collect::<HashSet<_>>().len() == leaf.wires.len()
                    && matches!(
                        (leaf.kind.as_str(), leaf.argument.as_slice()),
                        ("byte_xor", [])
                            | ("byte_and", [])
                            | ("byte_not", [])
                            | ("byte_rol", [3])
                            | ("byte_xor_const", [129])
                    )
                {
                    numeric_bodies.entry(leaf.kind.clone()).or_insert_with(|| {
                        (
                            body,
                            leaf.wires
                                .iter()
                                .map(|i| case.words[*i])
                                .collect::<Vec<_>>(),
                        )
                    });
                }
            }
        }
        guard_vectors += guards(
            &registry,
            &signatures,
            foreign_signature,
            &mut sink,
            &mut metrics,
            &case.name,
        )?;
        ledger.push(json!({"case":case.name,"catalogue_id":case.expected_spec_id,"registry_id":hex::encode(id),"words":case.spec.words.len(),"leaves":case.spec.leaves.len(),"executed_leaves":case.checks.len(),"all_disproof_script_bytes":sum,"largest_disproof_leaf_bytes":largest,"leaf_stream_sha256":sha256::Hash::from_engine(stream).to_string(),"leaf_costs":costs}));
    }
    for fields in field_bodies.values() {
        if fields.len() != 2 || fields.get("P") != fields.get("Q") {
            return Err(
                "actual byte kernel/parameter/alias bodies differ across P/Q fields".into(),
            );
        }
    }
    if field_bodies.is_empty() {
        return Err("no actual byte body field comparison".into());
    }
    let bare = exhaustive(&bare_bodies)?;
    let (numeric_probes, numeric_executions) = numeric_abort_probes(&numeric_bodies)?;
    let mut result = json!({"schema":"bitvm2-nova-byte-kernel-execution/v1","passed":true,
        "input_sha256":hex::encode(expected),"cases":cases.len(),"metrics":metrics,"ledger":ledger,
        "native_rejections":native_rejections,"normal_leaf_checks":normal,"guard_vectors":guard_vectors,
        "signatures_generated_once_per_wire":signatures_count,
        "shared_baseline_bit_opening_links":bit_links,"shared_baseline_aux_opening_links":aux_links});
    extend_object(
        &mut result,
        json!({"bare_exhaustive_pairs":bare["pairs"],
        "bare_exhaustive_engine_executions":bare["engine_executions"],
        "ordinary_false_inverse_probes":bare["ordinary_false_inverse_probes"],
        "correctness_inverse_probes":bare["correctness_inverse_probes"],"bare_exhaustive":bare,
        "body_equality_across_fields_checked":true,"field_body_shapes_compared":field_bodies.len(),
        "selected_vectors_hashed_bytes":sink.bytes,"selected_vectors_sha256":sha256::Hash::from_engine(sink.hash).to_string()}),
    )?;
    extend_object(
        &mut result,
        json!({"bare_numeric_abort_probes":numeric_probes,
        "bare_numeric_abort_engine_executions":numeric_executions}),
    )?;
    extend_object(
        &mut result,
        json!({"raw_vector_file_written":false,"test_keys_only":true,
        "stack_limit_enabled":true,"op_cat_enabled":false,"full_permutation_verified":false,
        "full_hash_verified":false,"transcript_verified":false,"proof_verified":false,
        "complete_nova_verifier":false,"complete_bitvm2_verifier":false,
        "production_assertion_binding":false,"bitcoin_transaction_graph":false}),
    )?;
    extend_object(
        &mut result,
        json!({"transactions_broadcast":0,"native_proofs_verified":0,
        "proving_jobs":0,"gpu_jobs":0,"setup_calls":0,"panic_is_rejection":false,
        "wall_seconds":started.elapsed().as_secs_f64()}),
    )?;
    let encoded = serde_json::to_vec(&result)?;
    if encoded.len() > SUMMARY_CAP {
        return Err("byte native summary exceeds1MiB".into());
    }
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&args[2])?;
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
    // Admission-only stubs: the dummy OP_TRUE body is never executed and makes
    // no byte arithmetic or cryptographic verification claim.
    fn case() -> Case {
        let body = sha256::Hash::hash(&[0x51]).to_string();
        let spec = GraphSpec {
            program_sha256: "00".repeat(32),
            context: "00".repeat(32),
            field_role: "pallas_scalar".into(),
            operation_id: "test/byte-admission".into(),
            words: (0..3)
                .map(|i| bitvm2_nova_script_oracle::registry::Word {
                    name: format!("w{i}"),
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
        };
        Case {
            name: "test/admission-only".into(),
            expected_spec_id: hex::encode(spec.identity().unwrap()),
            spec,
            words: vec![1, 2, 3],
            checks: vec![Check {
                ordinal: 0,
                expected_correct: true,
            }],
            measure_all: true,
        }
    }
    #[test]
    fn strict_word_transport_rejects_non_u32_and_duplicate_case_fields() {
        let valid = case();
        let raw=serde_json::to_value(json!({"name":valid.name,"spec":valid.spec,"expected_spec_id":valid.expected_spec_id,"words":valid.words,"checks":[{"ordinal":0,"expected_correct":true}],"measure_all":true})).unwrap();
        for value in [
            json!(-1),
            json!(1.0),
            json!(true),
            json!("1"),
            json!(4294967296u64),
        ] {
            let mut bad = raw.clone();
            bad["words"][0] = value;
            assert!(serde_json::from_value::<Case>(bad).is_err());
        }
        assert!(serde_json::from_str::<Check>(
            r#"{"ordinal":0,"ordinal":0,"expected_correct":true}"#
        )
        .is_err());
    }
    #[test]
    fn strict_checks_reject_unknown_and_non_boolean_result_fields() {
        for raw in [
            r#"{"ordinal":0,"expected_correct":1}"#,
            r#"{"ordinal":0,"expected_correct":true,"extra":0}"#,
            r#"{"ordinal":-1,"expected_correct":true}"#,
        ] {
            assert!(serde_json::from_str::<Check>(raw).is_err());
        }
    }
    #[test]
    fn all_ordered_leaf_checks_are_mandatory() {
        let valid = case();
        assert!(validate_case(&valid).is_ok());
        let mut bad = valid.clone();
        bad.checks.clear();
        assert!(validate_case(&bad).is_err());
        let mut bad = valid.clone();
        bad.checks[0].ordinal = 1;
        assert!(validate_case(&bad).is_err());
        let mut bad = valid;
        bad.measure_all = false;
        assert!(validate_case(&bad).is_err());
    }
    #[test]
    fn invalid_shape_is_rejected_before_native_truth_and_signed_u32_is_preserved() {
        let valid = case();
        let mut bad = valid.clone();
        bad.spec.leaves[0].argument = vec![-1];
        assert!(validate_case(&bad).is_err());
        let mut bad = valid.clone();
        bad.spec.words[0].bound = 2;
        assert!(validate_case(&bad).is_err());
        let mut signed = valid;
        signed.words[0] = u32::MAX;
        assert!(validate_case(&signed).is_ok());
        assert!(!truth(&signed.spec, &signed.words, 0).unwrap());
    }
    #[test]
    fn canonical_digests_and_minimal_unsigned_script_numbers_are_exact() {
        assert!(digest(&"00".repeat(32)).is_ok());
        assert!(digest(&"AA".repeat(32)).is_err());
        assert!(digest(&"00".repeat(31)).is_err());
        for (value, raw) in [
            (0, vec![]),
            (127, vec![127]),
            (128, vec![128, 0]),
            (255, vec![255, 0]),
            (256, vec![0, 1]),
        ] {
            assert_eq!(script_num(value), raw);
        }
    }
}
