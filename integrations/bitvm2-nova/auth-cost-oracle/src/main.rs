//! Bounded, hosted-only authentication cost comparison. No production receipts.
mod body_pins;
mod engine;
mod hints;
mod keys;
mod registry;
mod source;
mod transport;
use bitcoin::{
    hashes::{hash160, sha256, Hash, HashEngine},
    ScriptBuf,
};
use bitvm::signatures::{Wots, Wots4};
use bitvm2_nova_script_oracle::wots::{id32, Result};
use registry::{Adapter, GraphSpec, Mode, Registry};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, HashMap},
    fs,
    io::{self, Write},
    path::Path,
    time::Instant,
};

const RECORD_CAP: usize = 128 << 20;
const SUMMARY_CAP: usize = 1 << 20;
const ADAPTERS: [Adapter; 2] = [Adapter::Compact, Adapter::Bound256Hinted];
const MALFORMED_HINTS: [&[u8]; 10] = [
    &[0],
    &[0x80],
    &[0x81],
    &[16],
    &[17],
    &[1, 0],
    &[0, 0],
    &[1, 0, 0, 0, 0],
    &[255],
    &[0, 1],
];
fn ensure(yes: bool, message: &str) -> Result<()> {
    if yes {
        Ok(())
    } else {
        Err(message.into())
    }
}
fn sha(bytes: &[u8]) -> String {
    sha256::Hash::hash(bytes).to_string()
}
fn counter(value: &Value, key: &str) -> Result<usize> {
    let number = value
        .get(key)
        .and_then(Value::as_u64)
        .ok_or("typed internal summary counter")?;
    Ok(usize::try_from(number)?)
}
fn framed(h: &mut sha256::HashEngine, bytes: &[u8]) {
    h.input(&(bytes.len() as u64).to_le_bytes());
    h.input(bytes);
}
fn witness_hash(witness: &[Vec<u8>]) -> String {
    let mut h = sha256::Hash::engine();
    h.input(&(witness.len() as u64).to_le_bytes());
    for cell in witness {
        framed(&mut h, cell);
    }
    sha256::Hash::from_engine(h).to_string()
}
fn fold_metrics(aggregate: &mut engine::Metrics, local: &engine::Metrics) {
    aggregate.vectors += local.vectors;
    aggregate.expected_rejections += local.expected_rejections;
    aggregate.max_script_bytes = aggregate.max_script_bytes.max(local.max_script_bytes);
    aggregate.max_witness_items = aggregate.max_witness_items.max(local.max_witness_items);
    aggregate.max_witness_payload_bytes = aggregate
        .max_witness_payload_bytes
        .max(local.max_witness_payload_bytes);
    aggregate.max_stack_items = aggregate.max_stack_items.max(local.max_stack_items);
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
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let total = self
            .bytes
            .checked_add(bytes.len())
            .ok_or_else(|| io::Error::other("record overflow"))?;
        if total > RECORD_CAP {
            return Err(io::Error::other("128MiB compact execution record cap"));
        }
        self.bytes = total;
        self.hash.input(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn record(
    out: &mut RecordSink,
    metrics: &mut engine::Metrics,
    adapter: Adapter,
    name: &str,
    index: Value,
    disprove: bool,
    script: &ScriptBuf,
    witness: &[Vec<u8>],
    expected: bool,
) -> Result<()> {
    ensure(name.len() <= 4, "compact source label width")?;
    if let Value::String(s) = &index {
        ensure(
            s.len() <= 32 && s.is_ascii(),
            "compact guard identifier width",
        )?;
    }
    let (actual, stack) = engine::execute(script, witness.to_vec())?;
    ensure(
        actual == expected,
        &format!(
            "{name}/{index}: adapter{} mode{} expected{expected}, got{actual}",
            adapter.index(),
            u8::from(disprove)
        ),
    )?;
    metrics.vectors += 1;
    metrics.expected_rejections += usize::from(!expected);
    metrics.max_script_bytes = metrics.max_script_bytes.max(script.len());
    metrics.max_stack_items = metrics.max_stack_items.max(stack);
    metrics.max_witness_items = metrics.max_witness_items.max(witness.len());
    metrics.max_witness_payload_bytes = metrics
        .max_witness_payload_bytes
        .max(witness.iter().map(Vec::len).sum::<usize>());
    // Only after the actual interpreter result is checked is this record hashed.
    serde_json::to_writer(
        &mut *out,
        &json!({"a":adapter.index(),"c":name,"i":index,"m":disprove,"e":expected,"s":sha(script.as_bytes()),"w":witness_hash(witness)}),
    )?;
    out.write_all(b"\n")?;
    Ok(())
}
fn reject_both(
    out: &mut RecordSink,
    metrics: &mut engine::Metrics,
    r: &Registry,
    name: &str,
    ordinal: usize,
    id: &str,
    witness: &[Vec<u8>],
) -> Result<usize> {
    for disprove in [false, true] {
        record(
            out,
            metrics,
            r.adapter(),
            name,
            json!(id),
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
    for wire in &leaf.wires {
        let position = match unique.iter().position(|x| x == wire) {
            Some(p) => p,
            None => {
                unique.push(*wire);
                unique.len() - 1
            }
        };
        aliases.push(position);
    }
    let bounds: Vec<_> = unique.iter().map(|i| spec.words[*i].bound).collect();
    Ok(serde_json::to_string(&(
        leaf.body_sha256.clone(),
        bounds,
        aliases,
    ))?)
}
fn representatives(spec: &GraphSpec) -> Result<Vec<usize>> {
    let mut layouts = BTreeMap::new();
    for ordinal in 0..spec.leaves.len() {
        layouts.entry(layout(spec, ordinal)?).or_insert(ordinal);
    }
    Ok(layouts.into_values().collect())
}
fn bounded_layouts(spec: &GraphSpec) -> Result<Vec<usize>> {
    let reps = representatives(spec)?;
    let expected = if spec.words.len() == 3 { 2 } else { 11 };
    ensure(reps.len() == expected, "closed authenticated layout census")?;
    for &ordinal in &reps {
        let leaf = &spec.leaves[ordinal];
        let unique: std::collections::HashSet<_> = leaf.wires.iter().collect();
        ensure(unique.len() <= 3, "closed hinted-slot guard budget")?;
    }
    Ok(reps)
}
#[derive(Default)]
struct GuardCounts {
    standard: usize,
    replay: usize,
    hint_grammar: usize,
    hint_hash: usize,
    hinted_slots: usize,
    special: usize,
}
impl GuardCounts {
    fn total(&self) -> usize {
        self.standard + self.replay + self.hint_grammar + self.hint_hash + self.special
    }
}
fn guards(
    out: &mut RecordSink,
    metrics: &mut engine::Metrics,
    r: &Registry,
    opposite: &Registry,
    material: &keys::Material,
    name: &str,
    reps: &[usize],
) -> Result<GuardCounts> {
    let mut counts = GuardCounts::default();
    for (number, &ordinal) in reps.iter().enumerate() {
        let witness = r.witness(ordinal, &material.signatures)?;
        ensure(!witness.is_empty(), "empty honest witness")?;
        let mut variants = vec![Vec::new(), witness[..witness.len() - 1].to_vec()];
        let mut prepended = vec![vec![]];
        prepended.extend(witness.clone());
        variants.push(prepended);
        let mut appended = witness.clone();
        appended.push(vec![]);
        variants.push(appended);
        let mut first = witness.clone();
        first[0][0] ^= 1;
        variants.push(first);
        let ranges = r.packet_ranges(ordinal)?;
        let last_range = ranges.last().ok_or("missing unique packet")?.1.clone();
        let last_hash = last_range.start
            + if r.word_mode(ranges.last().unwrap().0)? == Mode::Hinted {
                18
            } else {
                9
            };
        let mut last = witness.clone();
        last[last_hash][0] ^= 1;
        variants.push(last);
        ensure(
            ranges.len() >= 2,
            "closed guard source needs two unique words",
        )?;
        let mut swapped = Vec::new();
        swapped.extend_from_slice(&witness[ranges[1].1.clone()]);
        swapped.extend_from_slice(&witness[ranges[0].1.clone()]);
        for (_, range) in ranges.iter().skip(2) {
            swapped.extend_from_slice(&witness[range.clone()]);
        }
        variants.push(swapped);
        for (variant, bad) in variants.iter().enumerate() {
            counts.standard += reject_both(
                out,
                metrics,
                r,
                name,
                ordinal,
                &format!("g/{number}/{variant}"),
                bad,
            )?;
        }
        let replay = opposite.witness(ordinal, &material.signatures)?;
        counts.replay += reject_both(
            out,
            metrics,
            r,
            name,
            ordinal,
            &format!("r/{number}"),
            &replay,
        )?;
        for (slot, (word, range)) in ranges.iter().enumerate() {
            if r.word_mode(*word)? != Mode::Hinted {
                continue;
            }
            counts.hinted_slots += 1;
            for digit in 0..10 {
                for (variant, raw) in MALFORMED_HINTS.iter().enumerate() {
                    let mut bad = witness.clone();
                    bad[range.start + 2 * digit + 1] = raw.to_vec();
                    counts.hint_grammar += reject_both(
                        out,
                        metrics,
                        r,
                        name,
                        ordinal,
                        &format!("h/{number}/{slot}/{digit}/{variant}"),
                        &bad,
                    )?;
                }
            }
            for digit in [0, 9] {
                let mut bad = witness.clone();
                bad[range.start + 2 * digit][0] ^= 1;
                counts.hint_hash += reject_both(
                    out,
                    metrics,
                    r,
                    name,
                    ordinal,
                    &format!("x/{number}/{slot}/{digit}"),
                    &bad,
                )?;
            }
        }
    }
    ensure(
        counts.standard == 14 * reps.len()
            && counts.replay == 2 * reps.len()
            && counts.hint_grammar == 200 * counts.hinted_slots
            && counts.hint_hash == 4 * counts.hinted_slots,
        "guard count invariant",
    )?;
    Ok(counts)
}

#[derive(Clone, PartialEq, Eq)]
struct Capture {
    word: usize,
    bound: u32,
    value: u32,
    mode: Mode,
    key: Vec<u8>,
    // Common full-signature conversion provenance. Compact mode does NOT
    // Script-authenticate its unused hint bytes; only `chunk` is the actual
    // mode-specific witness packet, whose authentication is executed below.
    signature: Vec<u8>,
    chunk: Vec<Vec<u8>>,
}
fn same_assertion(left: &Capture, right: &Capture) -> Result<()> {
    ensure(
        left == right,
        "mode/key/value/bound/signature/opening cache conflict",
    )
}
fn capture(
    r: &Registry,
    material: &keys::Material,
    ordinal: usize,
    word: usize,
    witness: &[Vec<u8>],
) -> Result<Capture> {
    let range = r
        .packet_ranges(ordinal)?
        .into_iter()
        .find(|(w, _)| *w == word)
        .ok_or("word is not a leaf operand")?
        .1;
    let expected = r.packet(word, &material.signatures[word])?;
    ensure(
        range.end <= witness.len() && witness[range.clone()] == expected,
        "actual witness chunk does not match source material",
    )?;
    let key: &[[u8; 20]] = r.keys()[word].as_ref();
    let signature: &[[u8; 21]] = material.signatures[word].as_ref();
    Ok(Capture {
        word,
        bound: r.spec().words[word].bound,
        value: material.values[word],
        mode: r.word_mode(word)?,
        key: key.iter().flatten().copied().collect(),
        signature: signature.iter().flatten().copied().collect(),
        chunk: witness[range].to_vec(),
    })
}
fn chains_valid(
    packet: &[Vec<u8>],
    key: &bitvm2_nova_script_oracle::wots::PublicKey,
) -> Result<bool> {
    ensure(packet.len() == 20, "ten digit proof packet")?;
    let keys: &[[u8; 20]] = key.as_ref();
    ensure(keys.len() == 10, "ten digit key")?;
    for digit in 0..10 {
        if packet[2 * digit].len() != 20 || !hints::canonical_hint(&packet[2 * digit + 1]) {
            return Ok(false);
        }
        let hint = packet[2 * digit + 1].first().copied().unwrap_or(0);
        let mut hash: [u8; 20] = packet[2 * digit].as_slice().try_into()?;
        for _ in hint..15 {
            hash = hash160::Hash::hash(&hash).to_byte_array();
        }
        if hash != keys[digit] {
            return Ok(false);
        }
    }
    Ok(true)
}
fn checksum_consistent(packet: &[Vec<u8>]) -> Result<bool> {
    ensure(packet.len() == 20, "ten digit checksum packet")?;
    let mut digits = Vec::new();
    for digit in 0..10 {
        ensure(
            hints::canonical_hint(&packet[2 * digit + 1]),
            "canonical checksum evidence hint",
        )?;
        digits.push(u32::from(
            packet[2 * digit + 1].first().copied().unwrap_or(0),
        ));
    }
    let expected = 120 - digits[..8].iter().sum::<u32>();
    Ok(expected == 16 * digits[8] + digits[9])
}
fn forwarded_checksum_packet(material: &keys::Material) -> Result<Vec<Vec<u8>>> {
    let full = hints::hinted_packet(&material.signatures[0])?;
    ensure(
        chains_valid(&full, &material.keys[0])? && checksum_consistent(&full)?,
        "honest ten digit chains/checksum",
    )?;
    let data = (0..8)
        .find(|i| full[2 * i + 1].first().copied().unwrap_or(0) < 15)
        .ok_or("forwardable data digit")?;
    let mut forwarded = full.clone();
    let digit = forwarded[2 * data + 1].first().copied().unwrap_or(0);
    forwarded[2 * data] = hash160::Hash::hash(&forwarded[2 * data])
        .to_byte_array()
        .to_vec();
    forwarded[2 * data + 1] = vec![digit + 1];
    ensure(
        chains_valid(&forwarded, &material.keys[0])?,
        "forwarded checksum attack must preserve all ten hash chains",
    )?;
    ensure(
        forwarded[16..] == full[16..] && !checksum_consistent(&forwarded)?,
        "only checksum consistency must fail",
    )?;
    Ok(forwarded)
}
fn fixed_attacks(
    out: &mut RecordSink,
    metrics: &mut engine::Metrics,
    r: &Registry,
    material: &keys::Material,
    name: &str,
    profile: &str,
) -> Result<(usize, usize)> {
    if r.adapter() != Adapter::Bound256Hinted || r.spec().words.len() != 3 {
        return Ok((0, 0));
    }
    let mut vectors = 0;
    let mut isolated = 0;
    if profile == "auth-order" {
        // Same keys, legitimate invalid aux/sq; corrupted hinted a must fail in
        // both reversed authentication orders, before any semantic flag branch.
        ensure(
            material.values == [9, u32::MAX, u32::MAX],
            "auth-order source values",
        )?;
        let forwarded = forwarded_checksum_packet(material)?;
        isolated = 10;
        for ordinal in 0..2 {
            let original = r.witness(ordinal, &material.signatures)?;
            let range = r
                .packet_ranges(ordinal)?
                .into_iter()
                .find(|(w, _)| *w == 0)
                .ok_or("a packet")?
                .1;
            for (variant, offset) in [0, 18, 19, 1].into_iter().enumerate() {
                let mut bad = original.clone();
                if offset == 19 {
                    bad[range.start + offset] = vec![16];
                } else if offset == 1 {
                    let current = bad[range.start + offset].first().copied().unwrap_or(0);
                    bad[range.start + offset] = vec![if current == 15 { 14 } else { current + 1 }];
                } else {
                    bad[range.start + offset][0] ^= 1;
                }
                vectors += reject_both(
                    out,
                    metrics,
                    r,
                    name,
                    ordinal,
                    &format!("o/h/{ordinal}/{variant}"),
                    &bad,
                )?;
            }
            let mut bad = original.clone();
            bad[range].clone_from_slice(&forwarded);
            vectors += reject_both(
                out,
                metrics,
                r,
                name,
                ordinal,
                &format!("o/checksum/{ordinal}"),
                &bad,
            )?;
        }
    }
    if profile == "a256" {
        ensure(material.values == [256, 256, 65536], "a256 source values")?;
        for ordinal in 0..2 {
            let mut bad = r.witness(ordinal, &material.signatures)?;
            let other = if ordinal == 0 { 1 } else { 2 };
            let range = r
                .packet_ranges(ordinal)?
                .into_iter()
                .find(|(w, _)| *w == other)
                .ok_or("compact operand")?
                .1;
            bad[range.start][0] ^= 1;
            vectors += reject_both(
                out,
                metrics,
                r,
                name,
                ordinal,
                &format!("o/c/{ordinal}"),
                &bad,
            )?;
        }
    }
    if profile == "a-max" {
        ensure(material.values[0] == u32::MAX, "MAX clamp fixture")?;
        let digits: &[[u8; 21]] = material.signatures[0].as_ref();
        ensure(digits[..8].iter().all(|d| d[20] == 15), "MAX data digits")?;
        for ordinal in 0..2 {
            let mut bad = r.witness(ordinal, &material.signatures)?;
            let range = r
                .packet_ranges(ordinal)?
                .into_iter()
                .find(|(w, _)| *w == 0)
                .ok_or("MAX packet")?
                .1;
            bad[range.start + 1] = vec![16];
            vectors += reject_both(
                out,
                metrics,
                r,
                name,
                ordinal,
                &format!("clamp/data/{ordinal}"),
                &bad,
            )?;
        }
    }
    if profile == "a9" {
        let full = hints::hinted_packet(&material.signatures[0])?;
        let checksum = (8..10)
            .find(|i| full[2 * i + 1] == [15])
            .ok_or("signed9 checksum digit15")?;
        let forwarded = forwarded_checksum_packet(material)?;
        isolated = 10;
        for ordinal in 0..2 {
            let witness = r.witness(ordinal, &material.signatures)?;
            let range = r
                .packet_ranges(ordinal)?
                .into_iter()
                .find(|(w, _)| *w == 0)
                .ok_or("signed9 packet")?
                .1;
            let mut clamp = witness.clone();
            clamp[range.start + 2 * checksum + 1] = vec![16];
            vectors += reject_both(
                out,
                metrics,
                r,
                name,
                ordinal,
                &format!("clamp/check/{ordinal}"),
                &clamp,
            )?;
            let mut bad = witness.clone();
            bad[range].clone_from_slice(&forwarded);
            vectors += reject_both(
                out,
                metrics,
                r,
                name,
                ordinal,
                &format!("checksum/{ordinal}"),
                &bad,
            )?;
        }
    }
    Ok((vectors, isolated))
}

fn registry_negatives(spec: &GraphSpec, material: &keys::Material, r: &Registry) -> Result<usize> {
    let expected = spec.identity()?;
    let id = r.identity();
    let adapter = r.adapter();
    let other = if adapter == Adapter::Compact {
        Adapter::Bound256Hinted
    } else {
        Adapter::Compact
    };
    let mut count = 0;
    let mut bad = expected;
    bad[0] ^= 1;
    ensure(
        Registry::new(spec.clone(), material.keys.clone(), adapter, bad, id).is_err(),
        "source identity mutation admitted",
    )?;
    count += 1;
    let mut bad = id;
    bad[0] ^= 1;
    ensure(
        Registry::new(spec.clone(), material.keys.clone(), adapter, expected, bad).is_err(),
        "registry identity mutation admitted",
    )?;
    count += 1;
    ensure(
        Registry::new(spec.clone(), material.keys.clone(), other, expected, id).is_err(),
        "adapter identity replay admitted",
    )?;
    count += 1;
    let mut keys = material.keys.clone();
    keys.swap(0, 1);
    ensure(
        Registry::new(spec.clone(), keys, adapter, expected, id).is_err(),
        "key order mutation admitted",
    )?;
    count += 1;
    let mut keys = material.keys.clone();
    keys[1] = keys[0];
    ensure(
        Registry::new(spec.clone(), keys, adapter, expected, id).is_err(),
        "duplicate key admitted",
    )?;
    count += 1;
    ensure(
        r.script(spec.leaves.len(), false).is_err() && r.script(spec.leaves.len(), true).is_err(),
        "ordinal admitted",
    )?;
    count += 2;
    ensure(
        r.witness(0, &material.signatures[..material.signatures.len() - 1])
            .is_err(),
        "truncated material admitted",
    )?;
    count += 1;
    let mut extra = material.signatures.clone();
    extra.push(extra[0]);
    ensure(r.witness(0, &extra).is_err(), "surplus material admitted")?;
    count += 1;
    Ok(count)
}
fn run_adapter(
    out: &mut RecordSink,
    aggregate_metrics: &mut engine::Metrics,
    r: &Registry,
    other: &Registry,
    material: &keys::Material,
    facts: &source::SourceFacts,
    name: &str,
    profile: &str,
) -> Result<Value> {
    // Each adapter owns its statistics; opposite-adapter replay guards may
    // inflate all-execution peaks, so snapshot normal C/D before those guards.
    let mut local_metrics = engine::Metrics::default();
    let metrics = &mut local_metrics;
    let reps = bounded_layouts(r.spec())?;
    let mut stream = sha256::Hash::engine();
    let mut bytes = 0usize;
    let mut largest = 0usize;
    let mut costs = Vec::new();
    let mut cache: HashMap<usize, Capture> = HashMap::new();
    let mut occurrences = 0usize;
    let mut links = 0usize;
    let mut aliases = 0usize;
    for ordinal in 0..r.spec().leaves.len() {
        let witness = r.witness(ordinal, &material.signatures)?;
        let slots = r.unique_slots(ordinal)?;
        for word in &slots {
            let actual = capture(r, material, ordinal, *word, &witness)?;
            occurrences += 1;
            if let Some(previous) = cache.get(word) {
                same_assertion(previous, &actual)?;
                links += 1;
            } else {
                cache.insert(*word, actual);
            }
        }
        aliases += r.spec().leaves[ordinal].wires.len() - slots.len();
        let correct = r.script(ordinal, false)?;
        let disproof = r.script(ordinal, true)?;
        record(
            out,
            metrics,
            r.adapter(),
            name,
            json!(ordinal),
            false,
            &correct,
            &witness,
            facts.truth[ordinal],
        )?;
        record(
            out,
            metrics,
            r.adapter(),
            name,
            json!(ordinal),
            true,
            &disproof,
            &witness,
            !facts.truth[ordinal],
        )?;
        bytes = bytes
            .checked_add(disproof.len())
            .ok_or("compiled byte overflow")?;
        ensure(bytes <= 256 << 20, "compiled stream256MiB cap")?;
        largest = largest.max(disproof.len());
        framed(&mut stream, disproof.as_bytes());
        costs.push(json!([
            ordinal,
            correct.len(),
            disproof.len(),
            witness.len(),
            witness.iter().map(Vec::len).sum::<usize>()
        ]));
    }
    ensure(
        metrics.vectors == 2 * r.spec().leaves.len()
            && metrics.expected_rejections == r.spec().leaves.len(),
        "normal adapter metrics census",
    )?;
    let normal_metrics = serde_json::to_value(&*metrics)?;
    ensure(
        cache.len() == r.spec().words.len() && occurrences == cache.len() + links,
        "actual opening census",
    )?;
    // Actual assertion cache mutation coverage, using captured complete material.
    let captured = cache
        .values()
        .next()
        .ok_or("no captured assertion")?
        .clone();
    let mut cache_rejections = 0;
    for variant in 0..7 {
        let mut bad = captured.clone();
        match variant {
            0 => bad.word ^= 1,
            1 => bad.bound ^= 1,
            2 => bad.value ^= 1,
            3 => {
                bad.mode = if bad.mode == Mode::Compact {
                    Mode::Hinted
                } else {
                    Mode::Compact
                }
            }
            4 => bad.key[0] ^= 1,
            5 => bad.signature[0] ^= 1,
            _ => bad.chunk[0][0] ^= 1,
        };
        ensure(
            same_assertion(&captured, &bad).is_err(),
            "cache mutant accepted",
        )?;
        cache_rejections += 1;
    }
    let mut guards = guards(out, metrics, r, other, material, name, &reps)?;
    let (special, isolated) = fixed_attacks(out, metrics, r, material, name, profile)?;
    guards.special = special;
    let native_rejections = registry_negatives(r.spec(), material, r)?;
    ensure(
        metrics.vectors == 2 * r.spec().leaves.len() + guards.total()
            && metrics.expected_rejections == r.spec().leaves.len() + guards.total(),
        "all-execution adapter metrics census",
    )?;
    let all_metrics = serde_json::to_value(&*metrics)?;
    fold_metrics(aggregate_metrics, metrics);
    Ok(
        json!({"adapter":r.adapter().index(),"label":r.adapter().label(),"registry_id":hex::encode(r.identity()),"compiled_script_bytes":bytes,"compiled_stream_sha256":sha256::Hash::from_engine(stream).to_string(),"largest_disproof_leaf_bytes":largest,"normal_vectors":2*r.spec().leaves.len(),"normal_metrics":normal_metrics,"metrics":all_metrics,"guard_layouts":reps.len(),"standard_guard_vectors":guards.standard,"mode_replay_vectors":guards.replay,"hinted_guard_slots":guards.hinted_slots,"hint_grammar_vectors":guards.hint_grammar,"hint_hash_vectors":guards.hint_hash,"special_auth_vectors":guards.special,"total_guard_vectors":guards.total(),"isolated_checksum_valid_digit_chains":isolated,"actual_opening_occurrences":occurrences,"shared_opening_links":links,"alias_formal_reuses":aliases,"cache_rejections":cache_rejections,"native_rejections":native_rejections,"leaf_costs":costs}),
    )
}
fn case_run(
    run: &transport::Run,
    d: &transport::CaseDescriptor,
    dir: &Path,
    out: &mut RecordSink,
    metrics: &mut engine::Metrics,
) -> Result<Value> {
    let case = run.load_case(d, dir)?;
    let facts = source::admit(&case, d, &run.context, &run.operation_id)?;
    let material = keys::generate(&case.spec, &facts.source_sha256, &d.name, &facts.values)?;
    let expected = case.spec.identity()?;
    let mut regs = Vec::new();
    for adapter in ADAPTERS {
        let id = Registry::key_identity(&case.spec, &material.keys, adapter)?;
        regs.push(Registry::new(
            case.spec.clone(),
            material.keys.clone(),
            adapter,
            expected,
            id,
        )?);
    }
    ensure(
        regs[0].identity() != regs[1].identity(),
        "adapter identities must differ",
    )?;
    let mut adapters = Vec::new();
    for index in 0..2 {
        adapters.push(run_adapter(
            out,
            metrics,
            &regs[index],
            &regs[1 - index],
            &material,
            &facts,
            &d.name,
            &d.profile,
        )?);
    }
    // Cross-adapter hashes are views of every same full signature. Hints do not
    // create a shorter key, a truncated value or a second signing operation.
    let mut hash_links = 0;
    for signature in &material.signatures {
        let compact = hints::compact_packet(signature)?;
        let hinted = hints::hinted_packet(signature)?;
        for digit in 0..10 {
            ensure(
                compact[digit] == hinted[2 * digit],
                "cross-adapter hash material",
            )?;
            hash_links += 1;
        }
    }
    Ok(
        json!({"name":d.name,"fixture":d.fixture,"profile":d.profile,"role":d.role,"program_sha256":facts.program_sha256,"catalogue_id":facts.catalogue_id,"source_sha256":facts.source_sha256,"source_maps_sha256":facts.source_maps_sha256,"words":case.spec.words.len(),"leaves":case.spec.leaves.len(),"false_predicates":facts.false_ordinals,"abort_predicates":facts.abort_ordinals,"signature_entries_created":material.values.len(),"full_signature_signing_calls":material.values.len(),"cross_adapter_hash_links":hash_links,"adapters":adapters}),
    )
}
fn run(manifest: &Path, dir: &Path, output: &Path, expected: &str) -> Result<()> {
    let start = Instant::now();
    let run = transport::Run::load(manifest, dir, expected)?;
    let mut records = RecordSink::new();
    let mut metrics = engine::Metrics::default();
    let mut cases = Vec::new();
    // Fresh independent source admission for EVERY raw snapshot precedes any key.
    let mut admitted_leaves = 0usize;
    let mut admitted_words = 0usize;
    let mut admitted_layouts = 0usize;
    for d in &run.cases {
        let case = run.load_case(d, dir)?;
        source::admit(&case, d, &run.context, &run.operation_id)?;
        admitted_layouts += bounded_layouts(&case.spec)?.len();
        admitted_leaves += case.spec.leaves.len();
        admitted_words += case.spec.words.len();
    }
    ensure(
        admitted_layouts == 80 && admitted_leaves == 4904 && admitted_words == 5722,
        "closed complete source census before keys",
    )?;
    for d in &run.cases {
        cases.push(
            case_run(&run, d, dir, &mut records, &mut metrics)
                .map_err(|e| format!("case {}: {e}", d.name))?,
        );
    }
    // Re-read all pinned source files after execution. No mutable report input.
    let final_snapshot = transport::Run::load(manifest, dir, expected)?;
    for descriptor in &final_snapshot.cases {
        final_snapshot.load_case(descriptor, dir)?;
    }
    let wall = start.elapsed().as_secs_f64();
    ensure(wall <= 1260.0, "native wall bound")?;
    ensure(
        metrics.vectors <= 71392 && records.bytes <= 15_706_240,
        "closed authentication call/record budget",
    )?;
    let mut signature_entries = 0usize;
    let mut signing_calls = 0usize;
    let mut hash_links = 0usize;
    let mut isolated_chains = 0usize;
    let mut guard_vectors = 0usize;
    for case in &cases {
        signature_entries += counter(case, "signature_entries_created")?;
        signing_calls += counter(case, "full_signature_signing_calls")?;
        hash_links += counter(case, "cross_adapter_hash_links")?;
        for adapter in case
            .get("adapters")
            .and_then(Value::as_array)
            .ok_or("adapter ledgers")?
        {
            isolated_chains += counter(adapter, "isolated_checksum_valid_digit_chains")?;
            guard_vectors += counter(adapter, "total_guard_vectors")?;
        }
    }
    ensure(
        signature_entries == 5722
            && signing_calls == 5722
            && hash_links == 57220
            && isolated_chains == 40,
        "full32 material/native checksum census",
    )?;
    ensure(
        metrics.vectors == 19616 + guard_vectors
            && metrics.expected_rejections == 9808 + guard_vectors,
        "actual engine/record census",
    )?;
    let mut report = json!({"schema":"bitvm2-nova-auth-cost-execution/v1","passed":true,"input_manifest_sha256":expected,"cases":cases,"leaf_cost_columns":["ordinal","correctness_script_bytes","disproof_script_bytes","witness_items","witness_payload_bytes"],"compact_execution_records_bytes":records.bytes,"compact_execution_records_sha256":sha256::Hash::from_engine(records.hash).to_string(),"wall_seconds":wall,"metrics":metrics});
    let object = report.as_object_mut().ok_or("report object")?;
    for (key, value) in [
        ("signature_entries_created", signature_entries),
        ("full_signature_signing_calls", signing_calls),
        ("cross_adapter_hash_links", hash_links),
        ("isolated_checksum_valid_digit_chains", isolated_chains),
        ("isolated_chain_engine_executions", 0),
    ] {
        ensure(
            object.insert(key.into(), json!(value)).is_none(),
            "duplicate report aggregate",
        )?;
    }
    for flag in [
        "same_full32_signature_material_checked",
        "bound_only_mode_selection_checked",
        "all_operand_authentication_before_semantics_checked",
        "canonical_all_ten_hints_checked",
        "actual_mode_aware_opening_links_checked",
        "all_source_predicates_executed_both_adapters",
        "test_keys_only",
        "stack_limit_enabled",
    ] {
        ensure(
            object.insert(flag.into(), json!(true)).is_none(),
            "duplicate report flag",
        )?;
    }
    for flag in [
        "raw_vector_file_written",
        "op_cat_enabled",
        "panic_is_rejection",
        "candidate_taproot_tree_verified",
        "candidate_forest_verified",
        "candidate_membership_verified",
        "production_assertion_binding",
        "bitcoin_transaction_graph",
        "complete_bitvm2_verifier",
        "complete_nova_verifier",
        "full_permutation_verified",
        "full_hash_verified",
        "transcript_verified",
        "proof_verified",
        "savings_assumed",
        "compact_hint_bytes_script_authenticated",
    ] {
        ensure(
            object.insert(flag.into(), json!(false)).is_none(),
            "duplicate report flag",
        )?;
    }
    for field in [
        "setup_calls",
        "proving_jobs",
        "native_proofs_verified",
        "gpu_jobs",
        "transactions_broadcast",
        "tree_calls",
    ] {
        ensure(
            object.insert(field.into(), json!(0)).is_none(),
            "duplicate report zero",
        )?;
    }
    let bytes = serde_json::to_vec(&report)?;
    ensure(bytes.len() <= SUMMARY_CAP, "summary1MiB cap")?;
    fs::write(output, bytes)?;
    Ok(())
}
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() != 5 {
        return Err("usage: auth_cost MANIFEST CASEDIR OUTPUT EXPECTED_SHA256".into());
    }
    let expected = args[4].to_str().ok_or("ASCII manifest hash")?;
    ensure(
        hex::encode(id32(expected)?) == expected,
        "canonical manifest digest",
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
    fn malformed_inventory_is_closed_and_never_canonical() {
        assert_eq!(MALFORMED_HINTS.len(), 10);
        for raw in MALFORMED_HINTS {
            assert!(!hints::canonical_hint(raw));
            assert!(raw.len() <= 520);
        }
    }
    #[test]
    fn record_sink_enforces_existing_cap_before_mutating() {
        let mut sink = RecordSink::new();
        sink.bytes = RECORD_CAP;
        assert!(sink.write(&[1]).is_err());
        assert_eq!(sink.bytes, RECORD_CAP);
    }
    #[test]
    fn witness_hash_binds_boundaries_and_order() {
        assert_ne!(
            witness_hash(&[vec![1], vec![2]]),
            witness_hash(&[vec![1, 2]])
        );
        assert_ne!(
            witness_hash(&[vec![1], vec![2]]),
            witness_hash(&[vec![2], vec![1]])
        );
    }
    #[test]
    fn checksum_evidence_uses_all_eight_message_and_two_checksum_digits() {
        let mut packet = vec![vec![0; 20]; 20];
        for digit in 0..10 {
            packet[2 * digit + 1] = vec![];
        }
        packet[15] = vec![9];
        packet[17] = vec![6];
        packet[19] = vec![15];
        assert!(checksum_consistent(&packet).unwrap());
        packet[1] = vec![1];
        assert!(!checksum_consistent(&packet).unwrap());
        packet[1] = vec![0];
        assert!(checksum_consistent(&packet).is_err());
        packet[1] = vec![];
        packet[19] = vec![16];
        assert!(checksum_consistent(&packet).is_err());
    }
    #[test]
    fn cache_comparison_binds_every_material_field_and_actual_packet() {
        let a = Capture {
            word: 1,
            bound: 256,
            value: 9,
            mode: Mode::Hinted,
            key: vec![1; 200],
            signature: vec![2; 210],
            chunk: vec![vec![3; 20]; 20],
        };
        same_assertion(&a, &a.clone()).unwrap();
        for i in 0..7 {
            let mut b = a.clone();
            match i {
                0 => b.word = 2,
                1 => b.bound = 257,
                2 => b.value = 10,
                3 => b.mode = Mode::Compact,
                4 => b.key[0] ^= 1,
                5 => b.signature[0] ^= 1,
                _ => b.chunk[0][0] ^= 1,
            };
            assert!(same_assertion(&a, &b).is_err());
        }
    }
    #[test]
    fn metric_fold_adds_counts_takes_peaks_and_preserves_normal_snapshot() {
        let mut local = engine::Metrics {
            vectors: 4,
            expected_rejections: 2,
            max_script_bytes: 100,
            max_witness_items: 20,
            max_witness_payload_bytes: 400,
            max_stack_items: 31,
        };
        let normal = serde_json::to_value(&local).unwrap();
        // A later replay guard can inflate witness/stack peaks independently
        // of the adapter's normal executions. It must not change the snapshot.
        local.vectors += 2;
        local.expected_rejections += 2;
        local.max_witness_items = 40;
        local.max_witness_payload_bytes = 600;
        local.max_stack_items = 69;
        let mut aggregate = engine::Metrics {
            vectors: 10,
            expected_rejections: 7,
            max_script_bytes: 150,
            max_witness_items: 30,
            max_witness_payload_bytes: 800,
            max_stack_items: 51,
        };
        fold_metrics(&mut aggregate, &local);
        assert_eq!(aggregate.vectors, 16);
        assert_eq!(aggregate.expected_rejections, 11);
        assert_eq!(aggregate.max_script_bytes, 150);
        assert_eq!(aggregate.max_witness_items, 40);
        assert_eq!(aggregate.max_witness_payload_bytes, 800);
        assert_eq!(aggregate.max_stack_items, 69);
        assert_eq!(
            normal,
            json!({"vectors":4,"expected_rejections":2,"max_script_bytes":100,"max_witness_items":20,"max_witness_payload_bytes":400,"max_stack_items":31})
        );
    }
}
