//! Paired legacy-row/grouped-AND arithmetic measurement, isolated from defaults.
//! No new authentication primitive, tree, proof, proving or production binding.
pub use bitvm2_nova_script_oracle::{engine, wots};
mod body_pins;
mod keys;
#[path = "../../point-oracle/src/body_pins.rs"]
mod legacy_body_pins;
mod registry;
mod source;
mod transport;
use bitcoin::{
    hashes::{sha256, Hash, HashEngine},
    ScriptBuf,
};
use bitvm2_nova_script_oracle::registry as legacy_registry;
use registry::GraphSpec;
use serde_json::{json, Value};
use std::{
    collections::{HashMap, HashSet},
    fs,
    io::{self, Write},
    path::Path,
    time::Instant,
};
use wots::{id32, PublicKey, Result};

const RECORD_CAP: usize = 128 << 20;
const SUMMARY_CAP: usize = 1 << 20;
const MAX_ROWS: usize = 27844;
const MAX_CALLS: usize = 447552;
const MAX_RECORD_LINE: usize = 218;
const DERIVED_RECORD_CAP: usize = 97566336;
const DERIVED_SUMMARY_CAP: usize = 884724;
const METADATA_CAP: usize = 300000;
fn require(yes: bool, message: &str) -> Result<()> {
    if yes {
        Ok(())
    } else {
        Err(message.into())
    }
}
fn merge_report_object(target: &mut Value, extra: Value) -> Result<()> {
    let target = target.as_object_mut().ok_or("report target object")?;
    let Value::Object(extra) = extra else {
        return Err("report extension object".into());
    };
    for (key, value) in extra {
        require(!target.contains_key(&key), "duplicate report field")?;
        target.insert(key, value);
    }
    Ok(())
}
fn sha(raw: &[u8]) -> String {
    sha256::Hash::hash(raw).to_string()
}
fn framed(h: &mut sha256::HashEngine, raw: &[u8]) {
    h.input(&(raw.len() as u64).to_le_bytes());
    h.input(raw);
}
fn witness_hash(w: &[Vec<u8>]) -> String {
    let mut h = sha256::Hash::engine();
    h.input(&(w.len() as u64).to_le_bytes());
    for v in w {
        framed(&mut h, v);
    }
    sha256::Hash::from_engine(h).to_string()
}
fn fold(a: &mut engine::Metrics, b: &engine::Metrics) {
    a.vectors += b.vectors;
    a.expected_rejections += b.expected_rejections;
    a.max_script_bytes = a.max_script_bytes.max(b.max_script_bytes);
    a.max_witness_items = a.max_witness_items.max(b.max_witness_items);
    a.max_witness_payload_bytes = a.max_witness_payload_bytes.max(b.max_witness_payload_bytes);
    a.max_stack_items = a.max_stack_items.max(b.max_stack_items);
}
fn legacy_spec(spec: &GraphSpec) -> Result<legacy_registry::GraphSpec> {
    let old: legacy_registry::GraphSpec = serde_json::from_value(serde_json::to_value(spec)?)?;
    require(
        serde_json::to_value(&old)? == serde_json::to_value(spec)?
            && old.identity()? == spec.identity()?,
        "old catalogue shape/identity conversion must be exact",
    )?;
    Ok(old)
}
enum Inner {
    Legacy(legacy_registry::Registry),
    Grouped(registry::Registry),
}
struct AuthRegistry {
    inner: Inner,
    spec: GraphSpec,
}
impl AuthRegistry {
    fn new(spec: GraphSpec, keys: Vec<PublicKey>, adapter: usize) -> Result<Self> {
        let expected = spec.identity()?;
        let id = spec.key_identity(&keys)?;
        let inner = match adapter {
            0 => {
                let old = legacy_spec(&spec)?;
                require(
                    old.key_identity(&keys)? == id,
                    "old/new key identity parity",
                )?;
                Inner::Legacy(legacy_registry::Registry::new(old, keys, expected, id)?)
            }
            1 => Inner::Grouped(registry::Registry::new(spec.clone(), keys, expected, id)?),
            _ => return Err("closed adapter index".into()),
        };
        Ok(Self { inner, spec })
    }
    fn identity(&self) -> [u8; 32] {
        match &self.inner {
            Inner::Legacy(r) => r.identity(),
            Inner::Grouped(r) => r.identity(),
        }
    }
    fn script(&self, ordinal: usize, disprove: bool) -> Result<ScriptBuf> {
        match &self.inner {
            Inner::Legacy(r) => r.script(ordinal, disprove),
            Inner::Grouped(r) => r.script(ordinal, disprove),
        }
    }
    fn unique_slots(&self, ordinal: usize) -> Result<Vec<usize>> {
        match &self.inner {
            Inner::Legacy(r) => r.unique_slots(ordinal),
            Inner::Grouped(r) => r.unique_slots(ordinal),
        }
    }
    fn witness(
        &self,
        ordinal: usize,
        signatures: &[legacy_registry::Signature],
    ) -> Result<Vec<Vec<u8>>> {
        match &self.inner {
            Inner::Legacy(r) => r.witness(ordinal, signatures),
            Inner::Grouped(r) => r.witness(ordinal, signatures),
        }
    }
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
        if total > RECORD_CAP || total > DERIVED_RECORD_CAP {
            return Err(io::Error::other("record byte cap"));
        }
        self.bytes = total;
        self.hash.input(raw);
        Ok(raw.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn guard_id(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= 32
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/_.:-".contains(&b))
}
fn record(
    out: &mut RecordSink,
    metrics: &mut engine::Metrics,
    name: &str,
    adapter: usize,
    index: Value,
    disprove: bool,
    script: &ScriptBuf,
    witness: &[Vec<u8>],
    expected: bool,
) -> Result<()> {
    require(
        name.len() == 4
            && matches!(name.as_bytes()[0], b'p' | b'v')
            && name.as_bytes()[1] == b'/'
            && name.as_bytes()[2..].iter().all(u8::is_ascii_digit)
            && adapter < 2,
        "closed compact record name/adapter",
    )?;
    match &index {
        Value::String(v) => require(guard_id(v), "owned escapeless guard label")?,
        Value::Number(n) => require(n.as_u64().is_some_and(|n| n < 6151), "record ordinal")?,
        _ => return Err("record index kind".into()),
    }
    let (actual, stack) = engine::execute(script, witness.to_vec())?;
    require(
        actual == expected,
        &format!("{name}/{adapter}/{index}: expected{expected}, got{actual}"),
    )?;
    metrics.vectors += 1;
    metrics.expected_rejections += usize::from(!expected);
    metrics.max_script_bytes = metrics.max_script_bytes.max(script.len());
    metrics.max_stack_items = metrics.max_stack_items.max(stack);
    metrics.max_witness_items = metrics.max_witness_items.max(witness.len());
    metrics.max_witness_payload_bytes = metrics
        .max_witness_payload_bytes
        .max(witness.iter().map(Vec::len).sum());
    let mut line = serde_json::to_vec(
        &json!({"c":[name,adapter],"i":index,"m":disprove,"e":expected,"s":sha(script.as_bytes()),"w":witness_hash(witness)}),
    )?;
    line.push(b'\n');
    require(
        line.len() <= MAX_RECORD_LINE,
        "actual compact record218-byte bound",
    )?;
    out.write_all(&line)?;
    Ok(())
}
fn reject_both(
    out: &mut RecordSink,
    metrics: &mut engine::Metrics,
    r: &AuthRegistry,
    name: &str,
    adapter: usize,
    ordinal: usize,
    label: &str,
    witness: &[Vec<u8>],
) -> Result<usize> {
    for disprove in [false, true] {
        record(
            out,
            metrics,
            name,
            adapter,
            json!(label),
            disprove,
            &r.script(ordinal, disprove)?,
            witness,
            false,
        )?;
    }
    Ok(2)
}
fn preflight(old: &transport::Case, new: &transport::Case) -> Result<()> {
    require(
        old.spec.words.len() == new.spec.words.len()
            && old.words == new.words
            && old
                .spec
                .words
                .iter()
                .zip(&new.spec.words)
                .all(|(a, b)| a.name == b.name && a.bound == b.bound),
        "same paired word catalogue/bounds/assignment",
    )?;
    legacy_spec(&old.spec)?;
    for case in [old, new] {
        case.spec.identity()?;
        for leaf in &case.spec.leaves {
            require(
                leaf.wires.iter().collect::<HashSet<_>>().len() * 10 <= 1000,
                "pre-key compact witness1000 cap",
            )?;
        }
        require(
            case.spec.leaves.len() <= 1 << 19,
            "unchanged future depth19 structural bound",
        )?;
    }
    Ok(())
}
#[derive(Clone, PartialEq, Eq)]
struct Capture {
    word: usize,
    name: String,
    bound: u32,
    value: u32,
    key: Vec<u8>,
    signature: Vec<u8>,
    packet: Vec<Vec<u8>>,
}
fn same(a: &Capture, b: &Capture) -> Result<()> {
    require(
        a == b,
        "paired key/value/bound/signature/opening cache conflict",
    )
}
fn capture(
    r: &AuthRegistry,
    material: &keys::Material,
    ordinal: usize,
    word: usize,
) -> Result<Capture> {
    let witness = r.witness(ordinal, &material.signatures)?;
    let slots = r.unique_slots(ordinal)?;
    require(
        witness.len() == slots.len() * 10,
        "actual full32 compact packet layout",
    )?;
    let slot = slots
        .iter()
        .position(|i| *i == word)
        .ok_or("actual requested word occurrence")?;
    let packet = witness[10 * slot..10 * (slot + 1)].to_vec();
    let expected: Vec<Vec<u8>> = material.signatures[word]
        .iter()
        .map(|cell| cell.to_vec())
        .collect();
    require(
        packet == expected,
        "actual opening differs from once-signed material",
    )?;
    let key: &[[u8; 20]] = material.keys[word].as_ref();
    Ok(Capture {
        word,
        name: r.spec.words[word].name.clone(),
        bound: r.spec.words[word].bound,
        value: material.values[word],
        key: key.iter().flatten().copied().collect(),
        signature: material.signatures[word]
            .iter()
            .flatten()
            .copied()
            .collect(),
        packet,
    })
}
fn coordinate(
    r: &AuthRegistry,
    material: &keys::Material,
    ordinal: usize,
    occurrence: usize,
    word: usize,
) -> Result<Capture> {
    require(
        r.spec
            .leaves
            .get(ordinal)
            .and_then(|leaf| leaf.wires.get(occurrence))
            == Some(&word),
        "actual source-map formal coordinate",
    )?;
    capture(r, material, ordinal, word)
}
fn first_occurrences(spec: &GraphSpec) -> Result<Vec<usize>> {
    let mut first = vec![None; spec.words.len()];
    for (ordinal, leaf) in spec.leaves.iter().enumerate() {
        for &word in &leaf.wires {
            first[word].get_or_insert(ordinal);
        }
    }
    first
        .into_iter()
        .map(|ordinal| ordinal.ok_or_else(|| "missing paired word opening coverage".into()))
        .collect()
}
fn actual_links(
    registries: &[AuthRegistry; 2],
    material: &keys::Material,
    facts: &source::SourceFacts,
) -> Result<(usize, usize, usize)> {
    let a = first_occurrences(&registries[0].spec)?;
    let b = first_occurrences(&registries[1].spec)?;
    let mut hashes = 0usize;
    for word in 0..material.values.len() {
        let old = capture(&registries[0], material, a[word], word)?;
        let new = capture(&registries[1], material, b[word], word)?;
        same(&old, &new)?;
        require(
            old.packet.len() == 10 && old.packet.iter().zip(&new.packet).all(|(a, b)| a == b),
            "actual paired hash cells",
        )?;
        hashes += 10;
    }
    let mut subtotals = HashSet::new();
    for link in &facts.subtotal_links {
        let old = coordinate(
            &registries[0],
            material,
            link.baseline_ab_ordinal,
            link.baseline_ab_occurrence,
            link.word_index,
        )?;
        let grouped = coordinate(
            &registries[1],
            material,
            link.candidate_group_ordinal,
            link.candidate_group_occurrence,
            link.word_index,
        )?;
        let old_column = coordinate(
            &registries[0],
            material,
            link.baseline_column_ordinal,
            link.baseline_column_occurrence,
            link.word_index,
        )?;
        let new_column = coordinate(
            &registries[1],
            material,
            link.candidate_column_ordinal,
            link.candidate_column_occurrence,
            link.word_index,
        )?;
        same(&old, &grouped)?;
        same(&old, &old_column)?;
        same(&old, &new_column)?;
        require(
            old.bound == 1 << 18 && subtotals.insert(link.word_index),
            "distinct immutable subtotal opening",
        )?;
    }
    let mut carries = HashSet::new();
    for link in &facts.carry_links {
        let old = coordinate(
            &registries[0],
            material,
            link.baseline_producer,
            link.baseline_producer_occurrence,
            link.word_index,
        )?;
        let consumer = coordinate(
            &registries[0],
            material,
            link.baseline_consumer,
            link.baseline_consumer_occurrence,
            link.word_index,
        )?;
        let grouped = coordinate(
            &registries[1],
            material,
            link.candidate_producer,
            link.candidate_producer_occurrence,
            link.word_index,
        )?;
        let new_consumer = coordinate(
            &registries[1],
            material,
            link.candidate_consumer,
            link.candidate_consumer_occurrence,
            link.word_index,
        )?;
        same(&old, &consumer)?;
        same(&old, &grouped)?;
        same(&old, &new_consumer)?;
        require(
            old.bound == 16384 && carries.insert(link.word_index),
            "distinct immutable carry opening",
        )?;
    }
    let n = facts.projection.multiplication_prefixes.len();
    require(
        subtotals.len() == 280 * n
            && carries.len() == 63 * n
            && hashes == 10 * material.values.len(),
        "actual paired word/subtotal/carry census",
    )?;
    Ok((hashes, subtotals.len(), carries.len()))
}
fn guards(
    out: &mut RecordSink,
    metrics: &mut engine::Metrics,
    r: &AuthRegistry,
    material: &keys::Material,
    name: &str,
    adapter: usize,
    ordinals: &[usize],
) -> Result<usize> {
    let mut total = 0;
    for &ordinal in ordinals {
        let original = r.witness(ordinal, &material.signatures)?;
        let slots = r.unique_slots(ordinal)?;
        require(
            !original.is_empty() && original.iter().all(|cell| cell.len() == 20),
            "real compact hash cells",
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
            let foreign = (0..r.spec.words.len())
                .find(|i| *i != word && r.spec.words[*i].bound == r.spec.words[word].bound)
                .ok_or("same-bound foreign global word")?;
            require(
                material.keys[foreign] != material.keys[word],
                "actual distinct-key packet substitution",
            )?;
            let packet: Vec<Vec<u8>> = material.signatures[foreign]
                .iter()
                .map(|v| v.to_vec())
                .collect();
            cross[..10].clone_from_slice(&packet);
        }
        variants.push(cross);
        for (index, bad) in variants.iter().enumerate() {
            total += reject_both(
                out,
                metrics,
                r,
                name,
                adapter,
                ordinal,
                &format!("g/{ordinal}/{index}"),
                bad,
            )?;
        }
    }
    require(
        total == 14 * ordinals.len(),
        "every measured leaf has all fourteen guard executions",
    )?;
    Ok(total)
}
fn native_negatives(r: &AuthRegistry, material: &keys::Material) -> Result<usize> {
    let spec = r.spec.identity()?;
    let registry_id = r.identity();
    let denied = |keys: Vec<PublicKey>, expected: [u8; 32], id: [u8; 32]| -> Result<bool> {
        Ok(match &r.inner {
            Inner::Legacy(_) => {
                legacy_registry::Registry::new(legacy_spec(&r.spec)?, keys, expected, id).is_err()
            }
            Inner::Grouped(_) => {
                registry::Registry::new(r.spec.clone(), keys, expected, id).is_err()
            }
        })
    };
    let mut wrong = spec;
    wrong[0] ^= 1;
    require(
        denied(material.keys.clone(), wrong, registry_id)?,
        "wrong source pin accepted",
    )?;
    wrong = registry_id;
    wrong[0] ^= 1;
    require(
        denied(material.keys.clone(), spec, wrong)?,
        "wrong registry pin accepted",
    )?;
    let mut keys = material.keys.clone();
    keys.swap(0, 1);
    require(
        denied(keys, spec, registry_id)?,
        "key order mutation accepted",
    )?;
    let mut keys = material.keys.clone();
    keys[1] = keys[0].clone();
    require(
        denied(keys, spec, registry_id)?,
        "duplicate global key accepted",
    )?;
    require(
        denied(
            material.keys[..material.keys.len() - 1].to_vec(),
            spec,
            registry_id,
        )?,
        "missing key accepted",
    )?;
    require(
        r.script(r.spec.leaves.len(), false).is_err(),
        "correctness ordinal overflow accepted",
    )?;
    require(
        r.script(r.spec.leaves.len(), true).is_err(),
        "disproof ordinal overflow accepted",
    )?;
    require(
        r.witness(0, &material.signatures[..material.signatures.len() - 1])
            .is_err(),
        "missing signature accepted",
    )?;
    let mut extra = material.signatures.clone();
    extra.push(material.signatures[0].clone());
    require(r.witness(0, &extra).is_err(), "surplus signature accepted")?;
    Ok(9)
}
fn late_auth(
    out: &mut RecordSink,
    metrics: &mut engine::Metrics,
    r: &AuthRegistry,
    material: &keys::Material,
    d: &transport::Descriptor,
    adapter: usize,
    facts: &source::SourceFacts,
) -> Result<(usize, Vec<Value>)> {
    if !matches!(d.profile.as_str(), "row-middle-0" | "subtotal-max") {
        return Ok((0, vec![]));
    }
    let f = if adapter == 0 {
        &facts.baseline
    } else {
        &facts.candidate
    };
    let (ordinal, semantic_word, forged_word, forged_group_row) = if d.profile == "subtotal-max" {
        let semantic = facts
            .subtotal_links
            .iter()
            .find(|link| material.values[link.word_index] == u32::MAX)
            .ok_or("actual signed MAX subtotal")?;
        let ordinal = if adapter == 0 {
            semantic.baseline_ab_ordinal
        } else {
            semantic.candidate_group_ordinal
        };
        let slots = r.unique_slots(ordinal)?;
        let position = slots
            .iter()
            .position(|word| *word == semantic.word_index)
            .ok_or("actual MAX subtotal unique position")?;
        let forged = slots[..position]
            .iter()
            .copied()
            .find(|word| material.values[*word] < r.spec.words[*word].bound)
            .ok_or("valid packet recovered after invalid subtotal")?;
        (ordinal, semantic.word_index, forged, None)
    } else {
        let (_, _, rows) = facts
            .projection
            .groups
            .iter()
            .find(|(_, _, rows)| {
                rows.len() == 4
                    && rows
                        .iter()
                        .all(|old| row_product_count(&r.spec, adapter, *old, facts) == Some(4))
            })
            .ok_or("actual first all-four group")?;
        let first = facts
            .subtotal_links
            .iter()
            .find(|link| link.baseline_ab_ordinal == rows[0])
            .ok_or("actual early row subtotal link")?;
        let last = facts
            .subtotal_links
            .iter()
            .find(|link| link.baseline_ab_ordinal == rows[3])
            .ok_or("actual late row subtotal link")?;
        require(
            facts.baseline.truth[rows[0]] == Some(false)
                && facts.baseline.truth[rows[3]] == Some(true),
            "actual early false and late true row",
        )?;
        let ordinal = if adapter == 0 {
            first.baseline_ab_ordinal
        } else {
            first.candidate_group_ordinal
        };
        require(
            r.spec.leaves[ordinal]
                .wires
                .iter()
                .all(|word| material.values[*word] < r.spec.words[*word].bound),
            "ordinary semantic false must retain every bound",
        )?;
        let forged = if adapter == 0 {
            r.unique_slots(ordinal)?[0]
        } else {
            require(
                last.candidate_group_ordinal == ordinal,
                "same actual late-row conjunction",
            )?;
            last.word_index
        };
        (
            ordinal,
            first.word_index,
            forged,
            if adapter == 1 { Some(3usize) } else { None },
        )
    };
    require(
        f.truth[ordinal] == Some(false)
            && f.selected_ordinals.contains(&ordinal)
            && semantic_word != forged_word
            && material.values[forged_word] < r.spec.words[forged_word].bound,
        "closed selected false statement with separate valid malformed packet",
    )?;
    let slots = r.unique_slots(ordinal)?;
    let semantic_position = slots
        .iter()
        .position(|w| *w == semantic_word)
        .ok_or("semantic unique position")?;
    let forged_position = slots
        .iter()
        .position(|w| *w == forged_word)
        .ok_or("forged unique position")?;
    if d.profile == "subtotal-max" {
        require(
            forged_position < semantic_position && material.values[semantic_word] == u32::MAX,
            "invalid flag is decoded before the later malformed authentication",
        )?;
    }
    let mut bad = r.witness(ordinal, &material.signatures)?;
    require(
        bad[10 * forged_position].len() == 20,
        "actual late-auth signature hash",
    )?;
    bad[10 * forged_position][0] ^= 1;
    let calls = reject_both(
        out,
        metrics,
        r,
        &d.name,
        adapter,
        ordinal,
        "late/auth",
        &bad,
    )?;
    Ok((
        calls,
        vec![
            json!({"ordinal":ordinal,"semantic_word":semantic_word,"forged_word":forged_word,"semantic_unique_position":semantic_position,"forged_unique_position":forged_position,"forged_group_row":forged_group_row}),
        ],
    ))
}
// Derive an old row's public product count from the independently checked
// candidate projection when the caller has the candidate spec; baseline facts
// do not supply body authority or values to this public schedule test.
fn row_product_count(
    spec: &GraphSpec,
    adapter: usize,
    ordinal: usize,
    facts: &source::SourceFacts,
) -> Option<i64> {
    if adapter == 0 {
        return spec.leaves.get(ordinal)?.argument.first().copied();
    }
    let (new, row) = *facts.projection.old_to_new.get(ordinal)?;
    spec.leaves.get(new)?.argument.get(row?).copied()
}
fn adapter_run(
    out: &mut RecordSink,
    global: &mut engine::Metrics,
    normal_global: &mut engine::Metrics,
    r: &AuthRegistry,
    shadow: Option<&registry::Registry>,
    material: &keys::Material,
    d: &transport::Descriptor,
    adapter: usize,
    facts: &source::SourceFacts,
    lexical_nodes: usize,
) -> Result<Value> {
    let f = if adapter == 0 {
        &facts.baseline
    } else {
        &facts.candidate
    };
    let header = &d.adapters[adapter];
    let mut metrics = engine::Metrics::default();
    let mut stream = sha256::Hash::engine();
    let (
        mut bytes,
        mut largest,
        mut aborts,
        mut disproofs,
        mut occurrences,
        mut links,
        mut aliases,
    ) = (0usize, 0usize, 0usize, 0usize, 0usize, 0usize, 0usize);
    let mut cache = HashMap::<usize, Capture>::new();
    let mut costs = Vec::new();
    for &ordinal in &f.selected_ordinals {
        let witness = r.witness(ordinal, &material.signatures)?;
        let slots = r.unique_slots(ordinal)?;
        for &word in &slots {
            let actual = capture(r, material, ordinal, word)?;
            occurrences += 1;
            if let Some(old) = cache.get(&word) {
                same(old, &actual)?;
                links += 1;
            } else {
                cache.insert(word, actual);
            }
        }
        aliases += r.spec.leaves[ordinal].wires.len() - slots.len();
        let correct = r.script(ordinal, false)?;
        let disproof = r.script(ordinal, true)?;
        require(
            correct.len().checked_add(1) == Some(disproof.len()),
            "actual C+1 equals D",
        )?;
        if let Some(new) = shadow {
            require(
                new.witness(ordinal, &material.signatures)? == witness
                    && new.script(ordinal, false)? == correct
                    && new.script(ordinal, true)? == disproof,
                "unchanged old-spec witness and C/D Script bytes",
            )?;
        }
        let truth = f.truth[ordinal];
        aborts += usize::from(truth.is_none());
        disproofs += usize::from(truth == Some(false));
        record(
            out,
            &mut metrics,
            &d.name,
            adapter,
            json!(ordinal),
            false,
            &correct,
            &witness,
            truth == Some(true),
        )?;
        record(
            out,
            &mut metrics,
            &d.name,
            adapter,
            json!(ordinal),
            true,
            &disproof,
            &witness,
            truth == Some(false),
        )?;
        bytes = bytes
            .checked_add(disproof.len())
            .ok_or("compiled stream overflow")?;
        require(bytes <= 256 << 20, "unchanged component256MiB cap")?;
        largest = largest.max(disproof.len());
        framed(&mut stream, disproof.as_bytes());
        let row = json!([
            disproof.len(),
            witness.len(),
            witness.iter().map(Vec::len).sum::<usize>()
        ]);
        require(
            serde_json::to_vec(&row)?.len() + 1 <= 21,
            "derived leaf-cost triple bound",
        )?;
        costs.push(row);
    }
    require(
        metrics.vectors == 2 * f.selected_ordinals.len()
            && metrics.expected_rejections == f.selected_ordinals.len() + aborts
            && occurrences == cache.len() + links,
        "normal/capture execution census",
    )?;
    if header.execution_mode == "all" {
        require(
            cache.len() == material.values.len(),
            "complete honest global word opening coverage",
        )?;
        if adapter == 0 && d.profile == "point" {
            require(
                bytes
                    == if d.role == "pallas_base" {
                        88586200
                    } else {
                        88688588
                    },
                "frozen complete-point legacy byte total",
            )?;
        }
    }
    let normal_metrics = serde_json::to_value(&metrics)?;
    fold(normal_global, &metrics);
    let guard_calls = guards(
        out,
        &mut metrics,
        r,
        material,
        &d.name,
        adapter,
        &f.selected_ordinals,
    )?;
    let (late_calls, evidence) = late_auth(out, &mut metrics, r, material, d, adapter, facts)?;
    let native_rejections = native_negatives(r, material)?;
    require(
        metrics.vectors == 16 * f.selected_ordinals.len() + late_calls
            && metrics.expected_rejections == 15 * f.selected_ordinals.len() + aborts + late_calls,
        "normal plus all guards and late-auth census",
    )?;
    fold(global, &metrics);
    let mut row = json!({"index":adapter,"label":header.label,"program_sha256":f.program_sha256,"catalogue_id":f.catalogue_id,"words":header.words,"arithmetic_constraints":header.arithmetic_constraints,"canonical_fields":header.canonical_fields,"leaves":header.leaves,"execution_mode":header.execution_mode,
        "false_predicates":f.false_ordinals,"abort_predicates":f.abort_ordinals,"measured_ordinals":if header.execution_mode=="all"{None}else{Some(f.selected_ordinals.clone())}});
    merge_report_object(
        &mut row,
        json!({
        "compiled_script_bytes":bytes,"largest_disproof_leaf_bytes":largest,"compiled_stream_sha256":sha256::Hash::from_engine(stream).to_string(),"registry_id":hex::encode(r.identity()),
        "normal_vectors":2*f.selected_ordinals.len(),"normal_metrics":normal_metrics,"metrics":metrics,"guarded_leaves":f.selected_ordinals.len(),"standard_guard_vectors":guard_calls,"late_auth_vectors":late_calls,"late_auth_evidence":evidence}),
    )?;
    merge_report_object(
        &mut row,
        json!({
        "proper_disproof_vectors":disproofs,"abort_leaf_checks":aborts,"leaf_costs":costs,"actual_opening_occurrences":occurrences,"actual_opened_words":cache.len(),"shared_opening_links":links,"alias_formal_reuses":aliases,
        "input_lexical_nodes":lexical_nodes,"lexical_node_limit":550000,"native_rejections":native_rejections}),
    )?;
    Ok(row)
}
fn case_run(
    run: &transport::Run,
    d: &transport::Descriptor,
    dir: &Path,
    out: &mut RecordSink,
    metrics: &mut engine::Metrics,
    normal: &mut engine::Metrics,
) -> Result<Value> {
    let (old, old_nodes) = run.load_case(d, 0, dir)?;
    let (new, new_nodes) = run.load_case(d, 1, dir)?;
    let facts = source::admit(&old, &new, d, &run.context, &run.operation_id)?;
    preflight(&old, &new)?;
    require(
        facts.values == old.words
            && facts.values == new.words
            && facts.baseline.values == facts.values
            && facts.candidate.values == facts.values
            && facts.baseline.global_ids == facts.candidate.global_ids,
        "same source-admitted paired values/global IDs",
    )?;
    let material = keys::generate(&old.spec, &facts.source_sha256, &d.name, &facts.values)?;
    let registries = [
        AuthRegistry::new(old.spec.clone(), material.keys.clone(), 0)?,
        AuthRegistry::new(new.spec.clone(), material.keys.clone(), 1)?,
    ];
    let shadow = registry::Registry::new(
        old.spec.clone(),
        material.keys.clone(),
        old.spec.identity()?,
        old.spec.key_identity(&material.keys)?,
    )?;
    require(
        shadow.identity() == registries[0].identity(),
        "old-spec actual key/registry identity equality",
    )?;
    let (hashes, subtotals, carries) = actual_links(&registries, &material, &facts)?;
    let n = facts.projection.multiplication_prefixes.len();
    let adapters = vec![
        adapter_run(
            out,
            metrics,
            normal,
            &registries[0],
            Some(&shadow),
            &material,
            d,
            0,
            &facts,
            old_nodes,
        )?,
        adapter_run(
            out,
            metrics,
            normal,
            &registries[1],
            None,
            &material,
            d,
            1,
            &facts,
            new_nodes,
        )?,
    ];
    let combined = adapters
        .iter()
        .map(|a| a["compiled_script_bytes"].as_u64().unwrap_or(u64::MAX))
        .try_fold(0u64, |sum, value| {
            sum.checked_add(value)
                .ok_or("combined Script bytes overflow")
        })?;
    require(
        combined <= 5u64 << 28 && adapters.len() <= 16,
        "unchanged aggregate Script/component caps",
    )?;
    Ok(
        json!({"name":d.name,"profile":d.profile,"role":d.role,"fixture":d.fixture,"source_sha256":facts.source_sha256,"source_maps_sha256":facts.source_maps_sha256,"word_catalogue_sha256":d.word_catalogue_sha256,"assignment_sha256":d.assignment_sha256,
        "signature_entries_created":material.values.len(),"full_signature_signing_calls":material.values.len(),"cross_adapter_hash_links":hashes,"old_ab_rows":280*n,"grouped_ab_leaves":72*n,"unchanged_leaf_projections":old.spec.leaves.len()-280*n,"canonical_guard_projections":d.adapters[0].canonical_fields,
        "subtotal_opening_links":subtotals,"carry_opening_links":carries,"opening_link_pass_all_leaves":false,"opening_link_pass_all_mapped_coordinates":true,"paired_word_opening_pass_all_words":true,"legacy_equivalence_leaves":facts.baseline.selected_ordinals.len(),"curve_verdict":facts.curve_verdict,"adapters":adapters}),
    )
}
fn counter(v: &Value, key: &str) -> Result<usize> {
    Ok(v[key]
        .as_u64()
        .ok_or_else(|| format!("typed report counter {key}"))? as usize)
}
fn metadata_json_bytes(report: &Value) -> Result<usize> {
    let mut metadata = report.clone();
    for case in metadata["cases"].as_array_mut().ok_or("report cases")? {
        for adapter in case["adapters"].as_array_mut().ok_or("report adapters")? {
            adapter["leaf_costs"] = json!([]);
        }
    }
    Ok(serde_json::to_vec(&metadata)?.len())
}
fn run(manifest: &Path, dir: &Path, output: &Path, expected: &str) -> Result<()> {
    let start = Instant::now();
    let run = transport::Run::load(manifest, dir, expected)?;
    for d in &run.cases {
        let (old, _) = run.load_case(d, 0, dir)?;
        let (new, _) = run.load_case(d, 1, dir)?;
        source::admit(&old, &new, d, &run.context, &run.operation_id)?;
        preflight(&old, &new)?;
    }
    let mut sink = RecordSink::new();
    let mut metrics = engine::Metrics::default();
    let mut normal = engine::Metrics::default();
    let mut cases = Vec::new();
    for d in &run.cases {
        cases.push(
            case_run(&run, d, dir, &mut sink, &mut metrics, &mut normal)
                .map_err(|e| format!("case {}: {e}", d.name))?,
        );
    }
    let final_run = transport::Run::load(manifest, dir, expected)?;
    for d in &final_run.cases {
        final_run.load_case(d, 0, dir)?;
        final_run.load_case(d, 1, dir)?;
    }
    let (
        mut signatures,
        mut sign_calls,
        mut hashes,
        mut rows,
        mut vectors,
        mut rejections,
        mut late,
    ) = (0usize, 0usize, 0usize, 0usize, 0usize, 0usize, 0usize);
    for case in &cases {
        signatures += counter(case, "signature_entries_created")?;
        sign_calls += counter(case, "full_signature_signing_calls")?;
        hashes += counter(case, "cross_adapter_hash_links")?;
        for a in case["adapters"].as_array().ok_or("adapter report array")? {
            rows += a["leaf_costs"].as_array().ok_or("leaf cost rows")?.len();
            vectors += counter(&a["metrics"], "vectors")?;
            rejections += counter(&a["metrics"], "expected_rejections")?;
            late += counter(a, "late_auth_vectors")?;
        }
    }
    require(
        signatures == 52508
            && sign_calls == signatures
            && hashes == 525080
            && rows <= MAX_ROWS
            && late == 16
            && vectors == metrics.vectors
            && rejections == metrics.expected_rejections
            && vectors == 16 * rows + late
            && vectors <= MAX_CALLS,
        "closed actual material/call/late-auth budget",
    )?;
    let wall = start.elapsed().as_secs_f64();
    require(wall <= 1260.0, "native1260s cap")?;
    let mut report = json!({"schema":"bitvm2-nova-grouped-convolution-execution/v1","passed":true,"input_manifest_sha256":expected,"leaf_cost_columns":["disproof_script_bytes","witness_items","witness_payload_bytes"],"cases":cases,"normal_metrics":normal,"metrics":metrics,
        "compact_execution_records_bytes":sink.bytes,"compact_execution_records_sha256":sha256::Hash::from_engine(sink.hash).to_string(),"wall_seconds":wall,"full_statement_cases":8,"targeted_statement_cases":32,"signature_entries_created":signatures,"full_signature_signing_calls":sign_calls,"cross_adapter_hash_links":hashes});
    let obj = report.as_object_mut().ok_or("report object")?;
    for flag in [
        "legacy_registry_and_engine_used",
        "same_full32_signature_material_checked",
        "paired_word_opening_pass_all_words",
        "row_projection_checked",
        "canonical_guards_preserved",
        "unchanged_kernels_preserved",
        "all_honest_catalogues_executed",
        "correctness_bytes_equal_disproof_minus_one_checked",
        "test_keys_only",
        "stack_limit_enabled",
    ] {
        require(
            obj.insert(flag.into(), json!(true)).is_none(),
            "duplicate true report flag",
        )?;
    }
    for flag in [
        "all_cases_full_statement_executed",
        "raw_vector_file_written",
        "op_cat_enabled",
        "panic_is_rejection",
        "proof_verified",
        "complete_nova_verifier",
        "complete_bitvm2_verifier",
        "full_permutation_verified",
        "full_hash_verified",
        "transcript_verified",
        "production_assertion_binding",
        "bitcoin_transaction_graph",
        "candidate_taproot_tree_verified",
        "candidate_forest_verified",
        "candidate_membership_verified",
        "savings_assumed",
    ] {
        require(
            obj.insert(flag.into(), json!(false)).is_none(),
            "duplicate false report flag",
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
        require(
            obj.insert(field.into(), json!(0)).is_none(),
            "duplicate zero report field",
        )?;
    }
    require(
        metadata_json_bytes(&report)? <= METADATA_CAP,
        "derived300000-byte metadata bound",
    )?;
    let raw = serde_json::to_vec(&report)?;
    require(
        raw.len() <= DERIVED_SUMMARY_CAP && raw.len() <= SUMMARY_CAP,
        "derived and hard summary caps",
    )?;
    fs::write(output, raw)?;
    Ok(())
}
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().collect();
    require(
        args.len() == 5,
        "usage: grouped_convolution MANIFEST CASE_DIR OUTPUT EXPECTED_SHA256",
    )?;
    let expected = args[4].to_str().ok_or("ASCII manifest SHA")?;
    require(
        hex::encode(id32(expected)?) == expected,
        "canonical expected manifest pin",
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
    fn resource_math_and_escapeless_labels_are_explicit() {
        assert_eq!(MAX_ROWS * 16 + 2048, MAX_CALLS);
        assert_eq!(MAX_CALLS * MAX_RECORD_LINE, DERIVED_RECORD_CAP);
        assert!(DERIVED_RECORD_CAP < RECORD_CAP);
        assert_eq!(MAX_ROWS * 21 + METADATA_CAP, DERIVED_SUMMARY_CAP);
        assert!(DERIVED_SUMMARY_CAP < SUMMARY_CAP);
        assert!(guard_id("g/6150/6"));
        assert!(!guard_id("g/\""));
        assert!(!guard_id("g/\n"));
    }
    #[test]
    fn report_extensions_reject_duplicate_fields_without_replacing_them() {
        let mut row = json!({"a":1});
        merge_report_object(&mut row, json!({"b":2})).unwrap();
        assert!(merge_report_object(&mut row, json!({"a":3})).is_err());
        assert_eq!(row["a"], 1);
        assert!(merge_report_object(&mut row, json!([])).is_err());
    }
    #[test]
    fn old_catalogue_key_witness_and_script_identity_are_unchanged() {
        // Dummy key/signature cells exercise only compilation/transport parity;
        // no cryptographic authentication or arithmetic execution is claimed.
        for role in ["pallas_base", "vesta_base"] {
            let body = vec![0x51];
            let body_id = sha(&body);
            let spec = GraphSpec {
                program_sha256: "11".repeat(32),
                context: "22".repeat(32),
                field_role: role.into(),
                operation_id: "unit/legacy-shape-parity".into(),
                words: vec![
                    registry::Word {
                        name: "byte".into(),
                        bound: 256,
                    },
                    registry::Word {
                        name: "subtotal".into(),
                        bound: 1 << 18,
                    },
                ],
                leaves: vec![registry::Leaf {
                    kind: "conv_ab".into(),
                    argument: vec![1],
                    wires: vec![0, 0, 1],
                    body_sha256: body_id.clone(),
                }],
                bodies: std::collections::BTreeMap::from([(body_id, hex::encode(body))]),
            };
            let old = legacy_spec(&spec).unwrap();
            let keys = vec![[[0u8; 20]; 10], [[1u8; 20]; 10]];
            let signatures = vec![[[2u8; 20]; 10], [[3u8; 20]; 10]];
            let catalogue = spec.identity().unwrap();
            let id = spec.key_identity(&keys).unwrap();
            assert_eq!(old.identity().unwrap(), catalogue);
            assert_eq!(old.key_identity(&keys).unwrap(), id);
            let a = legacy_registry::Registry::new(old, keys.clone(), catalogue, id).unwrap();
            let b = registry::Registry::new(spec, keys, catalogue, id).unwrap();
            assert_eq!(
                a.witness(0, &signatures).unwrap(),
                b.witness(0, &signatures).unwrap()
            );
            for disprove in [false, true] {
                assert_eq!(
                    a.script(0, disprove).unwrap(),
                    b.script(0, disprove).unwrap()
                );
            }
        }
    }
    #[test]
    fn new_kind_admits_only_the_three_exact_row_bound_sequences() {
        // Shape admission only; the dummy body is never executed. Source
        // admission separately requires the verifier-owned composed-body pins.
        for pattern in [vec![1, 2, 3, 4], vec![4, 4, 4, 4], vec![3, 2, 1]] {
            let mut bounds = Vec::<u32>::new();
            for count in &pattern {
                bounds.extend(std::iter::repeat(256).take(2 * *count as usize));
                bounds.push(1 << 18);
            }
            let body = vec![0x51];
            let digest = sha(&body);
            let spec = GraphSpec {
                program_sha256: "11".repeat(32),
                context: "22".repeat(32),
                field_role: "pallas_base".into(),
                operation_id: "unit/grouped-shape".into(),
                words: bounds
                    .iter()
                    .enumerate()
                    .map(|(i, bound)| registry::Word {
                        name: format!("w{i}"),
                        bound: *bound,
                    })
                    .collect(),
                leaves: vec![registry::Leaf {
                    kind: "conv_ab_all".into(),
                    argument: pattern,
                    wires: (0..bounds.len()).collect(),
                    body_sha256: digest.clone(),
                }],
                bodies: std::collections::BTreeMap::from([(digest, hex::encode(body))]),
            };
            assert!(spec.identity().is_ok());
            let mut changed = spec.clone();
            changed.leaves[0].argument = vec![4, 4];
            assert!(changed.identity().is_err());
            let mut changed = spec.clone();
            changed.words[0].bound = 255;
            assert!(changed.identity().is_err());
            let mut changed = spec.clone();
            changed.words.last_mut().unwrap().bound -= 1;
            assert!(changed.identity().is_err());
            let mut changed = spec;
            changed.leaves[0].kind = "conv_ab".into();
            assert!(changed.identity().is_err());
        }
    }
}
