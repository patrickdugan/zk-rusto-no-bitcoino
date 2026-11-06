//! Hosted TEST-ONLY two framed Keccak branches and uniform512 reduction.
//! One full registry is live at a time; shared words reuse original WOTS signatures.
#[path = "../byte_rho_keys.rs"]
mod keys;
#[path = "../byte_rho_source.rs"]
mod source;
#[path = "../byte_rho_tail.rs"]
mod tail;
use bitcoin::{
    hashes::{sha256, Hash, HashEngine},
    ScriptBuf,
};
use bitvm::signatures::{CompactWots, Wots, Wots4};
use bitvm2_nova_script_oracle::{
    engine::{execute, Metrics},
    registry::{GraphSpec, Registry, Signature},
    taproot_commitment::TaprootCommitment,
    taproot_forest::TaprootForest,
    wots::{PublicKey, Result},
};
use permutation::{canonical, digest, opening, Case};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
    time::Instant,
};

const INPUT_CAP: u64 = 32 << 20;
const MAP_CAP: u64 = 8 << 20;
const MANIFEST_CAP: u64 = 1 << 20;
const SUMMARY_CAP: usize = 1 << 20;
const RECORD_CAP: u64 = 128 << 20;
const BRANCHES: [&str; 3] = ["hi", "lo", "tail"];
const PROFILES: [&str; 4] = ["honest", "bad-hi-digest", "bad-lo-frame", "wrong-result"];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Run {
    schema: String,
    context: String,
    operation_id: String,
    cases: Vec<Group>,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Group {
    name: String,
    profile: String,
    role: String,
    counter: u64,
    execution_mode: String,
    source_sha256: String,
    source_maps_sha256: String,
    eval_w_le: String,
    prior_state_hex: String,
    expected_hi_output_state_hex: String,
    expected_lo_output_state_hex: String,
    expected_raw_state_le: String,
    expected_result_le: String,
    expected_quotient_le: String,
    rho_source_filename: String,
    rho_source_file_sha256: String,
    rho_source_file_bytes: u64,
    rho_maps_filename: String,
    rho_maps_file_sha256: String,
    rho_maps_file_bytes: u64,
    components: Vec<Header>,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    descriptor: source::ComponentDescriptor,
    filename: String,
    file_sha256: String,
    file_bytes: u64,
    maps_filename: String,
    maps_file_sha256: String,
    maps_file_bytes: u64,
    program_manifest_filename: Option<String>,
    program_manifest_file_sha256: Option<String>,
    program_manifest_file_bytes: Option<u64>,
    source_manifest_filename: String,
    source_manifest_file_sha256: String,
    source_manifest_file_bytes: u64,
    execution_mode: String,
    selected_ordinals: Option<Vec<usize>>,
    expected_false: Vec<usize>,
    full: Option<permutation::Descriptor>,
}
struct Prepared {
    case: Case,
    facts: source::ComponentFacts,
    full: Option<permutation::Full>,
    tail: Option<tail::CheckedTail>,
}

fn fixed_hex<const N: usize>(text: &str) -> Result<[u8; N]> {
    let value: [u8; N] = hex::decode(text)?
        .try_into()
        .map_err(|_| "fixed byte encoding length")?;
    if hex::encode(value) != text {
        return Err("canonical lowercase byte encoding required".into());
    }
    Ok(value)
}
fn checked_file(root: &Path, name: &str, cap: u64, sha: &str, bytes: u64) -> Result<Vec<u8>> {
    if name.is_empty()
        || name.len() > 80
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
        || bytes == 0
        || bytes > cap
    {
        return Err("flat bounded file descriptor required".into());
    }
    let raw = permutation::snapshot(&root.join(name), cap, digest(sha)?)?;
    if raw.len() as u64 != bytes {
        return Err("pinned file byte count differs".into());
    }
    Ok(raw)
}
fn selected(profile: &str, component: usize) -> (&'static str, Option<Vec<usize>>) {
    if component == 2 || profile == "honest" || profile == "bad-hi-digest" {
        ("all", None)
    } else if profile == "bad-lo-frame" && component == 1 {
        ("selected", Some(vec![125, 351]))
    } else {
        ("none", None)
    }
}
fn validate_run(run: &Run) -> Result<()> {
    if run.schema != "bitvm2-nova-byte-rho-run/v1"
        || run.operation_id != "benchmark/byte-rho/v1"
        || run.context != sha256::Hash::hash(b"BITVM2-NOVA/BYTE-RHO-CONFORMANCE/v1").to_string()
        || run.cases.len() != 8
    {
        return Err("exact bounded rho benchmark run required".into());
    }
    let mut names = HashSet::new();
    for (i, group) in run.cases.iter().enumerate() {
        let role = if i < 4 {
            "pallas_scalar"
        } else {
            "vesta_scalar"
        };
        let counter = if i < 4 { 59 } else { 44 };
        let profile = PROFILES[i % 4];
        if group.role != role
            || group.counter != counter
            || group.profile != profile
            || group.name != format!("{role}/rho-{profile}")
            || !names.insert(&group.name)
            || group.components.len() != 3
            || group.execution_mode != if i % 4 < 2 { "full" } else { "targeted" }
            || group.rho_source_filename != format!("rho-source-{i:02}.json")
            || group.rho_maps_filename != format!("rho-maps-{i:02}.json")
        {
            return Err("closed ordered rho profiles/roles/files required".into());
        }
        digest(&group.source_sha256)?;
        digest(&group.source_maps_sha256)?;
        fixed_hex::<32>(&group.eval_w_le)?;
        fixed_hex::<64>(&group.prior_state_hex)?;
        fixed_hex::<200>(&group.expected_hi_output_state_hex)?;
        fixed_hex::<200>(&group.expected_lo_output_state_hex)?;
        fixed_hex::<64>(&group.expected_raw_state_le)?;
        fixed_hex::<32>(&group.expected_result_le)?;
        fixed_hex::<33>(&group.expected_quotient_le)?;
        for (j, h) in group.components.iter().enumerate() {
            let d = &h.descriptor;
            let branch = BRANCHES[j];
            let (mode, ordinals) = selected(profile, j);
            let stem = format!("{i:02}-{branch}");
            if d.index != j
                || d.branch != branch
                || d.field_role != role
                || d.counter != counter
                || d.operation_id != format!("{}/counter/{counter}/{branch}", run.operation_id)
                || h.execution_mode != mode
                || h.selected_ordinals != ordinals
                || h.filename != format!("case-{stem}.json")
                || h.maps_filename != format!("maps-{stem}.json")
                || h.source_manifest_filename != format!("source-{stem}.json")
                || h.full.is_some() != (j < 2)
                || d.words != if j < 2 { 29445 } else { 587 }
                || d.leaves != if j < 2 { 29245 } else { 453 }
            {
                return Err("rho component identity, count, selector or file differs".into());
            }
            if j < 2 {
                if h.program_manifest_filename.as_deref()
                    != Some(format!("program-{stem}.json").as_str())
                    || h.program_manifest_file_sha256.is_none()
                    || h.program_manifest_file_bytes.is_none()
                {
                    return Err("full source requires all three compact identity files".into());
                }
            } else if h.program_manifest_filename.is_some()
                || h.program_manifest_file_sha256.is_some()
                || h.program_manifest_file_bytes.is_some()
            {
                return Err("tail has no manifest-as-program file".into());
            }
        }
    }
    Ok(())
}

fn reference_input(group: &Group, branch: &str) -> Result<[u8; 200]> {
    let eval = fixed_hex::<32>(&group.eval_w_le)?;
    let mut canonical_probe = [0u8; 64];
    canonical_probe[..32].copy_from_slice(&eval);
    let (remainder, quotient) = tail::reduction(&canonical_probe, &group.role)?;
    if remainder != eval || quotient.iter().any(|byte| *byte != 0) {
        return Err("host eval_W must be canonical for the explicit scalar role".into());
    }
    let mut result = [0u8; 200];
    for (byte, value) in source::fixed_frame(group.counter, branch)? {
        result[byte] = u8::try_from(value)?;
    }
    result[1..33].copy_from_slice(&eval);
    result[45..109].copy_from_slice(&fixed_hex::<64>(&group.prior_state_hex)?);
    if group.profile == "bad-lo-frame" && branch == "lo" {
        result[111] ^= 1;
    }
    Ok(result)
}
fn full_reference(
    case: &Case,
    full: &permutation::Full,
    group: &Group,
    component: usize,
) -> Result<()> {
    let mut current = reference_input(group, BRANCHES[component])?;
    for (r, view) in full.rounds.iter().enumerate() {
        for i in 0..200 {
            if case.words[view.map[view.layout.ports.inputs[i]]] != u32::from(current[i]) {
                return Err("framed input or preceding claimed state differs".into());
            }
        }
        let mut out = permutation::reference(&current, r);
        if group.profile == "bad-hi-digest" && component == 0 && r == 23 {
            out[0] ^= 1;
        }
        for i in 0..200 {
            if case.words[view.map[view.layout.ports.outputs[i]]] != u32::from(out[i]) {
                return Err("BYTE round differs from independent word reference".into());
            }
        }
        current = out;
    }
    let claimed = if component == 0 {
        &group.expected_hi_output_state_hex
    } else {
        &group.expected_lo_output_state_hex
    };
    if current != fixed_hex::<200>(claimed)? {
        return Err("terminal full reference differs".into());
    }
    Ok(())
}

fn prepare(run: &Run, group: &Group, index: usize, root: &Path) -> Result<Prepared> {
    let h = &group.components[index];
    let d = &h.descriptor;
    let case: Case = serde_json::from_slice(&checked_file(
        root,
        &h.filename,
        INPUT_CAP,
        &h.file_sha256,
        h.file_bytes,
    )?)?;
    if case.name != format!("{}/{}", group.name, d.branch)
        || !case.measure_all
        || case.expected_spec_id != d.catalogue_id
        || case.spec.program_sha256 != d.program_sha256
        || case.spec.context != run.context
        || case.spec.field_role != group.role
        || case.spec.operation_id != d.operation_id
        || case.spec.words.len() != d.words
        || case.words.len() != d.words
        || case.spec.leaves.len() != d.leaves
        || case.spec.identity()? != digest(&d.catalogue_id)?
        || case
            .spec
            .words
            .iter()
            .zip(&case.words)
            .any(|(w, v)| *v >= w.bound)
    {
        return Err("component graph/assignment differs from pinned identity/ranges".into());
    }
    let map_bytes = checked_file(
        root,
        &h.maps_filename,
        MAP_CAP,
        &h.maps_file_sha256,
        h.maps_file_bytes,
    )?;
    let (facts, full, checked_tail, source_value) = if index < 2 {
        let f = h.full.as_ref().ok_or("missing full identity descriptor")?;
        if f.name != case.name
            || f.profile != group.profile
            || f.role != group.role
            || f.filename != h.filename
            || f.file_sha256 != h.file_sha256
            || f.file_bytes != h.file_bytes
            || f.catalogue_id != d.catalogue_id
            || f.program_sha256 != d.program_sha256
            || f.source_sha256 != d.source_sha256
            || f.words != d.words
            || f.leaves != d.leaves
            || f.maps_filename != h.maps_filename
            || f.maps_file_sha256 != h.maps_file_sha256
            || f.maps_file_bytes != h.maps_file_bytes
            || f.source_maps_sha256 != d.source_maps_sha256
            || f.source_manifest_filename != h.source_manifest_filename
            || f.source_manifest_file_sha256 != h.source_manifest_file_sha256
            || f.source_manifest_file_bytes != h.source_manifest_file_bytes
            || Some(&f.program_manifest_filename) != h.program_manifest_filename.as_ref()
            || Some(&f.program_manifest_file_sha256) != h.program_manifest_file_sha256.as_ref()
            || Some(f.program_manifest_file_bytes) != h.program_manifest_file_bytes
            || f.expected_false != h.expected_false
            || f.state_index.is_some()
            || f.byte_slot.is_some()
        {
            return Err("nested full header differs from component pins".into());
        }
        let raw: permutation::RawMaps = serde_json::from_slice(&map_bytes)?;
        let full = permutation::compose(&case.spec, f, &raw, &d.operation_id)?;
        if canonical(&full.maps)? != map_bytes {
            return Err("full canonical source maps differ".into());
        }
        let (program, source_value) = permutation::identities(&case, f, &full, &d.operation_id)?;
        if checked_file(
            root,
            &f.program_manifest_filename,
            MANIFEST_CAP,
            &f.program_manifest_file_sha256,
            f.program_manifest_file_bytes,
        )? != canonical(&program)?
        {
            return Err("full program sidecar differs".into());
        }
        full_reference(&case, &full, group, index)?;
        if fixed_hex::<200>(&f.input_state_hex)? != reference_input(group, &d.branch)?
            || f.expected_output_state_hex
                != if index == 0 {
                    &group.expected_hi_output_state_hex
                } else {
                    &group.expected_lo_output_state_hex
                }
                .as_str()
        {
            return Err("nested full reference state differs".into());
        }
        let ids = case
            .spec
            .words
            .iter()
            .map(|w| source::branch_global_id(&d.branch, &w.name))
            .collect::<Result<Vec<_>>>()?;
        let last = &full.rounds[23];
        let facts = source::ComponentFacts {
            index,
            branch: d.branch.clone(),
            global_ids_sha256: sha256::Hash::hash(&canonical(&json!(ids))?).to_string(),
            global_ids: ids,
            input_indices: full.inputs.clone(),
            output_indices: full.outputs.clone(),
            producer_ordinals: last
                .layout
                .ports
                .producers
                .iter()
                .map(|p| last.first_leaf + p.0)
                .collect(),
            producer_occurrences: last.layout.ports.producers.iter().map(|p| p.1).collect(),
            input_consumer_occurrences: permutation::consumers(&full.rounds[0]),
        };
        (facts, Some(full), None, source_value)
    } else {
        let raw: Value = serde_json::from_slice(&map_bytes)?;
        let t = tail::check(
            &case.spec,
            &run.context,
            &group.role,
            group.counter,
            &d.operation_id,
            &raw,
        )?;
        if canonical(&t.source_maps)? != map_bytes
            || t.source_maps_sha256 != d.source_maps_sha256
            || t.source_sha256 != d.source_sha256
            || t.program_sha256 != d.program_sha256
        {
            return Err("tail independently rebuilt identity differs".into());
        }
        tail_reference(&case, &t, group)?;
        let facts = source::ComponentFacts {
            index,
            branch: "tail".into(),
            global_ids: t.global_ids.clone(),
            global_ids_sha256: sha256::Hash::hash(&canonical(&json!(t.global_ids))?).to_string(),
            input_indices: t.digest_indices.clone(),
            output_indices: t.result_indices.clone(),
            producer_ordinals: vec![],
            producer_occurrences: vec![],
            input_consumer_occurrences: (1..=64).map(|i| vec![(i, 0)]).collect(),
        };
        let source_value = t.source_manifest.clone();
        (facts, None, Some(t), source_value)
    };
    if facts.global_ids_sha256 != d.global_ids_sha256
        || h.maps_file_sha256 != d.source_maps_sha256
        || checked_file(
            root,
            &h.source_manifest_filename,
            MANIFEST_CAP,
            &h.source_manifest_file_sha256,
            h.source_manifest_file_bytes,
        )? != canonical(&source_value)?
    {
        return Err("component source/global file identity differs".into());
    }
    let false_rows = native_false(&case, index)?;
    let expected = if group.profile == "bad-hi-digest" && index == 0 {
        vec![29241]
    } else if group.profile == "bad-lo-frame" && index == 2 {
        vec![363]
    } else if group.profile == "wrong-result" && index == 2 {
        let t = checked_tail
            .as_ref()
            .ok_or("wrong result requires checked uniform topology")?;
        let mut raw = [0u8; 64];
        raw[..32].copy_from_slice(&fixed_hex::<200>(&group.expected_lo_output_state_hex)?[..32]);
        raw[32..].copy_from_slice(&fixed_hex::<200>(&group.expected_hi_output_state_hex)?[..32]);
        let (honest_result, _) = tail::reduction(&raw, &group.role)?;
        wrong_result_false(&t.uniform_metadata, &honest_result)?
    } else {
        vec![]
    };
    if false_rows != expected
        || false_rows != h.expected_false
        || group.profile == "wrong-result" && index == 2 && false_rows.is_empty()
    {
        return Err("exact native controlled fault profile differs".into());
    }
    let ordinals: Vec<_> = match h.execution_mode.as_str() {
        "all" => (0..d.leaves).collect(),
        "none" => vec![],
        "selected" => h
            .selected_ordinals
            .clone()
            .ok_or("selected leaves missing")?,
        _ => return Err("execution mode".into()),
    };
    if case.checks.len() != ordinals.len()
        || case
            .checks
            .iter()
            .zip(ordinals)
            .any(|(c, i)| c.ordinal != i || c.expected_correct == false_rows.contains(&i))
    {
        return Err("actual ordered Script selection/truth differs".into());
    }
    Ok(Prepared {
        case,
        facts,
        full,
        tail: checked_tail,
    })
}
fn wrong_result_false(metadata: &Value, honest_result: &[u8; 32]) -> Result<Vec<usize>> {
    // Re-witnessing c-1 while keeping q leaves the first base-256 remainder
    // equal to one. The c=0 -> c'=1 fallback instead leaves remainder255
    // in every column and contradicts the unchanged final zero carry.
    let columns = metadata["column_ordinals"]
        .as_array()
        .ok_or("checked uniform column ordinals")?;
    let first = columns
        .first()
        .and_then(Value::as_u64)
        .ok_or("checked first uniform column ordinal")?;
    let mut expected = vec![usize::try_from(first)?];
    if honest_result.iter().all(|byte| *byte == 0) {
        expected.clear();
        for column in columns {
            expected.push(usize::try_from(
                column
                    .as_u64()
                    .ok_or("checked uniform column ordinal type")?,
            )?);
        }
        expected.push(usize::try_from(
            metadata["final_anchor_ordinal"]
                .as_u64()
                .ok_or("checked final carry anchor ordinal")?,
        )?);
        expected.sort_unstable();
    }
    Ok(expected)
}
fn native_false(case: &Case, index: usize) -> Result<Vec<usize>> {
    (0..case.spec.leaves.len())
        .filter_map(|i| {
            match if index < 2 {
                permutation::truth(&case.spec, &case.words, i)
            } else {
                tail::truth(&case.spec, &case.words, i)
            } {
                Ok(true) => None,
                Ok(false) => Some(Ok(i)),
                Err(e) => Some(Err(e)),
            }
        })
        .collect()
}
fn tail_reference(case: &Case, t: &tail::CheckedTail, group: &Group) -> Result<()> {
    let lo = fixed_hex::<200>(&group.expected_lo_output_state_hex)?;
    let hi = fixed_hex::<200>(&group.expected_hi_output_state_hex)?;
    let mut raw = [0u8; 64];
    raw[..32].copy_from_slice(&lo[..32]);
    raw[32..].copy_from_slice(&hi[..32]);
    let (mut c, q) = tail::reduction(&raw, &group.role)?;
    if group.profile == "wrong-result" {
        if c.iter().any(|b| *b != 0) {
            for b in &mut c {
                let (v, borrow) = b.overflowing_sub(1);
                *b = v;
                if !borrow {
                    break;
                }
            }
        } else {
            c[0] = 1;
        }
    }
    if raw != fixed_hex::<64>(&group.expected_raw_state_le)?
        || c != fixed_hex::<32>(&group.expected_result_le)?
        || q != fixed_hex::<33>(&group.expected_quotient_le)?
    {
        return Err("independent unsigned512 result/quotient differs".into());
    }
    for (i, slot) in t.digest_indices.iter().enumerate() {
        if case.words[*slot] != u32::from(raw[i]) {
            return Err("LO then HI reducer byte input differs".into());
        }
    }
    for (prefix, bytes) in [
        ("result/encoding/byte/", c.as_slice()),
        ("quotient/byte/", q.as_slice()),
    ] {
        for (i, value) in bytes.iter().enumerate() {
            let name = format!("{prefix}{i}");
            let slot = case
                .spec
                .words
                .iter()
                .position(|w| w.name == name)
                .ok_or("result/quotient canonical byte absent")?;
            if case.words[slot] != u32::from(*value) {
                return Err("reducer canonical byte assignment differs".into());
            }
        }
    }
    Ok(())
}

struct RecordSink {
    hash: sha256::HashEngine,
    bytes: u64,
}
impl Write for RecordSink {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        let next = self
            .bytes
            .checked_add(data.len() as u64)
            .ok_or_else(|| std::io::Error::other("record size overflow"))?;
        if next > RECORD_CAP {
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
    sink: &mut RecordSink,
    metrics: &mut Metrics,
    code: &ScriptBuf,
    witness: &[Vec<u8>],
    expected: bool,
    group: &str,
    id: Value,
    disprove: bool,
) -> Result<()> {
    if id.as_str().is_some_and(|s| s.len() > 64) {
        return Err("compact identifier exceeds64bytes".into());
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
fn registry_for(
    prepared: &Prepared,
    pool: &keys::GlobalPool,
) -> Result<(Registry, Vec<PublicKey>, Vec<Signature>)> {
    let mut public = Vec::with_capacity(prepared.case.words.len());
    let mut signatures = Vec::with_capacity(prepared.case.words.len());
    for ((id, word), value) in prepared
        .facts
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
fn guards(
    registry: &Registry,
    signatures: &[Signature],
    sink: &mut RecordSink,
    metrics: &mut Metrics,
    group: &str,
    component: usize,
) -> Result<usize> {
    let mut shapes = HashSet::new();
    for ordinal in 0..registry.spec().leaves.len() {
        if !shapes.insert(permutation::auth_shape(registry.spec(), ordinal)) {
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
    if component < 2 && shapes.len() != 23 {
        return Err("all23 permutation authenticated layouts required".into());
    }
    Ok(shapes.len())
}
fn measure_execute(
    p: &Prepared,
    h: &Header,
    registry: &Registry,
    signatures: &[Signature],
    sink: &mut RecordSink,
    metrics: &mut Metrics,
    group: &str,
    global_stream: &mut sha256::HashEngine,
) -> Result<Value> {
    let mut compiled = 0u64;
    let mut largest = 0usize;
    let mut stream = sha256::Hash::engine();
    let mut check = 0usize;
    for ordinal in 0..p.case.spec.leaves.len() {
        let disproof = registry.script(ordinal, true)?;
        bitvm2_nova_script_oracle::engine::validate(&disproof)?;
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
            let witness = registry.witness(ordinal, signatures)?;
            record(
                sink,
                metrics,
                &registry.script(ordinal, false)?,
                &witness,
                expected,
                group,
                json!([h.descriptor.index, ordinal]),
                false,
            )?;
            record(
                sink,
                metrics,
                &disproof,
                &witness,
                !expected,
                group,
                json!([h.descriptor.index, ordinal]),
                true,
            )?;
            check += 1;
        }
    }
    if check != p.case.checks.len() {
        return Err("unexecuted selected predicate".into());
    }
    let layouts = guards(
        registry,
        signatures,
        sink,
        metrics,
        group,
        h.descriptor.index,
    )?;
    let mut ledger = serde_json::to_value(&h.descriptor)?;
    permutation::extend_object(
        &mut ledger,
        json!({"context":p.case.spec.context,"registry_id":hex::encode(registry.identity()),"compiled_script_bytes":compiled,"largest_disproof_leaf_bytes":largest,"compiled_stream_sha256":sha256::Hash::from_engine(stream).to_string(),"execution_mode":h.execution_mode,"selected_ordinals":h.selected_ordinals,"executed_leaves":check,"native_predicates_checked":p.case.spec.leaves.len(),"false_predicates":h.expected_false,"guard_layouts":layouts,"guard_vectors":14*layouts}),
    )?;
    Ok(ledger)
}

#[derive(Clone)]
struct Capture {
    id: String,
    bound: u32,
    value: u32,
    key: PublicKey,
    signature: Signature,
    opening: Vec<Vec<u8>>,
}
fn capture(
    registry: &Registry,
    public: &[PublicKey],
    signatures: &[Signature],
    values: &[u32],
    ids: &[String],
    ordinal: usize,
    formal: usize,
) -> Result<Capture> {
    let slot = *registry
        .spec()
        .leaves
        .get(ordinal)
        .and_then(|l| l.wires.get(formal))
        .ok_or("capture actual operand bounds")?;
    Ok(Capture {
        id: ids.get(slot).ok_or("capture global ID bounds")?.clone(),
        bound: registry
            .spec()
            .words
            .get(slot)
            .ok_or("capture bound")?
            .bound,
        value: *values.get(slot).ok_or("capture value")?,
        key: *public.get(slot).ok_or("capture key")?,
        signature: *signatures.get(slot).ok_or("capture signature")?,
        opening: opening(registry, signatures, ordinal, slot)?,
    })
}
fn same_assertion(left: &Capture, right: &Capture) -> Result<()> {
    if left.id != right.id
        || left.bound != right.bound
        || left.value != right.value
        || left.key != right.key
        || left.signature != right.signature
        || left.opening != right.opening
    {
        return Err("actual global source bound/value/key/signature/opening changed".into());
    }
    Ok(())
}
fn pool_capture(pool: &keys::GlobalPool, id: &str, bound: u32, value: u32) -> Result<Capture> {
    let (key, signature) = pool.lookup(id, bound, value)?;
    Ok(Capture {
        id: id.into(),
        bound,
        value,
        key: *key,
        signature: *signature,
        opening: signature.iter().map(|s| s.to_vec()).collect(),
    })
}
fn capture_negatives(entry: &Capture, foreign: &Capture) -> Result<usize> {
    let mut count = 0;
    for mutation in 0..6 {
        let mut bad = entry.clone();
        match mutation {
            0 => bad.value ^= 1,
            1 => bad.bound = if bad.bound == 2 { 256 } else { 2 },
            2 => bad.key = foreign.key,
            3 => bad.signature = foreign.signature,
            4 => {
                *bad.opening
                    .first_mut()
                    .and_then(|b| b.first_mut())
                    .ok_or("cache original digit empty")? ^= 1
            }
            _ => bad.id.push_str("/swapped"),
        };
        if same_assertion(&bad, entry).is_ok() {
            return Err("altered original assertion cache accepted".into());
        }
        count += 1;
    }
    Ok(count)
}
fn internal_links(
    p: &Prepared,
    registry: &Registry,
    public: &[PublicKey],
    signatures: &[Signature],
) -> Result<(usize, usize)> {
    let full = p.full.as_ref().ok_or("full state cache topology missing")?;
    let mut entries = 0usize;
    let mut links = 0usize;
    for join in 0..23 {
        let left = &full.rounds[join];
        let right = &full.rounds[join + 1];
        let uses = permutation::consumers(right);
        for i in 0..200 {
            let (local, formal) = left.layout.ports.producers[i];
            let ordinal = left.first_leaf + local;
            let original = capture(
                registry,
                public,
                signatures,
                &p.case.words,
                &p.facts.global_ids,
                ordinal,
                formal,
            )?;
            let source_slot = left.map[left.layout.ports.outputs[i]];
            let incoming = right.map[right.layout.ports.inputs[i]];
            if source_slot != incoming
                || original.bound != 256
                || registry.spec().leaves[ordinal].wires[formal] != source_slot
            {
                return Err("state join actual producer/consumer word differs".into());
            }
            for (consumer, occurrence) in &uses[i] {
                let next = capture(
                    registry,
                    public,
                    signatures,
                    &p.case.words,
                    &p.facts.global_ids,
                    *consumer,
                    *occurrence,
                )?;
                same_assertion(&original, &next)?;
                links += 1;
            }
            entries += 1;
        }
    }
    if entries != 4600 || links != 9200 {
        return Err("all23 state opening caches required".into());
    }
    Ok((entries, links))
}
#[derive(Default)]
struct CrossCache {
    frames: HashMap<String, Vec<Capture>>,
    digests: HashMap<String, Capture>,
    message_checks: usize,
    frame_checks: usize,
    digest_checks: usize,
    negative_checks: usize,
}
fn source_links(
    p: &Prepared,
    registry: &Registry,
    public: &[PublicKey],
    signatures: &[Signature],
    pool: &keys::GlobalPool,
    cache: &mut CrossCache,
) -> Result<()> {
    let branch = &p.facts.branch;
    let foreign = pool_capture(
        pool,
        &p.facts.global_ids[100],
        p.case.spec.words[100].bound,
        p.case.words[100],
    )?;
    let mut origin_representative = None;
    let mut frame_representative = None;
    let mut digest_representative = None;
    for i in 0..200 {
        let word = p.facts.input_indices[i];
        let id = &p.facts.global_ids[word];
        let is_message = (1..=32).contains(&i) || (45..=108).contains(&i);
        let mut captures = Vec::new();
        for (ordinal, formal) in &p.facts.input_consumer_occurrences[i] {
            if registry
                .spec()
                .leaves
                .get(*ordinal)
                .and_then(|l| l.wires.get(*formal))
                != Some(&word)
            {
                return Err("actual message/frame input occurrence differs".into());
            }
            let actual = capture(
                registry,
                public,
                signatures,
                &p.case.words,
                &p.facts.global_ids,
                *ordinal,
                *formal,
            )?;
            same_assertion(&actual, &pool_capture(pool, id, 256, p.case.words[word])?)?;
            if is_message {
                cache.message_checks += 1;
                origin_representative.get_or_insert(actual.clone());
            } else {
                frame_representative.get_or_insert(actual.clone());
                captures.push(actual);
            }
        }
        if !is_message && cache.frames.insert(id.clone(), captures).is_some() {
            return Err("private frame source aliased".into());
        }
    }
    for i in 0..32 {
        let actual = capture(
            registry,
            public,
            signatures,
            &p.case.words,
            &p.facts.global_ids,
            p.facts.producer_ordinals[i],
            p.facts.producer_occurrences[i],
        )?;
        if actual.id != p.facts.global_ids[p.facts.output_indices[i]] {
            return Err("digest producer is not natural terminal BYTE".into());
        }
        digest_representative.get_or_insert(actual.clone());
        if cache.digests.insert(actual.id.clone(), actual).is_some() {
            return Err("private digest aliased".into());
        }
    }
    if branch == "hi" {
        cache.negative_checks += capture_negatives(
            origin_representative
                .as_ref()
                .ok_or("message cache missing")?,
            &foreign,
        )?;
    }
    cache.negative_checks += capture_negatives(
        frame_representative.as_ref().ok_or("frame cache missing")?,
        &foreign,
    )?;
    cache.negative_checks += capture_negatives(
        digest_representative
            .as_ref()
            .ok_or("digest cache missing")?,
        &foreign,
    )?;
    Ok(())
}
fn tail_links(
    p: &Prepared,
    registry: &Registry,
    public: &[PublicKey],
    signatures: &[Signature],
    cache: &mut CrossCache,
) -> Result<()> {
    let tail = p.tail.as_ref().ok_or("tail facts missing")?;
    for frame in &tail.frame_records {
        let producer = capture(
            registry,
            public,
            signatures,
            &p.case.words,
            &p.facts.global_ids,
            frame.anchor_ordinal,
            0,
        )?;
        if producer.id != frame.global_id || producer.bound != 256 {
            return Err("framing anchor actual BYTE differs".into());
        }
        let consumers = cache
            .frames
            .get(&frame.global_id)
            .ok_or("original source frame openings missing")?;
        if consumers.len() != 2 {
            return Err("two original frame consumers required".into());
        }
        for consumer in consumers {
            same_assertion(&producer, consumer)?;
            cache.frame_checks += 1;
        }
    }
    for (i, slot) in tail.digest_indices.iter().enumerate() {
        let actual = capture(
            registry,
            public,
            signatures,
            &p.case.words,
            &p.facts.global_ids,
            1 + i,
            0,
        )?;
        if registry.spec().leaves[1 + i].kind != "conv_ab"
            || registry.spec().leaves[1 + i].wires[0] != *slot
        {
            return Err("unchanged unit input adapter occurrence differs".into());
        }
        same_assertion(
            &actual,
            cache
                .digests
                .get(&actual.id)
                .ok_or("natural digest producer opening missing")?,
        )?;
        cache.digest_checks += 1;
    }
    if cache.frames.len() != 208
        || cache.digests.len() != 64
        || cache.message_checks != 384
        || cache.frame_checks != 416
        || cache.digest_checks != 64
        || cache.negative_checks != 30
    {
        return Err("exact original cross-component opening census differs".into());
    }
    Ok(())
}

fn compare_source(
    run: &Run,
    g: &Group,
    descriptors: &[source::ComponentDescriptor],
    facts: &[source::ComponentFacts],
    tail_maps: &Value,
) -> Result<source::CheckedSource> {
    let checked = source::build(
        &run.context,
        &g.role,
        g.counter,
        &run.operation_id,
        descriptors,
        facts,
        tail_maps,
    )?;
    if checked.source_sha256 != g.source_sha256
        || checked.source_maps_sha256 != g.source_maps_sha256
    {
        return Err("outer source/maps differ from independently pinned scenario identity".into());
    }
    Ok(checked)
}
fn admission_negatives(
    run: &Run,
    g: &Group,
    descriptors: &[source::ComponentDescriptor],
    facts: &[source::ComponentFacts],
    tail_maps: &Value,
) -> Result<(usize, usize)> {
    let mut map_count = 0;
    let mut source_count = 0;
    for mutation in 0..8 {
        let mut bad = facts.to_vec();
        match mutation {
            0 => bad[0].global_ids[0] = bad[0].global_ids[1].clone(),
            1 => bad[0].global_ids.swap(0, 1),
            2 => bad[1].global_ids[0] = bad[0].global_ids[0].clone(),
            3 => bad[0].input_indices.swap(0, 1),
            4 => bad[0].output_indices.swap(0, 1),
            5 => bad[1].producer_ordinals[0] += 1,
            6 => bad[1].producer_occurrences[0] = 2,
            _ => bad[0].input_consumer_occurrences[0][0].0 += 1,
        }
        if compare_source(run, g, descriptors, &bad, tail_maps).is_ok() {
            return Err("substituted outer origin/frame/digest map accepted".into());
        }
        map_count += 1;
    }
    for mutation in 0..12 {
        let mut bad = descriptors.to_vec();
        match mutation {
            0 => bad[0].field_role = "wrong-role".into(),
            1 => bad[0].counter += 1,
            2 => bad[0].operation_id.push_str("/different"),
            3 => bad[0].program_sha256 = permutation::changed(&bad[0].program_sha256)?,
            4 => bad[0].catalogue_id = permutation::changed(&bad[0].catalogue_id)?,
            5 => bad[0].source_sha256 = permutation::changed(&bad[0].source_sha256)?,
            6 => bad[0].source_maps_sha256 = permutation::changed(&bad[0].source_maps_sha256)?,
            7 => bad[0].global_ids_sha256 = permutation::changed(&bad[0].global_ids_sha256)?,
            8 => bad[2].kind = "full-permutation".into(),
            9 => bad[2].program_identity_kind = "imported root receipt".into(),
            10 => bad[1].words += 1,
            _ => bad.swap(0, 1),
        }
        if compare_source(run, g, &bad, facts, tail_maps).is_ok() {
            return Err("substituted outer component source identity accepted".into());
        }
        source_count += 1;
    }
    Ok((map_count, source_count))
}
fn reject<T>(
    result: Result<T>,
    name: &'static str,
    counts: &mut BTreeMap<&'static str, usize>,
) -> Result<()> {
    if result.is_ok() {
        return Err(format!("negative forest opening accepted: {name}").into());
    }
    *counts.entry(name).or_default() += 1;
    Ok(())
}
fn forest_negatives(
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
        forest.verify_member(registry, manifest, root, key, (component + 1) % 3, ordinal),
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
fn selected_leaf(g: &Group) -> Result<(usize, usize)> {
    Ok(match g.profile.as_str() {
        "honest" => (2, 452),
        "bad-hi-digest" => (0, 29241),
        "bad-lo-frame" => (2, 363),
        "wrong-result" => (
            2,
            *g.components[2]
                .expected_false
                .first()
                .ok_or("wrong result lacks counterexample")?,
        ),
        _ => return Err("closed rho profile".into()),
    })
}
fn group_run(
    run: &Run,
    g: &Group,
    root: &Path,
    sink: &mut RecordSink,
    metrics: &mut Metrics,
) -> Result<Value> {
    // Phase one performs every identity/reference/topology/declaration check.
    // No WOTS seed, key or signature exists until this phase has succeeded.
    let mut declarations = keys::Declarations::new();
    let mut facts = Vec::new();
    let mut tail_maps = None;
    for index in 0..3 {
        let p = prepare(run, g, index, root)?;
        for ((id, word), value) in p
            .facts
            .global_ids
            .iter()
            .zip(&p.case.spec.words)
            .zip(&p.case.words)
        {
            declarations.add(id, word.bound, *value)?;
        }
        facts.push(p.facts.clone());
        if let Some(t) = p.tail {
            tail_maps = Some(t.source_maps);
        }
        // All full graphs and their projected views die at this loop boundary.
    }
    let descriptors: Vec<_> = g.components.iter().map(|h| h.descriptor.clone()).collect();
    let tail_maps = tail_maps.ok_or("tail maps absent")?;
    let outer = compare_source(run, g, &descriptors, &facts, &tail_maps)?;
    if checked_file(
        root,
        &g.rho_maps_filename,
        MAP_CAP,
        &g.rho_maps_file_sha256,
        g.rho_maps_file_bytes,
    )? != canonical(&outer.maps)?
        || checked_file(
            root,
            &g.rho_source_filename,
            MANIFEST_CAP,
            &g.rho_source_file_sha256,
            g.rho_source_file_bytes,
        )? != canonical(&outer.manifest)?
    {
        return Err("outer canonical source sidecars differ".into());
    }
    let (map_rejections, source_rejections) =
        admission_negatives(run, g, &descriptors, &facts, &tail_maps)?;
    drop(outer);
    drop(facts);
    drop(tail_maps);
    drop(descriptors);
    let pool = declarations.seal(&g.source_sha256, &g.name)?;
    if pool.len() != 59109
        || pool.local_declarations() != 59477
        || pool.cached_signature_reuses() != 368
    {
        return Err("global signature inventory changed".into());
    }
    let (chosen_component, chosen_leaf) = selected_leaf(g)?;
    let mut components = Vec::new();
    let mut live = Vec::new();
    let mut cache = CrossCache::default();
    let mut global_stream = sha256::Hash::engine();
    let mut native_rejections = 0usize;
    let mut internal_entries = 0usize;
    let mut internal_openings = 0usize;
    let mut normal = 0usize;
    let mut layouts = 0usize;
    for index in 0..3 {
        let p = prepare(run, g, index, root)?;
        let h = &g.components[index];
        let (registry, public, signatures) = registry_for(&p, &pool)?;
        let mut foreign_seed = sha256::Hash::engine();
        foreign_seed.input(b"BITVM2-NOVA/BYTE-RHO/FOREIGN-TEST-ONLY/v1\0");
        foreign_seed.input(&digest(&g.source_sha256)?);
        foreign_seed.input(g.name.as_bytes());
        foreign_seed.input(&[index as u8]);
        let secret = sha256::Hash::from_engine(foreign_seed)
            .to_byte_array()
            .to_vec();
        let foreign = Wots4::generate_public_key(&secret);
        if public.contains(&foreign) {
            return Err("foreign test key collided".into());
        }
        native_rejections +=
            permutation::native_negatives(&p.case, &public, &signatures, foreign, &registry)?;
        let ledger = measure_execute(
            &p,
            h,
            &registry,
            &signatures,
            sink,
            metrics,
            &g.name,
            &mut global_stream,
        )?;
        normal += p.case.checks.len();
        layouts += ledger["guard_layouts"]
            .as_u64()
            .ok_or("guard layout integer")? as usize;
        if index < 2 {
            let (entries, links) = internal_links(&p, &registry, &public, &signatures)?;
            internal_entries += entries;
            internal_openings += links;
            source_links(&p, &registry, &public, &signatures, &pool, &mut cache)?;
        } else {
            tail_links(&p, &registry, &public, &signatures, &mut cache)?;
        }
        let selected = if index == chosen_component {
            chosen_leaf
        } else {
            0
        };
        let tree = TaprootCommitment::new(&registry, selected)?;
        if tree.registry_id() != registry.identity()
            || tree.catalogue_id() != digest(&h.descriptor.catalogue_id)?
            || tree.leaf_count() != h.descriptor.leaves
            || tree.compiled_script_bytes()
                != ledger["compiled_script_bytes"]
                    .as_u64()
                    .ok_or("component compiled count")?
            || hex::encode(tree.compiled_stream_sha256())
                != ledger["compiled_stream_sha256"]
                    .as_str()
                    .ok_or("component stream hash")?
        {
            return Err("live component tree differs from complete measured Script stream".into());
        }
        tree.verify_member(&registry, tree.merkle_root(), tree.output_key(), selected)?;
        components.push(ledger);
        live.push(tree);
        // Registry includes a recovery/compiler cache: release it before LO.
        drop(registry);
        drop(public);
        drop(signatures);
        drop(p);
    }
    if native_rejections != 72 || internal_entries != 9200 || internal_openings != 18400 {
        return Err("native/state cache census differs".into());
    }
    // Re-admit ONLY the selected component after both full registries have
    // been released. Immutable lookup reuses every original assertion.
    let selected = prepare(run, g, chosen_component, root)?;
    let (registry, _, signatures) = registry_for(&selected, &pool)?;
    let forest = TaprootForest::new(&live, chosen_component)?;
    forest.verify_member(
        &registry,
        forest.component_manifest_sha256(),
        forest.merkle_root(),
        forest.output_key(),
        chosen_component,
        chosen_leaf,
    )?;
    if forest.component_count() != 3
        || forest.leaf_count() != 58943
        || forest.compiled_script_bytes()
            != components
                .iter()
                .map(|c| c["compiled_script_bytes"].as_u64().unwrap_or(0))
                .sum::<u64>()
        || forest.selected_script().as_bytes() != registry.script(chosen_leaf, true)?.as_bytes()
    {
        return Err("whole live forest census or selected Script differs".into());
    }
    let count = if chosen_component < 2 {
        29245usize
    } else {
        453
    };
    let height = count.ilog2();
    let deep = 2 * (count - (1usize << height));
    let expected_control = 33
        + 32 * (height as usize
            + usize::from(chosen_leaf < deep)
            + if chosen_component < 2 { 2 } else { 1 });
    let control = forest.control_block_bytes();
    if control.len() != expected_control || control.len() > 33 + 32 * 19 {
        return Err("exact hierarchical control depth differs".into());
    }
    let correct = !g.components[chosen_component]
        .expected_false
        .contains(&chosen_leaf);
    if correct != (g.profile == "honest") {
        return Err("selected honest/disproof profile differs".into());
    }
    let witness = registry.witness(chosen_leaf, &signatures)?;
    for disprove in [false, true] {
        record(
            sink,
            metrics,
            &registry.script(chosen_leaf, disprove)?,
            &witness,
            correct != disprove,
            &g.name,
            json!(format!("{chosen_component}/tree/{chosen_leaf}")),
            disprove,
        )?;
    }
    let negatives = forest_negatives(&forest, &registry, &mut live)?;
    let forest_row = json!({"components":3,"leaf_count":forest.leaf_count(),"compiled_script_bytes":forest.compiled_script_bytes(),"selected_component":chosen_component,"selected_leaf":chosen_leaf,"control_block_bytes":control.len(),"merkle_root":hex::encode(forest.merkle_root().to_byte_array()),"output_key":hex::encode(forest.output_key().serialize()),"control_block_sha256":sha256::Hash::hash(&control).to_string(),"selected_script_sha256":sha256::Hash::hash(forest.selected_script().as_bytes()).to_string(),"component_manifest_sha256":hex::encode(forest.component_manifest_sha256()),"compiled_stream_sha256":sha256::Hash::from_engine(global_stream).to_string(),"hierarchical_membership_verified":true,"roots_independently_pinned":false,"negative_counts":negatives});
    let mut row = json!({"name":g.name,"profile":g.profile,"role":g.role,"counter":g.counter,"execution_mode":g.execution_mode,"source_sha256":g.source_sha256,"source_maps_sha256":g.source_maps_sha256,"expected_raw_state_le":g.expected_raw_state_le,"expected_result_le":g.expected_result_le,"expected_quotient_le":g.expected_quotient_le,"full_statement_executed":g.execution_mode=="full","components":components,"forest":forest_row});
    permutation::extend_object(
        &mut row,
        json!({"signature_entries_created":pool.len(),"cached_signature_reuses":pool.cached_signature_reuses(),"message_origins":96,"message_consumer_opening_links":cache.message_checks,"framing_anchors":cache.frames.len(),"framing_consumer_opening_links":cache.frame_checks,"digest_producer_consumer_links":cache.digest_checks,"internal_cached_boundary_entries":internal_entries,"internal_producer_consumer_opening_links":internal_openings}),
    )?;
    permutation::extend_object(
        &mut row,
        json!({"all_native_predicates_checked":58943,"selected_leaf_checks":normal,"guard_layouts":layouts,"guard_vectors":14*layouts,"native_rejections":native_rejections,"map_rejections":map_rejections,"source_rejections":source_rejections,"cache_rejections":cache.negative_checks,"selected_component":chosen_component,"selected_leaf":chosen_leaf,"additional_selected_engine_executions":2,"selected_correctness_execution_success":correct,"selected_disproof_execution_success":!correct}),
    )?;
    Ok(row)
}

fn inventory(run: &Run, root: &Path) -> Result<()> {
    let info = fs::symlink_metadata(root)?;
    if !info.is_dir() || info.file_type().is_symlink() {
        return Err("plain case directory required".into());
    }
    let mut names = HashSet::from(["manifest.json".to_string()]);
    for g in &run.cases {
        for name in [&g.rho_source_filename, &g.rho_maps_filename] {
            if !names.insert(name.clone()) {
                return Err("duplicate pinned file".into());
            }
        }
        for h in &g.components {
            for name in [&h.filename, &h.maps_filename, &h.source_manifest_filename] {
                if !names.insert(name.clone()) {
                    return Err("duplicate component file".into());
                }
            }
            if let Some(name) = &h.program_manifest_filename {
                if !names.insert(name.clone()) {
                    return Err("duplicate program file".into());
                }
            }
        }
    }
    let actual = fs::read_dir(root)?
        .map(|entry| {
            let entry = entry?;
            let ty = entry.file_type()?;
            if !ty.is_file() || ty.is_symlink() {
                return Err("case inventory contains nonregular entry".into());
            }
            entry
                .file_name()
                .into_string()
                .map_err(|_| "nonASCII case filename".into())
        })
        .collect::<Result<HashSet<String>>>()?;
    if names.len() != 105 || actual != names {
        return Err("exact105 pinned source/case files required before keys".into());
    }
    Ok(())
}
fn run() -> Result<Value> {
    let started = Instant::now();
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 5 {
        return Err(
            "usage: byte_rho MANIFEST CASE_DIRECTORY OUTPUT EXPECTED_MANIFEST_SHA256".into(),
        );
    }
    let root = Path::new(&args[2]);
    let manifest_path = Path::new(&args[1]);
    if manifest_path.file_name().and_then(|s| s.to_str()) != Some("manifest.json")
        || manifest_path.canonicalize()? != root.join("manifest.json").canonicalize()?
    {
        return Err("manifest must be the pinned case-directory manifest".into());
    }
    if Path::new(&args[3]).exists() {
        return Err("fresh native output required".into());
    }
    let expected = digest(&args[4])?;
    let bytes = permutation::snapshot(manifest_path, MANIFEST_CAP, expected)?;
    let run: Run = serde_json::from_slice(&bytes)?;
    validate_run(&run)?;
    inventory(&run, root)?;
    drop(bytes);
    let mut sink = RecordSink {
        hash: sha256::Hash::engine(),
        bytes: 0,
    };
    let mut metrics = Metrics::default();
    let mut cases = Vec::new();
    for g in &run.cases {
        cases.push(group_run(&run, g, root, &mut sink, &mut metrics)?);
    }
    let normal = 237588usize;
    let guards = cases
        .iter()
        .map(|c| c["guard_vectors"].as_u64().unwrap_or(0) as usize)
        .sum::<usize>();
    if metrics.vectors != 2 * normal + guards + 16
        || metrics.expected_rejections != normal + guards + 8
        || sink.bytes < 100077184
        || sink.bytes > 115189564
        || sink.bytes > RECORD_CAP
        || started.elapsed().as_secs_f64() > 1260.0
    {
        return Err(
            "exact execution census/independent unchanged record budget/wall cap differs".into(),
        );
    }
    let mut result = json!({"schema":"bitvm2-nova-byte-rho-execution/v1","passed":true,"input_manifest_sha256":hex::encode(expected),"cases":cases,"metrics":metrics,"compact_execution_records_bytes":sink.bytes,"compact_execution_records_sha256":sha256::Hash::from_engine(sink.hash).to_string(),"wall_seconds":started.elapsed().as_secs_f64(),"full_statement_cases":4,"targeted_statement_cases":4});
    permutation::extend_object(
        &mut result,
        json!({"signature_entries_created":8*59109,"cached_signature_reuses":8*368,"message_origins":8*96,"message_consumer_opening_links":8*384,"framing_anchors":8*208,"framing_consumer_opening_links":8*416,"digest_producer_consumer_links":8*64,"internal_cached_boundary_entries":8*9200,"internal_producer_consumer_opening_links":8*18400}),
    )?;
    for flag in [
        "framed_rho_script_conformance_checked",
        "all_native_reference_predicates_checked",
        "boundary_opening_links_checked",
        "framing_constants_script_bound",
        "both_digest_endpoints_script_bound",
        "digest_reduction_script_bound",
        "test_keys_only",
        "stack_limit_enabled",
        "hierarchical_membership_verified",
    ] {
        result
            .as_object_mut()
            .ok_or("result object")?
            .insert(flag.into(), json!(true));
    }
    for flag in [
        "all_cases_full_statement_executed",
        "raw_vector_file_written",
        "op_cat_enabled",
        "full_permutation_verified",
        "full_hash_verified",
        "transcript_verified",
        "nova_transcript_verified_in_script",
        "proof_verified",
        "complete_nova_verifier",
        "complete_bitvm2_verifier",
        "production_assertion_binding",
        "bitcoin_transaction_graph",
        "panic_is_rejection",
        "eval_w_canonicality_script_bound",
        "dynamic_message_sources_script_bound",
        "eval_w_proof_origin_bound",
        "prior_state_transcript_bound",
        "complete_keccak_sponge",
    ] {
        result
            .as_object_mut()
            .ok_or("result object")?
            .insert(flag.into(), json!(false));
    }
    for key in [
        "setup_calls",
        "proving_jobs",
        "native_proofs_verified",
        "gpu_jobs",
        "transactions_broadcast",
    ] {
        result
            .as_object_mut()
            .ok_or("result object")?
            .insert(key.into(), json!(0));
    }
    let raw = serde_json::to_vec(&result)?;
    if raw.len() > SUMMARY_CAP {
        return Err("native summary exceeds unchanged1MiB cap".into());
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
    #[test]
    fn closed_json_types_and_unknown_fields() {
        let root = json!({"schema":"x","context":"00".repeat(32),"operation_id":"test","cases":[]});
        assert!(serde_json::from_value::<Run>(root.clone()).is_ok());
        let mut bad = root.clone();
        bad["unexpected"] = json!(1);
        assert!(serde_json::from_value::<Run>(bad).is_err());
        let mut bad = root;
        bad["cases"] = json!(true);
        assert!(serde_json::from_value::<Run>(bad).is_err());
        assert!(serde_json::from_value::<Header>(json!({"descriptor":true})).is_err());
    }
    #[test]
    fn exact_bytes_and_flat_pins() {
        assert_eq!(fixed_hex::<2>("00ff").unwrap(), [0, 255]);
        for bad in ["00FF", "00ff00", "0", "xz"] {
            assert!(fixed_hex::<2>(bad).is_err());
        }
        for bad in ["../secret", "sub/file.json", "C:secret", ""] {
            assert!(checked_file(Path::new("."), bad, 1, "00", 1).is_err());
        }
        assert!(checked_file(Path::new("."), "case.json", 1, &"00".repeat(32), 2).is_err());
    }
    #[test]
    fn explicit_full_and_targeted_selection() {
        for component in 0..3 {
            assert_eq!(selected("honest", component), ("all", None));
            assert_eq!(selected("bad-hi-digest", component), ("all", None));
        }
        assert_eq!(selected("bad-lo-frame", 0), ("none", None));
        assert_eq!(
            selected("bad-lo-frame", 1),
            ("selected", Some(vec![125, 351]))
        );
        assert_eq!(selected("bad-lo-frame", 2), ("all", None));
        assert_eq!(selected("wrong-result", 0), ("none", None));
        assert_eq!(selected("wrong-result", 1), ("none", None));
        assert_eq!(selected("wrong-result", 2), ("all", None));
    }
    #[test]
    fn compact_record_cap_is_fail_closed() {
        let mut sink = RecordSink {
            hash: sha256::Hash::engine(),
            bytes: RECORD_CAP,
        };
        assert!(sink.write_all(b"x").is_err());
        assert_eq!(sink.bytes, RECORD_CAP);
        let mut sink = RecordSink {
            hash: sha256::Hash::engine(),
            bytes: u64::MAX,
        };
        assert!(sink.write_all(b"x").is_err());
    }
    #[test]
    fn wrong_result_faults_are_derived_from_reduction_and_checked_topology() {
        let metadata = json!({"column_ordinals":[85,86,87], "final_anchor_ordinal":243});
        let mut positive = [0u8; 32];
        positive[15] = 1;
        assert_eq!(wrong_result_false(&metadata, &positive).unwrap(), vec![85]);
        assert_eq!(
            wrong_result_false(&metadata, &[0u8; 32]).unwrap(),
            vec![85, 86, 87, 243]
        );
        assert!(wrong_result_false(&json!({"column_ordinals":[]}), &positive).is_err());
    }
    #[test]
    fn exact_frame_and_two_input_consumer_coordinates() {
        for branch in ["hi", "lo"] {
            let frame = source::fixed_frame(59, branch).unwrap();
            assert_eq!(frame.len(), 104);
            assert_eq!(frame.iter().find(|(i, _)| *i == 111).unwrap().1, 1);
            assert!(!frame
                .iter()
                .any(|(i, _)| (1..=32).contains(i) || (45..=108).contains(i)));
        }
        let slot = 111usize;
        let lane = slot / 8;
        let j = slot % 8;
        let x = lane % 5;
        let y = lane / 5;
        assert_eq!(
            (x * 32 + j * 4 + y.saturating_sub(1), usize::from(y != 0)),
            (125, 1)
        );
        assert_eq!((240 + slot, 0), (351, 0));
    }
}

#[allow(dead_code, unused_imports)]
mod permutation {
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
    pub(super) struct Check {
        pub(super) ordinal: usize,
        pub(super) expected_correct: bool,
    }
    #[derive(Clone, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub(super) struct Case {
        pub(super) name: String,
        pub(super) spec: GraphSpec,
        pub(super) expected_spec_id: String,
        pub(super) words: Vec<u32>,
        pub(super) checks: Vec<Check>,
        pub(super) measure_all: bool,
    }
    const MAP_CAP: u64 = 8 << 20;
    const LEAVES: usize = 29245;
    const WORDS: usize = 29445;
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    pub(super) struct Manifest {
        pub(super) schema: String,
        pub(super) context: String,
        pub(super) operation_id: String,
        pub(super) cases: Vec<Descriptor>,
    }
    #[derive(Clone, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub(super) struct Descriptor {
        pub(super) name: String,
        pub(super) profile: String,
        pub(super) role: String,
        pub(super) filename: String,
        pub(super) file_sha256: String,
        pub(super) file_bytes: u64,
        pub(super) catalogue_id: String,
        pub(super) program_sha256: String,
        pub(super) source_sha256: String,
        pub(super) global_ids_sha256: String,
        pub(super) words: usize,
        pub(super) leaves: usize,
        pub(super) input_state_hex: String,
        pub(super) expected_output_state_hex: String,
        pub(super) expected_false: Vec<usize>,
        pub(super) state_index: Option<usize>,
        pub(super) byte_slot: Option<usize>,
        pub(super) maps_filename: String,
        pub(super) maps_file_sha256: String,
        pub(super) maps_file_bytes: u64,
        pub(super) source_maps_sha256: String,
        pub(super) program_manifest_filename: String,
        pub(super) program_manifest_file_sha256: String,
        pub(super) program_manifest_file_bytes: u64,
        pub(super) source_manifest_filename: String,
        pub(super) source_manifest_file_sha256: String,
        pub(super) source_manifest_file_bytes: u64,
        pub(super) blocks: Vec<BlockDescriptor>,
    }
    #[derive(Clone, Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    pub(super) struct BlockDescriptor {
        pub(super) index: usize,
        pub(super) first_round: usize,
        pub(super) last_round: usize,
        pub(super) operation_id: String,
        pub(super) program_operation_id: String,
        pub(super) source_sha256: String,
        pub(super) program_sha256: String,
        pub(super) catalogue_id: String,
        pub(super) global_ids_sha256: String,
        pub(super) words: usize,
        pub(super) leaves: usize,
        pub(super) leaf_offset: usize,
        pub(super) word_map_sha256: String,
        pub(super) leaf_map_sha256: String,
    }
    #[derive(Clone, Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    pub(super) struct BlockRecord {
        pub(super) index: usize,
        pub(super) first_round: usize,
        pub(super) last_round: usize,
        pub(super) operation_id: String,
        pub(super) program_operation_id: String,
        pub(super) source_sha256: String,
        pub(super) program_sha256: String,
        pub(super) catalogue_id: String,
        pub(super) global_ids_sha256: String,
        pub(super) words: usize,
        pub(super) leaves: usize,
        pub(super) leaf_offset: usize,
        pub(super) word_map_sha256: String,
        pub(super) leaf_map_sha256: String,
        pub(super) word_map: Vec<usize>,
        pub(super) leaf_map: Vec<usize>,
    }
    #[derive(Clone, Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    pub(super) struct RoundRecord {
        pub(super) index: usize,
        pub(super) round_index: usize,
        pub(super) operation_id: String,
        pub(super) program_operation_id: String,
        pub(super) source_sha256: String,
        pub(super) program_sha256: String,
        pub(super) catalogue_id: String,
        pub(super) global_ids_sha256: String,
        pub(super) block_index: usize,
        pub(super) child_index: usize,
        pub(super) word_map: Vec<usize>,
        pub(super) leaf_map: Vec<usize>,
        pub(super) input_indices: Vec<usize>,
        pub(super) output_indices: Vec<usize>,
        pub(super) producer_ordinals: Vec<usize>,
        pub(super) producer_occurrences: Vec<usize>,
        pub(super) input_consumer_occurrences: Vec<Vec<(usize, usize)>>,
    }
    #[derive(Clone, Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    pub(super) struct JoinRecord {
        pub(super) index: usize,
        pub(super) state_round: usize,
        pub(super) words: Vec<String>,
        pub(super) indices: Vec<usize>,
        pub(super) producer_ordinals: Vec<usize>,
        pub(super) producer_occurrences: Vec<usize>,
        pub(super) consumer_occurrences: Vec<Vec<(usize, usize)>>,
    }
    #[derive(Clone, Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    pub(super) struct RawMaps {
        pub(super) schema: String,
        pub(super) blocks: Vec<BlockRecord>,
        pub(super) rounds: Vec<RoundRecord>,
        pub(super) input_indices: Vec<usize>,
        pub(super) output_indices: Vec<usize>,
        pub(super) producer_ordinals: Vec<usize>,
        pub(super) producer_occurrences: Vec<usize>,
        pub(super) global_ids: Vec<String>,
        pub(super) global_ids_sha256: String,
        pub(super) joins: Vec<JoinRecord>,
    }
    #[derive(Clone)]
    pub(super) struct ChildDescriptor {
        pub(super) round: usize,
        pub(super) operation_id: String,
        pub(super) program_sha256: String,
        pub(super) catalogue_id: String,
        pub(super) source_sha256: String,
        pub(super) wordmap_sha256: String,
        pub(super) words: usize,
        pub(super) leaves: usize,
        pub(super) first_leaf: usize,
    }
    #[derive(Clone)]
    pub(super) struct SegmentDescriptor {
        pub(super) start_round: usize,
        pub(super) program_sha256: String,
        pub(super) catalogue_id: String,
        pub(super) source_sha256: String,
        pub(super) global_ids_sha256: String,
        pub(super) children: Vec<ChildDescriptor>,
    }
    #[derive(Clone)]
    pub(super) struct View {
        pub(super) spec: GraphSpec,
        pub(super) map: Vec<usize>,
        pub(super) first_leaf: usize,
        pub(super) layout: ChildLayout,
    }
    #[derive(Clone)]
    pub(super) struct Block {
        pub(super) views: Vec<View>,
        pub(super) inputs: Vec<usize>,
        pub(super) outputs: Vec<usize>,
    }
    pub(super) struct Segment {
        pub(super) spec: GraphSpec,
        pub(super) map: Vec<usize>,
        pub(super) first_leaf: usize,
        pub(super) block: Block,
        pub(super) metadata: SegmentDescriptor,
        pub(super) maps: Value,
    }
    pub(super) struct Full {
        pub(super) segments: Vec<Segment>,
        pub(super) rounds: Vec<View>,
        pub(super) inputs: Vec<usize>,
        pub(super) outputs: Vec<usize>,
        pub(super) maps: Value,
    }
    pub(super) fn segment(
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
    pub(super) fn compose(
        parent: &GraphSpec,
        d: &Descriptor,
        raw: &RawMaps,
        root_op: &str,
    ) -> Result<Full> {
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
        if offset != LEAVES || encountered != (0..WORDS).collect::<Vec<_>>() || union.len() != WORDS
        {
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
    pub(super) fn identities(
        case: &Case,
        d: &Descriptor,
        full: &Full,
        root_op: &str,
    ) -> Result<(Value, Value)> {
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
            return Err(
                "full domain-separated manifest-as-program/catalogue identity differs".into(),
            );
        }
        let source = json!({"schema":"bitvm2-nova-byte-keccak-permutation-source/v1","context":case.spec.context,"field_role":case.spec.field_role,
        "operation_id":case.spec.operation_id,"program_sha256":program_sha,"catalogue_id":d.catalogue_id,
        "program_manifest_sha256":sha256::Hash::hash(&canonical(&program)?).to_string(),"source_maps_sha256":map_sha,
        "scope":"one complete BYTE Keccak-f1600 permutation; no sponge, transcript, proof or production assertion"});
        if domain_hash(b"BITVM2-NOVA/BYTE-KECCAK-PERMUTATION-SOURCE/v1\0", &source)?
            != d.source_sha256
        {
            return Err("separate acyclic full source-manifest identity differs".into());
        }
        Ok((program, source))
    }
    pub(super) fn byte_layout(spec: &GraphSpec, r: usize) -> Result<ChildLayout> {
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
    pub(super) fn canonical(value: &Value) -> Result<Vec<u8>> {
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
    pub(super) fn domain_hash(domain: &[u8], value: &Value) -> Result<String> {
        let mut h = sha256::Hash::engine();
        h.input(domain);
        h.input(&canonical(value)?);
        Ok(sha256::Hash::from_engine(h).to_string())
    }
    pub(super) fn consumers(view: &View) -> Vec<Vec<(usize, usize)>> {
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
    pub(super) fn state(value: &str) -> Result<[u8; 200]> {
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
    pub(super) fn reference(input: &[u8; 200], r: usize) -> [u8; 200] {
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
    pub(super) fn extend_object(target: &mut Value, extra: Value) -> Result<()> {
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
    pub(super) fn digest(value: &str) -> Result<[u8; 32]> {
        let raw = id32(value)?;
        if hex::encode(raw) != value {
            return Err("canonical lowercase32 digest required".into());
        }
        Ok(raw)
    }
    pub(super) fn identifier(value: &str) -> bool {
        !value.is_empty()
            && value.len() <= 192
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.:/-".contains(&b))
    }
    pub(super) fn snapshot(path: &Path, cap: u64, expected: [u8; 32]) -> Result<Vec<u8>> {
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
            if (before.dev(), before.ino(), before.len())
                != (opened.dev(), opened.ino(), opened.len())
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
    pub(super) fn truth(spec: &GraphSpec, values: &[u32], ordinal: usize) -> Result<bool> {
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
    pub(super) fn changed(value: &str) -> Result<String> {
        let mut raw = digest(value)?;
        raw[0] ^= 1;
        Ok(hex::encode(raw))
    }
    pub(super) fn native_negatives(
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

    pub(super) fn auth_shape(spec: &GraphSpec, ordinal: usize) -> (String, Vec<u32>, Vec<usize>) {
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
    pub(super) fn opening(
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
    pub(super) fn program_digest(spec: &GraphSpec) -> Result<[u8; 32]> {
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
    pub(super) fn map_hash(map: &[usize]) -> Result<String> {
        Ok(sha256::Hash::hash(&serde_json::to_vec(map)?).to_string())
    }
    pub(super) fn state_word(name: &str, round: usize) -> Result<(usize, usize)> {
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
    pub(super) fn project(
        parent: &GraphSpec,
        d: &SegmentDescriptor,
        root_op: &str,
    ) -> Result<Block> {
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
                let local = if let Some(local) = word.name.strip_prefix(&format!("byte-round/{r}/"))
                {
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
                let expected = if let Some(j) = layout.ports.inputs.iter().position(|w| *w == local)
                {
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
                    if left != right || shared != left.into_iter().collect() || shared.len() != 200
                    {
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
    pub(super) fn round_source(
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
    pub(super) fn validate_sources(
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
    pub(super) fn validate_maps(parent: &GraphSpec, block: &Block, start: usize) -> Result<()> {
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
                let expected = if let Some(j) =
                    view.layout.ports.inputs.iter().position(|w| *w == local)
                {
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
                    || parent.bodies.get(&actual.body_sha256)
                        != view.spec.bodies.get(&leaf.body_sha256)
                {
                    return Err("child predicate/body/alias projection differs".into());
                }
            }
            images.push(view.map.iter().copied().collect::<HashSet<_>>());
        }
        if order != (0..parent.words.len()).collect::<Vec<_>>() || union.len() != parent.words.len()
        {
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
                    if left != right || actual != left.into_iter().collect() || actual.len() != 200
                    {
                        return Err("child join intersection/order changed".into());
                    }
                } else if !actual.is_empty() {
                    return Err("nonadjacent child maps share a word".into());
                }
            }
        }
        Ok(())
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
    pub(super) struct Ports {
        pub(super) inputs: Vec<usize>,
        pub(super) outputs: Vec<usize>,
        pub(super) producers: Vec<(usize, usize)>,
    }
    #[derive(Clone)]
    pub(super) struct ChildLayout {
        pub(super) ports: Ports,
    }
    pub(super) struct Checker<'a> {
        pub(super) spec: &'a GraphSpec,
        pub(super) word: usize,
        pub(super) leaf: usize,
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
}
