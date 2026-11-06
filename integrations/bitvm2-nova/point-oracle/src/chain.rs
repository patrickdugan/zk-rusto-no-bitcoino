//! Hosted TEST-ONLY rho raw-state to two-block sumcheck challenge chain.
//! Full permutation identities remain independent; one Registry is live at a time.
//! No proof acceptance, production assertion authority or transactions exist here.
#[path = "../../rust-oracle/src/byte_sumcheck_absorb.rs"]
pub(crate) mod absorb;
#[path = "../../rust-oracle/src/byte_sumcheck_frame.rs"]
pub(crate) mod frame;
use crate::keys;
#[path = "../../rust-oracle/src/byte_rho_chain_openings.rs"]
pub(crate) mod openings;
#[path = "../../rust-oracle/src/byte_rho_chain_probe.rs"]
pub(crate) mod probe_crypto;
#[path = "../../rust-oracle/src/byte_rho_source.rs"]
pub(crate) mod rho_source;
use crate::rho_tail;
use crate::source::chain as source;
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

pub(crate) const COMPONENT_NAMES: [&str; 9] = [
    "rho-hi",
    "rho-lo",
    "rho-tail",
    "c-coeff-frame",
    "c-prefix",
    "c-absorb",
    "c-hi",
    "c-lo",
    "c-uniform",
];
pub(crate) const COMPONENT_COUNTS: [(usize, usize); 9] = [
    (29445, 29245),
    (29445, 29245),
    (587, 453),
    (187, 111),
    (29445, 29245),
    (23, 9),
    (29445, 29245),
    (29445, 29245),
    (379, 245),
];
pub(crate) const MAIN_UNIQUE_WORDS: usize = 147355;
pub(crate) const MAIN_LOCAL_WORDS: usize = 148401;
pub(crate) const MAIN_LEAVES: usize = 147043;
pub(crate) const INPUT_CAP: u64 = 32 << 20;
pub(crate) const MAP_CAP: u64 = 8 << 20;
pub(crate) const MANIFEST_CAP: u64 = 1 << 20;
pub(crate) const SUMMARY_CAP: usize = 1 << 20;
pub(crate) const RECORD_CAP: u64 = 128 << 20;
pub(crate) const PROFILES: [&str; 3] = ["honest", "coherent-rho-raw", "coherent-prefix-capacity"];
pub(crate) const PROBE_KINDS: [&str; 10] = [
    "coefficient-c0-modulus",
    "coefficient-c2-modulus",
    "frame-counter",
    "frame-NoDS",
    "frame-tag",
    "frame-zero-capacity",
    "absorb-wrong-xor",
    "absorb-selector",
    "absorb-delimiter",
    "absorb-end-mask",
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Run {
    pub(crate) schema: String,
    pub(crate) context: String,
    pub(crate) operation_id: String,
    pub(crate) cases: Vec<Group>,
    pub(crate) probes: Vec<Probe>,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Group {
    pub(crate) name: String,
    pub(crate) profile: String,
    pub(crate) role: String,
    pub(crate) rho_counter: u64,
    pub(crate) c_counter: u64,
    pub(crate) execution_mode: String,
    pub(crate) source_sha256: String,
    pub(crate) source_maps_sha256: String,
    pub(crate) eval_w_le: String,
    pub(crate) prior_state_hex: String,
    pub(crate) compressed_coefficients_le: [String; 2],
    pub(crate) expected_rho_hi_output_state_hex: String,
    pub(crate) expected_rho_lo_output_state_hex: String,
    pub(crate) expected_rho_raw_state_le: String,
    pub(crate) expected_rho_result_le: String,
    pub(crate) expected_rho_quotient_le: String,
    pub(crate) expected_prefix_output_state_hex: String,
    pub(crate) expected_c_hi_output_state_hex: String,
    pub(crate) expected_c_lo_output_state_hex: String,
    pub(crate) expected_c_raw_state_le: String,
    pub(crate) expected_c_result_le: String,
    pub(crate) expected_c_quotient_le: String,
    pub(crate) chain_source_filename: String,
    pub(crate) chain_source_file_sha256: String,
    pub(crate) chain_source_file_bytes: u64,
    pub(crate) chain_maps_filename: String,
    pub(crate) chain_maps_file_sha256: String,
    pub(crate) chain_maps_file_bytes: u64,
    pub(crate) components: Vec<Header>,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Header {
    pub(crate) descriptor: source::ComponentDescriptor,
    pub(crate) filename: String,
    pub(crate) file_sha256: String,
    pub(crate) file_bytes: u64,
    pub(crate) maps_filename: String,
    pub(crate) maps_file_sha256: String,
    pub(crate) maps_file_bytes: u64,
    pub(crate) program_manifest_filename: Option<String>,
    pub(crate) program_manifest_file_sha256: Option<String>,
    pub(crate) program_manifest_file_bytes: Option<u64>,
    pub(crate) source_manifest_filename: String,
    pub(crate) source_manifest_file_sha256: String,
    pub(crate) source_manifest_file_bytes: u64,
    pub(crate) execution_mode: String,
    pub(crate) selected_ordinals: Option<Vec<usize>>,
    pub(crate) expected_false: Vec<usize>,
    pub(crate) expected_abort_ordinals: Vec<usize>,
    pub(crate) full: Option<permutation::Descriptor>,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Probe {
    pub(crate) name: String,
    pub(crate) kind: String,
    pub(crate) role: String,
    pub(crate) source_case: String,
    pub(crate) source_component: usize,
    pub(crate) filename: String,
    pub(crate) file_sha256: String,
    pub(crate) file_bytes: u64,
    pub(crate) catalogue_id: String,
    pub(crate) program_sha256: String,
    pub(crate) source_sha256: String,
    pub(crate) words: usize,
    pub(crate) leaves: usize,
    pub(crate) expected_false: Vec<usize>,
    pub(crate) selected_leaf: usize,
}
pub(crate) struct References {
    pub(crate) full_inputs: HashMap<usize, [u8; 200]>,
    pub(crate) full_outputs: HashMap<usize, [u8; 200]>,
    pub(crate) rho_raw: [u8; 64],
    pub(crate) rho_result: [u8; 32],
    pub(crate) rho_quotient: [u8; 33],
    pub(crate) c_raw: [u8; 64],
    pub(crate) c_result: [u8; 32],
    pub(crate) c_quotient: [u8; 33],
    pub(crate) coefficients: [[u8; 32]; 2],
}

pub(crate) fn fixed_hex<const N: usize>(text: &str) -> Result<[u8; N]> {
    let bytes: [u8; N] = hex::decode(text)?
        .try_into()
        .map_err(|_| "fixed byte encoding length")?;
    if hex::encode(bytes) != text {
        return Err("canonical lowercase byte encoding required".into());
    }
    Ok(bytes)
}
pub(crate) fn canonical_scalar(bytes: &[u8; 32], role: &str) -> Result<()> {
    let mut wide = [0u8; 64];
    wide[..32].copy_from_slice(bytes);
    let (result, quotient) = rho_tail::reduction(&wide, role)?;
    if result != *bytes || quotient.iter().any(|b| *b != 0) {
        return Err("canonical scalar host input required".into());
    }
    Ok(())
}
pub(crate) fn permutation_reference(input: &[u8; 200]) -> [u8; 200] {
    let mut state = *input;
    for r in 0..24 {
        state = permutation::reference(&state, r);
    }
    state
}
pub(crate) fn references(group: &Group) -> Result<References> {
    if group.c_counter
        != group
            .rho_counter
            .checked_add(1)
            .ok_or("public transcript counter overflow")?
    {
        return Err("next-c counter must increment rho counter exactly once".into());
    }
    let eval = fixed_hex::<32>(&group.eval_w_le)?;
    canonical_scalar(&eval, &group.role)?;
    let coefficients = [
        fixed_hex::<32>(&group.compressed_coefficients_le[0])?,
        fixed_hex::<32>(&group.compressed_coefficients_le[1])?,
    ];
    for scalar in &coefficients {
        canonical_scalar(scalar, &group.role)?;
    }
    let prior = fixed_hex::<64>(&group.prior_state_hex)?;
    let mut inputs = HashMap::new();
    let mut outputs = HashMap::new();
    for (index, branch) in [(0, "hi"), (1, "lo")] {
        let mut input = [0u8; 200];
        for (byte, value) in rho_source::fixed_frame(group.rho_counter, branch)? {
            input[byte] = u8::try_from(value)?;
        }
        input[1..33].copy_from_slice(&eval);
        input[45..109].copy_from_slice(&prior);
        let mut output = permutation_reference(&input);
        if index == 0 && group.profile == "coherent-rho-raw" {
            output[31] ^= 1;
        }
        inputs.insert(index, input);
        outputs.insert(index, output);
    }
    let mut rho_raw = [0u8; 64];
    rho_raw[..32].copy_from_slice(&outputs[&1][..32]);
    rho_raw[32..].copy_from_slice(&outputs[&0][..32]);
    let (rho_result, rho_quotient) = rho_tail::reduction(&rho_raw, &group.role)?;
    let mut prefix = [0u8; 200];
    prefix[0] = 0x70;
    prefix[1..33].copy_from_slice(&coefficients[0]);
    prefix[33..65].copy_from_slice(&coefficients[1]);
    prefix[65..69].copy_from_slice(b"NoDS");
    prefix[69..77].copy_from_slice(&group.c_counter.to_le_bytes());
    prefix[77..136].copy_from_slice(&rho_raw[..59]);
    let mut prefix_output = permutation_reference(&prefix);
    if group.profile == "coherent-prefix-capacity" {
        prefix_output[136] ^= 1;
    }
    inputs.insert(4, prefix);
    outputs.insert(4, prefix_output);
    for (index, selector) in [(6, 1u8), (7, 0u8)] {
        let mut rate = [0u8; 136];
        rate[..5].copy_from_slice(&rho_raw[59..]);
        rate[5] = 0x63;
        rate[6] = selector;
        rate[7] = 1;
        rate[135] = 128;
        let mut input = prefix_output;
        for i in 0..136 {
            input[i] ^= rate[i];
        }
        if input[136..] != prefix_output[136..] {
            return Err("second absorption must forward capacity unchanged".into());
        }
        let output = permutation_reference(&input);
        inputs.insert(index, input);
        outputs.insert(index, output);
    }
    if (0..200)
        .filter(|i| inputs[&6][*i] != inputs[&7][*i])
        .collect::<Vec<_>>()
        != [6]
    {
        return Err("only branch selector BYTE6 may distinguish final inputs".into());
    }
    let mut c_raw = [0u8; 64];
    c_raw[..32].copy_from_slice(&outputs[&7][..32]);
    c_raw[32..].copy_from_slice(&outputs[&6][..32]);
    let (c_result, c_quotient) = rho_tail::reduction(&c_raw, &group.role)?;
    for (index, expected) in [
        (0, &group.expected_rho_hi_output_state_hex),
        (1, &group.expected_rho_lo_output_state_hex),
        (4, &group.expected_prefix_output_state_hex),
        (6, &group.expected_c_hi_output_state_hex),
        (7, &group.expected_c_lo_output_state_hex),
    ] {
        if outputs[&index] != fixed_hex::<200>(expected)? {
            return Err(
                "independent full permutation reference differs from claimed chain state".into(),
            );
        }
    }
    if rho_raw != fixed_hex::<64>(&group.expected_rho_raw_state_le)?
        || rho_result != fixed_hex::<32>(&group.expected_rho_result_le)?
        || rho_quotient != fixed_hex::<33>(&group.expected_rho_quotient_le)?
        || c_raw != fixed_hex::<64>(&group.expected_c_raw_state_le)?
        || c_result != fixed_hex::<32>(&group.expected_c_result_le)?
        || c_quotient != fixed_hex::<33>(&group.expected_c_quotient_le)?
    {
        return Err("independent rawLO||HI or canonical quotient/remainder differs".into());
    }
    Ok(References {
        full_inputs: inputs,
        full_outputs: outputs,
        rho_raw,
        rho_result,
        rho_quotient,
        c_raw,
        c_result,
        c_quotient,
        coefficients,
    })
}

/// A fresh unchanged Uniform view comes from an actually validated small rho
/// tail, never an imported catalogue/metadata receipt. Rebinding only its
/// operation ID preserves every predicate body, alias, word and canonical field.
pub(crate) fn project_uniform(
    tail: &GraphSpec,
    checked: &rho_tail::CheckedTail,
    operation: &str,
) -> Result<(GraphSpec, Value)> {
    if !permutation::identifier(operation)
        || tail.words.len() != 587
        || tail.leaves.len() != 453
        || tail.program_sha256 != checked.program_sha256
        || checked.result_indices.len() != 9
        || tail.leaves[452].kind != "field_valid"
        || tail.leaves[452].wires != checked.result_indices
    {
        return Err("fresh independently checked rho-tail projection required".into());
    }
    let decimal = match tail.field_role.as_str() {
        "pallas_scalar" => {
            "28948022309329048855892746252171976963363056481941647379679742748393362948097"
        }
        "vesta_scalar" => {
            "28948022309329048855892746252171976963363056481941560715954676764349967630337"
        }
        _ => return Err("explicit scalar role for uniform projection".into()),
    };
    let names = |indices: &[usize]| -> Result<Vec<String>> {
        indices
            .iter()
            .map(|i| {
                tail.words
                    .get(*i)
                    .filter(|_| *i < 379)
                    .map(|w| w.name.clone())
                    .ok_or_else(|| "uniform projection operand outside original word image".into())
            })
            .collect()
    };
    let words: Vec<_> = tail.words[..379]
        .iter()
        .map(|w| json!([w.name, w.bound]))
        .collect();
    let constraints = tail.leaves[..244]
        .iter()
        .map(|l| Ok(json!([l.kind, names(&l.wires)?, l.argument])))
        .collect::<Result<Vec<Value>>>()?;
    let shape = json!({"schema":"bitvm2-nova-fixed-trace/v2","field_role":tail.field_role,"modulus":decimal,"operation_id":operation,"context":tail.context,"words":words,"fields":[["result",names(&checked.result_indices)?]],"constraints":constraints});
    let program = sha256::Hash::hash(&permutation::canonical(&shape)?).to_string();
    let mut leaves = tail.leaves[..244].to_vec();
    leaves.push(tail.leaves[452].clone());
    let used: HashSet<_> = leaves.iter().map(|l| l.body_sha256.clone()).collect();
    let bodies = tail
        .bodies
        .iter()
        .filter(|(id, _)| used.contains(*id))
        .map(|(id, body)| (id.clone(), body.clone()))
        .collect();
    let spec = GraphSpec {
        program_sha256: program.clone(),
        context: tail.context.clone(),
        field_role: tail.field_role.clone(),
        operation_id: operation.into(),
        words: tail.words[..379].to_vec(),
        leaves,
        bodies,
    };
    spec.identity()?;
    let mut metadata = checked.uniform_metadata.clone();
    let object = metadata
        .as_object_mut()
        .ok_or("checked uniform metadata object")?;
    if object.get("schema") != Some(&json!("bitvm2-nova-uniform-reduction/v1"))
        || object.get("context") != Some(&json!(tail.context))
        || object.get("field_role") != Some(&json!(tail.field_role))
    {
        return Err("checked uniform metadata context/role differs".into());
    }
    object.insert("operation_id".into(), json!(operation));
    object.insert("program_sha256".into(), json!(program));
    Ok((spec, metadata))
}

pub(crate) struct Basis {
    pub(crate) spec: GraphSpec,
    pub(crate) checked: rho_tail::CheckedTail,
}
pub(crate) struct Prepared {
    pub(crate) case: Case,
    pub(crate) global_ids: Vec<String>,
    pub(crate) facts: source::ComponentFacts,
    pub(crate) full: Option<permutation::Full>,
    pub(crate) tail: Option<rho_tail::CheckedTail>,
    pub(crate) frame: Option<frame::CheckedFrame>,
    pub(crate) absorb: Option<absorb::CheckedAbsorb>,
}
pub(crate) fn is_full(index: usize) -> bool {
    [0, 1, 4, 6, 7].contains(&index)
}
pub(crate) fn component_operation(run: &Run, g: &Group, index: usize) -> Result<String> {
    if index >= 9 {
        return Err("component index bound".into());
    }
    if index < 3 {
        Ok(format!(
            "{}/rho/counter/{}/{}",
            run.operation_id,
            g.rho_counter,
            ["hi", "lo", "tail"][index]
        ))
    } else {
        Ok(format!(
            "{}/c/counter/{}/{}",
            run.operation_id,
            g.c_counter,
            ["coeff-frame", "prefix", "absorb", "hi", "lo", "uniform"][index - 3]
        ))
    }
}
pub(crate) fn checked_file(
    root: &Path,
    name: &str,
    cap: u64,
    sha: &str,
    bytes: u64,
) -> Result<Vec<u8>> {
    if name.is_empty()
        || name.len() > 80
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
        || bytes == 0
        || bytes > cap
    {
        return Err("flat bounded pinned file required".into());
    }
    let raw = permutation::snapshot(&root.join(name), cap, digest(sha)?)?;
    if raw.len() as u64 != bytes {
        return Err("pinned byte length differs".into());
    }
    Ok(raw)
}
pub(crate) fn selection(profile: &str, index: usize) -> Result<(&'static str, Option<Vec<usize>>)> {
    if index >= 9 || !PROFILES.contains(&profile) {
        return Err("closed profile/component required".into());
    }
    if profile == "honest" || !is_full(index) {
        return Ok(("all", None));
    }
    let ordinals = match (profile, index) {
        ("coherent-rho-raw", 0) => vec![29072],
        ("coherent-prefix-capacity", 4) => vec![29177],
        ("coherent-rho-raw", 6 | 7) => vec![16, 244],
        ("coherent-prefix-capacity", 6 | 7) => vec![66, 376],
        _ => vec![],
    };
    Ok(if ordinals.is_empty() {
        ("none", None)
    } else {
        ("selected", Some(ordinals))
    })
}
pub(crate) fn validate_run(run: &Run) -> Result<()> {
    if run.schema != "bitvm2-nova-byte-rho-chain-run/v1"
        || run.context
            != sha256::Hash::hash(b"BITVM2-NOVA/BYTE-RHO-CHAIN-CONFORMANCE/v1").to_string()
        || run.operation_id != "benchmark/byte-rho-chain/v1"
        || run.cases.len() != 6
        || run.probes.len() != 20
    {
        return Err("closed six-chain/twenty-probe run required".into());
    }
    for (i, g) in run.cases.iter().enumerate() {
        let role = if i < 3 {
            "pallas_scalar"
        } else {
            "vesta_scalar"
        };
        let prefix = if i < 3 { "p" } else { "v" };
        let counter = if i < 3 { 59 } else { 44 };
        let tag = ["h", "r", "p"][i % 3];
        if g.role != role
            || g.rho_counter != counter
            || g.c_counter != counter + 1
            || g.profile != PROFILES[i % 3]
            || g.name != format!("{prefix}/{tag}")
            || g.execution_mode != if i % 3 == 0 { "full" } else { "targeted" }
            || g.components.len() != 9
            || g.chain_source_filename != format!("chain-source-{i:02}.json")
            || g.chain_maps_filename != format!("chain-maps-{i:02}.json")
        {
            return Err("closed ordered role/profile/counter/files differ".into());
        }
        digest(&g.source_sha256)?;
        digest(&g.source_maps_sha256)?;
        source::validate_policy(&run.context, &g.role, g.rho_counter, &run.operation_id)?;
        references(g)?;
        for (j, h) in g.components.iter().enumerate() {
            let d = &h.descriptor;
            let stem = format!("{i:02}-{j}");
            let (mode, ordinals) = selection(&g.profile, j)?;
            if d.index != j
                || d.branch != COMPONENT_NAMES[j]
                || d.field_role != g.role
                || d.counter != if j < 3 { g.rho_counter } else { g.c_counter }
                || d.operation_id != component_operation(run, g, j)?
                || (d.words, d.leaves) != COMPONENT_COUNTS[j]
                || h.full.is_some() != is_full(j)
                || h.execution_mode != mode
                || h.selected_ordinals != ordinals
                || h.filename != format!("case-{stem}.json")
                || h.maps_filename != format!("maps-{stem}.json")
                || h.source_manifest_filename != format!("source-{stem}.json")
            {
                return Err("component count,identity,execution selector or file differs".into());
            }
            if is_full(j) {
                if h.program_manifest_filename.as_deref()
                    != Some(format!("program-{stem}.json").as_str())
                    || h.program_manifest_file_sha256.is_none()
                    || h.program_manifest_file_bytes.is_none()
                {
                    return Err("full source requires its program-manifest sidecar".into());
                }
            } else if h.program_manifest_filename.is_some()
                || h.program_manifest_file_sha256.is_some()
                || h.program_manifest_file_bytes.is_some()
            {
                return Err("small actualProgram must not masquerade as manifest identity".into());
            }
        }
    }
    for (i, p) in run.probes.iter().enumerate() {
        let local = i % 10;
        let role = if i < 10 {
            "pallas_scalar"
        } else {
            "vesta_scalar"
        };
        let prefix = if i < 10 { "p" } else { "v" };
        let component = if local < 6 { 3 } else { 5 };
        let (words, leaves) = COMPONENT_COUNTS[component];
        if p.name != format!("{prefix}/q{local}")
            || p.kind != PROBE_KINDS[local]
            || p.role != role
            || p.source_case != format!("{prefix}/h")
            || p.source_component != component
            || p.filename != format!("probe-{i:02}.json")
            || p.words != words
            || p.leaves != leaves
            || p.expected_false != [p.selected_leaf]
            || p.selected_leaf >= leaves
        {
            return Err("closed ordered private probe inventory differs".into());
        }
        for sha in [&p.catalogue_id, &p.program_sha256, &p.source_sha256] {
            digest(sha)?;
        }
    }
    Ok(())
}
pub(crate) fn full_reference(
    case: &Case,
    full: &permutation::Full,
    g: &Group,
    index: usize,
    refs: &References,
) -> Result<()> {
    let mut current = *refs
        .full_inputs
        .get(&index)
        .ok_or("full input reference absent")?;
    for (r, view) in full.rounds.iter().enumerate() {
        for i in 0..200 {
            if case.words[view.map[view.layout.ports.inputs[i]]] != u32::from(current[i]) {
                return Err("actual input differs from preceding signed state".into());
            }
        }
        let mut output = permutation::reference(&current, r);
        if r == 23 {
            if index == 0 && g.profile == "coherent-rho-raw" {
                output[31] ^= 1;
            }
            if index == 4 && g.profile == "coherent-prefix-capacity" {
                output[136] ^= 1;
            }
        }
        for i in 0..200 {
            if case.words[view.map[view.layout.ports.outputs[i]]] != u32::from(output[i]) {
                return Err("actual round output differs from native word reference/controlled coherent claim".into());
            }
        }
        current = output;
    }
    if current != refs.full_outputs[&index] {
        return Err("terminal full reference differs".into());
    }
    Ok(())
}
pub(crate) fn uniform_assignment(
    case: &Case,
    input: &[u8; 64],
    result: &[u8; 32],
    quotient: &[u8; 33],
) -> Result<()> {
    for (prefix, bytes) in [
        ("input/byte/", input.as_slice()),
        ("result/encoding/byte/", result.as_slice()),
        ("quotient/byte/", quotient.as_slice()),
    ] {
        for (i, value) in bytes.iter().enumerate() {
            let name = format!("{prefix}{i}");
            let slot = case
                .spec
                .words
                .iter()
                .position(|w| w.name == name)
                .ok_or("canonical Uniform BYTE port missing")?;
            if case.words[slot] != u32::from(*value) {
                return Err("actual Uniform byte/result/quotient differs".into());
            }
        }
    }
    Ok(())
}
pub(crate) fn compact_facts(
    case: &Case,
    index: usize,
    ids: &[String],
    full: Option<&permutation::Full>,
) -> Result<source::ComponentFacts> {
    let (inputs, outputs, producers, formals) = if let Some(full) = full {
        let last = &full.rounds[23];
        (
            full.inputs.clone(),
            full.outputs.clone(),
            last.layout
                .ports
                .producers
                .iter()
                .map(|p| last.first_leaf + p.0)
                .collect(),
            last.layout.ports.producers.iter().map(|p| p.1).collect(),
        )
    } else {
        (vec![], vec![], vec![], vec![])
    };
    let chosen: HashSet<usize> = if is_full(index) {
        inputs.iter().chain(&outputs).copied().collect()
    } else {
        (0..case.spec.words.len()).collect()
    };
    let mut occurrences: BTreeMap<usize, Vec<(usize, usize)>> =
        chosen.iter().map(|i| (*i, vec![])).collect();
    for (ordinal, leaf) in case.spec.leaves.iter().enumerate() {
        for (formal, word) in leaf.wires.iter().enumerate() {
            if let Some(row) = occurrences.get_mut(word) {
                row.push((ordinal, formal));
            }
        }
    }
    let interfaces = occurrences
        .into_iter()
        .map(|(word_index, occurrences)| {
            if occurrences.is_empty() {
                return Err("exposed interface has no actual predicate opening".into());
            }
            Ok(source::Interface {
                word_index,
                global_id: ids[word_index].clone(),
                bound: case.spec.words[word_index].bound,
                occurrences,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(source::ComponentFacts {
        index,
        branch: COMPONENT_NAMES[index].into(),
        global_ids_sha256: sha256::Hash::hash(&canonical(&json!(ids))?).to_string(),
        input_indices: inputs,
        output_indices: outputs,
        producer_ordinals: producers,
        producer_occurrences: formals,
        interfaces,
    })
}
pub(crate) fn prepare(
    run: &Run,
    g: &Group,
    index: usize,
    root: &Path,
    refs: &References,
    basis: Option<&Basis>,
) -> Result<Prepared> {
    if index >= 9 {
        return Err("component index bound".into());
    }
    let h = &g.components[index];
    let d = &h.descriptor;
    let case: Case = serde_json::from_slice(&checked_file(
        root,
        &h.filename,
        INPUT_CAP,
        &h.file_sha256,
        h.file_bytes,
    )?)?;
    if case.name != format!("{}/{}", g.name, COMPONENT_NAMES[index])
        || !case.measure_all
        || case.expected_spec_id != d.catalogue_id
        || case.spec.program_sha256 != d.program_sha256
        || case.spec.context != run.context
        || case.spec.field_role != g.role
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
        return Err("actual component graph/assignment differs from pinned identity/ranges".into());
    }
    let maps_bytes = checked_file(
        root,
        &h.maps_filename,
        MAP_CAP,
        &h.maps_file_sha256,
        h.maps_file_bytes,
    )?;
    let maps: Value = serde_json::from_slice(&maps_bytes)?;
    let ids = case
        .spec
        .words
        .iter()
        .map(|w| source::global_id(index, &w.name))
        .collect::<Result<Vec<_>>>()?;
    if ids.iter().collect::<HashSet<_>>().len() != ids.len() {
        return Err("component global map is not injective".into());
    }
    let mut full = None;
    let mut tail = None;
    let mut checked_frame = None;
    let mut checked_absorb = None;
    let source_value = if is_full(index) {
        let f = h.full.as_ref().ok_or("full source header absent")?;
        if f.name != case.name
            || f.profile != g.profile
            || f.role != g.role
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
            || fixed_hex::<200>(&f.input_state_hex)? != refs.full_inputs[&index]
            || fixed_hex::<200>(&f.expected_output_state_hex)? != refs.full_outputs[&index]
        {
            return Err("nested full source/reference pins differ".into());
        }
        let raw: permutation::RawMaps = serde_json::from_slice(&maps_bytes)?;
        let actual = permutation::compose(&case.spec, f, &raw, &d.operation_id)?;
        if canonical(&actual.maps)? != maps_bytes {
            return Err(
                "actual full maps differ from independently rebuilt canonical source".into(),
            );
        }
        let (program, source_value) = permutation::identities(&case, f, &actual, &d.operation_id)?;
        if checked_file(
            root,
            &f.program_manifest_filename,
            MANIFEST_CAP,
            &f.program_manifest_file_sha256,
            f.program_manifest_file_bytes,
        )? != canonical(&program)?
        {
            return Err("actual full program manifest differs".into());
        }
        full_reference(&case, &actual, g, index, refs)?;
        full = Some(actual);
        source_value
    } else if index == 2 {
        let t = rho_tail::check(
            &case.spec,
            &run.context,
            &g.role,
            g.rho_counter,
            &d.operation_id,
            &maps,
        )?;
        uniform_assignment(&case, &refs.rho_raw, &refs.rho_result, &refs.rho_quotient)?;
        for record in &t.frame_records {
            let branch_index = if record.branch == "hi" { 0 } else { 1 };
            if case.words[record.word_index]
                != u32::from(refs.full_inputs[&branch_index][record.byte_index])
            {
                return Err("rho framing BYTE assignment differs".into());
            }
        }
        let value = t.source_manifest.clone();
        tail = Some(t);
        value
    } else if index == 3 {
        let b = basis.ok_or("checked small rho-tail basis absent")?;
        let (uniform, _) = project_uniform(
            &b.spec,
            &b.checked,
            &format!("{}/uniform-reference", d.operation_id),
        )?;
        let f = frame::check(
            &case.spec,
            &run.context,
            &g.role,
            g.c_counter,
            &d.operation_id,
            &maps,
            &uniform,
        )?;
        if case.words
            != frame::expected_assignment(&refs.coefficients, &g.role, g.c_counter, None, None)?
        {
            return Err(
                "actual coefficient/frame assignment differs from independent integer encoding"
                    .into(),
            );
        }
        let value = f.metadata.clone();
        checked_frame = Some(f);
        value
    } else if index == 5 {
        let a = absorb::check(&case.spec, &run.context, &g.role, &d.operation_id, &maps)?;
        if case.words != absorb::assignment_reference(&refs.full_outputs[&4], &refs.rho_raw) {
            return Err("actual rate-XOR/selector/padding assignment differs".into());
        }
        let (lo, hi) = absorb::route_states(&refs.full_outputs[&4], &case.words)?;
        if lo != refs.full_inputs[&7] || hi != refs.full_inputs[&6] {
            return Err("actual rate/capacity routes differ from final permutation inputs".into());
        }
        let value = a.source_manifest.clone();
        checked_absorb = Some(a);
        value
    } else {
        let b = basis.ok_or("checked Uniform projection basis absent")?;
        let (uniform, metadata) = project_uniform(&b.spec, &b.checked, &d.operation_id)?;
        if canonical(&serde_json::to_value(&uniform)?)?
            != canonical(&serde_json::to_value(&case.spec)?)?
        {
            return Err("c reducer is not the exact unchanged Uniform projection".into());
        }
        if g.profile == "coherent-scalar-alias" {
            if case.words
                != crate::uniform_alias::expected_uniform_assignment(&refs.c_raw, &g.role)?
            {
                return Err(
                    "closed scalar alias assignment differs from independent integer witness"
                        .into(),
                );
            }
        } else {
            uniform_assignment(&case, &refs.c_raw, &refs.c_result, &refs.c_quotient)?;
        }
        let expected_maps = json!({"uniform_metadata_sha256":sha256::Hash::hash(&canonical(&metadata)?).to_string(),"ports":metadata["ports"],"word_map":(0..379).collect::<Vec<_>>(),"leaf_map":(0..245).collect::<Vec<_>>(),"global_ids_sha256":sha256::Hash::hash(&canonical(&json!(ids))?).to_string()});
        if maps != expected_maps {
            return Err("actual c reducer maps/ports differ".into());
        }
        json!({"schema":"bitvm2-nova-byte-rho-chain-uniform/v1","context":run.context,"field_role":g.role,"counter":g.c_counter,"operation_id":d.operation_id,"program_sha256":case.spec.program_sha256,"catalogue_id":case.expected_spec_id,"source_maps_sha256":sha256::Hash::hash(&canonical(&expected_maps)?).to_string(),"scope":"unchanged unsigned512 reducer consuming actual c LO32||HI32"})
    };
    let domain: &[u8] = match index {
        2 => b"BITVM2-NOVA/BYTE-RHO-TAIL/v1\0",
        3 => b"BITVM2-NOVA/BYTE-SUMCHECK-FRAME/v1\0",
        5 => b"BITVM2-NOVA/BYTE-SUMCHECK-ABSORB/v1\0",
        8 => b"BITVM2-NOVA/BYTE-RHO-CHAIN-UNIFORM/v1\0",
        _ => b"BITVM2-NOVA/BYTE-KECCAK-PERMUTATION-SOURCE/v1\0",
    };
    if canonical(&maps)? != maps_bytes
        || sha256::Hash::hash(&maps_bytes).to_string() != d.source_maps_sha256
        || h.maps_file_sha256 != d.source_maps_sha256
        || permutation::domain_hash(domain, &source_value)? != d.source_sha256
        || checked_file(
            root,
            &h.source_manifest_filename,
            MANIFEST_CAP,
            &h.source_manifest_file_sha256,
            h.source_manifest_file_bytes,
        )? != canonical(&source_value)?
    {
        return Err("component actual source/maps sidecars differ".into());
    }
    let facts = compact_facts(&case, index, &ids, full.as_ref())?;
    if facts.global_ids_sha256 != d.global_ids_sha256 {
        return Err("actual global word map hash differs".into());
    }
    let false_rows = native_false(&case, index)?;
    let expected = if index == 0 && g.profile == "coherent-rho-raw"
        || index == 4 && g.profile == "coherent-prefix-capacity"
    {
        let actual = full.as_ref().ok_or("controlled full producer absent")?;
        let last = &actual.rounds[23];
        let slot = if index == 0 { 31 } else { 136 };
        let (ordinal, formal) = last.layout.ports.producers[slot];
        if formal != 2 || case.spec.leaves[last.first_leaf + ordinal].kind != "byte_xor" {
            return Err("actual controlled source is not the selected Chi producer".into());
        }
        vec![last.first_leaf + ordinal]
    } else if index == 8 && g.profile == "coherent-scalar-alias" {
        vec![244]
    } else {
        vec![]
    };
    if false_rows != expected
        || false_rows != h.expected_false
        || !h.expected_abort_ordinals.is_empty()
    {
        return Err("exact coherent native false-producer profile differs".into());
    }
    let ordinals = match h.execution_mode.as_str() {
        "all" => (0..d.leaves).collect(),
        "none" => vec![],
        "selected" => h
            .selected_ordinals
            .clone()
            .ok_or("selected ordinals absent")?,
        _ => return Err("execution selector".into()),
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
        global_ids: ids,
        facts,
        full,
        tail,
        frame: checked_frame,
        absorb: checked_absorb,
    })
}
pub(crate) fn native_false(case: &Case, index: usize) -> Result<Vec<usize>> {
    (0..case.spec.leaves.len())
        .filter_map(|i| {
            match if is_full(index) || index == 5 {
                permutation::truth(&case.spec, &case.words, i)
            } else {
                rho_tail::truth(&case.spec, &case.words, i)
            } {
                Ok(true) => None,
                Ok(false) => Some(Ok(i)),
                Err(error) => Some(Err(error)),
            }
        })
        .collect()
}

pub(crate) struct RecordSink {
    pub(crate) hash: sha256::HashEngine,
    pub(crate) bytes: u64,
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
pub(crate) fn registry_for(
    prepared: &Prepared,
    pool: &keys::GlobalPool,
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
    if shapes.len() > maximum {
        return Err(
            "authenticated-layout census exceeds independently closed record budget".into(),
        );
    }
    Ok(shapes.len())
}
pub(crate) fn measure_execute(
    p: &Prepared,
    h: &Header,
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
                !expected,
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
    let layouts = guards(
        registry,
        signatures,
        sink,
        metrics,
        group,
        h.descriptor.index,
    )?;
    let mut ledger = json!({});
    permutation::extend_object(
        &mut ledger,
        json!({"context":p.case.spec.context,"registry_id":hex::encode(registry.identity()),"compiled_script_bytes":compiled,"largest_disproof_leaf_bytes":largest,"compiled_stream_sha256":sha256::Hash::from_engine(stream).to_string(),"execution_mode":h.execution_mode,"selected_ordinals":h.selected_ordinals,"executed_leaves":check,"native_predicates_checked":p.case.spec.leaves.len(),"false_predicates":h.expected_false,"abort_predicates":h.expected_abort_ordinals,"guard_layouts":layouts,"guard_vectors":14*layouts}),
    )?;
    Ok(ledger)
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Connection {
    pub(crate) global_id: String,
    pub(crate) source_component: usize,
    pub(crate) source_word: usize,
    pub(crate) source_occurrences: Vec<(usize, usize)>,
    pub(crate) target_component: usize,
    pub(crate) target_word: usize,
    pub(crate) target_occurrences: Vec<(usize, usize)>,
}
pub(crate) struct StoredOpening {
    pub(crate) word: usize,
    pub(crate) assertion: openings::Capture,
}
pub(crate) type OpeningStore = BTreeMap<(usize, usize, usize), StoredOpening>;
pub(crate) const CONNECTION_COUNTS: [(&str, usize, usize); 11] = [
    ("rho_messages", 96, 384),
    ("rho_frames", 208, 416),
    ("rho_reduction", 64, 64),
    ("coefficients", 64, 128),
    ("prefix_frame", 77, 154),
    ("rho_raw_prefix", 59, 118),
    ("rho_raw_absorb", 5, 5),
    ("prefix_absorb", 9, 9),
    ("prefix_suffix", 383, 766),
    ("absorb_suffix", 17, 34),
    ("c_reduction", 64, 64),
];
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
pub(crate) fn internal_joins(full: &permutation::Full) -> Vec<openings::Join> {
    (0..23)
        .map(|i| {
            let left = &full.rounds[i];
            openings::Join {
                producer_occurrences: left
                    .layout
                    .ports
                    .producers
                    .iter()
                    .map(|p| (left.first_leaf + p.0, p.1))
                    .collect(),
                consumer_occurrences: permutation::consumers(&full.rounds[i + 1]),
            }
        })
        .collect()
}
pub(crate) fn verify_connections(
    checked: &source::CheckedSource,
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
pub(crate) fn checked_outer(
    run: &Run,
    g: &Group,
    descriptors: &[source::ComponentDescriptor],
    facts: &[source::ComponentFacts],
) -> Result<source::CheckedSource> {
    let checked = source::build(
        &run.context,
        &g.role,
        g.rho_counter,
        &run.operation_id,
        descriptors,
        facts,
    )?;
    if checked.source_sha256 != g.source_sha256
        || checked.source_maps_sha256 != g.source_maps_sha256
    {
        return Err("independently rebuilt source/maps differ from scenario pin".into());
    }
    Ok(checked)
}
pub(crate) fn admission_negatives(
    run: &Run,
    g: &Group,
    descriptors: &[source::ComponentDescriptor],
    facts: &[source::ComponentFacts],
) -> Result<(usize, usize)> {
    let mut maps = 0usize;
    let mut sources = 0usize;
    for mutation in 0..12 {
        let mut bad = facts.to_vec();
        match mutation {
            0 => bad[0].interfaces[0].global_id = bad[0].interfaces[1].global_id.clone(),
            1 => bad[0].input_indices.swap(0, 1),
            2 => bad[1].output_indices.swap(0, 1),
            3 => bad[4].producer_ordinals[0] += 1,
            4 => bad[4].producer_occurrences[0] = 2,
            5 => bad[6].interfaces[0].occurrences[0].0 += 1,
            6 => bad[7].interfaces[0].occurrences[0].1 = 1,
            7 => bad[3].interfaces[0].bound = 256,
            8 => bad[5].interfaces[0].word_index = 1,
            9 => bad[8].interfaces.swap(1, 2),
            10 => bad[6].interfaces[136].global_id = source::prefix_id(0, 136)?,
            _ => bad[8].global_ids_sha256 = permutation::changed(&bad[8].global_ids_sha256)?,
        }
        if checked_outer(run, g, descriptors, &bad).is_ok() {
            return Err("substituted raw/coefficient/absorption/capacity/port map accepted".into());
        }
        maps += 1;
    }
    for mutation in 0..18 {
        let mut bad = descriptors.to_vec();
        match mutation {
            0 => bad[0].field_role = "wrong".into(),
            1 => bad[0].counter += 1,
            2 => bad[3].counter -= 1,
            3 => bad[4].operation_id.push_str("/different"),
            4 => bad[0].program_sha256 = permutation::changed(&bad[0].program_sha256)?,
            5 => bad[1].catalogue_id = permutation::changed(&bad[1].catalogue_id)?,
            6 => bad[2].source_sha256 = permutation::changed(&bad[2].source_sha256)?,
            7 => bad[3].source_maps_sha256 = permutation::changed(&bad[3].source_maps_sha256)?,
            8 => bad[4].global_ids_sha256 = permutation::changed(&bad[4].global_ids_sha256)?,
            9 => bad[5].program_identity_kind = "plain Program".into(),
            10 => bad[8].kind = "full-permutation".into(),
            11 => bad[6].words += 1,
            12 => bad[7].leaves -= 1,
            13 => bad[8].index = 9,
            14 => bad.swap(0, 1),
            15 => bad[4].branch = "c-hi".into(),
            16 => bad[5].source_sha256 = permutation::changed(&bad[5].source_sha256)?,
            _ => bad[8].program_sha256 = permutation::changed(&bad[8].program_sha256)?,
        }
        if checked_outer(run, g, &bad, facts).is_ok() {
            return Err(
                "substituted component/field/counter/program/source identity accepted".into(),
            );
        }
        sources += 1;
    }
    Ok((maps, sources))
}

pub(crate) fn reject<T>(
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

#[allow(dead_code, unused_imports)]
pub(crate) mod permutation {
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
    pub(crate) struct Check {
        pub(crate) ordinal: usize,
        pub(crate) expected_correct: bool,
    }
    #[derive(Clone, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub(crate) struct Case {
        pub(crate) name: String,
        pub(crate) spec: GraphSpec,
        pub(crate) expected_spec_id: String,
        pub(crate) words: Vec<u32>,
        pub(crate) checks: Vec<Check>,
        pub(crate) measure_all: bool,
    }
    const MAP_CAP: u64 = 8 << 20;
    const LEAVES: usize = 29245;
    const WORDS: usize = 29445;
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    pub(crate) struct Manifest {
        pub(crate) schema: String,
        pub(crate) context: String,
        pub(crate) operation_id: String,
        pub(crate) cases: Vec<Descriptor>,
    }
    #[derive(Clone, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub(crate) struct Descriptor {
        pub(crate) name: String,
        pub(crate) profile: String,
        pub(crate) role: String,
        pub(crate) filename: String,
        pub(crate) file_sha256: String,
        pub(crate) file_bytes: u64,
        pub(crate) catalogue_id: String,
        pub(crate) program_sha256: String,
        pub(crate) source_sha256: String,
        pub(crate) global_ids_sha256: String,
        pub(crate) words: usize,
        pub(crate) leaves: usize,
        pub(crate) input_state_hex: String,
        pub(crate) expected_output_state_hex: String,
        pub(crate) expected_false: Vec<usize>,
        pub(crate) state_index: Option<usize>,
        pub(crate) byte_slot: Option<usize>,
        pub(crate) maps_filename: String,
        pub(crate) maps_file_sha256: String,
        pub(crate) maps_file_bytes: u64,
        pub(crate) source_maps_sha256: String,
        pub(crate) program_manifest_filename: String,
        pub(crate) program_manifest_file_sha256: String,
        pub(crate) program_manifest_file_bytes: u64,
        pub(crate) source_manifest_filename: String,
        pub(crate) source_manifest_file_sha256: String,
        pub(crate) source_manifest_file_bytes: u64,
        pub(crate) blocks: Vec<BlockDescriptor>,
    }
    #[derive(Clone, Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    pub(crate) struct BlockDescriptor {
        pub(crate) index: usize,
        pub(crate) first_round: usize,
        pub(crate) last_round: usize,
        pub(crate) operation_id: String,
        pub(crate) program_operation_id: String,
        pub(crate) source_sha256: String,
        pub(crate) program_sha256: String,
        pub(crate) catalogue_id: String,
        pub(crate) global_ids_sha256: String,
        pub(crate) words: usize,
        pub(crate) leaves: usize,
        pub(crate) leaf_offset: usize,
        pub(crate) word_map_sha256: String,
        pub(crate) leaf_map_sha256: String,
    }
    #[derive(Clone, Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    pub(crate) struct BlockRecord {
        pub(crate) index: usize,
        pub(crate) first_round: usize,
        pub(crate) last_round: usize,
        pub(crate) operation_id: String,
        pub(crate) program_operation_id: String,
        pub(crate) source_sha256: String,
        pub(crate) program_sha256: String,
        pub(crate) catalogue_id: String,
        pub(crate) global_ids_sha256: String,
        pub(crate) words: usize,
        pub(crate) leaves: usize,
        pub(crate) leaf_offset: usize,
        pub(crate) word_map_sha256: String,
        pub(crate) leaf_map_sha256: String,
        pub(crate) word_map: Vec<usize>,
        pub(crate) leaf_map: Vec<usize>,
    }
    #[derive(Clone, Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    pub(crate) struct RoundRecord {
        pub(crate) index: usize,
        pub(crate) round_index: usize,
        pub(crate) operation_id: String,
        pub(crate) program_operation_id: String,
        pub(crate) source_sha256: String,
        pub(crate) program_sha256: String,
        pub(crate) catalogue_id: String,
        pub(crate) global_ids_sha256: String,
        pub(crate) block_index: usize,
        pub(crate) child_index: usize,
        pub(crate) word_map: Vec<usize>,
        pub(crate) leaf_map: Vec<usize>,
        pub(crate) input_indices: Vec<usize>,
        pub(crate) output_indices: Vec<usize>,
        pub(crate) producer_ordinals: Vec<usize>,
        pub(crate) producer_occurrences: Vec<usize>,
        pub(crate) input_consumer_occurrences: Vec<Vec<(usize, usize)>>,
    }
    #[derive(Clone, Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    pub(crate) struct JoinRecord {
        pub(crate) index: usize,
        pub(crate) state_round: usize,
        pub(crate) words: Vec<String>,
        pub(crate) indices: Vec<usize>,
        pub(crate) producer_ordinals: Vec<usize>,
        pub(crate) producer_occurrences: Vec<usize>,
        pub(crate) consumer_occurrences: Vec<Vec<(usize, usize)>>,
    }
    #[derive(Clone, Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    pub(crate) struct RawMaps {
        pub(crate) schema: String,
        pub(crate) blocks: Vec<BlockRecord>,
        pub(crate) rounds: Vec<RoundRecord>,
        pub(crate) input_indices: Vec<usize>,
        pub(crate) output_indices: Vec<usize>,
        pub(crate) producer_ordinals: Vec<usize>,
        pub(crate) producer_occurrences: Vec<usize>,
        pub(crate) global_ids: Vec<String>,
        pub(crate) global_ids_sha256: String,
        pub(crate) joins: Vec<JoinRecord>,
    }
    #[derive(Clone)]
    pub(crate) struct ChildDescriptor {
        pub(crate) round: usize,
        pub(crate) operation_id: String,
        pub(crate) program_sha256: String,
        pub(crate) catalogue_id: String,
        pub(crate) source_sha256: String,
        pub(crate) wordmap_sha256: String,
        pub(crate) words: usize,
        pub(crate) leaves: usize,
        pub(crate) first_leaf: usize,
    }
    #[derive(Clone)]
    pub(crate) struct SegmentDescriptor {
        pub(crate) start_round: usize,
        pub(crate) program_sha256: String,
        pub(crate) catalogue_id: String,
        pub(crate) source_sha256: String,
        pub(crate) global_ids_sha256: String,
        pub(crate) children: Vec<ChildDescriptor>,
    }
    #[derive(Clone)]
    pub(crate) struct View {
        pub(crate) spec: GraphSpec,
        pub(crate) map: Vec<usize>,
        pub(crate) first_leaf: usize,
        pub(crate) layout: ChildLayout,
    }
    #[derive(Clone)]
    pub(crate) struct Block {
        pub(crate) views: Vec<View>,
        pub(crate) inputs: Vec<usize>,
        pub(crate) outputs: Vec<usize>,
    }
    pub(crate) struct Segment {
        pub(crate) spec: GraphSpec,
        pub(crate) map: Vec<usize>,
        pub(crate) first_leaf: usize,
        pub(crate) block: Block,
        pub(crate) metadata: SegmentDescriptor,
        pub(crate) maps: Value,
    }
    pub(crate) struct Full {
        pub(crate) segments: Vec<Segment>,
        pub(crate) rounds: Vec<View>,
        pub(crate) inputs: Vec<usize>,
        pub(crate) outputs: Vec<usize>,
        pub(crate) maps: Value,
    }
    pub(crate) fn segment(
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
    pub(crate) fn compose(
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
    pub(crate) fn identities(
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
    pub(crate) fn byte_layout(spec: &GraphSpec, r: usize) -> Result<ChildLayout> {
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
    pub(crate) fn canonical(value: &Value) -> Result<Vec<u8>> {
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
    pub(crate) fn domain_hash(domain: &[u8], value: &Value) -> Result<String> {
        let mut h = sha256::Hash::engine();
        h.input(domain);
        h.input(&canonical(value)?);
        Ok(sha256::Hash::from_engine(h).to_string())
    }
    pub(crate) fn consumers(view: &View) -> Vec<Vec<(usize, usize)>> {
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
    pub(crate) fn state(value: &str) -> Result<[u8; 200]> {
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
    pub(crate) fn reference(input: &[u8; 200], r: usize) -> [u8; 200] {
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
    pub(crate) fn extend_object(target: &mut Value, extra: Value) -> Result<()> {
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
    pub(crate) fn digest(value: &str) -> Result<[u8; 32]> {
        let raw = id32(value)?;
        if hex::encode(raw) != value {
            return Err("canonical lowercase32 digest required".into());
        }
        Ok(raw)
    }
    pub(crate) fn identifier(value: &str) -> bool {
        !value.is_empty()
            && value.len() <= 192
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.:/-".contains(&b))
    }
    pub(crate) fn snapshot(path: &Path, cap: u64, expected: [u8; 32]) -> Result<Vec<u8>> {
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
    pub(crate) fn truth(spec: &GraphSpec, values: &[u32], ordinal: usize) -> Result<bool> {
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
    pub(crate) fn changed(value: &str) -> Result<String> {
        let mut raw = digest(value)?;
        raw[0] ^= 1;
        Ok(hex::encode(raw))
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
    pub(crate) fn opening(
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
    pub(crate) fn program_digest(spec: &GraphSpec) -> Result<[u8; 32]> {
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
    pub(crate) fn map_hash(map: &[usize]) -> Result<String> {
        Ok(sha256::Hash::hash(&serde_json::to_vec(map)?).to_string())
    }
    pub(crate) fn state_word(name: &str, round: usize) -> Result<(usize, usize)> {
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
    pub(crate) fn project(
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
    pub(crate) fn round_source(
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
    pub(crate) fn validate_sources(
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
    pub(crate) fn validate_maps(parent: &GraphSpec, block: &Block, start: usize) -> Result<()> {
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
    pub(crate) struct Ports {
        pub(crate) inputs: Vec<usize>,
        pub(crate) outputs: Vec<usize>,
        pub(crate) producers: Vec<(usize, usize)>,
    }
    #[derive(Clone)]
    pub(crate) struct ChildLayout {
        pub(crate) ports: Ports,
    }
    pub(crate) struct Checker<'a> {
        pub(crate) spec: &'a GraphSpec,
        pub(crate) word: usize,
        pub(crate) leaf: usize,
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
