//! Compact thirteen-component source composition. No key generation or Script.
//!
//! Descriptors/facts MUST be derived from fresh independently checked component
//! bytes. The Reference MUST come from retained_scalar_block::reference on the
//! actual pinned container, not from an imported JSON receipt. Its hashes remain
//! reference provenance only: the asserted96 scalar BYTEs are not value anchors.
#[path = "../../point-oracle/src/source.rs"]
pub mod point;
pub use point::{ComponentDescriptor, ComponentFacts, Interface};

use crate::retained_scalar_block::{
    Reference, BUNDLE_SHA256, DIMENSIONS_SHA256, POLICY_SHA256, PROOF_SHA256, VK_SHA256,
};
use bitcoin::hashes::{sha256, Hash};
use bitvm2_nova_script_oracle::wots::{id32, Result};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, HashSet};

const DOMAIN: &[u8] = b"BITVM2-NOVA/RETAINED-SCALAR-SOURCES/v1\0";
const MAP_CAP: usize = 8 << 20;
const MANIFEST_CAP: usize = 1 << 20;
const BASE: u32 = 1 << 29;
const CROSSINGS: [(usize, usize); 7] =
    [(3, 5), (7, 2), (10, 7), (14, 4), (18, 1), (21, 6), (25, 3)];

pub struct CheckedSource {
    pub maps: Value,
    pub manifest: Value,
    pub source_sha256: String,
    pub source_maps_sha256: String,
}

fn identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 192
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.:/-".contains(&b))
}
fn decimal(s: &str, high: usize) -> Result<usize> {
    let value: usize = s.parse()?;
    if value > high || value.to_string() != s {
        return Err("canonical bounded source index required".into());
    }
    Ok(value)
}
fn digest(s: &str) -> Result<()> {
    if hex::encode(id32(s)?) != s {
        return Err("canonical lowercase32 source digest required".into());
    }
    Ok(())
}
fn profile(role: &str) -> Result<(u64, usize, usize, usize, &'static str, &'static str)> {
    match role {
        "pallas_scalar" => Ok((59, 19, 4624, 5180, "primary", "pallas")),
        "vesta_scalar" => Ok((44, 14, 10048, 10604, "secondary", "vesta")),
        _ => Err("supported retained scalar ROLE NAME required".into()),
    }
}
pub fn component_operation(op: &str, index: usize) -> Result<String> {
    if !identifier(op) {
        return Err("bounded retained scalar operation required".into());
    }
    match index {
        11 => Ok(format!("{op}/proof/scalar-block")),
        12 => Ok(format!("{op}/proof/eval-w")),
        _ => Err("new scalar-source component index11/12 required".into()),
    }
}
pub fn validate_policy(
    context: &str,
    role: &str,
    rho_counter: u64,
    bit_index: usize,
    op: &str,
) -> Result<()> {
    if profile(role)?.0 != rho_counter {
        return Err("retained source counter must be59/44 by role".into());
    }
    point::validate_policy(
        context,
        role,
        rho_counter,
        bit_index,
        &format!("{op}/point"),
    )?;
    let tape = component_operation(op, 11)?;
    let eval = component_operation(op, 12)?;
    if !identifier(&tape) || !identifier(&eval) || !identifier(&format!("{eval}/uniform-reference"))
    {
        return Err("derived retained scalar child operation exceeds existing cap".into());
    }
    Ok(())
}
fn eval_id(byte: usize) -> Result<String> {
    if byte >= 32 {
        return Err("eval_W BYTE index bound".into());
    }
    Ok(format!("rho/message/eval_w/byte/{byte}"))
}
fn coefficient_id(degree: usize, byte: usize) -> Result<String> {
    if ![0, 2].contains(&degree) || byte >= 32 {
        return Err("compressed degree0/2 BYTE index bound".into());
    }
    Ok(format!("c/coeff/{degree}/byte/{byte}"))
}
pub fn global_id(index: usize, local: &str, role: &str, bit_index: usize) -> Result<String> {
    let (_, _, _, start, _, _) = profile(role)?;
    if index >= 13 || bit_index >= 255 {
        return Err("retained component/fixed-bit bound".into());
    }
    if index < 11 {
        return point::global_id(index, local, role, bit_index);
    }
    let out = if index == 11 {
        let byte = decimal(
            local
                .strip_prefix("block/byte/")
                .ok_or("closed retained block BYTE name")?,
            111,
        )?;
        if byte < 32 {
            eval_id(byte)?
        } else if byte >= 48 {
            coefficient_id(if byte < 80 { 0 } else { 2 }, (byte - 48) % 32)?
        } else {
            format!("proof/container-byte/{}", start + byte)
        }
    } else {
        if !identifier(local) {
            return Err("actual bounded eval_W local name required".into());
        }
        if let Some(tail) = local.strip_prefix("scalar/encoding/byte/") {
            eval_id(decimal(tail, 31)?)?
        } else {
            format!("eval-w/{local}")
        }
    };
    if !identifier(&out) {
        return Err("retained global namespace exceeds existing identifier cap".into());
    }
    Ok(out)
}

fn canonical(v: &Value) -> Result<Vec<u8>> {
    fn ordered(v: &Value, depth: usize) -> Result<Value> {
        if depth > 16 {
            return Err("retained source canonical JSON depth cap".into());
        }
        Ok(match v {
            Value::Object(obj) => {
                let mut keys: Vec<_> = obj.keys().collect();
                keys.sort_unstable();
                let mut result = Map::new();
                for key in keys {
                    if !key.is_ascii() {
                        return Err("ASCII source key required".into());
                    }
                    result.insert(key.clone(), ordered(&obj[key], depth + 1)?);
                }
                Value::Object(result)
            }
            Value::Array(items) => Value::Array(
                items
                    .iter()
                    .map(|x| ordered(x, depth + 1))
                    .collect::<Result<_>>()?,
            ),
            Value::String(text) if !text.is_ascii() => {
                return Err("ASCII source string required".into())
            }
            Value::Number(n) if n.as_u64().is_none() && n.as_i64().is_none() => {
                return Err("source integer required".into())
            }
            other => other.clone(),
        })
    }
    Ok(serde_json::to_vec(&ordered(v, 0)?)?)
}
fn hash(v: &Value) -> Result<String> {
    Ok(sha256::Hash::hash(&canonical(v)?).to_string())
}

fn validate_reference(r: &Reference, role: &str) -> Result<()> {
    let (_, rows, proof_start, start, owner, engine) = profile(role)?;
    if r.role != role
        || r.engine != engine
        || r.proof_offset != proof_start
        || r.bundle_offset != start
        || r.proof_bytes != 12664
        || r.bundle_bytes != 13220
        || r.proof_sha256 != PROOF_SHA256
        || r.bundle_sha256 != BUNDLE_SHA256
        || r.expected_policy_sha256 != POLICY_SHA256
        || r.dimensions_sha256 != DIMENSIONS_SHA256
        || r.verifier_key_sha256 != VK_SHA256
        || r.raw_span[..32] != r.eval_w
        || r.raw_span[48..80] != r.c0
        || r.raw_span[80..112] != r.c2
        || r.raw_span[32..40] != (rows as u64).to_le_bytes()
        || r.raw_span[40..48] != 2u64.to_le_bytes()
    {
        return Err(
            "fresh retained reference/policy/role/spans/length-prefix identity differs".into(),
        );
    }
    let root = format!("snark_{owner}");
    let vector = format!("{root}.sc_proof_batch.compressed_polys");
    let row = format!("{vector}[0].coeffs_except_linear_term");
    let paths = [
        format!("{root}.eval_W"),
        vector,
        row.clone(),
        format!("{row}[0]"),
        format!("{row}[1]"),
    ];
    let mut spans = Vec::new();
    for (i, (offset, size, kind)) in [
        (0, 32, "scalar"),
        (32, 8, "length"),
        (40, 8, "length"),
        (48, 32, "scalar"),
        (80, 32, "scalar"),
    ]
    .into_iter()
    .enumerate()
    {
        spans.push(
            json!({"path":paths[i],"kind":kind,"start":proof_start+offset,"size":size,
            "engine":if kind=="scalar"{json!(engine)}else{Value::Null}}),
        );
    }
    if r.spans != json!(spans) {
        return Err(
            "fresh retained reference must expose the fixed five exact internal paths".into(),
        );
    }
    Ok(())
}

fn descriptor(
    d: &ComponentDescriptor,
    f: &ComponentFacts,
    index: usize,
    role: &str,
    rho: u64,
    op: &str,
) -> Result<()> {
    let tape = index == 11;
    let branch = if tape {
        "retained-scalar-block"
    } else {
        "eval-w-encoding"
    };
    let shape = if tape { (112, 112) } else { (55, 17) };
    if d.index != index
        || d.branch != branch
        || d.kind != branch
        || d.field_role != role
        || d.counter != rho
        || d.operation_id != component_operation(op, index)?
        || (d.words, d.leaves) != shape
        || d.program_identity_kind
            != if tape {
                "ByteProgram.digest (byte-v1)"
            } else {
                "ConvolutionProgram.digest (fixed-trace/v2)"
            }
        || f.index != index
        || f.branch != branch
        || f.global_ids_sha256 != d.global_ids_sha256
        || !f.input_indices.is_empty()
        || !f.output_indices.is_empty()
        || !f.producer_ordinals.is_empty()
        || !f.producer_occurrences.is_empty()
    {
        return Err("retained source descriptor/facts kind/role/counter/census differs".into());
    }
    for value in [
        &d.program_sha256,
        &d.catalogue_id,
        &d.source_sha256,
        &d.source_maps_sha256,
        &d.global_ids_sha256,
    ] {
        digest(value)?;
    }
    Ok(())
}

fn encoding_layout() -> (Vec<(String, u32)>, Vec<Vec<usize>>) {
    let mut words = Vec::new();
    for i in 0..9 {
        words.push((format!("scalar/l{i}"), BASE));
    }
    for i in 0..32 {
        words.push((format!("scalar/encoding/byte/{i}"), 256));
    }
    for (byte, width) in CROSSINGS {
        words.push((format!("scalar/encoding/split/{byte}/lo"), 1u32 << width));
        words.push((
            format!("scalar/encoding/split/{byte}/hi"),
            1u32 << (8 - width),
        ));
    }
    let mut leaves = Vec::new();
    for (i, (byte, _)) in CROSSINGS.iter().enumerate() {
        leaves.push(vec![9 + byte, 41 + 2 * i, 42 + 2 * i]);
    }
    for limb in 0..9 {
        let start = 29 * limb;
        let end = (start + 29).min(256);
        let mut wires = vec![limb];
        for byte in start / 8..(end + 7) / 8 {
            let low = start.max(8 * byte);
            let high = end.min(8 * byte + 8);
            let word = if low == 8 * byte && high == 8 * byte + 8 {
                9 + byte
            } else {
                let crossing = CROSSINGS
                    .iter()
                    .position(|(j, _)| *j == byte)
                    .expect("fixed seven crossing-byte layout");
                41 + 2 * crossing + usize::from(low != 8 * byte)
            };
            wires.push(word);
        }
        leaves.push(wires);
    }
    leaves.push((0..9).collect());
    (words, leaves)
}
fn encoding_interfaces(role: &str) -> Result<Vec<Interface>> {
    let (words, leaves) = encoding_layout();
    let mut out = Vec::new();
    for (word, (name, bound)) in words.iter().enumerate() {
        let mut occurrences = Vec::new();
        for (ordinal, wires) in leaves.iter().enumerate() {
            for (formal, slot) in wires.iter().enumerate() {
                if *slot == word {
                    occurrences.push((ordinal, formal));
                }
            }
        }
        out.push(Interface {
            word_index: word,
            global_id: global_id(12, name, role, 0)?,
            bound: *bound,
            occurrences,
        });
    }
    Ok(out)
}
fn check_interfaces(f: &ComponentFacts, role: &str) -> Result<()> {
    let expected = if f.index == 11 {
        (0..112)
            .map(|byte| {
                Ok(Interface {
                    word_index: byte,
                    global_id: global_id(11, &format!("block/byte/{byte}"), role, 0)?,
                    bound: 256,
                    occurrences: vec![(
                        if byte < 32 {
                            16 + byte
                        } else if byte < 48 {
                            byte - 32
                        } else {
                            byte
                        },
                        0,
                    )],
                })
            })
            .collect::<Result<Vec<_>>>()?
    } else {
        encoding_interfaces(role)?
    };
    if f.interfaces != expected {
        return Err("complete actual tape/encoding word bounds/occurrences differ".into());
    }
    if hash(&json!(f
        .interfaces
        .iter()
        .map(|r| &r.global_id)
        .collect::<Vec<_>>()))?
        != f.global_ids_sha256
    {
        return Err("complete actual new scalar word-map SHA differs".into());
    }
    Ok(())
}

fn lookup<'a>(facts: &'a [ComponentFacts], component: usize, id: &str) -> Result<&'a Interface> {
    facts[component]
        .interfaces
        .iter()
        .find(|r| r.global_id == id)
        .ok_or_else(|| "missing actual scalar source/consumer interface".into())
}
fn direct_links(facts: &[ComponentFacts]) -> Result<Value> {
    let mut links = Vec::new();
    let mut count = 0;
    for byte in (0..32).chain(48..112) {
        let source = &facts[11].interfaces[byte];
        let id = &source.global_id;
        let expected_source = (if byte < 32 { 16 + byte } else { byte }, 0);
        if source.bound != 256 || source.occurrences != [expected_source] {
            return Err("dynamic tape BYTE needs its actual word_valid opener".into());
        }
        let targets: Vec<(usize, usize)> = if byte < 32 {
            vec![(0, 2), (1, 2), (12, 1)]
        } else {
            vec![(3, 1), (4, 2)]
        };
        let mut rows = Vec::new();
        for (component, expected) in targets {
            let target = lookup(facts, component, id)?;
            if target.bound != 256 || target.occurrences.len() != expected {
                return Err("actual scalar BYTE consumer coverage differs".into());
            }
            count += target.occurrences.len();
            rows.push(json!({"component_index":component,"word_index":target.word_index,"occurrences":target.occurrences}));
        }
        links.push(json!({"global_id":id,"source_component":11,"source_word":byte,"source_ordinal":expected_source.0,
            "source_occurrence":expected_source.1,"targets":rows}));
    }
    if links.len() != 96 || count != 352 {
        return Err("96 tape origins must cover exactly352 actual direct comparisons".into());
    }
    Ok(json!(links))
}

fn internal_links(facts: &[ComponentFacts]) -> Result<Value> {
    let (_, leaves) = encoding_layout();
    let mut links = Vec::new();
    for i in 0..9 {
        let row = &facts[12].interfaces[i];
        if row.bound != BASE || row.occurrences != [(7 + i, 0), (16, i)] {
            return Err("eval_W reconstruction-to-field-valid link differs".into());
        }
        links.push(json!({"component_index":12,"global_id":row.global_id,"kind":"limb-to-field-valid","word_index":i,
            "source_ordinal":7+i,"source_occurrence":0,"target_ordinal":16,"target_occurrence":i}));
    }
    for part in 0..14 {
        let word = 41 + part;
        let source = part / 2;
        let formal = 1 + part % 2;
        let mut targets = Vec::new();
        for ordinal in 7..16 {
            for (slot, wire) in leaves[ordinal].iter().enumerate() {
                if slot > 0 && *wire == word {
                    targets.push((ordinal, slot));
                }
            }
        }
        if targets.len() != 1 || leaves[source][formal] != word {
            return Err("eval_W split-to-reconstruction link differs".into());
        }
        links.push(json!({"component_index":12,"global_id":facts[12].interfaces[word].global_id,
            "kind":"split-to-reconstruction","word_index":word,"source_ordinal":source,"source_occurrence":formal,
            "target_ordinal":targets[0].0,"target_occurrence":targets[0].1}));
    }
    if links.len() != 23 {
        return Err("exact23 internal eval_W links required".into());
    }
    Ok(json!(links))
}

fn check_histogram(facts: &[ComponentFacts]) -> Result<()> {
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for component in facts {
        let mut local = HashSet::new();
        for row in &component.interfaces {
            if !local.insert(&row.global_id) {
                return Err("injective actual component interfaces required".into());
            }
            *counts.entry(&row.global_id).or_default() += 1;
        }
    }
    if counts.values().filter(|n| **n == 2).count() != 432
        || counts.values().filter(|n| **n == 3).count() != 328
        || counts.values().filter(|n| **n == 4).count() != 32
        || counts.values().any(|n| *n > 4)
        || counts.values().map(|n| n - 1).sum::<usize>() != 1184
    {
        return Err("retained quotient must be432double/328triple/32quadruple/1184reuse".into());
    }
    Ok(())
}
fn prefix_anchors(r: &Reference) -> Value {
    json!((32..48).map(|i|json!({"block_index":i,"word_index":i,"expected":r.raw_span[i],"ordinal":i-32,"formal":0})).collect::<Vec<_>>())
}
fn eval_ports() -> Value {
    let (words, _) = encoding_layout();
    json!({"input_bytes":words[9..41].iter().map(|w|&w.0).collect::<Vec<_>>(),
        "scalar_limbs":words[..9].iter().map(|w|&w.0).collect::<Vec<_>>(),
        "split_auxiliaries":words[41..].iter().map(|w|&w.0).collect::<Vec<_>>()})
}

pub fn build(
    context: &str,
    role: &str,
    rho_counter: u64,
    bit_index: usize,
    outer_op: &str,
    descriptors: &[ComponentDescriptor],
    facts: &[ComponentFacts],
    reference: &Reference,
) -> Result<CheckedSource> {
    validate_policy(context, role, rho_counter, bit_index, outer_op)?;
    validate_reference(reference, role)?;
    if descriptors.len() != 13 || facts.len() != 13 {
        return Err("thirteen exact fresh descriptors/facts required".into());
    }
    let nested = point::build(
        context,
        role,
        rho_counter,
        bit_index,
        &format!("{outer_op}/point"),
        &descriptors[..11],
        &facts[..11],
    )?;
    for index in [11, 12] {
        descriptor(
            &descriptors[index],
            &facts[index],
            index,
            role,
            rho_counter,
            outer_op,
        )?;
        check_interfaces(&facts[index], role)?;
    }
    let mut programs = HashSet::new();
    let mut catalogues = HashSet::new();
    let mut sources = HashSet::new();
    for d in descriptors {
        if !programs.insert(&d.program_sha256)
            || !catalogues.insert(&d.catalogue_id)
            || !sources.insert(&d.source_sha256)
        {
            return Err("distinct actual retained child identities required".into());
        }
    }
    check_histogram(facts)?;
    let local: usize = descriptors.iter().map(|d| d.words).sum();
    let leaves: usize = descriptors.iter().map(|d| d.leaves).sum();
    if local != 156330 || leaves != 153342 || 155107 + 16 + 23 != 155146 || local - 1184 != 155146 {
        return Err("retained thirteen-component fixed census differs".into());
    }
    let links = direct_links(facts)?;
    let internal = internal_links(facts)?;
    let maps = json!({"schema":"bitvm2-nova-retained-scalar-sources-maps/v1",
        "point_source_sha256":nested.source_sha256,"point_source_maps_sha256":nested.source_maps_sha256,
        "inherited_component_indices":(0..11).collect::<Vec<_>>(),"components":descriptors,
        "tape_to_consumers":links,"eval_canonical_internal_links":internal,"eval_encoding_ports":eval_ports(),
        "reference_block":{"proof_relative_start":reference.proof_offset,"container_relative_start":reference.bundle_offset,
            "source_byte_offsets":(reference.bundle_offset..reference.bundle_offset+112).collect::<Vec<_>>(),
            "prefix_anchors":prefix_anchors(reference),"reference_block_sha256":sha256::Hash::hash(&reference.raw_span).to_string(),"source_authority":false},
        "normative_global_maps":{"point":"unchanged eleven-component mixed-role global IDs",
            "tape_dynamic":"eval_W32 and compressed c0_LE32/c2_LE32 share their exact existing BYTE identities",
            "tape_count_prefix":"proof/container-byte/{actual retained container offset}",
            "eval_byte_inputs":"rho/message/eval_w/byte/{0..31}","eval_private":"eval-w/<actual-encoding-local>"},
        "shared_histogram":{"double":432,"triple":328,"quadruple":32,"shared_unique":792},
        "leaves":153342,"local_declared_words":156330,"unique_global_words":155146,"cached_signature_reuses":1184});
    let raw_maps = canonical(&maps)?;
    if raw_maps.len() > MAP_CAP {
        return Err("retained scalar maps exceed unchanged8MiB cap".into());
    }
    let maps_sha = sha256::Hash::hash(&raw_maps).to_string();
    let manifest = json!({"schema":"bitvm2-nova-retained-scalar-sources/v1","context":context,"field_role":role,
        "point_field_role":point::point_role_for_scalar(role)?,"rho_counter":rho_counter,"c_counter":rho_counter+1,
        "bit_index":bit_index,"operation_id":outer_op,"point_operation_id":format!("{outer_op}/point"),
        "point_source_sha256":nested.source_sha256,"point_source_maps_sha256":nested.source_maps_sha256,
        "expected_policy_sha256":POLICY_SHA256,"verifier_dimensions_sha256":DIMENSIONS_SHA256,
        "component_order":descriptors.iter().map(|d|&d.branch).collect::<Vec<_>>(),"components":descriptors,
        "source_maps_sha256":maps_sha,"leaves":153342,"local_declared_words":156330,"unique_global_words":155146,"cached_signature_reuses":1184,
        "relation":"asserted eval_W/c0/c2 BYTE tape -> scalar encodings and existing RHO/c/point consumers",
        "commitment_order":"external retained policy/context -> source/maps -> one global pool -> thirteen registries -> Scripts -> forest",
        "scope":"local relations on asserted retained scalar BYTEs; whole-proof hash/EOF, prior-state and point/key origins remain unbound"});
    let raw = canonical(&manifest)?;
    if raw.len() > MANIFEST_CAP {
        return Err("retained scalar source exceeds unchanged1MiB cap".into());
    }
    let mut commitment = DOMAIN.to_vec();
    commitment.extend_from_slice(&raw);
    Ok(CheckedSource {
        maps,
        manifest,
        source_sha256: sha256::Hash::hash(&commitment).to_string(),
        source_maps_sha256: maps_sha,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Symbolic interface tables only: no GraphSpec, Registry, WOTS or Script.
    fn empty(index: usize) -> ComponentFacts {
        ComponentFacts {
            index,
            branch: format!("symbolic-{index}"),
            global_ids_sha256: "00".repeat(32),
            input_indices: vec![],
            output_indices: vec![],
            producer_ordinals: vec![],
            producer_occurrences: vec![],
            interfaces: vec![],
        }
    }
    fn tape(role: &str) -> ComponentFacts {
        let mut facts = empty(11);
        facts.interfaces = (0..112)
            .map(|i| Interface {
                word_index: i,
                global_id: global_id(11, &format!("block/byte/{i}"), role, 0).unwrap(),
                bound: 256,
                occurrences: vec![(
                    if i < 32 {
                        16 + i
                    } else if i < 48 {
                        i - 32
                    } else {
                        i
                    },
                    0,
                )],
            })
            .collect();
        facts.global_ids_sha256 = hash(&json!(facts
            .interfaces
            .iter()
            .map(|r| &r.global_id)
            .collect::<Vec<_>>()))
        .unwrap();
        facts
    }
    fn encoding(role: &str) -> ComponentFacts {
        let mut facts = empty(12);
        facts.interfaces = encoding_interfaces(role).unwrap();
        facts.global_ids_sha256 = hash(&json!(facts
            .interfaces
            .iter()
            .map(|r| &r.global_id)
            .collect::<Vec<_>>()))
        .unwrap();
        facts
    }
    fn symbolic_links(role: &str) -> Vec<ComponentFacts> {
        let mut facts: Vec<_> = (0..13).map(empty).collect();
        facts[11] = tape(role);
        facts[12] = encoding(role);
        for byte in (0..32).chain(48..112) {
            let id = facts[11].interfaces[byte].global_id.clone();
            let targets: &[usize] = if byte < 32 { &[0, 1] } else { &[3, 4] };
            for &component in targets {
                let n = if component == 3 { 1 } else { 2 };
                facts[component].interfaces.push(Interface {
                    word_index: byte,
                    global_id: id.clone(),
                    bound: 256,
                    occurrences: (0..n).map(|formal| (byte, formal)).collect(),
                });
            }
        }
        facts
    }

    #[test]
    fn retained_profiles_and_closed_namespaces() {
        for (role, rho, rows, start) in [
            ("pallas_scalar", 59, 19, 5180),
            ("vesta_scalar", 44, 14, 10604),
        ] {
            let p = profile(role).unwrap();
            assert_eq!((p.0, p.1, p.3), (rho, rows, start));
            assert_eq!(
                global_id(11, "block/byte/0", role, 0).unwrap(),
                "rho/message/eval_w/byte/0"
            );
            assert_eq!(
                global_id(11, "block/byte/48", role, 0).unwrap(),
                "c/coeff/0/byte/0"
            );
            assert_eq!(
                global_id(11, "block/byte/111", role, 0).unwrap(),
                "c/coeff/2/byte/31"
            );
            assert_eq!(
                global_id(11, "block/byte/32", role, 0).unwrap(),
                format!("proof/container-byte/{}", start + 32)
            );
            assert_eq!(
                global_id(12, "scalar/encoding/byte/31", role, 0).unwrap(),
                "rho/message/eval_w/byte/31"
            );
            assert_eq!(
                global_id(12, "scalar/l8", role, 0).unwrap(),
                "eval-w/scalar/l8"
            );
            for bad in [
                "block/byte/01",
                "block/byte/112",
                "block/byte/-1",
                "block/byte/1/extra",
            ] {
                assert!(global_id(11, bad, role, 0).is_err());
            }
            for bad in ["scalar/encoding/byte/032", "scalar/encoding/byte/32", ""] {
                assert!(global_id(12, bad, role, 0).is_err());
            }
        }
        assert!(profile("pallas_base").is_err());
        assert!(global_id(13, "x", "pallas_scalar", 0).is_err());
        assert!(global_id(11, "block/byte/0", "pallas_scalar", 255).is_err());
    }

    #[test]
    fn pure_policy_preflights_all_nested_identifiers() {
        let context = "21".repeat(32);
        for (role, rho) in [("pallas_scalar", 59), ("vesta_scalar", 44)] {
            assert!(validate_policy(&context, role, rho, 0, "source-test").is_ok());
            assert!(validate_policy(&context, role, rho, 254, "source-test").is_ok());
            assert!(validate_policy(&context, role, rho + 1, 0, "source-test").is_err());
            assert!(validate_policy(&context, role, rho, 255, "source-test").is_err());
            assert!(validate_policy(&context, role, rho, 0, &"x".repeat(192)).is_err());
        }
        assert!(validate_policy(&"AB".repeat(32), "pallas_scalar", 59, 0, "source-test").is_err());
        assert!(validate_policy(&context, "pallas_scalar", u64::MAX, 0, "source-test").is_err());
        assert!(component_operation("source-test", 10).is_err());
    }

    #[test]
    fn complete_encoding_actual_occurrences_and_bounds() {
        let (words, leaves) = encoding_layout();
        assert_eq!((words.len(), leaves.len()), (55, 17));
        let rows = encoding_interfaces("pallas_scalar").unwrap();
        assert_eq!(rows[9].occurrences, vec![(7, 1)]);
        assert_eq!(rows[12].occurrences, vec![(0, 0)]);
        assert_eq!(rows[40].occurrences, vec![(15, 3)]);
        assert_eq!(rows[8].occurrences, vec![(15, 0), (16, 8)]);
        assert_eq!((rows[41].bound, rows[42].bound), (32, 8));
        assert_eq!(rows[41].occurrences, vec![(0, 1), (7, 4)]);
        assert_eq!(rows[42].occurrences, vec![(0, 2), (8, 1)]);
        for role in ["pallas_scalar", "vesta_scalar"] {
            let t = tape(role);
            let mut e = encoding(role);
            assert!(check_interfaces(&t, role).is_ok());
            assert!(check_interfaces(&e, role).is_ok());
            e.interfaces[41].bound *= 2;
            assert!(check_interfaces(&e, role).is_err());
            let mut e = encoding(role);
            e.interfaces[42].occurrences[1].1 += 1;
            assert!(check_interfaces(&e, role).is_err());
            let mut e = encoding(role);
            e.global_ids_sha256 = "00".repeat(32);
            assert!(check_interfaces(&e, role).is_err());
        }
    }

    #[test]
    fn direct_and_internal_symbolic_opening_coverage() {
        for role in ["pallas_scalar", "vesta_scalar"] {
            let mut facts = symbolic_links(role);
            let direct = direct_links(&facts).unwrap();
            let rows = direct.as_array().unwrap();
            assert_eq!(rows.len(), 96);
            let comparisons: usize = rows
                .iter()
                .map(|row| {
                    row["targets"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|target| target["occurrences"].as_array().unwrap().len())
                        .sum::<usize>()
                })
                .sum();
            assert_eq!(comparisons, 352);
            let internal = internal_links(&facts).unwrap();
            assert_eq!(internal.as_array().unwrap().len(), 23);
            assert_eq!(internal[0]["target_ordinal"], 16);
            facts[0].interfaces[0].occurrences.pop();
            assert!(direct_links(&facts).is_err());
            let mut facts = symbolic_links(role);
            facts[11].interfaces[0].occurrences[0].0 += 1;
            assert!(direct_links(&facts).is_err());
            let mut facts = symbolic_links(role);
            facts[12].interfaces[8].occurrences[1].1 -= 1;
            assert!(internal_links(&facts).is_err());
        }
    }

    #[test]
    fn symbolic_exact_alias_histogram_rejects_extra_alias() {
        let mut facts: Vec<_> = (0..13).map(empty).collect();
        for (prefix, count, copies) in
            [("double", 432, 2), ("triple", 328, 3), ("quadruple", 32, 4)]
        {
            for index in 0..count {
                for component in 0..copies {
                    let word_index = facts[component].interfaces.len();
                    facts[component].interfaces.push(Interface {
                        word_index,
                        global_id: format!("{prefix}/{index}"),
                        bound: 256,
                        occurrences: vec![(word_index, 0)],
                    });
                }
            }
        }
        assert!(check_histogram(&facts).is_ok());
        let extra = facts[0].interfaces.last().unwrap().clone();
        facts[4].interfaces.push(extra);
        assert!(check_histogram(&facts).is_err());
        facts[4].interfaces.pop();
        let duplicate = facts[0].interfaces[0].clone();
        facts[0].interfaces.push(duplicate);
        assert!(check_histogram(&facts).is_err());
    }

    #[test]
    fn strict_canonical_source_json_and_digest() {
        assert_eq!(
            canonical(&json!({"z":[3,2,1],"a":false})).unwrap(),
            br#"{"a":false,"z":[3,2,1]}"#
        );
        assert!(canonical(&json!({"x":"\u{e9}"})).is_err());
        assert!(canonical(&json!({"\u{e9}":1})).is_err());
        assert!(canonical(&json!(1.5)).is_err());
        let mut deep = Value::Null;
        for _ in 0..18 {
            deep = json!([deep]);
        }
        assert!(canonical(&deep).is_err());
        assert!(digest(&"ab".repeat(32)).is_ok());
        assert!(digest(&"AB".repeat(32)).is_err());
        assert!(digest(&"00".repeat(31)).is_err());
    }
}
