//! Opt-in grouped conditional-point source admission.
//!
//! The complete legacy source is independently admitted with its original
//! GraphSpec and body pins before this module reconstructs the new grouping.
//! No header/kind proxy, imported receipt, key/signing or Script execution.
use crate::{
    conditional_point,
    registry::{GraphSpec, Leaf},
};
use bitcoin::{
    hashes::{sha256, Hash, HashEngine},
    script::Builder,
};
use bitvm2_nova_script_oracle::{registry as legacy_registry, wots::Result};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, HashSet};
const PROGRAM_DOMAIN: &[u8] = b"BITVM2-NOVA/GROUPED-CONVOLUTION-PROGRAM/v1\0";
const DOMAIN: &[u8] = b"BITVM2-NOVA/GROUPED-CONDITIONAL-POINT/v1\0";
const PATTERNS: [&[i64]; 3] = [&[1, 2, 3, 4], &[4, 4, 4, 4], &[3, 2, 1]];
const WORDS: usize = 7498;
const ARITHMETIC: usize = 3420;
const LEAVES: usize = 3457;
const CHILD_WORDS: usize = 7476;
const CHILD_ARITHMETIC: usize = 3412;
pub use conditional_point::{CurveVerdict, PointPorts};
pub struct Reference {
    pub spec: legacy_registry::GraphSpec,
    pub checked: conditional_point::CheckedPoint,
    pub sha256: String,
}
pub struct CheckedPoint {
    pub bit_index: usize,
    pub source_maps: Value,
    pub metadata: Value,
    pub source_sha256: String,
    pub source_maps_sha256: String,
    pub program_sha256: String,
    pub catalogue_id: String,
    pub child_program_sha256: String,
    pub child_catalogue_id: String,
    pub child_word_map: Vec<usize>,
    pub child_leaf_map: Vec<usize>,
    pub a: PointPorts,
    pub p: PointPorts,
    pub e: PointPorts,
    pub r: PointPorts,
    pub bit: usize,
    pub delta: usize,
    pub masked: usize,
    pub bit_occurrences: Vec<(usize, usize)>,
    pub r_field_guards: [usize; 2],
    pub fields: Vec<(String, Vec<usize>)>,
    pub projection: Projection,
    pub projection_sha256: String,
    pub reference_sha256: String,
    pub grouping: Value,
}
fn require(ok: bool, msg: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(msg.into())
    }
}
fn canonical(v: &Value) -> Result<Vec<u8>> {
    fn ordered(v: &Value, d: usize) -> Result<Value> {
        require(d <= 32, "grouped source JSON depth")?;
        Ok(match v {
            Value::Object(o) => {
                let mut keys = o.keys().collect::<Vec<_>>();
                keys.sort_unstable();
                let mut out = Map::new();
                for k in keys {
                    require(k.is_ascii(), "ASCII source key")?;
                    out.insert(k.clone(), ordered(&o[k], d + 1)?);
                }
                Value::Object(out)
            }
            Value::Array(a) => {
                Value::Array(a.iter().map(|x| ordered(x, d + 1)).collect::<Result<_>>()?)
            }
            Value::String(s) => {
                require(s.is_ascii(), "ASCII source string")?;
                v.clone()
            }
            Value::Number(n) => {
                require(
                    n.as_u64().is_some() || n.as_i64().is_some(),
                    "integer source JSON",
                )?;
                v.clone()
            }
            _ => v.clone(),
        })
    }
    Ok(serde_json::to_vec(&ordered(v, 0)?)?)
}
fn sha(raw: &[u8]) -> String {
    sha256::Hash::hash(raw).to_string()
}
fn hash(v: &Value) -> Result<String> {
    Ok(sha(&canonical(v)?))
}
fn names(spec: &GraphSpec, indices: &[usize]) -> Result<Vec<String>> {
    indices
        .iter()
        .map(|i| {
            spec.words
                .get(*i)
                .map(|w| w.name.clone())
                .ok_or_else(|| "word index".into())
        })
        .collect()
}
fn aliases(wires: &[usize]) -> Vec<usize> {
    let mut seen = BTreeMap::new();
    wires
        .iter()
        .map(|w| {
            let n = seen.len();
            *seen.entry(*w).or_insert(n)
        })
        .collect()
}
fn modulus_text(role: &str) -> Result<&'static str> {
    match role {
        "pallas_base" => {
            Ok("28948022309329048855892746252171976963363056481941560715954676764349967630337")
        }
        "vesta_base" => {
            Ok("28948022309329048855892746252171976963363056481941647379679742748393362948097")
        }
        _ => Err("exact Pasta base role".into()),
    }
}
fn program_digest(
    spec: &GraphSpec,
    operation: &str,
    words: usize,
    arithmetic: usize,
    fields: &[(String, Vec<usize>)],
) -> Result<String> {
    let shape = json!({"schema":"bitvm2-nova-fixed-trace/v2","field_role":spec.field_role,
        "modulus":modulus_text(&spec.field_role)?,"operation_id":operation,"context":spec.context,
        "words":spec.words[..words].iter().map(|w|json!([w.name,w.bound])).collect::<Vec<_>>(),
        "fields":fields.iter().map(|(n,ws)|Ok(json!([n,names(spec,ws)?]))).collect::<Result<Vec<_>>>()?,
        "constraints":spec.leaves[..arithmetic].iter().map(|l|Ok(json!([l.kind,names(spec,&l.wires)?,l.argument]))).collect::<Result<Vec<_>>>()?});
    let plain = hash(&shape)?;
    let mut h = sha256::Hash::engine();
    h.input(PROGRAM_DOMAIN);
    h.input(&hex::decode(plain)?);
    Ok(hex::encode(sha256::Hash::from_engine(h)))
}
/// The caller bounds and duplicate-checks the ORIGINAL reference JSON before
/// serde. This comparison binds its exact canonical {spec,maps} bytes, not a
/// file-name/receipt authority. The old checker runs on the genuine old spec.
pub fn admit_reference(
    spec: legacy_registry::GraphSpec,
    maps: Value,
    raw_sha256: &str,
    context: &str,
    role: &str,
    bit_index: usize,
    operation: &str,
) -> Result<Reference> {
    let actual = hash(&json!({"spec":spec,"maps":maps}))?;
    require(
        actual == raw_sha256,
        "canonical genuine reference file hash",
    )?;
    let checked = conditional_point::check(&spec, context, role, bit_index, operation, &maps)?;
    Ok(Reference {
        spec,
        checked,
        sha256: actual,
    })
}
/// Exact conversion is for checked OLD shapes only. No new grouped kind ever
/// travels through the legacy Registry or legacy-kind admission path.
pub fn legacy_to_local(spec: &legacy_registry::GraphSpec) -> Result<GraphSpec> {
    let value = serde_json::to_value(spec)?;
    let local: GraphSpec = serde_json::from_value(value.clone())?;
    require(
        serde_json::to_value(&local)? == value && local.identity()? == spec.identity()?,
        "strict old-to-local typed catalogue parity",
    )?;
    Ok(local)
}
#[derive(Clone)]
struct Cell {
    column: usize,
    block: usize,
    pairs: Vec<(usize, usize)>,
}
fn cells() -> Vec<Cell> {
    let mut out = Vec::new();
    for column in 0usize..63 {
        let start = column.saturating_sub(31);
        let end = column.min(31);
        for (block, first) in (start..=end).step_by(4).enumerate() {
            out.push(Cell {
                column,
                block,
                pairs: (first..=end.min(first + 3))
                    .map(|i| (i, column - i))
                    .collect(),
            });
        }
    }
    out
}
fn groups() -> Result<Vec<Vec<Cell>>> {
    let cells = cells();
    let mut out = Vec::new();
    for (lo, hi) in [(0, 31), (32, 62)] {
        for block in 0..8 {
            let strip = cells
                .iter()
                .filter(|c| lo <= c.column && c.column <= hi && c.block == block)
                .cloned()
                .collect::<Vec<_>>();
            out.extend(strip.chunks(4).map(|x| x.to_vec()));
        }
    }
    require(
        out.len() == 72
            && out.iter().map(Vec::len).sum::<usize>() == 280
            && out.iter().all(|g| {
                PATTERNS.contains(
                    &g.iter()
                        .map(|c| c.pairs.len() as i64)
                        .collect::<Vec<_>>()
                        .as_slice(),
                )
            }),
        "72-group exact partition",
    )?;
    Ok(out)
}
fn number(code: &mut Vec<u8>, n: usize) {
    code.extend_from_slice(Builder::new().push_int(n as i64).into_script().as_bytes());
}
fn expansion(wires: &[usize]) -> Vec<u8> {
    let a = aliases(wires);
    let unique = a.iter().max().map_or(0, |m| m + 1);
    if unique == a.len() {
        return Vec::new();
    }
    let mut code = Vec::new();
    for index in a.iter().rev() {
        let depth = unique - 1 - index;
        match depth {
            0 => code.push(0x76),
            1 => code.push(0x78),
            _ => {
                number(&mut code, depth);
                code.push(0x79);
            }
        }
        code.push(0x6b);
    }
    for _ in 0..unique / 2 {
        code.push(0x6d);
    }
    if unique % 2 == 1 {
        code.push(0x75);
    }
    for _ in &a {
        code.push(0x6c);
    }
    code
}

fn grouped_body(role: &str, args: &[i64], wires: &[usize]) -> Result<Vec<u8>> {
    require(PATTERNS.contains(&args), "closed grouped pattern")?;
    let formal = args.iter().map(|n| 2 * (*n as usize) + 1).sum::<usize>();
    require(formal == wires.len(), "grouped formal framing")?;
    let mut raw = vec![0x51];
    let mut offset = 0;
    for n in args {
        let length = 2 * (*n as usize) + 1;
        for _ in 0..length {
            number(&mut raw, formal - offset);
            raw.push(0x79);
        }
        raw.extend(crate::grouped_body_pins::frozen_row_body(*n as usize)?);
        raw.push(0x9a);
        offset += length;
    }
    raw.push(0x6b);
    raw.extend(std::iter::repeat(0x6d).take(formal / 2));
    if formal % 2 == 1 {
        raw.push(0x75);
    }
    raw.push(0x6c);
    require(
        sha(&raw) == crate::grouped_body_pins::expected_raw_body_sha256(role, args)?,
        "independent frozen-row wrapper differs",
    )?;
    let mut body = expansion(wires);
    body.extend(raw);
    require(
        body.len() <= 20000
            && sha(&body)
                == crate::grouped_body_pins::expected_body_sha256(role, args, &aliases(wires))?,
        "new grouped body pin/unchanged cap",
    )?;
    Ok(body)
}
#[derive(Clone)]
pub struct Projection {
    pub old_to_new: Vec<(usize, Option<usize>)>,
    pub new_to_old: Vec<Vec<usize>>,
    pub multiplication_prefixes: Vec<String>,
    pub groups: Vec<(String, usize, Vec<usize>)>,
}
impl Projection {
    pub fn json(&self) -> Value {
        json!({"schema":"bitvm2-nova-grouped-convolution-projection/v1","old_to_new":self.old_to_new,"new_to_old":self.new_to_old,"multiplication_prefixes":self.multiplication_prefixes,"groups":self.groups})
    }
}
fn transformed(old: &GraphSpec, new: &GraphSpec, arithmetic: usize) -> Result<Projection> {
    require(
        old.context == new.context
            && old.field_role == new.field_role
            && old.operation_id == new.operation_id
            && serde_json::to_value(&old.words)? == serde_json::to_value(&new.words)?,
        "grouping must preserve every word/bound/header",
    )?;
    let mut batches: Vec<(String, BTreeMap<(usize, usize), usize>)> = Vec::new();
    for (i, l) in old.leaves[..arithmetic].iter().enumerate() {
        if l.kind != "conv_ab" {
            continue;
        }
        let name = &old.words[*l.wires.last().ok_or("AB output")?].name;
        let (prefix, tail) = name.rsplit_once("/ab/").ok_or("AB source path")?;
        let (k, r) = tail.split_once('/').ok_or("AB cell path")?;
        let key = (k.parse::<usize>()?, r.parse::<usize>()?);
        let pos = if let Some(pos) = batches.iter().position(|(p, _)| p == prefix) {
            pos
        } else {
            batches.push((prefix.into(), BTreeMap::new()));
            batches.len() - 1
        };
        require(batches[pos].1.insert(key, i).is_none(), "duplicate AB cell")?;
    }
    require(batches.len() == 13, "closed multiplication batch count")?;
    let mut replacements = BTreeMap::new();
    let mut removed = HashSet::new();
    for (prefix, batch) in &batches {
        require(batch.len() == 280, "complete280AB batch")?;
        for (gi, g) in groups()?.iter().enumerate() {
            let rows = g
                .iter()
                .map(|c| {
                    batch
                        .get(&(c.column, c.block))
                        .copied()
                        .ok_or_else(|| "missing AB cell".into())
                })
                .collect::<Result<Vec<_>>>()?;
            let anchor = *rows.iter().min().ok_or("group anchor")?;
            replacements.insert(anchor, (prefix.clone(), gi, rows.clone()));
            removed.extend(rows);
        }
    }
    let mut expected = Vec::new();
    let mut reverse = Vec::new();
    let mut forward = vec![(usize::MAX, None); old.leaves.len()];
    let mut records = Vec::new();
    let mut bodies = BTreeMap::new();
    for i in 0..arithmetic {
        if let Some((prefix, gi, rows)) = replacements.get(&i) {
            let wires = rows
                .iter()
                .flat_map(|j| old.leaves[*j].wires.iter().copied())
                .collect::<Vec<_>>();
            let args = rows
                .iter()
                .map(|j| old.leaves[*j].argument[0])
                .collect::<Vec<_>>();
            let body = grouped_body(&old.field_role, &args, &wires)?;
            let sha = sha(&body);
            bodies.insert(sha.clone(), hex::encode(body));
            let ordinal = expected.len();
            expected.push(Leaf {
                kind: "conv_ab_all".into(),
                argument: args,
                wires,
                body_sha256: sha,
            });
            reverse.push(rows.clone());
            for (row, previous) in rows.iter().enumerate() {
                forward[*previous] = (ordinal, Some(row));
            }
            records.push((prefix.clone(), *gi, rows.clone()));
        } else if !removed.contains(&i) {
            let ordinal = expected.len();
            let l = old.leaves[i].clone();
            bodies.insert(l.body_sha256.clone(), old.bodies[&l.body_sha256].clone());
            expected.push(l);
            reverse.push(vec![i]);
            forward[i] = (ordinal, None);
        }
    }
    for i in arithmetic..old.leaves.len() {
        let ordinal = expected.len();
        let l = old.leaves[i].clone();
        bodies.insert(l.body_sha256.clone(), old.bodies[&l.body_sha256].clone());
        expected.push(l);
        reverse.push(vec![i]);
        forward[i] = (ordinal, None);
    }
    require(
        expected.len() == old.leaves.len() - 208 * batches.len()
            && new.leaves.len() == expected.len()
            && new.bodies == bodies,
        "candidate exact new leaf/body catalogue",
    )?;
    for (a, e) in new.leaves.iter().zip(&expected) {
        require(
            a.kind == e.kind
                && a.argument == e.argument
                && a.wires == e.wires
                && a.body_sha256 == e.body_sha256,
            "candidate grouped/unchanged occurrence projection",
        )?;
    }
    require(
        forward.iter().all(|x| x.0 != usize::MAX),
        "all old leaves projected",
    )?;
    new.identity()?;
    Ok(Projection {
        old_to_new: forward,
        new_to_old: reverse,
        multiplication_prefixes: batches.into_iter().map(|x| x.0).collect(),
        groups: records,
    })
}

fn unchanged_projection(projection: &Projection, old: usize) -> Result<usize> {
    let (new, row) = *projection
        .old_to_new
        .get(old)
        .ok_or("old projection ordinal")?;
    require(
        row.is_none(),
        "selector/field must remain one unchanged predicate",
    )?;
    Ok(new)
}
fn subset_bodies(spec: &GraphSpec, leaves: &[Leaf]) -> Result<BTreeMap<String, String>> {
    leaves
        .iter()
        .map(|l| {
            Ok((
                l.body_sha256.clone(),
                spec.bodies
                    .get(&l.body_sha256)
                    .ok_or("source body missing")?
                    .clone(),
            ))
        })
        .collect()
}
pub fn check(spec: &GraphSpec, reference: &Reference, raw_maps: &Value) -> Result<CheckedPoint> {
    let old = legacy_to_local(&reference.spec)?;
    let checked = &reference.checked;
    require(
        hex::encode(old.identity()?) == checked.catalogue_id
            && old.program_sha256 == checked.program_sha256,
        "genuine reference retains its independently admitted identity",
    )?;
    require(
        spec.words.len() == WORDS
            && spec.leaves.len() == LEAVES
            && old.words.len() == WORDS
            && old.leaves.len() == 6161,
        "grouped conditional point closed census",
    )?;
    let projection = transformed(&old, spec, 6124)?;
    require(
        projection.multiplication_prefixes.len() == 13 && projection.groups.len() == 936,
        "all13 complete multiplication batches grouped",
    )?;
    let program = program_digest(spec, &spec.operation_id, WORDS, ARITHMETIC, &checked.fields)?;
    require(
        program == spec.program_sha256,
        "grouped Program domain and full constraint identity",
    )?;
    let catalogue = hex::encode(spec.identity()?);

    let old_child_leaves = checked
        .child_leaf_map
        .iter()
        .map(|i| old.leaves[*i].clone())
        .collect::<Vec<_>>();
    let child_operation = format!("{}/complete-add", spec.operation_id);
    let old_child = GraphSpec {
        program_sha256: checked.child_program_sha256.clone(),
        context: old.context.clone(),
        field_role: old.field_role.clone(),
        operation_id: child_operation.clone(),
        words: old.words[..CHILD_WORDS].to_vec(),
        bodies: subset_bodies(&old, &old_child_leaves)?,
        leaves: old_child_leaves,
    };
    require(
        hex::encode(old_child.identity()?) == checked.child_catalogue_id,
        "genuine complete-add child identity",
    )?;
    let original_field_leaves = (6124..6159)
        .map(|i| unchanged_projection(&projection, i))
        .collect::<Result<Vec<_>>>()?;
    let child_leaf_map = (0..CHILD_ARITHMETIC)
        .chain(original_field_leaves.iter().copied())
        .collect::<Vec<_>>();
    require(
        child_leaf_map.len() == 3447 && original_field_leaves == (3420..3455).collect::<Vec<_>>(),
        "actual grouped complete-add field projection",
    )?;
    let child_program = program_digest(
        spec,
        &child_operation,
        CHILD_WORDS,
        CHILD_ARITHMETIC,
        &checked.fields[..35],
    )?;
    let child_leaves = child_leaf_map
        .iter()
        .map(|i| spec.leaves[*i].clone())
        .collect::<Vec<_>>();
    let child = GraphSpec {
        program_sha256: child_program.clone(),
        context: spec.context.clone(),
        field_role: spec.field_role.clone(),
        operation_id: child_operation,
        words: spec.words[..CHILD_WORDS].to_vec(),
        bodies: subset_bodies(spec, &child_leaves)?,
        leaves: child_leaves,
    };
    let child_catalogue = hex::encode(child.identity()?);
    let child_projection = transformed(&old_child, &child, 6116)?;
    let complete_add = json!({"legacy_program_sha256":checked.child_program_sha256,
        "legacy_catalogue_id":checked.child_catalogue_id,"program_sha256":child_program,
        "catalogue_id":child_catalogue,"words":7476,"arithmetic_constraints":3412,
        "canonical_fields":35,"leaves":3447,"word_map":(0..CHILD_WORDS).collect::<Vec<_>>(),
        "leaf_map":child_leaf_map,"projection_sha256":hash(&child_projection.json())?});
    let mut selectors = Map::new();
    for (name, ordinal) in checked.source_maps["selector_constraints"]
        .as_object()
        .ok_or("legacy selector map")?
    {
        let index = usize::try_from(ordinal.as_u64().ok_or("legacy selector ordinal")?)?;
        selectors.insert(
            name.clone(),
            json!(unchanged_projection(&projection, index)?),
        );
    }
    let actual_bits = spec
        .leaves
        .iter()
        .enumerate()
        .flat_map(|(ordinal, leaf)| {
            leaf.wires
                .iter()
                .enumerate()
                .filter_map(move |(formal, word)| {
                    (*word == checked.bit).then_some((ordinal, formal))
                })
        })
        .collect::<Vec<_>>();
    let expected_bits = checked
        .bit_occurrences
        .iter()
        .map(|(ordinal, formal)| Ok((unchanged_projection(&projection, *ordinal)?, *formal)))
        .collect::<Result<Vec<_>>>()?;
    let r_field_guards = [
        unchanged_projection(&projection, checked.r_field_guards[0])?,
        unchanged_projection(&projection, checked.r_field_guards[1])?,
    ];
    require(
        checked.bit == 7476
            && actual_bits == expected_bits
            && actual_bits == [(3413, 0), (3415, 0), (3416, 0), (3417, 0), (3418, 0)]
            && r_field_guards == [3455, 3456],
        "actual grouped bit and R canonical occurrences",
    )?;
    let maps = json!({"schema":"bitvm2-nova-grouped-conditional-point-maps/v1",
        "compiler":"grouped-convolution-v1","legacy_reference_sha256":reference.sha256,
        "legacy_source_sha256":checked.source_sha256,"legacy_source_maps_sha256":checked.source_maps_sha256,
        "projection":projection.json(),"complete_add":complete_add,
        "ports":checked.source_maps["ports"],"port_indices":checked.source_maps["port_indices"],
        "selector_constraints":selectors,"selected_bit_occurrences":actual_bits,
        "R_canonical_field_leaves":r_field_guards,"original_field_leaves":original_field_leaves,
        "point_form_ordinal":unchanged_projection(&projection,6123)?,"bit_index":checked.bit_index,
        "coordinate_outputs_are_asserted_ports":true,"all_child_predicates_active":true});
    require(
        raw_maps == &maps,
        "actual grouped conditional source maps independently rebuilt",
    )?;
    let map_bytes = canonical(&maps)?;
    require(
        map_bytes.len() <= 8 << 20,
        "grouped conditional maps unchanged8MiB cap",
    )?;
    let maps_sha = sha(&map_bytes);
    let metadata = json!({"schema":"bitvm2-nova-grouped-conditional-point/v1","compiler":"grouped-convolution-v1",
        "context":spec.context,"field_role":spec.field_role,
        "scalar_field_role":checked.metadata["scalar_field_role"],"curve":checked.metadata["curve"],
        "bit_index":checked.bit_index,"operation_id":spec.operation_id,"program_sha256":program,
        "catalogue_id":catalogue,"program_identity_kind":"GroupedProgram.digest (grouped-convolution/v1)",
        "source_maps_sha256":maps_sha,"legacy_program_sha256":checked.program_sha256,
        "legacy_catalogue_id":checked.catalogue_id,"legacy_source_sha256":checked.source_sha256,
        "legacy_source_maps_sha256":checked.source_maps_sha256,"legacy_reference_sha256":reference.sha256,
        "complete_add_program_sha256":child_program,"complete_add_catalogue_id":child_catalogue,
        "words":7498,"arithmetic_constraints":3420,"canonical_fields":37,"leaves":3457,
        "relation":checked.metadata["relation"],"infinity_relation":checked.metadata["infinity_relation"],
        "scope":"grouped conjunctions preserve one conditional point relation; proof/key origins, scalar multiplication and IPA remain open"});
    let meta_bytes = canonical(&metadata)?;
    require(
        meta_bytes.len() <= 1 << 20,
        "grouped conditional source unchanged1MiB cap",
    )?;
    let mut source = sha256::Hash::engine();
    source.input(DOMAIN);
    source.input(&meta_bytes);
    let projection_sha256 = hash(&projection.json())?;
    let grouping = json!({"compiler":"grouped-convolution-v1","legacy_reference_sha256":reference.sha256,
        "projection_sha256":projection_sha256});
    Ok(CheckedPoint {
        bit_index: checked.bit_index,
        source_maps: maps,
        metadata,
        source_sha256: hex::encode(sha256::Hash::from_engine(source)),
        source_maps_sha256: maps_sha,
        program_sha256: program,
        catalogue_id: catalogue,
        child_program_sha256: child_program,
        child_catalogue_id: child_catalogue,
        child_word_map: (0..CHILD_WORDS).collect(),
        child_leaf_map,
        a: checked.a.clone(),
        p: checked.p.clone(),
        e: checked.e.clone(),
        r: checked.r.clone(),
        bit: checked.bit,
        delta: checked.delta,
        masked: checked.masked,
        bit_occurrences: actual_bits,
        r_field_guards,
        fields: checked.fields.clone(),
        projection,
        projection_sha256,
        reference_sha256: reference.sha256.clone(),
        grouping,
    })
}
/// Every old row is evaluated even after a previous false row. Aborts remain
/// None and cannot be reinterpreted as a successful disproof.
pub fn truth_all(
    spec: &GraphSpec,
    values: &[u32],
    reference: &Reference,
    checked: &CheckedPoint,
) -> Result<Vec<Option<bool>>> {
    require(
        spec.program_sha256 == checked.program_sha256
            && values.len() == WORDS
            && spec.words.len() == WORDS
            && spec.leaves.len() == LEAVES
            && reference.sha256 == checked.reference_sha256
            && hex::encode(spec.identity()?) == checked.catalogue_id,
        "admitted grouped truth source identity",
    )?;
    let old = (0..reference.spec.leaves.len())
        .map(|i| conditional_point::truth(&reference.spec, values, i))
        .collect::<Result<Vec<_>>>()?;
    checked
        .projection
        .new_to_old
        .iter()
        .map(|rows| {
            require(!rows.is_empty(), "nonempty projected predicate")?;
            if rows.len() == 1 {
                return Ok(old[rows[0]]);
            }
            let mut all = true;
            for index in rows {
                // Independently admitted legacy grouped rows are precisely conv_ab.
                require(
                    reference.spec.leaves[*index].kind == "conv_ab",
                    "grouped truth only old AB rows",
                )?;
                let actual = old[*index].ok_or("closed AB row unexpectedly aborts")?;
                all &= actual;
            }
            Ok(Some(all))
        })
        .collect()
}
pub fn truth(
    spec: &GraphSpec,
    values: &[u32],
    ordinal: usize,
    reference: &Reference,
    checked: &CheckedPoint,
) -> Result<Option<bool>> {
    truth_all(spec, values, reference, checked)?
        .get(ordinal)
        .copied()
        .ok_or_else(|| "grouped truth ordinal".into())
}
pub fn checked_curve(reference: &Reference, values: &[u32]) -> Result<CurveVerdict> {
    conditional_point::checked_curve(&reference.spec, values)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn closed_group_partition_covers_every_cell_once() {
        let groups = groups().unwrap();
        assert_eq!(groups.len(), 72);
        let flat = groups
            .iter()
            .flat_map(|g| g.iter().map(|c| (c.column, c.block)))
            .collect::<Vec<_>>();
        assert_eq!(flat.len(), 280);
        assert_eq!(flat.iter().collect::<HashSet<_>>().len(), 280);
        assert_eq!(
            groups
                .iter()
                .flatten()
                .map(|c| c.pairs.len())
                .sum::<usize>(),
            1024
        );
    }
    #[test]
    fn formal_alias_identity_is_global_number_independent() {
        assert_eq!(aliases(&[7, 7, 9]), [0, 0, 1]);
        assert_eq!(aliases(&[7, 7, 9]), aliases(&[13, 13, 2]));
        assert_ne!(aliases(&[7, 7, 9]), aliases(&[7, 9, 9]));
    }
    #[test]
    fn canonical_grouped_metadata_is_sorted_and_integer_only() {
        assert_eq!(
            canonical(&json!({"z":[1,0],"a":"test"})).unwrap(),
            br#"{"a":"test","z":[1,0]}"#
        );
        assert!(canonical(&json!({"a":1.25})).is_err());
        assert!(canonical(&json!({"a":"\u{00e9}"})).is_err());
    }
}
