//! Offline hierarchical membership over live, locally constructed commitments.
//!
//! No root/JSON receipt constructor exists. Components have already compiled
//! every actual registry Script through TaprootCommitment's unchanged local
//! limits. This layer combines raw Merkle roots, retaining one selected Script.
//! It does not establish global wire links, signatures, assertion UTXOs or a
//! Bitcoin transaction graph. NUMS retains its unknown-discrete-log assumption.
use crate::{
    registry::Registry,
    taproot_commitment::{
        nums_internal_key, TaprootCommitment, MAX_COMPILED_SCRIPT_BYTES as LOCAL_SCRIPT_CAP,
        MAX_LEAVES, NUMS_INTERNAL_KEY_HEX, TREE_SCHEDULE,
    },
    wots::Result,
};
use bitcoin::{
    hashes::{sha256, Hash},
    secp256k1::{self, Parity, Scalar, Secp256k1, XOnlyPublicKey},
    taproot::{
        ControlBlock, LeafVersion, NodeInfo, TapNodeHash, TapTweakHash, TaprootBuilder,
        TaprootSpendInfo,
    },
    Script, ScriptBuf,
};
use serde_json::{json, Map, Value};
use std::collections::HashSet;

pub const MAX_COMPONENTS: usize = 16;
pub const MAX_GLOBAL_SCRIPT_BYTES: u64 = 5 << 28;
pub const MAX_GLOBAL_DEPTH: usize = 19;
pub const MANIFEST_SCHEMA: &str = "bitvm2-nova-taproot-forest-components/v1";
const MAX_SCRIPT_BYTES: usize = 100_000;

#[derive(Clone)]
struct Component {
    id: [u8; 32],
    registry_id: [u8; 32],
    root: TapNodeHash,
    output: XOnlyPublicKey,
    leaves: usize,
    bytes: u64,
    stream: [u8; 32],
}
impl Component {
    fn live(value: &TaprootCommitment) -> Self {
        Self {
            id: value.catalogue_id(),
            registry_id: value.registry_id(),
            root: value.merkle_root(),
            output: value.output_key(),
            leaves: value.leaf_count(),
            bytes: value.compiled_script_bytes(),
            stream: value.compiled_stream_sha256(),
        }
    }
}
fn depth(count: usize, index: usize, cap: usize) -> Result<usize> {
    if count == 0 || count > cap || index >= count {
        return Err("forest component/leaf count or index out of bounds".into());
    }
    let height = count.ilog2();
    let base = 1usize.checked_shl(height).ok_or("forest depth overflow")?;
    let deep = count
        .checked_sub(base)
        .and_then(|n| n.checked_mul(2))
        .ok_or("forest depth overflow")?;
    Ok(usize::try_from(height)? + usize::from(index < deep))
}
fn checked_sum(total: u64, bytes: u64) -> Result<u64> {
    let sum = total
        .checked_add(bytes)
        .ok_or("forest Script byte total overflow")?;
    if sum > MAX_GLOBAL_SCRIPT_BYTES {
        return Err("forest exceeds explicit 1.25 GiB global Script budget".into());
    }
    Ok(sum)
}
fn validate_components(components: &[Component]) -> Result<(u64, u64)> {
    if !(1..=MAX_COMPONENTS).contains(&components.len()) {
        return Err("forest requires one through sixteen live components".into());
    }
    let (mut ids, mut registries, mut roots) = (HashSet::new(), HashSet::new(), HashSet::new());
    let (mut leaves, mut bytes) = (0u64, 0u64);
    for component in components {
        if !(1..=MAX_LEAVES).contains(&component.leaves)
            || component.bytes == 0
            || component.bytes > LOCAL_SCRIPT_CAP
        {
            return Err("forest component violates unchanged local limits".into());
        }
        if !ids.insert(component.id)
            || !registries.insert(component.registry_id)
            || !roots.insert(component.root)
        {
            return Err("duplicate component ID, registry ID or raw Merkle root".into());
        }
        leaves = leaves
            .checked_add(u64::try_from(component.leaves)?)
            .ok_or("forest leaf census overflow")?;
        bytes = checked_sum(bytes, component.bytes)?;
    }
    Ok((leaves, bytes))
}
fn scalar(bytes: [u8; 32]) -> Result<Scalar> {
    Scalar::from_be_bytes(bytes).map_err(|_| "forest tweak outside secp256k1 scalar range".into())
}
fn checked_output<C: secp256k1::Verification>(
    secp: &Secp256k1<C>,
    root: TapNodeHash,
) -> Result<(XOnlyPublicKey, Parity)> {
    let internal = nums_internal_key()?;
    let tweak = scalar(TapTweakHash::from_key_and_tweak(internal, Some(root)).to_byte_array())?;
    internal
        .add_tweak(secp, &tweak)
        .map_err(|_| "forest tweak produces invalid output point".into())
}
fn encode(control: &ControlBlock) -> Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(control.size());
    control.encode(&mut bytes)?;
    Ok(bytes)
}
fn fold(script: &Script, siblings: &[TapNodeHash]) -> TapNodeHash {
    siblings.iter().fold(
        TapNodeHash::from_script(script, LeafVersion::TapScript),
        |root, sibling| TapNodeHash::from_node_hashes(root, *sibling),
    )
}
fn selected_node(component: &TaprootCommitment) -> Result<NodeInfo> {
    let expected_depth = depth(
        component.leaf_count(),
        component.selected_ordinal(),
        MAX_LEAVES,
    )?;
    let script = component.selected_script();
    let bytes = component.control_block_bytes();
    if script.is_empty()
        || script.len() > MAX_SCRIPT_BYTES
        || bytes.len() != 33 + 32 * expected_depth
    {
        return Err("live local opening size/depth mismatch".into());
    }
    let control = ControlBlock::decode(&bytes)?;
    if control != *component.control_block()
        || control.leaf_version != LeafVersion::TapScript
        || control.internal_key != nums_internal_key()?
        || encode(&control)? != bytes
    {
        return Err("live local opening violates canonical NUMS/TapScript policy".into());
    }
    let root = fold(script, control.merkle_branch.as_slice());
    let secp = Secp256k1::verification_only();
    let (output, parity) = checked_output(&secp, root)?;
    if root != component.merkle_root()
        || output != component.output_key()
        || parity != control.output_key_parity
    {
        return Err("live local root/output/parity mismatch".into());
    }
    if !control.verify_taproot_commitment(&secp, output, script) {
        return Err("mature local commitment verification rejected live component".into());
    }
    // Reconstruct the genuine subtree, not a TapLeaf wrapping a root receipt.
    let mut node = NodeInfo::new_leaf_with_ver(script.to_owned(), LeafVersion::TapScript);
    for sibling in &control.merkle_branch {
        node = NodeInfo::combine(node, NodeInfo::new_hidden_node(*sibling))?;
    }
    if node.node_hash() != root || node.leaf_nodes().len() != 1 {
        return Err("selected local subtree reconstruction mismatch".into());
    }
    Ok(node)
}
fn combine(
    components: &[Component],
    offset: usize,
    selected: usize,
    node: &mut Option<NodeInfo>,
) -> Result<NodeInfo> {
    if components.len() == 1 {
        return if offset == selected {
            node.take()
                .ok_or_else(|| "selected component consumed twice".into())
        } else {
            Ok(NodeInfo::new_hidden_node(components[0].root))
        };
    }
    let base = 1usize
        .checked_shl(components.len().ilog2())
        .ok_or("forest split overflow")?;
    let half = base / 2;
    let left = half
        .checked_add((components.len() - base).min(half))
        .ok_or("forest split overflow")?;
    if left == 0 || left >= components.len() {
        return Err("forest split does not form a full binary tree".into());
    }
    Ok(NodeInfo::combine(
        combine(&components[..left], offset, selected, node)?,
        combine(&components[left..], offset + left, selected, node)?,
    )?)
}
fn roots_only(components: &[Component]) -> Result<TapNodeHash> {
    let mut builder = TaprootBuilder::with_capacity(5);
    for (index, component) in components.iter().enumerate() {
        builder = builder.add_hidden_node(
            u8::try_from(depth(components.len(), index, MAX_COMPONENTS)?)?,
            component.root,
        )?;
    }
    if !builder.is_finalizable() {
        return Err("incomplete forest root tree".into());
    }
    Ok(builder
        .try_into_node_info()
        .map_err(|_| "forest roots did not finalize")?
        .node_hash())
}
fn manifest(components: &[Component], leaves: u64, bytes: u64) -> Value {
    let records: Vec<_> = components.iter().enumerate().map(|(index, component)| json!({
        "index":index,"component_id":hex::encode(component.id),"registry_id":hex::encode(component.registry_id),
        "merkle_root":hex::encode(component.root.to_byte_array()),"output_key":hex::encode(component.output.serialize()),
        "leaf_count":component.leaves,"compiled_script_bytes":component.bytes,
        "compiled_stream_sha256":hex::encode(component.stream)})).collect();
    json!({"schema":MANIFEST_SCHEMA,"tree_schedule":TREE_SCHEDULE,
        "nums_internal_key_hex":NUMS_INTERNAL_KEY_HEX,"component_count":components.len(),
        "total_leaves":leaves,"compiled_script_bytes":bytes,"components":records})
}
fn canonical(value: &Value) -> Result<Vec<u8>> {
    fn sorted(value: &Value, depth: usize) -> Result<Value> {
        if depth > 8 {
            return Err("forest manifest JSON depth".into());
        }
        match value {
            Value::Object(object) => {
                let mut entries: Vec<_> = object.iter().collect();
                entries.sort_by(|a, b| a.0.cmp(b.0));
                let mut result = Map::new();
                for (key, value) in entries {
                    if !key.is_ascii() {
                        return Err("forest manifest non-ASCII key".into());
                    }
                    result.insert(key.clone(), sorted(value, depth + 1)?);
                }
                Ok(Value::Object(result))
            }
            Value::Array(values) => Ok(Value::Array(
                values
                    .iter()
                    .map(|v| sorted(v, depth + 1))
                    .collect::<Result<_>>()?,
            )),
            Value::String(s) if s.is_ascii() => Ok(value.clone()),
            Value::Number(n) if n.as_u64().is_some() => Ok(value.clone()),
            _ => Err("unsupported forest manifest value".into()),
        }
    }
    let bytes = serde_json::to_vec(&sorted(value, 0)?)?;
    if bytes.len() > 32768 {
        return Err("forest manifest exceeds 32 KiB".into());
    }
    Ok(bytes)
}

/// Immutable offline membership object. No Deserialize or raw-root constructor.
pub struct TaprootForest {
    components: Vec<Component>,
    manifest: Value,
    manifest_sha256: [u8; 32],
    leaves: u64,
    bytes: u64,
    selected_component: usize,
    selected_ordinal: usize,
    selected_script: ScriptBuf,
    control: ControlBlock,
    control_bytes: Vec<u8>,
    root: TapNodeHash,
    output: XOnlyPublicKey,
}
impl TaprootForest {
    pub fn new(live: &[TaprootCommitment], selected_component: usize) -> Result<Self> {
        // Do not allocate a selected Script or subtree before limits/duplicates.
        if !(1..=MAX_COMPONENTS).contains(&live.len()) || selected_component >= live.len() {
            return Err("forest requires 1..16 live components and a valid selection".into());
        }
        let components: Vec<_> = live.iter().map(Component::live).collect();
        let (leaves, bytes) = validate_components(&components)?;
        let selected = &live[selected_component];
        let expected_depth = depth(components.len(), selected_component, MAX_COMPONENTS)?
            .checked_add(depth(
                selected.leaf_count(),
                selected.selected_ordinal(),
                MAX_LEAVES,
            )?)
            .ok_or("forest total depth overflow")?;
        if expected_depth > MAX_GLOBAL_DEPTH {
            return Err("forest depth exceeds 19".into());
        }
        let mut selected = Some(selected_node(selected)?);
        let node = combine(&components, 0, selected_component, &mut selected)?;
        if selected.is_some() || node.leaf_nodes().len() != 1 {
            return Err("forest retained an unexpected selected subtree".into());
        }
        let root = node.node_hash();
        if root != roots_only(&components)? {
            return Err("forest combination/depth schedule mismatch".into());
        }
        let secp = Secp256k1::verification_only();
        let (output, parity) = checked_output(&secp, root)?;
        let info = TaprootSpendInfo::from_node_info(&secp, nums_internal_key()?, node);
        if info.merkle_root() != Some(root)
            || XOnlyPublicKey::from(info.output_key()) != output
            || info.output_key_parity() != parity
            || info.script_map().len() != 1
        {
            return Err("mature forest output differs from preflight".into());
        }
        let (script_version, _) = info
            .script_map()
            .iter()
            .next()
            .ok_or("missing forest selected Script")?;
        let control = info
            .control_block(script_version)
            .ok_or("missing forest control block")?;
        if control.merkle_branch.len() != expected_depth {
            return Err("forest control depth mismatch".into());
        }
        let selected_script = script_version.0.clone();
        let control_bytes = encode(&control)?;
        let manifest = manifest(&components, leaves, bytes);
        let manifest_sha256 = sha256::Hash::hash(&canonical(&manifest)?).to_byte_array();
        Ok(Self {
            components,
            manifest,
            manifest_sha256,
            leaves,
            bytes,
            selected_component,
            selected_ordinal: live[selected_component].selected_ordinal(),
            selected_script,
            control,
            control_bytes,
            root,
            output,
        })
    }
    pub fn component_count(&self) -> usize {
        self.components.len()
    }
    pub fn component_manifest_sha256(&self) -> [u8; 32] {
        self.manifest_sha256
    }
    pub fn manifest(&self) -> Value {
        self.manifest.clone()
    }
    pub fn selected_component(&self) -> usize {
        self.selected_component
    }
    pub fn selected_ordinal(&self) -> usize {
        self.selected_ordinal
    }
    pub fn leaf_count(&self) -> u64 {
        self.leaves
    }
    pub fn compiled_script_bytes(&self) -> u64 {
        self.bytes
    }
    pub fn selected_script(&self) -> &Script {
        self.selected_script.as_script()
    }
    pub fn control_block(&self) -> &ControlBlock {
        &self.control
    }
    pub fn control_block_bytes(&self) -> Vec<u8> {
        self.control_bytes.clone()
    }
    pub fn merkle_root(&self) -> TapNodeHash {
        self.root
    }
    pub fn output_key(&self) -> XOnlyPublicKey {
        self.output
    }

    /// Expected digest/root/output/selection come from the caller's authenticated
    /// configuration, not an opening or a self-reported success receipt.
    pub fn verify_member(
        &self,
        registry: &Registry,
        expected_manifest: [u8; 32],
        expected_root: TapNodeHash,
        expected_output: XOnlyPublicKey,
        component_index: usize,
        ordinal: usize,
    ) -> Result<()> {
        if encode(&self.control)? != self.control_bytes {
            return Err("forest stored control encoding mismatch".into());
        }
        self.verify_opening(
            registry,
            expected_manifest,
            expected_root,
            expected_output,
            component_index,
            ordinal,
            &self.selected_script,
            &self.control_bytes,
        )
    }
    /// Verify external opening bytes against this live-component collection and
    /// independently expected identities. The unchanged local API stays strict.
    pub fn verify_opening(
        &self,
        registry: &Registry,
        expected_manifest: [u8; 32],
        expected_root: TapNodeHash,
        expected_output: XOnlyPublicKey,
        component_index: usize,
        ordinal: usize,
        script: &Script,
        control_bytes: &[u8],
    ) -> Result<()> {
        let (leaves, bytes) = validate_components(&self.components)?;
        let actual_manifest = manifest(&self.components, leaves, bytes);
        if actual_manifest != self.manifest
            || sha256::Hash::hash(&canonical(&actual_manifest)?).to_byte_array()
                != expected_manifest
            || self.manifest_sha256 != expected_manifest
            || self.root != expected_root
            || self.output != expected_output
            || leaves != self.leaves
            || bytes != self.bytes
            || component_index != self.selected_component
            || ordinal != self.selected_ordinal
            || component_index >= self.components.len()
        {
            return Err(
                "forest manifest/root/output/selection differs from external expectation".into(),
            );
        }
        let component = &self.components[component_index];
        if registry.identity() != component.registry_id
            || registry.spec().identity()? != component.id
            || registry.spec().leaves.len() != component.leaves
        {
            return Err(
                "forest selected registry/catalogue differs from component manifest".into(),
            );
        }
        let local_depth = depth(component.leaves, ordinal, MAX_LEAVES)?;
        let total_depth =
            local_depth + depth(self.components.len(), component_index, MAX_COMPONENTS)?;
        if total_depth > MAX_GLOBAL_DEPTH
            || control_bytes.len() != 33 + 32 * total_depth
            || script.is_empty()
            || script.len() > MAX_SCRIPT_BYTES
        {
            return Err("forest opening size/depth exceeds exact policy".into());
        }
        if registry.script(ordinal, true)?.as_bytes() != script.as_bytes() {
            return Err("forest opening is not exact recompiled selected Script".into());
        }
        let control = ControlBlock::decode(control_bytes)?;
        if control.leaf_version != LeafVersion::TapScript
            || control.internal_key != nums_internal_key()?
            || control.merkle_branch.len() != total_depth
            || encode(&control)? != control_bytes
        {
            return Err("forest opening violates canonical NUMS/TapScript policy".into());
        }
        let local_root = fold(script, &control.merkle_branch.as_slice()[..local_depth]);
        if local_root != component.root {
            return Err("forest opening local root mismatch".into());
        }
        let global_root = control.merkle_branch.as_slice()[local_depth..]
            .iter()
            .fold(local_root, |root, sibling| {
                TapNodeHash::from_node_hashes(root, *sibling)
            });
        if global_root != expected_root || roots_only(&self.components)? != expected_root {
            return Err("forest opening global root/topology mismatch".into());
        }
        let secp = Secp256k1::verification_only();
        if checked_output(&secp, local_root)?.0 != component.output {
            return Err("forest local output does not match component root".into());
        }
        let (output, parity) = checked_output(&secp, global_root)?;
        if output != expected_output || control.output_key_parity != parity {
            return Err("forest global output key/parity mismatch".into());
        }
        if !control.verify_taproot_commitment(&secp, expected_output, script) {
            return Err("mature forest commitment verification rejected opening".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        registry::{GraphSpec, Leaf, Word},
        wots::PublicKey,
    };
    use bitvm::signatures::{Wots, Wots4};
    use std::collections::BTreeMap;
    fn registry(n: usize, context: u8, key: u8) -> Registry {
        let body = sha256::Hash::hash(&[0x51]).to_string();
        let spec = GraphSpec {
            program_sha256: "05".repeat(32),
            context: format!("{context:02x}").repeat(32),
            field_role: "pallas_base".into(),
            operation_id: "test/taproot-forest".into(),
            words: vec![Word {
                name: "public-fixture".into(),
                bound: 2,
            }],
            leaves: (0..n)
                .map(|_| Leaf {
                    kind: "const".into(),
                    argument: vec![0],
                    wires: vec![0],
                    body_sha256: body.clone(),
                })
                .collect(),
            bodies: BTreeMap::from([(body, "51".into())]),
        };
        let key: PublicKey = vec![[key; 20]; Wots4::TOTAL_DIGIT_LEN as usize]
            .try_into()
            .unwrap();
        let keys = vec![key];
        let catalogue = spec.identity().unwrap();
        let id = spec.key_identity(&keys).unwrap();
        Registry::new(spec, keys, catalogue, id).unwrap()
    }
    fn live(registries: &[Registry]) -> Vec<TaprootCommitment> {
        registries
            .iter()
            .enumerate()
            .map(|(i, registry)| {
                TaprootCommitment::new(registry, i % registry.spec().leaves.len()).unwrap()
            })
            .collect()
    }
    fn ordinary(registries: &[Registry]) -> TaprootSpendInfo {
        let mut builder = TaprootBuilder::new();
        for (index, registry) in registries.iter().enumerate() {
            for ordinal in 0..registry.spec().leaves.len() {
                let d = depth(registries.len(), index, MAX_COMPONENTS).unwrap()
                    + depth(registry.spec().leaves.len(), ordinal, MAX_LEAVES).unwrap();
                builder = builder
                    .add_leaf(d as u8, registry.script(ordinal, true).unwrap())
                    .unwrap();
            }
        }
        let node = builder.try_into_node_info().unwrap();
        let secp = Secp256k1::verification_only();
        checked_output(&secp, node.node_hash()).unwrap();
        TaprootSpendInfo::from_node_info(&secp, nums_internal_key().unwrap(), node)
    }
    #[test]
    fn every_selected_component_matches_ordinary_hierarchical_all_script_tree() {
        for count in 1..=16 {
            let registries: Vec<_> = (0..count)
                .map(|i| registry(1 + i % 5, i as u8, 11))
                .collect();
            let components = live(&registries);
            let reference = ordinary(&registries);
            let mut pin = None;
            for selected in 0..count {
                let forest = TaprootForest::new(&components, selected).unwrap();
                assert_eq!(Some(forest.merkle_root()), reference.merkle_root());
                assert_eq!(
                    forest.output_key(),
                    XOnlyPublicKey::from(reference.output_key())
                );
                let ordinal = components[selected].selected_ordinal();
                let pair = (
                    registries[selected].script(ordinal, true).unwrap(),
                    LeafVersion::TapScript,
                );
                assert_eq!(
                    forest.control_block_bytes(),
                    reference.control_block(&pair).unwrap().serialize()
                );
                forest
                    .verify_member(
                        &registries[selected],
                        forest.component_manifest_sha256(),
                        forest.merkle_root(),
                        forest.output_key(),
                        selected,
                        ordinal,
                    )
                    .unwrap();
                if let Some(expected) = pin {
                    assert_eq!(forest.component_manifest_sha256(), expected);
                } else {
                    pin = Some(forest.component_manifest_sha256());
                }
            }
        }
    }
    #[test]
    fn external_opening_manifest_selection_and_root_mutations_reject() {
        let registries = vec![registry(3, 0, 11), registry(4, 1, 12), registry(2, 2, 13)];
        let components = live(&registries);
        let forest = TaprootForest::new(&components, 0).unwrap();
        let digest = forest.component_manifest_sha256();
        let root = forest.merkle_root();
        let output = forest.output_key();
        let script = forest.selected_script();
        let control = forest.control_block_bytes();
        let check = |script: &Script, bytes: &[u8]| {
            forest.verify_opening(&registries[0], digest, root, output, 0, 0, script, bytes)
        };
        let mut bad_script = script.as_bytes().to_vec();
        bad_script[1] ^= 1;
        assert!(check(Script::from_bytes(&bad_script), &control).is_err());
        for position in [0, 33, control.len() - 1] {
            let mut bad = control.clone();
            bad[position] ^= 1;
            assert!(check(script, &bad).is_err());
        }
        let mut version = control.clone();
        version[0] = (version[0] & 1) | 0xc2;
        assert!(check(script, &version).is_err());
        let public = XOnlyPublicKey::from_slice(
            &hex::decode("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
                .unwrap(),
        )
        .unwrap();
        let mut internal = control.clone();
        internal[1..33].copy_from_slice(&public.serialize());
        assert!(check(script, &internal).is_err());
        assert!(check(script, &control[..control.len() - 1]).is_err());
        let mut extra = control.clone();
        extra.extend([0; 32]);
        assert!(check(script, &extra).is_err());
        let mut wrong = digest;
        wrong[0] ^= 1;
        for (pin, r, key, index, ordinal) in [
            (wrong, root, output, 0, 0),
            (digest, TapNodeHash::from_byte_array([7; 32]), output, 0, 0),
            (digest, root, public, 0, 0),
            (digest, root, output, 1, 0),
            (digest, root, output, 0, 1),
            (digest, root, output, usize::MAX, 0),
        ] {
            assert!(forest
                .verify_member(&registries[0], pin, r, key, index, ordinal)
                .is_err());
        }
        assert!(forest
            .verify_member(&registries[1], digest, root, output, 0, 0)
            .is_err());
        // A global branch must not weaken the unchanged strict LOCAL verifier.
        assert!(crate::taproot_commitment::verify_opening(
            &registries[0],
            root,
            output,
            0,
            script,
            &control
        )
        .is_err());
    }
    #[test]
    fn ordered_manifest_disambiguates_sorted_sibling_root_symmetry() {
        let registries = vec![registry(2, 1, 11), registry(2, 2, 12)];
        let mut components = live(&registries);
        let first = TaprootForest::new(&components, 0).unwrap();
        components.swap(0, 1);
        let second = TaprootForest::new(&components, 1).unwrap();
        assert_eq!(first.merkle_root(), second.merkle_root());
        assert_eq!(first.output_key(), second.output_key());
        assert_ne!(
            first.component_manifest_sha256(),
            second.component_manifest_sha256()
        );
        assert!(second
            .verify_member(
                &registries[0],
                first.component_manifest_sha256(),
                first.merkle_root(),
                first.output_key(),
                1,
                0
            )
            .is_err());
    }
    #[test]
    fn duplicate_id_registry_root_limits_and_budget_overflow_fail_without_big_graphs() {
        let registries: Vec<_> = (0..6).map(|i| registry(1, i, 11)).collect();
        let components = live(&registries);
        assert!(TaprootForest::new(&[], 0).is_err());
        assert!(TaprootForest::new(&components, 6).is_err());
        let duplicate = vec![
            TaprootCommitment::new(&registries[0], 0).unwrap(),
            TaprootCommitment::new(&registries[0], 0).unwrap(),
        ];
        assert!(TaprootForest::new(&duplicate, 0).is_err());
        let mut metadata: Vec<_> = components.iter().map(Component::live).collect();
        for mode in 0..3 {
            let mut bad = metadata.clone();
            match mode {
                0 => bad[1].id = bad[0].id,
                1 => bad[1].registry_id = bad[0].registry_id,
                _ => bad[1].root = bad[0].root,
            };
            assert!(validate_components(&bad).is_err());
        }
        // TEST ONLY census mutation exercises arithmetic guards, never a public
        // raw-record/receipt constructor and never a claimed measured payload.
        for record in &mut metadata {
            record.bytes = LOCAL_SCRIPT_CAP;
        }
        assert_eq!(
            validate_components(&metadata[..5]).unwrap().1,
            MAX_GLOBAL_SCRIPT_BYTES
        );
        assert!(validate_components(&metadata).is_err());
        metadata[0].bytes = LOCAL_SCRIPT_CAP + 1;
        assert!(validate_components(&metadata[..1]).is_err());
        assert!(checked_sum(u64::MAX, 1).is_err());
        assert!(depth(17, 0, MAX_COMPONENTS).is_err());
        assert_eq!(
            depth(16, 0, MAX_COMPONENTS).unwrap() + depth(30_000, 0, MAX_LEAVES).unwrap(),
            MAX_GLOBAL_DEPTH
        );
    }
    #[test]
    fn fallible_tweak_policy_and_canonical_manifest_have_no_panic_as_rejection() {
        // There is deliberately no catch_unwind: any panic fails this oracle.
        assert!(scalar([0xff; 32]).is_err());
        assert_eq!(
            hex::encode(
                sha256::Hash::hash(&canonical(&json!({"z":2,"a":{"x":[1,"00"]}})).unwrap())
                    .to_byte_array()
            ),
            "63fee996985eddf1154dd76942ebe09225110f233b9bf2417e0259080b161a53"
        );
        assert!(canonical(&json!({"x":true})).is_err());
    }
}
