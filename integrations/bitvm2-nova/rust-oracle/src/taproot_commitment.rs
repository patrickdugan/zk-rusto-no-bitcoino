//! Offline commitment to every actual immutable-registry disproof Script.
//!
//! This proves selected Script membership only. It creates no transaction,
//! signature, secret key or assertion UTXO binding. Expected registry identities,
//! root and output key must be independently owned by the verifier.
use crate::{registry::Registry, wots::Result};
use bitcoin::{
    hashes::{sha256, Hash, HashEngine},
    secp256k1::{self, Parity, Scalar, Secp256k1, XOnlyPublicKey},
    taproot::{
        ControlBlock, LeafVersion, TapNodeHash, TapTweakHash, TaprootBuilder, TaprootSpendInfo,
    },
    Script, ScriptBuf,
};

pub const MAX_LEAVES: usize = 30_000;
pub const MAX_COMPILED_SCRIPT_BYTES: u64 = 256 << 20;
pub const TREE_SCHEDULE: &str = "complete-left-filled-dfs/v1";
/// BIP341: SHA256 of the standard uncompressed secp256k1 generator encoding.
/// This public NUMS point has no known discrete logarithm; no secret is created.
pub const NUMS_INTERNAL_KEY_HEX: &str =
    "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";
const MAX_SCRIPT_BYTES: usize = 100_000;

pub fn nums_internal_key() -> Result<XOnlyPublicKey> {
    Ok(XOnlyPublicKey::from_slice(&hex::decode(
        NUMS_INTERNAL_KEY_HEX,
    )?)?)
}

fn depth(leaf_count: usize, ordinal: usize) -> Result<u8> {
    if !(1..=MAX_LEAVES).contains(&leaf_count) || ordinal >= leaf_count {
        return Err("invalid Taproot catalogue size or leaf ordinal".into());
    }
    let height = leaf_count.ilog2();
    let base = 1usize
        .checked_shl(height)
        .ok_or("Taproot schedule overflow")?;
    let deep_leaves = leaf_count
        .checked_sub(base)
        .and_then(|extra| extra.checked_mul(2))
        .ok_or("Taproot schedule overflow")?;
    Ok(u8::try_from(height + u32::from(ordinal < deep_leaves))?)
}
fn script_budget(total: u64, length: usize) -> Result<u64> {
    if length == 0 || length > MAX_SCRIPT_BYTES {
        return Err("compiled Taproot Script exceeds registry leaf bound".into());
    }
    let total = total
        .checked_add(u64::try_from(length)?)
        .ok_or("compiled Taproot Script byte total overflow")?;
    if total > MAX_COMPILED_SCRIPT_BYTES {
        return Err("compiled Taproot Scripts exceed 256 MiB cap".into());
    }
    Ok(total)
}
fn scalar(bytes: [u8; 32]) -> Result<Scalar> {
    Scalar::from_be_bytes(bytes)
        .map_err(|_| "Taproot tweak is outside secp256k1 scalar range".into())
}
fn checked_output<C: secp256k1::Verification>(
    secp: &Secp256k1<C>,
    internal_key: XOnlyPublicKey,
    root: TapNodeHash,
) -> Result<(XOnlyPublicKey, Parity)> {
    // The mature convenience APIs call expect for an out-of-range tweak or
    // invalid output point. Check those exact inputs fallibly before calling
    // them; never catch a panic and classify it as successful rejection.
    let tweak = scalar(TapTweakHash::from_key_and_tweak(internal_key, Some(root)).to_byte_array())?;
    internal_key
        .add_tweak(secp, &tweak)
        .map_err(|_| "Taproot tweak produces an invalid output point".into())
}
fn encode_control(control: &ControlBlock) -> Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(control.size());
    control.encode(&mut bytes)?;
    Ok(bytes)
}

/// An immutable offline commitment plus one selected Script/control proof.
pub struct TaprootCommitment {
    registry_id: [u8; 32],
    catalogue_id: [u8; 32],
    selected_ordinal: usize,
    leaf_count: usize,
    compiled_script_bytes: u64,
    compiled_stream_sha256: [u8; 32],
    selected_script: ScriptBuf,
    control_block: ControlBlock,
    control_bytes: Vec<u8>,
    root: TapNodeHash,
    output_key: XOnlyPublicKey,
}

impl TaprootCommitment {
    pub fn new(registry: &Registry, selected_ordinal: usize) -> Result<Self> {
        let leaf_count = registry.spec().leaves.len();
        depth(leaf_count, selected_ordinal)?;
        let catalogue_id = registry.spec().identity()?;
        let mut builder = TaprootBuilder::with_capacity(16);
        let mut compiled_script_bytes = 0u64;
        let mut stream = sha256::Hash::engine();
        for ordinal in 0..leaf_count {
            // Compile EVERY exact disproof Script. Hidden nodes are hashes of
            // these actual bytes, never caller-supplied or synthetic hashes.
            let script = registry.script(ordinal, true)?;
            compiled_script_bytes = script_budget(compiled_script_bytes, script.len())?;
            stream.input(&u32::try_from(script.len())?.to_le_bytes());
            stream.input(script.as_bytes());
            let level = depth(leaf_count, ordinal)?;
            builder = if ordinal == selected_ordinal {
                builder.add_leaf(level, script)?
            } else {
                let hash = TapNodeHash::from_script(&script, LeafVersion::TapScript);
                builder.add_hidden_node(level, hash)?
            };
        }
        if !builder.is_finalizable() {
            return Err("incomplete Taproot catalogue tree".into());
        }
        let node = builder
            .try_into_node_info()
            .map_err(|_| "Taproot tree could not be finalized")?;
        if node.leaf_nodes().len() != 1 {
            return Err("Taproot construction retained an unexpected number of Scripts".into());
        }
        let root = node.node_hash();
        let secp = Secp256k1::verification_only();
        let internal_key = nums_internal_key()?;
        let (output_key, parity) = checked_output(&secp, internal_key, root)?;
        let info = TaprootSpendInfo::from_node_info(&secp, internal_key, node);
        if info.merkle_root() != Some(root)
            || XOnlyPublicKey::from(info.output_key()) != output_key
            || info.output_key_parity() != parity
            || info.script_map().len() != 1
        {
            return Err("mature Taproot result differs from preflight".into());
        }
        let (script_version, _) = info
            .script_map()
            .iter()
            .next()
            .ok_or("missing selected Taproot Script")?;
        let control_block = info
            .control_block(script_version)
            .ok_or("missing selected Taproot control block")?;
        // The public spend-info map is borrowed. Only this selected Script is
        // copied out, then spend-info and its original copy are released.
        let selected_script = script_version.0.clone();
        let control_bytes = encode_control(&control_block)?;
        drop(info);
        let result = Self {
            registry_id: registry.identity(),
            catalogue_id,
            selected_ordinal,
            leaf_count,
            compiled_script_bytes,
            compiled_stream_sha256: sha256::Hash::from_engine(stream).to_byte_array(),
            selected_script,
            control_block,
            control_bytes,
            root,
            output_key,
        };
        result.verify_member(registry, root, output_key, selected_ordinal)?;
        Ok(result)
    }
    pub fn registry_id(&self) -> [u8; 32] {
        self.registry_id
    }
    pub fn catalogue_id(&self) -> [u8; 32] {
        self.catalogue_id
    }
    pub fn selected_ordinal(&self) -> usize {
        self.selected_ordinal
    }
    pub fn leaf_count(&self) -> usize {
        self.leaf_count
    }
    pub fn compiled_script_bytes(&self) -> u64 {
        self.compiled_script_bytes
    }
    pub fn compiled_stream_sha256(&self) -> [u8; 32] {
        self.compiled_stream_sha256
    }
    pub fn selected_script(&self) -> &Script {
        self.selected_script.as_script()
    }
    pub fn control_block(&self) -> &ControlBlock {
        &self.control_block
    }
    pub fn control_block_bytes(&self) -> Vec<u8> {
        self.control_bytes.clone()
    }
    pub fn merkle_root(&self) -> TapNodeHash {
        self.root
    }
    pub fn output_key(&self) -> XOnlyPublicKey {
        self.output_key
    }

    /// Verify against separately supplied expected root/key and admitted registry.
    /// These expected values must not be copied from an untrusted opening.
    pub fn verify_member(
        &self,
        registry: &Registry,
        expected_root: TapNodeHash,
        expected_output_key: XOnlyPublicKey,
        ordinal: usize,
    ) -> Result<()> {
        if ordinal != self.selected_ordinal
            || self.registry_id != registry.identity()
            || self.catalogue_id != registry.spec().identity()?
            || self.leaf_count != registry.spec().leaves.len()
            || self.root != expected_root
            || self.output_key != expected_output_key
            || encode_control(&self.control_block)? != self.control_bytes
        {
            return Err(
                "Taproot commitment identity/selection differs from verifier expectations".into(),
            );
        }
        verify_opening(
            registry,
            expected_root,
            expected_output_key,
            ordinal,
            &self.selected_script,
            &self.control_bytes,
        )
    }
}

/// Verify externally supplied opening bytes, including exact recompiled Script.
/// This proves membership only, not Script execution or assertion UTXO binding.
pub fn verify_opening(
    registry: &Registry,
    expected_root: TapNodeHash,
    expected_output_key: XOnlyPublicKey,
    ordinal: usize,
    script: &Script,
    control_bytes: &[u8],
) -> Result<()> {
    let expected_depth = usize::from(depth(registry.spec().leaves.len(), ordinal)?);
    if control_bytes.len() != 33 + 32 * expected_depth || script.len() > MAX_SCRIPT_BYTES {
        return Err("Taproot opening size/depth differs from catalogue policy".into());
    }
    if registry.script(ordinal, true)?.as_bytes() != script.as_bytes() {
        return Err("Taproot opening is not the exact selected registry disproof Script".into());
    }
    let control = ControlBlock::decode(control_bytes)?;
    let internal_key = nums_internal_key()?;
    if control.leaf_version != LeafVersion::TapScript
        || control.internal_key != internal_key
        || control.merkle_branch.len() != expected_depth
        || encode_control(&control)? != control_bytes
    {
        return Err("Taproot opening violates fixed leaf-version/NUMS/control policy".into());
    }
    let mut root = TapNodeHash::from_script(script, LeafVersion::TapScript);
    for sibling in &control.merkle_branch {
        root = TapNodeHash::from_node_hashes(root, *sibling);
    }
    if root != expected_root {
        return Err("Taproot opening root differs from external expectation".into());
    }
    let secp = Secp256k1::verification_only();
    let (output_key, parity) = checked_output(&secp, internal_key, root)?;
    if output_key != expected_output_key || control.output_key_parity != parity {
        return Err("Taproot opening output key/parity differs from external expectation".into());
    }
    if !control.verify_taproot_commitment(&secp, expected_output_key, script) {
        return Err("mature Taproot commitment verification rejected opening".into());
    }
    Ok(())
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

    // Fixed synthetic PUBLIC bytes only. These admission/commitment tests never
    // create a signing secret or execute their dummy predicate as arithmetic.
    fn registry(n: usize, context: u8) -> Registry {
        let body = sha256::Hash::hash(&[0x51]).to_string();
        let spec = GraphSpec {
            program_sha256: "03".repeat(32),
            context: format!("{context:02x}").repeat(32),
            field_role: "pallas_base".into(),
            operation_id: "test/taproot-membership".into(),
            words: vec![Word {
                name: "public-fixture-word".into(),
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
        admitted(spec)
    }
    fn admitted(spec: GraphSpec) -> Registry {
        let key: PublicKey = vec![[11u8; 20]; Wots4::TOTAL_DIGIT_LEN as usize]
            .try_into()
            .unwrap();
        let keys = vec![key];
        let expected_spec = spec.identity().unwrap();
        let expected_registry = spec.key_identity(&keys).unwrap();
        Registry::new(spec, keys, expected_spec, expected_registry).unwrap()
    }
    fn ordinary(registry: &Registry) -> TaprootSpendInfo {
        let n = registry.spec().leaves.len();
        let mut builder = TaprootBuilder::new();
        for i in 0..n {
            builder = builder
                .add_leaf(depth(n, i).unwrap(), registry.script(i, true).unwrap())
                .unwrap();
        }
        let node = builder.try_into_node_info().unwrap();
        let secp = Secp256k1::verification_only();
        let internal = nums_internal_key().unwrap();
        checked_output(&secp, internal, node.node_hash()).unwrap();
        TaprootSpendInfo::from_node_info(&secp, internal, node)
    }
    #[test]
    fn every_selected_small_tree_matches_ordinary_all_script_builder() {
        for n in 1..=17 {
            let registry = registry(n, 0);
            let reference = ordinary(&registry);
            for selected in 0..n {
                let streamed = TaprootCommitment::new(&registry, selected).unwrap();
                assert_eq!(Some(streamed.merkle_root()), reference.merkle_root());
                assert_eq!(
                    streamed.output_key(),
                    XOnlyPublicKey::from(reference.output_key())
                );
                let pair = (
                    registry.script(selected, true).unwrap(),
                    LeafVersion::TapScript,
                );
                assert_eq!(
                    streamed.control_block_bytes(),
                    reference.control_block(&pair).unwrap().serialize()
                );
                streamed
                    .verify_member(
                        &registry,
                        streamed.merkle_root(),
                        streamed.output_key(),
                        selected,
                    )
                    .unwrap();
                assert_eq!(
                    streamed.control_block().merkle_branch.len(),
                    depth(n, selected).unwrap() as usize
                );
            }
        }
    }
    #[test]
    fn opening_mutations_and_external_root_key_ordinal_expectations_fail() {
        let registry = registry(5, 0);
        let commitment = TaprootCommitment::new(&registry, 0).unwrap();
        let root = commitment.merkle_root();
        let output = commitment.output_key();
        let script = commitment.selected_script();
        let control = commitment.control_block_bytes();
        let check = |script: &Script, bytes: &[u8], ordinal| {
            verify_opening(&registry, root, output, ordinal, script, bytes)
        };
        let mut changed_script = script.as_bytes().to_vec();
        changed_script[1] ^= 1;
        assert!(check(Script::from_bytes(&changed_script), &control, 0).is_err());
        for position in [0, 33, control.len() - 1] {
            let mut changed = control.clone();
            changed[position] ^= 1;
            assert!(check(script, &changed, 0).is_err());
        }
        let mut version = control.clone();
        version[0] = (version[0] & 1) | 0xc2;
        assert!(check(script, &version, 0).is_err());
        let mut internal = control.clone();
        internal[1..33].copy_from_slice(
            &hex::decode("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
                .unwrap(),
        );
        assert!(check(script, &internal, 0).is_err());
        assert!(check(script, &control[..control.len() - 1], 0).is_err());
        let mut surplus = control.clone();
        surplus.extend([0u8; 32]);
        assert!(check(script, &surplus, 0).is_err());
        assert!(check(script, &control, 1).is_err());
        assert!(check(script, &control, usize::MAX).is_err());
        let wrong_root = TapNodeHash::from_byte_array([7; 32]);
        assert!(commitment
            .verify_member(&registry, wrong_root, output, 0)
            .is_err());
        let foreign = XOnlyPublicKey::from_slice(
            &hex::decode("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
                .unwrap(),
        )
        .unwrap();
        assert!(commitment
            .verify_member(&registry, root, foreign, 0)
            .is_err());
    }
    #[test]
    fn context_program_field_and_catalogue_changes_cannot_reuse_opening() {
        let original = registry(3, 0);
        let proof = TaprootCommitment::new(&original, 1).unwrap();
        let mut specs = Vec::new();
        let mut spec = original.spec().clone();
        spec.context = "01".repeat(32);
        specs.push(spec);
        let mut spec = original.spec().clone();
        spec.program_sha256 = "04".repeat(32);
        specs.push(spec);
        let mut spec = original.spec().clone();
        spec.field_role = "vesta_base".into();
        specs.push(spec);
        let mut spec = original.spec().clone();
        spec.leaves[2].argument[0] = 1;
        specs.push(spec);
        for spec in specs {
            let other = admitted(spec);
            assert!(proof
                .verify_member(&other, proof.merkle_root(), proof.output_key(), 1)
                .is_err());
            assert!(verify_opening(
                &other,
                proof.merkle_root(),
                proof.output_key(),
                1,
                proof.selected_script(),
                &proof.control_block_bytes()
            )
            .is_err());
        }
    }
    #[test]
    fn schedule_caps_nums_provenance_and_tweak_errors_are_checked_without_large_work() {
        assert!(depth(0, 0).is_err());
        assert!(depth(MAX_LEAVES + 1, 0).is_err());
        assert!(depth(3, 3).is_err());
        assert_eq!(
            (0..5).map(|i| depth(5, i).unwrap()).collect::<Vec<_>>(),
            vec![3, 3, 2, 2, 2]
        );
        assert_eq!(
            script_budget(MAX_COMPILED_SCRIPT_BYTES - 1, 1).unwrap(),
            MAX_COMPILED_SCRIPT_BYTES
        );
        assert!(script_budget(MAX_COMPILED_SCRIPT_BYTES, 1).is_err());
        assert!(script_budget(u64::MAX, 1).is_err());
        assert!(script_budget(0, MAX_SCRIPT_BYTES + 1).is_err());
        assert!(scalar([0xff; 32]).is_err());
        let generator=hex::decode("0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8").unwrap();
        assert_eq!(
            sha256::Hash::hash(&generator).to_string(),
            NUMS_INTERNAL_KEY_HEX
        );
        let secp = Secp256k1::verification_only();
        let public = XOnlyPublicKey::from_slice(&generator[1..33]).unwrap();
        let negative_one = scalar(
            hex::decode("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140")
                .unwrap()
                .try_into()
                .unwrap(),
        )
        .unwrap();
        assert!(public.add_tweak(&secp, &negative_one).is_err());
    }
    #[test]
    fn sorted_tapbranch_children_are_not_an_order_authentication_claim() {
        let first = TapNodeHash::from_script(Script::from_bytes(&[0x51]), LeafVersion::TapScript);
        let second = TapNodeHash::from_script(Script::from_bytes(&[0x52]), LeafVersion::TapScript);
        assert_eq!(
            TapNodeHash::from_node_hashes(first, second),
            TapNodeHash::from_node_hashes(second, first)
        );
        let registry = registry(2, 0);
        assert_ne!(
            registry.script(0, true).unwrap(),
            registry.script(1, true).unwrap()
        );
    }
}
