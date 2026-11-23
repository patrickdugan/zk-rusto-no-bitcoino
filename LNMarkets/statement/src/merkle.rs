use crate::*;

fn pair_hash(label: &str, left: &Hash, right: &Hash) -> Hash {
    let mut bytes = [0; 64];
    bytes[..32].copy_from_slice(left);
    bytes[32..].copy_from_slice(right);
    tagged_hash(label, &bytes)
}

fn parent_level(label: &str, hashes: &[Hash]) -> Vec<Hash> {
    (0..hashes.len())
        .step_by(2)
        .map(|index| pair_hash(label, &hashes[index], &hashes[index + 1]))
        .collect()
}

pub fn outcome_leaf_hash(summary: &DlcSummary, outcome: &Outcome) -> Hash {
    let mut bytes = Vec::with_capacity(136);
    bytes.extend_from_slice(&summary.contract_id);
    bytes.extend_from_slice(&summary.oracle_event_id);
    bytes.extend_from_slice(&summary.outcome_count.to_le_bytes());
    bytes.extend_from_slice(&codec::outcome_bytes(outcome));
    tagged_hash("outcome-leaf", &bytes)
}

fn padding_leaf(label: &str, index: u32, count: u32) -> Hash {
    let mut bytes = [0; 8];
    bytes[..4].copy_from_slice(&index.to_le_bytes());
    bytes[4..].copy_from_slice(&count.to_le_bytes());
    tagged_hash(label, &bytes)
}

pub fn outcome_root_and_path(
    summary: &DlcSummary,
    outcomes: &[Outcome],
    selected: usize,
) -> Result<(Hash, Vec<Hash>)> {
    if outcomes.is_empty()
        || outcomes.len() > MAX_OUTCOMES as usize
        || outcomes.len() != summary.outcome_count as usize
        || selected >= outcomes.len()
    {
        return Err("invalid outcome tree dimensions".to_owned());
    }
    let count = outcomes.len();
    let mut hashes = Vec::with_capacity(count.next_power_of_two());
    for (index, outcome) in outcomes.iter().enumerate() {
        if outcome.index as usize != index {
            return Err("outcome leaves require consecutive indices".to_owned());
        }
        hashes.push(outcome_leaf_hash(summary, outcome));
    }
    for index in count..count.next_power_of_two() {
        hashes.push(padding_leaf("outcome-padding", index as u32, count as u32));
    }
    let mut siblings = Vec::new();
    let mut index = selected;
    while hashes.len() > 1 {
        siblings.push(hashes[index ^ 1]);
        hashes = parent_level("outcome-node", &hashes);
        index /= 2;
    }
    Ok((hashes[0], siblings))
}

pub(crate) fn verify_outcome_membership(
    summary: &DlcSummary,
    outcome: &Outcome,
    siblings: &[Hash],
) -> Result<()> {
    let depth = summary.outcome_count.next_power_of_two().trailing_zeros() as usize;
    if outcome.index >= summary.outcome_count || siblings.len() != depth {
        return Err("invalid outcome index or path depth".to_owned());
    }
    let mut node = outcome_leaf_hash(summary, outcome);
    let mut index = outcome.index;
    for sibling in siblings {
        node = if index & 1 == 0 {
            pair_hash("outcome-node", &node, sibling)
        } else {
            pair_hash("outcome-node", sibling, &node)
        };
        index >>= 1;
    }
    if node != summary.outcome_root {
        return Err("selected payout is outside the signed outcome root".to_owned());
    }
    Ok(())
}

pub fn accepted_contracts_root(rows: &[Row]) -> Result<Hash> {
    if rows.is_empty() || rows.len() > MAX_ROWS {
        return Err("invalid accepted set dimensions".to_owned());
    }
    let count = rows.len();
    let mut hashes = Vec::with_capacity(count.next_power_of_two());
    for (index, row) in rows.iter().enumerate() {
        let mut bytes = Vec::with_capacity(40);
        bytes.extend_from_slice(&(index as u32).to_le_bytes());
        bytes.extend_from_slice(&(count as u32).to_le_bytes());
        bytes.extend_from_slice(&summary_digest(&row.summary));
        hashes.push(tagged_hash("accepted-contract-leaf", &bytes));
    }
    for index in count..count.next_power_of_two() {
        hashes.push(padding_leaf(
            "accepted-contract-padding",
            index as u32,
            count as u32,
        ));
    }
    while hashes.len() > 1 {
        hashes = parent_level("accepted-contract-node", &hashes);
    }
    Ok(hashes[0])
}

fn empty_leaf() -> Hash {
    tagged_hash("nullifier-empty-leaf", &[])
}
fn used_leaf(key: &Hash) -> Hash {
    tagged_hash("nullifier-used-leaf", key)
}
fn branch(left: &Hash, right: &Hash) -> Hash {
    pair_hash("nullifier-node", left, right)
}

fn default_nodes() -> Vec<Hash> {
    let mut nodes = Vec::with_capacity(SMT_DEPTH + 1);
    nodes.push(empty_leaf());
    for level in 0..SMT_DEPTH {
        nodes.push(branch(&nodes[level], &nodes[level]));
    }
    nodes
}

pub fn empty_nullifier_root() -> Hash {
    default_nodes()[SMT_DEPTH]
}

fn bit(key: &Hash, index: usize) -> bool {
    (key[index / 8] & (0x80 >> (index % 8))) != 0
}

fn root_from_path(key: &Hash, leaf: Hash, siblings: &[Hash]) -> Result<Hash> {
    if siblings.len() != SMT_DEPTH {
        return Err("nullifier membership path must contain 256 siblings".to_owned());
    }
    let mut node = leaf;
    for (level, sibling) in siblings.iter().enumerate() {
        node = if bit(key, SMT_DEPTH - 1 - level) {
            branch(sibling, &node)
        } else {
            branch(&node, sibling)
        };
    }
    Ok(node)
}

pub(crate) fn consume_nullifier(
    key: &Hash,
    siblings: &[Hash],
    current_root: &Hash,
) -> Result<Hash> {
    if root_from_path(key, empty_leaf(), siblings)? != *current_root {
        return Err("nullifier is already consumed or its nonmembership path does not match the current root".to_owned());
    }
    root_from_path(key, used_leaf(key), siblings)
}

fn prefix(key: &Hash, depth: usize) -> Hash {
    let mut value = *key;
    if depth < SMT_DEPTH {
        let byte = depth / 8;
        let remainder = depth % 8;
        if remainder == 0 {
            value[byte..].fill(0);
        } else {
            value[byte] &= 0xff << (8 - remainder);
            value[byte + 1..].fill(0);
        }
    }
    value
}

/// Reference witness builder for a sparse tree of consumed application
/// authorizations. This holds nullifiers only, and does not observe Bitcoin.
#[derive(Debug, Clone)]
pub struct SparseNullifierTree {
    nodes: BTreeMap<(usize, Hash), Hash>,
    used: BTreeSet<Hash>,
    defaults: Vec<Hash>,
}

impl Default for SparseNullifierTree {
    fn default() -> Self {
        Self::new()
    }
}
impl SparseNullifierTree {
    pub fn new() -> Self {
        Self {
            nodes: BTreeMap::new(),
            used: BTreeSet::new(),
            defaults: default_nodes(),
        }
    }
    pub fn root(&self) -> Hash {
        self.nodes
            .get(&(0, [0; 32]))
            .copied()
            .unwrap_or(self.defaults[SMT_DEPTH])
    }
    pub fn proof(&self, key: &Hash) -> Vec<Hash> {
        let mut proof = Vec::with_capacity(SMT_DEPTH);
        for depth in (1..=SMT_DEPTH).rev() {
            let mut sibling = prefix(key, depth);
            let index = depth - 1;
            sibling[index / 8] ^= 0x80 >> (index % 8);
            proof.push(
                self.nodes
                    .get(&(depth, sibling))
                    .copied()
                    .unwrap_or(self.defaults[SMT_DEPTH - depth]),
            );
        }
        proof
    }
    pub fn insert(&mut self, key: &Hash) -> Result<()> {
        if !self.used.insert(*key) {
            return Err("nullifier already present".to_owned());
        }
        self.nodes.insert((SMT_DEPTH, *key), used_leaf(key));
        for depth in (0..SMT_DEPTH).rev() {
            let left = prefix(key, depth);
            let mut right = left;
            right[depth / 8] |= 0x80 >> (depth % 8);
            let fallback = self.defaults[SMT_DEPTH - depth - 1];
            let left_hash = self
                .nodes
                .get(&(depth + 1, left))
                .copied()
                .unwrap_or(fallback);
            let right_hash = self
                .nodes
                .get(&(depth + 1, right))
                .copied()
                .unwrap_or(fallback);
            self.nodes
                .insert((depth, prefix(key, depth)), branch(&left_hash, &right_hash));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sparse_updates_handle_shared_prefixes_and_both_directions() {
        let mut tree = SparseNullifierTree::new();
        let keys = [
            [0; 32],
            [0xff; 32],
            {
                let mut k = [0; 32];
                k[31] = 1;
                k
            },
            {
                let mut k = [0; 32];
                k[0] = 0x80;
                k
            },
        ];
        for key in keys {
            let old = tree.root();
            let proof = tree.proof(&key);
            let expected = consume_nullifier(&key, &proof, &old).unwrap();
            tree.insert(&key).unwrap();
            assert_eq!(tree.root(), expected);
            assert!(consume_nullifier(&key, &tree.proof(&key), &tree.root()).is_err());
        }
        assert!(tree.insert(&keys[0]).is_err());
    }
}
