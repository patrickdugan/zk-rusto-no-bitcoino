//! Metamorphic inclusion checks against a complete-tree oracle.
//!
//! Equivalently encoded transaction IDs, roots, and sibling arrays must yield
//! identical verdicts. Changes to the committed leaf, root, position, or
//! sibling path must be rejected. The oracle constructs all levels of a full
//! tree rather than following the verifier's leaf-to-root control flow.
//!
//! Transaction count is a caller-supplied claim: Bitcoin's Merkle root does
//! not, by itself, commit to the tree width. An explicit regression below
//! records a width ambiguity so this API cannot be mischaracterized as an
//! authenticated transaction-count proof.

use bitcoin::hashes::Hash;
use bitcoin::{TxMerkleNode, Txid};
use rust_bitcoin_zk_adapter::merkle::{verify_tx_merkle_root, MerkleError};

fn txid_for(index: usize) -> Txid {
    let mut bytes = [0x5au8; 32];
    bytes[..8].copy_from_slice(&((index as u64) + 1).to_le_bytes());
    Txid::from_byte_array(bytes)
}

fn node(id: Txid) -> TxMerkleNode {
    TxMerkleNode::from_byte_array(id.to_byte_array())
}

fn parent(left: TxMerkleNode, right: TxMerkleNode) -> TxMerkleNode {
    let mut bytes = [0u8; 64];
    bytes[..32].copy_from_slice(&left.to_byte_array());
    bytes[32..].copy_from_slice(&right.to_byte_array());
    TxMerkleNode::hash(&bytes)
}

/// Independently calculate a complete tree's root, duplicating only its
/// rightmost node at odd-width levels.
fn full_tree_root(level: &[TxMerkleNode]) -> TxMerkleNode {
    assert!(!level.is_empty());
    if level.len() == 1 {
        return level[0];
    }
    let upper: Vec<_> = level
        .chunks(2)
        .map(|pair| parent(pair[0], *pair.get(1).unwrap_or(&pair[0])))
        .collect();
    full_tree_root(&upper)
}

fn full_tree_branch(leaves: &[TxMerkleNode], mut index: usize) -> Vec<TxMerkleNode> {
    assert!(index < leaves.len());
    let mut level = leaves.to_vec();
    let mut branch = Vec::new();
    while level.len() > 1 {
        let sibling_index = if index.is_multiple_of(2) {
            (index + 1).min(level.len() - 1)
        } else {
            index - 1
        };
        branch.push(level[sibling_index]);
        level = level
            .chunks(2)
            .map(|pair| parent(pair[0], *pair.get(1).unwrap_or(&pair[0])))
            .collect();
        index /= 2;
    }
    branch
}

fn flipped(node: TxMerkleNode) -> TxMerkleNode {
    let mut bytes = node.to_byte_array();
    bytes[0] ^= 0x80;
    TxMerkleNode::from_byte_array(bytes)
}

#[test]
fn full_tree_oracle_metamorphisms_cover_every_position_to_width_32() {
    let mut accepted = 0usize;
    for width in 1usize..=32 {
        let ids: Vec<_> = (0..width).map(txid_for).collect();
        let leaves: Vec<_> = ids.iter().copied().map(node).collect();
        let root = full_tree_root(&leaves);

        for (index, &original_id) in ids.iter().enumerate() {
            let branch = full_tree_branch(&leaves, index);
            let count = width as u32;
            let position = index as u32;

            assert_eq!(
                verify_tx_merkle_root(original_id, position, count, &branch, root),
                Ok(()),
                "honest witness: width={width}, index={index}"
            );

            // Normalize the entire input through the public byte-array
            // representation. Naming and reconstruction are semantics-free.
            let renamed_id = Txid::from_byte_array(original_id.to_byte_array());
            let renamed_root = TxMerkleNode::from_byte_array(root.to_byte_array());
            let renamed_path: Vec<_> = branch
                .iter()
                .map(|sibling| TxMerkleNode::from_byte_array(sibling.to_byte_array()))
                .collect();
            assert_eq!(
                verify_tx_merkle_root(renamed_id, position, count, &renamed_path, renamed_root,),
                Ok(()),
                "re-encoded witness: width={width}, index={index}"
            );

            let mut changed_txid = original_id.to_byte_array();
            changed_txid[0] ^= 0x80;
            assert!(
                verify_tx_merkle_root(
                    Txid::from_byte_array(changed_txid),
                    position,
                    count,
                    &branch,
                    root,
                )
                .is_err(),
                "mutated transaction ID accepted: width={width}, index={index}"
            );
            assert!(
                verify_tx_merkle_root(original_id, position, count, &branch, flipped(root))
                    .is_err(),
                "mutated root accepted: width={width}, index={index}"
            );

            if width > 1 {
                assert!(
                    verify_tx_merkle_root(
                        original_id,
                        ((index + 1) % width) as u32,
                        count,
                        &branch,
                        root,
                    )
                    .is_err(),
                    "mutated position accepted: width={width}, index={index}"
                );

                let mut changed_branch = branch.clone();
                changed_branch[0] = flipped(changed_branch[0]);
                assert!(
                    verify_tx_merkle_root(original_id, position, count, &changed_branch, root,)
                        .is_err(),
                    "mutated Merkle sibling accepted: width={width}, index={index}"
                );
                assert_eq!(
                    verify_tx_merkle_root(
                        original_id,
                        position,
                        count,
                        &branch[..branch.len() - 1],
                        root,
                    ),
                    Err(MerkleError::MissingSibling)
                );
            }

            let mut trailing_branch = branch.clone();
            trailing_branch.push(node(txid_for(width + 1)));
            assert_eq!(
                verify_tx_merkle_root(original_id, position, count, &trailing_branch, root,),
                Err(MerkleError::ExtraSibling)
            );
            assert_eq!(
                verify_tx_merkle_root(original_id, position, 0, &branch, root),
                Err(MerkleError::InvalidPosition)
            );

            accepted += 1;
        }
    }
    assert_eq!(accepted, 528);
}

#[test]
fn width_of_the_tree_requires_external_authentication() {
    // Three leaves A,B,C have root H(H(A,B),H(C,C)). A branch for
    // position zero has the same verification steps if the caller
    // claims four leaves, with H(C,C) supplied as the right sibling.
    let ids: Vec<_> = (0..3).map(txid_for).collect();
    let leaves: Vec<_> = ids.iter().copied().map(node).collect();
    let root = full_tree_root(&leaves);
    let branch = full_tree_branch(&leaves, 0);

    assert_eq!(verify_tx_merkle_root(ids[0], 0, 3, &branch, root), Ok(()));
    assert_eq!(verify_tx_merkle_root(ids[0], 0, 4, &branch, root), Ok(()));
    // This is a statement-boundary test, not permission to trust width=4.
}
