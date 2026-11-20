//! Independent attacks against the public native/guest relation interface.
//! Fixtures use disclosed disposable keys; no proof or chain claim is made.
use lnm_batch_statement::fixture::{demo_batch, resign_batch};
use lnm_batch_statement::{
    accepted_contracts_root, batch_consent_message, encode_journal, outcome_root_and_path,
    outpoint_nullifier, sha256, summary_digest, unsigned_batch_transaction, verify_batch,
    verify_expected_journal, BatchWitness, Hash, JournalPins, SparseNullifierTree,
};
use sha2::{Digest, Sha256};

fn pins(batch: &BatchWitness) -> JournalPins {
    let c = &batch.context;
    JournalPins {
        epoch: c.epoch,
        batch_id: c.batch_id,
        evaluation_height: c.evaluation_height,
        valid_until_height: c.valid_until_height,
        row_count: c.row_count,
        accepted_contracts_root: c.accepted_contracts_root,
        old_nullifier_root: c.old_nullifier_root,
        batch_tx_digest: c.batch_tx_digest,
    }
}

#[test]
fn independently_retained_context_rejects_stale_or_replaced_journals() {
    let batch = demo_batch(2).unwrap();
    let journal = verify_batch(&batch).unwrap();
    let encoded = encode_journal(&journal);
    let original = pins(&batch);
    verify_expected_journal(&encoded, &original).unwrap();

    let mutations: [fn(&mut JournalPins); 8] = [
        |p| p.epoch += 1,
        |p| p.batch_id[0] ^= 1,
        |p| p.evaluation_height += 1,
        |p| p.valid_until_height -= 1,
        |p| p.row_count += 1,
        |p| p.accepted_contracts_root[0] ^= 1,
        |p| p.old_nullifier_root[0] ^= 1,
        |p| p.batch_tx_digest[0] ^= 1,
    ];
    for mutate in mutations {
        let mut expected = original.clone();
        mutate(&mut expected);
        assert!(verify_expected_journal(&encoded, &expected).is_err());
    }
}

#[test]
fn resalting_and_renaming_cannot_reidentify_one_funding_outpoint() {
    let batch = demo_batch(2).unwrap();
    let original = &batch.rows[0].summary;
    let mut renamed = original.clone();
    renamed.salt[0] ^= 1;
    renamed.contract_id[0] ^= 1;
    renamed.plan_digest[0] ^= 1;
    renamed.recovery_digest[0] ^= 1;
    assert_ne!(summary_digest(&renamed), summary_digest(original));
    assert_eq!(outpoint_nullifier(&renamed), outpoint_nullifier(original));

    renamed.funding_vout += 1;
    assert_ne!(outpoint_nullifier(&renamed), outpoint_nullifier(original));

    let mut duplicated = batch.clone();
    duplicated.rows[1].summary.funding_txid = original.funding_txid;
    duplicated.rows[1].summary.funding_vout = original.funding_vout;
    duplicated.rows[1].summary.salt[0] ^= 1;
    duplicated.rows[1].summary.contract_id[0] ^= 1;
    resign_batch(&mut duplicated).unwrap();
    let error = verify_batch(&duplicated).unwrap_err();
    assert!(error.contains("outpoints must be unique"), "{error}");
}

#[test]
fn valid_fresh_consent_cannot_consume_an_outpoint_twice_across_epochs() {
    let first = demo_batch(2).unwrap();
    let first_journal = verify_batch(&first).unwrap();
    let mut tree = SparseNullifierTree::new();
    for row in &first.rows {
        tree.insert(&outpoint_nullifier(&row.summary)).unwrap();
    }
    assert_eq!(tree.root(), first_journal.new_nullifier_root);

    let mut replay = first.clone();
    replay.context.epoch += 1;
    replay.context.batch_id[0] ^= 1;
    replay.context.old_nullifier_root = tree.root();
    replay.context.new_nullifier_root = tree.root();
    for row in &mut replay.rows {
        row.nullifier_siblings = tree.proof(&outpoint_nullifier(&row.summary));
    }
    resign_batch(&mut replay).unwrap();
    let error = verify_batch(&replay).unwrap_err();
    assert!(
        error.contains("nullifier") || error.contains("nonmembership"),
        "{error}"
    );
}

#[test]
fn new_batch_signatures_do_not_rewrite_the_previously_agreed_payout_tree() {
    let mut batch = demo_batch(2).unwrap();
    batch.rows[0].outcome.trader_sats += 1;
    batch.rows[0].outcome.maker_sats -= 1;
    // Accounting still balances, and both parties approve the modified
    // transaction. The selected payout must also open the original tree.
    batch.context.batch_tx_digest = sha256(&unsigned_batch_transaction(&batch.rows).unwrap());
    resign_batch(&mut batch).unwrap();
    let error = verify_batch(&batch).unwrap_err();
    assert!(
        error.contains("outcome") || error.contains("payout"),
        "{error}"
    );
}

#[test]
fn batch_consent_and_transaction_reconstruction_are_separate_checks() {
    let mut batch = demo_batch(1).unwrap();
    batch.context.batch_tx_digest[0] ^= 1;
    let error = verify_batch(&batch).unwrap_err();
    assert!(error.contains("BIP340"), "{error}");

    // Even the real fixture key holders cannot authenticate an arbitrary
    // transaction digest in place of the transaction built from the rows.
    resign_batch(&mut batch).unwrap();
    let error = verify_batch(&batch).unwrap_err();
    assert!(error.contains("transaction digest"), "{error}");
}

#[test]
fn summary_consent_cannot_be_replayed_as_batch_consent() {
    let mut batch = demo_batch(1).unwrap();
    let row = &batch.rows[0];
    assert_ne!(
        summary_digest(&row.summary),
        batch_consent_message(&batch.context, &row.summary)
    );
    batch.rows[0].batch_signatures = batch.rows[0].summary_signatures;
    let error = verify_batch(&batch).unwrap_err();
    assert!(error.contains("BIP340"), "{error}");
}

#[test]
fn repeated_oracle_message_cannot_authorize_a_different_payout_index() {
    let mut batch = demo_batch(1).unwrap();
    let original_attestations = batch.rows[0].oracle_attestations.clone();
    let original_outcome = batch.rows[0].outcome.clone();
    assert_eq!(original_outcome.index, 0);

    // Create a fully signed alternative table whose index 1 pays the trader
    // one extra satoshi using the same opaque message as index 0. Membership,
    // accounting, exact transaction reconstruction and bilateral consent all
    // remain valid, so rejection must come from the old oracle attestations.
    let outcomes: Vec<_> = (0..3)
        .map(|index| {
            let mut outcome = original_outcome.clone();
            outcome.index = index;
            outcome.trader_sats += u64::from(index);
            outcome.maker_sats -= u64::from(index);
            outcome
        })
        .collect();
    let (root, path) = outcome_root_and_path(&batch.rows[0].summary, &outcomes, 1).unwrap();
    batch.rows[0].summary.outcome_root = root;
    batch.rows[0].outcome = outcomes[1].clone();
    batch.rows[0].outcome_siblings = path;
    batch.context.accepted_contracts_root = accepted_contracts_root(&batch.rows).unwrap();
    batch.context.batch_tx_digest = sha256(&unsigned_batch_transaction(&batch.rows).unwrap());
    resign_batch(&mut batch).unwrap();
    verify_batch(&batch).unwrap();

    batch.rows[0].oracle_attestations = original_attestations;
    let error = verify_batch(&batch).unwrap_err();
    assert!(error.contains("BIP340"), "{error}");
}

// This reference implementation constructs the tree top down from a set of
// full keys. It shares neither the production prefix map nor its path-folding
// code, so a consistently reversed builder/verifier cannot satisfy the check.
fn reference_hash(label: &str, bytes: &[u8]) -> Hash {
    let domain = format!("UTXORef/LNMarkets/bitcoin-regtest/lnmarkets/v1/{label}");
    let tag = Sha256::digest(domain.as_bytes());
    let mut digest = Sha256::new();
    digest.update(tag);
    digest.update(tag);
    digest.update(bytes);
    digest.finalize().into()
}

fn reference_branch(left: &Hash, right: &Hash) -> Hash {
    let mut bytes = [0; 64];
    bytes[..32].copy_from_slice(left);
    bytes[32..].copy_from_slice(right);
    reference_hash("nullifier-node", &bytes)
}

fn reference_defaults() -> [Hash; 257] {
    let mut defaults = [[0; 32]; 257];
    defaults[256] = reference_hash("nullifier-empty-leaf", &[]);
    for depth in (0..256).rev() {
        defaults[depth] = reference_branch(&defaults[depth + 1], &defaults[depth + 1]);
    }
    defaults
}

fn reference_subtree(keys: &[Hash], depth: usize, defaults: &[Hash; 257]) -> Hash {
    if keys.is_empty() {
        return defaults[depth];
    }
    if depth == 256 {
        assert_eq!(keys.len(), 1);
        return reference_hash("nullifier-used-leaf", &keys[0]);
    }
    let (left, right): (Vec<Hash>, Vec<Hash>) = keys
        .iter()
        .copied()
        .partition(|key| (key[depth / 8] >> (7 - depth % 8)) & 1 == 0);
    reference_branch(
        &reference_subtree(&left, depth + 1, defaults),
        &reference_subtree(&right, depth + 1, defaults),
    )
}

fn reference_path(keys: &[Hash], query: &Hash, depth: usize, defaults: &[Hash; 257]) -> Vec<Hash> {
    if depth == 256 {
        return Vec::new();
    }
    let (left, right): (Vec<Hash>, Vec<Hash>) = keys
        .iter()
        .copied()
        .partition(|key| (key[depth / 8] >> (7 - depth % 8)) & 1 == 0);
    let (selected, sibling) = if (query[depth / 8] >> (7 - depth % 8)) & 1 == 0 {
        (&left, &right)
    } else {
        (&right, &left)
    };
    let mut path = reference_path(selected, query, depth + 1, defaults);
    path.push(reference_subtree(sibling, depth + 1, defaults));
    path
}

#[test]
fn sparse_tree_and_paths_match_independent_full_key_partitioning() {
    let defaults = reference_defaults();
    let mut tree = SparseNullifierTree::new();
    assert_eq!(tree.root(), defaults[0]);
    let mut first_bit = [0; 32];
    first_bit[0] = 0x80;
    let mut last_bit = [0; 32];
    last_bit[31] = 1;
    let mut byte_boundary = [0; 32];
    byte_boundary[1] = 0x80;
    let queries = [[0; 32], [0xff; 32], first_bit, last_bit, byte_boundary];
    let mut inserted = Vec::new();

    for key in queries {
        for query in queries {
            assert_eq!(
                tree.proof(&query),
                reference_path(&inserted, &query, 0, &defaults)
            );
        }
        tree.insert(&key).unwrap();
        inserted.push(key);
        assert_eq!(tree.root(), reference_subtree(&inserted, 0, &defaults));
    }
    for query in queries {
        assert_eq!(
            tree.proof(&query),
            reference_path(&inserted, &query, 0, &defaults)
        );
    }
}
