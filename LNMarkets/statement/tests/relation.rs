use lnm_batch_statement::{fixture::*, *};

fn bytes<const N: usize>(hex: &str) -> [u8; N] {
    assert_eq!(hex.len(), N * 2);
    let mut out = [0; N];
    for (index, value) in out.iter_mut().enumerate() {
        *value = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).unwrap();
    }
    out
}

#[test]
fn independent_published_bip340_vectors_use_raw_message_semantics() {
    // Bitcoin BIP340 test-vectors.csv, vectors 0 (valid) and 5 (invalid key).
    // https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv
    let key = bytes("F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9");
    let message = [0; 32];
    let signature = bytes("E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0");
    verify_bip340(&key, &message, &signature).unwrap();
    assert!(verify_bip340(&key, &sha256(&message), &signature).is_err());
    let invalid_key = bytes("EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34");
    let msg = bytes("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89");
    let sig = bytes("6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E17776969E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B");
    assert!(verify_bip340(&invalid_key, &msg, &sig).is_err());
}

#[test]
fn nums_template_matches_utxoref_and_independent_rust_bitcoin() {
    let a = fixture_pubkey(11);
    let b = fixture_pubkey(12);
    let ours = derive_funding_script(&a, &b, 144).unwrap();
    // Generated from UTXO-Ref@0dff29e using buildDlcFundingOutput(keys11/12,144).
    assert_eq!(
        hex(&ours),
        "5120b855eac8771861baee8061e84ebc00d5b940834e3b276edb981d6d0dc57aa9cd"
    );
    let cet_hex = "20774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cbad20d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85aac";
    let refund_hex = format!("029000b275{cet_hex}");
    let parse = |value: &str| {
        bitcoin::ScriptBuf::from_bytes(
            (0..value.len())
                .step_by(2)
                .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
                .collect(),
        )
    };
    let internal = bitcoin::secp256k1::XOnlyPublicKey::from_slice(&bytes::<32>(
        "c99e9965166e7ff80516494709db8fdfdc31b0626500bb70dc3652fc2ff584ab",
    ))
    .unwrap();
    let secp = bitcoin::secp256k1::Secp256k1::verification_only();
    let spend = bitcoin::taproot::TaprootBuilder::new()
        .add_leaf(1, parse(cet_hex))
        .unwrap()
        .add_leaf(1, parse(&refund_hex))
        .unwrap()
        .finalize(&secp, internal)
        .unwrap();
    let script = bitcoin::ScriptBuf::new_p2tr_tweaked(spend.output_key());
    assert_eq!(script.as_bytes(), &ours);
    assert_eq!(derive_funding_script(&b, &a, 144).unwrap(), ours);
    assert!(derive_funding_script(&a, &a, 144).is_err());
    assert!(derive_funding_script(&a, &b, 0).is_err());
}

#[test]
fn complete_batch_roundtrips_with_constant_journal_size_and_bitcoin_txid() {
    for count in [1, 2, 8, 32] {
        let batch = demo_batch(count).unwrap();
        let wire = encode_batch(&batch).unwrap();
        assert!(wire.len() < MAX_WITNESS_BYTES);
        assert_eq!(decode_batch(&wire).unwrap(), batch);
        let journal = verify_batch_bytes(&wire).unwrap();
        assert_eq!(journal.len(), JOURNAL_LEN);
        let public = verify_expected_journal(&journal, &journal_pins(&batch.context)).unwrap();
        assert_eq!(public.row_count, count as u32);
        assert_eq!(public.total_collateral_sats, 401_330 * count as u64);
        assert_eq!(public.total_fee_sats, 1000 * count as u64);
        assert_eq!(
            public.total_payout_sats + public.total_fee_sats,
            public.total_collateral_sats
        );
        let raw = unsigned_batch_transaction(&batch.rows).unwrap();
        let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(&raw).unwrap();
        assert_eq!(tx.input.len(), count);
        assert_eq!(tx.output.len(), 3);
        assert_eq!(tx.compute_txid().to_string(), hex(&public.batch_txid));
        assert_eq!(tx.lock_time.to_consensus_u32(), 1000);
        assert!(tx.input.iter().all(|input| input.witness.is_empty()
            && input.script_sig.is_empty()
            && input.sequence.to_consensus_u32() == 0xfffffffd));
        assert_eq!(
            tx.output
                .iter()
                .map(|output| output.value.to_sat())
                .sum::<u64>(),
            public.total_payout_sats
        );
    }
}

#[test]
fn parser_bounds_allocation_and_rejects_noncanonical_frames() {
    let batch = demo_batch(1).unwrap();
    let wire = encode_batch(&batch).unwrap();
    for length in [0, 1, 7, 8, 80, 180, wire.len() - 1] {
        assert!(decode_batch(&wire[..length]).is_err());
    }
    assert!(decode_batch(&vec![0; MAX_WITNESS_BYTES + 1]).is_err());
    let mut trailing = wire.clone();
    trailing.push(0);
    assert!(decode_batch(&trailing).is_err());
    let mut magic = wire.clone();
    magic[7] = b'2';
    assert!(decode_batch(&magic).is_err());
    for count in [0u32, 33, u32::MAX] {
        let mut bad = wire.clone();
        bad[184..188].copy_from_slice(&count.to_le_bytes());
        assert!(decode_batch(&bad).is_err());
    }
    let journal = verify_batch_bytes(&wire).unwrap();
    assert!(decode_journal(&journal[..JOURNAL_LEN - 1]).is_err());
    let mut bad_journal = journal.clone();
    bad_journal.push(0);
    assert!(decode_journal(&bad_journal).is_err());
}

#[test]
fn every_party_and_oracle_signature_is_enforced() {
    let valid = demo_batch(1).unwrap();
    for index in 0..6 {
        let mut bad = valid.clone();
        match index {
            0 => bad.rows[0].summary_signatures[0][0] ^= 1,
            1 => bad.rows[0].summary_signatures[1][0] ^= 1,
            2 => bad.rows[0].batch_signatures[0][0] ^= 1,
            3 => bad.rows[0].batch_signatures[1][0] ^= 1,
            4 => bad.rows[0].oracle_attestations[0].signature[0] ^= 1,
            _ => bad.rows[0].oracle_attestations[1].signature[0] ^= 1,
        }
        assert!(verify_batch(&bad).is_err(), "signature {index}");
    }
}

#[test]
fn summary_bindings_and_oracle_quorum_cannot_be_substituted() {
    let valid = demo_batch(1).unwrap();
    let mut bad = valid.clone();
    bad.rows[0].summary.recovery_digest[0] ^= 1;
    assert!(verify_batch(&bad).is_err());
    let mut bad = valid.clone();
    bad.rows[0].summary.funding_script = bad.rows[0].summary.trader_script;
    resign_batch(&mut bad).unwrap();
    assert!(verify_batch(&bad).unwrap_err().contains("derived"));
    let mut bad = valid.clone();
    bad.rows[0].oracle_attestations[1] = bad.rows[0].oracle_attestations[0].clone();
    assert!(verify_batch(&bad).unwrap_err().contains("distinct"));
    let mut bad = valid.clone();
    bad.rows[0].summary.salt = [0; 32];
    resign_batch(&mut bad).unwrap();
    assert!(verify_batch(&bad).unwrap_err().contains("salt"));
}

#[test]
fn payout_path_index_money_and_maturity_constraints_survive_fresh_signatures() {
    let valid = demo_batch(1).unwrap();
    let mut bad = valid.clone();
    bad.rows[0].outcome.index = 3;
    resign_batch(&mut bad).unwrap();
    assert!(verify_batch(&bad).is_err());
    let mut bad = valid.clone();
    bad.rows[0].outcome_siblings[0][0] ^= 1;
    assert!(verify_batch(&bad).unwrap_err().contains("outcome root"));
    let mut bad = valid.clone();
    bad.rows[0].outcome_siblings.push([0; 32]);
    assert!(verify_batch(&bad).unwrap_err().contains("depth"));
    let mut bad = valid.clone();
    bad.rows[0].outcome.trader_sats = MAX_MONEY + 1;
    resign_batch(&mut bad).unwrap();
    assert!(verify_batch(&bad).is_err());
    let mut bad = valid.clone();
    bad.rows[0].outcome.anchor_sats = 0;
    resign_batch(&mut bad).unwrap();
    assert!(verify_batch(&bad).is_err());
    let mut bad = valid.clone();
    bad.context.evaluation_height = 999;
    resign_batch(&mut bad).unwrap();
    assert!(verify_batch(&bad).unwrap_err().contains("maturity"));
    let mut bad = valid.clone();
    bad.context.evaluation_height = 1101;
    resign_batch(&mut bad).unwrap();
    assert!(verify_batch(&bad).unwrap_err().contains("window"));
}

#[test]
fn canonical_row_order_and_entire_accepted_set_are_required() {
    let valid = demo_batch(2).unwrap();
    let mut bad = valid.clone();
    bad.rows.reverse();
    assert!(verify_batch(&bad).is_err());
    let mut bad = valid.clone();
    bad.rows.pop();
    bad.context.row_count = 1;
    resign_batch(&mut bad).unwrap();
    assert!(verify_batch(&bad).is_err());
    let mut bad = valid.clone();
    bad.context.accepted_contracts_root[0] ^= 1;
    resign_batch(&mut bad).unwrap();
    assert!(verify_batch(&bad)
        .unwrap_err()
        .contains("accepted contracts"));
    let mut bad = valid.clone();
    bad.context.new_nullifier_root[0] ^= 1;
    resign_batch(&mut bad).unwrap();
    assert!(verify_batch(&bad)
        .unwrap_err()
        .contains("authorization root"));
}

#[test]
fn oracle_authorization_binds_outcome_index_even_when_messages_repeat() {
    let mut batch = demo_batch(1).unwrap();
    let original_attestations = batch.rows[0].oracle_attestations.clone();
    let outcomes: Vec<_> = (0..3)
        .map(|index| Outcome {
            index,
            ..batch.rows[0].outcome.clone()
        })
        .collect();
    let (root, path) = outcome_root_and_path(&batch.rows[0].summary, &outcomes, 1).unwrap();
    batch.rows[0].summary.outcome_root = root;
    batch.rows[0].outcome = outcomes[1].clone();
    batch.rows[0].outcome_siblings = path;
    batch.context.accepted_contracts_root = accepted_contracts_root(&batch.rows).unwrap();
    resign_batch(&mut batch).unwrap();
    verify_batch(&batch).unwrap();
    batch.rows[0].oracle_attestations = original_attestations;
    assert!(verify_batch(&batch).unwrap_err().contains("BIP340"));
}
