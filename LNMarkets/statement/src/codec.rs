use crate::*;

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn fixed<const N: usize>(&mut self) -> Result<[u8; N]> {
        let end = self.at.checked_add(N).ok_or("input offset overflow")?;
        let bytes = self
            .bytes
            .get(self.at..end)
            .ok_or("truncated binary input")?;
        self.at = end;
        bytes
            .try_into()
            .map_err(|_| "invalid fixed field length".to_owned())
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.fixed::<1>()?[0])
    }
    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.fixed()?))
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.fixed()?))
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.fixed()?))
    }
    fn done(&self) -> Result<()> {
        if self.at != self.bytes.len() {
            return Err("trailing bytes after canonical binary input".to_owned());
        }
        Ok(())
    }
}

pub(crate) fn context_bytes(c: &BatchContext) -> Vec<u8> {
    let mut b = Vec::with_capacity(180);
    b.extend_from_slice(&c.epoch.to_le_bytes());
    b.extend_from_slice(&c.batch_id);
    b.extend_from_slice(&c.evaluation_height.to_le_bytes());
    b.extend_from_slice(&c.valid_until_height.to_le_bytes());
    b.extend_from_slice(&c.accepted_contracts_root);
    b.extend_from_slice(&c.old_nullifier_root);
    b.extend_from_slice(&c.new_nullifier_root);
    b.extend_from_slice(&c.batch_tx_digest);
    b.extend_from_slice(&c.row_count.to_le_bytes());
    b
}

fn read_context(r: &mut Reader<'_>) -> Result<BatchContext> {
    Ok(BatchContext {
        epoch: r.u64()?,
        batch_id: r.fixed()?,
        evaluation_height: r.u32()?,
        valid_until_height: r.u32()?,
        accepted_contracts_root: r.fixed()?,
        old_nullifier_root: r.fixed()?,
        new_nullifier_root: r.fixed()?,
        batch_tx_digest: r.fixed()?,
        row_count: r.u32()?,
    })
}

pub(crate) fn summary_bytes(s: &DlcSummary) -> Vec<u8> {
    let mut b = Vec::with_capacity(582);
    for h in [
        &s.salt,
        &s.contract_id,
        &s.plan_digest,
        &s.recovery_digest,
        &s.funding_txid,
    ] {
        b.extend_from_slice(h);
    }
    b.extend_from_slice(&s.funding_vout.to_le_bytes());
    b.extend_from_slice(&s.collateral_sats.to_le_bytes());
    b.extend_from_slice(&s.funding_script);
    b.extend_from_slice(&s.trader_key);
    b.extend_from_slice(&s.maker_key);
    for script in [&s.trader_script, &s.maker_script, &s.anchor_script] {
        b.extend_from_slice(script);
    }
    for key in &s.oracle_keys {
        b.extend_from_slice(key);
    }
    b.extend_from_slice(&s.oracle_event_id);
    b.extend_from_slice(&s.outcome_root);
    b.extend_from_slice(&s.outcome_count.to_le_bytes());
    b.extend_from_slice(&s.maturity_height.to_le_bytes());
    b.extend_from_slice(&s.refund_height.to_le_bytes());
    b.extend_from_slice(&s.refund_csv.to_le_bytes());
    b
}

fn read_summary(r: &mut Reader<'_>) -> Result<DlcSummary> {
    Ok(DlcSummary {
        salt: r.fixed()?,
        contract_id: r.fixed()?,
        plan_digest: r.fixed()?,
        recovery_digest: r.fixed()?,
        funding_txid: r.fixed()?,
        funding_vout: r.u32()?,
        collateral_sats: r.u64()?,
        funding_script: r.fixed()?,
        trader_key: r.fixed()?,
        maker_key: r.fixed()?,
        trader_script: r.fixed()?,
        maker_script: r.fixed()?,
        anchor_script: r.fixed()?,
        oracle_keys: [r.fixed()?, r.fixed()?, r.fixed()?],
        oracle_event_id: r.fixed()?,
        outcome_root: r.fixed()?,
        outcome_count: r.u32()?,
        maturity_height: r.u32()?,
        refund_height: r.u32()?,
        refund_csv: r.u16()?,
    })
}

pub(crate) fn outcome_bytes(o: &Outcome) -> Vec<u8> {
    let mut b = Vec::with_capacity(68);
    b.extend_from_slice(&o.index.to_le_bytes());
    b.extend_from_slice(&o.message);
    for value in [o.trader_sats, o.maker_sats, o.anchor_sats, o.fee_sats] {
        b.extend_from_slice(&value.to_le_bytes());
    }
    b
}

fn read_outcome(r: &mut Reader<'_>) -> Result<Outcome> {
    Ok(Outcome {
        index: r.u32()?,
        message: r.fixed()?,
        trader_sats: r.u64()?,
        maker_sats: r.u64()?,
        anchor_sats: r.u64()?,
        fee_sats: r.u64()?,
    })
}

pub fn encode_batch(batch: &BatchWitness) -> Result<Vec<u8>> {
    if batch.rows.is_empty()
        || batch.rows.len() > MAX_ROWS
        || batch.context.row_count as usize != batch.rows.len()
    {
        return Err("cannot encode an invalid row count".to_owned());
    }
    let mut b = Vec::with_capacity(188 + batch.rows.len() * 9600);
    b.extend_from_slice(BATCH_MAGIC);
    b.extend_from_slice(&context_bytes(&batch.context));
    for row in &batch.rows {
        if row.outcome_siblings.len() > 10 || row.nullifier_siblings.len() != SMT_DEPTH {
            return Err("invalid membership path lengths".to_owned());
        }
        b.extend_from_slice(&summary_bytes(&row.summary));
        for sig in &row.summary_signatures {
            b.extend_from_slice(sig);
        }
        b.extend_from_slice(&outcome_bytes(&row.outcome));
        b.extend_from_slice(&(row.outcome_siblings.len() as u16).to_le_bytes());
        for sibling in &row.outcome_siblings {
            b.extend_from_slice(sibling);
        }
        for oracle in &row.oracle_attestations {
            b.push(oracle.oracle_index);
            b.extend_from_slice(&oracle.signature);
        }
        for sig in &row.batch_signatures {
            b.extend_from_slice(sig);
        }
        for sibling in &row.nullifier_siblings {
            b.extend_from_slice(sibling);
        }
    }
    if b.len() > MAX_WITNESS_BYTES {
        return Err("witness exceeds 512 KiB".to_owned());
    }
    Ok(b)
}

pub fn decode_batch(bytes: &[u8]) -> Result<BatchWitness> {
    if bytes.len() > MAX_WITNESS_BYTES {
        return Err("witness exceeds 512 KiB".to_owned());
    }
    let mut r = Reader { bytes, at: 0 };
    if &r.fixed::<8>()? != BATCH_MAGIC {
        return Err("unsupported witness magic/version/network domain".to_owned());
    }
    let context = read_context(&mut r)?;
    if context.row_count == 0 || context.row_count as usize > MAX_ROWS {
        return Err("row count must be in 1..32".to_owned());
    }
    let mut rows = Vec::with_capacity(context.row_count as usize);
    for _ in 0..context.row_count {
        let summary = read_summary(&mut r)?;
        if summary.outcome_count == 0 || summary.outcome_count > MAX_OUTCOMES {
            return Err("outcome count must be in 1..1024".to_owned());
        }
        let summary_signatures = [r.fixed()?, r.fixed()?];
        let outcome = read_outcome(&mut r)?;
        let path_len = r.u16()? as usize;
        if path_len != summary.outcome_count.next_power_of_two().trailing_zeros() as usize {
            return Err("noncanonical outcome membership depth".to_owned());
        }
        let mut outcome_siblings = Vec::with_capacity(path_len);
        for _ in 0..path_len {
            outcome_siblings.push(r.fixed()?);
        }
        let oracle_attestations = [
            OracleAttestation {
                oracle_index: r.u8()?,
                signature: r.fixed()?,
            },
            OracleAttestation {
                oracle_index: r.u8()?,
                signature: r.fixed()?,
            },
        ];
        let batch_signatures = [r.fixed()?, r.fixed()?];
        let mut nullifier_siblings = Vec::with_capacity(SMT_DEPTH);
        for _ in 0..SMT_DEPTH {
            nullifier_siblings.push(r.fixed()?);
        }
        rows.push(Row {
            summary,
            summary_signatures,
            outcome,
            outcome_siblings,
            oracle_attestations,
            batch_signatures,
            nullifier_siblings,
        });
    }
    r.done()?;
    Ok(BatchWitness { context, rows })
}

pub fn encode_journal(j: &Journal) -> Vec<u8> {
    let mut b = Vec::with_capacity(JOURNAL_LEN);
    b.extend_from_slice(JOURNAL_MAGIC);
    b.extend_from_slice(&j.domain);
    b.extend_from_slice(&j.epoch.to_le_bytes());
    b.extend_from_slice(&j.batch_id);
    b.extend_from_slice(&j.evaluation_height.to_le_bytes());
    b.extend_from_slice(&j.valid_until_height.to_le_bytes());
    b.extend_from_slice(&j.row_count.to_le_bytes());
    for h in [
        &j.accepted_contracts_root,
        &j.old_nullifier_root,
        &j.new_nullifier_root,
        &j.batch_tx_digest,
        &j.batch_txid,
    ] {
        b.extend_from_slice(h);
    }
    for value in [
        j.total_collateral_sats,
        j.total_payout_sats,
        j.total_fee_sats,
    ] {
        b.extend_from_slice(&value.to_le_bytes());
    }
    debug_assert_eq!(b.len(), JOURNAL_LEN);
    b
}

pub fn decode_journal(bytes: &[u8]) -> Result<Journal> {
    if bytes.len() != JOURNAL_LEN {
        return Err("journal must be exactly 276 bytes".to_owned());
    }
    let mut r = Reader { bytes, at: 0 };
    if &r.fixed::<8>()? != JOURNAL_MAGIC {
        return Err("unsupported journal magic/version".to_owned());
    }
    let j = Journal {
        domain: r.fixed()?,
        epoch: r.u64()?,
        batch_id: r.fixed()?,
        evaluation_height: r.u32()?,
        valid_until_height: r.u32()?,
        row_count: r.u32()?,
        accepted_contracts_root: r.fixed()?,
        old_nullifier_root: r.fixed()?,
        new_nullifier_root: r.fixed()?,
        batch_tx_digest: r.fixed()?,
        batch_txid: r.fixed()?,
        total_collateral_sats: r.u64()?,
        total_payout_sats: r.u64()?,
        total_fee_sats: r.u64()?,
    };
    r.done()?;
    Ok(j)
}
