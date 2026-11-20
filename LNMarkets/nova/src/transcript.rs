//! Fixed-width private signed-row transcript binding.
//!
//! SHA-256 is constrained over the exact v1 transcript. Signature bytes and the
//! two message digests are committed here; BIP340 verification and construction
//! of those message digests from a DLC summary remain separate claims.

use ff::Field;
use lnm_batch_statement::{batch_consent_message, summary_digest, BatchWitness};
use m18_utxo_window::elem::F;
use nova_snark::frontend::gadgets::boolean::{AllocatedBit, Boolean};
use nova_snark::frontend::gadgets::num::AllocatedNum;
use nova_snark::frontend::gadgets::sha256::sha256;
use nova_snark::frontend::{ConstraintSystem, LinearCombination, SynthesisError};

pub const TRANSCRIPT_TAG: &[u8; 46] = b"UTXORef/LNMarkets/Nova/validated-signed-row/v1";
pub const TRANSCRIPT_LEN: usize = 600;
pub const OUTCOME_INDEX_OFFSET: usize = 496;
pub const AMOUNTS_OFFSET: usize = 532;
pub const FUNDING_TXID_OFFSET: usize = 564;
pub const FUNDING_VOUT_OFFSET: usize = 596;

/// Encode exactly two party summary signatures, two party batch signatures and
/// two indexed oracle signatures. Public test vectors pin the byte layout.
pub fn signed_row_transcript(
    batch: &BatchWitness,
    index: usize,
) -> Result<[u8; TRANSCRIPT_LEN], String> {
    let row = batch.rows.get(index).ok_or("row index outside batch")?;
    let mut out = Vec::with_capacity(TRANSCRIPT_LEN);
    out.extend_from_slice(TRANSCRIPT_TAG);
    out.extend_from_slice(&summary_digest(&row.summary));
    out.extend_from_slice(&batch_consent_message(&batch.context, &row.summary));
    for signature in &row.summary_signatures {
        out.extend_from_slice(signature);
    }
    for signature in &row.batch_signatures {
        out.extend_from_slice(signature);
    }
    for attestation in &row.oracle_attestations {
        out.push(attestation.oracle_index);
        out.extend_from_slice(&attestation.signature);
    }
    out.extend_from_slice(&row.outcome.index.to_le_bytes());
    out.extend_from_slice(&row.outcome.message);
    for amount in [
        row.outcome.trader_sats,
        row.outcome.maker_sats,
        row.outcome.anchor_sats,
        row.outcome.fee_sats,
    ] {
        out.extend_from_slice(&amount.to_le_bytes());
    }
    out.extend_from_slice(&row.summary.funding_txid);
    out.extend_from_slice(&row.summary.funding_vout.to_le_bytes());
    out.try_into()
        .map_err(|_| "signed-row transcript encoding changed".into())
}

/// Allocations already used by the accounting equations and Poseidon chain.
/// Borrowing them avoids a second, independently choosable set of row values.
pub struct TranscriptFields<'a> {
    pub digest_lo: &'a AllocatedNum<F>,
    pub digest_hi: &'a AllocatedNum<F>,
    pub funding_lo: &'a AllocatedNum<F>,
    pub funding_hi: &'a AllocatedNum<F>,
    pub funding_vout: &'a AllocatedNum<F>,
    pub outcome_index: &'a AllocatedNum<F>,
    pub trader: &'a AllocatedNum<F>,
    pub maker: &'a AllocatedNum<F>,
    pub anchor: &'a AllocatedNum<F>,
    pub fee: &'a AllocatedNum<F>,
}

/// `bits` is a byte sequence, with bits in big-endian order within each byte.
/// Bind its little-endian integer interpretation to a field allocation. All
/// slices here are at most 128 bits, so the encoding is injective in Pallas.
fn bind_le_bytes<CS: ConstraintSystem<F>>(
    cs: &mut CS,
    bits: &[Boolean],
    field: &AllocatedNum<F>,
    name: &'static str,
) {
    assert!(bits.len().is_multiple_of(8) && bits.len() <= 128);
    let mut sum = LinearCombination::zero();
    let mut weight = F::ONE;
    for byte in bits.as_chunks::<8>().0 {
        for bit in byte.iter().rev() {
            sum = sum + &bit.lc(CS::one(), weight);
            weight = weight.double();
        }
    }
    cs.enforce(
        || name,
        |_| sum,
        |lc| lc + CS::one(),
        |lc| lc + field.get_variable(),
    );
}

/// Prove the fixed framing, SHA-256 digest and exact equality of the economic
/// and outpoint fields. Padding, message length and IV come from Nova's existing
/// SHA-256 gadget. Witness values never select the shape of this circuit.
pub fn bind_transcript<CS: ConstraintSystem<F>>(
    cs: &mut CS,
    transcript: &[u8; TRANSCRIPT_LEN],
    fields: TranscriptFields<'_>,
) -> Result<(), SynthesisError> {
    let mut cs = cs.namespace(|| "signed transcript");
    let mut bits = Vec::with_capacity(TRANSCRIPT_LEN * 8);
    for (i, byte) in transcript.iter().enumerate() {
        for j in (0..8).rev() {
            if i < TRANSCRIPT_TAG.len() {
                // The prefix is part of the relation, never a witness choice.
                bits.push(Boolean::constant((TRANSCRIPT_TAG[i] >> j) & 1 == 1));
            } else {
                bits.push(Boolean::from(AllocatedBit::alloc(
                    cs.namespace(|| format!("byte {i} bit {j}")),
                    Some((byte >> j) & 1 == 1),
                )?));
            }
        }
    }
    let digest = sha256(cs.namespace(|| "sha256"), &bits)?;
    bind_le_bytes(&mut cs, &digest[..128], fields.digest_lo, "digest low");
    bind_le_bytes(&mut cs, &digest[128..], fields.digest_hi, "digest high");
    let slice = |offset: usize, len: usize| &bits[offset * 8..(offset + len) * 8];
    bind_le_bytes(
        &mut cs,
        slice(FUNDING_TXID_OFFSET, 16),
        fields.funding_lo,
        "funding low",
    );
    bind_le_bytes(
        &mut cs,
        slice(FUNDING_TXID_OFFSET + 16, 16),
        fields.funding_hi,
        "funding high",
    );
    bind_le_bytes(
        &mut cs,
        slice(FUNDING_VOUT_OFFSET, 4),
        fields.funding_vout,
        "funding vout",
    );
    bind_le_bytes(
        &mut cs,
        slice(OUTCOME_INDEX_OFFSET, 4),
        fields.outcome_index,
        "outcome index",
    );
    for (index, (field, label)) in [
        (fields.trader, "trader sats"),
        (fields.maker, "maker sats"),
        (fields.anchor, "anchor sats"),
        (fields.fee, "fee sats"),
    ]
    .into_iter()
    .enumerate()
    {
        bind_le_bytes(&mut cs, slice(AMOUNTS_OFFSET + index * 8, 8), field, label);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_transcript_offsets_and_reference_digest_are_stable() {
        let batch = lnm_batch_statement::fixture::demo_batch(1).unwrap();
        let bytes = signed_row_transcript(&batch, 0).unwrap();
        let row = &batch.rows[0];
        assert_eq!(&bytes[..46], TRANSCRIPT_TAG);
        assert_eq!(&bytes[46..78], &summary_digest(&row.summary));
        assert_eq!(
            &bytes[78..110],
            &batch_consent_message(&batch.context, &row.summary)
        );
        assert_eq!(&bytes[110..174], &row.summary_signatures[0]);
        assert_eq!(&bytes[174..238], &row.summary_signatures[1]);
        assert_eq!(&bytes[238..302], &row.batch_signatures[0]);
        assert_eq!(&bytes[302..366], &row.batch_signatures[1]);
        assert_eq!(bytes[366], row.oracle_attestations[0].oracle_index);
        assert_eq!(&bytes[367..431], &row.oracle_attestations[0].signature);
        assert_eq!(bytes[431], row.oracle_attestations[1].oracle_index);
        assert_eq!(&bytes[432..496], &row.oracle_attestations[1].signature);
        assert_eq!(&bytes[496..500], &row.outcome.index.to_le_bytes());
        assert_eq!(&bytes[500..532], &row.outcome.message);
        for (i, value) in [
            row.outcome.trader_sats,
            row.outcome.maker_sats,
            row.outcome.anchor_sats,
            row.outcome.fee_sats,
        ]
        .into_iter()
        .enumerate()
        {
            assert_eq!(&bytes[532 + i * 8..540 + i * 8], &value.to_le_bytes());
        }
        assert_eq!(&bytes[564..596], &row.summary.funding_txid);
        assert_eq!(&bytes[596..600], &row.summary.funding_vout.to_le_bytes());
    }
}
