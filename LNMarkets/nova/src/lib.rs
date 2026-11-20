//! Nova folding envelope for the LNMarkets co-signed DLC batch prototype.
//!
//! Each step enforces per-row amount conservation, range checks, cumulative
//! totals, SHA-256 of the exact private signed transcript, and Poseidon binding.
//! BIP340, oracle memberships, exact Bitcoin transactions and SHA256 replay
//! paths are verified by lnm-batch-statement BEFORE the trace is constructed.
//! They are NOT reverified in R1CS: a folded proof alone is insufficient to
//! attest signature validity or Bitcoin spendability. See README.md.
//!
//! Uses the same Pallas scalar Poseidon parameters/gadgets as M18.
#![forbid(unsafe_code)]

use ff::{Field, PrimeFieldBits};
use lnm_batch_statement::{encode_journal, sha256, verify_batch, BatchWitness, Journal};
use m18_utxo_window::cost::G;
use m18_utxo_window::elem::{f_from_le, fu, hash as poseidon, F};
use nova_snark::frontend::gadgets::num::AllocatedNum;
use nova_snark::frontend::{ConstraintSystem, SynthesisError};
use nova_snark::traits::circuit::StepCircuit;

pub mod artifact;
pub mod bip340;
pub mod transcript;
use transcript::{bind_transcript, signed_row_transcript, TranscriptFields, TRANSCRIPT_LEN};

pub const RELATION_ID: &str = "lnmarkets/sha256-transcript-accounting/v2";
pub const STATE_ARITY: usize = 8;
pub const ROWS_MAX: usize = 32;
pub const DOMAIN: u64 = 0x4c4e_4d5f_4e4f_5641; // "LNM_NOVA"
const MONEY_BITS: usize = 51; // Bitcoin MAX_MONEY < 2^51.
const TOTAL_BITS: usize = MONEY_BITS + 5; // At most 32 bounded rows.
const COUNT_BITS: usize = 5; // A step consumes count 0..31 and returns 1..32.

fn fits_bits(value: F, bits: usize) -> bool {
    value.to_le_bits().iter().skip(bits).all(|bit| !*bit)
}

/// The digest of a validated private row includes the original summary and
/// batch-consent messages, BOTH parties' co-signatures and the oracle signatures.
/// The circuit recomputes the digest from the fixed transcript and binds its
/// outpoint/economic fields. The signature equations remain external.
#[derive(Clone, Debug)]
pub struct VerifiedRowDigest {
    pub transcript: [u8; TRANSCRIPT_LEN],
    pub lo: F,
    pub hi: F,
    pub funding_lo: F,
    pub funding_hi: F,
    pub funding_vout: u32,
    pub outcome_index: u32,
    pub collateral: u64,
    pub trader: u64,
    pub maker: u64,
    pub anchor: u64,
    pub fee: u64,
}

impl Default for VerifiedRowDigest {
    fn default() -> Self {
        Self {
            transcript: [0; TRANSCRIPT_LEN],
            lo: F::ZERO,
            hi: F::ZERO,
            funding_lo: F::ZERO,
            funding_hi: F::ZERO,
            funding_vout: 0,
            outcome_index: 0,
            collateral: 0,
            trader: 0,
            maker: 0,
            anchor: 0,
            fee: 0,
        }
    }
}

pub fn digest_from_verified_row(
    batch: &BatchWitness,
    index: usize,
) -> Result<VerifiedRowDigest, String> {
    let row = batch.rows.get(index).ok_or("row index outside batch")?;
    let transcript = signed_row_transcript(batch, index)?;
    let signed = sha256(&transcript);
    Ok(VerifiedRowDigest {
        transcript,
        lo: f_from_le(&signed[..16]),
        hi: f_from_le(&signed[16..]),
        funding_lo: f_from_le(&row.summary.funding_txid[..16]),
        funding_hi: f_from_le(&row.summary.funding_txid[16..]),
        funding_vout: row.summary.funding_vout,
        outcome_index: row.outcome.index,
        collateral: row.summary.collateral_sats,
        trader: row.outcome.trader_sats,
        maker: row.outcome.maker_sats,
        anchor: row.outcome.anchor_sats,
        fee: row.outcome.fee_sats,
    })
}

#[derive(Clone)]
pub struct NovaSettlementStep {
    pub row: VerifiedRowDigest,
}

impl NovaSettlementStep {
    pub fn blank() -> Self {
        Self {
            row: VerifiedRowDigest::default(),
        }
    }
}

pub fn initial_state(journal: &[u8; 276], epoch: u64) -> [F; STATE_ARITY] {
    let h = sha256(journal);
    let lo = f_from_le(&h[..16]);
    let hi = f_from_le(&h[16..]);
    let e = fu(epoch);
    let start_root = poseidon(&[fu(DOMAIN), lo, hi, e]);
    [F::ZERO, F::ZERO, F::ZERO, F::ZERO, start_root, lo, hi, e]
}

fn row_poseidon_input(z: &[F], row: &VerifiedRowDigest) -> [F; 13] {
    [
        fu(DOMAIN),
        z[4],
        row.lo,
        row.hi,
        row.funding_lo,
        row.funding_hi,
        fu(row.funding_vout as u64),
        fu(row.outcome_index as u64),
        fu(row.collateral),
        fu(row.trader),
        fu(row.maker),
        fu(row.anchor),
        fu(row.fee),
    ]
}

/// Native mirror of the constrained accumulator. This does not verify a
/// signature. The caller must derive the row from verify_batch().
pub fn native_step(
    z: &[F; STATE_ARITY],
    row: &VerifiedRowDigest,
) -> Result<[F; STATE_ARITY], String> {
    let bytes = &row.transcript;
    let digest = sha256(bytes);
    if &bytes[..transcript::TRANSCRIPT_TAG.len()] != transcript::TRANSCRIPT_TAG
        || row.lo != f_from_le(&digest[..16])
        || row.hi != f_from_le(&digest[16..])
        || row.funding_lo != f_from_le(&bytes[564..580])
        || row.funding_hi != f_from_le(&bytes[580..596])
        || bytes[496..500] != row.outcome_index.to_le_bytes()
        || bytes[596..600] != row.funding_vout.to_le_bytes()
        || [row.trader, row.maker, row.anchor, row.fee]
            .iter()
            .enumerate()
            .any(|(i, value)| bytes[532 + i * 8..540 + i * 8] != value.to_le_bytes())
    {
        return Err("row digest or fields differ from the fixed signed transcript".into());
    }
    if !fits_bits(z[0], COUNT_BITS) {
        return Err("a Nova batch may contain at most 32 rows".into());
    }
    if z[1..4].iter().any(|&value| !fits_bits(value, TOTAL_BITS))
        || !fits_bits(z[5], 128)
        || !fits_bits(z[6], 128)
        || !fits_bits(z[7], 64)
    {
        return Err("state encoding exceeds its circuit range".into());
    }
    if [row.lo, row.hi, row.funding_lo, row.funding_hi]
        .iter()
        .any(|&value| !fits_bits(value, 128))
    {
        return Err("digest or funding limb exceeds 128 bits".into());
    }
    if [row.collateral, row.trader, row.maker, row.anchor, row.fee]
        .iter()
        .any(|&n| n >= (1u64 << MONEY_BITS))
    {
        return Err("row amount exceeds the 51-bit circuit range".into());
    }
    let payout = row
        .trader
        .checked_add(row.maker)
        .and_then(|n| n.checked_add(row.anchor))
        .ok_or("payout overflow")?;
    if payout.checked_add(row.fee) != Some(row.collateral) {
        return Err("collateral conservation failed".into());
    }
    let next_totals = [
        z[1] + fu(row.collateral),
        z[2] + fu(payout),
        z[3] + fu(row.fee),
    ];
    if next_totals
        .iter()
        .any(|&value| !fits_bits(value, TOTAL_BITS))
    {
        return Err("accumulated amount exceeds the circuit range".into());
    }
    let next_root = poseidon(&row_poseidon_input(z, row));
    Ok([
        z[0] + F::ONE,
        z[1] + fu(row.collateral),
        z[2] + fu(payout),
        z[3] + fu(row.fee),
        next_root,
        z[5],
        z[6],
        z[7],
    ])
}

fn accumulate<CS: ConstraintSystem<F>>(
    g: &mut G<CS>,
    old: &AllocatedNum<F>,
    increment: &AllocatedNum<F>,
    name: &'static str,
) -> AllocatedNum<F> {
    let new =
        g.alloc(old.get_value().unwrap_or(F::ZERO) + increment.get_value().unwrap_or(F::ZERO));
    let (old_var, increment_var, new_var) = (
        old.get_variable(),
        increment.get_variable(),
        new.get_variable(),
    );
    g.cs.enforce(
        || name,
        |lc| lc + old_var + increment_var,
        |lc| lc + CS::one(),
        |lc| lc + new_var,
    );
    new
}

impl StepCircuit<F> for NovaSettlementStep {
    fn arity(&self) -> usize {
        STATE_ARITY
    }

    fn synthesize<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<F>],
    ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
        if z.len() != STATE_ARITY {
            return Err(SynthesisError::Unsatisfiable(
                "expected eight state limbs".into(),
            ));
        }
        let mut g = G::new(cs);
        let a = &self.row;
        // The public initial state is independently pinned by the receiver.
        // Range checks make all carried integer encodings explicit in each step.
        g.range(&z[0], COUNT_BITS);
        for total in &z[1..4] {
            g.range(total, TOTAL_BITS);
        }
        g.range(&z[5], 128);
        g.range(&z[6], 128);
        g.range(&z[7], 64);

        let alloc = |g: &mut G<CS>, name: &'static str, value: F| {
            AllocatedNum::alloc_infallible(g.cs.namespace(|| name), || value)
        };
        let coll = alloc(&mut g, "collateral", fu(a.collateral));
        let trader = alloc(&mut g, "trader", fu(a.trader));
        let maker = alloc(&mut g, "maker", fu(a.maker));
        let anchor = alloc(&mut g, "anchor", fu(a.anchor));
        let fee = alloc(&mut g, "fee", fu(a.fee));
        // Bit decomposition excludes adversarial field wraparound in the
        // satoshi equations. Native validation has the stricter MAX_MONEY cap.
        for x in [&coll, &trader, &maker, &anchor, &fee] {
            g.range(x, MONEY_BITS);
        }
        let payout = alloc(&mut g, "payout", fu(a.trader) + fu(a.maker) + fu(a.anchor));
        let (t, m, anchor_v, fee_v, payout_v, coll_v) = (
            trader.get_variable(),
            maker.get_variable(),
            anchor.get_variable(),
            fee.get_variable(),
            payout.get_variable(),
            coll.get_variable(),
        );
        g.cs.enforce(
            || "payout sum",
            |lc| lc + t + m + anchor_v,
            |lc| lc + CS::one(),
            |lc| lc + payout_v,
        );
        g.cs.enforce(
            || "collateral conservation",
            |lc| lc + payout_v + fee_v,
            |lc| lc + CS::one(),
            |lc| lc + coll_v,
        );

        // A literal coefficient binds the increment. Allocating F::ONE as an
        // unconstrained witness would let a malicious prover choose the count.
        let count = alloc(
            &mut g,
            "count",
            z[0].get_value().unwrap_or(F::ZERO) + F::ONE,
        );
        g.cs.enforce(
            || "increment count",
            |lc| lc + z[0].get_variable() + CS::one(),
            |lc| lc + CS::one(),
            |lc| lc + count.get_variable(),
        );
        let collateral = accumulate(&mut g, &z[1], &coll, "increment collateral");
        let payouts = accumulate(&mut g, &z[2], &payout, "increment payouts");
        let fees = accumulate(&mut g, &z[3], &fee, "increment fees");
        for total in [&collateral, &payouts, &fees] {
            g.range(total, TOTAL_BITS);
        }

        let domain = alloc(&mut g, "domain", fu(DOMAIN));
        g.cs.enforce(
            || "fixed domain",
            |lc| lc + domain.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + (fu(DOMAIN), CS::one()),
        );
        let lo = alloc(&mut g, "digest low", a.lo);
        let hi = alloc(&mut g, "digest high", a.hi);
        let funding_lo = alloc(&mut g, "funding low", a.funding_lo);
        let funding_hi = alloc(&mut g, "funding high", a.funding_hi);
        for limb in [&lo, &hi, &funding_lo, &funding_hi] {
            g.range(limb, 128);
        }
        let vout = alloc(&mut g, "funding vout", fu(a.funding_vout as u64));
        let outcome_index = alloc(&mut g, "outcome index", fu(a.outcome_index as u64));
        g.range(&vout, 32);
        g.range(&outcome_index, 32);

        bind_transcript(
            g.cs,
            &a.transcript,
            TranscriptFields {
                digest_lo: &lo,
                digest_hi: &hi,
                funding_lo: &funding_lo,
                funding_hi: &funding_hi,
                funding_vout: &vout,
                outcome_index: &outcome_index,
                trader: &trader,
                maker: &maker,
                anchor: &anchor,
                fee: &fee,
            },
        )?;

        // Every amount here is the *same R1CS variable* used in the range,
        // conservation and cumulative-total equations above.
        let inputs = [
            domain,
            z[4].clone(),
            lo,
            hi,
            funding_lo,
            funding_hi,
            vout,
            outcome_index,
            coll,
            trader,
            maker,
            anchor,
            fee,
        ];
        let root = {
            let mut ns = g.cs.namespace(|| "row hash");
            G::new(&mut ns).hash(&inputs)
        };
        Ok(vec![
            count,
            collateral,
            payouts,
            fees,
            root,
            z[5].clone(),
            z[6].clone(),
            z[7].clone(),
        ])
    }
}

pub struct VerifiedNovaTrace {
    pub journal: Journal,
    pub journal_bytes: [u8; 276],
    pub initial: Vec<F>,
    pub final_state: Vec<F>,
    pub steps: Vec<NovaSettlementStep>,
}

/// The co-signature and DLC checks happen in the independent native verifier.
/// The Nova step only constrains the folded commitment and accounting layer.
pub fn validated_trace(batch: &BatchWitness) -> Result<VerifiedNovaTrace, String> {
    let journal = verify_batch(batch)?;
    let encoded = encode_journal(&journal);
    let journal_bytes: [u8; 276] = encoded
        .try_into()
        .map_err(|_| "journal encoding changed".to_string())?;
    let initial = initial_state(&journal_bytes, journal.epoch);
    let mut state = initial;
    let mut steps = Vec::with_capacity(batch.rows.len());
    for index in 0..batch.rows.len() {
        let row = digest_from_verified_row(batch, index)?;
        state = native_step(&state, &row)?;
        steps.push(NovaSettlementStep { row });
    }
    if state[0] != fu(journal.row_count as u64)
        || state[1] != fu(journal.total_collateral_sats)
        || state[2] != fu(journal.total_payout_sats)
        || state[3] != fu(journal.total_fee_sats)
    {
        return Err("fold totals differ from the pinned native journal".into());
    }
    Ok(VerifiedNovaTrace {
        journal,
        journal_bytes,
        initial: initial.to_vec(),
        final_state: state.to_vec(),
        steps,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use nova_snark::frontend::util_cs::test_cs::TestConstraintSystem;

    fn synthesize_row(step: &NovaSettlementStep, z: &[F]) -> (bool, Vec<F>) {
        let mut cs = TestConstraintSystem::<F>::new();
        let inputs: Vec<_> = z
            .iter()
            .enumerate()
            .map(|(i, v)| AllocatedNum::alloc_infallible(cs.namespace(|| format!("z{i}")), || *v))
            .collect();
        let output = step
            .synthesize(&mut cs, &inputs)
            .expect("circuit synthesis");
        (
            cs.is_satisfied(),
            output.iter().map(|x| x.get_value().unwrap()).collect(),
        )
    }

    #[test]
    fn native_verified_rows_match_r1cs_trace_for_1_2_and_8() {
        for n in [1, 2, 8] {
            let batch = lnm_batch_statement::fixture::demo_batch(n).unwrap();
            let trace = validated_trace(&batch).unwrap();
            let mut z = trace.initial.clone();
            for step in &trace.steps {
                let (ok, next) = synthesize_row(step, &z);
                assert!(ok, "step R1CS unsatisfied");
                z = next;
            }
            assert_eq!(z, trace.final_state);
            assert_eq!(trace.journal.row_count as usize, n);
            assert_eq!(trace.journal_bytes.len(), 276);
        }
    }

    #[test]
    fn altered_payout_with_stale_collateral_is_unsatisfiable() {
        let batch = lnm_batch_statement::fixture::demo_batch(1).unwrap();
        let trace = validated_trace(&batch).unwrap();
        let mut broken = trace.steps[0].clone();
        broken.row.maker += 1;
        let (ok, _) = synthesize_row(&broken, &trace.initial);
        assert!(!ok);
    }

    #[test]
    fn changed_row_digest_with_stale_transcript_is_unsatisfiable() {
        let batch = lnm_batch_statement::fixture::demo_batch(1).unwrap();
        let trace = validated_trace(&batch).unwrap();
        let mut broken = trace.steps[0].clone();
        broken.row.lo += F::ONE;
        let (ok, computed) = synthesize_row(&broken, &trace.initial);
        assert!(!ok);
        assert_ne!(computed[4], trace.final_state[4]);
        assert!(native_step(&trace.initial.clone().try_into().unwrap(), &broken.row).is_err());
    }

    #[test]
    fn tampered_original_signature_is_refused_before_trace_building() {
        let mut batch = lnm_batch_statement::fixture::demo_batch(1).unwrap();
        batch.rows[0].batch_signatures[0][0] ^= 1;
        assert!(validated_trace(&batch).is_err());
    }

    #[test]
    fn excessive_satoshi_value_fails_r1cs_range_check() {
        let batch = lnm_batch_statement::fixture::demo_batch(1).unwrap();
        let trace = validated_trace(&batch).unwrap();
        let mut broken = trace.steps[0].clone();
        broken.row.collateral = 1u64 << MONEY_BITS;
        let (ok, _) = synthesize_row(&broken, &trace.initial);
        assert!(!ok);
    }
}
