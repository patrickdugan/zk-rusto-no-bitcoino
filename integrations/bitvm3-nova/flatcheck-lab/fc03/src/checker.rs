//! The native FC03 adjudicator: one challenge, one local predicate, one verdict.
//!
//! Verdict semantics (shared bit-for-bit with the garbled circuits and the Python reference):
//! - `ChallengeInvalid`: the challenge does not name this claim, its replay domain differs, the
//!   version is unknown, or its index is out of range. Never a refutation.
//! - otherwise the challenge refutes the claim unless the claim's fields used by the predicate
//!   are well-formed under the trusted configuration, the response is present, answers exactly
//!   this challenge and authenticates every operand, and the predicate holds on those operands.
use crate::{
    binding,
    enc::{self, tag},
    field::{aff_from_bytes, fe_from_bytes, point_from_bytes, proj_eq_aff, rcb_add, to_proj, FcEngine, PointBytes},
    flatmerkle::{self, Opening},
    protocol::*,
    sha,
    shape::{parse_row_record, row_record_len},
};
use ff::{Field, PrimeField, PrimeFieldBits};
use nova_snark::{
    constants::NUM_CHALLENGE_BITS,
    gadgets::utils::{base_as_scalar, scalar_as_base},
    provider::traits::{DlogGroup, DlogGroupExt},
    traits::{Engine, ROConstants, ROTrait},
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    ChallengeInvalid(String),
    ClaimInvalid(String),
    ResponseMissing,
    ResponseInvalid(String),
    Holds,
    Violated(String),
}

impl Verdict {
    pub fn refutes(&self) -> bool {
        !matches!(self, Verdict::ChallengeInvalid(_) | Verdict::Holds)
    }
    pub fn code(&self) -> &'static str {
        match self {
            Verdict::ChallengeInvalid(_) => "challenge_invalid",
            Verdict::ClaimInvalid(_) => "claim_invalid",
            Verdict::ResponseMissing => "response_missing",
            Verdict::ResponseInvalid(_) => "response_invalid",
            Verdict::Holds => "holds",
            Verdict::Violated(_) => "violated",
        }
    }
}

macro_rules! bail {
    ($v:ident, $($t:tt)*) => { return Verdict::$v(format!($($t)*)) };
}

fn k_of(tc: &TrustedConfig) -> [usize; 3] {
    [tc.k[0] as usize, tc.k[1] as usize, tc.k[2] as usize]
}

/// Context validity: identical to `ctx_ok` in the circuits.
pub fn challenge_valid(tc: &TrustedConfig, claim: &FlatCheckClaim, ch: &FlatCheckChallenge) -> Result<(), String> {
    if ch.version != VERSION {
        return Err("challenge version".into());
    }
    if ch.claim_id != claim.id() {
        return Err("challenge names another claim".into());
    }
    if ch.replay.digest() != claim.replay.digest() {
        return Err("replay domain differs from the claim's".into());
    }
    match ch.kind {
        ChallengeKind::Row { row } if row >= tc.num_cons => Err(format!("row {row} out of range")),
        ChallengeKind::BindingStep { vec, step } if step >= tc.trace_steps(vec) => Err(format!("step {step} out of range")),
        _ => Ok(()),
    }
}

pub fn adjudicate<E: FcEngine>(tc: &TrustedConfig, claim: &FlatCheckClaim, ch: &FlatCheckChallenge, resp: Option<&FlatCheckResponse>) -> Verdict
where
    E::GE: DlogGroup + DlogGroupExt,
    E::Scalar: PrimeFieldBits,
    E::Base: PrimeFieldBits,
{
    if let Err(e) = challenge_valid(tc, claim, ch) {
        return Verdict::ChallengeInvalid(e);
    }
    if claim.version != VERSION {
        bail!(ClaimInvalid, "claim version");
    }
    if claim.tc_digest != tc.digest() {
        bail!(ClaimInvalid, "claim is not under the pinned trusted configuration");
    }
    if claim.field != tc.field || claim.field != E::FIELD.byte() {
        bail!(ClaimInvalid, "claim field {} differs from the pinned field {}", claim.field, tc.field);
    }
    if let ChallengeKind::Claim = ch.kind {
        return match claim_public_check::<E>(tc, claim) {
            Ok(()) => Verdict::Holds,
            Err(e) => Verdict::Violated(e),
        };
    }
    let Some(resp) = resp else { return Verdict::ResponseMissing };
    if resp.challenge_id() != ch.id() {
        bail!(ResponseInvalid, "response answers another challenge");
    }
    match (ch.kind, resp) {
        (ChallengeKind::Row { row }, FlatCheckResponse::Row(r)) => row_check::<E>(tc, claim, row, r),
        (ChallengeKind::BindingStep { vec, step }, FlatCheckResponse::Step(r)) => step_check::<E>(tc, claim, vec, step, r),
        (ChallengeKind::BindingStart { vec }, FlatCheckResponse::Start(r)) => start_check::<E>(tc, claim, vec, r),
        (ChallengeKind::BindingEnd { vec }, FlatCheckResponse::End(r)) => end_check::<E>(tc, claim, vec, r),
        _ => Verdict::ResponseInvalid("response kind differs from the challenge".into()),
    }
}

/// An authenticated value record: the opening verifies at `index` and the item is
/// (field, tag, index, payload). Returns the payload.
fn open_value(fid: u8, tg: u8, leaves: u32, root: &[u8; 32], index: u32, o: &OpeningJ) -> Option<[u8; 32]> {
    let op: Opening = o.into();
    let it = op.pair[(op.index & 1) as usize];
    let v = enc::parse_item(&it)?;
    if v.field_id != fid || v.tag != tg || v.index != index {
        return None;
    }
    flatmerkle::verify(leaves as usize, root, index as usize, &it, &op).then_some(v.payload)
}

/// An authenticated record whose item payload is SHA-256(record).
fn open_record(fid: u8, tg: u8, leaves: u32, root: &[u8; 32], index: u32, r: &RecordOpen) -> bool {
    let it = enc::item(fid, tg, index, &sha::sha256(&r.record));
    let op: Opening = (&r.open).into();
    op.pair[(op.index & 1) as usize] == it && flatmerkle::verify(leaves as usize, root, index as usize, &it, &op)
}

fn row_check<E: FcEngine>(tc: &TrustedConfig, claim: &FlatCheckClaim, row: u32, r: &RowResponse) -> Verdict
where
    E::GE: DlogGroup + DlogGroupExt,
{
    let fid = tc.field;
    let Some(u) = fe_from_bytes::<E::Scalar>(&claim.instance.u) else { bail!(ClaimInvalid, "u is not canonical") };
    if claim.instance.x.len() != tc.num_io as usize {
        bail!(ClaimInvalid, "public IO length");
    }
    let mut x = Vec::new();
    for xb in &claim.instance.x {
        let Some(v) = fe_from_bytes::<E::Scalar>(xb) else { bail!(ClaimInvalid, "X is not canonical") };
        x.push(v);
    }
    let k = k_of(tc);
    let n_cols = (tc.num_vars + 1 + tc.num_io) as usize;
    if r.row_record.len() != row_record_len(k) {
        bail!(ResponseInvalid, "row record length");
    }
    if !open_record(fid, tag::ROW, tc.matrix_leaves, &tc.matrix_root, row, &RecordOpen { record: r.row_record.clone(), open: r.row_open.clone() }) {
        bail!(ResponseInvalid, "row record is not row {row} of the pinned matrix");
    }
    let Some(rec) = parse_row_record::<E::Scalar>(&r.row_record, fid, k, n_cols) else { bail!(ResponseInvalid, "row record malformed") };
    if rec.row != row {
        bail!(ResponseInvalid, "row record index");
    }
    if r.terms.len() != k.iter().sum::<usize>() {
        bail!(ResponseInvalid, "term count");
    }
    let mut seen: Vec<(u32, E::Scalar)> = Vec::new();
    let mut prod = [E::Scalar::ZERO; 3];
    let mut slot = 0;
    for m in 0..3 {
        for j in 0..k[m] {
            let (col, coef) = rec.slots[m][j];
            let active = (j as u32) < rec.nnz[m];
            let o = &r.terms[slot];
            slot += 1;
            if !active {
                continue;
            }
            let z = if col < tc.num_vars {
                let Some(vb) = open_value(fid, tag::W, tc.w_leaves, &claim.root_w, col, o) else {
                    bail!(ResponseInvalid, "W[{col}] opening does not verify against root_W")
                };
                let Some(v) = fe_from_bytes::<E::Scalar>(&vb) else { bail!(Violated, "committed W[{col}] is not canonical") };
                if let Some((_, prev)) = seen.iter().find(|(c, _)| *c == col) {
                    if *prev != v {
                        bail!(ResponseInvalid, "inconsistent repeated operand W[{col}]");
                    }
                }
                seen.push((col, v));
                v
            } else if col == tc.num_vars {
                u
            } else {
                x[(col - tc.num_vars - 1) as usize]
            };
            prod[m] += coef * z;
        }
    }
    let Some(eb) = open_value(fid, tag::E, tc.e_leaves, &claim.root_e, row, &r.e_open) else {
        bail!(ResponseInvalid, "E[{row}] opening does not verify against root_E")
    };
    let Some(e) = fe_from_bytes::<E::Scalar>(&eb) else { bail!(Violated, "committed E[{row}] is not canonical") };
    if prod[0] * prod[1] == u * prod[2] + e {
        Verdict::Holds
    } else {
        Verdict::Violated(format!("(Az)(Bz) != u(Cz) + E at row {row}"))
    }
}

fn decode_state<F: PrimeField>(fid: u8, v: Vector, t: u32, rec: &[u8]) -> Result<(crate::field::Aff<F>, crate::field::Aff<F>), String> {
    let (tt, a, p) = binding::parse_trace_record(rec, fid, v).ok_or("trace record malformed")?;
    if tt != t {
        return Err(format!("trace record says step {tt}, sits at {t}"));
    }
    let a = aff_from_bytes::<F>(&a).ok_or("trace accumulator not canonical")?;
    let p = aff_from_bytes::<F>(&p).ok_or("trace point not canonical")?;
    Ok((a, p))
}


fn step_check<E: FcEngine>(tc: &TrustedConfig, claim: &FlatCheckClaim, v: Vector, step: u32, r: &StepResponse) -> Verdict
where
    E::GE: DlogGroup + DlogGroupExt,
    E::Scalar: PrimeFieldBits,
{
    let fid = tc.field;
    let (leaves, root) = (tc.trace_leaves(v), claim.trace_root(v));
    let (j, b) = (step / 256, step % 256);
    let n = tc.n_vec(v);
    if !open_record(fid, v.trace_tag(), leaves, &root, step, &r.cur) {
        bail!(ResponseInvalid, "trace state {step} does not verify");
    }
    if !open_record(fid, v.trace_tag(), leaves, &root, step + 1, &r.next) {
        bail!(ResponseInvalid, "trace state {} does not verify", step + 1);
    }
    let Some(sb) = open_value(fid, v.value_tag(), tc.vec_leaves(v), &claim.root(v), j, &r.scalar) else {
        bail!(ResponseInvalid, "scalar {j} does not verify")
    };
    let need_gen = b == 255 && j < n;
    let gi = binding::gen_index(n, tc.ck_len, j + 1);
    if need_gen && !open_record(fid, tag::GEN, tc.ck_leaves, &tc.ck_root, gi, &r.gen) {
        bail!(ResponseInvalid, "generator {gi} does not verify against the pinned key");
    }
    let (acc, p) = match decode_state::<E::Base>(fid, v, step, &r.cur.record) {
        Ok(s) => s,
        Err(e) => bail!(Violated, "{e}"),
    };
    let (acc2, p2) = match decode_state::<E::Base>(fid, v, step + 1, &r.next.record) {
        Ok(s) => s,
        Err(e) => bail!(Violated, "{e}"),
    };
    let Some(s) = fe_from_bytes::<E::Scalar>(&sb) else { bail!(Violated, "committed scalar {j} is not canonical") };
    let bit = s.to_le_bits().get(b as usize).map(|x| *x).unwrap_or(false);
    let pa = to_proj(&acc);
    let pp = to_proj(&p);
    let exp_acc = if bit { rcb_add(&pa, &pp) } else { pa };
    let ok_acc = proj_eq_aff(&exp_acc, &acc2);
    let ok_p = if b < 255 {
        proj_eq_aff(&rcb_add(&pp, &pp), &p2)
    } else if j < n {
        let Some((gj, g)) = binding::parse_gen_record(&r.gen.record, fid) else { bail!(ResponseInvalid, "generator record malformed") };
        let Some(ga) = aff_from_bytes::<E::Base>(&g) else { bail!(ResponseInvalid, "generator not canonical") };
        gj == gi && ga == p2
    } else {
        p2.inf
    };
    if ok_acc && ok_p {
        Verdict::Holds
    } else {
        Verdict::Violated(format!("binding transition {step} of {v:?} is wrong (acc ok: {ok_acc}, point ok: {ok_p})"))
    }
}

fn start_check<E: FcEngine>(tc: &TrustedConfig, claim: &FlatCheckClaim, v: Vector, r: &StartResponse) -> Verdict
where
    E::GE: DlogGroup + DlogGroupExt,
{
    let fid = tc.field;
    if !open_record(fid, v.trace_tag(), tc.trace_leaves(v), &claim.trace_root(v), 0, &r.first) {
        bail!(ResponseInvalid, "trace state 0 does not verify");
    }
    if !open_record(fid, tag::GEN, tc.ck_leaves, &tc.ck_root, 0, &r.gen0) {
        bail!(ResponseInvalid, "generator 0 does not verify");
    }
    let (acc, p) = match decode_state::<E::Base>(fid, v, 0, &r.first.record) {
        Ok(s) => s,
        Err(e) => bail!(Violated, "{e}"),
    };
    let Some((0, g)) = binding::parse_gen_record(&r.gen0.record, fid) else { bail!(ResponseInvalid, "generator record malformed") };
    match aff_from_bytes::<E::Base>(&g) {
        Some(ga) if acc.inf && ga == p => Verdict::Holds,
        _ => Verdict::Violated("trace does not start at (O, G_0)".into()),
    }
}

fn end_check<E: FcEngine>(tc: &TrustedConfig, claim: &FlatCheckClaim, v: Vector, r: &EndResponse) -> Verdict
where
    E::GE: DlogGroup + DlogGroupExt,
{
    let fid = tc.field;
    let last = tc.trace_steps(v);
    let comm = claim.comm(v);
    let Some(ca) = aff_from_bytes::<E::Base>(&comm) else { bail!(ClaimInvalid, "commitment encoding is not canonical") };
    if !open_record(fid, v.trace_tag(), tc.trace_leaves(v), &claim.trace_root(v), last, &r.last) {
        bail!(ResponseInvalid, "last trace state does not verify");
    }
    let (acc, _) = match decode_state::<E::Base>(fid, v, last, &r.last.record) {
        Ok(s) => s,
        Err(e) => bail!(Violated, "{e}"),
    };
    if acc == ca {
        Verdict::Holds
    } else {
        Verdict::Violated(format!("binding trace of {v:?} ends at another point than the instance's commitment"))
    }
}

fn absorb_point<E: Engine>(ro: &mut E::RO, b: &PointBytes) -> Result<(), String> {
    let a = aff_from_bytes::<E::Base>(b).ok_or("point not canonical")?;
    ro.absorb(a.x);
    ro.absorb(a.y);
    ro.absorb(if a.inf { E::Base::ONE } else { E::Base::ZERO });
    Ok(())
}

fn scalars<F: PrimeField>(v: &[[u8; 32]], n: u32) -> Result<Vec<F>, String> {
    if v.len() != n as usize {
        return Err("public IO length".into());
    }
    v.iter().map(|b| fe_from_bytes::<F>(b).ok_or_else(|| "scalar not canonical".to_string())).collect()
}

/// Public-data checks of a claim: network and pp digest pinned, every point on the curve, every
/// scalar canonical, and U = fold(U1, U2, comm_T) with Nova's Poseidon challenge.
pub fn claim_public_check<E: FcEngine>(tc: &TrustedConfig, c: &FlatCheckClaim) -> Result<(), String>
where
    E::GE: DlogGroup + DlogGroupExt,
{
    if c.replay.network != tc.network {
        return Err("claim network differs from the pinned network".into());
    }
    if c.statement.pp_digest != tc.pp_digest {
        return Err("statement pp digest differs from the pinned one".into());
    }
    let pt = |b: &PointBytes| point_from_bytes::<E>(b).ok_or_else(|| "point off the curve or non-canonical".to_string());
    let (u1w, u1e, u2w, ct) = (pt(&c.folding.u1.comm_w)?, pt(&c.folding.u1.comm_e)?, pt(&c.folding.u2.comm_w)?, pt(&c.folding.comm_t)?);
    let (uw, ue) = (pt(&c.instance.comm_w)?, pt(&c.instance.comm_e)?);
    let u1u = fe_from_bytes::<E::Scalar>(&c.folding.u1.u).ok_or("U1.u not canonical")?;
    let uu = fe_from_bytes::<E::Scalar>(&c.instance.u).ok_or("U.u not canonical")?;
    let x1 = scalars::<E::Scalar>(&c.folding.u1.x, tc.num_io)?;
    let x2 = scalars::<E::Scalar>(&c.folding.u2.x, tc.num_io)?;
    let xu = scalars::<E::Scalar>(&c.instance.x, tc.num_io)?;
    let pp = fe_from_bytes::<E::Scalar>(&c.statement.pp_digest).ok_or("pp digest not canonical")?;
    let mut ro = E::RO::new(ROConstants::<E>::default());
    ro.absorb(scalar_as_base::<E>(pp));
    absorb_point::<E>(&mut ro, &c.folding.u2.comm_w)?;
    for x in &x2 {
        ro.absorb(scalar_as_base::<E>(*x));
    }
    absorb_point::<E>(&mut ro, &c.folding.comm_t)?;
    let r = base_as_scalar::<E>(ro.squeeze(NUM_CHALLENGE_BITS, false));
    if uw != u1w + u2w * r {
        return Err("comm_W != U1.comm_W + r U2.comm_W".into());
    }
    if ue != u1e + ct * r {
        return Err("comm_E != U1.comm_E + r comm_T".into());
    }
    if uu != u1u + r {
        return Err("u != U1.u + r".into());
    }
    if xu.iter().zip(x1.iter().zip(&x2)).any(|(xu, (a, b))| *xu != *a + r * *b) {
        return Err("X != U1.X + r U2.X".into());
    }
    Ok(())
}
