//! The fixed row-refutation circuit for one trusted configuration.
//!
//! Output 1 ("refute") iff the challenge context is valid (the claim values hash to the on-chain
//! claim id, the challenge names that id and the claim's replay domain, kind Row, version 1,
//! row < num_cons) and NOT all of: the claim's version / config digest / field byte are pinned
//! and u, X are canonical; the response echoes SHA-256(challenge); the row record is row `i` of
//! the pinned matrix and well-formed; every active W operand opens at its column under root_W,
//! repeated columns agree; E_i opens under root_E; all values canonical; and
//! (Az)_i (Bz)_i = u (Cz)_i + E_i in the pinned field. Same semantics as `checker::adjudicate`.
use super::{
    and_all, be32_bits, const_bytes, eq_bits, eq_const_bytes, eq_const_u, field::PField, flat_verify, is_zero, lt_const, mask, or, parse_item, record_item,
    select, sha256, words_of_bytes, xor_vec, CEnc, Cur, W,
};
use crate::{
    field::FieldId,
    protocol::TrustedConfig,
    shape::{row_record_len, ROW_DOMAIN},
};
use garbled_snark_verifier::{circuit::FALSE_WIRE, CircuitContext};
use m12_gates as g;
use num_bigint::BigUint;

pub struct ClaimW {
    pub id_in: Vec<W>,
    pub version: Vec<W>,
    pub tc: Vec<W>,
    pub field: Vec<W>,
    pub replay: Vec<W>,
    pub comm_w: Vec<W>,
    pub comm_e: Vec<W>,
    pub u: Vec<W>,
    pub x: Vec<Vec<W>>,
    pub root_w: Vec<W>,
    pub root_e: Vec<W>,
    pub root_tw: Vec<W>,
    pub root_te: Vec<W>,
}

pub struct ChW {
    pub index_be: Vec<W>,
    pub index_bits: Vec<W>,
}

pub struct Common {
    pub claim: ClaimW,
    pub ch: ChW,
    pub ctx_ok: W,
    pub claim_ok: W,
    pub ch_hash: Vec<W>,
}

/// Read and check the claim and challenge sections (shared by every FC03 circuit).
#[allow(clippy::too_many_arguments)]
pub fn read_common<C: CircuitContext>(c: &mut C, cur: &mut Cur, tc: &TrustedConfig, tc_digest: &[u8; 32], kind: u8, vec: u8, limit: u64, check_ux: Option<&PField>) -> Common {
    let id_in = cur.bytes(32);
    let version = cur.bytes(4);
    let tcw = cur.bytes(32);
    let field = cur.bytes(1);
    let session = cur.bytes(32);
    let replay = cur.bytes(32);
    let statement = cur.bytes(32);
    let folding = cur.bytes(32);
    let comm_w = cur.bytes(65);
    let comm_e = cur.bytes(65);
    let u = cur.bytes(32);
    let x: Vec<Vec<W>> = (0..tc.num_io).map(|_| cur.bytes(32)).collect();
    let (root_w, root_e, root_tw, root_te) = (cur.bytes(32), cur.bytes(32), cur.bytes(32), cur.bytes(32));
    let ch_version = cur.bytes(4);
    let ch_claim = cur.bytes(32);
    let ch_kind = cur.bytes(1);
    let ch_index = cur.bytes(4);
    let ch_vec = cur.bytes(1);
    let ch_challenger = cur.bytes(32);
    let ch_nonce = cur.bytes(32);
    let ch_replay = cur.bytes(32);

    let mut e = CEnc::new("claim");
    e.field("version", &version)
        .field("tc_digest", &tcw)
        .field("field", &field)
        .field("session_id", &session)
        .field("replay", &replay)
        .field("statement", &statement)
        .field("folding", &folding)
        .field("U.comm_W", &comm_w)
        .field("U.comm_E", &comm_e)
        .field("U.u", &u)
        .field("U.num_x", &const_bytes(&tc.num_io.to_be_bytes()));
    for xi in &x {
        e.field("U.x", xi);
    }
    e.field("root_W", &root_w).field("root_E", &root_e).field("root_trace_W", &root_tw).field("root_trace_E", &root_te);
    let h = sha256(c, e.bytes());
    let index_bits = be32_bits(&ch_index);
    let ctx = [
        eq_bits(c, &h, &words_of_bytes(&id_in)),
        eq_bits(c, &ch_claim, &id_in),
        eq_bits(c, &ch_replay, &replay),
        eq_const_bytes(c, &ch_version, &crate::protocol::VERSION.to_be_bytes()),
        eq_const_bytes(c, &ch_kind, &[kind]),
        eq_const_bytes(c, &ch_vec, &[vec]),
        lt_const(c, &index_bits, &BigUint::from(limit)),
    ];
    let ctx_ok = and_all(c, &ctx);
    let mut cl = vec![
        eq_const_bytes(c, &version, &crate::protocol::VERSION.to_be_bytes()),
        eq_const_bytes(c, &tcw, tc_digest),
        eq_const_bytes(c, &field, &[tc.field]),
    ];
    if let Some(pf) = check_ux {
        cl.push(pf.canonical(c, &u));
        for xi in &x {
            cl.push(pf.canonical(c, xi));
        }
    }
    let claim_ok = and_all(c, &cl);
    let mut ce = CEnc::new("challenge");
    ce.field("version", &ch_version)
        .field("claim_id", &ch_claim)
        .field("kind", &ch_kind)
        .field("index", &ch_index)
        .field("vec", &ch_vec)
        .field("challenger", &ch_challenger)
        .field("nonce", &ch_nonce)
        .field("replay", &ch_replay);
    let ch_hash = sha256(c, ce.bytes());
    Common {
        claim: ClaimW { id_in, version, tc: tcw, field, replay, comm_w, comm_e, u, x, root_w, root_e, root_tw, root_te },
        ch: ChW { index_be: ch_index, index_bits },
        ctx_ok,
        claim_ok,
        ch_hash,
    }
}

pub const DUP_CHECK_MAX_SLOTS: usize = 16;

pub struct RowKnown {
    pub tc: TrustedConfig,
    pub tc_digest: [u8; 32],
    pub pf: PField,
}

impl RowKnown {
    pub fn new(tc: &TrustedConfig) -> Self {
        let f = FieldId::from_byte(tc.field).expect("pinned field");
        RowKnown { tc: tc.clone(), tc_digest: tc.digest(), pf: PField::new(f.modulus()) }
    }
}

pub fn row_circuit<C: CircuitContext>(c: &mut C, k: &RowKnown, w: &[W]) -> W {
    let tc = &k.tc;
    let pf = &k.pf;
    let fid = tc.field;
    let mut cur = Cur::new(w);
    let com = read_common(c, &mut cur, tc, &k.tc_digest, 1, 0, tc.num_cons as u64, Some(pf));
    let kk = [tc.k[0] as usize, tc.k[1] as usize, tc.k[2] as usize];
    let resp_cid = cur.bytes(32);
    let rec = cur.bytes(row_record_len(kk));
    let row_open = cur.opening(tc.matrix_leaves as usize);
    let terms: Vec<_> = (0..kk.iter().sum::<usize>()).map(|_| cur.opening(tc.w_leaves as usize)).collect();
    let e_open = cur.opening(tc.e_leaves as usize);
    cur.done();

    let ridx = &com.ch.index_bits;
    let mut ok: Vec<W> = vec![com.claim_ok];
    ok.push(eq_bits(c, &words_of_bytes(&resp_cid), &com.ch_hash));
    // The row record is row i of the pinned matrix.
    let rec_digest = sha256(c, &rec);
    let rec_item = record_item(fid, crate::enc::tag::ROW, &com.ch.index_be, &rec_digest);
    let mroot = words_of_bytes(&const_bytes(&tc.matrix_root));
    ok.push(flat_verify(c, tc.matrix_leaves as usize, &mroot, ridx, &rec_item, &row_open));
    ok.push(eq_const_bytes(c, &rec[..88], ROW_DOMAIN));
    ok.push(eq_const_bytes(c, &rec[88..96], &[fid]));
    ok.push(eq_bits(c, &be32_bits(&rec[96..128]), ridx));
    let n_cols = (tc.num_vars + 1 + tc.num_io) as u64;
    struct Slot {
        m: usize,
        active: W,
        col: Vec<W>,
        coef: Vec<W>,
    }
    let mut slots = Vec::new();
    let mut off = 16;
    for (m, &km) in kk.iter().enumerate() {
        let nnz = be32_bits(&rec[8 * off..8 * (off + 4)]);
        ok.push(lt_const(c, &nnz, &BigUint::from(km as u64 + 1)));
        off += 4;
        for j in 0..km {
            let col = be32_bits(&rec[8 * off..8 * (off + 4)]);
            let coef = rec[8 * (off + 4)..8 * (off + 36)].to_vec();
            let lt = lt_const(c, &nnz, &BigUint::from(j as u64 + 1));
            let active = g::not(c, lt);
            ok.push(lt_const(c, &col, &BigUint::from(n_cols)));
            ok.push(pf.canonical(c, &coef));
            let zc = is_zero(c, &col);
            let zk = is_zero(c, &coef);
            let pad = g::and(c, zc, zk);
            ok.push(or(c, active, pad));
            slots.push(Slot { m, active, col, coef });
            off += 36;
        }
    }
    let zero = vec![FALSE_WIRE; super::field::N];
    let mut prod = [zero.clone(), zero.clone(), zero];
    let root_w = words_of_bytes(&com.claim.root_w);
    let mut reads: Vec<(W, Vec<W>, Vec<W>)> = Vec::new();
    for (s, sl) in slots.iter().enumerate() {
        let op = &terms[s];
        let is_w = lt_const(c, &sl.col, &BigUint::from(tc.num_vars));
        let is_u = eq_const_u(c, &sl.col, tc.num_vars as u64);
        let sel = select(c, sl.col[0], &op.pair[0], &op.pair[1]);
        let it = parse_item(c, &sel, fid, crate::enc::tag::W);
        let idx_ok = eq_bits(c, &it.index, &sl.col);
        let fv = flat_verify(c, tc.w_leaves as usize, &root_w, &sl.col, &sel, op);
        let canon = pf.canonical(c, &it.payload);
        let open_ok = and_all(c, &[it.ok_fixed, idx_ok, fv, canon]);
        let need = g::and(c, sl.active, is_w);
        let fine = g::not(c, need);
        ok.push(or(c, fine, open_ok));
        let mut z = mask(c, is_w, &it.payload[..super::field::N]);
        let zu = mask(c, is_u, &com.claim.u[..super::field::N]);
        z = xor_vec(c, &z, &zu);
        for (i, xi) in com.claim.x.iter().enumerate() {
            let is_x = eq_const_u(c, &sl.col, tc.num_vars as u64 + 1 + i as u64);
            let zx = mask(c, is_x, &xi[..super::field::N]);
            z = xor_vec(c, &z, &zx);
        }
        let t = pf.mul(c, &sl.coef, &z);
        prod[sl.m] = pf.add(c, &prod[sl.m], &t);
        reads.push((need, sl.col.clone(), it.payload.clone()));
    }
    // Repeated W columns must carry one value. Two valid openings at one index under one root
    // already agree (else SHA-256 collides); the explicit pairwise check is quadratic in the slot
    // count, so it is emitted only for configurations with at most DUP_CHECK_MAX_SLOTS slots.
    let pairs = if reads.len() <= DUP_CHECK_MAX_SLOTS { reads.len() } else { 0 };
    for a in 0..pairs {
        for b in a + 1..pairs {
            let same = eq_bits(c, &reads[a].1, &reads[b].1);
            let both = and_all(c, &[reads[a].0, reads[b].0, same]);
            let eqv = eq_bits(c, &reads[a].2, &reads[b].2);
            let nb = g::not(c, both);
            ok.push(or(c, nb, eqv));
        }
    }
    // E_i.
    let sel = select(c, ridx[0], &e_open.pair[0], &e_open.pair[1]);
    let it = parse_item(c, &sel, fid, crate::enc::tag::E);
    ok.push(it.ok_fixed);
    ok.push(eq_bits(c, &it.index, ridx));
    let root_e = words_of_bytes(&com.claim.root_e);
    ok.push(flat_verify(c, tc.e_leaves as usize, &root_e, ridx, &sel, &e_open));
    ok.push(pf.canonical(c, &it.payload));
    // (Az)(Bz) R^-3 == (u Cz + E) R^-3.
    let lhs = pf.mul(c, &prod[0], &prod[1]);
    let rhs1 = pf.mul(c, &com.claim.u, &prod[2]);
    let e2 = pf.mul_const(c, &it.payload, &pf.rinv.clone());
    let s = pf.add(c, &rhs1, &e2);
    let rhs = pf.mul_const(c, &s, &BigUint::from(1u8));
    ok.push(pf.eq(c, &lhs, &rhs));
    let all = and_all(c, &ok);
    let nall = g::not(c, all);
    g::and(c, com.ctx_ok, nall)
}
