//! The fixed binding-step circuit for one trusted configuration and one vector (W or E): decides
//! whether transition t of the committed double-and-add trace is wrong. Curve arithmetic is the
//! RCB complete addition (`field::rcb_add`) in Montgomery form over the commitment group's
//! coordinate field. Same semantics as `checker::step_check`.
use super::{
    and_all, be32_bits, be32_bytes, const_bytes, eq_bits, eq_const_bytes, eq_const_u, field::PField, flat_verify, inc32, is_zero, lt_const, or,
    parse_item, record_item, row::read_common, select, sha256, words_of_bytes, Cur, W,
};
use crate::{
    binding::{GEN_DOMAIN, TRACE_DOMAIN},
    field::FieldId,
    protocol::{TrustedConfig, Vector},
};
use garbled_snark_verifier::{circuit::FALSE_WIRE, CircuitContext};
use m12_gates as g;
use num_bigint::BigUint;

pub struct StepKnown {
    pub tc: TrustedConfig,
    pub tc_digest: [u8; 32],
    pub v: Vector,
    pub sf: PField,
    pub bf: PField,
}

impl StepKnown {
    pub fn new(tc: &TrustedConfig, v: Vector) -> Self {
        let f = FieldId::from_byte(tc.field).expect("pinned field");
        StepKnown { tc: tc.clone(), tc_digest: tc.digest(), v, sf: PField::new(f.modulus()), bf: PField::new(f.base_modulus()) }
    }
}

/// A 65-byte point: canonical-encoding flag, infinity flag, Montgomery coordinates.
struct PtW {
    ok: W,
    inf: W,
    x: Vec<W>,
    y: Vec<W>,
}

fn point<C: CircuitContext>(c: &mut C, f: &PField, b: &[W]) -> PtW {
    assert_eq!(b.len(), 65 * 8);
    let inf = b[0];
    let flag_ok = is_zero(c, &b[1..8]);
    let (xb, yb) = (&b[8..264], &b[264..520]);
    let cx = f.canonical(c, xb);
    let cy = f.canonical(c, yb);
    let zx = is_zero(c, xb);
    let zy = is_zero(c, yb);
    let zero_xy = g::and(c, zx, zy);
    let not_inf = g::not(c, inf);
    let inf_ok = or(c, not_inf, zero_xy);
    let ok = and_all(c, &[flag_ok, cx, cy, inf_ok]);
    let x = f.to_mont(c, xb);
    let y = f.to_mont(c, yb);
    PtW { ok, inf, x, y }
}

struct Proj {
    x: Vec<W>,
    y: Vec<W>,
    z: Vec<W>,
}

fn to_proj<C: CircuitContext>(c: &mut C, f: &PField, p: &PtW) -> Proj {
    let one = f.mont_const(1);
    let zero = vec![FALSE_WIRE; super::field::N];
    Proj { x: select(c, p.inf, &p.x, &zero), y: select(c, p.inf, &p.y, &one), z: select(c, p.inf, &one, &zero) }
}

fn times15<C: CircuitContext>(c: &mut C, f: &PField, a: &[W]) -> Vec<W> {
    let t2 = f.add(c, a, a);
    let t4 = f.add(c, &t2, &t2);
    let t8 = f.add(c, &t4, &t4);
    let t16 = f.add(c, &t8, &t8);
    f.sub(c, &t16, a)
}

/// RCB 2016 Algorithm 7 (a = 0, b3 = 15), step for step as `field::rcb_add`.
fn rcb_add<C: CircuitContext>(c: &mut C, f: &PField, p: &Proj, q: &Proj) -> Proj {
    let (x1, y1, z1, x2, y2, z2) = (&p.x, &p.y, &p.z, &q.x, &q.y, &q.z);
    let mut t0 = f.mul(c, x1, x2);
    let mut t1 = f.mul(c, y1, y2);
    let mut t2 = f.mul(c, z1, z2);
    let mut t3 = f.add(c, x1, y1);
    let mut t4 = f.add(c, x2, y2);
    t3 = f.mul(c, &t3, &t4);
    t4 = f.add(c, &t0, &t1);
    t3 = f.sub(c, &t3, &t4);
    t4 = f.add(c, y1, z1);
    let mut x3 = f.add(c, y2, z2);
    t4 = f.mul(c, &t4, &x3);
    x3 = f.add(c, &t1, &t2);
    t4 = f.sub(c, &t4, &x3);
    x3 = f.add(c, x1, z1);
    let mut y3 = f.add(c, x2, z2);
    x3 = f.mul(c, &x3, &y3);
    y3 = f.add(c, &t0, &t2);
    y3 = f.sub(c, &x3, &y3);
    x3 = f.add(c, &t0, &t0);
    t0 = f.add(c, &x3, &t0);
    t2 = times15(c, f, &t2);
    let mut z3 = f.add(c, &t1, &t2);
    t1 = f.sub(c, &t1, &t2);
    y3 = times15(c, f, &y3);
    x3 = f.mul(c, &t4, &y3);
    t2 = f.mul(c, &t3, &t1);
    x3 = f.sub(c, &t2, &x3);
    y3 = f.mul(c, &y3, &t0);
    t1 = f.mul(c, &t1, &z3);
    y3 = f.add(c, &t1, &y3);
    t0 = f.mul(c, &t0, &t3);
    z3 = f.mul(c, &z3, &t4);
    z3 = f.add(c, &z3, &t0);
    Proj { x: x3, y: y3, z: z3 }
}

/// Does projective p represent affine a? (identity iff Z = 0; else X = xZ and Y = yZ.)
fn proj_eq_aff<C: CircuitContext>(c: &mut C, f: &PField, p: &Proj, a: &PtW) -> W {
    let zz = f.is_zero(c, &p.z);
    let xz = f.mul(c, &a.x, &p.z);
    let yz = f.mul(c, &a.y, &p.z);
    let ex = f.eq(c, &p.x, &xz);
    let ey = f.eq(c, &p.y, &yz);
    let nz = g::not(c, zz);
    let fin = and_all(c, &[nz, ex, ey]);
    g::mux(c, a.inf, fin, zz)
}

/// Bit b (8 bits, LSB first) of a 256-bit value: a 255-mux tree.
fn bit_at<C: CircuitContext>(c: &mut C, v: &[W], b: &[W]) -> W {
    let mut layer: Vec<W> = v[..256].to_vec();
    for &sb in b.iter().take(8) {
        layer = layer.chunks(2).map(|p| g::mux(c, sb, p[0], p[1])).collect();
    }
    layer[0]
}

pub fn step_circuit<C: CircuitContext>(c: &mut C, k: &StepKnown, w: &[W]) -> W {
    let tc = &k.tc;
    let fid = tc.field;
    let v = k.v;
    let n = tc.n_vec(v) as u64;
    let mut cur = Cur::new(w);
    let com = read_common(c, &mut cur, tc, &k.tc_digest, 3, v.byte(), tc.trace_steps(v) as u64, None);
    let resp_cid = cur.bytes(32);
    let rec0 = cur.bytes(crate::binding::TRACE_RECORD_LEN);
    let op0 = cur.opening(tc.trace_leaves(v) as usize);
    let rec1 = cur.bytes(crate::binding::TRACE_RECORD_LEN);
    let op1 = cur.opening(tc.trace_leaves(v) as usize);
    let ops = cur.opening(tc.vec_leaves(v) as usize);
    let grec = cur.bytes(crate::binding::GEN_RECORD_LEN);
    let opg = cur.opening(tc.ck_leaves as usize);
    cur.done();

    let step = &com.ch.index_bits;
    let b_bits = &step[..8];
    let j_bits: Vec<W> = (0..32).map(|i| if i < 24 { step[i + 8] } else { FALSE_WIRE }).collect();
    let next_bits = inc32(c, step);
    let (troot, vroot) = match v {
        Vector::W => (&com.claim.root_tw, &com.claim.root_w),
        Vector::E => (&com.claim.root_te, &com.claim.root_e),
    };
    let troot = words_of_bytes(troot);
    let vroot = words_of_bytes(vroot);

    // Response validity: every operand authenticated.
    let mut ok: Vec<W> = vec![com.claim_ok];
    ok.push(eq_bits(c, &words_of_bytes(&resp_cid), &com.ch_hash));
    let d0 = sha256(c, &rec0);
    let it0 = record_item(fid, v.trace_tag(), &com.ch.index_be, &d0);
    ok.push(flat_verify(c, tc.trace_leaves(v) as usize, &troot, step, &it0, &op0));
    let d1 = sha256(c, &rec1);
    let it1 = record_item(fid, v.trace_tag(), &be32_bytes(&next_bits), &d1);
    ok.push(flat_verify(c, tc.trace_leaves(v) as usize, &troot, &next_bits, &it1, &op1));
    let sel = select(c, j_bits[0], &ops.pair[0], &ops.pair[1]);
    let si = parse_item(c, &sel, fid, v.value_tag());
    ok.push(si.ok_fixed);
    ok.push(eq_bits(c, &si.index, &j_bits));
    ok.push(flat_verify(c, tc.vec_leaves(v) as usize, &vroot, &j_bits, &sel, &ops));
    let b255 = eq_const_u(c, b_bits, 255);
    let j_lt_n = lt_const(c, &j_bits, &BigUint::from(n));
    let need_gen = g::and(c, b255, j_lt_n);
    let j1 = inc32(c, &j_bits);
    let j1_is_n = eq_const_u(c, &j1, n);
    let gi = select(c, j1_is_n, &j1, &g::const_bits(tc.ck_len as u128, 32));
    let dg = sha256(c, &grec);
    let itg = record_item(fid, crate::enc::tag::GEN, &be32_bytes(&gi), &dg);
    let ckroot = words_of_bytes(&const_bytes(&tc.ck_root));
    let gv = flat_verify(c, tc.ck_leaves as usize, &ckroot, &gi, &itg, &opg);
    let ng = g::not(c, need_gen);
    ok.push(or(c, ng, gv));

    // Committed data well-formed (else the operator committed garbage: refute).
    let rec_ok = |c: &mut C, r: &[W], t: &[W]| -> W {
        let d = eq_const_bytes(c, &r[..13 * 8], TRACE_DOMAIN);
        let f = eq_const_bytes(c, &r[13 * 8..15 * 8], &[fid, v.byte()]);
        let f = g::and(c, d, f);
        let tt = eq_bits(c, &be32_bits(&r[15 * 8..19 * 8]), t);
        g::and(c, f, tt)
    };
    ok.push(rec_ok(c, &rec0, step));
    ok.push(rec_ok(c, &rec1, &next_bits));
    let bf = &k.bf;
    let acc = point(c, bf, &rec0[19 * 8..84 * 8]);
    let p = point(c, bf, &rec0[84 * 8..149 * 8]);
    let acc2 = point(c, bf, &rec1[19 * 8..84 * 8]);
    let p2 = point(c, bf, &rec1[84 * 8..149 * 8]);
    ok.extend([acc.ok, p.ok, acc2.ok, p2.ok]);
    ok.push(k.sf.canonical(c, &si.payload));
    let bit = bit_at(c, &si.payload, b_bits);

    // acc' = acc + bit P.
    let pa = to_proj(c, bf, &acc);
    let pp = to_proj(c, bf, &p);
    let sum = rcb_add(c, bf, &pa, &pp);
    let exp = Proj { x: select(c, bit, &pa.x, &sum.x), y: select(c, bit, &pa.y, &sum.y), z: select(c, bit, &pa.z, &sum.z) };
    ok.push(proj_eq_aff(c, bf, &exp, &acc2));
    // P' = 2P (b < 255), G_{j+1} (b = 255, j < n), O (b = 255, j = n).
    let dbl = rcb_add(c, bf, &pp, &pp);
    let ok_dbl = proj_eq_aff(c, bf, &dbl, &p2);
    let gen_dom = eq_const_bytes(c, &grec[..11 * 8], GEN_DOMAIN);
    let gen_pt = eq_bits(c, &rec1[84 * 8..149 * 8], &grec[16 * 8..81 * 8]);
    let ok_gen = g::and(c, gen_dom, gen_pt);
    let ok_last = g::mux(c, j_lt_n, p2.inf, ok_gen);
    ok.push(g::mux(c, b255, ok_dbl, ok_last));

    let all = and_all(c, &ok);
    let nall = g::not(c, all);
    g::and(c, com.ctx_ok, nall)
}
