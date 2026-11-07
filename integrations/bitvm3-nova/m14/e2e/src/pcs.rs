//! PCS stage of the final verifier circuit: sp1-hypercube's jagged PCS
//! (`JaggedPcsVerifier::verify_trusted_evaluations`), the jagged evaluation sub-protocol with its
//! branching program, the stacked PCS and BaseFold with Merkle tensor openings and FRI queries.
use std::collections::BTreeMap;

use garbled_snark_verifier::CircuitContext;
use m12_gates::{self as g, W};
use m14_circuit::{
    ext::{self, Ext},
    field::{self as f, Fe},
    hash::{self, Transcript},
    multilinear as ml, sample, sumcheck,
};

use crate::{
    native::{self, Shard},
    verifier::{Inputs, ZerocheckOut},
};

fn const_bytes(b: &[u8]) -> Vec<W> {
    b.iter().flat_map(|x| g::const_bits(*x as u128, 8)).collect()
}

/// Constants of the PCS stage, from the pinned proof and SP1's wrap verifier configuration.
pub struct PcsShape {
    pub log_m: usize,
    pub log_stacking_height: usize,
    pub num_col_vars: usize,
    /// Column prefix sums as (log_m + 1)-bit points, most significant bit first.
    pub prefix_sums: Vec<Vec<u32>>,
    /// Real columns per round and the added zero columns after them.
    pub real_cols: Vec<usize>,
    pub added_cols: Vec<usize>,
    /// Digest of each round's table sizes (the modified-commitment check).
    pub table_hashes: Vec<[u8; 32]>,
    pub batch_lens: Vec<usize>,
    pub fri_rounds: usize,
    pub log_blowup: usize,
    pub num_queries: usize,
    pub pow_bits: usize,
    /// (log height, width) of each tensor opening: the components, then the FRI rounds.
    pub openings: Vec<(usize, usize)>,
}

impl PcsShape {
    pub fn new(reference: &Shard) -> Self {
        let ep = &reference.evaluation_proof;
        let sv = m13_verify::wrap_verifier_v2();
        let jv = &sv.shard_verifier().jagged_pcs_verifier;
        let bf = &jv.pcs_verifier.basefold_verifier;
        let rc: Vec<Vec<(usize, usize)>> = ep.row_counts_and_column_counts.iter().cloned().collect();
        let mut heights = Vec::new();
        for round in &rc {
            for &(r, cnt) in round {
                heights.extend(std::iter::repeat_n(r, cnt));
            }
        }
        let mut prefix = vec![0usize];
        for h in &heights {
            prefix.push(prefix.last().unwrap() + h);
        }
        let log_m = ep.log_m;
        let bits = |x: usize| (0..=log_m).rev().map(|i| ((x >> i) & 1) as u32).collect::<Vec<_>>();
        let real_cols = rc.iter().map(|r| r[..r.len() - 2].iter().map(|x| x.1).sum()).collect();
        let added_cols = rc.iter().map(|r| r[r.len() - 2].1 + 1).collect();
        let table_hashes = rc
            .iter()
            .map(|r| {
                let mut xs = vec![r.len()];
                xs.extend(r.iter().map(|x| x.0));
                xs.extend(r.iter().map(|x| x.1));
                native::leaf_hash_const(&xs)
            })
            .collect();
        let b = &ep.pcs_proof.basefold_proof;
        let openings = b
            .component_polynomials_query_openings_and_proofs
            .iter()
            .chain(&b.query_phase_openings_and_proofs)
            .map(|o| (o.proof.log_tensor_height, o.proof.width))
            .collect();
        PcsShape {
            log_m,
            log_stacking_height: m13_verify::WRAP_LOG_STACKING_HEIGHT as usize,
            num_col_vars: (prefix.len() - 1).next_power_of_two().ilog2() as usize,
            prefix_sums: prefix.iter().map(|&x| bits(x)).collect(),
            real_cols,
            added_cols,
            table_hashes,
            batch_lens: ep.pcs_proof.batch_evaluations.iter().map(|r| r.num_evaluations()).collect(),
            fri_rounds: b.fri_commitments.len(),
            log_blowup: bf.fri_config.log_blowup(),
            num_queries: bf.fri_config.num_queries,
            pow_bits: bf.fri_config.proof_of_work_bits,
            openings,
        }
    }
}

/// L(bits, y) = prod (bit ? y : 1 - y) for constant bits; shared prefixes are computed once
/// (sorted prefix sums share their high bits).
fn lagrange_const<C: CircuitContext>(c: &mut C, bits: &[u32], y: &[Ext], memo: &mut BTreeMap<Vec<u32>, Ext>) -> Ext {
    let mut start = bits.len();
    while start > 0 && !memo.contains_key(&bits[..start]) {
        start -= 1;
    }
    let mut v = if start == 0 { Ext::one() } else { memo[&bits[..start]].clone() };
    for k in start..bits.len() {
        let fct = if bits[k] == 1 { y[k].clone() } else { ext::sub(c, &Ext::one(), &y[k]) };
        v = ext::mul(c, &v, &fct);
        memo.insert(bits[..=k].to_vec(), v.clone());
    }
    v
}

/// `BranchingProgram::new(z_row, z_index).eval(prefix_sum, next_prefix_sum)`.
fn branching_program<C: CircuitContext>(c: &mut C, z_row: &[Ext], z_index: &[Ext], cur: &[Ext], next: &[Ext]) -> Ext {
    let ith = |p: &[Ext], i: usize| if p.len() <= i { Ext::zero() } else { p[p.len() - i - 1].clone() };
    let num_vars = z_index.len().max(z_row.len());
    // memory state index = carry + 2 * comparison_so_far; start at success (carry 0, comparison 1)
    let mut res: [Ext; 4] = [Ext::zero(), Ext::zero(), Ext::one(), Ext::zero()];
    for layer in (0..num_vars + 1).rev() {
        let point = [ith(z_row, layer), ith(z_index, layer), ith(cur, layer), ith(next, layer)];
        let eq = ml::partial_lagrange(c, &point);
        let mut new_res: [Ext; 4] = std::array::from_fn(|_| Ext::zero());
        for cmp in 0..2usize {
            for carry in 0..2usize {
                let mut acc_elems: [Vec<Ext>; 4] = Default::default();
                for (i, e) in eq.iter().enumerate() {
                    // bit state order: row, index, current prefix sum, next prefix sum
                    let (row, index, curb, nextb) = ((i >> 3) & 1, (i >> 2) & 1, (i >> 1) & 1, i & 1);
                    let new_cmp = if index == nextb { cmp } else { nextb };
                    let sum = row + carry + curb;
                    if index != sum & 1 {
                        continue;
                    }
                    acc_elems[(sum >> 1) + 2 * new_cmp].push(e.clone());
                }
                let mut accum = Ext::zero();
                for (j, terms) in acc_elems.iter().enumerate() {
                    let mut s = Ext::zero();
                    for x in terms {
                        s = ext::add(c, &s, x);
                    }
                    let t = ext::mul(c, &s, &res[j]);
                    accum = ext::add(c, &accum, &t);
                }
                new_res[carry + 2 * cmp] = accum;
            }
        }
        res = new_res;
    }
    res[0].clone()
}

/// One row of `MerkleTreeTcs::verify_tensor_openings`: the path from the row's leaf reaches
/// `root`. The caller passes exactly `depth` index bits (higher index bits are zero by
/// construction of the sampled indices).
fn tensor_path<C: CircuitContext>(c: &mut C, row: &[Fe], index: &[W], path: &[Vec<W>], root: &[W]) -> W {
    let leaf = hash::leaf_hash(c, row);
    let r = hash::path_root(c, &leaf, index, path);
    hash::digest_eq(c, &r, root)
}

/// `JaggedPcsVerifier::verify_trusted_evaluations` with SP1's stacked BaseFold PCS.
pub fn pcs<C: CircuitContext>(
    c: &mut C,
    t: &mut Transcript,
    ps: &PcsShape,
    inp: &mut Inputs,
    vk_preprocessed_commit: [u8; 32],
    main_commitment: &[W],
    z: &ZerocheckOut,
) -> Vec<W> {
    let mut oks = Vec::new();
    let z_col: Vec<Ext> = (0..ps.num_col_vars).map(|_| sumcheck::sample_ext(c, t)).collect();

    // Modified commitments: compress(original, hash(table sizes)) is the shard's commitment.
    let originals: Vec<Vec<W>> = (0..2).map(|_| inp.digest()).collect();
    for (r, target) in [const_bytes(&vk_preprocessed_commit), main_commitment.to_vec()].iter().enumerate() {
        let h = const_bytes(&ps.table_hashes[r]);
        let m = hash::node(c, &originals[r], &h);
        oks.push(hash::digest_eq(c, &m, target));
    }

    // Column claims: preprocessed openings of the chips that have them, then all main openings,
    // with the added zero columns after each round, padded to a power of two.
    let mut claims: Vec<Ext> = z.prep.iter().flatten().cloned().collect();
    assert_eq!(claims.len(), ps.real_cols[0]);
    claims.extend(std::iter::repeat_n(Ext::zero(), ps.added_cols[0]));
    claims.extend(z.main.iter().flatten().cloned());
    claims.extend(std::iter::repeat_n(Ext::zero(), ps.added_cols[1]));
    assert_eq!(claims.len() + 1, ps.prefix_sums.len());
    claims.resize(1 << ps.num_col_vars, Ext::zero());
    let claim = ml::mle_eval(c, &claims, &z_col);

    let polys: Vec<Vec<Ext>> = (0..ps.log_m).map(|_| (0..3).map(|_| inp.ext()).collect()).collect();
    let (ok, z_trace, dense_eval) = sumcheck::verify(c, t, &claim, &polys);
    oks.push(ok);

    // Jagged evaluation sub-protocol.
    let jagged_eval = inp.ext();
    sumcheck::observe_ext(t, &jagged_eval);
    let n2 = 2 * (ps.log_m + 1);
    let polys2: Vec<Vec<Ext>> = (0..n2).map(|_| (0..3).map(|_| inp.ext()).collect()).collect();
    let (ok2, p56, eval56) = sumcheck::verify(c, t, &jagged_eval, &polys2);
    oks.push(ok2);
    let (first, second) = p56.split_at(ps.log_m + 1);
    let z_col_eq = ml::partial_lagrange(c, &z_col);
    let (mut m1, mut m2) = (BTreeMap::new(), BTreeMap::new());
    let mut sum = Ext::zero();
    for col in 0..ps.prefix_sums.len() - 1 {
        let a = lagrange_const(c, &ps.prefix_sums[col], first, &mut m1);
        let b = lagrange_const(c, &ps.prefix_sums[col + 1], second, &mut m2);
        let ab = ext::mul(c, &a, &b);
        let term = ext::mul(c, &z_col_eq[col], &ab);
        sum = ext::add(c, &sum, &term);
    }
    let bp = branching_program(c, &z.point, &z_trace, first, second);
    let expected56 = ext::mul(c, &sum, &bp);
    oks.push(ext::eq(c, &expected56, &eval56));

    let expected_eval = inp.ext();
    let ee = ext::mul(c, &expected_eval, &jagged_eval);
    oks.push(ext::eq(c, &ee, &dense_eval));

    // Stacked PCS (untrusted evaluation: the claim is observed first). A short table is evaluated
    // as if padded with zeros (SP1's dot product zips the rows with the eq weights).
    sumcheck::observe_ext(t, &expected_eval);
    let split = z_trace.len() - ps.log_stacking_height;
    let (batch_point, stack_point) = z_trace.split_at(split);
    let batch_evals: Vec<Vec<Ext>> = ps.batch_lens.iter().map(|&n| (0..n).map(|_| inp.ext()).collect()).collect();
    let mut flat: Vec<Ext> = batch_evals.iter().flatten().cloned().collect();
    assert!(flat.len() <= 1 << batch_point.len());
    flat.resize(1 << batch_point.len(), Ext::zero());
    let stacked = ml::mle_eval(c, &flat, batch_point);
    oks.push(ext::eq(c, &stacked, &expected_eval));

    // BaseFold (untrusted evaluations: the batch evaluations are observed first).
    for r in &batch_evals {
        r.iter().for_each(|x| sumcheck::observe_ext(t, x));
    }
    let bgw = inp.fe();
    t.observe_fe(&bgw);
    let bb = t.sample_bytes(c, 4);
    let low = sample::bits_from_le32(&bb, slop_basefold::BATCH_GRINDING_BITS);
    let any = f::or_all(c, &low);
    oks.push(g::not(c, any));
    let total: usize = ps.batch_lens.iter().sum();
    let nbv = total.next_power_of_two().ilog2() as usize;
    let batching_point: Vec<Ext> = (0..nbv).map(|_| sumcheck::sample_ext(c, t)).collect();
    let coeffs = ml::partial_lagrange(c, &batching_point);
    let mut eval_claim = Ext::zero();
    for (v, k) in batch_evals.iter().flatten().zip(&coeffs) {
        let tv = ext::mul(c, v, k);
        eval_claim = ext::add(c, &eval_claim, &tv);
    }
    let point: Vec<Ext> = stack_point.iter().rev().cloned().collect();
    assert_eq!(point.len(), ps.fri_rounds);
    t.observe_fe(&Fe::constant(ps.fri_rounds as u32));
    let mut msgs = Vec::new();
    let mut fri_commits = Vec::new();
    let mut betas = Vec::new();
    for _ in 0..ps.fri_rounds {
        let m = [inp.ext(), inp.ext()];
        let d = inp.digest();
        m.iter().for_each(|x| sumcheck::observe_ext(t, x));
        t.observe_digest(&d);
        betas.push(sumcheck::sample_ext(c, t));
        msgs.push(m);
        fri_commits.push(d);
    }
    // (1 - x) m0 + x m1 = m0 + x (m1 - m0)
    fn lin<C: CircuitContext>(c: &mut C, x: &Ext, m: &[Ext; 2]) -> Ext {
        let d = ext::sub(c, &m[1], &m[0]);
        let tx = ext::mul(c, x, &d);
        ext::add(c, &m[0], &tx)
    }
    let first_v = lin(c, &point[0], &msgs[0]);
    oks.push(ext::eq(c, &eval_claim, &first_v));
    // SP1 folds each message as m0 + beta * m1 (the consistency check above interpolates).
    let fold = |c: &mut C, beta: &Ext, m: &[Ext; 2]| {
        let t = ext::mul(c, beta, &m[1]);
        ext::add(c, &m[0], &t)
    };
    let mut expected = fold(c, &betas[0], &msgs[0]);
    for i in 1..ps.fri_rounds {
        let v = lin(c, &point[i], &msgs[i]);
        oks.push(ext::eq(c, &expected, &v));
        expected = fold(c, &betas[i], &msgs[i]);
    }
    let final_poly = inp.ext();
    sumcheck::observe_ext(t, &final_poly);
    let pw = inp.fe();
    t.observe_fe(&pw);
    let pb = t.sample_bytes(c, 4);
    let low = sample::bits_from_le32(&pb, ps.pow_bits);
    let any = f::or_all(c, &low);
    oks.push(g::not(c, any));
    // final check of verify_mle_evaluations: final_poly = last m0 + last beta * last m1
    oks.push(ext::eq(c, &final_poly, &expected));

    let log_max = ps.fri_rounds + ps.log_blowup;
    let index_bits: Vec<Vec<W>> = (0..ps.num_queries)
        .map(|_| {
            let b = t.sample_bytes(c, 4);
            sample::bits_from_le32(&b, log_max)
        })
        .collect();

    // Component openings: Merkle paths, then the batched value per query.
    let mut batch_vals = vec![Ext::zero(); ps.num_queries];
    let mut coeff_at = 0;
    for (r, original) in originals.iter().enumerate() {
        let (log_h, width) = ps.openings[r];
        assert_eq!(log_h, log_max);
        let root = inp.digest();
        for q in 0..ps.num_queries {
            let row: Vec<Fe> = (0..width).map(|_| inp.fe()).collect();
            let path: Vec<Vec<W>> = (0..log_h).map(|_| inp.digest()).collect();
            oks.push(tensor_path(c, &row, &index_bits[q], &path, &root));
            for (k, v) in row.iter().enumerate() {
                let tv = ext::mul_base(c, &coeffs[coeff_at + k], v);
                batch_vals[q] = ext::add(c, &batch_vals[q], &tv);
            }
        }
        coeff_at += width;
        let h = const_bytes(&native::leaf_hash_const(&[log_h, width]));
        let m = hash::node(c, &root, &h);
        oks.push(hash::digest_eq(c, &m, original));
    }

    // FRI queries. x = g^rev(index) and x^-1 = (g^-1)^rev(index), both squared each round, so the
    // division by xs[1] - xs[0] = +-2x needs no field inversion.
    let gen = native::two_adic_generator(log_max);
    let gen_inv = native::inverse(gen);
    let half = native::inverse(2);
    let mut xs = Vec::new();
    let mut xinvs = Vec::new();
    for bits in &index_bits {
        let rev: Vec<W> = bits.iter().rev().copied().collect();
        xs.push(f::pow_const_base(c, gen, &rev));
        xinvs.push(f::pow_const_base(c, gen_inv, &rev));
    }
    let mut folded = batch_vals;
    for (round, (commit, beta)) in fri_commits.iter().zip(&betas).enumerate() {
        let (log_h, width) = ps.openings[2 + round];
        assert_eq!((log_h, width), (log_max - 1 - round, 8));
        let root = inp.digest();
        for q in 0..ps.num_queries {
            let row: Vec<Fe> = (0..8).map(|_| inp.fe()).collect();
            let path: Vec<Vec<W>> = (0..log_h).map(|_| inp.digest()).collect();
            let bit = index_bits[q][round];
            let e0 = Ext([row[0].clone(), row[1].clone(), row[2].clone(), row[3].clone()]);
            let e1 = Ext([row[4].clone(), row[5].clone(), row[6].clone(), row[7].clone()]);
            let mine = ext::select(c, bit, &e0, &e1);
            oks.push(ext::eq(c, &mine, &folded[q]));
            // bit 0: xs = [x, -x]; bit 1: xs = [-x, x]. xs0 = (bit ? -x : x);
            // 1 / (xs1 - xs0) = (bit ? 1 : -1) * x^-1 / 2.
            let neg_x = f::neg(c, &xs[q]);
            let xs0 = f::select(c, bit, &xs[q], &neg_x);
            let hinv = f::mul_const(c, &xinvs[q], half);
            let nhinv = f::neg(c, &hinv);
            let inv = f::select(c, bit, &nhinv, &hinv);
            let bm = ext::sub(c, beta, &Ext::from_base(&xs0));
            let de = ext::sub(c, &e1, &e0);
            let p = ext::mul(c, &bm, &de);
            let p = ext::mul_base(c, &p, &inv);
            folded[q] = ext::add(c, &e0, &p);
            xs[q] = f::square(c, &xs[q]);
            xinvs[q] = f::square(c, &xinvs[q]);
            oks.push(tensor_path(c, &row, &index_bits[q][round + 1..], &path, &root));
        }
        let h = const_bytes(&native::leaf_hash_const(&[log_h, width]));
        let m = hash::node(c, &root, &h);
        oks.push(hash::digest_eq(c, &m, commit));
    }
    for fv in &folded {
        oks.push(ext::eq(c, fv, &final_poly));
    }
    oks
}
