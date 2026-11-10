//! Native encoders for the circuits' input bits, in exactly the order `Cur` consumes them:
//! claim id || claim values || challenge values || response. Openings are re-ordered so the
//! revealed states come top level first (`level_order`), which is the circuit's fixed layout.
use crate::{
    flatmerkle::{self, mid, Opening},
    protocol::*,
    sha::{self, compress, IV},
    shape::row_record_len,
    binding,
};

/// Level of each reveal in `flatmerkle::open`'s (in-order) list for pair index `index`.
fn levels_in_open_order(m: usize, index: usize) -> Vec<usize> {
    fn seq(l: usize, index: usize, out: &mut Vec<usize>) {
        if l == 0 {
            return;
        }
        if (index >> l) & 1 == 1 {
            out.push(l);
            seq(l - 1, index, out);
        } else {
            seq(l - 1, index, out);
            out.push(l);
        }
    }
    let mut out = Vec::new();
    seq(m - 1, index, &mut out);
    out
}

/// Reveals re-ordered top level first; `None` if the count is wrong for n.
pub fn level_order(n: usize, index: usize, reveals: &[[u8; 32]]) -> Option<Vec<[u8; 32]>> {
    let m = flatmerkle::level(n)?;
    if reveals.len() != m - 1 {
        return None;
    }
    let lv = levels_in_open_order(m, index);
    let mut out = vec![[0u8; 32]; m - 1];
    for (pos, l) in lv.iter().enumerate() {
        out[m - 1 - l] = reveals[pos];
    }
    Some(out)
}

/// Native model of `circuit::flat_verify` over level-ordered reveals.
pub fn verify_level_ordered(n: usize, root: &[u8; 32], idx: usize, item: &[u8; 64], index: u32, pair: &[[u8; 64]; 2], s_top_first: &[[u8; 32]]) -> bool {
    let m = flatmerkle::level(n).unwrap();
    let d = |l: usize| (idx >> l) & 1 == 1;
    let s = |l: usize| s_top_first[m - 1 - l];
    if index as usize != idx || pair[idx & 1] != *item {
        return false;
    }
    let mut ck = vec![[0u8; 32]; m - 1];
    ck[m - 2] = if d(m - 1) { s(m - 1) } else { IV };
    for l in (1..m - 1).rev() {
        ck[l - 1] = if d(l) { s(l) } else { ck[l] };
    }
    let x = compress(&compress(&ck[0], &pair[0]), &pair[1]);
    let mut e = compress(&x, &mid(&ck[0]));
    for (l, ckl) in ck.iter().enumerate().take(m - 1).skip(1) {
        let right = if d(l) { e } else { compress(&s(l), &mid(&e)) };
        e = compress(&right, &mid(ckl));
    }
    let state = if d(m - 1) { e } else { compress(&s(m - 1), &mid(&e)) };
    sha::finalize(&state, flatmerkle::stream_blocks(n) * 64) == *root
}

fn opening(out: &mut Vec<u8>, n: u32, o: &OpeningJ) -> Result<(), String> {
    let lo = level_order(n as usize, o.index as usize, &o.reveals).ok_or("opening has the wrong number of reveals")?;
    out.extend_from_slice(&o.index.to_be_bytes());
    out.extend_from_slice(&o.pair[0]);
    out.extend_from_slice(&o.pair[1]);
    for r in lo {
        out.extend_from_slice(&r);
    }
    Ok(())
}

/// Bytes of the claim and challenge sections. `onchain_claim_id` is the id the dispute
/// contract committed (the adjudicated claim's id).
pub fn common(tc: &TrustedConfig, claim: &FlatCheckClaim, ch: &FlatCheckChallenge) -> Result<Vec<u8>, String> {
    if claim.instance.x.len() != tc.num_io as usize {
        return Err("claim public IO length is not the pinned one (not representable)".into());
    }
    let mut o = Vec::new();
    o.extend_from_slice(&claim.id());
    o.extend_from_slice(&claim.version.to_be_bytes());
    o.extend_from_slice(&claim.tc_digest);
    o.push(claim.field);
    o.extend_from_slice(&claim.session_id);
    o.extend_from_slice(&claim.replay.digest());
    o.extend_from_slice(&claim.statement.digest());
    o.extend_from_slice(&claim.folding.digest());
    o.extend_from_slice(&claim.instance.comm_w);
    o.extend_from_slice(&claim.instance.comm_e);
    o.extend_from_slice(&claim.instance.u);
    for x in &claim.instance.x {
        o.extend_from_slice(x);
    }
    for r in [claim.root_w, claim.root_e, claim.root_trace_w, claim.root_trace_e] {
        o.extend_from_slice(&r);
    }
    let (kind, idx, v) = ch.kind.code();
    o.extend_from_slice(&ch.version.to_be_bytes());
    o.extend_from_slice(&ch.claim_id);
    o.push(kind);
    o.extend_from_slice(&idx.to_be_bytes());
    o.push(v);
    o.extend_from_slice(&ch.challenger);
    o.extend_from_slice(&ch.nonce);
    o.extend_from_slice(&ch.replay.digest());
    Ok(o)
}

pub fn row_input(tc: &TrustedConfig, claim: &FlatCheckClaim, ch: &FlatCheckChallenge, resp: Option<&FlatCheckResponse>) -> Result<Vec<u8>, String> {
    let Some(FlatCheckResponse::Row(r)) = resp else { return Err("no row response (the timeout leaf, not the circuit, decides)".into()) };
    let k = [tc.k[0] as usize, tc.k[1] as usize, tc.k[2] as usize];
    if r.row_record.len() != row_record_len(k) || r.terms.len() != k.iter().sum::<usize>() {
        return Err("response shape is not the pinned one (not representable)".into());
    }
    let mut o = common(tc, claim, ch)?;
    o.extend_from_slice(&r.challenge_id);
    o.extend_from_slice(&r.row_record);
    opening(&mut o, tc.matrix_leaves, &r.row_open)?;
    for t in &r.terms {
        opening(&mut o, tc.w_leaves, t)?;
    }
    opening(&mut o, tc.e_leaves, &r.e_open)?;
    Ok(o)
}

pub fn step_input(tc: &TrustedConfig, claim: &FlatCheckClaim, ch: &FlatCheckChallenge, resp: Option<&FlatCheckResponse>, v: Vector) -> Result<Vec<u8>, String> {
    let Some(FlatCheckResponse::Step(r)) = resp else { return Err("no step response (the timeout leaf, not the circuit, decides)".into()) };
    if r.cur.record.len() != binding::TRACE_RECORD_LEN || r.next.record.len() != binding::TRACE_RECORD_LEN || r.gen.record.len() != binding::GEN_RECORD_LEN {
        return Err("record length is not the pinned one (not representable)".into());
    }
    let mut o = common(tc, claim, ch)?;
    o.extend_from_slice(&r.challenge_id);
    o.extend_from_slice(&r.cur.record);
    opening(&mut o, tc.trace_leaves(v), &r.cur.open)?;
    o.extend_from_slice(&r.next.record);
    opening(&mut o, tc.trace_leaves(v), &r.next.open)?;
    opening(&mut o, tc.vec_leaves(v), &r.scalar)?;
    o.extend_from_slice(&r.gen.record);
    opening(&mut o, tc.ck_leaves, &r.gen.open)?;
    Ok(o)
}

fn open_len(n: u32) -> usize {
    4 + 128 + 32 * (flatmerkle::level(n as usize).unwrap() - 1)
}

/// Input bytes of the claim and challenge sections.
pub fn common_len(tc: &TrustedConfig) -> usize {
    32 + (4 + 32 + 1 + 32 * 4 + 65 * 2 + 32 + 32 * tc.num_io as usize + 32 * 4) + (4 + 32 + 1 + 4 + 1 + 32 * 3)
}

pub fn row_input_len(tc: &TrustedConfig) -> usize {
    let k = [tc.k[0] as usize, tc.k[1] as usize, tc.k[2] as usize];
    common_len(tc) + 32 + row_record_len(k) + open_len(tc.matrix_leaves) + k.iter().sum::<usize>() * open_len(tc.w_leaves) + open_len(tc.e_leaves)
}

pub fn step_input_len(tc: &TrustedConfig, v: Vector) -> usize {
    common_len(tc) + 32 + 2 * (binding::TRACE_RECORD_LEN + open_len(tc.trace_leaves(v))) + open_len(tc.vec_leaves(v)) + binding::GEN_RECORD_LEN + open_len(tc.ck_leaves)
}

pub fn bits(bytes: &[u8]) -> Vec<bool> {
    bytes.iter().flat_map(|&b| (0..8).map(move |i| (b >> i) & 1 == 1)).collect()
}

/// Reveal bytes as published: the in-order `Opening` list (FlatMerkle) for size accounting.
pub fn opening_wire_bytes(o: &Opening) -> usize {
    o.size_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn level_ordered_verification_matches_flatmerkle() {
        for n in [4usize, 8, 16, 64, 256] {
            let items: Vec<[u8; 64]> = (0..n).map(|i| [((i * 37) % 251) as u8; 64]).collect();
            let s = flatmerkle::build(&items).unwrap();
            for i in 0..n {
                let o = flatmerkle::open(&s, i);
                let lo = level_order(n, i, &o.reveals).unwrap();
                assert!(verify_level_ordered(n, &s.digest, i, &items[i], o.index, &o.pair, &lo), "n={n} i={i}");
                assert!(!verify_level_ordered(n, &s.digest, i ^ 1, &items[i ^ 1], o.index, &o.pair, &lo));
                if n > 4 {
                    let mut bad = lo.clone();
                    bad.swap(0, 1);
                    assert!(lo[0] == lo[1] || !verify_level_ordered(n, &s.digest, i, &items[i], o.index, &o.pair, &bad));
                }
            }
        }
    }
}
