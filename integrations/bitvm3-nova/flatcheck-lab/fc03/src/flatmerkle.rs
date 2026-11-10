//! FlatMerkle (Lerner, 2026): one linear SHA-256 stream whose ordinary SHA-256 digest commits to
//! a power-of-two list of 64-byte items, with logarithmic openings that reveal intermediate
//! chaining states. Byte-for-byte port of `../flatmerkle.py` (the PR #23 reference), extended with
//! multi-index openings that share reveals.
//!
//! Stream layout for a node covering items [start, start + 2^k): the two children (or, at k = 1,
//! the two items), then a MID block `checkpoint(start) || 0x80 || 0^31`, where checkpoint(start)
//! is the chaining state before the node. The top level is two nodes of k = level - 1 followed by
//! ordinary SHA-256 finalization; the stream holds (2n - 2) blocks.
use crate::sha::{self, compress, IV};
use std::collections::HashMap;

pub fn mid(checkpoint: &[u8; 32]) -> [u8; 64] {
    let mut b = [0u8; 64];
    b[..32].copy_from_slice(checkpoint);
    b[32] = 0x80;
    b
}

pub fn level(n: usize) -> Option<usize> {
    if n < 4 || !n.is_power_of_two() {
        return None;
    }
    Some(n.trailing_zeros() as usize)
}

pub fn stream_blocks(n: usize) -> usize {
    2 * n - 2
}

#[derive(Clone, Debug)]
pub struct Stream {
    pub items: Vec<[u8; 64]>,
    pub digest: [u8; 32],
    pub payload_len: usize,
    checkpoint: HashMap<usize, [u8; 32]>,
    ending: HashMap<(usize, usize), [u8; 32]>,
    prewrap: HashMap<(usize, usize), [u8; 32]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Opening {
    pub index: u32,
    pub pair: [[u8; 64]; 2],
    pub reveals: Vec<[u8; 32]>,
}

impl Opening {
    /// Bytes on the wire: index (4), the two items (128), the revealed states.
    pub fn size_bytes(&self) -> usize {
        4 + 128 + 32 * self.reveals.len()
    }
    pub fn item(&self) -> &[u8; 64] {
        &self.pair[(self.index & 1) as usize]
    }
}

pub fn build(items: &[[u8; 64]]) -> Result<Stream, String> {
    let n = items.len();
    let lv = level(n).ok_or("item count must be a power of two >= 4")?;
    let mut st = Builder { items, state: IV, len: 0, checkpoint: HashMap::new(), ending: HashMap::new(), prewrap: HashMap::new() };
    let half = n / 2;
    st.node(0, lv - 1);
    st.node(half, lv - 1);
    let digest = sha::finalize(&st.state, st.len);
    Ok(Stream { items: items.to_vec(), digest, payload_len: st.len, checkpoint: st.checkpoint, ending: st.ending, prewrap: st.prewrap })
}

struct Builder<'a> {
    items: &'a [[u8; 64]],
    state: [u8; 32],
    len: usize,
    checkpoint: HashMap<usize, [u8; 32]>,
    ending: HashMap<(usize, usize), [u8; 32]>,
    prewrap: HashMap<(usize, usize), [u8; 32]>,
}

impl Builder<'_> {
    fn emit(&mut self, b: &[u8; 64]) {
        self.state = compress(&self.state, b);
        self.len += 64;
    }
    fn node(&mut self, start: usize, k: usize) {
        self.checkpoint.insert(start, self.state);
        let ck = self.state;
        if k == 1 {
            let (a, b) = (self.items[start], self.items[start + 1]);
            self.emit(&a);
            self.emit(&b);
        } else {
            let m = 1 << (k - 1);
            self.node(start, k - 1);
            self.node(start + m, k - 1);
        }
        self.prewrap.insert((start, k), self.state);
        self.emit(&mid(&ck));
        self.ending.insert((start, k), self.state);
    }
}

/// Walk the FlatMerkle layout over an arbitrary (possibly malformed) published stream: the
/// recorded states are those the stream really produces, so `open` on the result gives the best
/// openings an operator who published `payload` can offer, and `digest` is SHA-256(payload).
pub fn build_from_payload(items: &[[u8; 64]], payload: &[u8]) -> Result<Stream, String> {
    let n = items.len();
    let lv = level(n).ok_or("item count must be a power of two >= 4")?;
    if payload.len() != stream_blocks(n) * 64 {
        return Err("payload length".into());
    }
    struct W<'a> {
        p: &'a [u8],
        state: [u8; 32],
        len: usize,
        checkpoint: HashMap<usize, [u8; 32]>,
        ending: HashMap<(usize, usize), [u8; 32]>,
        prewrap: HashMap<(usize, usize), [u8; 32]>,
    }
    impl W<'_> {
        fn emit(&mut self) {
            let b: [u8; 64] = self.p[self.len..self.len + 64].try_into().unwrap();
            self.state = compress(&self.state, &b);
            self.len += 64;
        }
        fn node(&mut self, start: usize, k: usize) {
            self.checkpoint.insert(start, self.state);
            if k == 1 {
                self.emit();
                self.emit();
            } else {
                self.node(start, k - 1);
                self.node(start + (1 << (k - 1)), k - 1);
            }
            self.prewrap.insert((start, k), self.state);
            self.emit();
            self.ending.insert((start, k), self.state);
        }
    }
    let mut w = W { p: payload, state: IV, len: 0, checkpoint: HashMap::new(), ending: HashMap::new(), prewrap: HashMap::new() };
    w.node(0, lv - 1);
    w.node(n / 2, lv - 1);
    let digest = sha::finalize(&w.state, w.len);
    Ok(Stream { items: items.to_vec(), digest, payload_len: w.len, checkpoint: w.checkpoint, ending: w.ending, prewrap: w.prewrap })
}

/// The exact stream bytes (for publication-size accounting and malformed-stream tests).
pub fn payload(items: &[[u8; 64]]) -> Result<Vec<u8>, String> {
    let n = items.len();
    let lv = level(n).ok_or("item count must be a power of two >= 4")?;
    fn node(items: &[[u8; 64]], out: &mut Vec<u8>, st: &mut [u8; 32], start: usize, k: usize) {
        let ck = *st;
        let emit = |out: &mut Vec<u8>, st: &mut [u8; 32], b: &[u8; 64]| {
            out.extend_from_slice(b);
            *st = compress(st, b);
        };
        if k == 1 {
            emit(out, st, &items[start]);
            emit(out, st, &items[start + 1]);
        } else {
            node(items, out, st, start, k - 1);
            node(items, out, st, start + (1 << (k - 1)), k - 1);
        }
        emit(out, st, &mid(&ck));
    }
    let mut out = Vec::with_capacity(stream_blocks(n) * 64);
    let mut st = IV;
    node(items, &mut out, &mut st, 0, lv - 1);
    node(items, &mut out, &mut st, n / 2, lv - 1);
    Ok(out)
}

pub fn open(s: &Stream, index: usize) -> Opening {
    let n = s.items.len();
    let lv = level(n).unwrap();
    assert!(index < n);
    let p = index & !1;
    let mut reveals = Vec::new();
    fn visit(s: &Stream, p: usize, start: usize, k: usize, out: &mut Vec<[u8; 32]>) {
        if k == 1 {
            return;
        }
        let half = 1 << (k - 1);
        if p < start + half {
            visit(s, p, start, k - 1, out);
            out.push(s.prewrap[&(start + half, k - 1)]);
        } else {
            out.push(s.ending[&(start, k - 1)]);
            visit(s, p, start + half, k - 1, out);
        }
    }
    let half = n / 2;
    if p < half {
        visit(s, p, 0, lv - 1, &mut reveals);
        reveals.push(s.prewrap[&(half, lv - 1)]);
    } else {
        reveals.push(s.ending[&(0, lv - 1)]);
        visit(s, p, half, lv - 1, &mut reveals);
    }
    let _ = &s.checkpoint;
    Opening { index: index as u32, pair: [s.items[p], s.items[p + 1]], reveals }
}

/// Verify that `item` sits at `index` of the n-item stream with this digest.
pub fn verify(n: usize, digest: &[u8; 32], index: usize, item: &[u8; 64], op: &Opening) -> bool {
    let Some(lv) = level(n) else { return false };
    if index >= n || op.index as usize != index || &op.pair[index & 1] != item || op.reveals.len() != lv - 1 {
        return false;
    }
    let p = index & !1;
    let mut it = op.reveals.iter();
    fn visit<'a>(op: &Opening, p: usize, start: usize, k: usize, ck: [u8; 32], it: &mut impl Iterator<Item = &'a [u8; 32]>) -> Option<[u8; 32]> {
        if k == 1 {
            let x = compress(&compress(&ck, &op.pair[0]), &op.pair[1]);
            return Some(compress(&x, &mid(&ck)));
        }
        let half = 1 << (k - 1);
        if p < start + half {
            let left = visit(op, p, start, k - 1, ck, it)?;
            let right = compress(it.next()?, &mid(&left));
            Some(compress(&right, &mid(&ck)))
        } else {
            let left = *it.next()?;
            let right = visit(op, p, start + half, k - 1, left, it)?;
            Some(compress(&right, &mid(&ck)))
        }
    }
    let half = n / 2;
    let state = if p < half {
        let Some(left) = visit(op, p, 0, lv - 1, IV, &mut it) else { return false };
        let Some(r) = it.next() else { return false };
        compress(r, &mid(&left))
    } else {
        let Some(left) = it.next().copied() else { return false };
        let Some(s) = visit(op, p, half, lv - 1, left, &mut it) else { return false };
        s
    };
    if it.next().is_some() {
        return false;
    }
    sha::finalize(&state, stream_blocks(n) * 64) == *digest
}

/// Several indices opened together; the shared parts of their paths are revealed once.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MultiOpening {
    /// Pair start indices (even), ascending, with both items of each pair.
    pub pairs: Vec<(u32, [[u8; 64]; 2])>,
    pub reveals: Vec<[u8; 32]>,
}

impl MultiOpening {
    pub fn size_bytes(&self) -> usize {
        self.pairs.len() * (4 + 128) + 32 * self.reveals.len()
    }
}

fn pairs_of(indices: &[usize]) -> Vec<usize> {
    let mut p: Vec<usize> = indices.iter().map(|i| i & !1).collect();
    p.sort_unstable();
    p.dedup();
    p
}

fn any_in(pairs: &[usize], start: usize, len: usize) -> bool {
    pairs.iter().any(|&p| p >= start && p < start + len)
}

pub fn open_multi(s: &Stream, indices: &[usize]) -> MultiOpening {
    let n = s.items.len();
    let lv = level(n).unwrap();
    let pairs = pairs_of(indices);
    let mut reveals = Vec::new();
    fn visit(s: &Stream, pairs: &[usize], start: usize, k: usize, out: &mut Vec<[u8; 32]>) {
        if k == 1 {
            return;
        }
        let half = 1 << (k - 1);
        let (l, r) = (any_in(pairs, start, half), any_in(pairs, start + half, half));
        if l {
            visit(s, pairs, start, k - 1, out);
        } else {
            out.push(s.ending[&(start, k - 1)]);
        }
        if r {
            visit(s, pairs, start + half, k - 1, out);
        } else {
            out.push(s.prewrap[&(start + half, k - 1)]);
        }
    }
    let half = n / 2;
    let (l, r) = (any_in(&pairs, 0, half), any_in(&pairs, half, half));
    if l {
        visit(s, &pairs, 0, lv - 1, &mut reveals);
    } else {
        reveals.push(s.ending[&(0, lv - 1)]);
    }
    if r {
        visit(s, &pairs, half, lv - 1, &mut reveals);
    } else {
        reveals.push(s.prewrap[&(half, lv - 1)]);
    }
    MultiOpening { pairs: pairs.iter().map(|&p| (p as u32, [s.items[p], s.items[p + 1]])).collect(), reveals }
}

/// Verify a multi-opening against `(index, item)` claims (indices may repeat only with equal items).
pub fn verify_multi(n: usize, digest: &[u8; 32], claims: &[(usize, [u8; 64])], mo: &MultiOpening) -> bool {
    let Some(lv) = level(n) else { return false };
    let idx: Vec<usize> = claims.iter().map(|c| c.0).collect();
    let pairs = pairs_of(&idx);
    if pairs.len() != mo.pairs.len() || pairs.iter().zip(&mo.pairs).any(|(&p, q)| p != q.0 as usize) || claims.iter().any(|c| c.0 >= n) {
        return false;
    }
    let pair_of = |p: usize| -> &[[u8; 64]; 2] { &mo.pairs.iter().find(|q| q.0 as usize == p).unwrap().1 };
    for (i, it) in claims {
        if &pair_of(i & !1)[i & 1] != it {
            return false;
        }
    }
    let mut it = mo.reveals.iter();
    #[allow(clippy::too_many_arguments)]
    fn visit<'a, F: Fn(usize) -> &'a [[u8; 64]; 2]>(
        pairs: &[usize],
        pair_of: &F,
        start: usize,
        k: usize,
        ck: [u8; 32],
        it: &mut impl Iterator<Item = &'a [u8; 32]>,
    ) -> Option<[u8; 32]> {
        if k == 1 {
            let pr = pair_of(start);
            let x = compress(&compress(&ck, &pr[0]), &pr[1]);
            return Some(compress(&x, &mid(&ck)));
        }
        let half = 1 << (k - 1);
        let left = if any_in(pairs, start, half) { visit(pairs, pair_of, start, k - 1, ck, it)? } else { *it.next()? };
        let right = if any_in(pairs, start + half, half) {
            visit(pairs, pair_of, start + half, k - 1, left, it)?
        } else {
            compress(it.next()?, &mid(&left))
        };
        Some(compress(&right, &mid(&ck)))
    }
    let half = n / 2;
    let left = if any_in(&pairs, 0, half) {
        match visit(&pairs, &pair_of, 0, lv - 1, IV, &mut it) {
            Some(v) => v,
            None => return false,
        }
    } else {
        match it.next() {
            Some(v) => *v,
            None => return false,
        }
    };
    let state = if any_in(&pairs, half, half) {
        match visit(&pairs, &pair_of, half, lv - 1, left, &mut it) {
            Some(v) => v,
            None => return false,
        }
    } else {
        match it.next() {
            Some(r) => compress(r, &mid(&left)),
            None => return false,
        }
    };
    if it.next().is_some() {
        return false;
    }
    sha::finalize(&state, stream_blocks(n) * 64) == *digest
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn py_items(n: usize) -> Vec<[u8; 64]> {
        (0..n as u32)
            .map(|i| {
                let mut b = [0u8; 64];
                b[..32].copy_from_slice(&Sha256::digest(i.to_le_bytes()));
                b
            })
            .collect()
    }

    /// Digests and first reveals computed by `../flatmerkle.py` at PR #23 head 5e9095d.
    #[test]
    fn matches_python_reference() {
        let cases = [
            (4, "00cc6484dd66164ed72af34efb6782a4f961cdb7b056c3fd4af98a0b20e32d7a", "a5aa0436b25f8c068a4d79177517b629eeea4fdadc79d191a738f2c2beae4e3a"),
            (16, "6057a6a81265fef8ba81fee9282092af182f12d622b4214f518dc6e98cf6235c", "c70eae0cdb5fda89cd5204c829dc23c5394900764257cde82060f46c57a12477"),
            (64, "5a7ae78f3df81cd138e17ed8008f73c8201d73469c60680cf070b906e98b04f5", "c85f098581ab32d932c755d687f2256144c6bd2fcff2df021984715a95dcdd94"),
        ];
        for (n, d, r0) in cases {
            let s = build(&py_items(n)).unwrap();
            assert_eq!(hex::encode(s.digest), d);
            let o = open(&s, n - 3);
            assert_eq!(hex::encode(o.reveals[0]), r0);
            assert_eq!(s.digest.as_slice(), Sha256::digest(payload(&s.items).unwrap()).as_slice());
        }
    }

    #[test]
    fn every_index_and_tampering() {
        for n in [4usize, 8, 16, 32] {
            let items = py_items(n);
            let s = build(&items).unwrap();
            for i in 0..n {
                let o = open(&s, i);
                assert!(verify(n, &s.digest, i, &items[i], &o));
                assert!(!verify(n, &s.digest, i ^ 1, &items[i ^ 1], &o), "index substitution");
                let mut bad = items[i];
                bad[5] ^= 1;
                assert!(!verify(n, &s.digest, i, &bad, &o));
                for j in 0..o.reveals.len() {
                    let mut o2 = o.clone();
                    o2.reveals[j][0] ^= 1;
                    assert!(!verify(n, &s.digest, i, &items[i], &o2));
                }
                let mut o3 = o.clone();
                o3.reveals.push([0u8; 32]);
                assert!(!verify(n, &s.digest, i, &items[i], &o3), "extra reveal");
            }
        }
    }

    #[test]
    fn multi_open_matches_single() {
        let n = 64;
        let items = py_items(n);
        let s = build(&items).unwrap();
        for set in [vec![0usize], vec![0, 1], vec![3, 17, 17, 40, 63], (0..n).collect::<Vec<_>>()] {
            let mo = open_multi(&s, &set);
            let claims: Vec<(usize, [u8; 64])> = set.iter().map(|&i| (i, items[i])).collect();
            assert!(verify_multi(n, &s.digest, &claims, &mo));
            let mut bad = claims.clone();
            bad[0].1[9] ^= 1;
            assert!(!verify_multi(n, &s.digest, &bad, &mo));
        }
        let single = open(&s, 5);
        let mo = open_multi(&s, &[5]);
        assert_eq!(mo.reveals, single.reveals);
    }
}
