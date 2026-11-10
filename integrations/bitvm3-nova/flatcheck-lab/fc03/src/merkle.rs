//! Conventional domain-separated SHA-256 binary Merkle tree over 64-byte items:
//! leaf = SHA256(0x00 || item), node = SHA256(0x01 || left || right). The baseline FlatMerkle is
//! compared against.
use crate::sha::sha256;

pub fn leaf_hash(item: &[u8; 64]) -> [u8; 32] {
    let mut b = [0u8; 65];
    b[1..].copy_from_slice(item);
    sha256(&b)
}

pub fn node_hash(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
    let mut b = [0u8; 65];
    b[0] = 1;
    b[1..33].copy_from_slice(l);
    b[33..].copy_from_slice(r);
    sha256(&b)
}

#[derive(Clone, Debug)]
pub struct Tree {
    /// levels[0] = leaf hashes, last = [root].
    pub levels: Vec<Vec<[u8; 32]>>,
}

impl Tree {
    pub fn root(&self) -> [u8; 32] {
        self.levels.last().unwrap()[0]
    }
    pub fn n(&self) -> usize {
        self.levels[0].len()
    }
}

pub fn build(items: &[[u8; 64]]) -> Result<Tree, String> {
    if items.is_empty() || !items.len().is_power_of_two() {
        return Err("item count must be a power of two".into());
    }
    let mut levels = vec![items.iter().map(leaf_hash).collect::<Vec<_>>()];
    while levels.last().unwrap().len() > 1 {
        let prev = levels.last().unwrap();
        levels.push(prev.chunks(2).map(|c| node_hash(&c[0], &c[1])).collect());
    }
    Ok(Tree { levels })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Opening {
    pub index: u32,
    pub siblings: Vec<[u8; 32]>,
}

impl Opening {
    /// index (4) + item (64) + siblings.
    pub fn size_bytes(&self) -> usize {
        4 + 64 + 32 * self.siblings.len()
    }
}

pub fn open(t: &Tree, index: usize) -> Opening {
    let mut i = index;
    let mut sib = Vec::new();
    for lvl in &t.levels[..t.levels.len() - 1] {
        sib.push(lvl[i ^ 1]);
        i >>= 1;
    }
    Opening { index: index as u32, siblings: sib }
}

pub fn verify(n: usize, root: &[u8; 32], index: usize, item: &[u8; 64], op: &Opening) -> bool {
    if !n.is_power_of_two() || index >= n || op.index as usize != index || op.siblings.len() != n.trailing_zeros() as usize {
        return false;
    }
    let mut h = leaf_hash(item);
    let mut i = index;
    for s in &op.siblings {
        h = if i & 1 == 0 { node_hash(&h, s) } else { node_hash(s, &h) };
        i >>= 1;
    }
    h == *root
}

/// Multiproof: the sibling hashes not derivable from the opened leaves, level by level.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MultiOpening {
    pub indices: Vec<u32>,
    pub hashes: Vec<[u8; 32]>,
}

impl MultiOpening {
    /// indices (4 each) + items (64 each) + hashes.
    pub fn size_bytes(&self) -> usize {
        self.indices.len() * (4 + 64) + 32 * self.hashes.len()
    }
}

pub fn open_multi(t: &Tree, indices: &[usize]) -> MultiOpening {
    let mut known: Vec<usize> = indices.to_vec();
    known.sort_unstable();
    known.dedup();
    let idx = known.iter().map(|&i| i as u32).collect();
    let mut hashes = Vec::new();
    for lvl in &t.levels[..t.levels.len() - 1] {
        let mut next = Vec::new();
        for &i in &known {
            if !known.contains(&(i ^ 1)) {
                hashes.push(lvl[i ^ 1]);
            }
            if next.last() != Some(&(i >> 1)) {
                next.push(i >> 1);
            }
        }
        known = next;
    }
    MultiOpening { indices: idx, hashes }
}

pub fn verify_multi(n: usize, root: &[u8; 32], claims: &[(usize, [u8; 64])], mo: &MultiOpening) -> bool {
    if !n.is_power_of_two() {
        return false;
    }
    let mut cur: Vec<(usize, [u8; 32])> = Vec::new();
    let mut idx: Vec<usize> = claims.iter().map(|c| c.0).collect();
    idx.sort_unstable();
    idx.dedup();
    if idx.len() != mo.indices.len() || idx.iter().zip(&mo.indices).any(|(&a, &b)| a != b as usize) || idx.iter().any(|&i| i >= n) {
        return false;
    }
    for &i in &idx {
        let items: Vec<&[u8; 64]> = claims.iter().filter(|c| c.0 == i).map(|c| &c.1).collect();
        if items.iter().any(|x| *x != items[0]) {
            return false;
        }
        cur.push((i, leaf_hash(items[0])));
    }
    let mut it = mo.hashes.iter();
    for _ in 0..n.trailing_zeros() {
        let mut next: Vec<(usize, [u8; 32])> = Vec::new();
        let mut k = 0;
        while k < cur.len() {
            let (i, h) = cur[k];
            let (l, r, step) = if i & 1 == 0 && k + 1 < cur.len() && cur[k + 1].0 == i + 1 {
                (h, cur[k + 1].1, 2)
            } else if i & 1 == 0 {
                let Some(s) = it.next() else { return false };
                (h, *s, 1)
            } else {
                let Some(s) = it.next() else { return false };
                (*s, h, 1)
            };
            next.push((i >> 1, node_hash(&l, &r)));
            k += step;
        }
        cur = next;
    }
    it.next().is_none() && cur.len() == 1 && cur[0].1 == *root
}

#[cfg(test)]
mod tests {
    use super::*;

    fn items(n: usize) -> Vec<[u8; 64]> {
        (0..n).map(|i| [i as u8; 64]).collect()
    }

    #[test]
    fn single_and_multi() {
        for n in [4usize, 16, 64] {
            let its = items(n);
            let t = build(&its).unwrap();
            for i in 0..n {
                let o = open(&t, i);
                assert!(verify(n, &t.root(), i, &its[i], &o));
                assert!(!verify(n, &t.root(), i ^ 1, &its[i ^ 1], &o));
            }
            for set in [vec![1usize], vec![0, 1, 2, 3], vec![2, 9 % n, n - 1, n - 1]] {
                let mo = open_multi(&t, &set);
                let claims: Vec<_> = set.iter().map(|&i| (i, its[i])).collect();
                assert!(verify_multi(n, &t.root(), &claims, &mo), "n={n} set={set:?}");
                let mut bad = claims.clone();
                bad[0].1[0] ^= 1;
                assert!(!verify_multi(n, &t.root(), &bad, &mo));
            }
        }
    }

    /// Leaf/node domain separation: an internal node's two children cannot be presented as a
    /// leaf item, and a node hash cannot stand in for a leaf.
    #[test]
    fn leaf_node_confusion_rejected() {
        let its = items(8);
        let t = build(&its).unwrap();
        let mut fake = [0u8; 64];
        fake[..32].copy_from_slice(&t.levels[0][0]);
        fake[32..].copy_from_slice(&t.levels[0][1]);
        let o = open(&t, 0);
        let short = Opening { index: 0, siblings: o.siblings[1..].to_vec() };
        assert!(!verify(4, &t.root(), 0, &fake, &short));
        assert_ne!(leaf_hash(&fake), t.levels[1][0]);
    }
}
