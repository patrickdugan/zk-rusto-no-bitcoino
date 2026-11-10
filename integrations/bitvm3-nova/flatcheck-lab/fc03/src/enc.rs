//! Canonical, length-prefixed, domain-separated encodings.
//!
//! Every hashed object is `frame(PROTOCOL) || frame(kind) || (frame(tag) || frame(value))*`, where
//! `frame(x) = u32_be(len(x)) || x`. Field elements are 32-byte little-endian canonical
//! representatives; integers are big-endian; points are `inf(1) || x(32 LE) || y(32 LE)` with
//! x = y = 0 for the identity.
use crate::sha;

pub const PROTOCOL: &[u8] = b"FLATCHECK/FC03/v1";

#[derive(Clone, Debug, Default)]
pub struct Enc(Vec<u8>);

impl Enc {
    pub fn new(kind: &str) -> Enc {
        let mut e = Enc(Vec::new());
        e.frame(PROTOCOL);
        e.frame(kind.as_bytes());
        e
    }
    fn frame(&mut self, b: &[u8]) {
        self.0.extend_from_slice(&(b.len() as u32).to_be_bytes());
        self.0.extend_from_slice(b);
    }
    pub fn field(&mut self, tag: &str, v: &[u8]) -> &mut Self {
        self.frame(tag.as_bytes());
        self.frame(v);
        self
    }
    pub fn u8(&mut self, tag: &str, v: u8) -> &mut Self {
        self.field(tag, &[v])
    }
    pub fn u32(&mut self, tag: &str, v: u32) -> &mut Self {
        self.field(tag, &v.to_be_bytes())
    }
    pub fn u64(&mut self, tag: &str, v: u64) -> &mut Self {
        self.field(tag, &v.to_be_bytes())
    }
    pub fn bytes(&self) -> &[u8] {
        &self.0
    }
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
    pub fn digest(&self) -> [u8; 32] {
        sha::sha256(&self.0)
    }
}

/// Tags of the 64-byte FlatMerkle / Merkle records.
pub mod tag {
    pub const W: u8 = b'W';
    pub const E: u8 = b'E';
    pub const ROW: u8 = b'R';
    pub const GEN: u8 = b'G';
    pub const TRACE_W: u8 = b'w';
    pub const TRACE_E: u8 = b'e';
    pub const PAD: u8 = b'Z';
}

pub const ITEM_MAGIC: &[u8; 4] = b"FC03";

/// `"FC03" || field_id || tag || 00 00 || index (u32 BE) || payload (32) || 00 * 20`.
pub fn item(field_id: u8, tag: u8, index: u32, payload: &[u8; 32]) -> [u8; 64] {
    let mut it = [0u8; 64];
    it[..4].copy_from_slice(ITEM_MAGIC);
    it[4] = field_id;
    it[5] = tag;
    it[8..12].copy_from_slice(&index.to_be_bytes());
    it[12..44].copy_from_slice(payload);
    it
}

/// Parsed view of a record item; `None` unless every fixed byte is canonical.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ItemView {
    pub field_id: u8,
    pub tag: u8,
    pub index: u32,
    pub payload: [u8; 32],
}

pub fn parse_item(it: &[u8; 64]) -> Option<ItemView> {
    if &it[..4] != ITEM_MAGIC || it[6] != 0 || it[7] != 0 || it[44..].iter().any(|&b| b != 0) {
        return None;
    }
    Some(ItemView {
        field_id: it[4],
        tag: it[5],
        index: u32::from_be_bytes(it[8..12].try_into().unwrap()),
        payload: it[12..44].try_into().unwrap(),
    })
}

/// Pad a record list to a power of two (at least 4) with PAD items.
pub fn pad_items(field_id: u8, mut items: Vec<[u8; 64]>) -> Vec<[u8; 64]> {
    let n = items.len().max(4).next_power_of_two();
    for i in items.len()..n {
        items.push(item(field_id, tag::PAD, i as u32, &[0u8; 32]));
    }
    items
}

pub fn hex32(b: &[u8; 32]) -> String {
    hex::encode(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_are_length_prefixed() {
        let mut a = Enc::new("k");
        a.field("ab", b"c");
        let mut b = Enc::new("k");
        b.field("a", b"bc");
        assert_ne!(a.bytes(), b.bytes(), "tag/value boundary must be unambiguous");
        assert_eq!(&a.bytes()[..4], &(PROTOCOL.len() as u32).to_be_bytes());
    }

    #[test]
    fn item_roundtrip_and_strictness() {
        let it = item(1, tag::W, 7, &[9u8; 32]);
        let v = parse_item(&it).unwrap();
        assert_eq!((v.field_id, v.tag, v.index, v.payload), (1, b'W', 7, [9u8; 32]));
        let mut bad = it;
        bad[63] = 1;
        assert!(parse_item(&bad).is_none());
        let mut bad = it;
        bad[6] = 1;
        assert!(parse_item(&bad).is_none());
    }
}
