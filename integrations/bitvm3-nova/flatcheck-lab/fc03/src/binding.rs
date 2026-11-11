//! The Pedersen binding of a FlatMerkle-committed vector to Nova's commitment, decomposed into
//! locally checkable double-and-add steps.
//!
//! Nova 0.76: Com(v; r) = sum_j v_j G_j + r H (`provider::pedersen::CommitmentEngine::commit`).
//! Scalars s_0..s_{n-1} = v (zero-padded to the shape), s_n = r; generators G_0..G_{n-1} from the
//! commitment key, G_n = H. Transition t (j = t / 256, b = t mod 256) maps state (acc, P) to
//!   acc' = acc + bit_b(s_j) * P,
//!   P'   = 2P if b < 255; G_{j+1} if b = 255 and j < n; O if b = 255 and j = n.
//! T_0 = (O, G_0); after (n + 1) * 256 transitions acc must equal comm_v. Each transition reads
//! four authenticated records (two trace states, one scalar, one generator), so one challenge
//! settles one transition, and an operator that committed a vector other than Nova's witness
//! cannot finish the trace at Nova's commitment without a wrong transition.
use crate::{
    enc::{self, tag},
    field::{point_bytes, FcEngine, PointBytes},
    protocol::Vector,
    sha,
};
use ff::PrimeFieldBits;
use nova_snark::provider::traits::{DlogGroup, DlogGroupExt};

pub const TRACE_DOMAIN: &[u8; 13] = b"FC03/trace/v1";
pub const GEN_DOMAIN: &[u8; 11] = b"FC03/gen/v1";
pub const TRACE_RECORD_LEN: usize = 13 + 1 + 1 + 4 + 65 + 65;
pub const GEN_RECORD_LEN: usize = 11 + 1 + 4 + 65;

pub fn trace_record(fid: u8, v: Vector, t: u32, acc: &PointBytes, p: &PointBytes) -> Vec<u8> {
    let mut b = Vec::with_capacity(TRACE_RECORD_LEN);
    b.extend_from_slice(TRACE_DOMAIN);
    b.push(fid);
    b.push(v.byte());
    b.extend_from_slice(&t.to_be_bytes());
    b.extend_from_slice(acc);
    b.extend_from_slice(p);
    b
}

pub fn gen_record(fid: u8, j: u32, g: &PointBytes) -> Vec<u8> {
    let mut b = Vec::with_capacity(GEN_RECORD_LEN);
    b.extend_from_slice(GEN_DOMAIN);
    b.push(fid);
    b.extend_from_slice(&j.to_be_bytes());
    b.extend_from_slice(g);
    b
}

/// Structural parse (length, domain, field, vector); point canonicality is checked by the caller.
pub fn parse_trace_record(b: &[u8], fid: u8, v: Vector) -> Option<(u32, PointBytes, PointBytes)> {
    if b.len() != TRACE_RECORD_LEN || &b[..13] != TRACE_DOMAIN || b[13] != fid || b[14] != v.byte() {
        return None;
    }
    let t = u32::from_be_bytes(b[15..19].try_into().unwrap());
    Some((t, b[19..84].try_into().unwrap(), b[84..149].try_into().unwrap()))
}

pub fn parse_gen_record(b: &[u8], fid: u8) -> Option<(u32, PointBytes)> {
    if b.len() != GEN_RECORD_LEN || &b[..11] != GEN_DOMAIN || b[11] != fid {
        return None;
    }
    Some((u32::from_be_bytes(b[12..16].try_into().unwrap()), b[16..81].try_into().unwrap()))
}

/// Index of generator j of an n-scalar vector in the commitment-key tree (H sits at ck_len).
pub fn gen_index(n_vec: u32, ck_len: u32, j: u32) -> u32 {
    if j == n_vec {
        ck_len
    } else {
        j
    }
}

/// The honest trace states 0..=(n+1)*256, by the group law.
pub fn trace_states<E: FcEngine>(scalars: &[E::Scalar], gens: &[E::GE]) -> Vec<(PointBytes, PointBytes)>
where
    E::GE: DlogGroup + DlogGroupExt,
    E::Scalar: PrimeFieldBits,
{
    assert_eq!(scalars.len(), gens.len());
    let n1 = scalars.len();
    let mut acc = <E::GE as DlogGroup>::zero();
    let mut p = gens[0];
    let mut out = Vec::with_capacity(n1 * 256 + 1);
    out.push((point_bytes::<E>(&acc), point_bytes::<E>(&p)));
    for j in 0..n1 {
        let bits = scalars[j].to_le_bits();
        for b in 0..256usize {
            if bits.get(b).map(|x| *x).unwrap_or(false) {
                acc += p;
            }
            p = if b < 255 {
                p + p
            } else if j + 1 < n1 {
                gens[j + 1]
            } else {
                <E::GE as DlogGroup>::zero()
            };
            out.push((point_bytes::<E>(&acc), point_bytes::<E>(&p)));
        }
    }
    out
}

pub fn trace_items(fid: u8, v: Vector, states: &[(PointBytes, PointBytes)]) -> Vec<[u8; 64]> {
    let items = states
        .iter()
        .enumerate()
        .map(|(t, (a, p))| enc::item(fid, v.trace_tag(), t as u32, &sha::sha256(&trace_record(fid, v, t as u32, a, p))))
        .collect();
    enc::pad_items(fid, items)
}

/// Generator records: G_0..G_{ck_len-1}, then H at index ck_len.
pub fn gen_items(fid: u8, gens: &[PointBytes]) -> Vec<[u8; 64]> {
    let items = gens.iter().enumerate().map(|(j, g)| enc::item(fid, tag::GEN, j as u32, &sha::sha256(&gen_record(fid, j as u32, g)))).collect();
    enc::pad_items(fid, items)
}

/// Value records of a committed vector: v_0..v_{n-1}, then the blinding scalar at index n.
pub fn scalar_items(fid: u8, v: Vector, values: &[[u8; 32]], blind: &[u8; 32]) -> Vec<[u8; 64]> {
    let mut items: Vec<[u8; 64]> = values.iter().enumerate().map(|(i, x)| enc::item(fid, v.value_tag(), i as u32, x)).collect();
    items.push(enc::item(fid, v.value_tag(), values.len() as u32, blind));
    enc::pad_items(fid, items)
}
