//! FlatMerkle versus a domain-separated binary Merkle tree over the same 64-byte FC03 records:
//! construction, opening size, verification, compression calls, shared-operand multiproofs,
//! publication bytes, peak heap, malformed streams and proof substitution.
use crate::{enc, flatmerkle, merkle, sha};
use serde_json::{json, Value};
use std::time::Instant;

/// Peak-heap probe supplied by the binary's counting allocator: (reset, read peak above reset).
pub struct HeapProbe {
    pub reset: fn(),
    pub peak: fn() -> usize,
}

fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[v.len() / 2]
}

fn time_us<T>(reps: usize, mut f: impl FnMut() -> T) -> f64 {
    let mut ts = Vec::with_capacity(reps);
    for _ in 0..reps {
        let t = Instant::now();
        std::hint::black_box(f());
        ts.push(t.elapsed().as_secs_f64() * 1e6);
    }
    median(ts)
}

pub fn records(n: usize) -> Vec<[u8; 64]> {
    (0..n as u32).map(|i| enc::item(1, enc::tag::W, i, &sha::sha256(&i.to_be_bytes()))).collect()
}

/// A row read with repeated and adjacent operands: 7 reads, 5 distinct records.
pub fn shared_operands(n: usize) -> Vec<usize> {
    vec![3, 3, n / 2, n / 2 + 1, n - 1, 7 % n, 7 % n]
}

/// Witness bytes of a byte string pushed in <= 520-byte chunks (push opcodes included).
pub fn witness_push_bytes(len: usize) -> usize {
    let mut total = 0;
    let mut left = len;
    while left > 0 {
        let c = left.min(520);
        // compact-size length prefix of the witness item
        total += c + if c < 253 { 1 } else { 3 };
        left -= c;
    }
    total
}

pub fn run(probe: &HeapProbe) -> Value {
    let mut rows = Vec::new();
    for n in [16usize, 64, 256, 1024] {
        let items = records(n);
        let reps = if n <= 256 { 31 } else { 11 };
        // ---------------- FlatMerkle
        (probe.reset)();
        let (fs, f_build_c) = sha::counted(|| flatmerkle::build(&items).unwrap());
        let f_peak = (probe.peak)();
        let f_build_us = time_us(reps, || flatmerkle::build(&items).unwrap());
        let fo: Vec<_> = (0..n).map(|i| flatmerkle::open(&fs, i)).collect();
        let (_, f_ver_c) = sha::counted(|| flatmerkle::verify(n, &fs.digest, 5, &items[5], &fo[5]));
        let f_ver_us = time_us(reps, || (0..n).all(|i| flatmerkle::verify(n, &fs.digest, i, &items[i], &fo[i]))) / n as f64;
        let set = shared_operands(n);
        let fm = flatmerkle::open_multi(&fs, &set);
        let claims: Vec<(usize, [u8; 64])> = set.iter().map(|&i| (i, items[i])).collect();
        let (fm_ok, fm_c) = sha::counted(|| flatmerkle::verify_multi(n, &fs.digest, &claims, &fm));
        assert!(fm_ok);
        let mut distinct = set.clone();
        distinct.sort_unstable();
        distinct.dedup();
        let f_singles: usize = distinct.iter().map(|&i| fo[i].size_bytes()).sum();
        // ---------------- Merkle
        (probe.reset)();
        let (mt, m_build_c) = sha::counted(|| merkle::build(&items).unwrap());
        let m_peak = (probe.peak)();
        let m_build_us = time_us(reps, || merkle::build(&items).unwrap());
        let mo: Vec<_> = (0..n).map(|i| merkle::open(&mt, i)).collect();
        let (_, m_ver_c) = sha::counted(|| merkle::verify(n, &mt.root(), 5, &items[5], &mo[5]));
        let m_ver_us = time_us(reps, || (0..n).all(|i| merkle::verify(n, &mt.root(), i, &items[i], &mo[i]))) / n as f64;
        let mm = merkle::open_multi(&mt, &set);
        let (mm_ok, mm_c) = sha::counted(|| merkle::verify_multi(n, &mt.root(), &claims, &mm));
        assert!(mm_ok);
        let m_singles: usize = distinct.iter().map(|&i| mo[i].size_bytes()).sum();
        // ---------------- malformed structured stream: wrong checkpoint in the MID block of
        // node (n/2, k = 1), the first pair of the right half.
        let mut payload = flatmerkle::payload(&items).unwrap();
        let mid_block_of_right_first_pair = {
            // left half occupies n - 2 blocks; then pair blocks 0, 1, MID at block 2.
            (n - 1) + 2
        };
        payload[64 * mid_block_of_right_first_pair] ^= 1;
        let bad = flatmerkle::build_from_payload(&items, &payload).unwrap();
        let openable = (0..n).filter(|&i| flatmerkle::verify(n, &bad.digest, i, &items[i], &flatmerkle::open(&bad, i))).count();
        let honest_rebuild_detects = flatmerkle::build(&items).unwrap().digest != bad.digest;
        // ---------------- proof substitution (both schemes): every opening at every other index,
        // and openings from a second tree under the first root.
        let other: Vec<[u8; 64]> = records(n).into_iter().map(|mut x| {
            x[13] ^= 0x55;
            x
        }).collect();
        let fs2 = flatmerkle::build(&other).unwrap();
        let mt2 = merkle::build(&other).unwrap();
        let mut f_sub = (0usize, 0usize);
        let mut m_sub = (0usize, 0usize);
        let pairs: Vec<(usize, usize)> = (0..n).flat_map(|i| [(i, (i + 1) % n), (i, (i + n / 2) % n), (i, i ^ 1)]).collect();
        for &(i, j) in &pairs {
            f_sub.0 += 1;
            f_sub.1 += (!flatmerkle::verify(n, &fs.digest, j, &items[j], &fo[i])) as usize;
            m_sub.0 += 1;
            m_sub.1 += (!merkle::verify(n, &mt.root(), j, &items[j], &mo[i])) as usize;
        }
        for i in 0..n {
            f_sub.0 += 1;
            f_sub.1 += (!flatmerkle::verify(n, &fs.digest, i, &other[i], &flatmerkle::open(&fs2, i))) as usize;
            m_sub.0 += 1;
            m_sub.1 += (!merkle::verify(n, &mt.root(), i, &other[i], &merkle::open(&mt2, i))) as usize;
        }
        let row_reads = set.len();
        rows.push(json!({
            "records": n,
            "flatmerkle": {
                "build_us_median": f_build_us, "build_compressions": f_build_c, "build_peak_heap_bytes": f_peak,
                "stream_bytes": flatmerkle::stream_blocks(n) * 64, "root_bytes": 32,
                "opening_bytes": fo[5].size_bytes(), "verify_us_median": f_ver_us, "verify_compressions": f_ver_c,
                "multiproof": {"reads": row_reads, "distinct": distinct.len(), "bytes": fm.size_bytes(), "singles_bytes": f_singles, "verify_compressions": fm_c},
                "malformed_mid_checkpoint": {"openable_items": openable, "unopenable_items": n - openable, "rebuild_from_items_detects": honest_rebuild_detects},
                "substitution": {"attempts": f_sub.0, "rejected": f_sub.1},
                "row_response_witness_bytes": witness_push_bytes(f_singles),
            },
            "merkle": {
                "build_us_median": m_build_us, "build_compressions": m_build_c, "build_peak_heap_bytes": m_peak,
                "full_publication_bytes": n * 64, "root_bytes": 32,
                "opening_bytes": mo[5].size_bytes(), "verify_us_median": m_ver_us, "verify_compressions": m_ver_c,
                "multiproof": {"reads": row_reads, "distinct": distinct.len(), "bytes": mm.size_bytes(), "singles_bytes": m_singles, "verify_compressions": mm_c},
                "substitution": {"attempts": m_sub.0, "rejected": m_sub.1},
                "row_response_witness_bytes": witness_push_bytes(m_singles),
            },
        }));
    }
    json!({
        "records_are": "FC03 64-byte W items (enc::item), identical input to both schemes",
        "merkle_scheme": "leaf = SHA256(0x00 || item), node = SHA256(0x01 || L || R)",
        "flatmerkle_scheme": "Lerner linear SHA-256 stream, digest = SHA256(stream); port of flatmerkle.py",
        "shared_operand_set": "indices [3, 3, n/2, n/2+1, n-1, 7, 7]: 7 reads, 5 distinct",
        "bitcoin_binding": {
            "root_in_claim_bytes": 32,
            "claim_id_op_return_script_bytes": 34,
            "tapscript_full_stream_check": "FlatMerkle digest is plain SHA-256 of the stream, so OP_SHA256 <root> OP_EQUAL checks a whole commitment when the stream fits one 520-byte push: n = 4 (384 bytes). n >= 8 needs OP_CAT or chunked hashing, which Script lacks; a Merkle root needs OP_CAT at every n.",
        },
        "sizes": rows,
    })
}
