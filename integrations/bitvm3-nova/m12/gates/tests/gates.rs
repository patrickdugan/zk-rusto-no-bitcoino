//! M12 gate-cost measurements. Each test builds the circuit with fresh input wires, checks it
//! against a native reference on random inputs, and asserts the non-free gate count. The count is
//! taken twice: ExecuteMode `gate_count.nonfree_gate_count()` and the number of ciphertexts emitted
//! by GarbleMode (the M3-M10 pattern); both must agree.
use garbled_snark_verifier::{
    AesCcrGateHasher, GarbledWire, S, WireId,
    circuit::{
        CiphertextHandler, CircuitBuilder, CircuitInput, CircuitMode, EncodeInput, ExecuteMode, StreamingResult,
    },
    GarbleMode,
    nova::transcript::keccak256,
};
use m12_gates::*;
use rand::{Rng, RngCore, SeedableRng};
use rand_chacha::ChaChaRng;
use sha3::{Digest, Keccak256};

const CAP: usize = 65536;
const TRIALS: usize = 64;

struct Plain(Vec<bool>);
impl CircuitInput for Plain {
    type WireRepr = Vec<WireId>;
    fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
        (0..self.0.len()).map(|_| issue()).collect()
    }
    fn collect_wire_ids(w: &Self::WireRepr) -> Vec<WireId> { w.clone() }
}
impl EncodeInput<ExecuteMode> for Plain {
    fn encode(&self, w: &Self::WireRepr, mode: &mut ExecuteMode) {
        for (id, value) in w.iter().zip(&self.0) { mode.feed_wire(*id, *value); }
    }
}
struct GIn(usize);
impl CircuitInput for GIn {
    type WireRepr = Vec<WireId>;
    fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
        (0..self.0).map(|_| issue()).collect()
    }
    fn collect_wire_ids(w: &Self::WireRepr) -> Vec<WireId> { w.clone() }
}
impl EncodeInput<GarbleMode<AesCcrGateHasher, Count>> for GIn {
    fn encode(&self, w: &Self::WireRepr, mode: &mut GarbleMode<AesCcrGateHasher, Count>) {
        for id in w { let v = mode.issue_garbled_wire(); mode.feed_wire(*id, v); }
    }
}
struct Count(u64);
impl CiphertextHandler for Count {
    type Result = u64;
    fn handle(&mut self, _ct: S) { self.0 += 1; }
    fn finalize(self) -> u64 { self.0 }
}

/// Non-free count of a circuit with `n` fresh input wires, via both execute and garble.
macro_rules! count {
    ($n:expr, $f:expr) => {{
        let exec: StreamingResult<ExecuteMode, _, Vec<bool>> =
            CircuitBuilder::streaming_execute(Plain(vec![false; $n]), CAP, $f);
        let nf = exec.gate_count.nonfree_gate_count();
        let g: StreamingResult<GarbleMode<AesCcrGateHasher, Count>, _, Vec<GarbledWire>> =
            CircuitBuilder::streaming_garbling(GIn($n), CAP, 12, Count(0), $f);
        assert_eq!(nf, g.ciphertext_handler_result, "execute vs garble ciphertext count");
        nf
    }};
}
macro_rules! run {
    ($bits:expr, $f:expr) => {{
        let r: StreamingResult<ExecuteMode, _, Vec<bool>> =
            CircuitBuilder::streaming_execute(Plain($bits), CAP, $f);
        r.output_value
    }};
}

fn bits_of(v: u128, n: usize) -> Vec<bool> { (0..n).map(|i| (v >> i) & 1 == 1).collect() }
fn val(b: &[bool]) -> u128 { b.iter().enumerate().fold(0, |a, (i, &x)| a | ((x as u128) << i)) }
fn words_bits(ws: &[u32]) -> Vec<bool> { ws.iter().flat_map(|&w| bits_of(w as u128, 32)).collect() }
fn bits_words(b: &[bool]) -> Vec<u32> { b.chunks(32).map(|c| val(c) as u32).collect() }
fn report(name: &str, nf: u64) { eprintln!("M12 {name} nonfree={nf}"); }

#[test]
fn keccak_f1600_via_keccak256_one_block() {
    // One 8-byte message pads to exactly one rate block: keccak256 = 1 permutation, 0 other ANDs.
    macro_rules! f { () => { |c, w| keccak256(c, w).to_vec() } }
    let nf = count!(64, f!());
    report("keccak_f1600", nf);
    let mut rng = ChaChaRng::seed_from_u64(1);
    for _ in 0..TRIALS {
        let mut m = [0u8; 8]; rng.fill_bytes(&mut m);
        let bits: Vec<bool> = m.iter().flat_map(|b| (0..8).map(move |i| (b >> i) & 1 == 1)).collect();
        let out = run!(bits, f!());
        let want: Vec<bool> = Keccak256::digest(m).iter().flat_map(|b| (0..8).map(move |i| (b >> i) & 1 == 1)).collect();
        assert_eq!(out, want);
    }
    assert_eq!(nf, 24 * 1600);
}

#[test]
fn sha256_compression() {
    macro_rules! f { () => { |c, w| sha256_compress(c, w) } }
    let nf = count!(768, f!());
    report("sha256_compress", nf);
    let mut rng = ChaChaRng::seed_from_u64(2);
    for _ in 0..TRIALS {
        let cv: [u32; 8] = rng.r#gen();
        let blk: [u8; 64] = { let mut b = [0u8; 64]; rng.fill_bytes(&mut b); b };
        let mut st = cv;
        sha2::compress256(&mut st, &[blk.into()]);
        let mut words: Vec<u32> = cv.to_vec();
        words.extend(blk.chunks(4).map(|c| u32::from_be_bytes(c.try_into().unwrap())));
        let out = bits_words(&run!(words_bits(&words), f!()));
        assert_eq!(out, st.to_vec());
    }
    assert_eq!(nf, SHA256_NF);
}
const SHA256_NF: u64 = 22573;

fn b3_native(cv: [u32; 8], m: [u32; 16], counter: u64, blen: u32, flags: u32) -> [u32; 16] {
    fn g(v: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, mx: u32, my: u32) {
        v[a] = v[a].wrapping_add(v[b]).wrapping_add(mx); v[d] = (v[d] ^ v[a]).rotate_right(16);
        v[c] = v[c].wrapping_add(v[d]); v[b] = (v[b] ^ v[c]).rotate_right(12);
        v[a] = v[a].wrapping_add(v[b]).wrapping_add(my); v[d] = (v[d] ^ v[a]).rotate_right(8);
        v[c] = v[c].wrapping_add(v[d]); v[b] = (v[b] ^ v[c]).rotate_right(7);
    }
    let mut v = [0u32; 16];
    v[..8].copy_from_slice(&cv); v[8..12].copy_from_slice(&B3_IV[..4]);
    v[12] = counter as u32; v[13] = (counter >> 32) as u32; v[14] = blen; v[15] = flags;
    let mut m = m;
    for r in 0..7 {
        g(&mut v, 0, 4, 8, 12, m[0], m[1]); g(&mut v, 1, 5, 9, 13, m[2], m[3]);
        g(&mut v, 2, 6, 10, 14, m[4], m[5]); g(&mut v, 3, 7, 11, 15, m[6], m[7]);
        g(&mut v, 0, 5, 10, 15, m[8], m[9]); g(&mut v, 1, 6, 11, 12, m[10], m[11]);
        g(&mut v, 2, 7, 8, 13, m[12], m[13]); g(&mut v, 3, 4, 9, 14, m[14], m[15]);
        if r < 6 { let o = m; for i in 0..16 { m[i] = o[B3_PERM[i]]; } }
    }
    for i in 0..8 { v[i] ^= v[i + 8]; v[i + 8] ^= cv[i]; }
    v
}

#[test]
fn blake3_compression() {
    const FLAGS: u32 = 1 | 2 | 8; // CHUNK_START | CHUNK_END | ROOT
    macro_rules! f { () => { |c, w| blake3_compress(c, w, 0, 64, FLAGS) } }
    let nf = count!(768, f!());
    report("blake3_compress", nf);
    let mut rng = ChaChaRng::seed_from_u64(3);
    for t in 0..TRIALS {
        let mut msg = [0u8; 64]; rng.fill_bytes(&mut msg);
        let m: [u32; 16] = std::array::from_fn(|i| u32::from_le_bytes(msg[4 * i..4 * i + 4].try_into().unwrap()));
        // Native reference vs the blake3 crate (single chunk, single block, root).
        let native = b3_native(B3_IV, m, 0, 64, FLAGS);
        let digest: Vec<u8> = native[..8].iter().flat_map(|w| w.to_le_bytes()).collect();
        assert_eq!(digest, blake3::hash(&msg).as_bytes().to_vec());
        // Circuit with cv = IV is the crate's hash; odd trials use a random chaining value.
        let cv: [u32; 8] = if t % 2 == 0 { B3_IV } else { rng.r#gen() };
        let want = b3_native(cv, m, 0, 64, FLAGS);
        let mut words = cv.to_vec(); words.extend(m);
        let got = bits_words(&run!(words_bits(&words), f!()));
        assert_eq!(got, want.to_vec());
        if t % 2 == 0 {
            let d: Vec<u8> = got[..8].iter().flat_map(|w| w.to_le_bytes()).collect();
            assert_eq!(d, blake3::hash(&msg).as_bytes().to_vec());
        }
    }
    assert_eq!(nf, BLAKE3_NF);
}
const BLAKE3_NF: u64 = 10410;

fn fields() -> [(&'static str, Field); 2] { [("koalabear", KOALA), ("babybear", BABY)] }

#[test]
fn barrett_model_error_bound() {
    // The native model of the circuit algorithm must be exact with <= 2 corrections everywhere.
    let mut rng = ChaChaRng::seed_from_u64(4);
    for (_, f) in fields() {
        let p = f.p as u128;
        let mut xs: Vec<u128> = vec![0, 1, p - 1, p, p + 1, 2 * p - 1, 2 * p, 3 * p - 1, 3 * p, (p - 1) * (p - 1), (1u128 << 62) - 1];
        for _ in 0..2_000_000 {
            let a = rng.gen_range(0..p); let b = rng.gen_range(0..p);
            xs.push(a * b);
            xs.push(rng.gen_range(0..(p - 1) * (p - 1) + 1));
        }
        let mut worst = 0;
        for x in xs {
            let (r, n) = f.barrett_native(x);
            assert_eq!(r as u128, x % p);
            worst = worst.max(n);
        }
        assert!(worst <= 2);
    }
}

fn edge_values(p: u64, rng: &mut ChaChaRng) -> Vec<u64> {
    let mut v = vec![0, 1, 2, 3, p - 1, p - 2, p / 2, p / 2 + 1, (1 << 24) - 1, 1 << 24, 1 << 30];
    for _ in 0..TRIALS { v.push(rng.gen_range(0..p)); }
    v
}

#[test]
fn field_mul_add_and_small_consts() {
    let mut rng = ChaChaRng::seed_from_u64(5);
    for (name, f) in fields() {
        let p = f.p;
        macro_rules! mulf { () => { |c, w| f.mul_mod(c, &w[..31], &w[31..62]) } }
        macro_rules! addf { () => { |c, w| f.add_mod(c, &w[..31], &w[31..62]) } }
        macro_rules! m3 { () => { |c, w| f.mul_small(c, &w[..31], 3) } }
        macro_rules! m11 { () => { |c, w| f.mul_small(c, &w[..31], 11) } }
        macro_rules! rawmul { () => { |c, w| f.mul31(c, &w[..31], &w[31..62]) } }
        macro_rules! rawnaive { () => { |c, w| f.mul31_naive(c, &w[..31], &w[31..62]) } }
        macro_rules! redf { () => { |c, w| f.reduce62(c, &w[..62]) } }
        report(&format!("{name}_mul31x31_raw_repo_mul"), count!(62, rawmul!()));
        report(&format!("{name}_mul31x31_raw_naive"), count!(62, rawnaive!()));
        report(&format!("{name}_reduce62"), count!(62, redf!()));
        let nmul = count!(62, mulf!());
        let nadd = count!(62, addf!());
        let n3 = count!(31, m3!());
        let n11 = count!(31, m11!());
        report(&format!("{name}_mul_mod"), nmul);
        report(&format!("{name}_add_mod"), nadd);
        report(&format!("{name}_mul_by_3"), n3);
        report(&format!("{name}_mul_by_11"), n11);

        let ev = edge_values(p, &mut rng);
        let mut pairs: Vec<(u64, u64)> = vec![(p - 1, p - 1), (0, 0), (1, p - 1), (p - 1, 0)];
        for &a in &ev { pairs.push((a, ev[rng.gen_range(0..ev.len())])); }
        for _ in 0..TRIALS { pairs.push((rng.gen_range(0..p), rng.gen_range(0..p))); }
        assert!(pairs.len() >= TRIALS);
        for (a, b) in pairs {
            let ab = { let mut v = bits_of(a as u128, 31); v.extend(bits_of(b as u128, 31)); v };
            assert_eq!(val(&run!(ab.clone(), mulf!())), (a as u128 * b as u128) % p as u128, "{name} mul {a} {b}");
            assert_eq!(val(&run!(ab.clone(), rawmul!())), a as u128 * b as u128);
            assert_eq!(val(&run!(ab.clone(), addf!())), ((a + b) % p) as u128, "{name} add {a} {b}");
            let a1 = bits_of(a as u128, 31);
            assert_eq!(val(&run!(a1.clone(), m3!())), (3 * a as u128) % p as u128, "{name} x3 {a}");
            assert_eq!(val(&run!(a1, m11!())), (11 * a as u128) % p as u128, "{name} x11 {a}");
        }
        assert_eq!((nmul, nadd, n3, n11), expected_field(name), "{name} counts");
    }
}
fn expected_field(n: &str) -> (u64, u64, u64, u64) { if n == "koalabear" { (2068, 94, 159, 328) } else { (2161, 94, 159, 328) } }

#[test]
fn ext4_mul() {
    let mut rng = ChaChaRng::seed_from_u64(6);
    for (name, f) in fields() {
        let p = f.p as u128;
        let w = f.w_ext as u128;
        macro_rules! em { () => { |c, v| {
            let a: Vec<Vec<WireId>> = (0..4).map(|i| v[31 * i..31 * i + 31].to_vec()).collect();
            let b: Vec<Vec<WireId>> = (0..4).map(|i| v[124 + 31 * i..124 + 31 * i + 31].to_vec()).collect();
            f.ext4_mul(c, &a, &b).concat()
        } } }
        let nf = count!(248, em!());
        report(&format!("{name}_ext4_mul"), nf);
        for t in 0..TRIALS {
            let genv = |rng: &mut ChaChaRng| -> [u128; 4] {
                std::array::from_fn(|_| if t < 4 { p - 1 } else { rng.gen_range(0..p as u64) as u128 })
            };
            let (a, b) = (genv(&mut rng), genv(&mut rng));
            let mut want = [0u128; 4];
            for j in 0..4 { for l in 0..4 {
                let pr = a[j] * b[l] % p;
                if j + l < 4 { want[j + l] = (want[j + l] + pr) % p } else { want[j + l - 4] = (want[j + l - 4] + w * pr) % p }
            } }
            let mut bits = Vec::new();
            for x in a.iter().chain(&b) { bits.extend(bits_of(*x, 31)); }
            let out = run!(bits, em!());
            let got: Vec<u128> = out.chunks(31).map(val).collect();
            assert_eq!(got, want.to_vec(), "{name} ext4");
        }
        assert_eq!(nf, expected_ext(name));
    }
}
fn expected_ext(n: &str) -> u64 { if n == "koalabear" { 34693 } else { 36688 } }
