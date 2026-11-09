use ff::PrimeField;
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use std::path::PathBuf;

pub const SEED: &[u8; 32] = b"nova-vectors-0.76.0-seed-2026-11";

pub fn rng() -> ChaCha20Rng {
    ChaCha20Rng::from_seed(*SEED)
}

pub fn rng_for(tag: &str) -> ChaCha20Rng {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(SEED);
    h.update(tag.as_bytes());
    let s: [u8; 32] = h.finalize().into();
    ChaCha20Rng::from_seed(s)
}

pub fn hx(b: &[u8]) -> String {
    hex::encode(b)
}

pub fn fe<F: PrimeField>(f: &F) -> String {
    hex::encode(f.to_repr().as_ref())
}

pub fn rbytes(r: &mut impl RngCore, n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    r.fill_bytes(&mut v);
    v
}

pub fn out_dir() -> PathBuf {
    // NOVA_VEC_OUT: TradeLayer-Rust's fixtures/zk_nova, or a staging directory.
    let p = PathBuf::from(std::env::var("NOVA_VEC_OUT").expect("set NOVA_VEC_OUT to the output directory"));
    std::fs::create_dir_all(&p).unwrap();
    p
}

#[derive(Default)]
pub struct Tsv {
    pub s: String,
    pub n: usize,
}

impl Tsv {
    pub fn comment(&mut self, c: &str) {
        for l in c.lines() {
            self.s.push_str("# ");
            self.s.push_str(l);
            self.s.push('\n');
        }
    }
    pub fn line(&mut self, cols: &[String]) {
        self.s.push_str(&cols.join("\t"));
        self.s.push('\n');
        self.n += 1;
    }
    pub fn save(&self, name: &str) {
        let p = out_dir().join(name);
        std::fs::write(&p, &self.s).unwrap();
        eprintln!("wrote {} ({} records, {} bytes)", p.display(), self.n, self.s.len());
    }
}

#[macro_export]
macro_rules! row {
    ($t:expr, $($x:expr),+ $(,)?) => { $t.line(&[$(($x).to_string()),+]) };
}
