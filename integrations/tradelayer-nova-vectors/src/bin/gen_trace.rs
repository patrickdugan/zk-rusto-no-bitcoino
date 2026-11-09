//! Verifier traces: re-verifies a stored (vk, proof) with nova's own verify, under a recording Engine
//! that logs every Poseidon RO squeeze and every Keccak transcript operation.
use ff::PrimeField;
use group::GroupEncoding;
use halo2curves::pasta::{Fp, Fq};
use nova_snark::errors::NovaError;
use nova_snark::nova::CompressedSNARK;
use nova_snark::provider::keccak::Keccak256Transcript;
use nova_snark::provider::pasta::{pallas, vesta};
use nova_snark::provider::pedersen::CommitmentEngine as PedersenCE;
use nova_snark::provider::poseidon::{PoseidonConstantsCircuit, PoseidonRO, PoseidonROCircuit};
use nova_snark::provider::traits::DlogGroup;
use nova_snark::provider::ipa_pc;
use nova_snark::spartan::ppsnark::RelaxedR1CSSNARK;
use nova_snark::traits::circuit::TrivialCircuit;
use nova_snark::traits::{Engine, ROTrait, TranscriptEngineTrait, TranscriptReprTrait};
use nova_vectors::util::*;
use serde::{Deserialize, Serialize};
use std::sync::Mutex;

static ROLOG: Mutex<Vec<String>> = Mutex::new(Vec::new());
static TELOG: Mutex<Vec<(String, Vec<String>)>> = Mutex::new(Vec::new());

pub struct LogRO<B: PrimeField + ff::PrimeFieldBits + Serialize + for<'de> Deserialize<'de>> {
    inner: PoseidonRO<B>,
    buf: Vec<B>,
}

fn fname<B: PrimeField>() -> &'static str {
    if B::MODULUS.ends_with("d00000001") {
        "fp"
    } else {
        "fq"
    }
}

impl<B: PrimeField + ff::PrimeFieldBits + Serialize + for<'de> Deserialize<'de>> ROTrait<B> for LogRO<B> {
    type CircuitRO = PoseidonROCircuit<B>;
    type Constants = PoseidonConstantsCircuit<B>;
    fn new(c: Self::Constants) -> Self {
        LogRO { inner: <PoseidonRO<B> as ROTrait<B>>::new(c), buf: vec![] }
    }
    fn absorb(&mut self, e: B) {
        self.inner.absorb(e);
        self.buf.push(e);
    }
    fn squeeze(&mut self, num_bits: usize, start_with_one: bool) -> B {
        let out = self.inner.squeeze(num_bits, start_with_one);
        let line = format!(
            "ro\t{}\t{}\t{}\t{}\t{}",
            fname::<B>(),
            num_bits,
            if start_with_one { 1 } else { 0 },
            fe(&out),
            self.buf.iter().map(|x| fe(x)).collect::<Vec<_>>().join(",")
        );
        ROLOG.lock().unwrap().push(line);
        self.buf.clear();
        out
    }
}

pub struct LogTE<E: Engine> {
    inner: Keccak256Transcript<E>,
    lines: Vec<String>,
    tag: &'static str,
}

impl<E: Engine> Drop for LogTE<E> {
    fn drop(&mut self) {
        TELOG.lock().unwrap().push((self.tag.to_string(), std::mem::take(&mut self.lines)));
    }
}

fn lab(l: &[u8]) -> String {
    String::from_utf8_lossy(l).to_string()
}

macro_rules! rec_engine {
    ($E:ident, $m:ident, $tag:expr, $Base:ty, $Scalar:ty) => {
        #[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
        pub struct $E;
        impl Engine for $E {
            type Base = $m::Base;
            type Scalar = $m::Scalar;
            type GE = $m::Point;
            type RO = LogRO<$Base>;
            type ROCircuit = PoseidonROCircuit<$Base>;
            type RO2 = PoseidonRO<$Scalar>;
            type RO2Circuit = PoseidonROCircuit<$Scalar>;
            type TE = LogTE<$E>;
            type CE = PedersenCE<$E>;
        }
        impl TranscriptEngineTrait<$E> for LogTE<$E> {
            fn new(label: &'static [u8]) -> Self {
                LogTE { inner: Keccak256Transcript::<$E>::new(label), lines: vec![format!("te_begin\t{}\t{}", $tag, lab(label))], tag: $tag }
            }
            fn squeeze(&mut self, label: &'static [u8]) -> Result<$Scalar, NovaError> {
                let o = self.inner.squeeze(label)?;
                self.lines.push(format!("te_squeeze\t{}\t{}", lab(label), fe(&o)));
                Ok(o)
            }
            fn squeeze_bits(&mut self, label: &'static [u8], nb: usize, one: bool) -> Result<$Scalar, NovaError> {
                let o = self.inner.squeeze_bits(label, nb, one)?;
                self.lines.push(format!("te_squeeze_bits\t{}\t{}\t{}\t{}", lab(label), nb, one as u8, fe(&o)));
                Ok(o)
            }
            fn absorb<T: TranscriptReprTrait<<$E as Engine>::GE>>(&mut self, label: &'static [u8], o: &T) {
                self.inner.absorb(label, o);
                self.lines.push(format!("te_absorb\t{}\t{}", lab(label), hx(&o.to_transcript_bytes())));
            }
            fn dom_sep(&mut self, bytes: &'static [u8]) {
                self.inner.dom_sep(bytes);
                self.lines.push(format!("te_dom_sep\t{}", lab(bytes)));
            }
        }
    };
}

rec_engine!(RecP, pallas, "pallas", Fp, Fq);
rec_engine!(RecV, vesta, "vesta", Fq, Fp);

type S1 = RelaxedR1CSSNARK<RecP, ipa_pc::EvaluationEngine<RecP>>;
type S2 = RelaxedR1CSSNARK<RecV, ipa_pc::EvaluationEngine<RecV>>;
type C = TrivialCircuit<Fq>;

fn meta_get(meta: &str, key: &str) -> String {
    meta.lines().find(|l| l.starts_with(&format!("{key}\t"))).unwrap_or_else(|| panic!("meta key {key}")).split('\t').nth(1).unwrap().to_string()
}

fn rebuild_vk(stripped: &[u8], meta: &str) -> Vec<u8> {
    let mut ranges: Vec<(String, usize, usize)> = Vec::new();
    for l in meta.lines() {
        if l.starts_with("vk_removed_generator_range\t") {
            let p: Vec<&str> = l.split('\t').collect();
            ranges.push((p[1].to_string(), p[2].parse().unwrap(), p[3].parse().unwrap()));
        }
    }
    let n_p: usize = meta_get(meta, "ck_primary_generators").parse().unwrap();
    let n_s: usize = meta_get(meta, "ck_secondary_generators").parse().unwrap();
    let gp = <halo2curves::pasta::Pallas as DlogGroup>::from_label(b"ck", n_p + 1);
    let ip = <halo2curves::pasta::Pallas as DlogGroup>::from_label(b"ipa", 2);
    let gv = <halo2curves::pasta::Vesta as DlogGroup>::from_label(b"ck", n_s + 1);
    let iv = <halo2curves::pasta::Vesta as DlogGroup>::from_label(b"ipa", 2);
    fn list<A: GroupEncoding>(pts: &[A]) -> Vec<u8> {
        let mut v = (pts.len() as u64).to_le_bytes().to_vec();
        for p in pts {
            v.extend_from_slice(p.to_bytes().as_ref());
        }
        v
    }
    let mut out = Vec::new();
    let mut cur_o = 0usize; // original coordinates
    let mut cur_s = 0usize; // stripped coordinates
    for (name, st, ln) in ranges {
        let take = st - cur_o;
        out.extend_from_slice(&stripped[cur_s..cur_s + take]);
        cur_s += take;
        let ins = match name.as_str() {
            "vk_primary.ck_v.generators" => list(&gp[1..]),
            "vk_primary.ck_s.generators" => list(&ip[1..]),
            "vk_secondary.ck_v.generators" => list(&gv[1..]),
            "vk_secondary.ck_s.generators" => list(&iv[1..]),
            _ => panic!("unknown range {name}"),
        };
        assert_eq!(ins.len(), ln);
        out.extend_from_slice(&ins);
        cur_o = st + ln;
    }
    out.extend_from_slice(&stripped[cur_s..]);
    out
}

fn main() {
    let names: Vec<String> = std::env::args().skip(1).collect();
    for name in names {
        let dir = out_dir();
        let meta = std::fs::read_to_string(dir.join(format!("{name}.meta.tsv"))).unwrap();
        let stripped = hex::decode(std::fs::read_to_string(dir.join(format!("{name}.vk_nogens.hex"))).unwrap().trim()).unwrap();
        let proof = hex::decode(std::fs::read_to_string(dir.join(format!("{name}.proof.hex"))).unwrap().trim()).unwrap();
        let vk_bytes = rebuild_vk(&stripped, &meta);
        let want: usize = meta_get(&meta, "vk_bytes").parse().unwrap();
        assert_eq!(vk_bytes.len(), want, "rebuilt vk size");
        assert_eq!(hx(&<sha2::Sha256 as sha2::Digest>::digest(&vk_bytes)), meta_get(&meta, "vk_sha256"), "rebuilt vk hash");
        let num_steps: usize = meta_get(&meta, "num_steps").parse().unwrap();
        let z0: Vec<Fq> = meta_get(&meta, "z0")
            .split(',')
            .map(|h| {
                let mut r = <Fq as PrimeField>::Repr::default();
                r.as_mut().copy_from_slice(&hex::decode(h).unwrap());
                Option::from(Fq::from_repr(r)).unwrap()
            })
            .collect();
        type Snark = CompressedSNARK<RecP, RecV, C, S1, S2>;
        let vk: nova_snark::nova::VerifierKey<RecP, RecV, C, S1, S2> = bincode::deserialize(&vk_bytes).unwrap();
        let snark: Snark = bincode::deserialize(&proof).unwrap();
        ROLOG.lock().unwrap().clear();
        TELOG.lock().unwrap().clear();
        let zn = snark.verify(&vk, num_steps, &z0).expect("recording verify succeeds");
        assert_eq!(meta_get(&meta, "zn"), zn.iter().map(|f| fe(f)).collect::<Vec<_>>().join(","));
        drop(snark);
        let mut t = Tsv::default();
        t.comment(&format!(
            "{name}.trace.tsv: every Poseidon-RO squeeze and Keccak-transcript operation performed by nova-snark 0.76.0 CompressedSNARK::verify on {name}.proof.hex, in order (RO events), then the two Spartan transcripts.\n\
Records:\n\
 ro <field> <num_bits> <start_with_one> <output> <absorbed elements since the previous squeeze, comma separated, 32 B LE hex>\n\
     field fp = RO over the Pallas base field (E1::RO: hasher2 and the primary NIFS); fq = RO over the Vesta base field (E2::RO: hasher and the secondary NIFS). Each RO object is created fresh (new), so there is no carry-over between records of one verification; within one record the elements listed are exactly the absorbs before that squeeze.\n\
     Order: [hasher (E2 RO): pp_digest, num_steps, z0.., zn.., r_U_secondary (absorb_in_ro), ri_primary] -> record 1 (fq, 250 bits); [hasher2 (E1 RO): scalar_as_base(pp_digest), num_steps, 0, 0, r_U_primary, ri_secondary] -> record 2 (fp, 250 bits); then NIFS Uf secondary (fq, 128 bits), NIFSRelaxed Un secondary (fq, 128), NIFSRelaxed Un primary (fp, 128).\n\
 te_begin <engine> <label>        a new Keccak256Transcript for the Spartan verifier of the primary (pallas) or secondary (vesta) instance; label RelaxedR1CSSNARK\n\
 te_absorb <label> <bytes hex>    exact to_transcript_bytes appended after the label\n\
 te_squeeze <label> <challenge>   te_squeeze_bits ... te_dom_sep <ascii>\n\
Challenges are in the engine's scalar field (pallas -> fq, vesta -> fp)."
        ));
        for l in ROLOG.lock().unwrap().iter() {
            t.s.push_str(l);
            t.s.push('\n');
            t.n += 1;
        }
        let mut tes = TELOG.lock().unwrap().clone();
        tes.sort_by_key(|(tag, _)| if tag == "pallas" { 0 } else { 1 });
        for (_, lines) in tes {
            for l in lines {
                t.s.push_str(&l);
                t.s.push('\n');
                t.n += 1;
            }
        }
        t.save(&format!("{name}.trace.tsv"));
    }
}
