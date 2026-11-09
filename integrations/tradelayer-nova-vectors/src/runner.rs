//! Prove / verify / dump pipeline shared by the small-circuit and NHC1 binaries.
use crate::mirror::*;
use crate::util::*;
use ff::{Field, PrimeField};
use group::GroupEncoding;
use halo2curves::pasta::Fq;
use nova_snark::nova::{CompressedSNARK, PublicParams, RecursiveSNARK};
use nova_snark::provider::traits::DlogGroup;
use nova_snark::provider::{ipa_pc, PallasEngine, VestaEngine};
use nova_snark::spartan::ppsnark::RelaxedR1CSSNARK;
use nova_snark::traits::circuit::StepCircuit;
use nova_snark::traits::snark::{DigestHelperTrait, RelaxedR1CSSNARKTrait};
use sha2::{Digest, Sha256};
use sha3::Sha3_256;
use std::time::Instant;

pub type E1 = PallasEngine;
pub type E2 = VestaEngine;
pub type S1 = RelaxedR1CSSNARK<E1, ipa_pc::EvaluationEngine<E1>>;
pub type S2 = RelaxedR1CSSNARK<E2, ipa_pc::EvaluationEngine<E2>>;

#[repr(C)]
#[allow(non_snake_case)]
struct ProcessMemoryCounters {
    cb: u32,
    PageFaultCount: u32,
    PeakWorkingSetSize: usize,
    WorkingSetSize: usize,
    QuotaPeakPagedPoolUsage: usize,
    QuotaPagedPoolUsage: usize,
    QuotaPeakNonPagedPoolUsage: usize,
    QuotaNonPagedPoolUsage: usize,
    PagefileUsage: usize,
    PeakPagefileUsage: usize,
}

#[link(name = "kernel32")]
extern "system" {
    fn GetCurrentProcess() -> isize;
    fn K32GetProcessMemoryInfo(h: isize, c: *mut ProcessMemoryCounters, cb: u32) -> i32;
}

/// (current working set, peak working set) in bytes
pub fn mem_now() -> (usize, usize) {
    unsafe {
        let mut c: ProcessMemoryCounters = std::mem::zeroed();
        c.cb = std::mem::size_of::<ProcessMemoryCounters>() as u32;
        K32GetProcessMemoryInfo(GetCurrentProcess(), &mut c, c.cb);
        (c.WorkingSetSize, c.PeakWorkingSetSize)
    }
}

pub fn mib(b: usize) -> usize {
    b / (1024 * 1024)
}

/// Prints phase timing and memory to stderr (flushed).
pub fn phase(t0: &Instant, what: &str) {
    let (cur, peak) = mem_now();
    eprintln!("[{:8.1}s] {:<40} ws={} MiB peak={} MiB", t0.elapsed().as_secs_f64(), what, mib(cur), mib(peak));
}

/// Aborts the process if the memory or time budget is exceeded; always prints the numbers first.
pub fn spawn_watchdog(max_gib: usize, max_secs: u64, t0: Instant) {
    std::thread::spawn(move || loop {
        std::thread::sleep(std::time::Duration::from_secs(5));
        let (cur, peak) = mem_now();
        let el = t0.elapsed().as_secs();
        if peak > max_gib * 1024 * 1024 * 1024 || el > max_secs {
            eprintln!("WATCHDOG STOP: elapsed {el}s, ws {} MiB, peak {} MiB (limits {max_gib} GiB / {max_secs}s)", mib(cur), mib(peak));
            std::process::exit(3);
        }
    });
}

fn digest_to_field(d: &[u8; 32]) -> Fq {
    // DigestComputer::map_to_field: the first 250 bits (little-endian bit order inside each byte)
    let mut acc = Fq::ZERO;
    let mut coeff = Fq::ONE;
    for i in 0..250 {
        if (d[i / 8] >> (i % 8)) & 1 == 1 {
            acc += coeff;
        }
        coeff = coeff + coeff;
    }
    acc
}

pub struct Opts {
    pub name: String,
    pub circuit_desc: String,
    pub write_full_vk: bool,
    pub watchdog: bool,
}

pub fn run_proof<C: StepCircuit<Fq>>(o: &Opts, circuits: &[C], z0: &[Fq], expect_zn: Option<Vec<Fq>>) -> Tsv {
    let t0 = Instant::now();
    let out = out_dir();
    let name = &o.name;
    let num_steps = circuits.len();
    let mut meta = Tsv::default();
    meta.comment(&format!(
        "{name}: nova-snark 0.76.0 CompressedSNARK<Pallas, Vesta, C, ppsnark::RelaxedR1CSSNARK<_, ipa_pc::EvaluationEngine<_>>, same for Vesta>.\n\
Circuit: {}\n\
Records <key> <value...>; hex is lowercase; field elements 32 B LE. Byte offsets are into the bincode 1.3 serialization (bincode::serialize).",
        o.circuit_desc
    ));
    macro_rules! kv {
        ($k:expr, $($v:expr),+) => { meta.line(&[$k.to_string(), $(($v).to_string()),+]) };
    }
    kv!("name", name);
    kv!("nova_snark", "0.76.0");
    kv!("num_steps", num_steps);

    phase(&t0, "start");
    let tt = Instant::now();
    let pp = PublicParams::<E1, E2, C>::setup(&circuits[0], &*S1::ck_floor(), &*S2::ck_floor()).unwrap();
    let setup_pp_s = tt.elapsed().as_secs_f64();
    phase(&t0, "public params ready");
    let (nc, nv) = (pp.num_constraints(), pp.num_variables());
    kv!("r1cs_primary_constraints", nc.0);
    kv!("r1cs_primary_variables", nv.0);
    kv!("r1cs_secondary_constraints", nc.1);
    kv!("r1cs_secondary_variables", nv.1);
    let pp_digest = pp.digest();
    kv!("pp_digest", fe(&pp_digest));

    let tt = Instant::now();
    let mut rs = RecursiveSNARK::<E1, E2, C>::new(&pp, &circuits[0], z0).unwrap();
    for (i, c) in circuits.iter().enumerate() {
        rs.prove_step(&pp, c).unwrap();
        phase(&t0, &format!("prove_step {i}"));
    }
    let fold_s = tt.elapsed().as_secs_f64();
    let zr = rs.verify(&pp, num_steps, z0).expect("recursive snark verifies");
    phase(&t0, "recursive verify ok");
    if let Some(e) = &expect_zn {
        assert_eq!(&zr, e, "folded output differs from the native computation");
    }

    let tt = Instant::now();
    let (pk, vk) = CompressedSNARK::<E1, E2, C, S1, S2>::setup(&pp).unwrap();
    let setup_snark_s = tt.elapsed().as_secs_f64();
    phase(&t0, "compressed setup");
    let tt = Instant::now();
    let proof = CompressedSNARK::<E1, E2, C, S1, S2>::prove(&pp, &pk, &rs).unwrap();
    let prove_s = tt.elapsed().as_secs_f64();
    phase(&t0, "compressed prove");
    drop(pk);
    let tt = Instant::now();
    let zn = proof.verify(&vk, num_steps, z0).expect("compressed proof verifies");
    let verify_s = tt.elapsed().as_secs_f64();
    phase(&t0, "compressed verify (nova)");
    assert_eq!(zn, zr);

    let proof_bytes = bincode::serialize(&proof).unwrap();
    let vk_bytes = bincode::serialize(&vk).unwrap();
    drop(pp);
    drop(rs);

    kv!("timing_pp_setup_s", format!("{setup_pp_s:.2}"));
    kv!("timing_fold_s", format!("{fold_s:.2}"));
    kv!("timing_compressed_setup_s", format!("{setup_snark_s:.2}"));
    kv!("timing_compressed_prove_s", format!("{prove_s:.2}"));
    kv!("timing_nova_verify_s", format!("{verify_s:.3}"));
    kv!("peak_working_set_mib", mib(mem_now().1));
    kv!("z0", z0.iter().map(|f| fe(f)).collect::<Vec<_>>().join(","));
    kv!("zn", zn.iter().map(|f| fe(f)).collect::<Vec<_>>().join(","));
    kv!("proof_bytes", proof_bytes.len());
    kv!("proof_sha256", hx(&Sha256::digest(&proof_bytes)));
    kv!("vk_bytes", vk_bytes.len());
    kv!("vk_sha256", hx(&Sha256::digest(&vk_bytes)));

    // ---------------- vk structure
    let vkm: Vk = bincode::deserialize(&vk_bytes).unwrap();
    assert_eq!(bincode::serialize(&vkm).unwrap(), vk_bytes, "vk mirror re-encodes identically");
    assert_eq!(vkm.pp_digest, pp_digest);
    kv!("vk_f_arity", vkm.f_arity);
    let offc = std::cell::Cell::new(0usize);
    let reg = |meta: &mut Tsv, n: &str, l: usize| {
        meta.line(&["vk_region".into(), n.into(), offc.get().to_string(), l.to_string()]);
        offc.set(offc.get() + l);
    };
    reg(&mut meta, "F_arity", 8);
    reg(&mut meta, "ro_consts_primary", size(&vkm.ro_consts_primary));
    reg(&mut meta, "ro_consts_secondary", size(&vkm.ro_consts_secondary));
    reg(&mut meta, "pp_digest", 32);
    // per ppsnark vk: num_cons, num_vars, ck_v{ck vec(len+n*32), h}, ck_s{ck vec, h}, S_comm
    let mut gens_ranges: Vec<(String, usize, usize)> = Vec::new();
    for (pre, vkp) in [("vk_primary", &vkm.vk_primary as &dyn std::any::Any), ("vk_secondary", &vkm.vk_secondary as &dyn std::any::Any)] {
        let _ = vkp;
        let (nc, nv, ckv_n, cks_n, base_pallas) = if pre == "vk_primary" {
            (vkm.vk_primary.num_cons, vkm.vk_primary.num_vars, vkm.vk_primary.vk_ee.ck_v.ck.len(), vkm.vk_primary.vk_ee.ck_s.ck.len(), true)
        } else {
            (vkm.vk_secondary.num_cons, vkm.vk_secondary.num_vars, vkm.vk_secondary.vk_ee.ck_v.ck.len(), vkm.vk_secondary.vk_ee.ck_s.ck.len(), false)
        };
        let _ = base_pallas;
        meta.line(&[format!("{pre}_num_cons"), nc.to_string()]);
        meta.line(&[format!("{pre}_num_vars"), nv.to_string()]);
        meta.line(&[format!("{pre}_ck_v_len"), ckv_n.to_string()]);
        meta.line(&[format!("{pre}_ck_s_len"), cks_n.to_string()]);
        let start = offc.get();
        reg(&mut meta, &format!("{pre}.num_cons"), 8);
        reg(&mut meta, &format!("{pre}.num_vars"), 8);
        // ck_v: u64 count + n*32 (generators) then h (32)
        gens_ranges.push((format!("{pre}.ck_v.generators"), offc.get(), 8 + ckv_n * 32));
        reg(&mut meta, &format!("{pre}.ck_v.generators(u64 count + 32B each)"), 8 + ckv_n * 32);
        reg(&mut meta, &format!("{pre}.ck_v.h"), 32);
        gens_ranges.push((format!("{pre}.ck_s.generators"), offc.get(), 8 + cks_n * 32));
        reg(&mut meta, &format!("{pre}.ck_s.generators(u64 count + 32B each)"), 8 + cks_n * 32);
        reg(&mut meta, &format!("{pre}.ck_s.h"), 32);
        reg(&mut meta, &format!("{pre}.S_comm.N"), 8);
        for n in ["comm_row", "comm_col", "comm_val_A", "comm_val_B", "comm_val_C", "comm_ts_row", "comm_ts_col"] {
            reg(&mut meta, &format!("{pre}.S_comm.{n}"), 32);
        }
        meta.line(&[format!("{pre}_region_total"), (offc.get() - start).to_string()]);
    }
    reg(&mut meta, "dk_primary.h", 32);
    reg(&mut meta, "dk_secondary.h", 32);
    assert_eq!(offc.get(), vk_bytes.len());

    // generator lists must equal from_label(b"ck", n+1) (h first) and from_label(b"ipa", 2)
    let n_ck_p = vkm.vk_primary.vk_ee.ck_v.ck.len();
    let n_ck_s = vkm.vk_secondary.vk_ee.ck_v.ck.len();
    kv!("ck_primary_generators", n_ck_p);
    kv!("ck_secondary_generators", n_ck_s);
    kv!("from_label_n_primary_ck", n_ck_p + 1);
    kv!("from_label_n_secondary_ck", n_ck_s + 1);
    {
        let gp = <halo2curves::pasta::Pallas as DlogGroup>::from_label(b"ck", n_ck_p + 1);
        assert_eq!(gp[0], vkm.vk_primary.vk_ee.ck_v.h);
        assert!(gp[1..] == vkm.vk_primary.vk_ee.ck_v.ck[..]);
        let ip = <halo2curves::pasta::Pallas as DlogGroup>::from_label(b"ipa", 2);
        assert_eq!(ip[0], vkm.vk_primary.vk_ee.ck_s.h);
        assert_eq!(ip[1..], vkm.vk_primary.vk_ee.ck_s.ck[..]);
        let mut c = Sha256::new();
        for p in gp.iter() {
            c.update(p.to_bytes().as_ref());
        }
        kv!("sha256_concat_compressed_from_label_ck_primary", hx(&c.finalize()));
        let gv = <halo2curves::pasta::Vesta as DlogGroup>::from_label(b"ck", n_ck_s + 1);
        assert_eq!(gv[0], vkm.vk_secondary.vk_ee.ck_v.h);
        assert!(gv[1..] == vkm.vk_secondary.vk_ee.ck_v.ck[..]);
        let iv = <halo2curves::pasta::Vesta as DlogGroup>::from_label(b"ipa", 2);
        assert_eq!(iv[0], vkm.vk_secondary.vk_ee.ck_s.h);
        assert_eq!(iv[1..], vkm.vk_secondary.vk_ee.ck_s.ck[..]);
        let mut c = Sha256::new();
        for p in gv.iter() {
            c.update(p.to_bytes().as_ref());
        }
        kv!("sha256_concat_compressed_from_label_ck_secondary", hx(&c.finalize()));
        assert_eq!(vkm.dk_primary.as_slice(), gp[0].to_bytes().as_ref());
        assert_eq!(vkm.dk_secondary.as_slice(), gv[0].to_bytes().as_ref());
    }
    kv!("vk_generators_checked_against_from_label", "true");
    let gens_bytes: usize = gens_ranges.iter().map(|g| g.2).sum();
    kv!("vk_generator_list_bytes", gens_bytes);
    kv!("vk_without_generator_lists_bytes", vk_bytes.len() - gens_bytes);

    // vk digests (key into the Spartan transcript: absorb(b"vk", vk.digest()))
    let vk_regions: Vec<(usize, usize)> = {
        // locate vk_primary / vk_secondary byte ranges from the region records
        let find = |n: &str| -> (usize, usize) {
            let r = meta.s.lines().find(|l| l.starts_with(&format!("vk_region\t{n}\t"))).unwrap();
            let p: Vec<&str> = r.split('\t').collect();
            (p[2].parse().unwrap(), p[3].parse().unwrap())
        };
        let a = find("vk_primary.num_cons").0;
        let b = find("vk_secondary.num_cons").0;
        let c = find("dk_primary.h").0;
        vec![(a, b - a), (b, c - b)]
    };
    let vkp: <S1 as RelaxedR1CSSNARKTrait<E1>>::VerifierKey = bincode::deserialize(&vk_bytes[vk_regions[0].0..vk_regions[0].0 + vk_regions[0].1]).unwrap();
    let vks: <S2 as RelaxedR1CSSNARKTrait<E2>>::VerifierKey = bincode::deserialize(&vk_bytes[vk_regions[1].0..vk_regions[1].0 + vk_regions[1].1]).unwrap();
    let dg_p = DigestHelperTrait::<E1>::digest(&vkp);
    let dg_s = DigestHelperTrait::<E2>::digest(&vks);
    for (lab, (st, ln), lib) in [("vk_primary_digest", vk_regions[0], hx(dg_p.to_repr().as_ref())), ("vk_secondary_digest", vk_regions[1], hx(dg_s.to_repr().as_ref()))] {
        let mut h = Sha3_256::new();
        h.update(&vk_bytes[st..st + ln]);
        let d: [u8; 32] = h.finalize().into();
        let ind = digest_to_field(&d);
        // the primary vk digest is a Pallas scalar (Fq); the secondary one a Vesta scalar (Fp)
        let ind_hex = if lab == "vk_primary_digest" { fe(&ind) } else { let mut acc = halo2curves::pasta::Fp::ZERO; let mut coeff = halo2curves::pasta::Fp::ONE; for i in 0..250 { if (d[i / 8] >> (i % 8)) & 1 == 1 { acc += coeff; } coeff = coeff + coeff; } fe(&acc) };
        assert_eq!(ind_hex, lib, "independent digest = library digest ({lab})");
        kv!(lab, lib);
        kv!(format!("{lab}_input_sha3_256"), hx(&d));
    }

    // ---------------- proof structure
    let pm: ProofMirror = bincode::deserialize(&proof_bytes).unwrap();
    assert_eq!(bincode::serialize(&pm).unwrap(), proof_bytes, "proof mirror re-encodes identically");
    let layout = proof_layout(&pm);
    for (n, off, len) in &layout {
        meta.line(&["proof_region".into(), n.clone(), off.to_string(), len.to_string()]);
    }
    kv!("proof_sumcheck_outer_rounds_primary", pm_rounds(&bincode::serialize(&pm.snark_primary.sc_outer).unwrap()));
    kv!("proof_sumcheck_inner_rounds_primary", pm_rounds(&bincode::serialize(&pm.snark_primary.sc_inner_batched).unwrap()));
    kv!("proof_ipa_rounds_primary", pm.snark_primary.eval_arg.l_vec.len());
    kv!("proof_sumcheck_outer_rounds_secondary", pm_rounds(&bincode::serialize(&pm.snark_secondary.sc_outer).unwrap()));
    kv!("proof_sumcheck_inner_rounds_secondary", pm_rounds(&bincode::serialize(&pm.snark_secondary.sc_inner_batched).unwrap()));
    kv!("proof_ipa_rounds_secondary", pm.snark_secondary.eval_arg.l_vec.len());

    {
        // size formulas (validated here on every run):
        // snark(Ro, Ri, K) = 864 + 104*(Ro + Ri) + 64*K  with Ro = log2(num_cons padded), Ri = K = log2(N), N = S_comm.N
        let lg = |x: u64| x.trailing_zeros() as usize;
        let snark_sz = |ro: usize, ri: usize, k: usize| 864 + 104 * (ro + ri) + 64 * k;
        let (rop, rip) = (lg(vkm.vk_primary.num_cons), lg(vkm.vk_primary.s_comm.n));
        let (ros, ris) = (lg(vkm.vk_secondary.num_cons), lg(vkm.vk_secondary.s_comm.n));
        let pred_proof = 536 + 400 + 128 + snark_sz(rop, rip, rip) + snark_sz(ros, ris, ris) + 8 + 32 * z0.len();
        assert_eq!(pred_proof, proof_bytes.len(), "proof size formula");
        let vk_one = |n: usize| 16 + (8 + n * 32 + 32) + (8 + 32 + 32) + (8 + 7 * 32);
        let pred_vk = 8 + 2 * size(&vkm.ro_consts_primary) + 32 + vk_one(n_ck_p) + vk_one(n_ck_s) + 64;
        assert_eq!(pred_vk, vk_bytes.len(), "vk size formula");
        kv!("formula_proof_bytes", "536 + 400 + 128 + sum over {primary,secondary} of (864 + 104*(Ro+Ri) + 64*K) + 8 + 32*arity; Ro=log2(num_cons padded) Ri=K=log2(N)");
        kv!("formula_vk_bytes", "8 + 543600 + 32 + sum over {primary,secondary} of (16 + (8+32*n_ck+32) + 72 + 232) + 64; n_ck = N (generator count)");
        kv!("log2_num_cons_primary", rop);
        kv!("log2_N_primary", rip);
        kv!("log2_num_cons_secondary", ros);
        kv!("log2_N_secondary", ris);
    }
    // ---------------- corrupted proofs
    let region = |n: &str| -> (usize, usize) {
        let r = layout.iter().find(|r| r.0 == n).unwrap_or_else(|| panic!("region {n}"));
        (r.1, r.2)
    };
    let mut corrupt_cases: Vec<(String, usize, u8)> = Vec::new();
    corrupt_cases.push(("snark_primary.eval_W low bit".into(), region("snark_primary.eval_W").0, 0x01));
    corrupt_cases.push(("snark_primary.comm_L_row sign bit".into(), region("snark_primary.comm_L_row").0 + 31, 0x80));
    corrupt_cases.push(("snark_secondary.eval_Az_at_r_outer low bit".into(), region("snark_secondary.eval_Az_at_r_outer").0, 0x01));
    corrupt_cases.push(("zn low bit".into(), region("zn").0 + 8, 0x01));
    corrupt_cases.push(("snark_primary.eval_arg.a_hat low bit".into(), region("snark_primary.eval_arg.a_hat").0, 0x01));
    corrupt_cases.push(("r_U_primary.u low bit".into(), region("r_U_primary").0 + 32 * 2 + 8 + 2 * 32, 0x01));
    corrupt_cases.push(("nifs_Un_secondary.comm_T sign bit".into(), region("nifs_Un_secondary").0 + 31, 0x80));
    let mut first_corrupt: Option<Vec<u8>> = None;
    for (i, (what, at, mask)) in corrupt_cases.iter().enumerate() {
        let mut bad = proof_bytes.clone();
        bad[*at] ^= *mask;
        let outcome = match bincode::deserialize::<CompressedSNARK<E1, E2, C, S1, S2>>(&bad) {
            Err(e) => format!("decode_error: {e}"),
            Ok(p) => match p.verify(&vk, num_steps, z0) {
                Ok(_) => "ACCEPTED".to_string(),
                Err(e) => format!("verify_error: {e:?}"),
            },
        };
        assert!(!outcome.starts_with("ACCEPTED"), "corrupted proof accepted: {what}");
        meta.line(&["corrupt".into(), i.to_string(), what.clone(), at.to_string(), format!("xor 0x{:02x}", mask), outcome]);
        if i == 0 {
            first_corrupt = Some(bad);
        }
    }
    // a flip that breaks point decoding: try xor masks on the low byte of comm_L_row's x until bincode rejects it
    {
        let at = region("snark_primary.comm_L_row").0;
        for mask in 1u8..=255 {
            let mut bad = proof_bytes.clone();
            bad[at] ^= mask;
            if let Err(e) = bincode::deserialize::<CompressedSNARK<E1, E2, C, S1, S2>>(&bad) {
                meta.line(&["corrupt_decode".into(), "snark_primary.comm_L_row x low byte".into(), at.to_string(), format!("xor 0x{:02x}", mask), format!("decode_error: {e}")]);
                break;
            }
        }
    }
    // truncation
    let trunc = &proof_bytes[..proof_bytes.len() - 1];
    let tr = match bincode::deserialize::<CompressedSNARK<E1, E2, C, S1, S2>>(trunc) {
        Err(e) => format!("decode_error: {e}"),
        Ok(_) => "ACCEPTED_DECODE".to_string(),
    };
    meta.line(&["corrupt_truncated_by_1".into(), tr]);
    // wrong num_steps and wrong z0
    {
        let p2: CompressedSNARK<E1, E2, C, S1, S2> = bincode::deserialize(&proof_bytes).unwrap();
        let r = p2.verify(&vk, num_steps + 1, z0);
        assert!(r.is_err());
        meta.line(&["wrong_num_steps".into(), (num_steps + 1).to_string(), format!("verify_error: {:?}", r.err().unwrap())]);
        let mut z1 = z0.to_vec();
        z1[0] += Fq::ONE;
        let r = p2.verify(&vk, num_steps, &z1);
        assert!(r.is_err());
        meta.line(&["wrong_z0".into(), "z0[0]+1".into(), format!("verify_error: {:?}", r.err().unwrap())]);
    }

    // ---------------- files
    std::fs::write(out.join(format!("{name}.proof.hex")), format!("{}\n", hx(&proof_bytes))).unwrap();
    std::fs::write(out.join(format!("{name}.proof_corrupt0.hex")), format!("{}\n", hx(&first_corrupt.unwrap()))).unwrap();
    // vk with the generator lists removed (the removed ranges are listed in vk_region records and are regenerable)
    let mut stripped = Vec::new();
    let mut cursor = 0usize;
    for (_, st, ln) in &gens_ranges {
        stripped.extend_from_slice(&vk_bytes[cursor..*st]);
        cursor = st + ln;
    }
    stripped.extend_from_slice(&vk_bytes[cursor..]);
    std::fs::write(out.join(format!("{name}.vk_nogens.hex")), format!("{}\n", hx(&stripped))).unwrap();
    kv!("vk_nogens_sha256", hx(&Sha256::digest(&stripped)));
    for (n, st, ln) in &gens_ranges {
        meta.line(&["vk_removed_generator_range".into(), n.clone(), st.to_string(), ln.to_string()]);
    }
    if o.write_full_vk {
        std::fs::write(out.join(format!("{name}.vk.hex")), format!("{}\n", hx(&vk_bytes))).unwrap();
    }
    kv!("total_wall_s", format!("{:.1}", t0.elapsed().as_secs_f64()));
    meta.save(&format!("{name}.meta.tsv"));
    meta
}

fn pm_rounds(b: &[u8]) -> u64 {
    u64::from_le_bytes(b[0..8].try_into().unwrap())
}
