//! FC03 measurement driver.
//!   fc03 bench OUT.json                 FlatMerkle vs Merkle
//!   fc03 circuits OUT.json REALSHAPE.json  gate counts, garbling, real-shape projections
//!   fc03 regtest BITCOIND BITCOIN-CLI DATADIR OUT.json   the regtest dispute
use flatcheck_fc03::{
    bench,
    cases::Suite,
    circuit::{inputs, row::RowKnown, run, step::StepKnown},
    field::FieldId,
    protocol::*,
};
use nova_snark::provider::{PallasEngine, VestaEngine};
use serde_json::{json, Value};
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

struct Counting;
static CUR: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
static BASE: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(l) };
        if !p.is_null() {
            let c = CUR.fetch_add(l.size(), Ordering::Relaxed) + l.size();
            PEAK.fetch_max(c, Ordering::Relaxed);
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        CUR.fetch_sub(l.size(), Ordering::Relaxed);
        unsafe { System.dealloc(p, l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        let q = unsafe { System.realloc(p, l, n) };
        if !q.is_null() {
            if n > l.size() {
                let c = CUR.fetch_add(n - l.size(), Ordering::Relaxed) + n - l.size();
                PEAK.fetch_max(c, Ordering::Relaxed);
            } else {
                CUR.fetch_sub(l.size() - n, Ordering::Relaxed);
            }
        }
        q
    }
}

#[global_allocator]
static A: Counting = Counting;

fn heap_reset() {
    let c = CUR.load(Ordering::Relaxed);
    BASE.store(c, Ordering::Relaxed);
    PEAK.store(c, Ordering::Relaxed);
}
fn heap_peak() -> usize {
    PEAK.load(Ordering::Relaxed) - BASE.load(Ordering::Relaxed)
}

/// Peak resident set of this process, bytes.
pub fn peak_rss() -> u64 {
    #[cfg(windows)]
    {
        #[repr(C)]
        struct Pmc {
            cb: u32,
            page_fault_count: u32,
            peak_working_set_size: usize,
            working_set_size: usize,
            a: usize,
            b: usize,
            c: usize,
            d: usize,
            pagefile_usage: usize,
            peak_pagefile_usage: usize,
        }
        extern "system" {
            fn GetCurrentProcess() -> isize;
            fn K32GetProcessMemoryInfo(h: isize, p: *mut Pmc, cb: u32) -> i32;
        }
        let mut m: Pmc = unsafe { std::mem::zeroed() };
        m.cb = std::mem::size_of::<Pmc>() as u32;
        unsafe { K32GetProcessMemoryInfo(GetCurrentProcess(), &mut m, m.cb) };
        m.peak_working_set_size as u64
    }
    #[cfg(not(windows))]
    {
        let s = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
        s.lines()
            .find(|l| l.starts_with("VmHWM:"))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|k| k.parse::<u64>().ok())
            .map(|k| k * 1024)
            .unwrap_or(0)
    }
}

fn write(path: &str, v: &Value) {
    std::fs::write(path, serde_json::to_string_pretty(v).unwrap() + "\n").unwrap();
    eprintln!("wrote {path}");
}

/// A trusted configuration with the real HeaderStep primary dimensions (values of roots and
/// digests do not change any gate count; only sizes and the field do).
fn real_tc(field: u8, num: u32, k: [u32; 3]) -> TrustedConfig {
    let pow = |n: u64| n.max(4).next_power_of_two() as u32;
    TrustedConfig {
        field,
        network: "regtest".into(),
        shape_digest: [7; 32],
        matrix_root: [8; 32],
        matrix_leaves: pow(num as u64),
        num_cons: num,
        num_vars: num,
        num_io: 2,
        k,
        w_leaves: pow(num as u64 + 1),
        e_leaves: pow(num as u64 + 1),
        ck_len: num,
        ck_root: [9; 32],
        ck_leaves: pow(num as u64 + 1),
        trace_w_leaves: pow((num as u64 + 1) * 256 + 1),
        trace_e_leaves: pow((num as u64 + 1) * 256 + 1),
        pp_digest: [3; 32],
        ro: RO_ID.into(),
    }
}

fn count(w: &run::Which, len: usize) -> (u64, f64) {
    let t = std::time::Instant::now();
    let (_, nf, _) = run::execute(w, vec![false; len * 8]);
    (nf, t.elapsed().as_secs_f64())
}

fn circuits(out: &str, realshape: &str) {
    let p = Suite::<PallasEngine>::build(0xFC03_0001);
    let v = Suite::<VestaEngine>::build(0xFC03_0002);
    let mut all = p.cases.clone();
    all.extend(v.cases.clone());
    let mut toy = Vec::new();
    for (label, pick) in [
        ("row/honest", "/honest/row3"),
        ("row/refuted", "/W2-changed-row3"),
        ("step-W/honest", "/honest/binding-step-W-255"),
        ("step-W/refuted", "/forged-WE-end-patched/last-step-W"),
        ("step-E/honest", "/honest/binding-step-E-700"),
    ] {
        for f in [FieldId::PallasScalar, FieldId::VestaScalar] {
            let c = all.iter().find(|c| c.field == f && c.name.ends_with(pick)).unwrap();
            let tc = if f == FieldId::PallasScalar { &p.toy.pinned.tc } else { &v.toy.pinned.tc };
            let (w, bytes) = match c.challenge.kind {
                ChallengeKind::Row { .. } => (run::Which::Row(RowKnown::new(tc)), inputs::row_input(tc, &c.claim, &c.challenge, c.response.as_ref()).unwrap()),
                ChallengeKind::BindingStep { vec, .. } => {
                    (run::Which::Step(StepKnown::new(tc, vec)), inputs::step_input(tc, &c.claim, &c.challenge, c.response.as_ref(), vec).unwrap())
                }
                _ => unreachable!(),
            };
            let bits = inputs::bits(&bytes);
            let t = std::time::Instant::now();
            let (outb, nf, total) = run::execute(&w, bits.clone());
            let exec_s = t.elapsed().as_secs_f64();
            let rep = run::garble_and_evaluate(&w, bits, 0xFC03);
            assert_eq!(rep.refutes(), Some(c.expected_refutes));
            assert_eq!(outb, c.expected_refutes);
            toy.push(json!({
                "circuit": label, "field": f.name(), "case": c.name,
                "nonfree_gates_execute": nf, "total_gates": total, "ciphertexts": rep.ciphertexts, "ciphertext_bytes": rep.ciphertext_bytes,
                "input_bits": rep.input_labels, "input_label_bytes": rep.input_labels * 16,
                "execute_seconds": exec_s, "garble_and_evaluate_seconds": rep.garble_and_evaluate_seconds,
                "evaluator_got": if rep.refutes() == Some(true) { "refute label" } else { "accept label" },
                "process_peak_rss_bytes_so_far": peak_rss(),
            }));
            eprintln!("{label} {} nonfree={nf} cts={} {:.2}s", f.name(), rep.ciphertexts, rep.garble_and_evaluate_seconds);
        }
    }
    // Real HeaderStep primary dimensions.
    let rs: Value = serde_json::from_str(&std::fs::read_to_string(realshape).unwrap()).unwrap();
    let prim = &rs["primary"];
    let num = prim["num_cons"].as_u64().unwrap() as u32;
    let kmax = [prim["max_per_row"]["A"].as_u64().unwrap() as u32, prim["max_per_row"]["B"].as_u64().unwrap() as u32, prim["max_per_row"]["C"].as_u64().unwrap() as u32];
    let fid = FieldId::PallasScalar.byte();
    let mut real = Vec::new();
    // Exact counts at real tree depths. Above DUP_CHECK_MAX_SLOTS the circuit is a fixed part plus
    // one identical block per slot, so the widest row is a linear extrapolation from exact points;
    // building it (~1.1e9 gates) needs more than 20 GB in ExecuteMode, beyond this host.
    let mut pts = Vec::new();
    for k in [[1u32, 1, 1], [2, 1, 1], [16, 8, 8], [32, 16, 8], [64, 16, 8]] {
        let tc = real_tc(fid, num, k);
        let len = inputs::row_input_len(&tc);
        let (nf, s) = count(&run::Which::Row(RowKnown::new(&tc)), len);
        let slots = k.iter().sum::<u32>();
        eprintln!("real row K={k:?} nonfree={nf} ({s:.1}s)");
        if slots as usize > flatcheck_fc03::circuit::row::DUP_CHECK_MAX_SLOTS {
            pts.push((slots as f64, nf as f64));
        }
        real.push(json!({"circuit": "row", "k": k, "slots": slots, "input_bytes": len, "nonfree_gates": nf, "execute_seconds": s, "exact": true}));
    }
    let n = pts.len() as f64;
    let (sx, sy) = (pts.iter().map(|p| p.0).sum::<f64>(), pts.iter().map(|p| p.1).sum::<f64>());
    let sxx = pts.iter().map(|p| p.0 * p.0).sum::<f64>();
    let sxy = pts.iter().map(|p| p.0 * p.1).sum::<f64>();
    let b = (n * sxy - sx * sy) / (n * sxx - sx * sx);
    let a = (sy - b * sx) / n;
    let resid = pts.iter().map(|p| (p.1 - (a + b * p.0)).abs()).fold(0.0, f64::max);
    let kslots = kmax.iter().sum::<u32>() as f64;
    let p99 = prim["row_total_nnz"]["p99"].as_f64().unwrap();
    real.push(json!({"circuit": "row", "k": kmax, "slots": kslots, "nonfree_gates": (a + b * kslots).round(), "exact": false,
        "model": {"fixed": a.round(), "per_slot": b.round(), "max_abs_residual_on_exact_points": resid, "fit_points_slots": pts.iter().map(|p| p.0).collect::<Vec<_>>()}}));
    real.push(json!({"circuit": "row (p99 width)", "slots": p99, "nonfree_gates": (a + b * p99).round(), "exact": false}));
    for vv in [Vector::W, Vector::E] {
        let tc = real_tc(fid, num, kmax);
        let len = inputs::step_input_len(&tc, vv);
        let (nf, s) = count(&run::Which::Step(StepKnown::new(&tc, vv)), len);
        eprintln!("real step {vv:?} nonfree={nf} ({s:.1}s)");
        real.push(json!({"circuit": format!("step-{vv:?}"), "trace_leaves": tc.trace_leaves(vv), "input_bytes": len, "nonfree_gates": nf, "execute_seconds": s, "exact": true}));
    }
    write(
        out,
        &json!({
            "toy": toy,
            "real_headerstep_primary": {"source": realshape, "num_cons": num, "k_max": kmax, "row_total_nnz": prim["row_total_nnz"], "counts": real},
            "baseline": {
                "what": "complete final verifier of the Nova proof (SP1 wrap, BLAKE3 transcript v2) as one garbled circuit",
                "nonfree_gates": 785_442_492u64,
                "source": "integrations/bitvm3-nova/m14/README.md (garbled-snark-verifier m14/e2e, commit f6ec7ab)",
            },
            "garbling_scheme": "garbled-snark-verifier 8fa7efe GarbleMode with AesCcrGateHasher (free-XOR, one 16-byte ciphertext per non-free gate)",
            "process_peak_rss_bytes": peak_rss(),
        }),
    );
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    match a.get(1).map(String::as_str) {
        Some("bench") => {
            let v = bench::run(&bench::HeapProbe { reset: heap_reset, peak: heap_peak });
            let mut v = v;
            v["process_peak_rss_bytes"] = json!(peak_rss());
            write(&a[2], &v);
        }
        Some("circuits") => circuits(&a[2], &a[3]),
        Some("regtest") => {
            let v = flatcheck_fc03::regtest::run(&a[2], &a[3], &a[4]).unwrap_or_else(|e| panic!("regtest: {e}"));
            write(&a[5], &v);
        }
        _ => eprintln!("usage: fc03 bench OUT | circuits OUT REALSHAPE | regtest BITCOIND BITCOIN-CLI DATADIR OUT"),
    }
}
