//! m12 vk-export NET K OUT
//! m12 prove NET K STEPS HEADERS.bin OUTDIR     (fold from genesis; writes bundle, vk, accumulator, report)
//! m12 verify BUNDLE VK [--unpinned]           (statement-bound native verification)
//! m12 decider-b VK ACCUMULATOR [--skip-pcs]    (architecture B relation on a real folded witness)
#![allow(non_snake_case)]
use nova_bitvm3_m12::{
  decider_b,
  mirror::{self, CompressedVk, RecursiveMirror},
  nova_io::{self, sha256_hex},
};
use nova_header_chain::native::Network;
use std::{path::PathBuf, time::Instant};

fn net(s: &str) -> Network {
  Network::parse(s).expect("network: mainnet|testnet4")
}

fn peak_rss_mib() -> Option<u64> {
  let s = std::fs::read_to_string("/proc/self/status").ok()?;
  let l = s.lines().find(|l| l.starts_with("VmHWM:"))?;
  l.split_whitespace().nth(1)?.parse::<u64>().ok().map(|kb| kb / 1024)
}

fn main() {
  let a: Vec<String> = std::env::args().collect();
  match a.get(1).map(String::as_str) {
    Some("vk-export") => {
      let t = Instant::now();
      let vk = nova_io::vk_export(net(&a[2]), a[3].parse().unwrap());
      std::fs::write(&a[4], &vk).unwrap();
      println!(
        "{}",
        serde_json::json!({"vk_bytes": vk.len(), "vk_sha256": sha256_hex(&vk), "seconds": t.elapsed().as_secs_f64(), "peak_rss_mib": peak_rss_mib()})
      );
    }
    Some("prove") => {
      let n = net(&a[2]);
      let (k, steps): (usize, usize) = (a[3].parse().unwrap(), a[4].parse().unwrap());
      let hs = nova_io::load_headers_bin(&std::fs::read(&a[5]).unwrap(), n).unwrap();
      let out = PathBuf::from(&a[6]);
      std::fs::create_dir_all(&out).unwrap();
      let p = nova_io::prove_from_genesis(n, k, steps, &hs).unwrap();
      let tag = format!("{}-k{k}-0-{}", n.name(), k * steps);
      std::fs::write(out.join(format!("{tag}.{}", if n == Network::Testnet4 { "nht4" } else { "nhc1" })), &p.bundle).unwrap();
      std::fs::write(out.join(format!("{tag}.vk")), &p.vk).unwrap();
      std::fs::write(out.join(format!("{tag}.accumulator.bin")), &p.rs_bytes).unwrap();
      let mut r = p.report.clone();
      r["peak_rss_mib"] = serde_json::json!(peak_rss_mib());
      std::fs::write(out.join(format!("{tag}.report.json")), serde_json::to_string_pretty(&r).unwrap()).unwrap();
      println!("{}", serde_json::to_string_pretty(&r).unwrap());
    }
    Some("verify") => {
      let bundle = std::fs::read(&a[2]).unwrap();
      let vk = std::fs::read(&a[3]).unwrap();
      let res = if a.iter().any(|x| x == "--unpinned") {
        nova_io::verify_unpinned(&bundle, &vk)
      } else {
        nova_io::verify_statement(&bundle, &vk)
      };
      match res {
        Ok(v) => {
          let mut j = serde_json::to_value(&v.statement).unwrap();
          j["verified"] = true.into();
          j["vk_decode_seconds"] = v.vk_decode_seconds.into();
          j["verify_seconds"] = v.verify_seconds.into();
          j["peak_rss_mib"] = serde_json::json!(peak_rss_mib());
          println!("{}", serde_json::to_string_pretty(&j).unwrap());
        }
        Err(e) => {
          println!("{}", serde_json::json!({"verified": false, "error": e}));
          std::process::exit(1);
        }
      }
    }
    Some("decider-b") => {
      let t = Instant::now();
      let vk_b = std::fs::read(&a[2]).unwrap();
      let vk: CompressedVk = mirror::decode_exact(&vk_b).unwrap();
      drop(vk_b);
      let vk_decode_s = t.elapsed().as_secs_f64();
      let acc = std::fs::read(&a[3]).unwrap();
      let t = Instant::now();
      let rs: RecursiveMirror = mirror::decode_exact(&acc).unwrap();
      let acc_decode_s = t.elapsed().as_secs_f64();
      let (U, Wt) = (&rs.r_U_primary, &rs.r_W_primary);
      let s = &vk.vk_primary.S;
      let ck = &vk.vk_primary.vk_ee.ck_v;
      let t = Instant::now();
      decider_b::relaxed_sat(s, &Wt.W, &Wt.E, U.u, &U.X).unwrap();
      let r1cs_s = t.elapsed().as_secs_f64();
      let t = Instant::now();
      let bw = decider_b::pedersen(ck, &Wt.W, &Wt.r_W) == U.comm_W;
      let be = decider_b::pedersen(ck, &Wt.E, &Wt.r_E) == U.comm_E;
      let two_msm_s = t.elapsed().as_secs_f64();
      assert!(bw && be, "honest witness must bind");
      let t = Instant::now();
      let gamma = nova_io::F1::from(7u64);
      assert!(decider_b::binds_combined(ck, &U.comm_W, &U.comm_E, &Wt.W, &Wt.E, Wt.r_W, Wt.r_E, gamma));
      let combined_msm_s = t.elapsed().as_secs_f64();
      let mut report = serde_json::json!({
        "vk_sha256": sha256_hex(&std::fs::read(&a[2]).unwrap()), "accumulator_sha256": sha256_hex(&acc),
        "accumulator_bytes": acc.len(), "steps_i": rs.i,
        "z0_sha256": sha256_hex(&nova_io::z_bytes(&rs.z0)), "zi_sha256": sha256_hex(&nova_io::z_bytes(&rs.zi)),
        "primary": {"W_len": Wt.W.len(), "E_len": Wt.E.len(), "padded_rows": s.num_cons, "padded_vars": s.num_vars,
                     "nnz": s.A.data.len() + s.B.data.len() + s.C.data.len()},
        "secondary": {"W_len": rs.r_W_secondary.W.len(), "E_len": rs.r_W_secondary.E.len(), "fresh_W_len": rs.l_w_secondary.W.len()},
        "seconds": {"vk_decode": vk_decode_s, "accumulator_decode": acc_decode_s, "relaxed_r1cs_check": r1cs_s,
                    "pedersen_two_msms": two_msm_s, "pedersen_combined_msm": combined_msm_s},
      });
      if !a.iter().any(|x| x == "--skip-pcs") {
        let nw = decider_b::num_vars_for(s.num_vars);
        let ne = decider_b::num_vars_for(s.num_cons);
        let t = Instant::now();
        let (p, _, _) = decider_b::prove(U, &Wt.W, &Wt.E, nw, ne);
        let prove_s = t.elapsed().as_secs_f64();
        let t = Instant::now();
        decider_b::verify_pcs_only(U, &p).unwrap();
        let pcs_verify_s = t.elapsed().as_secs_f64();
        let t = Instant::now();
        decider_b::verify_with_binding(U, &p, s, ck, &Wt.W, &Wt.E, Wt.r_W, Wt.r_E).unwrap();
        let full_s = t.elapsed().as_secs_f64();
        // The forgery: any W' with E' = A z' o B z' - u C z'.
        let mut w2 = Wt.W.clone();
        w2[0] += nova_io::F1::from(1u64);
        let e2 = decider_b::forge_error(s, &w2, U.u, &U.X).unwrap();
        let (pf, _, _) = decider_b::prove(U, &w2, &e2, nw, ne);
        let pcs_only_accepts_forgery = decider_b::verify_pcs_only(U, &pf).is_ok();
        let relaxed_accepts_forgery = decider_b::relaxed_sat(s, &w2, &e2, U.u, &U.X).is_ok();
        let binding_err = decider_b::verify_with_binding(U, &pf, s, ck, &w2, &e2, Wt.r_W, Wt.r_E).err();
        report["pcs"] = serde_json::json!({
          "num_vars_W": nw, "num_vars_E": ne, "queries": nova_bitvm3_m12::pcs::QUERIES,
          "proof_bytes": p.size_bytes(), "prove_seconds": prove_s, "pcs_verify_seconds": pcs_verify_s,
          "relation_with_binding_seconds": full_s,
          "forgery": {"pcs_only_accepts": pcs_only_accepts_forgery, "relaxed_r1cs_accepts": relaxed_accepts_forgery,
                       "binding_rejects": binding_err.is_some(), "binding_error": binding_err},
        });
      }
      report["peak_rss_mib"] = serde_json::json!(peak_rss_mib());
      println!("{}", serde_json::to_string_pretty(&report).unwrap());
    }
    _ => {
      eprintln!("usage: see the header of src/bin/m12.rs");
      std::process::exit(2);
    }
  }
}
