//! Architecture B on a real folded witness: a fresh k=1 testnet4
//! RecursiveSNARK (genesis to height 2) is decoded field for field, its
//! relaxed R1CS and Pedersen commitments are re-checked independently of
//! Nova's code, and the commitment-binding attack is shown to pass a hash-PCS
//! verifier and to fail the binding check.
use nova_bitvm3_m12::{
  decider_b,
  mirror::{self, CompressedVk, RecursiveMirror},
  nova_io::{self, F1},
};
use nova_header_chain::native::Network;
use std::sync::OnceLock;

const HEADERS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../fixtures/testnet4-headers-0-80.bin");

struct Fixture {
  vk: CompressedVk,
  rs: RecursiveMirror,
}

fn fixture() -> &'static Fixture {
  static F: OnceLock<Fixture> = OnceLock::new();
  F.get_or_init(|| {
    let hs = nova_io::load_headers_bin(&std::fs::read(HEADERS).unwrap(), Network::Testnet4).unwrap();
    let p = nova_io::prove_from_genesis(Network::Testnet4, 1, 2, &hs).unwrap();
    let rs: RecursiveMirror = mirror::decode_exact(&p.rs_bytes).expect("RecursiveSNARK mirror consumes every byte");
    assert_eq!(rs.i, 2);
    assert_eq!(rs.z0, p.z0);
    assert_eq!(rs.zi, p.zn);
    let vk: CompressedVk = mirror::decode_exact(&p.vk).expect("verifier key mirror consumes every byte");
    Fixture { vk, rs }
  })
}

#[test]
fn honest_folded_witness_satisfies_and_binds() {
  let f = fixture();
  let (s1, ck1) = (&f.vk.vk_primary.S, &f.vk.vk_primary.vk_ee.ck_v);
  let (u, w) = (&f.rs.r_U_primary, &f.rs.r_W_primary);
  decider_b::relaxed_sat(s1, &w.W, &w.E, u.u, &u.X).unwrap();
  assert!(decider_b::pedersen(ck1, &w.W, &w.r_W) == u.comm_W);
  assert!(decider_b::pedersen(ck1, &w.E, &w.r_E) == u.comm_E);
  // Secondary running instance and the fresh secondary instance (u = 1, E = 0).
  let (s2, ck2) = (&f.vk.vk_secondary.S, &f.vk.vk_secondary.vk_ee.ck_v);
  let (u2, w2) = (&f.rs.r_U_secondary, &f.rs.r_W_secondary);
  decider_b::relaxed_sat(s2, &w2.W, &w2.E, u2.u, &u2.X).unwrap();
  assert!(decider_b::pedersen(ck2, &w2.W, &w2.r_W) == u2.comm_W);
  assert!(decider_b::pedersen(ck2, &w2.E, &w2.r_E) == u2.comm_E);
  let (l2, lw2) = (&f.rs.l_u_secondary, &f.rs.l_w_secondary);
  let one = <nova_io::F2 as ff::Field>::ONE;
  decider_b::relaxed_sat(s2, &lw2.W, &[], one, &l2.X).unwrap();
  assert!(decider_b::pedersen(ck2, &lw2.W, &lw2.r_W) == l2.comm_W);
}

#[test]
fn hash_pcs_decider_accepts_honest_witness_with_binding() {
  let f = fixture();
  let (s, ck) = (&f.vk.vk_primary.S, &f.vk.vk_primary.vk_ee.ck_v);
  let (u, w) = (&f.rs.r_U_primary, &f.rs.r_W_primary);
  let (nw, ne) = (decider_b::num_vars_for(s.num_vars), decider_b::num_vars_for(s.num_cons));
  let (p, _, _) = decider_b::prove(u, &w.W, &w.E, nw, ne);
  decider_b::verify_pcs_only(u, &p).unwrap();
  decider_b::verify_with_binding(u, &p, s, ck, &w.W, &w.E, w.r_W, w.r_E).unwrap();
}

/// The M12 adversarial test: a valid hash-PCS opening of W' paired with
/// Nova's commitment to W must be rejected.
#[test]
fn opening_of_other_witness_with_original_commitment_is_rejected() {
  let f = fixture();
  let (s, ck) = (&f.vk.vk_primary.S, &f.vk.vk_primary.vk_ee.ck_v);
  let (u, w) = (&f.rs.r_U_primary, &f.rs.r_W_primary);
  let (nw, ne) = (decider_b::num_vars_for(s.num_vars), decider_b::num_vars_for(s.num_cons));
  let one = <F1 as ff::Field>::ONE;
  for idx in [0usize, w.W.len() / 2, w.W.len() - 1] {
    let mut w2 = w.W.clone();
    w2[idx] += one;
    // Any W' satisfies the relaxed relation with this E'.
    let e2 = decider_b::forge_error(s, &w2, u.u, &u.X).unwrap();
    decider_b::relaxed_sat(s, &w2, &e2, u.u, &u.X).expect("forged pair satisfies relaxed R1CS");
    let (p, _, _) = decider_b::prove(u, &w2, &e2, nw, ne);
    decider_b::verify_pcs_only(u, &p).expect("the hash-PCS openings of W', E' are valid");
    let e = decider_b::verify_with_binding(u, &p, s, ck, &w2, &e2, w.r_W, w.r_E).unwrap_err();
    assert!(e.contains("Pedersen binding fails"), "{e}");
  }
  // W' alone (honest E) fails the relation itself.
  let mut w2 = w.W.clone();
  w2[1] += one;
  let (p, _, _) = decider_b::prove(u, &w2, &w.E, nw, ne);
  assert!(decider_b::verify_with_binding(u, &p, s, ck, &w2, &w.E, w.r_W, w.r_E).is_err());
  // Honest vectors with a wrong blinding factor fail the binding.
  let (p, _, _) = decider_b::prove(u, &w.W, &w.E, nw, ne);
  assert!(decider_b::verify_with_binding(u, &p, s, ck, &w.W, &w.E, w.r_W + one, w.r_E).is_err());
  // A proof whose root commits W' cannot be passed off as committing W.
  let mut w3 = w.W.clone();
  w3[2] += one;
  let e3 = decider_b::forge_error(s, &w3, u.u, &u.X).unwrap();
  let (p3, _, _) = decider_b::prove(u, &w3, &e3, nw, ne);
  let e = decider_b::verify_with_binding(u, &p3, s, ck, &w.W, &w.E, w.r_W, w.r_E).unwrap_err();
  assert!(e.contains("not the vector under root_W"), "{e}");
}

#[test]
fn combined_binding_check_matches_two_msms() {
  let f = fixture();
  let ck = &f.vk.vk_primary.vk_ee.ck_v;
  let (u, w) = (&f.rs.r_U_primary, &f.rs.r_W_primary);
  for g in [3u64, 1 << 40] {
    let gamma = F1::from(g);
    assert!(decider_b::binds_combined(ck, &u.comm_W, &u.comm_E, &w.W, &w.E, w.r_W, w.r_E, gamma));
    let mut e2 = w.E.clone();
    e2[0] += <F1 as ff::Field>::ONE;
    assert!(!decider_b::binds_combined(ck, &u.comm_W, &u.comm_E, &w.W, &e2, w.r_W, w.r_E, gamma));
  }
}
