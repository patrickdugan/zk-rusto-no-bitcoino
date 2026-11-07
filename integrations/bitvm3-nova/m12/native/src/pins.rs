//! Pinned verifier-key digests. A statement is accepted only under the key
//! pinned for its (network, k), and a key pinned to another (network, k) is
//! refused even if it verifies (the NHC1/NHT4 relabel hole fixed upstream in
//! d93940e).
use nova_header_chain::native::{self, Network};

/// Keys pinned here in addition to `nova_header_chain::native::PINNED_VERIFIER_KEYS`.
/// Each is the SHA-256 of the bincode 1.x key written by
/// `btc-header-fold vk-export K OUT --network NET` at de607d3; see
/// `../fixtures/README.md` for how each digest was reproduced.
pub const M12_PINNED_KEYS: [(Network, usize, &str); 2] = [
  (Network::Testnet4, 1, "6894f4903a9ff9713111bb1076b61663ac3592ad3d51b697d58125403fc5c12a"),
  (Network::Testnet4, 20, "9e94b9083b5be30e796e974218804214b7106284c071eeec9b15945735321727"),
];

pub fn all_pins() -> Vec<(Network, usize, &'static str)> {
  native::PINNED_VERIFIER_KEYS.iter().copied().chain(M12_PINNED_KEYS.iter().copied()).collect()
}

pub fn pinned(net: Network, k: usize) -> Option<&'static str> {
  all_pins().into_iter().find(|(n, kk, _)| *n == net && *kk == k).map(|p| p.2)
}

pub fn owner(vk_sha256: &str) -> Option<(Network, usize)> {
  all_pins().into_iter().find(|p| p.2 == vk_sha256).map(|p| (p.0, p.1))
}

/// Accept `vk_sha256` for (net, k) only if it is that pair's pinned key.
pub fn check(net: Network, k: usize, vk_sha256: &str) -> Result<(), String> {
  if let Some((n, kk)) = owner(vk_sha256) {
    if n != net || kk != k {
      return Err(format!("verifier key is pinned to {} k={kk}, not {} k={k}", n.name(), net.name()));
    }
  }
  match pinned(net, k) {
    Some(p) if p == vk_sha256 => Ok(()),
    Some(_) => Err(format!("verifier key differs from the pinned {} k={k} key", net.name())),
    None => Err(format!("no pinned verifier key for {} k={k}", net.name())),
  }
}
