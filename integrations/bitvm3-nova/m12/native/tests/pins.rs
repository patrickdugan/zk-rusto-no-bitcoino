//! Pin table: the mainnet k=1 key is accepted for mainnet k=1 and refused
//! for any other (network, k).
use nova_bitvm3_m12::pins;
use nova_header_chain::native::Network;

const MAINNET_K1: &str = "6aa50d09397c51d0b89d78b3a918d3fe0962251225c8b6ca91e83199a4e6da1d";
const TESTNET4_K1: &str = "6894f4903a9ff9713111bb1076b61663ac3592ad3d51b697d58125403fc5c12a";

#[test]
fn mainnet_k1_key_is_pinned_and_accepted() {
  assert_eq!(pins::pinned(Network::Mainnet, 1), Some(MAINNET_K1));
  assert_eq!(pins::owner(MAINNET_K1), Some((Network::Mainnet, 1)));
  assert!(pins::check(Network::Mainnet, 1, MAINNET_K1).is_ok());
}

#[test]
fn mainnet_k1_key_is_refused_elsewhere() {
  assert!(pins::check(Network::Testnet4, 1, MAINNET_K1).is_err());
  for k in [2, 5, 10, 20] {
    assert!(pins::check(Network::Mainnet, k, MAINNET_K1).is_err(), "k={k}");
    assert!(pins::check(Network::Testnet4, k, MAINNET_K1).is_err(), "k={k}");
  }
}

#[test]
fn other_keys_are_refused_for_mainnet_k1() {
  assert!(pins::check(Network::Mainnet, 1, TESTNET4_K1).is_err());
  assert!(pins::check(Network::Mainnet, 1, &"0".repeat(64)).is_err());
  assert!(pins::check(Network::Testnet4, 1, TESTNET4_K1).is_ok());
}
