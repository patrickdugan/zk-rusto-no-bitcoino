//! Control C: the same header-chain statement proved directly, with no Nova.
//! The guest applies the testnet4/mainnet consensus transition of
//! zk-rusto-no-bitcoino de607d3 (`nova_header_chain::native::State::apply_on`,
//! the circuit's native mirror) from the consensus genesis state over the
//! supplied headers and commits magic | n | z0 | zn in the 17-element
//! encoding the Nova statement uses. Used to measure cycles per header.
#![no_main]
sp1_zkvm::entrypoint!(main);

use ff::PrimeField;
use halo2curves::pasta::Fq as F;
use nova_header_chain::native::{Header, Network, State};

pub fn main() {
  let net_byte = sp1_zkvm::io::read_vec();
  let headers = sp1_zkvm::io::read_vec();
  let (net, magic) = match net_byte.as_slice() {
    [0] => (Network::Mainnet, *b"NHC1"),
    [1] => (Network::Testnet4, *b"NHT4"),
    _ => panic!("network byte"),
  };
  assert!(!headers.is_empty() && headers.len() % 80 == 0, "headers");
  let n = (headers.len() / 80) as u32;
  let start = State::genesis(net);
  println!("cycle-tracker-report-start: apply_headers");
  let mut s = start.clone();
  for h in headers.chunks(80) {
    let h: Header = h.try_into().unwrap();
    s = s.apply_on(net, &h).expect("header violates consensus rules");
  }
  println!("cycle-tracker-report-end: apply_headers");
  let z = |st: &State| -> Vec<u8> { st.to_z::<F>().iter().flat_map(|f| f.to_repr().as_ref().to_vec()).collect() };
  let mut out = magic.to_vec();
  out.extend_from_slice(&n.to_le_bytes());
  out.extend_from_slice(&z(&start));
  out.extend_from_slice(&z(&s));
  sp1_zkvm::io::commit_slice(&out);
}
