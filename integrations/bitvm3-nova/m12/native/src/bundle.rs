//! Bundle format and the public statement.
//!
//! A bundle is `magic | steps u32 LE | k u32 LE | z0 (17 x 32) | proof`, with
//! magic `NHC1` (mainnet) or `NHT4` (testnet4), as written by
//! `btc-header-fold pack` and `nova-chain export`.
//!
//! The public statement a final wrapper commits is the fixed encoding
//! `magic | k | steps | z0 | zn | sha256(verifier key) | sha256(proof)`
//! (4 + 4 + 4 + 544 + 544 + 32 + 32 = 1,164 bytes). Network and k select the
//! pinned key; the key digest makes the key identity explicit as well.
use nova_header_chain::native::Network;
use serde::{Deserialize, Serialize};

pub const ARITY: usize = 17;
pub const Z_BYTES: usize = ARITY * 32;
pub const MAX_BUNDLE_BYTES: usize = 1 << 20;
pub const MAX_K: u32 = 64;
pub const PUBLIC_BYTES: usize = 4 + 4 + 4 + Z_BYTES + Z_BYTES + 32 + 32;
pub const STATEMENT_ID: &str = "nova_header_chain_statement_v1";

pub fn magic(net: Network) -> [u8; 4] {
  match net {
    Network::Mainnet => *b"NHC1",
    Network::Testnet4 => *b"NHT4",
  }
}

pub fn network_of(magic: &[u8]) -> Option<Network> {
  match magic {
    b"NHC1" => Some(Network::Mainnet),
    b"NHT4" => Some(Network::Testnet4),
    _ => None,
  }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bundle {
  pub net: Network,
  pub steps: u32,
  pub k: u32,
  pub z0: Vec<u8>,
  pub proof: Vec<u8>,
}

impl Bundle {
  pub fn parse(b: &[u8]) -> Result<Bundle, String> {
    if b.len() > MAX_BUNDLE_BYTES || b.len() <= 12 + Z_BYTES {
      return Err("bundle size out of range".into());
    }
    let net = network_of(&b[..4]).ok_or("not an NHC1/NHT4 bundle")?;
    let steps = u32::from_le_bytes(b[4..8].try_into().unwrap());
    let k = u32::from_le_bytes(b[8..12].try_into().unwrap());
    if steps == 0 || k == 0 || k > MAX_K {
      return Err("step count or fold width out of range".into());
    }
    Ok(Bundle { net, steps, k, z0: b[12..12 + Z_BYTES].to_vec(), proof: b[12 + Z_BYTES..].to_vec() })
  }

  pub fn to_bytes(&self) -> Vec<u8> {
    let mut out = magic(self.net).to_vec();
    out.extend_from_slice(&self.steps.to_le_bytes());
    out.extend_from_slice(&self.k.to_le_bytes());
    out.extend_from_slice(&self.z0);
    out.extend_from_slice(&self.proof);
    out
  }
}

/// The fixed public encoding committed by a wrapper.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicStatement {
  pub net: Network,
  pub k: u32,
  pub steps: u32,
  pub z0: Vec<u8>,
  pub zn: Vec<u8>,
  pub vk_sha256: [u8; 32],
  pub proof_sha256: [u8; 32],
}

impl PublicStatement {
  pub fn encode(&self) -> Vec<u8> {
    let mut out = Vec::with_capacity(PUBLIC_BYTES);
    out.extend_from_slice(&magic(self.net));
    out.extend_from_slice(&self.k.to_le_bytes());
    out.extend_from_slice(&self.steps.to_le_bytes());
    out.extend_from_slice(&self.z0);
    out.extend_from_slice(&self.zn);
    out.extend_from_slice(&self.vk_sha256);
    out.extend_from_slice(&self.proof_sha256);
    out
  }

  pub fn decode(b: &[u8]) -> Result<PublicStatement, String> {
    if b.len() != PUBLIC_BYTES {
      return Err(format!("public statement must be {PUBLIC_BYTES} bytes, got {}", b.len()));
    }
    let net = network_of(&b[..4]).ok_or("unknown network magic")?;
    let k = u32::from_le_bytes(b[4..8].try_into().unwrap());
    let steps = u32::from_le_bytes(b[8..12].try_into().unwrap());
    let z0 = b[12..12 + Z_BYTES].to_vec();
    let zn = b[12 + Z_BYTES..12 + 2 * Z_BYTES].to_vec();
    let o = 12 + 2 * Z_BYTES;
    Ok(PublicStatement {
      net,
      k,
      steps,
      z0,
      zn,
      vk_sha256: b[o..o + 32].try_into().unwrap(),
      proof_sha256: b[o + 32..o + 64].try_into().unwrap(),
    })
  }
}

/// Human-readable form of an accepted statement.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Statement {
  pub statement: String,
  pub network: String,
  pub k: u32,
  pub steps: u32,
  pub headers: u64,
  pub vk_sha256: String,
  pub proof_sha256: String,
  pub checkpoint_state_sha256: String,
  pub end_state_sha256: String,
  pub start_height: u32,
  pub end_height: u32,
  pub end_tip_hash: String,
  pub end_chainwork: String,
  pub public_statement_sha256: String,
}
