//! m15-guest elf OUT.elf: writes the M15 guest A ELF (built by build.rs) and prints its SHA-256.
use sha2::{Digest, Sha256};
use sp1_sdk::{include_elf, Elf};

const ELF: Elf = include_elf!("m15-nova-wrapper-program");

fn main() {
    let a: Vec<String> = std::env::args().collect();
    assert!(a.len() == 3 && a[1] == "elf", "usage: m15-guest elf OUT.elf");
    std::fs::write(&a[2], ELF.as_ref()).expect("writing the ELF");
    println!("{}", hex::encode(Sha256::digest(ELF.as_ref())));
}
