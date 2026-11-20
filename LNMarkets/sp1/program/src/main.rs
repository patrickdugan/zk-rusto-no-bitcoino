#![no_main]

use lnm_batch_statement::{verify_batch_bytes, JOURNAL_LEN, MAX_WITNESS_BYTES};

sp1_zkvm::entrypoint!(main);

pub fn main() {
    // The host bounds the frame before write_vec. The relation independently
    // bounds every count before allocation. read_vec allocates its input frame,
    // so this cap protects the relation rather than the zkVM input allocator.
    let witness = sp1_zkvm::io::read_vec();
    assert!(witness.len() <= MAX_WITNESS_BYTES, "witness exceeds cap");
    let journal = verify_batch_bytes(&witness).expect("batch relation rejected");
    assert_eq!(journal.len(), JOURNAL_LEN, "journal schema changed");
    sp1_zkvm::io::commit_slice(&journal);
}
