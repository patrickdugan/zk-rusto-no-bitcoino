//! Canonical hint packets for the unchanged full32-bit upstream Wots4 scheme.
//! Packet conversion never signs, hashes a chain, truncates a word, or verifies
//! a signature. The registry must check exact total leaf depth before any PICK,
//! run preflight on a top20-item packet before upstream Listpick's OP_MIN, and
//! authenticate every word before a semantic invalidity flag can be inverted.
use bitcoin::script::Builder;
use bitvm::signatures::{CompactWots, Wots, Wots4};
use bitvm2_nova_script_oracle::wots::Result;

pub type FullSignature = <Wots4 as Wots>::Signature;
pub const PACKET_ITEMS: usize = 20;
pub const COMPACT_PACKET_ITEMS: usize = 10;
pub const HINT_DEPTHS: [i64; 10] = [0, 2, 4, 6, 8, 10, 12, 14, 16, 18];

/// Raw canonical witness grammar, independent of interpreter minimality flags.
pub fn canonical_hint(raw: &[u8]) -> bool {
    matches!(raw, [] | [1..=15])
}

fn copied_hint_guard() -> Vec<u8> {
    vec![
        0x76, 0x00, 0x87, 0x63, // DUP empty EQUAL IF: exactly empty is canonical zero.
        0x67, // ELSE: the nonempty copy remains on the stack.
        0x82, 0x51, 0x88, // SIZE 1 EQUALVERIFY, before numeric decoding.
        0x76, 0x00, 0x7c, 0x9f, 0x69, // DUP 0 SWAP LESSTHAN VERIFY: 0 < digit.
        0x76, 0x60, 0x9f, 0x69, // DUP 16 LESSTHAN VERIFY: digit < 16.
        0x68, // ENDIF: leave the unchanged validated copy.
    ]
}

/// Preserve the complete top20-item packet, checking all8 message and2 checksum
/// hint positions. No OP_MIN or alternative verifier is embedded in this guard.
/// Caller precondition: exact whole-leaf DEPTH guard has already succeeded.
pub fn preflight() -> Vec<u8> {
    let guard = copied_hint_guard();
    let mut code = Vec::new();
    for depth in HINT_DEPTHS {
        code.extend_from_slice(Builder::new().push_int(depth).into_script().as_bytes());
        code.push(0x79); // PICK one numeric hint; retain every packet item.
        code.extend_from_slice(&guard);
        code.push(0x75); // DROP only the validated copy.
    }
    code
}

fn check_full(signature: &FullSignature) -> Result<()> {
    let digits: &[[u8; 21]] = signature.as_ref();
    if Wots4::MSG_BYTE_LEN != 4
        || Wots4::TOTAL_DIGIT_LEN != 10
        || digits.len() != 10
        || digits.iter().any(|digit| digit[20] > 15)
    {
        return Err("full32 Wots4 must have8 message and2 canonical checksum hints".into());
    }
    Ok(())
}

/// Bottom-to-top: hash0,hint0,...,hash9,hint9. Derive from the ONE upstream
/// Wots4::sign result retained for a word, never by a second signing operation.
pub fn hinted_packet(signature: &FullSignature) -> Result<Vec<Vec<u8>>> {
    check_full(signature)?;
    let packet = Wots4::signature_to_raw_witness(signature).to_vec();
    let digits: &[[u8; 21]] = signature.as_ref();
    if packet.len() != PACKET_ITEMS
        || packet.chunks_exact(2).enumerate().any(|(i, pair)| {
            pair[0].as_slice() != &digits[i][..20]
                || !canonical_hint(&pair[1])
                || (digits[i][20] == 0 && !pair[1].is_empty())
                || (digits[i][20] != 0 && pair[1].as_slice() != [digits[i][20]])
        })
    {
        return Err("upstream full Wots4 witness layout/canonical hint changed".into());
    }
    Ok(packet)
}

/// The matching compact packet contains the same10 hash-chain elements, without
/// hints. Both views come from the same signature and full32-bit message.
pub fn compact_packet(signature: &FullSignature) -> Result<Vec<Vec<u8>>> {
    check_full(signature)?;
    let compact = Wots4::signature_to_compact_signature(signature);
    let packet = Wots4::compact_signature_to_raw_witness(&compact).to_vec();
    let digits: &[[u8; 21]] = signature.as_ref();
    if packet.len() != COMPACT_PACKET_ITEMS
        || packet
            .iter()
            .enumerate()
            .any(|(i, hash)| hash.as_slice() != &digits[i][..20])
    {
        return Err("upstream compact Wots4 packet differs from the same full signature".into());
    }
    Ok(packet)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{script::Instruction, ScriptBuf};

    // Pure model of the guard's exact byte equality, SIZE and signed one-byte
    // numeric comparisons. This is not Script execution or cryptographic proof.
    fn grammar_from_guard(raw: &[u8]) -> bool {
        if raw.is_empty() {
            return true;
        }
        if raw.len() != 1 {
            return false;
        }
        let magnitude = i16::from(raw[0] & 127);
        let signed = if raw[0] & 128 != 0 {
            -magnitude
        } else {
            magnitude
        };
        0 < signed && signed < 16
    }

    #[test]
    fn canonical_byte_grammar_is_independent_of_minimal_numeric_decoding() {
        assert!(canonical_hint(&[]));
        for byte in 0u8..=255 {
            assert_eq!(canonical_hint(&[byte]), (1..=15).contains(&byte));
            assert_eq!(canonical_hint(&[byte]), grammar_from_guard(&[byte]));
        }
        for malformed in [
            vec![0],
            vec![0x80],
            vec![0x81],
            vec![16],
            vec![1, 0],
            vec![0, 0],
            vec![0; 5],
            vec![0; 521],
        ] {
            assert!(!canonical_hint(&malformed));
            assert!(!grammar_from_guard(&malformed));
        }
    }

    #[test]
    fn preflight_checks_all_ten_positions_and_uses_only_legacy_opcodes() {
        assert_eq!(HINT_DEPTHS, [0, 2, 4, 6, 8, 10, 12, 14, 16, 18]);
        let script = ScriptBuf::from_bytes(preflight());
        crate::engine::validate(&script).unwrap(); // Parse only, no execution.
        let ops: Vec<_> = script
            .instructions_minimal()
            .map(|instruction| match instruction.unwrap() {
                Instruction::Op(op) => Some(op.to_u8()),
                _ => None,
            })
            .flatten()
            .collect();
        for op in [0x79, 0x75, 0x63, 0x67, 0x68, 0x82] {
            assert_eq!(ops.iter().filter(|value| **value == op).count(), 10);
        }
        assert!(!ops.contains(&0xa3));
        assert_eq!(preflight().len(), 211);
    }

    #[test]
    fn packets_are_views_of_one_full_signature_without_signing() {
        // Synthetic public arrays test formatting only: these are not valid
        // signatures and this test makes no cryptographic acceptance claim.
        let mut signature: FullSignature = [[0u8; 21]; 10];
        for (i, digit) in signature.iter_mut().enumerate() {
            digit[..20].fill(i as u8);
            digit[20] = (i % 16) as u8;
        }
        let hinted = hinted_packet(&signature).unwrap();
        let compact = compact_packet(&signature).unwrap();
        assert_eq!(hinted.len(), 20);
        assert_eq!(compact.len(), 10);
        assert!(hinted[1].is_empty());
        for i in 0..10 {
            assert_eq!(hinted[2 * i], compact[i]);
            assert!(canonical_hint(&hinted[2 * i + 1]));
        }
        signature[9][20] = 16;
        assert!(hinted_packet(&signature).is_err());
        assert!(compact_packet(&signature).is_err());
    }
}
