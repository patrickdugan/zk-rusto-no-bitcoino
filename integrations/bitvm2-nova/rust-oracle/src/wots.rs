//! One mul-bit disproof leaf authenticated by upstream BitVM WOTS4.
//!
//! The verifier must obtain both expected identities from its own authenticated
//! program and key commitment, not from an assertion's declared identifiers.
//! This does not implement the assertion transaction or one-time key lifecycle.
use bitcoin::{
    hashes::{sha256, Hash},
    script::Builder,
    ScriptBuf,
};
use bitvm::signatures::{utils::digits_to_number, CompactWots, Wots, Wots4};
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, error::Error};

pub type Result<T> = std::result::Result<T, Box<dyn Error>>;
pub type PublicKey = <Wots4 as Wots>::PublicKey;
const WORDS: usize = 28;
const BASE: u32 = 1 << 29;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Template {
    pub program_sha256: String,
    pub context: String,
    pub field_role: String,
    pub operation_id: String,
    pub ordinal: u32,
    pub wires: Vec<String>,
    pub bounds: Vec<u32>,
    pub body_hex: String,
    pub compiler: String,
}

pub fn id32(value: &str) -> Result<[u8; 32]> {
    if value.len() != 64 {
        return Err("expected 32-byte identity".into());
    }
    hex::decode(value)?
        .try_into()
        .map_err(|_| "identity length".into())
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 192
        && value
            .bytes()
            .all(|x| x.is_ascii_alphanumeric() || b"_.:/-".contains(&x))
}

fn text(data: &mut Vec<u8>, value: &str) {
    data.extend_from_slice(&(value.len() as u16).to_le_bytes());
    data.extend_from_slice(value.as_bytes());
}

fn digest(data: &[u8]) -> [u8; 32] {
    sha256::Hash::hash(data).to_byte_array()
}
fn number(code: &mut Vec<u8>, n: i64) {
    code.extend_from_slice(Builder::new().push_int(n).into_script().as_bytes());
}

impl Template {
    pub fn identity(&self) -> Result<[u8; 32]> {
        if !matches!(
            self.field_role.as_str(),
            "pallas_base" | "pallas_scalar" | "vesta_base" | "vesta_scalar"
        ) || !identifier(&self.operation_id)
            || self.compiler != "compact-v1"
            || self.ordinal >= 10_000
            || self.wires.len() != WORDS
            || self.bounds.len() != WORDS
            || self.wires.iter().any(|w| !identifier(w))
            || self.wires.iter().collect::<HashSet<_>>().len() != WORDS
        {
            return Err("unsupported WOTS multiplication template".into());
        }
        for (i, bound) in self.bounds.iter().enumerate() {
            if *bound != if i == 18 { 2 } else { BASE } {
                return Err("unexpected wire bounds".into());
            }
        }
        if self.body_hex.len() > 40_000 {
            return Err("predicate body too large".into());
        }
        let body = hex::decode(&self.body_hex)?;
        if body.is_empty() {
            return Err("empty predicate body".into());
        }
        let mut data = b"BITVM2-NOVA/WOTS-TEMPLATE/v1\0".to_vec();
        data.extend_from_slice(&id32(&self.program_sha256)?);
        data.extend_from_slice(&id32(&self.context)?);
        for value in [&self.field_role, &self.operation_id, &self.compiler] {
            text(&mut data, value);
        }
        data.extend_from_slice(&self.ordinal.to_le_bytes());
        for (wire, bound) in self.wires.iter().zip(&self.bounds) {
            text(&mut data, wire);
            data.extend_from_slice(&bound.to_le_bytes());
        }
        data.extend_from_slice(&digest(&body));
        Ok(digest(&data))
    }

    pub fn key_identity(&self, keys: &[PublicKey]) -> Result<[u8; 32]> {
        let id = self.identity()?;
        if keys.len() != WORDS {
            return Err("expected one WOTS key per wire".into());
        }
        let mut data = b"BITVM2-NOVA/WOTS-KEYS/v1\0".to_vec();
        data.extend_from_slice(&id);
        let mut unique = HashSet::new();
        for (wire, key) in self.wires.iter().zip(keys) {
            text(&mut data, wire);
            let mut bytes = Vec::new();
            for digit in key {
                bytes.extend_from_slice(digit);
            }
            if !unique.insert(bytes.clone()) {
                return Err("one-time key reused across wires".into());
            }
            data.extend_from_slice(&bytes);
        }
        Ok(digest(&data))
    }
}

pub struct AuthenticatedLeaf {
    template: Template,
    keys: Vec<PublicKey>,
    template_id: [u8; 32],
    key_id: [u8; 32],
}

impl AuthenticatedLeaf {
    pub fn new(
        template: Template,
        keys: Vec<PublicKey>,
        expected_template: [u8; 32],
        expected_keys: [u8; 32],
    ) -> Result<Self> {
        let template_id = template.identity()?;
        let key_id = template.key_identity(&keys)?;
        if template_id != expected_template || key_id != expected_keys {
            return Err("verifier-owned program or key identity mismatch".into());
        }
        Ok(Self {
            template,
            keys,
            template_id,
            key_id,
        })
    }

    pub fn witness_items(&self) -> usize {
        WORDS * Wots4::TOTAL_DIGIT_LEN as usize
    }

    pub fn script(&self, disprove: bool) -> Result<ScriptBuf> {
        let mut code = vec![0x74]; // OP_DEPTH, before upstream signature stack access.
        number(&mut code, self.witness_items() as i64);
        code.push(0x88); // OP_EQUALVERIFY
        let mut tag = b"BITVM2-NOVA/WOTS-LEAF/v1\0".to_vec();
        tag.extend_from_slice(&self.template_id);
        tag.extend_from_slice(&self.key_id);
        tag.push(u8::from(disprove));
        code.push(32);
        code.extend_from_slice(&digest(&tag));
        code.push(0x75); // OP_DROP
                         // Signatures are supplied in wire order; the final wire is stack top.
                         // Previously recovered pairs stay below upstream's temporary altstack.
        for i in (0..WORDS).rev() {
            code.extend_from_slice(
                Wots4::compact_checksig_verify(&self.keys[i])
                    .compile()
                    .as_bytes(),
            );
            // The eight authenticated digits are MSB first, LSB on stack top.
            // Check the high nibble before reassembly to avoid >4-byte ScriptNums.
            number(&mut code, 7);
            code.push(0x79); // OP_PICK
            number(&mut code, 2);
            code.extend_from_slice(&[0x9f, 0x63]); // LESSTHAN IF
            code.extend_from_slice(digits_to_number::<8, 4>().compile().as_bytes());
            code.push(0x76); // DUP
            number(&mut code, self.template.bounds[i] as i64);
            code.push(0x9f); // LESSTHAN: word, validity
            code.push(0x67); // ELSE: authenticated >29-bit words are disputable.
            code.extend_from_slice(&[0x6d; 4]); // discard eight nibbles.
            number(&mut code, 0);
            number(&mut code, 0); // placeholder word, false validity.
            code.extend_from_slice(&[0x68, 0x6b, 0x6b]); // ENDIF; save validity, then word.
        }
        // Verify ALL signatures before allowing any malformed-value disproof.
        number(&mut code, 1);
        for _ in 0..WORDS {
            code.extend_from_slice(&[0x6c, 0x6c, 0x7b, 0x9a]); // FROMALT, FROMALT, ROT, BOOLAND
        }
        code.push(0x63); // IF all recovered words are bounded.
        code.extend_from_slice(&hex::decode(&self.template.body_hex)?);
        code.push(0x67);
        code.extend_from_slice(&[0x6d; WORDS / 2]);
        number(&mut code, 0);
        code.push(0x68);
        if disprove {
            code.push(0x91);
        }
        if code.len() > 100_000 {
            return Err("authenticated leaf exceeds research bound".into());
        }
        Ok(ScriptBuf::from_bytes(code))
    }
}
