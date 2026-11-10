//! Native checker for Bitcoin Core's signature and locktime rules (legacy/P2SH and witness v0).
//!
//! Mirrors `src/script/interpreter.cpp`: IsValidSignatureEncoding, IsLowDERSignature,
//! IsDefinedHashtypeSignature, CheckSignatureEncoding, CheckPubKeyEncoding, FindAndDelete,
//! SignatureHash (legacy serializer and BIP143), EvalChecksigPreTapscript, the OP_CHECKMULTISIG
//! body, CheckLockTime and CheckSequence. No taproot.
//!
//! Error strings are Core's ScriptError names. Exception: a CScriptNum failure (overflow or
//! non-minimal encoding) is reported as "SCRIPTNUM"; Core's EvalScript catches the exception and
//! reports SCRIPT_ERR_UNKNOWN_ERROR for it.
#![allow(dead_code)]

use secp256k1::{ecdsa::Signature, Message, PublicKey, Secp256k1, VerifyOnly};
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

pub type SResult<T> = Result<T, &'static str>;

pub mod flags {
    pub const P2SH: u32 = 0x1;
    pub const NULLDUMMY: u32 = 0x2;
    pub const DISCOURAGE_UPGRADABLE_NOPS: u32 = 0x4;
    pub const CHECKLOCKTIMEVERIFY: u32 = 0x8;
    pub const CHECKSEQUENCEVERIFY: u32 = 0x10;
    pub const CLEANSTACK: u32 = 0x20;
    pub const DERSIG: u32 = 0x40;
    pub const LOW_S: u32 = 0x80;
    pub const MINIMALDATA: u32 = 0x100;
    pub const NULLFAIL: u32 = 0x200;
    pub const SIGPUSHONLY: u32 = 0x400;
    pub const STRICTENC: u32 = 0x800;
    pub const WITNESS: u32 = 0x1000;
    pub const DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM: u32 = 0x2000;
    pub const MINIMALIF: u32 = 0x4000;
    pub const WITNESS_PUBKEYTYPE: u32 = 0x8000;
    pub const TAPROOT: u32 = 0x10000;
    pub const DISCOURAGE_UPGRADABLE_TAPROOT_VERSION: u32 = 0x20000;
    pub const DISCOURAGE_OP_SUCCESS: u32 = 0x40000;
    pub const DISCOURAGE_UPGRADABLE_PUBKEYTYPE: u32 = 0x80000;
    pub const CONST_SCRIPTCODE: u32 = 0x100000;
}
use flags as f;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SigVersion {
    Base,
    WitnessV0,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxIn {
    pub prev_txid: [u8; 32],
    pub prev_vout: u32,
    pub script_sig: Vec<u8>,
    pub sequence: u32,
    pub witness: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxOut {
    pub value: i64,
    pub script_pubkey: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tx {
    pub version: i32,
    pub inputs: Vec<TxIn>,
    pub outputs: Vec<TxOut>,
    pub locktime: u32,
}

// ---------------------------------------------------------------------------------------------
// Serialization helpers
// ---------------------------------------------------------------------------------------------

struct Reader<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        if self.b.len() - self.p < n {
            return Err("unexpected end of data".into());
        }
        let s = &self.b[self.p..self.p + n];
        self.p += n;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }
    fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64, String> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    /// ReadCompactSize with range check and canonical-form check, as Core.
    fn compact(&mut self) -> Result<u64, String> {
        let first = self.u8()?;
        let v = match first {
            0..=252 => first as u64,
            253 => {
                let v = u16::from_le_bytes(self.take(2)?.try_into().unwrap()) as u64;
                if v < 253 {
                    return Err("non-canonical ReadCompactSize()".into());
                }
                v
            }
            254 => {
                let v = self.u32()? as u64;
                if v < 0x10000 {
                    return Err("non-canonical ReadCompactSize()".into());
                }
                v
            }
            255 => {
                let v = self.u64()?;
                if v < 0x1_0000_0000 {
                    return Err("non-canonical ReadCompactSize()".into());
                }
                v
            }
        };
        if v > 0x0200_0000 {
            return Err("ReadCompactSize(): size too large".into());
        }
        Ok(v)
    }
    fn bytes(&mut self) -> Result<Vec<u8>, String> {
        let n = self.compact()? as usize;
        Ok(self.take(n)?.to_vec())
    }
}

fn write_compact(out: &mut Vec<u8>, n: u64) {
    if n < 253 {
        out.push(n as u8);
    } else if n <= 0xffff {
        out.push(253);
        out.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= 0xffff_ffff {
        out.push(254);
        out.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        out.push(255);
        out.extend_from_slice(&n.to_le_bytes());
    }
}

fn write_var_bytes(out: &mut Vec<u8>, b: &[u8]) {
    write_compact(out, b.len() as u64);
    out.extend_from_slice(b);
}

/// Parses a transaction (legacy or segwit serialization) as Core's UnserializeTransaction with
/// witnesses allowed; rejects trailing bytes.
pub fn parse_tx(raw: &[u8]) -> Result<Tx, String> {
    let mut r = Reader { b: raw, p: 0 };
    let version = r.u32()? as i32;
    let mut flags_byte = 0u8;
    let mut inputs: Vec<TxIn>;
    let mut outputs: Vec<TxOut> = Vec::new();

    fn read_inputs(r: &mut Reader) -> Result<Vec<TxIn>, String> {
        let n = r.compact()?;
        let mut v = Vec::new();
        for _ in 0..n {
            let mut prev_txid = [0u8; 32];
            prev_txid.copy_from_slice(r.take(32)?);
            let prev_vout = r.u32()?;
            let script_sig = r.bytes()?;
            let sequence = r.u32()?;
            v.push(TxIn { prev_txid, prev_vout, script_sig, sequence, witness: vec![] });
        }
        Ok(v)
    }
    fn read_outputs(r: &mut Reader) -> Result<Vec<TxOut>, String> {
        let n = r.compact()?;
        let mut v = Vec::new();
        for _ in 0..n {
            let value = r.u64()? as i64;
            let script_pubkey = r.bytes()?;
            v.push(TxOut { value, script_pubkey });
        }
        Ok(v)
    }

    inputs = read_inputs(&mut r)?;
    if inputs.is_empty() {
        flags_byte = r.u8()?;
        if flags_byte != 0 {
            inputs = read_inputs(&mut r)?;
            outputs = read_outputs(&mut r)?;
        }
    } else {
        outputs = read_outputs(&mut r)?;
    }
    if flags_byte & 1 != 0 {
        flags_byte ^= 1;
        for inp in inputs.iter_mut() {
            let n = r.compact()?;
            let mut w = Vec::new();
            for _ in 0..n {
                w.push(r.bytes()?);
            }
            inp.witness = w;
        }
        if inputs.iter().all(|i| i.witness.is_empty()) {
            return Err("Superfluous witness record".into());
        }
    }
    if flags_byte != 0 {
        return Err("Unknown transaction optional data".into());
    }
    let locktime = r.u32()?;
    if r.p != raw.len() {
        return Err("trailing bytes after transaction".into());
    }
    Ok(Tx { version, inputs, outputs, locktime })
}

pub fn sha256d(b: &[u8]) -> [u8; 32] {
    let h = Sha256::digest(Sha256::digest(b));
    let mut o = [0u8; 32];
    o.copy_from_slice(&h);
    o
}

// ---------------------------------------------------------------------------------------------
// Script iteration and FindAndDelete
// ---------------------------------------------------------------------------------------------

const OP_PUSHDATA1: u8 = 0x4c;
const OP_PUSHDATA2: u8 = 0x4d;
const OP_PUSHDATA4: u8 = 0x4e;
const OP_CODESEPARATOR: u8 = 0xab;

const SIGHASH_ALL: i32 = 1;
const SIGHASH_NONE: i32 = 2;
const SIGHASH_SINGLE: i32 = 3;
const SIGHASH_ANYONECANPAY: i32 = 0x80;

/// CScript::GetOp. Returns (ok, opcode, new_pc). On failure the new pc is where Core leaves it
/// (after the opcode and any fully-read length bytes, before the data).
fn get_op(s: &[u8], pc: usize) -> (bool, u8, usize) {
    if pc >= s.len() {
        return (false, 0xff, pc);
    }
    let op = s[pc];
    let mut p = pc + 1;
    if op <= OP_PUSHDATA4 {
        let n: usize;
        if op < OP_PUSHDATA1 {
            n = op as usize;
        } else if op == OP_PUSHDATA1 {
            if s.len() - p < 1 {
                return (false, 0xff, p);
            }
            n = s[p] as usize;
            p += 1;
        } else if op == OP_PUSHDATA2 {
            if s.len() - p < 2 {
                return (false, 0xff, p);
            }
            n = u16::from_le_bytes([s[p], s[p + 1]]) as usize;
            p += 2;
        } else {
            if s.len() - p < 4 {
                return (false, 0xff, p);
            }
            n = u32::from_le_bytes([s[p], s[p + 1], s[p + 2], s[p + 3]]) as usize;
            p += 4;
        }
        if s.len() - p < n {
            return (false, 0xff, p);
        }
        p += n;
    }
    (true, op, p)
}

/// `CScript() << vch`: direct push encoding (no minimal-number opcodes).
fn push_encode(data: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(data.len() + 5);
    let n = data.len();
    if n < OP_PUSHDATA1 as usize {
        v.push(n as u8);
    } else if n <= 0xff {
        v.push(OP_PUSHDATA1);
        v.push(n as u8);
    } else if n <= 0xffff {
        v.push(OP_PUSHDATA2);
        v.extend_from_slice(&(n as u16).to_le_bytes());
    } else {
        v.push(OP_PUSHDATA4);
        v.extend_from_slice(&(n as u32).to_le_bytes());
    }
    v.extend_from_slice(data);
    v
}

/// Core's FindAndDelete(script, CScript() << sig). Returns the new script and the number of
/// removed occurrences.
pub fn find_and_delete(script: &[u8], sig: &[u8]) -> (Vec<u8>, usize) {
    let b = push_encode(sig);
    let mut found = 0usize;
    let mut result: Vec<u8> = Vec::new();
    let end = script.len();
    let mut pc = 0usize;
    let mut pc2 = 0usize;
    loop {
        result.extend_from_slice(&script[pc2..pc]);
        while end - pc >= b.len() && script[pc..pc + b.len()] == b[..] {
            pc += b.len();
            found += 1;
        }
        pc2 = pc;
        let (ok, _, np) = get_op(script, pc);
        pc = np;
        if !ok {
            break;
        }
    }
    if found > 0 {
        result.extend_from_slice(&script[pc2..end]);
        (result, found)
    } else {
        (script.to_vec(), 0)
    }
}

// ---------------------------------------------------------------------------------------------
// Sighash
// ---------------------------------------------------------------------------------------------

fn one_hash() -> [u8; 32] {
    let mut o = [0u8; 32];
    o[0] = 1;
    o
}

/// CTransactionSignatureSerializer::SerializeScriptCode (OP_CODESEPARATOR stripped).
fn serialize_script_code(out: &mut Vec<u8>, sc: &[u8]) {
    let mut it = 0usize;
    let mut nsep = 0u64;
    loop {
        let (ok, op, np) = get_op(sc, it);
        it = np;
        if !ok {
            break;
        }
        if op == OP_CODESEPARATOR {
            nsep += 1;
        }
    }
    write_compact(out, sc.len() as u64 - nsep);
    let mut begin = 0usize;
    it = 0;
    loop {
        let (ok, op, np) = get_op(sc, it);
        it = np;
        if !ok {
            break;
        }
        if op == OP_CODESEPARATOR {
            out.extend_from_slice(&sc[begin..it - 1]);
            begin = it;
        }
    }
    if begin != sc.len() {
        out.extend_from_slice(&sc[begin..it]);
    }
}

pub fn legacy_sighash(tx: &Tx, n_in: usize, script_code: &[u8], hash_type: i32) -> [u8; 32] {
    if n_in >= tx.inputs.len() {
        return one_hash();
    }
    let base = hash_type & 0x1f;
    if base == SIGHASH_SINGLE && n_in >= tx.outputs.len() {
        return one_hash();
    }
    let acp = hash_type & SIGHASH_ANYONECANPAY != 0;
    let single = base == SIGHASH_SINGLE;
    let none = base == SIGHASH_NONE;

    let mut s: Vec<u8> = Vec::new();
    s.extend_from_slice(&tx.version.to_le_bytes());
    let n_inputs = if acp { 1 } else { tx.inputs.len() };
    write_compact(&mut s, n_inputs as u64);
    for k in 0..n_inputs {
        let idx = if acp { n_in } else { k };
        let inp = &tx.inputs[idx];
        s.extend_from_slice(&inp.prev_txid);
        s.extend_from_slice(&inp.prev_vout.to_le_bytes());
        if idx != n_in {
            s.push(0);
        } else {
            serialize_script_code(&mut s, script_code);
        }
        let seq = if idx != n_in && (single || none) { 0 } else { inp.sequence };
        s.extend_from_slice(&seq.to_le_bytes());
    }
    let n_outputs = if none {
        0
    } else if single {
        n_in + 1
    } else {
        tx.outputs.len()
    };
    write_compact(&mut s, n_outputs as u64);
    for k in 0..n_outputs {
        if single && k != n_in {
            s.extend_from_slice(&(-1i64).to_le_bytes());
            s.push(0);
        } else {
            s.extend_from_slice(&tx.outputs[k].value.to_le_bytes());
            write_var_bytes(&mut s, &tx.outputs[k].script_pubkey);
        }
    }
    s.extend_from_slice(&tx.locktime.to_le_bytes());
    s.extend_from_slice(&(hash_type as u32).to_le_bytes());
    sha256d(&s)
}

pub fn bip143_sighash(tx: &Tx, n_in: usize, script_code: &[u8], amount: i64, hash_type: i32) -> [u8; 32] {
    if n_in >= tx.inputs.len() {
        return one_hash();
    }
    let base = hash_type & 0x1f;
    let acp = hash_type & SIGHASH_ANYONECANPAY != 0;
    let mut hash_prevouts = [0u8; 32];
    let mut hash_sequence = [0u8; 32];
    let mut hash_outputs = [0u8; 32];
    if !acp {
        let mut b = Vec::new();
        for i in &tx.inputs {
            b.extend_from_slice(&i.prev_txid);
            b.extend_from_slice(&i.prev_vout.to_le_bytes());
        }
        hash_prevouts = sha256d(&b);
    }
    if !acp && base != SIGHASH_SINGLE && base != SIGHASH_NONE {
        let mut b = Vec::new();
        for i in &tx.inputs {
            b.extend_from_slice(&i.sequence.to_le_bytes());
        }
        hash_sequence = sha256d(&b);
    }
    if base != SIGHASH_SINGLE && base != SIGHASH_NONE {
        let mut b = Vec::new();
        for o in &tx.outputs {
            b.extend_from_slice(&o.value.to_le_bytes());
            write_var_bytes(&mut b, &o.script_pubkey);
        }
        hash_outputs = sha256d(&b);
    } else if base == SIGHASH_SINGLE && n_in < tx.outputs.len() {
        let o = &tx.outputs[n_in];
        let mut b = Vec::new();
        b.extend_from_slice(&o.value.to_le_bytes());
        write_var_bytes(&mut b, &o.script_pubkey);
        hash_outputs = sha256d(&b);
    }
    let inp = &tx.inputs[n_in];
    let mut s = Vec::new();
    s.extend_from_slice(&tx.version.to_le_bytes());
    s.extend_from_slice(&hash_prevouts);
    s.extend_from_slice(&hash_sequence);
    s.extend_from_slice(&inp.prev_txid);
    s.extend_from_slice(&inp.prev_vout.to_le_bytes());
    write_var_bytes(&mut s, script_code);
    s.extend_from_slice(&amount.to_le_bytes());
    s.extend_from_slice(&inp.sequence.to_le_bytes());
    s.extend_from_slice(&hash_outputs);
    s.extend_from_slice(&tx.locktime.to_le_bytes());
    s.extend_from_slice(&(hash_type as u32).to_le_bytes());
    sha256d(&s)
}

// ---------------------------------------------------------------------------------------------
// Encoding checks
// ---------------------------------------------------------------------------------------------

/// Core's IsValidSignatureEncoding (BIP66 strict DER, whole sig including hashtype byte).
fn is_valid_signature_encoding(sig: &[u8]) -> bool {
    let n = sig.len();
    if n < 9 || n > 73 {
        return false;
    }
    if sig[0] != 0x30 {
        return false;
    }
    if sig[1] as usize != n - 3 {
        return false;
    }
    let len_r = sig[3] as usize;
    if 5 + len_r >= n {
        return false;
    }
    let len_s = sig[5 + len_r] as usize;
    if len_r + len_s + 7 != n {
        return false;
    }
    if sig[2] != 0x02 {
        return false;
    }
    if len_r == 0 {
        return false;
    }
    if sig[4] & 0x80 != 0 {
        return false;
    }
    if len_r > 1 && sig[4] == 0x00 && sig[5] & 0x80 == 0 {
        return false;
    }
    if sig[len_r + 4] != 0x02 {
        return false;
    }
    if len_s == 0 {
        return false;
    }
    if sig[len_r + 6] & 0x80 != 0 {
        return false;
    }
    if len_s > 1 && sig[len_r + 6] == 0x00 && sig[len_r + 7] & 0x80 == 0 {
        return false;
    }
    true
}

fn verify_ctx() -> &'static Secp256k1<VerifyOnly> {
    static CTX: OnceLock<Secp256k1<VerifyOnly>> = OnceLock::new();
    CTX.get_or_init(Secp256k1::verification_only)
}

/// CPubKey::CheckLowS on the DER signature without the hashtype byte.
fn check_low_s(der: &[u8]) -> bool {
    match Signature::from_der_lax(der) {
        Err(_) => false,
        Ok(sig) => {
            let mut n = sig;
            n.normalize_s();
            n == sig
        }
    }
}

fn is_low_der_signature(sig: &[u8]) -> SResult<()> {
    if !is_valid_signature_encoding(sig) {
        return Err("SIG_DER");
    }
    if !check_low_s(&sig[..sig.len() - 1]) {
        return Err("SIG_HIGH_S");
    }
    Ok(())
}

fn is_defined_hashtype_signature(sig: &[u8]) -> bool {
    if sig.is_empty() {
        return false;
    }
    let ht = (sig[sig.len() - 1] as i32) & !SIGHASH_ANYONECANPAY;
    (SIGHASH_ALL..=SIGHASH_SINGLE).contains(&ht)
}

fn check_signature_encoding(sig: &[u8], fl: u32) -> SResult<()> {
    if sig.is_empty() {
        return Ok(());
    }
    if fl & (f::DERSIG | f::LOW_S | f::STRICTENC) != 0 && !is_valid_signature_encoding(sig) {
        return Err("SIG_DER");
    }
    if fl & f::LOW_S != 0 {
        is_low_der_signature(sig)?;
    }
    if fl & f::STRICTENC != 0 && !is_defined_hashtype_signature(sig) {
        return Err("SIG_HASHTYPE");
    }
    Ok(())
}

fn is_compressed_or_uncompressed_pubkey(pk: &[u8]) -> bool {
    if pk.len() < 33 {
        return false;
    }
    match pk[0] {
        0x04 => pk.len() == 65,
        0x02 | 0x03 => pk.len() == 33,
        _ => false,
    }
}

fn is_compressed_pubkey(pk: &[u8]) -> bool {
    pk.len() == 33 && (pk[0] == 0x02 || pk[0] == 0x03)
}

fn check_pubkey_encoding(pk: &[u8], fl: u32, sv: SigVersion) -> SResult<()> {
    if fl & f::STRICTENC != 0 && !is_compressed_or_uncompressed_pubkey(pk) {
        return Err("PUBKEYTYPE");
    }
    if fl & f::WITNESS_PUBKEYTYPE != 0 && sv == SigVersion::WitnessV0 && !is_compressed_pubkey(pk) {
        return Err("WITNESS_PUBKEYTYPE");
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// ECDSA verification
// ---------------------------------------------------------------------------------------------

/// CPubKey::IsValid (header byte / length), as built from a raw vector.
fn cpubkey_valid(pk: &[u8]) -> bool {
    match pk.first() {
        Some(2) | Some(3) => pk.len() == 33,
        Some(4) | Some(6) | Some(7) => pk.len() == 65,
        _ => false,
    }
}

/// CPubKey::Verify: lax DER parse, normalize S, libsecp verify.
fn verify_signature(der: &[u8], pubkey: &[u8], sighash: &[u8; 32]) -> bool {
    if !cpubkey_valid(pubkey) {
        return false;
    }
    let pk = match PublicKey::from_slice(pubkey) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let mut sig = match Signature::from_der_lax(der) {
        Ok(s) => s,
        Err(_) => return false,
    };
    sig.normalize_s();
    let msg = Message::from_digest(*sighash);
    verify_ctx().verify_ecdsa(&msg, &sig, &pk).is_ok()
}

/// TransactionSignatureChecker::CheckECDSASignature.
fn check_ecdsa_signature(
    sig: &[u8],
    pubkey: &[u8],
    script_code: &[u8],
    sv: SigVersion,
    tx: &Tx,
    n_in: usize,
    amount: i64,
) -> bool {
    if !cpubkey_valid(pubkey) {
        return false;
    }
    if sig.is_empty() {
        return false;
    }
    let hash_type = sig[sig.len() - 1] as i32;
    let der = &sig[..sig.len() - 1];
    let sighash = match sv {
        SigVersion::Base => legacy_sighash(tx, n_in, script_code, hash_type),
        SigVersion::WitnessV0 => bip143_sighash(tx, n_in, script_code, amount, hash_type),
    };
    verify_signature(der, pubkey, &sighash)
}

pub fn checksig(
    sig: &[u8],
    pubkey: &[u8],
    script: &[u8],
    codesep: usize,
    sigversion: SigVersion,
    fl: u32,
    tx: &Tx,
    n_in: usize,
    amount: i64,
) -> SResult<bool> {
    let start = codesep.min(script.len());
    let mut script_code = script[start..].to_vec();
    if sigversion == SigVersion::Base {
        let (sc, found) = find_and_delete(&script_code, sig);
        if found > 0 && fl & f::CONST_SCRIPTCODE != 0 {
            return Err("SIG_FINDANDDELETE");
        }
        script_code = sc;
    }
    check_signature_encoding(sig, fl)?;
    check_pubkey_encoding(pubkey, fl, sigversion)?;
    let ok = check_ecdsa_signature(sig, pubkey, &script_code, sigversion, tx, n_in, amount);
    if !ok && fl & f::NULLFAIL != 0 && !sig.is_empty() {
        return Err("NULLFAIL");
    }
    Ok(ok)
}

pub fn checkmultisig(
    keys: &[Vec<u8>],
    sigs: &[Vec<u8>],
    dummy: &[u8],
    script: &[u8],
    codesep: usize,
    sigversion: SigVersion,
    fl: u32,
    tx: &Tx,
    n_in: usize,
    amount: i64,
) -> SResult<bool> {
    if sigs.len() > keys.len() {
        return Err("SIG_COUNT");
    }
    let start = codesep.min(script.len());
    let mut script_code = script[start..].to_vec();
    for sig in sigs {
        if sigversion == SigVersion::Base {
            let (sc, found) = find_and_delete(&script_code, sig);
            if found > 0 && fl & f::CONST_SCRIPTCODE != 0 {
                return Err("SIG_FINDANDDELETE");
            }
            script_code = sc;
        }
    }
    let mut n_sigs = sigs.len();
    let mut n_keys = keys.len();
    let (mut isig, mut ikey) = (0usize, 0usize);
    let mut success = true;
    while success && n_sigs > 0 {
        let sig = &sigs[isig];
        let pk = &keys[ikey];
        check_signature_encoding(sig, fl)?;
        check_pubkey_encoding(pk, fl, sigversion)?;
        if check_ecdsa_signature(sig, pk, &script_code, sigversion, tx, n_in, amount) {
            isig += 1;
            n_sigs -= 1;
        }
        ikey += 1;
        n_keys -= 1;
        if n_sigs > n_keys {
            success = false;
        }
    }
    if !success && fl & f::NULLFAIL != 0 && sigs.iter().any(|s| !s.is_empty()) {
        return Err("NULLFAIL");
    }
    if fl & f::NULLDUMMY != 0 && !dummy.is_empty() {
        return Err("SIG_NULLDUMMY");
    }
    Ok(success)
}

// ---------------------------------------------------------------------------------------------
// Locktime
// ---------------------------------------------------------------------------------------------

const LOCKTIME_THRESHOLD: i64 = 500_000_000;
const SEQUENCE_FINAL: u32 = 0xffff_ffff;
const SEQUENCE_LOCKTIME_DISABLE_FLAG: i64 = 1 << 31;
const SEQUENCE_LOCKTIME_TYPE_FLAG: i64 = 1 << 22;
const SEQUENCE_LOCKTIME_MASK: i64 = 0x0000_ffff;

/// CScriptNum(vch, fRequireMinimal, nMaxNumSize) decode.
fn script_num(v: &[u8], require_minimal: bool, max_size: usize) -> SResult<i64> {
    if v.len() > max_size {
        return Err("SCRIPTNUM");
    }
    if require_minimal && !v.is_empty() && v[v.len() - 1] & 0x7f == 0 {
        if v.len() <= 1 || v[v.len() - 2] & 0x80 == 0 {
            return Err("SCRIPTNUM");
        }
    }
    if v.is_empty() {
        return Ok(0);
    }
    let mut r: i64 = 0;
    for (i, b) in v.iter().enumerate() {
        r |= (*b as i64) << (8 * i);
    }
    if v[v.len() - 1] & 0x80 != 0 {
        r &= !(0x80i64 << (8 * (v.len() - 1)));
        r = -r;
    }
    Ok(r)
}

fn check_lock_time_value(n: i64, tx: &Tx, n_in: usize) -> bool {
    let tl = tx.locktime as i64;
    if !((tl < LOCKTIME_THRESHOLD && n < LOCKTIME_THRESHOLD) || (tl >= LOCKTIME_THRESHOLD && n >= LOCKTIME_THRESHOLD)) {
        return false;
    }
    if n > tl {
        return false;
    }
    if tx.inputs[n_in].sequence == SEQUENCE_FINAL {
        return false;
    }
    true
}

fn check_sequence_value(n: i64, tx: &Tx, n_in: usize) -> bool {
    let tx_seq = tx.inputs[n_in].sequence as i64;
    if (tx.version as u32) < 2 {
        return false;
    }
    if tx_seq & SEQUENCE_LOCKTIME_DISABLE_FLAG != 0 {
        return false;
    }
    let mask = SEQUENCE_LOCKTIME_TYPE_FLAG | SEQUENCE_LOCKTIME_MASK;
    let tx_m = tx_seq & mask;
    let n_m = n & mask;
    if !((tx_m < SEQUENCE_LOCKTIME_TYPE_FLAG && n_m < SEQUENCE_LOCKTIME_TYPE_FLAG)
        || (tx_m >= SEQUENCE_LOCKTIME_TYPE_FLAG && n_m >= SEQUENCE_LOCKTIME_TYPE_FLAG))
    {
        return false;
    }
    if n_m > tx_m {
        return false;
    }
    true
}

/// OP_CHECKLOCKTIMEVERIFY. If the CLTV flag is unset the opcode is a NOP (error only with
/// DISCOURAGE_UPGRADABLE_NOPS).
pub fn check_locktime(operand: &[u8], fl: u32, tx: &Tx, n_in: usize) -> SResult<()> {
    if fl & f::CHECKLOCKTIMEVERIFY == 0 {
        if fl & f::DISCOURAGE_UPGRADABLE_NOPS != 0 {
            return Err("DISCOURAGE_UPGRADABLE_NOPS");
        }
        return Ok(());
    }
    let n = script_num(operand, fl & f::MINIMALDATA != 0, 5)?;
    if n < 0 {
        return Err("NEGATIVE_LOCKTIME");
    }
    if !check_lock_time_value(n, tx, n_in) {
        return Err("UNSATISFIED_LOCKTIME");
    }
    Ok(())
}

/// OP_CHECKSEQUENCEVERIFY. If the CSV flag is unset the opcode is a NOP.
pub fn check_sequence(operand: &[u8], fl: u32, tx: &Tx, n_in: usize) -> SResult<()> {
    if fl & f::CHECKSEQUENCEVERIFY == 0 {
        if fl & f::DISCOURAGE_UPGRADABLE_NOPS != 0 {
            return Err("DISCOURAGE_UPGRADABLE_NOPS");
        }
        return Ok(());
    }
    let n = script_num(operand, fl & f::MINIMALDATA != 0, 5)?;
    if n < 0 {
        return Err("NEGATIVE_LOCKTIME");
    }
    if n & SEQUENCE_LOCKTIME_DISABLE_FLAG != 0 {
        return Ok(());
    }
    if !check_sequence_value(n, tx, n_in) {
        return Err("UNSATISFIED_LOCKTIME");
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::SecretKey;

    fn h(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    fn mk_tx(version: i32, locktime: u32, seqs: &[u32], nouts: usize) -> Tx {
        Tx {
            version,
            inputs: seqs
                .iter()
                .enumerate()
                .map(|(i, s)| TxIn {
                    prev_txid: [i as u8 + 1; 32],
                    prev_vout: i as u32,
                    script_sig: vec![],
                    sequence: *s,
                    witness: vec![],
                })
                .collect(),
            outputs: (0..nouts)
                .map(|i| TxOut { value: 1000 + i as i64, script_pubkey: vec![0x51] })
                .collect(),
            locktime,
        }
    }

    const BLOCK170: &str = "0100000001c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704000000004847304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901ffffffff0200ca9a3b00000000434104ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84cac00286bee0000000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac00000000";
    const BLOCK170_PREV_SPK: &str = "410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac";

    #[test]
    fn mainnet_block170_p2pk_legacy_sighash_verifies() {
        let raw = h(BLOCK170);
        let tx = parse_tx(&raw).unwrap();
        let mut txid = sha256d(&raw);
        txid.reverse();
        assert_eq!(hex::encode(txid), "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16");
        let spk = h(BLOCK170_PREV_SPK);
        // scriptSig = push(sig) only
        let ss = &tx.inputs[0].script_sig;
        let sig = &ss[1..1 + ss[0] as usize];
        assert_eq!(*sig.last().unwrap(), 1);
        let pubkey = &spk[1..66];
        let fl = f::P2SH | f::DERSIG | f::LOW_S | f::STRICTENC | f::NULLFAIL;
        assert_eq!(checksig(sig, pubkey, &spk, 0, SigVersion::Base, fl, &tx, 0, 0), Ok(true));
        // flipping a bit of the tx fails (and NULLFAIL fires)
        let mut tx2 = tx.clone();
        tx2.outputs[0].value += 1;
        assert_eq!(checksig(sig, pubkey, &spk, 0, SigVersion::Base, 0, &tx2, 0, 0), Ok(false));
        assert_eq!(checksig(sig, pubkey, &spk, 0, SigVersion::Base, f::NULLFAIL, &tx2, 0, 0), Err("NULLFAIL"));
    }

    fn bip143_native_tx() -> Tx {
        parse_tx(&h("0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000")).unwrap()
    }

    #[test]
    fn bip143_native_p2wpkh_sighash_and_sig() {
        let tx = bip143_native_tx();
        let sc = h("76a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac");
        let sh = bip143_sighash(&tx, 1, &sc, 600_000_000, 1);
        assert_eq!(hex::encode(sh), "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670");
        let sig = h("304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee01");
        let pk = h("025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357");
        let fl = f::WITNESS | f::P2SH | f::DERSIG | f::LOW_S | f::STRICTENC | f::NULLFAIL | f::WITNESS_PUBKEYTYPE;
        assert_eq!(checksig(&sig, &pk, &sc, 0, SigVersion::WitnessV0, fl, &tx, 1, 600_000_000), Ok(true));
        // wrong amount fails
        assert_eq!(checksig(&sig, &pk, &sc, 0, SigVersion::WitnessV0, 0, &tx, 1, 600_000_001), Ok(false));
        // uncompressed key in witness v0 with WITNESS_PUBKEYTYPE
        let unc = [vec![4u8], vec![0u8; 64]].concat();
        assert_eq!(
            checksig(&sig, &unc, &sc, 0, SigVersion::WitnessV0, f::WITNESS_PUBKEYTYPE, &tx, 1, 0),
            Err("WITNESS_PUBKEYTYPE")
        );
    }

    #[test]
    fn bip143_p2sh_p2wpkh_sighash() {
        let tx = parse_tx(&h("0100000001db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a54770100000000feffffff02b8b4eb0b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac0008af2f000000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac92040000")).unwrap();
        let sc = h("76a91479091972186c449eb1ded22b78e40d009bdf008988ac");
        let sh = bip143_sighash(&tx, 0, &sc, 1_000_000_000, 1);
        assert_eq!(hex::encode(sh), "64f3b0f4dd2bb3aa1ce8566d220cc74dda9df97d8490cc81d89d735c92e59fb6");
    }

    #[test]
    fn sighash_single_out_of_range_is_one() {
        let tx = mk_tx(1, 0, &[0xffffffff, 0xffffffff], 1);
        let sh = legacy_sighash(&tx, 1, &[0x51], 3);
        let mut one = [0u8; 32];
        one[0] = 1;
        assert_eq!(sh, one);
        assert_eq!(legacy_sighash(&tx, 1, &[0x51], 0x83), one);
        assert_ne!(legacy_sighash(&tx, 0, &[0x51], 3), one);
        // BIP143 SINGLE out of range does not return ONE: hashOutputs is zero
        let b = bip143_sighash(&tx, 1, &[0x51], 5, 3);
        assert_ne!(b, one);
    }

    #[test]
    fn sighash_none_zeroes_other_sequences() {
        let tx = mk_tx(1, 0, &[1, 2], 2);
        let mut tx2 = tx.clone();
        tx2.inputs[1].sequence = 99;
        assert_eq!(legacy_sighash(&tx, 0, &[0x51], 2), legacy_sighash(&tx2, 0, &[0x51], 2));
        assert_ne!(legacy_sighash(&tx, 0, &[0x51], 1), legacy_sighash(&tx2, 0, &[0x51], 1));
        // ANYONECANPAY ignores other inputs entirely
        let mut tx3 = tx.clone();
        tx3.inputs[1].prev_vout = 77;
        assert_eq!(legacy_sighash(&tx, 0, &[0x51], 0x81), legacy_sighash(&tx3, 0, &[0x51], 0x81));
    }

    #[test]
    fn codeseparator_stripped_in_legacy_script_code() {
        let tx = mk_tx(1, 0, &[0], 1);
        let a = legacy_sighash(&tx, 0, &[0x51, 0xab, 0x52, 0xab], 1);
        let b = legacy_sighash(&tx, 0, &[0x51, 0x52], 1);
        assert_eq!(a, b);
        // a 0xab inside a push is data, not a separator
        let c = legacy_sighash(&tx, 0, &[0x01, 0xab], 1);
        assert_ne!(c, legacy_sighash(&tx, 0, &[0x01], 1));
    }

    #[test]
    fn find_and_delete_cases() {
        // sig = 02 03 02? use sig=[0x03,0x02]: push encoding b=[2,3,2]
        let sig = [0x03u8, 0x02];
        let b = [0x02u8, 0x03, 0x02];
        let mut s = b.to_vec();
        s.push(0x51);
        assert_eq!(find_and_delete(&s, &sig), (vec![0x51], 1));
        let mut s = vec![0x51];
        s.extend_from_slice(&b);
        s.extend_from_slice(&b);
        assert_eq!(find_and_delete(&s, &sig), (vec![0x51], 2));
        // match not on an opcode boundary: inside a 3-byte push [3, 2,3,2]
        let s = vec![0x03, 0x02, 0x03, 0x02];
        assert_eq!(find_and_delete(&s, &sig), (s.clone(), 0));
        // deletion can splice: 51 [b] 51
        let s = vec![0x51, 0x02, 0x03, 0x02, 0x51];
        assert_eq!(find_and_delete(&s, &sig), (vec![0x51, 0x51], 1));
        // Core's "OP_1 ... CScript() << sig" overlapping: b b b adjacent all removed
        let s = [b, b, b].concat();
        assert_eq!(find_and_delete(&s, &sig), (vec![], 3));
        // empty sig: b = [0x00]; removes OP_0 occurrences
        assert_eq!(find_and_delete(&[0x00, 0x51, 0x00], &[]), (vec![0x51], 2));
        // an OP_0 byte inside a push is not removed
        assert_eq!(find_and_delete(&[0x01, 0x00, 0x51], &[]), (vec![0x01, 0x00, 0x51], 0));
        // truncated push at the end: remainder kept, earlier match still removed
        let s = vec![0x02, 0x03, 0x02, 0x4c, 0x05, 0x01];
        assert_eq!(find_and_delete(&s, &sig), (vec![0x4c, 0x05, 0x01], 1));
        // PUSHDATA1 encoding for 76-byte sig
        let big = vec![0xaa; 76];
        let mut s = vec![0x4c, 76];
        s.extend_from_slice(&big);
        s.push(0x51);
        assert_eq!(find_and_delete(&s, &big), (vec![0x51], 1));
        // a direct 76-byte push is not matched by a minimal-push of different encoding
        assert_eq!(find_and_delete(&[0x4d, 76, 0, 0xaa], &[0xaa]).1, 0);
    }

    fn der(r: &[u8], s: &[u8], ht: u8) -> Vec<u8> {
        let mut v = vec![0x30, (r.len() + s.len() + 4) as u8, 0x02, r.len() as u8];
        v.extend_from_slice(r);
        v.push(0x02);
        v.push(s.len() as u8);
        v.extend_from_slice(s);
        v.push(ht);
        v
    }

    #[test]
    fn der_edge_cases() {
        let r = [0x11u8; 32];
        let s = [0x22u8; 32];
        assert!(is_valid_signature_encoding(&der(&r, &s, 1)));
        // too short / too long
        assert!(!is_valid_signature_encoding(&[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]));
        assert!(is_valid_signature_encoding(&[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x01]));
        let big = [0x11u8; 34];
        assert!(!is_valid_signature_encoding(&der(&big, &big, 1)));
        // wrong tag
        let mut d = der(&r, &s, 1);
        d[0] = 0x31;
        assert!(!is_valid_signature_encoding(&d));
        // wrong total length byte
        let mut d = der(&r, &s, 1);
        d[1] += 1;
        assert!(!is_valid_signature_encoding(&d));
        // negative R
        let mut rn = r;
        rn[0] = 0x81;
        assert!(!is_valid_signature_encoding(&der(&rn, &s, 1)));
        // R excess padding
        let rp = [vec![0x00, 0x11], vec![0x11; 30]].concat();
        assert!(!is_valid_signature_encoding(&der(&rp, &s, 1)));
        // R padding needed (high bit set after 00) is valid
        let rp2 = [vec![0x00, 0x81], vec![0x11; 30]].concat();
        assert!(is_valid_signature_encoding(&der(&rp2, &s, 1)));
        // negative S, S excess padding
        let mut sn = s;
        sn[0] = 0x80;
        assert!(!is_valid_signature_encoding(&der(&r, &sn, 1)));
        let sp = [vec![0x00, 0x22], vec![0x22; 30]].concat();
        assert!(!is_valid_signature_encoding(&der(&r, &sp, 1)));
        // zero-length R / S
        assert!(!is_valid_signature_encoding(&der(&[], &s, 1)));
        assert!(!is_valid_signature_encoding(&der(&r, &[], 1)));
        // R's integer tag wrong
        let mut d = der(&r, &s, 1);
        d[2] = 0x03;
        assert!(!is_valid_signature_encoding(&d));
        // S's integer tag wrong
        let mut d = der(&r, &s, 1);
        d[4 + 32] = 0x03;
        assert!(!is_valid_signature_encoding(&d));
        // trailing garbage between sig and hashtype changes lengths -> invalid
        let mut d = der(&r, &s, 1);
        d.insert(d.len() - 1, 0);
        assert!(!is_valid_signature_encoding(&d));
    }

    #[test]
    fn encoding_error_order_and_empty_sig() {
        let tx = mk_tx(1, 0, &[0], 1);
        let pk = [vec![2u8], vec![0x11; 32]].concat();
        // empty sig: encoding OK; checksig false; NULLFAIL does not fire for empty sig
        let all = f::DERSIG | f::LOW_S | f::STRICTENC | f::NULLFAIL;
        assert_eq!(checksig(&[], &pk, &[0x51], 0, SigVersion::Base, all, &tx, 0, 0), Ok(false));
        // not DER
        assert_eq!(checksig(&[1, 2, 3], &pk, &[0x51], 0, SigVersion::Base, f::DERSIG, &tx, 0, 0), Err("SIG_DER"));
        // bad hashtype (STRICTENC only)
        let sig = der(&[0x11; 32], &[0x22; 32], 0);
        assert_eq!(checksig(&sig, &pk, &[0x51], 0, SigVersion::Base, f::STRICTENC, &tx, 0, 0), Err("SIG_HASHTYPE"));
        let sig = der(&[0x11; 32], &[0x22; 32], 0x84);
        assert_eq!(checksig(&sig, &pk, &[0x51], 0, SigVersion::Base, f::STRICTENC, &tx, 0, 0), Err("SIG_HASHTYPE"));
        let sig = der(&[0x11; 32], &[0x22; 32], 0x81);
        assert!(checksig(&sig, &pk, &[0x51], 0, SigVersion::Base, f::STRICTENC, &tx, 0, 0).is_ok());
        // sig errors precede pubkey errors
        let bad_pk = [vec![5u8], vec![0x11; 32]].concat();
        let badsig = der(&[0x11; 32], &[0x22; 32], 0);
        assert_eq!(
            checksig(&badsig, &bad_pk, &[0x51], 0, SigVersion::Base, f::STRICTENC, &tx, 0, 0),
            Err("SIG_HASHTYPE")
        );
        let okig = der(&[0x11; 32], &[0x22; 32], 1);
        assert_eq!(checksig(&okig, &bad_pk, &[0x51], 0, SigVersion::Base, f::STRICTENC, &tx, 0, 0), Err("PUBKEYTYPE"));
        // hybrid key allowed by STRICTENC? no: 06/07 are rejected by STRICTENC
        let hyb = [vec![6u8], vec![0x11; 64]].concat();
        assert_eq!(checksig(&okig, &hyb, &[0x51], 0, SigVersion::Base, f::STRICTENC, &tx, 0, 0), Err("PUBKEYTYPE"));
        // without flags, an invalid pubkey just fails (no error)
        assert_eq!(checksig(&okig, &bad_pk, &[0x51], 0, SigVersion::Base, 0, &tx, 0, 0), Ok(false));
        // with NULLFAIL a non-empty failing sig errors
        assert_eq!(checksig(&okig, &bad_pk, &[0x51], 0, SigVersion::Base, f::NULLFAIL, &tx, 0, 0), Err("NULLFAIL"));
    }

    const N: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xba, 0xae, 0xdc,
        0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
    ];

    fn n_minus(s: &[u8; 32]) -> [u8; 32] {
        let mut out = [0u8; 32];
        let mut borrow = 0i32;
        for i in (0..32).rev() {
            let mut d = N[i] as i32 - s[i] as i32 - borrow;
            if d < 0 {
                d += 256;
                borrow = 1;
            } else {
                borrow = 0;
            }
            out[i] = d as u8;
        }
        out
    }

    fn keypair(b: u8) -> (SecretKey, Vec<u8>) {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[b; 32]).unwrap();
        let pk = PublicKey::from_secret_key(&secp, &sk);
        (sk, pk.serialize().to_vec())
    }

    fn sign_with(sk: &SecretKey, sighash: [u8; 32], ht: u8, high_s: bool) -> Vec<u8> {
        let secp = Secp256k1::new();
        let mut sig = secp.sign_ecdsa(&Message::from_digest(sighash), sk);
        sig.normalize_s();
        if high_s {
            let c = sig.serialize_compact();
            let mut s = [0u8; 32];
            s.copy_from_slice(&c[32..]);
            let hs = n_minus(&s);
            let mut c2 = c;
            c2[32..].copy_from_slice(&hs);
            sig = Signature::from_compact(&c2).unwrap();
        }
        let mut v = sig.serialize_der().to_vec();
        v.push(ht);
        v
    }

    #[test]
    fn low_s_enforced_and_lax_verify_accepts_high_s() {
        let tx = mk_tx(1, 0, &[0], 1);
        let (sk, pk) = keypair(7);
        let script = [vec![0x21], pk.clone(), vec![0xac]].concat();
        let sh = legacy_sighash(&tx, 0, &script, 1);
        let low = sign_with(&sk, sh, 1, false);
        let high = sign_with(&sk, sh, 1, true);
        assert_eq!(checksig(&low, &pk, &script, 0, SigVersion::Base, f::LOW_S, &tx, 0, 0), Ok(true));
        assert_eq!(checksig(&high, &pk, &script, 0, SigVersion::Base, f::LOW_S, &tx, 0, 0), Err("SIG_HIGH_S"));
        // without LOW_S, high-S verifies (Core normalizes)
        assert_eq!(checksig(&high, &pk, &script, 0, SigVersion::Base, 0, &tx, 0, 0), Ok(true));
        // DER-invalid with LOW_S reports SIG_DER
        assert_eq!(checksig(&[1, 2, 3], &pk, &script, 0, SigVersion::Base, f::LOW_S, &tx, 0, 0), Err("SIG_DER"));
    }

    #[test]
    fn checksig_find_and_delete_and_codesep() {
        let tx = mk_tx(1, 0, &[0], 1);
        let (sk, pk) = keypair(9);
        // script: <pk> CHECKSIG ; the signature is computed over the script without itself
        let base_script = [vec![0x21], pk.clone(), vec![0xac]].concat();
        let sh = legacy_sighash(&tx, 0, &base_script, 1);
        let sig = sign_with(&sk, sh, 1, false);
        // executing script embeds the sig as a push in front; FindAndDelete removes it
        let exec = [push_encode(&sig), base_script.clone()].concat();
        assert_eq!(checksig(&sig, &pk, &exec, 0, SigVersion::Base, 0, &tx, 0, 0), Ok(true));
        assert_eq!(
            checksig(&sig, &pk, &exec, 0, SigVersion::Base, f::CONST_SCRIPTCODE, &tx, 0, 0),
            Err("SIG_FINDANDDELETE")
        );
        // witness v0 keeps it, so the same sig no longer matches
        assert_eq!(checksig(&sig, &pk, &exec, 0, SigVersion::WitnessV0, 0, &tx, 0, 0), Ok(false));
        // codesep offset: scriptCode starts after the separator
        let exec2 = [vec![0x51, 0xab], base_script.clone()].concat();
        assert_eq!(checksig(&sig, &pk, &exec2, 2, SigVersion::Base, 0, &tx, 0, 0), Ok(true));
        assert_eq!(checksig(&sig, &pk, &exec2, 0, SigVersion::Base, 0, &tx, 0, 0), Ok(false)); // 0x51 remains in scriptCode
    }

    #[test]
    fn multisig_loop_nullfail_nulldummy() {
        let tx = mk_tx(1, 0, &[0], 1);
        let (sk1, pk1) = keypair(1);
        let (sk2, pk2) = keypair(2);
        let (_sk3, pk3) = keypair(3);
        let mut script = vec![0x52];
        for pk in [&pk1, &pk2, &pk3] {
            script.push(0x21);
            script.extend_from_slice(pk);
        }
        script.extend_from_slice(&[0x53, 0xae]);
        let sh = legacy_sighash(&tx, 0, &script, 1);
        let sig1 = sign_with(&sk1, sh, 1, false);
        let sig2 = sign_with(&sk2, sh, 1, false);
        let keys = vec![pk3.clone(), pk2.clone(), pk1.clone()];
        let good = vec![sig2.clone(), sig1.clone()];
        let run = |sigs: &[Vec<u8>], dummy: &[u8], fl: u32| {
            checkmultisig(&keys, sigs, dummy, &script, 0, SigVersion::Base, fl, &tx, 0, 0)
        };
        assert_eq!(run(&good, &[], 0), Ok(true));
        assert_eq!(run(&good, &[], f::NULLDUMMY | f::NULLFAIL | f::STRICTENC | f::DERSIG), Ok(true));
        // out-of-order sigs fail
        let bad = vec![sig1.clone(), sig2.clone()];
        assert_eq!(run(&bad, &[], 0), Ok(false));
        assert_eq!(run(&bad, &[], f::NULLFAIL), Err("NULLFAIL"));
        // NULLFAIL fires for any non-empty sig even if one is empty
        let mixed = vec![vec![], sig1.clone()];
        assert_eq!(run(&mixed, &[], 0), Ok(false));
        assert_eq!(run(&mixed, &[], f::NULLFAIL), Err("NULLFAIL"));
        let allempty = vec![vec![], vec![]];
        assert_eq!(run(&allempty, &[], f::NULLFAIL), Ok(false));
        // dummy
        assert_eq!(run(&good, &[1], f::NULLDUMMY), Err("SIG_NULLDUMMY"));
        assert_eq!(run(&good, &[1], 0), Ok(true));
        // NULLFAIL before NULLDUMMY
        assert_eq!(run(&bad, &[1], f::NULLDUMMY | f::NULLFAIL), Err("NULLFAIL"));
        // encoding checked only for pairs compared: second sig garbage but first fails early
        // (sig count 2, keys 3: first pair mismatch -> key 2 -> n_sigs(2) > n_keys(1)? after pair 2: yes)
        let garbage = vec![sig2.clone(), vec![1, 2, 3]];
        assert_eq!(run(&garbage, &[], f::DERSIG), Err("SIG_DER"));
        let g2 = vec![vec![1, 2, 3], sig1.clone()];
        // pair1 (garbage, pk3) hits SIG_DER immediately
        assert_eq!(run(&g2, &[], f::DERSIG), Err("SIG_DER"));
        // after the first sig fails against too many keys, the second sig is never encoding-checked
        let early = vec![sig1.clone(), vec![1, 2, 3]];
        // sig1 vs pk3 fail (nSigs2,nKeys2), vs pk2 fail (2 > 1 -> stop)
        assert_eq!(run(&early, &[], f::DERSIG), Ok(false));
        // zero sigs: success with no checks
        assert_eq!(run(&[], &[], f::NULLDUMMY), Ok(true));
        // FindAndDelete over all sigs
        let exec = [push_encode(&sig1), script.clone()].concat();
        assert_eq!(
            checkmultisig(&keys, &good, &[], &exec, 0, SigVersion::Base, f::CONST_SCRIPTCODE, &tx, 0, 0),
            Err("SIG_FINDANDDELETE")
        );
        assert_eq!(checkmultisig(&keys, &good, &[], &exec, 0, SigVersion::Base, 0, &tx, 0, 0), Ok(true));
    }

    #[test]
    fn cltv_cases() {
        let fl = f::CHECKLOCKTIMEVERIFY;
        let tx = mk_tx(1, 500, &[0], 1);
        assert_eq!(check_locktime(&[0xf4, 0x01], fl, &tx, 0), Ok(())); // 500
        assert_eq!(check_locktime(&[0xf5, 0x01], fl, &tx, 0), Err("UNSATISFIED_LOCKTIME"));
        assert_eq!(check_locktime(&[], fl, &tx, 0), Ok(()));
        assert_eq!(check_locktime(&[0x81], fl, &tx, 0), Err("NEGATIVE_LOCKTIME"));
        // type mismatch: time-based operand vs height-based tx
        assert_eq!(check_locktime(&[0x00, 0x65, 0xcd, 0x1d], fl, &tx, 0), Err("UNSATISFIED_LOCKTIME"));
        // final sequence
        let txf = mk_tx(1, 500, &[0xffffffff], 1);
        assert_eq!(check_locktime(&[0x01], fl, &txf, 0), Err("UNSATISFIED_LOCKTIME"));
        // time-based match
        let txt = mk_tx(1, 600_000_000, &[0], 1);
        assert_eq!(check_locktime(&[0x00, 0x65, 0xcd, 0x1d], fl, &txt, 0), Ok(())); // 500000000
        // 5-byte numbers allowed, 6-byte rejected
        assert_eq!(check_locktime(&[0, 0, 0, 0, 1], fl, &tx, 0), Err("UNSATISFIED_LOCKTIME"));
        assert_eq!(check_locktime(&[1, 0, 0, 0, 0, 0], fl, &tx, 0), Err("SCRIPTNUM"));
        // minimal encoding only with MINIMALDATA
        assert_eq!(check_locktime(&[0x01, 0x00], fl, &tx, 0), Ok(()));
        assert_eq!(check_locktime(&[0x01, 0x00], fl | f::MINIMALDATA, &tx, 0), Err("SCRIPTNUM"));
        assert_eq!(check_locktime(&[0x00], fl | f::MINIMALDATA, &tx, 0), Err("SCRIPTNUM"));
        assert_eq!(check_locktime(&[0xff, 0x00], fl | f::MINIMALDATA, &tx, 0), Ok(()));
        // flag unset: NOP
        assert_eq!(check_locktime(&[0x81], 0, &tx, 0), Ok(()));
        assert_eq!(check_locktime(&[0x81], f::DISCOURAGE_UPGRADABLE_NOPS, &tx, 0), Err("DISCOURAGE_UPGRADABLE_NOPS"));
    }

    #[test]
    fn csv_cases() {
        let fl = f::CHECKSEQUENCEVERIFY;
        let tx = mk_tx(2, 0, &[10], 1);
        assert_eq!(check_sequence(&[10], fl, &tx, 0), Ok(()));
        assert_eq!(check_sequence(&[11], fl, &tx, 0), Err("UNSATISFIED_LOCKTIME"));
        assert_eq!(check_sequence(&[0x81], fl, &tx, 0), Err("NEGATIVE_LOCKTIME"));
        // version < 2
        let tx1 = mk_tx(1, 0, &[10], 1);
        assert_eq!(check_sequence(&[10], fl, &tx1, 0), Err("UNSATISFIED_LOCKTIME"));
        // version with the top bit set compares as uint32 >= 2
        let txneg = mk_tx(-1, 0, &[10], 1);
        assert_eq!(check_sequence(&[10], fl, &txneg, 0), Ok(()));
        // operand disable flag short-circuits to success
        assert_eq!(check_sequence(&[0, 0, 0, 0x80, 0x00], fl, &tx1, 0), Ok(()));
        // tx disable flag
        let txd = mk_tx(2, 0, &[0x8000000a], 1);
        assert_eq!(check_sequence(&[10], fl, &txd, 0), Err("UNSATISFIED_LOCKTIME"));
        // type mismatch: operand time-based (bit 22), tx height-based
        assert_eq!(check_sequence(&[10, 0, 0x40], fl, &tx, 0), Err("UNSATISFIED_LOCKTIME"));
        let txt = mk_tx(2, 0, &[0x0040000a], 1);
        assert_eq!(check_sequence(&[10, 0, 0x40], fl, &txt, 0), Ok(()));
        assert_eq!(check_sequence(&[11, 0, 0x40], fl, &txt, 0), Err("UNSATISFIED_LOCKTIME"));
        // bits above the mask are ignored
        let txh = mk_tx(2, 0, &[0x0001000a], 1);
        assert_eq!(check_sequence(&[10], fl, &txh, 0), Ok(()));
        assert_eq!(check_sequence(&[10, 0, 0, 0x01], fl, &txh, 0), Ok(())); // 0x01000000 masked to 0
        // flag unset: NOP
        assert_eq!(check_sequence(&[0x81], 0, &tx, 0), Ok(()));
    }

    #[test]
    fn parse_tx_rejects_trailing_and_parses_segwit() {
        let mut raw = h(BLOCK170);
        raw.push(0);
        assert!(parse_tx(&raw).is_err());
        let build = |wit: &[u8]| {
            let mut v = vec![2, 0, 0, 0, 0, 1, 1];
            v.extend_from_slice(&[0xaa; 32]);
            v.extend_from_slice(&[0, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff]);
            v.push(1);
            v.extend_from_slice(&1i64.to_le_bytes());
            v.extend_from_slice(&[1, 0x51]);
            v.extend_from_slice(wit);
            v.extend_from_slice(&[0, 0, 0, 0]);
            v
        };
        let tx = parse_tx(&build(&[1, 1, 0xaa])).unwrap();
        assert_eq!(tx.inputs[0].witness, vec![vec![0xaa]]);
        assert_eq!(tx.outputs[0].script_pubkey, vec![0x51]);
        // superfluous witness record (flag set, all witnesses empty)
        assert!(parse_tx(&build(&[0])).is_err());
    }
}
