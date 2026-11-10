//! Compiles one input's verification (Core's VerifyScript, legacy/P2SH/witness v0) into a linear
//! program for the step machine.
//!
//! Everything Core decides from the scripts and flags alone is decided here, and a spend that
//! fails one of those checks never gets a program: oversized scripts and pushes, disabled
//! opcodes, OP_VERIF/OP_VERNOTIF, unparsable scripts, OP_CODESEPARATOR under CONST_SCRIPTCODE,
//! SIGPUSHONLY, the witness program shapes and the P2SH-witness malleability rules. What depends
//! on stack contents is left to the machine.

use crate::elem::{enc, hash, script_num, F};
use crate::isa::iop;
use crate::sigcheck::{flags::*, SigVersion, Tx};
use sha2::{Digest, Sha256};

fn sha256(b: &[u8]) -> Vec<u8> {
  Sha256::digest(b).to_vec()
}
use ff::Field;

pub const MAX_SCRIPT_SIZE: usize = 10_000;
pub const MAX_ELEMENT: usize = 520;

#[derive(Clone, Debug)]
pub struct Instr {
  pub iop: u64,
  pub data: F,
  pub aux: u64,
  /// The pushed bytes (PUSH, LIT, POPEQ), for the native engine.
  pub bytes: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct Program {
  pub instrs: Vec<Instr>,
  /// Script id -> (bytes, signature version). 0 scriptSig, 1 scriptPubKey, 2 redeem script,
  /// 3 witness script (P2WSH) or the implied P2WPKH script.
  pub scripts: Vec<(Vec<u8>, SigVersion)>,
}

impl Program {
  /// Commitments of every suffix: commits()[i] commits to instrs[i..]; commits()[len] = 0.
  pub fn commits(&self) -> Vec<F> {
    let mut c = vec![F::ZERO; self.instrs.len() + 1];
    for i in (0..self.instrs.len()).rev() {
      let n = &self.instrs[i];
      c[i] = hash(&[F::from(n.iop), n.data, F::from(n.aux), c[i + 1]]);
    }
    c
  }
}

/// aux layout: bit 0 fail-if-executed (non-minimal push), bit 1 require minimal numbers, rest
/// (aux >> 2) the CODESEPARATOR offset or the BEGIN script id.
pub fn aux(fail: bool, req_min: bool, rest: u64) -> u64 {
  fail as u64 | (req_min as u64) << 1 | rest << 2
}

#[derive(Clone, Debug)]
pub struct Op {
  pub opcode: u8,
  pub data: Option<Vec<u8>>,
  /// Byte offset just after this opcode and its data.
  pub end: usize,
}

/// Core's GetScriptOp over the whole script; Err at the first malformed push.
pub fn parse(script: &[u8]) -> Result<Vec<Op>, ()> {
  let mut ops = vec![];
  let mut i = 0;
  while i < script.len() {
    let op = script[i];
    i += 1;
    let data = if op <= 0x4e {
      let n = match op {
        0x4c => {
          let n = *script.get(i).ok_or(())? as usize;
          i += 1;
          n
        }
        0x4d => {
          let b = script.get(i..i + 2).ok_or(())?;
          i += 2;
          u16::from_le_bytes([b[0], b[1]]) as usize
        }
        0x4e => {
          let b = script.get(i..i + 4).ok_or(())?;
          i += 4;
          u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize
        }
        n => n as usize,
      };
      let d = script.get(i..i.checked_add(n).ok_or(())?).ok_or(())?.to_vec();
      i += n;
      Some(d)
    } else {
      None
    };
    ops.push(Op { opcode: op, data, end: i });
  }
  Ok(ops)
}

pub fn is_push_only(script: &[u8]) -> bool {
  match parse(script) {
    Ok(ops) => ops.iter().all(|o| o.opcode <= 0x60),
    Err(_) => false,
  }
}

pub fn check_minimal_push(data: &[u8], opcode: u8) -> bool {
  if data.is_empty() {
    return opcode == 0x00;
  }
  if data.len() == 1 && (1..=16).contains(&data[0]) {
    return false;
  }
  if data.len() == 1 && data[0] == 0x81 {
    return false;
  }
  if data.len() <= 75 {
    return opcode as usize == data.len();
  }
  if data.len() <= 255 {
    return opcode == 0x4c;
  }
  if data.len() <= 65535 {
    return opcode == 0x4d;
  }
  true
}

pub fn is_p2sh(spk: &[u8]) -> bool {
  spk.len() == 23 && spk[0] == 0xa9 && spk[1] == 0x14 && spk[22] == 0x87
}

pub fn witness_program(spk: &[u8]) -> Option<(u8, Vec<u8>)> {
  if spk.len() < 4 || spk.len() > 42 {
    return None;
  }
  if spk[0] != 0x00 && !(0x51..=0x60).contains(&spk[0]) {
    return None;
  }
  if spk[1] as usize + 2 == spk.len() {
    let v = if spk[0] == 0 { 0 } else { spk[0] - 0x50 };
    return Some((v, spk[2..].to_vec()));
  }
  None
}

fn push_script(data: &[u8]) -> Vec<u8> {
  // CScript() << data
  let mut s = vec![];
  match data.len() {
    0 => s.push(0x00),
    1 if (1..=16).contains(&data[0]) => s.push(0x50 + data[0]),
    1 if data[0] == 0x81 => s.push(0x4f),
    n if n <= 75 => {
      s.push(n as u8);
      s.extend_from_slice(data);
    }
    n if n <= 255 => {
      s.push(0x4c);
      s.push(n as u8);
      s.extend_from_slice(data);
    }
    n if n <= 65535 => {
      s.push(0x4d);
      s.extend_from_slice(&(n as u16).to_le_bytes());
      s.extend_from_slice(data);
    }
    n => {
      s.push(0x4e);
      s.extend_from_slice(&(n as u32).to_le_bytes());
      s.extend_from_slice(data);
    }
  }
  s
}

struct Builder {
  flags: u32,
  p: Program,
}

impl Builder {
  fn emit(&mut self, iop: u64, bytes: Vec<u8>, aux: u64) {
    let data = if bytes.is_empty() && iop != iop::PUSH && iop != iop::LIT && iop != iop::POPEQ {
      F::ZERO
    } else {
      enc(&bytes)
    };
    self.p.instrs.push(Instr { iop, data, aux, bytes });
  }

  /// EvalScript: BEGIN, the mapped opcodes, END.
  fn script(&mut self, sid: u64, script: &[u8], sv: SigVersion) -> Result<(), &'static str> {
    while self.p.scripts.len() <= sid as usize {
      self.p.scripts.push((vec![], SigVersion::Base));
    }
    self.p.scripts[sid as usize] = (script.to_vec(), sv);
    if script.len() > MAX_SCRIPT_SIZE {
      return Err("SCRIPT_SIZE");
    }
    let ops = parse(script).map_err(|_| "BAD_OPCODE")?;
    let f = self.flags;
    let min = f & MINIMALDATA != 0;
    self.emit(iop::BEGIN, vec![], aux(false, false, sid));
    for o in &ops {
      let op = o.opcode;
      if let Some(d) = &o.data {
        if d.len() > MAX_ELEMENT {
          return Err("PUSH_SIZE");
        }
      }
      if matches!(op, 0x7e..=0x81 | 0x83..=0x86 | 0x8d | 0x8e | 0x95..=0x99) {
        return Err("DISABLED_OPCODE");
      }
      if op == 0xab && sv == SigVersion::Base && f & CONST_SCRIPTCODE != 0 {
        return Err("OP_CODESEPARATOR");
      }
      let discourage = f & DISCOURAGE_UPGRADABLE_NOPS != 0;
      let (i, bytes, a) = match op {
        0x00..=0x4e => {
          let d = o.data.clone().unwrap();
          let bad = min && !check_minimal_push(&d, op);
          (iop::PUSH, d, aux(bad, false, 0))
        }
        0x4f => (iop::PUSH, script_num(-1), 0),
        0x51..=0x60 => (iop::PUSH, script_num((op - 0x50) as i64), 0),
        0x50 => (iop::FAIL_N, vec![], 0),
        0x61 => (iop::NOP, vec![], 0),
        0x62 | 0x6a | 0x89 | 0x8a | 0xba..=0xff => (iop::FAIL_C, vec![], 0),
        0x63 | 0x64 => {
          let minif = sv == SigVersion::WitnessV0 && f & MINIMALIF != 0;
          let i = match (op, minif) {
            (0x63, false) => iop::IF,
            (0x64, false) => iop::NOTIF,
            (0x63, true) => iop::IF_MIN,
            _ => iop::NOTIF_MIN,
          };
          (i, vec![], 0)
        }
        0x65 | 0x66 => return Err("BAD_OPCODE"),
        0x67 => (iop::ELSE, vec![], 0),
        0x68 => (iop::ENDIF, vec![], 0),
        0x69 => (iop::VERIFY, vec![], 0),
        0x6b..=0x7d | 0x82 | 0x87 | 0x88 | 0x8b..=0x8c | 0x8f..=0x94 | 0x9a..=0xaa | 0xac | 0xad => {
          let i = match op {
            0x6b => iop::TOALT,
            0x6c => iop::FROMALT,
            0x6d => iop::DROP2,
            0x6e => iop::DUP2,
            0x6f => iop::DUP3,
            0x70 => iop::OVER2,
            0x71 => iop::ROT2,
            0x72 => iop::SWAP2,
            0x73 => iop::IFDUP,
            0x74 => iop::DEPTH,
            0x75 => iop::DROP,
            0x76 => iop::DUP,
            0x77 => iop::NIP,
            0x78 => iop::OVER,
            0x79 => iop::PICK,
            0x7a => iop::ROLL,
            0x7b => iop::ROT,
            0x7c => iop::SWAP,
            0x7d => iop::TUCK,
            0x82 => iop::SIZE,
            0x87 => iop::EQUAL,
            0x88 => iop::EQUALVERIFY,
            0x8b => iop::ADD1,
            0x8c => iop::SUB1,
            0x8f => iop::NEGATE,
            0x90 => iop::ABS,
            0x91 => iop::NOT,
            0x92 => iop::NOTEQ0,
            0x93 => iop::ADD,
            0x94 => iop::SUB,
            0x9a => iop::BOOLAND,
            0x9b => iop::BOOLOR,
            0x9c => iop::NUMEQ,
            0x9d => iop::NUMEQV,
            0x9e => iop::NUMNE,
            0x9f => iop::LT,
            0xa0 => iop::GT,
            0xa1 => iop::LE,
            0xa2 => iop::GE,
            0xa3 => iop::MIN,
            0xa4 => iop::MAX,
            0xa5 => iop::WITHIN,
            0xa6 => iop::RIPEMD160,
            0xa7 => iop::SHA1,
            0xa8 => iop::SHA256,
            0xa9 => iop::HASH160,
            0xaa => iop::HASH256,
            0xac => iop::CHECKSIG,
            _ => iop::CHECKSIGV,
          };
          (i, vec![], aux(false, min, 0))
        }
        0xab => (iop::CODESEP, vec![], aux(false, false, o.end as u64)),
        0xae => (iop::CMS, vec![], aux(false, min, 0)),
        0xaf => (iop::CMSV, vec![], aux(false, min, 0)),
        0xb1 if f & CHECKLOCKTIMEVERIFY != 0 => (iop::CLTV, vec![], 0),
        0xb2 if f & CHECKSEQUENCEVERIFY != 0 => (iop::CSV, vec![], 0),
        0xb0..=0xb9 => (if discourage { iop::FAIL_C } else { iop::NOP }, vec![], 0),
        _ => unreachable!(),
      };
      self.emit(i, bytes, a);
    }
    self.emit(iop::END, vec![], 0);
    Ok(())
  }

  /// VerifyWitnessProgram (v0, and unknown versions); the caller emits SETD1 after it.
  fn witness(&mut self, version: u8, program: &[u8], witness: &[Vec<u8>], p2sh: bool) -> Result<(), &'static str> {
    let f = self.flags;
    if version == 0 {
      let (script, stack): (Vec<u8>, &[Vec<u8>]) = if program.len() == 32 {
        if witness.is_empty() {
          return Err("WITNESS_PROGRAM_WITNESS_EMPTY");
        }
        let s = witness.last().unwrap().clone();
        if sha256(&s) != program {
          return Err("WITNESS_PROGRAM_MISMATCH");
        }
        (s, &witness[..witness.len() - 1])
      } else if program.len() == 20 {
        if witness.len() != 2 {
          return Err("WITNESS_PROGRAM_MISMATCH");
        }
        let mut s = vec![0x76, 0xa9, 0x14];
        s.extend_from_slice(program);
        s.extend_from_slice(&[0x88, 0xac]);
        (s, witness)
      } else {
        return Err("WITNESS_PROGRAM_WRONG_LENGTH");
      };
      for e in stack {
        if e.len() > MAX_ELEMENT {
          return Err("PUSH_SIZE");
        }
      }
      self.emit(iop::RESET, vec![], 0);
      for e in stack {
        self.emit(iop::LIT, e.clone(), 0);
      }
      self.script(3, &script, SigVersion::WitnessV0)?;
      self.emit(iop::CLEAN1, vec![], 0);
      self.emit(iop::CHECKTRUE, vec![], 0);
      Ok(())
    } else if version == 1 && program.len() == 32 && !p2sh && f & TAPROOT != 0 {
      Err("UNSUPPORTED_TAPROOT")
    } else if f & DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM != 0 {
      Err("DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM")
    } else {
      Ok(())
    }
  }
}

/// VerifyScript for input n_in of tx spending (amount, spk) under flags.
pub fn compile(tx: &Tx, n_in: usize, spk: &[u8], flags: u32) -> Result<Program, &'static str> {
  let sig = tx.inputs[n_in].script_sig.clone();
  let wit = tx.inputs[n_in].witness.clone();
  let mut b = Builder { flags, p: Program { instrs: vec![], scripts: vec![] } };
  if flags & SIGPUSHONLY != 0 && !is_push_only(&sig) {
    return Err("SIG_PUSHONLY");
  }
  b.script(0, &sig, SigVersion::Base)?;
  if flags & P2SH != 0 {
    b.emit(iop::SAVE, vec![], 0);
  }
  b.script(1, spk, SigVersion::Base)?;
  b.emit(iop::CHECKTRUE, vec![], 0);
  let mut had_witness = false;
  if flags & WITNESS != 0 {
    if let Some((v, prog)) = witness_program(spk) {
      had_witness = true;
      if !sig.is_empty() {
        return Err("WITNESS_MALLEATED");
      }
      b.witness(v, &prog, &wit, false)?;
      b.emit(iop::SETD1, vec![], 0);
    }
  }
  if flags & P2SH != 0 && is_p2sh(spk) {
    if !is_push_only(&sig) {
      return Err("SIG_PUSHONLY");
    }
    // The scriptSig is push-only, so its final stack is its pushes; the redeem script is the
    // last. With no pushes the scriptPubKey's HASH160 fails first.
    let ops = parse(&sig).unwrap();
    let redeem: Vec<u8> = match ops.last() {
      Some(o) => match &o.data {
        Some(d) => d.clone(),
        None if o.opcode == 0x4f => script_num(-1),
        None if (0x51..=0x60).contains(&o.opcode) => script_num((o.opcode - 0x50) as i64),
        None => vec![],
      },
      None => vec![],
    };
    b.emit(iop::RESTORE, vec![], 0);
    b.emit(iop::POPEQ, redeem.clone(), 0);
    b.script(2, &redeem, SigVersion::Base)?;
    b.emit(iop::CHECKTRUE, vec![], 0);
    if flags & WITNESS != 0 {
      if let Some((v, prog)) = witness_program(&redeem) {
        had_witness = true;
        if sig != push_script(&redeem) {
          return Err("WITNESS_MALLEATED_P2SH");
        }
        b.witness(v, &prog, &wit, true)?;
        b.emit(iop::SETD1, vec![], 0);
      }
    }
  }
  if flags & CLEANSTACK != 0 {
    b.emit(iop::CLEAN1, vec![], 0);
  }
  if flags & WITNESS != 0 && !had_witness && !wit.is_empty() {
    return Err("WITNESS_UNEXPECTED");
  }
  Ok(b.p)
}
