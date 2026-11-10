//! The native step machine: runs a compiled program with Bitcoin Core's semantics on real bytes,
//! and for each step records the circuit's witness and the next state vector.
//!
//! Semantics follow Core's EvalScript (and Shinigami's port of it, which passes Core's
//! script_tests.json); the control table only decides how many elements each step pops and
//! where the circuit finds its outputs.

use crate::compile::Program;
use crate::elem::{enc, fu, hash, is_long, F};
use crate::isa::{ctrl, iop, kind, phase, Src, MAX_OPS, MAX_STACK, NO_FALSE};
use crate::sigcheck::{self, Tx};
use ff::Field;
use ripemd::Ripemd160;
use sha1::Sha1;
use sha2::{Digest, Sha256};

pub const ARITY: usize = 19;

/// Indices into the state vector.
pub mod z {
  pub const P: usize = 0;
  pub const S: usize = 1;
  pub const D: usize = 2;
  pub const A: usize = 3;
  pub const AD: usize = 4;
  pub const T: usize = 5;
  pub const TD: usize = 6;
  pub const SV: usize = 7;
  pub const SVD: usize = 8;
  pub const CS: usize = 9;
  pub const FF: usize = 10;
  pub const OC: usize = 11;
  pub const CL: usize = 12;
  pub const SID: usize = 13;
  pub const CSP: usize = 14;
  pub const PH: usize = 15;
  pub const CNT: usize = 16;
  pub const HOLD: usize = 17;
  pub const HOLD2: usize = 18;
}

pub type State = [F; ARITY];

#[derive(Clone, Debug)]
pub struct El {
  pub b: Vec<u8>,
  pub g: F,
}

impl El {
  pub fn new(b: Vec<u8>) -> Self {
    let g = enc(&b);
    El { b, g }
  }
}

#[derive(Clone, Default)]
pub struct CStack {
  pub items: Vec<El>,
  comms: Vec<F>,
}

impl CStack {
  pub fn top(&self) -> F {
    *self.comms.last().unwrap_or(&F::ZERO)
  }
  pub fn len(&self) -> usize {
    self.items.len()
  }
  pub fn push(&mut self, e: El) {
    let c = hash(&[self.top(), e.g]);
    self.items.push(e);
    self.comms.push(c);
  }
  /// The popped element and the commitment of the stack below it.
  pub fn pop(&mut self) -> Option<(El, F)> {
    let e = self.items.pop()?;
    self.comms.pop();
    Some((e, self.top()))
  }
}

/// Nondeterministic inputs of one step.
#[derive(Clone, Debug, Default)]
pub struct Wit {
  pub iop: u64,
  pub data: F,
  pub aux: u64,
  pub next: F,
  /// Popped main-stack elements, top first, and the commitment below each (for i >= k: the
  /// commitment below the last pop).
  pub p: [F; 6],
  pub s: [F; 6],
  pub a: F,
  pub a1: F,
  pub t: F,
  pub t1: F,
  pub w: F,
}

#[derive(Clone, Debug)]
pub enum Claim {
  Hash { op: u64, input: Vec<u8> },
  Bool { bytes: Vec<u8> },
  Size { bytes: Vec<u8> },
  CheckSig { sig: Vec<u8>, key: Vec<u8>, sid: u64, csp: u64 },
  Cms { keys: Vec<Vec<u8>>, sigs: Vec<Vec<u8>>, dummy: Vec<u8>, sid: u64, csp: u64 },
  LockTime { op: u64, operand: Vec<u8> },
}

pub struct Ctx<'a> {
  pub tx: &'a Tx,
  pub n_in: usize,
  pub amount: i64,
  pub flags: u32,
}

pub fn hash_op(op: u64, x: &[u8]) -> Vec<u8> {
  match op {
    iop::RIPEMD160 => Ripemd160::digest(x).to_vec(),
    iop::SHA1 => Sha1::digest(x).to_vec(),
    iop::SHA256 => Sha256::digest(x).to_vec(),
    iop::HASH160 => Ripemd160::digest(Sha256::digest(x)).to_vec(),
    iop::HASH256 => Sha256::digest(Sha256::digest(x)).to_vec(),
    _ => unreachable!(),
  }
}

pub fn cast_bool(b: &[u8]) -> bool {
  for (i, &x) in b.iter().enumerate() {
    if x != 0 {
      return !(i == b.len() - 1 && x == 0x80);
    }
  }
  false
}

/// CScriptNum(vch, fRequireMinimal, max_len).
pub fn script_num(b: &[u8], req_min: bool, max_len: usize) -> Result<i64, &'static str> {
  if b.len() > max_len {
    return Err("SCRIPTNUM_OVERFLOW");
  }
  if req_min && !b.is_empty() {
    let last = b[b.len() - 1];
    if last & 0x7f == 0 && (b.len() <= 1 || b[b.len() - 2] & 0x80 == 0) {
      return Err("SCRIPTNUM_MINIMAL");
    }
  }
  if b.is_empty() {
    return Ok(0);
  }
  let mut v: i64 = 0;
  for (i, &x) in b.iter().enumerate() {
    v |= (x as i64) << (8 * i);
  }
  let last = b[b.len() - 1];
  if last & 0x80 != 0 {
    Ok(-(v & !(0x80i64 << (8 * (b.len() - 1)))))
  } else {
    Ok(v)
  }
}

impl Claim {
  /// The claim's kind and fields as the accumulator absorbs them, recomputed from the payload.
  /// `result` is the outcome the checker computed (bool claims and signature claims).
  pub fn fields(&self, result: u64) -> (u64, [F; 6]) {
    let z = F::ZERO;
    match self {
      Claim::Hash { op, input } => (*op, [enc(input), enc(&hash_op(*op, input)), z, z, z, z]),
      Claim::Bool { bytes } => (kind::BOOL, [enc(bytes), fu(cast_bool(bytes) as u64), z, z, z, z]),
      Claim::Size { bytes } => (kind::SIZE, [enc(bytes), fu(bytes.len() as u64), z, z, z, z]),
      Claim::CheckSig { sig, key, sid, csp } => {
        (iop::CHECKSIG, [enc(sig), enc(key), fu(*sid), fu(*csp), fu(result), z])
      }
      Claim::Cms { keys, sigs, dummy, sid, csp } => {
        let mut h = F::ZERO;
        for e in keys.iter().chain(sigs.iter()) {
          h = hash(&[h, enc(e)]);
        }
        let h2 = keys.len() as u64 + 256 * sigs.len() as u64;
        (iop::CMS, [h, fu(h2), enc(dummy), fu(*sid), fu(*csp), fu(result)])
      }
      Claim::LockTime { op, operand } => (*op, [enc(operand), z, z, z, z, z]),
    }
  }
}

pub fn absorb_claim(acc: F, kind: u64, f: &[F; 6]) -> F {
  hash(&[acc, fu(kind), f[0], f[1], f[2], f[3], f[4], f[5]])
}

/// Checks one claim with Core's rules; returns the result bit the accumulator must carry.
pub fn check_claim(c: &Claim, prog: &Program, ctx: &Ctx) -> Result<u64, &'static str> {
  let script = |sid: u64| &prog.scripts[sid as usize];
  Ok(match c {
    Claim::Hash { .. } | Claim::Bool { .. } | Claim::Size { .. } => 0,
    Claim::CheckSig { sig, key, sid, csp } => {
      let (s, sv) = script(*sid);
      sigcheck::checksig(sig, key, s, *csp as usize, *sv, ctx.flags, ctx.tx, ctx.n_in, ctx.amount)? as u64
    }
    Claim::Cms { keys, sigs, dummy, sid, csp } => {
      let (s, sv) = script(*sid);
      sigcheck::checkmultisig(keys, sigs, dummy, s, *csp as usize, *sv, ctx.flags, ctx.tx, ctx.n_in, ctx.amount)?
        as u64
    }
    Claim::LockTime { op, operand } => {
      if *op == iop::CLTV {
        sigcheck::check_locktime(operand, ctx.flags, ctx.tx, ctx.n_in)?;
      } else {
        sigcheck::check_sequence(operand, ctx.flags, ctx.tx, ctx.n_in)?;
      }
      0
    }
  })
}

pub struct Machine<'a> {
  pub prog: &'a Program,
  pub commits: Vec<F>,
  pub ctx: Ctx<'a>,
  pub pc: usize,
  pub main: CStack,
  pub alt: CStack,
  pub tmp: CStack,
  pub saved: CStack,
  /// Set by SETD1 (Core's stack.resize(1) after a witness program): the depth the state reports.
  pub depth_override: Option<usize>,
  pub cs: u64,
  pub ff: u64,
  pub oc: u64,
  pub cl: F,
  pub sid: u64,
  pub csp: u64,
  pub ph: u64,
  pub cnt: u64,
  pub hold: F,
  pub hold_el: Option<El>,
  pub hold2: u64,
  pub ms_keys: Vec<Vec<u8>>,
  pub ms_sigs: Vec<Vec<u8>>,
  pub claims: Vec<Claim>,
  /// The last error came from a claim check (a signature or locktime rule), not the machine.
  pub claim_failed: bool,
}

pub struct Trace {
  pub z0: State,
  pub wits: Vec<Wit>,
  pub zs: Vec<State>,
  pub claims: Vec<Claim>,
}

impl<'a> Machine<'a> {
  pub fn new(prog: &'a Program, ctx: Ctx<'a>) -> Self {
    Machine {
      commits: prog.commits(),
      prog,
      ctx,
      pc: 0,
      main: CStack::default(),
      alt: CStack::default(),
      tmp: CStack::default(),
      saved: CStack::default(),
      depth_override: None,
      cs: 0,
      ff: NO_FALSE,
      oc: 0,
      cl: F::ZERO,
      sid: 0,
      csp: 0,
      ph: 0,
      cnt: 0,
      hold: F::ZERO,
      hold_el: None,
      hold2: 0,
      ms_keys: vec![],
      ms_sigs: vec![],
      claims: vec![],
      claim_failed: false,
    }
  }

  pub fn depth(&self) -> usize {
    self.depth_override.unwrap_or(self.main.len())
  }

  pub fn state(&self) -> State {
    let mut s = [F::ZERO; ARITY];
    s[z::P] = self.commits[self.pc];
    s[z::S] = self.main.top();
    s[z::D] = fu(self.depth() as u64);
    s[z::A] = self.alt.top();
    s[z::AD] = fu(self.alt.len() as u64);
    s[z::T] = self.tmp.top();
    s[z::TD] = fu(self.tmp.len() as u64);
    s[z::SV] = self.saved.top();
    s[z::SVD] = fu(self.saved.len() as u64);
    s[z::CS] = fu(self.cs);
    s[z::FF] = fu(self.ff);
    s[z::OC] = fu(self.oc);
    s[z::CL] = self.cl;
    s[z::SID] = fu(self.sid);
    s[z::CSP] = fu(self.csp);
    s[z::PH] = fu(self.ph);
    s[z::CNT] = fu(self.cnt);
    s[z::HOLD] = self.hold;
    s[z::HOLD2] = fu(self.hold2);
    s
  }

  pub fn done(&self) -> bool {
    self.pc == self.prog.instrs.len() && self.ph == 0
  }

  fn claim(&mut self, c: Claim) -> Result<F, &'static str> {
    let r = check_claim(&c, self.prog, &self.ctx).map_err(|e| {
      self.claim_failed = true;
      e
    })?;
    let (k, f) = c.fields(r);
    self.cl = absorb_claim(self.cl, k, &f);
    self.claims.push(c);
    Ok(fu(r))
  }

  /// One step. Err is the Core error that ends the execution.
  pub fn step(&mut self) -> Result<Wit, &'static str> {
    let mut w = Wit::default();
    self.step_into(&mut w)?;
    Ok(w)
  }

  /// One step, filling `w` as far as the step got: on an error the witness of the failing step
  /// is left in `w` (the soundness test feeds it to the circuit).
  pub fn step_into(&mut self, w: &mut Wit) -> Result<(), &'static str> {
    let ins = self.prog.instrs.get(self.pc).ok_or("PROGRAM_END")?.clone();
    *w = Wit { iop: ins.iop, data: ins.data, aux: ins.aux, next: self.commits[self.pc + 1], ..Default::default() };
    let exec = self.ff == NO_FALSE;
    let dc = if self.ph == 0 { ins.iop } else { self.ph + (self.cnt == 0) as u64 };
    let c = ctrl(dc).expect("dispatch code");
    let g = !c.gated || exec;
    let req_min = ins.aux & 2 != 0;
    if self.ph == 0 && c.counted {
      self.oc += 1;
    }

    // Pops (the circuit pops exactly c.k when the row applies).
    let mut p: Vec<El> = vec![];
    let mut below = self.main.top();
    if g {
      for i in 0..c.k as usize {
        let (e, b) = self.main.pop().ok_or("INVALID_STACK_OPERATION")?;
        w.p[i] = e.g;
        w.s[i] = b;
        below = b;
        p.push(e);
      }
    }
    for i in p.len()..6 {
      w.s[i] = below;
    }

    let mut n_out: Option<El> = None;
    let mut b_out: Option<bool> = None;
    let mut w_el: Option<El> = None;
    let mut a_el: Option<El> = None;
    let mut t_el: Option<El> = None;
    let mut ifdup_extra = false;
    let mut advance = true;

    if g {
      match dc {
        iop::PUSH => {
          if ins.aux & 1 != 0 {
            return Err("MINIMALDATA");
          }
        }
        iop::NOP | iop::CODESEP => {
          if dc == iop::CODESEP {
            self.csp = ins.aux >> 2;
          }
        }
        iop::FAIL_C | iop::FAIL_N => return Err("BAD_OPCODE"),
        iop::IF | iop::NOTIF | iop::IF_MIN | iop::NOTIF_MIN | iop::ELSE | iop::ENDIF => {}
        iop::VERIFY | iop::CHECKTRUE | iop::IFDUP => {
          let b = cast_bool(&p[0].b);
          if is_long(&p[0].g) {
            self.claim(Claim::Bool { bytes: p[0].b.clone() })?;
            w.w = fu(b as u64);
          }
          if dc == iop::IFDUP {
            ifdup_extra = b;
          } else if !b {
            return Err(if dc == iop::VERIFY { "VERIFY" } else { "EVAL_FALSE" });
          }
          b_out = Some(b);
        }
        iop::DROP2 | iop::DUP2 | iop::DUP3 | iop::OVER2 | iop::ROT2 | iop::SWAP2 | iop::DROP | iop::DUP | iop::NIP
        | iop::OVER | iop::ROT | iop::SWAP | iop::TUCK => {}
        iop::TOALT => self.alt.push(p[0].clone()),
        iop::FROMALT => {
          let (e, below) = self.alt.pop().ok_or("INVALID_ALTSTACK_OPERATION")?;
          w.a = e.g;
          w.a1 = below;
          a_el = Some(e);
        }
        iop::DEPTH => n_out = Some(El::new(crate::elem::script_num(self.depth() as i64))),
        iop::SIZE => {
          let l = p[0].b.len();
          if is_long(&p[0].g) {
            self.claim(Claim::Size { bytes: p[0].b.clone() })?;
            w.w = fu(l as u64);
          }
          n_out = Some(El::new(crate::elem::script_num(l as i64)));
        }
        iop::EQUAL | iop::EQUALVERIFY => {
          let b = p[0].b == p[1].b;
          if dc == iop::EQUALVERIFY && !b {
            return Err("EQUALVERIFY");
          }
          b_out = Some(b);
        }
        iop::ADD1..=iop::WITHIN => {
          let n1 = script_num(&p[0].b, req_min, 4)?;
          let (n2, n3) = match c.nnum {
            1 => (0, 0),
            2 => (script_num(&p[1].b, req_min, 4)?, 0),
            _ => (script_num(&p[1].b, req_min, 4)?, script_num(&p[2].b, req_min, 4)?),
          };
          // binary ops: x1 = n2 (second), x2 = n1 (top); WITHIN: x = n3, min = n2, max = n1
          let num = |v: i64| Some(El::new(crate::elem::script_num(v)));
          match dc {
            iop::ADD1 => n_out = num(n1 + 1),
            iop::SUB1 => n_out = num(n1 - 1),
            iop::NEGATE => n_out = num(-n1),
            iop::ABS => n_out = num(n1.abs()),
            iop::NOT => b_out = Some(n1 == 0),
            iop::NOTEQ0 => b_out = Some(n1 != 0),
            iop::ADD => n_out = num(n2 + n1),
            iop::SUB => n_out = num(n2 - n1),
            iop::BOOLAND => b_out = Some(n2 != 0 && n1 != 0),
            iop::BOOLOR => b_out = Some(n2 != 0 || n1 != 0),
            iop::NUMEQ => b_out = Some(n2 == n1),
            iop::NUMEQV => {
              if n2 != n1 {
                return Err("NUMEQUALVERIFY");
              }
              b_out = Some(true);
            }
            iop::NUMNE => b_out = Some(n2 != n1),
            iop::LT => b_out = Some(n2 < n1),
            iop::GT => b_out = Some(n2 > n1),
            iop::LE => b_out = Some(n2 <= n1),
            iop::GE => b_out = Some(n2 >= n1),
            iop::MIN => n_out = num(n2.min(n1)),
            iop::MAX => n_out = num(n2.max(n1)),
            iop::WITHIN => b_out = Some(n2 <= n3 && n3 < n1),
            _ => unreachable!(),
          }
        }
        iop::RIPEMD160..=iop::HASH256 => {
          let out = El::new(hash_op(dc, &p[0].b));
          self.claim(Claim::Hash { op: dc, input: p[0].b.clone() })?;
          w.w = out.g;
          w_el = Some(out);
        }
        iop::CHECKSIG | iop::CHECKSIGV => {
          let r = self.claim(Claim::CheckSig { sig: p[1].b.clone(), key: p[0].b.clone(), sid: self.sid, csp: self.csp })?;
          let ok = r == F::ONE;
          if dc == iop::CHECKSIGV && !ok {
            return Err("CHECKSIGVERIFY");
          }
          w.w = r;
          b_out = Some(ok);
        }
        iop::CLTV | iop::CSV => {
          self.claim(Claim::LockTime { op: dc, operand: p[0].b.clone() })?;
        }
        iop::PICK | iop::ROLL => {
          let n = script_num(&p[0].b, req_min, 4)?;
          if n < 0 || n as usize >= self.main.len() {
            return Err("INVALID_STACK_OPERATION");
          }
          self.cnt = n as u64;
          self.ph = c.next_phase;
          advance = false;
        }
        iop::CMS | iop::CMSV => {
          let n = script_num(&p[0].b, req_min, 4)?;
          if !(0..=20).contains(&n) {
            return Err("PUBKEY_COUNT");
          }
          self.oc += n as u64;
          if self.oc > MAX_OPS {
            return Err("OP_COUNT");
          }
          self.cnt = n as u64;
          self.hold = F::ZERO;
          self.hold2 = n as u64;
          self.ms_keys.clear();
          self.ms_sigs.clear();
          self.ph = c.next_phase;
          advance = false;
        }
        iop::BEGIN => {
          if self.cs != 0 {
            return Err("UNBALANCED_CONDITIONAL");
          }
          self.oc = 0;
          self.alt = CStack::default();
          self.sid = ins.aux >> 2;
          self.csp = 0;
        }
        iop::END => {
          if self.cs != 0 {
            return Err("UNBALANCED_CONDITIONAL");
          }
          self.alt = CStack::default();
        }
        iop::SAVE => self.saved = self.main.clone(),
        iop::RESTORE => self.main = self.saved.clone(),
        iop::RESET => {
          self.main = CStack::default();
          self.depth_override = None;
        }
        iop::LIT => {}
        iop::CLEAN1 => {
          if self.depth() != 1 {
            return Err("CLEANSTACK");
          }
        }
        iop::SETD1 => self.depth_override = Some(1),
        iop::POPEQ => {
          if p[0].g != ins.data {
            return Err("P2SH_REDEEM");
          }
        }
        // PICK/ROLL phases
        80 | 82 => {
          self.tmp.push(p[0].clone());
          self.cnt -= 1;
          advance = false;
        }
        81 | 83 => {
          self.hold = p[0].g;
          self.hold_el = Some(p[0].clone());
          self.cnt = self.tmp.len() as u64;
          self.ph = phase::UP;
          advance = false;
        }
        84 => {
          let (e, below) = self.tmp.pop().unwrap();
          w.t = e.g;
          w.t1 = below;
          t_el = Some(e);
          self.cnt -= 1;
          advance = false;
        }
        85 => {
          self.hold = F::ZERO;
          self.ph = 0;
        }
        // CHECKMULTISIG phases
        86 | 88 | 90 | 92 => {
          self.hold = hash(&[self.hold, p[0].g]);
          if dc == 86 || dc == 90 {
            self.ms_keys.push(p[0].b.clone());
          } else {
            self.ms_sigs.push(p[0].b.clone());
          }
          self.cnt -= 1;
          advance = false;
        }
        87 | 91 => {
          let m = script_num(&p[0].b, req_min, 4)?;
          if m < 0 || m as u64 > self.hold2 {
            return Err("SIG_COUNT");
          }
          self.cnt = m as u64;
          self.hold2 += 256 * m as u64;
          self.ph = c.next_phase;
          advance = false;
        }
        89 | 93 => {
          let claim = Claim::Cms {
            keys: std::mem::take(&mut self.ms_keys),
            sigs: std::mem::take(&mut self.ms_sigs),
            dummy: p[0].b.clone(),
            sid: self.sid,
            csp: self.csp,
          };
          let r = self.claim(claim)?;
          let ok = r == F::ONE;
          if dc == 93 && !ok {
            return Err("CHECKMULTISIGVERIFY");
          }
          w.w = r;
          b_out = Some(ok);
          self.hold = F::ZERO;
          self.hold2 = 0;
          self.ph = 0;
        }
        _ => unreachable!("dispatch {dc}"),
      }
    }

    // Condition stack (not gated).
    match dc {
      iop::IF | iop::NOTIF | iop::IF_MIN | iop::NOTIF_MIN => {
        let mut f = false;
        if exec {
          let e = &p[0];
          if dc == iop::IF_MIN || dc == iop::NOTIF_MIN {
            if e.b.len() > 1 || (e.b.len() == 1 && e.b[0] != 1) {
              return Err("MINIMALIF");
            }
          } else if is_long(&e.g) {
            self.claim(Claim::Bool { bytes: e.b.clone() })?;
            w.w = fu(cast_bool(&e.b) as u64);
          }
          f = cast_bool(&e.b);
          if dc == iop::NOTIF || dc == iop::NOTIF_MIN {
            f = !f;
          }
        }
        if self.ff == NO_FALSE && !f {
          self.ff = self.cs;
        }
        self.cs += 1;
      }
      iop::ELSE => {
        if self.cs == 0 {
          return Err("UNBALANCED_CONDITIONAL");
        }
        if self.ff == NO_FALSE {
          self.ff = self.cs - 1;
        } else if self.ff == self.cs - 1 {
          self.ff = NO_FALSE;
        }
      }
      iop::ENDIF => {
        if self.cs == 0 {
          return Err("UNBALANCED_CONDITIONAL");
        }
        self.cs -= 1;
        if self.ff == self.cs {
          self.ff = NO_FALSE;
        }
      }
      _ => {}
    }

    // Pushes, in the control row's order.
    if g {
      let m = c.m as usize + ifdup_extra as usize;
      for j in 0..m {
        let src = if j < c.m as usize { c.out[j] } else { Src::P1 };
        let e = match src {
          Src::P1 => p[0].clone(),
          Src::P2 => p[1].clone(),
          Src::P3 => p[2].clone(),
          Src::P4 => p[3].clone(),
          Src::P5 => p[4].clone(),
          Src::P6 => p[5].clone(),
          Src::D => El { b: ins.bytes.clone(), g: ins.data },
          Src::N => n_out.clone().unwrap(),
          Src::B => El::new(if b_out.unwrap() { vec![1] } else { vec![] }),
          Src::W => w_el.clone().unwrap(),
          Src::A => a_el.clone().unwrap(),
          Src::T => t_el.clone().unwrap(),
          Src::H => self.hold_el.take().unwrap(),
        };
        self.main.push(e);
      }
    }

    if self.oc > MAX_OPS {
      return Err("OP_COUNT");
    }
    if self.depth() + self.alt.len() + self.tmp.len() > MAX_STACK as usize {
      return Err("STACK_SIZE");
    }
    if advance && !(g && c.stay) {
      self.pc += 1;
    }
    Ok(())
  }

  /// Runs to the end of the program. Err is the first Core error.
  pub fn run(&mut self, record: bool) -> Result<Trace, &'static str> {
    let z0 = self.state();
    let mut wits = vec![];
    let mut zs = vec![];
    while !self.done() {
      let w = self.step()?;
      if record {
        wits.push(w);
        zs.push(self.state());
      }
    }
    Ok(Trace { z0, wits, zs, claims: std::mem::take(&mut self.claims) })
  }
}

/// The checker's view: z0 of a compiled program.
pub fn initial_state(prog: &Program) -> State {
  let mut s = [F::ZERO; ARITY];
  s[z::P] = prog.commits()[0];
  s[z::FF] = fu(NO_FALSE);
  s
}

/// Verifies the claims a proof's final state accumulated: each against Core's rules, and the
/// accumulator recomputed from the payloads alone.
pub fn verify_claims(claims: &[Claim], prog: &Program, ctx: &Ctx, acc: F) -> Result<(), &'static str> {
  let mut a = F::ZERO;
  for c in claims {
    let r = check_claim(c, prog, ctx)?;
    let (k, f) = c.fields(r);
    a = absorb_claim(a, k, &f);
  }
  if a != acc {
    return Err("CLAIMS_MISMATCH");
  }
  Ok(())
}
