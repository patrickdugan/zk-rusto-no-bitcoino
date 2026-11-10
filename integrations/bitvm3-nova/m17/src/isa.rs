//! The step machine's instruction set and its control table.
//!
//! The checker compiles a spend (scriptSig, scriptPubKey, P2SH redeem script, witness script, and
//! the flags) into a linear program of these instructions. Bitcoin opcodes map one to one where
//! their meaning does not depend on the flags; flag-dependent behaviour is resolved at compile
//! time (MINIMALIF, discouraged NOPs, CLTV/CSV without their flag, CONST_SCRIPTCODE). Pseudo
//! instructions carry out VerifyScript's orchestration between scripts.
//!
//! Each step executes one dispatch code: the instruction's iop when no multi-step operation is in
//! progress, else the phase register plus one when the counter is zero. The control row of the
//! dispatch code fixes every selector of the step circuit.

pub mod iop {
  pub const PUSH: u64 = 1;
  pub const NOP: u64 = 2;
  pub const FAIL_C: u64 = 3; // fails when executed; counts toward the opcode limit
  pub const FAIL_N: u64 = 4; // fails when executed; does not count (OP_RESERVED)
  pub const IF: u64 = 5;
  pub const NOTIF: u64 = 6;
  pub const IF_MIN: u64 = 7;
  pub const NOTIF_MIN: u64 = 8;
  pub const ELSE: u64 = 9;
  pub const ENDIF: u64 = 10;
  pub const VERIFY: u64 = 11;
  pub const TOALT: u64 = 12;
  pub const FROMALT: u64 = 13;
  pub const DROP2: u64 = 14;
  pub const DUP2: u64 = 15;
  pub const DUP3: u64 = 16;
  pub const OVER2: u64 = 17;
  pub const ROT2: u64 = 18;
  pub const SWAP2: u64 = 19;
  pub const IFDUP: u64 = 20;
  pub const DEPTH: u64 = 21;
  pub const DROP: u64 = 22;
  pub const DUP: u64 = 23;
  pub const NIP: u64 = 24;
  pub const OVER: u64 = 25;
  pub const PICK: u64 = 26;
  pub const ROLL: u64 = 27;
  pub const ROT: u64 = 28;
  pub const SWAP: u64 = 29;
  pub const TUCK: u64 = 30;
  pub const SIZE: u64 = 31;
  pub const EQUAL: u64 = 32;
  pub const EQUALVERIFY: u64 = 33;
  pub const ADD1: u64 = 34;
  pub const SUB1: u64 = 35;
  pub const NEGATE: u64 = 36;
  pub const ABS: u64 = 37;
  pub const NOT: u64 = 38;
  pub const NOTEQ0: u64 = 39;
  pub const ADD: u64 = 40;
  pub const SUB: u64 = 41;
  pub const BOOLAND: u64 = 42;
  pub const BOOLOR: u64 = 43;
  pub const NUMEQ: u64 = 44;
  pub const NUMEQV: u64 = 45;
  pub const NUMNE: u64 = 46;
  pub const LT: u64 = 47;
  pub const GT: u64 = 48;
  pub const LE: u64 = 49;
  pub const GE: u64 = 50;
  pub const MIN: u64 = 51;
  pub const MAX: u64 = 52;
  pub const WITHIN: u64 = 53;
  pub const RIPEMD160: u64 = 54;
  pub const SHA1: u64 = 55;
  pub const SHA256: u64 = 56;
  pub const HASH160: u64 = 57;
  pub const HASH256: u64 = 58;
  pub const CODESEP: u64 = 59;
  pub const CHECKSIG: u64 = 60;
  pub const CHECKSIGV: u64 = 61;
  pub const CMS: u64 = 62;
  pub const CMSV: u64 = 63;
  pub const CLTV: u64 = 64;
  pub const CSV: u64 = 65;
  // pseudo instructions
  pub const BEGIN: u64 = 66;
  pub const END: u64 = 67;
  pub const SAVE: u64 = 68;
  pub const RESTORE: u64 = 69;
  pub const RESET: u64 = 70;
  pub const LIT: u64 = 71;
  pub const CLEAN1: u64 = 72;
  pub const SETD1: u64 = 73;
  pub const POPEQ: u64 = 74;
  pub const CHECKTRUE: u64 = 75;
}

/// Phase registers of the multi-step operations (dispatch = phase + [counter == 0]).
pub mod phase {
  pub const PICK_DN: u64 = 80;
  pub const ROLL_DN: u64 = 82;
  pub const UP: u64 = 84;
  pub const CMS_K: u64 = 86;
  pub const CMS_S: u64 = 88;
  pub const CMSV_K: u64 = 90;
  pub const CMSV_S: u64 = 92;
}

/// Claim kinds that are not opcodes.
pub mod kind {
  pub const BOOL: u64 = 100;
  pub const SIZE: u64 = 101;
}

/// The condition stack's "no false entry" marker (Core's ConditionStack::NO_FALSE).
pub const NO_FALSE: u64 = 1 << 20;
pub const MAX_OPS: u64 = 201;
pub const MAX_STACK: u64 = 1000;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Src {
  P1,
  P2,
  P3,
  P4,
  P5,
  P6,
  D,
  N,
  B,
  W,
  A,
  T,
  H,
}
pub const SRCS: [Src; 13] =
  [Src::P1, Src::P2, Src::P3, Src::P4, Src::P5, Src::P6, Src::D, Src::N, Src::B, Src::W, Src::A, Src::T, Src::H];

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Enc {
  None,
  Inc,
  Dec,
  Neg,
  Abs,
  Add,
  Sub,
  Min,
  Max,
  Depth,
  Size,
}
pub const ENCS: [Enc; 10] =
  [Enc::Inc, Enc::Dec, Enc::Neg, Enc::Abs, Enc::Add, Enc::Sub, Enc::Min, Enc::Max, Enc::Depth, Enc::Size];

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Bool {
  None,
  Not,
  Nz,
  BAnd,
  BOr,
  NumEq,
  NumNe,
  Lt,
  Gt,
  Le,
  Ge,
  Within,
  Equal,
  Cb,
  W,
}
pub const BOOLS: [Bool; 14] = [
  Bool::Not,
  Bool::Nz,
  Bool::BAnd,
  Bool::BOr,
  Bool::NumEq,
  Bool::NumNe,
  Bool::Lt,
  Bool::Gt,
  Bool::Le,
  Bool::Ge,
  Bool::Within,
  Bool::Equal,
  Bool::Cb,
  Bool::W,
];

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CSrc {
  Zero,
  P1,
  P2,
  W,
  Hold,
  Hold2,
  Sid,
  Csp,
}
pub const CSRCS: [CSrc; 7] = [CSrc::P1, CSrc::P2, CSrc::W, CSrc::Hold, CSrc::Hold2, CSrc::Sid, CSrc::Csp];

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ClaimMode {
  None,
  Always,
  IfLong,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Cond {
  None,
  If,
  NotIf,
  IfMin,
  NotIfMin,
  Else,
  EndIf,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Pseudo {
  None,
  Begin,
  End,
  Save,
  Restore,
  Reset,
  SetD1,
  Clean1,
  PopEq,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Cnt {
  Keep,
  N1,
  Dec,
  Td,
}
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Hold {
  Keep,
  Zero,
  Hash,
  P1,
}
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Hold2 {
  Keep,
  Zero,
  N1,
  AddSigs,
}
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Rc {
  None,
  PickRoll, // n1 <= D - 2
  MsKeys,   // n1 <= 20
  MsSigs,   // n1 <= HOLD2
}

#[derive(Clone, Copy, Debug)]
pub struct Ctrl {
  /// Stack, claim and register effects apply only while executing (fExec).
  pub gated: bool,
  pub counted: bool,
  pub k: u8,
  pub m: u8,
  pub out: [Src; 6],
  /// OP_IFDUP: one more push of P1 when the castbool result is true.
  pub ifdup: bool,
  pub alt_pop: bool,
  pub alt_push: bool,
  pub tmp_pop: bool,
  pub tmp_push: bool,
  pub nnum: u8,
  pub bits: bool,
  pub enc: Enc,
  pub bool_: Bool,
  pub verify: bool,
  pub w_bool: bool,
  pub claim: ClaimMode,
  pub claim_kind: u64,
  pub cf: [CSrc; 6],
  pub cond: Cond,
  pub pseudo: Pseudo,
  pub codesep: bool,
  pub fail: bool,
  pub push_fail_aux: bool,
  pub stay: bool,
  pub next_phase: u64,
  pub cnt: Cnt,
  pub hold: Hold,
  pub hold2: Hold2,
  pub rc: Rc,
  pub nonneg1: bool,
  pub oc_add_n1: bool,
}

const BASE: Ctrl = Ctrl {
  gated: true,
  counted: true,
  k: 0,
  m: 0,
  out: [Src::P1; 6],
  ifdup: false,
  alt_pop: false,
  alt_push: false,
  tmp_pop: false,
  tmp_push: false,
  nnum: 0,
  bits: false,
  enc: Enc::None,
  bool_: Bool::None,
  verify: false,
  w_bool: false,
  claim: ClaimMode::None,
  claim_kind: 0,
  cf: [CSrc::Zero; 6],
  cond: Cond::None,
  pseudo: Pseudo::None,
  codesep: false,
  fail: false,
  push_fail_aux: false,
  stay: false,
  next_phase: 0,
  cnt: Cnt::Keep,
  hold: Hold::Keep,
  hold2: Hold2::Keep,
  rc: Rc::None,
  nonneg1: false,
  oc_add_n1: false,
};

fn outs(o: &[Src]) -> [Src; 6] {
  let mut a = [Src::P1; 6];
  a[..o.len()].copy_from_slice(o);
  a
}

fn mv(k: u8, o: &[Src]) -> Ctrl {
  Ctrl { k, m: o.len() as u8, out: outs(o), ..BASE }
}

fn cf(f: &[CSrc]) -> [CSrc; 6] {
  let mut a = [CSrc::Zero; 6];
  a[..f.len()].copy_from_slice(f);
  a
}

fn num(k: u8, nnum: u8, o: &[Src], enc: Enc, b: Bool) -> Ctrl {
  Ctrl { nnum, enc, bool_: b, ..mv(k, o) }
}

fn castbool(k: u8, o: &[Src]) -> Ctrl {
  Ctrl {
    bits: true,
    bool_: Bool::Cb,
    claim: ClaimMode::IfLong,
    claim_kind: kind::BOOL,
    cf: cf(&[CSrc::P1, CSrc::W]),
    ..mv(k, o)
  }
}

fn pseudo(p: Pseudo) -> Ctrl {
  Ctrl { gated: false, counted: false, pseudo: p, ..BASE }
}

fn ms_start(next: u64) -> Ctrl {
  Ctrl {
    nnum: 1,
    rc: Rc::MsKeys,
    nonneg1: true,
    oc_add_n1: true,
    stay: true,
    next_phase: next,
    cnt: Cnt::N1,
    hold: Hold::Zero,
    hold2: Hold2::N1,
    ..mv(1, &[])
  }
}

fn ph(c: Ctrl) -> Ctrl {
  Ctrl { counted: false, ..c }
}

fn ms_key(next: u64) -> Ctrl {
  ph(Ctrl { hold: Hold::Hash, cnt: Cnt::Dec, stay: true, next_phase: next, ..mv(1, &[]) })
}

fn ms_nsigs(next: u64) -> Ctrl {
  ph(Ctrl {
    nnum: 1,
    rc: Rc::MsSigs,
    nonneg1: true,
    cnt: Cnt::N1,
    hold2: Hold2::AddSigs,
    stay: true,
    next_phase: next,
    ..mv(1, &[])
  })
}

fn ms_end(verify: bool) -> Ctrl {
  let o: &[Src] = if verify { &[] } else { &[Src::B] };
  ph(Ctrl {
    bool_: Bool::W,
    w_bool: true,
    verify,
    claim: ClaimMode::Always,
    claim_kind: iop::CMS,
    cf: cf(&[CSrc::Hold, CSrc::Hold2, CSrc::P1, CSrc::Sid, CSrc::Csp, CSrc::W]),
    hold: Hold::Zero,
    hold2: Hold2::Zero,
    ..mv(1, o)
  })
}

/// The control row of a dispatch code, or None for codes that cannot occur.
pub fn ctrl(dc: u64) -> Option<Ctrl> {
  use iop::*;
  use Src::*;
  let c = match dc {
    PUSH => Ctrl { counted: false, push_fail_aux: true, ..mv(0, &[D]) },
    NOP => BASE,
    FAIL_C => Ctrl { fail: true, ..BASE },
    FAIL_N => Ctrl { fail: true, counted: false, ..BASE },
    IF => Ctrl { cond: Cond::If, ..castbool(1, &[]) },
    NOTIF => Ctrl { cond: Cond::NotIf, ..castbool(1, &[]) },
    IF_MIN => Ctrl { cond: Cond::IfMin, ..mv(1, &[]) },
    NOTIF_MIN => Ctrl { cond: Cond::NotIfMin, ..mv(1, &[]) },
    ELSE => Ctrl { gated: false, cond: Cond::Else, ..BASE },
    ENDIF => Ctrl { gated: false, cond: Cond::EndIf, ..BASE },
    VERIFY => Ctrl { verify: true, ..castbool(1, &[]) },
    TOALT => Ctrl { alt_push: true, ..mv(1, &[]) },
    FROMALT => Ctrl { alt_pop: true, ..mv(0, &[A]) },
    DROP2 => mv(2, &[]),
    DUP2 => mv(2, &[P2, P1, P2, P1]),
    DUP3 => mv(3, &[P3, P2, P1, P3, P2, P1]),
    OVER2 => mv(4, &[P4, P3, P2, P1, P4, P3]),
    ROT2 => mv(6, &[P4, P3, P2, P1, P6, P5]),
    SWAP2 => mv(4, &[P2, P1, P4, P3]),
    IFDUP => Ctrl { ifdup: true, ..castbool(1, &[P1]) },
    DEPTH => Ctrl { enc: Enc::Depth, ..mv(0, &[N]) },
    DROP => mv(1, &[]),
    DUP => mv(1, &[P1, P1]),
    NIP => mv(2, &[P1]),
    OVER => mv(2, &[P2, P1, P2]),
    PICK | ROLL => Ctrl {
      nnum: 1,
      rc: Rc::PickRoll,
      nonneg1: true,
      stay: true,
      next_phase: if dc == PICK { phase::PICK_DN } else { phase::ROLL_DN },
      cnt: Cnt::N1,
      ..mv(1, &[])
    },
    ROT => mv(3, &[P2, P1, P3]),
    SWAP => mv(2, &[P1, P2]),
    TUCK => mv(2, &[P1, P2, P1]),
    SIZE => Ctrl {
      bits: true,
      enc: Enc::Size,
      claim: ClaimMode::IfLong,
      claim_kind: kind::SIZE,
      cf: cf(&[CSrc::P1, CSrc::W]),
      ..mv(1, &[P1, N])
    },
    EQUAL => Ctrl { bool_: Bool::Equal, ..mv(2, &[B]) },
    EQUALVERIFY => Ctrl { bool_: Bool::Equal, verify: true, ..mv(2, &[]) },
    ADD1 => num(1, 1, &[N], Enc::Inc, Bool::None),
    SUB1 => num(1, 1, &[N], Enc::Dec, Bool::None),
    NEGATE => num(1, 1, &[N], Enc::Neg, Bool::None),
    ABS => num(1, 1, &[N], Enc::Abs, Bool::None),
    NOT => num(1, 1, &[B], Enc::None, Bool::Not),
    NOTEQ0 => num(1, 1, &[B], Enc::None, Bool::Nz),
    ADD => num(2, 2, &[N], Enc::Add, Bool::None),
    SUB => num(2, 2, &[N], Enc::Sub, Bool::None),
    BOOLAND => num(2, 2, &[B], Enc::None, Bool::BAnd),
    BOOLOR => num(2, 2, &[B], Enc::None, Bool::BOr),
    NUMEQ => num(2, 2, &[B], Enc::None, Bool::NumEq),
    NUMEQV => Ctrl { verify: true, ..num(2, 2, &[], Enc::None, Bool::NumEq) },
    NUMNE => num(2, 2, &[B], Enc::None, Bool::NumNe),
    LT => num(2, 2, &[B], Enc::None, Bool::Lt),
    GT => num(2, 2, &[B], Enc::None, Bool::Gt),
    LE => num(2, 2, &[B], Enc::None, Bool::Le),
    GE => num(2, 2, &[B], Enc::None, Bool::Ge),
    MIN => num(2, 2, &[N], Enc::Min, Bool::None),
    MAX => num(2, 2, &[N], Enc::Max, Bool::None),
    WITHIN => num(3, 3, &[B], Enc::None, Bool::Within),
    RIPEMD160 | SHA1 | SHA256 | HASH160 | HASH256 => Ctrl {
      claim: ClaimMode::Always,
      claim_kind: dc,
      cf: cf(&[CSrc::P1, CSrc::W]),
      ..mv(1, &[W])
    },
    CODESEP => Ctrl { codesep: true, ..BASE },
    CHECKSIG | CHECKSIGV => Ctrl {
      bool_: Bool::W,
      w_bool: true,
      verify: dc == CHECKSIGV,
      claim: ClaimMode::Always,
      claim_kind: CHECKSIG,
      cf: cf(&[CSrc::P2, CSrc::P1, CSrc::Sid, CSrc::Csp, CSrc::W]),
      ..mv(2, if dc == CHECKSIG { &[B] } else { &[] })
    },
    CMS => ms_start(phase::CMS_K),
    CMSV => ms_start(phase::CMSV_K),
    CLTV | CSV => Ctrl {
      claim: ClaimMode::Always,
      claim_kind: dc,
      cf: cf(&[CSrc::P1]),
      ..mv(1, &[P1])
    },
    BEGIN => pseudo(Pseudo::Begin),
    END => pseudo(Pseudo::End),
    SAVE => pseudo(Pseudo::Save),
    RESTORE => pseudo(Pseudo::Restore),
    RESET => pseudo(Pseudo::Reset),
    LIT => Ctrl { k: 0, m: 1, out: outs(&[D]), ..pseudo(Pseudo::None) },
    CLEAN1 => pseudo(Pseudo::Clean1),
    SETD1 => pseudo(Pseudo::SetD1),
    POPEQ => Ctrl { k: 1, ..pseudo(Pseudo::PopEq) },
    CHECKTRUE => Ctrl { gated: false, counted: false, verify: true, ..castbool(1, &[P1]) },
    // PICK/ROLL: move n elements to the temporary stack, take the target, move them back.
    80 | 82 => ph(Ctrl { tmp_push: true, cnt: Cnt::Dec, stay: true, next_phase: dc, ..mv(1, &[]) }),
    81 => ph(Ctrl { hold: Hold::P1, cnt: Cnt::Td, stay: true, next_phase: phase::UP, ..mv(1, &[P1]) }),
    83 => ph(Ctrl { hold: Hold::P1, cnt: Cnt::Td, stay: true, next_phase: phase::UP, ..mv(1, &[]) }),
    84 => ph(Ctrl { tmp_pop: true, cnt: Cnt::Dec, stay: true, next_phase: phase::UP, ..mv(0, &[T]) }),
    85 => ph(Ctrl { hold: Hold::Zero, ..mv(0, &[H]) }),
    86 => ms_key(phase::CMS_K),
    87 => ms_nsigs(phase::CMS_S),
    88 => ms_key(phase::CMS_S),
    89 => ms_end(false),
    90 => ms_key(phase::CMSV_K),
    91 => ms_nsigs(phase::CMSV_S),
    92 => ms_key(phase::CMSV_S),
    93 => ms_end(true),
    _ => return None,
  };
  Some(c)
}

/// Every dispatch code with a control row, ascending.
pub fn dispatch_codes() -> Vec<u64> {
  (0..128).filter(|&d| ctrl(d).is_some()).collect()
}
