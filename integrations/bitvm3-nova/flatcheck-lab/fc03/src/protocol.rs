//! FC03 wire objects: trusted configuration, claim, challenge and response, with their canonical
//! encodings and identifiers. Every identifier is SHA-256 over an `enc::Enc` encoding.
use crate::{enc::Enc, flatmerkle, hexser};
use serde::{Deserialize, Serialize};

pub const VERSION: u32 = 1;
pub const RO_ID: &str = "nova-snark-0.76.0/PoseidonRO/ROConstants::default/128-bit-challenge";

/// Verifier-controlled parameters. Every field is pinned by the dispute contract; nothing here
/// comes from the operator.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustedConfig {
    pub field: u8,
    pub network: String,
    #[serde(with = "hexser::a32")]
    pub shape_digest: [u8; 32],
    #[serde(with = "hexser::a32")]
    pub matrix_root: [u8; 32],
    pub matrix_leaves: u32,
    pub num_cons: u32,
    pub num_vars: u32,
    pub num_io: u32,
    pub k: [u32; 3],
    pub w_leaves: u32,
    pub e_leaves: u32,
    pub ck_len: u32,
    #[serde(with = "hexser::a32")]
    pub ck_root: [u8; 32],
    pub ck_leaves: u32,
    pub trace_w_leaves: u32,
    pub trace_e_leaves: u32,
    #[serde(with = "hexser::a32")]
    pub pp_digest: [u8; 32],
    pub ro: String,
}

impl TrustedConfig {
    pub fn encode(&self) -> Enc {
        let mut e = Enc::new("trusted-config");
        e.u32("version", VERSION)
            .u8("field", self.field)
            .field("network", self.network.as_bytes())
            .field("shape_digest", &self.shape_digest)
            .field("matrix_root", &self.matrix_root)
            .u32("matrix_leaves", self.matrix_leaves)
            .u32("num_cons", self.num_cons)
            .u32("num_vars", self.num_vars)
            .u32("num_io", self.num_io)
            .u32("k_a", self.k[0])
            .u32("k_b", self.k[1])
            .u32("k_c", self.k[2])
            .u32("w_leaves", self.w_leaves)
            .u32("e_leaves", self.e_leaves)
            .u32("ck_len", self.ck_len)
            .field("ck_root", &self.ck_root)
            .u32("ck_leaves", self.ck_leaves)
            .u32("trace_w_leaves", self.trace_w_leaves)
            .u32("trace_e_leaves", self.trace_e_leaves)
            .field("pp_digest", &self.pp_digest)
            .field("ro", self.ro.as_bytes());
        e
    }
    pub fn digest(&self) -> [u8; 32] {
        self.encode().digest()
    }
    pub fn n_vec(&self, v: Vector) -> u32 {
        match v {
            Vector::W => self.num_vars,
            Vector::E => self.num_cons,
        }
    }
    /// Binding-trace transitions for vector v: 256 per scalar, the blinding scalar included.
    pub fn trace_steps(&self, v: Vector) -> u32 {
        (self.n_vec(v) + 1) * 256
    }
    pub fn trace_leaves(&self, v: Vector) -> u32 {
        match v {
            Vector::W => self.trace_w_leaves,
            Vector::E => self.trace_e_leaves,
        }
    }
    pub fn vec_leaves(&self, v: Vector) -> u32 {
        match v {
            Vector::W => self.w_leaves,
            Vector::E => self.e_leaves,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Vector {
    W,
    E,
}

impl Vector {
    pub fn byte(self) -> u8 {
        match self {
            Vector::W => b'W',
            Vector::E => b'E',
        }
    }
    pub fn value_tag(self) -> u8 {
        self.byte()
    }
    pub fn trace_tag(self) -> u8 {
        match self {
            Vector::W => crate::enc::tag::TRACE_W,
            Vector::E => crate::enc::tag::TRACE_E,
        }
    }
}

/// Binds a challenge to one contract on one network.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayDomain {
    pub network: String,
    #[serde(with = "hexser::a32")]
    pub contract_id: [u8; 32],
}

impl ReplayDomain {
    pub fn digest(&self) -> [u8; 32] {
        let mut e = Enc::new("replay-domain");
        e.field("network", self.network.as_bytes()).field("contract_id", &self.contract_id);
        e.digest()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Statement {
    #[serde(with = "hexser::a32")]
    pub pp_digest: [u8; 32],
    pub steps: u64,
    #[serde(with = "hexser::a32")]
    pub app_digest: [u8; 32],
}

impl Statement {
    pub fn digest(&self) -> [u8; 32] {
        let mut e = Enc::new("statement");
        e.field("pp_digest", &self.pp_digest).u64("steps", self.steps).field("app_digest", &self.app_digest);
        e.digest()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelaxedInstanceBytes {
    #[serde(with = "hexser::a65")]
    pub comm_w: [u8; 65],
    #[serde(with = "hexser::a65")]
    pub comm_e: [u8; 65],
    #[serde(with = "hexser::a32")]
    pub u: [u8; 32],
    #[serde(with = "hexser::v32")]
    pub x: Vec<[u8; 32]>,
}

impl RelaxedInstanceBytes {
    fn put(&self, e: &mut Enc, p: &str) {
        e.field(&format!("{p}.comm_W"), &self.comm_w).field(&format!("{p}.comm_E"), &self.comm_e).field(&format!("{p}.u"), &self.u);
        e.u32(&format!("{p}.num_x"), self.x.len() as u32);
        for x in &self.x {
            e.field(&format!("{p}.x"), x);
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StrictInstanceBytes {
    #[serde(with = "hexser::a65")]
    pub comm_w: [u8; 65],
    #[serde(with = "hexser::v32")]
    pub x: Vec<[u8; 32]>,
}

/// The NIFS transcript inputs of the last fold: U = fold(U1, U2, comm_T, r) with
/// r = Poseidon(pp_digest, U2, comm_T) truncated to 128 bits.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Folding {
    pub u1: RelaxedInstanceBytes,
    pub u2: StrictInstanceBytes,
    #[serde(with = "hexser::a65")]
    pub comm_t: [u8; 65],
}

impl Folding {
    pub fn digest(&self) -> [u8; 32] {
        let mut e = Enc::new("folding");
        self.u1.put(&mut e, "U1");
        e.field("U2.comm_W", &self.u2.comm_w).u32("U2.num_x", self.u2.x.len() as u32);
        for x in &self.u2.x {
            e.field("U2.x", x);
        }
        e.field("comm_T", &self.comm_t);
        e.digest()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlatCheckClaim {
    pub version: u32,
    #[serde(with = "hexser::a32")]
    pub tc_digest: [u8; 32],
    pub field: u8,
    #[serde(with = "hexser::a32")]
    pub session_id: [u8; 32],
    pub replay: ReplayDomain,
    pub statement: Statement,
    pub folding: Folding,
    pub instance: RelaxedInstanceBytes,
    #[serde(with = "hexser::a32")]
    pub root_w: [u8; 32],
    #[serde(with = "hexser::a32")]
    pub root_e: [u8; 32],
    #[serde(with = "hexser::a32")]
    pub root_trace_w: [u8; 32],
    #[serde(with = "hexser::a32")]
    pub root_trace_e: [u8; 32],
}

impl FlatCheckClaim {
    /// The exact bytes hashed into the claim id. For a fixed trusted configuration the layout is
    /// fixed: the garbled circuit rebuilds it from the claim's values.
    pub fn encode(&self) -> Enc {
        let mut e = Enc::new("claim");
        e.u32("version", self.version)
            .field("tc_digest", &self.tc_digest)
            .u8("field", self.field)
            .field("session_id", &self.session_id)
            .field("replay", &self.replay.digest())
            .field("statement", &self.statement.digest())
            .field("folding", &self.folding.digest());
        self.instance.put(&mut e, "U");
        e.field("root_W", &self.root_w).field("root_E", &self.root_e).field("root_trace_W", &self.root_trace_w).field("root_trace_E", &self.root_trace_e);
        e
    }
    pub fn id(&self) -> [u8; 32] {
        self.encode().digest()
    }
    pub fn root(&self, v: Vector) -> [u8; 32] {
        match v {
            Vector::W => self.root_w,
            Vector::E => self.root_e,
        }
    }
    pub fn trace_root(&self, v: Vector) -> [u8; 32] {
        match v {
            Vector::W => self.root_trace_w,
            Vector::E => self.root_trace_e,
        }
    }
    pub fn comm(&self, v: Vector) -> [u8; 65] {
        match v {
            Vector::W => self.instance.comm_w,
            Vector::E => self.instance.comm_e,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChallengeKind {
    /// Relaxed R1CS row `row` is violated by the committed (W, E, u, X).
    Row { row: u32 },
    /// The binding trace of `vec` does not start at (O, G_0).
    BindingStart { vec: Vector },
    /// Transition `step` -> `step + 1` of the binding trace of `vec` is wrong.
    BindingStep { vec: Vector, step: u32 },
    /// The last accumulator of `vec`'s binding trace is not the instance's commitment.
    BindingEnd { vec: Vector },
    /// Public-data check: the claim is malformed or U != fold(U1, U2, comm_T).
    Claim,
}

impl ChallengeKind {
    pub fn code(&self) -> (u8, u32, u8) {
        match *self {
            ChallengeKind::Row { row } => (1, row, 0),
            ChallengeKind::BindingStart { vec } => (2, 0, vec.byte()),
            ChallengeKind::BindingStep { vec, step } => (3, step, vec.byte()),
            ChallengeKind::BindingEnd { vec } => (4, 0, vec.byte()),
            ChallengeKind::Claim => (5, 0, 0),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlatCheckChallenge {
    pub version: u32,
    #[serde(with = "hexser::a32")]
    pub claim_id: [u8; 32],
    pub kind: ChallengeKind,
    /// x-only public key of the challenger.
    #[serde(with = "hexser::a32")]
    pub challenger: [u8; 32],
    #[serde(with = "hexser::a32")]
    pub nonce: [u8; 32],
    pub replay: ReplayDomain,
}

impl FlatCheckChallenge {
    pub fn encode(&self) -> Enc {
        let (k, idx, v) = self.kind.code();
        let mut e = Enc::new("challenge");
        e.u32("version", self.version)
            .field("claim_id", &self.claim_id)
            .u8("kind", k)
            .u32("index", idx)
            .u8("vec", v)
            .field("challenger", &self.challenger)
            .field("nonce", &self.nonce)
            .field("replay", &self.replay.digest());
        e
    }
    pub fn id(&self) -> [u8; 32] {
        self.encode().digest()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpeningJ {
    pub index: u32,
    #[serde(with = "hexser::pair64")]
    pub pair: [[u8; 64]; 2],
    #[serde(with = "hexser::v32")]
    pub reveals: Vec<[u8; 32]>,
}

impl From<&flatmerkle::Opening> for OpeningJ {
    fn from(o: &flatmerkle::Opening) -> Self {
        OpeningJ { index: o.index, pair: o.pair, reveals: o.reveals.clone() }
    }
}
impl From<&OpeningJ> for flatmerkle::Opening {
    fn from(o: &OpeningJ) -> Self {
        flatmerkle::Opening { index: o.index, pair: o.pair, reveals: o.reveals.clone() }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RowResponse {
    #[serde(with = "hexser::a32")]
    pub challenge_id: [u8; 32],
    #[serde(with = "hexser::bytes")]
    pub row_record: Vec<u8>,
    pub row_open: OpeningJ,
    /// One W opening per row-record slot, A slots then B then C. Only slots that are active
    /// (slot < nnz) and reference a W column are checked.
    pub terms: Vec<OpeningJ>,
    pub e_open: OpeningJ,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordOpen {
    #[serde(with = "hexser::bytes")]
    pub record: Vec<u8>,
    pub open: OpeningJ,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepResponse {
    #[serde(with = "hexser::a32")]
    pub challenge_id: [u8; 32],
    pub cur: RecordOpen,
    pub next: RecordOpen,
    pub scalar: OpeningJ,
    /// Generator j + 1 (the blinding generator at j + 1 = n); checked only at bit 255.
    pub gen: RecordOpen,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StartResponse {
    #[serde(with = "hexser::a32")]
    pub challenge_id: [u8; 32],
    pub first: RecordOpen,
    pub gen0: RecordOpen,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndResponse {
    #[serde(with = "hexser::a32")]
    pub challenge_id: [u8; 32],
    pub last: RecordOpen,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum FlatCheckResponse {
    Row(RowResponse),
    Step(StepResponse),
    Start(StartResponse),
    End(EndResponse),
}

impl FlatCheckResponse {
    pub fn challenge_id(&self) -> [u8; 32] {
        match self {
            FlatCheckResponse::Row(r) => r.challenge_id,
            FlatCheckResponse::Step(r) => r.challenge_id,
            FlatCheckResponse::Start(r) => r.challenge_id,
            FlatCheckResponse::End(r) => r.challenge_id,
        }
    }
}
