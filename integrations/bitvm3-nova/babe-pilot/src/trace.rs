//! Composition of an entire Boolean verifier into authenticated local checks.
//!
//! The compiler records the actual `CircuitContext` program, including free gates.
//! There is one scheduled check for every initial wire, every gate and every
//! required accepting output. A single indexed commitment to all wire values
//! supplies both ends of every dependency. Thus a producer and all of its
//! consumers refer to the same committed value, including across partitions.
//! If every scheduled check holds, induction over the single-assignment wire
//! indices fixes every value to the complete verifier's execution on its pinned
//! inputs. The terminal checks then require acceptance. With available committed
//! data, a rejecting execution or an inconsistent trace exposes a local fault.
//!
//! A program pin must be compiled independently from the intended complete
//! verifier, its key, shape and statement. Giving a native verifier's answer to
//! this module as an input does not compile that verifier. The optional M14
//! adapter calls the existing complete Boolean verifier directly. Compilation
//! limits abort before a pin or a partially covered claim can be returned.
//!
//! Publication verification establishes that all committed data was supplied to
//! this process. Durable delivery and a Bitcoin response deadline are separate
//! protocol obligations. The local predicate is always authenticated AND invalid;
//! an arbitrary malformed challenger opening cannot refute an honest claim.

use std::panic::{catch_unwind, panic_any, AssertUnwindSafe};

use anyhow::{ensure, Context, Result};
use garbled_snark_verifier::{
    circuit::{ExecuteMode, FromWires, WiresObject, FALSE_WIRE},
    CircuitContext, Gate, WireId,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::gates::{self as g, W};

pub type Digest = [u8; 32];
const RECORD_BYTES: usize = 26;
const INPUT: u8 = 0;
const GATE: u8 = 1;
const OUTPUT: u8 = 2;
const PROGRAM_TREE: u8 = 0;
const INPUT_TREE: u8 = 1;
const VALUE_TREE: u8 = 2;
const DOMAIN: &[u8] = b"babe/complete-boolean-trace/v1\0";

pub fn digest(bytes: &[u8]) -> Digest {
    Sha256::digest(bytes).into()
}

fn framed_hash(tag: u8, fields: &[&[u8]]) -> Digest {
    let mut h = Sha256::new();
    h.update(DOMAIN);
    h.update([tag]);
    for field in fields {
        h.update((field.len() as u64).to_le_bytes());
        h.update(field);
    }
    h.finalize().into()
}

/// Semantic pins supplied by the adapter, alongside the compiled program root.
/// `source` covers the verifier implementation/version; `parameters` covers its
/// key and shape; `statement` covers the complete expected public statement;
/// `input_schema` identifies the canonical proof-to-bit encoding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifierBinding {
    pub source: Digest,
    pub parameters: Digest,
    pub statement: Digest,
    pub input_schema: Digest,
}

impl VerifierBinding {
    pub fn id(&self) -> Digest {
        framed_hash(
            0,
            &[
                &self.source,
                &self.parameters,
                &self.statement,
                &self.input_schema,
            ],
        )
    }
}

/// Local resource policy. Raising these values never changes the relation or
/// permits a truncated program. The in-memory implementation has no implicit
/// claim to accommodate the multi-billion-wire M14 circuit.
#[derive(Clone, Copy, Debug)]
pub struct TraceLimits {
    pub max_input_bits: usize,
    pub max_gates: usize,
    pub max_outputs: usize,
    pub max_proof_bytes: usize,
}

impl Default for TraceLimits {
    fn default() -> Self {
        Self {
            max_input_bits: 16 * 1024 * 1024,
            max_gates: 100_000,
            max_outputs: 256,
            max_proof_bytes: 8 * 1024 * 1024,
        }
    }
}

/// One fixed scheduled check. Truth-table bit `(a | (b << 1))` gives a gate's
/// output. All eleven GSV gate families therefore share one exact predicate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckRecord {
    pub kind: u8,
    pub truth_table: u8,
    pub a: u64,
    pub b: u64,
    pub c: u64,
}

impl CheckRecord {
    pub fn to_bytes(&self) -> [u8; RECORD_BYTES] {
        let mut out = [0; RECORD_BYTES];
        out[0] = self.kind;
        out[1] = self.truth_table;
        out[2..10].copy_from_slice(&self.a.to_le_bytes());
        out[10..18].copy_from_slice(&self.b.to_le_bytes());
        out[18..26].copy_from_slice(&self.c.to_le_bytes());
        out
    }

    fn gate_value(&self, a: bool, b: bool) -> bool {
        self.truth_table & (1 << (u8::from(a) | (u8::from(b) << 1))) != 0
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceProgramPin {
    pub binding: VerifierBinding,
    pub program_root: Digest,
    pub input_count: u64,
    pub wire_count: u64,
    pub check_count: u64,
    pub output_count: u64,
    pub id: Digest,
}

impl TraceProgramPin {
    fn compute_id(&self) -> Digest {
        framed_hash(
            1,
            &[
                &self.binding.id(),
                &self.program_root,
                &self.input_count.to_le_bytes(),
                &self.wire_count.to_le_bytes(),
                &self.check_count.to_le_bytes(),
                &self.output_count.to_le_bytes(),
            ],
        )
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            self.input_count >= 2 && self.input_count <= self.wire_count,
            "invalid input count"
        );
        ensure!(self.output_count > 0, "missing verifier output");
        ensure!(
            self.wire_count.checked_add(self.output_count) == Some(self.check_count),
            "incomplete check coverage"
        );
        ensure!(
            self.check_count <= (1u64 << 48),
            "trace index exceeds supported range"
        );
        ensure!(self.id == self.compute_id(), "program pin digest mismatch");
        Ok(())
    }
}

#[derive(Debug)]
struct CompileAbort(&'static str);

/// Generic GSV backend used to compile the existing full verifier. Logical wire
/// handles are translated to topologically ordered single-assignment indices.
/// In-place writes and reads of unassigned wires fail closed.
pub struct TraceCompiler {
    mapping: Vec<Option<u64>>,
    records: Vec<CheckRecord>,
    inputs: usize,
    gates: usize,
    limits: TraceLimits,
}

impl TraceCompiler {
    fn resolve(&self, w: WireId) -> u64 {
        self.mapping
            .get(w.0)
            .and_then(|v| *v)
            .unwrap_or_else(|| panic_any(CompileAbort("read of unassigned or invalid wire")))
    }
}

impl CircuitContext for TraceCompiler {
    type Mode = ExecuteMode;

    fn issue_wire(&mut self) -> WireId {
        // A component may allocate its outputs before emitting the corresponding
        // gates. Cap those pending handles as well as the emitted instructions.
        if self.mapping.len()
            >= self
                .inputs
                .saturating_add(self.limits.max_gates)
                .saturating_add(1)
        {
            panic_any(CompileAbort("wire allocation limit reached"));
        }
        let w = WireId(self.mapping.len());
        self.mapping.push(None);
        w
    }

    fn add_gate(&mut self, gate: Gate) {
        if self.gates >= self.limits.max_gates {
            panic_any(CompileAbort("complete verifier exceeds gate limit"));
        }
        let a = self.resolve(gate.wire_a);
        let b = self.resolve(gate.wire_b);
        if self.mapping.get(gate.wire_c.0).is_none_or(Option::is_some) {
            panic_any(CompileAbort("gate output is invalid or assigned twice"));
        }
        let c = (self.inputs + self.gates) as u64;
        let mut truth_table = 0;
        for i in 0..4 {
            truth_table |= u8::from(gate.execute(i & 1 != 0, i & 2 != 0)) << i;
        }
        self.records.push(CheckRecord {
            kind: GATE,
            truth_table,
            a,
            b,
            c,
        });
        self.mapping[gate.wire_c.0] = Some(c);
        self.gates += 1;
    }

    fn with_named_child<I: WiresObject, O: FromWires>(
        &mut self,
        _key: [u8; 8],
        inputs: I,
        f: impl Fn(&mut Self, &I) -> O,
        arity: usize,
    ) -> O {
        for wire in inputs.to_wires_vec() {
            self.resolve(wire);
        }
        let result = f(self, &inputs);
        if result.to_wires_vec().len() != arity {
            panic_any(CompileAbort("component output arity mismatch"));
        }
        for wire in result.to_wires_vec() {
            self.resolve(wire);
        }
        result
    }
}

/// Only the compiler can construct this trusted schedule. A deserialized
/// operator-supplied schedule is never promoted to an independently pinned one.
pub struct TraceProgram {
    pin: TraceProgramPin,
    records: Vec<CheckRecord>,
    tree: MerkleTree,
    limits: TraceLimits,
}

impl TraceProgram {
    pub fn compile(
        binding: VerifierBinding,
        proof_input_bits: usize,
        limits: TraceLimits,
        build: impl FnOnce(&mut TraceCompiler, &[W]) -> Vec<W>,
    ) -> Result<Self> {
        ensure!(
            proof_input_bits <= limits.max_input_bits,
            "proof input limit exceeded"
        );
        ensure!(
            limits.max_outputs > 0 && limits.max_gates < (1usize << 48),
            "invalid compilation limits"
        );
        let inputs = proof_input_bits
            .checked_add(2)
            .context("input count overflow")?;
        let mut compiler = TraceCompiler {
            mapping: (0..inputs).map(|i| Some(i as u64)).collect(),
            records: (0..inputs)
                .map(|i| CheckRecord {
                    kind: INPUT,
                    truth_table: 0,
                    a: 0,
                    b: 0,
                    c: i as u64,
                })
                .collect(),
            inputs,
            gates: 0,
            limits,
        };
        let input_wires: Vec<W> = (2..inputs).map(WireId).collect();
        let outputs = catch_unwind(AssertUnwindSafe(|| build(&mut compiler, &input_wires)))
            .map_err(|payload| match payload.downcast::<CompileAbort>() {
                Ok(abort) => anyhow::anyhow!(abort.0),
                Err(_) => {
                    anyhow::anyhow!("verifier compilation panicked; no program was published")
                }
            })?;
        ensure!(
            !outputs.is_empty() && outputs.len() <= limits.max_outputs,
            "invalid verifier output count"
        );
        for wire in &outputs {
            let c = compiler
                .mapping
                .get(wire.0)
                .and_then(|v| *v)
                .context("unassigned verifier output")?;
            compiler.records.push(CheckRecord {
                kind: OUTPUT,
                truth_table: 0,
                a: 0,
                b: 0,
                c,
            });
        }
        let context = binding.id();
        let tree = MerkleTree::new(
            PROGRAM_TREE,
            context,
            compiler
                .records
                .iter()
                .map(|r| r.to_bytes().to_vec())
                .collect(),
        )?;
        let mut pin = TraceProgramPin {
            binding,
            program_root: tree.root(),
            input_count: inputs as u64,
            wire_count: (inputs + compiler.gates) as u64,
            check_count: compiler.records.len() as u64,
            output_count: outputs.len() as u64,
            id: [0; 32],
        };
        pin.id = pin.compute_id();
        pin.validate()?;
        Ok(Self {
            pin,
            records: compiler.records,
            tree,
            limits,
        })
    }

    pub fn pin(&self) -> &TraceProgramPin {
        &self.pin
    }
    pub fn checks(&self) -> &[CheckRecord] {
        &self.records
    }

    /// The adapter must compute `bits` with the pinned canonical proof encoder.
    /// Checking a native proof's Boolean answer and encoding that one bit would
    /// describe a different, incomplete program. The full M14 adapter passes
    /// `native::bits(full::items(proof))` after pinned shape validation.
    pub fn bind_inputs(
        &self,
        proof_bytes: &[u8],
        expected_proof_sha256: Digest,
        bits: &[bool],
    ) -> Result<PinnedInputs> {
        ensure!(
            proof_bytes.len() <= self.limits.max_proof_bytes,
            "proof byte limit exceeded"
        );
        ensure!(
            digest(proof_bytes) == expected_proof_sha256,
            "proof bytes differ from independent pin"
        );
        ensure!(
            bits.len() as u64 + 2 == self.pin.input_count,
            "canonical input width mismatch"
        );
        let mut values = Vec::with_capacity(bits.len() + 2);
        values.extend([false, true]);
        values.extend_from_slice(bits);
        let tree = value_tree(INPUT_TREE, self.pin.id, &values)?;
        Ok(PinnedInputs {
            program_id: self.pin.id,
            proof_sha256: expected_proof_sha256,
            proof_bytes: proof_bytes.to_vec(),
            values,
            tree,
        })
    }

    /// Execute the compiled Boolean instructions. A rejecting proof still has a
    /// complete execution trace; its output check is refutable.
    pub fn execute(&self, inputs: &PinnedInputs) -> Result<Vec<bool>> {
        ensure!(
            inputs.program_id == self.pin.id,
            "inputs belong to another program"
        );
        let mut values = inputs.values.clone();
        values.reserve(self.pin.wire_count as usize - values.len());
        for record in &self.records[self.pin.input_count as usize..self.pin.wire_count as usize] {
            values.push(record.gate_value(values[record.a as usize], values[record.b as usize]));
        }
        Ok(values)
    }
}

pub struct PinnedInputs {
    program_id: Digest,
    proof_sha256: Digest,
    proof_bytes: Vec<u8>,
    values: Vec<bool>,
    tree: MerkleTree,
}

impl PinnedInputs {
    pub fn root(&self) -> Digest {
        self.tree.root()
    }
    pub fn proof_sha256(&self) -> Digest {
        self.proof_sha256
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceClaim {
    pub session_id: Digest,
    pub program_id: Digest,
    pub proof_sha256: Digest,
    pub input_root: Digest,
    pub values_root: Digest,
    pub id: Digest,
}

impl TraceClaim {
    fn value_context(&self) -> Digest {
        framed_hash(
            2,
            &[
                &self.session_id,
                &self.program_id,
                &self.proof_sha256,
                &self.input_root,
            ],
        )
    }
    fn compute_id(&self) -> Digest {
        framed_hash(3, &[&self.value_context(), &self.values_root])
    }
}

/// Packed, complete data supplied by the operator. Its exact lengths come from
/// the independent program pin; unused high bits must be zero. A storage or wire
/// decoder must impose these limits before allocating untrusted vectors.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TracePublication {
    pub proof_bytes: Vec<u8>,
    pub input_bits: Vec<u8>,
    pub wire_values: Vec<u8>,
}

impl TracePublication {
    pub fn create(
        program: &TraceProgram,
        inputs: &PinnedInputs,
        session_id: Digest,
        values: &[bool],
    ) -> Result<(TraceClaim, Self)> {
        ensure!(
            inputs.program_id == program.pin.id,
            "input program mismatch"
        );
        ensure!(
            values.len() as u64 == program.pin.wire_count,
            "partial trace publication"
        );
        let mut claim = TraceClaim {
            session_id,
            program_id: program.pin.id,
            proof_sha256: inputs.proof_sha256,
            input_root: inputs.root(),
            values_root: [0; 32],
            id: [0; 32],
        };
        claim.values_root = value_tree(VALUE_TREE, claim.value_context(), values)?.root();
        claim.id = claim.compute_id();
        Ok((
            claim,
            Self {
                proof_bytes: inputs.proof_bytes.clone(),
                input_bits: pack(&inputs.values),
                wire_values: pack(values),
            },
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceDisputeSpec {
    program: TraceProgramPin,
    claim: TraceClaim,
}

impl TraceDisputeSpec {
    /// Check a decoded specification's shape and internal digests. The caller
    /// must still compare it with its independently agreed specification before
    /// accepting a setup certificate or selecting a funded dispute.
    pub fn validate(&self) -> Result<()> {
        self.program.validate()?;
        ensure!(
            self.claim.program_id == self.program.id,
            "claim uses another program"
        );
        ensure!(
            self.claim.id == self.claim.compute_id(),
            "claim digest mismatch"
        );
        Ok(())
    }
    pub fn new(
        program: &TraceProgram,
        inputs: &PinnedInputs,
        expected_session: Digest,
        claim: &TraceClaim,
    ) -> Result<Self> {
        program.pin.validate()?;
        ensure!(
            claim.program_id == program.pin.id && inputs.program_id == program.pin.id,
            "wrong program pin"
        );
        ensure!(claim.session_id == expected_session, "wrong trace session");
        ensure!(
            claim.proof_sha256 == inputs.proof_sha256 && claim.input_root == inputs.root(),
            "wrong proof or encoded inputs"
        );
        ensure!(claim.id == claim.compute_id(), "claim digest mismatch");
        let spec = Self {
            program: program.pin.clone(),
            claim: claim.clone(),
        };
        spec.validate()?;
        Ok(spec)
    }

    pub fn program(&self) -> &TraceProgramPin {
        &self.program
    }
    pub fn claim(&self) -> &TraceClaim {
        &self.claim
    }
    pub fn circuit_id(&self) -> Digest {
        framed_hash(4, &[&self.program.id, &self.claim.id])
    }
    pub fn input_bits(&self) -> usize {
        64 + RECORD_BYTES * 8
            + depth(self.program.check_count) * 256
            + 3 * (1 + depth(self.program.wire_count) * 256)
            + 1
            + depth(self.program.input_count) * 256
    }

    pub fn native_refutes(&self, response: &TraceResponse) -> bool {
        let r = &response.record;
        if !verify_opening(
            PROGRAM_TREE,
            self.program.binding.id(),
            self.program.program_root,
            self.program.check_count,
            response.check_index,
            &r.to_bytes(),
            &response.program_path,
        ) || !verify_value(self, r.c, &response.c)
        {
            return false;
        }
        match r.kind {
            INPUT => {
                verify_opening(
                    INPUT_TREE,
                    self.program.id,
                    self.claim.input_root,
                    self.program.input_count,
                    r.c,
                    &[u8::from(response.initial.value)],
                    &response.initial.path,
                ) && response.c.value != response.initial.value
            }
            GATE => {
                verify_value(self, r.a, &response.a)
                    && verify_value(self, r.b, &response.b)
                    && response.c.value != r.gate_value(response.a.value, response.b.value)
            }
            OUTPUT => !response.c.value,
            _ => false,
        }
    }
}

/// Availability capability. Constructing it checks every byte and every
/// committed wire, but deliberately permits arithmetic faults for challenges.
pub struct AvailableTrace {
    spec: TraceDisputeSpec,
    values: Vec<bool>,
    value_tree: MerkleTree,
    initial: Vec<bool>,
    initial_tree: MerkleTree,
}

pub fn verify_publication(
    program: &TraceProgram,
    spec: &TraceDisputeSpec,
    publication: &TracePublication,
) -> Result<AvailableTrace> {
    spec.validate()?;
    ensure!(
        program.pin == spec.program,
        "publication program differs from independent pin"
    );
    ensure!(
        publication.proof_bytes.len() <= program.limits.max_proof_bytes,
        "proof publication too large"
    );
    ensure!(
        digest(&publication.proof_bytes) == spec.claim.proof_sha256,
        "missing or changed proof publication"
    );
    let initial = unpack(&publication.input_bits, program.pin.input_count as usize)?;
    let values = unpack(&publication.wire_values, program.pin.wire_count as usize)?;
    let initial_tree = value_tree(INPUT_TREE, program.pin.id, &initial)?;
    ensure!(
        initial_tree.root() == spec.claim.input_root,
        "changed canonical input publication"
    );
    let value_tree = value_tree(VALUE_TREE, spec.claim.value_context(), &values)?;
    ensure!(
        value_tree.root() == spec.claim.values_root,
        "missing or changed trace data"
    );
    Ok(AvailableTrace {
        spec: spec.clone(),
        values,
        value_tree,
        initial,
        initial_tree,
    })
}

impl AvailableTrace {
    pub fn response(&self, program: &TraceProgram, check_index: u64) -> Result<TraceResponse> {
        ensure!(
            program.pin == self.spec.program,
            "response program mismatch"
        );
        let record = program
            .records
            .get(check_index as usize)
            .context("challenge index out of range")?
            .clone();
        let value = |index: u64| -> Result<ValueOpening> {
            Ok(ValueOpening {
                value: *self
                    .values
                    .get(index as usize)
                    .context("invalid operand index")?,
                path: self.value_tree.open(index)?,
            })
        };
        let initial_index = if record.kind == INPUT { record.c } else { 0 };
        Ok(TraceResponse {
            check_index,
            program_path: program.tree.open(check_index)?,
            a: value(record.a)?,
            b: value(record.b)?,
            c: value(record.c)?,
            initial: ValueOpening {
                value: self.initial[initial_index as usize],
                path: self.initial_tree.open(initial_index)?,
            },
            record,
        })
    }

    pub fn first_refutation(&self, program: &TraceProgram) -> Result<Option<TraceResponse>> {
        ensure!(program.pin == self.spec.program, "search program mismatch");
        for (index, record) in program.records.iter().enumerate() {
            let c = self.values[record.c as usize];
            let valid = match record.kind {
                INPUT => c == self.initial[record.c as usize],
                GATE => {
                    c == record.gate_value(
                        self.values[record.a as usize],
                        self.values[record.b as usize],
                    )
                }
                OUTPUT => c,
                _ => false,
            };
            if !valid {
                return self.response(program, index as u64).map(Some);
            }
        }
        Ok(None)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValueOpening {
    pub value: bool,
    pub path: Vec<Digest>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TraceResponse {
    pub check_index: u64,
    pub record: CheckRecord,
    pub program_path: Vec<Digest>,
    pub a: ValueOpening,
    pub b: ValueOpening,
    pub c: ValueOpening,
    pub initial: ValueOpening,
}

impl TraceResponse {
    pub fn to_bits(&self, spec: &TraceDisputeSpec) -> Result<Vec<bool>> {
        ensure!(
            self.program_path.len() == depth(spec.program.check_count),
            "program path length"
        );
        for value in [&self.a, &self.b, &self.c] {
            ensure!(
                value.path.len() == depth(spec.program.wire_count),
                "wire path length"
            );
        }
        ensure!(
            self.initial.path.len() == depth(spec.program.input_count),
            "initial input path length"
        );
        let mut bits = g::bytes_to_bits_le(&self.check_index.to_le_bytes());
        bits.extend(g::bytes_to_bits_le(&self.record.to_bytes()));
        for node in &self.program_path {
            bits.extend(g::bytes_to_bits_le(node));
        }
        for value in [&self.a, &self.b, &self.c, &self.initial] {
            bits.push(value.value);
            for node in &value.path {
                bits.extend(g::bytes_to_bits_le(node));
            }
        }
        ensure!(bits.len() == spec.input_bits(), "response width mismatch");
        Ok(bits)
    }
}

fn verify_value(spec: &TraceDisputeSpec, index: u64, value: &ValueOpening) -> bool {
    verify_opening(
        VALUE_TREE,
        spec.claim.value_context(),
        spec.claim.values_root,
        spec.program.wire_count,
        index,
        &[u8::from(value.value)],
        &value.path,
    )
}

fn depth(count: u64) -> usize {
    if count <= 1 {
        0
    } else {
        (64 - (count - 1).leading_zeros()) as usize
    }
}

fn leaf_prefix(tree: u8, context: Digest) -> Vec<u8> {
    let mut v = DOMAIN.to_vec();
    v.extend([10, tree]);
    v.extend(context);
    v
}
fn node_prefix(tree: u8, context: Digest, level: usize) -> Vec<u8> {
    let mut v = DOMAIN.to_vec();
    v.extend([11, tree, level as u8]);
    v.extend(context);
    v
}
fn leaf_hash(tree: u8, context: Digest, index: u64, payload: &[u8]) -> Digest {
    let mut bytes = leaf_prefix(tree, context);
    bytes.extend(index.to_le_bytes());
    bytes.extend(payload);
    digest(&bytes)
}
fn node_hash(tree: u8, context: Digest, level: usize, left: Digest, right: Digest) -> Digest {
    let mut bytes = node_prefix(tree, context, level);
    bytes.extend(left);
    bytes.extend(right);
    digest(&bytes)
}

struct MerkleTree {
    count: u64,
    levels: Vec<Vec<Digest>>,
}
impl MerkleTree {
    fn new(tree: u8, context: Digest, payloads: Vec<Vec<u8>>) -> Result<Self> {
        ensure!(!payloads.is_empty(), "empty commitment");
        let count = payloads.len();
        let size = count
            .checked_next_power_of_two()
            .context("commitment size overflow")?;
        let mut leaves: Vec<Digest> = payloads
            .iter()
            .enumerate()
            .map(|(i, p)| leaf_hash(tree, context, i as u64, p))
            .collect();
        leaves.reserve(size - count);
        for i in count..size {
            leaves.push(leaf_hash(tree, context, i as u64, &[0xff]));
        }
        let mut levels = vec![leaves];
        while levels.last().expect("nonempty tree").len() > 1 {
            let level = levels.len() - 1;
            levels.push(
                levels[level]
                    .chunks_exact(2)
                    .map(|v| node_hash(tree, context, level, v[0], v[1]))
                    .collect(),
            );
        }
        Ok(Self {
            count: count as u64,
            levels,
        })
    }
    fn root(&self) -> Digest {
        self.levels.last().expect("nonempty tree")[0]
    }
    fn open(&self, index: u64) -> Result<Vec<Digest>> {
        ensure!(index < self.count, "opening index out of range");
        Ok((0..self.levels.len() - 1)
            .map(|level| self.levels[level][((index >> level) as usize) ^ 1])
            .collect())
    }
}

fn value_tree(tree: u8, context: Digest, values: &[bool]) -> Result<MerkleTree> {
    MerkleTree::new(
        tree,
        context,
        values.iter().map(|v| vec![u8::from(*v)]).collect(),
    )
}

fn verify_opening(
    tree: u8,
    context: Digest,
    root: Digest,
    count: u64,
    index: u64,
    payload: &[u8],
    path: &[Digest],
) -> bool {
    if index >= count || path.len() != depth(count) {
        return false;
    }
    let mut h = leaf_hash(tree, context, index, payload);
    for (level, sibling) in path.iter().enumerate() {
        h = if (index >> level) & 1 == 0 {
            node_hash(tree, context, level, h, *sibling)
        } else {
            node_hash(tree, context, level, *sibling, h)
        };
    }
    h == root
}

fn pack(bits: &[bool]) -> Vec<u8> {
    let mut bytes = vec![0; bits.len().div_ceil(8)];
    for (i, bit) in bits.iter().enumerate() {
        bytes[i / 8] |= u8::from(*bit) << (i % 8);
    }
    bytes
}
fn unpack(bytes: &[u8], count: usize) -> Result<Vec<bool>> {
    ensure!(
        bytes.len() == count.div_ceil(8),
        "partial or oversized trace publication"
    );
    if !count.is_multiple_of(8) {
        ensure!(
            bytes.last().is_none_or(|b| *b >> (count % 8) == 0),
            "noncanonical packed padding"
        );
    }
    Ok((0..count)
        .map(|i| bytes[i / 8] >> (i % 8) & 1 != 0)
        .collect())
}

struct TreeAnchor {
    tree: u8,
    context: Digest,
    root: Digest,
    count: u64,
}

fn boolean_opening<C: CircuitContext>(
    c: &mut C,
    anchor: &TreeAnchor,
    index: &[W],
    payload: &[W],
    path: &[W],
) -> W {
    let mut msg = g::const_bytes_le(&leaf_prefix(anchor.tree, anchor.context));
    msg.extend(index);
    msg.extend(payload);
    let mut h = g::sha256_bytes(c, &msg);
    for (level, sibling) in path.chunks_exact(256).enumerate() {
        let left = g::mux_vec(c, index[level], &h, sibling);
        let right = g::mux_vec(c, index[level], sibling, &h);
        let mut msg = g::const_bytes_le(&node_prefix(anchor.tree, anchor.context, level));
        msg.extend(left);
        msg.extend(right);
        h = g::sha256_bytes(c, &msg);
    }
    let (_, ge) = g::sub(c, index, &g::const_bits_le(anchor.count as u128, 64), 64);
    let in_range = g::not(c, ge);
    let root_ok = g::eq_vec(c, &h, &g::const_bytes_le(&anchor.root));
    g::and(c, in_range, root_ok)
}

/// Universal authenticated local predicate. All opcode dispatch, SHA-256 paths,
/// positions and operand equalities are inside the Boolean circuit.
pub fn eval_trace_dispute_circuit<C: CircuitContext>(
    c: &mut C,
    spec: &TraceDisputeSpec,
    wires: &[W],
) -> Vec<W> {
    assert_eq!(
        wires.len(),
        spec.input_bits(),
        "trace response circuit width"
    );
    let mut at = 0;
    let mut take = |n: usize| {
        let start = at;
        at += n;
        &wires[start..at]
    };
    let check_index = take(64);
    let record = take(RECORD_BYTES * 8);
    let program_path = take(depth(spec.program.check_count) * 256);
    let mut value_bits = Vec::new();
    let mut value_paths = Vec::new();
    for _ in 0..3 {
        value_bits.push(take(1)[0]);
        value_paths.push(take(depth(spec.program.wire_count) * 256));
    }
    let initial_bit = take(1)[0];
    let initial_path = take(depth(spec.program.input_count) * 256);
    let kind = &record[0..8];
    let table = &record[8..16];
    let indices = [&record[16..80], &record[80..144], &record[144..208]];
    let program_ok = boolean_opening(
        c,
        &TreeAnchor {
            tree: PROGRAM_TREE,
            context: spec.program.binding.id(),
            root: spec.program.program_root,
            count: spec.program.check_count,
        },
        check_index,
        record,
        program_path,
    );
    let mut value_ok = Vec::new();
    for (i, index) in indices.iter().enumerate() {
        let mut payload = vec![FALSE_WIRE; 8];
        payload[0] = value_bits[i];
        value_ok.push(boolean_opening(
            c,
            &TreeAnchor {
                tree: VALUE_TREE,
                context: spec.claim.value_context(),
                root: spec.claim.values_root,
                count: spec.program.wire_count,
            },
            index,
            &payload,
            value_paths[i],
        ));
    }
    let mut initial_payload = vec![FALSE_WIRE; 8];
    initial_payload[0] = initial_bit;
    let initial_ok = boolean_opening(
        c,
        &TreeAnchor {
            tree: INPUT_TREE,
            context: spec.program.id,
            root: spec.claim.input_root,
            count: spec.program.input_count,
        },
        indices[2],
        &initial_payload,
        initial_path,
    );
    let is_input = g::eq_vec(c, kind, &g::const_bits_le(INPUT as u128, 8));
    let is_gate = g::eq_vec(c, kind, &g::const_bits_le(GATE as u128, 8));
    let is_output = g::eq_vec(c, kind, &g::const_bits_le(OUTPUT as u128, 8));
    let same_input = g::eq_bit(c, value_bits[2], initial_bit);
    let low = g::mux(c, value_bits[0], table[0], table[1]);
    let high = g::mux(c, value_bits[0], table[2], table[3]);
    let evaluated = g::mux(c, value_bits[1], low, high);
    let same_gate = g::eq_bit(c, value_bits[2], evaluated);
    let input_bad = g::not(c, same_input);
    let gate_bad = g::not(c, same_gate);
    let output_bad = g::not(c, value_bits[2]);
    let input_refute = g::all_true(c, &[is_input, initial_ok, input_bad]);
    let gate_refute = g::all_true(c, &[is_gate, value_ok[0], value_ok[1], gate_bad]);
    let output_refute = g::and(c, is_output, output_bad);
    let either = g::or(c, input_refute, gate_refute);
    let violation = g::or(c, either, output_refute);
    vec![g::all_true(c, &[program_ok, value_ok[2], violation])]
}

/// Entry point for the existing complete SP1-wrap verifier of the Nova proof.
/// This preserves the wrapped statement and the M14 Boolean implementation. It
/// supplies no separate direct-Nova verifier and performs no new Nova proving.
#[cfg(feature = "m14-trace")]
pub mod m14 {
    use super::*;
    use m13_verify::FinalStatement;
    use m14_e2e::{full, native};

    /// Compile all of `full::final_verifier`, with a caller-selected resource
    /// cap. Reference proof, challenged proof and expected statement hashes
    /// must come from the independent application/contract configuration.
    /// Native cryptographic acceptance is never an authorization shortcut.
    pub fn compile(
        reference_bytes: &[u8],
        expected_reference_sha256: Digest,
        proof_bytes: &[u8],
        expected_proof_sha256: Digest,
        statement_bytes: &[u8],
        expected_statement_sha256: Digest,
        limits: TraceLimits,
    ) -> Result<(TraceProgram, PinnedInputs)> {
        ensure!(
            reference_bytes.len() <= limits.max_proof_bytes
                && proof_bytes.len() <= limits.max_proof_bytes,
            "M14 proof byte limit exceeded"
        );
        ensure!(
            statement_bytes.len() <= 16 * 1024,
            "M14 statement byte limit exceeded"
        );
        ensure!(
            digest(reference_bytes) == expected_reference_sha256,
            "reference proof pin mismatch"
        );
        ensure!(
            digest(proof_bytes) == expected_proof_sha256,
            "challenged proof pin mismatch"
        );
        ensure!(
            digest(statement_bytes) == expected_statement_sha256,
            "public statement pin mismatch"
        );
        let reference = native::try_decode(reference_bytes).context("decode pinned reference")?;
        let proof = native::try_decode(proof_bytes).context("decode challenged proof")?;
        native::validate_proof_shape(&reference, &proof)
            .context("challenged proof differs from pinned verifier shape/key")?;
        let statement: FinalStatement =
            serde_json::from_slice(statement_bytes).context("decode pinned final statement")?;
        let known = full::Known::try_new(&reference, &statement)?;
        let bits = native::bits(&full::items(&proof));
        // The code pin covers this adapter plus the actual source of every
        // M14 Boolean stage. The independently compiled instruction root also
        // binds all transitive gadget behavior and generated AIR constraints.
        let source = framed_hash(20, &[
            b"M14 complete final verifier / SP1 6.9.0 / transcript v2 / GSV af374b4a5bb5a805ecaea749c61ff446986e8f10",
            include_bytes!("../../m14/e2e/src/full.rs"),
            include_bytes!("../../m14/e2e/src/verifier.rs"),
            include_bytes!("../../m14/e2e/src/pcs.rs"),
            include_bytes!("../../m14/e2e/src/native.rs"),
            include_bytes!("trace.rs"),
        ]);
        let binding = VerifierBinding {
            source,
            parameters: framed_hash(21, &[&expected_reference_sha256, &m13_verify::vk_sha256_bytes(&reference.vk)]),
            statement: expected_statement_sha256,
            input_schema: digest(b"m14_e2e::native::bits(full::items(proof)); pinned shape; canonical fixed-int bincode v2; little-endian bits"),
        };
        let program = TraceProgram::compile(binding, bits.len(), limits, |c, w| {
            vec![full::final_verifier(c, &known, w)]
        })
        .context("complete M14 trace compilation failed; no partial program or claim is usable")?;
        let inputs = program.bind_inputs(proof_bytes, expected_proof_sha256, &bits)?;
        Ok((program, inputs))
    }
}
