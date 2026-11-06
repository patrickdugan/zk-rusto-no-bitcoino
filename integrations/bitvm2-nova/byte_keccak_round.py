"""Hosted optional BYTE Keccak round with natural terminal output ports.

The existing Boolean round remains unchanged. Each new gate has one fresh BYTE
output and derives any bits inside byte-v1 Script. Rho/Pi byte-aligned routing
reuses public wire references, never equal assignment values. Final Chi wires,
or fresh Iota wires where the public mask is nonzero, ARE the200 outputs; there
are no output copies or zero anchors. Sealed source maps identify each actual
producer and give BYTE boundaries their own global namespace.

This is exactly one permutation round. No sponge input, padding, absorption,
squeeze, transcript, proof, production assertion or transaction is verified.
"""
from dataclasses import dataclass
from hashlib import sha256
import json
import os
import sys
from types import MappingProxyType

from byte_kernels import BYTE, KINDS, ByteConstraint, ByteProgram, ByteTraceBuilder
from keccak_trace import (RHO, ROUND_CONSTANTS, keccak_f1600_round,
                          state_from_bytes, state_to_bytes)
from trace import ID, MAX_WORDS, ROLES
from wots_graph import GraphSpec

SCHEMA = 'bitvm2-nova-byte-keccak-round/v1'
MAP_SCHEMA = 'bitvm2-nova-byte-keccak-round-maps/v1'
SOURCE_DOMAIN = b'BITVM2-NOVA/BYTE-KECCAK-ROUND/v1\x00'
STATE_BYTES, BASE_GATES = 200, 1216
FALSE_FLAGS = ('full_permutation_verified', 'full_permutation_verified_in_script',
    'full_hash_verified', 'hash_verified', 'padding_bound_in_script',
    'absorption_bound_in_script', 'squeeze_bound_in_script', 'transcript_verified',
    'nova_transcript_verified', 'proof_verified', 'bitvm2_script_verified',
    'production_assertion_binding', 'bitcoin_transaction_graph')


def _hosted_guard():
    if (os.environ.get('GITHUB_ACTIONS') != 'true'
            or os.environ.get('RUNNER_OS') != 'Linux' or sys.platform != 'linux'):
        raise ValueError('BYTE Keccak round construction/binding is hosted GitHub Linux only')


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def _integer(value, low, high, label):
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f'canonical {label} required')
    return value


def _round(round_index):
    return _integer(round_index, 0, 23, 'round index0..23')


def round_constant_bytes(round_index):
    """Pure eight little-endian public Iota bytes; no graph construction."""
    return ROUND_CONSTANTS[_round(round_index)].to_bytes(8, 'little')


def byte_rotation_sources(byte_index, shift):
    """Pure LE64 ROL routing: return(a_index,b_index,residual_shift).

    For shift=8*q+r, out[j]=((src[j-q]<<r)&255)+(src[j-q-1]>>(8-r)).
    r=0 routes only a; the returned b=(a-1)%8 remains defined but unused.
    """
    _integer(byte_index, 0, 7, 'lane byte index0..7')
    _integer(shift, 0, 63, 'lane rotation0..63')
    quotient, residual = divmod(shift, 8)
    return ((byte_index-quotient) % 8, (byte_index-quotient-1) % 8, residual)


def pi_destination(lane):
    """Pure source x+5*y -> destination y+5*((2*x+3*y)%5)."""
    _integer(lane, 0, 24, 'source lane0..24')
    x, y = lane % 5, lane//5
    return y+5*((2*x+3*y) % 5)


def input_wire_names():
    return tuple(f'input/l{lane}/byte{j}' for lane in range(25) for j in range(8))


def output_wire_names(round_index):
    masks = round_constant_bytes(round_index)
    return tuple(f'iota/byte{j}' if lane == 0 and masks[j]
                 else f'chi/out/l{lane}/byte{j}' for lane in range(25) for j in range(8))


def global_word_ids(round_index, words, inputs, outputs):
    """Pure bounded map validation; this cannot construct a sealed round.

    The exact ordered boundary names are normative. BYTE identities are distinct
    from the older Boolean state/round names, so different decoder bounds never
    silently share a WOTS key.
    """
    r = _round(round_index)
    if (type(words) is not tuple or not 0 < len(words) <= MAX_WORDS
            or type(inputs) is not tuple or type(outputs) is not tuple
            or inputs != input_wire_names() or outputs != output_wire_names(r)):
        raise ValueError('immutable exact BYTE boundary ports and bounded words required')
    names = []
    for word in words:
        if (type(word) is not tuple or len(word) != 2 or type(word[0]) is not str
                or not ID.fullmatch(word[0]) or type(word[1]) is not int or word[1] != BYTE):
            raise ValueError('unique canonical BYTE word declarations required')
        names.append(word[0])
    if (len(set(names)) != len(names) or len(set(inputs)) != STATE_BYTES
            or len(set(outputs)) != STATE_BYTES or set(inputs) & set(outputs)
            or not set(inputs+outputs) <= set(names)):
        raise ValueError('distinct input/output boundaries must exist and never alias')
    incoming = {word: index for index, word in enumerate(inputs)}
    outgoing = {word: index for index, word in enumerate(outputs)}
    result = []
    for name in names:
        if name in incoming:
            slot = incoming[name]
            global_id = f'byte-state/{r}/l{slot//8}/byte{slot%8}'
        elif name in outgoing:
            slot = outgoing[name]
            global_id = f'byte-state/{r+1}/l{slot//8}/byte{slot%8}'
        else:
            global_id = f'byte-round/{r}/{name}'
        if not ID.fullmatch(global_id):
            raise ValueError('derived BYTE global identity exceeds existing identifier cap')
        result.append(global_id)
    if len(set(result)) != len(result):
        raise ValueError('BYTE global map must be injective')
    return tuple(result)


def _parameters(round_index, context, role, operation_id):
    _round(round_index)
    if (type(context) is not bytes or len(context) != 32
            or type(role) is not str or role not in ROLES
            or type(operation_id) is not str or not ID.fullmatch(operation_id)
            or not ID.fullmatch(f'{operation_id}/round/{round_index}')):
        raise ValueError('explicit round role/operation/32-byte immutable context required')


def _state_bytes(value, label):
    if type(value) is not bytes or len(value) != STATE_BYTES:
        raise ValueError(f'exact immutable200-byte {label} required')
    return value


def _validate_ssa(program, inputs, outputs):
    """Every post-input word is one actual gate output; endpoints are terminal."""
    if type(program) is not ByteProgram or program.fields:
        raise ValueError('fresh BYTE-only round program required')
    declared = tuple(word for word, _ in program.words)
    if (declared[:STATE_BYTES] != inputs or len(set(declared)) != len(declared)
            or any(type(bound) is not int or bound != BYTE for _, bound in program.words)):
        raise ValueError('BYTE SSA input/declaration partition mismatch')
    known, produced, consumed, order = set(inputs), {}, set(), list(inputs)
    for ordinal, constraint in enumerate(program.constraints):
        if (type(constraint) is not ByteConstraint or constraint.kind not in KINDS
                or len(constraint.wires) not in (2, 3)):
            raise ValueError('BYTE round gate kind/arity mismatch')
        out = constraint.wires[-1]
        if out in known or not set(constraint.wires[:-1]) <= known:
            raise ValueError('each BYTE gate needs defined inputs and one fresh output')
        produced[out] = ordinal
        consumed.update(constraint.wires[:-1])
        known.add(out)
        order.append(out)
    if (tuple(order) != declared or set(outputs) != set(produced)-consumed
            or len(set(outputs)) != STATE_BYTES or set(inputs) & set(outputs)):
        raise ValueError('natural outputs must be exactly200 distinct terminal gate producers')
    return tuple(produced[word] for word in outputs)


def _build(round_index, initial_state, *, context, role, operation_id, claimed_output=None):
    _hosted_guard()  # Protect private regeneration as well as public entrypoints.
    _parameters(round_index, context, role, operation_id)
    initial = _state_bytes(initial_state, 'initial state')
    if claimed_output is not None:
        _state_bytes(claimed_output, 'claimed output')
    # Standard Keccak RCs repeat (notably rounds5 and22), so the RC arguments
    # alone cannot bind the public Program/fixed-opening identity to its round.
    # Keep the caller prefix separate and include the explicit round below.
    program_operation_id = f'{operation_id}/round/{round_index}'
    builder = ByteTraceBuilder(role, program_operation_id, context)
    inputs = input_wire_names()
    a = [[builder.byte(inputs[8*lane+j], initial[8*lane+j]) for j in range(8)]
         for lane in range(25)]
    c = [[None]*8 for _ in range(5)]
    for x in range(5):
        for j in range(8):
            current = a[x][j]
            for y in range(1, 5):
                current = builder.apply('byte_xor', f'theta/c/x{x}/byte{j}/step{y}',
                                        current, a[x+5*y][j])
            c[x][j] = current
    rotated = [[builder.apply('byte_rol', f'theta/d/rot/x{x}/byte{j}',
                   c[(x+1) % 5][j], c[(x+1) % 5][(j-1) % 8], argument=(1,))
                for j in range(8)] for x in range(5)]
    d = [[builder.apply('byte_xor', f'theta/d/x{x}/byte{j}', c[(x-1) % 5][j], rotated[x][j])
          for j in range(8)] for x in range(5)]
    t = [[builder.apply('byte_xor', f'theta/t/l{lane}/byte{j}', a[lane][j], d[lane % 5][j])
          for j in range(8)] for lane in range(25)]
    b = [[None]*8 for _ in range(25)]
    rho_count = 0
    for lane in range(25):
        shift = RHO[lane//5][lane % 5]
        target = pi_destination(lane)
        for j in range(8):
            low, high, residual = byte_rotation_sources(j, shift)
            word = t[lane][low]
            if residual:  # Public RHO offset only, never a witness value.
                word = builder.apply('byte_rol', f'rho/l{lane}/byte{j}',
                                     word, t[lane][high], argument=(residual,))
                rho_count += 1
            b[target][j] = word
    if rho_count != 176 or len({word for lane in b for word in lane}) != STATE_BYTES:
        raise ValueError('public Rho/Pi routing must preserve200 distinct BYTE references')
    negated = [[builder.apply('byte_not', f'chi/not/l{lane}/byte{j}',
                              b[(lane % 5+1) % 5+5*(lane//5)][j])
                for j in range(8)] for lane in range(25)]
    gated = [[builder.apply('byte_and', f'chi/and/l{lane}/byte{j}', negated[lane][j],
                            b[(lane % 5+2) % 5+5*(lane//5)][j])
              for j in range(8)] for lane in range(25)]
    out = [[builder.apply('byte_xor', f'chi/out/l{lane}/byte{j}', b[lane][j], gated[lane][j])
            for j in range(8)] for lane in range(25)]
    masks = round_constant_bytes(round_index)
    for j, mask in enumerate(masks):
        if mask:  # Public round constant only; zero masks introduce no gate.
            out[0][j] = builder.apply('byte_xor_const', f'iota/byte{j}', out[0][j], argument=(mask,))
    outputs = tuple(word for lane in out for word in lane)
    if outputs != output_wire_names(round_index):
        raise ValueError('natural Chi/Iota endpoints differ from public round masks')
    program, assignment = builder.finish()
    producer_ordinals = _validate_ssa(program, inputs, outputs)
    reference = state_to_bytes(keccak_f1600_round(state_from_bytes(initial), round_index))
    if bytes(assignment[word] for word in outputs) != reference:
        raise ValueError('fresh BYTE round differs from independent word-level reference')
    if claimed_output is not None:
        for word, value in zip(outputs, claimed_output, strict=True):
            assignment[word] = value
    program._admit(assignment)
    spec = GraphSpec.from_program(program)
    count = BASE_GATES+sum(mask != 0 for mask in masks)
    if (len(program.constraints) != count or len(spec.leaves) != count
            or len(program.words) != STATE_BYTES+count or spec.field_leaves
            or any(leaf.kind not in KINDS for leaf in spec.leaves)):
        raise ValueError('BYTE round census/coverage changed or copy/constant gate introduced')
    global_ids = global_word_ids(round_index, program.words, inputs, outputs)
    indices = {word: index for index, (word, _) in enumerate(program.words)}
    maps = dict(schema=MAP_SCHEMA, round_index=round_index,
        input_indices=tuple(indices[word] for word in inputs),
        output_indices=tuple(indices[word] for word in outputs),
        producer_ordinals=producer_ordinals, global_ids=global_ids,
        global_ids_sha256=sha256(_canonical(list(global_ids))).hexdigest(),
        phase_counts=dict(theta_c=160, theta_d_rot=40, theta_d_xor=40,
            theta_mix=200, rho=176, chi_not=200, chi_and=200, chi_xor=200,
            iota=sum(mask != 0 for mask in masks)))
    manifest = dict(schema=SCHEMA, round_index=round_index, context=context.hex(), role=role,
        operation_id=operation_id, program_operation_id=program_operation_id,
        program_sha256=program.digest().hex(),
        catalogue_id=spec.digest().hex(), round_constant_le=masks.hex(),
        input_encoding='25lanes(x+5*y),8bytesLEperlane',
        output_encoding='natural terminal Chi/Iota producer words; no copies',
        inputs=inputs, outputs=outputs, source_maps=maps,
        scope='one BYTE Keccak round; no sponge, transcript, proof or production assertion')
    return program, spec, assignment, reference, inputs, outputs, producer_ordinals, global_ids, manifest


def _make(cls, **fields):
    result = object.__new__(cls)
    for name, value in fields.items():
        object.__setattr__(result, name, value)
    return result


@dataclass(frozen=True, init=False)
class ByteKeccakRoundBinding:
    round: object
    program: ByteProgram
    spec: GraphSpec
    initial_state: bytes
    reference_output: bytes
    output_state: bytes
    _assignment: tuple

    def __init__(self, *args, **kwargs):
        raise TypeError('bind through the sealed BYTE round factory')

    @property
    def assignment(self):
        return dict(self._assignment)

    def summary(self):
        result = dict(round_index=self.round.round_index,
            source_sha256=self.round.source_sha256.hex(),
            program_operation_id=self.program.operation_id,
            round_binding_constructed=True, reference_matches=self.output_state == self.reference_output,
            words=len(self.program.words), leaves=len(self.spec.leaves))
        result.update({flag: False for flag in FALSE_FLAGS})
        return result


@dataclass(frozen=True, init=False)
class ByteKeccakRound:
    round_index: int
    context: bytes
    role: str
    operation_id: str
    program: ByteProgram
    spec: GraphSpec
    inputs: tuple[str, ...]
    outputs: tuple[str, ...]
    producer_ordinals: tuple[int, ...]
    global_ids: tuple[str, ...]
    source_sha256: bytes
    _manifest: bytes
    _maps: bytes

    def __init__(self, *args, **kwargs):
        raise TypeError('use the hosted BYTE Keccak round factory; no receipt/map admission exists')

    @property
    def manifest(self):
        return json.loads(self._manifest)

    @property
    def source_maps(self):
        return json.loads(self._maps)

    @property
    def ports(self):
        return MappingProxyType({'inputs': self.inputs, 'outputs': self.outputs})

    @property
    def program_operation_id(self):
        return self.program.operation_id

    def bind(self, initial_state, claimed_output=None):
        _hosted_guard()  # Before regeneration/Script/reference allocation.
        _state_bytes(initial_state, 'initial state')
        if claimed_output is not None:
            _state_bytes(claimed_output, 'claimed output')
        built = _build(self.round_index, initial_state, context=self.context, role=self.role,
                       operation_id=self.operation_id, claimed_output=claimed_output)
        program, spec, assignment, reference, inputs, outputs, producers, ids, manifest = built
        if (sha256(SOURCE_DOMAIN+_canonical(manifest)).digest() != self.source_sha256
                or program.digest() != self.program.digest() or spec.digest() != self.spec.digest()
                or inputs != self.inputs or outputs != self.outputs
                or producers != self.producer_ordinals or ids != self.global_ids):
            raise ValueError('fresh BYTE round changed sealed source/topology/producer identities')
        return _make(ByteKeccakRoundBinding, round=self, program=program, spec=spec,
            initial_state=initial_state, reference_output=reference,
            output_state=bytes(assignment[word] for word in outputs),
            _assignment=tuple(assignment.items()))

    def summary(self):
        result = dict(schema=SCHEMA, round_index=self.round_index, context=self.context.hex(),
            role=self.role, operation_id=self.operation_id, source_sha256=self.source_sha256.hex(),
            program_operation_id=self.program.operation_id,
            program_sha256=self.program.digest().hex(), catalogue_id=self.spec.digest().hex(),
            words=len(self.program.words), leaves=len(self.spec.leaves),
            input_bytes=STATE_BYTES, output_bytes=STATE_BYTES,
            round_graph_constructed=True, natural_terminal_producers=STATE_BYTES,
            boundary_copy_gates=0, zero_anchors=0,
            scope='one BYTE Keccak round only')
        result.update({flag: False for flag in FALSE_FLAGS})
        return result


def build_byte_keccak_round(round_index, *, context, role, operation_id='byte-keccak/round'):
    """Fresh value-free sealed round; actual construction is hosted Linux only."""
    _hosted_guard()  # Before the first builder, Program or Script allocation.
    _parameters(round_index, context, role, operation_id)
    built = _build(round_index, bytes(STATE_BYTES), context=context, role=role,
                   operation_id=operation_id)
    program, spec, _, _, inputs, outputs, producers, ids, manifest = built
    encoded = _canonical(manifest)
    return _make(ByteKeccakRound, round_index=round_index, context=context, role=role,
        operation_id=operation_id, program=program, spec=spec, inputs=inputs, outputs=outputs,
        producer_ordinals=producers, global_ids=ids,
        source_sha256=sha256(SOURCE_DOMAIN+encoded).digest(), _manifest=encoded,
        _maps=_canonical(manifest['source_maps']))
