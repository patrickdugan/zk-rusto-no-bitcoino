"""Sealed upstream scalar-limb to Boolean-bit relation, without field admission.

The nine input limbs come from the actual Uniform result assignment. The outer
source must share their keys/openings and retain Uniform's field_valid leaf244.
This helper intentionally declares no field and does not reduce an integer or
treat an independently supplied scalar as canonical authority. Its nine existing
bits predicates reconstruct all input limbs; high bits255..260 cannot float.
Public bit indices are little endian, while predicate operands are MSB first.
"""
from dataclasses import dataclass
from hashlib import sha256
import json
import os
import sys
from types import MappingProxyType

from script import BASE
from trace import ID, TraceBuilder
from wots_graph import GraphSpec

SCHEMA = 'bitvm2-nova-scalar-bits/v1'
MAP_SCHEMA = 'bitvm2-nova-scalar-bits-maps/v1'
SOURCE_DOMAIN = b'BITVM2-NOVA/SCALAR-BITS/v1\x00'
SCALAR_ROLES = ('pallas_scalar', 'vesta_scalar')
LIMB_WIDTHS = (29,)*8+(23,)
POINT_CONSUMERS = ((6117, 0), (6119, 0), (6120, 0), (6121, 0), (6122, 0))
FALSE_FLAGS = ('canonical_challenge_script_bound', 'curve_operation_verified',
    'scalar_multiplication_verified', 'transcript_verified', 'proof_verified',
    'production_assertion_binding', 'bitcoin_transaction_graph')


def _hosted_guard():
    if (os.environ.get('GITHUB_ACTIONS') != 'true'
            or os.environ.get('RUNNER_OS') != 'Linux' or sys.platform != 'linux'):
        raise ValueError('scalar bit graph construction is hosted GitHub Linux only')


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def _parameters(context, role, bit_index, operation_id):
    """Pure bounded preflight, before any outer chain or graph allocation."""
    if (type(context) is not bytes or len(context) != 32
            or type(role) is not str or role not in SCALAR_ROLES
            or type(bit_index) is not int or not 0 <= bit_index < 255
            or type(operation_id) is not str or not ID.fullmatch(operation_id)):
        raise ValueError('scalar role, fixed bit0..254, operation and32-byte context required')


def _limbs(input_limbs):
    if (type(input_limbs) is not tuple or len(input_limbs) != 9
            or any(type(value) is not int or not 0 <= value < BASE for value in input_limbs)):
        raise ValueError('exact immutable tuple of nine upstream BASE-bound limbs required')
    return input_limbs


def limb_bits(input_limbs, *, bit_index, claimed_bit=None):
    """Pure unsigned reference, with no canonical-field or provenance verdict.

    A high input limb may encode bits above254. The full limb is retained in
    assignments, so the original23-bit top reconstruction rejects those bits.
    The sole diagnostic changes the selected Boolean wire, never the inputs.
    """
    _limbs(input_limbs)
    if type(bit_index) is not int or not 0 <= bit_index < 255:
        raise ValueError('fixed selected bit0..254 required')
    if claimed_bit is not None and (type(claimed_bit) is not int or claimed_bit not in (0, 1)):
        raise ValueError('selected claimed bit must be strict integer0 or1')
    value = sum(limb << (29*index) for index, limb in enumerate(input_limbs))
    bits = [(value >> index) & 1 for index in range(255)]
    if claimed_bit is not None:
        bits[bit_index] = claimed_bit
    return tuple(bits)


def _make(cls, **fields):
    result = object.__new__(cls)
    for name, value in fields.items():
        object.__setattr__(result, name, value)
    return result


@dataclass(frozen=True, init=False)
class ScalarBits:
    context: bytes
    role: str
    bit_index: int
    operation_id: str
    program: object
    spec: GraphSpec
    _ports: tuple
    _assignment: tuple
    _source_maps: bytes
    _metadata: bytes
    source_sha256: str
    source_maps_sha256: str

    def __init__(self, *args, **kwargs):
        raise TypeError('use the hosted sealed scalar bit factory')

    ports = property(lambda self: MappingProxyType(dict(self._ports)))
    assignment = property(lambda self: dict(self._assignment))
    source_maps = property(lambda self: json.loads(self._source_maps))
    metadata = property(lambda self: json.loads(self._metadata))

    def bind(self, input_limbs, *, claimed_bit=None):
        _hosted_guard()
        _limbs(input_limbs)
        bits = limb_bits(input_limbs, bit_index=self.bit_index, claimed_bit=claimed_bit)
        fresh = _construct(context=self.context, role=self.role,
                           bit_index=self.bit_index, operation_id=self.operation_id)
        if (fresh.source_sha256 != self.source_sha256
                or fresh.spec.digest() != self.spec.digest()
                or fresh._source_maps != self._source_maps):
            raise ValueError('scalar bit binding must retain its fresh value-free source')
        assignment = tuple(zip(fresh.ports['input_limbs']+fresh.ports['bits'],
                               input_limbs+bits, strict=True))
        return _make(ScalarBitsBinding, plan=fresh, input_limbs=input_limbs,
                     bits=bits, claimed_bit=claimed_bit, _assignment=assignment)


@dataclass(frozen=True, init=False)
class ScalarBitsBinding:
    plan: ScalarBits
    input_limbs: tuple
    bits: tuple
    claimed_bit: int | None
    _assignment: tuple

    def __init__(self, *args, **kwargs):
        raise TypeError('bind actual upstream limbs through a sealed scalar bit plan')

    program = property(lambda self: self.plan.program)
    spec = property(lambda self: self.plan.spec)
    ports = property(lambda self: self.plan.ports)
    source_maps = property(lambda self: self.plan.source_maps)
    metadata = property(lambda self: self.plan.metadata)
    source_sha256 = property(lambda self: self.plan.source_sha256)
    source_maps_sha256 = property(lambda self: self.plan.source_maps_sha256)
    assignment = property(lambda self: dict(self._assignment))
    selected_bit = property(lambda self: self.bits[self.plan.bit_index])


def _construct(*, context, role, bit_index, operation_id):
    _hosted_guard()
    _parameters(context, role, bit_index, operation_id)
    builder = TraceBuilder(role, operation_id, context)
    inputs = tuple(builder.small(f'scalar/l{i}', 0, BASE) for i in range(9))
    bits = tuple(builder.small(f'bit/{i}', 0, 2) for i in range(255))
    for index, width in enumerate(LIMB_WIDTHS):
        low, high = 29*index, 29*index+width
        builder.check('bits', (inputs[index],)+tuple(reversed(bits[low:high])), (width,))
    program, assignment = builder.finish()
    spec = GraphSpec.from_program(program)
    if (len(program.words) != 264 or len(program.constraints) != 9 or program.fields
            or len(spec.leaves) != 9 or spec.field_leaves):
        raise ValueError('scalar bit bridge must retain264 words/9 leaves/no fields')
    bit_occurrences = tuple((index//29, min(29*(index//29+1), 255)-index)
                            for index in range(255))
    for index, (ordinal, occurrence) in enumerate(bit_occurrences):
        if spec.leaves[ordinal].wires[occurrence] != 9+index:
            raise ValueError('public LSB bit detached from actual MSB formal occurrence')
    ports = dict(input_limbs=inputs, bits=bits, selected_bit=bits[bit_index])
    maps = dict(schema=MAP_SCHEMA, input_limb_indices=tuple(range(9)),
        bit_indices=tuple(range(9, 264)), selected_index=9+bit_index,
        limb_occurrences=tuple((i, 0) for i in range(9)),
        bit_occurrences=bit_occurrences, limb_widths=LIMB_WIDTHS,
        upstream_uniform=dict(component_index=8, result_word_indices=tuple(range(129, 138)),
            result_byte_indices=tuple(range(138, 170)),
            result_reconstruction_occurrences=tuple((72+i, 0) for i in range(9)),
            field_valid_ordinal=244, field_valid_occurrences=tuple((244, i) for i in range(9)),
            canonicality_required=True),
        required_limb_global_ids=tuple(f'c/reduction/result/l{i}' for i in range(9)),
        bit_global_ids=tuple(f'c/bits/bit/{i}' for i in range(255)),
        selected_point_consumers=POINT_CONSUMERS, ports=ports)
    raw_maps = _canonical(maps)
    maps_sha = sha256(raw_maps).hexdigest()
    metadata = dict(schema=SCHEMA, context=context.hex(), field_role=role, bit_index=bit_index,
        operation_id=operation_id, program_sha256=program.digest().hex(),
        catalogue_id=spec.digest().hex(), source_maps_sha256=maps_sha,
        words=264, leaves=9, fields=0,
        input_encoding='nine little-endian radix2^29 upstream limbs',
        bit_order='public LSB indices0..254; predicate formal operands MSB first per limb',
        upstream_canonicality_required=True,
        canonicality_source='upstream Uniform result field_valid ordinal244; no local field guard',
        source_authority=False,
        scope='upstream limb/Boolean reconstruction only; canonical challenge and point origins require outer joins')
    metadata.update({flag: False for flag in FALSE_FLAGS})
    raw_metadata = _canonical(metadata)
    return _make(ScalarBits, context=context, role=role, bit_index=bit_index,
        operation_id=operation_id, program=program, spec=spec, _ports=tuple(ports.items()),
        _assignment=tuple(assignment.items()), _source_maps=raw_maps, _metadata=raw_metadata,
        source_sha256=sha256(SOURCE_DOMAIN+raw_metadata).hexdigest(), source_maps_sha256=maps_sha)


def build_scalar_bits(*, context, role, bit_index, operation_id='scalar/bits'):
    """Fresh value-free plan; bit selection is verifier-fixed in source identity."""
    _hosted_guard()
    return _construct(context=context, role=role, bit_index=bit_index, operation_id=operation_id)
