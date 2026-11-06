"""Closed noncanonical Uniform witnesses for the challenge-bit adversary.

This is a negative-fixture constructor, never an admission bypass for callers.
It always constructs a fresh ordinary Uniform graph, then re-witnesses exactly
the integer-equivalent c+p, q-1 alternative. The original field_valid leaf244
must be false while every original arithmetic leaf stays true. No imported
Program, assignment, signature, key, receipt or caller-selected alternative is
accepted. Actual graph construction remains hosted-only.
"""
from dataclasses import dataclass
from hashlib import sha256
import json
from types import MappingProxyType

from convolution import BYTE, CARRY_OFFSET, ConvolutionProgram
from scalar_bits import build_scalar_bits
from script import BASE
from trace import Constraint, ID, ROLES
from uniform_reduce import build_uniform_reduction, _hosted_guard
from wots_graph import GraphSpec

SCALAR_ROLES = ('pallas_scalar', 'vesta_scalar')
SCHEMA = 'bitvm2-nova-closed-uniform-alias/v1'
MERGED_SCHEMA = 'bitvm2-nova-closed-scalar-alias/v1'
SOURCE_DOMAIN = b'BITVM2-NOVA/CLOSED-SCALAR-ALIAS/v1\x00'


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def alias_values(raw64, *, role):
    """Pure tiny integer reference; no graph or field-admission verdict."""
    if (type(raw64) is not bytes or len(raw64) != 64
            or type(role) is not str or role not in SCALAR_ROLES):
        raise ValueError('exact immutable64-byte input and explicit scalar role required')
    value, modulus = int.from_bytes(raw64, 'little'), ROLES[role]
    quotient, canonical = divmod(value, modulus)
    result = canonical+modulus
    if quotient == 0 or result >= 1 << 255:
        raise ValueError('closed c+p,q-1 fixture needs q>0 and a255-bit alternative')
    if value != result+modulus*(quotient-1):
        raise ValueError('closed scalar alias integer relation changed')
    return result, quotient-1


def _parameters(context, role, operation_id):
    if (type(context) is not bytes or len(context) != 32
            or type(role) is not str or role not in SCALAR_ROLES
            or type(operation_id) is not str or not ID.fullmatch(operation_id)):
        raise ValueError('scalar role, immutable32-byte context and operation required')


def _make(cls, **fields):
    result = object.__new__(cls)
    for name, value in fields.items():
        object.__setattr__(result, name, value)
    return result


@dataclass(frozen=True, init=False)
class UniformAlias:
    program: object
    spec: GraphSpec
    result_value: int
    quotient_value: int
    _assignment: tuple
    _ports: tuple
    _metadata: bytes
    _anchors: tuple

    def __init__(self, *args, **kwargs):
        raise TypeError('use the closed hosted Uniform alias constructor')

    assignment = property(lambda self: dict(self._assignment))
    ports = property(lambda self: MappingProxyType(dict(self._ports)))
    metadata = property(lambda self: json.loads(self._metadata))
    anchor_constraints = property(lambda self: MappingProxyType(dict(self._anchors)))


def build_uniform_alias(raw64, *, context, role, operation_id):
    """Fresh original379-word/245-leaf source, closed false field_valid244.

    The source metadata/ports remain identical to the ordinary value-free
    Uniform source. Only the assignment changes. In particular no Program.bind
    is called with a noncanonical field, and no adapter verdict is inferred
    from this constructor: hosted native execution must test the actual leaf.
    """
    _hosted_guard()
    _parameters(context, role, operation_id)
    result, quotient = alias_values(raw64, role=role)
    positive = build_uniform_reduction(raw64, context=context, role=role,
                                       operation_id=operation_id)
    program, ports, assignment = positive.program, positive.ports, positive.assignment
    spec = GraphSpec.from_program(program)
    if (len(program.words) != 379 or len(program.constraints) != 244
            or len(program.fields) != 1 or len(spec.leaves) != 245
            or tuple(spec.field_leaves) != (('result', 244),)):
        raise ValueError('closed Uniform alias source dimensions/field projection changed')
    for index, word in enumerate(ports['result_field']):
        assignment[word] = (result >> (29*index)) & (BASE-1)
    for word, value in zip(ports['result_bytes'], result.to_bytes(32, 'little'), strict=True):
        assignment[word] = value
    for word, value in zip(ports['quotient_bytes'], quotient.to_bytes(33, 'little'), strict=True):
        assignment[word] = value

    # Recompute every dependent auxiliary in the original fixed constraint
    # order. Check both endpoint anchors rather than overwriting a failed one.
    for constraint in program.constraints:
        kind, wires, argument = constraint.kind, constraint.wires, constraint.argument
        values = [assignment[word] for word in wires]
        if kind == 'conv_split':
            width, = argument
            assignment[wires[1]] = values[0] & ((1 << width)-1)
            assignment[wires[2]] = values[0] >> width
        elif kind == 'conv_ab':
            assignment[wires[-1]] = sum(values[2*i]*values[2*i+1]
                                         for i in range(argument[0]))
        elif kind == 'conv_pq':
            assignment[wires[-1]] = sum(value*coefficient for value, coefficient
                                         in zip(values[:-1], argument, strict=True))
        elif kind == 'conv_column':
            ab, pq, has_output = argument
            numerator = (sum(values[:ab])+values[ab+pq]+255*CARRY_OFFSET
                         -sum(values[ab:ab+pq])-(values[-1] if has_output else 0))
            outgoing, remainder = divmod(numerator, BYTE)
            if remainder:
                raise ValueError('closed scalar alias has a false integer column')
            assignment[wires[ab+pq+1]] = outgoing
        elif kind not in ('conv_reconstruct', 'const'):
            raise ValueError('unexpected predicate in closed Uniform alias source')
        if not constraint.native(assignment, program.p):
            raise ValueError('closed Uniform alias must preserve all arithmetic predicates')
    if (any(type(assignment[word]) is not int or not 0 <= assignment[word] < bound
            for word, bound in program.words)
            or sum(assignment[word] << (29*i)
                   for i, word in enumerate(ports['result_field'])) != result
            or not program.p <= result < 1 << 255
            or assignment[ports['carries'][0]] != CARRY_OFFSET
            or assignment[ports['carries'][-1]] != CARRY_OFFSET):
        raise ValueError('closed Uniform alias range, canonical failure or endpoint mismatch')
    return _make(UniformAlias, program=program, spec=spec, result_value=result,
        quotient_value=quotient, _assignment=tuple(assignment.items()),
        _ports=tuple(ports.items()), _metadata=_canonical(positive.metadata),
        _anchors=tuple(positive.anchor_constraints.items()))


@dataclass(frozen=True, init=False)
class ScalarAlias:
    program: object
    spec: GraphSpec
    result_value: int
    quotient_value: int
    field_valid_ordinal: int
    _assignment: tuple
    _ports: tuple
    _metadata: bytes
    _source_maps: bytes
    source_sha256: str
    source_maps_sha256: str

    def __init__(self, *args, **kwargs):
        raise TypeError('use the closed hosted scalar alias constructor')

    assignment = property(lambda self: dict(self._assignment))
    ports = property(lambda self: MappingProxyType(dict(self._ports)))
    metadata = property(lambda self: json.loads(self._metadata))
    source_maps = property(lambda self: json.loads(self._source_maps))


def build_scalar_alias(raw64, *, context, role, bit_index=0, operation_id='scalar/alias'):
    """Private merged Uniform+bits probe:634 words,254 leaves, sole false FV253.

    This is an actual small ConvolutionProgram. Its244 old arithmetic leaves
    precede nine bit leaves; the single canonical-field leaf moves244 ->253.
    The complete main source continues to use the unchanged separate FV244.
    """
    _hosted_guard()
    _parameters(context, role, operation_id)
    if (type(bit_index) is not int or not 0 <= bit_index < 255
            or not ID.fullmatch(operation_id+'/uniform')
            or not ID.fullmatch(operation_id+'/bits')):
        raise ValueError('fixed bit0..254 and bounded child operations required')
    uniform = build_uniform_alias(raw64, context=context, role=role,
                                  operation_id=operation_id+'/uniform')
    bridge = build_scalar_bits(context=context, role=role, bit_index=bit_index,
                               operation_id=operation_id+'/bits')
    inputs = tuple(uniform.assignment[word] for word in uniform.ports['result_field'])
    bound = bridge.bind(inputs)
    limb_map = dict(zip(bridge.ports['input_limbs'], uniform.ports['result_field'], strict=True))
    bits = tuple(f'scalar-alias/bit/{i}' for i in range(255))
    word_map = {**limb_map, **dict(zip(bridge.ports['bits'], bits, strict=True))}
    constraints = uniform.program.constraints+tuple(
        Constraint(c.kind, tuple(word_map[word] for word in c.wires), c.argument)
        for c in bridge.program.constraints)
    program = ConvolutionProgram(role, operation_id, context,
        uniform.program.words+tuple((word, 2) for word in bits),
        uniform.program.fields, constraints)
    assignment = uniform.assignment
    assignment.update({word_map[word]: value for word, value in bound.assignment.items()})
    spec = GraphSpec.from_program(program)
    if (len(program.words) != 634 or len(program.constraints) != 253
            or len(spec.leaves) != 254 or spec.field_leaves != (('result', 253),)
            or any(not c.native(assignment, program.p) for c in constraints)):
        raise ValueError('merged closed alias dimensions, projection or arithmetic changed')
    indices = {word: index for index, (word, _) in enumerate(program.words)}
    maps = dict(schema=MERGED_SCHEMA, uniform_word_map=tuple(range(379)),
        uniform_leaf_map=tuple(range(244))+(253,),
        bits_word_map=tuple(indices[word_map[word]] for word, _ in bridge.program.words),
        bits_leaf_map=tuple(range(244, 253)), field_valid_ordinal=253,
        selected_bit_index=indices[bits[bit_index]],
        uniform_program_sha256=uniform.program.digest().hex(),
        uniform_catalogue_id=uniform.spec.digest().hex(),
        bits_program_sha256=bridge.program.digest().hex(), bits_catalogue_id=bridge.spec.digest().hex())
    raw_maps = _canonical(maps)
    metadata = dict(schema=MERGED_SCHEMA, context=context.hex(), field_role=role,
        operation_id=operation_id, bit_index=bit_index,
        program_sha256=program.digest().hex(), catalogue_id=spec.digest().hex(),
        source_maps_sha256=sha256(raw_maps).hexdigest(), words=634, leaves=254,
        arithmetic_predicates=253, field_valid_ordinal=253,
        construction='closed c+p,q-1 only; fresh Uniform and scalar bits children',
        production_assertion_binding=False, proof_verified=False,
        bitcoin_transaction_graph=False)
    raw_metadata = _canonical(metadata)
    return _make(ScalarAlias, program=program, spec=spec, result_value=uniform.result_value,
        quotient_value=uniform.quotient_value, field_valid_ordinal=253,
        _assignment=tuple(assignment.items()),
        _ports=tuple(dict(input_bytes=uniform.ports['input_bytes'],
                         result_field=uniform.ports['result_field'], bits=bits,
                         selected_bit=bits[bit_index]).items()),
        _metadata=raw_metadata, _source_maps=raw_maps,
        source_sha256=sha256(SOURCE_DOMAIN+raw_metadata).hexdigest(),
        source_maps_sha256=sha256(raw_maps).hexdigest())
