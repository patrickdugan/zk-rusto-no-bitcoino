"""Sealed exact eval_W BYTE/limb encoding with an explicit Script field guard.

The input is an unsigned256-bit little-endian claim, including noncanonical
values. Binding preserves every bit without modular reduction or host field
admission. The original seven splits and nine reconstructions always hold for
that exact integer; the original field_valid leaf16 decides scalar canonicality.
Proof/hash/root provenance requires the outer source and remains unclaimed.
"""
from dataclasses import dataclass
from hashlib import sha256
import json
import os
import sys
from types import MappingProxyType

from convolution import ConvolutionTraceBuilder
from script import BASE
from trace import ID
from wots_graph import GraphSpec

SCHEMA = 'bitvm2-nova-eval-w-encoding/v1'
MAP_SCHEMA = 'bitvm2-nova-eval-w-encoding-maps/v1'
SOURCE_DOMAIN = b'BITVM2-NOVA/EVAL-W-ENCODING/v1\x00'
SCALAR_ROLES = ('pallas_scalar', 'vesta_scalar')
CROSSINGS = ((3, 5), (7, 2), (10, 7), (14, 4), (18, 1), (21, 6), (25, 3))
FALSE_FLAGS = ('encoding_relation_verified', 'canonicality_verified',
    'proof_byte_origins_bound', 'hash_verified', 'transcript_verified',
    'proof_verified', 'root_verified', 'production_assertion_binding',
    'bitcoin_transaction_graph', 'complete_nova_verifier', 'complete_bitvm2_verifier')


def _hosted_guard():
    if (os.environ.get('GITHUB_ACTIONS') != 'true'
            or os.environ.get('RUNNER_OS') != 'Linux' or sys.platform != 'linux'):
        raise ValueError('eval_W encoding graph construction is hosted GitHub Linux only')


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def _parameters(context, role, operation_id):
    """Pure preflight for the outer wrapper, before any graph allocation."""
    if (type(context) is not bytes or len(context) != 32
            or type(role) is not str or role not in SCALAR_ROLES
            or type(operation_id) is not str or not ID.fullmatch(operation_id)
            or not ID.fullmatch(operation_id+'/uniform-reference')):
        raise ValueError('explicit scalar role, operation and32-byte immutable context required')


def encoding_values(raw):
    """Pure exact integer reference, without a canonical-field verdict."""
    if type(raw) is not bytes or len(raw) != 32:
        raise ValueError('exact immutable32-byte unsigned little-endian claim required')
    value = int.from_bytes(raw, 'little')
    limbs = tuple((value >> (29*i)) & (BASE-1) for i in range(9))
    pieces = tuple(piece for byte, width in CROSSINGS
                   for piece in (raw[byte] & ((1 << width)-1), raw[byte] >> width))
    return limbs, tuple(raw), pieces


def _make(cls, **fields):
    result = object.__new__(cls)
    for name, value in fields.items():
        object.__setattr__(result, name, value)
    return result


@dataclass(frozen=True, init=False)
class EvalWEncoding:
    context: bytes
    role: str
    operation_id: str
    program: object
    spec: GraphSpec
    _assignment: tuple
    _ports: tuple
    _source_maps: bytes
    _metadata: bytes
    source_sha256: str
    source_maps_sha256: str

    def __init__(self, *args, **kwargs):
        raise TypeError('use the hosted sealed eval_W encoding factory')

    assignment = property(lambda self: dict(self._assignment))
    ports = property(lambda self: MappingProxyType(dict(self._ports)))
    source_maps = property(lambda self: json.loads(self._source_maps))
    metadata = property(lambda self: json.loads(self._metadata))

    def bind(self, raw):
        _hosted_guard()
        values = encoding_values(raw)
        fresh = _construct(context=self.context, role=self.role, operation_id=self.operation_id)
        if (fresh.source_sha256 != self.source_sha256
                or fresh.spec.digest() != self.spec.digest()
                or fresh._source_maps != self._source_maps):
            raise ValueError('eval_W binding must preserve its fresh value-free source')
        names = (fresh.ports['scalar_limbs']+fresh.ports['input_bytes']
                 +fresh.ports['split_auxiliaries'])
        assignment = tuple(zip(names, values[0]+values[1]+values[2], strict=True))
        # No Program.bind: a noncanonical field is an actual signed assertion
        # refuted by field_valid16, rather than a host-side admission exception.
        return _make(EvalWEncodingBinding, plan=fresh, raw=raw, _assignment=assignment)


@dataclass(frozen=True, init=False)
class EvalWEncodingBinding:
    plan: EvalWEncoding
    raw: bytes
    _assignment: tuple

    def __init__(self, *args, **kwargs):
        raise TypeError('bind a byte claim through the sealed eval_W encoding plan')

    program = property(lambda self: self.plan.program)
    spec = property(lambda self: self.plan.spec)
    ports = property(lambda self: self.plan.ports)
    source_maps = property(lambda self: self.plan.source_maps)
    metadata = property(lambda self: self.plan.metadata)
    source_sha256 = property(lambda self: self.plan.source_sha256)
    source_maps_sha256 = property(lambda self: self.plan.source_maps_sha256)
    assignment = property(lambda self: dict(self._assignment))


def _construct(*, context, role, operation_id):
    _hosted_guard()
    _parameters(context, role, operation_id)
    builder = ConvolutionTraceBuilder(role, operation_id, context)
    scalar = builder.field('scalar', 0)
    byte_ports = builder._bytes('scalar/encoding', scalar)
    program, assignment = builder.finish()
    spec = GraphSpec.from_program(program)
    if (len(program.words) != 55 or len(program.constraints) != 16 or len(program.fields) != 1
            or len(spec.leaves) != 17 or spec.field_leaves != (('scalar', 16),)):
        raise ValueError('eval_W must retain55 words/16 encoding predicates/field_valid16')
    auxiliary = tuple(f'scalar/encoding/split/{byte}/{part}'
                      for byte, _ in CROSSINGS for part in ('lo', 'hi'))
    positions = {word: index for index, (word, _) in enumerate(program.words)}
    byte_occurrences = []
    for byte, word in enumerate(byte_ports):
        slot = positions[word]
        crossing = next((index for index, (original, _) in enumerate(CROSSINGS)
                         if original == byte), None)
        occurrences = ([(crossing, 0)] if crossing is not None else
            [(ordinal, formal) for ordinal in range(7, 16)
             for formal, wire in enumerate(spec.leaves[ordinal].wires)
             if formal > 0 and wire == slot])
        if len(occurrences) != 1 or spec.leaves[occurrences[0][0]].wires[occurrences[0][1]] != slot:
            raise ValueError('each eval_W BYTE needs its exact existing encoding occurrence')
        byte_occurrences.append(occurrences[0])
    split_sources, split_consumers, links = [], [], []
    for limb, word in enumerate(scalar):
        slot = positions[word]
        if spec.leaves[7+limb].wires[0] != slot or spec.leaves[16].wires[limb] != slot:
            raise ValueError('eval_W scalar reconstruction detached from its canonical guard')
        links.append(dict(kind='limb-to-field-valid', word_index=slot,
            source_ordinal=7+limb, source_occurrence=0, target_ordinal=16, target_occurrence=limb))
    for part, word in enumerate(auxiliary):
        slot, source, occurrence = positions[word], part//2, 1+part % 2
        consumers = [(ordinal, formal) for ordinal in range(7, 16)
                     for formal, wire in enumerate(spec.leaves[ordinal].wires)
                     if formal > 0 and wire == slot]
        if len(consumers) != 1 or spec.leaves[source].wires[occurrence] != slot:
            raise ValueError('eval_W split auxiliary detached from its actual reconstruction')
        target, formal = consumers[0]
        split_sources.append((source, occurrence))
        split_consumers.append((target, formal))
        links.append(dict(kind='split-to-reconstruction', word_index=slot,
            source_ordinal=source, source_occurrence=occurrence,
            target_ordinal=target, target_occurrence=formal))
    ports = dict(input_bytes=byte_ports, scalar_limbs=scalar, split_auxiliaries=auxiliary)
    maps = dict(schema=MAP_SCHEMA,
        input_byte_indices=tuple(positions[word] for word in byte_ports),
        scalar_limb_indices=tuple(positions[word] for word in scalar),
        split_auxiliary_indices=tuple(positions[word] for word in auxiliary),
        byte_opening_occurrences=tuple(byte_occurrences),
        limb_reconstruction_occurrences=tuple((7+i, 0) for i in range(9)),
        canonical_field_ordinal=16, canonical_field_occurrences=tuple((16, i) for i in range(9)),
        split_source_occurrences=tuple(split_sources), split_consumer_occurrences=tuple(split_consumers),
        canonical_internal_links=tuple(links), legacy_uniform_word_map=tuple(range(129, 184)),
        legacy_uniform_leaf_map=tuple(range(65, 81))+(244,), ports=ports)
    raw_maps = _canonical(maps)
    maps_sha = sha256(raw_maps).hexdigest()
    metadata = dict(schema=SCHEMA, context=context.hex(), field_role=role, operation_id=operation_id,
        program_sha256=program.digest().hex(), catalogue_id=spec.digest().hex(),
        source_maps_sha256=maps_sha, words=55, arithmetic_constraints=16, canonical_fields=1, leaves=17,
        relation='exact unsigned256LE bytes = nine radix2^29 limbs; scalar canonicality at field_valid16',
        input_encoding='unsigned256-bit little endian; no modular reduction',
        encoding_relation_constructed=True, source_authority=False,
        scope='BYTE/limb scalar encoding only; proof/hash/root origins require outer authenticated joins')
    metadata.update({flag: False for flag in FALSE_FLAGS})
    raw_metadata = _canonical(metadata)
    return _make(EvalWEncoding, context=context, role=role, operation_id=operation_id,
        program=program, spec=spec, _assignment=tuple(assignment.items()), _ports=tuple(ports.items()),
        _source_maps=raw_maps, _metadata=raw_metadata,
        source_sha256=sha256(SOURCE_DOMAIN+raw_metadata).hexdigest(), source_maps_sha256=maps_sha)


def build_eval_w_encoding(*, context, role, operation_id='eval-w/encoding'):
    """Fresh value-free scalar encoding; Script alone decides canonicality."""
    _hosted_guard()
    return _construct(context=context, role=role, operation_id=operation_id)
