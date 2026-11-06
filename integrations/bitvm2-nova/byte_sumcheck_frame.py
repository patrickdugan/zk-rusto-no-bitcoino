"""Sealed two-scalar BYTE encodings and the following-c prefix constants.

The encoded compressed quadratic contains c0 then c2, with no linear term or
vector-length prefix. Each scalar reuses the existing ConvolutionTraceBuilder
field-to-BYTE relation: seven splits, nine reconstructions, and field_valid.
These relations also prove BYTE-to-canonical-field consistency. Their BYTE
ports have actual opening occurrences, not invented SSA output producers.

The fresh unchanged uniform reducer supplies independent projection identities
for its result encoding. The parent is an actual two-field ConvolutionProgram,
below every existing Program/GraphSpec bound. Its77 prefix constants cover p,
NoDS, counterLE8 and the first absorption's zero capacity only.

Proof-byte origins and the surrounding transcript/Spartan equations are future
source obligations. Host admission does not stand in for Script canonicality.
"""
from dataclasses import dataclass
from hashlib import sha256
import json
import os
import sys
from types import MappingProxyType

from convolution import ConvolutionTraceBuilder
from script import BASE, limbs
from trace import ID, ROLES
from uniform_reduce import build_uniform_reduction
from wots_graph import GraphSpec

SCHEMA = 'bitvm2-nova-byte-sumcheck-frame/v1'
MAP_SCHEMA = 'bitvm2-nova-byte-sumcheck-frame-maps/v1'
SOURCE_DOMAIN = b'BITVM2-NOVA/BYTE-SUMCHECK-FRAME/v1\x00'
SCALAR_ROLES = ('pallas_scalar', 'vesta_scalar')
DEGREES = (0, 2)
CROSSINGS = ((3, 5), (7, 2), (10, 7), (14, 4), (18, 1), (21, 6), (25, 3))
FIXED_PREFIX_INDICES = (0,)+tuple(range(65, 77))+tuple(range(136, 200))
FALSE_FLAGS = ('proof_byte_origins_bound', 'coefficient_proof_origins_bound',
    'transcript_verified', 'nova_transcript_verified', 'proof_verified',
    'bitvm2_script_verified', 'production_assertion_binding', 'bitcoin_transaction_graph')


def _hosted_guard():
    if (os.environ.get('GITHUB_ACTIONS') != 'true'
            or os.environ.get('RUNNER_OS') != 'Linux' or sys.platform != 'linux'):
        raise ValueError('sumcheck coefficient/frame construction is hosted GitHub Linux only')


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def _hash(value):
    return sha256(_canonical(value)).hexdigest()


def _counter(counter):
    if type(counter) is not int or not 0 <= counter < 1 << 64:
        raise ValueError('canonical public u64 counter required')
    return counter


def fixed_prefix_bytes(counter):
    """Pure77 fixed first-block BYTE positions; no hashes or graph allocation."""
    _counter(counter)
    state = bytearray(200)
    state[0] = ord('p')
    state[65:69] = b'NoDS'
    state[69:77] = counter.to_bytes(8, 'little')
    return tuple((index, state[index]) for index in FIXED_PREFIX_INDICES)


def _parameters(context, role, counter, operation_id):
    _counter(counter)
    if (type(context) is not bytes or len(context) != 32
            or type(role) is not str or role not in SCALAR_ROLES
            or type(operation_id) is not str or not ID.fullmatch(operation_id)):
        raise ValueError('explicit scalar role/operation/immutable32-byte context required')
    for suffix in ('/coefficient/0', '/coefficient/2', '/uniform-reference'):
        if not ID.fullmatch(operation_id+suffix):
            raise ValueError('derived encoding/reference operation exceeds existing cap')


def _coefficients(coefficients, role):
    if type(coefficients) is not tuple or len(coefficients) != 2:
        raise ValueError('exact immutable tuple(c0_LE32,c2_LE32) required')
    for raw in coefficients:
        if type(raw) is not bytes or len(raw) != 32:
            raise ValueError('each compressed coefficient must be immutable32 bytes')
        if int.from_bytes(raw, 'little') >= ROLES[role]:
            raise ValueError('host coefficient admission requires a canonical scalar')
    return coefficients


def _make(cls, **fields):
    result = object.__new__(cls)
    for name, value in fields.items():
        object.__setattr__(result, name, value)
    return result


def _encoding_child(raw, *, context, role, operation_id):
    """Fresh original encoding code; diagnostic values do not choose topology."""
    _hosted_guard()  # Private child regeneration also precedes any Script work.
    value = int.from_bytes(raw, 'little')
    builder = ConvolutionTraceBuilder(role, operation_id, context)
    field = builder.field('result', value if value < ROLES[role] else 0)
    digits = builder._bytes('result/encoding', field)
    program, assignment = builder.finish()
    # Numeric signed assertions can dispute field_valid. Do not call the
    # fixed-claim field admission gate on a controlled noncanonical witness.
    for word, digit in zip(field, limbs(value), strict=True):
        assignment[word] = digit
    for word, digit in zip(digits, raw, strict=True):
        assignment[word] = digit
    auxiliaries = []
    for index, width in CROSSINGS:
        low = f'result/encoding/split/{index}/lo'
        high = f'result/encoding/split/{index}/hi'
        assignment[low] = raw[index] & ((1 << width)-1)
        assignment[high] = raw[index] >> width
        auxiliaries.extend((low, high))
    spec = GraphSpec.from_program(program)
    if (len(program.words) != 55 or len(program.constraints) != 16
            or len(program.fields) != 1 or len(spec.leaves) != 17
            or spec.field_leaves != (('result', 16),)):
        raise ValueError('original scalar BYTE encoding census changed')
    return program, spec, assignment, field, digits, tuple(auxiliaries)


def _projection(child_spec, reference_spec):
    word_map = tuple(range(129, 184))
    leaf_map = tuple(range(65, 81))+(244,)
    if (len(reference_spec.words) != 379 or len(reference_spec.leaves) != 245
            or child_spec.words != reference_spec.words[129:184]):
        raise ValueError('fresh uniform result word projection changed')
    child_bodies, reference_bodies = dict(child_spec.bodies), dict(reference_spec.bodies)
    for before, after in enumerate(leaf_map):
        old, new = child_spec.leaves[before], reference_spec.leaves[after]
        if (old.kind != new.kind or old.argument != new.argument
                or tuple(word_map[i] for i in old.wires) != new.wires
                or old.body_sha256 != new.body_sha256
                or child_bodies[old.body_sha256] != reference_bodies[new.body_sha256]):
            raise ValueError('original uniform encoding body/bounds/alias projection changed')
    return word_map, leaf_map


def _opening_maps(child_spec, word_map, leaf_map, field, digits, auxiliaries):
    positions = {word: i for i, (word, _) in enumerate(child_spec.words)}
    byte_occurrences = []
    for byte, word in enumerate(digits):
        slot = positions[word]
        crossing = next((i for i, (index, _) in enumerate(CROSSINGS) if index == byte), None)
        matches = ([(crossing, 0)] if crossing is not None else
            [(ordinal, formal) for ordinal in range(7, 16)
             for formal, wire in enumerate(child_spec.leaves[ordinal].wires)
             if formal > 0 and wire == slot])
        if len(matches) != 1:
            raise ValueError('each BYTE needs one exact selected encoding occurrence')
        ordinal, formal = matches[0]
        if (child_spec.leaves[ordinal].wires[formal] != slot
                or child_spec.words[slot][1] != 256):
            raise ValueError('BYTE opening occurrence detached from its actual word')
        byte_occurrences.append((leaf_map[ordinal], formal))
    links = []
    for limb, word in enumerate(field):
        slot = positions[word]
        if (child_spec.leaves[7+limb].wires[0] != slot
                or child_spec.leaves[16].wires[limb] != slot):
            raise ValueError('field reconstruction/canonicality link detached')
        links.append(dict(kind='limb-to-field-valid', word_index=word_map[slot],
            source_ordinal=leaf_map[7+limb], source_occurrence=0,
            target_ordinal=leaf_map[16], target_occurrence=limb))
    for part, word in enumerate(auxiliaries):
        slot = positions[word]
        source, formal = part//2, 1+part % 2
        matches = [(ordinal, occurrence) for ordinal in range(7, 16)
            for occurrence, wire in enumerate(child_spec.leaves[ordinal].wires)
            if occurrence > 0 and wire == slot]
        if len(matches) != 1 or child_spec.leaves[source].wires[formal] != slot:
            raise ValueError('split auxiliary needs its exact reconstruction consumer')
        target, occurrence = matches[0]
        links.append(dict(kind='split-to-reconstruction', word_index=word_map[slot],
            source_ordinal=leaf_map[source], source_occurrence=formal,
            target_ordinal=leaf_map[target], target_occurrence=occurrence))
    return tuple(byte_occurrences), tuple(links)


def _construct(coefficients, *, context, role, counter, operation_id, fault_degree=None,
               frame_fault=None):
    _hosted_guard()  # Protect this private regeneration seam as well.
    _parameters(context, role, counter, operation_id)
    _coefficients(coefficients, role)
    if fault_degree is not None and (type(fault_degree) is not int or fault_degree not in DEGREES):
        raise ValueError('only the closed c0/c2 modulus diagnostic is supported')
    if frame_fault is not None:
        if (fault_degree is not None or type(frame_fault) is not tuple or len(frame_fault) != 2
                or type(frame_fault[0]) is not int or frame_fault[0] not in FIXED_PREFIX_INDICES
                or type(frame_fault[1]) is not int or not 0 <= frame_fault[1] <= 255):
            raise ValueError('only one fixed-position BYTE frame diagnostic is supported')
    actual = tuple(ROLES[role].to_bytes(32, 'little') if degree == fault_degree else raw
                   for degree, raw in zip(DEGREES, coefficients, strict=True))
    reference = build_uniform_reduction(bytes(64), role=role, context=context,
                                       operation_id=operation_id+'/uniform-reference')
    reference_spec = GraphSpec.from_program(reference.program)
    builder = ConvolutionTraceBuilder(role, operation_id, context)
    children, ports, byte_openings, internal_links = [], [], [], []
    for child, (degree, raw) in enumerate(zip(DEGREES, actual, strict=True)):
        program, spec, values, field, digits, auxiliaries = _encoding_child(raw,
            context=context, role=role, operation_id=f'{operation_id}/coefficient/{degree}')
        uniform_words, uniform_leaves = _projection(spec, reference_spec)
        prefix = f'coefficient/{degree}/'
        rename = {word: prefix+word for word, _ in program.words}
        word_offset = len(builder.words)
        builder.words.update((rename[word], bound) for word, bound in program.words)
        builder.fields.update((prefix+name, tuple(rename[word] for word in wires))
                              for name, wires in program.fields)
        builder.values.update((rename[word], value) for word, value in values.items())
        arithmetic_offset = len(builder.constraints)
        builder.constraints.extend(type(c)(c.kind, tuple(rename[word] for word in c.wires), c.argument)
                                   for c in program.constraints)
        word_map = tuple(range(word_offset, word_offset+55))
        leaf_map = tuple(range(arithmetic_offset, arithmetic_offset+16))+(109+child,)
        occurrences, links = _opening_maps(spec, word_map, leaf_map, field, digits, auxiliaries)
        byte_openings.append(occurrences)
        internal_links.extend(links)
        ports.append(dict(degree=degree, fields=tuple(rename[word] for word in field),
            bytes=tuple(rename[word] for word in digits), auxiliaries=tuple(rename[word] for word in auxiliaries)))
        children.append(dict(degree=degree, operation_id=program.operation_id,
            program_sha256=program.digest().hex(), catalogue_id=spec.digest().hex(),
            word_map=word_map, leaf_map=leaf_map,
            uniform_word_map=uniform_words, uniform_leaf_map=uniform_leaves))
    frames = []
    for byte, expected in fixed_prefix_bytes(counter):
        ordinal = len(builder.constraints)
        value = frame_fault[1] if frame_fault is not None and frame_fault[0] == byte else expected
        word = builder.small(f'prefix/frame/byte/{byte}', value, 256)
        builder.check('const', (word,), (expected,))
        frames.append(dict(byte_index=byte, expected=expected, word=word, anchor_ordinal=ordinal))
    program, assignment = builder.finish()
    spec = GraphSpec.from_program(program)
    if (len(program.words) != 187 or len(program.constraints) != 109 or len(spec.leaves) != 111
            or spec.field_leaves != (('coefficient/0/result', 109), ('coefficient/2/result', 110))):
        raise ValueError('two coefficient encodings and77 prefix anchors changed census')
    parent_bodies = dict(spec.bodies)
    for child, descriptor in enumerate(children):
        degree = descriptor['degree']
        fresh_program, fresh_spec, _, _, _, _ = _encoding_child(actual[child], context=context,
            role=role, operation_id=f'{operation_id}/coefficient/{degree}')
        if fresh_program.digest().hex() != descriptor['program_sha256']:
            raise ValueError('fresh coefficient child identity changed')
        for before, after in enumerate(descriptor['leaf_map']):
            old, new = fresh_spec.leaves[before], spec.leaves[after]
            if (new.kind != old.kind or new.argument != old.argument
                    or new.wires != tuple(descriptor['word_map'][i] for i in old.wires)
                    or new.body_sha256 != old.body_sha256
                    or parent_bodies[new.body_sha256] != dict(fresh_spec.bodies)[old.body_sha256]):
                raise ValueError('coefficient parent projection changed original body or alias')
    positions = {word: i for i, (word, _) in enumerate(program.words)}
    for record in frames:
        record['word_index'] = positions[record['word']]
        leaf = spec.leaves[record['anchor_ordinal']]
        if leaf.kind != 'const' or leaf.wires != (record['word_index'],) or leaf.argument != (record['expected'],):
            raise ValueError('prefix anchor no longer constrains its actual BYTE word')
    for link in internal_links:
        source = spec.leaves[link['source_ordinal']]
        target = spec.leaves[link['target_ordinal']]
        if (source.wires[link['source_occurrence']] != link['word_index']
                or target.wires[link['target_occurrence']] != link['word_index']):
            raise ValueError('canonicality opening link changed parent word')
    if len(internal_links) != 46 or len(frames) != 77:
        raise ValueError('canonical internal links/frame coverage changed')
    public_ports = dict(coefficient_bytes=tuple(record['bytes'] for record in ports),
        coefficient_fields=tuple(record['fields'] for record in ports),
        split_auxiliaries=tuple(record['auxiliaries'] for record in ports),
        frame_bytes=tuple(record['word'] for record in frames))
    maps = dict(schema=MAP_SCHEMA, children=children,
        uniform_reference=dict(operation_id=reference.program.operation_id,
            program_sha256=reference.program.digest().hex(), catalogue_id=reference_spec.digest().hex()),
        coefficient_degrees=DEGREES,
        coefficient_byte_indices=tuple(tuple(positions[word] for word in names)
                                       for names in public_ports['coefficient_bytes']),
        coefficient_field_indices=tuple(tuple(positions[word] for word in names)
                                        for names in public_ports['coefficient_fields']),
        byte_opening_occurrences=tuple(byte_openings), canonical_field_leaves=(109, 110),
        canonical_internal_links=tuple(internal_links), frame_anchors=frames, ports=public_ports)
    raw_maps = _canonical(maps)
    metadata = dict(schema=SCHEMA, context=context.hex(), field_role=role, counter=counter,
        operation_id=operation_id, program_sha256=program.digest().hex(), catalogue_id=spec.digest().hex(),
        source_maps_sha256=sha256(raw_maps).hexdigest(),
        coefficient_encoding='compressed quadratic c0_LE32||c2_LE32; no linear term or length prefix',
        canonicality='original9radix2^29 limbs,32LEbytes,7splits,9reconstructions,field_valid per scalar',
        scope='canonical scalar/BYTE relations and following-c prefix constants; proof origins remain external')
    raw_metadata = _canonical(metadata)
    if any(type(value) is not int or not 0 <= value < bound for word, bound in program.words
           for value in (assignment[word],)):
        raise ValueError('numeric assertion escaped original word bounds')
    if fault_degree is None:
        program._admit(assignment)
    return dict(program=program, spec=spec, assignment=assignment, actual_coefficients=actual,
        ports=public_ports, source_sha256=sha256(SOURCE_DOMAIN+raw_metadata).digest(),
        source_maps_sha256=sha256(raw_maps).digest(), metadata=raw_metadata, maps=raw_maps)


@dataclass(frozen=True, init=False)
class SumcheckFrameBinding:
    frame: object
    program: object
    spec: GraphSpec
    input_coefficients: tuple[bytes, bytes]
    coefficients: tuple[bytes, bytes]
    diagnostic_degree: int | None
    diagnostic_frame: tuple | None
    _assignment: tuple

    def __init__(self, *args, **kwargs):
        raise TypeError('bind through the sealed sumcheck coefficient/frame factory')

    assignment = property(lambda self: dict(self._assignment))
    ports = property(lambda self: self.frame.ports)
    metadata = property(lambda self: self.frame.metadata)
    source_maps = property(lambda self: self.frame.source_maps)
    source_sha256 = property(lambda self: self.frame.source_sha256)
    source_maps_sha256 = property(lambda self: self.frame.source_maps_sha256)

    def summary(self):
        result = dict(source_sha256=self.source_sha256.hex(), coefficient_frame_binding_constructed=True,
            words=len(self.program.words), leaves=len(self.spec.leaves), canonical_field_guards=(109, 110),
            diagnostic_degree=self.diagnostic_degree, diagnostic_frame=self.diagnostic_frame)
        result.update({flag: False for flag in FALSE_FLAGS})
        return result


@dataclass(frozen=True, init=False)
class SumcheckFrame:
    context: bytes
    role: str
    counter: int
    operation_id: str
    program: object
    spec: GraphSpec
    source_sha256: bytes
    source_maps_sha256: bytes
    _assignment: tuple
    _ports: tuple
    _metadata: bytes
    _maps: bytes

    def __init__(self, *args, **kwargs):
        raise TypeError('use the hosted sealed coefficient/frame factory; no receipt/map admission')

    assignment = property(lambda self: dict(self._assignment))
    ports = property(lambda self: MappingProxyType(dict(self._ports)))
    metadata = property(lambda self: json.loads(self._metadata))
    source_maps = property(lambda self: json.loads(self._maps))

    def bind(self, coefficients):
        _hosted_guard()
        _coefficients(coefficients, self.role)
        return _binding(self, coefficients)

    def summary(self):
        result = dict(schema=SCHEMA, source_sha256=self.source_sha256.hex(),
            source_maps_sha256=self.source_maps_sha256.hex(), field_role=self.role, counter=self.counter,
            operation_id=self.operation_id, words=187, constraints=109, leaves=111,
            coefficient_degrees=DEGREES, prefix_anchors=77, canonical_field_guards=(109, 110),
            canonical_internal_opening_links=46, source_constructed=True)
        result.update({flag: False for flag in FALSE_FLAGS})
        return result


def _binding(frame, coefficients, fault_degree=None, frame_fault=None):
    _hosted_guard()
    if type(frame) is not SumcheckFrame:
        raise ValueError('fresh sealed coefficient/frame plan required')
    built = _construct(coefficients, context=frame.context, role=frame.role, counter=frame.counter,
                       operation_id=frame.operation_id, fault_degree=fault_degree, frame_fault=frame_fault)
    if (built['program'].digest() != frame.program.digest() or built['spec'].digest() != frame.spec.digest()
            or built['source_sha256'] != frame.source_sha256
            or built['source_maps_sha256'] != frame.source_maps_sha256):
        raise ValueError('fresh coefficient/frame binding changed sealed topology/source identity')
    return _make(SumcheckFrameBinding, frame=frame, program=built['program'], spec=built['spec'],
        input_coefficients=coefficients, coefficients=built['actual_coefficients'],
        diagnostic_degree=fault_degree, diagnostic_frame=frame_fault,
        _assignment=tuple(built['assignment'].items()))


def _bind_modulus_fault(frame, coefficients, degree):
    """Private fresh-key SMALL-probe seam; never a main-chain source override."""
    _hosted_guard()
    if type(degree) is not int or degree not in DEGREES:
        raise ValueError('modulus probe must select semantic coefficient0 or2')
    return _binding(frame, coefficients, fault_degree=degree)


def _bind_frame_fault(frame, coefficients, byte_index, replacement):
    """Private fixed77-position SMALL-probe seam with unchanged source identity."""
    _hosted_guard()
    return _binding(frame, coefficients, frame_fault=(byte_index, replacement))


def build_sumcheck_frame(*, context, role, counter, operation_id='sumcheck/frame'):
    _hosted_guard()  # Before the first encoding, reference or Script allocation.
    _parameters(context, role, counter, operation_id)
    built = _construct((bytes(32), bytes(32)), context=context, role=role, counter=counter,
                       operation_id=operation_id)
    return _make(SumcheckFrame, context=context, role=role, counter=counter, operation_id=operation_id,
        program=built['program'], spec=built['spec'], source_sha256=built['source_sha256'],
        source_maps_sha256=built['source_maps_sha256'], _assignment=tuple(built['assignment'].items()),
        _ports=tuple(built['ports'].items()), _metadata=built['metadata'], _maps=built['maps'])
