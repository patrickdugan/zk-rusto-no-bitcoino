"""Complete E=A+P followed by R=A+bP for one externally linked Boolean bit.

The original convolution point-addition arithmetic and all35 canonical field
guards remain active even when b=0. The selector adds three Boolean infinity
mux gates, four coordinate comparisons, point_form and two canonical R fields.
This is a point relation on external A/P ports, not scalar multiplication or an
IPA/proof verifier. Upstream bit/proof/key origins require an outer composition.
"""
from dataclasses import dataclass
from hashlib import sha256
import json
import os
import sys
from types import MappingProxyType

from convolution import ConvolutionTraceBuilder
from curve_trace import AUTO, EncodedPoint, point_add_trace
from ipa_algebra import PALLAS, VESTA
from trace import ID
from wots_graph import GraphSpec

SCHEMA = 'bitvm2-nova-conditional-point/v1'
MAP_SCHEMA = 'bitvm2-nova-conditional-point-maps/v1'
SOURCE_DOMAIN = b'BITVM2-NOVA/CONDITIONAL-POINT/v1\x00'
BASE_ROLES = ('pallas_base', 'vesta_base')
CHILD_WORDS, CHILD_ARITHMETIC, CHILD_FIELDS = 7476, 6116, 35
WORDS, ARITHMETIC, FIELDS, LEAVES = 7498, 6124, 37, 6161
SELECTOR_ORDINALS = (('infinity_delta', 6116), ('infinity_masked', 6117),
    ('infinity_result', 6118), ('x_from_A', 6119), ('y_from_A', 6120),
    ('x_from_E', 6121), ('y_from_E', 6122), ('point_form', 6123))
BIT_OCCURRENCES = ((6117, 0), (6119, 0), (6120, 0), (6121, 0), (6122, 0))
FALSE_FLAGS = ('challenge_bit_origin_bound', 'A_proof_origin_bound', 'P_key_origin_bound',
    'scalar_multiplication_verified', 'ipa_verified', 'transcript_verified',
    'proof_verified', 'bitvm2_script_verified', 'production_assertion_binding', 'bitcoin_transaction_graph')


def _hosted_guard():
    if (os.environ.get('GITHUB_ACTIONS') != 'true'
            or os.environ.get('RUNNER_OS') != 'Linux' or sys.platform != 'linux'):
        raise ValueError('conditional point construction/binding is hosted GitHub Linux only')


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def _hash(value):
    return sha256(_canonical(value)).hexdigest()


def curve_for_role(role):
    if type(role) is not str or role not in BASE_ROLES:
        raise ValueError('explicit pallas_base or vesta_base role required')
    return PALLAS if role == 'pallas_base' else VESTA


def _parameters(context, role, bit_index, operation_id):
    curve_for_role(role)
    if (type(context) is not bytes or len(context) != 32 or type(bit_index) is not int
            or not 0 <= bit_index < 255 or type(operation_id) is not str
            or not ID.fullmatch(operation_id) or not ID.fullmatch(operation_id+'/complete-add')):
        raise ValueError('explicit context/bit0..254/bounded point operation required')


def _bit(value):
    if type(value) is not int or value not in (0, 1):
        raise ValueError('strict integer Boolean bit required')
    return value


def encoded_point(value, *, role, label='point', canonical_form=True):
    """Pure canonical coordinate/flag parser, without asserting curve membership.

    Finite membership is checked by the complete child graph. Controlled explicit
    E claims can expose invalid A/P point_form or membership assertions there.
    """
    curve = curve_for_role(role)
    if value is None:
        point = EncodedPoint(1, 0, 0)
    elif type(value) is EncodedPoint:
        point = value
    elif type(value) is tuple and len(value) == 2:
        point = EncodedPoint(0, value[0], value[1])
    else:
        raise ValueError(f'exact EncodedPoint, finite tuple2, or None required for {label}')
    if (type(point.infinity) is not int or point.infinity not in (0, 1)
            or type(point.x) is not int or type(point.y) is not int
            or not 0 <= point.x < curve.p or not 0 <= point.y < curve.p
            or (canonical_form and point.infinity and (point.x or point.y))):
        raise ValueError(f'canonical base-field coordinates/infinity flag required for {label}')
    return point


def _make(cls, **fields):
    value = object.__new__(cls)
    for key, item in fields.items():
        object.__setattr__(value, key, item)
    return value


def _ports():
    result = dict(bit='select/bit', infinity_delta='select/infinity-delta',
                  infinity_masked='select/infinity-masked')
    for label, prefix in (('A', 'left'), ('P', 'right'), ('E', 'result'), ('R', 'selected')):
        result[label+'_infinity'] = prefix+'/infinity'
        result[label+'_x'] = tuple(f'{prefix}/x/l{i}' for i in range(9))
        result[label+'_y'] = tuple(f'{prefix}/y/l{i}' for i in range(9))
    return result


def _construct(A, P, bit, *, context, role, bit_index, operation_id,
               claimed_E=AUTO, claimed_R=AUTO):
    _hosted_guard()
    _parameters(context, role, bit_index, operation_id)
    _bit(bit)
    curve = curve_for_role(role)
    a = encoded_point(A, role=role, label='A', canonical_form=claimed_E is AUTO)
    p = encoded_point(P, role=role, label='P', canonical_form=claimed_E is AUTO)
    if claimed_E is AUTO:
        if not curve.valid(a.native()) or not curve.valid(p.native()):
            raise ValueError('explicit E claim required for invalid input-point diagnostics')
        e = EncodedPoint.of(curve.add(a.native(), p.native()))
    else:
        e = encoded_point(claimed_E, role=role, label='E claim')
    selected_r = a if bit == 0 else e
    r = encoded_point(selected_r if claimed_R is AUTO else claimed_R, role=role, label='R claim')
    valid_inputs = (curve.valid(a.native()) and curve.valid(p.native())
        and (not a.infinity or not (a.x or a.y)) and (not p.infinity or not (p.x or p.y)))
    reference_e = EncodedPoint.of(curve.add(a.native(), p.native())) if valid_inputs else None
    reference_r = (a if bit == 0 else reference_e) if valid_inputs else None
    child, child_values = point_add_trace(curve, a, p, claimed_output=e, context=context,
        operation_id=operation_id+'/complete-add', multiplication_backend='convolution-v1')
    child_spec = GraphSpec.from_program(child)
    if (len(child.words) != CHILD_WORDS or len(child.constraints) != CHILD_ARITHMETIC
            or len(child.fields) != CHILD_FIELDS or len(child_spec.leaves) != 6151):
        raise ValueError('original complete convolution point-addition census changed')
    builder = ConvolutionTraceBuilder(role, operation_id, context)
    builder.words.update(child.words)
    builder.fields.update(child.fields)
    builder.values.update(child_values)
    builder.constraints.extend(child.constraints)
    ports = _ports()
    selector = builder.small(ports['bit'], bit, 2)
    delta = builder.small(ports['infinity_delta'], a.infinity ^ e.infinity, 2)
    masked = builder.small(ports['infinity_masked'], bit & (a.infinity ^ e.infinity), 2)
    r_inf = builder.small(ports['R_infinity'], r.infinity, 2)
    rx, ry = builder.field('selected/x', r.x), builder.field('selected/y', r.y)
    builder.check('bool_xor', (ports['A_infinity'], ports['E_infinity'], delta))
    builder.check('bool_and', (selector, delta, masked))
    builder.check('bool_xor', (ports['A_infinity'], masked, r_inf))
    for case, label in ((0, 'A'), (1, 'E')):
        builder.check('gate_equal', (selector,)+rx+ports[label+'_x'], (case,))
        builder.check('gate_equal', (selector,)+ry+ports[label+'_y'], (case,))
    builder.check('point_form', (r_inf,)+rx+ry)
    program, assignment = builder.finish()
    program._admit(assignment)
    spec = GraphSpec.from_program(program)
    leaf_map = tuple(range(CHILD_ARITHMETIC))+tuple(ARITHMETIC+j for j in range(CHILD_FIELDS))
    if (len(program.words) != WORDS or len(program.constraints) != ARITHMETIC
            or len(program.fields) != FIELDS or len(spec.leaves) != LEAVES
            or program.words[:CHILD_WORDS] != child.words
            or program.constraints[:CHILD_ARITHMETIC] != child.constraints
            or program.fields[:CHILD_FIELDS] != child.fields
            or spec.field_leaves != tuple((name, ARITHMETIC+j) for j, (name, _) in enumerate(child.fields))
                +(('selected/x', 6159), ('selected/y', 6160))):
        raise ValueError('conditional point must preserve child and append exactly22 words/8 arithmetic/2 fields')
    old_bodies, bodies = dict(child_spec.bodies), dict(spec.bodies)
    for before, after in enumerate(leaf_map):
        old, new = child_spec.leaves[before], spec.leaves[after]
        if old != new or old_bodies[old.body_sha256] != bodies[new.body_sha256]:
            raise ValueError('complete child body/alias/bound projection changed under selector')
    positions = {word: i for i, (word, _) in enumerate(program.words)}
    bit_slot = positions[selector]
    actual_bits = tuple((ordinal, formal) for ordinal, leaf in enumerate(spec.leaves)
                       for formal, word in enumerate(leaf.wires) if word == bit_slot)
    if bit_slot != CHILD_WORDS or actual_bits != BIT_OCCURRENCES:
        raise ValueError('selected bit must use exactly its five actual point predicate occurrences')
    maps = dict(schema=MAP_SCHEMA,
        child=dict(operation_id=child.operation_id, program_sha256=child.digest().hex(),
            catalogue_id=child_spec.digest().hex(), word_map=tuple(range(CHILD_WORDS)),
            leaf_map=leaf_map, fields=tuple(name for name, _ in child.fields)),
        ports=ports, port_indices={key: tuple(positions[word] for word in value) if type(value) is tuple
                                  else positions[value] for key, value in ports.items()},
        selector_constraints=dict(SELECTOR_ORDINALS), selected_bit_occurrences=BIT_OCCURRENCES,
        R_canonical_field_leaves=(6159, 6160), original_field_leaves=tuple(6124+j for j in range(35)),
        point_form_ordinal=6123, bit_index=bit_index,
        coordinate_outputs_are_asserted_ports=True, all_child_predicates_active=True)
    raw_maps = _canonical(maps)
    metadata = dict(schema=SCHEMA, context=context.hex(), field_role=role,
        scalar_field_role=curve.name+'_scalar', curve=curve.name, bit_index=bit_index,
        operation_id=operation_id, program_sha256=program.digest().hex(), catalogue_id=spec.digest().hex(),
        source_maps_sha256=sha256(raw_maps).hexdigest(), words=WORDS, arithmetic_constraints=ARITHMETIC,
        canonical_fields=FIELDS, leaves=LEAVES, relation='E=A+P; R=A if b=0 else E',
        infinity_relation='d=A_inf XOR E_inf; m=b AND d; R_inf=A_inf XOR m',
        scope='one conditional point relation given an external bit and A/P ports; origins/IPA remain open')
    raw_metadata = _canonical(metadata)
    return dict(program=program, spec=spec, assignment=assignment, ports=ports,
        source_sha256=sha256(SOURCE_DOMAIN+raw_metadata).digest(),
        source_maps_sha256=sha256(raw_maps).digest(), metadata=raw_metadata, maps=raw_maps,
        A=a, P=p, E=e, R=r, reference_E=reference_e, reference_R=reference_r)


@dataclass(frozen=True, init=False)
class ConditionalPointBinding:
    plan: object
    program: object
    spec: GraphSpec
    input_bit: int
    A: EncodedPoint
    P: EncodedPoint
    E: EncodedPoint
    R: EncodedPoint
    reference_E: EncodedPoint | None
    reference_R: EncodedPoint | None
    _assignment: tuple

    def __init__(self, *args, **kwargs):
        raise TypeError('bind through the sealed conditional point plan')

    assignment = property(lambda self: dict(self._assignment))
    ports = property(lambda self: self.plan.ports)
    metadata = property(lambda self: self.plan.metadata)
    source_maps = property(lambda self: self.plan.source_maps)
    source_sha256 = property(lambda self: self.plan.source_sha256)
    source_maps_sha256 = property(lambda self: self.plan.source_maps_sha256)


@dataclass(frozen=True, init=False)
class ConditionalPointPlan:
    context: bytes
    role: str
    bit_index: int
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
        raise TypeError('use the hosted conditional point factory; no imported child/map authority')

    assignment = property(lambda self: dict(self._assignment))
    ports = property(lambda self: MappingProxyType(dict(self._ports)))
    metadata = property(lambda self: json.loads(self._metadata))
    source_maps = property(lambda self: json.loads(self._maps))

    def bind(self, A, P, bit, *, claimed_E=AUTO, claimed_R=AUTO):
        _hosted_guard()
        built = _construct(A, P, bit, context=self.context, role=self.role, bit_index=self.bit_index,
            operation_id=self.operation_id, claimed_E=claimed_E, claimed_R=claimed_R)
        if (built['program'].digest() != self.program.digest() or built['spec'].digest() != self.spec.digest()
                or built['source_sha256'] != self.source_sha256
                or built['source_maps_sha256'] != self.source_maps_sha256):
            raise ValueError('fresh conditional point binding changed sealed topology/source identity')
        return _make(ConditionalPointBinding, plan=self, program=built['program'], spec=built['spec'],
            input_bit=bit, A=built['A'], P=built['P'], E=built['E'], R=built['R'],
            reference_E=built['reference_E'], reference_R=built['reference_R'],
            _assignment=tuple(built['assignment'].items()))

    def summary(self):
        result = dict(schema=SCHEMA, source_sha256=self.source_sha256.hex(), field_role=self.role,
            bit_index=self.bit_index, words=WORDS, leaves=LEAVES, canonical_fields=FIELDS,
            conditional_point_graph_constructed=True, complete_child_preserved=True)
        result.update({flag: False for flag in FALSE_FLAGS})
        return result


def build_conditional_point(*, context, role, bit_index=0, operation_id='conditional-point'):
    _hosted_guard()
    _parameters(context, role, bit_index, operation_id)
    built = _construct(None, None, 0, context=context, role=role,
                       bit_index=bit_index, operation_id=operation_id)
    return _make(ConditionalPointPlan, context=context, role=role, bit_index=bit_index,
        operation_id=operation_id, program=built['program'], spec=built['spec'],
        source_sha256=built['source_sha256'], source_maps_sha256=built['source_maps_sha256'],
        _assignment=tuple(built['assignment'].items()), _ports=tuple(built['ports'].items()),
        _metadata=built['metadata'], _maps=built['maps'])
