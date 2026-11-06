"""Sealed mixed-role RHO/c chain -> fixed scalar bit -> conditional point relation.

The original nine chain components are unchanged. A tenth component reconstructs
all255 bits from its actual Uniform result limbs; its canonical guard244 remains
in the ninth component. The eleventh component checks complete E=A+P and R=A+bP.
Only the chosen bound2 word crosses from scalar role to the corresponding curve
base role. This is one bit's point relation, not a scalar multiplication or IPA.
"""
from dataclasses import dataclass
from hashlib import sha256
import json
import os
import sys
from types import MappingProxyType

from byte_rho_chain import (ByteRhoChainComponentDescriptor, build_byte_rho_chain,
                            _parameters as _chain_parameters)
from conditional_point import (AUTO, BIT_OCCURRENCES, EncodedPoint,
    build_conditional_point, curve_for_role, encoded_point,
    _parameters as _point_parameters)
from scalar_bits import (build_scalar_bits, limb_bits,
                         _parameters as _bits_parameters)
from script import BASE, limbs
from trace import ID, ROLES

SCHEMA = 'bitvm2-nova-byte-c-bit-point-source/v1'
MAP_SCHEMA = 'bitvm2-nova-byte-c-bit-point-maps/v1'
SOURCE_DOMAIN = b'BITVM2-NOVA/BYTE-C-BIT-POINT-SOURCE/v1\x00'
MAX_MAP_BYTES, MAX_MANIFEST_BYTES = 8 << 20, 1 << 20
FALSE_FLAGS = ('eval_w_canonical_in_script', 'eval_w_proof_origin_bound',
    'prior_state_transcript_bound', 'coefficient_proof_origins_bound',
    'A_proof_origin_bound', 'P_key_origin_bound', 'sumcheck_equation_verified',
    'scalar_multiplication_verified', 'ipa_verified', 'full_transcript_verified',
    'transcript_verified', 'nova_transcript_verified', 'proof_verified',
    'bitvm2_script_verified', 'production_assertion_binding', 'bitcoin_transaction_graph')


def _hosted_guard():
    if (os.environ.get('GITHUB_ACTIONS') != 'true'
            or os.environ.get('RUNNER_OS') != 'Linux' or sys.platform != 'linux'):
        raise ValueError('BYTE c-bit point construction/binding is hosted GitHub Linux only')


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def _hash(value):
    return sha256(_canonical(value)).hexdigest()


def _hex_digest(value):
    if type(value) is bytes and len(value) == 32:
        return value.hex()
    if type(value) is str and len(value) == 64:
        try:
            if bytes.fromhex(value).hex() == value:
                return value
        except ValueError:
            pass
    raise ValueError('canonical source digest required')


def _integer(value, lo, hi, label):
    if type(value) is not int or not lo <= value <= hi:
        raise ValueError(f'canonical {label} required')
    return value


def point_role_for_scalar(role):
    # Select by semantic ROLE NAME, never by modulus equality across the cycle.
    if type(role) is not str or role not in ('pallas_scalar', 'vesta_scalar'):
        raise ValueError('explicit pallas_scalar or vesta_scalar role required')
    return 'pallas_base' if role == 'pallas_scalar' else 'vesta_base'


def _operations(operation_id, bit_index):
    return (operation_id+'/chain', f'{operation_id}/scalar-bits/bit/{bit_index}',
            f'{operation_id}/point/bit/{bit_index}')


def _parameters(context, role, rho_counter, bit_index, operation_id):
    point_role = point_role_for_scalar(role)
    _integer(bit_index, 0, 254, 'verifier-fixed bit index0..254')
    if type(operation_id) is not str or not ID.fullmatch(operation_id):
        raise ValueError('bounded outer operation identifier required')
    chain_op, bits_op, point_op = _operations(operation_id, bit_index)
    # All old nested block/round IDs and both new operation families preflight
    # before the first full chain/permutation/point allocation.
    _chain_parameters(context, role, rho_counter, chain_op)
    _bits_parameters(context, role, bit_index, bits_op)
    _point_parameters(context, point_role, bit_index, point_op)


def bit_global_id(index):
    _integer(index, 0, 254, 'bit index0..254')
    return f'c/bits/bit/{index}'


def bridge_global_id(local_name):
    if type(local_name) is not str:
        raise ValueError('actual scalar bridge word name required')
    if local_name.startswith('scalar/l'):
        raw = local_name[len('scalar/l'):]
        if raw.isascii() and raw.isdigit() and str(int(raw)) == raw and 0 <= int(raw) < 9:
            return f'c/reduction/result/l{raw}'
    if local_name.startswith('bit/'):
        raw = local_name[len('bit/'):]
        if raw.isascii() and raw.isdigit() and str(int(raw)) == raw and 0 <= int(raw) < 255:
            return bit_global_id(int(raw))
    raise ValueError('closed nine-limb/255-bit bridge name required')


def point_global_id(local_name, *, role, bit_index):
    curve = curve_for_role(role)
    _integer(bit_index, 0, 254, 'fixed point bit index')
    if type(local_name) is not str or not ID.fullmatch(local_name):
        raise ValueError('actual bounded point word name required')
    result = bit_global_id(bit_index) if local_name == 'select/bit' else f'point/{curve.name}/{local_name}'
    if not ID.fullmatch(result):
        raise ValueError('point global namespace exceeds unchanged identifier cap')
    return result


def _make(cls, **fields):
    result = object.__new__(cls)
    for key, value in fields.items():
        object.__setattr__(result, key, value)
    return result


@dataclass(frozen=True, init=False)
class CBitPointComponentSource:
    index: int
    branch: str
    descriptor: ByteRhoChainComponentDescriptor
    child: object
    program: object
    spec: object
    global_ids: tuple[str, ...]
    _program_manifest: bytes | None
    _source_manifest: bytes
    _source_maps: bytes

    def __init__(self, *args, **kwargs):
        raise TypeError('regenerate components from the sealed c-bit point plan')

    child_program_manifest = property(lambda self: None if self._program_manifest is None else json.loads(self._program_manifest))
    child_source_manifest = property(lambda self: json.loads(self._source_manifest))
    child_source_maps = property(lambda self: json.loads(self._source_maps))


@dataclass(frozen=True, init=False)
class CBitPointComponentBinding:
    index: int
    branch: str
    descriptor: ByteRhoChainComponentDescriptor
    program: object
    spec: object
    global_ids: tuple[str, ...]
    _assignment: tuple
    _program_manifest: bytes | None
    _source_manifest: bytes
    _source_maps: bytes

    def __init__(self, *args, **kwargs):
        raise TypeError('stream components from the sealed c-bit point binding')

    assignment = property(lambda self: dict(self._assignment))
    child_program_manifest = property(lambda self: None if self._program_manifest is None else json.loads(self._program_manifest))
    child_source_manifest = property(lambda self: json.loads(self._source_manifest))
    child_source_maps = property(lambda self: json.loads(self._source_maps))


def _new_source(index, child, *, role, point_role, rho_counter, bit_index):
    bits = index == 9
    ids = (tuple(bridge_global_id(name) for name, _ in child.spec.words) if bits else
           tuple(point_global_id(name, role=point_role, bit_index=bit_index) for name, _ in child.spec.words))
    expected = (264, 9) if bits else (7498, 6161)
    actual_role = role if bits else point_role
    if ((len(child.spec.words), len(child.spec.leaves)) != expected
            or child.program.field_role != actual_role or child.spec.field_role != actual_role
            or len(set(ids)) != len(ids) or child.spec.program_sha256 != child.program.digest().hex()):
        raise ValueError('fresh mixed-role child shape/identity changed')
    raw_maps, raw_metadata = _canonical(child.source_maps), _canonical(child.metadata)
    maps_sha = _hex_digest(child.source_maps_sha256)
    if sha256(raw_maps).hexdigest() != maps_sha:
        raise ValueError('fresh child source-map snapshot changed sealed digest')
    if len(raw_maps) > MAX_MAP_BYTES or len(raw_metadata) > MAX_MANIFEST_BYTES:
        raise ValueError('child metadata exceeds unchanged bounded sidecar caps')
    descriptor = _make(ByteRhoChainComponentDescriptor, index=index,
        branch='scalar-bits' if bits else 'conditional-point',
        kind='scalar-bits' if bits else 'conditional-point', operation_id=child.program.operation_id,
        program_sha256=child.program.digest().hex(), catalogue_id=child.spec.digest().hex(),
        source_sha256=_hex_digest(child.source_sha256), source_maps_sha256=maps_sha,
        global_ids_sha256=_hash(ids), words=expected[0], leaves=expected[1],
        counter=rho_counter+1, field_role=actual_role,
        program_identity_kind='Program.digest (fixed-trace/v2)' if bits else 'ConvolutionProgram.digest (fixed-trace/v2)')
    return _make(CBitPointComponentSource, index=index, branch=descriptor.branch, descriptor=descriptor,
        child=child, program=child.program, spec=child.spec, global_ids=ids,
        _program_manifest=None, _source_manifest=raw_metadata, _source_maps=raw_maps)


def _validate_new_maps(bits_source, point_source, *, bit_index):
    expected_bits = tuple(f'c/reduction/result/l{i}' for i in range(9))+tuple(bit_global_id(i) for i in range(255))
    if bits_source.global_ids != expected_bits:
        raise ValueError('bridge must share exactly nine upstream limbs and255 distinct Boolean slots')
    chosen = bit_global_id(bit_index)
    if (set(bits_source.global_ids) & set(point_source.global_ids) != {chosen}
            or sum(name.startswith('point/') for name in point_source.global_ids) != 7497
            or point_source.global_ids[7476] != chosen
            or tuple(bound for _, bound in bits_source.spec.words) != (BASE,)*9+(2,)*255
            or point_source.spec.words[7476][1] != 2):
        raise ValueError('the selected bound2 bit must be the only scalar/base-role shared word')


def _joins(chain, bits_source, point_source, *, bit_index):
    # The fresh sealed chain factory produced these actual interface rows; no
    # caller can submit a stand-alone replay/map to this composition.
    uniform = chain.source_maps['components'][8]
    rows = {record['word_index']: record for record in uniform['interfaces']}
    bridge = bits_source.child
    links = []
    for i in range(9):
        source = rows[129+i]
        target = bridge.spec.leaves[i]
        expected_id = f'c/reduction/result/l{i}'
        if (source['global_id'] != expected_id or source['bound'] != BASE
                or source['occurrences'] != [[72+i, 0], [244, i]]
                or bits_source.global_ids[i] != expected_id
                or target.kind != 'bits' or target.argument != ((29 if i < 8 else 23),)
                or target.wires[0] != i):
            raise ValueError('canonical Uniform limb/actual reconstruction/guard link changed')
        links.append(dict(global_id=expected_id, source_component=8, source_word=129+i,
            source_ordinal=72+i, source_occurrence=0, canonical_ordinal=244, canonical_occurrence=i,
            target_component=9, target_word=i, target_ordinal=i, target_occurrence=0))
    width = 29 if bit_index//29 < 8 else 23
    bit_ordinal, bit_formal = bit_index//29, width-bit_index % 29
    bit_word = 9+bit_index
    if bridge.spec.leaves[bit_ordinal].wires[bit_formal] != bit_word:
        raise ValueError('public LSB bit index detached from actual MSB predicate occurrence')
    point_word = 7476
    actual = tuple((ordinal, formal) for ordinal, leaf in enumerate(point_source.spec.leaves)
                   for formal, word in enumerate(leaf.wires) if word == point_word)
    if actual != BIT_OCCURRENCES or point_source.spec.words[point_word][1] != 2:
        raise ValueError('point selector detached from five actual bound2 predicate occurrences')
    bit_link = dict(global_id=bit_global_id(bit_index), source_component=9, source_word=bit_word,
        source_ordinal=bit_ordinal, source_occurrence=bit_formal, target_component=10,
        target_word=point_word, target_occurrences=BIT_OCCURRENCES, cross_role_bound=2)
    return tuple(links), bit_link


def _record(index, descriptor, program, spec, ids, assignment, program_manifest, metadata, maps):
    if (index != descriptor.index or spec.digest().hex() != descriptor.catalogue_id
            or _hash(ids) != descriptor.global_ids_sha256
            or len(ids) != len(spec.words) or len(set(ids)) != len(ids)
            or set(assignment) != {word for word, _ in spec.words}):
        raise ValueError('actual component changed its sealed graph/global-map/assignment coverage')
    for word, bound in spec.words:
        value = assignment[word]
        if type(value) is not int or not 0 <= value < bound:
            raise ValueError('actual numeric assertion escaped its unchanged decoder bound')
    return _make(CBitPointComponentBinding, index=index, branch=descriptor.branch,
        descriptor=descriptor, program=program, spec=spec, global_ids=ids,
        _assignment=tuple(assignment.items()), _program_manifest=program_manifest,
        _source_manifest=metadata, _source_maps=maps)


def _actual_uniform_limbs(record):
    if record.index != 8 or record.program is None:
        raise ValueError('actual upstream Uniform component8 required')
    fields = dict(record.program.fields)
    words = fields.get('result')
    if type(words) is not tuple or len(words) != 9:
        raise ValueError('actual Uniform result must remain one nine-limb field')
    positions = {word: i for i, (word, _) in enumerate(record.spec.words)}
    if (tuple(positions[word] for word in words) != tuple(range(129, 138))
            or record.spec.leaves[244].kind != 'field_valid'
            or record.spec.leaves[244].wires != tuple(range(129, 138))):
        raise ValueError('canonical Uniform guard244 must remain on the actual result limbs')
    values = record.assignment
    for index, word in enumerate(words):
        if (record.global_ids[positions[word]] != f'c/reduction/result/l{index}'
                or record.spec.words[positions[word]][1] != BASE
                or record.spec.leaves[72+index].kind != 'conv_reconstruct'
                or record.spec.leaves[72+index].wires[0] != positions[word]):
            raise ValueError('actual Uniform limb reconstruction/opening was replaced')
    return tuple(values[word] for word in words)


@dataclass(frozen=True, init=False)
class CBitPointBinding:
    plan: object
    chain: object
    A: EncodedPoint
    P: EncodedPoint
    E: EncodedPoint
    R: EncodedPoint
    reference_E: EncodedPoint | None
    reference_R: EncodedPoint | None
    scalar_value: int
    scalar_quotient_value: int
    selected_bit: int
    canonical_bit: int
    bits: tuple[int, ...]
    claimed_bit: int | None
    claimed_E: object
    claimed_R: object
    uniform_alias: bool

    def __init__(self, *args, **kwargs):
        raise TypeError('bind through the sealed c-bit point factory')

    raw_c = property(lambda self: self.chain.raw_c)
    input_limbs = property(lambda self: tuple(limbs(self.scalar_value)))

    def iter_components(self):
        """Stream eleven actual registries; release yielded graph/value aliases before next."""
        _hosted_guard()

        def stream():
            actual_limbs = None
            for old in self.chain.iter_components():
                index = old.index
                values = old.assignment
                program, spec = old.program, old.spec
                alias = None
                if index == 8 and self.uniform_alias:
                    # This closed source helper accepts raw bytes and trusted
                    # policy only; no caller-owned assignment/receipt is admitted.
                    from uniform_alias import build_uniform_alias
                    alias = build_uniform_alias(self.chain.raw_c, context=self.plan.context,
                        role=self.plan.role, operation_id=old.descriptor.operation_id)
                    program, spec, values = alias.program, alias.spec, alias.assignment
                    if (alias.result_value != self.scalar_value
                            or alias.quotient_value != self.scalar_quotient_value
                            or spec.digest() != old.spec.digest()
                            or program.digest() != old.program.digest()):
                        raise ValueError('closed Uniform alias changed source identity or requested c+p/q-1 relation')
                descriptor = self.plan.components[index]
                if old.descriptor.json() != descriptor.json():
                    raise ValueError('fresh chain record changed inherited component descriptor')
                result = _record(index, descriptor, program, spec, old.global_ids, values,
                    old._program_manifest, old._source_manifest, old._source_maps)
                if index == 8:
                    actual_limbs = _actual_uniform_limbs(result)
                    if sum(value << (29*i) for i, value in enumerate(actual_limbs)) != self.scalar_value:
                        raise ValueError('actual streamed Uniform limbs differ from the selected scalar assertion')
                del old, values, program, spec, alias
                yield result
                del result
            if actual_limbs is None:
                raise ValueError('missing actual Uniform source before scalar-bit/point composition')
            source = self.plan.regenerate_component(9)
            bound = source.child.bind(actual_limbs, claimed_bit=self.claimed_bit)
            if (bound.input_limbs != actual_limbs or bound.selected_bit != self.selected_bit
                    or tuple(bound.bits) != self.bits or bound.spec.digest() != source.spec.digest()):
                raise ValueError('fresh scalar bits detached from actual Uniform limb assignment')
            result = _record(9, source.descriptor, bound.program, bound.spec, source.global_ids,
                bound.assignment, None, source._source_manifest, source._source_maps)
            del source, bound, actual_limbs
            yield result
            del result
            source = self.plan.regenerate_component(10)
            bound = source.child.bind(self.A, self.P, self.selected_bit,
                claimed_E=self.claimed_E, claimed_R=self.claimed_R)
            if (bound.input_bit != self.selected_bit or bound.E != self.E or bound.R != self.R
                    or bound.spec.digest() != source.spec.digest()):
                raise ValueError('fresh point selector detached from actual selected bridge bit')
            result = _record(10, source.descriptor, bound.program, bound.spec, source.global_ids,
                bound.assignment, None, source._source_manifest, source._source_maps)
            del source, bound
            yield result
            del result
        return stream()

    def summary(self):
        def point(value):
            return None if value is None else dict(infinity=value.infinity, x=str(value.x), y=str(value.y))
        result = dict(source_sha256=self.plan.source_sha256.hex(), field_role=self.plan.role,
            point_field_role=self.plan.point_role, bit_index=self.plan.bit_index,
            selected_bit=self.selected_bit, canonical_bit=self.canonical_bit,
            uniform_alias_diagnostic=self.uniform_alias, scalar_value=str(self.scalar_value),
            conditional_bit_point_binding_constructed=True, E=point(self.E), R=point(self.R),
            reference_E=point(self.reference_E), reference_R=point(self.reference_R),
            selected_bit_matches_canonical_challenge=self.selected_bit == self.canonical_bit,
            R_matches_honest_reference=self.reference_R is not None and self.R == self.reference_R)
        result.update({flag: False for flag in FALSE_FLAGS})
        return result


def _bind(plan, eval_w, prior_state, compressed_coefficients, A, P, *, claimed_bit=None,
          claimed_E=AUTO, claimed_R=AUTO, uniform_alias=False):
    _hosted_guard()
    if type(plan) is not CBitPointPlan or type(uniform_alias) is not bool:
        raise ValueError('fresh sealed c-bit point plan and closed diagnostic policy required')
    if claimed_bit is not None:
        _integer(claimed_bit, 0, 1, 'claimed selected Boolean bit')
    chain = plan.chain.bind(eval_w, prior_state, compressed_coefficients)
    modulus = ROLES[plan.role]
    scalar = chain.c_result_value+modulus if uniform_alias else chain.c_result_value
    quotient = chain.c_quotient_value-1 if uniform_alias else chain.c_quotient_value
    if uniform_alias and (quotient < 0 or not modulus <= scalar < 1 << 255):
        raise ValueError('closed c+modulus/q-1 alias must fit255 bits with unsigned quotient')
    scalar_limbs = tuple(limbs(scalar))
    bits = limb_bits(scalar_limbs, bit_index=plan.bit_index, claimed_bit=claimed_bit)
    bit = bits[plan.bit_index]
    curve = curve_for_role(plan.point_role)
    a = encoded_point(A, role=plan.point_role, label='A', canonical_form=claimed_E is AUTO)
    p = encoded_point(P, role=plan.point_role, label='P', canonical_form=claimed_E is AUTO)
    valid_inputs = (curve.valid(a.native()) and curve.valid(p.native())
        and (not a.infinity or not (a.x or a.y)) and (not p.infinity or not (p.x or p.y)))
    if claimed_E is AUTO:
        if not valid_inputs:
            raise ValueError('explicit E claim required for invalid input-point diagnostics')
        e = EncodedPoint.of(curve.add(a.native(), p.native()))
    else:
        e = encoded_point(claimed_E, role=plan.point_role, label='E claim')
    r = encoded_point((a if bit == 0 else e) if claimed_R is AUTO else claimed_R,
                      role=plan.point_role, label='R claim')
    canonical_bit = (chain.c_result_value >> plan.bit_index) & 1
    reference_e = EncodedPoint.of(curve.add(a.native(), p.native())) if valid_inputs else None
    reference_r = (a if canonical_bit == 0 else reference_e) if valid_inputs else None
    return _make(CBitPointBinding, plan=plan, chain=chain, A=a, P=p, E=e, R=r,
        reference_E=reference_e, reference_R=reference_r, scalar_value=scalar,
        scalar_quotient_value=quotient, selected_bit=bit, canonical_bit=canonical_bit,
        bits=bits, claimed_bit=claimed_bit, claimed_E=claimed_E, claimed_R=claimed_R,
        uniform_alias=uniform_alias)


def _bind_uniform_alias(plan, eval_w, prior_state, compressed_coefficients, A, P, *,
                        claimed_E=AUTO, claimed_R=AUTO):
    """Closed c+p/q-1 profile only; actual rewitnessing uses root's fresh helper."""
    _hosted_guard()
    return _bind(plan, eval_w, prior_state, compressed_coefficients, A, P,
        claimed_E=claimed_E, claimed_R=claimed_R, uniform_alias=True)


@dataclass(frozen=True, init=False)
class CBitPointPlan:
    context: bytes
    role: str
    point_role: str
    curve_name: str
    rho_counter: int
    bit_index: int
    operation_id: str
    chain: object
    components: tuple
    source_sha256: bytes
    source_maps_sha256: bytes
    _manifest: bytes
    _maps: bytes

    def __init__(self, *args, **kwargs):
        raise TypeError('use the hosted c-bit point factory; no imported graph/map/receipt authority')

    manifest = property(lambda self: json.loads(self._manifest))
    source_maps = property(lambda self: json.loads(self._maps))

    @property
    def ports(self):
        curve = self.curve_name
        ports = dict(self.chain.ports)
        ports.update(challenge_bits=tuple(bit_global_id(i) for i in range(255)),
            selected_bit=bit_global_id(self.bit_index))
        for label, prefix in (('A', 'left'), ('P', 'right'), ('E', 'result'), ('R', 'selected')):
            ports[label+'_infinity'] = f'point/{curve}/{prefix}/infinity'
            ports[label+'_x'] = tuple(f'point/{curve}/{prefix}/x/l{i}' for i in range(9))
            ports[label+'_y'] = tuple(f'point/{curve}/{prefix}/y/l{i}' for i in range(9))
        return MappingProxyType(ports)

    def regenerate_component(self, index):
        _hosted_guard()
        _integer(index, 0, 10, 'component index0..10')
        if index < 9:
            old = self.chain.regenerate_component(index)
            if old.descriptor.json() != self.components[index].json():
                raise ValueError('fresh inherited chain component changed source identity')
            return _make(CBitPointComponentSource, index=index, branch=old.branch,
                descriptor=old.descriptor, child=old.child, program=old.program, spec=old.spec,
                global_ids=old.global_ids, _program_manifest=old._program_manifest,
                _source_manifest=old._source_manifest, _source_maps=old._source_maps)
        _, bits_op, point_op = _operations(self.operation_id, self.bit_index)
        child = (build_scalar_bits(context=self.context, role=self.role, bit_index=self.bit_index,
                                   operation_id=bits_op) if index == 9 else
                 build_conditional_point(context=self.context, role=self.point_role,
                                         bit_index=self.bit_index, operation_id=point_op))
        source = _new_source(index, child, role=self.role, point_role=self.point_role,
                             rho_counter=self.rho_counter, bit_index=self.bit_index)
        if source.descriptor.json() != self.components[index].json():
            raise ValueError('fresh scalar/point component changed sealed source/global identity')
        return source

    def bind(self, eval_w, prior_state, compressed_coefficients, A, P, *, claimed_bit=None,
             claimed_E=AUTO, claimed_R=AUTO):
        _hosted_guard()
        return _bind(self, eval_w, prior_state, compressed_coefficients, A, P,
                     claimed_bit=claimed_bit, claimed_E=claimed_E, claimed_R=claimed_R)

    def summary(self):
        result = dict(schema=SCHEMA, source_sha256=self.source_sha256.hex(), field_role=self.role,
            point_field_role=self.point_role, curve=self.curve_name, bit_index=self.bit_index,
            components=11, leaves=153213, local_declared_words=156163,
            unique_global_words=155107, cached_signature_reuses=1056,
            new_shared_limb_words=9, new_shared_bit_words=1, new_opening_comparisons=14,
            new_canonical_opening_comparisons=9, new_total_opening_comparisons=23,
            c_bit_point_topology_constructed=True)
        result.update({flag: False for flag in FALSE_FLAGS})
        return result


def build_byte_c_bit_point(*, context, role, rho_counter, bit_index=0, operation_id='byte-c-bit-point'):
    _hosted_guard()
    _parameters(context, role, rho_counter, bit_index, operation_id)
    point_role = point_role_for_scalar(role)
    chain_op, bits_op, point_op = _operations(operation_id, bit_index)
    chain = build_byte_rho_chain(context=context, role=role, rho_counter=rho_counter,
                                 operation_id=chain_op)
    bridge = build_scalar_bits(context=context, role=role, bit_index=bit_index, operation_id=bits_op)
    bits_source = _new_source(9, bridge, role=role, point_role=point_role,
                              rho_counter=rho_counter, bit_index=bit_index)
    point = build_conditional_point(context=context, role=point_role, bit_index=bit_index,
                                    operation_id=point_op)
    point_source = _new_source(10, point, role=role, point_role=point_role,
                               rho_counter=rho_counter, bit_index=bit_index)
    _validate_new_maps(bits_source, point_source, bit_index=bit_index)
    scalar_links, bit_link = _joins(chain, bits_source, point_source, bit_index=bit_index)
    descriptors = chain.components+(bits_source.descriptor, point_source.descriptor)
    local = sum(item.words for item in descriptors)
    leaves = sum(item.leaves for item in descriptors)
    if (local != 156163 or leaves != 153213 or chain.manifest['unique_global_words']+255+7497 != 155107
            or chain.manifest['cached_signature_reuses']+9+1 != 1056):
        raise ValueError('fixed eleven-component mixed-role declaration census changed')
    maps = dict(schema=MAP_SCHEMA, chain_source_sha256=chain.source_sha256.hex(),
        chain_source_maps_sha256=chain.source_maps_sha256.hex(), chain_component_indices=tuple(range(9)),
        components=[descriptor.json() for descriptor in descriptors],
        scalar_to_bits=scalar_links, selected_bit_to_point=bit_link,
        normative_global_maps=dict(chain='unchanged nine-component chain global IDs',
            scalar_limbs='c/reduction/result/l{0..8}', scalar_bits='c/bits/bit/{0..254}',
            point_private=f'point/{curve_for_role(point_role).name}/<actual-point-local>',
            point_selected_bit=bit_global_id(bit_index)),
        new_intersections=({'left': 8, 'right': 9, 'words': 9,
                            'global_ids_sha256': _hash(tuple(f'c/reduction/result/l{i}' for i in range(9)))},
                           {'left': 9, 'right': 10, 'words': 1, 'global_ids_sha256': _hash((bit_global_id(bit_index),))}),
        chain_point_intersection=(), cross_role_shared_words=(bit_global_id(bit_index),),
        scalar_field_role=role, point_field_role=point_role, bit_index=bit_index,
        upstream_canonical_guard=dict(component_index=8, ordinal=244, limb_indices=tuple(range(129, 138))),
        leaves=153213, local_declared_words=156163, unique_global_words=155107, cached_signature_reuses=1056)
    raw_maps = _canonical(maps)
    if len(raw_maps) > MAX_MAP_BYTES:
        raise ValueError('compact mixed-role source maps exceed unchanged8MiB cap')
    maps_sha = sha256(raw_maps).digest()
    manifest = dict(schema=SCHEMA, context=context.hex(), field_role=role, point_field_role=point_role,
        curve=curve_for_role(point_role).name, rho_counter=rho_counter, c_counter=rho_counter+1,
        bit_index=bit_index, operation_id=operation_id, chain_operation_id=chain_op,
        chain_source_sha256=chain.source_sha256.hex(), chain_source_maps_sha256=chain.source_maps_sha256.hex(),
        component_order=tuple(item.branch for item in descriptors), components=[item.json() for item in descriptors],
        source_maps_sha256=maps_sha.hex(), leaves=153213, local_declared_words=156163,
        unique_global_words=155107, cached_signature_reuses=1056,
        relation='b=bit_k(canonical following-c); E=A+P; R=A if b=0 else E',
        commitment_order='external context -> mixed-role source/maps -> one global key pool -> eleven registries -> Scripts -> forest',
        scope='one verifier-fixed challenge-bit conditional point relation; proof/key origins, scalar multiplication and IPA remain open')
    raw = _canonical(manifest)
    if len(raw) > MAX_MANIFEST_BYTES:
        raise ValueError('compact mixed-role source manifest exceeds unchanged1MiB cap')
    del bridge, point, bits_source, point_source
    return _make(CBitPointPlan, context=context, role=role, point_role=point_role,
        curve_name=curve_for_role(point_role).name, rho_counter=rho_counter, bit_index=bit_index,
        operation_id=operation_id, chain=chain, components=descriptors,
        source_sha256=sha256(SOURCE_DOMAIN+raw).digest(), source_maps_sha256=maps_sha,
        _manifest=raw, _maps=raw_maps)
