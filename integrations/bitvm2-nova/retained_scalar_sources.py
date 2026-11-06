"""Retained scalar BYTE tape and eval_W encoding joined to the frozen point chain.

Only16 vector-length BYTEs are constants. The other96 tape BYTEs remain asserted
values, shared with their actual consumers. A canonically changed eval_W/c0/c2
can satisfy every local relation after coherent downstream re-witnessing. The
admitted reference proof SHA/offsets in metadata do NOT authenticate those claims
in Script. Whole-proof hashing, EOF/parsing, prior transcript and point/key
origins, production roots and transactions remain separate obligations.
"""
from dataclasses import dataclass
from hashlib import sha256
import json
import os
import sys
from types import MappingProxyType

from byte_c_bit_point import (AUTO, build_byte_c_bit_point,
    _parameters as _point_parameters)
from byte_rho_chain import ByteRhoChainComponentDescriptor
from eval_w_encoding import build_eval_w_encoding, _parameters as _eval_parameters
from retained_scalar_block import (build_retained_scalar_block,
    _parameters as _block_parameters, _asserted as _block_asserted)
from trace import ID, ROLES

SCHEMA = 'bitvm2-nova-retained-scalar-sources/v1'
MAP_SCHEMA = 'bitvm2-nova-retained-scalar-sources-maps/v1'
SOURCE_DOMAIN = b'BITVM2-NOVA/RETAINED-SCALAR-SOURCES/v1\x00'
MAX_MAP_BYTES, MAX_MANIFEST_BYTES = 8 << 20, 1 << 20
# Same independently pinned retained policy as retained_verifier.py. Caller
# objects must still be exact typed and independently re-admitted by the tape.
EXPECTED_POLICY_SHA256 = 'cdfa31622881cc1863abd1eb252c136184501785b4b02e9985e6ba0850b2ac54'
DIMENSION_SHA256 = 'de6333df2e41b5f5bae1c103fab862f8d6022fd54abeb80ba61920bc9f360edc'
PROFILE = {'pallas_scalar': (59, 19, 4624, 5180),
           'vesta_scalar': (44, 14, 10048, 10604)}
FALSE_FLAGS = ('eval_w_canonicality_script_relation_checked', 'proof_byte_origins_bound',
    'eval_w_proof_origin_bound', 'coefficient_proof_origins_bound',
    'whole_container_script_bound', 'proof_length_script_bound', 'proof_eof_script_bound',
    'proof_sha256_script_bound', 'bundle_sha256_script_bound', 'whole_proof_authenticated',
    'prior_state_transcript_bound', 'A_proof_origin_bound', 'P_key_origin_bound',
    'sumcheck_equation_verified', 'scalar_multiplication_verified', 'ipa_verified',
    'full_transcript_verified', 'transcript_verified', 'nova_transcript_verified',
    'proof_verified', 'bitvm2_script_verified', 'production_root_binding',
    'production_assertion_binding', 'bitcoin_transaction_graph',
    'complete_nova_verifier', 'complete_bitvm2_verifier')


def _hosted_guard():
    if (os.environ.get('GITHUB_ACTIONS') != 'true'
            or os.environ.get('RUNNER_OS') != 'Linux' or sys.platform != 'linux'):
        raise ValueError('retained scalar source composition is hosted GitHub Linux only')


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
    raise ValueError('canonical source SHA256 required')


def retained_profile(role):
    if type(role) is not str or role not in PROFILE:
        raise ValueError('retained pallas_scalar or vesta_scalar profile required')
    return PROFILE[role]


def _operations(operation_id):
    return operation_id+'/point', operation_id+'/proof/scalar-block', operation_id+'/proof/eval-w'


def _parameters(raw_bundle, expected, dimensions, context, role, bit_index, operation_id):
    rho_counter, _, _, _ = retained_profile(role)
    if type(operation_id) is not str or not ID.fullmatch(operation_id):
        raise ValueError('bounded retained scalar operation identifier required')
    point_op, block_op, eval_op = _operations(operation_id)
    # All existing nested IDs and new /uniform-reference IDs are checked before
    # the tape's tiny graph or the old five full permutations can allocate.
    _point_parameters(context, role, rho_counter, bit_index, point_op)
    _eval_parameters(context, role, eval_op)
    _block_parameters(raw_bundle, expected, dimensions, context, role, block_op)
    if (_hash(expected.json()) != EXPECTED_POLICY_SHA256
            or _hex_digest(dimensions.descriptor_sha256) != DIMENSION_SHA256
            or expected.bundle_bytes != 13220 or expected.proof_bytes != 12664
            or len(raw_bundle) != expected.bundle_bytes):
        raise ValueError('exact caller-owned retained policy/dimension identities and13220-byte container required')


def eval_w_global_id(index):
    if type(index) is not int or not 0 <= index < 32:
        raise ValueError('eval_W BYTE index0..31 required')
    return f'rho/message/eval_w/byte/{index}'


def coefficient_global_id(degree, index):
    if type(degree) is not int or degree not in (0, 2) or type(index) is not int or not 0 <= index < 32:
        raise ValueError('compressed coefficient degree0/2 and BYTE0..31 required')
    return f'c/coeff/{degree}/byte/{index}'


def tape_global_id(local_name, *, role):
    _, _, _, start = retained_profile(role)
    if type(local_name) is not str or not local_name.startswith('block/byte/'):
        raise ValueError('closed retained block BYTE name required')
    text = local_name[len('block/byte/'):]
    if not text.isascii() or not text.isdigit() or str(int(text)) != text or not 0 <= int(text) < 112:
        raise ValueError('canonical retained block index0..111 required')
    index = int(text)
    if index < 32:
        return eval_w_global_id(index)
    if index >= 48:
        return coefficient_global_id(0 if index < 80 else 2, (index-48) % 32)
    return f'proof/container-byte/{start+index}'


def encoder_global_id(local_name):
    if type(local_name) is not str or not ID.fullmatch(local_name):
        raise ValueError('actual bounded eval_W encoder local word required')
    if local_name.startswith('scalar/encoding/byte/'):
        text = local_name[len('scalar/encoding/byte/'):]
        if not text.isascii() or not text.isdigit() or str(int(text)) != text or not 0 <= int(text) < 32:
            raise ValueError('canonical eval_W input BYTE index0..31 required')
        return eval_w_global_id(int(text))
    result = 'eval-w/'+local_name
    if not ID.fullmatch(result):
        raise ValueError('eval_W private namespace exceeds unchanged cap')
    return result


def _make(cls, **fields):
    value = object.__new__(cls)
    for key, item in fields.items():
        object.__setattr__(value, key, item)
    return value


@dataclass(frozen=True, init=False)
class RetainedScalarComponentSource:
    index: int
    branch: str
    descriptor: object
    child: object
    program: object
    spec: object
    global_ids: tuple[str, ...]
    _program_manifest: bytes | None
    _source_manifest: bytes
    _source_maps: bytes

    def __init__(self, *args, **kwargs):
        raise TypeError('regenerate a component from the sealed retained scalar sources')

    child_program_manifest = property(lambda self: None if self._program_manifest is None else json.loads(self._program_manifest))
    child_source_manifest = property(lambda self: json.loads(self._source_manifest))
    child_source_maps = property(lambda self: json.loads(self._source_maps))


@dataclass(frozen=True, init=False)
class RetainedScalarComponentBinding:
    index: int
    branch: str
    descriptor: object
    program: object
    spec: object
    global_ids: tuple[str, ...]
    _assignment: tuple
    _program_manifest: bytes | None
    _source_manifest: bytes
    _source_maps: bytes

    def __init__(self, *args, **kwargs):
        raise TypeError('stream components from the sealed retained scalar binding')

    assignment = property(lambda self: dict(self._assignment))
    child_program_manifest = property(lambda self: None if self._program_manifest is None else json.loads(self._program_manifest))
    child_source_manifest = property(lambda self: json.loads(self._source_manifest))
    child_source_maps = property(lambda self: json.loads(self._source_maps))


def _new_source(index, child, *, role, rho_counter):
    tape = index == 11
    ids = tuple(tape_global_id(name, role=role) if tape else encoder_global_id(name)
                for name, _ in child.spec.words)
    shape = (112, 112) if tape else (55, 17)
    if ((len(child.spec.words), len(child.spec.leaves)) != shape
            or child.program.field_role != role or child.spec.field_role != role
            or child.program.digest().hex() != child.spec.program_sha256
            or len(ids) != len(set(ids))):
        raise ValueError('fresh tape/encoder source shape/role/global identity changed')
    if tape:
        _, rows, proof_start, container_start = retained_profile(role)
        if (child.metadata['proof_relative_start'] != proof_start
                or child.metadata['container_relative_start'] != container_start
                or child.metadata['row_count'] != rows or child.metadata['row_width'] != 2
                or child.source_maps['source_byte_offsets'] != list(range(container_start, container_start+112))):
            raise ValueError('exact retained role-relative source spans and count profile required')
    raw_maps, raw_metadata = _canonical(child.source_maps), _canonical(child.metadata)
    maps_sha = _hex_digest(child.source_maps_sha256)
    if (sha256(raw_maps).hexdigest() != maps_sha or len(raw_maps) > MAX_MAP_BYTES
            or len(raw_metadata) > MAX_MANIFEST_BYTES):
        raise ValueError('fresh scalar source sidecar changed its sealed digest/budget')
    branch = 'retained-scalar-block' if tape else 'eval-w-encoding'
    descriptor = _make(ByteRhoChainComponentDescriptor, index=index, branch=branch, kind=branch,
        operation_id=child.program.operation_id, program_sha256=child.program.digest().hex(),
        catalogue_id=child.spec.digest().hex(), source_sha256=_hex_digest(child.source_sha256),
        source_maps_sha256=maps_sha, global_ids_sha256=_hash(ids), words=shape[0], leaves=shape[1],
        counter=rho_counter, field_role=role,
        program_identity_kind='ByteProgram.digest (byte-v1)' if tape else 'ConvolutionProgram.digest (fixed-trace/v2)')
    return _make(RetainedScalarComponentSource, index=index, branch=branch, descriptor=descriptor,
        child=child, program=child.program, spec=child.spec, global_ids=ids,
        _program_manifest=None, _source_manifest=raw_metadata, _source_maps=raw_maps)


def _check_new_maps(tape, encoder, role):
    dynamic = {eval_w_global_id(i) for i in range(32)}|{coefficient_global_id(d, i) for d in (0, 2) for i in range(32)}
    if (set(tape.global_ids) & set(encoder.global_ids) != {eval_w_global_id(i) for i in range(32)}
            or set(tape.global_ids)-dynamic != {f'proof/container-byte/{retained_profile(role)[3]+i}' for i in range(32, 48)}
            or sum(name.startswith('eval-w/') for name in encoder.global_ids) != 23):
        raise ValueError('tape96 shared sources/count16 and eval32 shared/private23 maps changed')


def _connections(point, tape, encoder):
    # These are facts produced by the fresh sealed old chain, never an imported
    # source-map or replay receipt. Keep only the three consumed interface maps.
    old = point.chain.source_maps['components']
    by_id = [{r['global_id']: r for r in old[i]['interfaces']} for i in (0, 1, 3, 4)]
    tape_maps, encoder_maps = tape.child.source_maps, encoder.child.source_maps
    encoder_positions = {name: i for i, (name, _) in enumerate(encoder.spec.words)}
    links = []
    for index in tuple(range(32))+tuple(range(48, 112)):
        global_id = tape.global_ids[index]
        source_ordinal, source_formal = tape_maps['byte_occurrences'][index]
        source_leaf = tape.spec.leaves[source_ordinal]
        if source_leaf.kind != 'word_valid' or source_leaf.wires != (index,) or source_formal != 0:
            raise ValueError('dynamic source BYTE needs its actual word_valid opener, not a fake producer')
        targets = []
        if index < 32:
            for component, lookup in ((0, by_id[0]), (1, by_id[1])):
                row = lookup[global_id]
                if row['bound'] != 256 or len(row['occurrences']) != 2:
                    raise ValueError('eval_W must feed both actual RHO C/Theta consumers')
                targets.append(dict(component_index=component, word_index=row['word_index'], occurrences=row['occurrences']))
            word = encoder.child.ports['input_bytes'][index]
            slot = encoder_positions[word]
            occurrence = encoder_maps['byte_opening_occurrences'][index]
            if encoder.global_ids[slot] != global_id or encoder.spec.leaves[occurrence[0]].wires[occurrence[1]] != slot:
                raise ValueError('eval_W source must share the actual encoder BYTE opener')
            targets.append(dict(component_index=12, word_index=slot, occurrences=(tuple(occurrence),)))
        else:
            for component, lookup, count in ((3, by_id[2], 1), (4, by_id[3], 2)):
                row = lookup[global_id]
                if row['bound'] != 256 or len(row['occurrences']) != count:
                    raise ValueError('compressed coefficient must feed its canonical encoding and prefix C/Theta openers')
                targets.append(dict(component_index=component, word_index=row['word_index'], occurrences=row['occurrences']))
        links.append(dict(global_id=global_id, source_component=11, source_word=index,
            source_ordinal=source_ordinal, source_occurrence=source_formal, targets=tuple(targets)))
    if len(links) != 96 or sum(len(t['occurrences']) for link in links for t in link['targets']) != 352:
        raise ValueError('96 tape source words must cover all352 actual direct consumers')
    internal = []
    for link in encoder_maps['canonical_internal_links']:
        word = link['word_index']
        if (encoder.spec.leaves[link['source_ordinal']].wires[link['source_occurrence']] != word
                or encoder.spec.leaves[link['target_ordinal']].wires[link['target_occurrence']] != word):
            raise ValueError('eval_W private limb/split canonicality link detached')
        internal.append(dict(component_index=12, global_id=encoder.global_ids[word], **link))
    if (len(internal) != 23 or encoder.spec.leaves[16].kind != 'field_valid'
            or encoder.spec.leaves[16].wires != tuple(range(9))):
        raise ValueError('eval_W encoding must retain its exact23 internal links and field_valid16')
    return tuple(links), tuple(internal)


def _record(source, spec, program, assignment):
    descriptor = source.descriptor
    if (spec.digest().hex() != descriptor.catalogue_id
            or _hash(source.global_ids) != descriptor.global_ids_sha256
            or set(assignment) != {word for word, _ in spec.words}):
        raise ValueError('fresh scalar record changed source/assignment/global-map identity')
    for word, bound in spec.words:
        value = assignment[word]
        if type(value) is not int or not 0 <= value < bound:
            raise ValueError('composed scalar assertion escaped BYTE/limb decoder bounds')
    return _make(RetainedScalarComponentBinding, index=source.index, branch=source.branch,
        descriptor=descriptor, program=program, spec=spec, global_ids=source.global_ids,
        _assignment=tuple(assignment.items()), _program_manifest=source._program_manifest,
        _source_manifest=source._source_manifest, _source_maps=source._source_maps)


@dataclass(frozen=True, init=False)
class RetainedScalarSourcesBinding:
    plan: object
    point: object
    tape: object
    asserted_values: tuple[int, ...]
    asserted_block: bytes
    eval_w: bytes
    coefficients: tuple[bytes, bytes]

    def __init__(self, *args, **kwargs):
        raise TypeError('bind claims through the sealed retained scalar source factory')

    reference_block = property(lambda self: self.plan.reference_block)
    reference_inputs = property(lambda self: self.plan.reference_inputs)
    prior_state = property(lambda self: self.point.chain.prior_state)
    A = property(lambda self: self.point.A)
    P = property(lambda self: self.point.P)
    E = property(lambda self: self.point.E)
    R = property(lambda self: self.point.R)
    selected_bit = property(lambda self: self.point.selected_bit)
    raw_rho = property(lambda self: self.point.chain.raw_rho)
    raw_c = property(lambda self: self.point.raw_c)

    def iter_components(self):
        """Stream thirteen registries; delete each yielded graph/value alias before next."""
        _hosted_guard()

        def stream():
            for old in self.point.iter_components():
                if old.descriptor.json() != self.plan.components[old.index].json():
                    raise ValueError('inherited mixed-role component changed source identity')
                # Forward already canonical immutable sidecars. Do not parse a
                # large full-permutation map while its live graph is resident.
                result = _make(RetainedScalarComponentBinding, index=old.index, branch=old.branch,
                    descriptor=old.descriptor, program=old.program, spec=old.spec,
                    global_ids=old.global_ids, _assignment=old._assignment,
                    _program_manifest=old._program_manifest, _source_manifest=old._source_manifest,
                    _source_maps=old._source_maps)
                del old
                yield result
                del result
            source = self.plan.regenerate_component(11)
            bound = source.child.bind(self.asserted_values)
            if (bound.asserted_values != self.asserted_values or bound.asserted_block != self.asserted_block
                    or bound.reference_block != self.plan.reference_block
                    or _hex_digest(bound.source_sha256) != source.descriptor.source_sha256):
                raise ValueError('fresh tape changed original reference or actual asserted values')
            result = _record(source, bound.spec, bound.program, bound.assignment)
            del source, bound
            yield result
            del result
            source = self.plan.regenerate_component(12)
            bound = source.child.bind(self.eval_w)
            if bound.raw != self.eval_w or _hex_digest(bound.source_sha256) != source.descriptor.source_sha256:
                raise ValueError('eval_W encoder detached from the actual asserted tape bytes')
            result = _record(source, bound.spec, bound.program, bound.assignment)
            del source, bound
            yield result
            del result
        return stream()

    def summary(self):
        result = dict(source_sha256=self.plan.source_sha256.hex(), field_role=self.plan.role,
            retained_scalar_binding_constructed=True,
            asserted_values_equal_reference=self.asserted_values == tuple(self.reference_block),
            asserted_block_sha256=sha256(self.asserted_block).hexdigest(),
            reference_block_sha256=sha256(self.reference_block).hexdigest(),
            asserted_prefix_constants_satisfied=self.asserted_block[32:48] == self.reference_block[32:48],
            eval_w_le=self.eval_w.hex(), coefficients_le=tuple(value.hex() for value in self.coefficients),
            selected_bit=self.selected_bit,
            scope='local relations on asserted scalar BYTE tape; a matching reference hash is not Script source authentication')
        result.update({flag: False for flag in FALSE_FLAGS})
        return result


@dataclass(frozen=True, init=False)
class RetainedScalarSourcesPlan:
    context: bytes
    role: str
    point_role: str
    rho_counter: int
    bit_index: int
    operation_id: str
    point: object
    tape: object
    components: tuple
    source_sha256: bytes
    source_maps_sha256: bytes
    _manifest: bytes
    _maps: bytes

    def __init__(self, *args, **kwargs):
        raise TypeError('use the retained scalar source factory; no imported graph/map/receipt authority')

    manifest = property(lambda self: json.loads(self._manifest))
    source_maps = property(lambda self: json.loads(self._maps))
    reference_block = property(lambda self: self.tape.reference_block)
    reference_inputs = property(lambda self: self.tape.reference_inputs)

    @property
    def ports(self):
        ports = dict(self.point.ports)
        ports.update(asserted_block=tuple(tape_global_id(f'block/byte/{i}', role=self.role) for i in range(112)),
            eval_w_scalar=tuple(f'eval-w/scalar/l{i}' for i in range(9)),
            eval_w_split_auxiliaries=tuple('eval-w/'+word for word in self.source_maps['eval_encoding_ports']['split_auxiliaries']))
        return MappingProxyType(ports)

    def regenerate_component(self, index):
        _hosted_guard()
        if type(index) is not int or not 0 <= index < 13:
            raise ValueError('component index0..12 required')
        if index < 11:
            old = self.point.regenerate_component(index)
            if old.descriptor.json() != self.components[index].json():
                raise ValueError('fresh inherited point component changed source identity')
            return _make(RetainedScalarComponentSource, index=index, branch=old.branch,
                descriptor=old.descriptor, child=old.child, program=old.program, spec=old.spec,
                global_ids=old.global_ids, _program_manifest=old._program_manifest,
                _source_manifest=old._source_manifest, _source_maps=old._source_maps)
        _, block_op, eval_op = _operations(self.operation_id)
        child = (build_retained_scalar_block(self.tape._raw_bundle, self.tape.expected, self.tape.dimensions,
            context=self.context, role=self.role, operation_id=block_op) if index == 11 else
            build_eval_w_encoding(context=self.context, role=self.role, operation_id=eval_op))
        source = _new_source(index, child, role=self.role, rho_counter=self.rho_counter)
        if source.descriptor.json() != self.components[index].json():
            raise ValueError('fresh tape/encoder changed admitted reference or source/global identity')
        return source

    def bind(self, asserted_values, prior_state, A, P, *, claimed_bit=None, claimed_E=AUTO, claimed_R=AUTO):
        _hosted_guard()
        _block_asserted(asserted_values)
        if any(value >= 256 for value in asserted_values):
            raise ValueError('full composition requires BYTE claims; isolated tape probes cover signed-u32 range violations')
        block = bytes(asserted_values)
        eval_w, coefficients = block[:32], (block[48:80], block[80:112])
        if any(int.from_bytes(raw, 'little') >= ROLES[self.role] for raw in (eval_w,)+coefficients):
            raise ValueError('full composition preserves old canonical input admission; isolated encoders expose field-validity negatives')
        bound_tape = self.tape.bind(asserted_values)
        if (bound_tape.asserted_block != block
                or _hex_digest(bound_tape.source_sha256) != self.components[11].source_sha256):
            raise ValueError('fresh admitted tape source changed its sealed identity')
        point = self.point.bind(eval_w, prior_state, coefficients, A, P,
            claimed_bit=claimed_bit, claimed_E=claimed_E, claimed_R=claimed_R)
        return _make(RetainedScalarSourcesBinding, plan=self, point=point, tape=bound_tape,
            asserted_values=asserted_values, asserted_block=block, eval_w=eval_w, coefficients=coefficients)

    def summary(self):
        result = dict(schema=SCHEMA, source_sha256=self.source_sha256.hex(), field_role=self.role,
            point_field_role=self.point_role, rho_counter=self.rho_counter, bit_index=self.bit_index,
            components=13, leaves=153342, local_declared_words=156330,
            unique_global_words=155146, cached_signature_reuses=1184,
            new_tape_shared_bytes=96, new_encoder_shared_bytes=32,
            new_direct_opening_comparisons=352, new_eval_internal_opening_comparisons=23,
            reference_admitted=True, retained_scalar_topology_constructed=True)
        result.update({flag: False for flag in FALSE_FLAGS})
        return result


def build_retained_scalar_sources(raw_bundle, expected, dimensions, *, context, role,
                                  bit_index=0, operation_id='retained-scalar-sources'):
    _hosted_guard()
    _parameters(raw_bundle, expected, dimensions, context, role, bit_index, operation_id)
    rho_counter, _, _, _ = retained_profile(role)
    point_op, block_op, eval_op = _operations(operation_id)
    # Reference admission precedes the first large inherited graph allocation.
    tape = build_retained_scalar_block(raw_bundle, expected, dimensions,
        context=context, role=role, operation_id=block_op)
    tape_source = _new_source(11, tape, role=role, rho_counter=rho_counter)
    point = build_byte_c_bit_point(context=context, role=role, rho_counter=rho_counter,
        bit_index=bit_index, operation_id=point_op)
    encoder = build_eval_w_encoding(context=context, role=role, operation_id=eval_op)
    eval_source = _new_source(12, encoder, role=role, rho_counter=rho_counter)
    _check_new_maps(tape_source, eval_source, role)
    links, internal = _connections(point, tape_source, eval_source)
    components = point.components+(tape_source.descriptor, eval_source.descriptor)
    if (sum(item.words for item in components) != 156330
            or sum(item.leaves for item in components) != 153342
            or point.manifest['unique_global_words']+16+23 != 155146
            or point.manifest['cached_signature_reuses']+96+32 != 1184):
        raise ValueError('thirteen-component retained scalar census changed')
    maps = dict(schema=MAP_SCHEMA, point_source_sha256=point.source_sha256.hex(),
        point_source_maps_sha256=point.source_maps_sha256.hex(), inherited_component_indices=tuple(range(11)),
        components=[item.json() for item in components], tape_to_consumers=links,
        eval_canonical_internal_links=internal, eval_encoding_ports=dict(encoder.ports),
        reference_block=dict(proof_relative_start=tape.metadata['proof_relative_start'],
            container_relative_start=tape.metadata['container_relative_start'],
            source_byte_offsets=tape.source_maps['source_byte_offsets'],
            prefix_anchors=tape.source_maps['prefix_anchors'],
            reference_block_sha256=tape.metadata['reference_block_sha256'], source_authority=False),
        normative_global_maps=dict(point='unchanged eleven-component mixed-role global IDs',
            tape_dynamic='eval_W32 and compressed c0_LE32/c2_LE32 share their exact existing BYTE identities',
            tape_count_prefix='proof/container-byte/{actual retained container offset}',
            eval_byte_inputs='rho/message/eval_w/byte/{0..31}', eval_private='eval-w/<actual-encoding-local>'),
        shared_histogram=dict(double=432, triple=328, quadruple=32, shared_unique=792),
        leaves=153342, local_declared_words=156330, unique_global_words=155146, cached_signature_reuses=1184)
    raw_maps = _canonical(maps)
    if len(raw_maps) > MAX_MAP_BYTES:
        raise ValueError('retained scalar maps exceed unchanged8MiB cap')
    maps_sha = sha256(raw_maps).digest()
    manifest = dict(schema=SCHEMA, context=context.hex(), field_role=role, point_field_role=point.point_role,
        rho_counter=rho_counter, c_counter=rho_counter+1, bit_index=bit_index, operation_id=operation_id,
        point_operation_id=point_op, point_source_sha256=point.source_sha256.hex(),
        point_source_maps_sha256=point.source_maps_sha256.hex(),
        expected_policy_sha256=EXPECTED_POLICY_SHA256, verifier_dimensions_sha256=DIMENSION_SHA256,
        component_order=tuple(item.branch for item in components), components=[item.json() for item in components],
        source_maps_sha256=maps_sha.hex(), leaves=153342, local_declared_words=156330,
        unique_global_words=155146, cached_signature_reuses=1184,
        relation='asserted eval_W/c0/c2 BYTE tape -> scalar encodings and existing RHO/c/point consumers',
        commitment_order='external retained policy/context -> source/maps -> one global pool -> thirteen registries -> Scripts -> forest',
        scope='local relations on asserted retained scalar BYTEs; whole-proof hash/EOF, prior-state and point/key origins remain unbound')
    raw = _canonical(manifest)
    if len(raw) > MAX_MANIFEST_BYTES:
        raise ValueError('retained scalar manifest exceeds unchanged1MiB cap')
    del encoder, eval_source, tape_source
    return _make(RetainedScalarSourcesPlan, context=context, role=role, point_role=point.point_role,
        rho_counter=rho_counter, bit_index=bit_index, operation_id=operation_id,
        point=point, tape=tape, components=components,
        source_sha256=sha256(SOURCE_DOMAIN+raw).digest(), source_maps_sha256=maps_sha,
        _manifest=raw, _maps=raw_maps)
