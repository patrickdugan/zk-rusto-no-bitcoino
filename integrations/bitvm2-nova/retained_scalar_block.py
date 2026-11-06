"""Sealed retained-proof BYTE block for eval_W and the first batch quadratic.

The reference container is freshly admitted by the existing bounded codecs.
Only the two verifier-owned little-endian vector lengths become constants in
this catalogue. Its other96 BYTE words remain dynamic assertions. In particular,
a proof digest in metadata does not authenticate those asserted values in
Script. Canonical scalar relations and their downstream opening links belong
to the consuming components; whole-proof parsing and production origins remain
separate obligations.
"""
from dataclasses import dataclass
from hashlib import sha256
import json
import os
import sys
from types import MappingProxyType

from byte_kernels import ByteTraceBuilder
from nht4 import HEADER_BYTES, ExpectedBundle, bind_container
from proof_codec import VerifierDimensions, decode_proof
from trace import ID
from wots_graph import GraphSpec, authenticated_shape


SCHEMA = 'bitvm2-nova-retained-scalar-block/v1'
MAP_SCHEMA = 'bitvm2-nova-retained-scalar-block-maps/v1'
SOURCE_DOMAIN = b'BITVM2-NOVA/RETAINED-SCALAR-BLOCK/v1\x00'
BLOCK_BYTES = 112
BYTE = 256
SCALAR_ROLES = {'pallas_scalar': ('primary', 'pallas', 19),
                'vesta_scalar': ('secondary', 'vesta', 14)}
FALSE_FLAGS = ('proof_byte_origins_bound', 'whole_container_script_bound',
    'proof_length_script_bound', 'proof_eof_script_bound',
    'proof_sha256_script_bound', 'bundle_sha256_script_bound',
    'scalar_canonicality_script_bound', 'transcript_verified', 'proof_verified',
    'bitvm2_script_verified', 'complete_nova_verifier', 'complete_bitvm2_verifier',
    'production_assertion_binding', 'bitcoin_transaction_graph')


def _hosted_guard():
    if (os.environ.get('GITHUB_ACTIONS') != 'true'
            or os.environ.get('RUNNER_OS') != 'Linux' or sys.platform != 'linux'):
        raise ValueError('retained scalar source construction is hosted GitHub Linux only')


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def _parameters(raw_bundle, expected, dimensions, context, role, operation_id):
    if (type(expected) is not ExpectedBundle
            or type(dimensions) is not VerifierDimensions
            or type(raw_bundle) is not bytes
            or type(context) is not bytes or len(context) != 32
            or type(role) is not str or role not in SCALAR_ROLES
            or type(operation_id) is not str or not ID.fullmatch(operation_id)):
        raise ValueError('owned container/policy/dimensions, scalar role, operation and32-byte context required')
    # Recheck the admitted descriptor against this exact policy. A descriptor
    # authenticated for some other network/key must not supply these offsets.
    checked = VerifierDimensions.from_json(dimensions.json(), expected,
        expected_descriptor_sha256=dimensions.descriptor_sha256)
    if checked != dimensions or (checked.primary.batch_rounds, checked.secondary.batch_rounds) != (19, 14):
        raise ValueError('retained19/14 batch-round descriptor required')


def _asserted(values):
    if (type(values) is not tuple or len(values) != BLOCK_BYTES
            or any(type(value) is not int or not 0 <= value <= 0xffffffff for value in values)):
        raise ValueError('exact immutable112 signed-u32 BYTE assertions required')
    return values


def _reference(raw_bundle, expected, dimensions, role):
    """Read fixed paths internally; caller-supplied spans never reach a graph."""
    container = bind_container(raw_bundle, expected)
    decoded = decode_proof(container.proof, dimensions)
    owner, engine, rounds = SCALAR_ROLES[role]
    if getattr(dimensions, owner).batch_rounds != rounds:
        raise ValueError('retained scalar role and trusted batch count differ')
    root = 'snark_'+owner
    vector = root+'.sc_proof_batch.compressed_polys'
    row = vector+'[0].coeffs_except_linear_term'
    paths = (root+'.eval_W', vector, row, row+'[0]', row+'[1]')
    by_path = {span.path: span for span in decoded.spans}
    if len(by_path) != len(decoded.spans) or any(path not in by_path for path in paths):
        raise ValueError('exact retained eval_W/batch paths required')
    spans = tuple(by_path[path] for path in paths)
    start = spans[0].start
    for span, offset, size, kind in zip(spans, (0, 32, 40, 48, 80),
            (32, 8, 8, 32, 32), ('scalar', 'length', 'length', 'scalar', 'scalar'), strict=True):
        expected_engine = engine if kind == 'scalar' else None
        if (span.start != start+offset or span.size != size or span.kind != kind
                or span.engine != expected_engine):
            raise ValueError('retained scalar source must be one contiguous112-byte block')
    block = container.proof[start:start+BLOCK_BYTES]
    if (len(block) != BLOCK_BYTES or int.from_bytes(block[32:40], 'little') != rounds
            or int.from_bytes(block[40:48], 'little') != 2):
        raise ValueError('trusted batch count and retained quadratic row-width2 required')
    return block, spans


def _make(cls, **fields):
    result = object.__new__(cls)
    for name, value in fields.items():
        object.__setattr__(result, name, value)
    return result


@dataclass(frozen=True, init=False)
class RetainedScalarBlock:
    expected: ExpectedBundle
    dimensions: VerifierDimensions
    context: bytes
    role: str
    operation_id: str
    program: object
    spec: GraphSpec
    reference_block: bytes
    source_sha256: bytes
    source_maps_sha256: bytes
    _raw_bundle: bytes
    _ports: tuple
    _reference_inputs: tuple
    _assignment: tuple
    _metadata: bytes
    _maps: bytes

    def __init__(self, *args, **kwargs):
        raise TypeError('use the hosted sealed retained scalar block factory')

    ports = property(lambda self: MappingProxyType(dict(self._ports)))
    reference_inputs = property(lambda self: MappingProxyType(dict(self._reference_inputs)))
    assignment = property(lambda self: dict(self._assignment))
    metadata = property(lambda self: json.loads(self._metadata))
    source_maps = property(lambda self: json.loads(self._maps))

    def bind(self, asserted_values):
        _hosted_guard()
        _asserted(asserted_values)
        fresh = _construct(self._raw_bundle, self.expected, self.dimensions,
            context=self.context, role=self.role, operation_id=self.operation_id)
        if (fresh.program.digest() != self.program.digest()
                or fresh.spec.digest() != self.spec.digest()
                or fresh.source_sha256 != self.source_sha256
                or fresh._maps != self._maps or fresh.reference_block != self.reference_block):
            raise ValueError('fresh retained block binding changed its sealed reference/topology')
        # Deliberately bypass fixed-claim Program.bind admission. An oversized
        # signed assertion must reach the existing authenticated decoder flag,
        # while coherent changed BYTE assertions are valid local source values.
        assignment = tuple(zip(fresh.ports['block_bytes'], asserted_values, strict=True))
        return _make(RetainedScalarBlockBinding, plan=fresh,
                     asserted_values=asserted_values, _assignment=assignment)

    def summary(self):
        result = dict(schema=SCHEMA, source_sha256=self.source_sha256.hex(),
            source_maps_sha256=self.source_maps_sha256.hex(), field_role=self.role,
            words=112, leaves=112, prefix_constant_leaves=16, dynamic_byte_leaves=96,
            reference_admitted=True, source_block_constructed=True)
        result.update({flag: False for flag in FALSE_FLAGS})
        return result


@dataclass(frozen=True, init=False)
class RetainedScalarBlockBinding:
    plan: RetainedScalarBlock
    asserted_values: tuple
    _assignment: tuple

    def __init__(self, *args, **kwargs):
        raise TypeError('bind asserted BYTE values through a sealed retained block')

    program = property(lambda self: self.plan.program)
    spec = property(lambda self: self.plan.spec)
    ports = property(lambda self: self.plan.ports)
    reference_block = property(lambda self: self.plan.reference_block)
    reference_inputs = property(lambda self: self.plan.reference_inputs)
    metadata = property(lambda self: self.plan.metadata)
    source_maps = property(lambda self: self.plan.source_maps)
    source_sha256 = property(lambda self: self.plan.source_sha256)
    source_maps_sha256 = property(lambda self: self.plan.source_maps_sha256)
    assignment = property(lambda self: dict(self._assignment))
    asserted_block = property(lambda self: bytes(self.asserted_values)
        if all(value < BYTE for value in self.asserted_values) else None)

    def summary(self):
        result = self.plan.summary()
        result.update(asserted_values_equal_reference=self.asserted_values == tuple(self.reference_block),
            asserted_byte_domains_satisfied=all(value < BYTE for value in self.asserted_values),
            asserted_prefix_constants_satisfied=self.asserted_values[32:48] == tuple(self.reference_block[32:48]))
        return result


def _construct(raw_bundle, expected, dimensions, *, context, role, operation_id):
    _hosted_guard()
    _parameters(raw_bundle, expected, dimensions, context, role, operation_id)
    block, spans = _reference(raw_bundle, expected, dimensions, role)
    builder = ByteTraceBuilder(role, operation_id, context)
    words = tuple(builder.byte(f'block/byte/{index}', value) for index, value in enumerate(block))
    # These are format constants from the authenticated dimensions and the
    # explicitly selected retained quadratic profile, never scalar values.
    count = getattr(dimensions, SCALAR_ROLES[role][0]).batch_rounds
    prefixes = count.to_bytes(8, 'little')+(2).to_bytes(8, 'little')
    for index, value in enumerate(prefixes, 32):
        builder.check('const', (words[index],), (value,))
    program, assignment = builder.finish()
    spec = GraphSpec.from_program(program)
    if (len(program.words) != BLOCK_BYTES or len(program.constraints) != 16
            or program.fields or len(spec.leaves) != BLOCK_BYTES or spec.field_leaves
            or any(bound != BYTE for _, bound in spec.words)
            or len({authenticated_shape(spec, leaf) for leaf in spec.leaves}) > 4):
        raise ValueError('retained block must keep112 BYTE words/16constants/96validity leaves')
    occurrences = [[] for _ in words]
    anchors = []
    for ordinal, leaf in enumerate(spec.leaves):
        if len(leaf.wires) != 1 or leaf.kind not in ('const', 'word_valid'):
            raise ValueError('retained BYTE source occurrence shape changed')
        slot, = leaf.wires
        occurrences[slot].append((ordinal, 0))
        if 32 <= slot < 48:
            if leaf.kind != 'const' or leaf.argument != (prefixes[slot-32],):
                raise ValueError('length prefix BYTE must retain its actual constant leaf')
            anchors.append(dict(block_index=slot, word_index=slot, expected=prefixes[slot-32],
                                ordinal=ordinal, formal=0))
        elif leaf.kind != 'word_valid' or leaf.argument:
            raise ValueError('dynamic source BYTE cannot become a proof-value constant')
    if any(len(items) != 1 for items in occurrences) or len(anchors) != 16:
        raise ValueError('every source BYTE needs exactly one actual predicate occurrence')
    ports = dict(block_bytes=words, eval_w=words[:32], row_count=words[32:40],
                 row_width=words[40:48], coefficient_bytes=(words[48:80], words[80:112]))
    inputs = dict(eval_w=block[:32], coefficients=(block[48:80], block[80:112]),
                  row_count=count, row_width=2)
    start = spans[0].start
    maps = dict(schema=MAP_SCHEMA, proof_relative_start=start,
        container_relative_start=HEADER_BYTES+start, block_indices=tuple(range(BLOCK_BYTES)),
        source_byte_offsets=tuple(HEADER_BYTES+start+i for i in range(BLOCK_BYTES)),
        byte_occurrences=tuple(items[0] for items in occurrences), prefix_anchors=anchors,
        eval_w_indices=tuple(range(32)), row_count_indices=tuple(range(32, 40)),
        row_width_indices=tuple(range(40, 48)),
        coefficient_byte_indices=(tuple(range(48, 80)), tuple(range(80, 112))),
        spans=tuple(dict(path=span.path, kind=span.kind, start=span.start,
                         size=span.size, engine=span.engine) for span in spans), ports=ports)
    raw_maps = _canonical(maps)
    maps_sha = sha256(raw_maps).digest()
    metadata = dict(schema=SCHEMA, context=context.hex(), field_role=role,
        operation_id=operation_id, program_sha256=program.digest().hex(), catalogue_id=spec.digest().hex(),
        source_maps_sha256=maps_sha.hex(), expected_policy_sha256=sha256(_canonical(expected.json())).hexdigest(),
        verifier_dimensions_sha256=dimensions.descriptor_sha256.hex(),
        verifier_key_sha256=expected.verifier_key_sha256.hex(), header_revision=expected.header_revision,
        nova_version=expected.nova_version, network=expected.network, k=expected.k, steps=expected.steps,
        proof_bytes=expected.proof_bytes, proof_sha256=expected.proof_sha256.hex(),
        bundle_bytes=expected.bundle_bytes, bundle_sha256=expected.bundle_sha256.hex(),
        proof_relative_start=start, container_relative_start=HEADER_BYTES+start,
        block_bytes=BLOCK_BYTES, row_count=count, row_width=2,
        reference_block_sha256=sha256(block).hexdigest(),
        reference_inputs=dict(eval_w=block[:32].hex(), coefficients=(block[48:80].hex(), block[80:112].hex())),
        source_authority=False,
        scope='retained reference admission and local asserted BYTE/length-prefix relations; whole-proof and production origins remain unbound')
    metadata.update({flag: False for flag in FALSE_FLAGS})
    raw_metadata = _canonical(metadata)
    return _make(RetainedScalarBlock, expected=expected, dimensions=dimensions, context=context,
        role=role, operation_id=operation_id, program=program, spec=spec, reference_block=block,
        source_sha256=sha256(SOURCE_DOMAIN+raw_metadata).digest(), source_maps_sha256=maps_sha,
        _raw_bundle=raw_bundle, _ports=tuple(ports.items()), _reference_inputs=tuple(inputs.items()),
        _assignment=tuple(assignment.items()), _metadata=raw_metadata, _maps=raw_maps)


def build_retained_scalar_block(raw_bundle, expected, dimensions, *, context, role, operation_id):
    """Fresh fixed-path reference source; accepts no offsets, maps or receipts."""
    _hosted_guard()
    return _construct(raw_bundle, expected, dimensions,
                      context=context, role=role, operation_id=operation_id)
