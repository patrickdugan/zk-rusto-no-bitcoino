"""Sealed BYTE-port baseline around the unchanged Boolean Keccak round.

The legacy child retains every word, predicate, zero anchor and output copy.
A separate bounded bridge child uses the same3,200 input/output bit identities
and adds400 BYTE ports plus400 BASE auxiliaries. Its800 reconstruction leaves
are appended in a GraphSpec; no oversized Program or raised cap is introduced.
This is a hosted reference/comparison factory, never hash or proof acceptance.
"""
from dataclasses import dataclass
from hashlib import sha256
import json
import os
import re
import sys

from convolution import ConvolutionTraceBuilder
from keccak_trace import (ROUND_CONSTANTS, keccak_f1600_round, keccak_round_trace,
                          state_from_bytes, state_to_bytes, state_wire_names)
from script import BASE
from trace import ID, MAX_WORDS, ROLES
from trace_kernels import compile_predicate
from wots_graph import GraphSpec, Leaf, MAX_GRAPH_LEAVES, expansion_script

SCHEMA = 'bitvm2-nova-boolean-byte-round/v1'
MAP_SCHEMA = 'bitvm2-nova-boolean-byte-round-maps/v1'
PROGRAM_DOMAIN = b'BITVM2-NOVA/BOOLEAN-BYTE-ROUND-PROGRAM/v1\x00'
SOURCE_DOMAIN = b'BITVM2-NOVA/BOOLEAN-BYTE-ROUND-SOURCE/v1\x00'
STATE_BYTES, STATE_BITS, BYTE_BOUND = 200, 1600, 256
_PORT = re.compile(r'^(input|output)/l([0-9]{1,2})/byte([0-7])$')
FALSE_FLAGS = ('full_hash_verified', 'full_permutation_verified',
    'full_permutation_verified_in_script', 'transcript_verified',
    'hash_verified', 'nova_transcript_verified', 'nova_transcript_verified_in_script',
    'proof_verified', 'bitvm2_script_verified', 'complete_nova_verifier',
    'complete_bitvm2_verifier', 'production_assertion_binding',
    'bitcoin_transaction_graph')


def _hosted_guard():
    if (os.environ.get('GITHUB_ACTIONS') != 'true'
            or os.environ.get('RUNNER_OS') != 'Linux' or sys.platform != 'linux'):
        raise ValueError('Boolean BYTE round construction/binding is hosted GitHub Linux only')


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def _raw(value):
    if type(value) is not bytes or len(value) != STATE_BYTES:
        raise ValueError('exactly200 immutable state bytes required')
    return value


def _round(value):
    if type(value) is not int or not 0 <= value < 24:
        raise ValueError('Boolean BYTE round must be an integer0..23')
    return value


def byte_port_name(stage, lane, byte):
    """Tiny public naming rule; no graph construction or source authority."""
    if (type(stage) is not str or stage not in ('input', 'output')
            or type(lane) is not int or not 0 <= lane < 25
            or type(byte) is not int or not 0 <= byte < 8):
        raise ValueError('canonical BYTE stage/lane/byte required')
    return f'{stage}/l{lane}/byte{byte}'


def byte_port_names(stage):
    return tuple(byte_port_name(stage, lane, byte)
                 for lane in range(25) for byte in range(8))


def byte_bit_names(stage, lane, byte):
    """The exact old Boolean boundary bits, returned least-significant first."""
    byte_port_name(stage, lane, byte)
    return tuple(f'boolean/{stage}/l{lane}/b{8*byte+bit}' for bit in range(8))


def baseline_global_id(round_index, name):
    """Pure normative namespace; BYTE states remain distinct from Boolean bits."""
    r = _round(round_index)
    if type(name) is not str or not ID.fullmatch(name):
        raise ValueError('canonical bounded baseline word name required')
    match = _PORT.fullmatch(name)
    if match:
        stage, lane_text, byte_text = match.groups()
        lane, byte = int(lane_text), int(byte_text)
        if lane >= 25 or lane_text != str(lane):
            raise ValueError('canonical BYTE lane required')
        return f'byte-state/{r+int(stage == "output")}/l{lane}/byte{byte}'
    if name.startswith('input/') or name.startswith('output/'):
        raise ValueError('malformed reserved BYTE port name')
    result = f'boolean-round/{r}/{name}'
    if not ID.fullmatch(result):
        raise ValueError('baseline global name exceeds unchanged identifier limit')
    return result


def _parameters(round_index, context, role, operation_id):
    _round(round_index)
    if type(context) is not bytes or len(context) != 32:
        raise ValueError('caller-owned immutable32-byte context required')
    if type(role) is not str or role not in ROLES:
        raise ValueError('explicit supported Pasta field role required')
    if type(operation_id) is not str or not ID.fullmatch(operation_id):
        raise ValueError('canonical bounded baseline operation ID required')
    for suffix in (f'/boolean/round/{round_index}', '/bridges'):
        if not ID.fullmatch(operation_id+suffix):
            raise ValueError('derived baseline child operation ID exceeds existing limit')


def _alias_partition(wires):
    first = {}
    return tuple(first.setdefault(word, len(first)) for word in wires)


def _make(cls, **fields):
    result = object.__new__(cls)
    for name, value in fields.items():
        object.__setattr__(result, name, value)
    return result


def _construct(raw, round_index, context, role, operation_id, claimed_output=None):
    """Private fresh-child construction, guarded even when reached directly."""
    _hosted_guard()
    _parameters(round_index, context, role, operation_id)
    raw = _raw(raw)
    reference = state_to_bytes(keccak_f1600_round(state_from_bytes(raw), round_index))
    output = reference if claimed_output is None else _raw(claimed_output)
    old_program, old_values = keccak_round_trace(state_from_bytes(raw), round_index,
        context=context, role=role, operation_id=operation_id+'/boolean',
        input_prefix='boolean/input', output_prefix='boolean/output',
        claimed_output=state_from_bytes(output))
    old = GraphSpec.from_program(old_program)
    count = ROUND_CONSTANTS[round_index].bit_count()
    if (len(old.words) != 11201+count or len(old.leaves) != 9601+count
            or old.field_leaves or old_program.fields
            or old.original_constraints != len(old.leaves)):
        raise ValueError('legacy Boolean round census changed')

    bridge_builder = ConvolutionTraceBuilder(role, operation_id+'/bridges', context)
    bridge_rows = []
    for stage, data in (('input', raw), ('output', output)):
        for position, value in enumerate(data):
            lane, byte = divmod(position, 8)
            port = bridge_builder.small(byte_port_name(stage, lane, byte), value, BYTE_BOUND)
            auxiliary = bridge_builder.small(f'bridge/{stage}/l{lane}/byte{byte}/aux', value, BASE)
            bits = tuple(bridge_builder.small(name, (value >> bit) & 1, 2)
                         for bit, name in enumerate(byte_bit_names(stage, lane, byte)))
            bits_ordinal = len(bridge_builder.constraints)
            bridge_builder.check('bits', (auxiliary,)+tuple(reversed(bits)), (8,))
            byte_ordinal = len(bridge_builder.constraints)
            bridge_builder.check('conv_reconstruct', (auxiliary, port), (8,))
            bridge_rows.append((stage, position, port, auxiliary, bits,
                                bits_ordinal, byte_ordinal))
    bridge_program, bridge_values = bridge_builder.finish()
    bridge = GraphSpec.from_program(bridge_program)
    if (len(bridge.words), len(bridge.leaves), len(bridge_program.fields)) != (4000, 800, 0):
        raise ValueError('bounded bridge child census changed')

    old_indices = {name: i for i, (name, _) in enumerate(old.words)}
    bridge_indices = {name: i for i, (name, _) in enumerate(bridge.words)}
    shared = set(old_indices) & set(bridge_indices)
    expected_shared = set(state_wire_names('boolean/input')) | set(state_wire_names('boolean/output'))
    if shared != expected_shared or len(shared) != 3200:
        raise ValueError('child intersection is not exactly the legacy boundary bits')
    words, bridge_map = list(old.words), []
    for name, bound in bridge.words:
        if name in old_indices:
            i = old_indices[name]
            if bound != 2 or old.words[i][1] != bound:
                raise ValueError('shared bit bound changed')
            bridge_map.append(i)
        else:
            bridge_map.append(len(words))
            words.append((name, bound))
    words, bridge_map = tuple(words), tuple(bridge_map)
    old_map = tuple(range(len(old.words)))
    if (len(words) != 12001+count or len(words) > MAX_WORDS
            or len(set(name for name, _ in words)) != len(words)
            or len(set(bridge_map)) != len(bridge.words)
            or set(old_map) & set(bridge_map) != {old_indices[name] for name in shared}
            or set(old_map) | set(bridge_map) != set(range(len(words)))):
        raise ValueError('complete injective baseline word projection failed')

    leaves, bodies = list(old.leaves), dict(old.bodies)
    for leaf in bridge.leaves:
        occurrences = tuple(bridge_map[i] for i in leaf.wires)
        if _alias_partition(occurrences) != _alias_partition(leaf.wires):
            raise ValueError('bridge formal alias partition changed')
        compiled = expansion_script(occurrences)+compile_predicate(old_program.p, leaf.kind, leaf.argument)
        encoded = compiled.hex()
        if (sha256(compiled).hexdigest() != leaf.body_sha256
                or dict(bridge.bodies)[leaf.body_sha256] != encoded):
            raise ValueError('remapped bridge predicate bytes changed')
        if leaf.body_sha256 in bodies and bodies[leaf.body_sha256] != encoded:
            raise ValueError('predicate body hash collision')
        bodies[leaf.body_sha256] = encoded
        leaves.append(Leaf(leaf.kind, leaf.argument, occurrences, leaf.body_sha256))
    if (tuple(leaves[:len(old.leaves)]) != old.leaves
            or words[:len(old.words)] != old.words
            or any(bodies[key] != value for key, value in old.bodies)
            or len(leaves) != 10401+count or len(leaves) > MAX_GRAPH_LEAVES
            or {wire for leaf in leaves for wire in leaf.wires} != set(range(len(words)))):
        raise ValueError('legacy predicate prefix or full baseline census changed')

    values = dict(old_values)
    for name, bound in bridge.words:
        value = bridge_values[name]
        if type(value) is not int or not 0 <= value < bound:
            raise ValueError('bridge assignment exceeds its declared bound')
        if name in values and values[name] != value:
            raise ValueError('shared legacy bit has contradictory bridge value')
        values[name] = value
    if set(values) != {name for name, _ in words}:
        raise ValueError('baseline assignment coverage mismatch')

    names = {name: i for i, (name, _) in enumerate(words)}
    inputs, outputs = byte_port_names('input'), byte_port_names('output')
    input_indices, output_indices = tuple(names[n] for n in inputs), tuple(names[n] for n in outputs)
    producers = tuple(len(old.leaves)+401+2*i for i in range(STATE_BYTES))
    bridges = []
    for stage, position, port, auxiliary, bits, bits_ordinal, byte_ordinal in bridge_rows:
        a, b = len(old.leaves)+bits_ordinal, len(old.leaves)+byte_ordinal
        bit_indices = tuple(names[name] for name in bits)
        if (leaves[a].kind != 'bits' or leaves[a].argument != (8,)
                or leaves[a].wires != (names[auxiliary],)+tuple(reversed(bit_indices))
                or leaves[b].kind != 'conv_reconstruct' or leaves[b].argument != (8,)
                or leaves[b].wires != (names[auxiliary], names[port])):
            raise ValueError('BYTE port is not linked to its exact ordered old bits')
        bridges.append(dict(stage=stage, position=position, byte_index=names[port],
            auxiliary_index=names[auxiliary], bit_indices=bit_indices,
            bit_ordinal=a, byte_ordinal=b, byte_formal_occurrence=1))
    for i, ordinal in enumerate(producers):
        if leaves[ordinal].wires[1] != output_indices[i] or words[output_indices[i]][1] != BYTE_BOUND:
            raise ValueError('ordered output BYTE producer changed')
    global_ids = tuple(baseline_global_id(round_index, name) for name, _ in words)
    if len(set(global_ids)) != len(global_ids):
        raise ValueError('baseline global word map is not injective')
    source_maps = dict(schema=MAP_SCHEMA,
        children=[dict(kind='legacy-boolean-round', program_sha256=old.program_sha256,
            catalogue_id=old.digest().hex(), word_map=old_map, leaf_map=tuple(range(len(old.leaves)))),
            dict(kind='byte-bit-bridges', program_sha256=bridge.program_sha256,
            catalogue_id=bridge.digest().hex(), word_map=bridge_map,
            leaf_map=tuple(range(len(old.leaves), len(leaves))))],
        input_indices=input_indices, output_indices=output_indices,
        inputs=inputs, outputs=outputs, producer_ordinals=producers,
        producer_occurrences=(1,)*STATE_BYTES,
        input_producer_ordinals=tuple(len(old.leaves)+2*i+1 for i in range(STATE_BYTES)),
        input_producer_occurrences=(1,)*STATE_BYTES,
        bridges=bridges, shared_legacy_bit_words=3200,
        old_zero_anchor_ordinal=len(old.leaves)-1601,
        old_output_copy_start=len(old.leaves)-1600)
    manifest = dict(schema=SCHEMA, round_index=round_index, context=context.hex(),
        field_role=role, operation_id=operation_id,
        program_identity_kind='domain-separated child/projection manifest, not an oversized Program',
        legacy_operation_id=old.operation_id, bridge_operation_id=bridge.operation_id,
        words=len(words), leaves=len(leaves), old_words=len(old.words), old_leaves=len(old.leaves),
        bridge_words=4000, bridge_leaves=800, appended_words=800,
        boundary_order='lane=x+5*y; byte0..7 little-endian; bit0..7 least-significant-first',
        global_ids_sha256=sha256(_canonical(list(global_ids))).hexdigest(),
        source_maps=source_maps)
    encoded = _canonical(manifest)
    program_sha = sha256(PROGRAM_DOMAIN+encoded).hexdigest()
    spec = GraphSpec(program_sha, context.hex(), role, operation_id, words,
        tuple(leaves), tuple(sorted(bodies.items())), len(leaves), ())
    source_sha = sha256(SOURCE_DOMAIN+_canonical(dict(manifest=manifest,
        program_sha256=program_sha, catalogue_id=spec.digest().hex()))).digest()
    return spec, values, manifest, global_ids, source_sha, reference, output


@dataclass(frozen=True, init=False)
class BooleanByteRound:
    round_index: int
    context: bytes
    role: str
    operation_id: str
    spec: GraphSpec
    inputs: tuple[str, ...]
    outputs: tuple[str, ...]
    producer_ordinals: tuple[int, ...]
    global_ids: tuple[str, ...]
    source_sha256: bytes
    _manifest: bytes

    def __init__(self, *args, **kwargs):
        raise TypeError('use the hosted Boolean BYTE round factory')

    @property
    def manifest(self):
        return json.loads(self._manifest)

    @property
    def source_maps(self):
        return self.manifest['source_maps']

    @property
    def metadata(self):
        return self.manifest | dict(program_sha256=self.spec.program_sha256,
            catalogue_id=self.spec.digest().hex(), source_sha256=self.source_sha256.hex())

    input_ports = property(lambda self: self.inputs)
    output_ports = property(lambda self: self.outputs)
    input_words = property(lambda self: self.inputs)
    output_words = property(lambda self: self.outputs)
    producers = property(lambda self: self.producer_ordinals)
    output_producer_ordinals = property(lambda self: self.producer_ordinals)
    input_indices = property(lambda self: tuple(self.source_maps['input_indices']))
    output_indices = property(lambda self: tuple(self.source_maps['output_indices']))
    producer_occurrences = property(lambda self: (1,)*STATE_BYTES)
    output_producer_occurrences = property(lambda self: (1,)*STATE_BYTES)
    boolean_program_sha256 = property(lambda self: self.source_maps['children'][0]['program_sha256'])
    boolean_catalogue_id = property(lambda self: self.source_maps['children'][0]['catalogue_id'])
    legacy_operation_id = property(lambda self: self.manifest['legacy_operation_id'])

    def bind(self, initial_state, claimed_output=None):
        _hosted_guard()
        raw = _raw(initial_state)
        if claimed_output is not None:
            _raw(claimed_output)
        spec, values, manifest, global_ids, source_sha, reference, output = _construct(
            raw, self.round_index, self.context, self.role, self.operation_id, claimed_output)
        if (spec.digest() != self.spec.digest() or spec.program_sha256 != self.spec.program_sha256
                or source_sha != self.source_sha256 or global_ids != self.global_ids
                or _canonical(manifest) != self._manifest):
            raise ValueError('fresh Boolean BYTE assignment changed sealed source topology')
        return _make(BooleanByteRoundBinding, plan=self, initial_state=raw,
            reference_output=reference, output_state=output, _assignment=tuple(values.items()))

    def summary(self):
        result = dict(schema=SCHEMA, round_index=self.round_index, context=self.context.hex(),
            field_role=self.role, operation_id=self.operation_id, words=len(self.spec.words),
            leaves=len(self.spec.leaves), input_bytes=STATE_BYTES, output_bytes=STATE_BYTES,
            legacy_boolean_prefix_preserved=True, conversion_bridges=800,
            program_sha256=self.spec.program_sha256, catalogue_id=self.spec.digest().hex(),
            source_sha256=self.source_sha256.hex(), graph_constructed=True,
            scope='one unchanged Boolean round with complete external BYTE ports only')
        result.update({flag: False for flag in FALSE_FLAGS})
        return result


@dataclass(frozen=True, init=False)
class BooleanByteRoundBinding:
    plan: BooleanByteRound
    initial_state: bytes
    reference_output: bytes
    output_state: bytes
    _assignment: tuple

    def __init__(self, *args, **kwargs):
        raise TypeError('bind a sealed Boolean BYTE round plan')

    @property
    def spec(self):
        return self.plan.spec

    @property
    def assignment(self):
        return dict(self._assignment)

    source_maps = property(lambda self: self.plan.source_maps)
    inputs = property(lambda self: self.plan.inputs)
    outputs = property(lambda self: self.plan.outputs)
    input_ports = property(lambda self: self.plan.inputs)
    output_ports = property(lambda self: self.plan.outputs)
    producer_ordinals = property(lambda self: self.plan.producer_ordinals)
    producer_occurrences = property(lambda self: self.plan.producer_occurrences)
    input_indices = property(lambda self: self.plan.input_indices)
    output_indices = property(lambda self: self.plan.output_indices)
    global_ids = property(lambda self: self.plan.global_ids)
    source_sha256 = property(lambda self: self.plan.source_sha256)
    metadata = property(lambda self: self.plan.metadata)

    def summary(self):
        return self.plan.summary() | dict(binding_constructed=True,
            reference_output_matches=self.output_state == self.reference_output,
            initial_state_hex=self.initial_state.hex(), output_state_hex=self.output_state.hex())


def build_boolean_byte_round(round_index, *, context, role='pallas_scalar',
                             operation_id='boolean-byte/keccak'):
    """Fresh guarded plan; no imported graph, source map or receipt admission."""
    _hosted_guard()
    _parameters(round_index, context, role, operation_id)
    spec, _, manifest, global_ids, source_sha, _, _ = _construct(
        bytes(STATE_BYTES), round_index, context, role, operation_id)
    return _make(BooleanByteRound, round_index=round_index, context=context, role=role,
        operation_id=operation_id, spec=spec, inputs=byte_port_names('input'),
        outputs=byte_port_names('output'), producer_ordinals=tuple(manifest['source_maps']['producer_ordinals']),
        global_ids=global_ids, source_sha256=source_sha, _manifest=_canonical(manifest))
