"""Hosted framed LO Keccak endpoint and claimed HI digest reduction.

Twelve existing pair components execute one Keccak-f1600 permutation. A separate
tail preserves the fresh digest reducer and anchors exactly832 fixed input bits.
Its256 LO words name the actual final state's first four lanes; its832 framing
words name the actual initial state. The699 remaining tail words are private.
These global names prescribe WOTS opening reuse; production keys/assertions and
the Bitcoin transaction graph remain outside this factory.

The message has the retained primary rho layout, counter59 and branch0. eval_W
and the previous transcript state are external byte ports; HI is an external
digest. Neither host byte validation nor metadata makes eval_W canonical or
proof-derived, authenticates the previous transcript, or computes HI Keccak.
"""
from dataclasses import dataclass
from hashlib import sha256
import json
import os
import re
import sys

from convolution import ConvolutionProgram, ConvolutionTraceBuilder
from digest_reduce import DigestReduction, build_digest_reduction
from keccak_permutation import (PairDescriptor, build_keccak_permutation,
                                _validate_join)
from keccak_trace import (_state, keccak_f1600, keccak_f1600_round,
                          state_from_bytes, state_to_bytes)
from trace import ID
from wots_graph import GraphSpec

PLAN_SCHEMA = 'bitvm2-nova-keccak-lo-endpoint-plan/v1'
TAIL_SCHEMA = 'bitvm2-nova-keccak-lo-endpoint-tail/v1'
MAP_SCHEMA = 'bitvm2-nova-keccak-lo-endpoint-maps/v1'
TOPOLOGY_DOMAIN = b'BITVM2-NOVA/KECCAK-LO-ENDPOINT-TOPOLOGY/v1\x00'
TAIL_DOMAIN = b'BITVM2-NOVA/KECCAK-LO-ENDPOINT-TAIL/v1\x00'
ROLE, COUNTER, EVENT_SEQUENCE = 'pallas_scalar', 59, 103
PAIR_COUNT, COMPONENTS = 12, 13
TAIL_WORDS, TAIL_CONSTRAINTS, TAIL_LEAVES = 1787, 1204, 1205
TOTAL_LEAVES, GLOBAL_WORDS, LOCAL_WORDS = 231715, 232809, 251497
FRAME_BITS, LO_BITS = 832, 256
PADDING_ANCHOR = 492
FIXED_BYTE_INDICES = (0,)+tuple(range(33, 45))+(109, 110)+tuple(range(111, 200))
SCENARIOS = ('honest', 'coherent-output', 'wrong-padding')
FALSE_FLAGS = ('full_permutation_verified', 'full_permutation_verified_in_script',
    'full_hash_verified', 'hash_verified', 'transcript_verified', 'nova_transcript_verified',
    'proof_verified', 'bitvm2_script_verified', 'production_assertion_binding',
    'bitcoin_transaction_graph', 'eval_w_canonical_in_script', 'eval_w_proof_origin_bound',
    'prior_state_transcript_bound', 'hi_keccak_origin_bound', 'whole_challenge_keccak_bound')
_LO = re.compile(r'^digest/lo/l([0-3])/b([0-9]{1,2})$')
_FRAME = re.compile(r'^frame/byte/([0-9]{1,3})/bit/([0-7])$')


def _hosted_guard():
    if (os.environ.get('GITHUB_ACTIONS') != 'true'
            or os.environ.get('RUNNER_OS') != 'Linux' or sys.platform != 'linux'):
        raise ValueError('framed Keccak endpoint construction/binding is hosted GitHub Linux only')


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def _bytes(value, size, label):
    if type(value) is not bytes or len(value) != size:
        raise ValueError(f'exact immutable {size}-byte {label} required')
    return value


def rho_preimage(eval_w_le, prior_state):
    """Pure111-byte LO preimage; no hash, graph, or source verification.

    Offsets: w[0],eval_W[1:33],NoDS[33:37],counterLE[37:45],
    priorState[45:109],r[109],branch0[110]. eval_W is an external raw32B port.
    """
    return (b'w'+_bytes(eval_w_le, 32, 'external eval_W')+b'NoDS'
            +COUNTER.to_bytes(8, 'little')+_bytes(prior_state, 64, 'external prior state')
            +b'r\0')


def framed_state_bytes(eval_w_le, prior_state):
    """Pure single-block Keccak input: rate136 bytes plus zero64B capacity.

    Keccak suffix0x01 is at byte111, zeros112..134, and final0x80 at135.
    Initial state is zero before this first absorption, so the absorbed state
    is exactly these bytes. SHA3's0x06 suffix is deliberately not used.
    """
    return rho_preimage(eval_w_le, prior_state)+b'\x01'+bytes(23)+b'\x80'+bytes(64)


def fixed_frame_bytes():
    """Return104 ordered fixed (state-byte-index,value) pairs; safe locally."""
    reference = framed_state_bytes(bytes(32), bytes(64))
    return tuple((index, reference[index]) for index in FIXED_BYTE_INDICES)


def tail_global_id(local_name):
    """Pure normative alias rule, never an external-map admission interface."""
    if type(local_name) is not str or not ID.fullmatch(local_name):
        raise ValueError('canonical bounded endpoint local word name required')
    match = _LO.fullmatch(local_name)
    if match:
        lane, bit = (int(item) for item in match.groups())
        if bit >= 64 or match.group(2) != str(bit):
            raise ValueError('canonical LO lane/LSB bit required')
        return f'state/24/l{lane}/b{bit}'
    if local_name.startswith('digest/lo/'):
        raise ValueError('malformed reserved LO bit identity')
    match = _FRAME.fullmatch(local_name)
    if match:
        byte, bit = (int(item) for item in match.groups())
        if byte not in FIXED_BYTE_INDICES or match.group(1) != str(byte):
            raise ValueError('frame alias must name an exact fixed byte/LSB bit')
        return f'state/0/l{byte//8}/b{8*(byte % 8)+bit}'
    if local_name.startswith('frame/'):
        raise ValueError('malformed reserved framing bit identity')
    result = 'tail/'+local_name
    if not ID.fullmatch(result):
        raise ValueError('derived endpoint private word identity exceeds existing cap')
    return result


def _parameters(context, role, operation_id):
    if type(context) is not bytes or len(context) != 32:
        raise ValueError('32-byte caller-owned immutable context required')
    if type(role) is not str or role != ROLE:
        raise ValueError('retained primary pallas_scalar endpoint role required')
    if type(operation_id) is not str or not ID.fullmatch(operation_id):
        raise ValueError('valid bounded endpoint operation ID required')
    for suffix in ('/permutation/pair/11/child/1/round/23', '/tail/digest/uniform'):
        if not ID.fullmatch(operation_id+suffix):
            raise ValueError('derived endpoint child operation ID exceeds existing cap')


def _make(cls, **fields):
    result = object.__new__(cls)
    for name, value in fields.items():
        object.__setattr__(result, name, value)
    return result


@dataclass(frozen=True, init=False)
class TailDescriptor:
    index: int
    operation_id: str
    program_sha256: str
    catalogue_id: str
    words: int
    leaves: int
    global_ids_sha256: str
    digest_program_sha256: str
    digest_catalogue_id: str
    digest_source_sha256: str

    def __init__(self, *args, **kwargs):
        raise TypeError('build the endpoint plan to obtain its tail descriptor')

    def json(self):
        return {name: getattr(self, name) for name in self.__dataclass_fields__}


@dataclass(frozen=True, init=False)
class EndpointTail:
    digest: DigestReduction
    program: ConvolutionProgram
    spec: GraphSpec
    descriptor: TailDescriptor
    global_ids: tuple[str, ...]
    anchor_words: tuple[str, ...]
    anchor_constraints: tuple[int, ...]
    digest_leaf_map: tuple[int, ...]
    source_sha256: bytes
    _assignment: tuple
    _metadata: bytes
    _maps: bytes

    def __init__(self, *args, **kwargs):
        raise TypeError('regenerate the tail from a sealed endpoint binding')

    @property
    def assignment(self):
        return dict(self._assignment)

    @property
    def metadata(self):
        return json.loads(self._metadata)

    @property
    def source_maps(self):
        return json.loads(self._maps)


def _build_tail(lo, hi, initial_state, *, role, context, operation_id):
    _hosted_guard()  # Also protects this private regeneration/test seam.
    initial = state_to_bytes(_state(initial_state))
    digest = build_digest_reduction(lo, hi, role=role, context=context,
                                    operation_id=operation_id+'/digest')
    builder = ConvolutionTraceBuilder(role, operation_id, context)
    builder.words.update(digest.program.words)
    builder.fields.update(digest.program.fields)
    builder.values.update(digest.assignment)
    builder.constraints.extend(digest.program.constraints)
    anchors, ordinals, frame_slots = [], [], []
    for byte, expected in fixed_frame_bytes():
        for bit in range(8):
            word = builder.small(f'frame/byte/{byte}/bit/{bit}', (initial[byte] >> bit) & 1, 2)
            ordinals.append(len(builder.constraints))
            builder.check('const', (word,), ((expected >> bit) & 1,))
            anchors.append(word)
            frame_slots.append((byte, bit))
    program, assignment = builder.finish()
    program._admit(assignment)
    spec = GraphSpec.from_program(program)
    if (len(program.words) != TAIL_WORDS or len(program.constraints) != TAIL_CONSTRAINTS
            or len(spec.leaves) != TAIL_LEAVES or spec.field_leaves != (('result', 1204),)
            or program.words[:955] != digest.program.words
            or program.constraints[:372] != digest.program.constraints
            or program.fields != digest.program.fields):
        raise ValueError('endpoint tail differs from exact digest-plus-framing topology')
    digest_leaf_map = tuple(range(372))+(1204,)
    child_bodies, bodies = dict(digest.spec.bodies), dict(spec.bodies)
    for before, after in enumerate(digest_leaf_map):
        old, new = digest.spec.leaves[before], spec.leaves[after]
        if (old != new or bodies.get(new.body_sha256) != child_bodies.get(old.body_sha256)):
            raise ValueError('endpoint changed a digest child leaf/body/alias occurrence')
    ids = tuple(tail_global_id(word) for word, _ in program.words)
    names = {word: index for index, (word, _) in enumerate(program.words)}
    lo_slots = tuple(names[word] for word in digest.ports['digest_lo_bits'])
    hi_slots = tuple(names[word] for word in digest.ports['digest_hi_bits'])
    frame_indices = tuple(names[word] for word in anchors)
    expected_lo = tuple(f'state/24/l{lane}/b{bit}' for lane in range(4) for bit in range(64))
    expected_frame = tuple(f'state/0/l{byte//8}/b{8*(byte % 8)+bit}' for byte, bit in frame_slots)
    if (len(set(ids)) != TAIL_WORDS or tuple(ids[i] for i in lo_slots) != expected_lo
            or tuple(ids[i] for i in frame_indices) != expected_frame
            or len(expected_frame) != FRAME_BITS
            or any(program.words[i][1] != 2 for i in lo_slots+frame_indices)
            or any(not ids[i].startswith('tail/') for i in hi_slots)
            or sum(name.startswith('tail/') for name in ids) != 699
            or len(set(expected_lo) & set(expected_frame)) != 0):
        raise ValueError('endpoint global aliases differ from exact LO/fixed-input masks')
    for index, (word, ordinal, (byte, bit)) in enumerate(zip(anchors, ordinals, frame_slots, strict=True)):
        leaf = spec.leaves[ordinal]
        expected = dict(fixed_frame_bytes())[byte] >> bit & 1
        if (ordinal != 372+index or leaf.kind != 'const' or leaf.argument != (expected,)
                or leaf.wires != (names[word],)):
            raise ValueError('endpoint framing const occurrences differ from fixed state mask')
    maps = dict(schema=MAP_SCHEMA, digest_word_map=tuple(range(955)),
        digest_leaf_map=digest_leaf_map, lo_indices=lo_slots, hi_indices=hi_slots,
        frame_indices=frame_indices, frame_slots=tuple(frame_slots),
        anchor_ordinals=tuple(ordinals), canonical_result_leaf=1204,
        lo_global_ids=expected_lo, frame_global_ids=expected_frame,
        private_global_ids=tuple(name for name in ids if name.startswith('tail/')),
        global_ids_sha256=sha256(_canonical(list(ids))).hexdigest())
    descriptor = _make(TailDescriptor, index=12, operation_id=operation_id,
        program_sha256=program.digest().hex(), catalogue_id=spec.digest().hex(),
        words=len(program.words), leaves=len(spec.leaves),
        global_ids_sha256=maps['global_ids_sha256'],
        digest_program_sha256=digest.program.digest().hex(),
        digest_catalogue_id=digest.spec.digest().hex(), digest_source_sha256=digest.source_sha256.hex())
    metadata = dict(schema=TAIL_SCHEMA, context=context.hex(), role=role,
        operation_id=operation_id, descriptor=descriptor.json(), source_maps=maps,
        fixed_frame_bytes=fixed_frame_bytes(), input_bit_order='lane-major,LSB-first',
        scope='one framed LO branch; external eval_W/prior-state/HI ports remain unauthenticated')
    encoded = _canonical(metadata)
    return _make(EndpointTail, digest=digest, program=program, spec=spec, descriptor=descriptor,
        global_ids=ids, anchor_words=tuple(anchors), anchor_constraints=tuple(ordinals),
        digest_leaf_map=digest_leaf_map, source_sha256=sha256(TAIL_DOMAIN+encoded).digest(),
        _assignment=tuple(assignment.items()), _metadata=encoded, _maps=_canonical(maps))


@dataclass(frozen=True, init=False)
class EndpointPairBinding:
    index: int
    descriptor: PairDescriptor
    pair_binding: object
    global_ids: tuple[str, ...]
    topology_sha256: bytes
    reference_output_state: tuple[int, ...]
    permutation_prefix_matches_reference: bool

    def __init__(self, *args, **kwargs):
        raise TypeError('stream fresh pairs from a sealed endpoint binding')

    @property
    def binding(self):
        return self.pair_binding


@dataclass(frozen=True, init=False)
class KeccakEndpointBinding:
    plan: object
    eval_w_le: bytes
    prior_state: bytes
    hi: bytes
    scenario: str
    initial_state: tuple[int, ...]
    reference_output_state: tuple[int, ...]
    output_state: tuple[int, ...]
    lo: bytes

    def __init__(self, *args, **kwargs):
        raise TypeError('bind external byte inputs through a sealed endpoint plan')

    def iter_pairs(self):
        """Stream one fresh pair at a time; release yielded aliases before next."""
        _hosted_guard()  # Immediate, rather than deferred until iterator advance.

        def stream():
            current = reference = self.initial_state
            previous_ids = None
            for index in range(PAIR_COUNT):
                planned = self.plan.permutation.regenerate_pair(index)
                if previous_ids is not None:
                    _validate_join(previous_ids, planned.global_ids, state_index=2*index)
                reference = keccak_f1600_round(keccak_f1600_round(reference, 2*index), 2*index+1)
                output = self.output_state if index == 11 and self.scenario == 'coherent-output' else None
                binding = planned.pair.bind(current, claimed_output=output)
                if binding.initial_state != current:
                    raise ValueError('endpoint pair changed its scheduled state input')
                result = _make(EndpointPairBinding, index=index, descriptor=planned.descriptor,
                    pair_binding=binding, global_ids=planned.global_ids,
                    topology_sha256=self.plan.topology_sha256, reference_output_state=reference,
                    permutation_prefix_matches_reference=binding.output_state == reference)
                current, previous_ids = binding.output_state, planned.global_ids
                if index == 11 and current != self.output_state:
                    raise ValueError('fresh final pair does not produce the sealed endpoint output')
                yield result
                del result, binding, planned
        return stream()

    def regenerate_tail(self):
        _hosted_guard()  # Before fresh digest/endpoint Program or Script allocation.
        tail = _build_tail(self.lo, self.hi, self.initial_state, role=self.plan.role,
                           context=self.plan.context, operation_id=self.plan.operation_id+'/tail')
        if tail.descriptor.json() != self.plan.tail_descriptor.json():
            raise ValueError('fresh endpoint tail changed its sealed topology/global-map descriptor')
        return tail

    def summary(self):
        result = dict(scenario=self.scenario, topology_sha256=self.plan.topology_sha256.hex(),
            initial_state_hex=state_to_bytes(self.initial_state).hex(),
            output_state_hex=state_to_bytes(self.output_state).hex(), lo_hex=self.lo.hex(),
            hi_hex=self.hi.hex(), framed_lo_endpoint_binding_constructed=True,
            reference_permutation_matches=self.output_state == self.reference_output_state,
            fixed_framing_matches=self.scenario != 'wrong-padding')
        result.update({flag: False for flag in FALSE_FLAGS})
        return result


@dataclass(frozen=True, init=False)
class KeccakEndpointPlan:
    context: bytes
    role: str
    operation_id: str
    permutation: object
    tail_descriptor: TailDescriptor
    topology_sha256: bytes
    _manifest: bytes

    def __init__(self, *args, **kwargs):
        raise TypeError('use the hosted framed LO endpoint factory')

    @property
    def manifest(self):
        return json.loads(self._manifest)

    @property
    def descriptors(self):
        return self.permutation.descriptors+(self.tail_descriptor,)

    def bind(self, eval_w_le, prior_state, hi, *, scenario='honest'):
        _hosted_guard()  # Before reference states or binding/graph allocation.
        _bytes(eval_w_le, 32, 'external eval_W')
        _bytes(prior_state, 64, 'external prior state')
        _bytes(hi, 32, 'external HI digest')
        if type(scenario) is not str or scenario not in SCENARIOS:
            raise ValueError('unsupported controlled endpoint diagnostic scenario')
        initial_bytes = bytearray(framed_state_bytes(eval_w_le, prior_state))
        if scenario == 'wrong-padding':
            initial_bytes[111] ^= 1
        initial = state_from_bytes(bytes(initial_bytes))
        reference = keccak_f1600(initial)
        output = list(reference)
        if scenario == 'coherent-output':
            output[0] ^= 1
        output = tuple(output)
        return _make(KeccakEndpointBinding, plan=self, eval_w_le=eval_w_le,
            prior_state=prior_state, hi=hi, scenario=scenario, initial_state=initial,
            reference_output_state=reference, output_state=output,
            lo=state_to_bytes(output)[:32])

    def summary(self):
        result = dict(schema=PLAN_SCHEMA, context=self.context.hex(), role=self.role,
            operation_id=self.operation_id, topology_sha256=self.topology_sha256.hex(),
            components=COMPONENTS, pairs=PAIR_COUNT, rounds=24, leaves=TOTAL_LEAVES,
            unique_global_words=GLOBAL_WORDS, component_local_words=LOCAL_WORDS,
            fixed_input_bits=FRAME_BITS, shared_lo_bits=LO_BITS, tail_private_words=699,
            tail_words=TAIL_WORDS, tail_leaves=TAIL_LEAVES,
            framed_lo_endpoint_topology_constructed=True,
            scope='one LO permutation endpoint plus framed external input ports and external HI')
        result.update({flag: False for flag in FALSE_FLAGS})
        return result


def build_keccak_endpoint(*, context, role=ROLE, operation_id='keccak/rho59/lo'):
    """Fresh13-component plan; imported Programs, maps and receipts are rejected."""
    _hosted_guard()  # Before the first actual pair/tail construction.
    _parameters(context, role, operation_id)
    permutation = build_keccak_permutation(context=context, role=role,
                                           operation_id=operation_id+'/permutation')
    # Assignment values are arbitrary here: only the static child descriptor
    # survives in the plan. Actual bindings independently regenerate the tail.
    tail = _build_tail(bytes(32), bytes(32),
        state_from_bytes(framed_state_bytes(bytes(32), bytes(64))),
        role=role, context=context, operation_id=operation_id+'/tail')
    descriptor = tail.descriptor
    del tail
    if (len(permutation.descriptors) != PAIR_COUNT
            or sum(d.leaves for d in permutation.descriptors)+descriptor.leaves != TOTAL_LEAVES
            or sum(d.words for d in permutation.descriptors)+descriptor.words != LOCAL_WORDS
            or LOCAL_WORDS-17600-FRAME_BITS-LO_BITS != GLOBAL_WORDS):
        raise ValueError('complete endpoint topology census differs from its fixed schedule')
    manifest = dict(schema=PLAN_SCHEMA, context=context.hex(), role=role, operation_id=operation_id,
        event_identity=dict(engine='pallas', session=0, sequence=EVENT_SEQUENCE,
                            label_hex='72', counter=COUNTER, branch=0),
        permutation_topology_sha256=permutation.topology_sha256.hex(),
        permutation_operation_id=permutation.operation_id,
        pair_descriptors=[d.json() for d in permutation.descriptors],
        tail_descriptor=descriptor.json(), components=COMPONENTS, leaves=TOTAL_LEAVES,
        component_local_words=LOCAL_WORDS, unique_global_words=GLOBAL_WORDS,
        inter_pair_reuses=17600, endpoint_input_reuses=FRAME_BITS, endpoint_lo_reuses=LO_BITS,
        fixed_frame_bytes=fixed_frame_bytes(), dynamic_byte_ranges=((1, 33), (45, 109)),
        framing='w||eval_W_LE32||NoDS||59_LE8||prior_state64||r||00;Keccak-pad111;zero-capacity64',
        global_ids='LO->state/24 first256;frame->state/0 fixed832;other699->tail/',
        commitment_order='external context -> topology -> keys -> registries -> forest')
    encoded = _canonical(manifest)
    return _make(KeccakEndpointPlan, context=context, role=role, operation_id=operation_id,
        permutation=permutation, tail_descriptor=descriptor,
        topology_sha256=sha256(TOPOLOGY_DOMAIN+encoded).digest(), _manifest=encoded)
