"""Hosted streaming topology/binding for 24 rounds in 12 Keccak pair registries.

No flat Program, GraphSpec or Registry represents the entire permutation. A plan
keeps only small descriptors; every pair is rebuilt under its sealed identity
before use. Canonical global names share only the intended 1,600-bit states.
Topology contains no witness values, WOTS keys, registry IDs, Scripts or roots.
Context -> topology -> test keys -> registries -> component roots remains acyclic.
This exposes graph/reference conformance, not hash/transcript/proof acceptance.
"""
from dataclasses import dataclass
from hashlib import sha256
import json
import os
import re
import sys

from keccak_pair import KeccakPair, KeccakPairBinding, build_keccak_pair
from keccak_trace import _state, keccak_f1600_round
from trace import ID, MAX_WORDS, ROLES

PLAN_SCHEMA = 'bitvm2-nova-keccak-permutation-plan/v1'
GLOBAL_ID_SCHEMA = 'bitvm2-nova-keccak-permutation-global-ids/v1'
TOPOLOGY_DOMAIN = b'BITVM2-NOVA/KECCAK-PERMUTATION-TOPOLOGY/v1\x00'
PAIR_COUNT, ROUND_COUNT, STATE_BITS = 12, 24, 1600
EXPECTED_LEAVES, EXPECTED_PAIR_WORDS, EXPECTED_GLOBAL_WORDS = 230510, 249710, 232110
JOIN_COUNT, JOIN_BITS = 11, 17600
FALSE_FLAGS = ('full_permutation_verified', 'full_hash_verified', 'transcript_verified',
    'proof_verified', 'bitvm2_script_verified', 'production_assertion_binding',
    'bitcoin_transaction_graph', 'full_permutation_verified_in_script',
    'nova_transcript_verified', 'padding_bound_in_script',
    'absorption_bound_in_script', 'squeeze_bound_in_script')
_BOUNDARY = re.compile(r'^boundary/(input|middle|output)/l([0-9]{1,2})/b([0-9]{1,2})$')


def _hosted_guard():
    if (os.environ.get('GITHUB_ACTIONS') != 'true'
            or os.environ.get('RUNNER_OS') != 'Linux' or sys.platform != 'linux'):
        raise ValueError('Keccak permutation planning/binding is hosted GitHub Linux only')


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def _index(value):
    if type(value) is not int or not 0 <= value < PAIR_COUNT:
        raise ValueError('pair index must be 0 through 11')
    return value


def _parameters(context, role, operation_id):
    if type(context) is not bytes or len(context) != 32:
        raise ValueError('caller-owned 32-byte context required')
    if type(role) is not str or role not in ROLES:
        raise ValueError('known Boolean graph field role required')
    if type(operation_id) is not str or not ID.fullmatch(operation_id):
        raise ValueError('valid permutation operation ID required')
    for index in range(PAIR_COUNT):
        if not ID.fullmatch(f'{operation_id}/pair/{index}/child/1/round/{2*index+1}'):
            raise ValueError('derived pair/child operation ID exceeds existing bounds')


def _state_ids(state_index, count=STATE_BITS):
    if type(state_index) is not int or not 0 <= state_index <= ROUND_COUNT:
        raise ValueError('global state index outside 0 through 24')
    if type(count) is not int or not 1 <= count <= STATE_BITS:
        raise ValueError('private state port count outside bounds')
    return tuple(f'state/{state_index}/l{i//64}/b{i%64}' for i in range(count))


def _global_id(pair_index, local_name):
    """Pure tiny-test seam: deterministic names, never value-based aliases."""
    pair_index = _index(pair_index)
    if type(local_name) is not str or not ID.fullmatch(local_name):
        raise ValueError('canonical local word name required')
    match = _BOUNDARY.fullmatch(local_name)
    if match:
        stage, lane_text, bit_text = match.groups()
        lane, bit = int(lane_text), int(bit_text)
        if (not 0 <= lane < 25 or not 0 <= bit < 64
                or lane_text != str(lane) or bit_text != str(bit)):
            raise ValueError('canonical lane/LSB boundary name required')
        offset = {'input': 0, 'middle': 1, 'output': 2}[stage]
        result = f'state/{2*pair_index+offset}/l{lane}/b{bit}'
    elif local_name.startswith('child/0/') or local_name.startswith('child/1/'):
        child, original = int(local_name[6]), local_name[8:]
        if not original or not ID.fullmatch(original):
            raise ValueError('original child word suffix required')
        result = f'round/{2*pair_index+child}/{original}'
    else:
        raise ValueError('unexpected pair-local word namespace')
    if not ID.fullmatch(result):
        raise ValueError('canonical global ID exceeds existing bounds')
    return result


def _global_ids(pair_index, words, *, port_count=STATE_BITS):
    """Private tiny-map seam; public plans always use all 1,600 state ports."""
    pair_index = _index(pair_index)
    if (type(words) is not tuple or not 0 < len(words) <= MAX_WORDS
            or type(port_count) is not int or not 1 <= port_count <= STATE_BITS):
        raise ValueError('bounded immutable local words/state ports required')
    names, ids = set(), []
    states = {2*pair_index+i: set() for i in range(3)}
    for item in words:
        if (type(item) is not tuple or len(item) != 2 or type(item[0]) is not str
                or item[0] in names or type(item[1]) is not int or item[1] != 2):
            raise ValueError('unique bound-two local words required')
        name = item[0]
        global_id = _global_id(pair_index, name)
        names.add(name)
        ids.append(global_id)
        if global_id.startswith('state/'):
            state_index = int(global_id.split('/', 2)[1])
            states[state_index].add(global_id)
    if len(set(ids)) != len(ids):
        raise ValueError('per-pair global mapping must be injective')
    for state_index, found in states.items():
        if found != set(_state_ids(state_index, port_count)):
            raise ValueError('global map lacks an exact ordered state domain')
    return tuple(ids)


def _validate_global_ids(pair_index, words, ids, *, port_count=STATE_BITS):
    if (type(ids) not in (tuple, list) or not 0 < len(ids) <= MAX_WORDS
            or any(type(name) is not str for name in ids)
            or tuple(ids) != _global_ids(pair_index, words, port_count=port_count)):
        raise ValueError('global ID map differs from canonical local-word mapping')


def _validate_join(left_ids, right_ids, *, state_index=None, port_count=STATE_BITS):
    if type(port_count) is not int or not 1 <= port_count <= STATE_BITS:
        raise ValueError('private state port count outside bounds')
    for ids in (left_ids, right_ids):
        if (type(ids) not in (tuple, list) or not 0 < len(ids) <= MAX_WORDS
                or any(type(name) is not str or not ID.fullmatch(name) for name in ids)
                or len(set(ids)) != len(ids)):
            raise ValueError('injective bounded global ID maps required')
    expected = set() if state_index is None else set(_state_ids(state_index, port_count))
    if set(left_ids) & set(right_ids) != expected:
        raise ValueError('global map intersection differs from exact scheduled state join')


@dataclass(frozen=True)
class PairDescriptor:
    index: int
    first_round: int
    operation_id: str
    program_sha256: str
    catalogue_id: str
    words: int
    leaves: int
    first_child_leaves: int
    middle_producer_start: int
    final_output_start: int
    leaf_offset: int
    global_ids_sha256: str

    @property
    def spec_sha256(self):
        return self.catalogue_id

    def json(self):
        return {name: getattr(self, name) for name in self.__dataclass_fields__}


def _describe_pair(pair_index, pair, leaf_offset):
    if type(pair) is not KeccakPair or pair.first_round != 2*_index(pair_index):
        raise ValueError('fresh sealed scheduled KeccakPair required')
    spec, maps = pair.spec, pair.source_maps
    ids = _global_ids(pair_index, spec.words)
    if {i for leaf in spec.leaves for i in leaf.wires} != set(range(len(spec.words))):
        raise ValueError('pair catalogue does not cover all mapped words')
    if (tuple(ids[i] for i in maps['input_indices']) != _state_ids(2*pair_index)
            or tuple(ids[i] for i in maps['boundary_indices']) != _state_ids(2*pair_index+1)
            or tuple(ids[i] for i in maps['output_indices']) != _state_ids(2*pair_index+2)):
        raise ValueError('pair state slots differ from ordered global domains')
    first_count = len(maps['children'][0]['leaf_map'])
    if (tuple(maps['producer_leaves']) != tuple(range(first_count-STATE_BITS, first_count))
            or any(leaf.kind != 'bool_xor' for leaf in spec.leaves[-STATE_BITS:])):
        raise ValueError('scheduled pair producer/output layout changed')
    descriptor = PairDescriptor(pair_index, pair.first_round, pair.operation_id,
        spec.program_sha256, spec.digest().hex(), len(spec.words), len(spec.leaves),
        first_count, first_count-STATE_BITS, len(spec.leaves)-STATE_BITS, leaf_offset,
        sha256(_canonical(list(ids))).hexdigest())
    return descriptor, ids


def _validate_totals(*, pairs, leaves, pair_local_words, unique_global_words,
                     inter_pair_joins, shared_join_bits):
    """Private integer-only budget regression seam; no plan is admitted here."""
    actual = (pairs, leaves, pair_local_words, unique_global_words, inter_pair_joins, shared_join_bits)
    expected = (PAIR_COUNT, EXPECTED_LEAVES, EXPECTED_PAIR_WORDS, EXPECTED_GLOBAL_WORDS,
                JOIN_COUNT, JOIN_BITS)
    if any(type(value) is not int or value != target for value, target in zip(actual, expected, strict=True)):
        raise ValueError('complete permutation topology census differs from retained construction')
    if pair_local_words-shared_join_bits != unique_global_words:
        raise ValueError('global quotient census is inconsistent')


@dataclass(frozen=True, init=False)
class PlannedPair:
    index: int
    descriptor: PairDescriptor
    pair: KeccakPair
    global_ids: tuple[str, ...]

    def __init__(self, *args, **kwargs):
        raise TypeError('regenerate one pair from a sealed permutation plan')


@dataclass(frozen=True, init=False)
class StreamedPairBinding:
    index: int
    descriptor: PairDescriptor
    pair_binding: KeccakPairBinding
    global_ids: tuple[str, ...]
    topology_sha256: bytes
    reference_output_state: tuple[int, ...]
    permutation_prefix_matches_reference: bool

    def __init__(self, *args, **kwargs):
        raise TypeError('stream a binding from a sealed permutation plan')

    @property
    def binding(self):
        return self.pair_binding

    def summary(self):
        result = dict(index=self.index, descriptor=self.descriptor.json(),
            topology_sha256=self.topology_sha256.hex(), reference_checked=True,
            permutation_pair_binding_constructed=True,
            permutation_prefix_matches_reference=self.permutation_prefix_matches_reference,
            middle_matches_reference=self.pair_binding.middle_matches_reference,
            output_matches_reference=self.pair_binding.output_matches_reference,
            scope='streamed permutation prefix reference; no sponge or transcript framing')
        result.update({flag: False for flag in FALSE_FLAGS})
        return result


@dataclass(frozen=True, init=False)
class KeccakPermutationPlan:
    context: bytes
    role: str
    operation_id: str
    descriptors: tuple[PairDescriptor, ...]
    topology_sha256: bytes
    _manifest: bytes

    def __init__(self, *args, **kwargs):
        raise TypeError('use hosted build_keccak_permutation; no receipt/map admission exists')

    @property
    def manifest(self):
        return json.loads(self._manifest)

    def summary(self):
        result = dict(pairs=PAIR_COUNT, rounds=ROUND_COUNT, leaves=EXPECTED_LEAVES,
            pair_local_words=EXPECTED_PAIR_WORDS, unique_global_words=EXPECTED_GLOBAL_WORDS,
            inter_pair_joins=JOIN_COUNT, shared_join_bits=JOIN_BITS,
            topology_sha256=self.topology_sha256.hex(), context=self.context.hex(),
            role=self.role, operation_id=self.operation_id,
            permutation_topology_constructed=True, full_permutation_graph_constructed=True,
            reference_checked=False, topology_identity_kind='streaming plan manifest; no flat Program',
            scope='twelve sealed pair registries with canonical global state IDs')
        result.update({flag: False for flag in FALSE_FLAGS})
        return result

    def regenerate_pair(self, index):
        _hosted_guard()  # Before allocating this real pair.
        index = _index(index)
        pair = build_keccak_pair(2*index, context=self.context, role=self.role,
                                 operation_id=f'{self.operation_id}/pair/{index}')
        if (pair.context != self.context or pair.role != self.role
                or pair.operation_id != f'{self.operation_id}/pair/{index}'):
            raise ValueError('regenerated pair changed caller context/role/operation')
        descriptor, ids = _describe_pair(index, pair, self.descriptors[index].leaf_offset)
        if _canonical(descriptor.json()) != _canonical(self.descriptors[index].json()):
            raise ValueError('regenerated pair changed sealed topology/map descriptor')
        result = object.__new__(PlannedPair)
        for name, value in dict(index=index, descriptor=descriptor, pair=pair, global_ids=ids).items():
            object.__setattr__(result, name, value)
        return result

    def iter_bindings(self, initial_state, claimed_states=None):
        """Yield one pair at a time; callers must not collect full specs.

        Delete the yielded item and any binding/spec aliases before advancing:
        an ordinary for-loop variable otherwise retains the old item while the
        next pair is built. The iterator drops its own full references.

        Diagnostic overrides are restricted to even inter-pair states 2..22.
        A changed state is the producer pair's claimed output and the exact next
        pair input; later pairs are honestly recomputed from that shared value.
        There is no independently chosen consumer copy of a joining state.
        """
        _hosted_guard()  # Immediate guard even before returning an iterator.
        initial = _state(initial_state)
        if claimed_states is not None and (type(claimed_states) is not dict or len(claimed_states) > JOIN_COUNT):
            raise ValueError('bounded diagnostic inter-pair state overrides required')
        overrides = {}
        try:
            for state_index, state in ({} if claimed_states is None else claimed_states).items():
                if type(state_index) is not int or state_index not in range(2, ROUND_COUNT, 2):
                    raise ValueError('diagnostic overrides must name even states 2 through 22')
                overrides[state_index] = _state(state)
        except RuntimeError as error:
            raise ValueError('diagnostic state overrides mutated during snapshot') from error

        def stream():
            current = reference = initial
            previous_ids = None
            for index in range(PAIR_COUNT):
                planned = self.regenerate_pair(index)
                if previous_ids is not None:
                    _validate_join(previous_ids, planned.global_ids, state_index=2*index)
                reference_middle = keccak_f1600_round(reference, 2*index)
                reference_output = keccak_f1600_round(reference_middle, 2*index+1)
                binding = planned.pair.bind(current, claimed_output=overrides.get(2*index+2))
                if (type(binding) is not KeccakPairBinding or binding.pair is not planned.pair
                        or binding.initial_state != current):
                    raise ValueError('fresh pair binding changed the scheduled input state')
                result = object.__new__(StreamedPairBinding)
                for name, value in dict(index=index, descriptor=planned.descriptor,
                    pair_binding=binding, global_ids=planned.global_ids,
                    topology_sha256=self.topology_sha256, reference_output_state=reference_output,
                    permutation_prefix_matches_reference=binding.output_state == reference_output).items():
                    object.__setattr__(result, name, value)
                current, reference = binding.output_state, reference_output
                previous_ids = planned.global_ids
                yield result
                # Only previous IDs survive inside this iterator; see caller
                # alias-lifetime requirements in the method documentation.
                del result, binding, planned
        return stream()

    stream_bindings = iter_bindings


def build_keccak_permutation(*, context, role='pallas_scalar', operation_id='keccak/permutation'):
    """Fresh streaming plan; external child receipts/maps/JSON are unsupported."""
    _hosted_guard()  # Before allocating the first real pair.
    _parameters(context, role, operation_id)
    descriptors, previous_ids = [], None
    leaves = local_words = internal_words = 0
    state_occurrences = [0]*(ROUND_COUNT+1)
    for index in range(PAIR_COUNT):
        pair = build_keccak_pair(2*index, context=context, role=role,
                                 operation_id=f'{operation_id}/pair/{index}')
        if (pair.context != context or pair.role != role
                or pair.operation_id != f'{operation_id}/pair/{index}'):
            raise ValueError('fresh pair changed caller context/role/operation')
        descriptor, ids = _describe_pair(index, pair, leaves)
        if previous_ids is not None:
            _validate_join(previous_ids, ids, state_index=2*index)
        # _global_id confines every state name to these three complete domains
        # and every internal name to these two unique round namespaces. Thus
        # nonadjacent pairs cannot intersect, without retaining all old maps.
        current_states = set(range(2*index, 2*index+3))
        current_rounds = set(range(2*index, 2*index+2))
        for earlier in range(index-1):
            if (current_states & set(range(2*earlier, 2*earlier+3))
                    or current_rounds & set(range(2*earlier, 2*earlier+2))):
                raise ValueError('nonadjacent canonical domains overlap')
        for state_index in current_states:
            state_occurrences[state_index] += 1
        leaves += descriptor.leaves
        local_words += descriptor.words
        internal_words += descriptor.words-3*STATE_BITS
        descriptors.append(descriptor)
        previous_ids = ids
        del pair, ids
    for state_index, count in enumerate(state_occurrences):
        expected = 2 if state_index not in (0, ROUND_COUNT) and state_index % 2 == 0 else 1
        if count != expected:
            raise ValueError('global state domain coverage differs from the scheduled joins')
    unique_words = internal_words+(ROUND_COUNT+1)*STATE_BITS
    _validate_totals(pairs=len(descriptors), leaves=leaves, pair_local_words=local_words,
        unique_global_words=unique_words, inter_pair_joins=PAIR_COUNT-1,
        shared_join_bits=(PAIR_COUNT-1)*STATE_BITS)
    manifest = dict(schema=PLAN_SCHEMA, global_id_schema=GLOBAL_ID_SCHEMA,
        context=context.hex(), role=role, operation_id=operation_id,
        pair_count=PAIR_COUNT, round_count=ROUND_COUNT,
        descriptors=[descriptor.json() for descriptor in descriptors],
        leaves=leaves, pair_local_words=local_words, unique_global_words=unique_words,
        inter_pair_joins=JOIN_COUNT, shared_join_bits=JOIN_BITS,
        state_order='lane-major-least-significant-bit-first',
        validation='injective maps; exact state domains; disjoint internal round namespaces',
        commitment_order='external context -> topology -> keys -> registries -> Scripts -> Taproot')
    encoded = _canonical(manifest)
    plan = object.__new__(KeccakPermutationPlan)
    for name, value in dict(context=context, role=role, operation_id=operation_id,
        descriptors=tuple(descriptors), topology_sha256=sha256(TOPOLOGY_DOMAIN+encoded).digest(),
        _manifest=encoded).items():
        object.__setattr__(plan, name, value)
    return plan
