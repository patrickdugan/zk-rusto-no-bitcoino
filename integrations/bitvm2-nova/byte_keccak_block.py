"""Hosted sealed four-round BYTE composition in one actual Program/registry.

Four fresh absolute-round children share exactly three200-byte state domains.
Parent words are their sealed global identities in first-encounter order; no
assignment value can create an alias. Every child predicate body and formal
alias partition survives. Natural intermediate outputs become consumed joins;
only the last child's200 outputs remain terminal. No copy or zero gate is added.

The parent is an actual versioned ByteProgram below existing resource caps.
Its explicit range operation binds Program identity; a separate source manifest
binds all child identities, maps and actual producer/consumer occurrences.
This is not a full permutation, sponge, transcript, proof or production verifier.
"""
from dataclasses import dataclass
from hashlib import sha256
import json
import os
import sys

from byte_kernels import BYTE, KINDS, ByteConstraint, ByteProgram
from byte_keccak_round import (FALSE_FLAGS, ByteKeccakRound, ByteKeccakRoundBinding,
                               build_byte_keccak_round)
from keccak_trace import keccak_f1600_round, state_from_bytes, state_to_bytes
from trace import ID, MAX_CONSTRAINTS, MAX_WORDS, ROLES
from wots_graph import GraphSpec

SCHEMA = 'bitvm2-nova-byte-keccak-block/v1'
MAP_SCHEMA = 'bitvm2-nova-byte-keccak-block-maps/v1'
SOURCE_DOMAIN = b'BITVM2-NOVA/BYTE-KECCAK-BLOCK/v1\x00'
STATE_BYTES, ROUND_COUNT = 200, 4


def _hosted_guard():
    if (os.environ.get('GITHUB_ACTIONS') != 'true'
            or os.environ.get('RUNNER_OS') != 'Linux' or sys.platform != 'linux'):
        raise ValueError('four-round BYTE block construction/binding is hosted GitHub Linux only')


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def block_rounds(first_round):
    if type(first_round) is not int or not 0 <= first_round <= 20:
        raise ValueError('four-round block must start at an integer0..20')
    return tuple(range(first_round, first_round+ROUND_COUNT))


def parent_operation_id(first_round, operation_id):
    rounds = block_rounds(first_round)
    if type(operation_id) is not str or not ID.fullmatch(operation_id):
        raise ValueError('bounded caller block operation ID required')
    result = f'{operation_id}/rounds/{rounds[0]}-{rounds[-1]}'
    if not ID.fullmatch(result):
        raise ValueError('derived parent range operation ID exceeds existing cap')
    return result


def _parameters(first_round, context, role, operation_id):
    rounds = block_rounds(first_round)
    parent_operation_id(first_round, operation_id)
    if (type(context) is not bytes or len(context) != 32
            or type(role) is not str or role not in ROLES):
        raise ValueError('explicit block role/32-byte immutable caller context required')
    # Check ALL derived identities before constructing even the first child.
    for index, absolute in enumerate(rounds):
        caller = f'{operation_id}/child/{index}'
        if not ID.fullmatch(caller) or not ID.fullmatch(f'{caller}/round/{absolute}'):
            raise ValueError('derived child round operation ID exceeds existing cap')


def _state_ids(round_index, count=STATE_BYTES):
    if (type(round_index) is not int or not 0 <= round_index <= 24
            or type(count) is not int or not 1 <= count <= STATE_BYTES):
        raise ValueError('bounded absolute BYTE state/count required')
    return tuple(f'byte-state/{round_index}/l{i//8}/byte{i%8}' for i in range(count))


def _validate_maps(first_round, child_global_ids, maps, words, *, port_count=STATE_BYTES):
    """Pure tiny-map seam; never admits a public block or imported catalogue."""
    rounds = block_rounds(first_round)
    if (type(port_count) is not int or not 1 <= port_count <= STATE_BYTES
            or type(child_global_ids) is not tuple or len(child_global_ids) != ROUND_COUNT
            or type(maps) is not tuple or len(maps) != ROUND_COUNT
            or type(words) is not tuple or not 0 < len(words) <= MAX_WORDS):
        raise ValueError('four immutable bounded BYTE maps required')
    for item in words:
        if (type(item) is not tuple or len(item) != 2 or type(item[0]) is not str
                or not ID.fullmatch(item[0]) or type(item[1]) is not int or item[1] != BYTE):
            raise ValueError('parent words must have exact BYTE bounds')
    names = tuple(name for name, _ in words)
    if len(set(names)) != len(names):
        raise ValueError('duplicate parent identity')
    encountered, seen, images = [], set(), []
    for index, (ids, mapping) in enumerate(zip(child_global_ids, maps, strict=True)):
        if (type(ids) is not tuple or not 0 < len(ids) <= MAX_WORDS
                or any(type(name) is not str or not ID.fullmatch(name) for name in ids)
                or len(set(ids)) != len(ids) or type(mapping) is not tuple
                or len(mapping) != len(ids)
                or any(type(i) is not int or not 0 <= i < len(words) for i in mapping)
                or len(set(mapping)) != len(mapping)):
            raise ValueError('each child map must be complete, typed and injective')
        states = set(_state_ids(rounds[index], port_count)+_state_ids(rounds[index]+1, port_count))
        if not states <= set(ids):
            raise ValueError('child map lacks an exact complete input/output state')
        prefix = f'byte-round/{rounds[index]}/'
        if any(name not in states and (not name.startswith(prefix) or len(name) == len(prefix))
               for name in ids):
            raise ValueError('child map contains an unintended state/internal domain')
        if any(names[parent] != name for name, parent in zip(ids, mapping, strict=True)):
            raise ValueError('child word order/identity differs from parent map')
        images.append(set(mapping))
        for name in ids:
            if name not in seen:
                seen.add(name)
                encountered.append(name)
    for left in range(ROUND_COUNT):
        for right in range(left+1, ROUND_COUNT):
            expected = set(_state_ids(first_round+right, port_count)) if right == left+1 else set()
            actual = set(child_global_ids[left]) & set(child_global_ids[right])
            if actual != expected:
                raise ValueError('child intersection differs from exact adjacent state join')
    if (tuple(encountered) != names or set.union(*images) != set(range(len(words)))
            or len(words) != sum(len(ids) for ids in child_global_ids)-3*port_count):
        raise ValueError('parent first-encounter quotient/coverage census mismatch')


def _alias_partition(wires):
    unique = tuple(dict.fromkeys(wires))
    return tuple(unique.index(word) for word in wires)


def _parent_ssa(program, inputs, outputs):
    known, produced, consumed, order = set(inputs), {}, set(), list(inputs)
    for ordinal, constraint in enumerate(program.constraints):
        if (type(constraint) is not ByteConstraint or constraint.kind not in KINDS
                or constraint.wires[-1] in known or not set(constraint.wires[:-1]) <= known):
            raise ValueError('parent must preserve BYTE single-assignment gate order')
        out = constraint.wires[-1]
        produced[out] = ordinal
        consumed.update(constraint.wires[:-1])
        known.add(out)
        order.append(out)
    if (tuple(order) != tuple(word for word, _ in program.words)
            or set(outputs) != set(produced)-consumed or len(set(outputs)) != STATE_BYTES
            or set(inputs) & set(outputs)):
        raise ValueError('only the final200 mapped outputs may remain terminal')
    ordinals = tuple(produced[word] for word in outputs)
    occurrences = tuple(len(program.constraints[i].wires)-1 for i in ordinals)
    return ordinals, occurrences


@dataclass(frozen=True, init=False)
class ByteBlockJoin:
    index: int
    state_round: int
    words: tuple[str, ...]
    indices: tuple[int, ...]
    producer_ordinals: tuple[int, ...]
    producer_occurrences: tuple[int, ...]
    consumer_occurrences: tuple

    def __init__(self, *args, **kwargs):
        raise TypeError('obtain joins from the sealed BYTE block factory')

    def json(self):
        return json.loads(_canonical({name: getattr(self, name) for name in self.__dataclass_fields__}))


def _make(cls, **fields):
    result = object.__new__(cls)
    for name, value in fields.items():
        object.__setattr__(result, name, value)
    return result


def _compose(first_round, context, role, operation_id, children, programs=None, specs=None):
    _hosted_guard()  # Private composition cannot bypass the real-graph guard.
    _parameters(first_round, context, role, operation_id)
    if type(children) is not tuple or len(children) != ROUND_COUNT:
        raise ValueError('four freshly sealed absolute-round children required')
    programs = tuple(child.program for child in children) if programs is None else programs
    specs = tuple(child.spec for child in children) if specs is None else specs
    if type(programs) is not tuple or type(specs) is not tuple or len(programs) != 4 or len(specs) != 4:
        raise ValueError('exact fresh child program/catalogue projections required')
    for index, (child, program, spec) in enumerate(zip(children, programs, specs, strict=True)):
        absolute, caller = first_round+index, f'{operation_id}/child/{index}'
        if (type(child) is not ByteKeccakRound or type(program) is not ByteProgram
                or type(spec) is not GraphSpec or child.round_index != absolute
                or child.context != context or child.role != role or child.operation_id != caller
                or program.operation_id != f'{caller}/round/{absolute}'
                or program.context != context or program.field_role != role or program.fields
                or program.digest() != child.program.digest() or spec.digest() != child.spec.digest()
                or spec.program_sha256 != program.digest().hex()
                or len(spec.leaves) != len(program.constraints) or spec.field_leaves):
            raise ValueError('child absolute round/context/role/operation/source projection mismatch')
    words, indices, word_maps, constraints, leaf_maps = [], {}, [], [], []
    for child, program in zip(children, programs, strict=True):
        mapping = []
        for (local, bound), global_id in zip(program.words, child.global_ids, strict=True):
            if type(bound) is not int or bound != BYTE:
                raise ValueError('child BYTE bound changed')
            if global_id not in indices:
                indices[global_id] = len(words)
                words.append((global_id, BYTE))
            mapping.append(indices[global_id])
        mapping = tuple(mapping)
        word_maps.append(mapping)
        local_indices = {name: i for i, (name, _) in enumerate(program.words)}
        offset = len(constraints)
        for constraint in program.constraints:
            mapped = tuple(words[mapping[local_indices[word]]][0] for word in constraint.wires)
            constraints.append(ByteConstraint(constraint.kind, mapped, constraint.argument))
        leaf_maps.append(tuple(range(offset, len(constraints))))
    words, word_maps, leaf_maps = tuple(words), tuple(word_maps), tuple(leaf_maps)
    _validate_maps(first_round, tuple(child.global_ids for child in children), word_maps, words)
    if not 0 < len(constraints) <= MAX_CONSTRAINTS:
        raise ValueError('four-round parent exceeds existing constraint cap')
    program = ByteProgram(role, parent_operation_id(first_round, operation_id), context,
                          words, (), tuple(constraints))
    spec = GraphSpec.from_program(program)
    bodies = dict(spec.bodies)
    child_records = []
    for index, (child, old_spec, mapping, leaves) in enumerate(zip(children, specs, word_maps, leaf_maps, strict=True)):
        old_bodies = dict(old_spec.bodies)
        for before, after in enumerate(leaves):
            old, new = old_spec.leaves[before], spec.leaves[after]
            if (new.kind != old.kind or new.argument != old.argument
                    or new.wires != tuple(mapping[i] for i in old.wires)
                    or _alias_partition(new.wires) != _alias_partition(old.wires)
                    or new.body_sha256 != old.body_sha256
                    or bodies.get(new.body_sha256) != old_bodies.get(old.body_sha256)):
                raise ValueError('a projected child predicate body/alias partition changed')
        old_indices = {word: i for i, (word, _) in enumerate(child.program.words)}
        input_local = tuple(old_indices[word] for word in child.inputs)
        output_local = tuple(old_indices[word] for word in child.outputs)
        consumers = {slot: [] for slot in input_local}
        for old_ordinal, leaf in enumerate(old_spec.leaves):
            for formal, slot in enumerate(leaf.wires[:-1]):
                if slot in consumers:
                    consumers[slot].append((leaves[old_ordinal], formal))
        consumer_slots = []
        for slot, local in enumerate(input_local):
            lane, j = divmod(slot, 8)
            x, y = lane % 5, lane//5
            expected = ((leaves[x*32+j*4+max(y-1, 0)], 0 if y == 0 else 1),
                        (leaves[240+slot], 0))
            if tuple(consumers[local]) != expected:
                raise ValueError('a state byte must have exactly its two actual C/Theta consumers')
            consumer_slots.append(expected)
        producers = tuple(leaves[ordinal] for ordinal in child.producer_ordinals)
        producer_occurrences = tuple(len(spec.leaves[ordinal].wires)-1 for ordinal in producers)
        mapped_output = tuple(mapping[local] for local in output_local)
        if any(spec.leaves[ordinal].wires[formal] != word for ordinal, formal, word
               in zip(producers, producer_occurrences, mapped_output, strict=True)):
            raise ValueError('natural child producer does not produce its actual mapped output')
        child_records.append(dict(index=index, round_index=child.round_index,
            operation_id=child.operation_id, program_operation_id=child.program.operation_id,
            source_sha256=child.source_sha256.hex(), program_sha256=child.program.digest().hex(),
            catalogue_id=child.spec.digest().hex(),
            global_ids_sha256=child.source_maps['global_ids_sha256'], word_map=mapping, leaf_map=leaves,
            input_indices=tuple(mapping[local] for local in input_local), output_indices=mapped_output,
            producer_ordinals=producers, producer_occurrences=producer_occurrences,
            input_consumer_occurrences=tuple(consumer_slots)))
    joins = []
    for index in range(3):
        left, right = child_records[index:index+2]
        shared = tuple(left['output_indices'])
        state_round = first_round+index+1
        if (shared != tuple(right['input_indices'])
                or tuple(words[i][0] for i in shared) != _state_ids(state_round)):
            raise ValueError('ordered actual output/input state bytes must be identical parent words')
        joins.append(_make(ByteBlockJoin, index=index, state_round=state_round,
            words=tuple(words[i][0] for i in shared), indices=shared,
            producer_ordinals=left['producer_ordinals'], producer_occurrences=left['producer_occurrences'],
            consumer_occurrences=right['input_consumer_occurrences']))
    inputs = tuple(words[i][0] for i in child_records[0]['input_indices'])
    outputs = tuple(words[i][0] for i in child_records[-1]['output_indices'])
    producers, producer_occurrences = _parent_ssa(program, inputs, outputs)
    if (producers != child_records[-1]['producer_ordinals']
            or producer_occurrences != child_records[-1]['producer_occurrences']
            or len(spec.leaves) != sum(len(old.leaves) for old in specs)
            or len(program.words) != STATE_BYTES+len(spec.leaves)):
        raise ValueError('parent leaves/SSA/terminal producer census differs from its complete children')
    ids = tuple(name for name, _ in words)
    maps = dict(schema=MAP_SCHEMA, first_round=first_round, children=child_records,
        input_indices=child_records[0]['input_indices'], output_indices=child_records[-1]['output_indices'],
        producer_ordinals=producers, producer_occurrences=producer_occurrences,
        global_ids=ids, global_ids_sha256=sha256(_canonical(list(ids))).hexdigest(),
        joins=[join.json() for join in joins])
    manifest = dict(schema=SCHEMA, first_round=first_round, last_round=first_round+3,
        context=context.hex(), role=role, operation_id=operation_id,
        program_operation_id=program.operation_id, program_sha256=program.digest().hex(),
        catalogue_id=spec.digest().hex(), inputs=inputs, outputs=outputs, source_maps=maps,
        commitment_order='external context -> source topology -> keys -> registry -> Script',
        scope='four consecutive BYTE rounds only; no full permutation, sponge, transcript or proof')
    return program, spec, inputs, outputs, producers, producer_occurrences, ids, tuple(joins), manifest


def _bytes(value, label):
    if type(value) is not bytes or len(value) != STATE_BYTES:
        raise ValueError(f'exact immutable200-byte {label} required')
    return value


@dataclass(frozen=True, init=False)
class ByteKeccakBlockBinding:
    block: object
    program: ByteProgram
    spec: GraphSpec
    children: tuple
    initial_state: bytes
    boundaries: tuple[bytes, ...]
    reference_output: bytes
    output_state: bytes
    global_ids: tuple[str, ...]
    _assignment: tuple

    def __init__(self, *args, **kwargs):
        raise TypeError('bind through the sealed four-round BYTE block')

    @property
    def assignment(self):
        return dict(self._assignment)

    def summary(self):
        result = dict(first_round=self.block.first_round, source_sha256=self.block.source_sha256.hex(),
            block_binding_constructed=True, reference_matches=self.output_state == self.reference_output,
            words=len(self.program.words), leaves=len(self.spec.leaves),
            shared_boundary_words=600, consumer_occurrences=1200)
        result.update({flag: False for flag in FALSE_FLAGS})
        return result


@dataclass(frozen=True, init=False)
class ByteKeccakBlock:
    first_round: int
    context: bytes
    role: str
    operation_id: str
    children: tuple
    program: ByteProgram
    spec: GraphSpec
    inputs: tuple[str, ...]
    outputs: tuple[str, ...]
    producer_ordinals: tuple[int, ...]
    producer_occurrences: tuple[int, ...]
    global_ids: tuple[str, ...]
    joins: tuple[ByteBlockJoin, ...]
    source_sha256: bytes
    _manifest: bytes
    _maps: bytes

    def __init__(self, *args, **kwargs):
        raise TypeError('use the hosted four-round BYTE block factory; no receipt/map admission')

    @property
    def manifest(self):
        return json.loads(self._manifest)

    @property
    def source_maps(self):
        return json.loads(self._maps)

    @property
    def program_operation_id(self):
        return self.program.operation_id

    @property
    def topology_sha256(self):
        return self.source_sha256

    def bind(self, initial_state, *, boundary_claims=(None, None, None), claimed_output=None):
        _hosted_guard()  # Before any child regeneration, Script or reference state.
        _bytes(initial_state, 'initial state')
        if type(boundary_claims) is not tuple or len(boundary_claims) != 3:
            raise ValueError('exact immutable three-tuple of None|bytes200 boundary claims required')
        for value in boundary_claims:
            if value is not None:
                _bytes(value, 'boundary claim')
        if claimed_output is not None:
            _bytes(claimed_output, 'claimed output')
        current, bindings = initial_state, []
        reference = state_from_bytes(initial_state)
        for index, child in enumerate(self.children):
            requested = boundary_claims[index] if index < 3 else claimed_output
            bound = child.bind(current, claimed_output=requested)
            if type(bound) is not ByteKeccakRoundBinding or bound.round is not child or bound.initial_state != current:
                raise ValueError('fresh child binding changed its sealed source or actual incoming state')
            bindings.append(bound)
            current = bound.output_state
            # This reference never consumes a diagnostic boundary override.
            reference = keccak_f1600_round(reference, self.first_round+index)
        bindings = tuple(bindings)
        built = _compose(self.first_round, self.context, self.role, self.operation_id, self.children,
            tuple(binding.program for binding in bindings), tuple(binding.spec for binding in bindings))
        program, spec, inputs, outputs, producers, occurrences, ids, joins, manifest = built
        if (sha256(SOURCE_DOMAIN+_canonical(manifest)).digest() != self.source_sha256
                or program.digest() != self.program.digest() or spec.digest() != self.spec.digest()
                or inputs != self.inputs or outputs != self.outputs or producers != self.producer_ordinals
                or occurrences != self.producer_occurrences or ids != self.global_ids):
            raise ValueError('fresh block composition changed its sealed source/maps/producer identity')
        assignment = {}
        for child, binding in zip(self.children, bindings, strict=True):
            values = binding.assignment
            for (local, _), global_id in zip(binding.program.words, child.global_ids, strict=True):
                value = values[local]
                if global_id in assignment and assignment[global_id] != value:
                    raise ValueError('a shared boundary has conflicting actual assignment values')
                assignment[global_id] = value
        program._admit(assignment)
        if bytes(assignment[word] for word in outputs) != current:
            raise ValueError('actual final200 parent words differ from selected final child output')
        return _make(ByteKeccakBlockBinding, block=self, program=program, spec=spec,
            children=bindings, initial_state=initial_state, boundaries=tuple(b.output_state for b in bindings[:3]),
            reference_output=state_to_bytes(reference), output_state=current,
            global_ids=ids, _assignment=tuple(assignment.items()))

    def summary(self):
        result = dict(schema=SCHEMA, first_round=self.first_round, last_round=self.first_round+3,
            context=self.context.hex(), role=self.role, operation_id=self.operation_id,
            program_operation_id=self.program.operation_id, source_sha256=self.source_sha256.hex(),
            program_sha256=self.program.digest().hex(), catalogue_id=self.spec.digest().hex(),
            rounds=4, words=len(self.program.words), leaves=len(self.spec.leaves),
            input_bytes=STATE_BYTES, output_bytes=STATE_BYTES, natural_terminal_producers=STATE_BYTES,
            joins=3, shared_boundary_words=600, consumer_occurrences=1200,
            block_graph_constructed=True, boundary_copy_gates=0, zero_anchors=0,
            scope='four consecutive BYTE rounds only')
        result.update({flag: False for flag in FALSE_FLAGS})
        return result


def build_byte_keccak_block(first_round, *, context, role, operation_id='byte-keccak/block'):
    _hosted_guard()  # Before even the first child's actual builder allocation.
    _parameters(first_round, context, role, operation_id)
    children = tuple(build_byte_keccak_round(absolute, context=context, role=role,
                     operation_id=f'{operation_id}/child/{index}')
                     for index, absolute in enumerate(block_rounds(first_round)))
    built = _compose(first_round, context, role, operation_id, children)
    program, spec, inputs, outputs, producers, occurrences, ids, joins, manifest = built
    encoded = _canonical(manifest)
    return _make(ByteKeccakBlock, first_round=first_round, context=context, role=role,
        operation_id=operation_id, children=children, program=program, spec=spec,
        inputs=inputs, outputs=outputs, producer_ordinals=producers, producer_occurrences=occurrences,
        global_ids=ids, joins=joins, source_sha256=sha256(SOURCE_DOMAIN+encoded).digest(),
        _manifest=encoded, _maps=_canonical(manifest['source_maps']))
