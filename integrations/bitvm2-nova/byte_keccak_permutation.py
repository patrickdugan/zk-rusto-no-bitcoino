"""Hosted FULL24 BYTE catalogue: one GraphSpec, never an oversized Program.

Six fresh aligned four-round blocks are projected one at a time. Exactly five
200-byte outer states are identified; all18 inner joins survive, giving23
ordered states with4,600 words and9,200 actual consumer coordinates. Natural
terminal producers are preserved without copies, anchors or value-based aliases.

The versioned program identity is a manifest hash, explicitly NOT Program.digest.
Caller context precedes child sources/maps, then program identity, catalogue and
separate source identity. No keys, signatures or roots enter that dependency
chain. Compact manifests commit hashes of bounded raw maps kept separately.

This constructs one permutation relation on external200-byte state ports. It
does not establish sponge framing, a hash, transcript, proof, production
assertion binding, or a Bitcoin transaction graph.
"""
from dataclasses import dataclass
from hashlib import sha256
import json
import os
import sys

from byte_kernels import BYTE, KINDS
from byte_keccak_block import (ByteKeccakBlock, build_byte_keccak_block,
                               _parameters as _block_parameters)
from byte_keccak_round import FALSE_FLAGS
from keccak_trace import keccak_f1600, state_from_bytes, state_to_bytes
from trace import ID, MAX_WORDS, ROLES
from trace_kernels import compile_predicate
from wots_graph import MAX_GRAPH_LEAVES, GraphSpec, Leaf, expansion_script

PROGRAM_SCHEMA = 'bitvm2-nova-byte-keccak-permutation-program/v1'
SOURCE_SCHEMA = 'bitvm2-nova-byte-keccak-permutation-source/v1'
MAP_SCHEMA = 'bitvm2-nova-byte-keccak-permutation-maps/v1'
PROGRAM_DOMAIN = b'BITVM2-NOVA/BYTE-KECCAK-PERMUTATION-PROGRAM/v1\x00'
SOURCE_DOMAIN = b'BITVM2-NOVA/BYTE-KECCAK-PERMUTATION-SOURCE/v1\x00'
BLOCKS, ROUNDS, STATE_BYTES = 6, 24, 200
EXPECTED_WORDS, EXPECTED_LEAVES = 29445, 29245
MAX_RAW_MAP_BYTES, MAX_COMPACT_MANIFEST_BYTES = 8 << 20, 1 << 20


def _hosted_guard():
    if (os.environ.get('GITHUB_ACTIONS') != 'true'
            or os.environ.get('RUNNER_OS') != 'Linux' or sys.platform != 'linux'):
        raise ValueError('FULL24 BYTE construction/binding is hosted GitHub Linux only')


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def _hash(value):
    return sha256(_canonical(value)).hexdigest()


def aligned_block_rounds():
    return (0, 4, 8, 12, 16, 20)


def _index(index):
    if type(index) is not int or not 0 <= index < BLOCKS:
        raise ValueError('aligned block index must be an integer0..5')
    return index


def block_operation_id(index, operation_id):
    _index(index)
    if type(operation_id) is not str or not ID.fullmatch(operation_id):
        raise ValueError('bounded caller permutation operation ID required')
    result = f'{operation_id}/block/{index}'
    if not ID.fullmatch(result):
        raise ValueError('derived block operation ID exceeds existing cap')
    return result


def _parameters(context, role, operation_id):
    if (type(context) is not bytes or len(context) != 32
            or type(role) is not str or role not in ROLES
            or type(operation_id) is not str or not ID.fullmatch(operation_id)):
        raise ValueError('explicit permutation role/operation/immutable32-byte context required')
    # Preflight every block, range identity and all24 nested round identities
    # before constructing even the first real block.
    for index, first in enumerate(aligned_block_rounds()):
        _block_parameters(first, context, role, block_operation_id(index, operation_id))


def _state_ids(round_index, count=STATE_BYTES):
    if (type(round_index) is not int or not 0 <= round_index <= ROUNDS
            or type(count) is not int or not 1 <= count <= STATE_BYTES):
        raise ValueError('canonical absolute BYTE state/count required')
    return tuple(f'byte-state/{round_index}/l{i//8}/byte{i%8}' for i in range(count))


def _validate_maps(child_global_ids, maps, words, *, port_count=STATE_BYTES):
    """Pure tiny quotient validation, never a raw-map catalogue importer."""
    if (type(port_count) is not int or not 1 <= port_count <= STATE_BYTES
            or type(child_global_ids) is not tuple or len(child_global_ids) != BLOCKS
            or type(maps) is not tuple or len(maps) != BLOCKS
            or type(words) is not tuple or not 0 < len(words) <= MAX_WORDS):
        raise ValueError('six bounded immutable BYTE block maps required')
    for item in words:
        if (type(item) is not tuple or len(item) != 2 or type(item[0]) is not str
                or not ID.fullmatch(item[0]) or type(item[1]) is not int or item[1] != BYTE):
            raise ValueError('canonical parent BYTE declarations required')
    names = tuple(name for name, _ in words)
    if len(set(names)) != len(names):
        raise ValueError('duplicate parent word identity')
    encountered, seen, covered = [], set(), set()
    for index, (ids, mapping) in enumerate(zip(child_global_ids, maps, strict=True)):
        if (type(ids) is not tuple or not 0 < len(ids) <= MAX_WORDS
                or any(type(name) is not str or not ID.fullmatch(name) for name in ids)
                or len(set(ids)) != len(ids) or type(mapping) is not tuple
                or len(mapping) != len(ids)
                or any(type(i) is not int or not 0 <= i < len(words) for i in mapping)
                or len(set(mapping)) != len(mapping)):
            raise ValueError('complete injective typed block word map required')
        first = 4*index
        states = {name for r in range(first, first+5) for name in _state_ids(r, port_count)}
        prefixes = tuple(f'byte-round/{r}/' for r in range(first, first+4))
        if (not states <= set(ids)
                or any(name not in states and not any(name.startswith(prefix) and len(name) > len(prefix)
                           for prefix in prefixes) for name in ids)):
            raise ValueError('block must contain exactly its public state/internal domains')
        if any(names[parent] != name for name, parent in zip(ids, mapping, strict=True)):
            raise ValueError('block/parent ordered identity projection changed')
        covered.update(mapping)
        for name in ids:
            if name not in seen:
                seen.add(name)
                encountered.append(name)
    for left in range(BLOCKS):
        for right in range(left+1, BLOCKS):
            expected = set(_state_ids(4*right, port_count)) if right == left+1 else set()
            if set(child_global_ids[left]) & set(child_global_ids[right]) != expected:
                raise ValueError('only five complete adjacent BYTE states may intersect')
    if (tuple(encountered) != names or covered != set(range(len(words)))
            or len(words) != sum(len(ids) for ids in child_global_ids)-5*port_count):
        raise ValueError('full first-encounter quotient/coverage census mismatch')


def _alias(wires):
    unique = tuple(dict.fromkeys(wires))
    return tuple(unique.index(word) for word in wires)


def _make(cls, **fields):
    result = object.__new__(cls)
    for name, value in fields.items():
        object.__setattr__(result, name, value)
    return result


@dataclass(frozen=True, init=False)
class BytePermutationBlockDescriptor:
    index: int
    first_round: int
    last_round: int
    operation_id: str
    program_operation_id: str
    source_sha256: str
    program_sha256: str
    catalogue_id: str
    global_ids_sha256: str
    words: int
    leaves: int
    leaf_offset: int
    word_map_sha256: str
    leaf_map_sha256: str

    def __init__(self, *args, **kwargs):
        raise TypeError('obtain descriptors from the sealed FULL24 BYTE plan')

    def json(self):
        return {name: getattr(self, name) for name in self.__dataclass_fields__}


@dataclass(frozen=True, init=False)
class BytePermutationJoin:
    index: int
    state_round: int
    words: tuple[str, ...]
    indices: tuple[int, ...]
    producer_ordinals: tuple[int, ...]
    producer_occurrences: tuple[int, ...]
    consumer_occurrences: tuple

    def __init__(self, *args, **kwargs):
        raise TypeError('obtain joins from the sealed FULL24 BYTE plan')

    def json(self):
        return json.loads(_canonical({name: getattr(self, name) for name in self.__dataclass_fields__}))


class _Collector:
    """Private one-block-at-a-time projection, never a public receipt importer."""
    def __init__(self, context, role, operation_id):
        _hosted_guard()
        _parameters(context, role, operation_id)
        self.context, self.role, self.operation_id = context, role, operation_id
        self.words, self.indices, self.leaves, self.bodies = [], {}, [], {}
        self.blocks, self.rounds, self.descriptors, self.inner_joins = [], [], [], {}

    def add(self, index, block, spec=None):
        _index(index)
        if index != len(self.blocks) or type(block) is not ByteKeccakBlock:
            raise ValueError('six fresh aligned blocks must be projected in order')
        spec = block.spec if spec is None else spec
        if (block.first_round != 4*index or block.context != self.context or block.role != self.role
                or block.operation_id != block_operation_id(index, self.operation_id)
                or type(spec) is not GraphSpec or spec.digest() != block.spec.digest()
                or spec.program_sha256 != block.program.digest().hex()
                or spec.words != block.program.words or spec.field_leaves
                or tuple(name for name, _ in spec.words) != block.global_ids):
            raise ValueError('fresh aligned block context/role/operation/catalogue changed')
        mapping = []
        for name, bound in spec.words:
            if type(bound) is not int or bound != BYTE:
                raise ValueError('all projected operands must retain exact BYTE bound')
            if name not in self.indices:
                self.indices[name] = len(self.words)
                self.words.append((name, BYTE))
            mapping.append(self.indices[name])
        mapping = tuple(mapping)
        offset = len(self.leaves)
        leaf_map = tuple(range(offset, offset+len(spec.leaves)))
        old_bodies, used, covered = dict(spec.bodies), set(), set()
        for leaf in spec.leaves:
            if type(leaf) is not Leaf or leaf.kind not in KINDS:
                raise ValueError('only actual BYTE gate leaves may enter the full catalogue')
            occurrences = tuple(mapping[i] for i in leaf.wires)
            body = expansion_script(occurrences)+compile_predicate(block.program.p, leaf.kind, leaf.argument)
            encoded = body.hex()
            if (_alias(occurrences) != _alias(leaf.wires)
                    or sha256(body).hexdigest() != leaf.body_sha256
                    or old_bodies.get(leaf.body_sha256) != encoded
                    or self.bodies.get(leaf.body_sha256, encoded) != encoded):
                raise ValueError('projected BYTE body or formal alias partition changed')
            self.bodies[leaf.body_sha256] = encoded
            self.leaves.append(Leaf(leaf.kind, leaf.argument, occurrences, leaf.body_sha256))
            used.add(leaf.body_sha256)
            covered.update(leaf.wires)
        if used != set(old_bodies) or covered != set(range(len(spec.words))):
            raise ValueError('every block body and declared word must be covered')
        descriptor = _make(BytePermutationBlockDescriptor, index=index, first_round=4*index,
            last_round=4*index+3, operation_id=block.operation_id,
            program_operation_id=block.program.operation_id, source_sha256=block.source_sha256.hex(),
            program_sha256=block.program.digest().hex(), catalogue_id=spec.digest().hex(),
            global_ids_sha256=_hash(list(block.global_ids)), words=len(spec.words), leaves=len(spec.leaves),
            leaf_offset=offset, word_map_sha256=_hash(mapping), leaf_map_sha256=_hash(leaf_map))
        self.descriptors.append(descriptor)
        self.blocks.append(descriptor.json() | dict(word_map=mapping, leaf_map=leaf_map))
        source = block.source_maps
        for child_index, old in enumerate(source['children']):
            record = {key: old[key] for key in ('index', 'round_index', 'operation_id',
                'program_operation_id', 'source_sha256', 'program_sha256', 'catalogue_id',
                'global_ids_sha256')}
            record.update(block_index=index, child_index=child_index,
                word_map=tuple(mapping[i] for i in old['word_map']),
                leaf_map=tuple(leaf_map[i] for i in old['leaf_map']),
                input_indices=tuple(mapping[i] for i in old['input_indices']),
                output_indices=tuple(mapping[i] for i in old['output_indices']),
                producer_ordinals=tuple(leaf_map[i] for i in old['producer_ordinals']),
                producer_occurrences=tuple(old['producer_occurrences']),
                input_consumer_occurrences=tuple(tuple((leaf_map[i], formal) for i, formal in cells)
                                                  for cells in old['input_consumer_occurrences']))
            if record['round_index'] != len(self.rounds):
                raise ValueError('all24 actual absolute-round projections must remain ordered')
            self.rounds.append(record)
        for join in block.joins:
            self.inner_joins[join.state_round] = dict(index=join.state_round-1,
                state_round=join.state_round, words=join.words,
                indices=tuple(mapping[i] for i in join.indices),
                producer_ordinals=tuple(leaf_map[i] for i in join.producer_ordinals),
                producer_occurrences=join.producer_occurrences,
                consumer_occurrences=tuple(tuple((leaf_map[i], formal) for i, formal in cells)
                                           for cells in join.consumer_occurrences))
        return descriptor

    def finish(self):
        if len(self.blocks) != BLOCKS or len(self.rounds) != ROUNDS or len(self.inner_joins) != 18:
            raise ValueError('exact six blocks,24 rounds and18 existing inner joins required')
        words, leaves = tuple(self.words), tuple(self.leaves)
        maps = tuple(tuple(record['word_map']) for record in self.blocks)
        ids = tuple(name for name, _ in words)
        child_ids = tuple(tuple(ids[i] for i in mapping) for mapping in maps)
        _validate_maps(child_ids, maps, words)
        if (len(words) != EXPECTED_WORDS or len(leaves) != EXPECTED_LEAVES
                or len(words) > MAX_WORDS or len(leaves) > MAX_GRAPH_LEAVES
                or len(self.bodies) > 512 or any(len(body)//2 > 20000 for body in self.bodies.values())):
            raise ValueError('full BYTE catalogue exceeds unchanged graph/body caps or exact census')
        inputs, outputs = tuple(self.rounds[0]['input_indices']), tuple(self.rounds[-1]['output_indices'])
        if tuple(ids[i] for i in inputs) != _state_ids(0) or tuple(ids[i] for i in outputs) != _state_ids(24):
            raise ValueError('full outer endpoints must be exact ordered states0 and24')
        known, produced, consumed = set(inputs), {}, {}
        if inputs != tuple(range(STATE_BYTES)):
            raise ValueError('first200 parent words must be the external BYTE inputs')
        for ordinal, leaf in enumerate(leaves):
            out = leaf.wires[-1]
            if (out != STATE_BYTES+ordinal or out in known or not set(leaf.wires[:-1]) <= known):
                raise ValueError('full catalogue must remain global single-assignment BYTE gate order')
            produced[out] = (ordinal, len(leaf.wires)-1)
            for formal, word in enumerate(leaf.wires[:-1]):
                consumed.setdefault(word, []).append((ordinal, formal))
            known.add(out)
        if (known != set(range(len(words))) or set(produced)-set(consumed) != set(outputs)
                or set(inputs) & set(outputs) or len(set(outputs)) != STATE_BYTES):
            raise ValueError('only the final200 natural BYTE words may remain terminal')
        joins = []
        for state_round in range(1, ROUNDS):
            left, right = self.rounds[state_round-1:state_round+1]
            shared = tuple(left['output_indices'])
            if shared != tuple(right['input_indices']) or tuple(ids[i] for i in shared) != _state_ids(state_round):
                raise ValueError('actual consecutive round endpoints must be the same ordered200 words')
            producers = tuple(produced[i][0] for i in shared)
            occurrences = tuple(produced[i][1] for i in shared)
            consumers = tuple(tuple(consumed.get(i, ())) for i in shared)
            if (producers != tuple(left['producer_ordinals'])
                    or occurrences != tuple(left['producer_occurrences'])
                    or consumers != tuple(tuple(tuple(cell) for cell in cells)
                                          for cells in right['input_consumer_occurrences'])
                    or any(len(cells) != 2 for cells in consumers)):
                raise ValueError('all23 joins require actual producer and exactly two C/Theta occurrences')
            join = _make(BytePermutationJoin, index=state_round-1, state_round=state_round,
                words=tuple(ids[i] for i in shared), indices=shared,
                producer_ordinals=producers, producer_occurrences=occurrences, consumer_occurrences=consumers)
            if state_round in self.inner_joins and _canonical(join.json()) != _canonical(self.inner_joins[state_round]):
                raise ValueError('an existing block inner join changed under full projection')
            joins.append(join)
        producers = tuple(produced[i][0] for i in outputs)
        occurrences = tuple(produced[i][1] for i in outputs)
        source_maps = dict(schema=MAP_SCHEMA, blocks=self.blocks, rounds=self.rounds,
            input_indices=inputs, output_indices=outputs, producer_ordinals=producers,
            producer_occurrences=occurrences, global_ids=ids, global_ids_sha256=_hash(list(ids)),
            joins=[join.json() for join in joins])
        encoded_maps = _canonical(source_maps)
        if len(encoded_maps) > MAX_RAW_MAP_BYTES:
            raise ValueError('raw source maps exceed their separate bounded file budget')
        maps_sha = sha256(encoded_maps).hexdigest()
        bodies = tuple(sorted(self.bodies.items()))
        program_manifest = dict(schema=PROGRAM_SCHEMA,
            program_identity_kind='domain-separated manifest hash; not Program.digest',
            context=self.context.hex(), field_role=self.role, operation_id=self.operation_id,
            first_round=0, rounds=ROUNDS, words=len(words), leaves=len(leaves),
            source_maps_sha256=maps_sha, body_catalogue_sha256=_hash(list(bodies)),
            blocks=[descriptor.json() for descriptor in self.descriptors])
        program_raw = _canonical(program_manifest)
        if len(program_raw) > MAX_COMPACT_MANIFEST_BYTES:
            raise ValueError('compact program manifest exceeds existing one-MiB bound')
        program_sha = sha256(PROGRAM_DOMAIN+program_raw).digest()
        # Deliberately construct GraphSpec directly. No full Program exists and
        # neither Program's10k cap nor GraphSpec.from_program is bypassed/changed.
        spec = GraphSpec(program_sha.hex(), self.context.hex(), self.role, self.operation_id,
                         words, leaves, bodies, len(leaves), ())
        source_manifest = dict(schema=SOURCE_SCHEMA, context=self.context.hex(), field_role=self.role,
            operation_id=self.operation_id, program_sha256=program_sha.hex(),
            catalogue_id=spec.digest().hex(), program_manifest_sha256=sha256(program_raw).hexdigest(),
            source_maps_sha256=maps_sha,
            scope='one complete BYTE Keccak-f1600 permutation; no sponge, transcript, proof or production assertion')
        source_raw = _canonical(source_manifest)
        if len(source_raw) > MAX_COMPACT_MANIFEST_BYTES:
            raise ValueError('compact source manifest exceeds existing one-MiB bound')
        return dict(spec=spec, program_sha256=program_sha,
            source_sha256=sha256(SOURCE_DOMAIN+source_raw).digest(), source_maps_sha256=bytes.fromhex(maps_sha),
            blocks=tuple(self.descriptors), inputs=tuple(ids[i] for i in inputs),
            outputs=tuple(ids[i] for i in outputs), producer_ordinals=producers,
            producer_occurrences=occurrences, global_ids=ids, joins=tuple(joins),
            _program_manifest=program_raw, _source_manifest=source_raw, _maps=encoded_maps)


def _state_bytes(value, label):
    if type(value) is not bytes or len(value) != STATE_BYTES:
        raise ValueError(f'exact immutable200-byte {label} required')
    return value


@dataclass(frozen=True, init=False)
class ByteKeccakPermutationBinding:
    permutation: object
    spec: GraphSpec
    initial_state: bytes
    states: tuple[bytes, ...]
    reference_output: bytes
    output_state: bytes
    global_ids: tuple[str, ...]
    _assignment: tuple

    def __init__(self, *args, **kwargs):
        raise TypeError('bind through the sealed FULL24 BYTE permutation')

    @property
    def assignment(self):
        return dict(self._assignment)

    def summary(self):
        result = dict(source_sha256=self.permutation.source_sha256.hex(),
            permutation_binding_constructed=True, reference_matches=self.output_state == self.reference_output,
            words=len(self.spec.words), leaves=len(self.spec.leaves), joins=23,
            shared_boundary_words=4600, consumer_occurrences=9200)
        result.update({flag: False for flag in FALSE_FLAGS})
        return result


@dataclass(frozen=True, init=False)
class ByteKeccakPermutation:
    context: bytes
    role: str
    operation_id: str
    spec: GraphSpec
    program_sha256: bytes
    source_sha256: bytes
    source_maps_sha256: bytes
    blocks: tuple[BytePermutationBlockDescriptor, ...]
    inputs: tuple[str, ...]
    outputs: tuple[str, ...]
    producer_ordinals: tuple[int, ...]
    producer_occurrences: tuple[int, ...]
    global_ids: tuple[str, ...]
    joins: tuple[BytePermutationJoin, ...]
    _program_manifest: bytes
    _source_manifest: bytes
    _maps: bytes

    def __init__(self, *args, **kwargs):
        raise TypeError('use the hosted FULL24 BYTE factory; no graph/map/receipt admission')

    @property
    def program_manifest(self):
        return json.loads(self._program_manifest)

    @property
    def source_manifest(self):
        return json.loads(self._source_manifest)

    @property
    def manifest(self):
        return self.source_manifest

    @property
    def source_maps(self):
        return json.loads(self._maps)

    @property
    def topology_sha256(self):
        return self.source_sha256

    def regenerate_block(self, index):
        _hosted_guard()  # Before actual aligned-block allocation.
        index = _index(index)
        block = build_byte_keccak_block(4*index, context=self.context, role=self.role,
                                        operation_id=block_operation_id(index, self.operation_id))
        descriptor = self.blocks[index]
        positions = {name: i for i, (name, _) in enumerate(self.spec.words)}
        mapping = tuple(positions[name] for name in block.global_ids)
        leaf_map = tuple(range(descriptor.leaf_offset, descriptor.leaf_offset+len(block.spec.leaves)))
        actual = dict(index=index, first_round=4*index, last_round=4*index+3,
            operation_id=block.operation_id, program_operation_id=block.program.operation_id,
            source_sha256=block.source_sha256.hex(), program_sha256=block.program.digest().hex(),
            catalogue_id=block.spec.digest().hex(), global_ids_sha256=_hash(list(block.global_ids)),
            words=len(block.spec.words), leaves=len(block.spec.leaves), leaf_offset=descriptor.leaf_offset,
            word_map_sha256=_hash(mapping), leaf_map_sha256=_hash(leaf_map))
        if actual != descriptor.json():
            raise ValueError('fresh block changed its sealed source/program/catalogue/map descriptor')
        return block

    def bind(self, initial_state, *, state_claims=(None,)*23, claimed_output=None):
        _hosted_guard()  # Before any full assignment, block or reference allocation.
        _state_bytes(initial_state, 'initial state')
        if type(state_claims) is not tuple or len(state_claims) != 23:
            raise ValueError('exact immutable23-tuple of None|bytes200 state claims required')
        for value in state_claims:
            if value is not None:
                _state_bytes(value, 'intermediate state claim')
        if claimed_output is not None:
            _state_bytes(claimed_output, 'claimed output')
        collector = _Collector(self.context, self.role, self.operation_id)
        assignment, states, current = {}, [], initial_state
        reference = state_to_bytes(keccak_f1600(state_from_bytes(initial_state)))
        for index in range(BLOCKS):
            block = self.regenerate_block(index)
            final_claim = state_claims[4*index+3] if index < 5 else claimed_output
            binding = block.bind(current, boundary_claims=state_claims[4*index:4*index+3],
                                 claimed_output=final_claim)
            if binding.block is not block or binding.initial_state != current:
                raise ValueError('fresh block binding changed its actual selected incoming state')
            collector.add(index, block, binding.spec)
            values = binding.assignment
            for (name, bound) in binding.spec.words:
                value = values[name]
                if type(bound) is not int or bound != BYTE or type(value) is not int or not 0 <= value < BYTE:
                    raise ValueError('actual full BYTE assignment escaped declared decoder range')
                if name in assignment and assignment[name] != value:
                    raise ValueError('selected shared state has conflicting actual assignment values')
                assignment[name] = value
            states.extend(binding.boundaries)
            current = binding.output_state
            if index < 5:
                states.append(current)
            # Keep only small selected states/assignment values before the next
            # block; do not retain a six-child graph or forest in the binding.
            del values, binding, block
        fresh = collector.finish()
        spec = fresh['spec']
        if (fresh['program_sha256'] != self.program_sha256 or fresh['source_sha256'] != self.source_sha256
                or fresh['source_maps_sha256'] != self.source_maps_sha256
                or spec.digest() != self.spec.digest() or fresh['global_ids'] != self.global_ids
                or fresh['inputs'] != self.inputs or fresh['outputs'] != self.outputs
                or set(assignment) != set(self.global_ids) or len(states) != 23
                or bytes(assignment[word] for word in self.outputs) != current):
            raise ValueError('fresh full binding changed sealed topology/identity/coverage')
        return _make(ByteKeccakPermutationBinding, permutation=self, spec=spec,
            initial_state=initial_state, states=tuple(states), reference_output=reference,
            output_state=current, global_ids=self.global_ids, _assignment=tuple(assignment.items()))

    def summary(self):
        result = dict(schema=SOURCE_SCHEMA, context=self.context.hex(), role=self.role,
            operation_id=self.operation_id, program_sha256=self.program_sha256.hex(),
            program_identity_kind='domain-separated manifest hash; not Program.digest',
            catalogue_id=self.spec.digest().hex(), source_sha256=self.source_sha256.hex(),
            source_maps_sha256=self.source_maps_sha256.hex(), blocks=6, rounds=24,
            words=len(self.spec.words), leaves=len(self.spec.leaves), joins=23,
            shared_boundary_words=4600, consumer_occurrences=9200,
            inter_block_shared_words=1000, inter_block_consumer_occurrences=2000,
            full_permutation_graph_constructed=True, natural_terminal_producers=200,
            boundary_copy_gates=0, zero_anchors=0,
            scope='one full BYTE permutation relation on external state ports only')
        result.update({flag: False for flag in FALSE_FLAGS})
        return result


def build_byte_keccak_permutation(*, context, role, operation_id='byte-keccak/permutation'):
    _hosted_guard()  # Before the first aligned block/GraphSpec allocation.
    _parameters(context, role, operation_id)
    collector = _Collector(context, role, operation_id)
    for index, first in enumerate(aligned_block_rounds()):
        block = build_byte_keccak_block(first, context=context, role=role,
                                        operation_id=block_operation_id(index, operation_id))
        collector.add(index, block)
        del block
    return _make(ByteKeccakPermutation, context=context, role=role, operation_id=operation_id,
                 **collector.finish())
