"""Sealed topology for exactly two adjacent Boolean Keccak rounds.

Full construction and binding are hosted-only. Children retain existing Program
caps; their pair is a GraphSpec, never an oversized Program. program_sha256 is a
versioned manifest hash, not Program.digest. Only 1,600 ordered middle bits share
global words. Caller context precedes topology, WOTS keys, Scripts and Taproot.
This is not a full permutation, hash, transcript, proof or production verifier.
"""
from dataclasses import dataclass
from hashlib import sha256
import json
import os
import sys

from keccak_trace import _state, keccak_f1600_round, keccak_round_trace, state_wire_names
from trace import ID, MAX_CONSTRAINTS, MAX_WORDS, ROLES
from trace_kernels import compile_predicate
from wots_graph import MAX_GRAPH_LEAVES, GraphSpec, Leaf, expansion_script

MANIFEST_SCHEMA = 'bitvm2-nova-keccak-pair-program/v1'
PROGRAM_DOMAIN = b'BITVM2-NOVA/KECCAK-PAIR-PROGRAM/v1\x00'
PORT_COUNT = 1600
FALSE_FLAGS = ('full_permutation_verified', 'full_hash_verified', 'transcript_verified',
    'proof_verified', 'bitvm2_script_verified', 'production_assertion_binding',
    'bitcoin_transaction_graph')


def _hosted_guard():
    if (os.environ.get('GITHUB_ACTIONS') != 'true'
            or os.environ.get('RUNNER_OS') != 'Linux' or sys.platform != 'linux'):
        raise ValueError('full Keccak pair construction/binding is hosted GitHub Linux only')


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def _parameters(first_round, context, role, operation_id):
    if type(first_round) is not int or not 0 <= first_round < 23:
        raise ValueError('adjacent Keccak first round must be 0 through 22')
    if type(context) is not bytes or len(context) != 32:
        raise ValueError('caller-owned 32-byte context required')
    if type(role) is not str or role not in ROLES:
        raise ValueError('known Keccak field role required')
    if type(operation_id) is not str or not ID.fullmatch(operation_id):
        raise ValueError('valid pair operation ID required')
    for child, round_index in enumerate((first_round, first_round+1)):
        if not ID.fullmatch(f'{operation_id}/child/{child}/round/{round_index}'):
            raise ValueError('child operation ID exceeds existing bounds')


def _hex(value, size=None, maximum=None):
    if (type(value) is not str or len(value) % 2
            or (size is not None and len(value) != 2*size)
            or (maximum is not None and len(value) > 2*maximum)
            or any(c not in '0123456789abcdef' for c in value)):
        raise ValueError('canonical bounded lowercase hex required')
    return bytes.fromhex(value)


def _boundary_names(stage, count):
    return tuple(f'boundary/{stage}/l{i//64}/b{i%64}' for i in range(count))


def _ports(value, size, count, description):
    if (type(value) not in (tuple, list) or len(value) != count
            or any(type(i) is not int or not 0 <= i < size for i in value)
            or len(set(value)) != count):
        raise ValueError(f'invalid ordered {description} ports')
    return tuple(value)


def _predicate(kind, argument, modulus):
    if type(argument) is not tuple:
        raise ValueError('immutable Boolean leaf arguments required')
    if kind in ('bool_xor', 'bool_and', 'bool_not'):
        if argument:
            raise ValueError('Boolean leaf has unexpected arguments')
        return compile_predicate(modulus, kind, argument)
    if kind == 'const':
        if len(argument) != 1 or type(argument[0]) is not int or argument[0] not in (0, 1):
            raise ValueError('Boolean constant required')
        return compile_predicate(modulus, kind, argument)
    if kind == 'word_valid' and not argument:
        return bytes([0x75, 0x51])
    raise ValueError('only Boolean/constant/word-valid predicates supported')


def _validate_spec(spec, context, role):
    if type(spec) is not GraphSpec or spec.context != context.hex() or spec.field_role != role:
        raise ValueError('typed child GraphSpec with matching context/role required')
    _hex(spec.program_sha256, 32)
    if (type(spec.operation_id) is not str or not ID.fullmatch(spec.operation_id)
            or type(spec.words) is not tuple or not 0 < len(spec.words) <= MAX_WORDS
            or type(spec.leaves) is not tuple or not 0 < len(spec.leaves) <= MAX_CONSTRAINTS
            or spec.field_leaves != () or type(spec.bodies) is not tuple):
        raise ValueError('bounded immutable Boolean child catalogue required')
    names = set()
    for item in spec.words:
        if (type(item) is not tuple or len(item) != 2 or type(item[0]) is not str
                or not ID.fullmatch(item[0]) or item[0] in names
                or type(item[1]) is not int or item[1] != 2):
            raise ValueError('unique bound-two child words required')
        names.add(item[0])
    if (type(spec.original_constraints) is not int
            or not 0 < spec.original_constraints <= len(spec.leaves)
            or len(spec.bodies) > len(spec.leaves)):
        raise ValueError('child constraint/body census mismatch')
    bodies = {}
    for item in spec.bodies:
        if type(item) is not tuple or len(item) != 2:
            raise ValueError('immutable child body record required')
        digest, encoded = item
        _hex(digest, 32)
        body = _hex(encoded, maximum=1024)
        if digest in bodies or sha256(body).hexdigest() != digest:
            raise ValueError('duplicate or unauthenticated child predicate body')
        bodies[digest] = body
    used, covered = set(), set()
    arities = {'bool_xor': 3, 'bool_and': 3, 'bool_not': 2, 'const': 1, 'word_valid': 1}
    for leaf in spec.leaves:
        if (type(leaf) is not Leaf or type(leaf.wires) is not tuple
                or type(leaf.kind) is not str or leaf.kind not in arities
                or len(leaf.wires) != arities[leaf.kind]
                or any(type(i) is not int or not 0 <= i < len(spec.words) for i in leaf.wires)):
            raise ValueError('unsupported child leaf occurrences')
        compiled = expansion_script(leaf.wires)+_predicate(leaf.kind, leaf.argument, ROLES[role])
        if (sha256(compiled).hexdigest() != leaf.body_sha256
                or bodies.get(leaf.body_sha256) != compiled):
            raise ValueError('child expansion/predicate bytes differ from catalogue')
        used.add(leaf.body_sha256)
        covered.update(leaf.wires)
    if used != set(bodies):
        raise ValueError('unreferenced child bodies are not accepted')
    if covered != set(range(len(spec.words))):
        raise ValueError('child catalogue has uncovered declared words')
    return bodies


def _validate_maps(specs, maps, producer_ports, consumer_ports, words, *, port_count):
    """Private raw-map validator; never admits a public KeccakPair."""
    if type(port_count) is not int or not 1 <= port_count <= PORT_COUNT:
        raise ValueError('private boundary count outside bounds')
    if (type(specs) not in (tuple, list) or len(specs) != 2
            or any(type(s) is not GraphSpec for s in specs)
            or type(maps) not in (tuple, list) or len(maps) != 2
            or type(words) is not tuple or not 0 < len(words) <= MAX_WORDS):
        raise ValueError('two child maps and bounded global words required')
    producer_ports = _ports(producer_ports, len(specs[0].words), port_count, 'producer')
    consumer_ports = _ports(consumer_ports, len(specs[1].words), port_count, 'consumer')
    if len(words) != sum(len(spec.words) for spec in specs)-port_count:
        raise ValueError('global word count does not match exact boundary quotient')
    names = set()
    for name, bound in words:
        if (type(name) is not str or not ID.fullmatch(name) or name in names
                or type(bound) is not int or bound != 2):
            raise ValueError('unique bound-two global words required')
        names.add(name)
    images = []
    for spec, mapping in zip(specs, maps, strict=True):
        if (type(mapping) not in (tuple, list) or len(mapping) != len(spec.words)
                or any(type(i) is not int or not 0 <= i < len(words) for i in mapping)
                or len(set(mapping)) != len(mapping)):
            raise ValueError('per-child word map must be complete and injective')
        if any(type(bound) is not int or bound != 2 or words[mapping[i]][1] != bound
               for i, (_, bound) in enumerate(spec.words)):
            raise ValueError('child/global word bound mismatch')
        images.append(set(mapping))
    boundary = tuple(maps[0][i] for i in producer_ports)
    if any(maps[1][i] != boundary[slot] for slot, i in enumerate(consumer_ports)):
        raise ValueError('ordered producer/consumer slots differ')
    if images[0] & images[1] != set(boundary):
        raise ValueError('child map intersection must be exactly the declared boundary')
    if images[0] | images[1] != set(range(len(words))):
        raise ValueError('global map image has missing words')
    if tuple(words[i][0] for i in boundary) != _boundary_names('middle', port_count):
        raise ValueError('global middle names do not match ordered lane/LSB slots')


def _alias_partition(indices):
    first = {}
    return tuple(first.setdefault(index, len(first)) for index in indices)


def _add_body(target, digest, body):
    if digest in target and target[digest] != body:
        raise ValueError('body hash collision has different predicate bytes')
    target[digest] = body


def _merge_specs(specs, producer_ports, consumer_ports, *, first_round, context, role,
                 operation_id, port_count=PORT_COUNT, input_ports=(), output_ports=()):
    """Private tiny-test/raw merge seam; not a KeccakPair admission API."""
    _parameters(first_round, context, role, operation_id)
    if type(specs) not in (tuple, list) or len(specs) != 2:
        raise ValueError('two child specifications required')
    specs = tuple(specs)
    child_bodies = [_validate_spec(spec, context, role) for spec in specs]
    if type(port_count) is not int or not 1 <= port_count <= PORT_COUNT:
        raise ValueError('private boundary count outside bounds')
    producer_ports = _ports(producer_ports, len(specs[0].words), port_count, 'producer')
    consumer_ports = _ports(consumer_ports, len(specs[1].words), port_count, 'consumer')
    if type(input_ports) not in (tuple, list) or type(output_ports) not in (tuple, list):
        raise ValueError('ordered outer endpoint lists required')
    inputs = _ports(input_ports, len(specs[0].words), len(input_ports), 'input')
    outputs = _ports(output_ports, len(specs[1].words), len(output_ports), 'output')
    if (len(inputs) not in (0, port_count) or len(outputs) not in (0, port_count)
            or set(inputs) & set(producer_ports) or set(outputs) & set(consumer_ports)):
        raise ValueError('outer endpoints must be disjoint complete port lists')
    if sum(len(spec.leaves) for spec in specs) > MAX_GRAPH_LEAVES:
        raise ValueError('composite catalogue exceeds unchanged leaf cap')
    middle_names = _boundary_names('middle', port_count)
    input_names, output_names = _boundary_names('input', len(inputs)), _boundary_names('output', len(outputs))
    source_outputs = {word: i for i, word in enumerate(producer_ports)}
    source_inputs = {word: i for i, word in enumerate(consumer_ports)}
    outer_inputs = {word: i for i, word in enumerate(inputs)}
    outer_outputs = {word: i for i, word in enumerate(outputs)}
    words, left_map, right_map = [], [], []
    for i, (name, bound) in enumerate(specs[0].words):
        mapped = (middle_names[source_outputs[i]] if i in source_outputs else
                  input_names[outer_inputs[i]] if i in outer_inputs else 'child/0/'+name)
        left_map.append(len(words))
        words.append((mapped, bound))
    for i, (name, bound) in enumerate(specs[1].words):
        if i in source_inputs:
            right_map.append(left_map[producer_ports[source_inputs[i]]])
        else:
            mapped = output_names[outer_outputs[i]] if i in outer_outputs else 'child/1/'+name
            right_map.append(len(words))
            words.append((mapped, bound))
    words, maps = tuple(words), (tuple(left_map), tuple(right_map))
    _validate_maps(specs, maps, producer_ports, consumer_ports, words, port_count=port_count)
    leaves, bodies, children = [], {}, []
    for child, (spec, mapping) in enumerate(zip(specs, maps, strict=True)):
        leaf_map = []
        for leaf in spec.leaves:
            occurrences = tuple(mapping[i] for i in leaf.wires)
            if _alias_partition(occurrences) != _alias_partition(leaf.wires):
                raise ValueError('leaf alias partition changed')
            compiled = expansion_script(occurrences)+_predicate(leaf.kind, leaf.argument, ROLES[role])
            if (sha256(compiled).hexdigest() != leaf.body_sha256
                    or compiled != child_bodies[child][leaf.body_sha256]):
                raise ValueError('remapped leaf expansion/predicate hash changed')
            _add_body(bodies, leaf.body_sha256, compiled)
            leaf_map.append(len(leaves))
            leaves.append(Leaf(leaf.kind, leaf.argument, occurrences, leaf.body_sha256))
        children.append(dict(round=first_round+child, namespace=f'child/{child}',
            program_sha256=spec.program_sha256, spec_sha256=spec.digest().hex(),
            word_map=list(mapping), leaf_map=leaf_map))
    # Derive incidence once; do not search a full child for each middle bit.
    produced, consumed = {}, {}
    for ordinal, leaf in enumerate(specs[0].leaves):
        produced.setdefault(leaf.wires[-1], []).append(ordinal)
    offset = len(specs[0].leaves)
    for ordinal, leaf in enumerate(specs[1].leaves):
        for word in set(leaf.wires):
            consumed.setdefault(word, []).append(offset+ordinal)
    producer_leaves, consumer_leaves = [], []
    for output, input_ in zip(producer_ports, consumer_ports, strict=True):
        matches = produced.get(output, [])
        if len(matches) != 1:
            raise ValueError('each producer port needs one unique producing leaf')
        producer_leaves.append(matches[0])
        consumer_leaves.append(consumed.get(input_, []))
    input_indices, boundary_indices, output_indices = (
        tuple(maps[0][i] for i in inputs), tuple(maps[0][i] for i in producer_ports),
        tuple(maps[1][i] for i in outputs))
    source_maps = dict(children=children, input_indices=list(input_indices),
        boundary_indices=list(boundary_indices), output_indices=list(output_indices),
        inputs=[words[i][0] for i in input_indices], middle=[words[i][0] for i in boundary_indices],
        outputs=[words[i][0] for i in output_indices], producer_leaves=producer_leaves,
        consumer_leaves=consumer_leaves)
    manifest = dict(schema=MANIFEST_SCHEMA,
        program_identity_kind='domain-separated manifest hash; not Program.digest',
        first_round=first_round, rounds=[first_round, first_round+1],
        context=context.hex(), field_role=role, operation_id=operation_id,
        boundary_count=port_count, boundary_order='lane-major-least-significant-bit-first',
        source_maps=source_maps)
    program_digest = sha256(PROGRAM_DOMAIN+_canonical(manifest)).hexdigest()
    if {word for leaf in leaves for word in leaf.wires} != set(range(len(words))):
        raise ValueError('composite catalogue has uncovered declared words')
    composite = GraphSpec(program_digest, context.hex(), role, operation_id, words,
        tuple(leaves), tuple(sorted((digest, body.hex()) for digest, body in bodies.items())),
        sum(spec.original_constraints for spec in specs), ())
    return composite, manifest, source_maps


@dataclass(frozen=True, init=False)
class KeccakPair:
    spec: GraphSpec
    first_round: int
    context: bytes
    role: str
    operation_id: str
    _manifest: bytes

    def __init__(self, *args, **kwargs):
        raise TypeError('use hosted build_keccak_pair; child/map/receipt admission is unsupported')

    @property
    def manifest(self):
        return json.loads(self._manifest)

    @property
    def source_maps(self):
        return self.manifest['source_maps']

    @property
    def input_words(self):
        return tuple(self.source_maps['inputs'])

    @property
    def boundary_words(self):
        return tuple(self.source_maps['middle'])

    @property
    def output_words(self):
        return tuple(self.source_maps['outputs'])

    inputs = property(lambda self: self.input_words)
    middle = property(lambda self: self.boundary_words)
    outputs = property(lambda self: self.output_words)
    producer_leaves = property(lambda self: tuple(self.source_maps['producer_leaves']))
    consumer_leaves = property(lambda self: tuple(tuple(x) for x in self.source_maps['consumer_leaves']))

    def summary(self):
        result = dict(first_round=self.first_round, rounds=[self.first_round, self.first_round+1],
            words=len(self.spec.words), leaves=len(self.spec.leaves), boundary_bits=PORT_COUNT,
            program_sha256=self.spec.program_sha256, spec_sha256=self.spec.digest().hex(),
            program_identity_kind='manifest hash; not Program.digest', context=self.context.hex(),
            role=self.role, operation_id=self.operation_id, canonical_field_leaves=0,
            scope='two adjacent Boolean rounds with exactly shared middle words')
        result.update({flag: False for flag in FALSE_FLAGS})
        return result

    def bind(self, initial_state, claimed_middle=None, claimed_output=None):
        _hosted_guard()  # Before either full child assignment is allocated.
        initial = _state(initial_state)
        correct_middle = keccak_f1600_round(initial, self.first_round)
        middle = correct_middle if claimed_middle is None else _state(claimed_middle)
        correct_output = keccak_f1600_round(middle, self.first_round+1)
        output = correct_output if claimed_output is None else _state(claimed_output)
        children = self.source_maps['children']
        values = {}
        for child, lanes, claimed in ((0, initial, middle), (1, middle, output)):
            program, assignment = keccak_round_trace(lanes, self.first_round+child,
                context=self.context, role=self.role, operation_id=f'{self.operation_id}/child/{child}',
                claimed_output=claimed)
            child_spec = GraphSpec.from_program(program)
            if (program.digest().hex() != children[child]['program_sha256']
                    or child_spec.digest().hex() != children[child]['spec_sha256']):
                raise ValueError('fresh assignment changed sealed child topology')
            mapping = children[child]['word_map']
            for (name, bound), global_index in zip(program.words, mapping, strict=True):
                value, global_name = assignment[name], self.spec.words[global_index][0]
                if type(value) is not int or not 0 <= value < bound:
                    raise ValueError('non-Boolean child assignment')
                if global_name in values and values[global_name] != value:
                    raise ValueError('shared boundary has contradictory child assignments')
                values[global_name] = value
        if len(values) != len(self.spec.words):
            raise ValueError('bound pair does not cover the entire sealed catalogue')
        binding = object.__new__(KeccakPairBinding)
        for name, value in dict(pair=self, _assignment=tuple(values.items()), initial_state=initial,
                middle_state=middle, output_state=output,
                middle_matches_reference=middle == correct_middle,
                output_matches_reference=output == correct_output).items():
            object.__setattr__(binding, name, value)
        return binding


@dataclass(frozen=True, init=False)
class KeccakPairBinding:
    pair: KeccakPair
    _assignment: tuple[tuple[str, int], ...]
    initial_state: tuple[int, ...]
    middle_state: tuple[int, ...]
    output_state: tuple[int, ...]
    middle_matches_reference: bool
    output_matches_reference: bool

    def __init__(self, *args, **kwargs):
        raise TypeError('bind a hosted sealed KeccakPair; no receipt constructor exists')

    @property
    def spec(self):
        return self.pair.spec

    @property
    def assignment(self):
        return dict(self._assignment)

    def summary(self):
        return dict(self.pair.summary(), middle_matches_reference=self.middle_matches_reference,
                    output_matches_reference=self.output_matches_reference)


def build_keccak_pair(first_round=0, *, context, role='pallas_scalar', operation_id='keccak/pair'):
    """Build sealed real child topology internally; no external graph authority."""
    _hosted_guard()  # Before the first real round graph allocation.
    _parameters(first_round, context, role, operation_id)
    specs, ports = [], []
    for child in range(2):
        program, _ = keccak_round_trace((0,)*25, first_round+child, context=context,
            role=role, operation_id=f'{operation_id}/child/{child}')
        spec = GraphSpec.from_program(program)
        indices = {name: i for i, (name, _) in enumerate(spec.words)}
        input_ports = tuple(indices[name] for name in state_wire_names('keccak/in'))
        output_ports = tuple(indices[name] for name in state_wire_names('keccak/out'))
        if (spec.field_leaves or any(bound != 2 for _, bound in spec.words)
                or program.digest().hex() != spec.program_sha256):
            raise ValueError('actual child topology is not the expected Boolean round')
        specs.append(spec)
        ports.append((input_ports, output_ports))
    spec, manifest, source_maps = _merge_specs(tuple(specs), ports[0][1], ports[1][0],
        first_round=first_round, context=context, role=role, operation_id=operation_id,
        input_ports=ports[0][0], output_ports=ports[1][1])
    if any(spec.leaves[i].kind != 'bool_xor' for i in source_maps['producer_leaves']):
        raise ValueError('actual producer boundary is not explicit XOR output copies')
    if first_round == 0 and (len(spec.words), len(spec.leaves)) != (20806, 19206):
        raise ValueError('default pair count changed from unchanged child construction')
    pair = object.__new__(KeccakPair)
    for name, value in dict(spec=spec, first_round=first_round, context=context, role=role,
            operation_id=operation_id, _manifest=_canonical(manifest)).items():
        object.__setattr__(pair, name, value)
    return pair
