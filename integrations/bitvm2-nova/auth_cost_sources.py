"""Closed synthetic sources for authenticated-adapter cost conformance.

The same immutable Program, GraphSpec, predicate bodies and raw u32 assignment
are consumed by both authentication adapters. No compiler, arithmetic default,
BYTE round, header prover or proof fixture is changed. The round input is a
synthetic cost fixture, not a Nova transcript or proof. Source identities bind
public topology and the closed recipe, not an authenticated proof-byte origin.

Construction and binding are hosted GitHub Linux only. Pure parameter, recipe
and census helpers do not build a graph, execute Script or generate keys.
"""
from dataclasses import dataclass
from hashlib import sha256
import json
import os
import sys
from types import MappingProxyType

from byte_keccak_round import build_byte_keccak_round
from byte_kernels import _expected as _byte_expected
from convolution import AB_BOUND, ConvolutionTraceBuilder
from keccak_trace import keccak_f1600_round, state_from_bytes, state_to_bytes
from script import BASE
from wots_graph import GraphSpec

CONTEXT = sha256(b'BITVM2-NOVA/AUTH-COST-CONFORMANCE/v1').digest()
OPERATION_ID = 'benchmark/auth-cost/v1'
SCHEMA = 'bitvm2-nova-auth-cost-source/v1'
MAP_SCHEMA = 'bitvm2-nova-auth-cost-source-maps/v1'
SOURCE_DOMAIN = b'BITVM2-NOVA/AUTH-COST-SOURCE/v1\x00'
MAX_SOURCE_BYTES = 1 << 20
ROLES = ('pallas_scalar', 'vesta_scalar')
FIXTURES = ('mixed', 'round')
MIXED_PROFILES = ('a0', 'a1', 'a9', 'a255', 'bad-aux', 'bad-square',
                  'a256', 'a-max', 'auth-order')
ROUND_PROFILES = ('honest', 'producer-fault')
FALSE_FLAGS = ('nova_transcript_verified', 'proof_verified',
    'full_permutation_verified', 'hash_verified', 'bitvm2_script_verified',
    'production_assertion_binding', 'bitcoin_transaction_graph',
    'independent_compiler_semantics_verified')


def _hosted_guard():
    if (os.environ.get('GITHUB_ACTIONS') != 'true'
            or os.environ.get('RUNNER_OS') != 'Linux' or sys.platform != 'linux'):
        raise ValueError('authentication cost source construction/binding is hosted GitHub Linux only')


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def _parameters(fixture, role):
    if (type(fixture) is not str or fixture not in FIXTURES
            or type(role) is not str or role not in ROLES):
        raise ValueError('closed mixed/round fixture and scalar ROLE NAME required')


def fixture_counts(fixture):
    """Source-derived census only; this helper cannot admit a graph."""
    _parameters(fixture, ROLES[0])
    if fixture == 'mixed':
        return MappingProxyType(dict(words=3, leaves=2, fields=0,
            authenticated_shapes=2, profiles=9, unique_openings=4,
            formal_occurrences=5))
    # Round0 has RC=1: 1216 base gates plus one nonzero-byte Iota gate.
    return MappingProxyType(dict(words=1417, leaves=1217, fields=0,
        authenticated_shapes=11, profiles=2, unique_openings=3450,
        formal_occurrences=3450))


def mixed_values(profile):
    """Exact (a, aux, sq), preserving every asserted u32 without reduction."""
    if type(profile) is not str or profile not in MIXED_PROFILES:
        raise ValueError('closed mixed authentication-cost profile required')
    maximum = (1 << 32)-1
    values = ((0, 0, 0), (1, 1, 1), (9, 9, 81), (255, 255, 65025),
              (9, 8, 81), (9, 9, 80), (256, 256, 65536),
              (maximum, 0, 0), (9, maximum, maximum))
    return values[MIXED_PROFILES.index(profile)]


def synthetic_input(role):
    _parameters('round', role)
    counter = 59 if role == 'pallas_scalar' else 44
    return bytes((17*i+counter) & 255 for i in range(200))


def _make(cls, **fields):
    result = object.__new__(cls)
    for name, value in fields.items():
        object.__setattr__(result, name, value)
    return result


def _mixed(role):
    _hosted_guard()
    builder = ConvolutionTraceBuilder(role, OPERATION_ID+'/mixed', CONTEXT)
    a = builder.small('a', 0, 256)
    aux = builder.small('aux', 0, BASE)
    sq = builder.small('sq', 0, AB_BOUND)
    builder.check('conv_reconstruct', (aux, a), (8,))
    builder.check('conv_ab', (a, a, sq), (1,))
    program, _ = builder.finish()
    return program, GraphSpec.from_program(program)


def _maps(fixture, program, spec):
    occurrences = [[] for _ in spec.words]
    for ordinal, leaf in enumerate(spec.leaves):
        for formal, wire in enumerate(leaf.wires):
            occurrences[wire].append((ordinal, formal))
    rows = []
    for index, (name, bound) in enumerate(spec.words):
        actual = tuple(occurrences[index])
        if not actual:
            raise ValueError('every cost-source word needs an actual opening occurrence')
        rows.append(dict(word_index=index, local_name=name,
            global_id=f'auth-cost/{fixture}/{name}', bound=bound,
            occurrences=actual))
    if len({row['global_id'] for row in rows}) != len(rows):
        raise ValueError('injective cost-source global identities required')
    if fixture == 'mixed':
        ports = dict(a='a', aux='aux', sq='sq')
        first_producer = None
        if (spec.words != (('a', 256), ('aux', BASE), ('sq', AB_BOUND))
                or program.fields or len(spec.leaves) != 2
                or (spec.leaves[0].kind, spec.leaves[0].argument, spec.leaves[0].wires)
                    != ('conv_reconstruct', (8,), (1, 0))
                or (spec.leaves[1].kind, spec.leaves[1].argument, spec.leaves[1].wires)
                    != ('conv_ab', (1,), (0, 0, 2))):
            raise ValueError('closed mixed kernel/alias topology differs')
    else:
        inputs = tuple(name for name, _ in spec.words[:200])
        outputs = tuple(program.constraints[ordinal].wires[-1]
                        for ordinal in _terminal_producers(program))
        # The source derives the fault location from the actual sealed graph;
        # no caller-supplied word or producer index is accepted.
        first = spec.leaves[0]
        word = first.wires[-1]
        if (word != 200 or spec.words[word][0] != program.constraints[0].wires[-1]
                or first.kind != 'byte_xor' or first.argument
                or first.wires != (0, 40, 200)):
            raise ValueError('round first actual SSA producer differs')
        first_producer = dict(word_index=word, local_name=spec.words[word][0],
            ordinal=0, occurrence=len(first.wires)-1)
        ports = dict(inputs=inputs, outputs=outputs)
    return dict(schema=MAP_SCHEMA, fixture=fixture, words=rows, ports=ports,
                first_producer=first_producer)


def _terminal_producers(program):
    produced = {c.wires[-1]: i for i, c in enumerate(program.constraints)}
    consumed = {word for c in program.constraints for word in c.wires[:-1]}
    terminal = set(produced)-consumed
    # Ordered source output bytes, not a suffix of the SSA word list.
    from byte_keccak_round import output_wire_names
    outputs = output_wire_names(0)
    if set(outputs) != terminal:
        raise ValueError('round terminal output set differs')
    return tuple(produced[name] for name in outputs)


def _round_values(program, role):
    """Fresh closed SSA assignment, with no second graph or claimed inputs.

    This uses the existing BYTE integer relation and separately compares the
    terminal bytes with the unchanged word-level Keccak round reference. The
    native worker independently replays the closed schedule and arithmetic.
    """
    initial = synthetic_input(role)
    values = {name: value for (name, _), value in zip(program.words[:200], initial, strict=True)}
    for constraint in program.constraints:
        if constraint.wires[-1] in values:
            raise ValueError('fresh BYTE cost assignment requires actual SSA producers')
        operands = tuple(values[name] for name in constraint.wires[:-1])
        values[constraint.wires[-1]] = _byte_expected(constraint.kind, constraint.argument, operands)
    producers = _terminal_producers(program)
    output = bytes(values[program.constraints[i].wires[-1]] for i in producers)
    reference = state_to_bytes(keccak_f1600_round(state_from_bytes(initial), 0))
    if output != reference or set(values) != {name for name, _ in program.words}:
        raise ValueError('synthetic BYTE SSA differs from independent word-level round reference')
    return tuple(values[name] for name, _ in program.words)


def _source(fixture, role, child=None):
    _hosted_guard()
    if fixture == 'mixed':
        program, spec = _mixed(role)
        child_source = child_maps = None
    else:
        if child is None:
            child = build_byte_keccak_round(0, context=CONTEXT, role=role,
                                           operation_id=OPERATION_ID+'/round')
        program, spec = child.program, child.spec
        child_source = child.source_sha256.hex()
        child_maps = sha256(child._maps).hexdigest()
    expected = fixture_counts(fixture)
    if ((len(spec.words), len(spec.leaves), len(program.fields))
            != (expected['words'], expected['leaves'], 0)):
        raise ValueError('closed cost-source census differs')
    maps = _maps(fixture, program, spec)
    raw_maps = _canonical(maps)
    maps_sha = sha256(raw_maps).digest()
    manifest = dict(schema=SCHEMA, fixture=fixture, context=CONTEXT.hex(),
        field_role=role, operation_id=program.operation_id,
        program_identity_kind=('ConvolutionProgram.digest (fixed-trace/v2)'
            if fixture == 'mixed' else 'ByteProgram.digest (byte-v1)'),
        program_sha256=program.digest().hex(), catalogue_id=spec.digest().hex(),
        source_maps_sha256=maps_sha.hex(), child_source_sha256=child_source,
        child_source_maps_sha256=child_maps, words=expected['words'],
        leaves=expected['leaves'], fields=0,
        profiles=MIXED_PROFILES if fixture == 'mixed' else ROUND_PROFILES,
        input_recipe=('closed raw-u32 triples in word order a,aux,sq' if fixture == 'mixed'
            else 'synthetic cost fixture: byte((17*i+roleCounter)&255), i=0..199; roleCounter=59/44'),
        fault_recipe=('closed raw-u32 triples without modular reduction or truncation'
            if fixture == 'mixed' else 'flip bit0 of first actual SSA gate output; keep all other words'),
        scope='adapter cost/conformance on synthetic statements; no Nova transcript or proof verification')
    raw_manifest = _canonical(manifest)
    if max(len(raw_maps), len(raw_manifest)) > MAX_SOURCE_BYTES:
        raise ValueError('cost-source sidecar exceeds existing bounded source policy')
    return program, spec, child, raw_maps, raw_manifest


def _validate_identity(source):
    """Recheck the sealed snapshot before its SSA or cached sidecars are used."""
    _parameters(source.fixture, source.role)
    expected_op = OPERATION_ID+('/mixed' if source.fixture == 'mixed' else '/round/round/0')
    if (type(source.context) is not bytes or source.context != CONTEXT
            or type(source.operation_id) is not str or source.operation_id != expected_op
            or source.program.context != CONTEXT or source.program.field_role != source.role
            or source.program.operation_id != expected_op
            or source.spec.context != CONTEXT.hex() or source.spec.field_role != source.role
            or source.spec.operation_id != expected_op
            or source.spec.words != source.program.words
            or type(source._maps) is not bytes or type(source._manifest) is not bytes
            or type(source.source_sha256) is not bytes or type(source.source_maps_sha256) is not bytes):
        raise ValueError('typed fixed cost-source context/role/operation snapshot differs')
    maps = json.loads(source._maps)
    manifest = json.loads(source._manifest)
    if source.fixture == 'round':
        child = source._child
        if (child.context != CONTEXT or child.role != source.role
                or child.operation_id != OPERATION_ID+'/round' or child.round_index != 0
                or child.program.digest() != source.program.digest()
                or child.spec.digest() != source.spec.digest()
                or manifest['child_source_sha256'] != child.source_sha256.hex()
                or manifest['child_source_maps_sha256'] != sha256(child._maps).hexdigest()):
            raise ValueError('unchanged sealed child round snapshot differs')
    elif source._child is not None:
        raise ValueError('mixed source has no imported child authority')
    if (source.spec.program_sha256 != source.program.digest().hex()
            or manifest['program_sha256'] != source.program.digest().hex()
            or manifest['catalogue_id'] != source.spec.digest().hex()
            or manifest['context'] != CONTEXT.hex() or manifest['field_role'] != source.role
            or manifest['operation_id'] != expected_op or manifest['fixture'] != source.fixture
            or _canonical(maps) != source._maps or _canonical(manifest) != source._manifest
            or _canonical(_maps(source.fixture, source.program, source.spec)) != source._maps
            or sha256(source._maps).digest() != source.source_maps_sha256
            or manifest['source_maps_sha256'] != source.source_maps_sha256.hex()
            or sha256(SOURCE_DOMAIN+source._manifest).digest() != source.source_sha256
            or source.global_ids != tuple(row['global_id'] for row in maps['words'])):
        raise ValueError('actual cost Program/catalogue/maps/manifest digest snapshot differs')


@dataclass(frozen=True, init=False)
class AuthCostBinding:
    source: object
    profile: str
    program: object
    spec: object
    values: tuple[int, ...]
    reference_values: tuple[int, ...]

    def __init__(self, *args, **kwargs):
        raise TypeError('bind a closed profile through the sealed cost-source factory')

    assignment = property(lambda self: dict(zip((w for w, _ in self.spec.words), self.values, strict=True)))

    def summary(self):
        result = self.source.summary()
        result.update(profile=self.profile, asserted_u32_values_preserved=True)
        return result


@dataclass(frozen=True, init=False)
class AuthCostSource:
    fixture: str
    role: str
    context: bytes
    operation_id: str
    program: object
    spec: object
    global_ids: tuple[str, ...]
    source_sha256: bytes
    source_maps_sha256: bytes
    _child: object
    _manifest: bytes
    _maps: bytes

    def __init__(self, *args, **kwargs):
        raise TypeError('use build_auth_cost_source; no external graph/map/receipt admission')

    manifest = property(lambda self: json.loads(self._manifest))
    source_maps = property(lambda self: json.loads(self._maps))
    ports = property(lambda self: MappingProxyType(json.loads(self._maps)['ports']))
    profiles = property(lambda self: MIXED_PROFILES if self.fixture == 'mixed' else ROUND_PROFILES)

    def bind(self, profile):
        _hosted_guard()
        _validate_identity(self)  # Before any sealed Program/SSA/cache consumption.
        if type(profile) is not str or profile not in self.profiles:
            raise ValueError('closed authentication-cost profile required')
        if self.fixture == 'mixed':
            program, spec, _, maps, manifest = _source(self.fixture, self.role)
            values = mixed_values(profile)
            reference = values
        else:
            program, spec = self.program, self.spec
            reference = _round_values(program, self.role)
            values = list(reference)
            if profile == 'producer-fault':
                values[spec.leaves[0].wires[-1]] ^= 1
            values = tuple(values)
            _, _, _, maps, manifest = _source(self.fixture, self.role, self._child)
        if (program.digest() != self.program.digest() or spec.digest() != self.spec.digest()
                or maps != self._maps or manifest != self._manifest
                or len(values) != len(spec.words)
                or any(type(value) is not int or not 0 <= value <= (1 << 32)-1 for value in values)):
            raise ValueError('fresh closed cost-source identity/raw-u32 assignment differs')
        # Deliberately no Program.bind/_admit: signed oversized assertions are
        # inputs to adapter conformance, not automatically rejected host values.
        return _make(AuthCostBinding, source=self, profile=profile, program=program,
                     spec=spec, values=values, reference_values=reference)

    def summary(self):
        result = dict(schema=SCHEMA, fixture=self.fixture, role=self.role,
            context=self.context.hex(), operation_id=self.operation_id,
            program_sha256=self.program.digest().hex(), catalogue_id=self.spec.digest().hex(),
            source_sha256=self.source_sha256.hex(), source_maps_sha256=self.source_maps_sha256.hex(),
            **dict(fixture_counts(self.fixture)),
            scope='synthetic adapter cost/conformance fixture only')
        result.update({flag: False for flag in FALSE_FLAGS})
        return result


def build_auth_cost_source(fixture, *, role):
    _hosted_guard()
    _parameters(fixture, role)
    program, spec, child, maps, manifest = _source(fixture, role)
    ids = tuple(f'auth-cost/{fixture}/{name}' for name, _ in spec.words)
    return _make(AuthCostSource, fixture=fixture, role=role, context=CONTEXT,
        operation_id=program.operation_id, program=program, spec=spec, global_ids=ids,
        source_sha256=sha256(SOURCE_DOMAIN+manifest).digest(),
        source_maps_sha256=sha256(maps).digest(), _child=child,
        _manifest=manifest, _maps=maps)
