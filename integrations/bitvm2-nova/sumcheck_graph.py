"""Two adjacent proof-derived outer sumcheck rounds as a port arithmetic graph.

Only the protocol's initial zero claim is a field constant. Compressed cubic
coefficients and replayed challenges are canonical field ports; the first next
claim is the exact nine-wire tuple consumed by round1. Convolution's internal
integer carry anchors are preserved. No proof-byte parser or Keccak computation
is made disputable by provenance metadata: those Script bindings remain open.

The public factory reconstructs strict production replay from admitted inputs.
It accepts neither replay receipts nor coefficient/challenge/claim overrides.
Source: nova-snark0.76.0 spartan/{snark,sumcheck}.rs and polys/univariate.rs.
"""
from dataclasses import dataclass
from hashlib import sha256
import json
from types import MappingProxyType

from convolution import ConvolutionTraceBuilder
from nht4 import ExpectedBundle, HEADER_BYTES
from poseidon_reference import PoseidonParameters
from production_replay import ReplayKeyBindings, replay_production
from proof_codec import NOVA_CRATE_SHA256, SCALAR_MODULI, DecodedProof

SOURCE_SCHEMA = 'bitvm2-nova-two-outer-sumcheck-sources/v1'
SOURCE_DOMAIN = b'BITVM2-NOVA/TWO-OUTER-SUMCHECK/v1\x00'
ROLES = (('primary', 'pallas'), ('secondary', 'vesta'))
ROUND_COUNT = 2
DEGREE = 3


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def _scalar(value, modulus):
    if type(value) is not int or not 0 <= value < modulus:
        raise ValueError('canonical sumcheck scalar integer required')
    return value


@dataclass(frozen=True)
class RoundPorts:
    index: int
    prior: tuple[str, ...]
    c0: tuple[str, ...]
    c2: tuple[str, ...]
    c3: tuple[str, ...]
    challenge: tuple[str, ...]
    c1: tuple[str, ...]
    next_claim: tuple[str, ...]
    evaluated: tuple[str, ...]
    output_constraint: int


def _build_arithmetic(role, engine, rows, challenges, context, *, claimed_next=None):
    """Private raw arithmetic/test seam, never a proof-derived graph factory.

    Overrides can deliberately produce coherent false assignments. Reusing a
    source context with changed ports can also satisfy this arithmetic fragment:
    metadata is not a Script constraint on proof bytes or challenge derivation.
    Only build_outer_sumcheck_graphs seals provenance-bound honest graph objects.
    """
    if type(role) is not str or type(engine) is not str or (role, engine) not in ROLES:
        raise ValueError('sumcheck role/engine mismatch')
    p = SCALAR_MODULI[engine]
    if type(rows) not in (tuple, list) or len(rows) != ROUND_COUNT:
        raise ValueError('exactly two compressed cubic rows required')
    if type(challenges) not in (tuple, list) or len(challenges) != ROUND_COUNT:
        raise ValueError('exactly two ordered outer challenges required')
    for row in rows:
        if type(row) not in (tuple, list) or len(row) != DEGREE:
            raise ValueError('compressed cubic requires c0,c2,c3 without trimming')
        for value in row:
            _scalar(value, p)
    for value in challenges:
        _scalar(value, p)
    if claimed_next is not None:
        if type(claimed_next) not in (tuple, list) or len(claimed_next) != ROUND_COUNT:
            raise ValueError('two diagnostic claim overrides required')
        for value in claimed_next:
            if value is not None:
                _scalar(value, p)
    g = ConvolutionTraceBuilder(engine+'_scalar', 'spartan/outer/two-rounds/0-1', context)
    prior = g.constant('initial/claim', 0)
    ports, rounds = {'initial/claim': prior}, []
    for index in range(ROUND_COUNT):
        prefix = f'round/{index}'
        c0, c2, c3 = (g.field(prefix+f'/c{power}', value)
                      for power, value in zip((0, 2, 3), rows[index], strict=True))
        challenge = g.field(prefix+'/challenge', challenges[index])
        twice_c0 = g.add(prefix+'/linear/twice-c0', c0, c0)
        partial = g.add(prefix+'/linear/plus-c2', twice_c0, c2)
        remainder = g.add(prefix+'/linear/plus-c3', partial, c3)
        c1 = g.sub(prefix+'/c1', prior, remainder)
        # Cubic Horner evaluation has exactly three variable field products.
        evaluated = c3
        for step, coefficient in enumerate((c2, c1, c0)):
            product = g.mul(prefix+f'/horner/product/{step}', evaluated, challenge)
            evaluated = g.add(prefix+f'/horner/partial/{step}', product, coefficient)
        actual = g.value(evaluated)
        claimed = actual if claimed_next is None or claimed_next[index] is None else claimed_next[index]
        next_claim = g.field(prefix+'/next', claimed)
        output_constraint = len(g.constraints)
        g.check('equal', evaluated+next_claim)
        rounds.append(RoundPorts(index, prior, c0, c2, c3, challenge, c1,
                                 next_claim, evaluated, output_constraint))
        for name, wires in (('prior', prior), ('c0', c0), ('c2', c2), ('c3', c3),
            ('challenge', challenge), ('c1', c1), ('next', next_claim), ('evaluated', evaluated)):
            ports[prefix+'/'+name] = wires
        prior = next_claim  # Exact object reuse: no detached round1 prior copy.
    program, assignment = g.finish()
    return program, assignment, tuple(rounds), MappingProxyType(ports)


@dataclass(frozen=True, init=False)
class OuterSumcheckGraph:
    role: str
    engine: str
    program: object
    rounds: tuple[RoundPorts, ...]
    ports: object
    source_sha256: bytes
    _assignment: tuple[tuple[str, int], ...]
    _sources: bytes

    def __init__(self, *args, **kwargs):
        raise TypeError('use build_outer_sumcheck_graphs with admitted proof and pinned inputs')

    @property
    def assignment(self):
        """Fresh mutable copy for bounded adversarial witness studies."""
        return dict(self._assignment)

    @property
    def sources(self):
        return json.loads(self._sources)

    def summary(self):
        return dict(role=self.role, engine=self.engine, field_role=self.program.field_role,
            phase='outer', round_start=0, round_count=ROUND_COUNT, degree=DEGREE,
            source_sha256=self.source_sha256.hex(), program_sha256=self.program.digest().hex(),
            words=len(self.program.words), constraints=len(self.program.constraints),
            canonical_fields=len(self.program.fields), field_products=6,
            convolution_columns=sum(c.kind == 'conv_column' for c in self.program.constraints),
            shared_claim_words=len(self.rounds[0].next_claim),
            protocol_zero_anchors=sum(c.kind == 'const' and c.argument == (0,)
                for c in self.program.constraints),
            arithmetic_graph_constructed=True, source_ports_script_bound=False,
            challenge_script_binding=False, proof_parser_script_binding=False,
            proof_verified=False, complete_verifier=False, bitvm2_script_verified=False,
            scope='two linked cubic outer-round arithmetic graphs with factory source provenance')


def _source_ports(decoded, native_trace, role, engine, outer_rounds, challenges):
    spans = {span.path: span for span in decoded.spans}
    candidates = [(i, stream) for i, stream in enumerate(native_trace['streams'])
                  if (stream['kind'], stream['engine'], stream['session']) == ('keccak', engine, 0)]
    if len(candidates) != 1:
        raise ValueError('unique replayed outer transcript stream required')
    stream_index, stream = candidates[0]
    ports = []
    for index in range(ROUND_COUNT):
        for position, power in enumerate((0, 2, 3)):
            path = (f'snark_{role}.sc_proof_outer.compressed_polys[{index}]'
                    f'.coeffs_except_linear_term[{position}]')
            span = spans.get(path)
            if span is None or span.kind != 'scalar' or span.engine != engine or span.size != 32:
                raise ValueError('exact admitted compressed-coefficient source span required')
            ports.append(dict(field=f'round/{index}/c{power}', kind='proof_scalar', path=path,
                round_index=index, coefficient_power=power, compressed_index=position,
                inner_proof_offset=span.start, bundle_offset=HEADER_BYTES+span.start, bytes=32))
        # new/vk/U, then ALL tau squeezes, then the ordered p/c round pairs.
        absorb_event = 3+outer_rounds+2*index
        event_index = absorb_event+1
        events = stream['events']
        if (len(events) <= event_index or events[absorb_event]['op'] != 'absorb'
                or events[absorb_event]['label_hex'] != b'p'.hex()
                or events[event_index]['op'] != 'squeeze'
                or events[event_index]['label_hex'] != b'c'.hex()
                or events[event_index]['challenge_le'] != challenges[index]):
            raise ValueError('ordered outer challenge source differs from fresh replay')
        ports.append(dict(field=f'round/{index}/challenge', kind='transcript_challenge',
            path=f'streams[{stream_index}].events[{event_index}].challenge_le',
            round_index=index, outer_challenge_index=index, stream_kind='keccak',
            stream_engine=engine, session=0, absorb_event_index=absorb_event,
            event_index=event_index, label_hex=b'c'.hex()))
    return ports


def build_outer_sumcheck_graphs(decoded, expected, bindings, native_trace, *,
                                expected_trace_sha256, poseidon_parameters):
    """Seal the first two actual outer rounds for both exact Pasta scalar roles.

    The caller owns the expected policy and independent metadata pins. No phase,
    round-count, arithmetic-source, context or claimed-output override is public.
    Provenance commits exact proof paths and ordered transcript events, but does
    not enforce proof/challenge-to-port equality in Bitcoin Script.
    """
    if (type(decoded) is not DecodedProof or type(expected) is not ExpectedBundle
            or type(bindings) is not ReplayKeyBindings
            or type(poseidon_parameters) is not PoseidonParameters):
        raise ValueError('admitted proof and typed independently pinned replay inputs required')
    if (decoded.dimensions != bindings.dimensions
            or decoded.dimensions != poseidon_parameters.dimensions):
        raise ValueError('sumcheck graph input dimension identities differ')
    replay = replay_production(decoded, expected, bindings, native_trace,
        expected_trace_sha256=expected_trace_sha256, poseidon_parameters=poseidon_parameters)
    proof, graphs = decoded.value, []
    for index, (role, engine) in enumerate(ROLES):
        shape, details = getattr(decoded.dimensions, role), replay['engines'][index]
        rows = proof[f'snark_{role}']['sc_proof_outer']['compressed_polys'][:ROUND_COUNT]
        if shape.outer_rounds < ROUND_COUNT or len(rows) != ROUND_COUNT or details['engine'] != engine:
            raise ValueError('two actual ordered outer rounds required')
        compressed = [row['coeffs_except_linear_term'] for row in rows]
        if any(len(row) != DEGREE for row in compressed):
            raise ValueError('bounded outer graph requires encoded compressed cubics of length3')
        encoded_challenges = details['r_x_le'][:ROUND_COUNT]
        sources = expected.json()
        sources['policy_schema'] = sources.pop('schema')
        sources.update(schema=SOURCE_SCHEMA, nova_crate_sha256=NOVA_CRATE_SHA256,
            verifier_dimensions_sha256=decoded.dimensions.descriptor_sha256.hex(),
            key_bindings_sha256=bindings.metadata_sha256.hex(),
            native_trace_sha256=replay['native_trace_sha256'],
            poseidon_parameters_sha256=poseidon_parameters.parameters_sha256.hex(),
            role=role, engine=engine, field_role=engine+'_scalar',
            phase='outer', round_start=0, round_count=ROUND_COUNT, degree=DEGREE,
            initial_claim_le='00'*32,
            ports=_source_ports(decoded, native_trace, role, engine, shape.outer_rounds,
                                encoded_challenges))
        source_json = _canonical(sources)
        context = sha256(SOURCE_DOMAIN+source_json).digest()
        rows = [tuple(int.from_bytes(bytes.fromhex(value), 'little') for value in row)
                for row in compressed]
        challenges = tuple(int.from_bytes(bytes.fromhex(value), 'little')
                           for value in encoded_challenges)
        program, assignment, rounds, ports = _build_arithmetic(role, engine, rows, challenges, context)
        if program.bind(assignment).failures():
            raise ValueError('honest proof-derived outer arithmetic construction failed')
        graph = object.__new__(OuterSumcheckGraph)
        for name, value in dict(role=role, engine=engine, program=program, rounds=rounds,
                ports=ports, source_sha256=context, _assignment=tuple(assignment.items()),
                _sources=source_json).items():
            object.__setattr__(graph, name, value)
        graphs.append(graph)
    return tuple(graphs)
