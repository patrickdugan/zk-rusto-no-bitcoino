"""Proof-bound Nova 0.76.0 transcript replay with explicit native-only stages.

This reconstructs production absorption objects/order from an admitted proof,
independently pinned key metadata, and caller-owned NHT4 expectations. Keccak
states/challenges, tiny NIFS folds, batching and IPA scalar factors are computed
here. Poseidon sponge hashes, matrix evaluations and the large generator MSM
are NOT independently evaluated. Captured Poseidon results are accepted only
inside a separately pinned native capture and their exact inputs/truncations
are checked. This is conformance evidence, not standalone proof verification.
"""
from dataclasses import dataclass
from hashlib import sha256
from hmac import compare_digest
import json

from ipa_algebra import PALLAS, VESTA
from nht4 import ExpectedBundle, HEADER_REVISION
from proof_codec import (BASE_MODULI, SCALAR_MODULI, DecodedProof,
                         VerifierDimensions, decode_point)
from production_transcript import NovaTranscript
from spartan_checks import (batch_initial_claim, batch_terminal, decompress,
                            evaluate, outer_terminal, sparse_evaluation)

KEY_SCHEMA = 'bitvm2-nova-replay-key-bindings/v1'
TRACE_SCHEMA = 'bitvm2-nova-real-verifier-trace/v1'
CURVES = {'pallas': PALLAS, 'vesta': VESTA}
MAX_TRACE_EVENTS = 2048
MAX_TRACE_BUFFER = 1024
MAX_POSEIDON_STATE = 128
MAX_CAPTURE_BYTES = 8 << 20


def _keys(value, keys, name):
    if type(value) is not dict or set(value) != set(keys):
        raise ValueError(f'unexpected {name} fields')


def _integer(value, minimum, maximum, name):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f'invalid {name}')
    return value


def _hex(value, size=None, maximum=None):
    if (type(value) is not str or len(value) % 2 or
            (size is not None and len(value) != 2*size) or
            (maximum is not None and len(value) > 2*maximum) or
            any(c not in '0123456789abcdef' for c in value)):
        raise ValueError('canonical bounded lowercase hex required')
    return bytes.fromhex(value)


def _scalar(value, modulus, bits=None):
    result = int.from_bytes(_hex(value, 32), 'little')
    if result >= modulus or (bits is not None and result >= 1 << bits):
        raise ValueError('noncanonical scalar or bit width')
    return result


def _le(value):
    return value.to_bytes(32, 'little').hex()


def _canonical_bytes(value):
    try:
        encoded = json.dumps(value, sort_keys=True, separators=(',', ':'),
                             ensure_ascii=True, allow_nan=False).encode('ascii')
    except (TypeError, ValueError, RecursionError, UnicodeError) as error:
        raise ValueError('invalid canonical JSON data') from error
    if len(encoded) > MAX_CAPTURE_BYTES:
        raise ValueError('canonical JSON byte budget exceeded')
    return encoded


def canonical_sha256(value):
    """Canonical JSON digest; inputs must first satisfy a bounded typed schema."""
    return sha256(_canonical_bytes(value)).digest()


def _pin(value, expected, name):
    if type(expected) is not bytes or len(expected) != 32:
        raise ValueError(f'independent {name} digest pin required')
    actual = canonical_sha256(value)
    if not compare_digest(actual, expected):
        raise ValueError(f'{name} digest mismatch')
    return actual


def _point(value, engine):
    _keys(value, {'comm'}, 'commitment')
    return decode_point(_hex(value['comm'], 32), engine)


def _point_hex(point):
    if point is None:
        return '00'*32
    return (point[0] | ((point[1] & 1) << 255)).to_bytes(32, 'little').hex()


@dataclass(frozen=True)
class _EngineKey:
    engine: str
    spartan_vk_digest: int
    derand_h: object
    ipa_scalar_generator: object
    ipa_scalar_h: object


@dataclass(frozen=True, init=False)
class ReplayKeyBindings:
    primary: _EngineKey
    secondary: _EngineKey
    pp_digest: int
    dimensions: VerifierDimensions
    metadata_sha256: bytes
    _metadata_json: str

    def __init__(self, *args, **kwargs):
        raise TypeError('use ReplayKeyBindings.from_json with an independent metadata pin')

    @classmethod
    def from_json(cls, data, expected, dimensions, *, expected_key_bindings_sha256):
        if type(expected) is not ExpectedBundle or type(dimensions) is not VerifierDimensions:
            raise ValueError('caller-owned expected policy and dimensions required')
        _keys(data, {'schema', 'header_revision', 'nova_version', 'network', 'k',
            'verifier_key_sha256', 'verifier_dimensions_sha256', 'pp_digest_le',
            'primary', 'secondary'}, 'replay key metadata')
        identities = {'schema': KEY_SCHEMA, 'header_revision': HEADER_REVISION,
            'nova_version': '0.76.0', 'network': expected.network, 'k': expected.k,
            'verifier_key_sha256': expected.verifier_key_sha256.hex(),
            'verifier_dimensions_sha256': dimensions.descriptor_sha256.hex()}
        if any(type(data[k]) is not type(v) or data[k] != v for k, v in identities.items()):
            raise ValueError('key metadata identity mismatch')
        descriptor = dimensions.json()
        if (descriptor['network'] != expected.network or descriptor['k'] != expected.k
                or descriptor['verifier_key_sha256'] != expected.verifier_key_sha256.hex()):
            raise ValueError('dimension policy identity mismatch')
        pp = _scalar(data['pp_digest_le'], SCALAR_MODULI['pallas'], 250)
        engines = []
        for role, engine, shape in (('primary', 'pallas', dimensions.primary),
                                    ('secondary', 'vesta', dimensions.secondary)):
            value = data[role]
            _keys(value, {'engine', 'spartan_vk_digest_le', 'derand_key', 'ipa_scalar_key'}, 'engine key')
            if type(value['engine']) is not str or value['engine'] != engine:
                raise ValueError('key engine role mismatch')
            vk_digest = _scalar(value['spartan_vk_digest_le'], SCALAR_MODULI[engine], 250)
            _keys(value['derand_key'], {'h'}, 'derandomization key')
            _keys(value['ipa_scalar_key'], {'ck', 'h'}, 'IPA scalar key')
            ck = value['ipa_scalar_key']['ck']
            if type(ck) is not list or len(ck) != 1 or shape.ck_s_generators != 1:
                raise ValueError('unsupported scalar commitment key shape')
            points = [decode_point(_hex(x, 32), engine) for x in
                (value['derand_key']['h'], ck[0], value['ipa_scalar_key']['h'])]
            if any(point is None for point in points):
                raise ValueError('key generator must be finite')
            engines.append(_EngineKey(engine, vk_digest, *points))
        # All nested values have a shallow exact typed schema before hashing.
        digest = _pin(data, expected_key_bindings_sha256, 'key metadata')
        result = object.__new__(cls)
        for name, value in (('primary', engines[0]), ('secondary', engines[1]),
            ('pp_digest', pp), ('dimensions', dimensions), ('metadata_sha256', digest),
            ('_metadata_json', json.dumps(data, separators=(',', ':')))):
            object.__setattr__(result, name, value)
        return result


def _keccak_snapshot(transcript):
    snapshot = transcript.snapshot()
    return {'round': snapshot['round'], 'state_hex': bytes(snapshot['state']).hex(),
            'buffer_hex': bytes(snapshot['transcript_buffer']).hex()}


def _validate_trace(trace):
    _keys(trace, {'schema', 'streams', 'events', 'recorded_event_bytes', 'max_streams',
        'max_events', 'max_recorded_event_bytes', 'complete_capture', 'panic_is_rejection'}, 'native trace')
    if (type(trace['schema']) is not str or trace['schema'] != TRACE_SCHEMA
            or type(trace['streams']) is not list or len(trace['streams']) > 7):
        raise ValueError('unsupported native trace schema/count')
    limits = {'max_streams': 16, 'max_events': 4096, 'max_recorded_event_bytes': MAX_CAPTURE_BYTES}
    for name, value in limits.items():
        if type(trace[name]) is not int or trace[name] != value:
            raise ValueError('native capture resource profile mismatch')
    if type(trace['complete_capture']) is not bool or trace['complete_capture'] is not True:
        raise ValueError('incomplete native capture')
    if type(trace['panic_is_rejection']) is not bool or trace['panic_is_rejection'] is not False:
        raise ValueError('panic cannot be native rejection evidence')
    _integer(trace['events'], 1, MAX_TRACE_EVENTS, 'reported trace event count')
    _integer(trace['recorded_event_bytes'], 1, MAX_CAPTURE_BYTES, 'reported trace bytes')
    total, recorded, seen, order = 0, 0, set(), []
    for stream in trace['streams']:
        _keys(stream, {'kind', 'engine', 'field_role', 'session', 'events'}, 'trace stream')
        kind, engine = stream['kind'], stream['engine']
        if type(kind) is not str or type(engine) is not str or engine not in CURVES:
            raise ValueError('unsupported trace engine/kind')
        if kind not in ('keccak', 'poseidon_base'):
            raise ValueError('unexpected RO2 or transcript stream')
        field = engine+('_scalar' if kind == 'keccak' else '_base')
        if type(stream['field_role']) is not str or stream['field_role'] != field:
            raise ValueError('trace field role mismatch')
        session = _integer(stream['session'], 0, 4, 'trace session')
        key = kind, engine, session
        if key in seen:
            raise ValueError('duplicate native trace session')
        seen.add(key)
        order.append(key)
        events = stream['events']
        if type(events) is not list or not 1 <= len(events) <= MAX_TRACE_EVENTS:
            raise ValueError('trace event budget')
        total += len(events)
        if total > MAX_TRACE_EVENTS:
            raise ValueError('total trace event budget')
        for sequence, event in enumerate(events):
            if type(event) is not dict or type(event.get('op')) is not str:
                raise ValueError('malformed trace event')
            op = event['op']
            common = {'sequence', 'op', 'after'}
            if kind == 'keccak':
                fields = {'new': {'label_hex'}, 'absorb': {'label_hex', 'repr_hex'},
                          'dom_sep': {'data_hex'}, 'squeeze': {'label_hex', 'challenge_le'}}
                if op not in fields:
                    raise ValueError('unsupported Keccak event')
                _keys(event, common | fields[op], 'Keccak event')
                after = event['after']
                _keys(after, {'round', 'state_hex', 'buffer_hex'}, 'Keccak snapshot')
                _integer(after['round'], 0, MAX_TRACE_EVENTS, 'Keccak round')
                _hex(after['state_hex'], 64)
                _hex(after['buffer_hex'], maximum=MAX_TRACE_BUFFER)
                for key in ('label_hex', 'data_hex'):
                    if key in event:
                        _hex(event[key], maximum=64)
                if 'repr_hex' in event:
                    _hex(event['repr_hex'], maximum=512)
                if 'challenge_le' in event:
                    _scalar(event['challenge_le'], SCALAR_MODULI[engine])
            else:
                fields = {'new': {'mode'}, 'absorb': {'value_le'},
                          'squeeze': {'num_bits', 'start_with_one', 'challenge_le'}}
                if op not in fields:
                    raise ValueError('unsupported Poseidon event')
                _keys(event, common | fields[op], 'Poseidon event')
                after = event['after']
                _keys(after, {'mode', 'state_le'}, 'Poseidon snapshot')
                if after['mode'] != 'wide' or type(after['mode']) is not str:
                    raise ValueError('unsupported Poseidon mode')
                if type(after['state_le']) is not list or len(after['state_le']) > MAX_POSEIDON_STATE:
                    raise ValueError('Poseidon state budget')
                for value in after['state_le']:
                    _scalar(value, BASE_MODULI[engine])
                if op == 'new' and event['mode'] != 'wide':
                    raise ValueError('unsupported initial Poseidon mode')
                if op == 'absorb':
                    _scalar(event['value_le'], BASE_MODULI[engine])
                if op == 'squeeze':
                    bits = _integer(event['num_bits'], 2, 250, 'Poseidon squeeze bits')
                    if type(event['start_with_one']) is not bool:
                        raise ValueError('invalid Poseidon bit mode')
                    _scalar(event['challenge_le'], BASE_MODULI[engine], bits)
            if type(event['sequence']) is not int or event['sequence'] != sequence:
                raise ValueError('noncanonical event sequence')
            recorded += len(_canonical_bytes(event))
            if recorded > MAX_CAPTURE_BYTES:
                raise ValueError('native capture byte budget')
    if order != sorted(order):
        raise ValueError('native trace stream ordering mismatch')
    if total != trace['events'] or recorded != trace['recorded_event_bytes']:
        raise ValueError('native capture event/byte accounting mismatch')
    return {(s['kind'], s['engine'], s['session']): s['events'] for s in trace['streams']}


class _KeccakReplay:
    def __init__(self, engine, events):
        self.engine, self.events, self.position, self.squeezes = engine, events, 0, 0
        self.transcript = NovaTranscript(engine, b'RelaxedR1CSSNARK')
        self._match('new', label_hex=b'RelaxedR1CSSNARK'.hex())

    def _match(self, op, **fields):
        expected = {'sequence': self.position, 'op': op, **fields,
                    'after': _keccak_snapshot(self.transcript)}
        if self.position >= len(self.events) or self.events[self.position] != expected:
            raise ValueError(f'{self.engine} {op} transcript mismatch at event {self.position}')
        self.position += 1

    def absorb(self, label, representation):
        self.transcript.absorb_bytes(label, representation)
        self._match('absorb', label_hex=label.hex(), repr_hex=representation.hex())

    def scalars(self, label, values):
        self.absorb(label, self.transcript.scalars_repr(values))

    def squeeze(self, label):
        challenge = self.transcript.squeeze(label)
        self._match('squeeze', label_hex=label.hex(), challenge_le=_le(challenge))
        self.squeezes += 1
        return challenge

    def dom_sep(self, data):
        self.transcript.dom_sep(data)
        self._match('dom_sep', data_hex=data.hex())

    def finish(self):
        if self.position != len(self.events):
            raise ValueError('surplus transcript events')


def _native_ro(engine, events, inputs, bits):
    """Check exact inputs, snapshots and truncation; do NOT compute Poseidon."""
    if len(events) != len(inputs)+2:
        raise ValueError('Poseidon native stream length mismatch')
    expected = {'sequence': 0, 'op': 'new', 'mode': 'wide',
                'after': {'mode': 'wide', 'state_le': []}}
    if events[0] != expected:
        raise ValueError('Poseidon initial state mismatch')
    state = []
    for i, value in enumerate(inputs, 1):
        value %= BASE_MODULI[engine]
        state.append(_le(value))
        expected = {'sequence': i, 'op': 'absorb', 'value_le': _le(value),
                    'after': {'mode': 'wide', 'state_le': list(state)}}
        if events[i] != expected:
            raise ValueError(f'Poseidon absorption mismatch at event {i}')
    last = events[-1]
    after = last.get('after', {})
    if type(after.get('state_le')) is not list or len(after['state_le']) != 1:
        raise ValueError('Poseidon post-squeeze hash shape')
    full_native_hash = _scalar(after['state_le'][0], BASE_MODULI[engine])
    output = full_native_hash & ((1 << bits)-1)
    expected = {'sequence': len(inputs)+1, 'op': 'squeeze', 'num_bits': bits,
        'start_with_one': False, 'challenge_le': _le(output),
        'after': {'mode': 'wide', 'state_le': [_le(full_native_hash)]}}
    if last != expected:
        raise ValueError('Poseidon captured output truncation mismatch')
    return output


@dataclass(frozen=True)
class _Instance:
    engine: str
    comm_w: object
    comm_e: object
    u: int
    x: tuple[int, ...]


def _instance(value, engine, ordinary=False):
    q = SCALAR_MODULI[engine]
    return _Instance(engine, _point(value['comm_W'], engine),
        None if ordinary else _point(value['comm_E'], engine),
        1 if ordinary else _scalar(value['u'], q),
        tuple(_scalar(x, q) for x in value['X']))


def _fold(left, right, comm_t, challenge, *, ordinary=False):
    if left.engine != right.engine or len(left.x) != len(right.x):
        raise ValueError('fold instance role/arity mismatch')
    curve, q = CURVES[left.engine], SCALAR_MODULI[left.engine]
    _integer(challenge, 0, (1 << 128)-1, 'NIFS challenge')
    if ordinary and (right.u != 1 or right.comm_e is not None):
        raise ValueError('ordinary fold requires ordinary instance')
    w = curve.add(left.comm_w, curve.mul(right.comm_w, challenge))
    e = curve.add(left.comm_e, curve.mul(comm_t, challenge))
    if not ordinary:
        e = curve.add(e, curve.mul(right.comm_e, challenge*challenge % q))
    return _Instance(left.engine, w, e, (left.u+challenge*right.u) % q,
                     tuple((a+challenge*b) % q for a, b in zip(left.x, right.x, strict=True)))


def _derandomize(instance, key, blind_w, blind_e):
    curve, q = CURVES[instance.engine], SCALAR_MODULI[instance.engine]
    if key.engine != instance.engine:
        raise ValueError('derandomization key role mismatch')
    for value in (blind_w, blind_e):
        _integer(value, 0, q-1, 'blinding scalar')
    return _Instance(instance.engine,
        curve.add(instance.comm_w, curve.mul(key.derand_h, -blind_w)),
        curve.add(instance.comm_e, curve.mul(key.derand_h, -blind_e)), instance.u, instance.x)


def _ro_point(point):
    return [0, 0, 1] if point is None else [point[0], point[1], 0]


def _ro_instance(instance, ordinary=False):
    result = _ro_point(instance.comm_w)
    if ordinary:
        return result + list(instance.x)
    result += _ro_point(instance.comm_e) + [instance.u]
    return result + [(value >> (64*i)) & ((1 << 64)-1) for value in instance.x for i in range(4)]


def _instance_repr(transcript, instance):
    return (transcript.commitment_repr(instance.comm_w)
            + transcript.commitment_repr(instance.comm_e)
            + transcript.scalar_repr(instance.u) + transcript.scalars_repr(instance.x))


def _instance_json(instance):
    return {'comm_W': {'comm': _point_hex(instance.comm_w)},
            'comm_E': {'comm': _point_hex(instance.comm_e)},
            'u': _le(instance.u), 'X': [_le(value) for value in instance.x]}


def ipa_factors(point, challenges, q):
    """Source-ordered tensor weights and <Eq(point),s> in O(log n) memory."""
    if q not in SCALAR_MODULI.values() or type(point) not in (tuple, list) or type(challenges) not in (tuple, list):
        raise ValueError('Pasta field and point/challenge arrays required')
    if len(point) != len(challenges) or not 1 <= len(challenges) <= 24:
        raise ValueError('IPA dimension mismatch')
    for value in point:
        _integer(value, 0, q-1, 'IPA point coordinate')
    for value in challenges:
        _integer(value, 1, q-1, 'nonzero IPA challenge')
    inverse = [pow(value, -1, q) for value in challenges]
    b_hat = s0 = 1
    for coordinate, positive, negative in zip(point, challenges, inverse, strict=True):
        b_hat = b_hat*((1-coordinate)*negative+coordinate*positive) % q
        s0 = s0*negative % q
    n = 1 << len(challenges)
    def weight(index):
        value = 1
        for j, (positive, negative) in enumerate(zip(challenges, inverse, strict=True)):
            value = value*(positive if (index >> (len(challenges)-1-j)) & 1 else negative) % q
        return value
    return {'b_hat': b_hat, 's0': s0,
            'left': [value*value % q for value in challenges],
            'right': [value*value % q for value in inverse],
            'selected_weights': {i: weight(i) for i in sorted({0, 1, n//2, n-1})}}


def _sumcheck(te, value, initial, rounds, degree):
    rows = value['compressed_polys']
    if len(rows) != rounds:
        raise ValueError('key-owned sumcheck round mismatch')
    q = SCALAR_MODULI[te.engine]
    claim, challenges = initial, []
    for row in rows:
        encoded = row['coeffs_except_linear_term']
        if not 1 <= len(encoded) <= degree:
            raise ValueError('compressed polynomial degree mismatch')
        compressed = tuple(_scalar(coefficient, q) for coefficient in encoded)
        coefficients = decompress(compressed, claim, q)
        # Source UniPoly::to_transcript_bytes recompresses and omits linear.
        te.scalars(b'p', compressed)
        challenge = te.squeeze(b'c')
        challenges.append(challenge)
        claim = evaluate(coefficients, challenge, q)
    return claim, tuple(challenges)


def _spartan_replay(instance, proof, key, shape, events):
    engine, q, curve = instance.engine, SCALAR_MODULI[instance.engine], CURVES[instance.engine]
    te = _KeccakReplay(engine, events)
    te.scalars(b'vk', (key.spartan_vk_digest,))
    te.absorb(b'U', _instance_repr(te.transcript, instance))
    tau = tuple(te.squeeze(b't') for _ in range(shape.outer_rounds))
    outer_claim, r_x = _sumcheck(te, proof['sc_proof_outer'], 0, shape.outer_rounds, 3)
    claims = tuple(_scalar(x, q) for x in proof['claims_outer'])
    eval_e, eval_w = _scalar(proof['eval_E'], q), _scalar(proof['eval_W'], q)
    expected_outer = outer_terminal(tau, r_x, *claims, eval_e, instance.u, q)
    if outer_claim != expected_outer:
        raise ValueError('production outer sumcheck terminal mismatch')
    te.scalars(b'claims_outer', claims+(eval_e,))
    inner_rho = te.squeeze(b'r')
    inner_initial = (claims[0]+inner_rho*claims[1]+inner_rho*inner_rho*claims[2]) % q
    inner_claim, r_y = _sumcheck(te, proof['sc_proof_inner'], inner_initial, shape.inner_rounds, 2)
    eval_x = sparse_evaluation((instance.u,)+instance.x, r_y[1:], q)
    eval_z = ((1-r_y[0])*eval_w+r_y[0]*eval_x) % q
    if eval_z == 0 and inner_claim != 0:
        raise ValueError('zero inner assignment evaluation has nonzero claim')
    required_matrix = None if not eval_z else inner_claim*pow(eval_z, -1, q) % q
    # Computing the actual key's A/B/C evaluations is intentionally separate.
    te.scalars(b'w', (eval_w,))
    batch_rho = te.squeeze(b'r')
    counts = (len(r_y)-1, len(r_x))
    batch_initial, maximum = batch_initial_claim((eval_w, eval_e), counts, (1, batch_rho), q)
    if maximum != shape.batch_rounds:
        raise ValueError('batch dimension differs from authenticated key')
    batch_claim, r_batch = _sumcheck(te, proof['sc_proof_batch'], batch_initial, maximum, 2)
    evals_batch = tuple(_scalar(x, q) for x in proof['evals_batch'])
    expected_batch = batch_terminal(evals_batch, (r_y[1:], r_x), r_batch, (1, batch_rho), q)
    if batch_claim != expected_batch:
        raise ValueError('production batch sumcheck terminal mismatch')
    te.scalars(b'l', evals_batch)
    joint_challenge = te.squeeze(b'c')
    joint_comm = curve.add(instance.comm_w, curve.mul(instance.comm_e, joint_challenge))
    joint_eval = 0
    for value, count, coefficient in zip(evals_batch, counts, (1, joint_challenge), strict=True):
        lagrange = 1
        for coordinate in r_batch[:maximum-count]:
            lagrange = lagrange*(1-coordinate) % q
        joint_eval = (joint_eval+coefficient*lagrange*value) % q
    te.dom_sep(b'IPA')
    te.absorb(b'U', te.transcript.commitment_repr(joint_comm)+te.transcript.scalar_repr(joint_eval))
    initial_ipa = te.squeeze(b'r')
    argument = proof['eval_arg']
    left, right = argument['L_vec'], argument['R_vec']
    if len(left) != shape.ipa_rounds or len(right) != shape.ipa_rounds:
        raise ValueError('IPA round count differs from authenticated key')
    challenges, left_points, right_points = [], [], []
    for l_value, r_value in zip(left, right, strict=True):
        l_point, r_point = _point(l_value, engine), _point(r_value, engine)
        left_points.append(l_point)
        right_points.append(r_point)
        te.absorb(b'L', te.transcript.commitment_repr(l_point))
        te.absorb(b'R', te.transcript.commitment_repr(r_point))
        challenges.append(te.squeeze(b'r'))
    te.finish()
    factors = ipa_factors(r_batch, challenges, q)
    a_hat = _scalar(argument['a_hat'], q)
    p_hat = curve.add(joint_comm, curve.mul(key.ipa_scalar_generator, initial_ipa*joint_eval % q))
    for point, coefficient in zip(left_points+right_points, factors['left']+factors['right'], strict=True):
        p_hat = curve.add(p_hat, curve.mul(point, coefficient))
    scalar_term = initial_ipa*a_hat*factors['b_hat'] % q
    residual = curve.add(p_hat, curve.mul(key.ipa_scalar_generator, -scalar_term))
    if a_hat == 0 and residual is not None:
        raise ValueError('IPA zero a_hat has nonzero required generator side')
    return {'engine': engine, 'keccak_events': te.position, 'keccak_squeezes': te.squeezes,
        'instance': _instance_json(instance), 'tau_le': [_le(x) for x in tau],
        'r_x_le': [_le(x) for x in r_x], 'outer_final_le': _le(outer_claim),
        'outer_terminal_checked': True, 'r_y_le': [_le(x) for x in r_y],
        'inner_final_le': _le(inner_claim), 'eval_z_le': _le(eval_z),
        'required_matrix_combination_le': None if required_matrix is None else _le(required_matrix),
        'matrix_evaluations_verified': False, 'batch_rho_le': _le(batch_rho),
        'batch_challenges_le': [_le(x) for x in r_batch],
        'batch_final_le': _le(batch_claim), 'batch_terminal_checked': True,
        'joint_challenge_le': _le(joint_challenge), 'joint_commitment': _point_hex(joint_comm),
        'joint_evaluation_le': _le(joint_eval),
        'ipa': {'initial_challenge_le': _le(initial_ipa),
            'challenges_le': [_le(x) for x in challenges],
            'left_coefficients_le': [_le(x) for x in factors['left']],
            'right_coefficients_le': [_le(x) for x in factors['right']],
            'b_hat_le': _le(factors['b_hat']), 's0_le': _le(factors['s0']),
            'selected_generator_weights': [{'index': index, 'scalar_le': _le(value)}
                for index, value in factors['selected_weights'].items()],
            'a_hat_le': _le(a_hat), 'P_hat': _point_hex(p_hat),
            'generator_residual': _point_hex(residual),
            'generator_msm_verified': False},
        'final_transcript': _keccak_snapshot(te.transcript)}


def replay_production(decoded, expected, bindings, native_trace, *, expected_trace_sha256):
    """Check a separately pinned native capture against proof/key-derived events.

    Caller-owned pins authenticate the capture and metadata. In particular,
    Poseidon results here are native-only inputs, not self-authenticating logs.
    Successful replay never returns ``proof_verified=True``.
    """
    if (type(decoded) is not DecodedProof or type(expected) is not ExpectedBundle
            or type(bindings) is not ReplayKeyBindings):
        raise ValueError('admitted proof, expected policy and pinned replay keys required')
    if decoded.dimensions != bindings.dimensions:
        raise ValueError('proof and key dimension identities differ')
    descriptor = decoded.dimensions.json()
    if (descriptor['network'] != expected.network or descriptor['k'] != expected.k
            or descriptor['verifier_key_sha256'] != expected.verifier_key_sha256.hex()):
        raise ValueError('replay policy identity mismatch')
    if not compare_digest(decoded.proof_sha256, expected.proof_sha256) or decoded.proof_bytes != expected.proof_bytes:
        raise ValueError('replay proof differs from verifier-owned proof identity')
    streams = _validate_trace(native_trace)
    capture_sha = _pin(native_trace, expected_trace_sha256, 'native trace')
    required = {('keccak', 'pallas', 0), ('keccak', 'vesta', 0),
                ('poseidon_base', 'pallas', 0), ('poseidon_base', 'pallas', 1),
                ('poseidon_base', 'vesta', 0), ('poseidon_base', 'vesta', 1),
                ('poseidon_base', 'vesta', 2)}
    if set(streams) != required:
        raise ValueError('missing or extra production verifier stream')
    proof = decoded.value
    z0 = expected.initial_state
    zn = tuple(_scalar(value, SCALAR_MODULI['pallas']) for value in proof['zn'])
    if sha256(b''.join(value.to_bytes(32, 'little') for value in zn)).digest() != expected.end_state_sha256:
        raise ValueError('replay output state differs from expected digest')
    if zn[0] != z0[0]+expected.steps*expected.k:
        raise ValueError('replay output height differs from header steps/k')
    p = _instance(proof['r_U_primary'], 'pallas')
    s = _instance(proof['r_U_secondary'], 'vesta')
    ordinary = _instance(proof['l_u_secondary'], 'vesta', ordinary=True)
    random_p = _instance(proof['l_ur_primary'], 'pallas')
    random_s = _instance(proof['l_ur_secondary'], 'vesta')
    q_p, q_s = SCALAR_MODULI['pallas'], SCALAR_MODULI['vesta']
    ri_p, ri_s = _scalar(proof['ri_primary'], q_p), _scalar(proof['ri_secondary'], q_s)
    hash_p = _native_ro('vesta', streams['poseidon_base', 'vesta', 0],
        [bindings.pp_digest, expected.steps]+list(z0)+list(zn)+_ro_instance(s)+[ri_p], 250)
    hash_s = _native_ro('pallas', streams['poseidon_base', 'pallas', 0],
        [bindings.pp_digest, expected.steps, 0, 0]+_ro_instance(p)+[ri_s], 250)
    if ordinary.x != (hash_p, hash_s):
        raise ValueError('captured native output hashes differ from proof public outputs')
    t_f = _point(proof['nifs_Uf_secondary']['comm_T'], 'vesta')
    challenge_f = _native_ro('vesta', streams['poseidon_base', 'vesta', 1],
        [bindings.pp_digest]+_ro_instance(ordinary, ordinary=True)+_ro_point(t_f), 128)
    folded_s = _fold(s, ordinary, t_f, challenge_f, ordinary=True)
    t_s = _point(proof['nifs_Un_secondary']['comm_T'], 'vesta')
    challenge_s = _native_ro('vesta', streams['poseidon_base', 'vesta', 2],
        [bindings.pp_digest]+_ro_instance(folded_s)+_ro_instance(random_s)+_ro_point(t_s), 128)
    folded_s = _fold(folded_s, random_s, t_s, challenge_s)
    t_p = _point(proof['nifs_Un_primary']['comm_T'], 'pallas')
    challenge_p = _native_ro('pallas', streams['poseidon_base', 'pallas', 1],
        [bindings.pp_digest]+_ro_instance(p)+_ro_instance(random_p)+_ro_point(t_p), 128)
    folded_p = _fold(p, random_p, t_p, challenge_p)
    unblinded = []
    for role, folded, key, q in (('primary', folded_p, bindings.primary, q_p),
                                 ('secondary', folded_s, bindings.secondary, q_s)):
        unblinded.append(_derandomize(folded, key,
            _scalar(proof[f'wit_blind_r_Wn_{role}'], q),
            _scalar(proof[f'err_blind_r_Wn_{role}'], q)))
    primary = _spartan_replay(unblinded[0], proof['snark_primary'], bindings.primary,
        decoded.dimensions.primary, streams['keccak', 'pallas', 0])
    secondary = _spartan_replay(unblinded[1], proof['snark_secondary'], bindings.secondary,
        decoded.dimensions.secondary, streams['keccak', 'vesta', 0])
    return {'passed': True, 'scope': 'proof-bound Keccak replay with native-only Poseidon results',
        'proof_sha256': decoded.proof_sha256.hex(), 'native_trace_sha256': capture_sha.hex(),
        'key_bindings_sha256': bindings.metadata_sha256.hex(),
        'verifier_dimensions_sha256': decoded.dimensions.descriptor_sha256.hex(),
        'native_capture_pin_matched': True, 'poseidon_absorption_streams_checked': 5,
        'poseidon_hashes_independently_verified': False,
        'poseidon_return_truncations_checked': True,
        'nifs_challenges_le': {'secondary_ordinary': _le(challenge_f),
            'secondary_relaxed': _le(challenge_s), 'primary_relaxed': _le(challenge_p)},
        'engines': [primary, secondary], 'matrix_evaluations_verified': False,
        'ipa_generator_msm_verified': False, 'proof_verified': False,
        'bitvm2_script_verified': False, 'transactions_broadcast': 0}
