"""Sealed proof-derived requests for a separately executed native IPA MSM.

Preparation is not execution or proof verification. The public builder accepts
an admitted proof and independently pinned key/trace/Poseidon/generator metadata,
then reconstructs the transcript itself. It never accepts a replay receipt as
authority. No JSON result-import API can enable a verification flag here.

Generator payload authentication, the large MSM and direct configured-process
execution are separate future boundaries. No generator payload is read by this
module. Native Nova 0.76 IPA equations/order: provider/ipa_pc.rs.
"""
from dataclasses import dataclass
from hashlib import sha256
from hmac import compare_digest
import json

from nht4 import ExpectedBundle, HEADER_REVISION
from poseidon_reference import PoseidonParameters
from production_replay import ReplayKeyBindings, replay_production
from proof_codec import (NOVA_CRATE_SHA256, SCALAR_MODULI, DecodedProof,
                         VerifierDimensions, decode_point)

COLLECTION_SCHEMA = 'bitvm2-nova-ipa-generators/v1'
REQUEST_SCHEMA = 'bitvm2-nova-ipa-request/v1'
ENCODING = 'bincode-1.3.3-legacy-fixed-little-endian'
MAX_METADATA_BYTES = 1 << 16
MAX_REQUEST_BYTES = 1 << 15
MAX_FILE_BYTES = 32 << 20
MAX_COLLECTION_BYTES = 32 << 20
ROLES = (('primary', 'pallas'), ('secondary', 'vesta'))


def _keys(value, names, description):
    if (type(value) is not dict or len(value) != len(names)
            or set(value) != set(names)):
        raise ValueError(f'unexpected {description} fields')


def _integer(value, low, high, description):
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f'invalid {description}')
    return value


def _hex32(value, description):
    if (type(value) is not str or len(value) != 64
            or any(c not in '0123456789abcdef' for c in value)):
        raise ValueError(f'canonical lowercase32-byte {description} hex required')
    return bytes.fromhex(value)


def _canonical(data, limit):
    encoded = json.dumps(data, sort_keys=True, separators=(',', ':'),
                         ensure_ascii=True, allow_nan=False).encode('ascii')
    if len(encoded) > limit:
        raise ValueError('IPA metadata/request JSON byte budget')
    return encoded


def _matches(data, identities):
    if any(type(data[key]) is not type(value) or data[key] != value
           for key, value in identities.items()):
        raise ValueError('IPA metadata identity/shape mismatch')


def _identity(expected, dimensions):
    if type(expected) is not ExpectedBundle or type(dimensions) is not VerifierDimensions:
        raise ValueError('caller-owned expected policy and dimensions required')
    data = dimensions.json()
    if (data['network'] != expected.network or data['k'] != expected.k
            or data['verifier_key_sha256'] != expected.verifier_key_sha256.hex()):
        raise ValueError('IPA dimension/policy identity mismatch')
    return dict(nova_version='0.76.0', nova_crate_sha256=NOVA_CRATE_SHA256,
        header_revision=HEADER_REVISION, network=expected.network, k=expected.k,
        verifier_key_sha256=expected.verifier_key_sha256.hex(),
        verifier_dimensions_sha256=dimensions.descriptor_sha256.hex())


def _transport(raw):
    if type(raw) is not bytes or not 1 <= len(raw) <= MAX_METADATA_BYTES:
        raise ValueError('IPA collection JSON byte budget/type')
    depth, quoted, escaped = 0, False, False
    for byte in raw:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            if depth > 8:
                raise ValueError('IPA collection JSON nesting budget')
        elif byte in (93, 125):
            depth -= 1
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('duplicate IPA collection JSON field')
            result[key] = value
        return result
    def invalid(_):
        raise ValueError('non-JSON constant')
    try:
        return json.loads(raw.decode('ascii'), object_pairs_hook=pairs, parse_constant=invalid)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError('invalid IPA collection JSON') from error


def _make(cls, **fields):
    result = object.__new__(cls)
    for key, value in fields.items():
        object.__setattr__(result, key, value)
    return result


class _FactoryOnly:
    def __init__(self, *args, **kwargs):
        raise TypeError('use an independently pinned IPA metadata/proof builder')


@dataclass(frozen=True, init=False)
class GeneratorSegment(_FactoryOnly):
    name: str
    offset: int
    bytes: int
    sha256: bytes


@dataclass(frozen=True, init=False)
class GeneratorFile(_FactoryOnly):
    role: str
    engine: str
    filename: str
    count: int
    bytes: int
    sha256: bytes
    segments: tuple[GeneratorSegment, ...]


@dataclass(frozen=True, init=False)
class IpaGeneratorCollection(_FactoryOnly):
    dimensions: VerifierDimensions
    collection_sha256: bytes
    total_bytes: int
    files: tuple[GeneratorFile, ...]
    _json: bytes

    @classmethod
    def from_json(cls, data, expected, dimensions, *, expected_collection_sha256):
        if type(expected_collection_sha256) is not bytes or len(expected_collection_sha256) != 32:
            raise ValueError('independent IPA generator collection SHA256 required')
        identities = _identity(expected, dimensions)
        identities.update(schema=COLLECTION_SCHEMA, encoding=ENCODING)
        _keys(data, set(identities) | {'total_bytes', 'files'}, 'IPA generator collection')
        _matches(data, identities)
        total = _integer(data['total_bytes'], 32, MAX_COLLECTION_BYTES, 'generator collection bytes')
        if type(data['files']) is not list or len(data['files']) != 2:
            raise ValueError('two ordered IPA generator files required')
        files = []
        for value, (role, engine) in zip(data['files'], ROLES, strict=True):
            dim = getattr(dimensions, role)
            if dim.ck_v_generators != dim.ipa_dimension or dim.ck_s_generators != 1:
                raise ValueError('bounded IPA profile requires exact vector capacity and one scalar generator')
            count = dim.ipa_dimension
            size = 8+32*count
            _integer(size, 40, MAX_FILE_BYTES, 'generator file byte budget')
            _keys(value, {'role', 'engine', 'base_field_role', 'scalar_field_role',
                'filename', 'count', 'bytes', 'sha256', 'segments'}, 'IPA generator file')
            _matches(value, dict(role=role, engine=engine, base_field_role=engine+'_base',
                scalar_field_role=engine+'_scalar', filename=f'{role}-generators.bin',
                count=count, bytes=size))
            if type(value['segments']) is not list or len(value['segments']) != 2:
                raise ValueError('count and points generator segments required')
            segments = []
            for segment, name, offset, length in zip(value['segments'],
                    ('count', 'points'), (0, 8), (8, 32*count), strict=True):
                _keys(segment, {'name', 'offset', 'bytes', 'sha256'}, 'generator segment')
                _matches(segment, dict(name=name, offset=offset, bytes=length))
                segments.append(_make(GeneratorSegment, name=name, offset=offset,
                    bytes=length, sha256=_hex32(segment['sha256'], 'segment SHA256')))
            files.append(_make(GeneratorFile, role=role, engine=engine,
                filename=value['filename'], count=count, bytes=size,
                sha256=_hex32(value['sha256'], 'file SHA256'), segments=tuple(segments)))
        if total != sum(file.bytes for file in files):
            raise ValueError('generator collection total byte mismatch')
        encoded = _canonical(data, MAX_METADATA_BYTES)
        digest = sha256(encoded).digest()
        if not compare_digest(digest, expected_collection_sha256):
            raise ValueError('IPA generator collection digest mismatch')
        return _make(cls, dimensions=dimensions, collection_sha256=digest,
                     total_bytes=total, files=tuple(files), _json=encoded)

    def file(self, role):
        if type(role) is not str or role not in ('primary', 'secondary'):
            raise ValueError('IPA role must be primary or secondary')
        return self.files[0 if role == 'primary' else 1]

    def json(self):
        return json.loads(self._json)


def load_generator_collection_json(raw, expected, dimensions, *, expected_collection_sha256):
    return IpaGeneratorCollection.from_json(_transport(raw), expected, dimensions,
        expected_collection_sha256=expected_collection_sha256)


def _scalar_hex(value, engine, *, nonzero=False):
    raw = _hex32(value, 'scalar')
    scalar = int.from_bytes(raw, 'little')
    if scalar >= SCALAR_MODULI[engine] or (nonzero and scalar == 0):
        raise ValueError('noncanonical or prohibited zero IPA scalar')
    return value


def _point_hex(value, engine):
    # decode_point rejects x>=p, off-curve points and identity sign aliases.
    decode_point(_hex32(value, 'point'), engine)
    return value


def _vector(value, count, decoder):
    if type(value) is not list or len(value) != count:
        raise ValueError('IPA request vector dimension mismatch')
    return [decoder(item) for item in value]


def _validated_statement(data, dimension, engine):
    """Private transport validation only; this never seals a public request."""
    _integer(dimension, 8, (MAX_FILE_BYTES-8)//32, 'IPA request dimension')
    rounds = dimension.bit_length()-1
    if dimension & (dimension-1) or type(engine) is not str or engine not in SCALAR_MODULI:
        raise ValueError('unsupported IPA request dimension/engine')
    _keys(data, {'joint_commitment', 'joint_evaluation_le', 'batch_point_le',
        'ipa_initial_challenge_le', 'L_vec', 'R_vec', 'challenges_le', 'a_hat_le',
        'generator_residual'}, 'IPA mathematical statement')
    return dict(joint_commitment=_point_hex(data['joint_commitment'], engine),
        joint_evaluation_le=_scalar_hex(data['joint_evaluation_le'], engine),
        batch_point_le=_vector(data['batch_point_le'], rounds, lambda x: _scalar_hex(x, engine)),
        ipa_initial_challenge_le=_scalar_hex(data['ipa_initial_challenge_le'], engine),
        L_vec=_vector(data['L_vec'], rounds, lambda x: _point_hex(x, engine)),
        R_vec=_vector(data['R_vec'], rounds, lambda x: _point_hex(x, engine)),
        challenges_le=_vector(data['challenges_le'], rounds,
                             lambda x: _scalar_hex(x, engine, nonzero=True)),
        a_hat_le=_scalar_hex(data['a_hat_le'], engine),
        generator_residual=_point_hex(data['generator_residual'], engine))


@dataclass(frozen=True, init=False)
class IpaStatement(_FactoryOnly):
    role: str
    engine: str
    request_sha256: bytes
    _json: bytes

    def to_bytes(self):
        return self._json

    def json(self):
        return json.loads(self._json)

    def summary(self):
        return dict(status='prepared', role=self.role, engine=self.engine,
            request_sha256=self.request_sha256.hex(), request_bytes=len(self._json),
            ipa_native_msm_executed=False, ipa_native_relation_checked=False,
            ipa_python_msm_independently_computed=False, ipa_generator_msm_verified=False,
            proof_verified=False, bitvm2_script_verified=False)


def build_ipa_statements(decoded, expected, bindings, native_trace, *,
                         expected_trace_sha256, poseidon_parameters,
                         generator_collection):
    """Reconstruct the proof transcript and prepare both sealed native requests.

    Every external pin is caller-owned. The generator collection pin authenticates
    metadata only until the native checker reads and authenticates exact payload
    bytes. Requests do not execute native code, allocate large tables, read bulk
    generators, or establish an IPA relation. There is no replay-JSON argument.
    """
    if (type(decoded) is not DecodedProof or type(expected) is not ExpectedBundle
            or type(bindings) is not ReplayKeyBindings
            or type(poseidon_parameters) is not PoseidonParameters
            or type(generator_collection) is not IpaGeneratorCollection):
        raise ValueError('admitted proof and typed independently pinned IPA inputs required')
    if (decoded.dimensions != bindings.dimensions
            or decoded.dimensions != poseidon_parameters.dimensions
            or decoded.dimensions != generator_collection.dimensions):
        raise ValueError('IPA request input dimension identities differ')
    # This is a fresh reconstruction from proof/key objects. A caller cannot
    # supply a receipt or a passed:true field in place of this computation.
    replay = replay_production(decoded, expected, bindings, native_trace,
        expected_trace_sha256=expected_trace_sha256,
        poseidon_parameters=poseidon_parameters)
    proof, requests = decoded.value, []
    for index, (role, engine) in enumerate(ROLES):
        shape = getattr(decoded.dimensions, role)
        details = replay['engines'][index]
        if details['engine'] != engine:
            raise ValueError('reconstructed IPA role mismatch')
        argument, ipa = proof['snark_'+role]['eval_arg'], details['ipa']
        mathematical = _validated_statement(dict(
            joint_commitment=details['joint_commitment'],
            joint_evaluation_le=details['joint_evaluation_le'],
            batch_point_le=details['batch_challenges_le'],
            ipa_initial_challenge_le=ipa['initial_challenge_le'],
            L_vec=[point['comm'] for point in argument['L_vec']],
            R_vec=[point['comm'] for point in argument['R_vec']],
            challenges_le=ipa['challenges_le'], a_hat_le=argument['a_hat'],
            generator_residual=ipa['generator_residual']), shape.ipa_dimension, engine)
        request = _identity(expected, decoded.dimensions)
        request.update(schema=REQUEST_SCHEMA, role=role, engine=engine,
            proof_sha256=decoded.proof_sha256.hex(), steps=expected.steps,
            bundle_sha256=expected.bundle_sha256.hex(), end_state_sha256=expected.end_state_sha256.hex(),
            key_bindings_sha256=bindings.metadata_sha256.hex(),
            native_trace_sha256=replay['native_trace_sha256'],
            poseidon_parameters_sha256=poseidon_parameters.parameters_sha256.hex(),
            generator_collection_sha256=generator_collection.collection_sha256.hex(),
            ipa_dimension=shape.ipa_dimension, generator_count=generator_collection.file(role).count,
            **mathematical)
        encoded = _canonical(request, MAX_REQUEST_BYTES)
        requests.append(_make(IpaStatement, role=role, engine=engine,
            request_sha256=sha256(encoded).digest(), _json=encoded))
    return tuple(requests)
