"""Independent arithmetic for Nova 0.76.0's vendored Poseidon sponge.

This uses caller-authenticated parameters exported from the actual pinned VK.
It does not derive or invent constants and never consumes an expected native
hash to compute an output. The optimized static schedule, mixed matrix
orientation and wrapping128-bit IO tag follow the released vendored source:
frontend/gadgets/poseidon/{poseidon_inner,sponge/api,sponge/vanilla}.rs and
provider/poseidon.rs. This is native Python arithmetic, not Bitcoin Script.
"""
from dataclasses import dataclass
from hashlib import sha256
from hmac import compare_digest
import json

from nht4 import ExpectedBundle, HEADER_REVISION
from proof_codec import BASE_MODULI, NOVA_CRATE_SHA256, VerifierDimensions

SCHEMA = 'bitvm2-nova-poseidon-parameters/v1'
MAX_PARAMETERS_BYTES = 2 << 20
MAX_INPUTS = 1024
MODES = {'wide': (24, 25), 'narrow': (5, 6)}
IO_BASE = (1 << 128)-159
U128_MASK = (1 << 128)-1


def _keys(value, keys, name):
    if type(value) is not dict or set(value) != set(keys):
        raise ValueError(f'unexpected {name} fields')


def _integer(value, minimum, maximum, name):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f'invalid {name}')
    return value


def _scalar(value, modulus):
    if (type(value) is not str or len(value) != 64
            or any(c not in '0123456789abcdef' for c in value)):
        raise ValueError('canonical32-byte lowercase scalar hex required')
    result = int.from_bytes(bytes.fromhex(value), 'little')
    if result >= modulus:
        raise ValueError('noncanonical Poseidon parameter scalar')
    return result


def _vector(value, count, modulus):
    if type(value) is not list or len(value) != count:
        raise ValueError('Poseidon parameter vector shape mismatch')
    return tuple(_scalar(item, modulus) for item in value)


def _matrix(value, width, modulus):
    if type(value) is not list or len(value) != width:
        raise ValueError('Poseidon matrix shape mismatch')
    return tuple(_vector(row, width, modulus) for row in value)


@dataclass(frozen=True, init=False)
class PoseidonProfile:
    engine: str
    mode: str
    modulus: int
    arity: int
    width: int
    rate: int
    capacity: int
    rf: int
    rp: int
    mds: tuple
    crc: tuple[int, ...]
    psm: tuple
    sm: tuple

    def __init__(self, *args, **kwargs):
        raise TypeError('use an authenticated PoseidonParameters profile')

    @classmethod
    def _from_json(cls, value, engine, mode):
        _keys(value, {'arity', 'width', 'rate', 'capacity', 'mds', 'crc', 'psm',
                      'sm', 'rf', 'rp', 's', 'ht'}, 'Poseidon profile')
        rate, width = MODES[mode]
        expected = {'arity': rate, 'width': width, 'rate': rate, 'capacity': 1,
                    's': 'Standard', 'ht': 'Sponge'}
        if any(type(value[k]) is not type(v) or value[k] != v for k, v in expected.items()):
            raise ValueError('unsupported Poseidon profile identity')
        rf = _integer(value['rf'], 2, 16, 'full round count')
        rp = _integer(value['rp'], 1, 128, 'partial round count')
        if rf % 2:
            raise ValueError('Poseidon full round count must be even')
        p = BASE_MODULI[engine]
        mds = _matrix(value['mds'], width, p)
        crc = _vector(value['crc'], rf*width+rp, p)
        psm = _matrix(value['psm'], width, p)
        if type(value['sm']) is not list or len(value['sm']) != rp:
            raise ValueError('Poseidon sparse round matrix count mismatch')
        sparse = []
        for matrix in value['sm']:
            _keys(matrix, {'w_hat', 'v_rest'}, 'sparse matrix')
            sparse.append((_vector(matrix['w_hat'], width, p),
                           _vector(matrix['v_rest'], width-1, p)))
        result = object.__new__(cls)
        for name, item in (('engine', engine), ('mode', mode), ('modulus', p),
            ('arity', rate), ('width', width), ('rate', rate), ('capacity', 1),
            ('rf', rf), ('rp', rp), ('mds', mds), ('crc', crc), ('psm', psm),
            ('sm', tuple(sparse))):
            object.__setattr__(result, name, item)
        return result


@dataclass(frozen=True, init=False)
class PoseidonParameters:
    dimensions: VerifierDimensions
    parameters_sha256: bytes
    _profiles: tuple[PoseidonProfile, ...]
    _canonical_json: bytes

    def __init__(self, *args, **kwargs):
        raise TypeError('use PoseidonParameters.from_json with an independent pin')

    @classmethod
    def from_json(cls, data, expected, dimensions, *, expected_parameters_sha256):
        """Pins must be authenticated separately from parameter JSON transport."""
        if type(expected) is not ExpectedBundle or type(dimensions) is not VerifierDimensions:
            raise ValueError('caller-owned expected policy and dimensions required')
        if type(expected_parameters_sha256) is not bytes or len(expected_parameters_sha256) != 32:
            raise ValueError('independent Poseidon parameter digest required')
        _keys(data, {'schema', 'nova_version', 'nova_crate_sha256', 'header_revision',
            'network', 'k', 'verifier_key_sha256', 'verifier_dimensions_sha256',
            'primary', 'secondary'}, 'Poseidon parameter object')
        identities = {'schema': SCHEMA, 'nova_version': '0.76.0',
            'nova_crate_sha256': NOVA_CRATE_SHA256, 'header_revision': HEADER_REVISION,
            'network': expected.network, 'k': expected.k,
            'verifier_key_sha256': expected.verifier_key_sha256.hex(),
            'verifier_dimensions_sha256': dimensions.descriptor_sha256.hex()}
        if any(type(data[k]) is not type(v) or data[k] != v for k, v in identities.items()):
            raise ValueError('Poseidon parameter policy identity mismatch')
        descriptor = dimensions.json()
        if (descriptor['network'] != expected.network or descriptor['k'] != expected.k
                or descriptor['verifier_key_sha256'] != expected.verifier_key_sha256.hex()):
            raise ValueError('Poseidon dimension/policy identity mismatch')
        profiles = []
        for role, engine in (('primary', 'pallas'), ('secondary', 'vesta')):
            value = data[role]
            _keys(value, {'engine', 'field_role', 'wide', 'narrow'}, 'Poseidon engine parameters')
            if (type(value['engine']) is not str or value['engine'] != engine
                    or type(value['field_role']) is not str or value['field_role'] != engine+'_base'):
                raise ValueError('Poseidon field/engine role mismatch')
            for mode in ('wide', 'narrow'):
                profiles.append(PoseidonProfile._from_json(value[mode], engine, mode))
        # Typed exact shallow dimensions are checked before recursive JSON work.
        encoded = json.dumps(data, sort_keys=True, separators=(',', ':'),
                             ensure_ascii=True, allow_nan=False).encode('ascii')
        if len(encoded) > MAX_PARAMETERS_BYTES:
            raise ValueError('Poseidon parameter byte budget')
        digest = sha256(encoded).digest()
        if not compare_digest(digest, expected_parameters_sha256):
            raise ValueError('Poseidon parameter digest mismatch')
        result = object.__new__(cls)
        for name, item in (('dimensions', dimensions), ('parameters_sha256', digest),
                            ('_profiles', tuple(profiles)), ('_canonical_json', encoded)):
            object.__setattr__(result, name, item)
        return result

    def profile(self, engine, mode='wide'):
        if type(engine) is not str or engine not in BASE_MODULI or type(mode) is not str or mode not in MODES:
            raise ValueError('unsupported Poseidon engine/mode')
        index = (0 if engine == 'pallas' else 2)+(0 if mode == 'wide' else 1)
        return self._profiles[index]

    def json(self):
        return json.loads(self._canonical_json)


def load_parameters_json(raw, expected, dimensions, *, expected_parameters_sha256):
    if type(raw) is not bytes or not 1 <= len(raw) <= MAX_PARAMETERS_BYTES:
        raise ValueError('Poseidon parameter JSON byte budget/type')
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('duplicate Poseidon parameter JSON field')
            result[key] = value
        return result
    def constant(_):
        raise ValueError('non-JSON constant')
    try:
        data = json.loads(raw.decode('utf-8'), object_pairs_hook=pairs, parse_constant=constant)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError('invalid Poseidon parameter JSON') from error
    return PoseidonParameters.from_json(data, expected, dimensions,
                                        expected_parameters_sha256=expected_parameters_sha256)


def io_tag(input_count):
    """Nova's [Absorb(n),Squeeze(1)] tag, with u128 wrapping and no domain."""
    _integer(input_count, 0, MAX_INPUTS, 'Poseidon input count')
    if input_count == 0:
        return IO_BASE
    return (IO_BASE*(input_count+(1 << 31))+IO_BASE*IO_BASE) & U128_MASK


def permute(profile, state):
    """Optimized-static permutation, returning the complete immutable state."""
    if type(profile) is not PoseidonProfile or type(state) not in (tuple, list) or len(state) != profile.width:
        raise ValueError('typed Poseidon profile and exact-width state required')
    p, width = profile.modulus, profile.width
    for value in state:
        _integer(value, 0, p-1, 'Poseidon state element')
    values = [(value+constant) % p for value, constant in zip(state, profile.crc[:width], strict=True)]
    offset, half = width, profile.rf//2
    for round_index in range(profile.rf+profile.rp):
        partial = half <= round_index < half+profile.rp
        last = round_index == profile.rf+profile.rp-1
        if partial:
            values[0] = (pow(values[0], 5, p)+profile.crc[offset]) % p
            offset += 1
        else:
            values = [pow(value, 5, p) for value in values]
            if not last:
                values = [(value+constant) % p for value, constant
                          in zip(values, profile.crc[offset:offset+width], strict=True)]
                offset += width
        if round_index == half-1:
            # Source pre-sparse multiplication uses row-vector * matrix columns.
            values = [sum(values[i]*profile.psm[i][j] for i in range(width)) % p
                      for j in range(width)]
        elif partial:
            w_hat, v_rest = profile.sm[round_index-half]
            first = sum(a*b for a, b in zip(values, w_hat, strict=True)) % p
            values = [first]+[(values[j]+values[0]*v_rest[j-1]) % p for j in range(1, width)]
        else:
            # Normal MDS multiplication is matrix rows * column state.
            values = [sum(a*b for a, b in zip(row, values, strict=True)) % p for row in profile.mds]
    if offset != len(profile.crc):
        raise ValueError('Poseidon compressed constant consumption mismatch')
    return tuple(values)


def sponge_hash(profile, inputs):
    """Fresh simplex sponge, no padding or clearing residual rate lanes."""
    if type(profile) is not PoseidonProfile or type(inputs) not in (tuple, list) or len(inputs) > MAX_INPUTS:
        raise ValueError('typed Poseidon profile and bounded input sequence required')
    p = profile.modulus
    for value in inputs:
        _integer(value, 0, p-1, 'Poseidon absorbed element')
    state, position = [io_tag(len(inputs))]+[0]*profile.rate, 0
    for value in inputs:
        if position == profile.rate:
            state, position = list(permute(profile, state)), 0
        # Add to the existing rate lane; do not overwrite previous permutation.
        state[position+1] = (state[position+1]+value) % p
        position += 1
    # SpongeAPI::absorb sets squeeze_pos=rate even for an empty input.
    state = permute(profile, state)
    return state[1]


class PoseidonRO:
    """Provider RO state: a fresh sponge per squeeze, retaining its FULL hash."""
    __slots__ = ('_profile', '_state', '_last_full_hash')

    def __init__(self, profile):
        if type(profile) is not PoseidonProfile:
            raise ValueError('authenticated Poseidon profile required')
        self._profile, self._state, self._last_full_hash = profile, (), None

    @property
    def state(self):
        return self._state

    @property
    def last_full_hash(self):
        return self._last_full_hash

    def absorb(self, value):
        _integer(value, 0, self._profile.modulus-1, 'Poseidon absorbed element')
        if len(self._state) >= MAX_INPUTS:
            raise ValueError('Poseidon RO input budget')
        self._state += (value,)

    def squeeze(self, num_bits, start_with_one=False):
        _integer(num_bits, 1, 255, 'Poseidon squeeze width')
        if type(start_with_one) is not bool:
            raise ValueError('Poseidon start_with_one must be boolean')
        full = sponge_hash(self._profile, self._state)
        output = full & ((1 << num_bits)-1)
        if start_with_one and not ((full >> (num_bits-1)) & 1):
            # Native field addition can wrap when forcing bit254 at width255.
            output += 1 << (num_bits-1)
        output %= self._profile.modulus
        self._state, self._last_full_hash = (full,), full
        return output
