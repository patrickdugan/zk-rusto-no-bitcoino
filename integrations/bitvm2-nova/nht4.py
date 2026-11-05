"""Strict NHC1/NHT4 framing and verifier-owned expectation binding.

Framing is not Nova proof verification. The container has no proof-length field,
so exact proof/container lengths and digests must come from an independently
authenticated expected claim. The native oracle additionally decodes the
compressed proof with strict bincode and calls the actual Nova verifier.
"""
from dataclasses import dataclass
from hashlib import sha256
from hmac import compare_digest
import json
import struct
from script import Q

HEADER_REVISION = 'de607d3db17d400dd6c2923d357f1d4a7bf233c7'
NOVA_VERSION = '0.76.0'
SCHEMA = 'bitvm2-nova-expected-bundle/v1'
MAGICS = {b'NHC1': 'mainnet', b'NHT4': 'testnet4'}
MAX_BUNDLE_BYTES, MAX_K, ARITY = 1 << 20, 64, 17
HEADER_BYTES = 12 + ARITY*32
U32_MAX = (1 << 32)-1
KEY_PINS = {
    ('mainnet', 10): bytes.fromhex('e46bb06929d701f1986d320e004e8ed744b0e5f74eb9f5e9c9bd0e2fe6ad1698'),
    ('testnet4', 5): bytes.fromhex('1ae88a7bcfdc5f14d030d0baafa06ec17fe904a5ebed42f9bd6fa6105fdc8c24'),
    ('testnet4', 10): bytes.fromhex('2495da9bf5965030e45fa2cef1a43ade78e099ca844b5d3a9abf56400447eabe'),
}


def _integer(value, low, high, label):
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f'{label} out of range')


def _digest(value, label):
    if type(value) is not bytes or len(value) != 32:
        raise ValueError(f'{label} must be 32 bytes')


def _hex(value, label):
    if type(value) is not str or len(value) != 64 or any(c not in '0123456789abcdef' for c in value):
        raise ValueError(f'{label} must be canonical 32-byte lowercase hex')
    return bytes.fromhex(value)


def initial_state_bytes(state):
    if type(state) is not tuple or len(state) != ARITY:
        raise ValueError('initial state must contain exactly 17 scalars')
    for i, value in enumerate(state):
        _integer(value, 0, Q-1, f'initial scalar {i}')
    # Match the pinned header backend's native State::from_z shape bounds.
    bounds = (1 << 32, 1 << 128, 1 << 128, 1 << 200) + (1 << 32,)*13
    if any(value >= bound for value, bound in zip(state, bounds, strict=True)):
        raise ValueError('initial header-state value exceeds its declared width')
    return b''.join(value.to_bytes(32, 'little') for value in state)


def genesis_initial_state(network):
    """The pinned circuit's state immediately after its consensus genesis."""
    if network == 'mainnet':
        merkle, timestamp, nonce = ('4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b',
                                    1_231_006_505, 2_083_236_893)
    elif network == 'testnet4':
        merkle, timestamp, nonce = ('7aa0a7ae1e223414cb807e40cd57e667b718e42aaf9306db9102fe28912b7b4e',
                                    1_714_777_860, 393_743_547)
    else:
        raise ValueError('unsupported network')
    bits = 0x1d00ffff
    header = struct.pack('<I', 1) + bytes(32) + bytes.fromhex(merkle)[::-1] + struct.pack('<III', timestamp, bits, nonce)
    block_hash = sha256(sha256(header).digest()).digest()
    target = (bits & 0x7fffff) << (8*((bits >> 24)-3))
    work = (1 << 256)//(target+1)
    times = tuple(0 if i % 2 == 0 else U32_MAX for i in range(10)) + (timestamp,)
    return (0, int.from_bytes(block_hash[:16], 'little'), int.from_bytes(block_hash[16:], 'little'),
            work, bits, timestamp) + times


@dataclass(frozen=True)
class ExpectedBundle:
    network: str
    k: int
    steps: int
    initial_state: tuple[int, ...]
    checkpoint_origin: str
    verifier_key_sha256: bytes
    proof_bytes: int
    proof_sha256: bytes
    bundle_bytes: int
    bundle_sha256: bytes
    end_state_sha256: bytes
    header_revision: str = HEADER_REVISION
    nova_version: str = NOVA_VERSION

    def __post_init__(self):
        if self.network not in MAGICS.values() or type(self.network) is not str:
            raise ValueError('unsupported expected network')
        _integer(self.k, 1, MAX_K, 'expected k')
        _integer(self.steps, 1, U32_MAX, 'expected steps')
        initial_state_bytes(self.initial_state)
        if self.initial_state[0] + self.steps*self.k > U32_MAX:
            raise ValueError('expected final height exceeds u32')
        if self.checkpoint_origin not in ('genesis', 'operator_pinned'):
            raise ValueError('explicit checkpoint origin required')
        if self.checkpoint_origin == 'genesis' and self.initial_state != genesis_initial_state(self.network):
            raise ValueError('initial state differs from the selected consensus genesis')
        for name in ('verifier_key_sha256', 'proof_sha256', 'bundle_sha256', 'end_state_sha256'):
            _digest(getattr(self, name), name)
        pin = KEY_PINS.get((self.network, self.k))
        if pin is not None and not compare_digest(pin, self.verifier_key_sha256):
            raise ValueError('verifier key differs from the pinned network/k key')
        for owner, known in KEY_PINS.items():
            if compare_digest(known, self.verifier_key_sha256) and owner != (self.network, self.k):
                raise ValueError('verifier key belongs to another network/k')
        _integer(self.proof_bytes, 1, MAX_BUNDLE_BYTES-HEADER_BYTES, 'expected proof length')
        _integer(self.bundle_bytes, HEADER_BYTES+1, MAX_BUNDLE_BYTES, 'expected bundle length')
        if self.bundle_bytes != HEADER_BYTES+self.proof_bytes:
            raise ValueError('expected proof/container lengths disagree')
        if self.header_revision != HEADER_REVISION or self.nova_version != NOVA_VERSION:
            raise ValueError('unsupported header circuit or Nova backend version')

    def json(self):
        return {'schema': SCHEMA, 'network': self.network, 'k': self.k, 'steps': self.steps,
                'initial_state_le': [value.to_bytes(32, 'little').hex() for value in self.initial_state],
                'checkpoint_origin': self.checkpoint_origin,
                'verifier_key_sha256': self.verifier_key_sha256.hex(), 'proof_bytes': self.proof_bytes,
                'proof_sha256': self.proof_sha256.hex(), 'bundle_bytes': self.bundle_bytes,
                'bundle_sha256': self.bundle_sha256.hex(), 'end_state_sha256': self.end_state_sha256.hex(),
                'header_revision': self.header_revision, 'nova_version': self.nova_version}

    @classmethod
    def from_json(cls, value):
        required = {'schema', 'network', 'k', 'steps', 'initial_state_le', 'checkpoint_origin',
                    'verifier_key_sha256', 'proof_bytes', 'proof_sha256', 'bundle_bytes',
                    'bundle_sha256', 'end_state_sha256', 'header_revision', 'nova_version'}
        if type(value) is not dict or set(value) != required or value['schema'] != SCHEMA:
            raise ValueError('unsupported expected-bundle schema or fields')
        state = value['initial_state_le']
        if type(state) is not list or len(state) != ARITY:
            raise ValueError('initial state must have exactly 17 encodings')
        return cls(value['network'], value['k'], value['steps'],
                   tuple(int.from_bytes(_hex(x, 'initial state'), 'little') for x in state),
                   value['checkpoint_origin'], _hex(value['verifier_key_sha256'], 'verifier key'),
                   value['proof_bytes'], _hex(value['proof_sha256'], 'proof'), value['bundle_bytes'],
                   _hex(value['bundle_sha256'], 'bundle'), _hex(value['end_state_sha256'], 'end state'),
                   value['header_revision'], value['nova_version'])


def load_expected_json(raw):
    """Read a bounded policy, rejecting duplicate fields before interpretation."""
    if type(raw) is not bytes or not 0 < len(raw) <= 8192:
        raise ValueError('expected-bundle JSON length out of bounds')

    def unique(pairs):
        out = {}
        for key, value in pairs:
            if key in out:
                raise ValueError('duplicate expected-bundle field')
            out[key] = value
        return out

    try:
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=unique)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError('invalid expected-bundle JSON') from error
    return ExpectedBundle.from_json(value)


@dataclass(frozen=True)
class Container:
    network: str
    steps: int
    k: int
    initial_state: tuple[int, ...]
    proof: bytes
    encoded: bytes

    def summary(self):
        return {'network': self.network, 'steps': self.steps, 'k': self.k,
                'bundle_bytes': len(self.encoded), 'proof_bytes': len(self.proof),
                'bundle_sha256': sha256(self.encoded).hexdigest(), 'proof_sha256': sha256(self.proof).hexdigest(),
                'initial_state_sha256': sha256(initial_state_bytes(self.initial_state)).hexdigest(),
                'proof_verified': False, 'bitvm2_script_verified': False, 'transactions_broadcast': 0}


def decode_container(raw):
    if type(raw) is not bytes or not HEADER_BYTES < len(raw) <= MAX_BUNDLE_BYTES:
        raise ValueError('container byte length out of bounds')
    network = MAGICS.get(raw[:4])
    if network is None:
        raise ValueError('unsupported NHC1/NHT4 magic')
    steps, k = struct.unpack_from('<II', raw, 4)
    _integer(steps, 1, U32_MAX, 'container steps')
    _integer(k, 1, MAX_K, 'container k')
    state = tuple(int.from_bytes(raw[12+32*i:44+32*i], 'little') for i in range(ARITY))
    initial_state_bytes(state)
    return Container(network, steps, k, state, raw[HEADER_BYTES:], raw)


def bind_container(raw, expected):
    """Bind framing to independent expectations, without verifying its proof."""
    if type(expected) is not ExpectedBundle:
        raise ValueError('verifier-owned ExpectedBundle required')
    if type(raw) is not bytes or len(raw) != expected.bundle_bytes:
        raise ValueError('container does not have the exact expected byte length')
    decoded = decode_container(raw)
    if (decoded.network, decoded.k, decoded.steps, decoded.initial_state) != (
            expected.network, expected.k, expected.steps, expected.initial_state):
        raise ValueError('container network/k/steps/initial-state expectation mismatch')
    if len(decoded.proof) != expected.proof_bytes or not compare_digest(sha256(decoded.proof).digest(), expected.proof_sha256):
        raise ValueError('compressed proof length or identity mismatch')
    if not compare_digest(sha256(raw).digest(), expected.bundle_sha256):
        raise ValueError('container identity mismatch')
    return decoded
