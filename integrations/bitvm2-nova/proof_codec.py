"""Bounded Nova 0.76.0 non-EVM Pallas/Vesta compressed-proof admission.

This parses exactly the released fixed-integer little-endian bincode layout.
It checks encodings and verifier-owned shapes; it does NOT verify a Nova proof.
Dimensions must come from an authenticated descriptor, independently pinned by
the caller. A matching VK hash written inside editable JSON is insufficient.

Primary source: nova-snark 0.76.0 (crate SHA below), nova/mod.rs,
r1cs/mod.rs, nova/nifs.rs, spartan/{snark,sumcheck}.rs,
spartan/polys/univariate.rs and provider/{ipa_pc,pedersen}.rs. Non-EVM only.
"""
from dataclasses import dataclass
from functools import lru_cache
from hashlib import sha256
from hmac import compare_digest
import json

from ipa_algebra import _sqrt
from nht4 import ExpectedBundle, HEADER_REVISION
from script import P, Q

NOVA_CRATE_SHA256 = 'c9bb3809a6c70057ea722c1c4fe5097cf29a3479d0b4671f3cddb1d81043bb31'
SCHEMA = 'bitvm2-nova-verifier-dimensions/v1'
MAX_PROOF_BYTES = 1 << 20
MAX_IPA_DIMENSION = 1 << 24
MAX_DESCRIPTOR_BYTES = 1 << 14
BASE_MODULI = {'pallas': P, 'vesta': Q}
SCALAR_MODULI = {'pallas': Q, 'vesta': P}
HEADER_WIDTHS = (32, 128, 128, 200) + (32,)*13


def _canonical_json(value):
    try:
        return json.dumps(value, sort_keys=True, separators=(',', ':'),
                          ensure_ascii=True, allow_nan=False).encode('ascii')
    except (TypeError, ValueError, UnicodeError) as error:
        raise ValueError('descriptor is not canonical JSON data') from error


def _integer(value, minimum, maximum, name):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f'{name} outside admission bounds')
    return value


def _keys(value, keys, name):
    if type(value) is not dict or set(value) != set(keys):
        raise ValueError(f'unexpected {name} fields')


@dataclass(frozen=True)
class CurveDimensions:
    engine: str
    num_cons: int
    num_vars: int
    num_io: int
    outer_rounds: int
    inner_rounds: int
    batch_rounds: int
    ipa_rounds: int
    ipa_dimension: int
    ck_v_generators: int
    ck_s_generators: int

    @classmethod
    def _from_json(cls, value, engine, limit):
        _keys(value, cls.__dataclass_fields__, 'curve dimension')
        if type(value['engine']) is not str or value['engine'] != engine:
            raise ValueError('dimension engine role mismatch')
        for name in set(cls.__dataclass_fields__) - {'engine'}:
            _integer(value[name], 1 if name not in ('outer_rounds', 'ipa_rounds', 'batch_rounds')
                     else 0, limit, name)
        nc, nv = value['num_cons'], value['num_vars']
        if nc & (nc-1) or nv & (nv-1) or value['num_io'] != 2 or nv < 8:
            raise ValueError('unsupported circuit dimensions')
        mc, mv = nc.bit_length()-1, nv.bit_length()-1
        m = max(mc, mv)
        expected = {'outer_rounds': mc, 'inner_rounds': mv+1,
                    'batch_rounds': m, 'ipa_rounds': m,
                    'ipa_dimension': max(nc, nv)}
        if m >= 32 or any(value[k] != v for k, v in expected.items()):
            raise ValueError('inconsistent derived dimensions')
        if value['ck_v_generators'] < value['ipa_dimension'] or value['ck_s_generators'] < 1:
            raise ValueError('insufficient authenticated generator capacity')
        return cls(**value)


@dataclass(frozen=True, init=False)
class VerifierDimensions:
    """Caller-authenticated dimension profile; never read from proof bytes."""
    primary: CurveDimensions
    secondary: CurveDimensions
    descriptor_sha256: bytes
    _descriptor_json: bytes

    def __init__(self, *args, **kwargs):
        raise TypeError('use VerifierDimensions.from_json with an independent pin')

    @classmethod
    def from_json(cls, data, expected, *, expected_descriptor_sha256):
        """Validate a descriptor against a separately authenticated digest/policy.

        The caller must obtain both pins independently of the untrusted proof
        and descriptor transport. This routine cannot authenticate its own pins.
        """
        if type(expected) is not ExpectedBundle:
            raise ValueError('verifier-owned ExpectedBundle required')
        if type(expected_descriptor_sha256) is not bytes or len(expected_descriptor_sha256) != 32:
            raise ValueError('independent descriptor SHA256 pin required')
        keys = {'schema', 'nova_version', 'nova_crate_sha256', 'header_revision',
                'network', 'k', 'verifier_key_sha256', 'outer_arity',
                'max_ipa_dimension', 'primary', 'secondary'}
        _keys(data, keys, 'dimension descriptor')
        identities = {'schema': SCHEMA, 'nova_version': '0.76.0',
                      'nova_crate_sha256': NOVA_CRATE_SHA256,
                      'header_revision': HEADER_REVISION, 'network': expected.network,
                      'k': expected.k, 'verifier_key_sha256': expected.verifier_key_sha256.hex(),
                      'outer_arity': 17}
        if any(type(data[k]) is not type(v) or data[k] != v for k, v in identities.items()):
            raise ValueError('dimension descriptor identity mismatch')
        limit = _integer(data['max_ipa_dimension'], 8, MAX_IPA_DIMENSION, 'IPA resource ceiling')
        if limit & (limit-1):
            raise ValueError('IPA resource ceiling must be a power of two')
        primary = CurveDimensions._from_json(data['primary'], 'pallas', limit)
        secondary = CurveDimensions._from_json(data['secondary'], 'vesta', limit)
        # Validate the exact shallow typed schema before canonical serialization;
        # untrusted nested containers must not drive recursive JSON dumping.
        encoded = _canonical_json(data)
        digest = sha256(encoded).digest()
        if not compare_digest(digest, expected_descriptor_sha256):
            raise ValueError('dimension descriptor digest mismatch')
        result = object.__new__(cls)
        for name, value in (('primary', primary), ('secondary', secondary),
                            ('descriptor_sha256', digest), ('_descriptor_json', encoded)):
            object.__setattr__(result, name, value)
        return result

    def json(self):
        return json.loads(self._descriptor_json)


def load_dimensions_json(raw, expected, *, expected_descriptor_sha256):
    """Bounded UTF8 transport with duplicate-key rejection before hashing."""
    if type(raw) is not bytes or not 1 <= len(raw) <= MAX_DESCRIPTOR_BYTES:
        raise ValueError('dimension descriptor JSON byte budget/type')
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('duplicate dimension descriptor JSON field')
            result[key] = value
        return result
    def constant(_):
        raise ValueError('non-JSON constant')
    try:
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=pairs,
                           parse_constant=constant)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError('invalid dimension descriptor JSON') from error
    return VerifierDimensions.from_json(value, expected,
                                        expected_descriptor_sha256=expected_descriptor_sha256)


@dataclass(frozen=True)
class Span:
    path: str
    kind: str
    start: int
    size: int
    engine: str | None


@dataclass(frozen=True, init=False)
class DecodedProof:
    _value_json: str
    spans: tuple[Span, ...]
    dimensions: VerifierDimensions
    proof_sha256: bytes
    proof_bytes: int

    def __init__(self, *args, **kwargs):
        raise TypeError('use decode_proof to construct an admitted object')

    @property
    def value(self):
        # Expose a copy so post-admission edits cannot change an admitted object.
        return json.loads(self._value_json)

    def summary(self):
        return {'proof_bytes': self.proof_bytes, 'proof_sha256': self.proof_sha256.hex(),
                'descriptor_sha256': self.dimensions.descriptor_sha256.hex(),
                'proof_verified': False, 'bitvm2_script_verified': False}


@dataclass(frozen=True)
class _Atom:
    kind: str
    engine: str
    bound: int | None = None


@dataclass(frozen=True)
class _Vector:
    item: object
    minimum: int
    maximum: int


@dataclass(frozen=True)
class _Struct:
    fields: tuple


@dataclass(frozen=True)
class _Tuple:
    items: tuple


def _struct(**fields):
    return _Struct(tuple(fields.items()))


def _layout(dimensions):
    def scalar(engine, bound=None):
        return _Atom('scalar', engine, bound)
    def commitment(engine):
        return _struct(comm=_Atom('commitment', engine))
    def relaxed(engine):
        return _struct(comm_W=commitment(engine), comm_E=commitment(engine),
                       X=_Vector(scalar(engine), 2, 2), u=scalar(engine))
    def ordinary(engine):
        return _struct(comm_W=commitment(engine), X=_Vector(scalar(engine), 2, 2))
    def nifs(engine):
        return _struct(comm_T=commitment(engine))
    def sumcheck(engine, rounds, degree):
        row = _struct(coeffs_except_linear_term=_Vector(scalar(engine), 1, degree))
        return _struct(compressed_polys=_Vector(row, rounds, rounds))
    def spartan(d):
        e = d.engine
        return _struct(sc_proof_outer=sumcheck(e, d.outer_rounds, 3),
            claims_outer=_Tuple((scalar(e),)*3), eval_E=scalar(e),
            sc_proof_inner=sumcheck(e, d.inner_rounds, 2), eval_W=scalar(e),
            sc_proof_batch=sumcheck(e, d.batch_rounds, 2),
            evals_batch=_Vector(scalar(e), 2, 2),
            eval_arg=_struct(L_vec=_Vector(commitment(e), d.ipa_rounds, d.ipa_rounds),
                             R_vec=_Vector(commitment(e), d.ipa_rounds, d.ipa_rounds),
                             a_hat=scalar(e)))
    return _struct(r_U_secondary=relaxed('vesta'), ri_secondary=scalar('vesta'),
        l_u_secondary=ordinary('vesta'), nifs_Uf_secondary=nifs('vesta'),
        l_ur_secondary=relaxed('vesta'), nifs_Un_secondary=nifs('vesta'),
        r_U_primary=relaxed('pallas'), ri_primary=scalar('pallas'),
        l_ur_primary=relaxed('pallas'), nifs_Un_primary=nifs('pallas'),
        wit_blind_r_Wn_primary=scalar('pallas'), err_blind_r_Wn_primary=scalar('pallas'),
        wit_blind_r_Wn_secondary=scalar('vesta'), err_blind_r_Wn_secondary=scalar('vesta'),
        snark_primary=spartan(dimensions.primary), snark_secondary=spartan(dimensions.secondary),
        zn=_Vector(tuple(scalar('pallas', 1 << b) for b in HEADER_WIDTHS), 17, 17), _p=None)


def _min_size(node):
    if isinstance(node, _Atom):
        return 32
    if isinstance(node, _Struct):
        return sum(_min_size(n) for _, n in node.fields)
    if isinstance(node, _Tuple):
        return sum(_min_size(n) for n in node.items)
    if isinstance(node, _Vector):
        return 8 + (sum(_min_size(n) for n in node.item) if type(node.item) is tuple
                    else node.minimum * _min_size(node.item))
    if node is None:
        return 0
    raise ValueError('unsupported proof layout')


def decode_point(raw, engine):
    """Canonical halo2curves0.9 Pasta compressed point, with identity support."""
    if (type(raw) is not bytes or len(raw) != 32 or type(engine) is not str
            or engine not in BASE_MODULI):
        raise ValueError('canonical 32-byte Pasta point required')
    return _decode_point_cached(raw, engine)


@lru_cache(maxsize=2048)
def _decode_point_cached(raw, engine):
    value = int.from_bytes(raw, 'little')
    sign, x = value >> 255, value & ((1 << 255)-1)
    p = BASE_MODULI[engine]
    if x == 0:
        if sign:
            raise ValueError('noncanonical identity sign alias')
        return None
    if x >= p:
        raise ValueError('noncanonical point coordinate')
    y = _sqrt((x*x*x+5) % p, p)
    if y is None:
        raise ValueError('point is not on declared curve')
    if (y & 1) != sign:
        y = p-y
    if y >= p or (y & 1) != sign:
        raise ValueError('noncanonical point sign')
    return x, y


class _Reader:
    def __init__(self, raw, build):
        self.raw, self.pos, self.build, self.spans = raw, 0, build, []

    def take(self, count, path):
        start = self.pos
        if count > len(self.raw)-start:
            raise ValueError(f'truncated proof at {path}')
        self.pos += count
        return start

    def read(self, node, path=''):
        if isinstance(node, _Atom):
            start = self.take(32, path)
            if not self.build:
                return None
            raw = self.raw[start:start+32]
            if node.kind == 'scalar':
                value = int.from_bytes(raw, 'little')
                if value >= SCALAR_MODULI[node.engine] or (node.bound is not None and value >= node.bound):
                    raise ValueError(f'noncanonical or out-of-width scalar at {path}')
            else:
                decode_point(raw, node.engine)
            self.spans.append(Span(path, node.kind, start, 32, node.engine))
            return raw.hex()
        if isinstance(node, _Struct):
            if self.build:
                return {name: self.read(child, f'{path}.{name}' if path else name)
                        for name, child in node.fields}
            for name, child in node.fields:
                self.read(child, f'{path}.{name}' if path else name)
            return None
        if isinstance(node, _Tuple):
            result = [self.read(child, f'{path}[{i}]') for i, child in enumerate(node.items)]
            return result if self.build else None
        if isinstance(node, _Vector):
            start = self.take(8, path)
            count = int.from_bytes(self.raw[start:start+8], 'little')
            if not node.minimum <= count <= node.maximum:
                raise ValueError(f'verifier-owned vector length mismatch at {path}')
            minimum = (sum(_min_size(child) for child in node.item) if type(node.item) is tuple
                       else count * _min_size(node.item))
            if minimum > len(self.raw)-self.pos:
                raise ValueError(f'truncated vector at {path}')
            if self.build:
                self.spans.append(Span(path, 'length', start, 8, None))
            result = [] if self.build else None
            for i in range(count):
                child = node.item[i] if type(node.item) is tuple else node.item
                value = self.read(child, f'{path}[{i}]')
                if self.build:
                    result.append(value)
            return result
        if node is None:
            return None
        raise ValueError('unsupported proof layout')


def decode_proof(raw, dimensions):
    """Admit bounded canonical bytes and shapes, without verifying proof validity."""
    if type(dimensions) is not VerifierDimensions:
        raise ValueError('authenticated verifier dimensions required')
    if type(raw) is not bytes or not 1 <= len(raw) <= MAX_PROOF_BYTES:
        raise ValueError('proof byte budget/type')
    node = _layout(dimensions)
    if len(raw) < _min_size(node):
        raise ValueError('proof shorter than minimum declared shape')
    # Shape-only pass rejects malformed prefixes/truncations before curve work.
    scan = _Reader(raw, False)
    scan.read(node)
    if scan.pos != len(raw):
        raise ValueError('surplus proof bytes')
    reader = _Reader(raw, True)
    value = reader.read(node)
    if reader.pos != len(raw):
        raise ValueError('surplus proof bytes')
    result = object.__new__(DecodedProof)
    for name, item in (('_value_json', json.dumps(value, separators=(',', ':'))),
                       ('spans', tuple(reader.spans)), ('dimensions', dimensions),
                       ('proof_sha256', sha256(raw).digest()), ('proof_bytes', len(raw))):
        object.__setattr__(result, name, item)
    return result


def encode_proof(decoded):
    """Serialize an admitted object in source field order, preserving row widths."""
    if type(decoded) is not DecodedProof:
        raise ValueError('admitted DecodedProof required')
    output = bytearray()
    def write(node, value):
        if isinstance(node, _Atom):
            output.extend(bytes.fromhex(value))
        elif isinstance(node, _Struct):
            for name, child in node.fields:
                write(child, value[name])
        elif isinstance(node, _Tuple):
            for child, item in zip(node.items, value, strict=True):
                write(child, item)
        elif isinstance(node, _Vector):
            output.extend(len(value).to_bytes(8, 'little'))
            for i, item in enumerate(value):
                write(node.item[i] if type(node.item) is tuple else node.item, item)
        elif node is not None:
            raise ValueError('unsupported proof layout')
    write(_layout(decoded.dimensions), decoded.value)
    return bytes(output)
