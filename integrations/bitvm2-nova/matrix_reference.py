"""Bounded, independently authenticated Nova 0.76 CSR matrix evaluations.

The profile describes lengths only. The separate collection pin authenticates
the actual six matrix payloads. Each segment is hashed over the same immutable
read buffers used for arithmetic; a preliminary whole-file hash alone never
authenticates a later read. No matrix payload is loaded wholesale into memory.

Source: nova-snark 0.76.0 r1cs/sparse.rs (serde field order data, indices,
indptr, cols), spartan/snark.rs and spartan/polys/multilinear.rs. Fixed-LE
bincode 1.3 legacy, 64-bit usize. This is field arithmetic, not proof or Script
verification. Actual payloads and large equality tables belong on hosted CI.
"""
from dataclasses import dataclass
from hashlib import sha256
from hmac import compare_digest
import json
from pathlib import Path

from nht4 import ExpectedBundle, HEADER_REVISION
from proof_codec import NOVA_CRATE_SHA256, SCALAR_MODULI, VerifierDimensions

PROFILE_SCHEMA = 'bitvm2-nova-matrix-profile/v1'
COLLECTION_SCHEMA = 'bitvm2-nova-matrix-collection/v1'
ENCODING = 'bincode-1.3.3-legacy-fixed-little-endian'
MAX_JSON_BYTES = 1 << 16
MAX_FILE_BYTES = 64 << 20
MAX_COLLECTION_BYTES = 160 << 20
DEFAULT_TABLE_BYTES = 1 << 20
MAX_TABLE_BYTES = 128 << 20
READ_BYTES = 1 << 16
ROLES = (('primary', 'pallas'), ('secondary', 'vesta'))
MATRICES = ('A', 'B', 'C')
SEGMENTS = ('data', 'indices', 'indptr', 'cols')


def _keys(value, names, description):
    if (type(value) is not dict or len(value) != len(names)
            or set(value) != set(names)):
        raise ValueError(f'unexpected {description} fields')


def _integer(value, low, high, description):
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f'invalid {description}')
    return value


def _digest(value, description):
    if (type(value) is not str or len(value) != 64
            or any(c not in '0123456789abcdef' for c in value)):
        raise ValueError(f'canonical lowercase {description} SHA256 required')
    return bytes.fromhex(value)


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def _pin(value, expected_pin, description):
    if type(expected_pin) is not bytes or len(expected_pin) != 32:
        raise ValueError(f'independent {description} SHA256 pin required')
    encoded = _canonical(value)
    if len(encoded) > MAX_JSON_BYTES:
        raise ValueError(f'{description} JSON byte budget')
    digest = sha256(encoded).digest()
    if not compare_digest(digest, expected_pin):
        raise ValueError(f'{description} digest mismatch')
    return encoded, digest


def _transport(raw):
    if type(raw) is not bytes or not 1 <= len(raw) <= MAX_JSON_BYTES:
        raise ValueError('matrix metadata JSON byte budget/type')
    # Bound nesting before json.loads allocates containers. Schema validation
    # then bounds every list and object before canonical serialization.
    depth, in_string, escape = 0, False, False
    for byte in raw:
        if in_string:
            if escape:
                escape = False
            elif byte == 92:
                escape = True
            elif byte == 34:
                in_string = False
        elif byte == 34:
            in_string = True
        elif byte in (91, 123):
            depth += 1
            if depth > 12:
                raise ValueError('matrix metadata nesting budget')
        elif byte in (93, 125):
            depth -= 1
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('duplicate matrix metadata JSON field')
            result[key] = value
        return result
    def invalid(_):
        raise ValueError('non-JSON constant')
    try:
        return json.loads(raw.decode('ascii'), object_pairs_hook=pairs,
                          parse_constant=invalid)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError('invalid matrix metadata JSON') from error


def _identity(expected, dimensions):
    if type(expected) is not ExpectedBundle or type(dimensions) is not VerifierDimensions:
        raise ValueError('caller-owned expected policy and dimensions required')
    descriptor = dimensions.json()
    if (descriptor['network'] != expected.network or descriptor['k'] != expected.k
            or descriptor['verifier_key_sha256'] != expected.verifier_key_sha256.hex()):
        raise ValueError('matrix dimension/policy identity mismatch')
    return {'nova_version': '0.76.0', 'nova_crate_sha256': NOVA_CRATE_SHA256,
        'header_revision': HEADER_REVISION, 'network': expected.network,
        'k': expected.k, 'verifier_key_sha256': expected.verifier_key_sha256.hex(),
        'verifier_dimensions_sha256': dimensions.descriptor_sha256.hex()}


def _matches(data, expected):
    if any(type(data[k]) is not type(value) or data[k] != value
           for k, value in expected.items()):
        raise ValueError('matrix metadata identity/shape mismatch')


def _make(cls, **values):
    result = object.__new__(cls)
    for key, value in values.items():
        object.__setattr__(result, key, value)
    return result


class _FactoryOnly:
    def __init__(self, *args, **kwargs):
        raise TypeError('use an independently pinned matrix metadata factory')


@dataclass(frozen=True, init=False)
class MatrixShape(_FactoryOnly):
    data_len: int
    indices_len: int
    indptr_len: int
    cols: int
    csr_rows: int

    @classmethod
    def _from_json(cls, data, rows, cols):
        _keys(data, cls.__dataclass_fields__, 'CSR shape')
        for name in ('data_len', 'indices_len'):
            _integer(data[name], 0, 1 << 49, name)
        _integer(data['indptr_len'], 1, rows+1, 'indptr length')
        _integer(data['csr_rows'], 0, rows, 'stored CSR rows')
        _integer(data['cols'], 0, cols, 'stored CSR columns')
        if (data['csr_rows']+1 != data['indptr_len']
                or data['data_len'] != data['indices_len']
                or data['data_len'] > data['csr_rows']*data['cols']):
            raise ValueError('inconsistent CSR length metadata')
        return _make(cls, **data)


@dataclass(frozen=True, init=False)
class MatrixRole(_FactoryOnly):
    role: str
    engine: str
    num_cons: int
    num_vars: int
    num_io: int
    evaluation_rows: int
    evaluation_cols: int
    matrices: tuple[MatrixShape, ...]

    def matrix(self, name):
        if type(name) is not str or name not in MATRICES:
            raise ValueError('matrix name must be A, B or C')
        return self.matrices[MATRICES.index(name)]


@dataclass(frozen=True, init=False)
class MatrixProfile(_FactoryOnly):
    dimensions: VerifierDimensions
    profile_sha256: bytes
    roles: tuple[MatrixRole, ...]
    _json: bytes

    @classmethod
    def from_json(cls, data, expected, dimensions, *, expected_profile_sha256):
        identities = _identity(expected, dimensions)
        identities.update(schema=PROFILE_SCHEMA, scope='CSR lengths and declared columns only')
        _keys(data, set(identities) | {'primary', 'secondary'}, 'matrix profile')
        _matches(data, identities)
        roles = []
        for role, engine in ROLES:
            value, dim = data[role], getattr(dimensions, role)
            _keys(value, {'engine', 'field_role', 'num_cons', 'num_vars', 'num_io',
                'evaluation_rows', 'evaluation_cols', 'matrices'}, 'matrix role')
            _matches(value, {'engine': engine, 'field_role': engine+'_scalar',
                'num_cons': dim.num_cons, 'num_vars': dim.num_vars, 'num_io': dim.num_io,
                'evaluation_rows': dim.num_cons, 'evaluation_cols': 2*dim.num_vars})
            _keys(value['matrices'], MATRICES, 'matrix catalogue')
            shapes = tuple(MatrixShape._from_json(value['matrices'][name],
                dim.num_cons, 2*dim.num_vars) for name in MATRICES)
            roles.append(_make(MatrixRole, role=role, engine=engine,
                num_cons=dim.num_cons, num_vars=dim.num_vars, num_io=dim.num_io,
                evaluation_rows=dim.num_cons, evaluation_cols=2*dim.num_vars,
                matrices=shapes))
        encoded, digest = _pin(data, expected_profile_sha256, 'matrix profile')
        return _make(cls, dimensions=dimensions, profile_sha256=digest,
                     roles=tuple(roles), _json=encoded)

    def role(self, role):
        if type(role) is not str or role not in ('primary', 'secondary'):
            raise ValueError('matrix role must be primary or secondary')
        return self.roles[0 if role == 'primary' else 1]

    def json(self):
        return json.loads(self._json)


def load_profile_json(raw, expected, dimensions, *, expected_profile_sha256):
    return MatrixProfile.from_json(_transport(raw), expected, dimensions,
                                    expected_profile_sha256=expected_profile_sha256)


@dataclass(frozen=True, init=False)
class MatrixSegment(_FactoryOnly):
    name: str
    offset: int
    bytes: int
    sha256: bytes


@dataclass(frozen=True, init=False)
class MatrixFile(_FactoryOnly):
    role: str
    engine: str
    matrix: str
    filename: str
    shape: MatrixShape
    bytes: int
    sha256: bytes
    segments: tuple[MatrixSegment, ...]


@dataclass(frozen=True, init=False)
class MatrixCollection(_FactoryOnly):
    profile: MatrixProfile
    collection_sha256: bytes
    files: tuple[MatrixFile, ...]
    total_bytes: int
    _json: bytes

    @classmethod
    def from_json(cls, data, expected, profile, *, expected_collection_sha256):
        if type(profile) is not MatrixProfile:
            raise ValueError('independently authenticated MatrixProfile required')
        identities = _identity(expected, profile.dimensions)
        identities.update(schema=COLLECTION_SCHEMA, encoding=ENCODING,
                          matrix_profile_sha256=profile.profile_sha256.hex())
        _keys(data, set(identities) | {'total_bytes', 'files'}, 'matrix collection')
        _matches(data, identities)
        total = _integer(data['total_bytes'], 0, MAX_COLLECTION_BYTES, 'collection bytes')
        if type(data['files']) is not list or len(data['files']) != 6:
            raise ValueError('six ordered matrix files required')
        files = []
        for index, value in enumerate(data['files']):
            role, engine = ROLES[index//3]
            name = MATRICES[index % 3]
            metadata, shape = profile.role(role), profile.role(role).matrix(name)
            _keys(value, {'role', 'engine', 'field_role', 'matrix', 'filename',
                'num_cons', 'num_vars', 'num_io', 'data_len', 'indices_len',
                'indptr_len', 'cols', 'csr_rows', 'bytes', 'sha256', 'segments'}, 'matrix file')
            _matches(value, {'role': role, 'engine': engine, 'field_role': engine+'_scalar',
                'matrix': name, 'filename': f'{role}-{name}.csr.bin',
                'num_cons': metadata.num_cons, 'num_vars': metadata.num_vars,
                'num_io': metadata.num_io, **{k: getattr(shape, k)
                    for k in MatrixShape.__dataclass_fields__}})
            lengths = (8+32*shape.data_len, 8+8*shape.indices_len,
                       8+8*shape.indptr_len, 8)
            size = _integer(value['bytes'], 32, MAX_FILE_BYTES, 'matrix file bytes')
            if size != sum(lengths):
                raise ValueError('matrix byte count disagrees with authenticated shape')
            if type(value['segments']) is not list or len(value['segments']) != 4:
                raise ValueError('four ordered matrix segments required')
            offset, segments = 0, []
            for segment, segment_name, length in zip(value['segments'], SEGMENTS, lengths, strict=True):
                _keys(segment, {'name', 'offset', 'bytes', 'sha256'}, 'matrix segment')
                _matches(segment, {'name': segment_name, 'offset': offset, 'bytes': length})
                segments.append(_make(MatrixSegment, name=segment_name, offset=offset,
                    bytes=length, sha256=_digest(segment['sha256'], 'segment')))
                offset += length
            files.append(_make(MatrixFile, role=role, engine=engine, matrix=name,
                filename=value['filename'], shape=shape, bytes=size,
                sha256=_digest(value['sha256'], 'matrix file'), segments=tuple(segments)))
        if sum(item.bytes for item in files) != total:
            raise ValueError('matrix collection total bytes mismatch')
        encoded, digest = _pin(data, expected_collection_sha256, 'matrix collection')
        return _make(cls, profile=profile, collection_sha256=digest,
                     files=tuple(files), total_bytes=total, _json=encoded)

    def file(self, role, matrix):
        self.profile.role(role).matrix(matrix)  # Validate public argument types.
        return self.files[(0 if role == 'primary' else 3)+MATRICES.index(matrix)]

    def json(self):
        return json.loads(self._json)


def load_collection_json(raw, expected, profile, *, expected_collection_sha256):
    return MatrixCollection.from_json(_transport(raw), expected, profile,
                                      expected_collection_sha256=expected_collection_sha256)


def _point(values, count, modulus):
    if type(values) not in (list, tuple) or len(values) != count:
        raise ValueError('matrix evaluation point has wrong full dimension')
    for value in values:
        if type(value) is not int or not 0 <= value < modulus:
            raise ValueError('canonical matrix evaluation scalar required')
    return tuple(values)


class _PackedEquality:
    """32-byte canonical slots, avoiding a Python-int object per table entry."""
    def __init__(self, point, modulus):
        self.point = point
        self.values = bytearray(32*(1 << len(point)))
        self.values[:32] = (1).to_bytes(32, 'little')
        size = 1
        for r in point:
            # r[0] is the MSB: each old prefix splits into suffix 0 and 1.
            for index in range(size-1, -1, -1):
                old = self[index]
                self.values[64*index:64*index+32] = (old*(1-r) % modulus).to_bytes(32, 'little')
                self.values[64*index+32:64*index+64] = (old*r % modulus).to_bytes(32, 'little')
            size *= 2

    def __getitem__(self, index):
        return int.from_bytes(self.values[32*index:32*index+32], 'little')


def _tables(metadata, r_x, r_y, max_table_bytes):
    p = SCALAR_MODULI[metadata.engine]
    x = _point(r_x, metadata.num_cons.bit_length()-1, p)
    y = _point(r_y, metadata.num_vars.bit_length(), p)
    _integer(max_table_bytes, 32, MAX_TABLE_BYTES, 'equality table byte budget')
    size = 32*(metadata.evaluation_rows+metadata.evaluation_cols)
    if size > max_table_bytes:
        raise ValueError('equality tables exceed explicit memory budget; actual matrices are hosted-only')
    return _PackedEquality(x, p), _PackedEquality(y, p)


class _SegmentReader:
    """Hash each immutable buffer once and consume it without rereading."""
    def __init__(self, stream, descriptor):
        self.stream, self.descriptor = stream, descriptor
        self.position = self.consumed = 0
        self.buffer = b''
        self.hash = sha256()

    def read(self, count):
        if count < 0 or self.consumed+count > self.descriptor.bytes:
            raise ValueError('matrix segment read exceeds authenticated length')
        output = bytearray()
        while len(output) < count:
            if self.position == len(self.buffer):
                left = self.descriptor.bytes-self.consumed
                self.stream.seek(self.descriptor.offset+self.consumed)
                raw = self.stream.read(min(READ_BYTES, left))
                if type(raw) is not bytes or not raw or len(raw) > min(READ_BYTES, left):
                    raise ValueError('truncated or malformed matrix segment read')
                self.buffer, self.position = raw, 0
                self.hash.update(raw)
            take = min(count-len(output), len(self.buffer)-self.position)
            output.extend(self.buffer[self.position:self.position+take])
            self.position += take
            self.consumed += take
        return bytes(output)

    def u64(self):
        return int.from_bytes(self.read(8), 'little')

    def finish(self):
        if self.consumed != self.descriptor.bytes or self.position != len(self.buffer):
            raise ValueError('matrix segment was not consumed exactly')
        if not compare_digest(self.hash.digest(), self.descriptor.sha256):
            raise ValueError('arithmetic matrix segment digest mismatch')


def _whole_file(stream, descriptor):
    stream.seek(0)
    digest, count = sha256(), 0
    while count < descriptor.bytes:
        raw = stream.read(min(READ_BYTES, descriptor.bytes-count))
        if (type(raw) is not bytes or not raw
                or len(raw) > min(READ_BYTES, descriptor.bytes-count)):
            raise ValueError('truncated or malformed matrix file read')
        digest.update(raw)
        count += len(raw)
    if stream.read(1) != b'':
        raise ValueError('matrix file has surplus bytes')
    if not compare_digest(digest.digest(), descriptor.sha256):
        raise ValueError('matrix file digest mismatch')


@dataclass(frozen=True, init=False)
class MatrixEvaluation(_FactoryOnly):
    role: str
    engine: str
    matrix: str
    r_x: tuple[int, ...]
    r_y: tuple[int, ...]
    value: int
    entries_checked: int
    bytes_checked: int
    collection_sha256: bytes
    arithmetic_segments_authenticated: bool


def _evaluate_stream(stream, descriptor, tables, collection):
    # Whole-file identity and EOF are useful checks, but the later segment
    # hashes authenticate the exact bytes actually used in field arithmetic.
    _whole_file(stream, descriptor)
    data, indices, pointers, columns = tuple(_SegmentReader(stream, item)
                                            for item in descriptor.segments)
    shape, p = descriptor.shape, SCALAR_MODULI[descriptor.engine]
    if (data.u64() != shape.data_len or indices.u64() != shape.indices_len
            or pointers.u64() != shape.indptr_len or columns.u64() != shape.cols):
        raise ValueError('matrix length prefix/column footer mismatch')
    if pointers.u64() != 0:
        raise ValueError('CSR first row pointer must be zero')
    row_weights, col_weights = tables
    position, value = 0, 0
    for row in range(shape.csr_rows):
        end = pointers.u64()
        if not position <= end <= shape.data_len:
            raise ValueError('CSR pointers are not monotone within entry count')
        subtotal = 0
        for _ in range(position, end):
            coefficient = int.from_bytes(data.read(32), 'little')
            column = indices.u64()
            if coefficient >= p:
                raise ValueError('noncanonical CSR coefficient')
            if column >= shape.cols:
                raise ValueError('CSR column index outside stored column count')
            # The actual frontend may place input columns before auxiliary
            # columns. SparseMatrix serialization and polynomial evaluation
            # preserve their order; arbitrary order and duplicates sum normally.
            subtotal = (subtotal+coefficient*col_weights[column]) % p
        value = (value+row_weights[row]*subtotal) % p
        position = end
    if position != shape.data_len:
        raise ValueError('CSR final row pointer does not equal entry count')
    for reader in (data, indices, pointers, columns):
        reader.finish()
    stream.seek(descriptor.bytes)
    if stream.read(1) != b'':
        raise ValueError('matrix file acquired surplus bytes during evaluation')
    return _make(MatrixEvaluation, role=descriptor.role, engine=descriptor.engine,
        matrix=descriptor.matrix, r_x=row_weights.point, r_y=col_weights.point,
        value=value, entries_checked=position,
        bytes_checked=descriptor.bytes, collection_sha256=collection.collection_sha256,
        arithmetic_segments_authenticated=True)


def _open(directory, descriptor, opener):
    if opener is not None:
        if not callable(opener):
            raise ValueError('matrix opener must be callable')
        return opener(descriptor.filename)
    if type(directory) not in (str, Path) and not isinstance(directory, Path):
        raise ValueError('matrix directory path required')
    # Filenames are exact authenticated literals, never arbitrary JSON paths.
    return (Path(directory)/descriptor.filename).open('rb')


def evaluate_matrix(collection, role, matrix, r_x, r_y, *, directory=None,
                    max_table_bytes=DEFAULT_TABLE_BYTES, opener=None):
    """Evaluate one authenticated matrix; default memory budget is toy-only.

    r_x has log2(Nc) coordinates and r_y has log2(Nv)+1. Both use MSB-first
    equality weights. The stored CSR can omit trailing logical zero rows and
    columns. A returned scalar is withheld until all arithmetic segments pass.
    An opener is a diagnostic/test seam returning a seekable binary context
    manager. Production callers should supply a local hosted export directory.
    """
    if type(collection) is not MatrixCollection:
        raise ValueError('independently authenticated MatrixCollection required')
    descriptor = collection.file(role, matrix)
    tables = _tables(collection.profile.role(role), r_x, r_y, max_table_bytes)
    with _open(directory, descriptor, opener) as stream:
        return _evaluate_stream(stream, descriptor, tables, collection)


def evaluate_role(collection, role, r_x, r_y, *, directory=None,
                  max_table_bytes=DEFAULT_TABLE_BYTES, opener=None):
    """Evaluate A/B/C with a single shared pair of bounded equality tables."""
    if type(collection) is not MatrixCollection:
        raise ValueError('independently authenticated MatrixCollection required')
    tables = _tables(collection.profile.role(role), r_x, r_y, max_table_bytes)
    results = []
    for matrix in MATRICES:
        descriptor = collection.file(role, matrix)
        with _open(directory, descriptor, opener) as stream:
            results.append(_evaluate_stream(stream, descriptor, tables, collection))
    return tuple(results)


def check_inner_terminal(evaluations, rho, eval_z, claim):
    """Compare claim == eval_Z * (A + rho*B + rho^2*C), including eval_Z=0.

    Results must belong to one role and the same independently pinned
    collection. This check does not establish IPA openings or full proof
    validity, and must be bound to the reconstructed transcript by its caller.
    """
    if (type(evaluations) not in (tuple, list) or len(evaluations) != 3
            or any(type(item) is not MatrixEvaluation for item in evaluations)):
        raise ValueError('authenticated A/B/C evaluations required')
    first = evaluations[0]
    for index, item in enumerate(evaluations):
        if (item.matrix != MATRICES[index] or item.role != first.role
                or item.engine != first.engine or item.collection_sha256 != first.collection_sha256
                or item.r_x != first.r_x or item.r_y != first.r_y
                or item.arithmetic_segments_authenticated is not True):
            raise ValueError('matrix terminal role/collection mismatch')
    p = SCALAR_MODULI[first.engine]
    for scalar in (rho, eval_z, claim):
        if type(scalar) is not int or not 0 <= scalar < p:
            raise ValueError('canonical matrix terminal scalar required')
    combination = (evaluations[0].value+rho*evaluations[1].value
                   +rho*rho*evaluations[2].value) % p
    if claim != eval_z*combination % p:
        raise ValueError('inner sumcheck matrix terminal mismatch')
    return combination
