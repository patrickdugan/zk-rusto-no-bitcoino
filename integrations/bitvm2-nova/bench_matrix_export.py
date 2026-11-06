"""Hosted-only integrity conformance for native CSR payload exports.

This checks that six files match a native manifest and independently pinned
length/profile metadata. The collection digest is NOT yet independently pinned.
Neither this command nor a self-printed digest verifies matrix polynomials,
proof validity or Bitcoin Script. Full export hashing is gated to hosted CI;
private helper tests use tiny, explicitly synthetic files only.
"""
import argparse
from dataclasses import dataclass
from hashlib import sha256
import json
import math
import os
from pathlib import Path
import stat
import time

from bench_compact import peak_rss
from nht4 import load_expected_json
from proof_codec import VerifierDimensions, load_dimensions_json

FIXTURES = Path(__file__).resolve().parent/'fixtures'
PROFILE_PIN = '7a69cdd0c39601c988c39719bbfc67386762d516eea8a3fcfc0e23c7938ac921'
DIMENSION_PIN = 'de6333df2e41b5f5bae1c103fab862f8d6022fd54abeb80ba61920bc9f360edc'
VK_PIN = '1ae88a7bcfdc5f14d030d0baafa06ec17fe904a5ebed42f9bd6fa6105fdc8c24'
CRATE_PIN = 'c9bb3809a6c70057ea722c1c4fe5097cf29a3479d0b4671f3cddb1d81043bb31'
REVISION = 'de607d3db17d400dd6c2923d357f1d4a7bf233c7'
FILE_CAP, TOTAL_CAP = 64 << 20, 160 << 20
REPORT_CAP, COLLECTION_CAP = 4 << 20, 32 << 10
CHUNK_BYTES = 1 << 20
EXPECTED_TOTAL_BYTES, EXPECTED_MAX_FILE_BYTES = 119674848, 50321224
U64_MAX = (1 << 64)-1
ROLES = ('primary', 'secondary')
ENGINES = ('pallas', 'vesta')
FIELDS = ('pallas_scalar', 'vesta_scalar')
MATRICES = ('A', 'B', 'C')
FILENAMES = tuple(f'{role}-{matrix}.csr.bin' for role in ROLES for matrix in MATRICES)
IDENTITY_KEYS = {'nova_version', 'nova_crate_sha256', 'header_revision', 'network',
                 'k', 'verifier_key_sha256', 'verifier_dimensions_sha256'}


def _keys(value, expected, name):
    if type(value) is not dict or set(value) != set(expected):
        raise ValueError(f'unexpected {name} fields')


def _uint(value, name, maximum=U64_MAX, minimum=0):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f'invalid unsigned {name}')
    return value


def _digest(value, name):
    if (type(value) is not str or len(value) != 64
            or any(c not in '0123456789abcdef' for c in value)):
        raise ValueError(f'invalid {name} digest')
    return value


def _same(actual, expected, name):
    if type(actual) is not type(expected) or actual != expected:
        raise ValueError(f'{name} mismatch')


def _strict_json(raw, cap):
    if type(raw) is not bytes or not 1 <= len(raw) <= cap:
        raise ValueError('JSON byte budget/type')
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError('duplicate JSON field')
            value[key] = item
        return value
    def integer(text):
        if len(text.lstrip('-')) > 20:
            raise ValueError('JSON integer digit budget')
        value = int(text)
        if not -(1 << 63) <= value <= U64_MAX:
            raise ValueError('JSON integer range')
        return value
    def floating(text):
        value = float(text)
        if not math.isfinite(value):
            raise ValueError('nonfinite JSON number')
        return value
    def constant(_):
        raise ValueError('non-JSON constant')
    try:
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=pairs,
            parse_int=integer, parse_float=floating, parse_constant=constant)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError('invalid JSON transport') from error
    pending, count = [(value, 0)], 0
    while pending:
        item, depth = pending.pop()
        count += 1
        if depth > 32 or count > 100000:
            raise ValueError('JSON depth/node budget')
        if type(item) in (dict, list):
            if len(item) > 100000:
                raise ValueError('JSON collection node budget')
            pending.extend((child, depth+1) for child in (item.values() if type(item) is dict else item))
    return value


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def _no_link(path, directory=False):
    info = path.lstat()
    if (stat.S_ISLNK(info.st_mode)
            or getattr(info, 'st_file_attributes', 0) & getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 0x400)):
        raise ValueError('symlink/reparse paths are forbidden')
    if directory:
        if not stat.S_ISDIR(info.st_mode):
            raise ValueError('expected matrix directory')
    elif not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ValueError('nonregular or aliased file')
    return info


def _directory(path):
    path = Path(path).absolute()
    if '..' in path.parts:
        raise ValueError('directory aliases are forbidden')
    for ancestor in reversed((path,)+tuple(path.parents)):
        _no_link(ancestor, directory=True)
    resolved = path.resolve(strict=True)
    if resolved != path:
        raise ValueError('noncanonical directory alias')
    return resolved


def _open_regular(path):
    before = _no_link(path)
    flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(path, flags)
    try:
        current = os.fstat(fd)
        if (not stat.S_ISREG(current.st_mode) or current.st_nlink != 1
                or (before.st_dev, before.st_ino, before.st_size) !=
                   (current.st_dev, current.st_ino, current.st_size)):
            raise ValueError('file changed during safe open')
        return os.fdopen(fd, 'rb'), current
    except BaseException:
        os.close(fd)
        raise


def _read(path, cap):
    source, info = _open_regular(Path(path))
    with source:
        if info.st_size > cap:
            raise ValueError('input file byte budget')
        raw = source.read(cap+1)
    if len(raw) > cap:
        raise ValueError('input file grew beyond byte budget')
    return raw


def _identity(profile):
    expected = {'nova_version': '0.76.0', 'nova_crate_sha256': CRATE_PIN,
                'header_revision': REVISION, 'network': 'testnet4', 'k': 5,
                'verifier_key_sha256': VK_PIN, 'verifier_dimensions_sha256': DIMENSION_PIN}
    for name, value in expected.items():
        _same(profile.get(name), value, name)
    return expected


@dataclass(frozen=True)
class _Segment:
    name: str
    offset: int
    size: int
    header: bytes


@dataclass(frozen=True)
class _Plan:
    fields: dict
    segments: tuple[_Segment, ...]


def _plans(profile):
    """Private structural helper; authentication is the full CLI's prerequisite."""
    _keys(profile, IDENTITY_KEYS | {'schema', 'scope', 'primary', 'secondary'}, 'matrix profile')
    _same(profile['schema'], 'bitvm2-nova-matrix-profile/v1', 'profile schema')
    _same(profile['scope'], 'CSR lengths and declared columns only', 'profile scope')
    _identity(profile)
    plans = []
    for role, engine, field in zip(ROLES, ENGINES, FIELDS, strict=True):
        curve = profile[role]
        _keys(curve, {'engine', 'field_role', 'num_cons', 'num_vars', 'num_io',
                      'evaluation_rows', 'evaluation_cols', 'matrices'}, 'curve matrix profile')
        _same(curve['engine'], engine, 'matrix curve role')
        _same(curve['field_role'], field, 'matrix scalar role')
        nc = _uint(curve['num_cons'], 'constraint dimension', 1 << 24, 1)
        nv = _uint(curve['num_vars'], 'variable dimension', 1 << 24, 8)
        if nc & (nc-1) or nv & (nv-1):
            raise ValueError('matrix dimensions must be powers of two')
        _same(curve['num_io'], 2, 'matrix IO arity')
        _same(curve['evaluation_rows'], nc, 'matrix evaluation rows')
        _same(curve['evaluation_cols'], 2*nv, 'matrix evaluation columns')
        _keys(curve['matrices'], MATRICES, 'matrix names')
        for matrix in MATRICES:
            csr = curve['matrices'][matrix]
            _keys(csr, {'data_len', 'indices_len', 'indptr_len', 'cols', 'csr_rows'}, 'CSR profile')
            nnz = _uint(csr['data_len'], 'data length')
            _same(csr['indices_len'], nnz, 'index length')
            pointers = _uint(csr['indptr_len'], 'pointer length', nc+1, 1)
            rows = pointers-1
            _same(csr['csr_rows'], rows, 'CSR rows')
            cols = _uint(csr['cols'], 'declared columns', 2*nv)
            if nnz > rows*cols:
                raise ValueError('matrix density metadata bound')
            segments, offset = [], 0
            for name, count, width in (('data', nnz, 32), ('indices', nnz, 8), ('indptr', pointers, 8)):
                size = 8+count*width
                if size > FILE_CAP or offset+size > FILE_CAP:
                    raise ValueError('matrix file exceeds 64MiB cap')
                segments.append(_Segment(name, offset, size, count.to_bytes(8, 'little')))
                offset += size
            segments.append(_Segment('cols', offset, 8, cols.to_bytes(8, 'little')))
            total = offset+8
            if total > FILE_CAP:
                raise ValueError('matrix file exceeds 64MiB cap')
            fields = {'role': role, 'engine': engine, 'field_role': field, 'matrix': matrix,
                'filename': f'{role}-{matrix}.csr.bin', 'num_cons': nc, 'num_vars': nv,
                'num_io': 2, 'data_len': nnz, 'indices_len': nnz, 'indptr_len': pointers,
                'cols': cols, 'csr_rows': rows, 'bytes': total}
            plans.append(_Plan(fields, tuple(segments)))
    if sum(plan.fields['bytes'] for plan in plans) > TOTAL_CAP:
        raise ValueError('matrix total exceeds 160MiB cap')
    return tuple(plans)


def _validate_collection(collection, profile):
    _keys(collection, IDENTITY_KEYS | {'schema', 'matrix_profile_sha256', 'encoding', 'total_bytes', 'files'}, 'matrix collection')
    _identity(collection)
    _same(collection['schema'], 'bitvm2-nova-matrix-collection/v1', 'collection schema')
    _same(collection['encoding'], 'bincode-1.3.3-legacy-fixed-little-endian', 'collection encoding')
    _same(collection['matrix_profile_sha256'], sha256(_canonical(profile)).hexdigest(), 'collection profile digest')
    plans = _plans(profile)
    _same(collection['total_bytes'], sum(plan.fields['bytes'] for plan in plans), 'collection total bytes')
    files = collection['files']
    if type(files) is not list or len(files) != 6:
        raise ValueError('exactly six ordered matrix files required')
    for record, plan in zip(files, plans, strict=True):
        _keys(record, set(plan.fields) | {'sha256', 'segments'}, 'matrix file record')
        for name, expected in plan.fields.items():
            _same(record[name], expected, f'file {name}')
        _digest(record['sha256'], 'whole-file')
        segments = record['segments']
        if type(segments) is not list or len(segments) != 4:
            raise ValueError('exactly four ordered segments required')
        for item, expected in zip(segments, plan.segments, strict=True):
            _keys(item, {'name', 'offset', 'bytes', 'sha256'}, 'segment record')
            for name, value in (('name', expected.name), ('offset', expected.offset), ('bytes', expected.size)):
                _same(item[name], value, f'segment {name}')
            _digest(item['sha256'], 'segment')
    if len(_canonical(collection)) > COLLECTION_CAP:
        raise ValueError('collection JSON byte budget')
    return plans


def _hash_file(path, record, plan):
    path_before = _no_link(path)
    source, before = _open_regular(path)
    whole = sha256()
    observed = []
    with source:
        if before.st_size != plan.fields['bytes']:
            raise ValueError('actual file length mismatch')
        for item, segment in zip(record['segments'], plan.segments, strict=True):
            if source.tell() != segment.offset:
                raise ValueError('actual segment offset mismatch')
            part = sha256()
            header = source.read(8)
            if header != segment.header:
                raise ValueError(f'actual {segment.name} prefix/column value mismatch')
            part.update(header); whole.update(header)
            remaining = segment.size-8
            while remaining:
                chunk = source.read(min(remaining, CHUNK_BYTES))
                if not chunk:
                    raise ValueError('truncated matrix payload')
                remaining -= len(chunk)
                part.update(chunk); whole.update(chunk)
            digest = part.hexdigest()
            if digest != item['sha256']:
                raise ValueError(f'{segment.name} segment hash mismatch')
            observed.append(digest)
        if source.read(1):
            raise ValueError('surplus matrix payload')
        after = os.fstat(source.fileno())
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns, before.st_nlink) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns, after.st_nlink):
            raise ValueError('matrix file changed during hashing')
    current = _no_link(path)
    if (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns, current.st_ctime_ns) != (
            path_before.st_dev, path_before.st_ino, path_before.st_size,
            path_before.st_mtime_ns, path_before.st_ctime_ns):
        raise ValueError('matrix path changed during hashing')
    if whole.hexdigest() != record['sha256']:
        raise ValueError('whole-file hash mismatch')
    return {'filename': record['filename'], 'bytes': before.st_size,
            'sha256': whole.hexdigest(), 'segment_sha256': observed}


def _verify_directory(directory, collection, profile):
    plans = _validate_collection(collection, profile)
    directory = _directory(directory)
    expected_names = set(FILENAMES) | {'collection.json'}
    if {path.name for path in directory.iterdir()} != expected_names:
        raise ValueError('matrix directory must contain exactly six files and collection.json')
    identities = set()
    for name in sorted(expected_names):
        info = _no_link(directory/name)
        identity = (info.st_dev, info.st_ino)
        if identity in identities:
            raise ValueError('aliased matrix/manifest file')
        identities.add(identity)
        if (directory/name).resolve(strict=True).parent != directory:
            raise ValueError('matrix path escapes directory')
    manifest = _read(directory/'collection.json', COLLECTION_CAP)
    parsed = _strict_json(manifest, COLLECTION_CAP)
    _validate_collection(parsed, profile)
    if manifest != _canonical(parsed) or manifest != _canonical(collection):
        raise ValueError('canonical manifest differs from native collection')
    rows = [_hash_file(directory/record['filename'], record, plan)
            for record, plan in zip(collection['files'], plans, strict=True)]
    if {path.name for path in directory.iterdir()} != expected_names:
        raise ValueError('matrix directory changed during hashing')
    return rows


def _load_profile():
    expected = load_expected_json(_read(FIXTURES/'nht4-genesis-0-2020-k5.expected.json', 1 << 16))
    dims = load_dimensions_json(_read(FIXTURES/'nht4-genesis-0-2020-k5.dimensions.json', 1 << 14),
        expected, expected_descriptor_sha256=bytes.fromhex(DIMENSION_PIN))
    raw = _read(FIXTURES/'nht4-genesis-0-2020-k5.matrix-profile.json', 1 << 14)
    if sha256(raw).hexdigest() != PROFILE_PIN:
        raise ValueError('independent matrix profile fixture pin')
    profile = _strict_json(raw, 1 << 14)
    if _canonical(profile) != raw:
        raise ValueError('noncanonical pinned profile transport')
    plans = _plans(profile)
    for role in ROLES:
        curve, dimension = profile[role], dims.json()[role]
        for name in ('engine', 'num_cons', 'num_vars', 'num_io'):
            _same(curve[name], dimension[name], f'profile/dimension {name}')
    if (sum(p.fields['bytes'] for p in plans) != EXPECTED_TOTAL_BYTES
            or max(p.fields['bytes'] for p in plans) != EXPECTED_MAX_FILE_BYTES):
        raise ValueError('independently expected export size census')
    return expected, dims, profile


def _source_collection(report, expected, dims, profile):
    if type(report) is not dict:
        raise ValueError('native report must be object')
    identities = {'schema': 'bitvm2-nova-native-production-replay/v1', 'passed': True,
        'native_nova_proofs_verified': 1, 'network': expected.network, 'k': expected.k,
        'steps': expected.steps, 'nova_version': expected.nova_version,
        'header_revision': expected.header_revision, 'bundle_sha256': expected.bundle_sha256.hex(),
        'proof_sha256': expected.proof_sha256.hex(), 'proof_bytes': expected.proof_bytes,
        'verifier_key_sha256': VK_PIN, 'verifier_dimensions_sha256': DIMENSION_PIN,
        'matrix_profile_sha256': PROFILE_PIN, 'end_state_sha256': expected.end_state_sha256.hex(),
        'end_height': 2020, 'setup_calls': 1, 'proving_jobs': 0, 'transactions_broadcast': 0,
        'bitcoin_script_verified': False, 'independent_poseidon_verification': False,
        'complete_bitvm2_verifier': False}
    for name, value in identities.items():
        _same(report.get(name), value, f'native report {name}')
    VerifierDimensions.from_json(report.get('verifier_dimensions'), expected,
        expected_descriptor_sha256=bytes.fromhex(DIMENSION_PIN))
    if _canonical(report.get('matrix_profile')) != _canonical(profile):
        raise ValueError('native profile differs from independent pin')
    # Validate original fields as well: dict equality must not coerce bools.
    _plans(report['matrix_profile'])
    collection = report.get('matrix_collection')
    _validate_collection(collection, profile)
    digest = sha256(_canonical(collection)).hexdigest()
    _same(report.get('matrix_collection_sha256'), digest, 'native collection digest')
    stats = report.get('matrix_payload_export')
    _keys(stats, {'files_written', 'total_bytes', 'selected_matrix_fields', 'skipped_fields',
        'per_file_cap_bytes', 'total_cap_bytes', 'writer_buffer_bytes',
        'full_key_materialized', 'matrix_payloads_materialized'}, 'native export stats')
    for name, value in {'files_written': 6, 'total_bytes': collection['total_bytes'],
        'selected_matrix_fields': 6, 'per_file_cap_bytes': FILE_CAP, 'total_cap_bytes': TOTAL_CAP,
        'writer_buffer_bytes': 64 << 10, 'full_key_materialized': False,
        'matrix_payloads_materialized': False}.items():
        _same(stats[name], value, f'export {name}')
    _uint(stats['skipped_fields'], 'skipped fields')
    seconds = report.get('matrix_payload_export_seconds')
    if type(seconds) not in (int, float) or not math.isfinite(seconds) or not 0 <= seconds <= 600:
        raise ValueError('invalid export duration')
    return collection, digest


def _summary(rows, collection_sha, source_sha):
    return {'schema': 'bitvm2-nova-matrix-export-conformance/v1',
        'file_integrity_conformance': True, 'files': rows,
        'total_bytes': sum(row['bytes'] for row in rows), 'whole_file_hashes_checked': len(rows),
        'segment_hashes_checked': 4*len(rows), 'prefixes_and_columns_checked': 4*len(rows),
        'matrix_collection_sha256': collection_sha, 'source_native_report_sha256': source_sha,
        'matrix_profile_sha256': PROFILE_PIN, 'verifier_dimensions_sha256': DIMENSION_PIN,
        'verifier_key_sha256': VK_PIN, 'max_hash_chunk_bytes': CHUNK_BYTES,
        'source_native_proofs_verified': 1, 'native_proofs_verified': 0,
        'collection_independently_pinned': False, 'matrix_verification_enabled': False,
        'matrix_polynomials_verified': False, 'csr_semantics_verified': False,
        'proof_verified': False, 'bitcoin_script_verified': False,
        'full_matrix_materialized': False, 'setup_calls': 0, 'proving_jobs': 0,
        'scope': 'source-manifest/file integrity conformance only; collection digest is not independent authority'}


def run(native_report, matrix_dir):
    # Resource protection only. An environment variable is never proof authority.
    if os.environ.get('GITHUB_ACTIONS') != 'true':
        raise ValueError('actual matrix-export hashing is hosted-GitHub-Actions-only')
    started = time.perf_counter()
    expected, dims, profile = _load_profile()
    raw = _read(Path(native_report), REPORT_CAP)
    report = _strict_json(raw, REPORT_CAP)
    collection, digest = _source_collection(report, expected, dims, profile)
    rows = _verify_directory(matrix_dir, collection, profile)
    result = _summary(rows, digest, sha256(raw).hexdigest())
    result.update(wall_seconds=time.perf_counter()-started, peak_rss_bytes=peak_rss(),
                  hosted_ci_resource_guard_satisfied=True)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native-report', type=Path, required=True)
    parser.add_argument('--matrix-dir', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = run(args.native_report, args.matrix_dir)
    encoded = _canonical(result)+b'\n'
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(encoded)
    # Keep the detailed file checks in the artifact; log the compact evidence.
    print(json.dumps({name: value for name, value in result.items() if name != 'files'}))


if __name__ == '__main__':
    main()
