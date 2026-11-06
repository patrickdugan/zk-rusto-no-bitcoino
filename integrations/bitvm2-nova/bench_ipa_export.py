"""Hosted-only file-integrity conformance for native IPA generator exports.

The collection digest is not independently pinned in this stage. Matching a
source manifest is not point decoding, an MSM, an IPA check or proof verification.
Actual generator files are hashed only in hosted CI; private helper tests use
tiny synthetic byte strings and never load the actual generator vectors.
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
DIMENSION_PIN = 'de6333df2e41b5f5bae1c103fab862f8d6022fd54abeb80ba61920bc9f360edc'
VK_PIN = '1ae88a7bcfdc5f14d030d0baafa06ec17fe904a5ebed42f9bd6fa6105fdc8c24'
CRATE_PIN = 'c9bb3809a6c70057ea722c1c4fe5097cf29a3479d0b4671f3cddb1d81043bb31'
REVISION = 'de607d3db17d400dd6c2923d357f1d4a7bf233c7'
COUNTS = (524288, 16384)
EXPECTED_TOTAL_BYTES = 17301520
FILE_CAP = TOTAL_CAP = 32 << 20
REPORT_CAP, COLLECTION_CAP = 4 << 20, 16 << 10
CHUNK_BYTES = 1 << 20
U64_MAX = (1 << 64)-1
ROLES, ENGINES = ('primary', 'secondary'), ('pallas', 'vesta')
FILENAMES = ('primary-generators.bin', 'secondary-generators.bin')
IDENTITY = {'nova_version': '0.76.0', 'nova_crate_sha256': CRATE_PIN,
    'header_revision': REVISION, 'network': 'testnet4', 'k': 5,
    'verifier_key_sha256': VK_PIN, 'verifier_dimensions_sha256': DIMENSION_PIN}


def _keys(value, expected, name):
    if type(value) is not dict or set(value) != set(expected):
        raise ValueError(f'unexpected {name} fields')


def _same(actual, expected, name):
    if type(actual) is not type(expected) or actual != expected:
        raise ValueError(f'{name} mismatch')


def _uint(value, name, maximum=U64_MAX, minimum=0):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f'invalid unsigned {name}')
    return value


def _digest(value, name):
    if (type(value) is not str or len(value) != 64
            or any(c not in '0123456789abcdef' for c in value)):
        raise ValueError(f'invalid {name} digest')
    return value


def _strict_json(raw, cap):
    if type(raw) is not bytes or not 1 <= len(raw) <= cap:
        raise ValueError('JSON byte budget/type')
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('duplicate JSON field')
            result[key] = value
        return result
    def integer(text):
        if len(text.lstrip('-')) > 20:
            raise ValueError('JSON integer digit budget')
        result = int(text)
        if not -(1 << 63) <= result <= U64_MAX:
            raise ValueError('JSON integer range')
        return result
    def floating(text):
        result = float(text)
        if not math.isfinite(result):
            raise ValueError('nonfinite JSON number')
        return result
    def constant(_):
        raise ValueError('non-JSON constant')
    try:
        result = json.loads(raw.decode('utf-8'), object_pairs_hook=pairs,
            parse_int=integer, parse_float=floating, parse_constant=constant)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError('invalid JSON transport') from error
    pending, count = [(result, 0)], 0
    while pending:
        value, depth = pending.pop()
        count += 1
        if depth > 32 or count > 100000:
            raise ValueError('JSON depth/node budget')
        if type(value) in (dict, list):
            if len(value) > 100000:
                raise ValueError('JSON collection budget')
            pending.extend((child, depth+1) for child in
                           (value.values() if type(value) is dict else value))
    return result


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
            raise ValueError('expected generator directory')
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
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0))
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


@dataclass(frozen=True)
class _Plan:
    fields: dict


def _plans(counts):
    """Private size helper. The CLI obtains counts only from pinned dimensions."""
    if type(counts) is not tuple or len(counts) != 2:
        raise ValueError('two ordered generator counts required')
    plans = []
    for role, engine, name, count in zip(ROLES, ENGINES, FILENAMES, counts, strict=True):
        _uint(count, 'generator count', 1 << 24, 1)
        size = 8+32*count
        if size > FILE_CAP:
            raise ValueError('generator file exceeds 32MiB cap')
        plans.append(_Plan({'role': role, 'engine': engine,
            'base_field_role': f'{engine}_base', 'scalar_field_role': f'{engine}_scalar',
            'filename': name, 'count': count, 'bytes': size}))
    if sum(plan.fields['bytes'] for plan in plans) > TOTAL_CAP:
        raise ValueError('generator total exceeds 32MiB cap')
    return tuple(plans)


def _validate_collection(collection, plans):
    _keys(collection, set(IDENTITY) | {'schema', 'encoding', 'total_bytes', 'files'}, 'generator collection')
    for name, expected in IDENTITY.items():
        _same(collection[name], expected, name)
    _same(collection['schema'], 'bitvm2-nova-ipa-generators/v1', 'collection schema')
    _same(collection['encoding'], 'bincode-1.3.3-legacy-fixed-little-endian', 'encoding')
    _same(collection['total_bytes'], sum(plan.fields['bytes'] for plan in plans), 'collection bytes')
    records = collection['files']
    if type(records) is not list or len(records) != 2:
        raise ValueError('two ordered generator files required')
    for record, plan in zip(records, plans, strict=True):
        _keys(record, set(plan.fields) | {'sha256', 'segments'}, 'generator file record')
        for name, value in plan.fields.items():
            _same(record[name], value, f'file {name}')
        _digest(record['sha256'], 'whole-file')
        segments = record['segments']
        if type(segments) is not list or len(segments) != 2:
            raise ValueError('two ordered generator segments required')
        for segment, expected in zip(segments, (('count', 0, 8), ('points', 8, 32*plan.fields['count'])), strict=True):
            _keys(segment, {'name', 'offset', 'bytes', 'sha256'}, 'generator segment')
            for name, value in zip(('name', 'offset', 'bytes'), expected, strict=True):
                _same(segment[name], value, f'segment {name}')
            _digest(segment['sha256'], 'segment')
    if len(_canonical(collection)) > COLLECTION_CAP:
        raise ValueError('collection JSON byte budget')


def _hash_file(path, record, plan):
    path_before = _no_link(path)
    source, before = _open_regular(path)
    whole, points = sha256(), sha256()
    with source:
        if before.st_size != plan.fields['bytes']:
            raise ValueError('actual generator file length mismatch')
        prefix = source.read(8)
        if prefix != plan.fields['count'].to_bytes(8, 'little'):
            raise ValueError('actual generator count prefix mismatch')
        count_sha = sha256(prefix).hexdigest()
        if count_sha != record['segments'][0]['sha256']:
            raise ValueError('count segment hash mismatch')
        whole.update(prefix)
        remaining = 32*plan.fields['count']
        while remaining:
            chunk = source.read(min(remaining, CHUNK_BYTES))
            if not chunk:
                raise ValueError('truncated generator payload')
            remaining -= len(chunk)
            points.update(chunk); whole.update(chunk)
        if source.read(1):
            raise ValueError('surplus generator payload')
        after = os.fstat(source.fileno())
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns, before.st_nlink) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns, after.st_nlink):
            raise ValueError('generator file changed during hashing')
    current = _no_link(path)
    if (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns, current.st_ctime_ns) != (
            path_before.st_dev, path_before.st_ino, path_before.st_size,
            path_before.st_mtime_ns, path_before.st_ctime_ns):
        raise ValueError('generator path changed during hashing')
    if points.hexdigest() != record['segments'][1]['sha256']:
        raise ValueError('points segment hash mismatch')
    if whole.hexdigest() != record['sha256']:
        raise ValueError('whole-file hash mismatch')
    return {'filename': record['filename'], 'count': plan.fields['count'],
        'bytes': before.st_size, 'sha256': whole.hexdigest(),
        'segment_sha256': [count_sha, points.hexdigest()]}


def _verify_directory(directory, collection, plans):
    _validate_collection(collection, plans)
    directory = _directory(directory)
    names = set(FILENAMES) | {'collection.json'}
    if {path.name for path in directory.iterdir()} != names:
        raise ValueError('generator directory must contain exactly two files and collection.json')
    identities = set()
    for name in sorted(names):
        info = _no_link(directory/name)
        identity = (info.st_dev, info.st_ino)
        if identity in identities:
            raise ValueError('aliased generator/manifest file')
        identities.add(identity)
        if (directory/name).resolve(strict=True).parent != directory:
            raise ValueError('generator path escapes directory')
    manifest = _read(directory/'collection.json', COLLECTION_CAP)
    parsed = _strict_json(manifest, COLLECTION_CAP)
    _validate_collection(parsed, plans)
    if manifest != _canonical(parsed) or manifest != _canonical(collection):
        raise ValueError('canonical manifest differs from native collection')
    rows = [_hash_file(directory/record['filename'], record, plan)
            for record, plan in zip(collection['files'], plans, strict=True)]
    if {path.name for path in directory.iterdir()} != names:
        raise ValueError('generator directory changed during hashing')
    return rows


def _load_policy():
    expected = load_expected_json(_read(FIXTURES/'nht4-genesis-0-2020-k5.expected.json', 1 << 16))
    dims = load_dimensions_json(_read(FIXTURES/'nht4-genesis-0-2020-k5.dimensions.json', 1 << 14),
        expected, expected_descriptor_sha256=bytes.fromhex(DIMENSION_PIN))
    data = dims.json()
    for name, value in IDENTITY.items():
        if name != 'verifier_dimensions_sha256':
            _same(data.get(name), value, f'policy {name}')
    counts = tuple(data[role]['ck_v_generators'] for role in ROLES)
    if counts != COUNTS or any(type(count) is not int for count in counts):
        raise ValueError('independent generator cardinality pin')
    plans = _plans(counts)
    if sum(plan.fields['bytes'] for plan in plans) != EXPECTED_TOTAL_BYTES:
        raise ValueError('independently expected generator byte census')
    return expected, dims, plans


def _source_collection(report, expected, dims, plans):
    if type(report) is not dict:
        raise ValueError('native report must be object')
    required = {'schema': 'bitvm2-nova-native-production-replay/v1', 'passed': True,
        'native_nova_proofs_verified': 1, 'network': expected.network, 'k': expected.k,
        'steps': expected.steps, 'nova_version': expected.nova_version,
        'header_revision': expected.header_revision, 'bundle_sha256': expected.bundle_sha256.hex(),
        'proof_sha256': expected.proof_sha256.hex(), 'proof_bytes': expected.proof_bytes,
        'verifier_key_sha256': VK_PIN, 'verifier_dimensions_sha256': DIMENSION_PIN,
        'end_state_sha256': expected.end_state_sha256.hex(), 'end_height': 2020,
        'setup_calls': 1, 'proving_jobs': 0, 'transactions_broadcast': 0,
        'bitcoin_script_verified': False, 'independent_poseidon_verification': False,
        'complete_bitvm2_verifier': False}
    for name, value in required.items():
        _same(report.get(name), value, f'native report {name}')
    decoded = VerifierDimensions.from_json(report.get('verifier_dimensions'), expected,
        expected_descriptor_sha256=bytes.fromhex(DIMENSION_PIN))
    if _canonical(decoded.json()) != _canonical(dims.json()):
        raise ValueError('native dimensions differ from caller policy')
    collection = report.get('ipa_generators')
    _validate_collection(collection, plans)
    digest = sha256(_canonical(collection)).hexdigest()
    _same(report.get('ipa_generators_sha256'), digest, 'native generator collection digest')
    stats = report.get('ipa_generator_export')
    _keys(stats, {'files_written', 'total_bytes', 'selected_generator_fields', 'skipped_fields',
        'per_file_cap_bytes', 'total_cap_bytes', 'writer_buffer_bytes',
        'full_key_materialized', 'generator_vectors_materialized'}, 'native generator export stats')
    for name, value in {'files_written': 2, 'total_bytes': collection['total_bytes'],
        'selected_generator_fields': 2, 'per_file_cap_bytes': FILE_CAP, 'total_cap_bytes': TOTAL_CAP,
        'writer_buffer_bytes': 64 << 10, 'full_key_materialized': False,
        'generator_vectors_materialized': False}.items():
        _same(stats[name], value, f'export {name}')
    _uint(stats['skipped_fields'], 'skipped fields')
    seconds = report.get('ipa_generator_export_seconds')
    if type(seconds) not in (int, float) or not math.isfinite(seconds) or not 0 <= seconds <= 600:
        raise ValueError('invalid export duration')
    return collection, digest


def _summary(rows, collection_sha, source_sha):
    return {'schema': 'bitvm2-nova-ipa-export-conformance/v1',
        'file_integrity_conformance': True, 'files': rows,
        'total_bytes': sum(row['bytes'] for row in rows), 'whole_file_hashes_checked': len(rows),
        'segment_hashes_checked': 2*len(rows), 'count_prefixes_checked': len(rows),
        'ipa_generators_sha256': collection_sha, 'source_native_report_sha256': source_sha,
        'verifier_dimensions_sha256': DIMENSION_PIN, 'verifier_key_sha256': VK_PIN,
        'max_hash_chunk_bytes': CHUNK_BYTES,
        'source_native_proofs_verified': 1, 'native_proofs_verified': 0,
        'collection_independently_pinned': False, 'point_encodings_verified': False,
        'generator_derivation_verified': False, 'msm_verified': False, 'ipa_verified': False,
        'proof_verified': False, 'bitcoin_script_verified': False,
        'full_generator_vectors_materialized': False, 'setup_calls': 0, 'proving_jobs': 0,
        'scope': 'source-manifest/file integrity conformance only; collection digest is not independent authority'}


def run(native_report, generator_dir):
    # This is resource protection, not authentication or evidence of provenance.
    if os.environ.get('GITHUB_ACTIONS') != 'true':
        raise ValueError('actual IPA-generator hashing is hosted-GitHub-Actions-only')
    started = time.perf_counter()
    expected, dims, plans = _load_policy()
    raw = _read(Path(native_report), REPORT_CAP)
    report = _strict_json(raw, REPORT_CAP)
    collection, digest = _source_collection(report, expected, dims, plans)
    rows = _verify_directory(generator_dir, collection, plans)
    result = _summary(rows, digest, sha256(raw).hexdigest())
    result.update(wall_seconds=time.perf_counter()-started, peak_rss_bytes=peak_rss(),
                  hosted_ci_resource_guard_satisfied=True)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native-report', type=Path, required=True)
    parser.add_argument('--generator-dir', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = run(args.native_report, args.generator_dir)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(_canonical(result)+b'\n')
    print(json.dumps({name: value for name, value in result.items() if name != 'files'}))


if __name__ == '__main__':
    main()
