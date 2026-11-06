"""Bounded source, scheduling and checkpoint policy for genuine native jobs.

These checks authenticate source bytes at read time and compare native receipt
data. They neither launch a process nor turn imported JSON into proof evidence.
The coordinator must obtain receipts from its own successful mature verifier.
"""
from dataclasses import dataclass
from hashlib import sha1, sha256
from hmac import compare_digest
import json
import math
import os
from pathlib import Path
import stat

from nht4 import HEADER_REVISION, KEY_PINS, genesis_initial_state, initial_state_bytes

REPOSITORY = 'patrickdugan/zk-rusto-no-bitcoino'
PACKAGE_PREFIX = 'integrations/nova-header-chain/'
PACKAGE_TREE_SHA = '382633db86c5540500db8b8653b7996e5dd26448'
SOURCE_FILES = 49
MAX_MANIFEST_BYTES = 256 << 10
MAX_SOURCE_FILE_BYTES = 8 << 20
MAX_SOURCE_BYTES = 16 << 20
MAX_LOCK_BYTES = 2 << 20
# This coordinator also invokes the pinned legacy verify-bundle decoder, whose
# accepted k range is 1..64. Reject unsupported jobs before any proving work.
MAX_K, MAX_SHARDS, MAX_THREADS = 64, 1024, 256
MAX_MEMORY_MIB = 1 << 20
U32_MAX = (1 << 32)-1
NATIVE_VERIFIER = 'nova-snark 0.76.0 pallas/vesta ipa, spartan compressed'


def _integer(value, low, high, label):
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f'{label} out of range')


def _digest(value, label):
    if type(value) is not bytes or len(value) != 32:
        raise ValueError(f'{label} must be exactly 32 bytes')
    return value


def _hex(value, length, label):
    if (type(value) is not str or len(value) != length*2
            or any(c not in '0123456789abcdef' for c in value)):
        raise ValueError(f'{label} must be canonical lowercase hex')
    return bytes.fromhex(value)


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON field')
        result[key] = value
    return result


def _json(raw):
    try:
        return json.loads(raw.decode('utf-8'), object_pairs_hook=_unique,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError('invalid source manifest JSON') from error


class _Sealed:
    def __new__(cls, *args, **kwargs):
        raise TypeError(f'{cls.__name__} is factory-only')


def _make(cls, **fields):
    result = object.__new__(cls)
    for key, value in fields.items():
        object.__setattr__(result, key, value)
    return result


@dataclass(frozen=True)
class VerifiedSourceFile:
    path: str
    mode: str
    git_blob: str
    sha256: bytes
    bytes: int


@dataclass(frozen=True, init=False)
class VerifiedSourcePackage(_Sealed):
    source_root: Path
    package_root: Path
    repository: str
    revision: str
    git_subtree_sha: str
    files: tuple
    file_count: int
    source_bytes: int
    manifest_sha256: bytes
    cargo_lock_sha256: bytes | None
    cargo_lock_bytes: int

    def summary(self):
        return {'schema': 'bitvm2-nova-proving-source/v1', 'repository': self.repository,
                'revision': self.revision, 'git_subtree_sha': self.git_subtree_sha,
                'file_count': self.file_count, 'source_bytes': self.source_bytes,
                'manifest_sha256': self.manifest_sha256.hex(),
                'cargo_lock_sha256': (None if self.cargo_lock_sha256 is None else self.cargo_lock_sha256.hex()),
                'cargo_lock_bytes': self.cargo_lock_bytes, 'cargo_lock_git_pinned': False,
                'source_bytes_authenticated_at_read': True, 'proof_verified': False}


def _relative_path(value):
    if (type(value) is not str or not value.startswith(PACKAGE_PREFIX)
            or not value.isascii() or '\\' in value or ':' in value or '\x00' in value):
        raise ValueError('invalid package source path')
    relative = value[len(PACKAGE_PREFIX):]
    parts = relative.split('/')
    if not parts or any(not part or part in ('.', '..') for part in parts):
        raise ValueError('invalid package source path component')
    return tuple(parts)


def _git_tree(records):
    """Compute Git's recursive tree from authenticated regular-file records."""
    root = {}
    for record in records:
        parts = _relative_path(record.path)
        node = root
        for part in parts[:-1]:
            existing = node.setdefault(part, {})
            if type(existing) is not dict:
                raise ValueError('source file/directory collision')
            node = existing
        if parts[-1] in node:
            raise ValueError('duplicate source tree entry')
        node[parts[-1]] = record

    def tree(node):
        entries = []
        for name, value in node.items():
            is_dir = type(value) is dict
            mode, digest = ('40000', tree(value)) if is_dir else (value.mode, bytes.fromhex(value.git_blob))
            entries.append((name.encode('ascii')+(b'/' if is_dir else b''),
                            mode.encode('ascii')+b' '+name.encode('ascii')+b'\0'+digest))
        body = b''.join(value for _, value in sorted(entries))
        return sha1(b'tree '+str(len(body)).encode('ascii')+b'\0'+body).digest()
    return tree(root).hex()


def _regular(path, *, directory=False):
    info = path.lstat()
    if (stat.S_ISLNK(info.st_mode)
            or getattr(info, 'st_file_attributes', 0) & getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 0x400)):
        raise ValueError('source symlinks/reparse points are not permitted')
    if not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)):
        raise ValueError('source path has the wrong file type')
    return info


def _hash_file(path, cap):
    before = _regular(path)
    if before.st_size > cap:
        raise ValueError('source file exceeds byte cap')
    plain = sha256()
    blob = sha1(b'blob '+str(before.st_size).encode('ascii')+b'\0')
    size = 0
    with path.open('rb') as stream:
        while True:
            block = stream.read(min(65536, cap-size+1))
            if not block:
                break
            size += len(block)
            if size > cap:
                raise ValueError('source file exceeds byte cap')
            plain.update(block)
            blob.update(block)
    after = _regular(path)
    attributes = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    if size != before.st_size or any(getattr(before, a) != getattr(after, a) for a in attributes):
        raise ValueError('source file changed while being authenticated')
    return size, plain.digest(), blob.hexdigest()


def _check_package_files(package_root, records):
    """Private tiny-test seam: authenticate files and return their tree facts."""
    expected = {tuple(_relative_path(record.path)): record for record in records}
    if len(expected) != len(records):
        raise ValueError('duplicate source file')
    folded = {tuple(part.casefold() for part in parts) for parts in expected}
    if len(folded) != len(expected):
        raise ValueError('case-colliding source files')
    directories = {parts[:i] for parts in expected for i in range(1, len(parts))}
    _regular(package_root, directory=True)
    seen, lock = set(), None
    for root, dirs, files in os.walk(package_root, followlinks=False):
        root_path = Path(root)
        relative = root_path.relative_to(package_root).parts
        for name in dirs:
            _regular(root_path/name, directory=True)
            if relative+(name,) not in directories:
                raise ValueError('unexpected directory inside source package')
        for name in files:
            parts = relative+(name,)
            if parts == ('Cargo.lock',) and parts not in expected:
                lock = _hash_file(root_path/name, MAX_LOCK_BYTES)
            elif parts not in expected:
                raise ValueError('unexpected file inside source package')
            else:
                record = expected[parts]
                size, digest, blob = _hash_file(root_path/name, MAX_SOURCE_FILE_BYTES)
                if size != record.bytes or not compare_digest(digest, record.sha256) or blob != record.git_blob:
                    raise ValueError('source bytes differ from the authenticated tree entry')
                seen.add(parts)
    if seen != set(expected):
        raise ValueError('source package is missing a pinned file')
    return _git_tree(records), lock


def verify_source_package(source_root):
    """Rehash the exact pinned package; an editable manifest is not authority.

    Cargo.lock is the sole allowed generated extra, and is reported separately.
    The caller owns later build isolation: this check does not freeze files.
    """
    if not isinstance(source_root, (str, Path)):
        raise ValueError('source root must be a path')
    source_root = Path(source_root).absolute()
    _regular(source_root, directory=True)
    manifest_path = source_root/'source-manifest.json'
    _regular(manifest_path)
    with manifest_path.open('rb') as stream:
        raw = stream.read(MAX_MANIFEST_BYTES+1)
    if not 0 < len(raw) <= MAX_MANIFEST_BYTES:
        raise ValueError('source manifest byte length exceeds cap')
    value = _json(raw)
    if (type(value) is not dict or set(value) != {'repository', 'revision', 'files', 'git_subtree_sha'}
            or value['repository'] != REPOSITORY or value['revision'] != HEADER_REVISION
            or value['git_subtree_sha'] != PACKAGE_TREE_SHA):
        raise ValueError('source identity differs from the literal pinned package')
    files = value['files']
    if type(files) is not list or len(files) != SOURCE_FILES:
        raise ValueError('source package must have exactly the pinned 49 files')
    records, total = [], 0
    for entry in files:
        if type(entry) is not dict or set(entry) != {'path', 'git_blob', 'sha256', 'bytes', 'mode'}:
            raise ValueError('invalid source entry fields')
        _relative_path(entry['path'])
        if type(entry['mode']) is not str or entry['mode'] not in ('100644', '100755'):
            raise ValueError('unsupported Git file mode')
        _hex(entry['git_blob'], 20, 'Git blob')
        digest = _hex(entry['sha256'], 32, 'source SHA256')
        _integer(entry['bytes'], 0, MAX_SOURCE_FILE_BYTES, 'source byte length')
        total += entry['bytes']
        if total > MAX_SOURCE_BYTES:
            raise ValueError('source package exceeds aggregate cap')
        records.append(VerifiedSourceFile(entry['path'], entry['mode'], entry['git_blob'], digest, entry['bytes']))
    # Reject unauthenticated metadata before opening any package payload.
    if _git_tree(records) != PACKAGE_TREE_SHA:
        raise ValueError('source entry modes/paths/blobs differ from the literal Git tree')
    package_root = source_root/'integrations'/'nova-header-chain'
    _regular(source_root/'integrations', directory=True)
    tree, lock = _check_package_files(package_root, records)
    if tree != PACKAGE_TREE_SHA:
        raise ValueError('reconstructed source subtree differs from literal pin')
    return _make(VerifiedSourcePackage, source_root=source_root, package_root=package_root,
                 repository=REPOSITORY, revision=HEADER_REVISION, git_subtree_sha=tree,
                 files=tuple(records), file_count=len(records), source_bytes=total,
                 manifest_sha256=sha256(raw).digest(), cargo_lock_sha256=None if lock is None else lock[1],
                 cargo_lock_bytes=0 if lock is None else lock[0])


@dataclass(frozen=True)
class ShardRange:
    index: int
    k: int
    start_height: int
    end_height: int
    steps: int

    @property
    def headers(self):
        return self.end_height-self.start_height

    @property
    def first_height(self):
        return self.start_height+1

    def json(self):
        return {'index': self.index, 'k': self.k, 'start_height': self.start_height,
                'end_height': self.end_height, 'steps': self.steps, 'headers': self.headers}


@dataclass(frozen=True, init=False)
class ProvingPlan(_Sealed):
    k: int
    to_height: int
    header_count: int
    shards: int
    parallel: int
    threads: int
    memory_mib: int
    total_steps: int
    ranges: tuple

    def summary(self):
        return {'schema': 'bitvm2-nova-sharded-proving-plan/v1', 'k': self.k,
                'to_height': self.to_height, 'header_count': self.header_count,
                'shards': self.shards, 'parallel': self.parallel, 'threads': self.threads,
                'memory_mib': self.memory_mib, 'total_steps': self.total_steps,
                'ranges': [value.json() for value in self.ranges], 'proving_jobs_launched': 0}


def plan_shards(*, k, to_height, header_count, shards, parallel, threads, memory_mib):
    _integer(k, 1, MAX_K, 'k')
    _integer(header_count, 2, U32_MAX+1, 'header count including genesis')
    _integer(to_height, 1, min(header_count-1, U32_MAX), 'target height')
    if to_height % k:
        raise ValueError('target height must be a multiple of k')
    total_steps = to_height//k
    _integer(total_steps, 1, U32_MAX, 'total steps')
    _integer(shards, 1, min(total_steps, MAX_SHARDS), 'shard count')
    _integer(parallel, 1, shards, 'parallel count')
    _integer(threads, 1, MAX_THREADS, 'thread count')
    _integer(memory_mib, 1, MAX_MEMORY_MIB, 'memory MiB')
    ranges = tuple(ShardRange(i, k, (total_steps*i//shards)*k,
                              (total_steps*(i+1)//shards)*k,
                              total_steps*(i+1)//shards-total_steps*i//shards)
                   for i in range(shards))
    return _make(ProvingPlan, k=k, to_height=to_height, header_count=header_count,
                 shards=shards, parallel=parallel, threads=threads, memory_mib=memory_mib,
                 total_steps=total_steps, ranges=ranges)


def _state(value, label):
    if type(value) is bytes:
        if len(value) != 17*32:
            raise ValueError(f'{label} must contain exactly 544 bytes')
        value = tuple(int.from_bytes(value[i:i+32], 'little') for i in range(0, len(value), 32))
    if type(value) is not tuple:
        raise ValueError(f'{label} must be a scalar tuple or fixed bytes')
    return value, initial_state_bytes(value)


def _key_policy(network, k, verifier_key_sha256, cold_reconstructed_vk_sha256):
    if type(network) is not str or network not in ('mainnet', 'testnet4'):
        raise ValueError('unsupported native network')
    _integer(k, 1, MAX_K, 'receipt k')
    _digest(verifier_key_sha256, 'verifier key')
    known = KEY_PINS.get((network, k))
    if known is not None:
        if not compare_digest(known, verifier_key_sha256):
            raise ValueError('verifier key differs from the pinned network/k')
    else:
        _digest(cold_reconstructed_vk_sha256, 'independently cold-reconstructed verifier key')
        if not compare_digest(cold_reconstructed_vk_sha256, verifier_key_sha256):
            raise ValueError('verifier key differs from independently cold-reconstructed key')
    for owner, digest in KEY_PINS.items():
        if compare_digest(digest, verifier_key_sha256) and owner != (network, k):
            raise ValueError('verifier key belongs to another network/k')


def _point(state):
    raw_hash = state[1].to_bytes(16, 'little')+state[2].to_bytes(16, 'little')
    return {'height': state[0], 'tip_hash': raw_hash[::-1].hex(), 'chainwork': '0x'+format(state[3], 'x')}


@dataclass(frozen=True, init=False)
class CheckedShardReceipt(_Sealed):
    shard: ShardRange
    k: int
    network: str
    verifier_key_sha256: bytes
    proof_sha256: bytes
    headers_sha256: bytes
    initial_state: tuple
    end_state: tuple
    initial_state_sha256: bytes
    end_state_sha256: bytes
    verify_seconds: float

    def summary(self):
        return {'schema': 'bitvm2-nova-checked-shard-receipt/v1', **self.shard.json(),
                'network': self.network, 'verifier_key_sha256': self.verifier_key_sha256.hex(),
                'proof_sha256': self.proof_sha256.hex(), 'headers_sha256': self.headers_sha256.hex(),
                'initial_state_sha256': self.initial_state_sha256.hex(),
                'end_state_sha256': self.end_state_sha256.hex(), 'verify_seconds': self.verify_seconds,
                'receipt_fields_checked': True, 'process_execution_authenticated': False,
                'proof_verified': False, 'bitvm2_script_verified': False}


def validate_native_receipt(receipt, *, shard, k, network, verifier_key_sha256,
                            proof_sha256, initial_state, end_state, headers_sha256,
                            cold_reconstructed_vk_sha256=None):
    """Compare a freshly produced native receipt to separately supplied claims.

    A successful return is a data check, not independent proof verification or
    process provenance. The coordinator must enforce those execution boundaries.
    """
    if type(shard) is not ShardRange:
        raise ValueError('typed shard range required')
    _integer(shard.k, 1, MAX_K, 'shard k')
    for name in ('index', 'start_height', 'end_height', 'steps'):
        _integer(getattr(shard, name), 0 if name in ('index', 'start_height') else 1, U32_MAX, name)
    if (shard.k != k or shard.end_height-shard.start_height != shard.steps*k
            or shard.start_height % shard.k or shard.end_height % shard.k):
        raise ValueError('shard range and k disagree')
    _key_policy(network, k, verifier_key_sha256, cold_reconstructed_vk_sha256)
    _digest(proof_sha256, 'proof')
    _digest(headers_sha256, 'headers')
    initial_state, initial_raw = _state(initial_state, 'initial state')
    end_state, end_raw = _state(end_state, 'end state')
    if initial_state[0] != shard.start_height or end_state[0] != shard.end_height:
        raise ValueError('full-state heights differ from expected shard')
    required = {'statement', 'verifier', 'vk_sha256', 'proof_sha256', 'checkpoint_state_sha256',
                'end_state_sha256', 'checkpoint', 'end', 'headers', 'verify_seconds', 'verified'}
    if network == 'testnet4':
        required.add('network')
    if type(receipt) is not dict or set(receipt) != required:
        raise ValueError('unexpected native receipt schema/fields')
    statement = 'btc_header_chain_testnet4_v1' if network == 'testnet4' else 'btc_header_chain_v1'
    if (type(receipt['statement']) is not str or receipt['statement'] != statement
            or type(receipt['verifier']) is not str or receipt['verifier'] != NATIVE_VERIFIER
            or receipt['verified'] is not True or (network == 'testnet4'
                and (type(receipt['network']) is not str or receipt['network'] != network))):
        raise ValueError('native receipt statement/network/verifier mismatch')
    initial_digest, end_digest = sha256(initial_raw).digest(), sha256(end_raw).digest()
    for field, expected in (('vk_sha256', verifier_key_sha256), ('proof_sha256', proof_sha256),
                            ('checkpoint_state_sha256', initial_digest), ('end_state_sha256', end_digest)):
        if not compare_digest(_hex(receipt[field], 32, field), expected):
            raise ValueError(f'native receipt {field} mismatch')
    for field, state in (('checkpoint', initial_state), ('end', end_state)):
        point = receipt[field]
        if type(point) is not dict or set(point) != {'height', 'tip_hash', 'chainwork'}:
            raise ValueError('invalid native checkpoint description')
        _integer(point['height'], 0, U32_MAX, 'checkpoint height')
        if type(point['tip_hash']) is not str or type(point['chainwork']) is not str:
            raise ValueError('native checkpoint hashes/work must be strings')
        if point != _point(state):
            raise ValueError('native checkpoint description differs from full state')
    _integer(receipt['headers'], 1, U32_MAX, 'receipt headers')
    if receipt['headers'] != shard.headers:
        raise ValueError('native receipt header count differs from shard')
    seconds = receipt['verify_seconds']
    if type(seconds) not in (int, float) or not 0 <= seconds <= 1e9 or not math.isfinite(seconds):
        raise ValueError('invalid native verification duration')
    return _make(CheckedShardReceipt, shard=shard, k=k, network=network,
                 verifier_key_sha256=verifier_key_sha256, proof_sha256=proof_sha256,
                 headers_sha256=headers_sha256, initial_state=initial_state, end_state=end_state,
                 initial_state_sha256=initial_digest, end_state_sha256=end_digest,
                 verify_seconds=float(seconds))


@dataclass(frozen=True, init=False)
class ShardContinuity(_Sealed):
    plan: ProvingPlan
    receipts: tuple
    network: str
    verifier_key_sha256: bytes
    headers_sha256: bytes

    def summary(self):
        return {'schema': 'bitvm2-nova-shard-continuity/v1', 'network': self.network,
                'k': self.plan.k, 'to_height': self.plan.to_height, 'shards': self.plan.shards,
                'headers_sha256': self.headers_sha256.hex(),
                'verifier_key_sha256': self.verifier_key_sha256.hex(),
                'initial_state_sha256': self.receipts[0].initial_state_sha256.hex(),
                'end_state_sha256': self.receipts[-1].end_state_sha256.hex(),
                'full_state_continuity_checked': True, 'genesis_anchor_checked': True,
                'process_execution_authenticated': False, 'proof_verified': False,
                'bitvm2_script_verified': False, 'transactions_broadcast': 0}


def validate_shard_continuity(plan, receipts, *, network, verifier_key_sha256, expected_headers_sha256):
    if type(plan) is not ProvingPlan:
        raise ValueError('typed proving plan required')
    _digest(verifier_key_sha256, 'verifier key')
    _digest(expected_headers_sha256, 'expected headers')
    if type(receipts) not in (tuple, list) or len(receipts) != plan.shards:
        raise ValueError('exactly one checked receipt per shard required')
    receipts = tuple(receipts)
    previous_state, previous_hash = genesis_initial_state(network), None
    for shard, receipt in zip(plan.ranges, receipts, strict=True):
        if type(receipt) is not CheckedShardReceipt or receipt.shard != shard:
            raise ValueError('checked receipt ordering/range mismatch')
        if (receipt.network != network or receipt.k != plan.k
                or not compare_digest(receipt.verifier_key_sha256, verifier_key_sha256)
                or not compare_digest(receipt.headers_sha256, expected_headers_sha256)):
            raise ValueError('shard network/key/header-source binding mismatch')
        if receipt.initial_state != previous_state:
            raise ValueError('full 17-scalar genesis/adjacent-state continuity mismatch')
        if previous_hash is not None and not compare_digest(receipt.initial_state_sha256, previous_hash):
            raise ValueError('adjacent state digest mismatch')
        if receipt.end_state[0] != shard.end_height:
            raise ValueError('checked receipt final height mismatch')
        previous_state, previous_hash = receipt.end_state, receipt.end_state_sha256
    if previous_state[0] != plan.to_height:
        raise ValueError('final shard does not reach the planned height')
    return _make(ShardContinuity, plan=plan, receipts=receipts, network=network,
                 verifier_key_sha256=verifier_key_sha256, headers_sha256=expected_headers_sha256)
