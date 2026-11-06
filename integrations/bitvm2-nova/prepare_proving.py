"""Materialize the literal pinned header-prover source into a new owned directory.

This command performs public HTTPS GETs and verifies source bytes. It never
invokes Cargo, a prover, a shell, or a downloaded program. Cargo.lock and build
outputs are deliberately separate from the pinned Git source package.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from hashlib import sha1, sha256
import json
import os
from pathlib import Path
import stat
import sys
from urllib.parse import quote, urlsplit
from urllib.request import Request, urlopen

from proving_policy import (
    HEADER_REVISION, MAX_MANIFEST_BYTES, MAX_SOURCE_BYTES, MAX_SOURCE_FILE_BYTES,
    PACKAGE_PREFIX, PACKAGE_TREE_SHA, REPOSITORY, SOURCE_FILES,
    VerifiedSourceFile, _git_tree, verify_source_package,
)

MAX_API_BYTES = 128 << 10
MAX_FILES = 128
DOWNLOAD_WORKERS = 4
HTTP_TIMEOUT = 30
TREE_URL = (f'https://api.github.com/repos/{REPOSITORY}/git/trees/'
            f'{PACKAGE_TREE_SHA}?recursive=1')
RAW_PREFIX = f'https://raw.githubusercontent.com/{REPOSITORY}/{HEADER_REVISION}/'
INCOMPLETE = 'source-preparation-incomplete.json'
FAILED = 'source-preparation-failed.json'
MANIFEST = 'source-manifest.json'
SCHEMA = 'bitvm2-nova-source-preparation/v1'


@dataclass(frozen=True)
class _Entry:
    path: str
    mode: str
    git_blob: str
    bytes: int


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate GitHub JSON field')
        result[key] = value
    return result


def _hex(value):
    if (type(value) is not str or len(value) != 40
            or any(c not in '0123456789abcdef' for c in value)):
        raise ValueError('invalid Git object identity')
    return value


def _parts(value):
    if (type(value) is not str or not value or len(value) > 512
            or not value.isascii() or '\\' in value or ':' in value
            or any(ord(c) < 32 or ord(c) == 127 for c in value)):
        raise ValueError('invalid source path')
    parts = value.split('/')
    devices = {'con', 'prn', 'aux', 'nul'} | {
        f'{prefix}{i}' for prefix in ('com', 'lpt') for i in range(1, 10)}
    if (len(parts) > 16 or any(not p or p in ('.', '..') or p.endswith((' ', '.'))
            or p.split('.')[0].casefold() in devices for p in parts)):
        raise ValueError('unsafe source path component')
    return tuple(parts)


def _tree_entries(raw):
    """Authenticate the complete small recursive tree before any file download."""
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_API_BYTES:
        raise ValueError('GitHub tree JSON exceeds byte cap')
    try:
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=_unique,
                           parse_constant=lambda _: (_ for _ in ()).throw(
                               ValueError('nonfinite GitHub JSON')))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError('invalid GitHub tree JSON') from error
    if (type(value) is not dict or set(value) != {'sha', 'url', 'tree', 'truncated'}
            or value['sha'] != PACKAGE_TREE_SHA or value['truncated'] is not False
            or type(value['url']) is not str):
        raise ValueError('GitHub tree identity/schema/truncation mismatch')
    nodes = value['tree']
    if type(nodes) is not list or not 1 <= len(nodes) <= MAX_FILES*2:
        raise ValueError('GitHub tree entry count exceeds cap')
    files, directories, seen, folded, total = [], set(), set(), set(), 0
    for node in nodes:
        if type(node) is not dict or not {'path', 'mode', 'type', 'sha'} <= set(node):
            raise ValueError('invalid GitHub tree entry')
        expected = {'path', 'mode', 'type', 'sha', 'url'}
        if node['type'] == 'blob':
            expected.add('size')
        if set(node) != expected or type(node['url']) is not str:
            raise ValueError('unexpected GitHub tree entry fields')
        parts = _parts(node['path'])
        folded_path = tuple(p.casefold() for p in parts)
        if parts in seen or folded_path in folded:
            raise ValueError('duplicate/case-colliding source path')
        seen.add(parts)
        folded.add(folded_path)
        _hex(node['sha'])
        if node['type'] == 'tree' and node['mode'] == '040000':
            directories.add(parts)
        elif node['type'] == 'blob' and node['mode'] in ('100644', '100755'):
            size = node['size']
            if type(size) is not int or not 0 <= size <= MAX_SOURCE_FILE_BYTES:
                raise ValueError('source file exceeds byte cap')
            total += size
            if total > MAX_SOURCE_BYTES or len(files) >= MAX_FILES:
                raise ValueError('source package exceeds aggregate cap')
            files.append(_Entry(PACKAGE_PREFIX+node['path'], node['mode'],
                                node['sha'], size))
        else:
            raise ValueError('source symlink/submodule/unsupported mode')
    ancestors = {tuple(entry.path[len(PACKAGE_PREFIX):].split('/')[:i])
                 for entry in files
                 for i in range(1, len(entry.path[len(PACKAGE_PREFIX):].split('/')))}
    if directories != ancestors or len(files) != SOURCE_FILES:
        raise ValueError('source tree coverage/file count differs from pinned package')
    records = tuple(VerifiedSourceFile(e.path, e.mode, e.git_blob, b'\0'*32, e.bytes)
                    for e in files)
    if _git_tree(records) != PACKAGE_TREE_SHA:
        raise ValueError('source paths/modes/blobs differ from the literal Git tree')
    return tuple(sorted(files, key=lambda entry: entry.path))


def _http_get(url, cap):
    """Bound every response including an omitted or dishonest Content-Length."""
    if type(cap) is not int or not 0 <= cap <= MAX_SOURCE_FILE_BYTES:
        raise ValueError('invalid source HTTP byte cap')
    parsed = urlsplit(url)
    if (parsed.scheme != 'https' or parsed.hostname not in
            ('api.github.com', 'raw.githubusercontent.com')
            or parsed.username is not None or parsed.password is not None
            or parsed.port not in (None, 443)):
        raise ValueError('unsupported source URL')
    request = Request(url, headers={'User-Agent': 'bitvm2-nova-source-preparation/1',
                                   'Accept': 'application/vnd.github+json'
                                   if parsed.hostname == 'api.github.com' else '*/*'})
    with urlopen(request, timeout=HTTP_TIMEOUT) as response:
        final = urlsplit(response.geturl())
        if (response.status != 200 or final.scheme != 'https'
                or final.hostname != parsed.hostname or final.port not in (None, 443)
                or final.username is not None or final.password is not None):
            raise ValueError('unexpected source HTTP response/redirect')
        length = response.headers.get('Content-Length')
        if length is not None and (not length.isascii() or not length.isdecimal()
                                   or int(length) > cap):
            raise ValueError('source HTTP Content-Length exceeds cap')
        raw = response.read(cap+1)
        if len(raw) > cap:
            raise ValueError('source HTTP response exceeds byte cap')
        return raw


def _regular_directory(path):
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or getattr(info, 'st_file_attributes', 0)
            & getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 0x400)):
        raise ValueError('owned source ancestors must be regular non-reparse directories')


def _new_root(source_root, owned_parent):
    if not isinstance(source_root, (str, Path)) or not isinstance(owned_parent, (str, Path)):
        raise ValueError('source root and owned parent must be paths')
    root = Path(os.path.abspath(source_root))
    owner = Path(os.path.abspath(owned_parent))
    # Check every existing ancestor, including ones above the selected owner.
    for candidate in (owner, root.parent):
        for ancestor in reversed((candidate,)+tuple(candidate.parents)):
            _regular_directory(ancestor)
    owner = owner.resolve(strict=True)
    root = root.parent.resolve(strict=True)/root.name
    try:
        relative = root.relative_to(owner)
    except ValueError as error:
        raise ValueError('new source root must stay within the owned parent') from error
    if not relative.parts:
        raise ValueError('source root must be a strict descendant of its owned parent')
    try:
        root.lstat()
    except FileNotFoundError:
        pass
    else:
        raise ValueError('source root already exists; choose a new directory')
    # Exclusive creation also refuses a concurrently created file/link/directory.
    root.mkdir()
    return root


def _write_new(path, raw):
    with path.open('xb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def _download_entry(root, entry, transport):
    raw = transport(RAW_PREFIX+quote(entry.path, safe='/'), entry.bytes)
    if type(raw) is not bytes or len(raw) != entry.bytes or len(raw) > MAX_SOURCE_FILE_BYTES:
        raise ValueError('downloaded source byte length differs from Git tree')
    blob = sha1(b'blob '+str(len(raw)).encode('ascii')+b'\0'+raw).hexdigest()
    if blob != entry.git_blob:
        raise ValueError('downloaded source Git blob SHA1 mismatch')
    path = root.joinpath(*entry.path.split('/'))
    # Parents were made by this invocation before the workers started.
    _write_new(path, raw)
    path.chmod(0o755 if entry.mode == '100755' else 0o644)
    return {'path': entry.path, 'mode': entry.mode, 'git_blob': blob,
            'sha256': sha256(raw).hexdigest(), 'bytes': len(raw)}


def prepare_source(source_root, *, owned_parent, transport=None):
    """Prepare a new tree, then return proving_policy's rehashed sealed result.

    ``transport`` is a small test seam, never source authority: the literal
    Git tree and every blob are checked regardless of where bytes came from.
    Failed roots are retained for inspection and cannot be reused by this CLI.
    """
    if transport is None:
        transport = _http_get
    if not callable(transport):
        raise ValueError('source transport must be callable')
    root = _new_root(source_root, owned_parent)
    phase = 'tree'
    manifest_written = False
    try:
        _write_new(root/INCOMPLETE, _canonical({'schema': SCHEMA, 'status': 'incomplete'}))
        entries = _tree_entries(transport(TREE_URL, MAX_API_BYTES))
        for directory in sorted({root.joinpath(*entry.path.split('/')).parent
                                 for entry in entries}, key=lambda p: len(p.parts)):
            directory.mkdir(parents=True, exist_ok=True)
            _regular_directory(directory)
        phase = 'files'
        with ThreadPoolExecutor(max_workers=DOWNLOAD_WORKERS) as executor:
            records = list(executor.map(lambda e: _download_entry(root, e, transport), entries))
        manifest = {'repository': REPOSITORY, 'revision': HEADER_REVISION,
                    'git_subtree_sha': PACKAGE_TREE_SHA, 'files': records}
        raw = _canonical(manifest)
        if len(raw) > MAX_MANIFEST_BYTES:
            raise ValueError('source manifest exceeds byte cap')
        phase = 'verification'
        _write_new(root/MANIFEST, raw)
        manifest_written = True
        # Remove the in-progress marker before admission. Policy may reject
        # markers; a crash now leaves only source which it independently rehashes.
        (root/INCOMPLETE).unlink()
        verified = verify_source_package(root)
        return verified
    except Exception as error:
        _write_new(root/FAILED, _canonical({'schema': SCHEMA, 'status': 'failed',
                   'phase': phase, 'error_type': type(error).__name__,
                   'source_prepared': False, 'builds_launched': 0, 'proving_jobs_launched': 0}))
        if manifest_written:
            try:
                (root/MANIFEST).unlink()
            except FileNotFoundError:
                pass
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', required=True,
                        help='new directory; an existing path is always refused')
    parser.add_argument('--owned-parent', default=str(Path.cwd()),
                        help='existing owned parent (default: current workspace directory)')
    args = parser.parse_args(argv)
    try:
        source = prepare_source(args.source_root, owned_parent=args.owned_parent)
    except (ValueError, OSError) as error:
        print(_canonical({'schema': SCHEMA, 'status': 'failed',
                          'error_type': type(error).__name__,
                          'source_prepared': False}).decode('ascii'), file=sys.stderr)
        return 1
    print(_canonical({'schema': SCHEMA, 'status': 'prepared',
                      'source_root': str(source.source_root),
                      'source': source.summary(), 'source_prepared': True,
                      'builds_launched': 0, 'proving_jobs_launched': 0}).decode('ascii'))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
