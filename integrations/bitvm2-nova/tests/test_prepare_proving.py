"""Tiny mocked source-preparation checks; no network, build, or proving jobs."""
from contextlib import contextmanager
from hashlib import sha1, sha256
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import prepare_proving as prepare


@contextmanager
def _owned_temporary_directory():
    # Never rely on the OS temp default: the Windows sandbox may redirect it
    # outside the explicitly writable workspace. Check the resolved target
    # before TemporaryDirectory eventually recursively removes its own tree.
    results = Path(__file__).resolve().parents[1]/'results'
    results.mkdir(exist_ok=True)
    prepare._regular_directory(results)
    results = results.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix='sourceprep-test-', dir=results) as name:
        owned = Path(name).resolve(strict=True)
        if owned == results or not owned.is_relative_to(results):
            raise AssertionError('test directory escaped integration/results')
        yield owned


def _entry(relative, raw, mode='100644'):
    blob = sha1(b'blob '+str(len(raw)).encode('ascii')+b'\0'+raw).hexdigest()
    return prepare._Entry(prepare.PACKAGE_PREFIX+relative, mode, blob, len(raw))


class PrepareProvingTests(unittest.TestCase):
    def setUp(self):
        network = patch.object(prepare, 'urlopen',
                               side_effect=AssertionError('network forbidden in tiny tests'))
        self.addCleanup(network.stop)
        self.urlopen = network.start()

    def test_paths_and_git_object_identity_are_strict(self):
        malformed = ('../bad', '/bad', 'x//y', 'x\\y', 'x:y', 'NUL',
                     'x/COM1.txt', 'x/..', 'x/end.', 'x/end ', '\x00',
                     'a/'*17+'file', False)
        for value in malformed:
            with self.subTest(path=value), self.assertRaises(ValueError):
                prepare._parts(value)
        self.assertEqual(prepare._parts('src/bin/nova-chain.rs'),
                         ('src', 'bin', 'nova-chain.rs'))
        for value in ('A'*40, '0'*39, True, b'0'*40):
            with self.subTest(digest=value), self.assertRaises(ValueError):
                prepare._hex(value)
        self.assertEqual(prepare._hex('0'*40), '0'*40)

    def test_tree_json_is_bounded_unique_and_pinned(self):
        malformed = (b'', b' '*(prepare.MAX_API_BYTES+1),
                     b'{"sha":0,"sha":1}', b'{"sha":NaN}', b'[]', b'{', b'\xff')
        for raw in malformed:
            with self.subTest(length=len(raw)), self.assertRaises(ValueError):
                prepare._tree_entries(raw)
        tree = {'sha': prepare.PACKAGE_TREE_SHA, 'url': prepare.TREE_URL,
                'tree': [], 'truncated': False}
        for field, value in (('sha', '0'*40), ('truncated', True),
                             ('truncated', 0), ('tree', [{}]*257), ('tree', {})):
            changed = dict(tree, **{field: value})
            with self.subTest(field=field), self.assertRaises(ValueError):
                prepare._tree_entries(prepare._canonical(changed))
        node = {'path': 'link', 'mode': '120000', 'type': 'blob',
                'sha': '0'*40, 'size': 1, 'url': prepare.TREE_URL}
        for change in ({}, {'path': '../escape'}, {'mode': '100644', 'size': True},
                       {'mode': '100644', 'size': prepare.MAX_SOURCE_FILE_BYTES+1}):
            changed = dict(tree, tree=[dict(node, **change)])
            with self.subTest(node=change), self.assertRaises(ValueError):
                prepare._tree_entries(prepare._canonical(changed))
        # An apparently complete set still cannot choose its own Git tree pin.
        fake_files = [dict(node, path=f'file-{i}', mode='100644', size=0)
                      for i in range(prepare.SOURCE_FILES)]
        with self.assertRaisesRegex(ValueError, 'literal Git tree'):
            prepare._tree_entries(prepare._canonical(dict(tree, tree=fake_files)))
        self.urlopen.assert_not_called()

    def test_http_rejects_bad_urls_and_caps_before_transport(self):
        malformed = (('http://api.github.com/a', 1), ('https://evil.test/a', 1),
                     ('https://user@api.github.com/a', 1),
                     ('https://api.github.com:444/a', 1),
                     ('https://api.github.com/a', True),
                     ('https://api.github.com/a', -1),
                     ('https://api.github.com/a', prepare.MAX_SOURCE_FILE_BYTES+1))
        for url, cap in malformed:
            with self.subTest(url=url, cap=cap), self.assertRaises(ValueError):
                prepare._http_get(url, cap)
        self.urlopen.assert_not_called()

    def test_new_root_stays_within_owner_and_never_overwrites(self):
        with _owned_temporary_directory() as owner:
            root = prepare._new_root(owner/'new', owner)
            self.assertEqual(root, owner/'new')
            sentinel = owner/'existing.txt'
            sentinel.write_bytes(b'preserve')
            outside = owner.parent/(owner.name+'-outside')
            for candidate in (root, owner, sentinel, outside):
                with self.subTest(path=candidate), self.assertRaises(ValueError):
                    prepare._new_root(candidate, owner)
            self.assertEqual(sentinel.read_bytes(), b'preserve')
            self.assertFalse(outside.exists())

    def test_blob_size_sha_mode_and_exclusive_write(self):
        raw = b'tiny'
        entry = _entry('tiny.txt', raw, '100755')
        with _owned_temporary_directory() as root:
            package = root/'integrations'/'nova-header-chain'
            package.mkdir(parents=True)
            calls = []

            def transport(url, cap):
                calls.append((url, cap))
                return raw

            record = prepare._download_entry(root, entry, transport)
            self.assertEqual(record, {'path': entry.path, 'mode': '100755',
                             'git_blob': entry.git_blob, 'sha256': sha256(raw).hexdigest(),
                             'bytes': len(raw)})
            self.assertEqual(calls, [(prepare.RAW_PREFIX+entry.path, len(raw))])
            self.assertEqual((package/'tiny.txt').read_bytes(), raw)
            with self.assertRaises(FileExistsError):
                prepare._download_entry(root, entry, transport)
            wrong = prepare._Entry(prepare.PACKAGE_PREFIX+'wrong.txt', '100644', '0'*40, 4)
            with self.assertRaisesRegex(ValueError, 'SHA1 mismatch'):
                prepare._download_entry(root, wrong, transport)
            with self.assertRaisesRegex(ValueError, 'byte length'):
                prepare._download_entry(root, wrong, lambda *_: b'bad')
            self.assertFalse((package/'wrong.txt').exists())
            empty = _entry('empty.txt', b'')
            self.assertEqual(prepare._download_entry(root, empty, lambda *_: b'')['bytes'], 0)
        self.urlopen.assert_not_called()

    def test_tree_failure_leaves_marker_without_admissible_manifest(self):
        with _owned_temporary_directory() as owner:
            root = owner/'new'
            with self.assertRaises(ValueError):
                prepare.prepare_source(root, owned_parent=owner, transport=lambda *_: b'[]')
            self.assertFalse((root/prepare.MANIFEST).exists())
            marker = json.loads((root/prepare.FAILED).read_bytes())
            self.assertEqual(marker['phase'], 'tree')
            self.assertFalse(marker['source_prepared'])
            self.assertEqual(marker['builds_launched'], 0)
            self.assertEqual(marker['proving_jobs_launched'], 0)
            with self.assertRaisesRegex(ValueError, 'already exists'):
                prepare.prepare_source(root, owned_parent=owner, transport=lambda *_: b'[]')
        self.urlopen.assert_not_called()

    def test_independent_policy_refusal_removes_manifest(self):
        raw = b'tiny'
        entry = _entry('tiny.txt', raw)
        with _owned_temporary_directory() as owner:
            root = owner/'new'

            def refuse(candidate):
                self.assertEqual(candidate, root)
                self.assertFalse((root/prepare.INCOMPLETE).exists())
                manifest = json.loads((root/prepare.MANIFEST).read_bytes())
                self.assertEqual(set(manifest), {'repository', 'revision', 'git_subtree_sha', 'files'})
                self.assertEqual(manifest['revision'], prepare.HEADER_REVISION)
                self.assertEqual(manifest['files'][0]['sha256'], sha256(raw).hexdigest())
                raise ValueError('independent policy refusal')

            # Replace only trusted internal boundaries for this tiny orchestration
            # check. A synthetic single-file tree is never admitted as a package.
            with patch.object(prepare, '_tree_entries', return_value=(entry,)), \
                    patch.object(prepare, 'verify_source_package', side_effect=refuse) as policy:
                with self.assertRaisesRegex(ValueError, 'independent policy refusal'):
                    prepare.prepare_source(root, owned_parent=owner, transport=lambda *_: raw)
            policy.assert_called_once_with(root)
            self.assertFalse((root/prepare.MANIFEST).exists())
            self.assertEqual(json.loads((root/prepare.FAILED).read_bytes())['phase'], 'verification')
        self.urlopen.assert_not_called()


if __name__ == '__main__':
    unittest.main()
