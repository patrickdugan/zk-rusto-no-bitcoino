"""Tiny transport/resource checks; no real pair or permutation is built."""
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import bench_keccak_permutation as bench


class PermutationBench(unittest.TestCase):
    def setUp(self):
        parent = Path(bench.__file__).parent/'results'
        parent.mkdir(exist_ok=True)
        self.temp = TemporaryDirectory(prefix='tiny-full-keccak-', dir=parent)
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)

    def test_guard_precedes_requested_paths_and_full_graph_construction(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(bench, '_worker') as worker, \
                patch.object(bench, '_generate') as generate:
            with self.assertRaisesRegex(ValueError, 'hosted'):
                bench.run(self.base/'not-created', self.base/'missing-worker')
            worker.assert_not_called()
            generate.assert_not_called()

    def test_exact_bytes_hash_and_budget_failure_preserve_existing_files(self):
        from hashlib import sha256
        path = self.base/'small.json'
        value = {'x': [0, 1], 'name': 'test'}
        result = bench._write_json(path, value, 128)
        raw = path.read_bytes()
        self.assertEqual(json.loads(raw), value)
        self.assertEqual(result, dict(file_bytes=len(raw), file_sha256=sha256(raw).hexdigest()))
        with self.assertRaisesRegex(ValueError, 'byte cap'):
            bench._write_json(path, {'long': 'x'*100}, 16)
        self.assertEqual(path.read_bytes(), raw)
        self.assertFalse(path.with_name(path.name+'.partial').exists())
        with self.assertRaisesRegex(ValueError, 'already exists'):
            bench._write_json(path, value, 128)
        self.assertEqual(path.read_bytes(), raw)

    def test_another_owners_partial_file_is_not_deleted(self):
        path = self.base/'small.json'
        partial = path.with_name(path.name+'.partial')
        partial.write_bytes(b'owned elsewhere')
        with self.assertRaises(FileExistsError):
            bench._write_json(path, {'x': 0}, 128)
        self.assertEqual(partial.read_bytes(), b'owned elsewhere')
        self.assertFalse(path.exists())


if __name__ == '__main__':
    unittest.main()
