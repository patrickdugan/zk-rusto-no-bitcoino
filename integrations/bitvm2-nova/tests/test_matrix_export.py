"""Tiny synthetic CSR integrity tests; never export/hash real matrix payloads."""
from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import bench_matrix_export as check


class MatrixExport(unittest.TestCase):
    def setUp(self):
        owned = (check.FIXTURES.parent/'results').resolve()
        owned.mkdir(exist_ok=True)
        self.temp = TemporaryDirectory(prefix='tiny-matrix-export-test-', dir=owned)
        base = Path(self.temp.name).resolve()
        self.assertTrue(base.is_relative_to(owned))
        self.addCleanup(self.temp.cleanup)
        self.directory = base/'toy-matrices'
        self.directory.mkdir()
        # Explicit TEST-ONLY metadata: the public full CLI cannot authenticate
        # this changed profile against its independently pinned real fixture.
        self.profile = json.loads((check.FIXTURES/'nht4-genesis-0-2020-k5.matrix-profile.json').read_bytes())
        for role in check.ROLES:
            curve = self.profile[role]
            curve.update(num_cons=8, num_vars=8, num_io=2, evaluation_rows=8, evaluation_cols=16)
            for matrix, n in zip(check.MATRICES, (2,1,0), strict=True):
                curve['matrices'][matrix] = dict(data_len=n, indices_len=n, indptr_len=3, cols=11, csr_rows=2)
        self.plans = check._plans(self.profile)
        files = []
        self.raw = {}
        for plan in self.plans:
            n = plan.fields['data_len']
            payloads = [(n.to_bytes(8,'little')+b''.join((3+i).to_bytes(32,'little') for i in range(n))),
                (n.to_bytes(8,'little')+b''.join(i.to_bytes(8,'little') for i in (10,0)[:n])),
                (3).to_bytes(8,'little')+b''.join(i.to_bytes(8,'little') for i in (0, min(1,n), n)),
                (11).to_bytes(8,'little')]
            raw = b''.join(payloads)
            record = dict(plan.fields, sha256=sha256(raw).hexdigest(), segments=[
                dict(name=segment.name, offset=segment.offset, bytes=segment.size, sha256=sha256(data).hexdigest())
                for segment, data in zip(plan.segments,payloads,strict=True)])
            (self.directory/record['filename']).write_bytes(raw)
            self.raw[record['filename']] = raw
            files.append(record)
        self.collection = dict(check._identity(self.profile),
            schema='bitvm2-nova-matrix-collection/v1',
            matrix_profile_sha256=sha256(check._canonical(self.profile)).hexdigest(),
            encoding='bincode-1.3.3-legacy-fixed-little-endian',
            total_bytes=sum(record['bytes'] for record in files), files=files)
        self.manifest()

    def manifest(self, value=None):
        (self.directory/'collection.json').write_bytes(check._canonical(self.collection if value is None else value))

    def test_tiny_streams_match_all_hashes_and_never_confer_math_authority(self):
        # Reading the 1376-byte actual profile is allowed; no real CSR is read.
        _, _, profile = check._load_profile()
        plans = check._plans(profile)
        self.assertEqual(sum(p.fields['bytes'] for p in plans), 119674848)
        self.assertEqual(max(p.fields['bytes'] for p in plans), 50321224)
        with patch.object(check, 'CHUNK_BYTES', 7):
            rows = check._verify_directory(self.directory, self.collection, self.profile)
        self.assertEqual((len(rows), sum(row['bytes'] for row in rows)), (6,576))
        result = check._summary(rows, sha256(check._canonical(self.collection)).hexdigest(), '00'*32)
        self.assertEqual((result['native_proofs_verified'], result['source_native_proofs_verified']), (0,1))
        for flag in ('collection_independently_pinned', 'matrix_verification_enabled',
                     'matrix_polynomials_verified', 'csr_semantics_verified', 'proof_verified', 'bitcoin_script_verified'):
            self.assertIs(result[flag], False)

    def test_mutated_headers_data_truncation_and_appending_reject(self):
        name = check.FILENAMES[0]
        path, original = self.directory/name, self.raw[name]
        for segment in self.plans[0].segments:
            malformed = bytearray(original); malformed[segment.offset] ^= 1
            path.write_bytes(malformed)
            with self.assertRaisesRegex(ValueError, 'prefix/column'):
                check._verify_directory(self.directory,self.collection,self.profile)
        for malformed in (original[:8]+bytes([original[8]^1])+original[9:], original[:-1], original+b'\0'):
            path.write_bytes(malformed)
            with self.assertRaises(ValueError):
                check._verify_directory(self.directory,self.collection,self.profile)
        path.write_bytes(original)
        changed = deepcopy(self.collection); changed['files'][0]['sha256'] = '00'*32
        self.manifest(changed)
        with self.assertRaisesRegex(ValueError,'whole-file hash'):
            check._verify_directory(self.directory,changed,self.profile)

    def test_offsets_types_paths_extra_fields_and_budgets_fail_closed(self):
        variants = []
        for field, value in (('filename','../escape.bin'),('filename','/absolute.bin'),('data_len',True),('bytes',1.0)):
            changed=deepcopy(self.collection);changed['files'][0][field]=value;variants.append(changed)
        for field, value in (('offset',1),('bytes',0),('sha256','AB'*32)):
            changed=deepcopy(self.collection);changed['files'][0]['segments'][0][field]=value;variants.append(changed)
        changed=deepcopy(self.collection);changed['files'][0]['matrix_verified']=True;variants.append(changed)
        changed=deepcopy(self.collection);changed['files'].reverse();variants.append(changed)
        changed=deepcopy(self.collection);changed['files'][0]['segments'].reverse();variants.append(changed)
        for changed in variants:
            with self.assertRaises(ValueError):check._validate_collection(changed,self.profile)
        oversized=deepcopy(self.profile)
        for role in check.ROLES:
            curve=oversized[role];curve.update(num_vars=1<<24,evaluation_cols=1<<25)
            for matrix in check.MATRICES:
                curve['matrices'][matrix].update(data_len=2_000_000,indices_len=2_000_000,cols=1<<25)
        with self.assertRaisesRegex(ValueError,'64MiB'):check._plans(oversized)
        for role in check.ROLES:
            for matrix in check.MATRICES:
                oversized[role]['matrices'][matrix].update(data_len=1_000_000,indices_len=1_000_000)
        with self.assertRaisesRegex(ValueError,'160MiB'):check._plans(oversized)

    def test_directory_alias_links_inventory_and_manifest_tampering_reject(self):
        extra=self.directory/'unexpected';extra.write_bytes(b'x')
        with self.assertRaises(ValueError):check._verify_directory(self.directory,self.collection,self.profile)
        extra.unlink()
        with self.assertRaises(ValueError):check._directory(self.directory/'..'/self.directory.name)
        fake=SimpleNamespace(st_mode=stat.S_IFLNK|0o777,st_nlink=1)
        with patch.object(Path,'lstat',return_value=fake):
            with self.assertRaises(ValueError):check._directory(self.directory)
        fake=SimpleNamespace(st_mode=stat.S_IFREG|0o600,st_nlink=2)
        with patch.object(Path,'lstat',return_value=fake):
            with self.assertRaises(ValueError):check._no_link(self.directory/check.FILENAMES[0])
        (self.directory/'collection.json').write_bytes(check._canonical(self.collection)+b'\n')
        with self.assertRaises(ValueError):check._verify_directory(self.directory,self.collection,self.profile)

    def test_strict_json_and_hosted_resource_guard(self):
        for raw in (b'{"x":1,"x":1}',b'\xff',b'{"x":NaN}',b'{"x":1e400}',b'{"x":999999999999999999999}',
                    b'['*34+b'0'+b']'*34,b'x'*(check.COLLECTION_CAP+1)):
            with self.assertRaises(ValueError):check._strict_json(raw,check.COLLECTION_CAP)
        with patch.dict(os.environ,{},clear=True),patch.object(check,'_load_profile') as loader:
            with self.assertRaisesRegex(ValueError,'hosted'):
                check.run(Path('not-read'),self.directory)
            loader.assert_not_called()


if __name__ == '__main__':
    unittest.main()
