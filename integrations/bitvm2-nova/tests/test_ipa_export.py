"""Tiny synthetic generator file tests; no actual generator vectors are read."""
from copy import deepcopy
from hashlib import sha256
import os
from pathlib import Path
import stat
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import bench_ipa_export as check


def collection_for(plans, payloads=None):
    """Test-only records; arbitrary point bytes do not claim valid encodings."""
    records = []
    for plan in plans:
        prefix = plan.fields['count'].to_bytes(8, 'little')
        data = None if payloads is None else payloads[plan.fields['filename']]
        records.append(dict(plan.fields,
            sha256='00'*32 if data is None else sha256(data).hexdigest(),
            segments=[dict(name='count', offset=0, bytes=8, sha256=sha256(prefix).hexdigest()),
                dict(name='points', offset=8, bytes=32*plan.fields['count'],
                    sha256='00'*32 if data is None else sha256(data[8:]).hexdigest())]))
    return dict(check.IDENTITY, schema='bitvm2-nova-ipa-generators/v1',
        encoding='bincode-1.3.3-legacy-fixed-little-endian',
        total_bytes=sum(record['bytes'] for record in records), files=records)


class IpaExport(unittest.TestCase):
    def setUp(self):
        owned = (check.FIXTURES.parent/'results').resolve()
        owned.mkdir(exist_ok=True)
        self.temp = TemporaryDirectory(prefix='tiny-ipa-export-test-', dir=owned)
        base = Path(self.temp.name).resolve()
        self.assertTrue(base.is_relative_to(owned))
        self.addCleanup(self.temp.cleanup)
        self.directory = base/'toy-generators'
        self.directory.mkdir()
        self.plans = check._plans((3,2))
        self.raw = {}
        for plan in self.plans:
            # TEST-ONLY arbitrary bytes. This checker does no point decoding.
            count = plan.fields['count']
            raw = count.to_bytes(8,'little')+bytes(range(32))*count
            name = plan.fields['filename']
            self.raw[name] = raw
            (self.directory/name).write_bytes(raw)
        self.collection = collection_for(self.plans, self.raw)
        self.manifest()

    def manifest(self, value=None):
        (self.directory/'collection.json').write_bytes(
            check._canonical(self.collection if value is None else value))

    def test_tiny_streams_and_pinned_metadata_never_confer_math_authority(self):
        # Only the small policy/dimension fixtures are read, not real payloads.
        _, _, actual = check._load_policy()
        self.assertEqual([plan.fields['count'] for plan in actual], [524288,16384])
        self.assertEqual([plan.fields['bytes'] for plan in actual], [16777224,524296])
        self.assertEqual(sum(plan.fields['bytes'] for plan in actual), 17301520)
        with patch.object(check,'CHUNK_BYTES',7):
            rows = check._verify_directory(self.directory,self.collection,self.plans)
        self.assertEqual((len(rows),sum(row['bytes'] for row in rows)), (2,176))
        result = check._summary(rows,sha256(check._canonical(self.collection)).hexdigest(),'00'*32)
        self.assertEqual((result['source_native_proofs_verified'],result['native_proofs_verified']),(1,0))
        self.assertEqual((result['segment_hashes_checked'],result['count_prefixes_checked']),(4,2))
        for flag in ('collection_independently_pinned','point_encodings_verified',
            'generator_derivation_verified','msm_verified','ipa_verified','proof_verified','bitcoin_script_verified'):
            self.assertIs(result[flag],False)

    def test_prefix_points_hash_mutations_and_exact_eof(self):
        path = self.directory/check.FILENAMES[0]
        original = self.raw[path.name]
        variants = [bytes([original[0]^1])+original[1:],
            original[:8]+bytes([original[8]^1])+original[9:],original[:-1],original+b'\0']
        for raw in variants:
            path.write_bytes(raw)
            with self.assertRaises(ValueError):
                check._verify_directory(self.directory,self.collection,self.plans)
        path.write_bytes(original)
        for section in (None,0,1):
            changed = deepcopy(self.collection)
            target = changed['files'][0] if section is None else changed['files'][0]['segments'][section]
            target['sha256'] = 'ff'*32
            self.manifest(changed)
            with self.assertRaisesRegex(ValueError,'hash mismatch'):
                check._verify_directory(self.directory,changed,self.plans)
        self.manifest()

    def test_collection_order_types_offsets_roles_paths_and_budgets(self):
        mutations = []
        for name,value in (('filename','../escape.bin'),('filename','/absolute.bin'),
            ('count',True),('bytes',1.0),('engine','vesta'),('base_field_role','pallas_scalar')):
            changed=deepcopy(self.collection);changed['files'][0][name]=value;mutations.append(changed)
        for name,value in (('offset',1),('bytes',0),('name','count'),('sha256','AB'*32)):
            changed=deepcopy(self.collection);changed['files'][0]['segments'][1][name]=value;mutations.append(changed)
        changed=deepcopy(self.collection);changed['files'][0]['ipa_verified']=True;mutations.append(changed)
        changed=deepcopy(self.collection);changed['files'].reverse();mutations.append(changed)
        changed=deepcopy(self.collection);changed['files'][0]['segments'].reverse();mutations.append(changed)
        changed=deepcopy(self.collection);changed['total_bytes']=True;mutations.append(changed)
        changed=deepcopy(self.collection);changed['k']=True;mutations.append(changed)
        for changed in mutations:
            with self.assertRaises(ValueError):check._validate_collection(changed,self.plans)
        for counts in ((True,2),(0,2),[3,2],(1<<24,2)):
            with self.assertRaises(ValueError):check._plans(counts)
        with self.assertRaisesRegex(ValueError,'file exceeds'):check._plans((1048576,1))
        with self.assertRaisesRegex(ValueError,'total exceeds'):check._plans((600000,600000))

    def test_inventory_aliases_links_canonical_manifest_and_read_budget(self):
        extra=self.directory/'unexpected';extra.write_bytes(b'x')
        with self.assertRaises(ValueError):check._verify_directory(self.directory,self.collection,self.plans)
        extra.unlink()
        with self.assertRaises(ValueError):check._directory(self.directory/'..'/self.directory.name)
        fake=SimpleNamespace(st_mode=stat.S_IFLNK|0o777,st_nlink=1)
        with patch.object(Path,'lstat',return_value=fake):
            with self.assertRaises(ValueError):check._directory(self.directory)
        fake=SimpleNamespace(st_mode=stat.S_IFREG|0o600,st_nlink=2)
        with patch.object(Path,'lstat',return_value=fake):
            with self.assertRaises(ValueError):check._no_link(self.directory/check.FILENAMES[0])
        (self.directory/'collection.json').write_bytes(check._canonical(self.collection)+b'\n')
        with self.assertRaises(ValueError):check._verify_directory(self.directory,self.collection,self.plans)
        with self.assertRaisesRegex(ValueError,'byte budget'):check._read(self.directory/check.FILENAMES[0],1)

    def test_strict_json_and_hosted_resource_guard_precedes_io(self):
        for raw in (b'{"x":1,"x":1}',b'\xff',b'{"x":NaN}',b'{"x":1e400}',
            b'{"x":999999999999999999999}',b'['*34+b'0'+b']'*34,b'x'*(check.COLLECTION_CAP+1)):
            with self.assertRaises(ValueError):check._strict_json(raw,check.COLLECTION_CAP)
        with patch.dict(os.environ,{},clear=True),patch.object(check,'_load_policy') as loader:
            with self.assertRaisesRegex(ValueError,'hosted'):check.run(Path('not-read'),self.directory)
            loader.assert_not_called()

    def test_native_report_identity_counters_booleans_and_transport(self):
        expected,dims,plans=check._load_policy()
        collection=collection_for(plans)  # Metadata only: no actual vector allocated.
        report={'schema':'bitvm2-nova-native-production-replay/v1','passed':True,
            'native_nova_proofs_verified':1,'network':expected.network,'k':expected.k,
            'steps':expected.steps,'nova_version':expected.nova_version,
            'header_revision':expected.header_revision,'bundle_sha256':expected.bundle_sha256.hex(),
            'proof_sha256':expected.proof_sha256.hex(),'proof_bytes':expected.proof_bytes,
            'verifier_key_sha256':check.VK_PIN,'verifier_dimensions_sha256':check.DIMENSION_PIN,
            'verifier_dimensions':dims.json(),'end_state_sha256':expected.end_state_sha256.hex(),
            'end_height':2020,'setup_calls':1,'proving_jobs':0,'transactions_broadcast':0,
            'bitcoin_script_verified':False,'independent_poseidon_verification':False,
            'complete_bitvm2_verifier':False,'ipa_generators':collection,
            'ipa_generators_sha256':sha256(check._canonical(collection)).hexdigest(),
            'ipa_generator_export':dict(files_written=2,total_bytes=check.EXPECTED_TOTAL_BYTES,
                selected_generator_fields=2,skipped_fields=13,per_file_cap_bytes=check.FILE_CAP,
                total_cap_bytes=check.TOTAL_CAP,writer_buffer_bytes=65536,
                full_key_materialized=False,generator_vectors_materialized=False),
            'ipa_generator_export_seconds':0.1,
            'diagnostic_extra_claim':{'proof_verified':True}}
        accepted,digest=check._source_collection(check._strict_json(check._canonical(report),check.REPORT_CAP),expected,dims,plans)
        self.assertEqual(accepted,collection)
        self.assertEqual(digest,report['ipa_generators_sha256'])
        mutations=[]
        for name,values in {'native_nova_proofs_verified':(True,0),'passed':(1,False),
            'bitcoin_script_verified':(0,True),'independent_poseidon_verification':(0,True),
            'complete_bitvm2_verifier':(0,True),'proving_jobs':(False,1),
            'transactions_broadcast':(False,1),'ipa_generator_export_seconds':(True,-1,float('inf')),
            'verifier_dimensions_sha256':('00'*32,)}.items():
            for value in values:
                changed=deepcopy(report);changed[name]=value;mutations.append(changed)
        for name in ('full_key_materialized','generator_vectors_materialized'):
            for value in (0,True):
                changed=deepcopy(report);changed['ipa_generator_export'][name]=value;mutations.append(changed)
        changed=deepcopy(report);del changed['ipa_generators'];mutations.append(changed)
        changed=deepcopy(report);changed['verifier_dimensions']['primary']['ck_v_generators']-=1;mutations.append(changed)
        for changed in mutations:
            with self.assertRaises(ValueError):check._source_collection(changed,expected,dims,plans)


if __name__ == '__main__':
    unittest.main()
