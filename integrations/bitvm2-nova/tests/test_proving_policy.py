"""Tiny policy/data tests only: no process, native build, or proving evidence."""
from dataclasses import FrozenInstanceError, replace
from hashlib import sha1, sha256
import copy
import json
from pathlib import Path
import tempfile
import unittest

import proving_policy as policy
from nht4 import KEY_PINS, genesis_initial_state, initial_state_bytes


def _record(relative, data, mode='100644'):
    blob = sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()
    return policy.VerifiedSourceFile(policy.PACKAGE_PREFIX+relative, mode, blob, sha256(data).digest(), len(data))


def _point(state):
    raw = state[1].to_bytes(16, 'little')+state[2].to_bytes(16, 'little')
    return {'height': state[0], 'tip_hash': raw[::-1].hex(), 'chainwork': hex(state[3])}


def _receipt(shard, initial, end, key, proof, network='testnet4'):
    result = {'statement': 'btc_header_chain_testnet4_v1' if network == 'testnet4' else 'btc_header_chain_v1',
              'verifier': policy.NATIVE_VERIFIER, 'vk_sha256': key.hex(), 'proof_sha256': proof.hex(),
              'checkpoint_state_sha256': sha256(initial_state_bytes(initial)).hexdigest(),
              'end_state_sha256': sha256(initial_state_bytes(end)).hexdigest(),
              'checkpoint': _point(initial), 'end': _point(end), 'headers': shard.headers,
              'verify_seconds': 0.125, 'verified': True}
    if network == 'testnet4':
        result['network'] = network
    return result


class ProvingPlanTests(unittest.TestCase):
    def test_pilot_and_floor_aligned_partition(self):
        plan = policy.plan_shards(k=10, to_height=40, header_count=2101,
                                  shards=2, parallel=2, threads=2, memory_mib=6144)
        self.assertEqual([(s.start_height, s.end_height, s.steps) for s in plan.ranges],
                         [(0, 20, 2), (20, 40, 2)])
        uneven = policy.plan_shards(k=5, to_height=35, header_count=36,
                                    shards=3, parallel=1, threads=1, memory_mib=1)
        self.assertEqual([(s.start_height, s.end_height) for s in uneven.ranges], [(0, 10), (10, 20), (20, 35)])
        self.assertEqual(sum(s.headers for s in uneven.ranges), 35)
        self.assertEqual(plan.ranges[1].first_height, 21)
        self.assertEqual(plan.summary()['proving_jobs_launched'], 0)
        with self.assertRaises(FrozenInstanceError):
            plan.k = 5
        with self.assertRaises(TypeError):
            policy.ProvingPlan()

    def test_typed_budgets_and_alignment(self):
        valid = dict(k=10, to_height=40, header_count=41, shards=2, parallel=2, threads=2, memory_mib=6144)
        changes = [('k', True), ('k', 0), ('k', 65), ('to_height', 41), ('to_height', 0),
                   ('to_height', 39), ('header_count', 40), ('header_count', True), ('shards', 5),
                   ('shards', False), ('parallel', 3), ('parallel', 0), ('threads', 0),
                   ('threads', 257), ('memory_mib', 0), ('memory_mib', 1 << 21)]
        for field, value in changes:
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                policy.plan_shards(**(valid | {field: value}))
        maximum = policy.plan_shards(k=1, to_height=policy.U32_MAX, header_count=policy.U32_MAX+1,
                                     shards=1, parallel=1, threads=1, memory_mib=1)
        self.assertEqual(maximum.total_steps, policy.U32_MAX)


class SourcePolicyTests(unittest.TestCase):
    def test_git_object_goldens_and_nested_modes(self):
        self.assertEqual(policy._git_tree(()), '4b825dc642cb6eb9a060e54bf8d69288fbee4904')
        record = _record('hello', b'hello\n')
        self.assertEqual(record.git_blob, 'ce013625030ba8dba906f756967f9e9ca394464a')
        leaf_body = b'100755 hello\0'+bytes.fromhex(record.git_blob)
        subtree = sha1(b'tree '+str(len(leaf_body)).encode()+b'\0'+leaf_body).digest()
        root_body = b'40000 sub\0'+subtree
        expected = sha1(b'tree '+str(len(root_body)).encode()+b'\0'+root_body).hexdigest()
        self.assertEqual(policy._git_tree((_record('sub/hello', b'hello\n', '100755'),)), expected)
        self.assertNotEqual(policy._git_tree((record,)), policy._git_tree((replace(record, mode='100755'),)))

    def test_tiny_file_authentication_and_generated_lock(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            root = Path(directory)
            (root/'src').mkdir()
            (root/'src'/'a.rs').write_bytes(b'hello\n')
            records = (_record('src/a.rs', b'hello\n'),)
            tree, lock = policy._check_package_files(root, records)
            self.assertEqual(tree, policy._git_tree(records))
            self.assertIsNone(lock)
            (root/'Cargo.lock').write_bytes(b'generated test lock')
            _, lock = policy._check_package_files(root, records)
            self.assertEqual(lock[:2], (19, sha256(b'generated test lock').digest()))
            (root/'src'/'a.rs').write_bytes(b'other\n')
            with self.assertRaises(ValueError):
                policy._check_package_files(root, records)

    def test_extra_files_directories_missing_and_case_collision(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            root = Path(directory)
            (root/'a').write_bytes(b'a')
            records = (_record('a', b'a'),)
            (root/'proof.bin').write_bytes(b'proof')
            with self.assertRaises(ValueError):
                policy._check_package_files(root, records)
            (root/'proof.bin').unlink()
            (root/'target').mkdir()
            with self.assertRaises(ValueError):
                policy._check_package_files(root, records)
            (root/'target').rmdir()
            (root/'a').unlink()
            with self.assertRaises(ValueError):
                policy._check_package_files(root, records)
            with self.assertRaises(ValueError):
                policy._check_package_files(root, (records[0], _record('A', b'a')))

    def test_path_rejection_and_literal_manifest_authority(self):
        for relative in ('../a', '/a', 'x//a', 'x/./a', 'x\\a', 'x:a'):
            with self.subTest(relative=relative), self.assertRaises(ValueError):
                policy._relative_path(policy.PACKAGE_PREFIX+relative)
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            root = Path(directory)
            manifest = {'repository': policy.REPOSITORY, 'revision': policy.HEADER_REVISION,
                        'git_subtree_sha': policy.PACKAGE_TREE_SHA, 'files': []}
            (root/'source-manifest.json').write_text(json.dumps(manifest), encoding='utf-8')
            with self.assertRaisesRegex(ValueError, '49 files'):
                policy.verify_source_package(root)
            (root/'source-manifest.json').write_bytes(b'{"repository":"x","repository":"x"}')
            with self.assertRaisesRegex(ValueError, 'duplicate'):
                policy.verify_source_package(root)
            # The literal tree field alone cannot authorize 49 substituted files.
            entries = []
            for index in range(49):
                record = _record(f'substitute-{index}', b'x')
                entries.append({'path': record.path, 'mode': record.mode, 'git_blob': record.git_blob,
                                'sha256': record.sha256.hex(), 'bytes': record.bytes})
            manifest['files'] = entries
            (root/'source-manifest.json').write_text(json.dumps(manifest), encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'literal Git tree'):
                policy.verify_source_package(root)
        with self.assertRaises(TypeError):
            policy.VerifiedSourcePackage()


class NativeReceiptPolicyTests(unittest.TestCase):
    def setUp(self):
        self.plan = policy.plan_shards(k=10, to_height=40, header_count=41,
                                      shards=2, parallel=2, threads=2, memory_mib=6144)
        self.key = KEY_PINS[('testnet4', 10)]
        self.proof, self.headers = sha256(b'test-only proof').digest(), sha256(b'test-only headers').digest()
        self.genesis = genesis_initial_state('testnet4')
        middle = list(self.genesis)
        middle[0], middle[3], middle[-1] = 20, middle[3]+20, middle[-1]+20
        end = list(middle)
        end[0], end[3], end[-1] = 40, end[3]+20, end[-1]+20
        self.middle, self.end = tuple(middle), tuple(end)

    def checked(self, index, initial, end, *, receipt=None, **changes):
        shard = self.plan.ranges[index]
        if receipt is None:
            receipt = _receipt(shard, initial, end, self.key, self.proof)
        values = dict(shard=shard, k=10, network='testnet4', verifier_key_sha256=self.key,
                      proof_sha256=self.proof, initial_state=initial, end_state=end, headers_sha256=self.headers)
        return policy.validate_native_receipt(receipt, **(values | changes))

    def test_full_state_and_continuity_data_only(self):
        first = self.checked(0, self.genesis, self.middle)
        second = self.checked(1, self.middle, self.end)
        result = policy.validate_shard_continuity(self.plan, (first, second), network='testnet4',
                                                  verifier_key_sha256=self.key, expected_headers_sha256=self.headers)
        self.assertTrue(result.summary()['full_state_continuity_checked'])
        self.assertFalse(result.summary()['proof_verified'])
        self.assertFalse(first.summary()['process_execution_authenticated'])
        raw_receipt = _receipt(self.plan.ranges[0], self.genesis, self.middle, self.key, self.proof)
        self.assertEqual(self.checked(0, initial_state_bytes(self.genesis), initial_state_bytes(self.middle),
                                      receipt=raw_receipt), first)
        with self.assertRaises(TypeError):
            policy.CheckedShardReceipt()
        with self.assertRaises(FrozenInstanceError):
            first.k = 5

    def test_full_state_continuity_includes_hidden_timestamp_and_genesis(self):
        first = self.checked(0, self.genesis, self.middle)
        changed = list(self.middle)
        changed[7] ^= 1  # Same height, tip and work; distinct full public state.
        second = self.checked(1, tuple(changed), self.end)
        with self.assertRaisesRegex(ValueError, '17-scalar'):
            policy.validate_shard_continuity(self.plan, (first, second), network='testnet4',
                                             verifier_key_sha256=self.key, expected_headers_sha256=self.headers)
        changed = list(self.genesis)
        changed[8] ^= 1
        non_genesis = self.checked(0, tuple(changed), self.middle)
        with self.assertRaisesRegex(ValueError, 'genesis'):
            policy.validate_shard_continuity(self.plan, (non_genesis, self.checked(1, self.middle, self.end)),
                                             network='testnet4', verifier_key_sha256=self.key,
                                             expected_headers_sha256=self.headers)

    def test_receipt_mutations_types_digests_widths(self):
        base = _receipt(self.plan.ranges[0], self.genesis, self.middle, self.key, self.proof)
        mutations = {'verified': 1, 'headers': True, 'vk_sha256': '0'*64, 'proof_sha256': '0'*64,
                     'checkpoint_state_sha256': '0'*64, 'end_state_sha256': '0'*64,
                     'network': 'mainnet', 'statement': 'btc_header_chain_v1',
                     'verifier': 'other', 'verify_seconds': float('inf')}
        for field, value in mutations.items():
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.checked(0, self.genesis, self.middle, receipt=base | {field: value})
        for field, value in (('height', True), ('tip_hash', '0'*64), ('chainwork', '0x00')):
            changed = copy.deepcopy(base)
            changed['checkpoint'][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.checked(0, self.genesis, self.middle, receipt=changed)
        for state in (list(self.genesis), initial_state_bytes(self.genesis)[:-1], self.genesis[:-1]):
            with self.assertRaises(ValueError):
                self.checked(0, state, self.middle)
        wide = list(self.genesis)
        wide[4] = 1 << 32
        with self.assertRaises(ValueError):
            self.checked(0, tuple(wide), self.middle, receipt=base)

    def test_order_source_key_binding_and_unknown_k(self):
        first, second = self.checked(0, self.genesis, self.middle), self.checked(1, self.middle, self.end)
        for receipts, headers in (((second, first), self.headers), ((first, second), bytes(32)), ((first,), self.headers)):
            with self.assertRaises(ValueError):
                policy.validate_shard_continuity(self.plan, receipts, network='testnet4',
                                                 verifier_key_sha256=self.key, expected_headers_sha256=headers)
        shard = policy.ShardRange(0, 20, 0, 20, 1)
        key = sha256(b'test-only cold reconstructed key').digest()
        receipt = _receipt(shard, self.genesis, self.middle, key, self.proof)
        args = dict(shard=shard, k=20, network='testnet4', verifier_key_sha256=key,
                    proof_sha256=self.proof, initial_state=self.genesis, end_state=self.middle, headers_sha256=self.headers)
        with self.assertRaises(ValueError):
            policy.validate_native_receipt(receipt, **args)
        checked = policy.validate_native_receipt(receipt, **args, cold_reconstructed_vk_sha256=key)
        self.assertEqual(checked.k, 20)
        with self.assertRaisesRegex(ValueError, 'belongs to another'):
            policy.validate_native_receipt(receipt | {'vk_sha256': self.key.hex()},
                                            **(args | {'verifier_key_sha256': self.key}),
                                            cold_reconstructed_vk_sha256=self.key)

    def test_shard_k_bool_and_mainnet_schema(self):
        key = sha256(b'test-only k1 key').digest()
        shard = policy.ShardRange(0, True, 0, 1, 1)
        end = (1,)+self.genesis[1:]
        receipt = _receipt(shard, self.genesis, end, key, self.proof)
        with self.assertRaisesRegex(ValueError, 'shard k'):
            policy.validate_native_receipt(receipt, shard=shard, k=1, network='testnet4',
                verifier_key_sha256=key, proof_sha256=self.proof, initial_state=self.genesis,
                end_state=end, headers_sha256=self.headers, cold_reconstructed_vk_sha256=key)
        genesis = genesis_initial_state('mainnet')
        end = (20,)+genesis[1:]
        key = KEY_PINS[('mainnet', 10)]
        shard = self.plan.ranges[0]
        receipt = _receipt(shard, genesis, end, key, self.proof, network='mainnet')
        checked = policy.validate_native_receipt(receipt, shard=shard, k=10, network='mainnet',
            verifier_key_sha256=key, proof_sha256=self.proof, initial_state=genesis,
            end_state=end, headers_sha256=self.headers)
        self.assertEqual(checked.network, 'mainnet')
        with self.assertRaisesRegex(ValueError, 'schema'):
            policy.validate_native_receipt(receipt | {'network': 'mainnet'}, shard=shard, k=10,
                network='mainnet', verifier_key_sha256=key, proof_sha256=self.proof,
                initial_state=genesis, end_state=end, headers_sha256=self.headers)


if __name__ == '__main__':
    unittest.main()
