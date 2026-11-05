from copy import deepcopy
from dataclasses import replace
from hashlib import sha256
import json
from pathlib import Path
import struct
import unittest
from nht4 import (ARITY, HEADER_BYTES, HEADER_REVISION, KEY_PINS, MAX_BUNDLE_BYTES,
                  Q, ExpectedBundle, bind_container, decode_container,
                  genesis_initial_state, initial_state_bytes, load_expected_json)

FIXTURES = Path(__file__).resolve().parents[1]/'fixtures'


class RetainedHeaderContainer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = (FIXTURES/'nht4-genesis-0-2020-k5.nht4').read_bytes()
        cls.policy_raw = (FIXTURES/'nht4-genesis-0-2020-k5.expected.json').read_bytes()
        cls.expected = load_expected_json(cls.policy_raw)

    def test_real_retained_identity_and_independent_genesis(self):
        c = bind_container(self.raw, self.expected)
        self.assertEqual((c.network, c.k, c.steps), ('testnet4', 5, 404))
        self.assertEqual((len(self.raw), len(c.proof)), (13220, 12664))
        self.assertEqual(sha256(self.raw).hexdigest(), 'c3143d5627ef7291ab6a858b866a4ba19e356a168dea992d3e572ef6531904e9')
        self.assertEqual(sha256(initial_state_bytes(c.initial_state)).hexdigest(), '9c82dffe8b6005378775c8f2028b7644039defadb0fcc1d77820b7aaced6de9c')
        self.assertEqual(c.initial_state, genesis_initial_state('testnet4'))
        self.assertEqual(c.initial_state[0]+c.steps*c.k, 2020)
        self.assertFalse(c.summary()['proof_verified'])
        self.assertFalse(c.summary()['bitvm2_script_verified'])

    def test_all_truncations_and_surplus_reject_at_bound_entry(self):
        for length in range(len(self.raw)):
            with self.subTest(length=length):
                with self.assertRaises(ValueError):
                    bind_container(self.raw[:length], self.expected)
        for data in (b'\0'+self.raw, b'x'*32+self.raw, self.raw+b'\0', self.raw+b'x'*32):
            with self.assertRaises(ValueError):
                bind_container(data, self.expected)

    def test_each_initial_scalar_is_bound(self):
        for i in range(ARITY):
            data = bytearray(self.raw)
            data[12+i*32] ^= 1
            with self.subTest(scalar=i), self.assertRaises(ValueError):
                bind_container(bytes(data), self.expected)

    def test_noncanonical_and_declared_widths(self):
        widths = (32, 128, 128, 200)+(32,)*13
        for i, bits in enumerate(widths):
            for value in (1 << bits, Q, (1 << 256)-1):
                data = bytearray(self.raw)
                data[12+32*i:44+32*i] = value.to_bytes(32, 'little')
                with self.subTest(scalar=i, value=value), self.assertRaises(ValueError):
                    decode_container(bytes(data))

    def test_header_and_proof_mutations(self):
        for offset, replacement in ((0, b'NHC1'), (0, b'BAD!'), (4, struct.pack('<I', 0)),
                                    (4, struct.pack('<I', 405)), (8, struct.pack('<I', 0)),
                                    (8, struct.pack('<I', 10)), (8, struct.pack('<I', 65))):
            data = self.raw[:offset]+replacement+self.raw[offset+len(replacement):]
            with self.assertRaises(ValueError):
                bind_container(data, self.expected)
        for i in (HEADER_BYTES, len(self.raw)//2, len(self.raw)-1):
            data = bytearray(self.raw)
            data[i] ^= 1
            with self.assertRaises(ValueError):
                bind_container(bytes(data), self.expected)

    def test_bounded_bytes_and_no_implicit_coercions(self):
        for data in (b'', self.raw[:HEADER_BYTES], b'x'*(MAX_BUNDLE_BYTES+1),
                     bytearray(self.raw), memoryview(self.raw), self.raw.hex(), None):
            with self.assertRaises(ValueError):
                decode_container(data)
        for expected in (self.expected.json(), None):
            with self.assertRaises(ValueError):
                bind_container(self.raw, expected)

    def test_policy_round_trip_and_exact_schema(self):
        self.assertEqual(ExpectedBundle.from_json(self.expected.json()), self.expected)
        mutations = [('schema', 'bad'), ('extra', 1), ('k', True), ('k', 5.0), ('steps', 0),
                     ('checkpoint_origin', 'proof_supplied'), ('nova_version', '0.75.0'),
                     ('header_revision', '0'*40), ('initial_state_le', []),
                     ('bundle_bytes', len(self.raw)+1), ('proof_bytes', 0),
                     ('proof_sha256', 'ff'*31), ('bundle_sha256', 'AA'*32)]
        for key, value in mutations:
            policy = deepcopy(self.expected.json())
            policy[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                ExpectedBundle.from_json(policy)
        for key in self.expected.json():
            policy = deepcopy(self.expected.json())
            del policy[key]
            with self.subTest(missing=key), self.assertRaises(ValueError):
                ExpectedBundle.from_json(policy)

    def test_duplicate_malformed_and_oversized_json_reject(self):
        duplicate = self.policy_raw.rstrip()[:-1]+b',"k":5}'
        for raw in (duplicate, b'{', b'\xff', self.policy_raw.decode().encode('utf-16'),
                    b'{} '+b' '*8192, b'[]', b'null',
                    b'['*1001+b'0'+b']'*1001):
            with self.assertRaises(ValueError):
                load_expected_json(raw)

    def test_policy_network_key_genesis_and_height_constraints(self):
        for changes in ({'network': 'mainnet'}, {'k': 10}, {'verifier_key_sha256': bytes(32)},
                        {'verifier_key_sha256': KEY_PINS[('mainnet', 10)]},
                        {'initial_state': (1,)+self.expected.initial_state[1:]},
                        {'steps': (1 << 32)-1}, {'network': 'testnet3'}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                replace(self.expected, **changes)
        with self.assertRaises(ValueError):
            replace(self.expected, network='mainnet', checkpoint_origin='operator_pinned')
        self.assertNotEqual(genesis_initial_state('mainnet'), self.expected.initial_state)
        with self.assertRaises(ValueError):
            genesis_initial_state('testnet3')

    def test_opaque_framing_never_becomes_a_proof_claim(self):
        # NHT4 has no inner length marker. An arbitrary opaque proof can be framed
        # and hash-bound; only the separate native Nova verifier establishes validity.
        data = self.raw[:HEADER_BYTES]+b'not a Nova proof'
        policy = replace(self.expected, proof_bytes=len(data)-HEADER_BYTES,
                         proof_sha256=sha256(data[HEADER_BYTES:]).digest(),
                         bundle_bytes=len(data), bundle_sha256=sha256(data).digest())
        self.assertFalse(bind_container(data, policy).summary()['proof_verified'])
        self.assertEqual(decode_container(data+b'\0').proof, b'not a Nova proof\0')
        with self.assertRaises(ValueError):
            bind_container(data+b'\0', policy)
        # A framing check cannot authenticate the claimed end state either.
        changed_end = replace(self.expected, end_state_sha256=bytes(32))
        self.assertFalse(bind_container(self.raw, changed_end).summary()['proof_verified'])

    def test_mainnet_magic_and_explicit_pinned_checkpoint_framing(self):
        state = genesis_initial_state('mainnet')
        data = b'NHC1'+struct.pack('<II', 1, 10)+initial_state_bytes(state)+b'opaque'
        policy = replace(self.expected, network='mainnet', k=10, steps=1,
                         initial_state=state, verifier_key_sha256=KEY_PINS[('mainnet', 10)],
                         proof_bytes=6, bundle_bytes=len(data),
                         proof_sha256=sha256(b'opaque').digest(), bundle_sha256=sha256(data).digest())
        self.assertEqual(bind_container(data, policy).network, 'mainnet')
        checkpoint = replace(policy, checkpoint_origin='operator_pinned')
        self.assertEqual(bind_container(data, checkpoint).initial_state, state)

    def test_generated_native_cases_have_reference_expectations(self):
        from bench_nht4 import cases
        rows = cases()
        self.assertEqual(len(rows), 23)
        self.assertEqual(sum(x['accept'] for x in rows), 1)
        self.assertEqual(len({x['name'] for x in rows}), len(rows))


if __name__ == '__main__':
    unittest.main()
