"""Admission tests using an independently exported and pinned VK descriptor.

Synthetic profile mutations are explicitly test-owned inputs. The production
shaped fixture is authenticated by a literal digest outside its editable JSON.
"""
from copy import deepcopy
from dataclasses import FrozenInstanceError
from hashlib import sha256
import json
from pathlib import Path
import unittest

from nht4 import HEADER_BYTES, load_expected_json
from proof_codec import (BASE_MODULI, SCALAR_MODULI, MAX_PROOF_BYTES,
                         DecodedProof, VerifierDimensions, decode_point,
                         decode_proof, encode_proof, load_dimensions_json)

FIXTURES = Path(__file__).resolve().parents[1]/'fixtures'
PINNED_DESCRIPTOR_SHA256 = bytes.fromhex(
    'de6333df2e41b5f5bae1c103fab862f8d6022fd54abeb80ba61920bc9f360edc')


def descriptor_pin(data):
    return sha256(json.dumps(data, sort_keys=True, separators=(',', ':'),
                             ensure_ascii=True).encode()).digest()


class ProofCodec(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.expected = load_expected_json((FIXTURES/'nht4-genesis-0-2020-k5.expected.json').read_bytes())
        cls.pin = PINNED_DESCRIPTOR_SHA256
        cls.dimensions = load_dimensions_json(
            (FIXTURES/'nht4-genesis-0-2020-k5.dimensions.json').read_bytes(), cls.expected,
            expected_descriptor_sha256=cls.pin)
        cls.descriptor = cls.dimensions.json()
        cls.raw = (FIXTURES/'nht4-genesis-0-2020-k5.nht4').read_bytes()[HEADER_BYTES:]
        cls.proof = decode_proof(cls.raw, cls.dimensions)

    def mutated(self, span, replacement):
        return self.raw[:span.start]+replacement+self.raw[span.start+span.size:]

    def test_retained_layout_roundtrip_without_proof_verification_claim(self):
        self.assertEqual(encode_proof(self.proof), self.raw)
        self.assertEqual(self.proof.proof_bytes, 12664)
        self.assertEqual(self.proof.proof_sha256.hex(),
            '2137c6e8621cedb7423e0ef7f9ff7c27b2c6fdf3ceb227e644b3d9660d056617')
        self.assertFalse(self.proof.summary()['proof_verified'])
        self.assertFalse(self.proof.summary()['bitvm2_script_verified'])
        self.assertEqual(len(self.proof.spans), 485)
        self.assertEqual([s.start for s in self.proof.spans], sorted(s.start for s in self.proof.spans))
        self.assertEqual(sum(s.size for s in self.proof.spans), len(self.raw))
        value = self.proof.value
        self.assertEqual(len(value['r_U_secondary']['X']), 2)
        self.assertEqual(len(value['snark_primary']['sc_proof_outer']['compressed_polys']), 19)
        self.assertEqual(len(value['snark_secondary']['sc_proof_inner']['compressed_polys']), 15)
        self.assertEqual(int.from_bytes(bytes.fromhex(value['zn'][0]), 'little'), 2020)
        self.assertIsNone(value['_p'])

    def test_descriptor_requires_independent_digest_and_owned_identity(self):
        forged = deepcopy(self.descriptor)
        forged['primary']['ck_v_generators'] += 1
        self.assertEqual(forged['verifier_key_sha256'], self.descriptor['verifier_key_sha256'])
        with self.assertRaisesRegex(ValueError, 'digest mismatch'):
            VerifierDimensions.from_json(forged, self.expected, expected_descriptor_sha256=self.pin)
        for pin in (None, self.pin.hex(), self.pin[:-1], bytearray(self.pin)):
            with self.assertRaises(ValueError):
                VerifierDimensions.from_json(self.descriptor, self.expected, expected_descriptor_sha256=pin)
        for field, bad in (('schema', 'other'), ('nova_version', '0.75.0'),
                           ('network', 'mainnet'), ('k', 10), ('k', True),
                           ('header_revision', '0'*40), ('verifier_key_sha256', '0'*64),
                           ('outer_arity', 16), ('nova_crate_sha256', '0'*64),
                           ('extra', 1)):
            data = deepcopy(self.descriptor)
            data[field] = bad
            with self.subTest(field=field), self.assertRaises(ValueError):
                VerifierDimensions.from_json(data, self.expected,
                                               expected_descriptor_sha256=descriptor_pin(data))
        with self.assertRaises(ValueError):
            VerifierDimensions.from_json(self.descriptor, self.expected.json(),
                                           expected_descriptor_sha256=self.pin)

    def test_descriptor_transport_rejects_duplicates_malformed_and_depth(self):
        raw = json.dumps(self.descriptor).encode()
        loaded = load_dimensions_json(raw, self.expected, expected_descriptor_sha256=self.pin)
        self.assertEqual(loaded, self.dimensions)
        duplicate = raw[:-1]+b',"outer_arity":17}'
        for bad in (duplicate, b'{', b'\xff', b'{"primary":NaN}',
                    b'['*2000+b'0'+b']'*2000, b'x'*(16384+1), raw.decode()):
            with self.assertRaises(ValueError):
                load_dimensions_json(bad, self.expected, expected_descriptor_sha256=self.pin)
        nested = deepcopy(self.descriptor)
        nested['primary'] = []
        for _ in range(2000):
            nested['primary'] = [nested['primary']]
        with self.assertRaises(ValueError):
            VerifierDimensions.from_json(nested, self.expected, expected_descriptor_sha256=self.pin)

    def test_dimension_guards_precede_proof_parsing(self):
        mutations = [('num_cons', 3), ('num_vars', 4), ('num_io', 3),
                     ('outer_rounds', True), ('inner_rounds', 1), ('ipa_rounds', 32),
                     ('ipa_dimension', 1 << 25), ('ck_v_generators', 1),
                     ('ck_s_generators', 0), ('engine', 'vesta')]
        for key, value in mutations:
            data = deepcopy(self.descriptor)
            data['primary'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                VerifierDimensions.from_json(data, self.expected,
                                               expected_descriptor_sha256=descriptor_pin(data))
        # Independently owned synthetic nonsquare shapes remain supported;
        # they cannot be substituted for the real fixture under its fixed pin.
        nonsquare = deepcopy(self.descriptor)
        nonsquare['primary']['num_cons'] = 1 << 18
        nonsquare['primary']['outer_rounds'] = 18
        dimensions = VerifierDimensions.from_json(nonsquare, self.expected,
            expected_descriptor_sha256=descriptor_pin(nonsquare))
        self.assertNotEqual(dimensions.primary.num_cons, dimensions.primary.num_vars)
        with self.assertRaises(ValueError):
            decode_proof(self.raw, dimensions)
        for bad in (0, 7, 15, 1 << 25, True):
            data = deepcopy(self.descriptor)
            data['max_ipa_dimension'] = bad
            with self.assertRaises(ValueError):
                VerifierDimensions.from_json(data, self.expected,
                                               expected_descriptor_sha256=descriptor_pin(data))

    def test_types_budgets_and_immutable_admitted_objects(self):
        for bad in (None, self.raw.hex(), bytearray(self.raw), memoryview(self.raw),
                    b'', bytes(MAX_PROOF_BYTES+1)):
            with self.assertRaises(ValueError):
                decode_proof(bad, self.dimensions)
        with self.assertRaises(ValueError):
            decode_proof(self.raw, self.descriptor)
        for cls in (VerifierDimensions, DecodedProof):
            with self.assertRaises(TypeError):
                cls()
        with self.assertRaises(FrozenInstanceError):
            self.dimensions.primary = self.dimensions.secondary
        changed = self.proof.value
        changed['zn'][0] = '00'*32
        self.assertEqual(encode_proof(self.proof), self.raw)
        changed = self.dimensions.json()
        changed['primary']['num_vars'] = 1
        self.assertNotEqual(changed, self.dimensions.json())

    def test_every_truncation_and_surplus_fail_closed(self):
        for length in range(len(self.raw)):
            with self.subTest(length=length), self.assertRaises(ValueError):
                decode_proof(self.raw[:length], self.dimensions)
        for bad in (b'\0'+self.raw, self.raw+b'\0', self.raw+bytes(32)):
            with self.assertRaises(ValueError):
                decode_proof(bad, self.dimensions)

    def test_every_length_prefix_rejects_zero_and_allocation_attacks(self):
        for span in self.proof.spans:
            if span.kind == 'length':
                for count in (0, (1 << 64)-1, 1 << 32):
                    with self.subTest(path=span.path, count=count), self.assertRaises(ValueError):
                        decode_proof(self.mutated(span, count.to_bytes(8, 'little')), self.dimensions)

    def test_every_scalar_requires_its_declared_field_and_header_width(self):
        for span in self.proof.spans:
            if span.kind == 'scalar':
                bad = SCALAR_MODULI[span.engine].to_bytes(32, 'little')
                with self.subTest(path=span.path), self.assertRaises(ValueError):
                    decode_proof(self.mutated(span, bad), self.dimensions)
        for i, bits in enumerate((32, 128, 128, 200)+(32,)*13):
            span = next(s for s in self.proof.spans if s.path == f'zn[{i}]')
            with self.assertRaises(ValueError):
                decode_proof(self.mutated(span, (1 << bits).to_bytes(32, 'little')), self.dimensions)

    def test_point_canonicality_aliases_curve_roles_and_bit254(self):
        for bad in (None, b'', [0]*32, bytearray(32), memoryview(bytes(32))):
            with self.assertRaises(ValueError):
                decode_point(bad, 'pallas')
        for engine in (None, [], {}, True, 'bn256'):
            with self.assertRaises(ValueError):
                decode_point(bytes(32), engine)
        for engine, p in BASE_MODULI.items():
            self.assertIsNone(decode_point(bytes(32), engine))
            for bad in ((1 << 255).to_bytes(32, 'little'), p.to_bytes(32, 'little')):
                with self.assertRaises(ValueError):
                    decode_point(bad, engine)
            for x in range(1, 32):
                try:
                    decode_point(x.to_bytes(32, 'little'), engine)
                except ValueError:
                    break
            else:
                self.fail('no small off-curve test encoding')
            with self.assertRaises(ValueError):
                decode_point(x.to_bytes(32, 'little'), engine)
            for x in range(1 << 254, (1 << 254)+32):
                try:
                    point = decode_point(x.to_bytes(32, 'little'), engine)
                    break
                except ValueError:
                    pass
            else:
                self.fail('no bit254 canonical coordinate test point')
            self.assertEqual(point[0], x)
            opposite = decode_point((x | (1 << 255)).to_bytes(32, 'little'), engine)
            self.assertEqual((point[1]+opposite[1]) % p, 0)
            span = next(s for s in self.proof.spans if s.kind == 'commitment' and s.engine == engine)
            admitted = decode_proof(self.mutated(span, bytes(32)), self.dimensions)
            self.assertFalse(admitted.summary()['proof_verified'])
            with self.assertRaises(ValueError):
                decode_proof(self.mutated(span, (1 << 255).to_bytes(32, 'little')), self.dimensions)

    def test_admission_preserves_short_rows_trailing_zeroes_and_false_proofs(self):
        # A shorter coefficient row can be degree-valid. Coherent removal must
        # be admitted; changing only a prefix is not a coherent serialization.
        span = next(s for s in self.proof.spans if s.path ==
            'snark_primary.sc_proof_outer.compressed_polys[0].coeffs_except_linear_term')
        changed = (self.raw[:span.start]+(2).to_bytes(8, 'little')
                   + self.raw[span.start+8:span.start+72]+self.raw[span.start+104:])
        admitted = decode_proof(changed, self.dimensions)
        row = admitted.value['snark_primary']['sc_proof_outer']['compressed_polys'][0]
        self.assertEqual(len(row['coeffs_except_linear_term']), 2)
        self.assertEqual(encode_proof(admitted), changed)
        scalar = next(s for s in self.proof.spans if s.path == 'ri_primary')
        self.assertNotEqual(self.raw[scalar.start:scalar.start+32], bytes(32))
        admitted = decode_proof(self.mutated(scalar, bytes(32)), self.dimensions)
        self.assertFalse(admitted.summary()['proof_verified'])
        last = next(s for s in self.proof.spans if s.path ==
            'snark_primary.sc_proof_outer.compressed_polys[0].coeffs_except_linear_term[2]')
        admitted = decode_proof(self.mutated(last, bytes(32)), self.dimensions)
        self.assertEqual(len(admitted.value['snark_primary']['sc_proof_outer']
                              ['compressed_polys'][0]['coeffs_except_linear_term']), 3)


if __name__ == '__main__':
    unittest.main()
