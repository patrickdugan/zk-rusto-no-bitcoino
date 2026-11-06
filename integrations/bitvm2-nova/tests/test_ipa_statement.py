"""Small request/metadata tests, with no generator payload or native MSM.

All collection hashes here are TEST-OWNED synthetic replacements. One public
builder test replays the retained proof to prepare its short request vectors;
that is not actual-generator evidence and cannot set execution/proof flags.
"""
from copy import deepcopy
from dataclasses import FrozenInstanceError
from hashlib import sha256
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from ipa_algebra import PALLAS, VESTA, test_generator
from ipa_statement import (COLLECTION_SCHEMA, ENCODING, MAX_COLLECTION_BYTES,
    MAX_FILE_BYTES, MAX_METADATA_BYTES, REQUEST_SCHEMA, GeneratorFile,
    GeneratorSegment, IpaGeneratorCollection, IpaStatement, _validated_statement,
    build_ipa_statements, load_generator_collection_json)
from nht4 import HEADER_BYTES, load_expected_json
from poseidon_reference import load_parameters_json
from production_replay import ReplayKeyBindings
from proof_codec import (BASE_MODULI, SCALAR_MODULI, VerifierDimensions,
                         decode_proof, load_dimensions_json)

FIXTURES = Path(__file__).resolve().parents[1]/'fixtures'
DIMENSION_PIN = bytes.fromhex('de6333df2e41b5f5bae1c103fab862f8d6022fd54abeb80ba61920bc9f360edc')
KEY_BINDINGS_PIN = bytes.fromhex('c8b117ea587c80bfdbdfc0cc262cdf68b1b4c07b3b45ba871413c7768aa62b9a')
TRACE_PIN = bytes.fromhex('394d90b302b2fe6b8f5c0a65ada372d820996f3230770a816961a75cefec59b8')
POSEIDON_PIN = bytes.fromhex('b55fa125133315243cb299ee7603c5f0508d68abf64f0dab43ecba4a0d09fa67')


def canonical(data):
    return json.dumps(data, sort_keys=True, separators=(',', ':')).encode('ascii')


def pin(data):
    return sha256(canonical(data)).digest()


def le(value):
    return value.to_bytes(32, 'little').hex()


def compressed(point):
    return (point[0] | ((point[1] & 1) << 255)).to_bytes(32, 'little').hex()


def synthetic_collection(expected, dimensions):
    """Shape-only diagnostic metadata; no real generator file is claimed."""
    data = {key: value for key, value in dimensions.json().items()
            if key not in ('outer_arity', 'max_ipa_dimension', 'primary', 'secondary')}
    data.update(schema=COLLECTION_SCHEMA, encoding=ENCODING,
                verifier_dimensions_sha256=dimensions.descriptor_sha256.hex())
    files = []
    for role, engine in (('primary', 'pallas'), ('secondary', 'vesta')):
        count = getattr(dimensions, role).ipa_dimension
        files.append(dict(role=role, engine=engine, base_field_role=engine+'_base',
            scalar_field_role=engine+'_scalar', filename=f'{role}-generators.bin',
            count=count, bytes=8+32*count, sha256=sha256((role+' TEST ONLY').encode()).hexdigest(),
            segments=[dict(name='count', offset=0, bytes=8,
                sha256=sha256(count.to_bytes(8, 'little')).hexdigest()),
                dict(name='points', offset=8, bytes=32*count, sha256='00'*32)]))
    data.update(files=files, total_bytes=sum(item['bytes'] for item in files))
    return data


class IpaStatementTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.expected = load_expected_json((FIXTURES/'nht4-genesis-0-2020-k5.expected.json').read_bytes())
        cls.actual_dimensions = load_dimensions_json(
            (FIXTURES/'nht4-genesis-0-2020-k5.dimensions.json').read_bytes(), cls.expected,
            expected_descriptor_sha256=DIMENSION_PIN)
        descriptor = cls.actual_dimensions.json()
        for role in ('primary', 'secondary'):
            descriptor[role].update(num_cons=8, num_vars=8, outer_rounds=3, inner_rounds=4,
                batch_rounds=3, ipa_rounds=3, ipa_dimension=8, ck_v_generators=8)
        cls.dimensions = VerifierDimensions.from_json(descriptor, cls.expected,
            expected_descriptor_sha256=pin(descriptor))
        cls.collection_data = synthetic_collection(cls.expected, cls.dimensions)
        cls.collection = IpaGeneratorCollection.from_json(cls.collection_data,
            cls.expected, cls.dimensions, expected_collection_sha256=pin(cls.collection_data))

    def test_small_collection_is_immutable_independently_pinned_and_not_payload_evidence(self):
        self.assertEqual(self.collection.file('primary').count, 8)
        self.assertEqual(self.collection.total_bytes, 528)
        self.assertEqual(self.collection.json(), self.collection_data)
        for value in (None, '', bytes(31), bytearray(32)):
            with self.assertRaises(ValueError):
                IpaGeneratorCollection.from_json(self.collection_data, self.expected,
                    self.dimensions, expected_collection_sha256=value)
        changed = deepcopy(self.collection_data)
        changed['files'][0]['sha256'] = '01'*32
        with self.assertRaisesRegex(ValueError, 'digest mismatch'):
            IpaGeneratorCollection.from_json(changed, self.expected, self.dimensions,
                expected_collection_sha256=self.collection.collection_sha256)
        for cls in (IpaGeneratorCollection, GeneratorFile, GeneratorSegment, IpaStatement):
            with self.assertRaises(TypeError):
                cls()
        self.assertFalse(hasattr(IpaStatement, 'from_json'))
        with self.assertRaises(FrozenInstanceError):
            self.collection.total_bytes = 0
        changed = self.collection.json()
        changed['files'][0]['count'] = 99
        self.assertEqual(self.collection.file('primary').count, 8)

    def test_collection_roles_counts_offsets_types_and_caps(self):
        for path, value in (
            (('files', 0, 'role'), 'secondary'), (('files', 0, 'engine'), 'vesta'),
            (('files', 0, 'base_field_role'), 'pallas_scalar'),
            (('files', 0, 'scalar_field_role'), 'pallas_base'),
            (('files', 0, 'filename'), '../primary-generators.bin'),
            (('files', 0, 'count'), True), (('files', 0, 'count'), 16),
            (('files', 0, 'bytes'), MAX_FILE_BYTES+1),
            (('files', 0, 'segments', 0, 'bytes'), 7),
            (('files', 0, 'segments', 1, 'offset'), 0),
            (('files', 0, 'segments', 1, 'bytes'), True),
            (('files', 0, 'sha256'), 'AA'*32),
            (('total_bytes',), MAX_COLLECTION_BYTES+1),
            (('network',), 'mainnet'), (('k',), True),
            (('verifier_dimensions_sha256',), '00'*32),
            (('verifier_key_sha256',), '00'*32)):
            changed = deepcopy(self.collection_data)
            parent = changed
            for key in path[:-1]:
                parent = parent[key]
            parent[path[-1]] = value
            with self.subTest(path=path), self.assertRaises(ValueError):
                IpaGeneratorCollection.from_json(changed, self.expected, self.dimensions,
                    expected_collection_sha256=pin(changed))
        changed = deepcopy(self.collection_data)
        changed['files'].reverse()
        with self.assertRaises(ValueError):
            IpaGeneratorCollection.from_json(changed, self.expected, self.dimensions,
                expected_collection_sha256=pin(changed))

    def test_collection_json_transport_guards(self):
        raw = canonical(self.collection_data)
        result = load_generator_collection_json(raw, self.expected, self.dimensions,
            expected_collection_sha256=self.collection.collection_sha256)
        self.assertEqual(result, self.collection)
        for raw in (raw[:-1]+b',"k":5}', b'{"n":NaN}', b'['*9+b'0'+b']'*9,
                    b'\xff', b'', bytearray(raw), b' '*(MAX_METADATA_BYTES+1)):
            with self.assertRaises(ValueError):
                load_generator_collection_json(raw, self.expected, self.dimensions,
                    expected_collection_sha256=self.collection.collection_sha256)

    def test_tiny_mathematical_statement_canonical_points_and_zero_policy(self):
        for engine, curve in (('pallas', PALLAS), ('vesta', VESTA)):
            point = compressed(test_generator(curve, 3))
            data = dict(joint_commitment=point, joint_evaluation_le=le(0),
                batch_point_le=[le(2), le(3), le(5)], ipa_initial_challenge_le=le(0),
                L_vec=[point, '00'*32, point], R_vec=['00'*32, point, point],
                challenges_le=[le(7), le(11), le(13)], a_hat_le=le(0),
                generator_residual='00'*32)
            result = _validated_statement(data, 8, engine)
            self.assertEqual(result, data)  # r0=0 and a_hat=0 are allowed.
            result['L_vec'][0] = '00'*32
            self.assertEqual(data['L_vec'][0], point)
            for field, value in (('joint_evaluation_le', le(SCALAR_MODULI[engine])),
                ('ipa_initial_challenge_le', 'AA'*32), ('a_hat_le', le(SCALAR_MODULI[engine])),
                ('joint_commitment', le(BASE_MODULI[engine])),
                ('generator_residual', '00'*31+'80')):
                changed = deepcopy(data)
                changed[field] = value
                with self.subTest(engine=engine, field=field), self.assertRaises(ValueError):
                    _validated_statement(changed, 8, engine)
            for field in ('batch_point_le', 'L_vec', 'R_vec', 'challenges_le'):
                for value in ([], data[field][:-1], data[field]+[data[field][0]], tuple(data[field])):
                    changed = deepcopy(data)
                    changed[field] = value
                    with self.subTest(engine=engine, field=field), self.assertRaises(ValueError):
                        _validated_statement(changed, 8, engine)
            changed = deepcopy(data)
            changed['challenges_le'][1] = le(0)
            with self.assertRaises(ValueError):
                _validated_statement(changed, 8, engine)
        for dimension in (True, 0, 7, 12, '8'):
            with self.assertRaises(ValueError):
                _validated_statement(data, dimension, 'pallas')

    def test_public_builder_reconstructs_short_requests_and_never_executes_or_accepts_receipt(self):
        raw = (FIXTURES/'nht4-genesis-0-2020-k5.nht4').read_bytes()[HEADER_BYTES:]
        decoded = decode_proof(raw, self.actual_dimensions)
        metadata = json.loads((FIXTURES/'nht4-genesis-0-2020-k5.key-bindings.json').read_bytes())
        bindings = ReplayKeyBindings.from_json(metadata, self.expected, self.actual_dimensions,
            expected_key_bindings_sha256=KEY_BINDINGS_PIN)
        params = load_parameters_json((FIXTURES/'nht4-genesis-0-2020-k5.poseidon.json').read_bytes(),
            self.expected, self.actual_dimensions, expected_parameters_sha256=POSEIDON_PIN)
        trace = json.loads((FIXTURES/'nht4-genesis-0-2020-k5.trace.json').read_bytes())
        data = synthetic_collection(self.expected, self.actual_dimensions)
        # TEST ONLY replacement pin. Preparation reads no generator bytes and
        # does not authenticate this invented payload hash as native evidence.
        collection = IpaGeneratorCollection.from_json(data, self.expected,
            self.actual_dimensions, expected_collection_sha256=pin(data))
        kwargs = dict(expected_trace_sha256=TRACE_PIN, poseidon_parameters=params,
                      generator_collection=collection)
        with patch('builtins.open', side_effect=AssertionError('no bulk file IO allowed')):
            requests = build_ipa_statements(decoded, self.expected, bindings, trace, **kwargs)
        self.assertEqual(tuple(item.role for item in requests), ('primary', 'secondary'))
        for request, role, engine, rounds in zip(requests, ('primary', 'secondary'),
                ('pallas', 'vesta'), (19, 14), strict=True):
            obj, status = request.json(), request.summary()
            self.assertEqual(request.to_bytes(), canonical(obj))
            self.assertEqual(sha256(request.to_bytes()).digest(), request.request_sha256)
            self.assertEqual(obj['schema'], REQUEST_SCHEMA)
            self.assertEqual((obj['role'], obj['engine']), (role, engine))
            self.assertEqual(obj['proof_sha256'], decoded.proof_sha256.hex())
            self.assertEqual(obj['generator_collection_sha256'], collection.collection_sha256.hex())
            self.assertEqual(obj['key_bindings_sha256'], KEY_BINDINGS_PIN.hex())
            self.assertEqual(obj['native_trace_sha256'], TRACE_PIN.hex())
            self.assertEqual(obj['poseidon_parameters_sha256'], POSEIDON_PIN.hex())
            self.assertEqual(obj['ipa_dimension'], 1 << rounds)
            self.assertEqual(len(obj['L_vec']), rounds)
            self.assertEqual(obj['L_vec'], [p['comm'] for p in decoded.value['snark_'+role]['eval_arg']['L_vec']])
            for name in ('ipa_native_msm_executed', 'ipa_native_relation_checked',
                         'ipa_python_msm_independently_computed', 'ipa_generator_msm_verified',
                         'proof_verified', 'bitvm2_script_verified'):
                self.assertFalse(status[name])
            obj['L_vec'][0] = '00'*32
            self.assertNotEqual(request.json()['L_vec'][0], obj['L_vec'][0])
            with self.assertRaises(FrozenInstanceError):
                request.request_sha256 = bytes(32)
        with self.assertRaisesRegex(ValueError, 'unexpected.*trace'):
            build_ipa_statements(decoded, self.expected, bindings, {'passed': True}, **kwargs)
        with self.assertRaisesRegex(ValueError, 'dimension identities'):
            build_ipa_statements(decoded, self.expected, bindings, None,
                expected_trace_sha256=TRACE_PIN, poseidon_parameters=params,
                generator_collection=self.collection)
        with self.assertRaisesRegex(ValueError, 'typed independently pinned'):
            build_ipa_statements({'passed': True}, self.expected, bindings, trace, **kwargs)


if __name__ == '__main__':
    unittest.main()
