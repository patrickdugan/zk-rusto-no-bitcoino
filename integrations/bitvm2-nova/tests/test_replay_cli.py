"""Malformed report transport checks; these are not native proof receipts."""
from copy import deepcopy
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from bench_replay import DIMENSION_PIN, KEY_PIN, POSEIDON_PIN, run
from nht4 import load_expected_json

FIXTURES = Path(__file__).resolve().parents[1]/'fixtures'


class ReplayReportTransport(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        expected = load_expected_json((FIXTURES/'nht4-genesis-0-2020-k5.expected.json').read_bytes())
        # Coherent surrounding fields let each negative reach its intended
        # transport guard. This deliberately constructed dictionary is never
        # used as positive native-verification evidence.
        cls.base = {'schema': 'bitvm2-nova-native-production-replay/v1',
            'passed': True, 'native_nova_proofs_verified': 1,
            'network': expected.network, 'k': expected.k, 'steps': expected.steps,
            'nova_version': expected.nova_version, 'header_revision': expected.header_revision,
            'bundle_sha256': expected.bundle_sha256.hex(), 'proof_sha256': expected.proof_sha256.hex(),
            'proof_bytes': expected.proof_bytes, 'verifier_key_sha256': expected.verifier_key_sha256.hex(),
            'verifier_dimensions_sha256': DIMENSION_PIN,
            'end_state_sha256': expected.end_state_sha256.hex(),
            'key_bindings_sha256': KEY_PIN, 'poseidon_parameters_sha256': POSEIDON_PIN}
        for field, suffix in (('verifier_dimensions', 'dimensions'),
                              ('key_bindings', 'key-bindings'), ('trace', 'trace'),
                              ('poseidon_parameters', 'poseidon')):
            cls.base[field] = json.loads((FIXTURES/f'nht4-genesis-0-2020-k5.{suffix}.json').read_bytes())

    def rejected(self, report, message):
        parent = (FIXTURES.parent/'results').resolve()
        parent.mkdir(exist_ok=True)
        with TemporaryDirectory(prefix='replay-transport-', dir=parent) as temporary:
            directory = Path(temporary).resolve()
            self.assertTrue(directory.is_relative_to(parent))
            path = directory/'negative-report.json'
            path.write_text(json.dumps(report), encoding='utf-8')
            with self.assertRaisesRegex(ValueError, message):
                run(path)

    def test_boolean_verification_count_is_not_integer_one(self):
        value = deepcopy(self.base)
        value['native_nova_proofs_verified'] = True
        self.rejected(value, 'successful actual native replay report required')

    def test_nested_boolean_dimension_is_not_integer_one(self):
        value = deepcopy(self.base)
        value['verifier_dimensions']['primary']['ck_s_generators'] = True
        self.rejected(value, 'ck_s_generators outside admission bounds')

    def test_report_trace_is_checked_rather_than_replaced_by_fixture(self):
        value = deepcopy(self.base)
        self.assertEqual(value['trace']['streams'][0]['session'], 0)
        value['trace']['streams'][0]['session'] = False
        self.rejected(value, 'session')

    def test_report_poseidon_constants_cannot_be_replaced_under_copied_digest(self):
        value = deepcopy(self.base)
        value['poseidon_parameters']['primary']['wide']['mds'][0][0] = '00'*32
        self.rejected(value, 'Poseidon parameter digest mismatch')

    def test_poseidon_boolean_width_is_not_integer_one(self):
        value = deepcopy(self.base)
        value['poseidon_parameters']['primary']['wide']['capacity'] = True
        self.rejected(value, 'unsupported Poseidon profile identity')


if __name__ == '__main__':
    unittest.main()
