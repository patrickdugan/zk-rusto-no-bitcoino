"""Corpus coverage and caller-owned policy tests; no native proof verification."""
from hashlib import sha256
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from bench_admission import (MAX_CASES, MAX_CORPUS_BYTES, PINNED_DIMENSIONS_SHA256,
                             build_cases, load_inputs)
from nht4 import HEADER_BYTES, load_expected_json
from proof_codec import decode_proof, load_dimensions_json

FIXTURES = Path(__file__).resolve().parents[1]/'fixtures'


class AdmissionGeneration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.expected = load_expected_json((FIXTURES/'nht4-genesis-0-2020-k5.expected.json').read_bytes())
        cls.descriptor_path = FIXTURES/'nht4-genesis-0-2020-k5.dimensions.json'
        cls.descriptor_raw = cls.descriptor_path.read_bytes()
        cls.dimensions = load_dimensions_json(cls.descriptor_raw, cls.expected,
            expected_descriptor_sha256=bytes.fromhex(PINNED_DIMENSIONS_SHA256))
        cls.raw = (FIXTURES/'nht4-genesis-0-2020-k5.nht4').read_bytes()[HEADER_BYTES:]
        cls.original = decode_proof(cls.raw, cls.dimensions)
        cls.cases, cls.coverage = build_cases(cls.raw, cls.dimensions)
        cls.by_name = {case['name']: case for case in cls.cases}

    def test_every_length_prefix_has_a_huge_count_rejection(self):
        lengths = [span for span in self.original.spans if span.kind == 'length']
        self.assertEqual((len(lengths), self.coverage['all_length_prefixes']), (119, 119))
        self.assertEqual(self.coverage['logical_length_classes'], 24)
        for span in lengths:
            with self.subTest(path=span.path):
                self.assertFalse(self.by_name['huge-length/'+span.path]['accept'])
        for engine in ('pallas', 'vesta'):
            self.assertFalse(self.by_name['point-identity-sign-alias/'+engine]['accept'])
            self.assertFalse(self.by_name['scalar-modulus/'+engine]['accept'])
        for i in range(17):
            self.assertFalse(self.by_name[f'output-width/{i}']['accept'])

    def test_shorter_degree_bounded_rows_remain_structurally_admitted(self):
        self.assertTrue(self.by_name['retained-original']['accept'])
        for stage in ('outer', 'inner'):
            case = self.by_name['shorter-admitted-coefficient-row/'+stage]
            self.assertTrue(case['accept'])
            self.assertLess(len(bytes.fromhex(case['proof_hex'])), len(self.raw))
        self.assertEqual(len(self.cases), 213)
        self.assertEqual(sum(case['accept'] for case in self.cases), 9)
        self.assertLessEqual(len(self.cases), MAX_CASES)
        self.assertEqual(len(self.by_name), len(self.cases))
        payload = json.dumps({'schema': 'bitvm2-nova-admission-cases/v1',
            'source': {'native_report_sha256': '0'*64,
                'verifier_dimensions_sha256': PINNED_DIMENSIONS_SHA256,
                'retained_proof_sha256': sha256(self.raw).hexdigest()},
            'cases': self.cases}, separators=(',', ':')).encode()
        self.assertLessEqual(len(payload), MAX_CORPUS_BYTES)

    def test_cli_rejects_duplicate_descriptor_and_unverified_report(self):
        temp_root = (FIXTURES.parent/'results').resolve()
        temp_root.mkdir(exist_ok=True)
        with TemporaryDirectory(prefix='admission-transport-', dir=temp_root) as directory:
            directory = Path(directory)
            self.assertTrue(directory.resolve().is_relative_to(temp_root))
            descriptor = directory/'descriptor.json'
            report = directory/'report.json'
            descriptor.write_bytes(self.descriptor_raw.rstrip()[:-1]+b',"outer_arity":17}')
            with self.assertRaises(ValueError):
                load_inputs(report, descriptor)
            descriptor.write_bytes(self.descriptor_raw)
            # These are explicit local TEST-ONLY negative transport fixtures;
            # neither is a native-verification report or claimed evidence.
            for value in ([], {'passed': True, 'native': {'native_nova_proofs_verified': False}}):
                report.write_text(json.dumps(value), encoding='utf-8')
                with self.assertRaises(ValueError):
                    load_inputs(report, descriptor)


if __name__ == '__main__':
    unittest.main()
