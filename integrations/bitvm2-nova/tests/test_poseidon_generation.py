"""Poseidon corpus coverage; actual native execution is a separate hosted check."""
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from bench_poseidon import (FIXTURES, LENGTHS, PATTERNS, PARAMETERS_SHA256,
                            MAX_CASES, MAX_FILE_BYTES, build_cases, load_parameters)
from poseidon_reference import sponge_hash


class PoseidonGeneration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.parameter_path = FIXTURES/'nht4-genesis-0-2020-k5.poseidon.json'
        cls.parameters = load_parameters(cls.parameter_path)
        cls.cases, cls.coverage = build_cases(cls.parameters)
        cls.by_name = {case['name']: case for case in cls.cases}

    def test_all_field_modes_lengths_patterns_and_boundaries(self):
        self.assertEqual((len(self.cases), sum(c['accept'] for c in self.cases)), (254, 200))
        self.assertLessEqual(len(self.cases), MAX_CASES)
        for engine in ('pallas', 'vesta'):
            for mode in ('wide', 'narrow'):
                for length in LENGTHS:
                    for pattern in PATTERNS:
                        self.assertTrue(self.by_name[f'{engine}/{mode}/{length}/{pattern}']['accept'])
        self.assertEqual(self.coverage['native_squeezes_expected'], 776)
        self.assertGreater(self.coverage['forced_255_field_reductions_expected'], 0)
        payload = json.dumps({'schema': 'bitvm2-nova-poseidon-cases/v1',
            'source': {'parameters_sha256': PARAMETERS_SHA256}, 'cases': self.cases},
            separators=(',', ':')).encode()
        self.assertLessEqual(len(payload), MAX_FILE_BYTES)

    def test_repeated_squeeze_retains_full_prior_hash_and_bool_negatives(self):
        saw_distinct = False
        for engine in ('pallas', 'vesta'):
            for mode in ('wide', 'narrow'):
                case = self.by_name[f'{engine}/{mode}/52/counter']
                squeezes = [event for event in case['events'] if event['op'] == 'squeeze']
                first, second = squeezes[:2]
                self.assertEqual(first['expected_state_le'], [first['expected_full_hash_le']])
                saw_distinct |= first['expected_full_hash_le'] != first['expected_challenge_le']
                expected_second = sponge_hash(self.parameters.profile(engine, mode),
                    [int.from_bytes(bytes.fromhex(first['expected_full_hash_le']), 'little')])
                self.assertEqual(second['expected_full_hash_le'], expected_second.to_bytes(32, 'little').hex())
        self.assertTrue(saw_distinct)
        for engine in ('pallas', 'vesta'):
            bad = self.by_name[f'{engine}/bad/bit-count-3']
            self.assertIs(bad['events'][0]['num_bits'], True)
            self.assertFalse(bad['accept'])
            self.assertFalse(self.by_name[f'{engine}/bad/absorbed-scalar-0']['accept'])

    def test_parameter_transport_tampering_cannot_replace_independent_pin(self):
        temp_root = (FIXTURES.parent/'results').resolve()
        temp_root.mkdir(exist_ok=True)
        with TemporaryDirectory(prefix='poseidon-parameter-test-', dir=temp_root) as directory:
            directory = Path(directory)
            self.assertTrue(directory.resolve().is_relative_to(temp_root))
            value = json.loads(self.parameter_path.read_bytes())
            original_vk = value['verifier_key_sha256']
            value['primary']['wide']['mds'][0][0] = '00'*32
            mutated = directory/'mutated.json'
            mutated.write_text(json.dumps(value, sort_keys=True, separators=(',', ':')), encoding='ascii')
            self.assertEqual(value['verifier_key_sha256'], original_vk)
            with self.assertRaises(ValueError):
                load_parameters(mutated)


if __name__ == '__main__':
    unittest.main()
