"""Lightweight corpus coverage checks; full byte ledgers run once separately."""
from hashlib import sha256
import json
from pathlib import Path
import tempfile
import unittest

from bench_convolution import (MAX_CASES, MAX_INPUT_BYTES, REGISTRY_CONTEXT,
                               build_registry_cases, write_registry_inputs)


class ConvolutionGeneration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases, cls.census, cls.diagnostics = build_registry_cases()
        cls.names = {case['name']: case for case in cls.cases}

    def test_complete_catalogues_and_every_authenticated_point_shape(self):
        self.assertEqual(len(self.cases), 44)
        self.assertEqual(len(self.names), len(self.cases))
        self.assertEqual(len(self.census), 4)
        for role in ('pallas_base', 'vesta_base'):
            case = self.names[role+'/convolution-mul']
            self.assertTrue(case['measure_all'])
            self.assertEqual(case['checks'], [])  # Hosted oracle executes EVERY leaf.
            self.assertEqual(len(case['spec']['leaves']), 489)
            self.assertEqual(len(case['spec']['words']), 634)
            self.assertEqual(case['spec']['context'], REGISTRY_CONTEXT.hex())
            self.assertEqual(case['spec']['operation_id'], 'registry/mul')
            self.assertFalse(case['name'].endswith('honest-full-multiplication'))
        for engine in ('pallas', 'vesta'):
            case = self.names[engine+'/convolution-point']
            self.assertTrue(case['measure_all'])
            self.assertEqual(len(case['spec']['leaves']), 6151)
            self.assertEqual(len(case['spec']['words']), 7476)
            self.assertEqual(case['spec']['operation_id'], 'registry/point')
            def shape(leaf):
                unique = tuple(dict.fromkeys(leaf['wires']))
                return leaf['body_sha256'], tuple(case['spec']['words'][i]['bound'] for i in unique)
            all_shapes = {shape(leaf) for leaf in case['spec']['leaves']}
            sampled = {shape(case['spec']['leaves'][check['ordinal']]) for check in case['checks']}
            self.assertEqual(sampled, all_shapes)
            self.assertEqual(len(sampled), 97)
            self.assertTrue(any(len(set(leaf['wires'])) < len(leaf['wires']) for leaf in case['spec']['leaves']))
            self.assertEqual(case['spec']['context'], sha256(b'global-registry-test').hexdigest())

    def test_adversarial_coverage_retains_shared_topology_and_known_false_leaves(self):
        required = {'coherent-wrong-product', 'noncoherent-wrong-product', 'wrong-quotient',
            'unsigned-max-quotient', 'quotient-is-modulus-integer', 'coherent-field-modulus',
            'coherent-field-modulus-plus-one', 'coherent-noncanonical-output', 'field261-high-bits',
            'oversized-field-limb', 'oversized-quotient-byte', 'unsigned32-max-quotient-byte',
            'oversized-input-byte', 'initial-carry-anchor', 'middle-carry-link', 'final-carry-anchor',
            'crossing-byte-split-lo', 'crossing-byte-split-hi', 'oversized-crossing-split'}
        for role in ('pallas_base', 'vesta_base'):
            honest = self.names[role+'/convolution-mul']
            for suffix in required:
                case = self.names[role+'/'+suffix]
                self.assertIs(case['spec'], honest['spec'])
                self.assertEqual(case['expected_spec_id'], honest['expected_spec_id'])
                self.assertFalse(case['measure_all'])
                self.assertTrue(any(not check['expected_correct'] for check in case['checks']))
                self.assertTrue(all(type(value) is int and 0 <= value <= 0xffffffff for value in case['words']))
            for suffix in ('coherent-field-modulus', 'coherent-field-modulus-plus-one', 'coherent-noncanonical-output'):
                case = self.names[role+'/'+suffix]
                self.assertEqual(sum(not check['expected_correct'] for check in case['checks']), 1)
                self.assertGreater(sum(check['expected_correct'] for check in case['checks']), 0)
            q = self.names[role+'/unsigned-max-quotient']
            slots = {word['name']: i for i, word in enumerate(q['spec']['words'])}
            self.assertEqual([q['words'][slots[f'product/q/{i}']] for i in range(32)], [255]*32)
        for engine in ('pallas', 'vesta'):
            wrong = self.names[engine+'/convolution-wrong-point-result']
            self.assertEqual(len(wrong['checks']), 2)
            self.assertTrue(all(not check['expected_correct'] for check in wrong['checks']))

    def test_streamed_fixture_is_bounded_and_contains_no_script_vector_payloads(self):
        self.assertLessEqual(len(self.cases), MAX_CASES)
        # Keep temporary output under this workspace, including on Windows
        # hosts whose generic sandbox temp path has narrower write permissions.
        workspace_output = Path(__file__).resolve().parents[1]/'results'
        workspace_output.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='convolution-corpus-test-', dir=workspace_output) as directory:
            path = Path(directory)/'inputs.json'
            info = write_registry_inputs(self.cases, path)
            self.assertLess(info['input_bytes'], MAX_INPUT_BYTES)
            self.assertEqual(info['input_bytes'], path.stat().st_size)
            digest = sha256()
            with path.open('rb') as stream:
                for block in iter(lambda: stream.read(1 << 20), b''):
                    digest.update(block)
            self.assertEqual(info['input_sha256'], digest.hexdigest())
            # Decode just the first bounded object instead of duplicating all
            # repeated catalogue dictionaries in local host RAM.
            decoder, prefix = json.JSONDecoder(), ''
            with path.open(encoding='ascii') as stream:
                while len(prefix) < 1 << 20:
                    chunk = stream.read(1 << 16)
                    self.assertTrue(chunk, 'unexpected EOF in generated first catalogue')
                    prefix += chunk
                    try:
                        first, _ = decoder.raw_decode(prefix[1:])
                        break
                    except json.JSONDecodeError:
                        pass
                else:
                    self.fail('first catalogue object exceeded1MiB test budget')
            self.assertEqual(set(first), {'name', 'spec', 'expected_spec_id', 'words', 'checks', 'measure_all'})
            self.assertNotIn('script_hex', first)
            self.assertEqual(len(list(Path(directory).iterdir())), 1)


if __name__ == '__main__':
    unittest.main()
