"""Tiny mocked-process transport tests; no original native helper or large MSM.

Toy sealed requests are constructed through a PRIVATE test seam. Production
callers must use build_ipa_statements. The helper process used in one test is a
small Python echo fixture under workspace/results, explicitly not Nova evidence.
"""
from copy import deepcopy
from dataclasses import FrozenInstanceError
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from ipa_algebra import PALLAS, test_generator
from ipa_runtime import (ADDRESS_SPACE_BYTES, CPU_SECONDS, NATIVE_SCOPE, OUTPUT_BYTES, PRLIMIT,
    RESULT_SCHEMA, WALL_SECONDS, IpaExecution, IpaRuntimeError, _checked_result,
    execute_ipa_statement)
from ipa_statement import (COLLECTION_SCHEMA, ENCODING, REQUEST_SCHEMA,
    IpaGeneratorCollection, IpaStatement, _make)
from nht4 import load_expected_json
from production_replay import ipa_factors
from proof_codec import SCALAR_MODULI, VerifierDimensions, load_dimensions_json

FIXTURES = Path(__file__).resolve().parents[1]/'fixtures'
DIMENSION_PIN = bytes.fromhex('de6333df2e41b5f5bae1c103fab862f8d6022fd54abeb80ba61920bc9f360edc')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode('ascii')


def pin(value):
    return sha256(canonical(value)).digest()


def le(value):
    return value.to_bytes(32, 'little').hex()


def point(value):
    if value is None:
        return '00'*32
    return (value[0] | ((value[1] & 1) << 255)).to_bytes(32, 'little').hex()


class IpaRuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.expected = load_expected_json((FIXTURES/'nht4-genesis-0-2020-k5.expected.json').read_bytes())
        dimensions = load_dimensions_json((FIXTURES/'nht4-genesis-0-2020-k5.dimensions.json').read_bytes(),
            cls.expected, expected_descriptor_sha256=DIMENSION_PIN)
        descriptor = dimensions.json()
        for role in ('primary', 'secondary'):
            descriptor[role].update(num_cons=8, num_vars=8, outer_rounds=3, inner_rounds=4,
                batch_rounds=3, ipa_rounds=3, ipa_dimension=8, ck_v_generators=8)
        cls.dimensions = VerifierDimensions.from_json(descriptor, cls.expected,
            expected_descriptor_sha256=pin(descriptor))
        cls.data = {k: v for k, v in descriptor.items()
                    if k not in ('outer_arity', 'max_ipa_dimension', 'primary', 'secondary')}
        cls.data.update(schema=COLLECTION_SCHEMA, encoding=ENCODING,
            verifier_dimensions_sha256=cls.dimensions.descriptor_sha256.hex(), total_bytes=528)
        cls.data['files'] = [dict(role=role, engine=engine, base_field_role=engine+'_base',
            scalar_field_role=engine+'_scalar', filename=f'{role}-generators.bin',
            count=8, bytes=264, sha256='00'*32, segments=[
                dict(name='count', offset=0, bytes=8, sha256='00'*32),
                dict(name='points', offset=8, bytes=256, sha256='00'*32)])
            for role, engine in (('primary', 'pallas'), ('secondary', 'vesta'))]
        cls.collection = IpaGeneratorCollection.from_json(cls.data, cls.expected,
            cls.dimensions, expected_collection_sha256=pin(cls.data))
        cls.generator = test_generator(PALLAS, 3)
        cls.keys = {'TEST ONLY': 'tiny mocked-process metadata, not a native VK export'}
        cls.statement, cls.result = cls.toy_request(3)

    @classmethod
    def toy_request(cls, a_hat):
        residual = point(PALLAS.mul(cls.generator, a_hat))
        request = dict(schema=REQUEST_SCHEMA, role='primary', engine='pallas',
            proof_sha256='11'*32, verifier_key_sha256=cls.expected.verifier_key_sha256.hex(),
            verifier_dimensions_sha256=cls.dimensions.descriptor_sha256.hex(),
            key_bindings_sha256=pin(cls.keys).hex(), native_trace_sha256='22'*32,
            poseidon_parameters_sha256='33'*32,
            generator_collection_sha256=cls.collection.collection_sha256.hex(),
            ipa_dimension=8, generator_count=8, joint_commitment=point(cls.generator),
            joint_evaluation_le=le(7), batch_point_le=[le(x) for x in (7, 11, 13)],
            ipa_initial_challenge_le=le(0), L_vec=[point(cls.generator)]*3,
            R_vec=[point(cls.generator)]*3, challenges_le=[le(x) for x in (2, 3, 5)],
            a_hat_le=le(a_hat), generator_residual=residual)
        encoded = canonical(request)
        statement = _make(IpaStatement, role='primary', engine='pallas',
            request_sha256=sha256(encoded).digest(), _json=encoded)
        b_hat = ipa_factors((7, 11, 13), (2, 3, 5), SCALAR_MODULI['pallas'])['b_hat']
        result = dict(schema=RESULT_SCHEMA, request_sha256=statement.request_sha256.hex(),
            generator_collection_sha256=cls.collection.collection_sha256.hex(),
            key_bindings_sha256=request['key_bindings_sha256'], role='primary', engine='pallas',
            ipa_dimension=8, generator_bytes_authenticated=True, cpu_only=True,
            wall_seconds=0.01, native_proofs_verified=0, proving_jobs=0,
            proof_verified=False, bitvm2_script_verified=False, scope=NATIVE_SCOPE,
            terminal=dict(relation_holds=True, residual_matches_python=True,
                generators_consumed=8, weights_computed=8, ipa_rounds=3,
                weights_sha256='44'*32, factorized_b_hat_le=le(b_hat),
                generator_sum=point(cls.generator), scaled_generator_sum=residual,
                required_generator_residual=residual, msm_seconds=0.005))
        return statement, result

    def work(self):
        root = Path.cwd()/'results'
        root.mkdir(exist_ok=True)
        return tempfile.TemporaryDirectory(prefix='ipa-runtime-unit-', dir=root)

    def prepare(self, directory):
        directory = Path(directory)
        keys, collection = directory/'keys.json', directory/'collection.json'
        keys.write_bytes(canonical(self.keys))
        collection.write_bytes(canonical(self.data))
        for file in self.collection.files:
            (directory/file.filename).write_bytes((8).to_bytes(8, 'little')+bytes(256))
        helper = directory/'ipa_msm'
        helper.write_text('TEST ONLY, not an executable Nova helper', encoding='ascii')
        return dict(executable=helper, key_bindings_file=keys, collection_file=collection,
                    generators_directory=directory, results_directory=directory)

    def test_hosted_guard_runs_before_any_io_even_for_forged_receipt(self):
        with patch.dict('os.environ', {'GITHUB_ACTIONS': 'false', 'RUNNER_OS': 'Linux'}):
            with patch('pathlib.Path.resolve', side_effect=AssertionError('unexpected path IO')):
                with patch('subprocess.run', side_effect=AssertionError('unexpected process')):
                    with self.assertRaisesRegex(IpaRuntimeError, 'hosted GitHub Linux only'):
                        execute_ipa_statement({'passed': True}, {'passed': True}, executable='unused',
                            key_bindings_file='unused', collection_file='unused', generators_directory='unused')
        with self.assertRaises(TypeError):
            IpaExecution()
        self.assertFalse(hasattr(IpaExecution, 'from_json'))

    def test_private_result_checks_ids_math_flags_counts_points_and_zero_a_hat(self):
        self.assertEqual(_checked_result(canonical(self.result), self.statement, self.collection), self.result)
        zero_statement, zero = self.toy_request(0)
        self.assertTrue(_checked_result(canonical(zero), zero_statement, self.collection)['terminal']['relation_holds'])
        for path, value in (
            (('request_sha256',), '00'*32), (('generator_collection_sha256',), '00'*32),
            (('key_bindings_sha256',), '00'*32), (('role',), 'secondary'),
            (('engine',), 'vesta'), (('ipa_dimension',), True),
            (('generator_bytes_authenticated',), 1), (('cpu_only',), False),
            (('proof_verified',), True), (('bitvm2_script_verified',), True),
            (('native_proofs_verified',), 1), (('proving_jobs',), True),
            (('terminal', 'relation_holds'), False), (('terminal', 'residual_matches_python'), False),
            (('terminal', 'generators_consumed'), 7), (('terminal', 'weights_computed'), 9),
            (('terminal', 'ipa_rounds'), True), (('terminal', 'weights_sha256'), 'AA'*32),
            (('terminal', 'factorized_b_hat_le'), le(0)),
            (('terminal', 'scaled_generator_sum'), '00'*32),
            (('terminal', 'required_generator_residual'), '00'*32),
            (('terminal', 'generator_sum'), '00'*32),
            (('terminal', 'generator_sum'), '00'*31+'80'),
            (('terminal', 'msm_seconds'), -1.0), (('terminal', 'msm_seconds'), 1.0),
            (('wall_seconds',), True), (('wall_seconds',), 0), (('wall_seconds',), 362.0)):
            result = deepcopy(self.result)
            parent = result
            for key in path[:-1]:
                parent = parent[key]
            parent[path[-1]] = value
            with self.subTest(path=path), self.assertRaises(ValueError):
                _checked_result(canonical(result), self.statement, self.collection)
        for raw in (b'', b'not JSON', b'{"a":NaN}', b'['*9+b'0'+b']'*9,
                    canonical(self.result)[:-1]+b',"role":"primary"}', b' '*(OUTPUT_BYTES+1)):
            with self.assertRaises(ValueError):
                _checked_result(raw, self.statement, self.collection)

    def test_direct_mocked_process_binds_external_sha_limits_and_scoped_execution_flags(self):
        with self.work() as directory:
            config = self.prepare(directory)
            commands = []
            def run(command, **kwargs):
                commands.append(command)
                self.assertEqual(command[:5], [str(PRLIMIT), f'--as={ADDRESS_SPACE_BYTES}',
                    f'--cpu={CPU_SECONDS}', f'--fsize={OUTPUT_BYTES}', '--'])
                self.assertEqual(command[-1], self.statement.request_sha256.hex())
                self.assertEqual(kwargs['timeout'], WALL_SECONDS)
                self.assertEqual(kwargs['env']['RAYON_NUM_THREADS'], '2')
                self.assertNotIn('capture_output', kwargs)
                self.assertEqual(Path(command[6]).read_bytes(), self.statement.to_bytes())
                kwargs['stdout'].write(canonical(self.result)+b'\n')
                return subprocess.CompletedProcess(command, 0)
            with patch('ipa_runtime._hosted_guard'), patch('ipa_runtime._trusted_executable', return_value=config['executable']):
                with patch('ipa_runtime.subprocess.run', side_effect=run):
                    execution = execute_ipa_statement(self.statement, self.collection, **config)
            self.assertEqual(len(commands), 1)
            status = execution.summary()
            self.assertTrue(status['ipa_native_msm_executed'])
            self.assertTrue(status['ipa_native_relation_checked'])
            for key in ('ipa_python_msm_independently_computed', 'ipa_generator_msm_verified',
                        'ipa_complete_verification', 'proof_verified', 'bitvm2_script_verified'):
                self.assertFalse(status[key])
            with self.assertRaises(FrozenInstanceError):
                execution.role = 'secondary'
            copy = execution.native_result()
            copy['terminal']['relation_holds'] = False
            self.assertTrue(execution.native_result()['terminal']['relation_holds'])
            self.assertEqual(list(Path(directory).glob('ipa-msm-*')), [])

    def test_actual_tiny_python_fixture_process_only_through_explicit_test_mock(self):
        # This deliberately substitutes a tiny test process for prlimit/native.
        # There is no production switch that performs this substitution.
        original_run = subprocess.run
        with self.work() as directory:
            config = self.prepare(directory)
            fixture = Path(directory)/'echo_fixture.py'
            output = Path(directory)/'fixture-output.json'
            output.write_bytes(canonical(self.result))
            fixture.write_text('import pathlib,sys\nsys.stdout.buffer.write(pathlib.Path(sys.argv[1]).read_bytes())\n', encoding='ascii')
            def run(command, **kwargs):
                return original_run([sys.executable, str(fixture), str(output)], **kwargs)
            with patch('ipa_runtime._hosted_guard'), patch('ipa_runtime._trusted_executable', return_value=config['executable']):
                with patch('ipa_runtime.subprocess.run', side_effect=run):
                    execution = execute_ipa_statement(self.statement, self.collection, **config)
            self.assertEqual(execution.request_sha256, self.statement.request_sha256)

    def test_process_failure_timeout_panic_oversize_and_malformed_never_make_execution(self):
        variants = [('exit', 1, canonical(self.result), b'panic: upstream failure'),
                    ('bool-exit', False, canonical(self.result), b''),
                    ('empty', 0, b'', b''), ('malformed', 0, b'panic', b''),
                    ('stdout', 0, b' '*(OUTPUT_BYTES+1), b''),
                    ('stderr', 0, canonical(self.result), b' '*(OUTPUT_BYTES+1))]
        with self.work() as directory:
            config = self.prepare(directory)
            for name, code, raw, diagnostic in variants:
                def run(command, **kwargs):
                    kwargs['stdout'].write(raw)
                    kwargs['stderr'].write(diagnostic)
                    return subprocess.CompletedProcess(command, code)
                with self.subTest(name=name), patch('ipa_runtime._hosted_guard'):
                    with patch('ipa_runtime._trusted_executable', return_value=config['executable']):
                        with patch('ipa_runtime.subprocess.run', side_effect=run), self.assertRaises(ValueError):
                            execute_ipa_statement(self.statement, self.collection, **config)
            for error in (subprocess.TimeoutExpired(['test'], 360), OSError('test-only spawn failure')):
                with patch('ipa_runtime._hosted_guard'), patch('ipa_runtime._trusted_executable', return_value=config['executable']):
                    with patch('ipa_runtime.subprocess.run', side_effect=error), self.assertRaises(ValueError):
                        execute_ipa_statement(self.statement, self.collection, **config)
            self.assertEqual(list(Path(directory).glob('ipa-msm-*')), [])

    def test_typed_request_and_metadata_guard_prevents_process_and_path_escape(self):
        with self.work() as directory:
            config = self.prepare(directory)
            with patch('ipa_runtime._hosted_guard'), patch('ipa_runtime.subprocess.run', side_effect=AssertionError('unexpected process')):
                with self.assertRaisesRegex(ValueError, 'sealed IpaStatement'):
                    execute_ipa_statement({'passed': True}, self.collection, **config)
                with patch('ipa_runtime._trusted_executable', return_value=config['executable']):
                    bad = dict(config, results_directory=Path.cwd().parent)
                    with self.assertRaisesRegex(ValueError, 'under cwd/results'):
                        execute_ipa_statement(self.statement, self.collection, **bad)
                    config['key_bindings_file'].write_bytes(b'{"changed":true}')
                    with self.assertRaisesRegex(ValueError, 'metadata digest mismatch'):
                        execute_ipa_statement(self.statement, self.collection, **config)


if __name__ == '__main__':
    unittest.main()
