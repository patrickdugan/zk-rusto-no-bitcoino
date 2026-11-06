"""Tiny orchestration tests; MOCKED coverage is never verification evidence.

Small actual typed fixtures authenticate identities and construct short IPA
requests. Trusted internal matrix/native boundaries are mocked explicitly.
No matrix/generator payload, large table, native child, MSM or proving runs.
There is no caller-facing receipt or injected-execution seam in the API.
"""
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import FrozenInstanceError, replace
from hashlib import sha256
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from ipa_runtime import IpaExecution, IpaRuntimeError, NATIVE_SCOPE, RESULT_SCHEMA
from ipa_statement import (IpaStatement, build_ipa_statements,
                           load_generator_collection_json, _make)
from matrix_reference import load_collection_json, load_profile_json
from nht4 import bind_container, load_expected_json
from poseidon_reference import load_parameters_json
from production_replay import CURVES, ReplayKeyBindings, ipa_factors, replay_production
from proof_codec import SCALAR_MODULI, decode_point, decode_proof, load_dimensions_json
from retained_verifier import RetainedMathVerification, verify_retained_math

FIXTURES = Path(__file__).resolve().parents[1]/'fixtures'
DIMENSION_PIN = bytes.fromhex('de6333df2e41b5f5bae1c103fab862f8d6022fd54abeb80ba61920bc9f360edc')
KEY_PIN = bytes.fromhex('c8b117ea587c80bfdbdfc0cc262cdf68b1b4c07b3b45ba871413c7768aa62b9a')
TRACE_PIN = bytes.fromhex('394d90b302b2fe6b8f5c0a65ada372d820996f3230770a816961a75cefec59b8')
POSEIDON_PIN = bytes.fromhex('b55fa125133315243cb299ee7603c5f0508d68abf64f0dab43ecba4a0d09fa67')
MATRIX_PROFILE_PIN = bytes.fromhex('7a69cdd0c39601c988c39719bbfc67386762d516eea8a3fcfc0e23c7938ac921')
MATRIX_PIN = bytes.fromhex('fb7dc2a6a27d366a742a97928dffa2209dfdb961f27190164e51494e7a6746e0')
GENERATOR_PIN = bytes.fromhex('db1f7cc9a47e0523635f7c52476f784e9c1cfe4e3686c98a54636c1d1a4134d4')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                      allow_nan=False).encode('ascii')


def point_hex(point):
    return '00'*32 if point is None else (point[0] | ((point[1] & 1) << 255)).to_bytes(32, 'little').hex()


class RetainedMathOrchestration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.expected = load_expected_json((FIXTURES/'nht4-genesis-0-2020-k5.expected.json').read_bytes())
        cls.dimensions = load_dimensions_json(
            (FIXTURES/'nht4-genesis-0-2020-k5.dimensions.json').read_bytes(), cls.expected,
            expected_descriptor_sha256=DIMENSION_PIN)
        bundle = (FIXTURES/'nht4-genesis-0-2020-k5.nht4').read_bytes()
        cls.decoded = decode_proof(bind_container(bundle, cls.expected).proof, cls.dimensions)
        cls.bindings = ReplayKeyBindings.from_json(json.loads(
            (FIXTURES/'nht4-genesis-0-2020-k5.key-bindings.json').read_bytes()),
            cls.expected, cls.dimensions, expected_key_bindings_sha256=KEY_PIN)
        cls.parameters = load_parameters_json(
            (FIXTURES/'nht4-genesis-0-2020-k5.poseidon.json').read_bytes(), cls.expected,
            cls.dimensions, expected_parameters_sha256=POSEIDON_PIN)
        cls.trace = json.loads((FIXTURES/'nht4-genesis-0-2020-k5.trace.json').read_bytes())
        profile = load_profile_json((FIXTURES/'nht4-genesis-0-2020-k5.matrix-profile.json').read_bytes(),
            cls.expected, cls.dimensions, expected_profile_sha256=MATRIX_PROFILE_PIN)
        cls.matrices = load_collection_json(
            (FIXTURES/'nht4-genesis-0-2020-k5.matrix-collection.json').read_bytes(),
            cls.expected, profile, expected_collection_sha256=MATRIX_PIN)
        cls.generators = load_generator_collection_json(
            (FIXTURES/'nht4-genesis-0-2020-k5.ipa-generators.json').read_bytes(),
            cls.expected, cls.dimensions, expected_collection_sha256=GENERATOR_PIN)
        # Genuine short transcript reconstruction, without real CSR evaluation.
        cls.partial = replay_production(cls.decoded, cls.expected, cls.bindings, cls.trace,
            expected_trace_sha256=TRACE_PIN, poseidon_parameters=cls.parameters)
        cls.statements = build_ipa_statements(cls.decoded, cls.expected, cls.bindings, cls.trace,
            expected_trace_sha256=TRACE_PIN, poseidon_parameters=cls.parameters,
            generator_collection=cls.generators)
        cls.mock_matrix_replay = cls.matrix_stub()

    @classmethod
    def matrix_stub(cls):
        """MOCK ONLY: metadata-correct control flow, not evaluated matrix data."""
        result = deepcopy(cls.partial)
        entries = 0
        for role, details in zip(('primary', 'secondary'), result['engines'], strict=True):
            evaluations = []
            for matrix in ('A', 'B', 'C'):
                record = cls.matrices.file(role, matrix)
                entries += record.shape.data_len
                value = details['required_matrix_combination_le'] if matrix == 'A' else '00'*32
                evaluations.append(dict(matrix=matrix, value_le=value,
                    entries_checked=record.shape.data_len, bytes_checked=record.bytes,
                    arithmetic_segments_authenticated=True))
            details['matrix_evaluations_verified'] = True
            details['matrices'] = dict(role=role, field_role=details['engine']+'_scalar',
                collection_sha256=MATRIX_PIN.hex(), matrix_profile_sha256=MATRIX_PROFILE_PIN.hex(),
                source='independently pinned original VK CSR matrix streams',
                combination_le=details['required_matrix_combination_le'], inner_terminal_checked=True,
                evaluations=evaluations)
        result.update(matrix_evaluations_verified=True, matrix_collection_sha256=MATRIX_PIN.hex(),
            matrix_profile_sha256=MATRIX_PROFILE_PIN.hex(), matrix_files_checked=6,
            matrix_inner_terminals_checked=2, matrix_entries_checked=entries,
            matrix_bytes_checked=cls.matrices.total_bytes)
        return result

    def invoke(self, **overrides):
        inputs = dict(decoded=self.decoded, expected=self.expected, bindings=self.bindings,
            native_trace=self.trace, expected_trace_sha256=TRACE_PIN,
            poseidon_parameters=self.parameters, matrix_collection=self.matrices,
            matrices_directory=FIXTURES, generator_collection=self.generators,
            generators_directory=FIXTURES, native_msm=Path('/MOCK_ONLY/ipa_msm'),
            key_bindings_file=FIXTURES/'nht4-genesis-0-2020-k5.key-bindings.json',
            collection_file=FIXTURES/'nht4-genesis-0-2020-k5.ipa-generators.json',
            results_directory=FIXTURES.parent/'results')
        inputs.update(overrides)
        return verify_retained_math(**inputs)

    def execution_stub(self, statement, collection, **configuration):
        """PRIVATE TEST OBJECT from a mocked trusted execution boundary only."""
        request, engine = statement.json(), statement.engine
        q, curve = SCALAR_MODULI[engine], CURVES[engine]
        residual = decode_point(bytes.fromhex(request['generator_residual']), engine)
        a_hat = int.from_bytes(bytes.fromhex(request['a_hat_le']), 'little')
        # Deliberately derived from the target, NOT an independent generator
        # MSM. This is only transport-consistent mocked process output.
        generator_sum = curve.mul(residual, pow(a_hat, -1, q)) if a_hat else None
        point = tuple(int.from_bytes(bytes.fromhex(x), 'little') for x in request['batch_point_le'])
        challenges = tuple(int.from_bytes(bytes.fromhex(x), 'little') for x in request['challenges_le'])
        b_hat = ipa_factors(point, challenges, q)['b_hat']
        result = dict(schema=RESULT_SCHEMA, request_sha256=statement.request_sha256.hex(),
            generator_collection_sha256=collection.collection_sha256.hex(), key_bindings_sha256=KEY_PIN.hex(),
            role=statement.role, engine=engine, ipa_dimension=request['ipa_dimension'],
            generator_bytes_authenticated=True, cpu_only=True, wall_seconds=0.01,
            native_proofs_verified=0, proving_jobs=0, proof_verified=False, bitvm2_script_verified=False,
            scope=NATIVE_SCOPE, terminal=dict(relation_holds=True, residual_matches_python=True,
                generators_consumed=request['generator_count'], weights_computed=request['ipa_dimension'],
                ipa_rounds=request['ipa_dimension'].bit_length()-1, weights_sha256='11'*32,
                factorized_b_hat_le=b_hat.to_bytes(32, 'little').hex(), generator_sum=point_hex(generator_sum),
                scaled_generator_sum=request['generator_residual'], required_generator_residual=request['generator_residual'],
                msm_seconds=0.005))
        execution = object.__new__(IpaExecution)
        for key, value in dict(role=statement.role, engine=engine, request_sha256=statement.request_sha256,
            collection_sha256=collection.collection_sha256, helper_path=str(configuration['executable']),
            stdout_bytes=len(canonical(result)), stderr_bytes=0, elapsed_seconds=0.02,
            _result=canonical(result)).items():
            object.__setattr__(execution, key, value)
        return execution

    @contextmanager
    def trusted_boundaries(self, *, matrix_replay=None, statements=None, execute=None):
        replay = deepcopy(self.mock_matrix_replay if matrix_replay is None else matrix_replay)
        config = dict(matrices_directory=FIXTURES, generators_directory=FIXTURES,
            native_msm=Path('/MOCK_ONLY/ipa_msm'),
            key_bindings_file=FIXTURES/'nht4-genesis-0-2020-k5.key-bindings.json',
            collection_file=FIXTURES/'nht4-genesis-0-2020-k5.ipa-generators.json',
            results_directory=FIXTURES.parent/'results')
        with patch('retained_verifier._hosted_guard'), \
             patch('retained_verifier._preflight_paths', return_value=config) as preflight, \
             patch('retained_verifier.replay_production', return_value=replay) as matrix, \
             patch('retained_verifier.build_ipa_statements', return_value=self.statements if statements is None else statements) as prepare, \
             patch('retained_verifier.execute_ipa_statement', side_effect=self.execution_stub if execute is None else execute) as native:
            yield SimpleNamespace(matrix=matrix, prepare=prepare, native=native, replay=replay,
                                  preflight=preflight)

    def test_hosted_resource_guard_precedes_io_replay_and_process_work(self):
        with patch.dict('os.environ', {'GITHUB_ACTIONS': 'false', 'RUNNER_OS': 'Linux'}), \
             patch('pathlib.Path.resolve', side_effect=AssertionError('unexpected path IO')), \
             patch('retained_verifier.replay_production') as replay, \
             patch('retained_verifier.execute_ipa_statement') as execute:
            with self.assertRaises(ValueError):
                self.invoke(decoded={'passed': True}, matrix_collection={'passed': True})
            replay.assert_not_called()
            execute.assert_not_called()

    def test_mocked_conjunction_is_sequential_scoped_and_immutable(self):
        order = []
        def execute(statement, collection, **config):
            order.append(statement.role)
            return self.execution_stub(statement, collection, **config)
        with self.trusted_boundaries(execute=execute) as calls:
            result = self.invoke()
        self.assertIs(type(result), RetainedMathVerification)
        self.assertEqual(order, ['primary', 'secondary'])
        self.assertEqual(calls.matrix.call_count, 1)
        self.assertEqual(calls.prepare.call_count, 1)
        self.assertEqual(calls.native.call_count, 2)
        matrix_args = calls.matrix.call_args.kwargs
        self.assertIs(matrix_args['matrix_collection'], self.matrices)
        self.assertEqual(matrix_args['matrix_directory'], FIXTURES)
        self.assertEqual(matrix_args['max_table_bytes'], 64 << 20)
        summary = result.summary()
        self.assertIs(summary['retained_math_checks_composed'], True)
        for name, count in (('matrix_files_checked', 6), ('matrix_inner_terminals_checked', 2),
                            ('ipa_native_msm_executions', 2), ('generator_count', 540672)):
            self.assertIs(type(summary[name]), int)
            self.assertEqual(summary[name], count)
        for flag in ('proof_verified', 'bitvm2_script_verified', 'ipa_generator_msm_verified',
                     'ipa_complete_verification'):
            self.assertIs(summary[flag], False, flag)
        changed = result.summary()
        changed['retained_math_checks_composed'] = False
        changed['roles'][0]['execution']['ipa_native_relation_checked'] = False
        self.assertIs(result.summary()['retained_math_checks_composed'], True)
        self.assertIs(result.summary()['roles'][0]['execution']['ipa_native_relation_checked'], True)
        with self.assertRaises((FrozenInstanceError, AttributeError)):
            result.retained_math_checks_composed = False
        with self.assertRaises(TypeError):
            RetainedMathVerification()
        self.assertFalse(hasattr(RetainedMathVerification, 'from_json'))

    def test_unsupported_literal_policy_and_replacement_pins_fail_before_replay(self):
        changed_matrix = self.matrices.json()
        changed_matrix['files'][0]['sha256'] = '33'*32
        replacement_matrix = type(self.matrices).from_json(changed_matrix, self.expected, self.matrices.profile,
            expected_collection_sha256=sha256(canonical(changed_matrix)).digest())
        changed_generators = self.generators.json()
        changed_generators['files'][0]['sha256'] = '44'*32
        replacement_generators = type(self.generators).from_json(changed_generators, self.expected,
            self.dimensions, expected_collection_sha256=sha256(canonical(changed_generators)).digest())
        for override in (
            dict(expected=replace(self.expected, steps=405)),
            dict(expected=replace(self.expected, proof_sha256=bytes(32))),
            dict(expected_trace_sha256=bytes(32)), dict(matrix_collection=replacement_matrix),
            dict(generator_collection=replacement_generators), dict(matrix_collection=None),
            dict(max_table_bytes=0), dict(max_table_bytes=True)):
            with self.subTest(override=tuple(override)), self.trusted_boundaries() as calls:
                with self.assertRaises((ValueError, TypeError)):
                    self.invoke(**override)
                calls.preflight.assert_not_called()
                calls.matrix.assert_not_called()
                calls.prepare.assert_not_called()
                calls.native.assert_not_called()

    def test_matrix_failure_prevents_statement_preparation_and_both_msms(self):
        with self.trusted_boundaries() as calls:
            calls.matrix.side_effect = ValueError('MOCK ONLY authenticated CSR failure')
            with self.assertRaisesRegex(ValueError, 'CSR failure'):
                self.invoke()
            calls.prepare.assert_not_called()
            calls.native.assert_not_called()

    def test_caller_trace_mutation_cannot_change_shared_owned_replay_snapshot(self):
        caller_trace, snapshots = deepcopy(self.trace), []
        def matrix_replay(decoded, expected, bindings, trace, **configuration):
            self.assertIsNot(trace, caller_trace)
            self.assertEqual(sha256(canonical(trace)).digest(), TRACE_PIN)
            snapshots.append(trace)
            # Deterministic mutation at the exact boundary between the two
            # internal computations; no thread or real matrix work is needed.
            caller_trace['streams'].clear()
            caller_trace['events'] = 0
            self.assertEqual(trace, self.trace)
            return deepcopy(self.mock_matrix_replay)
        def prepare(decoded, expected, bindings, trace, **configuration):
            self.assertIs(trace, snapshots[0])
            self.assertEqual(trace, self.trace)
            self.assertEqual(sha256(canonical(trace)).digest(), TRACE_PIN)
            self.assertNotEqual(trace, caller_trace)
            return self.statements
        with self.trusted_boundaries() as calls:
            calls.matrix.side_effect = matrix_replay
            calls.prepare.side_effect = prepare
            result = self.invoke(native_trace=caller_trace)
            self.assertEqual((calls.matrix.call_count, calls.prepare.call_count, calls.native.call_count), (1, 1, 2))
        self.assertIs(result.summary()['retained_math_checks_composed'], True)

    def test_owned_trace_list_and_depth_limits_fail_before_preflight_or_math(self):
        deep = 0
        for _ in range(12):
            deep = [deep]
        for trace in ({'bad': deep}, {'bad': [0]*2049}):
            with self.trusted_boundaries() as calls:
                with self.assertRaisesRegex(ValueError, 'owned trace.*budget'):
                    self.invoke(native_trace=trace)
                calls.preflight.assert_not_called()
                calls.matrix.assert_not_called()
                calls.prepare.assert_not_called()
                calls.native.assert_not_called()

    def test_missing_matrix_coverage_roles_and_digests_fail_before_native_execution(self):
        mutations = [
            (('matrix_evaluations_verified',), False), (('matrix_files_checked',), 5),
            (('matrix_inner_terminals_checked',), 1), (('matrix_files_checked',), True),
            (('matrix_collection_sha256',), '00'*32), (('matrix_profile_sha256',), '00'*32),
            (('matrix_bytes_checked',), self.matrices.total_bytes-1),
            (('matrix_entries_checked',), self.mock_matrix_replay['matrix_entries_checked']-1),
            (('engines', 0, 'engine'), 'vesta'),
            (('engines', 0, 'matrix_evaluations_verified'), 1),
            (('engines', 0, 'matrices', 'role'), 'secondary'),
            (('engines', 0, 'matrices', 'collection_sha256'), '00'*32),
            (('engines', 0, 'matrices', 'inner_terminal_checked'), False),
            (('engines', 0, 'matrices', 'evaluations'), self.mock_matrix_replay['engines'][0]['matrices']['evaluations'][:2]),
            (('engines', 1, 'matrices', 'evaluations', 0, 'arithmetic_segments_authenticated'), False),
            (('engines', 1, 'matrices', 'evaluations', 0, 'bytes_checked'), 0),
        ]
        for path, replacement in mutations:
            altered = deepcopy(self.mock_matrix_replay)
            destination = altered
            for key in path[:-1]:
                destination = destination[key]
            destination[path[-1]] = replacement
            with self.subTest(path=path), self.trusted_boundaries(matrix_replay=altered) as calls:
                with self.assertRaises(ValueError):
                    self.invoke()
                calls.native.assert_not_called()

    def test_plain_receipt_cannot_replace_typed_direct_execution(self):
        with self.trusted_boundaries(execute=lambda *args, **kwargs: {'relation_holds': True}) as calls:
            with self.assertRaises(ValueError):
                self.invoke()
            self.assertEqual(calls.native.call_count, 1)

    def test_first_ipa_error_prevents_second_role_and_no_result_is_returned(self):
        def fail(statement, collection, **configuration):
            self.assertEqual(statement.role, 'primary')
            raise IpaRuntimeError('MOCK ONLY first native process failed')
        with self.trusted_boundaries(execute=fail) as calls:
            with self.assertRaisesRegex(ValueError, 'first native process failed'):
                self.invoke()
            self.assertEqual(calls.native.call_count, 1)

    def test_prepared_request_math_must_match_mandatory_matrix_replay(self):
        for index, original in enumerate(self.statements):
            base = original.json()
            replacements = [('joint_commitment', '00'*32),
                ('joint_evaluation_le', '00'*32), ('ipa_initial_challenge_le', '00'*32),
                ('a_hat_le', '00'*32), ('key_bindings_sha256', '00'*32),
                ('native_trace_sha256', '00'*32), ('proof_sha256', '00'*32),
                ('generator_residual', '00'*32)]
            replacements += [(key, ['00'*32]+base[key][1:])
                             for key in ('batch_point_le', 'L_vec', 'R_vec', 'challenges_le')]
            for key, replacement in replacements:
                request = deepcopy(base)
                self.assertNotEqual(request[key], replacement)
                request[key] = replacement
                encoded = canonical(request)
                altered = _make(IpaStatement, role=original.role, engine=original.engine,
                    request_sha256=sha256(encoded).digest(), _json=encoded)
                requests = list(self.statements)
                requests[index] = altered
                with self.subTest(role=original.role, key=key), self.trusted_boundaries(statements=tuple(requests)) as calls:
                    with self.assertRaises(ValueError):
                        self.invoke()
                    calls.native.assert_not_called()
        with self.trusted_boundaries(statements=tuple(reversed(self.statements))) as calls:
            with self.assertRaises(ValueError):
                self.invoke()
            calls.native.assert_not_called()

    def test_second_role_failure_cannot_return_a_successful_conjunction(self):
        def execute(statement, collection, **config):
            if statement.role == 'secondary':
                raise IpaRuntimeError('MOCK ONLY second native process failed')
            return self.execution_stub(statement, collection, **config)
        with self.trusted_boundaries(execute=execute) as calls:
            with self.assertRaisesRegex(ValueError, 'second native process failed'):
                self.invoke()
            self.assertEqual(calls.native.call_count, 2)

    def test_typed_execution_with_false_relation_or_wrong_residual_is_rejected(self):
        for path, replacement in ((('terminal', 'relation_holds'), False),
            (('terminal', 'residual_matches_python'), False),
            (('terminal', 'scaled_generator_sum'), '00'*32),
            (('terminal', 'required_generator_residual'), '00'*32),
            (('terminal', 'generators_consumed'), True),
            (('generator_bytes_authenticated',), 1), (('proof_verified',), True)):
            def execute(statement, collection, **config):
                actual = self.execution_stub(statement, collection, **config)
                result = actual.native_result()
                destination = result
                for key in path[:-1]:
                    destination = destination[key]
                destination[path[-1]] = replacement
                object.__setattr__(actual, '_result', canonical(result))
                return actual
            with self.subTest(path=path), self.trusted_boundaries(execute=execute) as calls:
                with self.assertRaises(ValueError):
                    self.invoke()
                self.assertEqual(calls.native.call_count, 1)

    def test_execution_role_request_and_collection_identity_mismatches_fail(self):
        for key, replacement in (('role', 'secondary'), ('engine', 'vesta'),
            ('request_sha256', bytes(32)), ('collection_sha256', bytes(32))):
            def execute(statement, collection, **config):
                actual = self.execution_stub(statement, collection, **config)
                object.__setattr__(actual, key, replacement)  # PRIVATE malformed internal result only.
                return actual
            with self.subTest(key=key), self.trusted_boundaries(execute=execute) as calls:
                with self.assertRaises(ValueError):
                    self.invoke()
                self.assertEqual(calls.native.call_count, 1)

    def test_receipt_override_keywords_are_not_public_parameters(self):
        for keyword in ('replay', 'matrix_results', 'native_results', 'executions', 'receipt'):
            with self.subTest(keyword=keyword), self.trusted_boundaries() as calls:
                with self.assertRaises(TypeError):
                    self.invoke(**{keyword: {'passed': True}})
                calls.matrix.assert_not_called()
                calls.native.assert_not_called()


if __name__ == '__main__':
    unittest.main()
