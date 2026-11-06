"""Receipt-free composition of the exact retained Nova profile's math checks.

This accepts an already admitted inner proof, not an arbitrary network proof or
an outer container. The caller owns trusted compiled-helper configuration. The
GitHub/Linux guard protects resources; it is not authentication of that helper.
No external replay result, native receipt or prior execution object is accepted.

Released-source obligations: nova/mod.rs914--1036; spartan/snark.rs259--393;
spartan/mod.rs436--483; provider/ipa_pc.rs286--388 (nova-snark0.76.0).
The dedicated composition flag does not enable general proof/IPA or Script
acceptance, independent Python MSM, assertion binding or transactions.
"""
from dataclasses import dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import time

from ipa_runtime import (IpaExecution, _json, _owned_results, _regular_file,
                         _trusted_executable, execute_ipa_statement)
from ipa_statement import IpaGeneratorCollection, IpaStatement, build_ipa_statements
from matrix_reference import MatrixCollection
from nht4 import ExpectedBundle
from poseidon_reference import PoseidonParameters
from production_replay import (MAX_CAPTURE_BYTES, ReplayKeyBindings, _validate_trace,
                                canonical_sha256, replay_production)
from proof_codec import NOVA_CRATE_SHA256, DecodedProof

SCHEMA = 'bitvm2-nova-retained-math-verification/v1'
EXPECTED_POLICY_SHA256 = 'cdfa31622881cc1863abd1eb252c136184501785b4b02e9985e6ba0850b2ac54'
DIMENSION_SHA256 = 'de6333df2e41b5f5bae1c103fab862f8d6022fd54abeb80ba61920bc9f360edc'
KEY_BINDINGS_SHA256 = 'c8b117ea587c80bfdbdfc0cc262cdf68b1b4c07b3b45ba871413c7768aa62b9a'
TRACE_SHA256 = '394d90b302b2fe6b8f5c0a65ada372d820996f3230770a816961a75cefec59b8'
POSEIDON_SHA256 = 'b55fa125133315243cb299ee7603c5f0508d68abf64f0dab43ecba4a0d09fa67'
MATRIX_PROFILE_SHA256 = '7a69cdd0c39601c988c39719bbfc67386762d516eea8a3fcfc0e23c7938ac921'
MATRIX_COLLECTION_SHA256 = 'fb7dc2a6a27d366a742a97928dffa2209dfdb961f27190164e51494e7a6746e0'
GENERATOR_COLLECTION_SHA256 = 'db1f7cc9a47e0523635f7c52476f784e9c1cfe4e3686c98a54636c1d1a4134d4'
ROLES = (('primary', 'pallas'), ('secondary', 'vesta'))
MAX_TABLE_BYTES = 64 << 20
MAX_SMALL_FILE = 1 << 16
MATRIX_BYTES, MATRIX_ENTRIES = 119_674_848, 2_667_462
GENERATOR_BYTES, GENERATOR_COUNT = 17_301_520, 540_672
FALSE_FLAGS = ('ipa_python_msm_independently_computed', 'ipa_generator_msm_verified',
    'ipa_complete_verification', 'general_proof_verified', 'proof_verified',
    'complete_verifier', 'proof_parser_script_binding', 'challenge_script_binding',
    'bitvm2_script_verified', 'production_assertion_binding', 'bitcoin_transaction_graph',
    'production_transactions_verified')


def _hosted_guard():
    if (os.environ.get('GITHUB_ACTIONS') != 'true'
            or os.environ.get('RUNNER_OS') != 'Linux' or sys.platform != 'linux'):
        raise ValueError('retained math composition is hosted GitHub Linux only')


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def _equal(actual, expected, name):
    if type(actual) is not type(expected) or actual != expected:
        raise ValueError(f'retained math {name} mismatch')


def _pins(decoded, expected, bindings, parameters, matrices, generators, trace_pin):
    types = ((decoded, DecodedProof), (expected, ExpectedBundle), (bindings, ReplayKeyBindings),
             (parameters, PoseidonParameters), (matrices, MatrixCollection),
             (generators, IpaGeneratorCollection))
    if any(type(value) is not cls for value, cls in types):
        raise ValueError('retained math requires admitted proof and all typed pinned inputs')
    if sha256(_canonical(expected.json())).hexdigest() != EXPECTED_POLICY_SHA256:
        raise ValueError('literal retained expected policy mismatch')
    if (decoded.proof_sha256 != expected.proof_sha256 or decoded.proof_bytes != expected.proof_bytes):
        raise ValueError('literal retained proof identity mismatch')
    dimensions = decoded.dimensions
    if (dimensions.descriptor_sha256.hex() != DIMENSION_SHA256
            or bindings.dimensions != dimensions or parameters.dimensions != dimensions
            or matrices.profile.dimensions != dimensions or generators.dimensions != dimensions):
        raise ValueError('literal retained dimension/profile identity mismatch')
    for actual, literal, name in (
        (bindings.metadata_sha256, KEY_BINDINGS_SHA256, 'key bindings'),
        (parameters.parameters_sha256, POSEIDON_SHA256, 'Poseidon parameters'),
        (matrices.profile.profile_sha256, MATRIX_PROFILE_SHA256, 'matrix profile'),
        (matrices.collection_sha256, MATRIX_COLLECTION_SHA256, 'matrix collection'),
        (generators.collection_sha256, GENERATOR_COLLECTION_SHA256, 'generator collection'),
        (trace_pin, TRACE_SHA256, 'trace pin')):
        if type(actual) is not bytes or actual != bytes.fromhex(literal):
            raise ValueError(f'literal retained {name} pin mismatch')
    if (matrices.total_bytes != MATRIX_BYTES or len(matrices.files) != 6
            or sum(file.shape.data_len for file in matrices.files) != MATRIX_ENTRIES
            or generators.total_bytes != GENERATOR_BYTES or len(generators.files) != 2
            or sum(file.count for file in generators.files) != GENERATOR_COUNT):
        raise ValueError('literal retained payload census mismatch')
    for role, engine, count in (('primary', 'pallas', 524288), ('secondary', 'vesta', 16384)):
        dim, file = getattr(dimensions, role), generators.file(role)
        rounds = count.bit_length()-1
        if (dim.engine != engine or dim.num_cons != count or dim.num_vars != count
                or dim.outer_rounds != rounds or dim.inner_rounds != rounds+1
                or dim.ipa_rounds != rounds or dim.batch_rounds != rounds
                or dim.ipa_dimension != count or dim.ck_v_generators != count
                or dim.ck_s_generators != 1 or file.count != count):
            raise ValueError('literal retained role dimension mismatch')


def _owned_trace(value):
    # Bound each node while taking a private copy; no deepcopy/JSON encoding of
    # the caller-owned object occurs. Only the owned snapshot reaches the exact
    # trace validator (which serializes events for accounting). This also avoids
    # a caller mutation between original-object validation and serialization.
    nodes = strings = 0
    def copy(item, depth=0):
        nonlocal nodes, strings
        nodes += 1
        if nodes > 65536 or depth > 10:
            raise ValueError('owned trace node/depth budget')
        if type(item) is dict:
            if len(item) > 16:
                raise ValueError('owned trace object budget')
            result = {}
            for key, child in item.items():
                if type(key) is not str or len(key) > 64 or not key.isascii():
                    raise ValueError('owned trace key budget/type')
                result[key] = copy(child, depth+1)
            return result
        if type(item) is list:
            if len(item) > 2048:
                raise ValueError('owned trace list budget')
            return [copy(child, depth+1) for child in item]
        if type(item) is str:
            strings += len(item)
            if len(item) > 2048 or not item.isascii() or strings > MAX_CAPTURE_BYTES:
                raise ValueError('owned trace string budget')
            return item
        if type(item) is bool:
            return item
        if type(item) is int and 0 <= item < 1 << 64:
            return item
        raise ValueError('unsupported owned trace primitive')
    try:
        snapshot = copy(value)
    except RuntimeError as error:
        raise ValueError('trace mutated while taking owned snapshot') from error
    _validate_trace(snapshot)
    if canonical_sha256(snapshot).hex() != TRACE_SHA256:
        raise ValueError('owned retained trace digest mismatch')
    return snapshot


def _small_pin(path, literal):
    source = _regular_file(path, 'retained verifier metadata')
    if source.stat().st_size > MAX_SMALL_FILE:
        raise ValueError('retained metadata byte budget')
    with source.open('rb') as stream:
        raw = stream.read(MAX_SMALL_FILE+1)
    if sha256(_canonical(_json(raw, MAX_SMALL_FILE))).hexdigest() != literal:
        raise ValueError('retained configured metadata file pin mismatch')
    return source


def _preflight_paths(matrices, generators, *, matrices_directory, generators_directory,
                     native_msm, key_bindings_file, collection_file, results_directory):
    """Trusted configuration/small metadata/stat-only boundary before tables."""
    helper = _trusted_executable(native_msm)
    keys = _small_pin(key_bindings_file, KEY_BINDINGS_SHA256)
    collection = _small_pin(collection_file, GENERATOR_COLLECTION_SHA256)
    for directory in (matrices_directory, generators_directory):
        if type(directory) is not str and not isinstance(directory, Path):
            raise ValueError('trusted retained payload directory path required')
    matrix_dir, generator_dir = Path(matrices_directory), Path(generators_directory)
    for owner, directory in ((matrices, matrix_dir), (generators, generator_dir)):
        for descriptor in owner.files:
            path = _regular_file(directory/descriptor.filename, 'retained authenticated payload')
            if path.stat().st_size != descriptor.bytes:
                raise ValueError('retained authenticated payload file size mismatch')
    results = _owned_results(results_directory)
    return dict(matrices_directory=matrix_dir, generators_directory=generator_dir,
        native_msm=helper, key_bindings_file=keys, collection_file=collection,
        results_directory=results)


def _checked_matrix_replay(replay, decoded, expected, bindings, parameters, matrices):
    if type(replay) is not dict:
        raise ValueError('fresh mandatory matrix replay result required')
    identities = dict(passed=True, proof_sha256=decoded.proof_sha256.hex(),
        key_bindings_sha256=bindings.metadata_sha256.hex(),
        verifier_dimensions_sha256=DIMENSION_SHA256, native_trace_sha256=TRACE_SHA256,
        native_capture_pin_matched=True, poseidon_hashes_independently_verified=True,
        poseidon_full_hashes_checked=5, poseidon_absorption_streams_checked=5,
        poseidon_parameters_sha256=parameters.parameters_sha256.hex(),
        matrix_evaluations_verified=True, matrix_collection_sha256=MATRIX_COLLECTION_SHA256,
        matrix_profile_sha256=MATRIX_PROFILE_SHA256, matrix_files_checked=6,
        matrix_inner_terminals_checked=2,
        matrix_entries_checked=sum(file.shape.data_len for file in matrices.files),
        matrix_bytes_checked=matrices.total_bytes)
    for name, value in identities.items():
        _equal(replay.get(name), value, 'fresh replay '+name)
    engines = replay.get('engines')
    if type(engines) is not list or len(engines) != 2:
        raise ValueError('both ordered mandatory matrix replay engines required')
    for details, (role, engine) in zip(engines, ROLES, strict=True):
        if type(details) is not dict:
            raise ValueError('typed mandatory engine result required')
        for name, value in dict(engine=engine, outer_terminal_checked=True,
                batch_terminal_checked=True, matrix_evaluations_verified=True).items():
            _equal(details.get(name), value, 'engine '+name)
        info = details.get('matrices')
        if type(info) is not dict:
            raise ValueError('mandatory per-role matrix diagnostics required')
        for name, value in dict(role=role, field_role=engine+'_scalar',
                collection_sha256=MATRIX_COLLECTION_SHA256,
                matrix_profile_sha256=MATRIX_PROFILE_SHA256, inner_terminal_checked=True).items():
            _equal(info.get(name), value, 'matrix '+name)
        evaluations = info.get('evaluations')
        if type(evaluations) is not list or len(evaluations) != 3:
            raise ValueError('all A/B/C matrix evaluations required')
        for item, name in zip(evaluations, ('A', 'B', 'C'), strict=True):
            if type(item) is not dict:
                raise ValueError('typed matrix evaluation required')
            descriptor = matrices.file(role, name)
            for key, value in dict(matrix=name, entries_checked=descriptor.shape.data_len,
                    bytes_checked=descriptor.bytes, arithmetic_segments_authenticated=True).items():
                _equal(item.get(key), value, 'matrix evaluation '+key)
    return engines


def _checked_requests(requests, engines, decoded, expected, bindings, parameters, generators):
    if type(requests) is not tuple or len(requests) != 2:
        raise ValueError('both fresh sealed IPA requests required')
    proof = decoded.value
    for statement, details, (role, engine) in zip(requests, engines, ROLES, strict=True):
        if type(statement) is not IpaStatement:
            raise ValueError('factory-only sealed IPA request required')
        _equal(statement.role, role, 'request role')
        _equal(statement.engine, engine, 'request engine')
        request, argument, ipa = statement.json(), proof['snark_'+role]['eval_arg'], details['ipa']
        if (sha256(statement.to_bytes()).digest() != statement.request_sha256
                or statement.to_bytes() != _canonical(request)):
            raise ValueError('sealed request byte digest mismatch')
        identities = dict(schema='bitvm2-nova-ipa-request/v1', role=role, engine=engine,
            nova_version=expected.nova_version, nova_crate_sha256=NOVA_CRATE_SHA256,
            header_revision=expected.header_revision,
            network=expected.network, k=expected.k, steps=expected.steps,
            proof_sha256=decoded.proof_sha256.hex(), bundle_sha256=expected.bundle_sha256.hex(),
            end_state_sha256=expected.end_state_sha256.hex(),
            verifier_key_sha256=expected.verifier_key_sha256.hex(),
            verifier_dimensions_sha256=DIMENSION_SHA256, key_bindings_sha256=KEY_BINDINGS_SHA256,
            native_trace_sha256=TRACE_SHA256, poseidon_parameters_sha256=POSEIDON_SHA256,
            generator_collection_sha256=GENERATOR_COLLECTION_SHA256,
            ipa_dimension=getattr(decoded.dimensions, role).ipa_dimension,
            generator_count=generators.file(role).count,
            joint_commitment=details['joint_commitment'],
            joint_evaluation_le=details['joint_evaluation_le'],
            batch_point_le=details['batch_challenges_le'],
            ipa_initial_challenge_le=ipa['initial_challenge_le'],
            L_vec=[point['comm'] for point in argument['L_vec']],
            R_vec=[point['comm'] for point in argument['R_vec']],
            challenges_le=ipa['challenges_le'], a_hat_le=argument['a_hat'],
            generator_residual=ipa['generator_residual'])
        for name, value in identities.items():
            _equal(request.get(name), value, 'IPA request '+name)
        _equal(request['a_hat_le'], ipa['a_hat_le'], 'fresh replay a_hat')
    return requests


def _checked_execution(executed, statement, generators):
    if type(executed) is not IpaExecution:
        raise ValueError('direct factory-only IpaExecution required; receipts are unsupported')
    for name, value in dict(role=statement.role, engine=statement.engine,
            request_sha256=statement.request_sha256,
            collection_sha256=generators.collection_sha256).items():
        _equal(getattr(executed, name), value, 'direct execution '+name)
    status, native, request = executed.summary(), executed.native_result(), statement.json()
    for name in ('ipa_native_msm_executed', 'ipa_native_relation_checked'):
        _equal(status.get(name), True, 'execution '+name)
    for name in ('ipa_python_msm_independently_computed', 'ipa_generator_msm_verified',
                 'ipa_complete_verification', 'proof_verified', 'bitvm2_script_verified'):
        _equal(status.get(name), False, 'execution '+name)
    for name, value in dict(request_sha256=statement.request_sha256.hex(),
            generator_collection_sha256=GENERATOR_COLLECTION_SHA256,
            key_bindings_sha256=KEY_BINDINGS_SHA256, role=statement.role,
            engine=statement.engine, ipa_dimension=request['ipa_dimension'],
            generator_bytes_authenticated=True, proof_verified=False,
            bitvm2_script_verified=False).items():
        _equal(native.get(name), value, 'native execution '+name)
    terminal = native['terminal']
    for name, value in dict(relation_holds=True, residual_matches_python=True,
            generators_consumed=request['generator_count'], weights_computed=request['ipa_dimension'],
            ipa_rounds=request['ipa_dimension'].bit_length()-1,
            scaled_generator_sum=request['generator_residual'],
            required_generator_residual=request['generator_residual']).items():
        _equal(terminal.get(name), value, 'native terminal '+name)
    # Canonical points, independent b_hat and a_hat scaling were already checked
    # by the direct execution factory. No JSON can enter here as an execution.
    return status, native


@dataclass(frozen=True, init=False)
class RetainedMathVerification:
    _summary: bytes

    def __init__(self, *args, **kwargs):
        raise TypeError('run verify_retained_math directly; no receipt constructor exists')

    def summary(self):
        return json.loads(self._summary)


def verify_retained_math(decoded, expected, bindings, native_trace, *, expected_trace_sha256,
                         poseidon_parameters, matrix_collection, matrices_directory,
                         generator_collection, generators_directory, native_msm,
                         key_bindings_file, collection_file, results_directory=None,
                         max_table_bytes=MAX_TABLE_BYTES):
    """Compose only this literal retained profile, with no external result inputs.

    All operator paths, especially native_msm, are trusted configuration. The
    caller separately frames/admit the container; this API checks its admitted
    inner proof and whole expected policy. Bulk work is hosted-only. General
    proof/IPA, Script and transaction flags remain false even after success.
    """
    _hosted_guard()  # Before filesystem operations, tables, or child processes.
    started = time.monotonic()
    _pins(decoded, expected, bindings, poseidon_parameters, matrix_collection,
          generator_collection, expected_trace_sha256)
    needed = max(32*(curve.num_cons+2*curve.num_vars)
                 for curve in (decoded.dimensions.primary, decoded.dimensions.secondary))
    if type(max_table_bytes) is not int or not needed <= max_table_bytes <= MAX_TABLE_BYTES:
        raise ValueError('retained equality-table budget must cover the profile within64MiB')
    snapshot = _owned_trace(native_trace)
    paths = _preflight_paths(matrix_collection, generator_collection,
        matrices_directory=matrices_directory, generators_directory=generators_directory,
        native_msm=native_msm, key_bindings_file=key_bindings_file,
        collection_file=collection_file, results_directory=results_directory)
    replay = replay_production(decoded, expected, bindings, snapshot,
        expected_trace_sha256=expected_trace_sha256, poseidon_parameters=poseidon_parameters,
        matrix_collection=matrix_collection, matrix_directory=paths['matrices_directory'],
        max_table_bytes=max_table_bytes)
    engines = _checked_matrix_replay(replay, decoded, expected, bindings,
                                    poseidon_parameters, matrix_collection)
    requests = build_ipa_statements(decoded, expected, bindings, snapshot,
        expected_trace_sha256=expected_trace_sha256, poseidon_parameters=poseidon_parameters,
        generator_collection=generator_collection)
    _checked_requests(requests, engines, decoded, expected, bindings, poseidon_parameters,
                      generator_collection)
    roles = []
    for statement, details in zip(requests, engines, strict=True):
        executed = execute_ipa_statement(statement, generator_collection,
            executable=paths['native_msm'], key_bindings_file=paths['key_bindings_file'],
            collection_file=paths['collection_file'],
            generators_directory=paths['generators_directory'], results_directory=paths['results_directory'])
        status, native = _checked_execution(executed, statement, generator_collection)
        evaluations = details['matrices']['evaluations']
        roles.append(dict(role=statement.role, engine=statement.engine,
            request_sha256=statement.request_sha256.hex(),
            ipa_dimension=native['ipa_dimension'], ipa_rounds=native['terminal']['ipa_rounds'],
            matrix_entries_checked=sum(item['entries_checked'] for item in evaluations),
            matrix_bytes_checked=sum(item['bytes_checked'] for item in evaluations),
            matrix_values_le={item['matrix']: item['value_le'] for item in evaluations},
            execution=status, native_wall_seconds=native['wall_seconds'],
            msm_seconds=native['terminal']['msm_seconds']))
    summary = dict(schema=SCHEMA, retained_math_checks_composed=True,
        expected_policy_sha256=EXPECTED_POLICY_SHA256,
        network=expected.network, k=expected.k, steps=expected.steps,
        proof_sha256=decoded.proof_sha256.hex(), proof_bytes=decoded.proof_bytes,
        bundle_sha256=expected.bundle_sha256.hex(), bundle_bytes=expected.bundle_bytes,
        end_state_sha256=expected.end_state_sha256.hex(),
        verifier_key_sha256=expected.verifier_key_sha256.hex(),
        verifier_dimensions_sha256=DIMENSION_SHA256, key_bindings_sha256=KEY_BINDINGS_SHA256,
        native_trace_sha256=TRACE_SHA256, poseidon_parameters_sha256=POSEIDON_SHA256,
        matrix_profile_sha256=MATRIX_PROFILE_SHA256, matrix_collection_sha256=MATRIX_COLLECTION_SHA256,
        generator_collection_sha256=GENERATOR_COLLECTION_SHA256,
        poseidon_hashes_independently_verified=True, poseidon_full_hashes_checked=5,
        outer_terminal_checks=2, batch_terminal_checks=2,
        matrix_files_checked=6, matrix_inner_terminals_checked=2,
        matrix_entries_checked=replay['matrix_entries_checked'], matrix_bytes_checked=matrix_collection.total_bytes,
        ipa_native_msm_executions=2, ipa_native_msm_executed=True, ipa_native_relation_checked=True,
        generator_count=sum(file.count for file in generator_collection.files),
        generator_payload_bytes=generator_collection.total_bytes, roles=roles,
        wall_seconds=time.monotonic()-started, transactions_broadcast=0,
        native_proofs_verified=0,
        container_framing_checked_by_this_call=False,
        scope='literal retained-profile math checks composed with trusted direct native IPA execution')
    summary.update({name: False for name in FALSE_FLAGS})
    result = object.__new__(RetainedMathVerification)
    object.__setattr__(result, '_summary', _canonical(summary))
    return result
