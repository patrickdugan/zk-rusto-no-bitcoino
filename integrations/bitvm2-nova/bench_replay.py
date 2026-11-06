"""Replay the actual retained verifier capture against independent fixture pins.

This checks production protocol conformance, not complete proof validity.
The native report must originate from the separately executed hosted verifier.
"""
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import time

from bench_compact import peak_rss
from nht4 import bind_container, load_expected_json
from matrix_reference import (MatrixCollection, MatrixProfile, load_collection_json,
                              load_profile_json)
from poseidon_reference import PoseidonParameters, load_parameters_json
from proof_codec import VerifierDimensions, decode_proof, load_dimensions_json
from production_replay import ReplayKeyBindings, canonical_sha256, replay_production

FIXTURES = Path(__file__).resolve().parent/'fixtures'
DIMENSION_PIN = 'de6333df2e41b5f5bae1c103fab862f8d6022fd54abeb80ba61920bc9f360edc'
KEY_PIN = 'c8b117ea587c80bfdbdfc0cc262cdf68b1b4c07b3b45ba871413c7768aa62b9a'
TRACE_PIN = '394d90b302b2fe6b8f5c0a65ada372d820996f3230770a816961a75cefec59b8'
POSEIDON_PIN = 'b55fa125133315243cb299ee7603c5f0508d68abf64f0dab43ecba4a0d09fa67'
MATRIX_PROFILE_PIN = '7a69cdd0c39601c988c39719bbfc67386762d516eea8a3fcfc0e23c7938ac921'
MATRIX_COLLECTION_PIN = 'fb7dc2a6a27d366a742a97928dffa2209dfdb961f27190164e51494e7a6746e0'


def read(path, cap):
    with path.open('rb') as source:
        raw = source.read(cap+1)
    if len(raw) > cap:
        raise ValueError('replay input file budget')
    return raw


def strict_json(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError('duplicate replay JSON field')
            value[key] = item
        return value
    def constant(_):
        raise ValueError('non-JSON constant')
    try:
        return json.loads(raw.decode('utf-8'), object_pairs_hook=pairs,
                          parse_constant=constant)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError('invalid replay JSON transport') from error


def run(native_report, *, matrix_dir=None):
    if matrix_dir is not None:
        if os.environ.get('GITHUB_ACTIONS') != 'true':
            raise ValueError('actual matrix replay is hosted-GitHub-Actions-only')
        if (len(MATRIX_COLLECTION_PIN) != 64
                or any(c not in '0123456789abcdef' for c in MATRIX_COLLECTION_PIN)):
            raise ValueError('actual matrix collection has not been independently pinned')
    expected = load_expected_json(read(FIXTURES/'nht4-genesis-0-2020-k5.expected.json', 1 << 16))
    dims = load_dimensions_json(read(FIXTURES/'nht4-genesis-0-2020-k5.dimensions.json', 1 << 14),
        expected, expected_descriptor_sha256=bytes.fromhex(DIMENSION_PIN))
    keys = strict_json(read(FIXTURES/'nht4-genesis-0-2020-k5.key-bindings.json', 1 << 14))
    trace = strict_json(read(FIXTURES/'nht4-genesis-0-2020-k5.trace.json', 1 << 20))
    if canonical_sha256(keys).hex() != KEY_PIN or canonical_sha256(trace).hex() != TRACE_PIN:
        raise ValueError('independent replay fixture pin mismatch')
    load_parameters_json(read(FIXTURES/'nht4-genesis-0-2020-k5.poseidon.json', 2 << 20),
        expected, dims, expected_parameters_sha256=bytes.fromhex(POSEIDON_PIN))
    raw = read(native_report, 4 << 20)
    report = strict_json(raw)
    if (type(report) is not dict or report.get('passed') is not True
            or type(report.get('native_nova_proofs_verified')) is not int
            or report['native_nova_proofs_verified'] != 1
            or report.get('schema') != 'bitvm2-nova-native-production-replay/v1'):
        raise ValueError('successful actual native replay report required')
    identities = {'network': expected.network, 'k': expected.k, 'steps': expected.steps,
        'nova_version': expected.nova_version, 'header_revision': expected.header_revision,
        'bundle_sha256': expected.bundle_sha256.hex(), 'proof_sha256': expected.proof_sha256.hex(),
        'proof_bytes': expected.proof_bytes, 'verifier_key_sha256': expected.verifier_key_sha256.hex(),
        'verifier_dimensions_sha256': DIMENSION_PIN, 'end_state_sha256': expected.end_state_sha256.hex()}
    if any(type(report.get(k)) is not type(v) or report[k] != v for k, v in identities.items()):
        raise ValueError('native replay policy identity mismatch')
    # Validate original report values with the typed factories. Plain dict
    # equality would treat JSON true as equal to integer one in nested fields.
    VerifierDimensions.from_json(report.get('verifier_dimensions'), expected,
        expected_descriptor_sha256=bytes.fromhex(DIMENSION_PIN))
    if report.get('key_bindings_sha256') != KEY_PIN:
        raise ValueError('native key-binding digest differs from independent pin')
    bindings = ReplayKeyBindings.from_json(report.get('key_bindings'), expected, dims,
        expected_key_bindings_sha256=bytes.fromhex(KEY_PIN))
    if report.get('poseidon_parameters_sha256') != POSEIDON_PIN:
        raise ValueError('native Poseidon digest differs from independent pin')
    # Validate the original exported object as well as the retained fixture.
    # The report's printed digest cannot authorize replacement constants.
    parameters = PoseidonParameters.from_json(report.get('poseidon_parameters'), expected, dims,
        expected_parameters_sha256=bytes.fromhex(POSEIDON_PIN))
    matrices = None
    if matrix_dir is not None:
        load_profile_json(read(FIXTURES/'nht4-genesis-0-2020-k5.matrix-profile.json', 1 << 15),
            expected, dims, expected_profile_sha256=bytes.fromhex(MATRIX_PROFILE_PIN))
        profile = MatrixProfile.from_json(report.get('matrix_profile'), expected, dims,
            expected_profile_sha256=bytes.fromhex(MATRIX_PROFILE_PIN))
        load_collection_json(read(FIXTURES/'nht4-genesis-0-2020-k5.matrix-collection.json', 1 << 15),
            expected, profile, expected_collection_sha256=bytes.fromhex(MATRIX_COLLECTION_PIN))
        if report.get('matrix_collection_sha256') != MATRIX_COLLECTION_PIN:
            raise ValueError('native matrix collection differs from independent pin')
        matrices = MatrixCollection.from_json(report.get('matrix_collection'), expected, profile,
            expected_collection_sha256=bytes.fromhex(MATRIX_COLLECTION_PIN))
    proof = bind_container(read(FIXTURES/'nht4-genesis-0-2020-k5.nht4', 1 << 20), expected).proof
    decoded = decode_proof(proof, dims)
    result = replay_production(decoded, expected, bindings, report.get('trace'),
        expected_trace_sha256=bytes.fromhex(TRACE_PIN), poseidon_parameters=parameters,
        matrix_collection=matrices, matrix_directory=matrix_dir,
        max_table_bytes=64 << 20 if matrices is not None else 1 << 20)
    return {'schema': 'bitvm2-nova-production-python-replay/v1',
        'source_native_report_sha256': sha256(raw).hexdigest(),
        'key_bindings_sha256': KEY_PIN, 'trace_sha256': TRACE_PIN,
        'poseidon_parameters_sha256': POSEIDON_PIN,
        'matrix_collection_sha256': MATRIX_COLLECTION_PIN if matrices is not None else None,
        'native_proof_verifications_in_source_report': 1, 'replay': result,
        'native_proofs_verified_by_this_command': 0, 'proving_jobs': 0,
        'scope': 'retained real-proof protocol conformance; incomplete independent verification'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native-report', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--matrix-dir', type=Path,
        help='independently pinned actual matrix export, hosted execution only')
    args = parser.parse_args()
    started = time.perf_counter()
    result = run(args.native_report, matrix_dir=args.matrix_dir)
    result.update(wall_seconds=time.perf_counter()-started, peak_rss_bytes=peak_rss())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2)+'\n', encoding='utf-8')
    replay = result['replay']
    print(json.dumps({'passed': replay['passed'], 'key_bindings_sha256': KEY_PIN,
        'trace_sha256': TRACE_PIN, 'poseidon_parameters_sha256': POSEIDON_PIN,
        'engines': [{key: engine[key] for key in ('engine', 'keccak_events', 'keccak_squeezes',
                                                'outer_terminal_checked', 'batch_terminal_checked')}
                    for engine in replay['engines']],
        'poseidon_absorption_streams_checked': replay['poseidon_absorption_streams_checked'],
        'poseidon_hashes_independently_verified': replay['poseidon_hashes_independently_verified'],
        'matrix_evaluations_verified': replay['matrix_evaluations_verified'],
        'matrix_collection_sha256': replay['matrix_collection_sha256'],
        'matrix_files_checked': replay['matrix_files_checked'],
        'matrix_inner_terminals_checked': replay['matrix_inner_terminals_checked'],
        'matrix_entries_checked': replay['matrix_entries_checked'],
        'matrix_bytes_checked': replay['matrix_bytes_checked'],
        'matrix_evaluations': [engine['matrices'] for engine in replay['engines']],
        'ipa_generator_msm_verified': replay['ipa_generator_msm_verified'],
        'proof_verified': replay['proof_verified'],
        'bitvm2_script_verified': replay['bitvm2_script_verified'],
        'wall_seconds': result['wall_seconds'], 'peak_rss_bytes': result['peak_rss_bytes']}))


if __name__ == '__main__':
    main()
