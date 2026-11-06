"""Execute both proof-derived IPA terminals through a trusted hosted CPU helper.

This composes a sealed internal transcript replay with actual bounded process
execution. It never imports a result receipt as authority and does not claim a
general proof or complete Bitcoin Script verifier.
"""
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import time

from bench_compact import peak_rss
from bench_replay import (DIMENSION_PIN, FIXTURES, KEY_PIN, POSEIDON_PIN,
                          TRACE_PIN, read, run as validate_native_report,
                          strict_json)
from ipa_runtime import execute_ipa_statement
from ipa_statement import (IpaGeneratorCollection, build_ipa_statements,
                           load_generator_collection_json)
from nht4 import bind_container, load_expected_json
from poseidon_reference import PoseidonParameters
from production_replay import ReplayKeyBindings
from proof_codec import decode_proof, load_dimensions_json

GENERATOR_PIN = 'db1f7cc9a47e0523635f7c52476f784e9c1cfe4e3686c98a54636c1d1a4134d4'


def run(native_report, generator_dir, native_msm):
    if (os.environ.get('GITHUB_ACTIONS') != 'true'
            or os.environ.get('RUNNER_OS') != 'Linux' or sys.platform != 'linux'):
        raise ValueError('actual IPA MSM benchmark is hosted GitHub Linux only')
    started = time.perf_counter()
    # This validates the original typed native fields and the retained partial
    # replay. Its returned dictionary is never used as an IPA request/receipt.
    validate_native_report(native_report)
    raw = read(Path(native_report), 4 << 20)
    report = strict_json(raw)
    expected = load_expected_json(read(FIXTURES/'nht4-genesis-0-2020-k5.expected.json', 1 << 16))
    dims = load_dimensions_json(read(FIXTURES/'nht4-genesis-0-2020-k5.dimensions.json', 1 << 14),
        expected, expected_descriptor_sha256=bytes.fromhex(DIMENSION_PIN))
    keys_file = FIXTURES/'nht4-genesis-0-2020-k5.key-bindings.json'
    keys = ReplayKeyBindings.from_json(report.get('key_bindings'), expected, dims,
        expected_key_bindings_sha256=bytes.fromhex(KEY_PIN))
    parameters = PoseidonParameters.from_json(report.get('poseidon_parameters'), expected, dims,
        expected_parameters_sha256=bytes.fromhex(POSEIDON_PIN))
    collection_file = FIXTURES/'nht4-genesis-0-2020-k5.ipa-generators.json'
    load_generator_collection_json(read(collection_file, 1 << 16), expected, dims,
        expected_collection_sha256=bytes.fromhex(GENERATOR_PIN))
    if report.get('ipa_generators_sha256') != GENERATOR_PIN:
        raise ValueError('native generator projection differs from independent collection pin')
    collection = IpaGeneratorCollection.from_json(report.get('ipa_generators'), expected, dims,
        expected_collection_sha256=bytes.fromhex(GENERATOR_PIN))
    proof = bind_container(read(FIXTURES/'nht4-genesis-0-2020-k5.nht4', 1 << 20), expected).proof
    decoded = decode_proof(proof, dims)
    statements = build_ipa_statements(decoded, expected, keys, report.get('trace'),
        expected_trace_sha256=bytes.fromhex(TRACE_PIN), poseidon_parameters=parameters,
        generator_collection=collection)
    if tuple(statement.role for statement in statements) != ('primary', 'secondary'):
        raise ValueError('both ordered proof-derived IPA roles required')
    executions = []
    for statement in statements:
        executed = execute_ipa_statement(statement, collection,
            executable=native_msm, key_bindings_file=keys_file, collection_file=collection_file,
            generators_directory=generator_dir, results_directory=FIXTURES.parent/'results')
        executions.append({'statement': statement.summary(),
                           'execution': executed.summary(), 'native': executed.native_result()})
    if not all(row['execution']['ipa_native_relation_checked'] is True for row in executions):
        raise ValueError('both executed IPA terminal relations must pass')
    return {'schema': 'bitvm2-nova-ipa-runtime-conformance/v1',
        'source_native_report_sha256': sha256(raw).hexdigest(),
        'proof_sha256': expected.proof_sha256.hex(), 'generator_collection_sha256': GENERATOR_PIN,
        'roles': executions, 'native_msm_executions': 2, 'generator_count': 540672,
        'generator_payload_bytes': collection.total_bytes,
        'ipa_native_msm_executed': True, 'ipa_native_relation_checked': True,
        'ipa_python_msm_independently_computed': False, 'ipa_generator_msm_verified': False,
        'ipa_complete_verification': False, 'proof_verified': False, 'bitvm2_script_verified': False,
        'native_proof_verifications_in_source_report': 1, 'native_proofs_verified_by_this_command': 0,
        'setup_calls': 0, 'proving_jobs': 0, 'transactions_broadcast': 0,
        'wall_seconds': time.perf_counter()-started, 'parent_peak_rss_bytes': peak_rss(),
        'scope': 'two proof-derived mathematical IPA terminals from direct trusted CPU-helper execution'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native-report', type=Path, required=True)
    parser.add_argument('--generator-dir', type=Path, required=True)
    parser.add_argument('--native-msm', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = run(args.native_report, args.generator_dir, args.native_msm)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2)+'\n', encoding='utf-8')
    print(json.dumps(result))


if __name__ == '__main__':
    main()
