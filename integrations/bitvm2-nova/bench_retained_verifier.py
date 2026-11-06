"""Hosted composition of retained matrix replay and both direct IPA terminals.

Only small independently pinned fixture files enter the sealed composition API.
No external native/replay report or execution receipt is accepted as input.
Actual matrices, generator vectors and native MSM execution stay in hosted CI.
The result concerns the one retained profile, not general proof acceptance or
complete Bitcoin Script verification.
"""
import argparse
from hashlib import sha256
from pathlib import Path
import json
import os
import sys
import time

from bench_compact import peak_rss

FIXTURES = Path(__file__).resolve().parent/'fixtures'
DIMENSION_PIN = 'de6333df2e41b5f5bae1c103fab862f8d6022fd54abeb80ba61920bc9f360edc'
KEY_PIN = 'c8b117ea587c80bfdbdfc0cc262cdf68b1b4c07b3b45ba871413c7768aa62b9a'
TRACE_PIN = '394d90b302b2fe6b8f5c0a65ada372d820996f3230770a816961a75cefec59b8'
POSEIDON_PIN = 'b55fa125133315243cb299ee7603c5f0508d68abf64f0dab43ecba4a0d09fa67'
MATRIX_PROFILE_PIN = '7a69cdd0c39601c988c39719bbfc67386762d516eea8a3fcfc0e23c7938ac921'
MATRIX_COLLECTION_PIN = 'fb7dc2a6a27d366a742a97928dffa2209dfdb961f27190164e51494e7a6746e0'
GENERATOR_PIN = 'db1f7cc9a47e0523635f7c52476f784e9c1cfe4e3686c98a54636c1d1a4134d4'
MATRIX_BYTES, GENERATOR_BYTES, GENERATORS = 119674848, 17301520, 540672
FALSE_FLAGS = ('ipa_python_msm_independently_computed','ipa_generator_msm_verified',
    'ipa_complete_verification','general_proof_verified','proof_verified','complete_verifier',
    'proof_parser_script_binding','challenge_script_binding','bitvm2_script_verified',
    'production_assertion_binding','bitcoin_transaction_graph','production_transactions_verified')


def _hosted_guard():
    # A resource guard only: environment variables never authenticate evidence.
    if (os.environ.get('GITHUB_ACTIONS') != 'true'
            or os.environ.get('RUNNER_OS') != 'Linux' or sys.platform != 'linux'):
        raise ValueError('retained math composition is hosted GitHub Linux only')


def _load_inputs():
    """Small metadata/proof reads only; callers must first enforce the guard."""
    from bench_replay import read, strict_json
    from ipa_statement import load_generator_collection_json
    from matrix_reference import load_collection_json, load_profile_json
    from nht4 import bind_container, load_expected_json
    from poseidon_reference import load_parameters_json
    from production_replay import ReplayKeyBindings, canonical_sha256
    from proof_codec import decode_proof, load_dimensions_json

    expected = load_expected_json(read(FIXTURES/'nht4-genesis-0-2020-k5.expected.json', 1 << 16))
    dims = load_dimensions_json(read(FIXTURES/'nht4-genesis-0-2020-k5.dimensions.json', 1 << 14),
        expected, expected_descriptor_sha256=bytes.fromhex(DIMENSION_PIN))
    bindings = ReplayKeyBindings.from_json(
        strict_json(read(FIXTURES/'nht4-genesis-0-2020-k5.key-bindings.json', 1 << 14)), expected, dims,
        expected_key_bindings_sha256=bytes.fromhex(KEY_PIN))
    parameters = load_parameters_json(read(FIXTURES/'nht4-genesis-0-2020-k5.poseidon.json', 2 << 20),
        expected, dims, expected_parameters_sha256=bytes.fromhex(POSEIDON_PIN))
    trace = strict_json(read(FIXTURES/'nht4-genesis-0-2020-k5.trace.json', 1 << 20))
    if canonical_sha256(trace) != bytes.fromhex(TRACE_PIN):
        raise ValueError('retained trace fixture differs from independent pin')
    profile = load_profile_json(read(FIXTURES/'nht4-genesis-0-2020-k5.matrix-profile.json', 1 << 15),
        expected, dims, expected_profile_sha256=bytes.fromhex(MATRIX_PROFILE_PIN))
    matrices = load_collection_json(read(FIXTURES/'nht4-genesis-0-2020-k5.matrix-collection.json', 1 << 15),
        expected, profile, expected_collection_sha256=bytes.fromhex(MATRIX_COLLECTION_PIN))
    generators = load_generator_collection_json(
        read(FIXTURES/'nht4-genesis-0-2020-k5.ipa-generators.json', 1 << 16), expected, dims,
        expected_collection_sha256=bytes.fromhex(GENERATOR_PIN))
    if (matrices.total_bytes != MATRIX_BYTES or generators.total_bytes != GENERATOR_BYTES
            or sum(file.count for file in generators.files) != GENERATORS):
        raise ValueError('retained metadata byte/cardinality census mismatch')
    proof = bind_container(read(FIXTURES/'nht4-genesis-0-2020-k5.nht4', 1 << 20), expected).proof
    return dict(decoded=decode_proof(proof,dims), expected=expected, bindings=bindings,
        native_trace=trace, poseidon_parameters=parameters, matrix_collection=matrices,
        generator_collection=generators)


def _compose(inputs,matrix_dir,generator_dir,native_msm):
    from retained_verifier import RetainedMathVerification, verify_retained_math
    result = verify_retained_math(inputs['decoded'],inputs['expected'],inputs['bindings'],inputs['native_trace'],
        expected_trace_sha256=bytes.fromhex(TRACE_PIN),poseidon_parameters=inputs['poseidon_parameters'],
        matrix_collection=inputs['matrix_collection'],matrices_directory=matrix_dir,
        generator_collection=inputs['generator_collection'],native_msm=native_msm,
        key_bindings_file=FIXTURES/'nht4-genesis-0-2020-k5.key-bindings.json',
        collection_file=FIXTURES/'nht4-genesis-0-2020-k5.ipa-generators.json',
        generators_directory=generator_dir,results_directory=FIXTURES.parent/'results')
    if type(result) is not RetainedMathVerification:
        raise ValueError('sealed retained composition result required')
    return result


def _checked_summary(summary,expected):
    """Check a sealed API's summary contract, never load an external receipt."""
    if type(summary) is not dict:
        raise ValueError('retained composition summary must be an object')
    policy = json.dumps(expected.json(),sort_keys=True,separators=(',',':'),
                        ensure_ascii=True,allow_nan=False).encode('ascii')
    required = dict(schema='bitvm2-nova-retained-math-verification/v1',
        retained_math_checks_composed=True,matrix_files_checked=6,
        matrix_inner_terminals_checked=2,ipa_native_msm_executions=2,generator_count=GENERATORS,
        matrix_bytes_checked=MATRIX_BYTES,generator_payload_bytes=GENERATOR_BYTES,
        matrix_entries_checked=2667462,transactions_broadcast=0,native_proofs_verified=0,
        container_framing_checked_by_this_call=False,
        expected_policy_sha256=sha256(policy).hexdigest(),
        proof_sha256=expected.proof_sha256.hex(),bundle_sha256=expected.bundle_sha256.hex(),
        end_state_sha256=expected.end_state_sha256.hex(),verifier_key_sha256=expected.verifier_key_sha256.hex(),
        verifier_dimensions_sha256=DIMENSION_PIN,key_bindings_sha256=KEY_PIN,
        native_trace_sha256=TRACE_PIN,poseidon_parameters_sha256=POSEIDON_PIN,
        matrix_profile_sha256=MATRIX_PROFILE_PIN,matrix_collection_sha256=MATRIX_COLLECTION_PIN,
        generator_collection_sha256=GENERATOR_PIN)
    required.update({name:False for name in FALSE_FLAGS})
    for name,value in required.items():
        if type(summary.get(name)) is not type(value) or summary[name] != value:
            raise ValueError(f'retained composition summary {name} mismatch')
    roles = summary.get('roles')
    if (type(roles) is not list or len(roles) != 2
            or any(type(row) is not dict for row in roles)
            or [row.get('role') for row in roles] != ['primary','secondary']):
        raise ValueError('both ordered retained composition roles required')
    encoded = json.dumps(summary,sort_keys=True,separators=(',',':'),
                         ensure_ascii=True,allow_nan=False).encode('ascii')
    if len(encoded) > 1 << 20:
        raise ValueError('retained composition summary byte budget')
    return json.loads(encoded)


def run(matrix_dir,generator_dir,native_msm):
    _hosted_guard()
    started = time.perf_counter()
    inputs = _load_inputs()
    result = _compose(inputs,matrix_dir,generator_dir,native_msm)
    summary = _checked_summary(result.summary(),inputs['expected'])
    return {'schema':'bitvm2-nova-retained-math-composition/v1',
        'retained_math_checks_composed':True,'composition':summary,
        'proof_sha256':inputs['expected'].proof_sha256.hex(),
        'bundle_sha256':inputs['expected'].bundle_sha256.hex(),
        'verifier_key_sha256':inputs['expected'].verifier_key_sha256.hex(),
        'verifier_dimensions_sha256':DIMENSION_PIN,'key_bindings_sha256':KEY_PIN,
        'trace_sha256':TRACE_PIN,'poseidon_parameters_sha256':POSEIDON_PIN,
        'matrix_profile_sha256':MATRIX_PROFILE_PIN,'matrix_collection_sha256':MATRIX_COLLECTION_PIN,
        'generator_collection_sha256':GENERATOR_PIN,
        'matrix_files_checked':6,'matrix_inner_terminals_checked':2,
        'ipa_native_executions':2,'generators_consumed':GENERATORS,
        'matrix_payload_bytes':MATRIX_BYTES,'generator_payload_bytes':GENERATOR_BYTES,
        'external_native_report_loaded':False,'replay_receipt_loaded':False,
        'proof_verified':False,'bitvm2_script_verified':False,'ipa_complete_verification':False,
        'ipa_python_msm_independently_computed':False,'complete_bitvm2_verifier':False,
        'ipa_generator_msm_verified':False,'general_proof_verified':False,'complete_verifier':False,
        'production_assertion_binding':False,'bitcoin_transaction_graph':False,
        'native_proofs_verified_by_this_command':0,'native_complete_proofs_verified':0,
        'setup_calls':0,'proving_jobs':0,'transactions_broadcast':0,
        'wall_seconds':time.perf_counter()-started,'parent_peak_rss_bytes':peak_rss(),
        'hosted_resource_guard_satisfied':True,
        'scope':'one retained profile: fresh matrix replay and two direct IPA terminals; incomplete independent verification'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--matrix-dir',type=Path,required=True)
    parser.add_argument('--generator-dir',type=Path,required=True)
    parser.add_argument('--native-msm',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args = parser.parse_args()
    result = run(args.matrix_dir,args.generator_dir,args.native_msm)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(result,indent=2)+'\n',encoding='ascii',newline='\n')
    print(json.dumps(result))


if __name__ == '__main__':
    main()
