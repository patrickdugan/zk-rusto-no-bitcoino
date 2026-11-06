"""Check hosted digest/reduction evidence; never an acceptance receipt API."""
import json
from pathlib import Path


def main():
    root = Path('results')
    load = lambda name: json.loads((root/name).read_bytes())
    generation = load('digest-generation.json')
    inputs = load('digest-oracle-inputs.json')
    mature = load('digest-oracle-execution.json')
    native = load('digest-registry-execution.json')
    if generation['cases'] != 30 or generation['mature_oracle_cases'] != 10:
        raise ValueError('bounded digest fixture census changed')
    if (mature.get('passed') is not True or mature['case_count'] != 10
            or mature['native_reductions'] != 10 or len(mature['results']) != 10
            or mature['fields_checked'] != {'Fp': 5, 'Fq': 5}):
        raise ValueError('ten mature reductions must execute over both fields')
    if mature['op_endian'] != 'unsigned-little-endian-512-to-canonical-little-endian-32':
        raise ValueError('mature reduction encoding changed')
    for actual, expected in zip(mature['results'], inputs['cases'], strict=True):
        if (any(actual[key] != expected[key] for key in
                ('name', 'field_role', 'input_le', 'expected_le'))
                or actual['reduced_le'] != expected['expected_le']
                or actual.get('matched') is not True):
            raise ValueError('mature result detached from its exact byte input')
    for flag in ('proof_verified', 'bitvm2_script_verified', 'production_assertion_binding',
            'complete_nova_verifier', 'bitcoin_transaction_graph',
            'trusted_acceptance_receipt', 'panic_is_rejection'):
        if mature.get(flag) is not False:
            raise ValueError('mature oracle scope exceeded: '+flag)
    for count in ('native_proofs_verified', 'setup_calls', 'proving_jobs',
                  'matrix_jobs', 'msm_jobs', 'gpu_jobs', 'transactions_broadcast'):
        if type(mature.get(count)) is not int or mature[count] != 0:
            raise ValueError('unexpected work: '+count)
    expected = {
        'cases': generation['cases'],
        'native_rejections': generation['expected_native_rejections'],
        'signatures_generated_once_per_wire': generation['expected_signatures'],
        'shared_convolution_carry_links_checked': generation['expected_shared_carry_links'],
    }
    if native.get('passed') is not True or any(
            type(native.get(key)) is not int or native[key] != value
            for key, value in expected.items()):
        raise ValueError('native admission/signature/carry coverage mismatch')
    if (native['metrics']['vectors'] != generation['expected_vectors']
            or native['metrics']['expected_rejections'] != generation['expected_rejections']):
        raise ValueError('actual Script coverage mismatch')
    if len(native['ledger']) != 4 or len(generation['measured']) != 4:
        raise ValueError('two complete digest and two baseline catalogues required')
    for actual, expected in zip(native['ledger'], generation['measured'], strict=True):
        if (any(actual[key] != expected[key] for key in
                ('case', 'catalogue_id', 'words', 'leaves'))
                or actual['executed_leaves'] != actual['leaves']
                or actual['all_disproof_script_bytes'] <= 0):
            raise ValueError('measured complete catalogue detached from sealed source')
        shape = (actual['words'], actual['leaves'])
        required = (955, 373) if actual['case'].endswith('/digest-reduce512') else (379, 245)
        if shape != required:
            raise ValueError('digest or unchanged uniform baseline shape changed')
    if (native.get('stack_limit_enabled') is not True or native.get('op_cat_enabled') is not False
            or native.get('complete_nova_verifier') is not False
            or native.get('bitcoin_transaction_graph') is not False
            or native.get('transactions_broadcast') != 0):
        raise ValueError('Script execution scope changed')
    if (native.get('shared_digest_byte_links_checked') != 256
            or native.get('digest_layout_rejections') != 24):
        raise ValueError('ordered digest byte opening/substitution coverage changed')
    fragments = native.get('digest_reduction_fragments', [])
    disproofs = native.get('digest_reduction_disproofs', [])
    roles = ('pallas_scalar', 'vesta_scalar')
    fragment_names = {role+'/digest-reduce512' for role in roles}
    disproof_names = {role+'/digest-attack-coherent-'+attack for role in roles
                     for attack in ('low', 'high', 'producer')}
    if (len(fragments) != 2 or {item['case'] for item in fragments} != fragment_names
            or len(disproofs) != 6 or {item['case'] for item in disproofs} != disproof_names):
        raise ValueError('two honest catalogues and six coherent disproofs required')
    ledger = {item['case']: item for item in native['ledger']}
    for fragment in fragments:
        measured = ledger[fragment['case']]
        if (fragment['claimed_digest_bits'] != 512 or fragment['byte_bridge_pairs'] != 64
                or fragment['shared_auxiliary_and_input_byte_opening_links_checked'] != 128
                or fragment['taproot_selected_ordinal'] != 245
                or fragment['claimed_digest_bits_to_reduction_inputs_linked'] is not True
                or fragment['taproot_compiled_script_bytes'] != measured['all_disproof_script_bytes']
                or fragment['taproot_leaf_stream_sha256'] != measured['leaf_stream_sha256']):
            raise ValueError('ordered bridge disconnected from its full measured catalogue')
    for disproof in disproofs:
        ordinal = (309 if disproof['case'].endswith('/digest-attack-coherent-high') else
                   245 if disproof['case'].endswith('/digest-attack-coherent-low') else 244)
        if (disproof['false_predicate_ordinal'] != ordinal
                or disproof['taproot_selected_ordinal'] != ordinal
                or disproof['executed_leaves'] != 373
                or disproof['only_false_predicate'] is not True
                or disproof['actual_selected_disproof_executed'] is not True):
            raise ValueError('coherent attack did not execute its actual bridge disproof')
    for item in fragments+disproofs:
        if (item['offline_taproot_membership_verified'] is not True
                or item['taproot_roots_independently_pinned'] is not False
                or type(item['taproot_control_block_bytes']) is not int
                or item['taproot_control_block_bytes'] <= 33):
            raise ValueError('fresh offline catalogue membership not checked')
        for flag in ('keccak_output_source_authenticated', 'full_hash_verified',
                     'transcript_verified', 'proof_verified', 'complete_nova_verifier',
                     'production_assertion_binding', 'bitcoin_transaction_graph'):
            if item.get(flag) is not False:
                raise ValueError('digest reduction scope exceeded: '+flag)
    print('digest/reduction hosted evidence matched its exact generated corpus')


if __name__ == '__main__':
    main()
