"""Tiny record-budget policy checks only; no real graph or native worker."""
import unittest
import copy
import os
from unittest.mock import patch

import bench_byte_rho_chain as bench


def _synthetic():
    """Invented transport metadata, never native/proof/tree execution evidence."""
    descriptors, rows, census = [], [], []
    counts = dict(signature_entries_created=147355,local_declared_words=148401,
        cached_signature_reuses=1046,canonical_internal_opening_links=46,
        internal_cached_boundary_entries=23000,internal_producer_consumer_opening_links=46000)
    layouts = (23,23,61,30,23,9,23,23,61)
    forest_negatives = ('altered_script','branch','parity','internal_key','leaf_version','truncated_control',
        'appended_control','manifest','root','output_key','component','ordinal','reordered_components')
    local_negatives = ('altered_script','branch','parity','internal_key','leaf_version','truncated_control',
        'appended_control','root','output_key','ordinal','registry','catalogue')
    for name,role,counter,profile in bench._requests():
        honest = profile == 'honest'
        failed_component,failed_leaf = (8,244) if honest else (0,29072) if profile == 'coherent-rho-raw' else (4,29177)
        headers,parts,component_census = [],[],[]
        for i,(branch,words,leaves) in enumerate(zip(bench.BRANCHES,bench.COMPONENT_WORDS,bench.COMPONENT_LEAVES,strict=True)):
            mode,selected = bench._selection(profile,i)
            executed = leaves if mode=='all' else len(selected) if mode=='selected' else 0
            false = [] if honest or i != failed_component else [failed_leaf]
            descriptor = dict(index=i,branch=branch,kind='full-permutation' if i in bench.FULL_COMPONENTS else 'synthetic-small',
                operation_id=f'test/{branch}',program_sha256='11'*32,catalogue_id='22'*32,source_sha256='33'*32,
                source_maps_sha256='44'*32,global_ids_sha256='55'*32,words=words,leaves=leaves,
                counter=counter if i<3 else counter+1,field_role=role,program_identity_kind='test-only invented identity')
            header = dict(descriptor=descriptor,execution_mode=mode,selected_ordinals=selected,expected_false=false)
            part = dict(descriptor,context=bench.CONTEXT.hex(),registry_id='66'*32,compiled_script_bytes=100*leaves,
                largest_disproof_leaf_bytes=100,compiled_stream_sha256='77'*32,execution_mode=mode,
                selected_ordinals=selected,executed_leaves=executed,native_predicates_checked=leaves,
                false_predicates=list(false),guard_layouts=layouts[i],guard_vectors=14*layouts[i])
            headers.append(header); parts.append(part)
            component_census.append(dict(selected_leaf_checks=executed,guard_layouts=layouts[i],words=words,leaves=leaves))
        source = dict(name=name,profile=profile,role=role,rho_counter=counter,c_counter=counter+1,
            execution_mode='full' if honest else 'targeted',source_sha256='88'*32,source_maps_sha256='99'*32,
            expected_rho_raw_state_le='aa'*64,expected_c_raw_state_le='bb'*64,
            expected_rho_result_le='cc'*32,expected_c_result_le='dd'*32,components=headers)
        forest = dict(components=9,leaf_count=147043,compiled_script_bytes=14704300,
            selected_component=failed_component,selected_leaf=failed_leaf,
            control_block_bytes=353 if honest else 609 if failed_component==0 else 577,
            merkle_root='12'*32,output_key='13'*32,control_block_sha256='14'*32,selected_script_sha256='15'*32,
            component_manifest_sha256='16'*32,compiled_stream_sha256='17'*32,
            hierarchical_membership_verified=True,roots_independently_pinned=False,
            negative_counts={key:1 for key in forest_negatives})
        row = {key:source[key] for key in source if key not in ('components',)}
        row.update(**counts,all_native_predicates_checked=147043,selected_leaf_checks=147043 if honest else 823,
            guard_layouts=276,guard_vectors=3864,native_rejections=216,map_rejections=12,source_rejections=18,
            cache_rejections=96,selected_component=failed_component,selected_leaf=failed_leaf,
            additional_selected_engine_executions=2,selected_correctness_execution_success=honest,
            selected_disproof_execution_success=not honest,full_statement_executed=honest,components=parts,forest=forest,
            connections=[dict(kind=kind,logical_links=logical,opening_links=opening) for kind,logical,opening in (
                ('rho_messages',96,384),('rho_frames',208,416),('rho_reduction',64,64),('coefficients',64,128),
                ('prefix_frame',77,154),('rho_raw_prefix',59,118),('rho_raw_absorb',5,5),('prefix_absorb',9,9),
                ('prefix_suffix',383,766),('absorb_suffix',17,34),('c_reduction',64,64))])
        descriptors.append(source); rows.append(row); census.append(component_census)
    probe_headers,probes,probe_census = [],[],[]
    for name,role,kind,component,leaves in bench._probe_requests():
        words,layout = (187,32) if component==3 else (23,5)
        false = {'coefficient-c0-modulus':109,'coefficient-c2-modulus':110,'frame-counter':37,'frame-NoDS':33,
            'frame-tag':32,'frame-zero-capacity':45,'absorb-wrong-xor':0,'absorb-selector':8,
            'absorb-delimiter':6,'absorb-end-mask':7}[kind]
        source = dict(name=name,role=role,kind=kind,source_case=name[0]+'/h',source_component=component,
            source_sha256='33'*32,catalogue_id='22'*32,program_sha256='11'*32,words=words,leaves=leaves,
            expected_false=[false],selected_leaf=false)
        tree = dict(leaf_count=leaves,compiled_script_bytes=100*leaves,compiled_stream_sha256='77'*32,
            control_block_bytes=225 if false in (109,110) else 257 if component==3 else 161 if false==0 else 129,
            merkle_root='12'*32,output_key='13'*32,control_block_sha256='14'*32,selected_script_sha256='15'*32,
            membership_verified=True,roots_independently_pinned=False,negative_counts={key:1 for key in local_negatives})
        row = {key:source[key] for key in source if key != 'expected_false'}
        row.update(context=bench.CONTEXT.hex(),registry_id='66'*32,compiled_script_bytes=100*leaves,
            largest_disproof_leaf_bytes=100,compiled_stream_sha256='77'*32,executed_leaves=leaves,
            false_predicates=[false],signature_entries_created=words,guard_layouts=layout,guard_vectors=14*layout,
            native_rejections=24,additional_selected_engine_executions=2,
            selected_correctness_execution_success=False,selected_disproof_execution_success=True,tree=tree)
        probe_headers.append(source); probes.append(row)
        probe_census.append(dict(guard_layouts=layout,selected_leaf_checks=leaves,words=words,leaves=leaves))
    native = dict(schema='bitvm2-nova-byte-rho-chain-execution/v1',passed=True,input_manifest_sha256='18'*32,
        cases=rows,probes=probes,compact_execution_records_bytes=118000000,compact_execution_records_sha256='19'*32,
        wall_seconds=10.0,full_statement_cases=2,targeted_statement_cases=4,
        private_probe_signature_entries_created=2428,private_probe_registries=20,private_probe_trees=20,
        rho_to_sumcheck_chain_script_conformance_checked=True,all_native_reference_predicates_checked=True,
        boundary_opening_links_checked=True,rho_raw_state_linked_to_next_c=True,coefficients_canonical_script_bound=True,
        prefix_unpadded_first_block_checked=True,second_absorption_rate_xor_checked=True,
        capacity_forwarding_opening_links_checked=True,shared_prefix_used_once=True,digest_reduction_script_bound=True,
        test_keys_only=True,stack_limit_enabled=True,hierarchical_membership_verified=True,
        private_probe_keys_separate=True,private_probe_all_leaves_executed=True,
        all_cases_full_statement_executed=False,raw_vector_file_written=False,op_cat_enabled=False,
        full_permutation_verified=False,full_hash_verified=False,transcript_verified=False,
        nova_transcript_verified_in_script=False,proof_verified=False,complete_nova_verifier=False,
        complete_bitvm2_verifier=False,production_assertion_binding=False,bitcoin_transaction_graph=False,
        panic_is_rejection=False,eval_w_canonicality_script_bound=False,dynamic_message_sources_script_bound=False,
        eval_w_proof_origin_bound=False,prior_state_transcript_bound=False,complete_keccak_sponge=False,
        coefficient_proof_origins_bound=False,spartan_sumcheck_equations_verified=False,external_raw_state_input_loaded=False,
        setup_calls=0,proving_jobs=0,native_proofs_verified=0,gpu_jobs=0,transactions_broadcast=0,
        metrics=dict(vectors=626736,expected_rejections=327928,max_script_bytes=100,
                     max_stack_items=30,max_witness_items=20,max_witness_payload_bytes=400),
        **{key:6*value for key,value in counts.items()})
    return native,dict(context=bench.CONTEXT.hex(),cases=descriptors,probes=probe_headers),dict(file_sha256='18'*32),census,probe_census


class ByteRhoChainBenchTests(unittest.TestCase):
    def test_exact_budget_before_source_publication(self):
        budget = bench._record_budget()
        self.assertEqual(budget['full_honest_records'], 584900)
        self.assertEqual(budget['full_honest_exact_bytes'], 109154100)
        self.assertEqual(budget['all_small_records'], 9816)
        self.assertEqual(budget['all_small_exact_bytes'], 1811784)
        self.assertEqual(budget['max_authenticated_layouts_per_case'], 357)
        self.assertEqual(budget['guard_upper_bytes'], 7347060)
        self.assertEqual(budget['target_upper_bytes'], 2007040)
        self.assertEqual(budget['main_upper_bytes'], 120322924)
        self.assertEqual(budget['standalone_probe_records'], 2808)
        self.assertEqual(budget['standalone_probe_exact_bytes'], 508128)
        self.assertEqual(budget['standalone_probe_upper_bytes'], 5353344)
        self.assertEqual(budget['combined_upper_bytes'], 125676268)
        self.assertLess(budget['combined_upper_bytes'], 128 << 20)

    def test_closed_labels_keep_semantic_role_and_profile(self):
        self.assertEqual(list(bench._requests()), [
            ('p/h', 'pallas_scalar', 59, 'honest'),
            ('p/r', 'pallas_scalar', 59, 'coherent-rho-raw'),
            ('p/p', 'pallas_scalar', 59, 'coherent-prefix-capacity'),
            ('v/h', 'vesta_scalar', 44, 'honest'),
            ('v/r', 'vesta_scalar', 44, 'coherent-rho-raw'),
            ('v/p', 'vesta_scalar', 44, 'coherent-prefix-capacity')])
        self.assertEqual(sum(bench.COMPONENT_LEAVES), 147043)
        self.assertEqual(sum(bench.COMPONENT_WORDS), 148401)
        self.assertEqual(len(bench.BRANCHES), 9)
        self.assertEqual(bench.FULL_COMPONENTS, {0,1,4,6,7})
        probes = list(bench._probe_requests())
        self.assertEqual(len(probes), 20)
        self.assertEqual(sum(row[4] for row in probes), 1404)
        self.assertEqual(probes[0], ('p/q0', 'pallas_scalar', 'coefficient-c0-modulus', 3, 111))
        self.assertEqual(probes[-1], ('v/q9', 'vesta_scalar', 'absorb-end-mask', 5, 9))

    def test_fault_selectors_follow_last_raw_byte_and_capacity(self):
        self.assertEqual(bench._terminal_producer(31), (29072, 2))
        self.assertEqual(bench._terminal_producer(136), (29177, 2))
        for profile, failed, consumers in (('coherent-rho-raw', (0,29072), [16,244]),
                                            ('coherent-prefix-capacity', (4,29177), [66,376])):
            checks = 0
            for component, count in enumerate(bench.COMPONENT_LEAVES):
                mode, ordinals = bench._selection(profile, component)
                if component not in bench.FULL_COMPONENTS:
                    self.assertEqual((mode, ordinals), ('all', None))
                    checks += count
                elif component == failed[0]:
                    self.assertEqual((mode, ordinals), ('selected', [failed[1]]))
                    checks += 1
                elif component in (6,7):
                    self.assertEqual((mode, ordinals), ('selected', consumers))
                    checks += 2
                else:
                    self.assertEqual((mode, ordinals), ('none', None))
            self.assertEqual(checks, 823)
        from bench_byte_keccak_block import _consumers
        self.assertEqual(_consumers(0,4), ((16,0),(244,0)))
        self.assertEqual(_consumers(0,136), ((66,1),(376,0)))

    def test_hosted_guard_blocks_fixture_io_and_graph_factories(self):
        with patch.dict(os.environ, {'GITHUB_ACTIONS':'false'}):
            for call in (lambda:bench._fixture('pallas_scalar'),
                         lambda:bench.run('unused','unused'),
                         lambda:bench._one(0,'p/h','pallas_scalar',59,'honest',None),
                         lambda:bench._probe(0,None,None,None),
                         lambda:bench._generate(None),lambda:bench._worker('unused')):
                with self.assertRaisesRegex(ValueError,'hosted GitHub Linux'):
                    call()

    def test_synthetic_main_and_private_probe_accounting(self):
        native,manifest,info,census,probes = _synthetic()
        rows,private = bench._validate(native,manifest,info,census,probes)
        self.assertEqual(len(rows),6)
        self.assertEqual(len(private),20)
        self.assertEqual(sum(row['selected_leaf_checks'] for row in rows),297378)
        self.assertEqual(sum(row['executed_leaves'] for row in private),1404)
        self.assertEqual(sum(row['signature_entries_created'] for row in private),2428)
        self.assertTrue(all(row['tree']['roots_independently_pinned'] is False for row in private))

    def test_scope_link_counter_and_partial_execution_aliases_reject(self):
        native,manifest,info,census,probes = _synthetic()
        mutations = (
            lambda x:x.__setitem__('proof_verified',True),
            lambda x:x.__setitem__('coefficient_proof_origins_bound',True),
            lambda x:x.__setitem__('private_probe_keys_separate',False),
            lambda x:x.__setitem__('external_raw_state_input_loaded',True),
            lambda x:x.__setitem__('private_probe_signature_entries_created',True),
            lambda x:x['cases'][1].__setitem__('full_statement_executed',True),
            lambda x:x['cases'][1]['components'][6].__setitem__('selected_ordinals',[16,243]),
            lambda x:x['cases'][0]['connections'][0].__setitem__('opening_links',383),
            lambda x:x['cases'][0]['connections'][0].__setitem__('kind',[]),
            lambda x:x['cases'][0].__setitem__('canonical_internal_opening_links',True),
            lambda x:x['metrics'].__setitem__('vectors',626684),
            lambda x:x.__setitem__('compact_execution_records_bytes',125676269),
        )
        for mutate in mutations:
            changed=copy.deepcopy(native); mutate(changed)
            with self.assertRaises(ValueError):
                bench._validate(changed,manifest,info,census,probes)

    def test_detached_private_tree_and_identity_fields_reject(self):
        native,manifest,info,census,probes = _synthetic()
        mutations = (
            lambda x:x['probes'][0].__setitem__('source_case','v/h'),
            lambda x:x['probes'][0].__setitem__('registry_id',False),
            lambda x:x['probes'][6].__setitem__('false_predicates',[False]),
            lambda x:x['probes'][0]['tree'].__setitem__('compiled_stream_sha256','00'*32),
            lambda x:x['probes'][0]['tree'].__setitem__('roots_independently_pinned',True),
            lambda x:x['probes'][0]['tree']['negative_counts'].__setitem__('branch',True),
            lambda x:x['cases'][1]['forest'].__setitem__('control_block_bytes',577),
            lambda x:x['cases'][0]['forest'].__setitem__('compiled_script_bytes',14704301),
            lambda x:x['cases'][0]['components'][5].__setitem__('source_maps_sha256','00'*32),
        )
        for mutate in mutations:
            changed=copy.deepcopy(native); mutate(changed)
            with self.assertRaises(ValueError):
                bench._validate(changed,manifest,info,census,probes)


if __name__ == '__main__':
    unittest.main()
