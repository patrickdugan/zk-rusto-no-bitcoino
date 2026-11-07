"""SYNTHETIC transport/accounting unit tests; no Script or crypto evidence.

The small literal observations below never construct a Program, graph, key,
signature, tree or worker. They exercise contradictions in report metadata.
"""
import copy
from hashlib import sha256
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import bench_grouped_byte_c_bit_point as b

COMMIT='a'*40


def h(value):return sha256(value.encode('ascii')).hexdigest()


def metrics(calls,rejects):
    return dict(vectors=calls,expected_rejections=rejects,max_script_bytes=100 if calls else 0,
        max_witness_items=10 if calls else 0,max_witness_payload_bytes=20 if calls else 0,max_stack_items=15 if calls else 0)


def tree(ledger,count,ordinal,tag,component=None):
    local=count if component is None else b.COMPONENT_LEAVES[component]
    value=dict(leaf_count=count,compiled_script_bytes=ledger['compiled_script_bytes'],
        compiled_stream_sha256=ledger['compiled_stream_sha256'],control_block_bytes=33+32*(b._depth(local,ordinal)+(0 if component is None else b._depth(11,component))),
        merkle_root=h(tag+'/root'),output_key=h(tag+'/output'),control_block_sha256=h(tag+'/control'),
        selected_script_sha256=h(tag+'/script'),roots_independently_pinned=False)
    if component is None:value.update(membership_verified=True,negative_counts={key:1 for key in b.LOCAL_NEGATIVES})
    else:value.update(components=11,selected_component=component,selected_leaf=ordinal,
        hierarchical_membership_verified=True,component_manifest_sha256=h(tag+'/manifest'),
        negative_counts={key:1 for key in b.FOREST_NEGATIVES})
    return value


def fixture(role):
    """Independent handcrafted schema fixture; numbers are not real costs."""
    prefix,base,counter=b.ROLES[role]
    manifest=dict(schema=b.SCHEMA,role=role,context=b.CONTEXT.hex(),operation_id=b.OPERATION,
        legacy_point_reference_filename='legacy-point-reference.json',legacy_point_reference_file_sha256=h(role+'/reference'),
        legacy_point_reference_file_bytes=123,cases=[],probes=[])
    for name,_,_,_,profile in b._requests(role):
        headers=[]
        for i,(words,leaves) in enumerate(zip(b.COMPONENT_WORDS,b.COMPONENT_LEAVES,strict=True)):
            tag=role+'/'+str(i)
            descriptor=dict(index=i,branch=b.BRANCHES[i],field_role=base if i==10 else role,
                words=words,leaves=leaves,program_sha256=h(tag+'/program'),catalogue_id=h(tag+'/catalogue'),
                source_sha256=h(tag+'/source'),source_maps_sha256=h(tag+'/maps'),global_ids_sha256=h(tag+'/globals'))
            mode='all' if profile=='honest' or i not in b.FULL_COMPONENTS|{10} else 'selected' if i==10 else 'none'
            headers.append(dict(descriptor=descriptor,execution_mode=mode,selected_ordinals=[53] if mode=='selected' else None,
                expected_false=[0] if profile=='coherent-bit' and i==9 else [244] if profile=='coherent-scalar-alias' and i==8 else [],expected_abort_ordinals=[]))
        manifest['cases'].append(dict(name=name,profile=profile,role=role,base_role=base,rho_counter=counter,c_counter=counter+1,
            bit_index=0,execution_mode='full' if profile=='honest' else 'targeted',source_sha256=h(role+'/outer'),
            source_maps_sha256=h(role+'/outer-maps'),chain_source_sha256=h(role+'/chain'),chain_source_maps_sha256=h(role+'/chain-maps'),components=headers))
    for request in b._probe_requests(role):
        name=request['name'];category=request['category'];kind=request['kind']
        full=category in ('chain','scalar-alias');selected=None if full else [53,54] if kind=='grouped-ab-subtotal' else [3419]
        chosen=(0 if category=='chain' else 253 if category=='scalar-alias' else selected[0])
        correct=category=='point-edge';false=[] if correct else [chosen]
        if kind=='grouped-ab-subtotal':false=[53,54]
        inputs={} if category=='chain' else {'raw_c_le':'0'*128} if category=='scalar-alias' else dict(bit=2 if kind=='signed-bit-two' else 0,
            **{key:dict(infinity=2 if key=='point_R' and kind=='wrong-R-flag' else 0,x_le='0'*64,y_le='0'*64) for key in ('point_A','point_P','point_E','point_R')})
        manifest['probes'].append(dict(name=name,kind=kind,category=category,role=role,field_role=request['field_role'],
            source_case=prefix+'/h',source_component=3 if category=='chain' else 9 if category=='scalar-alias' else 10,
            operation_id=b.OPERATION+'/probe/'+name,source_sha256=h(name+'/source'),source_maps_sha256=h(name+'/maps'),
            program_sha256=h(name+'/program'),catalogue_id=h(name+'/catalogue'),words=187 if request['leaves']==111 else 23 if category=='chain' else 634 if category=='scalar-alias' else 7498,
            leaves=request['leaves'],execution_mode='all' if full else 'selected',selected_ordinals=selected,
            selected_leaf=chosen,expected_selected_correct=correct,expected_false=false,expected_abort_ordinals=[],inputs=inputs))
    info=dict(file_sha256=sha256(b._canonical(manifest)).hexdigest(),file_bytes=len(b._canonical(manifest)))
    native=dict(schema=b.NATIVE_SCHEMA,role=role,passed=True,input_manifest_sha256=info['file_sha256'],
        script_stream_framing=b.STREAM_FRAMING,cases=[],probes=[],wall_seconds=1.0,
        compact_execution_records_bytes=1000,compact_execution_records_sha256=h(role+'/records'),
        legacy_point_reference=dict(file_sha256=manifest['legacy_point_reference_file_sha256'],program_sha256=h(role+'/old-program'),catalogue_id=h(role+'/old-catalogue'),words=7498,leaves=6161,executed=False,committed=False))
    native.update({key:True for key in b.TRUE_FLAGS});native.update({key:False for key in b.FALSE_FLAGS})
    native.update({key:0 for key in ('setup_calls','proving_jobs','native_proofs_verified','gpu_jobs','transactions_broadcast')})
    normals=metrics(0,0);alls=metrics(0,0)
    for group in manifest['cases']:
        honest=group['profile']=='honest';row={k:v for k,v in group.items() if k!='components'};parts=[]
        row.update(full_statement_executed=honest,signature_entries_created=155107,local_declared_words=156163,cached_signature_reuses=1056,
            all_native_predicates_classified=150509,scalar_limb_opening_links=9,scalar_canonical_opening_links=9,selected_bit_opening_links=5,
            canonical_internal_opening_links=46,internal_cached_boundary_entries=23000,internal_producer_consumer_opening_links=46000,
            native_rejections=264,map_rejections=22,source_rejections=30,cache_rejections=108,
            connections=[dict(kind=k,logical_links=v,opening_links=b.OPENING_COUNTS[k]) for k,v in b.CONNECTION_COUNTS.items()])
        chosen=0
        for i,header in enumerate(group['components']):
            part=dict(header['descriptor']);n=part['leaves'] if header['execution_mode']=='all' else len(header['selected_ordinals'] or [])
            tag=group['name']+'/'+str(i);part.update(context=manifest['context'],execution_mode=header['execution_mode'],selected_ordinals=header['selected_ordinals'],
                executed_leaves=n,false_predicates=header['expected_false'],abort_predicates=[],guard_layouts=1,guard_vectors=14,
                registry_id=h(tag+'/registry'),compiled_script_bytes=100*part['leaves'],largest_disproof_leaf_bytes=100,compiled_stream_sha256=h(tag+'/stream'),
                normal_metrics=metrics(2*n,n),metrics=metrics(2*n+14,n+14),merkle_root=h(tag+'/root'),output_key=h(tag+'/output'))
            if i==10:part.update(group_ordinal=53,group_witness_sha256=h(tag+'/group-witness'),assertion_material_sha256=h(tag+'/material'))
            parts.append(part);chosen+=n;b._fold(normals,part['normal_metrics']);b._fold(alls,part['metrics'])
        component=10 if honest else 9 if group['profile']=='coherent-bit' else 8
        ordinal=3456 if honest else 0 if component==9 else 244
        forest=tree(dict(compiled_script_bytes=sum(p['compiled_script_bytes'] for p in parts),compiled_stream_sha256=h(group['name']+'/forest-stream')),150509,ordinal,group['name']+'/forest',component)
        row.update(components=parts,forest=forest,selected_leaf_checks=chosen,guard_layouts=11,guard_vectors=154,additional_selected_engine_executions=2,
            selected_component=component,selected_leaf=ordinal,selected_correctness_execution_success=honest,selected_disproof_execution_success=not honest,
            primary_selection_metrics=metrics(2,1),alternate_point=None)
        b._fold(alls,row['primary_selection_metrics'])
        if honest:
            part=parts[10];local=tree(part,3457,53,group['name']+'/alternate')
            local.update(merkle_root=part['merkle_root'],output_key=part['output_key'])
            altforest=tree(dict(compiled_script_bytes=forest['compiled_script_bytes'],compiled_stream_sha256=forest['compiled_stream_sha256']),150509,53,group['name']+'/alternate-forest',10)
            for key in ('merkle_root','output_key','component_manifest_sha256'):altforest[key]=forest[key]
            altforest['selected_script_sha256']=local['selected_script_sha256']
            row['alternate_point']=dict(registry_id=part['registry_id'],catalogue_id=part['catalogue_id'],assertion_material_sha256=part['assertion_material_sha256'],
                selected_witness_sha256=part['group_witness_sha256'],local_tree=local,forest=altforest,selected_component=10,selected_leaf=53,
                selected_correctness_execution_success=True,selected_disproof_execution_success=False,guard_vectors=14,additional_selected_engine_executions=2,metrics=metrics(16,15))
            b._fold(alls,row['alternate_point']['metrics'])
        native['cases'].append(row)
    for source in manifest['probes']:
        row=dict(source);n=source['leaves'] if source['execution_mode']=='all' else len(source['selected_ordinals']);correct=source['expected_selected_correct']
        row.update(context=manifest['context'],executed_leaves=n,false_predicates=source['expected_false'],abort_predicates=[],signature_entries_created=source['words'],
            guard_layouts=1,guard_vectors=14,native_rejections=24,additional_selected_engine_executions=2,
            selected_correctness_execution_success=correct,selected_disproof_execution_success=not correct,registry_id=h(source['name']+'/registry'),
            compiled_script_bytes=100*source['leaves'],largest_disproof_leaf_bytes=100,compiled_stream_sha256=h(source['name']+'/stream'),
            normal_metrics=metrics(2*n,n),metrics=metrics(2*n+16,n+15))
        row['tree']=tree(row,source['leaves'],source['selected_leaf'],source['name']+'/private')
        native['probes'].append(row);b._fold(normals,row['normal_metrics']);b._fold(alls,row['metrics'])
    native.update(signature_entries_created=465321,local_declared_words=468489,cached_signature_reuses=3168,canonical_internal_opening_links=138,
        scalar_canonical_opening_links=27,scalar_limb_opening_links=27,selected_bit_opening_links=15,internal_cached_boundary_entries=69000,
        internal_producer_consumer_opening_links=138000,full_statement_cases=1,targeted_statement_cases=2,private_probe_registries=27,private_probe_trees=27,
        private_probe_signature_entries_created=sum(p['words'] for p in manifest['probes']),normal_metrics=normals,metrics=alls)
    files=[dict(path='synthetic-schema-unit.py',bytes=1,sha256=h('synthetic-source'))]
    snapshot=dict(schema='bitvm2-nova-worker-source-snapshot/v1',files=files,source_snapshot_sha256=sha256(b._canonical(files)).hexdigest(),
        worker_executable=dict(bytes=1,sha256=h(role+'/synthetic-binary')),trusted_configured_library_boundary=True,binary_source_equivalence_attested=False)
    honest=native['cases'][0]
    report=dict(schema=b.REPORT_SCHEMA,role=role,tested_commit=COMMIT,context=b.CONTEXT.hex(),operation_id=b.OPERATION,policy_sha256=b._policy_sha256(),
        source_identity_sha256=b._source_identity(manifest),manifest=info,native=native,source_snapshot=snapshot,compact_record_budget=b._record_budget(role),
        cases=3,full_execution_cases=1,targeted_execution_cases=2,private_probe_registries=27,private_probe_keys_separate=True,bit_index=0,components_per_case=11,
        leaves_per_complete_forest=150509,unique_global_words_per_case=155107,direct_native_worker_executed=True,external_result_receipt_loaded=False,
        sources_unchanged_during_run=True,inputs_unchanged_during_run=True,wall_seconds=1.0,parent_peak_rss_bytes=1,
        honest_forest_ledger=dict(name=honest['name'],role=role,source_sha256=honest['source_sha256'],component_script_bytes=[p['compiled_script_bytes'] for p in honest['components']],
            complete_forest_script_bytes=honest['forest']['compiled_script_bytes'],merkle_root=honest['forest']['merkle_root'],output_key=honest['forest']['output_key']))
    return report,manifest,info


class GroupedPointBenchTests(unittest.TestCase):
    def setUp(self):
        self.reports=[];self.manifests={};self.infos={}
        for role in b.ROLES:
            report,manifest,info=fixture(role);self.reports.append(report);self.manifests[role]=manifest;self.infos[role]=info

    def audit(self):return b._aggregate(self.reports,self.manifests,self.infos,COMMIT)

    def test_synthetic_positive_and_shared_record_budget(self):
        result=self.audit();self.assertTrue(result['offline_accounting_only'])
        self.assertNotIn('combined_stream_sha256',result)
        self.assertEqual(len(result['role_observations']),2)
        self.assertNotEqual(self.reports[0]['source_identity_sha256'],self.reports[1]['source_identity_sha256'])
        self.assertEqual(b._record_budget('pallas_scalar')['shared_global_upper_bytes'],130470560)
        self.assertLess(130470560,128<<20)

    def test_missing_duplicate_foreign_roles_and_policy(self):
        original=copy.deepcopy(self.reports)
        mutations=[lambda: self.reports.pop(),lambda:self.reports.__setitem__(1,copy.deepcopy(self.reports[0]))]
        for key,value in (('role','other'),('tested_commit','b'*40),('policy_sha256','0'*64),('context','0'*64),('operation_id','foreign'),('schema','foreign')):
            mutations.append(lambda k=key,v=value:self.reports[0].__setitem__(k,v))
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                self.reports=copy.deepcopy(original);mutate()
                with self.assertRaises(ValueError):self.audit()

    def test_role_specific_sources_and_code_snapshot(self):
        original=copy.deepcopy(self.reports)
        for mutate in (
            lambda:self.reports[0].__setitem__('source_identity_sha256',self.reports[1]['source_identity_sha256']),
            lambda:self.reports[1]['source_snapshot']['files'][0].__setitem__('sha256','f'*64),
            lambda:self.reports[0]['native'].__setitem__('passed',False),
            lambda:self.reports[0]['native'].__setitem__('script_stream_framing','u64le-length-script/v1'),
            lambda:self.reports[0].__setitem__('combined_stream_sha256','1'*64)):
            self.reports=copy.deepcopy(original);mutate()
            with self.assertRaises(ValueError):self.audit()

    def test_strict_numeric_aliases_scope_and_execution(self):
        original=copy.deepcopy(self.reports);role='pallas_scalar';original_manifest=copy.deepcopy(self.manifests[role])
        for mutate in (
            lambda:self.manifests[role]['cases'][0].__setitem__('bit_index',False),
            lambda:self.reports[0]['native']['metrics'].__setitem__('max_stack_items',True),
            lambda:self.reports[0]['native'].__setitem__('full_statement_cases',True),
            lambda:self.reports[0]['native']['cases'][0].__setitem__('full_statement_executed',False),
            lambda:self.manifests[role]['cases'][0]['components'][0].__setitem__('execution_mode','none'),
            lambda:self.reports[0]['native'].__setitem__('nested',{'proof_verified':True}),
            lambda:self.reports[0]['native'].__setitem__('nested',{'taproot_forest_membership_verified':True})):
            self.reports=copy.deepcopy(original);self.manifests[role]=copy.deepcopy(original_manifest);mutate()
            with self.assertRaises(ValueError):self.audit()

    def test_alternate_registry_material_stream_and_membership(self):
        original=copy.deepcopy(self.reports)
        paths=[('registry_id',),('assertion_material_sha256',),('selected_witness_sha256',),('local_tree','compiled_stream_sha256'),
            ('local_tree','merkle_root'),('forest','output_key'),('forest','component_manifest_sha256')]
        for path in paths:
            self.reports=copy.deepcopy(original);value=self.reports[0]['native']['cases'][0]['alternate_point']
            for key in path[:-1]:value=value[key]
            value[path[-1]]='f'*64
            with self.subTest(path=path),self.assertRaises(ValueError):self.audit()
        self.reports=copy.deepcopy(original)
        self.reports[0]['native']['cases'][0]['alternate_point']['selected_disproof_execution_success']=True
        with self.assertRaises(ValueError):self.audit()

    def test_private_disproof_cannot_claim_honest_commitment(self):
        original=copy.deepcopy(self.reports)
        for key in ('registry','root'):
            self.reports=copy.deepcopy(original);native=self.reports[0]['native'];probe=native['probes'][-1]
            if key=='registry':probe['registry_id']=native['cases'][0]['components'][10]['registry_id']
            else:probe['tree']['merkle_root']=native['cases'][0]['components'][10]['merkle_root']
            with self.assertRaises(ValueError):self.audit()

    def test_guard_precedes_generation_and_workflow_flag(self):
        with patch.dict(os.environ,{'GITHUB_ACTIONS':'false'}),patch.object(b,'_generate') as generate:
            with self.assertRaises(ValueError):b.run('unused','unused','pallas_scalar')
            generate.assert_not_called()
        path=Path(__file__).resolve().parents[3]/'.github/workflows/bitvm2-nova-grouped-byte-c-bit-point.yml'
        workflow=path.read_text(encoding='utf-8')
        self.assertIn("BITVM2_NOVA_GROUPED_POINT_TESTS: '1'",workflow)
        self.assertNotIn('BITVM2_NOVA_GROUPED_BIT_POINT_TESTS',workflow)
        self.assertIn('needs: grouped-role',workflow)


if __name__=='__main__':unittest.main()
