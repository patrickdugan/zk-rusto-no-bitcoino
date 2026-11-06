"""Tiny source-free policy and byte-budget checks; no actual graphs or worker."""
import unittest
import copy
import os
import tempfile
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace

import bench_byte_c_bit_point as bench


def _synthetic():
    """Invented private transport fixture, not graph/Script/proof evidence."""
    cases=[];rows=[];census=[];largest=100;normal=guards=0
    def tree(count,ordinal,compiled,component=None):
        local=count if component is None else bench.COMPONENT_LEAVES[component]
        control=33+32*(bench._depth(local,ordinal)+(0 if component is None else bench._depth(11,component)))
        value=dict(leaf_count=count,compiled_script_bytes=compiled,compiled_stream_sha256='77'*32,
            control_block_bytes=control,merkle_root='11'*32,output_key='22'*32,control_block_sha256='33'*32,
            selected_script_sha256='44'*32,roots_independently_pinned=False)
        if component is None: value.update(membership_verified=True,negative_counts={k:1 for k in bench.LOCAL_NEGATIVES})
        else: value.update(components=11,selected_component=component,selected_leaf=ordinal,
            component_manifest_sha256='55'*32,hierarchical_membership_verified=True,negative_counts={k:1 for k in bench.FOREST_NEGATIVES})
        return value
    for name,role,base,counter,profile in bench._requests():
        honest=profile=='honest';headers=[];parts=[];counts=[]
        for i,(words,leaves) in enumerate(zip(bench.COMPONENT_WORDS,bench.COMPONENT_LEAVES,strict=True)):
            selected=None if honest or i not in bench.FULL_COMPONENTS and i!=10 else list(range(6116,6124))+[6159,6160] if i==10 else None
            mode='all' if honest or i not in bench.FULL_COMPONENTS and i!=10 else 'selected' if i==10 else 'none'
            executed=leaves if mode=='all' else len(selected) if mode=='selected' else 0
            false=[0] if profile=='coherent-bit' and i==9 else [244] if profile=='coherent-scalar-alias' and i==8 else []
            descriptor=dict(index=i,branch=bench.BRANCHES[i],kind='synthetic',operation_id=f'test/{i}',
                program_sha256='11'*32,catalogue_id='22'*32,source_sha256='33'*32,source_maps_sha256='44'*32,
                global_ids_sha256='55'*32,words=words,leaves=leaves,counter=counter if i<3 else counter+1,
                field_role=base if i==10 else role,program_identity_kind='test-only')
            header=dict(descriptor=descriptor,execution_mode=mode,selected_ordinals=selected,expected_false=false,expected_abort_ordinals=[])
            layout=(23,23,61,24,23,4,23,23,52,2,5)[i]
            part=dict(descriptor,context=bench.CONTEXT.hex(),registry_id='66'*32,compiled_script_bytes=100*leaves,
                largest_disproof_leaf_bytes=100,compiled_stream_sha256='77'*32,execution_mode=mode,selected_ordinals=selected,
                executed_leaves=executed,false_predicates=list(false),abort_predicates=[],guard_layouts=layout,guard_vectors=14*layout)
            headers.append(header);parts.append(part);counts.append(dict(selected_leaf_checks=executed,guard_layouts=layout))
        source=dict(name=name,role=role,base_role=base,profile=profile,rho_counter=counter,c_counter=counter+1,bit_index=0,
            execution_mode='full' if honest else 'targeted',source_sha256='88'*32,source_maps_sha256='99'*32,
            chain_source_sha256='aa'*32,chain_source_maps_sha256='bb'*32,asserted_scalar_le='00'*32,
            asserted_scalar_quotient_le='00'*33,selected_bit=0,canonical_bit=0,point_A={},point_P={},expected_R={},components=headers)
        selected_component=10 if honest else 9 if profile=='coherent-bit' else 8
        ordinal=6160 if honest else 0 if profile=='coherent-bit' else 244
        row={key:value for key,value in source.items() if key!='components'}
        selected_count=sum(c['selected_leaf_checks'] for c in counts);layout_count=sum(c['guard_layouts'] for c in counts)
        row.update(full_statement_executed=honest,signature_entries_created=155107,local_declared_words=156163,
            cached_signature_reuses=1056,all_native_predicates_classified=153213,scalar_limb_opening_links=9,
            scalar_canonical_opening_links=9,selected_bit_opening_links=5,canonical_internal_opening_links=46,
            internal_cached_boundary_entries=23000,internal_producer_consumer_opening_links=46000,
            native_rejections=264,map_rejections=22,source_rejections=30,cache_rejections=108,
            connections=[dict(kind=kind,logical_links=value,opening_links=bench.OPENING_COUNTS[kind])
                         for kind,value in bench.CONNECTION_COUNTS.items()],
            components=parts,selected_leaf_checks=selected_count,guard_layouts=layout_count,
            guard_vectors=14*layout_count,additional_selected_engine_executions=2,selected_component=selected_component,
            selected_leaf=ordinal,selected_correctness_execution_success=honest,selected_disproof_execution_success=not honest,
            forest=tree(153213,ordinal,15321300,selected_component))
        cases.append(source);rows.append(row);census.append(counts);normal+=selected_count;guards+=14*layout_count
    sources=[];probes=[];probe_census=[]
    for request in bench._probe_requests():
        category=request['category'];leaves=request['leaves'];edge=category=='point-edge'
        selected=10 if edge else 1 if category=='point-negative' else leaves
        ordinal=6123 if edge else 253 if category=='scalar-alias' else 6118 if category=='point-negative' else 0
        false=[] if edge else [ordinal];layout=5 if edge else 1 if category=='point-negative' else 8 if category=='scalar-alias' else request['guard_bound']
        words=7498 if category.startswith('point-') else 634 if category=='scalar-alias' else 187 if leaves==111 else 23
        source=dict(request,source_case=request['name'][0]+'/h',source_component=10 if category.startswith('point-') else None,
            operation_id='test/probe',source_sha256='33'*32,source_maps_sha256='44'*32,program_sha256='11'*32,
            catalogue_id='22'*32,words=words,execution_mode='all' if selected==leaves else 'selected',
            selected_ordinals=None if selected==leaves else [ordinal],expected_false=false,expected_abort_ordinals=[],
            selected_leaf=ordinal,expected_selected_correct=edge,inputs={})
        row=dict(source,context=bench.CONTEXT.hex(),executed_leaves=selected,false_predicates=list(false),abort_predicates=[],
            signature_entries_created=words,guard_layouts=layout,guard_vectors=14*layout,native_rejections=24,
            additional_selected_engine_executions=2,
            selected_correctness_execution_success=edge,selected_disproof_execution_success=not edge,
            registry_id='66'*32,compiled_stream_sha256='77'*32,compiled_script_bytes=leaves*100,
            largest_disproof_leaf_bytes=100,tree=tree(leaves,ordinal,leaves*100))
        sources.append(source);probes.append(row);probe_census.append(dict(selected_leaf_checks=selected,guard_layouts=layout))
        normal+=selected;guards+=14*layout
    native=dict(schema='bitvm2-nova-byte-c-bit-point-execution/v1',passed=True,input_manifest_sha256='12'*32,
        compact_execution_records_bytes=125000000,compact_execution_records_sha256='13'*32,cases=rows,probes=probes,
        signature_entries_created=6*155107,local_declared_words=6*156163,cached_signature_reuses=6*1056,
        canonical_internal_opening_links=6*46,scalar_canonical_opening_links=6*9,
        scalar_limb_opening_links=6*9,selected_bit_opening_links=6*5,
        internal_cached_boundary_entries=6*23000,internal_producer_consumer_opening_links=6*46000,
        full_statement_cases=2,targeted_statement_cases=4,private_probe_registries=52,private_probe_trees=52,
        private_probe_signature_entries_created=sum(p['words'] for p in sources),wall_seconds=10.0,
        metrics=dict(vectors=2*normal+guards+116,expected_rejections=normal+guards+58,max_script_bytes=largest,
                     max_stack_items=500,max_witness_items=480,max_witness_payload_bytes=9600))
    native.update({flag:True for flag in bench.TRUE_FLAGS});native.update({flag:False for flag in bench.FALSE_FLAGS})
    native.update({key:0 for key in ('setup_calls','proving_jobs','native_proofs_verified','gpu_jobs','transactions_broadcast')})
    return native,dict(context=bench.CONTEXT.hex(),cases=cases,probes=sources),dict(file_sha256='12'*32),census,probe_census


class ByteCBitPointBenchTests(unittest.TestCase):
    def test_closed_budget_includes_all_fifty_two_probes(self):
        budget=bench._record_budget()
        self.assertEqual(budget['combined_upper_bytes'],132472024)
        self.assertLess(budget['combined_upper_bytes'],128<<20)
        self.assertEqual(budget['private_probes'],52)
        self.assertEqual((budget['old_identifier_bytes'],budget['new_identifier_bytes']),(64,32))
        self.assertEqual((budget['point_shape_bound'],budget['bridge_shape_bound']),(107,2))

    def test_fixed_mixed_roles_and_probe_coverage(self):
        requests=list(bench._requests())
        self.assertEqual([row[0] for row in requests],['p/h','p/b','p/a','v/h','v/b','v/a'])
        self.assertEqual(requests[0][1:4],('pallas_scalar','pallas_base',59))
        self.assertEqual(requests[3][1:4],('vesta_scalar','vesta_base',44))
        probes=list(bench._probe_requests())
        self.assertEqual(len(probes),52)
        self.assertEqual({kind:sum(p['category']==kind for p in probes) for kind in
            ('chain','point-edge','scalar-alias','point-negative')},
            {'chain':20,'point-edge':12,'scalar-alias':2,'point-negative':18})
        for role in ('pallas_scalar','vesta_scalar'):
            self.assertEqual([p['bit'] for p in probes if p['category']=='point-edge' and p['role']==role],[0,1,0,1,0,1])
        self.assertEqual(sum(bench.COMPONENT_WORDS),156163)
        self.assertEqual(sum(bench.COMPONENT_LEAVES),153213)

    def test_snapshot_pins_isolated_worker_and_borrowed_sources(self):
        owner=Path(__file__).resolve().parents[1]/'results'
        owner.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=owner) as temporary:
            root=Path(temporary)
            for relative in ('bench_byte_c_bit_point.py','rust-oracle/src/lib.rs',
                    'rust-oracle/src/bin/byte_c_bit_point.rs','point-oracle/src/main.rs',
                    'point-oracle/src/body_pins.rs','point-oracle/src/keys.rs',
                    'rust-oracle/Cargo.toml','rust-oracle/Cargo.lock',
                    'point-oracle/Cargo.toml','point-oracle/Cargo.lock','transcript-requirements.txt','worker'):
                path=root/relative;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(relative.encode('utf-8'))
            with patch.object(bench,'_guard'),patch.object(bench,'__file__',str(root/'bench_byte_c_bit_point.py')):
                snapshot=bench._source_snapshot(root/'worker')
                names={item['path'] for item in snapshot['files']}
                self.assertIn('point-oracle/src/main.rs',names)
                self.assertIn('point-oracle/src/body_pins.rs',names)
                self.assertIn('point-oracle/src/keys.rs',names)
                self.assertIn('point-oracle/Cargo.lock',names)
                self.assertIn('transcript-requirements.txt',names)
                self.assertIn('rust-oracle/src/lib.rs',names)
                (root/'point-oracle/src/keys.rs').write_bytes(b'changed helper')
                self.assertNotEqual(bench._source_snapshot(root/'worker'),snapshot)
                (root/'point-oracle/src/main.rs').unlink()
                with self.assertRaisesRegex(ValueError,'complete configured-worker'):
                    bench._source_snapshot(root/'worker')

    def test_new_bits_and_point_raw_truth_without_graphs(self):
        from script import P,BASE,limbs
        def fixture(kind,argument,bounds,values):
            names=[f'w{i}' for i in range(len(bounds))]
            leaf=SimpleNamespace(kind=kind,argument=argument,wires=tuple(range(len(bounds))))
            spec=SimpleNamespace(words=tuple(zip(names,bounds)),leaves=(leaf,))
            return spec,dict(zip(names,values)),SimpleNamespace(p=P)
        for width in (29,23):
            value=(1<<(width-1))+3
            digits=[(value>>(width-1-i))&1 for i in range(width)]
            spec,values,program=fixture('bits',(width,),[BASE]+[2]*width,[value]+digits)
            self.assertIs(bench._leaf_truth(spec,values,0,program),True)
            values['w1']^=1
            self.assertIs(bench._leaf_truth(spec,values,0,program),False)
        spec,values,program=fixture('bool_and',(),[2,2,2],[2,0,0])
        self.assertIs(bench._leaf_truth(spec,values,0,program),False) # signed decoder flag, no bare VERIFY
        spec,values,program=fixture('field_valid',(),[BASE]*9,list(limbs(P)))
        self.assertIs(bench._leaf_truth(spec,values,0,program),False) # raw p is not reduced to zero
        spec,values,program=fixture('add',(),[BASE]*27,list(limbs(P))+[0]*18)
        self.assertIsNone(bench._leaf_truth(spec,values,0,program))
        self.assertEqual(bench._classify(spec,values,program),([],[0]))
        spec,values,program=fixture('add',(),[BASE]*27,[0]*18+list(limbs(P)))
        self.assertIs(bench._leaf_truth(spec,values,0,program),False) # canonical inputs, noncanonical claimed output

    def test_synthetic_transport_and_strict_scope_rejections(self):
        native,manifest,info,census,probes=_synthetic()
        rows,private=bench._validate(native,manifest,info,census,probes)
        self.assertEqual((len(rows),len(private)),(6,52))
        mutations=(lambda x:x.__setitem__('proof_verified',True),
            lambda x:x.__setitem__('all_negative_probe_leaves_executed',True),
            lambda x:x.__setitem__('private_probe_registries',True),
            lambda x:x['cases'][1].__setitem__('full_statement_executed',True),
            lambda x:x['cases'][0]['components'][10].__setitem__('field_role','pallas_scalar'),
            lambda x:x['cases'][0].__setitem__('selected_bit_opening_links',True),
            lambda x:x['cases'][0].__setitem__('scalar_canonical_opening_links',True),
            lambda x:x['cases'][0].__setitem__('cache_rejections',107),
            lambda x:x['cases'][0]['connections'][0].__setitem__('opening_links',True),
            lambda x:x.__setitem__('internal_producer_consumer_opening_links',True),
            lambda x:x['probes'][0].__setitem__('native_rejections',True),
            lambda x:x['cases'][1]['forest'].__setitem__('control_block_bytes',225),
            lambda x:x['probes'][16]['tree'].__setitem__('compiled_stream_sha256','00'*32),
            lambda x:x['probes'][-1].__setitem__('field_role','vesta_scalar'),
            lambda x:x['probes'][-1].__setitem__('selected_correctness_execution_success',True),
            lambda x:x['metrics'].__setitem__('vectors',1),
            lambda x:x.__setitem__('compact_execution_records_bytes',132472025))
        for mutate in mutations:
            changed=copy.deepcopy(native);mutate(changed)
            with self.assertRaises(ValueError): bench._validate(changed,manifest,info,census,probes)

    def test_guards_precede_all_graphs_or_io(self):
        with patch.dict(os.environ,{'GITHUB_ACTIONS':'false'}):
            for call in (lambda:bench.run('unused','unused'),lambda:bench._one(0,None,None),
                         lambda:bench._probe(0,None,None,None),lambda:bench._point_probe(None,None),
                         lambda:bench._generate(None),lambda:bench._source_snapshot(None)):
                with self.assertRaisesRegex(ValueError,'hosted GitHub Linux'):call()


if __name__=='__main__':
    unittest.main()
