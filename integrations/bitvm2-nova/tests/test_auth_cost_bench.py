"""SYNTHETIC transport unit tests, never Script/signature/proof evidence.

The invented report below exercises the direct-worker output checker only.
It constructs no source graph, key, signature, Script or native process.
"""
import copy
import os
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import bench_auth_cost as bench


def _synthetic_report():
    cases=[];rows=[];census=[];calls=rejects=keys=links=0
    for index,(name,fixture,profile,role) in enumerate(bench._requests()):
        mixed=fixture=='mixed';words,leaves=(3,2) if mixed else (1417,1217)
        # Counts and plausible packet sizes, not an executed round topology.
        unique=[2,2] if mixed else [3]*1016+[2]*201
        hinted=[1,1] if mixed else unique
        counts=dict(guard_layouts=2 if mixed else 11,hinted_guard_slots=2 if mixed else 31,
            actual_opening_occurrences=sum(unique),shared_opening_links=sum(unique)-words,
            alias_formal_reuses=1 if mixed else 0,unique_slots=unique,hinted_slots=hinted)
        false=({'bad-aux':[0],'bad-square':[1],'a256':[0,1],'a-max':[0,1],'auth-order':[0,1]}.get(profile,[])
               if mixed else ([] if profile=='honest' else [0,1]))
        source=dict(name=name,fixture=fixture,profile=profile,role=role,program_sha256='11'*32,
            catalogue_id='22'*32,source_sha256='33'*32,source_maps_sha256='44'*32,
            words=words,leaves=leaves,expected_false=false,expected_abort_ordinals=[])
        row={key:value for key,value in source.items() if not key.startswith('expected_')}
        row.update(false_predicates=false,abort_predicates=[],signature_entries_created=words,
            full_signature_signing_calls=words,cross_adapter_hash_links=10*words,adapters=[])
        for adapter in range(2):
            slots=counts['hinted_guard_slots'] if adapter else 0
            # Fixed closed special-call table, independent of runtime output.
            special=({'a9':8,'a256':4,'a-max':4,'auth-order':20}.get(profile,0) if adapter else 0)
            attacks=16*counts['guard_layouts']+204*slots+special
            ledger=dict(adapter=adapter,label=('compact','bound256-hinted')[adapter],
                registry_id=f'{2*index+adapter+1:064x}',compiled_stream_sha256='55'*32,
                normal_vectors=2*leaves,guard_layouts=counts['guard_layouts'],
                standard_guard_vectors=14*counts['guard_layouts'],mode_replay_vectors=2*counts['guard_layouts'],
                hinted_guard_slots=slots,hint_grammar_vectors=200*slots,hint_hash_vectors=4*slots,
                special_auth_vectors=special,actual_opening_occurrences=counts['actual_opening_occurrences'],
                shared_opening_links=counts['shared_opening_links'],alias_formal_reuses=counts['alias_formal_reuses'],
                native_rejections=9,cache_rejections=7,total_guard_vectors=attacks,
                isolated_checksum_valid_digit_chains=10 if adapter and profile in ('a9','auth-order') else 0,
                compiled_script_bytes=100*leaves,largest_disproof_leaf_bytes=100,
                leaf_costs=[[i,99,100,10*n+(10*hinted[i] if adapter else 0),200*n]
                            for i,n in enumerate(unique)])
            row['adapters'].append(ledger)
            calls+=2*leaves+attacks;rejects+=leaves+attacks
        cases.append(source);rows.append(row);census.append(counts);keys+=words;links+=10*words
    native=dict(schema='bitvm2-nova-auth-cost-execution/v1',passed=True,input_manifest_sha256='66'*32,
        leaf_cost_columns=['ordinal','correctness_script_bytes','disproof_script_bytes','witness_items','witness_payload_bytes'],
        cases=rows,compact_execution_records_bytes=1000000,compact_execution_records_sha256='77'*32,
        signature_entries_created=keys,full_signature_signing_calls=keys,cross_adapter_hash_links=links,
        isolated_checksum_valid_digit_chains=40,isolated_chain_engine_executions=0,
        metrics=dict(vectors=calls,expected_rejections=rejects,max_script_bytes=100,
            max_stack_items=70,max_witness_items=61,max_witness_payload_bytes=2000),wall_seconds=1.0)
    native.update({key:True for key in bench.TRUE_FLAGS})
    native.update({key:False for key in bench.FALSE_FLAGS})
    native.update({key:0 for key in ('setup_calls','proving_jobs','native_proofs_verified','gpu_jobs','transactions_broadcast','tree_calls')})
    return native,dict(cases=cases),dict(file_sha256='66'*32),census


class AuthenticationCostBench(unittest.TestCase):
    def test_closed_record_budget_and_case_order_without_graphs(self):
        budget=bench._record_budget()
        self.assertEqual((budget['source_cases'],budget['source_leaves'],budget['normal_engine_calls']),(22,4904,19616))
        self.assertEqual((budget['total_engine_calls_upper'],budget['record_bytes_upper'],budget['combined_upper_bytes']),
                         (71392,220,15706240))
        self.assertLess(budget['combined_upper_bytes'],128<<20)
        self.assertEqual(budget['tree_engine_calls'],0)
        self.assertEqual([row[0] for row in list(bench._requests())[-4:]],['p/rh','p/rf','v/rh','v/rf'])

    def test_resource_guards_precede_input_and_source_work(self):
        with patch.dict(os.environ,{'GITHUB_ACTIONS':'false'}):
            for call in (lambda:bench.run(None,None),lambda:bench._generate(None),
                         lambda:bench._worker(None),lambda:bench._source_snapshot(None)):
                with self.assertRaisesRegex(ValueError,'hosted GitHub Linux'):call()

    def test_signed_u32_domains_and_alias_census_without_programs(self):
        spec=SimpleNamespace(words=(('a',256),('aux',1<<29),('sq',1<<18)),leaves=(
            SimpleNamespace(wires=(1,0),body_sha256='01'*32),
            SimpleNamespace(wires=(0,0,2),body_sha256='02'*32)))
        counts=bench._census(spec)
        self.assertEqual((counts['guard_layouts'],counts['hinted_guard_slots'],counts['actual_opening_occurrences'],
                          counts['shared_opening_links'],counts['alias_formal_reuses']),(2,2,4,1,1))
        def must_not_execute(values,p):
            raise AssertionError('decoder-invalid signed data reached bare predicate')
        program=SimpleNamespace(constraints=(SimpleNamespace(native=must_not_execute),)*2,p=0)
        self.assertIs(bench._truth(spec,{'a':256,'aux':256,'sq':65536},0,program),False)
        self.assertIs(bench._truth(spec,{'a':0xffffffff,'aux':0,'sq':0},1,program),False)
        self.assertIs(bench._truth(spec,{'a':9,'aux':0xffffffff,'sq':0xffffffff},1,program),False)

    def test_synthetic_complete_report_and_defensive_rejections(self):
        native,manifest,info,census=_synthetic_report()
        self.assertEqual(len(bench._validate(native,manifest,info,census)),22)
        self.assertEqual((native['metrics']['vectors'],native['metrics']['expected_rejections']), (54888,45080))
        mutations=(
            lambda x:x['cases'][0]['adapters'][0].__setitem__('total_guard_vectors',True),
            lambda x:x['cases'][0]['adapters'][1].__setitem__('total_guard_vectors',1),
            lambda x:x['cases'][2]['adapters'][1].__setitem__('isolated_checksum_valid_digit_chains',True),
            lambda x:x['cases'][2]['adapters'][0].__setitem__('isolated_checksum_valid_digit_chains',10),
            lambda x:x['cases'][0]['adapters'][1].__setitem__('adapter',True),
            lambda x:x['cases'][0]['adapters'][1].__setitem__('registry_id',x['cases'][0]['adapters'][0]['registry_id']),
            lambda x:x['cases'][0]['adapters'][1]['leaf_costs'][0].__setitem__(3,True),
            lambda x:x['cases'][0]['adapters'][1]['leaf_costs'][0].__setitem__(3,20),
            lambda x:x['cases'][0]['adapters'][1]['leaf_costs'][0].__setitem__(4,100000),
            lambda x:x.__setitem__('proof_verified',True),
            lambda x:x.__setitem__('compact_hint_bytes_script_authenticated',True),
            lambda x:x.__setitem__('candidate_taproot_tree_verified',True),
            lambda x:x.__setitem__('panic_is_rejection',True),
            lambda x:x.__setitem__('tree_calls',1),
        )
        for mutate in mutations:
            changed=copy.deepcopy(native);mutate(changed)
            with self.assertRaises(ValueError):bench._validate(changed,manifest,info,census)


if __name__=='__main__':unittest.main()
