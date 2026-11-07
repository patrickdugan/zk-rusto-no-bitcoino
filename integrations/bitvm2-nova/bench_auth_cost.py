"""Hosted comparison of two adapters for the unchanged full32-bit Wots4.

The same source, public keys, full signatures and raw-u32 values feed both
adapters. Only declared BYTE words use the candidate hinted witness format.
Every cost is measured from complete source catalogues; this synthetic cost
experiment creates no Taproot tree and verifies no Nova or Bitcoin proof.
"""
from hashlib import sha256
import argparse
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
import time

from bench_byte_rho import (_execute,_new_directory,_equal,_hex32,MAX_CASE_BYTES,
                            MAX_MANIFEST_BYTES,MAX_RESULT_BYTES)
from bench_keccak_endpoint import _write_json
from bench_compact import peak_rss


CONTEXT=sha256(b'BITVM2-NOVA/AUTH-COST-CONFORMANCE/v1').digest()
OPERATION='benchmark/auth-cost/v1'
SCHEMA='bitvm2-nova-auth-cost-run/v1'
MAX_RECORD_BYTES=128<<20
MIXED_PROFILES=('a0','a1','a9','a255','bad-aux','bad-square','a256','a-max','auth-order')
LEAF_COST_COLUMNS=['ordinal','correctness_script_bytes','disproof_script_bytes','witness_items','witness_payload_bytes']
ADAPTERS=('compact','bound256-hinted')
METRIC_SUM_FIELDS=('vectors','expected_rejections')
METRIC_MAX_FIELDS=('max_script_bytes','max_witness_items','max_witness_payload_bytes','max_stack_items')


def _guard():
    if (os.environ.get('GITHUB_ACTIONS')!='true' or os.environ.get('RUNNER_OS')!='Linux'
            or sys.platform!='linux'):
        raise ValueError('authentication cost execution is hosted GitHub Linux only')


def _canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')


def _requests():
    for prefix,role in (('p','pallas_scalar'),('v','vesta_scalar')):
        for i,profile in enumerate(MIXED_PROFILES):yield f'{prefix}/m{i}','mixed',profile,role
    for prefix,role in (('p','pallas_scalar'),('v','vesta_scalar')):
        yield prefix+'/rh','round','honest',role
        yield prefix+'/rf','round','producer-fault',role


def _record_budget():
    """Analytic closed upper bound, before source graphs or keys exist."""
    source_leaves=18*2+4*1217
    layouts=18*2+4*11
    normal_calls=4*source_leaves
    standard_calls=28*layouts
    replay_calls=4*layouts
    # At most three distinct hinted BYTE slots per authenticated layout.
    # Each has10 positions x10 malformed encodings xC/D, then2 hash faults xC/D.
    hinted_slots=3*layouts
    hinted_calls=(10*10*2+2*2)*hinted_slots
    # The closed isolated-chain and special auth-order/clamp/checksum inventory
    # has a reserve of128 engine calls per role. No per-word guard expansion.
    special_calls=2*128
    upper_calls=normal_calls+standard_calls+replay_calls+hinted_calls+special_calls
    maximum_record=len(_canonical(dict(a=1,c='v/rf',i='g'*32,m=False,e=False,s='0'*64,w='0'*64)))+1
    upper=upper_calls*maximum_record
    if upper>MAX_RECORD_BYTES:raise ValueError('auth-cost corpus exceeds unchanged128MiB record cap')
    return dict(source_cases=22,source_leaves=source_leaves,normal_engine_calls=normal_calls,
        source_authenticated_layouts_upper=layouts,hinted_slots_upper=hinted_slots,
        standard_guard_calls_upper=standard_calls,mode_replay_calls_upper=replay_calls,
        hinted_guard_calls_upper=hinted_calls,special_and_isolated_calls_upper=special_calls,
        total_engine_calls_upper=upper_calls,record_bytes_upper=maximum_record,
        combined_upper_bytes=upper,hard_cap_bytes=MAX_RECORD_BYTES,tree_engine_calls=0)


def _truth(spec,values,ordinal,program):
    leaf=spec.leaves[ordinal]
    if any(type(values[spec.words[slot][0]]) is not int
            or not 0<=values[spec.words[slot][0]]<spec.words[slot][1] for slot in leaf.wires):return False
    if ordinal>=len(program.constraints):raise ValueError('closed auth fixture has no field/fallback leaves')
    result=program.constraints[ordinal].native(values,program.p)
    if type(result) is not bool:raise ValueError('closed raw predicate must have ordinary Boolean truth')
    return result


def _census(spec):
    from wots_graph import authenticated_shape
    representatives={}
    for ordinal,leaf in enumerate(spec.leaves):representatives.setdefault(authenticated_shape(spec,leaf),ordinal)
    unique=sum(len(set(leaf.wires)) for leaf in spec.leaves)
    formal=sum(len(leaf.wires) for leaf in spec.leaves)
    hinted_slots=sum(sum(spec.words[slot][1]==256 for slot in dict.fromkeys(spec.leaves[i].wires))
                     for i in representatives.values())
    return dict(guard_layouts=len(representatives),hinted_guard_slots=hinted_slots,
        actual_opening_occurrences=unique,shared_opening_links=unique-len(spec.words),
        alias_formal_reuses=formal-unique,unique_slots=[len(set(leaf.wires)) for leaf in spec.leaves],
        hinted_slots=[sum(spec.words[slot][1]==256 for slot in dict.fromkeys(leaf.wires)) for leaf in spec.leaves])


def _generate(directory):
    _guard();_record_budget()
    from auth_cost_sources import build_auth_cost_source,fixture_counts
    descriptors,census=[],[];source=None;key=None
    for index,(name,fixture,profile,role) in enumerate(_requests()):
        if key!=(fixture,role):
            source=None
            source=build_auth_cost_source(fixture,role=role);key=fixture,role
        binding=source.bind(profile);spec,program,values=binding.spec,binding.program,binding.assignment
        counts=dict(fixture_counts(fixture));facts=_census(spec)
        if (source.context!=CONTEXT or len(spec.words)!=counts['words'] or len(spec.leaves)!=counts['leaves']
                or facts['guard_layouts']!=counts['authenticated_shapes']
                or facts['actual_opening_occurrences']!=counts['unique_openings']
                or sum(len(leaf.wires) for leaf in spec.leaves)!=counts['formal_occurrences']):
            raise ValueError('fresh closed source census differs from independent profile')
        if set(values)!={word for word,_ in spec.words} or any(type(value) is not int or not 0<=value<=0xffffffff for value in values.values()):
            raise ValueError('every raw-u32 source assertion must be preserved')
        false=[i for i in range(len(spec.leaves)) if not _truth(spec,values,i,program)]
        if fixture=='round':_equal(false,[] if profile=='honest' else [0,1],'round first-producer/consumer truth')
        filename=f'case-{index:02d}.json'
        case=dict(name=name,spec=spec.json(),expected_spec_id=spec.digest().hex(),words=[values[word] for word,_ in spec.words],
            checks=[dict(ordinal=i,expected_correct=i not in false) for i in range(len(spec.leaves))],measure_all=True)
        info=_write_json(directory/filename,case,MAX_CASE_BYTES)
        descriptors.append(dict(name=name,fixture=fixture,profile=profile,role=role,filename=filename,**info,
            program_sha256=spec.program_sha256,catalogue_id=spec.digest().hex(),source_sha256=source.source_sha256.hex(),
            source_maps_sha256=source.source_maps_sha256.hex(),words=len(spec.words),leaves=len(spec.leaves),
            expected_false=false,expected_abort_ordinals=[]))
        census.append(facts)
        del binding,spec,program,values,case
    del source
    manifest=dict(schema=SCHEMA,context=CONTEXT.hex(),operation_id=OPERATION,cases=descriptors)
    info=_write_json(directory/'manifest.json',manifest,MAX_MANIFEST_BYTES)
    if len(list(directory.iterdir()))!=23:raise ValueError('exact twenty-three auth-cost input files required')
    return manifest,info,census


def _worker(path):
    _guard();source=Path(path)
    if source.is_symlink():raise ValueError('regular configured auth_cost executable required')
    target=source.resolve();entry=target.lstat()
    if (not stat.S_ISREG(entry.st_mode) or entry.st_uid!=os.getuid() or target.name!='auth_cost'
            or not os.access(target,os.X_OK)):
        raise ValueError('trusted configured owned auth_cost executable required')
    return target


def _hash_file(path,cap):
    path=Path(path)
    if path.is_symlink() or not path.is_file():raise ValueError('regular source/binary snapshot required')
    digest=sha256();total=0
    with path.open('rb') as stream:
        while True:
            part=stream.read(1<<20)
            if not part:break
            total+=len(part)
            if total>cap:raise ValueError('source/binary snapshot exceeds byte cap')
            digest.update(part)
    return dict(bytes=total,sha256=digest.hexdigest())


def _source_snapshot(worker):
    _guard();root=Path(__file__).resolve().parent
    paths=set(root.glob('*.py'));rust=[]
    for crate in ('rust-oracle','point-oracle','scalar-source-oracle','auth-cost-oracle'):
        rust.extend((root/crate/'src').rglob('*.rs'))
        for filename in ('Cargo.toml','Cargo.lock'):
            path=root/crate/filename
            if not path.is_file():raise ValueError('all four configured crate manifests/locks must be snapshotted')
            paths.add(path)
    paths.update(rust)
    for filename in ('requirements.txt','transcript-requirements.txt'):
        if (root/filename).is_file():paths.add(root/filename)
    for suffix in ('.expected.json','.dimensions.json','.nht4','.trace.json'):
        path=root/'fixtures'/('nht4-genesis-0-2020-k5'+suffix)
        if not path.is_file():raise ValueError('fixed compiled/runtime input snapshot incomplete')
        paths.add(path)
    # Include every workspace-local literal include_str!/include_bytes! input.
    # These hashes observe source inputs, not an attestation of binary equality.
    for path in rust:
        with path.open('rb') as stream: raw=stream.read((2<<20)+1)
        if len(raw)>2<<20:raise ValueError('compiled source input exceeds byte cap')
        text=raw.decode('utf-8')
        for relative in re.findall(r'include_(?:bytes|str)!\s*\(\s*"([^"]+)"\s*\)',text):
            target=(path.parent/relative).resolve()
            if not target.is_relative_to(root) or not target.is_file():raise ValueError('compiled include leaves integration source root')
            paths.add(target)
    if len(paths)>256 or not (root/'auth-cost-oracle'/'src'/'main.rs').is_file():
        raise ValueError('complete bounded configured auth-cost source snapshot required')
    files=[];total=0
    for path in sorted(paths):
        if path.is_symlink() or not path.resolve().is_relative_to(root):raise ValueError('source snapshot leaves integration root')
        info=_hash_file(path,2<<20);total+=info['bytes']
        if total>64<<20:raise ValueError('source snapshot total cap exceeded')
        files.append(dict(path=path.relative_to(root).as_posix(),**info))
    return dict(schema='bitvm2-nova-worker-source-snapshot/v1',files=files,
        source_snapshot_sha256=sha256(_canonical(files)).hexdigest(),worker_executable=_hash_file(worker,128<<20),
        trusted_configured_library_boundary=True,binary_source_equivalence_attested=False)


TRUE_FLAGS=('same_full32_signature_material_checked','bound_only_mode_selection_checked',
    'all_operand_authentication_before_semantics_checked','canonical_all_ten_hints_checked',
    'actual_mode_aware_opening_links_checked','all_source_predicates_executed_both_adapters',
    'test_keys_only','stack_limit_enabled')
FALSE_FLAGS=('raw_vector_file_written','op_cat_enabled','panic_is_rejection',
    'candidate_taproot_tree_verified','candidate_forest_verified','candidate_membership_verified',
    'production_assertion_binding','bitcoin_transaction_graph','complete_bitvm2_verifier',
    'complete_nova_verifier','full_permutation_verified','full_hash_verified','transcript_verified',
    'proof_verified','savings_assumed','compact_hint_bytes_script_authenticated')


def _special(profile,adapter):
    if adapter==0:return 0
    return {'a9':8,'a256':4,'a-max':4,'auth-order':20}.get(profile,0)


def _checked_metrics(value,vectors,rejections,label):
    fields=METRIC_SUM_FIELDS+METRIC_MAX_FIELDS
    if (type(value) is not dict or set(value)!=set(fields)
            or any(type(value[key]) is not int or value[key]<0 for key in fields)):
        raise ValueError(label+' requires the exact six integer engine metrics')
    _equal(value['vectors'],vectors,label+' engine calls')
    _equal(value['expected_rejections'],rejections,label+' rejection calls')
    if (not 0<value['max_script_bytes']<=100000
            or not 0<value['max_witness_items']<=value['max_stack_items']<=1000
            or not 0<value['max_witness_payload_bytes']<=520*value['max_witness_items']):
        raise ValueError(label+' exceeds unchanged Script/witness/combined-stack limits')
    return value


def _validate(native,manifest,info,census):
    """Accept only the result of this run's directly configured worker call."""
    if type(native) is not dict or native.get('passed') is not True:
        raise ValueError('successful direct authentication-cost worker required')
    _equal(native.get('schema'),'bitvm2-nova-auth-cost-execution/v1','schema')
    _equal(native.get('input_manifest_sha256'),info['file_sha256'],'fresh manifest identity')
    _equal(native.get('leaf_cost_columns'),LEAF_COST_COLUMNS,'complete ordered leaf cost schema')
    for flag in TRUE_FLAGS:
        if native.get(flag) is not True:raise ValueError('required adapter conformance missing: '+flag)
    for flag in FALSE_FLAGS:
        if native.get(flag) is not False:raise ValueError('adapter cost scope exceeded: '+flag)
    for key in ('setup_calls','proving_jobs','native_proofs_verified','gpu_jobs','transactions_broadcast','tree_calls'):
        _equal(native.get(key),0,key)
    size=native.get('compact_execution_records_bytes')
    if type(size) is not int or not 0<size<=_record_budget()['combined_upper_bytes'] or not _hex32(native.get('compact_execution_records_sha256')):
        raise ValueError('actual compact records exceed closed unchanged record budget')
    rows=native.get('cases')
    if type(rows) is not list or len(rows)!=22 or len(census)!=22:raise ValueError('all twenty-two cost cases required')
    calls=rejects=largest=signatures=hash_links=0
    folded_metrics={key:0 for key in METRIC_SUM_FIELDS+METRIC_MAX_FIELDS}
    comparison=[]
    for row,source,count in zip(rows,manifest['cases'],census,strict=True):
        if type(row) is not dict:raise ValueError('typed case observation required')
        for key in ('name','fixture','profile','role','program_sha256','catalogue_id',
                    'source_sha256','source_maps_sha256','words','leaves'):
            _equal(row.get(key),source[key],key)
        for key,value in (('false_predicates',source['expected_false']),('abort_predicates',source['expected_abort_ordinals']),
                ('signature_entries_created',source['words']),('full_signature_signing_calls',source['words']),
                ('cross_adapter_hash_links',10*source['words'])):
            _equal(row.get(key),value,key)
        adapters=row.get('adapters')
        if type(adapters) is not list or len(adapters)!=2:raise ValueError('both actual adapter ledgers required')
        registry_ids=[];costs=[]
        for adapter,ledger in enumerate(adapters):
            if type(ledger) is not dict:raise ValueError('typed mode-aware ledger required')
            slots=0 if adapter==0 else count['hinted_guard_slots']
            expected=dict(adapter=adapter,label=ADAPTERS[adapter],normal_vectors=2*source['leaves'],
                guard_layouts=count['guard_layouts'],standard_guard_vectors=14*count['guard_layouts'],
                mode_replay_vectors=2*count['guard_layouts'],hinted_guard_slots=slots,
                hint_grammar_vectors=200*slots,hint_hash_vectors=4*slots,
                special_auth_vectors=_special(source['profile'],adapter),
                actual_opening_occurrences=count['actual_opening_occurrences'],
                shared_opening_links=count['shared_opening_links'],alias_formal_reuses=count['alias_formal_reuses'],
                native_rejections=9,cache_rejections=7)
            for key,value in expected.items():_equal(ledger.get(key),value,'adapter '+key)
            for key in ('registry_id','compiled_stream_sha256'):
                if not _hex32(ledger.get(key)):raise ValueError('actual mode-aware identity missing: '+key)
            registry_ids.append(ledger['registry_id'])
            leaf_costs=ledger.get('leaf_costs')
            if type(leaf_costs) is not list or len(leaf_costs)!=source['leaves']:
                raise ValueError('all ordered leaf costs required; no sampling or shape projection')
            compiled=maximum=normal_script=normal_items=normal_payload=0
            for ordinal,entry in enumerate(leaf_costs):
                if type(entry) is not list or len(entry)!=5 or any(type(value) is not int for value in entry):
                    raise ValueError('strict integer five-column cost row required')
                i,cbytes,dbytes,items,payload=entry
                _equal(i,ordinal,'ordered cost ordinal')
                if not 0<cbytes<=100000 or not 0<dbytes<=100000:
                    raise ValueError('per-leaf Script exceeds unchanged100000-byte cap')
                unique=count['unique_slots'][ordinal];hinted=0 if adapter==0 else count['hinted_slots'][ordinal]
                _equal(items,10*unique+10*hinted,'actual variable-width packet witness depth')
                # Full upstream Wots4 carries ten20-byte chain elements. Hints
                # add one minimal0..15 ScriptNum item per digit (zero is empty).
                if not 200*unique<=payload<=200*unique+10*hinted:
                    raise ValueError('full32 signature witness payload accounting differs')
                compiled+=dbytes;maximum=max(maximum,dbytes)
                normal_script=max(normal_script,cbytes,dbytes)
                normal_items=max(normal_items,items);normal_payload=max(normal_payload,payload)
            _equal(ledger.get('compiled_script_bytes'),compiled,'complete disproof Script sum')
            _equal(ledger.get('largest_disproof_leaf_bytes'),maximum,'largest actual disproof leaf')
            if compiled>256<<20:raise ValueError('complete component Script stream exceeds unchanged256MiB cap')
            largest=max(largest,maximum);costs.append(compiled)
            attacks=(expected['standard_guard_vectors']+expected['mode_replay_vectors']+
                expected['hint_grammar_vectors']+expected['hint_hash_vectors']+expected['special_auth_vectors'])
            _equal(ledger.get('total_guard_vectors'),attacks,'all adapter attack calls')
            isolated=10 if adapter==1 and source['profile'] in ('a9','auth-order') else 0
            _equal(ledger.get('isolated_checksum_valid_digit_chains'),isolated,'native-only isolated digit-chain evidence')
            normal_metrics=_checked_metrics(ledger.get('normal_metrics'),2*source['leaves'],source['leaves'],
                'normal adapter metrics')
            for key,value in (('max_script_bytes',normal_script),('max_witness_items',normal_items),
                              ('max_witness_payload_bytes',normal_payload)):
                _equal(normal_metrics[key],value,'normal leaf-cost maximum '+key)
            all_metrics=_checked_metrics(ledger.get('metrics'),2*source['leaves']+attacks,
                source['leaves']+attacks,'all adapter metrics')
            _equal(all_metrics['max_script_bytes'],normal_script,'guards reuse normal catalogue scripts')
            for key in METRIC_MAX_FIELDS:
                if all_metrics[key]<normal_metrics[key]:raise ValueError('all adapter maximum is below its normal snapshot: '+key)
                folded_metrics[key]=max(folded_metrics[key],all_metrics[key])
            for key in METRIC_SUM_FIELDS:folded_metrics[key]+=all_metrics[key]
            calls+=2*source['leaves']+attacks;rejects+=source['leaves']+attacks
        if registry_ids[0]==registry_ids[1]:raise ValueError('adapter policy must be committed in distinct registry identities')
        signatures+=source['words'];hash_links+=10*source['words']
        comparison.append(dict(name=source['name'],fixture=source['fixture'],profile=source['profile'],role=source['role'],
            compact_disproof_script_bytes=costs[0],hinted_disproof_script_bytes=costs[1],
            hinted_minus_compact_bytes=costs[1]-costs[0],hinted_to_compact_ratio=costs[1]/costs[0]))
    for key,value in (('signature_entries_created',signatures),('full_signature_signing_calls',signatures),
            ('cross_adapter_hash_links',hash_links),('isolated_checksum_valid_digit_chains',40),
            ('isolated_chain_engine_executions',0)):
        _equal(native.get(key),value,key)
    metrics=_checked_metrics(native.get('metrics'),calls,rejects,'global engine metrics')
    _equal(metrics,folded_metrics,'exact global fold of all adapter metrics')
    wall=native.get('wall_seconds')
    if type(wall) not in (int,float) or not math.isfinite(wall) or not 0<=wall<=1260:raise ValueError('native wall cap exceeded')
    return comparison


def run(cases_dir,native_worker):
    _guard();started=time.perf_counter();budget=_record_budget()
    worker=_worker(native_worker);snapshot=_source_snapshot(worker);directory=_new_directory(cases_dir)
    manifest,info,census=_generate(directory)
    native=_execute(worker,directory,info['file_sha256'])
    comparison=_validate(native,manifest,info,census)
    _equal(_source_snapshot(worker),snapshot,'configured source/binary unchanged during direct run')
    return dict(schema='bitvm2-nova-auth-cost-conformance/v1',native=native,manifest=info,source_snapshot=snapshot,
        compact_record_budget=budget,cases=22,adapters=list(ADAPTERS),actual_cost_comparison=comparison,
        direct_native_worker_executed=True,external_result_receipt_loaded=False,sources_unchanged_during_run=True,
        measurement_includes_complete_source_catalogues=True,transaction_framing_included=False,
        taproot_or_forest_constructed=False,full_permutation_verified=False,full_hash_verified=False,
        transcript_verified=False,proof_verified=False,complete_nova_verifier=False,complete_bitvm2_verifier=False,
        production_assertion_binding=False,bitcoin_transaction_graph=False,savings_assumed=False,
        setup_calls=0,proving_jobs=0,native_proofs_verified=0,gpu_jobs=0,transactions_broadcast=0,
        wall_seconds=time.perf_counter()-started,parent_peak_rss_bytes=peak_rss(),
        scope='synthetic full32 Wots4 adapter conformance and measured source costs; no hash, proof, tree or production acceptance')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cases-dir',type=Path,required=True);parser.add_argument('--native-worker',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True);args=parser.parse_args();_guard()
    from bench_keccak_endpoint import _output_file
    output=_output_file(args.output);result=run(args.cases_dir,args.native_worker)
    _write_json(output,result,MAX_RESULT_BYTES);print(json.dumps(result,ensure_ascii=True,allow_nan=False))


if __name__=='__main__':main()
