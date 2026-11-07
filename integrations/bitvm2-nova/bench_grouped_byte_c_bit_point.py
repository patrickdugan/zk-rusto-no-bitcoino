"""Role-scoped grouped conditional-point and live forest conformance.

Each worker executes fresh sources. Separate aggregate mode checks accounting
observations; it never admits a proof or feeds a receipt back into a worker.
"""
from hashlib import sha256
import argparse
import json
import math
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time

import bench_byte_c_bit_point as legacy
from bench_byte_rho import (_new_directory, _equal, _hex32, MAX_CASE_BYTES,
    MAX_MAP_BYTES, MAX_MANIFEST_BYTES, MAX_RESULT_BYTES)
from bench_byte_rho_chain import (_fixture, _check_interfaces, _full_states,
    CONNECTION_COUNTS, OPENING_COUNTS, FOREST_NEGATIVES, LOCAL_NEGATIVES, _depth)
from bench_keccak_endpoint import _write_json
from bench_compact import peak_rss
from bench_proof_payload_origins import _hash_file, _literal_dependencies

CONTEXT = sha256(b'BITVM2-NOVA/GROUPED-BYTE-C-BIT-POINT-CONFORMANCE/v1').digest()
OPERATION = 'benchmark/grouped-byte-c-bit-point/v1'
SCHEMA = 'bitvm2-nova-grouped-byte-c-bit-point-run/v1'
REPORT_SCHEMA = 'bitvm2-nova-grouped-byte-c-bit-point-conformance/v1'
NATIVE_SCHEMA = 'bitvm2-nova-grouped-byte-c-bit-point-execution/v1'
ROLES = {'pallas_scalar': ('p', 'pallas_base', 59), 'vesta_scalar': ('v', 'vesta_base', 44)}
COMPONENT_LEAVES = (29245,29245,453,111,29245,9,29245,29245,245,9,3457)
COMPONENT_WORDS = (29445,29445,587,187,29445,23,29445,29445,379,264,7498)
BRANCHES = ('rho-hi','rho-lo','rho-tail','c-coeff-frame','c-prefix','c-absorb',
    'c-hi','c-lo','c-uniform','scalar-bits','conditional-point')
FULL_COMPONENTS = frozenset((0,1,4,6,7))
MAIN_PROFILES = ('honest','coherent-bit','coherent-scalar-alias')
MAX_RECORD_BYTES = 128 << 20
ROLE_RECORD_UPPER, GLOBAL_RECORD_UPPER = 65235280, 130470560
ROLE_CALL_UPPER, ROLE_REJECTION_UPPER = 341804, 187520
METRIC_SUM = ('vectors','expected_rejections')
METRIC_MAX = ('max_script_bytes','max_witness_items','max_witness_payload_bytes','max_stack_items')
STREAM_FRAMING = 'u32le-length-script/v1'
SNAPSHOT_CRATES = ('rust-oracle','point-oracle','scalar-source-oracle','auth-cost-oracle',
    'proof-payload-origins-oracle','grouped-convolution-oracle','grouped-point-oracle')


def _guard():
    if (os.environ.get('GITHUB_ACTIONS') != 'true'
            or os.environ.get('RUNNER_OS') != 'Linux' or sys.platform != 'linux'):
        raise ValueError('grouped challenge-bit point execution is hosted GitHub Linux only')


def _role(role):
    if type(role) is not str or role not in ROLES:
        raise ValueError('one explicit pallas_scalar or vesta_scalar role required')
    return ROLES[role]


def _canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')


def _requests(role):
    prefix, base, counter = _role(role)
    return tuple((prefix+'/'+suffix,role,base,counter,profile)
        for suffix,profile in zip(('h','b','a'),MAIN_PROFILES,strict=True))


def _probe_requests(role):
    prefix, base, _ = _role(role)
    old = ('coefficient-c0-modulus','coefficient-c2-modulus','frame-counter','frame-NoDS',
        'frame-tag','frame-zero-capacity','absorb-wrong-xor','absorb-selector','absorb-delimiter','absorb-end-mask')
    negative = ('invalid-P-b0','wrong-E-b0','wrong-selected-R','wrong-R-flag','nonzero-infinity',
        'auxiliary-flip','signed-bit-two','coordinate-modulus','coordinate-modulus-plus-one','grouped-ab-subtotal')
    for i,kind in enumerate(old):
        yield dict(name=f'{prefix}/q{i}',role=role,field_role=role,kind=kind,category='chain',
            leaves=111 if i<6 else 9,guard_bound=24 if i<6 else 4)
    for i,bit in enumerate((0,1,0,1,0,1)):
        yield dict(name=f'{prefix}/e{i}',role=role,field_role=base,kind=f'point-edge-{i}',
            category='point-edge',bit=bit,leaves=3457,guard_bound=107)
    yield dict(name=prefix+'/s',role=role,field_role=role,kind='scalar-plus-modulus',
        category='scalar-alias',leaves=254,guard_bound=63)
    for i,kind in enumerate(negative):
        yield dict(name=f'{prefix}/n{i}',role=role,field_role=base,kind=kind,category='point-negative',
            leaves=3457,guard_bound=2 if i==9 else 12)


def _record_budget(role):
    _role(role)
    def size(name,index,mode=False,expected=False):
        return len(_canonical(dict(c=name,i=index,m=mode,e=expected,s='0'*64,w='0'*64)))+1
    def all_bytes(name,component,count):
        digits=1+sum(max(0,min(count,10**width)-10**(width-1))*width
            for width in range(1,len(str(count-1))+1))
        return count*(size(name,[component,0],False,True)+size(name,[component,0],True,False))+2*(digits-count)
    normal=guards=trees=target=alternate=0
    for name,_,_,_,profile in _requests(role):
        for component,count in enumerate(COMPONENT_LEAVES):
            if component not in FULL_COMPONENTS|{10} or profile=='honest':
                normal+=all_bytes(name,component,count)
        old,new=size(name,'g'*64),size(name,'g'*32)
        guards+=14*357*old+14*(2+107)*new
        trees+=2*new
        if profile!='honest':target+=2*128*old
        else:alternate+=(14+2)*new
    pn=pg=pt=0
    for probe in _probe_requests(role):
        name,category=probe['name'],probe['category']
        maximum=size(name,'g'*(64 if category=='chain' else 32))
        if category in ('chain','scalar-alias'):
            pn+=sum(size(name,i,False,True)+size(name,i,True,False) for i in range(probe['leaves']))
        else:
            selected=128 if category=='point-edge' else 2 if probe['kind']=='grouped-ab-subtotal' else 12
            pn+=2*selected*size(name,3456)
        pg+=14*probe['guard_bound']*maximum
        pt+=2*maximum
    total=normal+guards+trees+target+alternate+pn+pg+pt
    if total!=ROLE_RECORD_UPPER or 2*total!=GLOBAL_RECORD_UPPER or 2*total>MAX_RECORD_BYTES:
        raise ValueError('closed role/global compact record budget differs')
    return dict(main_normal_bytes=normal,targeted_point_upper_bytes=target,main_guard_upper_bytes=guards,
        main_tree_upper_bytes=trees,alternate_point_upper_bytes=alternate,probe_normal_upper_bytes=pn,
        probe_guard_upper_bytes=pg,probe_tree_upper_bytes=pt,combined_upper_bytes=total,
        shared_global_upper_bytes=2*total,shared_global_hard_cap_bytes=MAX_RECORD_BYTES,
        engine_calls_upper=ROLE_CALL_UPPER,expected_rejections_upper=ROLE_REJECTION_UPPER,
        main_cases=3,private_probes=27,full_cases=1,targeted_cases=2,old_identifier_bytes=64,new_identifier_bytes=32)


def _policy():
    return dict(schema='bitvm2-nova-grouped-bit-point-accounting-policy/v1',context=CONTEXT.hex(),
        operation_id=OPERATION,roles={role:dict(prefix=v[0],base_role=v[1],rho_counter=v[2]) for role,v in ROLES.items()},
        component_words=list(COMPONENT_WORDS),component_leaves=list(COMPONENT_LEAVES),
        main_profiles=list(MAIN_PROFILES),private_probe_kinds=[p['kind'] for p in _probe_requests('pallas_scalar')],
        stream_framing=STREAM_FRAMING,role_record_upper=ROLE_RECORD_UPPER,
        global_record_upper=GLOBAL_RECORD_UPPER,record_hard_cap=MAX_RECORD_BYTES,
        role_calls_upper=ROLE_CALL_UPPER,role_rejections_upper=ROLE_REJECTION_UPPER,
        max_component_script_bytes=256<<20,max_forest_script_bytes=5<<28,max_components=16,max_depth=19)


def _policy_sha256():return sha256(_canonical(_policy())).hexdigest()


def _leaf_truth(spec,values,ordinal,program):
    leaf=spec.leaves[ordinal]
    if leaf.kind!='conv_ab_all':return legacy._leaf_truth(spec,values,ordinal,program)
    operands=[]
    for slot in leaf.wires:
        word,bound=spec.words[slot];value=values[word]
        if type(value) is not int or not 0<=value<bound:return False
        operands.append(value)
    if leaf.argument not in ((1,2,3,4),(4,4,4,4),(3,2,1)):
        raise ValueError('closed grouped AB pattern required')
    offset=0;results=[]
    for count in leaf.argument:
        row=operands[offset:offset+2*count+1]
        if len(row)!=2*count+1:raise ValueError('complete independent row operands required')
        results.append(row[-1]==sum(row[2*i]*row[2*i+1] for i in range(count)))
        offset+=2*count+1
    if offset!=len(operands):raise ValueError('surplus grouped row operands')
    return all(results)


def _classify(spec,values,program):
    truth=tuple(_leaf_truth(spec,values,i,program) for i in range(len(spec.leaves)))
    if any(value is not None and type(value) is not bool for value in truth):
        raise ValueError('tri-state source classification required')
    return [i for i,v in enumerate(truth) if v is False],[i for i,v in enumerate(truth) if v is None]


def _point_selection(spec,values,operation_id,old_to_new):
    _guard()
    from conditional_point import build_conditional_point
    old=build_conditional_point(context=CONTEXT,role=spec.field_role,bit_index=0,operation_id=operation_id)
    false,abort=_classify(old.spec,values,old.program)
    selected=legacy._point_selection(old.spec,false,abort)
    if len(old_to_new)!=len(old.spec.leaves):raise ValueError('complete genuine legacy projection required')
    projected=sorted({old_to_new[i][0] for i in selected})
    if (len(projected)>128 or any(type(i) is not int or not 0<=i<len(spec.leaves) for i in projected)):
        raise ValueError('projected legacy point selection exceeds reviewed scope')
    return projected


def _case(name,spec,values,program,ordinals):
    if set(values)!={word for word,_ in spec.words} or any(type(v) is not int or not 0<=v<=0xffffffff for v in values.values()):
        raise ValueError('complete exact signed-u32 assertion required')
    false,abort=_classify(spec,values,program)
    if set(ordinals)&set(abort):raise ValueError('selected abort cannot count as a disproof')
    return dict(name=name,spec=spec.json(),expected_spec_id=spec.digest().hex(),
        words=[values[word] for word,_ in spec.words],measure_all=True,
        checks=[dict(ordinal=i,expected_correct=i not in false) for i in ordinals]),false,abort


def _files(directory,stem,name,record,values,ordinals,binding,profile):
    spec,program=record.spec,record.program;descriptor=record.descriptor.json()
    case,false,abort=_case(name,spec,values,program,ordinals)
    filename,maps_name,source_name=f'case-{stem}.json',f'maps-{stem}.json',f'source-{stem}.json'
    info=_write_json(directory/filename,case,MAX_CASE_BYTES)
    maps,source,manifest=record.child_source_maps,record.child_source_manifest,record.child_program_manifest
    mi=_write_json(directory/maps_name,maps,MAX_MAP_BYTES);si=_write_json(directory/source_name,source,MAX_MANIFEST_BYTES)
    program_name=f'program-{stem}.json' if manifest is not None else None
    pi=_write_json(directory/program_name,manifest,MAX_MANIFEST_BYTES) if manifest is not None else None
    if (mi['file_sha256']!=descriptor['source_maps_sha256']
            or sha256(_canonical(list(record.global_ids))).hexdigest()!=descriptor['global_ids_sha256']):
        raise ValueError('fresh component sidecars differ from sealed identities')
    full=None
    if record.index in FULL_COMPONENTS:
        initial,output=_full_states(binding.chain,record.index)
        full=dict(name=name,profile=profile,role=spec.field_role,filename=filename,**info,
            catalogue_id=spec.digest().hex(),program_sha256=spec.program_sha256,
            source_sha256=descriptor['source_sha256'],global_ids_sha256=maps['global_ids_sha256'],
            words=len(spec.words),leaves=len(spec.leaves),input_state_hex=initial.hex(),expected_output_state_hex=output.hex(),
            expected_false=false,state_index=None,byte_slot=None,maps_filename=maps_name,
            maps_file_sha256=mi['file_sha256'],maps_file_bytes=mi['file_bytes'],source_maps_sha256=descriptor['source_maps_sha256'],
            program_manifest_filename=program_name,program_manifest_file_sha256=pi['file_sha256'],program_manifest_file_bytes=pi['file_bytes'],
            source_manifest_filename=source_name,source_manifest_file_sha256=si['file_sha256'],source_manifest_file_bytes=si['file_bytes'],blocks=manifest['blocks'])
    mode='all' if len(ordinals)==len(spec.leaves) else 'selected' if ordinals else 'none'
    return dict(descriptor=descriptor,filename=filename,**info,maps_filename=maps_name,
        maps_file_sha256=mi['file_sha256'],maps_file_bytes=mi['file_bytes'],program_manifest_filename=program_name,
        program_manifest_file_sha256=None if pi is None else pi['file_sha256'],program_manifest_file_bytes=None if pi is None else pi['file_bytes'],
        source_manifest_filename=source_name,source_manifest_file_sha256=si['file_sha256'],source_manifest_file_bytes=si['file_bytes'],
        execution_mode=mode,selected_ordinals=None if mode!='selected' else ordinals,
        expected_false=false,expected_abort_ordinals=abort,full=full),dict(selected_leaf_checks=len(ordinals),
        guard_layouts=legacy._shapes(spec),words=len(spec.words),leaves=len(spec.leaves))


def _one(index,request,directory,plan):
    _guard()
    from grouped_byte_c_bit_point import _bind_uniform_alias,SOURCE_DOMAIN
    name,role,base,counter,profile=request
    eval_w,prior,coefficients,fixture=_fixture(role)
    _,A,P=legacy._points(base)
    binding=plan.bind(eval_w,prior,coefficients,A,P)
    if binding.chain.raw_c.hex()!=fixture['honest_c_raw_state_le'] or binding.canonical_bit!=(1 if role=='pallas_scalar' else 0):
        raise ValueError('retained canonical challenge/bit differs')
    if profile=='coherent-bit':binding=plan.bind(eval_w,prior,coefficients,A,P,claimed_bit=1-binding.canonical_bit)
    elif profile=='coherent-scalar-alias':binding=_bind_uniform_alias(plan,eval_w,prior,coefficients,A,P)
    maps,source=plan.source_maps,plan.manifest
    outer_m,outer_s=f'point-maps-{index:02d}.json',f'point-source-{index:02d}.json'
    om=_write_json(directory/outer_m,maps,MAX_MAP_BYTES);osource=_write_json(directory/outer_s,source,MAX_MANIFEST_BYTES)
    cm_name,cs_name=f'chain-maps-{index:02d}.json',f'chain-source-{index:02d}.json'
    chain_maps,chain_source=plan.chain.source_maps,plan.chain.manifest
    cm=_write_json(directory/cm_name,chain_maps,MAX_MAP_BYTES);cs=_write_json(directory/cs_name,chain_source,MAX_MANIFEST_BYTES)
    if om['file_sha256']!=plan.source_maps_sha256.hex() or sha256(SOURCE_DOMAIN+_canonical(source)).digest()!=plan.source_sha256:
        raise ValueError('outer sealed source identity changed')
    headers,census,seen=[],[],{}
    for record in binding.iter_components():
        i=record.index;spec,values,ids,program=record.spec,record.assignment,record.global_ids,record.program
        if (record.branch!=BRANCHES[i] or (len(spec.words),len(spec.leaves))!=(COMPONENT_WORDS[i],COMPONENT_LEAVES[i])
                or spec.field_role!=(base if i==10 else role)):
            raise ValueError('fixed mixed-role component census differs')
        if i<9:_check_interfaces(record,chain_maps['components'][i])
        for global_id,(word,bound) in zip(ids,spec.words,strict=True):
            assertion=bound,values[word]
            if global_id in seen and seen[global_id]!=assertion:raise ValueError('global value/bound conflict')
            seen[global_id]=assertion
        false,abort=_classify(spec,values,program)
        expected=[0] if profile=='coherent-bit' and i==9 else [244] if profile=='coherent-scalar-alias' and i==8 else []
        _equal(false,expected,'exact main false predicates')
        if abort:raise ValueError('unexpected main abort')
        chosen=(list(range(len(spec.leaves))) if profile=='honest' or i not in FULL_COMPONENTS and i!=10
            else _point_selection(spec,values,spec.operation_id,record.child_source_maps['projection']['old_to_new']) if i==10 else [])
        header,count=_files(directory,f'{index:02d}-{i}',name+'/'+record.branch,record,values,chosen,binding,profile)
        maximum=23 if i in FULL_COMPONENTS else 61 if i in (2,8) else 2 if i==9 else 107 if i==10 else COMPONENT_LEAVES[i]
        if count['guard_layouts']>maximum:raise ValueError('guard shapes exceed reviewed bound')
        if i==10:
            count['alternate_group_ordinal']=next(j for j,leaf in enumerate(spec.leaves) if leaf.kind=='conv_ab_all')
        headers.append(header);census.append(count)
        del record,spec,values,ids,program
    if len(headers)!=11 or len(seen)!=155107:raise ValueError('complete mixed-role assertion inventory required')
    if profile!='honest' and sum(census[i]['selected_leaf_checks'] for i in FULL_COMPONENTS|{10})>128:
        raise ValueError('all selected full/point normal leaves share one128-leaf reserve')
    ch=binding.chain
    group=dict(name=name,profile=profile,role=role,base_role=base,rho_counter=counter,c_counter=counter+1,bit_index=0,
        execution_mode='full' if profile=='honest' else 'targeted',source_sha256=plan.source_sha256.hex(),source_maps_sha256=plan.source_maps_sha256.hex(),
        chain_source_sha256=plan.chain.source_sha256.hex(),chain_source_maps_sha256=plan.chain.source_maps_sha256.hex(),
        eval_w_le=eval_w.hex(),prior_state_hex=prior.hex(),compressed_coefficients_le=[raw.hex() for raw in coefficients],
        expected_rho_hi_output_state_hex=ch.rho_hi_output.hex(),expected_rho_lo_output_state_hex=ch.rho_lo_output.hex(),
        expected_rho_raw_state_le=ch.raw_rho.hex(),expected_rho_result_le=ch.rho_result_value.to_bytes(32,'little').hex(),
        expected_rho_quotient_le=ch.rho_quotient_value.to_bytes(33,'little').hex(),expected_prefix_output_state_hex=ch.prefix_output.hex(),
        expected_c_hi_output_state_hex=ch.c_hi_output.hex(),expected_c_lo_output_state_hex=ch.c_lo_output.hex(),
        expected_c_raw_state_le=ch.raw_c.hex(),expected_c_result_le=ch.c_result_value.to_bytes(32,'little').hex(),
        expected_c_quotient_le=ch.c_quotient_value.to_bytes(33,'little').hex(),
        asserted_scalar_le=binding.scalar_value.to_bytes(32,'little').hex(),asserted_scalar_quotient_le=binding.scalar_quotient_value.to_bytes(33,'little').hex(),
        selected_bit=binding.selected_bit,canonical_bit=binding.canonical_bit,point_A=legacy._point(binding.A),point_P=legacy._point(binding.P),
        expected_E=legacy._point(binding.E),expected_R=legacy._point(binding.R),components=headers,
        point_source_filename=outer_s,point_source_file_sha256=osource['file_sha256'],point_source_file_bytes=osource['file_bytes'],
        point_maps_filename=outer_m,point_maps_file_sha256=om['file_sha256'],point_maps_file_bytes=om['file_bytes'],
        chain_source_filename=cs_name,chain_source_file_sha256=cs['file_sha256'],chain_source_file_bytes=cs['file_bytes'],
        chain_maps_filename=cm_name,chain_maps_file_sha256=cm['file_sha256'],chain_maps_file_bytes=cm['file_bytes'])
    return group,census


def _point_probe(probe,honest):
    _guard()
    from grouped_conditional_point import build_grouped_conditional_point
    from curve_trace import AUTO
    from script import limbs
    curve,G,H=legacy._points(probe['field_role'])
    plan=build_grouped_conditional_point(context=CONTEXT,role=probe['field_role'],bit_index=0,
        operation_id=honest['components'][10]['descriptor']['operation_id'])
    A,P,bit=G,H,honest['canonical_bit'];Eclaim=Rclaim=AUTO;kind=probe['kind']
    if probe['category']=='point-edge':
        edge=int(kind.rsplit('-',1)[1])
        A,P=((None,None),(None,G),(G,None),(G,(G[0],-G[1]%curve.p)),(G,G),(G,H))[edge]
        bit=probe['bit']
    elif kind=='invalid-P-b0':A,P,bit,Eclaim=G,(1,1),0,H
    elif kind=='wrong-E-b0':bit,Eclaim=0,G
    elif kind=='wrong-selected-R':Rclaim=curve.add(G,H) if bit==0 else G
    elif kind=='nonzero-infinity':A,P,bit=G,(G[0],-G[1]%curve.p),1
    elif kind in ('auxiliary-flip','signed-bit-two'):bit=0
    bound=plan.bind(A,P,bit,claimed_E=Eclaim,claimed_R=Rclaim)
    values=bound.assignment;ports=plan.ports
    if kind=='wrong-R-flag':values[ports['R_infinity']]=2
    elif kind=='nonzero-infinity':values[ports['R_x'][0]]=1
    elif kind=='auxiliary-flip':values[ports['infinity_delta']]^=1
    elif kind=='signed-bit-two':values[ports['bit']]=2
    elif kind in ('coordinate-modulus','coordinate-modulus-plus-one'):
        for word,value in zip(ports['R_x'],limbs(curve.p+int(kind.endswith('plus-one'))),strict=True):values[word]=value
    elif kind=='grouped-ab-subtotal':values['left/x2/ab/0/0']+=1
    false,abort=_classify(bound.spec,values,bound.program)
    if probe['category']=='point-edge':
        if false or abort:raise ValueError('honest edge contains false/abort predicates')
        selected=_point_selection(bound.spec,values,plan.operation_id,plan.projection.old_to_new);chosen=3419
    elif kind=='grouped-ab-subtotal':
        selected=sorted(false)
        if len(selected)!=2 or {bound.spec.leaves[i].kind for i in selected}!={'conv_ab_all','conv_column'}:
            raise ValueError('new AB probe must select both grouped and retained-column failures')
        chosen=next(i for i in selected if bound.spec.leaves[i].kind=='conv_ab_all')
    else:
        if kind=='invalid-P-b0':
            fields=dict(bound.program.fields)
            selected=[i for i,c in enumerate(bound.program.constraints) if c.kind=='gate_equal'
                and c.argument==(0,) and c.wires[1:10]==fields['right/y2'] and c.wires[10:]==fields['right/curve-rhs']]
        elif kind=='wrong-E-b0':selected=[next(i for i in false if i<3412)]
        elif kind=='wrong-selected-R':selected=[3415 if bit==0 else 3417]
        else:selected={'wrong-R-flag':[3414,3419],'nonzero-infinity':[3417,3419],
            'auxiliary-flip':[3412],'signed-bit-two':[3413,3415,3416,3417,3418],
            'coordinate-modulus':[3455],'coordinate-modulus-plus-one':[3455]}[kind]
        chosen=selected[0]
    if not selected or len(selected)>(128 if probe['category']=='point-edge' else 12) or set(selected)&set(abort):
        raise ValueError('closed selected point scope differs or includes abort')
    if probe['category']=='point-negative' and set(selected)-set(false):
        raise ValueError('point negative must be an actual ordinary disproof')
    inputs=dict(bit=values[ports['bit']],point_A=legacy._point(legacy._asserted_point(values,ports,'A')),
        point_P=legacy._point(legacy._asserted_point(values,ports,'P')),point_E=legacy._point(legacy._asserted_point(values,ports,'E')),
        point_R=legacy._point(legacy._asserted_point(values,ports,'R')))
    return plan,bound.program,bound.spec,values,selected,chosen,inputs


def _probe(index,probe,honest,directory):
    _guard()
    from byte_sumcheck_frame import build_sumcheck_frame,_bind_modulus_fault,_bind_frame_fault
    from byte_sumcheck_absorb import build_sumcheck_absorb
    from uniform_alias import build_scalar_alias
    name,role,kind=probe['name'],probe['role'],probe['kind']
    _,_,coefficients,fixture=_fixture(role);category=probe['category'];inputs={}
    if category=='chain':
        component=3 if probe['leaves']==111 else 5
        op=honest['components'][component]['descriptor']['operation_id']
        if component==3:
            source=build_sumcheck_frame(context=CONTEXT,role=role,counter=fixture['counter']+1,operation_id=op)
            if kind.startswith('coefficient-'):
                bound=_bind_modulus_fault(source,coefficients,0 if kind=='coefficient-c0-modulus' else 2)
            else:
                byte={'frame-counter':69,'frame-NoDS':65,'frame-tag':0,'frame-zero-capacity':136}[kind]
                anchor=next(row for row in source.source_maps['frame_anchors'] if row['byte_index']==byte)
                bound=_bind_frame_fault(source,coefficients,byte,anchor['expected']^1)
            program,spec,values=bound.program,bound.spec,bound.assignment
        else:
            source=build_sumcheck_absorb(context=CONTEXT,role=role,operation_id=op)
            prefix=bytes.fromhex(honest['expected_prefix_output_state_hex']);raw=bytes.fromhex(honest['expected_rho_raw_state_le'])
            base=source.bind(prefix,raw);output={'absorb-wrong-xor':0,'absorb-selector':8,'absorb-delimiter':6,'absorb-end-mask':7}[kind]
            claims=[None]*9;claims[output]=base.outputs[output]^1
            bound=source.bind(prefix,raw,claimed_outputs=tuple(claims));program,spec,values=source.program,source.spec,bound.assignment
        selected=list(range(len(spec.leaves)))
        false,abort=_classify(spec,values,program)
        chosen={'coefficient-c0-modulus':109,'coefficient-c2-modulus':110,'frame-counter':37,'frame-NoDS':33,
            'frame-tag':32,'frame-zero-capacity':45,'absorb-wrong-xor':0,'absorb-selector':8,'absorb-delimiter':6,'absorb-end-mask':7}[kind]
        _equal(false,[chosen],'closed chain counterexample')
    elif category=='scalar-alias':
        component=None;raw=bytes.fromhex(honest['expected_c_raw_state_le'])
        source=build_scalar_alias(raw,context=CONTEXT,role=role,bit_index=0,operation_id=OPERATION+'/probe/scalar-alias/'+name[0])
        program,spec,values=source.program,source.spec,source.assignment
        selected=list(range(254));chosen=253;inputs=dict(raw_c_le=raw.hex())
        false,abort=_classify(spec,values,program);_equal(false,[253],'merged scalar canonical guard')
    else:
        component=10;source,program,spec,values,selected,chosen,inputs=_point_probe(probe,honest)
        false,abort=_classify(spec,values,program)
    case,reported_false,reported_abort=_case(name,spec,values,program,selected)
    _equal(reported_false,false,'complete probe false classification');_equal(reported_abort,abort,'complete probe abort classification')
    filename=f'probe-{index:02d}.json';info=_write_json(directory/filename,case,MAX_CASE_BYTES)
    source_sha=legacy._digest(source.source_sha256);maps_sha=legacy._digest(source.source_maps_sha256)
    if component is not None:
        expected=honest['components'][component]['descriptor']
        for actual,wanted in ((source_sha,expected['source_sha256']),(maps_sha,expected['source_maps_sha256']),
                (spec.digest().hex(),expected['catalogue_id']),(spec.program_sha256,expected['program_sha256'])):
            _equal(actual,wanted,'fresh private positive topology')
    guarded=legacy._shapes(spec,selected if category=='point-negative' else None)
    if guarded>probe['guard_bound']:raise ValueError('private guard shapes exceed closed bound')
    header=dict(name=name,kind=kind,category=category,role=role,field_role=probe['field_role'],source_case=honest['name'],
        source_component=component,operation_id=program.operation_id,filename=filename,**info,
        source_sha256=source_sha,source_maps_sha256=maps_sha,catalogue_id=spec.digest().hex(),program_sha256=spec.program_sha256,
        words=len(spec.words),leaves=len(spec.leaves),execution_mode='all' if len(selected)==len(spec.leaves) else 'selected',
        selected_ordinals=None if len(selected)==len(spec.leaves) else selected,expected_false=false,expected_abort_ordinals=abort,
        selected_leaf=chosen,expected_selected_correct=chosen not in false,inputs=inputs)
    return header,dict(selected_leaf_checks=len(selected),guard_layouts=guarded,words=len(spec.words),leaves=len(spec.leaves))


def _generate(directory,role):
    _guard();_,_,counter=_role(role);_record_budget(role)
    from grouped_byte_c_bit_point import build_grouped_byte_c_bit_point
    plan=build_grouped_byte_c_bit_point(context=CONTEXT,role=role,rho_counter=counter,bit_index=0,operation_id=OPERATION)
    reference=plan.legacy_reference_bytes
    if type(reference) is not bytes or len(reference)>MAX_CASE_BYTES:
        raise ValueError('bounded actual legacy point reference required')
    decoded=json.loads(reference)
    if type(decoded) is not dict or set(decoded)!={'spec','maps'} or _canonical(decoded)!=reference:
        raise ValueError('canonical spec/maps legacy reference without values required')
    with (directory/'legacy-point-reference.json').open('xb') as stream:stream.write(reference)
    cases,census,honest=[],[],None
    for index,request in enumerate(_requests(role)):
        row,count=_one(index,request,directory,plan);cases.append(row);census.append(count)
        if request[-1]=='honest':honest=row
    probes,probe_census=[],[]
    for index,probe in enumerate(_probe_requests(role)):
        row,count=_probe(index,probe,honest,directory);probes.append(row);probe_census.append(count)
    manifest=dict(schema=SCHEMA,context=CONTEXT.hex(),operation_id=OPERATION,role=role,
        legacy_point_reference_filename='legacy-point-reference.json',
        legacy_point_reference_file_sha256=sha256(reference).hexdigest(),legacy_point_reference_file_bytes=len(reference),
        cases=cases,probes=probes)
    info=_write_json(directory/'manifest.json',manifest,MAX_MANIFEST_BYTES)
    if len(list(directory.iterdir()))!=155:raise ValueError('exact155-file one-role input inventory required')
    return manifest,info,census,probe_census


def _worker(path):
    _guard();source=Path(path)
    if source.is_symlink():raise ValueError('regular configured grouped point worker required')
    target=source.resolve();entry=target.lstat()
    if not stat.S_ISREG(entry.st_mode) or entry.st_uid!=os.getuid() or target.name!='grouped_byte_c_bit_point' or not os.access(target,os.X_OK):
        raise ValueError('owned configured grouped point executable required')
    return target


def _source_snapshot(worker):
    _guard();root=Path(__file__).resolve().parent;paths=set(root.glob('*.py'));rust=[]
    for crate in SNAPSHOT_CRATES:
        directory=root/crate/'src'
        if directory.is_symlink() or not directory.is_dir():raise ValueError('configured Rust source root missing')
        rust.extend(directory.rglob('*.rs'))
        for filename in ('Cargo.toml','Cargo.lock'):
            path=root/crate/filename
            if path.is_symlink() or not path.is_file():raise ValueError('configured manifest/lock missing')
            paths.add(path)
    paths.update(rust)
    required=root/'transcript-requirements.txt'
    if not required.is_file() or required.is_symlink():raise ValueError('required transcript dependencies missing')
    paths.add(required)
    optional=root/'requirements.txt'
    if optional.exists() or optional.is_symlink():
        if optional.is_symlink() or not optional.is_file():raise ValueError('optional dependency input must be regular')
        paths.add(optional)
    for suffix in ('.expected.json','.dimensions.json','.nht4','.trace.json'):
        path=root/'fixtures'/('nht4-genesis-0-2020-k5'+suffix)
        if not path.is_file():raise ValueError('retained runtime input snapshot incomplete')
        paths.add(path)
    pending=list(rust);inspected=set()
    while pending:
        path=pending.pop()
        if path in inspected:continue
        inspected.add(path)
        with path.open('rb') as stream:raw=stream.read((2<<20)+1)
        if len(raw)>2<<20:raise ValueError('compiled source input exceeds cap')
        for relative in _literal_dependencies(raw):
            target=(path.parent/relative).resolve()
            if not target.is_relative_to(root) or not target.is_file():raise ValueError('compiled input leaves integration root')
            paths.add(target)
            if target.suffix=='.rs':pending.append(target)
        if len(paths)>256:raise ValueError('configured source file-count cap exceeded')
    files=[];total=0
    for path in sorted(paths):
        if path.is_symlink() or not path.resolve().is_relative_to(root):raise ValueError('source snapshot leaves integration root')
        info=_hash_file(path,2<<20);total+=info['bytes']
        if total>64<<20:raise ValueError('source snapshot total cap exceeded')
        files.append(dict(path=path.relative_to(root).as_posix(),**info))
    return dict(schema='bitvm2-nova-worker-source-snapshot/v1',files=files,
        source_snapshot_sha256=sha256(_canonical(files)).hexdigest(),worker_executable=_hash_file(worker,128<<20),
        trusted_configured_library_boundary=True,binary_source_equivalence_attested=False)


def _tested_commit():
    result=subprocess.run(['git','rev-parse','HEAD'],cwd=Path(__file__).resolve().parent,
        check=True,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
    value=result.stdout.decode('ascii').strip()
    if len(value)!=40 or any(c not in '0123456789abcdef' for c in value):raise ValueError('full tested commit required')
    expected=os.environ.get('GITHUB_SHA')
    if expected is not None and expected!=value:raise ValueError('checked-out commit differs from workflow commit')
    return value


def _execute(worker,directory,manifest_sha,role):
    _guard();_role(role);output=directory/'native-execution.json'
    if output.exists():raise ValueError('fresh direct native output required')
    command=['/usr/bin/prlimit','--as=536870912','--cpu=1200','--fsize=16777216','--',str(worker),
        '--role',role,str(directory/'manifest.json'),str(directory),str(output),manifest_sha]
    environment=dict(os.environ,RAYON_NUM_THREADS='2',CUDA_VISIBLE_DEVICES='',RUST_BACKTRACE='0')
    with tempfile.TemporaryFile(dir=directory) as stdout,tempfile.TemporaryFile(dir=directory) as stderr:
        try:result=subprocess.run(command,stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr,timeout=1260,check=False,env=environment)
        except subprocess.TimeoutExpired as error:raise ValueError('native worker exceeded wall cap') from error
        if result.returncode!=0:
            stderr.seek(0);raise ValueError(f'direct worker failed ({result.returncode}): '+stderr.read(8192).decode('utf-8','replace'))
        for stream in (stdout,stderr):
            stream.seek(0,2)
            if stream.tell()>MAX_RESULT_BYTES:raise ValueError('native diagnostic output cap exceeded')
    return _read_json(output,MAX_RESULT_BYTES)


def _read_json(path,cap):
    path=Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size>cap:raise ValueError('bounded regular JSON required')
    with path.open('rb') as stream:raw=stream.read(cap+1)
    if len(raw)>cap:raise ValueError('JSON input grew beyond cap')
    def unique(pairs):
        out={}
        for key,value in pairs:
            if key in out:raise ValueError('duplicate JSON field')
            out[key]=value
        return out
    try:return json.loads(raw.decode('utf-8'),object_pairs_hook=unique,
        parse_constant=lambda _:(_ for _ in ()).throw(ValueError('nonfinite JSON number')))
    except (UnicodeError,json.JSONDecodeError,RecursionError) as error:raise ValueError('invalid bounded JSON') from error


def _input_files(manifest,info):
    entries={'manifest.json':(info['file_sha256'],info['file_bytes'],MAX_MANIFEST_BYTES),
        manifest['legacy_point_reference_filename']:(manifest['legacy_point_reference_file_sha256'],
            manifest['legacy_point_reference_file_bytes'],MAX_CASE_BYTES)}
    def add(name,digest,size,cap):
        if name in entries and entries[name]!=(digest,size,cap):raise ValueError('conflicting input pin')
        if type(name) is not str or Path(name).name!=name:raise ValueError('flat verifier-owned input filename required')
        entries[name]=(digest,size,cap)
    for group in manifest['cases']:
        for prefix,cap in (('point_source',MAX_MANIFEST_BYTES),('point_maps',MAX_MAP_BYTES),
                ('chain_source',MAX_MANIFEST_BYTES),('chain_maps',MAX_MAP_BYTES)):
            add(group[prefix+'_filename'],group[prefix+'_file_sha256'],group[prefix+'_file_bytes'],cap)
        for header in group['components']:
            add(header['filename'],header['file_sha256'],header['file_bytes'],MAX_CASE_BYTES)
            for prefix,cap in (('maps',MAX_MAP_BYTES),('source_manifest',MAX_MANIFEST_BYTES),('program_manifest',MAX_MANIFEST_BYTES)):
                if header[prefix+'_filename'] is not None:
                    add(header[prefix+'_filename'],header[prefix+'_file_sha256'],header[prefix+'_file_bytes'],cap)
    for probe in manifest['probes']:add(probe['filename'],probe['file_sha256'],probe['file_bytes'],MAX_CASE_BYTES)
    if len(entries)!=155:raise ValueError('exact155-file input pin ledger required')
    return entries


def _verify_inputs(directory,manifest,info,executed=False):
    _guard();_role(manifest['role']);entries=_input_files(manifest,info)
    for name,(digest,size,cap) in entries.items():
        _equal(_hash_file(directory/name,cap),dict(bytes=size,sha256=digest),'immutable source input '+name)
    expected=set(entries)
    if executed:expected.add('native-execution.json')
    _equal({path.name for path in directory.iterdir()},expected,'exclusive input/output directory')


def _source_identity(manifest):
    role=manifest['role'];_role(role)
    mains=[]
    for group in manifest['cases']:
        mains.append(dict(name=group['name'],source_sha256=group['source_sha256'],
            source_maps_sha256=group['source_maps_sha256'],chain_source_sha256=group['chain_source_sha256'],
            components=[{key:h['descriptor'][key] for key in ('index','field_role','program_sha256',
                'catalogue_id','source_sha256','source_maps_sha256')} for h in group['components']]))
    probes=[{key:p[key] for key in ('name','field_role','source_sha256','source_maps_sha256',
        'program_sha256','catalogue_id')} for p in manifest['probes']]
    return sha256(_canonical(dict(role=role,context=manifest['context'],operation_id=manifest['operation_id'],
        legacy_reference_sha256=manifest['legacy_point_reference_file_sha256'],cases=mains,probes=probes))).hexdigest()


def _manifest_scope(manifest,role):
    prefix,base,counter=_role(role)
    if type(manifest) is not dict:raise ValueError('typed one-role source manifest required')
    _narrow_scopes(manifest)
    for key,value in (('schema',SCHEMA),('context',CONTEXT.hex()),('operation_id',OPERATION),('role',role)):
        _equal(manifest.get(key),value,'manifest '+key)
    _equal(manifest.get('legacy_point_reference_filename'),'legacy-point-reference.json','genuine old reference filename')
    if (not _hex32(manifest.get('legacy_point_reference_file_sha256'))
            or type(manifest.get('legacy_point_reference_file_bytes')) is not int
            or not 0<manifest['legacy_point_reference_file_bytes']<=8<<20):
        raise ValueError('bounded genuine legacy reference pin required')
    if (type(manifest.get('cases')) is not list or type(manifest.get('probes')) is not list
            or len(manifest['cases'])!=3 or len(manifest['probes'])!=27):
        raise ValueError('exact one-role3main/27private corpus required')
    for group,request in zip(manifest['cases'],_requests(role),strict=True):
        if type(group) is not dict:raise ValueError('typed closed main source required')
        name,_,_,_,profile=request
        for key,value in (('name',name),('profile',profile),('role',role),('base_role',base),
                ('rho_counter',counter),('c_counter',counter+1),('bit_index',0),
                ('execution_mode','full' if profile=='honest' else 'targeted')):
            _equal(group.get(key),value,'closed group '+key)
        for key in ('selected_bit','canonical_bit'):
            if key in group and (type(group[key]) is not int or group[key] not in (0,1)):
                raise ValueError('strict signed bit value required')
        if 'canonical_bit' in group:
            canonical=1 if role=='pallas_scalar' else 0
            _equal(group['canonical_bit'],canonical,'retained canonical bit')
            _equal(group.get('selected_bit'),canonical if profile=='honest' else 1-canonical,'closed asserted bit')
        for key in ('point_A','point_P','expected_E','expected_R'):
            if key in group:_point_value(group[key],1)
        parts=group.get('components')
        if type(parts) is not list or len(parts)!=11:raise ValueError('eleven role components required')
        for index,header in enumerate(parts):
            if type(header) is not dict or type(header.get('descriptor')) is not dict:raise ValueError('typed sealed component header required')
            d=header['descriptor']
            for key,value in (('index',index),('words',COMPONENT_WORDS[index]),('leaves',COMPONENT_LEAVES[index]),
                    ('branch',BRANCHES[index]),('field_role',base if index==10 else role)):_equal(d.get(key),value,'component role/census')
            for key in ('program_sha256','catalogue_id','source_sha256','source_maps_sha256','global_ids_sha256'):
                if not _hex32(d.get(key)):raise ValueError('sealed component identity missing: '+key)
            expected=[0] if profile=='coherent-bit' and index==9 else [244] if profile=='coherent-scalar-alias' and index==8 else []
            _equal(header.get('expected_false'),expected,'closed main false inventory')
            _equal(header.get('expected_abort_ordinals'),[],'main has no canonical-input aborts')
    for probe,expected in zip(manifest['probes'],_probe_requests(role),strict=True):
        if type(probe) is not dict:raise ValueError('typed closed private source required')
        for key in ('name','role','field_role','kind','category','leaves'):
            _equal(probe.get(key),expected[key],'closed probe '+key)
        _equal(probe.get('source_case'),prefix+'/h','private source case')
        if type(probe.get('expected_selected_correct')) is not bool:raise ValueError('typed private correctness required')
        for key in ('expected_false','expected_abort_ordinals'):
            values=probe.get(key)
            if type(values) is not list or any(type(i) is not int or not 0<=i<probe['leaves'] for i in values) or values!=sorted(set(values)):
                raise ValueError('canonical typed private predicate inventory required')
        inputs=probe.get('inputs')
        if expected['category']=='chain':_equal(inputs,{},'closed chain probe inputs')
        elif expected['category']=='scalar-alias':
            if (type(inputs) is not dict or set(inputs)!={'raw_c_le'} or type(inputs['raw_c_le']) is not str
                    or len(inputs['raw_c_le'])!=128 or any(c not in '0123456789abcdef' for c in inputs['raw_c_le'])):
                raise ValueError('exact scalar-alias raw64 input required')
        else:
            if type(inputs) is not dict or set(inputs)!={'bit','point_A','point_P','point_E','point_R'}:
                raise ValueError('exact closed point probe inputs required')
            if type(inputs['bit']) is not int or not 0<=inputs['bit']<=(2 if expected['kind']=='signed-bit-two' else 1):
                raise ValueError('typed private signed bit required')
            for key in ('point_A','point_P','point_E','point_R'):
                _point_value(inputs[key],2 if key=='point_R' and expected['kind']=='wrong-R-flag' else 1)


def _point_value(value,max_flag):
    if (type(value) is not dict or set(value)!={'infinity','x_le','y_le'}
            or type(value['infinity']) is not int or not 0<=value['infinity']<=max_flag
            or not _hex32(value['x_le']) or not _hex32(value['y_le'])):
        raise ValueError('strict point port encoding required')


TRUE_FLAGS = legacy.TRUE_FLAGS+('grouped_point_projection_checked','frozen_nonpoint_identities_checked',
    'alternate_point_membership_checked')
FALSE_FLAGS = legacy.FALSE_FLAGS
RECURSIVE_FALSE_FLAGS = frozenset(FALSE_FLAGS+('challenge_bit_origin_bound','sumcheck_equation_verified',
    'full_transcript_verified','nova_transcript_verified','eval_w_canonical_in_script',
    'scalar_multiplication_verified','ipa_verified','complete_verifier','nova_transcript_bound',
    'taproot_coverage_verified','taproot_forest_membership_verified','source_authority',
    'binary_source_equivalence_attested','external_result_receipt_loaded','roots_independently_pinned'))


def _narrow_scopes(item):
    if type(item) is dict:
        for key,value in item.items():
            if key in ('combined_stream_sha256','combined_compact_execution_records_sha256'):
                raise ValueError('role streams retain separate raw hashes')
            if key in RECURSIVE_FALSE_FLAGS and value is not False:raise ValueError('contradictory source/proof scope: '+key)
            _narrow_scopes(value)
    elif type(item) is list:
        for value in item:_narrow_scopes(value)


def _alternate(row,part,count,primary):
    alternate=row.get('alternate_point')
    if row['profile']!='honest':
        _equal(alternate,None,'targeted case has no honest alternate selection');return None
    if type(alternate) is not dict:raise ValueError('actual alternate grouped selection required')
    group=count['alternate_group_ordinal']
    for key,value in (('selected_component',10),('selected_leaf',group),('registry_id',part['registry_id']),
            ('catalogue_id',part['catalogue_id']),('guard_vectors',14),('additional_selected_engine_executions',2),
            ('selected_correctness_execution_success',True),('selected_disproof_execution_success',False)):
        _equal(alternate.get(key),value,'alternate '+key)
    for key in ('assertion_material_sha256','group_witness_sha256'):
        if not _hex32(part.get(key)):raise ValueError('primary actual point material/witness observation missing')
    _equal(part.get('group_ordinal'),group,'actual first grouped predicate')
    _equal(alternate.get('assertion_material_sha256'),part['assertion_material_sha256'],'same live assertion material')
    _equal(alternate.get('selected_witness_sha256'),part['group_witness_sha256'],'same actual grouped witness')
    local=alternate.get('local_tree');forest=alternate.get('forest')
    _tree(local,part,3457,group)
    for key in ('merkle_root','output_key'):_equal(local.get(key),part.get(key),'same actual local '+key)
    _tree(forest,dict(compiled_script_bytes=primary['compiled_script_bytes']),150509,group,10)
    for key in ('merkle_root','output_key','component_manifest_sha256','compiled_stream_sha256','compiled_script_bytes'):
        _equal(forest.get(key),primary[key],'same live eleven-component forest '+key)
    _equal(local['selected_script_sha256'],forest['selected_script_sha256'],'same selected Script through hierarchy')
    return _metrics(alternate.get('metrics'),16,15,'alternate selection plus guards')


def _validate(native,manifest,info,census,probe_census,role):
    _manifest_scope(manifest,role)
    if type(native) is not dict or native.get('passed') is not True:raise ValueError('successful direct native observation required')
    _narrow_scopes(native)
    for key,value in (('schema',NATIVE_SCHEMA),('role',role),('input_manifest_sha256',info['file_sha256']),
            ('script_stream_framing',STREAM_FRAMING)):_equal(native.get(key),value,'native '+key)
    reference=native.get('legacy_point_reference')
    if type(reference) is not dict or set(reference)!={'file_sha256','program_sha256','catalogue_id','words','leaves','executed','committed'}:
        raise ValueError('exact independently admitted legacy reference summary required')
    for key,value in (('file_sha256',manifest['legacy_point_reference_file_sha256']),('words',7498),('leaves',6161),
            ('executed',False),('committed',False)):_equal(reference[key],value,'reference '+key)
    if any(not _hex32(reference[key]) for key in ('program_sha256','catalogue_id')):
        raise ValueError('native-admitted old identities must be well-formed observations')
    for flag in TRUE_FLAGS:
        if native.get(flag) is not True:raise ValueError('required measured relation missing: '+flag)
    for flag in FALSE_FLAGS:
        if native.get(flag) is not False:raise ValueError('verifier scope exceeded: '+flag)
    for key in ('setup_calls','proving_jobs','native_proofs_verified','gpu_jobs','transactions_broadcast'):_equal(native.get(key),0,key)
    size=native.get('compact_execution_records_bytes')
    if type(size) is not int or not 0<size<=ROLE_RECORD_UPPER or not _hex32(native.get('compact_execution_records_sha256')):
        raise ValueError('role record bytes/hash exceed the closed budget')
    rows,probes=native.get('cases'),native.get('probes')
    if type(rows) is not list or len(rows)!=3 or type(probes) is not list or len(probes)!=27 or len(census)!=3 or len(probe_census)!=27:
        raise ValueError('complete one-role three-main/twenty-seven-probe report required')
    normal_fold={key:0 for key in METRIC_SUM+METRIC_MAX};all_fold=dict(normal_fold)
    normal=guards=largest=0;main_ids=set();main_roots=set()
    for row,source,counts in zip(rows,manifest['cases'],census,strict=True):
        if type(row) is not dict or len(counts)!=11:raise ValueError('typed complete main observation required')
        for key in source:
            if key in ('name','profile','role','base_role','rho_counter','c_counter','bit_index','execution_mode',
                    'source_sha256','source_maps_sha256','chain_source_sha256','chain_source_maps_sha256',
                    'asserted_scalar_le','asserted_scalar_quotient_le','selected_bit','canonical_bit','point_A','point_P') or key.startswith('expected_'):
                _equal(row.get(key),source[key],'main '+key)
        honest=source['profile']=='honest'
        for key,value in (('full_statement_executed',honest),('signature_entries_created',155107),
                ('local_declared_words',156163),('cached_signature_reuses',1056),('all_native_predicates_classified',150509),
                ('scalar_limb_opening_links',9),('scalar_canonical_opening_links',9),('selected_bit_opening_links',5),
                ('canonical_internal_opening_links',46),('internal_cached_boundary_entries',23000),
                ('internal_producer_consumer_opening_links',46000),('native_rejections',264),
                ('map_rejections',22),('source_rejections',30),('cache_rejections',108)):
            _equal(row.get(key),value,key)
        _equal(row.get('connections'),[dict(kind=k,logical_links=v,opening_links=OPENING_COUNTS[k]) for k,v in CONNECTION_COUNTS.items()],
            'all eleven actual cross-component opening groups')
        parts=row.get('components')
        if type(parts) is not list or len(parts)!=11:raise ValueError('eleven measured component ledgers required')
        compiled=chosen=layouts=0
        for part,header,count in zip(parts,source['components'],counts,strict=True):
            for key,value in header['descriptor'].items():_equal(part.get(key),value,'component '+key)
            for key,value in (('context',manifest['context']),('execution_mode',header['execution_mode']),
                    ('selected_ordinals',header['selected_ordinals']),('executed_leaves',count['selected_leaf_checks']),
                    ('false_predicates',header['expected_false']),('abort_predicates',header['expected_abort_ordinals']),
                    ('guard_layouts',count['guard_layouts']),('guard_vectors',14*count['guard_layouts'])):
                _equal(part.get(key),value,'component '+key)
            byte_count,maximum=_cost(part);largest=max(largest,maximum);compiled+=byte_count
            n,g=count['selected_leaf_checks'],14*count['guard_layouts']
            before=_metrics(part.get('normal_metrics'),2*n,n,'component normal')
            after=_metrics(part.get('metrics'),2*n+g,n+g,'component with guards')
            if any(after[k]<before[k] for k in METRIC_MAX) or after['max_script_bytes']!=maximum:
                raise ValueError('component metric maxima contradict measured catalogue')
            _fold(normal_fold,before);_fold(all_fold,after)
            chosen+=n;layouts+=count['guard_layouts'];main_ids.add(part['registry_id'])
            if _hex32(part.get('merkle_root')):main_roots.add(part['merkle_root'])
        if compiled>5<<28:raise ValueError('complete forest exceeds unchanged1.25GiB cap')
        for key,value in (('selected_leaf_checks',chosen),('guard_layouts',layouts),('guard_vectors',14*layouts),
                ('additional_selected_engine_executions',2)):_equal(row.get(key),value,key)
        component=10 if honest else 9 if source['profile']=='coherent-bit' else 8
        ordinal=3456 if honest else 0 if source['profile']=='coherent-bit' else 244
        for key,value in (('selected_component',component),('selected_leaf',ordinal),
                ('selected_correctness_execution_success',honest),('selected_disproof_execution_success',not honest)):
            _equal(row.get(key),value,'primary '+key)
        forest=row.get('forest');_tree(forest,dict(compiled_script_bytes=compiled),150509,ordinal,component)
        _fold(all_fold,_metrics(row.get('primary_selection_metrics'),2,1,'primary live selection'))
        alternate=_alternate(row,parts[10],counts[10],forest)
        if alternate is not None:_fold(all_fold,alternate)
        normal+=chosen;guards+=14*layouts
    for row,source,count in zip(probes,manifest['probes'],probe_census,strict=True):
        if type(row) is not dict:raise ValueError('typed separate private observation required')
        for key in ('name','kind','category','role','field_role','source_case','source_component','operation_id',
                'source_sha256','source_maps_sha256','program_sha256','catalogue_id','words','leaves',
                'execution_mode','selected_ordinals','selected_leaf','expected_selected_correct','inputs'):
            _equal(row.get(key),source[key],'probe '+key)
        n,g=count['selected_leaf_checks'],14*count['guard_layouts']
        for key,value in (('context',manifest['context']),('executed_leaves',n),
                ('false_predicates',source['expected_false']),('abort_predicates',source['expected_abort_ordinals']),
                ('signature_entries_created',source['words']),('guard_layouts',count['guard_layouts']),
                ('guard_vectors',g),('native_rejections',24),('additional_selected_engine_executions',2)):
            _equal(row.get(key),value,'probe '+key)
        expected=source['expected_selected_correct']
        for key,value in (('selected_correctness_execution_success',expected),('selected_disproof_execution_success',not expected)):
            _equal(row.get(key),value,'probe '+key)
        _,maximum=_cost(row);largest=max(largest,maximum)
        _tree(row.get('tree'),row,source['leaves'],source['selected_leaf'])
        if row['registry_id'] in main_ids or row['tree']['merkle_root'] in main_roots:
            raise ValueError('private probe cannot use a main registry/commitment')
        before=_metrics(row.get('normal_metrics'),2*n,n,'private normal')
        after=_metrics(row.get('metrics'),2*n+g+2,n+g+1,'private guards and local tree')
        if any(after[k]<before[k] for k in METRIC_MAX) or after['max_script_bytes']>maximum:
            raise ValueError('private maxima contradict its measured catalogue')
        _fold(normal_fold,before);_fold(all_fold,after)
        normal+=n;guards+=g
    for key,value in (('signature_entries_created',3*155107),('local_declared_words',3*156163),
            ('cached_signature_reuses',3*1056),('canonical_internal_opening_links',3*46),
            ('scalar_canonical_opening_links',3*9),('scalar_limb_opening_links',3*9),('selected_bit_opening_links',3*5),
            ('internal_cached_boundary_entries',3*23000),('internal_producer_consumer_opening_links',3*46000),
            ('full_statement_cases',1),('targeted_statement_cases',2),('private_probe_registries',27),('private_probe_trees',27)):
        _equal(native.get(key),value,key)
    _equal(native.get('private_probe_signature_entries_created'),sum(p['words'] for p in manifest['probes']),'separate private signatures')
    _equal(all_fold['vectors'],2*normal+guards+14+62,'all normal/guard/tree calls')
    _equal(all_fold['expected_rejections'],normal+guards+14+31,'ordinary/guard/tree rejection accounting')
    _equal(_metrics(native.get('normal_metrics'),2*normal,normal,'global normal'),normal_fold,'exact normal fold')
    _equal(_metrics(native.get('metrics'),all_fold['vectors'],all_fold['expected_rejections'],'global all'),all_fold,'exact all fold')
    _equal(all_fold['max_script_bytes'],largest,'actual global maximum Script size')
    if all_fold['vectors']>ROLE_CALL_UPPER or all_fold['expected_rejections']>ROLE_REJECTION_UPPER:
        raise ValueError('actual role accounting exceeds reviewed bound')
    wall=native.get('wall_seconds')
    if type(wall) not in (int,float) or not math.isfinite(wall) or not 0<=wall<=1260:
        raise ValueError('native wall cap exceeded')
    return rows,probes


def _manifest_census(manifest,native):
    """Accounting-only reconstruction from separately bound input headers.

    It does not rebuild a graph or elevate an observation to Script authority.
    Direct execution used independently generated graph census in _validate.
    """
    if type(native) is not dict:raise ValueError('typed native observation required')
    role=manifest['role'];_manifest_scope(manifest,role)
    if type(native.get('cases')) is not list or len(native['cases'])!=3:
        raise ValueError('three role observations required')
    counts=[]
    for group,row in zip(manifest['cases'],native['cases'],strict=True):
        parts=row.get('components')
        if type(parts) is not list or len(parts)!=11:raise ValueError('eleven component observations required')
        case=[]
        for i,(header,part) in enumerate(zip(group['components'],parts,strict=True)):
            if type(part) is not dict:raise ValueError('typed component observation required')
            selected=header['selected_ordinals']
            mode=header['execution_mode']
            if mode=='all':n=COMPONENT_LEAVES[i]
            elif mode=='none':
                if selected is not None:raise ValueError('none mode has no selected ordinals')
                n=0
            elif mode=='selected':
                if type(selected) is not list or selected!=sorted(set(selected)) or any(type(k) is not int or not 0<=k<COMPONENT_LEAVES[i] for k in selected):
                    raise ValueError('typed selected component ordinals required')
                n=len(selected)
            else:raise ValueError('known component execution mode required')
            honest=group['profile']=='honest'
            if honest and mode!='all':raise ValueError('full honest source cannot become targeted')
            if not honest and i in FULL_COMPONENTS and mode!='none':raise ValueError('targeted full permutations have no normal calls')
            if not honest and i not in FULL_COMPONENTS|{10} and mode!='all':raise ValueError('small source is always fully executed')
            if not honest and i==10 and (mode!='selected' or n>128):raise ValueError('targeted point scope exceeds reserve')
            maximum=23 if i in FULL_COMPONENTS else 61 if i in (2,8) else 2 if i==9 else 107 if i==10 else COMPONENT_LEAVES[i]
            shape=part.get('guard_layouts')
            if type(shape) is not int or not 0<shape<=maximum:raise ValueError('typed component guard layout bound required')
            value=dict(selected_leaf_checks=n,guard_layouts=shape,words=COMPONENT_WORDS[i],leaves=COMPONENT_LEAVES[i])
            if i==10:
                ordinal=part.get('group_ordinal')
                if type(ordinal) is not int or not 0<=ordinal<3457:raise ValueError('typed grouped ordinal required')
                value['alternate_group_ordinal']=ordinal
            case.append(value)
        counts.append(case)
    probes=[]
    if type(native.get('probes')) is not list or len(native['probes'])!=27:raise ValueError('twenty-seven private observations required')
    for header,row,request in zip(manifest['probes'],native['probes'],_probe_requests(role),strict=True):
        if type(row) is not dict:raise ValueError('typed private observation required')
        if header['execution_mode']=='all':n=header['leaves']
        else:
            selected=header['selected_ordinals']
            if type(selected) is not list or selected!=sorted(set(selected)) or any(type(k) is not int or not 0<=k<header['leaves'] for k in selected):
                raise ValueError('typed selected private ordinals required')
            n=len(selected)
        maximum=128 if request['category']=='point-edge' else 2 if request['kind']=='grouped-ab-subtotal' else 12
        if request['category'] not in ('chain','scalar-alias') and n>maximum:raise ValueError('selected private scope exceeds bound')
        if request['kind']=='grouped-ab-subtotal' and (n!=2 or len(header['expected_false'])!=2 or sorted(header['expected_false'])!=header['selected_ordinals']):
            raise ValueError('new grouped probe must execute both actual false predicates')
        shape=row.get('guard_layouts')
        if type(shape) is not int or not 0<shape<=request['guard_bound']:raise ValueError('typed private guard layout bound required')
        probes.append(dict(selected_leaf_checks=n,guard_layouts=shape,words=header['words'],leaves=header['leaves']))
    return counts,probes


def _metrics(value,calls,rejects,label):
    keys=METRIC_SUM+METRIC_MAX
    if type(value) is not dict or set(value)!=set(keys) or any(type(value[k]) is not int or value[k]<0 for k in keys):
        raise ValueError('exact six strict-integer metrics required: '+label)
    _equal(value['vectors'],calls,label+' calls');_equal(value['expected_rejections'],rejects,label+' rejections')
    if calls==0:
        if any(value[k] for k in keys):raise ValueError('zero-call snapshot must be entirely zero')
    elif (not 0<value['max_script_bytes']<=100000
            or not 0<value['max_witness_items']<=value['max_stack_items']<=1000
            or not 0<value['max_witness_payload_bytes']<=520*value['max_witness_items']):
        raise ValueError('unchanged engine limits exceeded: '+label)
    return value


def _fold(target,value):
    for key in METRIC_SUM:target[key]+=value[key]
    for key in METRIC_MAX:target[key]=max(target[key],value[key])


def _cost(row):
    for key in ('registry_id','compiled_stream_sha256'):
        if not _hex32(row.get(key)):raise ValueError('actual compiled identity missing: '+key)
    size,maximum=row.get('compiled_script_bytes'),row.get('largest_disproof_leaf_bytes')
    if type(size) is not int or not 0<size<=256<<20 or type(maximum) is not int or not 0<maximum<=min(size,100000):
        raise ValueError('actual component Script accounting exceeds caps')
    return size,maximum


def _tree(tree,ledger,count,ordinal,component=None):
    if type(tree) is not dict:raise ValueError('actual live commitment observation required')
    local=count if component is None else COMPONENT_LEAVES[component]
    control=33+32*(_depth(local,ordinal)+(0 if component is None else _depth(11,component)))
    for key,value in (('leaf_count',count),('compiled_script_bytes',ledger['compiled_script_bytes']),
            ('control_block_bytes',control)):_equal(tree.get(key),value,'tree '+key)
    if component is None:
        _equal(tree.get('compiled_stream_sha256'),ledger['compiled_stream_sha256'],'local actual u32-framed stream')
        if tree.get('membership_verified') is not True:raise ValueError('actual local membership missing')
        negatives=LOCAL_NEGATIVES
    else:
        for key,value in (('components',11),('selected_component',component),('selected_leaf',ordinal)):
            _equal(tree.get(key),value,'forest '+key)
        if tree.get('hierarchical_membership_verified') is not True or not _hex32(tree.get('component_manifest_sha256')):
            raise ValueError('actual ordered live forest missing')
        negatives=FOREST_NEGATIVES
    if tree.get('roots_independently_pinned') is not False:raise ValueError('test roots cannot become production authority')
    for key in ('merkle_root','output_key','control_block_sha256','selected_script_sha256','compiled_stream_sha256'):
        if not _hex32(tree.get(key)):raise ValueError('actual tree identity missing: '+key)
    _equal(tree.get('negative_counts'),{key:1 for key in negatives},'finite actual membership negatives')


def _snapshot_scope(snapshot):
    if type(snapshot) is not dict:raise ValueError('typed source snapshot required')
    _equal(snapshot.get('schema'),'bitvm2-nova-worker-source-snapshot/v1','source snapshot schema')
    _equal(snapshot.get('trusted_configured_library_boundary'),True,'configured execution boundary')
    _equal(snapshot.get('binary_source_equivalence_attested'),False,'binary observation scope')
    files=snapshot.get('files')
    if type(files) is not list or not 0<len(files)<=256:raise ValueError('bounded code-source inventory required')
    names=[];total=0
    for entry in files:
        if type(entry) is not dict or set(entry)!={'path','bytes','sha256'}:raise ValueError('exact code-source file observation required')
        name=entry['path'];size=entry['bytes']
        if (type(name) is not str or not name or '\\' in name or name.startswith('/')
                or '..' in name.split('/') or type(size) is not int or not 0<=size<=2<<20
                or not _hex32(entry['sha256'])):raise ValueError('invalid bounded code-source observation')
        names.append(name);total+=size
    if names!=sorted(set(names)) or total>64<<20:raise ValueError('canonical bounded source list required')
    _equal(snapshot.get('source_snapshot_sha256'),sha256(_canonical(files)).hexdigest(),'canonical code-source hash')
    binary=snapshot.get('worker_executable')
    if (type(binary) is not dict or set(binary)!={'bytes','sha256'} or type(binary['bytes']) is not int
            or not 0<binary['bytes']<=128<<20 or not _hex32(binary['sha256'])):
        raise ValueError('bounded binary observation required')
    return files


def _validate_role_report(report,manifest,info,role,expected_commit):
    if type(report) is not dict:raise ValueError('typed role report required')
    _narrow_scopes(report)
    for key,value in (('schema',REPORT_SCHEMA),('role',role),('tested_commit',expected_commit),
            ('context',CONTEXT.hex()),('operation_id',OPERATION),('policy_sha256',_policy_sha256()),
            ('source_identity_sha256',_source_identity(manifest)),('manifest',info),
            ('cases',3),('full_execution_cases',1),('targeted_execution_cases',2),
            ('private_probe_registries',27),('private_probe_keys_separate',True),('bit_index',0),
            ('components_per_case',11),('leaves_per_complete_forest',150509),('unique_global_words_per_case',155107),
            ('direct_native_worker_executed',True),('external_result_receipt_loaded',False),
            ('sources_unchanged_during_run',True),('inputs_unchanged_during_run',True),
            ('compact_record_budget',_record_budget(role))):
        _equal(report.get(key),value,'role observation '+key)
    if any(key in report for key in ('combined_stream_sha256','combined_compact_execution_records_sha256')):
        raise ValueError('separate role streams have no fabricated combined raw hash')
    _snapshot_scope(report.get('source_snapshot'))
    native=report.get('native')
    census,probes=_manifest_census(manifest,native)
    rows,_=_validate(native,manifest,info,census,probes,role)
    honest=rows[0]
    ledger=dict(name=honest['name'],role=role,source_sha256=honest['source_sha256'],
        component_script_bytes=[part['compiled_script_bytes'] for part in honest['components']],
        complete_forest_script_bytes=honest['forest']['compiled_script_bytes'],
        merkle_root=honest['forest']['merkle_root'],output_key=honest['forest']['output_key'])
    _equal(report.get('honest_forest_ledger'),ledger,'actual complete honest forest ledger')
    wall,rss=report.get('wall_seconds'),report.get('parent_peak_rss_bytes')
    if type(wall) not in (int,float) or not math.isfinite(wall) or not 0<=wall<=1500:
        raise ValueError('role parent wall cap exceeded')
    if type(rss) is not int or not 0<rss<=512<<20:raise ValueError('role parent memory cap exceeded')
    return native


def _aggregate(reports,manifests,infos,expected_commit):
    """Offline consistency/accounting only; no report is a Script admission input."""
    if (type(expected_commit) is not str or len(expected_commit)!=40
            or any(c not in '0123456789abcdef' for c in expected_commit)):
        raise ValueError('one full expected tested commit required')
    if type(reports) is not list or len(reports)!=2 or set(manifests)!=set(ROLES) or set(infos)!=set(ROLES):
        raise ValueError('exact two fixed-role observations and separate input manifests required')
    indexed={}
    for report in reports:
        if type(report) is not dict:raise ValueError('typed role observation required')
        role=report.get('role');_role(role)
        if role in indexed:raise ValueError('duplicate role observation')
        indexed[role]=report
    if set(indexed)!=set(ROLES):raise ValueError('both fixed roles required')
    normal={key:0 for key in METRIC_SUM+METRIC_MAX};all_metrics=dict(normal)
    observations=[];common=None;total=0
    for role in ROLES:
        report=indexed[role];manifest=manifests[role]
        native=_validate_role_report(report,manifest,infos[role],role,expected_commit)
        files=_snapshot_scope(report['source_snapshot'])
        if common is None:common=files
        else:_equal(files,common,'same tested code-source inventory across role jobs')
        _fold(normal,native['normal_metrics']);_fold(all_metrics,native['metrics'])
        total+=native['compact_execution_records_bytes']
        observations.append(dict(role=role,input_manifest_sha256=infos[role]['file_sha256'],
            source_identity_sha256=report['source_identity_sha256'],
            compact_execution_records_bytes=native['compact_execution_records_bytes'],
            compact_execution_records_sha256=native['compact_execution_records_sha256'],
            worker_executable=report['source_snapshot']['worker_executable'],
            honest_forest_ledger=report['honest_forest_ledger']))
    if total>GLOBAL_RECORD_UPPER or total>MAX_RECORD_BYTES:raise ValueError('shared two-role record cap exceeded')
    if all_metrics['vectors']>2*ROLE_CALL_UPPER or all_metrics['expected_rejections']>2*ROLE_REJECTION_UPPER:
        raise ValueError('closed combined call/rejection bound exceeded')
    return dict(schema='bitvm2-nova-grouped-byte-c-bit-point-accounting/v1',passed=True,
        tested_commit=expected_commit,context=CONTEXT.hex(),operation_id=OPERATION,policy_sha256=_policy_sha256(),
        role_observations=observations,code_source_snapshot_sha256=sha256(_canonical(common)).hexdigest(),
        full_execution_cases=2,targeted_execution_cases=4,private_probe_registries=54,
        compact_execution_records_bytes=total,shared_record_hard_cap_bytes=MAX_RECORD_BYTES,
        normal_metrics=normal,metrics=all_metrics,offline_accounting_only=True,
        external_result_receipt_loaded=False,binary_source_equivalence_attested=False,
        proof_verified=False,production_assertion_binding=False,bitcoin_transaction_graph=False,
        scope='two separately executed role observations; stream hashes remain separate; accounting does not authenticate a proof or a production root')


def run(cases_dir,native_worker,role):
    _guard();_role(role);started=time.perf_counter();commit=_tested_commit();budget=_record_budget(role)
    worker=_worker(native_worker);snapshot=_source_snapshot(worker);directory=_new_directory(cases_dir)
    manifest,info,census,probe_census=_generate(directory,role)
    _verify_inputs(directory,manifest,info)
    native=_execute(worker,directory,info['file_sha256'],role)
    rows,_=_validate(native,manifest,info,census,probe_census,role)
    _verify_inputs(directory,manifest,info,executed=True)
    _equal(_source_snapshot(worker),snapshot,'source and executable unchanged throughout direct execution')
    _equal(_tested_commit(),commit,'tested commit unchanged')
    honest=rows[0]
    result=dict(schema=REPORT_SCHEMA,role=role,tested_commit=commit,context=CONTEXT.hex(),operation_id=OPERATION,
        policy_sha256=_policy_sha256(),source_identity_sha256=_source_identity(manifest),native=native,manifest=info,
        source_snapshot=snapshot,compact_record_budget=budget,cases=3,full_execution_cases=1,targeted_execution_cases=2,
        private_probe_registries=27,private_probe_keys_separate=True,direct_native_worker_executed=True,
        external_result_receipt_loaded=False,sources_unchanged_during_run=True,inputs_unchanged_during_run=True,
        bit_index=0,components_per_case=11,leaves_per_complete_forest=150509,unique_global_words_per_case=155107,
        honest_forest_ledger=dict(name=honest['name'],role=role,source_sha256=honest['source_sha256'],
            component_script_bytes=[part['compiled_script_bytes'] for part in honest['components']],
            complete_forest_script_bytes=honest['forest']['compiled_script_bytes'],merkle_root=honest['forest']['merkle_root'],
            output_key=honest['forest']['output_key']),wall_seconds=time.perf_counter()-started,parent_peak_rss_bytes=peak_rss(),
        proof_verified=False,production_assertion_binding=False,bitcoin_transaction_graph=False,
        scope='one role of the fixed grouped challenge-bit conditional-point corpus; private probes use separate keys and roots; origins, full proof and production remain open')
    _validate_role_report(result,manifest,info,role,commit)
    return result


def _aggregate_files(args):
    reports=[];manifests={};infos={}
    for role,report_path,manifest_path in (('pallas_scalar',args.pallas_report,args.pallas_manifest),
            ('vesta_scalar',args.vesta_report,args.vesta_manifest)):
        if report_path is None or manifest_path is None:raise ValueError('both separate role report/manifest pairs required')
        reports.append(_read_json(report_path,MAX_RESULT_BYTES))
        manifests[role]=_read_json(manifest_path,MAX_MANIFEST_BYTES)
        raw=_hash_file(manifest_path,MAX_MANIFEST_BYTES);infos[role]=dict(file_sha256=raw['sha256'],file_bytes=raw['bytes'])
    _equal(_tested_commit(),args.expected_commit,'audit checkout is the expected tested commit')
    result=_aggregate(reports,manifests,infos,args.expected_commit)
    # Independently compare source bytes in this checkout. Generated
    # locks are compared between jobs; their binary equivalence is not attested.
    root=Path(__file__).resolve().parent
    for entry in reports[0]['source_snapshot']['files']:
        if entry['path'].endswith('/Cargo.lock'):continue
        path=root/entry['path']
        if not path.resolve().is_relative_to(root):raise ValueError('audit source leaves integration root')
        _equal(_hash_file(path,2<<20),dict(bytes=entry['bytes'],sha256=entry['sha256']),'audit checkout source '+entry['path'])
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--role',choices=tuple(ROLES));parser.add_argument('--cases-dir',type=Path)
    parser.add_argument('--native-worker',type=Path);parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--aggregate',action='store_true');parser.add_argument('--expected-commit')
    for role in ('pallas','vesta'):
        parser.add_argument('--'+role+'-report',type=Path);parser.add_argument('--'+role+'-manifest',type=Path)
    args=parser.parse_args();_guard()
    from bench_keccak_endpoint import _output_file
    output=_output_file(args.output)
    if args.aggregate:
        if args.role is not None or args.cases_dir is not None or args.native_worker is not None:
            raise ValueError('offline accounting has no worker or source-generation interface')
        result=_aggregate_files(args)
    else:
        if (args.role is None or args.cases_dir is None or args.native_worker is None or args.expected_commit is not None
                or any(getattr(args,key) is not None for key in ('pallas_report','pallas_manifest','vesta_report','vesta_manifest'))):
            raise ValueError('direct execution requires one role, cases directory and configured worker')
        result=run(args.cases_dir,args.native_worker,args.role)
    _write_json(output,result,MAX_RESULT_BYTES);print(json.dumps(result,separators=(',',':'),ensure_ascii=True,allow_nan=False))


if __name__=='__main__':main()
