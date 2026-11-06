"""Hosted challenge-bit to conditional-point fixture conformance.

Two main cases execute every leaf. Other main cases and point probes have
explicit selected Script coverage, while every complete catalogue is measured
and every native predicate is classified. Private probe keys and trees never
become authority for the main forests or for production proof acceptance.
"""
from hashlib import sha256
import argparse
import json
import math
import os
from pathlib import Path
import stat
import sys
import time

from bench_byte_rho import (_execute,_new_directory,_equal,_hex32,MAX_CASE_BYTES,
                            MAX_MAP_BYTES,MAX_MANIFEST_BYTES,MAX_RESULT_BYTES)
from bench_byte_rho_chain import (_fixture,_truth,_check_interfaces,_full_states,
    CONNECTION_COUNTS,OPENING_COUNTS,FOREST_NEGATIVES,LOCAL_NEGATIVES,_depth)
from bench_keccak_endpoint import _write_json
from bench_compact import peak_rss


CONTEXT = sha256(b'BITVM2-NOVA/BYTE-C-BIT-POINT-CONFORMANCE/v1').digest()
OPERATION = 'benchmark/byte-c-bit-point/v1'
SCHEMA = 'bitvm2-nova-byte-c-bit-point-run/v1'
COMPONENT_LEAVES = (29245,29245,453,111,29245,9,29245,29245,245,9,6161)
COMPONENT_WORDS = (29445,29445,587,187,29445,23,29445,29445,379,264,7498)
FULL_COMPONENTS = frozenset((0,1,4,6,7))
MAX_RECORD_BYTES = 128 << 20
OLD_IDENTIFIER_BYTES, NEW_IDENTIFIER_BYTES = 64,32
MAX_SELECTED_POINT_LEAVES = 128
MAX_SELECTED_NEGATIVE_LEAVES = 12
BRANCHES=('rho-hi','rho-lo','rho-tail','c-coeff-frame','c-prefix','c-absorb','c-hi','c-lo','c-uniform','scalar-bits','conditional-point')


def _guard():
    if (os.environ.get('GITHUB_ACTIONS') != 'true'
            or os.environ.get('RUNNER_OS') != 'Linux' or sys.platform != 'linux'):
        raise ValueError('BYTE challenge-bit point conformance is hosted GitHub Linux only')


def _requests():
    for prefix,scalar,base,counter in (('p','pallas_scalar','pallas_base',59),
                                      ('v','vesta_scalar','vesta_base',44)):
        yield prefix+'/h',scalar,base,counter,'honest'
        yield prefix+'/b',scalar,base,counter,'coherent-bit'
        yield prefix+'/a',scalar,base,counter,'coherent-scalar-alias'


def _probe_requests():
    old = ('coefficient-c0-modulus','coefficient-c2-modulus','frame-counter','frame-NoDS',
           'frame-tag','frame-zero-capacity','absorb-wrong-xor','absorb-selector','absorb-delimiter','absorb-end-mask')
    negative = ('invalid-P-b0','wrong-E-b0','wrong-selected-R','wrong-R-flag','nonzero-infinity',
                'auxiliary-flip','signed-bit-two','coordinate-modulus','coordinate-modulus-plus-one')
    for prefix,scalar,base in (('p','pallas_scalar','pallas_base'),('v','vesta_scalar','vesta_base')):
        for i,kind in enumerate(old):
            yield dict(name=f'{prefix}/q{i}',role=scalar,field_role=scalar,kind=kind,
                       category='chain',leaves=111 if i<6 else 9,guard_bound=24 if i<6 else 4)
        for i,bit in enumerate((0,1,0,1,0,1)):
            yield dict(name=f'{prefix}/e{i}',role=scalar,field_role=base,kind=f'point-edge-{i}',
                       category='point-edge',bit=bit,leaves=6161,guard_bound=107)
        yield dict(name=f'{prefix}/s',role=scalar,field_role=scalar,kind='scalar-plus-modulus',
                   category='scalar-alias',leaves=254,guard_bound=63)
        for i,kind in enumerate(negative):
            yield dict(name=f'{prefix}/n{i}',role=scalar,field_role=base,kind=kind,
                       category='point-negative',leaves=6161,guard_bound=12)


def _canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('utf-8')


def _record_budget():
    """Closed byte bound; no graph, signing or Script execution is performed."""
    def size(name,index,mode,expected):
        return len(_canonical(dict(c=name,i=index,m=mode,e=expected,s='0'*64,w='0'*64)))+1

    def all_bytes(name,component,count):
        digits=1+sum(max(0,min(count,10**width)-10**(width-1))*width
                     for width in range(1,len(str(count-1))+1))
        return count*(size(name,[component,0],False,True)+size(name,[component,0],True,False))+2*(digits-count)

    normal=guards=trees=target=0
    for name,_,_,_,profile in _requests():
        for component,count in enumerate(COMPONENT_LEAVES):
            if component in FULL_COMPONENTS or component==10:
                if profile=='honest': normal+=all_bytes(name,component,count)
            else: normal+=all_bytes(name,component,count)
        old=max(size(name,'g'*64,False,False),size(name,'g'*64,True,False))
        new=max(size(name,'g'*32,False,False),size(name,'g'*32,True,False))
        # Five unchanged full permutations115, rho-tail61, uniform<=61,
        # coefficient frame<=111 and absorption<=9 remain the old357 bound.
        guards+=14*357*old+14*(2+107)*new
        trees+=2*new
        if profile!='honest':
            # Keep the larger old-sized allowance for selected normal records;
            # the32B saving applies only to NEW guard/tree string identifiers.
            target+=2*MAX_SELECTED_POINT_LEAVES*old
    probe_normal=probe_guards=probe_trees=0
    for probe in _probe_requests():
        name=probe['name']; old=probe['category']=='chain'
        identifier=OLD_IDENTIFIER_BYTES if old else NEW_IDENTIFIER_BYTES
        maximum=max(size(name,'g'*identifier,False,False),size(name,'g'*identifier,True,False))
        if probe['category'] in ('chain','scalar-alias'):
            probe_normal+=sum(size(name,i,False,True)+size(name,i,True,False) for i in range(probe['leaves']))
        else:
            selected=MAX_SELECTED_POINT_LEAVES if probe['category']=='point-edge' else MAX_SELECTED_NEGATIVE_LEAVES
            probe_normal+=2*selected*max(size(name,6160,False,False),size(name,6160,True,False))
        probe_guards+=14*probe['guard_bound']*maximum
        probe_trees+=2*maximum
    total=normal+guards+trees+target+probe_normal+probe_guards+probe_trees
    result=dict(main_normal_bytes=normal,main_guard_upper_bytes=guards,main_tree_upper_bytes=trees,
        targeted_point_upper_bytes=target,probe_normal_upper_bytes=probe_normal,
        probe_guard_upper_bytes=probe_guards,probe_tree_upper_bytes=probe_trees,
        combined_upper_bytes=total,hard_cap_bytes=MAX_RECORD_BYTES,
        old_identifier_bytes=64,new_identifier_bytes=32,point_shape_bound=107,bridge_shape_bound=2,
        main_cases=6,private_probes=52,main_full_cases=2,main_targeted_cases=4)
    if total>MAX_RECORD_BYTES:
        raise ValueError('conditional-point closed corpus exceeds unchanged128MiB cap')
    return result


def _digest(value):
    result=value.hex() if type(value) is bytes else value
    if not _hex32(result): raise ValueError('canonical source SHA required')
    return result


def _point(value):
    from curve_trace import EncodedPoint
    point=EncodedPoint.of(value)
    return dict(infinity=point.infinity,x_le=point.x.to_bytes(32,'little').hex(),y_le=point.y.to_bytes(32,'little').hex())


def _curve(role):
    from ipa_algebra import PALLAS,VESTA
    return PALLAS if role.startswith('pallas') else VESTA


def _points(role):
    curve=_curve(role); g=(curve.p-1,2); h=curve.mul(g,2)
    return curve,g,h


def _classify(spec,values,program):
    false=[]; abort=[]
    for i in range(len(spec.leaves)):
        # All closed inputs use existing bounded raw constraint semantics.
        # Decoder out-of-range flags are ordinary false, not bare VERIFY.
        result=_leaf_truth(spec,values,i,program)
        if result is None: abort.append(i)
        elif type(result) is not bool: raise ValueError('tri-state predicate classification required')
        elif not result: false.append(i)
    return false,abort


def _leaf_truth(spec,values,ordinal,program):
    """Raw predicate semantics with Registry flags preceding bare-kernel domains.

    `None` is an actual canonical-input VERIFY abort, never Boolean false.
    The frozen byte/Uniform helpers remain unchanged.
    """
    leaf=spec.leaves[ordinal]
    operands=[]
    for slot in leaf.wires:
        word,bound=spec.words[slot];value=values[word]
        if type(value) is not int or not 0<=value<bound: return False
        operands.append(value)
    if leaf.kind=='bits' and leaf.argument in ((29,),(23,)):
        width=leaf.argument[0]
        if len(operands)!=width+1 or any(bit not in (0,1) for bit in operands[1:]):
            raise ValueError('closed scalar bits arity/domain differs')
        return operands[0]==sum(bit<<(width-1-i) for i,bit in enumerate(operands[1:]))
    if leaf.kind=='add':
        if len(operands)!=27 or program is None: raise ValueError('closed raw add shape required')
        integer=lambda row:sum(value<<(29*i) for i,value in enumerate(row))
        x,y,z=integer(operands[:9]),integer(operands[9:18]),integer(operands[18:27])
        if x>=program.p or y>=program.p: return None
        return (x+y)%program.p==z
    if leaf.kind=='field_valid':
        if len(operands)!=9 or program is None: raise ValueError('closed canonical-field shape required')
        return sum(value<<(29*i) for i,value in enumerate(operands))<program.p
    return _truth(spec,values,ordinal,program)


def _shapes(spec,ordinals=None):
    from wots_graph import authenticated_shape
    chosen=range(len(spec.leaves)) if ordinals is None else ordinals
    return len({authenticated_shape(spec,spec.leaves[i]) for i in chosen})


def _point_selection(spec,false,abort):
    from wots_graph import authenticated_shape
    selected=set(range(6116,6124))|{6159,6160}|set(false)
    shapes=set()
    for i,leaf in enumerate(spec.leaves):
        shape=authenticated_shape(spec,leaf)
        if shape not in shapes: selected.add(i); shapes.add(shape)
    if len(shapes)>107 or len(selected)>128 or selected&set(abort):
        raise ValueError('point selected coverage exceeds the closed shape/leaf budget or includes an abort')
    return sorted(selected)


def _case(name,spec,values,program,ordinals):
    if set(values)!={word for word,_ in spec.words} or any(type(v) is not int or not 0<=v<=0xffffffff for v in values.values()):
        raise ValueError('complete signed-u32 assertion required')
    false,abort=_classify(spec,values,program)
    if set(ordinals)&set(abort): raise ValueError('checked predicate abort is not a disproof')
    return dict(name=name,spec=spec.json(),expected_spec_id=spec.digest().hex(),
        words=[values[word] for word,_ in spec.words],measure_all=True,
        checks=[dict(ordinal=i,expected_correct=i not in false) for i in ordinals]),false,abort


def _worker(path):
    _guard(); source=Path(path)
    if source.is_symlink(): raise ValueError('owned regular byte_c_bit_point worker required')
    target=source.resolve(); entry=target.lstat()
    if not stat.S_ISREG(entry.st_mode) or entry.st_uid!=os.getuid() or target.name!='byte_c_bit_point' or not os.access(target,os.X_OK):
        raise ValueError('trusted configured owned byte_c_bit_point worker required')
    return target


def _files(directory,stem,name,record,values,ordinals,binding=None):
    spec,program=record.spec,record.program
    descriptor=record.descriptor.json()
    case,false,abort=_case(name,spec,values,program,ordinals)
    filename,maps_name,source_name=f'case-{stem}.json',f'maps-{stem}.json',f'source-{stem}.json'
    info=_write_json(directory/filename,case,MAX_CASE_BYTES)
    maps,source,manifest=record.child_source_maps,record.child_source_manifest,record.child_program_manifest
    mi=_write_json(directory/maps_name,maps,MAX_MAP_BYTES); si=_write_json(directory/source_name,source,MAX_MANIFEST_BYTES)
    program_name=f'program-{stem}.json' if manifest is not None else None
    pi=_write_json(directory/program_name,manifest,MAX_MANIFEST_BYTES) if manifest is not None else None
    if mi['file_sha256']!=descriptor['source_maps_sha256'] or sha256(_canonical(list(record.global_ids))).hexdigest()!=descriptor['global_ids_sha256']:
        raise ValueError('fresh component sidecars changed sealed identities')
    full=None
    if record.index in FULL_COMPONENTS:
        initial,output=_full_states(binding.chain,record.index)
        profile=('coherent-scalar-alias' if binding.uniform_alias else
                 'coherent-bit' if binding.claimed_bit is not None else 'honest')
        full=dict(name=name,profile=profile,role=spec.field_role,filename=filename,**info,
            catalogue_id=spec.digest().hex(),program_sha256=spec.program_sha256,
            source_sha256=descriptor['source_sha256'],global_ids_sha256=maps['global_ids_sha256'],
            words=len(spec.words),leaves=len(spec.leaves),input_state_hex=initial.hex(),expected_output_state_hex=output.hex(),
            expected_false=false,state_index=None,byte_slot=None,maps_filename=maps_name,
            maps_file_sha256=mi['file_sha256'],maps_file_bytes=mi['file_bytes'],source_maps_sha256=descriptor['source_maps_sha256'],
            program_manifest_filename=program_name,program_manifest_file_sha256=pi['file_sha256'],program_manifest_file_bytes=pi['file_bytes'],
            source_manifest_filename=source_name,source_manifest_file_sha256=si['file_sha256'],source_manifest_file_bytes=si['file_bytes'],blocks=manifest['blocks'])
    mode='all' if len(ordinals)==len(spec.leaves) else 'selected' if ordinals else 'none'
    header=dict(descriptor=descriptor,filename=filename,**info,maps_filename=maps_name,
        maps_file_sha256=mi['file_sha256'],maps_file_bytes=mi['file_bytes'],
        program_manifest_filename=program_name,program_manifest_file_sha256=None if pi is None else pi['file_sha256'],
        program_manifest_file_bytes=None if pi is None else pi['file_bytes'],source_manifest_filename=source_name,
        source_manifest_file_sha256=si['file_sha256'],source_manifest_file_bytes=si['file_bytes'],
        execution_mode=mode,selected_ordinals=None if mode!='selected' else ordinals,
        expected_false=false,expected_abort_ordinals=abort,full=full)
    return header,dict(selected_leaf_checks=len(ordinals),guard_layouts=_shapes(spec),words=len(spec.words),leaves=len(spec.leaves))


def _one(index,request,directory):
    _guard()
    from byte_c_bit_point import build_byte_c_bit_point,_bind_uniform_alias,SOURCE_DOMAIN
    name,role,base,counter,profile=request
    eval_w,prior,coefficients,fixture=_fixture(role)
    curve,A,P=_points(base)
    plan=build_byte_c_bit_point(context=CONTEXT,role=role,rho_counter=counter,bit_index=0,operation_id=OPERATION)
    binding=plan.bind(eval_w,prior,coefficients,A,P)
    if binding.chain.raw_c.hex()!=fixture['honest_c_raw_state_le'] or binding.canonical_bit!=(1 if role=='pallas_scalar' else 0):
        raise ValueError('fixed retained canonical challenge/bit differs')
    if profile=='coherent-bit': binding=plan.bind(eval_w,prior,coefficients,A,P,claimed_bit=1-binding.canonical_bit)
    elif profile=='coherent-scalar-alias': binding=_bind_uniform_alias(plan,eval_w,prior,coefficients,A,P)
    maps,source=plan.source_maps,plan.manifest
    outer_m,outer_s=f'point-maps-{index:02d}.json',f'point-source-{index:02d}.json'
    om=_write_json(directory/outer_m,maps,MAX_MAP_BYTES); osource=_write_json(directory/outer_s,source,MAX_MANIFEST_BYTES)
    cm_name,cs_name=f'chain-maps-{index:02d}.json',f'chain-source-{index:02d}.json'
    chain_maps,chain_source=plan.chain.source_maps,plan.chain.manifest
    cm=_write_json(directory/cm_name,chain_maps,MAX_MAP_BYTES); cs=_write_json(directory/cs_name,chain_source,MAX_MANIFEST_BYTES)
    if om['file_sha256']!=plan.source_maps_sha256.hex() or sha256(SOURCE_DOMAIN+_canonical(source)).digest()!=plan.source_sha256:
        raise ValueError('outer source snapshot changed sealed identity')
    headers,census,seen=[],[],{}
    for record in binding.iter_components():
        i=record.index; spec,values,ids,program=record.spec,record.assignment,record.global_ids,record.program
        if (record.branch!=BRANCHES[i] or (len(spec.words),len(spec.leaves))!=(COMPONENT_WORDS[i],COMPONENT_LEAVES[i])
                or spec.field_role!=(base if i==10 else role)):
            raise ValueError('fixed mixed-role component identity/census differs')
        if i<9: _check_interfaces(record,chain_maps['components'][i])
        for global_id,(word,bound) in zip(ids,spec.words,strict=True):
            assertion=bound,values[word]
            if global_id in seen and seen[global_id]!=assertion: raise ValueError('one global assertion changed value/bound')
            seen[global_id]=assertion
        false,abort=_classify(spec,values,program)
        expected=[0] if profile=='coherent-bit' and i==9 else [244] if profile=='coherent-scalar-alias' and i==8 else []
        _equal(false,expected,'exact main diagnostic false predicates')
        if abort: raise ValueError('main fixture contains unexpected predicate abort')
        chosen=(list(range(len(spec.leaves))) if profile=='honest' or i not in FULL_COMPONENTS and i!=10 else
                _point_selection(spec,false,abort) if i==10 else [])
        header,count=_files(directory,f'{index:02d}-{i}',name+'/'+record.branch,record,values,chosen,binding)
        maximum=23 if i in FULL_COMPONENTS else 61 if i in (2,8) else 2 if i==9 else 107 if i==10 else COMPONENT_LEAVES[i]
        if count['guard_layouts']>maximum: raise ValueError('component shapes exceed preflighted budget')
        headers.append(header);census.append(count)
        del record,spec,values,ids,program
    if len(headers)!=11 or len(seen)!=155107: raise ValueError('complete mixed-role assertion inventory required')
    if profile!='honest' and sum(census[i]['selected_leaf_checks'] for i in FULL_COMPONENTS|{10})>128:
        raise ValueError('all selected full/point normal leaves must share one128-leaf target reserve')
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
        selected_bit=binding.selected_bit,canonical_bit=binding.canonical_bit,point_A=_point(binding.A),point_P=_point(binding.P),
        expected_E=_point(binding.E),expected_R=_point(binding.R),components=headers,
        point_source_filename=outer_s,point_source_file_sha256=osource['file_sha256'],point_source_file_bytes=osource['file_bytes'],
        point_maps_filename=outer_m,point_maps_file_sha256=om['file_sha256'],point_maps_file_bytes=om['file_bytes'],
        chain_source_filename=cs_name,chain_source_file_sha256=cs['file_sha256'],chain_source_file_bytes=cs['file_bytes'],
        chain_maps_filename=cm_name,chain_maps_file_sha256=cm['file_sha256'],chain_maps_file_bytes=cm['file_bytes'])
    del binding,plan,maps,source,chain_maps,chain_source,seen,ch
    return group,census


def _asserted_point(values,ports,label):
    from curve_trace import EncodedPoint
    return EncodedPoint(values[ports[label+'_infinity']],
        sum(values[word]<<(29*i) for i,word in enumerate(ports[label+'_x'])),
        sum(values[word]<<(29*i) for i,word in enumerate(ports[label+'_y'])))


def _point_probe(probe,honest):
    _guard()
    from conditional_point import build_conditional_point
    from curve_trace import AUTO
    from script import limbs
    curve,G,H=_points(probe['field_role'])
    plan=build_conditional_point(context=CONTEXT,role=probe['field_role'],bit_index=0,
        operation_id=honest['components'][10]['descriptor']['operation_id'])
    A,P,bit=G,H,honest['canonical_bit']; Eclaim=Rclaim=AUTO
    kind=probe['kind']
    if probe['category']=='point-edge':
        edge=int(kind.rsplit('-',1)[1])
        A,P=((None,None),(None,G),(G,None),(G,(G[0],-G[1]%curve.p)),(G,G),(G,H))[edge]
        bit=probe['bit']
    elif kind=='invalid-P-b0': A,P,bit,Eclaim=G,(1,1),0,H
    elif kind=='wrong-E-b0': bit,Eclaim=0,G
    elif kind=='wrong-selected-R': Rclaim=curve.add(G,H) if bit==0 else G
    elif kind=='nonzero-infinity': A,P,bit=G,(G[0],-G[1]%curve.p),1
    elif kind in ('auxiliary-flip','signed-bit-two'): bit=0
    bound=plan.bind(A,P,bit,claimed_E=Eclaim,claimed_R=Rclaim)
    values=bound.assignment; ports=plan.ports
    if kind=='wrong-R-flag': values[ports['R_infinity']]=2
    elif kind=='nonzero-infinity': values[ports['R_x'][0]]=1
    elif kind=='auxiliary-flip': values[ports['infinity_delta']]^=1
    elif kind=='signed-bit-two': values[ports['bit']]=2
    elif kind in ('coordinate-modulus','coordinate-modulus-plus-one'):
        for word,value in zip(ports['R_x'],limbs(curve.p+int(kind.endswith('plus-one'))),strict=True): values[word]=value
    false,abort=_classify(bound.spec,values,bound.program)
    if probe['category']=='point-edge':
        if false or abort: raise ValueError('honest point edge contains a false/abort predicate')
        selected=_point_selection(bound.spec,false,abort); chosen=6123
    else:
        if kind=='invalid-P-b0':
            fields=dict(bound.program.fields)
            selected=[i for i,c in enumerate(bound.program.constraints) if c.kind=='gate_equal'
                and c.argument==(0,) and c.wires[1:10]==fields['right/y2'] and c.wires[10:]==fields['right/curve-rhs']]
        elif kind=='wrong-E-b0': selected=[next(i for i in false if i<6116)]
        elif kind=='wrong-selected-R': selected=[6119 if bit==0 else 6121]
        else: selected={'wrong-R-flag':[6118,6123],'nonzero-infinity':[6121,6123],
            'auxiliary-flip':[6116],'signed-bit-two':[6117,6119,6120,6121,6122],
            'coordinate-modulus':[6159],'coordinate-modulus-plus-one':[6159]}[kind]
        if not selected or len(selected)>12 or set(selected)-set(false) or set(selected)&set(abort):
            raise ValueError('closed selected point negative is not an ordinary bounded counterexample')
        chosen=selected[0]
    inputs=dict(bit=values[ports['bit']],point_A=_point(_asserted_point(values,ports,'A')),
        point_P=_point(_asserted_point(values,ports,'P')),point_E=_point(_asserted_point(values,ports,'E')),
        point_R=_point(_asserted_point(values,ports,'R')))
    return plan,bound.program,bound.spec,values,selected,chosen,inputs


def _probe(index,probe,honest,directory):
    _guard()
    from byte_sumcheck_frame import build_sumcheck_frame,_bind_modulus_fault,_bind_frame_fault
    from byte_sumcheck_absorb import build_sumcheck_absorb
    from uniform_alias import build_scalar_alias
    name,role,kind=probe['name'],probe['role'],probe['kind']
    eval_w,prior,coefficients,fixture=_fixture(role)
    category=probe['category']; inputs={}
    if category=='chain':
        component=3 if probe['leaves']==111 else 5
        descriptor=honest['components'][component]['descriptor']; op=descriptor['operation_id']
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
            prefix=bytes.fromhex(honest['expected_prefix_output_state_hex']); raw=bytes.fromhex(honest['expected_rho_raw_state_le'])
            base=source.bind(prefix,raw); output={'absorb-wrong-xor':0,'absorb-selector':8,'absorb-delimiter':6,'absorb-end-mask':7}[kind]
            claims=[None]*9;claims[output]=base.outputs[output]^1
            bound=source.bind(prefix,raw,claimed_outputs=tuple(claims))
            program,spec,values=source.program,source.spec,bound.assignment
        selected=list(range(len(spec.leaves)))
        false,abort=_classify(spec,values,program)
        chosen={'coefficient-c0-modulus':109,'coefficient-c2-modulus':110,'frame-counter':37,'frame-NoDS':33,
            'frame-tag':32,'frame-zero-capacity':45,'absorb-wrong-xor':0,'absorb-selector':8,'absorb-delimiter':6,'absorb-end-mask':7}[kind]
        _equal(false,[chosen],'closed old small counterexample')
    elif category=='scalar-alias':
        component=None
        raw=bytes.fromhex(honest['expected_c_raw_state_le'])
        source=build_scalar_alias(raw,context=CONTEXT,role=role,bit_index=0,operation_id=OPERATION+'/probe/scalar-alias/'+name[0])
        program,spec,values=source.program,source.spec,source.assignment
        selected=list(range(254));chosen=253;inputs=dict(raw_c_le=raw.hex())
        false,abort=_classify(spec,values,program)
        _equal(false,[253],'merged scalar alias canonical guard')
    else:
        component=10
        source,program,spec,values,selected,chosen,inputs=_point_probe(probe,honest)
        false,abort=_classify(spec,values,program)
    if set(selected)&set(abort): raise ValueError('selected probe abort cannot count as disproof')
    case,reported_false,reported_abort=_case(name,spec,values,program,selected)
    _equal(reported_false,false,'complete probe native false classification')
    _equal(reported_abort,abort,'complete probe abort classification')
    filename=f'probe-{index:02d}.json';info=_write_json(directory/filename,case,MAX_CASE_BYTES)
    source_sha=_digest(source.source_sha256); maps_sha=_digest(source.source_maps_sha256)
    if component is not None:
        expected=honest['components'][component]['descriptor']
        if (source_sha!=expected['source_sha256'] or maps_sha!=expected['source_maps_sha256']
                or spec.digest().hex()!=expected['catalogue_id'] or spec.program_sha256!=expected['program_sha256']):
            raise ValueError('fresh private probe changed its positive source topology')
    guarded=_shapes(spec,selected if category=='point-negative' else None)
    if guarded>probe['guard_bound'] or len(selected)>(12 if category=='point-negative' else 128 if category=='point-edge' else probe['leaves']):
        raise ValueError('private probe exceeds closed selected/guard budget')
    header=dict(name=name,kind=kind,category=category,role=role,field_role=probe['field_role'],source_case=honest['name'],
        source_component=component,operation_id=program.operation_id,filename=filename,**info,
        source_sha256=source_sha,source_maps_sha256=maps_sha,catalogue_id=spec.digest().hex(),program_sha256=spec.program_sha256,
        words=len(spec.words),leaves=len(spec.leaves),execution_mode='all' if len(selected)==len(spec.leaves) else 'selected',
        selected_ordinals=None if len(selected)==len(spec.leaves) else selected,expected_false=false,
        expected_abort_ordinals=abort,selected_leaf=chosen,expected_selected_correct=chosen not in false,inputs=inputs)
    return header,dict(selected_leaf_checks=len(selected),guard_layouts=guarded,words=len(spec.words),leaves=len(spec.leaves))


def _generate(directory):
    _guard();_record_budget()
    cases,census,honest=[],[],{}
    for i,request in enumerate(_requests()):
        row,count=_one(i,request,directory);cases.append(row);census.append(count)
        if request[-1]=='honest': honest[request[1]]=row
    probes,probe_census=[],[]
    for i,request in enumerate(_probe_requests()):
        row,count=_probe(i,request,honest[request['role']],directory);probes.append(row);probe_census.append(count)
    manifest=dict(schema=SCHEMA,context=CONTEXT.hex(),operation_id=OPERATION,cases=cases,probes=probes)
    info=_write_json(directory/'manifest.json',manifest,MAX_MANIFEST_BYTES)
    return manifest,info,census,probe_census


def _hash_file(path,cap):
    path=Path(path)
    if path.is_symlink() or not path.is_file(): raise ValueError('regular source/binary snapshot required')
    digest=sha256();total=0
    with path.open('rb') as stream:
        while True:
            part=stream.read(1<<20)
            if not part: break
            total+=len(part)
            if total>cap: raise ValueError('source/binary snapshot exceeds explicit cap')
            digest.update(part)
    return dict(bytes=total,sha256=digest.hexdigest())


def _source_snapshot(worker):
    _guard();root=Path(__file__).resolve().parent
    paths=list(root.glob('*.py'))
    for crate in ('rust-oracle','point-oracle'):
        paths.extend((root/crate/'src').rglob('*.rs'))
        for filename in ('Cargo.toml','Cargo.lock'):
            path=root/crate/filename
            if not path.is_file(): raise ValueError('both configured crates require manifest/lock snapshots')
            paths.append(path)
    for filename in ('requirements.txt','transcript-requirements.txt'):
        if (root/filename).is_file(): paths.append(root/filename)
    if len(paths)>256 or not (root/'point-oracle'/'src'/'main.rs').is_file():
        raise ValueError('bounded complete configured-worker source snapshot required')
    files=[];total=0
    for path in sorted(paths):
        if path.is_symlink() or not path.resolve().is_relative_to(root): raise ValueError('source snapshot leaves integration root')
        info=_hash_file(path,2<<20);total+=info['bytes']
        if total>64<<20: raise ValueError('source snapshot total cap exceeded')
        files.append(dict(path=path.relative_to(root).as_posix(),**info))
    binary=_hash_file(worker,128<<20)
    return dict(schema='bitvm2-nova-worker-source-snapshot/v1',files=files,
        source_snapshot_sha256=sha256(_canonical(files)).hexdigest(),worker_executable=binary,
        trusted_configured_library_boundary=True,binary_source_equivalence_attested=False)


def _selection_guard_bound(header,count):
    if count['selected_leaf_checks']>header['leaves']: raise ValueError('selected count exceeds complete catalogue')
    if header['category']=='point-negative' and count['guard_layouts']>12: raise ValueError('negative guards exceed selected-only scope')
    return count['guard_layouts']


def _cost(row,largest):
    for key in ('registry_id','compiled_stream_sha256'):
        if not _hex32(row.get(key)): raise ValueError('actual registry/Script stream identity required')
    size,maximum=row.get('compiled_script_bytes'),row.get('largest_disproof_leaf_bytes')
    if type(size) is not int or not 0<size<=256<<20 or type(maximum) is not int or not 0<maximum<=min(size,100000):
        raise ValueError('Script accounting exceeds unchanged engine/component caps')
    return size,max(largest,maximum)


def _tree(tree,ledger,count,ordinal,component=None):
    if type(tree) is not dict: raise ValueError('actual fresh Taproot membership required')
    local_count=count if component is None else COMPONENT_LEAVES[component]
    control=33+32*(_depth(local_count,ordinal)+(0 if component is None else _depth(11,component)))
    for key,value in (('leaf_count',count),('compiled_script_bytes',ledger['compiled_script_bytes']),('control_block_bytes',control)):
        _equal(tree.get(key),value,'tree '+key)
    if component is None:
        _equal(tree.get('compiled_stream_sha256'),ledger['compiled_stream_sha256'],'local tree complete stream')
        if tree.get('membership_verified') is not True: raise ValueError('actual local probe membership missing')
        negative=LOCAL_NEGATIVES
    else:
        for key,value in (('components',11),('selected_component',component),('selected_leaf',ordinal)):
            _equal(tree.get(key),value,'forest '+key)
        if tree.get('hierarchical_membership_verified') is not True or not _hex32(tree.get('component_manifest_sha256')):
            raise ValueError('actual ordered eleven-component forest missing')
        negative=FOREST_NEGATIVES
    if tree.get('roots_independently_pinned') is not False: raise ValueError('live test roots cannot become production authority')
    for key in ('merkle_root','output_key','control_block_sha256','selected_script_sha256','compiled_stream_sha256'):
        if not _hex32(tree.get(key)): raise ValueError('actual tree identity missing: '+key)
    _equal(tree.get('negative_counts'),{key:1 for key in negative},'exact membership negative inventory')


TRUE_FLAGS=('challenge_bit_point_script_conformance_checked','all_native_reference_predicates_checked',
    'boundary_opening_links_checked','scalar_bits_reconstructed','selected_bit_point_linked',
    'complete_addition_active_when_bit_zero','point_edge_cases_checked','private_probe_keys_separate',
    'private_probe_selected_scope_checked','test_keys_only','stack_limit_enabled','hierarchical_membership_verified')
FALSE_FLAGS=('all_cases_full_statement_executed','raw_vector_file_written','op_cat_enabled','full_permutation_verified',
    'full_hash_verified','transcript_verified','nova_transcript_verified_in_script','proof_verified','complete_nova_verifier',
    'complete_bitvm2_verifier','production_assertion_binding','bitcoin_transaction_graph','panic_is_rejection',
    'eval_w_canonicality_script_bound','dynamic_message_sources_script_bound','eval_w_proof_origin_bound',
    'prior_state_transcript_bound','complete_keccak_sponge','coefficient_proof_origins_bound',
    'spartan_sumcheck_equations_verified','external_raw_state_input_loaded','scalar_multiplication_verified','ipa_verified',
    'A_proof_origin_bound','P_key_origin_bound','all_negative_probe_leaves_executed')


def _validate(native,manifest,info,census,probe_census):
    if type(native) is not dict or native.get('passed') is not True: raise ValueError('successful directly executed worker result required')
    _equal(native.get('schema'),'bitvm2-nova-byte-c-bit-point-execution/v1','schema')
    _equal(native.get('input_manifest_sha256'),info['file_sha256'],'fresh manifest identity')
    for flag in TRUE_FLAGS:
        if native.get(flag) is not True: raise ValueError('required conditional-point conformance missing: '+flag)
    for flag in FALSE_FLAGS:
        if native.get(flag) is not False: raise ValueError('conditional-point scope exceeded: '+flag)
    for key in ('setup_calls','proving_jobs','native_proofs_verified','gpu_jobs','transactions_broadcast'):
        _equal(native.get(key),0,key)
    size=native.get('compact_execution_records_bytes');budget=_record_budget()
    if type(size) is not int or not 0<size<=budget['combined_upper_bytes'] or not _hex32(native.get('compact_execution_records_sha256')):
        raise ValueError('actual compact stream exceeds closed unchanged budget')
    rows,probes=native.get('cases'),native.get('probes')
    if type(rows) is not list or len(rows)!=6 or type(probes) is not list or len(probes)!=52 or len(census)!=6 or len(probe_census)!=52:
        raise ValueError('complete six-main/fifty-two-probe result required')
    normal=guards=largest=0
    for row,source,counts in zip(rows,manifest['cases'],census,strict=True):
        if type(row) is not dict or len(counts)!=11: raise ValueError('typed complete main observation required')
        for key in ('name','profile','role','base_role','rho_counter','c_counter','bit_index','execution_mode',
                    'source_sha256','source_maps_sha256','chain_source_sha256','chain_source_maps_sha256',
                    'asserted_scalar_le','asserted_scalar_quotient_le','selected_bit','canonical_bit','point_A','point_P'):
            _equal(row.get(key),source[key],key)
        for key in source:
            if key.startswith('expected_'): _equal(row.get(key),source[key],key)
        honest=source['profile']=='honest'
        _equal(row.get('full_statement_executed'),honest,'actual full execution scope')
        for key,value in (('signature_entries_created',155107),('local_declared_words',156163),('cached_signature_reuses',1056),
                ('all_native_predicates_classified',153213),('scalar_limb_opening_links',9),
                ('scalar_canonical_opening_links',9),('selected_bit_opening_links',5),
                ('canonical_internal_opening_links',46),('internal_cached_boundary_entries',23000),
                ('internal_producer_consumer_opening_links',46000),('native_rejections',264),
                ('map_rejections',22),('source_rejections',30),('cache_rejections',108)):
            _equal(row.get(key),value,key)
        _equal(row.get('connections'),[dict(kind=kind,logical_links=logical,opening_links=OPENING_COUNTS[kind])
            for kind,logical in CONNECTION_COUNTS.items()],'all eleven exact cross-component opening groups')
        parts=row.get('components')
        if type(parts) is not list or len(parts)!=11: raise ValueError('all eleven measured component ledgers required')
        compiled=0;selected_count=0;layout_count=0
        for part,header,count in zip(parts,source['components'],counts,strict=True):
            if type(part) is not dict: raise ValueError('typed component ledger required')
            for key,value in header['descriptor'].items(): _equal(part.get(key),value,'component '+key)
            for key,value in (('context',manifest['context']),('execution_mode',header['execution_mode']),
                    ('selected_ordinals',header['selected_ordinals']),('executed_leaves',count['selected_leaf_checks']),
                    ('false_predicates',header['expected_false']),('abort_predicates',header['expected_abort_ordinals']),
                    ('guard_layouts',count['guard_layouts']),('guard_vectors',14*count['guard_layouts'])):
                _equal(part.get(key),value,'component '+key)
            byte_count,largest=_cost(part,largest);compiled+=byte_count
            selected_count+=count['selected_leaf_checks'];layout_count+=count['guard_layouts']
        if compiled>5<<28: raise ValueError('whole forest exceeds unchanged1.25GiB cap')
        for key,value in (('selected_leaf_checks',selected_count),('guard_layouts',layout_count),('guard_vectors',14*layout_count),
                          ('additional_selected_engine_executions',2)):
            _equal(row.get(key),value,key)
        selected_component=10 if honest else 9 if source['profile']=='coherent-bit' else 8
        selected_leaf=6160 if honest else 0 if source['profile']=='coherent-bit' else 244
        _equal(row.get('selected_component'),selected_component,'selected component')
        _equal(row.get('selected_leaf'),selected_leaf,'selected leaf')
        if row.get('selected_correctness_execution_success') is not honest or row.get('selected_disproof_execution_success') is not (not honest):
            raise ValueError('selected main result mismatch')
        _tree(row.get('forest'),dict(compiled_script_bytes=compiled),153213,selected_leaf,selected_component)
        normal+=selected_count;guards+=14*layout_count
    for row,source,count in zip(probes,manifest['probes'],probe_census,strict=True):
        if type(row) is not dict: raise ValueError('typed separate probe result required')
        for key in ('name','kind','category','role','field_role','source_case','source_component','operation_id',
                    'source_sha256','source_maps_sha256','program_sha256','catalogue_id','words','leaves',
                    'execution_mode','selected_ordinals','selected_leaf','expected_selected_correct','inputs'):
            _equal(row.get(key),source[key],'probe '+key)
        for key,value in (('context',manifest['context']),('executed_leaves',count['selected_leaf_checks']),
                ('false_predicates',source['expected_false']),('abort_predicates',source['expected_abort_ordinals']),
                ('signature_entries_created',source['words']),('guard_layouts',count['guard_layouts']),
                ('guard_vectors',14*count['guard_layouts']),('native_rejections',24),
                ('additional_selected_engine_executions',2)):
            _equal(row.get(key),value,'probe '+key)
        expected=source['expected_selected_correct']
        if row.get('selected_correctness_execution_success') is not expected or row.get('selected_disproof_execution_success') is not (not expected):
            raise ValueError('actual selected probe result mismatch')
        _,largest=_cost(row,largest)
        _tree(row.get('tree'),row,source['leaves'],source['selected_leaf'])
        normal+=count['selected_leaf_checks'];guards+=14*count['guard_layouts']
    for key,value in (('signature_entries_created',6*155107),('local_declared_words',6*156163),('cached_signature_reuses',6*1056),
            ('canonical_internal_opening_links',6*46),('scalar_canonical_opening_links',6*9),
            ('scalar_limb_opening_links',6*9),('selected_bit_opening_links',6*5),
            ('internal_cached_boundary_entries',6*23000),('internal_producer_consumer_opening_links',6*46000),
            ('full_statement_cases',2),('targeted_statement_cases',4),('private_probe_registries',52),('private_probe_trees',52)):
        _equal(native.get(key),value,key)
    _equal(native.get('private_probe_signature_entries_created'),sum(p['words'] for p in manifest['probes']),'all separate probe keys')
    metrics=native.get('metrics')
    if type(metrics) is not dict: raise ValueError('actual engine metrics required')
    _equal(metrics.get('vectors'),2*normal+guards+116,'all normal, guard and selected-tree calls')
    _equal(metrics.get('expected_rejections'),normal+guards+58,'actual ordinary false modes, abort guards and tree calls')
    _equal(metrics.get('max_script_bytes'),largest,'actual maximum Script size')
    for key in ('max_stack_items','max_witness_items'):
        if type(metrics.get(key)) is not int or not 0<metrics[key]<=1000: raise ValueError('engine stack/witness cap exceeded')
    payload=metrics.get('max_witness_payload_bytes')
    if type(payload) is not int or not 0<payload<=520*metrics['max_witness_items']: raise ValueError('witness payload cap exceeded')
    wall=native.get('wall_seconds')
    if type(wall) not in (int,float) or not math.isfinite(wall) or not 0<=wall<=1260: raise ValueError('native wall cap exceeded')
    return rows,probes


def run(cases_dir,native_worker):
    _guard();started=time.perf_counter();budget=_record_budget()
    worker=_worker(native_worker);snapshot=_source_snapshot(worker);directory=_new_directory(cases_dir)
    manifest,info,census,probe_census=_generate(directory)
    native=_execute(worker,directory,info['file_sha256'])
    rows,probes=_validate(native,manifest,info,census,probe_census)
    _equal(_source_snapshot(worker),snapshot,'source/binary snapshot unchanged throughout direct execution')
    honest=[dict(name=row['name'],role=row['role'],base_role=row['base_role'],selected_bit=row['selected_bit'],
        component_script_bytes=[part['compiled_script_bytes'] for part in row['components']],
        complete_forest_script_bytes=row['forest']['compiled_script_bytes'],merkle_root=row['forest']['merkle_root'],
        output_key=row['forest']['output_key']) for row in rows if row['profile']=='honest']
    return dict(schema='bitvm2-nova-byte-c-bit-point-conformance/v1',native=native,manifest=info,source_snapshot=snapshot,
        compact_record_budget=budget,cases=6,full_execution_cases=2,targeted_execution_cases=4,
        private_probe_registries=52,private_probe_keys_separate=True,honest_forest_ledger=honest,
        direct_native_worker_executed=True,external_result_receipt_loaded=False,sources_unchanged_during_run=True,
        bit_index=0,components_per_case=11,leaves_per_complete_forest=153213,unique_global_words_per_case=155107,
        full_hash_verified=False,transcript_verified=False,proof_verified=False,bitvm2_script_verified=False,
        complete_nova_verifier=False,complete_bitvm2_verifier=False,scalar_multiplication_verified=False,ipa_verified=False,
        A_proof_origin_bound=False,P_key_origin_bound=False,production_assertion_binding=False,bitcoin_transaction_graph=False,
        setup_calls=0,proving_jobs=0,gpu_jobs=0,transactions_broadcast=0,
        wall_seconds=time.perf_counter()-started,parent_peak_rss_bytes=peak_rss(),
        scope='one fixed challenge-bit conditional point fixture; selected negative probes have separate keys/trees; proof, point/key origins, scalar multiplication, IPA and production remain open')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cases-dir',type=Path,required=True);parser.add_argument('--native-worker',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True);args=parser.parse_args();_guard()
    from bench_keccak_endpoint import _output_file
    output=_output_file(args.output);result=run(args.cases_dir,args.native_worker)
    _write_json(output,result,MAX_RESULT_BYTES);print(json.dumps(result,ensure_ascii=True,allow_nan=False))


if __name__=='__main__': main()
