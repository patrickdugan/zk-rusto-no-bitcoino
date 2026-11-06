"""Pure rho framing/maps locally; BOTH full hashes and tail are HOSTED ONLY.

The retained values below were extracted from the literal SHA256-pinned native
trace394d90b3...59b8. They are reproducible fixtures, not proof/transcript authority.
No local test builds a full graph, executes Script, signs or proves.
"""
from dataclasses import FrozenInstanceError
from hashlib import sha256
import json
import os
import sys
import unittest
from unittest.mock import patch

from script import BASE,P,Q

CONTEXT=sha256(b'byte-rho-tests/caller-owned-context').digest()
OPERATION='tests/byte-rho'
VECTORS=(
    dict(role='pallas_scalar',modulus=Q,counter=59,
        eval_w='537b9d938bc6034f86e7a3e80acfe239738ce9cf711e01d98f962be35ce2f50d',
        prior='baeac41afe052c21cb039093874cb223c9a5e9e81be6d9f155ef6b660a0d9921c'
              '936762f733e9e28bc943ef10103de48ee6de67d875123c945f8dbbe38518694',
        lo='f04e669b472740ed7e968c559565f0ef1cc9a02bd7265a14380d37f150127006',
        hi='02a294e6894a96599a22f07296b9b94aa004b4f821ae0435755c5ccfd04bdc7f',
        result='4e248fbe6c6e3f895a93955b53dc406ca32d31d33cdeaa5f25405cfcaec7c23e'),
    dict(role='vesta_scalar',modulus=P,counter=44,
        eval_w='9af0b1db3bb739876ec135b290fa9016b388a2a71ba5a45bb7bee402582efc26',
        prior='379a4d9a1bb224b6d4a5b9b29dfd641a52630feaed5e5bb8732e5de012b1d933'
              '3965bbe9209263ab886274f82e4d1c263f4518ec86cf1da1049fa603ca1ed285',
        lo='05913fa1f3e416205487806536aacbca64e1b314c5f20e658ae5ca6b8fc2fb74',
        hi='a1199395495cb178b7ee439193c436f64b288afade6c973f80ec66f85e73936d',
        result='2cc2f411b9774ff97b240b4e02478805599898c401a3965a844b57f0c5345504'))
FIXED_INDICES=(0,*range(33,45),109,110,*range(111,200))
DYNAMIC_INDICES=tuple(range(1,33))+tuple(range(45,109))
FALSE_FLAGS=('eval_w_canonical_in_script','eval_w_proof_origin_bound','prior_state_transcript_bound',
    'full_transcript_verified','transcript_verified','nova_transcript_verified','proof_verified',
    'bitvm2_script_verified','production_assertion_binding','bitcoin_transaction_graph')


def _hosted():
    return (os.environ.get('GITHUB_ACTIONS')=='true'
        and os.environ.get('RUNNER_OS')=='Linux' and sys.platform=='linux')


def _canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,
                      allow_nan=False).encode('ascii')


def _frame(eval_w,prior,counter,branch):
    if type(eval_w) is not bytes or len(eval_w)!=32 or type(prior) is not bytes or len(prior)!=64:
        raise ValueError('exact immutable32/64-byte external input ports required')
    if type(counter) is not int or not 0<=counter<(1<<64):raise ValueError('u64 counter required')
    if type(branch) is not str or branch not in ('hi','lo'):raise ValueError('literal branch required')
    return b'w'+eval_w+b'NoDS'+counter.to_bytes(8,'little')+prior+b'r'+bytes([int(branch=='hi')])


def _initial(eval_w,prior,counter,branch):
    return _frame(eval_w,prior,counter,branch)+b'\x01'+bytes(23)+b'\x80'+bytes(64)


def _local_byte(state,index):
    return f'byte-state/{state}/l{index//8}/byte{index%8}'


def _keccak(message):
    from Cryptodome.Hash import keccak
    return keccak.new(digest_bits=256,data=message).digest()


def _input_consumers(byte_index):
    lane,byte=divmod(byte_index,8)
    x,y=lane%5,lane//5
    return ((32*x+4*byte+max(y-1,0),0 if y==0 else 1),(240+byte_index,0))


def _full_truth(spec,values,ordinal):
    leaf=spec.leaves[ordinal]
    operands=tuple(values[spec.words[index][0]] for index in leaf.wires)
    if any(type(value) is not int or not 0<=value<256 for value in operands):return False
    if leaf.kind=='byte_xor':expected=operands[0]^operands[1]
    elif leaf.kind=='byte_and':expected=operands[0]&operands[1]
    elif leaf.kind=='byte_not':expected=operands[0]^255
    elif leaf.kind=='byte_rol':
        shift,=leaf.argument
        expected=((operands[0]<<shift)&255)|(operands[1]>>(8-shift))
    elif leaf.kind=='byte_xor_const':expected=operands[0]^leaf.argument[0]
    else:raise AssertionError('unexpected non-BYTE hash leaf')
    return operands[-1]==expected


def _word_output(initial):
    from keccak_trace import keccak_f1600
    lanes=tuple(int.from_bytes(initial[index:index+8],'little') for index in range(0,200,8))
    return b''.join(value.to_bytes(8,'little') for value in keccak_f1600(lanes))


def _wrong_reduction_constraints(tail,binding,modulus):
    """Independent floor carry construction for a canonical false result."""
    raw=binding.raw_state
    c=binding.result_value.to_bytes(32,'little')
    q=binding.quotient_value.to_bytes(33,'little')
    p=modulus.to_bytes(32,'little')
    carry=0;failures=[];carries=[8192]
    for column in range(65):
        pq=sum(coefficient*q[column-index] for index,coefficient in enumerate(p)
               if 0<=column-index<33)
        x=raw[column] if column<64 else 0
        result=c[column] if column<32 else 0
        carry,remainder=divmod(x+carry-result-pq,256)
        carries.append(8192+carry)
        if remainder:failures.append(tail.uniform.column_constraints[column])
    if carry:failures.append(tail.uniform.anchor_constraints['carry_final'])
    return tuple(sorted(failures)),tuple(carries)


class ByteRhoPureFramingAndGuards(unittest.TestCase):
    def test_retained_primary59_secondary44_exact_frames_hashes_and_le512_reduction(self):
        import byte_rho as module
        for vector in VECTORS:
            eval_w=bytes.fromhex(vector['eval_w']);prior=bytes.fromhex(vector['prior'])
            self.assertLess(int.from_bytes(eval_w,'little'),vector['modulus'])
            digests={}
            for branch in ('hi','lo'):
                expected=_frame(eval_w,prior,vector['counter'],branch)
                self.assertEqual(len(expected),111)
                self.assertEqual(module.rho_preimage(eval_w,prior,counter=vector['counter'],branch=branch),expected)
                self.assertEqual(module.framed_state_bytes(eval_w,prior,counter=vector['counter'],branch=branch),
                                 _initial(eval_w,prior,vector['counter'],branch))
                digests[branch]=_keccak(expected)
                self.assertEqual(digests[branch].hex(),vector[branch])
            result=int.from_bytes(digests['lo']+digests['hi'],'little')%vector['modulus']
            self.assertEqual(result.to_bytes(32,'little').hex(),vector['result'])
            self.assertNotEqual(_keccak(_frame(eval_w,prior,vector['counter']+1,'hi')),digests['hi'])
            self.assertNotEqual(int.from_bytes(digests['hi']+digests['lo'],'little')%vector['modulus'],result)

    def test_all104_fixed_bytes_per_branch_and96_shared_origins_partition200(self):
        import byte_rho as module
        self.assertEqual((len(FIXED_INDICES),len(DYNAMIC_INDICES)),(104,96))
        self.assertFalse(set(FIXED_INDICES)&set(DYNAMIC_INDICES))
        self.assertEqual(set(FIXED_INDICES)|set(DYNAMIC_INDICES),set(range(200)))
        for counter in (0,1,44,59,(1<<64)-1):
            for branch in ('hi','lo'):
                initial=_initial(bytes(32),bytes(64),counter,branch)
                expected=tuple((index,initial[index]) for index in FIXED_INDICES)
                self.assertEqual(module.fixed_frame_bytes(counter,branch),expected)
                self.assertEqual(initial[37:45],counter.to_bytes(8,'little'))
                self.assertEqual(initial[110],int(branch=='hi'))
                self.assertEqual(initial[111:136],b'\x01'+bytes(23)+b'\x80')
                self.assertEqual(initial[136:],bytes(64))
        entries=2*len(FIXED_INDICES)
        self.assertEqual((entries,2*entries,2*32,4*len(DYNAMIC_INDICES)),(208,416,64,384))
        self.assertEqual(2*29445-96+587-2*136,59109)
        self.assertEqual(2*29245+453,58943)

    def test_small_branch_name_groups_share_only_the96_dynamic_input_ports(self):
        import byte_rho as module
        hi=tuple(module.branch_global_id('hi',_local_byte(0,index)) for index in range(200))
        lo=tuple(module.branch_global_id('lo',_local_byte(0,index)) for index in range(200))
        self.assertEqual((len(set(hi)),len(set(lo))),(200,200))
        expected={hi[index] for index in DYNAMIC_INDICES}
        self.assertEqual(set(hi)&set(lo),expected)
        self.assertEqual(len(expected),96)
        for index in range(200):
            self.assertEqual(hi[index]==lo[index],index in DYNAMIC_INDICES)
            if 1<=index<33:self.assertEqual(hi[index],f'message/eval_w/byte/{index-1}')
            elif 45<=index<109:self.assertEqual(hi[index],f'message/prior_state/byte/{index-45}')
            else:
                self.assertEqual(hi[index],'branch/hi/'+_local_byte(0,index))
                self.assertEqual(lo[index],'branch/lo/'+_local_byte(0,index))
        high_digest={module.branch_global_id('hi',_local_byte(24,index)) for index in range(32)}
        low_digest={module.branch_global_id('lo',_local_byte(24,index)) for index in range(32)}
        self.assertFalse(high_digest&low_digest)
        self.assertFalse((high_digest|low_digest)&(set(hi)|set(lo)))
        for word in ('byte-round/0/theta/t/l0/byte0','byte-round/23/chi/out/l0/byte0'):
            self.assertNotEqual(module.branch_global_id('hi',word),module.branch_global_id('lo',word))
            self.assertEqual(module.branch_global_id('hi',word),'branch/hi/'+word)

    def test_pure_frame_types_counter_bool_and_selector_aliases_reject(self):
        import byte_rho as module
        for counter in (True,False,-1,1<<64,1.0,'1',None):
            with self.assertRaises(ValueError):module.fixed_frame_bytes(counter,'hi')
            with self.assertRaises(ValueError):module.rho_preimage(bytes(32),bytes(64),counter=counter,branch='hi')
        for branch in (True,False,0,1,'HI','unknown',None):
            with self.assertRaises(ValueError):module.fixed_frame_bytes(59,branch)
            with self.assertRaises(ValueError):module.rho_preimage(bytes(32),bytes(64),counter=59,branch=branch)
        for bad in (None,True,bytes(31),bytes(33),bytearray(32)):
            with self.assertRaises(ValueError):module.rho_preimage(bad,bytes(64),counter=59,branch='lo')
        for bad in (None,True,bytes(63),bytes(65),bytearray(64)):
            with self.assertRaises(ValueError):module.rho_preimage(bytes(32),bad,counter=59,branch='lo')
        # Pure framing accepts raw32B; canonicality is the host binding policy,
        # and is not a Script proof-origin or scalar-canonicality assertion.
        self.assertEqual(module.rho_preimage(Q.to_bytes(32,'little'),bytes(64),counter=59,branch='lo'),
                         _frame(Q.to_bytes(32,'little'),bytes(64),59,'lo'))

    def test_pure_map_aliases_and_policy_preflight_reject_before_any_large_allocation(self):
        import byte_rho as module
        for word in (None,True,'','byte-state/00/l0/byte0','byte-state/0/l00/byte0',
                     'byte-state/25/l0/byte0','byte-state/0/l25/byte0','byte-state/0/l0/byte8',
                     'byte-round/00/theta','byte-round/24/theta','unknown/prefix'):
            with self.assertRaises(ValueError):module.branch_global_id('hi',word)
        for maps in (((),(),()),([],(),()),(None,(),()),(True,False,None)):
            with self.assertRaises(ValueError):module._validate_maps(*maps)
        with patch.object(module,'build_byte_keccak_permutation',side_effect=AssertionError('pure policy allocated full graph')) as child:
            for role in ('pallas_scalar','vesta_scalar'):
                for counter in (0,44,59,(1<<64)-1):
                    module._parameters(CONTEXT,role,counter,OPERATION)
            module._parameters(CONTEXT,'pallas_scalar',59,'x'*153)
            module._parameters(CONTEXT,'pallas_scalar',(1<<64)-1,'x'*135)
            for role,counter,context,operation in (
                ('pallas_base',59,CONTEXT,OPERATION),('vesta_base',44,CONTEXT,OPERATION),
                (True,59,CONTEXT,OPERATION),('pallas_scalar',True,CONTEXT,OPERATION),
                ('pallas_scalar',-1,CONTEXT,OPERATION),('pallas_scalar',1<<64,CONTEXT,OPERATION),
                ('pallas_scalar',59,bytes(31),OPERATION),('pallas_scalar',59,bytearray(32),OPERATION),
                ('pallas_scalar',59,CONTEXT,'x'*154),('pallas_scalar',(1<<64)-1,CONTEXT,'x'*136)):
                with self.assertRaises(ValueError):module._parameters(context,role,counter,operation)
            child.assert_not_called()

    def test_resource_guards_precede_components_binding_streaming_and_io(self):
        import byte_rho as module
        for github,runner,platform in [('false','Linux','linux'),('true','Windows','linux'),('true','Linux','win32')]:
            with patch.dict(os.environ,{'GITHUB_ACTIONS':github,'RUNNER_OS':runner},clear=True),\
                patch.object(module.sys,'platform',platform),\
                patch.object(module,'build_byte_keccak_permutation',side_effect=AssertionError('full graph allocated')) as child,\
                patch.object(module,'build_uniform_reduction',side_effect=AssertionError('tail allocated')) as tail,\
                patch('builtins.open',side_effect=AssertionError('I/O before guard')) as io:
                with self.assertRaisesRegex(ValueError,'hosted GitHub Linux'):
                    module.build_byte_rho(context=None,role=None,counter=None)
                empty=object.__new__(module.ByteRhoPlan)
                with self.assertRaisesRegex(ValueError,'hosted GitHub Linux'):empty.bind(None,None)
                with self.assertRaisesRegex(ValueError,'hosted GitHub Linux'):empty.regenerate_component(None)
                binding=object.__new__(module.ByteRhoBinding)
                with self.assertRaisesRegex(ValueError,'hosted GitHub Linux'):binding.iter_components()
                child.assert_not_called();tail.assert_not_called();io.assert_not_called()
        for cls in (module.ByteRhoPlan,module.ByteRhoBinding,module.ByteRhoTail,
                    module.ByteRhoComponentDescriptor,module.ByteRhoComponentSource,module.ByteRhoComponentBinding):
            with self.assertRaises(TypeError):cls()
            self.assertFalse(hasattr(cls,'from_json'))
        for key in ('hi','lo','hi_digest','prior_hi','components','source_maps','receipt','manifest',
                    'graph','spec','program','assignment','global_ids'):
            with self.assertRaises(TypeError):module.build_byte_rho(context=CONTEXT,
                role='pallas_scalar',counter=59,**{key:{'passed':True}})


@unittest.skipUnless(_hosted(),'both full BYTE hashes and tail Script are hosted GitHub Linux only')
class HostedByteRhoTests(unittest.TestCase):
    def setUp(self):
        if not _hosted():self.skipTest('hosted guard before any full graph or Script allocation')
        import byte_rho
        self.module=byte_rho

    def build(self,vector,*,context=CONTEXT,operation=OPERATION,counter=None,role=None):
        return self.module.build_byte_rho(context=context,role=vector['role'] if role is None else role,
            counter=vector['counter'] if counter is None else counter,operation_id=operation)

    def assert_plan_maps(self,plan,maps,vector):
        self.assertFalse(hasattr(plan,'program'))
        self.assertFalse(hasattr(plan,'spec'),'three components must not form an over-cap flat catalogue')
        self.assertEqual(tuple(item.branch for item in plan.components),('hi','lo','tail'))
        self.assertEqual(tuple((item.words,item.leaves) for item in plan.components),
                         ((29445,29245),(29445,29245),(587,453)))
        for index,descriptor in enumerate(plan.components):
            self.assertEqual((descriptor.index,descriptor.counter,descriptor.field_role),(index,vector['counter'],vector['role']))
            self.assertEqual(descriptor.operation_id,f'{OPERATION}/counter/{vector["counter"]}/{descriptor.branch}')
        hi,lo,tail=(tuple(component['global_ids']) for component in maps['components'])
        self.module._validate_maps(hi,lo,tail)
        sets=tuple(set(ids) for ids in (hi,lo,tail))
        self.assertEqual((len(sets[0]&sets[1]),len(sets[0]&sets[2]),len(sets[1]&sets[2])),(96,136,136))
        self.assertFalse(set.intersection(*sets))
        self.assertEqual(len(set.union(*sets)),59109)
        self.assertEqual(set(plan.ports['eval_w']+plan.ports['prior_state']),sets[0]&sets[1])
        self.assertEqual(plan.ports['raw_state'],tuple(
            self.module.branch_global_id(branch,_local_byte(24,index))
            for branch in ('lo','hi') for index in range(32)))
        self.assertEqual(plan.ports['scalar_result'],tuple(f'reduction/result/l{i}' for i in range(9)))
        self.assertEqual(plan.ports['quotient'],tuple(f'reduction/quotient/byte/{i}' for i in range(33)))
        with self.assertRaises(TypeError):plan.ports['raw_state']=()
        self.assertEqual((len(maps['messages']),len(maps['frames']),len(maps['digests'])),(96,208,64))
        origins=0
        for index,record in enumerate(maps['messages']):
            kind,local,byte=('eval_w',index,index+1) if index<32 else ('prior_state',index-32,index-32+45)
            self.assertEqual((record['index'],record['kind'],record['byte_index']),(index,kind,local))
            expected=f'message/{kind}/byte/{local}'
            self.assertEqual(record['global_id'],expected)
            for branch,component in (('hi',maps['components'][0]),('lo',maps['components'][1])):
                word=record[branch+'_word']
                self.assertEqual(word,component['input_indices'][byte])
                self.assertEqual(component['global_ids'][word],expected)
                self.assertEqual(record[branch+'_consumer_occurrences'],[list(cell) for cell in _input_consumers(byte)])
                origins+=len(record[branch+'_consumer_occurrences'])
        self.assertEqual(origins,384,'shared external-origin coherence coordinates, not proof-origin producer links')
        frame_coordinates=0
        for index,record in enumerate(maps['frames']):
            branch='hi' if index<104 else 'lo';byte=FIXED_INDICES[index%104]
            expected=_initial(bytes(32),bytes(64),vector['counter'],branch)[byte]
            component=maps['components'][0 if branch=='hi' else 1]
            self.assertEqual((record['index'],record['branch'],record['byte_index'],record['expected']),
                             (index,branch,byte,expected))
            self.assertEqual(record['anchor_ordinal'],244+index)
            self.assertEqual(record['source_word'],component['input_indices'][byte])
            self.assertEqual(record['global_id'],component['global_ids'][record['source_word']])
            self.assertEqual(record['global_id'],tail[record['tail_word']])
            self.assertEqual(record['source_consumer_occurrences'],[list(cell) for cell in _input_consumers(byte)])
            frame_coordinates+=len(record['source_consumer_occurrences'])
        self.assertEqual(frame_coordinates,416)
        for index,record in enumerate(maps['digests']):
            branch='lo' if index<32 else 'hi';byte=index%32
            component=maps['components'][1 if branch=='lo' else 0]
            self.assertEqual((record['index'],record['branch'],record['byte_index']),(index,branch,byte))
            self.assertEqual(record['source_word'],component['output_indices'][byte])
            self.assertEqual(record['global_id'],component['global_ids'][record['source_word']])
            self.assertEqual(record['global_id'],tail[record['tail_word']])
            self.assertEqual(record['producer_ordinal'],component['producer_ordinals'][byte])
            self.assertEqual(record['producer_occurrence'],component['producer_occurrences'][byte])
            self.assertEqual(record['consumer_occurrence'],0)
        self.assertEqual(maps['uniform']['leaf_map'],list(range(244))+[452])
        self.assertEqual(maps['uniform']['word_map'],list(range(379)))
        manifest=plan.manifest
        self.assertEqual((manifest['context'],manifest['field_role'],manifest['counter']),
                         (CONTEXT.hex(),vector['role'],vector['counter']))
        self.assertEqual(manifest['component_order'],['hi','lo','tail'])
        self.assertEqual(manifest['components'],[descriptor.json() for descriptor in plan.components])
        self.assertEqual(plan.source_maps_sha256,sha256(_canonical(maps)).digest())
        self.assertEqual(manifest['source_maps_sha256'],plan.source_maps_sha256.hex())
        self.assertEqual(plan.source_sha256,sha256(b'BITVM2-NOVA/BYTE-RHO-SOURCE/v1\x00'+_canonical(manifest)).digest())
        self.assertNotIn('source_sha256',manifest)
        # These raw-array mutations are diagnostics only; no constructor accepts
        # imported maps. Check that the pure intersection guard rejects extra
        # branch sharing or a split shared message identity as well.
        extra=list(hi);extra[maps['components'][0]['input_indices'][0]]=lo[maps['components'][1]['input_indices'][0]]
        with self.assertRaises(ValueError):self.module._validate_maps(tuple(extra),lo,tail)
        split=list(hi);split[maps['components'][0]['input_indices'][1]]='branch/hi/split-message-byte'
        with self.assertRaises(ValueError):self.module._validate_maps(tuple(split),lo,tail)

    def assert_tail_projection(self,item,maps,binding,vector,*,check_scripts=False):
        from wots_graph import GraphSpec
        tail=item.tail
        self.assertIsNotNone(tail)
        uniform=tail.uniform
        values=item.assignment
        self.assertEqual((len(tail.program.words),len(tail.program.constraints),len(item.spec.leaves)),(587,452,453))
        self.assertEqual(tail.program.words[:379],uniform.program.words)
        self.assertEqual(tail.program.constraints[:244],uniform.program.constraints)
        self.assertEqual(tail.program.fields,uniform.program.fields)
        self.assertEqual(tail.uniform_leaf_map,tuple(range(244))+(452,))
        self.assertEqual(item.spec.field_leaves,(('result',452),))
        child=GraphSpec.from_program(uniform.program)
        bodies,old_bodies=dict(item.spec.bodies),dict(child.bodies)
        for old,new in enumerate(tail.uniform_leaf_map):
            self.assertEqual(item.spec.leaves[new],child.leaves[old])
            body=child.leaves[old].body_sha256
            self.assertEqual(bodies[body],old_bodies[body])
        self.assertEqual(tuple(values[word] for word in uniform.ports['input_bytes']),tuple(binding.lo+binding.hi))
        self.assertEqual(tail.anchor_constraints,tuple(range(244,452)))
        self.assertEqual(len(tail.anchor_words),208)
        tail_maps=tail.source_maps
        self.assertEqual(tail_maps['uniform_leaf_map'],maps['uniform']['leaf_map'])
        self.assertEqual(tail_maps['uniform_word_map'],maps['uniform']['word_map'])
        self.assertEqual(tail_maps['uniform_program_sha256'],maps['uniform']['program_sha256'])
        self.assertEqual(tail_maps['uniform_catalogue_id'],child.digest().hex())
        for index,record in enumerate(tail_maps['frame_anchors']):
            branch='hi' if index<104 else 'lo';byte=FIXED_INDICES[index%104]
            word=f'frame/{branch}/byte/{byte}';ordinal=244+index
            expected=dict(self.module.fixed_frame_bytes(vector['counter'],branch))[byte]
            self.assertEqual((record['branch'],record['byte_index'],record['local_word'],record['anchor_ordinal']),
                             (branch,byte,word,ordinal))
            self.assertEqual(tail.anchor_words[index],word)
            self.assertEqual(item.spec.words[record['word_index']],(word,256))
            leaf=item.spec.leaves[ordinal]
            self.assertEqual((leaf.kind,leaf.argument,leaf.wires),('const',(expected,),(record['word_index'],)))
            self.assertEqual(item.global_ids[record['word_index']],maps['frames'][index]['global_id'])
        for index,record in enumerate(maps['digests']):
            ordinal=uniform.input_adapter_constraints[index]
            self.assertEqual(record['consumer_ordinal'],ordinal)
            leaf=item.spec.leaves[ordinal]
            self.assertEqual((leaf.kind,leaf.argument,leaf.wires[0]),('conv_ab',(1,),record['tail_word']))
            names=tuple(item.spec.words[slot][0] for slot in leaf.wires)
            self.assertEqual(names,(uniform.ports['input_bytes'][index],uniform.ports['constant_one'],uniform.ports['input_subtotals'][index]))
            self.assertEqual(tuple(item.spec.words[slot][1] for slot in leaf.wires),(256,256,1<<18))
        self.assertEqual(tail.program.fields,uniform.program.fields)
        for name,ordinal in uniform.anchor_constraints.items():
            self.assertEqual(tail.program.constraints[ordinal],uniform.program.constraints[ordinal],name)
        self.assertEqual(len(tail.program.fields),1,'quotient remains an integer, not a canonical field')
        self.assertEqual(tail.source_sha256,sha256(b'BITVM2-NOVA/BYTE-RHO-TAIL/v1\x00'+_canonical(tail.metadata)).digest())
        self.assertEqual(tail.source_maps_sha256,sha256(_canonical(tail_maps)).digest())
        if check_scripts:self.assert_tail_witness_and_field_guards(tail,values,vector)

    def assert_tail_witness_and_field_guards(self,tail,values,vector):
        from script import OPS,execute,num
        bound=tail.program.bind(values)
        selected={}
        for ordinal,constraint in enumerate(tail.program.constraints):selected.setdefault(constraint.kind,ordinal)
        selected['new-hi-frame']=244;selected['new-lo-frame']=348
        for ordinal in selected.values():
            witness=bound.witness(ordinal)
            for disprove in (False,True):
                code=bound.script(ordinal,disprove=disprove)
                self.assertEqual(execute(code,witness).success,not disprove)
                for malformed in ((),witness[:-1],(b'',)+witness,witness+(b'',)):
                    result=execute(code,malformed)
                    self.assertFalse(result.success);self.assertEqual(result.error,'EQUALVERIFY')
                first=tail.program.constraints[ordinal].wires[0]
                result=execute(code,(num(values[first]^1),)+witness[1:])
                self.assertFalse(result.success);self.assertEqual(result.error,'EQUALVERIFY')
        alias=dict(values)
        for index,word in enumerate(tail.uniform.ports['result_field']):
            alias[word]=(vector['modulus']>>(29*index))&(BASE-1)
        with self.assertRaises(ValueError):tail.program.bind(alias)
        leaf=tail.spec.leaves[452]
        body=bytes.fromhex(dict(tail.spec.bodies)[leaf.body_sha256])
        witness=tuple(num(alias[tail.spec.words[index][0]]) for index in leaf.wires)
        self.assertFalse(execute(body,witness).success)
        self.assertTrue(execute(body+bytes([OPS['NOT']]),witness).success)

    def stream_check(self,plan,maps,binding,vector,*,expected=None,wrong_reduction=False,deep=False):
        expected={} if expected is None else expected
        observed={}
        for item in binding.iter_components():
            branch=item.branch;spec=item.spec;values=item.assignment
            facts=maps['components'][item.index]
            self.assertEqual(item.descriptor,plan.components[item.index])
            self.assertEqual(item.global_ids,tuple(facts['global_ids']))
            self.assertEqual(spec.program_sha256,item.descriptor.program_sha256)
            self.assertEqual(spec.digest().hex(),item.descriptor.catalogue_id)
            self.assertEqual((spec.context,spec.field_role),(CONTEXT.hex(),vector['role']))
            self.assertEqual(item.descriptor.global_ids_sha256,sha256(_canonical(list(item.global_ids))).hexdigest())
            self.assertTrue(all(type(values[word]) is int and 0<=values[word]<bound for word,bound in spec.words))
            if branch in ('hi','lo'):
                self.assertIsNone(item.tail)
                self.assertEqual((len(spec.words),len(spec.leaves)),(29445,29245))
                self.assertTrue(all(bound==256 for _,bound in spec.words))
                self.assertEqual(item.global_ids,tuple(self.module.branch_global_id(branch,word) for word,_ in spec.words))
                self.assertEqual(bytes(values[spec.words[index][0]] for index in facts['input_indices']),
                    binding.initial_hi if branch=='hi' else binding.initial_lo)
                self.assertEqual(bytes(values[spec.words[index][0]] for index in facts['output_indices']),
                    binding.hi_output if branch=='hi' else binding.lo_output)
                for byte,source_word in enumerate(facts['input_indices']):
                    self.assertEqual(facts['input_consumer_occurrences'][byte],[list(cell) for cell in _input_consumers(byte)])
                    for consumer,formal in facts['input_consumer_occurrences'][byte]:
                        self.assertEqual(spec.leaves[consumer].wires[formal],source_word)
                for source_word,producer,formal in zip(facts['output_indices'],facts['producer_ordinals'],
                        facts['producer_occurrences'],strict=True):
                    self.assertEqual(spec.leaves[producer].wires[formal],source_word)
                    self.assertEqual(formal,1 if spec.leaves[producer].kind=='byte_xor_const' else 2)
                failures=tuple(ordinal for ordinal in range(len(spec.leaves)) if not _full_truth(spec,values,ordinal))
                if deep:
                    program=item.child_program_manifest;source=item.child_source_manifest;child_maps=item.child_source_maps
                    self.assertEqual(program['operation_id'],item.descriptor.operation_id)
                    self.assertEqual(item.descriptor.program_identity_kind,'domain-separated manifest hash; not Program.digest')
                    self.assertEqual(item.descriptor.program_sha256,sha256(
                        b'BITVM2-NOVA/BYTE-KECCAK-PERMUTATION-PROGRAM/v1\x00'+_canonical(program)).hexdigest())
                    self.assertEqual(item.descriptor.source_sha256,sha256(
                        b'BITVM2-NOVA/BYTE-KECCAK-PERMUTATION-SOURCE/v1\x00'+_canonical(source)).hexdigest())
                    self.assertEqual(item.descriptor.source_maps_sha256,sha256(_canonical(child_maps)).hexdigest())
                    self.assertEqual(child_maps['global_ids'],[word for word,_ in spec.words])
                    self.assertEqual(child_maps['input_indices'],facts['input_indices'])
                    self.assertEqual(child_maps['output_indices'],facts['output_indices'])
                    self.assertEqual(child_maps['producer_ordinals'],facts['producer_ordinals'])
                    self.assertEqual(child_maps['producer_occurrences'],facts['producer_occurrences'])
                    self.assertEqual(source['catalogue_id'],spec.digest().hex())
                    del program,source,child_maps
            else:
                self.assertEqual(branch,'tail')
                self.assertIsNone(item.child_program_manifest)
                tail=item.tail
                self.assertEqual(item.descriptor.program_identity_kind,'ConvolutionProgram.digest (fixed-trace/v2)')
                failures=tail.program.bind(values).failures()
                if wrong_reduction:
                    wanted,carries=_wrong_reduction_constraints(tail,binding,vector['modulus'])
                    self.assertTrue(wanted)
                    self.assertEqual(tuple(values[word] for word in tail.uniform.ports['carries']),carries)
                    self.assertEqual(failures,wanted)
                if deep:self.assert_tail_projection(item,maps,binding,vector,check_scripts=True)
                del tail
            wanted=failures if branch=='tail' and wrong_reduction else expected.get(branch,())
            self.assertEqual(failures,tuple(wanted),(branch,binding.summary()))
            observed[branch]=failures
            if failures:
                from script import OPS,execute,num
                for ordinal in failures:
                    if branch=='tail':
                        bound=item.tail.program.bind(values)
                        witness=bound.witness(ordinal)
                        for disprove in (False,True):
                            result=execute(bound.script(ordinal,disprove=disprove),witness)
                            self.assertEqual(result.success,disprove);self.assertIsNone(result.error)
                        del bound
                    else:
                        leaf=spec.leaves[ordinal]
                        body=bytes.fromhex(dict(spec.bodies)[leaf.body_sha256])
                        unique=tuple(dict.fromkeys(leaf.wires))
                        witness=tuple(num(values[spec.words[index][0]]) for index in unique)
                        for disprove in (False,True):
                            result=execute(body+(bytes([OPS['NOT']]) if disprove else b''),witness)
                            self.assertEqual(result.success,disprove);self.assertIsNone(result.error)
            # Release the previous full spec and values BEFORE iterator.advance
            # constructs the next component. Keep only small ordinal tuples.
            del values,spec,item
        self.assertEqual(tuple(observed),('hi','lo','tail'))
        return observed

    def test_retained_closed_hashes_and_uniform_projection_both_roles_one_component_at_a_time(self):
        for vector in VECTORS:
            plan=self.build(vector);maps=plan.source_maps
            self.assert_plan_maps(plan,maps,vector)
            eval_w=bytes.fromhex(vector['eval_w']);prior=bytes.fromhex(vector['prior'])
            binding=plan.bind(eval_w,prior)
            self.assertEqual((binding.lo.hex(),binding.hi.hex()),(vector['lo'],vector['hi']))
            self.assertEqual(binding.raw_state,binding.lo+binding.hi)
            for branch in ('hi','lo'):
                initial=_initial(eval_w,prior,vector['counter'],branch)
                self.assertEqual(getattr(binding,'initial_'+branch),initial)
                self.assertEqual(getattr(binding,branch),_keccak(_frame(eval_w,prior,vector['counter'],branch)))
                self.assertEqual(getattr(binding,branch+'_output'),_word_output(initial))
            integer=int.from_bytes(binding.raw_state,'little')
            quotient,result=divmod(integer,vector['modulus'])
            self.assertEqual((binding.quotient_value,binding.result_value),(quotient,result))
            self.assertEqual(result.to_bytes(32,'little').hex(),vector['result'])
            self.assertEqual(self.stream_check(plan,maps,binding,vector,deep=True),dict(hi=(),lo=(),tail=()))
            for summary in (plan.summary(),binding.summary()):
                for flag in FALSE_FLAGS:self.assertIs(summary[flag],False)
            self.assertIs(binding.summary()['reference_hashes_match'],True)
            self.assertIs(binding.summary()['reduction_relation_holds'],True)
            del binding,maps,plan

    def test_bad_hi_frame_faults_and_canonical_wrong_result_refute_their_actual_component(self):
        for role_index,vector in enumerate(VECTORS):
            plan=self.build(vector);maps=plan.source_maps
            eval_w=bytes.fromhex(vector['eval_w']);prior=bytes.fromhex(vector['prior'])
            normal_hi=_initial(eval_w,prior,vector['counter'],'hi')
            normal_lo=_initial(eval_w,prior,vector['counter'],'lo')
            high=bytearray(_word_output(normal_hi));high[0]^=1
            binding=plan.bind(eval_w,prior,claimed_hi_output=bytes(high))
            self.assertEqual(binding.hi_output,bytes(high))
            self.assertEqual(binding.result_value,int.from_bytes(binding.raw_state,'little')%vector['modulus'])
            self.assertNotEqual(binding.result_value,int.from_bytes(bytes.fromhex(vector['result']),'little'))
            producer=maps['components'][0]['producer_ordinals'][0]
            self.stream_check(plan,maps,binding,vector,expected=dict(hi=(producer,)))
            self.assertIs(binding.summary()['reference_hashes_match'],False)
            self.assertIs(binding.summary()['reduction_relation_holds'],True)
            del binding
            # Five representative fixed-byte classes per role. Alternating the
            # branch by role makes each class cover both HI and LO overall,
            # while avoiding redundant simultaneous component construction.
            for fault_index,byte in enumerate((0,37,110,111,136)):
                branch=('hi','lo')[(fault_index+role_index)%2]
                normal=normal_hi if branch=='hi' else normal_lo
                replacement=normal[byte]^1
                kwargs=(dict(padding_fault=branch) if byte==111 else
                        dict(frame_fault=(branch,byte,replacement)))
                binding=plan.bind(eval_w,prior,**kwargs)
                changed=bytearray(normal);changed[byte]=replacement
                self.assertEqual(getattr(binding,'initial_'+branch),bytes(changed))
                self.assertEqual(getattr(binding,branch+'_output'),_word_output(bytes(changed)))
                if byte<111:
                    self.assertEqual(getattr(binding,branch),_keccak(bytes(changed[:111])))
                # Invalid padding/capacity inputs deliberately describe only a
                # permutation; do not call them a mature Keccak hash preimage.
                self.assertEqual(getattr(binding,'initial_'+('lo' if branch=='hi' else 'hi')),
                    normal_lo if branch=='hi' else normal_hi)
                ordinal=244+(0 if branch=='hi' else 104)+FIXED_INDICES.index(byte)
                self.stream_check(plan,maps,binding,vector,expected=dict(tail=(ordinal,)))
                self.assertIs(binding.summary()['reference_hashes_match'],False)
                self.assertIs(binding.summary()['reduction_relation_holds'],True)
                del binding
            original=int.from_bytes(bytes.fromhex(vector['result']),'little')
            claimed=(original+1)%vector['modulus']
            binding=plan.bind(eval_w,prior,claimed_result=claimed)
            self.assertEqual(binding.result_value,claimed)
            self.assertLess(binding.result_value,vector['modulus'])
            self.stream_check(plan,maps,binding,vector,wrong_reduction=True)
            self.assertIs(binding.summary()['reference_hashes_match'],True)
            self.assertIs(binding.summary()['reduction_relation_holds'],False)
            del binding,maps,plan

    def test_host_admission_types_fields_state_claims_and_no_independent_hi_input(self):
        for vector in VECTORS:
            plan=self.build(vector)
            eval_w=bytes.fromhex(vector['eval_w']);prior=bytes.fromhex(vector['prior'])
            with patch.object(self.module.ByteRhoPlan,'regenerate_component',
                              side_effect=AssertionError('bad admission regenerated component')) as child:
                for bad in (None,True,bytes(31),bytes(33),bytearray(32)):
                    with self.assertRaises(ValueError):plan.bind(bad,prior)
                for bad in (None,True,bytes(63),bytes(65),bytearray(64)):
                    with self.assertRaises(ValueError):plan.bind(eval_w,bad)
                for alias in (vector['modulus'],vector['modulus']+1,(1<<256)-1):
                    with self.assertRaises(ValueError):plan.bind(alias.to_bytes(32,'little'),prior)
                for key in ('hi_state_claims','lo_state_claims'):
                    for claims in (None,True,(),(None,)*22,(None,)*24,[None]*23,
                            (True,)+(None,)*22,(None,)*22+(bytes(199),),(None,)*22+(bytearray(200),)):
                        with self.assertRaises(ValueError):plan.bind(eval_w,prior,**{key:claims})
                for key in ('claimed_hi_output','claimed_lo_output'):
                    for bad in (True,False,bytes(199),bytes(201),bytearray(200)):
                        with self.assertRaises(ValueError):plan.bind(eval_w,prior,**{key:bad})
                for bad in (True,False,-1,vector['modulus'],vector['modulus']+1,1.0):
                    with self.assertRaises(ValueError):plan.bind(eval_w,prior,claimed_result=bad)
                for bad in (True,False,-1,1<<258,1.0):
                    with self.assertRaises(ValueError):plan.bind(eval_w,prior,claimed_quotient=bad)
                for bad in (True,False,0,1,'HI','unknown'):
                    with self.assertRaises(ValueError):plan.bind(eval_w,prior,padding_fault=bad)
                for fault in (True,(),('hi',111),('hi',111,0,0),['hi',111,0],
                        (True,111,0),('hi',False,0),('hi',1,0),('lo',45,0),
                        ('hi',111,True),('hi',111,-1),('hi',111,256),('hi',111,1.0)):
                    with self.assertRaises(ValueError):plan.bind(eval_w,prior,frame_fault=fault)
                with self.assertRaises(ValueError):plan.bind(eval_w,prior,padding_fault='hi',frame_fault=('lo',111,0))
                for key in ('hi','hi_digest','lo','lo_digest','raw_state','source_maps','components','receipt'):
                    with self.assertRaises(TypeError):plan.bind(eval_w,prior,**{key:bytes(32)})
                child.assert_not_called()
            for bad in (True,False,-1,3,1.0,None):
                with patch.object(self.module,'build_byte_keccak_permutation',
                                  side_effect=AssertionError('bad component index allocated hash')) as child:
                    with self.assertRaises(ValueError):plan.regenerate_component(bad)
                    child.assert_not_called()
            default=plan.bind(eval_w,prior)
            default_values=(default.raw_state,default.result_value,default.quotient_value)
            del default
            explicit=plan.bind(eval_w,prior,hi_state_claims=(None,)*23,lo_state_claims=(None,)*23,
                               claimed_hi_output=None,claimed_lo_output=None,padding_fault=None,frame_fault=None)
            self.assertEqual(default_values,(explicit.raw_state,explicit.result_value,explicit.quotient_value))
            del explicit,plan

    def test_fresh_snapshots_policy_fingerprints_and_preallocation_identity_caps(self):
        vector=VECTORS[0]
        plan=self.build(vector)
        fingerprints=(plan.source_sha256,tuple(item.program_sha256 for item in plan.components))
        for obj,name in ((plan,'counter'),(plan.components[0],'counter')):
            with self.assertRaises((FrozenInstanceError,AttributeError)):setattr(obj,name,60)
        manifest=plan.manifest;manifest['components'][0]['counter']=60
        self.assertNotEqual(manifest,plan.manifest)
        maps=plan.source_maps;maps['components'][0]['global_ids'][0]='changed/identity'
        self.assertNotEqual(maps,plan.source_maps)
        del maps,manifest
        binding=plan.bind(bytes(32),bytes(64))
        with self.assertRaises((FrozenInstanceError,AttributeError)):binding.eval_w=bytes([1])*32
        self.assertEqual(binding.lo,_keccak(_frame(bytes(32),bytes(64),vector['counter'],'lo')))
        self.assertEqual(binding.hi,_keccak(_frame(bytes(32),bytes(64),vector['counter'],'hi')))
        self.assertEqual(binding.plan.source_sha256,fingerprints[0],'external input values do not define topology')
        for summary in (plan.summary(),binding.summary()):
            for flag in FALSE_FLAGS:self.assertIs(summary[flag],False)
        del binding,plan
        for options in (dict(context=bytes(32)),dict(operation=OPERATION+'/other'),
                        dict(counter=60),dict(role='vesta_scalar')):
            other=self.build(vector,**options)
            self.assertNotEqual(other.source_sha256,fingerprints[0])
            self.assertTrue(all(item.program_sha256!=old for item,old in zip(other.components,fingerprints[1],strict=True)))
            del other
        # Preflight later nested IDs before constructing the very first hash.
        for counter,operation in ((59,'x'*154),((1<<64)-1,'x'*136)):
            with patch.object(self.module,'build_byte_keccak_permutation',
                              side_effect=AssertionError('bad nested identity allocated first branch')) as child:
                with self.assertRaises(ValueError):self.build(vector,counter=counter,operation=operation)
                child.assert_not_called()


if __name__=='__main__':
    unittest.main()


