"""Independent endpoint bytes/maps; real endpoint graphs are HOSTED ONLY.

Local tests hash at most a 111-byte message and inspect pure global-name maps.
They never construct a round, pair, reduction graph, WOTS key or Script.
"""
from dataclasses import FrozenInstanceError
from hashlib import sha256
import json
import os
import random
import sys
import unittest
from unittest.mock import patch

from script import BASE, Q

EVAL_W=bytes.fromhex('537b9d938bc6034f86e7a3e80acfe239738ce9cf711e01d98f962be35ce2f50d')
PRIOR=bytes.fromhex('baeac41afe052c21cb039093874cb223c9a5e9e81be6d9f155ef6b660a0d9921c'
                    '936762f733e9e28bc943ef10103de48ee6de67d875123c945f8dbbe38518694')
LO=bytes.fromhex('f04e669b472740ed7e968c559565f0ef1cc9a02bd7265a14380d37f150127006')
HI=bytes.fromhex('02a294e6894a96599a22f07296b9b94aa004b4f821ae0435755c5ccfd04bdc7f')
RHO=bytes.fromhex('4e248fbe6c6e3f895a93955b53dc406ca32d31d33cdeaa5f25405cfcaec7c23e')
CONTEXT=sha256(b'keccak-endpoint-tests/caller-owned-context').digest()
OPERATION='tests/keccak/rho59/lo'
FALSE_FLAGS=('eval_w_canonical_in_script','eval_w_proof_origin_bound',
    'prior_state_transcript_bound','hi_keccak_origin_bound','whole_challenge_keccak_bound',
    'full_permutation_verified','full_permutation_verified_in_script','full_hash_verified',
    'hash_verified','transcript_verified','nova_transcript_verified','proof_verified',
    'bitvm2_script_verified','production_assertion_binding','bitcoin_transaction_graph')


def _hosted():
    return (os.environ.get('GITHUB_ACTIONS')=='true'
        and os.environ.get('RUNNER_OS')=='Linux' and sys.platform=='linux')


def _frame(eval_w,prior):
    """Independent released-Nova rho59 LO framing, without factory helpers."""
    if type(eval_w) is not bytes or len(eval_w)!=32 or type(prior) is not bytes or len(prior)!=64:
        raise ValueError('exact immutable 32-byte and 64-byte external ports required')
    return b'w'+eval_w+b'NoDS'+(59).to_bytes(8,'little')+prior+b'r\x00'


def _padded_state(eval_w,prior):
    message=_frame(eval_w,prior)
    assert len(message)==111
    return message+b'\x01'+bytes(23)+b'\x80'+bytes(64)


def _bits(raw):
    return tuple((byte>>bit)&1 for byte in raw for bit in range(8))


def _fixed_bytes():
    state=_padded_state(bytes(32),bytes(64))
    return tuple((index,state[index]) for index in (0,*range(33,45),109,110,*range(111,200)))


def _state_id(state,byte,bit):
    return f'state/{state}/l{byte//8}/b{8*(byte%8)+bit}'


def _canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,
                      allow_nan=False).encode('ascii')


def _boolean_truth(spec,values,ordinal):
    """Independent Boolean predicate evaluator, used only on hosted pair11."""
    leaf=spec.leaves[ordinal]
    operands=[values[spec.words[index][0]] for index in leaf.wires]
    if any(type(value) is not int or not 0<=value<spec.words[index][1]
           for value,index in zip(operands,leaf.wires,strict=True)):
        return False
    if leaf.kind=='bool_xor':return operands[2]==operands[0]^operands[1]
    if leaf.kind=='bool_and':return operands[2]==operands[0]&operands[1]
    if leaf.kind=='bool_not':return operands[1]==1-operands[0]
    if leaf.kind=='const':return operands[0]==leaf.argument[0]
    if leaf.kind=='word_valid':return True
    raise AssertionError('unexpected non-Boolean pair predicate')


class EndpointReferenceAndGuardTests(unittest.TestCase):
    def test_exact111_byte_frame_and_retained_mature_keccak_vector(self):
        from Cryptodome.Hash import keccak
        import keccak_endpoint as module
        expected=_frame(EVAL_W,PRIOR)
        self.assertEqual(len(expected),111)
        self.assertEqual(expected[0],0x77)
        self.assertEqual(expected[1:33],EVAL_W)
        self.assertEqual(expected[33:37],b'NoDS')
        self.assertEqual(expected[37:45],b'\x3b'+bytes(7))
        self.assertEqual(expected[45:109],PRIOR)
        self.assertEqual(expected[109:],b'r\x00')
        self.assertEqual(module.rho_preimage(EVAL_W,PRIOR),expected)
        self.assertEqual(keccak.new(digest_bits=256,data=expected).digest(),LO)
        self.assertEqual(keccak.new(digest_bits=256,data=expected[:-1]+b'\x01').digest(),HI)
        self.assertEqual((int.from_bytes(LO+HI,'little')%Q).to_bytes(32,'little'),RHO)
        # A branch byte, round counter, digest byte or state reversal is observable.
        for changed in (expected[:-1]+b'\x01',expected[:37]+(60).to_bytes(8,'little')+expected[45:],
                        _frame(EVAL_W[::-1],PRIOR),_frame(EVAL_W,PRIOR[::-1])):
            self.assertNotEqual(keccak.new(digest_bits=256,data=changed).digest(),LO)

    def test_single_block_padding_capacity_and_all1600_input_bit_locations(self):
        import keccak_endpoint as module
        from keccak_trace import keccak_f1600,state_from_bytes,state_to_bytes
        state=_padded_state(EVAL_W,PRIOR)
        self.assertEqual(len(state),200)
        self.assertEqual(module.framed_state_bytes(EVAL_W,PRIOR),state)
        self.assertEqual(state[111:136],b'\x01'+bytes(23)+b'\x80')
        self.assertEqual(state[136:],bytes(64))
        lanes=state_from_bytes(state)
        independent=_bits(state)
        locations=[]
        for byte in range(200):
            for bit in range(8):
                lane,lane_bit=byte//8,8*(byte%8)+bit
                locations.append((lane,lane_bit))
                self.assertEqual((lanes[lane]>>lane_bit)&1,independent[8*byte+bit])
        self.assertEqual(set(locations),{(lane,bit) for lane in range(25) for bit in range(64)})
        self.assertEqual(state_to_bytes(lanes),state)
        # Native word arithmetic is an independent tiny reference, not a graph.
        self.assertEqual(state_to_bytes(keccak_f1600(lanes))[:32],LO)

    def test_all104_fixed_bytes_and96_external_bytes_partition_state0(self):
        import keccak_endpoint as module
        fixed=_fixed_bytes()
        self.assertEqual(module.fixed_frame_bytes(),fixed)
        self.assertEqual(len(fixed),104)
        fixed_indices={index for index,_ in fixed}
        external=set(range(1,33))|set(range(45,109))
        self.assertEqual(len(external),96)
        self.assertFalse(fixed_indices&external)
        self.assertEqual(fixed_indices|external,set(range(200)))
        rng=random.Random(0xe0d59)
        for _ in range(8):
            eval_w=rng.getrandbits(256).to_bytes(32,'little')
            prior=rng.getrandbits(512).to_bytes(64,'little')
            state=module.framed_state_bytes(eval_w,prior)
            self.assertEqual(state,_padded_state(eval_w,prior))
            self.assertTrue(all(state[index]==value for index,value in fixed))
        anchors=[(index,bit,(value>>bit)&1) for index,value in fixed for bit in range(8)]
        self.assertEqual(len(anchors),832)
        self.assertEqual(anchors[120],(111,0,1))
        self.assertEqual(372+120,492)
        self.assertEqual(len(external)*8,768)

    def test_lo_and_fixed_frame_global_maps_are_exact_and_hi_is_external(self):
        import keccak_endpoint as module
        from keccak_permutation import _global_id
        lo_ids=[]
        for lane in range(4):
            for bit in range(64):
                local=f'digest/lo/l{lane}/b{bit}'
                expected=f'state/24/l{lane}/b{bit}'
                self.assertEqual(module.tail_global_id(local),expected)
                self.assertEqual(_global_id(11,f'boundary/output/l{lane}/b{bit}'),expected)
                lo_ids.append(expected)
                hi_local=f'digest/hi/l{lane}/b{bit}'
                self.assertEqual(module.tail_global_id(hi_local),'tail/'+hi_local)
        anchor_ids=[]
        for byte,_ in _fixed_bytes():
            for bit in range(8):
                expected=_state_id(0,byte,bit)
                self.assertEqual(module.tail_global_id(f'frame/byte/{byte}/bit/{bit}'),expected)
                self.assertEqual(_global_id(0,f'boundary/input/l{byte//8}/b{8*(byte%8)+bit}'),expected)
                anchor_ids.append(expected)
        self.assertEqual((len(set(lo_ids)),len(set(anchor_ids))),(256,832))
        self.assertFalse(set(lo_ids)&set(anchor_ids))
        for name in ('digest/byte/0/aux','result/l0','input/byte/0','quotient/byte/32'):
            self.assertEqual(module.tail_global_id(name),'tail/'+name)

    def test_pure_frame_helpers_reject_mutable_wrong_width_and_type_aliases(self):
        import keccak_endpoint as module
        for bad in (None,True,'00',bytearray(32),memoryview(bytes(32)),bytes(31),bytes(33)):
            for helper in (module.rho_preimage,module.framed_state_bytes):
                with self.assertRaises(ValueError):helper(bad,PRIOR)
        for bad in (None,True,'00',bytearray(64),memoryview(bytes(64)),bytes(63),bytes(65)):
            for helper in (module.rho_preimage,module.framed_state_bytes):
                with self.assertRaises(ValueError):helper(EVAL_W,bad)
        # External bytes are not a claimed canonical scalar or source proof port.
        for alias in (Q,Q+1,(1<<256)-1):
            raw=alias.to_bytes(32,'little')
            self.assertEqual(module.rho_preimage(raw,PRIOR),_frame(raw,PRIOR))

    def test_guard_precedes_plan_graph_script_and_io_without_local_bypass(self):
        import keccak_endpoint as module
        for github,runner,platform in [('false','Linux','linux'),('true','Windows','linux'),('true','Linux','win32')]:
            with patch.dict(os.environ,{'GITHUB_ACTIONS':github,'RUNNER_OS':runner},clear=True),\
                patch.object(module.sys,'platform',platform),\
                patch.object(module,'build_keccak_permutation',side_effect=AssertionError('plan allocated')) as plan,\
                patch.object(module,'build_digest_reduction',side_effect=AssertionError('tail allocated')) as tail,\
                patch('builtins.open',side_effect=AssertionError('I/O before resource guard')) as io:
                with self.assertRaisesRegex(ValueError,'hosted GitHub Linux'):
                    module.build_keccak_endpoint(context=None,role=None,operation_id=None)
                empty_plan=object.__new__(module.KeccakEndpointPlan)
                with self.assertRaisesRegex(ValueError,'hosted GitHub Linux'):
                    empty_plan.bind(None,None,None)
                empty_binding=object.__new__(module.KeccakEndpointBinding)
                with self.assertRaisesRegex(ValueError,'hosted GitHub Linux'):
                    empty_binding.iter_pairs()
                with self.assertRaisesRegex(ValueError,'hosted GitHub Linux'):
                    empty_binding.regenerate_tail()
                plan.assert_not_called();tail.assert_not_called();io.assert_not_called()

    def test_pure_alias_parser_and_sealed_factories_reject_external_authority(self):
        import keccak_endpoint as module
        for name in (None,True,'','digest/lo/l4/b0','digest/lo/l0/b64',
            'digest/lo/l0/b00','digest/lo/l00/b0','frame/byte/01/bit/0',
            'frame/byte/1/bit/0','frame/byte/45/bit/0','frame/byte/200/bit/0',
            'frame/byte/111/bit/8','frame/byte/111/bit/00','tail with space','x'*193):
            with self.assertRaises(ValueError):module.tail_global_id(name)
        for cls in (module.KeccakEndpointPlan,module.KeccakEndpointBinding,
                    module.EndpointTail,module.EndpointPairBinding,module.TailDescriptor):
            with self.assertRaises(TypeError):cls()
            self.assertFalse(hasattr(cls,'from_json'))
        for key in ('permutation','tail','program','spec','source_maps','receipt',
                    'event_identity','counter','branch','registry_id','output_key'):
            with self.assertRaises(TypeError):
                module.build_keccak_endpoint(context=CONTEXT,**{key:{'passed':True}})


@unittest.skipUnless(_hosted(),'real13-component endpoint graphs and Script are hosted GitHub Linux only')
class HostedKeccakEndpointTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not _hosted():raise unittest.SkipTest('hosted guard before real plan/graph/Script allocation')
        import keccak_endpoint
        cls.module=keccak_endpoint
        # One real value-independent12-pair plan for this class. Subsequent
        # tests regenerate only the small tail, except one explicit final pair.
        cls.plan=keccak_endpoint.build_keccak_endpoint(context=CONTEXT,
            role='pallas_scalar',operation_id=OPERATION)
        cls.honest=cls.plan.bind(EVAL_W,PRIOR,HI)
        cls.tail=cls.honest.regenerate_tail()

    @staticmethod
    def failures(tail,values):
        bounds=dict(tail.program.words)
        return [ordinal for ordinal,constraint in enumerate(tail.program.constraints)
            if not all(type(values[word]) is int and 0<=values[word]<bounds[word]
                       for word in constraint.wires)
            or not constraint.native(values,tail.program.p)]

    def test_all13_descriptors_and_exact_preserved_digest_projection(self):
        plan,tail=self.plan,self.tail
        values,maps=tail.assignment,tail.source_maps
        child=tail.digest
        self.assertEqual(len(plan.descriptors),13)
        self.assertEqual(plan.descriptors[-1],plan.tail_descriptor)
        self.assertEqual(tail.descriptor,plan.tail_descriptor)
        self.assertEqual((len(tail.program.words),len(tail.program.constraints),len(tail.spec.leaves)),(1787,1204,1205))
        self.assertEqual((sum(item.leaves for item in plan.descriptors),
                          sum(item.words for item in plan.descriptors)),(231715,251497))
        self.assertEqual(plan.summary()['unique_global_words'],232809)
        self.assertEqual(tail.program.words[:955],child.program.words)
        self.assertEqual(tail.program.constraints[:372],child.program.constraints)
        self.assertEqual(tail.program.fields,child.program.fields)
        self.assertEqual(tail.digest_leaf_map,tuple(range(372))+(1204,))
        self.assertEqual(maps['digest_word_map'],list(range(955)))
        self.assertEqual(maps['digest_leaf_map'],list(tail.digest_leaf_map))
        self.assertEqual(tail.spec.field_leaves,(('result',1204),))
        self.assertEqual(maps['canonical_result_leaf'],1204)
        bodies,old_bodies=dict(tail.spec.bodies),dict(child.spec.bodies)
        for before,after in enumerate(tail.digest_leaf_map):
            self.assertEqual(tail.spec.leaves[after],child.spec.leaves[before])
            body=tail.spec.leaves[after].body_sha256
            self.assertEqual(bodies[body],old_bodies[body])
        self.assertEqual(tuple(values[word] for word in child.ports['digest_lo_bits']),_bits(LO))
        self.assertEqual(tuple(values[word] for word in child.ports['digest_hi_bits']),_bits(HI))
        self.assertEqual(child.uniform.result_value,int.from_bytes(RHO,'little'))
        self.assertEqual(self.failures(tail,values),[])
        self.assertEqual(tail.program.bind(values).failures(),())

    def test_all832_anchor_and256_lo_maps_are_bound_to_exact_source_slots(self):
        tail=self.tail
        maps,values=tail.source_maps,tail.assignment
        words=tail.program.words
        positions={name:index for index,(name,_) in enumerate(words)}
        expected_slots=[(byte,bit) for byte,_ in _fixed_bytes() for bit in range(8)]
        self.assertEqual(maps['frame_slots'],[list(item) for item in expected_slots])
        self.assertEqual(tail.anchor_constraints,tuple(range(372,1204)))
        self.assertEqual(maps['anchor_ordinals'],list(tail.anchor_constraints))
        self.assertEqual(len(tail.anchor_words),832)
        fixed=dict(_fixed_bytes())
        for index,((byte,bit),word,ordinal) in enumerate(zip(expected_slots,
                tail.anchor_words,tail.anchor_constraints,strict=True)):
            self.assertEqual(word,f'frame/byte/{byte}/bit/{bit}')
            slot=positions[word]
            self.assertEqual((words[slot][1],values[word]),(2,(fixed[byte]>>bit)&1))
            leaf=tail.spec.leaves[ordinal]
            self.assertEqual((leaf.kind,leaf.argument,leaf.wires),('const',((fixed[byte]>>bit)&1,),(slot,)))
            self.assertEqual(maps['frame_indices'][index],slot)
            self.assertEqual(tail.global_ids[slot],_state_id(0,byte,bit))
        lo_words=tail.digest.ports['digest_lo_bits'];hi_words=tail.digest.ports['digest_hi_bits']
        self.assertEqual(maps['lo_indices'],[positions[word] for word in lo_words])
        self.assertEqual(maps['hi_indices'],[positions[word] for word in hi_words])
        expected_lo=[f'state/24/l{lane}/b{bit}' for lane in range(4) for bit in range(64)]
        self.assertEqual(maps['lo_global_ids'],expected_lo)
        self.assertEqual([tail.global_ids[positions[word]] for word in lo_words],expected_lo)
        self.assertTrue(all(tail.global_ids[positions[word]]=='tail/'+word for word in hi_words))
        self.assertEqual(len(set(tail.global_ids)),1787)
        self.assertEqual(len(maps['private_global_ids']),699)
        self.assertTrue(all(name.startswith('tail/') for name in maps['private_global_ids']))
        self.assertEqual(sha256(_canonical(list(tail.global_ids))).hexdigest(),tail.descriptor.global_ids_sha256)
        self.assertEqual(tail.global_ids[positions['frame/byte/111/bit/0']],_state_id(0,111,0))
        self.assertEqual(tail.anchor_constraints[120],492)

    def test_sealed_identity_is_acyclic_value_independent_and_snapshots_are_fresh(self):
        plan,tail=self.plan,self.tail
        manifest=plan.manifest
        self.assertEqual(manifest['context'],CONTEXT.hex())
        self.assertEqual((manifest['role'],manifest['operation_id']),('pallas_scalar',OPERATION))
        self.assertEqual(manifest['event_identity'],dict(engine='pallas',session=0,
            sequence=103,label_hex='72',counter=59,branch=0))
        self.assertEqual(plan.topology_sha256,sha256(
            self.module.TOPOLOGY_DOMAIN+_canonical(manifest)).digest())
        self.assertEqual(tail.source_sha256,sha256(
            self.module.TAIL_DOMAIN+_canonical(tail.metadata)).digest())
        self.assertEqual(manifest['commitment_order'],
            'external context -> topology -> keys -> registries -> forest')
        for key,new in (('context','09'*32),('role','vesta_scalar'),('operation_id',OPERATION+'/other')):
            changed=json.loads(json.dumps(manifest));changed[key]=new
            self.assertNotEqual(plan.topology_sha256,
                sha256(self.module.TOPOLOGY_DOMAIN+_canonical(changed)).digest())
        changed=json.loads(json.dumps(manifest));changed['event_identity']['counter']=60
        self.assertNotEqual(plan.topology_sha256,
            sha256(self.module.TOPOLOGY_DOMAIN+_canonical(changed)).digest())
        for frozen,name in ((plan,'context'),(self.honest,'hi'),(tail,'source_sha256')):
            with self.assertRaises((FrozenInstanceError,AttributeError)):setattr(frozen,name,b'changed')
        manifest['event_identity']['counter']=60
        self.assertEqual(plan.manifest['event_identity']['counter'],59)
        metadata=tail.metadata;metadata['source_maps']['digest_leaf_map'][0]=-1
        self.assertNotEqual(metadata,tail.metadata)
        maps=tail.source_maps;maps['lo_indices'][0]=-1
        self.assertNotEqual(maps,tail.source_maps)
        values=tail.assignment;values[tail.anchor_words[0]]^=1
        self.assertNotEqual(values,tail.assignment)
        fresh=self.honest.regenerate_tail()
        self.assertIsNot(fresh,tail)
        self.assertEqual((fresh.descriptor,fresh.source_sha256),(tail.descriptor,tail.source_sha256))
        for options in (dict(context=bytes(31)),dict(context=bytearray(32)),
                dict(role='vesta_scalar'),dict(role=True),dict(operation_id='bad operation'),dict(operation_id='x'*180)):
            parameters=dict(context=CONTEXT,role='pallas_scalar',operation_id=OPERATION)
            parameters.update(options)
            with patch.object(self.module,'build_keccak_permutation',side_effect=AssertionError('bad parameters allocated graph')) as child:
                with self.assertRaises(ValueError):self.module.build_keccak_endpoint(**parameters)
                child.assert_not_called()
        for scenario in (None,True,'unknown'):
            with self.assertRaises(ValueError):plan.bind(EVAL_W,PRIOR,HI,scenario=scenario)
        for bad in (bytes(31),bytes(33),bytearray(32),None,True):
            with self.assertRaises(ValueError):plan.bind(bad,PRIOR,HI)
            with self.assertRaises(ValueError):plan.bind(EVAL_W,PRIOR,bad)
        for bad in (bytes(63),bytes(65),bytearray(64),None,True):
            with self.assertRaises(ValueError):plan.bind(EVAL_W,bad,HI)

    def test_coherent_lo_output_and_wrong_padding_have_distinct_refutation_boundaries(self):
        from keccak_trace import keccak_f1600,keccak_f1600_round,state_from_bytes,state_to_bytes
        from script import OPS,execute,num
        honest=self.honest
        self.assertEqual(state_to_bytes(honest.initial_state),_padded_state(EVAL_W,PRIOR))
        self.assertEqual(honest.output_state,keccak_f1600(honest.initial_state))
        self.assertEqual(honest.lo,LO)
        attack=self.plan.bind(EVAL_W,PRIOR,HI,scenario='coherent-output')
        changed_output=list(honest.output_state);changed_output[0]^=1
        self.assertEqual(attack.output_state,tuple(changed_output))
        tail=attack.regenerate_tail()
        self.assertEqual(tail.descriptor,self.tail.descriptor)
        self.assertEqual(self.failures(tail,tail.assignment),[])
        self.assertEqual(tail.program.bind(tail.assignment).failures(),())
        # Regenerate only the final real pair. Its actual first output bit is
        # shared with the coherently re-witnessed reducer; only its producer fails.
        state22=honest.initial_state
        for round_index in range(22):state22=keccak_f1600_round(state22,round_index)
        planned=self.plan.permutation.regenerate_pair(11)
        final=planned.pair.bind(state22,claimed_output=attack.output_state)
        values,spec=final.assignment,final.spec
        failed=[ordinal for ordinal in range(len(spec.leaves)) if not _boolean_truth(spec,values,ordinal)]
        self.assertEqual(len(failed),1)
        leaf=spec.leaves[failed[0]]
        output_slot=next(index for index,(name,_) in enumerate(spec.words) if name=='boundary/output/l0/b0')
        self.assertEqual(leaf.kind,'bool_xor')
        self.assertIn(output_slot,leaf.wires)
        self.assertEqual(planned.global_ids[output_slot],'state/24/l0/b0')
        self.assertIn('state/24/l0/b0',tail.global_ids)
        body=bytes.fromhex(dict(spec.bodies)[leaf.body_sha256])
        witness=[num(values[spec.words[slot][0]]) for slot in leaf.wires]
        self.assertFalse(execute(body,witness).success)
        self.assertTrue(execute(body+bytes([OPS['NOT']]),witness).success)
        del final,planned,spec,values
        padding=self.plan.bind(EVAL_W,PRIOR,HI,scenario='wrong-padding')
        expected=bytearray(_padded_state(EVAL_W,PRIOR));expected[111]^=1
        self.assertEqual(padding.initial_state,state_from_bytes(bytes(expected)))
        self.assertEqual(padding.output_state,keccak_f1600(padding.initial_state))
        padding_tail=padding.regenerate_tail()
        self.assertEqual(padding_tail.descriptor,self.tail.descriptor)
        self.assertEqual(self.failures(padding_tail,padding_tail.assignment),[492])
        bound=padding_tail.program.bind(padding_tail.assignment)
        for disprove in (False,True):
            self.assertEqual(execute(bound.script(492,disprove=disprove),bound.witness(492)).success,disprove)

    def test_fully_rewitnessed_external_message_and_noncanonical_eval_remain_open(self):
        from Cryptodome.Hash import keccak
        prior=bytes(value^0xa5 for value in PRIOR)
        hi=bytes(value^0x3c for value in HI)
        for eval_w in (Q.to_bytes(32,'little'),((1<<256)-1).to_bytes(32,'little')):
            changed=self.plan.bind(eval_w,prior,hi)
            self.assertEqual(changed.lo,keccak.new(digest_bits=256,data=_frame(eval_w,prior)).digest())
            tail=changed.regenerate_tail()
            self.assertEqual(tail.descriptor,self.tail.descriptor)
            self.assertEqual(tail.source_sha256,self.tail.source_sha256)
            self.assertEqual(self.failures(tail,tail.assignment),[])
            self.assertEqual(tail.program.bind(tail.assignment).failures(),())
            self.assertEqual(changed.summary()['topology_sha256'],self.plan.topology_sha256.hex())
            for summary in (self.plan.summary(),changed.summary()):
                for name in FALSE_FLAGS:self.assertIs(summary[name],False)
            self.assertNotEqual(changed.lo,LO)
            self.assertEqual(changed.hi,hi)
            self.assertTrue(all(tail.global_ids[index].startswith('tail/') for index in tail.source_maps['hi_indices']))

    def test_canonical_result_and_all_original_reduction_anchors_remain_intact(self):
        from script import OPS,execute,num
        tail=self.tail
        uniform=tail.digest.uniform
        for name,ordinal in uniform.anchor_constraints.items():
            self.assertEqual(tail.program.constraints[ordinal],uniform.program.constraints[ordinal],name)
        self.assertEqual(tail.digest.uniform_leaf_map[244],372)
        self.assertEqual(tail.digest_leaf_map[372],1204)
        values=tail.assignment
        for index,word in enumerate(tail.digest.ports['result_field']):values[word]=(Q>>(29*index))&(BASE-1)
        with self.assertRaises(ValueError):tail.program.bind(values)
        leaf=tail.spec.leaves[1204]
        self.assertEqual(leaf.kind,'field_valid')
        body=bytes.fromhex(dict(tail.spec.bodies)[leaf.body_sha256])
        witness=[num(values[tail.spec.words[slot][0]]) for slot in leaf.wires]
        self.assertFalse(execute(body,witness).success)
        self.assertTrue(execute(body+bytes([OPS['NOT']]),witness).success)

    def test_exact_witness_guards_cover_both_anchor_values_and_preserved_tail_kinds(self):
        from script import execute
        tail=self.tail
        bound=tail.program.bind(tail.assignment)
        selected={}
        # Preserve each original predicate kind, plus the distinct8-bit byte
        # reconstruction and both const0/const1 framing anchors.
        for ordinal,constraint in enumerate(tail.program.constraints):
            key=(constraint.kind,constraint.argument if constraint.kind in ('const','bits','conv_reconstruct') else ())
            selected.setdefault(key,ordinal)
        self.assertTrue({('const',(0,)),('const',(1,)),('bits',(8,)),('conv_reconstruct',(8,))}<=set(selected))
        for ordinal in tail.anchor_constraints:
            value=tail.program.constraints[ordinal].argument[0]
            selected.setdefault(('frame_const',value),ordinal)
        self.assertTrue({('frame_const',0),('frame_const',1)}<=set(selected))
        selected[('padding_const',1)]=492
        for ordinal in selected.values():
            witness=bound.witness(ordinal)
            for disprove in (False,True):
                code=bound.script(ordinal,disprove=disprove)
                self.assertEqual(execute(code,witness).success,not disprove)
                for malformed in ((),witness[:-1],(b'',)+witness,witness+(b'',)):
                    result=execute(code,malformed)
                    self.assertFalse(result.success)
                    self.assertEqual(result.error,'EQUALVERIFY')


if __name__=='__main__':
    unittest.main()

