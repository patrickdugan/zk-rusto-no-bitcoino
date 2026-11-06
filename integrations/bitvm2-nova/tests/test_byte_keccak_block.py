"""Pure map/guard tests and HOSTED-ONLY sealed four-round BYTE conformance.

No local test constructs a round/block Program, compiles a full graph, signs
WOTS values, runs native code or proves. Shared-word counts describe topology;
the hosted native harness separately checks actual cached signatures/openings.
"""
from collections import Counter
from dataclasses import FrozenInstanceError
from hashlib import sha256
import json
import os
import random
import sys
import unittest
from unittest.mock import patch

CONTEXT=sha256(b'byte-keccak-block-tests/caller-owned-context').digest()
OPERATION='tests/byte-keccak/block'
ROLES=('pallas_scalar','vesta_scalar')
FALSE_FLAGS=('full_permutation_verified','full_hash_verified','transcript_verified',
    'nova_transcript_verified','proof_verified','bitvm2_script_verified',
    'production_assertion_binding','bitcoin_transaction_graph','hash_verified',
    'full_permutation_verified_in_script','padding_bound_in_script',
    'absorption_bound_in_script','squeeze_bound_in_script')


def _hosted():
    return (os.environ.get('GITHUB_ACTIONS')=='true'
        and os.environ.get('RUNNER_OS')=='Linux' and sys.platform=='linux')


def _canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,
                      allow_nan=False).encode('ascii')


def _constants():
    lfsr=1
    result=[]
    for _ in range(24):
        value=0
        for bit in range(7):
            if lfsr&1:value^=1<<((1<<bit)-1)
            lfsr=((lfsr<<1)^(0x71 if lfsr&0x80 else 0))&255
        result.append(value)
    return tuple(result)


IOTA_CONSTANTS=_constants()


def _producer(round_index,slot):
    lane,byte=divmod(slot,8)
    masks=IOTA_CONSTANTS[round_index].to_bytes(8,'little')
    return (1216+sum(mask!=0 for mask in masks[:byte]) if lane==0 and masks[byte]
            else 1016+8*lane+byte)


def _consumers(slot):
    lane,byte=divmod(slot,8)
    x,y=lane%5,lane//5
    return ((32*x+4*byte+max(y-1,0),0 if y==0 else 1),
            (240+8*lane+byte,0))


def _reference(initial,first):
    current=initial
    boundaries=[]
    for round_index in range(first,first+4):
        current=_one_round(current,round_index)
        boundaries.append(current)
    return tuple(boundaries)


def _one_round(initial,round_index):
    from keccak_trace import keccak_f1600_round
    lanes=tuple(int.from_bytes(initial[index:index+8],'little') for index in range(0,200,8))
    return b''.join(value.to_bytes(8,'little') for value in keccak_f1600_round(lanes,round_index))


def _partition(wires):
    unique=tuple(dict.fromkeys(wires))
    return tuple(unique.index(word) for word in wires)


def _tiny_ids(first=0,ports=2):
    return tuple(tuple(f'byte-state/{first+child}/l0/byte{slot}' for slot in range(ports))
        +tuple(f'byte-state/{first+child+1}/l0/byte{slot}' for slot in range(ports))
        +(f'byte-round/{first+child}/same/internal',f'byte-round/{first+child}/another/internal')
        for child in range(4))


def _quotient(child_ids):
    names=[]
    indices={}
    maps=[]
    for ids in child_ids:
        child=[]
        for name in ids:
            if name not in indices:
                indices[name]=len(names);names.append(name)
            child.append(indices[name])
        maps.append(tuple(child))
    return tuple(maps),tuple((name,256) for name in names)


class ByteBlockPureMapsAndGuards(unittest.TestCase):
    def test_all21_absolute_round_ranges_and_domain_operation_ids(self):
        import byte_keccak_block as module
        for first in range(21):
            self.assertEqual(module.block_rounds(first),tuple(range(first,first+4)))
            self.assertEqual(module.parent_operation_id(first,OPERATION),f'{OPERATION}/rounds/{first}-{first+3}')
        for invalid in (True,False,-1,21,1.0,'0',None):
            with self.assertRaises(ValueError):module.block_rounds(invalid)
            with self.assertRaises(ValueError):module.parent_operation_id(invalid,OPERATION)
        for invalid in ('','bad operation','x'*193,True,None):
            with self.assertRaises(ValueError):module.parent_operation_id(0,invalid)

    def test_independent_census_and_scattered_producer_formal_slots(self):
        constants=_constants()
        aligned={0:4873,4:4875,8:4871,12:4875,16:4874,20:4877}
        for first in range(21):
            masks=[constants[round_index].to_bytes(8,'little') for round_index in range(first,first+4)]
            leaves=4864+sum(mask!=0 for row in masks for mask in row)
            if first in aligned:self.assertEqual(leaves,aligned[first])
            self.assertEqual(leaves+200,4*1416+sum(mask!=0 for row in masks for mask in row)-600)
            for child in range(4):
                row=masks[child]
                producers=tuple(_producer(first+child,slot) for slot in range(200))
                self.assertEqual(len(set(producers)),200)
                self.assertTrue(all(0<=ordinal<1216+sum(byte!=0 for byte in row) for ordinal in producers))
                self.assertEqual(producers[8],1024)  # lane1/byte0 is a Chi output, not a suffix copy.
        occurrences=[_consumers(slot) for slot in range(200)]
        self.assertEqual(len({(ordinal,formal) for pair in occurrences for ordinal,formal in pair}),400)
        self.assertEqual((3*len(occurrences),3*sum(map(len,occurrences))),(600,1200))
        self.assertEqual(_consumers(0),((0,0),(240,0)))
        self.assertEqual(_consumers(40),((0,1),(280,0)))

    def test_resource_guard_precedes_children_catalogue_binding_and_io(self):
        import byte_keccak_block as module
        for github,runner,platform in [('false','Linux','linux'),('true','Windows','linux'),('true','Linux','win32')]:
            with patch.dict(os.environ,{'GITHUB_ACTIONS':github,'RUNNER_OS':runner},clear=True),\
                patch.object(module.sys,'platform',platform),\
                patch.object(module,'build_byte_keccak_round',side_effect=AssertionError('child graph allocated')) as child,\
                patch.object(module.GraphSpec,'from_program',side_effect=AssertionError('catalogue allocated')) as spec,\
                patch('builtins.open',side_effect=AssertionError('I/O before resource guard')) as io:
                with self.assertRaisesRegex(ValueError,'hosted GitHub Linux'):
                    module.build_byte_keccak_block(None,context=None,role=None,operation_id=None)
                empty=object.__new__(module.ByteKeccakBlock)
                with self.assertRaisesRegex(ValueError,'hosted GitHub Linux'):empty.bind(None)
                child.assert_not_called();spec.assert_not_called();io.assert_not_called()
        for cls in (module.ByteKeccakBlock,module.ByteKeccakBlockBinding,module.ByteBlockJoin):
            with self.assertRaises(TypeError):cls()
            self.assertFalse(hasattr(cls,'from_json'))
        for key in ('children','program','spec','source_maps','receipt','manifest','assignment',
                    'inputs','outputs','producer_ordinals','global_ids','joins','version'):
            with self.assertRaises(TypeError):
                module.build_byte_keccak_block(0,context=CONTEXT,role='pallas_scalar',**{key:{'passed':True}})

    def test_tiny_first_encounter_quotient_has_exact_adjacent_intersections(self):
        import byte_keccak_block as module
        for first in range(21):
            ids=_tiny_ids(first)
            maps,words=_quotient(ids)
            module._validate_maps(first,ids,maps,words,port_count=2)
            self.assertEqual(len(words),18)
            self.assertEqual(len(set(name for name,_ in words)),18)
            for child,mapping in enumerate(maps):
                self.assertEqual(len(set(mapping)),len(mapping))
                self.assertEqual(tuple(words[index][0] for index in mapping),ids[child])
                for later in range(child+1,4):
                    shared=set(mapping)&set(maps[later])
                    expected=set(mapping[2:4]) if later==child+1 else set()
                    self.assertEqual(shared,expected)
            self.assertEqual(maps[0][2:4],maps[1][:2])
            self.assertNotEqual(maps[0][-1],maps[1][-1],'equal local spelling cannot choose aliases')

    def test_tiny_missing_duplicate_reordered_split_and_unintended_alias_maps_reject(self):
        import byte_keccak_block as module
        ids=_tiny_ids()
        maps,words=_quotient(ids)
        variants=[]
        missing=[list(mapping) for mapping in maps];missing[1].pop()
        variants.append(tuple(tuple(mapping) for mapping in missing))
        duplicate=[list(mapping) for mapping in maps];duplicate[0][-1]=duplicate[0][0]
        variants.append(tuple(tuple(mapping) for mapping in duplicate))
        swapped=[list(mapping) for mapping in maps];swapped[1][0],swapped[1][1]=swapped[1][1],swapped[1][0]
        variants.append(tuple(tuple(mapping) for mapping in swapped))
        split=[list(mapping) for mapping in maps];split[1][0]=len(words)
        variants.append(tuple(tuple(mapping) for mapping in split))
        for changed in variants:
            with self.assertRaises(ValueError):module._validate_maps(0,ids,changed,words,port_count=2)
        for child in (1,2):
            changed=[list(item) for item in ids]
            changed[child][-1]=changed[0][-1]  # Adjacent extra alias or nonadjacent alias.
            changed=tuple(tuple(item) for item in changed)
            changed_maps,changed_words=_quotient(changed)
            with self.assertRaises(ValueError):module._validate_maps(0,changed,changed_maps,changed_words,port_count=2)
        changed=[list(item) for item in ids];changed[0][0]='byte-state/22/l0/byte0'
        changed=tuple(tuple(item) for item in changed)
        changed_maps,changed_words=_quotient(changed)
        with self.assertRaises(ValueError):module._validate_maps(0,changed,changed_maps,changed_words,port_count=2)
        # These transport helpers never import values, so even all-zero
        # witnesses could not justify merging unrelated identities.
        for changed_words in (words[:-1]+((words[-1][0],2),),words[:-1]+((words[-1][0],256.0),),
                              words+(('unused/extra',256),),list(words)):
            with self.assertRaises(ValueError):module._validate_maps(0,ids,maps,changed_words,port_count=2)
        for count in (True,0,201,2.0):
            with self.assertRaises(ValueError):module._validate_maps(0,ids,maps,words,port_count=count)


@unittest.skipUnless(_hosted(),'actual four-round BYTE graphs and Script are hosted GitHub Linux only')
class HostedByteKeccakBlockTests(unittest.TestCase):
    def setUp(self):
        if not _hosted():self.skipTest('hosted guard before actual four-round graph/Script allocation')
        import byte_keccak_block
        self.module=byte_keccak_block

    def build(self,first,role='pallas_scalar',*,context=CONTEXT,operation=OPERATION):
        return self.module.build_byte_keccak_block(first,context=context,role=role,operation_id=operation)

    def assert_projection(self,block,first,role):
        program,spec,maps=block.program,block.spec,block.source_maps
        expected_leaves=4864+sum(byte!=0 for round_index in range(first,first+4)
            for byte in IOTA_CONSTANTS[round_index].to_bytes(8,'little'))
        self.assertEqual((len(program.words),len(program.constraints),len(spec.leaves)),
                         (expected_leaves+200,expected_leaves,expected_leaves))
        self.assertEqual((program.field_role,program.context,program.fields),(role,CONTEXT,()))
        self.assertEqual(program.operation_id,f'{OPERATION}/rounds/{first}-{first+3}')
        self.assertEqual(spec.words,program.words)
        self.assertEqual(spec.field_leaves,())
        self.assertTrue(all(type(bound) is int and bound==256 for _,bound in program.words))
        self.assertEqual(block.global_ids,tuple(name for name,_ in program.words))
        self.assertEqual(len(set(block.global_ids)),len(program.words))
        self.assertEqual(maps['global_ids'],list(block.global_ids))
        self.assertEqual(maps['global_ids_sha256'],sha256(_canonical(list(block.global_ids))).hexdigest())
        self.assertEqual((len(block.children),len(maps['children'])),(4,4))
        self.assertEqual(maps['first_round'],first)
        covered_words=set();covered_leaves=set();offset=0
        parent_bodies=dict(spec.bodies)
        images=[]
        for index,(child,record) in enumerate(zip(block.children,maps['children'],strict=True)):
            r=first+index
            self.assertEqual(child.round_index,r)
            self.assertEqual((child.role,child.context),(role,CONTEXT))
            self.assertEqual(child.operation_id,f'{OPERATION}/child/{index}')
            self.assertEqual(child.program.operation_id,f'{OPERATION}/child/{index}/round/{r}')
            for name,expected in (('index',index),('round_index',r),
                    ('operation_id',child.operation_id),('program_operation_id',child.program.operation_id),
                    ('source_sha256',child.source_sha256.hex()),('program_sha256',child.program.digest().hex()),
                    ('catalogue_id',child.spec.digest().hex()),
                    ('global_ids_sha256',sha256(_canonical(list(child.global_ids))).hexdigest())):
                self.assertEqual(record[name],expected)
            word_map=record['word_map'];leaf_map=record['leaf_map']
            self.assertEqual(len(word_map),len(child.spec.words))
            self.assertEqual(len(set(word_map)),len(word_map))
            self.assertEqual(leaf_map,list(range(offset,offset+len(child.spec.leaves))))
            self.assertEqual(tuple(program.words[parent][0] for parent in word_map),child.global_ids)
            self.assertTrue(all(program.words[parent][1]==child.spec.words[local][1]==256
                for local,parent in enumerate(word_map)))
            child_maps=child.source_maps
            self.assertEqual(record['input_indices'],[word_map[slot] for slot in child_maps['input_indices']])
            self.assertEqual(record['output_indices'],[word_map[slot] for slot in child_maps['output_indices']])
            expected_producers=[leaf_map[_producer(r,slot)] for slot in range(200)]
            self.assertEqual(record['producer_ordinals'],expected_producers)
            expected_producer_occurrences=[len(program.constraints[ordinal].wires)-1
                for ordinal in expected_producers]
            self.assertEqual(record['producer_occurrences'],expected_producer_occurrences)
            expected_consumers=[[[leaf_map[ordinal],formal] for ordinal,formal in _consumers(slot)]
                for slot in range(200)]
            self.assertEqual(record['input_consumer_occurrences'],expected_consumers)
            child_bodies=dict(child.spec.bodies)
            for local,parent in enumerate(leaf_map):
                old,new=child.spec.leaves[local],spec.leaves[parent]
                self.assertEqual((new.kind,new.argument,new.body_sha256),(old.kind,old.argument,old.body_sha256))
                self.assertEqual(new.wires,tuple(word_map[word] for word in old.wires))
                self.assertEqual(_partition(new.wires),_partition(old.wires))
                self.assertEqual(parent_bodies[new.body_sha256],child_bodies[old.body_sha256])
                original=child.program.constraints[local]
                remapped=program.constraints[parent]
                self.assertEqual((remapped.kind,remapped.argument),(original.kind,original.argument))
                self.assertEqual(remapped.wires,tuple(program.words[slot][0] for slot in new.wires))
            covered_words.update(word_map);covered_leaves.update(leaf_map)
            images.append(set(word_map));offset+=len(child.spec.leaves)
        self.assertEqual(covered_words,set(range(len(program.words))))
        self.assertEqual(covered_leaves,set(range(len(spec.leaves))))
        for left in range(4):
            for right in range(left+1,4):
                shared=images[left]&images[right]
                expected=set(maps['children'][left]['output_indices']) if right==left+1 else set()
                self.assertEqual(shared,expected)
        self.assertEqual(maps['input_indices'],maps['children'][0]['input_indices'])
        self.assertEqual(maps['output_indices'],maps['children'][3]['output_indices'])
        self.assertEqual(block.inputs,tuple(program.words[index][0] for index in maps['input_indices']))
        self.assertEqual(block.outputs,tuple(program.words[index][0] for index in maps['output_indices']))
        self.assertEqual(block.producer_ordinals,tuple(maps['children'][3]['producer_ordinals']))
        self.assertEqual(maps['producer_ordinals'],list(block.producer_ordinals))
        self.assertEqual(maps['producer_occurrences'],maps['children'][3]['producer_occurrences'])
        self.assertEqual(block.producer_occurrences,tuple(maps['producer_occurrences']))
        self.assertEqual((len(set(block.inputs)),len(set(block.outputs))),(200,200))
        self.assertFalse(set(block.inputs)&set(block.outputs))
        seen=set(block.inputs);produced={};consumed=Counter()
        for ordinal,constraint in enumerate(program.constraints):
            self.assertTrue(all(word in seen for word in constraint.wires[:-1]))
            out=constraint.wires[-1]
            self.assertNotIn(out,seen)
            seen.add(out);produced[out]=ordinal;consumed.update(constraint.wires[:-1])
        self.assertEqual(seen,set(block.global_ids))
        self.assertEqual(set(produced)-set(consumed),set(block.outputs))
        self.assertEqual(block.producer_ordinals,tuple(produced[word] for word in block.outputs))
        for child in maps['children'][:3]:
            internal_outputs={program.words[index][0] for index in child['output_indices']}
            self.assertFalse(internal_outputs&set(block.outputs))
            self.assertTrue(all(consumed[word]==2 for word in internal_outputs))
        self.assertEqual(len(block.joins),3)
        all_join_words=set();opening_occurrences=0
        for index,join in enumerate(block.joins):
            expected_words=tuple(f'byte-state/{first+index+1}/l{lane}/byte{byte}'
                for lane in range(25) for byte in range(8))
            self.assertEqual((join.index,join.state_round),(index,first+index+1))
            self.assertEqual(join.words,expected_words)
            self.assertEqual(tuple(join.indices),tuple(maps['children'][index]['output_indices']))
            self.assertEqual(tuple(join.indices),tuple(maps['children'][index+1]['input_indices']))
            self.assertEqual(tuple(join.producer_ordinals),tuple(maps['children'][index]['producer_ordinals']))
            self.assertEqual(maps['joins'][index]['producer_occurrences'],maps['children'][index]['producer_occurrences'])
            self.assertEqual(tuple(join.producer_occurrences),tuple(maps['joins'][index]['producer_occurrences']))
            for slot,(word,parent_slot,producer,occurrences) in enumerate(zip(join.words,join.indices,
                    join.producer_ordinals,join.consumer_occurrences,strict=True)):
                self.assertEqual(program.words[parent_slot],(word,256))
                producing=program.constraints[producer]
                self.assertEqual(producing.wires[-1],word)
                producer_formal=len(producing.wires)-1
                self.assertEqual(maps['joins'][index]['producer_occurrences'][slot],producer_formal)
                self.assertEqual(producer_formal,1 if producing.kind=='byte_xor_const' else 2)
                expected=tuple(tuple(item) for item in maps['children'][index+1]['input_consumer_occurrences'][slot])
                self.assertEqual(tuple(tuple(item) for item in occurrences),expected)
                self.assertEqual(len(occurrences),2)
                for consumer,formal in occurrences:
                    self.assertEqual(program.constraints[consumer].wires[formal],word)
                    opening_occurrences+=1
            self.assertFalse(all_join_words&set(join.words))
            all_join_words.update(join.words)
        self.assertEqual((len(all_join_words),opening_occurrences),(600,1200))

    def test_all21_starts_both_roles_preserve_sources_and_reference_one_binding_at_a_time(self):
        program_ids=set();source_ids=set()
        for role in ROLES:
            for first in range(21):
                block=self.build(first,role)
                self.assert_projection(block,first,role)
                self.assertNotIn(block.program.digest(),program_ids)
                self.assertNotIn(block.source_sha256,source_ids)
                program_ids.add(block.program.digest());source_ids.add(block.source_sha256)
                initial=bytes(200) if first==0 else bytes((37*index+first)&255 for index in range(200))
                binding=block.bind(initial)
                reference=_reference(initial,first)
                self.assertEqual((binding.initial_state,binding.boundaries,binding.output_state,binding.reference_output),
                    (initial,reference[:3],reference[-1],reference[-1]))
                self.assertEqual((binding.program.digest(),binding.spec.digest()),(block.program.digest(),block.spec.digest()))
                self.assertEqual(binding.global_ids,block.global_ids)
                values=binding.assignment
                self.assertEqual(binding.program.bind(values).failures(),())
                self.assertEqual(bytes(values[word] for word in block.inputs),initial)
                self.assertEqual(bytes(values[word] for word in block.outputs),reference[-1])
                for index,child_binding in enumerate(binding.children):
                    self.assertEqual(child_binding.initial_state,initial if index==0 else reference[index-1])
                    self.assertEqual(child_binding.output_state,reference[index])
                    self.assertEqual(child_binding.round.source_sha256,block.children[index].source_sha256)
                    child_values=child_binding.assignment
                    for local,parent in enumerate(block.source_maps['children'][index]['word_map']):
                        self.assertEqual(values[block.program.words[parent][0]],child_values[child_binding.spec.words[local][0]])
                    del child_values
                del child_binding
                for summary in (block.summary(),binding.summary()):
                    for flag in FALSE_FLAGS:self.assertIs(summary[flag],False)
                del values,binding,block
        self.assertEqual((len(program_ids),len(source_ids)),(42,42))

    def test_each_middle_state_chi_and_iota_override_rewitnesses_all_downstream_children(self):
        from script import execute
        initial=bytes(range(200))
        for role in ROLES:
            block=self.build(0,role)
            honest_reference=_reference(initial,0)
            for join_index in range(3):
                masks=IOTA_CONSTANTS[join_index].to_bytes(8,'little')
                iota_slot=next(byte for byte,mask in enumerate(masks) if mask)
                for slot in (iota_slot,8):
                    changed=bytearray(honest_reference[join_index]);changed[slot]^=1
                    claims=[None,None,None];claims[join_index]=bytes(changed)
                    binding=block.bind(initial,boundary_claims=tuple(claims))
                    values=binding.assignment
                    bound=binding.program.bind(values)
                    producer=block.joins[join_index].producer_ordinals[slot]
                    self.assertEqual(bound.failures(),(producer,))
                    self.assertEqual(binding.boundaries[:join_index],honest_reference[:join_index])
                    self.assertEqual(binding.boundaries[join_index],bytes(changed))
                    self.assertEqual(binding.reference_output,honest_reference[-1])
                    current=bytes(changed)
                    for round_index in range(join_index+1,4):current=_one_round(current,round_index)
                    self.assertEqual(binding.output_state,current)
                    self.assertEqual(binding.program.digest(),block.program.digest())
                    self.assertEqual(binding.block.source_sha256,block.source_sha256)
                    for index,child_binding in enumerate(binding.children):
                        expected=(_producer(index,slot),) if index==join_index else ()
                        child_bound=child_binding.program.bind(child_binding.assignment)
                        self.assertEqual(child_bound.failures(),expected)
                        if index>join_index:
                            self.assertEqual(child_binding.output_state,child_binding.reference_output)
                        if index:
                            self.assertEqual(child_binding.initial_state,binding.children[index-1].output_state)
                        del child_bound
                    del child_binding
                    shared=block.joins[join_index]
                    self.assertEqual(bytes(values[word] for word in shared.words),bytes(changed))
                    producing=block.program.constraints[producer]
                    self.assertEqual(producing.kind,'byte_xor_const' if slot==iota_slot else 'byte_xor')
                    formal=shared.producer_occurrences[slot]
                    self.assertEqual(formal,1 if slot==iota_slot else 2)
                    self.assertEqual(producing.wires[formal],shared.words[slot])
                    for consumer,consumer_formal in shared.consumer_occurrences[slot]:
                        self.assertEqual(block.program.constraints[consumer].wires[consumer_formal],shared.words[slot])
                    for disprove in (False,True):
                        result=execute(bound.script(producer,disprove=disprove),bound.witness(producer))
                        self.assertEqual(result.success,disprove)
                        self.assertIsNone(result.error)
                    del values,bound,binding
            # Final output mutations have no downstream consumer to re-witness.
            final_masks=IOTA_CONSTANTS[3].to_bytes(8,'little')
            for slot in (next(byte for byte,mask in enumerate(final_masks) if mask),8):
                output=bytearray(honest_reference[-1]);output[slot]^=1
                binding=block.bind(initial,claimed_output=bytes(output))
                bound=binding.program.bind(binding.assignment)
                producer=block.producer_ordinals[slot]
                self.assertEqual(bound.failures(),(producer,))
                self.assertEqual(binding.boundaries,honest_reference[:3])
                self.assertEqual((binding.output_state,binding.reference_output),(bytes(output),honest_reference[-1]))
                for disprove in (False,True):
                    result=execute(bound.script(producer,disprove=disprove),bound.witness(producer))
                    self.assertEqual(result.success,disprove);self.assertIsNone(result.error)
                del bound,binding
            del block

    def test_sealed_value_independent_source_program_domains_and_foreign_admission(self):
        from trace import Program
        block=self.build(0)
        first=block.bind(bytes(200))
        changed=block.bind(bytes([255])*200,boundary_claims=(None,None,None),claimed_output=None)
        self.assertEqual((first.program.digest(),first.spec.digest()),(changed.program.digest(),changed.spec.digest()))
        self.assertEqual(first.block.source_sha256,changed.block.source_sha256)
        self.assertNotEqual(first.assignment,changed.assignment)
        self.assertEqual(first.program.bind(first.assignment).failures(),())
        self.assertEqual(changed.program.bind(changed.assignment).failures(),())
        manifest=block.manifest
        self.assertEqual(self.module.SOURCE_DOMAIN,b'BITVM2-NOVA/BYTE-KECCAK-BLOCK/v1\x00')
        self.assertEqual(block.source_sha256,sha256(
            b'BITVM2-NOVA/BYTE-KECCAK-BLOCK/v1\x00'+_canonical(manifest)).digest())
        plain=Program(block.program.field_role,block.program.operation_id,block.program.context,
                      block.program.words,block.program.fields,block.program.constraints)
        self.assertEqual(block.program.digest(),sha256(b'BITVM2-NOVA/BYTE-TRACE/v1\x00'+plain.digest()).digest())
        self.assertEqual((manifest['first_round'],manifest['last_round']),(0,3))
        self.assertEqual((manifest['operation_id'],manifest['program_operation_id']),
                         (OPERATION,f'{OPERATION}/rounds/0-3'))
        self.assertEqual((manifest['program_sha256'],manifest['catalogue_id']),
                         (block.program.digest().hex(),block.spec.digest().hex()))
        self.assertEqual(manifest['commitment_order'],
                         'external context -> source topology -> keys -> registry -> Script')
        forbidden={'assignment','initial_state','output_state','claimed_output','receipt',
                   'registry_id','key_catalogue_sha256','signature_catalogue_sha256',
                   'merkle_root','output_key','transaction_id'}
        def visit(value):
            if isinstance(value,dict):
                self.assertFalse(forbidden&set(value))
                for child in value.values():visit(child)
            elif isinstance(value,(list,tuple)):
                for child in value:visit(child)
        visit(manifest)
        for obj,attribute in ((block,'context'),(first,'initial_state'),(block.joins[0],'words')):
            with self.assertRaises((FrozenInstanceError,AttributeError)):setattr(obj,attribute,b'changed')
        mutated=block.source_maps;mutated['children'][0]['word_map'][0]=-1
        self.assertNotEqual(mutated,block.source_maps)
        manifest['source_maps']['joins'][0]['indices'][0]=-1
        self.assertNotEqual(manifest,block.manifest)
        altered=block.joins[0].json();altered['producer_occurrences'][0]=-1
        self.assertNotEqual(altered,block.joins[0].json())
        values=first.assignment;values[block.inputs[0]]^=1
        self.assertNotEqual(values,first.assignment)
        committed=first.program.bind(first.assignment)
        for options in (dict(first=1),dict(role='vesta_scalar'),dict(context=bytes(32)),
                        dict(operation=OPERATION+'/other')):
            parameters=dict(first=0,role='pallas_scalar',context=CONTEXT,operation=OPERATION)
            parameters.update(options)
            other=self.build(**parameters)
            self.assertNotEqual(other.program.digest(),block.program.digest())
            self.assertNotEqual(other.spec.digest(),block.spec.digest())
            self.assertNotEqual(other.source_sha256,block.source_sha256)
            with self.assertRaises(ValueError):committed.require_identity(other.program.digest(),committed.claim_digest)
            del other
        committed.require_identity(block.program.digest(),committed.claim_digest)
        with self.assertRaises(ValueError):committed.require_identity(block.program.digest(),bytes(32))
        with self.assertRaises(ValueError):committed.require_identity(bytes(32),committed.claim_digest)
        for summary in (block.summary(),first.summary(),changed.summary()):
            for flag in FALSE_FLAGS:self.assertIs(summary[flag],False)

    def test_types_and_all_derived_id_caps_reject_before_first_child_allocation(self):
        for options in (dict(first=True),dict(first=-1),dict(first=21),dict(role=True),
                        dict(role='unknown'),dict(context=bytes(31)),dict(context=bytearray(32)),
                        dict(operation='bad operation'),dict(first=20,operation='x'*180),
                        dict(first=20,operation='x'*176),dict(first=9,operation='x'*176)):
            parameters=dict(first=0,role='pallas_scalar',context=CONTEXT,operation=OPERATION)
            parameters.update(options)
            with patch.object(self.module,'build_byte_keccak_round',side_effect=AssertionError('invalid parameters allocated first child')) as child:
                with self.assertRaises(ValueError):self.build(**parameters)
                child.assert_not_called()
        # At first9 the first child ID fits192 bytes but a later round10 ID
        # needs193. Validating only child0 would allocate before rejecting.
        self.assertEqual(len('x'*176+'/child/0/round/9'),192)
        self.assertEqual(len('x'*176+'/child/1/round/10'),193)
        block=self.build(0)
        with patch.object(self.module.ByteKeccakRound,'bind',side_effect=AssertionError('invalid claim regenerated child')) as child:
            for bad in (None,True,bytes(199),bytes(201),bytearray(200)):
                with self.assertRaises(ValueError):block.bind(bad)
            for bad in (True,bytes(199),bytes(201),bytearray(200)):
                with self.assertRaises(ValueError):block.bind(bytes(200),claimed_output=bad)
            for claims in (None,True,(),(None,None),(None,)*4,[None,None,None],
                           (True,None,None),(bytes(199),None,None),(bytearray(200),None,None)):
                with self.assertRaises(ValueError):block.bind(bytes(200),boundary_claims=claims)
            child.assert_not_called()
        default=block.bind(bytes(200))
        explicit=block.bind(bytes(200),boundary_claims=(None,None,None),claimed_output=None)
        self.assertEqual(default.assignment,explicit.assignment)
        self.assertEqual(default.output_state,explicit.output_state)

    def test_exact_witness_lengths_openings_and_claim_guards_both_modes(self):
        from script import execute,num
        for role in ROLES:
            block=self.build(0,role)
            binding=block.bind(bytes(range(200)))
            values=binding.assignment;bound=binding.program.bind(values)
            selected={}
            for ordinal,constraint in enumerate(block.program.constraints):selected.setdefault(constraint.kind,ordinal)
            self.assertEqual(set(selected),{'byte_xor','byte_and','byte_not','byte_rol','byte_xor_const'})
            for join in block.joins:
                selected[('join-chi',join.index)]=join.producer_ordinals[8]
                mask=IOTA_CONSTANTS[join.state_round-1].to_bytes(8,'little')
                slot=next(byte for byte,value in enumerate(mask) if value)
                selected[('join-iota',join.index)]=join.producer_ordinals[slot]
            for ordinal in selected.values():
                witness=bound.witness(ordinal)
                for disprove in (False,True):
                    code=bound.script(ordinal,disprove=disprove)
                    self.assertEqual(execute(code,witness).success,not disprove)
                    for malformed in ((),witness[:-1],(b'',)+witness,witness+(b'',)):
                        result=execute(code,malformed)
                        self.assertFalse(result.success);self.assertEqual(result.error,'EQUALVERIFY')
                    first=block.program.constraints[ordinal].wires[0]
                    substituted=(num(values[first]^1),)+witness[1:]
                    result=execute(code,substituted)
                    self.assertFalse(result.success);self.assertEqual(result.error,'EQUALVERIFY')
            bound.require_identity(block.program.digest(),bound.claim_digest)
            with self.assertRaises(ValueError):bound.require_identity(bytes(32),bound.claim_digest)
            with self.assertRaises(ValueError):bound.require_identity(block.program.digest(),bytes(32))
            del values,bound,binding,block


if __name__=='__main__':
    unittest.main()

