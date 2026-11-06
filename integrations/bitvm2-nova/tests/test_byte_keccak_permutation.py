"""Tiny local source-map tests; all full BYTE graphs are HOSTED ONLY.

The24-round parent is a GraphSpec with a versioned manifest identity, never an
oversized Program. Local tests allocate only small symbolic tuples and perform
no Script, full graph, native process, key generation or proving work.
"""
from collections import Counter
from dataclasses import FrozenInstanceError
from hashlib import sha256
import gc
import json
import os
import sys
import unittest
import weakref
from unittest.mock import patch

CONTEXT=sha256(b'byte-keccak-permutation-tests/caller-owned-context').digest()
OPERATION='tests/byte-keccak/permutation'
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


CONSTANTS=_constants()
ROUND_LEAVES=tuple(1216+sum(byte!=0 for byte in value.to_bytes(8,'little')) for value in CONSTANTS)
ROUND_OFFSETS=tuple(sum(ROUND_LEAVES[:index]) for index in range(24))


class _NonRetainingProgramCap:
    """Count bounded child compilations without recording Program arguments.

    A Mock side_effect retains every Program in call_args_list, preventing the
    streaming tests from releasing their child graphs under the unchanged cap.
    """
    def __init__(self,compiler,maximum):
        self._compiler=compiler
        self._maximum=maximum
        self.call_count=0

    def __call__(self,program):
        if len(program.constraints)>self._maximum:
            raise AssertionError('only real bounded child Programs may use GraphSpec.from_program')
        self.call_count+=1
        return self._compiler(program)


def _producer(round_index,slot):
    lane,byte=divmod(slot,8)
    masks=CONSTANTS[round_index].to_bytes(8,'little')
    local=(1216+sum(value!=0 for value in masks[:byte]) if lane==0 and masks[byte]
           else 1016+slot)
    return ROUND_OFFSETS[round_index]+local


def _consumers(round_index,slot):
    lane,byte=divmod(slot,8)
    x,y=lane%5,lane//5
    offset=ROUND_OFFSETS[round_index]
    return ((offset+32*x+4*byte+max(y-1,0),0 if y==0 else 1),
            (offset+240+slot,0))


def _partition(wires):
    unique=tuple(dict.fromkeys(wires))
    return tuple(unique.index(word) for word in wires)


def _one_round(raw,round_index):
    from keccak_trace import keccak_f1600_round
    lanes=tuple(int.from_bytes(raw[index:index+8],'little') for index in range(0,200,8))
    return b''.join(value.to_bytes(8,'little') for value in keccak_f1600_round(lanes,round_index))


def _reference(initial):
    current=initial
    states=[]
    for round_index in range(24):
        current=_one_round(current,round_index);states.append(current)
    return tuple(states)


def _truth(spec,values,ordinal):
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
    else:raise AssertionError('unexpected non-BYTE leaf in full permutation')
    return operands[-1]==expected


def _tiny_ids(ports=2):
    return tuple(tuple(f'byte-state/{state}/l0/byte{slot}'
        for state in range(4*block,4*block+5) for slot in range(ports))
        +(f'byte-round/{4*block}/same/internal',f'byte-round/{4*block+3}/another/internal')
        for block in range(6))


def _quotient(child_ids):
    names=[];indices={};maps=[]
    for ids in child_ids:
        mapping=[]
        for name in ids:
            if name not in indices:indices[name]=len(names);names.append(name)
            mapping.append(indices[name])
        maps.append(tuple(mapping))
    return tuple(maps),tuple((name,256) for name in names)


class BytePermutationPureMapsAndGuards(unittest.TestCase):
    def test_program_cap_hook_counts_and_releases_tiny_argument_objects(self):
        class TinyChild:
            def __init__(self,size):self.constraints=(None,)*size
        class TinyCatalogue:
            calls=0
            @classmethod
            def from_program(cls,program):
                cls.calls+=1
                return len(program.constraints)
        original=TinyCatalogue.from_program
        hook=_NonRetainingProgramCap(original,2)
        references=[]
        # Exercise the exact staticmethod replacement used by the hosted
        # observer, with tiny objects rather than Programs or GraphSpecs.
        with patch.object(TinyCatalogue,'from_program',new=staticmethod(hook)):
            for _ in range(32):
                child=TinyChild(2)
                references.append(weakref.ref(child))
                self.assertEqual(TinyCatalogue.from_program(child),2)
                del child
            gc.collect()
            self.assertTrue(all(reference() is None for reference in references))
            self.assertEqual((hook.call_count,TinyCatalogue.calls),(32,32))
            self.assertFalse(hasattr(hook,'call_args_list'))
            with self.assertRaises(AssertionError):TinyCatalogue.from_program(TinyChild(3))
            self.assertEqual((hook.call_count,TinyCatalogue.calls),(32,32))

    def test_analytical_census_preserves_caps_and_has9200_consumer_coordinates(self):
        from trace import MAX_CONSTRAINTS,MAX_WORDS
        from wots_graph import MAX_GRAPH_LEAVES
        self.assertEqual((MAX_CONSTRAINTS,MAX_WORDS,MAX_GRAPH_LEAVES),(10000,100000,30000))
        self.assertEqual((sum(ROUND_LEAVES),200+sum(ROUND_LEAVES)),(29245,29445))
        self.assertGreater(sum(ROUND_LEAVES),MAX_CONSTRAINTS)
        self.assertLessEqual(sum(ROUND_LEAVES),MAX_GRAPH_LEAVES)
        self.assertLessEqual(200+sum(ROUND_LEAVES),MAX_WORDS)
        self.assertEqual((23*200,23*200*2,5*200,5*200*2),(4600,9200,1000,2000))
        self.assertEqual(tuple(sum(ROUND_LEAVES[first:first+4]) for first in range(0,24,4)),
                         (4873,4875,4871,4875,4874,4877))
        # Complete-left-filled balanced tree counts, not a root or membership proof.
        depth=(sum(ROUND_LEAVES)-1).bit_length()
        deep=2*sum(ROUND_LEAVES)-(1<<depth)
        shallow=(1<<depth)-sum(ROUND_LEAVES)
        self.assertEqual((depth,deep,shallow),(15,25722,3523))
        self.assertEqual((33+32*depth,33+32*(depth-1)),(513,481))
        self.assertEqual(CONSTANTS[3].to_bytes(8,'little')[0],0)
        self.assertEqual(CONSTANTS[3].to_bytes(8,'little')[1],128)
        self.assertEqual(_producer(3,1),4870)
        for state in range(1,24):
            actual=[_consumers(state,slot) for slot in range(200)]
            self.assertEqual(len({item for pair in actual for item in pair}),400)

    def test_six_tiny_block_maps_have_only_five_ordered_outer_intersections(self):
        import byte_keccak_permutation as module
        self.assertEqual(module.aligned_block_rounds(),(0,4,8,12,16,20))
        ids=_tiny_ids()
        maps,words=_quotient(ids)
        module._validate_maps(ids,maps,words,port_count=2)
        self.assertEqual(len(words),62)
        for left,mapping in enumerate(maps):
            self.assertEqual(len(mapping),len(set(mapping)))
            self.assertEqual(tuple(words[index][0] for index in mapping),ids[left])
            for right in range(left+1,6):
                expected={f'byte-state/{4*right}/l0/byte{slot}' for slot in range(2)} if right==left+1 else set()
                self.assertEqual(set(ids[left])&set(ids[right]),expected)
                self.assertEqual({words[index][0] for index in set(mapping)&set(maps[right])},expected)

    def test_tiny_missing_reordered_extra_alias_bound_and_domain_maps_reject(self):
        import byte_keccak_permutation as module
        ids=_tiny_ids();maps,words=_quotient(ids)
        variants=[]
        changed=[list(item) for item in maps];changed[1].pop();variants.append(changed)
        changed=[list(item) for item in maps];changed[0][-1]=changed[0][0];variants.append(changed)
        changed=[list(item) for item in maps];changed[1][0],changed[1][1]=changed[1][1],changed[1][0];variants.append(changed)
        changed=[list(item) for item in maps];changed[1][0]=len(words);variants.append(changed)
        for changed in variants:
            with self.assertRaises(ValueError):module._validate_maps(ids,tuple(tuple(item) for item in changed),words,port_count=2)
        for child in (1,2,5):
            changed=[list(item) for item in ids];changed[child][-1]=changed[0][-1]
            changed=tuple(tuple(item) for item in changed)
            changed_maps,changed_words=_quotient(changed)
            with self.assertRaises(ValueError):module._validate_maps(changed,changed_maps,changed_words,port_count=2)
        for replacement in ('byte-state/24/l0/byte0','byte-round/22/foreign/internal'):
            changed=[list(item) for item in ids];changed[0][0]=replacement
            changed=tuple(tuple(item) for item in changed)
            changed_maps,changed_words=_quotient(changed)
            with self.assertRaises(ValueError):module._validate_maps(changed,changed_maps,changed_words,port_count=2)
        for bad_words in (words[:-1]+((words[-1][0],2),),words[:-1]+((words[-1][0],256.0),),
                          words+(('extra/unused',256),),list(words)):
            with self.assertRaises(ValueError):module._validate_maps(ids,maps,bad_words,port_count=2)
        for count in (True,False,0,201,2.0):
            with self.assertRaises(ValueError):module._validate_maps(ids,maps,words,port_count=count)

    def test_identity_domains_and_pure_nested_operation_preflight(self):
        import byte_keccak_permutation as module
        self.assertEqual(module.PROGRAM_SCHEMA,'bitvm2-nova-byte-keccak-permutation-program/v1')
        self.assertEqual(module.SOURCE_SCHEMA,'bitvm2-nova-byte-keccak-permutation-source/v1')
        self.assertEqual(module.PROGRAM_DOMAIN,b'BITVM2-NOVA/BYTE-KECCAK-PERMUTATION-PROGRAM/v1\x00')
        self.assertEqual(module.SOURCE_DOMAIN,b'BITVM2-NOVA/BYTE-KECCAK-PERMUTATION-SOURCE/v1\x00')
        self.assertNotEqual(module.PROGRAM_DOMAIN,module.SOURCE_DOMAIN)
        # Call only the pure validator, with allocation spies still forbidding
        # children. No factory guard is patched or bypassed.
        with patch.object(module,'build_byte_keccak_block',side_effect=AssertionError('pure validator allocated block')) as child:
            for role in ROLES:module._parameters(context=CONTEXT,role=role,operation_id=OPERATION)
            module._parameters(context=CONTEXT,role='pallas_scalar',operation_id='x'*167)
            for options in (dict(role=True),dict(role='unknown'),dict(context=bytes(31)),
                    dict(context=bytearray(32)),dict(operation_id=True),dict(operation_id='bad operation'),
                    dict(operation_id='x'*168),dict(operation_id='x'*193)):
                parameters=dict(context=CONTEXT,role='pallas_scalar',operation_id=OPERATION)
                parameters.update(options)
                with self.assertRaises(ValueError):module._parameters(**parameters)
            child.assert_not_called()
        self.assertEqual(len('x'*168+'/block/0/child/0/round/0'),192)
        self.assertEqual(len('x'*168+'/block/2/child/2/round/10'),193)

    def test_resource_guard_precedes_first_block_catalogue_binding_and_io(self):
        import byte_keccak_permutation as module
        for github,runner,platform in [('false','Linux','linux'),('true','Windows','linux'),('true','Linux','win32')]:
            with patch.dict(os.environ,{'GITHUB_ACTIONS':github,'RUNNER_OS':runner},clear=True),\
                patch.object(module.sys,'platform',platform),\
                patch.object(module,'build_byte_keccak_block',side_effect=AssertionError('full block allocated')) as block,\
                patch.object(module.GraphSpec,'from_program',side_effect=AssertionError('catalogue allocated')) as spec,\
                patch('builtins.open',side_effect=AssertionError('I/O before guard')) as io:
                with self.assertRaisesRegex(ValueError,'hosted GitHub Linux'):
                    module.build_byte_keccak_permutation(context=None,role=None,operation_id=None)
                empty=object.__new__(module.ByteKeccakPermutation)
                with self.assertRaisesRegex(ValueError,'hosted GitHub Linux'):empty.bind(None)
                with self.assertRaisesRegex(ValueError,'hosted GitHub Linux'):empty.regenerate_block(None)
                block.assert_not_called();spec.assert_not_called();io.assert_not_called()
        for cls in (module.ByteKeccakPermutation,module.ByteKeccakPermutationBinding,
                    module.BytePermutationBlockDescriptor,module.BytePermutationJoin):
            with self.assertRaises(TypeError):cls()
            self.assertFalse(hasattr(cls,'from_json'))
        for key in ('blocks','program','spec','source_maps','program_manifest','source_manifest',
                    'receipt','manifest','assignment','inputs','outputs','producer_ordinals','global_ids','joins','version'):
            with self.assertRaises(TypeError):module.build_byte_keccak_permutation(
                context=CONTEXT,role='pallas_scalar',**{key:{'passed':True}})


@unittest.skipUnless(_hosted(),'full BYTE catalogues and Script are hosted GitHub Linux only')
class HostedByteKeccakPermutationTests(unittest.TestCase):
    def setUp(self):
        if not _hosted():self.skipTest('hosted guard before full BYTE catalogue or Script allocation')
        import byte_keccak_permutation
        self.module=byte_keccak_permutation
        from trace import MAX_CONSTRAINTS
        original=self.module.GraphSpec.from_program
        self._child_from_program=_NonRetainingProgramCap(original,MAX_CONSTRAINTS)
        guard=patch.object(self.module.GraphSpec,'from_program',new=staticmethod(self._child_from_program))
        guard.start()
        self.addCleanup(guard.stop)

    def build(self,role='pallas_scalar',*,context=CONTEXT,operation=OPERATION):
        return self.module.build_byte_keccak_permutation(context=context,role=role,operation_id=operation)

    def assert_manifests(self,plan,maps,role):
        spec=plan.spec
        self.assertFalse(hasattr(plan,'program'),'the full parent must not be an oversized Program')
        self.assertEqual((len(spec.words),len(spec.leaves)),(29445,29245))
        self.assertEqual((spec.context,spec.field_role,spec.operation_id),(CONTEXT.hex(),role,OPERATION))
        self.assertEqual(spec.field_leaves,())
        self.assertTrue(all(type(bound) is int and bound==256 for _,bound in spec.words))
        self.assertEqual(tuple(name for name,_ in spec.words),plan.global_ids)
        self.assertEqual(spec.program_sha256,plan.program_sha256.hex())
        program=plan.program_manifest;source=plan.source_manifest
        self.assertEqual(program['schema'],'bitvm2-nova-byte-keccak-permutation-program/v1')
        self.assertEqual(program['program_identity_kind'],'domain-separated manifest hash; not Program.digest')
        self.assertEqual((program['context'],program['field_role'],program['operation_id']),
                         (CONTEXT.hex(),role,OPERATION))
        self.assertEqual((program['first_round'],program['rounds'],program['words'],program['leaves']),
                         (0,24,29445,29245))
        self.assertEqual(plan.program_sha256,sha256(
            b'BITVM2-NOVA/BYTE-KECCAK-PERMUTATION-PROGRAM/v1\x00'+_canonical(program)).digest())
        self.assertEqual(plan.source_sha256,sha256(
            b'BITVM2-NOVA/BYTE-KECCAK-PERMUTATION-SOURCE/v1\x00'+_canonical(source)).digest())
        self.assertNotEqual(plan.program_sha256,plan.source_sha256)
        self.assertEqual(source['program_sha256'],plan.program_sha256.hex())
        self.assertEqual(source['catalogue_id'],spec.digest().hex())
        self.assertEqual(source['program_manifest_sha256'],sha256(_canonical(program)).hexdigest())
        self.assertEqual(plan.manifest,source)
        self.assertFalse({'program_sha256','source_sha256','catalogue_id','registry_id','merkle_root','output_key'}&set(program))
        # Child program/source/catalogue IDs are legitimate inputs. Only the
        # parent's own identities would make this dependency chain circular.
        encoded_program=_canonical(program)
        for own_id in (plan.program_sha256.hex(),plan.source_sha256.hex(),spec.digest().hex()):
            self.assertNotIn(own_id.encode('ascii'),encoded_program)
        forbidden={'assignment','initial_state','output_state','state_claims','claimed_output','receipt',
                   'registry_id','key_catalogue_sha256','signature_catalogue_sha256','merkle_root','output_key'}
        def visit(value):
            if isinstance(value,dict):
                self.assertFalse(forbidden&set(value))
                for child in value.values():visit(child)
            elif isinstance(value,(list,tuple)):
                for child in value:visit(child)
        visit(program);visit(source)
        maps_sha=sha256(_canonical(maps)).digest()
        self.assertEqual(plan.source_maps_sha256,maps_sha)
        self.assertEqual(program['source_maps_sha256'],maps_sha.hex())
        self.assertEqual(source['source_maps_sha256'],maps_sha.hex())
        self.assertEqual(program['body_catalogue_sha256'],sha256(_canonical(list(spec.bodies))).hexdigest())
        self.assertEqual(program['blocks'],[descriptor.json() for descriptor in plan.blocks])
        self.assertLessEqual(len(_canonical(maps)),8<<20)
        self.assertLessEqual(len(encoded_program),1<<20)
        self.assertLessEqual(len(_canonical(source)),1<<20)

    def assert_projections(self,plan,maps):
        spec=plan.spec;bodies=dict(spec.bodies)
        self.assertEqual((len(plan.blocks),len(maps['blocks']),len(maps['rounds'])),(6,6,24))
        all_words=set();all_leaves=set();images=[]
        for index,descriptor in enumerate(plan.blocks):
            block=plan.regenerate_block(index)
            record=maps['blocks'][index]
            word_map=record['word_map'];leaf_map=record['leaf_map']
            for key,value in descriptor.json().items():self.assertEqual(record[key],value)
            self.assertEqual((descriptor.index,descriptor.first_round,descriptor.last_round),(index,4*index,4*index+3))
            self.assertEqual(descriptor.operation_id,f'{OPERATION}/block/{index}')
            self.assertEqual(descriptor.program_operation_id,f'{OPERATION}/block/{index}/rounds/{4*index}-{4*index+3}')
            self.assertEqual((descriptor.words,descriptor.leaves),(len(block.spec.words),len(block.spec.leaves)))
            self.assertEqual(descriptor.leaf_offset,ROUND_OFFSETS[4*index])
            self.assertEqual(descriptor.program_sha256,block.program.digest().hex())
            self.assertEqual(descriptor.source_sha256,block.source_sha256.hex())
            self.assertEqual(descriptor.catalogue_id,block.spec.digest().hex())
            self.assertEqual(descriptor.global_ids_sha256,sha256(_canonical(list(block.global_ids))).hexdigest())
            self.assertEqual(descriptor.word_map_sha256,sha256(_canonical(word_map)).hexdigest())
            self.assertEqual(descriptor.leaf_map_sha256,sha256(_canonical(leaf_map)).hexdigest())
            self.assertEqual(len(word_map),len(set(word_map)))
            self.assertEqual(tuple(spec.words[parent][0] for parent in word_map),block.global_ids)
            self.assertEqual(leaf_map,list(range(descriptor.leaf_offset,descriptor.leaf_offset+descriptor.leaves)))
            old_bodies=dict(block.spec.bodies)
            for local,parent in enumerate(leaf_map):
                old,new=block.spec.leaves[local],spec.leaves[parent]
                self.assertEqual((new.kind,new.argument,new.body_sha256),(old.kind,old.argument,old.body_sha256))
                self.assertEqual(new.wires,tuple(word_map[word] for word in old.wires))
                self.assertEqual(_partition(new.wires),_partition(old.wires))
                self.assertEqual(bodies[new.body_sha256],old_bodies[old.body_sha256])
            source=block.source_maps
            for child_index,old in enumerate(source['children']):
                absolute=4*index+child_index
                new=maps['rounds'][absolute]
                self.assertEqual((new['block_index'],new['child_index'],new['round_index']),
                                 (index,child_index,absolute))
                for key in ('index','round_index','operation_id','program_operation_id','source_sha256',
                            'program_sha256','catalogue_id','global_ids_sha256'):
                    self.assertEqual(new[key],old[key])
                self.assertEqual(new['program_operation_id'],f'{OPERATION}/block/{index}/child/{child_index}/round/{absolute}')
                for key in ('word_map','input_indices','output_indices'):
                    self.assertEqual(new[key],[word_map[slot] for slot in old[key]])
                for key in ('leaf_map','producer_ordinals'):
                    self.assertEqual(new[key],[leaf_map[slot] for slot in old[key]])
                self.assertEqual(new['producer_occurrences'],old['producer_occurrences'])
                self.assertEqual(new['input_consumer_occurrences'],
                    [[[leaf_map[ordinal],formal] for ordinal,formal in cells]
                     for cells in old['input_consumer_occurrences']])
            for old_join in block.joins:
                new=plan.joins[old_join.state_round-1]
                self.assertEqual(new.words,old_join.words)
                self.assertEqual(new.indices,tuple(word_map[slot] for slot in old_join.indices))
                self.assertEqual(new.producer_ordinals,tuple(leaf_map[slot] for slot in old_join.producer_ordinals))
                self.assertEqual(new.producer_occurrences,old_join.producer_occurrences)
                self.assertEqual(new.consumer_occurrences,
                    tuple(tuple((leaf_map[ordinal],formal) for ordinal,formal in cells)
                          for cells in old_join.consumer_occurrences))
            all_words.update(word_map);all_leaves.update(leaf_map);images.append(set(word_map))
            del old_bodies,source,block
        self.assertEqual(all_words,set(range(len(spec.words))))
        self.assertEqual(all_leaves,set(range(len(spec.leaves))))
        for left in range(6):
            for right in range(left+1,6):
                expected=set(maps['rounds'][4*right]['input_indices']) if right==left+1 else set()
                self.assertEqual(images[left]&images[right],expected)
        self.assertEqual(maps['input_indices'],maps['rounds'][0]['input_indices'])
        self.assertEqual(maps['output_indices'],maps['rounds'][23]['output_indices'])
        self.assertEqual(plan.inputs,tuple(spec.words[index][0] for index in maps['input_indices']))
        self.assertEqual(plan.outputs,tuple(spec.words[index][0] for index in maps['output_indices']))
        self.assertEqual(plan.inputs,tuple(f'byte-state/0/l{lane}/byte{byte}' for lane in range(25) for byte in range(8)))
        self.assertEqual(plan.outputs,tuple(f'byte-state/24/l{lane}/byte{byte}' for lane in range(25) for byte in range(8)))

    def assert_all_join_occurrences_and_terminals(self,plan,maps):
        spec=plan.spec
        self.assertEqual(tuple(maps['input_indices']),tuple(range(200)))
        known=set(maps['input_indices']);produced={};consumed={}
        for ordinal,leaf in enumerate(spec.leaves):
            self.assertIn(leaf.kind,('byte_xor','byte_and','byte_not','byte_rol','byte_xor_const'))
            self.assertTrue(all(word in known for word in leaf.wires[:-1]))
            output=leaf.wires[-1]
            self.assertEqual(output,200+ordinal)
            self.assertNotIn(output,known)
            known.add(output);produced[output]=(ordinal,len(leaf.wires)-1)
            for formal,word in enumerate(leaf.wires[:-1]):consumed.setdefault(word,[]).append((ordinal,formal))
        self.assertEqual(known,set(range(len(spec.words))))
        self.assertEqual(set(produced)-set(consumed),set(maps['output_indices']))
        self.assertEqual(plan.producer_ordinals,tuple(_producer(23,slot) for slot in range(200)))
        self.assertEqual(maps['producer_ordinals'],list(plan.producer_ordinals))
        self.assertEqual(maps['producer_occurrences'],list(plan.producer_occurrences))
        self.assertEqual((len(plan.joins),len(maps['joins'])),(23,23))
        shared=set();coordinates=0;outer_words=set();outer_coordinates=0
        for state,join in enumerate(plan.joins,start=1):
            self.assertEqual((join.index,join.state_round),(state-1,state))
            self.assertEqual(join.words,tuple(f'byte-state/{state}/l{lane}/byte{byte}'
                for lane in range(25) for byte in range(8)))
            self.assertEqual(join.indices,tuple(maps['rounds'][state-1]['output_indices']))
            self.assertEqual(join.indices,tuple(maps['rounds'][state]['input_indices']))
            self.assertEqual(join.producer_ordinals,tuple(_producer(state-1,slot) for slot in range(200)))
            self.assertEqual(join.consumer_occurrences,tuple(_consumers(state,slot) for slot in range(200)))
            self.assertEqual(join.json(),maps['joins'][state-1])
            self.assertFalse(shared&set(join.words));shared.update(join.words)
            for slot,(word,parent,producer,formal,cells) in enumerate(zip(join.words,join.indices,
                    join.producer_ordinals,join.producer_occurrences,join.consumer_occurrences,strict=True)):
                self.assertEqual(spec.words[parent],(word,256))
                self.assertEqual(produced[parent],(producer,formal))
                self.assertEqual(spec.leaves[producer].wires[formal],parent)
                self.assertEqual(formal,1 if spec.leaves[producer].kind=='byte_xor_const' else 2)
                self.assertEqual(tuple(consumed[parent]),cells)
                self.assertEqual(len(cells),2)
                for consumer,consumer_formal in cells:
                    self.assertEqual(spec.leaves[consumer].wires[consumer_formal],parent)
                    coordinates+=1
                    if state%4==0:outer_coordinates+=1
            if state%4==0:outer_words.update(join.words)
        self.assertEqual((len(shared),coordinates),(4600,9200))
        self.assertEqual((len(outer_words),outer_coordinates),(1000,2000))
        self.assertEqual(maps['global_ids'],list(plan.global_ids))
        self.assertEqual(maps['global_ids_sha256'],sha256(_canonical(list(plan.global_ids))).hexdigest())

    def test_full_sources_both_roles_preserve_all_blocks_and_one_binding_at_a_time(self):
        for role in ROLES:
            plan=self.build(role);maps=plan.source_maps
            self.assert_manifests(plan,maps,role)
            self.assert_projections(plan,maps)
            self.assert_all_join_occurrences_and_terminals(plan,maps)
            first_claim=None
            for initial in (bytes(200),bytes(range(200))):
                binding=plan.bind(initial)
                values=binding.assignment
                expected=_reference(initial)
                self.assertEqual((binding.initial_state,binding.states,binding.output_state,binding.reference_output),
                                 (initial,expected[:23],expected[-1],expected[-1]))
                self.assertEqual(binding.spec.digest(),plan.spec.digest())
                self.assertFalse(hasattr(binding,'program'))
                self.assertFalse(hasattr(binding,'children'))
                self.assertEqual(binding.global_ids,plan.global_ids)
                self.assertTrue(all(_truth(binding.spec,values,ordinal) for ordinal in range(len(binding.spec.leaves))))
                self.assertEqual(bytes(values[word] for word in plan.inputs),initial)
                self.assertEqual(bytes(values[word] for word in plan.outputs),expected[-1])
                for state,join in enumerate(plan.joins,start=1):
                    self.assertEqual(bytes(values[word] for word in join.words),expected[state-1])
                claim=sha256(_canonical([values[word] for word in plan.global_ids])).digest()
                if first_claim is None:first_claim=claim
                else:self.assertNotEqual(claim,first_claim)
                for summary in (plan.summary(),binding.summary()):
                    for flag in FALSE_FLAGS:self.assertIs(summary[flag],False)
                del values,binding
            del maps,plan
        self.assertGreater(self._child_from_program.call_count,0)

    def test_all_five_outer_state_chi_iota_overrides_and_final_output_are_single_producer_refutations(self):
        from script import OPS,execute,num
        initial=bytes(range(200))
        reference=_reference(initial)
        for role in ROLES:
            plan=self.build(role)
            for state in (4,8,12,16,20):
                masks=CONSTANTS[state-1].to_bytes(8,'little')
                iota_slot=next(byte for byte,mask in enumerate(masks) if mask)
                if state==4:self.assertEqual(iota_slot,1)
                for slot in (iota_slot,8):
                    changed=bytearray(reference[state-1]);changed[slot]^=1
                    claims=[None]*23;claims[state-1]=bytes(changed)
                    binding=plan.bind(initial,state_claims=tuple(claims))
                    self.assertFalse(hasattr(binding,'program'))
                    values=binding.assignment
                    expected_producer=_producer(state-1,slot)
                    failures=tuple(ordinal for ordinal in range(len(binding.spec.leaves))
                                   if not _truth(binding.spec,values,ordinal))
                    self.assertEqual(failures,(expected_producer,))
                    self.assertEqual(binding.states[:state-1],reference[:state-1])
                    self.assertEqual(binding.states[state-1],bytes(changed))
                    self.assertEqual(binding.reference_output,reference[-1])
                    current=bytes(changed)
                    for round_index in range(state,24):
                        current=_one_round(current,round_index)
                        if round_index<23:self.assertEqual(binding.states[round_index],current)
                    self.assertEqual(binding.output_state,current)
                    self.assertEqual(binding.spec.digest(),plan.spec.digest())
                    self.assertEqual(binding.permutation.source_sha256,plan.source_sha256)
                    join=plan.joins[state-1]
                    self.assertEqual(join.producer_ordinals[slot],expected_producer)
                    self.assertEqual(bytes(values[word] for word in join.words),bytes(changed))
                    leaf=binding.spec.leaves[expected_producer]
                    self.assertEqual(leaf.kind,'byte_xor_const' if slot==iota_slot else 'byte_xor')
                    self.assertEqual(join.producer_occurrences[slot],1 if slot==iota_slot else 2)
                    body=bytes.fromhex(dict(binding.spec.bodies)[leaf.body_sha256])
                    unique=tuple(dict.fromkeys(leaf.wires))
                    witness=tuple(num(values[binding.spec.words[index][0]]) for index in unique)
                    # Bare predicate conformance only. Full authenticated length,
                    # opening and signature checks belong to the native registry.
                    for disprove in (False,True):
                        result=execute(body+(bytes([OPS['NOT']]) if disprove else b''),witness)
                        self.assertEqual(result.success,disprove);self.assertIsNone(result.error)
                    del values,binding
            masks=CONSTANTS[23].to_bytes(8,'little')
            for slot in (next(byte for byte,mask in enumerate(masks) if mask),8):
                output=bytearray(reference[-1]);output[slot]^=1
                binding=plan.bind(initial,claimed_output=bytes(output))
                values=binding.assignment
                failures=tuple(ordinal for ordinal in range(len(binding.spec.leaves))
                               if not _truth(binding.spec,values,ordinal))
                self.assertEqual(failures,(_producer(23,slot),))
                self.assertEqual(binding.states,reference[:23])
                self.assertEqual((binding.output_state,binding.reference_output),(bytes(output),reference[-1]))
                self.assertEqual(plan.producer_ordinals[slot],failures[0])
                del values,binding
            del plan

    def test_snapshots_claim_types_nested_caps_and_sequential_foreign_source_identities(self):
        plan=self.build()
        fingerprints=(plan.program_sha256,plan.source_sha256,plan.spec.digest())
        for obj,name in ((plan,'context'),(plan.blocks[0],'source_sha256'),(plan.joins[0],'words')):
            with self.assertRaises((FrozenInstanceError,AttributeError)):setattr(obj,name,b'changed')
        program=plan.program_manifest;program['blocks'][0]['word_map_sha256']='00'*32
        self.assertNotEqual(program,plan.program_manifest)
        source=plan.source_manifest;source['catalogue_id']='00'*32
        self.assertNotEqual(source,plan.source_manifest)
        maps=plan.source_maps;maps['blocks'][0]['word_map'][0]=-1
        self.assertNotEqual(maps,plan.source_maps)
        del maps,program,source
        with patch.object(self.module.ByteKeccakPermutation,'regenerate_block',
                          side_effect=AssertionError('invalid input regenerated block')) as child:
            for bad in (None,True,bytes(199),bytes(201),bytearray(200)):
                with self.assertRaises(ValueError):plan.bind(bad)
            for bad in (True,bytes(199),bytes(201),bytearray(200)):
                with self.assertRaises(ValueError):plan.bind(bytes(200),claimed_output=bad)
            for claims in (None,True,(),(None,)*22,(None,)*24,[None]*23,
                           (True,)+(None,)*22,(bytes(199),)+(None,)*22,(bytearray(200),)+(None,)*22,
                           (None,)*22+(True,),(None,)*22+(bytes(199),),(None,)*22+(bytearray(200),)):
                with self.assertRaises(ValueError):plan.bind(bytes(200),state_claims=claims)
            child.assert_not_called()
        for bad in (True,False,-1,6,1.0,None):
            with patch.object(self.module,'build_byte_keccak_block',
                              side_effect=AssertionError('bad index allocated block')) as child:
                with self.assertRaises(ValueError):plan.regenerate_block(bad)
                child.assert_not_called()
        binding=plan.bind(bytes(200),state_claims=(None,)*23,claimed_output=None)
        self.assertEqual(binding.output_state,_reference(bytes(200))[-1])
        self.assertFalse(hasattr(binding,'children'))
        self.assertFalse(hasattr(binding,'program'))
        with self.assertRaises((FrozenInstanceError,AttributeError)):binding.initial_state=b'changed'
        values=binding.assignment;values[plan.inputs[0]]^=1
        self.assertNotEqual(values,binding.assignment)
        del values,binding,plan
        # Keep no original full catalogue while constructing each variant.
        for parameters in (dict(role='vesta_scalar'),dict(context=bytes(32)),dict(operation=OPERATION+'/other')):
            options=dict(role='pallas_scalar',context=CONTEXT,operation=OPERATION);options.update(parameters)
            other=self.build(**options)
            self.assertNotEqual(other.program_sha256,fingerprints[0])
            self.assertNotEqual(other.source_sha256,fingerprints[1])
            self.assertNotEqual(other.spec.digest(),fingerprints[2])
            del other
        with patch.object(self.module,'build_byte_keccak_block',
                          side_effect=AssertionError('nested ID preflight allocated first block')) as child:
            with self.assertRaises(ValueError):self.build(operation='x'*168)
            child.assert_not_called()

    def test_tiny_existing_fixed_claim_guards_without_any_full_parent_program(self):
        from byte_kernels import byte_kernel_trace
        from script import execute,num
        shapes=(('byte_xor',(),(165,60)),('byte_and',(),(165,60)),('byte_not',(),(165,)),
                ('byte_rol',(3,),(165,60)),('byte_xor_const',(128,),(165,)))
        for role in ROLES:
            for kind,argument,inputs in shapes:
                program,values=byte_kernel_trace(role,kind,inputs,argument=argument,
                    context=CONTEXT,operation_id='tests/full-byte/tiny-fixed-claim')
                self.assertLess(len(program.words),100)
                bound=program.bind(values);witness=bound.witness(0)
                for disprove in (False,True):
                    code=bound.script(0,disprove=disprove)
                    self.assertEqual(execute(code,witness).success,not disprove)
                    for malformed in ((),witness[:-1],(b'',)+witness,witness+(b'',)):
                        result=execute(code,malformed)
                        self.assertFalse(result.success);self.assertEqual(result.error,'EQUALVERIFY')
                    result=execute(code,(num(inputs[0]^1),)+witness[1:])
                    self.assertFalse(result.success);self.assertEqual(result.error,'EQUALVERIFY')
                bound.require_identity(program.digest(),bound.claim_digest)
                with self.assertRaises(ValueError):bound.require_identity(bytes(32),bound.claim_digest)
                with self.assertRaises(ValueError):bound.require_identity(program.digest(),bytes(32))
                foreign,foreign_values=byte_kernel_trace(role,kind,inputs,argument=argument,
                    context=bytes(32),operation_id='tests/full-byte/tiny-fixed-claim')
                foreign_bound=foreign.bind(foreign_values)
                self.assertNotEqual(foreign.digest(),program.digest())
                self.assertNotEqual(foreign_bound.claim_digest,bound.claim_digest)
                self.assertEqual(foreign_bound.witness(0),witness)
                with self.assertRaises(ValueError):foreign_bound.require_identity(program.digest(),bound.claim_digest)
                with self.assertRaises(ValueError):bound.require_identity(foreign.digest(),foreign_bound.claim_digest)


if __name__=='__main__':
    unittest.main()


