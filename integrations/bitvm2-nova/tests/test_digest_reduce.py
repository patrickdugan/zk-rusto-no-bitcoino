"""Independent digest-bit references and HOSTED-ONLY composition/Script tests.

No local test constructs a real graph or executes Script. Local guard tests
only exercise blocked entry points with allocation spies; mapping helpers and
the independent bit/byte arithmetic are pure. No build, proving or publishing.
"""
from dataclasses import FrozenInstanceError
from hashlib import sha256
import json
import os
import random
import sys
import unittest
from unittest.mock import patch

from script import BASE, P, Q

FIELDS=(('pallas_scalar',Q),('vesta_scalar',P))


def _source_bits(lo,hi):
    """Independent raw-byte reference: LO first, bytes unchanged, bits LSB-first."""
    if type(lo) is not bytes or type(hi) is not bytes or len(lo)!=32 or len(hi)!=32:
        raise ValueError('two immutable32-byte digests required')
    return tuple((byte>>bit)&1 for byte in lo+hi for bit in range(8))


def _byte_from_lsb(bits):
    if len(bits)!=8 or any(type(bit) is not int or bit not in (0,1) for bit in bits):
        raise ValueError('eight Boolean bits required')
    return sum(bit<<index for index,bit in enumerate(bits))


def _horner_msb(bits):
    value=0
    for bit in bits:value=2*value+bit
    return value


def _hosted():
    return (os.environ.get('GITHUB_ACTIONS')=='true'
        and os.environ.get('RUNNER_OS')=='Linux' and sys.platform=='linux')


def _patterns():
    return (bytes([1,128]+list(range(2,32))),bytes((255-7*i)&255 for i in range(32)))


class DigestReferenceAndGuardTests(unittest.TestCase):
    def test_independent_byte_and_lane_maps_cover_every_ordered_bit(self):
        import digest_reduce as module
        lo,hi=_patterns()
        independent=_source_bits(lo,hi)
        self.assertEqual(module.digest_lane_bits(lo)+module.digest_lane_bits(hi),independent)
        self.assertEqual(len(set(module.digest_bit_location(i,j) for i in range(64) for j in range(8))),512)
        for index,byte in enumerate(lo+hi):
            group=independent[8*index:8*index+8]
            self.assertEqual(_byte_from_lsb(group),byte)
            self.assertEqual(_horner_msb(tuple(reversed(group))),byte)
            for bit in range(8):
                expected=('lo' if index<32 else 'hi',(index%32)//8,8*(index%8)+bit)
                self.assertEqual(module.digest_bit_location(index,bit),expected)
        for branch,raw in enumerate((lo,hi)):
            for lane in range(4):
                bits=independent[256*branch+64*lane:256*branch+64*(lane+1)]
                self.assertEqual(sum(bit<<index for index,bit in enumerate(bits)),
                    int.from_bytes(raw[8*lane:8*lane+8],'little'))
        self.assertEqual(sum(bit<<index for index,bit in enumerate(independent)),int.from_bytes(lo+hi,'little'))

    def test_asymmetric_and_random_bytes_detect_bit_and_branch_reversals(self):
        import digest_reduce as module
        rng=random.Random(0xd16e57)
        samples=[bytes(32),bytes([255])*32,bytes(range(32)),bytes([1,128])*16]
        samples += [rng.getrandbits(256).to_bytes(32,'little') for _ in range(16)]
        for raw in samples:
            expected=tuple((byte>>bit)&1 for byte in raw for bit in range(8))
            self.assertEqual(module.digest_lane_bits(raw),expected)
            self.assertTrue(all(type(bit) is int for bit in expected))
        self.assertEqual(_byte_from_lsb((1,0,0,0,0,0,0,0)),1)
        self.assertEqual(_byte_from_lsb((0,0,0,0,0,0,0,1)),128)
        lo,hi=_patterns()
        self.assertNotEqual(_source_bits(lo,hi),_source_bits(hi,lo))
        for _,p in FIELDS:
            self.assertNotEqual(int.from_bytes(lo+hi,'little')%p,int.from_bytes(hi+lo,'little')%p)

    def test_pure_mapping_helpers_reject_type_length_and_index_aliases(self):
        import digest_reduce as module
        for value in (bytes(31),bytes(33),bytearray(32),None,True):
            with self.assertRaises(ValueError):module.digest_lane_bits(value)
        for first,second in ((True,0),(0,True),(-1,0),(64,0),(0,-1),(0,8),(1.0,0),(0,1.0)):
            with self.assertRaises(ValueError):module.digest_bit_location(first,second)

    def test_hosted_guard_precedes_child_graph_script_and_catalogue_allocation(self):
        import digest_reduce as module
        for github,runner,platform in [('false','Linux','linux'),('true','Windows','linux'),('true','Linux','win32')]:
            with patch.dict(os.environ,{'GITHUB_ACTIONS':github,'RUNNER_OS':runner},clear=True),\
                patch.object(module.sys,'platform',platform),\
                patch.object(module,'build_uniform_reduction',side_effect=AssertionError('child allocated')) as child,\
                patch.object(module,'ConvolutionTraceBuilder',side_effect=AssertionError('graph allocated')) as builder,\
                patch.object(module.GraphSpec,'from_program',side_effect=AssertionError('catalogue allocated')) as spec:
                with self.assertRaisesRegex(ValueError,'hosted GitHub Linux'):
                    module.build_digest_reduction(None,None,role=None,context=None)
                child.assert_not_called();builder.assert_not_called();spec.assert_not_called()


@unittest.skipUnless(_hosted(),'real digest/reduction graphs and Script are hosted GitHub Linux only')
class HostedDigestReductionTests(unittest.TestCase):
    def setUp(self):
        if not _hosted():self.skipTest('hosted guard before actual graph or Script allocation')
        import digest_reduce
        self.module=digest_reduce
        self.context=bytes.fromhex('61'*32)
        self.operation='test/digest-reduce'

    def build(self,lo,hi,role,*,context=None,operation=None):
        return self.module.build_digest_reduction(lo,hi,role=role,
            context=self.context if context is None else context,
            operation_id=self.operation if operation is None else operation)

    @staticmethod
    def failures(graph,values):
        result=[]
        bounds=dict(graph.program.words)
        for ordinal,constraint in enumerate(graph.program.constraints):
            in_range=all(type(values[word]) is int and 0<=values[word]<bounds[word] for word in constraint.wires)
            if not in_range or not constraint.native(values,graph.program.p):result.append(ordinal)
        return result

    def test_all64_ordered_bridges_and_full_child_projection_are_exact(self):
        from wots_graph import GraphSpec
        lo,hi=_patterns()
        for role,p in FIELDS:
            graph=self.build(lo,hi,role)
            values,ports=graph.assignment,graph.ports
            self.assertEqual((len(graph.program.words),len(graph.program.constraints),len(graph.spec.leaves)),(955,372,373))
            self.assertEqual(graph.program.field_role,role)
            self.assertEqual(graph.program.context,self.context)
            self.assertEqual(graph.program.operation_id,self.operation)
            self.assertEqual(graph.program.words[:379],graph.uniform.program.words)
            self.assertEqual(graph.program.constraints[:244],graph.uniform.program.constraints)
            self.assertEqual(graph.program.fields,graph.uniform.program.fields)
            self.assertEqual(graph.uniform_leaf_map,tuple(range(244))+(372,))
            self.assertEqual(graph.bridge_bit_constraints,tuple(244+2*i for i in range(64)))
            self.assertEqual(graph.bridge_byte_constraints,tuple(245+2*i for i in range(64)))
            self.assertEqual(ports['digest_bits'],ports['digest_lo_bits']+ports['digest_hi_bits'])
            self.assertEqual(len(set(ports['digest_bits'])),512)
            self.assertEqual(len(set(ports['byte_auxiliaries'])),64)
            self.assertFalse(set(ports['digest_bits'])&set(ports['byte_auxiliaries']))
            bounds=dict(graph.program.words)
            self.assertEqual(tuple(values[word] for word in ports['digest_bits']),_source_bits(lo,hi))
            names={word:i for i,(word,_) in enumerate(graph.program.words)}
            maps=graph.source_maps
            self.assertEqual(maps['digest_bit_indices'],[names[word] for word in ports['digest_bits']])
            self.assertEqual(maps['byte_auxiliary_indices'],[names[word] for word in ports['byte_auxiliaries']])
            self.assertEqual(maps['input_byte_indices'],[names[word] for word in ports['input_bytes']])
            for index,byte in enumerate(lo+hi):
                group=ports['byte_bits'][index];aux=ports['byte_auxiliaries'][index];target=ports['input_bytes'][index]
                self.assertEqual(group,ports['digest_bits'][8*index:8*index+8])
                self.assertEqual(tuple(bounds[word] for word in group),(2,)*8)
                self.assertEqual((bounds[aux],bounds[target]),(BASE,256))
                self.assertEqual((values[aux],values[target]),(byte,byte))
                first=graph.program.constraints[graph.bridge_bit_constraints[index]]
                second=graph.program.constraints[graph.bridge_byte_constraints[index]]
                self.assertEqual((first.kind,first.argument,first.wires),('bits',(8,),(aux,)+tuple(reversed(group))))
                self.assertEqual((second.kind,second.argument,second.wires),('conv_reconstruct',(8,),(aux,target)))
            child_spec=GraphSpec.from_program(graph.uniform.program)
            self.assertEqual(maps['children'][0]['word_map'],list(range(379)))
            self.assertEqual(maps['children'][0]['leaf_map'],list(graph.uniform_leaf_map))
            self.assertEqual(maps['children'][0]['program_sha256'],graph.uniform.program.digest().hex())
            self.assertEqual(maps['children'][0]['catalogue_id'],child_spec.digest().hex())
            for old,new in enumerate(graph.uniform_leaf_map):
                self.assertEqual(graph.spec.leaves[new],child_spec.leaves[old])
                body=graph.spec.leaves[new].body_sha256
                self.assertEqual(dict(graph.spec.bodies)[body],dict(child_spec.bodies)[body])
            self.assertEqual(graph.spec.field_leaves,(('result',372),))
            self.assertEqual(maps['canonical_result_leaf'],372)
            self.assertEqual(graph.uniform.result_value,int.from_bytes(lo+hi,'little')%p)
            self.assertEqual(graph.program.bind(values).failures(),())

    def test_topology_is_value_independent_and_identity_binds_role_context_operation(self):
        lo,hi=_patterns()
        first=self.build(lo,hi,'pallas_scalar')
        same=self.build(lo,hi,'pallas_scalar')
        changed=self.build(bytes(32),bytes([255])*32,'pallas_scalar')
        self.assertIsNot(first.uniform,same.uniform)
        self.assertEqual(first.program.digest(),same.program.digest())
        self.assertEqual(first.spec.digest(),changed.spec.digest())
        self.assertEqual(first.source_sha256,changed.source_sha256)
        for other in (self.build(lo,hi,'vesta_scalar'),
                self.build(lo,hi,'pallas_scalar',context=bytes.fromhex('62'*32)),
                self.build(lo,hi,'pallas_scalar',operation='test/digest-reduce-other')):
            self.assertNotEqual(first.program.digest(),other.program.digest())
            self.assertNotEqual(first.spec.digest(),other.spec.digest())
            self.assertNotEqual(first.source_sha256,other.source_sha256)
        encoded=json.dumps(first.metadata,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode('ascii')
        self.assertEqual(first.source_sha256,sha256(self.module.SOURCE_DOMAIN+encoded).digest())

    def test_factory_surface_is_strict_and_returns_fresh_immutable_snapshots(self):
        lo,hi=_patterns()
        graph=self.build(lo,hi,'pallas_scalar')
        with self.assertRaises(TypeError):type(graph)()
        self.assertFalse(hasattr(type(graph),'from_json'))
        with self.assertRaises((FrozenInstanceError,AttributeError)):graph.role='vesta_scalar'
        with self.assertRaises(TypeError):graph.ports['digest_bits']=()
        values=graph.assignment;values[graph.ports['digest_bits'][0]]^=1
        self.assertNotEqual(values,graph.assignment)
        metadata=graph.metadata;metadata['source_maps']['children'][0]['leaf_map'][0]=999
        self.assertNotEqual(metadata,graph.metadata)
        maps=graph.source_maps;maps['digest_bit_indices'][0]=999
        self.assertNotEqual(maps,graph.source_maps)
        for bad in (bytes(31),bytes(33),bytearray(32),True,None):
            with self.assertRaises(ValueError):self.build(bad,hi,'pallas_scalar')
            with self.assertRaises(ValueError):self.build(lo,bad,'pallas_scalar')
        for role in (True,None,'unknown'):
            with self.assertRaises(ValueError):self.build(lo,hi,role)
        for context in (bytes(31),bytes(33),bytearray(32),True,None):
            with self.assertRaises(ValueError):
                self.module.build_digest_reduction(lo,hi,role='pallas_scalar',context=context,operation_id=self.operation)
        for operation in ('','x'*193,'contains space',True,None):
            with self.assertRaises(ValueError):
                self.module.build_digest_reduction(lo,hi,role='pallas_scalar',context=self.context,operation_id=operation)
        for key in ('graph','uniform','program','spec','assignment','receipt','source_maps','claimed_result'):
            with self.assertRaises(TypeError):
                self.module.build_digest_reduction(lo,hi,role='pallas_scalar',context=self.context,**{key:{'passed':True}})

    def test_bit_reversal_branch_swap_and_auxiliary_tamper_are_real_bridge_failures(self):
        lo,hi=_patterns()
        for role,_ in FIELDS:
            graph=self.build(lo,hi,role);honest=graph.assignment;ports=graph.ports
            reversed_bits=dict(honest)
            expected=[]
            for index,group in enumerate(ports['byte_bits']):
                original=tuple(honest[word] for word in group)
                for word,value in zip(group,reversed(original),strict=True):reversed_bits[word]=value
                if original!=tuple(reversed(original)):expected.append(graph.bridge_bit_constraints[index])
            self.assertTrue(expected)
            self.assertEqual(self.failures(graph,reversed_bits),expected)
            swapped=dict(honest)
            for word,value in zip(ports['digest_bits'],_source_bits(hi,lo),strict=True):swapped[word]=value
            expected=[graph.bridge_bit_constraints[i] for i,(old,new) in enumerate(zip(lo+hi,hi+lo,strict=True)) if old!=new]
            self.assertEqual(self.failures(graph,swapped),expected)
            changed=dict(honest);changed[ports['byte_auxiliaries'][0]]^=1
            self.assertEqual(self.failures(graph,changed),[graph.bridge_bit_constraints[0],graph.bridge_byte_constraints[0]])

    def test_coherent_rewitness_isolates_producer_and_consumer_and_open_origin(self):
        lo,hi=_patterns();changed_lo=bytes([lo[0]^1])+lo[1:]
        for role,_ in FIELDS:
            original=self.build(lo,hi,role);other=self.build(changed_lo,hi,role)
            self.assertEqual(original.program.digest(),other.program.digest())
            self.assertEqual(original.source_sha256,other.source_sha256)
            # Full coherent substitution is valid arithmetic under the same
            # topology. This stage explicitly does not prove Keccak origin.
            self.assertEqual(original.program.bind(other.assignment).failures(),())
            for name in ('keccak_origin_script_bound','full_keccak_verified','source_bytes_script_bound',
                'squeeze_bound_in_script','transcript_verified','proof_verified','bitvm2_script_verified'):
                self.assertIs(other.summary()[name],False)
            bits_only=other.assignment
            original_values=original.assignment
            for word in original.ports['digest_bits']:bits_only[word]=original_values[word]
            self.assertEqual(self.failures(original,bits_only),[original.bridge_bit_constraints[0]])
            consumer_only=dict(bits_only)
            for word in original.ports['byte_auxiliaries']:consumer_only[word]=original_values[word]
            self.assertEqual(self.failures(original,consumer_only),[original.bridge_byte_constraints[0]])
            from script import execute
            for values,ordinal in ((bits_only,original.bridge_bit_constraints[0]),
                                   (consumer_only,original.bridge_byte_constraints[0])):
                bound=original.program.bind(values)
                self.assertFalse(execute(bound.script(ordinal,disprove=False),bound.witness(ordinal)).success)
                self.assertTrue(execute(bound.script(ordinal,disprove=True),bound.witness(ordinal)).success)

    def test_uniform_anchors_and_canonical_field_refutation_are_preserved(self):
        from script import OPS,execute,num
        lo,hi=_patterns()
        for role,p in FIELDS:
            graph=self.build(lo,hi,role);uniform=graph.uniform
            for name,ordinal in uniform.anchor_constraints.items():
                self.assertEqual(graph.uniform_leaf_map[ordinal],ordinal)
                self.assertEqual(graph.program.constraints[ordinal],uniform.program.constraints[ordinal])
                changed=graph.assignment;word=graph.program.constraints[ordinal].wires[0];changed[word]^=1
                self.assertIn(ordinal,self.failures(graph,changed),name)
            noncanonical=graph.assignment
            for index,word in enumerate(graph.ports['result_field']):noncanonical[word]=(p>>(29*index))&(BASE-1)
            with self.assertRaises(ValueError):graph.program.bind(noncanonical)
            body=bytes.fromhex(dict(graph.spec.bodies)[graph.spec.leaves[372].body_sha256])
            witness=[num(noncanonical[word]) for word in graph.ports['result_field']]
            self.assertFalse(execute(body,witness).success)
            self.assertTrue(execute(body+bytes([OPS['NOT']]),witness).success)
            for word,value in ((graph.ports['digest_bits'][0],2),
                (graph.ports['input_bytes'][0],256),(graph.ports['result_field'][0],0xffffffff)):
                changed=graph.assignment;changed[word]=value
                with self.assertRaises(ValueError):graph.program.bind(changed)
                self.assertTrue(self.failures(graph,changed))

    def test_both_new_bridge_shapes_keep_exact_witness_length_guards(self):
        from script import execute
        lo,hi=_patterns()
        for role,_ in FIELDS:
            graph=self.build(lo,hi,role);bound=graph.program.bind(graph.assignment)
            for byte in (0,31,32,63):
                for ordinal in (graph.bridge_bit_constraints[byte],graph.bridge_byte_constraints[byte]):
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
