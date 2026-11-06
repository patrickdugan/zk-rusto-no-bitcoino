"""Independent BYTE routing references; actual round graphs are HOSTED ONLY.

Local tests construct no Program/GraphSpec and execute no Script. The hosted
suite releases each round binding before advancing; no24-round graph is built.
"""
from dataclasses import FrozenInstanceError
from hashlib import sha256
import json
import os
import random
import sys
import unittest
from unittest.mock import patch
from collections import Counter

CONTEXT=sha256(b'byte-keccak-round-tests/caller-owned-context').digest()
ROLES=('pallas_scalar','vesta_scalar')
MASK64=(1<<64)-1
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


def _rho_offsets():
    """Independent Keccak triangular-number recurrence, not the source table."""
    offsets=[0]*25
    x,y=1,0
    for step in range(24):
        offsets[x+5*y]=((step+1)*(step+2)//2)%64
        x,y=y,(2*x+3*y)%5
    return tuple(offsets)


def _round_constants():
    """Independent seven-bit-tap LFSR generation of the24 Iota constants."""
    lfsr=1
    constants=[]
    for _ in range(24):
        value=0
        for tap in range(7):
            if lfsr&1:value^=1<<((1<<tap)-1)
            lfsr=((lfsr<<1)^(0x71 if lfsr&0x80 else 0))&255
        constants.append(value)
    return tuple(constants)


def _rotate64(value,shift):
    return ((value<<shift)|(value>>((64-shift)%64)))&MASK64


def _state_patterns():
    rng=random.Random(0xb17e1600)
    return (bytes(200),bytes([255])*200,bytes(range(200)),
            bytes(rng.randrange(256) for _ in range(200)))


def _independent_round(raw,round_index):
    """The existing pure word-level reference, never its Boolean graph builder."""
    from keccak_trace import keccak_f1600_round
    lanes=tuple(int.from_bytes(raw[offset:offset+8],'little') for offset in range(0,200,8))
    return b''.join(value.to_bytes(8,'little') for value in keccak_f1600_round(lanes,round_index))


class ByteRoundPureRoutingAndGuards(unittest.TestCase):
    def test_all_rho_pi_routes_use_independent_lane_and_le_byte_references(self):
        import byte_keccak_round as module
        offsets=_rho_offsets()
        self.assertEqual(tuple(module.RHO[lane//5][lane%5] for lane in range(25)),offsets)
        self.assertEqual(len(set(offsets)),25)
        self.assertEqual(tuple(lane for lane,shift in enumerate(offsets) if shift%8==0),(0,19,23))
        destinations=[]
        for lane in range(25):
            x,y=lane%5,lane//5
            expected=y+5*((2*x+3*y)%5)
            self.assertEqual(module.pi_destination(lane),expected)
            destinations.append(expected)
        self.assertEqual(set(destinations),set(range(25)))
        samples=(bytes(8),bytes([255])*8,bytes(range(8)),bytes([1,128,2,64,4,32,8,16]))
        for shift in range(64):
            byte_shift,remainder=divmod(shift,8)
            for byte in range(8):
                a=(byte-byte_shift)%8
                b=(byte-byte_shift-1)%8
                self.assertEqual(module.byte_rotation_sources(byte,shift),(a,b,remainder))
                for raw in samples:
                    expected=_rotate64(int.from_bytes(raw,'little'),shift).to_bytes(8,'little')[byte]
                    actual=raw[a] if remainder==0 else ((raw[a]<<remainder)&255)|(raw[b]>>(8-remainder))
                    self.assertEqual(actual,expected)
        # Each Rho lane and Pi destination still denotes all eight byte slots.
        routed={(module.pi_destination(lane),byte) for lane in range(25) for byte in range(8)}
        self.assertEqual(routed,{(lane,byte) for lane in range(25) for byte in range(8)})

    def test_all24_round_constant_bytes_match_independent_lfsr_and_counts(self):
        import byte_keccak_round as module
        from keccak_trace import ROUND_CONSTANTS
        constants=_round_constants()
        self.assertEqual(constants,ROUND_CONSTANTS)
        for round_index,value in enumerate(constants):
            expected=value.to_bytes(8,'little')
            actual=module.round_constant_bytes(round_index)
            self.assertIs(type(actual),bytes)
            self.assertEqual(bytes(actual),expected)
            self.assertTrue(all(type(byte) is int and 0<=byte<256 for byte in actual))
            nonzero=sum(byte!=0 for byte in expected)
            self.assertEqual(1416+nonzero-(1216+nonzero),200)
            self.assertEqual(module.output_wire_names(round_index),tuple(
                f'iota/byte{byte}' if lane==0 and expected[byte] else f'chi/out/l{lane}/byte{byte}'
                for lane in range(25) for byte in range(8)))
        self.assertEqual(module.input_wire_names(),
            tuple(f'input/l{lane}/byte{byte}' for lane in range(25) for byte in range(8)))

    def test_pure_public_indices_reject_boolean_aliases_and_wrong_types(self):
        import byte_keccak_round as module
        for bad in (True,False,-1,8,1.0,'0',None):
            with self.assertRaises(ValueError):module.byte_rotation_sources(bad,0)
        for bad in (True,False,-1,64,1.0,'0',None):
            with self.assertRaises(ValueError):module.byte_rotation_sources(0,bad)
        for bad in (True,False,-1,25,1.0,'0',None):
            with self.assertRaises(ValueError):module.pi_destination(bad)
        for bad in (True,False,-1,24,1.0,'0',None):
            with self.assertRaises(ValueError):module.round_constant_bytes(bad)

    def test_pure_global_ids_preserve_all200_ordered_byte_ports(self):
        import byte_keccak_round as module
        inputs=tuple(f'input/l{lane}/byte{byte}' for lane in range(25) for byte in range(8))
        for round_index in (0,1,23):
            masks=_round_constants()[round_index].to_bytes(8,'little')
            outputs=tuple(f'iota/byte{byte}' if lane==0 and masks[byte] else
                f'chi/out/l{lane}/byte{byte}' for lane in range(25) for byte in range(8))
            private='theta/c/x0/byte0/row1'
            # Pure symbolic name tuples, without any Program/GraphSpec or values.
            words=tuple((name,256) for name in inputs+outputs+(private,))
            ids=module.global_word_ids(round_index,words,inputs,outputs)
            self.assertEqual(ids[:200],tuple(f'byte-state/{round_index}/l{lane}/byte{byte}'
                for lane in range(25) for byte in range(8)))
            self.assertEqual(ids[200:400],tuple(f'byte-state/{round_index+1}/l{lane}/byte{byte}'
                for lane in range(25) for byte in range(8)))
            self.assertEqual(ids[-1],f'byte-round/{round_index}/{private}')
            self.assertEqual(len(set(ids)),401)
            for bad_words in (words[:-1]+((private,255),),words[:-1]+((private,256.0),),
                              words[:-1]+((private,True),),words+(words[-1],),list(words)):
                with self.assertRaises(ValueError):module.global_word_ids(round_index,bad_words,inputs,outputs)
            for bad_inputs,bad_outputs in ((inputs[:-1],outputs),(inputs,outputs[:-1]),
                    (inputs[:-1]+(inputs[0],),outputs),(inputs,inputs),(list(inputs),outputs)):
                with self.assertRaises(ValueError):module.global_word_ids(round_index,words,bad_inputs,bad_outputs)

    def test_resource_guard_precedes_factory_binding_graph_and_io(self):
        import byte_keccak_round as module
        for github,runner,platform in [('false','Linux','linux'),('true','Windows','linux'),('true','Linux','win32')]:
            with patch.dict(os.environ,{'GITHUB_ACTIONS':github,'RUNNER_OS':runner},clear=True),\
                patch.object(module.sys,'platform',platform),\
                patch.object(module,'ByteTraceBuilder',side_effect=AssertionError('round graph allocated')) as builder,\
                patch.object(module.GraphSpec,'from_program',side_effect=AssertionError('catalogue allocated')) as spec,\
                patch('builtins.open',side_effect=AssertionError('I/O before guard')) as io:
                with self.assertRaisesRegex(ValueError,'hosted GitHub Linux'):
                    module.build_byte_keccak_round(None,context=None,role=None,operation_id=None)
                empty=object.__new__(module.ByteKeccakRound)
                with self.assertRaisesRegex(ValueError,'hosted GitHub Linux'):empty.bind(None)
                builder.assert_not_called();spec.assert_not_called();io.assert_not_called()
        for cls in (module.ByteKeccakRound,module.ByteKeccakRoundBinding):
            with self.assertRaises(TypeError):cls()
            self.assertFalse(hasattr(cls,'from_json'))
        for keyword in ('program','spec','source_maps','receipt','manifest','assignment',
                        'inputs','outputs','producer_ordinals','global_ids','version'):
            with self.assertRaises(TypeError):
                module.build_byte_keccak_round(0,context=CONTEXT,role='pallas_scalar',
                                               **{keyword:{'passed':True}})


@unittest.skipUnless(_hosted(),'actual BYTE round graphs and Script are hosted GitHub Linux only')
class HostedByteKeccakRoundTests(unittest.TestCase):
    def setUp(self):
        if not _hosted():self.skipTest('hosted guard before actual round/Script allocation')
        import byte_keccak_round
        self.module=byte_keccak_round

    def build(self,round_index,role='pallas_scalar',*,context=CONTEXT,operation='tests/byte-keccak/round'):
        return self.module.build_byte_keccak_round(round_index,context=context,role=role,operation_id=operation)

    def assert_topology(self,plan,round_index,role):
        program,spec=plan.program,plan.spec
        masks=_round_constants()[round_index].to_bytes(8,'little')
        nonzero=sum(mask!=0 for mask in masks)
        self.assertEqual((len(program.words),len(program.constraints),len(spec.leaves)),
                         (1416+nonzero,1216+nonzero,1216+nonzero))
        self.assertEqual((program.field_role,program.context,program.fields),(role,CONTEXT,()))
        self.assertEqual(program.operation_id,'tests/byte-keccak/round')
        self.assertEqual(spec.words,program.words)
        self.assertEqual(spec.field_leaves,())
        self.assertEqual(tuple(name for name,_ in program.words[:200]),plan.inputs)
        self.assertEqual(plan.inputs,self.module.input_wire_names())
        self.assertTrue(all(type(bound) is int and bound==256 for _,bound in program.words))
        self.assertEqual((len(set(plan.inputs)),len(set(plan.outputs))),(200,200))
        self.assertFalse(set(plan.inputs)&set(plan.outputs))
        expected_outputs=tuple(f'iota/byte{byte}' if lane==0 and masks[byte] else
            f'chi/out/l{lane}/byte{byte}' for lane in range(25) for byte in range(8))
        self.assertEqual(plan.outputs,expected_outputs)
        counts=Counter(constraint.kind for constraint in program.constraints)
        self.assertEqual(counts,Counter(byte_xor=600,byte_and=200,byte_not=200,
                                       byte_rol=216,byte_xor_const=nonzero))
        seen=set(plan.inputs)
        produced={}
        consumed=Counter()
        for ordinal,constraint in enumerate(program.constraints):
            self.assertIs(type(constraint.argument),tuple)
            self.assertTrue(all(type(value) is int for value in constraint.argument))
            if constraint.kind=='byte_rol':
                self.assertEqual(len(constraint.argument),1)
                self.assertTrue(1<=constraint.argument[0]<=7)
            elif constraint.kind=='byte_xor_const':
                self.assertEqual(len(constraint.argument),1)
                self.assertTrue(1<=constraint.argument[0]<=255)
            else:self.assertEqual(constraint.argument,())
            self.assertTrue(all(word in seen for word in constraint.wires[:-1]))
            output=constraint.wires[-1]
            self.assertNotIn(output,seen,'every post-input word has exactly one SSA producer')
            seen.add(output);produced[output]=ordinal
            consumed.update(constraint.wires[:-1])
            leaf=spec.leaves[ordinal]
            self.assertEqual((leaf.kind,leaf.argument),(constraint.kind,constraint.argument))
        self.assertEqual(seen,{name for name,_ in program.words})
        self.assertEqual(set(produced),set(seen)-set(plan.inputs))
        self.assertEqual(set(produced)-set(consumed),set(plan.outputs))
        self.assertTrue(all(consumed[word]==0 for word in plan.outputs))
        self.assertEqual(plan.producer_ordinals,tuple(produced[word] for word in plan.outputs))
        self.assertEqual(len(set(plan.producer_ordinals)),200)
        for lane in range(25):
            for byte in range(8):
                ordinal=plan.producer_ordinals[8*lane+byte]
                constraint=program.constraints[ordinal]
                if lane==0 and masks[byte]:
                    self.assertEqual((constraint.kind,constraint.argument),('byte_xor_const',(masks[byte],)))
                    self.assertEqual(constraint.wires[:-1],(f'chi/out/l0/byte{byte}',))
                else:self.assertEqual((constraint.kind,constraint.argument),('byte_xor',()))
        positions={name:index for index,(name,_) in enumerate(program.words)}
        maps=plan.source_maps
        self.assertEqual(maps['round_index'],round_index)
        self.assertEqual(maps['input_indices'],[positions[word] for word in plan.inputs])
        self.assertEqual(maps['output_indices'],[positions[word] for word in plan.outputs])
        self.assertEqual(maps['producer_ordinals'],list(plan.producer_ordinals))
        self.assertEqual(maps['global_ids'],list(plan.global_ids))
        self.assertEqual(maps['global_ids_sha256'],sha256(_canonical(list(plan.global_ids))).hexdigest())
        self.assertEqual(plan.global_ids,self.module.global_word_ids(round_index,program.words,plan.inputs,plan.outputs))
        self.assertEqual(len(set(plan.global_ids)),len(program.words))
        self.assertEqual([plan.global_ids[positions[word]] for word in plan.inputs],
            [f'byte-state/{round_index}/l{lane}/byte{byte}' for lane in range(25) for byte in range(8)])
        self.assertEqual([plan.global_ids[positions[word]] for word in plan.outputs],
            [f'byte-state/{round_index+1}/l{lane}/byte{byte}' for lane in range(25) for byte in range(8)])
        self.assertTrue(all(type(value) is int and value>=0 for value in maps['phase_counts'].values()))
        self.assertEqual(maps['phase_counts'],dict(theta_c=160,theta_d_rot=40,
            theta_d_xor=40,theta_mix=200,rho=176,chi_not=200,chi_and=200,
            chi_xor=200,iota=nonzero))

    def test_all24_rounds_four_states_both_scalar_roles_stream_one_binding_at_a_time(self):
        program_ids=set()
        source_ids=set()
        for role in ROLES:
            for round_index in range(24):
                plan=self.build(round_index,role)
                self.assert_topology(plan,round_index,role)
                self.assertNotIn(plan.program.digest(),program_ids)
                self.assertNotIn(plan.source_sha256,source_ids)
                program_ids.add(plan.program.digest());source_ids.add(plan.source_sha256)
                for initial in _state_patterns():
                    binding=plan.bind(initial)
                    values=binding.assignment
                    reference=_independent_round(initial,round_index)
                    self.assertEqual((binding.initial_state,binding.reference_output,binding.output_state),
                                     (initial,reference,reference))
                    self.assertEqual(bytes(values[word] for word in plan.inputs),initial)
                    self.assertEqual(bytes(values[word] for word in plan.outputs),reference)
                    self.assertEqual(binding.program.digest(),plan.program.digest())
                    self.assertEqual(binding.spec.digest(),plan.spec.digest())
                    self.assertEqual(binding.round.source_sha256,plan.source_sha256)
                    self.assertEqual(binding.program.bind(values).failures(),())
                    for summary in (plan.summary(),binding.summary()):
                        for flag in FALSE_FLAGS:self.assertIs(summary[flag],False)
                    del values,binding
                del plan
        self.assertEqual((len(program_ids),len(source_ids)),(48,48))

    def test_single_claimed_output_byte_refutes_only_its_terminal_iota_or_chi_producer(self):
        from script import execute
        initial=_state_patterns()[2]
        for role in ROLES:
            plan=self.build(0,role)
            reference=_independent_round(initial,0)
            for byte in (0,8):  # Iota(LO lane byte0), then a natural Chi output.
                claimed=bytearray(reference);claimed[byte]^=1
                binding=plan.bind(initial,claimed_output=bytes(claimed))
                self.assertEqual(binding.reference_output,reference)
                self.assertEqual(binding.output_state,bytes(claimed))
                self.assertEqual(binding.program.digest(),plan.program.digest())
                self.assertEqual(binding.round.source_sha256,plan.source_sha256)
                bound=binding.program.bind(binding.assignment)
                producer=plan.producer_ordinals[byte]
                self.assertEqual(bound.failures(),(producer,))
                self.assertEqual(plan.program.constraints[producer].kind,
                    'byte_xor_const' if byte==0 else 'byte_xor')
                for disprove in (False,True):
                    result=execute(bound.script(producer,disprove=disprove),bound.witness(producer))
                    self.assertEqual(result.success,disprove)
                    self.assertIsNone(result.error,'bounded false output is an ordinary refutable predicate')
                del bound,binding
            del plan

    def test_sealed_snapshots_and_context_role_operation_round_identities(self):
        plan=self.build(0)
        binding=plan.bind(_state_patterns()[3])
        for obj,name in ((plan,'source_sha256'),(binding,'initial_state')):
            with self.assertRaises((FrozenInstanceError,AttributeError)):setattr(obj,name,b'changed')
        manifest=plan.manifest;manifest['test-only-mutation']=True
        self.assertNotIn('test-only-mutation',plan.manifest)
        maps=plan.source_maps;maps['input_indices'][0]=-1
        self.assertNotEqual(maps,plan.source_maps)
        with self.assertRaises(TypeError):plan.ports['inputs']=()
        values=binding.assignment;values[plan.inputs[0]]^=1
        self.assertNotEqual(values,binding.assignment)
        self.assertEqual(plan.manifest['round_index'],0)
        self.assertEqual(plan.manifest['round_constant_le'],_round_constants()[0].to_bytes(8,'little').hex())
        self.assertEqual(self.module.SOURCE_DOMAIN,b'BITVM2-NOVA/BYTE-KECCAK-ROUND/v1\x00')
        self.assertEqual(plan.source_sha256,sha256(
            b'BITVM2-NOVA/BYTE-KECCAK-ROUND/v1\x00'+_canonical(plan.manifest)).digest())
        # Only source topology belongs in the pre-key manifest. No assertion,
        # witness values, native receipt or forest result can feed back into it.
        forbidden={'assignment','initial_state','output_state','claimed_output','receipt',
                   'registry_id','key_catalogue_sha256','signature_catalogue_sha256',
                   'merkle_root','output_key','transaction_id'}
        def visit(value):
            if isinstance(value,dict):
                self.assertFalse(forbidden&set(value))
                for child in value.values():visit(child)
            elif isinstance(value,(list,tuple)):
                for child in value:visit(child)
        visit(plan.manifest)
        committed=binding.program.bind(binding.assignment)
        for options in (dict(round_index=1),dict(role='vesta_scalar'),
                        dict(context=bytes(32)),dict(operation='tests/byte-keccak/other')):
            parameters=dict(round_index=0,role='pallas_scalar',context=CONTEXT,
                            operation='tests/byte-keccak/round')
            parameters.update(options)
            other=self.build(**parameters)
            self.assertNotEqual(other.program.digest(),plan.program.digest())
            self.assertNotEqual(other.spec.digest(),plan.spec.digest())
            self.assertNotEqual(other.source_sha256,plan.source_sha256)
            with self.assertRaises(ValueError):committed.require_identity(other.program.digest(),committed.claim_digest)
            del other
        for bad in (bytes(199),bytes(201),bytearray(200),None,True):
            with self.assertRaises(ValueError):plan.bind(bad)
            with self.assertRaises(ValueError):plan.bind(bytes(200),claimed_output=bad)
        for options in (dict(round_index=True),dict(round_index=-1),dict(round_index=24),
                        dict(role=True),dict(role='unknown'),dict(context=bytes(31)),
                        dict(context=bytearray(32)),dict(operation='bad operation')):
            parameters=dict(round_index=0,role='pallas_scalar',context=CONTEXT,
                            operation='tests/byte-keccak/round')
            parameters.update(options)
            with patch.object(self.module,'ByteTraceBuilder',side_effect=AssertionError('invalid identity allocated graph')) as builder:
                with self.assertRaises(ValueError):self.build(**parameters)
                builder.assert_not_called()

    def test_fixed_claim_length_opening_and_context_guards_preserve_all_round_kinds(self):
        from script import execute,num
        for role in ROLES:
            plan=self.build(0,role)
            binding=plan.bind(_state_patterns()[2])
            values=binding.assignment
            bound=binding.program.bind(values)
            selected={}
            for ordinal,constraint in enumerate(plan.program.constraints):selected.setdefault(constraint.kind,ordinal)
            self.assertEqual(set(selected),{'byte_xor','byte_and','byte_not','byte_rol','byte_xor_const'})
            for ordinal in selected.values():
                witness=bound.witness(ordinal)
                for disprove in (False,True):
                    code=bound.script(ordinal,disprove=disprove)
                    self.assertEqual(execute(code,witness).success,not disprove)
                    for malformed in ((),witness[:-1],(b'',)+witness,witness+(b'',)):
                        result=execute(code,malformed)
                        self.assertFalse(result.success);self.assertEqual(result.error,'EQUALVERIFY')
                    first=plan.program.constraints[ordinal].wires[0]
                    changed=(num(values[first]^1),)+witness[1:]
                    result=execute(code,changed)
                    self.assertFalse(result.success);self.assertEqual(result.error,'EQUALVERIFY')
            bound.require_identity(plan.program.digest(),bound.claim_digest)
            with self.assertRaises(ValueError):bound.require_identity(bytes(32),bound.claim_digest)
            with self.assertRaises(ValueError):bound.require_identity(plan.program.digest(),bytes(32))
            del values,bound,binding,plan


if __name__=='__main__':
    unittest.main()


