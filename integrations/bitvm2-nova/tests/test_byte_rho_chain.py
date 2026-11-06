"""Independent143-byte next-c oracle and HOSTED-ONLY nine-component checks.

Local work is limited to small immutable vectors, framing, hashes and guards.
No local full graph, Script, signing, native process or proving is executed.
"""
from dataclasses import FrozenInstanceError
from hashlib import sha256
import json
import os
import sys
import unittest
from unittest.mock import patch

from script import P,Q

CONTEXT=sha256(b'byte-rho-chain-tests/caller-owned-context').digest()
OPERATION='tests/byte-rho-chain'
COMPONENT_WORDS=(29445,29445,587,187,29445,23,29445,29445,379)
COMPONENT_LEAVES=(29245,29245,453,111,29245,9,29245,29245,245)
PREFIX_FIXED=(0,*range(65,77),*range(136,200))
FALSE_FLAGS=('eval_w_canonical_in_script','eval_w_proof_origin_bound','prior_state_transcript_bound',
    'coefficient_proof_origins_bound','sumcheck_equation_verified','full_transcript_verified',
    'transcript_verified','nova_transcript_verified','proof_verified','bitvm2_script_verified',
    'production_assertion_binding','bitcoin_transaction_graph')
VECTORS=(
    dict(role='pallas_scalar',modulus=Q,rho_counter=59,c_counter=60,events=(103,104,105),
        eval_w='537b9d938bc6034f86e7a3e80acfe239738ce9cf711e01d98f962be35ce2f50d',
        prior='baeac41afe052c21cb039093874cb223c9a5e9e81be6d9f155ef6b660a0d9921c'
              '936762f733e9e28bc943ef10103de48ee6de67d875123c945f8dbbe38518694',
        coefficients=('de1f5d1449af98395a9462433bc4057f8a6b43edc9671a8abd51110d0303b214',
                      '0694a1ed101c3cce0e0c06103a578051701393cdbeb9bb5c495d91685bba0e2d'),
        raw_rho='f04e669b472740ed7e968c559565f0ef1cc9a02bd7265a14380d37f150127006'
                '02a294e6894a96599a22f07296b9b94aa004b4f821ae0435755c5ccfd04bdc7f',
        raw_c='9a62ebb9a5aafea68609962656cd7aa854914ae0ccb073f9ee05519f76a8539e4'
              '5b5dd1b36e98d75dee609c1233ad184b6c5a0e1633a768e378f987f5235e474',
        challenge='2770fa4779eb97bb1272041a9c14403a0c1570a0308e5d84e27d518125ea5036',
        prefix_sha='25be8a01098a64cf35ffb38cada9841319922f3e59d7f3815035dc5ca3113a38',
        absorb_lo_sha='45d107172d5a099e21f24f084454e71613680c66b28324fa789cad5e816bfeb6',
        absorb_hi_sha='c158fc590a6b4461aa3f279b4d9822809636803cc0d7cdc63f34a986b4b079b7'),
    dict(role='vesta_scalar',modulus=P,rho_counter=44,c_counter=45,events=(78,79,80),
        eval_w='9af0b1db3bb739876ec135b290fa9016b388a2a71ba5a45bb7bee402582efc26',
        prior='379a4d9a1bb224b6d4a5b9b29dfd641a52630feaed5e5bb8732e5de012b1d933'
              '3965bbe9209263ab886274f82e4d1c263f4518ec86cf1da1049fa603ca1ed285',
        coefficients=('45fbb3a84e85d7a9749b760585302d0a5a23adbcc2f5da328707840be5eb1a13',
                      '58e2712c3104da7705f808d95e90e2719c1ebdc728bafd9007fa56ee3ec1793c'),
        raw_rho='05913fa1f3e416205487806536aacbca64e1b314c5f20e658ae5ca6b8fc2fb74'
                'a1199395495cb178b7ee439193c436f64b288afade6c973f80ec66f85e73936d',
        raw_c='ecc38c27f4712a179aa55bc3c0df663651be906a1fc47eaeff9eab8d5f2fa5be'
              '1c33641f687de1bbd723d7c203d020ad709914e4c52c0e3f005b221cd236e8df',
        challenge='f6a0f1ff6cdb56029324e4840d850f8aafcdc7037642ef35e8e53f8fb397dc0c',
        prefix_sha='a806131cc8321e3834af2ec59306a08bf95b86f2736f3a1b30b3a6059b84735a',
        absorb_lo_sha='0881b7b73508fc608316a71f159d8b84b4e80d1058fad451a3828f5c40af36b5',
        absorb_hi_sha='d55acc33d7ac28e366d069091a5c150a1f88bdc16899bfa57ba3693d5ab9b0c8'))


def _hosted():
    return (os.environ.get('GITHUB_ACTIONS')=='true'
        and os.environ.get('RUNNER_OS')=='Linux' and sys.platform=='linux'
        and os.environ.get('BITVM2_NOVA_CHAIN_TESTS')=='1')


def _canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,
                      allow_nan=False).encode('ascii')


def _keccak(raw):
    from Cryptodome.Hash import keccak
    return keccak.new(digest_bits=256,data=raw).digest()


def _word_permutation(raw):
    from keccak_trace import keccak_f1600
    lanes=tuple(int.from_bytes(raw[index:index+8],'little') for index in range(0,200,8))
    return b''.join(value.to_bytes(8,'little') for value in keccak_f1600(lanes))


def _message(raw_rho,coefficients,counter,branch):
    return b'p'+b''.join(coefficients)+b'NoDS'+counter.to_bytes(8,'little')+raw_rho+b'c'+bytes([int(branch=='hi')])


def _prefix(raw_rho,coefficients,counter):
    return _message(raw_rho,coefficients,counter,'lo')[:136]+bytes(64)


def _suffix(raw_rho,branch):
    return raw_rho[59:64]+b'c'+bytes([int(branch=='hi'),1])+bytes(127)+b'\x80'+bytes(64)


def _absorbed(prefix_output,raw_rho,branch):
    return bytes(left^right for left,right in zip(prefix_output,_suffix(raw_rho,branch),strict=True))


def _byte_truth(leaf,values):
    if leaf.kind=='byte_xor':expected=values[0]^values[1]
    elif leaf.kind=='byte_and':expected=values[0]&values[1]
    elif leaf.kind=='byte_not':expected=values[0]^255
    elif leaf.kind=='byte_rol':
        shift,=leaf.argument
        expected=((values[0]<<shift)&255)|(values[1]>>(8-shift))
    elif leaf.kind=='byte_xor_const':expected=values[0]^leaf.argument[0]
    else:raise AssertionError('unexpected BYTE gate')
    return values[-1]==expected


def _last_round_producer(byte):
    # Independent Keccak LFSR constants and natural Chi/Iota terminal formula.
    lfsr=1;constants=[]
    for _ in range(24):
        value=0
        for bit in range(7):
            if lfsr&1:value^=1<<((1<<bit)-1)
            lfsr=((lfsr<<1)^(0x71 if lfsr&0x80 else 0))&255
        constants.append(value.to_bytes(8,'little'))
    offset=sum(1216+sum(bool(mask) for mask in row) for row in constants[:23])
    masks=constants[23]
    if byte<8 and masks[byte]:return offset+1216+sum(bool(mask) for mask in masks[:byte]),1
    return offset+1016+byte,2


class ByteRhoChainPureOracleTests(unittest.TestCase):
    def test_retained143_byte_messages_two_block_oracle_and_counter_events(self):
        import byte_rho_chain as chain
        import byte_sumcheck_absorb as absorb
        for vector in VECTORS:
            raw=bytes.fromhex(vector['raw_rho'])
            coefficients=tuple(bytes.fromhex(value) for value in vector['coefficients'])
            self.assertEqual(vector['c_counter'],vector['rho_counter']+1)
            self.assertTrue(all(int.from_bytes(value,'little')<vector['modulus'] for value in coefficients))
            state=_prefix(raw,coefficients,vector['c_counter'])
            self.assertEqual(chain.prefix_state_bytes(coefficients,raw,counter=vector['c_counter']),state)
            self.assertEqual(absorb.prefix_state_bytes(coefficients,raw,counter=vector['c_counter']),state)
            output=_word_permutation(state)
            self.assertEqual(sha256(output).hexdigest(),vector['prefix_sha'])
            final=[]
            for branch in ('lo','hi'):
                message=_message(raw,coefficients,vector['c_counter'],branch)
                self.assertEqual(chain.c_preimage(coefficients,raw,counter=vector['c_counter'],branch=branch),message)
                self.assertEqual(absorb.sumcheck_preimage(coefficients,raw,counter=vector['c_counter'],branch=branch),message)
                self.assertEqual(len(message),143)
                self.assertEqual(message[0],0x70)
                self.assertEqual(message[1:33],coefficients[0]);self.assertEqual(message[33:65],coefficients[1])
                self.assertEqual(message[65:69],b'NoDS')
                self.assertEqual(message[69:77],vector['c_counter'].to_bytes(8,'little'))
                self.assertEqual(message[77:141],raw)
                self.assertEqual(message[141:],bytes([0x63,int(branch=='hi')]))
                padded=message+b'\x01'+bytes(127)+b'\x80'
                self.assertEqual(len(padded),272)
                self.assertEqual(state[:136],padded[:136]);self.assertEqual(state[136:],bytes(64))
                self.assertEqual(padded[136:],_suffix(raw,branch)[:136])
                absorbed=_absorbed(output,raw,branch)
                self.assertEqual(chain.suffix_state_bytes(output,raw,branch=branch),absorbed)
                self.assertEqual(absorb.absorbed_state_bytes(output,raw,branch=branch),absorbed)
                self.assertEqual(absorb.suffix_rate_bytes(raw,branch=branch),padded[136:])
                self.assertEqual(absorbed[136:],output[136:])
                self.assertEqual(sha256(absorbed).hexdigest(),vector['absorb_'+branch+'_sha'])
                digest=_word_permutation(absorbed)[:32]
                self.assertEqual(digest,_keccak(message))
                final.append(digest)
            wide=b''.join(final)
            self.assertEqual(wide.hex(),vector['raw_c'])
            self.assertEqual((int.from_bytes(wide,'little')%vector['modulus']).to_bytes(32,'little').hex(),vector['challenge'])
            self.assertEqual([index for index,(lo,hi) in enumerate(zip(_absorbed(output,raw,'lo'),_absorbed(output,raw,'hi')))
                              if lo!=hi],[6])

    def test_split59_5_capacity_and_unchanged_caps_are_explicit(self):
        import byte_rho_chain as chain
        from trace import MAX_CONSTRAINTS,MAX_WORDS
        from wots_graph import MAX_GRAPH_LEAVES
        self.assertEqual((MAX_CONSTRAINTS,MAX_WORDS,MAX_GRAPH_LEAVES),(10000,100000,30000))
        self.assertEqual((sum(COMPONENT_LEAVES),sum(COMPONENT_WORDS)),(147043,148401))
        self.assertEqual(sum(COMPONENT_WORDS)-147355,1046)
        self.assertGreater(sum(COMPONENT_LEAVES),MAX_GRAPH_LEAVES)
        self.assertTrue(all(leaves<=MAX_GRAPH_LEAVES for leaves in COMPONENT_LEAVES))
        self.assertEqual(chain.component_sizes(),tuple(zip(COMPONENT_WORDS,COMPONENT_LEAVES,strict=True)))
        self.assertEqual(len(PREFIX_FIXED),77)
        for vector,last in zip(VECTORS,('cfd04bdc7f','f85e73936d'),strict=True):
            raw=bytes.fromhex(vector['raw_rho']);coefficients=tuple(bytes.fromhex(value) for value in vector['coefficients'])
            first=_prefix(raw,coefficients,vector['c_counter'])
            self.assertEqual(first[77:136],raw[:59])
            self.assertEqual(raw[59:].hex(),last)
            self.assertEqual(_suffix(raw,'lo')[:5],raw[59:])
            prefix_output=_word_permutation(first)
            lo=_absorbed(prefix_output,raw,'lo');hi=_absorbed(prefix_output,raw,'hi')
            self.assertEqual(lo[136:200],prefix_output[136:200])
            self.assertEqual(hi[136:200],prefix_output[136:200])
            self.assertNotEqual(prefix_output[136:200],bytes(64))
            self.assertEqual(lo[6],prefix_output[6]);self.assertEqual(hi[6],prefix_output[6]^1)
            self.assertEqual((lo[7],lo[135]),(prefix_output[7]^1,prefix_output[135]^128))

    def test_small_normative_maps_preserve_raw64_provenance_and199_shared_suffix_inputs(self):
        import byte_rho_chain as chain
        import byte_sumcheck_absorb as absorb
        local=lambda state,byte:f'byte-state/{state}/l{byte//8}/byte{byte%8}'
        raw=tuple(chain.rho_raw_global_id(index) for index in range(64))
        self.assertEqual(raw,tuple('rho/branch/'+('lo' if index<32 else 'hi')+'/'+local(24,index%32) for index in range(64)))
        for degree,start in ((0,1),(2,33)):
            for byte in range(32):
                self.assertEqual(chain.full_global_id(4,local(0,start+byte)),f'c/coeff/{degree}/byte/{byte}')
        self.assertEqual(tuple(chain.full_global_id(4,local(0,77+byte)) for byte in range(59)),raw[:59])
        self.assertEqual(chain.full_global_id(4,local(0,136)),'c/prefix/'+local(0,136))
        self.assertNotEqual(chain.full_global_id(4,local(0,136)),raw[59])
        hi=tuple(chain.full_global_id(6,local(0,index)) for index in range(200))
        lo=tuple(chain.full_global_id(7,local(0,index)) for index in range(200))
        common=(0,1,2,3,4,5,7,135)
        self.assertEqual(len(set(hi)&set(lo)),199)
        for byte in range(200):
            if byte in common:self.assertEqual((hi[byte],lo[byte]),(f'c/suffix/shared/byte/{byte}',)*2)
            elif byte==6:
                self.assertEqual(hi[byte],'c/suffix/hi/byte/6')
                self.assertEqual(lo[byte],'c/prefix/'+local(24,byte))
            else:self.assertEqual((hi[byte],lo[byte]),('c/prefix/'+local(24,byte),)*2)
        maps=absorb._maps()
        self.assertEqual(maps['shared_final_input_positions'],tuple(index for index in range(200) if index!=6))
        self.assertEqual(maps['capacity_positions'],tuple(range(136,200)))
        self.assertEqual((len(maps['prefix_lo_forward_positions']),len(maps['prefix_hi_forward_positions'])),(192,191))
        words,gates=absorb._expected_shape()
        self.assertEqual((len(words),len(gates)),(23,9))
        self.assertTrue(all(type(bound) is int and bound==256 for _,bound in words))
        self.assertEqual(tuple(kind for kind,_,_ in gates),('byte_xor',)*5+('byte_xor_const',)*4)
        self.assertEqual(tuple(arguments for _,arguments,_ in gates[5:]),((99,),(1,),(128,),(1,)))
        self.assertEqual(tuple(gate[2][-1] for gate in gates),
            tuple(f'shared/byte/{index}' for index in common)+('hi/selector',))

    def test_pure_coefficient_canonicality_and_typed_nested_id_preflight(self):
        import byte_rho_chain as chain
        import byte_sumcheck_frame as frame
        for vector in VECTORS:
            role=vector['role'];modulus=vector['modulus']
            valid=(bytes(32),(modulus-1).to_bytes(32,'little'))
            self.assertEqual(frame._coefficients(valid,role),valid)
            self.assertEqual(valid[1][-1],0x40,'canonicality requires full comparison, not a top-byte shortcut')
            for index in (0,1):
                for bad in (modulus.to_bytes(32,'little'),(modulus+1).to_bytes(32,'little'),
                            bytes([255])*32,bytes(31),bytes(33),bytearray(32),None,True):
                    values=list(valid);values[index]=bad
                    with self.assertRaises(ValueError):frame._coefficients(tuple(values),role)
            for values in (None,True,(),(bytes(32),),(bytes(32),)*3,[bytes(32),bytes(32)]):
                with self.assertRaises(ValueError):frame._coefficients(values,role)
            self.assertEqual(frame.fixed_prefix_bytes(vector['c_counter']),tuple(
                (index,_prefix(bytes(64),(bytes(32),bytes(32)),vector['c_counter'])[index]) for index in PREFIX_FIXED))
        with patch.object(chain,'build_byte_keccak_permutation',side_effect=AssertionError('pure preflight built full graph')) as full:
            for role in ('pallas_scalar','vesta_scalar'):
                chain._parameters(CONTEXT,role,0,OPERATION)
                chain._parameters(CONTEXT,role,(1<<64)-2,OPERATION)
            chain._parameters(CONTEXT,'pallas_scalar',8,'x'*148)
            for context,role,counter,operation in (
                (CONTEXT,'pallas_scalar',True,OPERATION),(CONTEXT,'pallas_scalar',-1,OPERATION),
                (CONTEXT,'pallas_scalar',(1<<64)-1,OPERATION),(CONTEXT,'pallas_base',59,OPERATION),
                (bytes(31),'pallas_scalar',59,OPERATION),(bytearray(32),'pallas_scalar',59,OPERATION),
                (CONTEXT,'pallas_scalar',9,'x'*148),(CONTEXT,'pallas_scalar',59,'x'*193)):
                with self.assertRaises(ValueError):chain._parameters(context,role,counter,operation)
            full.assert_not_called()

    def test_pure_framing_types_and_resource_guards_precede_big_allocation(self):
        import byte_rho_chain as chain
        import byte_sumcheck_frame as frame
        import byte_sumcheck_absorb as absorb
        coefficients=(bytes(32),bytes(32))
        for counter in (True,False,-1,1<<64,1.0,None):
            with self.assertRaises(ValueError):chain.c_preimage(coefficients,bytes(64),counter=counter,branch='lo')
        for branch in (True,False,0,1,'HI',None):
            with self.assertRaises(ValueError):chain.c_preimage(coefficients,bytes(64),counter=60,branch=branch)
        for raw in (None,True,bytes(32),bytes(63),bytes(65),bytearray(64)):
            with self.assertRaises(ValueError):chain.c_preimage(coefficients,raw,counter=60,branch='lo')
        for index in (True,False,-1,2,3,5,8,9):
            with self.assertRaises(ValueError):chain.full_global_id(index,'byte-state/0/l0/byte0')
        for github,runner,platform in [('false','Linux','linux'),('true','Windows','linux'),('true','Linux','win32')]:
            with patch.dict(os.environ,{'GITHUB_ACTIONS':github,'RUNNER_OS':runner,'BITVM2_NOVA_CHAIN_TESTS':'1'},clear=True),\
                patch.object(chain.sys,'platform',platform),\
                patch.object(chain,'build_byte_keccak_permutation',side_effect=AssertionError('full graph allocated')) as full,\
                patch('builtins.open',side_effect=AssertionError('I/O before guard')) as io:
                with self.assertRaisesRegex(ValueError,'hosted GitHub Linux'):
                    chain.build_byte_rho_chain(context=None,role=None,rho_counter=None)
                empty=object.__new__(chain.ByteRhoChainPlan)
                with self.assertRaisesRegex(ValueError,'hosted GitHub Linux'):empty.bind(None,None,None)
                with self.assertRaisesRegex(ValueError,'hosted GitHub Linux'):empty.regenerate_component(None)
                binding=object.__new__(chain.ByteRhoChainBinding)
                with self.assertRaisesRegex(ValueError,'hosted GitHub Linux'):binding.iter_components()
                with self.assertRaisesRegex(ValueError,'hosted GitHub Linux'):frame.build_sumcheck_frame(context=None,role=None,counter=None)
                with self.assertRaisesRegex(ValueError,'hosted GitHub Linux'):absorb.build_sumcheck_absorb(context=None,role=None)
                full.assert_not_called();io.assert_not_called()
        for cls in (chain.ByteRhoChainPlan,chain.ByteRhoChainBinding,chain.ByteRhoChainComponentDescriptor,
                    chain.ByteRhoChainComponentSource,chain.ByteRhoChainComponentBinding,
                    frame.SumcheckFrame,frame.SumcheckFrameBinding,absorb.SumcheckAbsorbPlan,absorb.SumcheckAbsorbBinding):
            with self.assertRaises(TypeError):cls()
            self.assertFalse(hasattr(cls,'from_json'))
        for key in ('raw_rho','rho_scalar','rho','compressed_coefficients','components','source_maps','manifest','receipt','program','spec'):
            with self.assertRaises(TypeError):chain.build_byte_rho_chain(
                context=CONTEXT,role='pallas_scalar',rho_counter=59,**{key:{'passed':True}})

    def test_wrong_split_reduced_scalar_counter_label_selector_and_capacity_are_distinct(self):
        for vector in VECTORS:
            raw=bytes.fromhex(vector['raw_rho']);coefficients=tuple(bytes.fromhex(value) for value in vector['coefficients'])
            correct=_message(raw,coefficients,vector['c_counter'],'lo')
            expected=bytes.fromhex(vector['raw_c'])[:32]
            swapped=bytearray(raw);swapped[58],swapped[59]=swapped[59],swapped[58]
            reduced=(int.from_bytes(raw,'little')%vector['modulus']).to_bytes(32,'little')+bytes(32)
            wrong_label=bytearray(correct);wrong_label[141]=0x72
            for wrong in (_message(bytes(swapped),coefficients,vector['c_counter'],'lo'),
                          _message(reduced,coefficients,vector['c_counter'],'lo'),
                          _message(raw,coefficients,vector['rho_counter'],'lo'),bytes(wrong_label),
                          _message(raw,coefficients,vector['c_counter'],'hi')):
                self.assertNotEqual(_keccak(wrong),expected)
            prefix_output=_word_permutation(_prefix(raw,coefficients,vector['c_counter']))
            absorbed=_absorbed(prefix_output,raw,'lo')
            zeroed=absorbed[:136]+bytes(64)
            self.assertNotEqual(_word_permutation(zeroed)[:32],expected)


@unittest.skipUnless(_hosted(),'dedicated GHA Linux job and BITVM2_NOVA_CHAIN_TESTS=1 required')
class HostedByteRhoChainTests(unittest.TestCase):
    def setUp(self):
        if not _hosted():self.skipTest('dedicated opt-in before any full graph or Script allocation')
        import byte_rho_chain
        self.chain=byte_rho_chain

    def assert_maps(self,plan,maps,vector):
        self.assertFalse(hasattr(plan,'program'));self.assertFalse(hasattr(plan,'spec'))
        self.assertEqual((plan.rho_counter,plan.c_counter),(vector['rho_counter'],vector['c_counter']))
        self.assertEqual(tuple((row.words,row.leaves) for row in plan.components),tuple(zip(COMPONENT_WORDS,COMPONENT_LEAVES,strict=True)))
        self.assertEqual(plan.source_sha256,sha256(b'BITVM2-NOVA/BYTE-RHO-CHAIN-SOURCE/v1\x00'+_canonical(plan.manifest)).digest())
        self.assertEqual(plan.source_maps_sha256,sha256(_canonical(maps)).digest())
        self.assertEqual(plan.manifest['components'],[row.json() for row in plan.components])
        self.assertEqual((maps['leaves'],maps['local_declared_words'],maps['unique_global_words'],maps['cached_signature_reuses']),
                         (147043,148401,147355,1046))
        self.assertEqual(maps['first_block']['raw_rho_prefix_bytes'],59)
        self.assertIs(maps['first_block']['unpadded'],True)
        self.assertEqual(maps['second_block']['raw_rho_indices'],list(range(59,64)))
        self.assertEqual(maps['second_block']['forwarded_capacity'],list(range(136,200)))
        self.assertEqual(maps['coefficient_degrees'],[0,2])
        counts=dict(rho_messages=96,rho_frames=208,rho_reduction=64,coefficients=64,prefix_frame=77,
            rho_raw_prefix=59,rho_raw_absorb=5,prefix_absorb=9,prefix_suffix=383,absorb_suffix=17,c_reduction=64)
        self.assertEqual({name:len(rows) for name,rows in maps['connections'].items()},counts)
        self.assertEqual(sum(counts.values()),1046)
        rows=maps['components']
        self.assertEqual(len(rows),9)
        sets=[];lookups=[]
        for index,facts in enumerate(rows):
            self.assertEqual((facts['index'],facts['branch']),(index,plan.components[index].branch))
            lookup={row['global_id']:row for row in facts['interfaces']}
            self.assertEqual(len(lookup),len(facts['interfaces']))
            lookups.append(lookup);sets.append(set(lookup))
        self.assertEqual(sum(map(len,sets)),3176)
        self.assertEqual(sum(map(len,sets))-len(set.union(*sets)),1046)
        self.assertEqual(len(maps['pair_intersections']),36)
        for record in maps['pair_intersections']:
            common=sets[record['left']]&sets[record['right']]
            self.assertEqual(record['words'],len(common))
            self.assertEqual(record['global_ids_sha256'],sha256(_canonical(sorted(common))).hexdigest())
        self.assertEqual(len(sets[6]&sets[7]),199)
        for group,connections in maps['connections'].items():
            for record in connections:
                name=record['global_id'];left=lookups[record['source_component']][name];right=lookups[record['target_component']][name]
                self.assertEqual((left['bound'],right['bound']),(256,256))
                self.assertEqual((record['source_word'],record['target_word']),(left['word_index'],right['word_index']))
                self.assertEqual(record['source_occurrences'],left['occurrences'])
                self.assertEqual(record['target_occurrences'],right['occurrences'])
        self.assertEqual(tuple(row['global_id'] for row in maps['connections']['rho_raw_prefix']),plan.ports['raw_rho'][:59])
        self.assertEqual(tuple(row['global_id'] for row in maps['connections']['rho_raw_absorb']),plan.ports['raw_rho'][59:])
        self.assertFalse(set(plan.ports['rho_scalar_result'])&set(row['global_id'] for row in maps['connections']['rho_raw_prefix']))
        self.assertEqual(plan.ports['compressed_coefficients'],tuple(tuple(f'c/coeff/{degree}/byte/{byte}' for byte in range(32)) for degree in (0,2)))
        for summary in (plan.summary(),):
            for name in FALSE_FLAGS:self.assertIs(summary[name],False)

    def assert_component(self,item,facts,binding,vector,cache):
        from trace import MAX_CONSTRAINTS
        from wots_graph import MAX_GRAPH_LEAVES
        spec=item.spec;values=item.assignment
        self.assertEqual((len(spec.words),len(spec.leaves)),(COMPONENT_WORDS[item.index],COMPONENT_LEAVES[item.index]))
        self.assertLessEqual(len(spec.leaves),MAX_GRAPH_LEAVES)
        self.assertEqual(spec.digest().hex(),item.descriptor.catalogue_id)
        self.assertEqual(spec.program_sha256,item.descriptor.program_sha256)
        self.assertEqual((spec.context,spec.field_role),(CONTEXT.hex(),vector['role']))
        self.assertEqual(item.descriptor.global_ids_sha256,sha256(_canonical(item.global_ids)).hexdigest())
        self.assertEqual(item.descriptor.source_maps_sha256,sha256(item._source_maps).hexdigest())
        self.assertTrue(all(type(values[word]) is int and 0<=values[word]<bound for word,bound in spec.words))
        if item.program is None:
            self.assertIn(item.index,(0,1,4,6,7))
            program=item.child_program_manifest
            self.assertEqual(item.descriptor.program_sha256,sha256(b'BITVM2-NOVA/BYTE-KECCAK-PERMUTATION-PROGRAM/v1\x00'+_canonical(program)).hexdigest())
            source_domain=b'BITVM2-NOVA/BYTE-KECCAK-PERMUTATION-SOURCE/v1\x00'
            self.assertTrue(all(self.chain.full_global_id(item.index,word)==global_id for (word,_),global_id in zip(spec.words,item.global_ids,strict=True)))
            del program
        else:
            self.assertLessEqual(len(item.program.constraints),MAX_CONSTRAINTS)
            self.assertEqual(item.program.digest().hex(),item.descriptor.program_sha256)
            self.assertEqual(item.program.bind(values).failures(),())
            source_domain={2:b'BITVM2-NOVA/BYTE-RHO-TAIL/v1\x00',3:b'BITVM2-NOVA/BYTE-SUMCHECK-FRAME/v1\x00',
                5:b'BITVM2-NOVA/BYTE-SUMCHECK-ABSORB/v1\x00',8:b'BITVM2-NOVA/BYTE-RHO-CHAIN-UNIFORM/v1\x00'}[item.index]
        self.assertEqual(item.descriptor.source_sha256,sha256(source_domain+_canonical(item.child_source_manifest)).hexdigest())
        actual={row['word_index']:[] for row in facts['interfaces']}
        for ordinal,leaf in enumerate(spec.leaves):
            operands=tuple(values[spec.words[word][0]] for word in leaf.wires)
            if item.program is None or item.index==5:self.assertTrue(_byte_truth(leaf,operands))
            elif ordinal<len(item.program.constraints):self.assertTrue(item.program.constraints[ordinal].native(values,item.program.p))
            else:
                self.assertEqual(leaf.kind,'field_valid')
                self.assertLess(sum(value<<(29*index) for index,value in enumerate(operands)),item.program.p)
            for formal,word in enumerate(leaf.wires):
                if word in actual:actual[word].append([ordinal,formal])
        reused=0
        for row in facts['interfaces']:
            word=row['word_index'];name=row['global_id'];bound=spec.words[word][1];value=values[spec.words[word][0]]
            self.assertEqual(item.global_ids[word],name)
            self.assertEqual(row['bound'],bound)
            self.assertEqual(row['occurrences'],actual[word])
            if name in cache:
                self.assertEqual(cache[name],(bound,value));reused+=1
            else:cache[name]=(bound,value)
        if item.program is None:
            initial={0:binding.initial_rho_hi,1:binding.initial_rho_lo,4:binding.initial_prefix,6:binding.initial_c_hi,7:binding.initial_c_lo}[item.index]
            output={0:binding.rho_hi_output,1:binding.rho_lo_output,4:binding.prefix_output,6:binding.c_hi_output,7:binding.c_lo_output}[item.index]
            self.assertEqual(bytes(values[spec.words[word][0]] for word in facts['input_indices']),initial)
            self.assertEqual(bytes(values[spec.words[word][0]] for word in facts['output_indices']),output)
            for byte,word in enumerate(facts['input_indices']):
                lane,j=divmod(byte,8);x,y=lane%5,lane//5
                self.assertEqual(actual[word],[[x*32+j*4+max(y-1,0),0 if y==0 else 1],[240+byte,0]])
            for byte,word in enumerate(facts['output_indices']):
                ordinal,formal=_last_round_producer(byte)
                self.assertEqual(actual[word],[[ordinal,formal]])
                self.assertEqual((facts['producer_ordinals'][byte],facts['producer_occurrences'][byte]),(ordinal,formal))
        elif item.index==3:
            maps=item.child_source_maps
            self.assertEqual(spec.field_leaves,(('coefficient/0/result',109),('coefficient/2/result',110)))
            self.assertEqual(len(maps['canonical_internal_links']),46)
            self.assertEqual(len(maps['frame_anchors']),77)
            self.assertEqual(maps['coefficient_degrees'],[0,2])
            for child in maps['children']:
                self.assertEqual(len(child['word_map']),55);self.assertEqual(len(child['leaf_map']),17)
                self.assertEqual(child['uniform_word_map'],list(range(129,184)))
                self.assertEqual(child['uniform_leaf_map'],list(range(65,81))+[244])
            for slot,raw in zip(maps['coefficient_byte_indices'],binding.compressed_coefficients,strict=True):
                self.assertEqual(bytes(values[spec.words[word][0]] for word in slot),raw)
            for anchor in maps['frame_anchors']:
                self.assertEqual(values[anchor['word']],anchor['expected'])
                leaf=spec.leaves[anchor['anchor_ordinal']]
                self.assertEqual((leaf.kind,leaf.argument,leaf.wires),('const',(anchor['expected'],),(anchor['word_index'],)))
            for link in maps['canonical_internal_links']:
                self.assertEqual(spec.leaves[link['source_ordinal']].wires[link['source_occurrence']],link['word_index'])
                self.assertEqual(spec.leaves[link['target_ordinal']].wires[link['target_occurrence']],link['word_index'])
            del maps
        elif item.index==5:
            maps=item.child_source_maps
            self.assertEqual(maps['capacity_positions'],list(range(136,200)))
            self.assertEqual(maps['shared_final_input_positions'],[index for index in range(200) if index!=6])
            outputs=tuple(values[word] for word in maps['ports']['gate_outputs'])
            expected=tuple(binding.prefix_output[i]^binding.raw_rho[59+i] for i in range(5))+(binding.prefix_output[5]^99,
                binding.prefix_output[7]^1,binding.prefix_output[135]^128,binding.prefix_output[6]^1)
            self.assertEqual(outputs,expected)
            del maps
        if item.index in (2,8):
            # Preserve the actual original245-leaf reducer, including every
            # carry/quotient/unit/encoding leaf and its canonical field guard.
            from uniform_reduce import build_uniform_reduction
            from wots_graph import GraphSpec
            raw=binding.raw_rho if item.index==2 else binding.raw_c
            operation=item.program.operation_id+('/uniform' if item.index==2 else '')
            original=build_uniform_reduction(raw,context=CONTEXT,role=vector['role'],operation_id=operation)
            original_spec=GraphSpec.from_program(original.program)
            maps=item.child_source_maps
            word_map=maps['uniform_word_map' if item.index==2 else 'word_map']
            leaf_map=maps['uniform_leaf_map' if item.index==2 else 'leaf_map']
            self.assertEqual(word_map,list(range(379)))
            self.assertEqual(leaf_map,list(range(244))+[452] if item.index==2 else list(range(245)))
            self.assertEqual(spec.words[:379],original_spec.words)
            self.assertEqual(item.program.constraints[:244],original.program.constraints)
            self.assertEqual(item.program.fields,original.program.fields)
            bodies=dict(spec.bodies);original_bodies=dict(original_spec.bodies)
            for before,after in enumerate(leaf_map):
                self.assertEqual(spec.leaves[after],original_spec.leaves[before])
                self.assertEqual(bodies[spec.leaves[after].body_sha256],original_bodies[original_spec.leaves[before].body_sha256])
            self.assertEqual(tuple(values[word] for word in original.ports['input_bytes']),tuple(raw))
            self.assertEqual(tuple(values[word] for word in original.ports['carries'])[::65],(8192,8192))
            self.assertEqual(values[original.ports['constant_one']],1)
            self.assertEqual(values[original.ports['quotient_top_high']],0)
            del original,original_spec,maps,bodies,original_bodies
        self.assert_small_guards(item,values)
        return reused

    def assert_small_guards(self,item,values):
        if item.program is None:return
        from script import execute,num
        bound=item.program.bind(values)
        selected={}
        for ordinal,constraint in enumerate(item.program.constraints):selected.setdefault(constraint.kind,ordinal)
        for ordinal in selected.values():
            witness=bound.witness(ordinal)
            for disprove in (False,True):
                code=bound.script(ordinal,disprove=disprove)
                self.assertEqual(execute(code,witness).success,not disprove)
                for malformed in ((),witness[:-1],(b'',)+witness,witness+(b'',)):
                    result=execute(code,malformed)
                    self.assertFalse(result.success);self.assertEqual(result.error,'EQUALVERIFY')
                first=item.program.constraints[ordinal].wires[0]
                result=execute(code,(num(values[first]^1),)+witness[1:])
                self.assertFalse(result.success);self.assertEqual(result.error,'EQUALVERIFY')
        bound.require_identity(item.program.digest(),bound.claim_digest)
        with self.assertRaises(ValueError):bound.require_identity(bytes(32),bound.claim_digest)
        with self.assertRaises(ValueError):bound.require_identity(item.program.digest(),bytes(32))

    def focused_probes(self,plan,maps,honest,vector):
        """Word references and small catalogues only; never another full stream."""
        import byte_sumcheck_frame as frame_module
        import byte_sumcheck_absorb as absorb_module
        from uniform_reduce import build_uniform_reduction
        from script import OPS,execute,num
        modulus=vector['modulus'];coefficients=honest.compressed_coefficients
        identity=(plan.source_sha256,plan.source_maps_sha256,tuple(plan.components))

        # The last HI digest byte is raw byte63: suffix gate4 sees it, whereas
        # the unpadded first block consumes only bytes0..58 and stays unchanged.
        changed=bytearray(honest.rho_hi_output);changed[31]^=1
        fault=plan.bind(honest.eval_w,honest.prior_state,coefficients,claimed_rho_hi_output=bytes(changed))
        self.assertEqual([i for i,(a,b) in enumerate(zip(fault.raw_rho,honest.raw_rho)) if a!=b],[63])
        self.assertEqual(fault.initial_prefix,honest.initial_prefix)
        self.assertEqual(fault.prefix_output,honest.prefix_output)
        for branch in ('hi','lo'):
            before=getattr(honest,'initial_c_'+branch);after=getattr(fault,'initial_c_'+branch)
            self.assertEqual([i for i,(a,b) in enumerate(zip(before,after)) if a!=b],[4])
            self.assertEqual(getattr(fault,'c_'+branch+'_output'),_word_permutation(after))
        self.assertEqual(fault.rho_result_value,int.from_bytes(fault.raw_rho,'little')%modulus)
        self.assertEqual(fault.c_result_value,int.from_bytes(fault.raw_c,'little')%modulus)
        self.assertIs(fault.summary()['rho_reference_matches'],False)
        self.assertIs(fault.summary()['prefix_reference_matches'],True)
        self.assertIs(fault.summary()['c_reference_matches'],False)
        self.assertIs(fault.summary()['c_reduction_relation_holds'],True)
        self.assertEqual(maps['components'][0]['producer_occurrences'][31],2)
        del fault,changed

        # Capacity byte136 is an actual prefix OUTPUT. It must reach both
        # suffix inputs unchanged; none of the nine absorption gates uses it.
        changed=bytearray(honest.prefix_output);changed[136]^=1
        fault=plan.bind(honest.eval_w,honest.prior_state,coefficients,claimed_prefix_output=bytes(changed))
        self.assertEqual(fault.raw_rho,honest.raw_rho)
        self.assertEqual(fault.initial_prefix,honest.initial_prefix)
        self.assertEqual(fault.initial_prefix[136:],bytes(64))
        self.assertEqual(fault.prefix_output[136],honest.prefix_output[136]^1)
        for branch in ('hi','lo'):
            before=getattr(honest,'initial_c_'+branch);after=getattr(fault,'initial_c_'+branch)
            self.assertEqual([i for i,(a,b) in enumerate(zip(before,after)) if a!=b],[136])
            self.assertEqual(after[136:],fault.prefix_output[136:])
            self.assertEqual(getattr(fault,'c_'+branch+'_output'),_word_permutation(after))
        self.assertEqual(fault.c_result_value,int.from_bytes(fault.raw_c,'little')%modulus)
        self.assertIs(fault.summary()['rho_reference_matches'],True)
        self.assertIs(fault.summary()['prefix_reference_matches'],False)
        self.assertIs(fault.summary()['c_reference_matches'],False)
        self.assertEqual(maps['components'][4]['producer_occurrences'][136],2)
        del fault,changed

        # A value-only input substitution is admitted by these arithmetic
        # fragments. Its upstream proof/transcript origin remains an open port.
        other=plan.bind(bytes(32),bytes(64),(bytes(32),(modulus-1).to_bytes(32,'little')))
        self.assertEqual(other.plan.source_sha256,identity[0])
        for branch in ('hi','lo'):
            self.assertEqual(getattr(other,'c_'+branch+'_output')[:32],_keccak(_message(
                other.raw_rho,other.compressed_coefficients,vector['c_counter'],branch)))
        for flag in FALSE_FLAGS:self.assertIs(other.summary()[flag],False)
        del other

        # No large graph is created by bind. Public coefficient admission must
        # precede even the word permutation; a p alias is not an alternate c0/c2.
        with patch.object(self.chain,'_permutation',side_effect=AssertionError('invalid input reached permutation')) as word:
            for index in (0,1):
                for bad in (modulus.to_bytes(32,'little'),(modulus+1).to_bytes(32,'little'),bytearray(32),bytes(31)):
                    candidate=list(coefficients);candidate[index]=bad
                    with self.assertRaises(ValueError):plan.bind(honest.eval_w,honest.prior_state,tuple(candidate))
            for bad in (modulus.to_bytes(32,'little'),bytes(31),bytearray(32),True):
                with self.assertRaises(ValueError):plan.bind(bad,honest.prior_state,coefficients)
            for bad in (bytes(63),bytearray(64),None):
                with self.assertRaises(ValueError):plan.bind(honest.eval_w,bad,coefficients)
            for key in ('claimed_rho_hi_output','claimed_prefix_output','claimed_c_hi_output','claimed_c_lo_output'):
                for bad in (bytes(199),bytearray(200),True):
                    with self.assertRaises(ValueError):plan.bind(honest.eval_w,honest.prior_state,coefficients,**{key:bad})
            for key in ('raw_rho','rho_scalar','rho','components','source_maps','manifest','receipt','program','spec'):
                with self.assertRaises(TypeError):plan.bind(honest.eval_w,honest.prior_state,coefficients,**{key:bytes(64)})
            word.assert_not_called()

        # The coefficient encodings are actual small Programs. Re-witnessing a
        # modulus alias preserves their arithmetic but must fail field_valid.
        frame=frame_module.build_sumcheck_frame(context=CONTEXT,role=vector['role'],counter=vector['c_counter'],
            operation_id=plan.components[3].operation_id)
        self.assertEqual(frame.source_sha256.hex(),plan.components[3].source_sha256)
        canonical=frame.bind((bytes(32),(modulus-1).to_bytes(32,'little')))
        self.assertEqual(canonical.program.bind(canonical.assignment).failures(),())
        copied=canonical.assignment;first=next(iter(copied));copied[first]^=1
        self.assertNotEqual(copied,canonical.assignment)
        del canonical,copied
        for degree,ordinal in ((0,109),(2,110)):
            probe=frame_module._bind_modulus_fault(frame,coefficients,degree);values=probe.assignment
            self.assertEqual(probe.program.digest(),frame.program.digest())
            self.assertEqual(probe.source_sha256,frame.source_sha256)
            self.assertTrue(all(c.native(values,modulus) for c in probe.program.constraints))
            failed=[]
            for _,leaf_ordinal in probe.spec.field_leaves:
                leaf=probe.spec.leaves[leaf_ordinal]
                scalar=sum(values[probe.spec.words[word][0]]<<(29*i) for i,word in enumerate(leaf.wires))
                if scalar>=modulus:failed.append(leaf_ordinal)
            self.assertEqual(failed,[ordinal])
            leaf=probe.spec.leaves[ordinal]
            code=bytes.fromhex(dict(probe.spec.bodies)[leaf.body_sha256])
            witness=tuple(num(values[probe.spec.words[word][0]]) for word in leaf.wires)
            correct=execute(code,witness);disproof=execute(code+bytes([OPS['NOT']]),witness)
            self.assertFalse(correct.success);self.assertIsNone(correct.error)
            self.assertTrue(disproof.success);self.assertIsNone(disproof.error)
            with self.assertRaises(ValueError):probe.program.bind(values)
            del probe,values
        for byte in (0,65,69,136,199):
            expected=dict(frame_module.fixed_prefix_bytes(vector['c_counter']))[byte]
            probe=frame_module._bind_frame_fault(frame,coefficients,byte,expected^1)
            values=probe.assignment;bound=probe.program.bind(values)
            ordinal=32+PREFIX_FIXED.index(byte)
            self.assertEqual(bound.failures(),(ordinal,))
            self.assertFalse(bound.execute(ordinal,disprove=False).success)
            result=bound.execute(ordinal,disprove=True)
            self.assertTrue(result.success);self.assertIsNone(result.error)
            del probe,values,bound
        del frame

        absorb=absorb_module.build_sumcheck_absorb(context=CONTEXT,role=vector['role'],
            operation_id=plan.components[5].operation_id)
        normal=absorb.bind(honest.prefix_output,honest.raw_rho)
        self.assertEqual((normal.lo_state,normal.hi_state),(honest.initial_c_lo,honest.initial_c_hi))
        forwarded=bytearray(honest.prefix_output);forwarded[136]^=1
        capacity=absorb.bind(bytes(forwarded),honest.raw_rho)
        self.assertEqual(capacity.outputs,normal.outputs)
        self.assertEqual(capacity.lo_state[136:],bytes(forwarded)[136:])
        self.assertEqual(capacity.hi_state[136:],bytes(forwarded)[136:])
        del capacity,forwarded
        for ordinal in range(9):
            claims=[None]*9;claims[ordinal]=normal.outputs[ordinal]^1
            probe=absorb.bind(honest.prefix_output,honest.raw_rho,claimed_outputs=tuple(claims))
            bound=absorb.program.bind(probe.assignment)
            self.assertEqual(bound.failures(),(ordinal,))
            for disprove in (False,True):
                result=bound.execute(ordinal,disprove=disprove)
                self.assertEqual(result.success,disprove);self.assertIsNone(result.error)
            del probe,bound
        del absorb,normal

        wrong=build_uniform_reduction(honest.raw_c,context=CONTEXT,role=vector['role'],
            operation_id=plan.components[8].operation_id,claimed_result=(honest.c_result_value+1)%modulus)
        bound=wrong.program.bind(wrong.assignment)
        self.assertTrue(bound.failures())
        self.assertEqual(wrong.program.digest().hex(),plan.components[8].program_sha256)
        ordinal=bound.failures()[0]
        self.assertFalse(bound.execute(ordinal,disprove=False).success)
        result=bound.execute(ordinal,disprove=True)
        self.assertTrue(result.success);self.assertIsNone(result.error)
        del wrong,bound

        # Snapshot edits and input values cannot mutate a sealed source. Hash
        # admission binds counter/context/role/operation without building four
        # additional full plans merely to exercise those public identities.
        for obj,name,value in ((plan,'rho_counter',0),(plan.components[0],'counter',0),(honest,'eval_w',bytes(32))):
            with self.assertRaises((FrozenInstanceError,AttributeError)):setattr(obj,name,value)
        with self.assertRaises(TypeError):plan.ports['raw_rho']=()
        snapshot=plan.source_maps;snapshot['components'][0]['interfaces'][0]['global_id']='changed'
        self.assertNotEqual(snapshot,plan.source_maps);del snapshot
        for key,replacement in (('rho_counter',0),('c_counter',0),('context',bytes(32).hex()),
                                ('field_role','vesta_scalar' if vector['role']=='pallas_scalar' else 'pallas_scalar'),
                                ('operation_id',OPERATION+'/other')):
            snapshot=plan.manifest;snapshot[key]=replacement
            self.assertNotEqual(sha256(self.chain.SOURCE_DOMAIN+_canonical(snapshot)).digest(),identity[0])
            del snapshot
        self.assertEqual((plan.source_sha256,plan.source_maps_sha256,tuple(plan.components)),identity)

    def test_two_honest_streams_and_focused_probes_one_role_component_at_a_time(self):
        for vector in VECTORS:
            plan=self.chain.build_byte_rho_chain(context=CONTEXT,role=vector['role'],rho_counter=vector['rho_counter'],operation_id=OPERATION)
            maps=plan.source_maps
            self.assert_maps(plan,maps,vector)
            eval_w=bytes.fromhex(vector['eval_w']);prior=bytes.fromhex(vector['prior'])
            coefficients=tuple(bytes.fromhex(value) for value in vector['coefficients'])
            binding=plan.bind(eval_w,prior,coefficients)
            self.assertEqual((binding.raw_rho.hex(),binding.raw_c.hex()),(vector['raw_rho'],vector['raw_c']))
            self.assertEqual(binding.c_result_value.to_bytes(32,'little').hex(),vector['challenge'])
            self.assertEqual((binding.rho_result_value,binding.c_result_value),
                (int.from_bytes(binding.raw_rho,'little')%vector['modulus'],int.from_bytes(binding.raw_c,'little')%vector['modulus']))
            self.assertEqual(sha256(binding.prefix_output).hexdigest(),vector['prefix_sha'])
            self.assertEqual(binding.initial_prefix,_prefix(binding.raw_rho,coefficients,vector['c_counter']))
            self.assertEqual(binding.initial_c_hi,_absorbed(binding.prefix_output,binding.raw_rho,'hi'))
            self.assertEqual(binding.initial_c_lo,_absorbed(binding.prefix_output,binding.raw_rho,'lo'))
            cache={};reused=0;seen=[]
            for item in binding.iter_components():
                self.assertEqual(item.descriptor,plan.components[item.index])
                reused+=self.assert_component(item,maps['components'][item.index],binding,vector,cache)
                seen.append(item.index)
                del item
            self.assertEqual(seen,list(range(9)))
            self.assertEqual((len(cache),reused),(2130,1046))
            for summary in (plan.summary(),binding.summary()):
                for name in FALSE_FLAGS:self.assertIs(summary[name],False)
            self.focused_probes(plan,maps,binding,vector)
            del cache,binding,maps,plan


if __name__=='__main__':
    unittest.main()


