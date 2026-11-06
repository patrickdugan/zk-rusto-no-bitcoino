"""Independent retained-admission references and opt-in source graph checks.

Local tests only read the small pinned fixture, parse bytes, and use integers.
No local graph construction, Script execution, keys, native jobs or proving.
"""
from dataclasses import FrozenInstanceError
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

from nht4 import HEADER_BYTES, bind_container, load_expected_json
from proof_codec import decode_proof, encode_proof, load_dimensions_json
from script import BASE, P, Q

FIXTURES = Path(__file__).resolve().parents[1]/'fixtures'
DIMENSIONS_PIN = bytes.fromhex('de6333df2e41b5f5bae1c103fab862f8d6022fd54abeb80ba61920bc9f360edc')
POLICY_PIN = 'cdfa31622881cc1863abd1eb252c136184501785b4b02e9985e6ba0850b2ac54'
CONTEXT = sha256(b'retained-scalar-sources/independent-tests').digest()
OPERATION = 'tests/retained-scalar-sources'
PROFILES = (('pallas_scalar','primary','pallas',Q,19,4624,59),
            ('vesta_scalar','secondary','vesta',P,14,10048,44))


def _canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,
                      allow_nan=False).encode('ascii')


def _hosted():
    return (os.environ.get('GITHUB_ACTIONS')=='true'
        and os.environ.get('RUNNER_OS')=='Linux' and sys.platform=='linux'
        and os.environ.get('BITVM2_NOVA_SCALAR_SOURCE_TESTS')=='1')


def _load():
    expected=load_expected_json((FIXTURES/'nht4-genesis-0-2020-k5.expected.json').read_bytes())
    dimensions=load_dimensions_json((FIXTURES/'nht4-genesis-0-2020-k5.dimensions.json').read_bytes(),
        expected,expected_descriptor_sha256=DIMENSIONS_PIN)
    raw=(FIXTURES/'nht4-genesis-0-2020-k5.nht4').read_bytes()
    admitted=bind_container(raw,expected)
    return expected,dimensions,raw,admitted.proof,decode_proof(admitted.proof,dimensions)


def _independent_encoding(raw):
    if type(raw) is not bytes or len(raw)!=32:raise ValueError('exact32 bytes')
    value=int.from_bytes(raw,'little')
    limbs=tuple((value//(1<<(29*i)))%BASE for i in range(9))
    crossings=[]
    for boundary in range(29,256,29):
        byte,low=divmod(boundary,8)
        if low:crossings.append((byte,low))
    pieces=tuple(part for byte,width in crossings
        for part in (raw[byte]%(1<<width),raw[byte]//(1<<width)))
    return limbs,tuple(raw),pieces


def _truth(spec,values,ordinal):
    """Diagnostic truth for these small approved graphs, including FV leaves.

    A signed out-of-bound value is false at registry recovery; this helper does
    not pretend a bare range-VERIFY abort is a successful disproof.
    """
    leaf=spec.leaves[ordinal]
    v=tuple(values[spec.words[wire][0]] for wire in leaf.wires)
    if any(type(x) is not int or not 0<=x<spec.words[w][1]
           for x,w in zip(v,leaf.wires,strict=True)):return False
    if leaf.kind=='field_valid':return sum(x<<(29*i) for i,x in enumerate(v))<{'pallas_scalar':Q,'vesta_scalar':P}[spec.field_role]
    if leaf.kind=='word_valid':return True
    if leaf.kind=='const':return v[0]==leaf.argument[0]
    from convolution import convolution_native
    return convolution_native({'pallas_scalar':Q,'vesta_scalar':P}[spec.field_role],leaf.kind,leaf.argument,v)


class RetainedReferenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.expected,cls.dimensions,cls.bundle,cls.proof,cls.decoded=_load()

    def test_actual_paths_are_contiguous_and_reference_policy_is_independently_pinned(self):
        import retained_scalar_block as tape
        self.assertEqual(sha256(_canonical(self.expected.json())).hexdigest(),POLICY_PIN)
        self.assertEqual((self.expected.network,self.expected.k,self.expected.steps),('testnet4',5,404))
        self.assertEqual(self.expected.header_revision,'de607d3db17d400dd6c2923d357f1d4a7bf233c7')
        self.assertEqual((HEADER_BYTES,len(self.bundle),len(self.proof)),(556,13220,12664))
        self.assertEqual(encode_proof(self.decoded),self.proof)
        by_path={span.path:span for span in self.decoded.spans}
        self.assertEqual((len(by_path),sum(s.kind=='length' for s in self.decoded.spans)),(485,119))
        for role,owner,engine,_,rounds,start,_ in PROFILES:
            block,spans=tape._reference(self.bundle,self.expected,self.dimensions,role)
            root='snark_'+owner
            vector=root+'.sc_proof_batch.compressed_polys'
            row=vector+'[0].coeffs_except_linear_term'
            paths=(root+'.eval_W',vector,row,row+'[0]',row+'[1]')
            self.assertEqual(tuple(s.path for s in spans),paths)
            self.assertEqual(tuple((s.start,s.size,s.kind,s.engine) for s in spans),
                tuple((start+offset,size,kind,engine if kind=='scalar' else None)
                    for offset,size,kind in ((0,32,'scalar'),(32,8,'length'),(40,8,'length'),(48,32,'scalar'),(80,32,'scalar'))))
            self.assertEqual(block,self.bundle[HEADER_BYTES+start:HEADER_BYTES+start+112])
            self.assertEqual((int.from_bytes(block[32:40],'little'),int.from_bytes(block[40:48],'little')),(rounds,2))
            inner=self.decoded.value[root]
            self.assertEqual(block[:32].hex(),inner['eval_W'])
            self.assertEqual((block[48:80].hex(),block[80:].hex()),
                tuple(inner['sc_proof_batch']['compressed_polys'][0]['coeffs_except_linear_term']))
            self.assertEqual(by_path[paths[0]],spans[0])
        self.assertFalse(self.decoded.summary()['proof_verified'])

    def test_all119_lengths_reject_bombs_and_partial_prefixes_without_allocating_from_them(self):
        spans=[span for span in self.decoded.spans if span.kind=='length']
        self.assertEqual(len(spans),119)
        for span in spans:
            for count in (0,1<<32,(1<<64)-1):
                changed=self.proof[:span.start]+count.to_bytes(8,'little')+self.proof[span.start+8:]
                with self.subTest(path=span.path,count=count),self.assertRaises(ValueError):
                    decode_proof(changed,self.dimensions)
            with self.subTest(path=span.path,truncated=True),self.assertRaises(ValueError):
                decode_proof(self.proof[:span.start+7],self.dimensions)
        for changed in (b'',self.proof[:-1],b'\0'+self.proof,self.proof+b'\0',self.proof+bytes(32)):
            with self.assertRaises(ValueError):decode_proof(changed,self.dimensions)
        for changed in (self.bundle[:-1],b'\0'+self.bundle,self.bundle+b'\0'):
            with self.assertRaises(ValueError):bind_container(changed,self.expected)

    def test_selected_scalar_canonicality_is_admission_not_fresh_proof_verification(self):
        for role,owner,_,modulus,_,start,_ in PROFILES:
            for offset in (0,48,80):
                for integer in (0,modulus-1):
                    changed=self.proof[:start+offset]+integer.to_bytes(32,'little')+self.proof[start+offset+32:]
                    accepted=decode_proof(changed,self.dimensions)
                    self.assertEqual(encode_proof(accepted),changed)
                    self.assertFalse(accepted.summary()['proof_verified'])
                    with self.assertRaises(ValueError):bind_container(self.bundle[:HEADER_BYTES]+changed,self.expected)
                for integer in (modulus,modulus+1,1<<255,(1<<256)-1):
                    changed=self.proof[:start+offset]+integer.to_bytes(32,'little')+self.proof[start+offset+32:]
                    with self.subTest(role=role,offset=offset,value=integer),self.assertRaises(ValueError):
                        decode_proof(changed,self.dimensions)
            # A local source block has only length constants. Neither the
            # reference's hash nor a claimed report makes its96 values fixed.
            self.assertEqual(len(self.decoded.value['snark_'+owner]['sc_proof_batch']['compressed_polys']),19 if role=='pallas_scalar' else 14)

    def test_encoder_integer_reference_preserves_all256_bits_without_reduction(self):
        import eval_w_encoding as encoding
        for modulus in (P,Q):
            for value in (0,1,modulus-1,modulus,modulus+1,1<<255,(1<<256)-1):
                raw=value.to_bytes(32,'little')
                expected=_independent_encoding(raw)
                self.assertEqual(encoding.encoding_values(raw),expected)
                self.assertEqual(sum(x<<(29*i) for i,x in enumerate(expected[0])),value)
                self.assertEqual(expected[1],tuple(raw))
                self.assertEqual(expected[0][8]>>(255-232),(value>>255)&1)
        for bad in (None,'00'*32,bytearray(32),memoryview(bytes(32)),bytes(31),bytes(33),True):
            with self.assertRaises(ValueError):encoding.encoding_values(bad)

    def test_small_parameters_and_hosted_guards_precede_all_allocation_or_io(self):
        import retained_scalar_block as tape
        import eval_w_encoding as encoding
        for role,*_ in PROFILES:
            tape._parameters(self.bundle,self.expected,self.dimensions,CONTEXT,role,OPERATION)
            encoding._parameters(CONTEXT,role,OPERATION)
        for values in (None,[0]*112,(0,)*111,(0,)*113,(True,)+(0,)*111,
                       (-1,)+(0,)*111,((1<<32),)+(0,)*111):
            with self.assertRaises(ValueError):tape._asserted(values)
        self.assertEqual(tape._asserted((256,)+(0,)*111)[0],256)
        self.assertEqual(tape._asserted(((1<<32)-1,)+(0,)*111)[0],(1<<32)-1)
        for context,role,operation in ((None,'pallas_scalar',OPERATION),(bytes(31),'pallas_scalar',OPERATION),
            (bytearray(32),'pallas_scalar',OPERATION),(CONTEXT,'pallas_base',OPERATION),
            (CONTEXT,True,OPERATION),(CONTEXT,'pallas_scalar','x'*193),(CONTEXT,'pallas_scalar','')):
            with self.assertRaises(ValueError):encoding._parameters(context,role,operation)
            with self.assertRaises(ValueError):tape._parameters(self.bundle,self.expected,self.dimensions,context,role,operation)
        for github,runner,platform in (('false','Linux','linux'),('true','Windows','linux'),('true','Linux','win32')):
            with patch.dict(os.environ,{'GITHUB_ACTIONS':github,'RUNNER_OS':runner},clear=True),\
                 patch.object(tape.sys,'platform',platform),\
                 patch.object(tape,'ByteTraceBuilder',side_effect=AssertionError('allocation before guard')) as alloc,\
                 patch('builtins.open',side_effect=AssertionError('I/O before guard')) as io:
                with self.assertRaisesRegex(ValueError,'hosted GitHub Linux'):
                    tape.build_retained_scalar_block(None,None,None,context=None,role=None,operation_id=None)
                with self.assertRaisesRegex(ValueError,'hosted GitHub Linux'):
                    object.__new__(tape.RetainedScalarBlock).bind(None)
                alloc.assert_not_called();io.assert_not_called()
            with patch.dict(os.environ,{'GITHUB_ACTIONS':github,'RUNNER_OS':runner},clear=True),\
                 patch.object(encoding.sys,'platform',platform),\
                 patch.object(encoding,'ConvolutionTraceBuilder',side_effect=AssertionError('allocation before guard')) as alloc:
                with self.assertRaisesRegex(ValueError,'hosted GitHub Linux'):
                    encoding.build_eval_w_encoding(context=None,role=None)
                with self.assertRaisesRegex(ValueError,'hosted GitHub Linux'):
                    object.__new__(encoding.EvalWEncoding).bind(None)
                alloc.assert_not_called()
        for cls in (tape.RetainedScalarBlock,tape.RetainedScalarBlockBinding,encoding.EvalWEncoding,encoding.EvalWEncodingBinding):
            with self.assertRaises(TypeError):cls()
            self.assertFalse(hasattr(cls,'from_json'))

    def test_outer_profile_nested_ids_and_global_maps_are_closed_before_allocation(self):
        import retained_scalar_sources as outer
        for role,_,_,_,rows,start,counter in PROFILES:
            self.assertEqual(outer.retained_profile(role),(counter,rows,start,HEADER_BYTES+start))
            outer._parameters(self.bundle,self.expected,self.dimensions,CONTEXT,role,0,OPERATION)
            for index in range(112):
                expected=(f'rho/message/eval_w/byte/{index}' if index<32 else
                    f'c/coeff/{0 if index<80 else 2}/byte/{(index-48)%32}' if index>=48 else
                    f'proof/container-byte/{HEADER_BYTES+start+index}')
                self.assertEqual(outer.tape_global_id(f'block/byte/{index}',role=role),expected)
            for index in range(32):
                self.assertEqual(outer.encoder_global_id(f'scalar/encoding/byte/{index}'),outer.eval_w_global_id(index))
            allowed=[]
            for size in range(1,193):
                try:outer._parameters(self.bundle,self.expected,self.dimensions,CONTEXT,role,0,'x'*size)
                except ValueError:continue
                allowed.append(size)
            self.assertTrue(allowed);self.assertLess(max(allowed),192)
            with self.assertRaises(ValueError):
                outer._parameters(self.bundle,self.expected,self.dimensions,CONTEXT,role,0,'x'*(max(allowed)+1))
        for bad in (True,None,'pallas_base','vesta_base'):
            with self.assertRaises(ValueError):outer.retained_profile(bad)
        for bad in ('block/byte/00','block/byte/-1','block/byte/112','receipt/byte/0',None):
            with self.assertRaises(ValueError):outer.tape_global_id(bad,role='pallas_scalar')
        for degree,index in ((True,0),(1,0),(2,True),(0,32),(0,-1)):
            with self.assertRaises(ValueError):outer.coefficient_global_id(degree,index)
        for github,runner,platform in (('false','Linux','linux'),('true','Windows','linux'),('true','Linux','win32')):
            with patch.dict(os.environ,{'GITHUB_ACTIONS':github,'RUNNER_OS':runner},clear=True),\
                 patch.object(outer.sys,'platform',platform),\
                 patch.object(outer,'build_byte_c_bit_point',side_effect=AssertionError('large source before guard')) as large,\
                 patch.object(outer,'build_retained_scalar_block',side_effect=AssertionError('tape before guard')) as small,\
                 patch('builtins.open',side_effect=AssertionError('I/O before guard')) as io:
                with self.assertRaisesRegex(ValueError,'hosted GitHub Linux'):
                    outer.build_retained_scalar_sources(None,None,None,context=None,role=None)
                empty=object.__new__(outer.RetainedScalarSourcesPlan)
                with self.assertRaisesRegex(ValueError,'hosted GitHub Linux'):empty.bind(None,None,None,None)
                with self.assertRaisesRegex(ValueError,'hosted GitHub Linux'):empty.regenerate_component(None)
                with self.assertRaisesRegex(ValueError,'hosted GitHub Linux'):
                    object.__new__(outer.RetainedScalarSourcesBinding).iter_components()
                large.assert_not_called();small.assert_not_called();io.assert_not_called()
        for cls in (outer.RetainedScalarSourcesPlan,outer.RetainedScalarSourcesBinding,
                    outer.RetainedScalarComponentSource,outer.RetainedScalarComponentBinding):
            with self.assertRaises(TypeError):cls()
            self.assertFalse(hasattr(cls,'from_json'))
        for keyword in ('proof','spans','source_maps','claimed_hash','receipt','components','program','rho_counter'):
            with self.assertRaises(TypeError):outer.build_retained_scalar_sources(
                self.bundle,self.expected,self.dimensions,context=CONTEXT,role='pallas_scalar',**{keyword:{'passed':True}})


@unittest.skipUnless(_hosted(),'dedicated GHA Linux job and BITVM2_NOVA_SCALAR_SOURCE_TESTS=1 required')
class HostedScalarSourceTests(unittest.TestCase):
    def setUp(self):
        if not _hosted():self.skipTest('dedicated hosted opt-in before graph/Script work')

    def assert_bare_modes(self,spec,values,ordinal,correct):
        from script import OPS,execute,num
        leaf=spec.leaves[ordinal]
        witness=tuple(num(values[spec.words[i][0]]) for i in leaf.wires)
        code=bytes.fromhex(dict(spec.bodies)[leaf.body_sha256])
        for disprove in (False,True):
            result=execute(code+(bytes([OPS['NOT']]) if disprove else b''),witness)
            self.assertIsNone(result.error,'an abort must not be counted as an ordinary false/disproof')
            self.assertEqual(result.success,not correct if disprove else correct)

    def test_encoder_canonicality_faults_actual_opening_links_and_length_guards(self):
        import eval_w_encoding as encoding
        from script import execute
        for role,_,_,modulus,_,_,_ in PROFILES:
            plan=encoding.build_eval_w_encoding(context=CONTEXT,role=role,operation_id=OPERATION+'/eval')
            self.assertEqual((len(plan.spec.words),len(plan.spec.leaves)),(55,17))
            maps=plan.source_maps
            self.assertEqual(maps['legacy_uniform_word_map'],list(range(129,184)))
            self.assertEqual(maps['legacy_uniform_leaf_map'],list(range(65,81))+[244])
            self.assertEqual(plan.spec.leaves[16].kind,'field_valid')
            for value in (0,modulus-1,modulus,modulus+1,1<<255):
                bound=plan.bind(value.to_bytes(32,'little'));values=bound.assignment
                self.assertEqual(tuple(values[word] for word in plan.ports['scalar_limbs']),_independent_encoding(bound.raw)[0])
                self.assertEqual([i for i in range(17) if not _truth(bound.spec,values,i)],[] if value<modulus else [16])
                self.assert_bare_modes(bound.spec,values,16,value<modulus)
            binding=plan.bind(bytes(range(32)));honest=binding.assignment
            self.assertTrue(all(_truth(binding.spec,honest,i) for i in range(17)))
            for name in ('input_bytes','scalar_limbs','split_auxiliaries'):
                values=binding.assignment;word=plan.ports[name][0];values[word]^=1
                failed=[i for i in range(17) if not _truth(binding.spec,values,i)]
                self.assertTrue(failed)
                for ordinal in failed:self.assert_bare_modes(binding.spec,values,ordinal,False)
            values=binding.assignment;values[plan.ports['input_bytes'][0]]=0xffffffff
            affected=[i for i,l in enumerate(binding.spec.leaves) if dict(binding.spec.words)[plan.ports['input_bytes'][0]]==256
                      and any(binding.spec.words[w][0]==plan.ports['input_bytes'][0] for w in l.wires)]
            self.assertTrue(affected)
            self.assertTrue(all(not _truth(binding.spec,values,i) for i in affected))
            # Signed out-of-bound assertions are exercised by hosted WOTS;
            # never execute a bare VERIFY body and call its abort a disproof.
            fixed=binding.program.bind(honest)
            for ordinal in range(16):
                witness=fixed.witness(ordinal)
                for disprove in (False,True):
                    code=fixed.script(ordinal,disprove=disprove)
                    self.assertEqual(execute(code,witness).success,not disprove)
                    for malformed in ((),witness[:-1],(b'',)+witness,witness+(b'',)):
                        result=execute(code,malformed)
                        self.assertFalse(result.success);self.assertEqual(result.error,'EQUALVERIFY')
                    forged=(b'\x01' if witness[0]!=b'\x01' else b'\x02',)+witness[1:]
                    result=execute(code,forged)
                    self.assertFalse(result.success);self.assertEqual(result.error,'EQUALVERIFY')
            changed=plan.bind((1).to_bytes(32,'little')).program.bind(plan.bind((1).to_bytes(32,'little')).assignment)
            with self.assertRaises(ValueError):fixed.require_identity(changed.program_digest,changed.claim_digest)
            foreign=encoding.build_eval_w_encoding(context=sha256(CONTEXT).digest(),role=role,operation_id=OPERATION+'/eval')
            other=foreign.bind(binding.raw);other_fixed=other.program.bind(other.assignment)
            with self.assertRaises(ValueError):fixed.require_identity(other_fixed.program_digest,other_fixed.claim_digest)
            foreign=encoding.build_eval_w_encoding(context=CONTEXT,role=role,operation_id=OPERATION+'/foreign-eval')
            other=foreign.bind(binding.raw);other_fixed=other.program.bind(other.assignment)
            with self.assertRaises(ValueError):fixed.require_identity(other_fixed.program_digest,other_fixed.claim_digest)

    def test_tape_length_constants_dynamic_assertions_and_noncanonical_signed_byte(self):
        import retained_scalar_block as tape
        from script import execute
        expected,dimensions,raw,_,_=_load()
        for role,_,_,_,_,start,_ in PROFILES:
            plan=tape.build_retained_scalar_block(raw,expected,dimensions,context=CONTEXT,role=role,operation_id=OPERATION+'/tape')
            self.assertEqual((len(plan.spec.words),len(plan.spec.leaves),len(plan.program.constraints)),(112,112,16))
            maps=plan.source_maps
            self.assertEqual(maps['source_byte_offsets'],list(range(HEADER_BYTES+start,HEADER_BYTES+start+112)))
            for index,(ordinal,formal) in enumerate(maps['byte_occurrences']):
                self.assertEqual((plan.spec.leaves[ordinal].wires[formal],formal),(index,0))
            original=tuple(plan.reference_block);binding=plan.bind(original)
            self.assertTrue(all(_truth(binding.spec,binding.assignment,i) for i in range(112)))
            fixed=binding.program.bind(binding.assignment)
            for ordinal in range(16):
                witness=fixed.witness(ordinal)
                for disprove in (False,True):
                    code=fixed.script(ordinal,disprove=disprove)
                    self.assertEqual(execute(code,witness).success,not disprove)
                    for malformed in ((),witness[:-1],(b'',)+witness,witness+(b'',)):
                        result=execute(code,malformed)
                        self.assertFalse(result.success);self.assertEqual(result.error,'EQUALVERIFY')
            for index in range(32,48):
                values=list(original);values[index]^=1;negative=plan.bind(tuple(values))
                self.assertEqual([i for i in range(112) if not _truth(negative.spec,negative.assignment,i)],[index-32])
                self.assert_bare_modes(negative.spec,negative.assignment,index-32,False)
            for index in (0,48,80):
                values=list(original);values[index]^=1;changed=plan.bind(tuple(values))
                self.assertTrue(all(_truth(changed.spec,changed.assignment,i) for i in range(112)))
                self.assertEqual(changed.source_sha256,plan.source_sha256)
                self.assertFalse(changed.summary()['asserted_values_equal_reference'])
                self.assertFalse(changed.summary()['proof_sha256_script_bound'])
            values=list(original);values[0]=256;oversized=plan.bind(tuple(values))
            self.assertIsNone(oversized.asserted_block)
            self.assertEqual([i for i in range(112) if not _truth(oversized.spec,oversized.assignment,i)],[16])
            snapshot=plan.metadata;snapshot['proof_verified']=True
            self.assertFalse(plan.metadata['proof_verified'])
            source=plan.source_maps;source['byte_occurrences'][0][0]=999
            self.assertNotEqual(source,plan.source_maps)
            copy=plan.assignment;copy[plan.ports['block_bytes'][0]]=1234
            self.assertNotEqual(copy,plan.assignment)
            with self.assertRaises(TypeError):plan.ports['block_bytes']=()
            with self.assertRaises(FrozenInstanceError):plan.role='vesta_scalar'

    def test_coherent_canonical_tape_changes_pass_actual_small_consumers_without_origin_claim(self):
        import retained_scalar_block as tape
        import eval_w_encoding as encoding
        from byte_sumcheck_frame import build_sumcheck_frame
        expected,dimensions,raw,_,_=_load()
        for role,_,_,modulus,_,_,counter in PROFILES:
            source=tape.build_retained_scalar_block(raw,expected,dimensions,context=CONTEXT,role=role,operation_id=OPERATION+'/coherent-tape')
            changed=bytearray(source.reference_block)
            changed[:32]=(1).to_bytes(32,'little')
            changed[48:80]=(modulus-1).to_bytes(32,'little')
            changed[80:112]=(2).to_bytes(32,'little')
            bound=source.bind(tuple(changed))
            self.assertFalse(bound.summary()['asserted_values_equal_reference'])
            self.assertEqual(bound.source_sha256,source.source_sha256)
            self.assertTrue(all(_truth(bound.spec,bound.assignment,i) for i in range(112)))
            encoder=encoding.build_eval_w_encoding(context=CONTEXT,role=role,operation_id=OPERATION+'/coherent-eval')
            encoded=encoder.bind(bytes(changed[:32]))
            self.assertTrue(all(_truth(encoded.spec,encoded.assignment,i) for i in range(17)))
            frame=build_sumcheck_frame(context=CONTEXT,role=role,counter=counter+1,operation_id=OPERATION+'/coherent-coeff')
            coeff=frame.bind((bytes(changed[48:80]),bytes(changed[80:112])))
            self.assertEqual(coeff.program.bind(coeff.assignment).failures(),())
            for flag in tape.FALSE_FLAGS:self.assertFalse(bound.summary()[flag])
            del coeff,frame,encoded,encoder,bound,source

    def test_exactly_two_honest_thirteen_component_streams_bind_actual_scalar_openings(self):
        import retained_scalar_sources as outer
        from Cryptodome.Hash import keccak
        from curve_trace import EncodedPoint
        from test_byte_rho_chain import VECTORS
        from trace import ROLES
        expected,dimensions,raw,_,_=_load()
        seen_sources=set();streams=0
        for role,owner,_,modulus,_,_,counter in PROFILES:
            plan=outer.build_retained_scalar_sources(raw,expected,dimensions,context=CONTEXT,role=role,
                bit_index=0,operation_id=OPERATION)
            self.assertEqual((len(plan.components),plan.rho_counter),(13,counter))
            self.assertFalse(hasattr(plan,'program'));self.assertFalse(hasattr(plan,'spec'))
            self.assertEqual(plan.source_sha256,sha256(outer.SOURCE_DOMAIN+_canonical(plan.manifest)).digest())
            self.assertNotIn(plan.source_sha256,seen_sources);seen_sources.add(plan.source_sha256)
            reference=plan.reference_inputs
            vector=next(v for v in VECTORS if v['role']==role)
            self.assertEqual(reference['eval_w'].hex(),vector['eval_w'])
            self.assertEqual(tuple(v.hex() for v in reference['coefficients']),vector['coefficients'])
            prior=bytes.fromhex(vector['prior'])
            base=P if role=='pallas_scalar' else Q
            A=EncodedPoint(0,base-1,2);point_P=EncodedPoint(1,0,0)
            binding=plan.bind(tuple(plan.reference_block),prior,A,point_P)
            def digest(message):return keccak.new(digest_bits=256,data=message).digest()
            rho_message=b'w'+reference['eval_w']+b'NoDS'+counter.to_bytes(8,'little')+prior+b'r'
            rho_raw=digest(rho_message+b'\0')+digest(rho_message+b'\1')
            c_message=b'p'+b''.join(reference['coefficients'])+b'NoDS'+(counter+1).to_bytes(8,'little')+rho_raw+b'c'
            c_raw=digest(c_message+b'\0')+digest(c_message+b'\1')
            self.assertEqual((binding.raw_rho,binding.raw_c),(rho_raw,c_raw))
            self.assertEqual(binding.selected_bit,int.from_bytes(c_raw,'little')%modulus&1)
            self.assertEqual(binding.R,A)
            maps=plan.source_maps;links=maps['tape_to_consumers'];internal=maps['eval_canonical_internal_links']
            self.assertEqual((len(links),sum(len(t['occurrences']) for link in links for t in link['targets']),len(internal)),(96,352,23))
            wanted={i:[] for i in range(13)}
            for link in links:
                wanted[11].append((link['source_ordinal'],link['source_occurrence'],link['global_id']))
                for target in link['targets']:
                    wanted[target['component_index']].extend((o,f,link['global_id']) for o,f in target['occurrences'])
            for link in internal:
                wanted[12].extend(((link['source_ordinal'],link['source_occurrence'],link['global_id']),
                                   (link['target_ordinal'],link['target_occurrence'],link['global_id'])))
            observed={};projected=None;indices=[]
            for item in binding.iter_components():
                indices.append(item.index);spec=item.spec;values=item.assignment
                self.assertEqual(item.descriptor,plan.components[item.index])
                self.assertEqual((len(spec.words),len(spec.leaves)),(item.descriptor.words,item.descriptor.leaves))
                self.assertEqual((spec.context,spec.program_sha256,spec.digest().hex()),
                    (CONTEXT.hex(),item.descriptor.program_sha256,item.descriptor.catalogue_id))
                self.assertEqual(sha256(_canonical(item.global_ids)).hexdigest(),item.descriptor.global_ids_sha256)
                self.assertEqual(len(set(item.global_ids)),len(spec.words))
                self.assertTrue(all(type(values[name]) is int and 0<=values[name]<bound for name,bound in spec.words))
                for body_sha,code in spec.bodies:self.assertEqual(sha256(bytes.fromhex(code)).hexdigest(),body_sha)
                if item.program is None:
                    self.assertIn(item.index,(0,1,4,6,7))
                    for leaf in spec.leaves:
                        v=tuple(values[spec.words[w][0]] for w in leaf.wires)
                        if leaf.kind=='byte_xor':result=v[0]^v[1]
                        elif leaf.kind=='byte_and':result=v[0]&v[1]
                        elif leaf.kind=='byte_not':result=v[0]^255
                        elif leaf.kind=='byte_rol':result=((v[0]<<leaf.argument[0])&255)|(v[1]>>(8-leaf.argument[0]))
                        elif leaf.kind=='byte_xor_const':result=v[0]^leaf.argument[0]
                        else:self.fail('unexpected full permutation leaf')
                        self.assertEqual(v[-1],result)
                else:
                    self.assertLessEqual(len(item.program.constraints),10000)
                    self.assertEqual(item.program.digest().hex(),spec.program_sha256)
                    self.assertEqual(item.program.bind(values).failures(),())
                    for _,ordinal in spec.field_leaves:
                        leaf=spec.leaves[ordinal]
                        self.assertLess(sum(values[spec.words[w][0]]<<(29*i) for i,w in enumerate(leaf.wires)),ROLES[spec.field_role])
                if item.index==8:
                    self.assertEqual(spec.leaves[244].kind,'field_valid')
                    self.assertEqual(spec.leaves[244].wires,tuple(range(129,138)))
                    projected=tuple((spec.leaves[i].kind,spec.leaves[i].argument,
                        tuple(w-129 for w in spec.leaves[i].wires),spec.leaves[i].body_sha256)
                        for i in tuple(range(65,81))+(244,))
                if item.index==11:
                    self.assertEqual(item.global_ids,tuple(outer.tape_global_id(name,role=role) for name,_ in spec.words))
                    self.assertEqual(tuple(values[name] for name,_ in spec.words),tuple(plan.reference_block))
                if item.index==12:
                    self.assertEqual(item.global_ids,tuple(outer.encoder_global_id(name) for name,_ in spec.words))
                    self.assertEqual(tuple((leaf.kind,leaf.argument,leaf.wires,leaf.body_sha256) for leaf in spec.leaves),projected)
                    self.assertTrue(all(_truth(spec,values,i) for i in range(17)))
                for ordinal,formal,global_id in wanted[item.index]:
                    wire=spec.leaves[ordinal].wires[formal]
                    self.assertEqual(item.global_ids[wire],global_id)
                    observation=(spec.words[wire][1],values[spec.words[wire][0]])
                    if global_id in observed:self.assertEqual(observed[global_id],observation)
                    else:observed[global_id]=observation
                # Do not retain positive mocks, GraphSpecs, assignments, parsed
                # child sidecars or word lists across component regeneration.
                del item,spec,values
            self.assertEqual(indices,list(range(13)))
            self.assertEqual(len(observed),119)
            for flag in outer.FALSE_FLAGS:self.assertFalse(binding.summary()[flag])
            snapshot=plan.source_maps;snapshot['tape_to_consumers'][0]['source_word']=999
            self.assertNotEqual(snapshot,plan.source_maps)
            with self.assertRaises(FrozenInstanceError):plan.role='vesta_scalar'
            with self.assertRaises(TypeError):plan.ports['asserted_block']=()
            del binding,plan,maps,links,internal,wanted,observed,projected,snapshot
            streams+=1
        self.assertEqual(streams,2)


if __name__=='__main__':unittest.main()
