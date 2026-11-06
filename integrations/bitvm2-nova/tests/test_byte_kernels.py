"""Independent byte-predicate conformance with a strict local execution budget.

Only individual kernels and tiny (<100-word) graphs run here. Invalid bare
ScriptNum encodings must abort both modes; they are never counted as a disproof.
No full Keccak/reduction graph, native build, WOTS generation or proving runs.
"""
from hashlib import sha256
import random
import unittest

from script import BASE,OPS,P,Q,execute,num

CONTEXT=sha256(b'byte-kernels-tests/caller-owned-context').digest()
ROLES=(('pallas_base',P),('pallas_scalar',Q))
KINDS=('byte_xor','byte_and','byte_not','byte_rol','byte_xor_const')
MAX_SCRIPT_EXECUTIONS=2000
_script_executions=0


def _execute(code,witness):
    global _script_executions
    _script_executions+=1
    if _script_executions>MAX_SCRIPT_EXECUTIONS:
        raise AssertionError('local byte-kernel Script execution budget exceeded')
    return execute(code,witness)


def _expected(kind,argument,inputs):
    """Independent integer reference, including the cross-byte ROL fragment."""
    if kind=='byte_xor':return inputs[0]^inputs[1]
    if kind=='byte_and':return inputs[0]&inputs[1]
    if kind=='byte_not':return inputs[0]^255
    if kind=='byte_rol':
        shift,=argument
        return ((inputs[0]<<shift)&255)|(inputs[1]>>(8-shift))
    if kind=='byte_xor_const':return inputs[0]^argument[0]
    raise AssertionError('unknown test predicate')


def _shapes():
    return (('byte_xor',()),('byte_and',()),('byte_not',()),
            ('byte_rol',(3,)),('byte_xor_const',(0xa5,)))


def _case_samples():
    rng=random.Random(0xb178)
    pairs=[(0,0),(0,255),(255,0),(255,255),(1,128),(128,1),(85,170),(170,85)]
    pairs += [(rng.randrange(256),rng.randrange(256)) for _ in range(16)]
    for kind in ('byte_xor','byte_and'):
        for pair in pairs:yield kind,(),pair
    for value in (0,1,2,7,15,16,31,63,64,85,127,128,170,254,255,173):
        yield 'byte_not',(),(value,)
    for shift in range(1,8):
        for pair in pairs[:8]:yield 'byte_rol',(shift,),pair
    for mask in (0,1,2,3,7,15,16,31,63,64,85,127,128,170,254,255):
        for value in (0,165):yield 'byte_xor_const',(mask,),(value,)


class ByteKernelConformance(unittest.TestCase):
    @classmethod
    def tearDownClass(cls):
        if _script_executions>MAX_SCRIPT_EXECUTIONS:
            raise AssertionError('local Script budget exceeded')

    def test_existing_boolean_and_convolution_compiled_bytes_remain_unchanged(self):
        from trace_kernels import compile_predicate
        # Captured before the byte backend: exact lengths and SHA256 of bytes,
        # covering every existing Boolean and convolution predicate kind.
        goldens=(
            ('bool_xor',(),45,'ffb86a96482352f9af034f400aafcabb55792a6da1b344f1e4e0b76e0e39f67a'),
            ('bool_and',(),37,'b44ac76d8932ad6b11333ff846124b00d4db86e9ab73b31caeb18842c0758070'),
            ('bool_not',(),32,'83f246f81a4188f0e86f14c5e00c70085f090dd739d2f4ee43fa56f9b845847d'),
            ('conv_split',(3,),96,'486369a507d6af37db7cedd85c52d54e6d6f29891329f9b3b2f1f0d844e0ffde'),
            ('conv_reconstruct',(8,),217,'05ae67c636d88f5ccf8e5b5777cde728602adfba3114d1f62c858a4e7e10e74b'),
            ('conv_ab',(2,),1252,'6556d46b3b2b47f1f398f99a80db9c1c04dba3b638ccaf560cc95fecd0a1e310'),
            ('conv_pq',(1,255),365,'095d25b5ea03692839ed12570becdd696125dbffc5a86f73c3ad60733ef323c7'),
            ('conv_column',(1,1,1),411,'28f5d43a77a84e24afd83018401269e2c179a5dfab8a21a2055f90108af95779'))
        for modulus in (P,Q):
            for kind,argument,size,digest in goldens:
                body=compile_predicate(modulus,kind,argument)
                self.assertEqual((len(body),sha256(body).hexdigest()),(size,digest))

    def test_integer_references_public_shapes_and_neighbor_byte_rotation(self):
        import byte_kernels as module
        self.assertEqual(module.BYTE,256)
        self.assertEqual(module.KINDS,frozenset(KINDS))
        for modulus in (P,Q):
            for kind,argument,inputs in _case_samples():
                result=_expected(kind,argument,inputs)
                self.assertEqual(module._bounds(modulus,kind,argument),(256,)*(len(inputs)+1))
                self.assertIs(module.byte_native(modulus,kind,argument,inputs+(result,)),True)
                self.assertIs(module.byte_native(modulus,kind,argument,inputs+(result^1,)),False)
            for value in range(256):
                self.assertIs(module.byte_native(modulus,'byte_not',(),(value,255-value)),True)
                for mask in range(256):
                    # Pure integer checks, not Script executions or large graphs.
                    self.assertIs(module.byte_native(modulus,'byte_xor_const',(mask,),(value,value^mask)),True)
            rng=random.Random(0x6408)
            raw=bytes(rng.randrange(256) for _ in range(8))
            word=int.from_bytes(raw,'little')
            for byte_shift in range(8):
                for shift in range(1,8):
                    total=8*byte_shift+shift
                    rotated=((word<<total)|(word>>(64-total)))&((1<<64)-1)
                    expected_bytes=rotated.to_bytes(8,'little')
                    for byte in range(8):
                        pair=(raw[(byte-byte_shift)%8],raw[(byte-byte_shift-1)%8])
                        self.assertEqual(_expected('byte_rol',(shift,),pair),expected_bytes[byte])
                        self.assertIs(module.byte_native(modulus,'byte_rol',(shift,),pair+(expected_bytes[byte],)),True)

    def test_stratified_correct_and_wrong_bounded_output_bodies_both_fields(self):
        import byte_kernels as module
        for modulus in (P,Q):
            for kind,argument,inputs in _case_samples():
                code=module.compile_byte_predicate(modulus,kind,argument)
                expected=_expected(kind,argument,inputs)
                for output,good in ((expected,True),(expected^1,False)):
                    witness=tuple(num(value) for value in inputs+(output,))
                    for disprove in (False,True):
                        result=_execute(code+(bytes([OPS['NOT']]) if disprove else b''),witness)
                        self.assertEqual(result.success,good!=disprove,(modulus,kind,argument,inputs,output))
                        self.assertIsNone(result.error,'bounded false relation must not abort')

    def test_every_formal_slot_rejects_invalid_bare_encodings_in_both_modes(self):
        import byte_kernels as module
        bad_encodings=(num(-1),num(256),num((1<<31)-1),num(1<<31),
                       b'\x00',b'\x80',b'\x01\x00',b'\x80\x00\x00')
        for modulus in (P,Q):
            for kind,argument in _shapes():
                count=3 if kind in ('byte_xor','byte_and','byte_rol') else 2
                inputs=(0,)*(count-1)
                witness=tuple(num(value) for value in inputs+(_expected(kind,argument,inputs),))
                code=module.compile_byte_predicate(modulus,kind,argument)
                for slot in range(count):
                    for malformed in bad_encodings:
                        changed=witness[:slot]+(malformed,)+witness[slot+1:]
                        for disprove in (False,True):
                            result=_execute(code+(bytes([OPS['NOT']]) if disprove else b''),changed)
                            self.assertFalse(result.success)
                            self.assertIsNotNone(result.error,'encoding/domain abort is not a successful disproof')

    def test_public_shape_types_are_checked_before_warm_cache_lookup(self):
        import byte_kernels as module
        from trace_kernels import compile_predicate
        class IntAlias(int):pass
        class StrAlias(str):pass
        class TupleAlias(tuple):pass
        for modulus in (P,Q):
            for kind,argument in (('byte_rol',(1,)),('byte_xor_const',(0,)),
                    ('byte_xor_const',(1,)),('byte_xor',())):
                module.compile_byte_predicate(modulus,kind,argument)
                compile_predicate(modulus,kind,argument)
            invalid=[]
            for kind in ('byte_xor','byte_and','byte_not'):
                invalid.extend((modulus,kind,argument) for argument in ([],None,(0,),(True,)))
            for argument in ((),(0,),(8,),(-1,),(True,),(False,),(1.0,),('1',),(None,),
                             (1,2),[1],TupleAlias((1,)),(IntAlias(1),)):
                invalid.append((modulus,'byte_rol',argument))
            for argument in ((),(-1,),(256,),(True,),(False,),(1.0,),('1',),(None,),
                             (1,2),[0],TupleAlias((0,)),(IntAlias(1),)):
                invalid.append((modulus,'byte_xor_const',argument))
            for kind in (True,None,'xor','byte_XOR',StrAlias('byte_xor')):
                invalid.append((modulus,kind,()))
            for field in (True,None,str(modulus),modulus+1,float(modulus),IntAlias(modulus)):
                invalid.append((field,'byte_xor',()))
            before=module._compile_byte_predicate.cache_info()
            for field,kind,argument in invalid:
                for call in (module._bounds,module.compile_byte_predicate):
                    with self.assertRaises(ValueError):call(field,kind,argument)
                with self.assertRaises(ValueError):module.byte_native(field,kind,argument,(0,0,0))
            after=module._compile_byte_predicate.cache_info()
            self.assertEqual((after.hits,after.misses),(before.hits,before.misses))
            for kind,argument in _shapes():
                width=len(module._bounds(modulus,kind,argument))
                valid=(0,)*(width-1)+(_expected(kind,argument,(0,)*(width-1)),)
                for slot in range(width):
                    for bad in (True,False,-1,256,1.0,'1',None):
                        values=valid[:slot]+(bad,)+valid[slot+1:]
                        self.assertIs(module.byte_native(modulus,kind,argument,values),False)
                for values in (None,True,b'',set(valid),valid[:-1],valid+(0,)):
                    self.assertIs(module.byte_native(modulus,kind,argument,values),False)

    def test_tiny_builder_rejects_arity_and_each_exact_bound_mismatch(self):
        import byte_kernels as module
        for role,_ in ROLES:
            for kind,argument in _shapes():
                width=3 if kind in ('byte_xor','byte_and','byte_rol') else 2
                builder=module.ByteTraceBuilder(role,'tests/byte-shape',CONTEXT)
                words=tuple(builder.byte(f'w{i}',0) for i in range(width+1))
                for wires in (words[:width-1],words,words[:width-1]+('unknown',),
                              words[:width-1]+(True,)):
                    with self.assertRaises(ValueError):builder.check(kind,wires,argument)
                with self.assertRaises(ValueError):builder.check(kind,words[:width],list(argument))
                self.assertEqual(builder.constraints,[])
                for slot in range(width):
                    for wrong_bound in (2,255,257,BASE):
                        invalid=module.ByteTraceBuilder(role,'tests/byte-bound',CONTEXT)
                        wires=tuple(invalid.small(f'w{i}',0,wrong_bound if i==slot else 256)
                                    for i in range(width))
                        with self.assertRaises(ValueError):invalid.check(kind,wires,argument)
                        self.assertEqual(invalid.constraints,[])
                alias=module.ByteTraceBuilder(role,'tests/byte-alias-bound',CONTEXT)
                wrong=alias.small('same',0,255)
                with self.assertRaises(ValueError):alias.check(kind,(wrong,)*width,argument)
                for inputs in ((),words[:width],('unknown',)*(width-1)):
                    with self.assertRaises(ValueError):builder.apply(kind,'out',*inputs,argument=argument)
                self.assertNotIn('out',builder.words)
            for bad in (True,False,-1,256,1.0,None):
                builder=module.ByteTraceBuilder(role,'tests/byte-value',CONTEXT)
                with self.assertRaises(ValueError):builder.byte('bad',bad)
            for context in (bytes(31),bytes(33),bytearray(32),None,True):
                with self.assertRaises(ValueError):module.ByteTraceBuilder(role,'tests/byte',context)
            for operation in ('','bad operation','x'*193,None,True):
                with self.assertRaises(ValueError):module.ByteTraceBuilder(role,operation,CONTEXT)

    def test_formal_alias_partitions_keep_one_opening_and_correct_relations(self):
        import byte_kernels as module
        from wots_graph import GraphSpec
        partitions=((0,1,2),(0,0,1),(0,1,0),(0,1,1),(0,0,0))
        for role,_ in ROLES:
            for kind,argument in _shapes():
                unary=kind in ('byte_not','byte_xor_const')
                for partition in (((0,1),(0,0)) if unary else partitions):
                    builder=module.ByteTraceBuilder(role,'tests/byte-alias',CONTEXT)
                    distinct=tuple(dict.fromkeys(partition))
                    values_by_id={index:(0xa5,0x3c,0x12)[index] for index in distinct}
                    inputs=tuple(values_by_id[index] for index in partition[:-1])
                    if partition[-1] not in partition[:-1]:
                        values_by_id[partition[-1]]=_expected(kind,argument,inputs)
                    wires={index:builder.byte(f'v{index}',values_by_id[index]) for index in distinct}
                    formal=tuple(wires[index] for index in partition)
                    builder.check(kind,formal,argument)
                    program,values=builder.finish()
                    expected=values[formal[-1]]==_expected(kind,argument,tuple(values[word] for word in formal[:-1]))
                    self.assertEqual(len(program.words),len(distinct))
                    self.assertEqual(tuple(bound for _,bound in program.words),(256,)*len(distinct))
                    bound=program.bind(values)
                    self.assertEqual(bound.failures(),() if expected else (0,))
                    spec=GraphSpec.from_program(program)
                    self.assertEqual(len(spec.leaves),1)
                    self.assertEqual(spec.leaves[0].wires,partition)
                    self.assertEqual(spec.words,program.words)
                    unique=tuple(dict.fromkeys(spec.leaves[0].wires))
                    body=bytes.fromhex(dict(spec.bodies)[spec.leaves[0].body_sha256])
                    recovered=tuple(num(values[spec.words[index][0]]) for index in unique)
                    for disprove in (False,True):
                        direct=_execute(bound.script(0,disprove=disprove),bound.witness(0))
                        adapter=_execute(body+(bytes([OPS['NOT']]) if disprove else b''),recovered)
                        self.assertEqual((direct.success,adapter.success),(expected!=disprove,)*2)
                        self.assertIsNone(direct.error);self.assertIsNone(adapter.error)
                    if not unary and partition==(0,0,1):
                        if kind=='byte_xor':self.assertEqual(values[formal[-1]],0)
                        if kind=='byte_and':self.assertEqual(values[formal[-1]],values[formal[0]])
                        if kind=='byte_rol':
                            a=values[formal[0]];shift,=argument
                            self.assertEqual(values[formal[-1]],((a<<shift)|(a>>(8-shift)))&255)
            # Public mask0 may alias input/output; it is an authenticated copy.
            builder=module.ByteTraceBuilder(role,'tests/byte-mask0-alias',CONTEXT)
            same=builder.byte('same',173);builder.check('byte_xor_const',(same,same),(0,))
            program,values=builder.finish();bound=program.bind(values)
            self.assertEqual(bound.failures(),())
            for disprove in (False,True):
                result=_execute(bound.script(0,disprove=disprove),bound.witness(0))
                self.assertEqual(result.success,not disprove);self.assertIsNone(result.error)
            # One of two repeated formal openings cannot be substituted alone.
            builder=module.ByteTraceBuilder(role,'tests/byte-opening-alias',CONTEXT)
            same=builder.byte('same',173);out=builder.byte('out',0)
            builder.check('byte_xor',(same,same,out))
            program,values=builder.finish();bound=program.bind(values)
            witness=bound.witness(0)
            for disprove in (False,True):
                result=_execute(bound.script(0,disprove=disprove),(witness[0],num(172),witness[2]))
                self.assertFalse(result.success);self.assertEqual(result.error,'EQUALVERIFY')

    def test_versioned_role_context_operation_and_claim_identities(self):
        import byte_kernels as module
        from trace import Program
        self.assertEqual(module.COMPILER,'byte-v1')
        self.assertEqual(module.PROGRAM_DOMAIN,b'BITVM2-NOVA/BYTE-TRACE/v1\x00')
        first,values=module.byte_kernel_trace('pallas_base','byte_xor',(0x5a,0xa5),
            context=CONTEXT,operation_id='tests/byte-identity')
        bound=first.bind(values)
        old=Program(first.field_role,first.operation_id,first.context,first.words,first.fields,first.constraints)
        self.assertEqual(first.digest(),sha256(b'BITVM2-NOVA/BYTE-TRACE/v1\x00'+old.digest()).digest())
        self.assertNotEqual(first.digest(),old.digest())
        self.assertEqual((len(first.words),len(first.constraints),first.fields),(3,1,()))
        same,changed_values=module.byte_kernel_trace('pallas_base','byte_xor',(1,2),
            context=CONTEXT,operation_id='tests/byte-identity')
        self.assertEqual(first.digest(),same.digest())
        self.assertNotEqual(bound.claim_digest,same.bind(changed_values).claim_digest)
        for role,context,operation in (('pallas_scalar',CONTEXT,'tests/byte-identity'),
                ('pallas_base',bytes(32),'tests/byte-identity'),('pallas_base',CONTEXT,'tests/byte-identity/other')):
            other,_=module.byte_kernel_trace(role,'byte_xor',(0x5a,0xa5),context=context,operation_id=operation)
            self.assertNotEqual(first.digest(),other.digest())
        bound.require_identity(bound.program_digest,bound.claim_digest)
        for program_id,claim_id in ((old.digest(),bound.claim_digest),
                                   (bound.program_digest,bytes(32)),(True,bound.claim_digest)):
            with self.assertRaises(ValueError):bound.require_identity(program_id,claim_id)
        manifest=bound.manifest()
        self.assertEqual((manifest['compiler'],manifest['program_kind']),('byte-v1','byte-kernels/v1'))
        self.assertIs(manifest['dynamic_assertions'],False)
        self.assertIs(manifest['bitcoin_transaction_graph'],False)
        for compiler in ('m2','compact-v1','convolution-v1','byte-v2',True,None):
            with self.assertRaises(ValueError):bound.script(0,compiler=compiler)
        for ordinal in (True,-1,1,0.0,None):
            with self.assertRaises(ValueError):bound.script(ordinal)

    def test_exact_witness_length_and_opening_guards_both_modes(self):
        import byte_kernels as module
        for role,_ in ROLES:
            for kind,argument in _shapes():
                inputs=(0xa5,0x3c) if kind in ('byte_xor','byte_and','byte_rol') else (0xa5,)
                program,values=module.byte_kernel_trace(role,kind,inputs,argument=argument,
                    context=CONTEXT,operation_id='tests/byte-witness')
                bound=program.bind(values);witness=bound.witness(0)
                for disprove in (False,True):
                    code=bound.script(0,disprove=disprove)
                    self.assertEqual(_execute(code,witness).success,not disprove)
                    for malformed in ((),witness[:-1],(b'',)+witness,witness+(b'',)):
                        result=_execute(code,malformed)
                        self.assertFalse(result.success);self.assertEqual(result.error,'EQUALVERIFY')
                    # A bounded canonical replacement still fails the opening
                    # check before the relation can be inverted into disproof.
                    substituted=(num(inputs[0]^1),)+witness[1:]
                    result=_execute(code,substituted)
                    self.assertFalse(result.success);self.assertEqual(result.error,'EQUALVERIFY')


if __name__=='__main__':
    unittest.main()
