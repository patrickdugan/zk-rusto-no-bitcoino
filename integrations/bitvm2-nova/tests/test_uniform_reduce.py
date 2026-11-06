"""Independent integer tests plus HOSTED-ONLY uniform-reduction graph checks.

Local tests never construct a graph, compile/execute Script, create keys or run
native code. The separately guarded class exercises the real bounded factory
and selected Script leaves only on hosted GitHub Linux.
"""
from dataclasses import dataclass
import os
import random
import sys
import unittest

from script import BASE, P, Q

CARRY_OFFSET = 8192
EVENT103 = bytes.fromhex(
    'f04e669b472740ed7e968c559565f0ef1cc9a02bd7265a14380d37f150127006'
    '02a294e6894a96599a22f07296b9b94aa004b4f821ae0435755c5ccfd04bdc7f')
EVENT103_RESULT_Q_LE = '4e248fbe6c6e3f895a93955b53dc406ca32d31d33cdeaa5f25405cfcaec7c23e'
EVENT103_QUOTIENT = int('1ff712f433d7171d4d412b887e2d0128018fe9ae77717615627d583f8dcd72aa2',16)
FIELDS = (('pallas_scalar',Q),('vesta_scalar',P))


def _digits(value,count):
    if type(value) is not int or not 0 <= value < 1 << (8*count):
        raise ValueError('bounded unsigned integer required')
    return tuple((value >> (8*i)) & 255 for i in range(count))


@dataclass(frozen=True)
class IntegerColumn:
    index: int
    input_byte: int
    result_byte: int
    pq_sum: int
    carry_in: int
    carry_out: int
    remainder: int


def _columns(raw,modulus,result,quotient,*,initial=0,unit=1,final=None):
    """Independent integer producer; no graph or implementation helper calls."""
    if type(raw) is not bytes or len(raw) != 64 or modulus not in (P,Q):
        raise ValueError('exact64 input bytes and Pasta modulus required')
    xs=tuple(raw)
    cs,qs,ps=_digits(result,32),_digits(quotient,33),_digits(modulus,32)
    carry=initial
    rows=[]
    for index in range(65):
        x=xs[index] if index < 64 else 0
        c=cs[index] if index < 32 else 0
        pq=sum(coefficient*qs[index-i] for i,coefficient in enumerate(ps)
               if 0 <= index-i < 33)
        numerator=x*unit+carry-c-pq
        outgoing=numerator//256
        if index==64 and final is not None:
            outgoing=final
        rows.append(IntegerColumn(index,x,c,pq,carry,outgoing,numerator-256*outgoing))
        carry=outgoing
    return tuple(rows)


def _telescoping(rows):
    return rows[-1].carry_out*(1 << 520)-rows[0].carry_in+sum(
        row.remainder << (8*row.index) for row in rows)


def _hosted():
    return (os.environ.get('GITHUB_ACTIONS')=='true'
            and os.environ.get('RUNNER_OS')=='Linux' and sys.platform=='linux')


class UniformIntegerTests(unittest.TestCase):
    def test_fixed_and_random_honest_reductions_cover_both_fields(self):
        rng=random.Random(0x512c0ffee)
        for _,p in FIELDS:
            values=[0,p-1,p,p+1,(1<<512)-1,int.from_bytes(EVENT103,'little')]
            values += [rng.getrandbits(512) for _ in range(32)]
            for value in values:
                q,c=divmod(value,p)
                rows=_columns(value.to_bytes(64,'little'),p,c,q)
                self.assertEqual(len(rows),65)
                self.assertTrue(all(row.remainder==0 for row in rows))
                self.assertEqual((rows[0].carry_in,rows[-1].carry_out),(0,0))
                self.assertEqual(_telescoping(rows),value-c-p*q)
                self.assertLess(c,p)
                self.assertLess(q,1<<258)
                self.assertLess(_digits(q,33)[32],4)
                if value==(1<<512)-1:self.assertGreater(q,p)
                bound=sum(p.to_bytes(32,'little'))+1
                self.assertTrue(all(-bound <= row.carry_out <= 0 for row in rows))

    def test_retained_event103_is_low_then_high_without_reversal(self):
        # Nova0.76 provider/keccak.rs68-85,149-151; traits.rs315-319.
        # This retained Pallas-scalar event is a raw64-byte LO||HI fixture.
        value=int.from_bytes(EVENT103,'little')
        quotient,result=divmod(value,Q)
        self.assertEqual(len(EVENT103),64)
        self.assertEqual(result.to_bytes(32,'little').hex(),EVENT103_RESULT_Q_LE)
        self.assertEqual(quotient,EVENT103_QUOTIENT)
        self.assertEqual(quotient.bit_length(),257)
        self.assertNotEqual(int.from_bytes(EVENT103[32:]+EVENT103[:32],'little')%Q,result)

    def test_arbitrary_claims_preserve_telescoping_and_expose_nonzero_residual(self):
        rng=random.Random(0x258)
        for _,p in FIELDS:
            for _ in range(32):
                value=rng.getrandbits(512)
                result=rng.randrange(p)
                quotient=rng.randrange(1<<258)
                rows=_columns(value.to_bytes(64,'little'),p,result,quotient)
                difference=value-result-p*quotient
                self.assertEqual(_telescoping(rows),difference)
                if difference:
                    self.assertTrue(any(row.remainder for row in rows) or rows[-1].carry_out!=0)

    def test_signed_carry_and_script_number_bounds_have_independent_integer_proof(self):
        for p,expected_sum in ((P,1417),(Q,1597)):
            byte_sum=sum(p.to_bytes(32,'little'))
            self.assertEqual(byte_sum,expected_sum)
            self.assertEqual(sum(byte!=0 for byte in p.to_bytes(32,'little')),14)
            bound=byte_sum+1
            # For t in[-S-1,0], x,c in[0,255], PQ in[0,255S],
            # floor((x+t-c-PQ)/256) remains in[-S-1,0].
            for x in (0,255):
                for c in (0,255):
                    for pq in (0,255*byte_sum):
                        for carry in (-bound,0):
                            following=(x+carry-c-pq)//256
                            self.assertTrue(-bound <= following <= 0)
            self.assertGreater(CARRY_OFFSET-bound,0)
            self.assertLess(CARRY_OFFSET,16384)
        left=(1<<18)-1+16383+255*CARRY_OFFSET
        right=255+2*((1<<19)-1)+256*16383
        self.assertEqual((left,right),(2367486,5242877))
        self.assertLess(max(left,right),1<<23)
        self.assertLess((1<<29)-1,1<<31)

    def test_initial_unit_and_overflow_omissions_have_distinct_counterexamples(self):
        for _,p in FIELDS:
            initial=_columns(bytes(64),p,1,0,initial=1)
            self.assertTrue(all(row.remainder==0 for row in initial))
            self.assertEqual(initial[-1].carry_out,0)
            self.assertNotEqual(0,1+p*0)
            unit=_columns((1).to_bytes(64,'little'),p,0,0,unit=0)
            self.assertTrue(all(row.remainder==0 for row in unit))
            self.assertTrue(all(row.carry_out==0 for row in unit))
            q,c=divmod(1<<512,p)
            overflow=_columns(bytes(64),p,c,q,final=0)
            self.assertTrue(all(row.remainder==0 for row in overflow[:64]))
            self.assertEqual((overflow[64].carry_in,overflow[64].carry_out,overflow[64].remainder),(-1,0,-1))
            self.assertEqual(_telescoping(overflow),-(1<<512))
            # Final anchor65 is true in this attack: only explicit overflow64
            # refutes it. With all65 columns, |X-c-pq|<2^514<2^520 implies
            # terminal t65=0, so removing final anchor ALONE has no such attack.
            maximum=(1<<512)+p*(1<<258)+p
            self.assertLess(maximum,1<<514)
            self.assertLess(maximum,1<<520)


@unittest.skipUnless(_hosted(),'real uniform graphs and Script checks are hosted GitHub Linux only')
class HostedUniformGraphTests(unittest.TestCase):
    def setUp(self):
        if not _hosted():
            self.skipTest('hosted guard before imports, graph construction or Script')
        import uniform_reduce
        self.module=uniform_reduce
        self.context=bytes.fromhex('42'*32)

    def build(self,raw,role,**kwargs):
        return self.module.build_uniform_reduction(raw,role=role,context=self.context,
            operation_id='test/uniform-reduce',**kwargs)

    @staticmethod
    def failures(graph,values):
        return [i for i,constraint in enumerate(graph.program.constraints)
                if not constraint.native(values,graph.program.p)]

    def rewitness(self,graph,result,quotient,*,unit=1,initial=0,final=None):
        """Independent assignment producer from source ports/declared equations."""
        values=graph.assignment
        ports=graph.ports
        for i,word in enumerate(ports['result_field']):values[word]=(result>>(29*i))&(BASE-1)
        for word,value in zip(ports['result_bytes'],_digits(result,32),strict=True):values[word]=value
        result_bytes=set(ports['result_bytes'])
        for constraint in graph.program.constraints:
            if constraint.kind=='conv_split' and constraint.wires[0] in result_bytes:
                byte=values[constraint.wires[0]];width=constraint.argument[0]
                values[constraint.wires[1]]=byte&((1<<width)-1)
                values[constraint.wires[2]]=byte>>width
        for word,value in zip(ports['quotient_bytes'],_digits(quotient,33),strict=True):values[word]=value
        values[ports['quotient_top_low']]=values[ports['quotient_bytes'][32]]&3
        values[ports['quotient_top_high']]=values[ports['quotient_bytes'][32]]>>2
        values[ports['constant_one']]=unit
        for word,source in zip(ports['input_subtotals'],ports['input_bytes'],strict=True):values[word]=values[source]*unit
        for constraint in graph.program.constraints:
            if constraint.kind=='conv_pq':
                values[constraint.wires[-1]]=sum(values[word]*coefficient for word,coefficient
                    in zip(constraint.wires[:-1],constraint.argument,strict=True))
        raw=bytes(values[word] for word in ports['input_bytes'])
        rows=_columns(raw,graph.program.p,result,quotient,initial=initial,unit=unit,final=final)
        carries=(rows[0].carry_in,)+tuple(row.carry_out for row in rows)
        for word,value in zip(ports['carries'],carries,strict=True):values[word]=value+CARRY_OFFSET
        return values,rows

    def test_honest_vectors_match_independent_columns_and_immutable_factory(self):
        for role,p in FIELDS:
            for value in (0,p-1,p,p+1,(1<<512)-1,int.from_bytes(EVENT103,'little')):
                graph=self.build(value.to_bytes(64,'little'),role)
                quotient,result=divmod(value,p)
                expected=_columns(value.to_bytes(64,'little'),p,result,quotient)
                actual=self.module.reduction_columns(value.to_bytes(64,'little'),p,result,quotient)
                self.assertEqual([tuple(vars(row).values()) for row in actual],
                                 [tuple(vars(row).values()) for row in expected])
                self.assertEqual(graph.program.bind(graph.assignment).failures(),())
                self.assertEqual((len(graph.program.words),len(graph.program.constraints)),(379,244))
                self.assertEqual((len(graph.column_constraints),len(graph.ports['carries'])),(65,66))
                self.assertEqual(len(graph.input_adapter_constraints),64)
                self.assertEqual(sum(map(len,graph.ports['pq_blocks'])),94)
                for index,ordinal in enumerate(graph.input_adapter_constraints):
                    adapter=graph.program.constraints[ordinal]
                    self.assertEqual((adapter.kind,adapter.argument,adapter.wires),
                        ('conv_ab',(1,),(graph.ports['input_bytes'][index],
                         graph.ports['constant_one'],graph.ports['input_subtotals'][index])))
                changed=graph.assignment;changed[graph.ports['input_bytes'][0]]^=1
                self.assertNotEqual(changed,graph.assignment)
                metadata=graph.metadata;metadata['test_tamper']=True
                self.assertNotIn('test_tamper',graph.metadata)
                with self.assertRaises(TypeError):graph.ports['constant_one']='wrong'
                with self.assertRaises(TypeError):type(graph)()
                for flag in ('hash_verified','transcript_verified','proof_verified','bitvm2_script_verified'):
                    self.assertIs(graph.summary()[flag],False)

    def test_wrong_result_quotient_and_coherent_interior_column_are_refutable(self):
        for role,p in FIELDS:
            value=(1<<512)-1;q,c=divmod(value,p)
            graph=self.build(value.to_bytes(64,'little'),role)
            for result,quotient in (((c+1)%p,q),(c,q-1),(c,(1<<258)-1)):
                values,rows=self.rewitness(graph,result,quotient)
                expected={graph.column_constraints[row.index] for row in rows if row.remainder}
                if rows[-1].carry_out:expected.add(graph.anchor_constraints['carry_final'])
                self.assertTrue(expected)
                self.assertEqual(set(self.failures(graph,values)),expected)
            interior=self.build((1<<256).to_bytes(64,'little'),role,claimed_result=0,claimed_quotient=0)
            self.assertEqual(interior.program.digest(),graph.program.digest())
            values,_=self.rewitness(interior,0,0)
            self.assertEqual(self.failures(interior,values),[interior.column_constraints[32]])
            broken=graph.assignment;broken[graph.ports['carries'][32]]+=1
            failed=self.failures(graph,broken)
            self.assertIn(graph.column_constraints[31],failed)
            self.assertIn(graph.column_constraints[32],failed)

    def test_factory_rejects_noncanonical_types_lengths_and_public_claims(self):
        for role,p in FIELDS:
            for raw in (bytes(63),bytes(65),bytearray(64),None):
                with self.assertRaises(ValueError):self.build(raw,role)
            for argument,value in (('claimed_result',True),('claimed_result',-1),('claimed_result',p),
                ('claimed_quotient',True),('claimed_quotient',-1),('claimed_quotient',1<<258)):
                with self.assertRaises(ValueError):self.build(bytes(64),role,**{argument:value})

    def test_initial_and_unit_anchor_attacks_and_explicit_overflow_boundary(self):
        for role,p in FIELDS:
            initial=self.build(bytes(64),role,claimed_result=1,claimed_quotient=0)
            values,_=self.rewitness(initial,1,0,initial=1)
            self.assertEqual(self.failures(initial,values),[initial.anchor_constraints['carry_initial']])
            unit=self.build((1).to_bytes(64,'little'),role,claimed_result=0,claimed_quotient=0)
            values,_=self.rewitness(unit,0,0,unit=0)
            self.assertEqual(self.failures(unit,values),[unit.anchor_constraints['constant_one']])
            q,c=divmod(1<<512,p)
            overflow=self.build(bytes(64),role,claimed_result=c,claimed_quotient=q)
            values,_=self.rewitness(overflow,c,q,final=0)
            self.assertEqual(self.failures(overflow,values),[overflow.column_constraints[64]])
            self.assertEqual(values[overflow.ports['carries'][65]],CARRY_OFFSET)
            self.assertTrue(overflow.program.constraints[overflow.anchor_constraints['carry_final']].native(values,p))

    def test_noncanonical_result_aliases_need_the_separate_field_validity_leaf(self):
        from script import OPS,execute,num
        from wots_graph import GraphSpec
        for role,p in FIELDS:
            for alias in (p,p+1):
                graph=self.build(alias.to_bytes(64,'little'),role)
                values,_=self.rewitness(graph,alias,0)
                self.assertEqual(self.failures(graph,values),[])
                with self.assertRaises(ValueError):graph.program.bind(values)
                spec=GraphSpec.from_program(graph.program)
                self.assertEqual(len(spec.leaves),245)
                field=next(ordinal for name,ordinal in spec.field_leaves
                           if dict(graph.program.fields)[name]==graph.ports['result_field'])
                body=bytes.fromhex(dict(spec.bodies)[spec.leaves[field].body_sha256])
                witness=[num(values[word]) for word in graph.ports['result_field']]
                self.assertFalse(execute(body,witness).success)
                self.assertTrue(execute(body+bytes([OPS['NOT']]),witness).success)

    def test_quotient_top_bit_overflow_and_limb_byte_links_fail_closed(self):
        for role,p in FIELDS:
            graph=self.build(bytes(64),role)
            with self.assertRaises(ValueError):self.build(bytes(64),role,claimed_quotient=1<<258)
            with self.assertRaises(ValueError):self.build(bytes(64),role,claimed_result=p)
            values=graph.assignment
            values[graph.ports['quotient_bytes'][32]]=4
            top=next(i for i,c in enumerate(graph.program.constraints)
                     if c.kind=='conv_split' and c.wires[0]==graph.ports['quotient_bytes'][32])
            self.assertIn(top,self.failures(graph,values))
            values[graph.ports['quotient_top_low']]=0;values[graph.ports['quotient_top_high']]=1
            self.assertTrue(graph.program.constraints[top].native(values,p))
            self.assertIn(graph.anchor_constraints['quotient_top_high'],self.failures(graph,values))
            for word,value in ((graph.ports['result_field'][0],0xffffffff),
                (graph.ports['result_field'][-1],BASE-1),(graph.ports['result_bytes'][0],1),
                (graph.ports['input_bytes'][0],256),(graph.ports['quotient_bytes'][32],256)):
                changed=graph.assignment;changed[word]=value
                if value>=dict(graph.program.words)[word] or word in graph.ports['result_field']:
                    with self.assertRaises(ValueError):graph.program.bind(changed)
                self.assertTrue(self.failures(graph,changed))

    def test_exact_witness_guards_reject_empty_truncated_prepended_and_appended(self):
        from script import execute
        for role,_ in FIELDS:
            graph=self.build(EVENT103,role)
            bound=graph.program.bind(graph.assignment)
            seen=set()
            for ordinal,constraint in enumerate(graph.program.constraints):
                shape=(constraint.kind,constraint.argument,
                    tuple(dict(graph.program.words)[word] for word in constraint.wires))
                if shape in seen:continue
                seen.add(shape)
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
