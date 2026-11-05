import copy
import random
import unittest
from hashlib import sha256
from script import P, Q, BASE, OPS, kernel, witness, execute, num, push, readnum, bind_openings
from ipa_algebra import PALLAS, VESTA, weights, make_fixture, verify_equation, multiplication_steps


class Kernels(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.code = {(p,k,d): kernel(p,k,d) for p in (P,Q) for k in ('add','mul_bit') for d in (False,True)}

    def case(self,p,k,x,y,bit):
        z = ((x+y) if k=='add' else (2*x+bit*y)) % p
        ws = witness(x,y,z,bit)
        r = execute(self.code[p,k,False],ws)
        self.assertTrue(r.success, r)
        self.assertLessEqual(r.peak_stack,1000)
        self.assertFalse(execute(self.code[p,k,True],ws).success)
        wrong = witness(x,y,(z+1)%p,bit)
        self.assertFalse(execute(self.code[p,k,False],wrong).success)
        self.assertTrue(execute(self.code[p,k,True],wrong).success)

    def test_boundary_add(self):
        for p in (P,Q):
            for x,y in [(0,0),(0,p-1),(p-1,p-1),(p-1,1),(BASE-1,1),(BASE**4-1,1)]:
                self.case(p,'add',x,y,None)

    def test_boundary_mul_bit(self):
        for p in (P,Q):
            for bit in (0,1):
                for x,y in [(0,0),(p-1,p-1),(0,p-1),(p-1,1),(BASE**8-1,1)]:
                    self.case(p,'mul_bit',x,y,bit)

    def test_random_arithmetic(self):
        r = random.Random(20261105)
        for p in (P,Q):
            for _ in range(24):
                x,y = r.randrange(p),r.randrange(p)
                self.case(p,'add',x,y,None)
                self.case(p,'mul_bit',x,y,r.randrange(2))

    def test_noncanonical_inputs(self):
        for p in (P,Q):
            for kind in ('add','mul_bit'):
                bit = None if kind=='add' else 1
                for x,y in [(p,0),(0,p),(p+1,2)]:
                    self.assertFalse(execute(self.code[p,kind,False],witness(x,y,0,bit)).success)

    def test_bad_limbs(self):
        for bad in [-1,BASE,2**31,b'\x00',b'\x80',b'\x01\x00']:
            ws=witness(1,2,3)
            ws[0]=bad if isinstance(bad,bytes) else num(bad)
            self.assertFalse(execute(self.code[P,'add',False],ws).success)

    def test_bit_is_boolean(self):
        for bit in (-1,2,17):
            self.assertFalse(execute(self.code[P,'mul_bit',False],witness(1,2,4,bit)).success)

    def test_wrong_modulus(self):
        ws=witness(P-1,1,0)
        self.assertTrue(execute(self.code[P,'add',False],ws).success)
        self.assertFalse(execute(self.code[Q,'add',False],ws).success)

    def test_output_over_modulus_is_disputable(self):
        ws=witness(1,2,P+3)
        self.assertTrue(execute(self.code[P,'add',True],ws).success)

    def test_bound_honest_claim_cannot_be_disproved(self):
        ws=witness(P-1,1,0)
        script=bind_openings(self.code[P,'add',True],ws,sha256(b'test-context').digest())
        self.assertFalse(execute(script,ws).success)
        for i in range(len(ws)):
            bad=list(ws)
            bad[i]=num((readnum(bad[i])+1)%BASE)
            self.assertFalse(execute(script,bad).success)

    def test_bound_false_claim_is_disproved(self):
        ws=witness(P-1,1,1)
        script=bind_openings(self.code[P,'add',True],ws,sha256(b'test-context').digest())
        self.assertTrue(execute(script,ws).success)

    def test_context_changes_leaf(self):
        ws=witness(1,2,3)
        self.assertNotEqual(bind_openings(self.code[P,'add',True],ws,bytes(32)),
                            bind_openings(self.code[P,'add',True],ws,bytes([1])*32))

    def test_full_multiplication_stream(self):
        for p in (P,Q):
            x,y=p-19,p-73
            count=0
            for st in multiplication_steps(x,y,p):
                ws=witness(st['accumulator'],x,st['output'],st['bit'])
                self.assertTrue(execute(self.code[p,'mul_bit',False],ws).success)
                count+=1
            self.assertEqual(count,255)
            self.assertEqual(st['output'],x*y%p)

    def test_truncated_and_extra_witness(self):
        ws=witness(1,2,3)
        for bad in [ws[:-1],ws+[b''],[b'']+ws]:
            self.assertFalse(execute(self.code[P,'add',False],bad).success)

    def test_disabled_and_success_opcodes_fail_closed(self):
        for opcode in (0x7e,0x95,0x50,0xff):
            self.assertFalse(execute(bytes([opcode]),[]).success)

    def test_interpreter_bounds(self):
        self.assertFalse(execute(b'\x51',[bytes(521)]).success)
        self.assertFalse(execute(b'\x51',[b'']*1001).success)
        self.assertFalse(execute(b'\x4c\x20\x01',[]).success)
        self.assertFalse(execute(push(num(2))+bytes([OPS['IF']])+b'\x51'+bytes([OPS['ENDIF']]),[]).success)


class Algebra(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixtures={c.name:make_fixture(c,4) for c in (PALLAS,VESTA)}

    def test_curve_orders(self):
        for c in (PALLAS,VESTA):
            g=(c.p-1,2)
            self.assertTrue(c.valid(g))
            self.assertIsNone(c.mul(g,c.q))

    def test_point_edge_cases(self):
        for c in (PALLAS,VESTA):
            g=(c.p-1,2)
            self.assertEqual(c.add(None,g),g)
            self.assertEqual(c.add(g,g),c.mul(g,2))
            self.assertIsNone(c.add(g,(g[0],c.p-2)))
            self.assertFalse(c.valid((c.p,2)))
            self.assertFalse(c.valid((1,1)))

    def test_streamed_weights_match_upstream_recurrence(self):
        for c in (PALLAS,VESTA):
            rs=[2,7,13]
            actual=list(weights(rs,c.q))
            s=[pow(2*7*13,-1,c.q)]
            for i in range(1,8):
                pos=i.bit_length()-1
                s.append(s[i-(1<<pos)]*rs[len(rs)-1-pos]**2%c.q)
            self.assertEqual(actual,s)

    def test_valid_ipa_equations(self):
        for c in (PALLAS,VESTA):
            self.assertTrue(verify_equation(c,**self.fixtures[c.name]))

    def test_ipa_tamper_each_scalar(self):
        for c in (PALLAS,VESTA):
            for field in ('a_hat','evaluation','r0'):
                f=copy.deepcopy(self.fixtures[c.name]); f[field]=(f[field]+1)%c.q
                self.assertFalse(verify_equation(c,**f),field)

    def test_ipa_tamper_each_round(self):
        for c in (PALLAS,VESTA):
            for field in ('left','right','challenges'):
                for j in range(2):
                    f=copy.deepcopy(self.fixtures[c.name])
                    if field=='challenges': f[field][j]=(f[field][j]+1)%c.q
                    else: f[field][j]=c.add(f[field][j],(c.p-1,2))
                    self.assertFalse(verify_equation(c,**f))

    def test_ipa_wrong_vector_and_generator(self):
        for c in (PALLAS,VESTA):
            f=copy.deepcopy(self.fixtures[c.name]); f['b'][1]+=1
            self.assertFalse(verify_equation(c,**f))
            f=copy.deepcopy(self.fixtures[c.name]); f['generators'][1]=f['generators'][0]
            self.assertFalse(verify_equation(c,**f))

    def test_ipa_lengths_and_zero_challenge(self):
        for c in (PALLAS,VESTA):
            for field in ('left','right','b','generators'):
                f=copy.deepcopy(self.fixtures[c.name]); f[field]=f[field][:-1]
                self.assertFalse(verify_equation(c,**f))
            f=copy.deepcopy(self.fixtures[c.name]); f['challenges'][0]=0
            self.assertFalse(verify_equation(c,**f))
            f=copy.deepcopy(self.fixtures[c.name]); f['a_hat']=c.q
            self.assertFalse(verify_equation(c,**f))

    def test_bad_point(self):
        f=copy.deepcopy(self.fixtures['pallas']); f['left'][0]=(1,1)
        self.assertFalse(verify_equation(PALLAS,**f))

    def test_dimension_one(self):
        for c in (PALLAS,VESTA):
            self.assertTrue(verify_equation(c,**make_fixture(c,1)))


if __name__=='__main__': unittest.main()
