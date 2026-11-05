import dataclasses
import random
import unittest
from hashlib import sha256
from script import P, Q, BASE, OPS, execute, num
from trace import TraceBuilder, BoundTrace, multiplication_trace, change_field
from curve_trace import EncodedPoint, point_add_trace
from ipa_algebra import PALLAS, VESTA


class MultiplicationTrace(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.traces = {role: multiplication_trace(role, p-19, p-73,
            context=sha256(b'M2-context').digest(), operation_id='test/mul')
            for role,p in [('pallas_base',P),('vesta_base',Q)]}

    def prove_failure(self, program, values, kind=None):
        bound = program.bind(values)
        failures = bound.failures()
        self.assertTrue(failures)
        if kind:
            failures = [i for i in failures if program.constraints[i].kind == kind]
            self.assertTrue(failures, kind)
        i = failures[0]
        self.assertTrue(bound.execute(i).success, (i, program.constraints[i], bound.execute(i)))
        self.assertFalse(bound.execute(i, disprove=False).success)
        return bound, i

    def test_every_multiplication_leaf_executes(self):
        for program, values in self.traces.values():
            b = program.bind(values)
            self.assertEqual(len(program.constraints),274)
            self.assertFalse(b.failures())
            for i in range(len(program.constraints)):
                self.assertTrue(b.execute(i, disprove=False).success, i)
                self.assertFalse(b.execute(i).success, i)

    def test_each_multiplier_bit_is_bound(self):
        for program, values in self.traces.values():
            for bit in range(255):
                changed = dict(values)
                key = f'product/bit/{bit}'
                changed[key] ^= 1
                self.prove_failure(program,changed,'bits')

    def test_arithmetic_valid_trace_for_wrong_multiplier_is_refuted(self):
        for role, (program, values) in self.traces.items():
            _, wrong = multiplication_trace(role, program.p-19, program.p-74,
                context=program.context,operation_id=program.operation_id)
            # Replace every intermediate and bit coherently, retaining claimed b.
            for w in dict(program.fields)['input/b']:
                wrong[w] = values[w]
            self.prove_failure(program,wrong,'bits')

    def test_every_intermediate_accumulator_is_linked(self):
        for program, values in self.traces.values():
            for i in range(1,256):
                name = f'product/acc/{i}'
                ws = dict(program.fields)[name]
                old = sum(values[w] << (29*j) for j,w in enumerate(ws))
                changed = change_field(program,values,name,(old+1)%program.p)
                self.prove_failure(program,changed,'mul_bit')

    def test_nonzero_initial_state_is_refuted(self):
        for program,values in self.traces.values():
            changed=change_field(program,values,'product/acc/0',7)
            self.prove_failure(program,changed,'const')

    def test_wrong_final_result_is_refuted(self):
        for program,values in self.traces.values():
            changed=change_field(program,values,'product',1)
            self.prove_failure(program,changed,'equal')

    def test_changed_opening_cannot_disprove_honest_claim(self):
        program,values=self.traces['pallas_base']
        b=program.bind(values)
        for i in [0,8,9,18,145,273]:
            ws=list(b.witness(i))
            for j in range(len(ws)):
                altered=ws.copy(); altered[j]=num(17)
                if altered[j] == ws[j]: altered[j]=num(18)
                self.assertFalse(execute(b.script(i),altered).success)

    def test_wrong_witness_shape(self):
        program,values=self.traces['pallas_base']; b=program.bind(values)
        for i in [0,18,273]:
            ws=list(b.witness(i))
            for bad in [ws[:-1],ws+[b''],[b'']+ws]:
                self.assertFalse(execute(b.script(i),bad).success)

    def test_field_role_operation_and_context_bind_identity(self):
        original,_=self.traces['pallas_base']
        for role,op,ctx in [('vesta_scalar',original.operation_id,original.context),
                            ('pallas_base','different',original.context),
                            ('pallas_base',original.operation_id,bytes(32))]:
            p,v=multiplication_trace(role,P-19,P-73,operation_id=op,context=ctx)
            b=p.bind(v);old=original.bind(self.traces['pallas_base'][1])
            self.assertNotEqual(b.program_digest,old.program_digest)
            self.assertNotEqual(b.script(18),old.script(18))
            with self.assertRaises(ValueError):
                b.require_identity(old.program_digest,old.claim_digest)

    def test_missing_reordered_duplicated_constraints_change_identity(self):
        p,v=self.traces['pallas_base'];old=p.bind(v)
        for cs in [p.constraints[:-1],p.constraints[::-1],p.constraints+(p.constraints[-1],)]:
            other=dataclasses.replace(p,constraints=cs).bind(v)
            with self.assertRaises(ValueError):
                other.require_identity(old.program_digest,old.claim_digest)
        old.require_identity(old.program_digest,old.claim_digest)

    def test_assignment_is_copied_and_immutable(self):
        p,v=self.traces['pallas_base'];scratch=dict(v);b=p.bind(scratch)
        scratch['product/bit/0']^=1
        self.assertNotEqual(scratch['product/bit/0'],b.values['product/bit/0'])
        with self.assertRaises(TypeError): b.values['product/bit/0']=1

    def test_malformed_assignment_is_rejected_before_commitment(self):
        p,v=self.traces['pallas_base']
        for bad in [True,-1,BASE,b'\x00',b'\x01\x00',float(1),None]:
            x=dict(v);x['input/a/l0']=bad
            with self.assertRaises(ValueError): p.bind(x)
            with self.assertRaises(ValueError): BoundTrace(p,x)
        for edit in ('missing','extra'):
            x=dict(v)
            if edit=='missing': del x['input/a/l0']
            else: x['unknown']=0
            with self.assertRaises(ValueError):p.bind(x)

    def test_noncanonical_field_is_rejected_before_commitment(self):
        p,v=self.traces['pallas_base'];x=dict(v)
        for i,w in enumerate(dict(p.fields)['input/a']):x[w]=(P>>(29*i))&(BASE-1)
        with self.assertRaises(ValueError):p.bind(x)

    def test_top_limb_reconstruction_and_zero_inputs(self):
        for role,p in [('pallas_base',P),('vesta_base',Q)]:
            for a,b in [(0,0),(1,p-1),(p-1,p-1),(BASE**8,BASE**8)]:
                pr,va=multiplication_trace(role,a,b);bound=pr.bind(va)
                self.assertFalse(bound.failures())
                self.assertTrue(bound.execute(8,disprove=False).success)
                self.assertTrue(bound.execute(273,disprove=False).success)

    def test_bad_builder_inputs(self):
        for role,op,ctx in [('unknown','x',bytes(32)),('pallas_base','',bytes(32)),
                            ('pallas_base','x',bytes(31))]:
            with self.assertRaises(ValueError):TraceBuilder(role,op,ctx)
        g=TraceBuilder('pallas_base','x',bytes(32));g.field('a',1)
        with self.assertRaises(ValueError):g.field('a',2)
        with self.assertRaises(ValueError):g.check('equal',('missing',))


class CurveTraces(unittest.TestCase):
    def make(self,c,a,b,**kw):
        p,v=point_add_trace(c,a,b,**kw)
        return p,v,p.bind(v)

    def test_all_dispatch_branches_have_identical_topology(self):
        for c in (PALLAS,VESTA):
            g=(c.p-1,2);g2=c.mul(g,2)
            cases=[(None,g,0),(g,None,1),(g,(g[0],c.p-2),2),(g,g,3),(g,g2,4),(None,None,0)]
            digest=None
            for a,b,case in cases:
                p,v,t=self.make(c,a,b)
                self.assertEqual(v['dispatch'],case)
                self.assertFalse(t.failures())
                digest=digest or t.program_digest
                self.assertEqual(digest,t.program_digest)
                for i,cn in enumerate(p.constraints):
                    if cn.kind not in ('mul_bit','bits','const','equal','add'):
                        self.assertTrue(t.execute(i,disprove=False).success,(c.name,case,i))
                        self.assertFalse(t.execute(i).success)

    def test_wrong_branch_is_script_disputable(self):
        for c in (PALLAS,VESTA):
            g=(c.p-1,2);p,v,_=self.make(c,g,g)
            for wrong in (0,1,2,4):
                vv=dict(v);vv['dispatch']=wrong;t=p.bind(vv)
                idx=next(i for i,cn in enumerate(p.constraints) if cn.kind=='dispatch')
                self.assertTrue(t.execute(idx).success)

    def test_off_curve_inputs_and_outputs_are_disputable(self):
        for c in (PALLAS,VESTA):
            g=(c.p-1,2)
            for a,b,r in [((1,1),g,g),(g,(1,1),g),(g,g,(1,1))]:
                p,v,t=self.make(c,a,b,claimed_output=r)
                self.assertTrue(t.failures())
                self.assertTrue(any(t.execute(i).success for i in t.failures()))

    def test_noncanonical_infinity_is_disputable(self):
        for c in (PALLAS,VESTA):
            g=(c.p-1,2)
            for a,b,r in [(EncodedPoint(1,1,0),g,g),(g,g,EncodedPoint(1,0,1))]:
                p,v,t=self.make(c,a,b,claimed_output=r)
                bad=[i for i in t.failures() if p.constraints[i].kind=='point_form']
                self.assertTrue(bad)
                self.assertTrue(t.execute(bad[0]).success)

    def test_valid_but_wrong_curve_result_is_disputable(self):
        for c in (PALLAS,VESTA):
            g=(c.p-1,2)
            for a,b,r in [(g,g,g),(None,g,None),(g,None,None),(g,(g[0],c.p-2),g)]:
                p,v,t=self.make(c,a,b,claimed_output=r)
                self.assertTrue(t.failures())
                self.assertTrue(any(t.execute(i).success for i in t.failures()))

    def test_wrong_slope_and_internal_product_are_disputable(self):
        for c in (PALLAS,VESTA):
            g=(c.p-1,2);p,v,_=self.make(c,g,g)
            for field in ['slope','ordinary-slope','double-slope','slope2','y-equation','left/y2']:
                ws=dict(p.fields)[field];old=sum(v[w]<<(29*i) for i,w in enumerate(ws))
                t=p.bind(change_field(p,v,field,(old+1)%c.p))
                self.assertTrue(t.failures())
                self.assertTrue(t.execute(t.failures()[0]).success)

    def test_random_curve_operations_native_constraints(self):
        rng=random.Random(921711)
        for c in (PALLAS,VESTA):
            g=(c.p-1,2)
            for _ in range(6):
                a=c.mul(g,rng.randrange(c.q));b=c.mul(g,rng.randrange(c.q))
                p,v,t=self.make(c,a,b)
                self.assertFalse(t.failures())
                self.assertEqual(len(p.constraints),3616)

    def full_curve_script(self, c):
        # Every arithmetic leaf, including all 13*255 microsteps.
        g=(c.p-1,2);p,v,t=self.make(c,g,c.mul(g,2))
        for i in range(len(p.constraints)):
            r=t.execute(i,disprove=False)
            self.assertTrue(r.success,(c.name,i,p.constraints[i].kind,r))
            self.assertLess(r.peak_stack,1000)

    def test_every_pallas_leaf_in_script(self):
        self.full_curve_script(PALLAS)

    def test_every_vesta_leaf_in_script(self):
        self.full_curve_script(VESTA)


if __name__=='__main__':unittest.main()
