"""Grouped conditional source checks; every graph/Script path is hosted only."""
from dataclasses import FrozenInstanceError
from hashlib import sha256
import json
import os
import sys
import unittest
from unittest.mock import patch

import grouped_conditional_point as grouped
from curve_trace import EncodedPoint
from ipa_algebra import PALLAS,VESTA
from script import OPS,num

CONTEXT=sha256(b'grouped-conditional-point-tests/caller-context').digest()
OPERATION='tests/grouped-conditional-point'


def _hosted():
    return (os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('RUNNER_OS')=='Linux'
            and sys.platform=='linux' and os.environ.get('BITVM2_NOVA_GROUPED_POINT_TESTS')=='1')


def _canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':')).encode('ascii')


def _false(program,values):
    return tuple(i for i,c in enumerate(program.constraints) if not c.native(values,program.p))


class GroupedConditionalPureTests(unittest.TestCase):
    def test_exact_analytical_selector_field_projection_and_scope(self):
        self.assertEqual((grouped.WORDS,grouped.ARITHMETIC,grouped.FIELDS,grouped.LEAVES),(7498,3420,37,3457))
        self.assertEqual(13*(280-72),2704)
        self.assertEqual(tuple(old-2704 for old in (6117,6119,6120,6121,6122)),(3413,3415,3416,3417,3418))
        self.assertEqual(tuple(old-2704 for old in (6159,6160)),(3455,3456))
        self.assertIn('proof_verified',grouped.FALSE_FLAGS)
        self.assertIn('production_assertion_binding',grouped.FALSE_FLAGS)
        self.assertEqual(grouped.PROGRAM_IDENTITY_KIND,'GroupedProgram.digest (grouped-convolution/v1)')

    def test_typed_parameters_and_hosted_guard_precede_legacy_graphs(self):
        for role in ('pallas_base','vesta_base'):
            for bit in (0,28,29,232,254):grouped._parameters(CONTEXT,role,bit,OPERATION)
        for role,bit,context,operation in [('pallas_scalar',0,CONTEXT,OPERATION),
                ('pallas_base',True,CONTEXT,OPERATION),('vesta_base',255,CONTEXT,OPERATION),
                ('pallas_base',0,bytearray(32),OPERATION),('pallas_base',0,CONTEXT,'x'*180)]:
            with self.assertRaises(ValueError):grouped._parameters(context,role,bit,operation)
        for github,runner,platform in [('false','Linux','linux'),('true','Windows','linux'),('true','Linux','win32')]:
            with patch.dict(os.environ,{'GITHUB_ACTIONS':github,'RUNNER_OS':runner},clear=True),\
                    patch.object(grouped.sys,'platform',platform),\
                    patch.object(grouped,'build_conditional_point',side_effect=AssertionError('allocation before guard')) as allocate:
                with self.assertRaisesRegex(ValueError,'hosted GitHub Linux'):
                    grouped.build_grouped_conditional_point(context=None,role=None)
                empty=object.__new__(grouped.GroupedConditionalPointPlan)
                with self.assertRaisesRegex(ValueError,'hosted GitHub Linux'):empty.bind(None,None,0)
                allocate.assert_not_called()
        for cls in (grouped.GroupedConditionalPointPlan,grouped.GroupedConditionalPointBinding):
            with self.assertRaises(TypeError):cls()
            self.assertFalse(hasattr(cls,'from_json'))
        for forbidden in ('program','spec','maps','receipt','legacy_reference'):
            with self.assertRaises(TypeError):grouped.build_grouped_conditional_point(
                context=CONTEXT,role='pallas_base',**{forbidden:{}})


@unittest.skipUnless(_hosted(),'BITVM2_NOVA_GROUPED_POINT_TESTS=1 on GitHub Linux required')
class GroupedConditionalHostedTests(unittest.TestCase):
    def test_actual_complete_child_parent_projection_reference_and_identity_both_roles(self):
        for role in ('pallas_base','vesta_base'):
            plan=grouped.build_grouped_conditional_point(context=CONTEXT,role=role,operation_id=OPERATION)
            reference=plan.legacy_reference_json
            self.assertEqual(set(reference),{'spec','maps'})
            self.assertNotIn('values',reference)
            self.assertEqual(plan.legacy_reference_bytes,_canonical(reference))
            self.assertEqual(plan.spec.words,tuple((row['name'],row['bound']) for row in reference['spec']['words']))
            self.assertNotEqual(plan.program.digest().hex(),reference['spec']['program_sha256'])
            maps=plan.source_maps
            self.assertEqual(maps['legacy_reference_sha256'],sha256(plan.legacy_reference_bytes).hexdigest())
            self.assertEqual(maps['selected_bit_occurrences'],[[3413,0],[3415,0],[3416,0],[3417,0],[3418,0]])
            self.assertEqual(maps['R_canonical_field_leaves'],[3455,3456])
            self.assertEqual(maps['original_field_leaves'],list(range(3420,3455)))
            child=maps['complete_add']
            self.assertEqual((child['words'],child['arithmetic_constraints'],child['canonical_fields'],child['leaves']),
                             (7476,3412,35,3447))
            self.assertEqual(child['leaf_map'],list(range(3412))+list(range(3420,3455)))
            self.assertNotEqual(child['program_sha256'],child['legacy_program_sha256'])
            self.assertNotEqual(child['catalogue_id'],child['legacy_catalogue_id'])
            bodies=dict(plan.spec.bodies)
            for old,(new,row) in enumerate(plan.projection.old_to_new):
                before=reference['spec']['leaves'][old];after=plan.spec.leaves[new]
                if row is None:
                    self.assertEqual((before['kind'],before['argument'],before['wires'],before['body_sha256']),
                        (after.kind,list(after.argument),list(after.wires),after.body_sha256))
                    self.assertEqual(reference['spec']['bodies'][before['body_sha256']],bodies[after.body_sha256])
                else:
                    offset=sum(2*n+1 for n in after.argument[:row])
                    self.assertEqual(before['wires'],list(after.wires[offset:offset+2*after.argument[row]+1]))
            self.assertEqual(sum(leaf.kind=='conv_ab_all' for leaf in plan.spec.leaves),13*72)
            for flag in grouped.FALSE_FLAGS:self.assertIs(plan.summary()[flag],False)
            self.assertIs(plan.summary()['taproot_forest_membership_verified'],False)
            copied=plan.legacy_reference_json;copied.clear();self.assertTrue(plan.legacy_reference_json)
            plan.assignment.clear();self.assertTrue(plan.assignment)
            with self.assertRaises(FrozenInstanceError):plan.role='vesta_scalar'
            with self.assertRaisesRegex(ValueError,'GraphSpec-only'):plan.program.bind(plan.assignment)
            del plan,reference,maps,child,bodies,copied

    def test_all24_branches_diagnostics_and_group_plus_retained_column_refutation(self):
        from test_byte_c_bit_point import _pairs,_sum
        from script import execute
        for curve in (PALLAS,VESTA):
            role=curve.name+'_base'
            plan=grouped.build_grouped_conditional_point(context=CONTEXT,role=role,operation_id=OPERATION)
            for a,p in _pairs(curve):
                expected_e=EncodedPoint(*_sum(a,p,curve.p))
                for bit in (0,1):
                    bound=plan.bind(EncodedPoint(*a),EncodedPoint(*p),bit)
                    self.assertEqual(bound.E,expected_e)
                    self.assertEqual(bound.R,EncodedPoint(*a) if bit==0 else expected_e)
                    self.assertEqual(_false(bound.program,bound.assignment),())
                    self.assertEqual(bound.spec.digest(),plan.spec.digest())
                    del bound
            # P remains constrained even if the chosen output is A.
            invalid=plan.bind((curve.p-1,2),(1,1),0,claimed_E=None)
            self.assertTrue(_false(invalid.program,invalid.assignment));del invalid
            positive=plan.bind(None,(curve.p-1,2),0)
            values=positive.assignment;values['left/x2/ab/0/0']+=1
            failing=_false(positive.program,values)
            self.assertEqual(len(failing),2)
            self.assertEqual({positive.spec.leaves[i].kind for i in failing},{'conv_ab_all','conv_column'})
            for ordinal in failing:
                leaf=positive.spec.leaves[ordinal]
                unique=tuple(dict.fromkeys(leaf.wires))
                witness=tuple(num(values[positive.spec.words[i][0]]) for i in unique)
                body=bytes.fromhex(dict(positive.spec.bodies)[leaf.body_sha256])
                for disprove in (False,True):
                    result=execute(body+(bytes([OPS['NOT']]) if disprove else b''),witness)
                    self.assertEqual(result.success,disprove,result.error);self.assertIsNone(result.error)
            del plan,positive,values


if __name__=='__main__':unittest.main()
