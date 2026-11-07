"""Hosted streamed grouped-point composition; pure tests never allocate graphs."""
from dataclasses import FrozenInstanceError
from hashlib import sha256
import json
import os
import sys
import unittest
from unittest.mock import patch

import grouped_byte_c_bit_point as grouped
import byte_c_bit_point as legacy
from trace import ROLES


def _hosted():
    return (os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('RUNNER_OS')=='Linux'
            and sys.platform=='linux' and os.environ.get('BITVM2_NOVA_GROUPED_POINT_TESTS')=='1')


def _canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':')).encode('ascii')


def _byte_truth(leaf,values):
    if leaf.kind=='byte_xor':return values[2]==values[0]^values[1]
    if leaf.kind=='byte_and':return values[2]==values[0]&values[1]
    if leaf.kind=='byte_not':return values[1]==values[0]^255
    if leaf.kind=='byte_rol':
        r=leaf.argument[0]
        return values[2]==((values[0]<<r)&255)|(values[1]>>(8-r))
    if leaf.kind=='byte_xor_const':return values[1]==values[0]^leaf.argument[0]
    raise AssertionError('unexpected permutation predicate')


class GroupedOuterPureTests(unittest.TestCase):
    def test_fixed_benchmark_namespace_and_analytical_census(self):
        self.assertEqual(grouped.CONTEXT,sha256(b'BITVM2-NOVA/GROUPED-BYTE-C-BIT-POINT-CONFORMANCE/v1').digest())
        self.assertEqual(grouped.OPERATION_ID,'benchmark/grouped-byte-c-bit-point/v1')
        self.assertEqual(153213-13*(280-72),150509)
        self.assertEqual(156163-155107,1056)
        for role in ('pallas_scalar','vesta_scalar'):
            legacy._parameters(grouped.CONTEXT,role,59 if role=='pallas_scalar' else 44,0,grouped.OPERATION_ID)
        for role,counter,index in [('pallas_base',59,0),('pallas_scalar',True,0),('pallas_scalar',59,True),
                ('vesta_scalar',44,255)]:
            with self.assertRaises(ValueError):legacy._parameters(grouped.CONTEXT,role,counter,index,grouped.OPERATION_ID)
        for flag in ('A_proof_origin_bound','P_key_origin_bound','proof_verified','production_assertion_binding',
                     'taproot_forest_membership_verified'):
            self.assertIn(flag,grouped.FALSE_FLAGS)

    def test_no_imported_authority_and_guard_before_allocation_or_iteration(self):
        for github,runner,platform in [('false','Linux','linux'),('true','Windows','linux'),('true','Linux','win32')]:
            with patch.dict(os.environ,{'GITHUB_ACTIONS':github,'RUNNER_OS':runner},clear=True),\
                    patch.object(grouped.sys,'platform',platform),\
                    patch.object(legacy,'build_byte_c_bit_point',side_effect=AssertionError('legacy allocation before guard')) as allocate:
                with self.assertRaisesRegex(ValueError,'hosted GitHub Linux'):
                    grouped.build_grouped_byte_c_bit_point(context=None,role=None,rho_counter=None)
                plan=object.__new__(grouped.GroupedCBitPointPlan)
                with self.assertRaisesRegex(ValueError,'hosted GitHub Linux'):plan.bind(None,None,None,None,None)
                with self.assertRaisesRegex(ValueError,'hosted GitHub Linux'):plan.regenerate_component(None)
                binding=object.__new__(grouped.GroupedCBitPointBinding)
                with self.assertRaisesRegex(ValueError,'hosted GitHub Linux'):binding.iter_components()
                allocate.assert_not_called()
        for cls in (grouped.GroupedCBitPointPlan,grouped.GroupedCBitPointBinding):
            with self.assertRaises(TypeError):cls()
            self.assertFalse(hasattr(cls,'from_json'))
        for forbidden in ('program','spec','maps','receipt','chain_operation_id','legacy_reference'):
            with self.assertRaises(TypeError):grouped.build_grouped_byte_c_bit_point(
                context=grouped.CONTEXT,role='pallas_scalar',rho_counter=59,**{forbidden:{}})


@unittest.skipUnless(_hosted(),'BITVM2_NOVA_GROUPED_POINT_TESTS=1 on GitHub Linux required')
class GroupedOuterHostedTests(unittest.TestCase):
    def test_two_honest_streams_and_small_coherent_bit_and_scalar_alias_diagnostics(self):
        from test_byte_rho_chain import VECTORS
        from conditional_point import curve_for_role
        from uniform_alias import build_uniform_alias
        for vector in VECTORS:
            role=vector['role'];counter=vector['rho_counter']
            plan=grouped.build_grouped_byte_c_bit_point(context=grouped.CONTEXT,role=role,rho_counter=counter,
                                                       operation_id=grouped.OPERATION_ID)
            self.assertEqual(tuple(d.json() for d in plan.components[:10]),
                             tuple(d.json() for d in plan._legacy.components[:10]))
            self.assertEqual(plan.components[10].kind,'grouped-conditional-point')
            self.assertEqual(plan.components[10].branch,'conditional-point')
            self.assertEqual(plan.components[10].program_identity_kind,'GroupedProgram.digest (grouped-convolution/v1)')
            self.assertEqual(plan.components[10].leaves,3457)
            self.assertEqual(sum(d.leaves for d in plan.components),150509)
            self.assertEqual(sum(d.words for d in plan.components),156163)
            maps=plan.source_maps
            self.assertEqual(maps['selected_bit_to_point']['target_occurrences'],
                             [[3413,0],[3415,0],[3416,0],[3417,0],[3418,0]])
            self.assertEqual(maps['upstream_canonical_guard'],
                             {'component_index':8,'ordinal':244,'limb_indices':list(range(129,138))})
            self.assertEqual(maps['point_grouping']['legacy_reference_sha256'],sha256(plan.legacy_reference_bytes).hexdigest())
            self.assertEqual(set(plan.legacy_reference_json),{'spec','maps'})
            curve=curve_for_role(plan.point_role);g=(curve.p-1,2);p=curve.add(g,g)
            inputs=(bytes.fromhex(vector['eval_w']),bytes.fromhex(vector['prior']),
                    tuple(bytes.fromhex(value) for value in vector['coefficients']),g,p)
            bound=plan.bind(*inputs)
            self.assertEqual(bound.scalar_value,int.from_bytes(bytes.fromhex(vector['challenge']),'little'))
            self.assertEqual(bound.selected_bit,1 if role=='pallas_scalar' else 0)
            limbs=None;chosen=None;count=0;local=0;leaves=0
            for item in bound.iter_components():
                spec=item.spec;values=item.assignment
                self.assertEqual(item.descriptor,plan.components[item.index])
                self.assertEqual(spec.digest().hex(),item.descriptor.catalogue_id)
                self.assertEqual(spec.context,grouped.CONTEXT.hex())
                self.assertEqual(sha256(_canonical(item.global_ids)).hexdigest(),item.descriptor.global_ids_sha256)
                self.assertEqual(sha256(item._source_maps).hexdigest(),item.descriptor.source_maps_sha256)
                self.assertEqual(len(set(item.global_ids)),len(spec.words))
                self.assertTrue(all(type(values[word]) is int and 0<=values[word]<limit for word,limit in spec.words))
                if item.program is None:
                    self.assertTrue(all(_byte_truth(leaf,tuple(values[spec.words[i][0]] for i in leaf.wires))
                                        for leaf in spec.leaves))
                else:
                    self.assertEqual(item.program.digest().hex(),spec.program_sha256)
                    self.assertTrue(all(c.native(values,item.program.p) for c in item.program.constraints))
                    for _,ordinal in spec.field_leaves:
                        leaf=spec.leaves[ordinal]
                        self.assertLess(sum(values[spec.words[i][0]]<<(29*j) for j,i in enumerate(leaf.wires)),ROLES[spec.field_role])
                if item.index==8:
                    self.assertEqual(spec.leaves[244].kind,'field_valid')
                    self.assertEqual(spec.leaves[244].wires,tuple(range(129,138)))
                    limbs=tuple(values[spec.words[i][0]] for i in range(129,138))
                if item.index==9:
                    self.assertEqual(tuple(values[f'scalar/l{i}'] for i in range(9)),limbs)
                    chosen=values[f'bit/{plan.bit_index}']
                if item.index==10:
                    self.assertEqual(values['select/bit'],chosen)
                    self.assertEqual(spec.field_role,plan.point_role)
                    self.assertEqual(item.global_ids[7476],f'c/bits/bit/{plan.bit_index}')
                    point_maps=item.child_source_maps
                    self.assertEqual(point_maps['R_canonical_field_leaves'],[3455,3456])
                    self.assertEqual((len(spec.words),len(spec.leaves)),(7498,3457))
                    del point_maps
                count+=1;local+=len(spec.words);leaves+=len(spec.leaves)
                del item,spec,values
            self.assertEqual((count,local,leaves),(11,156163,150509))

            # No extra full-chain streams: only the small bridge and point
            # sources are regenerated for the closed coherent diagnostics.
            bit_source=plan.regenerate_component(9)
            point_source=plan.regenerate_component(10)
            flipped=plan.bind(*inputs,claimed_bit=1-bound.canonical_bit)
            bit_bound=bit_source.child.bind(flipped.input_limbs,claimed_bit=flipped.claimed_bit)
            self.assertEqual(tuple(i for i,c in enumerate(bit_bound.program.constraints)
                                   if not c.native(bit_bound.assignment,bit_bound.program.p)),(0,))
            point_bound=point_source.child.bind(flipped.A,flipped.P,flipped.selected_bit)
            self.assertTrue(all(c.native(point_bound.assignment,point_bound.program.p) for c in point_bound.program.constraints))
            del bit_bound,point_bound
            alias=grouped._bind_uniform_alias(plan,*inputs)
            uniform=build_uniform_alias(alias.raw_c,context=plan.context,role=role,
                                        operation_id=plan.components[8].operation_id)
            self.assertTrue(all(c.native(uniform.assignment,uniform.program.p) for c in uniform.program.constraints))
            self.assertGreaterEqual(uniform.result_value,ROLES[role])
            self.assertEqual(uniform.spec.leaves[244].kind,'field_valid')
            alias_bits=bit_source.child.bind(alias.input_limbs)
            self.assertTrue(all(c.native(alias_bits.assignment,alias_bits.program.p) for c in alias_bits.program.constraints))
            self.assertNotEqual(alias.selected_bit,bound.selected_bit)
            self.assertEqual(alias.input_limbs,tuple(uniform.assignment[f'result/l{i}'] for i in range(9)))
            for flag in grouped.FALSE_FLAGS:
                self.assertIs(plan.summary()[flag],False);self.assertIs(bound.summary()[flag],False)
            snapshot=plan.legacy_reference_json;snapshot.clear();self.assertTrue(plan.legacy_reference_json)
            with self.assertRaises(FrozenInstanceError):plan.bit_index=1
            del plan,bound,flipped,alias,bit_source,point_source,uniform,alias_bits,maps,snapshot


if __name__=='__main__':unittest.main()
