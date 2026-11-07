"""Pure partition/arithmetic/framing and bounded compiler-hash checks only."""
from collections import Counter
from hashlib import sha256
import os
import sys
import unittest
from unittest.mock import patch

import grouped_convolution as grouped
from convolution import compile_convolution_predicate
from script import OPS,P,Q,num,push
from wots_graph import expansion_script


def _hosted():
    return (os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('RUNNER_OS')=='Linux'
            and sys.platform=='linux' and os.environ.get('BITVM2_NOVA_GROUPED_CONVOLUTION_TESTS')=='1')


def values(group,a,b,changes=None):
    changes = {} if changes is None else changes
    result = []
    for cell in group:
        for i,j in cell.pairs:result.extend((a[i],b[j]))
        subtotal = sum(a[i]*b[j] for i,j in cell.pairs)
        result.append(changes.get(cell.key,subtotal))
    return tuple(result)


class GroupedPureTests(unittest.TestCase):
    def test_exact_partition_old_subtotal_identifiers_products_and_opening_counts(self):
        groups = grouped.groups();cells = grouped.cells()
        self.assertEqual((len(cells),len(groups)),(280,72))
        self.assertEqual(Counter(tuple(len(cell.pairs) for cell in group) for group in groups),
            {(1,2,3,4):8,(4,4,4,4):56,(3,2,1):8})
        self.assertEqual(len({cell.key for group in groups for cell in group}),280)
        self.assertEqual({pair for cell in cells for pair in cell.pairs},
            {(i,j) for i in range(32) for j in range(32)})
        totals = []
        layouts = []
        for square in (False,True):
            old = sum(len(set(word for i,j in c.pairs for word in
                (('a',i),('a' if square else 'b',j))))+1 for c in cells)
            new = sum(len(set(grouped.group_occurrences(g,square=square))) for g in groups)
            totals.append((old,new))
            layouts.append({(tuple(len(c.pairs) for c in g),grouped.aliases(grouped.group_occurrences(g,square=square))) for g in groups})
        self.assertEqual(totals,[(2328,1008),(2200,952)])
        self.assertEqual((len(layouts[0]),len(layouts[1]),len(layouts[0]&layouts[1]),len(layouts[0]|layouts[1])),(4,10,4,10))
        self.assertTrue(layouts[0] <= layouts[1])
        self.assertEqual(max(len(grouped.group_occurrences(g)) for g in groups),36)
        self.assertEqual(max(len(set(grouped.group_occurrences(g))) for g in groups),15)

    def test_rows_are_independent_conjunctions_and_cancellation_is_refuted(self):
        for modulus in (P,Q):
            for byte in (0,1,9,128,255):
                a = tuple((byte+17*i)%256 for i in range(32))
                b = tuple((255-byte+31*i)%256 for i in range(32))
                for group in grouped.groups():
                    args = tuple(len(c.pairs) for c in group)
                    honest = values(group,a,b)
                    self.assertTrue(grouped.grouped_native(modulus,grouped.KIND,args,honest))
                    for cell in group:
                        subtotal = sum(a[i]*b[j] for i,j in cell.pairs)
                        wrong = (subtotal+1)%(1<<18)
                        self.assertFalse(grouped.grouped_native(modulus,grouped.KIND,args,
                            values(group,a,b,{cell.key:wrong})))
            a = tuple((257>>(8*i))&255 for i in range(32))
            group = grouped.groups()[0]
            forged = {(0,0):2,(1,0):1}
            residuals = [forged.get(c.key,sum(a[i]*a[j] for i,j in c.pairs))-sum(a[i]*a[j] for i,j in c.pairs) for c in group]
            self.assertEqual(residuals,[1,-1,0,0]);self.assertEqual(sum(residuals),0)
            self.assertFalse(grouped.grouped_native(modulus,grouped.KIND,(1,2,3,4),values(group,a,a,forged)))
            # Every original integer column and both anchors can simultaneously
            # hold for the wrong output; only the AB equations refute this.
            c = (257*257-255).to_bytes(32,'little')
            carry = 0
            for column in range(64):
                total = sum(forged.get(cell.key,sum(a[i]*a[j] for i,j in cell.pairs))
                    for cell in grouped.cells() if cell.column==column)
                delta = total+carry-(c[column] if column<32 else 0)
                self.assertEqual(delta%256,0);carry=delta//256
                self.assertEqual(carry,0)

    def test_strict_public_shapes_bounds_and_warm_cache_type_aliases(self):
        for argument in grouped.PATTERNS:
            bounds = grouped._bounds(P,grouped.KIND,argument)
            self.assertEqual(len(bounds),sum(2*n+1 for n in argument))
            grouped.compile_grouped_predicate(P,grouped.KIND,argument)
        class Int(int):pass
        for p,kind,arg in [(True,grouped.KIND,(1,2,3,4)),(Int(P),grouped.KIND,(1,2,3,4)),
            (P,'conv_ab',(1,2,3,4)),(P,grouped.KIND,[1,2,3,4]),
            (P,grouped.KIND,(True,2,3,4)),(P,grouped.KIND,(Int(1),2,3,4)),
            (P,grouped.KIND,(4,4)),(P,grouped.KIND,(0,)),(P,grouped.KIND,(4,)*5)]:
            with self.assertRaises(ValueError):grouped.compile_grouped_predicate(p,kind,arg)
        group = grouped.groups()[0];args=(1,2,3,4)
        original = values(group,(255,)*32,(255,)*32)
        bounds = grouped._bounds(P,grouped.KIND,args)
        for index,bound in enumerate(bounds):
            changed = list(original);changed[index]=bound
            self.assertFalse(grouped.grouped_native(P,grouped.KIND,args,changed))
        self.assertLessEqual(4*255*255,260100)
        self.assertLess(260100,1<<18)
        for column,block,pairs in [(True,0,((0,0),)),(0,False,((0,0),)),
                (0,0,((False,0),)),(0,0,[(0,0)]),(0,0,((0,1),)),(63,0,((31,32),))]:
            with self.assertRaises(ValueError):grouped.Cell(column,block,pairs)
        class Cell(grouped.Cell):pass
        with self.assertRaises(ValueError):grouped.group_occurrences((Cell(0,0,((0,0),)),))
        with self.assertRaises(ValueError):grouped.aliases((('a',True),))

    def test_wrapper_exact_row_body_bytes_relative_pick_and_prefix_altstack_contract(self):
        for modulus in (P,Q):
            for args in grouped.PATTERNS:
                frames = grouped.row_frames(args)
                formal = sum(2*n+1 for n in args)
                expected = bytearray(push(num(1)))
                for n,(offset,length,depth) in zip(args,frames,strict=True):
                    self.assertEqual(length,2*n+1)
                    self.assertEqual(depth,formal-offset)
                    for copied in range(length):
                        self.assertEqual((formal+1+copied)-1-(offset+copied),depth)
                        expected.extend(push(num(depth)));expected.append(OPS['PICK'])
                    expected.extend(compile_convolution_predicate(modulus,'conv_ab',(n,)))
                    expected.append(OPS['BOOLAND'])
                expected.append(OPS['TOALTSTACK'])
                expected.extend([OPS['2DROP']]*(formal//2))
                if formal%2:expected.append(OPS['DROP'])
                expected.append(OPS['FROMALTSTACK'])
                self.assertEqual(bytes(expected),grouped.compile_grouped_predicate(modulus,grouped.KIND,args))
                # Frozen row macro: consumes exactly copied row values and
                # balances its own alt-stack. No outer semantic VERIFY/IF.
                self.assertEqual(len(frames),len(args))

    def test_bounded_raw_and_alias_body_hash_gate_without_graphs_or_script_execution(self):
        inventory = grouped.bounded_body_inventory()
        self.assertEqual(len(inventory),26)
        self.assertTrue(all(0<row['bytes']<=20000 for row in inventory))
        self.assertEqual(len(grouped.templates()),10)
        for argument,pattern in grouped.templates():
            body = expansion_script(pattern)+grouped.compile_grouped_predicate(P,grouped.KIND,argument)
            row = next(row for row in inventory if row['modulus']==str(P) and row['argument']==argument and row['aliases']==pattern)
            self.assertEqual((len(body),sha256(body).hexdigest()),(row['bytes'],row['sha256']))
        raw = [(row['bytes'],row['sha256']) for row in inventory[:3]]
        self.assertEqual(raw,[(7131,'86966252aa4f55c05229d006258213ff41a7e25a50911c7bfeb57c0a223afab3'),
            (12676,'0aab1dbed4793e2aab6a5a30f441acef79991f30ec1a360b4616bd932afc63f1'),
            (3962,'14cd7ce2146f4cb253869a12e60f91452d1558e097c0b9d6b40f72607e82835d')])
        self.assertEqual(max(row['bytes'] for row in inventory),12826)

    def test_fixed_policy_profiles_and_resource_guard_precedes_graph_construction(self):
        self.assertEqual(grouped.CONTEXT,sha256(b'BITVM2-NOVA/GROUPED-CONVOLUTION-CONFORMANCE/v1').digest())
        self.assertEqual(grouped.OPERATION_ID,'benchmark/grouped-convolution/v1')
        self.assertEqual((len(grouped.PROFILES),len(set(grouped.PROFILES))),(20,20))
        self.assertEqual(Counter(grouped.PROFILE_FIXTURES),
            {'mul-distinct':14,'mul-equal-distinct':2,'square':2,'point':1,'point-inactive':1})
        full=next(group for group in grouped.groups()
                  if tuple(len(cell.pairs) for cell in group)==(4,4,4,4))
        self.assertEqual(grouped.subtotal_max_cell(),full[-1])
        self.assertEqual(grouped.subtotal_max_cell().key,(7,0))
        self.assertEqual(grouped.subtotal_max_cell().pairs,((0,7),(1,6),(2,5),(3,4)))
        for role,fixture in [('pallas_scalar','square'),('vesta_base',True),('pallas_base','unknown')]:
            with self.assertRaises(ValueError):grouped._parameters(role,fixture)
        with patch.dict(os.environ,{'GITHUB_ACTIONS':'false'}),patch.object(grouped.GraphSpec,'from_program',
                side_effect=AssertionError('graph allocation before guard')):
            with self.assertRaisesRegex(RuntimeError,'hosted GitHub Linux'):
                grouped.build_grouped_source('pallas_base','mul-distinct')
            with self.assertRaisesRegex(RuntimeError,'hosted GitHub Linux'):grouped._transform(None,None)
        with self.assertRaisesRegex(ValueError,'GraphSpec-only'):grouped.GroupedProgram.bind(None,{})


@unittest.skipUnless(_hosted(),'requires BITVM2_NOVA_GROUPED_CONVOLUTION_TESTS=1 on GitHub Linux')
class GroupedHostedTests(unittest.TestCase):
    def test_frozen_macro_preserves_main_prefix_altstack_and_every_row_boolean(self):
        from script import execute
        for modulus in (P,Q):
            for args in grouped.PATTERNS:
                group=next(g for g in grouped.groups() if tuple(len(c.pairs) for c in g)==args)
                a=tuple((17*i+9)&255 for i in range(32));b=tuple((31*i+7)&255 for i in range(32))
                honest=values(group,a,b)
                kernel=grouped.compile_grouped_predicate(modulus,grouped.KIND,args)
                for row in range(-1,len(group)):
                    actual=list(honest)
                    if row>=0:
                        out=sum(2*n+1 for n in args[:row+1])-1;actual[out]+=1
                    # Prove exact preservation of arbitrary physical main and
                    # alt prefixes without modifying any legacy row body.
                    suffix=(bytes([OPS['NOT']]) if row>=0 else b'')+bytes([OPS['VERIFY'],OPS['FROMALTSTACK']])
                    suffix+=push(num(321))+bytes([OPS['EQUALVERIFY']])+push(num(123))+bytes([OPS['EQUAL']])
                    code=push(num(321))+bytes([OPS['TOALTSTACK']])+kernel+suffix
                    result=execute(code,(num(123),)+tuple(num(v) for v in actual))
                    self.assertTrue(result.success,result.error);self.assertIsNone(result.error)
                    self.assertLess(result.peak_stack,1000)
                # A false early row must not skip a malformed late row.
                actual=list(honest);actual[2*args[0]]+=1;actual[-1]=1<<18
                for disprove in (False,True):
                    result=execute(kernel+(bytes([OPS['NOT']]) if disprove else b''),tuple(num(v) for v in actual))
                    self.assertFalse(result.success);self.assertIsNotNone(result.error)

    def test_all_forty_closed_bindings_preserve_old_catalogues_and_project_all_constraints(self):
        for role in ('pallas_base','vesta_base'):
            for fixture in grouped.FIXTURES:
                source=grouped.build_grouped_source(role,fixture)
                old,new=source.baseline_spec,source.candidate_spec
                self.assertEqual(old.words,new.words)
                self.assertEqual(source.baseline_program.fields,source.candidate_program.fields)
                self.assertNotEqual(old.program_sha256,new.program_sha256)
                self.assertNotEqual(old.digest(),new.digest())
                self.assertEqual(len(source.projection.old_to_new),len(old.leaves))
                self.assertEqual(len(source.projection.new_to_old),len(new.leaves))
                old_bodies,new_bodies=dict(old.bodies),dict(new.bodies)
                for previous,(current,row) in enumerate(source.projection.old_to_new):
                    self.assertIn(previous,source.projection.new_to_old[current])
                    before,after=old.leaves[previous],new.leaves[current]
                    if row is None:
                        self.assertEqual(before,after)
                        self.assertEqual(old_bodies[before.body_sha256],new_bodies[after.body_sha256])
                    else:
                        self.assertEqual(after.kind,grouped.KIND)
                        offset=sum(2*n+1 for n in after.argument[:row])
                        self.assertEqual(after.wires[offset:offset+2*after.argument[row]+1],before.wires)
                        self.assertEqual(before.argument,(after.argument[row],))
                self.assertEqual(sum(leaf.kind==grouped.KIND for leaf in new.leaves),
                    72*len(source.projection.multiplication_prefixes))
                for ordinal,profile in enumerate(grouped.PROFILES):
                    if grouped.PROFILE_FIXTURES[ordinal]!=fixture:continue
                    bound=source.bind_profile(profile)
                    assignment=bound.assignment
                    self.assertEqual(tuple(assignment),tuple(word for word,_ in old.words))
                    self.assertEqual(len(bound.values),len(old.words))
                    for current,previous in enumerate(source.projection.new_to_old):
                        truths=tuple(bound.baseline_truth[i] for i in previous)
                        # Frozen WOTS range errors are ordinary false here;
                        # semantic canonical-input VERIFY remains None.
                        expected=None if None in truths else all(truths)
                        self.assertEqual(bound.candidate_truth[current],expected)
                    if bound.complete:
                        self.assertTrue(all(value is True for value in bound.baseline_truth))
                        self.assertTrue(all(value is True for value in bound.candidate_truth))
                    else:
                        self.assertLessEqual(len(bound.baseline_selected)+len(bound.candidate_selected),128)
                        for truth,selection in ((bound.baseline_truth,bound.baseline_selected),
                                (bound.candidate_truth,bound.candidate_selected)):
                            self.assertTrue({i for i,value in enumerate(truth) if value is not True}<=set(selection))
                    if profile.startswith('cancel-'):
                        self.assertEqual(sum(value is False for value in bound.baseline_truth),2)
                        self.assertEqual(sum(value is False for value in bound.candidate_truth),1)
                        self.assertTrue(all(assignment[f'product/carry/{i}']==8192 for i in range(65)))
                    if profile=='byte-256':self.assertEqual(assignment['product/a/byte/0'],256)
                    if profile=='subtotal-max':
                        cell=grouped.subtotal_max_cell()
                        self.assertEqual(assignment[f'product/ab/{cell.column}/{cell.block}'],0xffffffff)
                    del assignment,bound
                source.assignment.clear();maps=source.source_maps;maps.clear()
                self.assertTrue(source.assignment);self.assertTrue(source.source_maps)
                with self.assertRaises(TypeError):grouped.GroupedSource(None,None,None,None,None,None,None,None,None)
                with self.assertRaises(ValueError):source.bind_profile('unknown')
                del source,old,new,old_bodies,new_bodies


if __name__ == '__main__':unittest.main()
