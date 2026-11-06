"""Independent tiny selector oracle; full composition is HOSTED opt-in only.

Local checks use integer/Jacobian algebra and immutable framing only. They never
construct graph catalogues, compile/execute Script, sign, or launch native work.
"""
from dataclasses import FrozenInstanceError
from hashlib import sha256
import json
import os
import sys
import unittest
from unittest.mock import patch

from script import P,Q,BASE
from ipa_algebra import PALLAS,VESTA

CONTEXT=sha256(b'byte-c-bit-point-tests/caller-owned-context').digest()
OPERATION='tests/byte-c-bit-point'
RETAINED=(
    ('pallas_scalar',PALLAS,59,
     '2770fa4779eb97bb1272041a9c14403a0c1570a0308e5d84e27d518125ea5036',
     '9a62ebb9a5aafea68609962656cd7aa854914ae0ccb073f9ee05519f76a8539e4'
     '5b5dd1b36e98d75dee609c1233ad184b6c5a0e1633a768e378f987f5235e474'),
    ('vesta_scalar',VESTA,44,
     'f6a0f1ff6cdb56029324e4840d850f8aafcdc7037642ef35e8e53f8fb397dc0c',
     'ecc38c27f4712a179aa55bc3c0df663651be906a1fc47eaeff9eab8d5f2fa5be'
     '1c33641f687de1bbd723d7c203d020ad709914e4c52c0e3f005b221cd236e8df'))


def _hosted():
    return (os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('RUNNER_OS')=='Linux'
        and sys.platform=='linux' and os.environ.get('BITVM2_NOVA_BIT_POINT_TESTS')=='1')


def _canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')


def _valid(point,p):
    if type(point) is not tuple or len(point)!=3:return False
    infinity,x,y=point
    if any(type(value) is not int for value in point) or infinity not in (0,1):return False
    if not (0<=x<p and 0<=y<p):return False
    return (x==y==0) if infinity else (y*y-x*x*x-5)%p==0


def _jacobian(point):
    return (0,1,0) if point[0] else (point[1],point[2],1)


def _double_jacobian(point,p):
    x,y,z=point
    if not z or not y:return (0,1,0)
    yy=y*y%p;s=4*x*yy%p;m=3*x*x%p
    xx=(m*m-2*s)%p
    return xx,(m*(s-xx)-8*yy*yy)%p,2*y*z%p


def _add_jacobian(left,right,p):
    x,y,z=left;xx,yy,zz=right
    if not z:return right
    if not zz:return left
    u=x*zz*zz%p;v=xx*z*z%p;s=y*zz*zz*zz%p;t=yy*z*z*z%p
    if u==v:return _double_jacobian(left,p) if s==t else (0,1,0)
    h=(v-u)%p;r=(t-s)%p
    result_x=(r*r-h*h*h-2*u*h*h)%p
    return result_x,(r*(u*h*h-result_x)-s*h*h*h)%p,h*z*zz%p


def _affine(point,p):
    x,y,z=point
    if not z:return (1,0,0)
    inverse=pow(z,-1,p)
    return 0,x*inverse*inverse%p,y*inverse*inverse*inverse%p


def _sum(left,right,p):
    if not (_valid(left,p) and _valid(right,p)):raise ValueError('canonical curve inputs required')
    return _affine(_add_jacobian(_jacobian(left),_jacobian(right),p),p)


def _select(left,right,bit,p):
    if type(bit) is not int or bit not in (0,1):raise ValueError('exact bit required')
    added=_sum(left,right,p)  # Deliberately validate the unused P branch too.
    return added if bit else left


def _pairs(curve):
    p=curve.p;identity=(1,0,0);g=(0,p-1,2);negative=(0,p-1,p-2)
    doubled=(0,41*pow(16,-1,p)%p,-299*pow(64,-1,p)%p)
    return ((identity,identity),(identity,g),(g,identity),(g,negative),(g,g),(g,doubled))


def _digits(value):
    return tuple((value>>(29*index))&(BASE-1) for index in range(9))


def _bits(value):
    return tuple((value>>index)&1 for index in range(255))


class CBitPointPureOracleTests(unittest.TestCase):
    def test_all24_complete_branches_and_both_bits_with_independent_jacobian_reference(self):
        from curve_trace import EncodedPoint
        count=0
        for curve in (PALLAS,VESTA):
            for index,(left,right) in enumerate(_pairs(curve)):
                actual=_sum(left,right,curve.p)
                native=curve.add(EncodedPoint(*left).native(),EncodedPoint(*right).native())
                expected=(1,0,0) if native is None else (0,*native)
                self.assertEqual(actual,expected)
                for bit in (0,1):
                    selected=_select(left,right,bit,curve.p)
                    self.assertEqual(selected,actual if bit else left)
                    self.assertTrue(_valid(selected,curve.p));count+=1
                if index==3:self.assertEqual(actual,(1,0,0),'inverse dispatch must produce infinity')
                if index==4:self.assertEqual(actual,_pairs(curve)[5][1],'doubling formula differs from ordinary chord addition')
        self.assertEqual(count,24)

    def test_invalid_unused_p_infinity_flags_coordinates_and_field_boundaries_reject(self):
        for curve in (PALLAS,VESTA):
            p=curve.p;g=_pairs(curve)[4][0]
            for invalid in ((0,1,1),(1,1,0),(1,0,1),(0,0,0),(2,0,0),
                            (True,0,0),(0,True,2),(0,p,2),(0,p+1,2),(0,-1,2),
                            [0,p-1,2],(0,p-1),None):
                self.assertFalse(_valid(invalid,p))
                with self.assertRaises(ValueError):_select(g,invalid,0,p)
            self.assertTrue(_valid((1,0,0),p));self.assertTrue(_valid(g,p))
            for invalid_bit in (True,False,2,-1,1.0,None):
                with self.assertRaises(ValueError):_select(g,g,invalid_bit,p)
            # These transformations remain field-canonical, so their rejection
            # actually requires curve geometry rather than a byte-width guard.
            reversed_coordinates=(0,*(int.from_bytes(value.to_bytes(32,'little'),'big') for value in g[1:]))
            self.assertTrue(all(0<=value<p for value in reversed_coordinates[1:]))
            self.assertFalse(_valid(reversed_coordinates,p))
            self.assertFalse(_valid((0,g[2],g[1]),p))

    def test_retained_low_bit_is_reduced_c_not_raw_bytes_msb_or_an_imported_bit(self):
        for (role,curve,counter,encoded,raw),bit in zip(RETAINED,(1,0),strict=True):
            c=int.from_bytes(bytes.fromhex(encoded),'little');x=int.from_bytes(bytes.fromhex(raw),'little')
            self.assertEqual(c,x%curve.q)
            self.assertEqual(c&1,bit)
            self.assertNotEqual((bytes.fromhex(encoded)[0]>>7)&1,bit)
            self.assertEqual((_digits(c)[0]&1,_bits(c)[0]),(bit,bit))
            self.assertEqual((role,curve.q),('pallas_scalar',Q) if curve is PALLAS else ('vesta_scalar',P))
            self.assertEqual((curve.name+'_base',curve.p),('pallas_base',P) if curve is PALLAS else ('vesta_base',Q))
            if curve is PALLAS:self.assertNotEqual(bytes.fromhex(raw)[0]&1,bit)
            self.assertEqual(counter+1,60 if curve is PALLAS else 45)

    def test_closed_scalar_modulus_alias_flips_bit_but_preserves_integer_relation(self):
        for _,curve,_,encoded,raw in RETAINED:
            c=int.from_bytes(bytes.fromhex(encoded),'little');x=int.from_bytes(bytes.fromhex(raw),'little')
            q=x//curve.q;alias=c+curve.q
            self.assertGreaterEqual(q,1)
            self.assertLess(alias,1<<255)
            self.assertNotEqual(alias&1,c&1)
            self.assertEqual(x,alias+curve.q*(q-1))
            self.assertEqual(sum(value<<(29*i) for i,value in enumerate(_digits(alias))),alias)
            self.assertEqual(sum(value<<i for i,value in enumerate(_bits(alias))),alias)
            self.assertTrue(all(0<=word<BASE for word in _digits(alias)))
            self.assertGreaterEqual(alias,curve.q,'reconstruction alone is not scalar canonicality')
            for value,bit,canonical in ((0,0,True),(1,1,True),(curve.q-1,0,True),(curve.q,1,False),(curve.q+1,0,False)):
                self.assertEqual(value&1,bit);self.assertEqual(value<curve.q,canonical)

    def test_endian_bit_order_and_all_nine_limb_boundaries(self):
        import scalar_bits
        for value in (0,1,2,128,256,1<<29,1<<58,1<<232,1<<254,(1<<255)-1):
            bits=_bits(value);digits=_digits(value)
            for selected in (0,28,29,231,232,254):
                self.assertEqual(scalar_bits.limb_bits(digits,bit_index=selected),bits)
            for limb in range(9):
                low=29*limb;high=min(low+29,255)
                self.assertEqual(digits[limb],sum(bits[index]<<(index-low) for index in range(low,high)))
                msb_first=tuple(reversed(bits[low:high]));acc=0
                for bit in msb_first:acc=2*acc+bit
                self.assertEqual(acc,digits[limb])
            self.assertEqual(sum(value<<index for index,value in enumerate(bits)),value)
        self.assertEqual(tuple(len(_bits(0)[29*i:min(29*i+29,255)]) for i in range(9)),(29,)*8+(23,))
        self.assertEqual((1&1,(2>>1)&1,(128>>7)&1), (1,1,1))
        self.assertNotEqual(int.from_bytes((1).to_bytes(32,'little'),'big')&1,1)

    def test_scalar_pure_preflight_and_resource_guards_precede_allocation(self):
        import scalar_bits
        for role in ('pallas_scalar','vesta_scalar'):
            for index in (0,28,29,231,232,254):
                scalar_bits._parameters(CONTEXT,role,index,OPERATION)
        for bad in (None,True,(),(0,)*8,(0,)*10,[0]*9,(True,)+(0,)*8,
                    (-1,)+(0,)*8,(BASE,)+(0,)*8):
            with self.assertRaises(ValueError):scalar_bits.limb_bits(bad,bit_index=0)
        for bad in (True,False,-1,255,1.0,None):
            with self.assertRaises(ValueError):scalar_bits.limb_bits((0,)*9,bit_index=bad)
            with self.assertRaises(ValueError):scalar_bits._parameters(CONTEXT,'pallas_scalar',bad,OPERATION)
        for bad in (True,False,2,-1,1.0):
            with self.assertRaises(ValueError):scalar_bits.limb_bits((0,)*9,bit_index=0,claimed_bit=bad)
        with self.assertRaises(ValueError):scalar_bits._parameters(CONTEXT,'pallas_base',0,OPERATION)
        for github,runner,platform in (('false','Linux','linux'),('true','Windows','linux'),('true','Linux','win32')):
            with patch.dict(os.environ,{'GITHUB_ACTIONS':github,'RUNNER_OS':runner},clear=True),\
                    patch.object(scalar_bits.sys,'platform',platform),\
                    patch.object(scalar_bits,'TraceBuilder',side_effect=AssertionError('graph allocated before guard')) as builder,\
                    patch('builtins.open',side_effect=AssertionError('I/O before guard')) as io:
                with self.assertRaisesRegex(ValueError,'hosted GitHub Linux'):
                    scalar_bits.build_scalar_bits(context=None,role=None,bit_index=None)
                empty=object.__new__(scalar_bits.ScalarBits)
                with self.assertRaisesRegex(ValueError,'hosted GitHub Linux'):empty.bind(None)
                builder.assert_not_called();io.assert_not_called()
        for cls in (scalar_bits.ScalarBits,scalar_bits.ScalarBitsBinding):
            with self.assertRaises(TypeError):cls()
            self.assertFalse(hasattr(cls,'from_json'))

    def test_point_parser_is_canonical_encoding_admission_not_curve_membership(self):
        import conditional_point as point
        from curve_trace import EncodedPoint
        for curve in (PALLAS,VESTA):
            role=curve.name+'_base';p=curve.p
            self.assertEqual(point.encoded_point(None,role=role),EncodedPoint(1,0,0))
            self.assertEqual(point.encoded_point((p-1,2),role=role),EncodedPoint(0,p-1,2))
            offcurve=point.encoded_point((1,1),role=role)
            self.assertFalse(_valid((offcurve.infinity,offcurve.x,offcurve.y),p))
            for invalid in (EncodedPoint(1,1,0),EncodedPoint(1,0,1),EncodedPoint(True,0,0),
                            EncodedPoint(2,0,0),EncodedPoint(0,p,2),EncodedPoint(0,p+1,2),
                            EncodedPoint(0,-1,2),EncodedPoint(0,True,2),[p-1,2],(0,p-1,2)):
                with self.assertRaises(ValueError):point.encoded_point(invalid,role=role)
            diagnostic=point.encoded_point(EncodedPoint(1,1,0),role=role,canonical_form=False)
            self.assertEqual(diagnostic,EncodedPoint(1,1,0))
            self.assertFalse(_valid((diagnostic.infinity,diagnostic.x,diagnostic.y),p))
        for invalid in (True,False,2,-1,1.0,None):
            with self.assertRaises(ValueError):point._bit(invalid)
        for index in (0,28,29,231,232,254):point._parameters(CONTEXT,'pallas_base',index,OPERATION)
        point._parameters(CONTEXT,'pallas_base',0,'x'*179)
        for context,role,index,operation in ((CONTEXT,'pallas_scalar',0,OPERATION),(CONTEXT,'pallas_base',True,OPERATION),
                (CONTEXT,'pallas_base',255,OPERATION),(bytes(31),'pallas_base',0,OPERATION),
                (bytearray(32),'pallas_base',0,OPERATION),(CONTEXT,'pallas_base',0,'x'*180)):
            with self.assertRaises(ValueError):point._parameters(context,role,index,operation)
        for github,runner,platform in (('false','Linux','linux'),('true','Windows','linux'),('true','Linux','win32')):
            with patch.dict(os.environ,{'GITHUB_ACTIONS':github,'RUNNER_OS':runner},clear=True),\
                    patch.object(point.sys,'platform',platform),\
                    patch.object(point,'point_add_trace',side_effect=AssertionError('point graph before guard')) as child,\
                    patch('builtins.open',side_effect=AssertionError('I/O before guard')) as io:
                with self.assertRaisesRegex(ValueError,'hosted GitHub Linux'):
                    point.build_conditional_point(context=None,role=None)
                empty=object.__new__(point.ConditionalPointPlan)
                with self.assertRaisesRegex(ValueError,'hosted GitHub Linux'):empty.bind(None,None,None)
                child.assert_not_called();io.assert_not_called()
        for cls in (point.ConditionalPointPlan,point.ConditionalPointBinding):
            with self.assertRaises(TypeError):cls()
            self.assertFalse(hasattr(cls,'from_json'))

    def test_outer_policy_role_index_and_all_nested_ids_preflight_without_source_authority(self):
        import byte_c_bit_point as outer
        for role,base in (('pallas_scalar','pallas_base'),('vesta_scalar','vesta_base')):
            self.assertEqual(outer.point_role_for_scalar(role),base)
            for index in (0,28,29,231,232,254):
                outer._parameters(CONTEXT,role,59,index,OPERATION)
                self.assertEqual(outer.bit_global_id(index),f'c/bits/bit/{index}')
            for limb in range(9):self.assertEqual(outer.bridge_global_id(f'scalar/l{limb}'),f'c/reduction/result/l{limb}')
            self.assertEqual(outer.point_global_id('select/bit',role=base,bit_index=0),'c/bits/bit/0')
            self.assertEqual(outer.point_global_id('left/infinity',role=base,bit_index=0),f'point/{base[:-5]}/left/infinity')
        for invalid in ('pallas_base','vesta_base',None,True):
            with self.assertRaises(ValueError):outer.point_role_for_scalar(invalid)
        for name in ('scalar/l00','scalar/l9','bit/00','bit/255','receipt/bit','scalar/l-1',True):
            with self.assertRaises(ValueError):outer.bridge_global_id(name)
        for index in (True,False,-1,255,None,1.0):
            with self.assertRaises(ValueError):outer._parameters(CONTEXT,'pallas_scalar',59,index,OPERATION)
        for role,counter,index in (('pallas_scalar',59,0),('vesta_scalar',44,254)):
            valid=[]
            for size in range(1,193):
                try:outer._parameters(CONTEXT,role,counter,index,'x'*size)
                except ValueError:continue
                valid.append(size)
            self.assertTrue(valid);self.assertLess(max(valid),192)
            with self.assertRaises(ValueError):outer._parameters(CONTEXT,role,counter,index,'x'*(max(valid)+1))
        for github,runner,platform in (('false','Linux','linux'),('true','Windows','linux'),('true','Linux','win32')):
            with patch.dict(os.environ,{'GITHUB_ACTIONS':github,'RUNNER_OS':runner},clear=True),\
                    patch.object(outer.sys,'platform',platform),\
                    patch.object(outer,'build_byte_rho_chain',side_effect=AssertionError('chain before guard')) as chain,\
                    patch('builtins.open',side_effect=AssertionError('I/O before guard')) as io:
                with self.assertRaisesRegex(ValueError,'hosted GitHub Linux'):
                    outer.build_byte_c_bit_point(context=None,role=None,rho_counter=None)
                empty=object.__new__(outer.CBitPointPlan)
                with self.assertRaisesRegex(ValueError,'hosted GitHub Linux'):empty.bind(None,None,None,None,None)
                with self.assertRaisesRegex(ValueError,'hosted GitHub Linux'):empty.regenerate_component(None)
                empty_binding=object.__new__(outer.CBitPointBinding)
                with self.assertRaisesRegex(ValueError,'hosted GitHub Linux'):empty_binding.iter_components()
                chain.assert_not_called();io.assert_not_called()
        for cls in (outer.CBitPointPlan,outer.CBitPointBinding,outer.CBitPointComponentSource,outer.CBitPointComponentBinding):
            with self.assertRaises(TypeError):cls()
            self.assertFalse(hasattr(cls,'from_json'))
        for key in ('bit','raw_c','scalar','source_maps','components','receipt','program','spec'):
            with self.assertRaises(TypeError):outer.build_byte_c_bit_point(
                context=CONTEXT,role='pallas_scalar',rho_counter=59,**{key:{'passed':True}})


@unittest.skipUnless(_hosted(),'dedicated GHA Linux job and BITVM2_NOVA_BIT_POINT_TESTS=1 required')
class HostedCBitPointTests(unittest.TestCase):
    def setUp(self):
        if not _hosted():self.skipTest('dedicated hosted opt-in before any graph or Script')

    def assert_stream_component(self,item,binding,plan,chain_maps,cache):
        from trace import ROLES
        import byte_rho_chain
        import byte_c_bit_point as outer
        spec=item.spec;values=item.assignment
        self.assertEqual(item.descriptor,plan.components[item.index])
        self.assertEqual((len(spec.words),len(spec.leaves)),(item.descriptor.words,item.descriptor.leaves))
        self.assertEqual(spec.context,CONTEXT.hex())
        self.assertEqual((spec.program_sha256,spec.digest().hex()),(item.descriptor.program_sha256,item.descriptor.catalogue_id))
        self.assertEqual(sha256(_canonical(item.global_ids)).hexdigest(),item.descriptor.global_ids_sha256)
        self.assertEqual(sha256(item._source_maps).hexdigest(),item.descriptor.source_maps_sha256)
        self.assertEqual(len(set(item.global_ids)),len(spec.words))
        self.assertTrue(all(type(values[name]) is int and 0<=values[name]<bound for name,bound in spec.words))
        for digest,body in spec.bodies:self.assertEqual(sha256(bytes.fromhex(body)).hexdigest(),digest)
        if item.program is None:
            self.assertIn(item.index,(0,1,4,6,7))
            self.assertTrue(all(byte_rho_chain.full_global_id(item.index,name)==global_id
                for (name,_),global_id in zip(spec.words,item.global_ids,strict=True)))
            for leaf in spec.leaves:
                v=tuple(values[spec.words[word][0]] for word in leaf.wires)
                if leaf.kind=='byte_xor':expected=v[0]^v[1]
                elif leaf.kind=='byte_and':expected=v[0]&v[1]
                elif leaf.kind=='byte_not':expected=v[0]^255
                elif leaf.kind=='byte_rol':expected=((v[0]<<leaf.argument[0])&255)|(v[1]>>(8-leaf.argument[0]))
                elif leaf.kind=='byte_xor_const':expected=v[0]^leaf.argument[0]
                else:self.fail('unexpected full permutation predicate')
                self.assertEqual(v[-1],expected)
        else:
            self.assertLessEqual(len(item.program.constraints),10000)
            self.assertEqual(item.program.digest().hex(),spec.program_sha256)
            self.assertEqual(item.program.bind(values).failures(),())
            for _,ordinal in spec.field_leaves:
                leaf=spec.leaves[ordinal]
                self.assertEqual(leaf.kind,'field_valid')
                self.assertLess(sum(values[spec.words[word][0]]<<(29*i) for i,word in enumerate(leaf.wires)),ROLES[spec.field_role])
        if item.index<9:
            self.assertEqual(spec.field_role,plan.role)
            facts=chain_maps['components'][item.index]
            chosen=[row['word_index'] for row in facts['interfaces']]
            if item.index==8:
                self.assertEqual(spec.leaves[244].kind,'field_valid')
                self.assertEqual(spec.leaves[244].wires,tuple(range(129,138)))
                self.assertEqual(tuple(values[spec.words[word][0]] for word in range(129,138)),binding.input_limbs)
                for i in range(9):
                    self.assertEqual(spec.leaves[72+i].kind,'conv_reconstruct')
                    self.assertEqual(spec.leaves[72+i].wires[0],129+i)
        elif item.index==9:
            self.assertEqual(spec.field_role,plan.role)
            self.assertEqual(item.global_ids,tuple(outer.bridge_global_id(name) for name,_ in spec.words))
            self.assertEqual(tuple(values[f'scalar/l{i}'] for i in range(9)),binding.input_limbs)
            self.assertEqual(tuple(values[f'bit/{i}'] for i in range(255)),binding.bits)
            self.assertEqual(spec.field_leaves,())
            for i in range(9):
                self.assertEqual(spec.leaves[i].wires[0],i)
                self.assertEqual(cache[f'c/reduction/result/l{i}'],(BASE,values[f'scalar/l{i}']))
            chosen=list(range(264))
        else:
            self.assertEqual(spec.field_role,plan.point_role)
            self.assertEqual(item.program.p,P if plan.role=='pallas_scalar' else Q)
            self.assertEqual(item.global_ids,tuple(outer.point_global_id(name,role=plan.point_role,bit_index=0) for name,_ in spec.words))
            point_maps=item.child_source_maps
            self.assertEqual(point_maps['selected_bit_occurrences'],[[6117,0],[6119,0],[6120,0],[6121,0],[6122,0]])
            self.assertEqual(values['select/bit'],binding.selected_bit)
            for ordinal,formal in point_maps['selected_bit_occurrences']:
                self.assertEqual(spec.leaves[ordinal].wires[formal],7476)
            for label,point in (('A',binding.A),('P',binding.P),('E',binding.E),('R',binding.R)):
                ports=point_maps['ports']
                self.assertEqual(values[ports[label+'_infinity']],point.infinity)
                self.assertEqual(sum(values[word]<<(29*i) for i,word in enumerate(ports[label+'_x'])),point.x)
                self.assertEqual(sum(values[word]<<(29*i) for i,word in enumerate(ports[label+'_y'])),point.y)
            chosen=[7476]
            del point_maps
        reused=0
        for word in chosen:
            name=item.global_ids[word];value=(spec.words[word][1],values[spec.words[word][0]])
            if name in cache:self.assertEqual(cache[name],value);reused+=1
            else:cache[name]=value
        return reused

    def test_two_honest_full_streams_link_the_actual_canonical_scalar_and_cross_role_bit(self):
        import byte_c_bit_point as outer
        import scalar_bits
        from curve_trace import EncodedPoint
        # These are literal retained input bytes, not prior execution receipts.
        from test_byte_rho_chain import VECTORS
        for role,curve,counter,encoded,raw_c in RETAINED:
            vector=next(row for row in VECTORS if row['role']==role)
            args=(bytes.fromhex(vector['eval_w']),bytes.fromhex(vector['prior']),
                  tuple(bytes.fromhex(value) for value in vector['coefficients']))
            plan=outer.build_byte_c_bit_point(context=CONTEXT,role=role,rho_counter=counter,bit_index=0,operation_id=OPERATION)
            self.assertFalse(hasattr(plan,'program'));self.assertFalse(hasattr(plan,'spec'))
            self.assertEqual((plan.point_role,plan.curve_name),(curve.name+'_base',curve.name))
            self.assertEqual(plan.source_sha256,sha256(outer.SOURCE_DOMAIN+_canonical(plan.manifest)).digest())
            maps=plan.source_maps;chain_maps=plan.chain.source_maps
            self.assertEqual(plan.source_maps_sha256,sha256(_canonical(maps)).digest())
            self.assertEqual(maps['chain_source_sha256'],plan.chain.source_sha256.hex())
            self.assertEqual(maps['upstream_canonical_guard'],dict(component_index=8,ordinal=244,limb_indices=list(range(129,138))))
            self.assertEqual((maps['leaves'],maps['local_declared_words'],maps['unique_global_words'],maps['cached_signature_reuses']),
                             (153213,156163,155107,1056))
            self.assertEqual([(row['left'],row['right'],row['words']) for row in maps['new_intersections']],[(8,9,9),(9,10,1)])
            self.assertEqual(maps['chain_point_intersection'],[])
            self.assertEqual(maps['cross_role_shared_words'],['c/bits/bit/0'])
            self.assertEqual(maps['selected_bit_to_point'],dict(global_id='c/bits/bit/0',source_component=9,
                source_word=9,source_ordinal=0,source_occurrence=29,target_component=10,target_word=7476,
                target_occurrences=[[6117,0],[6119,0],[6120,0],[6121,0],[6122,0]],cross_role_bound=2))
            for i,row in enumerate(maps['scalar_to_bits']):
                self.assertEqual(row['global_id'],f'c/reduction/result/l{i}')
                self.assertEqual((row['source_component'],row['source_word'],row['source_ordinal'],row['source_occurrence']),
                                 (8,129+i,72+i,0))
                self.assertEqual((row['canonical_ordinal'],row['canonical_occurrence'],row['target_component'],row['target_word'],row['target_ordinal'],row['target_occurrence']),
                                 (244,i,9,i,i,0))
            g,h=(EncodedPoint(*value) for value in (_pairs(curve)[4][0],_pairs(curve)[5][1]))
            binding=plan.bind(*args,g,h)
            scalar=int.from_bytes(bytes.fromhex(encoded),'little')
            self.assertEqual((binding.chain.raw_c.hex(),binding.scalar_value),(raw_c,scalar))
            self.assertEqual((binding.canonical_bit,binding.selected_bit),(scalar&1,scalar&1))
            self.assertEqual(binding.input_limbs,_digits(scalar));self.assertEqual(binding.bits,_bits(scalar))
            expected=_select((g.infinity,g.x,g.y),(h.infinity,h.x,h.y),scalar&1,curve.p)
            self.assertEqual((binding.R.infinity,binding.R.x,binding.R.y),expected)
            self.assertEqual(binding.R,binding.reference_R)
            cache={};reused=0;seen=[]
            for item in binding.iter_components():
                reused+=self.assert_stream_component(item,binding,plan,chain_maps,cache)
                seen.append(item.index)
                del item
            self.assertEqual(seen,list(range(11)))
            self.assertEqual((len(cache),reused),(2385,1056))
            # Controlled faults only compute tiny word references here. The
            # dedicated native corpus executes their complete catalogues.
            flipped=plan.bind(*args,g,h,claimed_bit=1-binding.selected_bit)
            self.assertEqual(flipped.scalar_value,binding.scalar_value)
            self.assertEqual(flipped.chain.raw_c,binding.chain.raw_c)
            self.assertEqual([i for i,(a,b) in enumerate(zip(flipped.bits,binding.bits)) if a!=b],[0])
            self.assertNotEqual(flipped.R,binding.reference_R)
            tiny=scalar_bits.build_scalar_bits(context=CONTEXT,role=role,bit_index=0,
                operation_id=plan.components[9].operation_id)
            disputed=tiny.bind(binding.input_limbs,claimed_bit=flipped.selected_bit)
            bound=disputed.program.bind(disputed.assignment)
            self.assertEqual(bound.failures(),(0,));self.assert_modes(bound,0,False)
            del flipped,tiny,disputed,bound
            alias=outer._bind_uniform_alias(plan,*args,g,h)
            self.assertIs(alias.uniform_alias,True)
            self.assertEqual(alias.scalar_value,binding.scalar_value+curve.q)
            self.assertEqual(alias.scalar_quotient_value,binding.scalar_quotient_value-1)
            self.assertEqual(alias.chain.raw_c,binding.chain.raw_c)
            self.assertEqual(int.from_bytes(alias.chain.raw_c,'little'),alias.scalar_value+curve.q*alias.scalar_quotient_value)
            self.assertNotEqual(alias.selected_bit,binding.canonical_bit)
            self.assertEqual(alias.bits,_bits(alias.scalar_value))
            self.assertNotEqual(alias.R,binding.reference_R)
            self.assertEqual(alias.reference_R,binding.reference_R)
            for summary in (plan.summary(),binding.summary(),alias.summary()):
                for flag in outer.FALSE_FLAGS:self.assertIs(summary[flag],False)
            for key in ('scalar','raw_c','bits','bit_index','receipt','source_maps','components'):
                with self.assertRaises(TypeError):plan.bind(*args,g,h,**{key:bytes(32)})
            original=plan.source_sha256;snapshot=plan.manifest;snapshot['bit_index']=1
            self.assertNotEqual(sha256(outer.SOURCE_DOMAIN+_canonical(snapshot)).digest(),original)
            self.assertEqual(plan.source_sha256,original)
            with self.assertRaises((FrozenInstanceError,AttributeError)):plan.bit_index=1
            del alias,binding,cache,maps,chain_maps,plan

    def assert_modes(self,bound,ordinal,expected,*,guards=False):
        from script import execute,num
        witness=bound.witness(ordinal)
        for disprove in (False,True):
            script=bound.script(ordinal,disprove=disprove)
            result=execute(script,witness)
            self.assertEqual(result.success,(not expected) if disprove else expected)
            self.assertIsNone(result.error,'ordinary false predicates must not be guard aborts')
            if guards:
                for malformed in ((),witness[:-1],(b'',)+witness,witness+(b'',)):
                    result=execute(script,malformed)
                    self.assertFalse(result.success);self.assertEqual(result.error,'EQUALVERIFY')
                wire=bound.program.constraints[ordinal].wires[0]
                result=execute(script,(num(bound.values[wire]^1),)+witness[1:])
                self.assertFalse(result.success);self.assertEqual(result.error,'EQUALVERIFY')
        bound.require_identity(bound.program.digest(),bound.claim_digest)
        with self.assertRaises(ValueError):bound.require_identity(bytes(32),bound.claim_digest)
        with self.assertRaises(ValueError):bound.require_identity(bound.program.digest(),bytes(32))

    def test_small_scalar_bridge_all_fixed_index_boundaries_and_noncanonical_alias(self):
        import scalar_bits
        from script import OPS,execute,num
        for role,curve,_,encoded,_ in RETAINED:
            c=int.from_bytes(bytes.fromhex(encoded),'little')
            for index in (0,28,29,231,232,254):
                plan=scalar_bits.build_scalar_bits(context=CONTEXT,role=role,bit_index=index,
                    operation_id=f'{OPERATION}/bridge/bit/{index}')
                self.assertEqual((len(plan.program.words),len(plan.spec.leaves)),(264,9))
                self.assertEqual((plan.program.fields,plan.spec.field_leaves),((),()))
                self.assertEqual(tuple(bound for _,bound in plan.program.words),(BASE,)*9+(2,)*255)
                self.assertEqual(plan.source_sha256,sha256(scalar_bits.SOURCE_DOMAIN+_canonical(plan.metadata)).hexdigest())
                maps=plan.source_maps
                self.assertEqual(maps['upstream_uniform']['field_valid_ordinal'],244)
                self.assertIs(maps['upstream_uniform']['canonicality_required'],True)
                self.assertEqual(maps['upstream_uniform']['result_word_indices'],list(range(129,138)))
                self.assertEqual(maps['upstream_uniform']['result_reconstruction_occurrences'],[[72+i,0] for i in range(9)])
                self.assertEqual(maps['required_limb_global_ids'],[f'c/reduction/result/l{i}' for i in range(9)])
                self.assertEqual(maps['selected_point_consumers'],[[6117,0],[6119,0],[6120,0],[6121,0],[6122,0]])
                binding=plan.bind(_digits(c));values=binding.assignment;bound=binding.program.bind(values)
                self.assertEqual(binding.bits,_bits(c));self.assertEqual(binding.selected_bit,(c>>index)&1)
                self.assertEqual(bound.failures(),())
                for ordinal,constraint in enumerate(plan.program.constraints):
                    low=29*ordinal;high=min(low+29,255)
                    self.assertEqual((constraint.kind,constraint.argument),('bits',(high-low,)))
                    self.assertEqual(constraint.wires,(plan.ports['input_limbs'][ordinal],)+tuple(reversed(plan.ports['bits'][low:high])))
                for bit,coordinate in enumerate(maps['bit_occurrences']):
                    ordinal,formal=coordinate
                    self.assertEqual(ordinal,bit//29)
                    self.assertEqual(formal,min(29*(bit//29+1),255)-bit)
                    self.assertEqual(plan.spec.leaves[ordinal].wires[formal],9+bit)
                for ordinal in (0,8):self.assert_modes(bound,ordinal,True,guards=True)
                changed=plan.bind(_digits(c),claimed_bit=1-binding.selected_bit)
                disputed=changed.program.bind(changed.assignment)
                self.assertEqual(disputed.failures(),(index//29,))
                self.assert_modes(disputed,index//29,False)
                alias=plan.bind(_digits(c+curve.q))
                self.assertEqual(alias.program.bind(alias.assignment).failures(),())
                self.assertGreaterEqual(sum(v<<(29*i) for i,v in enumerate(alias.input_limbs)),curve.q)
                self.assertEqual(alias.selected_bit,((c+curve.q)>>index)&1)
                copied=binding.assignment;copied[plan.ports['bits'][0]]^=1
                self.assertNotEqual(copied,binding.assignment)
                with self.assertRaises(TypeError):plan.ports['selected_bit']='other'
                with self.assertRaises((FrozenInstanceError,AttributeError)):plan.bit_index=254-index
                if index==0:
                    high=plan.bind((0,)*8+(1<<23,));high_bound=high.program.bind(high.assignment)
                    self.assertEqual(high_bound.failures(),(8,))
                    self.assert_modes(high_bound,8,False)
                    values2=binding.assignment;values2[plan.ports['selected_bit']]=2
                    with self.assertRaises(ValueError):plan.program.bind(values2)
                    leaf=plan.spec.leaves[0];body=bytes.fromhex(dict(plan.spec.bodies)[leaf.body_sha256])
                    witness=tuple(num(values2[plan.spec.words[word][0]]) for word in leaf.wires)
                    for suffix in (b'',bytes([OPS['NOT']])):
                        result=execute(body+suffix,witness)
                        self.assertFalse(result.success);self.assertEqual(result.error,'VERIFY')
                    del high,high_bound,values2
                del plan,maps,binding,values,bound,changed,disputed,alias,copied

    def test_twelve_point_edge_probes_preserve_complete_child_and_reject_closed_faults(self):
        import conditional_point as point
        from curve_trace import EncodedPoint,point_add_trace
        from wots_graph import GraphSpec
        from script import OPS,execute,num
        edge_count=0
        for _,curve,_,_,_ in RETAINED:
            role=curve.name+'_base'
            plan=point.build_conditional_point(context=CONTEXT,role=role,bit_index=0,
                operation_id=OPERATION+'/private-point/bit/0')
            maps=plan.source_maps
            self.assertEqual((len(plan.program.words),len(plan.program.constraints),len(plan.program.fields),len(plan.spec.leaves)),
                             (7498,6124,37,6161))
            self.assertEqual(maps['child']['word_map'],list(range(7476)))
            self.assertEqual(maps['child']['leaf_map'],list(range(6116))+list(range(6124,6159)))
            self.assertEqual(maps['selected_bit_occurrences'],[[6117,0],[6119,0],[6120,0],[6121,0],[6122,0]])
            self.assertEqual(maps['R_canonical_field_leaves'],[6159,6160])
            self.assertEqual(plan.spec.field_leaves[-2:],(('selected/x',6159),('selected/y',6160)))
            self.assertEqual(plan.source_sha256,sha256(point.SOURCE_DOMAIN+_canonical(plan.metadata)).digest())
            self.assertEqual(plan.source_maps_sha256,sha256(_canonical(maps)).digest())
            for index,((left,right),bit) in enumerate(zip(_pairs(curve),(0,1,0,1,0,1),strict=True)):
                a,p=EncodedPoint(*left),EncodedPoint(*right)
                binding=plan.bind(a,p,bit);values=binding.assignment;bound=binding.program.bind(values)
                expected_e=_sum(left,right,curve.p);expected_r=_select(left,right,bit,curve.p)
                self.assertEqual((binding.E.infinity,binding.E.x,binding.E.y),expected_e)
                self.assertEqual((binding.R.infinity,binding.R.x,binding.R.y),expected_r)
                self.assertEqual(bound.failures(),())
                self.assertEqual(binding.program.digest(),plan.program.digest())
                self.assertEqual(binding.source_sha256,plan.source_sha256)
                self.assertEqual(tuple(values[word] for word in plan.ports['R_x']),_digits(expected_r[1]))
                self.assertEqual(tuple(values[word] for word in plan.ports['R_y']),_digits(expected_r[2]))
                self.assertEqual(values[plan.ports['R_infinity']],expected_r[0])
                self.assertEqual(values[plan.ports['infinity_delta']],left[0]^expected_e[0])
                self.assertEqual(values[plan.ports['infinity_masked']],bit&(left[0]^expected_e[0]))
                for ordinal in range(6116,6124):self.assert_modes(bound,ordinal,True,guards=index==0)
                # Compare all old body bytes and alias occurrences once per role;
                # no second Keccak or whole-chain catalogue is constructed.
                if index==0:
                    child,child_values=point_add_trace(curve,a,p,claimed_output=binding.E,context=CONTEXT,
                        operation_id=plan.program.operation_id+'/complete-add',multiplication_backend='convolution-v1')
                    original=GraphSpec.from_program(child)
                    self.assertEqual(plan.program.words[:7476],child.words)
                    self.assertEqual(plan.program.constraints[:6116],child.constraints)
                    self.assertEqual(plan.program.fields[:35],child.fields)
                    bodies=dict(binding.spec.bodies);old_bodies=dict(original.bodies)
                    for before,after in enumerate(maps['child']['leaf_map']):
                        self.assertEqual(binding.spec.leaves[after],original.leaves[before])
                        self.assertEqual(bodies[binding.spec.leaves[after].body_sha256],old_bodies[original.leaves[before].body_sha256])
                    del child,child_values,original,bodies,old_bodies
                edge_count+=1
                del binding,values,bound
            g=EncodedPoint(*_pairs(curve)[4][0]);h=EncodedPoint(*_pairs(curve)[5][1])
            # Unused invalid P must still fail the complete child under b=0.
            for invalid_p in ((1,1),EncodedPoint(1,1,0)):
                diagnostic=plan.bind(g,invalid_p,0,claimed_E=g,claimed_R=g)
                bound=diagnostic.program.bind(diagnostic.assignment)
                self.assertTrue(bound.failures())
                self.assertTrue(all(ordinal<6116 for ordinal in bound.failures()))
                for ordinal in bound.failures():self.assert_modes(bound,ordinal,False)
                del diagnostic,bound
            # The computed E is checked even when R selects A.
            diagnostic=plan.bind(g,g,0,claimed_E=g,claimed_R=g)
            bound=diagnostic.program.bind(diagnostic.assignment)
            self.assertTrue(bound.failures());self.assertTrue(all(ordinal<6116 for ordinal in bound.failures()))
            for ordinal in bound.failures():self.assert_modes(bound,ordinal,False)
            del diagnostic,bound
            for bit in (0,1):
                honest=plan.bind(g,h,bit)
                wrong=honest.E if bit==0 else honest.A
                diagnostic=plan.bind(g,h,bit,claimed_R=wrong)
                bound=diagnostic.program.bind(diagnostic.assignment)
                self.assertEqual(bound.failures(),(6119,6120) if bit==0 else (6121,6122))
                for ordinal in bound.failures():self.assert_modes(bound,ordinal,False)
                del honest,diagnostic,bound
            normal=plan.bind(g,h,1);original=normal.assignment
            for word,expected in ((plan.ports['infinity_delta'],(6116,6117)),
                                  (plan.ports['infinity_masked'],(6117,6118)),
                                  (plan.ports['R_infinity'],(6118,6123))):
                changed=normal.assignment;changed[word]^=1;bound=normal.program.bind(changed)
                self.assertEqual(bound.failures(),expected)
                for ordinal in expected:self.assert_modes(bound,ordinal,False)
                del changed,bound
            inverse=plan.bind(g,EncodedPoint(0,g.x,(-g.y)%curve.p),1)
            changed=inverse.assignment;changed[plan.ports['R_infinity']]=0
            bound=inverse.program.bind(changed)
            self.assertEqual(bound.failures(),(6118,))
            self.assert_modes(bound,6118,False)
            del inverse,changed,bound
            # Signed, in-range infinity coordinates are refuted normally.
            inverse=plan.bind(g,EncodedPoint(0,g.x,(-g.y)%curve.p),1)
            changed=inverse.assignment;changed[plan.ports['R_x'][0]]=1
            bound=inverse.program.bind(changed)
            self.assertEqual(bound.failures(),(6121,6123))
            for ordinal in bound.failures():self.assert_modes(bound,ordinal,False)
            del inverse,changed,bound
            # Noncanonical base coordinates have an explicit field_valid path;
            # do not count canonical-input VERIFY aborts as disproof success.
            for field in ('left/x','selected/x'):
                changed=normal.assignment
                for word,value in zip(dict(plan.program.fields)[field],_digits(curve.p),strict=True):changed[word]=value
                with self.assertRaises(ValueError):plan.program.bind(changed)
                leaf=plan.spec.leaves[dict(plan.spec.field_leaves)[field]]
                body=bytes.fromhex(dict(plan.spec.bodies)[leaf.body_sha256])
                witness=tuple(num(changed[plan.spec.words[word][0]]) for word in leaf.wires)
                for disprove in (False,True):
                    result=execute(body+(bytes([OPS['NOT']]) if disprove else b''),witness)
                    self.assertEqual(result.success,disprove);self.assertIsNone(result.error)
                del changed
            changed=normal.assignment;changed[plan.ports['bit']]=2
            with self.assertRaises(ValueError):plan.program.bind(changed)
            leaf=plan.spec.leaves[6117];body=bytes.fromhex(dict(plan.spec.bodies)[leaf.body_sha256])
            witness=tuple(num(changed[plan.spec.words[word][0]]) for word in leaf.wires)
            for suffix in (b'',bytes([OPS['NOT']])):
                result=execute(body+suffix,witness)
                self.assertFalse(result.success);self.assertEqual(result.error,'VERIFY')
            leaf=plan.spec.leaves[6123];body=bytes.fromhex(dict(plan.spec.bodies)[leaf.body_sha256])
            self.assertTrue(execute(body,(num(0),)*19).success,'point_form alone does not check the curve equation')
            self.assertFalse(_valid((0,0,0),curve.p))
            self.assertEqual(normal.assignment,original)
            for flag in point.FALSE_FLAGS:self.assertIs(plan.summary()[flag],False)
            del plan,maps,normal,original,changed
        self.assertEqual(edge_count,12)


if __name__=='__main__':
    unittest.main()

