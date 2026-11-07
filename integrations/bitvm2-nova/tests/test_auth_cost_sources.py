"""Independent closed source recipes; actual graphs/Script are opt-in hosted.

Local tests only use parameters, integers, the old word reference and source
ASTs. They never construct Program/GraphSpec, execute Script, or create keys.
"""
import ast
from dataclasses import FrozenInstanceError
from hashlib import sha256
import inspect
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

BASE=1<<29
AB=1<<18
MAX=(1<<32)-1
ROLES=('pallas_scalar','vesta_scalar')
PROFILES=('a0','a1','a9','a255','bad-aux','bad-square','a256','a-max','auth-order')
RECIPES=((0,0,0),(1,1,1),(9,9,81),(255,255,65025),(9,8,81),(9,9,80),
         (256,256,65536),(MAX,0,0),(9,MAX,MAX))


def _hosted():
    return (os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('RUNNER_OS')=='Linux'
        and sys.platform=='linux' and os.environ.get('BITVM2_NOVA_AUTH_COST_TESTS')=='1')


def _canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')


def _mixed_truth(values):
    a,aux,sq=values
    # The authenticated decoder's range flag is part of these truth values.
    return (0<=a<256 and 0<=aux<BASE and aux==a,
            0<=a<256 and 0<=sq<AB and sq==a*a)


def _word_round(raw):
    from keccak_trace import keccak_f1600_round
    lanes=tuple(int.from_bytes(raw[i:i+8],'little') for i in range(0,200,8))
    return b''.join(lane.to_bytes(8,'little') for lane in keccak_f1600_round(lanes,0))


def _leaf_truth(spec,values,ordinal):
    leaf=spec.leaves[ordinal]
    v=tuple(values[spec.words[i][0]] for i in leaf.wires)
    if any(type(x) is not int or not 0<=x<spec.words[i][1] for x,i in zip(v,leaf.wires,strict=True)):return False
    if leaf.kind=='conv_reconstruct':return v[0]==v[1]
    if leaf.kind=='conv_ab':return v[2]==v[0]*v[1]
    if leaf.kind=='byte_xor':expected=v[0]^v[1]
    elif leaf.kind=='byte_and':expected=v[0]&v[1]
    elif leaf.kind=='byte_not':expected=v[0]^255
    elif leaf.kind=='byte_rol':expected=((v[0]<<leaf.argument[0])&255)|(v[1]>>(8-leaf.argument[0]))
    elif leaf.kind=='byte_xor_const':expected=v[0]^leaf.argument[0]
    else:raise AssertionError('unexpected closed predicate')
    return v[-1]==expected


class AuthCostPureTests(unittest.TestCase):
    def test_all_closed_integer_recipes_preserve_unsigned_values_and_expected_truth(self):
        import auth_cost_sources as source
        self.assertEqual(source.MIXED_PROFILES,PROFILES)
        expected=((True,True),)*4+((False,True),(True,False),(False,False),(False,False),(False,False))
        for profile,values,correct in zip(PROFILES,RECIPES,expected,strict=True):
            self.assertEqual(source.mixed_values(profile),values)
            self.assertEqual(_mixed_truth(values),correct)
            self.assertTrue(all(type(value) is int and 0<=value<=MAX for value in values))
            self.assertEqual(tuple(int.from_bytes(value.to_bytes(4,'little'),'little') for value in values),values)
        self.assertEqual(source.mixed_values('a256'),(256,256,65536))
        self.assertEqual(source.mixed_values('auth-order'),(9,MAX,MAX))
        self.assertNotEqual(source.mixed_values('a256')[0]&255,source.mixed_values('a256')[0])
        for bad in (True,False,None,0,1,'a09','a-1',[],{},'honest'):
            with self.assertRaises(ValueError):source.mixed_values(bad)

    def test_fixed_synthetic_role_messages_and_source_census_are_not_proof_inputs(self):
        import auth_cost_sources as source
        self.assertEqual(source.CONTEXT,sha256(b'BITVM2-NOVA/AUTH-COST-CONFORMANCE/v1').digest())
        self.assertEqual(source.OPERATION_ID,'benchmark/auth-cost/v1')
        for role,counter in zip(ROLES,(59,44),strict=True):
            raw=bytes((17*i+counter)%256 for i in range(200))
            self.assertEqual(source.synthetic_input(role),raw)
            self.assertEqual(len(set(raw)),200)
            self.assertEqual(len(_word_round(raw)),200)
        self.assertNotEqual(source.synthetic_input(ROLES[0]),source.synthetic_input(ROLES[1]))
        mixed=dict(source.fixture_counts('mixed'));round_=dict(source.fixture_counts('round'))
        self.assertEqual((mixed['words'],mixed['leaves'],mixed['formal_occurrences'],mixed['unique_openings']),(3,2,5,4))
        self.assertEqual((round_['words'],round_['leaves'],round_['authenticated_shapes']),(1417,1217,11))
        self.assertEqual((round_['formal_occurrences'],round_['unique_openings']),(3450,3450))
        self.assertEqual(600*3+200*3+200*2+216*3+2,3450)
        with self.assertRaises(TypeError):source.fixture_counts('mixed')['words']=99
        for bad in (None,True,'boolean','full','round0',[],{}):
            with self.assertRaises(ValueError):source.fixture_counts(bad)

    def test_closed_parameters_and_resource_guard_precede_factory_or_io(self):
        import auth_cost_sources as source
        for fixture in ('mixed','round'):
            for role in ROLES:source._parameters(fixture,role)
        for fixture,role in ((True,ROLES[0]),(None,ROLES[0]),('mixed',True),('round','pallas_base'),('mixed',[]),([],ROLES[0])):
            with self.assertRaises(ValueError):source._parameters(fixture,role)
        for github,runner,platform in (('false','Linux','linux'),('true','Windows','linux'),('true','Linux','win32')):
            with patch.dict(os.environ,{'GITHUB_ACTIONS':github,'RUNNER_OS':runner},clear=True),\
                 patch.object(source.sys,'platform',platform),\
                 patch.object(source,'_source',side_effect=AssertionError('graph before guard')) as build,\
                 patch.object(source,'_round_values',side_effect=AssertionError('SSA before guard')) as ssa,\
                 patch('builtins.open',side_effect=AssertionError('I/O before guard')) as io:
                with self.assertRaisesRegex(ValueError,'hosted GitHub Linux'):source.build_auth_cost_source(None,role=None)
                with self.assertRaisesRegex(ValueError,'hosted GitHub Linux'):
                    object.__new__(source.AuthCostSource).bind(None)
                build.assert_not_called();ssa.assert_not_called();io.assert_not_called()
        for cls in (source.AuthCostSource,source.AuthCostBinding):
            with self.assertRaises(TypeError):cls()
            self.assertFalse(hasattr(cls,'from_json'))
        for key in ('context','operation_id','spec','program','receipt','source_maps','values','initial_state','counter'):
            with self.assertRaises(TypeError):source.build_auth_cost_source('mixed',role=ROLES[0],**{key:{'passed':True}})
        self.assertEqual(tuple(inspect.signature(source.AuthCostSource.bind).parameters),('self','profile'))

    def test_identity_validation_precedes_cached_ssa_and_native_source_is_independently_pinned(self):
        import auth_cost_sources as source
        tree=ast.parse(Path(source.__file__).read_text(encoding='utf-8'))
        cls=next(node for node in tree.body if isinstance(node,ast.ClassDef) and node.name=='AuthCostSource')
        bind=next(node for node in cls.body if isinstance(node,ast.FunctionDef) and node.name=='bind')
        calls=[node for node in ast.walk(bind) if isinstance(node,ast.Call) and isinstance(node.func,ast.Name)]
        lines={name:min(node.lineno for node in calls if node.func.id==name) for name in ('_hosted_guard','_validate_identity','_round_values')}
        self.assertLess(lines['_hosted_guard'],lines['_validate_identity'])
        self.assertLess(lines['_validate_identity'],lines['_round_values'])
        self.assertFalse(any(isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute)
            and node.func.attr in ('bind','_admit') for node in ast.walk(bind)))
        # Source is an isolated optional native integration and explicitly pins
        # compiler outputs after reconstructing the normative topology.
        native=Path(source.__file__).parent/'auth-cost-oracle/src/source.rs'
        text=native.read_text(encoding='utf-8')
        self.assertIn('crate::body_pins::check(',text)
        self.assertIn('2799369adbc1e02c2a9f9cfbfaea3def4e30c7de795603c20d5932e5fdf5c64e',text)
        self.assertNotIn('catch_unwind',text)
        self.assertNotIn('from_program(',text)


@unittest.skipUnless(_hosted(),'GHA Linux and BITVM2_NOVA_AUTH_COST_TESTS=1 required')
class HostedAuthCostTests(unittest.TestCase):
    def setUp(self):
        if not _hosted():self.skipTest('dedicated hosted opt-in before any graph or Script')

    def assert_source(self,source):
        import auth_cost_sources as module
        spec=source.spec
        self.assertEqual(source.context,module.CONTEXT)
        self.assertEqual(spec.context,module.CONTEXT.hex())
        self.assertEqual((spec.field_role,spec.operation_id),(source.role,source.operation_id))
        self.assertEqual(source.program.digest().hex(),spec.program_sha256)
        self.assertEqual(source.source_maps_sha256,sha256(_canonical(source.source_maps)).digest())
        self.assertEqual(source.source_sha256,sha256(module.SOURCE_DOMAIN+_canonical(source.manifest)).digest())
        self.assertEqual(source.global_ids,tuple(row['global_id'] for row in source.source_maps['words']))
        self.assertEqual(len(set(source.global_ids)),len(spec.words))
        self.assertEqual(source.manifest['catalogue_id'],spec.digest().hex())
        for digest,code in spec.bodies:self.assertEqual(sha256(bytes.fromhex(code)).hexdigest(),digest)
        for row in source.source_maps['words']:
            index=row['word_index'];self.assertEqual((row['local_name'],row['bound']),spec.words[index])
            for ordinal,formal in row['occurrences']:self.assertEqual(spec.leaves[ordinal].wires[formal],index)
        for flag in module.FALSE_FLAGS:self.assertFalse(source.summary()[flag])

    def test_mixed_both_roles_all_raw_profiles_aliases_wrong_bounded_values_and_exact_guards(self):
        import auth_cost_sources as module
        from script import OPS,execute,num
        previous_program=None
        for role in ROLES:
            source=module.build_auth_cost_source('mixed',role=role);self.assert_source(source)
            self.assertEqual(source.spec.words,(('a',256),('aux',BASE),('sq',AB)))
            self.assertEqual(source.spec.field_leaves,())
            self.assertEqual(tuple((leaf.kind,leaf.argument,leaf.wires) for leaf in source.spec.leaves),
                (('conv_reconstruct',(8,),(1,0)),('conv_ab',(1,),(0,0,2))))
            self.assertEqual([tuple(dict.fromkeys(leaf.wires)) for leaf in source.spec.leaves],[(1,0),(0,2)])
            self.assertEqual([tuple(spec_bound for spec_bound in (source.spec.words[w][1] for w in dict.fromkeys(leaf.wires)))
                for leaf in source.spec.leaves],[(BASE,256),(256,AB)])
            # These are the verified metadata offsets expected from native
            # compact10/hinted20 routing, independent of actual signature bytes.
            def route(wires):
                offset=0;rows={}
                for wire in dict.fromkeys(wires):
                    size=20 if source.spec.words[wire][1]==256 else 10
                    rows[wire]=(offset,size);offset+=size
                return tuple(rows[w] for w in wires),offset
            self.assertEqual(route(source.spec.leaves[0].wires),(((0,10),(10,20)),30))
            self.assertEqual(route(source.spec.leaves[1].wires),(((0,20),(0,20),(20,10)),30))
            if previous_program is not None:self.assertNotEqual(source.program.digest(),previous_program)
            previous_program=source.program.digest()
            for profile,expected in zip(PROFILES,RECIPES,strict=True):
                binding=source.bind(profile);values=binding.assignment
                self.assertEqual(binding.values,expected)
                self.assertEqual(tuple(values[name] for name,_ in source.spec.words),expected)
                self.assertEqual((binding.program.digest(),binding.spec.digest()),(source.program.digest(),source.spec.digest()))
                correct=_mixed_truth(expected)
                self.assertEqual(tuple(_leaf_truth(binding.spec,values,i) for i in range(2)),correct)
                for ordinal,leaf in enumerate(binding.spec.leaves):
                    unique=tuple(dict.fromkeys(leaf.wires))
                    witness=tuple(num(values[binding.spec.words[i][0]]) for i in unique)
                    body=bytes.fromhex(dict(binding.spec.bodies)[leaf.body_sha256])
                    in_domain=all(values[binding.spec.words[i][0]]<binding.spec.words[i][1] for i in unique)
                    for disprove in (False,True):
                        result=execute(body+(bytes([OPS['NOT']]) if disprove else b''),witness)
                        if in_domain:
                            self.assertIsNone(result.error)
                            self.assertEqual(result.success,not correct[ordinal] if disprove else correct[ordinal])
                        else:
                            self.assertFalse(result.success)
                            self.assertIsNotNone(result.error,'bare abort is not an authenticated disproof verdict')
                changed=binding.assignment;changed['a']=999
                self.assertNotEqual(changed,binding.assignment)
            honest=source.bind('a9');fixed=honest.program.bind(honest.assignment)
            wrong=source.bind('a1');other=wrong.program.bind(wrong.assignment)
            with self.assertRaises(ValueError):fixed.require_identity(other.program_digest,other.claim_digest)
            for ordinal in range(2):
                witness=fixed.witness(ordinal)
                for disprove in (False,True):
                    code=fixed.script(ordinal,disprove=disprove)
                    self.assertEqual(execute(code,witness).success,not disprove)
                    for malformed in ((),witness[:-1],(b'',)+witness,witness+(b'',)):
                        result=execute(code,malformed)
                        self.assertFalse(result.success);self.assertEqual(result.error,'EQUALVERIFY')
                    forged=(num(42),)+witness[1:]
                    result=execute(code,forged)
                    self.assertFalse(result.success);self.assertEqual(result.error,'EQUALVERIFY')
            self.assertEqual(source.manifest['source_maps_sha256'],source.source_maps_sha256.hex())
            with self.assertRaises(FrozenInstanceError):source.role='pallas_base'
            with self.assertRaises(FrozenInstanceError):source.program.context=bytes(32)
            with self.assertRaises(FrozenInstanceError):source.spec.operation_id='foreign'
            del source,binding,values,honest,fixed,wrong,other

    def test_exactly_two_round_graphs_have_fresh_closed_bindings_and_the_first_producer_fault(self):
        import auth_cost_sources as module
        from byte_kernels import KINDS
        from script import execute,num
        original=module.build_byte_keccak_round
        calls=0
        def counted(*args,**kwargs):
            nonlocal calls
            calls+=1
            return original(*args,**kwargs)
        # A direct wrapper retains only an integer counter, never the Programs
        # in Mock.call_args_list. Both profiles reuse each immutable source.
        with patch.object(module,'build_byte_keccak_round',new=counted):
            for role in ROLES:
                source=module.build_auth_cost_source('round',role=role);self.assert_source(source)
                self.assertEqual((len(source.spec.words),len(source.spec.leaves)),(1417,1217))
                self.assertEqual(source.operation_id,module.OPERATION_ID+'/round/round/0')
                self.assertEqual(source.spec.field_leaves,())
                first=source.source_maps['first_producer']
                self.assertEqual(first,dict(word_index=200,local_name='theta/c/x0/byte0/step1',ordinal=0,occurrence=2))
                self.assertEqual(source.spec.leaves[0].wires,(0,40,200))
                honest=source.bind('honest');values=honest.assignment
                self.assertEqual(tuple(values[name] for name in source.ports['inputs']),tuple(module.synthetic_input(role)))
                self.assertEqual(bytes(values[name] for name in source.ports['outputs']),_word_round(module.synthetic_input(role)))
                self.assertTrue(all(_leaf_truth(source.spec,values,i) for i in range(1217)))
                produced={leaf.wires[-1] for leaf in source.spec.leaves}
                consumed={w for leaf in source.spec.leaves for w in leaf.wires[:-1]}
                positions={name:i for i,(name,_) in enumerate(source.spec.words)}
                self.assertEqual({positions[name] for name in source.ports['outputs']},produced-consumed)
                self.assertTrue(all(leaf.kind in KINDS and leaf.wires[-1]==200+i for i,leaf in enumerate(source.spec.leaves)))
                fault=source.bind('producer-fault');changed=fault.assignment
                self.assertEqual([i for i,(a,b) in enumerate(zip(honest.values,fault.values,strict=True)) if a!=b],[200])
                self.assertEqual(honest.values[200]^fault.values[200],1)
                self.assertEqual([i for i in range(1217) if not _leaf_truth(source.spec,changed,i)],[0,1])
                self.assertEqual((honest.spec.digest(),fault.spec.digest()),(source.spec.digest(),source.spec.digest()))
                self.assertEqual(honest.reference_values,fault.reference_values)
                fixed=honest.program.bind(values);failed=fault.program.bind(changed)
                self.assertEqual(failed.failures(),(0,1))
                seen=set()
                for ordinal,leaf in enumerate(source.spec.leaves):
                    shape=(leaf.kind,leaf.argument,tuple(dict.fromkeys(leaf.wires)))
                    # Shape identity uses alias partition/bounds, not absolute
                    # global wire numbers or coincident assignment values.
                    alias={};pattern=[]
                    for wire in leaf.wires:
                        if wire not in alias:alias[wire]=len(alias)
                        pattern.append(alias[wire])
                    shape=(leaf.kind,leaf.argument,tuple(pattern))
                    if shape in seen:continue
                    seen.add(shape);witness=fixed.witness(ordinal)
                    for disprove in (False,True):
                        code=fixed.script(ordinal,disprove=disprove)
                        self.assertEqual(execute(code,witness).success,not disprove)
                        for malformed in ((),witness[:-1],(b'',)+witness,witness+(b'',)):
                            result=execute(code,malformed)
                            self.assertFalse(result.success);self.assertEqual(result.error,'EQUALVERIFY')
                self.assertEqual(len(seen),11)
                for ordinal in (0,1):
                    for disprove in (False,True):
                        result=execute(failed.script(ordinal,disprove=disprove),failed.witness(ordinal))
                        self.assertIsNone(result.error);self.assertEqual(result.success,disprove)
                snapshot=source.source_maps;snapshot['words'][0]['occurrences'][0][0]=9999
                self.assertNotEqual(snapshot,source.source_maps)
                ports=source.ports;ports['inputs'][0]='foreign'
                self.assertNotEqual(ports['inputs'],source.ports['inputs'])
                with self.assertRaises(TypeError):source.ports['inputs']=[]
                with self.assertRaises(FrozenInstanceError):source.context=bytes(32)
                self.assert_source(source)
                # Profiles reject caller-selected assignments/states/origins.
                for bad in (None,True,{},'a9','honest/receipt'):
                    with self.assertRaises(ValueError):source.bind(bad)
                with self.assertRaises(TypeError):source.bind('honest',assignment=values)
                del source,honest,fault,values,changed,fixed,failed,snapshot,ports
        self.assertEqual(calls,2)


if __name__=='__main__':unittest.main()
