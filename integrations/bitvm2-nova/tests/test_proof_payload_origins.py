"""Independent retained profile/claim checks; real graphs are hosted only."""
import ast
from collections import Counter
from dataclasses import FrozenInstanceError
from hashlib import sha256
import inspect
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

from nht4 import HEADER_BYTES,bind_container,load_expected_json
from proof_codec import decode_proof,load_dimensions_json
from script import BASE,P,Q

FIXTURES = Path(__file__).resolve().parents[1]/'fixtures'
STEM = 'nht4-genesis-0-2020-k5'
DIM_PIN = bytes.fromhex('de6333df2e41b5f5bae1c103fab862f8d6022fd54abeb80ba61920bc9f360edc')
CONTEXT = sha256(b'proof-payload-origins/independent-source-tests').digest()
OP = 'tests/proof-payload-origins'
PROFILES = ('honest','coherent-p-eval','coherent-v-eval','p-mod','p-mod1','v-mod','v-mod1',
    'zn0-width','p-outer-count','v-outer-count','opaque-p','opaque-v','byte-256','byte-max')


def _load():
    expected = load_expected_json((FIXTURES/(STEM+'.expected.json')).read_bytes())
    dimensions = load_dimensions_json((FIXTURES/(STEM+'.dimensions.json')).read_bytes(),expected,
        expected_descriptor_sha256=DIM_PIN)
    bundle = (FIXTURES/(STEM+'.nht4')).read_bytes()
    payload = bind_container(bundle,expected).proof
    return expected,dimensions,bundle,payload


def _canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')


def _hosted():
    return (os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('RUNNER_OS')=='Linux'
        and sys.platform=='linux' and os.environ.get('BITVM2_NOVA_PROOF_PAYLOAD_ORIGINS_TESTS')=='1')


def _independent_field(raw):
    value = int.from_bytes(raw,'little')
    digits = tuple((value//(1<<(29*i)))%BASE for i in range(9))
    pieces = []
    for boundary in range(29,256,29):
        byte,width = divmod(boundary,8)
        if width:pieces.extend((raw[byte]%(1<<width),raw[byte]//(1<<width)))
    return digits,tuple(pieces)


class PayloadPureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.expected,cls.dimensions,cls.bundle,cls.payload = _load()

    def test_verifier_owned_maximum_layout_partition_roles_offsets_and_narrower_zn_widths(self):
        import proof_payload_origins as source
        layout = source.retained_layout(self.dimensions)
        decoded = decode_proof(self.payload,self.dimensions)
        self.assertEqual(tuple((s.path,s.kind,s.start,s.size,s.engine) for s in layout),
            tuple((s.path,s.kind,s.start,s.size,s.engine) for s in decoded.spans))
        self.assertEqual(Counter(s.kind for s in layout),{'scalar':288,'commitment':78,'length':119})
        self.assertEqual(Counter((s.kind,s.engine) for s in layout if s.kind!='length'),
            {('scalar','pallas'):169,('scalar','vesta'):119,('commitment','pallas'):43,('commitment','vesta'):35})
        self.assertEqual(Counter((s.minimum,s.maximum) for s in layout if s.kind=='length'),
            {(1,3):33,(1,2):68,(2,2):7,(19,19):4,(14,14):4,(20,20):1,(15,15):1,(17,17):1})
        self.assertEqual(sum(s.kind=='length' and s.minimum!=s.maximum for s in layout),101)
        self.assertEqual(tuple(s.width_bits for s in layout if s.width_bits is not None),
            (32,128,128,200)+(32,)*13)
        self.assertEqual((layout[0].start,layout[-1].start+layout[-1].size),(0,12664))
        self.assertTrue(all(a.start+a.size==b.start for a,b in zip(layout,layout[1:])))
        offsets = {s.path:s.start for s in layout}
        self.assertEqual((offsets['snark_primary.eval_W'],offsets['snark_secondary.eval_W']),(4624,10048))
        self.assertEqual((offsets['zn'],offsets['zn[0]'],offsets['zn[16]']),(12112,12120,12632))
        self.assertEqual(source._reference(self.bundle,self.expected,self.dimensions,layout),self.payload)

    def test_disjoint_prefix_and_width_constants_exact_byte_order_and_scope(self):
        import proof_payload_origins as source
        layout = source.retained_layout(self.dimensions)
        anchors = source.tape_anchors(layout)
        self.assertEqual(len(anchors),1383)
        self.assertEqual(len({a[0] for a in anchors}),1383)
        self.assertEqual(Counter(a[2] for a in anchors),{'length':952,'zn-width':431})
        self.assertEqual({a[1] for a in anchors},{0,2,3,14,15,17,19,20})
        for offset,value,reason,path in anchors:
            self.assertEqual(self.payload[offset],value,(reason,path,offset))
        order = source._tape_order(layout)
        self.assertEqual(len(order),12664)
        self.assertEqual(set(order),set(range(12664)))
        self.assertEqual(order[:1383],tuple(a[0] for a in anchors))
        maps = source._component_maps(0,layout)
        for offset,ordinal in enumerate(maps['byte_ordinals']):self.assertEqual(order[ordinal],offset)
        self.assertEqual(tuple(len(source._controls(i,layout)) for i in range(3)),(9,17,17))
        self.assertEqual(12664+169*17+119*17,17560)
        self.assertEqual(12664+(169+119)*55,28504)
        self.assertEqual(12664+(169+119)*23,19288)
        self.assertEqual(288*32,9216)
        self.assertEqual(288*23,6624)
        self.assertEqual(17560*2,35120)

    def test_exact_unsigned_encoding_arithmetic_and_all_closed_profile_truth_limits(self):
        import proof_payload_origins as source
        from eval_w_encoding import encoding_values
        for modulus in (P,Q):
            for value in (0,1,modulus-1,modulus,modulus+1,1<<255,(1<<256)-1):
                raw = value.to_bytes(32,'little')
                expected_limbs,expected_pieces = _independent_field(raw)
                actual_limbs,actual_bytes,actual_pieces = encoding_values(raw)
                self.assertEqual((actual_limbs,actual_pieces),(expected_limbs,expected_pieces))
                self.assertEqual(tuple(raw),actual_bytes)
                self.assertEqual(sum(v<<(29*i) for i,v in enumerate(actual_limbs)),value)
        layout = source.retained_layout(self.dimensions)
        targets = (17560,92,92,92,92,92,92,92,50,51,75,74,61,61)
        false_counts = ((0,0,0),(0,0,0),(0,0,0),(0,1,0),(0,1,0),(0,0,1),(0,0,1),
                        (1,0,0),(1,0,0),(1,0,0),(0,0,0),(0,0,0),(1,1,0),(1,1,0))
        self.assertEqual(source.PROFILES,PROFILES)
        for profile,target,failures in zip(PROFILES,targets,false_counts,strict=True):
            values,changed = source.profile_values(profile,self.payload,layout)
            self.assertEqual(len(values),12664)
            records = tuple(source._pure_component(i,layout,values,self.payload) for i in range(3))
            truth = tuple(row[1] for row in records)
            self.assertEqual(tuple(map(len,truth)),(12664,2873,2023))
            self.assertEqual(tuple(len(row[0]) for row in records),(12664,9295,6545))
            self.assertEqual(tuple(sum(v is False for v in rows) for rows in truth),failures,profile)
            selection = source._selection(profile,layout,truth,changed)
            self.assertEqual(sum(map(len,selection)),target)
            if profile!='honest':self.assertLessEqual(target,128)
            for i in range(3):
                self.assertTrue({j for j,v in enumerate(truth[i]) if not v}<=set(selection[i]))
            if profile in ('byte-256','byte-max'):
                expected = 256 if profile=='byte-256' else (1<<32)-1
                self.assertEqual(values[4624],expected)
                p_index = next(i for i,s in enumerate(source._scalar_spans(layout,1)) if s.path=='snark_primary.eval_W')
                self.assertEqual(records[1][0][55*p_index+9],expected)
                self.assertTrue(all(type(v) is int and 0<=v<(1<<32) for v in records[1][0]))

    def test_opaque_points_and_coherent_scalars_are_deliberately_unbound_origins(self):
        import proof_payload_origins as source
        from proof_codec import decode_point
        layout = source.retained_layout(self.dimensions)
        for profile,engine in [('opaque-p','pallas'),('opaque-v','vesta')]:
            values,changed = source.profile_values(profile,self.payload,layout)
            self.assertEqual(len(changed),32)
            raw = bytes(values[min(changed):min(changed)+32])
            with self.assertRaises(ValueError):decode_point(raw,engine)
            self.assertFalse(any(not x for i in range(3)
                for x in source._pure_component(i,layout,values,self.payload)[1]))
        for profile in ('coherent-p-eval','coherent-v-eval'):
            values,_ = source.profile_values(profile,self.payload,layout)
            self.assertNotEqual(bytes(values),self.payload)
            self.assertNotEqual(sha256(bytes(values)).digest(),self.expected.proof_sha256)
            self.assertFalse(any(not x for i in range(3)
                for x in source._pure_component(i,layout,values,self.payload)[1]))

    def test_canonical_width_valid_zn_change_does_not_bind_public_header_state(self):
        import proof_payload_origins as source
        layout = source.retained_layout(self.dimensions)
        zn0 = next(span for span in layout if span.path=='zn[0]')
        claimed = bytearray(self.payload)
        expected_height = self.expected.initial_state[0]+self.expected.steps*self.expected.k
        self.assertEqual(int.from_bytes(claimed[zn0.start:zn0.start+32],'little'),expected_height)
        claimed[zn0.start:zn0.start+32] = (expected_height+1).to_bytes(32,'little')
        self.assertLess(expected_height+1,1<<32)
        self.assertNotEqual(bytes(claimed),self.payload)
        self.assertFalse(any(not truth for i in range(3) for truth in
            source._pure_component(i,layout,tuple(claimed),self.payload)[1]))
        self.assertIn('public_state_to_zn_script_bound',source.FALSE_FLAGS)

    def test_resource_guard_types_fixed_policy_and_no_candidate_backend_dependencies(self):
        import proof_payload_origins as source
        source._parameters(self.bundle,self.expected,self.dimensions,CONTEXT,OP)
        for bad in (bytearray(self.bundle),self.bundle[:-1],self.bundle+b'\x00'):
            with self.assertRaises(ValueError):source._parameters(bad,self.expected,self.dimensions,CONTEXT,OP)
        for context,op in [(bytearray(CONTEXT),OP),(CONTEXT,'x'*192),(CONTEXT,True)]:
            with self.assertRaises(ValueError):source._parameters(self.bundle,self.expected,self.dimensions,context,op)
        for github,runner,platform in [('false','Linux','linux'),('true','Windows','linux'),('true','Linux','win32')]:
            with patch.dict(os.environ,{'GITHUB_ACTIONS':github,'RUNNER_OS':runner},clear=True),\
                 patch.object(source.sys,'platform',platform),\
                 patch.object(source,'_build_component',side_effect=AssertionError('graph before guard')) as build:
                with self.assertRaisesRegex(ValueError,'hosted GitHub Linux'):
                    source.build_proof_payload_origins(None,None,None,context=None)
                with self.assertRaisesRegex(ValueError,'hosted GitHub Linux'):
                    object.__new__(source.ProofPayloadOrigins).bind(None)
                build.assert_not_called()
        for cls in (source.ProofPayloadOrigins,source.ProofPayloadBinding,source.PayloadComponentBinding):
            with self.assertRaises(TypeError):cls()
        for name in ('program','spec','receipt','source_maps','layout','role','claimed_payload'):
            with self.assertRaises(TypeError):source.build_proof_payload_origins(
                self.bundle,self.expected,self.dimensions,context=CONTEXT,**{name:None})
        self.assertEqual(tuple(inspect.signature(source.ProofPayloadOrigins.bind).parameters),('self','claimed_payload'))
        tree = ast.parse(Path(source.__file__).read_text(encoding='utf-8'))
        imports = [n.module for n in ast.walk(tree) if isinstance(n,ast.ImportFrom)]
        self.assertFalse(any(name and ('auth_cost' in name or 'hint' in name) for name in imports))
        self.assertIn('convolution',imports)
        self.assertIn('eval_w_encoding',imports)


@unittest.skipUnless(_hosted(),'GHA Linux and BITVM2_NOVA_PROOF_PAYLOAD_ORIGINS_TESTS=1 required')
class HostedPayloadTests(unittest.TestCase):
    def test_one_complete_legacy_stream_exact_fields_openings_and_noncanonical_raw_binding(self):
        import proof_payload_origins as module
        expected,dimensions,bundle,payload = _load()
        plan = module.build_proof_payload_origins(bundle,expected,dimensions,context=CONTEXT,operation_id=OP)
        self.assertEqual(plan.source_maps_sha256,sha256(_canonical(plan.source_maps)).digest())
        self.assertEqual(plan.source_sha256,sha256(module.DOMAIN+_canonical(plan.manifest)).digest())
        self.assertEqual(tuple((d.words,d.arithmetic_constraints,d.canonical_fields,d.leaves) for d in plan.components),
            ((12664,1383,0,12664),(9295,2704,169,2873),(6545,1904,119,2023)))
        honest = plan.bind_profile('honest')
        self.assertEqual(honest.asserted_payload,payload)
        captures = {};declared=0;leaves=0;iterator=honest.iter_components()
        for index in range(3):
            item = next(iterator)
            self.assertEqual(item.index,index)
            self.assertEqual(item.descriptor,plan.components[index])
            self.assertEqual(item.program.digest().hex(),item.spec.program_sha256)
            self.assertEqual(item.descriptor.catalogue_id,item.spec.digest().hex())
            self.assertEqual(item.descriptor.source_maps_sha256,sha256(item._source_maps).hexdigest())
            self.assertEqual(item.descriptor.source_sha256,sha256(module.COMPONENT_DOMAIN+item._source_manifest).hexdigest())
            self.assertEqual(len(item.truth),len(item.spec.leaves));self.assertTrue(all(item.truth))
            self.assertEqual(item.selected_ordinals,tuple(range(len(item.spec.leaves))))
            declared += len(item.spec.words);leaves += len(item.spec.leaves)
            for word,(name,bound),value in zip(item.global_ids,item.spec.words,item.values,strict=True):
                self.assertLessEqual(len(word),192)
                self.assertNotIn('[',word)
                if word in captures:self.assertEqual(captures[word],(bound,value))
                else:captures[word]=(bound,value)
            if index == 0:
                maps = item.child_source_maps
                self.assertEqual(sum(leaf.kind=='const' for leaf in item.spec.leaves),1383)
                self.assertEqual(sum(leaf.kind=='word_valid' for leaf in item.spec.leaves),11281)
                for offset,ordinal in enumerate(maps['byte_ordinals']):self.assertEqual(item.spec.leaves[ordinal].wires,(offset,))
            else:
                n = (169,119)[index-1]
                self.assertEqual(tuple(i for _,i in item.spec.field_leaves),tuple(range(16*n,17*n)))
                maps = item.child_source_maps
                for row in maps['scalars']:
                    for word,(ordinal,formal) in zip(row['byte_words'],row['byte_occurrences'],strict=True):
                        self.assertEqual(item.spec.leaves[ordinal].wires[formal],word)
                    for link in row['canonical_links']:
                        self.assertEqual(item.spec.leaves[link['source_ordinal']].wires[link['source_occurrence']],link['word_index'])
                        self.assertEqual(item.spec.leaves[link['target_ordinal']].wires[link['target_occurrence']],link['word_index'])
            assignment=item.assignment;assignment[item.spec.words[0][0]]=123
            self.assertNotEqual(assignment,item.assignment)
            del item,maps,assignment
        with self.assertRaises(StopIteration):next(iterator)
        self.assertEqual((declared,len(captures),leaves),(28504,19288,17560))
        self.assertEqual(declared-len(captures),9216)
        for profile in PROFILES:
            claim = plan.bind_profile(profile)
            self.assertEqual(sum(map(len,claim.selected_ordinals)),17560 if profile=='honest' else
                (92 if profile in PROFILES[1:8] else {'p-outer-count':50,'v-outer-count':51,
                    'opaque-p':75,'opaque-v':74,'byte-256':61,'byte-max':61}[profile]))
            if claim.asserted_payload is not None:
                public = plan.bind(claim.asserted_payload)
                self.assertEqual(public.truth,claim.truth)
                self.assertEqual(public.values,claim.values)
                del public
            del claim
        for bad in (payload[:-1],payload+b'\x00',bytearray(payload)):
            with self.assertRaises(ValueError):plan.bind(bad)
        copy = plan.source_maps;copy['layout'][0]['start']=99
        self.assertNotEqual(copy,plan.source_maps)
        with self.assertRaises(FrozenInstanceError):plan.operation_id='changed'
        for flag in module.FALSE_FLAGS:self.assertFalse(plan.summary()[flag])


if __name__ == '__main__':unittest.main()
