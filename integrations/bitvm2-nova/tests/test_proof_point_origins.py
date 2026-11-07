"""M23 compressed-commitment decoding: pure relation checks, plus hosted graph checks.

The pure tests use only the strict codec, integer arithmetic and the closed
profile recipes. Graph construction, binding and leaf truth run only on the
hosted GitHub Linux runner (BITVM2_NOVA_PROOF_POINT_ORIGINS_TESTS=1).
"""
from hashlib import sha256
import os
from pathlib import Path
import random
import sys
import unittest

from ipa_algebra import PALLAS, VESTA, _sqrt
from nht4 import bind_container, load_expected_json
from proof_codec import load_dimensions_json
import proof_point_origins as m
from proof_payload_origins import retained_layout
from script import P, Q

FIXTURES = Path(__file__).resolve().parents[1]/'fixtures'
STEM = 'nht4-genesis-0-2020-k5'
DIM_PIN = bytes.fromhex('de6333df2e41b5f5bae1c103fab862f8d6022fd54abeb80ba61920bc9f360edc')
CONTEXT = sha256(b'proof-point-origins/independent-source-tests').digest()
OP = 'tests/proof-point-origins'

EXPECTED_VERDICTS = {
    'honest': (), 'coherent-negate': (), 'coherent-identity': (),
    'sign-flip': ('parity',), 'wrong-root': ('parity',),
    'x-noncanonical': ('x-canonical',), 'off-curve': ('on-curve',),
    'identity-alias': ('parity',), 'identity-finite-flag': ('on-curve',),
    'infinity-lie': ('point-form',), 'byte-256': ('byte-bound',), 'byte-max': ('byte-bound',)}


def _load():
    expected = load_expected_json((FIXTURES/(STEM+'.expected.json')).read_bytes())
    dimensions = load_dimensions_json((FIXTURES/(STEM+'.dimensions.json')).read_bytes(), expected,
        expected_descriptor_sha256=DIM_PIN)
    bundle = (FIXTURES/(STEM+'.nht4')).read_bytes()
    payload = bind_container(bundle, expected).proof
    return expected, dimensions, bundle, payload


def _guard_passes():
    return (os.environ.get('GITHUB_ACTIONS') == 'true'
            and os.environ.get('RUNNER_OS') == 'Linux' and sys.platform == 'linux')


def _hosted():
    return os.environ.get('BITVM2_NOVA_PROOF_POINT_ORIGINS_TESTS') == '1' and _guard_passes()


class PureFacts(unittest.TestCase):
    def test_five_is_a_nonresidue_and_orders_are_the_other_modulus(self):
        for p in (P, Q):
            self.assertEqual(pow(5, (p-1)//2, p), p-1)
        # Pasta cycle: #Pallas(F_P) = Q and #Vesta(F_Q) = P, both odd, so no
        # point of order two exists and finite points have y != 0.
        for curve, order in ((PALLAS, Q), (VESTA, P)):
            x = 1
            while pow((x**3+5) % curve.p, (curve.p-1)//2, curve.p) != 1:
                x += 1
            point = (x, _sqrt((x**3+5) % curve.p, curve.p))
            self.assertTrue(curve.valid(point))
            self.assertIsNone(curve.mul(point, order))
            self.assertEqual(order % 2, 1)

    def test_component_plan_and_census_respect_unchanged_caps(self):
        self.assertEqual(m.component_plan('pallas'), tuple(
            tuple(range(s, min(s+7, 43))) for s in range(0, 43, 7)))
        self.assertEqual(len(m.component_plan('pallas')), 7)
        self.assertEqual(len(m.component_plan('vesta')), 5)
        for engine in m.ENGINES:
            leaves = m.TAPE_CENSUS[3]
            for index in range(1, len(m.component_plan(engine))+1):
                words, arithmetic, fields, count = m.component_census(engine, index)
                self.assertLessEqual(arithmetic, 10_000)
                self.assertLessEqual(count, 30_000)
                self.assertLessEqual(words, 100_000)
                leaves += count
                ordinals = []
                for local in range(len(m.component_plan(engine)[index-1])):
                    ordinals.extend(m.decoder_leaf_ordinals(engine, index, local))
                self.assertEqual(len(ordinals), len(set(ordinals)))
                self.assertEqual(sorted(ordinals+list(range(10))+[arithmetic]), list(range(count)))
            self.assertEqual(leaves, 12664+m.COMMITMENTS[engine]*1406+11*len(m.component_plan(engine)))

    def test_constraint_count_matches_convolution_schedule(self):
        def blocks(p):
            modulus = p.to_bytes(32, 'little')
            ab = sum((len([i for i in range(32) if 0 <= c-i < 32])+3)//4 for c in range(64))
            pq = sum((len([i for i in range(32) if modulus[i] and 0 <= c-i < 32])+7)//8 for c in range(64))
            return ab, pq
        for p in (P, Q):
            ab, pq = blocks(p)
            self.assertEqual((ab, pq), (280, 92))
            mul_words = 9+32+14+32+1+ab+pq+64
            mul_constraints = 16+1+ab+pq+64+1
            self.assertEqual(1+9+9+32+3+14+32+14+1+3*mul_words+9, m.DECODER_WORDS)
            self.assertEqual(2+16+1+16+1+3*mul_constraints+1+1, m.DECODER_CONSTRAINTS)


class PureRelation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.expected, cls.dimensions, cls.bundle, cls.payload = _load()
        cls.layout = retained_layout(cls.dimensions)

    def test_every_retained_commitment_decodes_and_model_is_exact(self):
        for engine in m.ENGINES:
            p = m.MODULUS[engine]
            spans = m.commitment_spans(self.layout, engine)
            for span in spans:
                raw = self.payload[span.start:span.start+32]
                claim = m.canonical_decoding(raw, engine)
                self.assertIsNotNone(claim)
                self.assertEqual(m.decoder_verdict(tuple(raw), *claim, p), ())
                words = m.decoder_values(tuple(raw), *claim, p, raw)
                self.assertEqual(len(words), m.DECODER_WORDS)
                self.assertEqual(words[0], claim[0])
                self.assertEqual(tuple(words[19:51]), tuple(raw))
                self.assertEqual(words[52], raw[31] >> 7)

    def test_profile_recipes_have_their_exact_semantic_verdicts(self):
        for engine in m.ENGINES:
            p = m.MODULUS[engine]
            spans = m.commitment_spans(self.layout, engine)
            for profile in m.PROFILES:
                values, claims, changed, target = m.profile_claims(profile, engine, self.payload, self.layout)
                for d, span in enumerate(spans):
                    verdict = m.decoder_verdict(tuple(values[span.start:span.start+32]), *claims[d], p)
                    if d == target:
                        self.assertEqual(verdict, EXPECTED_VERDICTS[profile], (engine, profile))
                    else:
                        self.assertEqual(verdict, (), (engine, profile, d))
                outside = [i for i, (a, b) in enumerate(zip(values, self.payload)) if a != b]
                self.assertEqual(tuple(outside), changed)
                if target is not None:
                    span = spans[target]
                    self.assertTrue(all(span.start <= i < span.start+32 for i in changed))
                    m.decoder_values(tuple(values[span.start:span.start+32]), *claims[target], p,
                                     self.payload[span.start:span.start+32])

    def test_verdict_accepts_exactly_the_strict_canonical_decoding(self):
        rng = random.Random(23)
        for engine in m.ENGINES:
            p = m.MODULUS[engine]
            samples = [bytes(32), bytes(31)+b'\x80', p.to_bytes(32, 'little'),
                       (p+(1 << 255)).to_bytes(32, 'little')]
            for span in m.commitment_spans(self.layout, engine)[:6]:
                raw = self.payload[span.start:span.start+32]
                samples.append(raw)
                samples.append(raw[:31]+bytes([raw[31] ^ 0x80]))
            samples += [rng.randbytes(32) for _ in range(40)]
            for raw in samples:
                value = int.from_bytes(raw, 'little')
                x, sign = value & ((1 << 255)-1), value >> 255
                decoded = m.canonical_decoding(raw, engine)
                candidates = {(1, 0, 0), (0, 0, 0), (1, x, 0), (0, x, 0)}
                if x < p:
                    root = _sqrt((x**3+5) % p, p)
                    if root is not None:
                        candidates.update({(0, x, root), (0, x, p-root), (1, x, root)})
                for claim in candidates:
                    if claim[1] >= 1 << 255:
                        continue
                    accepted = m.decoder_verdict(tuple(raw), *claim, p) == ()
                    self.assertEqual(accepted, claim == decoded, (engine, raw.hex(), claim))
                if decoded is None:
                    self.assertTrue(all(m.decoder_verdict(tuple(raw), *c, p) for c in candidates
                                        if c[1] < 1 << 255))

    def test_identity_alias_is_rejected_like_the_strict_codec(self):
        for engine in m.ENGINES:
            alias = bytes(31)+b'\x80'
            self.assertIsNone(m.canonical_decoding(alias, engine))
            self.assertEqual(m.decoder_verdict(tuple(alias), 1, 0, 0, m.MODULUS[engine]), ('parity',))
            self.assertEqual(m.canonical_decoding(bytes(32), engine), (1, 0, 0))

    def test_hosted_guard_blocks_local_graph_construction(self):
        if _guard_passes():
            self.skipTest('hosted runner: the guard admits construction here')
        with self.assertRaises(ValueError):
            m.build_proof_point_origins(self.bundle, self.expected, self.dimensions,
                                        engine='pallas', context=CONTEXT, operation_id=OP)


@unittest.skipUnless(_hosted(), 'hosted GitHub Linux graph checks only')
class HostedGraphs(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.expected, cls.dimensions, cls.bundle, cls.payload = _load()
        cls.layout = retained_layout(cls.dimensions)
        cls.engine = os.environ.get('BITVM2_NOVA_POINT_ENGINE', 'pallas')
        cls.plan = m.build_proof_point_origins(cls.bundle, cls.expected, cls.dimensions,
            engine=cls.engine, context=CONTEXT, operation_id=OP)

    def test_census_identity_and_honest_builder_assignment(self):
        binding = self.plan.bind_profile('honest')
        total = 0
        for record in binding.iter_components():
            self.assertEqual((record.descriptor['words'], record.descriptor['leaves']),
                             (len(record.spec.words), len(record.spec.leaves)))
            self.assertTrue(all(value is True for value in record.truth))
            total += len(record.spec.leaves)
        self.assertEqual(total, sum(c['leaves'] for c in self.plan.components))

    def test_each_fault_is_localized_to_the_target_decoder(self):
        for profile in m.PROFILES[1:]:
            binding = self.plan.bind_profile(profile)
            target = binding.target
            component = 1+target//m.BATCH
            local = target % m.BATCH
            decoder = set(m.decoder_leaf_ordinals(self.engine, component, local))
            false, total = {}, 0
            for index, record in enumerate(binding.iter_components()):
                rows = [j for j, t in enumerate(record.truth) if t is not True]
                false[index] = rows
                self.assertTrue(set(rows) <= set(record.selected_ordinals))
                total += len(record.selected_ordinals)
                del record
            self.assertLessEqual(total, m.TARGET_CAP)
            for index, rows in false.items():
                if index == component:
                    self.assertTrue(set(rows) <= decoder, (profile, rows))
                elif index == 0:
                    expected = 1 if profile in ('byte-256', 'byte-max') else 0
                    self.assertEqual(len(rows), expected, profile)
                else:
                    self.assertEqual(rows, [], profile)
            count = len(false[component])
            if profile in m.COHERENT:
                self.assertEqual(count, 0, profile)
            elif profile in ('byte-256', 'byte-max'):
                self.assertEqual(count, 93, profile)
            else:
                self.assertEqual(count, 1, profile)
            del binding


if __name__ == '__main__':
    unittest.main()
