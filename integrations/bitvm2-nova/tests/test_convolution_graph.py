"""Complete point dispatch and shared-adapter checks for the opt-in backend."""
from hashlib import sha256
import unittest

from curve_trace import EncodedPoint, point_add_trace
from ipa_algebra import PALLAS, VESTA
from script import P
from trace_kernels import compile_predicate
from wots_graph import GraphSpec


class ConvolutionPointGraphs(unittest.TestCase):
    def test_all_dispatch_branches_have_fixed_topology_and_canonical_fields(self):
        for curve in (PALLAS, VESTA):
            g = (curve.p-1, 2)
            h = curve.mul(g, 2)
            inverse = (g[0], (-g[1]) % curve.p)
            identity = None
            for a, b in ((None, None), (None, g), (g, None),
                         (g, inverse), (g, g), (g, h)):
                program, values = point_add_trace(curve, a, b,
                    context=sha256(b'convolution-dispatch-regression').digest(),
                    multiplication_backend='convolution-v1')
                if identity is None:
                    identity = program.digest()
                self.assertEqual(program.digest(), identity)
                self.assertEqual((len(program.words), len(program.constraints), len(program.fields)),
                                 (7476, 6116, 35))
                self.assertFalse(program.bind(values).failures())
                # The actual integer quotient has no field declaration.
                self.assertFalse(any('/q/' in name for name, _ in program.fields))
            spec = GraphSpec.from_program(program)
            self.assertEqual(len(spec.leaves), 6151)
            self.assertTrue(any(leaf.kind == 'conv_ab'
                and len(set(leaf.wires)) < len(leaf.wires) for leaf in spec.leaves))

    def test_false_point_claims_are_refuted_by_executable_constraints(self):
        for curve in (PALLAS, VESTA):
            g = (curve.p-1, 2)
            for a, b, claim in ((g, g, g), (None, g, None), (g, None, None),
                                (EncodedPoint(1, 1, 0), g, g)):
                program, values = point_add_trace(curve, a, b, claimed_output=claim,
                    multiplication_backend='convolution-v1')
                bound = program.bind(values)
                failures = bound.failures()
                self.assertTrue(failures)
                for ordinal in failures:
                    result = bound.execute(ordinal)
                    self.assertTrue(result.success, result.error)
                    self.assertFalse(bound.execute(ordinal, disprove=False).success)

    def test_shared_dispatch_validates_before_cache_and_rejects_unknown_backend(self):
        compile_predicate(P, 'conv_ab', (1,))
        with self.assertRaises(ValueError):
            compile_predicate(P, 'conv_ab', (True,))
        with self.assertRaises(ValueError):
            point_add_trace(PALLAS, None, None, multiplication_backend='unsupported')


if __name__ == '__main__':
    unittest.main()
