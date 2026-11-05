import itertools
import unittest
from script import P, OPS, execute, num
from trace import TraceBuilder
from trace_kernels import compile_predicate
from wots_graph import GraphSpec


class BooleanKernels(unittest.TestCase):
    def test_complete_truth_tables_and_false_claims(self):
        for kind in ('bool_xor', 'bool_and', 'bool_not'):
            width = 2 if kind == 'bool_not' else 3
            for values in itertools.product((0, 1), repeat=width):
                expected = (1-values[0] if kind == 'bool_not' else
                            values[0] ^ values[1] if kind == 'bool_xor' else values[0] & values[1])
                good = values[-1] == expected
                code = compile_predicate(P, kind)
                ws = [num(v) for v in values]
                self.assertEqual(execute(code, ws).success, good)
                self.assertEqual(execute(code+bytes([OPS['NOT']]), ws).success, not good)
                g = TraceBuilder('pallas_base', 'boolean', bytes(32))
                wires = [g.small(f'w{i}', v, 2) for i, v in enumerate(values)]
                g.check(kind, wires)
                pr, va = g.finish()
                bound = pr.bind(va)
                self.assertEqual(bool(bound.failures()), not good)
                self.assertEqual(bound.execute(0).success, not good)
                spec = GraphSpec.from_program(pr)
                self.assertEqual(len(spec.leaves), 1)
                self.assertEqual(spec.leaves[0].kind, kind)

    def test_malformed_encodings_and_shapes_fail_closed(self):
        for kind in ('bool_xor', 'bool_and', 'bool_not'):
            width = 2 if kind == 'bool_not' else 3
            for bad in (num(2), num(-1), b'\x00', b'\x01\x00'):
                ws = [b'']*width
                ws[0] = bad
                code = compile_predicate(P, kind)+bytes([OPS['NOT']])
                self.assertFalse(execute(code, ws).success)
                self.assertIsNotNone(execute(code, ws).error)
            with self.assertRaises(ValueError):
                compile_predicate(P, kind, (1,))
            g = TraceBuilder('pallas_base', 'bad-boolean', bytes(32))
            w = g.small('w', 0, 2)
            with self.assertRaises(ValueError):
                g.check(kind, [w])


if __name__ == '__main__':
    unittest.main()
