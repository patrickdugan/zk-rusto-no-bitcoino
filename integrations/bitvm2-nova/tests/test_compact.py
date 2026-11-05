"""Independent integer expectations and adversarial coverage for compact-v1."""
import dataclasses
import random
import unittest
from hashlib import sha256
from compact import mul_bit
from script import BASE, P, Q, OPS, execute, kernel, num, witness
from trace import multiplication_trace, change_field
from curve_trace import point_add_trace
from ipa_algebra import PALLAS, VESTA


class Compact(unittest.TestCase):
    def test_integer_differential_boundaries_and_random(self):
        rng = random.Random(190711)
        for p in (P, Q):
            edges = [0, 1, BASE-1, BASE, BASE**4-1, BASE**8-1, p//2, p-2, p-1]
            pairs = [(x, y) for x in edges for y in edges]
            pairs += [(rng.randrange(p), rng.randrange(p)) for _ in range(32)]
            for x, y in pairs:
                for bit in (0, 1):
                    z = (2*x + bit*y) % p
                    for output, good in ((z, True), ((z+1) % p, False)):
                        ws = witness(x, y, output, bit)
                        for code in (mul_bit(p), kernel(p, 'mul_bit')):
                            r = execute(code, ws)
                            self.assertIsNone(r.error, (x, y, bit, r))
                            self.assertEqual(r.success, good)

    def test_noncanonical_and_malformed_inputs_abort(self):
        for p in (P, Q):
            bad = [witness(x, y, 0, 1) for x, y in
                   ((p, 0), (0, p), (p+1, 1), (BASE**9-1, p-1))]
            for pos in (0, 8, 9, 17, 19, 27):
                for value in (-1, BASE, 2**31, b'\x00', b'\x80', b'\x01\x00'):
                    ws = witness(1, 2, 4, 1)
                    ws[pos] = value if isinstance(value, bytes) else num(value)
                    bad.append(ws)
            for bit in (-1, 2, 17, 2**31):
                bad.append(witness(1, 2, 4, bit))
            for ws in bad:
                r = execute(mul_bit(p), ws)
                self.assertFalse(r.success)
                self.assertIsNotNone(r.error)

    def test_new_stack_ops_and_underflow_fail_closed(self):
        for op, ws in [('DUP', []), ('OVER', []), ('OVER', [b'']),
                       ('2DROP', []), ('2DROP', [b''])]:
            self.assertEqual(execute(bytes([OPS[op]]), ws).error, 'stack underflow')
        self.assertTrue(execute(bytes([OPS['DUP'], OPS['EQUAL']]), [b'abc']).success)
        self.assertTrue(execute(bytes([OPS['OVER'], OPS['EQUAL'], OPS['BOOLAND']]),
                                [b'\x01', b'\x01']).success)
        self.assertTrue(execute(bytes([OPS['2DROP']]), [b'\x01', b'a', b'b']).success)

    def test_full_multiplication_and_all_links(self):
        for role, p in [('pallas_base', P), ('vesta_base', Q)]:
            program, values = multiplication_trace(role, p-19, p-73)
            bound = program.bind(values)
            for i in range(len(program.constraints)):
                self.assertTrue(bound.execute(i, disprove=False, compiler='compact-v1').success)
                self.assertFalse(bound.execute(i, compiler='compact-v1').success)
            for bit in range(255):
                changed = dict(values)
                changed[f'product/bit/{bit}'] ^= 1
                self.assert_refutable(program, changed, 'bits')
            for step in range(256):
                name = f'product/acc/{step}'
                ws = dict(program.fields)[name]
                old = sum(values[w] << (29*j) for j, w in enumerate(ws))
                changed = change_field(program, values, name, (old+1) % p)
                self.assert_refutable(program, changed, 'const' if step == 0 else 'mul_bit')
            self.assert_refutable(program, change_field(program, values, 'product', 1), 'equal')
            _, wrong = multiplication_trace(role, p-19, p-74)
            for w in dict(program.fields)['input/b']:
                wrong[w] = values[w]
            self.assert_refutable(program, wrong, 'bits')

    def assert_refutable(self, program, values, kind=None):
        bound = program.bind(values)
        failures = [i for i in bound.failures() if kind is None or program.constraints[i].kind == kind]
        self.assertTrue(failures)
        for i in failures:
            self.assertTrue(bound.execute(i, compiler='compact-v1').success)
            self.assertFalse(bound.execute(i, disprove=False, compiler='compact-v1').success)

    def test_exact_witness_lengths_and_opening_binding(self):
        for role, p in [('pallas_base', P), ('vesta_base', Q)]:
            program, values = multiplication_trace(role, p-19, p-73)
            b = program.bind(values)
            for i in (0, 8, 9, 18, 145, 273):
                ws = list(b.witness(i))
                for disprove in (False, True):
                    code = b.script(i, disprove=disprove, compiler='compact-v1')
                    self.assertEqual(code[0], OPS['DEPTH'])
                    for bad in ([], ws[:-1], [b'']+ws, ws+[b'']):
                        rr = execute(code, bad)
                        self.assertFalse(rr.success)
                        self.assertEqual(rr.error, 'EQUALVERIFY')
                    for j in range(len(ws)):
                        bad = ws.copy()
                        bad[j] = num(17) if bad[j] != num(17) else num(18)
                        rr = execute(code, bad)
                        self.assertFalse(rr.success)
                        self.assertEqual(rr.error, 'EQUALVERIFY')

    def test_identity_and_original_leaf_bytes(self):
        p, v = multiplication_trace('pallas_base', P-19, P-73)
        b = p.bind(v)
        # Captured directly from PR #18's 4742994 compiler, not regenerated
        # through compact-v1. Default output must stay byte-for-byte stable.
        golden = {0: '83bc3a637b67ea87432065121cd95bff2b0ef04dfe9a6fecbbedb228d007c817',
                  8: '92beade1c2e5d0e9cc87332880e36dbb43994581cff866ca294fdaf29377f761',
                  9: '82e7da564d9a68ecc5e130cf354a9907582f8982a59772e2117d9eb89158aa65',
                  18: 'e3790f87354d71854a9e61037902c251e6e47d06428aa821cc49d0039491921c',
                  145: '5d824bb9e9cd1efa86a250470acc2c12009be80a2bfcbadfe57842aceb1a9568',
                  273: 'd9ae408a187014e505dfd83ea785d843de9548e93f674647f7ff30edb687dc5c'}
        for i, digest in golden.items():
            self.assertEqual(sha256(b.script(i)).hexdigest(), digest)
        for role, op, ctx in [('vesta_scalar', 'mul', bytes(32)),
                              ('pallas_base', 'other', bytes(32)),
                              ('pallas_base', 'mul', bytes([1])*32),
                              ('vesta_base', 'mul', bytes(32))]:
            pr, va = multiplication_trace(role, P-19, P-73, operation_id=op, context=ctx)
            changed = pr.bind(va)
            with self.assertRaises(ValueError):
                changed.require_identity(b.program_digest, b.claim_digest)
            self.assertNotEqual(changed.script(18, compiler='compact-v1'),
                                b.script(18, compiler='compact-v1'))
        for cs in (p.constraints[:-1], p.constraints[::-1], p.constraints+(p.constraints[-1],)):
            changed = dataclasses.replace(p, constraints=cs).bind(v)
            with self.assertRaises(ValueError):
                changed.require_identity(b.program_digest, b.claim_digest)
        self.assertNotEqual(b.script(18), b.script(18, compiler='compact-v1'))
        with self.assertRaises(ValueError):
            b.script(18, compiler='unknown')

    def test_complete_point_graphs_and_false_claims(self):
        for c in (PALLAS, VESTA):
            g = (c.p-1, 2)
            pr, va = point_add_trace(c, g, c.mul(g, 2))
            bound = pr.bind(va)
            self.assertEqual(len(pr.constraints), 3616)
            for i in range(len(pr.constraints)):
                rr = bound.execute(i, disprove=False, compiler='compact-v1')
                self.assertTrue(rr.success, (c.name, i, rr))
            for field in ('slope', 'left/y2', 'result/x', 'result/y', 'ordinary-slope', 'y-equation'):
                ws = dict(pr.fields)[field]
                old = sum(va[w] << (29*j) for j, w in enumerate(ws))
                self.assert_refutable(pr, change_field(pr, va, field, (old+1) % c.p))
            for left, right, result in ((g, g, g), (None, g, None),
                                        ((1, 1), g, g), (g, (g[0], c.p-2), g)):
                pp, vv = point_add_trace(c, left, right, claimed_output=result)
                self.assert_refutable(pp, vv)


if __name__ == '__main__':
    unittest.main()
