import dataclasses
import unittest
from script import BASE, P, Q, execute, witness
from trace import multiplication_trace
from wots_leaf import WotsLeafTemplate, admitted_body


class WotsTemplates(unittest.TestCase):
    def test_honest_and_false_arithmetic(self):
        for p in (P, Q):
            for bit in (0, 1):
                for x, a in ((0, 0), (p-1, p-1), (BASE**8-1, 1), (1, p-1)):
                    z = (2*x+bit*a) % p
                    for output, good in ((z, True), ((z+1) % p, False)):
                        rr = execute(admitted_body(p), witness(x, a, output, bit))
                        self.assertEqual(rr.success, good, rr)
                        self.assertIsNone(rr.error)

    def test_authenticated_noncanonical_fields_return_false(self):
        for p in (P, Q):
            for x, a, z in ((p, 1, 0), (1, p, 0), (1, 1, p),
                            (p+1, 0, 0), (BASE**9-1, 0, 0)):
                rr = execute(admitted_body(p), witness(x, a, z, 1))
                self.assertFalse(rr.success)
                self.assertIsNone(rr.error, rr)

    def test_template_never_includes_assignment(self):
        for role, p in (('pallas_base', P), ('vesta_base', Q)):
            a, _ = multiplication_trace(role, 1, 2)
            b, _ = multiplication_trace(role, p-1, p-2)
            x, y = WotsLeafTemplate.from_program(a, 18), WotsLeafTemplate.from_program(b, 18)
            self.assertEqual(x, y)
            self.assertEqual(x.digest(), y.digest())

    def test_identity_and_order(self):
        p, _ = multiplication_trace('pallas_base', 1, 2)
        t = WotsLeafTemplate.from_program(p, 18)
        for field, value in [('context', '01'*32), ('program_sha256', '02'*32),
                             ('field_role', 'vesta_scalar'), ('operation_id', 'other'),
                             ('ordinal', 19), ('wires', t.wires[::-1]), ('body_hex', '51')]:
            self.assertNotEqual(t.digest(), dataclasses.replace(t, **{field: value}).digest())
        self.assertNotEqual(t.digest(), WotsLeafTemplate.from_program(p, 19).digest())

    def test_unsupported_shapes_fail_closed(self):
        p, _ = multiplication_trace('pallas_base', 1, 2)
        for i in (True, -1, 274, 0, 9, 273):
            with self.assertRaises(ValueError):
                WotsLeafTemplate.from_program(p, i)
        c = p.constraints[18]
        bad = dataclasses.replace(c, wires=(c.wires[0],)*28)
        pr = dataclasses.replace(p, constraints=p.constraints[:18]+(bad,)+p.constraints[19:])
        with self.assertRaises(ValueError):
            WotsLeafTemplate.from_program(pr, 18)


if __name__ == '__main__':
    unittest.main()
