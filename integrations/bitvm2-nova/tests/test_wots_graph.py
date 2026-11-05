import dataclasses
import unittest
from script import BASE, P, Q, execute, num
from trace import multiplication_trace, TraceBuilder
from curve_trace import point_add_trace
from ipa_algebra import PALLAS, VESTA
from wots_graph import GraphSpec, expansion_script, field_valid_body, authenticated_shape


class GraphCatalogue(unittest.TestCase):
    def test_every_multiplication_link_uses_same_registry_slot(self):
        for role, p in [('pallas_base', P), ('vesta_base', Q)]:
            pr, _ = multiplication_trace(role, p-19, p-73)
            spec = GraphSpec.from_program(pr)
            self.assertEqual(len(spec.leaves), 533)
            self.assertEqual(len(spec.words), 2586)
            self.assertEqual(spec.original_constraints, 274)
            for step in range(254):
                current, following = spec.leaves[18+step], spec.leaves[19+step]
                self.assertEqual(current.wires[19:], following.wires[:9])
            self.assertEqual(spec.leaves[272].wires[19:], spec.leaves[273].wires[:9])
            slots = {name: i for i, (name, _) in enumerate(spec.words)}
            for shift in range(255):
                self.assertEqual(spec.leaves[18+254-shift].wires[18], slots[f'product/bit/{shift}'])
            for limb in range(9):
                self.assertEqual(spec.leaves[limb].wires[0], slots[f'input/b/l{limb}'])
            self.assertEqual({name for name, _ in spec.field_leaves}, {name for name, _ in pr.fields})

    def test_field_validity_is_disputable_not_an_abort(self):
        for p in (P, Q):
            for value in (0, p-1, p, p+1, BASE**9-1):
                words = [num((value >> (29*i)) & (BASE-1)) for i in range(9)]
                result = execute(field_valid_body(p), words)
                self.assertIsNone(result.error)
                self.assertEqual(result.success, value < p)

    def test_duplicate_occurrences_recover_one_signed_word(self):
        # Two identical operands are signed once and expanded in the raw body.
        for occurrences in ((0, 0, 1), (2, 0, 2, 1, 0), (0, 1, 2, 0, 1, 2)):
            unique = tuple(dict.fromkeys(occurrences))
            code = expansion_script(occurrences)
            # Verify each restored stack position, then leave a true clean stack.
            for i in reversed(occurrences):
                code += bytes([0x51+i, 0x88])
            code += b'\x51'
            self.assertTrue(execute(code, [num(i+1) for i in unique]).success)

    def test_complete_point_catalogues_cover_all_fields_and_wires(self):
        for curve in (PALLAS, VESTA):
            g = (curve.p-1, 2)
            pr, _ = point_add_trace(curve, g, g)
            spec = GraphSpec.from_program(pr)
            self.assertEqual(spec.original_constraints, 3616)
            self.assertEqual(len(spec.field_leaves), len(pr.fields))
            self.assertEqual(set(w for l in spec.leaves for w in l.wires), set(range(len(spec.words))))
            self.assertTrue(any(len(set(l.wires)) < len(l.wires) for l in spec.leaves))

    def test_point_membership_and_dispatch_use_their_declared_selector_bounds(self):
        g = (PALLAS.p-1, 2)
        pr, _ = point_add_trace(PALLAS, g, g)
        spec = GraphSpec.from_program(pr)
        selectors = {spec.words[l.wires[0]][1] for l in spec.leaves if l.kind == 'gate_equal'}
        # Curve membership is gated by a Boolean infinity flag, while slope
        # and output equations use the five-way addition dispatch selector.
        self.assertEqual(selectors, {2, 5})

    def test_point_sampling_distinguishes_decoder_bounds(self):
        g = (PALLAS.p-1, 2)
        pr, _ = point_add_trace(PALLAS, g, PALLAS.mul(g, 2))
        spec = GraphSpec.from_program(pr)
        self.assertEqual(len({l.body_sha256 for l in spec.leaves}), 23)
        self.assertEqual(len({authenticated_shape(spec, l) for l in spec.leaves}), 25)
        self.assertEqual(spec.leaves[0].body_sha256, spec.leaves[18].body_sha256)
        self.assertNotEqual(authenticated_shape(spec, spec.leaves[0]),
                            authenticated_shape(spec, spec.leaves[18]))

    def test_unreferenced_small_has_a_validity_path(self):
        g = TraceBuilder('pallas_base', 'bounds', bytes(32))
        g.constant('zero', 0)
        g.small('unused', 1, 3)
        pr, _ = g.finish()
        spec = GraphSpec.from_program(pr)
        self.assertEqual(spec.leaves[-1].kind, 'word_valid')
        self.assertEqual(spec.leaves[-1].wires, (9,))

    def test_identity_commits_order_context_and_catalogue(self):
        pr, _ = multiplication_trace('pallas_base', 1, 2)
        spec = GraphSpec.from_program(pr)
        for field, value in [('words', spec.words[::-1]), ('leaves', spec.leaves[::-1]),
                             ('context', '01'*32), ('field_role', 'vesta_scalar')]:
            self.assertNotEqual(spec.digest(), dataclasses.replace(spec, **{field: value}).digest())
        other, _ = multiplication_trace('pallas_base', P-1, P-2)
        self.assertEqual(spec.digest(), GraphSpec.from_program(other).digest())


if __name__ == '__main__':
    unittest.main()
