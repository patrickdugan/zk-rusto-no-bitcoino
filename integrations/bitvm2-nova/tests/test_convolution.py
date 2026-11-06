"""Independent integer and Script checks for the opt-in multiplication graph.

These do not execute upstream Rust or measure a WOTS/transaction footprint.
"""
from hashlib import sha256
import random
import unittest

from convolution import (AB_BOUND, CARRY_BOUND, CARRY_OFFSET, KINDS,
    ConvolutionTraceBuilder, compile_convolution_predicate, convolution_native,
    multiplication_trace)
from script import BASE, OPS, P, Q, execute, num
from trace import multiplication_trace as horner_trace


class ByteConvolution(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.honest = {}
        for role, p in (('pallas_base', P), ('vesta_base', Q)):
            cls.honest[role] = multiplication_trace(role, p-19, p-73,
                context=sha256(b'convolution-independent-tests').digest())

    def test_complete_integer_and_script_graphs_in_both_fields(self):
        for role, (program, values) in self.honest.items():
            self.assertEqual((len(program.words), len(program.constraints), len(program.fields)),
                             (634, 486, 3), role)
            self.assertEqual(set(c.kind for c in program.constraints), KINDS | {'const'})
            bound = program.bind(values)
            self.assertEqual(bound.failures(), ())
            for ordinal, constraint in enumerate(program.constraints):
                with self.subTest(role=role, ordinal=ordinal, kind=constraint.kind):
                    correct = bound.execute(ordinal, disprove=False)
                    self.assertTrue(correct.success, correct.error)
                    self.assertLessEqual(correct.peak_stack, 1000)
                    self.assertFalse(bound.execute(ordinal).success)

    def test_topology_does_not_depend_on_witness_and_original_horner_stays_exact(self):
        for role, p in (('pallas_base', P), ('vesta_base', Q)):
            baseline, baseline_values = horner_trace(role, p-19, p-73)
            self.assertEqual((len(baseline.words), len(baseline.constraints)), (2586, 274))
            self.assertTrue(all(c.native(baseline_values, p) for c in baseline.constraints))
            reference, _ = self.honest[role]
            for a, b in ((0, 0), (1, p-1), (p-1, p-1), (1 << 254, 1 << 128)):
                candidate, values = multiplication_trace(role, a, b, context=reference.context)
                self.assertEqual(candidate.digest(), reference.digest())
                self.assertTrue(all(c.native(values, p) for c in candidate.constraints))

    def test_integer_expected_products_and_coherent_false_claims(self):
        rng = random.Random(0x2562026)
        for role, p in (('pallas_base', P), ('vesta_base', Q)):
            pairs = [(0, 0), (0, p-1), (1, p-1), (p-1, p-1),
                     (p-19, p-73), (1 << 254, 1 << 254)]
            pairs += [(rng.randrange(p), rng.randrange(p)) for _ in range(6)]
            for a, b in pairs:
                correct = a*b % p
                for c, q, expected in ((correct, a*b//p, True),
                    ((correct+1) % p, a*b//p, False),
                    (correct, (a*b//p+1) % (1 << 256), False),
                    (correct, (1 << 256)-1, False)):
                    program, values = multiplication_trace(role, a, b, claimed_value=c, quotient=q)
                    failures = [i for i, constraint in enumerate(program.constraints)
                                if not constraint.native(values, p)]
                    self.assertEqual(not failures, expected, (role, a, b, c, q))
                    if not expected:
                        # All decompositions/products are coherently generated;
                        # only the integer columns/end anchor expose this claim.
                        self.assertTrue(all(program.constraints[i].kind in ('conv_column', 'const')
                                            for i in failures))
                        bound = program.bind(values)
                        for i in failures:
                            self.assertTrue(bound.execute(i).success, (i, program.constraints[i].kind))
            # q is explicitly an integer: the field modulus itself is admitted
            # as a quotient encoding, then refuted arithmetically for 0*0.
            program, values = multiplication_trace(role, 0, 0, quotient=p)
            self.assertTrue(program.bind(values).failures())

    def test_all_original_261_bits_are_tied_to_byte_reconstruction(self):
        for role, (program, values) in self.honest.items():
            for _, words in program.fields:
                for bit in range(261):
                    altered = dict(values)
                    word = words[bit//29]
                    altered[word] ^= 1 << (bit % 29)
                    constraints = [c for c in program.constraints
                        if c.kind == 'conv_reconstruct' and c.wires[0] == word]
                    self.assertEqual(len(constraints), 1)
                    constraint = constraints[0]
                    self.assertFalse(constraint.native(altered, program.p), (role, word, bit))
                    body = compile_convolution_predicate(program.p, constraint.kind, constraint.argument)
                    self.assertTrue(execute(body+bytes([OPS['NOT']]),
                        [num(altered[w]) for w in constraint.wires]).success)

    def test_crossing_bytes_quotient_bytes_and_carry_anchors_cannot_float(self):
        for role, (program, values) in self.honest.items():
            cases = []
            for word in values:
                if '/split/' in word or '/q/' in word:
                    altered = dict(values)
                    bound = dict(program.words)[word]
                    altered[word] = (altered[word]+1) % bound
                    cases.append((word, altered))
            for endpoint in ('product/carry/0', 'product/carry/64'):
                altered = dict(values)
                altered[endpoint] += 1
                failures = [c for c in program.constraints if not c.native(altered, program.p)]
                self.assertTrue(any(c.kind == 'const' for c in failures))
                self.assertTrue(any(c.kind == 'conv_column' for c in failures))
                cases.append((endpoint, altered))
            for word, altered in cases:
                self.assertTrue(any(not c.native(altered, program.p) for c in program.constraints),
                                (role, word))
            for i in range(65):
                self.assertLess(abs(values[f'product/carry/{i}']-CARRY_OFFSET), CARRY_OFFSET)

    def test_coherent_false_product_needs_initial_carry_anchor(self):
        for role, p in (('pallas_base', P), ('vesta_base', Q)):
            program, values = multiplication_trace(role, 1, 1, claimed_value=2, quotient=0)
            values['product/carry/0'] = CARRY_OFFSET+1
            for i in range(1, 65):
                values[f'product/carry/{i}'] = CARRY_OFFSET
            failures = [c for c in program.constraints if not c.native(values, p)]
            self.assertEqual([(c.kind, c.wires) for c in failures],
                             [('const', ('product/carry/0',))])
            self.assertTrue(program.bind(values).execute(program.constraints.index(failures[0])).success)

    def test_byte_product_predicates_against_plain_integer_expectations(self):
        values = (0, 1, 127, 128, 254, 255)
        for count in range(1, 5):
            body = compile_convolution_predicate(P, 'conv_ab', (count,))
            for left in values:
                for right in values:
                    operands = [left, right]*count+[count*left*right]
                    self.assertTrue(execute(body, [num(x) for x in operands]).success)
                    operands[-1] = (operands[-1]+1) % AB_BOUND
                    self.assertTrue(execute(body+bytes([OPS['NOT']]),
                                            [num(x) for x in operands]).success)
            malformed = [0, 256]*count+[0]
            self.assertFalse(execute(body, [num(x) for x in malformed]).success)

    def test_formal_aliases_are_preserved_and_all_witness_length_failures_reject(self):
        builder = ConvolutionTraceBuilder('pallas_base', 'convolution/square', bytes(32))
        x = builder.field('x', P-1)
        builder.mul('square', x, x)
        program, values = builder.finish()
        self.assertTrue(all(c.native(values, P) for c in program.constraints))
        bound = program.bind(values)
        representatives = {}
        for i, constraint in enumerate(program.constraints):
            representatives.setdefault(constraint.kind, i)
        alias = next(i for i, c in enumerate(program.constraints)
                     if c.kind == 'conv_ab' and len(set(c.wires)) < len(c.wires))
        self.assertTrue(bound.execute(alias, disprove=False).success)
        for i in tuple(representatives.values())+(alias,):
            code, witness = bound.script(i, disprove=False), bound.witness(i)
            for malformed in ((), witness[:-1], (b'',)+witness, witness+(b'',)):
                self.assertFalse(execute(code, malformed).success, (i, len(malformed)))
            altered = list(witness)
            altered[0] = num(1 if altered[0] != num(1) else 0)
            self.assertFalse(execute(code, altered).success)
        different_context, _ = multiplication_trace('pallas_base', P-19, P-73,
                                                     context=b'c'*32)
        with self.assertRaises(ValueError):
            bound.require_identity(different_context.digest(), bound.claim_digest)
        with self.assertRaises(ValueError):
            bound.script(0, compiler='m2')

    def test_public_shapes_and_numeric_operand_bounds_fail_closed(self):
        for kind, argument in (('conv_split', (0,)), ('conv_split', (8,)),
                ('conv_ab', (True,)), ('conv_ab', (5,)), ('conv_pq', (0,)),
                ('conv_reconstruct', (8,)*4), ('conv_column', (9, 0, 0)),
                ('conv_column', (0, 5, 0)), ('conv_column', (0, 0, True))):
            with self.assertRaises(ValueError):
                compile_convolution_predicate(P, kind, argument)
        self.assertFalse(convolution_native(P, 'conv_split', (5,), [True, 0, 0]))
        builder = ConvolutionTraceBuilder('pallas_base', 'invalid-bound', bytes(32))
        byte = builder.small('byte', 1, 2)  # A Boolean wire is not a byte wire.
        low = builder.small('lo', 1, 32)
        high = builder.small('hi', 0, 8)
        with self.assertRaisesRegex(ValueError, 'bounds'):
            builder.check('conv_split', (byte, low, high), (5,))
        # Even maximal declared (dishonest) block/carry words keep every
        # column intermediate below2^23 and every ScriptNum below2^31.
        left = 8*((1 << 18)-1)+(CARRY_BOUND-1)+255*CARRY_OFFSET
        right = 4*((1 << 19)-1)+256*(CARRY_BOUND-1)+255
        self.assertLess(max(left, right), 1 << 23)
        self.assertLess(BASE-1, 1 << 31)


if __name__ == '__main__':
    unittest.main()
