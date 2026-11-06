"""Closed canonicality attack; local checks are tiny integer arithmetic only."""
from hashlib import sha256
import os
import sys
import unittest

from trace import ROLES
from uniform_alias import alias_values

CONTEXT = sha256(b'closed-scalar-alias-tests/verifier-context').digest()
RAW = (
    ('pallas_scalar', '9a62ebb9a5aafea68609962656cd7aa854914ae0ccb073f9ee05519f76a8539e4'
                      '5b5dd1b36e98d75dee609c1233ad184b6c5a0e1633a768e378f987f5235e474'),
    ('vesta_scalar', 'ecc38c27f4712a179aa55bc3c0df663651be906a1fc47eaeff9eab8d5f2fa5be'
                     '1c33641f687de1bbd723d7c203d020ad709914e4c52c0e3f005b221cd236e8df'))


def _hosted():
    return (os.environ.get('GITHUB_ACTIONS') == 'true'
            and os.environ.get('RUNNER_OS') == 'Linux' and sys.platform == 'linux'
            and os.environ.get('BITVM2_NOVA_BIT_POINT_TESTS') == '1')


class ClosedScalarAliasPureTests(unittest.TestCase):
    def test_retained_alias_preserves_every_integer_column_and_flips_selected_bit(self):
        for role, encoded in RAW:
            raw = bytes.fromhex(encoded)
            result, quotient = alias_values(raw, role=role)
            modulus = ROLES[role]
            value = int.from_bytes(raw, 'little')
            self.assertEqual(value, result+modulus*quotient)
            self.assertNotEqual(result & 1, (value % modulus) & 1)
            self.assertTrue(modulus <= result < 1 << 255)
            p, q, c = modulus.to_bytes(32, 'little'), quotient.to_bytes(33, 'little'), result.to_bytes(32, 'little')
            carry = 0
            for column in range(65):
                x = raw[column] if column < 64 else 0
                output = c[column] if column < 32 else 0
                pq = sum(coefficient*q[column-i] for i, coefficient in enumerate(p)
                         if 0 <= column-i < 33)
                carry, remainder = divmod(x+carry-output-pq, 256)
                self.assertEqual(remainder, 0)
                self.assertTrue(-(sum(p)+1) <= carry <= 0)
            self.assertEqual(carry, 0)

    def test_alias_is_closed_to_exact_unsigned_input_and_scalar_role(self):
        for raw, role in ((bytes(64), 'pallas_scalar'), (bytes(63), 'pallas_scalar'),
                          (bytes(65), 'pallas_scalar'), (bytearray(64), 'pallas_scalar'),
                          (None, 'pallas_scalar'), (bytes(64), 'pallas_base'),
                          (bytes(64), True)):
            with self.assertRaises(ValueError):
                alias_values(raw, role=role)


@unittest.skipUnless(_hosted(), 'dedicated GHA Linux BITVM2_NOVA_BIT_POINT_TESTS=1 required')
class HostedClosedScalarAliasTests(unittest.TestCase):
    def test_fresh_original_and_merged_sources_retain_only_canonicality_failure(self):
        from script import OPS, execute, num
        from uniform_alias import build_scalar_alias, build_uniform_alias
        from uniform_reduce import build_uniform_reduction
        from wots_graph import GraphSpec

        for role, encoded in RAW:
            raw = bytes.fromhex(encoded)
            operation = 'tests/closed-scalar-alias'
            positive = build_uniform_reduction(raw, context=CONTEXT, role=role,
                                               operation_id=operation)
            alias = build_uniform_alias(raw, context=CONTEXT, role=role,
                                        operation_id=operation)
            self.assertEqual(alias.program.digest(), positive.program.digest())
            self.assertEqual(alias.spec, GraphSpec.from_program(positive.program))
            self.assertEqual(alias.metadata, positive.metadata)
            self.assertEqual(dict(alias.ports), dict(positive.ports))
            merged = build_scalar_alias(raw, context=CONTEXT, role=role, bit_index=0,
                                         operation_id=operation)
            self.assertEqual(merged.source_maps['uniform_leaf_map'], list(range(244))+[253])
            self.assertEqual(merged.source_maps['bits_leaf_map'], list(range(244, 253)))
            self.assertEqual(len(merged.program.words), 634)
            self.assertEqual(merged.field_valid_ordinal, 253)
            self.assertEqual(merged.assignment[merged.ports['selected_bit']], alias.result_value & 1)
            for probe, ordinal in ((alias, 244), (merged, 253)):
                values = probe.assignment
                self.assertTrue(all(c.native(values, probe.program.p) for c in probe.program.constraints))
                self.assertEqual(probe.spec.field_leaves, (('result', ordinal),))
                leaf = probe.spec.leaves[ordinal]
                encoded_result = sum(values[probe.spec.words[word][0]] << (29*i)
                                     for i, word in enumerate(leaf.wires))
                self.assertEqual(encoded_result, alias.result_value)
                self.assertGreaterEqual(encoded_result, probe.program.p)
                body = bytes.fromhex(dict(probe.spec.bodies)[leaf.body_sha256])
                witness = tuple(num(values[probe.spec.words[word][0]]) for word in leaf.wires)
                correct = execute(body, witness)
                disproof = execute(body+bytes([OPS['NOT']]), witness)
                self.assertFalse(correct.success)
                self.assertIsNone(correct.error)
                self.assertTrue(disproof.success)
                self.assertIsNone(disproof.error)
                with self.assertRaises(ValueError):
                    probe.program.bind(values)
            del positive, alias, merged


if __name__ == '__main__':
    unittest.main()
