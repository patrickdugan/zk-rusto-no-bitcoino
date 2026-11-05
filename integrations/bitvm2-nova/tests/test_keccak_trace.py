"""Tiny native/oracle and selected Script checks; never build a whole-hash graph."""
import dataclasses
import hashlib
import itertools
import unittest

from Cryptodome.Hash import keccak
from keccak_trace import (MASK64, RATE_BYTES, ROUND_CONSTANTS, keccak256_padded,
                          keccak256_reference, keccak_f1600_round, keccak_round_trace,
                          rol64, state_from_bit_wires, state_from_bytes,
                          state_to_bytes, state_wire_names)
from script import P, execute, num
from trace_kernels import compile_predicate


class KeccakReference(unittest.TestCase):
    def test_known_keccak_hashes_and_mature_oracle(self):
        known = {b'': 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470',
                 b'abc': '4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45'}
        for message, digest in known.items():
            self.assertEqual(keccak256_reference(message).hex(), digest)
            self.assertNotEqual(keccak256_reference(message), hashlib.sha3_256(message).digest())
        for n in (0, 1, 31, 32, 63, 64, 134, 135, 136, 137, 255, 270, 271, 272, 273, 4096):
            message = bytes((i*73+19) % 256 for i in range(n))
            self.assertEqual(keccak256_reference(message),
                             keccak.new(digest_bits=256, data=message).digest(), n)

    def test_keccak_padding_boundaries(self):
        for n in (0, 1, 134, 135, 136, 137, 270, 271, 272):
            message = bytes([0xa5])*n
            padded = keccak256_padded(message)
            self.assertEqual(len(padded), RATE_BYTES*(n//RATE_BYTES+1))
            self.assertEqual(padded[:n], message)
            self.assertEqual(padded[n], 0x81 if n % RATE_BYTES == 135 else 0x01)
            self.assertEqual(padded[-1] & 0x80, 0x80)
            if n % RATE_BYTES != 135:
                self.assertEqual(padded[-1], 0x80)
                self.assertEqual(set(padded[n+1:-1]), {0} if len(padded[n+1:-1]) else set())

    def test_official_xkcp_intermediate_zero_vectors(self):
        # XKCP pinned intermediate values: all-zero state after rounds 0 and 1.
        first = (1,) + (0,)*24
        self.assertEqual(keccak_f1600_round((0,)*25, 0), first)
        second = tuple(int(v, 16) for v in '''
            0000000000008083 0000100000000000 0000000000008000 0000000000000001 0000100000008000
            0000000000000000 0000200000200000 0000000000000000 0000200000000000 0000000000200000
            0000000000000002 0000000000000200 0000000000000000 0000000000000202 0000000000000000
            0000000010000400 0000000000000000 0000000000000400 0000000010000000 0000000000000000
            0000010000000000 0000000000000000 0000010000000004 0000000000000000 0000000000000004
        '''.split())
        self.assertEqual(keccak_f1600_round(first, 1), second)

    def test_endian_lane_and_rotation_boundaries(self):
        raw = bytes(range(200))
        lanes = state_from_bytes(raw)
        self.assertEqual(lanes[0], 0x0706050403020100)
        self.assertEqual(lanes[24], 0xc7c6c5c4c3c2c1c0)
        self.assertEqual(state_to_bytes(lanes), raw)
        self.assertEqual(rol64(1 << 63, 1), 1)
        self.assertEqual(rol64(1, 63), 1 << 63)
        self.assertEqual(rol64(0x123456789abcdef0, 0), 0x123456789abcdef0)
        names = state_wire_names('boundary')
        self.assertEqual((names[0], names[63], names[64], names[-1]),
                         ('boundary/l0/b0', 'boundary/l0/b63', 'boundary/l1/b0', 'boundary/l24/b63'))
        assignment = {name: 0 for name in names}
        for i in (0, 63, 64, 1599):
            assignment[names[i]] = 1
        self.assertEqual(state_from_bit_wires(assignment, 'boundary'),
                         (1+(1 << 63), 1) + (0,)*22 + (1 << 63,))

    def test_reference_admission_bounds(self):
        for state in ((0,)*24, (0,)*26, (0,)*24+(True,), (0,)*24+(-1,), (0,)*24+(1 << 64,)):
            with self.assertRaises(ValueError):
                keccak_f1600_round(state, 0)
        for r in (-1, 24, True, 0.0):
            with self.assertRaises(ValueError):
                keccak_f1600_round((0,)*25, r)
        for message in (bytearray(), 'abc', bytes(4097)):
            with self.assertRaises(ValueError):
                keccak256_reference(message)
        for data in (bytes(199), bytes(201), bytearray(200)):
            with self.assertRaises(ValueError):
                state_from_bytes(data)
        for value, shift in ((-1, 0), (1 << 64, 0), (1, -1), (1, 64), (True, 0), (1, True)):
            with self.assertRaises(ValueError):
                rol64(value, shift)


class KeccakBooleanRound(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.state = tuple((i*0x0123456789abcdef ^ (1 << (i % 64))) & MASK64 for i in range(25))
        cls.program, cls.values = keccak_round_trace(cls.state, 23,
            context=hashlib.sha256(b'keccak-one-round-test').digest(), operation_id='test/keccak',
            input_prefix='state/before', output_prefix='state/after')
        cls.bound = cls.program.bind(cls.values)

    def selected_ordinals(self):
        prefixes = ('keccak/r23/c/', 'keccak/r23/d/', 'keccak/r23/t/',
                    'keccak/r23/chi/n/', 'keccak/r23/chi/a/', 'keccak/r23/chi/x/',
                    'keccak/r23/iota/', 'keccak/r23/zero', 'state/after/')
        return tuple(next(i for i, c in enumerate(self.program.constraints)
                          if c.wires[-1].startswith(prefix)) for prefix in prefixes) + (
                              len(self.program.constraints)-1,)

    def test_entire_native_round_and_typed_boundaries(self):
        p, v = self.program, self.values
        self.assertFalse(self.bound.failures())
        self.assertEqual(state_from_bit_wires(v, 'state/before'), self.state)
        self.assertEqual(state_from_bit_wires(v, 'state/after'), keccak_f1600_round(self.state, 23))
        flips = ROUND_CONSTANTS[23].bit_count()
        self.assertEqual((len(p.words), len(p.constraints)), (11201+flips, 9601+flips))
        self.assertTrue(all(bound == 2 for _, bound in p.words))
        self.assertEqual(p.fields, ())
        self.assertEqual(p.operation_id, 'test/keccak/round/23')
        self.assertEqual(set(state_wire_names('state/after')), set(v).intersection(state_wire_names('state/after')))

    def test_selected_script_leaves_and_bad_intermediate_bits(self):
        for i in self.selected_ordinals():
            with self.subTest(ordinal=i):
                self.assertTrue(self.bound.execute(i, disprove=False).success)
                self.assertFalse(self.bound.execute(i).success)
                changed = dict(self.values)
                changed[self.program.constraints[i].wires[-1]] ^= 1
                bad = self.program.bind(changed)
                self.assertIn(i, bad.failures())
                self.assertTrue(bad.execute(i).success)
                self.assertFalse(bad.execute(i, disprove=False).success)

    def test_opening_binding_and_exact_witness_lengths(self):
        for i in self.selected_ordinals():
            ws = self.bound.witness(i)
            for disprove in (False, True):
                code = self.bound.script(i, disprove=disprove)
                for bad in ((), ws[:-1], (b'',)+ws, ws+(b'',)):
                    result = execute(code, bad)
                    self.assertFalse(result.success)
                    self.assertEqual(result.error, 'EQUALVERIFY')
                for j in range(len(ws)):
                    bad = list(ws)
                    bad[j] = b'\x01' if ws[j] == b'' else b''
                    result = execute(code, bad)
                    self.assertFalse(result.success)
                    self.assertEqual(result.error, 'EQUALVERIFY')

    def test_context_role_operation_round_and_boundary_names_bind_identity(self):
        original = self.bound
        for changes in ({'context': bytes(32)}, {'field_role': 'vesta_scalar'},
                        {'operation_id': 'test/keccak/round/22'}):
            changed = dataclasses.replace(self.program, **changes).bind(self.values)
            self.assertNotEqual(original.program_digest, changed.program_digest)
            self.assertNotEqual(original.script(0), changed.script(0))
            with self.assertRaises(ValueError):
                changed.require_identity(original.program_digest, original.claim_digest)
        renamed = dataclasses.replace(self.program, words=tuple(
            (w.replace('state/before', 'different/before'), b) for w, b in self.program.words))
        self.assertNotEqual(renamed.digest(), self.program.digest())

    def test_non_boolean_assignment_is_rejected(self):
        wire = state_wire_names('state/before')[0]
        for value in (-1, 2, True):
            bad = dict(self.values)
            bad[wire] = value
            with self.assertRaises(ValueError):
                self.program.bind(bad)

    def test_selected_input_bits_cannot_change_without_linked_constraints(self):
        for bit_index in (0, 63, 64, 5*64, 1599):
            bad = dict(self.values)
            bad[state_wire_names('state/before')[bit_index]] ^= 1
            bound = self.program.bind(bad)
            failures = bound.failures()
            self.assertTrue(failures, bit_index)
            self.assertTrue(bound.execute(failures[0]).success)
            self.assertNotEqual(bound.claim_digest, self.bound.claim_digest)
            self.assertEqual(bound.program_digest, self.bound.program_digest)

    def test_claimed_wrong_output_is_disprovable(self):
        # Round zero is separately exercised through the bit compiler. The
        # changed output remains admissible, so it needs an actual disproof.
        expected = list(keccak_f1600_round((0,)*25, 0))
        expected[24] ^= 1 << 63
        p, v = keccak_round_trace((0,)*25, 0, context=bytes(32), claimed_output=expected)
        b = p.bind(v)
        self.assertEqual(b.failures(), (len(p.constraints)-1,))
        self.assertTrue(b.execute(len(p.constraints)-1).success)
        self.assertEqual(state_from_bit_wires(v, 'keccak/out'), tuple(expected))

    def test_compiler_is_bounded_and_boundary_names_cannot_alias(self):
        for args in ({'input_prefix': 'same', 'output_prefix': 'same'},
                     {'input_prefix': 'bad space'}, {'operation_id': 'x'*192},
                     {'context': b''}, {'claimed_output': (0,)*24}):
            options = {'context': bytes(32), **args}
            with self.assertRaises(ValueError):
                keccak_round_trace((0,)*25, 0, **options)

    def test_boolean_truth_tables_and_malformed_encodings(self):
        for kind in ('bool_xor', 'bool_and', 'bool_not'):
            arity = 2 if kind == 'bool_not' else 3
            code = compile_predicate(P, kind)
            for values in itertools.product((0, 1), repeat=arity):
                expected = (values[1] == 1-values[0] if kind == 'bool_not'
                            else values[2] == (values[0] ^ values[1] if kind == 'bool_xor'
                                               else values[0] & values[1]))
                self.assertEqual(execute(code, tuple(num(v) for v in values)).success, expected,
                                 (kind, values))
            for bad in (num(-1), num(2), b'\x00', b'\x80', b'\x01\x00', bytes(5)):
                for i in range(arity):
                    ws = [num(0)] * arity
                    ws[i] = bad
                    self.assertFalse(execute(code, ws).success, (kind, bad.hex(), i))


if __name__ == '__main__':
    unittest.main()
