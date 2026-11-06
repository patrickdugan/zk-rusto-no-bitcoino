"""Pure naming/guard checks and hosted legacy-prefix BYTE baseline tests.

Local tests never construct a Boolean round, bridge Program, WOTS key or Script.
The complete factory class runs only under its real hosted Linux guard.
"""
from dataclasses import FrozenInstanceError
from hashlib import sha256
import json
import os
import sys
import unittest
from unittest.mock import patch


def _hosted():
    return (os.environ.get('GITHUB_ACTIONS') == 'true'
        and os.environ.get('RUNNER_OS') == 'Linux' and sys.platform == 'linux')


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


class BooleanByteBaselinePureTests(unittest.TestCase):
    def test_every_byte_and_bit_name_has_the_expected_lane_little_endian_order(self):
        import byte_keccak_baseline as module
        for stage in ('input', 'output'):
            ports = module.byte_port_names(stage)
            self.assertEqual(len(ports), 200)
            self.assertEqual(len(set(ports)), 200)
            bits = []
            for index, port in enumerate(ports):
                lane, byte = divmod(index, 8)
                self.assertEqual(port, f'{stage}/l{lane}/byte{byte}')
                expected = tuple(f'boolean/{stage}/l{lane}/b{8*byte+bit}' for bit in range(8))
                self.assertEqual(module.byte_bit_names(stage, lane, byte), expected)
                bits.extend(expected)
            self.assertEqual(len(set(bits)), 1600)

    def test_global_names_are_injective_byte_states_and_private_boolean_names(self):
        import byte_keccak_baseline as module
        for r in (0, 23):
            left = tuple(module.baseline_global_id(r, name) for name in module.byte_port_names('input'))
            right = tuple(module.baseline_global_id(r, name) for name in module.byte_port_names('output'))
            self.assertEqual(left[0], f'byte-state/{r}/l0/byte0')
            self.assertEqual(right[-1], f'byte-state/{r+1}/l24/byte7')
            self.assertEqual(len(set(left+right)), 400)
            self.assertEqual(module.baseline_global_id(r, 'boolean/input/l0/b0'),
                             f'boolean-round/{r}/boolean/input/l0/b0')
        for value in (True, -1, 24, 1.0):
            with self.assertRaises(ValueError): module.baseline_global_id(value, 'input/l0/byte0')
        for name in ('input/l00/byte0', 'input/l25/byte0', 'input/l0/byte00',
                     'output/l0/byte8', '', None, 'a b', 'x'*193):
            with self.assertRaises(ValueError): module.baseline_global_id(0, name)
        for args in ((True, 0, 0), ('input', True, 0), ('input', 0, True),
                     ('other', 0, 0), ('input', -1, 0), ('input', 25, 0), ('input', 0, 8)):
            with self.assertRaises(ValueError): module.byte_port_name(*args)

    def test_guard_precedes_children_and_external_authority_has_no_constructor(self):
        import byte_keccak_baseline as module
        for github, runner, platform in (('false', 'Linux', 'linux'),
                ('true', 'Windows', 'linux'), ('true', 'Linux', 'win32')):
            with patch.dict(os.environ, {'GITHUB_ACTIONS': github, 'RUNNER_OS': runner}, clear=True), \
                    patch.object(module.sys, 'platform', platform), \
                    patch.object(module, 'keccak_round_trace', side_effect=AssertionError('allocated')) as child, \
                    patch.object(module, 'ConvolutionTraceBuilder', side_effect=AssertionError('allocated')) as bridge:
                with self.assertRaisesRegex(ValueError, 'hosted GitHub Linux'):
                    module.build_boolean_byte_round(None, context=None)
                empty = object.__new__(module.BooleanByteRound)
                with self.assertRaisesRegex(ValueError, 'hosted GitHub Linux'):
                    empty.bind(None)
                with self.assertRaisesRegex(ValueError, 'hosted GitHub Linux'):
                    module._construct(None, None, None, None, None)
                child.assert_not_called(); bridge.assert_not_called()
        for cls in (module.BooleanByteRound, module.BooleanByteRoundBinding):
            with self.assertRaises(TypeError): cls()
            self.assertFalse(hasattr(cls, 'from_json'))
        for key in ('program', 'spec', 'source_maps', 'receipt', 'child', 'word_map'):
            with self.assertRaises(TypeError): module.build_boolean_byte_round(0, context=bytes(32), **{key: {}})


@unittest.skipUnless(_hosted(), 'real Boolean BYTE baseline graphs are hosted GitHub Linux only')
class HostedBooleanByteBaselineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not _hosted(): raise unittest.SkipTest('host guard before actual baseline allocation')
        import byte_keccak_baseline as module
        cls.module = module
        cls.context = sha256(b'independent-boolean-byte-round-baseline-test').digest()
        cls.operation = 'tests/boolean-byte-round'
        cls.plan = module.build_boolean_byte_round(0, context=cls.context,
            role='pallas_scalar', operation_id=cls.operation)
        cls.raw = bytes((37*i+11) & 255 for i in range(200))
        cls.binding = cls.plan.bind(cls.raw)

    def test_old_boolean_words_leaves_bodies_zero_and_output_copies_are_exact_prefix(self):
        from keccak_trace import keccak_round_trace, state_from_bytes
        from wots_graph import GraphSpec
        program, values = keccak_round_trace(state_from_bytes(self.raw), 0,
            context=self.context, role='pallas_scalar', operation_id=self.operation+'/boolean',
            input_prefix='boolean/input', output_prefix='boolean/output')
        old = GraphSpec.from_program(program)
        spec, maps = self.plan.spec, self.plan.source_maps
        self.assertEqual((len(spec.words), len(spec.leaves)), (12002, 10402))
        self.assertEqual(spec.words[:len(old.words)], old.words)
        self.assertEqual(spec.leaves[:len(old.leaves)], old.leaves)
        for key, encoded in old.bodies: self.assertEqual(dict(spec.bodies)[key], encoded)
        self.assertEqual(maps['children'][0]['word_map'], list(range(len(old.words))))
        self.assertEqual(maps['children'][0]['leaf_map'], list(range(len(old.leaves))))
        self.assertEqual(maps['children'][0]['program_sha256'], program.digest().hex())
        self.assertEqual(maps['children'][0]['catalogue_id'], old.digest().hex())
        self.assertEqual(old.leaves[maps['old_zero_anchor_ordinal']].kind, 'const')
        self.assertEqual(old.leaves[maps['old_zero_anchor_ordinal']].argument, (0,))
        self.assertEqual(len(old.leaves)-maps['old_output_copy_start'], 1600)
        self.assertTrue(all(leaf.kind == 'bool_xor' for leaf in old.leaves[-1600:]))
        for name in values: self.assertEqual(self.binding.assignment[name], values[name])

    def test_all400_byte_bridge_maps_and_200_output_sources_are_ordered_and_complete(self):
        from script import BASE
        spec, maps, values = self.plan.spec, self.plan.source_maps, self.binding.assignment
        self.assertEqual(len(maps['bridges']), 400)
        self.assertEqual(len(set(self.plan.global_ids)), len(spec.words))
        old_count = maps['old_output_copy_start']+1600
        for i, row in enumerate(maps['bridges']):
            stage = 'input' if i < 200 else 'output'
            position = i % 200
            lane, byte = divmod(position, 8)
            self.assertEqual((row['stage'], row['position']), (stage, position))
            bit_names = [f'boolean/{stage}/l{lane}/b{8*byte+bit}' for bit in range(8)]
            self.assertEqual([spec.words[index][0] for index in row['bit_indices']], bit_names)
            self.assertEqual(spec.words[row['byte_index']], (f'{stage}/l{lane}/byte{byte}', 256))
            self.assertEqual(spec.words[row['auxiliary_index']][1], BASE)
            self.assertEqual((row['bit_ordinal'], row['byte_ordinal']), (old_count+2*i, old_count+2*i+1))
            a, b = spec.leaves[row['bit_ordinal']], spec.leaves[row['byte_ordinal']]
            self.assertEqual((a.kind, a.argument, a.wires), ('bits', (8,),
                (row['auxiliary_index'],)+tuple(reversed(row['bit_indices']))))
            self.assertEqual((b.kind, b.argument, b.wires), ('conv_reconstruct', (8,),
                (row['auxiliary_index'], row['byte_index'])))
            expected = self.raw[position] if stage == 'input' else self.binding.output_state[position]
            self.assertEqual(values[spec.words[row['byte_index']][0]], expected)
            self.assertEqual(values[spec.words[row['auxiliary_index']][0]], expected)
        self.assertEqual(self.plan.producer_occurrences, (1,)*200)
        for i, ordinal in enumerate(self.plan.producer_ordinals):
            self.assertEqual(ordinal, old_count+401+2*i)
            self.assertEqual(spec.leaves[ordinal].wires[1], self.plan.output_indices[i])

    def test_identity_snapshots_and_binding_are_value_independent_and_sealed(self):
        from keccak_trace import keccak_f1600_round, state_from_bytes, state_to_bytes
        plan, binding = self.plan, self.binding
        self.assertEqual(binding.reference_output,
            state_to_bytes(keccak_f1600_round(state_from_bytes(self.raw), 0)))
        self.assertEqual(binding.reference_output, binding.output_state)
        other = plan.bind(bytes(200))
        self.assertEqual(other.spec.digest(), binding.spec.digest())
        self.assertEqual(other.source_sha256, binding.source_sha256)
        with self.assertRaises(FrozenInstanceError): plan.round_index = 1
        maps = plan.source_maps; maps['input_indices'][0] = -1
        self.assertNotEqual(maps, plan.source_maps)
        values = binding.assignment; values[plan.inputs[0]] ^= 1
        self.assertNotEqual(values, binding.assignment)
        manifest = plan.manifest
        self.assertEqual(plan.spec.program_sha256,
            sha256(self.module.PROGRAM_DOMAIN+_canonical(manifest)).hexdigest())
        source = dict(manifest=manifest, program_sha256=plan.spec.program_sha256,
                      catalogue_id=plan.spec.digest().hex())
        self.assertEqual(plan.source_sha256, sha256(self.module.SOURCE_DOMAIN+_canonical(source)).digest())
        for flag in ('full_hash_verified', 'full_permutation_verified', 'proof_verified',
                     'bitvm2_script_verified', 'production_assertion_binding', 'bitcoin_transaction_graph'):
            self.assertIs(binding.summary()[flag], False)

    def test_claimed_byte_changes_old_bit_producer_only_with_all_bridges_coherent(self):
        raw_output = bytearray(self.binding.output_state); raw_output[0] ^= 1
        changed = self.plan.bind(self.raw, claimed_output=bytes(raw_output))
        self.assertEqual(changed.spec.digest(), self.plan.spec.digest())
        values, spec = changed.assignment, changed.spec
        false = []
        for ordinal, leaf in enumerate(spec.leaves):
            v = [values[spec.words[index][0]] for index in leaf.wires]
            if leaf.kind == 'bool_xor': good = v[2] == (v[0] ^ v[1])
            elif leaf.kind == 'bool_and': good = v[2] == (v[0] & v[1])
            elif leaf.kind == 'bool_not': good = v[1] == 1-v[0]
            elif leaf.kind == 'const': good = v[0] == leaf.argument[0]
            elif leaf.kind == 'bits': good = v[0] == sum(bit << n for n, bit in enumerate(reversed(v[1:])))
            elif leaf.kind == 'conv_reconstruct': good = v[0] == v[1]
            else: self.fail('unexpected baseline predicate')
            if not good: false.append(ordinal)
        self.assertEqual(false, [self.plan.source_maps['old_output_copy_start']])
        self.assertEqual(changed.output_state, bytes(raw_output))
        self.assertFalse(changed.summary()['reference_output_matches'])

    def test_typed_parameters_roles_lengths_and_derived_identity_changes(self):
        for bad in (True, -1, 24, 1.0):
            with self.assertRaises(ValueError): self.module.build_boolean_byte_round(bad, context=self.context)
        for raw in (None, bytearray(200), bytes(199), bytes(201)):
            with self.assertRaises(ValueError): self.plan.bind(raw)
        for raw in (bytearray(200), bytes(199), bytes(201)):
            with self.assertRaises(ValueError): self.plan.bind(self.raw, claimed_output=raw)
        for role, context, operation in (('vesta_scalar', self.context, self.operation),
                ('pallas_scalar', bytes([1])*32, self.operation),
                ('pallas_scalar', self.context, self.operation+'/other')):
            other = self.module.build_boolean_byte_round(0, context=context, role=role, operation_id=operation)
            self.assertNotEqual(other.spec.digest(), self.plan.spec.digest())
            self.assertNotEqual(other.source_sha256, self.plan.source_sha256)


if __name__ == '__main__':
    unittest.main()
