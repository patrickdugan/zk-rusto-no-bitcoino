"""Tiny local ID invariants; the 12 real pairs are strictly HOSTED ONLY.

Local cases use eight symbolic words and two state bits. They create no actual
round/pair graph, WOTS key, native process, table or proof. Hosted cases stream
one pair at a time; canonical global IDs describe intended shared wires, not a
production cross-registry signature/assertion binding.
"""
from dataclasses import FrozenInstanceError
from hashlib import sha256
import json
import os
import unittest
from unittest.mock import patch

import keccak_permutation as permutation
from keccak_permutation import (_global_id, _global_ids, _validate_global_ids,
                                _validate_join, _validate_totals, build_keccak_permutation)
from keccak_trace import (MASK64, keccak_f1600, keccak_f1600_round,
                           keccak256_padded, state_from_bytes, state_to_bytes)
from trace import MAX_CONSTRAINTS, MAX_WORDS
from wots_graph import MAX_GRAPH_LEAVES

CONTEXT = sha256(b'keccak-permutation-tests/external-context').digest()
ROLE, OPERATION = 'pallas_scalar', 'tests/keccak-permutation'
FALSE_FLAGS = ('full_permutation_verified', 'full_hash_verified', 'transcript_verified',
    'proof_verified', 'bitvm2_script_verified', 'production_assertion_binding',
    'bitcoin_transaction_graph')


def tiny_words():
    return (tuple((f'boundary/{kind}/l0/b{bit}', 2)
                  for kind in ('input', 'middle', 'output') for bit in range(2))
            +(('child/0/same-internal-name', 2), ('child/1/same-internal-name', 2)))


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')


def truth(spec, assignment, ordinal):
    leaf = spec.leaves[ordinal]
    values = [assignment[spec.words[index][0]] for index in leaf.wires]
    if any(type(value) is not int or not 0 <= value < spec.words[index][1]
           for value, index in zip(values, leaf.wires, strict=True)):
        return False
    if leaf.kind == 'bool_xor':
        return values[2] == values[0] ^ values[1]
    if leaf.kind == 'bool_and':
        return values[2] == values[0] & values[1]
    if leaf.kind == 'bool_not':
        return values[1] == 1-values[0]
    if leaf.kind == 'const':
        return values[0] == leaf.argument[0]
    if leaf.kind == 'word_valid':
        return True
    raise AssertionError('non-Boolean leaf in Keccak-only topology')


def output_state(item):
    binding = item.pair_binding
    values, spec = binding.assignment, binding.spec
    named = {global_id: values[spec.words[index][0]]
             for index, global_id in enumerate(item.global_ids)}
    state_index = 2*item.index+2
    return tuple(sum(named[f'state/{state_index}/l{lane}/b{bit}'] << bit for bit in range(64))
                 for lane in range(25))


class TinyPermutationGlobalIDs(unittest.TestCase):
    def test_canonical_state_round_ids_and_adjacent_sharing(self):
        self.assertEqual(_global_id(0, 'boundary/input/l0/b0'), 'state/0/l0/b0')
        self.assertEqual(_global_id(7, 'boundary/middle/l17/b31'), 'state/15/l17/b31')
        self.assertEqual(_global_id(11, 'boundary/output/l24/b63'), 'state/24/l24/b63')
        self.assertEqual(_global_id(7, 'child/0/same-internal-name'), 'round/14/same-internal-name')
        self.assertEqual(_global_id(7, 'child/1/same-internal-name'), 'round/15/same-internal-name')
        for pair in range(11):
            self.assertEqual(_global_id(pair, 'boundary/output/l0/b1'),
                             _global_id(pair+1, 'boundary/input/l0/b1'))
            self.assertNotEqual(_global_id(pair, 'child/1/same-internal-name'),
                                _global_id(pair+1, 'child/0/same-internal-name'))

    def test_tiny_maps_are_injective_ordered_and_nonadjacent_disjoint(self):
        words = tiny_words()
        left = tuple(_global_ids(0, words, port_count=2))
        right = tuple(_global_ids(1, words, port_count=2))
        later = tuple(_global_ids(2, words, port_count=2))
        for index, ids in enumerate((left, right, later)):
            self.assertEqual(len(ids), len(words))
            self.assertEqual(len(set(ids)), len(ids))
            _validate_global_ids(index, words, ids, port_count=2)
        expected = {f'state/2/l0/b{bit}' for bit in range(2)}
        self.assertEqual(set(left).intersection(right), expected)
        self.assertTrue(set(left).isdisjoint(later))
        _validate_join(left, right, state_index=2, port_count=2)
        with self.assertRaises(ValueError):
            _validate_join(left, later, state_index=2, port_count=2)
        reordered = list(left)
        reordered[0], reordered[1] = reordered[1], reordered[0]
        for invalid in (tuple(reordered), left[:-1], left[:-1]+(left[0],)):
            with self.assertRaises(ValueError):
                _validate_global_ids(0, words, invalid, port_count=2)

    def test_split_missing_and_unintended_join_aliases_reject(self):
        words = tiny_words()
        left = tuple(_global_ids(0, words, port_count=2))
        right = tuple(_global_ids(1, words, port_count=2))
        split = tuple('state/99/l0/b0' if item == 'state/2/l0/b0' else item for item in right)
        extra_alias = list(right)
        extra_alias[-1] = left[-1]  # Unrelated equal-spelling gate from another round.
        duplicate = right[:-1]+(right[0],)
        for invalid in (split, tuple(extra_alias), duplicate, right[1:]):
            with self.assertRaises(ValueError):
                _validate_join(left, invalid, state_index=2, port_count=2)

    def test_malformed_canonical_names_and_typed_limits_fail_closed(self):
        for index in (-1, 12, True, '0', None):
            with self.assertRaises((ValueError, TypeError)):
                _global_id(index, 'boundary/input/l0/b0')
        for name in ('boundary/input/l25/b0', 'boundary/input/l0/b64',
            'boundary/input/l01/b0', 'boundary/input/l0/b00', 'boundary/unknown/l0/b0',
            'child/2/gate', 'child/0/', 'other/gate', True):
            with self.assertRaises((ValueError, TypeError)):
                _global_id(0, name)
        words = tiny_words()
        for count in (0, -1, 1601, True, 2.0):
            with self.assertRaises((ValueError, TypeError)):
                _global_ids(0, words, port_count=count)
        with self.assertRaises(ValueError):
            _global_ids(0, words[:-1]+((words[-1][0], 4),), port_count=2)
        self.assertEqual((MAX_CONSTRAINTS, MAX_WORDS, MAX_GRAPH_LEAVES), (10000, 100000, 30000))

    def test_typed_whole_topology_budgets_reject_boolean_aliases_and_changed_counts(self):
        totals = dict(pairs=12, leaves=230510, pair_local_words=249710,
            unique_global_words=232110, inter_pair_joins=11, shared_join_bits=17600)
        _validate_totals(**totals)
        for field, value in totals.items():
            for replacement in (value+1, -1, True, float(value), None):
                changed = dict(totals)
                changed[field] = replacement
                with self.subTest(field=field, replacement=replacement), self.assertRaises(ValueError):
                    _validate_totals(**changed)

    def test_resource_guard_precedes_pairs_and_context_has_no_key_or_root_inputs(self):
        with patch.dict('os.environ', {'GITHUB_ACTIONS': 'false'}), \
             patch('keccak_permutation.build_keccak_pair', side_effect=AssertionError('real pair forbidden')) as pairs:
            with self.assertRaises(ValueError):
                build_keccak_permutation(context=CONTEXT, role=ROLE, operation_id=OPERATION)
            empty = object.__new__(permutation.KeccakPermutationPlan)
            with self.assertRaises(ValueError):
                empty.regenerate_pair(0)
            with self.assertRaises(ValueError):
                empty.iter_bindings((0,)*25)
            pairs.assert_not_called()
        for cls in (permutation.KeccakPermutationPlan, permutation.PairDescriptor,
                    permutation.PlannedPair, permutation.StreamedPairBinding):
            with self.assertRaises(TypeError):
                cls()
            self.assertFalse(hasattr(cls, 'from_json'))
        for keyword in ('pairs', 'descriptors', 'source_maps', 'receipt', 'registry_id',
                        'taproot_root', 'assertion_txid', 'output_key'):
            with self.assertRaises(TypeError):
                build_keccak_permutation(context=CONTEXT, role=ROLE, operation_id=OPERATION,
                                         **{keyword: {'passed': True}})
        with patch('keccak_permutation._hosted_guard'), \
             patch('keccak_permutation.build_keccak_pair', side_effect=AssertionError('real pair forbidden')) as pairs:
            for options in (dict(context=bytes(31)), dict(context=bytearray(32)),
                            dict(role='unsupported'), dict(operation_id='bad operation')):
                inputs = dict(context=CONTEXT, role=ROLE, operation_id=OPERATION)
                inputs.update(options)
                with self.assertRaises(ValueError):
                    build_keccak_permutation(**inputs)
            pairs.assert_not_called()


@unittest.skipUnless(os.environ.get('GITHUB_ACTIONS') == 'true',
                     'real 24-round topology/bindings are hosted only')
class HostedKeccakPermutation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.environ.get('GITHUB_ACTIONS') != 'true':
            raise unittest.SkipTest('real permutation is hosted only')
        cls.plan = build_keccak_permutation(context=CONTEXT, role=ROLE, operation_id=OPERATION)
        cls.initial = tuple((i*0x0123456789abcdef ^ (1 << (i % 64))) & MASK64 for i in range(25))

    def test_all_descriptors_streamed_maps_unique_values_and_word_reference(self):
        plan, previous, owners, last_output = self.plan, None, {}, None
        leaves = local_words = joins = 0
        self.assertEqual(len(plan.descriptors), 12)
        for index, item in enumerate(plan.iter_bindings(self.initial)):
            self.assertEqual(item.index, index)
            self.assertEqual(item.descriptor, plan.descriptors[index])
            descriptor, binding = item.descriptor, item.pair_binding
            self.assertEqual((descriptor.index, descriptor.first_round), (index, 2*index))
            self.assertEqual(descriptor.operation_id, f'{OPERATION}/pair/{index}')
            self.assertEqual(descriptor.leaf_offset, leaves)
            self.assertEqual((descriptor.words, descriptor.leaves),
                             (len(binding.spec.words), len(binding.spec.leaves)))
            self.assertEqual(sha256(canonical(list(item.global_ids))).hexdigest(), descriptor.global_ids_sha256)
            self.assertEqual(len(item.global_ids), len(set(item.global_ids)))
            values = binding.assignment
            self.assertTrue(all(truth(binding.spec, values, i) for i in range(len(binding.spec.leaves))))
            current = set(item.global_ids)
            if previous is not None:
                self.assertEqual(previous.intersection(current),
                    {f'state/{2*index}/l{lane}/b{bit}' for lane in range(25) for bit in range(64)})
            for local, global_id in enumerate(item.global_ids):
                value = values[binding.spec.words[local][0]]
                if global_id in owners:
                    owner = owners[global_id]
                    self.assertEqual(owner >> 1, index-1)  # No nonadjacent sharing.
                    self.assertEqual(owner & 1, value)  # One asserted value per global ID.
                    joins += 1
                else:
                    owners[global_id] = (index << 1) | value
            previous = current
            leaves += descriptor.leaves
            local_words += descriptor.words
            self.assertTrue(item.permutation_prefix_matches_reference)
            last_output = output_state(item)
            self.assertEqual(last_output, item.reference_output_state)
            # Release the consumer's large references before asking the source
            # iterator to regenerate the next pair.
            del item, binding, values
        self.assertEqual((leaves, local_words, len(owners), joins), (230510, 249710, 232110, 17600))
        self.assertEqual(last_output, keccak_f1600(self.initial))
        summary = plan.summary()
        for name, expected in dict(pairs=12, rounds=24, leaves=230510, pair_local_words=249710,
            unique_global_words=232110, inter_pair_joins=11, shared_join_bits=17600).items():
            self.assertIs(type(summary[name]), int)
            self.assertEqual(summary[name], expected)
        self.assertIs(summary['permutation_topology_constructed'], True)
        for flag in FALSE_FLAGS:
            self.assertIs(summary[flag], False, flag)

    def test_corrupt_state2_has_only_pair0_final_producer_failure_and_coherent_later_pairs(self):
        changed = list(keccak_f1600_round(keccak_f1600_round(self.initial, 0), 1))
        changed[0] ^= 1
        previous_values, failures, last = None, [], None
        for item in self.plan.iter_bindings(self.initial, claimed_states={2: tuple(changed)}):
            binding, values = item.pair_binding, item.pair_binding.assignment
            local_false = [i for i in range(len(binding.spec.leaves)) if not truth(binding.spec, values, i)]
            failures.extend((item.index, i) for i in local_false)
            state = output_state(item)
            if item.index == 0:
                self.assertEqual(state, tuple(changed))
            else:
                self.assertEqual(state, keccak_f1600_round(
                    keccak_f1600_round(last, 2*item.index), 2*item.index+1))
            by_id = {global_id: values[binding.spec.words[i][0]] for i, global_id in enumerate(item.global_ids)}
            if previous_values is not None:
                for global_id, value in previous_values.items():
                    self.assertEqual(by_id[global_id], value)
            previous_values = {f'state/{2*item.index+2}/l{lane}/b{bit}': (state[lane] >> bit) & 1
                               for lane in range(25) for bit in range(64)}
            last = state
            del item, binding, values, by_id
        self.assertEqual(failures, [(0, 17606)])

    def test_properly_padded_empty_input_matches_known_hash_without_claiming_padding_script_binding(self):
        padded = keccak256_padded(b'')
        self.assertEqual(len(padded), 136)
        initial = state_from_bytes(padded+bytes(64))
        for item in self.plan.iter_bindings(initial):
            final = output_state(item)
            del item
        self.assertEqual(final, keccak_f1600(initial))
        self.assertEqual(state_to_bytes(final)[:32].hex(),
                         'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470')
        self.assertIs(self.plan.summary()['full_hash_verified'], False)

    def test_regeneration_factory_only_immutable_copies_and_invalid_diagnostics(self):
        regenerated = self.plan.regenerate_pair(0)
        self.assertEqual(regenerated.descriptor, self.plan.descriptors[0])
        self.assertEqual(regenerated.pair.spec.digest().hex(), regenerated.descriptor.catalogue_id)
        self.assertEqual(sha256(canonical(list(regenerated.global_ids))).hexdigest(),
                         regenerated.descriptor.global_ids_sha256)
        manifest = self.plan.manifest
        self.assertEqual(manifest['context'], CONTEXT.hex())
        self.assertTrue(manifest['commitment_order'].startswith('external context -> topology'))
        self.assertEqual(self.plan.topology_sha256,
                         sha256(permutation.TOPOLOGY_DOMAIN+canonical(manifest)).digest())
        manifest['context'] = '00'*32
        self.assertNotEqual(manifest, self.plan.manifest)
        summary = self.plan.summary()
        summary['permutation_topology_constructed'] = False
        self.assertIs(self.plan.summary()['permutation_topology_constructed'], True)
        for value, field in ((self.plan, 'topology_sha256'), (regenerated.descriptor, 'words'),
                             (regenerated, 'global_ids')):
            with self.assertRaises((FrozenInstanceError, AttributeError)):
                setattr(value, field, None)
        for cls in (type(self.plan), type(regenerated), type(regenerated.descriptor)):
            with self.assertRaises(TypeError):
                cls()
            self.assertFalse(hasattr(cls, 'from_json'))
        for index in (-1, 12, True, '0'):
            with self.assertRaises(ValueError):
                self.plan.regenerate_pair(index)
        for claimed in ({0: self.initial}, {1: self.initial}, {24: self.initial},
                        {True: self.initial}, {2: (0,)*24}, {2: (True,)+(0,)*24}):
            with self.assertRaises(ValueError):
                self.plan.iter_bindings(self.initial, claimed_states=claimed)


if __name__ == '__main__':
    unittest.main()
