"""Tiny local composition invariants; real Keccak pairs are HOSTED ONLY.

The synthetic private seam is not a Keccak verifier or public import API. Local
tests never construct a real pair, sign WOTS values or run native code. Full
20k-word construction/binding checks live in the explicitly guarded class.
"""
from copy import deepcopy
from collections import Counter
from dataclasses import FrozenInstanceError, replace
from hashlib import sha256
import json
import os
import unittest
from unittest.mock import patch

from keccak_pair import (MANIFEST_SCHEMA, PROGRAM_DOMAIN, KeccakPair,
    _merge_specs, _validate_maps, build_keccak_pair)
from keccak_trace import MASK64, keccak_f1600_round
from script import execute, num
from trace import MAX_CONSTRAINTS, MAX_WORDS, TraceBuilder
from wots_graph import MAX_GRAPH_LEAVES, GraphSpec

CONTEXT = sha256(b'keccak-pair-test-context').digest()
ROLE, OPERATION = 'pallas_scalar', 'tests/keccak-pair'


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')


def alias_partition(words):
    unique = tuple(dict.fromkeys(words))
    return tuple(unique.index(word) for word in words)


def tiny_children(context=CONTEXT, role=ROLE):
    """Five Boolean words per child, with intentional repeated local names."""
    specs, values, programs = [], [], []
    initial = (1, 0)
    for index in range(2):
        builder = TraceBuilder(role, f'{OPERATION}/tiny/{index}', context)
        a = builder.small('state/in/0', initial[0], 2)
        b = builder.small('state/in/1', initial[1], 2)
        builder.small_constant('same/internal/name', 0, 2)
        out0 = builder.small('state/out/0', initial[0] ^ initial[1], 2)
        out1 = builder.small('state/out/1', 0, 2)
        builder.check('bool_xor', (a, b, out0))
        builder.check('bool_xor', (a, a, out1))  # Authenticate a once, expand twice.
        program, assignment = builder.finish()
        specs.append(GraphSpec.from_program(program))
        values.append(assignment)
        programs.append(program)
        initial = (assignment[out0], assignment[out1])
    return tuple(specs), tuple(values), tuple(programs)


def tiny_merge(specs=None, *, first_round=0, context=CONTEXT, role=ROLE,
               operation_id=OPERATION):
    if specs is None:
        specs = tiny_children(context, role)[0]
    producer = tuple(i for i, (name, _) in enumerate(specs[0].words) if name.startswith('state/out/'))
    consumer = tuple(i for i, (name, _) in enumerate(specs[1].words) if name.startswith('state/in/'))
    result = _merge_specs(specs, producer, consumer, first_round=first_round,
        context=context, role=role, operation_id=operation_id, port_count=2)
    return specs, producer, consumer, result


def graph_truth(spec, values, ordinal):
    leaf = spec.leaves[ordinal]
    words = [values[spec.words[index][0]] for index in leaf.wires]
    if any(type(value) is not int or not 0 <= value < spec.words[index][1]
           for value, index in zip(words, leaf.wires, strict=True)):
        return False
    if leaf.kind == 'const':
        return words[0] == leaf.argument[0]
    if leaf.kind == 'bool_not':
        return words[1] == 1-words[0]
    if leaf.kind == 'bool_xor':
        return words[2] == words[0] ^ words[1]
    if leaf.kind == 'bool_and':
        return words[2] == words[0] & words[1]
    if leaf.kind == 'word_valid':
        return True
    raise AssertionError('unexpected Keccak-only predicate')


class TinyKeccakPairComposition(unittest.TestCase):
    def setUp(self):
        self.specs, self.values, self.programs = tiny_children()
        _, self.producer, self.consumer, result = tiny_merge(self.specs)
        self.spec, self.manifest, self.sources = result
        self.maps = tuple(tuple(child['word_map']) for child in self.sources['children'])

    def validate(self, maps=None, *, producer=None, consumer=None, words=None):
        return _validate_maps(self.specs, self.maps if maps is None else maps,
            self.producer if producer is None else producer,
            self.consumer if consumer is None else consumer,
            self.spec.words if words is None else words, port_count=2)

    def test_maps_are_injective_and_intersect_at_exact_ordered_ports(self):
        self.validate()
        for child, mapping in zip(self.specs, self.maps, strict=True):
            self.assertEqual(len(mapping), len(child.words))
            self.assertEqual(len(set(mapping)), len(mapping))
        intersection = set(self.maps[0]).intersection(self.maps[1])
        expected = {self.maps[0][i] for i in self.producer}
        self.assertEqual(intersection, expected)
        self.assertEqual(len(intersection), 2)
        for ordinal, (producer, consumer) in enumerate(zip(self.producer, self.consumer, strict=True)):
            global_index = self.maps[0][producer]
            self.assertEqual(global_index, self.maps[1][consumer])
            self.assertEqual(self.spec.words[global_index],
                             (f'boundary/middle/l{ordinal//64}/b{ordinal%64}', 2))
        # Equal spelling and equal value are deliberately insufficient to alias.
        first_internal = next(i for i, word in enumerate(self.specs[0].words) if word[0] == 'same/internal/name')
        second_internal = next(i for i, word in enumerate(self.specs[1].words) if word[0] == 'same/internal/name')
        self.assertNotEqual(self.maps[0][first_internal], self.maps[1][second_internal])

    def test_missing_duplicate_permuted_and_unintended_alias_maps_reject(self):
        maps = [list(m) for m in self.maps]
        variants = []
        missing = deepcopy(maps)
        missing[0].pop()
        variants.append(missing)
        duplicate = deepcopy(maps)
        duplicate[0][1] = duplicate[0][0]
        variants.append(duplicate)
        permuted = deepcopy(maps)
        permuted[1][self.consumer[0]], permuted[1][self.consumer[1]] = (
            permuted[1][self.consumer[1]], permuted[1][self.consumer[0]])
        variants.append(permuted)
        extra_alias = deepcopy(maps)
        # These two unrelated wires even have the same spelling AND value0.
        # Merging them must fail structurally, independently of assignments.
        first = next(i for i, word in enumerate(self.specs[0].words) if word[0] == 'same/internal/name')
        second = next(i for i, word in enumerate(self.specs[1].words) if word[0] == 'same/internal/name')
        extra_alias[1][second] = extra_alias[0][first]
        variants.append(extra_alias)
        split = deepcopy(maps)
        split[1][self.consumer[0]] = len(self.spec.words)
        variants.append(split)
        for candidate in variants:
            with self.subTest(candidate=candidate), self.assertRaises(ValueError):
                self.validate(tuple(tuple(m) for m in candidate))
        for producer, consumer in ((self.producer[:1], self.consumer),
                ((self.producer[0],)*2, self.consumer),
                (self.producer, (self.consumer[0],)*2),
                (tuple(reversed(self.producer)), self.consumer)):
            with self.assertRaises(ValueError):
                self.validate(producer=producer, consumer=consumer)
        malformed_words = list(self.spec.words)
        boundary = self.maps[0][self.producer[0]]
        malformed_words[boundary] = ('boundary/bit/wrong', 2)
        with self.assertRaises(ValueError):
            self.validate(words=tuple(malformed_words))
        malformed_words[boundary] = ('boundary/middle/l0/b0', 4)
        with self.assertRaises(ValueError):
            self.validate(words=tuple(malformed_words))

    def test_every_leaf_alias_partition_body_hash_and_word_is_preserved(self):
        covered, assignments = set(), {}
        global_bodies = dict(self.spec.bodies)
        for index, child in enumerate(self.specs):
            leaf_map = self.sources['children'][index]['leaf_map']
            self.assertEqual(len(leaf_map), len(child.leaves))
            for local, global_index in enumerate(self.maps[index]):
                value = self.values[index][child.words[local][0]]
                name = self.spec.words[global_index][0]
                if name in assignments:
                    self.assertEqual(assignments[name], value)
                assignments[name] = value
            for local_ordinal, global_ordinal in enumerate(leaf_map):
                original, merged = child.leaves[local_ordinal], self.spec.leaves[global_ordinal]
                self.assertEqual(merged.wires, tuple(self.maps[index][i] for i in original.wires))
                self.assertEqual(alias_partition(original.wires), alias_partition(merged.wires))
                self.assertEqual((merged.kind, merged.argument, merged.body_sha256),
                                 (original.kind, original.argument, original.body_sha256))
                self.assertEqual(global_bodies[merged.body_sha256], dict(child.bodies)[original.body_sha256])
                self.assertEqual(sha256(bytes.fromhex(global_bodies[merged.body_sha256])).hexdigest(), merged.body_sha256)
                covered.update(merged.wires)
        self.assertEqual(covered, set(range(len(self.spec.words))))
        self.assertEqual(len(self.spec.leaves), sum(len(child.leaves) for child in self.specs))
        self.assertEqual({ordinal for child in self.sources['children'] for ordinal in child['leaf_map']},
                         set(range(len(self.spec.leaves))))
        self.assertEqual(set(global_bodies), {leaf.body_sha256 for leaf in self.spec.leaves})
        # Tiny bare bodies only. Ordered unique authentication slots are expanded
        # back into the complete formal operand list by the retained body bytes.
        for ordinal, leaf in enumerate(self.spec.leaves):
            slots = tuple(dict.fromkeys(leaf.wires))
            witness = [num(assignments[self.spec.words[i][0]]) for i in slots]
            body = bytes.fromhex(global_bodies[leaf.body_sha256])
            self.assertTrue(execute(body, witness).success, ordinal)

    def test_manifest_identity_and_existing_resource_caps_are_explicit(self):
        self.assertEqual(self.manifest['schema'], MANIFEST_SCHEMA)
        self.assertEqual(self.spec.program_sha256, sha256(PROGRAM_DOMAIN+canonical(self.manifest)).hexdigest())
        self.assertNotIn(self.spec.program_sha256, tuple(p.digest().hex() for p in self.programs))
        self.assertEqual((MAX_CONSTRAINTS, MAX_WORDS, MAX_GRAPH_LEAVES), (10000, 100000, 30000))
        with self.assertRaises(FrozenInstanceError):
            self.spec.context = '00'*32
        for other in (replace(self.spec, context='00'*32),
                      replace(self.spec, field_role='vesta_base'),
                      replace(self.spec, operation_id='other-operation'),
                      replace(self.spec, program_sha256='00'*32)):
            self.assertNotEqual(other.digest(), self.spec.digest())
        for options in (dict(first_round=1), dict(context=b'c'*32), dict(role='vesta_scalar')):
            _, _, _, (other, manifest, _) = tiny_merge(**options)
            self.assertNotEqual(manifest, self.manifest)
            self.assertNotEqual(other.program_sha256, self.spec.program_sha256)
            self.assertNotEqual(other.digest(), self.spec.digest())

    def test_malformed_child_body_coverage_roles_context_and_parameters_reject(self):
        body_id, body = self.specs[0].bodies[0]
        bad_bodies = tuple((key, '51' if key == body_id else value) for key, value in self.specs[0].bodies)
        variants = [replace(self.specs[0], bodies=bad_bodies),
                    replace(self.specs[0], bodies=self.specs[0].bodies+((sha256(b'\x51').hexdigest(), '51'),)),
                    replace(self.specs[0], leaves=self.specs[0].leaves[:-1]),
                    replace(self.specs[0], words=self.specs[0].words+(('unused', 2),)),
                    replace(self.specs[0], field_role='vesta_scalar'),
                    replace(self.specs[0], context='01'*32)]
        for other in variants:
            with self.subTest(other=other.operation_id), self.assertRaises(ValueError):
                tiny_merge((other, self.specs[1]))
        for extra in (dict(first_round=-1), dict(first_round=23), dict(first_round=True),
                      dict(context=bytes(31)), dict(context=bytearray(32)),
                      dict(role='unsupported'), dict(operation_id='bad operation')):
            with self.assertRaises(ValueError):
                tiny_merge(self.specs, **extra)

    def test_public_factory_is_guarded_before_real_round_construction_and_has_no_receipt_api(self):
        with patch.dict('os.environ', {'GITHUB_ACTIONS': 'false'}), \
             patch('keccak_pair.keccak_round_trace', side_effect=AssertionError('real graph forbidden')) as rounds:
            with self.assertRaises(ValueError):
                build_keccak_pair(0, context=CONTEXT, role=ROLE, operation_id=OPERATION)
            # PRIVATE uninitialized object solely to verify the resource guard
            # precedes any attribute-dependent/full-graph binding operation.
            uninitialized = object.__new__(KeccakPair)
            with self.assertRaises(ValueError):
                uninitialized.bind((0,)*25)
            rounds.assert_not_called()
        for extra in (dict(child_programs=self.programs), dict(specs=self.specs),
                      dict(source_maps=self.maps), dict(receipt={'passed': True})):
            with self.assertRaises(TypeError):
                build_keccak_pair(0, context=CONTEXT, role=ROLE, operation_id=OPERATION, **extra)
        with self.assertRaises(TypeError):
            KeccakPair()
        self.assertFalse(hasattr(KeccakPair, 'from_json'))


@unittest.skipUnless(os.environ.get('GITHUB_ACTIONS') == 'true',
                     'real two-round Keccak graph construction is hosted only')
class HostedRealKeccakPair(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Redundant explicit guard keeps future direct setup calls lightweight.
        if os.environ.get('GITHUB_ACTIONS') != 'true':
            raise unittest.SkipTest('real graph is hosted only')
        cls.pair = build_keccak_pair(0, context=CONTEXT, role=ROLE, operation_id=OPERATION)
        cls.state = tuple((i*0x0123456789abcdef ^ (1 << (i % 64))) & MASK64 for i in range(25))
        cls.bound = cls.pair.bind(cls.state)

    def state_value(self, values, names):
        bits = [values[name] for name in names]
        self.assertEqual(len(bits), 1600)
        self.assertTrue(all(type(bit) is int and bit in (0, 1) for bit in bits))
        return tuple(sum(bits[64*lane+bit] << bit for bit in range(64)) for lane in range(25))

    def test_all_1600_links_and_two_round_word_reference(self):
        pair, values = self.pair, self.bound.assignment
        sources = pair.source_maps
        maps = tuple(tuple(child['word_map']) for child in sources['children'])
        occurrences = tuple(Counter(mapping) for mapping in maps)
        self.assertEqual(tuple(len(mapping) for mapping in maps), (11202, 11204))
        self.assertEqual((len(pair.spec.words), len(pair.spec.leaves)), (20806, 19206))
        self.assertEqual(len(set(maps[0]).intersection(maps[1])), 1600)
        self.assertEqual(tuple(pair.boundary_words), tuple(sources['middle']))
        self.assertEqual(len(pair.producer_leaves), 1600)
        self.assertEqual(len(pair.consumer_leaves), 1600)
        for index, name in enumerate(pair.boundary_words):
            global_index = sources['boundary_indices'][index]
            self.assertEqual(pair.spec.words[global_index], (name, 2))
            self.assertTrue(pair.consumer_leaves[index])
            self.assertEqual(occurrences[0][global_index], 1)
            self.assertEqual(occurrences[1][global_index], 1)
            # The source round builder declares input bits first and output
            # bits last, both in lane-major/least-significant-bit-first order.
            self.assertEqual(maps[0][-1600+index], global_index)
            self.assertEqual(maps[1][index], global_index)
            self.assertEqual(pair.spec.leaves[pair.producer_leaves[index]].wires[-1], global_index)
            self.assertTrue(all(global_index in pair.spec.leaves[ordinal].wires
                                for ordinal in pair.consumer_leaves[index]))
        middle = keccak_f1600_round(self.state, 0)
        self.assertEqual(self.state_value(values, pair.input_words), self.state)
        self.assertEqual(self.state_value(values, pair.boundary_words), middle)
        self.assertEqual(self.state_value(values, pair.output_words), keccak_f1600_round(middle, 1))
        self.assertEqual([i for i in range(len(pair.spec.leaves)) if not graph_truth(pair.spec, values, i)], [])
        bodies, selected = dict(pair.spec.bodies), {}
        for leaf in pair.spec.leaves:
            selected.setdefault(leaf.body_sha256, leaf)
        for digest, leaf in selected.items():
            slots = tuple(dict.fromkeys(leaf.wires))
            witness = [num(values[pair.spec.words[index][0]]) for index in slots]
            self.assertTrue(execute(bytes.fromhex(bodies[digest]), witness).success)
        zeros = [leaf for leaf in pair.spec.leaves if leaf.kind == 'const']
        self.assertEqual(len(zeros), 2)
        self.assertTrue(all(leaf.argument == (0,) for leaf in zeros))

    def test_corrupt_middle_with_coherent_consumer_refutes_only_producer_output(self):
        middle = list(keccak_f1600_round(self.state, 0))
        middle[7] ^= 1 << 13
        bound = self.pair.bind(self.state, claimed_middle=tuple(middle))
        values = bound.assignment
        failures = [i for i in range(len(bound.spec.leaves)) if not graph_truth(bound.spec, values, i)]
        self.assertEqual(failures, [self.pair.producer_leaves[7*64+13]])
        self.assertEqual(self.state_value(bound.assignment, self.pair.output_words),
                         keccak_f1600_round(tuple(middle), 1))

    def test_wrong_final_output_and_invalid_boolean_assignment_have_failures(self):
        final = list(keccak_f1600_round(keccak_f1600_round(self.state, 0), 1))
        final[0] ^= 1
        final[24] ^= 1 << 63
        bound = self.pair.bind(self.state, claimed_output=tuple(final))
        values = bound.assignment
        targets = {self.pair.output_words[0], self.pair.output_words[-1]}
        expected = [i for i, leaf in enumerate(bound.spec.leaves)
                    if bound.spec.words[leaf.wires[-1]][0] in targets]
        failures = [i for i in range(len(bound.spec.leaves)) if not graph_truth(bound.spec, values, i)]
        self.assertEqual(failures, expected)
        malformed = self.bound.assignment
        malformed[self.pair.boundary_words[0]] = 2
        self.assertTrue(any(not graph_truth(self.pair.spec, malformed, i)
                            for i in tuple(self.pair.producer_leaves)+tuple(self.pair.consumer_leaves[0])))
        # WOTS authenticity, decoder-false disproof paths and exact signed-witness
        # guards are exercised separately by the hosted registry generator.

    def test_sealed_pair_and_bound_assignments_are_immutable_copies(self):
        sources = self.pair.source_maps
        sources['children'][0]['word_map'][0] = -1
        self.assertNotEqual(sources, self.pair.source_maps)
        manifest = self.pair.manifest
        manifest['schema'] = 'edited'
        self.assertNotEqual(manifest, self.pair.manifest)
        assignment = self.bound.assignment
        assignment[self.pair.input_words[0]] ^= 1
        self.assertNotEqual(assignment, self.bound.assignment)
        with self.assertRaises((FrozenInstanceError, AttributeError)):
            self.pair.spec = None
        with self.assertRaises((FrozenInstanceError, AttributeError)):
            self.bound.spec = None
        summary = self.bound.summary()
        for flag in ('full_permutation_verified', 'full_hash_verified', 'transcript_verified',
                     'proof_verified', 'bitvm2_script_verified', 'production_assertion_binding',
                     'bitcoin_transaction_graph'):
            self.assertIs(summary[flag], False, flag)


if __name__ == '__main__':
    unittest.main()
