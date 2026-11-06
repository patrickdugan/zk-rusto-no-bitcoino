"""Proof-derived two-round arithmetic checks, with explicit open boundaries.

No WOTS signing, native build, bulk matrix/generator read or proving runs here.
Source metadata associates ports with proof/transcript data; it does not make
that association a Bitcoin Script proof-byte or Fiat-Shamir computation.
"""
from copy import deepcopy
from dataclasses import FrozenInstanceError, replace
from hashlib import sha256
import json
import os
from pathlib import Path
import unittest

from nht4 import HEADER_BYTES, load_expected_json
from poseidon_reference import load_parameters_json
from production_replay import ReplayKeyBindings, canonical_sha256
from proof_codec import decode_proof, load_dimensions_json
from script import OPS, execute, limbs, num
from sumcheck_graph import (SOURCE_DOMAIN, SOURCE_SCHEMA, OuterSumcheckGraph,
                            _build_arithmetic, build_outer_sumcheck_graphs)
from wots_graph import GraphSpec

FIXTURES = Path(__file__).resolve().parents[1]/'fixtures'
DIMENSION_PIN = bytes.fromhex('de6333df2e41b5f5bae1c103fab862f8d6022fd54abeb80ba61920bc9f360edc')
KEY_PIN = bytes.fromhex('c8b117ea587c80bfdbdfc0cc262cdf68b1b4c07b3b45ba871413c7768aa62b9a')
TRACE_PIN = bytes.fromhex('394d90b302b2fe6b8f5c0a65ada372d820996f3230770a816961a75cefec59b8')
POSEIDON_PIN = bytes.fromhex('b55fa125133315243cb299ee7603c5f0508d68abf64f0dab43ecba4a0d09fa67')


def field(values, words):
    return sum(values[word] << (29*i) for i, word in enumerate(words))


def changed_field(values, words, value):
    altered = dict(values)
    for word, limb in zip(words, limbs(value), strict=True):
        altered[word] = limb
    return altered


def polynomial_step(prior, compressed, challenge, modulus):
    """Plain integer polynomial formula, independent of graph/native helpers."""
    c0, c2, c3 = compressed
    c1 = (prior-2*c0-c2-c3) % modulus
    # p(0)+p(1)=prior. Evaluate with explicit powers, not builder Horner code.
    assert (2*c0+c1+c2+c3) % modulus == prior
    return c1, (c0+c1*challenge+c2*challenge**2+c3*challenge**3) % modulus


class OuterSumcheckGraphs(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.expected = load_expected_json((FIXTURES/'nht4-genesis-0-2020-k5.expected.json').read_bytes())
        cls.dimensions = load_dimensions_json(
            (FIXTURES/'nht4-genesis-0-2020-k5.dimensions.json').read_bytes(), cls.expected,
            expected_descriptor_sha256=DIMENSION_PIN)
        cls.raw_proof = (FIXTURES/'nht4-genesis-0-2020-k5.nht4').read_bytes()[HEADER_BYTES:]
        cls.decoded = decode_proof(cls.raw_proof, cls.dimensions)
        cls.bindings = ReplayKeyBindings.from_json(json.loads(
            (FIXTURES/'nht4-genesis-0-2020-k5.key-bindings.json').read_bytes()),
            cls.expected, cls.dimensions, expected_key_bindings_sha256=KEY_PIN)
        cls.parameters = load_parameters_json(
            (FIXTURES/'nht4-genesis-0-2020-k5.poseidon.json').read_bytes(), cls.expected,
            cls.dimensions, expected_parameters_sha256=POSEIDON_PIN)
        cls.trace = json.loads((FIXTURES/'nht4-genesis-0-2020-k5.trace.json').read_bytes())
        cls.graphs = build_outer_sumcheck_graphs(cls.decoded, cls.expected, cls.bindings, cls.trace,
            expected_trace_sha256=TRACE_PIN, poseidon_parameters=cls.parameters)
        cls.specs = tuple(GraphSpec.from_program(graph.program) for graph in cls.graphs)

    def build(self, **overrides):
        inputs = dict(decoded=self.decoded, expected=self.expected, bindings=self.bindings,
            native_trace=self.trace, expected_trace_sha256=TRACE_PIN,
            poseidon_parameters=self.parameters)
        inputs.update(overrides)
        return build_outer_sumcheck_graphs(**inputs)

    def source_inputs(self, graph):
        proof = self.decoded.value['snark_'+graph.role]['sc_proof_outer']['compressed_polys']
        rows = tuple(tuple(int.from_bytes(bytes.fromhex(value), 'little')
                           for value in row['coeffs_except_linear_term']) for row in proof[:2])
        stream = next(s for s in self.trace['streams'] if s['kind'] == 'keccak'
                      and s['engine'] == graph.engine and s['session'] == 0)
        positions = [i for i, event in enumerate(stream['events'])
                     if event['op'] == 'squeeze' and event['label_hex'] == b'c'.hex()][:2]
        challenges = tuple(int.from_bytes(bytes.fromhex(stream['events'][i]['challenge_le']), 'little')
                           for i in positions)
        return rows, challenges, stream, positions

    def test_real_rows_challenges_and_manual_polynomial_relations_in_both_roles(self):
        self.assertEqual(tuple(g.role for g in self.graphs), ('primary', 'secondary'))
        self.assertEqual(tuple(g.engine for g in self.graphs), ('pallas', 'vesta'))
        for graph in self.graphs:
            values, prior = graph.assignment, 0
            rows, challenges, stream, positions = self.source_inputs(graph)
            self.assertEqual(graph.program.field_role, graph.engine+'_scalar')
            self.assertEqual(len(graph.rounds), 2)
            for i, ports in enumerate(graph.rounds):
                self.assertEqual(ports.index, i)
                self.assertEqual(field(values, ports.prior), prior)
                self.assertEqual(tuple(field(values, p) for p in (ports.c0, ports.c2, ports.c3)), rows[i])
                self.assertEqual(field(values, ports.challenge), challenges[i])
                previous = stream['events'][positions[i]-1]
                self.assertEqual((previous['op'], previous['label_hex']), ('absorb', b'p'.hex()))
                self.assertEqual(previous['repr_hex'], ''.join(x.to_bytes(32, 'little').hex() for x in rows[i]))
                linear, expected = polynomial_step(prior, rows[i], challenges[i], graph.program.p)
                self.assertEqual(field(values, ports.c1), linear)
                self.assertEqual(field(values, ports.evaluated), expected)
                self.assertEqual(field(values, ports.next_claim), expected)
                prior = expected

    def test_shared_round_boundary_and_only_required_constant_anchors(self):
        for graph in self.graphs:
            self.assertEqual(graph.rounds[1].prior, graph.rounds[0].next_claim)
            self.assertEqual(graph.ports['initial/claim'], graph.rounds[0].prior)
            constants = [c for c in graph.program.constraints if c.kind == 'const']
            zero_anchors = {c.wires[0] for c in constants if c.argument == (0,)}
            self.assertEqual(zero_anchors, set(graph.rounds[0].prior))
            self.assertEqual(len(zero_anchors), 9)
            # The convolution argument also needs its own carry endpoint anchors.
            self.assertTrue(all(c.argument in ((0,), (8192,)) for c in constants))
            source_words = {w for ports in graph.rounds
                for names in (ports.c0, ports.c2, ports.c3, ports.challenge) for w in names}
            self.assertFalse(any(set(c.wires) & source_words for c in constants))

    def test_provenance_proof_spans_and_transcript_event_locations_are_exact(self):
        spans = {span.path: span for span in self.decoded.spans}
        for graph in self.graphs:
            rows, challenges, stream, positions = self.source_inputs(graph)
            stream_index = self.trace['streams'].index(stream)
            counts = {'proof_scalar': 0, 'transcript_challenge': 0}
            for record in graph.sources['ports']:
                counts[record['kind']] += 1
                index = record['round_index']
                words = graph.ports[record['field']]
                if record['kind'] == 'proof_scalar':
                    compressed_index = {0: 0, 2: 1, 3: 2}[record['coefficient_power']]
                    path = (f'snark_{graph.role}.sc_proof_outer.compressed_polys[{index}]'
                            f'.coeffs_except_linear_term[{compressed_index}]')
                    self.assertEqual(record['path'], path)
                    self.assertEqual(record['compressed_index'], compressed_index)
                    span = spans[path]
                    self.assertEqual((span.kind, span.engine, span.size), ('scalar', graph.engine, 32))
                    self.assertEqual((record['inner_proof_offset'], record['bundle_offset'], record['bytes']),
                                     (span.start, HEADER_BYTES+span.start, 32))
                    value = int.from_bytes(self.raw_proof[span.start:span.start+32], 'little')
                    self.assertEqual(value, rows[index][compressed_index])
                else:
                    self.assertEqual((record['stream_kind'], record['stream_engine'], record['session']),
                                     ('keccak', graph.engine, 0))
                    self.assertEqual((record['event_index'], record['absorb_event_index']),
                                     (positions[index], positions[index]-1))
                    self.assertEqual(record['path'],
                        f'streams[{stream_index}].events[{positions[index]}].challenge_le')
                    self.assertEqual((record['outer_challenge_index'], record['label_hex']),
                                     (index, b'c'.hex()))
                    value = challenges[index]
                self.assertEqual(field(graph.assignment, words), value)
            self.assertEqual(counts, {'proof_scalar': 6, 'transcript_challenge': 2})

    @unittest.skipUnless(os.environ.get('GITHUB_ACTIONS') == 'true',
                         'all-leaf Script execution is hosted only')
    def test_every_arithmetic_leaf_executes_honestly_without_native_or_wots(self):
        for graph in self.graphs:
            bound = graph.program.bind(graph.assignment)
            self.assertEqual(bound.failures(), ())
            for ordinal in range(len(graph.program.constraints)):
                outcome = bound.execute(ordinal, disprove=False)
                self.assertTrue(outcome.success, (graph.role, ordinal, outcome.error))
                self.assertLessEqual(outcome.peak_stack, 1000)

    def test_source_context_is_exact_and_factory_outputs_are_immutable_copies(self):
        for graph in self.graphs:
            sources = graph.sources
            self.assertEqual(sources['schema'], SOURCE_SCHEMA)
            for key, value in dict(role=graph.role, engine=graph.engine, phase='outer',
                round_start=0, round_count=2, degree=3, proof_sha256=self.expected.proof_sha256.hex(),
                verifier_key_sha256=self.expected.verifier_key_sha256.hex(),
                verifier_dimensions_sha256=DIMENSION_PIN.hex(), key_bindings_sha256=KEY_PIN.hex(),
                native_trace_sha256=TRACE_PIN.hex(), poseidon_parameters_sha256=POSEIDON_PIN.hex()).items():
                self.assertEqual(sources[key], value, key)
            encoded = json.dumps(sources, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')
            self.assertEqual(graph.source_sha256, sha256(SOURCE_DOMAIN+encoded).digest())
            self.assertEqual(graph.program.context, graph.source_sha256)
            self.assertEqual(len(sources['ports']), 8)
            summary = graph.summary()
            for flag in ('source_ports_script_bound', 'challenge_script_binding',
                         'proof_parser_script_binding', 'proof_verified',
                         'complete_verifier', 'bitvm2_script_verified'):
                self.assertIs(summary[flag], False, flag)
            values = graph.assignment
            first = next(iter(values))
            values[first] = (values[first]+1) % dict(graph.program.words)[first]
            self.assertNotEqual(values, graph.assignment)
            sources['role'] = 'edited'
            sources['ports'][0]['path'] = 'edited'
            self.assertNotEqual(sources, graph.sources)
            with self.assertRaises((FrozenInstanceError, AttributeError)):
                graph.role = 'edited'
            with self.assertRaises((FrozenInstanceError, AttributeError)):
                graph.rounds[0].index = 7
            with self.assertRaises(TypeError):
                graph.ports['initial/claim'] = ()
        self.assertNotEqual(self.graphs[0].source_sha256, self.graphs[1].source_sha256)
        with self.assertRaises(TypeError):
            OuterSumcheckGraph()

    def test_fixed_ports_wrong_first_claim_remains_refutable_after_coherent_second_round(self):
        for graph in self.graphs:
            rows, challenges, _, _ = self.source_inputs(graph)
            wrong = (field(graph.assignment, graph.rounds[0].next_claim)+1) % graph.program.p
            program, values, rounds, _ = _build_arithmetic(graph.role, graph.engine, rows,
                challenges, graph.source_sha256, claimed_next=(wrong, None))
            self.assertEqual(program.digest(), graph.program.digest())
            self.assertEqual(rounds[0].next_claim, rounds[1].prior)
            _, expected_second = polynomial_step(wrong, rows[1], challenges[1], program.p)
            self.assertEqual(field(values, rounds[1].next_claim), expected_second)
            failures = [i for i, c in enumerate(program.constraints) if not c.native(values, program.p)]
            self.assertEqual(failures, [rounds[0].output_constraint])
            self.assertTrue(program.bind(values).execute(failures[0]).success)

    def test_coherent_source_substitution_is_an_explicit_open_boundary(self):
        for graph in self.graphs:
            rows, challenges, _, _ = self.source_inputs(graph)
            for kind in ('coefficient', 'challenge'):
                alternate_rows, alternate_challenges = [list(row) for row in rows], list(challenges)
                if kind == 'coefficient':
                    alternate_rows[0][1] = (alternate_rows[0][1]+1) % graph.program.p
                else:
                    alternate_challenges[0] = (alternate_challenges[0]+1) % graph.program.p
                program, values, rounds, _ = _build_arithmetic(graph.role, graph.engine,
                    alternate_rows, alternate_challenges, graph.source_sha256)
                # This is intentional: source labels/context alone do not bind
                # signed port VALUES to proof bytes or a Script Keccak graph.
                self.assertEqual(program.digest(), graph.program.digest())
                self.assertTrue(all(c.native(values, program.p) for c in program.constraints))
                self.assertIs(graph.summary()['source_ports_script_bound'], False)
                prior = 0
                for i, ports in enumerate(rounds):
                    _, prior = polynomial_step(prior, alternate_rows[i], alternate_challenges[i], program.p)
                    self.assertEqual(field(values, ports.next_claim), prior)

    def test_source_and_output_ports_have_disputable_field_canonicality_paths(self):
        for graph, spec in zip(self.graphs, self.specs, strict=True):
            indices, bodies = dict(spec.field_leaves), dict(spec.bodies)
            fields_by_words = {words: name for name, words in graph.program.fields}
            for ports in graph.rounds:
                for names in (ports.c0, ports.c2, ports.c3, ports.challenge, ports.next_claim):
                    leaf = spec.leaves[indices[fields_by_words[names]]]
                    self.assertEqual(leaf.kind, 'field_valid')
                    for invalid in (graph.program.p, graph.program.p+1):
                        values = changed_field(graph.assignment, names, invalid)
                        with self.assertRaises(ValueError):
                            graph.program.bind(values)
                        witness = [num(values[spec.words[i][0]]) for i in leaf.wires]
                        # This executes only the predicate body. The hosted
                        # registry corpus separately authenticates WOTS values.
                        result = execute(bytes.fromhex(bodies[leaf.body_sha256])+bytes([OPS['NOT']]), witness)
                        self.assertTrue(result.success, (graph.role, invalid, result.error))

    def test_changed_boundary_openings_and_all_witness_lengths_fail_closed(self):
        for graph in self.graphs:
            bound = graph.program.bind(graph.assignment)
            ordinals = {graph.rounds[0].output_constraint, graph.rounds[1].output_constraint}
            for kind in ('conv_split', 'conv_reconstruct', 'conv_ab', 'conv_pq', 'conv_column', 'add', 'const'):
                ordinals.add(next(i for i, c in enumerate(graph.program.constraints) if c.kind == kind))
            for ordinal in ordinals:
                witness = bound.witness(ordinal)
                code = bound.script(ordinal, disprove=False)
                for malformed in ((), witness[:-1], (b'',)+witness, witness+(b'',)):
                    self.assertFalse(execute(code, malformed).success)
                altered = list(witness)
                altered[0] = num(1) if witness[0] != num(1) else num(0)
                self.assertFalse(execute(code, altered).success)
            for context, role in ((b'x'*32, graph.program.field_role),
                (graph.program.context, 'vesta_base' if graph.engine == 'pallas' else 'pallas_base')):
                other = replace(graph.program, context=context, field_role=role)
                self.assertNotEqual(other.digest(), graph.program.digest())
                with self.assertRaises(ValueError):
                    bound.require_identity(other.digest(), bound.claim_digest)

    def test_no_receipt_or_mutated_capture_can_replace_fresh_proof_replay(self):
        for receipt in ({'passed': True}, {'proof_verified': True, 'engines': []}):
            with self.assertRaises((ValueError, TypeError)):
                self.build(native_trace=receipt)
            with self.assertRaises((ValueError, TypeError)):
                self.build(decoded=receipt)
        with self.assertRaises(ValueError):
            self.build(expected_trace_sha256=bytes(32))
        altered = deepcopy(self.trace)
        stream = next(s for s in altered['streams'] if s['kind'] == 'keccak' and s['engine'] == 'pallas')
        events = [event for event in stream['events'] if event['op'] == 'squeeze'
                  and event['label_hex'] == b'c'.hex()][:2]
        events[0]['challenge_le'], events[1]['challenge_le'] = events[1]['challenge_le'], events[0]['challenge_le']
        # TEST ONLY replacement pin: even re-pinning this malformed capture
        # cannot turn its substituted challenges into reconstructed Keccak.
        with self.assertRaises(ValueError):
            self.build(native_trace=altered, expected_trace_sha256=canonical_sha256(altered))

    def test_swapped_proof_role_coefficients_and_wrong_proof_pins_reject(self):
        path = '.sc_proof_outer.compressed_polys[0].coeffs_except_linear_term[1]'
        primary = next(s for s in self.decoded.spans if s.path == 'snark_primary'+path)
        secondary = next(s for s in self.decoded.spans if s.path == 'snark_secondary'+path)
        raw = bytearray(self.raw_proof)
        raw[primary.start:primary.start+32], raw[secondary.start:secondary.start+32] = (
            self.raw_proof[secondary.start:secondary.start+32], self.raw_proof[primary.start:primary.start+32])
        substituted = decode_proof(bytes(raw), self.dimensions)
        self.assertNotEqual(substituted.proof_sha256, self.decoded.proof_sha256)
        with self.assertRaises(ValueError):
            self.build(decoded=substituted)
        with self.assertRaises(ValueError):
            self.build(expected=replace(self.expected, proof_sha256=bytes(32)))

    def test_unsupported_factory_parameters_and_malformed_arithmetic_inputs_reject(self):
        for extra in ({'round_count': 1}, {'round_count': 3}, {'degree': 2}, {'phase': 'inner'},
                      {'replay': {'passed': True}}, {'claimed_next': (0, 0)}):
            with self.assertRaises(TypeError):
                self.build(**extra)
        graph = self.graphs[0]
        rows, challenges, _, _ = self.source_inputs(graph)
        malformed = (
            ('primary', 'vesta', rows, challenges, graph.source_sha256),
            ('primary', 'pallas', rows[:1], challenges, graph.source_sha256),
            ('primary', 'pallas', ((0, 0), rows[1]), challenges, graph.source_sha256),
            ('primary', 'pallas', rows, challenges[:1], graph.source_sha256),
            ('primary', 'pallas', rows, (True, challenges[1]), graph.source_sha256),
            ('primary', 'pallas', rows, (graph.program.p, challenges[1]), graph.source_sha256),
            ('primary', 'pallas', rows, challenges, b'short'),
        )
        for arguments in malformed:
            with self.assertRaises((ValueError, TypeError)):
                _build_arithmetic(*arguments)
        with self.assertRaises((ValueError, TypeError)):
            _build_arithmetic(graph.role, graph.engine, rows, challenges, graph.source_sha256,
                              claimed_next=(True, None))


if __name__ == '__main__':
    unittest.main()
