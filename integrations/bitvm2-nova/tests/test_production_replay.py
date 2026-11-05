"""Short synthetic checks and independently pinned actual retained-proof replay."""
from copy import deepcopy
from dataclasses import FrozenInstanceError, replace
from hashlib import sha256
import json
from pathlib import Path
import random
import unittest

from ipa_algebra import PALLAS, VESTA, test_generator, weights
from nht4 import HEADER_BYTES, load_expected_json
from proof_codec import decode_proof, load_dimensions_json
from production_transcript import NovaTranscript
from production_replay import (KEY_SCHEMA, TRACE_SCHEMA, ReplayKeyBindings,
    _EngineKey, _Instance, _KeccakReplay, _derandomize, _fold, _instance_repr,
    _keccak_snapshot, _le, _native_ro, _point_hex, _ro_instance,
    _sumcheck, _validate_trace, canonical_sha256, ipa_factors, replay_production)

FIXTURES = Path(__file__).resolve().parents[1]/'fixtures'
DIMENSION_PIN = bytes.fromhex('de6333df2e41b5f5bae1c103fab862f8d6022fd54abeb80ba61920bc9f360edc')
KEY_BINDINGS_PIN = bytes.fromhex('c8b117ea587c80bfdbdfc0cc262cdf68b1b4c07b3b45ba871413c7768aa62b9a')
TRACE_PIN = bytes.fromhex('394d90b302b2fe6b8f5c0a65ada372d820996f3230770a816961a75cefec59b8')


def synthetic_keccak(engine, operations):
    t = NovaTranscript(engine, b'RelaxedR1CSSNARK')
    events = [{'sequence': 0, 'op': 'new', 'label_hex': b'RelaxedR1CSSNARK'.hex(),
               'after': _keccak_snapshot(t)}]
    for op, label, value in operations:
        fields = {'sequence': len(events), 'op': op}
        if op == 'absorb':
            t.absorb_bytes(label, value)
            fields.update(label_hex=label.hex(), repr_hex=value.hex())
        elif op == 'dom_sep':
            t.dom_sep(label)
            fields.update(data_hex=label.hex())
        elif op == 'squeeze':
            fields.update(label_hex=label.hex(), challenge_le=_le(t.squeeze(label)))
        else:
            raise AssertionError('unknown synthetic operation')
        fields['after'] = _keccak_snapshot(t)
        events.append(fields)
    return events


def synthetic_ro(engine, inputs, bits, full_hash):
    events = [{'sequence': 0, 'op': 'new', 'mode': 'wide',
               'after': {'mode': 'wide', 'state_le': []}}]
    state = []
    for value in inputs:
        state.append(_le(value))
        events.append({'sequence': len(events), 'op': 'absorb', 'value_le': _le(value),
                       'after': {'mode': 'wide', 'state_le': list(state)}})
    events.append({'sequence': len(events), 'op': 'squeeze', 'num_bits': bits,
        'start_with_one': False, 'challenge_le': _le(full_hash & ((1 << bits)-1)),
        'after': {'mode': 'wide', 'state_le': [_le(full_hash)]}})
    return events


def synthetic_report(streams):
    recorded = sum(len(json.dumps(event, sort_keys=True, separators=(',', ':')).encode())
                   for stream in streams for event in stream['events'])
    return {'schema': TRACE_SCHEMA, 'streams': streams,
            'events': sum(len(stream['events']) for stream in streams),
            'recorded_event_bytes': recorded, 'max_streams': 16, 'max_events': 4096,
            'max_recorded_event_bytes': 8 << 20, 'complete_capture': True,
            'panic_is_rejection': False}


class ProductionReplayComponents(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.expected = load_expected_json((FIXTURES/'nht4-genesis-0-2020-k5.expected.json').read_bytes())
        cls.dimensions = load_dimensions_json(
            (FIXTURES/'nht4-genesis-0-2020-k5.dimensions.json').read_bytes(), cls.expected,
            expected_descriptor_sha256=DIMENSION_PIN)
        cls.raw = (FIXTURES/'nht4-genesis-0-2020-k5.nht4').read_bytes()[HEADER_BYTES:]
        cls.decoded = decode_proof(cls.raw, cls.dimensions)
        cls.generators = {curve.name: test_generator(curve, 3) for curve in (PALLAS, VESTA)}
        # Deliberately test-owned metadata, NOT an export of the real VK.
        cls.metadata = {'schema': KEY_SCHEMA, 'header_revision': cls.expected.header_revision,
            'nova_version': '0.76.0', 'network': cls.expected.network, 'k': cls.expected.k,
            'verifier_key_sha256': cls.expected.verifier_key_sha256.hex(),
            'verifier_dimensions_sha256': DIMENSION_PIN.hex(), 'pp_digest_le': _le(7)}
        for role, engine in (('primary', 'pallas'), ('secondary', 'vesta')):
            point = _point_hex(cls.generators[engine])
            cls.metadata[role] = {'engine': engine, 'spartan_vk_digest_le': _le(11),
                'derand_key': {'h': point}, 'ipa_scalar_key': {'ck': [point], 'h': point}}
        cls.metadata_pin = canonical_sha256(cls.metadata)
        cls.bindings = ReplayKeyBindings.from_json(cls.metadata, cls.expected, cls.dimensions,
            expected_key_bindings_sha256=cls.metadata_pin)

    def test_metadata_requires_separate_pin_and_exact_identity(self):
        for pin in (None, b'', self.metadata_pin.hex(), bytearray(self.metadata_pin)):
            with self.assertRaises(ValueError):
                ReplayKeyBindings.from_json(self.metadata, self.expected, self.dimensions,
                    expected_key_bindings_sha256=pin)
        changed = deepcopy(self.metadata)
        changed['primary']['spartan_vk_digest_le'] = _le(12)
        with self.assertRaisesRegex(ValueError, 'digest mismatch'):
            ReplayKeyBindings.from_json(changed, self.expected, self.dimensions,
                expected_key_bindings_sha256=self.metadata_pin)
        changes = [('network', 'mainnet'), ('k', True), ('nova_version', '0.75.0'),
                   ('verifier_key_sha256', '0'*64), ('verifier_dimensions_sha256', '0'*64),
                   ('extra', 1)]
        for name, value in changes:
            changed = deepcopy(self.metadata)
            changed[name] = value
            with self.subTest(name=name), self.assertRaises(ValueError):
                ReplayKeyBindings.from_json(changed, self.expected, self.dimensions,
                    expected_key_bindings_sha256=canonical_sha256(changed))
        for point in ('00'*32, '00'*31+'80'):
            changed = deepcopy(self.metadata)
            changed['primary']['derand_key']['h'] = point
            with self.assertRaises(ValueError):
                ReplayKeyBindings.from_json(changed, self.expected, self.dimensions,
                    expected_key_bindings_sha256=canonical_sha256(changed))
        with self.assertRaises(TypeError):
            ReplayKeyBindings()
        with self.assertRaises(FrozenInstanceError):
            self.bindings.pp_digest = 1

    def test_synthetic_keccak_checks_labels_objects_states_and_surplus(self):
        operations = [('absorb', b'vk', bytes(32)), ('squeeze', b't', None),
                      ('dom_sep', b'IPA', None), ('absorb', b'L', b'object'),
                      ('squeeze', b'r', None)]
        for engine in ('pallas', 'vesta'):
            events = synthetic_keccak(engine, operations)
            def execute(rows):
                replay = _KeccakReplay(engine, rows)
                for op, label, value in operations:
                    if op == 'absorb':
                        replay.absorb(label, value)
                    elif op == 'dom_sep':
                        replay.dom_sep(label)
                    else:
                        replay.squeeze(label)
                replay.finish()
                return replay
            self.assertEqual(execute(events).squeezes, 2)
            for index, key, value in ((1, 'label_hex', b'U'.hex()),
                                       (1, 'repr_hex', '01'*32),
                                       (2, 'challenge_le', '00'*32),
                                       (3, 'data_hex', b'ipa'.hex()),
                                       (4, 'sequence', 1)):
                bad = deepcopy(events)
                bad[index][key] = value
                with self.assertRaises(ValueError):
                    execute(bad)
            bad = deepcopy(events)
            bad[1]['after']['buffer_hex'] = ''
            with self.assertRaises(ValueError):
                execute(bad)
            for bad in (events[:-1], events+[events[-1]]):
                with self.assertRaises(ValueError):
                    execute(bad)

    def test_sumcheck_absorbs_recompressed_row_without_linear_term(self):
        row, initial = (3, 5, 7), 13
        for engine, curve in (('pallas', PALLAS), ('vesta', VESTA)):
            q = curve.q
            encoded = b''.join(value.to_bytes(32, 'little') for value in row)
            events = synthetic_keccak(engine, [('absorb', b'p', encoded), ('squeeze', b'c', None)])
            te = _KeccakReplay(engine, events)
            proof = {'compressed_polys': [{'coeffs_except_linear_term': [_le(v) for v in row]}]}
            actual, challenges = _sumcheck(te, proof, initial, 1, 3)
            te.finish()
            c = challenges[0]
            linear = (initial-2*row[0]-sum(row[1:])) % q
            self.assertEqual(actual, (row[0]+linear*c+row[1]*c*c+row[2]*c*c*c) % q)
            full = b''.join(v.to_bytes(32, 'little') for v in (row[0], linear, row[1], row[2]))
            wrong = synthetic_keccak(engine, [('absorb', b'p', full), ('squeeze', b'c', None)])
            with self.assertRaises(ValueError):
                _sumcheck(_KeccakReplay(engine, wrong), proof, initial, 1, 3)

    def test_poseidon_capture_only_checks_inputs_snapshots_and_truncation(self):
        # This full hash is synthetic, not a computed Poseidon sponge value.
        inputs, full = [1, 2, 3], (1 << 200)+17
        for engine in ('pallas', 'vesta'):
            rows = synthetic_ro(engine, inputs, 128, full)
            self.assertEqual(_native_ro(engine, rows, inputs, 128), 17)
            bad = deepcopy(rows)
            bad[1]['value_le'] = _le(7)
            with self.assertRaises(ValueError):
                _native_ro(engine, bad, inputs, 128)
            bad = deepcopy(rows)
            bad[-1]['challenge_le'] = _le(18)
            with self.assertRaises(ValueError):
                _native_ro(engine, bad, inputs, 128)
            bad = deepcopy(rows)
            bad[-1]['after']['state_le'] = []
            with self.assertRaises(ValueError):
                _native_ro(engine, bad, inputs, 128)

    def test_small_nifs_folds_derandomization_and_representation_orders(self):
        for curve in (PALLAS, VESTA):
            g, q = self.generators[curve.name], curve.q
            left = _Instance(curve.name, curve.mul(g, 2), curve.mul(g, 3), 5, (7, 11))
            ordinary = _Instance(curve.name, curve.mul(g, 13), None, 1, (17, 19))
            cross = curve.mul(g, 23)
            folded = _fold(left, ordinary, cross, 3, ordinary=True)
            self.assertEqual(folded.comm_w, curve.mul(g, 2+3*13))
            self.assertEqual(folded.comm_e, curve.mul(g, 3+3*23))
            self.assertEqual((folded.u, folded.x), (8, (58, 68)))
            right = _Instance(curve.name, curve.mul(g, 29), curve.mul(g, 31), 37, (41, 43))
            relaxed = _fold(left, right, cross, 3)
            self.assertEqual(relaxed.comm_e, curve.mul(g, 3+3*23+9*31))
            self.assertEqual(relaxed.u, 5+3*37)
            h = curve.mul(g, 47)
            key = _EngineKey(curve.name, 11, h, g, g)
            unblinded = _derandomize(relaxed, key, 5, 7)
            self.assertEqual(unblinded.comm_w, curve.mul(g, 2+3*29-47*5))
            self.assertEqual(unblinded.comm_e, curve.mul(g, 3+3*23+9*31-47*7))
            transcript = NovaTranscript(curve.name, b'unit')
            representation = _instance_repr(transcript, left)
            self.assertEqual(representation[130:162], left.u.to_bytes(32, 'little'))
            self.assertEqual(representation[162:], b''.join(x.to_bytes(32, 'little') for x in left.x))
            self.assertEqual(_ro_instance(left)[6], left.u)
            self.assertEqual(_ro_instance(left)[7:11], [7, 0, 0, 0])
            with self.assertRaises(ValueError):
                _fold(left, right, cross, 1 << 128)

    def test_factorized_ipa_matches_small_dense_source_weights(self):
        rng = random.Random(0x495041)
        for curve in (PALLAS, VESTA):
            q = curve.q
            for rounds in range(1, 6):
                challenges = tuple(rng.randrange(1, q) for _ in range(rounds))
                point = tuple(rng.randrange(q) for _ in range(rounds))
                result = ipa_factors(point, challenges, q)
                source_weights = list(weights(challenges, q))
                dense = 0
                for i, weight in enumerate(source_weights):
                    eq = 1
                    for j, coordinate in enumerate(point):
                        eq = eq*(coordinate if (i >> (rounds-1-j)) & 1 else 1-coordinate) % q
                    dense = (dense+eq*weight) % q
                self.assertEqual(result['b_hat'], dense)
                for index, weight in result['selected_weights'].items():
                    self.assertEqual(weight, source_weights[index])
                self.assertEqual(result['s0'], source_weights[0])
                with self.assertRaises(ValueError):
                    ipa_factors(point, (0,)+challenges[1:], q)

    def test_trace_schema_budgets_and_proof_binding_fail_closed(self):
        events = synthetic_keccak('pallas', [])
        stream = {'kind': 'keccak', 'engine': 'pallas', 'field_role': 'pallas_scalar',
                  'session': 0, 'events': events}
        trace = synthetic_report([stream])
        self.assertEqual(len(_validate_trace(trace)), 1)
        for mutate in (lambda x: x['streams'].append(deepcopy(stream)),
                       lambda x: x['streams'][0].update(field_role='pallas_base'),
                       lambda x: x['streams'][0]['events'][0].update(sequence=True),
                       lambda x: x['streams'][0]['events'][0]['after'].update(round=-1),
                       lambda x: x['streams'][0]['events'][0]['after'].update(buffer_hex='00'*1025)):
            bad = deepcopy(trace)
            mutate(bad)
            with self.assertRaises(ValueError):
                _validate_trace(bad)
        for name, value in (('complete_capture', False), ('complete_capture', 1),
                            ('panic_is_rejection', True), ('panic_is_rejection', 0),
                            ('events', 2), ('recorded_event_bytes', 1),
                            ('max_streams', 8), ('max_events', 4000)):
            bad = deepcopy(trace)
            bad[name] = value
            with self.assertRaises(ValueError):
                _validate_trace(bad)
        with self.assertRaisesRegex(ValueError, 'missing or extra'):
            replay_production(self.decoded, self.expected, self.bindings, trace,
                expected_trace_sha256=canonical_sha256(trace))
        scalar = next(span for span in self.decoded.spans if span.path == 'ri_primary')
        changed = self.raw[:scalar.start]+bytes(32)+self.raw[scalar.start+32:]
        admitted = decode_proof(changed, self.dimensions)
        with self.assertRaisesRegex(ValueError, 'proof identity'):
            replay_production(admitted, self.expected, self.bindings, None,
                expected_trace_sha256=bytes(32))


class ActualRetainedProductionReplay(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bundle = (FIXTURES/'nht4-genesis-0-2020-k5.nht4').read_bytes()
        cls.expected = load_expected_json((FIXTURES/'nht4-genesis-0-2020-k5.expected.json').read_bytes())
        cls.dimensions = load_dimensions_json(
            (FIXTURES/'nht4-genesis-0-2020-k5.dimensions.json').read_bytes(), cls.expected,
            expected_descriptor_sha256=DIMENSION_PIN)
        cls.raw = cls.bundle[HEADER_BYTES:]
        cls.decoded = decode_proof(cls.raw, cls.dimensions)
        cls.metadata = json.loads((FIXTURES/'nht4-genesis-0-2020-k5.key-bindings.json').read_bytes())
        cls.trace = json.loads((FIXTURES/'nht4-genesis-0-2020-k5.trace.json').read_bytes())
        cls.bindings = ReplayKeyBindings.from_json(cls.metadata, cls.expected, cls.dimensions,
            expected_key_bindings_sha256=KEY_BINDINGS_PIN)
        cls.result = replay_production(cls.decoded, cls.expected, cls.bindings, cls.trace,
                                       expected_trace_sha256=TRACE_PIN)

    @staticmethod
    def stream(trace, kind, engine, session=0):
        return next(stream for stream in trace['streams']
                    if (stream['kind'], stream['engine'], stream['session']) == (kind, engine, session))

    def diagnostic_repin(self, trace, decoded=None, expected=None):
        """TEST ONLY: own a new pin to reach semantic checks after transport.

        This explicitly does not authenticate a changed capture as native output.
        The normal path always uses the independent literal TRACE_PIN above.
        """
        trace['events'] = sum(len(stream['events']) for stream in trace['streams'])
        trace['recorded_event_bytes'] = sum(
            len(json.dumps(event, sort_keys=True, separators=(',', ':')).encode())
            for stream in trace['streams'] for event in stream['events'])
        return replay_production(decoded or self.decoded, expected or self.expected,
            self.bindings, trace, expected_trace_sha256=canonical_sha256(trace))

    def changed_proof(self, path):
        """TEST ONLY: own changed statement pins to inspect proof-object binding."""
        span = next(span for span in self.decoded.spans if span.path == path)
        from proof_codec import SCALAR_MODULI
        old = int.from_bytes(self.raw[span.start:span.start+32], 'little')
        changed = (old+1) % SCALAR_MODULI[span.engine]
        raw = self.raw[:span.start]+changed.to_bytes(32, 'little')+self.raw[span.start+32:]
        decoded = decode_proof(raw, self.dimensions)
        bundle = self.bundle[:HEADER_BYTES]+raw
        policy = replace(self.expected, proof_sha256=sha256(raw).digest(),
                         bundle_sha256=sha256(bundle).digest())
        return decoded, policy

    def test_actual_capture_matches_all_keccak_objects_and_challenges(self):
        self.assertEqual(canonical_sha256(self.metadata), KEY_BINDINGS_PIN)
        self.assertEqual(canonical_sha256(self.trace), TRACE_PIN)
        self.assertTrue(self.result['passed'])
        self.assertEqual(self.result['poseidon_absorption_streams_checked'], 5)
        self.assertEqual(self.trace['events'], 517)
        self.assertEqual(self.trace['recorded_event_bytes'], 367197)
        pallas, vesta = self.result['engines']
        self.assertEqual((pallas['keccak_events'], pallas['keccak_squeezes']), (204, 100))
        self.assertEqual((vesta['keccak_events'], vesta['keccak_squeezes']), (154, 75))
        for engine in self.result['engines']:
            self.assertTrue(engine['outer_terminal_checked'])
            self.assertTrue(engine['batch_terminal_checked'])
            self.assertFalse(engine['matrix_evaluations_verified'])
            self.assertFalse(engine['ipa']['generator_msm_verified'])
        for name in ('proof_verified', 'bitvm2_script_verified',
                     'poseidon_hashes_independently_verified', 'ipa_generator_msm_verified'):
            self.assertFalse(self.result[name])

    def test_capture_pin_is_independent_of_edited_trace_metadata(self):
        changed = deepcopy(self.trace)
        changed['recorded_event_bytes'] += 1
        with self.assertRaises(ValueError):
            replay_production(self.decoded, self.expected, self.bindings, changed,
                               expected_trace_sha256=TRACE_PIN)
        changed = deepcopy(self.trace)
        event = self.stream(changed, 'keccak', 'pallas')['events'][1]
        event['repr_hex'] = '00'*32
        # Fixed source digest rejects edited transport even if its accounting
        # and an unrelated self-reported hash are coherently changed.
        changed['recorded_event_bytes'] = sum(
            len(json.dumps(event, sort_keys=True, separators=(',', ':')).encode())
            for stream in changed['streams'] for event in stream['events'])
        with self.assertRaisesRegex(ValueError, 'digest mismatch'):
            replay_production(self.decoded, self.expected, self.bindings, changed,
                               expected_trace_sha256=TRACE_PIN)

    def test_diagnostic_repin_still_checks_source_objects_labels_states_and_order(self):
        # Re-pinning here is a test-only way to reach semantic comparisons. It
        # never upgrades modified bytes into an authenticated native capture.
        for engine in ('pallas', 'vesta'):
            for operation in ('vk', 'U', 'p', 'challenge', 'domain', 'order', 'state'):
                changed = deepcopy(self.trace)
                events = self.stream(changed, 'keccak', engine)['events']
                if operation in ('vk', 'U', 'p'):
                    label = operation.encode().hex()
                    event = next(event for event in events
                                 if event['op'] == 'absorb' and event['label_hex'] == label)
                    raw = bytearray.fromhex(event['repr_hex'])
                    raw[0] ^= 1
                    event['repr_hex'] = raw.hex()
                elif operation == 'challenge':
                    event = next(event for event in events if event['op'] == 'squeeze')
                    event['challenge_le'] = _le((int.from_bytes(bytes.fromhex(event['challenge_le']), 'little')+1)
                                                % (PALLAS.q if engine == 'pallas' else VESTA.q))
                elif operation == 'domain':
                    next(event for event in events if event['op'] == 'dom_sep')['data_hex'] = b'ipa'.hex()
                elif operation == 'order':
                    left = next(i for i, event in enumerate(events)
                                if event['op'] == 'absorb' and event['label_hex'] == b'L'.hex())
                    events[left], events[left+1] = events[left+1], events[left]
                    events[left]['sequence'], events[left+1]['sequence'] = left, left+1
                else:
                    event = next(event for event in events if event['op'] == 'squeeze')
                    value = bytearray.fromhex(event['after']['state_hex'])
                    value[0] ^= 1
                    event['after']['state_hex'] = value.hex()
                with self.subTest(engine=engine, operation=operation), self.assertRaises(ValueError):
                    self.diagnostic_repin(changed)

    def test_diagnostic_poseidon_inputs_truncation_and_proof_objects_are_bound(self):
        for operation in ('input', 'truncation'):
            changed = deepcopy(self.trace)
            events = self.stream(changed, 'poseidon_base', 'vesta', 1)['events']
            if operation == 'input':
                events[1]['value_le'] = _le(0)
            else:
                events[-1]['challenge_le'] = _le(
                    (int.from_bytes(bytes.fromhex(events[-1]['challenge_le']), 'little')+1) % (1 << 128))
            with self.subTest(operation=operation), self.assertRaises(ValueError):
                self.diagnostic_repin(changed)
        for path, message in (('ri_primary', 'Poseidon absorption'),
            ('snark_primary.sc_proof_outer.compressed_polys[0].coeffs_except_linear_term[0]', 'transcript mismatch'),
            ('snark_primary.eval_E', 'outer sumcheck terminal')):
            decoded, policy = self.changed_proof(path)
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, message):
                self.diagnostic_repin(deepcopy(self.trace), decoded, policy)

    def test_native_only_poseidon_boundary_is_explicit_after_diagnostic_repin(self):
        changed = deepcopy(self.trace)
        event = self.stream(changed, 'poseidon_base', 'vesta', 1)['events'][-1]
        old = int.from_bytes(bytes.fromhex(event['after']['state_le'][0]), 'little')
        # Changing a bit ABOVE the returned128 bits leaves the fold challenge
        # unchanged. A separately authenticated original capture rejects it;
        # a diagnostic caller-owned replacement pin cannot make this checker
        # independently evaluate the Poseidon permutation.
        event['after']['state_le'][0] = _le(old ^ (1 << 128))
        with self.assertRaisesRegex(ValueError, 'digest mismatch'):
            replay_production(self.decoded, self.expected, self.bindings, changed,
                               expected_trace_sha256=TRACE_PIN)
        diagnostic = self.diagnostic_repin(changed)
        self.assertTrue(diagnostic['passed'])
        self.assertFalse(diagnostic['poseidon_hashes_independently_verified'])
        self.assertFalse(diagnostic['proof_verified'])

    def test_unabsorbed_a_hat_remains_an_explicit_generator_msm_boundary(self):
        decoded, policy = self.changed_proof('snark_primary.eval_arg.a_hat')
        # Source does not absorb a_hat. It is taken from the decoded proof and
        # changes the required generator-side equality, not transcript bytes.
        diagnostic = self.diagnostic_repin(deepcopy(self.trace), decoded, policy)
        actual_ipa = self.result['engines'][0]['ipa']
        changed_ipa = diagnostic['engines'][0]['ipa']
        self.assertNotEqual(changed_ipa['a_hat_le'], actual_ipa['a_hat_le'])
        self.assertNotEqual(changed_ipa['generator_residual'], actual_ipa['generator_residual'])
        self.assertEqual(changed_ipa['challenges_le'], actual_ipa['challenges_le'])
        self.assertFalse(diagnostic['ipa_generator_msm_verified'])
        self.assertFalse(diagnostic['proof_verified'])


if __name__ == '__main__':
    unittest.main()
