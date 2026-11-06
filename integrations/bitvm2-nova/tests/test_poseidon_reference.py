"""Synthetic schedules and independently pinned actual native parameter checks.

The small-round test constants below are deliberately weak synthetic data.
They exercise arithmetic, shape guards and source scheduling, and are never
presented as production Nova constants or cryptographic proof evidence.
"""
from copy import deepcopy
from dataclasses import FrozenInstanceError
from hashlib import sha256
import json
from pathlib import Path
import unittest

from nht4 import load_expected_json
from proof_codec import BASE_MODULI, NOVA_CRATE_SHA256, load_dimensions_json
from poseidon_reference import (IO_BASE, MAX_INPUTS, MAX_PARAMETERS_BYTES, MODES,
    SCHEMA, PoseidonParameters, PoseidonProfile, PoseidonRO, io_tag,
    load_parameters_json, permute, sponge_hash)

FIXTURES = Path(__file__).resolve().parents[1]/'fixtures'
DIMENSIONS_PIN = bytes.fromhex('de6333df2e41b5f5bae1c103fab862f8d6022fd54abeb80ba61920bc9f360edc')
ACTUAL_PARAMETERS_PIN = bytes.fromhex('b55fa125133315243cb299ee7603c5f0508d68abf64f0dab43ecba4a0d09fa67')
ACTUAL_TRACE_PIN = bytes.fromhex('394d90b302b2fe6b8f5c0a65ada372d820996f3230770a816961a75cefec59b8')


def pin(data):
    return sha256(json.dumps(data, sort_keys=True, separators=(',', ':')).encode()).digest()


def le(value):
    return value.to_bytes(32, 'little').hex()


def synthetic_parameters(expected, dimensions):
    def profile(mode):
        rate, width = MODES[mode]
        rf, rp = 2, 2
        return {'arity': rate, 'width': width, 'rate': rate, 'capacity': 1,
            'rf': rf, 'rp': rp, 's': 'Standard', 'ht': 'Sponge',
            # Deliberately nonsymmetric matrices detect row/column confusion.
            'mds': [[le(1+(3*i+7*j) % 17) for j in range(width)] for i in range(width)],
            'psm': [[le(1+(11*i+5*j) % 19) for j in range(width)] for i in range(width)],
            'crc': [le(i+1) for i in range(rf*width+rp)],
            'sm': [{'w_hat': [le(1+r+2*i) for i in range(width)],
                    'v_rest': [le(3+r+5*i) for i in range(width-1)]} for r in range(rp)]}
    result = {'schema': SCHEMA, 'nova_version': '0.76.0',
        'nova_crate_sha256': NOVA_CRATE_SHA256, 'header_revision': expected.header_revision,
        'network': expected.network, 'k': expected.k,
        'verifier_key_sha256': expected.verifier_key_sha256.hex(),
        'verifier_dimensions_sha256': dimensions.descriptor_sha256.hex()}
    for role, engine in (('primary', 'pallas'), ('secondary', 'vesta')):
        result[role] = {'engine': engine, 'field_role': engine+'_base',
                       'wide': profile('wide'), 'narrow': profile('narrow')}
    return result


def independent_schedule(profile, state):
    """Dense-matrix equivalent of the source schedule, separate test code."""
    p, width, half = profile.modulus, profile.width, profile.rf//2
    constants = iter(profile.crc)
    values = [(value+next(constants)) % p for value in state]
    for r in range(profile.rf+profile.rp):
        partial = half <= r < half+profile.rp
        full_last = r == profile.rf+profile.rp-1
        if partial:
            values[0] = (values[0]**5+next(constants)) % p
        else:
            values = [value**5 % p for value in values]
            if not full_last:
                values = [(value+next(constants)) % p for value in values]
        if r == half-1:
            matrix = tuple(zip(*profile.psm, strict=True))
        elif partial:
            w, v = profile.sm[r-half]
            matrix = [w]
            for j in range(1, width):
                row = [0]*width
                row[0], row[j] = v[j-1], 1
                matrix.append(row)
        else:
            matrix = profile.mds
        values = [sum(row[i]*values[i] for i in range(width)) % p for row in matrix]
    try:
        next(constants)
    except StopIteration:
        return tuple(values)
    raise AssertionError('synthetic schedule left unused keys')


class PoseidonReference(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.expected = load_expected_json((FIXTURES/'nht4-genesis-0-2020-k5.expected.json').read_bytes())
        cls.dimensions = load_dimensions_json(
            (FIXTURES/'nht4-genesis-0-2020-k5.dimensions.json').read_bytes(), cls.expected,
            expected_descriptor_sha256=DIMENSIONS_PIN)
        cls.data = synthetic_parameters(cls.expected, cls.dimensions)
        cls.pin = pin(cls.data)  # Caller-owned synthetic test pin, not production.
        cls.params = PoseidonParameters.from_json(cls.data, cls.expected, cls.dimensions,
                                                  expected_parameters_sha256=cls.pin)

    def test_source_schedule_matches_dense_expansion_and_mixed_orientation(self):
        for engine in BASE_MODULI:
            for mode in MODES:
                profile = self.params.profile(engine, mode)
                for state in ([0]*profile.width, list(range(profile.width)),
                              [profile.modulus-1]*profile.width):
                    self.assertEqual(permute(profile, state), independent_schedule(profile, state))
                changed = deepcopy(self.data)
                changed['primary' if engine == 'pallas' else 'secondary'][mode]['crc'][-1] = le(0)
                altered = PoseidonParameters.from_json(changed, self.expected, self.dimensions,
                    expected_parameters_sha256=pin(changed)).profile(engine, mode)
                self.assertNotEqual(permute(profile, list(range(profile.width))),
                                    permute(altered, list(range(profile.width))))

    def test_io_tag_uses_u128_wrapping_and_skips_empty_absorb(self):
        mask = (1 << 128)-1
        for n in (0, 1, 4, 5, 6, 23, 24, 25, 48, MAX_INPUTS):
            operations = ([n+(1 << 31)] if n else [])+[1, 0]
            power, expected = 1, 0
            for value in operations:
                power = power*IO_BASE & mask
                expected = (expected+power*value) & mask
            self.assertEqual(io_tag(n), expected)
        self.assertEqual(io_tag(0), IO_BASE)
        self.assertNotEqual(io_tag(0), (IO_BASE*(1 << 31)+IO_BASE*IO_BASE) & mask)
        for bad in (True, -1, MAX_INPUTS+1, '1'):
            with self.assertRaises(ValueError):
                io_tag(bad)

    def test_multiple_full_round_halves_keep_post_keys_and_sparse_offsets(self):
        # RF2 alone cannot exercise ordinary full rounds on both sides of the
        # sparse section. These remain explicitly synthetic test profiles.
        for rf in (4, 8):
            for engine in BASE_MODULI:
                for mode in MODES:
                    changed = deepcopy(self.data)
                    role = 'primary' if engine == 'pallas' else 'secondary'
                    data = changed[role][mode]
                    data['rf'] = rf
                    data['crc'] = [le(i+1) for i in range(rf*data['width']+data['rp'])]
                    profile = PoseidonParameters.from_json(changed, self.expected, self.dimensions,
                        expected_parameters_sha256=pin(changed)).profile(engine, mode)
                    state = [i*17+3 for i in range(profile.width)]
                    self.assertEqual(permute(profile, state), independent_schedule(profile, state))

    def test_sponge_rate_boundaries_add_to_residual_lanes_without_padding(self):
        for engine in BASE_MODULI:
            for mode in MODES:
                profile = self.params.profile(engine, mode)
                r, p = profile.rate, profile.modulus
                for n in (0, 1, r-1, r, r+1, 2*r, 2*r+1):
                    inputs = list(range(1, n+1))
                    tag = io_tag(n)
                    state = [tag]+[0]*r
                    blocks = [inputs[i:i+r] for i in range(0, n, r)] or [[]]
                    for block in blocks:
                        for i, value in enumerate(block, 1):
                            state[i] = (state[i]+value) % p
                        state = list(independent_schedule(profile, state))
                    self.assertEqual(sponge_hash(profile, inputs), state[1])
                inputs = list(range(1, r+2))
                first = list(permute(profile, [io_tag(len(inputs))]+inputs[:r]))
                wrong = [first[0], inputs[-1]]+[0]*(r-1)
                self.assertNotEqual(sponge_hash(profile, inputs), permute(profile, wrong)[1])

    def test_ro_squeezes_use_fresh_sponges_and_keep_full_hash(self):
        for engine in BASE_MODULI:
            for mode in MODES:
                profile = self.params.profile(engine, mode)
                ro = PoseidonRO(profile)
                for value in (1, 2, 3):
                    ro.absorb(value)
                first = sponge_hash(profile, (1, 2, 3))
                self.assertEqual(ro.squeeze(8), first & 255)
                self.assertEqual(ro.last_full_hash, first)
                self.assertEqual(ro.state, (first,))
                second = sponge_hash(profile, (first,))
                self.assertEqual(ro.squeeze(128), second & ((1 << 128)-1))
                ro.absorb(7)
                third = sponge_hash(profile, (second, 7))
                self.assertEqual(ro.squeeze(250, True), (third & ((1 << 250)-1)) | (1 << 249))
                self.assertEqual(ro.state, (third,))
                self.assertNotEqual(sponge_hash(profile, (first & 255,)), second)

    def test_255bit_forcing_matches_field_addition_and_rejection_is_atomic(self):
        for engine in BASE_MODULI:
            profile = self.params.profile(engine, 'narrow')
            ro = PoseidonRO(profile)
            ro.absorb(1)
            full = sponge_hash(profile, (1,))
            expected = (full | (1 << 254)) % profile.modulus
            self.assertEqual(ro.squeeze(255, True), expected)
            self.assertEqual(ro.state, (full,))
            before = ro.state
            for bits, force in ((0, False), (256, False), (True, False), (8, 1), (8, None)):
                with self.assertRaises(ValueError):
                    ro.squeeze(bits, force)
                self.assertEqual(ro.state, before)
            for bad in (-1, profile.modulus, True, None):
                with self.assertRaises(ValueError):
                    ro.absorb(bad)
                self.assertEqual(ro.state, before)

    def test_parameter_pins_shapes_policy_and_immutability(self):
        changed = deepcopy(self.data)
        changed['primary']['wide']['crc'][0] = le(77)
        with self.assertRaisesRegex(ValueError, 'digest mismatch'):
            PoseidonParameters.from_json(changed, self.expected, self.dimensions,
                                          expected_parameters_sha256=self.pin)
        for name, bad in (('network', 'mainnet'), ('k', True), ('verifier_key_sha256', '0'*64),
                          ('verifier_dimensions_sha256', '0'*64), ('schema', 'other')):
            changed = deepcopy(self.data)
            changed[name] = bad
            with self.subTest(name=name), self.assertRaises(ValueError):
                PoseidonParameters.from_json(changed, self.expected, self.dimensions,
                                              expected_parameters_sha256=pin(changed))
        for key, bad in (('rf', 3), ('rf', True), ('rp', 0), ('rp', 129),
                         ('width', 24), ('capacity', 2), ('s', 'Strengthened'),
                         ('mds', []), ('psm', [[]]), ('crc', []), ('sm', [])):
            changed = deepcopy(self.data)
            changed['primary']['wide'][key] = bad
            with self.subTest(key=key), self.assertRaises(ValueError):
                PoseidonParameters.from_json(changed, self.expected, self.dimensions,
                                              expected_parameters_sha256=pin(changed))
        changed = deepcopy(self.data)
        changed['primary']['wide']['sm'][0]['v_rest'][0] = le(BASE_MODULI['pallas'])
        with self.assertRaises(ValueError):
            PoseidonParameters.from_json(changed, self.expected, self.dimensions,
                                          expected_parameters_sha256=pin(changed))
        with self.assertRaises(FrozenInstanceError):
            self.params.parameters_sha256 = bytes(32)
        with self.assertRaises(FrozenInstanceError):
            self.params.profile('pallas').rf = 4
        for cls in (PoseidonProfile, PoseidonParameters):
            with self.assertRaises(TypeError):
                cls()
        copy = self.params.json()
        copy['primary']['wide']['crc'][0] = le(99)
        self.assertNotEqual(copy, self.params.json())

    def test_bounded_transport_and_value_guards(self):
        raw = json.dumps(self.data).encode()
        parsed = load_parameters_json(raw, self.expected, self.dimensions,
                                      expected_parameters_sha256=self.pin)
        self.assertEqual(parsed, self.params)
        for bad in (raw[:-1]+b',"k":5}', b'{', b'\xff', b'['*2000+b'0'+b']'*2000,
                    b'x'*(MAX_PARAMETERS_BYTES+1), raw.decode()):
            with self.assertRaises(ValueError):
                load_parameters_json(bad, self.expected, self.dimensions,
                                      expected_parameters_sha256=self.pin)
        profile = self.params.profile('pallas')
        for bad in (None, [0]*(profile.width-1), [0]*(profile.width+1),
                    [True]*profile.width, [-1]*profile.width, [profile.modulus]*profile.width):
            with self.assertRaises(ValueError):
                permute(profile, bad)
        for bad in (None, (0,)*(MAX_INPUTS+1), [True], [-1], [profile.modulus]):
            with self.assertRaises(ValueError):
                sponge_hash(profile, bad)
        for engine, mode in (([], 'wide'), ('pallas', []), ('bn256', 'wide'), ('pallas', 'other')):
            with self.assertRaises(ValueError):
                self.params.profile(engine, mode)


class ActualPoseidonReference(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.expected = load_expected_json((FIXTURES/'nht4-genesis-0-2020-k5.expected.json').read_bytes())
        cls.dimensions = load_dimensions_json(
            (FIXTURES/'nht4-genesis-0-2020-k5.dimensions.json').read_bytes(), cls.expected,
            expected_descriptor_sha256=DIMENSIONS_PIN)
        cls.raw = (FIXTURES/'nht4-genesis-0-2020-k5.poseidon.json').read_bytes()
        cls.params = load_parameters_json(cls.raw, cls.expected, cls.dimensions,
                                          expected_parameters_sha256=ACTUAL_PARAMETERS_PIN)
        trace_raw = (FIXTURES/'nht4-genesis-0-2020-k5.trace.json').read_bytes()
        cls.trace = json.loads(trace_raw)
        if pin(cls.trace) != ACTUAL_TRACE_PIN:
            raise AssertionError('actual native capture pin mismatch')

    def test_actual_vk_profiles_have_verified_export_counts(self):
        self.assertEqual(sha256(self.raw).digest(), ACTUAL_PARAMETERS_PIN)
        self.assertEqual(self.params.parameters_sha256, ACTUAL_PARAMETERS_PIN)
        for engine in BASE_MODULI:
            for mode, rate, width, rp, crc in (('wide', 24, 25, 59, 259),
                                              ('narrow', 5, 6, 56, 104)):
                profile = self.params.profile(engine, mode)
                self.assertEqual((profile.rate, profile.width, profile.rf, profile.rp),
                                 (rate, width, 8, rp))
                self.assertEqual((len(profile.crc), len(profile.sm)), (crc, rp))

    def test_all_five_native_full_hashes_match_independent_arithmetic(self):
        checks = []
        for stream in self.trace['streams']:
            if stream['kind'] == 'poseidon_base':
                inputs = [int.from_bytes(bytes.fromhex(event['value_le']), 'little')
                          for event in stream['events'] if event['op'] == 'absorb']
                full = sponge_hash(self.params.profile(stream['engine'], 'wide'), inputs)
                native = int.from_bytes(bytes.fromhex(stream['events'][-1]['after']['state_le'][0]), 'little')
                self.assertEqual(full, native)
                checks.append((stream['engine'], stream['session'], len(inputs)))
        self.assertEqual(checks, [('pallas', 0, 20), ('pallas', 1, 34),
                                  ('vesta', 0, 52), ('vesta', 1, 9), ('vesta', 2, 34)])

    def test_actual_constant_substitution_cannot_self_authenticate_with_vk_digest(self):
        changed = self.params.json()
        original_vk = changed['verifier_key_sha256']
        value = int.from_bytes(bytes.fromhex(changed['primary']['wide']['crc'][0]), 'little')
        changed['primary']['wide']['crc'][0] = le(value ^ 1)
        self.assertEqual(changed['verifier_key_sha256'], original_vk)
        with self.assertRaisesRegex(ValueError, 'digest mismatch'):
            PoseidonParameters.from_json(changed, self.expected, self.dimensions,
                                          expected_parameters_sha256=ACTUAL_PARAMETERS_PIN)


if __name__ == '__main__':
    unittest.main()
