import hashlib
import random
import unittest

from production_transcript import (
    ENGINES, MAX_BUFFER, MAX_ROUND, NovaTranscript, keccak256,
)


class ProductionTranscriptTests(unittest.TestCase):
    def test_keccak_padding_and_upstream_pallas_golden(self):
        self.assertEqual(keccak256(b'').hex(),
                         'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470')
        self.assertNotEqual(keccak256(b''), hashlib.sha3_256(b'').digest())
        transcript = NovaTranscript('pallas', b'test')
        transcript.absorb_scalar(b's1', 2)
        transcript.absorb_scalar(b's2', 5)
        self.assertEqual(transcript.squeeze(b'c1').to_bytes(32, 'little').hex(),
                         '60dba8657186ff1abbeb237854707faf6ea79361546f8aae65a8fbb722c9ca0c')
        transcript.absorb_scalar(b's3', 128)
        self.assertEqual(transcript.squeeze(b'c2').to_bytes(32, 'little').hex(),
                         '8bb5dcd9f95115fbc178a1e76d04955423610f5788c7ef2ed200611fecfdf60b')

    def test_raw_state_reductions_and_bits(self):
        rng = random.Random(0x4e6f5452)
        for engine in ENGINES:
            for bits in (2, 3, 7, 8, 9, 63, 64, 65, 127, 128, 129, 253, 254):
                for force in (False, True):
                    t = NovaTranscript(engine, rng.randbytes(17))
                    t.absorb_bytes(b'input', rng.randbytes(257))
                    copy = t.clone()
                    value = t.squeeze_bits(b'c', bits, force)
                    reduced = copy.squeeze(b'c')
                    raw = int.from_bytes(bytes(t.snapshot()['state']), 'little')
                    want = raw & ((1 << bits) - 1)
                    if force:
                        want |= 1 << (bits - 1)
                    self.assertEqual(value, want)
                    self.assertEqual(reduced, raw % t.scalar_modulus)
                    self.assertEqual(t.snapshot(), copy.snapshot())
                    self.assertEqual(t.snapshot()['transcript_buffer'], [])

    def test_scalar_vector_and_point_representations(self):
        for engine, (base, scalar) in ENGINES.items():
            t = NovaTranscript(engine, b'repr')
            self.assertEqual(t.scalar_repr(scalar - 1), (scalar - 1).to_bytes(32, 'little'))
            self.assertEqual(t.scalars_repr([0, 1]), bytes(32) + b'\1' + bytes(31))
            self.assertEqual(t.scalars_repr([]), b'')
            point = (base - 1, 2)
            self.assertEqual(t.affine_repr(point),
                             (base - 1).to_bytes(32, 'little') + (2).to_bytes(32, 'little'))
            self.assertEqual(t.commitment_repr(point), t.affine_repr(point) + b'\0')
            self.assertEqual(t.commitment_repr(None), bytes(64) + b'\1')
            t.absorb_scalars(b'p', [3, 7])
            copy = NovaTranscript(engine, b'repr')
            copy.absorb_bytes(b'p', t.scalar_repr(3) + t.scalar_repr(7))
            self.assertEqual(t.snapshot(), copy.snapshot())

    def test_serialize_replay_and_clone_independence(self):
        for engine in ENGINES:
            t = NovaTranscript(engine, b'init')
            t.dom_sep(b'domain')
            t.absorb_scalar(b'x', 77)
            t.absorb_commitment(b'C', None)
            snapshot = t.snapshot()
            copy = NovaTranscript.from_snapshot(engine, snapshot)
            snapshot['state'][0] ^= 1
            snapshot['transcript_buffer'].clear()
            self.assertEqual(copy.squeeze(b'c'), t.squeeze(b'c'))
            clone = t.clone()
            clone.absorb_scalar(b'x', 1)
            self.assertNotEqual(clone.squeeze(b'c'), t.squeeze(b'c'))
            empty = t.snapshot()
            del empty['transcript_buffer']
            self.assertEqual(NovaTranscript.from_snapshot(engine, empty).snapshot(), t.snapshot())

    def test_domains_labels_round_order_and_buffer_reset(self):
        reference = NovaTranscript('pallas', b'init')
        reference.absorb_scalar(b'x', 9)
        want = reference.squeeze(b'c')
        for field in ('init', 'absorb', 'squeeze', 'domain', 'round'):
            t = NovaTranscript('pallas', b'other' if field == 'init' else b'init')
            t.absorb_scalar(b'y' if field == 'absorb' else b'x', 9)
            if field == 'domain':
                t.dom_sep(b'domain')
            if field == 'round':
                state = t.snapshot()
                state['round'] = 1
                t = NovaTranscript.from_snapshot('pallas', state)
            self.assertNotEqual(t.squeeze(b'd' if field == 'squeeze' else b'c'), want)
        # Exact upstream encoding has no length prefixes; callers own object grammar.
        a, b = NovaTranscript('pallas', b'i'), NovaTranscript('pallas', b'i')
        a.absorb_bytes(b'a', b'bc')
        b.absorb_bytes(b'ab', b'c')
        self.assertEqual(a.squeeze(b'c'), b.squeeze(b'c'))
        state = reference.snapshot()
        self.assertEqual(state['round'], 1)
        self.assertEqual(state['transcript_buffer'], [])

    def test_malformed_inputs_reject_without_mutation(self):
        for engine in ENGINES:
            t = NovaTranscript(engine, b'invalid')
            original = t.snapshot()
            actions = [
                lambda: t.absorb_scalar(b'x', -1),
                lambda: t.absorb_scalar(b'x', t.scalar_modulus),
                lambda: t.absorb_scalar(b'x', True),
                lambda: t.absorb_scalars(b'x', [0, t.scalar_modulus]),
                lambda: t.absorb_affine(b'x', None),
                lambda: t.absorb_affine(b'x', (0, 0)),
                lambda: t.absorb_affine(b'x', (t.base_modulus, 0)),
                lambda: t.squeeze_bits(b'c', 1),
                lambda: t.squeeze_bits(b'c', 255),
                lambda: t.squeeze_bits(b'c', True),
                lambda: t.squeeze_bits(b'c', 8, 1),
                lambda: t.absorb_bytes(b'x' * 1025, b''),
                lambda: t.absorb_bytes(b'x', bytes(MAX_BUFFER)),
            ]
            for action in actions:
                with self.assertRaises(ValueError):
                    action()
                self.assertEqual(t.snapshot(), original)
            snapshot = t.snapshot()
            snapshot['round'] = MAX_ROUND
            overflow = NovaTranscript.from_snapshot(engine, snapshot)
            with self.assertRaises(ValueError):
                overflow.squeeze(b'overflow')
            self.assertEqual(overflow.snapshot(), snapshot)

    def test_malformed_snapshots(self):
        original = NovaTranscript('pallas', b'state').snapshot()
        for key, value in [('round', -1), ('round', MAX_ROUND + 1), ('round', True),
                           ('state', []), ('state', [0] * 65), ('state', [256] * 64),
                           ('state', [False] * 64), ('transcript_buffer', [-1]),
                           ('extra', [])]:
            snap = dict(original)
            snap[key] = value
            with self.assertRaises(ValueError):
                NovaTranscript.from_snapshot('pallas', snap)
        for engine in ('pallas-evm', 'bn256', None):
            with self.assertRaises(ValueError):
                NovaTranscript(engine, b'test')


if __name__ == '__main__':
    unittest.main()
