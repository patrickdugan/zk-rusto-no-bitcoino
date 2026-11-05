"""Emit bounded Python/actual-Nova transcript conformance cases; no proving."""
import argparse
import json
import random
from pathlib import Path

from production_transcript import ENGINES, MAX_ROUND, NovaTranscript


def fixtures():
    rng = random.Random(0x4e6f5452)
    cases = []
    for engine, (base, scalar) in ENGINES.items():
        for sample in range(8):
            label = b'test' if sample == 0 else rng.randbytes(sample * 17)
            t = NovaTranscript(engine, label)
            case = {'name': f'{engine}-{sample}', 'engine': engine,
                    'label_hex': label.hex(), 'initial_expected': t.snapshot(), 'events': []}
            def event(op, **args):
                challenge = None
                repr_ = None
                if op == 'absorb_bytes':
                    repr_ = bytes.fromhex(args['data_hex'])
                    t.absorb_bytes(bytes.fromhex(args['label_hex']), repr_)
                elif op == 'absorb_scalar':
                    value = int.from_bytes(bytes.fromhex(args['value_le']), 'little')
                    repr_ = t.scalar_repr(value)
                    t.absorb_scalar(bytes.fromhex(args['label_hex']), value)
                elif op == 'absorb_scalars':
                    values = [int.from_bytes(bytes.fromhex(v), 'little') for v in args['values_le']]
                    repr_ = t.scalars_repr(values)
                    t.absorb_scalars(bytes.fromhex(args['label_hex']), values)
                elif op in ('absorb_affine', 'absorb_commitment'):
                    p = args['point']
                    point = None if p['infinity'] else tuple(
                        int.from_bytes(bytes.fromhex(p[k]), 'little') for k in ('x_le', 'y_le'))
                    repr_ = (t.affine_repr(point) if op == 'absorb_affine' else t.commitment_repr(point))
                    getattr(t, op)(bytes.fromhex(args['label_hex']), point)
                elif op == 'dom_sep':
                    t.dom_sep(bytes.fromhex(args['data_hex']))
                elif op == 'squeeze':
                    challenge = t.squeeze(bytes.fromhex(args['label_hex']))
                elif op == 'squeeze_bits':
                    challenge = t.squeeze_bits(bytes.fromhex(args['label_hex']), args['num_bits'],
                                               args['start_with_one'])
                item = {'op': op, **args, 'expected': t.snapshot()}
                if repr_ is not None:
                    item['repr_hex'] = repr_.hex()
                if challenge is not None:
                    item['challenge_le'] = challenge.to_bytes(32, 'little').hex()
                case['events'].append(item)
            # Includes the release's existing golden scalar sequence.
            for label_, value in ((b's1', 2), (b's2', 5)):
                event('absorb_scalar', label_hex=label_.hex(), value_le=value.to_bytes(32, 'little').hex())
            event('squeeze', label_hex=b'c1'.hex())
            event('absorb_scalar', label_hex=b's3'.hex(), value_le=(128).to_bytes(32, 'little').hex())
            event('squeeze', label_hex=b'c2'.hex())
            for n in (0, 1, 135, 136, 137, 271):
                event('absorb_bytes', label_hex=b'bytes'.hex(), data_hex=rng.randbytes(n).hex())
            event('dom_sep', data_hex=b'Nova-production-conformance'.hex())
            event('absorb_scalars', label_hex=b'p'.hex(), values_le=[
                v.to_bytes(32, 'little').hex() for v in (0, 1, scalar - 1, rng.randrange(scalar))])
            event('absorb_scalars', label_hex=b'empty'.hex(), values_le=[])
            finite = {'infinity': False, 'x_le': (base - 1).to_bytes(32, 'little').hex(),
                      'y_le': (2).to_bytes(32, 'little').hex()}
            event('absorb_affine', label_hex=b'point'.hex(), point=finite)
            event('absorb_commitment', label_hex=b'comm'.hex(), point=finite)
            event('absorb_commitment', label_hex=b'zero'.hex(), point={
                'infinity': True, 'x_le': bytes(32).hex(), 'y_le': bytes(32).hex()})
            for bits in (2, 7, 8, 9, 63, 64, 65, 127, 128, 129, 253, 254):
                event('squeeze_bits', label_hex=b'bits'.hex(), num_bits=bits,
                      start_with_one=bool((bits + sample) % 2))
            event('squeeze', label_hex=b'final'.hex())
            cases.append(case)
            # Replay a snapshot containing absorbed bytes through upstream serde.
            snap = NovaTranscript(engine, b'restore')
            snap.absorb_scalar(b'x', sample)
            restored = snap.snapshot()
            restored['round'] = 0x0102030405060708 + sample
            replay = NovaTranscript.from_snapshot(engine, restored)
            c = replay.squeeze(b'replay')
            cases.append({'name': f'{engine}-restore-{sample}', 'engine': engine,
                          'label_hex': '', 'initial_state': restored, 'initial_expected': restored,
                          'events': [{'op': 'squeeze', 'label_hex': b'replay'.hex(),
                                      'challenge_le': c.to_bytes(32, 'little').hex(),
                                      'expected': replay.snapshot()}]})
        for bits in (0, 1, 255, 256, 1000000):
            cases.append({'name': f'{engine}-bad-bits-{bits}', 'engine': engine,
                          'label_hex': '', 'expected_error': 'admission', 'events': [
                              {'op': 'squeeze_bits', 'label_hex': '', 'num_bits': bits,
                               'start_with_one': False}]})
        negatives = [
            {'op': 'absorb_scalar', 'label_hex': '', 'value_le': scalar.to_bytes(32, 'little').hex()},
            {'op': 'absorb_scalar', 'label_hex': '', 'value_le': '00' * 31},
            {'op': 'absorb_scalar', 'label_hex': '', 'value_le': '00' * 33},
            {'op': 'absorb_scalars', 'label_hex': '', 'values_le': ['ff' * 32]},
            {'op': 'absorb_affine', 'label_hex': '', 'point': {
                'infinity': True, 'x_le': '00' * 32, 'y_le': '00' * 32}},
            {'op': 'absorb_affine', 'label_hex': '', 'point': {
                'infinity': False, 'x_le': '00' * 32, 'y_le': '00' * 32}},
            {'op': 'absorb_affine', 'label_hex': '', 'point': {
                'infinity': False, 'x_le': base.to_bytes(32, 'little').hex(), 'y_le': '00' * 32}},
            {'op': 'absorb_commitment', 'label_hex': '', 'point': {
                'infinity': True, 'x_le': '01' + '00' * 31, 'y_le': '00' * 32}},
            {'op': 'absorb_bytes', 'label_hex': '00' * 1025, 'data_hex': ''},
            {'op': 'dom_sep', 'data_hex': 'xy'},
        ]
        for i, item in enumerate(negatives):
            cases.append({'name': f'{engine}-bad-object-{i}', 'engine': engine,
                          'label_hex': '', 'expected_error': 'admission', 'events': [item]})
        for i, change in enumerate(({'state': [0] * 63}, {'state': [0] * 65},
                                    {'state': [256] * 64}, {'extra': []})):
            state = NovaTranscript(engine, b'').snapshot()
            state.update(change)
            cases.append({'name': f'{engine}-bad-state-{i}', 'engine': engine,
                          'label_hex': '', 'initial_state': state,
                          'expected_error': 'admission', 'events': []})
        overflow = NovaTranscript(engine, b'overflow').snapshot()
        overflow['round'] = MAX_ROUND
        cases.append({'name': f'{engine}-overflow', 'engine': engine, 'label_hex': '',
                      'initial_state': overflow, 'initial_expected': overflow,
                      'expected_error': 'upstream',
                      'events': [{'op': 'squeeze', 'label_hex': ''}]})
        # Missing buffer is explicitly supported by the release's deserializer.
        old = NovaTranscript(engine, b'old').snapshot()
        del old['transcript_buffer']
        t = NovaTranscript.from_snapshot(engine, old)
        cases.append({'name': f'{engine}-legacy-state', 'engine': engine, 'label_hex': '',
                      'initial_state': old, 'initial_expected': t.snapshot(), 'events': []})
    return cases


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cases', type=Path, required=True)
    args = parser.parse_args()
    cases = fixtures()
    payload = json.dumps(cases, separators=(',', ':')) + '\n'
    if len(payload.encode()) > 2 << 20:
        raise ValueError('oracle fixture file exceeds bound')
    args.cases.parent.mkdir(parents=True, exist_ok=True)
    args.cases.write_text(payload, encoding='utf-8')
    print(json.dumps({'cases': len(cases), 'accept_cases': sum('expected_error' not in c for c in cases),
                      'reject_cases': sum('expected_error' in c for c in cases),
                      'events': sum(len(c['events']) for c in cases),
                      'case_file_bytes': len(payload.encode()),
                      'backend': 'nova-snark=0.76.0/non-EVM',
                      'crate_sha256': 'c9bb3809a6c70057ea722c1c4fe5097cf29a3479d0b4671f3cddb1d81043bb31',
                      'crate_vcs': '98576efa884072bfe69bfad8f275a3a5cd8754e5',
                      'proving': False, 'complete_verifier': False}))


if __name__ == '__main__':
    main()
