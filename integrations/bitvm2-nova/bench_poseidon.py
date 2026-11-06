"""Generate independent optimized Poseidon/native vectors, never proofs.

Only the actual-key parameter fixture plus its independent literal pin is used.
Native expected outputs are not consumed by the Python computation.
"""
import argparse
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import time

from bench_compact import peak_rss
from nht4 import load_expected_json
from poseidon_reference import PoseidonParameters, PoseidonRO
from proof_codec import load_dimensions_json

FIXTURES = Path(__file__).resolve().parent/'fixtures'
PARAMETERS_SHA256 = 'b55fa125133315243cb299ee7603c5f0508d68abf64f0dab43ecba4a0d09fa67'
DIMENSIONS_SHA256 = 'de6333df2e41b5f5bae1c103fab862f8d6022fd54abeb80ba61920bc9f360edc'
LENGTHS = (0, 1, 4, 5, 6, 23, 24, 25, 47, 48, 49, 52)
PATTERNS = ('zero', 'counter', 'alternating', 'sparse')
MAX_CASES, MAX_FILE_BYTES = 256, 8 << 20


def _read(path, cap):
    if path.stat().st_size > cap:
        raise ValueError('input file byte budget')
    with path.open('rb') as source:
        raw = source.read(cap+1)
    if len(raw) > cap:
        raise ValueError('input file grew beyond byte budget')
    return raw


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError('duplicate parameter JSON key')
        result[key] = value
    return result


def load_parameters(path):
    if len(PARAMETERS_SHA256) != 64 or any(c not in '0123456789abcdef' for c in PARAMETERS_SHA256):
        raise ValueError('actual-key Poseidon parameter export has not been independently pinned')
    raw = _read(path, 2 << 20)
    if sha256(raw).hexdigest() != PARAMETERS_SHA256:
        raise ValueError('independent canonical parameter file pin mismatch')
    expected = load_expected_json(_read(FIXTURES/'nht4-genesis-0-2020-k5.expected.json', 1 << 16))
    dimensions = load_dimensions_json(_read(FIXTURES/'nht4-genesis-0-2020-k5.dimensions.json', 1 << 14),
        expected, expected_descriptor_sha256=bytes.fromhex(DIMENSIONS_SHA256))
    data = json.loads(raw, object_pairs_hook=_pairs)
    return PoseidonParameters.from_json(data, expected, dimensions,
        expected_parameters_sha256=bytes.fromhex(PARAMETERS_SHA256))


def _le(value):
    return value.to_bytes(32, 'little').hex()


def _inputs(pattern, length, modulus):
    if pattern == 'zero':
        return [0]*length
    if pattern == 'counter':
        return list(range(1, length+1))
    if pattern == 'alternating':
        return [0 if i % 2 == 0 else modulus-1 for i in range(length)]
    result = [0]*length
    if length:
        result[length//2] = 1
        if length > 1:
            result[-1] = modulus-1
    return result


def build_cases(parameters):
    cases = []
    forced_reductions = 0
    squeezes = 0
    coverage = []

    def session(engine, mode, values, name, single=None):
        nonlocal forced_reductions, squeezes
        profile = parameters.profile(engine, mode)
        ro, events = PoseidonRO(profile), []
        def absorb(value):
            ro.absorb(value)
            events.append({'op': 'absorb', 'value_le': _le(value)})
        def squeeze(bits, force):
            nonlocal forced_reductions, squeezes
            returned = ro.squeeze(bits, force)
            full = ro.last_full_hash
            if bits == 255 and force and not ((full >> 254) & 1) and returned < full:
                forced_reductions += 1
            events.append({'op': 'squeeze', 'num_bits': bits, 'start_with_one': force,
                'expected_full_hash_le': _le(full), 'expected_challenge_le': _le(returned),
                'expected_state_le': [_le(value) for value in ro.state]})
            squeezes += 1
        for value in values:
            absorb(value)
        if single:
            squeeze(*single)
        else:
            squeeze(128, False)
            squeeze(250, True)  # Consecutive squeeze retains the prior full hash.
            absorb(profile.modulus-1)
            squeeze(255, True)  # Source addition can reduce modulo the field.
            squeeze(1, False)
        cases.append({'name': name, 'engine': engine, 'mode': mode, 'events': events, 'accept': True})

    for engine in ('pallas', 'vesta'):
        for mode in ('wide', 'narrow'):
            profile = parameters.profile(engine, mode)
            for length in LENGTHS:
                for pattern in PATTERNS:
                    session(engine, mode, _inputs(pattern, length, profile.modulus),
                            f'{engine}/{mode}/{length}/{pattern}')
            session(engine, mode, [7], f'{engine}/{mode}/full-hash-return', (255, False))
            session(engine, mode, [7], f'{engine}/{mode}/one-bit-forcing', (1, True))
            coverage.append({'engine': engine, 'mode': mode, 'lengths': list(LENGTHS),
                             'patterns': list(PATTERNS)})

    def negative(engine, label, events, mode='wide'):
        cases.append({'name': f'{engine}/bad/{label}', 'engine': engine,
                      'mode': mode, 'events': events, 'accept': False})

    zero = '00'*32
    squeeze = {'op': 'squeeze', 'num_bits': 128, 'start_with_one': False,
               'expected_full_hash_le': zero, 'expected_challenge_le': zero,
               'expected_state_le': [zero]}
    for engine in ('pallas', 'vesta'):
        modulus = parameters.profile(engine, 'wide').modulus
        for i, value in enumerate((_le(modulus), 'ff'*32, '00'*31, '00'*33,
                                    True, 0, 'xy'*32, '00'*31+'AB')):
            negative(engine, f'absorbed-scalar-{i}', [{'op': 'absorb', 'value_le': value}])
        for i, bits in enumerate((0, 256, -1, True, 1.0, '128')):
            event = deepcopy(squeeze); event['num_bits'] = bits
            negative(engine, f'bit-count-{i}', [event])
        for i, flag in enumerate((0, None)):
            event = deepcopy(squeeze); event['start_with_one'] = flag
            negative(engine, f'force-type-{i}', [event])
        for i, state in enumerate(([], [zero, zero])):
            event = deepcopy(squeeze); event['expected_state_le'] = state
            negative(engine, f'poststate-arity-{i}', [event])
        negative(engine, 'too-many-absorbed', [{'op': 'absorb', 'value_le': zero}]*1025)
        negative(engine, 'too-many-events', [{'op': 'absorb', 'value_le': zero}]*2049)
        event = deepcopy(squeeze); del event['expected_challenge_le']
        negative(engine, 'missing-event-field', [event])
        negative(engine, 'unknown-operation', [{'op': 'hash'}])
        negative(engine, 'nonobject-event', [None])
        negative(engine, 'unknown-mode', [], 'Wide')
        negative(engine, 'bool-mode', [], True)
    for i, engine in enumerate((None, True, 'bn256', 'pallas_scalar')):
        cases.append({'name': f'bad-engine/{i}', 'engine': engine, 'mode': 'wide', 'events': [], 'accept': False})
    if len(cases) > MAX_CASES or len({case['name'] for case in cases}) != len(cases):
        raise ValueError('Poseidon corpus count/name budget')
    if not forced_reductions:
        raise AssertionError('corpus failed to exercise actual255-bit field reduction')
    return cases, {'profiles': coverage, 'native_squeezes_expected': squeezes,
                   'forced_255_field_reductions_expected': forced_reductions}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--parameters', type=Path,
        default=FIXTURES/'nht4-genesis-0-2020-k5.poseidon.json')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    start = time.perf_counter()
    cases, coverage = build_cases(load_parameters(args.parameters))
    data = {'schema': 'bitvm2-nova-poseidon-cases/v1',
            'source': {'parameters_sha256': PARAMETERS_SHA256}, 'cases': cases}
    payload = (json.dumps(data, separators=(',', ':'))+'\n').encode('ascii')
    if len(payload) > MAX_FILE_BYTES:
        raise ValueError('Poseidon corpus byte budget')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(payload)
    print(json.dumps({'cases': len(cases), 'accepted': sum(case['accept'] for case in cases),
        'admission_rejections': sum(not case['accept'] for case in cases),
        'bytes': len(payload), 'input_sha256': sha256(payload).hexdigest(),
        'parameters_sha256': PARAMETERS_SHA256, 'coverage': coverage,
        'wall_seconds': time.perf_counter()-start, 'peak_rss_bytes': peak_rss(),
        'native_proofs_verified': 0, 'scope': 'independent Poseidon reference vectors only'}))


if __name__ == '__main__':
    main()
