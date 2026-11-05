"""Generate bounded differential admission cases; this verifies no Nova proof.

The production CLI requires a separately pinned descriptor plus the successful
native report that emitted it. The cases file never supplies dimensions or
policy. The Rust oracle receives those verifier-owned inputs separately.
"""
import argparse
from dataclasses import asdict
from hashlib import sha256
import json
from pathlib import Path
import re
import time

from bench_compact import peak_rss
from nht4 import bind_container, load_expected_json
from proof_codec import (BASE_MODULI, HEADER_WIDTHS, MAX_PROOF_BYTES,
                         SCALAR_MODULI, decode_proof, encode_proof,
                         load_dimensions_json)

FIXTURES = Path(__file__).resolve().parent/'fixtures'
MAX_CASES = 256
MAX_CORPUS_BYTES = 8 << 20
# Filled only after the retained verifier key emits its independently checked
# dimension descriptor. A native report's self-declared digest is not a pin.
PINNED_DIMENSIONS_SHA256 = 'de6333df2e41b5f5bae1c103fab862f8d6022fd54abeb80ba61920bc9f360edc'


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError('duplicate JSON key')
        result[key] = value
    return result


def _read(path, cap):
    if path.stat().st_size > cap:
        raise ValueError('input file byte budget')
    with path.open('rb') as source:
        value = source.read(cap+1)
    if len(value) > cap:
        raise ValueError('input file grew beyond byte budget')
    return value


def build_cases(raw, dimensions):
    """Build semantic/shape corpus from explicit admitted dimensions.

    Unit tests may supply clearly provisional dimensions. The production CLI
    below never calls this without the independently pinned native descriptor.
    """
    original = decode_proof(raw, dimensions)
    if encode_proof(original) != raw:
        raise AssertionError('genuine proof did not roundtrip')
    candidates, seen = [], set()

    def add(name, data):
        if data in seen:
            return
        if not name or len(name) > 192:
            raise ValueError('case name length')
        seen.add(data)
        candidates.append((name, data))

    def replace(span, value, name):
        add(name, raw[:span.start]+value+raw[span.start+span.size:])

    add('retained-original', raw)
    lengths = [span for span in original.spans if span.kind == 'length']
    groups = {}
    for span in lengths:
        groups.setdefault(re.sub(r'\[\d+\]', '[*]', span.path), []).append(span)
        replace(span, bytes([255])*8, 'huge-length/'+span.path)
    for members in groups.values():
        span = members[0]
        count = int.from_bytes(raw[span.start:span.start+8], 'little')
        replace(span, bytes(8), 'zero-length/'+span.path)
        replace(span, (count+1).to_bytes(8, 'little'), 'long-length/'+span.path)

    for engine in ('pallas', 'vesta'):
        scalar = next(s for s in original.spans if s.kind == 'scalar' and s.engine == engine)
        for label, value in (('scalar-modulus', SCALAR_MODULI[engine]),
                             ('scalar-maximum-canonical', SCALAR_MODULI[engine]-1),
                             ('scalar-u256-max', (1 << 256)-1)):
            replace(scalar, value.to_bytes(32, 'little'), label+'/'+engine)
        point = next(s for s in original.spans if s.kind == 'commitment' and s.engine == engine)
        replace(point, bytes(32), 'point-canonical-identity/'+engine)
        replace(point, bytes(31)+b'\x80', 'point-identity-sign-alias/'+engine)
        replace(point, BASE_MODULI[engine].to_bytes(32, 'little'), 'point-noncanonical-x/'+engine)
        flipped = bytearray(raw[point.start:point.start+32])
        flipped[-1] ^= 0x80
        replace(point, bytes(flipped), 'point-negated-y/'+engine)

    for i, bits in enumerate(HEADER_WIDTHS):
        span = next(s for s in original.spans if s.path == f'zn[{i}]')
        replace(span, (1 << bits).to_bytes(32, 'little'), f'output-width/{i}')

    # Shorter nonempty compressed coefficient rows are legitimate encodings.
    # They remain structural admission examples, not valid proof claims.
    for stage in ('outer', 'inner'):
        span = next(s for s in lengths if s.path ==
            f'snark_primary.sc_proof_{stage}.compressed_polys[0].coeffs_except_linear_term')
        count = int.from_bytes(raw[span.start:span.start+8], 'little')
        end = span.start+8+32*count
        shortened = (raw[:span.start]+(count-1).to_bytes(8, 'little')
                     +raw[span.start+8:end-32]+raw[end:])
        add('shorter-admitted-coefficient-row/'+stage, shortened)

    for label, data in (('empty', b''), ('truncated-last', raw[:-1]),
                        ('prepended-one', b'\0'+raw), ('appended-one', raw+b'\0'),
                        ('prepended-word', bytes(32)+raw), ('appended-word', raw+bytes(32)),
                        ('oversize-proof', bytes(MAX_PROOF_BYTES+1))):
        add(label, data)
    for offset in (1, 7, 31, lengths[0].start+4, lengths[-1].start+4):
        add(f'truncated-boundary/{offset}', raw[:offset])
    if len(candidates) > MAX_CASES:
        raise ValueError('admission case count exceeds fixed budget')

    cases = []
    for name, data in candidates:
        row = {'name': name, 'proof_hex': data.hex(), 'accept': False}
        try:
            decoded = decode_proof(data, dimensions)
        except ValueError:
            pass
        else:
            if encode_proof(decoded) != data:
                raise AssertionError('admitted mutation changed byte encoding')
            row.update(accept=True, expected_value=decoded.value,
                       expected_spans=[asdict(span) for span in decoded.spans])
        cases.append(row)
    return cases, {'all_length_prefixes': len(lengths),
                   'logical_length_classes': len(groups),
                   'original_spans': len(original.spans)}


def load_inputs(native_report, descriptor_path):
    """Require caller-pinned descriptor before processing the proof corpus."""
    if (len(PINNED_DIMENSIONS_SHA256) != 64
            or any(c not in '0123456789abcdef' for c in PINNED_DIMENSIONS_SHA256)):
        raise ValueError('trusted native dimension export has not been pinned')
    expected = load_expected_json(_read(FIXTURES/'nht4-genesis-0-2020-k5.expected.json', 1 << 16))
    descriptor_raw = _read(descriptor_path, 1 << 14)
    dimensions = load_dimensions_json(descriptor_raw, expected,
        expected_descriptor_sha256=bytes.fromhex(PINNED_DIMENSIONS_SHA256))
    report_raw = _read(native_report, 2 << 20)
    report = json.loads(report_raw, object_pairs_hook=_pairs)
    if type(report) is not dict:
        raise ValueError('native report must be a JSON object')
    native = report.get('native')
    if (report.get('passed') is not True or type(native) is not dict
            or type(native.get('native_nova_proofs_verified')) is not int
            or native['native_nova_proofs_verified'] != 1
            or native.get('verifier_key_sha256') != expected.verifier_key_sha256.hex()
            or native.get('verifier_dimensions_sha256') != PINNED_DIMENSIONS_SHA256
            or native.get('verifier_dimensions') != dimensions.json()):
        raise ValueError('successful matching native dimension report required')
    raw = bind_container(_read(FIXTURES/'nht4-genesis-0-2020-k5.nht4', MAX_PROOF_BYTES), expected).proof
    return raw, dimensions, {'native_report_sha256': sha256(report_raw).hexdigest(),
        'verifier_dimensions_sha256': PINNED_DIMENSIONS_SHA256,
        'retained_proof_sha256': expected.proof_sha256.hex()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native-report', type=Path, required=True)
    parser.add_argument('--descriptor', type=Path,
        default=FIXTURES/'nht4-genesis-0-2020-k5.dimensions.json')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    started = time.perf_counter()
    raw, dimensions, source = load_inputs(args.native_report, args.descriptor)
    cases, coverage = build_cases(raw, dimensions)
    data = {'schema': 'bitvm2-nova-admission-cases/v1', 'source': source, 'cases': cases}
    payload = (json.dumps(data, separators=(',', ':'))+'\n').encode('ascii')
    if len(payload) > MAX_CORPUS_BYTES:
        raise ValueError('admission corpus byte budget exceeded')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(payload)
    print(json.dumps({'cases': len(cases), 'accepted': sum(c['accept'] for c in cases),
        'rejected': sum(not c['accept'] for c in cases), 'bytes': len(payload),
        'input_sha256': sha256(payload).hexdigest(), 'coverage': coverage,
        'wall_seconds': time.perf_counter()-started, 'peak_rss_bytes': peak_rss(),
        'native_proofs_verified': 0, 'proving_jobs': 0, 'scope': 'structural admission only'}))


if __name__ == '__main__':
    main()
