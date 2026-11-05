"""Emit bounded retained-proof inputs for the native, verification-only oracle."""
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import struct
from nht4 import HEADER_BYTES, Q, bind_container, load_expected_json

ROOT = Path(__file__).resolve().parent
FIXTURE = ROOT/'fixtures/nht4-genesis-0-2020-k5.nht4'
POLICY = ROOT/'fixtures/nht4-genesis-0-2020-k5.expected.json'


def cases():
    raw = FIXTURE.read_bytes()
    expected = load_expected_json(POLICY.read_bytes())
    bind_container(raw, expected)
    result = []

    def add(name, data, policy=None, accept=False):
        owner = expected if policy is None else load_expected_json(json.dumps(policy).encode())
        try:
            bind_container(data, owner)
            actual = True
        except ValueError:
            actual = False
        if actual != accept:
            raise AssertionError(f'incorrect reference expectation: {name}')
        result.append({'name': name, 'bundle_hex': data.hex(), 'expected': owner.json(),
                       'accept': accept})

    def replace(offset, data):
        return raw[:offset]+data+raw[offset+len(data):]

    add('retained_genesis', raw, accept=True)
    add('empty', b'')
    add('header_only', raw[:HEADER_BYTES])
    add('truncated_header', raw[:HEADER_BYTES-1])
    add('truncated_proof', raw[:-1])
    add('prepended', b'\0'+raw)
    add('appended', raw+b'\0')
    add('network_magic', replace(0, b'NHC1'))
    add('unknown_magic', replace(0, b'BAD!'))
    for name, offset, number in [('zero_steps', 4, 0), ('changed_steps', 4, 405),
                                  ('zero_k', 8, 0), ('changed_k', 8, 10), ('oversized_k', 8, 65)]:
        add(name, replace(offset, struct.pack('<I', number)))
    add('noncanonical_scalar', replace(12, Q.to_bytes(32, 'little')))
    add('height_width', replace(12, (1 << 32).to_bytes(32, 'little')))
    add('hash_width', replace(44, (1 << 128).to_bytes(32, 'little')))
    add('work_width', replace(108, (1 << 200).to_bytes(32, 'little')))
    add('timestamp_width', replace(12+32*16, (1 << 32).to_bytes(32, 'little')))
    add('changed_initial_state', replace(44, (int.from_bytes(raw[44:76], 'little')+1).to_bytes(32, 'little')))
    add('proof_tamper', raw[:-1]+bytes([raw[-1]^1]))
    changed = deepcopy(expected.json())
    changed['proof_sha256'] = sha256(b'other proof').hexdigest()
    add('wrong_expected_proof', raw, changed)
    changed = deepcopy(expected.json())
    changed['bundle_sha256'] = sha256(b'other bundle').hexdigest()
    add('wrong_expected_bundle', raw, changed)
    return result


def main():
    rows = cases()
    out = ROOT/'results'
    out.mkdir(exist_ok=True)
    payload = {'schema': 'bitvm2-nova-nht4-cases/v1', 'cases': rows}
    (out/'nht4-inputs.json').write_text(json.dumps(payload, separators=(',', ':'))+'\n')
    result = {'framing_cases': len(rows), 'accepted_framing': sum(x['accept'] for x in rows),
              'rejected_framing': sum(not x['accept'] for x in rows),
              'retained_bundle_bytes': FIXTURE.stat().st_size,
              'retained_proof_bytes': FIXTURE.stat().st_size-HEADER_BYTES,
              'native_nova_proofs_verified': 0, 'bitvm2_script_verified': False,
              'note': 'Python checks bind framing/identity only; native oracle must verify proof.'}
    (out/'nht4-summary.json').write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result))


if __name__ == '__main__':
    main()
