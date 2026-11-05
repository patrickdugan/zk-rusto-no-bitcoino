"""Tiny deterministic inputs for the upstream WOTS adapter; no proof jobs."""
from hashlib import sha256
from pathlib import Path
import json
import random
from script import BASE, P, Q, limbs
from trace import multiplication_trace
from wots_leaf import WotsLeafTemplate


def main():
    cases = []
    for role, p in (('pallas_base', P), ('vesta_base', Q)):
        program, _ = multiplication_trace(role, 0, 0,
            context=sha256(b'WOTS-leaf-test-context').digest(), operation_id='wots/mul-bit')
        template = WotsLeafTemplate.from_program(program, 18)
        rows = [('zero', 0, 0, 0, 0, True),
                ('boundary', p-1, p-1, 1, p-3, True),
                ('bit-zero', p-1, p-1, 0, p-2, True),
                ('false-result', p-1, p-1, 1, p-2, False),
                ('noncanonical-t', p, 1, 1, 1, False),
                ('noncanonical-a', 1, p, 1, 2, False),
                ('noncanonical-result', 0, 0, 0, p, False),
                ('invalid-bit', 1, 2, 2, 6, False)]
        rng = random.Random(25002)
        for i in range(8):
            t, a, bit = rng.randrange(p), rng.randrange(p), rng.randrange(2)
            z = (2*t+bit*a) % p
            rows.append((f'random/{i}', t, a, bit, z, True))
            rows.append((f'random-false/{i}', t, a, bit, (z+1) % p, False))
        for name, t, a, bit, z, expected in rows:
            cases.append({'name': f'{role}/{name}', 'template': template.json(),
                'expected_template_id': template.digest().hex(),
                'words': limbs(t)+limbs(a)+[bit]+limbs(z), 'expected_correct': expected})
        for value in (BASE, 0x7fffffff, 0x80000000, 0xffffffff):
            words = [0]*28
            words[0] = value
            cases.append({'name': f'{role}/oversize-word/{value}', 'template': template.json(),
                'expected_template_id': template.digest().hex(), 'words': words, 'expected_correct': False})
    path = Path(__file__).resolve().parent/'results/wots-inputs.json'
    path.write_text(json.dumps(cases, separators=(',', ':'))+'\n', encoding='ascii', newline='\n')
    print(json.dumps({'cases': len(cases), 'bytes': path.stat().st_size,
                      'sha256': sha256(path.read_bytes()).hexdigest()}))


if __name__ == '__main__':
    main()
