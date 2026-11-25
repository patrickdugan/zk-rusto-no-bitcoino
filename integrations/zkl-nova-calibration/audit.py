"""Finite substitution differential and certificate fixture replay."""
import copy
import hashlib
import json
from pathlib import Path

import term_reference as ref


def main():
    for seed in range(4096):
        t, s, k = ref.generate(seed, 5)
        assert ref.substitute(t, k, s) == ref.standard_substitute(t, k, s)
        b = ref.Builder()
        b.beta(ref.app(ref.lam(t), s))
        assert ref.replay(b.wire(str(seed)))
    cases = ref.fixtures()
    coverage = set(r[0] for c in cases for r in c['rows'])
    assert coverage == set(range(17))
    rejected = 0
    for i, field, val in [(0, 4, 1), (1, 4, 1), (2, 4, 1), (3, 4, 1), (3, 3, 1), (1, 2, 0)]:
        case = copy.deepcopy(cases[0]); case['rows'][i][field] = val
        try:
            ref.replay(case)
        except ValueError:
            rejected += 1
        else:
            raise AssertionError('accepted mutated certificate')
    raw = (json.dumps({'schema': 'zkl-term-v1', 'cases': cases}, sort_keys=True, separators=(',', ':')) + '\n').encode()
    assert raw == Path(__file__).with_name('term-fixtures.json').read_bytes()
    print(json.dumps({'differential_cases': 4096, 'public_fixtures': len(cases),
                      'honest_rows': sum(len(c['rows']) for c in cases), 'local_rules_covered': len(coverage),
                      'mutated_native_rows_rejected': rejected, 'fixture_sha256': hashlib.sha256(raw).hexdigest()}))


if __name__ == '__main__':
    main()
