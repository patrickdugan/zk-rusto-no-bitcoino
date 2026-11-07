#!/usr/bin/env python3
"""Require a fresh `m13-verify verify` run to report exactly the recorded
counts: the statement, proof sizes, every BLAKE3 role and every KoalaBear
operation. Wall time is the only field allowed to differ.

usage: compare_counts.py RECORDED.json FRESH.json
"""
import json
import os
import sys


def main() -> int:
    recorded, fresh = (json.load(open(p)) for p in sys.argv[1:3])
    keys = ['status', 'statement', 'wrap_file_bytes', 'wrap_proof_bytes', 'public_values_len',
            'blake3', 'blake3_compressions_total', 'koalabear_ops']
    bad = [k for k in keys if recorded.get(k) != fresh.get(k)]
    if fresh.get('koalabear_ops') is None:
        bad.append('koalabear_ops missing: build with --features opcount and the patched p3-koala-bear')
    for k in bad:
        print(f'differs: {k}\n  recorded {recorded.get(k)}\n  fresh    {fresh.get(k)}')
        if os.environ.get('GITHUB_ACTIONS') == 'true':
            # Annotations are readable without signing in; job logs are not.
            print(f'::error title=m13 count differs::{k}: recorded {recorded.get(k)} fresh {fresh.get(k)}')
    if bad:
        return 1
    print('counts identical to the recorded run:', ', '.join(keys))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
