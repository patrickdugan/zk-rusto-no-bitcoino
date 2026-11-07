"""Projected size of the IPA generator MSM under the measured point backend.

Pure arithmetic over measured inputs; nothing here is executed in Script.
The retained k=5 key's IPA terminal computes ck_hat = <s, G> over every
generator (524,288 primary, 16,384 secondary; NATIVE-CONFORMANCE.md). Its
point additions are counted for the best Pippenger window and priced with
the measured M22 grouped complete-addition graph (GROUPED-CONVOLUTION.md):
61,523,789 / 61,626,177 Script bytes and 7,476 asserted words per addition.
Doublings are priced as additions (the complete graph handles both).
"""
from math import ceil

SCALAR_BITS = 255
GENERATORS = dict(primary=524_288, secondary=16_384)
COMPLETE_ADD_BYTES = dict(primary=61_523_789, secondary=61_626_177)
COMPLETE_ADD_WORDS = 7_476
WOTS_SIGNATURE_BYTES = 200
FOREST_POLICY_BYTES = 5 << 28


def pippenger_additions(n, bits=SCALAR_BITS):
    """(additions, window) of a bucket MSM, minimized over the window width."""
    if type(n) is not int or n < 1 or type(bits) is not int or bits < 1:
        raise ValueError('positive point count and scalar width required')
    best = None
    for window in range(1, 25):
        rounds = ceil(bits/window)
        # n bucket insertions plus 2^(c+1) running-sum additions per window,
        # then `window` doublings and one addition to combine each window.
        total = rounds*(n + (1 << (window+1))) + rounds*(window+1)
        if best is None or total < best[0]:
            best = (total, window)
    return best


def projection():
    roles = {}
    for role, n in GENERATORS.items():
        additions, window = pippenger_additions(n)
        roles[role] = dict(generators=n, window=window, point_additions=additions,
            disproof_script_bytes=additions*COMPLETE_ADD_BYTES[role],
            asserted_words=additions*COMPLETE_ADD_WORDS,
            assertion_signature_bytes=additions*COMPLETE_ADD_WORDS*WOTS_SIGNATURE_BYTES)
    total = sum(r['disproof_script_bytes'] for r in roles.values())
    signatures = sum(r['assertion_signature_bytes'] for r in roles.values())
    return dict(roles=roles, disproof_script_bytes=total, assertion_signature_bytes=signatures,
        forest_policy_ratio=total/FOREST_POLICY_BYTES, measured=False,
        basis='measured M22 grouped complete addition x Pippenger addition count')
