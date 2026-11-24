#!/usr/bin/env python3
"""Paper-count sensitivity; not measured throughput or a security estimator."""
import math

GIB = 2**30
CIPHERTEXT = 7.88 * GIB
ENCRYPT = 2**34.2
DECRYPT = 2**33
print("Paper baseline (100-bit): {:.0f} ciphertext bytes".format(CIPHERTEXT))
print("Assumed effective Fq multiplications/second | encrypt seconds | decrypt seconds")
for rate in (1e6, 1e7, 1e8, 1e9):
    print(f"{rate:>14.0f} {ENCRYPT/rate:>18.2f} {DECRYPT/rate:>18.2f}")
print("Sequential read lower bound for one ciphertext pass")
for gib_s in (0.5, 1, 3, 7):
    print(f"{gib_s:g} GiB/s: {CIPHERTEXT/GIB/gib_s:.2f} s")
print("Fixed-N asymptotic search component relative to lambda=100")
for security in (100, 112, 120, 128):
    print(f"{security}: {math.exp2((security-100)/4):g}x (not an instantiated parameter set)")
