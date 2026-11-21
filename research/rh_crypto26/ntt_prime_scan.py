"""RH-CRYPTO-26 / RH-02: deterministic toy NTT-prime selection and exact transform checks.

Bit widths 8..24 only. The exhaustive trial-divisor primality test is suitable
for these toy fields and gives a standalone proof of primality by enumeration.
Dirichlet GRH is *not* needed to find these primes or to run an NTT.

Run: python -m research.rh_crypto26.ntt_prime_scan --bit-width 20 --two-adicity 8
"""
from __future__ import annotations

import argparse
import json
import math
import random


def is_prime_by_trial(n: int):
    """Return (prime, modular divisibility tests), deterministic for every n."""
    if n < 2:
        return False, 0
    if n == 2:
        return True, 0
    if n % 2 == 0:
        return False, 1
    tests = 1
    for divisor in range(3, math.isqrt(n) + 1, 2):
        tests += 1
        if n % divisor == 0:
            return False, tests
    return True, tests


def distinct_prime_factors(n: int):
    result = []
    for d in range(2, math.isqrt(n) + 1):
        if n % d == 0:
            result.append(d)
            while n % d == 0:
                n //= d
    if n > 1:
        result.append(n)
    return result


def first_prime_in_class(bit_width: int, two_adicity: int, direct: bool):
    if bit_width < 8 or bit_width > 24 or two_adicity < 1 or two_adicity >= bit_width:
        raise ValueError("require 8 <= bits <= 24 and 1 <= k < bits")
    lower, upper = 1 << (bit_width - 1), 1 << bit_width
    modulus = 1 << two_adicity
    start = lower + ((1 - lower) % modulus) if direct else (lower | 1)
    stride = modulus if direct else 2
    visited, primality_checks, divisions = 0, 0, 0
    for p in range(start, upper, stride):
        visited += 1
        if p % modulus != 1:
            continue
        primality_checks += 1
        is_p, ops = is_prime_by_trial(p)
        divisions += ops
        if is_p:
            return {
                "p": p, "integers_visited": visited,
                "primality_checks": primality_checks, "divisibility_tests": divisions,
                "search": "congruence-stepped" if direct else "odd-integer-scan",
            }
    raise ValueError("no suitable prime in requested bit interval")


def primitive_root_mod_prime(p: int):
    factors = distinct_prime_factors(p - 1)
    for g in range(2, p):
        if all(pow(g, (p - 1) // q, p) != 1 for q in factors):
            return g
    raise AssertionError("primitive generator missing")


def primitive_power_of_two_root(p: int, k: int):
    n = 1 << k
    if (p - 1) % n:
        raise ValueError("2^k must divide p-1")
    g = primitive_root_mod_prime(p)
    omega = pow(g, (p - 1) // n, p)
    if pow(omega, n, p) != 1 or pow(omega, n // 2, p) == 1:
        raise AssertionError("root does not have exact 2^k order")
    return omega, g


def ntt(vector: list[int], omega: int, p: int):
    """Iterative radix-two NTT, returns (values, butterfly count)."""
    a = [x % p for x in vector]
    n = len(a)
    if n < 2 or (n & (n - 1)):
        raise ValueError("NTT size must be a power of two >= 2")
    if pow(omega, n, p) != 1 or pow(omega, n // 2, p) == 1:
        raise ValueError("omega is not a primitive size-n root")
    j = 0
    for i in range(1, n):
        bit = n >> 1
        while j & bit:
            j ^= bit
            bit >>= 1
        j ^= bit
        if i < j:
            a[i], a[j] = a[j], a[i]
    butterflies = 0
    length = 2
    while length <= n:
        wlen = pow(omega, n // length, p)
        for offset in range(0, n, length):
            w = 1
            for j in range(length // 2):
                u = a[offset + j]
                v = a[offset + j + length // 2] * w % p
                a[offset + j] = (u + v) % p
                a[offset + j + length // 2] = (u - v) % p
                w = w * wlen % p
                butterflies += 1
        length <<= 1
    return a, butterflies


def naive_dft(vector: list[int], omega: int, p: int):
    n = len(vector)
    return [sum(vector[j] * pow(omega, i * j, p) for j in range(n)) % p
            for i in range(n)]


def run_case(bit_width=20, two_adicity=8, check_log_size=6, seed=20261122):
    stepped = first_prime_in_class(bit_width, two_adicity, direct=True)
    scanned = first_prime_in_class(bit_width, two_adicity, direct=False)
    if stepped["p"] != scanned["p"]:
        raise AssertionError("search methods disagree")
    p = stepped["p"]
    certificate, _ = is_prime_by_trial(p)
    if not certificate:
        raise AssertionError("trial division rejected selected modulus")
    omega, g = primitive_power_of_two_root(p, two_adicity)
    n = 1 << min(check_log_size, two_adicity)
    subroot = pow(omega, (1 << two_adicity) // n, p)
    rng = random.Random(seed * 1000003 + p)
    data = [rng.randrange(p) for _ in range(n)]
    forward, butterflies = ntt(data, subroot, p)
    if forward != naive_dft(data, subroot, p):
        raise AssertionError("radix-two NTT differs from independent DFT")
    reverse, reverse_butterflies = ntt(forward, pow(subroot, -1, p), p)
    recovered = [x * pow(n, -1, p) % p for x in reverse]
    if recovered != data:
        raise AssertionError("inverse NTT failed")
    return {
        "experiment": "RH-CRYPTO-26/RH-02", "evidence": "exact finite trial",
        "bit_width": bit_width, "two_adicity": two_adicity,
        "prime_modulus": p, "trial_division_primality_certified": True,
        "root_generator": g, "root_of_unity": omega,
        "root_exact_order": 1 << two_adicity,
        "progression": stepped, "odd_scan_control": scanned,
        "transform_checked_length": n, "butterflies": butterflies,
        "inverse_butterflies": reverse_butterflies,
        "independent_dft_equal": True, "inverse_equal": True,
        "claim_boundary": "No RH-dependent improvement or ZK-system security claim",
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--bit-width", type=int, default=20)
    ap.add_argument("--two-adicity", type=int, default=8)
    ap.add_argument("--check-log-size", type=int, default=6)
    ap.add_argument("--seed", type=int, default=20261122)
    args = ap.parse_args(argv)
    if args.check_log_size < 1:
        ap.error("check-log-size must be positive")
    print(json.dumps(run_case(args.bit_width, args.two_adicity,
                              args.check_log_size, args.seed),
                     indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
