# RH-CRYPTO-26 / RH-02: NTT-prime construction baseline

**Status:** exact standard-library toy experiment. This is a small, implementable finite-field investigation, separate from the existing Groth16/Nova proving code. Mathematical assumption ledger: [MathCan RH-01](https://github.com/patrickdugan/MathCan/blob/research/rh-crypto26-assumptions-20261122/research/rh_crypto26/ASSUMPTION_LEDGER.md).

A proof of Dirichlet GRH improves the effective search guarantees for prime moduli in specified arithmetic progressions. For a radix-two transform of length \`2^k\`, a primitive root of that order in the multiplicative group of \`F_p\` requires \`p ≡ 1 (mod 2^k)\`. This simple condition predates the 2026 RH proof.

The runnable baseline constructs the first suitable prime in a fixed 8–24-bit interval using two independently formulated searches: direct stepping over \`1 mod 2^k\` candidates, and an odd-integer scan that filters congruences. Each candidate's primality is checked by exhaustive trial division up to its square root. The algorithm then constructs a primitive root, verifies its exact order, compares an in-place radix-two NTT against a quadratic DFT, and checks the inverse. Each integer test and butterfly operation has a finite receipt.

\`\`\`bash
python -m unittest research.rh_crypto26.test_ntt_prime_scan -v
python -m research.rh_crypto26.ntt_prime_scan --bit-width 20 --two-adicity 8
\`\`\`

**Interpretation gate.** Direct stepping necessarily visits fewer *integers* than the naive odd scan; the two methods perform the same primality tests in this construction. This is a programming baseline, not a novel GRH algorithm or a security result. Field-modulus search must be separated from integer labels assigned to x-coordinates on a chosen elliptic curve.

Before any ZK-performance claim, expand to validated larger fields and record modular reduction timing, arithmetic circuit constraints, prover FFT cost, security parameters, and primality/root certificates. Conditional GRH bounds should enter as symbolic performance guarantees with exact quantifiers and effective constants, rather than as invented measurements.

In pairing-based systems, a group with smooth \`p-1\` is not itself evidence that curve-group discrete logarithms are easy. KZG/Groth16 security assumptions require separate scrutiny. STARKs require independent analysis of FRI soundness, hash commitments, and challenge security.
