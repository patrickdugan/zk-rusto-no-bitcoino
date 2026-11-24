# PRAXIS-04: QAP and extension-field tie regression

Source: Tse, Vanjani, Vesely, Praxis, https://arxiv.org/pdf/2611.28552
Sections 4.1–4.4, Lemmas 4.3, 4.5, 4.7, Section 5.1 equation (5).
PDF pp. 24–28 reviewed 2026-11-24. This is an independent toy reference,
not a full Praxis port or proof of its extraction theorem.

## Replay
```sh
node integrations/praxis-we/rank_gap_ties.js > /tmp/praxis-04.json
diff -u integrations/praxis-we/results/praxis-04-toy.json /tmp/praxis-04.json
```

## Parameters and certificates

Field F17; N=3; n=4; extension T^4-3, Frobenius T -> 13T.
The code excludes every monic linear and quadratic factor of the quartic
and compares extension multiplication to polynomial division. QAP uses
two cosets of order four and five separate points, D=13. Construct A/B
via Lagrange interpolation, compute P_W, interpolate allowed remainder,
divide both the key and ordinary numerators. Equality of RREF row bases
for the direct and two polynomial residual maps establishes equality of
their kernels for all 17^10 symmetric matrices, without enumerating those
matrices. The test space is homogeneous; exhaustive projective rank-one
directions cover every nonzero symmetric rank-one matrix up to scalar.

True fixture: x1*x2+x3=1, x1=x2. False fixture: 0=1 plus a padding constraint.
Six weighted copies (four U and two V coefficients) implement all three
ties in equation (5). With phi_i=e_i, the joint linear nullspace for the
false fixture has dimension seven. For every one of 5220 projective right
null vectors, intersect that space with the kernel of the map W -> Wv;
all intersections are zero. Thus every nonzero passing tied stack in this
one fixture has full row-space rank four. It is not a general theorem.

Controls: E12+E21 and its stack with E13+E31 pass the untied tests.
Their ranks are two and three, exact guessing probabilities 1/9 and 1/27
under independent r_i uniform on {2,3,4}. Both fail ties with identity
forms. When phi_3 is zero, weight E13+E31 by the U,V coefficients at e1.
This passes all ties and has rank two; e3 is a nonzero form-kernel vector.
This is expected, not a break of the paper's MSIS-based construction.
The toy forms are deterministic and no MSIS hardness claim is made.

PRAXIS-03 CI succeeded at checkpoint 6a4caefc7aa8c5b78a1e07e609b2b1a339ce63db,
runs 45374512110 and 45374511948. PRAXIS-04 results obtained by executing the
same JavaScript function that is committed as the standalone Node reference.

## Next gate PRAXIS-05
- Generalize QAP and ties to arkworks Fr and a parameterized small extension.
- Add independently evaluated QAP fixtures and nontrivial form maps.
- Implement exact centered sampler (Def. 5.3) and distinguish its histogram
  from the independent sampler here.
- Translate Figures 6/7 first, with deterministic test vectors and an explicit
  clear exponent oracle for every group element and pairing; then Figure 9/10.
  Stop before full-size ciphertexts until differential tests cover valid and
  invalid witnesses, quotient/remainder corruption, wrong statement, masks,
  zero key weight, and key recovery. Pin author Lean revision and PDF digest.
