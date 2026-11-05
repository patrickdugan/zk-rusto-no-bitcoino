import random
import unittest
import copy

from bench_spartan import encoded, native_corpus
from production_transcript import NovaTranscript
from script import P, Q, execute
from spartan_checks import (
    SumcheckShape, batch_initial_claim, batch_terminal, decompress,
    eq_evaluation, evaluate, fold_batched_sumcheck, fold_sumcheck,
    inner_terminal, outer_terminal, round_trace, sparse_evaluation,
    verify_batched_sumcheck, verify_sumcheck,
)


class SpartanChecksTests(unittest.TestCase):
    def test_reconstruction_and_independent_power_evaluation(self):
        rng = random.Random(7600)
        for p in (P, Q):
            for degree in (1, 2, 3):
                for _ in range(15):
                    row = [rng.randrange(p) for _ in range(degree)]
                    claim, point = rng.randrange(p), rng.randrange(p)
                    poly = decompress(row, claim, p)
                    self.assertEqual((poly[0]+sum(poly)) % p, claim)
                    self.assertEqual(evaluate(poly, point, p),
                                     sum(c*pow(point, i, p) for i, c in enumerate(poly)) % p)
        self.assertEqual(decompress([2, 0, 0], 11, P), (2, 7, 0, 0))

    def test_production_absorption_order_and_functional_state(self):
        for engine in ('pallas', 'vesta'):
            transcript = NovaTranscript(engine, b'spartan-tests')
            transcript.absorb_scalar(b'prelude', 19)
            before = transcript.snapshot()
            rows = [[7, 3, 0], [11, 13], [17]]
            result = fold_sumcheck(rows, 23, SumcheckShape(3, 3), transcript)
            independent, claim = transcript.clone(), 23
            for row, state in zip(rows, result.rounds, strict=True):
                # Byte concatenation here independently tests the vector repr:
                # no restored linear term and no vector-length prefix.
                independent.absorb_bytes(b'p', b''.join(v.to_bytes(32, 'little') for v in row))
                challenge = independent.squeeze(b'c')
                coeffs = (row[0], (claim-2*row[0]-sum(row[1:])) % transcript.scalar_modulus, *row[1:])
                claim = sum(c*pow(challenge, i, transcript.scalar_modulus)
                            for i, c in enumerate(coeffs)) % transcript.scalar_modulus
                self.assertEqual((state.challenge, state.claim_after), (challenge, claim))
            self.assertEqual(result.final_claim, claim)
            self.assertEqual(result.transcript.snapshot(), independent.snapshot())
            self.assertEqual(transcript.snapshot(), before)
            verify_sumcheck(rows, 23, SumcheckShape(3, 3), transcript, expected_final=claim)
            for altered, initial, final in (([[8, 3, 0], *rows[1:]], 23, claim),
                                           (rows, 24, claim), (rows, 23, (claim+1) % P)):
                with self.assertRaises(ValueError):
                    verify_sumcheck(altered, initial, SumcheckShape(3, 3), transcript,
                                    expected_final=final)
                self.assertEqual(transcript.snapshot(), before)

    def test_shape_degree_and_canonical_rejections(self):
        t = NovaTranscript('pallas', b'test')
        cases = [([], 0, SumcheckShape(1, 2)), ([[]], 0, SumcheckShape(1, 2)),
                 ([[1, 2, 0]], 0, SumcheckShape(1, 2)),
                 ([[Q]], 0, SumcheckShape(1, 2)), ([[True]], 0, SumcheckShape(1, 2)),
                 ([[1]], -1, SumcheckShape(1, 2)), ([[1]], Q, SumcheckShape(1, 2)),
                 (iter([[1]]), 0, SumcheckShape(1, 2)), ([[1]], 0, (1, 2))]
        for proof, claim, shape in cases:
            with self.assertRaises(ValueError):
                fold_sumcheck(proof, claim, shape, t)
        for rounds, degree in ((-1, 2), (33, 2), (True, 2), (1, 1), (1, 4), (1, True)):
            with self.assertRaises(ValueError):
                SumcheckShape(rounds, degree)
        for row in ([], [1]*9, [None], [1.0], [P]):
            with self.assertRaises(ValueError):
                decompress(row, 0, P)
        with self.assertRaises(ValueError):
            fold_sumcheck([[1]], 0, SumcheckShape(1, 2), object())
        class FakeTranscript(NovaTranscript):
            pass
        with self.assertRaises(ValueError):
            fold_sumcheck([[1]], 0, SumcheckShape(1, 2), FakeTranscript('pallas', b'x'))
        altered = t.clone()
        altered.scalar_modulus = P
        with self.assertRaises(ValueError):
            fold_sumcheck([[1]], 0, SumcheckShape(1, 2), altered)
        with self.assertRaises(ValueError):
            round_trace([], [1], 1, 1, 1, context=bytes(32))
        self.assertEqual(fold_sumcheck([], 12, SumcheckShape(0, 2), t).final_claim, 12)
        overflow = NovaTranscript.from_snapshot('pallas',
            {'round': (1 << 64)-1, 'state': [0]*64, 'transcript_buffer': []})
        before = overflow.snapshot()
        with self.assertRaises(ValueError):
            fold_sumcheck([[1]], 0, SumcheckShape(1, 2), overflow)
        self.assertEqual(overflow.snapshot(), before)

    def test_batched_padding_and_malformed_vectors(self):
        for engine, p in (('pallas', Q), ('vesta', P)):
            claims, rounds, weights = [3, 5, 7], [0, 3, 1], [11, 13, 17]
            initial, nmax = batch_initial_claim(claims, rounds, weights, p)
            self.assertEqual((initial, nmax), ((3*8*11+5*13+7*4*17) % p, 3))
            transcript = NovaTranscript(engine, b'batch')
            proof = [[2, 0], [p-1, 3], [5, 7]]
            single = fold_sumcheck(proof, initial, SumcheckShape(nmax, 2), transcript)
            batch = fold_batched_sumcheck(proof, claims, rounds, weights, 2, transcript)
            self.assertEqual(batch.final_claim, single.final_claim)
            self.assertEqual(batch.challenges, single.challenges)
            verify_batched_sumcheck(proof, claims, rounds, weights, 2, transcript,
                                    expected_final=batch.final_claim)
            with self.assertRaises(ValueError):
                verify_batched_sumcheck(proof, claims, rounds, weights, 2, transcript,
                                        expected_final=(batch.final_claim+1) % p)
        for args in (([], [], []), ([1], [], [1]), ([1], [0], []),
                     ([1], [33], [1]), ([True], [1], [1]), ([1], [1], [P])):
            with self.assertRaises(ValueError):
                batch_initial_claim(*args, P)

    def test_terminal_equations_and_upstream_sparse_domain(self):
        for p in (P, Q):
            left, right = [3, 5, 7], [11, 13, 17]
            eq = 1
            for a, b in zip(left, right):
                eq = eq*(a*b+(1-a)*(1-b)) % p
            self.assertEqual(eq_evaluation(left, right, p), eq)
            self.assertEqual(outer_terminal(left, right, 19, 23, 29, 31, 37, p),
                             eq*(19*23-37*29-31) % p)
            values, point = [2, 3, 5], [7, 11, 13, 17]
            sparse = 0
            for i, value in enumerate(values):
                weight = 1
                for j, x in enumerate(point):
                    weight = weight*(x if (i >> (len(point)-1-j)) & 1 else 1-x) % p
                sparse = (sparse+value*weight) % p
            self.assertEqual(sparse_evaluation(values, point, p), sparse)
            ry = [19, *point]
            self.assertEqual(inner_terminal(ry, 23, 29, 31, 37, 41, 2, [3, 5], p),
                             ((1-19)*41+19*sparse)*(23+37*29+37*37*31) % p)
            self.assertEqual(batch_terminal([43, 47], [left, []], right, [53, 59], p),
                             (43*53*eq+47*59) % p)
        for call in (lambda: eq_evaluation([1], [], P),
                     lambda: sparse_evaluation([], [1], P),
                     lambda: sparse_evaluation([1, 2], [1], P),
                     lambda: batch_terminal([], [], [], [], P),
                     lambda: batch_terminal([1], [[1]], [], [1], P),
                     lambda: inner_terminal([], 1, 1, 1, 1, 1, 1, [], P),
                     lambda: evaluate([1], 1, 17)):
            with self.assertRaises(ValueError):
                call()

    def test_typed_round_arithmetic_and_authenticated_leaf(self):
        for engine in ('pallas', 'vesta'):
            p = Q if engine == 'pallas' else P
            claim, row, challenge = 13, [3, 5], 7
            final = evaluate(decompress(row, claim, p), challenge, p)
            good, values = round_trace(engine, row, claim, challenge, final,
                                       context=bytes(32))
            bound = good.bind(values)
            self.assertEqual(bound.failures(), ())
            last = len(good.constraints)-1
            self.assertTrue(bound.execute(last, disprove=False).success)
            self.assertFalse(bound.execute(last).success)
            bad, altered = round_trace(engine, row, claim, challenge, (final+1) % p,
                                       context=bytes(32))
            failed = bad.bind(altered)
            self.assertEqual(failed.failures(), (last,))
            self.assertTrue(failed.execute(last).success)
            code, witness = failed.script(last), failed.witness(last)
            for malformed in ((), witness[:-1], (b'',)+witness, witness+(b'',)):
                self.assertFalse(execute(code, malformed).success)
            swapped = list(witness)
            swapped[0] = b'\x01' if witness[0] != b'\x01' else b'\x02'
            self.assertFalse(execute(code, tuple(swapped)).success)

    def test_native_coefficient_corpus_schema_is_bounded(self):
        # Format fixture only; this deliberately does not claim native proof
        # verification or real-proof Fiat-Shamir replay in the unit test.
        components = {}
        for component in ('snark_primary', 'snark_secondary'):
            components[component] = {'sc_proof_'+stage: {'compressed_polys': [
                {'coeffs_except_linear_term': [encoded(3), encoded(5)]}]}
                for stage in ('outer', 'inner', 'batch')}
        report = {'passed': True, 'native': {'native_nova_proofs_verified': 1,
                                           'proof_components': components}}
        corpus = native_corpus(report)
        self.assertEqual(len(corpus), 12)
        self.assertEqual(sum(c['expect'] == 'terminal' for c in corpus), 6)
        mutations = []
        altered = copy.deepcopy(report); altered['passed'] = False; mutations.append(altered)
        for row in ([], [encoded(Q)], ['00'], [encoded(3).upper().replace('3', 'A')]):
            altered = copy.deepcopy(report)
            altered['native']['proof_components']['snark_primary']['sc_proof_outer'][
                'compressed_polys'][0]['coeffs_except_linear_term'] = row
            mutations.append(altered)
        altered = copy.deepcopy(report)
        altered['native']['proof_components']['snark_secondary']['sc_proof_inner'][
            'compressed_polys'] *= 33
        mutations.append(altered)
        for altered in mutations:
            with self.assertRaises(ValueError):
                native_corpus(altered)


if __name__ == '__main__':
    unittest.main()
