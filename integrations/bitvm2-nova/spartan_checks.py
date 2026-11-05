"""Bounded Nova 0.76.0 Spartan sumcheck verification and arithmetic checks.

This uses the production non-EVM transcript, not the IPA TEST-ONLY transcript.
Sumcheck folding alone does not verify a Spartan/Nova proof: callers must bind
the initial claim, verifier-owned round/degree shape and terminal equation to
the authenticated instance, verification key and IPA openings.

Primary source: published nova-snark0.76.0 src/spartan/{sumcheck.rs,
polys/univariate.rs,polys/multilinear.rs,snark.rs}. Crate SHA256
c9bb3809a6c70057ea722c1c4fe5097cf29a3479d0b4671f3cddb1d81043bb31;
VCS98576efa884072bfe69bfad8f275a3a5cd8754e5. Non-EVM Pasta only.
"""
from dataclasses import dataclass
from production_transcript import NovaTranscript
from script import P, Q

MAX_ROUNDS = 32
MAX_INSTANCES = 64
MAX_COMPRESSED_COEFFICIENTS = 8
SCALARS = {'pallas': Q, 'vesta': P}


def _modulus(p):
    if type(p) is not int or p not in (P, Q):
        raise ValueError('unsupported Pasta scalar modulus')
    return p


def _scalar(value, p):
    if type(value) is not int or not 0 <= value < p:
        raise ValueError('canonical scalar integer required')
    return value


def _sequence(values, bound, name):
    if type(values) not in (list, tuple) or len(values) > bound:
        raise ValueError(f'bounded {name} list/tuple required')
    return tuple(values)


def _transcript(value):
    if (type(value) is not NovaTranscript or type(value.engine) is not str
            or value.engine not in SCALARS
            or value.scalar_modulus != SCALARS[value.engine]
            or value.base_modulus != (P if value.engine == 'pallas' else Q)):
        raise ValueError('production NovaTranscript required')
    return value, SCALARS[value.engine]


@dataclass(frozen=True)
class SumcheckShape:
    """Round count and degree selected from the verifier key, never the proof."""
    rounds: int
    degree: int

    def __post_init__(self):
        if type(self.rounds) is not int or not 0 <= self.rounds <= MAX_ROUNDS:
            raise ValueError('sumcheck round count out of bounds')
        if type(self.degree) is not int or self.degree not in (2, 3):
            raise ValueError('only Spartan quadratic/cubic degree bounds supported')


@dataclass(frozen=True)
class RoundState:
    claim_before: int
    coefficients: tuple[int, ...]
    challenge: int
    claim_after: int


@dataclass(frozen=True)
class SumcheckResult:
    final_claim: int
    challenges: tuple[int, ...]
    rounds: tuple[RoundState, ...]
    transcript: NovaTranscript


def decompress(compressed, claim, p):
    """Restore the omitted linear coefficient, preserving encoded degree.

    Upstream does not trim trailing zeroes during decompression. In particular,
    a compressed cubic with a zero cubic coefficient is still encoded degree 3.
    """
    _modulus(p)
    compressed = _sequence(compressed, MAX_COMPRESSED_COEFFICIENTS, 'coefficient')
    if not compressed:
        raise ValueError('empty compressed polynomial')
    _scalar(claim, p)
    for coefficient in compressed:
        _scalar(coefficient, p)
    linear = (claim - 2*compressed[0] - sum(compressed[1:])) % p
    return (compressed[0], linear) + compressed[1:]


def evaluate(coefficients, point, p):
    _modulus(p)
    coefficients = _sequence(coefficients, MAX_COMPRESSED_COEFFICIENTS+1, 'coefficient')
    if not coefficients:
        raise ValueError('empty polynomial')
    _scalar(point, p)
    result = 0
    for coefficient in reversed(coefficients):
        result = (result*point + _scalar(coefficient, p)) % p
    return result


def fold_sumcheck(compressed_polys, initial_claim, shape, transcript):
    """Return the upstream fold and updated transcript, without terminal binding.

    This functional wrapper leaves its input transcript unchanged. Continue the
    protocol with result.transcript. No state is returned on rejection.
    """
    transcript, p = _transcript(transcript)
    if type(shape) is not SumcheckShape:
        raise ValueError('verifier-owned SumcheckShape required')
    proof = _sequence(compressed_polys, MAX_ROUNDS, 'round polynomial')
    if len(proof) != shape.rounds:
        raise ValueError('sumcheck round count mismatch')
    claim = _scalar(initial_claim, p)
    admitted = []
    for row in proof:
        row = _sequence(row, MAX_COMPRESSED_COEFFICIENTS, 'coefficient')
        if not row or len(row) > shape.degree:
            raise ValueError('empty polynomial or encoded degree exceeds bound')
        for coefficient in row:
            _scalar(coefficient, p)
        admitted.append(row)
    running = transcript.clone()
    rounds, challenges = [], []
    for row in admitted:
        coefficients = decompress(row, claim, p)
        # UniPoly::to_transcript_bytes serializes its compressed coefficients,
        # not the restored linear term and not a vector-length prefix.
        running.absorb_scalars(b'p', row)
        challenge = running.squeeze(b'c')
        next_claim = evaluate(coefficients, challenge, p)
        rounds.append(RoundState(claim, coefficients, challenge, next_claim))
        challenges.append(challenge)
        claim = next_claim
    return SumcheckResult(claim, tuple(challenges), tuple(rounds), running)


def verify_sumcheck(compressed_polys, initial_claim, shape, transcript, *, expected_final):
    """Verify the fold against a separately bound terminal equation value."""
    _, p = _transcript(transcript)
    expected_final = _scalar(expected_final, p)
    result = fold_sumcheck(compressed_polys, initial_claim, shape, transcript)
    if result.final_claim != expected_final:
        raise ValueError('sumcheck terminal claim mismatch')
    return result


def batch_initial_claim(claims, rounds, coefficients, p):
    _modulus(p)
    claims = _sequence(claims, MAX_INSTANCES, 'batch claim')
    rounds = _sequence(rounds, MAX_INSTANCES, 'batch round count')
    coefficients = _sequence(coefficients, MAX_INSTANCES, 'batch coefficient')
    if not claims or len(claims) != len(rounds) or len(claims) != len(coefficients):
        raise ValueError('empty or mismatched batch vectors')
    for n in rounds:
        SumcheckShape(n, 2)
    nmax = max(rounds)
    result = sum(_scalar(c, p)*_scalar(weight, p)*pow(2, nmax-n, p)
                 for c, n, weight in zip(claims, rounds, coefficients, strict=True)) % p
    return result, nmax


def fold_batched_sumcheck(compressed_polys, claims, rounds, coefficients, degree, transcript):
    """Match SumcheckProof::verify_batch, including unequal-round padding."""
    _, p = _transcript(transcript)
    initial, nmax = batch_initial_claim(claims, rounds, coefficients, p)
    return fold_sumcheck(compressed_polys, initial, SumcheckShape(nmax, degree), transcript)


def verify_batched_sumcheck(compressed_polys, claims, rounds, coefficients, degree, transcript, *, expected_final):
    _, p = _transcript(transcript)
    expected_final = _scalar(expected_final, p)
    result = fold_batched_sumcheck(compressed_polys, claims, rounds, coefficients, degree, transcript)
    if result.final_claim != expected_final:
        raise ValueError('batched sumcheck terminal claim mismatch')
    return result


def eq_evaluation(left, right, p):
    """Multilinear equality polynomial, with both point dimensions checked."""
    _modulus(p)
    left = _sequence(left, MAX_ROUNDS, 'evaluation point')
    right = _sequence(right, MAX_ROUNDS, 'evaluation point')
    if len(left) != len(right):
        raise ValueError('equality polynomial dimension mismatch')
    result = 1
    for x, y in zip(left, right, strict=True):
        x, y = _scalar(x, p), _scalar(y, p)
        result = result*(x*y+(1-x)*(1-y)) % p
    return result


def sparse_evaluation(values, point, p):
    """Evaluate verifier-owned sparse public inputs padded with zeroes.

    Index bits are MSB first, matching Spartan SparsePolynomial::evaluate.
    No 2**n-sized table is allocated. Reject dimensions which would underflow
    upstream's optimized SparsePolynomial evaluator before calling its oracle.
    """
    _modulus(p)
    values = _sequence(values, MAX_INSTANCES, 'sparse value')
    point = _sequence(point, MAX_ROUNDS, 'evaluation point')
    if not values or len(point) < 1+(len(values)-1).bit_length():
        raise ValueError('unsupported upstream sparse evaluation dimensions')
    for coordinate in point:
        _scalar(coordinate, p)
    result = 0
    for i, value in enumerate(values):
        weight = 1
        for j, coordinate in enumerate(point):
            weight = weight*(coordinate if (i >> (len(point)-1-j)) & 1 else 1-coordinate) % p
        result = (result+_scalar(value, p)*weight) % p
    return result


def outer_terminal(tau, r_x, claim_az, claim_bz, claim_cz, eval_e, u, p):
    _modulus(p)
    az, bz, cz, e, u = (_scalar(v, p) for v in (claim_az, claim_bz, claim_cz, eval_e, u))
    return eq_evaluation(tau, r_x, p)*(az*bz-u*cz-e) % p


def inner_terminal(r_y, matrix_a, matrix_b, matrix_c, batching_challenge, eval_w, u, public_inputs, p):
    _modulus(p)
    r_y = _sequence(r_y, MAX_ROUNDS, 'inner evaluation point')
    if not r_y:
        raise ValueError('inner evaluation point needs selector coordinate')
    a, b, c, rho, w, u = (_scalar(v, p) for v in
                           (matrix_a, matrix_b, matrix_c, batching_challenge, eval_w, u))
    y0 = _scalar(r_y[0], p)
    inputs = _sequence(public_inputs, MAX_INSTANCES-1, 'public input')
    eval_x = sparse_evaluation((u,)+inputs, r_y[1:], p)
    eval_z = ((1-y0)*w+y0*eval_x) % p
    return eval_z*(a+rho*b+rho*rho*c) % p


def batch_terminal(evaluations, evaluation_points, challenges, coefficients, p):
    _modulus(p)
    evaluations = _sequence(evaluations, MAX_INSTANCES, 'batch evaluation')
    evaluation_points = _sequence(evaluation_points, MAX_INSTANCES, 'batch evaluation point')
    coefficients = _sequence(coefficients, MAX_INSTANCES, 'batch coefficient')
    challenges = _sequence(challenges, MAX_ROUNDS, 'challenge')
    if not evaluations or len(evaluations) != len(evaluation_points) or len(evaluations) != len(coefficients):
        raise ValueError('empty or mismatched batch terminal vectors')
    for challenge in challenges:
        _scalar(challenge, p)
    total = 0
    for value, point, coefficient in zip(evaluations, evaluation_points, coefficients, strict=True):
        point = _sequence(point, MAX_ROUNDS, 'evaluation point')
        if len(point) > len(challenges):
            raise ValueError('batch evaluation point exceeds challenge dimension')
        tail = challenges[len(challenges)-len(point):]
        total += _scalar(value, p)*_scalar(coefficient, p)*eq_evaluation(tail, point, p)
    return total % p


def round_trace(engine, compressed, claim_before, challenge, claimed_after, *, context, round_index=0):
    """Arithmetic fixture for a round pinned to decoded proof/transcript values.

    Input coefficients, prior claim and challenge are constants in this graph.
    This does NOT make native Keccak computation or proof parsing disputable in
    Bitcoin. A production adapter must bind them to those computations.
    """
    from trace import TraceBuilder
    if (type(engine) is not str or engine not in SCALARS
            or type(round_index) is not int or not 0 <= round_index < MAX_ROUNDS):
        raise ValueError('invalid engine or round index')
    p = SCALARS[engine]
    coefficients = decompress(compressed, claim_before, p)
    if len(coefficients) > 4:
        raise ValueError('only quadratic/cubic round traces supported')
    _scalar(challenge, p); _scalar(claimed_after, p)
    role = 'pallas_scalar' if engine == 'pallas' else 'vesta_scalar'
    g = TraceBuilder(role, f'spartan/sumcheck-round/{round_index}', context)
    # Constant anchors make the standalone fixture's arithmetic obligations
    # concrete; the caller must own the program/context commitment.
    prior = g.constant('input/prior', claim_before)
    r = g.constant('input/challenge', challenge)
    compressed = tuple(compressed)
    c0 = g.constant('input/c0', compressed[0])
    tail = [g.constant(f'input/c{i+2}', value) for i, value in enumerate(compressed[1:])]
    c0_twice = g.add('linear/twice-c0', c0, c0)
    remainder = c0_twice
    for i, value in enumerate(tail):
        remainder = g.add(f'linear/partial/{i}', remainder, value)
    linear = g.sub('linear', prior, remainder)
    coeff_wires = [c0, linear]+tail
    accumulator = coeff_wires[-1]
    for i, coefficient in enumerate(reversed(coeff_wires[:-1])):
        product = g.mul(f'evaluation/product/{i}', accumulator, r)
        accumulator = g.add(f'evaluation/partial/{i}', product, coefficient)
    claimed = g.field('claimed/next', claimed_after)
    g.check('equal', accumulator+claimed)
    return g.finish()
