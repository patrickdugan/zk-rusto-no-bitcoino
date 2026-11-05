"""Streaming algebra reference for Nova's IPA equality, over both Pasta curves.

The equality matches the pinned ipa_pc.rs. Fixture transcripts and generators
are deliberately test-only. This module does not parse or authenticate a Nova
CompressedSNARK, its Fiat-Shamir transcript, or the surrounding Spartan proof.
"""
from dataclasses import dataclass
from hashlib import sha256
from script import P, Q

Point = tuple[int, int] | None


@dataclass(frozen=True)
class Curve:
    name: str
    p: int
    q: int

    def valid(self, pt):
        return pt is None or (isinstance(pt, tuple) and len(pt) == 2
            and all(type(x) is int and 0 <= x < self.p for x in pt)
            and (pt[1]*pt[1] - pt[0]**3 - 5) % self.p == 0)

    def add(self, a: Point, b: Point) -> Point:
        if a is None:
            return b
        if b is None:
            return a
        x, y = a
        xx, yy = b
        if x == xx and (y+yy) % self.p == 0:
            return None
        slope = ((3*x*x) * pow(2*y, -1, self.p) if a == b else
                 (yy-y) * pow(xx-x, -1, self.p)) % self.p
        nx = (slope*slope-x-xx) % self.p
        return nx, (slope*(x-nx)-y) % self.p

    def mul(self, a: Point, k: int) -> Point:
        # Deliberately do not reduce k here: order tests must exercise q*G.
        if k < 0:
            return self.mul(None if a is None else (a[0], -a[1] % self.p), -k)
        out = None
        while k:
            if k & 1:
                out = self.add(out, a)
            a = self.add(a, a)
            k >>= 1
        return out

    def msm(self, points, scalars):
        points, scalars = list(points), list(scalars)
        if len(points) != len(scalars):
            raise ValueError('MSM length mismatch')
        out = None
        for g, s in zip(points, scalars):
            out = self.add(out, self.mul(g, s))
        return out


PALLAS, VESTA = Curve('pallas', P, Q), Curve('vesta', Q, P)


def _sqrt(a, p):
    if not a:
        return 0
    if pow(a, (p-1)//2, p) != 1:
        return None
    odd, s = p-1, 0
    while odd % 2 == 0:
        odd //= 2
        s += 1
    z = 2
    while pow(z, (p-1)//2, p) != p-1:
        z += 1
    c, x, t, m = pow(z, odd, p), pow(a, (odd+1)//2, p), pow(a, odd, p), s
    while t != 1:
        i, u = 0, t
        while u != 1 and i < m:
            u = u*u % p
            i += 1
        if i == m:
            raise ValueError('sqrt failure')
        b = pow(c, 1 << (m-i-1), p)
        x, t, c, m = x*b % p, t*b*b % p, b*b % p, i
    return min(x, p-x)


def test_generator(curve, index):
    """Deterministic hash-and-try point, NOT Nova's production derivation."""
    tag = b'BITVM2-NOVA-TEST-ONLY-GENERATOR/' + curve.name.encode()
    for attempt in range(256):
        x = int.from_bytes(sha256(tag + index.to_bytes(4, 'little')
            + attempt.to_bytes(2, 'little')).digest(), 'little') % curve.p
        y = _sqrt((x*x*x+5) % curve.p, curve.p)
        if y is not None:
            return x, y
    raise ValueError('generator derivation exhausted')


def point_bytes(pt):
    return b'\x00' + bytes(64) if pt is None else b'\x01' + b''.join(x.to_bytes(32, 'little') for x in pt)


def weights(challenges, q):
    """Yield s_i in upstream order with O(log n) auxiliary storage."""
    if len(challenges) > 20 or any(type(r) is not int or not 0 < r < q for r in challenges):
        raise ValueError('noncanonical/zero challenge or dimension limit')
    inv = [pow(r, -1, q) for r in challenges]
    def visit(j, value):
        if j == len(challenges):
            yield value
        else:
            yield from visit(j+1, value*inv[j] % q)
            yield from visit(j+1, value*challenges[j] % q)
    yield from visit(0, 1)


def verify_equation(curve, generators, b, commitment, evaluation, u_base,
                    r0, challenges, left, right, a_hat):
    """Only the IPA algebraic equality. Challenges must be authenticated upstream."""
    n = len(generators)
    scalar = lambda x: type(x) is int and 0 <= x < curve.q
    if (n < 1 or n > 1 << 20 or n & (n-1) or n != 1 << len(challenges)
        or len(left) != len(challenges) or len(right) != len(challenges) or len(b) != n
        or not all(scalar(x) for x in [evaluation, a_hat, r0] + list(b))
        or not r0 or not all(curve.valid(g) for g in [commitment, u_base] + list(generators) + list(left) + list(right))
        or u_base is None or any(g is None for g in generators)):
        return False
    try:
        g_hat, b_hat = None, 0
        # The generator vector itself may be disk backed by the future adapter.
        # This loop does not allocate the length-n vector of s coefficients.
        for g, bi, si in zip(generators, b, weights(challenges, curve.q)):
            g_hat = curve.add(g_hat, curve.mul(g, si))
            b_hat = (b_hat + bi*si) % curve.q
        u = curve.mul(u_base, r0)
        lhs = curve.add(commitment, curve.mul(u, evaluation))
        for l, r, challenge in zip(left, right, challenges):
            lhs = curve.add(lhs, curve.mul(l, challenge*challenge % curve.q))
            inv = pow(challenge, -1, curve.q)
            lhs = curve.add(lhs, curve.mul(r, inv*inv % curve.q))
        rhs = curve.add(curve.mul(g_hat, a_hat), curve.mul(u, a_hat*b_hat % curve.q))
        return lhs == rhs
    except (ValueError, ZeroDivisionError):
        return False


class TestTranscript:
    """Explicitly incompatible with Nova's production Fiat-Shamir transcript."""
    def __init__(self, curve, generators, b, commitment, evaluation, u):
        self.q = curve.q
        payload = (curve.name.encode() + len(b).to_bytes(4, 'little')
            + b''.join(point_bytes(g) for g in generators) + point_bytes(u)
            + b''.join(v.to_bytes(32, 'little') for v in b)
            + point_bytes(commitment) + evaluation.to_bytes(32, 'little'))
        self.state = sha256(b'BITVM2-NOVA-TEST-ONLY-TRANSCRIPT/v1/' + payload).digest()

    def squeeze(self, data=b''):
        self.state = sha256(self.state + len(data).to_bytes(4, 'little') + data).digest()
        v = int.from_bytes(self.state, 'little') % self.q
        # Both sides fail closed rather than silently map zero to another scalar.
        if not v:
            raise ValueError('zero challenge')
        return v


def make_fixture(curve, n=4):
    if n < 1 or n > 16 or n & (n-1):
        raise ValueError('fixture dimension must be a power of two <=16')
    gs = [test_generator(curve, i) for i in range(n)]
    u0 = test_generator(curve, n)
    aa = list(range(1, n+1))
    bb = [3*i+2 for i in range(n)]
    c = sum(a*b for a, b in zip(aa, bb)) % curve.q
    comm = curve.msm(gs, aa)
    tr = TestTranscript(curve, gs, bb, comm, c, u0)
    r0 = tr.squeeze()
    u = curve.mul(u0, r0)
    av, bv, gv = aa, bb, gs
    ls, rs, challenges = [], [], []
    while len(av) > 1:
        h = len(av)//2
        l = curve.add(curve.msm(gv[h:], av[:h]), curve.mul(u, sum(a*b for a,b in zip(av[:h],bv[h:])) % curve.q))
        r = curve.add(curve.msm(gv[:h], av[h:]), curve.mul(u, sum(a*b for a,b in zip(av[h:],bv[:h])) % curve.q))
        challenge = tr.squeeze(point_bytes(l)+point_bytes(r))
        inv = pow(challenge, -1, curve.q)
        av = [(challenge*a+inv*b) % curve.q for a,b in zip(av[:h],av[h:])]
        bv = [(inv*a+challenge*b) % curve.q for a,b in zip(bv[:h],bv[h:])]
        gv = [curve.add(curve.mul(a, inv),curve.mul(b, challenge)) for a,b in zip(gv[:h],gv[h:])]
        ls.append(l)
        rs.append(r)
        challenges.append(challenge)
    return dict(generators=gs, b=bb, commitment=comm, evaluation=c, u_base=u0,
                r0=r0, challenges=challenges, left=ls, right=rs, a_hat=av[0])


def multiplication_steps(x, y, p):
    """Stream exactly 255 MSB-first Horner transitions; keep no full trace."""
    if p not in (P,Q) or any(type(v) is not int or not 0 <= v < p for v in (x,y)):
        raise ValueError('canonical Pasta field inputs required')
    acc = 0
    for step, shift in enumerate(range(254, -1, -1)):
        bit = (y >> shift) & 1
        out = (2*acc + bit*x) % p
        yield dict(step=step, accumulator=acc, multiplicand=x, bit=bit, output=out)
        acc = out
