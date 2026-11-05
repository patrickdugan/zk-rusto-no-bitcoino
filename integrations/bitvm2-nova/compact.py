"""Opt-in M2 multiplication compiler; the original kernels remain the baseline.

Canonical comparison and stack housekeeping are changed. Range checks,
arithmetic, opening layout and the 255-step graph are retained. No claim values
specialize this predicate.
"""
from functools import lru_cache
from script import BASE, LIMBS, P, Q, Builder, limbs


class BorrowBuilder(Builder):
    def copy(self, v):
        depth = len(self.stack) - 1 - self.stack.index(v)
        if depth not in (0, 1):
            return super().copy(v)
        self.op('DUP' if depth == 0 else 'OVER')
        name = self.name()
        self.stack.append(name)
        return name

    def keep(self, names):
        for v in names:
            self.copy(v)
            self.op('TOALTSTACK')
            self.stack.pop()
        for _ in range(len(self.stack) // 2):
            self.op('2DROP')
        if len(self.stack) % 2:
            self.op('DROP')
        for _ in names:
            self.op('FROMALTSTACK')
        self.stack = list(reversed(names))

    def canonical(self, xs, p):
        # With 0 <= x_i,m_i < B and borrow in {0,1}, t lies in [-B,B-1].
        # Subtraction of p underflows exactly when the whole value is < p.
        saved = list(self.stack)
        borrow, zero = self.literal(0), self.literal(0)
        for x, m in zip(xs, limbs(p), strict=True):
            t = self.binary('SUB', self.binary('SUB', x, self.literal(m)), borrow)
            borrow = self.binary('LESSTHAN', t, zero)
        self.verify(borrow)
        self.keep(saved)


@lru_cache(maxsize=2)
def mul_bit(p):
    """Same admitted-input predicate as M1, using borrow-chain comparisons."""
    if p not in (P, Q):
        raise ValueError('unsupported field')
    xs, ys, zs = [[f'{c}{i}' for i in range(LIMBS)] for c in 'xyz']
    b = BorrowBuilder(xs + ys + ['bit'] + zs)
    for v in xs + ys + zs:
        b.range(v, BASE)
    b.canonical(xs, p)
    b.canonical(ys, p)
    b.range('bit', 2)
    twice = b.add_mod(xs, xs, p)
    gated = [b.choose('bit', y, 0) for y in ys]
    out = b.add_mod(twice, gated, p)
    ok = b.literal(1)
    for z, r in zip(zs, out, strict=True):
        ok = b.binary('BOOLAND', ok, b.binary('EQUAL', z, r))
    b.keep([ok])
    return bytes(b.code)
