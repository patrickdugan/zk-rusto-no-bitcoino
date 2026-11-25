"""ZKL-17: raw lambda terms, capture-avoiding substitution, local certificate rows."""
from dataclasses import dataclass
import argparse
import json
import random
from pathlib import Path

# De Bruijn indices. Const is an inert symbol, not an axiom.
VAR, CONST, LAM, APP = range(4)
L_BELOW, L_ABOVE, L_CONST, L_LAM, L_APP, S_BELOW, S_EQUAL, S_ABOVE, S_CONST, S_LAM, S_APP, E_REFL, E_SYM, E_TRANS, E_BETA, E_LAM, E_APP = range(17)
ARITY = (0, 0, 0, 1, 2, 0, 0, 0, 0, 2, 2, 0, 1, 2, 1, 1, 2)


def var(i): return (VAR, i)
def const(i): return (CONST, i)
def lam(t): return (LAM, t)
def app(t, u): return (APP, t, u)


def shift(t, k=0, delta=1):
    tag = t[0]
    if tag == VAR:
        i = t[1] + (delta if t[1] >= k else 0)
        if i < 0:
            raise ValueError('negative index')
        return var(i)
    if tag == CONST: return t
    if tag == LAM: return lam(shift(t[1], k + 1, delta))
    return app(shift(t[1], k, delta), shift(t[2], k, delta))


def substitute(t, k, s):
    """Remove binder k, replacing it by s already in the surrounding context."""
    tag = t[0]
    if tag == VAR:
        i = t[1]
        return var(i) if i < k else s if i == k else var(i - 1)
    if tag == CONST: return t
    if tag == LAM: return lam(substitute(t[1], k + 1, shift(s)))
    return app(substitute(t[1], k, s), substitute(t[2], k, s))


def standard_substitute(t, k, s, depth=0):
    """Independent depth-accumulator algorithm; only shifts at a replaced variable."""
    tag = t[0]
    if tag == VAR:
        i = t[1]
        if i == k + depth:
            return shift(s, 0, depth)
        return var(i - int(i > k + depth))
    if tag == CONST: return t
    if tag == LAM: return lam(standard_substitute(t[1], k, s, depth + 1))
    return app(standard_substitute(t[1], k, s, depth), standard_substitute(t[2], k, s, depth))


def kind(op): return 0 if op < 5 else 1 if op < 11 else 2


@dataclass(frozen=True)
class Row:
    op: int
    t: int
    k: int
    s: int
    u: int
    refs: tuple


class Builder:
    def __init__(self):
        self.terms = []
        self.ids = {}
        self.rows = []
        self.memo = {}
        self.intern(const(0))

    def intern(self, t):
        if t not in self.ids:
            tag = t[0]
            if tag in (VAR, CONST): a, b = t[1], 0
            elif tag == LAM: a, b = self.intern(t[1]), 0
            else: a, b = self.intern(t[1]), self.intern(t[2])
            self.ids[t] = len(self.terms)
            self.terms.append((tag, a, b))
        return self.ids[t]

    def emit(self, op, t, k, s, u, refs=()):
        row = Row(op, self.intern(t), k, self.intern(s) if s is not None else 0,
                  self.intern(u), tuple(refs))
        self.rows.append(row)
        return len(self.rows) - 1

    def lift(self, t, k):
        key = ('l', t, k)
        if key in self.memo: return self.memo[key]
        tag = t[0]
        if tag == VAR: op, refs = (L_BELOW if t[1] < k else L_ABOVE), ()
        elif tag == CONST: op, refs = L_CONST, ()
        elif tag == LAM: op, refs = L_LAM, (self.lift(t[1], k + 1),)
        else: op, refs = L_APP, (self.lift(t[1], k), self.lift(t[2], k))
        result = self.emit(op, t, k, None, shift(t, k), refs)
        self.memo[key] = result
        return result

    def sub(self, t, k, s):
        key = ('s', t, k, s)
        if key in self.memo: return self.memo[key]
        tag = t[0]
        if tag == VAR: op, refs = (S_BELOW if t[1] < k else S_EQUAL if t[1] == k else S_ABOVE), ()
        elif tag == CONST: op, refs = S_CONST, ()
        elif tag == LAM: op, refs = S_LAM, (self.lift(s, 0), self.sub(t[1], k + 1, shift(s)))
        else: op, refs = S_APP, (self.sub(t[1], k, s), self.sub(t[2], k, s))
        result = self.emit(op, t, k, s, substitute(t, k, s), refs)
        self.memo[key] = result
        return result

    def beta(self, t):
        assert t[0] == APP and t[1][0] == LAM
        body, s = t[1][1], t[2]
        u = substitute(body, 0, s)
        r = self.emit(E_BETA, t, 0, None, u, (self.sub(body, 0, s),))
        return u, r

    def wire(self, name):
        final = self.rows[-1]
        assert kind(final.op) == 2
        return {'name': name, 'terms': self.terms, 'rows': [[r.op, r.t, r.k, r.s, r.u, list(r.refs)] for r in self.rows],
                'goal': [final.t, final.u]}


def replay(case):
    """Independent replay by full direct normalization of each claimed lift/sub row."""
    terms = []
    seen = set()
    for tag, a, b in case['terms']:
        if type(a) is not int or type(b) is not int or not 0 <= a <= 65535 or not 0 <= b <= 65535:
            raise ValueError('term field')
        if tag in (VAR, CONST) and b == 0: t = (tag, a)
        elif tag == LAM and a < len(terms) and b == 0: t = lam(terms[a])
        elif tag == APP and a < len(terms) and b < len(terms): t = app(terms[a], terms[b])
        else: raise ValueError('arena')
        if t in seen: raise ValueError('noncanonical duplicate')
        terms.append(t); seen.add(t)
    rows = []
    for op, t, k, s, u, refs in case['rows']:
        if not 0 <= op < len(ARITY) or len(refs) != ARITY[op] or any(not 0 <= r < len(rows) for r in refs):
            raise ValueError('references')
        if any(type(i) is not int or not 0 <= i < len(terms) for i in (t, s, u)) or not 0 <= k <= 65535:
            raise ValueError('row')
        a, b, c = terms[t], terms[s], terms[u]
        old = [rows[r] for r in refs]
        def want(j, typ, t0, k0, s0, u0):
            r = old[j]
            return (kind(r[0]), terms[r[1]], r[2], r[3], terms[r[4]]) == (typ, t0, k0, s0, u0)
        if kind(op) == 0:
            ok = s == 0 and shift(a, k) == c
            if op == L_BELOW: ok &= a[0] == VAR and a[1] < k
            elif op == L_ABOVE: ok &= a[0] == VAR and a[1] >= k
            elif op == L_CONST: ok &= a[0] == CONST
            elif op == L_LAM: ok &= a[0] == LAM and want(0, 0, a[1], k+1, 0, c[1])
            elif op == L_APP: ok &= a[0] == APP and want(0, 0, a[1], k, 0, c[1]) and want(1, 0, a[2], k, 0, c[2])
        elif kind(op) == 1:
            ok = standard_substitute(a, k, b) == c
            if op == S_BELOW: ok &= a[0] == VAR and a[1] < k
            elif op == S_EQUAL: ok &= a[0] == VAR and a[1] == k
            elif op == S_ABOVE: ok &= a[0] == VAR and a[1] > k
            elif op == S_CONST: ok &= a[0] == CONST
            elif op == S_LAM:
                lifted = old[0][4]
                ok &= a[0] == LAM and want(0, 0, b, 0, 0, shift(b)) and want(1, 1, a[1], k+1, lifted, c[1])
            elif op == S_APP: ok &= a[0] == APP and want(0, 1, a[1], k, s, c[1]) and want(1, 1, a[2], k, s, c[2])
        else:
            ok = k == s == 0
            if op == E_REFL: ok &= t == u
            elif op == E_SYM: ok &= want(0, 2, c, 0, 0, a)
            elif op == E_TRANS:
                mid = terms[old[0][4]]
                ok &= want(0, 2, a, 0, 0, mid) and want(1, 2, mid, 0, 0, c)
            elif op == E_BETA:
                ok &= a[0] == APP and a[1][0] == LAM and want(0, 1, a[1][1], 0, terms.index(a[2]), c)
            elif op == E_LAM: ok &= a[0] == c[0] == LAM and want(0, 2, a[1], 0, 0, c[1])
            elif op == E_APP: ok &= a[0] == c[0] == APP and want(0, 2, a[1], 0, 0, c[1]) and want(1, 2, a[2], 0, 0, c[2])
        if not ok: raise ValueError('local rule')
        rows.append((op,t,k,s,u))
    if not rows or kind(rows[-1][0]) != 2 or [rows[-1][1], rows[-1][4]] != case['goal']:
        raise ValueError('terminal')
    return True


def fixtures():
    out = []
    # Substitution under a lambda with an OPEN replacement must lift it.
    for name, t in [
        ('capture', app(lam(lam(var(1))), var(0))),
        ('lift_binder', app(lam(lam(app(var(1), const(3)))), lam(app(var(0), var(1))))),
        ('decrement', app(lam(app(var(2), var(0))), const(1))),
        ('nested', app(lam(lam(app(app(var(0), var(1)), var(3)))), app(var(0), const(2)))),
    ]:
        b = Builder(); b.beta(t); out.append(b.wire(name))
    b = Builder()
    t = app(lam(var(0)), const(1)); u, r = b.beta(t)
    left, right = lam(t), lam(u)
    a = b.emit(E_LAM, left, 0, None, right, (r,))
    ident = b.emit(E_REFL, const(2), 0, None, const(2))
    ll, rr = app(left, const(2)), app(right, const(2))
    p = b.emit(E_APP, ll, 0, None, rr, (a, ident))
    q = b.emit(E_SYM, rr, 0, None, ll, (p,))
    b.emit(E_TRANS, ll, 0, None, ll, (p, q)); out.append(b.wire('congruence'))
    assert all(replay(c) for c in out)
    return out


def generate(seed, depth):
    rng = random.Random(seed)
    def term(d):
        tag = rng.randrange(4 if d else 2)
        if tag == VAR: return var(rng.randrange(6))
        if tag == CONST: return const(rng.randrange(4))
        if tag == LAM: return lam(term(d-1))
        return app(term(d-1), term(d-1))
    return term(depth), term(depth), rng.randrange(4)


def main():
    p = argparse.ArgumentParser(); p.add_argument('--out', type=Path, required=True); args=p.parse_args()
    data = {'schema': 'zkl-term-v1', 'cases': fixtures()}
    args.out.write_text(json.dumps(data, sort_keys=True, separators=(',', ':'))+'\n')

if __name__ == '__main__': main()
