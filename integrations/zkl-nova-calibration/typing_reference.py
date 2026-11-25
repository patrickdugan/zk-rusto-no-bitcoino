"""Bounded public-syntax dependent Pi typing certificate generator (original)."""
import argparse
import json
import random
from pathlib import Path

SORT, VAR, PI, LAM, APP = range(5)
EMPTY, EXTEND, SRT, VREF, PIF, LAMF, APPF, CONV = range(8)


def sort(i): return (SORT, i)
def var(i): return (VAR, i)
def pi(a, b): return (PI, a, b)
def lam(a, b): return (LAM, a, b)
def app(a, b): return (APP, a, b)


def lift(t, d=1, k=0):
    op = t[0]
    if op == SORT: return t
    if op == VAR: return var(t[1] + (d if t[1] >= k else 0))
    return (op, lift(t[1], d, k), lift(t[2], d, k + int(op in (PI, LAM))))


def sub(t, s, k=0):
    op = t[0]
    if op == SORT: return t
    if op == VAR:
        i = t[1]
        return var(i) if i < k else s if i == k else var(i - 1)
    if op in (PI, LAM): return (op, sub(t[1], s, k), sub(t[2], lift(s), k + 1))
    return app(sub(t[1], s, k), sub(t[2], s, k))


def normalize(t, budget=None):
    if budget is None: budget = [10000]
    budget[0] -= 1
    if budget[0] < 0: raise ValueError('normalization cap')
    if t[0] in (SORT, VAR): return t
    a = normalize(t[1], budget)
    if t[0] == APP and a[0] == LAM:
        return normalize(sub(a[2], t[2]), budget)
    return (t[0], a, normalize(t[2], budget))


def imax(u, v): return 0 if v == 0 else max(u, v)


def level(t):
    if t[0] != SORT: raise ValueError('expected sort')
    return t[1]


def named(t, env=()):
    """Convert small named expressions to de Bruijn terms."""
    if isinstance(t, str): return var(env.index(t))
    tag = t[0]
    if tag == 's': return sort(t[1])
    if tag == 'a': return app(named(t[1], env), named(t[2], env))
    if tag in ('p', 'l'):
        return (PI if tag == 'p' else LAM, named(t[2], env), named(t[3], (t[1], *env)))
    raise ValueError('named syntax')


class Builder:
    def __init__(self):
        self.terms, self.term_ids = [], {}
        self.contexts, self.context_ids = [[0, 0]], {(): 0}
        self.desc, self.rows, self.memo = [], [], {}
        self.term(sort(0))

    def term(self, t):
        if t not in self.term_ids:
            op = t[0]
            a, b = (t[1], 0) if op in (SORT, VAR) else (self.term(t[1]), self.term(t[2]))
            self.term_ids[t] = len(self.terms)
            self.terms.append([op, a, b])
        return self.term_ids[t]

    def ctx(self, ctx):
        if ctx not in self.context_ids:
            parent, binder = self.ctx(ctx[1:]), self.term(ctx[0])
            self.context_ids[ctx] = len(self.contexts)
            self.contexts.append([parent, binder])
        return self.context_ids[ctx]

    def emit(self, key, op, c, t=0, ty=0, ext=0, u=0, v=0, refs=()):
        i = len(self.rows)
        self.desc.append([op, c, t, ty, ext, u, v])
        self.rows.append({'rule': len(self.desc)-1, 'refs': list(refs)})
        self.memo[key] = i
        return i

    def wf(self, ctx):
        key = ('wf', ctx)
        if key in self.memo: return self.memo[key]
        c = self.ctx(ctx)
        if not ctx: return self.emit(key, EMPTY, c)
        prior = self.wf(ctx[1:])
        ty, a = self.infer(ctx[1:], ctx[0]); level(ty)
        return self.emit(key, EXTEND, c, u=self.term(ty), refs=(prior, a))

    def infer(self, ctx, t):
        op = t[0]
        c, tid = self.ctx(ctx), self.term(t)
        if op == SORT:
            ty = sort(t[1]+1); rule, ext, u, v, refs = SRT, 0, 0, 0, (self.wf(ctx),)
        elif op == VAR:
            ty = lift(ctx[t[1]], t[1]+1); rule, ext, u, v, refs = VREF, 0, 0, 0, (self.wf(ctx),)
        elif op == PI:
            a, body = t[1:]; aty, ar = self.infer(ctx, a)
            bty, br = self.infer((a, *ctx), body)
            ty = sort(imax(level(aty), level(bty)))
            rule, ext, u, v, refs = PIF, self.ctx((a, *ctx)), self.term(aty), self.term(bty), (ar, br)
        elif op == LAM:
            a, body = t[1:]; bty, br = self.infer((a, *ctx), body)
            ty = pi(a, bty); pty, pr = self.infer(ctx, ty); level(pty)
            rule, ext, u, v, refs = LAMF, self.ctx((a, *ctx)), self.term(pty), 0, (pr, br)
        else:
            fn, arg = t[1:]; fty, fr = self.infer(ctx, fn)
            if fty[0] != PI: raise ValueError('expected Pi')
            aty, ar = self.infer(ctx, arg)
            if aty != fty[1]: ar = self.convert(ctx, arg, aty, ar, fty[1])
            ty = sub(fty[2], arg)
            rule, ext, u, v, refs = APPF, 0, self.term(fty), 0, (fr, ar)
        key = ('ty', ctx, t, ty)
        if key in self.memo: return ty, self.memo[key]
        return ty, self.emit(key, rule, c, tid, self.term(ty), ext, u, v, refs)

    def convert(self, ctx, t, old, row, target):
        if old == target: return row
        if normalize(old) != normalize(target): raise ValueError('not convertible')
        key = ('ty', ctx, t, target)
        if key in self.memo: return self.memo[key]
        sty, sr = self.infer(ctx, target); level(sty)
        return self.emit(key, CONV, self.ctx(ctx), self.term(t), self.term(target),
                         0, self.term(old), self.term(sty), (row, sr))

    def build(self, name, t, target=None):
        ty, row = self.infer((), t)
        if target is not None: row = self.convert((), t, ty, row, target); ty = target
        # If a reused final judgement appears early, prune the proof to its ancestors.
        reachable = set()
        def visit(i):
            if i in reachable: return
            reachable.add(i)
            for p in self.rows[i]['refs']: visit(p)
        visit(row)
        chosen = sorted(reachable)
        positions = {old: new for new, old in enumerate(chosen)}
        rows = [{'rule': self.rows[i]['rule'], 'refs': [positions[j] for j in self.rows[i]['refs']]} for i in chosen]
        # Add valid unused public descriptors and shuffle public rule table.
        s0, s1 = self.term(sort(0)), self.term(sort(1))
        for c in range(len(self.contexts)):
            d = [SRT, c, s0, s1, 0, 0, 0]
            if d not in self.desc: self.desc.append(d)
        order = list(range(len(self.desc))); random.Random(name).shuffle(order)
        perm = {old: new for new, old in enumerate(order)}
        for r in rows: r['rule'] = perm[r['rule']]
        return {'name': name, 'terms': self.terms, 'contexts': self.contexts,
                'descriptors': [self.desc[i] for i in order], 'steps': rows,
                'goal': [1, 0, self.term(t), self.term(ty)]}


def compile_rules(case):
    """Replay public descriptors into exact conclusions/premises, without trusting proof steps."""
    terms = []
    for op, a, b in case['terms']:
        if op in (SORT, VAR) and b == 0: t = (op, a)
        elif op in (PI, LAM, APP) and 0 <= a < len(terms) and 0 <= b < len(terms): t = (op, terms[a], terms[b])
        else: raise ValueError('arena')
        if t in terms: raise ValueError('duplicate term')
        terms.append(t)
    contexts = [()]
    for parent, a in case['contexts'][1:]:
        c = (terms[a], *contexts[parent]); contexts.append(c)
    def wf(c): return (0, c, 0, 0)
    def ty(c, t, a): return (1, c, terms.index(t), terms.index(a))
    out = []
    for op, c, tid, aid, e, u, v in case['descriptors']:
        ctx, t, a, st, vt = contexts[c], terms[tid], terms[aid], terms[u], terms[v]
        goal = ty(c, t, a)
        if op == EMPTY:
            assert c == tid == aid == e == u == v == 0; goal, pre = wf(0), []
        elif op == EXTEND:
            parent, binder = case['contexts'][c]; assert c != 0 and tid == aid == e == v == 0; level(st)
            goal, pre = wf(c), [wf(parent), ty(parent, terms[binder], st)]
        elif op == SRT:
            assert e == u == v == 0 and a == sort(level(t)+1); pre = [wf(c)]
        elif op == VREF:
            assert e == u == v == 0 and t[0] == VAR and a == lift(ctx[t[1]], t[1]+1); pre = [wf(c)]
        elif op == PIF:
            assert t[0] == PI and contexts[e] == (t[1], *ctx) and a == sort(imax(level(st),level(vt)))
            pre = [ty(c,t[1],st),ty(e,t[2],vt)]
        elif op == LAMF:
            assert t[0] == LAM and a[0] == PI and t[1] == a[1] and contexts[e] == (t[1], *ctx) and v == 0; level(st)
            pre = [ty(c,a,st),ty(e,t[2],a[2])]
        elif op == APPF:
            assert e == v == 0 and t[0] == APP and st[0] == PI and a == sub(st[2],t[2])
            pre = [ty(c,t[1],st),ty(c,t[2],st[1])]
        elif op == CONV:
            assert e == 0 and normalize(st) == normalize(a); level(vt)
            pre = [ty(c,t,st),ty(c,a,vt)]
        else: raise ValueError('descriptor')
        out.append((goal, pre))
    return out


def replay(case):
    rules, prior = compile_rules(case), []
    for row in case['steps']:
        goal, pre = rules[row['rule']]
        assert len(row['refs']) == len(pre) and all(0 <= p < len(prior) for p in row['refs'])
        assert [prior[p] for p in row['refs']] == pre
        prior.append(goal)
    assert prior[-1] == tuple(case['goal'])
    return len(prior)


def fixtures():
    P, T = ('s',0), ('s',1)
    l = lambda n,a,b: ('l',n,a,b)
    p = lambda n,a,b: ('p',n,a,b)
    a = lambda f,x: ('a',f,x)
    ident = l('A',P,l('x','A','x'))
    dep = l('A',T,l('B',p('z','A',T),l('f',p('z','A',a('B','z')),l('x','A',a('f','x')))))
    const = l('A',P,l('B',P,l('x','A',l('y','B','x'))))
    conv = p('A',P,p('x','A',a(l('X',P,'X'),'A')))
    cases = [('identity',ident,None),('dependent_app',dep,None),('weakening',const,None),('conversion',ident,conv),
             ('impredicative_pi',p('A',T,p('x',p('z','A',P),P)),None)]
    return [Builder().build(n,named(t),named(g) if g is not None else None) for n,t,g in cases]


def main():
    parser=argparse.ArgumentParser(); parser.add_argument('--out',type=Path,required=True); args=parser.parse_args()
    cases=fixtures()
    print(json.dumps([{'name':c['name'],'terms':len(c['terms']),'contexts':len(c['contexts']),'rules':len(c['descriptors']),'rows':replay(c)} for c in cases]))
    print('ops',sorted(set(c['descriptors'][s['rule']][0] for c in cases for s in c['steps'])))
    args.out.write_text(json.dumps({'schema':'zkl-typed-public-v1','cases':cases},sort_keys=True,separators=(',',':'))+'\n')


if __name__=='__main__': main()
