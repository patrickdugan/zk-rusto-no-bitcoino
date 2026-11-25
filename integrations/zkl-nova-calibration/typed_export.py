"""Infer monomorphic simple types for public raw conversion examples and export Lean rfl goals.

No dependent type checker: this is an independent STLC admission layer for the
raw beta-equality examples, not an arbitrary Lean importer.
"""
from pathlib import Path
import argparse
import json


class Infer:
    def __init__(self):
        self.n = 0
        self.solutions = {}
        self.free = {}
        self.constants = {}

    def fresh(self):
        v = self.n
        self.n += 1
        return v

    def resolve(self, t):
        if isinstance(t, int):
            return self.resolve(self.solutions[t]) if t in self.solutions else t
        return tuple(self.resolve(x) for x in t)

    def bind(self, v, t):
        def occurs(v, t):
            t = self.resolve(t)
            return t == v if isinstance(t, int) else any(occurs(v, x) for x in t)
        if occurs(v, t):
            raise ValueError('recursive simple type')
        self.solutions[v] = t

    def unify(self, a, b):
        a, b = self.resolve(a), self.resolve(b)
        if a == b:
            return
        if isinstance(a, int):
            self.bind(a, b)
        elif isinstance(b, int):
            self.bind(b, a)
        else:
            self.unify(a[0], b[0])
            self.unify(a[1], b[1])

    def variable(self, table, i):
        if i not in table:
            table[i] = self.fresh()
        return table[i]

    def infer(self, arena, i, env=()):
        tag, a, b = arena[i]
        if tag == 0:
            if a < len(env):
                name, ty = env[a]
            else:
                j = a - len(env)
                name, ty = f'x{j}', self.variable(self.free, j)
            return ty, ('var', name)
        if tag == 1:
            return self.variable(self.constants, a), ('var', f'c{a}')
        if tag == 2:
            v = self.fresh()
            name = f'b{len(env)}'
            ty, body = self.infer(arena, a, ((name, v), *env))
            return (v, ty), ('lam', name, v, body)
        if tag == 3:
            ft, fun = self.infer(arena, a, env)
            xt, arg = self.infer(arena, b, env)
            y = self.fresh()
            self.unify(ft, (xt, y))
            return y, ('app', fun, arg)
        raise ValueError('unknown term')

    def show_type(self, t):
        t = self.resolve(t)
        if isinstance(t, int):
            return f'T{t}'
        return f'({self.show_type(t[0])} → {self.show_type(t[1])})'

    def show_term(self, t):
        if t[0] == 'var':
            return t[1]
        if t[0] == 'lam':
            return f'(fun ({t[1]} : {self.show_type(t[2])}) => {self.show_term(t[3])})'
        return f'({self.show_term(t[1])} {self.show_term(t[2])})'


def export(case):
    inf = Infer()
    a, left = inf.infer(case['terms'], case['goal'][0])
    b, right = inf.infer(case['terms'], case['goal'][1])
    inf.unify(a, b)
    params = []
    for i in range(inf.n):
        if inf.resolve(i) == i:
            params.append(f'(T{i} : Type)')
    for table, prefix in ((inf.free, 'x'), (inf.constants, 'c')):
        for i, ty in sorted(table.items()):
            params.append(f'({prefix}{i} : {inf.show_type(ty)})')
    name = 'zkl_' + case['name']
    return f'theorem {name} {" ".join(params)} :\n  {inf.show_term(left)} = {inf.show_term(right)} := rfl\n#print axioms {name}\n'


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--out', type=Path, required=True)
    args = p.parse_args()
    batch = json.loads(Path(__file__).with_name('term-fixtures.json').read_text())
    args.out.write_text('\n'.join(export(c) for c in batch['cases']))


if __name__ == '__main__':
    main()
