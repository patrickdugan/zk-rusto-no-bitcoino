"""Render the exact public typed goals as closed Lean definitions."""
import argparse
import json
from pathlib import Path


def render(arena, i, depth=0):
    tag, a, b = arena[i]
    if tag == 0:
        return f'(Sort {a})'
    if tag == 1:
        if a >= depth:
            raise ValueError('free variable in closed goal')
        return f'x{depth - 1 - a}'
    if tag == 4:
        return f'({render(arena, a, depth)} {render(arena, b, depth)})'
    domain = render(arena, a, depth)
    body = render(arena, b, depth + 1)
    if tag == 2:
        return f'(∀ (x{depth} : {domain}), {body})'
    if tag == 3:
        return f'(fun (x{depth} : {domain}) => {body})'
    raise ValueError('tag')


def main():
    p = argparse.ArgumentParser()
    p.add_argument('fixture', type=Path)
    p.add_argument('--out', type=Path, required=True)
    a = p.parse_args()
    cases = json.loads(a.fixture.read_text())['cases']
    lines = []
    for c in cases:
        kind, ctx, t, ty = c['goal']
        assert kind == 1 and ctx == 0
        name = 'zkl_' + c['name']
        lines.append(f'def {name} : {render(c["terms"], ty)} :=\n  {render(c["terms"], t)}\n#print axioms {name}')
    a.out.write_text('\n\n'.join(lines) + '\n')


if __name__ == '__main__':
    main()
