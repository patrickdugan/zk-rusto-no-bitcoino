"""Bounded Script predicates used by the M2 fixed-claim trace compiler.

Each predicate returns true for correctness. Disproof leaves invert only that
result; opening authentication and admitted-encoding checks still fail closed.
"""
from functools import lru_cache
from script import BASE, LIMBS, Builder, kernel


def eq_words(b: Builder, xs, ys):
    ok = b.literal(1)
    for x, y in zip(xs, ys, strict=True):
        ok = b.binary('BOOLAND', ok, b.binary('EQUAL', x, y))
    return ok


def zero_word(b: Builder, xs):
    zero = b.literal(0)
    return eq_words(b, xs, [zero] * len(xs))


def negate(b: Builder, value):
    return b.binary('EQUAL', value, b.literal(0))


def finish(b: Builder, ok):
    b.keep([ok])
    return bytes(b.code)


def gate(b: Builder, selector, cases):
    yes = b.literal(0)
    for case in cases:
        yes = b.binary('BOOLOR', yes, b.binary('EQUAL', selector, b.literal(case)))
    return yes


def compile_predicate(p: int, kind: str, argument: tuple[int, ...] = ()) -> bytes:
    if kind in ('byte_xor', 'byte_and', 'byte_not', 'byte_rol', 'byte_xor_const'):
        from byte_kernels import compile_byte_predicate
        return compile_byte_predicate(p, kind, argument)
    # The optional backend validates types before its private cache, so a bool
    # cannot alias an integer shape that was compiled earlier.
    if kind in ('conv_split', 'conv_reconstruct', 'conv_ab', 'conv_pq', 'conv_column'):
        from convolution import compile_convolution_predicate
        return compile_convolution_predicate(p, kind, argument)
    return _compile_predicate(p, kind, argument)


@lru_cache(maxsize=128)
def _compile_predicate(p: int, kind: str, argument: tuple[int, ...] = ()) -> bytes:
    """Compile a fixed shape. Parameters never contain claim values."""
    if kind in ('bool_xor', 'bool_and', 'bool_not'):
        if argument:
            raise ValueError('Boolean predicates have no parameters')
        names = ['a', 'out'] if kind == 'bool_not' else ['a', 'b', 'out']
        b = Builder(names)
        for name in names:
            b.range(name, 2)
        if kind == 'bool_not':
            result = negate(b, 'a')
        elif kind == 'bool_and':
            result = b.binary('BOOLAND', 'a', 'b')
        else:
            result = negate(b, b.binary('EQUAL', 'a', 'b'))
        return finish(b, b.binary('EQUAL', result, 'out'))
    if kind in ('add', 'mul_bit'):
        return kernel(p, kind)
    if kind == 'bits':
        width, = argument
        if not 1 <= width <= 29:
            raise ValueError('limb width must be 1..29')
        names = [f'b{i}' for i in range(width)]
        b = Builder(['limb'] + names)
        b.range('limb', BASE)
        acc = b.literal(0)
        for name in names:
            b.range(name, 2)
            acc = b.binary('ADD', b.binary('ADD', acc, acc), name)
        return finish(b, b.binary('EQUAL', acc, 'limb'))
    if kind == 'const':
        # The expected constant is part of the verifier-owned program.
        b = Builder(['word'])
        return finish(b, b.binary('EQUAL', 'word', b.literal(argument[0])))
    if kind in ('equal', 'gate_equal', 'gate_nonzero', 'point_form'):
        xs = [f'x{i}' for i in range(LIMBS)]
        ys = [f'y{i}' for i in range(LIMBS)]
        names = xs + ([] if kind == 'gate_nonzero' else ys)
        if kind != 'equal':
            names = ['sel'] + names
        b = Builder(names)
        for name in xs + ([] if kind == 'gate_nonzero' else ys):
            b.range(name, BASE)
        if kind == 'equal':
            return finish(b, eq_words(b, xs, ys))
        b.range('sel', 2 if kind == 'point_form' else 5)
        if kind == 'point_form':
            zero = b.binary('BOOLAND', zero_word(b, xs), zero_word(b, ys))
            return finish(b, b.binary('BOOLOR', negate(b, 'sel'), zero))
        active = gate(b, 'sel', argument)
        good = negate(b, zero_word(b, xs)) if kind == 'gate_nonzero' else eq_words(b, xs, ys)
        return finish(b, b.binary('BOOLOR', negate(b, active), good))
    if kind == 'dispatch':
        # inf flags; input x/y; canonical y1+y2; claimed branch.
        x = [f'x{i}' for i in range(LIMBS)]
        y = [f'y{i}' for i in range(LIMBS)]
        xx = [f'X{i}' for i in range(LIMBS)]
        yy = [f'Y{i}' for i in range(LIMBS)]
        sy = [f's{i}' for i in range(LIMBS)]
        b = Builder(['i1', 'i2'] + x + y + xx + yy + sy + ['case'])
        b.range('i1', 2)
        b.range('i2', 2)
        b.range('case', 5)
        for name in x + y + xx + yy + sy:
            b.range(name, BASE)
        same_x = eq_words(b, x, xx)
        inverse = b.binary('BOOLAND', same_x, zero_word(b, sy))
        same_point = b.binary('BOOLAND', same_x, eq_words(b, y, yy))
        ordinary = b.choose(same_point, 3, 4)
        finite = b.choose(inverse, 2, ordinary)
        right_inf = b.choose('i2', 1, finite)
        expected = b.choose('i1', 0, right_inf)
        return finish(b, b.binary('EQUAL', expected, 'case'))
    if kind == 'gate_small_equal':
        b = Builder(['sel', 'a', 'b'])
        b.range('sel', 5)
        b.range('a', 2)
        b.range('b', 2)
        active = gate(b, 'sel', argument)
        good = b.binary('EQUAL', 'a', 'b')
        return finish(b, b.binary('BOOLOR', negate(b, active), good))
    raise ValueError(f'unknown predicate: {kind}')
