"""Opt-in byte-convolution multiplication candidate for the research backend.

The original Horner traces and compilers remain unchanged. This module supplies
standalone predicates and an explicit builder routed through the shared WOTS
graph adapter. Native signature-inclusive footprint evidence comes from the
hosted comparison, never from the word census alone.

For canonical a,b,c, the graph proves the INTEGER equality a*b = c + p*q.
q is an unsigned 32-byte integer, not a field element. Sixty-four radix-256
columns telescope using signed carries encoded with offset8192. Both endpoint
carries are anchored to that offset. The existing canonical-field declarations
remain necessary, especially when importing this graph into the WOTS adapter.
"""
from functools import lru_cache
from hashlib import sha256

from compact import BorrowBuilder
from script import BASE, OPS, P, Q, execute, num, push
from trace import (BoundTrace, Constraint, MAX_ARGUMENTS, MAX_CONSTRAINTS,
                   Program, TraceBuilder)
from trace_kernels import compile_predicate

BYTE = 256
CARRY_OFFSET, CARRY_BOUND = 8192, 16384
AB_BOUND, PQ_BOUND = 1 << 18, 1 << 19
KINDS = frozenset(('conv_split', 'conv_reconstruct', 'conv_ab',
                   'conv_pq', 'conv_column'))


def _integer(value, minimum, maximum):
    return type(value) is int and minimum <= value <= maximum


def _bounds(p, kind, argument):
    """Validate public shape and return every formal operand's range bound."""
    if type(p) is not int or p not in (P, Q) or type(kind) is not str or type(argument) is not tuple:
        raise ValueError('unsupported convolution field/argument')
    if kind == 'conv_split':
        if len(argument) != 1 or not _integer(argument[0], 1, 7):
            raise ValueError('crossing byte split width')
        low, = argument
        return (BYTE, 1 << low, 1 << (8-low))
    if kind == 'conv_reconstruct':
        if (not 1 <= len(argument) <= 5
                or any(not _integer(width, 1, 8) for width in argument)
                or not 1 <= sum(argument) <= 29):
            raise ValueError('limb reconstruction widths')
        return (BASE,)+tuple(1 << width for width in argument)
    if kind == 'conv_ab':
        if len(argument) != 1 or not _integer(argument[0], 1, 4):
            raise ValueError('byte product block size')
        count, = argument
        return (BYTE, BYTE)*count+(AB_BOUND,)
    if kind == 'conv_pq':
        if (not 1 <= len(argument) <= 8
                or any(not _integer(coefficient, 1, 255) for coefficient in argument)):
            raise ValueError('public modulus byte block')
        return (BYTE,)*len(argument)+(PQ_BOUND,)
    if kind == 'conv_column':
        if (len(argument) != 3 or not _integer(argument[0], 0, 8)
                or not _integer(argument[1], 0, 4)
                or not _integer(argument[2], 0, 1)):
            raise ValueError('convolution column shape')
        ab, pq, has_output = argument
        return ((AB_BOUND,)*ab+(PQ_BOUND,)*pq+(CARRY_BOUND, CARRY_BOUND)
                +(BYTE,)*has_output)
    raise ValueError('unknown convolution predicate')


def convolution_native(p, kind, argument, values):
    bounds = _bounds(p, kind, argument)
    if (len(values) != len(bounds)
            or any(not _integer(value, 0, bound-1)
                   for value, bound in zip(values, bounds, strict=True))):
        return False
    if kind == 'conv_split':
        return values[0] == values[1]+(values[2] << argument[0])
    if kind == 'conv_reconstruct':
        accumulator, offset = 0, 0
        for value, width in zip(values[1:], argument, strict=True):
            accumulator += value << offset
            offset += width
        return values[0] == accumulator
    if kind == 'conv_ab':
        return values[-1] == sum(values[2*i]*values[2*i+1]
                                 for i in range(argument[0]))
    if kind == 'conv_pq':
        return values[-1] == sum(value*coefficient for value, coefficient
                                 in zip(values[:-1], argument, strict=True))
    ab, pq, has_output = argument
    incoming, outgoing = values[ab+pq:ab+pq+2]
    output = values[-1] if has_output else 0
    return (sum(values[:ab])+incoming+255*CARRY_OFFSET
            == output+sum(values[ab:ab+pq])+256*outgoing)


def _times_power(b, value, exponent):
    saved = list(b.stack)
    result = value
    for _ in range(exponent):
        result = b.binary('ADD', result, result)
        b.keep(saved+[result])
    return result


def _times_constant(b, value, coefficient):
    saved = list(b.stack)
    result = b.literal(0)
    for bit in range(coefficient.bit_length()-1, -1, -1):
        result = b.binary('ADD', result, result)
        if (coefficient >> bit) & 1:
            result = b.binary('ADD', result, value)
        b.keep(saved+[result])
    return result


def _times_byte(b, left, right):
    """Eight derived Boolean bits; no per-product asserted bit wires."""
    saved = list(b.stack)
    remainder, result = right, b.literal(0)
    for bit in range(7, -1, -1):
        power = 1 << bit
        flag = b.binary('GREATERTHANOREQUAL', remainder, b.literal(power))
        remainder = b.binary('SUB', remainder, b.choose(flag, power, 0))
        result = b.binary('ADD', b.binary('ADD', result, result),
                          b.choose(flag, left, 0))
        b.keep(saved+[remainder, result])
    return result


def compile_convolution_predicate(p, kind, argument=()):
    """Correctness body. Authentication/length guards belong to its adapter."""
    # Validate before caching: Python considers (True,) equal to (1,), so a
    # public cached validator could admit a Boolean shape after an integer hit.
    _bounds(p, kind, argument)
    return _compile_convolution_predicate(p, kind, argument)


@lru_cache(maxsize=256)
def _compile_convolution_predicate(p, kind, argument):
    bounds = _bounds(p, kind, argument)
    names = [f'w{i}' for i in range(len(bounds))]
    b = BorrowBuilder(names)
    for name, bound in zip(names, bounds, strict=True):
        b.range(name, bound)
    saved = list(b.stack)
    if kind == 'conv_split':
        expected = b.binary('ADD', names[1], _times_power(b, names[2], argument[0]))
        expected, actual = expected, names[0]
    elif kind == 'conv_reconstruct':
        expected = b.literal(0)
        for name, width in reversed(tuple(zip(names[1:], argument, strict=True))):
            expected = b.binary('ADD', _times_power(b, expected, width), name)
            b.keep(saved+[expected])
        actual = names[0]
    elif kind == 'conv_ab':
        expected = b.literal(0)
        for pair in range(argument[0]):
            product = _times_byte(b, names[2*pair], names[2*pair+1])
            expected = b.binary('ADD', expected, product)
            b.keep(saved+[expected])
        actual = names[-1]
    elif kind == 'conv_pq':
        expected = b.literal(0)
        for name, coefficient in zip(names[:-1], argument, strict=True):
            product = _times_constant(b, name, coefficient)
            expected = b.binary('ADD', expected, product)
            b.keep(saved+[expected])
        actual = names[-1]
    else:
        ab, pq, has_output = argument
        incoming, outgoing = names[ab+pq:ab+pq+2]
        expected = b.binary('ADD', incoming, b.literal(255*CARRY_OFFSET))
        for name in names[:ab]:
            expected = b.binary('ADD', expected, name)
            b.keep(saved+[expected])
        actual = _times_power(b, outgoing, 8)
        for name in names[ab:ab+pq]:
            actual = b.binary('ADD', actual, name)
            b.keep(saved+[expected, actual])
        if has_output:
            actual = b.binary('ADD', actual, names[-1])
    result = b.binary('EQUAL', expected, actual)
    b.keep([result])
    return bytes(b.code)


class ConvolutionConstraint(Constraint):
    def native(self, values, p):
        if self.kind in KINDS:
            return convolution_native(p, self.kind, self.argument,
                                      [values[word] for word in self.wires])
        return super().native(values, p)


class ConvolutionBoundTrace(BoundTrace):
    """Standalone fixed-claim adapter; original BoundTrace stays unchanged."""
    def script(self, ordinal, *, disprove=True, compiler='convolution-v1'):
        if compiler != 'convolution-v1':
            raise ValueError('convolution trace requires explicit compiler identity')
        if type(ordinal) is not int or not 0 <= ordinal < len(self.program.constraints):
            raise ValueError('constraint ordinal out of bounds')
        constraint = self.program.constraints[ordinal]
        mode = b'D' if disprove else b'C'
        tag = sha256(b'BITVM2-NOVA/LEAF/convolution-v1\x00'+self.program_digest
                     +self.claim_digest+ordinal.to_bytes(4, 'little')+mode).digest()
        code = bytearray(bytes([OPS['DEPTH']])+push(num(len(constraint.wires)))
                         +bytes([OPS['EQUALVERIFY']])+push(tag)+bytes([OPS['DROP']]))
        for i, word in enumerate(constraint.wires):
            code.extend(push(num(len(constraint.wires)-1-i)))
            code.extend([OPS['PICK'], OPS['SHA256']])
            code.extend(push(self.hashes[word]))
            code.append(OPS['EQUALVERIFY'])
        if constraint.kind in KINDS:
            code.extend(compile_convolution_predicate(self.program.p, constraint.kind,
                                                     constraint.argument))
        else:
            code.extend(compile_predicate(self.program.p, constraint.kind, constraint.argument))
        if disprove:
            code.append(OPS['NOT'])
        return bytes(code)

    def execute(self, ordinal, *, disprove=True, compiler='convolution-v1'):
        return execute(self.script(ordinal, disprove=disprove, compiler=compiler),
                       self.witness(ordinal))


class ConvolutionProgram(Program):
    def bind(self, values):
        return ConvolutionBoundTrace(self, values)


class ConvolutionTraceBuilder(TraceBuilder):
    """Explicit alternative builder. Witness values never choose topology."""
    def __init__(self, role, operation_id, context):
        super().__init__(role, operation_id, context)
        self._byte_fields = {}

    def check(self, kind, ws, argument=()):
        if kind not in KINDS:
            return super().check(kind, ws, argument)
        ws, argument = tuple(ws), tuple(argument)
        bounds = _bounds(self.p, kind, argument)
        if (len(ws) != len(bounds) or len(ws) > MAX_ARGUMENTS
                or any(word not in self.words for word in ws)
                or any(self.words[word] != bound
                       for word, bound in zip(ws, bounds, strict=True))):
            raise ValueError('convolution predicate arity/wires/bounds')
        if len(self.constraints) >= MAX_CONSTRAINTS:
            raise ValueError('constraint bound exceeded')
        compile_convolution_predicate(self.p, kind, argument)
        self.constraints.append(ConvolutionConstraint(kind, ws, argument))

    def _bytes(self, name, field):
        field = tuple(field)
        if field in self._byte_fields:
            return self._byte_fields[field]
        if len(field) != 9 or field not in self.fields.values():
            raise ValueError('declared canonical field wires required')
        value = self.value(field)
        digits = tuple(self.small(f'{name}/byte/{i}', (value >> (8*i)) & 255, BYTE)
                       for i in range(32))
        crossings = {}
        for boundary in (29, 58, 87, 116, 145, 174, 203):
            index, low = divmod(boundary, 8)
            byte = self.values[digits[index]]
            lo = self.small(f'{name}/split/{index}/lo', byte & ((1 << low)-1), 1 << low)
            hi = self.small(f'{name}/split/{index}/hi', byte >> low, 1 << (8-low))
            self.check('conv_split', (digits[index], lo, hi), (low,))
            crossings[index] = (low, lo, hi)
        for limb, original in enumerate(field):
            start, end = limb*29, min(limb*29+29, 256)
            pieces, widths = [], []
            for byte_index in range(start//8, (end+7)//8):
                low, high = max(start, byte_index*8), min(end, byte_index*8+8)
                if low == byte_index*8 and high == byte_index*8+8:
                    part = digits[byte_index]
                else:
                    _, lo, hi = crossings[byte_index]
                    part = lo if low == byte_index*8 else hi
                pieces.append(part)
                widths.append(high-low)
            self.check('conv_reconstruct', (original,)+tuple(pieces), tuple(widths))
        self._byte_fields[field] = digits
        return digits

    def mul(self, name, x, y, *, claimed_value=None, quotient=None):
        xv, yv = self.value(x), self.value(y)
        value = xv*yv % self.p if claimed_value is None else claimed_value
        qv = xv*yv // self.p if quotient is None else quotient
        if type(qv) is not int or not 0 <= qv < 1 << 256:
            raise ValueError('unsigned32-byte quotient required')
        result = self.field(name, value)
        a = self._bytes(name+'/a', x)
        b = self._bytes(name+'/b', y)
        c = self._bytes(name+'/c', result)
        q = tuple(self.small(f'{name}/q/{i}', (qv >> (8*i)) & 255, BYTE)
                  for i in range(32))
        modulus = self.p.to_bytes(32, 'little')
        carry = self.small_constant(name+'/carry/0', CARRY_OFFSET, CARRY_BOUND)
        signed = 0
        for column in range(64):
            products = [(i, column-i) for i in range(32) if 0 <= column-i < 32]
            ab, pq = [], []
            for block in range(0, len(products), 4):
                pairs = products[block:block+4]
                total = sum(self.values[a[i]]*self.values[b[j]] for i, j in pairs)
                out = self.small(f'{name}/ab/{column}/{block//4}', total, AB_BOUND)
                self.check('conv_ab', tuple(word for i, j in pairs for word in (a[i], b[j]))
                           +(out,), (len(pairs),))
                ab.append(out)
            products = [(modulus[i], column-i) for i in range(32)
                        if modulus[i] and 0 <= column-i < 32]
            for block in range(0, len(products), 8):
                pairs = products[block:block+8]
                total = sum(coefficient*self.values[q[j]] for coefficient, j in pairs)
                out = self.small(f'{name}/pq/{column}/{block//8}', total, PQ_BOUND)
                self.check('conv_pq', tuple(q[j] for _, j in pairs)+(out,),
                           tuple(coefficient for coefficient, _ in pairs))
                pq.append(out)
            output = self.values[c[column]] if column < 32 else 0
            signed = (sum(self.values[word] for word in ab)+signed-output
                      -sum(self.values[word] for word in pq)) // 256
            outgoing = self.small(f'{name}/carry/{column+1}', signed+CARRY_OFFSET, CARRY_BOUND)
            self.check('conv_column', tuple(ab)+tuple(pq)+(carry, outgoing)
                       +((c[column],) if column < 32 else ()),
                       (len(ab), len(pq), int(column < 32)))
            carry = outgoing
        self.check('const', (carry,), (CARRY_OFFSET,))
        return result

    def finish(self):
        program = ConvolutionProgram(self.role, self.operation_id, self.context,
            tuple(self.words.items()), tuple(self.fields.items()), tuple(self.constraints))
        return program, dict(self.values)


def multiplication_trace(role, x, y, *, context=bytes(32), operation_id='convolution/mul',
                         claimed_value=None, quotient=None):
    builder = ConvolutionTraceBuilder(role, operation_id, context)
    a, b = builder.field('input/a', x), builder.field('input/b', y)
    builder.mul('product', a, b, claimed_value=claimed_value, quotient=quotient)
    return builder.finish()
