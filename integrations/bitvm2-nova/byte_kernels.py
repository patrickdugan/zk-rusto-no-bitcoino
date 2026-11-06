"""Opt-in BYTE arithmetic predicates; the Boolean backend stays unchanged.

All formal operands, including outputs and repeated aliases, have exclusive
bound256. Binary XOR/AND and cross-byte left-rotation derive the necessary bits
inside Script by descending comparisons/subtractions. They accept no asserted
bit witnesses and use no OP_XOR, OP_AND, OP_MUL, OP_CAT or experimental opcode.

byte_rol(a,b,out;r) means out=((a<<r)&255)+(b>>(8-r)), r=1..7. For a future
little-endian64-bit lane rotation s=8*q+r, output byte j would consume
a=input[(j-q)%8], b=input[(j-q-1)%8]. Byte-aligned routing is outside this kernel.
byte_xor_const has one PUBLIC mask0..255, including copy0 and complement255.

Wrong bounded outputs return ordinary false; the disproof adapter inverts that
Boolean. Out-of-range or nonminimal numeric operands abort the bare body instead.
The existing authenticated adapter's decoder/invalid-message rules remain
necessary; an abort is never evidence of successful disproof. This module is
neither a byte Keccak permutation nor a hash/transcript/proof verifier.
"""
from functools import lru_cache
from hashlib import sha256

from compact import BorrowBuilder
from script import P, Q, execute
from trace import (BoundTrace, Constraint, ID, MAX_ARGUMENTS, MAX_CONSTRAINTS,
                   Program, ROLES, TraceBuilder)

BYTE = 256
COMPILER = 'byte-v1'
PROGRAM_DOMAIN = b'BITVM2-NOVA/BYTE-TRACE/v1\x00'
KINDS = frozenset(('byte_xor', 'byte_and', 'byte_not', 'byte_rol', 'byte_xor_const'))


def _integer(value, low, high):
    return type(value) is int and low <= value <= high


def _bounds(p, kind, argument):
    """Validate immutable public shape before cache lookup or operand use."""
    if (type(p) is not int or p not in (P, Q) or type(kind) is not str
            or kind not in KINDS or type(argument) is not tuple):
        raise ValueError('unsupported byte field/kind/immutable argument')
    if kind in ('byte_xor', 'byte_and', 'byte_not'):
        if argument:
            raise ValueError('byte Boolean predicate takes no public arguments')
    elif kind == 'byte_rol':
        if len(argument) != 1 or not _integer(argument[0], 1, 7):
            raise ValueError('cross-byte rotation must be an integer1..7')
    elif len(argument) != 1 or not _integer(argument[0], 0, 255):
        raise ValueError('public byte XOR mask must be an integer0..255')
    return (BYTE,)*(2 if kind in ('byte_not', 'byte_xor_const') else 3)


def _expected(kind, argument, inputs):
    if kind == 'byte_xor':
        return inputs[0] ^ inputs[1]
    if kind == 'byte_and':
        return inputs[0] & inputs[1]
    if kind == 'byte_not':
        return 255-inputs[0]
    if kind == 'byte_rol':
        shift, = argument
        return ((inputs[0] << shift) & 255)+(inputs[1] >> (8-shift))
    return inputs[0] ^ argument[0]


def byte_native(p, kind, argument, values):
    """Independent integer relation, not an encoding/admissibility receipt.

    False for an out-of-domain operand is a domain-failure diagnostic. The bare
    Script range guard aborts on that input; its inverse does not become true.
    """
    bounds = _bounds(p, kind, argument)
    if (type(values) not in (tuple, list) or len(values) != len(bounds)
            or any(not _integer(value, 0, BYTE-1) for value in values)):
        return False
    return values[-1] == _expected(kind, argument, values[:-1])


def _unary(builder, opcode, value):
    builder.copy(value)
    builder.op(opcode)
    name = builder.name()
    builder.stack[-1] = name
    return name


def _finish(builder, actual, expected):
    result = builder.binary('EQUAL', actual, expected)
    builder.keep([result])
    return bytes(builder.code)


def compile_byte_predicate(p, kind, argument=()):
    # tuple(True) aliases tuple(1) in Python dictionaries. Validate every public
    # parameter BEFORE the private cache, even when a valid integer shape is hot.
    _bounds(p, kind, argument)
    return _compile_byte_predicate(p, kind, argument)


@lru_cache(maxsize=1024)
def _compile_byte_predicate(p, kind, argument):
    bounds = _bounds(p, kind, argument)
    names = ['a', 'out'] if len(bounds) == 2 else ['a', 'b', 'out']
    builder = BorrowBuilder(names)
    for name in names:
        builder.range(name, BYTE)
    saved = list(builder.stack)
    if kind == 'byte_not':
        return _finish(builder, 'out', builder.binary('SUB', builder.literal(255), 'a'))
    if kind == 'byte_xor_const':
        mask, = argument
        if mask == 0:
            return _finish(builder, 'out', 'a')
        if mask == 255:
            return _finish(builder, 'out', builder.binary('SUB', builder.literal(255), 'a'))
        remainder, expected = 'a', builder.binary('ADD', 'a', builder.literal(0))
        low = (mask & -mask).bit_length()-1
        for bit in range(7, low-1, -1):
            power = 1 << bit
            flag = builder.binary('GREATERTHANOREQUAL', remainder, builder.literal(power))
            remainder = builder.binary('SUB', remainder, builder.choose(flag, power, 0))
            if mask & power:  # Public mask only, never an assignment bit.
                expected = builder.binary('ADD', expected, builder.choose(flag, -power, power))
            builder.keep(saved+[remainder, expected])
        return _finish(builder, 'out', expected)

    left, right, accumulator = 'a', 'b', builder.literal(0)
    width = argument[0] if kind == 'byte_rol' else 8
    for bit in range(7, 7-width, -1):
        power = 1 << bit
        left_bit = builder.binary('GREATERTHANOREQUAL', left, builder.literal(power))
        left = builder.binary('SUB', left, builder.choose(left_bit, power, 0))
        right_bit = builder.binary('GREATERTHANOREQUAL', right, builder.literal(power))
        right = builder.binary('SUB', right, builder.choose(right_bit, power, 0))
        if kind == 'byte_xor':
            flag = _unary(builder, 'NOT', builder.binary('EQUAL', left_bit, right_bit))
        elif kind == 'byte_and':
            flag = builder.binary('BOOLAND', left_bit, right_bit)
        else:
            flag = right_bit
        accumulator = builder.binary('ADD', builder.binary('ADD', accumulator, accumulator), flag)
        builder.keep(saved+[left, right, accumulator])
    if kind == 'byte_rol':
        # Only a % 2**(8-r) survives the r derived high-bit subtractions.
        # Repeated doubling is therefore <=256-2**r; adding b's high r bits
        # yields <=255. No intermediate full a<<r is formed in Script.
        scaled = left
        for _ in range(width):
            scaled = builder.binary('ADD', scaled, scaled)
            builder.keep(saved+[scaled, accumulator])
        accumulator = builder.binary('ADD', scaled, accumulator)
    return _finish(builder, 'out', accumulator)


class ByteConstraint(Constraint):
    def native(self, values, p):
        if self.kind in KINDS:
            return byte_native(p, self.kind, self.argument, [values[word] for word in self.wires])
        return super().native(values, p)


class ByteBoundTrace(BoundTrace):
    """Byte-v1 identity with byte-for-byte reuse of inherited opening guards."""
    def script(self, ordinal, *, disprove=True, compiler=COMPILER):
        if type(compiler) is not str or compiler != COMPILER:
            raise ValueError('byte trace requires its explicit byte-v1 compiler identity')
        # ByteProgram.digest already includes PROGRAM_DOMAIN. The inherited
        # leaf tag binds that digest, claim, ordinal and mode; its exact witness
        # length and per-occurrence opening checks stay unchanged.
        return super().script(ordinal, disprove=disprove, compiler='m2')

    def execute(self, ordinal, *, disprove=True, compiler=COMPILER):
        return execute(self.script(ordinal, disprove=disprove, compiler=compiler), self.witness(ordinal))

    def manifest(self):
        return super().manifest() | {'compiler': COMPILER, 'program_kind': 'byte-kernels/v1'}


class ByteProgram(Program):
    def digest(self):
        return sha256(PROGRAM_DOMAIN+super().digest()).digest()

    def bind(self, values):
        return ByteBoundTrace(self, values)


class ByteTraceBuilder(TraceBuilder):
    """Optional BYTE-only builder; every formal alias keeps its declared bound."""
    def __init__(self, role, operation_id, context):
        if (type(role) is not str or role not in ROLES
                or type(operation_id) is not str or not ID.fullmatch(operation_id)
                or type(context) is not bytes or len(context) != 32):
            raise ValueError('explicit byte role/operation/32-byte context required')
        super().__init__(role, operation_id, context)

    def byte(self, name, value):
        return self.small(name, value, BYTE)

    def check(self, kind, ws, argument=()):
        if type(kind) is not str or type(ws) not in (tuple, list) or type(argument) is not tuple:
            raise ValueError('ordered byte wires and immutable public arguments required')
        ws = tuple(ws)
        if kind == 'const':
            if (len(ws) != 1 or len(argument) != 1 or not _integer(argument[0], 0, BYTE-1)):
                raise ValueError('BYTE constant requires one word and an integer0..255')
            bounds = (BYTE,)
        else:
            bounds = _bounds(self.p, kind, argument)
        if (len(ws) != len(bounds) or len(ws) > MAX_ARGUMENTS
                or any(type(word) is not str or word not in self.words for word in ws)
                or any(type(self.words[word]) is not int or self.words[word] != bound
                       for word, bound in zip(ws, bounds, strict=True))):
            raise ValueError('byte predicate arity/wires/exact formal bounds mismatch')
        if len(self.constraints) >= MAX_CONSTRAINTS:
            raise ValueError('constraint bound exceeded')
        if kind == 'const':
            super().check(kind, ws, argument)
            self.constraints[-1] = ByteConstraint(kind, ws, argument)
        else:
            compile_byte_predicate(self.p, kind, argument)
            self.constraints.append(ByteConstraint(kind, ws, argument))

    def apply(self, kind, name, *inputs, argument=(), claimed_value=None):
        bounds = _bounds(self.p, kind, argument)
        if (len(inputs) != len(bounds)-1
                or any(type(word) is not str or word not in self.words
                       or type(self.words[word]) is not int or self.words[word] != BYTE
                       for word in inputs)):
            raise ValueError('byte operation requires exact BYTE input occurrences')
        expected = _expected(kind, argument, [self.values[word] for word in inputs])
        value = expected if claimed_value is None else claimed_value
        out = self.byte(name, value)
        self.check(kind, inputs+(out,), argument)
        return out

    def finish(self):
        if (self.fields or not self.words or not self.constraints
                or any(type(bound) is not int or bound != BYTE for bound in self.words.values())
                or any(type(c) is not ByteConstraint for c in self.constraints)):
            raise ValueError('byte program requires BYTE words and byte/constant constraints only')
        program = ByteProgram(self.role, self.operation_id, self.context,
            tuple(self.words.items()), (), tuple(self.constraints))
        return program, dict(self.values)


def byte_kernel_trace(role, kind, inputs, *, argument=(), context,
                      operation_id='byte/kernel', claimed_value=None):
    """Return one optional versioned kernel Program and an assignment snapshot.

    Every input/output remains a BYTE port; use ByteTraceBuilder.check for
    explicit input/output aliases. No bit witnesses or alternate default backend
    are introduced. This tiny graph API is safe for bounded local kernel tests.
    """
    builder = ByteTraceBuilder(role, operation_id, context)
    bounds = _bounds(builder.p, kind, argument)
    if type(inputs) not in (tuple, list) or len(inputs) != len(bounds)-1:
        raise ValueError('byte kernel input count mismatch')
    wires = tuple(builder.byte('a' if i == 0 else 'b', value) for i, value in enumerate(inputs))
    builder.apply(kind, 'out', *wires, argument=argument, claimed_value=claimed_value)
    return builder.finish()
