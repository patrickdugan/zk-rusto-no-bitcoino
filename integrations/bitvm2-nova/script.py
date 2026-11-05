"""Pasta arithmetic in Bitcoin Tapscript. Research kernels, not a bridge verifier.

Words are nine little-endian radix-2**29 limbs. The compiler uses only enabled
opcodes, no OP_MUL/CAT, and derives every carry inside Script. A small, strict
reference interpreter is included; upstream BitVM differential tests are separate.
"""
from dataclasses import dataclass
from hashlib import sha256

P = int('40000000000000000000000000000000224698fc094cf91b992d30ed00000001', 16)
Q = int('40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001', 16)
BASE, LIMBS = 1 << 29, 9
OPS = dict(IF=0x63, ELSE=0x67, ENDIF=0x68, VERIFY=0x69, TOALTSTACK=0x6b,
           FROMALTSTACK=0x6c, DROP=0x75, PICK=0x79, EQUAL=0x87,
           EQUALVERIFY=0x88, NOT=0x91, ADD=0x93, SUB=0x94, BOOLAND=0x9a,
           BOOLOR=0x9b, LESSTHAN=0x9f, GREATERTHANOREQUAL=0xa2, WITHIN=0xa5,
           SHA256=0xa8)
NAMES = {v: k for k, v in OPS.items()}


def num(n):
    if type(n) is not int:
        raise ValueError('integer required')
    if not n:
        return b''
    a = abs(n).to_bytes((abs(n).bit_length() + 7) // 8, 'little')
    if a[-1] & 128:
        a += bytes([128 if n < 0 else 0])
    elif n < 0:
        a = a[:-1] + bytes([a[-1] | 128])
    return a


def readnum(b):
    if len(b) > 4:
        raise ValueError('ScriptNum exceeds four bytes')
    if b and not (b[-1] & 127) and (len(b) == 1 or not (b[-2] & 128)):
        raise ValueError('nonminimal ScriptNum')
    if not b:
        return 0
    v = int.from_bytes(b, 'little')
    return -(v & ~(128 << (8 * (len(b) - 1)))) if b[-1] & 128 else v


def push(b):
    if len(b) > 520:
        raise ValueError('oversize stack element')
    if not b:
        return b'\x00'
    if b == b'\x81':
        return b'\x4f'
    if len(b) == 1 and 1 <= b[0] <= 16:
        return bytes([0x50 + b[0]])
    return (bytes([len(b)]) if len(b) < 76 else b'\x4c' + bytes([len(b)])
            if len(b) <= 255 else b'\x4d' + len(b).to_bytes(2, 'little')) + b


def limbs(n):
    if type(n) is not int or not 0 <= n < BASE ** LIMBS:
        raise ValueError('unsigned 261-bit input required')
    return [(n >> (29 * i)) & (BASE - 1) for i in range(LIMBS)]


class Builder:
    def __init__(self, inputs):
        self.stack = list(inputs)
        self.code = bytearray()
        self.serial = 0

    def name(self):
        self.serial += 1
        return f'v{self.serial}'

    def op(self, op):
        self.code.append(OPS[op])

    def literal(self, n):
        self.code.extend(push(num(n)))
        v = self.name()
        self.stack.append(v)
        return v

    def copy(self, v):
        self.code.extend(push(num(len(self.stack) - 1 - self.stack.index(v))))
        self.op('PICK')
        w = self.name()
        self.stack.append(w)
        return w

    def binary(self, op, a, b):
        self.copy(a)
        self.copy(b)
        self.op(op)
        self.stack.pop()
        self.stack.pop()
        v = self.name()
        self.stack.append(v)
        return v

    def choose(self, cond, a, b):
        self.copy(cond)
        self.op('IF')
        self.stack.pop()
        saved = list(self.stack)
        self.copy(a) if isinstance(a, str) else self.literal(a)
        self.op('ELSE')
        self.stack = list(saved)
        self.copy(b) if isinstance(b, str) else self.literal(b)
        self.op('ENDIF')
        v = self.name()
        self.stack[-1] = v
        return v

    def verify(self, v):
        self.copy(v)
        self.op('VERIFY')
        self.stack.pop()

    def keep(self, names):
        for v in names:
            self.copy(v)
            self.op('TOALTSTACK')
            self.stack.pop()
        for _ in self.stack:
            self.op('DROP')
        for _ in names:
            self.op('FROMALTSTACK')
        # FROMALTSTACK reverses the order in which copies were saved.
        self.stack = list(reversed(names))

    def range(self, v, bound):
        self.copy(v)
        self.literal(0)
        self.literal(bound)
        self.op('WITHIN')
        del self.stack[-3:]
        self.op('VERIFY')

    def canonical(self, xs, p):
        saved = list(self.stack)
        lt, eq = self.literal(0), self.literal(1)
        for x, m in zip(reversed(xs), reversed(limbs(p))):
            c = self.literal(m)
            lt = self.binary('BOOLOR', lt, self.binary('BOOLAND', eq, self.binary('LESSTHAN', x, c)))
            eq = self.binary('BOOLAND', eq, self.binary('EQUAL', x, c))
        self.verify(lt)
        self.keep(saved)

    def add_mod(self, xs, ys, p):
        saved = list(self.stack)
        carry, base = self.literal(0), self.literal(BASE)
        ss = []
        for x, y in zip(xs, ys):
            t = self.binary('ADD', self.binary('ADD', x, y), carry)
            carry = self.binary('GREATERTHANOREQUAL', t, base)
            ss.append(self.binary('SUB', t, self.choose(carry, BASE, 0)))
        self.verify(self.binary('EQUAL', carry, self.literal(0)))
        borrow, zero = self.literal(0), self.literal(0)
        ds = []
        for s, m in zip(ss, limbs(p)):
            t = self.binary('SUB', self.binary('SUB', s, self.literal(m)), borrow)
            borrow = self.binary('LESSTHAN', t, zero)
            ds.append(self.binary('ADD', t, self.choose(borrow, BASE, 0)))
        out = [self.choose(borrow, s, d) for s, d in zip(ss, ds)]
        self.keep(saved + out)
        return out


def kernel(p, kind='add', disprove=False):
    """Correctness predicate, or its inverse, on canonical admitted inputs.

    Witness: x[9], y[9], [bit for mul_bit], output[9]. All limbs are LE.
    mul_bit verifies output = (2*x + bit*y) mod p. Input validation failures
    abort; callers must enforce admissible encodings before trace publication.
    """
    if p not in (P, Q) or kind not in ('add', 'mul_bit'):
        raise ValueError('unsupported field/kernel')
    xs, ys, zs = [[f'{c}{i}' for i in range(LIMBS)] for c in 'xyz']
    inputs = xs + ys + (['bit'] if kind == 'mul_bit' else []) + zs
    b = Builder(inputs)
    for v in xs + ys + zs:
        b.range(v, BASE)
    b.canonical(xs, p)
    b.canonical(ys, p)
    if kind == 'mul_bit':
        b.range('bit', 2)
        twice = b.add_mod(xs, xs, p)
        gated = [b.choose('bit', y, 0) for y in ys]
        out = b.add_mod(twice, gated, p)
    else:
        out = b.add_mod(xs, ys, p)
    ok = b.literal(1)
    for z, r in zip(zs, out):
        ok = b.binary('BOOLAND', ok, b.binary('EQUAL', z, r))
    b.keep([ok])
    if disprove:
        b.op('NOT')
    return bytes(b.code)


def witness(x, y, z, bit=None):
    return [num(v) for v in limbs(x) + limbs(y) + ([] if bit is None else [bit]) + limbs(z)]


def bind_openings(code, ws, context):
    """Specialize a research leaf to precommitted words and a 32-byte context.

    This is a fixed-claim fixture mechanism. Production BitVM assertions require
    authenticated dynamic openings (e.g. WOTS) and a transaction graph adapter.
    """
    if len(context) != 32 or len(ws) not in (27, 28):
        raise ValueError('bad context/witness shape')
    out = bytearray(push(context) + bytes([OPS['DROP']]))
    for i, w in enumerate(ws):
        out.extend(push(num(len(ws) - i - 1)))
        out.extend([OPS['PICK'], OPS['SHA256']])
        out.extend(push(sha256(w).digest()))
        out.append(OPS['EQUALVERIFY'])
    return bytes(out) + code


@dataclass
class Execution:
    success: bool
    error: str | None
    peak_stack: int
    op_count: int


def execute(code, witness_items):
    """Fail-closed interpreter for this compiler's opcode subset, not consensus."""
    s, alt, cond = list(witness_items), [], []
    peak, count = len(s), 0
    def pop():
        if not s:
            raise ValueError('stack underflow')
        return s.pop()
    def integer():
        return readnum(pop())
    def truth(b):
        return any(v and not (i == len(b)-1 and v == 128) for i, v in enumerate(b))
    try:
        if len(code) > 4_000_000 or len(s) > 1000 or any(len(v) > 520 for v in s):
            raise ValueError('initial resource limit')
        pc = 0
        while pc < len(code):
            op = code[pc]
            pc += 1
            count += 1
            data = None
            if op <= 78:
                if op <= 75:
                    size = op
                else:
                    n = {76: 1, 77: 2, 78: 4}[op]
                    if pc+n > len(code):
                        raise ValueError('truncated push size')
                    size = int.from_bytes(code[pc:pc+n], 'little')
                    pc += n
                if pc+size > len(code) or size > 520:
                    raise ValueError('invalid push')
                data, pc = code[pc:pc+size], pc+size
            elif op == 79 or 81 <= op <= 96:
                data = num(-1 if op == 79 else op-80)
            elif op not in NAMES:
                raise ValueError('unsupported opcode (including OP_SUCCESS)')
            active = all(cond)
            if data is not None:
                if active:
                    s.append(data)
            elif op == OPS['IF']:
                v = pop() if active else b''
                if v not in (b'', b'\x01'):
                    raise ValueError('MINIMALIF')
                cond.append(v == b'\x01' if active else False)
            elif op == OPS['ELSE']:
                if not cond:
                    raise ValueError('unmatched ELSE')
                cond[-1] = not cond[-1]
            elif op == OPS['ENDIF']:
                if not cond:
                    raise ValueError('unmatched ENDIF')
                cond.pop()
            elif active:
                name = NAMES[op]
                if name == 'DROP':
                    pop()
                elif name == 'PICK':
                    i = integer()
                    if not 0 <= i < len(s):
                        raise ValueError('PICK index')
                    s.append(s[-1-i])
                elif name == 'TOALTSTACK':
                    alt.append(pop())
                elif name == 'FROMALTSTACK':
                    if not alt:
                        raise ValueError('altstack underflow')
                    s.append(alt.pop())
                elif name == 'VERIFY':
                    if not truth(pop()):
                        raise ValueError('VERIFY')
                elif name == 'SHA256':
                    s.append(sha256(pop()).digest())
                elif name == 'NOT':
                    s.append(num(int(integer() == 0)))
                elif name == 'WITHIN':
                    hi, lo, x = integer(), integer(), integer()
                    s.append(num(int(lo <= x < hi)))
                elif name in ('EQUAL', 'EQUALVERIFY'):
                    equal = pop() == pop()
                    if name == 'EQUALVERIFY':
                        if not equal:
                            raise ValueError('EQUALVERIFY')
                    else:
                        s.append(num(int(equal)))
                else:
                    y, x = integer(), integer()
                    value = {'ADD': lambda: x+y, 'SUB': lambda: x-y,
                             'BOOLAND': lambda: int(bool(x) and bool(y)),
                             'BOOLOR': lambda: int(bool(x) or bool(y)),
                             'LESSTHAN': lambda: int(x < y),
                             'GREATERTHANOREQUAL': lambda: int(x >= y)}[name]()
                    s.append(num(value))
            peak = max(peak, len(s)+len(alt))
            if peak > 1000:
                raise ValueError('stack limit')
        if cond or alt or len(s) != 1:
            raise ValueError('unbalanced/CLEANSTACK')
        return Execution(truth(s[0]), None, peak, count)
    except (ValueError, KeyError) as e:
        return Execution(False, str(e), peak, count)
