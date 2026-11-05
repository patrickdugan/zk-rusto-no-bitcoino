"""Fixed-claim, typed arithmetic trace for the BitVM2 Nova research backend.

A verifier-owned Program fixes every wire and constraint. BoundTrace commits
one admitted assignment; repeated wire references reuse the same SHA-256 word
commitment. Each failed constraint has a separate Script disproof predicate.
This is NOT BitVM2's dynamic WOTS assertion protocol or a Taproot transaction
builder. The caller must authenticate the program and claim identifiers.
"""
from dataclasses import dataclass
from hashlib import sha256
from types import MappingProxyType
import json
import re
from script import BASE, LIMBS, P, Q, OPS, num, push, limbs, execute
from trace_kernels import compile_predicate

ROLES = {'pallas_base': P, 'vesta_scalar': P, 'vesta_base': Q, 'pallas_scalar': Q}
MAX_WORDS, MAX_CONSTRAINTS, MAX_ARGUMENTS = 100_000, 10_000, 64
ID = re.compile(r'^[A-Za-z0-9_.:/-]{1,192}$')


def _json(value):
    return json.dumps(value, separators=(',', ':'), sort_keys=True).encode('ascii')


def _field(words):
    return sum(v << (29*i) for i, v in enumerate(words))


@dataclass(frozen=True)
class Constraint:
    kind: str
    wires: tuple[str, ...]
    argument: tuple[int, ...] = ()

    def native(self, values, p):
        v = [values[w] for w in self.wires]
        if self.kind == 'add':
            return (_field(v[:9]) + _field(v[9:18])) % p == _field(v[18:])
        if self.kind == 'mul_bit':
            return (2*_field(v[:9]) + v[18]*_field(v[9:18])) % p == _field(v[19:])
        if self.kind == 'bits':
            return v[0] == sum(bit << i for i, bit in enumerate(reversed(v[1:])))
        if self.kind == 'const':
            return v[0] == self.argument[0]
        if self.kind == 'equal':
            return v[:9] == v[9:]
        if self.kind == 'point_form':
            return v[0] == 0 or all(word == 0 for word in v[1:])
        if self.kind == 'gate_equal':
            return v[0] not in self.argument or v[1:10] == v[10:]
        if self.kind == 'gate_nonzero':
            return v[0] not in self.argument or any(v[1:])
        if self.kind == 'gate_small_equal':
            return v[0] not in self.argument or v[1] == v[2]
        if self.kind == 'dispatch':
            i1, i2 = v[:2]
            same_x = v[2:11] == v[20:29]
            same_y = v[11:20] == v[29:38]
            inverse = same_x and not any(v[38:47])
            expected = 0 if i1 else 1 if i2 else 2 if inverse else 3 if same_x and same_y else 4
            return v[47] == expected
        raise ValueError('unknown constraint')


@dataclass(frozen=True)
class Program:
    field_role: str
    operation_id: str
    context: bytes
    words: tuple[tuple[str, int], ...]
    fields: tuple[tuple[str, tuple[str, ...]], ...]
    constraints: tuple[Constraint, ...]

    @property
    def p(self):
        return ROLES[self.field_role]

    def digest(self):
        shape = {'schema': 'bitvm2-nova-fixed-trace/v2',
                 'field_role': self.field_role, 'modulus': str(self.p),
                 'operation_id': self.operation_id, 'context': self.context.hex(),
                 'words': self.words, 'fields': self.fields,
                 'constraints': [(c.kind, c.wires, c.argument) for c in self.constraints]}
        return sha256(_json(shape)).digest()

    def _admit(self, values):
        """Admit a full assignment BEFORE producing any committed leaf.

        Encodings come from num(integer), so malformed ScriptNum byte strings
        cannot enter this fixed-claim API. Dynamic malformed-assertion dispute
        coverage is a separate, unimplemented production adapter obligation.
        """
        if len(values) != len(self.words) or set(values) != {w for w, _ in self.words}:
            raise ValueError('missing, extra, or duplicate assignment keys')
        for w, bound in self.words:
            if type(values[w]) is not int or not 0 <= values[w] < bound:
                raise ValueError(f'inadmissible word: {w}')
        for name, ws in self.fields:
            if _field(values[w] for w in ws) >= self.p:
                raise ValueError(f'noncanonical field: {name}')
    def bind(self, values):
        return BoundTrace(self, values)


class BoundTrace:
    """Immutable admitted openings; leaves are compiled on demand."""
    def __init__(self, program, values):
        program._admit(values)
        self.program = program
        self.values = MappingProxyType(dict(values))
        self.program_digest = program.digest()
        self.words = MappingProxyType({w: num(values[w]) for w, _ in program.words})
        self.hashes = MappingProxyType({w: sha256(v).digest() for w, v in self.words.items()})
        h = sha256(b'BITVM2-NOVA/FIXED-CLAIM/v2\x00' + self.program_digest)
        for w, _ in program.words:
            h.update(len(w).to_bytes(2, 'little'))
            h.update(w.encode('ascii'))
            h.update(self.hashes[w])
        self.claim_digest = h.digest()

    def require_identity(self, expected_program, expected_claim):
        from hmac import compare_digest
        if (type(expected_program) is not bytes or len(expected_program) != 32
                or type(expected_claim) is not bytes or len(expected_claim) != 32
                or not compare_digest(self.program_digest, expected_program)
                or not compare_digest(self.claim_digest, expected_claim)):
            raise ValueError('program or claim identity mismatch')

    def witness(self, ordinal):
        c = self.program.constraints[ordinal]
        return tuple(self.words[w] for w in c.wires)

    def script(self, ordinal, *, disprove=True):
        if type(ordinal) is not int or not 0 <= ordinal < len(self.program.constraints):
            raise ValueError('constraint ordinal out of bounds')
        c = self.program.constraints[ordinal]
        mode = b'D' if disprove else b'C'
        tag = sha256(b'BITVM2-NOVA/LEAF/v2\x00' + self.program_digest
                     + self.claim_digest + ordinal.to_bytes(4, 'little') + mode).digest()
        code = bytearray(push(tag) + bytes([OPS['DROP']]))
        # The same named wire has exactly the same opening hash at every use.
        for i, w in enumerate(c.wires):
            code.extend(push(num(len(c.wires)-1-i)))
            code.extend([OPS['PICK'], OPS['SHA256']])
            code.extend(push(self.hashes[w]))
            code.append(OPS['EQUALVERIFY'])
        code.extend(compile_predicate(self.program.p, c.kind, c.argument))
        if disprove:
            code.append(OPS['NOT'])
        return bytes(code)

    def failures(self):
        """Native reference only. A returned ordinal still needs Script execution."""
        return tuple(i for i, c in enumerate(self.program.constraints)
                     if not c.native(self.values, self.program.p))

    def execute(self, ordinal, *, disprove=True):
        return execute(self.script(ordinal, disprove=disprove), self.witness(ordinal))

    def manifest(self):
        return {'schema': 'bitvm2-nova-fixed-trace-manifest/v2',
                'program_sha256': self.program_digest.hex(),
                'claim_sha256': self.claim_digest.hex(),
                'context_sha256': self.program.context.hex(),
                'field_role': self.program.field_role,
                'operation_id': self.program.operation_id,
                'words': len(self.words), 'constraints': len(self.program.constraints),
                'authentication': 'fixed-claim-per-word-SHA256',
                'dynamic_assertions': False, 'bitcoin_transaction_graph': False}


class TraceBuilder:
    def __init__(self, role, operation_id, context):
        if role not in ROLES or not isinstance(operation_id, str) or not ID.fullmatch(operation_id):
            raise ValueError('invalid field role or operation ID')
        if type(context) is not bytes or len(context) != 32:
            raise ValueError('32-byte verifier-owned context digest required')
        self.role, self.operation_id, self.context = role, operation_id, context
        self.p = ROLES[role]
        self.words, self.fields, self.values, self.constraints = {}, {}, {}, []

    def small(self, name, value, bound):
        if (not ID.fullmatch(name) or name in self.words or len(self.words) >= MAX_WORDS
                or type(bound) is not int or not 1 <= bound <= BASE
                or type(value) is not int or not 0 <= value < bound):
            raise ValueError('invalid or duplicate word')
        self.words[name], self.values[name] = bound, value
        return name

    def field(self, name, value):
        if name in self.fields or type(value) is not int or not 0 <= value < self.p:
            raise ValueError('invalid or duplicate canonical field')
        ws = tuple(self.small(f'{name}/l{i}', v, BASE) for i, v in enumerate(limbs(value)))
        self.fields[name] = ws
        return ws

    def value(self, ws):
        return _field(self.values[w] for w in ws)

    def check(self, kind, ws, argument=()):
        ws, argument = tuple(ws), tuple(argument)
        if len(ws) > MAX_ARGUMENTS or any(w not in self.words for w in ws):
            raise ValueError('unknown wire or oversize predicate')
        if len(self.constraints) >= MAX_CONSTRAINTS:
            raise ValueError('constraint bound exceeded')
        # Compile once to fail closed on unsupported kinds and parameters.
        compile_predicate(self.p, kind, argument)
        self.constraints.append(Constraint(kind, ws, argument))

    def constant(self, name, value):
        ws = self.field(name, value)
        for w, v in zip(ws, limbs(value), strict=True):
            self.check('const', [w], (v,))
        return ws

    def small_constant(self, name, value, bound):
        w = self.small(name, value, bound)
        self.check('const', [w], (value,))
        return w

    def add(self, name, x, y):
        z = self.field(name, (self.value(x)+self.value(y)) % self.p)
        self.check('add', x+y+z)
        return z

    def sub(self, name, x, y):
        z = self.field(name, (self.value(x)-self.value(y)) % self.p)
        self.check('add', y+z+x)
        return z

    def mul(self, name, x, y):
        """255 linked Horner steps with authenticated bit reconstruction."""
        xv, yv = self.value(x), self.value(y)
        z = self.field(name, xv*yv % self.p)
        bits = tuple(self.small(f'{name}/bit/{i}', (yv >> i) & 1, 2) for i in range(255))
        for i, limb in enumerate(y):
            low, high = i*29, min((i+1)*29, 255)
            self.check('bits', (limb,) + tuple(reversed(bits[low:high])), (high-low,))
        t = self.constant(f'{name}/acc/0', 0)
        tv = 0
        for step, shift in enumerate(range(254, -1, -1), 1):
            tv = (2*tv + ((yv >> shift) & 1)*xv) % self.p
            nxt = self.field(f'{name}/acc/{step}', tv)
            self.check('mul_bit', t+x+(bits[shift],)+nxt)
            t = nxt
        self.check('equal', t+z)
        return z

    def finish(self):
        program = Program(self.role, self.operation_id, self.context,
                          tuple(self.words.items()), tuple(self.fields.items()),
                          tuple(self.constraints))
        return program, dict(self.values)


def multiplication_trace(role, x, y, *, context=bytes(32), operation_id='mul'):
    g = TraceBuilder(role, operation_id, context)
    a, b = g.field('input/a', x), g.field('input/b', y)
    g.mul('product', a, b)
    return g.finish()


def change_field(program, values, name, value):
    """Test helper: change one claimed field, leaving every other wire intact."""
    if type(value) is not int or not 0 <= value < program.p:
        raise ValueError('canonical replacement required')
    result = dict(values)
    for w, n in zip(dict(program.fields)[name], limbs(value), strict=True):
        result[w] = n
    return result
