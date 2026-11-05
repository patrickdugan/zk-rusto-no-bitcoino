"""Verifier-owned template for one WOTS-authenticated multiplication step.

No values are committed into the template. Rust uses pinned upstream BitVM
WOTS4 to authenticate/recover the 28 unsigned four-byte words before this body.
This is a leaf adapter, not the complete BitVM2 assertion/transaction protocol.
"""
from dataclasses import dataclass
from functools import lru_cache
from hashlib import sha256
from compact import BorrowBuilder, mul_bit
from script import BASE, OPS, limbs
from trace import ID


@lru_cache(maxsize=2)
def admitted_body(p):
    """28 bounded words -> correctness Boolean, including field validity.

    The WOTS adapter checks every word's unsigned-29-bit/Boolean bound before
    entering here. Invalid authenticated words take a false-result branch there.
    Canonical field failure takes a false-result branch here, not VERIFY.
    """
    names = [f'w{i}' for i in range(28)]
    b = BorrowBuilder(names)
    good = b.literal(1)
    zero = b.literal(0)
    for start in (0, 9, 19):
        borrow = zero
        for x, m in zip(names[start:start+9], limbs(p), strict=True):
            t = b.binary('SUB', b.binary('SUB', x, b.literal(m)), borrow)
            borrow = b.binary('LESSTHAN', t, zero)
        good = b.binary('BOOLAND', good, borrow)
    # Builder.keep reverses its argument order on restoration.
    b.keep(list(reversed(names+[good])))
    b.op('IF')
    b.code.extend(mul_bit(p))
    b.op('ELSE')
    for _ in range(14):
        b.op('2DROP')
    b.literal(0)
    b.op('ENDIF')
    return bytes(b.code)


def _text(h, text):
    value = text.encode('ascii')
    h.update(len(value).to_bytes(2, 'little'))
    h.update(value)


@dataclass(frozen=True)
class WotsLeafTemplate:
    program_sha256: str
    context: str
    field_role: str
    operation_id: str
    ordinal: int
    wires: tuple[str, ...]
    bounds: tuple[int, ...]
    body_hex: str
    compiler: str = 'compact-v1'

    @classmethod
    def from_program(cls, program, ordinal):
        if type(ordinal) is not int or not 0 <= ordinal < len(program.constraints):
            raise ValueError('constraint ordinal out of bounds')
        c = program.constraints[ordinal]
        if c.kind != 'mul_bit' or c.argument or len(c.wires) != 28 or len(set(c.wires)) != 28:
            raise ValueError('only distinct-wire mul_bit leaves are supported')
        expected = (BASE,)*18 + (2,) + (BASE,)*9
        bounds = tuple(dict(program.words)[w] for w in c.wires)
        if bounds != expected or any(not ID.fullmatch(w) for w in c.wires):
            raise ValueError('unexpected multiplication wire layout')
        fields = set(program.fields)
        for start in (0, 9, 19):
            if not any(ws == c.wires[start:start+9] for _, ws in fields):
                raise ValueError('field words must belong to a canonical program field')
        return cls(program.digest().hex(), program.context.hex(), program.field_role,
                   program.operation_id, ordinal, c.wires, bounds, admitted_body(program.p).hex())

    def digest(self):
        h = sha256(b'BITVM2-NOVA/WOTS-TEMPLATE/v1\x00')
        h.update(bytes.fromhex(self.program_sha256))
        h.update(bytes.fromhex(self.context))
        for text in (self.field_role, self.operation_id, self.compiler):
            _text(h, text)
        h.update(self.ordinal.to_bytes(4, 'little'))
        for wire, bound in zip(self.wires, self.bounds, strict=True):
            _text(h, wire)
            h.update(bound.to_bytes(4, 'little'))
        h.update(sha256(bytes.fromhex(self.body_hex)).digest())
        return h.digest()

    def json(self):
        return {**self.__dict__, 'wires': list(self.wires), 'bounds': list(self.bounds)}
