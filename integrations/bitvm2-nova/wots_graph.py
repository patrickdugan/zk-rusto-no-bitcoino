"""Verifier-owned WOTS graph catalogue, independent of assertion values.

Adds field-validity leaves because fixed-claim admission is not an on-chain
disproof. Rust binds this complete catalogue and all wire keys to one registry.
"""
from dataclasses import dataclass
from hashlib import sha256
from compact import BorrowBuilder, mul_bit
from script import BASE, LIMBS, limbs
from trace import ID, MAX_WORDS, MAX_CONSTRAINTS, ROLES
from trace_kernels import compile_predicate

MAX_GRAPH_LEAVES = 30_000


def _text(h, value):
    value = value.encode('ascii')
    h.update(len(value).to_bytes(2, 'little'))
    h.update(value)


def field_valid_body(p):
    names = [f'w{i}' for i in range(LIMBS)]
    b = BorrowBuilder(names)
    borrow, zero = b.literal(0), b.literal(0)
    for word, modulus in zip(names, limbs(p), strict=True):
        t = b.binary('SUB', b.binary('SUB', word, b.literal(modulus)), borrow)
        borrow = b.binary('LESSTHAN', t, zero)
    b.keep([borrow])
    return bytes(b.code)


def expansion_script(occurrences):
    """Authenticated unique values -> all ordered predicate occurrences."""
    unique = tuple(dict.fromkeys(occurrences))
    if unique == occurrences:
        return b''
    names = {index: f'w{index}' for index in unique}
    b = BorrowBuilder([names[i] for i in unique])
    b.keep([names[i] for i in reversed(occurrences)])
    return bytes(b.code)


def authenticated_shape(spec, leaf):
    """Body/alias layout plus every recovered word's decoder bound."""
    unique = tuple(dict.fromkeys(leaf.wires))
    return leaf.body_sha256, tuple(spec.words[i][1] for i in unique)


@dataclass(frozen=True)
class Leaf:
    kind: str
    argument: tuple[int, ...]
    wires: tuple[int, ...]
    body_sha256: str


@dataclass(frozen=True)
class GraphSpec:
    program_sha256: str
    context: str
    field_role: str
    operation_id: str
    words: tuple[tuple[str, int], ...]
    leaves: tuple[Leaf, ...]
    bodies: tuple[tuple[str, str], ...]
    original_constraints: int
    field_leaves: tuple[tuple[str, int], ...]

    @classmethod
    def from_program(cls, program):
        if (program.field_role not in ROLES or type(program.context) is not bytes
                or len(program.context) != 32 or not ID.fullmatch(program.operation_id)
                or not 0 < len(program.words) <= MAX_WORDS
                or not 0 < len(program.constraints) <= MAX_CONSTRAINTS):
            raise ValueError('unsupported graph')
        indices = {w: i for i, (w, _) in enumerate(program.words)}
        if len(indices) != len(program.words):
            raise ValueError('duplicate wire')
        for w, bound in program.words:
            if not ID.fullmatch(w) or type(bound) is not int or not 1 <= bound <= BASE:
                raise ValueError('invalid wire declaration')
        leaves, bodies, covered = [], {}, set()

        def append(kind, argument, wires, predicate):
            if not wires or len(wires) > 64 or any(w not in indices for w in wires):
                raise ValueError('invalid predicate wires')
            occurrences = tuple(indices[w] for w in wires)
            body = expansion_script(occurrences) + predicate
            digest = sha256(body).hexdigest()
            bodies[digest] = body.hex()
            leaves.append(Leaf(kind, tuple(argument), occurrences, digest))
            covered.update(wires)

        for c in program.constraints:
            predicate = mul_bit(program.p) if c.kind == 'mul_bit' else compile_predicate(program.p, c.kind, c.argument)
            append(c.kind, c.argument, c.wires, predicate)
        fields = []
        field_names = set()
        for name, words in program.fields:
            if (not ID.fullmatch(name) or name in field_names or len(words) != LIMBS
                    or len(set(words)) != LIMBS or any(w not in indices for w in words)
                    or any(program.words[indices[w]][1] != BASE for w in words)):
                raise ValueError('invalid canonical field declaration')
            field_names.add(name)
            fields.append((name, len(leaves)))
            append('field_valid', (), words, field_valid_body(program.p))
        # Every asserted word gets an explicit validity path, even unused smalls.
        for word, _ in program.words:
            if word not in covered:
                append('word_valid', (), (word,), bytes([0x75, 0x51]))
        if len(leaves) > MAX_GRAPH_LEAVES:
            raise ValueError('authenticated leaf bound exceeded')
        return cls(program.digest().hex(), program.context.hex(), program.field_role,
                   program.operation_id, program.words, tuple(leaves), tuple(sorted(bodies.items())),
                   len(program.constraints), tuple(fields))

    def digest(self):
        h = sha256(b'BITVM2-NOVA/WOTS-GRAPH/v1\x00')
        h.update(bytes.fromhex(self.program_sha256))
        h.update(bytes.fromhex(self.context))
        _text(h, self.field_role)
        _text(h, self.operation_id)
        h.update(len(self.words).to_bytes(4, 'little'))
        for word, bound in self.words:
            _text(h, word)
            h.update(bound.to_bytes(4, 'little'))
        h.update(len(self.leaves).to_bytes(4, 'little'))
        for i, leaf in enumerate(self.leaves):
            h.update(i.to_bytes(4, 'little'))
            _text(h, leaf.kind)
            h.update(len(leaf.argument).to_bytes(4, 'little'))
            for arg in leaf.argument:
                h.update(arg.to_bytes(8, 'little', signed=True))
            h.update(len(leaf.wires).to_bytes(4, 'little'))
            for wire in leaf.wires:
                h.update(wire.to_bytes(4, 'little'))
            h.update(bytes.fromhex(leaf.body_sha256))
        return h.digest()

    def json(self):
        # Field names and original count are compiler diagnostics, not trusted
        # Rust inputs. Their semantics are already in program_sha256 and leaves.
        return {'program_sha256': self.program_sha256, 'context': self.context,
                'field_role': self.field_role, 'operation_id': self.operation_id,
                'words': [{'name': w, 'bound': b} for w, b in self.words],
                'leaves': [dict(kind=l.kind, argument=list(l.argument), wires=list(l.wires),
                                body_sha256=l.body_sha256) for l in self.leaves],
                'bodies': dict(self.bodies)}
