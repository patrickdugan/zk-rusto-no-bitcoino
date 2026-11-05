"""Bounded Keccak reference and one-round Boolean Bitcoin Script trace.

Lane index is x + 5*y; lane bytes and lane bits are little endian. Keccak-256
uses suffix 0x01, rather than SHA3-256's suffix 0x06. The word-level reference
can hash small inputs, but the Script graph implements exactly ONE permutation
round. Its 1,600 named input and output bits are explicit authenticated boundary
wires when admitted through the existing registry. Separate round programs do
not, by themselves, authenticate their shared boundary or a whole hash. Absorb,
padding, 24-round composition, squeeze and Nova transcript framing still need
an authenticated whole-hash graph before this can verify a transcript in Script.

Round equations and constants follow the Keccak specification and XKCP's CC0
CompactFIPS202 implementation; immutable sources are in keccak-sources.json.
"""
from trace import ID, TraceBuilder

MASK64 = (1 << 64) - 1
STATE_BYTES = 200
RATE_BYTES = 136
MAX_REFERENCE_INPUT = 4096
ROUND_CONSTANTS = (
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
)
# Rows are y, columns are x.
RHO = ((0, 1, 62, 28, 27), (36, 44, 6, 55, 20),
       (3, 10, 43, 25, 39), (41, 45, 15, 21, 8),
       (18, 2, 61, 56, 14))


def _state(lanes):
    if (type(lanes) not in (list, tuple) or len(lanes) != 25
            or any(type(v) is not int or not 0 <= v <= MASK64 for v in lanes)):
        raise ValueError('exactly 25 canonical unsigned 64-bit lanes required')
    return tuple(lanes)


def _round(round_index):
    if type(round_index) is not int or not 0 <= round_index < 24:
        raise ValueError('Keccak-f[1600] round must be an integer from 0 to 23')
    return round_index


def rol64(value, shift):
    if (type(value) is not int or not 0 <= value <= MASK64
            or type(shift) is not int or not 0 <= shift < 64):
        raise ValueError('canonical lane and rotation from 0 to 63 required')
    return ((value << shift) | (value >> ((64 - shift) % 64))) & MASK64


def state_from_bytes(data):
    if type(data) is not bytes or len(data) != STATE_BYTES:
        raise ValueError('exactly 200 state bytes required')
    return tuple(int.from_bytes(data[i:i+8], 'little') for i in range(0, 200, 8))


def state_to_bytes(lanes):
    return b''.join(v.to_bytes(8, 'little') for v in _state(lanes))


def keccak_f1600_round(lanes, round_index):
    """Native word-level reference, separate from the Boolean trace builder."""
    a, r = _state(lanes), _round(round_index)
    c = [a[x] ^ a[x+5] ^ a[x+10] ^ a[x+15] ^ a[x+20] for x in range(5)]
    d = [c[(x-1) % 5] ^ rol64(c[(x+1) % 5], 1) for x in range(5)]
    b = [0] * 25
    for y in range(5):
        for x in range(5):
            b[y + 5*((2*x + 3*y) % 5)] = rol64(a[x+5*y] ^ d[x], RHO[y][x])
    out = [b[x+5*y] ^ ((~b[(x+1) % 5+5*y]) & b[(x+2) % 5+5*y])
           for y in range(5) for x in range(5)]
    out[0] ^= ROUND_CONSTANTS[r]
    return tuple(v & MASK64 for v in out)


def keccak_f1600(lanes):
    """Native reference only; this does not build a 24-round Script graph."""
    result = _state(lanes)
    for r in range(24):
        result = keccak_f1600_round(result, r)
    return result


def keccak256_padded(data):
    """Return bounded Keccak-256 pad10*1 bytes, including a combined 0x81."""
    if type(data) is not bytes or len(data) > MAX_REFERENCE_INPUT:
        raise ValueError('reference hash input must be bytes of length at most 4096')
    padded = bytearray(data + b'\x01')
    padded.extend(bytes((-len(padded)) % RATE_BYTES))
    padded[-1] |= 0x80
    return bytes(padded)


def keccak256_reference(data):
    """Small native reference for comparison with mature Keccak libraries."""
    padded, state = keccak256_padded(data), (0,) * 25
    for offset in range(0, len(padded), RATE_BYTES):
        block = padded[offset:offset+RATE_BYTES]
        absorb = state_from_bytes(block + bytes(STATE_BYTES - RATE_BYTES))
        state = keccak_f1600(tuple(a ^ b for a, b in zip(state, absorb, strict=True)))
    return state_to_bytes(state)[:32]


def state_wire_names(prefix):
    """Stable lane-major, least-significant-bit-first boundary names."""
    if type(prefix) is not str or not ID.fullmatch(prefix + '/l24/b63'):
        raise ValueError('invalid state wire prefix')
    return tuple(f'{prefix}/l{lane}/b{bit}' for lane in range(25) for bit in range(64))


def state_from_bit_wires(values, prefix):
    bits = [values[name] for name in state_wire_names(prefix)]
    if any(type(bit) is not int or bit not in (0, 1) for bit in bits):
        raise ValueError('state boundary contains a non-Boolean value')
    return tuple(sum(bits[64*lane+bit] << bit for bit in range(64)) for lane in range(25))


def keccak_round_trace(lanes, round_index, *, context, role='pallas_scalar',
                       operation_id='keccak', input_prefix='keccak/in',
                       output_prefix='keccak/out', claimed_output=None):
    """Return one typed round Program and assignment, with explicit boundaries.

    All words have bound two. Rho and pi only permute existing authenticated
    wire references; they introduce no unconstrained copies. Output copies are
    XORs with a constrained zero so callers can retain their own boundary names.
    The field role and context remain part of the existing Program identity even
    though these Boolean equations do not depend on the field modulus.
    """
    lanes, r = _state(lanes), _round(round_index)
    if type(operation_id) is not str:
        raise ValueError('invalid operation ID')
    input_names, output_names = state_wire_names(input_prefix), state_wire_names(output_prefix)
    if claimed_output is not None:
        claimed_output = _state(claimed_output)
    g = TraceBuilder(role, f'{operation_id}/round/{r}', context)
    prefix = f'keccak/r{r}'
    a = [[g.small(input_names[64*l+b], (lanes[l] >> b) & 1, 2)
          for b in range(64)] for l in range(25)]

    def gate(stage, kind, *inputs):
        v = [g.values[w] for w in inputs]
        value = 1-v[0] if kind == 'bool_not' else (
            v[0] ^ v[1] if kind == 'bool_xor' else v[0] & v[1])
        out = g.small(f'{prefix}/{stage}', value, 2)
        g.check(kind, (*inputs, out))
        return out

    c = [[None] * 64 for _ in range(5)]
    for x in range(5):
        for bit in range(64):
            acc = a[x][bit]
            for y in range(1, 5):
                acc = gate(f'c/{x}/{bit}/{y}', 'bool_xor', acc, a[x+5*y][bit])
            c[x][bit] = acc
    d = [[gate(f'd/{x}/{bit}', 'bool_xor', c[(x-1) % 5][bit],
               c[(x+1) % 5][(bit-1) % 64]) for bit in range(64)] for x in range(5)]
    theta = [[gate(f't/{l}/{bit}', 'bool_xor', a[l][bit], d[l % 5][bit])
              for bit in range(64)] for l in range(25)]
    b = [[None] * 64 for _ in range(25)]
    for y in range(5):
        for x in range(5):
            target = y + 5*((2*x + 3*y) % 5)
            for bit in range(64):
                b[target][(bit+RHO[y][x]) % 64] = theta[x+5*y][bit]
    chi = [[None] * 64 for _ in range(25)]
    for y in range(5):
        for x in range(5):
            l = x+5*y
            for bit in range(64):
                neg = gate(f'chi/n/{l}/{bit}', 'bool_not', b[(x+1) % 5+5*y][bit])
                product = gate(f'chi/a/{l}/{bit}', 'bool_and', neg, b[(x+2) % 5+5*y][bit])
                chi[l][bit] = gate(f'chi/x/{l}/{bit}', 'bool_xor', b[l][bit], product)
    for bit in range(64):
        if (ROUND_CONSTANTS[r] >> bit) & 1:
            chi[0][bit] = gate(f'iota/{bit}', 'bool_not', chi[0][bit])
    zero = g.small_constant(f'{prefix}/zero', 0, 2)
    for l in range(25):
        for bit in range(64):
            value = (g.values[chi[l][bit]] if claimed_output is None
                     else (claimed_output[l] >> bit) & 1)
            out = g.small(output_names[64*l+bit], value, 2)
            g.check('bool_xor', (chi[l][bit], zero, out))
    return g.finish()
