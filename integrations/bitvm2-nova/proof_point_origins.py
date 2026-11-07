"""Retained compressed-commitment decoding: proof BYTEs -> canonical affine points.

M23 source relation. The retained NHT4 payload carries 78 halo2curves 0.9
compressed Pasta commitments (43 Pallas, 35 Vesta). M17 signed every payload
BYTE but left these 32-byte encodings opaque. This module binds, for one curve
role at a time, each encoding at its physical container offsets to asserted
canonical affine coordinates (infinity, x, y) using only frozen legacy
predicates:

* x is the little-endian integer of bytes 0..31 with bit 255 removed; byte 31
  is split into its low seven bits and the sign bit;
* x and y are canonical field elements (field_valid);
* infinity => x = y = 0 (point_form);
* not infinity => y^2 = x^3 + 5 (three convolution products, gate_equal);
* the low bit of y equals the sign bit (parity split of y's BYTE 0).

5 is a quadratic non-residue in both Pasta base fields and both curves have
prime (odd) order, so no finite point has x = 0 or y = 0. Hence every 32-byte
string has at most one satisfying (infinity, x, y), it exists exactly for the
canonical encodings (to_bytes(from_bytes(B)) == B), and the all-zero string is
the only identity encoding. The upstream from_bytes x=0/sign=1 identity alias
is rejected, matching the repository's strict codec and reference admission.

The decoded coordinates are asserted ports. Which point a commitment ought to
be (transcript, folding, IPA/MSM) is not established here; a coherent
substitution of another valid point passes this local relation by design.
Graph construction and binding are hosted GitHub Linux only. The pure value
model, profile recipes and decoder verdicts are local-safe math.
"""
from dataclasses import dataclass
from hashlib import sha256
import json
import os
import sys

from byte_kernels import ByteTraceBuilder
from convolution import CARRY_OFFSET, ConvolutionTraceBuilder, convolution_native
from nht4 import ExpectedBundle, HEADER_BYTES, bind_container
import proof_codec as codec
from proof_payload_origins import (DIMENSIONS_PIN, PAYLOAD_BYTES, POLICY_PIN,
                                   retained_layout, tape_anchors)
from script import BASE, P, Q, limbs
from trace import ID
from wots_graph import GraphSpec

SCHEMA = 'bitvm2-nova-proof-point-origins/v1'
COMPONENT_SCHEMA = 'bitvm2-nova-proof-point-component/v1'
DOMAIN = b'BITVM2-NOVA/PROOF-POINT-ORIGINS/v1\x00'
ENGINES = ('pallas', 'vesta')
BASE_ROLE = {'pallas': 'pallas_base', 'vesta': 'vesta_base'}
MODULUS = {'pallas': P, 'vesta': Q}
COMMITMENTS = {'pallas': 43, 'vesta': 35}
BATCH = 7
TAPE_ROLE = 'pallas_scalar'
CROSSING_BOUNDARIES = (29, 58, 87, 116, 145, 174, 203)

# Exact per-decoder census of the schedule below (checked against the actual
# builder in hosted tests and independently re-derived by the native worker).
DECODER_WORDS, DECODER_CONSTRAINTS, DECODER_FIELDS = 1696, 1400, 6
CONSTANT_WORDS, CONSTANT_CONSTRAINTS, CONSTANT_FIELDS = 10, 10, 1
TAPE_CENSUS = (12664, 1383, 0, 12664)
MAX_CONSTRAINTS = 10_000
TARGET_CAP = 2048

PROFILES = ('honest', 'coherent-negate', 'coherent-identity', 'sign-flip',
            'wrong-root', 'x-noncanonical', 'off-curve', 'identity-alias',
            'identity-finite-flag', 'infinity-lie', 'byte-256', 'byte-max')
# Profiles whose claims satisfy every local predicate (expected limits).
COHERENT = frozenset(('honest', 'coherent-negate', 'coherent-identity'))
FALSE_FLAGS = ('blob_sha256_script_bound', 'proof_eof_authenticated',
    'container_header_script_bound', 'public_state_to_zn_script_bound',
    'commitment_semantics_bound', 'affine_transcript_encoding_bound',
    'generic_nova_decoder', 'transcript_verified', 'msm_or_ipa_verified',
    'proof_verified', 'complete_nova_verifier', 'complete_bitvm2_verifier',
    'production_assertion_binding', 'bitcoin_transaction_graph',
    'taproot_or_forest_constructed')


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def _hosted_guard():
    if (os.environ.get('GITHUB_ACTIONS') != 'true'
            or os.environ.get('RUNNER_OS') != 'Linux' or sys.platform != 'linux'):
        raise ValueError('proof-point graph construction/binding is hosted GitHub Linux only')


def _make(cls, **fields):
    result = object.__new__(cls)
    for name, value in fields.items():
        object.__setattr__(result, name, value)
    return result


def _engine(engine):
    if type(engine) is not str or engine not in ENGINES:
        raise ValueError('explicit pallas or vesta commitment role required')
    return engine


# ---------------------------------------------------------------------------
# Pure layout and component plan (no graphs).

def commitment_spans(layout, engine):
    """Verifier-owned commitment spans of one curve, in payload order."""
    spans = tuple(s for s in layout if s.kind == 'commitment' and s.engine == _engine(engine))
    if len(spans) != COMMITMENTS[engine] or any(s.size != 32 for s in spans):
        raise ValueError('retained commitment census differs')
    return spans


def component_plan(engine):
    """Decoder index ranges per decoder component, chunks of BATCH in order."""
    count = COMMITMENTS[_engine(engine)]
    rows = tuple(tuple(range(start, min(start+BATCH, count))) for start in range(0, count, BATCH))
    for row in rows:
        if CONSTANT_CONSTRAINTS + DECODER_CONSTRAINTS*len(row) > MAX_CONSTRAINTS:
            raise ValueError('decoder component exceeds unchanged Program constraint cap')
    if 1+len(rows) > 16:
        raise ValueError('source exceeds unchanged 16-component policy')
    return rows


def component_census(engine, index):
    """(words, arithmetic constraints, canonical fields, leaves) of component index."""
    if index == 0:
        return TAPE_CENSUS
    n = len(component_plan(engine)[index-1])
    words = CONSTANT_WORDS + DECODER_WORDS*n
    arithmetic = CONSTANT_CONSTRAINTS + DECODER_CONSTRAINTS*n
    fields = CONSTANT_FIELDS + DECODER_FIELDS*n
    return words, arithmetic, fields, arithmetic+fields


def decoder_leaf_ordinals(engine, index, local):
    """All leaf ordinals of decoder `local` inside decoder component `index`."""
    _, arithmetic, _, _ = component_census(engine, index)
    start = CONSTANT_CONSTRAINTS + DECODER_CONSTRAINTS*local
    fields = arithmetic + CONSTANT_FIELDS + DECODER_FIELDS*local
    return tuple(range(start, start+DECODER_CONSTRAINTS)) + tuple(range(fields, fields+DECODER_FIELDS))


# ---------------------------------------------------------------------------
# Pure value model of one decoder, mirroring the builder schedule exactly.

def _bytes32(value):
    if type(value) is not int or not 0 <= value < 1 << 256:
        raise ValueError('unsigned 256-bit integer required')
    return tuple(value.to_bytes(32, 'little'))


def _crossings(digits):
    out = []
    for boundary in CROSSING_BOUNDARIES:
        index, low = divmod(boundary, 8)
        out.extend((digits[index] & ((1 << low)-1), digits[index] >> low))
    return out


def _mul_values(a_digits, b_digits, p):
    """Words of ConvolutionTraceBuilder.mul after its cached a/b digits."""
    a = int.from_bytes(bytes(a_digits), 'little')
    b = int.from_bytes(bytes(b_digits), 'little')
    product = a*b
    c, q = product % p, product // p
    if q >= 1 << 256:
        raise ValueError('unsigned 32-byte quotient required')
    c_digits, q_digits = _bytes32(c), _bytes32(q)
    modulus = p.to_bytes(32, 'little')
    words = list(limbs(c)) + list(c_digits) + _crossings(c_digits) + list(q_digits)
    words.append(CARRY_OFFSET)
    signed = 0
    for column in range(64):
        pairs = [(i, column-i) for i in range(32) if 0 <= column-i < 32]
        ab = []
        for block in range(0, len(pairs), 4):
            ab.append(sum(a_digits[i]*b_digits[j] for i, j in pairs[block:block+4]))
        coefficients = [(modulus[i], column-i) for i in range(32)
                        if modulus[i] and 0 <= column-i < 32]
        pq = []
        for block in range(0, len(coefficients), 8):
            pq.append(sum(k*q_digits[j] for k, j in coefficients[block:block+8]))
        output = c_digits[column] if column < 32 else 0
        signed = (sum(ab)+signed-output-sum(pq)) // 256
        words.extend(ab)
        words.extend(pq)
        words.append(signed+CARRY_OFFSET)
    if signed != 0:
        raise ValueError('convolution carry chain must close for exact products')
    return c, c_digits, words


def decoder_values(claimed, infinity, x, y, p, reference):
    """Every decoder word value in declaration order, retaining raw claims.

    `claimed` are the 32 asserted unsigned32 BYTE values. A claimed value of 256
    or more is a signed diagnostic: every derived auxiliary then uses the
    reference encoding, so the out-of-range BYTE word itself is the only
    changed operand (the M17 diagnostic convention).
    """
    if (type(claimed) is not tuple or len(claimed) != 32
            or any(type(v) is not int or not 0 <= v < 1 << 32 for v in claimed)
            or type(reference) is not bytes or len(reference) != 32
            or infinity not in (0, 1) or p not in (P, Q)
            or type(x) is not int or type(y) is not int
            or not 0 <= x < 1 << 255 or not 0 <= y < 1 << 255):
        raise ValueError('closed decoder claim required')
    derived = bytes(claimed) if all(v < 256 for v in claimed) else reference
    lo, sign = derived[31] & 127, derived[31] >> 7
    x_digits = tuple(derived[:31]) + (lo,)
    if int.from_bytes(bytes(x_digits), 'little') != x and derived is not reference:
        raise ValueError('decoder recipes keep x limbs coherent with the asserted bytes')
    y_digits = _bytes32(y)
    words = [infinity] + list(limbs(x)) + list(limbs(y)) + list(claimed)
    words += [lo, sign, lo]
    words += _crossings(x_digits)
    words += list(y_digits) + _crossings(y_digits)
    words.append(y_digits[0] >> 1)
    x2, x2_digits, part = _mul_values(x_digits, x_digits, p)
    words += part
    x3, _, part = _mul_values(x2_digits, x_digits, p)
    words += part
    _, _, part = _mul_values(y_digits, y_digits, p)
    words += part
    words += list(limbs((x3+5) % p))
    if len(words) != DECODER_WORDS:
        raise ValueError('decoder value model census differs')
    return tuple(words)


def constant_values():
    return tuple(limbs(5)) + (0,)


def decoder_verdict(claimed, infinity, x, y, p):
    """Semantic relation verdict, independent of graph topology.

    Returns the failing relation names. An empty result means the claim is a
    canonical decoding of the asserted bytes.
    """
    failing = []
    if any(v >= 256 for v in claimed):
        failing.append('byte-bound')
        return tuple(failing)
    raw = bytes(claimed)
    value = int.from_bytes(raw, 'little')
    sign, encoded_x = value >> 255, value & ((1 << 255)-1)
    if encoded_x != x:
        failing.append('x-bytes')
    if x >= p:
        failing.append('x-canonical')
    if y >= p:
        failing.append('y-canonical')
    if infinity and (x or y):
        failing.append('point-form')
    if not infinity and (y*y - x*x*x - 5) % p:
        failing.append('on-curve')
    if (y & 1) != sign:
        failing.append('parity')
    return tuple(failing)


def canonical_decoding(raw, engine):
    """(infinity, x, y) of a canonical encoding, else None (strict codec)."""
    try:
        point = codec.decode_point(raw, engine)
    except ValueError:
        return None
    return (1, 0, 0) if point is None else (0,)+point


# ---------------------------------------------------------------------------
# Closed profile recipes (pure).

def _legendre_nonresidue(value, p):
    return pow(value % p, (p-1)//2, p) == p-1


def profile_target(profile, engine, payload, layout):
    """Decoder index changed by a targeted profile (verifier-owned rule)."""
    spans = commitment_spans(layout, engine)
    p = MODULUS[engine]
    if profile == 'x-noncanonical':
        for index, span in enumerate(spans):
            decoded = canonical_decoding(payload[span.start:span.start+32], engine)
            if decoded is not None and not decoded[0] and decoded[1]+p < 1 << 255:
                return index
        raise ValueError('no retained commitment admits a 255-bit noncanonical x')
    return 0


def profile_claims(profile, engine, payload, layout):
    """Asserted payload BYTEs and per-decoder coordinates for a closed profile.

    Returns (values, claims, changed_offsets, target) where values is the full
    12664-word unsigned32 payload assertion and claims lists (infinity, x, y)
    for every commitment of `engine`, in payload order.
    """
    if (type(profile) is not str or profile not in PROFILES
            or type(payload) is not bytes or len(payload) != PAYLOAD_BYTES):
        raise ValueError('closed profile and exact retained reference payload required')
    spans = commitment_spans(layout, engine)
    p = MODULUS[engine]
    values = list(payload)
    claims = []
    for span in spans:
        decoded = canonical_decoding(payload[span.start:span.start+32], engine)
        if decoded is None:
            raise ValueError('retained reference commitment is not canonical')
        claims.append(decoded)
    if profile == 'honest':
        return tuple(values), tuple(claims), (), None
    target = profile_target(profile, engine, payload, layout)
    span = spans[target]
    infinity, x, y = claims[target]
    if infinity:
        raise ValueError('retained recipe targets require a finite reference point')
    sign = y & 1

    def encode(x_value, sign_bit):
        return list((x_value | (sign_bit << 255)).to_bytes(32, 'little'))

    raw = list(payload[span.start:span.start+32])
    claim = (infinity, x, y)
    if profile == 'coherent-negate':
        raw, claim = encode(x, 1-sign), (0, x, p-y)
    elif profile == 'coherent-identity':
        raw, claim = [0]*32, (1, 0, 0)
    elif profile == 'sign-flip':
        raw = encode(x, 1-sign)
    elif profile == 'wrong-root':
        claim = (0, x, p-y)
    elif profile == 'x-noncanonical':
        raw, claim = encode(x+p, sign), (0, x+p, y)
    elif profile == 'off-curve':
        shifted = x+1
        while shifted < p and not _legendre_nonresidue(shifted**3+5, p):
            shifted += 1
        if shifted >= p:
            raise ValueError('unsupported off-curve recipe boundary')
        raw, claim = encode(shifted, sign), (0, shifted, y)
    elif profile == 'identity-alias':
        raw, claim = [0]*31+[0x80], (1, 0, 0)
    elif profile == 'identity-finite-flag':
        raw, claim = [0]*32, (0, 0, 0)
    elif profile == 'infinity-lie':
        claim = (1, x, y)
    elif profile in ('byte-256', 'byte-max'):
        raw[0] = 256 if profile == 'byte-256' else 0xffffffff
    values[span.start:span.start+32] = raw
    claims[target] = claim
    changed = tuple(span.start+i for i in range(32) if values[span.start+i] != payload[span.start+i])
    if profile not in ('wrong-root', 'infinity-lie') and not changed:
        raise ValueError('targeted byte recipe changed no payload position')
    return tuple(values), tuple(claims), changed, target


# ---------------------------------------------------------------------------
# Graph construction (hosted only).

def _bytes_from(builder, name, field, digits):
    """ConvolutionTraceBuilder._bytes with caller-supplied BYTE digit words."""
    crossings = {}
    for boundary in CROSSING_BOUNDARIES:
        index, low = divmod(boundary, 8)
        byte = builder.values[digits[index]]
        lo = builder.small(f'{name}/split/{index}/lo', byte & ((1 << low)-1), 1 << low)
        hi = builder.small(f'{name}/split/{index}/hi', byte >> low, 1 << (8-low))
        builder.check('conv_split', (digits[index], lo, hi), (low,))
        crossings[index] = (lo, hi)
    for limb, original in enumerate(field):
        start, end = limb*29, min(limb*29+29, 256)
        pieces, widths = [], []
        for byte_index in range(start//8, (end+7)//8):
            low, high = max(start, byte_index*8), min(end, byte_index*8+8)
            if low == byte_index*8 and high == byte_index*8+8:
                part = digits[byte_index]
            else:
                lo, hi = crossings[byte_index]
                part = lo if low == byte_index*8 else hi
            pieces.append(part)
            widths.append(high-low)
        builder.check('conv_reconstruct', (original,)+tuple(pieces), tuple(widths))
    builder._byte_fields[tuple(field)] = tuple(digits)


def _decoder(builder, d, raw, claim, five, zero_hi):
    name = f'point/{d}'
    infinity, x_value, y_value = claim
    inf = builder.small(f'{name}/infinity', infinity, 2)
    x = builder.field(f'{name}/x', x_value)
    y = builder.field(f'{name}/y', y_value)
    encoding = tuple(builder.small(f'{name}/encoding/byte/{i}', raw[i], 256) for i in range(32))
    lo = builder.small(f'{name}/encoding/sign-split/lo', raw[31] & 127, 128)
    sign = builder.small(f'{name}/encoding/sign', raw[31] >> 7, 2)
    x31 = builder.small(f'{name}/x/byte/31', raw[31] & 127, 256)
    builder.check('conv_split', (encoding[31], lo, sign), (7,))
    builder.check('conv_split', (x31, lo, zero_hi), (7,))
    _bytes_from(builder, f'{name}/x', x, encoding[:31]+(x31,))
    builder.check('point_form', (inf,)+x+y)
    y_digits = builder._bytes(f'{name}/y', y)
    y_high = builder.small(f'{name}/y/parity-split/hi', builder.values[y_digits[0]] >> 1, 128)
    builder.check('conv_split', (y_digits[0], sign, y_high), (1,))
    xx = builder.mul(f'{name}/x2', x, x)
    xxx = builder.mul(f'{name}/x3', xx, x)
    yy = builder.mul(f'{name}/y2', y, y)
    rhs = builder.add(f'{name}/curve-rhs', xxx, five)
    builder.check('gate_equal', (inf,)+yy+rhs, (0,))


def _operation(operation_id, engine, index):
    return f'{operation_id}/tape' if index == 0 else f'{operation_id}/{engine}-points/{index-1}'


def _global_ids(engine, index, spec, layout):
    if index == 0:
        return tuple(f'proof/container-byte/{HEADER_BYTES+i}' for i in range(PAYLOAD_BYTES))
    spans = commitment_spans(layout, engine)
    ids = []
    for word, _ in spec.words:
        parts = word.split('/')
        if parts[0] == 'point' and parts[2:4] == ['encoding', 'byte']:
            span = spans[int(parts[1])]
            ids.append(f'proof/container-byte/{HEADER_BYTES+span.start+int(parts[4])}')
        elif parts[0] == 'point':
            ids.append(f'proof/point/{engine}/{word[len("point/"):]}')
        else:
            ids.append(f'proof/point/{engine}/component/{index}/{word}')
    return tuple(ids)


def _build_component(engine, index, layout, reference, context, operation_id):
    """Fresh Program/GraphSpec plus the builder's own honest assignment."""
    _hosted_guard()
    op = _operation(operation_id, engine, index)
    if index == 0:
        builder = ByteTraceBuilder(TAPE_ROLE, op, context)
        words = tuple(builder.byte(f'payload/byte/{i}', value) for i, value in enumerate(reference))
        for offset, value, _, _ in tape_anchors(layout):
            builder.check('const', (words[offset],), (value,))
    else:
        builder = ConvolutionTraceBuilder(BASE_ROLE[engine], op, context)
        five = builder.constant('constant/five', 5)
        zero_hi = builder.small_constant('constant/zero-hi', 0, 2)
        spans = commitment_spans(layout, engine)
        for d in component_plan(engine)[index-1]:
            raw = reference[spans[d].start:spans[d].start+32]
            claim = canonical_decoding(raw, engine)
            if claim is None:
                raise ValueError('retained reference commitment is not canonical')
            _decoder(builder, d, raw, claim, five, zero_hi)
    program, assignment = builder.finish()
    spec = GraphSpec.from_program(program)
    census = (len(program.words), len(program.constraints), len(program.fields), len(spec.leaves))
    if census != component_census(engine, index):
        raise ValueError(f'proof-point component {index} differs from its fixed census: {census}')
    ids = _global_ids(engine, index, spec, layout)
    if len(ids) != len(spec.words) or len(set(ids)) != len(ids) or any(not ID.fullmatch(i) for i in ids):
        raise ValueError('injective physical BYTE and role-private point maps required')
    honest = tuple(assignment[word] for word, _ in spec.words)
    decoders = () if index == 0 else component_plan(engine)[index-1]
    descriptor = dict(index=index, name='tape' if index == 0 else f'{engine}-points-{index-1}',
        field_role=spec.field_role, operation_id=op,
        program_identity_kind='ByteProgram.digest (byte-v1)' if index == 0
            else 'ConvolutionProgram.digest (fixed-trace/v2)',
        words=census[0], arithmetic_constraints=census[1], canonical_fields=census[2], leaves=census[3],
        program_sha256=program.digest().hex(), catalogue_id=spec.digest().hex(),
        global_ids_sha256=sha256(_canonical(ids)).hexdigest(), decoders=decoders)
    return program, spec, ids, honest, descriptor


# ---------------------------------------------------------------------------
# Assignment and truth for a claimed profile.

def component_values(engine, index, layout, values, claims, reference):
    """Pure raw-u32 assignment of one component for a claimed payload/points."""
    if index == 0:
        return tuple(values)
    spans = commitment_spans(layout, engine)
    p = MODULUS[engine]
    words = list(constant_values())
    for d in component_plan(engine)[index-1]:
        span = spans[d]
        claimed = tuple(values[span.start:span.start+32])
        words += decoder_values(claimed, *claims[d], p, reference[span.start:span.start+32])
    return tuple(words)


def tape_ordinals(layout):
    """Payload offset -> tape leaf ordinal (anchors first, then BYTE validity)."""
    anchors = tuple(row[0] for row in tape_anchors(layout))
    fixed = frozenset(anchors)
    order = anchors + tuple(i for i in range(PAYLOAD_BYTES) if i not in fixed)
    result = [0]*PAYLOAD_BYTES
    for ordinal, offset in enumerate(order):
        result[offset] = ordinal
    return tuple(result)


def _integer(words):
    return sum(v << (29*i) for i, v in enumerate(words))


def leaf_truth(spec, program, values):
    """Strict Boolean/abort classification of every leaf (None = canonical abort)."""
    p = program.p
    result = []
    for ordinal, leaf in enumerate(spec.leaves):
        operands = [values[slot] for slot in leaf.wires]
        if any(value >= spec.words[slot][1] for slot, value in zip(leaf.wires, operands, strict=True)):
            result.append(False)
            continue
        kind = leaf.kind
        if kind == 'word_valid':
            truth = True
        elif kind == 'field_valid':
            truth = _integer(operands) < p
        elif kind == 'add':
            x, y, z = _integer(operands[:9]), _integer(operands[9:18]), _integer(operands[18:])
            truth = None if x >= p or y >= p else (x+y) % p == z
        elif kind.startswith('conv_'):
            truth = convolution_native(p, kind, leaf.argument, operands)
        elif kind == 'const':
            truth = operands[0] == leaf.argument[0]
        elif kind == 'point_form':
            truth = operands[0] == 0 or not any(operands[1:])
        elif kind == 'gate_equal':
            truth = operands[0] not in leaf.argument or operands[1:10] == operands[10:]
        else:
            raise ValueError('unexpected proof-point predicate kind')
        if ordinal < len(program.constraints) and kind != 'add' and truth is not None:
            reference = program.constraints[ordinal]
            if reference.kind != kind:
                raise ValueError('leaf/constraint order differs')
        result.append(truth)
    return tuple(result)


def component_selection(engine, index, profile, layout, truth, changed, target):
    """Full honest execution, or every non-true leaf, the complete affected
    decoder and fixed controls. Depends only on this component's truth."""
    if profile == 'honest':
        return tuple(range(len(truth)))
    selected = {j for j, value in enumerate(truth) if value is not True}
    if index == 0:
        anchors = tape_anchors(layout)
        seen = set()
        for ordinal, (_, value, _, _) in enumerate(anchors):
            if value not in seen:
                seen.add(value)
                selected.add(ordinal)
        selected.add(len(anchors))
        ordinals = tape_ordinals(layout)
        selected.update(ordinals[offset] for offset in changed)
    else:
        row = component_plan(engine)[index-1]
        if target in row:
            selected.update(range(CONSTANT_CONSTRAINTS))
            selected.update(decoder_leaf_ordinals(engine, index, row.index(target)))
            selected.add(component_census(engine, index)[1])  # constant/five field guard
        else:
            selected.add(0)
    return tuple(sorted(selected))


# ---------------------------------------------------------------------------
# Sealed plan and bindings.

def _parameters(raw_bundle, expected, dimensions, engine, context, operation_id):
    if (type(raw_bundle) is not bytes or len(raw_bundle) != HEADER_BYTES+PAYLOAD_BYTES
            or type(expected) is not ExpectedBundle or type(dimensions) is not codec.VerifierDimensions
            or type(context) is not bytes or len(context) != 32
            or type(operation_id) is not str or not ID.fullmatch(operation_id)):
        raise ValueError('retained container/policy/dimensions and explicit source identity required')
    _engine(engine)
    for index in range(len(component_plan(engine))+1):
        if not ID.fullmatch(_operation(operation_id, engine, index)):
            raise ValueError('bounded component operation identifier required')
    if (sha256(_canonical(expected.json())).hexdigest() != POLICY_PIN
            or dimensions.descriptor_sha256.hex() != DIMENSIONS_PIN):
        raise ValueError('literal retained policy and independently pinned dimensions required')


def _reference(raw_bundle, expected, dimensions, layout):
    container = bind_container(raw_bundle, expected)
    decoded = codec.decode_proof(container.proof, dimensions)
    if tuple((s.path, s.kind, s.start, s.size, s.engine) for s in decoded.spans) != tuple(
            (s.path, s.kind, s.start, s.size, s.engine) for s in layout):
        raise ValueError('reference is not the supported retained maximum-width serialization')
    return container.proof


def source_manifest(engine, layout, components, context, operation_id):
    spans = commitment_spans(layout, engine)
    decoders = tuple(dict(decoder=d, path=s.path, proof_start=s.start,
        container_start=HEADER_BYTES+s.start, component=1+d//BATCH, local=d % BATCH)
        for d, s in enumerate(spans))
    meta = dict(schema=SCHEMA, context=context.hex(), operation_id=operation_id, engine=engine,
        field_role=BASE_ROLE[engine], expected_policy_sha256=POLICY_PIN,
        verifier_dimensions_sha256=DIMENSIONS_PIN, payload_bytes=PAYLOAD_BYTES,
        container_bytes=HEADER_BYTES+PAYLOAD_BYTES, header_bytes_excluded=HEADER_BYTES,
        components=tuple(components), decoders=decoders, profiles=PROFILES,
        encoding='halo2curves 0.9 Pasta compressed: x LE with y-sign in bit 255; identity = 32 zero bytes',
        relation='asserted payload BYTEs -> canonical (infinity, x, y) with y^2=x^3+5 and parity(y)=sign',
        scope='commitment decoding only; point semantics, transcript, MSM/IPA and proof acceptance remain open')
    meta.update({flag: False for flag in FALSE_FLAGS})
    return meta


@dataclass(frozen=True, init=False)
class PointComponentRecord:
    descriptor: dict
    program: object
    spec: GraphSpec
    global_ids: tuple
    values: tuple
    truth: tuple
    selected_ordinals: tuple

    def __init__(self, *args, **kwargs):
        raise TypeError('stream from the sealed proof-point binding')
    assignment = property(lambda self: dict(zip((w for w, _ in self.spec.words), self.values, strict=True)))


@dataclass(frozen=True, init=False)
class ProofPointBinding:
    plan: object
    profile: str
    values: tuple
    claims: tuple
    changed_offsets: tuple
    target: object

    def __init__(self, *args, **kwargs):
        raise TypeError('bind through the sealed proof-point source')

    def iter_components(self):
        """Stream fresh components; each graph is built once and released.

        The targeted cap applies to the union of all yielded selections and is
        checked after the last component, before the stream is exhausted.
        """
        _hosted_guard()
        self.plan._validate()
        selected_total = 0
        for index in range(len(self.plan.components)):
            program, spec, ids, honest, descriptor = _build_component(self.plan.engine, index,
                self.plan.layout, self.plan.reference_payload, self.plan.context, self.plan.operation_id)
            if descriptor != self.plan.components[index]:
                raise ValueError('fresh proof-point component changed its sealed identity')
            values = component_values(self.plan.engine, index, self.plan.layout, self.values,
                                      self.claims, self.plan.reference_payload)
            if self.profile == 'honest' and values != honest:
                raise ValueError('pure value model differs from the frozen builder assignment')
            truth = leaf_truth(spec, program, values)
            selected = component_selection(self.plan.engine, index, self.profile, self.plan.layout,
                                           truth, self.changed_offsets, self.target)
            selected_total += len(selected)
            record = _make(PointComponentRecord, descriptor=descriptor, program=program, spec=spec,
                global_ids=ids, values=values, truth=truth, selected_ordinals=selected)
            del program, spec, ids, honest, values, truth, selected
            yield record
            del record
        if self.profile != 'honest' and selected_total > TARGET_CAP:
            raise ValueError('targeted selection exceeds closed cap; no counterexample omitted')


@dataclass(frozen=True, init=False)
class ProofPointOrigins:
    engine: str
    expected: ExpectedBundle
    dimensions: object
    context: bytes
    operation_id: str
    reference_payload: bytes
    layout: tuple
    components: tuple
    source_sha256: bytes
    _raw_bundle: bytes
    _manifest: bytes

    def __init__(self, *args, **kwargs):
        raise TypeError('use build_proof_point_origins; no graph/map/receipt admission')
    manifest = property(lambda self: json.loads(self._manifest))

    def _validate(self):
        _parameters(self._raw_bundle, self.expected, self.dimensions, self.engine,
                    self.context, self.operation_id)
        if (self._raw_bundle[HEADER_BYTES:] != self.reference_payload
                or sha256(self.reference_payload).digest() != self.expected.proof_sha256
                or retained_layout(self.dimensions) != self.layout):
            raise ValueError('owned admitted reference snapshot differs from its independent policy')
        meta = _canonical(source_manifest(self.engine, self.layout, self.components,
                                          self.context, self.operation_id))
        if meta != self._manifest or sha256(DOMAIN+meta).digest() != self.source_sha256:
            raise ValueError('actual proof-point source snapshot differs')

    def bind_profile(self, profile):
        _hosted_guard()
        self._validate()
        values, claims, changed, target = profile_claims(profile, self.engine,
                                                         self.reference_payload, self.layout)
        return _make(ProofPointBinding, plan=self, profile=profile, values=values, claims=claims,
            changed_offsets=changed, target=target)

    def summary(self):
        result = dict(schema=SCHEMA, engine=self.engine, source_sha256=self.source_sha256.hex(),
            components=len(self.components), decoders=COMMITMENTS[self.engine],
            words=sum(c['words'] for c in self.components),
            leaves=sum(c['leaves'] for c in self.components), byte_joins=32*COMMITMENTS[self.engine])
        result.update({flag: False for flag in FALSE_FLAGS})
        return result


def build_proof_point_origins(raw_bundle, expected, dimensions, *, engine, context,
                              operation_id='proof-point-origins'):
    _hosted_guard()
    _parameters(raw_bundle, expected, dimensions, engine, context, operation_id)
    layout = retained_layout(dimensions)
    reference = _reference(raw_bundle, expected, dimensions, layout)
    components = []
    for index in range(len(component_plan(engine))+1):
        built = _build_component(engine, index, layout, reference, context, operation_id)
        components.append(built[-1])
        del built
    components = tuple(components)
    meta = _canonical(source_manifest(engine, layout, components, context, operation_id))
    return _make(ProofPointOrigins, engine=engine, expected=expected, dimensions=dimensions,
        context=context, operation_id=operation_id, reference_payload=reference, layout=layout,
        components=components, source_sha256=sha256(DOMAIN+meta).digest(),
        _raw_bundle=raw_bundle, _manifest=meta)
