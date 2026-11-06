"""Hosted unsigned512-bit reduction using the unchanged arithmetic predicates.

This separate graph proves X=c+p*q for64 little-endian input bytes, a canonical
Pasta result c and an unsigned33-byte quotient q<2**258. It changes neither the
256-bit multiplication graph nor its32-byte quotient. Input bytes are external
ports; this module supplies no Keccak, transcript, proof-byte or assertion
binding. All original Script opening/identity/witness guards remain in the
reused ConvolutionProgram and WOTS adapters.

Sixty-four input-byte adapters multiply by one distinct, anchored BYTE-bound
unit wire. Sixty-five base256 columns include an explicit zero overflow column.
Signed carries are encoded with offset8192 and both endpoints are anchored.
The quotient's BYTE-bound top byte is split into low2/high6 bits; high is zero.
No new predicate or opcode is introduced.

With S=sum(p.to_bytes(32,'little')), each PQ column is at most255*S. Floor-derived
witness carries stay in[-(S+1),0]: min(-S-1-255-255*S)=-256*(S+1), while the
maximum numerator is255. Here S is1417 or1597, safely below8192. Even arbitrary
bounded subtotal words keep each column intermediate below2**23; the existing
limb reconstruction stays below2**29. All numeric operands fit ScriptNum4.
"""
from dataclasses import dataclass
from hashlib import sha256
import json
import os
import sys
from types import MappingProxyType

from convolution import (AB_BOUND, BYTE, CARRY_BOUND, CARRY_OFFSET, PQ_BOUND,
                         ConvolutionProgram, ConvolutionTraceBuilder)
from script import P, Q
from trace import ID, ROLES

SCHEMA = 'bitvm2-nova-uniform-reduction/v1'
INPUT_BYTES, QUOTIENT_BYTES, QUOTIENT_BITS, COLUMN_COUNT = 64, 33, 258, 65
FALSE_FLAGS = ('source_bytes_script_bound', 'keccak_output_script_bound',
    'hash_verified', 'transcript_verified', 'proof_verified', 'bitvm2_script_verified',
    'production_assertion_binding', 'bitcoin_transaction_graph')


def _hosted_guard():
    if (os.environ.get('GITHUB_ACTIONS') != 'true'
            or os.environ.get('RUNNER_OS') != 'Linux' or sys.platform != 'linux'):
        raise ValueError('uniform reduction graph construction is hosted GitHub Linux only')


def _integer(value, low, high, description):
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f'invalid {description}')
    return value


def _input(raw):
    if type(raw) is not bytes or len(raw) != INPUT_BYTES:
        raise ValueError('exactly64 unsigned little-endian input bytes required')
    return int.from_bytes(raw, 'little')


def _relation_inputs(input_bytes, modulus, result, quotient):
    value = _input(input_bytes)
    if type(modulus) is not int or modulus not in (P, Q):
        raise ValueError('supported Pasta reduction modulus required')
    _integer(result, 0, modulus-1, 'canonical reduction result')
    _integer(quotient, 0, (1 << QUOTIENT_BITS)-1, 'unsigned258-bit reduction quotient')
    return value


@dataclass(frozen=True)
class ReductionColumn:
    """Pure integer reference data; not graph construction or verification."""
    index: int
    input_byte: int
    result_byte: int
    pq_sum: int
    carry_in: int
    carry_out: int
    remainder: int

    @property
    def equation_holds(self):
        return self.remainder == 0


def reduction_columns(input_bytes, modulus, result, quotient):
    """Return65 tiny reference columns; safe locally and never builds a graph.

    For diagnostic false claims the witness uses floor division. A nonzero
    remainder exposes a false column; the carry endpoint anchors remain separate
    obligations. q is an integer rather than a field element and may exceed p.
    """
    _relation_inputs(input_bytes, modulus, result, quotient)
    p_bytes, q_bytes, c_bytes = (modulus.to_bytes(32, 'little'),
        quotient.to_bytes(QUOTIENT_BYTES, 'little'), result.to_bytes(32, 'little'))
    carry, columns = 0, []
    minimum = -(sum(p_bytes)+1)
    for index in range(COLUMN_COUNT):
        x = input_bytes[index] if index < INPUT_BYTES else 0
        c = c_bytes[index] if index < 32 else 0
        pq = sum(coefficient*q_bytes[index-i] for i, coefficient in enumerate(p_bytes)
                 if 0 <= index-i < QUOTIENT_BYTES)
        outgoing, remainder = divmod(x+carry-c-pq, BYTE)
        if not minimum <= outgoing <= 0:
            raise ValueError('integer reduction witness escaped its analytical carry bound')
        columns.append(ReductionColumn(index, x, c, pq, carry, outgoing, remainder))
        carry = outgoing
    return tuple(columns)


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


@dataclass(frozen=True, init=False)
class UniformReduction:
    role: str
    input_value: int
    result_value: int
    quotient_value: int
    program: ConvolutionProgram
    column_constraints: tuple[int, ...]
    input_adapter_constraints: tuple[int, ...]
    _assignment: tuple
    _ports: tuple
    _anchors: tuple
    _metadata: bytes

    def __init__(self, *args, **kwargs):
        raise TypeError('use the hosted uniform reduction factory')

    @property
    def assignment(self):
        return dict(self._assignment)

    @property
    def ports(self):
        # Every value is a string, immutable tuple, or tuple of immutable tuples.
        return MappingProxyType(dict(self._ports))

    @property
    def anchor_constraints(self):
        return MappingProxyType(dict(self._anchors))

    @property
    def metadata(self):
        return json.loads(self._metadata)

    def summary(self):
        result = dict(schema=SCHEMA, role=self.role, field_role=self.program.field_role,
            operation_id=self.program.operation_id, context=self.program.context.hex(),
            program_sha256=self.program.digest().hex(), metadata_sha256=sha256(self._metadata).hexdigest(),
            input_bytes=INPUT_BYTES, input_bits=512, quotient_bytes=QUOTIENT_BYTES,
            quotient_bits=QUOTIENT_BITS, result_limbs=9, result_bytes=32,
            columns=COLUMN_COUNT, overflow_column=64, carries=COLUMN_COUNT+1,
            input_byte_adapters=INPUT_BYTES, canonical_fields=len(self.program.fields),
            words=len(self.program.words), constraints=len(self.program.constraints),
            uniform_reduction_graph_constructed=True,
            reference_relation_holds=self.input_value == self.result_value+self.program.p*self.quotient_value,
            scope='unsigned512-bit integer reduction given external byte ports only')
        result.update({name: False for name in FALSE_FLAGS})
        return result


def build_uniform_reduction(input_bytes, *, role, context,
                            operation_id='uniform/reduce512', claimed_result=None,
                            claimed_quotient=None):
    """Construct a fresh fixed topology, optionally with diagnostic false claims.

    Input is exactly64 bytes; c must be canonical and q must be an unsigned
    integer below2**258. Diagnostic values change the assignment only. The
    public API accepts no Program, graph, replay receipt, or imported ports.
    Actual construction is hosted-only; use reduction_columns for tiny local
    integer checks. No claim bytes specialize a predicate or topology.
    """
    _hosted_guard()  # Before any arithmetic graph/Script allocation.
    if type(role) is not str or role not in ROLES:
        raise ValueError('explicit supported Pasta field role required')
    if type(context) is not bytes or len(context) != 32:
        raise ValueError('32-byte verifier-owned immutable context required')
    if type(operation_id) is not str or not ID.fullmatch(operation_id):
        raise ValueError('valid reduction operation identifier required')
    value, modulus = _input(input_bytes), ROLES[role]
    c = value % modulus if claimed_result is None else claimed_result
    q = value // modulus if claimed_quotient is None else claimed_quotient
    _relation_inputs(input_bytes, modulus, c, q)
    reference = reduction_columns(input_bytes, modulus, c, q)

    builder = ConvolutionTraceBuilder(role, operation_id, context)
    unit_ordinal = len(builder.constraints)
    unit = builder.small_constant('constant/byte-one', 1, BYTE)
    inputs = tuple(builder.small(f'input/byte/{i}', byte, BYTE)
                   for i, byte in enumerate(input_bytes))
    subtotals, adapter_ordinals = [], []
    for i, word in enumerate(inputs):
        subtotal = builder.small(f'input/subtotal/{i}', input_bytes[i], AB_BOUND)
        adapter_ordinals.append(len(builder.constraints))
        builder.check('conv_ab', (word, unit, subtotal), (1,))
        subtotals.append(subtotal)

    result = builder.field('result', c)
    result_bytes = builder._bytes('result/encoding', result)
    q_bytes = q.to_bytes(QUOTIENT_BYTES, 'little')
    quotient = tuple(builder.small(f'quotient/byte/{i}', byte, BYTE)
                     for i, byte in enumerate(q_bytes))
    low = builder.small('quotient/top/lo', q_bytes[-1] & 3, 4)
    high = builder.small('quotient/top/hi', q_bytes[-1] >> 2, 64)
    builder.check('conv_split', (quotient[-1], low, high), (2,))
    top_anchor = len(builder.constraints)
    builder.check('const', (high,), (0,))

    initial_anchor = len(builder.constraints)
    incoming = builder.small_constant('carry/0', CARRY_OFFSET, CARRY_BOUND)
    carries, column_ordinals, pq_blocks, pq_ordinals = [incoming], [], [], []
    modulus_bytes = modulus.to_bytes(32, 'little')
    for column in reference:
        index = column.index
        # Skip only PUBLIC zero modulus coefficients, never witness values.
        products = [(coefficient, index-i) for i, coefficient in enumerate(modulus_bytes)
                    if coefficient and 0 <= index-i < QUOTIENT_BYTES]
        blocks, block_ordinals = [], []
        for offset in range(0, len(products), 8):
            terms = products[offset:offset+8]
            total = sum(coefficient*q_bytes[j] for coefficient, j in terms)
            block = builder.small(f'reduction/pq/{index}/{offset//8}', total, PQ_BOUND)
            block_ordinals.append(len(builder.constraints))
            builder.check('conv_pq', tuple(quotient[j] for _, j in terms)+(block,),
                          tuple(coefficient for coefficient, _ in terms))
            blocks.append(block)
        outgoing = builder.small(f'carry/{index+1}', column.carry_out+CARRY_OFFSET, CARRY_BOUND)
        ab = (subtotals[index],) if index < INPUT_BYTES else ()
        output = (result_bytes[index],) if index < 32 else ()
        column_ordinals.append(len(builder.constraints))
        builder.check('conv_column', ab+tuple(blocks)+(incoming, outgoing)+output,
                      (len(ab), len(blocks), len(output)))
        carries.append(outgoing)
        pq_blocks.append(tuple(blocks))
        pq_ordinals.append(tuple(block_ordinals))
        incoming = outgoing
    final_anchor = len(builder.constraints)
    # This endpoint anchor can be algebraically redundant given the overflow
    # column plus all ranges/earlier equations. Keep it as an explicit boundary;
    # no final-anchor-alone counterexample is claimed.
    builder.check('const', (incoming,), (CARRY_OFFSET,))
    program, assignment = builder.finish()
    ports = dict(input_bytes=inputs, input_subtotals=tuple(subtotals),
        quotient_bytes=quotient, result_field=result, result_bytes=result_bytes,
        carries=tuple(carries), quotient_top_low=low, quotient_top_high=high,
        constant_one=unit, pq_blocks=tuple(pq_blocks))
    anchors = dict(constant_one=unit_ordinal, quotient_top_high=top_anchor,
                   carry_initial=initial_anchor, carry_final=final_anchor)
    metadata = dict(schema=SCHEMA, field_role=role, context=context.hex(), operation_id=operation_id,
        program_sha256=program.digest().hex(), relation='X = c + p*q',
        input_encoding='unsigned512-bit-little-endian', input_bits=512,
        quotient_encoding='unsigned258-bit-integer-in33-little-endian-bytes',
        quotient_is_field_element=False, quotient_top_byte_exclusive_bound=4,
        modulus_le=modulus.to_bytes(32, 'little').hex(), columns=COLUMN_COUNT, overflow_column=64,
        carry_offset=CARRY_OFFSET, encoded_carry_bound=CARRY_BOUND,
        reference_carry_min=-(sum(modulus_bytes)+1), reference_carry_max=0,
        max_pq_column_sum=255*sum(modulus_bytes),
        column_intermediate_exclusive_bound=1 << 23, reconstruction_exclusive_bound=1 << 29,
        ports=ports, column_ordinals=column_ordinals, input_adapter_ordinals=adapter_ordinals,
        pq_ordinals=pq_ordinals, initial_anchor_ordinal=initial_anchor,
        final_anchor_ordinal=final_anchor, unit_anchor_ordinal=unit_ordinal,
        quotient_top_anchor_ordinal=top_anchor, terminal_anchor_may_be_redundant=True,
        scope='arithmetic graph only; no hash/transcript/proof or production assertion binding')
    result_object = object.__new__(UniformReduction)
    for name, item in dict(role=role, input_value=value, result_value=c, quotient_value=q,
            program=program, column_constraints=tuple(column_ordinals),
            input_adapter_constraints=tuple(adapter_ordinals), _assignment=tuple(assignment.items()),
            _ports=tuple(ports.items()), _anchors=tuple(anchors.items()),
            _metadata=_canonical(metadata)).items():
        object.__setattr__(result_object, name, item)
    return result_object
