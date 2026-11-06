"""Hosted arithmetic bridge from claimed LO||HI digest bits to Pasta reduction.

The 512 external bit ports are distinct Boolean words, ordered LO then HI, with
four little-endian lanes per digest. Each byte's eight bits reconstruct one
BASE-bound auxiliary with the unchanged MSB-first bits(8) predicate. An unchanged
conv_reconstruct((8,)) equates that auxiliary to the SAME BYTE-bound input word
used by the fresh unsigned512-bit reducer. Equal-valued words are never merged.

This graph proves an arithmetic relation given claimed digest bits. It does not
prove that Keccak produced them, bind squeeze/framing, or verify a transcript,
proof, production assertion, or Bitcoin transaction graph. The input bytes only
provide an honest assignment; they never specialize the verifier-owned topology.
"""
from dataclasses import dataclass
from hashlib import sha256
import json
import os
import sys
from types import MappingProxyType

from convolution import ConvolutionProgram, ConvolutionTraceBuilder
from script import BASE
from trace import ID, ROLES
from uniform_reduce import UniformReduction, build_uniform_reduction
from wots_graph import GraphSpec

SCHEMA = 'bitvm2-nova-digest-reduction/v1'
MAP_SCHEMA = 'bitvm2-nova-digest-reduction-maps/v1'
SOURCE_DOMAIN = b'BITVM2-NOVA/DIGEST-REDUCTION/v1\x00'
DIGEST_BYTES, BYTE_COUNT, BIT_COUNT = 32, 64, 512
EXPECTED_WORDS, EXPECTED_CONSTRAINTS, EXPECTED_LEAVES = 955, 372, 373
FALSE_FLAGS = ('keccak_origin_script_bound', 'full_keccak_verified',
    'full_permutation_verified', 'full_hash_verified', 'hash_verified',
    'source_bytes_script_bound', 'keccak_output_script_bound',
    'padding_bound_in_script', 'absorption_bound_in_script', 'squeeze_bound_in_script',
    'transcript_verified', 'nova_transcript_verified', 'proof_verified',
    'bitvm2_script_verified', 'production_assertion_binding', 'bitcoin_transaction_graph')


def _hosted_guard():
    if (os.environ.get('GITHUB_ACTIONS') != 'true'
            or os.environ.get('RUNNER_OS') != 'Linux' or sys.platform != 'linux'):
        raise ValueError('digest reduction graph construction is hosted GitHub Linux only')


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def _digest(raw):
    if type(raw) is not bytes or len(raw) != DIGEST_BYTES:
        raise ValueError('each LO/HI digest must be exactly32 immutable bytes')
    return raw


def digest_bit_location(byte_index, lsb_bit):
    """Pure port mapping: LO||HI byte/bit -> (branch, lane, lane LSB bit).

    The byte index is 0..63 and lsb_bit is 0..7. This tiny integer helper
    performs no graph construction, Keccak evaluation, or verification.
    """
    if (type(byte_index) is not int or not 0 <= byte_index < BYTE_COUNT
            or type(lsb_bit) is not int or not 0 <= lsb_bit < 8):
        raise ValueError('canonical digest byte/LSB bit indices required')
    return ('lo' if byte_index < DIGEST_BYTES else 'hi',
            (byte_index % DIGEST_BYTES)//8, 8*(byte_index % 8)+lsb_bit)


def digest_lane_bits(raw):
    """Return256 bits: lane0..3, then bit0..63, all little endian.

    Bytes retain their original digest order. Concatenating this helper's LO
    and HI results represents int.from_bytes(LO+HI, 'little') without reversal.
    """
    return tuple((byte >> bit) & 1 for byte in _digest(raw) for bit in range(8))


def _bit_name(byte_index, lsb_bit):
    branch, lane, bit = digest_bit_location(byte_index, lsb_bit)
    return f'digest/{branch}/l{lane}/b{bit}'


def _parameters(lo, hi, role, context, operation_id):
    _digest(lo)
    _digest(hi)
    if type(role) is not str or role not in ROLES:
        raise ValueError('explicit supported Pasta field role required')
    if type(context) is not bytes or len(context) != 32:
        raise ValueError('32-byte verifier-owned immutable context required')
    if (type(operation_id) is not str or not ID.fullmatch(operation_id)
            or not ID.fullmatch(operation_id+'/uniform')):
        raise ValueError('valid bounded digest/reducer operation identifiers required')


def _source_maps(uniform, uniform_spec, program, spec, byte_bits, auxiliaries,
                 bit_ordinals, byte_ordinals):
    """Check the fresh child projection; maps cannot supply graph authority."""
    if type(uniform) is not UniformReduction or type(uniform_spec) is not GraphSpec:
        raise ValueError('fresh typed uniform child required')
    names = {name: index for index, (name, _) in enumerate(program.words)}
    child_words = tuple(names[name] for name, _ in uniform.program.words)
    if (len(child_words) != 379 or child_words != tuple(range(379))
            or program.words[:379] != uniform.program.words
            or len(uniform.program.constraints) != 244 or len(uniform_spec.leaves) != 245
            or program.constraints[:244] != uniform.program.constraints
            or program.fields != uniform.program.fields):
        raise ValueError('fresh uniform source projection differs from the fixed topology')
    child_leaves = tuple(range(244))+(372,)
    child_bodies, bodies = dict(uniform_spec.bodies), dict(spec.bodies)
    for old_index, new_index in enumerate(child_leaves):
        old, new = uniform_spec.leaves[old_index], spec.leaves[new_index]
        if (new.kind != old.kind or new.argument != old.argument
                or new.wires != tuple(child_words[i] for i in old.wires)
                or new.body_sha256 != old.body_sha256
                or bodies.get(new.body_sha256) != child_bodies.get(old.body_sha256)):
            raise ValueError('uniform leaf body/alias projection differs from its fresh child')
    bits = tuple(word for group in byte_bits for word in group)
    bit_indices = tuple(names[word] for word in bits)
    aux_indices = tuple(names[word] for word in auxiliaries)
    input_indices = tuple(names[word] for word in uniform.ports['input_bytes'])
    if (len(set(bits)) != BIT_COUNT or len(set(auxiliaries)) != BYTE_COUNT
            or set(bits) & set(auxiliaries) or set(bit_indices+aux_indices) & set(child_words)
            or set(child_words+bit_indices+aux_indices) != set(range(EXPECTED_WORDS))
            or any(program.words[i][1] != 2 for i in bit_indices)
            or any(program.words[i][1] != BASE for i in aux_indices)
            or any(program.words[i][1] != 256 for i in input_indices)):
        raise ValueError('distinct bit/auxiliary/byte port ranges or coverage differ')
    for i in range(BYTE_COUNT):
        bit_leaf, byte_leaf = spec.leaves[bit_ordinals[i]], spec.leaves[byte_ordinals[i]]
        expected_bits = (aux_indices[i],)+tuple(reversed(bit_indices[8*i:8*i+8]))
        if (bit_leaf.kind != 'bits' or bit_leaf.argument != (8,)
                or bit_leaf.wires != expected_bits
                or byte_leaf.kind != 'conv_reconstruct' or byte_leaf.argument != (8,)
                or byte_leaf.wires != (aux_indices[i], input_indices[i])):
            raise ValueError('ordered digest bits must link to the actual reducer BYTE port')
    return dict(schema=MAP_SCHEMA,
        children=[dict(kind='uniform-reduction', program_sha256=uniform.program.digest().hex(),
                       catalogue_id=uniform_spec.digest().hex(), word_map=child_words,
                       leaf_map=child_leaves)],
        digest_lo_indices=bit_indices[:256], digest_hi_indices=bit_indices[256:],
        digest_bit_indices=bit_indices, byte_bit_indices=tuple(
            bit_indices[8*i:8*i+8] for i in range(BYTE_COUNT)),
        byte_auxiliary_indices=aux_indices, input_byte_indices=input_indices,
        bridge_bits_leaves=bit_ordinals, bridge_byte_leaves=byte_ordinals,
        canonical_result_leaf=372)


@dataclass(frozen=True, init=False)
class DigestReduction:
    role: str
    lo: bytes
    hi: bytes
    uniform: UniformReduction
    program: ConvolutionProgram
    spec: GraphSpec
    source_sha256: bytes
    bridge_bit_constraints: tuple[int, ...]
    bridge_byte_constraints: tuple[int, ...]
    uniform_leaf_map: tuple[int, ...]
    _assignment: tuple
    _ports: tuple
    _metadata: bytes
    _maps: bytes

    def __init__(self, *args, **kwargs):
        raise TypeError('use the hosted digest reduction factory')

    @property
    def assignment(self):
        return dict(self._assignment)

    @property
    def ports(self):
        return MappingProxyType(dict(self._ports))

    @property
    def metadata(self):
        return json.loads(self._metadata)

    @property
    def source_maps(self):
        return json.loads(self._maps)

    def summary(self):
        result = dict(schema=SCHEMA, role=self.role, field_role=self.program.field_role,
            operation_id=self.program.operation_id, context=self.program.context.hex(),
            program_sha256=self.program.digest().hex(), catalogue_id=self.spec.digest().hex(),
            source_sha256=self.source_sha256.hex(),
            uniform_program_sha256=self.uniform.program.digest().hex(),
            input_encoding='LO||HI unsigned512-bit-little-endian', digest_bytes=32,
            digest_branches=2, digest_bits=BIT_COUNT, byte_auxiliaries=BYTE_COUNT,
            bridge_constraints=128, words=len(self.program.words),
            constraints=len(self.program.constraints), leaves=len(self.spec.leaves),
            canonical_fields=len(self.program.fields),
            digest_reduction_graph_constructed=True,
            digest_bits_to_reducer_bytes_linked=True,
            reference_relation_holds=self.uniform.input_value ==
                self.uniform.result_value+self.program.p*self.uniform.quotient_value,
            scope='arithmetic reduction of claimed external LO||HI digest-bit ports only')
        result.update({name: False for name in FALSE_FLAGS})
        return result


def build_digest_reduction(lo, hi, *, role, context, operation_id='digest/reduce512'):
    """Build a fresh fixed topology and honest assignment from two exact digests.

    No caller Program, GraphSpec, assignment, receipt, or port-map constructor
    exists. Claimed Keccak-origin bits remain explicit external ports. Actual
    graph construction is hosted-only; the pure mapping helpers are safe locally.
    """
    _hosted_guard()  # Before child graph, Script, or catalogue allocation.
    _parameters(lo, hi, role, context, operation_id)
    uniform = build_uniform_reduction(lo+hi, role=role, context=context,
                                      operation_id=operation_id+'/uniform')
    uniform_spec = GraphSpec.from_program(uniform.program)
    builder = ConvolutionTraceBuilder(role, operation_id, context)
    # Preserve exact child names/indices and all original anchors/constraints.
    builder.words.update(uniform.program.words)
    builder.fields.update(uniform.program.fields)
    builder.values.update(uniform.assignment)
    builder.constraints.extend(uniform.program.constraints)
    bits, auxiliaries, bit_ordinals, byte_ordinals = [], [], [], []
    raw = lo+hi
    for index, byte in enumerate(raw):
        group = tuple(builder.small(_bit_name(index, bit), (byte >> bit) & 1, 2)
                      for bit in range(8))
        auxiliary = builder.small(f'digest/byte/{index}/aux', byte, BASE)
        bit_ordinals.append(len(builder.constraints))
        builder.check('bits', (auxiliary,)+tuple(reversed(group)), (8,))
        byte_ordinals.append(len(builder.constraints))
        builder.check('conv_reconstruct', (auxiliary, uniform.ports['input_bytes'][index]), (8,))
        bits.append(group)
        auxiliaries.append(auxiliary)
    program, assignment = builder.finish()
    program._admit(assignment)
    spec = GraphSpec.from_program(program)
    if (len(program.words) != EXPECTED_WORDS or len(program.constraints) != EXPECTED_CONSTRAINTS
            or len(spec.leaves) != EXPECTED_LEAVES or len(program.fields) != 1
            or spec.field_leaves != (('result', 372),)):
        raise ValueError('digest reduction graph census differs from the fixed topology')
    bit_ordinals, byte_ordinals = tuple(bit_ordinals), tuple(byte_ordinals)
    maps = _source_maps(uniform, uniform_spec, program, spec, tuple(bits),
                        tuple(auxiliaries), bit_ordinals, byte_ordinals)
    flat_bits = tuple(word for group in bits for word in group)
    ports = dict(uniform.ports)
    ports.update(digest_lo_bits=flat_bits[:256], digest_hi_bits=flat_bits[256:],
                 digest_bits=flat_bits, byte_bits=tuple(bits), byte_auxiliaries=tuple(auxiliaries))
    metadata = dict(schema=SCHEMA, field_role=role, context=context.hex(), operation_id=operation_id,
        program_sha256=program.digest().hex(), catalogue_id=spec.digest().hex(),
        relation='int.from_bytes(LO||HI, little) = c + p*q',
        digest_branch_order=('lo', 'hi'), digest_lane_order='lane0..3,LSBbit0..63',
        byte_bit_order='LSBfirst ports; MSBfirst bits(8) formal occurrences',
        byte_link='conv_reconstruct((8,)) on BASE auxiliary and same reducer BYTE word',
        uniform_metadata_sha256=sha256(_canonical(uniform.metadata)).hexdigest(),
        source_maps=maps, ports=ports,
        scope='claimed digest-bit arithmetic only; no Keccak origin, squeeze, transcript or proof binding')
    encoded = _canonical(metadata)
    result = object.__new__(DigestReduction)
    for name, value in dict(role=role, lo=lo, hi=hi, uniform=uniform,
            program=program, spec=spec, source_sha256=sha256(SOURCE_DOMAIN+encoded).digest(),
            bridge_bit_constraints=bit_ordinals, bridge_byte_constraints=byte_ordinals,
            uniform_leaf_map=tuple(maps['children'][0]['leaf_map']),
            _assignment=tuple(assignment.items()), _ports=tuple(ports.items()),
            _metadata=encoded, _maps=_canonical(maps)).items():
        object.__setattr__(result, name, value)
    return result
