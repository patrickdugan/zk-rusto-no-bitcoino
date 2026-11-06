"""Bounded BYTE absorption for the second block of one sumcheck challenge.

The first 136 message bytes have already passed through a full permutation.
This helper XORs the seven remaining message bytes and Keccak padding into its
rate, forwarding all capacity bytes unchanged. Eight identical transforms are
shared between LO/HI; the HI selector transform is separate. It accepts no
external source authority, proof, transcript receipt or imported graph.
"""
from dataclasses import dataclass
from hashlib import sha256
import json
import os
import sys
from types import MappingProxyType

from byte_kernels import BYTE, ByteProgram, ByteTraceBuilder
from trace import ID
from wots_graph import GraphSpec

SCHEMA = 'bitvm2-nova-byte-sumcheck-absorb/v1'
MAP_SCHEMA = 'bitvm2-nova-byte-sumcheck-absorb-maps/v1'
SOURCE_DOMAIN = b'BITVM2-NOVA/BYTE-SUMCHECK-ABSORB/v1\x00'
PREFIX_POSITIONS = tuple(range(8))+(135,)
RAW_POSITIONS = tuple(range(59, 64))
COMMON_POSITIONS = tuple(range(6))+(7, 135)
GATE_POSITIONS = COMMON_POSITIONS+(6,)
SCALAR_ROLES = ('pallas_scalar', 'vesta_scalar')


def _hosted_guard():
    if (os.environ.get('GITHUB_ACTIONS') != 'true'
            or os.environ.get('RUNNER_OS') != 'Linux' or sys.platform != 'linux'):
        raise ValueError('sumcheck absorption construction/binding is hosted GitHub Linux only')


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def _bytes(value, size, label):
    if type(value) is not bytes or len(value) != size:
        raise ValueError(f'exact immutable {size}-byte {label} required')
    return value


def _counter(counter):
    if type(counter) is not int or not 0 <= counter < 1 << 64:
        raise ValueError('canonical u64 counter required')
    return counter


def _branch(branch):
    if type(branch) is not str or branch not in ('hi', 'lo'):
        raise ValueError('explicit hi/lo branch required')
    return branch


def sumcheck_preimage(coefficients, raw_rho, *, counter, branch):
    """Pure 143-byte framing; scalar canonicality is a separate Script source."""
    _counter(counter)
    _branch(branch)
    if type(coefficients) is not tuple or len(coefficients) != 2:
        raise ValueError('two immutable coefficient encodings, c0 then c2, required')
    c0, c2 = (_bytes(value, 32, 'coefficient') for value in coefficients)
    return (b'p'+c0+c2+b'NoDS'+counter.to_bytes(8, 'little')
            +_bytes(raw_rho, 64, 'raw LO then HI rho state')+b'c'
            +(b'\1' if branch == 'hi' else b'\0'))


def prefix_state_bytes(coefficients, raw_rho, *, counter):
    """The complete first rate block, with zero initial capacity and NO padding."""
    return sumcheck_preimage(coefficients, raw_rho, counter=counter, branch='lo')[:136]+bytes(64)


def suffix_rate_bytes(raw_rho, *, branch):
    _branch(branch)
    return (_bytes(raw_rho, 64, 'raw rho state')[59:]+b'c'
            +(b'\1' if branch == 'hi' else b'\0')+b'\1'+bytes(127)+b'\x80')


def absorbed_state_bytes(prefix_output, raw_rho, *, branch):
    state = _bytes(prefix_output, 200, 'prefix permutation output')
    suffix = suffix_rate_bytes(raw_rho, branch=branch)
    return bytes(a ^ b for a, b in zip(state[:136], suffix, strict=True))+state[136:]


def _parameters(context, role, operation_id):
    if (type(context) is not bytes or len(context) != 32
            or type(role) is not str or role not in SCALAR_ROLES
            or type(operation_id) is not str or not ID.fullmatch(operation_id)):
        raise ValueError('explicit scalar role, operation and immutable 32-byte context required')


def _prefix_names():
    return tuple(f'prefix/byte/{i}' for i in PREFIX_POSITIONS)


def _raw_names():
    return tuple(f'raw/byte/{i}' for i in RAW_POSITIONS)


def _output_names():
    return tuple(f'shared/byte/{i}' for i in COMMON_POSITIONS)+('hi/selector',)


def _expected_shape():
    prefixes = dict(zip(PREFIX_POSITIONS, _prefix_names(), strict=True))
    raws = dict(zip(RAW_POSITIONS, _raw_names(), strict=True))
    outputs = _output_names()
    gates = [('byte_xor', (), (prefixes[i], raws[59+i], outputs[i])) for i in range(5)]
    for ordinal, byte, mask in ((5, 5, 99), (6, 7, 1), (7, 135, 128), (8, 6, 1)):
        gates.append(('byte_xor_const', (mask,), (prefixes[byte], outputs[ordinal])))
    return tuple((name, BYTE) for name in _prefix_names()+_raw_names()+outputs), tuple(gates)


def _ports():
    return dict(prefix_bytes=_prefix_names(), prefix_byte_positions=PREFIX_POSITIONS,
        raw_bytes=_raw_names(), raw_byte_positions=RAW_POSITIONS,
        common_outputs=_output_names()[:8], common_byte_positions=COMMON_POSITIONS,
        hi_selector=_output_names()[8], gate_outputs=_output_names(),
        gate_output_positions=GATE_POSITIONS, gate_constraints=tuple(range(9)),
        prefix_occurrences=tuple((position, ordinal, 0)
            for ordinal, position in enumerate(GATE_POSITIONS)),
        raw_occurrences=tuple((59+i, i, 1) for i in range(5)),
        producer_occurrences=tuple((i, 2 if i < 5 else 1) for i in range(9)))


def _routes(branch):
    _branch(branch)
    shared = dict(zip(COMMON_POSITIONS, _output_names()[:8], strict=True))
    return tuple(('output', shared[i]) if i in shared else
        ('output', 'hi/selector') if i == 6 and branch == 'hi' else
        ('prefix', i) for i in range(200))


def _maps():
    return dict(schema=MAP_SCHEMA,
        ports={key: value for key, value in _ports().items()},
        lo_inputs=_routes('lo'), hi_inputs=_routes('hi'),
        shared_final_input_positions=tuple(i for i in range(200) if i != 6),
        prefix_lo_forward_positions=tuple(i for i in range(200) if i not in COMMON_POSITIONS),
        prefix_hi_forward_positions=tuple(i for i in range(200)
            if i not in COMMON_POSITIONS and i != 6),
        capacity_positions=tuple(range(136, 200)),
        first_block_unpadded=True, final_capacity_zero_anchored=False,
        forwarding_is_structural=True, value_selected_aliases=False)


def _manifest(program, spec, maps):
    return dict(schema=SCHEMA, context=program.context.hex(), field_role=program.field_role,
        operation_id=program.operation_id, program_sha256=program.digest().hex(),
        program_identity_kind='ByteProgram.digest (byte domain over fixed-trace/v2)',
        catalogue_id=spec.digest().hex(), source_maps_sha256=sha256(_canonical(maps)).hexdigest(),
        words=23, leaves=9, shared_suffix_transforms=8, hi_selector_transforms=1,
        prefix_input_bytes=9, raw_tail_bytes=5, capacity_forward_bytes=64,
        source_authority=False, proof_origin_bound=False,
        full_transcript_verified=False, production_assertion_binding=False)


def _make(cls, **fields):
    value = object.__new__(cls)
    for key, item in fields.items():
        object.__setattr__(value, key, item)
    return value


@dataclass(frozen=True, init=False)
class SumcheckAbsorbBinding:
    _assignment: tuple
    outputs: tuple[int, ...]
    lo_state: bytes
    hi_state: bytes

    def __init__(self, *args, **kwargs):
        raise TypeError('bind the sealed sumcheck absorption plan')

    @property
    def assignment(self):
        return dict(self._assignment)


@dataclass(frozen=True, init=False)
class SumcheckAbsorbPlan:
    program: ByteProgram
    spec: GraphSpec
    _maps_bytes: bytes
    _manifest_bytes: bytes
    source_sha256: bytes
    source_maps_sha256: bytes

    def __init__(self, *args, **kwargs):
        raise TypeError('use the sealed sumcheck absorption factory')

    @property
    def ports(self):
        return MappingProxyType(_ports())

    @property
    def source_maps(self):
        return json.loads(self._maps_bytes)

    @property
    def source_manifest(self):
        return json.loads(self._manifest_bytes)

    def _check(self):
        _parameters(self.program.context, self.program.field_role, self.program.operation_id)
        words, gates = _expected_shape()
        if (type(self.program) is not ByteProgram or self.program.words != words
                or self.program.fields or len(self.program.constraints) != 9
                or tuple((c.kind, c.argument, c.wires) for c in self.program.constraints) != gates
                or type(self.spec) is not GraphSpec or self.spec != GraphSpec.from_program(self.program)
                or self._maps_bytes != _canonical(_maps())
                or self.source_maps_sha256 != sha256(self._maps_bytes).digest()
                or self._manifest_bytes != _canonical(_manifest(self.program, self.spec, _maps()))
                or self.source_sha256 != sha256(SOURCE_DOMAIN+self._manifest_bytes).digest()):
            raise ValueError('sumcheck absorption sealed source fingerprint differs')

    def bind(self, prefix_output, raw_rho, *, claimed_outputs=None):
        _hosted_guard()
        self._check()
        state = _bytes(prefix_output, 200, 'prefix permutation output')
        raw = _bytes(raw_rho, 64, 'raw rho state')
        if claimed_outputs is not None and (type(claimed_outputs) is not tuple
                or len(claimed_outputs) != 9
                or any(value is not None and (type(value) is not int or not 0 <= value < BYTE)
                       for value in claimed_outputs)):
            raise ValueError('nine immutable optional BYTE output claims required')
        expected = tuple(state[i] ^ raw[59+i] for i in range(5))+(state[5] ^ 99,
            state[7] ^ 1, state[135] ^ 128, state[6] ^ 1)
        outputs = expected if claimed_outputs is None else tuple(
            expected[i] if value is None else value for i, value in enumerate(claimed_outputs))
        assignment = dict(zip(_prefix_names(), (state[i] for i in PREFIX_POSITIONS), strict=True))
        assignment.update(zip(_raw_names(), (raw[i] for i in RAW_POSITIONS), strict=True))
        assignment.update(zip(_output_names(), outputs, strict=True))
        out_values = dict(zip(_output_names(), outputs, strict=True))

        def routed(branch):
            return bytes(state[value] if kind == 'prefix' else out_values[value]
                         for kind, value in _routes(branch))

        return _make(SumcheckAbsorbBinding, _assignment=tuple(assignment.items()), outputs=outputs,
                     lo_state=routed('lo'), hi_state=routed('hi'))


def build_sumcheck_absorb(*, context, role, operation_id='sumcheck/absorb'):
    _hosted_guard()
    _parameters(context, role, operation_id)
    builder = ByteTraceBuilder(role, operation_id, context)
    for name in _prefix_names()+_raw_names():
        builder.byte(name, 0)
    _, gates = _expected_shape()
    for kind, arguments, wires in gates:
        builder.apply(kind, wires[-1], *wires[:-1], argument=arguments)
    program, _ = builder.finish()
    spec = GraphSpec.from_program(program)
    maps = _canonical(_maps())
    manifest = _canonical(_manifest(program, spec, _maps()))
    return _make(SumcheckAbsorbPlan, program=program, spec=spec, _maps_bytes=maps,
        _manifest_bytes=manifest, source_sha256=sha256(SOURCE_DOMAIN+manifest).digest(),
        source_maps_sha256=sha256(maps).digest())
