"""Hosted framed LO/HI BYTE Keccak hashes and unchanged uniform reduction.

Three components are ordered HI, LO, tail. Full permutation catalogues remain
unchanged; explicit global maps namespace both branches and share ONLY96 raw
message bytes. The tail preserves the245-leaf uniform reducer and adds208 BYTE
framing constants. Its64 inputs are actual LO32 then HI32 natural outputs.

Host eval_W admission is canonical, but that is NOT a Script canonicality/proof
origin check. The previous64-byte transcript value is message data, not a prior
Keccak sponge/capacity. Both branches use the SAME publicu64 counter and differ
only by selector0/1. No full transcript, Nova proof, production assertion or
Bitcoin transaction graph is accepted here.
"""
from dataclasses import dataclass
from hashlib import sha256
import json
import os
import re
import sys
from types import MappingProxyType

from byte_keccak_permutation import (ByteKeccakPermutation, build_byte_keccak_permutation,
                                    _parameters as _permutation_parameters)
from convolution import ConvolutionProgram, ConvolutionTraceBuilder
from keccak_trace import keccak_f1600, keccak_f1600_round, state_from_bytes, state_to_bytes
from trace import ID, ROLES
from uniform_reduce import build_uniform_reduction
from wots_graph import GraphSpec

SCHEMA = 'bitvm2-nova-byte-rho-source/v1'
MAP_SCHEMA = 'bitvm2-nova-byte-rho-maps/v1'
TAIL_SCHEMA = 'bitvm2-nova-byte-rho-tail/v1'
SOURCE_DOMAIN = b'BITVM2-NOVA/BYTE-RHO-SOURCE/v1\x00'
TAIL_DOMAIN = b'BITVM2-NOVA/BYTE-RHO-TAIL/v1\x00'
SCALAR_ROLES = ('pallas_scalar', 'vesta_scalar')
FIXED_BYTE_INDICES = (0,)+tuple(range(33, 45))+(109, 110)+tuple(range(111, 200))
MAX_RAW_MAP_BYTES, MAX_MANIFEST_BYTES = 8 << 20, 1 << 20
_STATE = re.compile(r'^byte-state/([0-9]{1,2})/l([0-9]{1,2})/byte([0-7])$')
_ROUND = re.compile(r'^byte-round/([0-9]{1,2})/(.+)$')
FALSE_FLAGS = ('eval_w_canonical_in_script', 'eval_w_proof_origin_bound',
    'prior_state_transcript_bound', 'full_transcript_verified', 'transcript_verified',
    'nova_transcript_verified', 'proof_verified', 'bitvm2_script_verified',
    'production_assertion_binding', 'bitcoin_transaction_graph')


def _hosted_guard():
    if (os.environ.get('GITHUB_ACTIONS') != 'true'
            or os.environ.get('RUNNER_OS') != 'Linux' or sys.platform != 'linux'):
        raise ValueError('BYTE rho source construction/binding is hosted GitHub Linux only')


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def _hash(value):
    return sha256(_canonical(value)).hexdigest()


def _integer(value, low, high, label):
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f'canonical {label} required')
    return value


def _bytes(value, size, label):
    if type(value) is not bytes or len(value) != size:
        raise ValueError(f'exact immutable{size}-byte {label} required')
    return value


def _branch(branch):
    if type(branch) is not str or branch not in ('hi', 'lo'):
        raise ValueError('explicit hi/lo branch required')
    return branch


def _counter(counter):
    return _integer(counter, 0, (1 << 64)-1, 'u64 transcript counter')


def rho_preimage(eval_w, prior_state, *, counter, branch):
    """Pure111B encoding; raw eval_W bytes here are NOT sealed admission."""
    _counter(counter)
    _branch(branch)
    return (b'w'+_bytes(eval_w, 32, 'eval_W')+b'NoDS'+counter.to_bytes(8, 'little')
            +_bytes(prior_state, 64, 'prior transcript value')+b'r'
            +(b'\1' if branch == 'hi' else b'\0'))


def framed_state_bytes(eval_w, prior_state, *, counter, branch):
    return rho_preimage(eval_w, prior_state, counter=counter, branch=branch)+b'\1'+bytes(23)+b'\x80'+bytes(64)


def fixed_frame_bytes(counter, branch):
    raw = framed_state_bytes(bytes(32), bytes(64), counter=counter, branch=branch)
    return tuple((index, raw[index]) for index in FIXED_BYTE_INDICES)


def branch_global_id(branch, local_name):
    """Pure normative namespacing; only96 declared dynamic origins are shared."""
    _branch(branch)
    if type(local_name) is not str or not ID.fullmatch(local_name):
        raise ValueError('canonical full-permutation local identity required')
    match = _STATE.fullmatch(local_name)
    if match:
        state, lane, j = (int(item) for item in match.groups())
        if state > 24 or lane > 24 or match.groups() != (str(state), str(lane), str(j)):
            raise ValueError('canonical absolute BYTE state/lane identity required')
        if state == 0:
            byte = 8*lane+j
            if 1 <= byte < 33:
                return f'message/eval_w/byte/{byte-1}'
            if 45 <= byte < 109:
                return f'message/prior_state/byte/{byte-45}'
    else:
        match = _ROUND.fullmatch(local_name)
        if not match or int(match.group(1)) > 23 or match.group(1) != str(int(match.group(1))):
            raise ValueError('canonical BYTE round identity required')
    result = f'branch/{branch}/{local_name}'
    if not ID.fullmatch(result):
        raise ValueError('namespaced branch identity exceeds existing cap')
    return result


def _state_id(branch, state, byte):
    return branch_global_id(branch, f'byte-state/{state}/l{byte//8}/byte{byte%8}')


def _message_ids():
    return (tuple(f'message/eval_w/byte/{i}' for i in range(32))
            +tuple(f'message/prior_state/byte/{i}' for i in range(64)))


def _frame_ids(branch):
    return tuple(_state_id(branch, 0, i) for i in FIXED_BYTE_INDICES)


def _digest_ids(branch):
    return tuple(_state_id(branch, 24, i) for i in range(32))


def _validate_maps(hi_ids, lo_ids, tail_ids):
    for ids, size in ((hi_ids, 29445), (lo_ids, 29445), (tail_ids, 587)):
        if (type(ids) is not tuple or len(ids) != size
                or any(type(name) is not str or not ID.fullmatch(name) for name in ids)
                or len(set(ids)) != len(ids)):
            raise ValueError('three exact injective component global maps required')
    hi, lo, tail = set(hi_ids), set(lo_ids), set(tail_ids)
    if (hi & lo != set(_message_ids())
            or hi & tail != set(_frame_ids('hi')+_digest_ids('hi'))
            or lo & tail != set(_frame_ids('lo')+_digest_ids('lo'))
            or hi & lo & tail or len(hi | lo | tail) != 59109):
        raise ValueError('rho intersections must be96/136/136, triple-empty, global59109')


def _operation(operation_id, counter, branch):
    return f'{operation_id}/counter/{counter}/{branch}'


def _parameters(context, role, counter, operation_id):
    _counter(counter)
    if (type(context) is not bytes or len(context) != 32
            or type(role) is not str or role not in SCALAR_ROLES
            or type(operation_id) is not str or not ID.fullmatch(operation_id)):
        raise ValueError('explicit scalar role/operation/immutable32-byte context required')
    for branch in ('hi', 'lo'):
        _permutation_parameters(context, role, _operation(operation_id, counter, branch))
    for derived in (_operation(operation_id, counter, 'tail'),
                    _operation(operation_id, counter, 'tail')+'/uniform'):
        if not ID.fullmatch(derived):
            raise ValueError('derived tail operation identity exceeds existing cap')


def _make(cls, **fields):
    result = object.__new__(cls)
    for name, value in fields.items():
        object.__setattr__(result, name, value)
    return result


@dataclass(frozen=True, init=False)
class ByteRhoComponentDescriptor:
    index: int
    branch: str
    kind: str
    operation_id: str
    program_sha256: str
    catalogue_id: str
    source_sha256: str
    source_maps_sha256: str
    global_ids_sha256: str
    words: int
    leaves: int
    counter: int
    field_role: str
    program_identity_kind: str

    def __init__(self, *args, **kwargs):
        raise TypeError('obtain descriptors from the sealed BYTE rho factory')

    def json(self):
        return {name: getattr(self, name) for name in self.__dataclass_fields__}


@dataclass(frozen=True, init=False)
class ByteRhoTail:
    uniform: object
    program: ConvolutionProgram
    spec: GraphSpec
    global_ids: tuple[str, ...]
    uniform_leaf_map: tuple[int, ...]
    anchor_words: tuple[str, ...]
    anchor_constraints: tuple[int, ...]
    source_sha256: bytes
    source_maps_sha256: bytes
    _assignment: tuple
    _metadata: bytes
    _maps: bytes

    def __init__(self, *args, **kwargs):
        raise TypeError('regenerate the tail through the sealed BYTE rho source')

    @property
    def assignment(self):
        return dict(self._assignment)

    @property
    def metadata(self):
        return json.loads(self._metadata)

    @property
    def source_maps(self):
        return json.loads(self._maps)


def _build_tail(lo, hi, initial_hi, initial_lo, *, context, role, counter, operation_id,
                claimed_result=None, claimed_quotient=None):
    _hosted_guard()
    _bytes(lo, 32, 'LO digest')
    _bytes(hi, 32, 'HI digest')
    _bytes(initial_hi, 200, 'actual HI input')
    _bytes(initial_lo, 200, 'actual LO input')
    uniform = build_uniform_reduction(lo+hi, role=role, context=context,
        operation_id=operation_id+'/uniform', claimed_result=claimed_result, claimed_quotient=claimed_quotient)
    uniform_spec = GraphSpec.from_program(uniform.program)
    builder = ConvolutionTraceBuilder(role, operation_id, context)
    builder.words.update(uniform.program.words)
    builder.fields.update(uniform.program.fields)
    builder.values.update(uniform.assignment)
    builder.constraints.extend(uniform.program.constraints)
    anchors, ordinals, records = [], [], []
    for branch, initial in (('hi', initial_hi), ('lo', initial_lo)):
        for byte, expected in fixed_frame_bytes(counter, branch):
            word = builder.small(f'frame/{branch}/byte/{byte}', initial[byte], 256)
            ordinal = len(builder.constraints)
            builder.check('const', (word,), (expected,))
            anchors.append(word)
            ordinals.append(ordinal)
            records.append(dict(branch=branch, byte_index=byte, expected=expected,
                                local_word=word, anchor_ordinal=ordinal))
    program, assignment = builder.finish()
    program._admit(assignment)
    spec = GraphSpec.from_program(program)
    uniform_map = tuple(range(244))+(452,)
    old_bodies, bodies = dict(uniform_spec.bodies), dict(spec.bodies)
    if (len(program.words) != 587 or len(program.constraints) != 452 or len(spec.leaves) != 453
            or program.words[:379] != uniform.program.words
            or program.constraints[:244] != uniform.program.constraints
            or program.fields != uniform.program.fields or spec.field_leaves != (('result', 452),)):
        raise ValueError('rho tail must preserve uniform source plus208 BYTE framing constants')
    for before, after in enumerate(uniform_map):
        old, new = uniform_spec.leaves[before], spec.leaves[after]
        if old != new or old_bodies[old.body_sha256] != bodies[new.body_sha256]:
            raise ValueError('uniform predicate body/alias partition changed under tail projection')
    input_names = {word: i for i, word in enumerate(uniform.ports['input_bytes'])}
    frame_names = {record['local_word']: record for record in records}
    ids = []
    positions = {word: i for i, (word, _) in enumerate(program.words)}
    for word, bound in program.words:
        if word in input_names:
            i = input_names[word]
            if bound != 256:
                raise ValueError('uniform digest ports must remain exact BYTE operands')
            global_id = _state_id('lo' if i < 32 else 'hi', 24, i % 32)
        elif word in frame_names:
            record = frame_names[word]
            if bound != 256:
                raise ValueError('framing anchors must retain exact BYTE bounds')
            global_id = _state_id(record['branch'], 0, record['byte_index'])
        else:
            global_id = 'reduction/'+word
        if not ID.fullmatch(global_id):
            raise ValueError('derived rho tail global word identity exceeds cap')
        ids.append(global_id)
    ids = tuple(ids)
    if len(set(ids)) != 587 or sum(name.startswith('reduction/') for name in ids) != 315:
        raise ValueError('tail aliases may identify only64 digest bytes and208 frame ports')
    for record in records:
        record['word_index'] = positions[record['local_word']]
        record['global_id'] = ids[record['word_index']]
    maps = dict(uniform_word_map=tuple(range(379)), uniform_leaf_map=uniform_map,
        uniform_program_sha256=uniform.program.digest().hex(), uniform_catalogue_id=uniform_spec.digest().hex(),
        uniform_metadata_sha256=_hash(uniform.metadata), uniform_ports=dict(uniform.ports),
        frame_anchors=records, digest_input_indices=tuple(positions[word] for word in uniform.ports['input_bytes']),
        result_field_indices=tuple(positions[word] for word in uniform.ports['result_field']),
        global_ids=ids, global_ids_sha256=_hash(list(ids)))
    raw_maps = _canonical(maps)
    metadata = dict(schema=TAIL_SCHEMA, context=context.hex(), field_role=role, counter=counter,
        operation_id=operation_id, program_sha256=program.digest().hex(), catalogue_id=spec.digest().hex(),
        source_maps_sha256=sha256(raw_maps).hexdigest(),
        scope='unchanged unsigned512 reduction plus208 BYTE framing constants')
    raw = _canonical(metadata)
    return _make(ByteRhoTail, uniform=uniform, program=program, spec=spec, global_ids=ids,
        uniform_leaf_map=uniform_map, anchor_words=tuple(anchors), anchor_constraints=tuple(ordinals),
        source_sha256=sha256(TAIL_DOMAIN+raw).digest(), source_maps_sha256=sha256(raw_maps).digest(),
        _assignment=tuple(assignment.items()), _metadata=raw, _maps=raw_maps)


def _full_facts(permutation, branch):
    if type(permutation) is not ByteKeccakPermutation:
        raise ValueError('fresh sealed full BYTE permutation required')
    spec = permutation.spec
    ids = tuple(branch_global_id(branch, word) for word, _ in spec.words)
    if len(ids) != 29445 or len(set(ids)) != len(ids) or len(spec.leaves) != 29245:
        raise ValueError('unchanged full permutation source census required')
    positions = {word: i for i, (word, _) in enumerate(spec.words)}
    inputs = tuple(positions[word] for word in permutation.inputs)
    outputs = tuple(positions[word] for word in permutation.outputs)
    consumers = {i: [] for i in inputs}
    for ordinal, leaf in enumerate(spec.leaves):
        for formal, word in enumerate(leaf.wires[:-1]):
            if word in consumers:
                consumers[word].append((ordinal, formal))
    cells = tuple(tuple(consumers[i]) for i in inputs)
    expected = permutation.source_maps['rounds'][0]['input_consumer_occurrences']
    if cells != tuple(tuple(tuple(cell) for cell in row) for row in expected) or any(len(row) != 2 for row in cells):
        raise ValueError('framed inputs must use their two actual C/Theta consumer occurrences')
    for index, (ordinal, formal) in enumerate(zip(permutation.producer_ordinals, permutation.producer_occurrences, strict=True)):
        if spec.leaves[ordinal].wires[formal] != outputs[index] or spec.words[outputs[index]][1] != 256:
            raise ValueError('digest source must be its actual natural BYTE producer')
    return dict(index=0 if branch == 'hi' else 1, branch=branch, global_ids=ids,
        global_ids_sha256=_hash(list(ids)), input_indices=inputs, output_indices=outputs,
        producer_ordinals=permutation.producer_ordinals, producer_occurrences=permutation.producer_occurrences,
        input_consumer_occurrences=cells)


def _descriptor(index, branch, child, facts, counter, role):
    full = branch != 'tail'
    return _make(ByteRhoComponentDescriptor, index=index, branch=branch,
        kind='full-permutation' if full else 'uniform-framing-tail', operation_id=child.operation_id if full else child.program.operation_id,
        program_sha256=child.program_sha256.hex() if full else child.program.digest().hex(),
        catalogue_id=child.spec.digest().hex(), source_sha256=child.source_sha256.hex(),
        source_maps_sha256=child.source_maps_sha256.hex(), global_ids_sha256=facts['global_ids_sha256'],
        words=len(child.spec.words), leaves=len(child.spec.leaves), counter=counter, field_role=role,
        program_identity_kind='domain-separated manifest hash; not Program.digest' if full
                              else 'ConvolutionProgram.digest (fixed-trace/v2)')


def _tail_facts(tail):
    maps = tail.source_maps
    return dict(index=2, branch='tail', global_ids=tail.global_ids, global_ids_sha256=_hash(list(tail.global_ids)),
        input_indices=tuple(maps['digest_input_indices']), output_indices=tuple(maps['result_field_indices']),
        producer_ordinals=(), producer_occurrences=(),
        input_consumer_occurrences=tuple(((i, 0),) for i in tail.uniform.input_adapter_constraints))


@dataclass(frozen=True, init=False)
class ByteRhoComponentSource:
    index: int
    branch: str
    child: object
    spec: GraphSpec
    global_ids: tuple[str, ...]
    descriptor: ByteRhoComponentDescriptor

    def __init__(self, *args, **kwargs):
        raise TypeError('regenerate a component from the sealed BYTE rho plan')


@dataclass(frozen=True, init=False)
class ByteRhoComponentBinding:
    index: int
    branch: str
    descriptor: ByteRhoComponentDescriptor
    spec: GraphSpec
    global_ids: tuple[str, ...]
    tail: object
    _assignment: tuple
    _child_program_manifest: bytes | None
    _child_source_manifest: bytes
    _child_source_maps: bytes

    def __init__(self, *args, **kwargs):
        raise TypeError('stream actual components from a sealed BYTE rho binding')

    @property
    def assignment(self):
        return dict(self._assignment)

    @property
    def child_program_manifest(self):
        return None if self._child_program_manifest is None else json.loads(self._child_program_manifest)

    @property
    def child_source_manifest(self):
        return json.loads(self._child_source_manifest)

    @property
    def child_source_maps(self):
        return json.loads(self._child_source_maps)


def _claims(value):
    if type(value) is not tuple or len(value) != 23:
        raise ValueError('exact immutable23-tuple of None|bytes200 state claims required')
    for state in value:
        if state is not None:
            _bytes(state, 200, 'intermediate state claim')
    return value


def _selected(initial, claims, final):
    state = state_from_bytes(initial)
    for index in range(24):
        state = keccak_f1600_round(state, index)
        override = claims[index] if index < 23 else final
        if override is not None:
            state = state_from_bytes(override)
    return state_to_bytes(state)


@dataclass(frozen=True, init=False)
class ByteRhoBinding:
    plan: object
    eval_w: bytes
    prior_state: bytes
    initial_hi: bytes
    initial_lo: bytes
    hi_state_claims: tuple
    lo_state_claims: tuple
    claimed_hi_output: bytes | None
    claimed_lo_output: bytes | None
    hi_output: bytes
    lo_output: bytes
    reference_hi: bytes
    reference_lo: bytes
    result_value: int
    quotient_value: int

    def __init__(self, *args, **kwargs):
        raise TypeError('bind through the sealed BYTE rho plan')

    hi = property(lambda self: self.hi_output[:32])
    lo = property(lambda self: self.lo_output[:32])
    raw_state = property(lambda self: self.lo+self.hi)

    def iter_components(self):
        """Yield HI, LO, tail; release every yielded spec/value alias before next."""
        _hosted_guard()

        def stream():
            for index, branch in enumerate(('hi', 'lo')):
                source = self.plan.regenerate_component(index)
                permutation = source.child
                initial = self.initial_hi if branch == 'hi' else self.initial_lo
                claims = self.hi_state_claims if branch == 'hi' else self.lo_state_claims
                final = self.claimed_hi_output if branch == 'hi' else self.claimed_lo_output
                bound = permutation.bind(initial, state_claims=claims, claimed_output=final)
                expected = self.hi_output if branch == 'hi' else self.lo_output
                if bound.output_state != expected:
                    raise ValueError('fresh full permutation changed the selected actual digest output')
                result = _make(ByteRhoComponentBinding, index=index, branch=branch,
                    descriptor=source.descriptor, spec=bound.spec, global_ids=source.global_ids,
                    tail=None, _assignment=tuple(bound.assignment.items()),
                    _child_program_manifest=_canonical(permutation.program_manifest),
                    _child_source_manifest=_canonical(permutation.source_manifest),
                    _child_source_maps=_canonical(permutation.source_maps))
                del bound, permutation, source
                yield result
                del result
            tail = _build_tail(self.lo, self.hi, self.initial_hi, self.initial_lo,
                context=self.plan.context, role=self.plan.role, counter=self.plan.counter,
                operation_id=_operation(self.plan.operation_id, self.plan.counter, 'tail'),
                claimed_result=self.result_value, claimed_quotient=self.quotient_value)
            descriptor = _descriptor(2, 'tail', tail, _tail_facts(tail), self.plan.counter, self.plan.role)
            if descriptor.json() != self.plan.components[2].json():
                raise ValueError('fresh reduction/framing tail changed sealed source identity')
            yield _make(ByteRhoComponentBinding, index=2, branch='tail', descriptor=descriptor,
                spec=tail.spec, global_ids=tail.global_ids, tail=tail, _assignment=tuple(tail.assignment.items()),
                _child_program_manifest=None, _child_source_manifest=tail._metadata, _child_source_maps=tail._maps)
        return stream()

    def summary(self):
        modulus = ROLES[self.plan.role]
        result = dict(source_sha256=self.plan.source_sha256.hex(), counter=self.plan.counter,
            role=self.plan.role, rho_binding_constructed=True, raw_state_hex=self.raw_state.hex(),
            result_le=self.result_value.to_bytes(32, 'little').hex(),
            reference_hashes_match=(self.hi_output == self.reference_hi and self.lo_output == self.reference_lo),
            reduction_relation_holds=int.from_bytes(self.raw_state, 'little') == self.result_value+modulus*self.quotient_value)
        result.update({flag: False for flag in FALSE_FLAGS})
        return result


@dataclass(frozen=True, init=False)
class ByteRhoPlan:
    context: bytes
    role: str
    counter: int
    operation_id: str
    components: tuple[ByteRhoComponentDescriptor, ...]
    source_sha256: bytes
    source_maps_sha256: bytes
    _manifest: bytes
    _maps: bytes

    def __init__(self, *args, **kwargs):
        raise TypeError('use the hosted BYTE rho factory; no imported graph/map/receipt authority')

    @property
    def manifest(self):
        return json.loads(self._manifest)

    @property
    def source_maps(self):
        return json.loads(self._maps)

    @property
    def ports(self):
        return MappingProxyType(dict(eval_w=_message_ids()[:32], prior_state=_message_ids()[32:],
            raw_state=_digest_ids('lo')+_digest_ids('hi'),
            scalar_result=tuple(f'reduction/result/l{i}' for i in range(9)),
            quotient=tuple(f'reduction/quotient/byte/{i}' for i in range(33))))

    def regenerate_component(self, index):
        _hosted_guard()
        _integer(index, 0, 2, 'component index0..2')
        branch = ('hi', 'lo', 'tail')[index]
        if index < 2:
            child = build_byte_keccak_permutation(context=self.context, role=self.role,
                operation_id=_operation(self.operation_id, self.counter, branch))
            facts = _full_facts(child, branch)
        else:
            child = _build_tail(bytes(32), bytes(32),
                framed_state_bytes(bytes(32), bytes(64), counter=self.counter, branch='hi'),
                framed_state_bytes(bytes(32), bytes(64), counter=self.counter, branch='lo'),
                context=self.context, role=self.role, counter=self.counter,
                operation_id=_operation(self.operation_id, self.counter, 'tail'))
            facts = _tail_facts(child)
        descriptor = _descriptor(index, branch, child, facts, self.counter, self.role)
        if descriptor.json() != self.components[index].json():
            raise ValueError('fresh rho component changed sealed source/global identity')
        return _make(ByteRhoComponentSource, index=index, branch=branch, child=child,
            spec=child.spec, global_ids=tuple(facts['global_ids']), descriptor=descriptor)

    def bind(self, eval_w, prior_state, *, hi_state_claims=(None,)*23, lo_state_claims=(None,)*23,
             claimed_hi_output=None, claimed_lo_output=None, padding_fault=None, frame_fault=None,
             claimed_result=None, claimed_quotient=None):
        _hosted_guard()  # Host admission precedes full regeneration/allocation.
        _bytes(eval_w, 32, 'eval_W')
        _bytes(prior_state, 64, 'prior transcript value')
        modulus = ROLES[self.role]
        if int.from_bytes(eval_w, 'little') >= modulus:
            raise ValueError('host eval_W must be a canonical scalar; Script provenance remains open')
        _claims(hi_state_claims)
        _claims(lo_state_claims)
        for value in (claimed_hi_output, claimed_lo_output):
            if value is not None:
                _bytes(value, 200, 'claimed full output')
        if padding_fault is not None:
            _branch(padding_fault)
            if frame_fault is not None:
                raise ValueError('choose only one controlled framing diagnostic')
            frame_fault = (padding_fault, 111, 0)
        if frame_fault is not None:
            if type(frame_fault) is not tuple or len(frame_fault) != 3:
                raise ValueError('immutable(branch,fixed-byte,replacementBYTE) diagnostic required')
            _branch(frame_fault[0])
            if type(frame_fault[1]) is not int or frame_fault[1] not in FIXED_BYTE_INDICES:
                raise ValueError('diagnostic may change only one fixed framing position')
            _integer(frame_fault[2], 0, 255, 'replacement BYTE')
        normal_hi = framed_state_bytes(eval_w, prior_state, counter=self.counter, branch='hi')
        normal_lo = framed_state_bytes(eval_w, prior_state, counter=self.counter, branch='lo')
        initial_hi, initial_lo = bytearray(normal_hi), bytearray(normal_lo)
        if frame_fault is not None:
            target = initial_hi if frame_fault[0] == 'hi' else initial_lo
            target[frame_fault[1]] = frame_fault[2]
        initial_hi, initial_lo = bytes(initial_hi), bytes(initial_lo)
        hi = _selected(initial_hi, hi_state_claims, claimed_hi_output)
        lo = _selected(initial_lo, lo_state_claims, claimed_lo_output)
        value = int.from_bytes(lo[:32]+hi[:32], 'little')
        result = value % modulus if claimed_result is None else claimed_result
        quotient = value//modulus if claimed_quotient is None else claimed_quotient
        _integer(result, 0, modulus-1, 'canonical claimed result')
        _integer(quotient, 0, (1 << 258)-1, 'unsigned258-bit claimed quotient')
        return _make(ByteRhoBinding, plan=self, eval_w=eval_w, prior_state=prior_state,
            initial_hi=initial_hi, initial_lo=initial_lo, hi_state_claims=hi_state_claims,
            lo_state_claims=lo_state_claims, claimed_hi_output=claimed_hi_output,
            claimed_lo_output=claimed_lo_output, hi_output=hi, lo_output=lo,
            reference_hi=state_to_bytes(keccak_f1600(state_from_bytes(normal_hi))),
            reference_lo=state_to_bytes(keccak_f1600(state_from_bytes(normal_lo))),
            result_value=result, quotient_value=quotient)

    def summary(self):
        result = dict(schema=SCHEMA, context=self.context.hex(), role=self.role, counter=self.counter,
            operation_id=self.operation_id, source_sha256=self.source_sha256.hex(),
            source_maps_sha256=self.source_maps_sha256.hex(), components=3,
            component_order=('hi', 'lo', 'tail'), leaves=58943, unique_global_words=59109,
            shared_message_bytes=96, frame_anchors=208, frame_consumer_links=416,
            digest_consumer_links=64, rho_source_constructed=True,
            scope='both framed Keccak hashes and scalar reduction given external message origins')
        result.update({flag: False for flag in FALSE_FLAGS})
        return result


def build_byte_rho(*, context, role, counter, operation_id='byte-rho'):
    _hosted_guard()
    _parameters(context, role, counter, operation_id)
    descriptors, components = [], []
    for index, branch in enumerate(('hi', 'lo')):
        permutation = build_byte_keccak_permutation(context=context, role=role,
            operation_id=_operation(operation_id, counter, branch))
        facts = _full_facts(permutation, branch)
        descriptors.append(_descriptor(index, branch, permutation, facts, counter, role))
        components.append(facts)
        del permutation, facts
    tail = _build_tail(bytes(32), bytes(32),
        framed_state_bytes(bytes(32), bytes(64), counter=counter, branch='hi'),
        framed_state_bytes(bytes(32), bytes(64), counter=counter, branch='lo'),
        context=context, role=role, counter=counter, operation_id=_operation(operation_id, counter, 'tail'))
    tail_facts = _tail_facts(tail)
    components.append(tail_facts)
    descriptors.append(_descriptor(2, 'tail', tail, tail_facts, counter, role))
    _validate_maps(*(tuple(record['global_ids']) for record in components))
    branches = {'hi': components[0], 'lo': components[1]}
    messages = []
    for i in range(96):
        kind, local, byte = ('eval_w', i, i+1) if i < 32 else ('prior_state', i-32, i-32+45)
        hi, lo = branches['hi'], branches['lo']
        hi_word, lo_word = hi['input_indices'][byte], lo['input_indices'][byte]
        expected = f'message/{kind}/byte/{local}'
        if hi['global_ids'][hi_word] != expected or lo['global_ids'][lo_word] != expected:
            raise ValueError('both hashes must consume the same declared raw message origin')
        messages.append(dict(index=i, kind=kind, byte_index=local, global_id=expected,
            hi_word=hi_word, lo_word=lo_word, hi_consumer_occurrences=hi['input_consumer_occurrences'][byte],
            lo_consumer_occurrences=lo['input_consumer_occurrences'][byte]))
    tail_maps = tail.source_maps
    frames = []
    for i, record in enumerate(tail_maps['frame_anchors']):
        full = branches[record['branch']]
        byte = record['byte_index']
        source_word = full['input_indices'][byte]
        if full['global_ids'][source_word] != record['global_id']:
            raise ValueError('framing constant must share the actual initial BYTE word')
        frames.append(dict(index=i, branch=record['branch'], byte_index=byte, expected=record['expected'],
            global_id=record['global_id'], source_word=source_word, tail_word=record['word_index'],
            anchor_ordinal=record['anchor_ordinal'], source_consumer_occurrences=full['input_consumer_occurrences'][byte]))
    digests = []
    for i, tail_word in enumerate(tail_maps['digest_input_indices']):
        branch, byte = ('lo' if i < 32 else 'hi'), i % 32
        full = branches[branch]
        source_word = full['output_indices'][byte]
        consumer = tail.uniform.input_adapter_constraints[i]
        leaf = tail.spec.leaves[consumer]
        global_id = full['global_ids'][source_word]
        if (global_id != tail.global_ids[tail_word] or leaf.kind != 'conv_ab'
                or leaf.argument != (1,) or leaf.wires[0] != tail_word):
            raise ValueError('LO||HI digest ports must be the exact original unit adapters')
        digests.append(dict(index=i, branch=branch, byte_index=byte, global_id=global_id,
            source_word=source_word, producer_ordinal=full['producer_ordinals'][byte],
            producer_occurrence=full['producer_occurrences'][byte], tail_word=tail_word,
            consumer_ordinal=consumer, consumer_occurrence=0))
    maps = dict(schema=MAP_SCHEMA, components=components, messages=messages, frames=frames, digests=digests,
        uniform=dict(program_sha256=tail_maps['uniform_program_sha256'],
            catalogue_id=tail_maps['uniform_catalogue_id'], metadata_sha256=tail_maps['uniform_metadata_sha256'],
            word_map=tail_maps['uniform_word_map'], leaf_map=tail_maps['uniform_leaf_map'], ports=tail_maps['uniform_ports']))
    raw_maps = _canonical(maps)
    if len(raw_maps) > MAX_RAW_MAP_BYTES:
        raise ValueError('raw rho maps exceed separate bounded file budget')
    maps_sha = sha256(raw_maps).digest()
    manifest = dict(schema=SCHEMA, context=context.hex(), field_role=role, counter=counter,
        operation_id=operation_id, component_order=('hi', 'lo', 'tail'),
        components=[descriptor.json() for descriptor in descriptors], source_maps_sha256=maps_sha.hex(),
        message_encoding='w||eval_W_LE32||NoDS||counter_LE8||prior64||r||selector;Keccak-pad111;zero-capacity64',
        digest_encoding='LO32||HI32 unsigned512-bit little-endian', leaves=58943, unique_global_words=59109,
        commitment_order='external context -> source/maps -> global keys -> registries -> Scripts -> forest',
        scope='both framed Keccak hashes and unchanged uniform reduction; external proof/transcript origins remain open')
    raw = _canonical(manifest)
    if len(raw) > MAX_MANIFEST_BYTES:
        raise ValueError('compact rho manifest exceeds one-MiB cap')
    del tail, tail_facts, tail_maps
    return _make(ByteRhoPlan, context=context, role=role, counter=counter, operation_id=operation_id,
        components=tuple(descriptors), source_sha256=sha256(SOURCE_DOMAIN+raw).digest(),
        source_maps_sha256=maps_sha, _manifest=raw, _maps=raw_maps)
