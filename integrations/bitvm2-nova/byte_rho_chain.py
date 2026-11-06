"""Sealed nine-component RHO -> following quadratic sumcheck challenge relation.

The five full permutations remain separate, unchanged GraphSpecs. Their global
maps identify only explicit framing, absorption and raw-state ports. The first
following-c block is an unpadded shared136-byte prefix; its actual200-byte output
feeds both suffix absorptions, including its64 capacity bytes. Eight common
suffix transforms are computed once, with a ninth gate for the HI selector.

The coefficients are canonical c0,c2 encodings. Their proof origins, the prior
transcript and eval_W origins, the surrounding sumcheck equation, production
assertions and a complete Nova/BitVM2 verifier remain outside this relation.
No aggregate oversized Program/GraphSpec or imported execution receipt exists.
"""
from dataclasses import dataclass
from hashlib import sha256
import json
import os
import re
import sys
from types import MappingProxyType

from byte_keccak_permutation import (build_byte_keccak_permutation,
                                    _parameters as _permutation_parameters)
from byte_rho import (branch_global_id as _rho_global_id, fixed_frame_bytes,
                      framed_state_bytes, _build_tail as _rho_tail,
                      _parameters as _rho_parameters)
from byte_sumcheck_frame import (build_sumcheck_frame, fixed_prefix_bytes,
                                _parameters as _frame_parameters)
from byte_sumcheck_absorb import build_sumcheck_absorb
from keccak_trace import keccak_f1600, state_from_bytes, state_to_bytes
from trace import ID, ROLES
from uniform_reduce import build_uniform_reduction
from wots_graph import GraphSpec

SCHEMA = 'bitvm2-nova-byte-rho-chain-source/v1'
MAP_SCHEMA = 'bitvm2-nova-byte-rho-chain-maps/v1'
UNIFORM_SCHEMA = 'bitvm2-nova-byte-rho-chain-uniform/v1'
SOURCE_DOMAIN = b'BITVM2-NOVA/BYTE-RHO-CHAIN-SOURCE/v1\x00'
UNIFORM_DOMAIN = b'BITVM2-NOVA/BYTE-RHO-CHAIN-UNIFORM/v1\x00'
MAX_MAP_BYTES, MAX_MANIFEST_BYTES = 8 << 20, 1 << 20
SCALAR_ROLES = ('pallas_scalar', 'vesta_scalar')
COMPONENT_ORDER = ('rho-hi', 'rho-lo', 'rho-tail', 'c-coeff-frame', 'c-prefix',
                   'c-absorb', 'c-hi', 'c-lo', 'c-uniform')
COMPONENT_SIZES = ((29445, 29245), (29445, 29245), (587, 453), (187, 111),
                   (29445, 29245), (23, 9), (29445, 29245), (29445, 29245), (379, 245))
FULL_COMPONENTS = (0, 1, 4, 6, 7)
PREFIX_OPERANDS = tuple(range(8))+(135,)
COMMON_TRANSFORMS = tuple(range(6))+(7, 135)
FALSE_FLAGS = ('eval_w_canonical_in_script', 'eval_w_proof_origin_bound',
    'prior_state_transcript_bound', 'coefficient_proof_origins_bound',
    'sumcheck_equation_verified', 'full_transcript_verified', 'transcript_verified',
    'nova_transcript_verified', 'proof_verified', 'bitvm2_script_verified',
    'production_assertion_binding', 'bitcoin_transaction_graph')
_STATE = re.compile(r'^byte-state/([0-9]{1,2})/l([0-9]{1,2})/byte([0-7])$')
_ROUND = re.compile(r'^byte-round/([0-9]{1,2})/(.+)$')


def _hosted_guard():
    if (os.environ.get('GITHUB_ACTIONS') != 'true'
            or os.environ.get('RUNNER_OS') != 'Linux' or sys.platform != 'linux'):
        raise ValueError('BYTE rho chain construction/binding is hosted GitHub Linux only')


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def _hash(value):
    return sha256(_canonical(value)).hexdigest()


def _integer(value, lo, hi, label):
    if type(value) is not int or not lo <= value <= hi:
        raise ValueError(f'canonical {label} required')
    return value


def _bytes(value, size, label):
    if type(value) is not bytes or len(value) != size:
        raise ValueError(f'exact immutable{size}-byte {label} required')
    return value


def _coefficient_bytes(coefficients):
    if type(coefficients) is not tuple or len(coefficients) != 2:
        raise ValueError('exact immutable tuple(c0_LE32,c2_LE32) required')
    for raw in coefficients:
        _bytes(raw, 32, 'compressed coefficient')
    return coefficients


def component_sizes():
    """Pure fixed local (words,leaves) census, with no graph allocation."""
    return COMPONENT_SIZES


def c_preimage(compressed_coefficients, raw_rho, *, counter, branch):
    """Pure143B encoding; field admission is the sealed factory's obligation."""
    _coefficient_bytes(compressed_coefficients)
    _bytes(raw_rho, 64, 'raw LO||HI rho state')
    _integer(counter, 0, (1 << 64)-1, 'u64 c counter')
    if type(branch) is not str or branch not in ('hi', 'lo'):
        raise ValueError('explicit hi/lo branch required')
    return (b'p'+b''.join(compressed_coefficients)+b'NoDS'+counter.to_bytes(8, 'little')
            +raw_rho+b'c'+(b'\1' if branch == 'hi' else b'\0'))


def prefix_state_bytes(compressed_coefficients, raw_rho, *, counter):
    # This is a full, UNPADDED first rate block. There is no delimiter here.
    return c_preimage(compressed_coefficients, raw_rho, counter=counter, branch='lo')[:136]+bytes(64)


def suffix_state_bytes(prefix_output, raw_rho, *, branch):
    _bytes(prefix_output, 200, 'actual prefix output')
    _bytes(raw_rho, 64, 'raw LO||HI rho state')
    if type(branch) is not str or branch not in ('hi', 'lo'):
        raise ValueError('explicit hi/lo branch required')
    block = raw_rho[59:]+b'c'+(b'\1' if branch == 'hi' else b'\0')+b'\1'+bytes(127)+b'\x80'+bytes(64)
    return bytes(a ^ b for a, b in zip(prefix_output, block, strict=True))


def _state_local(state, byte):
    return f'byte-state/{state}/l{byte//8}/byte{byte%8}'


def rho_raw_global_id(index):
    _integer(index, 0, 63, 'raw rho byte index')
    branch, byte = ('lo' if index < 32 else 'hi'), index % 32
    return 'rho/'+_rho_global_id(branch, _state_local(24, byte))


def coefficient_global_id(degree, byte):
    if type(degree) is not int or degree not in (0, 2):
        raise ValueError('compressed coefficient degree0 or2 required')
    _integer(byte, 0, 31, 'coefficient BYTE index')
    return f'c/coeff/{degree}/byte/{byte}'


def _prefix_id(state, byte):
    return 'c/prefix/'+_state_local(state, byte)


def _shared_absorb_id(byte):
    return f'c/suffix/shared/byte/{byte}'


def _suffix_input_id(branch, byte):
    if byte in COMMON_TRANSFORMS:
        return _shared_absorb_id(byte)
    if branch == 'hi' and byte == 6:
        return 'c/suffix/hi/byte/6'
    return _prefix_id(24, byte)


def _parse_local(local_name):
    if type(local_name) is not str or not ID.fullmatch(local_name):
        raise ValueError('canonical full-permutation local identity required')
    match = _STATE.fullmatch(local_name)
    if match:
        state, lane, byte = map(int, match.groups())
        if (state > 24 or lane > 24
                or match.groups() != (str(state), str(lane), str(byte))):
            raise ValueError('canonical absolute BYTE state/lane identity required')
        return state, 8*lane+byte
    match = _ROUND.fullmatch(local_name)
    if not match or int(match.group(1)) > 23 or match.group(1) != str(int(match.group(1))):
        raise ValueError('canonical absolute BYTE round identity required')
    return None


def full_global_id(component_index, local_name):
    """Pure normative projection: no witness value can select an alias."""
    _integer(component_index, 0, 8, 'chain component index')
    if component_index not in FULL_COMPONENTS:
        raise ValueError('full permutation component required')
    parsed = _parse_local(local_name)
    if component_index in (0, 1):
        result = 'rho/'+_rho_global_id('hi' if component_index == 0 else 'lo', local_name)
    elif component_index == 4:
        if parsed is not None and parsed[0] == 0 and 1 <= parsed[1] <= 64:
            slot, byte = divmod(parsed[1]-1, 32)
            result = coefficient_global_id((0, 2)[slot], byte)
        elif parsed is not None and parsed[0] == 0 and 77 <= parsed[1] < 136:
            result = rho_raw_global_id(parsed[1]-77)
        else:
            result = 'c/prefix/'+local_name
    else:
        branch = 'hi' if component_index == 6 else 'lo'
        result = (_suffix_input_id(branch, parsed[1]) if parsed is not None and parsed[0] == 0
                  else f'c/branch/{branch}/'+local_name)
    if not ID.fullmatch(result):
        raise ValueError('projected global identity exceeds unchanged cap')
    return result


def _operation(operation_id, rho_counter, index):
    if index < 3:
        return f'{operation_id}/rho/counter/{rho_counter}/'+('hi', 'lo', 'tail')[index]
    return f'{operation_id}/c/counter/{rho_counter+1}/'+('coeff-frame', 'prefix', 'absorb', 'hi', 'lo', 'uniform')[index-3]


def _parameters(context, role, rho_counter, operation_id):
    _integer(rho_counter, 0, (1 << 64)-2, 'rho counter with nonoverflowing following c')
    if (type(context) is not bytes or len(context) != 32 or type(role) is not str
            or role not in SCALAR_ROLES or type(operation_id) is not str or not ID.fullmatch(operation_id)):
        raise ValueError('explicit scalar role/operation/immutable32-byte context required')
    # Preflight EVERY nested ID, including counter digit growth, before builders.
    _rho_parameters(context, role, rho_counter, operation_id+'/rho')
    _frame_parameters(context, role, rho_counter+1, _operation(operation_id, rho_counter, 3))
    for index in (4, 6, 7):
        _permutation_parameters(context, role, _operation(operation_id, rho_counter, index))
    for index in (5, 8):
        if not ID.fullmatch(_operation(operation_id, rho_counter, index)):
            raise ValueError('derived small component operation exceeds unchanged cap')


def _make(cls, **fields):
    result = object.__new__(cls)
    for key, value in fields.items():
        object.__setattr__(result, key, value)
    return result


@dataclass(frozen=True, init=False)
class ByteRhoChainComponentDescriptor:
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
        raise TypeError('obtain descriptors from the sealed BYTE rho chain factory')

    def json(self):
        return {key: getattr(self, key) for key in self.__dataclass_fields__}


@dataclass(frozen=True, init=False)
class ByteRhoChainComponentSource:
    index: int
    branch: str
    descriptor: ByteRhoChainComponentDescriptor
    child: object
    program: object
    spec: GraphSpec
    global_ids: tuple[str, ...]
    _program_manifest: bytes | None
    _source_manifest: bytes
    _source_maps: bytes

    def __init__(self, *args, **kwargs):
        raise TypeError('regenerate an actual component from the sealed BYTE rho chain')

    child_program_manifest = property(lambda self: None if self._program_manifest is None else json.loads(self._program_manifest))
    child_source_manifest = property(lambda self: json.loads(self._source_manifest))
    child_source_maps = property(lambda self: json.loads(self._source_maps))


@dataclass(frozen=True, init=False)
class ByteRhoChainComponentBinding:
    index: int
    branch: str
    descriptor: ByteRhoChainComponentDescriptor
    program: object
    spec: GraphSpec
    global_ids: tuple[str, ...]
    _assignment: tuple
    _program_manifest: bytes | None
    _source_manifest: bytes
    _source_maps: bytes

    def __init__(self, *args, **kwargs):
        raise TypeError('stream components from the sealed BYTE rho chain binding')

    assignment = property(lambda self: dict(self._assignment))
    child_program_manifest = property(lambda self: None if self._program_manifest is None else json.loads(self._program_manifest))
    child_source_manifest = property(lambda self: json.loads(self._source_manifest))
    child_source_maps = property(lambda self: json.loads(self._source_maps))


def _small_ids(index, child, spec):
    if index == 2:
        return tuple('rho/'+name for name in child.global_ids)
    names = {}
    if index == 3:
        for degree, words in zip((0, 2), child.ports['coefficient_bytes'], strict=True):
            names.update((word, coefficient_global_id(degree, byte)) for byte, word in enumerate(words))
        frames = fixed_prefix_bytes(child.metadata['counter'])
        names.update((word, _prefix_id(0, byte))
                     for word, (byte, _) in zip(child.ports['frame_bytes'], frames, strict=True))
        fallback = 'c/coeff-frame/'
    elif index == 5:
        names.update((word, _prefix_id(24, byte))
                     for word, byte in zip(child.ports['prefix_bytes'], PREFIX_OPERANDS, strict=True))
        names.update((word, rho_raw_global_id(byte))
                     for word, byte in zip(child.ports['raw_bytes'], range(59, 64), strict=True))
        names.update((word, _shared_absorb_id(byte))
                     for word, byte in zip(child.ports['common_outputs'], COMMON_TRANSFORMS, strict=True))
        names[child.ports['hi_selector']] = 'c/suffix/hi/byte/6'
        if len(names) != 23 or set(names) != {word for word, _ in spec.words}:
            raise ValueError('nine absorption gates must expose their exact23 actual BYTE words')
        fallback = None
    elif index == 8:
        for byte, word in enumerate(child.ports['input_bytes']):
            branch = 'lo' if byte < 32 else 'hi'
            names[word] = f'c/branch/{branch}/'+_state_local(24, byte % 32)
        fallback = 'c/reduction/'
    else:
        raise ValueError('small chain component required')
    ids = tuple(names[word] if word in names else fallback+word for word, _ in spec.words)
    if any(bound != 256 for word, bound in spec.words if word in names):
        raise ValueError('shared byte ports must retain exactly BYTE decoder bounds')
    return ids


def _capture(index, child, *, role, rho_counter):
    full = index in FULL_COMPONENTS
    program = None if full else child.program
    spec = child.spec if index != 8 else GraphSpec.from_program(program)
    ids = (tuple(full_global_id(index, name) for name, _ in spec.words) if full
           else _small_ids(index, child, spec))
    if ((len(spec.words), len(spec.leaves)) != COMPONENT_SIZES[index]
            or len(ids) != len(spec.words) or len(set(ids)) != len(ids)
            or any(type(name) is not str or not ID.fullmatch(name) for name in ids)
            or spec.field_role != role):
        raise ValueError('fresh chain component declaration/census/role changed')
    program_manifest = _canonical(child.program_manifest) if full else None
    if index == 8:
        maps = dict(uniform_metadata_sha256=_hash(child.metadata), ports=dict(child.ports),
            word_map=tuple(range(379)), leaf_map=tuple(range(245)), global_ids_sha256=_hash(ids))
        raw_maps = _canonical(maps)
        metadata = dict(schema=UNIFORM_SCHEMA, context=program.context.hex(), field_role=role,
            counter=rho_counter+1, operation_id=program.operation_id,
            program_sha256=program.digest().hex(), catalogue_id=spec.digest().hex(),
            source_maps_sha256=sha256(raw_maps).hexdigest(),
            scope='unchanged unsigned512 reducer consuming actual c LO32||HI32')
        raw_source = _canonical(metadata)
        source_sha = sha256(UNIFORM_DOMAIN+raw_source).hexdigest()
        maps_sha = sha256(raw_maps).hexdigest()
    else:
        raw_maps = _canonical(child.source_maps)
        raw_source = _canonical(child.source_manifest if full or index == 5 else child.metadata)
        source_sha, maps_sha = child.source_sha256.hex(), child.source_maps_sha256.hex()
        if sha256(raw_maps).hexdigest() != maps_sha:
            raise ValueError('fresh child raw source-map bytes changed their sealed digest')
    if len(raw_maps) > MAX_MAP_BYTES or len(raw_source) > MAX_MANIFEST_BYTES:
        raise ValueError('child source/maps exceed unchanged bounded sidecar caps')
    descriptor = _make(ByteRhoChainComponentDescriptor, index=index, branch=COMPONENT_ORDER[index],
        kind=('full-permutation' if full else
              {2: 'uniform-framing-tail', 3: 'canonical-coefficients-frame', 5: 'suffix-absorption', 8: 'uniform-reduction'}[index]),
        operation_id=spec.operation_id, program_sha256=spec.program_sha256, catalogue_id=spec.digest().hex(),
        source_sha256=source_sha, source_maps_sha256=maps_sha, global_ids_sha256=_hash(ids),
        words=len(spec.words), leaves=len(spec.leaves), counter=rho_counter if index < 3 else rho_counter+1,
        field_role=role, program_identity_kind=('domain-separated manifest hash; not Program.digest' if full
            else ('ByteProgram.digest (byte-v1)' if index == 5 else 'ConvolutionProgram.digest (fixed-trace/v2)')))
    return _make(ByteRhoChainComponentSource, index=index, branch=COMPONENT_ORDER[index],
        descriptor=descriptor, child=child, program=program, spec=spec, global_ids=ids,
        _program_manifest=program_manifest, _source_manifest=raw_source, _source_maps=raw_maps)


def _regenerate(index, *, context, role, rho_counter, operation_id):
    op = _operation(operation_id, rho_counter, index)
    if index in FULL_COMPONENTS:
        child = build_byte_keccak_permutation(context=context, role=role, operation_id=op)
    elif index == 2:
        child = _rho_tail(bytes(32), bytes(32),
            framed_state_bytes(bytes(32), bytes(64), counter=rho_counter, branch='hi'),
            framed_state_bytes(bytes(32), bytes(64), counter=rho_counter, branch='lo'),
            context=context, role=role, counter=rho_counter, operation_id=op)
    elif index == 3:
        child = build_sumcheck_frame(context=context, role=role, counter=rho_counter+1, operation_id=op)
    elif index == 5:
        child = build_sumcheck_absorb(context=context, role=role, operation_id=op)
    else:
        child = build_uniform_reduction(bytes(64), context=context, role=role, operation_id=op)
    return _capture(index, child, role=role, rho_counter=rho_counter)


def _component_facts(source):
    """Retain actual interface occurrences, never a full child/global map."""
    spec, child, index = source.spec, source.child, source.index
    positions = {name: i for i, (name, _) in enumerate(spec.words)}
    if index in FULL_COMPONENTS:
        inputs = tuple(positions[word] for word in child.inputs)
        outputs = tuple(positions[word] for word in child.outputs)
        producers = tuple(child.producer_ordinals)
        formals = tuple(child.producer_occurrences)
        if inputs != tuple(range(200)) or len(outputs) != 200 or len(set(outputs)) != 200:
            raise ValueError('full child must retain ordered200 actual input/output ports')
        chosen = set(inputs+outputs)
    else:
        inputs = outputs = producers = formals = ()
        chosen = set(range(len(spec.words)))
    occurrences = {word: [] for word in chosen}
    for ordinal, leaf in enumerate(spec.leaves):
        for formal, word in enumerate(leaf.wires):
            if word in occurrences:
                occurrences[word].append((ordinal, formal))
    if any(not row for row in occurrences.values()):
        raise ValueError('every exposed interface must have an actual predicate occurrence')
    if index in FULL_COMPONENTS:
        for byte, word in enumerate(inputs):
            lane, j = divmod(byte, 8)
            x, y = lane % 5, lane // 5
            expected = ((x*32+j*4+max(y-1, 0), 0 if y == 0 else 1), (240+byte, 0))
            if tuple(occurrences[word]) != expected:
                raise ValueError('each actual full input must retain both C/Theta occurrences')
        for word, ordinal, formal in zip(outputs, producers, formals, strict=True):
            if (tuple(occurrences[word]) != ((ordinal, formal),)
                    or spec.leaves[ordinal].wires[formal] != word
                    or formal != len(spec.leaves[ordinal].wires)-1):
                raise ValueError('actual natural terminal producer occurrence changed')
    interface = tuple(dict(word_index=word, global_id=source.global_ids[word],
        bound=spec.words[word][1], occurrences=tuple(occurrences[word])) for word in sorted(chosen))
    return dict(index=index, branch=source.branch,
        global_ids_sha256=source.descriptor.global_ids_sha256,
        input_indices=inputs, output_indices=outputs, producer_ordinals=producers,
        producer_occurrences=formals, interfaces=interface)


def _rho_message_ids():
    return (tuple(f'rho/message/eval_w/byte/{i}' for i in range(32))
            +tuple(f'rho/message/prior_state/byte/{i}' for i in range(64)))


def _rho_frame_ids(branch):
    return tuple('rho/'+_rho_global_id(branch, _state_local(0, byte))
                 for byte, _ in fixed_frame_bytes(0, branch))


def _expected_intersection(left, right):
    """Closed structural alias sets; no values or supplied maps are authority."""
    pair = (left, right)
    raw = tuple(rho_raw_global_id(i) for i in range(64))
    if pair == (0, 1):
        return set(_rho_message_ids())
    if pair in ((0, 2), (1, 2)):
        branch = 'hi' if left == 0 else 'lo'
        return set(_rho_frame_ids(branch)+raw[32 if left == 0 else 0:64 if left == 0 else 32])
    if pair == (0, 4):
        return set(raw[32:59])
    if pair == (1, 4):
        return set(raw[:32])
    if pair == (2, 4):
        return set(raw[:59])
    if pair in ((0, 5), (2, 5)):
        return set(raw[59:])
    if pair == (3, 4):
        return ({coefficient_global_id(degree, byte) for degree in (0, 2) for byte in range(32)}
                | {_prefix_id(0, byte) for byte, _ in fixed_prefix_bytes(0)})
    if pair == (4, 5):
        return {_prefix_id(24, byte) for byte in PREFIX_OPERANDS}
    if pair in ((4, 6), (4, 7)):
        branch = 'hi' if right == 6 else 'lo'
        return {_prefix_id(24, byte) for byte in range(200)
                if _suffix_input_id(branch, byte) == _prefix_id(24, byte)}
    if pair == (5, 6):
        return {_shared_absorb_id(byte) for byte in COMMON_TRANSFORMS} | {'c/suffix/hi/byte/6'}
    if pair == (5, 7):
        # LO's unmodified byte6 is also an INPUT of the HI-only mask gate.
        return {_shared_absorb_id(byte) for byte in COMMON_TRANSFORMS} | {_prefix_id(24, 6)}
    if pair == (6, 7):
        return {_suffix_input_id('hi', byte) for byte in range(200) if byte != 6}
    if pair in ((6, 8), (7, 8)):
        branch = 'hi' if left == 6 else 'lo'
        return {f'c/branch/{branch}/'+_state_local(24, byte) for byte in range(32)}
    return set()


def _validate_interfaces(components):
    if type(components) is not tuple or len(components) != 9:
        raise ValueError('nine exact compact component facts required')
    sets, rows = [], []
    for index, component in enumerate(components):
        if component['index'] != index or component['branch'] != COMPONENT_ORDER[index]:
            raise ValueError('ordered fresh component facts required')
        interface = component['interfaces']
        names = {row['global_id'] for row in interface}
        if len(names) != len(interface) or any(not ID.fullmatch(name) for name in names):
            raise ValueError('injective actual component interface identities required')
        sets.append(names)
    for left in range(9):
        for right in range(left+1, 9):
            common = sets[left] & sets[right]
            if common != _expected_intersection(left, right):
                raise ValueError(f'unexpected chain alias set between components{left}/{right}')
            rows.append(dict(left=left, right=right, words=len(common),
                             global_ids_sha256=_hash(sorted(common))))
    duplicates = sum(map(len, sets))-len(set().union(*sets))
    if (duplicates != 1046 or sum(words for words, _ in COMPONENT_SIZES) != 148401
            or sum(leaves for _, leaves in COMPONENT_SIZES) != 147043
            or 148401-duplicates != 147355):
        raise ValueError('nine component forest must retain fixed147355/148401/147043 census')
    return tuple(rows)


def _connections(components):
    lookup = [{row['global_id']: row for row in component['interfaces']} for component in components]

    def link(source, target, name):
        a, b = lookup[source][name], lookup[target][name]
        if a['bound'] != b['bound'] or a['bound'] != 256:
            raise ValueError('cross-component BYTE bounds must agree at every actual formal')
        return dict(global_id=name, source_component=source, source_word=a['word_index'],
            source_occurrences=a['occurrences'], target_component=target,
            target_word=b['word_index'], target_occurrences=b['occurrences'])

    raw = tuple(rho_raw_global_id(i) for i in range(64))
    groups = dict(rho_messages=tuple(link(0, 1, name) for name in _rho_message_ids()),
        rho_frames=tuple(link(2, index, name) for index, branch in ((0, 'hi'), (1, 'lo'))
                         for name in _rho_frame_ids(branch)),
        rho_reduction=tuple(link(1 if byte < 32 else 0, 2, name) for byte, name in enumerate(raw)),
        coefficients=tuple(link(3, 4, coefficient_global_id(degree, byte))
                           for degree in (0, 2) for byte in range(32)),
        prefix_frame=tuple(link(3, 4, _prefix_id(0, byte)) for byte, _ in fixed_prefix_bytes(0)),
        rho_raw_prefix=tuple(link(1 if byte < 32 else 0, 4, name) for byte, name in enumerate(raw[:59])),
        rho_raw_absorb=tuple(link(0, 5, name) for name in raw[59:]),
        prefix_absorb=tuple(link(4, 5, _prefix_id(24, byte)) for byte in PREFIX_OPERANDS),
        prefix_suffix=tuple(link(4, index, _prefix_id(24, byte)) for index, branch in ((6, 'hi'), (7, 'lo'))
                            for byte in range(200) if _suffix_input_id(branch, byte) == _prefix_id(24, byte)),
        absorb_suffix=tuple(link(5, index, _shared_absorb_id(byte)) for index in (6, 7)
                            for byte in COMMON_TRANSFORMS)+(link(5, 6, 'c/suffix/hi/byte/6'),),
        c_reduction=tuple(link(index, 8, f'c/branch/{branch}/'+_state_local(24, byte))
                          for index, branch in ((7, 'lo'), (6, 'hi')) for byte in range(32)))
    expected = dict(rho_messages=96, rho_frames=208, rho_reduction=64, coefficients=64,
        prefix_frame=77, rho_raw_prefix=59, rho_raw_absorb=5, prefix_absorb=9,
        prefix_suffix=383, absorb_suffix=17, c_reduction=64)
    if {key: len(value) for key, value in groups.items()} != expected:
        raise ValueError('explicit source-to-consumer cross-component coverage changed')
    return groups


@dataclass(frozen=True, init=False)
class ByteRhoChainBinding:
    plan: object
    eval_w: bytes
    prior_state: bytes
    compressed_coefficients: tuple[bytes, bytes]
    initial_rho_hi: bytes
    initial_rho_lo: bytes
    rho_hi_output: bytes
    rho_lo_output: bytes
    rho_reference_hi: bytes
    rho_reference_lo: bytes
    rho_result_value: int
    rho_quotient_value: int
    initial_prefix: bytes
    prefix_output: bytes
    prefix_reference: bytes
    initial_c_hi: bytes
    initial_c_lo: bytes
    c_hi_output: bytes
    c_lo_output: bytes
    c_reference_hi: bytes
    c_reference_lo: bytes
    c_result_value: int
    c_quotient_value: int
    claimed_rho_hi_output: bytes | None
    claimed_prefix_output: bytes | None
    claimed_c_hi_output: bytes | None
    claimed_c_lo_output: bytes | None

    def __init__(self, *args, **kwargs):
        raise TypeError('bind through the sealed BYTE rho chain')

    raw_rho = property(lambda self: self.rho_lo_output[:32]+self.rho_hi_output[:32])
    raw_c = property(lambda self: self.c_lo_output[:32]+self.c_hi_output[:32])

    def iter_components(self):
        """Yield actual components; release each yielded spec/assignment alias before next."""
        _hosted_guard()

        def stream():
            for index in range(9):
                source = self.plan.regenerate_component(index)
                child, actual_child, bound = source.child, source.child, None
                spec, program = source.spec, source.program
                if index in FULL_COMPONENTS:
                    initial = {0: self.initial_rho_hi, 1: self.initial_rho_lo, 4: self.initial_prefix,
                               6: self.initial_c_hi, 7: self.initial_c_lo}[index]
                    claim = {0: self.claimed_rho_hi_output, 1: None, 4: self.claimed_prefix_output,
                             6: self.claimed_c_hi_output, 7: self.claimed_c_lo_output}[index]
                    expected = {0: self.rho_hi_output, 1: self.rho_lo_output, 4: self.prefix_output,
                                6: self.c_hi_output, 7: self.c_lo_output}[index]
                    bound = child.bind(initial, claimed_output=claim)
                    if bound.output_state != expected:
                        raise ValueError('fresh full binding changed its selected output')
                    spec, assignment = bound.spec, bound.assignment
                elif index == 2:
                    actual_child = _rho_tail(self.raw_rho[:32], self.raw_rho[32:],
                        self.initial_rho_hi, self.initial_rho_lo, context=self.plan.context,
                        role=self.plan.role, counter=self.plan.rho_counter,
                        operation_id=source.descriptor.operation_id,
                        claimed_result=self.rho_result_value, claimed_quotient=self.rho_quotient_value)
                    spec, program, assignment = actual_child.spec, actual_child.program, actual_child.assignment
                elif index == 3:
                    bound = child.bind(self.compressed_coefficients)
                    spec, program, assignment = bound.spec, bound.program, bound.assignment
                elif index == 5:
                    bound = child.bind(self.prefix_output, self.raw_rho)
                    if bound.lo_state != self.initial_c_lo or bound.hi_state != self.initial_c_hi:
                        raise ValueError('fresh absorption changed selected suffix inputs or capacity forwarding')
                    assignment = bound.assignment
                else:
                    actual_child = build_uniform_reduction(self.raw_c, context=self.plan.context,
                        role=self.plan.role, operation_id=source.descriptor.operation_id,
                        claimed_result=self.c_result_value, claimed_quotient=self.c_quotient_value)
                    program, assignment = actual_child.program, actual_child.assignment
                    spec = GraphSpec.from_program(program)
                fresh = _capture(index, actual_child, role=self.plan.role, rho_counter=self.plan.rho_counter)
                if (fresh.descriptor.json() != self.plan.components[index].json()
                        or spec.digest().hex() != fresh.descriptor.catalogue_id
                        or fresh.global_ids != source.global_ids
                        or set(assignment) != {name for name, _ in spec.words}):
                    raise ValueError('fresh bound component changed sealed source/port/assignment coverage')
                result = _make(ByteRhoChainComponentBinding, index=index, branch=source.branch,
                    descriptor=fresh.descriptor, program=program, spec=spec, global_ids=fresh.global_ids,
                    _assignment=tuple(assignment.items()), _program_manifest=fresh._program_manifest,
                    _source_manifest=fresh._source_manifest, _source_maps=fresh._source_maps)
                # No yielded record retains a child plan/binding or another registry.
                del source, child, actual_child, bound, fresh, assignment, spec, program
                yield result
                del result
        return stream()

    def summary(self):
        result = dict(source_sha256=self.plan.source_sha256.hex(), role=self.plan.role,
            rho_counter=self.plan.rho_counter, c_counter=self.plan.c_counter,
            rho_chain_binding_constructed=True, raw_rho_hex=self.raw_rho.hex(), raw_c_hex=self.raw_c.hex(),
            rho_result_le=self.rho_result_value.to_bytes(32, 'little').hex(),
            c_result_le=self.c_result_value.to_bytes(32, 'little').hex(),
            rho_reference_matches=(self.rho_hi_output == self.rho_reference_hi and self.rho_lo_output == self.rho_reference_lo),
            prefix_reference_matches=self.prefix_output == self.prefix_reference,
            c_reference_matches=(self.c_hi_output == self.c_reference_hi and self.c_lo_output == self.c_reference_lo),
            rho_reduction_relation_holds=int.from_bytes(self.raw_rho, 'little') == self.rho_result_value+ROLES[self.plan.role]*self.rho_quotient_value,
            c_reduction_relation_holds=int.from_bytes(self.raw_c, 'little') == self.c_result_value+ROLES[self.plan.role]*self.c_quotient_value)
        result.update({flag: False for flag in FALSE_FLAGS})
        return result


def _permutation(initial):
    return state_to_bytes(keccak_f1600(state_from_bytes(initial)))


@dataclass(frozen=True, init=False)
class ByteRhoChainPlan:
    context: bytes
    role: str
    rho_counter: int
    c_counter: int
    operation_id: str
    components: tuple[ByteRhoChainComponentDescriptor, ...]
    source_sha256: bytes
    source_maps_sha256: bytes
    _manifest: bytes
    _maps: bytes

    def __init__(self, *args, **kwargs):
        raise TypeError('use the hosted BYTE rho chain factory; no graph/map/receipt admission')

    manifest = property(lambda self: json.loads(self._manifest))
    source_maps = property(lambda self: json.loads(self._maps))

    @property
    def ports(self):
        return MappingProxyType(dict(eval_w=_rho_message_ids()[:32], prior_state=_rho_message_ids()[32:],
            compressed_coefficients=tuple(tuple(coefficient_global_id(degree, byte) for byte in range(32))
                                          for degree in (0, 2)),
            raw_rho=tuple(rho_raw_global_id(byte) for byte in range(64)),
            raw_c=tuple(f'c/branch/{branch}/'+_state_local(24, byte)
                        for branch in ('lo', 'hi') for byte in range(32)),
            rho_scalar_result=tuple(f'rho/reduction/result/l{i}' for i in range(9)),
            c_scalar_result=tuple(f'c/reduction/result/l{i}' for i in range(9))))

    def regenerate_component(self, index):
        _hosted_guard()
        _integer(index, 0, 8, 'component index0..8')
        source = _regenerate(index, context=self.context, role=self.role,
            rho_counter=self.rho_counter, operation_id=self.operation_id)
        if source.descriptor.json() != self.components[index].json():
            raise ValueError('fresh component changed its sealed source/program/catalogue/global-map identity')
        return source

    def bind(self, eval_w, prior_state, compressed_coefficients, *, claimed_rho_hi_output=None,
             claimed_prefix_output=None, claimed_c_hi_output=None, claimed_c_lo_output=None,
             claimed_c_result=None, claimed_c_quotient=None):
        _hosted_guard()  # Before any actual graph/state assignment allocation.
        _bytes(eval_w, 32, 'eval_W')
        _bytes(prior_state, 64, 'prior transcript value')
        _coefficient_bytes(compressed_coefficients)
        modulus = ROLES[self.role]
        if int.from_bytes(eval_w, 'little') >= modulus:
            raise ValueError('host eval_W admission requires canonical scalar; Script origin remains open')
        if any(int.from_bytes(raw, 'little') >= modulus for raw in compressed_coefficients):
            raise ValueError('host coefficients must be canonical c0,c2 scalars')
        for value in (claimed_rho_hi_output, claimed_prefix_output, claimed_c_hi_output, claimed_c_lo_output):
            if value is not None:
                _bytes(value, 200, 'controlled full output diagnostic')
        initial_rho_hi = framed_state_bytes(eval_w, prior_state, counter=self.rho_counter, branch='hi')
        initial_rho_lo = framed_state_bytes(eval_w, prior_state, counter=self.rho_counter, branch='lo')
        rho_reference_hi, rho_reference_lo = _permutation(initial_rho_hi), _permutation(initial_rho_lo)
        rho_hi = rho_reference_hi if claimed_rho_hi_output is None else claimed_rho_hi_output
        rho_lo = rho_reference_lo
        raw_rho = rho_lo[:32]+rho_hi[:32]
        rho_value = int.from_bytes(raw_rho, 'little')
        initial_prefix = prefix_state_bytes(compressed_coefficients, raw_rho, counter=self.c_counter)
        actual_prefix_reference = _permutation(initial_prefix)
        prefix = actual_prefix_reference if claimed_prefix_output is None else claimed_prefix_output
        initial_c_hi = suffix_state_bytes(prefix, raw_rho, branch='hi')
        initial_c_lo = suffix_state_bytes(prefix, raw_rho, branch='lo')
        hi = _permutation(initial_c_hi) if claimed_c_hi_output is None else claimed_c_hi_output
        lo = _permutation(initial_c_lo) if claimed_c_lo_output is None else claimed_c_lo_output
        c_value = int.from_bytes(lo[:32]+hi[:32], 'little')
        result = c_value % modulus if claimed_c_result is None else claimed_c_result
        quotient = c_value//modulus if claimed_c_quotient is None else claimed_c_quotient
        _integer(result, 0, modulus-1, 'canonical claimed c result')
        _integer(quotient, 0, (1 << 258)-1, 'unsigned258-bit claimed c quotient')
        # The honest reference is independent of every controlled output claim.
        normal_raw = rho_reference_lo[:32]+rho_reference_hi[:32]
        normal_prefix = _permutation(prefix_state_bytes(compressed_coefficients, normal_raw, counter=self.c_counter))
        return _make(ByteRhoChainBinding, plan=self, eval_w=eval_w, prior_state=prior_state,
            compressed_coefficients=compressed_coefficients, initial_rho_hi=initial_rho_hi,
            initial_rho_lo=initial_rho_lo, rho_hi_output=rho_hi, rho_lo_output=rho_lo,
            rho_reference_hi=rho_reference_hi, rho_reference_lo=rho_reference_lo,
            rho_result_value=rho_value % modulus, rho_quotient_value=rho_value//modulus,
            initial_prefix=initial_prefix, prefix_output=prefix, prefix_reference=normal_prefix,
            initial_c_hi=initial_c_hi, initial_c_lo=initial_c_lo, c_hi_output=hi, c_lo_output=lo,
            c_reference_hi=_permutation(suffix_state_bytes(normal_prefix, normal_raw, branch='hi')),
            c_reference_lo=_permutation(suffix_state_bytes(normal_prefix, normal_raw, branch='lo')),
            c_result_value=result, c_quotient_value=quotient, claimed_rho_hi_output=claimed_rho_hi_output,
            claimed_prefix_output=claimed_prefix_output, claimed_c_hi_output=claimed_c_hi_output,
            claimed_c_lo_output=claimed_c_lo_output)

    def summary(self):
        result = dict(schema=SCHEMA, context=self.context.hex(), field_role=self.role,
            operation_id=self.operation_id, rho_counter=self.rho_counter, c_counter=self.c_counter,
            source_sha256=self.source_sha256.hex(), source_maps_sha256=self.source_maps_sha256.hex(),
            component_order=COMPONENT_ORDER, components=9, full_permutations=5,
            leaves=147043, local_declared_words=148401, unique_global_words=147355,
            cached_signature_reuses=1046, rho_chain_topology_constructed=True,
            scope='framed RHO and following quadratic c hashes/reductions; external proof/transcript origins')
        result.update({flag: False for flag in FALSE_FLAGS})
        return result


def build_byte_rho_chain(*, context, role, rho_counter, operation_id='byte-rho-chain'):
    _hosted_guard()
    _parameters(context, role, rho_counter, operation_id)
    descriptors, facts = [], []
    for index in range(9):
        source = _regenerate(index, context=context, role=role, rho_counter=rho_counter, operation_id=operation_id)
        descriptors.append(source.descriptor)
        facts.append(_component_facts(source))
        del source  # Never retain five full child graphs in the plan.
    facts = tuple(facts)
    intersections = _validate_interfaces(facts)
    maps = dict(schema=MAP_SCHEMA, components=facts, pair_intersections=intersections,
        connections=_connections(facts),
        normative_global_maps=dict(rho='rho/<unchanged-rho-global-ID>',
            coefficients='c/coeff/{0,2}/byte/{0..31}',
            prefix='c/prefix/<full-local>; state0coeff/raw slots alias their exact existing ports',
            common_absorption='c/suffix/shared/byte/{0,1,2,3,4,5,7,135}',
            hi_selector='c/suffix/hi/byte/6; LO6 routes prefix output6',
            suffix='c/branch/{hi,lo}/<full-local>; state0 routes actual prefix/absorption ports',
            reduction='c/reduction/<unchanged-uniform-local>; input64 aliases LO32||HI32'),
        first_block=dict(rate_bytes=136, unpadded=True, raw_rho_prefix_bytes=59,
                         fixed_byte_indices=tuple(byte for byte, _ in fixed_prefix_bytes(rho_counter+1))),
        second_block=dict(raw_rho_indices=tuple(range(59, 64)), common_transformed_slots=COMMON_TRANSFORMS,
            hi_only_selector_slot=6, delimiter_slot=7, rate_end_slot=135, forwarded_capacity=tuple(range(136, 200))),
        coefficient_degrees=(0, 2), leaves=147043, local_declared_words=148401,
        unique_global_words=147355, cached_signature_reuses=1046)
    raw_maps = _canonical(maps)
    if len(raw_maps) > MAX_MAP_BYTES:
        raise ValueError('compact outer chain maps exceed unchanged8MiB cap')
    maps_sha = sha256(raw_maps).digest()
    manifest = dict(schema=SCHEMA, context=context.hex(), field_role=role,
        operation_id=operation_id, rho_counter=rho_counter, c_counter=rho_counter+1,
        component_order=COMPONENT_ORDER, components=[descriptor.json() for descriptor in descriptors],
        source_maps_sha256=maps_sha.hex(), leaves=147043, local_declared_words=148401,
        unique_global_words=147355, cached_signature_reuses=1046,
        message_encoding='p||c0_LE32||c2_LE32||NoDS||c_counter_LE8||rho_LO32||rho_HI32||c||selector',
        digest_encoding='LO32||HI32 unsigned512-bit little-endian',
        commitment_order='external context -> source/maps -> global keys -> nine registries -> Scripts -> forest',
        scope='RHO to following quadratic c relation; proof/transcript origins and sumcheck equation remain open')
    raw = _canonical(manifest)
    if len(raw) > MAX_MANIFEST_BYTES:
        raise ValueError('compact chain source manifest exceeds unchanged1MiB cap')
    return _make(ByteRhoChainPlan, context=context, role=role, rho_counter=rho_counter,
        c_counter=rho_counter+1, operation_id=operation_id, components=tuple(descriptors),
        source_sha256=sha256(SOURCE_DOMAIN+raw).digest(), source_maps_sha256=maps_sha,
        _manifest=raw, _maps=raw_maps)
