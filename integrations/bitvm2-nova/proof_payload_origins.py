"""Retained maximum-width proof-payload BYTE and scalar relations.

This independent source uses completed legacy BYTE/limb predicates only. The
reference is freshly admitted; asserted bytes are NOT decoded as another proof.
Canonical scalar substitutions and opaque point substitutions can satisfy this
local relation. No asserted blob hash, EOF, header, transcript, proof, production
root, or compressed-point decoding is authenticated by these graphs.
"""
from dataclasses import dataclass, asdict
from hashlib import sha256
import json
import os
import sys

from byte_kernels import ByteTraceBuilder
from convolution import ConvolutionTraceBuilder, convolution_native
from eval_w_encoding import CROSSINGS, encoding_values
from nht4 import ExpectedBundle, HEADER_BYTES, bind_container
import proof_codec as codec
from script import BASE, P, Q
from trace import ID
from wots_graph import GraphSpec

SCHEMA = 'bitvm2-nova-proof-payload-origins/v1'
MAP_SCHEMA = 'bitvm2-nova-proof-payload-origins-maps/v1'
DOMAIN = b'BITVM2-NOVA/PROOF-PAYLOAD-ORIGINS/v1\x00'
COMPONENT_DOMAIN = b'BITVM2-NOVA/PROOF-PAYLOAD-COMPONENT/v1\x00'
POLICY_PIN = 'cdfa31622881cc1863abd1eb252c136184501785b4b02e9985e6ba0850b2ac54'
DIMENSIONS_PIN = 'de6333df2e41b5f5bae1c103fab862f8d6022fd54abeb80ba61920bc9f360edc'
PAYLOAD_BYTES, MAP_CAP, MANIFEST_CAP, TARGET_CAP = 12664, 8 << 20, 1 << 20, 128
NAMES = ('tape', 'pallas', 'vesta')
ROLES = ('pallas_scalar', 'pallas_scalar', 'vesta_scalar')
ENGINES = (None, 'pallas', 'vesta')
COUNTS = (12664, 169, 119)
PROFILES = ('honest', 'coherent-p-eval', 'coherent-v-eval', 'p-mod', 'p-mod1',
    'v-mod', 'v-mod1', 'zn0-width', 'p-outer-count', 'v-outer-count',
    'opaque-p', 'opaque-v', 'byte-256', 'byte-max')
FALSE_FLAGS = ('blob_sha256_script_bound', 'proof_eof_authenticated',
    'container_header_script_bound', 'public_state_to_zn_script_bound', 'compressed_points_script_decoded',
    'generic_nova_decoder', 'transcript_verified', 'proof_verified',
    'complete_nova_verifier', 'complete_bitvm2_verifier',
    'production_assertion_binding', 'bitcoin_transaction_graph')


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def _hosted_guard():
    if (os.environ.get('GITHUB_ACTIONS') != 'true'
            or os.environ.get('RUNNER_OS') != 'Linux' or sys.platform != 'linux'):
        raise ValueError('proof-payload graph construction/binding is hosted GitHub Linux only')


def _make(cls, **fields):
    result = object.__new__(cls)
    for name, value in fields.items():
        object.__setattr__(result, name, value)
    return result


@dataclass(frozen=True)
class PayloadSpan:
    path: str
    kind: str
    start: int
    size: int
    engine: str | None
    width_bits: int | None
    minimum: int | None
    maximum: int | None

    def json(self):
        return asdict(self)


@dataclass(frozen=True)
class ComponentDescriptor:
    index: int
    name: str
    field_role: str
    operation_id: str
    program_identity_kind: str
    words: int
    arithmetic_constraints: int
    canonical_fields: int
    leaves: int
    program_sha256: str
    catalogue_id: str
    source_sha256: str
    source_maps_sha256: str
    global_ids_sha256: str

    def json(self):
        return asdict(self)


def _operations(operation_id):
    return (operation_id+'/tape', operation_id+'/pallas-scalars', operation_id+'/vesta-scalars')


def _parameters(raw_bundle, expected, dimensions, context, operation_id):
    if (type(raw_bundle) is not bytes or len(raw_bundle) != HEADER_BYTES+PAYLOAD_BYTES
            or type(expected) is not ExpectedBundle or type(dimensions) is not codec.VerifierDimensions
            or type(context) is not bytes or len(context) != 32
            or type(operation_id) is not str or not ID.fullmatch(operation_id)
            or any(not ID.fullmatch(op) for op in _operations(operation_id))):
        raise ValueError('retained container/policy/dimensions and explicit bounded source identity required')
    if (sha256(_canonical(expected.json())).hexdigest() != POLICY_PIN
            or dimensions.descriptor_sha256.hex() != DIMENSIONS_PIN):
        raise ValueError('literal retained policy and independently pinned dimensions required')
    checked = codec.VerifierDimensions.from_json(dimensions.json(), expected,
        expected_descriptor_sha256=bytes.fromhex(DIMENSIONS_PIN))
    if checked != dimensions or (expected.proof_bytes, expected.bundle_bytes) != (12664,13220):
        raise ValueError('unsupported retained proof-payload profile')


def retained_layout(dimensions):
    """Pure verifier-owned maximum-width layout, independent of claimed prefixes."""
    if (type(dimensions) is not codec.VerifierDimensions
            or dimensions.descriptor_sha256.hex() != DIMENSIONS_PIN):
        raise ValueError('literal retained dimension profile required')
    spans, position = [], 0
    def visit(node, path=''):
        nonlocal position
        if isinstance(node, codec._Atom):
            width = None if node.bound is None else node.bound.bit_length()-1
            spans.append(PayloadSpan(path,node.kind,position,32,node.engine,width,None,None))
            position += 32
        elif isinstance(node, codec._Struct):
            for name, child in node.fields:visit(child,path+'.'+name if path else name)
        elif isinstance(node, codec._Tuple):
            for i, child in enumerate(node.items):visit(child,f'{path}[{i}]')
        elif isinstance(node, codec._Vector):
            spans.append(PayloadSpan(path,'length',position,8,None,None,node.minimum,node.maximum))
            position += 8
            for i in range(node.maximum):
                visit(node.item[i] if type(node.item) is tuple else node.item,f'{path}[{i}]')
        elif node is not None:
            raise ValueError('unsupported retained grammar node')
    visit(codec._layout(dimensions))
    layout = tuple(spans)
    if (position != PAYLOAD_BYTES or len(layout) != 485
            or sum(s.kind == 'length' for s in layout) != 119
            or sum(s.kind == 'length' and s.minimum != s.maximum for s in layout) != 101
            or sum(s.kind == 'scalar' and s.engine == 'pallas' for s in layout) != 169
            or sum(s.kind == 'scalar' and s.engine == 'vesta' for s in layout) != 119
            or sum(s.kind == 'commitment' and s.engine == 'pallas' for s in layout) != 43
            or sum(s.kind == 'commitment' and s.engine == 'vesta' for s in layout) != 35
            or any(a.start+a.size != b.start for a,b in zip(layout,layout[1:]))):
        raise ValueError('retained maximum-width span partition differs')
    return layout


def tape_anchors(layout):
    """Pure sorted prefix and zn-width constants; no proof values become anchors."""
    rows = []
    for span in layout:
        if span.kind == 'length':
            for byte, value in enumerate(span.maximum.to_bytes(8,'little')):
                rows.append((span.start+byte,value,'length',span.path))
        elif span.width_bits is not None:
            if not span.path.startswith('zn[') or span.width_bits % 8:
                raise ValueError('unsupported non-byte-aligned retained scalar bound')
            for byte in range(span.width_bits//8,32):
                rows.append((span.start+byte,0,'zn-width',span.path))
    result = tuple(sorted(rows))
    if (len(result) != 1383 or len({r[0] for r in result}) != 1383
            or sum(r[2]=='length' for r in result) != 952
            or sum(r[2]=='zn-width' for r in result) != 431
            or {r[1] for r in result} != {0,2,3,14,15,17,19,20}):
        raise ValueError('retained constant union must be952 prefix+431 width BYTEs')
    return result


def _tape_order(layout):
    anchors = tape_anchors(layout)
    fixed = {row[0] for row in anchors}
    return tuple(row[0] for row in anchors)+tuple(i for i in range(PAYLOAD_BYTES) if i not in fixed)


def _scalar_spans(layout, index):
    return tuple(s for s in layout if s.kind == 'scalar' and s.engine == ENGINES[index])


def _reference(raw_bundle, expected, dimensions, layout):
    container = bind_container(raw_bundle,expected)
    decoded = codec.decode_proof(container.proof,dimensions)
    if tuple((s.path,s.kind,s.start,s.size,s.engine) for s in decoded.spans) != tuple(
            (s.path,s.kind,s.start,s.size,s.engine) for s in layout):
        raise ValueError('reference is not the supported retained maximum-width serialization')
    for offset,value,_,_ in tape_anchors(layout):
        if container.proof[offset] != value:
            raise ValueError('reference prefix/zn widths disagree with verifier-owned profile')
    return container.proof


def _encoding_template():
    bounds = (BASE,)*9+(256,)*32+tuple(bound for _,width in CROSSINGS
        for bound in (1<<width,1<<(8-width)))
    leaves = [('conv_split',(width,),(9+byte,41+2*i,42+2*i))
        for i,(byte,width) in enumerate(CROSSINGS)]
    for limb in range(9):
        start,end = 29*limb,min(29*limb+29,256)
        wires,widths = [limb],[]
        for byte in range(start//8,(end+7)//8):
            low,high = max(start,8*byte),min(end,8*byte+8)
            if low == 8*byte and high == 8*byte+8:word = 9+byte
            else:
                crossing = next(i for i,(b,_) in enumerate(CROSSINGS) if b == byte)
                word = 41+2*crossing+(low != 8*byte)
            wires.append(word);widths.append(high-low)
        leaves.append(('conv_reconstruct',tuple(widths),tuple(wires)))
    return bounds,tuple(leaves)


def _pure_component(index, layout, values, reference):
    """Unsigned witness and mathematical relation only; no Program or Script."""
    if index == 0:
        anchors = tape_anchors(layout)
        truth = tuple(values[offset] < 256 and values[offset] == expected for offset,expected,_,_ in anchors)
        truth += tuple(values[offset] < 256 for offset in _tape_order(layout)[1383:])
        return tuple(values),truth
    spans = _scalar_spans(layout,index)
    bounds,template = _encoding_template()
    modulus = Q if index == 1 else P
    assigned,arithmetic,canonical = [],[],[]
    for span in spans:
        claimed = tuple(values[span.start:span.start+32])
        # Invalid signed BYTE diagnostics use reference internal auxiliaries,
        # preserving the SAME raw u32 at the actual tape/encoder BYTE port.
        raw = bytes(claimed) if all(value < 256 for value in claimed) else reference[span.start:span.start+32]
        limbs_,_,pieces = encoding_values(raw)
        field_values = limbs_+claimed+pieces
        assigned.extend(field_values)
        for kind,args,wires in template:
            arithmetic.append(convolution_native(modulus,kind,args,tuple(field_values[i] for i in wires)))
        canonical.append(sum(digit<<(29*i) for i,digit in enumerate(limbs_)) < modulus)
    return tuple(assigned),tuple(arithmetic+canonical)


def profile_values(profile, reference, layout):
    """Pure closed recipes. This function is not a source/map importer."""
    if type(profile) is not str or profile not in PROFILES or type(reference) is not bytes or len(reference) != PAYLOAD_BYTES:
        raise ValueError('closed profile and exact retained reference payload required')
    by_path = {s.path:s for s in layout}
    values,changed = list(reference),()
    def replace(span, raw):
        nonlocal changed
        values[span.start:span.start+span.size] = raw
        changed = tuple(range(span.start,span.start+span.size))
    p_eval = by_path['snark_primary.eval_W'];v_eval = by_path['snark_secondary.eval_W']
    if profile.startswith('coherent-'):
        span,modulus = (p_eval,Q) if profile == 'coherent-p-eval' else (v_eval,P)
        value = int.from_bytes(reference[span.start:span.start+32],'little')+1
        if value >= modulus:raise ValueError('unsupported coherent reference boundary')
        replace(span,value.to_bytes(32,'little'))
    elif profile in ('p-mod','p-mod1','v-mod','v-mod1'):
        primary = profile.startswith('p-')
        replace(p_eval if primary else v_eval,((Q if primary else P)+int(profile.endswith('1'))).to_bytes(32,'little'))
    elif profile == 'zn0-width':
        replace(by_path['zn[0]'],(1<<32).to_bytes(32,'little'))
    elif profile in ('p-outer-count','v-outer-count'):
        owner = 'primary' if profile.startswith('p-') else 'secondary'
        replace(by_path[f'snark_{owner}.sc_proof_outer.compressed_polys[0].coeffs_except_linear_term'],(2).to_bytes(8,'little'))
    elif profile in ('opaque-p','opaque-v'):
        engine = 'pallas' if profile == 'opaque-p' else 'vesta'
        replace(next(s for s in layout if s.kind == 'commitment' and s.engine == engine),b'\xff'*32)
    elif profile in ('byte-256','byte-max'):
        values[p_eval.start] = 256 if profile == 'byte-256' else 0xffffffff
        changed = (p_eval.start,)
    return tuple(values),changed


def _controls(index,layout):
    if index:
        return tuple(range(16))+(16*COUNTS[index],)
    seen,ordinals = set(),[]
    for ordinal,(_,value,_,_) in enumerate(tape_anchors(layout)):
        if value not in seen:seen.add(value);ordinals.append(ordinal)
    return tuple(ordinals)+(1383,)


def _selection(profile,layout,truths,changed):
    if profile in (None,'honest'):
        return tuple(tuple(range(len(truth))) for truth in truths)
    selected = [set(_controls(i,layout)) | {j for j,value in enumerate(truths[i]) if value is False or value is None} for i in range(3)]
    tape_ordinal = {offset:i for i,offset in enumerate(_tape_order(layout))}
    selected[0].update(tape_ordinal[offset] for offset in changed)
    altered = set(changed)
    for index in (1,2):
        for scalar,span in enumerate(_scalar_spans(layout,index)):
            if altered.intersection(range(span.start,span.start+32)):
                selected[index].update(range(16*scalar,16*scalar+16))
                selected[index].add(16*COUNTS[index]+scalar)
    if sum(map(len,selected)) > TARGET_CAP:
        raise ValueError('all-failure/affected/control selections exceed128 TOTAL; no counterexample omitted')
    return tuple(tuple(sorted(rows)) for rows in selected)


def _byte_occurrences(template):
    return tuple(next((i,formal) for i,(_,_,wires) in enumerate(template)
        for formal,word in enumerate(wires) if word == 9+byte) for byte in range(32))


def _scalar_map(layout,index):
    spans = _scalar_spans(layout,index)
    _,template = _encoding_template()
    byte_occurrences = _byte_occurrences(template)
    rows = []
    for scalar,span in enumerate(spans):
        base,leaf = 55*scalar,16*scalar
        links = [dict(word_index=base+i,source_ordinal=leaf+7+i,source_occurrence=0,
            target_ordinal=16*len(spans)+scalar,target_occurrence=i) for i in range(9)]
        for part in range(14):
            word = 41+part
            target = next((j,slot) for j,(_,_,wires) in enumerate(template[7:],7)
                for slot,wire in enumerate(wires) if wire == word)
            links.append(dict(word_index=base+word,source_ordinal=leaf+part//2,source_occurrence=1+part%2,
                target_ordinal=leaf+target[0],target_occurrence=target[1]))
        rows.append(dict(scalar_index=scalar,path=span.path,proof_start=span.start,
            container_start=HEADER_BYTES+span.start,width_bits=span.width_bits,
            limb_words=tuple(range(base,base+9)),byte_words=tuple(range(base+9,base+41)),
            split_words=tuple(range(base+41,base+55)),
            byte_occurrences=tuple((leaf+i,formal) for i,formal in byte_occurrences),
            field_valid_ordinal=16*len(spans)+scalar,canonical_links=tuple(links)))
    return dict(schema='bitvm2-nova-proof-scalar-batch-maps/v1',engine=ENGINES[index],
        field_role=ROLES[index],scalar_count=len(spans),scalars=tuple(rows))


def _component_maps(index,layout):
    if index:return _scalar_map(layout,index)
    order = _tape_order(layout)
    ordinals = {offset:i for i,offset in enumerate(order)}
    return dict(schema='bitvm2-nova-proof-payload-tape-maps/v1',
        byte_ordinals=tuple(ordinals[j] for j in range(PAYLOAD_BYTES)),
        anchors=tuple(dict(payload_offset=offset,container_offset=HEADER_BYTES+offset,
            word_index=offset,ordinal=i,expected=value,reason=reason,path=path)
            for i,(offset,value,reason,path) in enumerate(tape_anchors(layout))),
        controls=_controls(0,layout),length_prefixes=119,variable_prefixes_fixed_at_max=101,
        width_zero_bytes=431,payload_bytes=PAYLOAD_BYTES)


def _global_ids(index,layout,program):
    if index == 0:return tuple(f'proof/container-byte/{HEADER_BYTES+i}' for i in range(PAYLOAD_BYTES))
    spans = _scalar_spans(layout,index)
    result = []
    for scalar,span in enumerate(spans):
        for local,(name,_) in enumerate(program.words[55*scalar:55*scalar+55]):
            if 9 <= local < 41:result.append(f'proof/container-byte/{HEADER_BYTES+span.start+local-9}')
            else:result.append(f'proof/scalar/{ENGINES[index]}/{scalar}/{name}')
    return tuple(result)


def _build_component(index,layout,reference,context,operation_id):
    _hosted_guard()
    op = _operations(operation_id)[index]
    if index == 0:
        builder = ByteTraceBuilder(ROLES[index],op,context)
        words = tuple(builder.byte(f'payload/byte/{i}',value) for i,value in enumerate(reference))
        for offset,value,_,_ in tape_anchors(layout):builder.check('const',(words[offset],),(value,))
    else:
        builder = ConvolutionTraceBuilder(ROLES[index],op,context)
        for scalar,_ in enumerate(_scalar_spans(layout,index)):
            field = builder.field(f'scalar/{scalar}',0)
            builder._bytes(f'scalar/{scalar}/encoding',field)
    program,_ = builder.finish()
    spec = GraphSpec.from_program(program)
    expected = ((12664,1383,0,12664),(9295,2704,169,2873),(6545,1904,119,2023))[index]
    if (len(program.words),len(program.constraints),len(program.fields),len(spec.leaves)) != expected:
        raise ValueError('proof-payload component differs from the fixed legacy census')
    maps = _component_maps(index,layout)
    ids = _global_ids(index,layout,program)
    if len(ids) != len(spec.words) or len(set(ids)) != len(ids) or any(not ID.fullmatch(word) for word in ids):
        raise ValueError('injective physical BYTE and role-private scalar maps required')
    if index == 0:
        for offset,ordinal in enumerate(maps['byte_ordinals']):
            if spec.leaves[ordinal].wires != (offset,):raise ValueError('actual tape byte-to-leaf order differs')
    else:
        for row in maps['scalars']:
            for word,(ordinal,formal) in zip(row['byte_words'],row['byte_occurrences'],strict=True):
                if spec.leaves[ordinal].wires[formal] != word:raise ValueError('actual scalar BYTE opener differs')
            for link in row['canonical_links']:
                if (spec.leaves[link['source_ordinal']].wires[link['source_occurrence']] != link['word_index']
                        or spec.leaves[link['target_ordinal']].wires[link['target_occurrence']] != link['word_index']):
                    raise ValueError('actual canonical reconstruction/split link differs')
    raw_maps = _canonical(maps);maps_sha = sha256(raw_maps).hexdigest()
    meta = dict(schema='bitvm2-nova-proof-payload-component/v1',index=index,name=NAMES[index],
        context=context.hex(),field_role=ROLES[index],operation_id=op,
        program_sha256=program.digest().hex(),catalogue_id=spec.digest().hex(),source_maps_sha256=maps_sha,
        words=expected[0],arithmetic_constraints=expected[1],canonical_fields=expected[2],leaves=expected[3],
        profile='retained maximum-width serialization; not a generic decoder',source_authority=False)
    raw_meta = _canonical(meta)
    descriptor = ComponentDescriptor(index,NAMES[index],ROLES[index],op,
        'ByteProgram.digest (byte-v1)' if index == 0 else 'ConvolutionProgram.digest (fixed-trace/v2)',
        *expected,program.digest().hex(),spec.digest().hex(),sha256(COMPONENT_DOMAIN+raw_meta).hexdigest(),
        maps_sha,sha256(_canonical(ids)).hexdigest())
    return program,spec,ids,raw_maps,raw_meta,descriptor


def _outer(layout,components,context,operation_id):
    anchors = tape_anchors(layout)
    tape_ord = {offset:i for i,offset in enumerate(_tape_order(layout))}
    joins = []
    for index in (1,2):
        for row in _scalar_map(layout,index)['scalars']:
            joins.append(dict(component=index,scalar_index=row['scalar_index'],path=row['path'],
                proof_start=row['proof_start'],container_start=row['container_start'],
                tape_words=tuple(range(row['proof_start'],row['proof_start']+32)),
                tape_ordinals=tuple(tape_ord[j] for j in range(row['proof_start'],row['proof_start']+32)),
                encoder_words=row['byte_words'],encoder_occurrences=row['byte_occurrences'],
                field_valid_ordinal=row['field_valid_ordinal'],canonical_links=row['canonical_links']))
    maps = dict(schema=MAP_SCHEMA,layout=tuple(span.json() for span in layout),
        components=tuple(d.json() for d in components),scalar_joins=tuple(joins),
        byte_joins=9216,canonical_internal_links=6624,
        local_words=28504,unique_global_words=19288,cached_signature_reuses=9216,
        leaves=17560,container_offset_bias=HEADER_BYTES)
    raw_maps = _canonical(maps)
    meta = dict(schema=SCHEMA,context=context.hex(),operation_id=operation_id,
        expected_policy_sha256=POLICY_PIN,verifier_dimensions_sha256=DIMENSIONS_PIN,
        payload_bytes=12664,container_bytes=13220,header_bytes_excluded=556,
        component_order=NAMES,components=tuple(d.json() for d in components),
        source_maps_sha256=sha256(raw_maps).hexdigest(),profiles=PROFILES,
        scalar_counts=dict(pallas=169,vesta=119),opaque_point_counts=dict(pallas=43,vesta=35),
        length_prefixes=119,fixed_prefixes=18,variable_prefixes_fixed_at_max=101,
        prefix_constant_bytes=952,width_zero_bytes=431,constant_bytes=len(anchors),
        local_words=28504,unique_global_words=19288,cached_signature_reuses=9216,leaves=17560,
        relation='asserted retained maximum-width payload BYTEs -> canonical scalar encodings and fixed lengths/zn widths',
        scope='opaque point BYTEs; no asserted blob SHA/EOF/header, transcript, proof or production origins')
    meta.update({flag:False for flag in FALSE_FLAGS})
    raw_meta = _canonical(meta)
    if len(raw_maps) > MAP_CAP or len(raw_meta) > MANIFEST_CAP:
        raise ValueError('proof-payload source exceeds unchanged bounded sidecar caps')
    return raw_maps,raw_meta


@dataclass(frozen=True,init=False)
class PayloadComponentBinding:
    descriptor: ComponentDescriptor
    program: object
    spec: object
    global_ids: tuple[str,...]
    values: tuple[int,...]
    truth: tuple[bool,...]
    selected_ordinals: tuple[int,...]
    _source_maps: bytes
    _source_manifest: bytes
    _program_manifest: None

    def __init__(self,*args,**kwargs):raise TypeError('stream from the sealed payload binding')
    assignment = property(lambda self:dict(zip((w for w,_ in self.spec.words),self.values,strict=True)))
    index = property(lambda self:self.descriptor.index)
    name = property(lambda self:self.descriptor.name)
    child_source_maps = property(lambda self:json.loads(self._source_maps))
    child_source_manifest = property(lambda self:json.loads(self._source_manifest))


@dataclass(frozen=True,init=False)
class ProofPayloadBinding:
    plan: object
    profile: str | None
    values: tuple[int,...]
    changed_offsets: tuple[int,...]
    truth: tuple[tuple[bool,...],...]
    selected_ordinals: tuple[tuple[int,...],...]

    def __init__(self,*args,**kwargs):raise TypeError('bind through the sealed payload source')
    asserted_payload = property(lambda self:bytes(self.values) if all(v<256 for v in self.values) else None)
    execution_mode = property(lambda self:'all' if self.profile in (None,'honest') else 'selected')

    def iter_components(self):
        _hosted_guard()
        self.plan._validate()
        return self._iterate()

    def _iterate(self):
        for index in range(3):
            program,spec,ids,maps,meta,descriptor = _build_component(index,self.plan.layout,
                self.plan.reference_payload,self.plan.context,self.plan.operation_id)
            if descriptor != self.plan.components[index]:raise ValueError('fresh payload component changed its sealed identity')
            values,truth = _pure_component(index,self.plan.layout,self.values,self.plan.reference_payload)
            if truth != self.truth[index]:raise ValueError('fresh mathematical payload truth differs')
            item = _make(PayloadComponentBinding,descriptor=descriptor,program=program,spec=spec,
                global_ids=ids,values=values,truth=truth,selected_ordinals=self.selected_ordinals[index],
                _source_maps=maps,_source_manifest=meta,_program_manifest=None)
            del program,spec,ids,maps,meta,descriptor,values,truth
            yield item
            del item  # Caller must also release its yielded aliases before advancing.


@dataclass(frozen=True,init=False)
class ProofPayloadOrigins:
    expected: ExpectedBundle
    dimensions: codec.VerifierDimensions
    context: bytes
    operation_id: str
    reference_payload: bytes
    layout: tuple[PayloadSpan,...]
    components: tuple[ComponentDescriptor,...]
    source_sha256: bytes
    source_maps_sha256: bytes
    _raw_bundle: bytes
    _maps: bytes
    _manifest: bytes

    def __init__(self,*args,**kwargs):raise TypeError('use build_proof_payload_origins; no graph/map/receipt admission')
    source_maps = property(lambda self:json.loads(self._maps))
    manifest = property(lambda self:json.loads(self._manifest))

    def _validate(self):
        _parameters(self._raw_bundle,self.expected,self.dimensions,self.context,self.operation_id)
        if (type(self.reference_payload) is not bytes or len(self.reference_payload) != PAYLOAD_BYTES
                or self._raw_bundle[HEADER_BYTES:] != self.reference_payload
                or sha256(self.reference_payload).digest() != self.expected.proof_sha256):
            raise ValueError('owned admitted reference snapshot differs from its independent policy')
        if retained_layout(self.dimensions) != self.layout:raise ValueError('sealed verifier-owned layout changed')
        maps,meta = _outer(self.layout,self.components,self.context,self.operation_id)
        if (maps != self._maps or meta != self._manifest
                or sha256(maps).digest() != self.source_maps_sha256
                or sha256(DOMAIN+meta).digest() != self.source_sha256):
            raise ValueError('actual payload layout/component/source snapshot differs')

    def _bind(self,values,profile,changed):
        if (type(values) is not tuple or len(values) != PAYLOAD_BYTES
                or any(type(v) is not int or not 0 <= v < 1<<32 for v in values)):
            raise ValueError('exact unsigned32 payload assertions required')
        truths = tuple(_pure_component(i,self.layout,values,self.reference_payload)[1] for i in range(3))
        selected = _selection(profile,self.layout,truths,changed)
        return _make(ProofPayloadBinding,plan=self,profile=profile,values=values,changed_offsets=changed,
            truth=truths,selected_ordinals=selected)

    def bind(self,claimed_payload):
        _hosted_guard();self._validate()
        if type(claimed_payload) is not bytes or len(claimed_payload) != PAYLOAD_BYTES:
            raise ValueError('exact immutable12664-byte payload assertion required')
        return self._bind(tuple(claimed_payload),None,tuple(i for i,(a,b) in enumerate(zip(
            claimed_payload,self.reference_payload,strict=True)) if a != b))

    def bind_profile(self,profile):
        _hosted_guard();self._validate()
        values,changed = profile_values(profile,self.reference_payload,self.layout)
        return self._bind(values,profile,changed)

    def summary(self):
        result = dict(schema=SCHEMA,source_sha256=self.source_sha256.hex(),
            source_maps_sha256=self.source_maps_sha256.hex(),components=3,
            payload_bytes=12664,local_words=28504,unique_global_words=19288,
            leaves=17560,byte_joins=9216,canonical_internal_links=6624,
            profile='retained maximum-width serialization only')
        result.update({flag:False for flag in FALSE_FLAGS})
        return result


def build_proof_payload_origins(raw_bundle,expected,dimensions,*,context,operation_id='proof-payload-origins'):
    _hosted_guard()
    _parameters(raw_bundle,expected,dimensions,context,operation_id)
    layout = retained_layout(dimensions)
    reference = _reference(raw_bundle,expected,dimensions,layout)
    descriptors = []
    for index in range(3):
        built = _build_component(index,layout,reference,context,operation_id)
        descriptors.append(built[-1]);del built
    components = tuple(descriptors)
    maps,meta = _outer(layout,components,context,operation_id)
    return _make(ProofPayloadOrigins,expected=expected,dimensions=dimensions,context=context,
        operation_id=operation_id,reference_payload=reference,layout=layout,components=components,
        source_sha256=sha256(DOMAIN+meta).digest(),source_maps_sha256=sha256(maps).digest(),
        _raw_bundle=raw_bundle,_maps=maps,_manifest=meta)
