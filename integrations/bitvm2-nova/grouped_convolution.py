"""Opt-in conjunctions of frozen convolution AB rows.

No row arithmetic is reimplemented by the Script compiler: each row copies its
formal inputs above an untouched prefix and invokes the exact legacy conv_ab
body. Every row result is BOOLANDed, including after a previous false result.
The old convolution/default compilers and authenticated word formats are intact.
"""
from dataclasses import dataclass
from functools import lru_cache
from hashlib import sha256
import json
import os
import re
import sys

from convolution import AB_BOUND, BYTE, ConvolutionConstraint, compile_convolution_predicate
from script import OPS, P, Q, num, push
from trace import MAX_CONSTRAINTS, Program, ROLES, _field
from wots_graph import GraphSpec, Leaf, expansion_script

KIND = 'conv_ab_all'
PATTERNS = ((1,2,3,4),(4,4,4,4),(3,2,1))
BODY_CAP = 20000
COMPILER = 'grouped-convolution-v1'
PROGRAM_DOMAIN = b'BITVM2-NOVA/GROUPED-CONVOLUTION-PROGRAM/v1\x00'
PROJECTION_SCHEMA = 'bitvm2-nova-grouped-convolution-projection/v1'
CONTEXT = sha256(b'BITVM2-NOVA/GROUPED-CONVOLUTION-CONFORMANCE/v1').digest()
OPERATION_ID = 'benchmark/grouped-convolution/v1'
SOURCE_SCHEMA = 'bitvm2-nova-grouped-convolution-source/v1'
MAPS_SCHEMA = 'bitvm2-nova-grouped-convolution-source-maps/v1'
SOURCE_DOMAIN = b'BITVM2-NOVA/GROUPED-CONVOLUTION-SOURCE/v1\x00'
FIXTURES = ('mul-distinct','mul-equal-distinct','square','point','point-inactive')
PROFILES = ('mul-distinct','mul-equal-distinct','square','point',
    'row-leading-0','row-leading-1','row-leading-2','row-leading-3',
    'row-middle-0','row-middle-1','row-middle-2','row-middle-3',
    'row-trailing-0','row-trailing-1','row-trailing-2',
    'cancel-equal','cancel-square','inactive-ab','byte-256','subtotal-max')
PROFILE_FIXTURES = ('mul-distinct','mul-equal-distinct','square','point')+('mul-distinct',)*11+(
    'mul-equal-distinct','square','point-inactive','mul-distinct','mul-distinct')
FALSE_FLAGS = ('complete_verifier','proof_verified','nova_transcript_bound',
    'production_assertion_binding','bitcoin_transaction_graph','taproot_coverage_verified')
_TOKEN = object()


def _hosted_guard():
    if os.environ.get('GITHUB_ACTIONS') != 'true' or not sys.platform.startswith('linux'):
        raise RuntimeError('grouped convolution graph construction requires hosted GitHub Linux')


def _canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':')).encode('ascii')


def _bounds(p,kind,argument):
    # Validate BEFORE the private cache: True aliases1 inside tuple keys.
    if (type(p) is not int or p not in (P,Q) or type(kind) is not str or kind != KIND
            or type(argument) is not tuple or any(type(n) is not int for n in argument)
            or argument not in PATTERNS):
        raise ValueError('closed grouped-AB field/kind/row-count pattern required')
    return tuple(bound for n in argument for bound in (BYTE,BYTE)*n+(AB_BOUND,))


def grouped_native(p,kind,argument,values):
    """Integer reference; false outside bounds is NOT a bare-body rejection."""
    bounds = _bounds(p,kind,argument)
    if (type(values) not in (tuple,list) or len(values) != len(bounds)
            or any(type(v) is not int or not 0 <= v < b for v,b in zip(values,bounds,strict=True))):
        return False
    offset,results = 0,[]
    for n in argument:
        row = values[offset:offset+2*n+1]
        results.append(row[-1] == sum(row[2*i]*row[2*i+1] for i in range(n)))
        offset += 2*n+1
    return all(results)


def row_frames(argument):
    _bounds(P,KIND,argument)
    total = sum(2*n+1 for n in argument)
    offset,rows = 0,[]
    for n in argument:
        length = 2*n+1
        # F originals, one accumulated Boolean, then j copied row operands.
        # Original(O+j) is at depth F+1+j-1-(O+j) = F-O.
        rows.append((offset,length,total-offset))
        offset += length
    return tuple(rows)


def compile_grouped_predicate(p,kind=KIND,argument=()):
    _bounds(p,kind,argument)
    return _compile(p,argument)


@lru_cache(maxsize=6)
def _compile(p,argument):
    frames = row_frames(argument)
    formal = sum(length for _,length,_ in frames)
    code = bytearray(push(num(1)))
    for n,(_,length,depth) in zip(argument,frames,strict=True):
        for _ in range(length):
            code.extend(push(num(depth)));code.append(OPS['PICK'])
        # The frozen body consumes ONLY its copied row, returns one Boolean,
        # never reaches below it, and balances its own alt-stack traffic.
        code.extend(compile_convolution_predicate(p,'conv_ab',(n,)))
        code.append(OPS['BOOLAND'])
    code.append(OPS['TOALTSTACK'])
    code.extend([OPS['2DROP']]*(formal//2))
    if formal % 2:code.append(OPS['DROP'])
    code.append(OPS['FROMALTSTACK'])
    if len(code) > BODY_CAP:
        raise ValueError('grouped AB raw body exceeds unchanged20000-byte catalogue cap')
    return bytes(code)


@dataclass(frozen=True)
class Cell:
    column: int
    block: int
    pairs: tuple[tuple[int,int],...]

    def __post_init__(self):
        if (type(self.column) is not int or not 0 <= self.column <= 62
                or type(self.block) is not int or not 0 <= self.block <= 7
                or type(self.pairs) is not tuple
                or any(type(pair) is not tuple or len(pair) != 2
                       or any(type(index) is not int or not 0 <= index < 32 for index in pair)
                       for pair in self.pairs)):
            raise ValueError('strict public AB cell metadata required')
        start=max(0,self.column-31)+4*self.block
        expected=tuple((i,self.column-i) for i in range(start,min(31,self.column,start+3)+1))
        if not expected or self.pairs != expected:
            raise ValueError('AB cell is not an exact original diagonal/block')

    @property
    def key(self):return self.column,self.block


def cells():
    result = []
    for k in range(63):
        lower = max(0,k-31)
        for block,start in enumerate(range(lower,min(31,k)+1,4)):
            result.append(Cell(k,block,tuple((i,k-i) for i in range(start,min(31,k,start+3)+1))))
    return tuple(result)


def groups():
    old = cells()
    result = []
    for low,high in ((0,31),(32,62)):
        for block in range(8):
            strip = tuple(cell for cell in old if low <= cell.column <= high and cell.block == block)
            for start in range(0,len(strip),4):result.append(strip[start:start+4])
    flat = tuple(cell.key for group in result for cell in group)
    if (len(old) != 280 or len(result) != 72 or len(flat) != len(set(flat))
            or set(flat) != {cell.key for cell in old}
            or sum(len(cell.pairs) for cell in old) != 1024
            or any(tuple(len(cell.pairs) for cell in group) not in PATTERNS for group in result)):
        raise ValueError('closed72-group/280-subtotal/1024-product partition differs')
    return tuple(result)


def subtotal_max_cell():
    """The late row of the first complete four-row group, fixed by topology."""
    return next(group for group in groups()
                if tuple(len(cell.pairs) for cell in group)==(4,4,4,4))[-1]


def group_occurrences(group,*,square=False):
    if (type(square) is not bool or type(group) is not tuple
            or any(type(cell) is not Cell for cell in group) or group not in groups()):
        raise ValueError('an exact closed public group and Boolean squaring profile required')
    result = []
    for cell in group:
        result.extend(word for i,j in cell.pairs for word in (('a',i),('a' if square else 'b',j)))
        result.append(('ab',cell.column,cell.block))
    return tuple(result)


def aliases(occurrences):
    if (type(occurrences) is not tuple or not occurrences
            or any(type(word) is not tuple or not word
                   or any(type(part) not in (str,int) for part in word) for word in occurrences)):
        raise ValueError('strict tuple word identities required')
    unique = {}
    return tuple(unique.setdefault(word,len(unique)) for word in occurrences)


def templates():
    result = set()
    for square in (False,True):
        for group in groups():
            result.add((tuple(len(cell.pairs) for cell in group),aliases(group_occurrences(group,square=square))))
    if len(result) != 10:raise ValueError('closed ordinary/squaring alias union must contain10 layouts')
    return tuple(sorted(result))


def bounded_body_inventory():
    """26 bounded hashes only (3raw+10expanded for each p); never a graph/test execution."""
    rows = []
    for modulus in (P,Q):
        for argument in PATTERNS:
            body = compile_grouped_predicate(modulus,KIND,argument)
            rows.append(dict(modulus=str(modulus),argument=argument,aliases=None,
                bytes=len(body),sha256=sha256(body).hexdigest()))
        for argument,pattern in templates():
            body = expansion_script(pattern)+compile_grouped_predicate(modulus,KIND,argument)
            if len(body) > BODY_CAP:raise ValueError('grouped AB alias-expanded body exceeds unchanged20000-byte cap')
            rows.append(dict(modulus=str(modulus),argument=argument,aliases=pattern,
                bytes=len(body),sha256=sha256(body).hexdigest()))
    return tuple(rows)


class GroupedConstraint(ConvolutionConstraint):
    def native(self,values,p):
        if self.kind == KIND:
            return grouped_native(p,self.kind,self.argument,[values[word] for word in self.wires])
        return super().native(values,p)


class GroupedProgram(Program):
    """An explicitly versioned program; never an old-kind compiler proxy."""
    def digest(self):
        return sha256(PROGRAM_DOMAIN+Program.digest(self)).digest()

    def bind(self,values):
        raise ValueError('grouped-convolution-v1 is isolated GraphSpec-only; fixed-claim binding is unsupported')


@dataclass(frozen=True)
class Projection:
    """Each old leaf maps to one new leaf and its row (None for unchanged)."""
    old_to_new: tuple[tuple[int,int|None],...]
    new_to_old: tuple[tuple[int,...],...]
    multiplication_prefixes: tuple[str,...]
    group_records: tuple[tuple[str,int,tuple[int,...]],...]

    def json(self):
        return {'schema':PROJECTION_SCHEMA,'old_to_new':self.old_to_new,
                'new_to_old':self.new_to_old,'multiplication_prefixes':self.multiplication_prefixes,
                'groups':self.group_records}


_AB_NAME = re.compile(r'(.+)/ab/(0|[1-9][0-9]*)/(0|[1-9][0-9]*)\Z')


def _transform(program,baseline_spec):
    """Private hosted compiler stage; public sources create both inputs fresh.

    The old arithmetic remains declarative: a group replaces its first old row,
    even when later row words were declared farther along the old builder. The
    complete word catalogue is fixed before authentication in either version.
    """
    _hosted_guard()
    from convolution import ConvolutionProgram
    if type(program) is not ConvolutionProgram or type(baseline_spec) is not GraphSpec:
        raise ValueError('fresh legacy convolution program and catalogue required')
    if (baseline_spec.program_sha256 != program.digest().hex()
            or baseline_spec.words != program.words
            or baseline_spec.original_constraints != len(program.constraints)
            or baseline_spec.context != program.context.hex()
            or baseline_spec.field_role != program.field_role
            or baseline_spec.operation_id != program.operation_id
            or len(baseline_spec.leaves) != len(program.constraints)+len(program.fields)):
        raise ValueError('legacy program/catalogue identity or coverage differs')
    bounds = dict(program.words)
    indices = {word:index for index,(word,_) in enumerate(program.words)}
    if len(bounds) != len(program.words):raise ValueError('duplicate original words')
    batches = {}
    for ordinal,constraint in enumerate(program.constraints):
        leaf = baseline_spec.leaves[ordinal]
        if (leaf.kind,leaf.argument,leaf.wires) != (constraint.kind,constraint.argument,
                tuple(indices[word] for word in constraint.wires)):
            raise ValueError('legacy arithmetic leaf projection differs')
        if constraint.kind != 'conv_ab':continue
        match = _AB_NAME.fullmatch(constraint.wires[-1])
        if not match:raise ValueError('legacy AB subtotal identity differs')
        prefix,k,r = match.group(1),int(match.group(2)),int(match.group(3))
        batch = batches.setdefault(prefix,{})
        if (k,r) in batch:raise ValueError('duplicate original AB cell')
        batch[k,r] = (ordinal,constraint)
    if not batches:raise ValueError('no complete multiplication AB batch')
    replacements,removed = {},set()
    for prefix,batch in batches.items():
        if set(batch) != {cell.key for cell in cells()}:
            raise ValueError('incomplete original280-row AB batch')
        operands = ({},{})
        outputs = set()
        for cell in cells():
            ordinal,constraint = batch[cell.key]
            if (constraint.argument != (len(cell.pairs),)
                    or len(constraint.wires) != 2*len(cell.pairs)+1
                    or constraint.wires[-1] != f'{prefix}/ab/{cell.column}/{cell.block}'
                    or bounds[constraint.wires[-1]] != AB_BOUND):
                raise ValueError('legacy AB row framing/output bound differs')
            outputs.add(constraint.wires[-1])
            for pair,(i,j) in enumerate(cell.pairs):
                for side,byte_index in ((0,i),(1,j)):
                    word = constraint.wires[2*pair+side]
                    if bounds[word] != BYTE or operands[side].setdefault(byte_index,word) != word:
                        raise ValueError('legacy AB byte index/identity differs')
        left,right = tuple(operands[0][i] for i in range(32)),tuple(operands[1][i] for i in range(32))
        if (len(outputs) != 280 or len(set(left)) != 32 or len(set(right)) != 32
                or (left != right and set(left)&set(right))):
            raise ValueError('AB operands must preserve distinct bytes or exact squaring aliases')
        for group_index,group in enumerate(groups()):
            old = tuple(batch[cell.key][0] for cell in group)
            constraints = tuple(batch[cell.key][1] for cell in group)
            argument = tuple(len(cell.pairs) for cell in group)
            wires = tuple(word for constraint in constraints for word in constraint.wires)
            if tuple(bounds[word] for word in wires) != _bounds(program.p,KIND,argument):
                raise ValueError('grouped formal slot bounds differ')
            anchor = min(old)
            replacements[anchor] = (GroupedConstraint(KIND,wires,argument),old,prefix,group_index)
            removed.update(old)
    constraints,new_to_old,old_to_new,records = [],[],[None]*len(baseline_spec.leaves),[]
    for ordinal,constraint in enumerate(program.constraints):
        if ordinal in replacements:
            grouped,old,prefix,group_index = replacements[ordinal]
            new = len(constraints);constraints.append(grouped);new_to_old.append(old)
            records.append((prefix,group_index,old))
            for row,previous in enumerate(old):old_to_new[previous]=(new,row)
        elif ordinal not in removed:
            new = len(constraints);constraints.append(constraint);new_to_old.append((ordinal,))
            old_to_new[ordinal]=(new,None)
    if not 0 < len(constraints) <= MAX_CONSTRAINTS:raise ValueError('grouped program cap differs')
    grouped = GroupedProgram(program.field_role,program.operation_id,program.context,
                             program.words,program.fields,tuple(constraints))
    leaves,bodies = [],{}
    old_bodies = dict(baseline_spec.bodies)
    for new,constraint in enumerate(grouped.constraints):
        old = new_to_old[new]
        if constraint.kind == KIND:
            occurrences = tuple(indices[word] for word in constraint.wires)
            body = expansion_script(occurrences)+compile_grouped_predicate(program.p,KIND,constraint.argument)
            if len(body)>BODY_CAP:raise ValueError('expanded grouped body exceeds unchanged cap')
            digest = sha256(body).hexdigest();bodies[digest]=body.hex()
            leaves.append(Leaf(KIND,constraint.argument,occurrences,digest))
        else:
            leaf = baseline_spec.leaves[old[0]]
            bodies[leaf.body_sha256]=old_bodies[leaf.body_sha256];leaves.append(leaf)
    fields=[]
    for field_index,(name,_) in enumerate(program.fields):
        previous = len(program.constraints)+field_index;new=len(leaves)
        old_to_new[previous]=(new,None);new_to_old.append((previous,))
        leaf=baseline_spec.leaves[previous]
        if leaf.kind != 'field_valid':raise ValueError('canonical guard projection differs')
        bodies[leaf.body_sha256]=old_bodies[leaf.body_sha256];leaves.append(leaf);fields.append((name,new))
    if any(item is None for item in old_to_new):raise ValueError('incomplete old leaf projection')
    if set(index for leaf in leaves for index in leaf.wires) != set(range(len(program.words))):
        raise ValueError('grouped word coverage differs')
    spec = GraphSpec(grouped.digest().hex(),program.context.hex(),program.field_role,program.operation_id,
        program.words,tuple(leaves),tuple(sorted(bodies.items())),len(grouped.constraints),tuple(fields))
    projection = Projection(tuple(old_to_new),tuple(new_to_old),tuple(batches),tuple(records))
    return grouped,spec,projection


def _parameters(role,fixture):
    if type(role) is not str or role not in ('pallas_base','vesta_base'):
        raise ValueError('closed Pasta base-field role required')
    if type(fixture) is not str or fixture not in FIXTURES:
        raise ValueError('closed grouped-convolution fixture required')


def _maps(program,baseline,candidate,projection):
    return dict(schema=MAPS_SCHEMA,compiler=COMPILER,
        word_catalogue_sha256=sha256(_canonical(program.words)).hexdigest(),
        baseline_field_leaves=baseline.field_leaves,candidate_field_leaves=candidate.field_leaves,
        old_to_new=projection.old_to_new,new_to_old=projection.new_to_old,
        multiplication_prefixes=projection.multiplication_prefixes,groups=projection.group_records)


def _metadata(role,fixture,program,baseline,candidate,maps):
    return dict(schema=SOURCE_SCHEMA,compiler=COMPILER,context=CONTEXT.hex(),field_role=role,
        modulus=str(ROLES[role]),operation_id=OPERATION_ID+'/'+fixture,fixture=fixture,
        baseline_program_sha256=program.digest().hex(),candidate_program_sha256=candidate.program_sha256,
        baseline_catalogue_id=baseline.digest().hex(),candidate_catalogue_id=candidate.digest().hex(),
        words=len(program.words),baseline_leaves=len(baseline.leaves),candidate_leaves=len(candidate.leaves),
        canonical_fields=len(program.fields),multiplications=len(maps['multiplication_prefixes']),
        source_maps_sha256=sha256(_canonical(maps)).hexdigest(),
        scope='closed-matched-cost-experiment-frozen-legacy-WOTS',
        **{name:False for name in FALSE_FLAGS})


def _truth(program,spec,values):
    """Registry-domain truth; authenticated out-of-range words are false.

    A semantic input VERIFY abort is distinct and represented by None. The
    raw bare conv_ab body also aborts on out-of-range inputs; the frozen WOTS
    decoder handles those words before it reaches that body in this experiment.
    """
    result=[]
    for ordinal,leaf in enumerate(spec.leaves):
        names=tuple(spec.words[index][0] for index in leaf.wires)
        if any(values[word] >= spec.words[index][1]
               for word,index in zip(names,leaf.wires,strict=True)):
            result.append(False);continue
        if leaf.kind == 'field_valid':
            result.append(_field(values[word] for word in names)<program.p);continue
        constraint=program.constraints[ordinal]
        if constraint.kind == 'add' and any(_field(values[word] for word in names[start:start+9])>=program.p
                                            for start in (0,9)):
            result.append(None);continue
        result.append(bool(constraint.native(values,program.p)))
    return tuple(result)


def _selection(spec,truth,changed,complete):
    if complete:return tuple(range(len(spec.leaves)))
    selected={ordinal for ordinal,value in enumerate(truth) if value is not True}
    first={}
    for ordinal,leaf in enumerate(spec.leaves):
        first.setdefault(leaf.kind,ordinal)
        if leaf.kind == 'field_valid' or any(spec.words[index][0] in changed for index in leaf.wires):
            selected.add(ordinal)
    selected.update(first.values())
    return tuple(sorted(selected))


@dataclass(frozen=True,init=False)
class GroupedSource:
    role:str
    fixture:str
    baseline_program:Program
    baseline_spec:GraphSpec
    candidate_program:GroupedProgram
    candidate_spec:GraphSpec
    projection:Projection
    _values:tuple[int,...]
    _maps:bytes
    _metadata:bytes
    source_sha256:str
    source_maps_sha256:str

    def __init__(self,token,role,fixture,program,baseline,candidate_program,candidate,projection,values):
        if token is not _TOKEN:raise TypeError('use build_grouped_source')
        maps=_canonical(_maps(program,baseline,candidate,projection))
        metadata=_canonical(_metadata(role,fixture,program,baseline,candidate,json.loads(maps)))
        for name,value in dict(role=role,fixture=fixture,baseline_program=program,baseline_spec=baseline,
                candidate_program=candidate_program,candidate_spec=candidate,projection=projection,
                _values=tuple(values[word] for word,_ in program.words),_maps=maps,_metadata=metadata,
                source_sha256=sha256(SOURCE_DOMAIN+metadata).hexdigest(),
                source_maps_sha256=sha256(maps).hexdigest()).items():object.__setattr__(self,name,value)

    @property
    def assignment(self):return dict(zip((word for word,_ in self.baseline_program.words),self._values,strict=True))
    @property
    def values(self):return self._values
    @property
    def metadata(self):return json.loads(self._metadata)
    @property
    def source_maps(self):return json.loads(self._maps)

    def _validate(self):
        _parameters(self.role,self.fixture)
        a,b=self.baseline_program,self.candidate_program
        if (a.words != b.words or a.fields != b.fields or a.words != self.baseline_spec.words
                or a.words != self.candidate_spec.words or a.field_role != self.role
                or b.field_role != self.role or a.context != CONTEXT or b.context != CONTEXT
                or a.operation_id != OPERATION_ID+'/'+self.fixture or b.operation_id != a.operation_id
                or self.baseline_spec.program_sha256 != a.digest().hex()
                or self.candidate_spec.program_sha256 != b.digest().hex()
                or _canonical(_maps(a,self.baseline_spec,self.candidate_spec,self.projection)) != self._maps
                or _canonical(_metadata(self.role,self.fixture,a,self.baseline_spec,self.candidate_spec,
                                       json.loads(self._maps))) != self._metadata
                or sha256(self._maps).hexdigest() != self.source_maps_sha256
                or sha256(SOURCE_DOMAIN+self._metadata).hexdigest() != self.source_sha256):
            raise ValueError('sealed grouped source identity changed')

    def bind_profile(self,profile):
        _hosted_guard();self._validate()
        if type(profile) is not str or profile not in PROFILES:
            raise ValueError('closed grouped-convolution profile required')
        profile_index=PROFILES.index(profile)
        if PROFILE_FIXTURES[profile_index] != self.fixture:
            raise ValueError('profile does not belong to source fixture')
        values=self.assignment
        if profile.startswith('row-'):
            pattern=PATTERNS[('leading','middle','trailing').index(profile.split('-')[1])]
            group=next(group for group in groups() if tuple(len(cell.pairs) for cell in group)==pattern)
            cell=group[int(profile[-1])]
            values[f'product/ab/{cell.column}/{cell.block}']+=1
        elif profile in ('cancel-equal','cancel-square'):
            c=257*257-255
            for index in range(9):values[f'product/l{index}']=(c>>(29*index))&((1<<29)-1)
            for index in range(32):values[f'product/c/byte/{index}']=(c>>(8*index))&255
            for boundary in (29,58,87,116,145,174,203):
                index,width=divmod(boundary,8);byte=values[f'product/c/byte/{index}']
                values[f'product/c/split/{index}/lo']=byte&((1<<width)-1)
                values[f'product/c/split/{index}/hi']=byte>>width
            values['product/ab/0/0']=2;values['product/ab/1/0']=1
        elif profile == 'inactive-ab':values['left/x2/ab/0/0']+=1
        elif profile == 'byte-256':values['product/a/byte/0']=256
        elif profile == 'subtotal-max':
            cell=subtotal_max_cell()
            values[f'product/ab/{cell.column}/{cell.block}']=0xffffffff
        if any(type(value) is not int or not 0<=value<=0xffffffff for value in values.values()):
            raise ValueError('profile must preserve full unsigned32-bit assertions')
        changed={word for word,old in self.assignment.items() if old != values[word]}
        baseline_truth=_truth(self.baseline_program,self.baseline_spec,values)
        candidate_truth=_truth(self.candidate_program,self.candidate_spec,values)
        complete=profile_index<4
        baseline_selected=_selection(self.baseline_spec,baseline_truth,changed,complete)
        candidate_selected=_selection(self.candidate_spec,candidate_truth,changed,complete)
        if not complete and len(baseline_selected)+len(candidate_selected)>128:
            raise ValueError('closed target exceeds unchanged128-leaf combined selection limit')
        return GroupedBinding(_TOKEN,self,profile,tuple(values[word] for word,_ in self.baseline_program.words),
            baseline_truth,candidate_truth,baseline_selected,candidate_selected,complete)


@dataclass(frozen=True,init=False)
class GroupedBinding:
    source:GroupedSource
    profile:str
    values:tuple[int,...]
    baseline_truth:tuple[bool|None,...]
    candidate_truth:tuple[bool|None,...]
    baseline_selected:tuple[int,...]
    candidate_selected:tuple[int,...]
    complete:bool

    def __init__(self,token,source,profile,values,baseline_truth,candidate_truth,baseline_selected,candidate_selected,complete):
        if token is not _TOKEN:raise TypeError('use source.bind_profile')
        for name,value in dict(source=source,profile=profile,values=values,baseline_truth=baseline_truth,
                candidate_truth=candidate_truth,baseline_selected=baseline_selected,
                candidate_selected=candidate_selected,complete=complete).items():object.__setattr__(self,name,value)

    @property
    def assignment(self):return dict(zip((word for word,_ in self.source.baseline_program.words),self.values,strict=True))
    @property
    def baseline_program(self):return self.source.baseline_program
    @property
    def baseline_spec(self):return self.source.baseline_spec
    @property
    def candidate_program(self):return self.source.candidate_program
    @property
    def candidate_spec(self):return self.source.candidate_spec
    @property
    def projection(self):return self.source.projection


def build_grouped_source(role,fixture):
    _hosted_guard();_parameters(role,fixture)
    from convolution import ConvolutionTraceBuilder,multiplication_trace
    if fixture in ('point','point-inactive'):
        from curve_trace import point_add_trace
        from ipa_algebra import PALLAS,VESTA
        curve=PALLAS if role=='pallas_base' else VESTA
        g=(curve.p-1,2)
        left,right=(g,curve.add(g,g)) if fixture=='point' else (None,g)
        program,values=point_add_trace(curve,left,right,context=CONTEXT,
            operation_id=OPERATION_ID+'/'+fixture,multiplication_backend='convolution-v1')
        expected=(7476,6151,3447,35,13)
    elif fixture=='square':
        builder=ConvolutionTraceBuilder(role,OPERATION_ID+'/'+fixture,CONTEXT)
        a=builder.field('input/a',257);builder.mul('product',a,a)
        program,values=builder.finish();expected=(579,472,264,2,1)
    else:
        program,values=multiplication_trace(role,257,259 if fixture=='mul-distinct' else 257,
            context=CONTEXT,operation_id=OPERATION_ID+'/'+fixture)
        expected=(634,489,281,3,1)
    baseline=GraphSpec.from_program(program)
    candidate_program,candidate,projection=_transform(program,baseline)
    actual=(len(program.words),len(baseline.leaves),len(candidate.leaves),len(program.fields),
            len(projection.multiplication_prefixes))
    if actual != expected:raise ValueError('closed source count differs; do not raise caps')
    return GroupedSource(_TOKEN,role,fixture,program,baseline,candidate_program,candidate,projection,values)
