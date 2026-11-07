"""Opt-in grouped-AB conditional point source, derived from fresh legacy graphs.

Only the AB predicates change. The reference is a genuine legacy catalogue and
its actual maps, never an execution receipt or a caller-supplied graph. Point,
proof/key origin, scalar multiplication and production claims remain separate.
"""
from dataclasses import dataclass
from hashlib import sha256
import json
import os
import sys
from types import MappingProxyType

from conditional_point import (AUTO, ConditionalPointPlan, build_conditional_point,
                               _parameters, _bit, encoded_point, FALSE_FLAGS)
from convolution import ConvolutionProgram
from grouped_convolution import COMPILER, _transform
from wots_graph import GraphSpec

SCHEMA = 'bitvm2-nova-grouped-conditional-point/v1'
MAP_SCHEMA = 'bitvm2-nova-grouped-conditional-point-maps/v1'
SOURCE_DOMAIN = b'BITVM2-NOVA/GROUPED-CONDITIONAL-POINT/v1\x00'
PROGRAM_IDENTITY_KIND = 'GroupedProgram.digest (grouped-convolution/v1)'
WORDS, ARITHMETIC, FIELDS, LEAVES = 7498, 3420, 37, 3457
MAX_MAP_BYTES, MAX_MANIFEST_BYTES, MAX_REFERENCE_BYTES = 8 << 20, 1 << 20, 8 << 20


def _hosted_guard():
    if (os.environ.get('GITHUB_ACTIONS') != 'true'
            or os.environ.get('RUNNER_OS') != 'Linux' or sys.platform != 'linux'):
        raise ValueError('grouped conditional point construction/binding is hosted GitHub Linux only')


def _canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')


def _hash(value):return sha256(_canonical(value)).hexdigest()


def _make(cls,**fields):
    result=object.__new__(cls)
    for key,value in fields.items():object.__setattr__(result,key,value)
    return result


def _single(projection,old):
    new,row=projection.old_to_new[old]
    if row is not None:raise ValueError('a selector/canonical guard was grouped as AB arithmetic')
    return new


def _derive(program,spec,legacy_maps,legacy_metadata,assignment):
    """Private stage: all inputs originate inside a fresh sealed legacy factory."""
    _hosted_guard()
    if type(program) is not ConvolutionProgram or type(spec) is not GraphSpec:
        raise ValueError('actual legacy conditional program/catalogue required')
    if (len(program.words),len(program.constraints),len(program.fields),len(spec.leaves)) != (7498,6124,37,6161):
        raise ValueError('legacy conditional point census changed')
    if (legacy_metadata['program_sha256'] != program.digest().hex()
            or legacy_metadata['catalogue_id'] != spec.digest().hex()
            or legacy_metadata['source_maps_sha256'] != _hash(legacy_maps)):
        raise ValueError('actual legacy conditional source identity changed')
    reference=_canonical(dict(spec=spec.json(),maps=legacy_maps))
    if len(reference)>MAX_REFERENCE_BYTES:raise ValueError('genuine legacy reference exceeds8MiB factory cap')
    reference_sha=sha256(reference).hexdigest()
    grouped,grouped_spec,projection=_transform(program,spec)

    # Derive a genuine complete-add child, verify its old identity, then group
    # it independently. Counts alone never serve as a child identity.
    old_child=ConvolutionProgram(program.field_role,legacy_maps['child']['operation_id'],program.context,
        program.words[:7476],program.fields[:35],program.constraints[:6116])
    old_child_spec=GraphSpec.from_program(old_child)
    child_info=legacy_maps['child']
    if (old_child.digest().hex()!=child_info['program_sha256']
            or old_child_spec.digest().hex()!=child_info['catalogue_id']
            or child_info['word_map']!=list(range(7476))):
        raise ValueError('fresh complete-add slice does not match genuine legacy child')
    child,child_spec,child_projection=_transform(old_child,old_child_spec)
    if (len(child.words),len(child.constraints),len(child.fields),len(child_spec.leaves))!=(7476,3412,35,3447):
        raise ValueError('grouped complete-add child census changed')
    child_leaf_map=[]
    for child_ordinal,old_rows in enumerate(child_projection.new_to_old):
        parent_rows=tuple(projection.old_to_new[child_info['leaf_map'][old]] for old in old_rows)
        if (len({ordinal for ordinal,_ in parent_rows})!=1
                or any(row!=child_projection.old_to_new[old][1]
                       for old,(_,row) in zip(old_rows,parent_rows,strict=True))):
            raise ValueError('actual grouped child predicate does not project to exactly one parent predicate')
        child_leaf_map.append(parent_rows[0][0])
    child_leaf_map=tuple(child_leaf_map)
    if (len(set(child_leaf_map))!=len(child_spec.leaves)
            or child_leaf_map!=tuple(range(3412))+tuple(3420+i for i in range(35))):
        raise ValueError('derived injective grouped complete-add leaf map changed')
    child_bodies,parent_bodies=dict(child_spec.bodies),dict(grouped_spec.bodies)
    for before,after in enumerate(child_leaf_map):
        a,b=child_spec.leaves[before],grouped_spec.leaves[after]
        if a!=b or child_bodies[a.body_sha256]!=parent_bodies[b.body_sha256]:
            raise ValueError('actual grouped complete-add body/alias/word projection changed')
    complete_add=dict(legacy_program_sha256=old_child.digest().hex(),legacy_catalogue_id=old_child_spec.digest().hex(),
        program_sha256=child.digest().hex(),catalogue_id=child_spec.digest().hex(),words=7476,
        arithmetic_constraints=3412,canonical_fields=35,leaves=3447,word_map=tuple(range(7476)),
        leaf_map=child_leaf_map,projection_sha256=_hash(child_projection.json()))
    del child,child_spec,child_projection,old_child,old_child_spec,child_bodies,parent_bodies

    ports=legacy_maps['ports']
    positions={word:index for index,(word,_) in enumerate(grouped.words)}
    selectors={name:_single(projection,ordinal) for name,ordinal in legacy_maps['selector_constraints'].items()}
    bit_word=positions[ports['bit']]
    bit_occurrences=tuple((ordinal,formal) for ordinal,leaf in enumerate(grouped_spec.leaves)
                         for formal,word in enumerate(leaf.wires) if word==bit_word)
    expected_bits=tuple((_single(projection,ordinal),formal)
                        for ordinal,formal in legacy_maps['selected_bit_occurrences'])
    original_guards=tuple(_single(projection,ordinal) for ordinal in legacy_maps['original_field_leaves'])
    r_guards=tuple(_single(projection,ordinal) for ordinal in legacy_maps['R_canonical_field_leaves'])
    if ((len(grouped.words),len(grouped.constraints),len(grouped.fields),len(grouped_spec.leaves))
            !=(WORDS,ARITHMETIC,FIELDS,LEAVES) or bit_word!=7476 or bit_occurrences!=expected_bits
            or bit_occurrences!=((3413,0),(3415,0),(3416,0),(3417,0),(3418,0))
            or original_guards!=tuple(range(3420,3455)) or r_guards!=(3455,3456)):
        raise ValueError('derived grouped selector/canonical source maps changed')
    legacy_source_sha=sha256(b'BITVM2-NOVA/CONDITIONAL-POINT/v1\x00'+_canonical(legacy_metadata)).hexdigest()
    maps=dict(schema=MAP_SCHEMA,compiler=COMPILER,legacy_reference_sha256=reference_sha,
        legacy_source_sha256=legacy_source_sha,legacy_source_maps_sha256=_hash(legacy_maps),
        projection=projection.json(),complete_add=complete_add,ports=ports,
        port_indices={key:tuple(positions[word] for word in value) if type(value) in (tuple,list)
                      else positions[value] for key,value in ports.items()},
        selector_constraints=selectors,selected_bit_occurrences=bit_occurrences,
        R_canonical_field_leaves=r_guards,original_field_leaves=original_guards,
        point_form_ordinal=_single(projection,legacy_maps['point_form_ordinal']),bit_index=legacy_maps['bit_index'],
        coordinate_outputs_are_asserted_ports=True,all_child_predicates_active=True)
    raw_maps=_canonical(maps)
    metadata=dict(schema=SCHEMA,compiler=COMPILER,context=program.context.hex(),field_role=program.field_role,
        scalar_field_role=legacy_metadata['scalar_field_role'],curve=legacy_metadata['curve'],
        bit_index=legacy_metadata['bit_index'],operation_id=program.operation_id,
        program_sha256=grouped.digest().hex(),catalogue_id=grouped_spec.digest().hex(),
        program_identity_kind=PROGRAM_IDENTITY_KIND,source_maps_sha256=sha256(raw_maps).hexdigest(),
        legacy_program_sha256=program.digest().hex(),legacy_catalogue_id=spec.digest().hex(),
        legacy_source_sha256=legacy_source_sha,legacy_source_maps_sha256=_hash(legacy_maps),
        legacy_reference_sha256=reference_sha,complete_add_program_sha256=complete_add['program_sha256'],
        complete_add_catalogue_id=complete_add['catalogue_id'],words=WORDS,arithmetic_constraints=ARITHMETIC,
        canonical_fields=FIELDS,leaves=LEAVES,relation=legacy_metadata['relation'],
        infinity_relation=legacy_metadata['infinity_relation'],
        scope='grouped conjunctions preserve one conditional point relation; proof/key origins, scalar multiplication and IPA remain open')
    raw_metadata=_canonical(metadata)
    if len(raw_maps)>MAX_MAP_BYTES or len(raw_metadata)>MAX_MANIFEST_BYTES:
        raise ValueError('grouped conditional metadata exceeds unchanged source caps')
    if set(assignment)!={word for word,_ in grouped.words}:
        raise ValueError('fresh legacy conditional assignment coverage changed')
    return dict(program=grouped,spec=grouped_spec,projection=projection,assignment=tuple(assignment.items()),
        ports=tuple((key,tuple(value) if type(value) is list else value) for key,value in ports.items()),
        reference=reference,maps=raw_maps,metadata=raw_metadata,
        source_sha256=sha256(SOURCE_DOMAIN+raw_metadata).digest(),source_maps_sha256=sha256(raw_maps).digest())


def _from_legacy_plan(legacy):
    _hosted_guard()
    if type(legacy) is not ConditionalPointPlan:raise ValueError('fresh sealed conditional point plan required')
    built=_derive(legacy.program,legacy.spec,legacy.source_maps,legacy.metadata,legacy.assignment)
    return _make(GroupedConditionalPointPlan,context=legacy.context,role=legacy.role,bit_index=legacy.bit_index,
        operation_id=legacy.operation_id,program=built['program'],spec=built['spec'],projection=built['projection'],
        source_sha256=built['source_sha256'],source_maps_sha256=built['source_maps_sha256'],
        _assignment=built['assignment'],_ports=built['ports'],_metadata=built['metadata'],_maps=built['maps'],
        _reference=built['reference'])


@dataclass(frozen=True,init=False)
class GroupedConditionalPointBinding:
    plan:object
    program:object
    spec:GraphSpec
    input_bit:int
    A:object
    P:object
    E:object
    R:object
    reference_E:object
    reference_R:object
    _assignment:tuple
    def __init__(self,*args,**kwargs):raise TypeError('bind through the sealed grouped conditional point plan')
    assignment=property(lambda self:dict(self._assignment))
    projection=property(lambda self:self.plan.projection)
    ports=property(lambda self:self.plan.ports)
    metadata=property(lambda self:self.plan.metadata)
    source_maps=property(lambda self:self.plan.source_maps)
    source_sha256=property(lambda self:self.plan.source_sha256)
    source_maps_sha256=property(lambda self:self.plan.source_maps_sha256)


@dataclass(frozen=True,init=False)
class GroupedConditionalPointPlan:
    context:bytes
    role:str
    bit_index:int
    operation_id:str
    program:object
    spec:GraphSpec
    projection:object
    source_sha256:bytes
    source_maps_sha256:bytes
    _assignment:tuple
    _ports:tuple
    _metadata:bytes
    _maps:bytes
    _reference:bytes
    def __init__(self,*args,**kwargs):raise TypeError('use the grouped conditional point factory; no imported graph authority')
    assignment=property(lambda self:dict(self._assignment))
    ports=property(lambda self:MappingProxyType(dict(self._ports)))
    metadata=property(lambda self:json.loads(self._metadata))
    source_maps=property(lambda self:json.loads(self._maps))
    legacy_reference_bytes=property(lambda self:self._reference)
    legacy_reference_json=property(lambda self:json.loads(self._reference))

    def bind(self,A,P,bit,*,claimed_E=AUTO,claimed_R=AUTO):
        _hosted_guard()
        _bit(bit)
        encoded_point(A,role=self.role,label='A',canonical_form=claimed_E is AUTO)
        encoded_point(P,role=self.role,label='P',canonical_form=claimed_E is AUTO)
        if claimed_E is not AUTO:encoded_point(claimed_E,role=self.role,label='E claim')
        if claimed_R is not AUTO:encoded_point(claimed_R,role=self.role,label='R claim')
        legacy=build_conditional_point(context=self.context,role=self.role,bit_index=self.bit_index,
                                       operation_id=self.operation_id)
        bound=legacy.bind(A,P,bit,claimed_E=claimed_E,claimed_R=claimed_R)
        built=_derive(bound.program,bound.spec,bound.source_maps,bound.metadata,bound.assignment)
        if (built['program'].digest()!=self.program.digest() or built['spec'].digest()!=self.spec.digest()
                or built['source_sha256']!=self.source_sha256 or built['source_maps_sha256']!=self.source_maps_sha256
                or built['reference']!=self._reference or built['projection']!=self.projection):
            raise ValueError('fresh grouped conditional binding changed sealed source identity')
        return _make(GroupedConditionalPointBinding,plan=self,program=built['program'],spec=built['spec'],
            input_bit=bound.input_bit,A=bound.A,P=bound.P,E=bound.E,R=bound.R,
            reference_E=bound.reference_E,reference_R=bound.reference_R,_assignment=built['assignment'])

    def summary(self):
        result=dict(schema=SCHEMA,source_sha256=self.source_sha256.hex(),field_role=self.role,bit_index=self.bit_index,
            words=WORDS,arithmetic_constraints=ARITHMETIC,leaves=LEAVES,canonical_fields=FIELDS,
            grouped_conditional_point_graph_constructed=True,complete_child_semantics_preserved=True,
            unchanged_non_ab_and_field_guards=True,taproot_forest_membership_verified=False)
        result.update({flag:False for flag in FALSE_FLAGS})
        return result


def build_grouped_conditional_point(*,context,role,bit_index=0,operation_id='grouped-conditional-point'):
    _hosted_guard();_parameters(context,role,bit_index,operation_id)
    return _from_legacy_plan(build_conditional_point(context=context,role=role,bit_index=bit_index,operation_id=operation_id))
