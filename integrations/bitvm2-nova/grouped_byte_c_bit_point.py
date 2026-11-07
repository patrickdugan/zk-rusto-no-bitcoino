"""Isolated grouped conditional-point replacement in the sealed eleven-source graph.

Components0..9 are genuine frozen legacy components under the SAME caller
parameters. Only component10 changes compiler/program/catalogue identity. New
source identities precede all test keys, Scripts and live forest construction.
"""
from dataclasses import dataclass
from hashlib import sha256
import json
import os
import sys

import byte_c_bit_point as legacy
from conditional_point import AUTO
from grouped_conditional_point import (PROGRAM_IDENTITY_KIND, _from_legacy_plan, _derive,
                                       _canonical, _hash)
from grouped_convolution import COMPILER

SCHEMA = 'bitvm2-nova-grouped-byte-c-bit-point-source/v1'
MAP_SCHEMA = 'bitvm2-nova-grouped-byte-c-bit-point-maps/v1'
SOURCE_DOMAIN = b'BITVM2-NOVA/GROUPED-BYTE-C-BIT-POINT-SOURCE/v1\x00'
CONTEXT = sha256(b'BITVM2-NOVA/GROUPED-BYTE-C-BIT-POINT-CONFORMANCE/v1').digest()
OPERATION_ID = 'benchmark/grouped-byte-c-bit-point/v1'
FALSE_FLAGS = legacy.FALSE_FLAGS+('taproot_forest_membership_verified',)
MAX_MAP_BYTES, MAX_MANIFEST_BYTES = 8 << 20, 1 << 20


def _hosted_guard():
    if (os.environ.get('GITHUB_ACTIONS') != 'true'
            or os.environ.get('RUNNER_OS') != 'Linux' or sys.platform != 'linux'):
        raise ValueError('grouped BYTE c-bit point construction/binding is hosted GitHub Linux only')


def _make(cls,**fields):
    result=object.__new__(cls)
    for key,value in fields.items():object.__setattr__(result,key,value)
    return result


def _point_descriptor(old,point):
    if (old.index!=10 or old.branch!='conditional-point' or old.words!=7498 or old.leaves!=6161
            or len(point.spec.words)!=7498 or len(point.spec.leaves)!=3457
            or point.program.field_role!=old.field_role or point.program.operation_id!=old.operation_id
            or point.spec.program_sha256!=point.program.digest().hex()):
        raise ValueError('actual grouped conditional descriptor changed its legacy slot/word identity')
    data=old.json()
    data.update(kind='grouped-conditional-point',program_sha256=point.program.digest().hex(),
        catalogue_id=point.spec.digest().hex(),source_sha256=point.source_sha256.hex(),
        source_maps_sha256=point.source_maps_sha256.hex(),leaves=3457,program_identity_kind=PROGRAM_IDENTITY_KIND)
    return _make(type(old),**data)


def _point_source(old,point,descriptor):
    ids=tuple(legacy.point_global_id(word,role=point.role,bit_index=point.bit_index)
              for word,_ in point.spec.words)
    if (ids!=old.global_ids or _hash(ids)!=descriptor.global_ids_sha256
            or point.legacy_reference_bytes!=_canonical(dict(spec=old.spec.json(),maps=old.child_source_maps))):
        raise ValueError('grouped point altered actual global IDs or genuine legacy reference')
    return _make(legacy.CBitPointComponentSource,index=10,branch='conditional-point',descriptor=descriptor,
        child=point,program=point.program,spec=point.spec,global_ids=ids,_program_manifest=None,
        _source_manifest=point._metadata,_source_maps=point._maps)


@dataclass(frozen=True,init=False)
class GroupedCBitPointPlan:
    context:bytes
    role:str
    point_role:str
    curve_name:str
    rho_counter:int
    bit_index:int
    operation_id:str
    components:tuple
    source_sha256:bytes
    source_maps_sha256:bytes
    _legacy:object
    _manifest:bytes
    _maps:bytes
    _reference:bytes
    def __init__(self,*args,**kwargs):raise TypeError('use the sealed grouped c-bit point factory; no imported graph/map authority')
    manifest=property(lambda self:json.loads(self._manifest))
    source_maps=property(lambda self:json.loads(self._maps))
    chain=property(lambda self:self._legacy.chain)
    ports=property(lambda self:self._legacy.ports)
    legacy_reference_bytes=property(lambda self:self._reference)
    legacy_reference_json=property(lambda self:json.loads(self._reference))
    legacy_source_manifest=property(lambda self:self._legacy.manifest)
    legacy_source_maps=property(lambda self:self._legacy.source_maps)

    def regenerate_component(self,index):
        _hosted_guard();legacy._integer(index,0,10,'component index0..10')
        old=self._legacy.regenerate_component(index)
        if index<10:
            if old.descriptor.json()!=self.components[index].json():
                raise ValueError('fresh inherited component differs under matched caller parameters')
            return old
        point=_from_legacy_plan(old.child)
        descriptor=_point_descriptor(old.descriptor,point)
        if descriptor.json()!=self.components[10].json() or point.legacy_reference_bytes!=self._reference:
            raise ValueError('fresh grouped point changed sealed source identity')
        return _point_source(old,point,descriptor)

    def bind(self,eval_w,prior_state,compressed_coefficients,A,P,*,claimed_bit=None,claimed_E=AUTO,claimed_R=AUTO):
        _hosted_guard()
        bound=self._legacy.bind(eval_w,prior_state,compressed_coefficients,A,P,
            claimed_bit=claimed_bit,claimed_E=claimed_E,claimed_R=claimed_R)
        return _binding(self,bound)

    def summary(self):
        result=dict(schema=SCHEMA,source_sha256=self.source_sha256.hex(),field_role=self.role,
            point_field_role=self.point_role,curve=self.curve_name,bit_index=self.bit_index,
            components=11,leaves=150509,local_declared_words=156163,unique_global_words=155107,
            cached_signature_reuses=1056,new_shared_limb_words=9,new_shared_bit_words=1,
            new_opening_comparisons=14,new_canonical_opening_comparisons=9,new_total_opening_comparisons=23,
            grouped_c_bit_point_topology_constructed=True)
        result.update({flag:False for flag in FALSE_FLAGS})
        return result


def _binding(plan,bound):
    if type(plan) is not GroupedCBitPointPlan or type(bound) is not legacy.CBitPointBinding or bound.plan is not plan._legacy:
        raise ValueError('actual sealed matched legacy binding required')
    return _make(GroupedCBitPointBinding,plan=plan,_legacy=bound)


@dataclass(frozen=True,init=False)
class GroupedCBitPointBinding:
    plan:GroupedCBitPointPlan
    _legacy:object
    def __init__(self,*args,**kwargs):raise TypeError('bind through the sealed grouped c-bit point plan')
    chain=property(lambda self:self._legacy.chain)
    A=property(lambda self:self._legacy.A)
    P=property(lambda self:self._legacy.P)
    E=property(lambda self:self._legacy.E)
    R=property(lambda self:self._legacy.R)
    reference_E=property(lambda self:self._legacy.reference_E)
    reference_R=property(lambda self:self._legacy.reference_R)
    scalar_value=property(lambda self:self._legacy.scalar_value)
    scalar_quotient_value=property(lambda self:self._legacy.scalar_quotient_value)
    selected_bit=property(lambda self:self._legacy.selected_bit)
    canonical_bit=property(lambda self:self._legacy.canonical_bit)
    bits=property(lambda self:self._legacy.bits)
    claimed_bit=property(lambda self:self._legacy.claimed_bit)
    claimed_E=property(lambda self:self._legacy.claimed_E)
    claimed_R=property(lambda self:self._legacy.claimed_R)
    uniform_alias=property(lambda self:self._legacy.uniform_alias)
    raw_c=property(lambda self:self._legacy.raw_c)
    input_limbs=property(lambda self:self._legacy.input_limbs)

    def iter_components(self):
        _hosted_guard()
        def stream():
            iterator=self._legacy.iter_components()
            for old in iterator:
                if old.index<10:
                    if old.descriptor.json()!=self.plan.components[old.index].json():
                        raise ValueError('fresh inherited binding descriptor changed')
                    yield old
                    del old
                    continue
                # Transform the ACTUAL fresh point record already bound to the
                # upstream selected bit. Do not retain another full point plan.
                built=_derive(old.program,old.spec,old.child_source_maps,old.child_source_manifest,old.assignment)
                descriptor=self.plan.components[10]
                if (built['program'].digest().hex()!=descriptor.program_sha256
                        or built['spec'].digest().hex()!=descriptor.catalogue_id
                        or built['source_sha256'].hex()!=descriptor.source_sha256
                        or built['source_maps_sha256'].hex()!=descriptor.source_maps_sha256
                        or built['reference']!=self.plan._reference):
                    raise ValueError('fresh grouped bound component changed sealed descriptor/reference')
                result=legacy._record(10,descriptor,built['program'],built['spec'],old.global_ids,
                    dict(built['assignment']),None,built['metadata'],built['maps'])
                del old,built
                if next(iterator,None) is not None:
                    raise ValueError('legacy iterator produced more than eleven components')
                yield result
                del result
        return stream()

    def summary(self):
        result=self._legacy.summary()
        result.update(source_sha256=self.plan.source_sha256.hex(),grouped_conditional_point_binding_constructed=True)
        result.update({flag:False for flag in FALSE_FLAGS})
        return result


def _bind_uniform_alias(plan,eval_w,prior_state,compressed_coefficients,A,P,*,claimed_E=AUTO,claimed_R=AUTO):
    _hosted_guard()
    if type(plan) is not GroupedCBitPointPlan:raise ValueError('actual sealed grouped plan required')
    return _binding(plan,legacy._bind_uniform_alias(plan._legacy,eval_w,prior_state,compressed_coefficients,A,P,
        claimed_E=claimed_E,claimed_R=claimed_R))


def build_grouped_byte_c_bit_point(*,context,role,rho_counter,bit_index=0,operation_id='grouped-byte-c-bit-point'):
    _hosted_guard();legacy._parameters(context,role,rho_counter,bit_index,operation_id)
    old=legacy.build_byte_c_bit_point(context=context,role=role,rho_counter=rho_counter,
                                     bit_index=bit_index,operation_id=operation_id)
    source=old.regenerate_component(10)
    point=_from_legacy_plan(source.child)
    descriptor=_point_descriptor(source.descriptor,point)
    grouped_source=_point_source(source,point,descriptor)
    descriptors=old.components[:10]+(descriptor,)
    maps=old.source_maps
    maps.update(schema=MAP_SCHEMA,components=[item.json() for item in descriptors],leaves=150509,
        legacy_source_sha256=old.source_sha256.hex(),legacy_source_maps_sha256=old.source_maps_sha256.hex(),
        point_grouping=dict(compiler=COMPILER,legacy_reference_sha256=sha256(point.legacy_reference_bytes).hexdigest(),
                            projection_sha256=_hash(point.projection.json())))
    bit_link=dict(maps['selected_bit_to_point'])
    bit_word=7476
    actual=tuple((ordinal,formal) for ordinal,leaf in enumerate(point.spec.leaves)
                 for formal,word in enumerate(leaf.wires) if word==bit_word)
    if (grouped_source.global_ids[bit_word]!=maps['cross_role_shared_words'][0]
            or point.spec.words[bit_word][1]!=2 or len(actual)!=5):
        raise ValueError('actual grouped point detached from sole shared bound2 bit')
    bit_link['target_occurrences']=actual
    maps['selected_bit_to_point']=bit_link
    if (sum(item.words for item in descriptors)!=156163 or sum(item.leaves for item in descriptors)!=150509
            or maps['unique_global_words']!=155107 or maps['cached_signature_reuses']!=1056):
        raise ValueError('grouped eleven-source declaration/leaf census changed')
    raw_maps=_canonical(maps)
    manifest=old.manifest
    manifest.update(schema=SCHEMA,components=[item.json() for item in descriptors],leaves=150509,
        source_maps_sha256=sha256(raw_maps).hexdigest(),legacy_source_sha256=old.source_sha256.hex(),
        legacy_source_maps_sha256=old.source_maps_sha256.hex(),point_grouping=maps['point_grouping'],
        scope='grouped one verifier-fixed challenge-bit conditional point relation; proof/key origins, scalar multiplication and IPA remain open')
    raw_manifest=_canonical(manifest)
    if len(raw_maps)>MAX_MAP_BYTES or len(raw_manifest)>MAX_MANIFEST_BYTES:
        raise ValueError('grouped mixed-role source exceeds unchanged metadata caps')
    reference=point.legacy_reference_bytes
    del source,point,grouped_source
    return _make(GroupedCBitPointPlan,context=context,role=role,point_role=old.point_role,curve_name=old.curve_name,
        rho_counter=rho_counter,bit_index=bit_index,operation_id=operation_id,components=descriptors,
        source_sha256=sha256(SOURCE_DOMAIN+raw_manifest).digest(),source_maps_sha256=sha256(raw_maps).digest(),
        _legacy=old,_manifest=raw_manifest,_maps=raw_maps,_reference=reference)
