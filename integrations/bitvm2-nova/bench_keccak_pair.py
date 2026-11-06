"""Hosted-only five-case benchmark for one authenticated Keccak round pair.

Every leaf is measured by the separate Rust registry runner. Engine execution
uses shape representatives and selected boundary positions; all 1,600 shared
wire/signature links are checked separately by that runner. This is neither a
full permutation/hash nor an authenticated Nova transcript or proof verifier.
No local WOTS keys, native execution or full pair construction is permitted.
"""
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import sys
import time

from bench_compact import peak_rss
from keccak_trace import MASK64, keccak_f1600_round
from wots_graph import authenticated_shape

ROOT = Path(__file__).resolve().parent
CONTEXT = sha256(b'BITVM2-NOVA/GLOBAL-KECCAK-PAIR-BENCHMARK/v1').digest()
ROLE, OPERATION = 'pallas_scalar', 'registry/keccak-pair'
MAX_CASES, MAX_INPUT_BYTES = 5, 32 << 20
EXPECTED_WORDS, EXPECTED_LEAVES = 20806, 19206
SAMPLES = (0,1,63,64,799,1599)


def _hosted_guard():
    # Resource protection, not evidence authentication.
    if (os.environ.get('GITHUB_ACTIONS') != 'true'
            or os.environ.get('RUNNER_OS') != 'Linux' or sys.platform != 'linux'):
        raise ValueError('full Keccak pair benchmark is hosted GitHub Linux only')


def _load_pair():
    from keccak_pair import build_keccak_pair
    return build_keccak_pair(0,context=CONTEXT,role=ROLE,operation_id=OPERATION)


def _truth(spec,values,ordinal):
    """Independent Boolean relation with the global WOTS decoder's bound flag."""
    leaf = spec.leaves[ordinal]
    operands = []
    for slot in leaf.wires:
        name,bound = spec.words[slot]
        value = values[name]
        if type(value) is not int or not 0 <= value < bound:
            return False
        operands.append(value)
    if leaf.kind == 'const' and len(operands) == 1 and len(leaf.argument) == 1:
        return operands[0] == leaf.argument[0]
    if leaf.kind == 'bool_not' and len(operands) == 2:
        return operands[1] == 1-operands[0]
    if leaf.kind == 'bool_and' and len(operands) == 3:
        return operands[2] == (operands[0]&operands[1])
    if leaf.kind == 'bool_xor' and len(operands) == 3:
        return operands[2] == (operands[0]^operands[1])
    raise ValueError('unexpected pair predicate kind/arity')


def _initial_state():
    return tuple((i*0x0123456789abcdef ^ (1 << (i%64))) & MASK64 for i in range(25))


def _flip_first(state):
    return (state[0]^1,)+tuple(state[1:])


def _state(values,wires):
    if len(wires) != 1600:
        raise ValueError('exact1600-bit state mapping required')
    bits = [values[word] for word in wires]
    if any(type(bit) is not int or bit not in (0,1) for bit in bits):
        raise ValueError('canonical Boolean state mapping required')
    return tuple(sum(bits[64*lane+bit] << bit for bit in range(64)) for lane in range(25))


def _boundary_mapping(pair,input_words,middle,output_words,maps):
    spec = pair.spec
    if (len(spec.words),len(spec.leaves)) != (EXPECTED_WORDS,EXPECTED_LEAVES):
        raise ValueError('two-round pair word/leaf census changed')
    if any(bound != 2 for _,bound in spec.words) or spec.field_role != ROLE:
        raise ValueError('pair requires one Boolean pallas_scalar registry')
    names = {word:i for i,(word,_) in enumerate(spec.words)}
    if len(names) != len(spec.words):
        raise ValueError('duplicate composite registry word')
    if middle != tuple(f'boundary/middle/l{lane}/b{bit}' for lane in range(25) for bit in range(64)):
        raise ValueError('stable global boundary prefix/order required')
    for label,wires,key in [('inputs',input_words,'input_indices'),
            ('middle',middle,'boundary_indices'),('outputs',output_words,'output_indices')]:
        if (len(wires) != 1600 or len(set(wires)) != 1600
                or tuple(maps[label]) != tuple(wires)
                or tuple(maps[key]) != tuple(names[word] for word in wires)):
            raise ValueError('sealed pair state/slot mapping mismatch')
    children = maps['children']
    if (type(children) is not list or len(children) != 2
            or [child['round'] for child in children] != [0,1]):
        raise ValueError('exact ordered round0/1 children required')
    first,second = (tuple(child['leaf_map']) for child in children)
    if (first != tuple(range(len(first)))
            or second != tuple(range(len(first),len(spec.leaves)))):
        raise ValueError('ordered child leaf maps must partition the full catalogue')
    producers,consumers = [],[]
    first_set,second_set = set(first),set(second)
    by_middle = {names[word]:i for i,word in enumerate(middle)}
    producer_lists,consumer_lists = [[] for _ in middle],[[] for _ in middle]
    for ordinal,leaf in enumerate(spec.leaves):
        if ordinal in first_set and leaf.wires[-1] in by_middle:
            producer_lists[by_middle[leaf.wires[-1]]].append(ordinal)
        if ordinal in second_set:
            for slot in set(leaf.wires):
                if slot in by_middle:
                    if leaf.wires[-1] == slot:
                        raise ValueError('consumer cannot redefine a shared boundary wire')
                    consumer_lists[by_middle[slot]].append(ordinal)
    for produce,consume in zip(producer_lists,consumer_lists,strict=True):
        if len(produce) != 1 or not consume:
            raise ValueError('each boundary bit needs one producer and actual consumer uses')
        producers.append(produce[0]);consumers.append(tuple(consume))
    if (tuple(pair.producer_leaves) != tuple(producers)
            or tuple(tuple(row) for row in pair.consumer_leaves) != tuple(consumers)
            or tuple(maps['producer_leaves']) != tuple(producers)
            or tuple(tuple(row) for row in maps['consumer_leaves']) != tuple(consumers)):
        raise ValueError('source map differs from independently derived shared-wire uses')
    output_slot = names[output_words[0]]
    output_producers = [i for i in second if spec.leaves[i].wires[-1] == output_slot]
    if len(output_producers) != 1:
        raise ValueError('first final output requires one explicit producer')
    return dict(producers=tuple(producers),consumers=tuple(consumers),
        first_leaves=first,second_leaves=second,first_input_slot=names[input_words[0]],
        first_output_producer=output_producers[0])


def _cases(pair,information):
    spec = pair.spec
    input_words,middle_words,output_words = tuple(pair.inputs),tuple(pair.middle),tuple(pair.outputs)
    source_maps = pair.source_maps
    mapping = _boundary_mapping(pair,input_words,middle_words,output_words,source_maps)
    shape,digest = spec.json(),spec.digest().hex()
    initial = _initial_state()
    middle = keccak_f1600_round(initial,0)
    final = keccak_f1600_round(middle,1)
    seen,representatives = set(),[]
    for i,leaf in enumerate(spec.leaves):
        signature = authenticated_shape(spec,leaf)
        if signature not in seen:
            representatives.append(i);seen.add(signature)
    selected = set(representatives)
    for bit in SAMPLES:
        selected.add(mapping['producers'][bit])
        selected.update(mapping['consumers'][bit])
    selected.add(mapping['first_output_producer'])
    input_refs = [i for i,leaf in enumerate(spec.leaves) if mapping['first_input_slot'] in leaf.wires]
    selected.update(input_refs)
    selected = sorted(selected)
    kinds = sorted({leaf.kind for leaf in spec.leaves})
    if set(kinds) != {'const','bool_xor','bool_and','bool_not'}:
        raise ValueError('unexpected pair Boolean/constant predicate kinds')

    def assignment(binding):
        from keccak_pair import KeccakPairBinding
        if type(binding) is not KeccakPairBinding or binding.spec.digest() != spec.digest():
            raise ValueError('sealed binding for this exact pair required')
        values = binding.assignment
        if set(values) != {word for word,_ in spec.words}:
            raise ValueError('binding changed pair assignment topology')
        return values

    def emit(name,values,checks,reason,measure=False):
        if (not checks or len({item['ordinal'] for item in checks}) != len(checks)
                or any(_truth(spec,values,item['ordinal']) != item['expected_correct'] for item in checks)):
            raise ValueError('pair check expectations disagree with independent Boolean relations')
        words = [values[word] for word,_ in spec.words]
        if any(type(word) is not int or not 0 <= word <= 0xffffffff for word in words):
            raise ValueError('registry signer needs unsigned32 words')
        information['diagnostics'].append(dict(name=name,reason=reason,
            expected_false_ordinals=[item['ordinal'] for item in checks if not item['expected_correct']],
            expected_true_ordinals=[item['ordinal'] for item in checks if item['expected_correct']]))
        information['normal_checks'] += len(checks)
        return dict(name=name,spec=shape,expected_spec_id=digest,words=words,checks=checks,measure_all=measure)

    honest = assignment(pair.bind(initial))
    if (any(not _truth(spec,honest,i) for i in range(len(spec.leaves)))
            or _state(honest,input_words) != initial or _state(honest,middle_words) != middle
            or _state(honest,output_words) != final):
        raise ValueError('honest pair differs from independent two-round word reference')
    encoded_maps = json.dumps(source_maps,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode('ascii')
    information.update(words=len(spec.words),leaves=len(spec.leaves),kinds=kinds,
        authenticated_shapes=len(representatives),selected_truth_leaves=len(selected),
        alias_shape_ordinals=[i for i in representatives if len(set(spec.leaves[i].wires)) != len(spec.leaves[i].wires)],
        selected_ordinals=selected,boundary_samples=list(SAMPLES),
        composite_identity_is_program_digest=False,
        shared_boundary_words=1600,shared_boundary_signature_pairs=sum(map(len,mapping['consumers'])),
        boundary_mappings=[dict(bit=bit,word=middle_words[bit],producer=mapping['producers'][bit],
            consumers=list(mapping['consumers'][bit])) for bit in range(1600)],
        source_maps_sha256=sha256(encoded_maps).hexdigest(),factory_manifest=pair.manifest,
        catalogue_sha256=digest,program_sha256=spec.program_sha256,
        first_child_leaves=len(mapping['first_leaves']),second_child_leaves=len(mapping['second_leaves']),
        first_input_word=input_words[0],first_output_producer=mapping['first_output_producer'])
    yield emit('keccak/pair-0-1',honest,[dict(ordinal=i,expected_correct=True) for i in selected],
        'complete catalogue measured; representative shapes and selected boundary uses execute',True)

    corrupt_middle = _flip_first(middle)
    coherent = assignment(pair.bind(initial,claimed_middle=corrupt_middle))
    false = [i for i in range(len(spec.leaves)) if not _truth(spec,coherent,i)]
    if (false != [mapping['producers'][0]] or _state(coherent,middle_words) != corrupt_middle
            or _state(coherent,output_words) != keccak_f1600_round(corrupt_middle,1)):
        raise ValueError('coherent middle attack must fail only the actual first producer')
    yield emit('keccak/pair-coherent-middle',coherent,[dict(ordinal=false[0],expected_correct=False)],
        'round1 is coherently witnessed from the changed same boundary wire; round0 producer refutes it')

    wrong = assignment(pair.bind(initial,claimed_output=_flip_first(final)))
    false = [i for i in range(len(spec.leaves)) if not _truth(spec,wrong,i)]
    if false != [mapping['first_output_producer']]:
        raise ValueError('wrong final bit must fail one explicit output producer')
    yield emit('keccak/pair-wrong-final',wrong,[dict(ordinal=false[0],expected_correct=False)],
        'honest internal rounds with one incorrect claimed final output bit')
    for label,value in [('bit2',2),('u32max',0xffffffff)]:
        malformed = dict(honest);malformed[input_words[0]]=value
        false = [i for i in range(len(spec.leaves)) if not _truth(spec,malformed,i)]
        if not false or false != input_refs:
            raise ValueError('signed malformed input must refute every exact input use')
        yield emit('keccak/pair-signed-input-'+label,malformed,
            [dict(ordinal=i,expected_correct=False) for i in false],
            'valid test signature on an unsigned word outside the declared Boolean bound')


def _write_cases(cases,path):
    """Bound every write and preserve the previous corpus if generation fails."""
    path = Path(path)
    path.parent.mkdir(parents=True,exist_ok=True)
    temporary = path.with_name(path.name+'.partial')
    encoder = json.JSONEncoder(ensure_ascii=True,separators=(',',':'),allow_nan=False)
    digest,total,count,created = sha256(),0,0,False
    try:
        with temporary.open('xb') as output:
            created = True
            def write(raw):
                nonlocal total
                if total+len(raw) > MAX_INPUT_BYTES:
                    raise ValueError('Keccak pair corpus exceeds32MiB')
                output.write(raw)
                digest.update(raw)
                total += len(raw)
            write(b'[')
            for case in cases:
                count += 1
                if count > MAX_CASES:
                    raise ValueError('Keccak pair five-case bound')
                if count > 1:
                    write(b',')
                for fragment in encoder.iterencode(case):
                    write(fragment.encode('ascii'))
            if not count:
                raise ValueError('nonempty pair corpus required')
            write(b']\n')
        temporary.replace(path)
    except BaseException:
        if created:
            temporary.unlink(missing_ok=True)
        raise
    return dict(cases=count,input_bytes=total,input_sha256=digest.hexdigest())


def run(inputs):
    _hosted_guard()
    started = time.perf_counter()
    pair = _load_pair()
    information = dict(normal_checks=0,diagnostics=[])
    written = _write_cases(_cases(pair,information),inputs)
    if written['cases'] != 5:
        raise ValueError('exactly five pair cases required')
    guards = 14*len(information['kinds'])
    checks = information['normal_checks']
    return dict(schema='bitvm2-nova-keccak-pair-generation/v1',**written,**information,
        field_role=ROLE,rounds=[0,1],context_sha256=CONTEXT.hex(),operation_id=OPERATION,
        expected_registry_vectors=2*checks+guards,expected_script_rejections=checks+guards,
        expected_witness_and_authentication_guard_vectors=guards,
        expected_native_catalogue_rejections=27,expected_measured_ledger_entries=1,
        expected_assertion_signatures=5*len(pair.spec.words),
        expected_pair_boundary_words=information['shared_boundary_words'],
        expected_pair_boundary_signature_links=information['shared_boundary_signature_pairs'],
        expected_coherent_middle_disproofs=1,expected_pair_taproot_commitments=2,
        two_round_word_reference_checked=True,all_leaves_to_measure=len(pair.spec.leaves),
        wots_script_bytes_measured=False,native_scripts_executed=0,wots_signatures_generated=0,
        full_permutation_verified=False,full_hash_verified=False,keccak256_verified=False,
        transcript_verified=False,proof_verified=False,bitvm2_script_verified=False,complete_verifier=False,
        absorb_padding_squeeze_verified=False,production_assertion_binding=False,
        bitcoin_transaction_graph=False,transactions_broadcast=0,proving_jobs=0,
        native_proofs_verified=0,generation_seconds=time.perf_counter()-started,
        python_peak_rss_bytes=peak_rss(),platform=platform.platform(),hosted_resource_guard_satisfied=True,
        scope='one synthetic two-round shared-boundary graph; incomplete permutation/hash/transcript/proof verification')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inputs',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args = parser.parse_args()
    _hosted_guard()
    if args.inputs.resolve() == args.output.resolve():
        raise ValueError('corpus and report paths must differ')
    result = run(args.inputs)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(result,indent=2)+'\n',encoding='ascii',newline='\n')
    print(json.dumps({name:value for name,value in result.items()
                      if name not in ('boundary_mappings','factory_manifest')}))


if __name__=='__main__':
    main()

