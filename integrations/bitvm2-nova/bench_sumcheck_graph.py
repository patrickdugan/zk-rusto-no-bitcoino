"""Generate hosted-only WOTS cases for two proof-derived outer sumcheck rounds.

The source is the independently pinned retained proof, verifier metadata and
capture. No replay receipt authorizes a graph. The factory replays the typed
inputs afresh. This command generates no WOTS keys/signatures and measures no
signature-inclusive Script footprint; the existing hosted Rust registry runner
must compile and execute the resulting authenticated cases separately.
"""
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import time

from bench_compact import peak_rss
from script import BASE, limbs
from wots_graph import GraphSpec, authenticated_shape

MAX_CASES, MAX_INPUT_BYTES = 32, 32 << 20
FIXTURES = Path(__file__).resolve().parent/'fixtures'
# Independently pinned retained identities, identical to bench_replay.py.
DIMENSION_PIN = 'de6333df2e41b5f5bae1c103fab862f8d6022fd54abeb80ba61920bc9f360edc'
KEY_PIN = 'c8b117ea587c80bfdbdfc0cc262cdf68b1b4c07b3b45ba871413c7768aa62b9a'
TRACE_PIN = '394d90b302b2fe6b8f5c0a65ada372d820996f3230770a816961a75cefec59b8'
POSEIDON_PIN = 'b55fa125133315243cb299ee7603c5f0508d68abf64f0dab43ecba4a0d09fa67'


def _load_graphs():
    # The caller's hosted resource guard must precede all fixture reads and
    # construction. The sealed factory independently performs strict replay.
    from sumcheck_graph import build_outer_sumcheck_graphs
    from bench_replay import read, strict_json
    from nht4 import bind_container, load_expected_json
    from poseidon_reference import load_parameters_json
    from production_replay import ReplayKeyBindings
    from proof_codec import decode_proof, load_dimensions_json
    expected = load_expected_json(read(FIXTURES/'nht4-genesis-0-2020-k5.expected.json', 1 << 16))
    dims = load_dimensions_json(read(FIXTURES/'nht4-genesis-0-2020-k5.dimensions.json', 1 << 14),
        expected, expected_descriptor_sha256=bytes.fromhex(DIMENSION_PIN))
    bindings = ReplayKeyBindings.from_json(
        strict_json(read(FIXTURES/'nht4-genesis-0-2020-k5.key-bindings.json', 1 << 14)), expected, dims,
        expected_key_bindings_sha256=bytes.fromhex(KEY_PIN))
    parameters = load_parameters_json(read(FIXTURES/'nht4-genesis-0-2020-k5.poseidon.json', 2 << 20),
        expected, dims, expected_parameters_sha256=bytes.fromhex(POSEIDON_PIN))
    trace = strict_json(read(FIXTURES/'nht4-genesis-0-2020-k5.trace.json', 1 << 20))
    proof = bind_container(read(FIXTURES/'nht4-genesis-0-2020-k5.nht4', 1 << 20), expected).proof
    decoded = decode_proof(proof, dims)
    graphs = build_outer_sumcheck_graphs(decoded, expected, bindings, trace,
        expected_trace_sha256=bytes.fromhex(TRACE_PIN), poseidon_parameters=parameters)
    if type(graphs) is not tuple or tuple(graph.role for graph in graphs) != ('primary','secondary'):
        raise ValueError('both ordered proof-derived sumcheck roles required')
    return graphs, expected


def _value(values, wires):
    return sum(values[word] << (29*i) for i, word in enumerate(wires))


def _set_field(values, wires, value):
    changed = dict(values)
    for word, digit in zip(wires, limbs(value), strict=True):
        changed[word] = digit
    return changed


def _truth(program, spec, values, ordinal):
    """True/False predicate result, or None for a kernel VERIFY precondition.

    WOTS bounds produce a false validity flag before entering a predicate.
    In contrast, add/mul_bit require canonical x/y with VERIFY inside their
    bodies: an out-of-domain operand aborts correctness AND disproof Scripts.
    The existing Rust boolean Check format cannot encode that third outcome.
    """
    leaf = spec.leaves[ordinal]
    if any(type(values[spec.words[index][0]]) is not int
           or not 0 <= values[spec.words[index][0]] < spec.words[index][1]
           for index in leaf.wires):
        return False
    if ordinal < len(program.constraints):
        constraint = program.constraints[ordinal]
        if constraint.kind in ('add','mul_bit'):
            # script.kernel validates canonical INPUTS, not its output field.
            if any(_value(values,constraint.wires[start:start+9]) >= program.p
                   for start in (0,9)):
                return None
        return constraint.native(values, program.p)
    if leaf.kind == 'field_valid':
        return _value(values, tuple(spec.words[index][0] for index in leaf.wires)) < program.p
    if leaf.kind == 'word_valid':
        return True
    raise ValueError('unknown appended graph validity leaf')


def _field_ordinal(program, spec, wires):
    names = [name for name, declared in program.fields if declared == wires]
    if len(names) != 1:
        raise ValueError('source port must have exactly one canonical field declaration')
    return dict(spec.field_leaves)[names[0]]


def _poly(program, values, round_ports):
    p = program.p
    prior = _value(values, round_ports.prior)
    c0, c2, c3 = (_value(values, getattr(round_ports,name)) for name in ('c0','c2','c3'))
    challenge = _value(values, round_ports.challenge)
    c1 = (prior-2*c0-c2-c3) % p
    return (c0+challenge*(c1+challenge*(c2+challenge*c3))) % p


def _coherent_wrong_shared_claim(graph):
    """TEST-ONLY re-witnessing; never seal an altered proof-derived object."""
    from sumcheck_graph import _build_arithmetic
    honest = graph.assignment
    rows = [tuple(_value(honest,getattr(ports,name)) for name in ('c0','c2','c3'))
            for ports in graph.rounds]
    challenges = tuple(_value(honest,ports.challenge) for ports in graph.rounds)
    wrong = (_value(honest,graph.rounds[0].next_claim)+1) % graph.program.p
    program,values,rounds,_ = _build_arithmetic(graph.role,graph.engine,rows,challenges,
        graph.source_sha256,claimed_next=(wrong,None))
    if (program.digest() != graph.program.digest()
            or rounds[0].next_claim != graph.rounds[0].next_claim
            or rounds[1].prior != graph.rounds[1].prior):
        raise ValueError('coherent test re-witnessing changed authenticated graph topology')
    return values


def _coverage(graph, spec):
    program, rounds = graph.program, graph.rounds
    if len(rounds) != 2 or tuple(item.index for item in rounds) != (0,1):
        raise ValueError('exactly adjacent outer rounds 0 and 1 required')
    shared = rounds[0].next_claim
    initial = graph.ports['initial/claim']
    if shared != rounds[1].prior or initial != rounds[0].prior:
        raise ValueError('round claims must use identical authenticated wire tuples')
    original = program.constraints
    shared_refs = [i for i,c in enumerate(original) if set(shared).intersection(c.wires)]
    initial_refs = [i for i,c in enumerate(original) if set(initial).intersection(c.wires)]
    anchors = [i for i,c in enumerate(original) if c.kind == 'const'
               and c.argument == (0,) and len(c.wires) == 1 and c.wires[0] in initial]
    if (len(anchors) != 9 or {original[i].wires[0] for i in anchors} != set(initial)
            or rounds[0].output_constraint not in shared_refs
            or not any(i != rounds[0].output_constraint for i in shared_refs)):
        raise ValueError('missing explicit zero anchor or shared round boundary')
    seen, representatives = set(), []
    for ordinal, leaf in enumerate(spec.leaves):
        shape = authenticated_shape(spec, leaf)
        if shape not in seen:
            representatives.append(ordinal)
            seen.add(shape)
    selected = sorted(set(representatives+shared_refs+initial_refs+anchors+
        [round_ports.output_constraint for round_ports in rounds]+
        [_field_ordinal(program,spec,shared),_field_ordinal(program,spec,initial)]))
    alias = [i for i in representatives if len(set(spec.leaves[i].wires)) != len(spec.leaves[i].wires)]
    if any(len(set(leaf.wires)) != len(leaf.wires) for leaf in spec.leaves) and not alias:
        raise ValueError('alias authentication shape omitted from selected execution')
    columns = [c for c in original if c.kind == 'conv_column']
    if len(columns) != 6*64:
        raise ValueError('two cubic rounds must expose six complete convolution products')
    incoming,outgoing = set(),set()
    for column in columns:
        offset = column.argument[0]+column.argument[1]
        incoming.add(column.wires[offset])
        outgoing.add(column.wires[offset+1])
    carry_links = len(incoming.intersection(outgoing))
    if carry_links != 6*63:
        raise ValueError('convolution products must share every adjacent integer carry')
    kinds = sorted({leaf.kind for leaf in spec.leaves})
    return selected, {'authenticated_shapes':len(representatives),'alias_shape_ordinals':alias,
        'authenticated_kinds':kinds,'convolution_products':len(columns)//64,
        'shared_convolution_carry_links':carry_links,
        'shape_ordinals':representatives,'shared_claim_words':list(shared),
        'shared_claim_constraint_ordinals':shared_refs,'initial_claim_words':list(initial),
        'initial_claim_constraint_ordinals':initial_refs,'initial_zero_anchor_ordinals':anchors,
        'output_constraint_ordinals':[item.output_constraint for item in rounds],
        'shared_field_validity_ordinal':_field_ordinal(program,spec,shared),
        'initial_field_validity_ordinal':_field_ordinal(program,spec,initial)}


def _cases_for_graph(graph, census, diagnostics):
    program = graph.program
    honest = graph.assignment
    spec = GraphSpec.from_program(program)
    shape, digest = spec.json(), spec.digest().hex()
    if graph.source_sha256 != program.context:
        raise ValueError('proof provenance differs from authenticated graph context')
    selected, coverage = _coverage(graph,spec)
    if any(not _truth(program,spec,honest,i) for i in range(len(spec.leaves))):
        raise ValueError('proof-derived honest graph has a false authenticated constraint')
    for ports in graph.rounds:
        if _poly(program,honest,ports) != _value(honest,ports.next_claim):
            raise ValueError('independent cubic field equality disagrees with replay-derived graph')
    initial = graph.ports['initial/claim']
    if _value(honest,initial) != 0:
        raise ValueError('outer initial claim must be anchored to zero')

    def emit(suffix,values,checks,reason,measure=False,excluded_aborts=()):
        if len({item['ordinal'] for item in checks}) != len(checks):
            raise ValueError('duplicate native execution check')
        for item in checks:
            if _truth(program,spec,values,item['ordinal']) != item['expected_correct']:
                raise ValueError('adversarial expectation disagrees with authenticated reference')
        if set(values) != {word for word,_ in spec.words}:
            raise ValueError('mutation changed graph assignment topology')
        words = [values[word] for word,_ in spec.words]
        if any(type(value) is not int or not 0 <= value <= 0xffffffff for value in words):
            raise ValueError('Rust WOTS cases require exact unsigned32 words')
        name = f'{graph.role}/{suffix}'
        diagnostics.append({'name':name,'reason':reason,'expected_false_ordinals':
            [item['ordinal'] for item in checks if not item['expected_correct']],
            'expected_true_ordinals':[item['ordinal'] for item in checks if item['expected_correct']],
            'kernel_verify_abort_ordinals_excluded':list(excluded_aborts)})
        return {'name':name,'spec':shape,'expected_spec_id':digest,'words':words,
                'checks':checks,'measure_all':measure}

    census.append({'role':graph.role,'engine':graph.engine,'field_role':program.field_role,
        'graph':graph.summary(),
        'source_sha256':graph.source_sha256.hex(),'sources':graph.sources,
        'program_sha256':program.digest().hex(),'catalogue_sha256':digest,
        'words':len(spec.words),'original_constraints':len(program.constraints),
        'field_validity_leaves':len(spec.field_leaves),'authenticated_leaves':len(spec.leaves),
        'predicate_bodies':len(spec.bodies),'selected_truth_leaves':len(selected),**coverage})
    yield emit('sumcheck-two-outer-rounds',honest,
        [{'ordinal':i,'expected_correct':True} for i in selected],
        'every distinct authenticated shape and alias, all shared-boundary uses and all zero anchors',True)

    mutations = []
    def field_mutation(suffix,wires,value,reason,required_false=(),required_true=(),single=False,
                       require_original=True):
        mutations.append((suffix,_set_field(honest,wires,value),reason,
                          tuple(required_false),tuple(required_true),single,require_original))
    shared = graph.rounds[0].next_claim
    field_mutation('sumcheck-broken-shared-claim',shared,(_value(honest,shared)+1)%program.p,
        'the exact same round0-next/round1-prior field changes at both authenticated uses',
        [graph.rounds[0].output_constraint])
    field_mutation('sumcheck-nonzero-initial-anchor',initial,1,
        'outer initial zero anchor cannot float independently')
    for kind,wires in [('coefficient',graph.rounds[0].c0),('challenge',graph.rounds[0].challenge)]:
        field_mutation('sumcheck-wrong-'+kind,wires,(_value(honest,wires)+1)%program.p,
            'proof/transcript source port changed while arithmetic auxiliaries remain authenticated')
    final = graph.rounds[1].next_claim
    field_mutation('sumcheck-coherent-wrong-next',final,(_value(honest,final)+1)%program.p,
        'every arithmetic auxiliary is honest; exactly the final output equality is false',
        [graph.rounds[1].output_constraint],[_field_ordinal(program,spec,final)],True)
    mutations.append(('sumcheck-coherent-wrong-shared-claim',_coherent_wrong_shared_claim(graph),
        'round1 is coherently re-witnessed from the changed shared claim; only round0 equality is false',
        (graph.rounds[0].output_constraint,),
        (graph.rounds[1].output_constraint,_field_ordinal(program,spec,shared)),True,True))
    source = graph.rounds[0].c0
    source_valid = _field_ordinal(program,spec,source)
    for suffix,value in [('modulus',program.p),('modulus-plus-one',program.p+1)]:
        field_mutation('sumcheck-noncanonical-'+suffix,source,value,
            'unsigned authenticated limbs encode a noncanonical field value', [source_valid],
            require_original=False)
    oversized = dict(honest)
    oversized[source[0]] = 0xffffffff
    mutations.append(('sumcheck-oversized-field-limb',oversized,
        'unsigned32 WOTS word exceeds its declared29-bit bound', (source_valid,),(),False,True))

    for suffix,values,reason,required_false,required_true,single,require_original in mutations:
        statuses = [_truth(program,spec,values,i) for i in range(len(spec.leaves))]
        false = [i for i,status in enumerate(statuses) if status is False]
        aborted = [i for i,status in enumerate(statuses) if status is None]
        original_false = [i for i in false if i < len(program.constraints)]
        if (not false or (require_original and (not original_false or aborted))
                or any(i not in false for i in required_false)):
            raise ValueError('negative assignment has no required real refuting constraint')
        if single and original_false != list(required_false):
            raise ValueError('coherent wrong next must refute exactly one original equality')
        checks = [{'ordinal':i,'expected_correct':False} for i in false]
        checks += [{'ordinal':i,'expected_correct':True} for i in required_true]
        if not original_false:
            # Canonical-input kernel VERIFY failures are outside the boolean
            # Check domain. Preserve their metadata, and execute unaffected
            # original shapes alongside the actual field-validity disproof.
            checks += [{'ordinal':i,'expected_correct':True}
                       for i in coverage['shape_ordinals']
                       if i < len(program.constraints) and statuses[i] is True]
        yield emit(suffix,values,checks,reason,excluded_aborts=aborted)


def _write_cases(cases,path):
    """Stream a complete bounded JSON array, hashing exactly the emitted bytes."""
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
                    raise ValueError('sumcheck registry inputs exceed32MiB')
                output.write(raw)
                digest.update(raw)
                total += len(raw)
            write(b'[')
            for case in cases:
                count += 1
                if count > MAX_CASES:
                    raise ValueError('sumcheck registry case bound')
                if count > 1:
                    write(b',')
                for fragment in encoder.iterencode(case):
                    write(fragment.encode('ascii'))
            if not count:
                raise ValueError('nonempty sumcheck registry cases required')
            write(b']\n')
        temporary.replace(path)
    except BaseException:
        if created:
            temporary.unlink(missing_ok=True)
        raise
    return {'cases':count,'input_bytes':total,'input_sha256':digest.hexdigest()}


def run(inputs):
    if os.environ.get('GITHUB_ACTIONS') != 'true':
        raise ValueError('actual sumcheck graph generation is hosted-GitHub-Actions-only')
    started = time.perf_counter()
    graphs,expected = _load_graphs()
    census,diagnostics = [],[]
    normal_checks,signatures,measured = 0,0,0
    def cases():
        nonlocal normal_checks,signatures,measured
        for graph in graphs:
            for case in _cases_for_graph(graph,census,diagnostics):
                normal_checks += len(case['checks'])
                signatures += len(case['words'])
                measured += int(case['measure_all'])
                yield case
    written = _write_cases(cases(),inputs)
    guard_vectors = sum(14*len(row['authenticated_kinds']) for row in census)
    if measured != 2 or len(census) != 2:
        raise ValueError('exactly two complete honest catalogues must be measured')
    return {'schema':'bitvm2-nova-sumcheck-graph-generation/v1',**written,
        'proof_sha256':expected.proof_sha256.hex(),'verifier_key_sha256':expected.verifier_key_sha256.hex(),
        'verifier_dimensions_sha256':DIMENSION_PIN,'key_bindings_sha256':KEY_PIN,
        'trace_sha256':TRACE_PIN,'poseidon_parameters_sha256':POSEIDON_PIN,
        'census':census,'diagnostics':diagnostics,'complete_graphs_to_measure':2,
        'expected_normal_leaf_checks':normal_checks,
        'expected_witness_and_authentication_guard_vectors':guard_vectors,
        'expected_registry_vectors':2*normal_checks+guard_vectors,
        'expected_script_rejections':normal_checks+guard_vectors,
        'expected_assertion_signatures':signatures,
        'expected_native_catalogue_rejections':27*measured,
        'expected_sumcheck_fragments':measured,
        'expected_shared_sumcheck_claim_links':sum(len(row['shared_claim_words']) for row in census),
        'expected_shared_convolution_carry_links':sum(row['shared_convolution_carry_links'] for row in census),
        'outer_rounds_per_graph':2,'strict_replay_performed_by_factory':True,
        'replay_receipt_loaded':False,'native_proofs_verified_by_this_command':0,
        'wots_script_bytes_measured':False,'fixed_claim_cost_measured':False,
        'wots_signatures_generated':0,'native_scripts_executed':0,
        'proof_verified':False,'bitvm2_script_verified':False,'complete_bitvm2_verifier':False,
        'source_ports_script_bound':False,'challenge_script_binding':False,
        'proof_parser_script_binding':False,
        'taproot_assertion_binding':False,'bitcoin_transaction_graph':False,
        'setup_calls':0,'proving_jobs':0,'transactions_broadcast':0,
        'generation_seconds':time.perf_counter()-started,'python_peak_rss_bytes':peak_rss(),
        'platform':platform.platform(),'hosted_resource_guard_satisfied':True,
        'scope':'two retained proof-derived outer-round graphs; cost and authenticated execution require the separate native runner'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inputs',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args = parser.parse_args()
    if args.inputs.resolve() == args.output.resolve():
        raise ValueError('input corpus and generation report paths must differ')
    report = run(args.inputs)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(report,indent=2)+'\n',encoding='ascii',newline='\n')
    print(json.dumps(report))


if __name__ == '__main__':
    main()
