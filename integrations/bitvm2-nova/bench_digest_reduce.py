"""Hosted claimed-digest-bit connectivity and reduction fixture generation.

The separate mature-field and authenticated Script workers execute these inputs.
This command builds fixtures only. In particular, its digest bits are claims,
not outputs authenticated to a Keccak transcript or a Nova proof in Script.
"""
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import time

from bench_compact import peak_rss
from bench_keccak_permutation import _write_json

CONTEXT = sha256(b'BITVM2-NOVA/DIGEST-REDUCTION-CONNECTIVITY-CONFORMANCE/v1').digest()
OPERATION = 'benchmark/digest/reduce512'
TRACE_SHA256 = '394d90b302b2fe6b8f5c0a65ada372d820996f3230770a816961a75cefec59b8'
TRACE_FILE = Path(__file__).resolve().parent/'fixtures'/'nht4-genesis-0-2020-k5.trace.json'
MAX_CASES, MAX_INPUT_BYTES = 64, 32 << 20
EXPECTED_WORDS, EXPECTED_LEAVES = 955, 373
BASELINE_WORDS, BASELINE_LEAVES = 379, 245


def _guard():
    if (os.environ.get('GITHUB_ACTIONS') != 'true'
            or os.environ.get('RUNNER_OS') != 'Linux' or sys.platform != 'linux'):
        raise ValueError('digest reduction graph fixtures are hosted GitHub Linux only')


def _retained_input():
    """Recompute two Keccak halves for a literal-pinned retained trace event.

    This gives a reproducible public fixture input, not transcript verification
    or proof authority. The complete transcript still has separate boundaries.
    """
    from production_transcript import keccak256
    from script import Q
    with TRACE_FILE.open('rb') as stream:
        raw = stream.read((1 << 20)+1)
    if len(raw) > 1 << 20 or sha256(raw).hexdigest() != TRACE_SHA256:
        raise ValueError('retained digest fixture trace differs from literal pin')
    trace = json.loads(raw)
    streams = [item for item in trace['streams'] if item['kind'] == 'keccak'
               and item['engine'] == 'pallas' and item['session'] == 0]
    if len(streams) != 1:
        raise ValueError('one pinned primary transcript stream required')
    previous, event = streams[0]['events'][102:104]
    if (event['sequence'] != 103 or event['op'] != 'squeeze' or event['label_hex'] != '72'
            or previous['sequence'] != 102):
        raise ValueError('retained rho squeeze event changed')
    before = previous['after']
    message = (bytes.fromhex(before['buffer_hex'])+b'NoDS'
               +before['round'].to_bytes(8, 'little')+bytes.fromhex(before['state_hex'])+b'r')
    wide = keccak256(message+b'\0')+keccak256(message+b'\1')
    challenge = (int.from_bytes(wide, 'little') % Q).to_bytes(32, 'little').hex()
    if (wide.hex() != event['after']['state_hex'] or event['after']['buffer_hex'] != ''
            or event['after']['round'] != before['round']+1 or challenge != event['challenge_le']):
        raise ValueError('independent retained rho Keccak/update reduction mismatch')
    return wide, dict(trace_sha256=TRACE_SHA256, engine='pallas', session=0,
        event_sequence=103, label_hex='72', input_le=wide.hex(), pallas_scalar_result_le=challenge,
        digest_fixture_recomputed=True, transcript_verified_by_this_command=False,
        digest_source_script_bound=False)


def _truth(program, spec, values, ordinal):
    """Independent bit equation plus existing reduction arithmetic reference.

    Out-of-range authenticated values produce the WOTS decoder's false flag;
    they do not count as successful canonical-encoding admission.
    """
    leaf = spec.leaves[ordinal]
    if any(type(values[spec.words[i][0]]) is not int
           or not 0 <= values[spec.words[i][0]] < spec.words[i][1] for i in leaf.wires):
        return False
    if leaf.kind == 'bits':
        operands = [values[spec.words[i][0]] for i in leaf.wires]
        if leaf.argument != (8,) or len(operands) != 9:
            raise ValueError('exact eight-bit bridge predicate required')
        return all(bit in (0, 1) for bit in operands[1:]) and operands[0] == sum(
            bit << (7-i) for i, bit in enumerate(operands[1:]))
    from bench_uniform_reduce import _truth as uniform_truth
    return uniform_truth(program, spec, values, ordinal)


def _case(name, graph, values, *, measure_all=False, select_all=False):
    from wots_graph import GraphSpec, authenticated_shape
    program = graph.program
    spec = graph.spec if hasattr(graph, 'spec') else GraphSpec.from_program(program)
    if set(values) != {name for name, _ in spec.words}:
        raise ValueError('diagnostic assignment changed topology')
    if any(type(value) is not int or not 0 <= value <= 0xffffffff for value in values.values()):
        raise ValueError('registry signer requires unsigned32 assignment words')
    false = [i for i in range(len(spec.leaves)) if not _truth(program, spec, values, i)]
    if measure_all or select_all:
        selected = set(range(len(spec.leaves)))
    else:
        selected, seen = set(false), set()
        for ordinal, leaf in enumerate(spec.leaves):
            shape = authenticated_shape(spec, leaf)
            if shape not in seen:
                selected.add(ordinal)
                seen.add(shape)
    return dict(name=name, spec=spec.json(), expected_spec_id=spec.digest().hex(),
        words=[values[word] for word, _ in spec.words], measure_all=measure_all,
        checks=[dict(ordinal=i, expected_correct=i not in false) for i in sorted(selected)]), false


def _coverage(graph):
    from wots_graph import GraphSpec
    spec, child = graph.spec, GraphSpec.from_program(graph.uniform.program)
    if ((len(spec.words), len(spec.leaves)) != (EXPECTED_WORDS, EXPECTED_LEAVES)
            or (len(child.words), len(child.leaves)) != (BASELINE_WORDS, BASELINE_LEAVES)):
        raise ValueError('digest/uniform exact word/leaf census changed')
    mapping = tuple(graph.uniform_leaf_map)
    if mapping != tuple(range(244))+(372,):
        raise ValueError('all245 original uniform leaf occurrences must survive')
    for before, after in enumerate(mapping):
        if child.leaves[before] != spec.leaves[after]:
            raise ValueError('an original uniform predicate/alias/body changed')
    ports = graph.ports
    bits, auxiliaries, bytes_ = ports['digest_bits'], ports['byte_auxiliaries'], ports['input_bytes']
    if (len(bits) != 512 or len(set(bits)) != 512 or len(auxiliaries) != 64
            or len(set(auxiliaries)) != 64 or len(bytes_) != 64
            or tuple(graph.bridge_bit_constraints) != tuple(244+2*i for i in range(64))
            or tuple(graph.bridge_byte_constraints) != tuple(245+2*i for i in range(64))):
        raise ValueError('ordered digest-bit/auxiliary/byte port census changed')
    indices = {word: i for i, (word, _) in enumerate(spec.words)}
    for i in range(64):
        byte_bits = tuple(ports['byte_bits'][i])
        expected = tuple(bits[8*i:8*i+8])
        producer = spec.leaves[graph.bridge_bit_constraints[i]]
        consumer = spec.leaves[graph.bridge_byte_constraints[i]]
        if (byte_bits != expected or producer.kind != 'bits' or producer.argument != (8,)
                or producer.wires != tuple(indices[word] for word in (auxiliaries[i],)+tuple(reversed(byte_bits)))
                or consumer.kind != 'conv_reconstruct' or consumer.argument != (8,)
                or consumer.wires != (indices[auxiliaries[i]], indices[bytes_[i]])
                or spec.words[indices[auxiliaries[i]]][1] != 1 << 29
                or spec.words[indices[bytes_[i]]][1] != 256
                or any(spec.words[indices[word]][1] != 2 for word in byte_bits)):
            raise ValueError('digest bridge ordered occurrence/bound equation changed')
    return dict(words=len(spec.words), leaves=len(spec.leaves), uniform_words=len(child.words),
                uniform_leaves=len(child.leaves), preserved_uniform_leaves=len(mapping),
                bridge_bit_leaves=64, bridge_byte_leaves=64, claimed_digest_bits=512,
                byte_auxiliaries=64, canonical_result_fields=1,
                shared_digest_byte_links=128, new_bridge_words=576, new_bridge_leaves=128)


def _same_topology(first, second):
    if (first.program.digest() != second.program.digest()
            or first.spec.digest() != second.spec.digest() or first.ports != second.ports):
        raise ValueError('claim substitution changed the supposedly value-free topology')


def _coherent_assignment(original, changed, *, restore_auxiliaries):
    _same_topology(original, changed)
    honest, values, ports = original.assignment, changed.assignment, original.ports
    words = tuple(ports['digest_bits'])
    if restore_auxiliaries:
        words += tuple(ports['byte_auxiliaries'])
    for word in words:
        values[word] = honest[word]
    return values


def generate():
    _guard()  # Before any fixture I/O, graph import or construction.
    from digest_reduce import build_digest_reduction
    from trace import ROLES
    from bench_uniform_reduce import _oracle_case
    retained, retained_source = _retained_input()
    pattern = bytes((37*i+11) & 255 for i in range(64))
    cases, oracle, diagnostics, measured, comparisons = [], [], [], [], []
    coverage = None
    for role in ('pallas_scalar', 'vesta_scalar'):
        for label, raw in (('zero', bytes(64)), ('max512', bytes([255])*64),
                           ('retained-rho', retained), ('pattern', pattern)):
            graph = build_digest_reduction(raw[:32], raw[32:], role=role,
                                            context=CONTEXT, operation_id=OPERATION)
            current = _coverage(graph)
            if coverage is not None and current != coverage:
                raise ValueError('both roles require identical declared bridge coverage')
            coverage = current
            name = f'{role}/digest-reduce512' if label == 'max512' else f'{role}/digest-edge-{label}'
            case, false = _case(name, graph, graph.assignment, measure_all=label == 'max512')
            if false:
                raise ValueError('honest claimed-digest reduction has a false predicate')
            cases.append(case)
            oracle.append(_oracle_case(name, role, raw, ROLES[role]))
            if label == 'max512':
                baseline_name = f'{role}/uniform-reduce512'
                baseline, baseline_false = _case(baseline_name, graph.uniform,
                                                graph.uniform.assignment, measure_all=True)
                if baseline_false:
                    raise ValueError('same-child standalone uniform baseline has a false predicate')
                cases.append(baseline)
                oracle.append(_oracle_case(baseline_name, role, raw, ROLES[role]))
                for kind, item in (('digest', case), ('uniform', baseline)):
                    measured.append(dict(case=item['name'], kind=kind, field_role=role,
                        catalogue_id=item['expected_spec_id'], words=len(item['words']),
                        leaves=len(item['spec']['leaves']), executed_leaf_checks=len(item['checks'])))
                comparisons.append(dict(field_role=role, baseline_case=baseline_name,
                    candidate_case=name, child_context_sha256=graph.uniform.program.context.hex(),
                    child_operation_id=graph.uniform.program.operation_id,
                    child_program_sha256=graph.uniform.program.digest().hex(),
                    additional_words=576, additional_leaves=128,
                    script_bytes_measured=False, signature_bytes_measured=False))
            del graph, case

        graph = build_digest_reduction(pattern[:32], pattern[32:], role=role,
                                        context=CONTEXT, operation_id=OPERATION)
        honest, ports = graph.assignment, graph.ports

        def add(label, values, expected, reason):
            # Full ordered execution is separate from measuring the complete
            # leaf stream: these six coherent attacks create no extra ledger.
            case, false = _case(f'{role}/digest-attack-{label}', graph, values,
                                select_all=label.startswith('coherent-'))
            if false != list(expected) or not false:
                raise ValueError(f'digest diagnostic {label} failed at unexpected predicates: {false}')
            cases.append(case)
            diagnostics.append(dict(case=case['name'], reason=reason, false_predicates=false,
                catalogue_id=case['expected_spec_id'], topology_matches_honest=True))

        values = dict(honest)
        values[ports['digest_bits'][0]] ^= 1
        add('bits-only', values, [244], 'one claimed bit changes; byte/reduction auxiliaries remain honest')
        values = dict(honest)
        values[ports['byte_auxiliaries'][0]] ^= 1
        add('byte-aux-only', values, [244, 245], 'one shared auxiliary disagrees with both source bits and byte')
        for label, byte_index, restore_aux, expected in (
                ('coherent-low', 0, True, [245]), ('coherent-high', 32, True, [309]),
                ('coherent-producer', 0, False, [244])):
            changed_input = bytearray(pattern)
            changed_input[byte_index] ^= 1
            changed = build_digest_reduction(bytes(changed_input[:32]), bytes(changed_input[32:]),
                role=role, context=CONTEXT, operation_id=OPERATION)
            values = _coherent_assignment(graph, changed, restore_auxiliaries=restore_aux)
            add(label, values, expected, 'changed input and full arithmetic rewitness; original claimed source bits retained')
            del changed
        swapped = build_digest_reduction(pattern[32:], pattern[:32], role=role,
                                          context=CONTEXT, operation_id=OPERATION)
        values = _coherent_assignment(graph, swapped, restore_auxiliaries=True)
        expected = [245+2*i for i in range(64) if pattern[i] != pattern[(i+32) % 64]]
        add('swapped-halves', values, expected, 'swapped LO/HI arithmetic cannot consume the original ordered digest bits')
        del swapped
        values, expected = dict(honest), []
        for i, words in enumerate(ports['byte_bits']):
            for word, reversed_word in zip(words, reversed(words), strict=True):
                values[word] = honest[reversed_word]
            if pattern[i] != int(f'{pattern[i]:08b}'[::-1], 2):
                expected.append(244+2*i)
        add('reversed-bits', values, expected, 'reverse each byte bit order while keeping its original numeric byte')
        for label, word, value, expected in (
                ('bit-two', ports['digest_bits'][0], 2, [244]),
                ('bit-u32max', ports['digest_bits'][0], 0xffffffff, [244]),
                ('aux-u32max', ports['byte_auxiliaries'][0], 0xffffffff, [244, 245])):
            values = dict(honest)
            values[word] = value
            add(label, values, expected, 'signed unsigned32 word exceeds its authenticated port bound')
        del graph
    if len(cases) != 30 or len(cases) > MAX_CASES or len(oracle) != 10 or len(measured) != 4:
        raise ValueError('exact bounded two-role digest fixture census changed')
    checks = sum(len(case['checks']) for case in cases)
    guards = sum(14*(len({leaf['kind'] for leaf in case['spec']['leaves']})
                    +int(case['name'].endswith('/digest-reduce512')))
                 for case in cases if case['measure_all'])
    if guards != 448:
        raise ValueError('expected every predicate kind plus BYTE bridge decoder-shape guard')
    return cases, dict(schema='bitvm2-nova-uniform-reduce-input/v1', cases=oracle), dict(
        cases=len(cases), mature_oracle_cases=len(oracle), measured=measured,
        comparisons=comparisons, diagnostics=diagnostics, coverage=coverage,
        retained_source=retained_source, expected_native_rejections=132,
        expected_digest_layout_rejections=24, expected_shared_carry_links=256,
        expected_shared_digest_byte_links=256, expected_digest_reduction_fragments=2,
        expected_digest_reduction_disproofs=6,
        expected_full_coherent_graphs_executed=6, expected_full_coherent_leaf_checks=6*373,
        expected_signatures=sum(len(case['words']) for case in cases),
        expected_vectors=2*checks+guards, expected_rejections=checks+guards,
        expected_guard_vectors=guards, expected_selected_leaf_checks=checks)


def _owned_file(path):
    cwd = Path.cwd().resolve()
    owner, target = (cwd/'results').resolve(), Path(path).resolve()
    if owner == cwd or not owner.is_relative_to(cwd) or target == owner or not target.is_relative_to(owner):
        raise ValueError('new digest fixture files must stay beneath canonical cwd/results')
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        raise ValueError('digest fixture output already exists')
    return target


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inputs', type=Path, required=True)
    parser.add_argument('--oracle-inputs', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    _guard()  # Before requested-path I/O.
    started = time.perf_counter()
    paths = tuple(_owned_file(path) for path in (args.inputs, args.oracle_inputs, args.output))
    if len(set(paths)) != 3:
        raise ValueError('three distinct digest reduction output files required')
    cases, oracle, census = generate()
    corpus = _write_json(paths[0], cases, MAX_INPUT_BYTES)
    oracle_info = _write_json(paths[1], oracle, 64 << 10)
    report = dict(schema='bitvm2-nova-digest-reduce-generation/v1', **census,
        corpus=corpus, oracle_input=oracle_info, field_context_sha256=CONTEXT.hex(), operation_id=OPERATION,
        graph_generation_only=True, claimed_digest_bits_connected_to_reduction_graph=True,
        wots_signatures_generated=0, native_worker_executed=False, native_scripts_executed=0,
        wots_script_bytes_measured=False, fixed_claim_cost_measured=False,
        source_bytes_script_bound=False, keccak_output_script_bound=False,
        keccak_origin_script_bound=False, full_keccak_verified=False,
        full_permutation_verified=False, full_hash_verified=False, hash_verified=False,
        padding_bound_in_script=False, absorption_bound_in_script=False, squeeze_bound_in_script=False,
        transcript_verified=False, nova_transcript_verified=False, proof_parser_script_binding=False,
        proof_verified=False, bitvm2_script_verified=False, complete_bitvm2_verifier=False,
        production_assertion_binding=False, bitcoin_transaction_graph=False,
        transactions_broadcast=0, proving_jobs=0,
        wall_seconds=time.perf_counter()-started, parent_peak_rss_bytes=peak_rss())
    _write_json(paths[2], report, 1 << 20)
    print(json.dumps(report))


if __name__ == '__main__':
    main()
