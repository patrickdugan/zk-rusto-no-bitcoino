"""Measure ONE round and emit bounded independent-engine fixtures, no proving.

Fixed-claim Script totals use the same BoundTrace accounting as M2: actual
serialized disproof Script bytes, including opening hashes, program/claim tags
and exact-witness-length guards. Totals exclude transaction framing, control
blocks and assertion signatures. WOTS registry costs need the separate Rust
oracle; this script emits selected-check registry cases without local key work.
"""
import argparse
from collections import Counter
from hashlib import sha256
import itertools
import json
from pathlib import Path
import time

from bench_compact import peak_rss
from keccak_trace import MASK64, ROUND_CONSTANTS, keccak_f1600_round, keccak_round_trace, state_from_bit_wires
from script import P, execute, num
from trace_kernels import compile_predicate
from wots_graph import GraphSpec


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, default=Path(__file__).resolve().parent/'results')
    parser.add_argument('--round', type=int, default=23, dest='round_index')
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    start = time.perf_counter()
    state = tuple((i*0x0123456789abcdef ^ (1 << (i % 64))) & MASK64 for i in range(25))
    program, values = keccak_round_trace(state, args.round_index,
        context=sha256(b'Keccak-one-round-benchmark/v1').digest(), operation_id='benchmark/keccak')
    bound = program.bind(values)
    if bound.failures() or state_from_bit_wires(values, 'keccak/out') != keccak_f1600_round(state, args.round_index):
        raise AssertionError('honest round does not match native reference')
    counts = Counter(c.kind for c in program.constraints)
    total, largest = 0, 0
    for i in range(len(program.constraints)):
        length = len(bound.script(i))
        total += length
        largest = max(largest, length)
    selected = []
    for stage in ('c/', 'd/', 't/', 'chi/n/', 'chi/a/', 'chi/x/', 'iota/', 'zero'):
        prefix = f'keccak/r{args.round_index}/{stage}'
        selected.append(next(i for i, c in enumerate(program.constraints) if c.wires[-1].startswith(prefix)))
    selected += [len(program.constraints)-1600, len(program.constraints)-1]
    selected = sorted(set(selected))
    vectors, rejections, peak_stack = 0, 0, 0
    stream = sha256()
    with (args.out/'keccak-engine-vectors.jsonl').open('w', encoding='ascii', newline='\n') as out:
        def emit(name, code, ws, expected):
            nonlocal vectors, rejections, peak_stack
            result = execute(code, ws)
            if result.success != expected:
                raise AssertionError((name, expected, result))
            peak_stack = max(peak_stack, result.peak_stack)
            row = json.dumps({'name': name, 'script_hex': code.hex(),
                'witness_hex': [w.hex() for w in ws], 'expected_success': expected}, separators=(',', ':'))+'\n'
            out.write(row)
            stream.update(row.encode('ascii'))
            vectors += 1
            rejections += int(not expected)
        for i in selected:
            ws = bound.witness(i)
            for disprove in (False, True):
                code = bound.script(i, disprove=disprove)
                emit(f'round/{i}/honest/{disprove}', code, ws, not disprove)
                for label, malformed in (('empty', ()), ('truncated', ws[:-1]),
                                         ('prepended', (b'',)+ws), ('appended', ws+(b'',))):
                    emit(f'round/{i}/{label}/{disprove}', code, malformed, False)
                for j in range(len(ws)):
                    wrong = list(ws)
                    wrong[j] = b'\x01' if ws[j] == b'' else b''
                    emit(f'round/{i}/wrong-opening/{j}/{disprove}', code, wrong, False)
            bad = dict(values)
            bad[program.constraints[i].wires[-1]] ^= 1
            false_claim = program.bind(bad)
            emit(f'round/{i}/false-claim-disproof', false_claim.script(i), false_claim.witness(i), True)
        for kind in ('bool_xor', 'bool_and', 'bool_not'):
            arity = 2 if kind == 'bool_not' else 3
            code = compile_predicate(P, kind)
            for v in itertools.product((0, 1), repeat=arity):
                expected = (v[1] == 1-v[0] if kind == 'bool_not' else
                            v[2] == (v[0] ^ v[1] if kind == 'bool_xor' else v[0] & v[1]))
                emit(f'{kind}/truth/{v}', code, tuple(num(x) for x in v), expected)
            for bad in (num(-1), num(2), b'\x00', b'\x80', b'\x01\x00', bytes(5)):
                for i in range(arity):
                    ws = [num(0)] * arity
                    ws[i] = bad
                    emit(f'{kind}/malformed/{bad.hex()}/{i}', code, ws, False)
    spec = GraphSpec.from_program(program)
    # Only selected checks execute WOTS in CI; no full graph signing/key work on
    # the local host. All round wires and ordered leaves are still in the spec.
    # The Rust registry CLI accepts Vec<Case>, hence a JSON ARRAY, rather than
    # the line-oriented ScriptVector format used by the independent executor.
    with (args.out/'keccak-registry-inputs.json').open('w', encoding='ascii', newline='\n') as out:
        out.write('[\n')
        registry_count = 0
        def registry(name, assignment, checks):
            nonlocal registry_count
            if registry_count:
                out.write(',\n')
            out.write(json.dumps({'name': name, 'spec': spec.json(), 'expected_spec_id': spec.digest().hex(),
                'words': [assignment[w] for w, _ in spec.words], 'checks': checks, 'measure_all': False},
                separators=(',', ':')))
            registry_count += 1
        registry('keccak/honest-round', values, [dict(ordinal=i, expected_correct=True) for i in selected])
        bad = dict(values)
        bad[program.constraints[-1].wires[-1]] ^= 1
        registry('keccak/false-output-boundary', bad,
                 [dict(ordinal=len(program.constraints)-1, expected_correct=False)])
        bad = dict(values)
        bad[program.constraints[0].wires[0]] = 2
        registry('keccak/non-Boolean-signed-input', bad, [dict(ordinal=0, expected_correct=False)])
        out.write('\n]\n')
    result = {'schema': 'bitvm2-nova-keccak-one-round-cost/v1', 'round': args.round_index,
        'round_constant_hex': f'{ROUND_CONSTANTS[args.round_index]:016x}', 'manifest': bound.manifest(),
        'constraint_kinds': dict(counts), 'disproof_script_bytes': total, 'largest_disproof_script_bytes': largest,
        'selected_script_peak_stack': peak_stack, 'engine_vectors': vectors, 'engine_expected_rejections': rejections,
        'engine_vectors_sha256': stream.hexdigest(), 'registry_selected_checks': len(selected)+2,
        'registry_words': len(spec.words), 'registry_leaves': len(spec.leaves), 'registry_bodies': len(spec.bodies),
        'wall_seconds': round(time.perf_counter()-start, 3), 'peak_rss_bytes': peak_rss(),
        'accounting': 'Actual fixed-claim disproof Script bytes; excludes transaction framing, control blocks and assertion signatures',
        'boundary': 'One permutation round only. Independent round programs do not authenticate a composed hash. No full transcript verifier or deployability claim.'}
    (args.out/'keccak-cost.json').write_text(json.dumps(result, indent=2)+'\n', encoding='ascii')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
