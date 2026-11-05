"""Generate bounded Nova0.76 sumcheck/upstream conformance inputs, no proving.

Synthetic polynomials exercise actual upstream verification and production
transcript behavior. They are not complete valid Spartan or Nova proofs.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import random

from production_transcript import NovaTranscript
from spartan_checks import (SCALARS, SumcheckShape, batch_initial_claim,
                            batch_terminal, decompress, eq_evaluation, evaluate,
                            fold_sumcheck, inner_terminal, outer_terminal,
                            round_trace, sparse_evaluation)


def encoded(value):
    return value.to_bytes(32, 'little').hex()


def make_case(engine, name, proof, *, claim=17, degree=3, batch=None):
    transcript = NovaTranscript(engine, b'RelaxedR1CSSNARK')
    # Snapshot support is needed to insert this stage after protocol prelude.
    transcript.absorb_scalar(b'vk-test-prelude', 7)
    initial, rounds = claim, len(proof)
    case = {'name': f'{engine}/{name}', 'engine': engine, 'expect': 'accept',
            'proof': [[encoded(x) for x in row] for row in proof],
            'rounds': rounds, 'degree': degree, 'initial_claim': encoded(claim),
            'snapshot': transcript.snapshot()}
    if batch:
        claims, counts, weights = batch
        initial, rounds = batch_initial_claim(claims, counts, weights, SCALARS[engine])
        case.update(batch={'claims': list(map(encoded, claims)), 'rounds': counts,
                           'coefficients': list(map(encoded, weights))}, rounds=rounds)
    result = fold_sumcheck(proof, initial, SumcheckShape(rounds, degree), transcript)
    case.update(expected_final=encoded(result.final_claim),
                challenges=list(map(encoded, result.challenges)),
                expected_snapshot=result.transcript.snapshot(),
                decompressed=[[encoded(x) for x in state.coefficients]
                              for state in result.rounds])
    return case


def inputs():
    rng = random.Random(0x7605CAFE)
    cases, terminals = [], []
    for engine, p in SCALARS.items():
        for degree in (2, 3):
            for rounds in (0, 1, 3, 8, 32):
                proof = [[rng.randrange(p) for _ in range(degree)] for _ in range(rounds)]
                cases.append(make_case(engine, f'd{degree}/n{rounds}', proof, degree=degree))
        cases.append(make_case(engine, 'zero-high-coefficient', [[3, 5, 0]]))
        cases.append(make_case(engine, 'linear-encoded', [[p-1], [0]], degree=2))
        cases.append(make_case(engine, 'unequal-batch', [[2, 3], [5, 7], [11, 13]],
            degree=2, batch=([17, 19, 23], [0, 3, 1], [29, 31, 37])))
        base = make_case(engine, 'rejection-base', [[2, 3]], degree=2)
        mutations = (
            ('empty-polynomial', 'admission', {'proof': [[]]}),
            ('round-count', 'upstream', {'rounds': 2}),
            ('encoded-cubic-zero', 'upstream', {'proof': [[encoded(2), encoded(3), encoded(0)]]}),
            ('noncanonical-coefficient', 'admission', {'proof': [[encoded(p)]]}),
            ('negative-round-count', 'admission', {'rounds': -1}),
            ('too-many-rounds', 'admission', {'rounds': 33}),
            ('bad-degree', 'admission', {'degree': 4}),
            ('terminal-mismatch', 'terminal', {'expected_final': encoded((int.from_bytes(bytes.fromhex(base['expected_final']), 'little')+1) % p)}),
            ('empty-batch', 'admission', {'batch': {'claims': [], 'rounds': [], 'coefficients': []}}),
            ('unequal-batch-lengths', 'admission', {'batch': {'claims': [encoded(1)], 'rounds': [], 'coefficients': [encoded(1)]}}),
            ('bad-snapshot', 'admission', {'snapshot': {'round': 0, 'state': [0]*63}}),
        )
        for name, expectation, change in mutations:
            invalid = copy.deepcopy(base)
            invalid.update(change, name=f'{engine}/{name}', expect=expectation)
            cases.append(invalid)
        tau, rx, ry = [3, 5, 7], [11, 13, 17], [19, 23, 29, 31, 37]
        values = {'tau': tau, 'rx': rx, 'ry': ry, 'az': 41, 'bz': 43, 'cz': 47,
                  'eval_e': 53, 'u': 59, 'a': 61, 'b': 67, 'c': 71,
                  'rho': 73, 'eval_w': 79, 'public_inputs': [83, 89],
                  'batch_evals': [97, 101], 'batch_points': [rx, []],
                  'batch_coefficients': [103, 107]}
        expected = {'eq': eq_evaluation(tau, rx, p),
            'sparse': sparse_evaluation([59, 83, 89], ry[1:], p),
            'outer': outer_terminal(tau, rx, 41, 43, 47, 53, 59, p),
            'inner': inner_terminal(ry, 61, 67, 71, 73, 79, 59, [83, 89], p),
            'batch': batch_terminal([97, 101], [rx, []], rx, [103, 107], p)}
        def convert(value):
            return [convert(x) for x in value] if isinstance(value, list) else encoded(value)
        terminals.append({'engine': engine, 'values': {k: convert(v) for k, v in values.items()},
                          'expected': {k: encoded(v) for k, v in expected.items()}})
    return {'schema': 'nova-0.76-spartan-sumcheck-conformance/v1',
            'source': {'crate': 'nova-snark', 'version': '0.76.0',
                       'crate_sha256': 'c9bb3809a6c70057ea722c1c4fe5097cf29a3479d0b4671f3cddb1d81043bb31',
                       'vcs': '98576efa884072bfe69bfad8f275a3a5cd8754e5'},
            'cases': cases, 'terminals': terminals}


def trace_costs():
    """Same aggregate leaf accounting for existing m2/compact-v1 compilers.

    Includes fixed-claim word hashes, anchors and exact witness length guards;
    excludes tx framing, control blocks and assertion signatures. These are
    synthetic anchored round fixtures, not full proof or Keccak Script graphs.
    """
    costs = []
    for engine, p in SCALARS.items():
        for degree in (2, 3):
            row = [3, 5, 7][:degree]
            final = evaluate(decompress(row, 13, p), 17, p)
            program, values = round_trace(engine, row, 13, 17, final, context=bytes(32))
            bound = program.bind(values)
            costs.append({'engine': engine, 'encoded_degree': degree,
                'leaves': len(program.constraints), 'words': len(program.words),
                'm2_script_bytes': sum(len(bound.script(i)) for i in range(len(program.constraints))),
                'compact_v1_script_bytes': sum(len(bound.script(i, compiler='compact-v1'))
                                               for i in range(len(program.constraints)))})
    return costs


def native_corpus(report):
    """Fold real, already natively verified proof coefficients in test states.

    This is coefficient corpus conformance, NOT that proof's FS transcript
    replay. halo2curves0.9 human-readable scalar serde is canonical LE32 hex;
    src/derive/field/common.rs serialize_deserialize_primefield defines it.
    """
    if (type(report) is not dict or report.get('passed') is not True
            or type(report.get('native')) is not dict
            or report['native'].get('native_nova_proofs_verified') != 1):
        raise ValueError('successful native retained-proof report required')
    components = report['native'].get('proof_components')
    if type(components) is not dict:
        raise ValueError('native proof component export required')
    cases = []
    for component, engine in (('snark_primary', 'pallas'), ('snark_secondary', 'vesta')):
        snark = components.get(component)
        if type(snark) is not dict:
            raise ValueError('both native SNARK components required')
        for stage, degree in (('outer', 3), ('inner', 2), ('batch', 2)):
            sc = snark.get('sc_proof_'+stage)
            if type(sc) is not dict or set(sc) != {'compressed_polys'}:
                raise ValueError('unexpected native sumcheck structure')
            rows = sc['compressed_polys']
            if type(rows) is not list or not 1 <= len(rows) <= 32:
                raise ValueError('bounded nonempty native sumcheck required')
            proof = []
            for row in rows:
                if type(row) is not dict or set(row) != {'coeffs_except_linear_term'}:
                    raise ValueError('unexpected native compressed polynomial structure')
                coefficients = row['coeffs_except_linear_term']
                if type(coefficients) is not list or not 1 <= len(coefficients) <= degree:
                    raise ValueError('native compressed polynomial degree bound')
                decoded = []
                for value in coefficients:
                    if (type(value) is not str or len(value) != 64
                            or any(c not in '0123456789abcdef' for c in value)):
                        raise ValueError('canonical native LE32 scalar hex required')
                    scalar = int.from_bytes(bytes.fromhex(value), 'little')
                    if scalar >= SCALARS[engine]:
                        raise ValueError('noncanonical native scalar')
                    decoded.append(scalar)
                proof.append(decoded)
            case = make_case(engine, 'native-coefficient-corpus/'+stage, proof, degree=degree)
            case['scope'] = 'real-proof coefficients, synthetic initial claim and transcript state'
            cases.append(case)
            tampered = copy.deepcopy(case)
            tampered.update(name=case['name']+'/changed-coefficient', expect='terminal')
            changed = copy.deepcopy(proof)
            changed[0][0] = (changed[0][0]+1) % SCALARS[engine]
            changed_case = make_case(engine, 'changed', changed, degree=degree)
            if changed_case['expected_final'] == case['expected_final']:
                raise ValueError('unexpected changed-coefficient terminal collision')
            tampered['proof'] = changed_case['proof']
            cases.append(tampered)
    return cases


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    parser.add_argument('--native-report', type=Path,
                        help='already verified nht4 oracle report; coefficient corpus only')
    args = parser.parse_args()
    data = inputs()
    if args.native_report:
        if args.native_report.stat().st_size > 2 << 20:
            raise ValueError('native report exceeds 2MiB')
        report = args.native_report.read_bytes()
        data['cases'].extend(native_corpus(json.loads(report)))
        data['source']['native_report_sha256'] = hashlib.sha256(report).hexdigest()
    data['round_arithmetic_costs'] = trace_costs()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(data, separators=(',', ':'))+'\n', encoding='utf-8')
    print(json.dumps({'cases': len(data['cases']), 'terminal_equations': 5*len(data['terminals']),
                      'expected_rejections': sum(c['expect'] != 'accept' for c in data['cases']),
                      'bytes': args.output.stat().st_size, 'proving': False,
                      'round_arithmetic_costs': data['round_arithmetic_costs']}))


if __name__ == '__main__':
    main()
