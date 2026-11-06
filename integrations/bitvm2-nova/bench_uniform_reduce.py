"""Hosted fixtures for an unsigned 512-bit Pasta reduction argument.

Generation is not proof verification. The actual mature field and authenticated
Script workers execute separately in bounded hosted CI; no local graph is built.
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

CONTEXT = sha256(b'BITVM2-NOVA/UNIFORM-512-REDUCTION-CONFORMANCE/v1').digest()
OPERATION = 'benchmark/uniform/reduce512'
RETAINED_WIDE_LE = bytes.fromhex(
    'f04e669b472740ed7e968c559565f0ef1cc9a02bd7265a14380d37f150127006'
    '02a294e6894a96599a22f07296b9b94aa004b4f821ae0435755c5ccfd04bdc7f')
RETAINED_RESULT_LE = '4e248fbe6c6e3f895a93955b53dc406ca32d31d33cdeaa5f25405cfcaec7c23e'
MAX_CASES, MAX_INPUT_BYTES = 64, 32 << 20


def _guard():
    if (os.environ.get('GITHUB_ACTIONS') != 'true'
            or os.environ.get('RUNNER_OS') != 'Linux' or sys.platform != 'linux'):
        raise ValueError('uniform reduction graph fixtures are hosted GitHub Linux only')


def _truth(program, spec, values, ordinal):
    leaf = spec.leaves[ordinal]
    if leaf.kind == 'field_valid':
        return sum(values[spec.words[i][0]] << (29*j)
                   for j, i in enumerate(leaf.wires)) < program.p
    return program.constraints[ordinal].native(values, program.p)


def _case(name, reduction, values, *, measure_all=False):
    from wots_graph import GraphSpec, authenticated_shape
    program = reduction.program
    spec = GraphSpec.from_program(program)
    false = [i for i in range(len(spec.leaves)) if not _truth(program, spec, values, i)]
    if measure_all:
        selected = set(range(len(spec.leaves)))
    else:
        selected, seen = set(false), set()
        for i, leaf in enumerate(spec.leaves):
            shape = authenticated_shape(spec, leaf)
            if shape not in seen:
                selected.add(i)
                seen.add(shape)
    return dict(name=name, spec=spec.json(), expected_spec_id=spec.digest().hex(),
        words=[values[word] for word, _ in spec.words], measure_all=measure_all,
        checks=[dict(ordinal=i, expected_correct=i not in false) for i in sorted(selected)]), false


def _oracle_case(name, role, raw, p):
    result = int.from_bytes(raw, 'little') % p
    return dict(name=name, field_role=role, input_le=raw.hex(),
                expected_le=result.to_bytes(32, 'little').hex())


def _rewitness(reduction, *, result, quotient, initial_signed=0, unit=1,
               terminal_signed=None):
    """Independent integer producer for diagnostic signed assignments only.

    This intentionally permits c=p; the WOTS field-validity leaf must refute it.
    It never changes topology or creates an accepted fixed claim.
    """
    from script import limbs
    values, ports = reduction.assignment, reduction.ports
    for word, digit in zip(ports['result_field'], limbs(result), strict=True):
        values[word] = digit
    for i, word in enumerate(ports['result_bytes']):
        values[word] = (result >> (8*i)) & 255
    for i, word in enumerate(ports['quotient_bytes']):
        values[word] = (quotient >> (8*i)) & 255
    values[ports['constant_one']] = unit
    values[ports['carries'][0]] = 8192+initial_signed
    for constraint in reduction.program.constraints:
        words = constraint.wires
        if constraint.kind == 'conv_split':
            width, = constraint.argument
            values[words[1]] = values[words[0]] & ((1 << width)-1)
            values[words[2]] = values[words[0]] >> width
        elif constraint.kind == 'conv_ab':
            values[words[-1]] = sum(values[words[2*i]]*values[words[2*i+1]]
                                   for i in range(constraint.argument[0]))
        elif constraint.kind == 'conv_pq':
            values[words[-1]] = sum(values[word]*coefficient for word, coefficient
                                   in zip(words[:-1], constraint.argument, strict=True))
        elif constraint.kind == 'conv_column':
            ab, pq, has_result = constraint.argument
            signed = values[words[ab+pq]]-8192
            numerator = (sum(values[word] for word in words[:ab])+signed
                -sum(values[word] for word in words[ab:ab+pq])
                -(values[words[-1]] if has_result else 0))
            values[words[ab+pq+1]] = 8192+numerator//256
    if terminal_signed is not None:
        values[ports['carries'][-1]] = 8192+terminal_signed
    return values


def _owned_file(path):
    cwd = Path.cwd().resolve()
    owner = (cwd/'results').resolve()
    target = Path(path).resolve()
    if (owner == cwd or not owner.is_relative_to(cwd)
            or target == owner or not target.is_relative_to(owner)):
        raise ValueError('new uniform fixture files must stay beneath canonical cwd/results')
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        raise ValueError('uniform fixture output already exists')
    return target


def generate():
    _guard()  # Before importing the graph builder or constructing a Program.
    from trace import ROLES
    from uniform_reduce import build_uniform_reduction
    cases, oracle, diagnostics, measured = [], [], [], []
    for role in ('pallas_scalar', 'vesta_scalar'):
        p = ROLES[role]
        samples = [('zero', bytes(64)), ('below-modulus', (p-1).to_bytes(64, 'little')),
            ('modulus', p.to_bytes(64, 'little')), ('above-modulus', (p+1).to_bytes(64, 'little')),
            ('max512', bytes([255])*64), ('retained-rho', RETAINED_WIDE_LE)]
        for label, raw in samples:
            name = f'{role}/uniform-reduce512' if label == 'max512' else f'{role}/uniform-edge-{label}'
            reduction = build_uniform_reduction(raw, role=role, context=CONTEXT, operation_id=OPERATION)
            case, false = _case(name, reduction, reduction.assignment, measure_all=label == 'max512')
            if false:
                raise ValueError('honest reduction has false native predicates')
            cases.append(case)
            oracle.append(_oracle_case(name, role, raw, p))
            if role == 'pallas_scalar' and label == 'retained-rho':
                if oracle[-1]['expected_le'] != RETAINED_RESULT_LE:
                    raise ValueError('retained Nova uniform reduction reference mismatch')
            if label == 'max512':
                measured.append(dict(case=name, catalogue_id=case['expected_spec_id'],
                    words=len(reduction.program.words), leaves=len(case['spec']['leaves']),
                    fields=len(reduction.program.fields), quotient_bits=(((1 << 512)-1)//p).bit_length()))
            del reduction, case

        def add(label, reduction, values, expected):
            name = f'{role}/uniform-attack-{label}'
            case, false = _case(name, reduction, values)
            if false != expected:
                raise ValueError(f'uniform diagnostic {label} failed at unexpected predicates: {false}')
            cases.append(case)
            diagnostics.append(dict(case=name, false_predicates=false))

        # A coherent wrong starting carry must expose only its const anchor.
        reduction = build_uniform_reduction(bytes(64), role=role, context=CONTEXT,
            operation_id=OPERATION, claimed_result=1, claimed_quotient=0)
        add('initial-carry', reduction,
            _rewitness(reduction, result=1, quotient=0, initial_signed=1),
            [reduction.metadata['initial_anchor_ordinal']])
        # First64 columns express 0=c+p*q-2^512; only overflow row64 refutes.
        carry_q, carry_result = divmod(1 << 512, p)
        reduction = build_uniform_reduction(bytes(64), role=role, context=CONTEXT,
            operation_id=OPERATION, claimed_result=carry_result, claimed_quotient=carry_q)
        add('overflow', reduction, _rewitness(reduction, result=carry_result,
            quotient=carry_q, terminal_signed=0), [reduction.metadata['column_ordinals'][-1]])
        # The multiplication-by-one adapter must not erase a nonzero input.
        reduction = build_uniform_reduction((1).to_bytes(64, 'little'), role=role,
            context=CONTEXT, operation_id=OPERATION, claimed_result=0, claimed_quotient=0)
        add('unit-zero', reduction, _rewitness(reduction, result=0, quotient=0, unit=0),
            [reduction.metadata['unit_anchor_ordinal']])
        # X=p,c=p,q=0 satisfies the integer relation but c must be canonical.
        reduction = build_uniform_reduction(p.to_bytes(64, 'little'), role=role,
            context=CONTEXT, operation_id=OPERATION)
        from wots_graph import GraphSpec
        spec = GraphSpec.from_program(reduction.program)
        invalid = [i for i, leaf in enumerate(spec.leaves) if leaf.kind == 'field_valid']
        if len(invalid) != 1:
            raise ValueError('one canonical result field is required')
        add('noncanonical-result', reduction, _rewitness(reduction, result=p, quotient=0), invalid)
        del reduction, spec

    if not 0 < len(cases) <= MAX_CASES or len(measured) != 2:
        raise ValueError('bounded two-role uniform fixture census required')
    checks = sum(len(case['checks']) for case in cases)
    guards = sum(14*len({leaf['kind'] for leaf in case['spec']['leaves']})
                 for case in cases if case['measure_all'])
    return cases, dict(schema='bitvm2-nova-uniform-reduce-input/v1', cases=oracle), dict(
        cases=len(cases), mature_oracle_cases=len(oracle), measured=measured, diagnostics=diagnostics,
        expected_native_rejections=54, expected_shared_carry_links=128,
        expected_signatures=sum(len(case['words']) for case in cases),
        expected_vectors=2*checks+guards, expected_rejections=checks+guards,
        expected_guard_vectors=guards, expected_selected_leaf_checks=checks)


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
        raise ValueError('three distinct uniform output files required')
    cases, oracle, census = generate()
    corpus = _write_json(paths[0], cases, MAX_INPUT_BYTES)
    oracle_info = _write_json(paths[1], oracle, 64 << 10)
    report = dict(schema='bitvm2-nova-uniform-reduce-generation/v1', **census,
        corpus=corpus, oracle_input=oracle_info, field_context_sha256=CONTEXT.hex(),
        operation_id=OPERATION, graph_generation_only=True, wots_signatures_generated=0,
        native_worker_executed=False, full_hash_verified=False, transcript_verified=False,
        proof_verified=False, complete_bitvm2_verifier=False, production_assertion_binding=False,
        bitcoin_transaction_graph=False, transactions_broadcast=0, proving_jobs=0,
        wall_seconds=time.perf_counter()-started, parent_peak_rss_bytes=peak_rss())
    _write_json(paths[2], report, 1 << 20)
    print(json.dumps(report))


if __name__ == '__main__':
    main()
