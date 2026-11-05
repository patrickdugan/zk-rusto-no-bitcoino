"""Stream compact-v1 vectors and compare identical M2 graphs, without proving."""
from hashlib import sha256
from pathlib import Path
import json
import platform
import random
import time
from compact import mul_bit
from script import BASE, P, Q, execute, num, witness
from trace import multiplication_trace, change_field
from curve_trace import point_add_trace
from ipa_algebra import PALLAS, VESTA

OUT = Path(__file__).resolve().parent / 'results'
BASELINE = '474299439e178da7b965d6c3716bdb8320e082d3'
# Captured from the pinned original compiler, including tags and arity guards.
BASELINE_STREAMS = {
    ('pallas', 'multiplication'): '9523fa680d734d5b2e079353d3963334d0740ac9828f05397eae99a1e37b8448',
    ('pallas', 'point-add'): '0c1fe977db2b0afaa6780c6e58de0e606fe7fe5a1ced6ba4a1d1f65fb1d50af3',
    ('vesta', 'multiplication'): 'ab938cecf003465c73b55796d49bfe68f6a4d4cf7077dc3f25042fcbab71b06e',
    ('vesta', 'point-add'): '59582b1d1642d307dc48399023e22622d41be276acc6ad64c1a2807129eae0b7',
}


def peak_rss():
    if platform.system() != 'Windows':
        import resource
        rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return rss if platform.system() == 'Darwin' else rss*1024
    import ctypes
    from ctypes import wintypes
    class Counters(ctypes.Structure):
        _fields_ = [('cb', wintypes.DWORD), ('PageFaultCount', wintypes.DWORD)] + [
            (name, ctypes.c_size_t) for name in ('PeakWorkingSetSize', 'WorkingSetSize',
            'QuotaPeakPagedPoolUsage', 'QuotaPagedPoolUsage', 'QuotaPeakNonPagedPoolUsage',
            'QuotaNonPagedPoolUsage', 'PagefileUsage', 'PeakPagefileUsage')]
    counters = Counters()
    counters.cb = ctypes.sizeof(counters)
    get_process = ctypes.windll.kernel32.GetCurrentProcess
    get_process.restype = wintypes.HANDLE
    get_memory = ctypes.windll.psapi.GetProcessMemoryInfo
    get_memory.argtypes = [wintypes.HANDLE, ctypes.POINTER(Counters), wintypes.DWORD]
    get_memory.restype = wintypes.BOOL
    if not get_memory(get_process(), ctypes.byref(counters), counters.cb):
        raise OSError('GetProcessMemoryInfo failed')
    return counters.PeakWorkingSetSize


def main():
    OUT.mkdir(exist_ok=True)
    start = time.perf_counter()
    count = rejected = 0
    cases = []
    path = OUT / 'compact-engine-vectors.jsonl'
    # Explicit encoding makes fixtures byte-identical on Windows and Linux.
    with path.open('w', encoding='ascii', newline='\n') as out:
        def emit(code, ws, expected, name):
            nonlocal count, rejected
            out.write(json.dumps({'name': name, 'script_hex': code.hex(),
                'witness_hex': [w.hex() for w in ws], 'expected_success': expected},
                separators=(',', ':'))+'\n')
            count += 1
            rejected += int(not expected)

        def leaf(bound, i, expected, name, ws=None):
            ws = bound.witness(i) if ws is None else ws
            for disprove in (False, True):
                emit(bound.script(i, compiler='compact-v1', disprove=disprove),
                     ws, expected != disprove, f'{name}/{disprove}')

        for c in (PALLAS, VESTA):
            for kind in ('multiplication', 'point-add'):
                # Exactly the M2 benchmark inputs, operation IDs and contexts.
                if kind == 'multiplication':
                    pr, va = multiplication_trace(c.name+'_base', c.p-19, c.p-73,
                        context=sha256(b'M2-benchmark').digest(), operation_id='benchmark/mul')
                else:
                    g = (c.p-1, 2)
                    pr, va = point_add_trace(c, g, c.mul(g, 2),
                        context=sha256(b'M2-benchmark').digest(), operation_id='benchmark/point')
                bound = pr.bind(va)
                if bound.failures():
                    raise AssertionError('honest fixture has native constraint failure')
                stats = {backend: {'all_disproof_scripts_bytes': 0, 'largest_leaf_bytes': 0,
                                  'leaf_stream_sha256': sha256()} for backend in ('m2', 'compact-v1')}
                for i in range(len(pr.constraints)):
                    for backend in stats:
                        code = bound.script(i, compiler=backend)
                        stats[backend]['all_disproof_scripts_bytes'] += len(code)
                        stats[backend]['largest_leaf_bytes'] = max(stats[backend]['largest_leaf_bytes'], len(code))
                        stats[backend]['leaf_stream_sha256'].update(len(code).to_bytes(4, 'little') + code)
                    leaf(bound, i, True, f'{c.name}/{kind}/honest/{i}')
                for data in stats.values():
                    data['leaf_stream_sha256'] = data['leaf_stream_sha256'].hexdigest()
                expected_baseline = 1_268_152 if kind == 'multiplication' else 16_554_753
                if stats['m2']['all_disproof_scripts_bytes'] != expected_baseline:
                    raise AssertionError('M2 size baseline changed')
                if stats['m2']['leaf_stream_sha256'] != BASELINE_STREAMS[c.name, kind]:
                    raise AssertionError('M2 baseline leaf bytes changed')
                saved = stats['m2']['all_disproof_scripts_bytes'] - stats['compact-v1']['all_disproof_scripts_bytes']
                cases.append({**bound.manifest(), 'case': kind, 'compilers': stats,
                    'saved_script_bytes': saved, 'saved_percent': 100*saved/expected_baseline})
                if kind == 'multiplication':
                    for bit in range(255):
                        changed = dict(va)
                        changed[f'product/bit/{bit}'] ^= 1
                        # Independent location: each 29-bit limb reconstruction.
                        leaf(pr.bind(changed), bit//29, False, f'{c.name}/wrong-bit/{bit}')
                    for step in range(256):
                        name = f'product/acc/{step}'
                        ws = dict(pr.fields)[name]
                        old = sum(va[w] << (29*j) for j, w in enumerate(ws))
                        changed = change_field(pr, va, name, (old+1) % c.p)
                        leaf(pr.bind(changed), 9 if step == 0 else 17+step,
                             False, f'{c.name}/wrong-accumulator/{step}')
                    leaf(pr.bind(change_field(pr, va, 'product', 1)), 273, False, f'{c.name}/wrong-result')
                    _, wrong = multiplication_trace(c.name+'_base', c.p-19, c.p-74,
                        context=pr.context, operation_id=pr.operation_id)
                    for w in dict(pr.fields)['input/b']:
                        wrong[w] = va[w]
                    leaf(pr.bind(wrong), 0, False, f'{c.name}/coherent-wrong-multiplier')
                    for i in (0, 8, 9, 18, 145, 273):
                        ws = list(bound.witness(i))
                        for disprove in (False, True):
                            code = bound.script(i, disprove=disprove, compiler='compact-v1')
                            for j, bad in enumerate(([], ws[:-1], [b'']+ws, ws+[b''])):
                                emit(code, bad, False, f'{c.name}/witness-length/{i}/{j}/{disprove}')
                            for j in range(len(ws)):
                                bad = ws.copy()
                                bad[j] = num(17) if bad[j] != num(17) else num(18)
                                emit(code, bad, False, f'{c.name}/opening/{i}/{j}/{disprove}')
                del bound, pr, va
            # Raw predicate vectors get integer expectations, never Constraint.native.
            rng = random.Random(190711)
            edges = [0, 1, BASE-1, BASE, BASE**4-1, BASE**8-1, c.p//2, c.p-2, c.p-1]
            pairs = [(x, y) for x in edges for y in edges]
            pairs += [(rng.randrange(c.p), rng.randrange(c.p)) for _ in range(32)]
            code = mul_bit(c.p)
            for j, (x, y) in enumerate(pairs):
                for bit in (0, 1):
                    z = (2*x+bit*y) % c.p
                    for output, expected in ((z, True), ((z+1) % c.p, False)):
                        emit(code, witness(x, y, output, bit), expected, f'{c.name}/integer/{j}/{bit}/{expected}')
            bad = [witness(x, y, 0, 1) for x, y in
                   ((c.p, 0), (0, c.p), (c.p+1, 1), (BASE**9-1, c.p-1))]
            for pos in (0, 8, 9, 17, 19, 27):
                for value in (-1, BASE, 2**31, b'\x00', b'\x80', b'\x01\x00'):
                    ws = witness(1, 2, 4, 1)
                    ws[pos] = value if isinstance(value, bytes) else num(value)
                    bad.append(ws)
            for bit in (-1, 2, 17, 2**31):
                bad.append(witness(1, 2, 4, bit))
            for j, ws in enumerate(bad):
                emit(code, ws, False, f'{c.name}/inadmissible/{j}')
    if count > 20_000 or path.stat().st_size > 256*1024*1024:
        raise AssertionError('fixture exceeds independent harness bounds')
    digest = sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1024*1024), b''):
            digest.update(block)
    metrics = []
    for p in (P, Q):
        rr = execute(mul_bit(p), witness(p-1, p-1, p-3, 1))
        if not rr.success:
            raise AssertionError(rr)
        metrics.append({'modulus': str(p), 'bare_mul_bit_bytes': len(mul_bit(p)),
                        'reference_peak_stack_items': rr.peak_stack,
                        'reference_executed_instructions': rr.op_count})
    report = {'schema': 'bitvm2-nova-compact-evidence/v1', 'baseline_commit': BASELINE,
        'compiler': 'compact-v1', 'python': platform.python_version(), 'platform': platform.platform(),
        'script_vectors': count, 'expected_script_rejections': rejected,
        'engine_fixture_bytes': path.stat().st_size, 'engine_fixture_sha256': digest.hexdigest(),
        'generation_seconds': time.perf_counter()-start, 'python_peak_rss_bytes': peak_rss(),
        'memory_limit_enforced': False, 'cases': cases, 'kernel_metrics': metrics,
        'trusted_setup': False, 'production_transcript': False, 'dynamic_bitvm2_assertions': False,
        'nova_proofs_verified': 0, 'transactions_broadcast': 0}
    (OUT/'compact-bench.json').write_text(json.dumps(report, indent=2)+'\n', encoding='ascii')
    print(json.dumps({k: v for k, v in report.items() if k != 'cases'}, indent=2))


if __name__ == '__main__':
    main()
