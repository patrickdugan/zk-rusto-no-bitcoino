"""Offline arithmetic and graph probes. No proof system or Bitcoin interpreter.

The bucket probe freezes ONE window's digits. It counts dependencies of that
chosen addition DAG; a reusable verifier must also authenticate/control the
schedule, scalars, generators and every omitted arithmetic constraint.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from hashlib import sha1
import importlib.util
import json
from pathlib import Path

BASE_COMMIT = '55e52156f800f0f39e4bc04ff76103c14633b273'
SOURCE = 'integrations/bitvm2-nova/msm_projection.py'
SOURCE_BLOB = 'ed86b1b20ea37bac1e368e2aa4fbf72631e41852'
ROLES = {'primary': (524288, 61523789), 'secondary': (16384, 61626177)}
POLICY_BYTES = 5 << 28
WORDS_PER_ADD = 7476
SIGNATURE_BYTES_PER_WORD = 200


def positive(value: int, name: str) -> int:
    if type(value) is not int or value < 1:
        raise ValueError(f'{name}: positive integer required')
    return value


def pippenger(n: int, bits: int = 255) -> tuple[int, int]:
    """Reproduce the pinned heuristic; counts are not an optimality bound."""
    positive(n, 'n')
    positive(bits, 'bits')
    return min((((bits + w - 1) // w) * (n + (1 << (w + 1)) + w + 1), w)
               for w in range(1, 25))


def baseline() -> dict:
    roles = {}
    for role, (n, script_bytes) in ROLES.items():
        additions, window = pippenger(n)
        roles[role] = {
            'generators': n, 'window': window, 'point_additions': additions,
            'disproof_script_bytes': additions * script_bytes,
            'asserted_words': additions * WORDS_PER_ADD,
            'assertion_signature_bytes': additions * WORDS_PER_ADD * SIGNATURE_BYTES_PER_WORD,
        }
    total = sum(r['disproof_script_bytes'] for r in roles.values())
    ops = sum(r['point_additions'] for r in roles.values())
    return {
        'roles': roles, 'disproof_script_bytes': total,
        'assertion_signature_bytes': sum(r['assertion_signature_bytes'] for r in roles.values()),
        'policy_bytes': POLICY_BYTES, 'policy_ratio': total / POLICY_BYTES,
        'average_bytes_per_original_addition_at_policy': POLICY_BYTES / ops,
        'measured_complete_verifier': False,
    }


def check_upstream(root: Path) -> dict:
    """Fail on source drift before importing the exact, pure-arithmetic module."""
    path = root / SOURCE
    data = path.read_bytes()
    blob = sha1(b'blob ' + str(len(data)).encode('ascii') + b'\0' + data).hexdigest()
    if blob != SOURCE_BLOB:
        raise ValueError(f'baseline source drift: {path}: {blob}')
    spec = importlib.util.spec_from_file_location('_compact_skunk_baseline', path)
    if spec is None or spec.loader is None:
        raise ValueError('could not load pinned baseline')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    original, ours = module.projection(), baseline()
    for key in ('roles', 'disproof_script_bytes', 'assertion_signature_bytes'):
        if original[key] != ours[key]:
            raise ValueError(f'projection mismatch: {key}')
    if module.FOREST_POLICY_BYTES != POLICY_BYTES:
        raise ValueError('policy mismatch')
    return {'source': SOURCE, 'git_blob_sha1': blob, 'projection_matches': True}


@dataclass(frozen=True)
class Add:
    out: str
    left: str
    right: str


def bucket_dag(digits: list[int], window: int) -> tuple[list[Add], set[str], str]:
    """A bounded one-window bucket schedule, with every add retained."""
    if type(window) is not int or not 1 <= window <= 8:
        raise ValueError('window must be in 1..8')
    if not 1 <= len(digits) <= 4096:
        raise ValueError('1..4096 digits required')
    if any(type(x) is not int or not 0 <= x < (1 << window) for x in digits):
        raise ValueError('noncanonical window digit')
    nodes: list[Add] = []
    fixed = {'zero'} | {f'g{i}' for i in range(len(digits))}
    buckets = ['zero'] * (1 << window)

    def add(left: str, right: str) -> str:
        out = f'v{len(nodes)}'
        nodes.append(Add(out, left, right))
        return out

    for i, digit in enumerate(digits):
        if digit:
            buckets[digit] = add(buckets[digit], f'g{i}')
    running = total = 'zero'
    for digit in range((1 << window) - 1, 0, -1):
        running = add(running, buckets[digit])
        total = add(total, running)
    return nodes, fixed, total


def cut_stats(nodes: list[Add], fixed: set[str], output: str,
              chunk_size: int, point_words: int = 19) -> dict:
    """Count unique point-valued ports and repeated live state separately.

    The default 19 u32 words describes two nine-limb coordinates plus a flag.
    Internal arithmetic words, authentication checks and dynamic memory costs
    are excluded. These counts never certify a valid dispute protocol.
    """
    positive(chunk_size, 'chunk_size')
    positive(point_words, 'point_words')
    if not nodes or len(nodes) > 10000:
        raise ValueError('1..10000 additions required')
    nchunks = (len(nodes) + chunk_size - 1) // chunk_size
    incoming = [set() for _ in range(nchunks)]
    outgoing = [set() for _ in range(nchunks)]
    owners: dict[str, int] = {}
    producers: dict[str, int] = {}
    last_use: dict[str, int] = {}
    for i, node in enumerate(nodes):
        if node.out in fixed or node.out in owners:
            raise ValueError('duplicate/fixed output')
        owner = i // chunk_size
        for value in {node.left, node.right}:
            if value in fixed:
                continue
            if value not in owners:
                raise ValueError('missing input or forward reference')
            last_use[value] = i
            if owners[value] != owner:
                incoming[owner].add(value)
                outgoing[owners[value]].add(value)
        owners[node.out], producers[node.out] = owner, i
        last_use[node.out] = i
    if output not in owners:
        raise ValueError('output must be produced')
    outgoing[owners[output]].add(output)
    last_use[output] = len(nodes)
    signed = set().union(*incoming, *outgoing)
    cut_live = [sum(producers[v] < cut <= last_use[v] for v in producers)
                for cut in range(chunk_size, len(nodes), chunk_size)]
    max_ports = max(len(a | b) for a, b in zip(incoming, outgoing))
    return {
        'additions': len(nodes), 'chunk_size': chunk_size, 'chunks': nchunks,
        'point_words': point_words, 'unique_signed_point_values': len(signed),
        'max_live_point_values_at_cut': max(cut_live, default=0),
        'sum_live_point_values_at_cuts': sum(cut_live),
        'max_chunk_point_ports': max_ports,
        'raw_point_port_signature_bytes': len(signed) * point_words * SIGNATURE_BYTES_PER_WORD,
        'raw_max_chunk_wots_items': max_ports * point_words * 10,
        'script_bytes': None, 'dispute_soundness_established': False,
    }


def evaluate(nodes: list[Add], fixed: dict[str, int], modulus: int = 101) -> dict[str, int]:
    """Additive finite-field toy, with all discrete logs public by construction."""
    positive(modulus, 'modulus')
    if modulus < 2 or any(type(v) is not int or not 0 <= v < modulus for v in fixed.values()):
        raise ValueError('canonical toy values required')
    values = dict(fixed)
    for node in nodes:
        if node.out in values or node.left not in values or node.right not in values:
            raise ValueError('invalid DAG')
        values[node.out] = (values[node.left] + values[node.right]) % modulus
    return values


def ipa_weights(challenges: list[int], q: int = 101) -> list[int]:
    """Toy-field coefficient order matches ipa_algebra.weights: first bit is MSB."""
    if q not in (7, 101) or len(challenges) > 12:
        raise ValueError('toy prime must be 7 or 101; at most 12 challenges')
    if any(type(u) is not int or not 0 < u < q for u in challenges):
        raise ValueError('canonical nonzero challenge required')
    weights = [1]
    for u in challenges:
        inv = pow(u, -1, q)
        weights = [v * factor % q for v in weights for factor in (inv, u)]
    return weights


def tensor_terminal(generators: list[int], challenges: list[int], q: int = 101) -> int:
    """Evaluate alpha * sum_b G_b product_j (u_j^2)^b_j in an additive toy group."""
    ipa_weights(challenges, q)
    if len(generators) != 1 << len(challenges):
        raise ValueError('dimension mismatch')
    if any(type(g) is not int or not 0 <= g < q for g in generators):
        raise ValueError('canonical toy generator required')
    d = len(challenges)
    alpha = 1
    for u in challenges:
        alpha = alpha * pow(u, -1, q) % q
    total = 0
    for i, g in enumerate(generators):
        term = g
        for j, u in enumerate(challenges):
            if (i >> (d - j - 1)) & 1:
                term = term * u * u % q
        total = (total + term) % q
    return alpha * total % q


def report() -> dict:
    rows = []
    for window in (2, 4, 6):
        # Deterministic digit census, not a sampled production transcript.
        digits = [((i * 13 + 7) ^ (i >> 1)) % (1 << window) for i in range(128)]
        nodes, fixed, output = bucket_dag(digits, window)
        for size in (1, 4, 16, 64, 256):
            rows.append({'window': window, 'generators': len(digits),
                         **cut_stats(nodes, fixed, output, size)})
    return {
        'schema': 'compact-skunk/offline-probes/v1', 'baseline_commit': BASE_COMMIT,
        'baseline': baseline(), 'bucket_cut_probes': rows,
        'executed': 'integer arithmetic and finite toy dependency graphs only',
        'bitcoin_script_executed': False, 'proofs_generated': 0,
        'full_verifier_compactified': False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-upstream', type=Path, metavar='REPO_ROOT')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    try:
        result = report()
        if args.check_upstream is not None:
            result['upstream_check'] = check_upstream(args.check_upstream)
        text = json.dumps(result, indent=2, sort_keys=True) + '\n'
        if args.output is None:
            print(text, end='')
        else:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(text, encoding='utf-8')
    except (OSError, ValueError) as exc:
        parser.error(str(exc))


if __name__ == '__main__':
    main()
