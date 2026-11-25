"""Native controls for public typing compilation, not cryptographic verification."""
import copy
import json
import random
from collections import defaultdict

from typing_reference import Builder, compile_rules, fixtures, named, replay


def closure(rules):
    """Least fixed point; derives each judgment once, independent of proof order."""
    reached = set()
    while True:
        new = {head for head, pre in rules if all(p in reached for p in pre)} - reached
        if not new:
            return reached
        reached.update(new)


def unique_minimum(rules, goal):
    """Exact only for tables with unique producers and acyclic goal dependencies."""
    by = defaultdict(list)
    for head, pre in rules:
        by[head].append(pre)
    seen = set()
    active = set()
    def visit(j):
        if j in active:
            raise ValueError('cyclic dependency')
        if j in seen:
            return
        if len(by[j]) != 1:
            raise ValueError('not a unique-producer table')
        active.add(j)
        for p in by[j][0]:
            visit(p)
        active.remove(j)
        seen.add(j)
    visit(goal)
    return len(seen)


def gen(seed):
    rng = random.Random(seed)
    n = rng.randrange(1, 9)
    # Closed K-style inhabitants over distinct proposition parameters.
    result = f'x{rng.randrange(n)}'
    for i in reversed(range(n)):
        result = ('l', f'x{i}', f'A{i}', result)
    for i in reversed(range(n)):
        result = ('l', f'A{i}', ('s', 0), result)
    return Builder().build(str(seed), named(result))


def main():
    cases = fixtures()
    fixture_results = []
    for c in cases:
        rules = compile_rules(c)
        goal = tuple(c['goal'])
        assert goal in closure(rules)
        minimum = unique_minimum(rules, goal)
        assert replay(c) == minimum
        fixture_results.append(dict(name=c['name'], rules=len(rules), rows=minimum))
    # A circular premise has no proof, even if the goal has a local producer.
    a, b = (1,0,1,2), (1,0,2,3)
    assert closure([(a,[b]),(b,[a])]) == set()
    # Reachability is monotone in adding valid rules.
    assert closure([(a,[]),(b,[a])]) == {a,b}
    attempted = 128
    total_rows = fits = max_rows = max_rules = 0
    for seed in range(18000, 18000 + attempted):
        c = gen(seed)
        rules = compile_rules(c)
        goal = tuple(c['goal'])
        assert goal in closure(rules)
        n = replay(c)
        assert n == unique_minimum(rules, goal)
        total_rows += n
        max_rows = max(max_rows, n)
        max_rules = max(max_rules, len(rules))
        fits += n <= 64 and len(rules) <= 64
    attacks = []
    for ci, op, field in [(0,3,3),(1,6,3),(0,4,3),(0,5,3),(3,7,3)]:
        c = copy.deepcopy(cases[ci]); row = next(d for d in c['descriptors'] if d[0] == op)
        row[field] = (row[field]+1)%len(c['terms']) if op in (3,6,4) else 0
        attacks.append(c)
    rejected = 0
    for c in attacks:
        try:
            compile_rules(c)
        except (AssertionError, ValueError):
            rejected += 1
        else:
            raise AssertionError('accepted false local inference')
    print(json.dumps(dict(fixtures=fixture_results, public_reachability_negative_pass=True,
                          generated_cases=attempted, generated_total_rows=total_rows,
                          max_rows=max_rows,max_rules=max_rules,fits_64=fits,
                          semantic_mutations_rejected=rejected),indent=2))


if __name__ == '__main__':
    main()
