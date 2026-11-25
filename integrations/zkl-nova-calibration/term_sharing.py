"""Measure certificate sharing on disjoint public synthetic roots."""
import json
import term_reference as ref


class TreeBuilder(ref.Builder):
    def lift(self, t, k):
        self.memo.pop(('l', t, k), None)
        return super().lift(t, k)

    def sub(self, t, k, s):
        self.memo.pop(('s', t, k, s), None)
        return super().sub(t, k, s)


def main():
    report = {}
    for depth in (3, 5, 7):
        z = []
        for seed in range(10000 + depth * 1000, 10000 + depth * 1000 + 256):
            t, a, _ = ref.generate(seed, depth)
            src = ref.app(ref.lam(t), a)
            b = ref.Builder()
            b.beta(src)
            c = TreeBuilder()
            c.beta(src)
            assert ref.replay(b.wire('dag')) and ref.replay(c.wire('tree'))
            z.append((len(b.rows), len(c.rows), len(b.terms)))
        report[depth] = dict(cases=len(z), dag_rows=sum(a for a, b, c in z),
                             tree_rows=sum(b for a, b, c in z), largest_dag=max(a for a, b, c in z),
                             fits_64=sum(a <= 64 and c <= 64 for a, b, c in z),
                             improved=sum(a < b for a, b, c in z))
    print(json.dumps(report, sort_keys=True))


if __name__ == '__main__':
    main()
