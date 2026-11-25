"""Independent lift composition and false-distance conformance tests (native)."""
import json
import random
from pathlib import Path
from bulk_reference import Build, tr
from bulk_audit import check


def sample(rng, depth):
    tag=rng.randrange(5 if depth else 2)
    if tag<2:
        return (tag,rng.randrange(4 if tag==0 else 16))
    return (tag,sample(rng,depth-1),sample(rng,depth-1))


def main():
    rng=random.Random(2026112520)
    for _ in range(4096):
        t=sample(rng,5);k=rng.randrange(7);d=rng.randrange(17)
        expected=t
        for _ in range(d):
            expected=tr.lift(expected,1,k)
        assert tr.lift(t,d,k)==expected
    batch=json.loads(Path(__file__).with_name('bulk-fixtures.json').read_text())
    invalid=0
    for case in batch['cases']:
        for i,row in enumerate(case['rows']):
            if row[0]==1:
                mutated=list(row);mutated[3]+=1
                assert not check(case,i,mutated)
                invalid+=1
            if row[0]<6:
                mutated=list(row);mutated[3]=65536
                assert not check(case,i,mutated)
                invalid+=1
    b=Build()
    i=b.lift(tr.var(0),0,65535)
    case={'arena':b.arena,'rows':b.rows}
    assert check(case,i,b.rows[i])
    # This is a bounded relation, so a mathematically valid out-of-range lift is inadmissible.
    assert b.arena[b.rows[i][4]]==[1,65535,0]
    row=list(b.rows[i]);row[3]=65536
    assert not check(case,i,row)
    b=Build();i=b.lift(tr.var(5),6,0)
    assert check({'arena':b.arena,'rows':b.rows},i,b.rows[i])
    print(json.dumps(dict(composition_cases=4096,invalid_distance_mutations=invalid,upper_boundary=True,zero_distance=True)))

if __name__=='__main__':main()
