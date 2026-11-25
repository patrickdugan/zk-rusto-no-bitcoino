"""Paired native capacity study; exact source-verified certificates, no timing claim."""
import json
from pathlib import Path
from scaling import generate
from unified_reference import Build as Old, replay as replay_old
from bulk_reference import Build as New, replay as replay_new
from bulk_audit import check


def main():
    results={}
    for fi,family in enumerate(('weakening','dependent_app','conversion')):
        stats=dict(cases=64,old_rows=0,bulk_rows=0,old_objects=0,bulk_objects=0,better=0,equal=0,worse=0,max_rows=0,max_objects=0,fit64=0,fit128=0,fit256=0,fit512=0)
        for seed in range(22000+fi*1000,22064+fi*1000):
            source=generate(seed,family)
            old=Old().compile(source); new=New().compile(source)
            a=replay_old(old); b=replay_new(new)
            assert all(check(new,i,r) for i,r in enumerate(new['rows']))
            stats['old_rows']+=a;stats['bulk_rows']+=b
            stats['old_objects']+=len(old['arena']);stats['bulk_objects']+=len(new['arena'])
            stats['better']+=int(b<a);stats['equal']+=int(b==a);stats['worse']+=int(b>a)
            stats['max_rows']=max(stats['max_rows'],b);stats['max_objects']=max(stats['max_objects'],len(new['arena']))
            for cap in (64,128,256,512):stats[f'fit{cap}']+=int(max(b,len(new['arena']))<=cap)
        results[family]=stats
    print(json.dumps(results,indent=2))
    Path(__file__).with_name('bulk-scaling-results.json').write_text(json.dumps(results,indent=2)+'\n')

if __name__=='__main__':main()
