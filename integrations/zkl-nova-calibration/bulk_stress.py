"""Preselected capacity stress case: dependent application seed 23004."""
import json
from pathlib import Path
from scaling import generate
from bulk_reference import Build,replay
from bulk_audit import check

if __name__=='__main__':
    c=Build().compile(generate(23004,'dependent_app'))
    c['name']='dependent-app-23004'
    assert replay(c)==270 and len(c['arena'])==112
    assert all(check(c,i,r) for i,r in enumerate(c['rows']))
    Path(__file__).with_name('bulk-stress.json').write_text(json.dumps({'schema':'zkl-bulk-v1','cases':[c]},sort_keys=True,separators=(',',':'))+'\n')
