"""Translate only closed, constant-free monomorphic Lean export slices.

The source reader is diagnostic; actual Lean replay and independent ZKL checks
are mandatory. No full RH/GRH theorem is admitted here.
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import typing_reference as tr
from typing_lean import render
from bulk_reference import Build, replay


def tup(x):
    return tuple(tup(v) for v in x) if isinstance(x, list) else x


def main():
    p = argparse.ArgumentParser()
    p.add_argument('inventory', type=Path)
    p.add_argument('--out', type=Path, required=True)
    a = p.parse_args()
    a.out.mkdir(parents=True, exist_ok=True)
    data = json.loads(a.inventory.read_text())
    expected = ['id', 'Function.const', 'Function.comp']
    assert data['schema'] == 'zkl-lean-export-inventory-v1'
    assert [r['name'] for r in data['targets']] == expected
    assert [(r['name'], r['instance']) for r in data['admission']] == [(n,i) for n in expected for i in (0,1)]
    records, cases, lean = [], [], ['import Init']
    for r in data['admission']:
        name = 'zkl_import_' + r['name'].replace('.', '_') + '_' + str(r['instance'])
        row = {k:r[k] for k in ('name','instance','universe_arguments','status')}
        if r['status'] != 'syntax_admitted':
            row['reason'] = r.get('reason', 'unsupported')
            records.append(row)
            continue
        try:
            c = tr.Builder().build(name, tup(r['term']), tup(r['type']))
            tr.replay(c)
            u = Build().compile(c)
            n = replay(u)
            if len(u['arena']) > 512 or n > 512:
                raise ValueError('512-slot capacity')
            kind, g, t, ty = c['goal']
            assert kind == 1 and g == 0
            # The declared type and elaborated value both originate in the export.
            tp, term = render(c['terms'], ty), render(c['terms'], t)
            params = ','.join(map(str, r['universe_arguments']))
            original = '@' + r['name'] + ('.{' + params + '}' if params else '')
            lean.append(f'def {name} : {tp} := {term}\n')
            lean.append(f'example : {tp} := {original}\n')
            lean.append(f'example : {original} = {name} := rfl\n')
            lean.append(f'#print axioms {name}\n')
            row.update(status='native_replayed', rows=n, objects=len(u['arena']), case=name)
            cases.append(u)
        except (ValueError, AssertionError, IndexError, RecursionError) as e:
            row.update(status='rejected',reason=type(e).__name__ + ': ' + str(e))
        records.append(row)
    (a.out/'admission.json').write_text(json.dumps({'source_export_sha256':data['export_sha256'],
        'attempted':len(records),'native_replayed':len(cases),'roots':records},indent=2)+'\n')
    (a.out/'Imported.lean').write_text('\n'.join(lean)+'\n')
    (a.out/'core-bulk.json').write_text(json.dumps({'schema':'zkl-bulk-v1','cases':cases},sort_keys=True,separators=(',',':'))+'\n')
    print(json.dumps(records,sort_keys=True))
    if len(cases)!=6:
        raise SystemExit('registered slice incomplete; retain all attempted roots')


if __name__ == '__main__':
    main()
