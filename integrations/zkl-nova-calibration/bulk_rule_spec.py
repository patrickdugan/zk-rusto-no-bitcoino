"""Static local inference equations for ZKL-19. Each expression must equal zero."""
import ast
import json
from pathlib import Path

NAMES=[f'r{i}' for i in range(5)]+[f'o{i}_{j}' for i in range(6) for j in range(5)]+[f'p{i}_{j}' for i in range(3) for j in range(5)]+['kp','bm','gap','vminus']
ARITY=(0,0,0,2,2,2,0,0,0,0,3,3,2,0,1,2,1,2,2,2,0,2,0,1,1,3,2,2,2,2,3,3)
def kind(op):return 0 if op<6 else 1 if op<13 else 2 if op<20 else 3 if op<22 else 4 if op<24 else 5

def make():
    specs=[]
    for op in range(32):
        k=kind(op);cond=['o0_0-r1','o1_0-r4','o1_4-1','o0_4-1' if k<3 else 'o0_4']
        def eq(a,b):cond.append(f'{a}-({b})')
        def prev(i,*vals):
            assert len(vals)==5
            for j,v in enumerate(vals):eq(f'p{i}_{j}',v)
        if k not in (0,1):eq('r3',0)
        if k in (2,3):eq('r2',0)
        if k==3:eq('r4',0)
        if k==1: eq('o2_0','r3');eq('o2_4',1)
        if k==5: eq('o2_0','r2');eq('o2_4',1)
        if op in (0,1,6,7,8):eq('o0_1',1)
        if op in (0,6):eq('r1','r4');cond.append('r2-o0_2-gap-1')
        if op==1:eq('o1_1',1);cond.extend(['o0_2-r2-gap','o1_2-o0_2-r3'])
        if op in (2,9):eq('o0_1',0);eq('r1','r4')
        if op in (3,4,5):
            eq('o0_1',op-1);eq('o1_1',op-1)
            prev(0,0,'o0_2','r2','r3','o1_2');prev(1,0,'o0_3','r2' if op==5 else 'kp','r3','o1_3')
        if op==7:eq('o0_2','r2');eq('r4','r3')
        if op==8:eq('o1_1',1);cond.extend(['o0_2-r2-gap-1','o0_2-o1_2-1'])
        if op in (10,11):
            eq('o0_1',op-8);eq('o1_1',op-8)
            prev(0,1,'o0_2','r2','r3','o1_2');prev(1,0,'r3',0,1,'p1_4');prev(2,1,'o0_3','kp','p1_4','o1_3')
        if op==12:
            eq('o0_1',4);eq('o1_1',4);prev(0,1,'o0_2','r2','r3','o1_2');prev(1,1,'o0_3','r2','r3','o1_3')
        if op==13:eq('r1','r4')
        if op==14:prev(0,2,'r4',0,0,'r1')
        if op==15:prev(0,2,'r1',0,0,'p0_4');prev(1,2,'p0_4',0,0,'r4')
        if op==16:
            eq('o0_1',4);eq('o2_0','o0_2');eq('o2_1',3);prev(0,1,'o2_3',0,'o0_3','r4')
        if op in (17,18,19):
            eq('o0_1',op-15);eq('o1_1',op-15);prev(0,2,'o0_2',0,0,'o1_2');prev(1,2,'o0_3',0,0,'o1_3')
        if op==20:eq('o0_1',5);eq('r1',1)
        if op==21:eq('o0_1',6);eq('o4_1',0);prev(0,3,'o0_2',0,0,0);prev(1,5,'o0_2','o0_3',0,'o4_0')
        if op==22:eq('o0_1',6);eq('r2',0);eq('r4','o0_3')
        if op==23:eq('o0_1',6);prev(0,4,'o0_2','bm',0,'r4')
        if op==24:eq('o2_1',0);eq('o1_1',0);cond.append('o1_2-o2_2-1');prev(0,3,'r1',0,0,0)
        if op==25:eq('o2_1',1);prev(0,3,'r1',0,0,0);prev(1,4,'r1','o2_2',0,'p1_4');prev(2,0,'p1_4',0,'o2_2+1','r4')
        if op in (26,27,28):
            eq('o2_1',2);eq('o1_1',0);eq('o3_1',6);eq('o3_2','r1');eq('o3_3','o2_2');eq('o4_1',0);eq('o5_1',0)
            if op==26:eq('o5_2',0);eq('o1_2',0)
            else:
                cond.append('o5_2-vminus-1');cond.append('o4_2-o5_2-gap' if op==27 else 'o5_2-o4_2-gap');eq('o1_2','o4_2' if op==27 else 'o5_2')
            prev(0,5,'r1','o2_2',0,'o4_0');prev(1,5,'o3_0','o2_3',0,'o5_0')
        if op==29:
            eq('o2_1',3);eq('o1_1',2);eq('o2_2','o1_2');eq('o3_1',6);eq('o3_2','r1');eq('o3_3','o2_2');eq('o4_1',0)
            prev(0,5,'r1','r4',0,'o4_0');prev(1,5,'o3_0','o2_3',0,'o1_3')
        if op==30:
            eq('o2_1',4);eq('o3_1',2);prev(0,5,'r1','o2_2',0,'o3_0');prev(1,5,'r1','o2_3',0,'o3_2');prev(2,1,'o3_3',0,'o2_3','r4')
        if op==31:
            eq('o4_1',0);prev(0,5,'r1','r2',0,'p0_4');prev(1,5,'r1','r4',0,'o4_0');prev(2,2,'p0_4',0,0,'r4')
        specs.append(dict(kind=k,arity=ARITY[op],conditions=cond))
    return specs

def linear(expr):
    from collections import Counter
    def walk(node,sign):
        if isinstance(node,ast.Name):return 0,Counter({NAMES.index(node.id):sign})
        if isinstance(node,ast.Constant) and isinstance(node.value,int):return sign*node.value,Counter()
        if isinstance(node,ast.UnaryOp) and isinstance(node.op,ast.USub):return walk(node.operand,-sign)
        if isinstance(node,ast.BinOp) and isinstance(node.op,(ast.Add,ast.Sub)):
            a,x=walk(node.left,sign);b,y=walk(node.right,sign if isinstance(node.op,ast.Add) else -sign);x.update(y);return a+b,x
        raise ValueError(expr)
    c,terms=walk(ast.parse(expr,mode='eval').body,1)
    return [c,[[v,i] for i,v in sorted(terms.items()) if v]]

if __name__=='__main__':
    specs=make()
    for s in specs:s['conditions']=[linear(e) for e in s['conditions']]
    Path(__file__).with_name('bulk-rules.json').write_text(json.dumps(specs,sort_keys=True,separators=(',',':'))+'\n')
