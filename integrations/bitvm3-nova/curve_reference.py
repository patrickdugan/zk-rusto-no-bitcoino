"""Small-field exhaustive check of the M3 complete affine predicate."""
from itertools import product
from time import monotonic
P=int('40000000000000000000000000000000224698fc094cf91b992d30ed00000001',16)
Q=int('40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001',16)
O=(0,0,True)
def admitted(t,p):
    x,y,inf=t
    return 0<=x<p and 0<=y<p and (x==y==0 if inf else (y*y-x*x*x-5)%p==0)
def add(a,b,p):
    if a[2]:return b,0
    if b[2]:return a,0
    x,y,_=a;u,v,_=b
    if x==u and (y+v)%p==0:return O,0
    m=((3*x*x)*pow(2*y,-1,p) if x==u else (v-y)*pow(u-x,-1,p))%p
    rx=(m*m-x-u)%p
    return (rx,(m*(x-rx)-y)%p,False),m

def predicate(a,b,r,m,p):
    if not all(admitted(t,p) for t in (a,b,r)) or not 0<=m<p:return False
    x,y,i=a;u,v,j=b;rx,ry,k=r
    if i:return r==b and m==0
    if j:return r==a and m==0
    samex=x==u;samey=y==v
    inverse=samex and (y+v)%p==0
    regular=(not samex) or (samey and y!=0)
    den=(2*y if samex else u-x)%p
    num=(3*x*x if samex else v-y)%p
    good=regular and not k and den!=0 and (m*den-num)%p==0
    good=good and (m*m-x-u-rx)%p==0 and (m*(x-rx)-y-ry)%p==0
    return (inverse and k and m==0) or good

def main():
    n=0;start=monotonic()
    for p in [7,11,13,17,19]:
        points=[O]+[(x,y,False) for x in range(p) for y in range(p) if (y*y-x*x*x-5)%p==0]
        for a,b in product(points,repeat=2):
            expected,m=add(a,b,p)
            for r,l in product(points,range(p)):
                assert predicate(a,b,r,l,p)==(r==expected and l==m),(p,a,b,r,l,expected,m)
                n+=1
    for p in (P,Q):
        g=(p-1,2,False);h=g
        for _ in range(20):
            r,m=add(g,h,p)
            assert predicate(g,h,r,m,p)
            assert not predicate(g,h,r,(m+1)%p,p)
            h=r
        assert not predicate((p-1,2,True),O,O,0,p)
        assert not predicate((p,2,False),g,O,0,p)
    print({'scope':'independent_integer_predicate','exhaustive_cases':n,'seconds':monotonic()-start})
if __name__=='__main__':main()
