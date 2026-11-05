"""Complete affine Pasta addition as a fixed typed constraint graph.

The topology includes all dispatch branches for every witness. On-curve checks,
infinity encoding, denominator checks and coordinate equations are constraints,
not native assumptions. Each field product expands to the linked M2 trace.
"""
from dataclasses import dataclass
from ipa_algebra import PALLAS, VESTA
from trace import TraceBuilder

AUTO = object()


@dataclass(frozen=True)
class EncodedPoint:
    infinity: int
    x: int
    y: int

    @classmethod
    def of(cls, point):
        if isinstance(point, cls):
            return point
        return cls(1, 0, 0) if point is None else cls(0, *point)

    def native(self):
        return None if self.infinity else (self.x, self.y)


def point_add_trace(curve, a, b, *, claimed_output=AUTO,
                    context=bytes(32), operation_id='point-add'):
    if curve not in (PALLAS, VESTA):
        raise ValueError('Pallas or Vesta required')
    a, b = EncodedPoint.of(a), EncodedPoint.of(b)
    if claimed_output is AUTO:
        for pt in (a, b):
            if (pt.infinity not in (0, 1) or not curve.valid(pt.native())
                    or (pt.infinity and (pt.x or pt.y))):
                raise ValueError('supply an explicit claim to test an invalid point')
        r = EncodedPoint.of(curve.add(a.native(), b.native()))
    else:
        r = EncodedPoint.of(claimed_output)
    g = TraceBuilder(curve.name+'_base', operation_id, context)
    zero = g.constant('constant/zero', 0)
    five = g.constant('constant/five', 5)
    false = g.small_constant('constant/false', 0, 2)
    true = g.small_constant('constant/true', 1, 2)
    points = []
    for name, pt in [('left', a), ('right', b), ('result', r)]:
        inf = g.small(name+'/infinity', pt.infinity, 2)
        x, y = g.field(name+'/x', pt.x), g.field(name+'/y', pt.y)
        g.check('point_form', (inf,)+x+y)
        xx = g.mul(name+'/x2', x, x)
        xxx = g.mul(name+'/x3', xx, x)
        yy = g.mul(name+'/y2', y, y)
        rhs = g.add(name+'/curve-rhs', xxx, five)
        g.check('gate_equal', (inf,)+yy+rhs, (0,))
        points.append((inf, x, y, xx))
    (i1,x1,y1,xx1), (i2,x2,y2,_), (ir,xr,yr,_) = points
    sy = g.add('sum-y', y1, y2)
    case = (0 if a.infinity else 1 if b.infinity else
            2 if a.x == b.x and (a.y+b.y) % curve.p == 0 else
            3 if a.x == b.x and a.y == b.y else 4)
    selector = g.small('dispatch', case, 5)
    g.check('dispatch', (i1,i2)+x1+y1+x2+y2+sy+(selector,))
    dx, dy = g.sub('dx', x2, x1), g.sub('dy', y2, y1)
    twice_y = g.add('twice-y', y1, y1)
    twice_xx = g.add('twice-x2', xx1, xx1)
    thrice_xx = g.add('thrice-x2', twice_xx, xx1)
    denominator = (b.x-a.x) % curve.p if case == 4 else (2*a.y) % curve.p
    numerator = (b.y-a.y) % curve.p if case == 4 else (3*a.x*a.x) % curve.p
    slope = numerator*pow(denominator, -1, curve.p) % curve.p if case in (3,4) and denominator else 0
    lam = g.field('slope', slope)
    ordinary_lhs = g.mul('ordinary-slope', dx, lam)
    double_lhs = g.mul('double-slope', twice_y, lam)
    g.check('gate_nonzero', (selector,)+dx, (4,))
    g.check('gate_nonzero', (selector,)+twice_y, (3,))
    g.check('gate_equal', (selector,)+ordinary_lhs+dy, (4,))
    g.check('gate_equal', (selector,)+double_lhs+thrice_xx, (3,))
    lsq = g.mul('slope2', lam, lam)
    sx = g.add('sum-x', x1, x2)
    sxr = g.add('sum-x-result', sx, xr)
    g.check('gate_equal', (selector,)+lsq+sxr, (3,4))
    xdiff = g.sub('left-x-minus-result-x', x1, xr)
    ylhs = g.mul('y-equation', lam, xdiff)
    ysum = g.add('left-y-plus-result-y', y1, yr)
    g.check('gate_equal', (selector,)+ylhs+ysum, (3,4))
    g.check('gate_small_equal', (selector,ir,false), (3,4))
    g.check('gate_small_equal', (selector,ir,true), (2,))
    for label, inf, x, y in [(0,i2,x2,y2),(1,i1,x1,y1)]:
        g.check('gate_small_equal', (selector,ir,inf), (label,))
        g.check('gate_equal', (selector,)+xr+x, (label,))
        g.check('gate_equal', (selector,)+yr+y, (label,))
    return g.finish()
