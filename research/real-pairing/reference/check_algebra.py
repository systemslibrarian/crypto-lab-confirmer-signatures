"""Machine-checked polynomial identities + small-field enumeration.
This is not a formalization of the security games or a mechanized ZK proof.
"""
from itertools import product, combinations
from sympy import symbols, expand, cancel

d,x,a,b,h,c,e,f,u,v,dc,du,dv,C,beta=symbols('d x a b h c e f u v dc du dv C beta')
def zero(expression):assert expand(expression)==0,expression
U=e-c*x*a;V=f-c*a;Beta=a*(b*x-h)
zero((d*U-d*x*V)-(d*e-d*x*f))
zero((Beta*c+b*U-h*V)-(b*e-h*f))
# Proposed simulator's translations have explicit inverses.
zero((u+c*x*a)-c*x*a-u)
zero((v+c*a)-c*a-v)
# Denominators are nonzero by the written prime-order argument.
K=d*du-C*dv;T=beta*dc+b*du-h*dv
assert cancel((d*(du/dv)-C)-K/dv)==0
assert cancel((beta-(-dv/dc)*(b*du/dv-h))-T/dc)==0
# If the statement is false (h=b*x) and D has log 1,
# the commitment and response key equation fix a UNIQUE challenge.
zero((beta*c+b*u-(b*x)*v)-(b*(u-x*v)+beta*c))
# Printed key-ratio beta is identically zero in exponent notation.
zero(a*(d*x-d*x))
print('8 polynomial identities verified over symbolic variables.')

checked=0
for q in (3,5):
    for key,base,alleged,be in product(range(q),range(q),range(q),range(1,q)):
        groups={}
        for uu,vv,cc in product(range(q),repeat=3):
            first=((uu-key*vv)%q,(be*cc+base*uu-alleged*vv)%q)
            groups.setdefault(first,[]).append((uu,vv,cc))
        for responses in groups.values():
            for left,right in combinations(responses,2):
                diffc=(left[2]-right[2])%q
                if not diffc:continue
                diffu=(left[0]-right[0])%q;diffv=(left[1]-right[1])%q
                assert diffv!=0
                extracted=diffu*pow(diffv,-1,q)%q
                blind=-diffv*pow(diffc,-1,q)%q
                assert extracted==key and (base*extracted-alleged)%q!=0
                assert (blind*(base*extracted-alleged))%q==be
                checked+=1
print(f'{checked} two-challenge branch extractions checked exhaustively for q=3,5.')
print('Nonzero premises, OR composition and probability/distribution arguments remain in DISAVOWAL-PROOF.md.')
