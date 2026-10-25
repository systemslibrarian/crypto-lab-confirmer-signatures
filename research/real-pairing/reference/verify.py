"""Separate public-transcript verifier. py_ecc only; no JS/Noble checker imports.
Output means equations hold, NEVER authenticated challenge timing or full DCS security.
"""
import hashlib
import json
import re
import sys
from functools import lru_cache
from pathlib import Path
from py_ecc.optimized_bls12_381 import (G1,G2,FQ12,curve_order as Q,field_modulus as P,
    add,neg,multiply,eq,is_inf,pairing)
from py_ecc.bls.point_compression import decompress_G1,decompress_G2,compress_G1,compress_G2
from py_ecc.bls.hash_to_curve import hash_to_G1
SCHEME='XIA-2013-TYPE3-RESEARCH-NOT-AUDITED'
DST=b'DCS_XIA2013_RESEARCH_BLS12381G1_XMD:SHA-256_SSWU_RO_'

def integer(value,limit=Q):
    if not isinstance(value,str) or not re.fullmatch(r'0|[1-9a-f][0-9a-f]*',value):
        raise ValueError('Noncanonical hexadecimal integer')
    x=int(value,16)
    if x>=limit:raise ValueError('Integer outside field')
    return x

def point(value,group,nonzero=False):
    size=48 if group==1 else 96
    if not isinstance(value,str) or not re.fullmatch('[0-9a-f]{'+str(size*2)+'}',value):
        raise ValueError('Invalid compressed point encoding')
    raw=bytes.fromhex(value)
    pt=decompress_G1(int.from_bytes(raw,'big')) if group==1 else decompress_G2((int.from_bytes(raw[:48],'big'),int.from_bytes(raw[48:],'big')))
    if (nonzero and is_inf(pt)) or not is_inf(multiply(pt,Q)):
        raise ValueError('Point outside required subgroup')
    if encode(pt,group)!=raw:raise ValueError('Noncanonical point')
    return pt

def encode(pt,group):
    if group==1:return int(compress_G1(pt)).to_bytes(48,'big')
    a,b=compress_G2(pt)
    return int(a).to_bytes(48,'big')+int(b).to_bytes(48,'big')

def target(values,nonidentity=False):
    if not isinstance(values,list) or len(values)!=12:raise ValueError('Expected twelve Fp coefficients')
    x=FQ12([integer(v,P) for v in values])
    if x==FQ12.zero() or x**Q!=FQ12.one() or (nonidentity and x==FQ12.one()):
        raise ValueError('Target subgroup/nonidentity failure')
    return x

def hscalar(domain,*parts):
    parts=[SCHEME.encode(),domain.encode(),*parts]
    return int.from_bytes(hashlib.sha256(b''.join(len(p).to_bytes(2,'big')+p for p in parts)).digest(),'big')%Q

def pair(g1,g2):
    # PINNED convention: Noble 2.4.0 in our polynomial basis is py_ecc 8.0.0's
    # reduced pairing to power -3. Anchored on generators and mixed/hash points
    # in test_reference.py; not a per-transcript fitted normalization.
    return pairing(g2,g1).inv()**3

@lru_cache(maxsize=32)
def statement(encoded):
    d=json.loads(encoded)
    if d['scheme']!=SCHEME:raise ValueError('Unknown scheme')
    m=d['message']
    if not isinstance(m,str) or not m.strip() or len(m.encode('utf-16-le'))//2>600 or re.search(r'[\x00-\x1f\x7f]',m):
        raise ValueError('Invalid message')
    ys=point(d['signerPublic'],2,True);yc1=point(d['confirmerPublicG1'],1,True);yc2=point(d['confirmerPublicG2'],2,True)
    proof=d['confirmerKeyProof'];r1=point(proof['R1'],1,True);r2=point(proof['R2'],2,True);z=integer(proof['z'])
    c=hscalar('dual-key-bind-v1',encode(yc1,1),encode(yc2,2),encode(r1,1),encode(r2,2))
    if not eq(multiply(G1,z),add(r1,multiply(yc1,c))) or not eq(multiply(G2,z),add(r2,multiply(yc2,c))):
        raise ValueError('Dual-key certificate rejected')
    sig=d['signature'];s1=point(sig['sigma1'],1,True);s2=point(sig['sigma2'],1,True)
    s=integer(sig['s']);t=integer(sig['t']);recovered=add(multiply(yc1,t),neg(multiply(s1,s)))
    if s!=hscalar('signed-elgamal-format-v1',encode(recovered,1),encode(s1,1),encode(s2,1)):
        raise ValueError('Signed-ElGamal format rejected')
    h=hash_to_G1(m.encode(),DST,hashlib.sha256)
    return pair(s2,yc2)/pair(s1,G2),[pair(h,ys),pair(h,yc2)],[yc1,ys]

def verify(document):
    """Fail closed on malformed public encodings; ignore claimed verdict/provenance."""
    try:
        if document['format']!='signature-gate-public-transcript-v1':return False
        A,B,C=statement(json.dumps(document['publicData'],sort_keys=True))
        proof=document['proof'];kind=proof['kind'];f=proof['firstMessage'];r=proof['response'];c=integer(proof['challenge'])
        c1=integer(r['c1']);c2=integer(r['c2'])
        if (c1+c2)%Q!=c:return False
        if kind not in ('confirmation','disavowal'):return False
        for j,(base,pub,cj) in enumerate(zip([G1,G2],C,[c1,c2]),1):
            if kind=='confirmation':
                b=integer(r['b'+str(j)])
                if target(f['z'+str(2*j-1)])!=B[j-1]**b*A**cj:return False
                if not eq(point(f['z'+str(2*j)],j),add(multiply(base,b),multiply(pub,cj))):return False
            else:
                beta=target(f['beta'+str(j)],True);u=integer(r['b'+str(j)+'1']);v=integer(r['b'+str(j)+'2'])
                if not eq(point(f['zKey'+str(j)],j),add(multiply(base,u),neg(multiply(pub,v)))):return False
                if target(f['zPair'+str(j)])!=beta**cj*B[j-1]**u/(A**v):return False
        return True
    except (ValueError,TypeError,KeyError,IndexError,OverflowError,AssertionError,ZeroDivisionError):
        return False

# ---------------------------------------------------------------------------
# A-D-09: non-interactive designated-verifier proofs (Jakobsson-Sako-Impagliazzo,
# EUROCRYPT '96, section 5). Recomputed here with py_ecc, independently of the
# browser's Noble implementation. EQUATIONS_HOLD never means the statement is
# true: the designated verifier can produce an accepting proof of anything.
# ---------------------------------------------------------------------------
DV_CHALLENGE_DOMAIN='dv-designated-challenge-v1'
PUBLIC_CHALLENGE_DOMAIN='dv-public-transferable-challenge-v1'
DV_KEY_DOMAIN='dv-verifier-key-registration-v1'
G1_INFINITY=bytes([0xc0])+bytes(47)
G2_INFINITY=bytes([0xc0])+bytes(95)

def dv_point(value,group):
    """Parse a point that MAY be the canonical compressed identity."""
    raw=bytes.fromhex(value) if isinstance(value,str) and re.fullmatch('[0-9a-f]+',value or '') else None
    if raw==(G1_INFINITY if group==1 else G2_INFINITY):
        return multiply(G1 if group==1 else G2,Q)
    return point(value,group)

def dv_point_bytes(pt,group):
    if is_inf(pt):return G1_INFINITY if group==1 else G2_INFINITY
    return encode(pt,group)

def dv_target_string(x):
    return ':'.join(format(int(c),'x') for c in x.coeffs)

def dv_multiply(pt,k):
    k%=Q
    return multiply(pt,k if k else Q)

def dv_branch(A,B,C,role):
    if role=='confirmer':return B[0],C[0],G1,1
    if role=='signer':return B[1],C[1],G2,2
    raise ValueError('Unknown role')

def verify_designated(vector):
    """Both equations of the designated proof, plus the verifier key registration."""
    try:
        A,B,C=statement(json.dumps(vector['publicData'],sort_keys=True))
        Bj,Cj,base,group=dv_branch(A,B,C,vector['role'])
        context=vector['context']
        if not isinstance(context,str) or not 0<len(context)<=200 or re.search(r'[\x00-\x1f\x7f]',context):
            return False
        key=vector['verifierKey']
        y=point(key['y'],1,True);commitment=dv_point(key['commitment'],1);response=integer(key['response'])
        kc=hscalar(DV_KEY_DOMAIN,dv_point_bytes(y,1),dv_point_bytes(commitment,1))
        if not eq(dv_multiply(G1,response),add(commitment,dv_multiply(y,kc))):return False
        proof=vector['proof']
        w=integer(proof['w']);r=integer(proof['r']);d=integer(proof['d'])
        t_src=dv_point(proof['tSrc'],group);t_tgt=target(proof['tTgt'])
        c=add(dv_multiply(G1,w),dv_multiply(y,r))
        h=hscalar(DV_CHALLENGE_DOMAIN,vector['role'].encode(),context.encode(),
                  dv_target_string(A).encode(),dv_target_string(Bj).encode(),
                  dv_point_bytes(Cj,group),dv_point_bytes(base,group),
                  dv_point_bytes(y,1),dv_point_bytes(c,1),dv_point_bytes(t_src,group),
                  dv_target_string(t_tgt).encode())
        e=(h+w)%Q
        if not eq(dv_multiply(base,d),add(t_src,dv_multiply(Cj,e))):return False
        return Bj**d==t_tgt*A**e
    except (ValueError,TypeError,KeyError,IndexError,OverflowError,AssertionError,ZeroDivisionError):
        return False

def verify_public_transferable(vector):
    """The ordinary Fiat-Shamir proof of the SAME statement: anyone is convinced."""
    try:
        A,B,C=statement(json.dumps(vector['publicData'],sort_keys=True))
        Bj,Cj,base,group=dv_branch(A,B,C,vector['role'])
        context=vector['context']
        if not isinstance(context,str) or not 0<len(context)<=200 or re.search(r'[\x00-\x1f\x7f]',context):
            return False
        proof=vector['proof']
        if 'w' in proof or 'r' in proof:return False
        d=integer(proof['d']);t_src=dv_point(proof['tSrc'],group);t_tgt=target(proof['tTgt'])
        e=hscalar(PUBLIC_CHALLENGE_DOMAIN,vector['role'].encode(),context.encode(),
                  dv_target_string(A).encode(),dv_target_string(Bj).encode(),
                  dv_point_bytes(Cj,group),dv_point_bytes(base,group),
                  dv_point_bytes(t_src,group),dv_target_string(t_tgt).encode())
        if not eq(dv_multiply(base,d),add(t_src,dv_multiply(Cj,e))):return False
        return Bj**d==t_tgt*A**e
    except (ValueError,TypeError,KeyError,IndexError,OverflowError,AssertionError,ZeroDivisionError):
        return False

if __name__=='__main__':
    if len(sys.argv)!=2:raise SystemExit('Usage: python verify.py PUBLIC_TRANSCRIPT.json')
    p=Path(sys.argv[1])
    if p.stat().st_size>2_000_000:raise SystemExit('Transcript too large')
    ok=verify(json.loads(p.read_text()))
    print('EQUATIONS_HOLD' if ok else 'REJECT')
    print('Recorded equations do not authenticate verifier participation or establish full DCS security.')
    raise SystemExit(0 if ok else 1)
