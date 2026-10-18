/**
 * RESEARCH ONLY — symbolically represented cyclic groups (NOT secure crypto).
 * Implements the exact algebraic roles of Xia (2013) Chapter 5 §5.5:
 * signed ElGamal encryption of a BLS-shaped signature and the two OR-based
 * confirmation Σ-protocols shown in Figures 5.1 and 5.2.
 *
 * DISCLAIMER: an element is stored as its discrete-log EXPONENT, so ALL
 * public keys disclose secret exponents! Pairing is exponent multiplication,
 * NOT a real elliptic-curve pairing. Invalidity proofs are NOT implemented.
 * This cannot demonstrate cryptographic secrecy, unforgeability, zero
 * knowledge, non-transferability, or deployable DCS security.
 */
const Q = 1019n; // prime, but intentionally TINY and the exponent is public
export const SYMBOLIC = Object.freeze({
  order: Q,
  name: 'Xia 2013 Chapter 5 DCS-UV — symbolic group algebra only',
  limitation: 'Exponents are public; no hardness assumptions hold; confirmation arithmetic only; no genuine DCS or disavowal security claims.'
});
const enc = new TextEncoder();
export const mod = v => ((v % Q) + Q) % Q;
function checked(v) { if(typeof v!== 'bigint' || v<0n || v>=Q) throw new TypeError('Scalar outside toy field'); return v; }
function nonzero(v) { checked(v); if(v===0n) throw new RangeError('Expected nonzero scalar'); return v; }
function sample({randomBytes}={}) {
  if(randomBytes) { const b=randomBytes(2); if(!(b instanceof Uint8Array)||b.length!==2) throw new Error('Invalid injected sampler'); return 1n+BigInt((b[0]<<8)|b[1])%(Q-1n); }
  const b = new Uint8Array(2);
  // Uniform rejection from 2^16 candidates; no modulus bias in default path.
  const limit=65536-(65536%Number(Q-1n));
  for(;;){crypto.getRandomValues(b);const v=(b[0]<<8)|b[1];if(v<limit)return 1n+BigInt(v%Number(Q-1n));}
}
async function digestValue(tag,values){
  const str=tag+'|'+values.map(v=>typeof v==='bigint'?v.toString(16):String(v)).join('|');
  const hash=new Uint8Array(await crypto.subtle.digest('SHA-256',enc.encode(str)));
  let n=0n;for(const b of hash)n=(n<<8n)+BigInt(b);
  return 1n+n%(Q-1n);
}
export async function hashMessage(message){
  if(typeof message!=='string'||!message.trim()||message.length>500)throw new TypeError('Provide a short fictional message');
  return digestValue('XIA2013-SYMBOLIC-MSG', [message]);
}
const randScalar=()=>sample();
export function keygen({signerSecret,confirmerSecret}={}){
  const xs=signerSecret===undefined?randScalar():nonzero(signerSecret);
  const xc=confirmerSecret===undefined?randScalar():nonzero(confirmerSecret);
  // G elements are represented by exponents of generator g, hence g = 1n.
  return Object.freeze({
    signerSecret:xs,confirmerSecret:xc,
    signerPublic:xs,confirmerPublic:xc, generator:1n
  });
}
export function validatePublicSignature(sig){
  return !!sig&&['sigma1','sigma2','s','t'].every(k=>typeof sig[k]==='bigint'&&sig[k]>=0n&&sig[k]<Q)&&sig.s!==0n;
}
export async function issue({message,keys,r,k}={}){
  if(!keys || typeof keys.signerSecret!=='bigint'||typeof keys.confirmerSecret!=='bigint')throw new TypeError('Missing signer and confirmer witnesses');
  nonzero(keys.signerSecret);nonzero(keys.confirmerSecret);
  const h=await hashMessage(message);
  r=r===undefined?randScalar():nonzero(r);
  k=k===undefined?randScalar():nonzero(k);
  const basic=mod(h*keys.signerSecret);
  const sigma1=mod(keys.confirmerPublic*r);
  const sigma2=mod(basic+r);
  const hk=mod(keys.confirmerPublic*k);
  const s=await digestValue('XIA2013-SYMBOLIC-SIGNED-ELGAMAL',[hk,sigma1,sigma2]);
  const t=mod(k+s*r);
  return Object.freeze({message,signerPublic:keys.signerPublic,confirmerPublic:keys.confirmerPublic,
    signature:Object.freeze({sigma1,sigma2,s,t}),
    scheme:'XIA2013-CH5-SYMBOLIC-ONLY'});
}
export async function validFormat(publicData){
  if(!publicData || publicData.scheme!=='XIA2013-CH5-SYMBOLIC-ONLY' ||
    !validatePublicSignature(publicData.signature))return false;
  const {signerPublic,confirmerPublic,signature:a}=publicData;
  try{nonzero(signerPublic);nonzero(confirmerPublic);
    const recoveredCommitment=mod(confirmerPublic*a.t-a.s*a.sigma1);
    const expected=await digestValue('XIA2013-SYMBOLIC-SIGNED-ELGAMAL',[recoveredCommitment,a.sigma1,a.sigma2]);
    return a.s===expected;
  }catch{return false;}
}
export async function extract({publicData,confirmerSecret}={}){
  if(!(await validFormat(publicData)))return Object.freeze({extracted:false,reason:'INVALID_FORMAT'});
  nonzero(confirmerSecret);
  if(confirmerSecret!==publicData.confirmerPublic)return Object.freeze({extracted:false,reason:'WRONG_CONFIRMER'});
  const {sigma1,sigma2}=publicData.signature;
  const xinv=inverse(confirmerSecret);
  const extracted=mod(sigma2-sigma1*xinv);
  const h=await hashMessage(publicData.message);
  // Pairing identity e(g,sig)=e(ys,h) in exponent representation.
  const valid = extracted===mod(publicData.signerPublic*h);
  return Object.freeze({extracted:valid,basic:valid?extracted:null,reason:valid?'VALID_BASIC_SIGNATURE':'BAD_BASIC_SIGNATURE'});
}
function inverse(v){nonzero(v);let t=1n; // Fermat in prime-order exponent field
  let x=v,p=Q-2n;t=1n;while(p){if(p&1n)t=mod(t*x);x=mod(x*x);p>>=1n;}return t;
}
export async function statement(publicData){
  if(!(await validFormat(publicData)))throw new Error('Format proof rejected');
  const h=await hashMessage(publicData.message);
  const {signerPublic:ys,confirmerPublic:yc,signature:{sigma1,sigma2}}=publicData;
  const A=mod(sigma2*yc-sigma1);
  return Object.freeze({
    // A1=A2=e(sigma2,yc)/e(sigma1,g) ; B1=e(h,ys); B2=e(h,yc)
    A1:A,A2:A,B1:mod(h*ys),B2:mod(h*yc),
    C1:yc,C2:ys,D1:1n,D2:1n
  });
}
const spent = new WeakSet();
const toB=role=>role==='confirmer'?1:role==='signer'?2:null;
function checkRelation(s,branch,secret){
  const b=branch===1?[s.B1,s.C1,s.D1]:[s.B2,s.C2,s.D2];
  return mod(b[0]*secret)===s.A1&&mod(b[2]*secret)===b[1];
}
/** Begin Fig 5.1/5.2 proof. The witness belongs ONLY to privateState. */
export async function confirmBegin({publicData,keys,role}={}){
  const branch=toB(role);if(!branch)throw new Error('Select signer or confirmer');
  if(!keys)throw new Error('Missing role keys');
  const secret=role==='confirmer'?keys.confirmerSecret:keys.signerSecret;
  nonzero(secret);
  const s=await statement(publicData);
  if(!checkRelation(s,branch,secret))throw new Error('Cannot honestly prove invalid signature');
  const other=branch===1?2:1;
  const a=randScalar(),bOther=randScalar(),cOther=randScalar();
  const first={};
  for(let j=1;j<=2;j++){
    const B=s['B'+j],D=s['D'+j],C=s['C'+j],A=s['A'+j];
    first['z'+(2*j-1)]=j===branch?mod(B*a):mod(B*bOther+A*cOther);
    first['z'+(2*j)]=j===branch?mod(D*a):mod(D*bOther+C*cOther);
  }
  return Object.freeze({
    statement:s,
    firstMessage:Object.freeze(first),
    privateState:Object.freeze({branch,secret,a,bOther,cOther,used:false})
  });
}
export function verifierChallenge(){
  const b=new Uint8Array(2), size=Number(Q), limit=65536-(65536%size);
  for(;;){crypto.getRandomValues(b);const n=(b[0]<<8)|b[1];if(n<limit)return BigInt(n%size);}
}
export function confirmRespond(session,challenge){
  if(!session?.privateState)throw new Error('Missing signer/confirmer proof session');
  const priv=session.privateState;if(spent.has(priv))throw new Error('First-message randomness already spent');
  spent.add(priv);
  checked(challenge);
  const cReal=mod(challenge-priv.cOther);
  const bReal=mod(priv.a-cReal*priv.secret);
  const response=priv.branch===1?{b1:bReal,b2:priv.bOther,c1:cReal,c2:priv.cOther}:
    {b1:priv.bOther,b2:bReal,c1:priv.cOther,c2:cReal};
  return Object.freeze(response);
}
export function confirmVerify({publicStatement,firstMessage,challenge,response}={}){
  const reject =Object.freeze({equationsHold:false,checks:Object.freeze({invalidInput:false})});
  try{
    if(!publicStatement||!firstMessage||!response||typeof challenge!=='bigint'||challenge<0n||challenge>=Q)return reject;
    const s=publicStatement;
    for(const field of ['A1','A2','B1','B2','C1','C2','D1','D2'])checked(s[field]);
    for(const field of ['z1','z2','z3','z4'])checked(firstMessage[field]);
    for(const field of ['b1','b2','c1','c2'])checked(response[field]);
    const checks={challenge:mod(response.c1+response.c2)===challenge};
    for(let j=1;j<=2;j++){
      const b=response['b'+j],c=response['c'+j];
      checks['groupPairing'+j]=firstMessage['z'+(j*2-1)]===mod(s['B'+j]*b+s['A'+j]*c);
      checks['groupKey'+j]=firstMessage['z'+(j*2)]===mod(s['D'+j]*b+s['C'+j]*c);
    }
    return Object.freeze({equationsHold:Object.values(checks).every(Boolean),checks:Object.freeze(checks)});
  }catch{return reject;}
}
/** The public values equal *exponents* in this model. This destroys secrecy! */
export const securityLimit = 'Public group-element exponents reveal all discrete logarithms. These are real modular identities but NOT cryptographic proof security.';