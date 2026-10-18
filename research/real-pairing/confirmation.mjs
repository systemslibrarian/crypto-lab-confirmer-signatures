/**
 * Real-group Xia 2013 / Wang–Xia–Zhao 2011 confirmation OR-protocol equations.
 * HONEST-VERIFIER, THREE-MOVE RESEARCH ADAPTATION ONLY.
 *
 * We use real BLS12-381 Type-3 pairings. Carol's G1/G2 public keys have a
 * same-scalar certificate (see core.mjs), an explicit extension to the
 * symmetric-pairing paper. The paper's concurrent-ZK/non-transferability
 * security guarantees do NOT automatically transfer to this version.
 *
 * Two branches, both publicly checked:
 *   e(σ2,yc)/e(σ1,g) == e(H(m),ys)^xc and yc=G1^xc
 * OR
 *   e(σ2,yc)/e(σ1,g) == e(H(m),yc)^xs and ys=G2^xs.
 */
import {
 Q,G1,G2,GT,SCHEME,SCOPE,mod,randomScalar,gtPow,gtEq,gtMul,
 publicStatement,verifyFormat
} from './core.mjs';
const spent=new WeakSet();
const times=(P,x)=>{
 const s=mod(x);
 return s===0n?P.subtract(P):P.multiply(s);
};
function branchS(s,j){
 return j===1?{B:s.B1,C:s.C1,D:s.D1}:{B:s.B2,C:s.C2,D:s.D2};
}
function correctRealWitness(s,x,j){
 const {B,C,D}=branchS(s,j);
 return C.equals(times(D,x))&&gtEq(s.A,gtPow(B,x));
}
function ensureChallenge(c){
 if(typeof c!=='bigint'||c<0n||c>=Q)throw new RangeError('Verifier challenge outside field');
}
function challengeBeforeReply(session,c){
 if(session?.mode!=='REAL-PAIRING-OR-CONFIRM'||
    !session._private)throw new Error('No valid session');
 if(spent.has(session._private))throw new Error('First-message blinding already used');
 spent.add(session._private);
 ensureChallenge(c);
}
/** Prover commits once; does not see Bob's independently chosen challenge. */
export async function beginConfirmation({publicData,privateKeys,role='confirmer'}={}){
 if(!(await verifyFormat(publicData)))throw Error('Invalid signed-ElGamal public envelope');
 const s=await publicStatement(publicData);
 const real=role==='confirmer'?1:role==='signer'?2:0;
 if(!real)throw new Error('Select signer or confirmer');
 const secret=real===1?privateKeys?.xc:privateKeys?.xs;
 if(typeof secret!=='bigint'||secret<=0n||secret>=Q||
    !correctRealWitness(s,secret,real))
   throw new Error('Cannot honestly confirm an invalid alleged signature');
 const fake=3-real;
 const a=randomScalar(),fakeB=randomScalar(),fakeC=randomScalar();
 const z={};
 for(const j of [1,2]){
  const {B,C,D}=branchS(s,j);
  z['z'+(2*j-1)]=j===real?gtPow(B,a):
    gtMul(gtPow(B,fakeB),gtPow(s.A,fakeC));
  z['z'+(2*j)]=j===real?times(D,a):
    times(D,fakeB).add(times(C,fakeC));
 }
 const state=Object.freeze({real,secret,a,fakeB,fakeC});
 return Object.freeze({
  mode:'REAL-PAIRING-OR-CONFIRM',
  firstMessage:Object.freeze(z),
  role,
  _private:state,
  status:'AWAITING_BOB_CHALLENGE'
 });
}
export function chooseVerifierChallenge(){
 return randomScalar();
}
/** One-use private response. Only b1,b2,c1,c2 are disclosed to Bob. */
export function respondConfirmation(session,c){
 challengeBeforeReply(session,c);
 const {real,secret,a,fakeB,fakeC}=session._private;
 const cReal=mod(c-fakeC),bReal=mod(a-cReal*secret);
 return Object.freeze(real===1?
  {b1:bReal,b2:fakeB,c1:cReal,c2:fakeC}:
  {b1:fakeB,b2:bReal,c1:fakeC,c2:cReal}
 );
}
export function checkConfirmationStatement(s,firstMessage,c,response){
 const failure=Object.freeze({equationsHold:false,
  checks:Object.freeze({invalidInput:false}),security:SCOPE});
 try{
  ensureChallenge(c);
  if(!s||!firstMessage||!response)return failure;
  const z=firstMessage;
  if(!GT.eql(z.z1,z.z1)||!GT.eql(z.z3,z.z3))return failure;
  for(const field of ['b1','b2','c1','c2'])
   if(typeof response[field]!=='bigint'||response[field]<0n||response[field]>=Q)return failure;
  const checks={challenge:mod(response.c1+response.c2)===c};
  for(const j of [1,2]){
   const {B,C,D}=branchS(s,j),b=response['b'+j],cj=response['c'+j];
   checks['pairing'+j]=gtEq(z['z'+(2*j-1)],
     gtMul(gtPow(B,b),gtPow(s.A,cj)));
   checks['publicKey'+j]=z['z'+(2*j)].equals(
     times(D,b).add(times(C,cj)));
  }
  return Object.freeze({equationsHold:Object.values(checks).every(Boolean),
   checks:Object.freeze(checks),security:SCOPE});
 }catch{return failure;}
}
/** Never trust a prover-supplied A,B,C,D: derive it from signed bytes. */
export async function verifyConfirmation({publicData,firstMessage,challenge,response}={}){
 try{
  const s=await publicStatement(publicData);
  return checkConfirmationStatement(s,firstMessage,challenge,response);
 }catch{return Object.freeze({equationsHold:false,
  checks:Object.freeze({invalidInput:false}),security:SCOPE});}
}
/**
 * HVZK-style simulator: chooses the verifier challenge itself. The transcript
 * passes public algebra even for an INVALID alleged signature. This is an
 * EXAMPLE of why a posted transcript is NOT evidence of a live, independent
 * verification interaction. It does not prove concurrency security.
 */
export async function simulateConfirmation({publicData}={}){
 const s=await publicStatement(publicData);
 const b1=randomScalar(),b2=randomScalar(),c1=randomScalar(),c2=randomScalar();
 const firstMessage=Object.freeze({
  z1:gtMul(gtPow(s.B1,b1),gtPow(s.A,c1)),
  z2:times(s.D1,b1).add(times(s.C1,c1)),
  z3:gtMul(gtPow(s.B2,b2),gtPow(s.A,c2)),
  z4:times(s.D2,b2).add(times(s.C2,c2))
 });
 return Object.freeze({firstMessage,challenge:mod(c1+c2),
  response:Object.freeze({b1,b2,c1,c2}),
  simulated:true,
  disclosure:'Challenge was chosen by transcript author, NOT an independent verifier'});
}
