/**
 * INDEPENDENT MATHEMATICAL RECONSTRUCTION — REAL-GROUP INEQUALITY OR PROOF.
 *
 * Xia 2013 thesis Fig 5.3/5.4 and Wang–Xia–Zhao 2011 Fig 4/5 print a
 * disavowal beta = (D^x/C)^a while ALSO specifying C=D^x.
 * This forces beta=identity, contradicting beta != identity.
 *
 * We DO NOT silently call that published protocol implemented. Instead,
 * we implement and test a candidate correction to the PRECISE inequality
 * statement in Xia 2013 §5.5:
 *
 *  (C1=D1^xc AND A!=B1^xc) OR (C2=D2^xs AND A!=B2^xs).
 *
 * For the real branch set beta=(B^x/A)^a != 1, where a!=0.
 * The independent public verifier checks:
 *   zKey=D^b1/C^b2,
 *   zPair=beta^c * B^b1/A^b2.
 * With b1=e-c*x*a and b2=e'-c*a these equations agree exactly.
 *
 * THIS IS A MATHEMATICALLY CONSISTENT RESEARCH PROPOSAL, NOT a corrected
 * peer-reviewed publication, audited Sigma proof, malicious-verifier CZK,
 * non-transferability guarantee or production DCS security result.
 * Separate mathematician/author review is REQUIRED before release as DCS.
 */
import {
 Q,G1,G2,GT,SCOPE,mod,randomScalar,randomFieldScalar,isTargetGroup,gtPow,gtMul,gtDiv,gtEq,
 pairing,publicStatement,verifyFormat
} from './core.mjs';
const spent=new WeakSet();
const times=(P,e)=>{
 const x=mod(e);
 return x===0n?P.subtract(P):P.multiply(x);
};
const branchS=(s,j)=>j===1?
  {B:s.B1,C:s.C1,D:s.D1}:
  {B:s.B2,C:s.C2,D:s.D2};
const gtRatio=(B,A,x)=>gtDiv(gtPow(B,x),A);
function challengeOk(c){return typeof c==='bigint'&&c>=0n&&c<Q;}
function betaValid(b){
 return isTargetGroup(b,{nonidentity:true});
}
function sourcePointValid(p,base,nonidentity=false){
 try{
  if(!(p instanceof base.constructor))return false;
  if(p.is0())return !nonidentity;
  p.assertValidity();
  return !nonidentity||!p.equals(base.subtract(base));
 }catch{return false;}
}
/**
 * Prover starts ONLY when private witness matches registered public key and
 * contradicts the alleged pairing validity. False or valid signatures cannot
 * acquire a dishonest "disavowed" decision from the honest prover.
 */
export async function beginDisavow({publicData,privateKeys,role='confirmer'}={}){
 if(!(await verifyFormat(publicData)))throw new Error('Malformed signed-ElGamal input; not a disavowal');
 const s=await publicStatement(publicData);
 const real=role==='confirmer'?1:role==='signer'?2:0;
 if(!real)throw new Error('Select signer or confirmer');
 const {B,C,D}=branchS(s,real);
 const x=real===1?privateKeys?.xc:privateKeys?.xs;
 if(typeof x!=='bigint'||x<=0n||x>=Q||
    !times(D,x).equals(C))throw new Error('No matching private role witness');
 const ratio=gtRatio(B,s.A,x);
 if(!betaValid(ratio))throw new Error('Alleged signature satisfies role validity; cannot honestly disavow');
 const fake=3-real;
 const a=randomScalar(),e=randomFieldScalar(),ePrime=randomFieldScalar();
 const cFake=randomFieldScalar(),bFake1=randomFieldScalar(),bFake2=randomFieldScalar();
 const betaReal=gtPow(ratio,a);
 const betaFake=gtPow(pairing(G1,G2),randomScalar());
 if(!betaValid(betaReal)||!betaValid(betaFake))throw new Error('Nontrivial disavowal base missing');
 const first={};
 for(const j of [1,2]){
  const {B,C,D}=branchS(s,j);
  const realBranch=j===real;
  const beta=realBranch?betaReal:betaFake;
  const zKey=realBranch?
    times(D,e).subtract(times(C,ePrime)):
    times(D,bFake1).subtract(times(C,bFake2));
  const zPair=realBranch?
    gtDiv(gtPow(B,e),gtPow(s.A,ePrime)):
    gtMul(gtPow(beta,cFake),gtDiv(gtPow(B,bFake1),gtPow(s.A,bFake2)));
  first['beta'+j]=beta;
  first['zKey'+j]=zKey;
  first['zPair'+j]=zPair;
 }
 return Object.freeze({
  mode:'REAL-PAIRING-DISAVOW-RESEARCH',
  role,
  firstMessage:Object.freeze(first),
  _private:Object.freeze({real,x,a,e,ePrime,cFake,bFake1,bFake2}),
  status:'AWAITING_INDEPENDENT_VERIFIER_CHALLENGE'
 });
}
export function respondDisavow(session,c){
 if(session?.mode!=='REAL-PAIRING-DISAVOW-RESEARCH'||!session._private)
  throw new Error('No private inequality proof session');
 if(spent.has(session._private))throw new Error('Disavowal first message already spent');
 spent.add(session._private);
 if(!challengeOk(c))throw new RangeError('Verifier challenge outside subgroup order');
 const p=session._private;
 const cReal=mod(c-p.cFake);
 const bReal1=mod(p.e-cReal*p.x*p.a),bReal2=mod(p.ePrime-cReal*p.a);
 return Object.freeze(p.real===1?
  {b11:bReal1,b12:bReal2,c1:cReal,b21:p.bFake1,b22:p.bFake2,c2:p.cFake}:
  {b11:p.bFake1,b12:p.bFake2,c1:p.cFake,b21:bReal1,b22:bReal2,c2:cReal});
}
/** Public-only checker of all four candidate disavowal equations. */
export function checkDisavowStatement(s,z,c,response){
 const fail=Object.freeze({equationsHold:false,
  checks:Object.freeze({invalidInput:false}),security:SCOPE});
 try{
  if(!s||!z||!response||!challengeOk(c))return fail;
  if(!isTargetGroup(s.A)||!isTargetGroup(s.B1)||!isTargetGroup(s.B2)||
     !sourcePointValid(s.C1,G1,true)||!sourcePointValid(s.C2,G2,true)||
     !sourcePointValid(s.D1,G1,true)||!sourcePointValid(s.D2,G2,true))return fail;
  for(const j of [1,2]){
   if(!betaValid(z['beta'+j])||!isTargetGroup(z['zPair'+j])||
      !sourcePointValid(z['zKey'+j],j===1?G1:G2))return fail;
   for(const f of ['b'+j+'1','b'+j+'2','c'+j])
     if(!challengeOk(response[f]))return fail;
  }
  const checks={
   challenge:mod(response.c1+response.c2)===c,
   nonidentity1:betaValid(z.beta1),
   nonidentity2:betaValid(z.beta2)
  };
  for(const j of [1,2]){
   const {B,C,D}=branchS(s,j);
   const b1=response['b'+j+'1'],b2=response['b'+j+'2'];
   const cj=response['c'+j],beta=z['beta'+j];
   checks['publicKey'+j]=z['zKey'+j].equals(times(D,b1).subtract(times(C,b2)));
   const expected=gtMul(gtPow(beta,cj),gtDiv(gtPow(B,b1),gtPow(s.A,b2)));
   checks['pairingInequality'+j]=gtEq(z['zPair'+j],expected);
  }
  return Object.freeze({equationsHold:Object.values(checks).every(Boolean),
   checks:Object.freeze(checks),security:SCOPE});
 }catch{return fail;}
}
export async function verifyDisavow({publicData,firstMessage,challenge,response}={}){
 try{
  const s=await publicStatement(publicData);
  return checkDisavowStatement(s,firstMessage,challenge,response);
 }catch{
  return Object.freeze({equationsHold:false,
   checks:Object.freeze({invalidInput:false}),security:SCOPE});
 }
}
/**
 * WARNING: A transcript author can simulate an accepting public proof for a
 * valid or invalid statement by choosing challenge and responses first.
 * It does NOT establish an actual Bob->Alice/Carol interaction.
 */
export async function simulateDisavow({publicData,challenge=randomFieldScalar()}={}){
 if(!challengeOk(challenge))throw new RangeError('Verifier challenge outside subgroup order');
 const s=await publicStatement(publicData);
 const z={},response={};
 const c1=randomFieldScalar();
 for(const j of [1,2]){
  const {B,C,D}=branchS(s,j);
  const beta=gtPow(pairing(G1,G2),randomScalar());
  const b1=randomFieldScalar(),b2=randomFieldScalar(),cj=j===1?c1:mod(challenge-c1);
  response['b'+j+'1']=b1;response['b'+j+'2']=b2;response['c'+j]=cj;
  z['beta'+j]=beta;
  z['zKey'+j]=times(D,b1).subtract(times(C,b2));
  z['zPair'+j]=gtMul(gtPow(beta,cj),gtDiv(gtPow(B,b1),gtPow(s.A,b2)));
 }
 return Object.freeze({firstMessage:Object.freeze(z),
  challenge,
  response:Object.freeze(response),simulated:true,
  disclosure:'Simulator chose the challenge itself. This is not live disavowal.'});
}
