/**
 * RESEARCH CANDIDATE ONLY. NOT a published corrected protocol, a reviewed
 * DCS disavowal, zero knowledge, secure proof, or production cryptography.
 *
 * The 2011 Wang–Xia–Zhao / Xia 2013 Ch5 disavowal figures print a
 * non-identity beta based on (D^x/C)^a, even while their public keys satisfy
 * C=D^x. A literal implementation cannot pass its first check. THIS MODULE
 * is an independently derived *candidate* inequality relation that instead
 * uses beta=(B^x/A)^a, then verifies the corresponding swapped algebra.
 * No source attribution or security claim is made for this new derivation.
 *
 * Groups are represented by PUBLIC EXPONENTS mod 1019: ZERO security.
 * Work remains: typeset-paper / author / errata check, formal soundness,
 * zero knowledge against malicious/concurrent verifiers, proper pairing,
 * substantive cryptographic parameters and a valid full DCS scheme.
 */
import {statement,validFormat,mod,SYMBOLIC} from './dcs-uv-symbolic.mjs';
const Q=SYMBOLIC.order;
const used=new WeakSet();
const checked=x=>{if(typeof x!=='bigint'||x<0n||x>=Q)throw new TypeError('Out-of-range symbolic scalar');return x;};
function draw(){const b=new Uint8Array(2),width=65536,limit=width-(width%Number(Q));for(;;){crypto.getRandomValues(b);const x=(b[0]<<8)|b[1];if(x<limit)return BigInt(x%Number(Q));}}
const randomNonzero=()=>{let x=0n;while(x===0n)x=draw();return x;};
const which=role=>role==='confirmer'?1:role==='signer'?2:0;
function result(status,checks){return Object.freeze({equationsHold:status,checks:Object.freeze(checks),scope:'RESEARCH CANDIDATE: NOT PUBLISHED DCS DISAVOWAL; NO SECURITY CLAIM'});}
/**
 * Witness-check and one-time first message for an *invalid* claimed message.
 * Public statement always derived from a correctly formatted issued object.
 * The signer or confirmer secret is held only in privateState.
 */
export async function candidateDisavowBegin({publicData,keys,role,coins}={}){
 const real=which(role);if(!real)throw new TypeError('Only Alice or Carol may propose candidate invalidity proof');
 if(!(await validFormat(publicData)))throw new Error('Signed-ElGamal format invalid; reject input, do not call it disavowed');
 const secret=real===1?keys?.confirmerSecret:keys?.signerSecret;
 checked(secret);if(secret===0n)throw new TypeError('Missing nonzero role witness');
 const s=await statement(publicData);
 if(mod(s['D'+real]*secret)!==s['C'+real])throw new Error('Wrong witness for the selected role');
 // REPAIRED candidate, not literally printed author beta.
 const a=coins?.a??randomNonzero();checked(a);if(a===0n)throw new TypeError('Candidate requires nonzero multiplier');
 const betaReal=mod((s['B'+real]*secret-s['A'+real])*a);
 if(betaReal===0n)throw new Error('No inequality witness: cannot honestly disavow the valid relation');
 const e=coins?.e??draw(),ePrime=coins?.ePrime??draw();checked(e);checked(ePrime);
 const simulated=3-real;
 const betaFake=coins?.betaFake??randomNonzero();checked(betaFake);if(betaFake===0n)throw new TypeError('Simulated inequality factor must be nonidentity');
 const cFake=coins?.cFake??draw(),bFake=coins?.bFake??draw(),bPrimeFake=coins?.bPrimeFake??draw();
 for(const t of [cFake,bFake,bPrimeFake])checked(t);
 const b1=real===1?betaReal:betaFake,b2=real===2?betaReal:betaFake;
 const first={beta1:b1,beta2:b2};
 for(let j=1;j<=2;j++){
  const zKey=j===real?mod(s['D'+j]*e-s['C'+j]*ePrime):mod(s['D'+j]*bFake-s['C'+j]*bPrimeFake);
  const zSignature=j===real?mod(s['B'+j]*e-s['A'+j]*ePrime):
     mod(betaFake*cFake+s['B'+j]*bFake-s['A'+j]*bPrimeFake);
  first['z'+(2*j-1)]=zKey;first['z'+(2*j)]=zSignature;
 }
 return Object.freeze({publicData,firstMessage:Object.freeze(first),
   privateState:Object.freeze({real,secret,a,e,ePrime,cFake,bFake,bPrimeFake}),
   scope:'DERIVED INEQUALITY CANDIDATE — NOT PUBLISHED DCS DISAVOWAL'});
}
/** A separate verifier samples challenge only AFTER receiving firstMessage. */
export function candidateVerifierChallenge(){return draw();}
export function candidateDisavowRespond(session,c){
 if(!session?.privateState)throw new TypeError('Missing candidate prover state');
 const st=session.privateState;if(used.has(st))throw new Error('Candidate prover masks already spent');
 used.add(st);checked(c);
 const cReal=mod(c-st.cFake);
 const bReal=mod(st.e-cReal*st.secret*st.a),bPrimeReal=mod(st.ePrime-cReal*st.a);
 return Object.freeze(st.real===1?{c1:cReal,c2:st.cFake,b1:bReal,b1Prime:bPrimeReal,b2:st.bFake,b2Prime:st.bPrimeFake}:
   {c1:st.cFake,c2:cReal,b1:st.bFake,b1Prime:st.bPrimeFake,b2:bReal,b2Prime:bPrimeReal});
}
/** Independent public verifier, deliberately no witness/private-state inputs. */
export async function candidateDisavowVerify({publicData,firstMessage,challenge,response}={}){
 const no=result(false,{invalidInput:false});
 try{
  if(!(await validFormat(publicData)))return no;
  checked(challenge);
  for(const k of ['beta1','beta2','z1','z2','z3','z4'])checked(firstMessage?.[k]);
  for(const k of ['b1','b1Prime','b2','b2Prime','c1','c2'])checked(response?.[k]);
  if(firstMessage.beta1===0n||firstMessage.beta2===0n)return no;
  const s=await statement(publicData);
  const checks={challenge:mod(response.c1+response.c2)===challenge};
  for(let j=1;j<=2;j++){
   const b=response['b'+j],bp=response['b'+j+'Prime'],c=response['c'+j];
   checks['keyRelation'+j]=firstMessage['z'+(2*j-1)]===mod(s['D'+j]*b-s['C'+j]*bp);
   checks['inequalityRelation'+j]=firstMessage['z'+(2*j)]===mod(firstMessage['beta'+j]*c+s['B'+j]*b-s['A'+j]*bp);
  }
  return result(Object.values(checks).every(Boolean),checks);
 }catch{return no;}
}