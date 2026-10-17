/**
 * RESEARCH ONLY: local decryptor-side predicates behind Camenisch–Shoup (2003)
 * §7.3, applied to Xia's 2013 thesis Chapter 6. It is NOT an affirmative
 * disavowal proof or zero-knowledge / designated confirmer protocol.
 *
 * Toy n=253 and Γ subgroup of Z_23*: all factors and secrets are accessible.
 * A real disavowal needs a sound interactive OR proof, exact interval proof,
 * full ciphertext/label checking, secure parameters and non-transferability.
 */
import {toyParameters,modPow,inv,gcd,challenge,decrypt,absResidue} from './cs-paillier.mjs';

const n=toyParameters.n, modulus=n*n;
export const TOY_DISAVOW_GROUP=Object.freeze({prime:23n,order:11n,generator:2n});
const square=x=>x*x%modulus;
function units(x,M){return typeof x==='bigint' && x>0n&&x<M&&gcd(x,M)===1n}
function subgroupContains(x){
 // Only feasible because the group is deliberately and trivially tiny.
 for(let r=0n;r<n;r++)if(modPow(n+1n,r,modulus)===x)return true;
 return false;
}
function output(branch,reason,measurements={}){
 return Object.freeze({branch,reason,measurements:Object.freeze(measurements),security:'RESEARCH PREDICATE ONLY — NOT A DISAVOWAL PROOF'});
}
function hasKeyPair(p,k){
 if(p?.n!==n||p.h!==n+1n||k?.n!==n)return false;
 if(![p.g,p.y1,p.y2,p.y3].every(x=>units(x,modulus)))return false;
 if(![k.x1,k.x2,k.x3].every(x=>typeof x==='bigint' && x>0n && x<modulus))return false;
 return p.y1===modPow(p.g,k.x1,modulus)&&p.y2===modPow(p.g,k.x2,modulus)&&p.y3===modPow(p.g,k.x3,modulus);
}
/**
 * The inspector is fed the decryption key. It reports which relation fails;
 * unlike a proof, it never convinces an independent verifier of anything.
 * claim is δ from CS §7.3, an alleged Γ element encoding the plaintext r;
 * it is NOT Xia's message commitment ψ.
 */
export function diagnoseToyDisavowal({publicKey,privateKey,ciphertext,label,claim}={}){
 try {
  if(!hasKeyPair(publicKey,privateKey)||typeof label!=='string'||label.length===0||label.length>200)return output('REJECT_INPUT','Invalid key pair or label');
  const {u,e,v}=ciphertext??{};
  if(![u,e,v].every(x=>units(x,modulus))||v!==absResidue(v,modulus))return output('REJECT_INPUT','Malformed ciphertext or noncanonical tag');
  const {prime,order,generator}=TOY_DISAVOW_GROUP;
  if(!units(claim,prime)||modPow(claim,order,prime)!==1n)return output('REJECT_INPUT','Claim not in the commitment subgroup');
  const H=challenge(u,e,label,n),{x1,x2,x3}=privateKey;
  const R=modPow(u,x2+H*x3,modulus)*inv(v,modulus)%modulus;
  const tagPowerN=modPow(R,2n*n,modulus)===1n;
  if(!tagPowerN)return output('CASE_1_TAG_ORDER','Tag relation fails at exponent 2n', {tagPowerN:false});
  const tagSquared=square(R)===1n;
  if(!tagSquared)return output('CASE_2_TAG_SQUARE','Tag relation fails at exponent 2',{tagPowerN:true,tagSquared:false});
  const Q=square(modPow(u,x1,modulus)*inv(e,modulus)%modulus);
  const representable=subgroupContains(Q);
  if(!representable)return output('CASE_3_PLAINTEXT_GROUP','Ciphertext plaintext does not lie in the required h-subgroup',{tagPowerN:true,tagSquared:true,hMembership:false});
  let r;
  try {r=decrypt(privateKey,publicKey,ciphertext,label)}
  catch {return output('INDETERMINATE_TOY','Tag passed and subgroup matched, but full labeled decrypt rejected; do not infer invalidity.');}
  const expected=modPow(generator,r%order,prime);
  if(claim!==expected)return output('CASE_4_GROUP_MISMATCH','Claimed discrete-log relation does not match decrypted plaintext',{r:r.toString(),claim:claim.toString(),expected:expected.toString()});
  return output('MATCH','Local decryption and alleged discrete-log relation agree',{r:r.toString(),expected:expected.toString()});
 }catch{return output('REJECT_INPUT','Unusable input; not a proof of invalidity');}
}
