/**
 * RESEARCH-ONLY WITNESS RELATION INSPECTOR — NOT interactive confirmation π1.
 * Xia 2013 thesis §6.5.1 / §6.5.2, PDF pp. 150,152–153.
 * Discloses the witness on purpose. This is an algebraic preflight, NOT a ZK proof,
 * designated confirmer signature, security proof or public verifier.
 *
 * All numbers are deliberately tiny and insecure (n=253, Γ subgroup mod 23).
 */
import {toyParameters, modPow, inv, challenge, decrypt, gcd} from './cs-paillier.mjs';

const n=toyParameters.n, nSquared=n*n;
export const TOY_GROUP=Object.freeze({prime:23n,order:11n,delta:2n,gamma:8n});
export const TOY_CRS=Object.freeze({modulus:2773n,g2:16n,h2:81n});
const positive=(v,m)=>((v%m)+m)%m;
function checkedScalar(v,name,min,max){
 if(typeof v!=='bigint'||v<min||v>max)throw new RangeError(name+' must be a bounded bigint');
 return v;
}
function groupUnit(x,mod){return typeof x==='bigint'&&x>0n&&x<mod&&gcd(x,mod)===1n;}
function safePow(a,k,mod){
 return k<0n ? modPow(inv(positive(a,mod),mod),-k,mod) : modPow(a,k,mod);
}
export function commitToy(message,opening){
 checkedScalar(message,'message',0n,TOY_GROUP.order-1n);
 checkedScalar(opening,'opening',0n,TOY_GROUP.order-1n);
 return modPow(TOY_GROUP.delta,message,TOY_GROUP.prime)*modPow(TOY_GROUP.gamma,opening,TOY_GROUP.prime)%TOY_GROUP.prime;
}
export function proofAuxiliaryToy(opening,s){
 checkedScalar(opening,'opening',0n,TOY_GROUP.order-1n);
 checkedScalar(s,'auxiliary randomness',0n,TOY_CRS.modulus/4n-1n);
 return modPow(TOY_CRS.g2,opening,TOY_CRS.modulus)*modPow(TOY_CRS.h2,s,TOY_CRS.modulus)%TOY_CRS.modulus;
}
/**
 * Checks the algebraic equations of the π1 witness relation. The provided
 * witness includes decryption key material. Never expose this as a public API.
 * Returns independent named booleans; a mismatch cannot turn into 'confirmed'.
 */
export function inspectPi1Witness({publicKey,privateKey,ciphertext,label,message,psi,opening,s,ell}={}){
 const rejects={invalidInputs:false};
 try{
  if(publicKey?.n!==n||publicKey.h!==n+1n||privateKey?.n!==n)throw Error('Toy modulus and key structure invalid');
  if(![publicKey.g,publicKey.y1,publicKey.y2,publicKey.y3, ciphertext?.u,ciphertext?.e,ciphertext?.v].every(v=>groupUnit(v,nSquared)))throw Error('Malformed public key or ciphertext');
  if(!groupUnit(psi,TOY_GROUP.prime)||!groupUnit(ell,TOY_CRS.modulus))throw Error('Bad commitment or auxiliary statement');
  checkedScalar(message,'message',0n,TOY_GROUP.order-1n);
  checkedScalar(opening,'opening',0n,TOY_GROUP.order-1n);
  checkedScalar(s,'s',0n,TOY_CRS.modulus/4n-1n);
  const {x1,x2,x3}=privateKey;
  for(const [v,name] of [[x1,'x1'],[x2,'x2'],[x3,'x3']])checkedScalar(v,name,1n,nSquared/4n-1n);
  if(typeof label!=='string'||!label)throw Error('Missing label');
  const {g,h,y1,y2,y3}=publicKey,{u,e,v}=ciphertext;
  const H=challenge(u,e,label,n);
  const alpha=psi*safePow(TOY_GROUP.delta,-message,TOY_GROUP.prime)%TOY_GROUP.prime;
  const checks={
    key1:y1===modPow(g,x1,nSquared),
    key2:y2===modPow(g,x2,nSquared),
    key3:y3===modPow(g,x3,nSquared),
    ciphertextE:modPow(e,2n,nSquared)===(modPow(u,2n*x1,nSquared)*modPow(h,2n*opening,nSquared)%nSquared),
    ciphertextV:modPow(v,2n,nSquared)===(modPow(u,2n*(x2+H*x3),nSquared)),
    commitmentOpening:alpha===modPow(TOY_GROUP.gamma,opening,TOY_GROUP.prime),
    auxiliary:ell===proofAuxiliaryToy(opening,s)
  };
  // Important: the algebraic squared-eqs are not the same as a certified
  // labeled-ciphertext decryption. Keep the actual original decrypt distinct.
  let decrypted=false;
  try{decrypted=decrypt(privateKey,publicKey,ciphertext,label)===opening;}catch{decrypted=false;}
  checks.decryptMatchesOpening=decrypted;
  return Object.freeze({relationSatisfied:Object.values(checks).every(Boolean),checks});
 }catch{return Object.freeze({relationSatisfied:false,checks:rejects});}
}
