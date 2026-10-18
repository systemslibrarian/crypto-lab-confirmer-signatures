/**
 * RESEARCH — GENUINE BLS12-381 GROUP AND PAIRING ARITHMETIC.
 *
 * This uses @noble/curves 2.4.0 and real BLS12-381 G1, G2 and Fp12, with
 * RFC 9380 hash-to-curve. This is NOT a production DCS or a verified
 * implementation of Wang–Xia–Zhao (2011) / Xia (2013): their presentation
 * assumes SYMMETRIC pairings. We explicitly represent a confirmer key in
 * BOTH G1 and G2 and certify same-secret consistency. That adaptation and
 * the locally chosen encodings require independent security review.
 *
 * Confirm/Disavow are implemented separately under the genuine group math,
 * but transcript non-transferability, concurrent zero knowledge, a proven
 * malicious-verifier compiler and the repaired disavowal relation are NOT
 * claimed. Do not ship real keys, signatures or sensitive data in this demo.
 */
import { bls12_381 as bls } from '@noble/curves/bls12-381.js';
export const Q=BigInt('0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001');
const encoder=new TextEncoder();
export const G1=bls.G1.Point.BASE;
export const G2=bls.G2.Point.BASE;
export const GT=bls.fields.Fp12;
export const SCHEME='XIA-2013-TYPE3-RESEARCH-NOT-AUDITED';
export const SOURCE_URL='https://eprint.iacr.org/2011/182';
export const SCOPE='REAL PAIRING ARITHMETIC — RESEARCH ADAPTATION, NOT FULL DCS SECURITY';
export const mod=x=>((x%Q)+Q)%Q;
function assertScalar(x,allowZero=false){
 if(typeof x!=='bigint'||x<0n||x>=Q||(x===0n&&!allowZero))
   throw new RangeError('Scalar outside BLS12-381 subgroup');
 return x;
}
export function randomScalar(){
 for(let i=0;i<1000;i++){
  const buf=new Uint8Array(32);
  if(!globalThis.crypto?.getRandomValues)throw new Error('Secure randomness unavailable');
  crypto.getRandomValues(buf);
  const x=BigInt('0x'+Array.from(buf,b=>b.toString(16).padStart(2,'0')).join(''));
  if(x>0n&&x<Q)return x;
 }
 throw new Error('Unable to sample field scalar');
}
const utf8=s=>encoder.encode(s);
const bytes=n=>n.toBytes();
const isG1=p=>p && typeof p.multiply==='function' &&
  typeof p.toBytes==='function' && !p.equals(bls.G1.Point.ZERO);
const isG2=p=>p && typeof p.multiply==='function' &&
  typeof p.toBytes==='function' && !p.equals(bls.G2.Point.ZERO);
export const isNonIdentityPair=x=>!GT.eql(x,GT.ONE);
function pushPart(arr,source){
 const b=typeof source==='string'?utf8(source):
  source instanceof Uint8Array?source:
  typeof source==='bigint'?utf8(source.toString(16)):
  bytes(source);
 if(b.length>65535)throw new RangeError('Oversize transcript field');
 arr.push((b.length>>8)&255,b.length&255,...b);
}
export async function hashScalar(domain,...values){
 if(!globalThis.crypto?.subtle)throw new Error('WebCrypto SHA-256 unavailable');
 const arr=[];
 pushPart(arr,SCHEME);pushPart(arr,domain);
 for(const value of values)pushPart(arr,value);
 const hash=new Uint8Array(await crypto.subtle.digest('SHA-256',new Uint8Array(arr)));
 return BigInt('0x'+Array.from(hash,b=>b.toString(16).padStart(2,'0')).join(''))%Q;
}
export function messagePoint(message){
 if(typeof message!=='string'||message.trim().length===0||message.length>600||
    /[\u0000-\u001f\u007f]/.test(message))
   throw new TypeError('Use a short nonempty fictional statement');
 return bls.G1.hashToCurve(utf8(message), {
  DST:'DCS_XIA2013_RESEARCH_BLS12381G1_XMD:SHA-256_SSWU_RO_'
 });
}
export const gtPow=(x,e)=>GT.pow(x,mod(e));
export const gtMul=(x,y)=>GT.mul(x,y);
export const gtDiv=(x,y)=>GT.mul(x,GT.inv(y));
export const gtEq=(x,y)=>GT.eql(x,y);
export const pairing=(g1,g2)=>bls.pairing(g1,g2);
export function shortenedPoint(p){
 const hex=Array.from(p.toBytes(),b=>b.toString(16).padStart(2,'0')).join('');
 return hex.slice(0,24)+'…'+hex.slice(-20);
}
export function toHex(data){
 return Array.from(data,b=>b.toString(16).padStart(2,'0')).join('');
}
/**
 * A TYPE-3 extension needs independent representations of the same xc in
 * G1 (signed ElGamal) and G2 (pairing). Both are explicitly certified here
 * by a Fiat–Shamir proof of equal discrete logarithms across both groups.
 * This key registration proof is OUR adaptation, not a theorem from Xia.
 */
export async function createKeys({signerSecret,confirmerSecret}={}){
 const xs=assertScalar(signerSecret??randomScalar());
 const xc=assertScalar(confirmerSecret??randomScalar());
 const ys2=G2.multiply(xs),yc1=G1.multiply(xc),yc2=G2.multiply(xc);
 const a=randomScalar(),R1=G1.multiply(a),R2=G2.multiply(a);
 const c=await hashScalar('dual-key-bind-v1',yc1,yc2,R1,R2);
 const proof=Object.freeze({R1,R2,z:mod(a+c*xc)});
 const publicKeys=Object.freeze({ys2,yc1,yc2,proof});
 return Object.freeze({publicKeys,privateKeys:Object.freeze({xs,xc})});
}
export async function verifyDualPublicKey(p){
 try{
  if(!p||!isG1(p.yc1)||!isG2(p.yc2)||
     !isG1(p.proof?.R1)||!isG2(p.proof?.R2))return false;
  const z=assertScalar(p.proof.z,true);
  const c=await hashScalar('dual-key-bind-v1',p.yc1,p.yc2,p.proof.R1,p.proof.R2);
  return G1.multiply(z).equals(p.proof.R1.add(p.yc1.multiply(c))) &&
         G2.multiply(z).equals(p.proof.R2.add(p.yc2.multiply(c)));
 }catch{return false;}
}
/**
 * Signed ElGamal encrypts actual BLS signature sigma=xs*H(m):
 * sigma1=r*(xc*G1), sigma2=sigma+r*G1.
 * signed-ElGamal proof uses s=H0(k*yc1,sigma1,sigma2);
 * t=k+s*r mod q. Encodings are local domain-separated choices.
 */
export async function issue({message,keys,r,k}={}){
 if(!keys)keys=await createKeys();
 if(!(await verifyDualPublicKey(keys.publicKeys)))throw Error('Mismatched confirmer public groups');
 const {xs,xc}=keys.privateKeys;
 assertScalar(xs);assertScalar(xc);
 const R=assertScalar(r??randomScalar()),K=assertScalar(k??randomScalar());
 const h=messagePoint(message);
 const sigma=h.multiply(xs);
 const {ys2,yc1,yc2,proof}=keys.publicKeys;
 const sigma1=yc1.multiply(R),sigma2=sigma.add(G1.multiply(R));
 const s=await hashScalar('signed-elgamal-format-v1',yc1.multiply(K),sigma1,sigma2);
 const t=mod(K+s*R);
 const publicData=Object.freeze({
  scheme:SCHEME,message,signerPublic:ys2,confirmerPublicG1:yc1,
  confirmerPublicG2:yc2,confirmerKeyProof:proof,
  signature:Object.freeze({sigma1,sigma2,s,t})
 });
 return Object.freeze({publicData,privateKeys:keys.privateKeys});
}
/** Format proof check does NOT determine whether message/signature is valid. */
export async function verifyFormat(publicData){
 try{
  if(publicData?.scheme!==SCHEME||!isG2(publicData.signerPublic))return false;
  const {sigma1,sigma2,s,t}=publicData.signature??{};
  if(!isG1(sigma1)||!isG1(sigma2))return false;
  assertScalar(s,true);assertScalar(t,true);
  const ok=await verifyDualPublicKey({
    yc1:publicData.confirmerPublicG1,yc2:publicData.confirmerPublicG2,
    proof:publicData.confirmerKeyProof
  });
  if(!ok)return false;
  const recovered=publicData.confirmerPublicG1.multiply(t).subtract(sigma1.multiply(s));
  return s===(await hashScalar('signed-elgamal-format-v1',recovered,sigma1,sigma2));
 }catch{return false;}
}
export function invertNonzero(x){
 assertScalar(x);let a=x,b=Q,u=1n,v=0n;
 while(b){const k=a/b;[a,b]=[b,a-k*b];[u,v]=[v,u-k*v];}
 return mod(u);
}
/** Only Carol can convert this into the underlying basic BLS signature. */
export async function extract(publicData,xc){
 if(!(await verifyFormat(publicData)))return Object.freeze({valid:false,reason:'BAD_FORMAT'});
 try{
  assertScalar(xc);
  if(!G1.multiply(xc).equals(publicData.confirmerPublicG1) ||
     !G2.multiply(xc).equals(publicData.confirmerPublicG2))
    return Object.freeze({valid:false,reason:'WRONG_CONFIRMER'});
  const {sigma1,sigma2}=publicData.signature;
  const basic=sigma2.subtract(sigma1.multiply(invertNonzero(xc)));
  const h=messagePoint(publicData.message);
  const valid=gtEq(pairing(basic,G2),pairing(h,publicData.signerPublic));
  return Object.freeze({valid,basic:valid?basic:null,reason:valid?'VALID_BLS':'WRONG_MESSAGE'});
 }catch{return Object.freeze({valid:false,reason:'MALFORMED'});}
}
/** Independently derived OR proof statement. No prover-supplied A,B,C,D. */
export async function publicStatement(d){
 if(!(await verifyFormat(d)))throw Error('Invalid signed-ElGamal format');
 const h=messagePoint(d.message);
 const {sigma1,sigma2}=d.signature;
 const A=gtDiv(pairing(sigma2,d.confirmerPublicG2),pairing(sigma1,G2));
 const B1=pairing(h,d.signerPublic);
 const B2=pairing(h,d.confirmerPublicG2);
 return Object.freeze({
  A,B1,B2,C1:d.confirmerPublicG1,C2:d.signerPublic,
  D1:G1,D2:G2
 });
}
