/** Public-only research wire format. No session or private-key object is serialized. */
import {bls12_381 as bls} from '@noble/curves/bls12-381.js';
import {toHex} from './core.mjs';
export const TRANSCRIPT_FORMAT='signature-gate-public-transcript-v1';
const point=p=>toHex(p.toBytes());
const scalar=x=>x.toString(16);
// Fp12 tower -> polynomial basis with w^12 - 2*w^6 + 2 = 0.
// u=w^6-1, v=w^2; each (a+b*u)*w^k becomes (a-b)*w^k+b*w^(k+6).
export function targetCoefficients(t){
 const p=bls.fields.Fp.ORDER,out=Array(12).fill('0');
 for(const [k,z] of [[0,t.c0.c0],[2,t.c0.c1],[4,t.c0.c2],
                    [1,t.c1.c0],[3,t.c1.c1],[5,t.c1.c2]]){
  out[k]=((z.c0-z.c1+p)%p).toString(16);out[k+6]=z.c1.toString(16);
 }
 return out;
}
export function publicEnvelope(d){
 return {scheme:d.scheme,message:d.message,
  signerPublic:point(d.signerPublic),confirmerPublicG1:point(d.confirmerPublicG1),
  confirmerPublicG2:point(d.confirmerPublicG2),
  confirmerKeyProof:{R1:point(d.confirmerKeyProof.R1),R2:point(d.confirmerKeyProof.R2),z:scalar(d.confirmerKeyProof.z)},
  signature:{sigma1:point(d.signature.sigma1),sigma2:point(d.signature.sigma2),s:scalar(d.signature.s),t:scalar(d.signature.t)}};
}
export function exportTranscript({publicData,kind,firstMessage,challenge,response,provenance='interactive-browser'}={}){
 if(!['confirmation','disavowal'].includes(kind))throw Error('Unknown proof kind');
 const f=firstMessage;
 const first=kind==='confirmation'?{z1:targetCoefficients(f.z1),z2:point(f.z2),z3:targetCoefficients(f.z3),z4:point(f.z4)}:
  {beta1:targetCoefficients(f.beta1),beta2:targetCoefficients(f.beta2),
   zKey1:point(f.zKey1),zKey2:point(f.zKey2),zPair1:targetCoefficients(f.zPair1),zPair2:targetCoefficients(f.zPair2)};
 const fields=kind==='confirmation'?['b1','b2','c1','c2']:['b11','b12','b21','b22','c1','c2'];
 return {format:TRANSCRIPT_FORMAT,provenance,
  warning:'Public equation check only. This file cannot prove who chose the challenge or establish full DCS security.',
  publicData:publicEnvelope(publicData),proof:{kind,firstMessage:first,challenge:scalar(challenge),
   response:Object.fromEntries(fields.map(k=>[k,scalar(response[k])]))}};
}
