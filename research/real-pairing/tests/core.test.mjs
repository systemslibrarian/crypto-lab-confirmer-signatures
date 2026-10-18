import test from 'node:test';
import assert from 'node:assert/strict';
import {webcrypto} from 'node:crypto';
import {bls12_381 as bls} from '@noble/curves/bls12-381.js';
import {Q,G1,G2,GT,SCHEME,createKeys,verifyDualPublicKey,
 issue,verifyFormat,extract,publicStatement,messagePoint,
 gtPow,gtEq,gtDiv,pairing} from '../core.mjs';
if(!globalThis.crypto)globalThis.crypto=webcrypto;
test('the real BLS12-381 pairing obeys published bilinearity; no public exponent modeling',()=>{
 const H=messagePoint('Fictional signed letter');
 const lhs=pairing(H.multiply(3n),G2.multiply(5n));
 const rhs=gtPow(pairing(H,G2),15n);
 assert.equal(gtEq(lhs,rhs),true);
 assert.equal(gtEq(lhs,GT.ONE),false);
});
test('dual confirmer G1/G2 key binding verifies both actual elliptic group equations',async()=>{
 const keys=await createKeys({signerSecret:13n,confirmerSecret:37n});
 assert.equal(await verifyDualPublicKey(keys.publicKeys),true);
 const broken={...keys.publicKeys,yc2:G2.multiply(38n)};
 assert.equal(await verifyDualPublicKey(broken),false);
 assert.equal(keys.publicKeys.yc1.equals(G1.multiply(37n)),true);
 assert.equal(keys.publicKeys.yc2.equals(G2.multiply(37n)),true);
});
test('real signed-ElGamal format proof authenticates the encrypted BLS signature structure',async()=>{
 const keys=await createKeys({signerSecret:13n,confirmerSecret:37n});
 const a=await issue({message:'Library book returned.',keys,r:23n,k:41n});
 assert.equal(a.publicData.scheme,SCHEME);
 assert.equal(await verifyFormat(a.publicData),true);
 assert.equal(a.publicData.signature.sigma1.equals(G1.multiply(37n*23n)),true);
 const tampered={...a.publicData,signature:{...a.publicData.signature,t:(a.publicData.signature.t+1n)%Q}};
 assert.equal(await verifyFormat(tampered),false);
});
test('confirmer truly extracts BLS signature and verifies with an independent pairing',async()=>{
 const a=await issue({message:'Fictional agreement'});
 assert.equal(await verifyFormat(a.publicData),true);
 const x=await extract(a.publicData,a.privateKeys.xc);
 assert.equal(x.valid,true);
 assert.equal(x.reason,'VALID_BLS');
 const H=messagePoint(a.publicData.message);
 assert.equal(gtEq(pairing(x.basic,G2),pairing(H,a.publicData.signerPublic)),true);
 assert.equal((await extract(a.publicData,(a.privateKeys.xc+1n)%Q)).valid,false);
});
test('signed-ElGamal format can remain valid for false claimed message; this is why designated confirmation is necessary',async()=>{
 const a=await issue({message:'Package delivered'});
 const altered={...a.publicData,message:'Package not delivered'};
 assert.equal(await verifyFormat(altered),true);
 assert.equal((await extract(altered,a.privateKeys.xc)).valid,false);
});
test('independent pairing statement has both exact signer and confirmer knowledge witnesses',async()=>{
 const a=await issue({message:'Authorized library withdrawal.'});
 const s=await publicStatement(a.publicData);
 assert.equal(gtEq(s.A,gtPow(s.B1,a.privateKeys.xc)),true);
 assert.equal(gtEq(s.A,gtPow(s.B2,a.privateKeys.xs)),true);
 assert.equal(s.C1.equals(G1.multiply(a.privateKeys.xc)),true);
 assert.equal(s.C2.equals(G2.multiply(a.privateKeys.xs)),true);
 const changed=await publicStatement({...a.publicData,message:'Different fact'});
 assert.equal(gtEq(changed.A,gtPow(changed.B1,a.privateKeys.xc)),false);
});
test('signature, signer key and declared ciphertext cannot be changed while preserving format evidence',async()=>{
 const a=await issue({message:'Synthetic package delivered'});
 const s=a.publicData.signature;
 for(const signature of [
  {...s,sigma1:s.sigma1.add(G1)},
  {...s,sigma2:s.sigma2.add(G1)},
  {...s,s:(s.s+1n)%Q}
 ]) assert.equal(await verifyFormat({...a.publicData,signature}),false);
});
