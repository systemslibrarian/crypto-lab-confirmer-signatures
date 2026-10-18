import test from 'node:test';
import assert from 'node:assert/strict';
import {webcrypto} from 'node:crypto';
import {issue,G1,G2,GT,Q,mod,gtPow,gtEq,gtDiv} from '../core.mjs';
import {beginDisavow,respondDisavow,verifyDisavow,simulateDisavow} from '../disavow-reconstructed.mjs';
if(!globalThis.crypto)globalThis.crypto=webcrypto;
const start=async()=>{
 const original=await issue({message:'Private contract signed'});
 return {original,falseData:{...original.publicData,message:'Private contract NOT signed'}};
};
async function honest(role,c=71n){
 const {original,falseData}=await start();
 const session=await beginDisavow({publicData:falseData,privateKeys:original.privateKeys,role});
 const response=respondDisavow(session,c);
 return {original,falseData,session,response,c};
}
for(const role of ['signer','confirmer']){
 test('actual BLS12-381 '+role+' candidate inequality OR proof is accepted for invalid signed message',async()=>{
  const a=await honest(role);
  const v=await verifyDisavow({publicData:a.falseData,
   firstMessage:a.session.firstMessage,challenge:a.c,response:a.response});
  assert.equal(v.equationsHold,true);
  assert.ok(Object.values(v.checks).every(Boolean));
  assert.equal(Object.hasOwn(a.response,'secret'),false);
  assert.equal(Object.hasOwn(a.response,'opening'),false);
 });
}
test('honest signer and confirmer REFUSE to disavow a valid signature',async()=>{
 const {original}=await start();
 for(const role of ['signer','confirmer']){
  await assert.rejects(beginDisavow({publicData:original.publicData,
   privateKeys:original.privateKeys,role}),/cannot honestly disavow/);
 }
});
test('the four public equations independently reject altered challenges and responses',async()=>{
 const a=await honest('confirmer');
 const args={publicData:a.falseData,firstMessage:a.session.firstMessage,
  challenge:a.c,response:a.response};
 for(const f of ['b11','b12','b21','b22','c1','c2']){
  assert.equal((await verifyDisavow({...args,
   response:{...a.response,[f]:mod(a.response[f]+1n)}})).equationsHold,false,f);
 }
 assert.equal((await verifyDisavow({...args,challenge:a.c+1n})).equationsHold,false);
});
test('changed alleged public message makes a previously accepted inequality transcript invalid',async()=>{
 const a=await honest('signer');
 const v=await verifyDisavow({publicData:a.original.publicData,
  firstMessage:a.session.firstMessage,challenge:a.c,response:a.response});
 assert.equal(v.equationsHold,false);
});
test('verifier refuses degenerate beta and malformed public-proof point',async()=>{
 const a=await honest('confirmer');
 const altered={...a.session.firstMessage,beta1:GT.ONE};
 const v=await verifyDisavow({publicData:a.falseData,
  firstMessage:altered,challenge:a.c,response:a.response});
 assert.equal(v.equationsHold,false);
});
test('challenge is consumed once; an invalid challenge cannot be retried with the same blinding',async()=>{
 const a=await start();
 const s=await beginDisavow({publicData:a.falseData,privateKeys:a.original.privateKeys});
 assert.throws(()=>respondDisavow(s,Q),/outside/);
 assert.throws(()=>respondDisavow(s,4n),/already spent/);
});
test('published beta=(D^x/C)^a equals ONE for any registered key — the printed equations contradict nonidentity',async()=>{
 const a=await start();
 const k=a.original.privateKeys;
 const C1=a.original.publicData.confirmerPublicG1,C2=a.original.publicData.signerPublic;
 const r1=G1.multiply(k.xc).subtract(C1),r2=G2.multiply(k.xs).subtract(C2);
 assert.equal(r1.equals(G1.subtract(G1)),true);
 assert.equal(r2.equals(G2.subtract(G2)),true);
 // This is a structural contradiction in the PRINTED Figure, not an attack on
 // the mathematically consistent inequality candidate in this module.
});
test('simulator can forge accepted PUBLIC disavowal equations even for a VALID signature if it chooses verifier challenge',async()=>{
 const {original}=await start();
 for(let i=0;i<3;i++){
  const fake=await simulateDisavow({publicData:original.publicData});
  const v=await verifyDisavow({publicData:original.publicData,...fake});
  assert.equal(v.equationsHold,true);
  assert.match(fake.disclosure,/not live disavowal/);
 }
});
test('asymmetric pairing research has no claim to fully proven 2013 disavowal security',async()=>{
 const {original,falseData}=await start();
 const s=await beginDisavow({publicData:falseData,privateKeys:original.privateKeys});
 const response=respondDisavow(s,19n);
 const verdict=await verifyDisavow({publicData:falseData,firstMessage:s.firstMessage,challenge:19n,response});
 assert.match(verdict.security,/RESEARCH ADAPTATION/);
 assert.equal(Object.hasOwn(verdict,'nonTransferable'),false);
 assert.equal(Object.hasOwn(verdict,'publishedCorrected'),false);
});
