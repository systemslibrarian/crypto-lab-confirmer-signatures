import test from 'node:test';
import assert from 'node:assert/strict';
import {webcrypto} from 'node:crypto';
import {issue,createKeys,Q} from '../core.mjs';
import {beginConfirmation,chooseVerifierChallenge,respondConfirmation,
 verifyConfirmation,simulateConfirmation} from '../confirmation.mjs';
if(!globalThis.crypto)globalThis.crypto=webcrypto;
const make=()=>issue({message:'Confidential library agreement'});
const honest=async(role,challenge=83n)=>{
 const obj=await make(),session=await beginConfirmation({publicData:obj.publicData,
  privateKeys:obj.privateKeys,role});
 const response=respondConfirmation(session,challenge);
 return {obj,session,challenge,response};
};
for(const role of ['signer','confirmer']){
 test('real BLS12-381 '+role+' OR confirmation proves five public equations with no witness in response',async()=>{
  const {obj,session,challenge,response}=await honest(role);
  const v=await verifyConfirmation({publicData:obj.publicData,firstMessage:session.firstMessage,
   challenge,response});
  assert.equal(v.equationsHold,true);
  assert.ok(Object.values(v.checks).every(Boolean));
  assert.equal(Object.hasOwn(response,'secret'),false);
  assert.equal(Object.hasOwn(session.firstMessage,'secret'),false);
 });
}
test('random independent Bob challenge produces genuine accepting real pairing transcript',async()=>{
 for(let i=0;i<5;i++){
  const obj=await make();
  const p=await beginConfirmation({publicData:obj.publicData,privateKeys:obj.privateKeys});
  const c=chooseVerifierChallenge();assert.ok(c>0n&&c<Q);
  const response=respondConfirmation(p,c);
  assert.equal((await verifyConfirmation({publicData:obj.publicData,
    firstMessage:p.firstMessage,challenge:c,response})).equationsHold,true);
 }
});
test('changing claimed message preserves signed-ElGamal format but honest signer/confirmer cannot confirm',async()=>{
 const obj=await make(),bad={...obj.publicData,message:'Different agreement'};
 for(const role of ['signer','confirmer'])
  await assert.rejects(beginConfirmation({publicData:bad,privateKeys:obj.privateKeys,role}),/Cannot honestly confirm/);
});
test('one proof first-message may answer only one challenge, even under failure',async()=>{
 const obj=await make(),p=await beginConfirmation({publicData:obj.publicData,privateKeys:obj.privateKeys});
 respondConfirmation(p,83n);
 assert.throws(()=>respondConfirmation(p,84n),/already used/);
});
test('tampered responses, first message, challenge and publicly signed object all reject',async()=>{
 const {obj,session,challenge,response}=await honest('confirmer');
 const args={publicData:obj.publicData,firstMessage:session.firstMessage,challenge,response};
 for(const field of ['b1','b2','c1','c2']){
  assert.equal((await verifyConfirmation({...args,response:{...response,[field]:(response[field]+1n)%Q}})).equationsHold,false);
 }
 assert.equal((await verifyConfirmation({...args,challenge:84n})).equationsHold,false);
 assert.equal((await verifyConfirmation({...args,publicData:{...obj.publicData,message:'Altered claim'}})).equationsHold,false);
});
test('adversary can simulate a SELF-chosen challenge transcript for a false message: recorded equations alone are not evidence',async()=>{
 const obj=await make(),falseD={...obj.publicData,message:'Fictional agreement changed'};
 for(let i=0;i<4;i++){
  const fake=await simulateConfirmation({publicData:falseD});
  assert.equal(fake.simulated,true);
  assert.equal((await verifyConfirmation({publicData:falseD,...fake})).equationsHold,true);
  assert.match(fake.disclosure,/NOT an independent verifier/);
 }
});
