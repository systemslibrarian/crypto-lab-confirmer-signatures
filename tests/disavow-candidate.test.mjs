import test from 'node:test';
import assert from 'node:assert/strict';
import {webcrypto} from 'node:crypto';
import {keygen,issue,validFormat,extract,mod,SYMBOLIC} from '../research/dcs-uv-symbolic.mjs';
import {candidateDisavowBegin,candidateDisavowRespond,candidateDisavowVerify,candidateVerifierChallenge} from '../research/disavow-candidate.mjs';
if(!globalThis.crypto)globalThis.crypto=webcrypto;
async function fixture(){const keys=keygen({signerSecret:73n,confirmerSecret:29n});const original=await issue({message:'Original signed document',keys,r:21n,k:37n});return {keys,original,invalid:{...original,message:'A different document'}};}
async function proof(role,challenge=51n,coins){
 const f=await fixture();const session=await candidateDisavowBegin({publicData:f.invalid,keys:f.keys,role,coins});
 const response=candidateDisavowRespond(session,challenge);
 return {f,session,transcript:{publicData:f.invalid,firstMessage:session.firstMessage,challenge,response}};
}
for(const role of ['signer','confirmer']){
 test('candidate inequality OR transcript verifies for an invalid claim, '+role,async()=>{
  const {f,session,transcript:t}=await proof(role,51n);
  assert.equal(await validFormat(f.invalid),true);
  assert.equal((await extract({publicData:f.invalid,confirmerSecret:f.keys.confirmerSecret})).extracted,false);
  const v=await candidateDisavowVerify(t);
  assert.equal(v.equationsHold,true);
  assert.ok(Object.values(v.checks).every(Boolean));
  assert.match(v.scope,/NOT PUBLISHED DCS/);
  assert.equal(Object.hasOwn(session.firstMessage,'secret'),false);
  assert.equal(Object.hasOwn(t.response,'secret'),false);
 });
 test('all boundary challenges yield candidate research algebra passes, '+role,async()=>{
  for(const c of [0n,1n,2n,17n,1018n]){
   const {transcript:t}=await proof(role,c);
   assert.equal((await candidateDisavowVerify(t)).equationsHold,true);
  }
 });
 test('cannot honestly disavow a VALID claimed signature, '+role,async()=>{
  const {keys,original}=await fixture();
  await assert.rejects(candidateDisavowBegin({publicData:original,keys,role}),/cannot honestly disavow/);
 });
}
test('wrong role witness and corrupted format refuse candidate disavowal',async()=>{
 const {keys,invalid}=await fixture();
 await assert.rejects(candidateDisavowBegin({publicData:invalid,keys:{...keys,confirmerSecret:32n},role:'confirmer'}),/Wrong witness/);
 await assert.rejects(candidateDisavowBegin({publicData:invalid,keys,role:'observer'}),/Only Alice or Carol/);
 const bad={...invalid,signature:{...invalid.signature,s:mod(invalid.signature.s+1n)}};
 await assert.rejects(candidateDisavowBegin({publicData:bad,keys,role:'signer'}),/format invalid/);
});
test('mutating any proof component or challenge cannot pass public candidate checker',async()=>{
 const {transcript:t}=await proof('confirmer',73n);
 for(const k of ['beta1','beta2','z1','z2','z3','z4']){
  const m={...t,firstMessage:{...t.firstMessage,[k]:mod(t.firstMessage[k]+1n)}};
  assert.equal((await candidateDisavowVerify(m)).equationsHold,false,k);
 }
 for(const k of ['b1','b1Prime','b2','b2Prime','c1','c2']){
  const m={...t,response:{...t.response,[k]:mod(t.response[k]+1n)}};
  assert.equal((await candidateDisavowVerify(m)).equationsHold,false,k);
 }
 assert.equal((await candidateDisavowVerify({...t,challenge:mod(t.challenge+1n)})).equationsHold,false);
});
test('all random verifier challenges validate candidate algebra but never a DCS security theorem',async()=>{
 const f=await fixture();for(let i=0;i<20;i++){
  const session=await candidateDisavowBegin({publicData:f.invalid,keys:f.keys,role:'signer'});
  const c=candidateVerifierChallenge();const response=candidateDisavowRespond(session,c);
  const result=await candidateDisavowVerify({publicData:f.invalid,firstMessage:session.firstMessage,challenge:c,response});
  assert.equal(result.equationsHold,true);
  assert.match(result.scope,/NOT PUBLISHED DCS/);
 }
});
test('candidate responder rejects reuse, malformed challenges and oversized values',async()=>{
 const f=await fixture();const session=await candidateDisavowBegin({publicData:f.invalid,keys:f.keys,role:'confirmer'});
 assert.throws(()=>candidateDisavowRespond(session,SYMBOLIC.order),/Out-of-range/);
 assert.throws(()=>candidateDisavowRespond(session,1n),/spent/);
 const {transcript:t}=await proof('confirmer',17n);
 assert.equal((await candidateDisavowVerify({...t,challenge:-1n})).equationsHold,false);
 assert.equal((await candidateDisavowVerify({...t,response:{...t.response,b1:SYMBOLIC.order}})).equationsHold,false);
 assert.equal((await candidateDisavowVerify({...t,firstMessage:{...t.firstMessage,beta1:0n}})).equationsHold,false);
});
test('full research scope: no confirmed disavowal / non-transferability verdict is produced',async()=>{
 const {transcript:t}=await proof('signer',28n);
 const r=await candidateDisavowVerify(t);
 assert.equal(r.equationsHold,true);
 for(const field of ['disavowed','nonTransferable','productionSecure','sourceProven'])assert.equal(Object.hasOwn(r,field),false);
});