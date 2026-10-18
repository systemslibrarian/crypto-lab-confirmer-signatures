import test from 'node:test';
import assert from 'node:assert/strict';
import {webcrypto} from 'node:crypto';
import {keygen,issue,validFormat,extract,statement,mod,SYMBOLIC} from '../research/dcs-uv-symbolic.mjs';
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

test('independent fixed-coins oracle checks all five proposed candidate equations',async()=>{
 const f=await fixture(),c=31n;
 const coins={a:7n,e:31n,ePrime:47n,betaFake:3n,cFake:11n,bFake:17n,bPrimeFake:19n};
 for(const role of ['signer','confirmer']){
  const st=await statement(f.invalid);
  const real=role==='confirmer'?1:2;
  const secret=role==='confirmer'?f.keys.confirmerSecret:f.keys.signerSecret;
  const proof=await candidateDisavowBegin({publicData:f.invalid,keys:f.keys,role,coins});
  const beta=mod((st['B'+real]*secret-st['A'+real])*coins.a);
  assert.equal(proof.firstMessage['beta'+real],beta);
  assert.equal(proof.firstMessage['beta'+(3-real)],coins.betaFake);
  const response=candidateDisavowRespond(proof,c);
  const cReal=mod(c-coins.cFake);
  assert.equal(response['c'+real],cReal);
  assert.equal(response['b'+real],mod(coins.e-cReal*secret*coins.a));
  assert.equal(response['b'+real+'Prime'],mod(coins.ePrime-cReal*coins.a));
  // Independent manual reconstruction — does not call the repo verifier.
  for(const j of [1,2]){
   const b=response['b'+j],bp=response['b'+j+'Prime'],cj=response['c'+j];
   assert.equal(proof.firstMessage['z'+(2*j-1)],mod(st['D'+j]*b-st['C'+j]*bp));
   assert.equal(proof.firstMessage['z'+(2*j)],mod(proof.firstMessage['beta'+j]*cj+st['B'+j]*b-st['A'+j]*bp));
  }
  assert.equal(mod(response.c1+response.c2),c);
  assert.equal((await candidateDisavowVerify({publicData:f.invalid,firstMessage:proof.firstMessage,challenge:c,response})).equationsHold,true);
 }
});
test('a challenge-first fabricated candidate transcript passes equations without proving invalidity',async()=>{
 const f=await fixture(),fake={...f.original,message:f.original.message};
 // Here the signature claim is actually valid! Eve still can satisfy the
 // candidate equations by choosing Bob's challenge before the first message.
 assert.equal((await extract({publicData:fake,confirmerSecret:f.keys.confirmerSecret})).extracted,true);
 const st=await statement(fake),challenge=57n,c1=23n,c2=mod(challenge-c1);
 const response={c1,c2,b1:11n,b1Prime:13n,b2:17n,b2Prime:19n};
 const firstMessage={beta1:5n,beta2:7n};
 for(const j of [1,2]){
  firstMessage['z'+(2*j-1)]=mod(st['D'+j]*response['b'+j]-st['C'+j]*response['b'+j+'Prime']);
  firstMessage['z'+(2*j)]=mod(firstMessage['beta'+j]*response['c'+j]+st['B'+j]*response['b'+j]-st['A'+j]*response['b'+j+'Prime']);
 }
 const passed=await candidateDisavowVerify({publicData:fake,firstMessage,challenge,response});
 assert.equal(passed.equationsHold,true);
 const different=await candidateDisavowVerify({publicData:fake,firstMessage,challenge:58n,response});
 assert.equal(different.equationsHold,false);
 assert.equal(different.checks.challenge,false);
 assert.match(passed.scope,/NO SECURITY CLAIM/);
});