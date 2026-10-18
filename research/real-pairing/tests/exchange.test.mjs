import test from 'node:test';
import assert from 'node:assert/strict';
import {issue,Q,G1,G2,GT,publicStatement,pairing,pointTimes} from '../core.mjs';
import {ProofExchange} from '../exchange.mjs';
import {exportTranscript} from '../transcript.mjs';
import {beginConfirmation,respondConfirmation,verifyConfirmation,checkConfirmationStatement} from '../confirmation.mjs';
import {checkDisavowStatement} from '../disavow-reconstructed.mjs';
const issued=await issue({message:'A fictional archive agreement.'});
for(const role of ['signer','confirmer'])for(const kind of ['confirmation','disavowal'])
 test('ordered single-use '+role+' '+kind+' exchange and public export',async()=>{
  const publicData=kind==='confirmation'?issued.publicData:{...issued.publicData,message:'A different agreement.'};
  const e=new ProofExchange({publicData,privateKeys:issued.privateKeys,role,kind});
  assert.throws(()=>e.challenge(),/commitment/);
  await assert.rejects(e.finish(),/challenge/);
  const committed=await e.commit();
  assert.equal(committed.challenge,undefined);assert.equal(committed.response,undefined);
  await assert.rejects(e.commit(),/already/);
  const challenged=e.challenge();assert.equal(challenged.firstMessage,committed.firstMessage);
  assert.throws(()=>e.challenge(),/commitment/);
  const done=await e.finish();assert.equal(done.result.equationsHold,true);
  assert.equal(done.firstMessage,committed.firstMessage);
  await assert.rejects(e.finish(),/challenge/);
  const wire=exportTranscript({publicData:{...publicData,privateKeys:issued.privateKeys},kind,...done});
  assert.deepEqual(Object.keys(wire.publicData).sort(),['scheme','message','signerPublic','confirmerPublicG1','confirmerPublicG2','confirmerKeyProof','signature'].sort());
  const serial=JSON.stringify(wire);
  for(const secret of ['privateKeys','_private','secret','ePrime','fakeB','fakeC'])assert.ok(!serial.includes('"'+secret+'"'));
  assert.equal(wire.proof.challenge,challenged.challenge.toString(16));
 });
test('a refusal creates no transcript and cannot advance to challenge',async()=>{
 const e=new ProofExchange({publicData:issued.publicData,privateKeys:issued.privateKeys,role:'confirmer',kind:'disavowal'});
 await assert.rejects(e.commit(),/cannot honestly disavow/);
 assert.equal(e.snapshot().stage,'no-proof');assert.equal(e.snapshot().firstMessage,undefined);
 assert.throws(()=>e.challenge(),/commitment/);
});
test('zero masks and zero challenge are valid, including identity commitments',async()=>{
 const descriptor=Object.getOwnPropertyDescriptor(globalThis,'crypto'),original=globalThis.crypto;let session;
 try{
  Object.defineProperty(globalThis,'crypto',{configurable:true,value:{subtle:original.subtle,getRandomValues:a=>{a.fill(0);return a;}}});
  session=await beginConfirmation({publicData:issued.publicData,privateKeys:issued.privateKeys,role:'signer'});
 }finally{Object.defineProperty(globalThis,'crypto',descriptor);}
 const response=respondConfirmation(session,0n);
 assert.deepEqual(response,{b1:0n,b2:0n,c1:0n,c2:0n});
 assert.equal((await verifyConfirmation({publicData:issued.publicData,firstMessage:session.firstMessage,challenge:0n,response})).equationsHold,true);
 assert.ok(pointTimes(G1,0n).is0());assert.ok(pointTimes(G2,0n).is0());
 const s=await publicStatement(issued.publicData),beta=pairing(G1,G2);
 const z={beta1:beta,beta2:beta,zKey1:G1.subtract(G1),zKey2:G2.subtract(G2),zPair1:GT.ONE,zPair2:GT.ONE};
 const r={b11:0n,b12:0n,b21:0n,b22:0n,c1:0n,c2:0n};
 assert.equal(checkDisavowStatement(s,z,0n,r).equationsHold,true);
 assert.equal(checkDisavowStatement(s,z,1n,r).equationsHold,false);
});
test('confirmation rejects wrong target subgroup and statement source group',async()=>{
 const s=await publicStatement(issued.publicData);
 const session=await beginConfirmation({publicData:issued.publicData,privateKeys:issued.privateKeys});
 const response=respondConfirmation(session,5n);
 for(const bad of [GT.ZERO,GT.neg(GT.ONE),null])
  assert.equal(checkConfirmationStatement(s,{...session.firstMessage,z1:bad},5n,response).equationsHold,false);
 assert.equal(checkConfirmationStatement({...s,C1:G2},session.firstMessage,5n,response).equationsHold,false);
 assert.equal(checkConfirmationStatement(s,session.firstMessage,Q,response).equationsHold,false);
});
