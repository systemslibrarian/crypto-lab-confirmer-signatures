import test from 'node:test';
import assert from 'node:assert/strict';
import {webcrypto} from 'node:crypto';
import {issue,Q,GT,G1,G2,mod,gtPow,isTargetGroup,randomFieldScalar} from '../core.mjs';
import {beginDisavow,respondDisavow,verifyDisavow,simulateDisavow} from '../disavow-reconstructed.mjs';
import {extractDisavowWitness} from '../disavow-extraction.mjs';
if(!globalThis.crypto)globalThis.crypto=webcrypto;

test('order-two beta attack against a VALID signature is rejected, even for even challenges',async()=>{
 const {publicData}=await issue({message:'A genuine signed agreement'});
 const minusOne=GT.neg(GT.ONE);
 assert.equal(GT.eql(GT.pow(minusOne,2n),GT.ONE),true);
 // Regression: the former membership expression accepted this order-two value.
 assert.equal(GT.eql(gtPow(minusOne,Q),GT.ONE),true);
 assert.equal(GT.eql(GT.pow(minusOne,Q),GT.ONE),false);
 assert.equal(isTargetGroup(minusOne,{nonidentity:true}),false);
 const firstMessage={beta1:minusOne,beta2:minusOne,
  zKey1:G1.subtract(G1),zKey2:G2.subtract(G2),zPair1:GT.ONE,zPair2:GT.ONE};
 for(const challenge of [0n,2n,42n,Q-1n]){
  const response={b11:0n,b12:0n,b21:0n,b22:0n,c1:0n,c2:challenge};
  // All old verification equations hold: (-1)^even=1, all other exponents=0.
  assert.equal(GT.eql(gtPow(minusOne,challenge),GT.ONE),true);
  assert.equal((await verifyDisavow({publicData,firstMessage,challenge,response})).equationsHold,false);
 }
});

for(const role of ['confirmer','signer'])test('two accepted challenges extract the '+role+' inequality witness',async()=>{
 const issued=await issue({message:'Original agreement'});
 const publicData={...issued.publicData,message:'Different alleged agreement'};
 const session=await beginDisavow({publicData,privateKeys:issued.privateKeys,role});
 // Deliberate test-only rewind of leaked research state; normal session reuse
 // remains prohibited. Do not export this fixture to the application.
 const fork={...session,_private:{...session._private}};
 const left={challenge:0n,response:respondDisavow(session,0n)};
 const right={challenge:Q-1n,response:respondDisavow(fork,Q-1n)};
 const args={publicData,firstMessage:session.firstMessage,left,right};
 const out=await extractDisavowWitness(args);
 assert.equal(out.branch,role==='confirmer'?1:2);
 assert.equal(out.x,role==='confirmer'?issued.privateKeys.xc:issued.privateKeys.xs);
 assert.equal(out.a,session._private.a);
 assert.equal(out.relationChecked,true);
 await assert.rejects(extractDisavowWitness({...args,right:left}),/Distinct/);
 await assert.rejects(extractDisavowWitness({...args,right:{...right,
  response:{...right.response,b11:mod(right.response.b11+1n)}}}),/accepting/);
 assert.throws(()=>respondDisavow(session,2n),/already spent/);
});

test('special HVZK simulator accepts any supplied canonical challenge, including zero',async()=>{
 const {publicData}=await issue({message:'Simulation is not live evidence'});
 for(const challenge of [0n,1n,Q-1n]){
  const transcript=await simulateDisavow({publicData,challenge});
  assert.equal(transcript.challenge,challenge);
  assert.equal((await verifyDisavow({publicData,...transcript})).equationsHold,true);
 }
 await assert.rejects(simulateDisavow({publicData,challenge:Q}),/outside/);
});

test('field sampler permits zero, while target membership rejects zero and malformed values',()=>{
 assert.equal(isTargetGroup(GT.ZERO),false);
 assert.equal(isTargetGroup(null),false);
 assert.equal(isTargetGroup(GT.ONE),true);
 assert.equal(isTargetGroup(GT.ONE,{nonidentity:true}),false);
 // Inject deterministic randomness only inside this synchronous test.
 const descriptor=Object.getOwnPropertyDescriptor(globalThis,'crypto');
 try{
  Object.defineProperty(globalThis,'crypto',{configurable:true,value:{getRandomValues:b=>b.fill(0)}});
  assert.equal(randomFieldScalar(),0n);
 }finally{Object.defineProperty(globalThis,'crypto',descriptor);}
});
