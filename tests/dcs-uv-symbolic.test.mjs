import test from 'node:test';
import assert from 'node:assert/strict';
import {webcrypto} from 'node:crypto';
import {keygen,issue,validFormat,extract,statement,confirmBegin,verifierChallenge,confirmRespond,confirmVerify,confirmVerifyEnvelope,mod,SYMBOLIC,securityLimit} from '../research/dcs-uv-symbolic.mjs';
if(!globalThis.crypto)globalThis.crypto=webcrypto;
const keys=()=>keygen({signerSecret:73n,confirmerSecret:29n});
const init=async()=>{const k=keys();const d=await issue({message:'Fictional library agreement',keys:k,r:21n,k:37n});return {keys:k,publicData:d};};
async function one(role,publicData,keys,c=51n){
 const z=await confirmBegin({publicData,keys,role});const response=confirmRespond(z,c);
 return {initial:z,transcript:{publicStatement:z.statement,firstMessage:z.firstMessage,challenge:c,response}};
}
test('published signed-ElGamal DCS-UV algebra, toy formal group implementation',async()=>{
 const {keys:k,publicData:d}=await init();
 assert.equal(await validFormat(d),true);
 assert.equal(d.signature.sigma1,mod(29n*21n));
 const basic=await extract({publicData:d,confirmerSecret:k.confirmerSecret});
 assert.equal(basic.extracted,true);
 assert.equal(basic.reason,'VALID_BASIC_SIGNATURE');
});
test('wrong confirmer cannot extract; altered ciphertext rejects signature or extracted content',async()=>{
 const {publicData:d}=await init();
 assert.equal((await extract({publicData:d,confirmerSecret:41n})).extracted,false);
 assert.equal((await extract({publicData:{...d,signature:{...d.signature,s:mod(d.signature.s+1n)}},confirmerSecret:29n})).extracted,false);
 const modified={...d,message:'Different agreement'};
 assert.equal((await extract({publicData:modified,confirmerSecret:29n})).extracted,false);
});
test('source A,B,C,D relations evaluate correctly for a valid DCS',async()=>{
 const {keys:k,publicData:d}=await init();
 const s=await statement(d);
 assert.equal(s.A1,s.A2);
 assert.equal(s.A1,mod(s.B1*k.confirmerSecret));
 assert.equal(s.A2,mod(s.B2*k.signerSecret));
 assert.equal(s.C1,mod(s.D1*k.confirmerSecret));
 assert.equal(s.C2,mod(s.D2*k.signerSecret));
});
for(const role of ['signer','confirmer']){
 test(`source Figure 5.1/5.2 honest ${role} OR-proof checks independent public equations`,async()=>{
  const {publicData:d,keys:k}=await init();const o=await one(role,d,k);
  assert.equal(confirmVerify(o.transcript).equationsHold,true);
  assert.deepEqual(Object.keys(confirmVerify(o.transcript).checks).sort(),['challenge','groupPairing1','groupPairing2','groupKey1','groupKey2'].sort());
  assert.equal('secret' in o.initial.firstMessage,false);
  assert.equal('secret' in o.transcript.response,false);
 });
}
test('all challenges at the toy field boundary verify for signer and confirmer',async()=>{
 const {keys:k,publicData:d}=await init();for(const role of ['signer','confirmer'])for(const c of [0n,1n,2n,17n,1018n]){
  assert.equal(confirmVerify((await one(role,d,k,c)).transcript).equationsHold,true,`${role} ${c}`);
 }
});
test('live fresh challenges are bounded and verify with independent public-only checker',async()=>{
 const {keys:k,publicData:d}=await init();for(let i=0;i<18;i++){
  const c=verifierChallenge();assert.ok(c>=0n&&c<SYMBOLIC.order);
  assert.equal(confirmVerify((await one('confirmer',d,k,c)).transcript).equationsHold,true);
 }
});
test('tampering with each response/challenge/first message is rejected',async()=>{
 const {keys:k,publicData:d}=await init();const {transcript:t}=await one('signer',d,k,91n);
 for(const f of ['b1','b2','c1','c2']){
  const modified={...t,response:{...t.response,[f]:mod(t.response[f]+1n)}};
  assert.equal(confirmVerify(modified).equationsHold,false,f);
 }
 for(const f of ['z1','z2','z3','z4']){
  const modified={...t,firstMessage:{...t.firstMessage,[f]:mod(t.firstMessage[f]+1n)}};
  assert.equal(confirmVerify(modified).equationsHold,false,f);
 }
 assert.equal(confirmVerify({...t,challenge:mod(t.challenge+1n)}).equationsHold,false);
});
test('two different challenges cannot be answered using same first-message masks',async()=>{
 const {keys:k,publicData:d}=await init();const sess=await confirmBegin({publicData:d,keys:k,role:'signer'});
 confirmRespond(sess,15n);
 assert.throws(()=>confirmRespond(sess,16n),/already spent/);
});
test('honest prover cannot confirm a false alleged signature even if signed-ElGamal format survives',async()=>{
 const {keys:k,publicData:d}=await init();const altered={...d,message:'Something never signed'};
 // Encryption attestation is independent of the message, so signed-ElGamal
 // format still passes. The actual pairing relation DOES NOT.
 assert.equal(await validFormat(altered),true);
 assert.equal((await extract({publicData:altered,confirmerSecret:k.confirmerSecret})).extracted,false);
 await assert.rejects(confirmBegin({publicData:altered,keys:k,role:'signer'}),/invalid signature/);
 await assert.rejects(confirmBegin({publicData:altered,keys:k,role:'confirmer'}),/invalid signature/);
});
test('strict public-only verification rejects malformed and out-of-range inputs',async()=>{
 const {keys:k,publicData:d}=await init();const {transcript:t}=await one('signer',d,k);
 for(const c of [-1n,SYMBOLIC.order,'51',null])assert.equal(confirmVerify({...t,challenge:c}).equationsHold,false);
 assert.equal(confirmVerify({...t,firstMessage:{...t.firstMessage,z1:'1'}}).equationsHold,false);
 assert.equal(confirmVerify({...t,response:{...t.response,b1:SYMBOLIC.order}}).equationsHold,false);
});
test('inequality-proof source literal has contradictory beta condition; do not fabricate disavowal',async()=>{
 const k=keys(),g=1n;
 // Thesis Fig 5.3/5.4 as printed: beta = (D^x / C)^a, with C=g^x,D=g.
 // This is always the identity, contradicting the printed beta != identity gate.
 for(const x of [k.signerSecret,k.confirmerSecret])for(const a of [1n,4n,277n]){
  const C=mod(g*x),D=g;
  const beta=mod(a*mod(D*x-C)); // exponent zero represents identity
  assert.equal(beta,0n);
 }
});
test('symbolic group representation exposes keys, cannot support actual DCS security claims',()=>{
 const k=keys();assert.equal(k.signerPublic,k.signerSecret);
 assert.equal(k.confirmerPublic,k.confirmerSecret);
 assert.match(securityLimit,/NOT cryptographic proof security/);
});

test('bound verifier derives statement from signed-ElGamal object rather than trusting supplied A/B fields',async()=>{
 const {keys:k,publicData:d}=await init();const {transcript:t}=await one('confirmer',d,k,57n);
 const verified=await confirmVerifyEnvelope({publicData:d,firstMessage:t.firstMessage,challenge:t.challenge,response:t.response});
 assert.equal(verified.equationsHold,true);
 const wrongMessage=await confirmVerifyEnvelope({publicData:{...d,message:'Different claim'},firstMessage:t.firstMessage,challenge:t.challenge,response:t.response});
 assert.equal(wrongMessage.equationsHold,false);
 const wrongSignature=await confirmVerifyEnvelope({publicData:{...d,signature:{...d.signature,s:mod(d.signature.s+1n)}},firstMessage:t.firstMessage,challenge:t.challenge,response:t.response});
 assert.equal(wrongSignature.equationsHold,false);
});
test('negative claim: if prover chooses verifier challenge AFTER first message, a false statement can pass',async()=>{
 const {publicData:d}=await init();const bad={...d,message:'Forged message'};
 assert.equal(await validFormat(bad),true);
 const s=await statement(bad), c=39n, c1=17n,c2=mod(c-c1),b1=8n,b2=9n;
 const f={
  z1:mod(s.B1*b1+s.A1*c1),z2:mod(s.D1*b1+s.C1*c1),
  z3:mod(s.B2*b2+s.A2*c2),z4:mod(s.D2*b2+s.C2*c2)
 };
 const forged=await confirmVerifyEnvelope({publicData:bad,firstMessage:f,challenge:c,response:{b1,b2,c1,c2}});
 assert.equal(forged.equationsHold,true);
 // This is NOT an honest 3-move exchange. Challenge must be selected by Bob
 // after receiving the prover commitment, not selected by the adversary.
});