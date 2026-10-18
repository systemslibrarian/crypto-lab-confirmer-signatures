import test from 'node:test';
import assert from 'node:assert/strict';
import {webcrypto} from 'node:crypto';
import {issueToyEnvelope,inspectToyPublicIssuance,inspectToyRecipient,toyLabel} from '../research/issued-envelope-toy.mjs';
import {verifyPi0Subproof} from '../research/pi0-equality.mjs';
import {commitToy} from '../research/pi1-relation.mjs';
if(!globalThis.crypto)globalThis.crypto=webcrypto;

const start=()=>issueToyEnvelope({message:4n,opening:7n,tS:3n,tC:4n});

test('source-structured toy issuance computes real commitment, ECDSA signature, two encrypted openings and partial pi0',async()=>{
 const {envelope:e,privateCustody:k}=await start();
 assert.equal(e.psi,commitToy(4n,7n));
 assert.equal(e.signature.length,64);
 assert.ok(e.cS.u>0n&&e.cS.e>0n&&e.cS.v>0n);
 assert.ok(e.cC.u>0n&&e.cC.e>0n&&e.cC.v>0n);
 assert.equal(typeof e.pi0.c,'bigint');
 assert.ok(e.labelS.includes('ROLE=S'));
 assert.ok(e.labelC.includes('ROLE=C'));
 assert.notEqual(e.labelS,e.labelC);
 assert.equal(k.message,4n);
 const v=await inspectToyPublicIssuance(e);
 assert.deepEqual(v,{signatureOk:true,encryptedEqualityOk:true,partialIssuanceAccepted:true,isDCS:false});
});
test('signer and confirmer independently decrypt the same opening with their distinct private keys',async()=>{
 for(let i=0;i<6;i++){
  const {envelope:e,privateCustody:k}=await start();
  const signer=await inspectToyRecipient(e,k.signerKey,'S',4n);
  const confirmer=await inspectToyRecipient(e,k.confirmerKey,'C',4n);
  assert.equal(signer.status,'PRIVATE_OPENING_MATCHES');
  assert.equal(confirmer.status,'PRIVATE_OPENING_MATCHES');
  assert.equal(signer.opening,7n);
  assert.equal(confirmer.opening,7n);
  assert.match(signer.evidence,/NOT CONFIRMATION OR DISAVOWAL/);
 }
});
test('changed claimed message cannot silently pass as confirmed even if underlying signature on psi is valid',async()=>{
 const {envelope:e,privateCustody:k}=await start();
 assert.equal((await inspectToyPublicIssuance(e)).signatureOk,true);
 for(const claim of [3n,5n,8n]){
  const v=await inspectToyRecipient(e,k.confirmerKey,'C',claim);
  assert.equal(v.status,'CLAIM_OR_CONTEXT_CHANGED');
  assert.ok(!Object.hasOwn(v,'confirmed'));
 }
});
test('tampered psi leaves partial pi0 proof unchanged but breaks genuine ECDSA signature on psi',async()=>{
 const {envelope:e}=await start();
 const broken={...e,psi:e.psi*2n%23n};
 assert.equal(verifyPi0Subproof(e.pubS,e.pubC,e.cS,e.cC,e.pi0),true);
 assert.equal(verifyPi0Subproof(broken.pubS,broken.pubC,broken.cS,broken.cC,broken.pi0),true);
 const v=await inspectToyPublicIssuance(broken);
 assert.equal(v.encryptedEqualityOk,true);
 assert.equal(v.signatureOk,false);
 assert.equal(v.partialIssuanceAccepted,false);
 assert.equal(v.isDCS,false);
});
test('tampering with pi0 response or encrypted e component breaks the public subproof',async()=>{
 const {envelope:e}=await start();
 const badResponse={...e,pi0:{...e.pi0,D:e.pi0.D+1n}};
 const badCipher={...e,cC:{...e.cC,e:e.cC.e*(253n+1n)%(253n*253n)}};
 assert.equal((await inspectToyPublicIssuance(badResponse)).encryptedEqualityOk,false);
 assert.equal((await inspectToyPublicIssuance(badCipher)).encryptedEqualityOk,false);
});
test('negative control: changed cC.v is invisible to the incomplete public e-only pi0 verifier',async()=>{
 const {envelope:e}=await start();
 const broken={...e,cC:{...e.cC,v:1n}};
 const view=await inspectToyPublicIssuance(broken);
 assert.equal(view.signatureOk,true);
 assert.equal(view.encryptedEqualityOk,true);
 assert.equal(view.partialIssuanceAccepted,true);
 assert.equal(view.isDCS,false);
});
test('altering the stored label rejects private context despite pi0 ignoring labels',async()=>{
 const {envelope:e,privateCustody:k}=await start();
 const tamper={...e,labelC:'attacker label'};
 assert.equal((await inspectToyPublicIssuance(tamper)).encryptedEqualityOk,true);
 assert.equal((await inspectToyRecipient(tamper,k.confirmerKey,'C',4n)).status,'CLAIM_OR_CONTEXT_CHANGED');
});
test('wrong private key, unknown role and modified ECDSA signature cannot be called a disavowal',async()=>{
 const {envelope:e,privateCustody:k}=await start();
 for(const [env,key,role] of [[e,{...k.confirmerKey,n:257n},'C'],[e,k.confirmerKey,'X']]){
   const result=await inspectToyRecipient(env,key,role,4n);
   assert.notEqual(result.status,'PRIVATE_OPENING_MATCHES');
   assert.match(result.evidence,/NOT DISAVOWAL/);
 }
 const tampered={...e,signature:e.signature.slice()};
 tampered.signature[5]^=1;
 const result=await inspectToyRecipient(tampered,k.confirmerKey,'C',4n);
 assert.equal(result.status,'PUBLIC_PREFLIGHT_REJECTED');
});
test('message, opening, nonce and recipient role inputs are explicitly bounded',async()=>{
 for(const spec of [
  {message:-1n},{message:11n},{opening:11n},{opening:-1n},
  {tS:0n},{tC:63n},{tS:3},{message:'4'}
 ])await assert.rejects(issueToyEnvelope(spec),/bounded|nonce/i);
 const {envelope:e}=await start();
 assert.throws(()=>toyLabel('D',4n,e.pubS,e.pubC),/Recipient/);
});
test('publicly accepted research issuance never claims DCS validity',async()=>{
 const {envelope:e}=await start();
 const report=await inspectToyPublicIssuance(e);
 assert.equal(report.isDCS,false);
 for(const field of ['confirmation','disavowal','nonTransferable','productionSecure'])assert.equal(Object.hasOwn(report,field),false);
});
