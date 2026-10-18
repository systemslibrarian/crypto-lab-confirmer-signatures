import test from 'node:test';
import assert from 'node:assert/strict';
import {webcrypto} from 'node:crypto';
import {issueToyEnvelope} from '../research/issued-envelope-toy.mjs';
import {beginToyConfirmation,finishToyConfirmation} from '../research/toy-confirmation-session.mjs';
import {checkToyPi1Transcript} from '../research/pi1-interactive-toy.mjs';
if(!globalThis.crypto)globalThis.crypto=webcrypto;
const issued=()=>issueToyEnvelope({message:4n,opening:7n,tS:3n,tC:4n});

test('the actual research issuer feeds an independently verified toy confirmer transcript',async()=>{
 const {envelope,privateCustody}=await issued();
 const session=await beginToyConfirmation({envelope,privateCustody,role:'C',claimedMessage:4n});
 assert.equal(session.status,'TOY_PROVER_READY');
 assert.equal(Object.hasOwn(session.public,'privateKey'),false);
 assert.equal(Object.hasOwn(session.public,'opening'),false);
 const out=finishToyConfirmation(session,2n);
 assert.equal(out.status,'TOY_EQUATIONS_HOLD');
 assert.equal(out.publicTranscript.challenge,2n);
 assert.equal(Object.hasOwn(out.publicTranscript,'proverState'),false);
 assert.ok(Object.values(out.publicChecks).every(Boolean));
 assert.match(out.evidence,/NOT FULL CONFIRMATION/);
 assert.equal(checkToyPi1Transcript(out.publicTranscript.statement,out.publicTranscript.firstMessage,2n,out.publicTranscript.response).equationsHold,true);
});
test('the signer can independently run the same toy source relation with their own encrypted opening',async()=>{
 const {envelope,privateCustody}=await issued();
 const session=await beginToyConfirmation({envelope,privateCustody,role:'S',claimedMessage:4n});
 assert.equal(session.status,'TOY_PROVER_READY');
 assert.equal(finishToyConfirmation(session,3n).status,'TOY_EQUATIONS_HOLD');
});
test('random post-commit verifier challenge produces mathematically checked public transcript',async()=>{
 for(let i=0;i<8;i++){
  const {envelope,privateCustody}=await issued();
  const session=await beginToyConfirmation({envelope,privateCustody});
  assert.equal(session.status,'TOY_PROVER_READY');
  const r=finishToyConfirmation(session);
  assert.equal(r.status,'TOY_EQUATIONS_HOLD');
  assert.ok(r.publicTranscript.challenge>=0n&&r.publicTranscript.challenge<4n);
 }
});
test('one commitment may answer only one challenge in this orchestrator',async()=>{
 const {envelope,privateCustody}=await issued();
 const session=await beginToyConfirmation({envelope,privateCustody});
 assert.equal(finishToyConfirmation(session,1n).status,'TOY_EQUATIONS_HOLD');
 assert.throws(()=>finishToyConfirmation(session,2n),/already used/);
});
test('out-of-range challenge consumes the masks rather than letting a prover retry',async()=>{
 const {envelope,privateCustody}=await issued();
 const session=await beginToyConfirmation({envelope,privateCustody});
 assert.throws(()=>finishToyConfirmation(session,4n),/Challenge outside/);
 assert.throws(()=>finishToyConfirmation(session,1n),/already used/);
});
test('changed claimed message yields NO PROOF, not false affirmative disavowal',async()=>{
 const {envelope,privateCustody}=await issued();
 for(const m of [3n,5n,8n]){
  const s=await beginToyConfirmation({envelope,privateCustody,claimedMessage:m});
  assert.equal(s.status,'NO_PROOF');
  assert.match(s.evidence,/NO DCS CONFIRMATION OR DISAVOWAL/);
  assert.throws(()=>finishToyConfirmation(s,1n),/No approved/);
 }
});
test('altered ECDSA signature or missing role secret prevents a proof before it begins',async()=>{
 const {envelope,privateCustody}=await issued();
 const altered={...envelope,signature:envelope.signature.slice()};
 altered.signature[3]^=1;
 const bad=await beginToyConfirmation({envelope:altered,privateCustody});
 assert.equal(bad.status,'NO_PROOF');
 assert.match(bad.reason,/Public ECDSA/);
 assert.equal((await beginToyConfirmation({envelope,privateCustody:{...privateCustody,confirmerKey:null}})).status,'NO_PROOF');
});
test('any tiny-equation truth cannot be published as a complete DCS validity decision',async()=>{
 const {envelope,privateCustody}=await issued();
 const s=await beginToyConfirmation({envelope,privateCustody});
 const r=finishToyConfirmation(s,1n);
 assert.equal(r.status,'TOY_EQUATIONS_HOLD');
 for(const field of ['confirmed','disavowed','nonTransferable','completeDCS'])assert.equal(Object.hasOwn(r,field),false);
});
