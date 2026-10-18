import {keygen,issue,validFormat,extract,confirmBegin,verifierChallenge,confirmRespond,confirmVerifyEnvelope,forgeWithKnownChallenge,securityLimit} from './dcs-uv-symbolic.mjs';
const id=x=>document.getElementById(x);
let keys=null, issued=null, busy=false,version=0, forgery=null;
const buttons=['keys','issue','carol','alice','change','forge','fresh-challenge'];
function renderButtons(){id('keys').disabled=busy;id('issue').disabled=busy||!keys;id('carol').disabled=busy||!issued;id('alice').disabled=busy||!issued;id('change').disabled=busy||!issued;id('forge').disabled=busy||!issued;id('fresh-challenge').disabled=busy||!forgery;}
function status(message,tone='neutral'){id('verdict').textContent=message;id('verdict').dataset.tone=tone;}
function publicLine(entry){return Object.entries(entry).map(([k,v])=>`${k}: ${typeof v==='bigint'?v.toString():v}`).join('\n');}
function resetProof(){id('proof-data').textContent='Awaiting Bob’s next challenge.';status('No proof transcript yet.');}

function resetForgery(){
 forgery=null;
 id('attack-result').textContent='Issue Alice\'s symbolic signature to unlock the attack experiment.';
 id('attack-result').dataset.tone='neutral';
 id('attack-proof').textContent='No attack transcript yet.';
 id('prediction-feedback').textContent='Predict first, then see the independent verifier\'s computed result.';
 renderButtons();
}
function reportForgery(message,tone='neutral'){
 id('attack-result').textContent=message;id('attack-result').dataset.tone=tone;
}
function guarded(action){if(busy)return;busy=true;renderButtons();Promise.resolve().then(action).catch(e=>status(`Operation rejected: ${e instanceof Error?e.message:'Unknown error'}`,'bad')).finally(()=>{busy=false;renderButtons();});}
id('keys').addEventListener('click',()=>guarded(async()=>{
  version++;keys=keygen();issued=null;resetForgery();id('issue-data').textContent=`Toy signer key: ${keys.signerPublic.toString()}\nToy confirmer key: ${keys.confirmerPublic.toString()}\nWARNING: These public exponents expose the private key. ${securityLimit}`;resetProof();status('Toy keys generated. They are NOT secret.');
}));
id('issue').addEventListener('click',()=>guarded(async()=>{
 const run=version, msg=id('message').value;
 issued=await issue({message:msg,keys});if(run!==version)return;
 const fmt=await validFormat(issued);const extracted=await extract({publicData:issued,confirmerSecret:keys.confirmerSecret});
 id('issue-data').textContent=`Signed-ElGamal tuple (symbolic exponents)\n${publicLine(issued.signature)}\nFormat proof: ${fmt?'PASS':'FAIL'}\nConfirmer extraction check: ${extracted.extracted?'PASS':'FAIL'}\n${securityLimit}`;
 resetForgery();resetProof();status('Source-structured symbolic signature issued. Ask Alice or Carol for a proof.');
}));
async function prove(role){
 const d=issued; const session=await confirmBegin({publicData:d,keys,role});
 // Bob's challenge sampled only AFTER prover's first message exists.
 const challenge=verifierChallenge();const response=confirmRespond(session,challenge);
 const verdict=await confirmVerifyEnvelope({publicData:d,firstMessage:session.firstMessage,challenge,response});
 const selected=role==='signer'?'Alice (signer)':'Carol (confirmer)';
 const lines=[`${selected} sent four first-message values:`,publicLine(session.firstMessage),`Bob selected challenge: ${challenge}`,`Response values:`,publicLine(response),'Bob recomputed these equations:',...Object.entries(verdict.checks).map(([k,v])=>`${k}: ${v?'MATCH':'REJECT'}`)];
 id('proof-data').textContent=lines.join('\n');
 status(verdict.equationsHold?`${selected}'s five OR-proof checks hold in this SYMBOLIC model. This is NOT secure confirmation.`:'The symbolic proof equations rejected this transcript.',verdict.equationsHold?'neutral':'bad');
}
id('carol').addEventListener('click',()=>guarded(()=>prove('confirmer')));
id('alice').addEventListener('click',()=>guarded(()=>prove('signer')));
id('change').addEventListener('click',()=>guarded(async()=>{
 if(!issued)return;
 const changed={...issued,message:issued.message+' [changed]'};
 try{await confirmBegin({publicData:changed,keys,role:'confirmer'});
  status('UNEXPECTED ACCEPTANCE: research assertion failure. Stop and report.', 'bad');
 }catch{
  id('proof-data').textContent='Carol cannot honestly prove the modified statement under Alice’s original symbolic signature.\nNo disavowal proof was run.';
  status('The altered statement failed the local proof precondition. That is NOT a mathematical disavowal.','warn');
 }
}));

// NEGATIVE CONTROL: Eve has no signing or confirmer key. She chooses Bob's
// challenge FIRST, then fabricates the earlier proof commitment backwards.
id('forge').addEventListener('click',()=>guarded(async()=>{
 if(!issued)return;
 const forgedMessage=issued.message==='A forged library agreement'?'A different forged agreement':'A forged library agreement';
 const demo=await forgeWithKnownChallenge({publicData:issued,forgedMessage});
 const check=await confirmVerifyEnvelope({publicData:demo.publicData,firstMessage:demo.firstMessage,challenge:demo.chosenChallenge,response:demo.response});
 forgery={...demo,initialChecks:check};
 if(!check.equationsHold){reportForgery('Research error: Eve\'s fabricated equations did not pass.','bad');return;}
 const predicted=document.querySelector('input[name="forgery-predict"]:checked')?.value;
 id('prediction-feedback').textContent=predicted==='pass'?'Correct prediction. Eve made the equations pass by choosing Bob\'s challenge too early.':'The result passed. Eve exploited the message order; this is not an honest confirmation.';
 id('attack-proof').textContent=[
  'Original agreement: '+issued.message,
  'Eve\'s false agreement: '+demo.publicData.message,
  'Eve PRESELECTED challenge: '+demo.chosenChallenge.toString(),
  'First message, calculated AFTER challenge:',
  publicLine(demo.firstMessage),'Eve\'s responses:',publicLine(demo.response),
  'Independent verifier checks:',
  ...Object.entries(check.checks).map(([k,v])=>k+': '+(v?'MATCH':'REJECT')),
  demo.warning
 ].join('\n');
 reportForgery('FALSE PROOF PASSED FIVE EQUATIONS — because Eve chose the challenge first. This is cheating, NOT valid confirmation.','warn');
}));
id('fresh-challenge').addEventListener('click',()=>guarded(async()=>{
 if(!forgery)return;
 let challenge=verifierChallenge();
 // Intentionally demand a DIFFERENT challenge to exhibit the failure.
 while(challenge===forgery.chosenChallenge)challenge=verifierChallenge();
 const verdict=await confirmVerifyEnvelope({publicData:forgery.publicData,firstMessage:forgery.firstMessage,challenge,response:forgery.response});
 id('attack-proof').textContent += '\n\nBob TESTS A DIFFERENT CHALLENGE: '+challenge.toString()+'\n'+
  Object.entries(verdict.checks).map(([k,v])=>k+': '+(v?'MATCH':'REJECT')).join('\n');
 reportForgery(verdict.equationsHold?'Unexpected toy acceptance: no security conclusion is valid.':'REJECTED — Bob used a different challenge. Eve\'s earlier response no longer satisfies his check.','bad');
 id('prediction-feedback').textContent='Bob must choose a fresh unpredictable challenge AFTER receiving the first proof message. A preselected challenge is not an honest three-message proof.';
}));
id('message').addEventListener('input',()=>{version++;issued=null;resetForgery();id('issue-data').textContent='Statement changed. Previous issued object retired; issue a new one.';resetProof();renderButtons();});
if(!globalThis.crypto?.subtle){status('Web Crypto requires HTTPS or localhost. No math executed.','bad');buttons.forEach(b=>id(b).disabled=true);}
else{status('Generate toy keys, then issue a symbolic signature.');renderButtons();}