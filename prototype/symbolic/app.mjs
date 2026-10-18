import {keygen,issue,validFormat,extract,confirmBegin,verifierChallenge,confirmRespond,confirmVerifyEnvelope,securityLimit} from './dcs-uv-symbolic.mjs';
const id=x=>document.getElementById(x);
let keys=null, issued=null, busy=false,version=0;
const buttons=['keys','issue','carol','alice','change'];
function renderButtons(){id('keys').disabled=busy;id('issue').disabled=busy||!keys;id('carol').disabled=busy||!issued;id('alice').disabled=busy||!issued;id('change').disabled=busy||!issued;}
function status(message,tone='neutral'){id('verdict').textContent=message;id('verdict').dataset.tone=tone;}
function publicLine(entry){return Object.entries(entry).map(([k,v])=>`${k}: ${typeof v==='bigint'?v.toString():v}`).join('\n');}
function resetProof(){id('proof-data').textContent='Awaiting Bob’s next challenge.';status('No proof transcript yet.');}
function guarded(action){if(busy)return;busy=true;renderButtons();Promise.resolve().then(action).catch(e=>status(`Operation rejected: ${e instanceof Error?e.message:'Unknown error'}`,'bad')).finally(()=>{busy=false;renderButtons();});}
id('keys').addEventListener('click',()=>guarded(async()=>{
  version++;keys=keygen();issued=null;id('issue-data').textContent=`Toy signer key: ${keys.signerPublic.toString()}\nToy confirmer key: ${keys.confirmerPublic.toString()}\nWARNING: These public exponents expose the private key. ${securityLimit}`;resetProof();status('Toy keys generated. They are NOT secret.');
}));
id('issue').addEventListener('click',()=>guarded(async()=>{
 const run=version, msg=id('message').value;
 issued=await issue({message:msg,keys});if(run!==version)return;
 const fmt=await validFormat(issued);const extracted=await extract({publicData:issued,confirmerSecret:keys.confirmerSecret});
 id('issue-data').textContent=`Signed-ElGamal tuple (symbolic exponents)\n${publicLine(issued.signature)}\nFormat proof: ${fmt?'PASS':'FAIL'}\nConfirmer extraction check: ${extracted.extracted?'PASS':'FAIL'}\n${securityLimit}`;
 resetProof();status('Source-structured symbolic signature issued. Ask Alice or Carol for a proof.');
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
id('message').addEventListener('input',()=>{version++;issued=null;id('issue-data').textContent='Statement changed. Previous issued object retired; issue a new one.';resetProof();renderButtons();});
if(!globalThis.crypto?.subtle){status('Web Crypto requires HTTPS or localhost. No math executed.','bad');buttons.forEach(b=>id(b).disabled=true);}
else{status('Generate toy keys, then issue a symbolic signature.');renderButtons();}