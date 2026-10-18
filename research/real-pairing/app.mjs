import {
 issue,verifyFormat,extract,shortenedPoint,Q,SCOPE
} from './core.mjs';
import {
 beginConfirmation,chooseVerifierChallenge,respondConfirmation,
 verifyConfirmation,simulateConfirmation
} from './confirmation.mjs';
import {
 beginDisavow,respondDisavow,verifyDisavow,simulateDisavow
} from './disavow-reconstructed.mjs';

const el=id=>document.getElementById(id);
let issued=null,claim=null,busy=false,epoch=0;
const outputs=['issue','confirm','deny','simulate'];
const buttons=['issue','reset','confirm-carol','confirm-alice','alter','deny-carol','deny-alice','simulate'];
function status(which,message,kind='neutral'){
 const node=el(which+'-status');
 node.dataset.kind=kind;
 node.textContent=message;
}
function show(which,lines){
 el(which+'-math').textContent=lines.join('\n');
}
function checkButtons(){
 const ready=!!issued;
 for(const id of buttons)el(id).disabled=busy||(id!=='issue'&&id!=='reset'&&!ready);
 const changed=ready&&claim!==issued.publicData.message;
 el('alter').disabled=busy||!ready||changed;
 el('deny-carol').disabled=busy||!changed;
 el('deny-alice').disabled=busy||!changed;
 el('simulate').disabled=busy||!ready;
 el('message').disabled=busy;
}
function retired(){
 issued=null;claim=null;
 for(const x of outputs)status(x,x==='issue'?'Issue a new signed object.':'Awaiting a fresh issued object.');
 for(const x of outputs)show(x,['No current public proof.']);
 checkButtons();
}
async function run(action){
 if(busy)return;
 busy=true;checkButtons();
 try{await action();}
 catch(e){status('simulate','Research operation rejected: '+(e instanceof Error?e.message:'Unknown error'),'reject');}
 finally{busy=false;checkButtons();}
}
function verdictLines(out){
 return Object.entries(out.checks).map(([k,v])=>k+': '+(v?'MATCH':'REJECT'));
}
function showSelected(which,label,first,challenge,response,result){
 const lines=[
  label,'',
  'Bob challenge: 0x'+challenge.toString(16),
  'The verifier CHOSE it after receiving the first message.',
  'Public response fields:'
 ];
 for(const [k,v] of Object.entries(response))lines.push(k+' = 0x'+v.toString(16).slice(0,40)+'…');
 lines.push('', 'Independent public checks:',...verdictLines(result),'');
 if(first.beta1)lines.push('Both nonidentity inequality beta values were checked.');
 lines.push('This is a research transcript, not a production-security certificate.');
 show(which,lines);
}
el('issue').addEventListener('click',()=>run(async()=>{
 const op=++epoch;
 const message=el('message').value;
 status('issue','Generating real BLS12-381 keys and pairing objects…');
 const result=await issue({message});
 if(op!==epoch)return;
 const format=await verifyFormat(result.publicData);
 const extraction=await extract(result.publicData,result.privateKeys.xc);
 if(!format||!extraction.valid)throw Error('Cryptographic issuance check failed');
 issued=result;claim=message;
 status('issue','Real BLS12-381 signature issued. Signed-ElGamal format and confirmer extraction both passed.','pass');
 status('confirm','Bob has not requested confirmation yet.');
 status('deny','The original signed statement is still valid. Alter the claim to try disavowal.');
 status('simulate','Try Eve’s simulated transcript; can it fool the recorded equation checks?');
 show('issue',[
  'Signed statement: '+message,
  'Signer BLS public key (G₂): '+shortenedPoint(result.publicData.signerPublic),
  'Confirmer encryption key (G₁): '+shortenedPoint(result.publicData.confirmerPublicG1),
  'Confirmer pairing key (G₂): '+shortenedPoint(result.publicData.confirmerPublicG2),
  'Signed-ElGamal σ₁ (G₁): '+shortenedPoint(result.publicData.signature.sigma1),
  'Signed-ElGamal σ₂ (G₁): '+shortenedPoint(result.publicData.signature.sigma2),
  'Dual public-key consistency: PASS',
  'Signed-ElGamal format: PASS',
  'Carol extraction + independent pairing: PASS',
  '',
  'Keys exist only in this browser experiment. Real roles would use distinct devices.'
 ]);
}));
el('reset').addEventListener('click',()=>{
 ++epoch;issued=null;claim=null;
 el('message').value='The library loan was returned.';
 retired();
});
el('message').addEventListener('input',()=>{
 ++epoch;retired();
});
async function confirmation(role){
 if(!issued)return;
 const message=claim;
 const alleged={...issued.publicData,message};
 const who=role==='signer'?'Alice':'Carol';
 try{
  const first=await beginConfirmation({publicData:alleged,privateKeys:issued.privateKeys,role});
  const challenge=chooseVerifierChallenge();
  const response=respondConfirmation(first,challenge);
  const publicResult=await verifyConfirmation({
   publicData:alleged,firstMessage:first.firstMessage,challenge,response
  });
  status('confirm',publicResult.equationsHold?
   who+' answered Bob’s independent challenge; five real pairing/point equations matched. (Research protocol.)':
   'The public confirmation equations rejected the transcript.',
   publicResult.equationsHold?'pass':'reject');
  showSelected('confirm',who+' real pairing OR confirmation',first.firstMessage,challenge,response,publicResult);
 }catch(e){
  status('confirm',who+' cannot honestly confirm this alleged signature. That failure is NOT proof it is invalid.','warn');
  show('confirm',['Honest proof precondition failed:',String(e.message),'No affirmative disavowal was run.']);
 }
}
el('confirm-carol').addEventListener('click',()=>run(()=>confirmation('confirmer')));
el('confirm-alice').addEventListener('click',()=>run(()=>confirmation('signer')));
el('alter').addEventListener('click',()=>{
 if(!issued||busy)return;
 claim=issued.publicData.message+' [ALTERED AFTER SIGNING]';
 status('deny','Bob’s claimed message was altered without a new signature. Test the inequality proof.','warn');
 status('confirm','An honest signer or confirmer should now refuse positive confirmation.','warn');
 show('deny',[
 'Original signed text: '+issued.publicData.message,
 'Bob now claims: '+claim,
 'Signed-ElGamal format is unchanged; underlying pairing validity relation differs.'
 ]);
 checkButtons();
});
async function disavow(role){
 if(!issued)return;
 const who=role==='signer'?'Alice':'Carol';
 const alleged={...issued.publicData,message:claim};
 try{
  const first=await beginDisavow({publicData:alleged,privateKeys:issued.privateKeys,role});
  const c=chooseVerifierChallenge();
  const response=respondDisavow(first,c);
  const verdict=await verifyDisavow({publicData:alleged,
   firstMessage:first.firstMessage,challenge:c,response});
  status('deny',verdict.equationsHold?
   who+' proved the candidate inequality relation to Bob using genuine pairings. NOT a published/audited DCS disavowal.':
   'The candidate inequality verifier rejected the proof.',
   verdict.equationsHold?'pass':'reject');
  showSelected('deny',who+' mathematically reconstructed disavowal candidate',first.firstMessage,c,response,verdict);
 }catch(e){
  status('deny',who+' cannot honestly produce this candidate invalidity proof: '+e.message,'warn');
 }
}
el('deny-carol').addEventListener('click',()=>run(()=>disavow('confirmer')));
el('deny-alice').addEventListener('click',()=>run(()=>disavow('signer')));
el('simulate').addEventListener('click',()=>run(async()=>{
 if(!issued)return;
 const alleged={...issued.publicData,message:claim};
 // Show both confirmation and disavowal simulator facts.
 const sim=await simulateConfirmation({publicData:alleged});
 const checked=await verifyConfirmation({publicData:alleged,...sim});
 const simD=await simulateDisavow({publicData:alleged});
 const checkedD=await verifyDisavow({publicData:alleged,...simD});
 const passed=checked.equationsHold&&checkedD.equationsHold;
 const guessed=document.querySelector('input[name="prediction"]:checked')?.value||'pass';
 const accurate=(guessed==='pass')===passed;
 status('simulate',(accurate?'Correct prediction. ':'Interesting—your prediction was wrong. ')+
  (passed?'Eve’s computed transcript PASSED the public equations for BOTH proof types, without Bob selecting either challenge!':
  'The simulated equations were rejected.')+
  ' This does not mean Eve fooled an independent live verifier.',
  passed?'warn':'reject');
 show('simulate',[
  'SIMULATED CONFIRMATION ON ALLEGED MESSAGE',
  'Math checks: '+(checked.equationsHold?'ALL MATCH':'REJECTED'),
  'Eve-selected challenge: 0x'+sim.challenge.toString(16),
  ...verdictLines(checked),'',
  'SIMULATED INVALIDITY PROOF (even for valid statements)',
  'Math checks: '+(checkedD.equationsHold?'ALL MATCH':'REJECTED'),
  'Eve-selected challenge: 0x'+simD.challenge.toString(16),
  ...verdictLines(checkedD),'',
  'The adversary authored the transcript and selected the challenges herself.',
  'Bob never sent an independent verifier challenge; these transcripts are NOT a real session.'
 ]);
}));
if(!globalThis.crypto?.subtle||!globalThis.crypto?.getRandomValues){
 for(const b of buttons)el(b).disabled=true;
 status('issue','HTTPS or localhost with Web Crypto is required for real BLS12-381 calculations.','reject');
}else checkButtons();
