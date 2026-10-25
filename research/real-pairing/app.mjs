import {issue,verifyFormat,extract,messagePoint} from './core.mjs';
import {chooseVerifierChallenge,simulateConfirmation,verifyConfirmation} from './confirmation.mjs';
import {ProofExchange} from './exchange.mjs';
import {exportTranscript} from './transcript.mjs';
import {createVerifierKey,proveWithWitness,proveWithVerifierSecret,verifyDesignatedProof,
 provePublicTransferable,verifyPublicTransferable,observerView,publicProofFields} from './designated-verifier.mjs';
const $=id=>document.getElementById(id);
let mode='guided',chapter=0,unlocked=0,busy=false,issued=null,claim=null;
let exchange=null,proof=null,proofData=null,lastExport=null,eve=null,eveCheck=null,liveCheck=null;
// The designated verifier's secret stays in module scope and is never rendered.
let dvKey=null,dvWitnessProof=null,dvVerifierProof=null,dvPublicProof=null;
const DV_CONTEXT='signature-gate-designated-verifier-lesson-v1';
const status=(id,text,kind='neutral')=>{const n=$(id);n.textContent=text;n.dataset.kind=kind;};
const json=x=>JSON.stringify(x,(_,v)=>typeof v==='bigint'?'0x'+v.toString(16):v,2);
const changed=()=>!!issued&&claim!==issued.publicData.message;
const prediction=name=>document.querySelector('input[name="'+name+'"]:checked')?.value;
function focusHeading(id){const h=$(id);h.tabIndex=-1;h.focus();}
function actor(name){for(const n of ['alice','carol','bob','eve'])$('actor-'+n).classList.toggle('active',n===name);}
function clearProof(){exchange=null;proof=null;proofData=null;lastExport=null;
 $('proof-math').textContent='No proof transcript yet.';
 status('proof-status','Receive a commitment before choosing your challenge.');
 $('export-status').textContent='Complete a proof exchange in the story first.';
}
function clearEve(){eve=null;eveCheck=null;liveCheck=null;
 $('recording-verdict').textContent='Not created yet';$('live-verdict').textContent='You have not challenged it';
 $('recording-explain').textContent='Eve will pick responses and a challenge, then calculate a matching commitment.';
 $('live-explain').textContent='Keep Eve’s commitment and answer fixed. Give her recording a different challenge.';
 $('eve-challenge').textContent='';$('live-challenge').textContent='';$('eve-math').textContent='No recording yet.';
 $('live-card').classList.remove('live-rejected');status('eve-status','Make your prediction first.');
}
function clearDv({keepKey=false}={}){
 if(!keepKey)dvKey=null;
 dvWitnessProof=null;dvVerifierProof=null;dvPublicProof=null;
 $('dv-witness-verdict').textContent='Not created yet';
 $('dv-verifier-verdict').textContent='Not created yet';
 $('dv-witness-explain').textContent='Alice uses the branch secret. She cannot make this proof for a statement she cannot prove.';
 $('dv-verifier-explain').textContent='You use your verifier secret instead of any branch secret, and the same verifier accepts the result.';
 $('dv-witness-d').textContent='';$('dv-verifier-d').textContent='';
 $('dv-observer-text').textContent='nothing yet; no proof has been created.';
 $('dv-math').textContent='No designated proof yet.';
 if(!keepKey)status('dv-key-status','You have no verifier key yet. The proof will be addressed to it, and its secret is what lets you forge the same proof.');
 status('dv-status',dvKey?'Your verifier key is ready. Ask Alice for a proof, or make one yourself.':'Create a verifier key to begin.');
}
function retire(){issued=null;claim=null;chapter=0;unlocked=0;clearProof();clearEve();clearDv();actor(null);
 status('issue-status','Ready. No signed object has been created.');
 status('alter-status','The original claim is still in use.');$('bob-knows').textContent='You have no proof yet';
 for(const input of document.querySelectorAll('input[type=radio]'))input.checked=false;
 render();
}
function render(){
 const all=mode==='explore',stage=proof?.stage??'ready',active=['preparing','committed','challenged','checking'].includes(stage);
 $('play-area').hidden=mode==='research';$('research-panel').hidden=mode!=='research';$('chapters').hidden=mode!=='guided';
 $('issue-panel').hidden=!all&&chapter!==0;
 $('participants').hidden=mode==='guided'&&chapter===0;
 $('alter-panel').hidden=!all&&chapter!==2;
 $('proof-panel').hidden=!all&&![1,2].includes(chapter);
 $('eve-panel').hidden=!all&&chapter!==3;
 $('dv-panel').hidden=!all&&chapter!==4;
 for(const name of ['guided','explore','research'])$('mode-'+name).setAttribute('aria-pressed',String(mode===name));
 for(let n=0;n<5;n++){$('chapter-'+n).disabled=busy||(n===4?!issued:n>unlocked);
  if(n===chapter)$('chapter-'+n).setAttribute('aria-current','step');else $('chapter-'+n).removeAttribute('aria-current');}
 $('mode-description').textContent=mode==='guided'?'Four short experiments. Make a prediction, choose a challenge, and see what the mathematics establishes.':mode==='explore'?'All experiments are available together. Switch prover roles, change the claim, and inspect exact public values.':'Reproduce the calculations, inspect the correction argument, and distinguish implemented checks from open security claims.';
 $('issue').disabled=busy;$('reset').disabled=busy;$('message').disabled=busy;
 $('role').disabled=busy||!issued;$('altered-message').disabled=busy||!issued;
 $('alter').disabled=busy||!issued||!prediction('alter-prediction');
 $('begin-confirm').disabled=busy||!issued||active;
 $('begin-deny').hidden=!changed();$('begin-deny').disabled=busy||!changed()||active;
 $('challenge').disabled=busy||stage!=='committed';$('answer').disabled=busy||stage!=='challenged';
 $('challenge-card').hidden=proof?.challenge===undefined;
 $('proof-outcome').hidden=stage!=='checked';
 $('next-alter').hidden=!(stage==='checked'&&proof.kind==='confirmation'&&!changed()&&proof.result.equationsHold);
 $('next-eve').hidden=!(stage==='checked'&&proof.kind==='disavowal'&&proof.result.equationsHold);
 $('simulate').disabled=busy||!issued||!prediction('eve-prediction');
 $('challenge-eve').disabled=busy||!eve||!!liveCheck;
 $('takeaway').hidden=!liveCheck||liveCheck.equationsHold;
 $('download').disabled=busy||!lastExport;
 $('dv-key').disabled=busy||!issued;
 $('dv-role').disabled=busy;
 for(const id of ['dv-prove','dv-simulate','dv-false','dv-public','dv-public-forge'])$(id).disabled=busy||!issued||!dvKey;
 $('claim-display').textContent=issued?'Bob is checking: “'+claim+'”':'Create an agreement first.';
 $('original-message').textContent=issued?.publicData.message??'Create an agreement first.';
 const rank={ready:0,preparing:0,committed:1,challenged:2,checking:2,checked:3,'no-proof':0,failed:0}[stage];
 ['commit','challenge','answer'].forEach((n,i)=>{
  $('stage-'+n).classList.toggle('done',rank>i);$('stage-'+n).classList.toggle('current',rank===i);
 });
}
async function run(where,action){if(busy)return;busy=true;render();
 try{await action();}catch(e){status(where,'Operation unavailable: '+e.message,'reject');}
 finally{busy=false;render();}
}
function go(n){chapter=n;render();focusHeading(['issue-heading','proof-heading','alter-heading','eve-heading','dv-heading'][n]);}
function view(name){mode=name;$('equations').open=name==='explore';render();$('global-status').textContent='View changed: '+$('mode-'+name).textContent;
 if(name==='research')focusHeading('research-heading');
}
for(const name of ['guided','explore','research'])$('mode-'+name).onclick=()=>view(name);
for(let n=0;n<5;n++)$('chapter-'+n).onclick=()=>{if(n===4?issued:n<=unlocked)go(n);};
$('next-alter').onclick=()=>go(2);$('next-eve').onclick=()=>go(3);$('open-evidence').onclick=()=>view('research');
$('reset').onclick=()=>{retire();focusHeading('issue-heading');};
$('message').oninput=()=>{if(!busy)retire();};
$('role').onchange=()=>{clearProof();actor(null);$('bob-knows').textContent='A new prover needs a fresh commitment';render();};
for(const r of document.querySelectorAll('input[type=radio]'))r.onchange=render;
$('issue').onclick=()=>run('issue-status',async()=>{
 retire();status('issue-status','Alice is signing and encrypting the fictional agreement…');actor('alice');
 const result=await issue({message:$('message').value});
 if(!(await verifyFormat(result.publicData))||!(await extract(result.publicData,result.privateKeys.xc)).valid)throw Error('Issuance checks failed');
 issued=result;claim=result.publicData.message;unlocked=1;
 status('issue-status','Signed and encrypted. Format and independent extraction checks passed.','pass');
 $('bob-knows').textContent='You have an encrypted signature, not confirmation';
 if($('altered-message').value===claim)$('altered-message').value=claim==='A changed fictional agreement.'?'Another fictional agreement.':'A changed fictional agreement.';
 if(mode==='guided')go(1);
});
$('alter').onclick=()=>run('alter-status',async()=>{
 const text=$('altered-message').value;messagePoint(text);
 if(text===issued.publicData.message)throw Error('Choose words different from Alice’s original statement');
 claim=text;clearProof();clearEve();actor('bob');
 const correct=prediction('alter-prediction')==='no';
 status('alter-status',(correct?'Correct prediction. ':'The unchanged object is not enough. ')+
  'The alleged message changed; the encrypted signature did not. Now test confirmation.','warn');
 $('bob-knows').textContent='You are checking a changed claim';
});
async function begin(kind){await run('proof-status',async()=>{
 clearProof();proofData={...issued.publicData,message:claim};
 exchange=new ProofExchange({publicData:proofData,privateKeys:issued.privateKeys,role:$('role').value,kind});
 actor($('role').value==='signer'?'alice':'carol');
 try{proof=await exchange.commit();}
 catch(e){proof=exchange.snapshot();
  status('proof-status',kind==='confirmation'?'No confirmation proof was produced. This refusal is NOT proof of invalidity. Try the separate inequality proof.':'No inequality proof was produced. '+e.message,'warn');
  $('proof-math').textContent='No transcript. Honest prover precondition: '+e.message;return;}
 status('proof-status','Commitment received and fixed. Now you—not the prover—choose the challenge.');
 $('bob-knows').textContent='Commitment received; you have not chosen a challenge';
 // Only public commitments; private session state never reaches this view.
 $('proof-math').textContent='FIRST MESSAGE FIXED\n'+json(proof.firstMessage)+'\n\nChallenge: not generated yet.';
 });}
$('begin-confirm').onclick=()=>begin('confirmation');$('begin-deny').onclick=()=>begin('disavowal');
$('challenge').onclick=()=>{if(busy)return;
 proof=exchange.challenge();actor('bob');$('challenge-value').textContent='0x'+proof.challenge.toString(16);
 status('proof-status','Your fresh challenge is fixed. The prover must answer this challenge with the same commitment.');
 $('bob-knows').textContent='Commitment + your challenge; no answer yet';
 $('proof-math').textContent+='\n\nBOB’S CHALLENGE\n0x'+proof.challenge.toString(16);render();
};
$('answer').onclick=()=>run('proof-status',async()=>{
 try{proof=await exchange.finish();}catch(e){proof=exchange.snapshot();throw e;}
 actor('bob');const ok=proof.result.equationsHold;
 lastExport=exportTranscript({publicData:proofData,kind:proof.kind,...proof});
 status('proof-status',ok?(proof.kind==='confirmation'?'Confirmation equations matched your challenge.':'Candidate inequality equations matched your challenge. Research disavowal only.'):'The verifier rejected this response.',ok?'pass':'reject');
 $('outcome-title').textContent=ok?(proof.kind==='confirmation'?'A matching confirmation response.':'A separate affirmative inequality proof.'):'The public check rejected.';
 $('outcome-text').textContent=proof.kind==='confirmation'?'The local protocol’s public equations link a role key to this signature and message. This does not establish that the statement is factually true.':'This is positive evidence for the candidate invalidity relation—not an inference from a failed confirmation. The complete published DCS security guarantees remain unestablished.';
 const checks=$('equation-checks');checks.replaceChildren();
 for(const [label,pass] of Object.entries(proof.result.checks)){const span=document.createElement('span');span.textContent=(pass?'✓ MATCH · ':'× REJECT · ')+label;if(!pass)span.className='fail';checks.append(span);}
 $('proof-math').textContent=json(lastExport);$('export-status').textContent='Ready: public '+proof.kind+' transcript. No role keys or private masks.';
 $('bob-knows').textContent=ok?'You checked the response against your challenge':'You rejected the response';
 if(ok)unlocked=Math.max(unlocked,proof.kind==='confirmation'?2:3);
});
$('simulate').onclick=()=>run('eve-status',async()=>{
 clearEve();actor('eve');const falseClaim=issued.publicData.message==='A different alleged statement.'?'Another alleged statement.':'A different alleged statement.';
 const publicData={...issued.publicData,message:changed()?claim:falseClaim};
 const transcript=await simulateConfirmation({publicData});
 eveCheck=await verifyConfirmation({publicData,...transcript});eve={publicData,...transcript};
 $('recording-verdict').textContent=eveCheck.equationsHold?'Recorded equations: PASS':'Recorded equations: REJECT';
 $('recording-explain').textContent='Eve’s claim: “'+publicData.message+'”. She knew her chosen challenge before calculating the commitment. No role key was used.';
 $('eve-challenge').textContent='Eve chose 0x'+eve.challenge.toString(16);
 status('eve-status',(prediction('eve-prediction')==='pass'?'Correct prediction. ':'Surprise: ')+
  'The recorded equations pass. Now give the SAME commitment and response a different live challenge.','warn');
 $('eve-math').textContent='EVE’S RECORDING\n'+json(exportTranscript({publicData,kind:'confirmation',...transcript,provenance:'simulated-challenge-known-before-commitment'}));
});
$('challenge-eve').onclick=()=>run('eve-status',async()=>{
 // Explicitly sample a different challenge for this controlled comparison.
 let c;do{c=chooseVerifierChallenge();}while(c===eve.challenge);
 liveCheck=await verifyConfirmation({publicData:eve.publicData,firstMessage:eve.firstMessage,challenge:c,response:eve.response});
 actor('bob');$('live-challenge').textContent='Bob chose 0x'+c.toString(16);
 $('live-verdict').textContent=liveCheck.equationsHold?'Live response: PASS':'Live response: REJECT';
 $('live-explain').textContent='Same commitment. Same response. Different challenge. The challenge split no longer matches.';
 $('live-card').classList.toggle('live-rejected',!liveCheck.equationsHold);
 status('eve-status',liveCheck.equationsHold?'Unexpected acceptance: inspect the research checks.':'Bob rejected the same recording under his different challenge. Eve has not demonstrated a live proof.','warn');
 $('eve-math').textContent+='\n\nBOB’S DIFFERENT CHALLENGE\n0x'+c.toString(16)+'\nCHECKS\n'+json(liveCheck.checks);
 $('bob-knows').textContent='A recording can pass without a live verifier';
});
$('download').onclick=()=>{if(!lastExport)return;
 const url=URL.createObjectURL(new Blob([json(lastExport)+'\n'],{type:'application/json'}));
 const a=document.createElement('a');a.href=url;a.download='signature-gate-public-transcript.json';a.click();
 setTimeout(()=>URL.revokeObjectURL(url),1000);
};
// ---------------------------------------------------------------------------
// Chapter 5: the non-interactive designated-verifier proof.
// ---------------------------------------------------------------------------
const dvData=()=>({...issued.publicData,message:claim});
const dvRole=()=>$('dv-role').value;
const dvWitness=()=>dvRole()==='confirmer'?issued.privateKeys.xc:issued.privateKeys.xs;
function dvShow(proofObject,label,{designated=true}={}){
 // A public proof carries no w or r; asking for them would be a different object.
 $('dv-math').textContent=label+'\n'+json(publicProofFields(proofObject,{designated}))+
  '\n\nContext bound into the challenge: '+DV_CONTEXT+'\nBranch proved: '+dvRole();
}
async function dvObserver(proofObject){
 const view=await observerView({publicData:dvData(),role:dvRole(),proof:proofObject,
  verifierPublicKey:dvKey.publicKey,context:DV_CONTEXT});
 $('dv-observer-text').textContent=(view.equationsHold?'the equations hold, and that is all. ':'the equations do not hold. ')+
  'It cannot establish '+view.doesNotEstablish.length+' things: '+view.doesNotEstablish.join(' ')+
  ' Possible origins: '+view.possibleOrigins.join('; or ')+'.';
}
$('dv-key').onclick=()=>run('dv-key-status',async()=>{
 clearDv();dvKey=await createVerifierKey();actor('bob');
 status('dv-key-status','Your verifier key is registered with a proof of knowledge of its secret. Section 7 of the paper requires exactly that: a verifier who could not forge could not be designated.','pass');
 $('dv-observer-text').textContent='nothing yet; no proof has been created.';
 status('dv-status','Ask Alice for a proof, or make the same proof yourself.');
});
$('dv-role').onchange=()=>{clearDv({keepKey:true});render();};
$('dv-prove').onclick=()=>run('dv-status',async()=>{
 actor(dvRole()==='confirmer'?'carol':'alice');
 try{dvWitnessProof=await proveWithWitness({publicData:dvData(),role:dvRole(),witness:dvWitness(),
   verifierPublicKey:dvKey.publicKey,context:DV_CONTEXT});}
 catch(e){dvWitnessProof=null;$('dv-witness-verdict').textContent='No proof was produced';
  $('dv-witness-explain').textContent='An honest prover refuses a statement it cannot prove: '+e.message;
  status('dv-status','Alice produced no proof. That refusal is not evidence of anything; you can still forge the proof yourself.','warn');return;}
 const verdict=await verifyDesignatedProof({publicData:dvData(),role:dvRole(),proof:dvWitnessProof,
  verifierPublicKey:dvKey.publicKey,context:DV_CONTEXT});
 $('dv-witness-verdict').textContent=verdict.accepted?'Your verifier: ACCEPTED':'Your verifier: REJECTED';
 $('dv-witness-explain').textContent=verdict.reason;
 $('dv-witness-d').textContent='d = 0x'+dvWitnessProof.d.toString(16).slice(0,24)+'…';
 dvShow(dvWitnessProof,'PROOF MADE BY ALICE, USING THE BRANCH SECRET');
 await dvObserver(dvWitnessProof);
 status('dv-status',verdict.accepted?'Accepted. Now make the same proof yourself and compare.':'Rejected; inspect the values.',verdict.accepted?'pass':'reject');
});
$('dv-simulate').onclick=()=>run('dv-status',async()=>{
 actor('bob');
 dvVerifierProof=await proveWithVerifierSecret({publicData:dvData(),role:dvRole(),verifierSecret:dvKey.secret,
  verifierPublicKey:dvKey.publicKey,context:DV_CONTEXT});
 const verdict=await verifyDesignatedProof({publicData:dvData(),role:dvRole(),proof:dvVerifierProof,
  verifierPublicKey:dvKey.publicKey,context:DV_CONTEXT});
 $('dv-verifier-verdict').textContent=verdict.accepted?'Your verifier: ACCEPTED':'Your verifier: REJECTED';
 $('dv-verifier-explain').textContent='You used no branch secret at all, only your own. On a true statement the two proofs are drawn from exactly the same distribution, so nothing in either one records which of you made it.';
 $('dv-verifier-d').textContent='d = 0x'+dvVerifierProof.d.toString(16).slice(0,24)+'…';
 dvShow(dvVerifierProof,'PROOF MADE BY YOU, USING ONLY YOUR VERIFIER SECRET');
 await dvObserver(dvVerifierProof);
 status('dv-status','Both proofs pass the same check. That is why showing either one to anybody else establishes nothing.','warn');
});
$('dv-false').onclick=()=>run('dv-status',async()=>{
 actor('bob');
 const falseMessage=claim==='A statement Alice never signed.'?'Another statement Alice never signed.':'A statement Alice never signed.';
 const falseData={...issued.publicData,message:falseMessage};
 const forged=await proveWithVerifierSecret({publicData:falseData,role:dvRole(),verifierSecret:dvKey.secret,
  verifierPublicKey:dvKey.publicKey,context:DV_CONTEXT});
 const verdict=await verifyDesignatedProof({publicData:falseData,role:dvRole(),proof:forged,
  verifierPublicKey:dvKey.publicKey,context:DV_CONTEXT});
 const view=await observerView({publicData:falseData,role:dvRole(),proof:forged,
  verifierPublicKey:dvKey.publicKey,context:DV_CONTEXT});
 $('dv-verifier-verdict').textContent=verdict.accepted?'Your verifier: ACCEPTED':'Your verifier: REJECTED';
 $('dv-verifier-explain').textContent='The claim was \u201c'+falseMessage+'\u201d, which Alice never signed. The equations still hold, because you made the proof. This is the designation property, not a break.';
 $('dv-verifier-d').textContent='d = 0x'+forged.d.toString(16).slice(0,24)+'…';
 dvShow(forged,'PROOF OF A FALSE STATEMENT, MADE BY YOU');
 $('dv-observer-text').textContent='the equations hold for a statement that is false. '+view.doesNotEstablish[0];
 status('dv-status','Accepted, for a statement Alice never signed. An accepting proof therefore tells an outsider nothing about the claim.','warn');
});
$('dv-public').onclick=()=>run('dv-status',async()=>{
 actor(dvRole()==='confirmer'?'carol':'alice');
 try{dvPublicProof=await provePublicTransferable({publicData:dvData(),role:dvRole(),witness:dvWitness(),context:DV_CONTEXT});}
 catch(e){dvPublicProof=null;status('dv-status','No public proof was produced: '+e.message,'warn');return;}
 const verdict=await verifyPublicTransferable({publicData:dvData(),role:dvRole(),proof:dvPublicProof,context:DV_CONTEXT});
 dvShow(dvPublicProof,'PUBLIC TRANSFERABLE PROOF OF THE SAME STATEMENT',{designated:false});
 $('dv-observer-text').textContent='everything. This proof carries no verifier key and no blinding, so anyone who reads it is convinced. That is exactly what designation removes.';
 status('dv-status',verdict.accepted?'Accepted, and transferable: this one convinces anybody, which is the property the designated proof gives up.':'Rejected; inspect the values.',verdict.accepted?'pass':'reject');
});
$('dv-public-forge').onclick=()=>run('dv-status',async()=>{
 actor('bob');
 try{await provePublicTransferable({publicData:dvData(),role:dvRole(),witness:dvKey.secret,context:DV_CONTEXT});
  status('dv-status','Unexpected: a public proof was produced without the branch secret. Inspect the research checks.','reject');}
 catch(e){status('dv-status','Refused. Your verifier secret forges the designated proof but is worthless here: '+e.message,'pass');}
 $('dv-observer-text').textContent='the public proof cannot be forged with a verifier secret, which is why it stays convincing to third parties.';
});

render();
if(!globalThis.crypto?.subtle||!globalThis.crypto?.getRandomValues){busy=true;render();status('issue-status','Web Crypto over HTTPS or localhost is required.','reject');}
