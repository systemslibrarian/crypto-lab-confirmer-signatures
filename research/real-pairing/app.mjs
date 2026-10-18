import {issue,verifyFormat,extract,messagePoint} from './core.mjs';
import {chooseVerifierChallenge,simulateConfirmation,verifyConfirmation} from './confirmation.mjs';
import {ProofExchange} from './exchange.mjs';
import {exportTranscript} from './transcript.mjs';
const $=id=>document.getElementById(id);
let mode='guided',chapter=0,unlocked=0,busy=false,issued=null,claim=null;
let exchange=null,proof=null,proofData=null,lastExport=null,eve=null,eveCheck=null,liveCheck=null;
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
function retire(){issued=null;claim=null;chapter=0;unlocked=0;clearProof();clearEve();actor(null);
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
 for(const name of ['guided','explore','research'])$('mode-'+name).setAttribute('aria-pressed',String(mode===name));
 for(let n=0;n<4;n++){$('chapter-'+n).disabled=busy||n>unlocked;
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
function go(n){chapter=n;render();focusHeading(['issue-heading','proof-heading','alter-heading','eve-heading'][n]);}
function view(name){mode=name;render();$('global-status').textContent='View changed: '+$('mode-'+name).textContent;
 if(name==='research')focusHeading('research-heading');
}
for(const name of ['guided','explore','research'])$('mode-'+name).onclick=()=>view(name);
for(let n=0;n<4;n++)$('chapter-'+n).onclick=()=>{if(n<=unlocked)go(n);};
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
render();
if(!globalThis.crypto?.subtle||!globalThis.crypto?.getRandomValues){busy=true;render();status('issue-status','Web Crypto over HTTPS or localhost is required.','reject');}
