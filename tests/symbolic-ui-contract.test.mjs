import test from 'node:test';import assert from 'node:assert/strict';import {readFileSync} from 'node:fs';
const read=p=>readFileSync(new URL('../'+p,import.meta.url),'utf8');
test('separate symbolic research chapter identifies its insecure algebra and missing disavowal',()=>{
 const html=read('prototype/symbolic/index.html');
 assert.match(html,/NOT SECURE CRYPTOGRAPHY OR A FINISHED DESIGNATED CONFIRMER SIGNATURE/);
 assert.match(html,/affirmative disavowal proof/);
 assert.match(html,/Figur(?:e|es) 5\.3/);
 assert.match(html,/Chapter 5/);
});
test('browser uses ONLY one linked module and real verifier equations',()=>{
 const source=read('prototype/symbolic/app.mjs');
 assert.match(source,/confirmBegin/);assert.match(source,/verifierChallenge/);assert.match(source,/confirmRespond/);assert.match(source,/confirmVerifyEnvelope/);
 assert.match(source,/NOT a mathematical disavowal/);
 const adapter=read('prototype/symbolic/dcs-uv-symbolic.mjs');
 assert.match(adapter,/research\/dcs-uv-symbolic\.mjs/);
});

test('the interactive attack lab explains challenge ordering without claiming DCS security',()=>{
 const html=read('prototype/symbolic/index.html');
 const js=read('prototype/symbolic/app.mjs');
 for(const id of ['forge','fresh-challenge','attack-result','attack-proof','prediction-feedback'])
  assert.match(html,new RegExp('id="'+id+'"'));
 assert.match(html,/deliberately incorrect message order/);
 assert.match(js,/forgeWithKnownChallenge/);
 assert.match(js,/confirmVerifyEnvelope/);
 assert.match(js,/challenge===forgery.chosenChallenge/);
 assert.match(js,/NOT valid confirmation/);
 assert.match(html,/does <b>not<\/b> implement disavowal/);
});
