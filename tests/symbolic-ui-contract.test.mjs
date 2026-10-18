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
 assert.match(source,/confirmBegin/);assert.match(source,/verifierChallenge/);assert.match(source,/confirmRespond/);assert.match(source,/confirmVerify/);
 assert.match(source,/NOT a mathematical disavowal/);
 const adapter=read('prototype/symbolic/dcs-uv-symbolic.mjs');
 assert.match(adapter,/research\/dcs-uv-symbolic\.mjs/);
});