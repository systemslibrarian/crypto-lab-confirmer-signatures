import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync,existsSync} from 'node:fs';
const root=new URL('../',import.meta.url);
const read=path=>readFileSync(new URL(path,root),'utf8');

test('source note distinguishes 2013 five-part scheme from abbreviated 2016 introduction',()=>{
 const s=read('research/SOURCE-RECONCILIATION.md');
 assert.match(s,/OPEN SPECIFICATION DISCREPANCY/);
 assert.match(s,/2013 thesis[\s\S]*?five listed objects/);
 assert.match(s,/2016 journal \*\*introduction summary\*\*/);
 assert.match(s,/does \*\*not\*\* prove/);
});
test('all authoring entry points preserve paper-specific scheme provenance',()=>{
 const gate=read('RESEARCH-GATE.md'),selection=read('SCHEME-SELECTION.md');
 const scheme=read('SCHEME-NOTES.md'),readme=read('README.md');
 assert.match(gate,/Open 2013\/2016 syntax discrepancy/);
 assert.match(selection,/2013 thesis construction sketch/);
 assert.match(scheme,/NOT verified as the 2016 final syntax/);
 assert.match(readme,/SOURCE-RECONCILIATION\.md/);
});
test('source discrepancy does not authorize a live or complete DCS',()=>{
 const s=read('research/SOURCE-RECONCILIATION.md');
 assert.match(s,/implementation\/release gate remains \*\*CLOSED\*\*/);
 assert.equal(existsSync(new URL('.github/workflows/deploy.yml',root)),false);
 const page=read('prototype/index.html');
 assert.match(page,/does <b>not<\/b> implement a designated confirmer signature/);
});
