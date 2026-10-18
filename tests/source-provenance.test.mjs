import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync,existsSync} from 'node:fs';
const root=new URL('../',import.meta.url);
const read=path=>readFileSync(new URL(path,root),'utf8');

test('2016 source §6–7 corrects its abbreviated introduction without inventing exact proof security',()=>{
 const s=read('research/SOURCE-RECONCILIATION.md');
 assert.match(s,/OPEN SPECIFICATION DISCREPANCY/);
 assert.match(s,/2013 thesis[\s\S]*?Five listed objects/i);
 assert.match(s,/2016 journal \*\*introduction summary\*\*/);
 assert.match(s,/§7\.2[\s\S]*?π0/);
 assert.match(s,/\*\*does not\*\* prove omission of π0/);
 assert.match(s,/full protocol implementation\/release gate remains CLOSED/);
});
test('research code and source notes do not claim an independently reviewed complete 2016 DCS',()=>{
 const gate=read('RESEARCH-GATE.md'),selection=read('SCHEME-SELECTION.md');
 const scheme=read('SCHEME-NOTES.md'),readme=read('README.md');
 assert.match(gate,/Issuance inventory reconciled; remaining 2013\/2016 proof fidelity open/);
 assert.match(selection,/2013 thesis construction sketch/);
 assert.match(scheme,/NOT verified as complete 2016 protocol/);
 assert.match(readme,/SOURCE-RECONCILIATION\.md/);
 assert.match(gate,/research gate CLOSED/);
});
test('partial source transcription never authorizes full DCS Pages publication',()=>{
 const s=read('research/SOURCE-RECONCILIATION.md');
 assert.match(s,/full protocol implementation\/release gate remains CLOSED/);
 assert.equal(existsSync(new URL('.github/workflows/deploy.yml',root)),false);
 const page=read('prototype/index.html');
 assert.match(page,/The separate protocol where Carol proves a signature valid or invalid is <b>not yet implemented<\/b>/);
});
