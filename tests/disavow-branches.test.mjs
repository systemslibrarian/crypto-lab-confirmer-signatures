import test from 'node:test';
import assert from 'node:assert/strict';
import {toyParameters,modPow,encrypt,absResidue,challenge,gcd} from '../research/cs-paillier.mjs';
import {TOY_DISAVOW_GROUP,diagnoseToyDisavowal} from '../research/disavow-branches.mjs';
const {n}=toyParameters,M=n*n;
const {prime,order,generator}=TOY_DISAVOW_GROUP;
function make(){
 const x1=7n,x2=11n,x3=13n,g=modPow(2n,2n*n,M),r=7n,t=3n,label='fictional/receipt/author/carol';
 const pub={n,g,h:n+1n,y1:modPow(g,x1,M),y2:modPow(g,x2,M),y3:modPow(g,x3,M)};
 const priv={n,x1,x2,x3};
 const cipher=encrypt(pub,r,label,{t});
 const claim=modPow(generator,r%order,prime);
 return {publicKey:pub,privateKey:priv,ciphertext:cipher,label,claim,r,t};
}
test('positive control: valid toy labeled ciphertext matches a Γ claim',()=>{
 const d=diagnoseToyDisavowal(make());
 assert.equal(d.branch,'MATCH');
 assert.equal(d.measurements.r,'7');
 assert.match(d.security,/NOT A DISAVOWAL PROOF/);
});
test('case 1: tampered tag fails power-2n condition',()=>{
 const s=make();
 const bad={...s.ciphertext,v:absResidue(s.ciphertext.v*2n%M,M)};
 const d=diagnoseToyDisavowal({...s,ciphertext:bad});
 assert.equal(d.branch,'CASE_1_TAG_ORDER');
});
test('case 2: n-torsion tag change passes 2n check but fails square check',()=>{
 const s=make();
 const bad={...s.ciphertext,v:absResidue(s.ciphertext.v*(1n+n)%M,M)};
 const d=diagnoseToyDisavowal({...s,ciphertext:bad});
 assert.equal(d.branch,'CASE_2_TAG_SQUARE');
 assert.equal(d.measurements.tagPowerN,true);
});
test('case 3: genuine u/tag algebra can accompany e outside h plaintext representation',()=>{
 const s=make();
 const e=s.ciphertext.e*2n%M;
 const H=challenge(s.ciphertext.u,e,s.label,n);
 const v=absResidue(modPow(s.publicKey.y2*modPow(s.publicKey.y3,H,M)%M,s.t,M),M);
 const d=diagnoseToyDisavowal({...s,ciphertext:{...s.ciphertext,e,v}});
 assert.equal(d.branch,'CASE_3_PLAINTEXT_GROUP');
 assert.equal(d.measurements.hMembership,false);
});
test('case 4: valid ciphertext but false claimed group element is a distinct relation',()=>{
 const s=make();const bad=modPow(generator,(s.r+1n)%order,prime);
 const d=diagnoseToyDisavowal({...s,claim:bad});
 assert.equal(d.branch,'CASE_4_GROUP_MISMATCH');
 assert.equal(d.measurements.expected,s.claim.toString());
});
test('malformed or noncanonical ciphertext is preflight REJECT_INPUT, not disavowal',()=>{
 const s=make();
 for(const ciphertext of [null,{...s.ciphertext,u:0n},{...s.ciphertext,v:M-s.ciphertext.v},{...s.ciphertext,e:'1'}]){
  assert.equal(diagnoseToyDisavowal({...s,ciphertext}).branch,'REJECT_INPUT');
 }
});
test('wrong or malformed subgroup claim is REJECT_INPUT',()=>{
 const s=make();
 for(const claim of [0n,prime,5n,undefined]){
  assert.equal(diagnoseToyDisavowal({...s,claim}).branch,'REJECT_INPUT');
 }
});
test('bad key, empty label and wrong modulus cannot become an invalidity proof',()=>{
 const s=make();
 assert.equal(diagnoseToyDisavowal({...s,publicKey:{...s.publicKey,y1:1n}}).branch,'REJECT_INPUT');
 assert.equal(diagnoseToyDisavowal({...s,label:''}).branch,'REJECT_INPUT');
 assert.equal(diagnoseToyDisavowal({...s,privateKey:{...s.privateKey,n:257n}}).branch,'REJECT_INPUT');
});
test('verified tag and claim do not establish public proof or zero-knowledge by themselves',()=>{
 const s=make();const d=diagnoseToyDisavowal(s);
 assert.equal(d.branch,'MATCH');
 assert.equal(d.measurements.r,'7');
 assert.match(d.security,/RESEARCH PREDICATE ONLY/);
});
test('branch diagnostics only report a failed local predicate, not an interactive disavowal proof',()=>{
 const s=make();const d=diagnoseToyDisavowal({...s,claim:modPow(generator,s.r+1n,prime)});
 assert.equal(d.branch,'CASE_4_GROUP_MISMATCH');
 assert.ok(!Object.hasOwn(d,'proof'));
 assert.ok(!Object.hasOwn(d,'transcript'));
});
