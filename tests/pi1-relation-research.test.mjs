import test from 'node:test';
import assert from 'node:assert/strict';
import {toyParameters,modPow,encrypt} from '../research/cs-paillier.mjs';
import {TOY_GROUP,TOY_CRS,commitToy,proofAuxiliaryToy,inspectPi1Witness} from '../research/pi1-relation.mjs';
const n=toyParameters.n,m=n*n;
function fixture(){
 const g=modPow(2n,2n*n,m),x1=7n,x2=11n,x3=13n;
 const publicKey={n,g,h:n+1n,y1:modPow(g,x1,m),y2:modPow(g,x2,m),y3:modPow(g,x3,m)};
 const privateKey={n,x1,x2,x3};
 const opening=7n, message=4n,s=19n,label='toy-pi1|fictional|alice';
 const ciphertext=encrypt(publicKey,opening,label,{t:3n});
 const psi=commitToy(message,opening),ell=proofAuxiliaryToy(opening,s);
 return {publicKey,privateKey,ciphertext,label,message,psi,opening,s,ell};
}
test('full eight-part witness preflight succeeds on a real toy ciphertext',()=>{
 const f=inspectPi1Witness(fixture());
 assert.equal(f.relationSatisfied,true);
 assert.deepEqual(Object.keys(f.checks).sort(),['key1','key2','key3','ciphertextE','ciphertextV','commitmentOpening','auxiliary','decryptMatchesOpening'].sort());
 assert.ok(Object.values(f.checks).every(Boolean));
});
test('preflight exposes key consistency separately from ciphertext correctness',()=>{
 const f=fixture();const a=inspectPi1Witness({...f,privateKey:{...f.privateKey,x1:8n}});
 assert.equal(a.relationSatisfied,false);
 assert.equal(a.checks.key1,false);
 assert.equal(a.checks.commitmentOpening,true);
});
test('changed opening fails the ciphertext and commitment relations',()=>{
 const f=fixture(),x=inspectPi1Witness({...f,opening:f.opening+1n});
 assert.equal(x.relationSatisfied,false);
 assert.equal(x.checks.commitmentOpening,false);
 assert.equal(x.checks.ciphertextE,false);
});
test('changed message cannot reuse old commitment without failure',()=>{
 const f=fixture(),x=inspectPi1Witness({...f,message:5n});
 assert.equal(x.relationSatisfied,false);
 assert.equal(x.checks.commitmentOpening,false);
});
test('changing ciphertext e must fail independently of the key equations',()=>{
 const f=fixture(),x=inspectPi1Witness({...f,ciphertext:{...f.ciphertext,e:f.ciphertext.e*(n+1n)%m}});
 assert.equal(x.relationSatisfied,false);
 assert.equal(x.checks.key1,true);
 assert.equal(x.checks.decryptMatchesOpening,false);
});
test('wrong encryption label cannot be counted as confirmed',()=>{
 const f=fixture(),x=inspectPi1Witness({...f,label:'wrong-label'});
 assert.equal(x.relationSatisfied,false);
 assert.equal(x.checks.decryptMatchesOpening,false);
});
test('altering v or ψ independently leaves a named failed equation',()=>{
 const f=fixture();
 const x=inspectPi1Witness({...f,ciphertext:{...f.ciphertext,v:1n}});
 assert.equal(x.relationSatisfied,false);
 assert.equal(x.checks.ciphertextV,false);
 const y=inspectPi1Witness({...f,psi:f.psi*TOY_GROUP.delta%TOY_GROUP.prime});
 assert.equal(y.relationSatisfied,false);
 assert.equal(y.checks.commitmentOpening,false);
});
test('altered auxiliary l or s is checked separately',()=>{
 const f=fixture(),x=inspectPi1Witness({...f,ell:2n}),y=inspectPi1Witness({...f,s:f.s+1n});
 assert.equal(x.relationSatisfied,false);assert.equal(x.checks.auxiliary,false);
 assert.equal(y.relationSatisfied,false);assert.equal(y.checks.auxiliary,false);
});
test('invalid statement, missing ciphertext and out-of-range witness fail closed',()=>{
 const f=fixture();for(const broken of [{...f,message:-1n},{...f,psi:0n},{...f,ciphertext:null},{...f,opening:99n},{...f,s:TOY_CRS.modulus}]){
  assert.equal(inspectPi1Witness(broken).relationSatisfied,false);
 }
 assert.throws(()=>commitToy(4n,11n),/opening/);
});
