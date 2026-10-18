import test from 'node:test';
import assert from 'node:assert/strict';
import {toyParameters,modPow,encrypt} from '../research/cs-paillier.mjs';
import {TOY_GROUP,commitToy,proofAuxiliaryToy} from '../research/pi1-relation.mjs';
import {beginToyPi1,answerToyPi1,checkToyPi1Transcript} from '../research/pi1-interactive-toy.mjs';
import {extractToyPi1Fork} from '../research/pi1-special-soundness.mjs';

const n=toyParameters.n,M=n*n;
const fixedMasks={x1:101n,x2:-88n,x3:53n,r:250n,s:-71n};
function fixture(){
 const g=modPow(2n,2n*n,M),x1=7n,x2=11n,x3=13n;
 const publicKey={n,g,h:n+1n,y1:modPow(g,x1,M),y2:modPow(g,x2,M),y3:modPow(g,x3,M)};
 const privateKey={n,x1,x2,x3};
 const opening=7n,message=4n,s=19n,label='fictional-2013-thesis-pi1';
 const ciphertext=encrypt(publicKey,opening,label,{t:3n});
 return {
   statement:{publicKey,ciphertext,label,message,psi:commitToy(message,opening),ell:proofAuxiliaryToy(opening,s)},
   witness:{privateKey,opening,s}
 };
}
function fork(cA=1n,cB=3n,masks=fixedMasks){
 const f=fixture();
 const {commitment,proverState}=beginToyPi1(f.statement,f.witness,{masks});
 return {
   statement:f.statement,firstMessage:commitment,
   first:{challenge:cA,response:answerToyPi1(proverState,cA)},
   second:{challenge:cB,response:answerToyPi1(proverState,cB)}
 };
}
test('two valid distinct-challenge transcripts reveal all five integer witnesses',()=>{
 const f=fork();
 assert.equal(checkToyPi1Transcript(f.statement,f.firstMessage,f.first.challenge,f.first.response).equationsHold,true);
 assert.equal(checkToyPi1Transcript(f.statement,f.firstMessage,f.second.challenge,f.second.response).equationsHold,true);
 const extracted=extractToyPi1Fork(f);
 assert.equal(extracted.algebraicWitnessRecovered,true);
 assert.deepEqual(extracted.recovered,{x1:7n,x2:11n,x3:13n,opening:7n,s:19n});
 assert.match(extracted.security,/NOT A DESIGNATED CONFIRMER/);
});
test('all six pairs of different toy verifier challenges permit exactly recovered witnesses',()=>{
 for(let a=0n;a<4n;a++)for(let b=a+1n;b<4n;b++){
  const x=extractToyPi1Fork(fork(a,b));
  assert.equal(x.recovered.x1,7n);
  assert.equal(x.recovered.opening,7n);
  assert.equal(x.recovered.s,19n);
 }
});
test('identical challenges give no extraction, even with two verified transcripts',()=>{
 const f=fork(2n,2n);
 assert.equal(checkToyPi1Transcript(f.statement,f.firstMessage,2n,f.first.response).equationsHold,true);
 assert.equal(checkToyPi1Transcript(f.statement,f.firstMessage,2n,f.second.response).equationsHold,true);
 assert.throws(()=>extractToyPi1Fork(f),/distinct well-formed challenges/);
});
test('tampering with a branch response causes independent public verification rejection',()=>{
 for(const field of ['x1','x2','x3','r','s']){
  const f=fork();
  const bad={...f,second:{...f.second,response:{...f.second.response,[field]:f.second.response[field]+1n}}};
  assert.throws(()=>extractToyPi1Fork(bad),/fails the independent public-only equations/);
 }
});
test('transcripts with FRESH independent masks cannot be combined against one first commitment',()=>{
 const f=fork();
 const other=fixture();
 const fresh=beginToyPi1(other.statement,other.witness,{masks:{...fixedMasks,x1:fixedMasks.x1+1n}});
 const bad={...f,second:{challenge:3n,response:answerToyPi1(fresh.proverState,3n)}};
 assert.equal(checkToyPi1Transcript(bad.statement,bad.firstMessage,3n,bad.second.response).equationsHold,false);
 assert.throws(()=>extractToyPi1Fork(bad),/public-only equations/);
});
test('changing the public message or commitment invalidates at least one branch',()=>{
 const f=fork();
 const modified=[{...f.statement,message:f.statement.message+1n},
   {...f.statement,psi:f.statement.psi*TOY_GROUP.delta%TOY_GROUP.prime}];
 for(const statement of modified)assert.throws(()=>extractToyPi1Fork({...f,statement}),/public-only equations/);
});
test('a changed ciphertext label, tag or public encryption key breaks a transcript',()=>{
 const f=fork();
 const bads=[
  {...f.statement,label:'altered'},
  {...f.statement,ciphertext:{...f.statement.ciphertext,e:f.statement.ciphertext.e*(n+1n)%M}},
  {...f.statement,publicKey:{...f.statement.publicKey,y2:f.statement.publicKey.y2*2n%M}}
 ];
 for(const statement of bads)assert.throws(()=>extractToyPi1Fork({...f,statement}),/public-only equations/);
});
test('malformed, non-bigint, out-of-range or missing challenge branches cannot claim recovery',()=>{
 const f=fork();
 for(const second of [
   null,{...f.second,challenge:-1n},{...f.second,challenge:4n},
   {...f.second,challenge:3},{...f.second,response:null},
   {...f.second,response:{...f.second.response,s:'19'}}
 ]) assert.throws(()=>extractToyPi1Fork({...f,second}),/RESEARCH FORK REJECTED/);
});
test('zero-challenge equation acceptance is not sufficient for a genuine validity claim',()=>{
 const f=fork(0n,1n);
 assert.equal(checkToyPi1Transcript(f.statement,f.firstMessage,0n,f.first.response).equationsHold,true);
 const changed={...f.statement,psi:f.statement.psi*TOY_GROUP.delta%TOY_GROUP.prime};
 assert.equal(checkToyPi1Transcript(changed,f.firstMessage,0n,f.first.response).equationsHold,true);
 assert.throws(()=>extractToyPi1Fork({...f,statement:changed}),/public-only equations/);
});
test('scope contract: the extractor does not claim production security or proof of disavowal',()=>{
 const f=fork();
 const result=extractToyPi1Fork(f);
 assert.ok(!Object.hasOwn(result,'dcsConfirmed'));
 assert.ok(!Object.hasOwn(result,'disavowed'));
 assert.ok(!Object.hasOwn(result,'nonTransferable'));
});
