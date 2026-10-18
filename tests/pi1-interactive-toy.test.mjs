import test from 'node:test';
import assert from 'node:assert/strict';
import {toyParameters,modPow,encrypt} from '../research/cs-paillier.mjs';
import {TOY_GROUP,TOY_CRS,commitToy,proofAuxiliaryToy} from '../research/pi1-relation.mjs';
import {TOY_PI1_LIMITS,beginToyPi1,sampleToyPi1Challenge,answerToyPi1,checkToyPi1Transcript} from '../research/pi1-interactive-toy.mjs';
const n=toyParameters.n,M=n*n;
const masks=Object.freeze({x1:101n,x2:-88n,x3:53n,r:250n,s:-71n});
function fixture(){
  const g=modPow(2n,2n*n,M),x1=7n,x2=11n,x3=13n;
  const publicKey={n,g,h:n+1n,y1:modPow(g,x1,M),y2:modPow(g,x2,M),y3:modPow(g,x3,M)};
  const privateKey={n,x1,x2,x3};
  const opening=7n,message=4n,s=19n,label='2013-thesis/pi1/toy/signer';
  const ciphertext=encrypt(publicKey,opening,label,{t:3n});
  const psi=commitToy(message,opening),ell=proofAuxiliaryToy(opening,s);
  return {publicStatement:{publicKey,ciphertext,label,message,psi,ell},privateWitness:{privateKey,opening,s}};
}
function transcript(c=2n,init=fixture(),selectedMasks=masks){
  const {publicStatement,privateWitness}=init;
  const {commitment,proverState}=beginToyPi1(publicStatement,privateWitness,{masks:selectedMasks});
  const response=answerToyPi1(proverState,c);
  return {publicStatement,commitment,response,c,proverState};
}
const check=t=>checkToyPi1Transcript(t.publicStatement,t.commitment,t.c,t.response);
test('toy challenge is two bits and cannot provide production soundness',()=>{
  assert.equal(TOY_PI1_LIMITS.challengeBits,2);
  assert.equal(TOY_PI1_LIMITS.challengeCount,4n);
  assert.match(TOY_PI1_LIMITS.security,/NOT DCS/);
});
test('prover creates seven first-message values, then waits for verifier challenge',()=>{
  const t=transcript();
  assert.deepEqual(Object.keys(t.commitment).sort(),['y1Prime','y2Prime','y3Prime','ePrime','vPrime','alphaPrime','ellPrime'].sort());
  assert.ok(Object.keys(t.response).every(x=>typeof t.response[x]==='bigint'));
  assert.equal(t.proverState.phase,'awaiting-verifier-challenge');
  assert.equal(Object.hasOwn(t.commitment,'privateKey'),false);
  assert.equal(Object.hasOwn(t.response,'privateKey'),false);
});
test('independent public-only verifier checks all seven published algebraic equations',()=>{
  const t=transcript();
  const v=check(t);
  assert.equal(v.equationsHold,true);
  assert.deepEqual(Object.keys(v.checks).sort(),['key1','key2','key3','ciphertextE','ciphertextV','commitmentOpening','auxiliary'].sort());
  assert.ok(Object.values(v.checks).every(Boolean));
  assert.match(v.security,/NOT SOUND/);
});
test('honest challenge 0, 1, 2 and 3 all produce valid algebraic transcripts',()=>{
  for(let c=0n;c<4n;c++){
    const t=transcript(c);
    assert.equal(check(t).equationsHold,true,'c='+c);
  }
});
test('fresh verifier challenges and random prover masks can both be exercised',()=>{
  for(let i=0;i<24;i++){
    const s=fixture();
    const {commitment,proverState}=beginToyPi1(s.publicStatement,s.privateWitness);
    const c=sampleToyPi1Challenge();
    assert.ok(c>=0n&&c<4n);
    const response=answerToyPi1(proverState,c);
    assert.equal(checkToyPi1Transcript(s.publicStatement,commitment,c,response).equationsHold,true);
  }
});
test('changing the challenge after prover response rejects the mathematical proof',()=>{
  const t=transcript(2n);
  assert.equal(checkToyPi1Transcript(t.publicStatement,t.commitment,3n,t.response).equationsHold,false);
});
test('wrong key exponents in the public statement break at least one key equation',()=>{
  const t=transcript();
  const bad={...t.publicStatement,publicKey:{...t.publicStatement.publicKey,y1:t.publicStatement.publicKey.y1*2n%M}};
  const v=checkToyPi1Transcript(bad,t.commitment,t.c,t.response);
  assert.equal(v.equationsHold,false);
});
test('altering any challenge response is detected by independent public equations',()=>{
  for(const k of ['x1','x2','x3','r','s']){
    const t=transcript();
    const a={...t.response,[k]:t.response[k]+1n};
    assert.equal(checkToyPi1Transcript(t.publicStatement,t.commitment,t.c,a).equationsHold,false,k);
  }
});
test('altering any first-message algebraic commitment fails a true challenge',()=>{
  const t=transcript();
  const limits={y1Prime:M,y2Prime:M,y3Prime:M,ePrime:M,vPrime:M,alphaPrime:TOY_GROUP.prime,ellPrime:TOY_CRS.modulus};
  for(const k of Object.keys(t.commitment)){
    const changed={...t.commitment,[k]:t.commitment[k]*2n%limits[k]};
    assert.equal(checkToyPi1Transcript(t.publicStatement,changed,t.c,t.response).equationsHold,false,k);
  }
});
test('changed message or claimed signed commitment cannot reuse a valid transcript',()=>{
  const t=transcript();
  for(const broken of [
    {...t.publicStatement,message:t.publicStatement.message+1n},
    {...t.publicStatement,psi:t.publicStatement.psi*TOY_GROUP.delta%TOY_GROUP.prime}
  ])assert.equal(checkToyPi1Transcript(broken,t.commitment,t.c,t.response).equationsHold,false);
});
test('changed encrypted plaintext, ciphertext tag, label or CRS proof commitment fails',()=>{
  const t=transcript();
  const z=t.publicStatement.ciphertext;
  const alternatives=[
    {...t.publicStatement,ciphertext:{...z,e:z.e*(n+1n)%M}},
    {...t.publicStatement,ciphertext:{...z,v:z.v*(n+1n)%M}},
    {...t.publicStatement,label:'wrong-ciphertext-label'},
    {...t.publicStatement,ell:t.publicStatement.ell*TOY_CRS.g2%TOY_CRS.modulus}
  ];
  for(const s of alternatives)assert.equal(checkToyPi1Transcript(s,t.commitment,t.c,t.response).equationsHold,false);
});
test('out-of-range or mistyped challenges and responses always fail closed',()=>{
  const t=transcript();
  for(const c of [-1n,4n,2,'2',null])assert.equal(checkToyPi1Transcript(t.publicStatement,t.commitment,c,t.response).equationsHold,false);
  for(const [k,v] of [['r',1n<<100n],['s',null],['x1','4']]){
    assert.equal(checkToyPi1Transcript(t.publicStatement,t.commitment,t.c,{...t.response,[k]:v}).equationsHold,false);
  }
  assert.throws(()=>answerToyPi1(t.proverState,4n),/outside/);
  assert.throws(()=>answerToyPi1({},1n),/state/);
});
test('prover refuses a wrong or incomplete witness instead of emitting a proof',()=>{
  const f=fixture();
  for(const bad of [
    {...f.privateWitness,opening:8n},
    {...f.privateWitness,privateKey:{...f.privateWitness.privateKey,x2:17n}},
    {...f.privateWitness,s:20n}
  ])assert.throws(()=>beginToyPi1(f.publicStatement,bad,{masks}),/consistent toy witness/);
});
test('negative claim: a zero challenge cannot bind the message commitment',()=>{
  const t=transcript(0n);
  const changed={...t.publicStatement,psi:t.publicStatement.psi*TOY_GROUP.delta%TOY_GROUP.prime};
  // Algebraic verification (not DCS validity) can still pass when c=0.
  assert.equal(checkToyPi1Transcript(changed,t.commitment,t.c,t.response).equationsHold,true);
});
test('negative claim: repeated public transcripts are not inherently replay protected',()=>{
  const t=transcript(2n);
  assert.equal(check(t).equationsHold,true);
  assert.equal(check(t).equationsHold,true);
  assert.match(TOY_PI1_LIMITS.security,/NOT DCS/);
});
