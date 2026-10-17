import test from 'node:test';
import assert from 'node:assert/strict';
import {toyParameters,modPow,encrypt,decrypt} from '../research/cs-paillier.mjs';
import {DEMONSTRATION,powSigned,makePi0Subproof,verifyPi0Subproof,challengeFromWitnessCommitments} from '../research/pi0-equality.mjs';
const {n}=toyParameters,m=n*n;
// Fixed algebraic inputs make this a REPRODUCIBLE independent arithmetic fixture,
// not a published author KAT or a parameter set claiming 2013/2016 DCS security.
function pair(g0,x1,x2,x3){
  const g=modPow(g0,2n*n,m), h=n+1n;
  return {publicKey:{n,g,h,y1:modPow(g,x1,m),y2:modPow(g,x2,m),y3:modPow(g,x3,m)},privateKey:{n,x1,x2,x3}};
}
function setup(){
  const S=pair(2n,7n,11n,13n),C=pair(3n,17n,19n,23n);
  const r=37n,tS=3n,tC=5n,labelS='fictional:alice',labelC='fictional:carol';
  const cS=encrypt(S.publicKey,r,labelS,{t:tS}),cC=encrypt(C.publicKey,r,labelC,{t:tC});
  const witness={r,tS,tC,labelS,labelC};
  const masks={etaS:200n,etaC:-301n,omega:77n};
  const proof=makePi0Subproof(S.publicKey,C.publicKey,cS,cC,witness,{masks});
  return {S,C,cS,cC,witness,masks,proof};
}
test('research-only parameter bounds are explicit and unfit for DCS security',()=>{
 assert.equal(DEMONSTRATION.modulus,253n);
 assert.equal(DEMONSTRATION.challengeBits,24);
 assert.ok((1n<<24n)>11n); // 2013 §6.5.1 condition 2^k < p′ is violated.
});
test('source π0 equality-of-encrypted-opening relation passes for two independent keys',()=>{
 const {S,C,cS,cC,proof}=setup();
 assert.equal(verifyPi0Subproof(S.publicKey,C.publicKey,cS,cC,proof),true);
});
test('the independent arithmetic of responses reconstructs both witness commitments',()=>{
 const {S,C,cS,cC,witness:{r,tS,tC},masks:{etaS,etaC,omega},proof}=setup();
 // This test derives the two equations from scratch rather than calling verifier internals.
 const wp1=modPow(S.publicKey.y1,etaS,m)*powSigned(n+1n,omega,m)%m;
 const wp2=powSigned(C.publicKey.y1,etaC,m)*powSigned(n+1n,omega,m)%m;
 assert.equal(proof.D,omega+proof.c*r);
 assert.equal(proof.D1,etaS+proof.c*tS);
 assert.equal(proof.D2,etaC+proof.c*tC);
 const reconstructed1=(((powSigned(S.publicKey.y1,proof.D1,m)*powSigned(n+1n,proof.D,m))%m)*powSigned(cS.e,-proof.c,m))%m;
 const reconstructed2=(((powSigned(C.publicKey.y1,proof.D2,m)*powSigned(n+1n,proof.D,m))%m)*powSigned(cC.e,-proof.c,m))%m;
 assert.equal(reconstructed1,wp1);
 assert.equal(reconstructed2,wp2);
 assert.equal(proof.c,challengeFromWitnessCommitments(wp1,wp2));
});
test('both ciphertexts actually decrypt to the same toy opening',()=>{
 const {S,C,cS,cC,witness:{r,labelS,labelC}}=setup();
 assert.equal(decrypt(S.privateKey,S.publicKey,cS,labelS),r);
 assert.equal(decrypt(C.privateKey,C.publicKey,cC,labelC),r);
});
test('prover cannot create a valid honest proof with mismatched openings',()=>{
 const {S,C,cS,cC,witness,masks}=setup();
 const wrong=encrypt(C.publicKey,witness.r+1n,witness.labelC,{t:witness.tC});
 assert.throws(()=>makePi0Subproof(S.publicKey,C.publicKey,cS,wrong,witness,{masks}),/inconsistent/);
});
test('changing public-key relation fails the proof verification',()=>{
 const {S,C,cS,cC,proof}=setup();
 const impostor=pair(5n,1n,2n,3n);
 assert.equal(verifyPi0Subproof(S.publicKey,impostor.publicKey,cS,cC,proof),false);
});
test('challenge and response tampering are caught on the fixed fixture',()=>{
 const {S,C,cS,cC,proof}=setup();
 for(const fake of [{...proof,c:proof.c^1n},{...proof,D:proof.D+1n},{...proof,D1:proof.D1+1n},{...proof,D2:proof.D2+1n}]){
   assert.equal(verifyPi0Subproof(S.publicKey,C.publicKey,cS,cC,fake),false);
 }
});
test('ciphertext e modifications fail the equality statement',()=>{
 const {S,C,cS,cC,proof}=setup();
 assert.equal(verifyPi0Subproof(S.publicKey,C.publicKey,{...cS,e:(cS.e*(n+1n))%m},cC,proof),false);
 assert.equal(verifyPi0Subproof(S.publicKey,C.publicKey,cS,{...cC,e:(cC.e*(n+1n))%m},proof),false);
});
test('malformed keys, proof values and ciphertext encodings fail closed',()=>{
 const {S,C,cS,cC,proof}=setup();
 for(const invalid of [null,{}, {...proof,c:-1n},{...proof,c:1n<<24n},{...proof,D:'1'},{...proof,D1:10n**10000n}]){
   assert.equal(verifyPi0Subproof(S.publicKey,C.publicKey,cS,cC,invalid),false);
 }
 assert.equal(verifyPi0Subproof({...S.publicKey,n:251n},C.publicKey,cS,cC,proof),false);
 assert.equal(verifyPi0Subproof(S.publicKey,C.publicKey,{...cS,u:0n},cC,proof),false);
 assert.equal(verifyPi0Subproof(S.publicKey,C.publicKey,cS,{...cC,v:0n},proof),false);
});
test('negative control: π0 alone does not validate a message commitment ψ',()=>{
 const {S,C,cS,cC,proof}=setup();
 // A toy Pedersen opening uses group Z_23^* of order 11, with known log_g(h):
 // just an algebraic fixture. The same π0 verifies no matter which ψ is displayed.
 const delta=2n, gamma=modPow(delta,3n,23n),rho=11n;
 const commit=(msg,opening)=>modPow(delta,msg%rho,23n)*modPow(gamma,opening%rho,23n)%23n;
 const genuine=commit(1n,37n),falseCommit=commit(2n,37n);
 assert.notEqual(genuine,falseCommit);
 assert.equal(verifyPi0Subproof(S.publicKey,C.publicKey,cS,cC,proof),true);
 // No ψ is an argument to verifyPi0Subproof: changing it cannot invalidate proof.
 assert.equal(verifyPi0Subproof(S.publicKey,C.publicKey,cS,cC,proof),true);
});
test('negative control: π0 alone does not validate labels or the v integrity tag',()=>{
 const {S,C,cS,cC,proof}=setup();
 const incorrectV=(cS.v+1n)%m;
 assert.equal(verifyPi0Subproof(S.publicKey,C.publicKey,cS,cC,{...proof}),true);
 assert.equal(verifyPi0Subproof(S.publicKey,C.publicKey,{...cS,v:incorrectV},cC,proof),true);
 // That alone cannot certify the original label-specific ciphertext as well formed.
});
test('negative witness masks are supported, out of range masks fail closed',()=>{
 const {S,C,cS,cC,witness}=setup();
 const p=makePi0Subproof(S.publicKey,C.publicKey,cS,cC,witness,{masks:{etaS:-150n,etaC:201n,omega:-72n}});
 assert.equal(verifyPi0Subproof(S.publicKey,C.publicKey,cS,cC,p),true);
 assert.throws(()=>makePi0Subproof(S.publicKey,C.publicKey,cS,cC,witness,{masks:{etaS:10n**4000n,etaC:0n,omega:0n}}),/bounds/);
});
