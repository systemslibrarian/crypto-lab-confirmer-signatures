import test from 'node:test';
import assert from 'node:assert/strict';
import {toyParameters, createToyKeyPair,encrypt,decrypt,modPow,inv,challenge,absResidue} from '../research/cs-paillier.mjs';
const label='lesson-v1|fictional-document|alice|carol';
test('toy modulus is fixed, deliberately insecure and not large enough for production',()=>{
 assert.equal(toyParameters.n,253n);
 assert.equal(toyParameters.p*toyParameters.q,toyParameters.n);
});
test('modular inverses checked independently against multiplication',()=>{
 for(let x=1n;x<33n;x+=2n)if(x%11n!==0n&&x%23n!==0n){const i=inv(x,253n);assert.equal(x*i%253n,1n)}
 assert.throws(()=>inv(11n,253n),/Non-invertible/);
 assert.equal(modPow(3n,0n,253n),1n);
});
test('fixed-randomness encryption round trips across boundary plaintexts',()=>{
 for(const plaintext of [0n,1n,2n,17n,128n,252n]){
  const pair=createToyKeyPair();const c=encrypt(pair.publicKey,plaintext,label,{t:4n});
  assert.equal(decrypt(pair.privateKey,pair.publicKey,c,label),plaintext);
 }
});
test('independent ciphertext algebra matches source encryption identities',()=>{
 const pair=createToyKeyPair(),{n,g,h,y1,y2,y3}=pair.publicKey,m=n*n,r=29n,t=5n;
 const c=encrypt(pair.publicKey,r,label,{t});
 assert.equal(c.u,modPow(g,t,m));
 assert.equal(c.e,modPow(y1,t,m)*modPow(h,r,m)%m);
 assert.equal(c.v,absResidue(modPow(y2*modPow(y3,challenge(c.u,c.e,label,n),m)%m,t,m),m));
});
test('different encryption randomness produces distinct full ciphertexts',()=>{
 const pair=createToyKeyPair();const a=encrypt(pair.publicKey,12n,label,{t:1n}),b=encrypt(pair.publicKey,12n,label,{t:2n});
 assert.notDeepEqual(a,b);
 assert.equal(decrypt(pair.privateKey,pair.publicKey,a,label),12n);
 assert.equal(decrypt(pair.privateKey,pair.publicKey,b,label),12n);
});
test('wrong ciphertext component rejects rather than returning a false plaintext',()=>{
 const pair=createToyKeyPair(),c=encrypt(pair.publicKey,52n,label);
 for(const tweak of [{...c,e:0n},{...c,u:0n},{...c,v:0n},{...c,e:pair.publicKey.n**2n},{...c,v:pair.publicKey.n**2n}]){
  assert.throws(()=>decrypt(pair.privateKey,pair.publicKey,tweak,label),/REJECTED/);
 }
});
test('missing or malformed labels fail closed',()=>{
 const pair=createToyKeyPair(),c=encrypt(pair.publicKey,2n,label);
 assert.throws(()=>decrypt(pair.privateKey,pair.publicKey,c,''),/Expected short/);
 assert.throws(()=>encrypt(pair.publicKey,2n,''),/Expected short/);
 assert.throws(()=>encrypt(pair.publicKey,-1n,label),/outside/);
 assert.throws(()=>encrypt(pair.publicKey,253n,label),/outside/);
});
test('unit-domain, type and wrong private-key rejection',()=>{
 const pair=createToyKeyPair(),c=encrypt(pair.publicKey,23n,label);
 assert.throws(()=>decrypt(pair.privateKey,pair.publicKey,{u:'1',e:c.e,v:c.v},label),/REJECTED/);
 assert.throws(()=>decrypt({...pair.privateKey,n:253n}, {...pair.publicKey,n:254n},c,label),/mismatch/);
 // Cross-key rejection is overwhelmingly likely, but tiny toy groups can collide; never use this as a security KAT.
 assert.equal(decrypt(pair.privateKey,pair.publicKey,c,label),23n);
});