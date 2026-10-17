import test from 'node:test';
import assert from 'node:assert/strict';
import {webcrypto} from 'node:crypto';
import {createSigner, signStatement, verifyPublic, verifyPublishedRawP256, publicFingerprint, unhex, checkedMessage} from '../prototype/crypto.mjs';
if (!globalThis.crypto) globalThis.crypto = webcrypto;

// RFC 6979 Appendix A.2.5, NIST P-256, SHA-256, message "sample".
// This is a published verification KAT, NOT a claim of deterministic nonce generation by WebCrypto.
const Ux='60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6';
const Uy='7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299';
const r='EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716';
const s='F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8';
const pub=unhex('04'+Ux+Uy), sig=unhex(r+s), raw=new TextEncoder().encode('sample');

test('RFC 6979 published P-256/SHA-256 signature verifies (known-answer)',async()=>{
 assert.equal(await verifyPublishedRawP256(pub,sig,raw),true);
});
test('published signature rejected for altered message',async()=>{
 assert.equal(await verifyPublishedRawP256(pub,sig,new TextEncoder().encode('Sample')),false);
});
test('published signature rejected for modified signature',async()=>{
 const tampered=sig.slice();tampered[40]^=1;
 assert.equal(await verifyPublishedRawP256(pub,tampered,raw),false);
});
test('fresh nonextractable P-256 key signs; independent public-key import verifies',async()=>{
 const a=await createSigner();assert.equal(a.privateKey.extractable,false);
 assert.equal(a.publicSpki instanceof Uint8Array,true);
 const signed=await signStatement(a.privateKey,'Package delivered.');
 assert.equal(signed.length,64);
 assert.equal(await verifyPublic(a.publicSpki,signed,'Package delivered.'),true);
 assert.equal(await verifyPublic(a.publicSpki.slice(),signed.slice(),'Package delivered.'),true);
 assert.equal((await publicFingerprint(a.publicSpki)).length,64);
});
test('wrong statement fails and no temporary stale pass is possible',async()=>{
 const a=await createSigner();const signed=await signStatement(a.privateKey,'Package delivered.');
 assert.equal(await verifyPublic(a.publicSpki,signed,'Package withheld.'),false);
 assert.equal(await verifyPublic(a.publicSpki,signed,'Package delivered.'),true);
});
test('wrong signer public key cannot verify a valid signature',async()=>{
 const a=await createSigner();const b=await createSigner();const signed=await signStatement(a.privateKey,'Fictional agreement');
 assert.equal(await verifyPublic(b.publicSpki,signed,'Fictional agreement'),false);
});
test('modified signature cannot be verified',async()=>{
 const a=await createSigner();const signed=await signStatement(a.privateKey,'Fictional agreement');signed[5]^=1;
 assert.equal(await verifyPublic(a.publicSpki,signed,'Fictional agreement'),false);
});
test('invalid proof inputs fail closed without exceptions painted as success',async()=>{
 const a=await createSigner();const signed=await signStatement(a.privateKey,'Fictional agreement');
 await assert.rejects(verifyPublic(a.publicSpki,signed.slice(0,63),'Fictional agreement'),/64-byte/);
 await assert.rejects(verifyPublic(a.publicSpki,signed,''),/nonempty/);
 await assert.rejects(verifyPublic(new Uint8Array(0),signed,'Fictional agreement'),/Missing public/);
 await assert.rejects(verifyPublishedRawP256(pub,sig.slice(0,63),raw),/64-byte/);
 await assert.rejects(verifyPublishedRawP256(pub.slice(1),sig,raw),/65-byte/);
});
test('message input limits are strict, no canonicalization of signed bytes',()=>{
 assert.throws(()=>checkedMessage(''),/nonempty/);
 assert.throws(()=>checkedMessage('x'.repeat(2001)),/maximum/);
 assert.throws(()=>checkedMessage('Hello\u0000World'),/control/);
 assert.notDeepEqual(checkedMessage('package'),checkedMessage('Package'));
});
