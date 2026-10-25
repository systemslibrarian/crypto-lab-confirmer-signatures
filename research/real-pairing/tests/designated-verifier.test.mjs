import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, webcrypto } from 'node:crypto';
import { bls12_381 as bls } from '@noble/curves/bls12-381.js';
import { issue, Q, G1, G2, GT, SCHEME, publicStatement, pointTimes, gtPow, gtMul, gtDiv, gtEq } from '../core.mjs';
import { targetCoefficients } from '../transcript.mjs';
import {
 DV_MODEL, DV_SCOPE, createVerifierKey, verifyVerifierKey, designatedBranch, isBranchWitness,
 proveWithWitness, proveWithVerifierSecret, verifyDesignatedProof, simulatorRandomnessOfProof,
 provePublicTransferable, verifyPublicTransferable, observerView, publicProofFields,
} from '../designated-verifier.mjs';
if (!globalThis.crypto) globalThis.crypto = webcrypto;

const CONTEXT = 'ad09-unit-context';
const issued = await issue({ message: 'The manuscript stays in the archive.' });
const altered = { ...issued.publicData, message: 'The manuscript leaves the archive.' };
const statement = await publicStatement(issued.publicData);
const bob = await createVerifierKey();
const cindy = await createVerifierKey();
const witnessOf = (role) => (role === 'confirmer' ? issued.privateKeys.xc : issued.privateKeys.xs);

// ---------------------------------------------------------------------------
// An independent recomputation of the verification equations. It reimplements
// the length-prefixed challenge encoding with node:crypto's synchronous SHA-256
// and drives the curve through @noble's own API rather than this lab's helper
// layer, so a wrong helper cannot validate itself.
// ---------------------------------------------------------------------------

function independentChallenge(domain, parts) {
 const bytes = [];
 const push = (value) => {
  const b = typeof value === 'string' ? new TextEncoder().encode(value) : value;
  bytes.push((b.length >> 8) & 255, b.length & 255, ...b);
 };
 push(SCHEME);
 push(domain);
 for (const part of parts) push(part);
 return BigInt('0x' + createHash('sha256').update(Buffer.from(bytes)).digest('hex')) % Q;
}

const independentTargetString = (value) => targetCoefficients(value).join(':');

/** Mirror of the module's canonical point encoding, written out independently. */
const G1_INF = Uint8Array.from({ length: 48 }, (_, i) => (i === 0 ? 0xc0 : 0));
const G2_INF = Uint8Array.from({ length: 96 }, (_, i) => (i === 0 ? 0xc0 : 0));
const independentPointBytes = (point) =>
 (point.is0() ? (point instanceof bls.G1.Point ? G1_INF : G2_INF) : point.toBytes());

/** Scalar multiplication that accepts zero, which noble's multiply() refuses. */
const mulPoint = (point, scalar) => {
 const k = ((scalar % Q) + Q) % Q;
 return k === 0n ? point.subtract(point) : point.multiply(k);
};

const independentBranchOf = (data, role) => (role === 'confirmer'
 ? { B: data.B1, C: data.C1, D: data.D1 }
 : { B: data.B2, C: data.C2, D: data.D2 });

/** Recompute both designated equations from scratch; returns the two booleans. */
function independentlyCheckDesignated({ role, proof, verifierKey, context = CONTEXT, data = statement }) {
 const branch = independentBranchOf(data, role);
 const c = mulPoint(bls.G1.Point.BASE, proof.w).add(mulPoint(verifierKey.y, proof.r));
 const h = independentChallenge('dv-designated-challenge-v1', [
  role, context, independentTargetString(data.A), independentTargetString(branch.B),
  independentPointBytes(branch.C), independentPointBytes(branch.D), independentPointBytes(verifierKey.y),
  independentPointBytes(c), independentPointBytes(proof.tSrc), independentTargetString(proof.tTgt),
 ]);
 const e = (h + proof.w) % Q;
 return {
  sourceEquation: mulPoint(branch.D, proof.d).equals(proof.tSrc.add(mulPoint(branch.C, e))),
  targetEquation: bls.fields.Fp12.eql(
   bls.fields.Fp12.pow(branch.B, proof.d),
   bls.fields.Fp12.mul(proof.tTgt, bls.fields.Fp12.pow(data.A, e)),
  ),
  challenge: e,
 };
}

test('the designated-verifier key carries an accepted proof of knowledge of its secret', async () => {
 assert.equal(await verifyVerifierKey(bob.publicKey), true);
 assert.equal(bob.publicKey.y.equals(G1.multiply(bob.secret)), true);
 assert.equal(await verifyVerifierKey({ ...bob.publicKey, response: (bob.publicKey.response + 1n) % Q }), false);
 assert.equal(await verifyVerifierKey({ ...bob.publicKey, y: cindy.publicKey.y }), false);
 assert.equal(await verifyVerifierKey({ ...bob.publicKey, y: G1.subtract(G1) }), false);
 assert.equal(await verifyVerifierKey(null), false);
 await assert.rejects(createVerifierKey({ secret: 0n }), /outside the nonzero scalar field/);
 await assert.rejects(createVerifierKey({ secret: Q }), /outside the nonzero scalar field/);
});

for (const role of ['confirmer', 'signer']) {
 test('both allowed origins produce proofs the same verifier accepts, for the ' + role + ' branch', async () => {
  const branch = designatedBranch(statement, role);
  assert.equal(isBranchWitness(statement, branch, witnessOf(role)), true);

  const fromWitness = await proveWithWitness({ publicData: issued.publicData, role, witness: witnessOf(role), verifierPublicKey: bob.publicKey, context: CONTEXT });
  const fromVerifier = await proveWithVerifierSecret({ publicData: issued.publicData, role, verifierSecret: bob.secret, verifierPublicKey: bob.publicKey, context: CONTEXT });

  for (const proof of [fromWitness, fromVerifier]) {
   const verdict = await verifyDesignatedProof({ publicData: issued.publicData, role, proof, verifierPublicKey: bob.publicKey, context: CONTEXT });
   assert.equal(verdict.accepted, true);
   assert.ok(Object.values(verdict.checks).every(Boolean));
   // Independent recomputation of both equations and of the challenge.
   const independent = independentlyCheckDesignated({ role, proof, verifierKey: bob.publicKey });
   assert.equal(independent.sourceEquation, true);
   assert.equal(independent.targetEquation, true);
   assert.equal(independent.challenge, verdict.challenge);
   // The proof carries the five public fields and no secret.
   assert.deepEqual(Object.keys(proof).sort(), ['d', 'r', 'tSrc', 'tTgt', 'w']);
   const wire = JSON.stringify(publicProofFields(proof));
   for (const secret of ['witness', 'secret', 'xc', 'xs', 'alpha', 'beta', 'verifierSecret']) assert.ok(!wire.includes('"' + secret + '"'));
  }
  // The two proofs are different objects: this is not one path calling the other.
  assert.notEqual(fromWitness.d, fromVerifier.d);
 });

 test('the two origins are exactly interchangeable on a true statement for the ' + role + ' branch', async () => {
  // The bijection (w,r,t) -> (d,alpha,beta). Feeding a real proof's derived
  // simulator randomness back through the simulator must reproduce that proof
  // byte for byte, and the converse must hold too. This is the exact
  // distribution invariant; no sample of transcripts is offered as a theorem.
  const real = await proveWithWitness({ publicData: issued.publicData, role, witness: witnessOf(role), verifierPublicKey: bob.publicKey, context: CONTEXT });
  const derived = await simulatorRandomnessOfProof({ publicData: issued.publicData, role, proof: real, verifierPublicKey: bob.publicKey, verifierSecret: bob.secret, context: CONTEXT });
  const rebuilt = await proveWithVerifierSecret({ publicData: issued.publicData, role, verifierSecret: bob.secret, verifierPublicKey: bob.publicKey, context: CONTEXT, randomness: derived });
  assert.deepEqual(publicProofFields(rebuilt), publicProofFields(real));

  const simulated = await proveWithVerifierSecret({ publicData: issued.publicData, role, verifierSecret: bob.secret, verifierPublicKey: bob.publicKey, context: CONTEXT });
  const back = await simulatorRandomnessOfProof({ publicData: issued.publicData, role, proof: simulated, verifierPublicKey: bob.publicKey, verifierSecret: bob.secret, context: CONTEXT });
  const reRun = await proveWithVerifierSecret({ publicData: issued.publicData, role, verifierSecret: bob.secret, verifierPublicKey: bob.publicKey, context: CONTEXT, randomness: back });
  assert.deepEqual(publicProofFields(reRun), publicProofFields(simulated));
 });
}

test('zero scalars and identity commitments are valid boundary values on both paths', async () => {
 const zero = await proveWithWitness({ publicData: issued.publicData, role: 'confirmer', witness: issued.privateKeys.xc, verifierPublicKey: bob.publicKey, context: CONTEXT, randomness: { w: 0n, r: 0n, t: 0n } });
 assert.equal(zero.tSrc.is0(), true);
 assert.equal(gtEq(zero.tTgt, GT.ONE), true);
 assert.equal((await verifyDesignatedProof({ publicData: issued.publicData, role: 'confirmer', proof: zero, verifierPublicKey: bob.publicKey, context: CONTEXT })).accepted, true);
 const zeroSim = await proveWithVerifierSecret({ publicData: issued.publicData, role: 'confirmer', verifierSecret: bob.secret, verifierPublicKey: bob.publicKey, context: CONTEXT, randomness: { d: 0n, alpha: 0n, beta: 0n } });
 assert.equal((await verifyDesignatedProof({ publicData: issued.publicData, role: 'confirmer', proof: zeroSim, verifierPublicKey: bob.publicKey, context: CONTEXT })).accepted, true);
});

test('an honest prover refuses a statement it cannot prove, while the designated verifier simulates it', async () => {
 for (const role of ['confirmer', 'signer']) {
  await assert.rejects(
   proveWithWitness({ publicData: altered, role, witness: witnessOf(role), verifierPublicKey: bob.publicKey, context: CONTEXT }),
   /No witness for this branch/,
  );
 }
 // This is the designation property, not a soundness failure: the designated
 // verifier can make an accepting proof of a false statement, so the transcript
 // alone establishes neither statement truth nor origin to an outside observer.
 const falseProof = await proveWithVerifierSecret({ publicData: altered, role: 'confirmer', verifierSecret: bob.secret, verifierPublicKey: bob.publicKey, context: CONTEXT });
 const verdict = await verifyDesignatedProof({ publicData: altered, role: 'confirmer', proof: falseProof, verifierPublicKey: bob.publicKey, context: CONTEXT });
 assert.equal(verdict.accepted, true);
 const independent = independentlyCheckDesignated({ role: 'confirmer', proof: falseProof, verifierKey: bob.publicKey, data: await publicStatement(altered) });
 assert.equal(independent.sourceEquation, true);
 assert.equal(independent.targetEquation, true);
});

test('a wrong statement witness cannot designate a proof', async () => {
 // The signer's key is not a witness for the confirmer branch, and vice versa.
 for (const [role, wrong] of [['confirmer', issued.privateKeys.xs], ['signer', issued.privateKeys.xc]]) {
  assert.equal(isBranchWitness(statement, designatedBranch(statement, role), wrong), false);
  await assert.rejects(
   proveWithWitness({ publicData: issued.publicData, role, witness: wrong, verifierPublicKey: bob.publicKey, context: CONTEXT }),
   /No witness for this branch/,
  );
 }
 for (const bad of [0n, Q, -1n, 7, '7', null]) {
  await assert.rejects(
   proveWithWitness({ publicData: issued.publicData, role: 'confirmer', witness: bad, verifierPublicKey: bob.publicKey, context: CONTEXT }),
   /No witness for this branch/,
  );
 }
});

test('only the holder of the designated verifier secret can take the second path', async () => {
 await assert.rejects(
  proveWithVerifierSecret({ publicData: issued.publicData, role: 'confirmer', verifierSecret: cindy.secret, verifierPublicKey: bob.publicKey, context: CONTEXT }),
  /does not open the designated verifier key/,
 );
 for (const bad of [0n, Q, -1n, 7, null]) {
  await assert.rejects(
   proveWithVerifierSecret({ publicData: issued.publicData, role: 'confirmer', verifierSecret: bad, verifierPublicKey: bob.publicKey, context: CONTEXT }),
   /does not open the designated verifier key/,
  );
 }
});

test('an unregistered verifier key is refused by both proving paths and by the verifier', async () => {
 // Section 7: a verifier who cannot prove knowledge of his secret cannot
 // simulate, so designation would be an empty claim.
 const unregistered = { ...bob.publicKey, response: (bob.publicKey.response + 1n) % Q };
 await assert.rejects(
  proveWithWitness({ publicData: issued.publicData, role: 'confirmer', witness: issued.privateKeys.xc, verifierPublicKey: unregistered, context: CONTEXT }),
  /Unregistered designated-verifier key/,
 );
 await assert.rejects(
  proveWithVerifierSecret({ publicData: issued.publicData, role: 'confirmer', verifierSecret: bob.secret, verifierPublicKey: unregistered, context: CONTEXT }),
  /Unregistered designated-verifier key/,
 );
 const proof = await proveWithWitness({ publicData: issued.publicData, role: 'confirmer', witness: issued.privateKeys.xc, verifierPublicKey: bob.publicKey, context: CONTEXT });
 const verdict = await verifyDesignatedProof({ publicData: issued.publicData, role: 'confirmer', proof, verifierPublicKey: unregistered, context: CONTEXT });
 assert.equal(verdict.accepted, false);
 assert.match(verdict.reason, /no accepted proof of knowledge/);
});

test('a designated proof does not replay across statements, roles or verifier keys', async () => {
 const proof = await proveWithWitness({ publicData: issued.publicData, role: 'confirmer', witness: issued.privateKeys.xc, verifierPublicKey: bob.publicKey, context: CONTEXT });
 const base = { proof, verifierPublicKey: bob.publicKey, context: CONTEXT };

 // Cross-statement: a different alleged message is a different statement.
 assert.equal((await verifyDesignatedProof({ ...base, publicData: altered, role: 'confirmer' })).accepted, false);
 // Cross-role: the same envelope, the other branch.
 assert.equal((await verifyDesignatedProof({ ...base, publicData: issued.publicData, role: 'signer' })).accepted, false);
 // Cross-verifier-key: the proof was designated to Bob, not Cindy.
 assert.equal((await verifyDesignatedProof({ publicData: issued.publicData, role: 'confirmer', proof, verifierPublicKey: cindy.publicKey, context: CONTEXT })).accepted, false);
 // A different issued envelope entirely.
 const other = await issue({ message: 'The manuscript stays in the archive.' });
 assert.equal((await verifyDesignatedProof({ ...base, publicData: other.publicData, role: 'confirmer' })).accepted, false);
});

test('the context string is bound: altering or omitting it rejects', async () => {
 const proof = await proveWithWitness({ publicData: issued.publicData, role: 'confirmer', witness: issued.privateKeys.xc, verifierPublicKey: bob.publicKey, context: CONTEXT });
 assert.equal((await verifyDesignatedProof({ publicData: issued.publicData, role: 'confirmer', proof, verifierPublicKey: bob.publicKey, context: CONTEXT + '-other' })).accepted, false);
 for (const bad of ['', null, undefined, 7, 'x'.repeat(201), 'has' + String.fromCharCode(0) + 'control']) {
  const verdict = await verifyDesignatedProof({ publicData: issued.publicData, role: 'confirmer', proof, verifierPublicKey: bob.publicKey, context: bad });
  assert.equal(verdict.accepted, false);
  assert.match(verdict.reason, /Statement unavailable|context/);
  await assert.rejects(proveWithWitness({ publicData: issued.publicData, role: 'confirmer', witness: issued.privateKeys.xc, verifierPublicKey: bob.publicKey, context: bad }), /context/);
 }
});

test('changing any single proof component is rejected', async () => {
 const proof = await proveWithWitness({ publicData: issued.publicData, role: 'confirmer', witness: issued.privateKeys.xc, verifierPublicKey: bob.publicKey, context: CONTEXT });
 const args = { publicData: issued.publicData, role: 'confirmer', verifierPublicKey: bob.publicKey, context: CONTEXT };
 for (const field of ['w', 'r', 'd']) {
  const mutated = { ...proof, [field]: (proof[field] + 1n) % Q };
  assert.equal((await verifyDesignatedProof({ ...args, proof: mutated })).accepted, false, field);
  const independent = independentlyCheckDesignated({ role: 'confirmer', proof: mutated, verifierKey: bob.publicKey });
  assert.equal(independent.sourceEquation && independent.targetEquation, false, field);
 }
 assert.equal((await verifyDesignatedProof({ ...args, proof: { ...proof, tSrc: proof.tSrc.add(G1) } })).accepted, false);
 assert.equal((await verifyDesignatedProof({ ...args, proof: { ...proof, tTgt: gtMul(proof.tTgt, gtPow(statement.B1, 2n)) } })).accepted, false);
});

test('the target-group equation is checked: a proof of only the key half is rejected', async () => {
 // Mutation testing found that no single-coordinate change isolates the target
 // equation, because the target commitment is itself hashed, so any edit to it
 // also moves the challenge and breaks the source equation. This fixture
 // separates the two halves of the statement instead.
 //
 // On an altered message the KEY relation C = D^x still holds, because the keys
 // did not change, while A != B^x. A prover that follows the honest algebra with
 // the real branch secret therefore satisfies the source equation exactly and
 // fails only in the target group. Nothing but the target check can catch it.
 const data = await publicStatement(altered);
 const branch = independentBranchOf(data, 'confirmer');
 const x = issued.privateKeys.xc;
 assert.equal(mulPoint(branch.D, x).equals(branch.C), true);
 assert.equal(bls.fields.Fp12.eql(data.A, bls.fields.Fp12.pow(branch.B, x)), false);

 const w = 11n; const r = 23n; const t = 37n;
 const c = mulPoint(bls.G1.Point.BASE, w).add(mulPoint(bob.publicKey.y, r));
 const tSrc = mulPoint(branch.D, t);
 const tTgt = bls.fields.Fp12.pow(branch.B, t);
 const h = independentChallenge('dv-designated-challenge-v1', [
  'confirmer', CONTEXT, independentTargetString(data.A), independentTargetString(branch.B),
  independentPointBytes(branch.C), independentPointBytes(branch.D), independentPointBytes(bob.publicKey.y),
  independentPointBytes(c), independentPointBytes(tSrc), independentTargetString(tTgt),
 ]);
 const e = (h + w) % Q;
 const proof = { w, r, tSrc, tTgt, d: (t + x * e) % Q };

 const independent = independentlyCheckDesignated({ role: 'confirmer', proof, verifierKey: bob.publicKey, data });
 assert.equal(independent.sourceEquation, true);
 assert.equal(independent.targetEquation, false);

 const verdict = await verifyDesignatedProof({ publicData: altered, role: 'confirmer', proof, verifierPublicKey: bob.publicKey, context: CONTEXT });
 assert.equal(verdict.accepted, false);
 assert.equal(verdict.checks.sourceEquation, true);
 assert.equal(verdict.checks.targetEquation, false);
});

test('malformed and noncanonical proof elements fail closed', async () => {
 const proof = await proveWithWitness({ publicData: issued.publicData, role: 'confirmer', witness: issued.privateKeys.xc, verifierPublicKey: bob.publicKey, context: CONTEXT });
 const args = { publicData: issued.publicData, role: 'confirmer', verifierPublicKey: bob.publicKey, context: CONTEXT };
 for (const bad of [undefined, null, {}, 'proof', 42]) {
  assert.equal((await verifyDesignatedProof({ ...args, proof: bad })).accepted, false);
 }
 for (const field of ['w', 'r', 'd']) {
  for (const bad of [Q, -1n, 7, '7', null, undefined]) {
   const verdict = await verifyDesignatedProof({ ...args, proof: { ...proof, [field]: bad } });
   assert.equal(verdict.accepted, false);
   assert.match(verdict.reason, /outside the scalar field|missing/);
  }
 }
 // Wrong group, non-subgroup and degenerate target values.
 assert.equal((await verifyDesignatedProof({ ...args, proof: { ...proof, tSrc: G2.multiply(3n) } })).accepted, false);
 for (const bad of [GT.ZERO, GT.neg(GT.ONE), null, 'target']) {
  assert.equal((await verifyDesignatedProof({ ...args, proof: { ...proof, tTgt: bad } })).accepted, false);
 }
 assert.equal((await verifyDesignatedProof({ ...args, publicData: { ...issued.publicData, signature: { ...issued.publicData.signature, t: (issued.publicData.signature.t + 1n) % Q } } })).accepted, false);
 assert.equal((await verifyDesignatedProof({ ...args, role: 'bystander' })).accepted, false);
});

test('the public proof equations verify, while the verifier secret is not a statement witness', async () => {
 for (const role of ['confirmer', 'signer']) {
  const pub = await provePublicTransferable({ publicData: issued.publicData, role, witness: witnessOf(role), context: CONTEXT });
  const verdict = await verifyPublicTransferable({ publicData: issued.publicData, role, proof: pub, context: CONTEXT });
  assert.equal(verdict.accepted, true);
  assert.equal(verdict.transferable, true);
  // Independent recomputation with the separate challenge domain.
  const branch = independentBranchOf(statement, role);
  const e = independentChallenge('dv-public-transferable-challenge-v1', [
   role, CONTEXT, independentTargetString(statement.A), independentTargetString(branch.B),
   independentPointBytes(branch.C), independentPointBytes(branch.D), independentPointBytes(pub.tSrc), independentTargetString(pub.tTgt),
  ]);
  assert.equal(e, verdict.challenge);
  assert.equal(mulPoint(branch.D, pub.d).equals(pub.tSrc.add(mulPoint(branch.C, e))), true);
  assert.equal(gtEq(gtPow(branch.B, pub.d), gtMul(pub.tTgt, gtPow(statement.A, e))), true);
  // The designated-verifier secret is not a witness for either branch, so this
  // honest-prover API refuses it. This is not a general unforgeability theorem.
  await assert.rejects(
   provePublicTransferable({ publicData: issued.publicData, role, witness: bob.secret, context: CONTEXT }),
   /No witness for this branch/,
  );
  await assert.rejects(
   provePublicTransferable({ publicData: altered, role, witness: witnessOf(role), context: CONTEXT }),
   /No witness for this branch/,
  );
  // Cross-statement and component mutation reject here too.
  assert.equal((await verifyPublicTransferable({ publicData: altered, role, proof: pub, context: CONTEXT })).accepted, false);
  assert.equal((await verifyPublicTransferable({ publicData: issued.publicData, role, proof: { ...pub, d: (pub.d + 1n) % Q }, context: CONTEXT })).accepted, false);
  assert.equal((await verifyPublicTransferable({ publicData: issued.publicData, role, proof: pub, context: CONTEXT + '!' })).accepted, false);
 }
});

test('the designated and public verification boundaries do not overlap in either direction', async () => {
 const designated = await proveWithWitness({ publicData: issued.publicData, role: 'confirmer', witness: issued.privateKeys.xc, verifierPublicKey: bob.publicKey, context: CONTEXT });
 const pub = await provePublicTransferable({ publicData: issued.publicData, role: 'confirmer', witness: issued.privateKeys.xc, context: CONTEXT });
 // A designated proof read as a public proof: its challenge is blinded by w,
 // and the domains differ, so the public verifier rejects it.
 assert.equal((await verifyPublicTransferable({ publicData: issued.publicData, role: 'confirmer', proof: designated, context: CONTEXT })).accepted, false);
 // A public proof dressed up with w = r = 0 is still rejected by the designated verifier.
 assert.equal((await verifyDesignatedProof({ publicData: issued.publicData, role: 'confirmer', proof: { ...pub, w: 0n, r: 0n }, verifierPublicKey: bob.publicKey, context: CONTEXT })).accepted, false);
 assert.equal(Object.keys(publicProofFields(pub, { designated: false })).sort().join(','), 'd,tSrc,tTgt');
});

test('the external observer view is computed from public values alone', async () => {
 const fromWitness = await proveWithWitness({ publicData: issued.publicData, role: 'confirmer', witness: issued.privateKeys.xc, verifierPublicKey: bob.publicKey, context: CONTEXT });
 const fromVerifier = await proveWithVerifierSecret({ publicData: issued.publicData, role: 'confirmer', verifierSecret: bob.secret, verifierPublicKey: bob.publicKey, context: CONTEXT });
 for (const proof of [fromWitness, fromVerifier]) {
  const view = await observerView({ publicData: issued.publicData, role: 'confirmer', proof, verifierPublicKey: bob.publicKey, context: CONTEXT });
  assert.equal(view.equationsHold, true);
  assert.equal(view.originUndetermined, true);
  assert.equal(view.possibleOrigins.length, 2);
  assert.match(view.doesNotEstablish.join(' '), /Whether the statement is true/);
  assert.match(view.doesNotEstablish.join(' '), /Who produced the proof/);
  assert.match(view.strengthOfClaim, /Exact, conditioned on a true statement/);
  assert.equal(view.model, DV_MODEL);
  assert.equal(view.scope, DV_SCOPE);
  // Nothing secret may appear anywhere in the observer's serialized view.
  const serialized = JSON.stringify(view);
  for (const secret of [issued.privateKeys.xc.toString(16), issued.privateKeys.xs.toString(16), bob.secret.toString(16)]) {
   assert.ok(!serialized.includes(secret));
  }
 }
 // A rejected proof establishes nothing at all.
 const broken = { ...fromWitness, d: (fromWitness.d + 1n) % Q };
 const view = await observerView({ publicData: issued.publicData, role: 'confirmer', proof: broken, verifierPublicKey: bob.publicKey, context: CONTEXT });
 assert.equal(view.equationsHold, false);
 assert.equal(view.originUndetermined, false);
 assert.match(view.establishes[0], /^Nothing/);
});

test('the module states its model and refuses any strong-designated-verifier or signature claim', () => {
 assert.match(DV_MODEL, /Random-oracle model/);
 assert.match(DV_MODEL, /no ROM theorem/);
 assert.match(DV_SCOPE, /NOT a designated-verifier signature/);
 assert.match(DV_SCOPE, /NOT strong designated verifier/);
 assert.match(DV_SCOPE, /NOT a confirmer signature/);
 assert.match(DV_SCOPE, /NOT a publicly transferable proof/);
});
