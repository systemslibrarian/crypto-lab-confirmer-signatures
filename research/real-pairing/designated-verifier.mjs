/**
 * NON-INTERACTIVE DESIGNATED-VERIFIER PROOF — RESEARCH LESSON, NOT AUDITED.
 *
 * Primary source: Markus Jakobsson, Kazue Sako, Russell Impagliazzo,
 * "Designated Verifier Proofs and Their Applications", EUROCRYPT '96,
 * LNCS 1070, pp. 143-154 (doi:10.1007/3-540-68339-9_13). Read in the
 * published volume: Definition 1 (designated verifier) and Definition 2
 * (trap-door commitment) on pp. 147-148, the non-interactive construction,
 * its verification and its simulator on pp. 149-150, the requirement that
 * the designated verifier KNOW his secret key in section 7 (p. 151), and
 * Definition 3 (strong designated verifier) in the Appendix (p. 154).
 *
 * The paper's section 5 construction, printed for an undeniable signature
 * where y_A = g^{x_A} and s = m^{x_A} in one prime-order subgroup of Z_p*:
 *
 *   prove     c = g^w y_B^r,  G = g^t,  M = m^t,
 *             h = hash_q(c,G,M),  d = t + x_A (h + w) mod q,  send (w,r,G,M,d)
 *   verify    c = g^w y_B^r,  h = hash_q(c,G,M),
 *             G y_A^{h+w} = g^d   AND   M s^{h+w} = m^d
 *   simulate  d,alpha,beta random;  c = g^alpha,  G = g^d y_A^-beta,
 *             M = m^d s^-beta,  h = hash_q(c,G,M),
 *             w = beta - h,  r = (alpha - w) x_B^{-1}
 *
 * WHAT THIS FILE IS. The same construction, instantiated on THIS lab's
 * existing confirmation statement so the lesson sits beside the interactive
 * exchange rather than inventing a second toy. For a role j the statement is
 *
 *   Theta_j : exists x such that C_j = D_j^x  AND  A = B_j^x
 *
 * with A, B_j, C_j, D_j derived by core.mjs publicStatement() from the
 * format-checked envelope. g -> D_j, y_A -> C_j, m -> B_j, s -> A.
 *
 * DELIBERATE DEVIATIONS FROM THE PAPER, none of them silent:
 *  D1 groups. The paper uses one subgroup of Z_p*. Here the key equality is
 *     in G1 or G2 and the signature equality is in the order-q subgroup of
 *     Fp12; the exponent and the proof shape are unchanged, the statement's
 *     meaning is this lab's, not the paper's undeniable signature.
 *  D2 hash binding. The paper's printed input is hash_q(c,G,M). This binds a
 *     domain separator, the scheme, the role, a caller context, the whole
 *     derived statement, the verifier key, c and both commitments. The
 *     narrower printed input is NOT carried into shipped code.
 *  D3 key registration. A Schnorr proof of knowledge of x_B travels with y_B.
 *     Section 7 requires the knowledge; this protocol for it is ours.
 *  D4 Definition 1 only. Transcripts are not probabilistically encrypted to
 *     the verifier, so NO strong-designated-verifier property is claimed.
 *  D5 Section 6 (multiple designated verifiers) is not implemented.
 *  D6 No security theorem. The paper proves none for section 5 and neither do
 *     we. The identical-distribution statement below is exact algebra about
 *     this construction, NOT a security proof of the surrounding DCS, whose
 *     security this repository records as unestablished.
 *
 * A proof produced here is meaningful ONLY to the holder of x_B, and only
 * because that holder knows it did not make the proof itself. It establishes
 * nothing to anyone else. This is inspectable research code; it is not an
 * audited library and must not carry real signatures or documents.
 */
import {
 Q, G1, G2, SCOPE, mod, randomFieldScalar, randomScalar, invertNonzero,
 isTargetGroup, pointTimes, gtPow, gtMul, gtDiv, gtEq, hashScalar,
 publicStatement, verifyFormat
} from './core.mjs';
import { targetCoefficients } from './transcript.mjs';

export const DV_SOURCE =
 "Jakobsson, Sako, Impagliazzo, Designated Verifier Proofs and Their Applications, EUROCRYPT '96, LNCS 1070, pp. 143-154, section 5 (pp. 149-150)";
export const DV_MODEL =
 'Random-oracle model: the challenge is hash-derived. The paper gives no ROM theorem for its non-interactive scheme, and neither does this lab.';
export const DV_SCOPE =
 'DESIGNATED-VERIFIER PROOF (Definition 1), NOT a designated-verifier signature, NOT strong designated verifier, NOT a confirmer signature, NOT a publicly transferable proof. ' + SCOPE;

/** Separate hash domains keep a designated proof and a public proof from ever standing in for each other. */
const DV_CHALLENGE_DOMAIN = 'dv-designated-challenge-v1';
const PUBLIC_CHALLENGE_DOMAIN = 'dv-public-transferable-challenge-v1';
const DV_KEY_DOMAIN = 'dv-verifier-key-registration-v1';

const MAX_CONTEXT = 200;
const isControlCharacter = (codePoint) => codePoint < 0x20 || codePoint === 0x7f;

/** Canonical, reduced twelve-coefficient encoding of a target-group element for hashing. */
const targetBytes = (value) => targetCoefficients(value).join(':');

/**
 * Canonical point encoding for hashing, including the identity.
 *
 * Zero masks are legal protocol values here, exactly as they are elsewhere in
 * this lab, so a commitment may be the identity. Noble's toBytes() refuses the
 * identity through assertValidity(), which would leave those legal transcripts
 * unhashable; dropping zero from the sampler instead would silently narrow the
 * very distribution the designation argument rests on. The identity is encoded
 * as the standard compressed infinity octet string for its group.
 */
const G1_INFINITY = Uint8Array.from({ length: 48 }, (_, i) => (i === 0 ? 0xc0 : 0));
const G2_INFINITY = Uint8Array.from({ length: 96 }, (_, i) => (i === 0 ? 0xc0 : 0));
export function pointBytes(point) {
 if (!point.is0()) return point.toBytes();
 return point instanceof G1.constructor ? G1_INFINITY : G2_INFINITY;
}

/** @param {string} context */
function checkedContext(context) {
 if (typeof context !== 'string' || context.length === 0 || context.length > MAX_CONTEXT ||
     [...context].some((character) => isControlCharacter(character.codePointAt(0)))) {
  throw new TypeError('Proof context must be a short nonempty control-free string');
 }
 return context;
}

/** The role's branch of the lab's existing confirmation statement. */
export function designatedBranch(statement, role) {
 if (role === 'confirmer') return { index: 1, B: statement.B1, C: statement.C1, D: statement.D1, base: G1 };
 if (role === 'signer') return { index: 2, B: statement.B2, C: statement.C2, D: statement.D2, base: G2 };
 throw new RangeError('Select the signer or confirmer branch');
}

/** x is a witness for this branch exactly when both equalities hold. */
export function isBranchWitness(statement, branch, x) {
 return typeof x === 'bigint' && x > 0n && x < Q &&
   pointTimes(branch.D, x).equals(branch.C) && gtEq(statement.A, gtPow(branch.B, x));
}

function sourceValid(point, base, { nonidentity = false } = {}) {
 try {
  if (!(point instanceof base.constructor)) return false;
  if (point.is0()) return !nonidentity;
  point.assertValidity();
  return true;
 } catch { return false; }
}

const fieldScalar = (x) => typeof x === 'bigint' && x >= 0n && x < Q;

// ---------------------------------------------------------------------------
// The designated verifier's key. Section 7 requires that he KNOWS its secret:
// a verifier who cannot simulate cannot make the designation argument, so an
// unregistered key is refused rather than quietly accepted.
// ---------------------------------------------------------------------------

export async function createVerifierKey({ secret } = {}) {
 const x = secret ?? randomScalar();
 if (typeof x !== 'bigint' || x <= 0n || x >= Q) throw new RangeError('Verifier secret outside the nonzero scalar field');
 const y = G1.multiply(x);
 const k = randomScalar();
 const commitment = G1.multiply(k);
 const challenge = await hashScalar(DV_KEY_DOMAIN, y, commitment);
 const response = mod(k + challenge * x);
 return Object.freeze({
  publicKey: Object.freeze({ y, commitment, response }),
  secret: x,
  knowledgeProof: 'Schnorr proof of knowledge of the verifier secret; see deviation D3',
 });
}

export async function verifyVerifierKey(publicKey) {
 try {
  if (!publicKey || !sourceValid(publicKey.y, G1, { nonidentity: true }) ||
      !sourceValid(publicKey.commitment, G1) || !fieldScalar(publicKey.response)) return false;
  const challenge = await hashScalar(DV_KEY_DOMAIN, publicKey.y, publicKey.commitment);
  return pointTimes(G1, publicKey.response)
    .equals(publicKey.commitment.add(pointTimes(publicKey.y, challenge)));
 } catch { return false; }
}

// ---------------------------------------------------------------------------
// The challenge. Deviation D2: every statement, key, context and commitment
// component is bound, not only the paper's printed (c, G, M).
// ---------------------------------------------------------------------------

async function designatedChallenge({ role, context, statement, branch, verifierKey, c, tSrc, tTgt }) {
 return hashScalar(DV_CHALLENGE_DOMAIN, role, context,
  targetBytes(statement.A), targetBytes(branch.B), pointBytes(branch.C), pointBytes(branch.D),
  pointBytes(verifierKey.y), pointBytes(c), pointBytes(tSrc), targetBytes(tTgt));
}

async function publicChallenge({ role, context, statement, branch, tSrc, tTgt }) {
 return hashScalar(PUBLIC_CHALLENGE_DOMAIN, role, context,
  targetBytes(statement.A), targetBytes(branch.B), pointBytes(branch.C), pointBytes(branch.D),
  pointBytes(tSrc), targetBytes(tTgt));
}

async function openStatement(publicData, role) {
 if (!(await verifyFormat(publicData))) throw new Error('Invalid signed-ElGamal public envelope');
 const statement = await publicStatement(publicData);
 return { statement, branch: designatedBranch(statement, role) };
}

// ---------------------------------------------------------------------------
// Path 1 of 2: the real statement witness. Paper section 5, "Constructing a proof".
// ---------------------------------------------------------------------------

/**
 * @param {{publicData:object, role:string, witness:bigint, verifierPublicKey:object,
 *          context:string, randomness?:{w:bigint,r:bigint,t:bigint}}} input
 */
export async function proveWithWitness({ publicData, role, witness, verifierPublicKey, context, randomness } = {}) {
 const safeContext = checkedContext(context);
 const { statement, branch } = await openStatement(publicData, role);
 if (!(await verifyVerifierKey(verifierPublicKey))) {
  throw new Error('Unregistered designated-verifier key: section 7 requires a verifier who knows his secret');
 }
 if (!isBranchWitness(statement, branch, witness)) {
  throw new Error('No witness for this branch; an honest prover cannot designate a proof of a statement it cannot prove');
 }
 const w = randomness ? randomness.w : randomFieldScalar();
 const r = randomness ? randomness.r : randomFieldScalar();
 const t = randomness ? randomness.t : randomFieldScalar();
 for (const value of [w, r, t]) if (!fieldScalar(value)) throw new RangeError('Prover randomness outside the scalar field');
 const c = pointTimes(G1, w).add(pointTimes(verifierPublicKey.y, r));
 const tSrc = pointTimes(branch.D, t);
 const tTgt = gtPow(branch.B, t);
 const h = await designatedChallenge({ role, context: safeContext, statement, branch, verifierKey: verifierPublicKey, c, tSrc, tTgt });
 const d = mod(t + witness * mod(h + w));
 return Object.freeze({ w, r, tSrc, tTgt, d });
}

// ---------------------------------------------------------------------------
// Path 2 of 2: the designated verifier's own secret. Paper section 5,
// "Simulating transcripts". This path never receives the statement witness.
// ---------------------------------------------------------------------------

/**
 * @param {{publicData:object, role:string, verifierSecret:bigint, verifierPublicKey:object,
 *          context:string, randomness?:{d:bigint,alpha:bigint,beta:bigint}}} input
 */
export async function proveWithVerifierSecret({ publicData, role, verifierSecret, verifierPublicKey, context, randomness } = {}) {
 const safeContext = checkedContext(context);
 const { statement, branch } = await openStatement(publicData, role);
 if (!(await verifyVerifierKey(verifierPublicKey))) {
  throw new Error('Unregistered designated-verifier key: section 7 requires a verifier who knows his secret');
 }
 if (typeof verifierSecret !== 'bigint' || verifierSecret <= 0n || verifierSecret >= Q ||
     !G1.multiply(verifierSecret).equals(verifierPublicKey.y)) {
  throw new Error('This secret does not open the designated verifier key; only its holder can forge a designated proof');
 }
 const d = randomness ? randomness.d : randomFieldScalar();
 const alpha = randomness ? randomness.alpha : randomFieldScalar();
 const beta = randomness ? randomness.beta : randomFieldScalar();
 for (const value of [d, alpha, beta]) if (!fieldScalar(value)) throw new RangeError('Simulator randomness outside the scalar field');
 const c = pointTimes(G1, alpha);
 const tSrc = pointTimes(branch.D, d).subtract(pointTimes(branch.C, beta));
 const tTgt = gtDiv(gtPow(branch.B, d), gtPow(statement.A, beta));
 const h = await designatedChallenge({ role, context: safeContext, statement, branch, verifierKey: verifierPublicKey, c, tSrc, tTgt });
 const w = mod(beta - h);
 const r = mod((alpha - w) * invertNonzero(verifierSecret));
 return Object.freeze({ w, r, tSrc, tTgt, d });
}

/**
 * The exact map that makes the two paths identically distributed on a TRUE
 * statement: (w,r,t) -> (d,alpha,beta) with alpha = w + x_B r, beta = h + w,
 * d = t + x beta. It is a bijection on the cube of scalars whenever x_B is
 * invertible, so uniform prover randomness and uniform simulator randomness
 * induce the same transcript distribution. Exposed so a test can check the
 * correspondence exactly instead of sampling and calling that a theorem.
 */
export async function simulatorRandomnessOfProof({ publicData, role, proof, verifierPublicKey, verifierSecret, context } = {}) {
 const safeContext = checkedContext(context);
 const { statement, branch } = await openStatement(publicData, role);
 const c = pointTimes(G1, proof.w).add(pointTimes(verifierPublicKey.y, proof.r));
 const h = await designatedChallenge({ role, context: safeContext, statement, branch, verifierKey: verifierPublicKey, c, tSrc: proof.tSrc, tTgt: proof.tTgt });
 return Object.freeze({ d: proof.d, alpha: mod(proof.w + verifierSecret * proof.r), beta: mod(h + proof.w) });
}

// ---------------------------------------------------------------------------
// The verifier. One algorithm; both paths above must satisfy it.
// ---------------------------------------------------------------------------

const refuse = (reason) => Object.freeze({
 accepted: false, checks: Object.freeze({ wellFormed: false }), reason, model: DV_MODEL, scope: DV_SCOPE,
});

export async function verifyDesignatedProof({ publicData, role, proof, verifierPublicKey, context } = {}) {
 let statement; let branch; let safeContext;
 try {
  safeContext = checkedContext(context);
  ({ statement, branch } = await openStatement(publicData, role));
 } catch (error) { return refuse('Statement unavailable: ' + error.message); }
 try {
  if (!(await verifyVerifierKey(verifierPublicKey))) {
   return refuse('The designated verifier key carries no accepted proof of knowledge of its secret');
  }
  if (!proof || !['w', 'r', 'd'].every((field) => fieldScalar(proof[field]))) {
   return refuse('Proof scalars are missing or outside the scalar field');
  }
  if (!sourceValid(proof.tSrc, branch.base) || !isTargetGroup(proof.tTgt)) {
   return refuse('Proof commitments are not canonical members of their groups');
  }
  if (!isTargetGroup(statement.A) || !isTargetGroup(branch.B) ||
      !sourceValid(branch.C, branch.base, { nonidentity: true }) ||
      !sourceValid(branch.D, branch.base, { nonidentity: true })) {
   return refuse('Derived statement elements failed group validation');
  }
  const c = pointTimes(G1, proof.w).add(pointTimes(verifierPublicKey.y, proof.r));
  const h = await designatedChallenge({ role, context: safeContext, statement, branch, verifierKey: verifierPublicKey, c, tSrc: proof.tSrc, tTgt: proof.tTgt });
  const challenge = mod(h + proof.w);
  const checks = {
   wellFormed: true,
   sourceEquation: pointTimes(branch.D, proof.d).equals(proof.tSrc.add(pointTimes(branch.C, challenge))),
   targetEquation: gtEq(gtPow(branch.B, proof.d), gtMul(proof.tTgt, gtPow(statement.A, challenge))),
  };
  const accepted = Object.values(checks).every(Boolean);
  return Object.freeze({
   accepted,
   checks: Object.freeze(checks),
   challenge,
   reason: accepted
     ? 'Both verification equations hold for the recomputed trap-door commitment and challenge'
     : 'At least one verification equation failed',
   model: DV_MODEL,
   scope: DV_SCOPE,
  });
 } catch { return refuse('Verification refused a malformed input'); }
}

// ---------------------------------------------------------------------------
// The contrast: an ordinary publicly transferable Fiat-Shamir proof of the
// SAME statement. No trap-door commitment, no w, no designated verifier. The
// paper names exactly this object on p. 150: collapsing the three moves with
// Fiat-Shamir alone leaves "a transitive proof whose correctness can be
// verified by anyone".
// ---------------------------------------------------------------------------

export async function provePublicTransferable({ publicData, role, witness, context, randomness } = {}) {
 const safeContext = checkedContext(context);
 const { statement, branch } = await openStatement(publicData, role);
 if (!isBranchWitness(statement, branch, witness)) {
  throw new Error('No witness for this branch; a publicly transferable proof cannot be made without one');
 }
 const t = randomness ? randomness.t : randomFieldScalar();
 if (!fieldScalar(t)) throw new RangeError('Prover randomness outside the scalar field');
 const tSrc = pointTimes(branch.D, t);
 const tTgt = gtPow(branch.B, t);
 const challenge = await publicChallenge({ role, context: safeContext, statement, branch, tSrc, tTgt });
 return Object.freeze({ tSrc, tTgt, d: mod(t + witness * challenge) });
}

export async function verifyPublicTransferable({ publicData, role, proof, context } = {}) {
 let statement; let branch; let safeContext;
 try {
  safeContext = checkedContext(context);
  ({ statement, branch } = await openStatement(publicData, role));
 } catch (error) { return refuse('Statement unavailable: ' + error.message); }
 try {
  if (!proof || !fieldScalar(proof.d)) return refuse('Proof scalar is missing or outside the scalar field');
  if (!sourceValid(proof.tSrc, branch.base) || !isTargetGroup(proof.tTgt)) {
   return refuse('Proof commitments are not canonical members of their groups');
  }
  const challenge = await publicChallenge({ role, context: safeContext, statement, branch, tSrc: proof.tSrc, tTgt: proof.tTgt });
  const checks = {
   wellFormed: true,
   sourceEquation: pointTimes(branch.D, proof.d).equals(proof.tSrc.add(pointTimes(branch.C, challenge))),
   targetEquation: gtEq(gtPow(branch.B, proof.d), gtMul(proof.tTgt, gtPow(statement.A, challenge))),
  };
  const accepted = Object.values(checks).every(Boolean);
  return Object.freeze({
   accepted,
   checks: Object.freeze(checks),
   challenge,
   reason: accepted
     ? 'Both equations hold against a challenge nobody can blind: anyone who reads this proof is convinced'
     : 'At least one verification equation failed',
   model: DV_MODEL,
   transferable: true,
   scope: 'PUBLICLY TRANSFERABLE PROOF of the same statement, shown for contrast. ' + SCOPE,
  });
 } catch { return refuse('Verification refused a malformed input'); }
}

// ---------------------------------------------------------------------------
// What a third party actually gets. This function is structurally unable to
// read a witness or a verifier secret: it accepts only public values.
// ---------------------------------------------------------------------------

export async function observerView({ publicData, role, proof, verifierPublicKey, context } = {}) {
 const designated = await verifyDesignatedProof({ publicData, role, proof, verifierPublicKey, context });
 return Object.freeze({
  equationsHold: designated.accepted,
  establishes: Object.freeze(designated.accepted
   ? ['The proof satisfies both verification equations for this statement and this designated verifier key.']
   : ['Nothing: the proof does not satisfy the verification equations.']),
  doesNotEstablish: Object.freeze([
   'Whether the statement is true: the designated verifier can produce an accepting proof of ANY statement.',
   'Who produced the proof: on a true statement the two origins are identically distributed.',
   'That the designated verifier was ever convinced, or that any interaction took place.',
  ]),
  possibleOrigins: Object.freeze([
   'a party holding the role witness for this branch',
   'the designated verifier, using the secret behind its registered public key',
  ]),
  originUndetermined: designated.accepted,
  strengthOfClaim:
   'Exact, conditioned on a true statement and an invertible verifier secret: the two origins induce the same transcript distribution. It is a claim about this transcript alone; side information, timing and the single-browser model are outside it.',
  model: DV_MODEL,
  scope: DV_SCOPE,
 });
}

const pointHex = (point) => Array.from(pointBytes(point), (b) => b.toString(16).padStart(2, '0')).join('');

/** Public wire form. Secrets are structurally absent rather than filtered late. */
export function publicProofFields(proof, { designated = true } = {}) {
 const shared = { tSrc: pointHex(proof.tSrc), tTgt: targetCoefficients(proof.tTgt), d: proof.d.toString(16) };
 return designated
  ? { w: proof.w.toString(16), r: proof.r.toString(16), ...shared }
  : shared;
}
