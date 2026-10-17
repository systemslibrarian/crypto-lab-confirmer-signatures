/**
 * RESEARCH ONLY — toy reconstruction of one relation in Xia's 2013 thesis,
 * Chapter 6, §6.5.2, PDF pages 151–152 (printed pages 138–139).
 *
 * Given two Camenisch–Shoup-style ciphertexts (u_i,e_i,v_i), this *subproof*
 * demonstrates knowledge of (tS,tC,r) such that
 *     eS = yS1^tS h^r,    eC = yC1^tC h^r (mod n^2).
 * It DOES NOT authenticate v_i, prove that u_i = g_i^t_i, bind a commitment ψ,
 * implement the paper's concurrent-ZK compiler, or construct a DCS.
 *
 * Uses the deliberately factorable n=253 research group, an explicitly chosen
 * SHA-256 encoding, and nonsensical security parameters. NOT secure cryptography.
 */
import {createHash, randomBytes} from 'node:crypto';
import {toyParameters, encrypt, modPow, inv, gcd} from './cs-paillier.mjs';

const n = toyParameters.n;
const N2 = n*n;
const h = n+1n;
// These are convenient for testing integer identities, NOT secure parameters.
export const DEMONSTRATION = Object.freeze({challengeBits:24, slackBits:4, rho:11n, modulus:n});

const positive = (v,mod) => ((v % mod)+mod)%mod;
const unit = x => typeof x==='bigint' && x>0n && x<N2 && gcd(x,N2)===1n;
export function powSigned(base, exponent, mod) {
  if(typeof exponent!=='bigint')throw new TypeError('Expected integral exponent');
  return exponent<0n ? modPow(inv(positive(base,mod),mod),-exponent,mod) : modPow(base,exponent,mod);
}
const maxChallenge = 1n << BigInt(DEMONSTRATION.challengeBits);
const maskTBound = N2*(1n << BigInt(DEMONSTRATION.challengeBits+DEMONSTRATION.slackBits-2));
const maskRBound = DEMONSTRATION.rho * (1n << BigInt(DEMONSTRATION.challengeBits+DEMONSTRATION.slackBits));

function below(bound){
  const size = Math.ceil(bound.toString(2).length/8),width=1n<<BigInt(8*size);
  const ceiling=width-width%bound;
  for(;;){const r=BigInt('0x'+randomBytes(size).toString('hex'));if(r<ceiling)return r%bound;}
}
function signedRandom(bound){return below(2n*bound+1n)-bound;}
function checkPublicKey(k){
  return k?.n===n && k.h===h && [k.g,k.y1,k.y2,k.y3].every(unit);
}
function checkCipher(c){
  return !!c && [c.u,c.e,c.v].every(unit) && c.v=== (c.v > N2/2n ? N2-c.v : c.v);
}
function serializeW(W){return W.toString(16).padStart(Math.ceil(N2.toString(16).length/2)*2,'0');}
/**
 * Paper writes c = H(W1 || W2) truncated to its challenge space. Exact H and
 * encoding are unspecified in this thesis excerpt: fixed-width hexadecimal
 * plus a research-only domain string are LOCAL choices, not official vectors.
 * Like the displayed π0 equation, this hash deliberately DOES NOT hash ψ.
 */
export function challengeFromWitnessCommitments(W1,W2){
  if(!unit(W1)||!unit(W2))throw new TypeError('Commitment must be a unit modulo n²');
  const input='XIA2013-TOY-PI0-V1|'+serializeW(W1)+'|'+serializeW(W2);
  const digest=createHash('sha256').update(input).digest('hex');
  return BigInt('0x'+digest) % maxChallenge;
}
function ensureSetup(pubS,pubC,cS,cC){
  if(!checkPublicKey(pubS)||!checkPublicKey(pubC))throw new TypeError('Invalid toy public key or mixed modulus');
  if(!checkCipher(cS)||!checkCipher(cC))throw new TypeError('Invalid toy ciphertext encoding');
}
function validateWitness(w){
  if(!w||![w.r,w.tS,w.tC].every(x=>typeof x==='bigint'))throw new TypeError('Witness needs bigint r, tS and tC');
  if(w.r<0n||w.r>=n||w.tS<1n||w.tS>=n/4n||w.tC<1n||w.tC>=n/4n)throw new RangeError('Toy witness outside its domain');
  if(typeof w.labelS!=='string'||!w.labelS||typeof w.labelC!=='string'||!w.labelC)throw new TypeError('Both encryption labels required');
}
function validateMasks(m){
  if(!m||![m.etaS,m.etaC,m.omega].every(x=>typeof x==='bigint'))throw new TypeError('Expected three signed BigInt blinding masks');
  if(m.etaS < -maskTBound||m.etaS>maskTBound||m.etaC < -maskTBound||m.etaC>maskTBound||m.omega < -maskRBound||m.omega>maskRBound)throw new RangeError('Research blinding mask outside bounds');
}
export function makePi0Subproof(pubS,pubC,cS,cC,witness,{masks}={}){
  ensureSetup(pubS,pubC,cS,cC);validateWitness(witness);
  const {r,tS,tC,labelS,labelC}=witness;
  // Prover preflight: verifies all three ciphertext fields were actually built
  // with this opening. π0's PUBLIC check below does not establish this!
  const expectedS=encrypt(pubS,r,labelS,{t:tS});
  const expectedC=encrypt(pubC,r,labelC,{t:tC});
  if(['u','e','v'].some(k=>expectedS[k]!==cS[k]||expectedC[k]!==cC[k]))throw new Error('Witness is inconsistent with a ciphertext');
  masks=masks??{etaS:signedRandom(maskTBound),etaC:signedRandom(maskTBound),omega:signedRandom(maskRBound)};
  validateMasks(masks);
  const {etaS,etaC,omega}=masks;
  const W1=positive(powSigned(pubS.y1,etaS,N2)*powSigned(h,omega,N2),N2);
  const W2=positive(powSigned(pubC.y1,etaC,N2)*powSigned(h,omega,N2),N2);
  const c=challengeFromWitnessCommitments(W1,W2);
  return Object.freeze({c,D:omega+c*r,D1:etaS+c*tS,D2:etaC+c*tC});
}
function responseBoundD(){return maskRBound+(maxChallenge-1n)*(n-1n);}
function responseBoundDT(){return maskTBound+(maxChallenge-1n)*(n/4n);}
export function verifyPi0Subproof(pubS,pubC,cS,cC,proof){
  // No witness, message, commitment ψ, labels or decryption keys enter the verifier.
  // Verifying this subrelation IS NOT checking DCS validity.
  try{
    ensureSetup(pubS,pubC,cS,cC);
    if(!proof||![proof.c,proof.D,proof.D1,proof.D2].every(x=>typeof x==='bigint'))return false;
    const {c,D,D1,D2}=proof;
    if(c<0n||c>=maxChallenge||D < -responseBoundD()||D>responseBoundD()||D1 < -responseBoundDT()||D1>responseBoundDT()||D2 < -responseBoundDT()||D2>responseBoundDT())return false;
    const W1=positive(powSigned(pubS.y1,D1,N2)*powSigned(h,D,N2)*powSigned(cS.e,-c,N2),N2);
    const W2=positive(powSigned(pubC.y1,D2,N2)*powSigned(h,D,N2)*powSigned(cC.e,-c,N2),N2);
    return c===challengeFromWitnessCommitments(W1,W2);
  }catch{return false;}
}
