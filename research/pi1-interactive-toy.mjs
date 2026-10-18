/**
 * RESEARCH ONLY: toy, interactive THREE-MOVE arithmetic behind the pi1 / pi2
 * confirmation relation in Xia (2013) thesis Chapter 6 section 6.5.2,
 * PDF pages 152-154. NOT a DCS confirmation protocol or zero-knowledge claim.
 *
 * This code has a trivially factorable Paillier modulus, a two-bit verifier
 * challenge, known CRS trapdoors, no concurrent-ZK compiler, no full issuance
 * check, no true interval proof and no 2016-final-spec reconciliation.
 *
 * Importantly, the independently called verifier receives NO private witness.
 * The prover state holds those values and must NEVER be transmitted as proof.
 */
import { randomBytes } from 'node:crypto';
import { toyParameters, modPow, inv, gcd, absResidue, challenge } from './cs-paillier.mjs';
import { TOY_GROUP, TOY_CRS, inspectPi1Witness } from './pi1-relation.mjs';

const n=toyParameters.n, M=n*n;
const G=TOY_GROUP, CRS=TOY_CRS;
const K=2n, KSLACK=4n;
const CHALLENGES=1n<<K;
const X_MASK=M*(1n<<(K+KSLACK-2n));
const R_MASK=G.order*(1n<<(K+KSLACK));
const S_MASK=X_MASK;
const toPositive=(a,p)=>((a%p)+p)%p;
const unit=(a,p)=>typeof a==='bigint'&&a>0n&&a<p&&gcd(a,p)===1n;
export const TOY_PI1_LIMITS=Object.freeze({
  challengeBits:Number(K),challengeCount:CHALLENGES,modulus:n,
  xMask:X_MASK,rMask:R_MASK,sMask:S_MASK,
  security:'NOT DCS, NOT SOUND/ZK AT CRYPTOGRAPHIC PARAMETERS'
});
function powSigned(base,exponent,mod){
  if(typeof exponent!=='bigint')throw new TypeError('Exponent must be BigInt');
  return modPow(exponent<0n ? inv(toPositive(base,mod),mod) : base,exponent<0n ? -exponent : exponent,mod);
}
function mul(mod,...values){return values.reduce((acc,x)=>acc*toPositive(x,mod)%mod,1n);}
function checkScalar(x,lo,hi){
  return typeof x==='bigint'&&x>=lo&&x<=hi;
}
function checkStatement(s){
  const p=s?.publicKey,c=s?.ciphertext;
  if(p?.n!==n||p.h!==n+1n||![p.g,p.y1,p.y2,p.y3,c?.u,c?.e,c?.v].every(x=>unit(x,M)))return false;
  if(c.v!==absResidue(c.v,M))return false;
  if(typeof s.label!=='string'||s.label.length<1||s.label.length>200)return false;
  if(!checkScalar(s.message,0n,G.order-1n))return false;
  if(!unit(s.psi,G.prime)||modPow(s.psi,G.order,G.prime)!==1n)return false;
  if(!unit(s.ell,CRS.modulus))return false;
  return true;
}
function sample(bound){
  const total=2n*bound+1n;
  const bytes=Math.max(1,Math.ceil(total.toString(2).length/8));
  const width=1n<<BigInt(bytes*8),limit=width-width%total;
  for(;;){
    const candidate=BigInt('0x'+randomBytes(bytes).toString('hex'));
    if(candidate<limit)return candidate%total-bound;
  }
}
function validateMasks(m){
  if(!m||!['x1','x2','x3'].every(k=>checkScalar(m[k],-X_MASK,X_MASK)) ||
     !checkScalar(m.r,-R_MASK,R_MASK)||!checkScalar(m.s,-S_MASK,S_MASK)) {
    throw new RangeError('Invalid bounded research-only blinding masks');
  }
}
function alpha(s){
  return mul(G.prime,s.psi,powSigned(G.delta,-s.message,G.prime));
}
/**
 * Private prover step 1: proof opening is checked with the existing research
 * witness inspector (including a genuine toy decryption). Produces a PUBLIC
 * first message and a PRIVATE ephemeral state with masks and witness.
 */
export function beginToyPi1(statement,witness,{masks}={}){
  if(!checkStatement(statement))throw new TypeError('Invalid toy public statement');
  if(!witness || !inspectPi1Witness({...statement,...witness}).relationSatisfied)
    throw new Error('No consistent toy witness; cannot start this protocol');
  const m=masks??{x1:sample(X_MASK),x2:sample(X_MASK),x3:sample(X_MASK),r:sample(R_MASK),s:sample(S_MASK)};
  validateMasks(m);
  const {publicKey:p,ciphertext:c,label}=statement;
  const H=challenge(c.u,c.e,label,n);
  const opening=m.r, xs=[m.x1,m.x2,m.x3];
  const commitment=Object.freeze({
    y1Prime:powSigned(p.g,xs[0],M),
    y2Prime:powSigned(p.g,xs[1],M),
    y3Prime:powSigned(p.g,xs[2],M),
    ePrime:mul(M,powSigned(c.u,m.x1,M),powSigned(p.h,opening,M)),
    vPrime:powSigned(c.u,m.x2+H*m.x3,M),
    alphaPrime:powSigned(G.gamma,opening,G.prime),
    ellPrime:mul(CRS.modulus,powSigned(CRS.g2,opening,CRS.modulus),powSigned(CRS.h2,m.s,CRS.modulus))
  });
  // Never send this private object: it includes the decryption key/witness.
  const proverState=Object.freeze({
    witness:Object.freeze({...witness}),masks:Object.freeze({...m}),
    protocol:'Xia2013-TOY-PI1-UNCOMPILED',phase:'awaiting-verifier-challenge'
  });
  return Object.freeze({commitment,proverState});
}
/** Verifier chooses a fresh challenge only AFTER receiving commitment. */
export function sampleToyPi1Challenge(){
  // Uniform over {0,1,2,3}; absolutely NOT cryptographic soundness.
  return BigInt(randomBytes(1)[0]&3);
}
/** Prover step 3: response under a supplied challenge; witness never returned. */
export function answerToyPi1(proverState,c){
  if(proverState?.protocol!=='Xia2013-TOY-PI1-UNCOMPILED'||
     proverState.phase!=='awaiting-verifier-challenge')throw new TypeError('Invalid research prover state');
  if(!checkScalar(c,0n,CHALLENGES-1n))throw new RangeError('Challenge outside toy two-bit space');
  const {witness:w,masks:m}=proverState;
  const xs=w.privateKey;
  return Object.freeze({
    x1:m.x1-c*xs.x1,x2:m.x2-c*xs.x2,x3:m.x3-c*xs.x3,
    r:m.r-c*w.opening,s:m.s-c*w.s
  });
}
const within=(x,mask,maxWitness)=>checkScalar(x,-mask-(CHALLENGES-1n)*maxWitness,mask+(CHALLENGES-1n)*maxWitness);
/**
 * Verifier: depends ONLY on public statement, first message, challenge and
 * responses. Never calls the private witness inspector or decryptor.
 * Reports equation checks, NOT "CONFIRMED" or DCS accept/reject.
 */
export function checkToyPi1Transcript(statement,commitment,c,response){
  const no=Object.freeze({equationsHold:false,checks:Object.freeze({invalidInput:false}),security:TOY_PI1_LIMITS.security});
  try{
    if(!checkStatement(statement)||!checkScalar(c,0n,CHALLENGES-1n))return no;
    if(!commitment||!['y1Prime','y2Prime','y3Prime','ePrime','vPrime'].every(k=>unit(commitment[k],M)) ||
       !unit(commitment.alphaPrime,G.prime)||!unit(commitment.ellPrime,CRS.modulus))return no;
    if(!response||!['x1','x2','x3'].every(k=>within(response[k],X_MASK,M/4n)) ||
       !within(response.r,R_MASK,G.order)||!within(response.s,S_MASK,CRS.modulus/4n))return no;
    const p=statement.publicKey,z=statement.ciphertext,H=challenge(z.u,z.e,statement.label,n);
    const checks={
      key1:commitment.y1Prime===mul(M,powSigned(p.y1,c,M),powSigned(p.g,response.x1,M)),
      key2:commitment.y2Prime===mul(M,powSigned(p.y2,c,M),powSigned(p.g,response.x2,M)),
      key3:commitment.y3Prime===mul(M,powSigned(p.y3,c,M),powSigned(p.g,response.x3,M)),
      ciphertextE:modPow(commitment.ePrime,2n,M)===mul(M,powSigned(z.e,2n*c,M),powSigned(z.u,2n*response.x1,M),powSigned(p.h,2n*response.r,M)),
      ciphertextV:modPow(commitment.vPrime,2n,M)===mul(M,powSigned(z.v,2n*c,M),powSigned(z.u,2n*(response.x2+H*response.x3),M)),
      commitmentOpening:commitment.alphaPrime===mul(G.prime,powSigned(alpha(statement),c,G.prime),powSigned(G.gamma,response.r,G.prime)),
      auxiliary:commitment.ellPrime===mul(CRS.modulus,powSigned(statement.ell,c,CRS.modulus),powSigned(CRS.g2,response.r,CRS.modulus),powSigned(CRS.h2,response.s,CRS.modulus))
    };
    return Object.freeze({
      equationsHold:Object.values(checks).every(Boolean),
      checks:Object.freeze(checks),security:TOY_PI1_LIMITS.security
    });
  }catch{return no;}
}
