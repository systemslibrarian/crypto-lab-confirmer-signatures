/**
 * RESEARCH ONLY: special-soundness / reused-first-message counterexample for
 * the toy pi1 arithmetic in Xia (2013), thesis Chapter 6 Section 6.5.2.
 *
 * TWO accepting responses to DIFFERENT challenges under the SAME first
 * commitment reveal the integer witnesses because the responses are linear.
 * This intentionally extracts toy SECRET KEY exponents. Never put this module
 * in the public browser preview or treat it as an attack on a correctly
 * implemented fresh-challenge protocol.
 *
 * This is NOT a published full DCS protocol, zero-knowledge proof, production
 * vulnerability claim or cryptographic-strength soundness demonstration.
 */
import { toyParameters } from './cs-paillier.mjs';
import { TOY_GROUP, TOY_CRS, inspectPi1Witness } from './pi1-relation.mjs';
import { TOY_PI1_LIMITS, checkToyPi1Transcript } from './pi1-interactive-toy.mjs';

const n=toyParameters.n;
const challengeOk=c=>typeof c==='bigint'&&c>=0n&&c<TOY_PI1_LIMITS.challengeCount;
const scalarNames=Object.freeze(['x1','x2','x3','r','s']);
function refuse(message){throw new Error('RESEARCH FORK REJECTED: '+message)}
function exactDiv(a,b){
 if(typeof a!=='bigint'||typeof b!=='bigint'||b===0n||a%b!==0n)refuse('response difference is not divisible by challenge difference');
 return a/b;
}
/**
 * Accepts ONLY PUBLIC transcript data. It deliberately extracts the witness
 * AFTER independent checks on both branches, illustrating why reusing masks is
 * disastrous. This API must never receive or emit actual production secrets.
 *
 * caller supplies a single shared first message and statement; passing two
 * unrelated accepting statements or fresh commitments does NOT yield a fork.
 */
export function extractToyPi1Fork({statement,firstMessage,first,second}={}){
 if(!first||!second||!challengeOk(first.challenge)||!challengeOk(second.challenge)||
    first.challenge===second.challenge)refuse('two distinct well-formed challenges are required');
 for(const branch of [first,second]){
  if(!branch.response||!scalarNames.every(k=>typeof branch.response[k]==='bigint'))
    refuse('missing or malformed response');
  if(!checkToyPi1Transcript(statement,firstMessage,branch.challenge,branch.response).equationsHold)
    refuse('one branch fails the independent public-only equations');
 }
 const delta=second.challenge-first.challenge;
 const [x1,x2,x3,opening,s]=scalarNames.map(k=>
  exactDiv(first.response[k]-second.response[k],delta));
 // Full private-witness recheck is allowed HERE: this is an extraction lab,
 // not a verifier. The independent public verifier above does not use it.
 const recovered={privateKey:{n,x1,x2,x3},opening,s};
 const preflight=inspectPi1Witness({...statement,...recovered});
 if(!preflight.relationSatisfied)refuse('extracted witness does not open all relations');
 return Object.freeze({
   recovered:Object.freeze({x1,x2,x3,opening,s}),
   algebraicWitnessRecovered:true,
   security:'TOY WITNESS REVEALED — NOT A DESIGNATED CONFIRMER SECURITY RESULT'
 });
}
