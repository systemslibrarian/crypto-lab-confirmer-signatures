/**
 * RESEARCH ONLY: source-structured toy issuer-to-confirmer transcript.
 *
 * Joins Xia et al. 2016 generic issuing idea (commit -> sign psi -> encrypt
 * opening for S and C) to the 2013 thesis toy interactive pi1/pi2 relations.
 * NOT A COMPLETE DCS. Initial pi0 is incomplete, toy groups are factorable,
 * proof ranges and concurrent ZK are absent; no disavowal proof exists.
 *
 * The confirmer privately decrypts and checks the opening before beginning
 * a toy transcript. Bob's verifier NEVER receives the private decryption key
 * or opening. Public verdict is TOY_EQUATIONS_HOLD, never DCS_CONFIRMED.
 */
import {decrypt} from './cs-paillier.mjs';
import {commitToy,proofAuxiliaryToy} from './pi1-relation.mjs';
import {beginToyPi1,answerToyPi1,checkToyPi1Transcript,sampleToyPi1Challenge} from './pi1-interactive-toy.mjs';
import {inspectToyPublicIssuance,toyLabel} from './issued-envelope-toy.mjs';

const used=new WeakSet();
const reject=reason=>Object.freeze({status:'NO_PROOF',reason,
  evidence:'NO DCS CONFIRMATION OR DISAVOWAL'});
function roleParts(envelope,custody,role){
 if(role==='S')return [envelope.pubS,envelope.cS,custody.signerKey,envelope.labelS];
 if(role==='C')return [envelope.pubC,envelope.cC,custody.confirmerKey,envelope.labelC];
 throw new TypeError('Invalid signer/confirmer role');
}
/**
 * STEP 1: Public material checked; signer or confirmer privately decrypts
 * their OWN toy ciphertext. Failures are not proof of invalidity.
 * Secret witnesses are held exclusively in private proverState, never public.
 */
export async function beginToyConfirmation({envelope,privateCustody,role='C',claimedMessage=4n}={}){
 const preflight=await inspectToyPublicIssuance(envelope);
 if(!preflight.partialIssuanceAccepted)return reject('Public ECDSA or partial equality check failed');
 try{
   const [pk,ciphertext,sk,storedLabel]=roleParts(envelope,privateCustody,role);
   const label=toyLabel(role,claimedMessage,envelope.pubS,envelope.pubC);
   if(label!==storedLabel)return reject('Claim/label differs from source context');
   const opening=decrypt(sk,pk,ciphertext,label);
   if(commitToy(claimedMessage,opening)!==envelope.psi)
     return reject('Confirmer privately found a different opening; no proof issued');
   const auxiliarySecret=19n;
   const statement=Object.freeze({
     publicKey:pk,ciphertext,label,message:claimedMessage,
     psi:envelope.psi,ell:proofAuxiliaryToy(opening,auxiliarySecret)
   });
   const witness={privateKey:sk,opening,s:auxiliarySecret};
   const {commitment,proverState}=beginToyPi1(statement,witness);
   return Object.freeze({
     status:'TOY_PROVER_READY',
     public:Object.freeze({statement,firstMessage:commitment}),
     // Private prover state: DO NOT serialize, display, log, or publish.
     proverState
   });
 }catch{return reject('Toy private decryption or relation preflight rejected');}
}
/**
 * STEP 2/3: Verifier chooses an independent challenge and receives exactly
 * one response. The orchestration burns the first-message masks before
 * generating the response, so this API does not permit fork extraction.
 */
export function finishToyConfirmation(session,challenge){
 if(session?.status!=='TOY_PROVER_READY'||!session.proverState||
    !session.public?.statement||!session.public.firstMessage)
   throw new TypeError('No approved toy confirmation session');
 if(used.has(session.proverState))throw new Error('Prover masks already used; one challenge per commitment');
 const c=challenge===undefined?sampleToyPi1Challenge():challenge;
 used.add(session.proverState); // consume before calculating response
 const response=answerToyPi1(session.proverState,c);
 const {statement,firstMessage}=session.public;
 const verification=checkToyPi1Transcript(statement,firstMessage,c,response);
 return Object.freeze({
   status:verification.equationsHold?'TOY_EQUATIONS_HOLD':'TOY_EQUATIONS_REJECTED',
   publicTranscript:Object.freeze({statement,firstMessage,challenge:c,response}),
   publicChecks:verification.checks,
   evidence:'TOY ONLY: NOT FULL CONFIRMATION, DISAVOWAL, OR NON-TRANSFERABILITY'
 });
}
