/**
 * Executable special-soundness witness extractor for the LOCAL reconstruction.
 * Research harness only: two accepted responses to ONE fixed first message
 * reveal a role key. Never rewind a live prover or expose this in the UI.
 * See DISAVOWAL-PROOF.md for the assumptions and derivation.
 */
import {mod,invertNonzero,gtPow,gtDiv,gtEq,GT,publicStatement} from './core.mjs';
import {verifyDisavow} from './disavow-reconstructed.mjs';

export async function extractDisavowWitness({publicData,firstMessage,left,right}={}){
 for(const transcript of [left,right]){
  if(!transcript||!(await verifyDisavow({publicData,firstMessage,
     challenge:transcript.challenge,response:transcript.response})).equationsHold)
   throw new Error('Extractor requires two accepting transcripts');
 }
 if(left.challenge===right.challenge)throw new Error('Distinct overall challenges required');
 const s=await publicStatement(publicData);
 for(const branch of [1,2]){
  const dc=mod(left.response['c'+branch]-right.response['c'+branch]);
  if(dc===0n)continue;
  const du=mod(left.response['b'+branch+'1']-right.response['b'+branch+'1']);
  const dv=mod(left.response['b'+branch+'2']-right.response['b'+branch+'2']);
  if(dv===0n)throw new Error('Nonzero response difference required by soundness');
  const x=mod(du*invertNonzero(dv));
  const a=mod(-dv*invertNonzero(dc));
  const C=s['C'+branch],D=s['D'+branch],B=s['B'+branch];
  const key=x===0n?D.subtract(D):D.multiply(x);
  const ratio=gtDiv(gtPow(B,x),s.A);
  if(!key.equals(C)||gtEq(ratio,GT.ONE)||a===0n||
     !gtEq(gtPow(ratio,a),firstMessage['beta'+branch]))
   throw new Error('Extracted witness failed independent relation check');
  return Object.freeze({branch,x,a,relationChecked:true,
   scope:'LOCAL RECONSTRUCTION SPECIAL SOUNDNESS; NOT FULL DCS SECURITY'});
 }
 throw new Error('Challenge split failed to yield a changed branch');
}
