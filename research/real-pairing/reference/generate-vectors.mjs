/** PUBLIC, FIXED, INSECURE TEST RANDOMNESS. Never import into the browser. */
import {createHash,webcrypto} from 'node:crypto';
import {writeFileSync,readFileSync} from 'node:fs';
let counter=0;
Object.defineProperty(globalThis,'crypto',{configurable:true,value:{subtle:webcrypto.subtle,
 getRandomValues(bytes){
  const h=createHash('sha256').update('Signature Gate PUBLIC fixture v1:'+counter++).digest();
  for(let i=0;i<bytes.length;i++)bytes[i]=h[i%h.length];return bytes;
 }}});
const {issue,createKeys,G1,G2,pairing,messagePoint,toHex}=await import('../core.mjs');
const {beginConfirmation,respondConfirmation,simulateConfirmation}=await import('../confirmation.mjs');
const {beginDisavow,respondDisavow,simulateDisavow}=await import('../disavow-reconstructed.mjs');
const {exportTranscript,targetCoefficients}=await import('../transcript.mjs');
const keys=await createKeys({signerSecret:7n,confirmerSecret:11n});
const issued=await issue({keys,message:'The manuscript stays in the archive.',r:13n,k:17n});
const altered={...issued.publicData,message:'The manuscript leaves the archive.'};
const vectors=[];
for(const role of ['confirmer','signer'])for(const kind of ['confirmation','disavowal']){
 const publicData=kind==='confirmation'?issued.publicData:altered;
 const begin=kind==='confirmation'?beginConfirmation:beginDisavow;
 const respond=kind==='confirmation'?respondConfirmation:respondDisavow;
 const session=await begin({publicData,privateKeys:keys.privateKeys,role});
 const challenge=23n,response=respond(session,challenge);
 vectors.push({name:role+'-'+kind,expected:true,transcript:exportTranscript({publicData,kind,
  firstMessage:session.firstMessage,challenge,response,provenance:'public-deterministic-fixture'})});
}
for(const kind of ['confirmation','disavowal']){
 const publicData=kind==='confirmation'?altered:issued.publicData;
 const sim=await (kind==='confirmation'?simulateConfirmation:simulateDisavow)({publicData});
 vectors.push({name:'simulated-'+kind,expected:true,transcript:exportTranscript({publicData,kind,...sim,
  provenance:'simulated-challenge-known-before-commitment'})});
}
const pairingAnchors=[
 ['generators',G1,G2],
 ['scaled-generators',G1.multiply(7n),G2.multiply(13n)],
 ['hash-and-scaled-generator',messagePoint('Separate implementation pairing anchor.'),G2.multiply(11n)]
].map(([name,p,q])=>({name,g1:toHex(p.toBytes()),g2:toHex(q.toBytes()),target:targetCoefficients(pairing(p,q))}));
const text=JSON.stringify({notice:'PUBLIC fixture keys 7 and 11; not usable for security. Expected means equations only.',pairingAnchors,vectors},null,2)+'\n';
const path=new URL('./vectors.json',import.meta.url);
if(process.argv.includes('--check')){
 if(readFileSync(path,'utf8')!==text)throw Error('Committed vectors differ from deterministic regeneration');
 console.log('Six committed vectors reproduce byte for byte.');
}else writeFileSync(path,text);
