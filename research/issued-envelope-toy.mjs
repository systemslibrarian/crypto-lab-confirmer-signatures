/**
 * RESEARCH ONLY — partial issuance/extraction path inspired by the 2016
 * Xia–Liu–Xia–Wang generic DCS construction (§6 and §7.2), using 2013-thesis
 * toy labeled-Paillier algebra, toy Pedersen, and real WebCrypto P-256 ECDSA.
 *
 * NOT A DESIGNATED CONFIRMER SIGNATURE: π0 verifies only an e-component
 * equality relation, not its full commitment/ciphertext relation; modulus
 * n=253 is factorable; Fiat–Shamir challenge width is 24 bits; labels are
 * local encodings; no source-compliant confirm/disavow, OR / range proofs,
 * concurrent-ZK compiler or non-transferability theorem is implemented.
 *
 * This combines ACTUAL computations, not simulated status buttons.
 * Does not ship in the public Chapter 01 browser preview.
 */
import {createSigner,signStatement,verifyPublic} from '../prototype/crypto.mjs';
import {createToyKeyPair,encrypt,decrypt} from './cs-paillier.mjs';
import {commitToy,TOY_GROUP} from './pi1-relation.mjs';
import {makePi0Subproof,verifyPi0Subproof} from './pi0-equality.mjs';

function checkMessage(m){if(typeof m!=='bigint'||m<0n||m>=TOY_GROUP.order)throw new RangeError('Toy message must be a bounded integer 0..10')}
function checkOpening(r){if(typeof r!=='bigint'||r<0n||r>=TOY_GROUP.order)throw new RangeError('Toy opening must be a bounded integer 0..10')}
function checkNonce(n){if(typeof n!=='bigint'||n<1n||n>=253n/4n)throw new RangeError('Toy encryption nonce outside 1..62')}
const signedBytes=psi=>'research-Xia2016-generic-commitment-psi='+psi.toString(10);
function pubId(k){return [k.n,k.g,k.y1,k.y2,k.y3].map(x=>x.toString(16)).join('-')}
/** Local LABEL demonstration choice; NOT the paper's official canonical encoding. */
export function toyLabel(role,message,pubS,pubC){
 if(role!=='S'&&role!=='C')throw new TypeError('Recipient must be S or C');
 checkMessage(message);
 return ['XIA2016-TOY','ROLE='+role,'m='+message.toString(),'pkS='+pubId(pubS),'pkC='+pubId(pubC)].join('|');
}
/**
 * Issuer (Alice) generates:
 *   ψ = PedersenToy(m;r), σ = ECDSA(ψ), cS=Enc(pkS,r), cC=Enc(pkC,r)
 * and an explicitly PARTIAL π0 e-component equality-of-plaintext proof.
 * Return the public envelope separately from private signer/confirmer custody.
 */
export async function issueToyEnvelope({message=4n,opening=7n,tS=3n,tC=4n}={}){
 checkMessage(message);checkOpening(opening);checkNonce(tS);checkNonce(tC);
 const [signer,pairS,pairC]=await Promise.all([createSigner(),Promise.resolve(createToyKeyPair()),Promise.resolve(createToyKeyPair())]);
 const psi=commitToy(message,opening);
 const labelS=toyLabel('S',message,pairS.publicKey,pairC.publicKey);
 const labelC=toyLabel('C',message,pairS.publicKey,pairC.publicKey);
 const cS=encrypt(pairS.publicKey,opening,labelS,{t:tS});
 const cC=encrypt(pairC.publicKey,opening,labelC,{t:tC});
 const pi0=makePi0Subproof(pairS.publicKey,pairC.publicKey,cS,cC,{r:opening,tS,tC,labelS,labelC});
 const signature=await signStatement(signer.privateKey,signedBytes(psi));
 const envelope=Object.freeze({
   psi,signature,signerPublicSpki:signer.publicSpki,
   pubS:pairS.publicKey,pubC:pairC.publicKey,cS,cC,labelS,labelC,pi0
 });
 return Object.freeze({
   envelope,
   privateCustody:Object.freeze({signerKey:pairS.privateKey,confirmerKey:pairC.privateKey,message,opening,tS,tC})
 });
}
/**
 * PUBLIC PRECHECK, not a DCS verifier. A genuine signature on ψ and toy
 * subproof do NOT establish that ψ opens to the alleged message, that cS/cC
 * have valid u/v/labels, or that a confirmer has given any proof.
 */
export async function inspectToyPublicIssuance(envelope){
 try{
  if(!envelope||typeof envelope.psi!=='bigint'||!envelope.signature||!envelope.signerPublicSpki)return Object.freeze({signatureOk:false,encryptedEqualityOk:false,partialIssuanceAccepted:false,isDCS:false});
  const signatureOk=await verifyPublic(envelope.signerPublicSpki,envelope.signature,signedBytes(envelope.psi));
  const encryptedEqualityOk=verifyPi0Subproof(envelope.pubS,envelope.pubC,envelope.cS,envelope.cC,envelope.pi0);
  return Object.freeze({signatureOk,encryptedEqualityOk,partialIssuanceAccepted:signatureOk&&encryptedEqualityOk,isDCS:false});
 }catch{return Object.freeze({signatureOk:false,encryptedEqualityOk:false,partialIssuanceAccepted:false,isDCS:false});}
}
/**
 * LOCAL PRIVATE INSPECTION: S or C decrypts their own ciphertext and checks
 * the message/commitment opening. NOT an interactive proof. The decrypted r
 * and private key must NEVER be sent as a verifier transcript.
 */
export async function inspectToyRecipient(envelope,secretKey,role,claimedMessage){
 const preflight=await inspectToyPublicIssuance(envelope);
 if(!preflight.partialIssuanceAccepted)return Object.freeze({status:'PUBLIC_PREFLIGHT_REJECTED',evidence:'LOCAL ONLY — NOT DISAVOWAL'});
 try{
   checkMessage(claimedMessage);
   if(role!=='S'&&role!=='C')throw new TypeError('Unknown recipient');
   const pub=role==='S'?envelope.pubS:envelope.pubC;
   const cipher=role==='S'?envelope.cS:envelope.cC;
   // Re-derive label from the CLAIMED message and public keys, rather than
   // simply trusting a mutable label string that arrived in the envelope.
   const correctLabel=toyLabel(role,claimedMessage,envelope.pubS,envelope.pubC);
   const storedLabel=role==='S'?envelope.labelS:envelope.labelC;
   if(correctLabel!==storedLabel)return Object.freeze({status:'CLAIM_OR_CONTEXT_CHANGED',evidence:'LOCAL ONLY — NOT DISAVOWAL'});
   const r=decrypt(secretKey,pub,cipher,correctLabel);
   const matching=commitToy(claimedMessage,r)===envelope.psi;
   return Object.freeze({status:matching?'PRIVATE_OPENING_MATCHES':'PRIVATE_OPENING_MISMATCH',opening:r,evidence:'LOCAL ONLY — NOT CONFIRMATION OR DISAVOWAL'});
 }catch{
   return Object.freeze({status:'PRIVATE_DECRYPT_REJECTED',evidence:'LOCAL ONLY — NOT DISAVOWAL'});
 }
}
