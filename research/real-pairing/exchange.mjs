import {beginConfirmation,respondConfirmation,verifyConfirmation,chooseVerifierChallenge} from './confirmation.mjs';
import {beginDisavow,respondDisavow,verifyDisavow} from './disavow-reconstructed.mjs';
/** A single-use exchange. The verifier's challenge cannot precede commitment. */
export class ProofExchange {
 #session; #first; #data; #keys; #role; #kind; #stage='ready'; #challenge; #response; #result;
 constructor({publicData,privateKeys,role,kind}){
  if(!['confirmation','disavowal'].includes(kind))throw Error('Unknown proof kind');
  this.#data=publicData;this.#keys=privateKeys;this.#role=role;this.#kind=kind;
 }
 async commit(){
  if(this.#stage!=='ready')throw Error('This exchange has already started');
  this.#stage='preparing';
  try{this.#session=await (this.#kind==='confirmation'?beginConfirmation:beginDisavow)(
   {publicData:this.#data,privateKeys:this.#keys,role:this.#role});this.#first=this.#session.firstMessage;this.#stage='committed';}
  catch(e){this.#stage='no-proof';throw e;}
  return this.snapshot();
 }
 challenge(){
  if(this.#stage!=='committed')throw Error('Receive a commitment before choosing the challenge');
  this.#challenge=chooseVerifierChallenge();this.#stage='challenged';return this.snapshot();
 }
 async finish(){
  if(this.#stage!=='challenged')throw Error('Choose Bob’s challenge before requesting the answer');
  this.#stage='checking';
  try{
   this.#response=(this.#kind==='confirmation'?respondConfirmation:respondDisavow)(this.#session,this.#challenge);
   this.#result=await (this.#kind==='confirmation'?verifyConfirmation:verifyDisavow)({publicData:this.#data,
    firstMessage:this.#session.firstMessage,challenge:this.#challenge,response:this.#response});
   this.#stage='checked';
  }catch(e){this.#stage='failed';throw e;}
  finally{this.#session=null;this.#keys=null;}
  return this.snapshot();
 }
 snapshot(){return Object.freeze({stage:this.#stage,kind:this.#kind,
  firstMessage:this.#first,
  challenge:this.#challenge,response:this.#response,result:this.#result});}
}
