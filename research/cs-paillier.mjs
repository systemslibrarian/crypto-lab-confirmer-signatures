/**
 * Research-only, deliberately TINY Camenisch–Shoup labeled-Paillier arithmetic.
 * Based on Xia (2013), Thesis Chapter 6, §6.2.2 (PDF pp.137–138), NOT a DCS.
 * Toy p=11, q=23 give n=253: breaks security assumptions immediately.
 * This module illustrates the actual algebra of (u,e,v) and its validity check.
 * Never use for real encryption, confidentiality or any untrusted environment.
 */
import {createHash, randomBytes} from 'node:crypto';
export const toyParameters=Object.freeze({p:11n,q:23n,n:253n});
function positive(x,n){return ((x%n)+n)%n;}
export function gcd(a,b){while(b){[a,b]=[b,a%b]}return a<0n?-a:a}
export function modPow(base,exponent,mod){
 if(typeof base!=='bigint'||typeof exponent!=='bigint'||typeof mod!=='bigint'||exponent<0n||mod<=1n)throw new TypeError('Invalid modular exponentiation');
 let acc=1n;for(let a=positive(base,mod),p=exponent;p>0n;p>>=1n,a=a*a%mod)if(p&1n)acc=acc*a%mod;return acc;
}
export function inv(a,n){
 let [t,nt,r,nr]=[0n,1n,n,positive(a,n)];
 while(nr){const q=r/nr;[t,nt]=[nt,t-q*nt];[r,nr]=[nr,r-q*nr]}
 if(r!==1n)throw new Error('Non-invertible group element');return positive(t,n);
}
function rngBelow(n){
 if(typeof n!=='bigint'||n<1n)throw new TypeError('Invalid sampling bound');
 const bytes=Math.max(1,Math.ceil(n.toString(2).length/8));
 const width=1n<<BigInt(bytes*8),limit=width-width%n;
 for(;;){const x=BigInt('0x'+randomBytes(bytes).toString('hex'));if(x<limit)return x%n}
}
export function absResidue(a,nSquared){const x=positive(a,nSquared);return x>nSquared/2n?nSquared-x:x}
function units(x,n){return x>0n&&x<n&&gcd(x,n)===1n}
function fail(message){throw new Error('CIPHERTEXT REJECTED: '+message)}
function isValidCipher(c,m){return c&&typeof c==='object'&&[c.u,c.e,c.v].every(x=>typeof x==='bigint'&&units(x,m))}
export function challenge(u,e,label,n){
 if(typeof label!=='string'||label.length<1||label.length>200)throw new TypeError('Expected short explicit label');
 const joined=JSON.stringify(['cs-paillier-research-v1',n.toString(),u.toString(),e.toString(),label]);
 return BigInt('0x'+createHash('sha256').update(joined,'utf8').digest('hex'));
}
/** Small, intentionally fixed safe-prime factors and ephemeral keys. */
export function createToyKeyPair(){
 const {p,q,n}=toyParameters,m=n*n,h=n+1n;
 if(p*q!==n||(p-1n)%2n!==0n||(q-1n)%2n!==0n)throw Error('Broken fixed toy modulus');
 let g=1n;for(let i=0;i<200&&g===1n;i++){
   const g0=1n+rngBelow(m-1n);if(gcd(g0,m)!==1n)continue;
   g=modPow(g0,2n*n,m);
 }
 if(g===1n)throw Error('No suitable toy generator');
 const [x1,x2,x3]=Array.from({length:3},()=>1n+rngBelow(m/4n-1n));
 return {publicKey:{n,g,h,y1:modPow(g,x1,m),y2:modPow(g,x2,m),y3:modPow(g,x3,m)},privateKey:{x1,x2,x3,n}};
}
export function encrypt(publicKey,value,label,{t:fixedT}={}){
 const {n,g,h,y1,y2,y3}=publicKey??{};
 if([n,g,h,y1,y2,y3].some(x=>typeof x!=='bigint'))throw new TypeError('Invalid public key');
 if(typeof value!=='bigint'||value<0n||value>=n)throw new RangeError('Plaintext outside [0,n)');
 const modulus=n*n;
 if(h!==n+1n)throw Error('Noncanonical Paillier base');
 let t=fixedT===undefined?1n+rngBelow(n/4n-1n):fixedT;
 if(typeof t!=='bigint'||t<1n||t>=n/4n)throw new RangeError('Invalid toy encryption randomness');
 const u=modPow(g,t,modulus);
 const e=modPow(y1,t,modulus)*modPow(h,value,modulus)%modulus;
 const H=challenge(u,e,label,n);
 const v=absResidue(modPow(y2*modPow(y3,H,modulus)%modulus,t,modulus),modulus);
 return Object.freeze({u,e,v});
}
export function decrypt(privateKey,publicKey,ciphertext,label){
 const {n,x1,x2,x3}=privateKey??{},m=n*n;
 if(typeof n!=='bigint'||[x1,x2,x3].some(x=>typeof x!=='bigint')||publicKey?.n!==n)throw new TypeError('Private/public key mismatch');
 if(!isValidCipher(ciphertext,m))fail('noncanonical or out-of-group element');
 const {u,e,v}=ciphertext;
 if(v!==absResidue(v,m))fail('noncanonical absolute residue');
 const H=challenge(u,e,label,n);
 const left=modPow(u,2n*(x2+H*x3),m),right=modPow(v,2n,m);
 if(left!==right)fail('wrong label, ciphertext or public parameters');
 // k = 2^{-1} mod n for odd n, so 2k = n + 1. See thesis §6.2.2.
 const k=inv(2n,n);
 const value=modPow(e*inv(modPow(u,x1,m),m)%m,2n*k,m);
 if((value-1n)%n!==0n)fail('invalid Paillier plaintext representation');
 const r=(value-1n)/n;
 if(r<0n||r>=n)fail('recovered value outside [0,n)');
 return r;
}