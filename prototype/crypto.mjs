/**
 * REAL ORDINARY ECDSA signatures for the first Signature Gate teaching exercise.
 * This is not a designated confirmer signature (DCS), confirmation, or disavowal.
 * All material is synthetic, and private keys remain non-extractable in memory.
 * Uses only the platform Web Crypto API; no network calls or persistence.
 */
const domain = 'crypto-lab:signature-gate:ordinary-signature-v1\n';
const enc = new TextEncoder();
const signAlgorithm = Object.freeze({ name: 'ECDSA', hash: 'SHA-256' });
const keyAlgorithm = Object.freeze({ name: 'ECDSA', namedCurve: 'P-256' });
const MAX_MESSAGE = 2_000;

export function checkedMessage(message) {
  if (typeof message !== 'string' || !message.trim() || message.length > MAX_MESSAGE ||
      /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(message)) {
    throw new Error(`Provide a nonempty fictional statement (maximum ${MAX_MESSAGE} characters, no control characters).`);
  }
  return enc.encode(domain + message);
}

export const hex = bytes => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
export const unhex = source => {
  if (typeof source !== 'string' || source.length % 2 !== 0 || !/^[a-f0-9]*$/i.test(source)) {
    throw new TypeError('Expected an even-length hexadecimal string.');
  }
  return Uint8Array.from(source.match(/.{2}/g) ?? [], pair => Number.parseInt(pair, 16));
};

export async function createSigner() {
  const pair = await crypto.subtle.generateKey(keyAlgorithm, false, ['sign', 'verify']);
  if (!pair.privateKey || !pair.publicKey || pair.privateKey.extractable) {
    throw new Error('The signing provider failed to create a non-extractable private key.');
  }
  const publicSpki = new Uint8Array(await crypto.subtle.exportKey('spki', pair.publicKey));
  return { privateKey: pair.privateKey, publicSpki };
}

export async function signStatement(privateKey, message) {
  const signature = new Uint8Array(await crypto.subtle.sign(signAlgorithm, privateKey, checkedMessage(message)));
  if (signature.length !== 64) throw new Error('Unexpected P-256 ECDSA signature encoding; expected 64 bytes (P1363).');
  return signature;
}

/** Verifies using a newly imported PUBLIC key. Never accepts a private key. */
export async function verifyPublic(publicSpki, signature, message) {
  if (!(publicSpki instanceof Uint8Array) || publicSpki.length === 0) throw new TypeError('Missing public key.');
  if (!(signature instanceof Uint8Array) || signature.length !== 64) throw new TypeError('Expected 64-byte P256 ECDSA signature.');
  const bytes = checkedMessage(message);
  // Explicitly import a public-key copy, as Bob and Dave would do separately.
  const verifier = await crypto.subtle.importKey('spki', new Uint8Array(publicSpki), keyAlgorithm, false, ['verify']);
  return crypto.subtle.verify(signAlgorithm, verifier, new Uint8Array(signature), bytes);
}

/** Published RFC 6979 vectors sign raw "sample", unlike this lab's domain-separated messages. */
export async function verifyPublishedRawP256(publicUncompressed, rawSignature, messageBytes) {
  if (!(publicUncompressed instanceof Uint8Array) || publicUncompressed.length !== 65 || publicUncompressed[0] !== 4) {
    throw new TypeError('Expected 65-byte uncompressed P-256 public point.');
  }
  if (!(rawSignature instanceof Uint8Array) || rawSignature.length !== 64) throw new TypeError('Expected 64-byte P1363 signature.');
  const publicKey = await crypto.subtle.importKey('raw', new Uint8Array(publicUncompressed), keyAlgorithm, false, ['verify']);
  return crypto.subtle.verify(signAlgorithm, publicKey, new Uint8Array(rawSignature), new Uint8Array(messageBytes));
}

export async function publicFingerprint(spki) {
  if (!(spki instanceof Uint8Array) || spki.length === 0) throw new TypeError('Public key missing.');
  return hex(new Uint8Array(await crypto.subtle.digest('SHA-256', spki)));
}

export const experiment = Object.freeze({
  title: 'Ordinary signatures, not designated confirmer signatures',
  algorithm: 'WebCrypto P-256 ECDSA with SHA-256',
  securityLimit: 'A signature confirms validity for message bytes under a public key. It does not prove the statement is factually true, identify a person by itself, or confer non-transferability.'
});
