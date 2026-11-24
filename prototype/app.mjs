import { createSigner, signStatement, verifyPublic, publicFingerprint, hex, experiment } from './crypto.mjs';

const byId = id => document.getElementById(id);
const dom = Object.fromEntries(['statement', 'generate', 'sign', 'verify-bob', 'verify-dave', 'tamper', 'reset', 'fingerprint', 'signature', 'bob-result', 'dave-result', 'overall'].map(id => [id, byId(id)]));
let actor = null;
let signature = null;
let signedMessage = '';
let pending = false;
let epoch = 0;
const supported = !!(globalThis.isSecureContext && globalThis.crypto?.subtle);

function verdict(which, state, text) {
  const el = dom[`${which}-result`];
  el.dataset.verdict = state;
  el.textContent = text;
}
function status(title, text, tone = 'neutral') {
  const el = dom.overall;
  el.dataset.tone = tone;
  el.replaceChildren();
  const head = document.createElement('b'); head.textContent = title;
  const para = document.createElement('p'); para.textContent = text;
  el.append(head, para);
}
function clearVerdicts() {
  verdict('bob', 'unknown', 'NOT TESTED');
  verdict('dave', 'unknown', 'NOT TESTED');
}
function refreshButtons() {
  dom.generate.disabled = pending || !supported;
  dom.statement.disabled = pending;
  dom.sign.disabled = pending || !actor;
  dom['verify-bob'].disabled = pending || !signature;
  dom['verify-dave'].disabled = pending || !signature;
  dom.tamper.disabled = pending || !signature;
  dom.tamper.textContent = signature && dom.statement.value !== signedMessage
    ? 'Restore signed message' : 'Change signed message';
  dom.reset.disabled = pending;
}
function discardSignature(reason) {
  signature = null;
  signedMessage = '';
  dom.signature.textContent = 'Not signed';
  clearVerdicts();
  refreshButtons();
  status('SIGNATURE RETIRED', reason);
}
async function perform(action) {
  if (pending) return;
  pending = true;
  refreshButtons();
  try { await action(); } catch (error) {
    status('OPERATION REJECTED', error instanceof Error ? error.message : 'Unexpected cryptographic failure', 'bad');
  } finally {
    pending = false;
    refreshButtons();
  }
}

dom.generate.addEventListener('click', () => perform(async () => {
  const intendedEpoch = ++epoch;
  actor = null; signature = null; clearVerdicts();
  dom.fingerprint.textContent = 'Generating…';
  dom.signature.textContent = 'Not signed';
  const a = await createSigner();
  if (intendedEpoch !== epoch) return;
  actor = a;
  dom.fingerprint.textContent = await publicFingerprint(a.publicSpki);
  status('KEYS GENERATED', 'Alice has a non-extractable private key. Only her public key fingerprint is displayed.', 'good');
}));

dom.sign.addEventListener('click', () => perform(async () => {
  if (!actor) return;
  // After signing, the message is frozen as the source-of-truth for this particular signature.
  const message = dom.statement.value;
  const original = await signStatement(actor.privateKey, message);
  signature = original;
  signedMessage = message;
  dom.signature.textContent = hex(original);
  clearVerdicts();
  status('SIGNED — PUBLICLY VERIFIABLE', 'Alice produced a real P-256 signature. Bob and Dave can now each verify it using the public key.', 'good');
}));

async function verifyPerson(person) {
  if (!actor || !signature) return;
  // This is deliberately independent verification using the exported *public* key.
  const outcome = await verifyPublic(actor.publicSpki, signature, dom.statement.value);
  verdict(person, outcome ? 'pass' : 'reject', outcome ? 'VERIFIED — SIGNATURE VALID' : 'REJECTED — SIGNATURE DOES NOT MATCH');
  const name = person === 'bob' ? 'Bob' : 'Dave';
  if (outcome) status(`${name.toUpperCase()} VERIFIED`, `${name} imported the public key and verified these exact message bytes. No confirmer was needed.`, 'good');
  else status(`${name.toUpperCase()} REJECTED`, `The signature is still for Alice's original statement. ${name} rejected the changed bytes.`, 'bad');
}
dom['verify-bob'].addEventListener('click', () => perform(() => verifyPerson('bob')));
dom['verify-dave'].addEventListener('click', () => perform(() => verifyPerson('dave')));

dom.tamper.addEventListener('click', () => {
  if (!signature || pending) return;
  const restoring = dom.statement.value !== signedMessage;
  if (restoring) {
    dom.statement.value = signedMessage;
  } else {
    const changed = signedMessage.replace(/delivered/i, 'withheld') + ' [changed]';
    // A message at the textarea limit still needs a valid, different signed-input candidate.
    const first = String.fromCodePoint(signedMessage.codePointAt(0));
    dom.statement.value = changed.length <= dom.statement.maxLength ? changed :
      (first === 'X' ? 'Y' : 'X') + signedMessage.slice(first.length);
  }
  clearVerdicts();
  refreshButtons();
  if (restoring) status('SIGNED MESSAGE RESTORED', 'The original message and signature are back. Bob and Dave can verify them again.');
  else status('MESSAGE CHANGED', 'The original signature is still displayed. Bob and Dave can check it against the edited message.');
});
dom.statement.addEventListener('input', () => {
  clearVerdicts();
  refreshButtons();
  if (signature) status('VERDICTS RETIRED', 'The message changed. Re-run Bob and Dave’s independent verification, or sign again.');
});
dom.reset.addEventListener('click', () => {
  ++epoch; actor = null; signature = null; signedMessage = '';
  dom.statement.value = 'Package delivered.';
  dom.fingerprint.textContent = 'Not generated';
  dom.signature.textContent = 'Not signed';
  clearVerdicts(); refreshButtons();
  status('SESSION RESET', 'The page no longer holds references to the temporary keys. This is not a guarantee of secure memory erasure.');
});

if (!supported) {
  status('WEB CRYPTO UNAVAILABLE', 'Use HTTPS or a localhost development server. No signing or verification has occurred.', 'bad');
  dom.generate.disabled = true;
} else {
  status('READY TO START', `${experiment.algorithm}. Generate Alice’s private key to start. This chapter checks ordinary signatures using the public key.`);
  refreshButtons();
}
