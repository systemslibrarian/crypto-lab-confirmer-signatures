import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

/**
 * A-D-09 scope guard. The designated-verifier lesson may be removed or rewritten,
 * but it may not quietly lose the distinctions it was built to teach, nor start
 * claiming a property the primary source does not give it.
 */
const root = new URL('../', import.meta.url);
const read = (path) => readFileSync(new URL(path, root), 'utf8');

test('the designated-verifier note cites the primary source with its exact sections', () => {
  const note = read('research/real-pairing/DESIGNATED-VERIFIER.md');
  assert.match(note, /Jakobsson, Kazue Sako and Russell Impagliazzo/);
  assert.match(note, /EUROCRYPT '96, LNCS \*\*1070\*\*, pp\. \*\*143–154\*\*/);
  assert.match(note, /10\.1007\/3-540-68339-9_13/);
  // The sections actually used, each by printed page.
  for (const section of [/§2 Approach, p\. 146/, /§3 Definition 1, p\. 147/, /§3 Definition 2 and scheme 1, pp\. 147–148/, /§5, pp\. 149–150/, /§7, p\. 151/, /Appendix, Definition 3, p\. 154/]) {
    assert.match(note, section);
  }
  // The encyclopedia entry is present but marked secondary.
  assert.match(note, /Secondary, and labelled as such/);
});

test('the lesson states its model and refuses the four claims it is not entitled to', () => {
  const note = read('research/real-pairing/DESIGNATED-VERIFIER.md');
  const module = read('research/real-pairing/designated-verifier.mjs');
  assert.match(note, /NOT an\s*audited implementation, NOT a security proof/);
  assert.match(note, /Definition 1\*\*, not Definition 3/);
  assert.match(note, /No security theorem/);
  assert.match(module, /Random-oracle model/);
  assert.match(module, /no ROM theorem for its non-interactive scheme/);
  assert.match(module, /NOT a designated-verifier signature/);
  assert.match(module, /NOT strong designated verifier/);
  assert.match(module, /NOT a confirmer signature/);
  assert.match(module, /NOT a publicly transferable proof/);
});

test('every deviation from the printed construction is written down', () => {
  const note = read('research/real-pairing/DESIGNATED-VERIFIER.md');
  const module = read('research/real-pairing/designated-verifier.mjs');
  for (const deviation of ['D1', 'D2', 'D3', 'D4', 'D5', 'D6']) {
    assert.match(note, new RegExp('\\| ' + deviation + ' \\|'), deviation + ' missing from the note');
    assert.match(module, new RegExp('\\*\\s+' + deviation + ' '), deviation + ' missing from the module header');
  }
  // The hash-binding deviation must say what the paper printed.
  assert.match(module, /The paper's printed input is hash_q\(c,G,M\)/);
  assert.match(note, /`hash_q\(c, G, M\)`/);
});

test('the exact strength of the origin claim is stated, not softened or overstated', () => {
  const note = read('research/real-pairing/DESIGNATED-VERIFIER.md');
  assert.match(note, /bijection/);
  assert.match(note, /exact — not statistical, not\s*computational/);
  assert.match(note, /It is about the \*\*transcript alone\*\*/);
  // A simulated proof of a false statement must be presented as the property,
  // never hidden, because it is why the object is worthless to a third party.
  assert.match(note, /verifies for a false statement/);
});

test('the three proof modes stay distinguished, and the interactive exchange is not claimed to become this by hashing', () => {
  const note = read('research/real-pairing/DESIGNATED-VERIFIER.md');
  assert.match(note, /Hashing the interactive exchange would not\s*produce this object/);
  assert.match(note, /Interactive exchange \(`confirmation\.mjs`\)/);
  assert.match(note, /Designated-verifier proof \(here\)/);
  assert.match(note, /Public transferable proof \(here, for contrast\)/);
  const page = read('research/real-pairing/index.html');
  assert.match(page, /either &Theta; is true, or I am Bob/);
  assert.match(page, /Definition 1, <strong>not<\/strong> the Appendix/);
  assert.match(page, /designated-verifier <em>proof<\/em>, not a designated-verifier signature/);
});

test('the lesson claims no change to the repository standing position on full DCS security', () => {
  const note = read('research/real-pairing/DESIGNATED-VERIFIER.md');
  assert.match(note, /full designated-confirmer-signature\s*security remains unestablished/);
  assert.match(note, /It has had no independent\s*expert review/);
  // The existing ledger must still be the place that lists the open obligations.
  assert.match(note, /\[security ledger\]\(SECURITY-MODEL\.md\)/);
});
