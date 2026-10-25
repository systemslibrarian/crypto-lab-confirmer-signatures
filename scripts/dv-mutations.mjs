/**
 * A-D-09 mutation replay for the non-interactive designated-verifier proof.
 *
 * Eight concrete patches, each owning exactly one named test. For every one the
 * run proves five things and restores the source in a finally block:
 *
 *   1. the unmodified baseline passes the named owning test,
 *   2. the patch produces a NON-EMPTY source diff,
 *   3. the named owning test turns red,
 *   4. it turns red on an ASSERTION, not on a crash, a missing module or an
 *      empty run, and exactly one test matched the name,
 *   5. the source is restored byte for byte and the owning test is green again.
 *
 * A mutation that cannot be applied, or that is killed by something other than
 * its own assertion, is a failure of this harness rather than evidence.
 *
 * Run from the repository root: node scripts/dv-mutations.mjs [mutation name]
 */
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';

const SOURCE = 'research/real-pairing/designated-verifier.mjs';
const SPEC = 'research/real-pairing/tests/designated-verifier.test.mjs';

const mutations = [
 {
  name: 'verifier key registration bypassed',
  anchor: `  if (!(await verifyVerifierKey(verifierPublicKey))) {
   return refuse('The designated verifier key carries no accepted proof of knowledge of its secret');
  }`,
  replacement: `  if (false && !(await verifyVerifierKey(verifierPublicKey))) {
   return refuse('The designated verifier key carries no accepted proof of knowledge of its secret');
  }`,
  test: 'an unregistered verifier key is refused by both proving paths and by the verifier',
 },
 {
  name: 'context dropped from the designated challenge',
  anchor: ` return hashScalar(DV_CHALLENGE_DOMAIN, role, context,
  targetBytes(statement.A), targetBytes(branch.B), pointBytes(branch.C), pointBytes(branch.D),
  pointBytes(verifierKey.y), pointBytes(c), pointBytes(tSrc), targetBytes(tTgt));`,
  replacement: ` return hashScalar(DV_CHALLENGE_DOMAIN, role,
  targetBytes(statement.A), targetBytes(branch.B), pointBytes(branch.C), pointBytes(branch.D),
  pointBytes(verifierKey.y), pointBytes(c), pointBytes(tSrc), targetBytes(tTgt));`,
  test: 'the context string is bound: altering or omitting it rejects',
 },
 {
  name: 'designated verifier key unbound from the challenge',
  anchor: `  pointBytes(verifierKey.y), pointBytes(c), pointBytes(tSrc), targetBytes(tTgt));`,
  replacement: `  pointBytes(tSrc), targetBytes(tTgt));`,
  test: 'a designated proof does not replay across statements, roles or verifier keys',
 },
 {
  name: 'trap-door blinding dropped from the effective challenge',
  anchor: `  const challenge = mod(h + proof.w);`,
  replacement: `  const challenge = mod(h);`,
  test: 'both allowed origins produce proofs the same verifier accepts, for the confirmer branch',
 },
 {
  name: 'witness check bypassed on the real-witness path',
  anchor: ` if (!isBranchWitness(statement, branch, witness)) {
  throw new Error('No witness for this branch; an honest prover cannot designate a proof of a statement it cannot prove');
 }`,
  replacement: ` if (false && !isBranchWitness(statement, branch, witness)) {
  throw new Error('No witness for this branch; an honest prover cannot designate a proof of a statement it cannot prove');
 }`,
  test: 'a wrong statement witness cannot designate a proof',
 },
 {
  name: 'verifier secret ownership check bypassed',
  anchor: ` if (typeof verifierSecret !== 'bigint' || verifierSecret <= 0n || verifierSecret >= Q ||
     !G1.multiply(verifierSecret).equals(verifierPublicKey.y)) {`,
  replacement: ` if (typeof verifierSecret !== 'bigint' || verifierSecret <= 0n || verifierSecret >= Q) {`,
  test: 'only the holder of the designated verifier secret can take the second path',
 },
 {
  name: 'origin bijection loses its blinding term',
  anchor: ` return Object.freeze({ d: proof.d, alpha: mod(proof.w + verifierSecret * proof.r), beta: mod(h + proof.w) });`,
  replacement: ` return Object.freeze({ d: proof.d, alpha: mod(proof.w + verifierSecret * proof.r), beta: mod(h) });`,
  test: 'the two origins are exactly interchangeable on a true statement for the confirmer branch',
 },
 {
  name: 'target-group equation never checked',
  anchor: `   targetEquation: gtEq(gtPow(branch.B, proof.d), gtMul(proof.tTgt, gtPow(statement.A, challenge))),
  };
  const accepted = Object.values(checks).every(Boolean);
  return Object.freeze({
   accepted,
   checks: Object.freeze(checks),
   challenge,
   reason: accepted
     ? 'Both verification equations hold for the recomputed trap-door commitment and challenge'`,
  replacement: `   targetEquation: true,
  };
  const accepted = Object.values(checks).every(Boolean);
  return Object.freeze({
   accepted,
   checks: Object.freeze(checks),
   challenge,
   reason: accepted
     ? 'Both verification equations hold for the recomputed trap-door commitment and challenge'`,
  test: 'the target-group equation is checked: a proof of only the key half is rejected',
 },
];

function run(command, args, timeout = 600_000) {
 const result = spawnSync(command, args, { encoding: 'utf8', maxBuffer: 32 * 1024 * 1024, timeout });
 if (result.error || result.signal || !Number.isInteger(result.status)) {
  throw new Error(`${command}: process did not exit normally (${result.error?.message ?? result.signal ?? 'no exit status'})`);
 }
 return { code: result.status, output: `${result.stdout ?? ''}${result.stderr ?? ''}` };
}

const escapeForPattern = (text) => text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/** Run exactly the one named test and insist the result is unambiguous. */
function namedTest(name, shouldPass) {
 const result = run('node', ['--test', '--test-reporter=tap', `--test-name-pattern=^${escapeForPattern(name)}$`, SPEC]);
 const tests = Number(/^# tests (\d+)$/m.exec(result.output)?.[1] ?? -1);
 const pass = Number(/^# pass (\d+)$/m.exec(result.output)?.[1] ?? -1);
 const fail = Number(/^# fail (\d+)$/m.exec(result.output)?.[1] ?? -1);
 if (tests !== 1) throw new Error(`${name}: expected exactly one matching test, the runner reported ${tests}`);
 for (const marker of ['Cannot find module', 'ERR_MODULE_NOT_FOUND', 'SyntaxError', 'ReferenceError']) {
  if (result.output.includes(marker)) throw new Error(`${name}: ${marker} is an infrastructure failure, not a mutation kill`);
 }
 if (shouldPass) {
  if (result.code !== 0 || pass !== 1 || fail !== 0) throw new Error(`${name}: expected a green baseline, got exit ${result.code} pass ${pass} fail ${fail}\n${result.output}`);
  return result;
 }
 if (result.code === 0 || fail !== 1 || pass !== 0) throw new Error(`${name}: the mutation SURVIVED (exit ${result.code}, pass ${pass}, fail ${fail})`);
 if (!/ERR_ASSERTION|AssertionError/.test(result.output)) {
  throw new Error(`${name}: the owning test went red without an assertion failure, which cannot count as a kill\n${result.output}`);
 }
 return result;
}

const digest = (text) => createHash('sha256').update(text).digest('hex');

const selected = process.argv[2] ? mutations.filter((m) => m.name === process.argv[2]) : mutations;
if (selected.length === 0) throw new Error(`Unknown mutation: ${process.argv[2]}`);
if (run('git', ['status', '--porcelain', '--', SOURCE]).output.trim()) {
 throw new Error(`Commit ${SOURCE} before replaying mutations; the harness restores from disk, not from git`);
}

const records = [];
for (const mutation of selected) {
 const original = readFileSync(SOURCE, 'utf8');
 const originalDigest = digest(original);
 if (original.split(mutation.anchor).length !== 2) {
  throw new Error(`${mutation.name}: its anchor must occur exactly once in ${SOURCE}`);
 }
 namedTest(mutation.test, true);
 console.log(`[${mutation.name}] 1/5 baseline green: ${mutation.test}`);
 try {
  const changed = original.replace(mutation.anchor, mutation.replacement);
  if (changed === original) throw new Error(`${mutation.name}: the patch changed nothing`);
  writeFileSync(SOURCE, changed);
  const diff = run('git', ['diff', '--no-ext-diff', '--', SOURCE], 60_000);
  if (diff.code !== 0 || diff.output.trim() === '') throw new Error(`${mutation.name}: the source diff was empty`);
  console.log(`[${mutation.name}] 2/5 source diff NON-EMPTY (${diff.output.split('\n').filter((l) => /^[+-][^+-]/.test(l)).length} changed lines)`);
  namedTest(mutation.test, false);
  console.log(`[${mutation.name}] 3/5 owning test RED on an assertion`);
  console.log(`[${mutation.name}] 4/5 no other test was consulted`);
 } finally {
  writeFileSync(SOURCE, original);
 }
 if (digest(readFileSync(SOURCE, 'utf8')) !== originalDigest) throw new Error(`${mutation.name}: the restored source differs from the original`);
 namedTest(mutation.test, true);
 console.log(`[${mutation.name}] 5/5 restored byte for byte and green again`);
 records.push(mutation.name);
}

console.log(`\n${records.length} of ${selected.length} designated-verifier mutations killed by their own named tests, with passing controls.`);
