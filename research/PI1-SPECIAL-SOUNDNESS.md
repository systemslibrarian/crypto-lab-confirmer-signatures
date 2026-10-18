# Reused-commitment test: recovering the toy confirmation witness

**Research-only arithmetic test. NOT a break of a deployed confirmer signature and NOT a completed DCS.**

This exercise illustrates an important property of the 2013 Xia thesis's three-move pi1/pi2 proof precursor: a prover cannot safely reuse the same first-message masks to answer two distinct verifier challenges. A pair of accepted transcripts reveals the **integer witnesses** under this particular uncompiled, tiny-group arithmetic.

## Exact algebra

As PI1-TRANSCRIPT.md documents, the five responses have the form:

- xTilde_i(c) = xPrime_i − c * x_i, for i=1,2,3.
- rTilde(c) = rPrime − c * r.
- sTilde(c) = sPrime − c * s.

If EXACTLY the same first-message masks are used twice, at challenges cA≠cB, the differences give:

- x_i = [xTilde_i(cA) − xTilde_i(cB)] / (cB−cA)
- r = [rTilde(cA) − rTilde(cB)] / (cB−cA)
- s = [sTilde(cA) − sTilde(cB)] / (cB−cA)

These divisions must be **exact integers**, not rounded values or modular guesses.

The source module [pi1-special-soundness.mjs](pi1-special-soundness.mjs) accepts only public values: the statement, a *single shared* prover first message, two verifier challenges and their response tuples. It independently checks BOTH transcripts with the public seven-equation verifier in pi1-interactive-toy.mjs. It then divides challenge-response differences and checks the extracted candidate against the toy research preflight and labeled decrypt.

Tests demonstrate that, under a fixed synthetic opening r=7 and decryption exponents (7,11,13), two distinct challenge responses can recover those integers plus auxiliary witness s=19. This is **demonstration math over an instantly factorable n=253**, not a runtime measurement against a production service.

## What is demonstrated and not demonstrated

- The code exhibits a genuine algebraic hazard: reusing a first proof commitment to answer two challenges leaks the toy witness through exact linear-response differences.
- An identical verifier challenge offers no pairwise extraction.
- A separate first-message commitment with independently generated masks cannot be substituted for the original one.
- Tampered transcript messages, malformed challenges and incorrect public ciphertext or claim fail closed instead of fabricating a secret.
- **Crucial negative fixture:** in the deliberately tiny Paillier group, the encryption generator used by the proof has order 5. Changing the ciphertext label can change the full SHA-256-derived H(u,e,L) but leave the exponent modulo 5 unchanged, so all toy public equations and the extracted witness still pass under a DIFFERENT label. The tests preserve this surprising counterexample. It is not an authenticated label-binding construction and **must not be advertised as one**.
- The special-soundness intuition concerns extraction under explicit conditions. It is NOT proof-of-knowledge security at meaningful strength: the challenge is TWO BITS and the group assumptions are intentionally violated.
- No experiment establishes zero knowledge, interactive session protection, non-transferability, or affirmative disavowal. The public verifier still has its deliberate zero-challenge limitation.
- The 2013 toy arithmetic is NOT claimed to match the unreconciled final 2016 journal DCS construction.

## Lesson and release boundary

When Chapter 02 eventually unlocks, a visitor can learn why a prover commits first, the verifier challenges second, and the prover must answer only once with the chosen masks. They can predict what happens if proof randomness is reused and verify the mathematical extraction.

**Do not publish this toy extractor as part of the Chapter 01 ordinary-signature preview or advertise it as a secure confirmer.** It belongs in the research-only source directory.

Run the focused tests with: node --test tests/pi1-special-soundness.test.mjs

Run all research tests with: node --test tests/*.test.mjs

The broader research gate still requires final-paper reconciliation, exact-range and OR-disavowal proofs, appropriate soundness/non-transferability assumptions and independent specialist review before the DCS exhibit can be released.
