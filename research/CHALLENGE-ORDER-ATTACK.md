# Challenge order attack — why Bob must choose AFTER Eve commits

**Working research demonstration, not a completed or secure designated confirmer signature.** The [interactive workbench](../prototype/symbolic/) now includes an adversarial lesson. Its maths uses Fubiao Xia's [2013 thesis, Chapter 5, Figures 5.1–5.2](https://etheses.bham.ac.uk/4579/1/Xia13PhD.pdf) and the corresponding [2011 paper](https://eprint.iacr.org/2011/182.pdf) as reference for the two-branch OR confirmation relation. All group elements are exposed as exponents modulo 1019. The toy model has no hardness assumptions, confidentiality, non-transferability or sound production security.

## The legitimate order

1. Alice issues a signed-ElGamal object on her fictional agreement.
2. Carol or Alice computes FOUR first-message values, z1–z4, from a private witness plus random masks and SENDS them to Bob.
3. Bob independently chooses an unpredictable challenge c.
4. The prover sends four response values (b1,b2,c1,c2) with c1+c2=c (mod q).
5. Bob independently derives the public statement A1,A2,B1,B2,C1,C2,D1,D2 from the actual signed object and checks FIVE equations. A match is a result in the symbolic algebra only, not a DCS security guarantee.

## How Eve cheats when she chooses the challenge first

Eve changes Alice's message but retains her signed-ElGamal object. The format proof can still check out: it binds the encrypted object, not the newly claimed message. Eve DOES NOT know a legitimate confirmation witness.

Suppose Eve gets to choose Bob's challenge c BEFORE creating the first proof message. Eve selects arbitrary b1,b2,c1 and sets c2=c−c1 (mod q). Then she computes z1–z4 backwards from the verifier's exact public equations, represented additively over toy exponents:

- z1 = B1*b1 + A1*c1 (mod q)
- z2 = D1*b1 + C1*c1 (mod q)
- z3 = B2*b2 + A2*c2 (mod q)
- z4 = D2*b2 + C2*c2 (mod q)

Bob's purely algebraic check PASSES for the challenge Eve preselected, even though the statement is false. This is an invalid ordering of proof messages, not a successful attack on a proper honest-verifier protocol. The recorded transcript alone cannot prove that the message commitment preceded the verifier's unpredictable challenge.

If Bob instead supplies a DIFFERENT challenge after the purported first message, Eve's already-chosen response shares do not sum to it. The same transcript FAILS his independent challenge check. The workbench forces a different challenge to demonstrate this counterexample; it does **not** pretend to measure the probability of a random challenge collision.

## Hands-on lesson

After Alice issues the symbolic object, the visitor predicts whether a forged proof will pass, clicks **Try Eve's challenge-first trick**, expands the real transcript, then clicks **Bob: require a different challenge**. The page renders the actual challenge and all five checker results. Everything is computed in the shared symbolic research module. The visitor can change the original statement to retire the proof and start over.

This exercise is a **negative control** for soundness reasoning. It does NOT implement source-defined non-transferability, zero knowledge against malicious or concurrent verifiers, genuine type-1 pairings, or an affirmative disavowal protocol. Signed evidence is not equivalent to factual truth. The printed 2013 disavowal equations still have an unresolved algebraic contradiction and the paper-specific research release gate remains closed.

## Evidence and tests

- `research/dcs-uv-symbolic.mjs`: `forgeWithKnownChallenge()`, which uses public inputs only and derives its statement from the signed object.
- `tests/dcs-uv-symbolic.test.mjs`: tests false-message format validity, honest confirmer refusal, an equation-level forged PASS with an attacker-chosen challenge, rejection after a different challenge, bad inputs, repeated random cases and no private-key requirement.
- `tests/symbolic-ui-contract.test.mjs`: ensures the page connects the real engine, offers an explicit prediction, and preserves non-production and disavowal disclaimers.
- `tests/browser_flow.py`: Playwright drives both attempts at mobile and desktop widths, checks transcript values and verifies stale proof state is retired when the statement changes.

**No public DCS catalog card until affirmative disavowal, production-strength pairing/parameter choices, the appropriate non-transferability model, and an independent cryptographic review are complete.**
