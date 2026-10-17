# Product vision — Signature Gate: Who Gets to Verify?

**Stage: visitor-experience concept only — no designated confirmer signature implementation exists yet.** This document explains the intended learning experience; [RESEARCH-GATE.md](RESEARCH-GATE.md) and [SCHEME-SELECTION.md](SCHEME-SELECTION.md) remain binding. Nothing below authorizes fake proof transcripts, a catalog card or deployment.

## One-sentence promise

**Learn why an ordinary digital signature can be checked by anybody, while a designated confirmer signature can require an authorized party to participate in proving whether an alleged signature is valid — without automatically creating portable public proof.**

This is an **advanced interactive Crypto Lab**, not an arcade game, an encrypted-document service, an electronic-contract product, or a way to hide wrongdoing. Every numerical verdict must come from the actual selected paper's computation. The experience should make sense to a newcomer before showing algebra.

## The story

Alice signs a *fictional*, confidential agreement. Bob needs assurance that a corresponding signature is valid. Carol is a **designated confirmer** entrusted to conduct the mathematical verification protocol. Dave is an outside observer.

- **Ordinary public signature:** Alice sends Bob an ordinary signature on the agreement. Bob, Carol, and Dave can all verify it given the public key and signature. Bob can also show that publicly verifiable signature to someone else.
- **Designated confirmer signature:** Alice issues a different cryptographic object under a formally specified scheme. Bob cannot merely run ordinary signature verification on the claimed message. Under the source-defined role rules, Carol (and, in some constructions, Alice) engages Bob in an **interactive proof of validity or invalidity**. Whether Bob can persuade Dave with that transcript depends on the paper's exact non-transferability definition and adversary model — never on a UI animation.
- **Invalid case:** Bob changes the signed statement or alleged signature. Carol must use the scheme's **affirmative disavowal proof** if supported. A missing response, refusal, or failed confirmation is **not** proof of invalidity.
- **Reality check:** A mathematically valid signature on “Package delivered” does not establish that a package was delivered. Verification establishes a particular cryptographic relation, not a real-world fact.

For beginners, define *transcript* as “the recorded messages exchanged during a cryptographic proof,” and *non-transferability* as “the specific inability to turn that interaction into independent convincing evidence under the scheme's formal assumptions.” Do not promise absolute privacy.

## The single moment the visitor should remember

> **A valid cryptographic signature and the ability to convince everyone else it is valid are different properties.** A designated confirmer can participate in a sound proof without being able to make an invalid signature true.

The mathematical mechanism—not a status button—must make this distinction visible.

## Proposed interactive tour

### 01 / Everybody can check (baseline)

Show the same fictional signed statement, a genuine ordinary digital signature, and its public verification. Three spectator views compute the same independent result. The learner clicks **Show this to Dave** and sees Dave independently verify. This establishes what is publicly transferable about an ordinary signature. It is a comparison, not the DCS construction.

**Evidence:** actual message bytes, public key, signature bytes and a real signature verifier.

### 02 / Ask the confirmer (headline experiment)

Issue a source-faithful **designated confirmer signature** to Alice's document. Bob initially sees **NOT PUBLICLY VERIFIED**, not a forged “invalid” verdict. Bob starts a proof session; Carol sends paper-defined commitments and responses in reaction to genuinely generated challenges. Reveal one proof step at a time, showing which values the independent verifier recomputes and why each check passes.

**Evidence:** paper-defined statement, witness relation, challenge distribution, proof transcript, exact verifier equations and computed verdict. Label what may be leaked by each public message. If the chosen full-verification scheme also lets Alice confirm, make that a separate actor path rather than changing roles silently.

### 03 / Try to cheat (failure experiment)

Let the learner change (a) the statement, (b) the alleged signature, or (c) a proof challenge/response; include wrong keys and cross-session replay. Real proof verification must reject wrong transcripts. For an actually invalid alleged signature, Carol executes a **separate valid disavowal protocol**, with its own positive proof verdict. Contrast:

- **CONFIRMED:** a valid confirmation proof was independently accepted.
- **DISAVOWED:** an independent disavowal proof of invalidity was accepted.
- **REJECTED:** a proposed proof transcript failed checks; nothing further was established.
- **UNDETERMINED:** no valid proof has been completed.

A dishonest disavowal of an actually valid signature must fail. Never treat confirmation failure as affirmative disavowal.

### 04 / Who can convince Dave? (limitations)

Contrast the plain publicly verifiable signature from step 01 with the completed proof interaction from step 02. Explain the **selected paper's formal non-transferability claim**, its simulator or designated-verifier conditions, and cases outside that definition. An interaction captured by the browser must not be sold as a proof of security against every external observer, malicious verifier or collusion.

If the paper defines an explicit `Convert` algorithm, demonstrate it separately and explain how conversion changes which evidence is transferable. If not, omit this interaction entirely.

### 05 / Authentic does not mean true (negative claim)

The fictional document says “Package delivered,” while a separately authored fictional dispatch log says “Not delivered.” A real valid DCS confirmation passes all its cryptographic checks, but the claim's factual truth is not established. The status must read **SIGNATURE CONFIRMED — CLAIM NOT FACT-CHECKED**. A browser test must reach this state and prove the warning remains visible even when every genuine cryptographic check succeeds.

## Layout and interaction rules

- **Top:** Crypto Lab standard bar and hero; title **Signature Gate**; subtitle **Designated confirmer signatures · Interactive proofs**; “Why it matters” says who can verify differs from whether a signature is valid.
- **Main:** Alice → Carol ↔ Bob lanes with clickable proof steps; Dave is visibly separate as an observer. On phones, stack the lanes in message order.
- **Right/below:** plain-language “What just happened?” and a minimal trace: *statement → challenge → response → recomputed acceptance*. Show full values and algebra only under **Inspect the actual cryptography**.
- **Make a prediction, then test it:** free guesses and retries; absolutely no badge, win state or green claim without a real verifier result.
- **Accessibility:** screen-reader-named participants, predictable keyboard controls, status text/icons beyond color, mobile widths, reduced motion and WCAG 2.1 AA checks, following the master template.

## Not an ordinary sign-and-encrypt demo

Encrypting an existing publicly verifiable signature then decrypting it for Bob is *not* enough. That would release an ordinary portable signature, with no convincing confirmation/disavowal soundness or source-defined transcript properties. We will not display scripted success/failure dialogs as if they were proof.

## Go/no-go checklist

**Do not start a public DCS workbench until ALL of the following are true:**

1. The complete publication is available and its exact `Setup`, `Sign`, `Confirm`, `Disavow`, optional `Convert`, proof statements, parameter sizes, encodings and admissible challenges have been recorded in a numbered, equation-level `SCHEME-NOTES.md`.
2. The candidate scheme has an implementable soundness relation for **both positive confirmation and affirmative disavowal** (a failed confirmation does not count).
3. Independent verification fixtures exist. Published vectors are preferred; otherwise independently derived test oracles and direct equation checks must be explicitly labeled nonofficial.
4. An adversarial test matrix exercises malicious messages, keys, proofs, malformed elements, replays and false disavowals.
5. Claims about secrecy, zero knowledge, non-transferability, conversion and signer-versus-confirmer rights match exactly what the selected publication actually establishes.
6. A code and math review verifies the library choices are appropriate to the publication. Only then follow the [Crypto Lab master template](https://github.com/systemslibrarian/crypto-lab/blob/main/audits/_MASTER-TEMPLATE.md) for tests, UI, deployment, catalog integration and live-source verification.

**Decision if the gate fails:** Keep the repository openly labeled **research / not shipped**. We may later create a clearly different **Ordinary vs. Interactive Signature Verification** teaching comparison, but we must never call a sign-and-encrypt mockup a designated confirmer signature.

## Editorial acceptance

A successful visitor should be able to answer these four questions without opening the math drawer:

1. Why can Dave verify an ordinary signature but not automatically verify an alleged designated confirmer signature?
2. What new fact does Carol's **accepted proof** establish, and what can she *not* decide arbitrarily?
3. Why is “confirmation failed” different from a valid **disavowal** proof?
4. Why is “authentic signature” not the same as “true statement”?

If a prototype cannot answer those questions clearly and accurately, it is not ready to ship, even if the underlying algebra is correct.
