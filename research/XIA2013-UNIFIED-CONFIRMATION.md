# Research workbench — 2013 unified-verification DCS equations

**Status: tested symbolic arithmetic, NOT a secure designated-confirmer signature implementation.** The interactive workbench at [prototype/symbolic/](../prototype/symbolic/) intentionally exposes all discrete-log exponents. It does not implement the required affirmative disavowal, malicious/concurrent-verifier zero-knowledge compiler, or non-transferability security proof. It must NOT be catalogued as a completed DCS lab.

## Distinct source from the 2016 generic construction

This experimental branch of research comes from **Fubiao Xia, *Designated Confirmer Signatures: Modelling, Design and Analysis* (2013), Chapter 5, §5.5, Figures 5.1–5.4, PDF pages 113–121**, full source: https://etheses.bham.ac.uk/4579/1/Xia13PhD.pdf. It describes **designated confirmer signatures with unified verification** constructed from a BLS signature and signed ElGamal encryption, not the later 2016 generic commitment-and-CCA2-encryption scheme documented in [SCHEME-NOTES.md](../SCHEME-NOTES.md). Never splice the two protocol families without a published derivation.

## Actually executed modular relations

Our [research module](dcs-uv-symbolic.mjs) implements abstract cyclic G and GT by storing the **discrete-log exponent** of each public element modulo the *tiny* prime q=1019. Group multiplication is exponent addition; exponentiation is exponent multiplication; the bilinear pairing is exponent multiplication between G factors. This satisfies the displayed **group identities**, but is not an elliptic-curve pairing, offers *no* hard discrete-log problem and is completely insecure: someone reading the public exponent already knows the secret.

The testbed performs:

1. Signer secret xs and confirmer secret xc; public values ys=g^xs and yc=g^xc.
2. BLS-shaped underlying signature σ=H(m)^xs, represented algebraically.
3. Signed ElGamal DCS object (σ1,σ2,s,t): σ1=yc^r, σ2=σ·g^r, s=H0(yc^k,σ1,σ2), t=k+s·r mod q. H/H0 are **local SHA-256 encodings** with explicit research domains, not official author vectors.
4. The paper's format check recomputes s from yc^t/σ1^s; the recipient checks the extracted basic signature against the supplied message.
5. Compute the public confirmation relation A=e(σ2,yc)/e(σ1,g), B1=e(H(m),ys), B2=e(H(m),yc), C1=yc, C2=ys, D1=D2=g.
6. Figures 5.1–5.2: **both roles** can issue four first-message commitments; an independent verifier chooses a challenge after those commitments; the prover returns (b1,b2,c1,c2), and a verifier **with no witness argument** checks the four group equations plus c1+c2=c mod q. The code enforces one challenge per set of prover masks. These are actual testable algebraic relations, not a scripted success dialog.

The UI exposes the real first-message, response, challenge and five computed checks. Bob's acceptance means only **symbolic OR-proof equations hold**, not cryptographic confirmation under a secure pairing.

## Explicit test failures and insecurity

- Changing the claimed message leaves the signed-ElGamal **format** proof intact but destroys the underlying signature relation. Both honest provers refuse to claim validity.
- Altering proof response fields, first-message commitments, or the verifier challenge causes independent rejection.
- Reusing prover masks is forbidden; this avoids the exact two-challenge extraction demonstrated by the separate 2013 Chapter 6 research module.
- Public exponent storage trivially reveals xs and xc. Thus *zero knowledge, non-transferability, confidentiality and unforgeability are false as security claims* for this model; only the algebraic structure is taught.
- Random challenges use a toy 1019-element field; this is not an appropriate production proof security level.
- The model does not use a real type-1 elliptic-curve pairing. A source-faithful pairing implementation and parameter security analysis are mandatory before any real cryptographic-security claim.

## Important unresolved printed disavowal relation

**Source-check blocker:** Figures 5.3 and 5.4 (thesis PDF pages 120–121; also in the public 2011 predecessor *Designated Confirmer Signatures With Unified Verification*, ePrint 2011/182) appear, as text-transcribed, to define a disavowal factor β or β′ involving (D^x/C)^a, while the public keys are **C=g^x and D=g**. That makes D^x/C the identity, so β=identity for all a. The same figure requires β ≠ identity. The two conditions cannot simultaneously hold **if the transcription is literal**. The automated negative control proves this elementary identity over all toy keys tested. A likely intended inequality factor is not safe to substitute without independently inspecting the typeset source, errata or author clarification.

Consequently we have **not** claimed an affirmative disavowal protocol is implemented or issued any such browser verdict. A failed confirmation or rejected format is not a proof of invalidity. Alternative full disavowal approaches in Camenisch–Shoup §7.3 require their own OR and exact-interval proofs, not an invented UI shortcut.

## Acceptance status

Source-specific signed-ElGamal algebra and the two OR-confirmation diagrams: **implemented and independently equation-tested at symbolic scale**.

Genuine bilinear pairing, exact security assumptions and parameter selection, malicious/concurrent-ZK transformation, **affirmative disavowal proof**, independent source review, and a complete securely modelled DCS: **NOT complete**.

Run the tests with `node --test tests/dcs-uv-symbolic.test.mjs tests/symbolic-ui-contract.test.mjs`, then the complete research suite. Actual browser flows, including the hostile-message negative control, run in GitHub Actions. None of this authorizes a main Crypto Lab card.
