# Derived inequality OR proof — research candidate ONLY

**Status: UNREVIEWED ORIGINAL DERIVATION, NOT THE PUBLISHED DCS DISAVOWAL PROTOCOL.** This module is an algebraic investigation over a symbolic group of order 1,019 with **public exponents**. It offers no secrecy, discrete-log hardness, zero-knowledge, soundness at meaningful security parameters, non-transferability, production safety, or verified authorship of its formula. Nothing here is authorized to unlock the live disavowal chapter or report a real signature as DISAVOWED.

## Why this candidate exists

[Xia's 2013 thesis, Chapter 5 §5.5, Figures 5.3–5.4](https://etheses.bham.ac.uk/4579/1/Xia13PhD.pdf) states that the disavowal should establish an **OR** of two witness relations:

- **Confirmer:** there exists xC such that C1 = D1^xC AND A1 != B1^xC.
- **Signer:** there exists xS such that C2 = D2^xS AND A2 != B2^xS.

The displayed text-extracted figures, however, calculate a nonidentity β from **(D^x / C)^a** while also defining C=D^x. Therefore that literal β is identity for every honestly generated key, contradicting the figures' condition β != 1. This conditional contradiction is documented and tested exhaustively in [DISAVOWAL-FIGURE-AUDIT.md](DISAVOWAL-FIGURE-AUDIT.md). A text extraction error, notation error or typeset-paper correction has **not** yet been authoritatively resolved.

## Derived candidate, not a claimed correction to the paper

For each branch j with public relation (Aj,Bj,Cj,Dj), hypothetically let the honest prover know x and an independent nonzero a such that:

- Cj = Dj^x (the public key relationship);
- Aj != Bj^x (the signed-message relation is invalid);
- **βj = (Bj^x / Aj)^a != identity.**

This last line is a **proposed new algebraic relation**, NOT an equation attributed to Xia 2013 or Wang–Xia–Zhao 2011. Under this candidate, an interactive OR proof would use, for its real branch, fresh masks e,ePrime and public elements:

- **zKey = D^e / C^ePrime**;
- **zInequality = B^e / A^ePrime**;
- after a verifier-chosen challenge cReal, responses b=e−cReal·x·a and bPrime=ePrime−cReal·a.

The public verifier independently checks:

- **zKey = D^b / C^bPrime**;
- **zInequality = β^cReal · B^b / A^bPrime**.

Because C=D^x, the first identity is algebraic. Because β=(B^x/A)^a, the second identity also holds. These equalities are represented **additively in toy exponent space** in the checked-in code.

The prover simulates the other OR branch by choosing a nonidentity βFake and a simulated challenge cFake plus bFake,bPrimeFake, and constructs its first-message elements from the desired verifier equations. The verifier issues a fresh c only after receiving the first message, and checks **c1+c2=c** and both branches' five total group/challenge identities. Neither branch role is revealed through a separate public accept result in the experiment.

## Independent computation and negative controls

Implementation: [disavow-candidate.mjs](disavow-candidate.mjs). Mathematical fixtures: [disavow-candidate.test.mjs](../tests/disavow-candidate.test.mjs).

Tests include honest signer and confirmer proofs of a deliberately changed fictional signed message, honest refusal to prove a **valid** signature invalid, the entire two-bit boundary 0/1 and the final toy field challenge, independent verifier checks, wrong role keys, invalid signed-ElGamal format, altered proof components, wrong challenges, refusal to answer twice with the same mask, random verifier challenges, and explicit assertions that no result contains a production or source-validated disavowal claim.

Every successful verifier result is labeled **RESEARCH CANDIDATE: NOT PUBLISHED DCS DISAVOWAL; NO SECURITY CLAIM**. A mathematical success in this intentionally broken symbolic model is only evidence that this proposed equation set is algebraically self-consistent for the checked inputs. A local `equationsHold=true` is **not** a transferable proof of invalidity and not a claim that any real signed statement was invalidated by a complete secure protocol.

## Release blockers — still ALL open

1. Inspect the **typeset** original figures (not just extracted text), 2011 predecessor, thesis errata, author explanations and related published proofs. Establish whether a true correction exists and whether this derived relation matches it.
2. Full source-faithful pairing setup: the current representation literally publishes discrete-log exponents. Cryptographic group security, BLS signature assumptions, proper subgroup/encoding and performance must be independently evaluated.
3. The stated honest-verifier proof must be upgraded and reviewed against malicious/concurrent-verifier zero-knowledge and non-transferability requirements; a Sigma-style OR algebra pass is not a security proof.
4. Proper range, challenge, replay and session handling, independent reference equations, and a cryptographic security review of the published corrected construction.
5. Confirm *sound affirmative disavowal of an invalid DCS* as a real published protocol, separately from merely rejecting a confirmation attempt. Nothing in this candidate substitutes for that review.

**Decision: no new user-facing DCS disavowal controls and NO main Crypto Lab card.** It is appropriate to continue mathematical and source-analysis research in `research/`, not to present the derived candidate as a corrected published security protocol.
