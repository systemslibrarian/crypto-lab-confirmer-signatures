# Paper fidelity blocker — 2013 unified-verification disavowal figures

**Status update, 2026-10-18:** The **typeset thesis** Figures 5.3–5.4 were visually inspected on printed pages 106–107 (one-based PDF pages 121–122). Both print the key-ratio beta and put its challenge factor on the key equation. Thus the thesis contradiction is confirmed beyond text extraction. This is not an author-approved correction or a final verdict on the intended scheme. The separate [local correction argument](real-pairing/DISAVOWAL-PROOF.md) identifies both required equation changes, proves narrowly scoped properties and records remaining review obligations.

## Cited sources

- Fubiao Xia, [*Designated Confirmer Signatures: Modelling, Design and Analysis*](https://etheses.bham.ac.uk/4579/1/Xia13PhD.pdf), University of Birmingham (2013), Chapter 5 §5.5.1, Figures 5.3–5.4, one-based PDF pp.121–122 (printed pp.106–107).
- Wang, Xia and Zhao, [*Designated Confirmer Signatures With Unified Verification*](https://eprint.iacr.org/2011/182.pdf), ePrint 2011/182, disavowal Figures 4–5. The accessible text-transcribed versions agree on the relevant structure.

## Formal conditional contradiction in the **literal extracted formula**

The common public statement in both versions defines **C1=yC=g^xC, C2=yS=g^xS, and D1=D2=g**.

The text-extracted signer and confirmer disavowal preliminaries appear to require a non-identity element derived from one of these expressions:

- Signer: betaPrime = (D2^xS / C2)^a.
- Confirmer: beta = (D1^xC / C1)^a.

But substituting the public-key definitions gives:

- D2^xS / C2 = g^xS / g^xS = **identity**.
- D1^xC / C1 = g^xC / g^xC = **identity**.

Every power of the identity remains the identity; therefore beta/betaPrime **cannot** satisfy the printed **non-identity** precondition. This holds for every honestly generated key, every nonzero exponent and every group order. The typeset thesis has now been visually checked and contains these same expressions. This does not establish that the authors intended an impossible protocol.

Our [research regression](../tests/dcs-uv-symbolic.test.mjs) checks the corresponding exponent identity exhaustively for **all 1,018 nonzero private scalars** in the toy order-1019 field, and three distinct multipliers, in addition to the earlier representative-key tests. In exponent representation the group identity is 0, rather than multiplicative 1.

## What is blocked

The workbench's actual confirmation OR equations are independently verified as research algebra. They do **not** imply a correct **affirmative disavowal** proof. It is not permissible to change the printed beta numerator or denominator by guesswork, replace disavowal with failed confirmation, or make the UI show DISAVOWED when a local Boolean rejects. Any attempt would create a lab teaching false cryptographic guarantees.

## Next concrete route

1. Completed for the typeset thesis Figures 5.3–5.4 on 2026-10-18. Publication-version reconciliation and authoritative erratum review remain open.
2. If the inconsistency remains, derive the intended proof algebra and seek independent cryptographic review or author clarification. A guessed swap of pairing elements is **not** sufficient.
3. In parallel, evaluate the *distinct* Xia et al. 2016 full-verification generic scheme, whose disavowal uses Camenisch–Shoup §7.3 OR and exact-interval proofs. Keep its proof/parameter assumptions separate; never splice constructions without a published derivation.
4. Only after a complete, cited and independently verified disavowal plus confirmation and the required non-transferability model exist should the full DCS web chapter unlock.

**Decision: the separate real-pairing workbench now includes a clearly labeled local inequality reconstruction and proof argument. The full designated confirmer signature release gate remains CLOSED.**
