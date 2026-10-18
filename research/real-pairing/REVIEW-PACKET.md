# Independent review packet: candidate disavowal correction

Status: **prepared for review; no external review, author endorsement or audit
has been obtained.** No reviewer has been contacted by this work. The goal is a
reviewable, falsifiable claim, not a declaration that the complete DCS is secure.

## Questions for a reviewer

1. Do the typeset source figures contain the reported inconsistency, and does
   this candidate match the authors' intended inequality relation?
2. Under the stated prime-order and validation assumptions, are completeness,
   two-special-soundness and special honest-verifier zero knowledge correct?
3. Does the code implement that narrowly stated protocol—including zero
   scalars, identity commitments, subgroup checks and single-use randomness?
4. Which additional changes and security reductions are required for a complete
   Type-3 designated-confirmer signature, with malicious and concurrent verifiers?

## Start here

| Evidence | Location | What it establishes |
| --- | --- | --- |
| Typeset source, exact equation changes | [DISAVOWAL-PROOF.md](DISAVOWAL-PROOF.md) | Source diagnosis and candidate correction |
| Completeness, extraction, simulation argument | Same note | Local prime-order relation, under explicit assumptions |
| Real-group implementation | [disavow-reconstructed.mjs](disavow-reconstructed.mjs) | Executable candidate equations |
| Two-transcript extractor | [disavow-extraction.mjs](disavow-extraction.mjs) | Rechecks both transcripts and recovered witness |
| Separate-library verifier and public vectors | [reference](reference/) | Reproducible agreement and negative controls |
| Symbolic identities and exhaustive small fields | [check_algebra.py](reference/check_algebra.py) | Machine-checked algebraic components, not full theorem |
| Subgroup attack regression | [disavow-soundness.test.mjs](tests/disavow-soundness.test.mjs) | Rejects an actual previously accepting false denial |
| Browser exchange and public export | [exchange.mjs](exchange.mjs), [transcript.mjs](transcript.mjs) | Enforces local event order and whitelists public fields |
| Security ledger | [SECURITY-MODEL.md](SECURITY-MODEL.md) | Implemented versus open scheme obligations |

The source is Xia 2013 Chapter 5, printed pp.105–107, PDF pages120–122
(one-based), especially Figures5.3/5.4. The displayed beta `(D^x/C)^a` is identity
under `C=D^x`, contradicting its nonidentity requirement. The candidate uses
`(B^x/A)^a` and moves the beta challenge factor from the key equation to the
inequality equation. Changing beta alone would be insufficient.

## Reproduce and try to break it

From `research/real-pairing`, run `npm ci --ignore-scripts`, `npm test`,
`node reference/generate-vectors.mjs --check`, and `npm run build`.
Follow [the Python instructions](reference/README.md) for the separate verifier
and symbolic checks. CI also plays both roles through both protocols on desktop
and mobile, exports an actual browser transcript, and checks it with Python.

Try malformed points, noncanonical scalars, identity commitments, order-two beta,
wrong-message claims, changing the public keys, reusing a commitment with a
second challenge, and a challenge chosen by the transcript author. The last
case intentionally produces accepting equations and must never be advertised as
an authenticated interactive proof.

## Claims that are still open

- Author/publisher reconciliation of the proposed correction.
- A fully mechanized proof of the protocol and security games.
- Malicious-verifier or concurrent zero knowledge and DCS non-transferability.
- A complete Type-3 reduction, including invisibility, key registration,
  issuance and conversion. The symmetric-pairing theorem does not transfer
  automatically to dual G1/G2 keys and a new certificate.
- Cross-device/network security, key custody, side channels, secure erasure,
  dependency auditing, and production serialization/transport.

All roles share one browser. The UI is a teaching model, not isolation between
adversarial devices. Exported transcripts are public algebra, not proof of
challenge provenance. The separate Python verifier was written in the same
research effort; **library diversity is not independent expert review**.

For a future review, record the exact commit, theorem assumptions, attempted
counterexamples, findings, fixes and residual limitations. Do not label this an
independently verified correction until such review has actually occurred.
