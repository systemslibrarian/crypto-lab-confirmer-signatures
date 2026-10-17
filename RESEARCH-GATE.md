# Designated Confirmer Signatures — research gate (NOT YET PASSED)

**Status: research only, 2026-10-17. No implementation, production claim, test vector, or Pages deployment is approved.**

This repository will not advertise ordinary signed-then-encrypted content as a designated confirmer signature. A browser animation with a button marked “confirm” does not establish either soundness or non-transferability.

## What a construction must establish

A chosen, published and fully specified scheme must provide:

1. `Setup`: signer and confirmer generate their separate keys under declared group/parameter assumptions.
2. `Sign`: a genuine *designated confirmer signature* on bound statement bytes, with explicit validity relation and parser.
3. `Confirm`: an actual interactive, sound, zero-knowledge or otherwise transcript-nontransferable proof that the confirmer can run for a valid signature. The browser must display challenges/responses from real algebra, not preset decisions.
4. `Disavow`: an explicit and sound protocol that proves invalidity, rather than merely a verifier failure or a timeout.
5. `Verify`: independent checks of both protocols and the exact statement binding.
6. `Convert`, only if the chosen scheme supports it; converting to public evidence is different from a private confirmation.
7. Negative controls: wrong message, wrong keys, altered proof messages, mismatched groups, malformed points, replayed challenge, and aborted sessions all fail closed.
8. Threat-model honesty: a simulator can show transcript non-transferability only under a paper's security definition; one-browser role separation is NOT deployment-grade trust isolation.

## What has been implemented — and what has not

- **Implemented and tested:** [Chapter 01 ordinary-signature comparison](prototype/) uses real WebCrypto P-256 ECDSA/SHA-256. Alice signs fictional bytes; Bob and Dave independently import the exported public key and verify; tampered messages and wrong keys reject. Published RFC 6979 P-256/SHA-256 verification fixture and browser interaction checks pass.
- **Added as research algebra, NOT a protocol:** [pi0-equality.mjs](research/pi0-equality.mjs) reproduces the §6.5.2 *e-component equality-of-encrypted-opening subrelation* with a distinct public verifier and positive/negative arithmetic fixtures. This partial calculation does **not** prove that the message commitment ψ opens with the same r, that u/v ciphertext fields are valid, or that the complete initial NIZK is sound or non-transferable; see [PI0-RELATION.md](research/PI0-RELATION.md).
- **NOT implemented:** the **complete** source-defined DCS constructor, paper-faithful complete initial NIZK `π0`, actual `Confirm`, affirmative `Disavow`, transcript non-transferability and public conversion. No toy verifier is allowed to report a DCS verdict.
- **Mandatory specification correction:** the full DCS must include `π0` tying the signer/confirmer ciphertext witnesses to each other and the commitment. See [SCHEME-NOTES.md](SCHEME-NOTES.md). A four-part tuple lacking `π0` must not pass the DCS review.

This is progress on the visitor vision, **not a change in the DCS acceptance gate.**

## Published foundations and candidate decision

**Research triage completed; implementation gate still closed.** [SCHEME-SELECTION.md](SCHEME-SELECTION.md) compares the 2016 full-verification construction with the 2024 threshold construction and the Camenisch–Shoup building blocks. The 2016 full-verification DCS is the **primary paper candidate**, not yet a selected *implementation*; exact equations and an independent proof oracle are still missing. The 2024 threshold construction's abort-on-invalid path does **not** establish the affirmative disavowal proof demanded by this brief. No implementation or deployment has been approved.

## Published foundations to evaluate

- David Chaum, *Designated Confirmer Signatures*, EUROCRYPT 1994, DOI: [10.1007/BFb0053427](https://doi.org/10.1007/BFb0053427). Foundational definition and protocols; obtain complete text and independently review proof equations before implementation.
- *Designated confirmer threshold signature and its applications in blockchains*, Cybersecurity (2024), [DOI and article](https://link.springer.com/article/10.1186/s42400-024-00256-2). A documented family combining threshold signatures, encryption, and Sigma protocols, with confirmation/disavowal proof details to study; not assume its threshold implementation can be simplified without changing the claim.

## Primary-source research progress

The 2013 [Fubiao Xia thesis](https://etheses.bham.ac.uk/4579/1/Xia13PhD.pdf) (Chapter 6, including equation-level proof material) is now available as a near-primary source to the 2016 construction. A deliberately insecure test harness for its labeled Paillier arithmetic is implemented and independently checked in [research/](research/). **The proof equations, final-paper differences, initial π0 commitment binding, disavowal, concurrent zero-knowledge compiler and full parameter assumptions are NOT resolved.** Source discovery does not pass the research gate. See [research/THESIS-EQUATIONS.md](research/THESIS-EQUATIONS.md).

## Gate evidence to record before building

- [ ] Full cited paper, exact protocol algorithms/parameter sets, known test-vector inputs/outputs or independent reference implementation recorded.
- [ ] Threat-model table: signer, confirmer, verifier, observer; which party can convince whom, before and after disclosure.
- [ ] Confirmation: simulator/transcript argument and soundness relation understood and reviewed.
- [ ] Disavowal: distinct, independently checked *invalidity proof* implemented and tested; no reliance on absence of valid confirmation.
- [ ] Replay/session binding and exact signed statement encoding fixed in specification.
- [ ] Rust/TypeScript or independent implementation oracle available to catch self-consistent algebraic errors.
- [ ] Independent security review completed before any claim of full DCS correctness.

## Required delivery gate

Once the mathematics and references pass, follow [`brief.md`](brief.md) and the catalog's [master template](https://github.com/systemslibrarian/crypto-lab/blob/main/audits/_MASTER-TEMPLATE.md) for a complete, accessible Vite + TypeScript lab with real proof flows, known-answer tests, adversarial cases, mutation-checks, GitHub Actions gates and served-byte deployment verification. Until then, **no live lab and no main catalog card**.
