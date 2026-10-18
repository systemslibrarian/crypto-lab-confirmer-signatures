# Designated Confirmer Signatures — research gate (NOT YET PASSED)

**Status: DCS research gate CLOSED. No complete designated-confirmer implementation, production security claim, DCS catalog card, or DCS deployment is approved. A separate, conspicuously labeled Chapter 01 ordinary-ECDSA-only research preview may be served by Pages; it cannot unlock any DCS chapter.**

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
- **Added as algebraic preflight, NOT confirmation:** [pi1-relation.mjs](research/pi1-relation.mjs) checks the source's seven π1 witness equations on tiny arithmetic **using the private witness** and independent decrypt. It neither generates commitments/challenges/responses nor hides a witness. See [PI1-WITNESS-RELATION.md](research/PI1-WITNESS-RELATION.md).
- **Added as invalidity-branch research, NOT disavowal:** [disavow-branches.mjs](research/disavow-branches.mjs) classifies the four Camenisch–Shoup §7.3 local failure relations using tiny insecure arithmetic and a private decryption key. It supplies **no** interactive OR proof, exact interval proof, or independent public verifier. A source-backed explanation and the modular alias negative control are in [DISAVOWAL-BRANCHES.md](research/DISAVOWAL-BRANCHES.md).
- **Research-only integrated path, NOT full DCS:** [issued-envelope-toy.mjs](research/issued-envelope-toy.mjs) now joins ψ, a real ECDSA signature on ψ, separately encrypted openings for signer and confirmer, and a partial π0 equality proof. [toy-confirmation-session.mjs](research/toy-confirmation-session.mjs) privately decrypts the appropriate ciphertext and runs an honest three-message seven-equation toy π1/π2 exchange with a public-only checker and one-use prover masks. It deliberately reports TOY_EQUATIONS_HOLD, **never confirmed DCS**. It has no full issuance soundness, exact-range or OR disavowal proof, secure parameter set, concurrent-ZK security or transferable security claim. See [END-TO-END-TOY.md](research/END-TO-END-TOY.md).
- **NOT implemented:** the **complete** source-defined DCS constructor, paper-faithful complete initial NIZK `π0`, actual `Confirm`, affirmative `Disavow`, transcript non-transferability and public conversion. No toy verifier is allowed to report a DCS verdict.
- **Issuance inventory reconciled; remaining 2013/2016 proof fidelity open:** the final 2016 journal's detailed §6 Extract and §7.2 include π0 alongside ψ, σ, c1 and c2. The four-object introductory summary was abbreviated. We have not independently verified the complete final scheme's equations, chosen parameters, malicious-verifier compiler, or complete disavowal; see [SOURCE-RECONCILIATION.md](research/SOURCE-RECONCILIATION.md).

This is progress on the visitor vision, **not a change in the DCS acceptance gate.**

### Interactive π1/π2 mathematics progress (research-only)

The new [three-move toy transcript](research/pi1-interactive-toy.mjs) now separates private prover masks/witnesses from a genuine public-only verifier for the **seven** equations displayed in the 2013 thesis, Chapter 6 §6.5.2. [Research notes](research/PI1-TRANSCRIPT.md) document deliberately factorable groups, a two-bit verifier challenge, a **successful zero-challenge counterexample**, replayability, a disputed range-bound line, absent concurrency compiler and the unresolved 2013/2016 correspondence. This is **not** cryptographically sound confirmation, the affirmative disavowal OR proof, a full DCS or permission to publish the web exhibit. All prior release gates remain closed.

**Independent toy limitation found:** the sample Camenisch–Shoup encryption generator has order 5. A changed label sometimes yields the same group exponent even when H(u,e,L) differs. The research extractor can therefore accept both toy proof transcripts under an altered label. This is now a passing **negative test**, not a claim of correct label authentication. Real DCS would require proper cryptographic-size parameters and exact source-defined validation.

### Two-challenge fork and special-soundness counterexample

The research-only [pi1-special-soundness.mjs](research/pi1-special-soundness.mjs) now takes TWO independently accepted public toy transcripts sharing a first message but having different challenges. It extracts all five integer witnesses by exact response subtraction/division. [The lesson and limits](research/PI1-SPECIAL-SOUNDNESS.md) explicitly warn that a prover answering two challenges with the same mask leaks the decryption exponents and opening; accepting two research transcripts is NOT evidence for deployed DCS soundness or non-transferability. The full paper-specific confirmer construction, secure challenge/range parameters, exact OR disavowal and zero-knowledge compilation remain missing. The Chapter 01 ECDSA-only preview is unaffected.

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

## Narrowly permitted research preview (not DCS)

To prevent a 404 for visitors inspecting progress, the separate [research-preview-pages.yml](.github/workflows/research-preview-pages.yml) is allowed to serve *only* four files copied verbatim from `prototype/`: `index.html`, `style.css`, `app.mjs` and `crypto.mjs`, plus `.nojekyll` and source-SHA `revision.json`. The workflow runs the research tests, exercises real P-256 signing in Chromium at desktop/mobile widths, and checks the served revision and the prominent `does not implement a designated confirmer signature` warning. It never copies `research/` toy proofs or provides Sign/Confirm/Disavow controls. **A successful preview publish is not a successful DCS publish**, and the main Crypto Lab catalogue must NOT gain a Confirmer Signatures card yet. If Pages is disabled at the repository settings level, the preview remains unavailable until its source is configured to GitHub Actions.

## Required delivery gate

Once the mathematics and references pass, follow [`brief.md`](brief.md) and the catalog's [master template](https://github.com/systemslibrarian/crypto-lab/blob/main/audits/_MASTER-TEMPLATE.md) for a complete, accessible Vite + TypeScript lab with real proof flows, known-answer tests, adversarial cases, mutation-checks, GitHub Actions gates and served-byte deployment verification. Until then, **no live lab and no main catalog card**.
