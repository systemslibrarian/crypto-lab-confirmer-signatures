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

## Published foundations to evaluate (no design chosen yet)

- David Chaum, *Designated Confirmer Signatures*, EUROCRYPT 1994, DOI: [10.1007/BFb0053427](https://doi.org/10.1007/BFb0053427). Foundational definition and protocols; obtain complete text and independently review proof equations before implementation.
- *Designated confirmer threshold signature and its applications in blockchains*, Cybersecurity (2024), [DOI and article](https://link.springer.com/article/10.1186/s42400-024-00256-2). A documented family combining threshold signatures, encryption, and Sigma protocols, with confirmation/disavowal proof details to study; not assume its threshold implementation can be simplified without changing the claim.

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
