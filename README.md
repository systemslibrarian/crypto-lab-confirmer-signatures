# Confirmer Signatures — Crypto Lab (Research Gate)

**Research status:** Chapter 01's **ordinary P-256 ECDSA baseline is implemented and tested**. There is **no executable designated confirmer signature**, and no completed DCS site, confirmation, disavowal or catalog card is approved.

**Planned visitor experience: _Signature Gate — Who Gets to Verify?_** Alice signs a fictional confidential agreement, Carol provides an interactive mathematical confirmation or disavowal, Bob evaluates the proof, and Dave illustrates when evidence is publicly transferable. The user should see why ordinary signature validity, controlled verification, and truth of a signed statement are separate properties.

**Research progress:** Fubiao Xia's [2013 doctoral thesis](https://etheses.bham.ac.uk/4579/1/Xia13PhD.pdf), a closely related full-verification DCS construction by a coauthor of the 2016 paper, supplies explicit labeled-encryption, confirmation and disavowal formulas. We have implemented and locally tested the **intentionally insecure n=253 Camenisch–Shoup-style labeled encryption arithmetic** in [research/cs-paillier.mjs](research/cs-paillier.mjs). The new [research-only π0 equality subproof](research/pi0-equality.mjs) implements the displayed Fiat–Shamir response/recomputation relation from thesis §6.5.2 over the same trivially factorable toy group. Its independent tests also demonstrate that the subrelation alone **does not bind a message commitment ψ or verify the complete ciphertext label/tag**. See [research/PI0-RELATION.md](research/PI0-RELATION.md) and [research/THESIS-EQUATIONS.md](research/THESIS-EQUATIONS.md) for exact formulas and blockers. The new [toy π1 witness-relation checker](research/pi1-relation.mjs) evaluates seven separate source-defined arithmetic equations, plus independently checks a labeled decrypt; its arguments **include the private witness** and therefore it is **not a proof**, interactive confirmation, or DCS. See [research/PI1-WITNESS-RELATION.md](research/PI1-WITNESS-RELATION.md) for the exact boundaries. Local Node tests: **38 passing** (9 ECDSA baseline, 8 labeled-encryption, 12 toy π0, 9 toy π1 witness relations). **This is not a DCS implementation or a complete cryptographic π0 proof.**

This repository records the development brief and the cryptographic selection gate for a proposed interactive lab on designated confirmer signatures. Genuine confirmation **and disavowal** protocols must come from a reviewed, published construction and pass independent mathematical checks. A normal signature hidden by encryption is not automatically a designated confirmer signature.

- **[Chapter 01 — ordinary signature prototype](prototype/)** — executable WebCrypto P-256/SHA-256, Bob/Dave public verification, tamper experiment; no DCS claimed. Serve locally on localhost; no Pages deployment. Tests: `node --test tests/baseline.test.mjs`, plus GitHub Actions desktop/mobile browser checks.
- [`PRODUCT-VISION.md`](PRODUCT-VISION.md) — intended visitor journey, educational outcome, interaction flow, and go/no-go criterion.
- [`SCHEME-NOTES.md`](SCHEME-NOTES.md) — source-backed DCS skeleton including the mandatory initial NIZK `π0`; exact confirmation/disavowal proofs remain open.
- [`brief.md`](brief.md) — required full build and teaching brief.
- [`RESEARCH-GATE.md`](RESEARCH-GATE.md) — scheme-selection prerequisites, literature and acceptance criteria.
- [Crypto Lab master template](https://github.com/systemslibrarian/crypto-lab/blob/main/audits/_MASTER-TEMPLATE.md) — binding Build → Teach → Look → Accessibility → README → Deploy standard, to apply after research passes.

**Non-goals for this stage:** claiming signature correctness, presenting a protocol simulation as proof, deploying a placeholder as a complete lab, or adding a card to the main catalog.

---

*One of the proposed exhibits for the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
