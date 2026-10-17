# Build brief — `crypto-lab-confirmer-signatures`

**2026-10-17 · Proposed / research-gated build brief.** GitHub repository created; full DCS implementation still research gated. **This is the most demanding of the four briefs.** Do not call a mere encrypted ordinary signature a full designated confirmer signature.

**Binding source:** [Crypto Lab Master Template](https://github.com/systemslibrarian/crypto-lab/blob/main/audits/_MASTER-TEMPLATE.md), §§0–6. Use [the in-repo kickoff](https://github.com/systemslibrarian/crypto-lab/blob/main/audits/kickoff.md) with this file as `brief.md`. Catalog changes follow `CLAUDE.md`.

```text
NEW DEMO BRIEF
- Repo name:         crypto-lab-confirmer-signatures
- Short name (H1):   Confirmer Signatures
- Subtitle:          Designated confirmation · Interactive proofs
- One-liner:         Run a published designated-confirmer signature construction so a designated confirmer proves validity or invalidity in an interactive protocol without simply handing out an ordinary publicly verifiable signature.
- Concept to teach:  Controlling who can establish a signature's validity is a separate problem from creating a conventional, publicly verifiable signature.
- Primitives/spec:   Select and pin ONE peer-reviewed DCS construction before coding, including its signature, encryption/commitment, confirmation and disavowal protocols; evaluate the 2016 generic full-verification DCS construction as a candidate.
- Accent (--accent): #83C5F7 (proposed; check fleet palette and contrast)
- Favicon emoji:     📜
- In scope:          genuine setup/sign/confirm/disavow flows from a single published construction; designated confirmer and verifier roles; actual challenge/response mathematics; transcripts and security assumptions; conversion only if supplied by that construction.
- Non-goals:         inventing a new DCS scheme, treating sign-then-encrypt plus reveal as full DCS, plain designated-verifier signatures, generic ZK proofs, fair-exchange enforcement, or production trust separation within one browser.
```

## Research gate — MUST complete before the implementation is approved

**Why this matters:** An ordinary signature plus public-key encryption is straightforward to draw. It is **not automatically** a designated confirmer signature: naive decryption and publishing the original signature creates transferable public evidence, and a status button is not a sound or non-transferable confirmation protocol.

1. Select **one formally specified, published DCS construction**, and record paper title, authors, publication, exact section/algorithms, parameter and assumption choices, and whether it supports public conversion. Candidate: *A reduction of security notions in designated confirmer signatures* (Theoretical Computer Science 618, 2016), which develops a full-verification generic DCS and distinguishes security notions. [Paper/DOI](https://doi.org/10.1016/j.tcs.2015.12.025).
2. Produce a readable `SCHEME-NOTES.md` with the scheme's *actual* named procedures and equations, confirmation/disavowal challenge distributions, transcript semantics, required hardness assumptions and applicable security model. Do **not** replace a paper's proof with “because zero knowledge.”
3. Confirm that its underlying signature, encryption/commitment and proof operations are implementable **entirely in the browser** with audited, named libraries or inspectable mathematics. Separate impossible-to-implement features as non-goals; a genuine scheme must still remain.
4. Define independent test oracles: published vectors if available, otherwise independently derived mathematical identities, a separate verifier implementation, and falsifiable malformed-transcript fixtures. Never claim a “published KAT” that the paper does not provide.
5. **Hard stop:** If full confirmation **and disavowal** cannot be correctly built, decline to ship under the name “Designated Confirmer Signatures.” Document the blocker. A narrower **“Encrypted Signature / Confirmation Workflow”** educational exhibit may be proposed later, explicitly *not* as DCS, but is not a substitute for this brief.

## The one question

**“Why can't I simply show the signature to everybody?”** Put three fictional actors on screen—**Signer**, **Designated Confirmer**, **Verifier**—and an untrusted **Observer**. The signer creates a confirmer signature for a synthetic statement. The verifier must engage the confirmer in an **actual interactive confirmation** protocol; an independent observer watching the transcript should not automatically gain an ordinary transferable signature. The learner next tampers with the statement/signature and runs an actual **disavowal** protocol. Show the source-defined protocol messages and independently recomputed checks.

Do not assert that placing roles in separate panels creates cryptographic privacy: all code runs in one browser. The model's secret-key compartments are educational; **the mathematics** must enforce the published verifier/confirmation requirements.

## Separate from current exhibits

- **Schnorr Forge** and other ordinary signature labs teach public verification and nonce risks; this one teaches why **confirmation authority and transcript transferability** are separate properties.
- **Commit Gate** covers binding/hiding commitments used as *building blocks*, but is not a DCS construction.
- **ElGamal Plain** teaches encryption/rerandomization; do not conflate it with proof of a designated confirmer statement.
- **The Digital Trade** is a game about fair exchange, not a DCS proof. Do not smuggle the game's simulated trade logic into formal DCS verification.

## §1 / SECURITY / CORRECTNESS INVARIANTS

1. **Published scheme fidelity:** Every displayed `Sign`, `Confirm`, `Disavow` and optional `Convert` event runs the selected paper's math, not pre-scripted status changes. Keep source references beside non-obvious equations.
2. **Soundness and correctness:** Honest confirmation for a valid designated confirmer signature succeeds; attempted confirmation of an invalid or altered one fails. Honest disavowal of an invalid signature succeeds; a dishonest disavowal of a valid one fails, to the degree the selected scheme specifies.
3. **Non-transferability is precise:** A viewer of an ordinary interactive transcript must not be told they possess a publicly verifiable signature unless an explicit paper-defined conversion takes place. Show the paper's protocol assumptions and the honest-verifier vs concurrent/composable model distinction where relevant. Empirical tests **cannot substitute** for the paper's security proof.
4. **Freshness and transcript binding:** Every challenge is sampled from a CSPRNG per scheme and bound to correct public statement, participant keys and session. Truncated, altered, cross-session, replayed or out-of-range proofs fail closed as dictated by the construction.
5. **No role-authority theater:** Changing a CSS class, role label or Boolean “confirmer says yes” cannot cause successful mathematical verification. Verifier outputs must be derived independently from actual transcript values.
6. **Hiding cannot be assumed:** State exactly which information is hidden by the chosen scheme and under which assumptions; do not promise signer identity secrecy, anonymity or an absent network metadata channel unless proven.
7. **Browser-only model:** Keys and witness material exist per session only. No network calls, persistence, server, fake external public-key infrastructure or production guarantees.

### ARCHITECTURE (final module names depend on the chosen paper)

- `src/dcs/types.ts`: explicit message/proof/participant/key types and strict canonical encodings.
- `src/dcs/parameters.ts`, `keygen.ts`, `sign.ts`: exact source-defined scheme setup.
- `src/dcs/confirm.ts`, `disavow.ts`: genuine challenge/response proofs; independent verifier(s), no UI code in proof engine.
- `src/dcs/convert.ts`: only if the chosen publication includes a conversion algorithm, with separate authorization and tests.
- `src/ui/`: role lanes, interactive transcript, inspectable equations, third-party view and warnings.
- `src/**/*.test.ts` run under Vitest; `e2e/claims.spec.ts` and accessibility scripts under Playwright, excluded from Vitest. Only 1–3 `// [extension] point` comments for future alternate schemes, not a suite of unfinished schemes.

### UI / THE ONE INTERACTION

1. **Issue:** Select a fictional document; signer produces a real designated confirmer signature. Show an unopened/pending validity state to an external observer, not a pre-decided success.
2. **Ask for confirmation:** Verifier requests proof; confirmer responds with paper-defined interactive messages; recompute and render each genuine step. Reveal enough mathematical structure to prove the demonstration is not a form-only simulation.
3. **Attack:** Tamper with signed bytes, proof, signer identity or confirmer identity. The real verification flow rejects; where specified, run genuine **disavowal** rather than merely saying “invalid.”
4. **Who can show whom?** Show what the verifier learned versus what an observer can establish from the transcript; if the scheme supports `Convert`, perform it explicitly and show public verifiability **after** conversion. Never equate merely posting decrypted underlying signature with an honest non-transferable transcript.
5. **Expert mode:** Honest/invalid/proof transcript side-by-side, algebraic checks, replay controls, formal assumptions and source line/section references. Do not show private keys by default.

**Visual semantics:** A *valid confirmation* reads `CONFIRMED FOR THIS PROTOCOL` instead of `UNIVERSALLY PUBLICLY VERIFIABLE`. An intentionally forged or tampered proof is labeled **REJECTED**; an untested transcript is **UNKNOWN**, not **INVALID**. Disavowal is an affirmative checked protocol result, not an absence of confirmation. Color + icon + text throughout.

### EDGE CASES (fail closed)

Altered message; wrong confirmer key; wrong signer key; proof transcript replay/cross-session swap; missing challenge; tampered response; malformed group element/subgroup or point; invalid commitment ciphertext; invalid proof on valid signature; dishonest confirmation of invalid signature; dishonest disavowal of valid signature; absent optional conversion; browser resource limit. Restrict parameters and input sizes by the selected scheme; performance limits are not proof of insecurity.

## §2 / Honest teaching & negative claim

**Opening:** A normal digital signature can be checked by anyone who has the public key. A designated confirmer signature changes the verification workflow: special confirmation is required, and the evidence from that interaction may be intentionally non-transferable. That is useful only when the precise security requirements are met—not merely when a signer has encrypted a signature.

**Negative claim (§4.1d):** “Successful cryptographic confirmation does **not** establish that the signed real-world statement is factually true.” Use a valid signature on `Package delivered` while the independent, fictional delivery record says **not delivered**. The actual confirmation protocol succeeds, all its mathematical checks report success, and the UI says **`SIGNATURE CONFIRMED — CLAIM NOT FACT-CHECKED`**. Assert this through the UI and mutation-check the warning.

## TESTS / ACCEPTANCE GATES

- Paper-specified key/sign/proof/confirm/disavow correctness with the author(s)' test vectors if provided. Otherwise construct pinned independent **equation-level** oracle fixtures and cross-verify with another engine, with no unsupported “official KAT” claim.
- Valid confirm, invalid confirm, valid disavow of invalid signature, dishonest disavow reject, wrong-key, wrong-message, challenge reuse, malformed transcript, subgroup validation and any paper-specific transcript/proof simulator tests. Tests are **necessary evidence**, not a formal proof of non-transferability.
- Demonstrate non-transferability only according to the paper's actual definition and simulator argument; describe if the implemented proof is honest-verifier ZK rather than stronger concurrent ZK. Never use “observer cannot see key because the UI hides it” as proof.
- `e2e/claims.spec.ts` derives the page's validity from raw exposed public inputs by an independent verifier; tests the negative-claim fixture; tests every failure path, stale-verdict retirement and no-op behavior. A `data-verdict` mutation harness must corrupt each important predicate, prove a changed built bundle and require a named owning test to fail.
- Master template §§3–6: static Vite+TypeScript site; exactly one H1, `cl-topbar` copied from a real lab, pinned dark theme/no toggle, Why It Matters, scripture footer; WCAG 2.1 AA zero axe violations; exact README sections, limitations and actual test count; MIT license, grouped Dependabot, full PR correctness+a11y gate, post-merge deploy dispatch, unique Playwright port and live-byte verification. All new demo cards and generated catalog artifacts follow root `CLAUDE.md` and its checks **after** the paper-faithful lab ships.

## Primary research & related demos

- [*A reduction of security notions in designated confirmer signatures* (2016), DOI](https://doi.org/10.1016/j.tcs.2015.12.025) — candidate scheme and distinctions among non-transferability, invisibility, simulation and full verification; verify complete algorithm text and implementation feasibility before committing to this instantiation.
- [*Designated confirmer threshold signature and its applications in blockchains* (2024)](https://doi.org/10.1186/s42400-024-00256-2) — background on designated confirmation, proofs and security notions; **threshold signatures are not in this exhibit's scope**.
- [Schnorr Forge](https://systemslibrarian.github.io/crypto-lab-schnorr-forge/) · [Commit Gate](https://systemslibrarian.github.io/crypto-lab-commit-gate/) · [ElGamal Plain](https://systemslibrarian.github.io/crypto-lab-elgamal-plain/).

**Ship criterion:** A *genuine, cited* designated confirmer construction provides mathematically checked **confirmation and disavowal**, with correct statements about who learns what, formal limitations and an independent test oracle. **Do not ship a look-alike.**
