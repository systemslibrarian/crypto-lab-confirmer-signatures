# Signature Gate — real-pairing research, source-to-claim ledger

**State:** executable BLS12-381 algebra and independently checked interactive equations. **NOT a peer-reviewed, fully secure designated-confirmer signature implementation.** This directory must never be described as a production signing system or as proof of the published schemes' invisibility, non-transferability or malicious-verifier/concurrent zero knowledge.

## What is truly computed

- Genuine elliptic-curve points and pairings in BLS12-381 with @noble/curves **2.4.0** (not a representation that reveals a discrete logarithm). Actual G₁ points, G₂ points and an Fp¹² Gₜ pairing target.
- RFC 9380-style hash-to-curve for BLS signing, with the explicit LOCAL research DST in core.mjs. The local encoding/DST is not a source-author test vector.
- A basic BLS-shaped signature σ = xₛ H(m) in G₁ and its verifiable pairing e(σ,G₂)=e(H(m),xₛG₂).
- Signed ElGamal as in Wang–Xia–Zhao (2011) / Xia (2013): σ₁ = r·Y꜀₁, σ₂ = σ+r·G₁, signature-format challenge s=H₀(k·Y꜀₁,σ₁,σ₂), response t=k+s·r. The H₀ encoding/domain is an explicitly noted LOCAL choice. The format proof DOES NOT reveal whether a message's underlying BLS signature is valid.
- Carol's private extraction σ = σ₂ − x꜀⁻¹·σ₁ followed by a fresh, independent pairing validity test.
- Both positive OR-verification branches from §5.5: A=e(σ₂,Y꜀₂)/e(σ₁,G₂), B₁=e(H(m),Yₛ₂), B₂=e(H(m),Y꜀₂), with A=B₁^x꜀ OR A=B₂^xₛ and the corresponding public-key equations. Real first-message commitments, a verifier-supplied challenge and independent response checking.
- A separately declared **research candidate** of the inequality/disavowal OR relation. It uses a correction DERIVED from the intended inequality statement, not a protocol that can legitimately be attributed verbatim to the source's published Figure 4/5 or Figure 5.3/5.4. Independent arithmetic fixtures test completeness for honest research instances and rejection for dishonest changes; a written completeness, two-special-soundness and special honest-verifier zero-knowledge argument is now available in [DISAVOWAL-PROOF.md](DISAVOWAL-PROOF.md), with executable witness extraction. The [Lean field model](formal/) now kernel-checks completeness, extraction and OR soundness, plus exact joint honest-branch sampling. Concrete-group interpretation, code refinement and the full OR distribution/security games are not formalized. It remains unreviewed by an external expert and is not a full DCS security proof.

## Reproducibility and review status

The [separate Python verifier](reference/) uses py_ecc 8.0.0 instead of Noble,
reconstructs the public statement and checks actual browser exports. Six fixed
vectors cover both roles, both relations and both known-challenge simulators;
three pairing anchors make the libraries’ normalization convention explicit.
Symbolic certificates check eight polynomial identities, alongside exhaustive
small-field extraction checks. The separate [Lean model](formal/) proves scoped
field-algebra theorems and one exact joint sampling distribution; publication
requires its kernel and axiom checks to pass on the same commit. None of this is a
full DCS security theorem or independent expert audit. The same research
effort produced both implementations. The [review packet](REVIEW-PACKET.md)
lists the unresolved claims and exact reproduction commands.

The challenge and proof masks use the entire scalar field, including zero.
Identity proof commitments are allowed; identity registered keys are rejected.
A single-use exchange enforces commitment → challenge → response locally. All
roles still share one browser, so this does not establish device isolation or
network/session security.

## Why Type-3 is an ADAPTATION, not the 2011/2013 implementation

The source writes a symmetric bilinear map e:G×G→Gₜ. BLS12-381 is an asymmetric Type-3 curve with e:G₁×G₂→Gₜ. Its two source groups cannot simply be treated as the same group. The workbench keeps the encrypted signature/σ₁/σ₂ in G₁, publishes Alice's signer key in G₂, and represents Carol's one secret exponent in **both** G₁ (for signed-ElGamal) and G₂ (for pairing). It adds a noninteractive same-secret dual-group key certification, checked with two elliptic equations and a domain-separated challenge.

**That extra certificate is our protocol modification.** Although it is mathematically checked in the research suite, it has NOT been proven to preserve the original paper's signer/confirmer security, invisibility, or non-transferability theorem. This is precisely why the site remains research-only.

## Paper and implementation audit matrix

| Mechanism or claim | What is published | Current implementation evidence | What remains missing |
|---|---|---|---|
| BLS signature | Boneh–Lynn–Shacham short signatures and hash-to-curve; Wang et al. (2011), §2 | Genuine BLS12-381 G₁/G₂ points, bilinearity and modified-message negative fixtures | Source-paper symmetric instantiation; exact author encoding |
| Signed ElGamal | Wang–Xia–Zhao (2011), §4 and Xia (2013), Ch. 5 | Actual issuance, format validation, Carol decryption, independently checked pairing | Proof its Type-3 adaptation meets the paper's security model |
| Unified OR confirmation | 2011 paper's Figs. 2–3, Xia (2013) Figs. 5.1–5.2 | Both role secrets yield accepted five-equation public checks; false claim is refused | Malicious-verifier/concurrent-ZK compiler and proof security |
| Disavowal | 2011 paper's Figs. 4–5, Xia (2013) Figs. 5.3–5.4 | Source contradiction is regression-tested; candidate inequality relation has kernel-checked field-model completeness and OR special soundness, a sampling theorem, real-group extraction and adversarial tests | Author reconciliation, concrete-group/code refinement, full OR distribution and malicious/concurrent ZK/non-transferability proofs, independent review |
| Non-interactive designated-verifier proof | Jakobsson–Sako–Impagliazzo (1996), §5 (pp. 149–150), Definitions 1–2, §7 | Both allowed origins produce proofs one verifier accepts; the origin bijection is checked exactly; a second library recomputes every equation; eight mutations are killed by named tests | Definition 3 (strong designated verifier), §6 multiple verifiers, a ROM theorem the paper does not give, and independent review. See [DESIGNATED-VERIFIER.md](DESIGNATED-VERIFIER.md) |
| Recorded transcript | Sigma-protocol HVZK/simulation concepts and formal DCS definitions | Public-only simulators produce accepting math for false/true statements when they choose their own challenges | **No claim** that the actual browser interaction implements the original paper's full non-transferability security |
| 2016 full verification | Xia et al. (2016), a DIFFERENT commitment + labeled CCA2 encryption construction | Separate 2016-oriented toy research under research/ | Not interchangeable; never mix implementation claims |

### Primary sources

- **Guilin Wang, Fubiao Xia, Yunlei Zhao (2011)**, *Designated Confirmer Signatures With Unified Verification*, IACR ePrint 2011/182: https://eprint.iacr.org/2011/182
- **Fubiao Xia (2013)**, *Designated Confirmer Signatures: Modelling, Design and Analysis*, University of Birmingham PhD thesis, Chapter 5 and proof/security-model chapters: https://etheses.bham.ac.uk/4579/1/Xia13PhD.pdf
- **Yingjie Xia, Xuejiao Liu, Fubiao Xia, Guilin Wang (2016)**, *A Reduction of Security Notions in Designated Confirmer Signatures*, TCS 618: https://doi.org/10.1016/j.tcs.2015.12.025
- **Jan Camenisch, Victor Shoup (2003)**, *Practical Verifiable Encryption and Decryption of Discrete Logarithms*: https://www.shoup.net/papers/verenc.pdf
- **RFC 9380**, *Hashing to Elliptic Curves*: https://www.rfc-editor.org/rfc/rfc9380
- **Noble Curves**, BLS12-381 implementation, pin version 2.4.0: https://github.com/paulmillr/noble-curves

## Important disavowal contradiction — explicitly NOT silently repaired

The printed figures define a beta quantity using (D^x/C)^a and also specify C=D^x. In any cyclic group with those assumptions this ratio is the identity for **all** x and a. However, the verifier then demands beta ≠ 1. Those conditions cannot be simultaneously satisfied if transcribed literally. This contradiction occurs in both 2011 ePrint Figure 4/5 and Xia's 2013 thesis Figures 5.3/5.4.

For the **actual intended inequality** A≠B^x, an algebraically consistent candidate chooses beta=(B^x/A)^a, with a≠0. It can check:
  z_key = D^b₁ / C^b₂;
  z_pair = beta^c · B^b₁ / A^b₂,
with b₁=e−c·x·a and b₂=e'−c·a.

Those equalities hold and are independently verified by the research code. This is an ORIGINAL RECONSTRUCTION of an intended proof statement, NOT an erratum, publisher-approved repair, or a substitute for cryptographic proof review. The local prime-order protocol now has a written two-special-soundness and special-HVZK argument, with an executable extractor and an order-two attack regression; see [DISAVOWAL-PROOF.md](DISAVOWAL-PROOF.md). Independent review, malicious/concurrent-verifier security and full DCS security remain open.

## What a visitor can learn without being misled

1. A real signature can be encrypted so that ordinary third-party verification is unavailable without extra cryptographic steps.
2. An authorized prover can participate in an OR confirmation proof using one of two private witnesses.
3. Confirmation failure is **not** affirmative disavowal; a separate inequality witness relation is needed, and the published Fig. remains under review.
4. A mathematically passing transcript does not prove a live honest verifier selected its challenge. The simulator explicitly demonstrates this even with **real** BLS12-381 arithmetic.
5. A valid signature does not mean the document's assertion is factually true.
6. A designated verifier can interpret an equation-valid proof using private knowledge of whether they produced it. From the transcript alone, an outsider cannot establish statement truth or proof origin because that verifier could have written it. This differs from both the interactive exchange and the publicly verifiable contrast.

## Go / no-go gate

Full DCS release is **NO-GO** until independently reviewed:
- the final publication-specific protocol definition with an explicit Type-3 reduction theorem (or implement the paper's symmetric instantiation directly);
- the correct disavowal proof statement and transcript as verified by sources/errata;
- unforgeability/invisibility and verifier soundness against adaptive chosen-message attacks;
- malicious- and concurrent-verifier zero knowledge and honest-verifier simulation limits;
- verified canonical encodings, subgroup checks, key registration, domain separation, replay/session binding, range checks and interoperability vectors;
- mutation-checked correctness, browser accessibility and separate security review.

**The current workbench is a genuine mathematics demonstration, not a cryptographic security certificate.** Do not issue real-world signatures or confidential documents through it.
