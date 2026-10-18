# SCHEME-NOTES — source-backed DCS structure and open mathematical questions

**Status: PARTIAL TRANSCRIPTION, NOT IMPLEMENTABLE SPECIFICATION (2026-10-17).** Do not use this as an algorithm to sign, confirm or disavow. Chapter 01's working P-256 ECDSA signatures are a **public-signature baseline only** and are not components claiming fidelity to the chosen DCS construction.

## Selected research candidate

Yingjie Xia, Xuejiao Liu, Fubiao Xia, Guilin Wang, *A reduction of security notions in designated confirmer signatures*, Theoretical Computer Science **618** (2016), 1–20, [DOI: 10.1016/j.tcs.2015.12.025](https://doi.org/10.1016/j.tcs.2015.12.025). The publisher's article contains **§6 generic construction, §7 concrete instantiation, Appendix A security analysis**. The complete equation-by-equation protocol and proof implementation has NOT been independently transcribed or checked yet.

### The five-part issuing inventory — confirmed in 2013 thesis and detailed 2016 Section 6

A designated confirmer signature is **not** a basic signature simply encrypted for Carol. Xia's **2013 thesis Chapter 6** and the final **2016 journal's detailed §6 Extract / §7.2 π0** describe a message commitment, an ordinary signature over that commitment, two independently encrypted opening values, and an initial consistency proof. The **2016 introduction abbreviates** this as four headline components, but the detailed sections include `π0`. This resolves the earlier *tuple-count* discrepancy, not the full proof specification. See [SOURCE-RECONCILIATION.md](research/SOURCE-RECONCILIATION.md). The following five-part notation reflects the shared documented **issuing inventory**, not a fully verified byte-level 2016 protocol:

```text
ψ    = Com(m; r)                 message commitment
σ    = Sig(sk_signer, ψ)         ordinary signature on the commitment ψ
cS   = Enc(pk_signer, r)         signer-readable encryption of opening randomness
cC   = Enc(pk_confirmer, r)      confirmer-readable encryption of same opening
π0   = NIZK(statement, witness) proves:
       both ciphertexts properly encrypt the SAME r
       corresponding to the opening of ψ
DCS  = (ψ, σ, cS, cC, π0)
```

**Version-specific rule:** Both the 2013 construction and the 2016 journal's detailed §6/§7 include a `π0` component. The complete 2016 **implementation is still NOT verified as complete 2016 protocol**: proof definitions, challenge distributions, ciphertext validity, group/CRS assumptions, exact ranges and malicious-verifier security remain to be independently checked. Our toy `π0` checks the narrower e-component equality subrelation and **does not verify public message commitment ψ**.

**Equation-level progress, not full π0:** The [2013 thesis §6.5.2 subrelation](research/PI0-RELATION.md) has now been exercised with actual toy modular arithmetic in [pi0-equality.mjs](research/pi0-equality.mjs). **The displayed π0 proof equations there compare the encrypted e components but do not take ψ as an input**, despite the source's generic prose saying π0 ties the openings to ψ. Changing ψ can leave that narrower relation verified. The complete protocol cannot be certified before this discrepancy is resolved from the full 2016 text and the other checking stages. No production-security claim follows from the tiny toy tests.

Do not code from this notation: the exact *public statement* for π0, the witness/witness relations, ranges, encryption-label handling, group validation, soundness and non-transferability model must all be taken from and independently checked against the complete article.

**Partial π1 witness research:** The [research-only π1 relation inspector](research/PI1-WITNESS-RELATION.md) now checks the seven displayed source equations (ciphertext e/v, recipient encryption key consistency, ψ's opening and the auxiliary CRS group). It deliberately receives the private witness and is **not** zero-knowledge confirmation. The final paper's proof transcript, concurrent-ZK compilation and affirmative disavowal remain unresolved; no DCS verifier is available.

**Disavowal source progress:** Found Camenisch–Shoup's [complete 2003 paper](https://www.shoup.net/papers/verenc.pdf), which Xia's thesis cites for affirmative invalidity proof. [DISAVOWAL-BRANCHES.md](research/DISAVOWAL-BRANCHES.md) identifies **four** distinct source-defined failure branches and the essential exact integer interval proof. Their conditions now have 11 independently checked **toy local predicate** fixtures at n=253 in [disavow-branches.mjs](research/disavow-branches.mjs). This is not interactive disavowal: the checker knows the private decryption key and has no sound OR proof or zero-knowledge transcript. The final 2016 paper still requires independent comparison.

## A concrete instantiation is NOT just three interchangeable existing labs

The concrete paper instantiation couples:

- **Pedersen-style commitments** for ψ; the paper writes a form of `ψ = δ^m γ^r`.
- **BLS pairing signatures** over a compatible group setup for σ on ψ (paper's relation uses a bilinear pairing check).
- **Camenisch–Shoup-style labeled Paillier encryption** for the signer and confirmer opening witnesses—not basic additive Paillier.
- **π0 and confirmation/disavowal protocols** with zero-knowledge proof relations specific to these concrete commitments/ciphertexts. The article cites Boudot-style commitments/proofs in connection with π0.

The existing [Commit Gate](https://github.com/systemslibrarian/crypto-lab-commit-gate), [Pairing Gate](https://github.com/systemslibrarian/crypto-lab-pairing-gate) and [Paillier Gate](https://github.com/systemslibrarian/crypto-lab-paillier-gate) are references for understanding arithmetic, **not validated drop-in implementations** of this combined scheme. In particular, generic Paillier does not automatically satisfy the cited IND-CCA2 labeled encryption requirement.

## Separate statements that must NOT be conflated

1. **Public underlying signature:** The check `Ver(vk, ψ, σ)` does *not* establish that ψ opens to a separately claimed message m.
2. **Initial consistency π0:** A proof binding encryptions and commitment is not itself the recipient's later interactive **confirmation**.
3. **Confirmation:** A paper-defined interactive proof that a source-defined validity relation holds; both the prover equations and an independently implemented verifier are required.
4. **Disavowal:** An *affirmative* sound proof of invalidity of the alleged signature/message relation; timeout, a failed confirmation, or merely an invalid conventional signature do not count.
5. **Non-transferability:** A statement about what the recipient/observer can subsequently prove in the paper's security model—not a browser CSS visibility setting and not automatically implied by an ordinary ZK claim.
6. **Conversion or extraction:** If the paper defines this operation, implement and describe its effect on transferability separately. Do not silently disclose the underlying signature as part of “confirmation.”

## New primary-source progress and published ambiguities

An institution-hosted complete **2013 Fubiao Xia doctoral thesis**, [Designated Confirmer Signatures: Modelling, Design and Analysis](https://etheses.bham.ac.uk/4579/1/Xia13PhD.pdf), Chapters 6.2–6.5, contains detailed formulas for a closely related generic full-verification construction, with explicit sign/confirm/disavow and labeled Camenisch–Shoup encryption formulas. See [research/THESIS-EQUATIONS.md](research/THESIS-EQUATIONS.md) for extraction and mathematics still requiring reconciliation against the final 2016 paper. This supersedes the claim that no complete primary-source mathematics is available, **not** the requirement for independent review.

The thesis contains at least two load-bearing apparent inconsistencies: its concrete encryption description begins with Enc(yS,m) / Enc(yC,m) but exponentiates h^r; and π0's written proof equation visibly binds the ciphertext openings to each other without explicitly naming the public Pedersen commitment ψ, despite describing that stronger binding in prose. Do not fill these gaps by guesswork.

A tiny labeled-Paillier arithmetic demonstration now lives at [research/cs-paillier.mjs](research/cs-paillier.mjs). It passes local arithmetic checks but uses trivially factorable n=253, implements **no** DCS construction, and proves no security theorem.

## Required mathematical extraction tasks before any DCS code

- [ ] Read the **complete text, equations and any errata** of §6, §7 and Appendix A, including the `π0` proof construction and exact domain/serialization conventions. Publisher overview text alone is insufficient.
- [ ] Write `Setup`, `KGen`, `DCSSign`, `Confirm(S,V)`, `Confirm(C,V)`, `Disavow(S,V)`, `Disavow(C,V)`, `Extract`/conversion (if supported), plus verification algorithms and all witness/public statements **faithfully and independently from the publication**.
- [ ] Resolve literal notation inconsistencies if any arise (e.g. which value ciphertexts encrypt in concrete vs generic construction) against full derivations—not by guessing what the authors intended.
- [ ] Record explicit parameter, modular arithmetic, range, subgroup, label, challenge and session-binding choices. No partial acceptance of unknown/non-canonical inputs.
- [ ] Identify independent known-answer fixtures or a separate verifier oracle; **no official test vectors have been established yet** for this DCS construction.
- [ ] Establish sound confirmation, affirmative disavowal, non-transferability security model and any special-HVZK-to-concurrent-ZK compiler actually required by the chosen proof.
- [ ] Peer/independent review of the exact scheme instantiation and transcript verification before enabling an interactive DCS verdict, adding a catalog card, or deploying Pages.

## Engineering progress independent of this gate

Chapter 01, [prototype/](prototype/), uses **real WebCrypto ECDSA P-256/SHA-256** as a PUBLIC verification comparison. The RFC 6979 Appendix A.2.5 signature verification vector, independent key import, message/sig tamper failures and actual desktop/mobile user flows are checked in GitHub Actions. Those checks provide **no evidence** that any of the DCS relations above have been implemented or proved.

**Decision remains: DCS RESEARCH GATE CLOSED.**
