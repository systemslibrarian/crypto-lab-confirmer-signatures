# Source reconciliation — Xia's 2013 thesis and final 2016 paper

**Status: OPEN SPECIFICATION DISCREPANCY for proof equations, parameters and security model.** The earlier FOUR-vs-FIVE component confusion is now **resolved at the published algorithm-inventory level**: the 2016 journal introduction abbreviates the issuing tuple, while its detailed Section 6 explicitly describes a five-component object including π0. This is NOT evidence that every 2013 proof equation or toy parameter choice carries over unchanged to the final 2016 scheme.

## Primary sources examined

1. **Complete 2013 thesis:** Fubiao Xia, [Designated Confirmer Signatures: Modelling, Design and Analysis](https://etheses.bham.ac.uk/4579/1/Xia13PhD.pdf), Chapter 6 §§6.3 and 6.5; the 2013 thesis expressly issues a commitment, ordinary signature, two encrypted openings, and an initial equality subproof π0.
2. **2016 journal indexed publication, introduction and detailed portions of §§6–7:** Yingjie Xia, Xuejiao Liu, Fubiao Xia, Guilin Wang, [A reduction of security notions in designated confirmer signatures](https://doi.org/10.1016/j.tcs.2015.12.025), *Theoretical Computer Science* **618**, pp. 1–20. The 2016 journal **introduction summary** describes four high-level objects. Crucially, its later §6 extraction algorithm explicitly consumes the five-object sequence including π0, and §7.2 defines the π0 equality-of-encrypted-opening subproof. These source-visible portions establish that the introduction was abbreviated; **we still lack a line-by-line independent transcription of the complete final article**.
3. **Primary proof component:** Jan Camenisch and Victor Shoup, [Practical Verifiable Encryption and Decryption of Discrete Logarithms](https://www.shoup.net/papers/verenc.pdf), §7.3. Its verified-decryption and OR-invalidity building blocks are not a stand-alone DCS.

## Resolved tuple issue versus unresolved full protocol

| Source | Issuing object | What the evidence establishes |
|---|---|---|
| 2013 thesis §6.3 | Five listed objects: (ψ,σ,cS,cC,π0) | Explicit equality proof plus subsequent interactive confirmation and disavowal |
| 2016 journal **introduction summary** | Four headline objects (φ,c1,c2,σ) | Editorial overview, NOT the final complete algorithm |
| 2016 journal §6 Extract and §7.2 | Detailed algorithm includes (ψ,σ,c1,c2,π0) | π0 is present; §7.2 gives a subproof tying the two encrypted opening values via their e components |

**What this does NOT establish:**

- The full 2016 byte encodings, exact challenge distributions, signatures, public statement, supported groups, proof bounds or malicious/concurrent-verifier compiler. Those cannot be inferred from a summarized formula.
- **Commitment linkage:** the π0 relation explicitly checks equality of the encrypted openings. The verifier equation shown in §7.2 contains e1/e2 and key elements, NOT ψ. It does **not** prove by itself that ψ is a commitment to the *claimed message*. The issue is **not** “missing π0”; it is the exact relationship between π0 and the rest of the verification protocol.
- **Ciphertext validity:** the e-component equality proof does **not** validate complete u/e/v triples, ciphertext labels or recipient proof rules. Separate validation is mandatory.
- **Disavowal:** Camenisch–Shoup §7.3 describes special OR and exact-range machinery. Our existing four-way local diagnostic is NOT an affirmative sound disavowal proof.
- **Non-transferability:** a basic three-move protocol, even with an algebraically correct public verifier, does NOT prove the full security notion for arbitrary/malicious interacting verifiers.

## Source-aligned code status

The [toy issuance path](issued-envelope-toy.mjs) now computes ψ, signs ψ with a *real* WebCrypto ECDSA signature, encrypts the same toy opening for S and C, and checks a toy π0 e-component equality proof. The [research confirmation orchestrator](toy-confirmation-session.mjs) privately decrypts an opening and runs the seven-equation toy π1/π2 precursor with an independent public-only checker. Neither is a source-compliant DCS.

This implementation uses n=11×23, insecure parameters, locally selected label/encoding rules, intentionally tiny challenges, and does not run the final proof compiler. Its positive tests prove execution of the stated toy algebra and ECDSA adapter; its negative tests show the missing binding and soundness conditions. **Do not interpret a partial test pass as production or full DCS validity.**

## Remaining gate for a genuine full implementation

- [ ] Obtain/review the COMPLETE final 2016 §§6–7 and Appendix A, not only indexed excerpts; fix source lines for Setup, DCSSign, π0, π1, π2, Confirm(S,V), Confirm(C,V), both Disavow protocols and Extract.
- [ ] Pin canonical statement / label encoding, group assumptions, exact witness intervals, challenge ranges, session binding and proof security model. Explain the counterintuitive printed range bound; do not relax it to get green tests.
- [ ] Implement independently checked complete π0 and the required concurrent-ZK transformations, with genuine security parameters.
- [ ] Implement affirmative Camenisch–Shoup disavowal OR proof and exact-interval proof; a rejected confirmation is not sufficient.
- [ ] Obtain independent test oracle and specialist review against the final published construction before shipping the full interactive UI.

**Decision: issuance inventory reconciled, full protocol implementation/release gate remains CLOSED.** The original four-part introductory wording **does not** prove omission of π0; the detailed paper includes it. This correction is an evidence improvement, not a release approval.
