# Source reconciliation — 2013 thesis versus 2016 journal introduction

**Status: OPEN SPECIFICATION DISCREPANCY.** This document prevents thesis equations from being accidentally attributed to the final 2016 journal algorithm. It does **not** claim that a particular final protocol is missing a proof or that either paper is incorrect.

## Materials actually examined

1. **Complete thesis:** Fubiao Xia (2013), [*Designated Confirmer Signatures: Modelling, Design and Analysis*](https://etheses.bham.ac.uk/4579/1/Xia13PhD.pdf), Chapter 6 §§6.3 and 6.5. The explicit procedure \`DCSSign\` includes an initial consistency proof, written as \`π0\`, alongside a commitment, underlying signature, and separately encrypted openings.
2. **Accessible journal article introduction and abstract:** Yingjie Xia, Xuejiao Liu, Fubiao Xia, Guilin Wang (2016), [*A reduction of security notions in designated confirmer signatures*](https://doi.org/10.1016/j.tcs.2015.12.025), *Theoretical Computer Science* **618**, pp. 1–20. The accessible **introductory overview** describes the output as the four components \`(φ, c1, c2, σ)\`, with a later zero-knowledge confirmation that the decrypted randomness opens the commitment.
3. **Complete underlying proof building block:** Camenisch and Shoup (2003), [*Practical Verifiable Encryption and Decryption of Discrete Logarithms*](https://www.shoup.net/papers/verenc.pdf), §7.3. Its affine/verifiable decryption relations and invalidity OR cases are independently accessible, but **do not define the 2016 DCS tuple**.

## Difference we can establish, and difference we cannot

| Source | Issuing object listed in accessible text | Proof described |
|---|---|---|
| Xia 2013 thesis Chapter 6 full \`DCSSign\` | \`(ψ, σ, cS, cC, π0)\` — five listed objects | Explicit initial equality/consistency \`π0\`; separate later interactive confirmation/disavowal |
| Xia et al. 2016 journal **introduction summary** | \`(φ, c1, c2, σ)\` — four listed objects | Interactive zero-knowledge proof after decrypting an opening; whether final §§6–7 also add \`π0\` is **unconfirmed** |

**What the source does not entitle us to infer:**

- The shorter journal introduction does **not** prove the actual algorithms in §§6–7 omit \`π0\`. Introductions can summarize or leave out auxiliary proof material.
- Conversely, the complete **2013** \`DCSSign\` tuple does **not** prove the **2016** implementation necessarily has the same initial \`π0\`, equations, wire encoding, or challenge distributions.
- The exact \`π0\` relation in the 2013 thesis visually links the two encrypted e components; the displayed equation does not explicitly mention the message commitment \`ψ\`. It is not safe to assert that our implemented \`π0\` subproof ties \`ψ\` to a claimed message. Independent negative tests intentionally demonstrate that it does not.
- Camenisch–Shoup's affirmative OR proof is not automatically a complete 2016 \`Disavow\` algorithm.

## Impact on the implementation and security gate

Our current \`research/\` executable toy arithmetic is **2013-thesis-inspired** and built from **2003 Camenisch–Shoup source relations**; it is not claimed to implement Xia et al.'s final 2016 DCS. The research lab can continue to test algebra and disavowal predicates but cannot label any of those exercises **“2016 DCS issuance,” “2016 complete π0,” “2016 Confirm,” or “2016 Disavow.”**

**Version-specific acceptance:** If we choose to implement the **2013 scheme**, its \`π0\` requirement remains mandatory, along with all actual proof statements and their correct security parameters. If we instead implement the **2016 scheme**, the decision must be made only after obtaining and scrutinizing the **complete final §§6–7 and security appendix**, recording every issued item and protocol obligation actually specified there. Neither a four-part object nor a five-part object should be accepted on the basis of an overview or guess.

## To close this discrepancy

- [ ] Obtain a legally accessible **complete publisher/author manuscript** of the final 2016 article, especially §§6–7 and the proof appendix. The publisher's indexed introduction does **not** replace the full algorithms.
- [ ] Make an explicit one-page, line-by-line table of 2016 \`KGen, DCSSign, Confirm(S,V), Confirm(C,V), Disavow(S,V), Disavow(C,V), Extract\` versus 2013 §6.3. Include **the full \`π0\` status**.
- [ ] Check all witnesses, commitment relation, ciphertext label, proof statement, challenge distribution, and security model. If there is a legitimate version change, choose **one** of the actual constructions rather than mixing algorithms.
- [ ] Independent mathematical review of transcript equations and source scope before enabling any DCS verdict or live deployment.

**Current decision:** the 2016 specification reconciliation gate is **OPEN / BLOCKING**; the DCS implementation/release gate remains **CLOSED**. The 49 passing research tests do not settle the papers' differences.
