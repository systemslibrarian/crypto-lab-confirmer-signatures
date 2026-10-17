# Source extraction: Xia 2013 thesis, Chapter 6

**Status: mathematics research and intentionally insecure arithmetic test ONLY. This is NOT a complete DCS construction, nor is it deployable cryptography.**

This is a substantial improvement over relying on the 2016 article's abstract. Fubiao Xia (a coauthor of that later paper) wrote an openly accessible 175-page doctoral thesis, *Designated Confirmer Signatures: Modelling, Design and Analysis* (University of Birmingham, January 2013), available at https://etheses.bham.ac.uk/4579/1/Xia13PhD.pdf. Its **Chapter 6** contains a closely related generic full-verification DCS construction, concrete parameters and explicit equations for the labeled encryption and zero-knowledge protocols. Because the thesis **predates** the 2016 journal article, do not call their equations identical without a line-by-line comparison of the final paper.

## Thesis sources and what they establish

| Location (PDF page index) | Source mechanism | Status |
|---|---|---|
| §§6.2.1–6.2.2, pages 136–138 | Pedersen commitment and Camenisch–Shoup labeled-Paillier encryption with actual (u,e,v) validity check | **Toy labeled-encryption arithmetic implemented and tested**, not production safe |
| §6.3, pages 139–141 | KGen, basic signing, DCSSign=(ψ,σ,c1,c2,π0), Confirm(S,V), Confirm(C,V), Disavow(S,V), Disavow(C,V), Extract | **Source inventory only** |
| §6.5.1, pages 147–151 | Concrete bilinear/BLS commitments, CS-Paillier components, the π0, π1, π2 relations and OR statement for disavowal | **Full cryptographic extraction not verified** |
| §6.5.2, pages 151–155 | Challenge/response equations, preliminary HVZK proofs, validity checks, required conversion to concurrent ZK | **Not implemented or independently verified** |

The source specifies, for safe-prime-based modulus n=pq, M=n², h=1+n, g=g₀^(2n) and yᵢ=g^(xᵢ):

- Encrypt opening randomness r, with fresh t and nonempty label L: u=g^t, e=y₁^t h^r, v=abs((y₂ y₃^H(u,e,L))^t) modulo M.
- Decrypt only when v=abs(v) and u^(2(x₂+H(u,e,L)x₃))=v² modulo M. Then recover h^r using (e/u^(x₁))^(2k), where k=2⁻¹ mod n, and check that (h^r−1)/n is a well-formed plaintext.
- Commit as ψ=δ^m γ^r; sign **the commitment**, not the plaintext. The two encryptions are tied through an initial consistency proof π0; later confirmation and disavowal require *different* sound interactive proofs.

These equations do not prove the whole scheme secure simply because they can be calculated.

## New executable arithmetic — extremely small and insecure

The code in research/cs-paillier.mjs uses deliberately tiny safe primes **p=11, q=23, n=253** to make the published encryption/decryption algebra inspectable. An ordinary computer can factor 253 instantly; all claimed IND-CCA2, commitment, soundness, non-transferability and secrecy assurances **do not apply** to this demonstration. No data leaves local Node; no DCS UI or publication is enabled.

The regression suite tests/cs-paillier-research.test.mjs independently checks the arithmetic equations and exercises invalid elements, out-of-domain inputs and altered values. It contains no official DCS test vectors and is **not** evidence of a secure labeled encryption implementation. The research module uses SHA-256 over an explicit encoding as a **local implementation choice** for the label hash, not an assertion that the thesis mandates this encoding or that it is adequate for a full proof.

## Six critical issues still open

1. **The 2013 and 2016 constructions must be reconciled.** Thesis Chapter 6 is directly useful, but the final paper is the selected specification; obtain and compare final equations and errata before DCS implementation.
2. **Apparent typo in §6.5.1:** Enc(yS,m) and Enc(yC,m) appear in the opening sentence (PDF p.149), while immediately displayed ciphertext equations encrypt opening *r*, and §6.3 expressly encrypts *r*. Do not copy this inconsistency into code.
3. **Public commitment binding by π0:** the source says π0 ties both encrypted openings to commitment ψ, but the displayed π0 proof expression on p.149 explicitly describes the equality of opening exponents for e1 and e2 and does not visibly include ψ. Investigate whether additional equations or verification rules close this gap. A proof that c1 and c2 contain the same r is **not itself** a proof that ψ opens with r.
4. **BLS pairing mismatch:** §6.5.1 assumes *symmetric* pairings; modern BLS12-381 libraries use asymmetric type-3 pairings. The existing Pairing Gate cannot be transplanted without independent group-placement and security analysis.
5. **Full proof of INVALIDITY required:** Disavow(S,V) and Disavow(C,V) each require a source-defined valid interactive OR proof establishing an invalid ciphertext **or** an opening inconsistent with the claimed message and commitment. A failed confirmation, tag check, or withheld response is not such a proof.
6. **Concurrent ZK and parameter bounds:** §§6.5.1–6.5.2 assume additional common-reference-string moduli, strict challenge ranges, and conversion of preliminary zero-knowledge protocols to malicious/concurrent-verifier security. The toy encryption code satisfies **none** of these cryptographic security assumptions.

## Next protocol gates

1. Transcribe π0, π1, π2 and both disavowal branches into a numbered set of proof statements, messages, equations and validation boundaries, checked against the final 2016 paper.
2. Verify the public commitment/ciphertext link, group choices, labels, challenge distributions, sessions and security proofs with an independent reviewer and implementation oracle.
3. Only after that, implement the complete Setup/DCSSign/Confirm/**affirmative** Disavow in the browser, then the master's UI/a11y/correctness/deployment requirements. **Research gate stays CLOSED until those are verified.**
