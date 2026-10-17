# π1 research — source-defined witness relations, NOT a confirmation protocol

**Status: RESEARCH-ONLY ALGEBRAIC PREFLIGHT. The user-facing designated confirmer protocol is still NOT implemented.**

**Source:** Fubiao Xia, [2013 doctoral thesis](https://etheses.bham.ac.uk/4579/1/Xia13PhD.pdf), Chapter 6 §6.5.1 and §6.5.2, PDF pp.150–153, especially the stated π1 relation on p.150/152 and challenge-response equations on p.153. This is the precursor to the selected 2016 paper, not a verified verbatim replacement for its final version.

## Relation that an honest confirmer would need to prove

Using the signer's or confirmer's labeled ciphertext (u,e,v), recipient key (x1,x2,x3), encryption public key (g,h,y1,y2,y3), the claimed message digest m and commitment ψ, the source's π1/π2 statement includes:

\`\`\`text
y1  = g^x1                          (mod n²)
y2  = g^x2                          (mod n²)
y3  = g^x3                          (mod n²)
e²  = u^(2x1) · h^(2r)              (mod n²)
v²  = u^(2x2) · u^(2H(u,e,L)x3)     (mod n²)
α   = ψ · δ^(−m) = γ^r             (in the commitment group Γ)
l   = g2^r · h2^s                  (in a second common-reference-string group)
\`\`\`

The published relation also requires bounds on the witnesses and proof challenges, plus a conversion to the appropriate concurrent-ZK protocol before DCS security claims. The thesis writes the public interaction as separate **commit → unpredictable verifier challenge → masked response → verify** stages. **Simply checking these seven equations with the witness in hand is not the protocol.**

The [research module](pi1-relation.mjs) deliberately requires the private encryption exponents, r and s as its inputs and checks all seven relations independently, plus a separate call to the existing toy labeled-ciphertext decryption. It returns only named per-equation booleans and \`relationSatisfied\`. It never calls any result a \`CONFIRMED\` signature or pretends to keep the witness hidden.

## Deliberately insecure parameter choices

- First group: n = 253 = 11·23, n² = 64009. Both primes are instantly factorable; the thesis's soundness assumptions do not apply.
- Commitment group: \`Γ⊂ℤ23*\` with order 11, generator δ=2 and γ=8; their discrete-log relationship is publicly known, so the binding assumption fails.
- Second CRS modulus: 2773 = 47·59, g2=16 and h2=81, with publicly obvious construction and factors; this is not a secure setup.
- All statements are synthetic and all operations are local Node research code. Nothing is wired into \`prototype/\` or GitHub Pages.

## What the tests actually establish

The nine new arithmetic tests in [pi1-relation-research.test.mjs](../tests/pi1-relation-research.test.mjs) cover a deterministic valid witness, wrong encryption exponents, wrong opening, wrong message, tampered e/v/ψ, altered label, modified auxiliary witness or public value, and out-of-domain inputs. They establish that these particular **checks are executable and reject chosen counterexamples**; they are not published cryptographic test vectors, a security proof, or a zero-knowledge protocol demonstration.

## Blocking questions before the interactive confirmation can be written

1. **Precise π1 verifier transcript:** §6.5.2 shows explicit public elements, a k-bit challenge, five masked responses and seven verification equations. Reproduce these faithfully, with strict group/range validation, *and compare to the final 2016 paper*. The current witness inspector does none of the protocol communication.
2. **Odd bound in the printed response equation:** On thesis PDF p.153 the displayed check appears to require \`−n/4 < r̃ < n/4\`, while its preceding response is \`r̃ = r'−c·r\` with r' sampled over a much larger interval. Determine whether the bound is mistranscribed, applies to a balanced remainder, or is an error. Do not invent a rule or weaken verification to force tests green.
3. **Commitment group and ciphertext modulus:** The thesis requires compatible security parameters and distinct unknown-factorization CRS structures. Our tiny toy groups intentionally satisfy none of those requirements.
4. **Concurrent zero knowledge:** The preliminary three-move relation is not automatically a concurrent-ZK or non-transferable proof; the required compiler and simulator theorem must be identified and implemented separately.
5. **Disavowal is a distinct OR proof:** The thesis p.153–154 points to Camenisch–Shoup §7.3 for the disavowal relation. A failed confirmation, invalid ciphertext, or \`false\` from our relation checker **does not constitute affirmative disavowal**.
6. **Whole DCS:** A signature on ψ, two labeled encryptions of opening r, proper initial π0, secure confirmation/disavowal, extraction/conversion if supported and strict transcript binding still require independent implementation and mathematical review.

## Gate

The proof cannot be presented as a working designated confirmer signature, and these checks cannot justify publishing a main catalog card. Continue to call the repository **research-only** until the full source-derived protocols and independent adversarial verification are complete.
