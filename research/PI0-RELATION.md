# π0 research note — equality of two encrypted openings

**Status (2026-10-17): partial equation-level exercise, NOT a usable designated confirmer signature, NOT a soundness or zero-knowledge security proof.**

**Primary source:** Fubiao Xia, *Designated Confirmer Signatures: Modelling, Design and Analysis* (University of Birmingham, 2013), [full 175-page thesis](https://etheses.bham.ac.uk/4579/1/Xia13PhD.pdf), Chapter 6 §6.5.1–§6.5.2, PDF pages 148–152 (the relevant π0 proof messages appear on PDF page 152). **Caveat:** the thesis predates Xia *et al.*'s 2016 paper. The 2016 publication has NOT been compared line-by-line; the thesis is a research source, not conclusive 2016 implementation guidance.

## Source's displayed subrelation

Two ciphertexts are each created by a different encryption public key but share the same hidden plaintext/opening **r**. Their components satisfy:

\`\`\`text
eS ≡ yS1^tS · h^r  (mod n²)
eC ≡ yC1^tC · h^r  (mod n²)
\`\`\`

The statement shown in the thesis is an equality-of-plaintext proof for these **e components**. It is not sufficient on its own to certify both complete ciphertext triples **(u,e,v)** or that r opens a separate commitment ψ.

The published §6.5.2 proof outline chooses random integer masks ηS, ηC and ω and constructs:

\`\`\`text
WS = yS1^ηS · h^ω  (mod n²)
WC = yC1^ηC · h^ω  (mod n²)

c  = H(WS || WC) in the challenge space
D  = ω + c·r
D1 = ηS + c·tS
D2 = ηC + c·tC
\`\`\`

An independently run verifier recomputes, with modular inverses for the negative powers:

\`\`\`text
WS' = yS1^D1 · h^D · eS^(−c)  (mod n²)
WC' = yC1^D2 · h^D · eC^(−c)  (mod n²)

accept THIS SUBRELATION only when c == H(WS' || WC')
\`\`\`

The verification equations follow from cancelling the ciphertext factors. They are implemented in [pi0-equality.mjs](pi0-equality.mjs). [The tests](../tests/pi0-equality-research.test.mjs) independently re-derive both reconstructed commitments and test honest and tampered transcripts.

## What the executable experiment demonstrates

- Prover checks that two toy labeled-Paillier ciphertexts were originally constructed with identical opening r and known randomness tS,tC.
- The transmitted proof has **only c, D, D1, D2**. No decryption key or opening r is passed to the verifier.
- The verifier checks the above arithmetic from the **public** e components and public encryption keys.
- Wrong public-key relations, wrong e components, inconsistent honest witnesses, altered responses and malformed encodings fail the test fixtures.

**Crucial negative-claim fixture:** The public verifier accepts this subrelation when a separate commitment ψ is changed, because **ψ is not a verifier input**. A ciphertext's v component can likewise be altered without necessarily invalidating this e-only proof. These are **counterexamples to treating the subrelation as a complete DCS check**, not claims that the whole published DCS is insecure. Complete DCS verification must do more than this.

## Parameters and limits — cannot be used for secure cryptography

| Item | Toy implementation | Published-security consequence |
|---|---|---|
| Paillier modulus n | 253 = 11·23 | Trivially factorable |
| Group modulus | n² = 64009 | Tiny; not secure |
| Challenge width | 24 bits | Far below cryptographic soundness |
| Slack width | 4 bits | Far below statistical ZK security |
| Commitment order symbol ρ | 11, only for toy blinding range | Does not instantiate the required Γ group |
| Challenge derivation | SHA-256 over fixed-width hexadecimal WS/WC and a local domain label, truncated to 24 bits | The thesis excerpt does not define this exact encoding; there are **no author test vectors** |
| Transcript security | No concurrent ZK compiler; no CRS; no production parameter generation | Non-transferability and zero knowledge **not established** |

**The thesis's parameter inequalities are knowingly violated**, particularly the requirement that the challenge space be smaller than the applicable safe-prime subgroup factors. All code is under \`research/\` using Node's crypto module, and none of it is wired into the public visitor prototype.

## Open blocking questions before declaring π0 implemented

1. **Commitment binding:** The generic description (§6.3) says π0 ties both encryptions to the same opening as the commitment ψ, but the explicitly displayed equation in §6.5.1/§6.5.2 includes **eS and eC, not ψ**. Establish whether the complete 2016 protocol includes an additional relation/check, whether the commitment link is deferred to π1/π2, or whether the statement as printed is incomplete. Do not silently assume the gap is closed.
2. **Full labeled ciphertext relation:** The e-only equation does not certify u or v. Identify exactly what other checks are needed, which party can perform them, and whether the proof compiler requires them as public relations.
3. **Transcript domain and replays:** The paper's c = H(WS||WC) representation does not visibly include the statement, labels, participants or session context. The local hash format above is an explicit demonstration choice, **not** a researched replacement for the paper's security proof. Independent analysis must determine correct binding.
4. **Proof soundness:** The relation is demonstrated over a factorable tiny group with a 24-bit challenge. Neither witness extraction nor zero knowledge nor non-transferability has been established.
5. **2016 confirmation/disavowal:** The verifier equations for π1 and π2 and affirmative disavowal protocols, including the OR relation and concurrent-ZK compiler, still need a source-faithful specification, independent implementation and adversarial review.

## Release rule

The test suite may pass as a **research arithmetic** exercise while the [research gate](../RESEARCH-GATE.md) remains **CLOSED**. Do not add DCS signing buttons, private confirmation/disavowal verdicts, GitHub Pages deployment or a main Crypto Lab catalog card on the strength of this subproof.
