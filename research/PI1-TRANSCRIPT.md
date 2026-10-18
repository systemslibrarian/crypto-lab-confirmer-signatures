# Interactive π1 / π2 precursor: an independently verified toy transcript

**Status: THREE-MESSAGE TOY ARITHMETIC ONLY — NOT genuine designated-confirmer confirmation, NOT zero knowledge at secure parameters, and NOT an implementation of the final 2016 scheme. The release gate remains CLOSED.**

Primary source: Fubiao Xia, *Designated Confirmer Signatures: Modelling, Design and Analysis* (University of Birmingham, 2013), Chapter 6 §6.5.2, PDF pages 152–154. The source sets out the interactive pi1 and corresponding pi2 relation, then says the preliminary special-HVZK proof must be transformed into the required concurrent-zero-knowledge form. The 2016 Xia et al. journal paper remains unreconciled, so this is **2013-thesis-specific research**.

## Statement and three messages

For public labeled-Paillier key (g, y1, y2, y3), labeled ciphertext (u,e,v), commitment ψ, message m, and auxiliary proof element ℓ, let H=H(u,e,L) and α=ψ·δ^(−m). An honest prover knows (x1,x2,x3,r,s) such that:

- yi=g^xi for i=1,2,3.
- e²=u^(2x1) h^(2r).
- v²=u^(2x2 + 2H x3).
- α=γ^r.
- ℓ=g2^r h2^s.

**Round 1 — prover's first message.** Choose independent signed masks x1',x2',x3',r',s'. Publish yi'=g^(xi'); e'=u^(x1')h^(r'); v'=u^(x2'+H x3'); α'=γ^(r'); ℓ'=g2^(r')h2^(s').

**Round 2 — verifier's challenge.** Independently sample c in {0,1,2,3} after receiving the first message. This **two-bit** challenge is intentional toy scale and NOT meaningfully sound.

**Round 3 — prover's response.** Return signed integers xiTilde=xi'−c xi, rTilde=r'−c r and sTilde=s'−c s. The prover's private witness and masks are NOT transmitted.

**Verifier's seven checks, all public-only:**

1–3. yi' = yi^c · g^(xiTilde) for i=1,2,3.
4. (e')² = e^(2c) u^(2x1Tilde) h^(2rTilde).
5. (v')² = v^(2c) u^(2x2Tilde + 2H x3Tilde).
6. α' = α^c γ^(rTilde).
7. ℓ' = ℓ^c g2^(rTilde) h2^(sTilde).

Each equality is tested by a verifier that has no decryption key and does not call the private-witness inspector. A true result means **only these seven toy equations hold**, NOT a valid DCS or a complete confirmation proof.

## Assumptions intentionally NOT met

- **Factorable modulus and public trapdoors.** Paillier n=11×23, group Γ has order 11 and the auxiliary modulus is also factorable. The tiny parameters destroy the source's security assumptions.
- **Challenge soundness absent.** c=0 occurs with probability 1/4; in that case the seven equations may hold even after ψ is changed, because the α^c factor is 1. A passing negative-control test demonstrates this vulnerability. This is evidence AGAINST making a secure confirmation claim.
- **No exact-range proof.** The printed thesis check appears to bound the masked response rTilde by n/4, although the preceding masking interval is much larger. This code checks only coarse demonstration-specific bounds. It does **not** silently rewrite the author's bound, prove strict soundness or implement the exact-interval proof required for disavowal.
- **No anti-replay.** Reusing the identical transcript under the identical public statement and challenge still checks out; an explicit negative fixture documents this, rather than pretending browser role panels enforce session isolation.
- **No final-spec reconciliation.** This demonstrates 2013-thesis arithmetic, not the exact 2016 final journal DCS construction.
- **No complete issue/verification.** The checker receives no BLS signature on ψ, no full π0 consistency certificate, and no affirmed disavowal OR proof. It does not check DCS validity.
- **No concurrent-ZK compiler or formal non-transferability proof.** The paper's security claims cannot be inferred from ordinary Sigma-protocol-style arithmetic, a web animation, or unit test success.

## Testable progress

New module: research/pi1-interactive-toy.mjs. New tests: tests/pi1-interactive-toy.test.mjs. Run the complete research suite with the existing GitHub Actions workflow or locally with the command: node --test tests/*.test.mjs.

The tests cover a public-only seven-equation verifier, independent verifier challenges, 24 randomly masked runs, malicious changes to each proof field, changed messages, keys, ciphertext fields, labels and auxiliary commitments, malformed values, incorrect private witnesses and the two deliberate counterexamples (zero-challenge weakness and transcript replay).

**Release decision remains NO-GO.** This advances Chapter 02's mathematical prerequisite only. Do not unlock the interface chapter, claim a DCS, deploy Pages or add the main catalog card. The next gates are final-paper comparison, resolution of the odd response-bound statement, independent proof-oracle review, and a true OR proof of invalidity with exact-range enforcement.
