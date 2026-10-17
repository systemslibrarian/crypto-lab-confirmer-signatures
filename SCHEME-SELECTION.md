# Scheme selection and mathematical acceptance — Designated Confirmer Signatures

**2026-10-17 · Research decision: a defensible primary candidate is identified, but the implementation gate remains CLOSED.** This is a source-backed design review, **not** a proof that the construction has been independently verified or implemented.

## Primary candidate — full-verification DCS, 2016

Yingjie Xia, Xuejiao Liu, Fubiao Xia and Guilin Wang, *A reduction of security notions in designated confirmer signatures*, Theoretical Computer Science **618** (2016), 1–20. DOI: https://doi.org/10.1016/j.tcs.2015.12.025 .

**Why this candidate:** Unlike ordinary sign-then-encrypt, the paper explicitly describes a **full-verification** construction in which either the signer or designated confirmer can confirm **or disavow** an alleged signature. The paper distinguishes unforgeability, invisibility and non-transferability, and describes a generic construction using a binding commitment, a public-key encryption scheme secure against chosen-ciphertext attacks, and an ordinary signature. Its concrete implementation uses BLS signatures, Camenisch–Shoup-style labeled Paillier encryption, and Pedersen commitments. This stack is mathematically heavier than ECDSA; that cost is justified only if the complete protocol and proof relations can be implemented and independently checked.

### 2013 thesis construction sketch — NOT verified as final 2016 syntax

Fubiao Xia's **2013 doctoral thesis**, Chapter 6, describes committing to message **m** with randomness **r**, encrypting the same opening for both parties, signing the commitment and also issuing `π0`. The **2016 article's accessible introduction** lists only `(φ,c1,c2,σ)` as its high-level object; whether the final paper's actual §6–§7 algorithms include `π0` is **not established** by that introduction. This five-component sketch is thus **thesis-specific research notation**:

```text
ψ   ← Commit(m; r)
σ   ← Sign(skS, ψ)
cS  ← Encrypt(pkS, r)
cC  ← Encrypt(pkC, r)
π0  ← NIZK proving the two ciphertexts encrypt the same
      opening randomness r consistent with ψ
DCS ← (ψ, σ, cS, cC, π0)
```

**Source reconciliation (2026-10-17):** The complete thesis includes an initial `π0`. It was incorrect to claim from that fact alone that the final 2016 algorithm **must** include the identical proof. The journal's own accessible introduction is shorter and cannot decide the question either way. Resolve it from the final paper's full algorithms before implementing DCS. See [SOURCE-RECONCILIATION.md](research/SOURCE-RECONCILIATION.md). The mathematics/release gate remains CLOSED.

The lines above summarize the idea **only**. They are *not an implementation recipe*: exact encodings, domains, ciphertext labels, equations, proof statements, signature binding and challenge distributions have to come **verbatim in meaning** from the chosen publication. Never replace paper-defined signed/transcript inputs with this informal tuple.

The verifier may check that σ is a conventional valid signature on φ without learning an opening for φ to message m. **Confirmation** must be an actual source-defined interactive proof that an authorized party knows an opening consistent with m **and** the encrypted randomness, not a UI declaration or a decrypted signature printed for the verifier. **Disavowal** must be a distinct source-defined sound proof that the relevant validity relation does *not* hold. A failed confirmation or a withheld response is **not** disavowal.

## Not selected: the 2024 threshold construction for this lab

Yunfeng Ji, Rui Zhang, Yang Tao et al., *Designated confirmer threshold signature and its applications in blockchains*, Cybersecurity (2024): https://doi.org/10.1186/s42400-024-00256-2 .

The open-access text specifies threshold Sign, Confirm, Convert and Verify, with practical threshold-Schnorr and threshold-ECDSA instantiations. Its generic Confirm procedure proves a *valid* encrypted underlying signature when decryption/verification succeed, and otherwise **declares invalidity and aborts**. That is not the separate cryptographically sound **disavowal proof** required by this project's brief. It therefore cannot be silently promoted to this lab's four-protocol objective; adopting it would require a new scoped project and a different acceptance contract.

## Other related source, not a drop-in DCS

Jan Camenisch and Victor Shoup, *Practical Verifiable Encryption and Decryption of Discrete Logarithms* (2002/161), https://eprint.iacr.org/2002/161 . It supplies efficient building blocks for verifiable encryption/decryption and explicitly notes confirmer-signature applications, but is not by itself the selected, end-to-end four-protocol DCS specification.

## Independent role and transferability matrix

| Role | Public input available | Secret witness in correct protocol | What may be asserted |
|---|---|---|---|
| Signer | signer/verifier keys, statement and DCS | signing key; possible decryption witness in full-verification construction | may issue signature; confirm/disavow only through paper-defined procedures |
| Confirmer | public parameters, statement and DCS | confirmer decryption key | may interactively confirm **and** disavow when supported by the selected paper |
| Requesting verifier | public parameters and received transcript | **no** signer/confirmer secret key | accepts/rejects only the source-defined proof relation |
| Third-party observer | transmitted DCS and any exposed transcript | **no** secret key | must not be told the transcript constitutes independently transferable evidence without an explicitly authorized conversion or an applicable theorem |

**Security notions are not interchangeable.** Unforgeability does not imply that verification is private. Invisibility does not itself prove confirmation transcripts non-transferable. Honest-verifier zero knowledge does not, without the paper's explicit compiler and assumptions, justify claims of concurrent or malicious-verifier non-transferability. Role separation drawn in one browser is a user-interface model, not isolation against a compromised browser.

## Acceptance tests required before an implementation is allowed

1. **Get the complete 2016 paper and identify exact algorithms.** Record the numbered sections, every public statement, underlying group, range check, encryption labels, commitment message encoding, and which procedures use Fiat–Shamir versus interactive challenges. The abstract and accessible snippets are insufficient to code from.
2. **Confirm source-defined transcript equations.** For each of valid confirmation, dishonest confirmation, valid disavowal, dishonest disavowal, test a complete sequence of commitment/challenge/response messages against a verifier implemented without reusing the prover's predicate logic.
3. **Check the chosen assumptions and concrete security model.** EUF-CMA signing, commitment binding, appropriate IND-CCA2 (or source-specific) encryption, ZK/non-transferability requirements and whether a concurrency compiler is used. Disallow generic “it uses ZK” claims.
4. **Build a boundary/adversary matrix.** Alter message, commitment, ciphertext labels, group elements, subgroup membership, signature, challenge, response, session ID, prover/verifier public key, and replays across sessions. Distinguish rejection from an affirmative proof of invalidity.
5. **Reference and independent oracle.** Prefer author test vectors and independently implemented reference routines. If the paper supplies no numeric test vectors, say so and derive pinned independent equation-level fixtures. A round-trip that simply uses the same buggy predicate twice is not enough.
6. **Browser feasibility and implementation review.** Establish bounded parameters, named libraries for vetted arithmetic, performance measurements, and reviewer signoff before emitting a public verification verdict. Don't turn a partial prototype into the live “Confirmer Signatures” catalog entry.

## Present decision

**Paper-selection narrowed; full math gate remains NOT PASSED.** The 2016 source is a credible fit for full confirmation and disavowal, while the 2024 threshold paper is not a substitute for affirmative disavowal. The complete 2016 protocol equations, independent oracle, adversarial tests and third-party security review are still missing. Until those exist, do not build a deceptively reassuring signature demo, enable Pages, or publish a catalog card.
