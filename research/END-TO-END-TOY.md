# End-to-end designated-confirmer issuing research — source-backed toy path

**Status: RESEARCH ONLY — NOT A COMPLETE DCS. No secure confirmation, no affirmative disavowal, no non-transferability claim, and no public DCS UI.**

The code now joins several concrete mathematical components of the [Xia–Liu–Xia–Wang 2016 generic DCS construction](https://doi.org/10.1016/j.tcs.2015.12.025), with **deliberately insecure** building blocks from [Xia's 2013 thesis, Chapter 6](https://etheses.bham.ac.uk/4579/1/Xia13PhD.pdf). The 2016 paper's detailed §6 Extract and §7.2 explicitly include an initial π0 component even though the introduction abbreviates the output. The full 2016 equations, proof system, challenge distributions and assumptions are **not yet independently transcribed and verified**.

## Actual operations performed

1. Alice creates a *toy* commitment ψ = δ^m γ^r in an order-11 group. The message and opening are both synthetic small integers.
2. Alice generates a genuine WebCrypto **ECDSA P-256/SHA-256** signature **on the commitment ψ**, rather than signing the fictional message directly. This is a generic-signature teaching adapter, not a claim to implement the final paper's concrete BLS pairing instantiation.
3. Separate toy labeled Camenisch–Shoup-style ciphertexts encrypt the SAME small opening r under signer and confirmer keys. Encryption uses n=253=11×23, which is trivially factorable.
4. A paper-inspired partial π0 proof compares the e components of those ciphertexts. It establishes ONLY the common-opening subrelation used in the experiment.
5. The public precheck verifies real ECDSA and the partial π0 using *only public bytes*. It deliberately returns **isDCS: false**: those two checks cannot bind ψ to the encrypted opening, nor fully validate u/v ciphertext/tag/label correctness.
6. Separately, the signer or confirmer privately decrypts their own ciphertext, checks whether the recovered r opens ψ for the alleged message, and refuses proof preparation on incorrect claims. A local refusal is **not** affirmative disavowal.
7. The signer/confirmer can execute the 2013-thesis-inspired toy three-message π1/π2 algebra: prover sends seven commitments, verifier independently chooses a two-bit challenge, prover gives five responses, and the public-only verifier checks seven equations without receiving the private key or r. That produces **TOY_EQUATIONS_HOLD**, not a designated-confirmer validity decision. Prover masks are consumed after one challenge to avoid two-challenge witness extraction.

## Critically important negative test cases

- Alter ψ while retaining the original signature. Genuine ECDSA rejects; the e-only π0 checker is unaware of ψ.
- Alter a ciphertext's v component without touching e. Public ECDSA and the partial equality checker may still pass, proving the **public checks are incomplete**.
- Alter the alleged message/context. A participant refuses to produce proof; the check does **not** become DISAVOWED.
- Supply the wrong private decryption key, damaged signature or bogus proof response. These do not generate a valid positive demonstration.
- Reuse the same first-message proof randomness for two challenges in the low-security standalone toy module: algebraic special-soundness extraction recovers the toy witness. The integrated session burns masks after the first answer.
- In tiny order-5 encryption subgroups, altered labels can alias under the modular exponent even when the full hash differs; that negative fixture remains explicit.

## Missing requirements for a genuine DCS

**All of these remain BLOCKING:**

- Full paper-defined Setup, KeyGen, DCSSign including a *complete* NIZK/π0 and canonical signed statement. The current equality check is not the whole π0 validity relation.
- Cryptographic-strength labeled IND-CCA2 encryption, binding/hiding commitment and proof-compatible signature groups rather than factorable n=253 and known discrete-log relationships.
- Exact π1/π2 response intervals, subgroup checks, source-defined challenge handling and the necessary malicious/concurrent-verifier zero-knowledge transformation. **Honest-looking toy arithmetic does not establish non-transferability.**
- Camenisch–Shoup §7.3 **affirmative disavowal OR proof of knowledge**, including full exact integer interval/range enforcement and independent verification. A decryption failure, absence of confirmation or local Boolean is not disavowal.
- Independent mathematical oracle, attack fixtures and specialist review of every final-paper relation and the formal security model.
- Only after those pass: a complete visitor interface, a11y, CI and real publication as a finished Crypto Lab card.

## Repeatable checks

Research-only suite: `node --test tests/*.test.mjs`.

The two new integration suites test actual WebCrypto signature verification, signer/confirmer independent decryption, proof transcript recomputation by a public-only verifier, one-use prover state, wrong-message and wrong-key refusal, and explicit counterexamples for what π0 does not check.

**Do not copy research Node modules into the public Chapter 01 Pages preview.** The current preview remains a clearly labeled ordinary-signature baseline until the entire full-implementation security gate passes.
