# Disavowal research — four invalidity branches, NOT an affirmative proof

**Status: PAPER-DERIVED LOCAL DIAGNOSTIC ONLY. No zero knowledge, designated confirmer disavowal, soundness, concurrent security or production cryptography is claimed.**

## Primary sources now available in full

- Jan Camenisch and Victor Shoup, [*Practical Verifiable Encryption and Decryption of Discrete Logarithms*](https://www.shoup.net/papers/verenc.pdf) (author-hosted complete 2003 paper), especially **§7.2–§7.3, printed pp. 24–33; PDF page indices 23–32**. The author-hosted version is a complete primary source, not an abstract. The final 2016 DCS construction has not been equated with this paper.
- Fubiao Xia, [*Designated Confirmer Signatures: Modelling, Design and Analysis*](https://etheses.bham.ac.uk/4579/1/Xia13PhD.pdf) (2013 thesis), **Chapter 6 §6.5.1–§6.5.2, PDF pp. 150–154**, references Camenisch–Shoup §7.3 for affirmative disavowal.

The Camenisch–Shoup paper is **a building-block protocol for proving or disproving a discrete-logarithm relation about a labeled ciphertext**, not a complete DCS by itself. Xia's DCS must bind it to the exact signer/confirmer roles, original message, issued tuple, initial consistency π0, label, encryption key, proper zero-knowledge compilation and associated security model.

## Important notation boundary

Camenisch–Shoup §7.3 uses a public group element **δ** whose claimed discrete logarithm (base γ) is the decrypted plaintext m: δ = γ^(m rem n). In the DCS description from Xia, the publicly signed *commitment* is ψ = δ_DCS^message · γ_DCS^r. These are **not the same δ**. Applying the §7.3 discrete-logarithm protocol to the DCS means first establishing the correct commitment-derived alleged opening element and checking all the linked DCS relations. Our experimental variable **claim** is Camenisch–Shoup's discrete-log group element, **NOT ψ**, and the inspector does not combine them.

## Source's four branches

Let n be the Paillier modulus, M=n², the decryption private key be (x1,x2,x3), the claimed labeled ciphertext be (u,e,v), H = H(u,e,L), and let R = u^(x2+H x3)/v (mod M). For Camenisch–Shoup §7.3 (case analysis before its OR proof):

| Source case | Failed relation | Interpret it carefully |
|---|---|---|
| **1 — tag factor outside n-torsion** | R^(2n) ≠ 1 (mod M) | One form of invalid labeled-ciphertext authentication |
| **2 — tag factor inside n-torsion but invalid** | R^(2n) = 1 but R² ≠ 1 | Distinct tag failure; case 1 alone is insufficient |
| **3 — plaintext residue not representable** | Tag passes, but (u^x1/e)² ∉ ⟨h⟩ | The required plaintext representation is missing |
| **4 — discrete-log claim mismatch** | Labeled ciphertext is valid, but δ ≠ γ^(m rem n) | Decryption succeeds yet the alleged group relation is false |

**Preflight is separate:** if δ is not a canonical Γ group element or (u,e,v) is malformed, the source protocol stops with a negative response rather than launching this four-branch proof. In a teaching UI a malformed input should read **REJECTED AS INPUT**, not **DISAVOWED BY A VERIFIED PROOF**.

The four branches are combined by a source-defined **interactive OR proof of partial knowledge**, not by announcing which branch is true. Section 7.3 sets up auxiliary integer commitments, with a **Cramer–Damgård–Schoenmakers-style OR construction**. Its successful and unsuccessful proofs require actual three-move commitment/challenge/response messages and a separately checked verifier. This repository has **not** implemented them.

## Why §7.3 needs an exact interval proof

The source explicitly warns that a relaxed range proof can let a prover add a nonzero multiple of n to a candidate plaintext and claim a false equality or inequality. The permitted interval is tied to a canonical representative (centered on zero), and the protocol uses a sum-of-squares style exact interval proof to prevent integer aliasing.

**Our negative fixture shows a simpler toy alias**: the toy Γ has order 11. For any r, γ^r = γ^(r+11); seeing the same group element cannot distinguish those two integers. The current local classifier does not implement the necessary interval proof and must never claim it has soundly proven disavowal.

## What is actually implemented

[disavow-branches.mjs](disavow-branches.mjs) uses the fixed **insecure** Paillier n=253, with γ=2 in the order-11 subgroup of ℤ23*. It **receives the decryption private key** and computes the four local predicates, not a witness-hiding proof. Cases 1, 2, 3 and 4 are separately reachable and have independent adversarial tests; invalid/malformed inputs are rejected distinctly, while valid matching inputs are classified as \`MATCH\`. No emitted result contains a proof or transcript.

[The regression suite](../tests/disavow-branches.test.mjs) adds **11 tests**, including engineered representatives of all four failure branches and a negative-claim fixture that detects modulo-subgroup ambiguity. Together with the earlier 38 tests, **49 local research tests pass**. The tests establish only bounded arithmetic behavior for these examples, not DCS security or a working confirmer.

These tests deliberately distinguish **CASE_4_GROUP_MISMATCH** from an actual *affirmative proof* of invalidity. A local secret-key predicate returning true can be wrong, manipulated or unconvincing to a separate verifier; the source requires real sound interactive algebra to create transferable or non-transferable evidence according to its security model.

## Outstanding hard engineering/research gates

1. **Source reconciliation:** read the full 2016 Xia *et al.* paper and compare its §6/§7/appendix equations and assumptions with 2013 Chapter 6 and Camenisch–Shoup §7.3. The papers have overlapping ideas, but they are not interchangeable specifications.
2. **Authentic OR proof:** implement the exact source-defined OR proof of partial knowledge and sound verifier. Include challenge sampling and rejection on malformed transcripts, group validation, cross-session replay, wrong signer/confirmer keys and wrong labels.
3. **Exact integer interval:** implement the range proof required by §7.3; rejecting merely on modulo-group equality is not enough. Its common-reference-string and nonfactorization assumptions need a reviewed parameter choice and independently established invariants.
4. **Confirmation:** the previously implemented π1 *witness inspector* sees private key and opening and must be transformed into a source-defined interactive proof with actual commitments, unpredictable challenges, response verification, and the necessary zero-knowledge compiler.
5. **Complete issuance/π0:** the earlier π0 subproof checks two e components but does not, on its own, bind ψ or authenticate ciphertext v/labels. Require a complete source-consistent issued tuple and independent verifier before granting DCS status.
6. **End-to-end security review:** zero knowledge and non-transferability are formal claims requiring a matched security model and specialist review, not outcomes proven by passing unit tests on factorable n=253.

**Release rule:** No DCS signature, confirmation or disavowal UI verdicts; no Pages deploy; no main Crypto Lab catalog card until the above proof statements, exact transcript, independent test oracle and security review are demonstrably complete.
