# Non-interactive designated-verifier proofs (A-D-09)

**Status: an executable research lesson built from the primary source. NOT an
audited implementation, NOT a security proof, and NOT a change to this
repository's standing position that full designated-confirmer-signature
security remains unestablished.**

## The primary source, and what was read

Markus Jakobsson, Kazue Sako and Russell Impagliazzo, **"Designated Verifier
Proofs and Their Applications"**, EUROCRYPT '96, LNCS **1070**, pp. **143–154**,
doi:[10.1007/3-540-68339-9_13](https://doi.org/10.1007/3-540-68339-9_13).

Read in the published proceedings volume, cross-checked against the authors'
own PDF. Sections used, by printed page:

| Where | What it gives this lesson |
|---|---|
| §2 Approach, p. 146 | The idea in the authors' words: *instead of proving Θ, Alice proves "either Θ is true, or I am Bob"*. Φ_Bob is "I know Bob's secret key" |
| §2 Threat and trust model, pp. 146–147 | Who the hidden verifier Cindy is, and the two attacks explicitly excluded |
| §3 Definition 1, p. 147 | Designated verifier: Cindy cannot distinguish transcripts Bob could have produced himself |
| §3 Definition 2 and scheme 1, pp. 147–148 | Trap-door (chameleon) commitment `c = g^w y_B^r mod p`, trapdoor `x_B` |
| **§5, pp. 149–150** | **The construction implemented here**: constructing, verifying and simulating the non-interactive proof, plus the warning that plain Fiat–Shamir alone leaves "a transitive proof whose correctness can be verified by anyone" |
| §7, p. 151 | The designated verifier must *know* his secret key; registration approaches |
| Appendix, Definition 3, p. 154 | Strong designated verifier, requiring probabilistically encrypted transcripts — **not** implemented here |

Secondary, and labelled as such: Berry Schoenmakers, "Designated Verifier
Proofs", *Encyclopedia of Cryptography, Security and Privacy*, 3rd ed., Springer
2025, doi:10.1007/978-3-030-71522-9_4, which describes the alternative
OR-composition route (Cramer–Damgård–Schoenmakers plus Fiat–Shamir). That route
is **not** what this lesson implements.

## The printed construction

For an undeniable signature where `y_A = g^{x_A}` and `s = m^{x_A}` in a
prime-order subgroup of `Z_p^*`, with `hash_q` into `Z_q`:

```
construct   c = g^w y_B^r mod p,  G = g^t mod p,  M = m^t mod p,
            h = hash_q(c, G, M),  d = t + x_A (h + w) mod q
            the prover sends (w, r, G, M, d)

verify      c = g^w y_B^r mod p,  h = hash_q(c, G, M),
            G y_A^{h+w} = g^d mod p   AND   M s^{h+w} = m^d mod p

simulate    d, alpha, beta uniform;  c = g^alpha,  G = g^d y_A^{-beta},
            M = m^d s^{-beta},  h = hash_q(c, G, M),
            w = beta - h mod q,  r = (alpha - w) x_B^{-1} mod q
```

## What this lab executes

The statement is **this lab's existing confirmation statement**, so the lesson
sits beside the interactive exchange instead of inventing a second toy. For a
role *j*, `core.mjs publicStatement()` derives `A`, `B_j`, `C_j`, `D_j` from the
format-checked envelope, and

```
Theta_j :  exists x such that  C_j = D_j^x   AND   A = B_j^x
```

with witness `x_C` (confirmer) or `x_S` (signer). The paper's `g, y_A, m, s` map
to `D_j, C_j, B_j, A`. The designated verifier holds a separate G1 key pair
`(x_B, y_B = G1^{x_B})`.

```
construct   c = G1^w · y_B^r,  T_src = D_j^t,  T_tgt = B_j^t,
            h = H(domain ‖ scheme ‖ role ‖ context ‖ A ‖ B_j ‖ C_j ‖ D_j ‖ y_B ‖ c ‖ T_src ‖ T_tgt),
            d = t + x·(h + w) mod q,   proof = (w, r, T_src, T_tgt, d)

verify      c = G1^w · y_B^r,  h = H(…),  e = h + w,
            D_j^d = T_src · C_j^e   AND   B_j^d = T_tgt · A^e

simulate    c = G1^alpha,  T_src = D_j^d · C_j^{-beta},  T_tgt = B_j^d · A^{-beta},
            h = H(…),  w = beta - h,  r = (alpha - w)·x_B^{-1}
```

Completeness uses `A = B_j^x`; the simulator's two commitments satisfy both
equations by construction for **any** `A` and `C_j`, which is precisely why a
simulated proof also verifies for a false statement.

## Why an outside observer cannot establish origin, and exactly how strongly

On a **true** statement with an invertible `x_B`, the map

```
(w, r, t)  ->  (d, alpha, beta),   alpha = w + x_B·r,   beta = h + w,   d = t + x·beta
```

is a **bijection** on the cube of scalars; its inverse is the simulator itself.
Uniform prover randomness and uniform simulator randomness therefore induce the
**same** transcript distribution. The claim is exact — not statistical, not
computational — and `simulatorRandomnessOfProof()` exposes the map so the tests
can check the correspondence by reproducing proofs byte for byte, rather than
sampling transcripts and calling that a theorem.

The executable conclusion for an outside observer is deliberately narrower:
the equations hold, and the object could have come either from the role witness
or from the holder of `x_B`. Since that holder can produce an accepting proof
of **any** statement, including a false one, the transcript alone establishes
neither statement truth nor proof origin. The designated verifier interprets it
using information found nowhere in the transcript: whether he made it himself.

Boundaries of that claim:

- It is about the **transcript alone**. Timing, provenance, who handed it over
  and the single-browser teaching model are all outside it.
- It is **Definition 1**, not Definition 3. The proof is a plain transcript, not
  probabilistically encrypted to the verifier, so a third party willing to
  assume the verifier only ever runs prescribed protocols is outside the
  guarantee. The paper's own Appendix says exactly this.
- It rests on `x_B` being secret **and genuinely known** to the designated
  verifier (§7). An unregistered key is refused here rather than accepted.

## Three ways to prove the same statement

| | Messages | Why the verifier believes it | What a third party learns |
|---|---|---|---|
| Interactive exchange (`confirmation.mjs`) | three | the verifier sampled a challenge after the commitment was fixed | the equations in a recording alone do not establish a live exchange |
| Designated-verifier proof (here) | one | the holder knows whether he used the registered verifier secret | the equation-valid transcript alone establishes neither truth nor origin |
| Publicly verifiable proof (here, for contrast) | one | any reader can recompute both relation equations | an equation-valid public transcript; witness knowledge needs a security theorem and assumptions not supplied here |

The interactive exchange and the designated proof are designed to be
non-transferable for **different reasons**, and they hide different things: the
interactive OR exchange hides *which role* proved, while the designated proof
names the role and hides *who produced the object*. This lab demonstrates those
distinct transcript mechanisms; it does not supply a full security theorem for
either surrounding protocol. Hashing the interactive exchange would not produce
this object, and this lesson does not claim otherwise.

The publicly verifiable contrast is the same Chaum–Pedersen statement with an
ordinary Fiat–Shamir challenge and no trap-door commitment. The two verifiers
use separate hash domains and neither accepts the other's proofs. Supplying the
designated verifier secret to the honest-prover API fails its branch-witness
check; that demonstrates that this trapdoor does not directly satisfy the
public statement, **not** a general unforgeability or proof-of-knowledge theorem.

## Deviations from the paper, none of them silent

| | Deviation |
|---|---|
| D1 | **Groups and statement.** The paper uses one prime-order subgroup of `Z_p^*` and an undeniable-signature statement. Here the key equality lives in G1 or G2 and the signature equality in the order-q subgroup of Fp12. The exponent and proof shape are unchanged; the meaning of Θ is this lab's. |
| D2 | **Hash binding.** The paper's printed input is `hash_q(c, G, M)`. This binds a domain separator, the scheme, the role, a caller context, the entire derived statement, the verifier key, `c` and both commitments. The narrower printed input is not carried into shipped code. |
| D3 | **Verifier key registration.** A Schnorr proof of knowledge of `x_B` travels with `y_B`. §7 requires the knowledge; this protocol for it is ours. |
| D4 | **Definition 1 only.** No probabilistic encryption of the transcript, so no strong-designated-verifier claim. |
| D5 | **No multiple designated verifiers** (§6 not implemented). |
| D6 | **No security theorem.** The paper proves none for §5, and neither does this lab. The identical-distribution statement above is exact algebra about this construction, not a security proof of the surrounding scheme. The publicly verifiable contrast likewise comes with no lab-supplied proof-of-knowledge or soundness theorem. |

One implementation choice is worth naming because it could have been made
dishonestly: zero masks are legal values, so a commitment can be the group
identity, and noble's `toBytes()` refuses the identity. Rather than drop zero
from the sampler — which would have silently narrowed the very distribution the
designation argument depends on — the identity is encoded for hashing as the
standard compressed infinity octet string for its group.

## Five things this is not

1. A **designated-verifier proof** is what this implements: a proof about a
   statement, convincing only to the holder of `y_B`.
2. A **designated-verifier signature** is a signature scheme. Not implemented.
3. A **confirmer signature** is this repository's subject: who may run the
   verification protocol. This is a mode of *proving* the confirmation
   statement, not a different signature object.
4. An **ordinary publicly verifiable proof** is implemented alongside, purely
   as the transferability contrast; the lab checks its equations and does not
   prove a proof-of-knowledge or soundness theorem for it.
5. An **interactive transcript that happens to be simulatable** is the lab's
   existing Eve recording. Simulatability of a recording is not designation.

## Evidence

| Evidence | Where |
|---|---|
| Construction, verifier, simulator, observer view | [designated-verifier.mjs](designated-verifier.mjs) |
| 19 unit tests, with both equations recomputed independently | [tests/designated-verifier.test.mjs](tests/designated-verifier.test.mjs) |
| Cross-library agreement: py_ecc recomputes what Noble produced | [reference/verify.py](reference/verify.py), [reference/test_reference.py](reference/test_reference.py) |
| Seven committed public vectors, regenerated byte for byte | [reference/vectors.json](reference/vectors.json) |
| Eight source mutations, each killed by its own named test | [../../scripts/dv-mutations.mjs](../../scripts/dv-mutations.mjs) |
| Browser flow, keyboard, axe and reflow at 390 px and 1360 px | [../../tests/real_pairing_browser.py](../../tests/real_pairing_browser.py) |

Mutation testing earned its place here: it found that **no single-coordinate
change could isolate the target-group equation**, because the target commitment
is itself hashed, so every edit to it also moved the challenge and tripped the
source equation first. The fixture that closes that gap separates the two halves
of the statement instead — on an altered message the key relation still holds
while the signature relation does not — and it is the one test that fails if the
target check is removed.

## What remains open

Everything the [security ledger](SECURITY-MODEL.md) already lists, unchanged.
This lesson adds no claim about the full designated-confirmer scheme's
unforgeability, invisibility or non-transferability, about malicious or
concurrent verifiers, or about the Type-3 adaptation. It has had no independent
expert review.
