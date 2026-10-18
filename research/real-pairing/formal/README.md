# Lean verification of the candidate inequality OR relation

This project checks the local disavowal argument with **Lean 4.19.0** and mathlib
commit `c44e0c8ee63ca166450922a373c7409c5d26b00b`. The complete dependency lock is
committed. The check must pass on the commit being reviewed; the presence of a
`.lean` file alone is not evidence of a successful proof.

## Exactly what is formalized

The model uses exponent coordinates over an arbitrary field `F`. For a branch,
`Statement` contains `d`, `key`, `b`, `alleged`; `Commitment` contains `beta`,
`keyMask`, `pairMask`; `Response` contains `u`, `v`, `challenge`.

The accepting equations are:

```
beta ≠ 0
keyMask  = d*u - key*v
pairMask = beta*challenge + b*u - alleged*v
```

The witness relation is `∃ x, key = d*x ∧ alleged ≠ b*x`.
The OR verifier checks both branches and the challenge sum. The two transcripts
in the soundness theorems share the exact same statements and commitments.

| Declaration | Kernel-checked conclusion when this build passes |
| --- | --- |
| `completeness` | Honest responses satisfy the equations for every challenge, given a valid witness and nonzero blinding |
| `differenceEquations` | Two accepting responses imply the key and target difference equations |
| `responseDifferenceNonzero` | The extractor denominator cannot vanish when d and beta are nonzero and challenges differ |
| `extraction` | The explicit response-difference formulas recover the key relation, nonzero blinding, beta relation and signature inequality |
| `branchSpecialSoundness` | Two accepted branch responses yield an inequality witness |
| `orSpecialSoundness` | Two accepted OR transcripts with different overall challenges yield a witness in at least one branch |
| `falseStatementUniqueChallenge` | A false OR statement has at most one accepting overall challenge per fixed commitment |
| `simulatorAccepts` | A known-challenge transcript can satisfy the equations without a witness |
| `maskEquiv` | The fixed-challenge mask-to-response translation is a bijection |
| `betaEquiv` | Multiplication by a nonzero inequality ratio bijects nonzero blindings and nonzero betas |
| `uniformEquiv` | A permutation preserves the exact uniform probability mass function on a finite type |
| `honestRandomnessEquiv` | A joint bijection from `(a,e,ePrime)` to `(beta,u,v)`, including the responses’ dependence on a |
| `honestBranchUniform` | For each fixed witness, nonzero inequality ratio and challenge, the joint `(beta,u,v)` distribution is exactly uniform |
| `printedBetaIsIdentity` | The printed key-ratio beta is zero in exponent coordinates under the key relation |

The soundness theorems do not assume the desired witness or soundness conclusion.
The honest completeness theorem necessarily assumes a witness; the extraction and OR
soundness theorems assume only validation, acceptance and different challenges.
The denominator's nonzero condition is derived, not quietly assumed.

## Coordinate model versus real groups

For cyclic groups of prime order q, choosing a generator gives a mathematical
coordinate in `F_q` for every element. Multiplication becomes coordinate
addition, exponentiation becomes scalar multiplication, and group identity
becomes coordinate zero. G1, G2 and the pairing target use separate coordinates;
they share the scalar field. A nonidentity source generator has `d≠0`; a validated
nonidentity target beta has `beta≠0`.

**These coordinates are for the proof only.** The browser does not expose them
and the extractor does not compute discrete logarithms. It uses the public
response differences `x=du/dv` and `a=-dv/dc`, then checks the real groups.

The existence/correctness of this coordinate interpretation for the concrete
BLS12-381 implementation, the derivation of A and B from pairings, and refinement
of JavaScript/Python into this Lean model are **not formalized here**. The formal
statement must still be reviewed against the intended protocol. A proof checker
checks the statement supplied to it, not the fidelity of that modeling choice.

The probability theorem uses mathlib’s probability mass functions, not sampled
histograms. It proves the **joint honest-branch sampling distribution**: uniform
nonzero a and full-field masks become a uniform nonzero beta and uniform full-field
responses, for each fixed witness, inequality ratio and challenge. This includes
the dependence of the response translation on a; checking separate marginal
distributions would not suffice.

This is a component of the written special-HVZK argument. The full two-branch
transcript distribution, challenge-split symmetry, malicious/concurrent-verifier
compiler and full DCS security games are **not formalized**.
The `1/q` soundness bound additionally uses an independent uniform challenge;
this project proves the unique-accepting-challenge algebraic prerequisite.

## Reproduce and audit the proof dependencies

Install [Elan/Lean](https://lean-lang.org/install/) and run in this directory:

```sh
lake update
lake exe cache get Mathlib.Tactic.FieldSimp Mathlib.Tactic.LinearCombination Mathlib.Tactic.Ring Mathlib.Algebra.Field.Basic Mathlib.Probability.Distributions.Uniform Mathlib.Probability.ProbabilityMassFunction.Constructions
lake build
lake env lean CheckAxioms.lean > axioms.txt
python3 check_axioms.py axioms.txt
python3 -m unittest discover -p test_axiom_guard.py -v
```

CI builds the proof and prints the transitive axiom dependencies of all fourteen
listed declarations. The gate allows only Lean's standard `propext`,
`Classical.choice`, and `Quot.sound`. It rejects omitted results, duplicate
reports, `sorryAx`, new postulates and native-evaluation trust axioms. Negative
controls test the gate itself. See Lean's [axiom documentation](https://lean-lang.org/doc/reference/latest/Axioms/).

The trust base includes the pinned Lean kernel/toolchain and imported mathlib
artifacts. This is not an independent implementation of the Lean kernel, an
external cryptographer's audit, or an author-approved erratum. See the
[review packet](../REVIEW-PACKET.md) and [written argument](../DISAVOWAL-PROOF.md).

The Pages publication job requires this reusable proof workflow to pass on the
same source commit as the browser and cryptographic tests. A failed proof or axiom
gate blocks publication. The live page links the workflow so the evidence can be
checked rather than inferred from a static badge.
