# Candidate disavowal correction: proof and implementation obligations

Review date: 2026-10-18. **Original research derivation, with executable checks;
not an author-approved erratum, mechanically verified proof, or full DCS security theorem.**

This note establishes a narrowly stated mathematical argument for the local
inequality OR protocol. It replaces the previous situation of completeness
examples without a written extraction or simulation argument. Independent review
is still required. The original paper's security theorem does not automatically
apply to this reconstruction or to its Type-3 instantiation.

## Source and exact proposed changes

Source: [Xia 2013 thesis](https://etheses.bham.ac.uk/4579/1/Xia13PhD.pdf),
Chapter 5, printed pp. 105–107; PDF pages 120–122 (one-based).
Figures 5.3 and 5.4 were visually inspected in rendered PDF pages on the review
date. Both actually print the problematic key-ratio beta; this is not just an
OCR observation. The intended statement in the preceding text is key equality
AND signature inequality, OR-composed across signer and confirmer.

| Item | Printed diagrams | Local proposed correction |
| --- | --- | --- |
| Real-branch beta | `(D^x/C)^a` | `(B^x/A)^a` |
| Key check | `zKey = beta^c D^u/C^v` | `zKey = D^u/C^v` |
| Inequality check | `zPair = B^u/A^v` | `zPair = beta^c B^u/A^v` |
| Sampling | The printed sampling line mixes beta and scalars | `a` uniform nonzero scalar; masks, simulated responses and branch challenge uniform over the whole scalar field; simulated beta uniform nonidentity target-group element |

Changing only the beta formula is insufficient: its challenge factor must move
to the inequality equation as well. The key-ratio in the source is identity
when the stated key relation holds, contradicting the nonidentity check.
This diagnoses the displayed equations, not the authors' intended protocol.
No author-approved erratum has been established by this review.

## Precisely scoped statement and setup

Let q be prime. For each branch j, let K_j be a cyclic group of order q,
D_j a nonidentity element (therefore a generator), C_j in K_j, and A,B_j in
a cyclic target group T of order q. All received elements must be validated in
these groups, not merely accepted as extension-field values. The witness relation is

`R = exists (j,x): C_j = D_j^x AND A != B_j^x`.

Our registered keys additionally exclude identity. K_1 is BLS12-381 G1,
K_2 is G2, and T is the order-q subgroup of Fp12*. Multiplicative notation
below represents the source groups too; the implementation uses point addition.
The high-level verifier derives A,B,C,D from the format-checked envelope.
Accepting a prover-selected replacement statement would prove a different claim.

## Transcript and completeness

For the real branch, choose `a` uniformly in F_q*, and `e,ePrime` uniformly
in F_q. Set `beta=(B^x/A)^a`, `zKey=D^e/C^ePrime`,
`zPair=B^e/A^ePrime`. Since `B^x/A != 1`, beta is nonidentity.

For the simulated branch choose beta uniformly in T minus identity, and
`cFake,uFake,vFake` uniformly in F_q. Construct its commitments using the
verification equations below. Send BOTH betas and all commitments BEFORE c.

After the independent verifier challenge c, let `cReal=c-cFake`,
`uReal=e-cReal*x*a`, `vReal=ePrime-cReal*a` (mod q).
The verifier checks `c1+c2=c`, subgroup/nonidentity constraints, and each branch:

`zKey_j = D_j^u_j / C_j^v_j`

`zPair_j = beta_j^c_j * B_j^u_j / A^v_j`.

For the real branch the challenge terms in the key equation cancel because
`C=D^x`. In the second equation the beta challenge term cancels
`(B^x/A)^(-cReal*a)`. The fake branch holds by construction. Thus completeness
holds for every allowed challenge, including zero, not just sampled fixtures.

## Two-special-soundness argument

Take TWO accepting transcripts for the SAME public statement and EXACT SAME
first message, with different overall challenges. At least one branch has
`dc=c_j-c'_j != 0`, since the branch challenges sum to their overall challenges.
For that branch put `du=u_j-u'_j`, `dv=v_j-v'_j`. Dividing the accepted equations gives

`D^du = C^dv`, and `1 = beta^dc * B^du / A^dv`.

If dv=0, the first equality forces du=0 since D has prime order q. The
second then forces beta^dc=1, impossible for nonidentity beta of order q
and nonzero dc. Therefore dv is invertible. Extract

`x = du / dv`, and `a = -dv / dc` in F_q.

Raising the first equality to `1/dv` proves `C=D^x`. Substitution into the
second gives `beta=(B^x/A)^a`. As beta is nonidentity, `B^x/A != 1`.
The extracted x is a witness to the intended inequality relation.

Consequently a first message for a FALSE statement can have accepting responses
for at most one overall challenge. For a fresh uniform challenge in F_q the
soundness error is at most 1/q. The existing browser challenge helper samples
F_q* instead; its bound is 1/(q-1). Neither statement holds when an adversary
chooses the challenge after constructing its responses.

`disavow-extraction.mjs` implements the extractor, re-verifies both transcripts
against one explicit first message, and independently checks the recovered key,
inequality and beta relation. The two role tests deliberately rewind test-only
private state. Normal response-session reuse remains rejected. The extractor is
not imported into the browser application.

## Special honest-verifier zero knowledge (abstract protocol)

For any fixed canonical challenge c, the simulator selects both betas uniformly
from T minus identity, selects c1 uniformly from F_q, sets c2=c-c1, and selects
all four responses uniformly from F_q. It computes commitments from the verifier
equations. It uses no witness. This is `simulateDisavow({publicData,challenge:c})`.

For an honest real branch, the fixed nonidentity ratio `B^x/A` generates T,
so uniform nonzero a makes beta uniform nonidentity. Conditional on beta and the
branch challenge, translation of independent uniform e,ePrime makes u,v uniform
and independent. For the simulated branch these distributions are chosen directly.
The challenge split has the same distribution regardless of which branch is real.
The commitments are deterministic functions of these values and c in both cases.
Thus the full transcript distributions are IDENTICAL for true statements in the
abstract protocol. Sampling the overall challenge from the verifier's actual
domain gives the corresponding honest-verifier view. The simulator also produces
equation-valid transcripts for false statements; this does not make those live proofs.

This argument requires full-field masks/responses; the old code excluded zero.
The updated sampler includes zero for these values while keeping a, secret keys
and beta exponents nonzero. This is an exact distribution argument, not a claim
that a histogram or several passing simulations proves zero knowledge.

## Concrete implementation flaw found during this proof work

The previous beta test used `gtPow(beta,Q)`. That helper reduces exponents
modulo Q, so it actually tested `beta^0=1`. It did NOT validate subgroup membership.

A counterexample sets both betas to -1 in Fp12 (order two), both key commitments
to identity, both target commitments to 1, all responses to zero, and branch
challenges to 0 and c. For any even c the old equations accept, including for a
VALID signature. This is a false disavowal attack without either key, succeeding
on roughly half the nonzero challenges. It is not merely a malformed-input concern.

The repair uses raw `GT.pow(beta,Q)`, canonical field validation and nonzero/
nonidentity checks. The low-level verifier also validates statement/commitment
target elements and curve subgroup membership. The regression constructs this
attack on a real issued object and checks several even challenge boundaries.

## Remaining obligations

- Independent mathematical review of this proof and reconciliation with the
  publication's intended correction; no publisher or author endorsement claimed.
- Mechanized proof checking if the deliverable is to be described as formally
  machine-verified. These Node tests are executable examples and regressions.
- Malicious-verifier/concurrent zero knowledge and full DCS non-transferability;
  the straight-line fixed-challenge simulator above proves neither.
- A reduction for the complete Type-3 DCS construction, including invisibility,
  key registration, issuance, conversion and the original security-game adversaries.
- Protocol encoding, network/session security, implementation side channels,
  and independently reviewed interoperability vectors.

**Established here:** a written completeness, two-special-soundness and special
HVZK argument for the specified local prime-order protocol, with executable
extraction and attack regression tests. **Not established:** a verified correction
of the complete published DCS scheme or production security.
