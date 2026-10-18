# Separate public-transcript verifier

This Python implementation uses **py_ecc 8.0.0**, independently of the browser's
**@noble/curves 2.4.0** equations and group code. It recomputes the message hash,
dual-key certificate, signed-ElGamal format, challenge split and every public
confirmation or candidate disavowal equation. It accepts no private key.

“Separate implementation” does not mean independent authorship, expert review,
formal verification or audited cryptographic dependencies. These checks were
prepared as part of the same research effort. py_ecc itself is experimental.

From the repository root:

```sh
python -m venv .venv
. .venv/bin/activate
python -m pip install -r research/real-pairing/reference/requirements.txt
python -m unittest discover -s research/real-pairing/reference -p 'test_reference.py' -v
python research/real-pairing/reference/check_algebra.py
cd research/real-pairing
npm ci --ignore-scripts
node reference/generate-vectors.mjs --check
```

In the workbench, finish a proof, open **Review the evidence**, and download its
public transcript. Check that file with:

```sh
python research/real-pairing/reference/verify.py signature-gate-public-transcript.json
```

`EQUATIONS_HOLD` means only that the public equations hold. Two committed vectors
are deliberately simulated false statements that MUST pass these checks. The
file cannot prove that an independent verifier chose the challenge after the
commitment. A caller-controlled `provenance` or `verified` field is not evidence.

## Encoding and pinned pairing convention

The versioned JSON uses canonical lowercase hexadecimal scalars without `0x`,
canonical compressed G1/G2 points, and twelve canonical Fp coefficients for each
Fp12 value. The polynomial basis satisfies `w^12 - 2*w^6 + 2 = 0`.
Noble's tower converts through `u=w^6-1`, `v=w^2`: `(a+b*u)*w^k` becomes
`(a-b)*w^k+b*w^(k+6)`. This conversion is implemented in `transcript.mjs`.

These pinned libraries normalize their reduced pairings differently. In this
basis, the convention used here is `NoblePair(P,Q) = py_eccPair(Q,P)^(-3)`.
Three committed anchors check generators, independently scaled generators, and
a hash-to-curve point. The same fixed conversion is applied to every pairing;
there is no per-transcript fitted exponent. Changing either library requires
rechecking these anchors and the six public vectors. This is interoperability
evidence for these versions, not a claim that all pairing libraries use that
normalization. Source implementations: [Noble](https://github.com/paulmillr/noble-curves)
and [py_ecc](https://github.com/ethereum/py_ecc).

Received target elements must be nonzero and in the order-q subgroup; beta must
also be nonidentity. Received curve points are decompressed, subgroup-checked,
and re-encoded. Identity commitments are permitted, but identity registered keys
are not. Scalars must be in `[0,q)`. Declared verdict metadata is ignored.

## Reproducibility and boundaries

`generate-vectors.mjs` contains **public, fixed, insecure test randomness** and
keys 7 and 11. It is a Node-only fixture generator and is never imported by the
browser. `--check` compares the entire committed JSON byte for byte. The six
vectors cover both roles for both protocols and both known-challenge simulators.
The suite mutates responses, challenges, messages, key certificates, encodings
and subgroup elements and requires rejection.

`check_algebra.py` uses SymPy to check eight polynomial identities supporting
completeness, extraction and simulator translations. It also exhaustively checks
100,972 two-challenge branch extractions over q=3 and q=5. These are **machine-checked
components**, not a machine-checked security theorem: the nonzero assumptions,
prime-order reasoning, OR composition and distribution arguments remain in the
[written proof](../DISAVOWAL-PROOF.md). Small fields provide counterexample checks,
not evidence of secure parameters or a proof for all primes.

CI runs these checks before Pages publication. See the [review packet](../REVIEW-PACKET.md)
for obligations that still require an independent cryptographer.
