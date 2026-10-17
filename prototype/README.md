# Signature Gate — ordinary ECDSA baseline (research prototype)

This is the **first functional chapter** from [`PRODUCT-VISION.md`](../PRODUCT-VISION.md), not a designated confirmer signature implementation.

What is real: Alice creates a fresh non-extractable WebCrypto ECDSA P-256 key, signs a domain-separated fictional statement using SHA-256, and Bob and Dave **independently import the public key** to verify a standard 64-byte P1363 signature. Changing message bytes, a signature byte or the public key causes real verification to reject. Published RFC 6979 Appendix A.2.5 P-256/SHA-256 signature verification vectors are checked in the tests. Key material is not persisted.

What is **not** implemented: DCS signing, authorized confirmation, affirmative disavowal, zero-knowledge proof, non-transferability, conversion, role-isolation or any production security guarantee. Research Steps 02–04 are visibly locked; Step 05 is only a conceptual distinction between cryptographic authenticity and factual truth. An ordinary signature is publicly verifiable by design.

To try locally: serve the repository root on localhost (for example `python3 -m http.server 8000`) and visit `http://localhost:8000/prototype/`. The Web Crypto API requires a secure context (HTTPS or localhost). Nothing is deployed to GitHub Pages from this folder and no main Crypto Lab card is authorized.

Run unit tests with `node --test tests/baseline.test.mjs` (Node 22+). Run browser tests through the research branch's CI. Full Crypto Lab Vite/TypeScript template adoption remains conditional on the paper-accurate DCS implementation gate.

Source: [RFC 6979 §A.2.5](https://www.rfc-editor.org/rfc/rfc6979#appendix-A.2.5); [Crypto Lab master template](https://github.com/systemslibrarian/crypto-lab/blob/main/audits/_MASTER-TEMPLATE.md).
