# Paper corpus subset

These synthetic certificates are from version 1.0.2 of the reproducibility package for
“Classical Acceptance Is Not Hybrid Authentication” (arXiv:2607.20800).

Source commit: `b1c2ee5e87862c4103b482571945505f82a0d0d9`

Source repository: <https://github.com/taesung901-ui/pqt-verifier-semantics-artifact>

The files are public-domain data under CC0-1.0. See `LICENSE-data`. The original manifest is
included so tests can verify the DER SHA-256 digests instead of trusting filenames.

The three `wolfgen` certificates are the package's committed wolfSSL fixed vectors. Their random
generation is not byte-reproducible. The evaluator checks their published DER digests and the four
published accept or reject outcomes.
