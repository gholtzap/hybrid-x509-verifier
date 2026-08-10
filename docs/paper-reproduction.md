# Paper reproduction

Paper artifact commit: `b1c2ee5e87862c4103b482571945505f82a0d0d9`.

Current clean-source comparison artifacts:

- `reports/local-arm64/paper-comparison.json`: 54 common matrix rows compared, 54 matched, zero differences.
- `reports/local-arm64/paper-wolfssl-comparison.json`: four wolfSSL fixed-vector rows compared, four matched, zero differences.
- `tests/fixtures/paper-v1.0.2/expected-lifecycle.json`: seven lifecycle rows accounted for at `2026-06-20T00:00:00Z`.

Lifecycle coverage:

- Revoked post-quantum credential: OpenSSL accepts the classical path; P2 rejects and reports lifecycle desynchronization.
- Expired post-quantum credential: OpenSSL accepts the classical path; P2 rejects.
- Unknown post-quantum OCSP status: the OCSP checker reports revocation indeterminate.
- Missing peer credential: P2 rejects because required post-quantum evidence is absent.
- Both credentials good: the stack accepts. The product policy accepts only when post-quantum evidence is decision-sensitive-for-fixture in the selected authentication result.
- Revoked post-quantum credential alone: direct revocation control rejects.
- Expired post-quantum credential alone: direct validity control rejects.

These comparison files use the v9 report contract and source commit
`ee72f1cb5403866130c66dbe6d4522c93eed6074`.

The main semantic difference is intentional. The paper records whether a stack accepts available
credentials. This evaluator records whether post-quantum evidence affected the final
authentication decision.
