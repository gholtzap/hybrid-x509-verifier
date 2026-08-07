# Hybrid X.509 evidence policy evaluator

This pre-alpha research harness evaluates trusted evidence claims about fixture-specific
certificate-validation and TLS operations. It is not an X.509 verifier, a TLS authentication
verifier, or proof of broad hybrid-certificate support.

The main command is not a security-boundary evaluator for untrusted JSON input. It does not
independently derive most evidence from certificate bytes or TLS transcripts. Treat its input as
trusted adapter output, or bind the evidence to locally generated or signed adapter reports before
using the result for a security decision.

The current implementation provides:

- A versioned JSON evidence and result model.
- P0, P1, P2, and P3 policy judgments. P3 returns indeterminate until an authenticated
  continuity record exists.
- End-entity and certification-path scopes. Trust-anchor self-signatures are not
  selected path evidence.
- Per-check confidence: observed, behaviorally established, inferred, or unknown.
- OID-based fixture classification for classical, pure post-quantum, composite, Catalyst,
  Chameleon, and Related candidate certificate encodings.
- RFC 9763 RelatedCertificate profile checks for digest binding, end-entity use, key
  usage, and extended key usage. Local hybrid policy separately checks traditional-plus-PQ
  key direction and reference identity overlap.
- Direct complete-CRL checks with strict nextUpdate handling and unsupported advanced CRL
  semantics.
- OCSP checks with revocation-time handling, explicit hard-fail, soft-fail, and not-required
  policy modes, and delegated-responder revocation evidence or no-check handling.
- A bounded OpenSSL adapter with raw-output hashes.
- GnuTLS, Go crypto/x509, Python cryptography, and isolated Bouncy Castle, NSS,
  oqs-provider, and wolfSSL adapters.
- Deterministic outer-signature mutation for every certificate design.
- Detection of Related-certificate revocation desynchronization.
- A reproducible Rust CycloneDX SBOM and Rust and Go vulnerability checks.
- Container-isolated authoritative adapters with explicit `process-only` labels for optional
  native diagnostic probes.

See [verification status](docs/verification-status.md) for the exact local evidence and
external gates.

## Build and test

```sh
cargo test
cargo clippy --all-targets --all-features -- -D warnings
scripts/dependency-check.sh
scripts/generate-sbom.sh
scripts/clean-linux-check.sh
scripts/reproducible-build-check.sh
scripts/reproducible-image-check.sh
scripts/fuzz.sh 30
```

## Reproduce the first lifecycle result

```sh
cargo run -- analyze-related-openssl \
  --trust-store tests/fixtures/paper-v1.0.2/root.pem \
  --issuer tests/fixtures/paper-v1.0.2/ica.pem \
  --classical-certificate tests/fixtures/paper-v1.0.2/related-certA.pem \
  --post-quantum-certificate tests/fixtures/paper-v1.0.2/related-leafB.pem \
  --expired-post-quantum-certificate tests/fixtures/paper-v1.0.2/related-leafB-expired.pem \
  --invalid-binding-certificate tests/fixtures/generated-controls/related-leafB-unbound.pem \
  --crl tests/fixtures/paper-v1.0.2/related-crl.pem \
  --validation-time 2026-06-20T00:00:00Z \
  --policy p2
```

The expected policy result is `reject`. The expected classifications are
`classical_only_fallback: true` and `lifecycle_desynchronization: true`.

## JSON schemas

```sh
cargo run -- schema request
cargo run -- schema result
cargo run -- schema adapter
cargo run -- schema tls
cargo run -- schema tls-transcript
cargo run -- schema related-open-ssl
cargo run -- schema catalyst-bouncy-castle
cargo run -- schema catalyst-path-scope
cargo run -- schema catalyst-tls
cargo run -- schema atomic-tls
cargo run -- schema atomic-path-scope
cargo run -- schema pure-path-scope
cargo run -- schema cross-signed-path
cargo run -- schema chameleon-tls
cargo run -- schema chameleon-path-scope
cargo run -- schema related-tls
cargo run -- schema related-path-scope
cargo run -- schema matrix
```

Create a controlled invalid-signature certificate with:

```sh
cargo run -- mutate-certificate-signature \
  --certificate tests/fixtures/paper-v1.0.2/related-certA.pem \
  --output target/related-certA-invalid-signature.pem
```

## Rebuild the published corpus

Docker is required.

```sh
tools/corpus-generator/generate.sh
```

The generator also rebuilds deterministic RelatedCertificate OCSP controls. It creates good
and revoked classical results plus good, revoked, unknown, stale, and unavailable
post-quantum results, and checks each committed response for exact byte equality.

```sh
openssl base64 -d -A \
  -in tests/fixtures/generated-controls/related-leafB-revoked-ocsp.der.b64 \
  -out target/related-leafB-revoked-ocsp.der
cargo run -- check-ocsp \
  --certificate tests/fixtures/paper-v1.0.2/related-leafB.pem \
  --issuer tests/fixtures/paper-v1.0.2/ica.pem \
  --response target/related-leafB-revoked-ocsp.der \
  --validation-time 2026-06-21T00:00:00Z \
  --revocation-mode soft-fail
```

Use `--expected-nonce-base64 ABEiM0RVZneImaq7zN3u/w==` with the generated nonce response.
If the response omits or changes the requested nonce, its revocation result is indeterminate.

## Run the available local matrix

Build the OpenSSL, Go, Bouncy Castle, GnuTLS, NSS, oqs-provider, Python cryptography, and wolfSSL
helpers first:

```sh
tools/go-x509-adapter/build.sh
tools/openssl-x509-adapter/build.sh
tools/bc-x509-adapter/build.sh
tools/gnutls-x509-adapter/build.sh
tools/nss-x509-adapter/build.sh
tools/oqs-provider-adapter/build.sh
tools/pyca-x509-adapter/build.sh
tools/wolfssl-x509-adapter/build.sh
cargo run -- matrix-available \
  --validation-time 2026-06-20T00:00:00Z
```

Use `--publication` only from a clean source tree. Publication mode rejects a dirty tree. The
matrix report records the source commit, source tree, clean-state result, platform, and each
unique adapter image content digest.

This command records 345 isolated fixture results. Each row records an operation profile, claim
identifier, expected fixture verdict, and standards status. It runs seven valid cases: classical, Related,
Catalyst, atomic composite, Chameleon, pure post-quantum, and the published Chameleon study
fixture. It also runs corrupted outer certificate signatures, invalid Catalyst,
atomic-composite, and Chameleon evidence signatures, and Related Certificate controls for
missing evidence, broken binding, an unknown algorithm, malformed evidence, a critical hybrid
extension, and revoked classical status.

The matrix is a fixture matrix. It shows neither general standards support nor internal library
operation beyond the named inputs, versions, adapters, and commands.

## Reproduce controlled Catalyst fallback

Generate the controls and build the Bouncy Castle adapter first. Then run:

```sh
cargo run -- analyze-catalyst-bouncy-castle \
  --trust-store target/generated-corpus/root.pem \
  --issuer target/generated-corpus/catalyst-ica.pem \
  --valid-certificate target/generated-corpus/catalyst-leaf.pem \
  --invalid-post-quantum-certificate target/generated-corpus/catalyst-leaf-bad-alt.pem \
  --crl target/generated-corpus/catalyst-crl.pem \
  --root-crl target/generated-corpus/root-crl.pem \
  --validation-time 2026-06-20T00:00:00Z \
  --policy p2
```

Run the same controlled fallback during a TLS 1.3 server handshake with:

```sh
cargo run -- analyze-catalyst-tls \
  --trust-store tests/fixtures/paper-v1.0.2/root.pem \
  --issuer tests/fixtures/paper-v1.0.2/catalyst-ica.pem \
  --valid-certificate tests/fixtures/paper-v1.0.2/catalyst-leaf.pem \
  --invalid-post-quantum-certificate tests/fixtures/generated-controls/catalyst-leaf-bad-alt.pem \
  --private-key tests/fixtures/generated-controls/catalyst-leaf-base-key.pem \
  --crl tests/fixtures/generated-controls/catalyst-crl.pem \
  --hostname catalyst.pqc-probe.test \
  --validation-time 2026-06-20T00:00:00Z
```

The TLS report keeps the certificate-authentication signature and the negotiated key-exchange
group separate. A hybrid key-exchange group does not show hybrid certificate authentication.

The generic `probe-openssl-tls` command also supports pure post-quantum credentials. The committed
`pure-leaf-key.pem` control produces `mldsa44` TLS 1.3 authentication. Run
`probe-tls-transcript` with the same leaf, key, and issuer to show that an ML-DSA signature over
an altered transcript input is rejected. The transcript probe also requires rejection when the
client offers only an incompatible CertificateVerify signature algorithm.

Run the deterministic pure post-quantum path control at all three policy scopes with:

```sh
cargo run -- analyze-pure-path-scope \
  --root tests/fixtures/generated-controls/pure-path-root.pem \
  --intermediate tests/fixtures/generated-controls/pure-path-ica.pem \
  --leaf tests/fixtures/generated-controls/pure-path-leaf.pem \
  --invalid-root tests/fixtures/generated-controls/pure-path-root-bad-signature.pem \
  --invalid-intermediate tests/fixtures/generated-controls/pure-path-ica-bad-signature.pem \
  --invalid-leaf tests/fixtures/generated-controls/pure-path-leaf-bad-signature.pem \
  --root-crl tests/fixtures/generated-controls/pure-path-root-crl.pem \
  --intermediate-crl tests/fixtures/generated-controls/pure-path-ica-crl.pem \
  --validation-time 2026-06-20T00:00:00Z \
  --policy p2
```

This is a post-quantum control, not a hybrid result. P2 rejects it because required classical
evidence is absent. The report does not mislabel it as classical fallback.

Build and compare both cross-signed routes with:

```sh
cargo run -- analyze-cross-signed-path \
  --validation-time 2026-06-20T00:00:00Z \
  --policy p2
```

The report records the SHA-256 identity of every selected path certificate. It also removes each
trust route and breaks each cross-certificate in turn. This distinguishes atomic path selection
from classical fallback.

## Reproduce controlled Chameleon delta handling

Run the direct delta-signature operation against the corrected and wrong-signer controls:

```sh
cargo run -- probe-bouncy-castle --mode delta-signature \
  --trust-store tests/fixtures/paper-v1.0.2/root.pem \
  --intermediate tests/fixtures/paper-v1.0.2/ica.pem \
  --leaf tests/fixtures/generated-controls/chameleon-base-valid-delta.pem \
  --validation-time 2026-06-20T00:00:00Z

cargo run -- probe-bouncy-castle --mode delta-signature \
  --trust-store tests/fixtures/paper-v1.0.2/root.pem \
  --intermediate tests/fixtures/paper-v1.0.2/ica.pem \
  --leaf tests/fixtures/generated-controls/chameleon-base-bad-delta.pem \
  --validation-time 2026-06-20T00:00:00Z
```

The direct results are `accept` and `reject`. Default path validation accepts both base
certificates. This difference shows that default acceptance does not depend on the delta
evidence.

Run the combined TLS control with:

```sh
cargo run -- analyze-chameleon-tls \
  --trust-store tests/fixtures/paper-v1.0.2/root.pem \
  --issuer tests/fixtures/paper-v1.0.2/ica.pem \
  --valid-base-certificate tests/fixtures/generated-controls/chameleon-base-valid-delta.pem \
  --invalid-delta-base-certificate tests/fixtures/generated-controls/chameleon-base-bad-delta.pem \
  --delta-certificate tests/fixtures/generated-controls/chameleon-delta-valid.pem \
  --base-private-key tests/fixtures/generated-controls/chameleon-base-key.pem \
  --delta-private-key tests/fixtures/generated-controls/chameleon-delta-key.pem \
  --validation-time 2026-06-20T00:00:00Z
```

Run the deterministic Chameleon hierarchy at all policy scopes with:

```sh
cargo run -- analyze-chameleon-path-scope \
  --root-base tests/fixtures/generated-controls/chameleon-path-root-base.pem \
  --intermediate-base tests/fixtures/generated-controls/chameleon-path-ica-base.pem \
  --leaf-base tests/fixtures/generated-controls/chameleon-path-leaf-base.pem \
  --root-delta tests/fixtures/generated-controls/chameleon-path-root-delta.pem \
  --intermediate-delta tests/fixtures/generated-controls/chameleon-path-ica-delta.pem \
  --leaf-delta tests/fixtures/generated-controls/chameleon-path-leaf-delta.pem \
  --invalid-delta-root-base tests/fixtures/generated-controls/chameleon-path-root-base-bad-delta.pem \
  --invalid-delta-intermediate-base tests/fixtures/generated-controls/chameleon-path-ica-base-bad-delta.pem \
  --invalid-delta-leaf-base tests/fixtures/generated-controls/chameleon-path-leaf-base-bad-delta.pem \
  --invalid-base-root tests/fixtures/generated-controls/chameleon-path-root-base-bad-signature.pem \
  --invalid-base-intermediate tests/fixtures/generated-controls/chameleon-path-ica-base-bad-signature.pem \
  --invalid-base-leaf tests/fixtures/generated-controls/chameleon-path-leaf-base-bad-signature.pem \
  --root-base-crl tests/fixtures/generated-controls/chameleon-path-root-base-crl.pem \
  --intermediate-base-crl tests/fixtures/generated-controls/chameleon-path-ica-base-crl.pem \
  --root-delta-crl tests/fixtures/generated-controls/chameleon-path-root-delta-crl.pem \
  --intermediate-delta-crl tests/fixtures/generated-controls/chameleon-path-ica-delta-crl.pem \
  --validation-time 2026-06-20T00:00:00Z \
  --policy p2
```

## Run atomic and Related TLS controls

The atomic control changes each composite certificate-signature component independently:

```sh
cargo run -- analyze-atomic-tls \
  --trust-store tests/fixtures/paper-v1.0.2/root.pem \
  --issuer tests/fixtures/paper-v1.0.2/composite-ica.pem \
  --valid-certificate tests/fixtures/paper-v1.0.2/composite-leaf.pem \
  --invalid-post-quantum-certificate tests/fixtures/generated-controls/composite-leaf-bad-mldsa.pem \
  --private-key tests/fixtures/generated-controls/composite-leaf-key.pem \
  --validation-time 2026-06-20T00:00:00Z
```

Run the deterministic atomic chain at all policy scopes with:

```sh
cargo run -- analyze-atomic-path-scope \
  --root tests/fixtures/generated-controls/atomic-path-root.pem \
  --intermediate tests/fixtures/generated-controls/atomic-path-ica.pem \
  --leaf tests/fixtures/generated-controls/atomic-path-leaf.pem \
  --invalid-classical-root tests/fixtures/generated-controls/atomic-path-root-bad-ecdsa.pem \
  --invalid-post-quantum-root tests/fixtures/generated-controls/atomic-path-root-bad-mldsa.pem \
  --invalid-classical-intermediate tests/fixtures/generated-controls/atomic-path-ica-bad-ecdsa.pem \
  --invalid-post-quantum-intermediate tests/fixtures/generated-controls/atomic-path-ica-bad-mldsa.pem \
  --invalid-classical-leaf tests/fixtures/generated-controls/atomic-path-leaf-bad-ecdsa.pem \
  --invalid-post-quantum-leaf tests/fixtures/generated-controls/atomic-path-leaf-bad-mldsa.pem \
  --root-crl tests/fixtures/generated-controls/atomic-path-root-crl.pem \
  --intermediate-crl tests/fixtures/generated-controls/atomic-path-ica-crl.pem \
  --validation-time 2026-06-20T00:00:00Z \
  --policy p2
```

The Related control compares the classical handshake with valid, broken, and missing binding
evidence. It checks the bound post-quantum credential in a separate handshake and checks its CRL
status at the same time:

```sh
cargo run -- analyze-related-tls \
  --trust-store tests/fixtures/paper-v1.0.2/root.pem \
  --issuer tests/fixtures/paper-v1.0.2/ica.pem \
  --classical-certificate tests/fixtures/paper-v1.0.2/related-certA.pem \
  --invalid-binding-classical-certificate tests/fixtures/generated-controls/related-certA-broken-binding.pem \
  --missing-binding-classical-certificate tests/fixtures/generated-controls/related-certA-missing.pem \
  --post-quantum-certificate tests/fixtures/paper-v1.0.2/related-leafB.pem \
  --expired-post-quantum-certificate tests/fixtures/paper-v1.0.2/related-leafB-expired.pem \
  --classical-private-key tests/fixtures/generated-controls/related-certA-key.pem \
  --post-quantum-private-key tests/fixtures/generated-controls/related-leafB-key.pem \
  --crl tests/fixtures/paper-v1.0.2/related-crl.pem \
  --validation-time 2026-06-20T00:00:00Z
```

Run the paired Related chains at all policy scopes with:

```sh
cargo run -- analyze-related-path-scope \
  --classical-root tests/fixtures/generated-controls/related-path-root-a.pem \
  --classical-intermediate tests/fixtures/generated-controls/related-path-ica-a.pem \
  --classical-leaf tests/fixtures/generated-controls/related-path-leaf-a.pem \
  --post-quantum-root tests/fixtures/generated-controls/related-path-root-b.pem \
  --post-quantum-intermediate tests/fixtures/generated-controls/related-path-ica-b.pem \
  --post-quantum-leaf tests/fixtures/generated-controls/related-path-leaf-b.pem \
  --invalid-binding-root tests/fixtures/generated-controls/related-path-root-a-bad-binding.pem \
  --invalid-binding-intermediate tests/fixtures/generated-controls/related-path-ica-a-bad-binding.pem \
  --invalid-binding-leaf tests/fixtures/generated-controls/related-path-leaf-a-bad-binding.pem \
  --invalid-classical-root tests/fixtures/generated-controls/related-path-root-a-bad-signature.pem \
  --invalid-classical-intermediate tests/fixtures/generated-controls/related-path-ica-a-bad-signature.pem \
  --invalid-classical-leaf tests/fixtures/generated-controls/related-path-leaf-a-bad-signature.pem \
  --invalid-post-quantum-root tests/fixtures/generated-controls/related-path-root-b-bad-signature.pem \
  --invalid-post-quantum-intermediate tests/fixtures/generated-controls/related-path-ica-b-bad-signature.pem \
  --invalid-post-quantum-leaf tests/fixtures/generated-controls/related-path-leaf-b-bad-signature.pem \
  --classical-root-crl tests/fixtures/generated-controls/related-path-root-a-crl.pem \
  --classical-intermediate-crl tests/fixtures/generated-controls/related-path-ica-a-crl.pem \
  --post-quantum-root-crl tests/fixtures/generated-controls/related-path-root-b-crl.pem \
  --post-quantum-intermediate-crl tests/fixtures/generated-controls/related-path-ica-b-crl.pem \
  --validation-time 2026-06-20T00:00:00Z \
  --policy p2
```

## Reproduce controlled path-wide Catalyst fallback

```sh
cargo run -- analyze-catalyst-path-scope \
  --root tests/fixtures/generated-controls/catalyst-path-root.pem \
  --intermediate tests/fixtures/generated-controls/catalyst-path-ica.pem \
  --leaf tests/fixtures/generated-controls/catalyst-path-leaf.pem \
  --invalid-alternative-root tests/fixtures/generated-controls/catalyst-path-root-bad-alt.pem \
  --invalid-alternative-intermediate tests/fixtures/generated-controls/catalyst-path-ica-bad-alt.pem \
  --invalid-alternative-leaf tests/fixtures/generated-controls/catalyst-path-leaf-bad-alt.pem \
  --root-crl tests/fixtures/generated-controls/catalyst-path-root-crl.pem \
  --intermediate-crl tests/fixtures/generated-controls/catalyst-path-ica-crl.pem \
  --validation-time 2026-06-20T00:00:00Z \
  --policy p2
```

P2 rejects end-entity and certification-path claims for these Catalyst controls.
Default validation ignores invalid alternative signatures at all three positions. The
certification-path scope does not treat the trust-anchor self-signature as selected path evidence.

These results are limited to the named fixtures, stack versions, validation times, and commands.

## Research basis

The initial test cases come from “Classical Acceptance Is Not Hybrid Authentication,”
arXiv:2607.20800. The product oracle is independent from a tested validation stack. The paper
artifact is used only as a cited source of synthetic test data and published observations.
