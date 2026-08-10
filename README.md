# Hybrid X.509 evidence policy evaluator

This is a pre-alpha research harness for controlled hybrid X.509 experiments. It records stack
behavior, evaluates versioned evidence under P0, P1, and P2 policies, and checks whether classical
and post-quantum evidence affected the same authentication result.

The experiments cover certificate paths, revocation, TLS authentication, fallback, and the
classical, pure post-quantum, composite, Catalyst, Chameleon, and Related certificate designs.

Publication runs use isolated adapters for OpenSSL, GnuTLS, Go crypto/x509, Python cryptography,
Bouncy Castle, NSS, oqs-provider, and wolfSSL.

## Requirements

- Rust 1.92.0, selected by `rust-toolchain.toml`.
- Docker with Buildx.
- OpenSSL and `jq`.
- GnuTLS command-line tools and Python 3 for the complete Linux adapter suite.

## Quick validation

Run the portable checks:

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --locked --test oracle
```

Run the complete adapter suite serially:

```sh
python3 -m venv .venv
.venv/bin/pip install cryptography==46.0.4

for build in tools/*-adapter/build.sh; do
  "$build"
done

tools/corpus-generator/generate.sh
PATH="$PWD/.venv/bin:$PATH" cargo test --locked --all-features -- --test-threads=1
scripts/dependency-check.sh
scripts/generate-sbom.sh
git diff --exit-code -- sbom-rust.cdx.json sbom-all.cdx.json
```

Run the reproducible binary and OCI image checks:

```sh
scripts/reproducible-build-check.sh
docker buildx create --driver docker-container --use
scripts/reproducible-image-check.sh
```

## Generate the fixture matrix

Build the adapters first, then run publication mode from a clean source tree:

```sh
for build in tools/*-adapter/build.sh; do
  "$build"
done

mkdir -p target/publication
cargo run --locked -- matrix-available \
  --validation-time 2026-06-20T00:00:00Z \
  --publication > target/publication/matrix-report.json
jq -e . target/publication/matrix-report.json >/dev/null
```

Publication mode requires a clean tree. The report records the source commit, source tree, clean
state, platform, and adapter image digests.

## Reproduce the lifecycle result

This experiment checks a valid classical certificate with a revoked Related post-quantum
certificate:

```sh
cargo run --locked -- analyze-related-openssl \
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

The expected result is `reject`, with `classical_only_fallback: true` and
`lifecycle_desynchronization: true`.

## Find an experiment

Use `cargo run --locked -- <command> --help` for complete arguments.

- `analyze-cross-signed-path` compares both cross-signed routes.
- `analyze-catalyst-bouncy-castle` and `analyze-catalyst-tls` check Catalyst fallback.
- `analyze-atomic-tls` changes each composite signature component independently.
- `analyze-chameleon-tls` checks base and delta certificate behavior.
- `analyze-related-tls` checks bound classical and post-quantum credentials.
- The `analyze-*-path-scope` commands check leaf, intermediate, and trust-anchor controls.
- `check-ocsp` checks one OCSP response.
- `mutate-certificate-signature` creates a controlled invalid certificate signature.

List every command or print a JSON schema with:

```sh
cargo run --locked -- --help
cargo run --locked -- schema --help
cargo run --locked -- schema request
cargo run --locked -- schema result
```

## Research basis

The initial fixtures and observations come from [“Classical Acceptance Is Not Hybrid
Authentication: How Deployed X.509 Validation Stacks Treat Hybrid
Certificates”](https://arxiv.org/abs/2607.20800), arXiv:2607.20800. The fixtures preserve the
paper inputs and published observations, while the policy evaluator lives in this repository.

See [paper reproduction](docs/paper-reproduction.md) and [specification
baseline](docs/specification-baseline.md) for the exact comparison and standards scope.
