#!/bin/sh
set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
output=${1:-"$repo/target/generated-corpus"}
mkdir -p "$output"
output=$(CDPATH= cd -- "$output" && pwd)
check=$(mktemp -d)
trap 'rm -rf "$check"' EXIT

cp "$repo/tests/fixtures/paper-v1.0.2/composite-ica.pem" "$output/composite-ica.pem"
cp "$repo/tests/fixtures/paper-v1.0.2/composite-leaf.pem" "$output/composite-leaf.pem"
cp "$repo/tests/fixtures/paper-v1.0.2/composite-ica.pem" "$check/composite-ica.pem"
cp "$repo/tests/fixtures/paper-v1.0.2/composite-leaf.pem" "$check/composite-leaf.pem"

docker build -q -t hybrid-x509-corpus-generator "$repo/tools/corpus-generator" >/dev/null
docker run --rm -v "$output:/out" hybrid-x509-corpus-generator
docker run --rm -v "$check:/out" hybrid-x509-corpus-generator
for file in \
  catalyst-leaf-base-key.pem \
  pure-leaf-key.pem \
  pure-path-root.pem \
  pure-path-ica.pem \
  pure-path-leaf.pem \
  pure-path-root-bad-signature.pem \
  pure-path-ica-bad-signature.pem \
  pure-path-leaf-bad-signature.pem \
  pure-path-root-crl.pem \
  pure-path-ica-crl.pem \
  chameleon-base-key.pem \
  chameleon-delta-key.pem \
  chameleon-delta.pem \
  chameleon-delta-valid.pem \
  chameleon-base-valid-delta.pem \
  chameleon-base-bad-delta.pem \
  chameleon-path-root-base.pem \
  chameleon-path-root-delta.pem \
  chameleon-path-ica-base.pem \
  chameleon-path-ica-delta.pem \
  chameleon-path-leaf-base.pem \
  chameleon-path-leaf-delta.pem \
  chameleon-path-root-base-bad-delta.pem \
  chameleon-path-ica-base-bad-delta.pem \
  chameleon-path-leaf-base-bad-delta.pem \
  chameleon-path-root-base-bad-signature.pem \
  chameleon-path-ica-base-bad-signature.pem \
  chameleon-path-leaf-base-bad-signature.pem \
  chameleon-path-root-base-crl.pem \
  chameleon-path-ica-base-crl.pem \
  chameleon-path-root-delta-crl.pem \
  chameleon-path-ica-delta-crl.pem \
  catalyst-leaf-bad-alt.pem \
  catalyst-path-root.pem \
  catalyst-path-ica.pem \
  catalyst-path-leaf.pem \
  catalyst-path-root-bad-alt.pem \
  catalyst-path-ica-bad-alt.pem \
  catalyst-path-leaf-bad-alt.pem \
  catalyst-path-leaf-base-key.pem \
  catalyst-path-leaf-alt-key.pem \
  catalyst-path-root-crl.pem \
  catalyst-path-ica-crl.pem \
  atomic-path-root.pem \
  atomic-path-ica.pem \
  atomic-path-leaf.pem \
  atomic-path-root-key.pem \
  atomic-path-ica-key.pem \
  atomic-path-leaf-key.pem \
  atomic-path-root-bad-mldsa.pem \
  atomic-path-root-bad-ecdsa.pem \
  atomic-path-ica-bad-mldsa.pem \
  atomic-path-ica-bad-ecdsa.pem \
  atomic-path-leaf-bad-mldsa.pem \
  atomic-path-leaf-bad-ecdsa.pem \
  atomic-path-root-crl.pem \
  atomic-path-ica-crl.pem \
  cross-root-classical.pem \
  cross-root-atomic.pem \
  cross-ica-classical.pem \
  cross-ica-atomic.pem \
  cross-leaf.pem \
  cross-roots.pem \
  cross-icas.pem \
  cross-ica-classical-bad-signature.pem \
  cross-root-classical-bad-signature.pem \
  cross-root-atomic-bad-mldsa.pem \
  cross-root-atomic-bad-ecdsa.pem \
  cross-ica-atomic-bad-mldsa.pem \
  cross-ica-atomic-bad-ecdsa.pem \
  cross-leaf-bad-mldsa.pem \
  cross-leaf-bad-ecdsa.pem \
  cross-icas-classical-fallback.pem \
  cross-icas-atomic-fallback.pem \
  cross-root-classical-crl.pem \
  cross-root-atomic-crl.pem \
  cross-ica-crl.pem \
  related-path-root-a.pem \
  related-path-root-b.pem \
  related-path-ica-a.pem \
  related-path-ica-b.pem \
  related-path-leaf-a.pem \
  related-path-leaf-b.pem \
  related-path-root-a-bad-binding.pem \
  related-path-ica-a-bad-binding.pem \
  related-path-leaf-a-bad-binding.pem \
  related-path-root-a-bad-signature.pem \
  related-path-root-b-bad-signature.pem \
  related-path-ica-a-bad-signature.pem \
  related-path-ica-b-bad-signature.pem \
  related-path-leaf-a-bad-signature.pem \
  related-path-leaf-b-bad-signature.pem \
  related-path-root-a-crl.pem \
  related-path-ica-a-crl.pem \
  related-path-root-b-crl.pem \
  related-path-ica-b-crl.pem \
  root-crl.pem \
  related-certA-key.pem \
  related-leafB-key.pem \
  composite-leaf-key.pem \
  composite-leaf-bad-mldsa.pem \
  related-crl-future.pem \
  related-leafB-wrong-signer.pem \
  related-leafB-unbound.pem \
  related-certA-missing.pem \
  related-certA-broken-binding.pem \
  related-certA-unknown-digest.pem \
  related-certA-malformed.pem \
  related-certA-critical.pem \
  related-certA-good-ocsp.der.b64 \
  related-certA-revoked-ocsp.der.b64 \
  related-leafB-good-ocsp.der.b64 \
  related-leafB-revoked-ocsp.der.b64 \
  related-leafB-unknown-ocsp.der.b64 \
  related-leafB-stale-ocsp.der.b64 \
  related-leafB-nonce-ocsp.der.b64 \
  related-leafB-delegated-ocsp.der.b64 \
  related-leafB-delegated-no-eku-ocsp.der.b64 \
  related-leafB-unavailable-ocsp.der.b64 \
  related-leafB-malformed-ocsp.der.b64
do
  cmp "$output/$file" "$check/$file"
  cmp "$output/$file" "$repo/tests/fixtures/generated-controls/$file"
done

cargo run --quiet --manifest-path "$repo/Cargo.toml" -- verify-corpus \
  --manifest "$repo/tests/fixtures/paper-v1.0.2/manifest.json" \
  --root "$output"
