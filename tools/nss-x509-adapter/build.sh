#!/bin/sh
set -eu
repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
docker build -t hybrid-x509-nss:3.98 "$repo/tools/nss-x509-adapter"
docker build -f "$repo/tools/nss-x509-adapter/Dockerfile.current" \
  -t hybrid-x509-nss:3.126 "$repo/tools/nss-x509-adapter"

test "$(docker run --rm hybrid-x509-nss:3.126 --version)" = 3.126
set +e
output=$(docker run --rm --network=none --read-only --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  -e NSS_VERIFY_TOOL=missing-nss-tool \
  -v "$repo/tests/fixtures/paper-v1.0.2/root.pem:/input/root.pem:ro" \
  -v "$repo/tests/fixtures/paper-v1.0.2/ica.pem:/input/intermediate.pem:ro" \
  -v "$repo/tests/fixtures/paper-v1.0.2/related-certA.pem:/input/leaf.pem:ro" \
  hybrid-x509-nss:3.126 \
  --root /input/root.pem --intermediate /input/intermediate.pem --leaf /input/leaf.pem \
  --time 2606200000Z 2>/dev/null)
status=$?
set -e
[ "$status" -eq 3 ] && [ -z "$output" ]

mkdir -p "$repo/target/nss-adapter-check"
cargo run --quiet --manifest-path "$repo/Cargo.toml" -- mutate-certificate-signature \
  --certificate "$repo/tests/fixtures/paper-v1.0.2/related-certA.pem" \
  --output "$repo/target/nss-adapter-check/related-certA-invalid-signature.pem" >/dev/null
verdict=$(docker run --rm --network=none --read-only --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  -v "$repo/tests/fixtures/paper-v1.0.2/root.pem:/input/root.pem:ro" \
  -v "$repo/tests/fixtures/paper-v1.0.2/ica.pem:/input/intermediate.pem:ro" \
  -v "$repo/target/nss-adapter-check/related-certA-invalid-signature.pem:/input/leaf.pem:ro" \
  hybrid-x509-nss:3.126 \
  --root /input/root.pem --intermediate /input/intermediate.pem --leaf /input/leaf.pem \
  --time 2606200000Z 2>/dev/null)
[ "$verdict" = '{"verdict":"reject"}' ]
