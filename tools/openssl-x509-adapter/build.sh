#!/bin/sh
set -eu
repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
image=hybrid-x509-openssl:4.0.1
docker build -t "$image" "$repo/tools/openssl-x509-adapter"
version=$(docker run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges "$image" --version)
case "$version" in
  "OpenSSL 4.0.1 "*) ;;
  *) echo "unexpected OpenSSL version: $version" >&2; exit 1 ;;
esac
