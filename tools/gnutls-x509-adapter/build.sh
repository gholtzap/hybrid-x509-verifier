#!/bin/sh
set -eu
repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
docker build -t hybrid-x509-gnutls:3.7.3 "$repo/tools/gnutls-x509-adapter"
docker build -f "$repo/tools/gnutls-x509-adapter/Dockerfile.current" \
  -t hybrid-x509-gnutls:3.8.13 "$repo/tools/gnutls-x509-adapter"
version=$(docker run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges hybrid-x509-gnutls:3.8.13 --version)
case "$version" in
  *"3.8.13"*) ;;
  *) echo "unexpected GnuTLS version: $version" >&2; exit 1 ;;
esac
