#!/bin/sh
set -eu
repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
for version in 49.0.0 50.0.0; do
  docker build --build-arg "CRYPTOGRAPHY_VERSION=$version" \
    -f "$repo/tools/pyca-x509-adapter/Dockerfile" \
    -t "hybrid-x509-pyca:$version" "$repo"
done
