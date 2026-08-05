#!/bin/sh
set -eu
repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
for version in 1.84 1.85; do
  docker build --build-arg BC_VERSION="$version" \
    -t "hybrid-x509-bouncycastle:$version" "$repo/tools/bc-x509-adapter"
done
