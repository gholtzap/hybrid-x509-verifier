#!/bin/sh
set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

build() {
  output=$1
  docker buildx build \
    --file "$repo/Dockerfile.release" \
    --no-cache \
    --provenance=false \
    --sbom=false \
    --build-arg SOURCE_DATE_EPOCH=1782000000 \
    --output "type=oci,dest=$output,rewrite-timestamp=true" \
    "$repo" >/dev/null
}

build "$work/first.tar"
build "$work/second.tar"
cmp "$work/first.tar" "$work/second.tar"
sha256sum "$work/first.tar" | cut -d ' ' -f 1
