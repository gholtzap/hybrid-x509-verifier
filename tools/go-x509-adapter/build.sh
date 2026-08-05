#!/bin/sh
set -eu
repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
docker build -t hybrid-x509-go:1.26.4 "$repo/tools/go-x509-adapter"
docker build -f "$repo/tools/go-x509-adapter/Dockerfile.current" \
  -t hybrid-x509-go:1.26.5 "$repo/tools/go-x509-adapter"

study=$(docker run --rm hybrid-x509-go:1.26.4 --version)
current=$(docker run --rm hybrid-x509-go:1.26.5 --version)
[ "$study" = "go1.26.4" ]
[ "$current" = "go1.26.5" ]
