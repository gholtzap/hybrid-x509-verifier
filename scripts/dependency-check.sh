#!/bin/sh
set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
mkdir -p "$repo/target/tooling"

if [ ! -x "$repo/target/tooling/bin/cargo-audit" ]; then
  cargo install --root "$repo/target/tooling" cargo-audit --version 0.22.0 --locked
fi
"$repo/target/tooling/bin/cargo-audit" audit --deny warnings

docker run --rm \
  --mount "type=bind,src=$repo/tools/go-x509-adapter,dst=/source,readonly" \
  -w /source \
  golang:1.26.5-bookworm@sha256:8d36439c36258ba98de1bf2b316eda72905f9d743117119f6db9705c49245644 \
  go run golang.org/x/vuln/cmd/govulncheck@v1.6.0 ./...

docker run --rm \
  --read-only \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  --tmpfs=/tmp:rw,noexec,nosuid,size=64m \
  --mount "type=bind,src=$repo,dst=/source,readonly" \
  ghcr.io/google/osv-scanner@sha256:5116601dedc01c1c580eb92371883ec052fc4c13c3fbc109d621a63ac416d475 \
  scan source --recursive --experimental-disable-plugins=sbom \
  --config=/source/osv-scanner.toml /source
