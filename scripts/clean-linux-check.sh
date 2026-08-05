#!/bin/sh
set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
docker run --rm \
  --read-only \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  --env RUSTUP_TOOLCHAIN=1.92.0 \
  --env CARGO_HOME=/work/.cargo \
  --mount type=volume,dst=/work,volume-nocopy \
  --tmpfs=/tmp:rw,noexec,nosuid,size=64m \
  --mount "type=bind,src=$repo,dst=/source,readonly" \
  -w /work \
  rust:1.92.0-bookworm@sha256:e90e846de4124376164ddfbaab4b0774c7bdeef5e738866295e5a90a34a307a2 \
  sh -c 'tar -C /source --exclude=.git --exclude=target --exclude=fuzz/target --exclude=fuzz/corpus -cf - . | tar --no-same-owner -xf - && cargo test --locked --test oracle'
