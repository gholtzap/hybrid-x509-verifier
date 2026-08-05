#!/bin/sh
set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
image=rust:1.92.0-bookworm@sha256:e90e846de4124376164ddfbaab4b0774c7bdeef5e738866295e5a90a34a307a2

build_digest() {
  docker run --rm \
    --read-only \
    --cap-drop=ALL \
    --security-opt=no-new-privileges \
    --env RUSTUP_TOOLCHAIN=1.92.0 \
    --env CARGO_HOME=/work/.cargo \
    --env CARGO_INCREMENTAL=0 \
    --env SOURCE_DATE_EPOCH=1782000000 \
    --tmpfs=/tmp:rw,noexec,nosuid,size=64m \
    --mount type=volume,dst=/work,volume-nocopy \
    --mount "type=bind,src=$repo,dst=/source,readonly" \
    -w /work \
    "$image" \
    sh -c 'tar -C /source --exclude=.git --exclude=target --exclude=fuzz/target --exclude=fuzz/corpus -cf - . | tar --no-same-owner -xf - && cargo build --quiet --locked --release --bin hybrid-x509-verify && sha256sum target/release/hybrid-x509-verify | cut -d " " -f 1'
}

first=$(build_digest)
second=$(build_digest)
[ "$first" = "$second" ]
printf '%s\n' "$first"
